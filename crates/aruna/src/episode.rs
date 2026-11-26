//! The pure core of the execution episode, a generation-fenced claim rather than a lease:
//! a closed status vocabulary, a transition table checked by one predicate, typed reasons,
//! and the values the store methods answer. No I/O: the store half
//! (`IntentLog::{start_episode, episode, episode_status_check, mark_ready, invalidate_episode,
//! complete_episode_if_done}`, both stores) calls through here, and every write it makes bumps
//! the head row's `generation` under a compare-and-set and appends one `episode_journal` row.
//! There is no owner lease in this module.

use crate::attempt::MemberDiff;

/// The status column's closed vocabulary. The `execution_episode` and `episode_journal` DDL
/// CHECKs spell exactly [`EpisodeStatusToken::ALL`], pinned by
/// `tokens_round_trip_and_the_ddl_check_is_regenerated_from_the_enum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpisodeStatusToken {
    Active,
    Paused,
    Cancelled,
    Completed,
    Invalidated,
}

impl EpisodeStatusToken {
    /// Every member, in the DDL CHECK's order.
    pub const ALL: [EpisodeStatusToken; 5] = [
        EpisodeStatusToken::Active,
        EpisodeStatusToken::Paused,
        EpisodeStatusToken::Cancelled,
        EpisodeStatusToken::Completed,
        EpisodeStatusToken::Invalidated,
    ];
    /// The durable spelling, the `status` CHECK's own token.
    pub fn as_token(self) -> &'static str {
        match self {
            EpisodeStatusToken::Active => "active",
            EpisodeStatusToken::Paused => "paused",
            EpisodeStatusToken::Cancelled => "cancelled",
            EpisodeStatusToken::Completed => "completed",
            EpisodeStatusToken::Invalidated => "invalidated",
        }
    }
    /// The inverse; `None` for a spelling outside [`EpisodeStatusToken::ALL`].
    pub fn from_token(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_token() == s)
    }
    /// Terminal means no row of [`TRANSITIONS`] leaves this status. Derived from the table, so
    /// a row added there changes this answer with it.
    pub fn is_terminal(self) -> bool {
        !TRANSITIONS.iter().any(|(from, _)| *from == self)
    }
}

/// The transition table: the allowed `(from, to)` pairs as data; [`assert_transition`] is the
/// predicate over it. The pause/cancel rows are here so the vocabulary is complete, but
/// nothing writes `paused` or `cancelled` yet. The store methods write: start to `active`;
/// `active` to `completed` or `invalidated`.
pub const TRANSITIONS: &[(EpisodeStatusToken, EpisodeStatusToken)] = &[
    (EpisodeStatusToken::Active, EpisodeStatusToken::Paused),
    (EpisodeStatusToken::Paused, EpisodeStatusToken::Active),
    (EpisodeStatusToken::Active, EpisodeStatusToken::Cancelled),
    (EpisodeStatusToken::Paused, EpisodeStatusToken::Cancelled),
    (EpisodeStatusToken::Active, EpisodeStatusToken::Completed),
    (EpisodeStatusToken::Active, EpisodeStatusToken::Invalidated),
    (EpisodeStatusToken::Paused, EpisodeStatusToken::Invalidated),
];

/// The journal's event column vocabulary: which method wrote the row. The `episode_journal`
/// DDL CHECK spells exactly [`EpisodeEvent::ALL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpisodeEvent {
    /// `start_episode` created the head.
    Start,
    /// `mark_ready` set the preflight `ready_at` marker.
    Ready,
    /// A status transition (`invalidate_episode`, `complete_episode_if_done`).
    Transition,
}

impl EpisodeEvent {
    pub const ALL: [EpisodeEvent; 3] = [EpisodeEvent::Start, EpisodeEvent::Ready, EpisodeEvent::Transition];
    pub fn as_token(self) -> &'static str {
        match self {
            EpisodeEvent::Start => "start",
            EpisodeEvent::Ready => "ready",
            EpisodeEvent::Transition => "transition",
        }
    }
    pub fn from_token(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_token() == s)
    }
}

/// Every refusal an episode method answers. Each is named, never a bare "no".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpisodeRefusal {
    /// `(from, to)` is not a row of [`TRANSITIONS`].
    IllegalTransition { from: EpisodeStatusToken, to: EpisodeStatusToken },
    /// The generation compare-and-set failed: the write named a generation the head no longer
    /// holds.
    GenerationConflict { expected: u64, found: u64 },
    /// No `triage_plan` row has this id.
    NoPlan,
    /// The plan has no `approval_evidence` row.
    NotApproved,
    /// The plan has no episode (a method that needs one was called first).
    NoEpisode,
    /// The store's `control_epoch` has moved since the plan was minted.
    EpochMismatch { plan: i64, current: i64 },
    /// The plan's `expires_at` is at or before the sticky clock's effective now.
    Expired { expires_at: String, effective_now: String },
    /// The plan's episode is terminal: a completed, cancelled or invalidated plan never starts
    /// or re-marks a second time.
    Terminal(EpisodeStatusToken),
    /// The episode exists and is not terminal, but is not `active` (`paused`, which nothing
    /// writes yet).
    NotActive(EpisodeStatusToken),
    /// A wholesale (preflight) step, `mark_ready` or `invalidate_episode` with
    /// [`InvalidationReason::StalePreflight`], was requested after this many of the plan's
    /// children hold a `send_authorized` fact. Dispatch has begun, so preflight is over.
    DispatchBegan { send_authorized_children: u64 },
    /// A stored value this build cannot have written (a reason that does not parse, a status
    /// token with the wrong reason shape).
    Malformed(String),
    /// The store itself failed.
    Store(String),
}

impl std::fmt::Display for EpisodeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EpisodeRefusal {}

impl From<crate::LogError> for EpisodeRefusal {
    fn from(e: crate::LogError) -> Self {
        EpisodeRefusal::Store(e.0)
    }
}

/// The predicate over [`TRANSITIONS`]; every other edge is a named refusal carrying the pair.
pub fn assert_transition(from: EpisodeStatusToken, to: EpisodeStatusToken) -> Result<(), EpisodeRefusal> {
    if TRANSITIONS.contains(&(from, to)) {
        Ok(())
    } else {
        Err(EpisodeRefusal::IllegalTransition { from, to })
    }
}

/// Parse a stored reason strictly: it must parse as `T` and re-serialize to the very JSON value
/// it was read from, so an extra key, a missing optional key, or any spelling this build's
/// writer (`serde_json::to_string` of the same type) cannot have produced is refused. (serde's
/// `deny_unknown_fields` does not cover the unit variants of an internally tagged enum, which is
/// why the comparison, not the attribute, is the rule.)
fn strict_reason<T: serde::Serialize + serde::de::DeserializeOwned>(v: serde_json::Value) -> Option<T> {
    let parsed: T = serde_json::from_value(v.clone()).ok()?;
    (serde_json::to_value(&parsed).ok()? == v).then_some(parsed)
}

/// `paused{operator | anomaly}`: a machine-initiated pause is a reason, not a state. Nothing
/// writes a pause yet; the type exists so a stored `paused` row reads back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PauseReason {
    Operator,
    Anomaly,
}

/// `invalidated{reason}`. Its fields are epochs, atom names, booleans and Photon message refs;
/// no subject, sender or address field exists on it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvalidationReason {
    /// The control epoch moved past the plan's.
    EpochMismatch { plan: i64, current: i64 },
    /// The plan expired with work outstanding (the durable abandonment bound).
    Expired,
    /// Preflight found these members diverged: `(message_ref, diffs)`.
    StalePreflight { diverged: Vec<(String, Vec<MemberDiff>)> },
    /// The grant the plan was minted under is no longer admitted.
    GrantRetired,
}

impl InvalidationReason {
    /// Every `kind` tag, one per variant, pinned against the variants by
    /// `typed_reasons_serialize_content_free_and_round_trip`.
    pub const KINDS: [&'static str; 4] = ["epoch_mismatch", "expired", "stale_preflight", "grant_retired"];

    /// This reason's `kind` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            InvalidationReason::EpochMismatch { .. } => "epoch_mismatch",
            InvalidationReason::Expired => "expired",
            InvalidationReason::StalePreflight { .. } => "stale_preflight",
            InvalidationReason::GrantRetired => "grant_retired",
        }
    }

    /// The durable spelling (the `status_reason` / journal `reason` column).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a closed enum of integers, strings and booleans serializes")
    }

    /// The strict inverse: text that is not a JSON object with a `kind`, a `kind` outside
    /// [`InvalidationReason::KINDS`], and a known kind whose body is not exactly what
    /// [`InvalidationReason::to_json`] writes (an unknown or missing key included, via
    /// `strict_reason`) are each `Malformed`, never a default. The messages name the kind, never
    /// the stored bytes.
    pub fn from_json(s: &str) -> Result<Self, EpisodeRefusal> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|_| EpisodeRefusal::Malformed("invalidation reason is not JSON".into()))?;
        let kind = v
            .get("kind")
            .and_then(|k| k.as_str())
            .ok_or_else(|| EpisodeRefusal::Malformed("invalidation reason has no kind".into()))?
            .to_string();
        if !Self::KINDS.contains(&kind.as_str()) {
            return Err(EpisodeRefusal::Malformed(format!("unknown invalidation kind '{kind}'")));
        }
        strict_reason(v).ok_or_else(|| EpisodeRefusal::Malformed(format!("malformed invalidation reason of kind '{kind}'")))
    }
}

/// The typed status a reader gets: the token and its reason, parsed together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpisodeStatus {
    Active,
    Paused(PauseReason),
    Cancelled,
    Completed,
    Invalidated(InvalidationReason),
}

impl EpisodeStatus {
    /// The column token.
    pub fn token(&self) -> EpisodeStatusToken {
        match self {
            EpisodeStatus::Active => EpisodeStatusToken::Active,
            EpisodeStatus::Paused(_) => EpisodeStatusToken::Paused,
            EpisodeStatus::Cancelled => EpisodeStatusToken::Cancelled,
            EpisodeStatus::Completed => EpisodeStatusToken::Completed,
            EpisodeStatus::Invalidated(_) => EpisodeStatusToken::Invalidated,
        }
    }
    /// Rebuild from the two columns. `paused` and `invalidated` need a reason and the other
    /// three must carry none; any other pairing is `Malformed`.
    pub fn from_columns(token: &str, reason: Option<&str>) -> Result<Self, EpisodeRefusal> {
        let t = EpisodeStatusToken::from_token(token)
            .ok_or_else(|| EpisodeRefusal::Malformed(format!("status token '{token}' is not one this build writes")))?;
        Ok(match (t, reason) {
            (EpisodeStatusToken::Active, None) => EpisodeStatus::Active,
            (EpisodeStatusToken::Cancelled, None) => EpisodeStatus::Cancelled,
            (EpisodeStatusToken::Completed, None) => EpisodeStatus::Completed,
            (EpisodeStatusToken::Paused, Some(r)) => EpisodeStatus::Paused(
                serde_json::from_str(r)
                    .ok()
                    .and_then(strict_reason)
                    .ok_or_else(|| EpisodeRefusal::Malformed("malformed pause reason".into()))?,
            ),
            (EpisodeStatusToken::Invalidated, Some(r)) => EpisodeStatus::Invalidated(InvalidationReason::from_json(r)?),
            (t, r) => {
                return Err(EpisodeRefusal::Malformed(format!(
                    "status '{}' {} a reason",
                    t.as_token(),
                    if r.is_some() { "carries" } else { "lacks" }
                )))
            }
        })
    }
    /// The reason column's value: `Some` exactly for `paused` / `invalidated`.
    pub fn reason_json(&self) -> Option<String> {
        match self {
            EpisodeStatus::Paused(r) => Some(serde_json::to_string(r).expect("a closed unit enum serializes")),
            EpisodeStatus::Invalidated(r) => Some(r.to_json()),
            _ => None,
        }
    }
}

/// The head row a reader gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Episode {
    pub plan_id: crate::plan::PlanId,
    /// An opaque id minted at start by the store's id minter.
    pub episode_id: String,
    pub status: EpisodeStatus,
    /// 1 at start; every write adds 1, under a compare-and-set on the value the writer read.
    pub generation: u64,
    /// The store's `control_epoch` when the episode started.
    pub claim_epoch: i64,
    pub started_at: String,
    /// The durable preflight `ready` marker: `record()` admits a plan child only once it is set.
    pub ready_at: Option<String>,
    /// Set when the episode completes.
    pub completed_at: Option<String>,
}

/// What `start_episode` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpisodeStart {
    Started(Episode),
    /// The plan's non-terminal episode already exists and is returned as read (the call's only
    /// write is the sticky clock's latch advance).
    Resumed(Episode),
}

/// What `mark_ready` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyOutcome {
    Ready,
    /// `ready_at` was already set — nothing written.
    AlreadyReady,
}

/// What `complete_episode_if_done` decided, in one transaction (an exact count of members).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// Every member holds a terminal child: the episode is now `completed`.
    Completed,
    /// Work is outstanding: `total` members, `minted` of them with a child row, `terminal` of
    /// them with a terminal child. No episode write (evaluating an active episode does advance
    /// the sticky clock's latch).
    Incomplete { total: u64, minted: u64, terminal: u64 },
    /// Work was outstanding at or past the plan's expiry: the episode is now
    /// `invalidated{expired}`, the durable abandonment bound.
    Invalidated(InvalidationReason),
    /// The episode was already terminal — nothing written.
    AlreadyTerminal(EpisodeStatusToken),
    /// The plan has no episode — nothing written.
    NoEpisode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transition_table_is_the_only_legality_and_every_illegal_edge_names_its_triple() {
        assert!(assert_transition(EpisodeStatusToken::Active, EpisodeStatusToken::Completed).is_ok());
        assert!(assert_transition(EpisodeStatusToken::Active, EpisodeStatusToken::Paused).is_ok());
        assert!(assert_transition(EpisodeStatusToken::Paused, EpisodeStatusToken::Active).is_ok());
        assert!(assert_transition(EpisodeStatusToken::Paused, EpisodeStatusToken::Invalidated).is_ok());
        assert_eq!(assert_transition(EpisodeStatusToken::Completed, EpisodeStatusToken::Active).unwrap_err(), EpisodeRefusal::IllegalTransition { from: EpisodeStatusToken::Completed, to: EpisodeStatusToken::Active });
        assert!(assert_transition(EpisodeStatusToken::Cancelled, EpisodeStatusToken::Completed).is_err(), "a cancelled plan can never complete");
        assert!(assert_transition(EpisodeStatusToken::Invalidated, EpisodeStatusToken::Active).is_err());
        assert!(assert_transition(EpisodeStatusToken::Paused, EpisodeStatusToken::Completed).is_err(), "a paused episode resumes before it completes");
        // Every pair is legal EXACTLY when it is a row of the table.
        for from in EpisodeStatusToken::ALL {
            for to in EpisodeStatusToken::ALL {
                assert_eq!(assert_transition(from, to).is_ok(), TRANSITIONS.contains(&(from, to)), "{from:?} -> {to:?}");
            }
        }
        // Terminal set = exactly {cancelled, completed, invalidated}.
        let terminal: Vec<_> = EpisodeStatusToken::ALL.iter().filter(|s| s.is_terminal()).collect();
        assert_eq!(terminal, vec![&EpisodeStatusToken::Cancelled, &EpisodeStatusToken::Completed, &EpisodeStatusToken::Invalidated]);
        // …and `is_terminal` is DERIVED from the table, not a second hand-written list: its body
        // reads `TRANSITIONS` (a behaviourally-equal hand-written list would pass the assertion
        // above today and drift the day a row is added).
        let src = include_str!("episode.rs");
        let body_at = src.find("pub fn is_terminal(self) -> bool {").expect("is_terminal is defined here");
        let body = &src[body_at..body_at + src[body_at..].find("\n    }").expect("the body ends")];
        assert!(body.contains("TRANSITIONS"), "is_terminal must derive from TRANSITIONS: {body}");
    }

    /// The `attempt.rs` / `plan.rs` closed-vocabulary guard, copied: the CHECK list is read out of
    /// the DDL the store executes (`store_open::schema_ddl()`), bounded to ONE table's statement.
    fn ddl_table_section(table: &str) -> String {
        let ddl = crate::store_open::schema_ddl();
        let anchor = format!("CREATE TABLE IF NOT EXISTS {table} (");
        let start = ddl.find(&anchor).unwrap_or_else(|| panic!("schema_ddl() must carry the table {table}"));
        let rest = &ddl[start..];
        let end = rest.find(");").expect("the CREATE TABLE statement terminates");
        rest[..end].to_string()
    }
    fn ddl_check_list(table: &str, anchor: &str) -> Vec<String> {
        let section = ddl_table_section(table);
        let start = section.find(anchor).unwrap_or_else(|| panic!("{table} must carry the CHECK constraint {anchor}"));
        let rest = &section[start + anchor.len()..];
        let end = rest.find("))").expect("the CHECK list must terminate");
        let mut tokens: Vec<String> = rest[..end].split(',').map(|t| t.trim().trim_matches('\'').to_string()).filter(|t| !t.is_empty()).collect();
        tokens.sort();
        tokens
    }

    #[test]
    fn tokens_round_trip_and_the_ddl_check_is_regenerated_from_the_enum() {
        for s in EpisodeStatusToken::ALL {
            assert_eq!(EpisodeStatusToken::from_token(s.as_token()), Some(s));
        }
        assert_eq!(EpisodeStatusToken::from_token("done"), None, "the vocabulary is closed");
        for e in EpisodeEvent::ALL {
            assert_eq!(EpisodeEvent::from_token(e.as_token()), Some(e));
        }
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let statuses = sorted(EpisodeStatusToken::ALL.iter().map(|s| s.as_token().to_string()).collect());
        assert_eq!(statuses, ddl_check_list("execution_episode", "CHECK (status IN ("), "EpisodeStatusToken and the execution_episode CHECK have drifted");
        assert_eq!(statuses, ddl_check_list("episode_journal", "CHECK (status IN ("), "EpisodeStatusToken and the episode_journal CHECK have drifted");
        assert_eq!(
            sorted(EpisodeEvent::ALL.iter().map(|e| e.as_token().to_string()).collect()),
            ddl_check_list("episode_journal", "CHECK (event IN ("),
            "EpisodeEvent and the episode_journal CHECK have drifted"
        );
        // The plan's literal pin: the status CHECK spells the enum in ALL's order.
        let check = format!("status IN ({})", EpisodeStatusToken::ALL.iter().map(|s| format!("'{}'", s.as_token())).collect::<Vec<_>>().join(","));
        assert!(crate::store_open::schema_ddl().contains(&check), "DDL: {check}");
    }

    #[test]
    fn typed_reasons_serialize_content_free_and_round_trip() {
        let r = InvalidationReason::StalePreflight { diverged: vec![(String::from("m1"), vec![crate::attempt::MemberDiff { atom: "membership:INBOX".into(), expected: true, observed: Some(false) }])] };
        let json = r.to_json();
        assert_eq!(InvalidationReason::from_json(&json).unwrap(), r);
        assert!(!json.contains('@'));
        assert_eq!(InvalidationReason::from_json("{\"kind\":\"nope\"}").unwrap_err(), EpisodeRefusal::Malformed("unknown invalidation kind 'nope'".into()));
        for r in [InvalidationReason::EpochMismatch { plan: 1, current: 2 }, InvalidationReason::Expired, InvalidationReason::GrantRetired] {
            assert_eq!(InvalidationReason::from_json(&r.to_json()).unwrap(), r);
            assert!(InvalidationReason::KINDS.contains(&r.kind()), "{r:?}");
        }
        assert_eq!(InvalidationReason::KINDS.len(), 4);
        // A known kind with a body this writer cannot have produced, and text that is not a
        // reason at all, are Malformed — never a default.
        for bad in [r#"{"kind":"expired","extra":1}"#, r#"{"kind":"epoch_mismatch","plan":1}"#, "[]", "not json", r#"{"plan":1}"#] {
            assert!(matches!(InvalidationReason::from_json(bad), Err(EpisodeRefusal::Malformed(_))), "{bad}");
        }
        // The typed status rebuilds from its two columns, and refuses a token/reason mismatch.
        let invalidated = EpisodeStatus::Invalidated(InvalidationReason::Expired);
        assert_eq!(EpisodeStatus::from_columns("invalidated", invalidated.reason_json().as_deref()).unwrap(), invalidated);
        assert_eq!(EpisodeStatus::from_columns("active", None).unwrap(), EpisodeStatus::Active);
        let paused = EpisodeStatus::Paused(PauseReason::Anomaly);
        assert_eq!(EpisodeStatus::from_columns("paused", paused.reason_json().as_deref()).unwrap(), paused);
        assert!(matches!(EpisodeStatus::from_columns("invalidated", None), Err(EpisodeRefusal::Malformed(_))));
        assert!(matches!(EpisodeStatus::from_columns("active", Some(r#"{"kind":"expired"}"#)), Err(EpisodeRefusal::Malformed(_))));
        assert!(matches!(EpisodeStatus::from_columns("done", None), Err(EpisodeRefusal::Malformed(_))));
        assert!(matches!(EpisodeStatus::from_columns("paused", Some(r#"{"kind":"operator","extra":1}"#)), Err(EpisodeRefusal::Malformed(_))));
        assert!(matches!(EpisodeStatus::from_columns("paused", Some(r#"{"kind":"nope"}"#)), Err(EpisodeRefusal::Malformed(_))));
        for s in [EpisodeStatus::Active, paused, EpisodeStatus::Cancelled, EpisodeStatus::Completed, invalidated] {
            assert_eq!(EpisodeStatus::from_columns(s.token().as_token(), s.reason_json().as_deref()).unwrap(), s);
        }
    }
}
