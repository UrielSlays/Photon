//! Pre-state capture types. Content-free by construction: native identities, atom keys and
//! freshness provenance, never bodies, subjects, headers, or snippets.

use std::collections::{BTreeMap, BTreeSet};

/// Compiled undo-offer window of 7 days. A recorded-config knob may replace it later.
pub const UNDO_OFFER_SECONDS: u64 = 604_800;

/// The single encoding for a provider-native resource key. Every construction of a
/// [`FrozenBasis::native_resource_key`] or an [`Observation::native_resource_key`] goes through
/// here, in every connector and every fixture.
///
/// Joining components with `/` (`format!("jmap:{account}/{email}")`) is not injective: provider
/// ids are opaque, so `(account="a/b", email="c")` and `(account="a", email="b/c")` both spell
/// `jmap:a/b/c`. The key is compared by string equality everywhere (the rebind check, the head
/// predicate's native lane, the recovery barrier), so a resolver rebind between two such pairs
/// would pass every check and dispatch against the wrong message. The fix is one injective
/// encoding, not a charset promise from any provider.
///
/// Distinct `(provider, components)` vectors produce distinct strings: the encoding is a
/// canonical JSON array of the provider tag followed by the components. JSON string escaping
/// makes it total (the delimiters `"`, `,`, `[`, `]` are exactly the bytes JSON escapes inside a
/// string, so no component can forge one) and `serde_json`'s serialization of a `&[&str]` is
/// deterministic, so length is never needed as a disambiguator.
///
/// The result is opaque above this function: used for equality and indexing, never parsed back
/// apart. Callers that want the components keep them (the operands live in `touched_atoms`).
pub fn native_resource_key(provider: &str, components: &[&str]) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(components.len() + 1);
    parts.push(provider);
    parts.extend_from_slice(components);
    // `&[&str]` always serializes (no non-string map keys, no non-finite floats).
    serde_json::to_string(&parts).expect("a JSON array of strings always serializes")
}

/// The admission-frozen native basis (`intents.frozen_basis`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenBasis {
    /// Provider-scoped native resource key, the durable ordering key, scoped exactly as the
    /// provider scopes identity, e.g. `gmail:<user>/<msg-id>` or `jmap:<account-id>/<email-id>`.
    pub native_resource_key: String,
    /// Primitive touched atoms mapped to the resolved native operand each is carried by, e.g.
    /// `membership:INBOX` to `INBOX` (Gmail label), `membership:<mailbox-id>` to
    /// `<mailbox-id>` (JMAP), `keyword:$seen` to `$seen`.
    pub touched_atoms: BTreeMap<String, String>,
    /// The value each touched atom holds after the forward action applies (`A` in the
    /// requalification table), frozen at resolve time. Only the resolver knows role direction,
    /// and re-resolving at undo time is the rebind the basis check forbids. Serde default: rows
    /// admitted before capture carried targets parse as empty, and the undo path answers those
    /// with a named refusal (`PredatesSubstrate`-class), never a guess.
    #[serde(default)]
    pub atom_targets: BTreeMap<String, bool>,
    /// The role-to-id mapping frozen at admission, the only place role direction is knowable
    /// (see `resolve_basis`); empty for connectors whose atoms are provider constants (Gmail).
    /// The basis identity check compares this map, never an unordered id set: a role-set
    /// permutation that preserves the id set still fails it. Connector-agnostic strings
    /// (lowercase role name such as "inbox"/"archive", mapped to the resolved operand id), so
    /// this type does not depend on any connector's role enum, like `touched_atoms`.
    #[serde(default)]
    pub role_bindings: BTreeMap<String, String>,
    /// Freshness provenance of the resolution.
    pub freshness: Freshness,
}

/// Freshness provenance. Value equality alone is never freshness: where the provider issues a
/// state cursor, the cursor is the evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// The resolved identities are provider-immutable constants (Gmail system labels: literal
    /// constants, nothing to cache).
    ImmutableConstants,
    /// A provider-issued state cursor for the resolved namespace (JMAP RFC 8621 Mailbox
    /// state).
    StateCursor { cursor: String },
}

impl FrozenBasis {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// The structural well-formedness check, shared by every entry point.
    ///
    /// A basis with an empty native key cannot key the resource tail (the native key is the
    /// durable ordering key), and one with no touched atoms names nothing to observe, verify or
    /// restore. Neither is a basis at all.
    ///
    /// Called by [`FrozenBasis::from_json`] on the way in from storage and by the admission
    /// boundary on the way in from a connector, so the two directions cannot drift: a shape the
    /// parser refuses cannot be committed by a resolver that skipped the round-trip.
    pub fn validate(&self) -> Result<(), String> {
        if self.native_resource_key.is_empty() {
            return Err("frozen_basis: empty native_resource_key".into());
        }
        if self.touched_atoms.is_empty() {
            return Err("frozen_basis: no touched atoms".into());
        }
        // Cardinality is not well-formedness. `{"":""}` is a nonempty map that names nothing:
        // an empty atom key would satisfy the coverage check while describing no touched label
        // (a false restoration record), and an empty resolved operand resolves nothing.
        for (atom, operand) in &self.touched_atoms {
            if atom.is_empty() {
                return Err("frozen_basis: empty touched-atom key".into());
            }
            if operand.is_empty() {
                return Err(format!("frozen_basis: atom '{atom}' has an empty resolved operand"));
            }
        }
        // An empty state cursor is "freshness evidence" that evidences nothing.
        if let Freshness::StateCursor { cursor } = &self.freshness {
            if cursor.is_empty() {
                return Err("frozen_basis: empty freshness state cursor".into());
            }
        }
        // When the target vector is present its key set must equal the touched atoms, in both
        // directions (as `JournalRow::validate` does): a target for an untouched atom is a
        // smuggling channel, and a touched atom without a target makes the requalification
        // table undecidable. Empty means a legacy row, which is legal at the storage tier; the
        // admission tier below refuses it for new rows.
        if !self.atom_targets.is_empty() && !self.atom_targets.keys().eq(self.touched_atoms.keys()) {
            return Err("frozen_basis: atom_targets keys do not equal the touched atom set".into());
        }
        // `role_bindings` freezes the role-to-id mapping, the only place role direction is
        // knowable (`resolve_basis`), so the basis check can refuse a role permutation that
        // preserves the id set but inverts the role-to-id mapping. When present, every id it
        // names must be non-empty and an operand in `touched_atoms` (the frozen role ids are
        // membership operands); a binding to an id the action never touched is a smuggling
        // channel, as an out-of-set atom_target is. Empty means a keyword-verb basis or a
        // legacy row (storage tier); tolerated here, required for a move verb by the JMAP
        // connector, never globally.
        if !self.role_bindings.is_empty() {
            let operands: BTreeSet<&str> = self.touched_atoms.values().map(String::as_str).collect();
            for id in self.role_bindings.values() {
                if id.is_empty() || !operands.contains(id.as_str()) {
                    return Err("frozen_basis: role_bindings id not in touched_atoms".into());
                }
            }
        }
        Ok(())
    }

    /// The admission-tier check: `validate()` plus the requirement that a new basis carries the
    /// forward target vector `A` (a row admitted without it cannot answer the requalification
    /// table or the no-op check later). Storage-tier parsing stays `validate()` so legacy rows
    /// remain readable.
    pub fn validate_for_admission(&self) -> Result<(), String> {
        self.validate()?;
        if self.atom_targets.is_empty() {
            return Err("frozen_basis: no atom_targets (the forward target vector A is required at admission)".into());
        }
        Ok(())
    }

    /// Strict parse; a basis with an empty native key or no atoms is not well-formed (the
    /// open-time integrity scan and prepare both rely on this). The structural rules live in
    /// [`FrozenBasis::validate`]; this is deserialization plus that check.
    pub fn from_json(s: &str) -> Result<Self, String> {
        let b: FrozenBasis = serde_json::from_str(s).map_err(|e| e.to_string())?;
        b.validate()?;
        Ok(b)
    }

    /// Test seam: an empty basis, a placeholder for a connector that never reads the basis.
    /// Not well-formed: it has no touched atoms, so [`FrozenBasis::validate`] refuses it.
    #[cfg(test)]
    pub(crate) fn for_test_empty() -> Self {
        Self {
            native_resource_key: "gmail:u:m".to_string(),
            touched_atoms: BTreeMap::new(),
            atom_targets: BTreeMap::new(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        }
    }

    /// Test seam: a valid, admissible Trash basis, the shape the Gmail resolver freezes for
    /// `Action::Trash` (`label:TRASH` to `TRASH`, `membership:INBOX` to `INBOX`; forward targets
    /// TRASH set, INBOX cleared; no role bindings; provider constants). Unlike
    /// [`FrozenBasis::for_test_empty`] it passes [`FrozenBasis::validate_for_admission`], so
    /// `record` accepts it.
    #[cfg(test)]
    pub(crate) fn for_test_trash() -> Self {
        Self {
            native_resource_key: "gmail:u:m".to_string(),
            touched_atoms: [
                ("label:TRASH".to_string(), "TRASH".to_string()),
                ("membership:INBOX".to_string(), "INBOX".to_string()),
            ]
            .into_iter()
            .collect(),
            atom_targets: [
                ("label:TRASH".to_string(), true),
                ("membership:INBOX".to_string(), false),
            ]
            .into_iter()
            .collect(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        }
    }
}

/// The at-rest encoding of a provider label vector: a canonical JSON array of the label ids in
/// `BTreeSet` order (sorted, one entry per label), so one set always spells the same bytes.
/// Every stored vector goes through here: `pre_state.observed_label_vector`,
/// `intents.effect_label_vector`, `intents.ripple_unexpected`.
pub fn label_vector_json(labels: &BTreeSet<String>) -> String {
    serde_json::to_string(labels).expect("a JSON array of strings always serializes")
}

/// The strict inverse of [`label_vector_json`]: a stored value that is not exactly the
/// canonical array of some set (not JSON, not an array of strings, unsorted, duplicated,
/// re-spaced) is corruption and refuses. Never a silent `None`, never a quietly re-sorted set.
/// The message names the field only (label ids are provider data and stay out of error text).
pub fn parse_label_vector(field: &str, raw: &str) -> Result<BTreeSet<String>, String> {
    let labels: BTreeSet<String> = serde_json::from_str::<Vec<String>>(raw)
        .map_err(|_| format!("{field}: not a JSON array of label ids"))?
        .into_iter()
        .collect();
    if label_vector_json(&labels) != raw {
        return Err(format!(
            "{field}: not the canonical (sorted, de-duplicated) label array"
        ));
    }
    Ok(labels)
}

/// Did any label outside the declared closure differ between the capture's observe read and the
/// route's answer? The route's own ripple and any other writer in that interval both land here;
/// the verdict does not tell them apart. The `pre` vector is the journal row's observe read,
/// taken at prepare (which never re-captures) or at a retry's re-prepare through
/// `replace_journal_row`; nothing re-reads it at effect time. The verdict is judged over the
/// delta between the pre-effect vector (the observe read) and the post-effect vector (the
/// route's response), never over the whole sets: an unchanged atom outside the closure is not a
/// ripple. `OutsideClosure` marks the restoration claim undetermined for this operation: the
/// undo presentation (`CommandBus::undo_presentation`) reads `IntentLog::effect_witness` and
/// shows `OutsideClosure`, a row with no verdict, or a NULL witness on an operation whose
/// forward effect landed as restoration undetermined (`crate::RestorationVerdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RippleVerdict {
    WithinClosure,
    OutsideClosure { unexpected: std::collections::BTreeSet<String> },
}

impl RippleVerdict {
    pub fn as_token(&self) -> &'static str {
        match self {
            RippleVerdict::WithinClosure => "within_closure",
            RippleVerdict::OutsideClosure { .. } => "outside_closure",
        }
    }

    /// The verdict as its two `intents` columns: the token ([`RippleVerdict::as_token`]) and,
    /// for `outside_closure` only, the canonical array of the unexpected labels. The table's
    /// CHECK pairs the two, so the enum reads back whole ([`RippleVerdict::from_columns`]).
    pub fn to_columns(&self) -> (&'static str, Option<String>) {
        match self {
            RippleVerdict::WithinClosure => (self.as_token(), None),
            RippleVerdict::OutsideClosure { unexpected } => {
                (self.as_token(), Some(label_vector_json(unexpected)))
            }
        }
    }

    /// The strict inverse of [`RippleVerdict::to_columns`]. `(None, None)` means no verdict was
    /// judged; every pairing `to_columns` cannot produce (an unknown token, a token without its
    /// set or a set without its token, an `outside_closure` naming no label) is corruption.
    pub fn from_columns(
        token: Option<&str>,
        unexpected: Option<&str>,
    ) -> Result<Option<Self>, String> {
        match (token, unexpected) {
            (None, None) => Ok(None),
            (Some("within_closure"), None) => Ok(Some(RippleVerdict::WithinClosure)),
            (Some("outside_closure"), Some(raw)) => {
                let unexpected = parse_label_vector("ripple_unexpected", raw)?;
                if unexpected.is_empty() {
                    return Err("ripple_unexpected: an outside_closure verdict names no label".into());
                }
                Ok(Some(RippleVerdict::OutsideClosure { unexpected }))
            }
            _ => Err("ripple_verdict: the stored token and ripple_unexpected are not a verdict".into()),
        }
    }
}

pub fn ripple_verdict(
    pre: &std::collections::BTreeSet<String>,
    post: &std::collections::BTreeSet<String>,
    closure: &std::collections::BTreeSet<String>,
) -> RippleVerdict {
    let changed: std::collections::BTreeSet<String> = pre.symmetric_difference(post).cloned().collect();
    let unexpected: std::collections::BTreeSet<String> = changed.difference(closure).cloned().collect();
    if unexpected.is_empty() {
        RippleVerdict::WithinClosure
    } else {
        RippleVerdict::OutsideClosure { unexpected }
    }
}

/// Is this a Gmail system label id? These are the reserved all-caps names (`INBOX`, `TRASH`,
/// `IMPORTANT`, `CATEGORY_*`, ...), locale-independent and safe to name. User labels are
/// provider-native `Label_<n>` ids and are never named on a caller surface. This is the same
/// predicate, byte for byte, as `is_system_label` / `sanitize_minimal_capture` in
/// `crates/aruna-gmail/tests/live_readside.rs`; that copy is local to an integration test
/// binary and cannot be imported, so this is the one the engine and the shell use.
pub fn is_system_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A label set in its reduced form: the system labels named (in the set's order) and the user
/// labels counted, never named ([`is_system_label`]). This is what a restoration verdict may
/// show a caller about the labels that rippled.
pub fn banked_label_split(labels: &std::collections::BTreeSet<String>) -> (Vec<String>, usize) {
    let named: Vec<String> = labels.iter().filter(|l| is_system_label(l)).cloned().collect();
    let counted = labels.len() - named.len();
    (named, counted)
}

/// What `Connector::observe` read (provider read, outside any write transaction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The native resource key the provider answered for (the input to basis verification).
    pub native_resource_key: String,
    /// Current value of each touched atom (atom key to present/set).
    pub atoms: BTreeMap<String, bool>,
    /// Provider request id, if surfaced.
    pub request_id: Option<String>,
    /// The full provider label set the read returned, beside the `atoms` projection: label ids,
    /// not atoms (the same separation as [`crate::EffectWitness`]). Gmail's `observe` sets it;
    /// `None` means the connector's read yields no such set (JMAP, the fixtures), never an
    /// empty set.
    pub provider_label_vector: Option<std::collections::BTreeSet<String>>,
}

/// The row prepare inserts. `journal_id` is minted inside the insert transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRow {
    /// Typed observed projection, content-free JSON (atom key to bool).
    pub observed: String,
    /// The touched atom(s) and captured value `P`, the same shape as `observed` for the
    /// single and pair Boolean atoms; kept as its own field.
    pub touched_atom: String,
    /// Frozen provider operand ids (copied from the basis; JSON map).
    pub resolved_operands: String,
    pub request_id: Option<String>,
    /// The full provider label vector the capture's observe read returned
    /// ([`Observation::provider_label_vector`]), the pre-effect vector the ripple check judges
    /// against, as a [`label_vector_json`] canonical array. `None` means the read yielded no
    /// vector. Not an atom map: [`JournalRow::validate`] does not read it; its own read
    /// boundary is [`JournalRow::observed_label_vector_set`].
    pub observed_label_vector: Option<String>,
}

impl JournalRow {
    /// The stored observed label vector as a set, through the strict [`parse_label_vector`]:
    /// `Ok(None)` when absent; a stored value that is not the canonical array is a `LogError`,
    /// never a silent `None`.
    pub fn observed_label_vector_set(&self) -> Result<Option<BTreeSet<String>>, crate::LogError> {
        self.observed_label_vector
            .as_deref()
            .map(|raw| parse_label_vector("journal row: observed_label_vector", raw))
            .transpose()
            .map_err(crate::LogError)
    }

    /// Structural well-formedness against the intent's frozen basis: the prepare-boundary twin
    /// of [`FrozenBasis::validate`]. The journal row is the prepare phase, so a malformed or
    /// basis-mismatched row committed by a direct `IntentLog::prepare` caller would flip
    /// `prepared()` true and make recovery skip the real observation, producing a false
    /// restoration record. Both `prepare` impls call this inside the insert path, so the
    /// boundary never persists a row it could not honor: `observed`/`touched_atom` must be
    /// non-empty Boolean maps whose keys equal the frozen atoms (the coverage check, repeated
    /// where the row becomes durable), and `resolved_operands` must equal the admission-frozen
    /// operand map exactly.
    pub fn validate(&self, basis: &FrozenBasis) -> Result<(), String> {
        let parse_bool_map = |field: &str, s: &str| -> Result<BTreeMap<String, bool>, String> {
            let m: BTreeMap<String, bool> = serde_json::from_str(s)
                .map_err(|e| format!("journal row: {field} is not a Boolean atom map ({e})"))?;
            if m.is_empty() {
                return Err(format!("journal row: {field} observes nothing"));
            }
            if m.keys().any(|k| k.is_empty()) {
                return Err(format!("journal row: {field} carries an empty atom key"));
            }
            Ok(m)
        };
        let observed = parse_bool_map("observed", &self.observed)?;
        let touched = parse_bool_map("touched_atom", &self.touched_atom)?;
        // Key-set equality with the frozen atoms, in both directions. Coverage alone (a
        // superset) would admit extra keys: a content-like-key smuggling channel into the
        // content-free journal, and a record claiming atoms the forward command never touched.
        // Equality is what `journal_row_from_observation` produces (exactly the touched atoms);
        // a future operation that observes more than it touches would widen `observed` here,
        // deliberately, and never implicitly.
        for (field, map) in [("observed", &observed), ("touched_atom", &touched)] {
            if !map.keys().eq(basis.touched_atoms.keys()) {
                return Err(format!(
                    "journal row: {field} atoms do not equal the admission-frozen atom set"
                ));
            }
        }
        // Value equality between the two projections, not just key-set equality. Undo reads
        // `touched_atom` as `P` and the no-op check decides `P == A`, so a direct
        // `IntentLog::prepare` caller who kept the keys equal but diverged the values
        // (observed {INBOX:true}, touched_atom {INBOX:false}) could forge `P` to equal `A` and
        // win a false no-op: an undo "verified" without ever restoring. For the single and pair
        // Boolean projections, `journal_row_from_observation` sets both maps to the identical
        // observation, so equal keys with divergent values is a corrupt row. A future operation
        // that observes more than it touches would widen `observed` past `touched_atom`
        // deliberately, as with the key-set rule above. This is a correctness check at the
        // durable-store boundary (a first-party-constructable corrupt row), not a security
        // control.
        if observed != touched {
            return Err(
                "journal row: observed and touched_atom diverge in value (M1 projects them equal)"
                    .into(),
            );
        }
        let operands: BTreeMap<String, String> = serde_json::from_str(&self.resolved_operands)
            .map_err(|e| format!("journal row: resolved_operands is not an operand map ({e})"))?;
        if operands != basis.touched_atoms {
            return Err(
                "journal row: resolved_operands does not equal the admission-frozen operand map"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Outcome of one prepare attempt (insert-or-nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareOutcome {
    /// This call inserted the journal row; the intent is now dispatch-eligible.
    Prepared,
    /// A journal row already exists (crash between prepare and dispatch, or a concurrent
    /// preparer). Never re-capture: post-effect observation poisons no-op detection.
    AlreadyPrepared,
    /// A lower-seq same-native-resource intent is still non-terminal, so this one is not at
    /// the head.
    NotAtHead,
    /// `control_epoch != admitted_control_epoch`: the sever epoch check. The intent parks
    /// (stays `Pending`, undispatched); the sever machinery terminalizes it.
    EpochFenced,
    /// **The operation was closed under this capture** (a defensive check). The row is no
    /// longer pre-dispatch because it is terminal: a sever's atomic closure, or a peer writer's
    /// settlement, committed in the window between the caller's read and this transaction.
    /// That is a normal closure, not store corruption. The caller answers what an identical
    /// replay of the key answers (`CommandBus::status_replay_outcome`) and a sweep skips the
    /// row without raising a barrier, as the claim and authorization paths' own terminal arms
    /// already do.
    ///
    /// The genuinely inconsistent case still fails and is not this variant: a row that is
    /// neither pre-dispatch nor terminal (`Undoing`, the only such state) is a phase prepare
    /// must never meet live, and it returns a `LogError`.
    Closed(crate::IntentStatus),
}

/// Project one verified observation into the row prepare inserts. Content-free: only atom keys
/// and their Boolean values, plus the frozen native operand ids copied from the basis, and
/// nothing the provider said about the message itself.
///
/// `observed` and `touched_atom` carry the same projection for the single and pair Boolean
/// atoms; they are separate fields because a later multi-atom operation will observe more than
/// it touches.
pub fn journal_row_from_observation(obs: &Observation, basis: &FrozenBasis) -> JournalRow {
    let atoms_json = serde_json::to_string(&obs.atoms).expect("BTreeMap<String,bool> serializes");
    JournalRow {
        observed: atoms_json.clone(),
        touched_atom: atoms_json,
        resolved_operands: serde_json::to_string(&basis.touched_atoms).expect("serializes"),
        request_id: obs.request_id.clone(),
        observed_label_vector: obs.provider_label_vector.as_ref().map(label_vector_json),
    }
}

/// Why an undo is unavailable: typed, exhaustive, and mechanically derived (never free text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoUnavailableReason {
    /// The intent's own `journal_required=0`: capture was off for this operation.
    CaptureDisabled,
    /// Now (via the persisted, sticky high-water latch) is past the row's `undo_offer_until`.
    /// The row may well still exist (deletion is dormant): the offer lapsed, the bytes did not.
    /// `tombstoned` adds deletion provenance if deletion ever ran.
    Expired { tombstoned: bool },
    /// The intent predates the pre-state capture (no frozen basis or no target vector).
    PredatesSubstrate,
    /// `journal_required=1`, no row, no tombstone: an integrity failure, rendered as an
    /// integrity warning, never a benign configuration message.
    JournalGapUnexplained,
    /// The operation was caught in a sever's atomic member closure. Terminal and undo-ineligible:
    /// a severed operation carries no verified applied state (the attempt never issued, or the
    /// operation had none at all), so there is nothing to restore.
    Severed,
    /// The operation's operational axis closed via in-place adjudication. Undo-ineligible by
    /// policy while the historical axis is unresolved; an operation whose historical axis later
    /// resolves `Applied` via a `LATE_ACK_APPLIED` stays undo-ineligible too (its journal row
    /// may have expired and its resource may hold a successor). The resolved-versus-unresolved
    /// distinction in the surfaced reason belongs to the fact grammar, not this enum.
    Adjudicated,
    /// The retry-requalification `C == A` no-op terminal: the forward target was already
    /// produced by another actor. Terminal and undo-ineligible: a stale captured `P` must never
    /// reverse the other actor's change.
    ExternallySatisfied,
}

/// Requalification decision over Boolean atom maps (`P` = captured, `A` = frozen forward
/// target, `C` = observed current). Runs only when `P != A`; the no-op check runs first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequalifyDecision {
    /// `C == A`: the forward result still holds, so dispatch the delta restore (write `P`).
    Restore,
    /// `C == P`: the pre-state already holds, so this is a terminal no-op undo, recorded, with
    /// no dispatch.
    AlreadyRestored,
    /// Neither (reachable only for multi-atom pairs): refuse, never blind-write.
    Conflict,
}

/// The no-op check: `P == A`, decided from the journal row and the admission-frozen target
/// vector alone. No provider read, no dispatch.
pub fn noop_kill(p: &BTreeMap<String, bool>, a: &BTreeMap<String, bool>) -> bool {
    p == a
}

/// The three-way requalification table. `C == A` wins the first comparison; when `P == A` the
/// caller never reaches here (the no-op check fired).
pub fn requalify(
    p: &BTreeMap<String, bool>,
    a: &BTreeMap<String, bool>,
    c: &BTreeMap<String, bool>,
) -> RequalifyDecision {
    if c == a {
        RequalifyDecision::Restore
    } else if c == p {
        RequalifyDecision::AlreadyRestored
    } else {
        RequalifyDecision::Conflict
    }
}

/// The requalification table read for a forward retry.
///
/// One table has two readings. The undo reading asks "may I put `P` back?"; the retry reading
/// asks "is the capture I am about to dispatch against still truthful?". The three comparisons
/// are the same, with different names for the answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryRequalifyDecision {
    /// `C == P`: the provider still looks the way it looked when the capture was taken, so the
    /// existing capture is still truthful and the retry proceeds on the existing row. No
    /// re-capture (the never-re-capture rule is untouched) and no new row. **This comparison is
    /// made first**, which covers the `P == A`-and-unchanged world without a pre-guard.
    ProceedOnCapturedRow,
    /// `C == A`: the forward target already holds, because another actor produced it during the
    /// retry gap. The retry completes as a durable no-op terminal that marks the operation
    /// undo-ineligible, because a stale `P` must never reverse the other actor's change.
    ExternallySatisfied,
    /// Neither: the world moved somewhere the capture cannot describe. Re-prepare: one
    /// versioned atomic replace of the journal row, the one narrow exception to prepare's
    /// insert-or-nothing rule.
    RePrepare,
}

/// The requalification table under its retry reading: the same three comparisons as
/// [`requalify`], in the order this reading's question demands. **Total: it has no
/// precondition.**
///
/// **Why the order differs from the undo reading, which is the safety argument.** Undo asks "may
/// I put `P` back?", so `C == A` (the forward result still holds) wins first. Retry asks "is the
/// capture I am about to dispatch against still truthful?", which is `C == P`, so it is asked
/// first.
///
/// With `C == A` first, a `P == A` world would always answer `ExternallySatisfied`, which forced
/// a `P != A` precondition enforced by a `noop_kill` pre-guard at the call site. That pre-guard
/// short-circuited such a retry to "proceed" without observing the provider, a hole: another
/// actor can move the provider off `A` during the retry gap, the blind retry then makes a real
/// change, and undo stays killed by the `P == A` test, so the other actor's state is
/// unrestorable. With `C == P` first, the unchanged `P == A` world answers `ProceedOnCapturedRow`
/// (the pre-guard's answer) by observing that the world is unchanged, and the moved world falls
/// through to `RePrepare`.
///
/// The two readings agree wherever both are defined: for `P != A` the branches are mutually
/// exclusive, so order cannot change the answer. It changes the answer only for `P == A`, which
/// the undo reading never sees (the no-op check fires first there).
pub fn requalify_retry(
    p: &BTreeMap<String, bool>,
    a: &BTreeMap<String, bool>,
    c: &BTreeMap<String, bool>,
) -> RetryRequalifyDecision {
    if c == p {
        RetryRequalifyDecision::ProceedOnCapturedRow
    } else if c == a {
        RetryRequalifyDecision::ExternallySatisfied
    } else {
        RetryRequalifyDecision::RePrepare
    }
}

/// A store-agnostic view of the journal row for eligibility derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedJournalView {
    pub p: BTreeMap<String, bool>,
    pub undo_offer_until: String,
}

/// The undo eligibility outcome: eligible (carrying `P`) or unavailable with its mechanical
/// reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoEligibility {
    Eligible { p: BTreeMap<String, bool> },
    Unavailable(UndoUnavailableReason),
}

/// The undo-eligibility derivation: typed, exhaustive, mechanical. The checks run in order:
/// capture off, then pre-state capture, then the offer deadline (sticky effective now; a
/// tombstone adds provenance), then the journal gap (an error). RFC 3339 UTC strings compare
/// lexicographically.
///
/// Precondition: `effective_now` and any journal's `undo_offer_until` are canonical
/// ([`is_canonical_rfc3339_utc`]), enforced at the store boundary, where a malformed persisted
/// value fails instead of reaching this comparison. The function stays total anyway: see the
/// fail-closed arm below.
pub fn derive_undo_eligibility(
    journal_required: bool,
    has_target_vector: bool,
    journal: Option<CapturedJournalView>,
    tombstoned: bool,
    effective_now: &str,
) -> UndoEligibility {
    use UndoUnavailableReason as R;
    // Ambiguous-clock rule, as a second line of defense: an instant this comparison cannot
    // order is an ambiguous clock, and an ambiguous clock evaluates fail-closed, never "still
    // offered". Normally unreachable (the store boundary already refused the row), but the
    // pure function owes any future caller the safe answer rather than an ordering over
    // garbage, where `"2026-…" < "invalid"` reads as an open offer.
    if !is_canonical_rfc3339_utc(effective_now)
        || journal
            .as_ref()
            .is_some_and(|j| !is_canonical_rfc3339_utc(&j.undo_offer_until))
    {
        return UndoEligibility::Unavailable(R::Expired { tombstoned });
    }
    if !journal_required {
        return UndoEligibility::Unavailable(R::CaptureDisabled);
    }
    if !has_target_vector {
        return UndoEligibility::Unavailable(R::PredatesSubstrate);
    }
    match journal {
        Some(j) if effective_now > j.undo_offer_until.as_str() => {
            UndoEligibility::Unavailable(R::Expired { tombstoned })
        }
        Some(j) => UndoEligibility::Eligible { p: j.p },
        None if tombstoned => UndoEligibility::Unavailable(R::Expired { tombstoned: true }),
        None => UndoEligibility::Unavailable(R::JournalGapUnexplained),
    }
}

/// The canonical-timestamp shape check: is `s` exactly what [`rfc3339_utc`] emits
/// (`YYYY-MM-DDTHH:MM:SSZ`, 20 bytes, fixed positions), and therefore a value over which
/// lexicographic order is time order?
///
/// The two persisted instants the undo-eligibility derivation compares, the offer deadline
/// (`pre_state.undo_offer_until`) and the sticky-clock latch (`time_high_water.max_seen`), are
/// bare TEXT columns, so they must clear this at the store boundary or the read fails (closed). A
/// malformed deadline must never reach a lexicographic compare, where `"2026-…" < "invalid"`
/// would read as "the offer is still open"; a malformed latch is the same exposure through SQL
/// `MAX()`.
///
/// **No stored timestamp participates in a comparison, `MAX`, or decision without clearing this
/// at its read boundary.** The rule is on the read, not the computed result, because corruption
/// in a lexicographic order is directional: validating only what a `MAX` returned catches values
/// that sort high and silently overwrites those that sort low, destroying the evidence the sticky
/// expiry invariant rests on.
///
/// The check is "what `rfc3339_utc` can emit", not "a valid civil date": ranges only (month
/// 01-12, day 01-31, hour < 24, minute/second < 60), no leap-year arithmetic. Fixed width inside
/// those ranges orders correctly, which is the only property the comparison needs.
pub fn is_canonical_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return false;
    }
    if b[19] != b'Z' {
        return false;
    }
    // Every remaining position is a digit, checked before any of them is read as a number.
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !b[i].is_ascii_digit() {
            return false;
        }
    }
    let two = |i: usize| (b[i] - b'0') as u32 * 10 + (b[i + 1] - b'0') as u32;
    let (month, day, hour, minute, second) = (two(5), two(8), two(11), two(14), two(17));
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60
}

/// Minimal RFC 3339 UTC formatter (no chrono dependency; civil-from-days, Howard Hinnant's
/// algorithm). Seconds precision; stored as TEXT.
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let secs = unix_secs % 86_400;
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// The exact inverse of [`rfc3339_utc`]: canonical instant to Unix seconds (civil-to-days,
/// Howard Hinnant's algorithm, the mirror of the emitter's days-to-civil).
///
/// It exists to compute an instant that is `n` seconds after a stored one, so the comparison
/// itself can stay a lexicographic compare of two canonical strings (the rule every time-typed
/// decision in this engine follows). Nothing here compares; it converts.
///
/// `None` for anything [`is_canonical_rfc3339_utc`] refuses: a stored timestamp that cannot
/// clear the shape check never becomes a number, and its caller must fail closed rather than
/// do arithmetic over garbage.
pub fn unix_secs_from_rfc3339_utc(s: &str) -> Option<u64> {
    if !is_canonical_rfc3339_utc(s) {
        return None;
    }
    let b = s.as_bytes();
    let n = |i: usize, len: usize| -> i64 {
        b[i..i + len]
            .iter()
            .fold(0i64, |acc, d| acc * 10 + (d - b'0') as i64)
    };
    let (y, m, d) = (n(0, 4), n(5, 2), n(8, 2));
    let (h, mi, sec) = (n(11, 2), n(14, 2), n(17, 2));
    // days_from_civil: the emitter's civil_from_days, run backwards.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec;
    let unix = u64::try_from(secs).ok()?;
    // The shape check covers digit ranges, not civil validity: a shape-valid impossible date
    // (2026-02-31) would silently normalize through the days_from_civil arithmetic (to March 3)
    // and hand the cadence an invented instant. The emitter is the civil authority: a value is
    // a real instant iff it round-trips through it byte for byte. Anything else is corruption
    // and fails closed here.
    if rfc3339_utc(unix) != s {
        return None;
    }
    Some(unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    // the ripple check, the observed vector, the Trash seam ----

    #[test]
    fn ripple_verdict_is_within_closure_when_every_changed_label_is_in_the_declared_closure() {
        use std::collections::BTreeSet;
        let set = |s: &[&str]| -> BTreeSet<String> { s.iter().map(|x| x.to_string()).collect() };
        let closure = set(&["TRASH", "INBOX"]);
        assert_eq!(ripple_verdict(&set(&["INBOX", "CATEGORY_PROMOTIONS"]), &set(&["TRASH", "CATEGORY_PROMOTIONS"]), &closure), RippleVerdict::WithinClosure);
        // An atom outside the closure changed ⇒ the restoration claim is UNDETERMINED for this
        // operation, loudly (v7 §1-§2).
        assert_eq!(ripple_verdict(&set(&["INBOX", "IMPORTANT"]), &set(&["TRASH"]), &closure), RippleVerdict::OutsideClosure { unexpected: set(&["IMPORTANT"]) });
        // Unchanged atoms outside the closure are fine; only the DELTA is judged.
        assert_eq!(ripple_verdict(&set(&["INBOX", "STARRED"]), &set(&["TRASH", "STARRED"]), &closure), RippleVerdict::WithinClosure);
        // …in BOTH directions: a label that APPEARED outside the closure is a ripple too.
        assert_eq!(ripple_verdict(&set(&["INBOX"]), &set(&["TRASH", "IMPORTANT"]), &closure), RippleVerdict::OutsideClosure { unexpected: set(&["IMPORTANT"]) });
        assert_eq!(RippleVerdict::WithinClosure.as_token(), "within_closure");
        assert_eq!(RippleVerdict::OutsideClosure { unexpected: set(&["X"]) }.as_token(), "outside_closure");
    }

    #[test]
    fn the_observed_label_vector_rides_the_journal_row_as_a_canonical_array_and_a_malformed_one_refuses() {
        let set = |s: &[&str]| -> BTreeSet<String> { s.iter().map(|x| x.to_string()).collect() };
        let basis = FrozenBasis::for_test_trash();
        basis
            .validate_for_admission()
            .expect("the Trash seam is a VALID, admissible basis");
        let obs = Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: [("label:TRASH".to_string(), false), ("membership:INBOX".to_string(), true)]
                .into_iter()
                .collect(),
            request_id: None,
            provider_label_vector: Some(set(&["STARRED", "INBOX"])),
        };
        let row = journal_row_from_observation(&obs, &basis);
        // Canonical: sorted, one entry per label, a JSON array — never the provider's order.
        assert_eq!(row.observed_label_vector.as_deref(), Some(r#"["INBOX","STARRED"]"#));
        assert_eq!(row.observed_label_vector_set().unwrap(), Some(set(&["INBOX", "STARRED"])));
        // `validate` is the ATOM-map authority and does not read the vector.
        row.validate(&basis).expect("the vector is not an atom map");

        // Honest absence stays absent…
        let absent = journal_row_from_observation(
            &Observation { provider_label_vector: None, ..obs.clone() },
            &basis,
        );
        assert_eq!(absent.observed_label_vector, None);
        assert_eq!(absent.observed_label_vector_set().unwrap(), None);
        // …and an EMPTY answer is a legitimate one (a message with no labels), never absence.
        let empty = journal_row_from_observation(
            &Observation { provider_label_vector: Some(BTreeSet::new()), ..obs.clone() },
            &basis,
        );
        assert_eq!(empty.observed_label_vector.as_deref(), Some("[]"));
        assert_eq!(empty.observed_label_vector_set().unwrap(), Some(BTreeSet::new()));

        // A stored value that is not the canonical array is corruption — a LogError, never a
        // silent `None` and never a quietly re-sorted set.
        for bad in ["not json", "null", r#"{"INBOX":true}"#, r#"["STARRED","INBOX"]"#, r#"["INBOX","INBOX"]"#, r#"[1]"#] {
            let corrupt = JournalRow { observed_label_vector: Some(bad.to_string()), ..row.clone() };
            assert!(corrupt.observed_label_vector_set().is_err(), "{bad} must refuse");
        }
    }

    #[test]
    fn rfc3339_round_trips_through_its_own_inverse() {
        // The parser is the emitter's inverse or it is nothing: every instant the emitter can
        // produce must come back as the same number, and a value the SHAPE AUTHORITY refuses
        // must come back as `None` (the complement rule at this door).
        for secs in [
            0u64,
            1,
            86_399,
            86_400,
            1_000_000_000,
            1_754_611_200,
            1_754_611_200 + 3600,
            4_102_444_800,
        ] {
            let text = rfc3339_utc(secs);
            assert_eq!(
                unix_secs_from_rfc3339_utc(&text),
                Some(secs),
                "the inverse must recover {secs} from {text}"
            );
        }
        for bad in ["", "2026-08-08", "2026-08-08T00:00:00", "2026-13-01T00:00:00Z"] {
            assert_eq!(
                unix_secs_from_rfc3339_utc(bad),
                None,
                "a value outside the shape authority never becomes a number: {bad:?}"
            );
        }
        // s4-: shape-valid but civilly IMPOSSIBLE dates must refuse, never
        // normalize — pre-fix, 2026-02-31 silently became March 3's instant and the cadence
        // arithmetic ran on an invented time.
        for impossible in [
            "2026-02-31T00:00:00Z", // February has no 31st
            "2026-02-29T00:00:00Z", // 2026 is not a leap year
            "2026-04-31T00:00:00Z", // April has 30 days
            "2026-00-10T00:00:00Z", // month zero
            "2026-01-00T00:00:00Z", // day zero
        ] {
            assert_eq!(
                unix_secs_from_rfc3339_utc(impossible),
                None,
                "an impossible civil date is corruption and fails closed: {impossible:?}"
            );
        }
        // The leap-year positive control: 2024-02-29 IS real and must survive the round-trip.
        let leap = unix_secs_from_rfc3339_utc("2024-02-29T12:00:00Z");
        assert!(leap.is_some(), "a real leap day is a real instant");
        assert_eq!(rfc3339_utc(leap.unwrap()), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn frozen_basis_serializes_canonically_and_round_trips() {
        // The key comes from the ONE encoding authority, not a hand-spelled shape (
        // PR) — this is also the round-trip witness that an ESCAPED key (the encoding
        // embeds quotes) survives being nested inside the basis JSON unchanged.
        let key = native_resource_key("jmap", &["acct-1", "email-9"]);
        let basis = FrozenBasis {
            native_resource_key: key.clone(),
            touched_atoms: [
                ("membership:mb-inbox".to_string(), "mb-inbox".to_string()),
                ("membership:mb-archive".to_string(), "mb-archive".to_string()),
            ]
            .into_iter()
            .collect(),
            // `A` for an Archive: the source membership drops, the destination gains.
            atom_targets: [
                ("membership:mb-inbox".to_string(), false),
                ("membership:mb-archive".to_string(), true),
            ]
            .into_iter()
            .collect(),
            // The frozen role→id mapping — round-trips like every other field, and each id IS a
            // touched-atom operand.
            role_bindings: [
                ("inbox".to_string(), "mb-inbox".to_string()),
                ("archive".to_string(), "mb-archive".to_string()),
            ]
            .into_iter()
            .collect(),
            freshness: Freshness::StateCursor {
                cursor: "s-77".into(),
            },
        };
        let json = basis.to_json().unwrap();
        // BTreeMap ⇒ stable key order; the persisted form is deterministic.
        let embedded = serde_json::to_string(&key).unwrap();
        assert!(
            json.contains(&format!("\"native_resource_key\":{embedded}")),
            "the frozen key must persist verbatim (escaped once), got: {json}"
        );
        let back = FrozenBasis::from_json(&json).unwrap();
        assert_eq!(back, basis);
        assert_eq!(back.native_resource_key, key);
    }

    #[test]
    fn frozen_basis_from_json_refuses_malformed_or_incomplete() {
        assert!(FrozenBasis::from_json("not json").is_err());
        assert!(FrozenBasis::from_json("{}").is_err());
        // An empty native key is not a well-formed basis (open-time integrity reads this).
        let empty_key = r#"{"native_resource_key":"","touched_atoms":{},"freshness":"immutable_constants"}"#;
        assert!(FrozenBasis::from_json(empty_key).is_err());
    }

    #[test]
    fn validate_refuses_empty_components_not_just_empty_collections() {
        // PR: `{"":""}` is a NONEMPTY map that names nothing — an
        // empty atom key satisfies a coverage check while describing no touched label, so
        // the journal row becomes a false restoration witness; an empty StateCursor is
        // "freshness evidence" that evidences nothing. Cardinality is not well-formedness.
        let empty_atom_key = FrozenBasis {
            native_resource_key: "prov:a/n".into(),
            touched_atoms: [(String::new(), String::new())].into_iter().collect(),
            atom_targets: BTreeMap::new(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        };
        assert!(empty_atom_key.validate().is_err(), "an empty atom key names nothing");
        let empty_operand = FrozenBasis {
            native_resource_key: "prov:a/n".into(),
            touched_atoms: [("membership:INBOX".to_string(), String::new())]
                .into_iter()
                .collect(),
            atom_targets: BTreeMap::new(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        };
        assert!(empty_operand.validate().is_err(), "an empty resolved operand resolves nothing");
        let empty_cursor = FrozenBasis {
            native_resource_key: "prov:a/n".into(),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            atom_targets: BTreeMap::new(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::StateCursor { cursor: String::new() },
        };
        assert!(empty_cursor.validate().is_err(), "an empty cursor is not freshness evidence");
    }

    #[test]
    fn journal_row_validate_refuses_divergent_observed_and_touched_values() {
        // `validate` checked observed/touched_atom key-set equality but NOT
        // value equality. Undo reads `touched_atom` as P and the §4.1 no-op kill decides
        // `P == A`, so a direct `IntentLog::prepare` caller could keep the KEYS equal while
        // diverging the VALUES — observed {INBOX:true} + touched_atom {INBOX:false} — forging
        // P to equal A and winning a FALSE no-op kill (an undo "verified" without restoring).
        // For the M1 single/pair Boolean projections the two maps are IDENTICAL by
        // construction (`journal_row_from_observation`), so equal keys with divergent values is
        // a corrupt row the durable-store boundary must refuse.
        let basis = FrozenBasis {
            native_resource_key: "prov:a/n".into(),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        };
        let observed: BTreeMap<String, bool> =
            [("membership:INBOX".to_string(), true)].into_iter().collect();
        let touched: BTreeMap<String, bool> =
            [("membership:INBOX".to_string(), false)].into_iter().collect();
        let forged = JournalRow {
            observed: serde_json::to_string(&observed).unwrap(),
            touched_atom: serde_json::to_string(&touched).unwrap(),
            resolved_operands: serde_json::to_string(&basis.touched_atoms).unwrap(),
            request_id: None,
            observed_label_vector: None,
        };
        assert!(
            forged.validate(&basis).is_err(),
            "equal keys with divergent values forge P — the store boundary must refuse it"
        );

        // The production path still passes: both projections are the SAME observation.
        let obs = Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: observed.clone(),
            request_id: None,
            provider_label_vector: None,
        };
        journal_row_from_observation(&obs, &basis)
            .validate(&basis)
            .expect("the production journal_row_from_observation row is well-formed");
    }

    #[test]
    fn journal_rows_with_atoms_outside_the_frozen_basis_are_refused() {
        // PR: coverage (⊇) alone let a direct caller persist EXTRA
        // keys beyond the frozen basis — a content-like-key smuggling channel into the
        // content-free journal, and a witness claiming atoms the forward command never
        // touched. The boundary requires key-set EQUALITY with the frozen atoms (the M1
        // reality; a future observe-more-than-touched operation widens this at the one
        // authority, deliberately, when it lands).
        let basis = FrozenBasis {
            native_resource_key: "prov:a/n".into(),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        };
        let mut atoms: BTreeMap<String, bool> =
            [("membership:INBOX".to_string(), true)].into_iter().collect();
        atoms.insert("subject:the entire message subject line".to_string(), true);
        let smuggled = serde_json::to_string(&atoms).unwrap();
        let row = JournalRow {
            observed: smuggled.clone(),
            touched_atom: smuggled,
            resolved_operands: serde_json::to_string(&basis.touched_atoms).unwrap(),
            request_id: None,
            observed_label_vector: None,
        };
        assert!(
            row.validate(&basis).is_err(),
            "an atom OUTSIDE the frozen basis must refuse — the journal is content-free by construction"
        );
    }

    #[test]
    fn native_resource_key_is_injective_over_its_components() {
        // THE property (PR): DISTINCT component vectors must produce
        // DISTINCT keys. The old `format!("{provider}:{a}/{b}")` shape was not injective —
        // provider ids are OPAQUE, so `("a/b","c")` and `("a","b/c")` collided, and a resolver
        // rebind between them passed BASIS-6's string equality. The separators a JSON array
        // uses are the ones JSON also ESCAPES inside strings, which is what makes the encoding
        // injective for EVERY byte string, not just the well-behaved ones.
        let colliding_under_a_separator_join = [
            (vec!["a/b", "c"], vec!["a", "b/c"]),
            (vec!["a:b", "c"], vec!["a", "b:c"]),
            (vec!["a\"b", "c"], vec!["a", "b\"c"]),
            (vec!["a\\", "b"], vec!["a", "\\b"]),
            (vec!["a", ""], vec!["", "a"]),
            (vec!["a,b", "c"], vec!["a", "b,c"]),
        ];
        for (left, right) in colliding_under_a_separator_join {
            assert_ne!(
                native_resource_key("prov", &left),
                native_resource_key("prov", &right),
                "distinct components {left:?} vs {right:?} must not encode to one key"
            );
        }
        // The PROVIDER tag is a component too: it can never be absorbed into the first id.
        assert_ne!(
            native_resource_key("gmail", &["me", "MSG-1"]),
            native_resource_key("gm", &["ail", "me", "MSG-1"]),
        );
        // Deterministic and equality-stable: the same components always encode identically.
        assert_eq!(
            native_resource_key("jmap", &["acct-1", "email-9"]),
            native_resource_key("jmap", &["acct-1", "email-9"]),
        );
        // Non-empty, so it clears `FrozenBasis::validate`'s BASIS-1 floor.
        assert!(!native_resource_key("prov", &["a"]).is_empty());
    }

    #[test]
    fn rfc3339_utc_formats_epoch_seconds() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_754_600_000), "2025-08-07T20:53:20Z");
    }

    #[test]
    fn atom_targets_default_empty_on_legacy_rows_and_key_equality_enforced_when_present() {
        // Build-decision under the §7c stop line: `A` (the value each touched atom holds AFTER
        // the forward action) is frozen at resolve time — only the resolver knows role
        // direction (JMAP Archive: which frozen mailbox id is source vs destination), and
        // re-resolving at undo time is the rebind BASIS-6 forbids. Legacy stage-2 rows parse
        // with EMPTY targets (serde default) — the undo path answers them with a named
        // refusal, never a guess.
        let legacy = r#"{"native_resource_key":"[\"p\",\"a\"]","touched_atoms":{"membership:INBOX":"INBOX"},"freshness":"immutable_constants"}"#;
        let parsed = FrozenBasis::from_json(legacy).expect("legacy stage-2 JSON must still parse");
        assert!(parsed.atom_targets.is_empty());
        // When present, the target key-set must EQUAL the touched-atom key-set (same
        // both-directions discipline as JournalRow::validate — a target for an atom the
        // action doesn't touch is a smuggling channel; a touched atom without a target makes
        // the three-way table undecidable).
        let mut mismatched = parsed.clone();
        mismatched.atom_targets = [("membership:OTHER".to_string(), true)].into_iter().collect();
        assert!(mismatched.validate().is_err());
        let mut matched = parsed.clone();
        matched.atom_targets = [("membership:INBOX".to_string(), false)].into_iter().collect();
        matched.validate().expect("equal key-sets are well-formed");
        // Round-trip preserves targets.
        let back = FrozenBasis::from_json(&matched.to_json().unwrap()).unwrap();
        assert_eq!(back.atom_targets, matched.atom_targets);
    }

    #[test]
    fn role_bindings_freeze_the_role_direction_and_must_name_touched_operands() {
        // 2026-08-08: `role_bindings` freezes the role→id MAPPING so BASIS-6 can
        // refuse a role permutation that preserves the id SET but inverts the direction. When
        // present, every id it names must be an operand in `touched_atoms` — else it binds a role
        // to a mailbox the action never touched (a smuggling channel, exactly like an out-of-set
        // atom_target). Legacy/keyword rows carry it empty (serde default) and stay well-formed.
        let base = FrozenBasis {
            native_resource_key: native_resource_key("jmap", &["acct-1", "email-9"]),
            touched_atoms: [
                ("membership:mb-inbox".to_string(), "mb-inbox".to_string()),
                ("membership:mb-archive".to_string(), "mb-archive".to_string()),
            ]
            .into_iter()
            .collect(),
            atom_targets: [
                ("membership:mb-inbox".to_string(), false),
                ("membership:mb-archive".to_string(), true),
            ]
            .into_iter()
            .collect(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::StateCursor { cursor: "s-1".into() },
        };
        // RED: a binding to an id that is NOT a touched-atom operand is refused.
        let mut smuggled = base.clone();
        smuggled.role_bindings = [
            ("inbox".to_string(), "mb-inbox".to_string()),
            ("archive".to_string(), "mb-NOT-TOUCHED".to_string()),
        ]
        .into_iter()
        .collect();
        let err = smuggled.validate().unwrap_err();
        assert_eq!(err, "frozen_basis: role_bindings id not in touched_atoms");
        // An empty-id binding is refused by the same rule.
        let mut empty_id = base.clone();
        empty_id.role_bindings =
            [("inbox".to_string(), String::new())].into_iter().collect();
        assert_eq!(
            empty_id.validate().unwrap_err(),
            "frozen_basis: role_bindings id not in touched_atoms"
        );
        // A consistent mapping (both ids ARE touched operands) is well-formed and round-trips.
        let mut good = base.clone();
        good.role_bindings = [
            ("inbox".to_string(), "mb-inbox".to_string()),
            ("archive".to_string(), "mb-archive".to_string()),
        ]
        .into_iter()
        .collect();
        good.validate().expect("a mapping onto touched operands is well-formed");
        let back = FrozenBasis::from_json(&good.to_json().unwrap()).unwrap();
        assert_eq!(back.role_bindings, good.role_bindings);
        // Legacy JSON with NO role_bindings key still parses (serde default → empty).
        let legacy = r#"{"native_resource_key":"[\"p\",\"a\"]","touched_atoms":{"membership:INBOX":"INBOX"},"freshness":"immutable_constants"}"#;
        let parsed = FrozenBasis::from_json(legacy).expect("legacy JSON must still parse");
        assert!(parsed.role_bindings.is_empty());
    }

    #[test]
    fn admission_validation_requires_nonempty_targets() {
        // The ADMISSION tier (validate_for_admission) refuses an empty target vector — a NEW
        // row without `A` cannot answer §3.2/§4.1 later; the storage tier (validate) accepts
        // it so legacy rows stay readable.
        let legacy = r#"{"native_resource_key":"[\"p\",\"a\"]","touched_atoms":{"membership:INBOX":"INBOX"},"freshness":"immutable_constants"}"#;
        let parsed = FrozenBasis::from_json(legacy).unwrap();
        assert!(parsed.validate_for_admission().is_err(), "admission requires A");
    }

    #[test]
    fn noop_kill_fires_exactly_when_p_equals_a() {
        // §4.1: P == A in the journal row ⇒ undo is a recorded no-op — restores nothing,
        // manufactures nothing, decided first, from the row (+ frozen A) alone. THE class
        // this issue exists to close.
        let p_in: BTreeMap<String, bool> = [("membership:INBOX".into(), false)].into_iter().collect();
        let a: BTreeMap<String, bool> = [("membership:INBOX".into(), false)].into_iter().collect();
        assert!(noop_kill(&p_in, &a), "archive of a not-in-INBOX message: undo restores nothing");
        let p_out: BTreeMap<String, bool> = [("membership:INBOX".into(), true)].into_iter().collect();
        assert!(!noop_kill(&p_out, &a));
    }

    #[test]
    fn requalify_single_boolean_conflict_is_unreachable() {
        // §3.2(4): Boolean atoms have no third value — when P ≠ A, C is one of them. The
        // refuse branch exists for multi-valued atoms only, and this test SAYS so.
        let p: BTreeMap<String, bool> = [("label:UNREAD".into(), true)].into_iter().collect();
        let a: BTreeMap<String, bool> = [("label:UNREAD".into(), false)].into_iter().collect();
        let c_is_a: BTreeMap<String, bool> = a.clone();
        let c_is_p: BTreeMap<String, bool> = p.clone();
        assert_eq!(requalify(&p, &a, &c_is_a), RequalifyDecision::Restore);
        assert_eq!(requalify(&p, &a, &c_is_p), RequalifyDecision::AlreadyRestored);
    }

    #[test]
    fn requalify_jmap_pair_covers_all_four_observed_cases() {
        // §3.1a: the pair has reachable third states ({both}, {neither}) an
        // external client can produce — the refuse branch IS reachable here. W-STALE's
        // JMAP-pair arm: all four observed-pair cases.
        let p: BTreeMap<String, bool> =
            [("membership:mb-i".into(), true), ("membership:mb-a".into(), false)].into_iter().collect();
        let a: BTreeMap<String, bool> =
            [("membership:mb-i".into(), false), ("membership:mb-a".into(), true)].into_iter().collect();
        let both: BTreeMap<String, bool> =
            [("membership:mb-i".into(), true), ("membership:mb-a".into(), true)].into_iter().collect();
        let neither: BTreeMap<String, bool> =
            [("membership:mb-i".into(), false), ("membership:mb-a".into(), false)].into_iter().collect();
        assert_eq!(requalify(&p, &a, &a.clone()), RequalifyDecision::Restore);
        assert_eq!(requalify(&p, &a, &p.clone()), RequalifyDecision::AlreadyRestored);
        assert_eq!(requalify(&p, &a, &both), RequalifyDecision::Conflict);
        assert_eq!(requalify(&p, &a, &neither), RequalifyDecision::Conflict);
    }

    #[test]
    fn requalify_retry_is_the_same_table_read_for_a_forward_retry() {
        // §5.2a -: ONE table, TWO readings — the retry reading's three answers
        // are the undo reading's three answers renamed, and for every `P != A` world the two
        // orders agree (the branches are mutually exclusive there).
        //
        // (2026-08-08) recut the LAST arm, and it is the fold's whole point:
        // this reading asks `C == P` FIRST, which makes it TOTAL — the `P == A` world it used
        // to mis-answer (and which a caller-side pre-guard therefore had to hide from it) now
        // answers correctly and by OBSERVATION.
        let p: BTreeMap<String, bool> =
            [("membership:mb-i".into(), true), ("membership:mb-a".into(), false)].into_iter().collect();
        let a: BTreeMap<String, bool> =
            [("membership:mb-i".into(), false), ("membership:mb-a".into(), true)].into_iter().collect();
        let both: BTreeMap<String, bool> =
            [("membership:mb-i".into(), true), ("membership:mb-a".into(), true)].into_iter().collect();
        // C == P: the capture still describes the world ⇒ dispatch on the existing row.
        assert_eq!(
            requalify_retry(&p, &a, &p.clone()),
            RetryRequalifyDecision::ProceedOnCapturedRow
        );
        // C == A: another actor produced the target ⇒ the durable no-op terminal.
        assert_eq!(
            requalify_retry(&p, &a, &a.clone()),
            RetryRequalifyDecision::ExternallySatisfied
        );
        // Neither ⇒ RE-PREPARE (the undo reading REFUSES here; a forward retry re-captures,
        // which is the whole point of the ONE narrow §2.2b exception).
        assert_eq!(
            requalify_retry(&p, &a, &both),
            RetryRequalifyDecision::RePrepare
        );
        // ── THE `P == A` WORLD, which this function is now TOTAL over. ──
        // There is no precondition left to state, and no pre-guard is entitled to answer for
        // it: the two sub-worlds have DIFFERENT right answers, and only an observation of `C`
        // tells them apart.
        let flat: BTreeMap<String, bool> = [("membership:mb-i".into(), true)].into_iter().collect();
        let moved: BTreeMap<String, bool> = [("membership:mb-i".into(), false)].into_iter().collect();
        assert!(noop_kill(&flat, &flat.clone()), "P == A, by construction");
        // UNCHANGED: `C == P` wins first, so the operation proceeds on its existing row —
        // exactly the disposition the deleted pre-guard gave it, now earned by observing.
        assert_eq!(
            requalify_retry(&flat, &flat.clone(), &flat.clone()),
            RetryRequalifyDecision::ProceedOnCapturedRow
        );
        // MOVED: another actor changed the atom during the retry gap. The pre-guard answered
        // "proceed" here too — a BLIND dispatch over another actor's state, with undo killed by
        // the stale `P == A`. The table re-prepares instead.
        assert_eq!(
            requalify_retry(&flat, &flat.clone(), &moved),
            RetryRequalifyDecision::RePrepare
        );
    }

    #[test]
    fn eligibility_four_reasons_derive_mechanically() {
        let p: BTreeMap<String, bool> = [("membership:INBOX".into(), true)].into_iter().collect();
        let journal = |until: &str| {
            Some(CapturedJournalView {
                p: p.clone(),
                undo_offer_until: until.into(),
            })
        };
        // CaptureDisabled: journal_required=0.
        assert_eq!(
            derive_undo_eligibility(
                false,
                true,
                journal("2999-01-01T00:00:00Z"),
                false,
                "2026-01-01T00:00:00Z"
            ),
            UndoEligibility::Unavailable(UndoUnavailableReason::CaptureDisabled)
        );
        // PredatesSubstrate: no basis targets (legacy row).
        assert_eq!(
            derive_undo_eligibility(
                true,
                false,
                journal("2999-01-01T00:00:00Z"),
                false,
                "2026-01-01T00:00:00Z"
            ),
            UndoEligibility::Unavailable(UndoUnavailableReason::PredatesSubstrate)
        );
        // Expired — retained-row arm: the row still EXISTS, the OFFER lapsed (deadline <
        // effective_now); reason renders from the deadline, never from a tombstone.
        assert_eq!(
            derive_undo_eligibility(
                true,
                true,
                journal("2026-01-01T00:00:00Z"),
                false,
                "2026-06-01T00:00:00Z"
            ),
            UndoEligibility::Unavailable(UndoUnavailableReason::Expired { tombstoned: false })
        );
        // Expired — tombstone provenance rides the same answer.
        assert_eq!(
            derive_undo_eligibility(true, true, None, true, "2026-06-01T00:00:00Z"),
            UndoEligibility::Unavailable(UndoUnavailableReason::Expired { tombstoned: true })
        );
        // JournalGapUnexplained: required, no row, no tombstone — fail-loud.
        assert_eq!(
            derive_undo_eligibility(true, true, None, false, "2026-06-01T00:00:00Z"),
            UndoEligibility::Unavailable(UndoUnavailableReason::JournalGapUnexplained)
        );
        // Eligible: row present, offer open.
        assert_eq!(
            derive_undo_eligibility(
                true,
                true,
                journal("2999-01-01T00:00:00Z"),
                false,
                "2026-06-01T00:00:00Z"
            ),
            UndoEligibility::Eligible { p: p.clone() }
        );
    }

    #[test]
    fn the_canonical_timestamp_shape_authority_accepts_exactly_what_it_emits() {
        // The authority is defined BY the emitter: whatever `rfc3339_utc` can produce must
        // clear it, and the fixed-width shape is the whole reason lexicographic order is
        // time order. Sample the emitter across the epoch, then the rejection classes.
        for secs in [0u64, 1, 59, 60, 86_399, 86_400, 1_754_600_000, 32_503_680_000] {
            let t = rfc3339_utc(secs);
            assert!(is_canonical_rfc3339_utc(&t), "emitter output rejected: {t}");
        }
        for bad in [
            "",                          // the empty latch — sorts BELOW every instant
            "invalid",                   // sorts ABOVE every instant (the fail-open shape)
            "zzz-not-a-time",            //
            "2026-06-01T00:00:00",       // 19 bytes, no zone
            "2026-06-01T00:00:00Z ",     // trailing byte
            "2026-06-01T00:00:00z",      // lowercase zone: NOT what the emitter writes
            "2026-06-01 00:00:00Z",      // space separator
            "2026-06-01T00:00:00+00:00", // offset form: right instant, WRONG order shape
            "2026-6-01T00:00:00Z0",      // unpadded month re-padded to 20 bytes
            "2026-13-01T00:00:00Z",      // month out of range
            "2026-00-01T00:00:00Z",      //
            "2026-06-32T00:00:00Z",      // day out of range
            "2026-06-00T00:00:00Z",      //
            "2026-06-01T24:00:00Z",      // hour out of range
            "2026-06-01T00:60:00Z",      // minute out of range
            "2026-06-01T00:00:60Z",      // second out of range
            "20a6-06-01T00:00:00Z",      // non-digit in a digit position
        ] {
            assert!(!is_canonical_rfc3339_utc(bad), "shape accepted garbage: {bad:?}");
        }
        // Multi-byte input must not panic on the byte indexing, and must be refused.
        assert!(!is_canonical_rfc3339_utc("2026-06-01T00:00:0🌙"));
    }

    #[test]
    fn eligibility_fails_closed_on_a_malformed_deadline() {
        // the offer deadline is a bare TEXT column, so a malformed
        // persisted value reaches this comparison. Lexicographic order over garbage is not
        // time order: `"2026-…" < "invalid"` made a corrupt deadline read as "the offer is
        // still open" — FAIL OPEN, outside any window. §4.4's rule is the opposite: an
        // ambiguous clock evaluates fail-closed. The store boundary refuses such rows now;
        // this is the belt on the pure fn, which stays TOTAL for any future caller.
        let p: BTreeMap<String, bool> = [("membership:INBOX".into(), true)].into_iter().collect();
        let journal = |until: &str| {
            Some(CapturedJournalView {
                p: p.clone(),
                undo_offer_until: until.into(),
            })
        };
        // A malformed DEADLINE that sorts ABOVE every real instant — the fail-open shape.
        assert_eq!(
            derive_undo_eligibility(true, true, journal("invalid"), false, "2026-06-01T00:00:00Z"),
            UndoEligibility::Unavailable(UndoUnavailableReason::Expired { tombstoned: false })
        );
        // A malformed EFFECTIVE_NOW that sorts BELOW every real instant (an empty/garbage
        // latch): the clock reads as "before every deadline", the other fail-open shape.
        assert_eq!(
            derive_undo_eligibility(true, true, journal("2026-01-01T00:00:00Z"), false, ""),
            UndoEligibility::Unavailable(UndoUnavailableReason::Expired { tombstoned: false })
        );
        // …and one that sorts above: already refused, but for the RIGHT reason now.
        assert_eq!(
            derive_undo_eligibility(
                true,
                true,
                journal("2999-01-01T00:00:00Z"),
                false,
                "zzz-not-a-time"
            ),
            UndoEligibility::Unavailable(UndoUnavailableReason::Expired { tombstoned: false })
        );
        // Tombstone provenance still rides the reason on the fail-closed arm.
        assert_eq!(
            derive_undo_eligibility(true, true, journal("invalid"), true, "2026-06-01T00:00:00Z"),
            UndoEligibility::Unavailable(UndoUnavailableReason::Expired { tombstoned: true })
        );
        // Shape-valid inputs are untouched: the open offer is still Eligible.
        assert_eq!(
            derive_undo_eligibility(
                true,
                true,
                journal("2999-01-01T00:00:00Z"),
                false,
                "2026-06-01T00:00:00Z"
            ),
            UndoEligibility::Eligible { p }
        );
    }
}
