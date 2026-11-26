//! An intent's lifecycle status, the guarded status-write outcomes, and the recorded intent.

use crate::{Command, LogError};

#[cfg(doc)]
use crate::{IntentLog, RETRY_CAP};

/// Lifecycle of an intent in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentStatus {
    Pending,
    Applied,
    /// Reserved: the fail-closed gate between local apply and provider submit (evidence and
    /// pre-state snapshot written, ready to dispatch). Not yet reachable; named now so the
    /// evidence gate can attach without an enum-breaking migration.
    EvidenceSnapshotWritten,
    Failed,
    /// Undo in progress: the inverse has been (or is being) dispatched but not yet reconciled.
    /// Non-terminal — crash-recovery re-dispatches the inverse and advances to `Undone`.
    Undoing,
    Undone,
    /// Every operation member caught by a sever's atomic closure. Terminal and not eligible for
    /// undo: no verified applied state exists to restore (the attempt never issued, or the whole
    /// operation had no attempt). Replaying the identical fingerprint yields `Err(Severed)`.
    Severed,
    /// The operational axis was closed by in-place adjudication: an authority-gated control
    /// transition, not a new operation. The historical axis may stay unknown forever or later
    /// resolve via a `LATE_ACK_*` fact. Terminal, and not undo-eligible while unresolved (a
    /// `LATE_ACK_APPLIED` on an undo attempt flips the parent to `Undone`, not this status).
    Adjudicated,
    /// The retry-requalification no-op terminal: a later actor already produced the forward
    /// target while this operation held the retry budget. Terminal and not undo-eligible (a stale
    /// captured pre-state must never reverse the other actor's change); distinct from `Applied`
    /// so recovery never mistakes it for a dispatched success carrying a stale pre-state.
    ExternallySatisfied,
}

impl IntentStatus {
    /// Every variant of the lifecycle. Test-only: the guard test regenerates
    /// [`NON_TERMINAL_STATUS_SQL`] by filtering this list to check it is derived from
    /// [`IntentStatus::is_terminal`]. An exhaustive match in that test makes a variant missing
    /// here a compile error.
    #[cfg(test)]
    pub(crate) const ALL: [IntentStatus; 9] = [
        IntentStatus::Pending,
        IntentStatus::Undoing,
        IntentStatus::EvidenceSnapshotWritten,
        IntentStatus::Applied,
        IntentStatus::Undone,
        IntentStatus::Failed,
        IntentStatus::Severed,
        IntentStatus::Adjudicated,
        IntentStatus::ExternallySatisfied,
    ];

    /// A terminal status is a settled outcome: the optimistic projection it governs is
    /// confirmed, so divergence-correction may overwrite it from provider truth. Non-terminal
    /// (`Pending`, `Undoing`, `EvidenceSnapshotWritten`) means in-flight: never correct it, or a
    /// legitimate pending mutation is clobbered (the JMAP reconcile footgun).
    ///
    /// This is the single authority for the terminal/non-terminal split. In-memory predicates
    /// call it, and SQL predicates use the crate-private `NON_TERMINAL_STATUS_SQL`, which is
    /// derived from it. Call sites must not hand-enumerate the non-terminal tokens: separate
    /// enumerations had drifted apart and omitted `evidence_snapshot_written`.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            IntentStatus::Applied
                | IntentStatus::Undone
                | IntentStatus::Failed
                // All three P013 status-set additions are terminal: a settled
                // sever/adjudication/requalification disposition, never re-dispatched.
                | IntentStatus::Severed
                | IntentStatus::Adjudicated
                | IntentStatus::ExternallySatisfied
        )
    }

    /// May this intent still gain a pre-state journal row? True only where no provider effect
    /// can have been released: `Pending`, and the reserved `EvidenceSnapshotWritten` gate
    /// (written before provider submit by definition). `Undoing`/`Applied`/`Undone` mean the
    /// forward effect happened, so a capture now would be post-effect and poison no-op
    /// detection; `Failed` is terminal. Exhaustive so a new status must take a position.
    pub fn is_pre_dispatch(&self) -> bool {
        match self {
            IntentStatus::Pending | IntentStatus::EvidenceSnapshotWritten => true,
            IntentStatus::Applied
            | IntentStatus::Undoing
            | IntentStatus::Undone
            | IntentStatus::Failed
            // These are terminal dispositions reached only from a post-dispatch (or
            // never-dispatched-but-closed) state; a fresh pre-state journal row never attaches.
            | IntentStatus::Severed
            | IntentStatus::Adjudicated
            | IntentStatus::ExternallySatisfied => false,
        }
    }
}

/// The non-terminal status domain as a SQL tuple, for every `status IN (…)` predicate in the
/// engine. This is the SQL half of [`IntentStatus::is_terminal`] and the only place these
/// tokens are written; a new status needs one edit here plus `ALL`. The test
/// `the_non_terminal_sql_domain_is_derived_from_is_terminal_not_hand_enumerated` regenerates
/// the string from the enum and fails if they disagree.
///
/// It is a constant rather than a `format!` at each site because it is interpolated into SQL:
/// it must be compile-time text of our own making, never anything derived from input.
pub(crate) const NON_TERMINAL_STATUS_SQL: &str =
    "('pending','undoing','evidence_snapshot_written')";

/// The compare half of every engine status write. No status write is unconditional: each
/// names the world it expects, and [`IntentLog::set_status_if`] refuses when the row has moved
/// instead of overwriting what another authority wrote.
///
/// This closes the terminal-overwrite class: a write decided against a read that lands after
/// a concurrent sever has already terminalized the row. `terminalize_operation` always carried
/// the `NON_TERMINAL_STATUS_SQL` guard; the bug was in writes that bypassed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusPrecondition {
    /// The row must still be non-terminal (see [`IntentStatus::is_terminal`]). Every
    /// terminalizing write takes this: a settled disposition is never rewritten.
    NonTerminal,
    /// The row must hold exactly this status. The engine's two legitimate terminal-to-terminal
    /// transitions take it (undo's parent flip `Applied -> Undone`, and the legacy pair map
    /// `Undone -> Applied`), where the non-terminal guard would be inverted.
    Exactly(IntentStatus),
}

/// What a guarded status write did. A refusal is never silent: it carries the status the row
/// actually holds, so the caller can report that the world changed rather than a false
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a refused status write means the world changed — converge on it or surface it, \
              never assume the write landed"]
pub enum StatusWrite {
    /// The row satisfied the precondition and now holds the new status.
    Written,
    /// Refused, nothing written. Carries what the row actually holds (`None` when the row does
    /// not exist).
    Refused(Option<IntentStatus>),
}

/// What the over-budget dead-letter did ([`IntentLog::dead_letter_if_quiescent`]).
///
/// Three answers because one transaction decides two things: a live attempt means the
/// operation is still someone's in-flight work (park it behind the sweep), while a refused
/// compare-and-set means the row is already settled and can be skipped.
/// row is already settled (not a predecessor at all — move on).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a refused dead-letter means the operation is still live or already settled — \
              route on it, never assume the terminal landed"]
pub enum DeadLetterWrite {
    /// The operation held no live attempt and the row was still non-terminal: it now holds
    /// [`IntentStatus::Failed`].
    Written,
    /// Refused, nothing written: the operation holds a live attempt (its class is named). A
    /// dead-letter attributes no effect, and no local read can support that for an attempt
    /// another driver still owns.
    LiveAttempt(crate::attempt::AttemptClass),
    /// Refused, nothing written: the row is no longer non-terminal (or no longer exists).
    /// Carries what it actually holds, as [`StatusWrite::Refused`] does.
    StatusMoved(Option<IntentStatus>),
}

/// What the transient budget charge did
/// ([`IntentLog::charge_and_dead_letter_if_quiescent`]).
///
/// Three answers, at the grain of the caller's decision: the operation is still alive (retry
/// later), this call closed it (report the dead-letter), or there was nothing of ours to charge
/// (someone else already settled it; replay their disposition).
///
/// "Alive" is one answer, not two: an over-budget charge parked by a peer's live attempt and an
/// in-budget charge leave the caller with the same disposition (stay pending, a later sweep
/// decides again). Where the difference is the decision, as in the sweep's pre-dispatch
/// self-heal, [`DeadLetterWrite::LiveAttempt`] names the class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a charge that did NOT dead-letter leaves the operation ALIVE — route on it, never \
              assume the budget closed anything"]
pub enum TransientCharge {
    /// The budget was charged and the operation is still alive: either budget remains, or it
    /// ran out while a live attempt not owned by this caller holds the operation.
    ChargedOnly,
    /// The budget was charged, ran out, and the operation was quiescent and non-terminal: the
    /// row now holds [`IntentStatus::Failed`], written in the same transaction as the charge.
    ChargedAndDeadLettered,
    /// Refused, nothing written: the row is already terminal (or does not exist, `None`), so
    /// there is no retry budget to spend. Carries what the row actually holds, as
    /// [`StatusWrite::Refused`] does.
    ChargeRefusedTerminal(Option<IntentStatus>),
}

/// What [`IntentLog::verify_undo_pair`] did: the undo verification's pair transition, as one
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a refused pair transition means the pair moved — re-route on it, never report a \
              verified undo"]
pub enum UndoPairFlip {
    /// Both preconditions held: the parent is `Undone`, and (when asked for) the child is
    /// `Applied`.
    Flipped,
    /// Refused, nothing written: the child is no longer non-terminal (a sever, adjudication,
    /// or peer settlement closed it under the caller's read). Carries its actual status.
    ChildMoved(Option<IntentStatus>),
    /// Refused, nothing written: the parent is neither `Applied` nor already `Undone`, so this
    /// verification is not the one the pair is owed. Carries its actual status.
    ParentMoved(Option<IntentStatus>),
}

/// Which half of the pair transition the child takes ([`IntentLog::verify_undo_pair`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoPairChild {
    /// Terminalize the child `Applied` in the same transaction. For wire-free lineages (the
    /// no-op kill), which hold no attempt and so have no verdict to record.
    Terminalize,
    /// Do not write the child; only require that it is still non-terminal. For
    /// attempt-carrying lineages, whose child terminal belongs to the verdict write
    /// ([`IntentLog::settle_attempt`]) so the lifecycle moves with the fact that justifies it.
    LeaveToSettlement,
}

/// Does a row holding `actual` satisfy `precondition`? The in-memory half of the compare,
/// kept beside its vocabulary (the SQLite half is [`status_precondition_sql`]); both
/// non-terminal arms derive from [`IntentStatus::is_terminal`].
pub(crate) fn status_precondition_holds(precondition: &StatusPrecondition, actual: &IntentStatus) -> bool {
    match precondition {
        StatusPrecondition::NonTerminal => !actual.is_terminal(),
        StatusPrecondition::Exactly(expected) => actual == expected,
    }
}

/// The SQL half of the compare: the `AND …` fragment a guarded `UPDATE` carries, plus the
/// status token `Exactly` binds (`None` for the non-terminal arm, which binds nothing).
///
/// The fragment is a compile-time constant in both arms: the non-terminal domain is
/// [`NON_TERMINAL_STATUS_SQL`], and the exact arm compares against a bound parameter, never
/// interpolated text.
pub(crate) fn status_precondition_sql(precondition: &StatusPrecondition) -> (String, Option<&'static str>) {
    match precondition {
        StatusPrecondition::NonTerminal => {
            (format!("status IN {NON_TERMINAL_STATUS_SQL}"), None)
        }
        StatusPrecondition::Exactly(expected) => {
            ("status = ?3".to_string(), Some(status_to_str(expected)))
        }
    }
}

/// The native-resource-key expression, re-exported from its home so every predicate in this
/// module interpolates the byte-identical text the index was built with (SQLite matches
/// expression indexes textually; a divergent copy silently plans a full scan).
pub(crate) use crate::store_open::NATIVE_KEY_EXPR_SQL;

/// The head-predecessor predicate: is there an earlier non-terminal intent on the same
/// underlying resource? Every admission and every recovery pass runs it.
///
/// A resource is identified by its frozen native key when it has one, and by the Photon-local
/// `message_ref` when it does not (a pre-stage-2 row with a NULL basis).
///
/// **The account scopes the fallback lane only.** A native key is provider-scoped and already
/// names the provider account, while `message_ref` is Photon-local and meaningless without one.
/// Two local account handles that resolve to the same provider account and message carry
/// identical native keys under different local accounts; an account-scoped native lane would
/// hide each handle's non-terminal intents from the other, letting the second dispatch past the
/// first and recovery apply the older mutation last. The native lane therefore keys on the
/// native key alone, and only the `message_ref` lane is account-scoped (`msg-1` under two
/// accounts is two different messages).
///
/// The fallback lane restricts the caller's key shape, not the candidate's. A store may hold
/// both generations on one message: a NULL-basis caller keys on its local ref, while a newer
/// non-terminal row on the same message carries a basis. Excluding candidates by basis would let
/// that row through and the head would look clear. An `(account, message_ref)` match therefore
/// blocks regardless of the candidate's basis. This is conservative: the lanes overlap, so a
/// rebind edge can defer an operation a perfect predicate would allow. Over-deferral parks work
/// for the next recovery sweep; under-deferral corrupts order.
///
/// The one fragment serves `has_non_terminal_native_predecessor` and PREPARE's in-transaction
/// re-verify, so the check and its re-verify cannot drift. They differ only in `exclude_self`.
///
/// Parameters: `?1` head seq bound, `?2` account (fallback lane only), `?3` native key, `?4`
/// fallback `message_ref`, and `?5` the idempotency key to exclude when `exclude_self`.
///
/// The two lanes are separate `EXISTS` subqueries rather than one `OR`: SQLite can use an index
/// for an `OR` only when every arm is independently indexable, and the NULL-basis arm had no
/// index, so the combined form planned `SCAN intents` on every admission and recovery pass.
/// Split, the native-key lane uses `idx_intents_native_key_guarded` and the fallback lane the
/// plain `idx_intents_account_msgref` (plain rather than partial, since the lane no longer
/// carries the partial index's `WHERE` clause). `EXISTS OR EXISTS` short-circuits. The plan is
/// pinned by `the_real_head_predecessor_predicate_never_plans_a_table_scan`.
pub(crate) fn non_terminal_native_predecessor_sql(exclude_self: bool) -> String {
    let exclusion = if exclude_self {
        "AND idempotency_key <> ?5"
    } else {
        ""
    };
    // The head filter is written once and interpolated into both lanes so they agree on which
    // rows are candidates. It carries no account: that belongs to the fallback lane alone.
    let head = format!("seq < ?1 AND status IN {NON_TERMINAL_STATUS_SQL} {exclusion}");
    format!(
        "SELECT (
           EXISTS (
             SELECT 1 FROM intents
              WHERE {head} AND {NATIVE_KEY_EXPR_SQL} = ?3
           )
           OR EXISTS (
             SELECT 1 FROM intents
              WHERE {head} AND account = ?2 AND message_ref = ?4
           )
         );"
    )
}

/// A recorded mutation intent: the command, its lifecycle status, and its durable sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub command: Command,
    pub status: IntentStatus,
    /// Durable monotonic record order (separate from the idempotency key). Replay and recovery
    /// are ordered by it so non-commutative mutations never re-apply out of order.
    pub seq: u64,
    /// Durable count of dispatch attempts that failed transiently. It survives restart so a
    /// crash-loop cannot retry forever: at [`RETRY_CAP`] the intent is dead-lettered to `Failed`
    /// (ADR-P013 (b)). A deterministic failure dead-letters immediately and never touches it.
    pub attempts: u32,
    /// The provider-native basis frozen into this intent by its admission transaction. `None`
    /// for rows admitted before the column existed; a non-terminal row with a NULL basis is what
    /// the open-time integrity scan surfaces. A present-but-malformed value is a `LogError`,
    /// never a silent `None`.
    pub frozen_basis: Option<crate::prestate::FrozenBasis>,
    /// Whether this operation owes a pre-state journal row: the capture mode bound as
    /// provenance at admission, not re-read from the current config head.
    pub journal_required: bool,
    /// Whether this intent's `Applied` effect has been written to the local projection
    /// (`message_header`/`message_placement`, through `apply_verb_delta`). Meaningless (and
    /// `false`) on a non-`Applied` row; `Applied` with `projected == false` means "owed", which
    /// [`IntentLog::applied_unprojected_forward_intents`] enumerates.
    pub projected: bool,
    /// The `message_header.ingest_revision` for (account, message_ref) at record time: the
    /// observation this intent's effect was committed against, frozen before the provider call
    /// and never re-derived at settle time. `None` when no header row existed yet.
    /// `ReadCoordinator::project_applied_intent` compares it with the row's current revision: a
    /// strictly newer row means a refresh observed the message after the effect was decided, and
    /// the stale delta must not overwrite it.
    ///
    /// One writer may advance it after record time: the projection path's sibling rule, inside
    /// its own transaction, moves it from `b` to the post-write revision iff this intent is
    /// forward (`compensates` NULL), still unprojected, its basis still equals `b` (the
    /// pre-write revision of the sibling just projected), and its own delta writes a different
    /// projection column (placement, `flagged`, `seen`) than that sibling's. A write to another
    /// column is not a newer observation for it; a same-column write never advances it.
    pub basis_ingest_revision: Option<i64>,
}

/// The durable `intents.status` token for `status`: the one spelling the store writes and
/// `status_from_str` reads back (public so the shell can project a member's status without a
/// second copy of this map).
pub fn status_to_str(status: &IntentStatus) -> &'static str {
    match status {
        IntentStatus::Pending => "pending",
        IntentStatus::Applied => "applied",
        IntentStatus::EvidenceSnapshotWritten => "evidence_snapshot_written",
        IntentStatus::Failed => "failed",
        IntentStatus::Undoing => "undoing",
        IntentStatus::Undone => "undone",
        // Status-set additions from ADR-P013.
        IntentStatus::Severed => "severed",
        IntentStatus::Adjudicated => "adjudicated",
        IntentStatus::ExternallySatisfied => "externally_satisfied",
    }
}

pub(crate) fn status_from_str(s: &str) -> Result<IntentStatus, LogError> {
    match s {
        "pending" => Ok(IntentStatus::Pending),
        "applied" => Ok(IntentStatus::Applied),
        "evidence_snapshot_written" => Ok(IntentStatus::EvidenceSnapshotWritten),
        "failed" => Ok(IntentStatus::Failed),
        "undoing" => Ok(IntentStatus::Undoing),
        "undone" => Ok(IntentStatus::Undone),
        "severed" => Ok(IntentStatus::Severed),
        "adjudicated" => Ok(IntentStatus::Adjudicated),
        "externally_satisfied" => Ok(IntentStatus::ExternallySatisfied),
        other => Err(LogError(format!("unknown status in intent log: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_status_reserves_an_evidence_snapshot_written_phase() {
        // D6.2: the outbox FSM reserves an explicit evidence/snapshot-written phase
        // BETWEEN local apply and provider submit — M0-unreachable, but named now so the
        // fail-closed gate attaches without an enum-breaking migration.
        assert_ne!(IntentStatus::EvidenceSnapshotWritten, IntentStatus::Applied);
    }

    // ---- THE STATUS-DOMAIN CLASS: every non-terminal predicate derives from ONE authority ----

    #[test]
    fn the_non_terminal_sql_domain_is_derived_from_is_terminal_not_hand_enumerated() {
        // The guard that makes `NON_TERMINAL_STATUS_SQL` a DERIVED fragment rather than a third
        // hand-written list: regenerate it from the lifecycle enum itself. Adding a status (or
        // changing `is_terminal`) without updating the fragment fails HERE, once — the one edit
        // the whole class collapses to.
        let derived = format!(
            "({})",
            IntentStatus::ALL
                .iter()
                .filter(|s| !s.is_terminal())
                .map(|s| format!("'{}'", status_to_str(s)))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(derived, NON_TERMINAL_STATUS_SQL);
        // …and `ALL` is itself complete: this match is exhaustive, so a new variant is a
        // COMPILE error here until it is added to `ALL`.
        assert_eq!(
            IntentStatus::ALL.len(),
            IntentStatus::ALL
                .iter()
                .map(|s| match s {
                    IntentStatus::Pending => 1,
                    IntentStatus::Applied => 1,
                    IntentStatus::EvidenceSnapshotWritten => 1,
                    IntentStatus::Failed => 1,
                    IntentStatus::Undoing => 1,
                    IntentStatus::Undone => 1,
                    // Stage 4 (design §7a P013 status-set additions).
                    IntentStatus::Severed => 1,
                    IntentStatus::Adjudicated => 1,
                    IntentStatus::ExternallySatisfied => 1,
                })
                .sum::<usize>()
        );
    }

    #[test]
    fn every_status_round_trips_through_its_str_encoding() {
        // `status_to_str`/`status_from_str`
        // are the ONE (de)serialization authority for the persisted `intents.status` column —
        // a status that encodes but does not decode (or vice versa) is a silent data-loss trap
        // on the very next open. `IntentStatus::ALL` is the exhaustive domain, so this test
        // covers every future addition automatically once it lands in `ALL`.
        for status in IntentStatus::ALL {
            let encoded = status_to_str(&status);
            let decoded = status_from_str(encoded).unwrap_or_else(|e| {
                panic!("status_from_str({encoded:?}) must round-trip {status:?}: {e:?}")
            });
            assert_eq!(decoded, status, "round-trip mismatch for {encoded:?}");
        }
        // The three stage-4 additions specifically, byte-exact (house style: lower snake_case,
        // matching every existing token) — pinned so a future rename is a deliberate edit here,
        // not a silent drift caught only by the loop above.
        assert_eq!(status_to_str(&IntentStatus::Severed), "severed");
        assert_eq!(status_to_str(&IntentStatus::Adjudicated), "adjudicated");
        assert_eq!(
            status_to_str(&IntentStatus::ExternallySatisfied),
            "externally_satisfied"
        );
    }
}
