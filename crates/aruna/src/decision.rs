//! The single idempotency decision for a command against the durable log.

use crate::{
    AdjudicatedHistory, Command, ExecuteError, Executed, Intent, IntentStatus, WitnessRecord,
};

/// A terminal intent status: the command is consumed, and replaying it must never re-apply
/// (ADR-P013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Terminal {
    Applied,
    Undone,
    /// A dead-letter, carrying why when the fact chain holds a reason the status column
    /// cannot express: an exposure block names the blocking obligation's engine id (in the
    /// id-free form). Like [`Terminal::Adjudicated`], the detail is read from the fact chain
    /// and projected to its surfaceable half by [`CommandBus::failed_why`], only when the
    /// status is already `Failed`. The plan-child path adds the plan-admission record as the
    /// second reason ([`FailedWhy`]).
    Failed(FailedWhy),
    /// ADR-P013 status-set addition.
    Severed,
    /// Adjudication closed the operational axis by decision. What the replay owes the caller
    /// depends on the historical axis, which adjudication leaves open and a `LATE_ACK_*` may
    /// later resolve, so the class carries it: the status column alone cannot tell the three
    /// cases apart, and answering `AdjudicatedUnresolved` for all three would deny a truth the
    /// engine holds.
    Adjudicated(AdjudicatedHistory),
    ExternallySatisfied,
}

/// Why a `Failed` operation failed, when its fact chain records a reason the status column
/// cannot express. Read only for a row already `Failed`, by [`CommandBus::failed_why`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FailedWhy {
    /// The chain records none: the plain dead-letter.
    Unrecorded,
    /// The blocking obligation's engine id.
    Exposure(String),
    /// The plan arm's refusal, rebuilt from its record, and the member.
    Plan { reason: crate::plan::PlanSendRefusal, member_ref: String },
}

/// A non-terminal (in-flight) intent status: recovery owns it, and a replay must neither
/// re-record nor re-dispatch (ADR-P013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonTerminal {
    Pending,
    Undoing,
    EvidenceSnapshotWritten,
}

/// The single idempotency decision for a command against the durable log (ADR-P013). Keyed on
/// status so the `IntentStatus` match in `classify` is the one exhaustive point (a new status
/// is a compile error there until mapped), while call sites match `Decision` exhaustively and
/// never touch raw status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// No durable row for this key: reserve and dispatch.
    Fresh,
    /// Same key, a different command fingerprint: refuse; the system of record is immutable.
    Conflict,
    /// Same key, an in-flight (non-terminal) intent: recovery owns it; never re-record or
    /// re-dispatch.
    InProgress(NonTerminal),
    /// Same key, a consumed (terminal) intent: replay the terminal outcome; never re-apply.
    TerminalReplay(Terminal),
}

/// Classify a command against the existing durable row for its key (ADR-P013). Pure: no mutation;
/// the durable claim of a `Fresh` key is made atomically by `IntentLog::record`. The fingerprint
/// is the full `Command` (including the `ActionEnvelope`): a same-key submission differing in any
/// field (e.g. a different principal or epoch) is a `Conflict`, not a replay.
///
/// `adjudicated` is the operation's historical axis, read from the fact chain by
/// [`CommandBus::decide`] and consulted only by the `Adjudicated` arm, so the caller only pays
/// for the read for that status. `failed_why` has the same shape for the `Failed` arm: the
/// surfaceable half of an exposure block (the blocking obligation's engine id) or the plan arm's
/// rebuilt refusal, projected before this call ([`CommandBus::failed_why`]).
pub(crate) fn classify(
    existing: Option<&Intent>,
    command: &Command,
    adjudicated: AdjudicatedHistory,
    failed_why: FailedWhy,
) -> Decision {
    let Some(intent) = existing else {
        return Decision::Fresh;
    };
    if intent.command != *command {
        return Decision::Conflict;
    }
    match intent.status {
        IntentStatus::Pending => Decision::InProgress(NonTerminal::Pending),
        IntentStatus::Undoing => Decision::InProgress(NonTerminal::Undoing),
        IntentStatus::EvidenceSnapshotWritten => {
            Decision::InProgress(NonTerminal::EvidenceSnapshotWritten)
        }
        IntentStatus::Applied => Decision::TerminalReplay(Terminal::Applied),
        IntentStatus::Undone => Decision::TerminalReplay(Terminal::Undone),
        IntentStatus::Failed => Decision::TerminalReplay(Terminal::Failed(failed_why)),
        // Unreachable for now (no production writer sets this yet), but the exhaustive
        // match forces the replay contract to be decided here.
        IntentStatus::Severed => Decision::TerminalReplay(Terminal::Severed),
        IntentStatus::Adjudicated => Decision::TerminalReplay(Terminal::Adjudicated(adjudicated)),
        IntentStatus::ExternallySatisfied => {
            Decision::TerminalReplay(Terminal::ExternallySatisfied)
        }
    }
}

/// An `execute()` answer from a path that did not dispatch (a replay, a park, a settled row
/// read back): an `Ok` there is [`WitnessRecord::NotDispatched`], since this call wrote no
/// witness.
pub(crate) fn not_dispatched(outcome: Result<(), ExecuteError>) -> Result<Executed, ExecuteError> {
    outcome.map(|()| Executed { witness: WitnessRecord::NotDispatched })
}

/// Map a `Decision` to the `execute()` outcome (the ADR-P013 return-signal contract), or `None`
/// for `Fresh` (the caller proceeds to the atomic claim and dispatch). Kept in one place so the
/// truth table is applied identically before the claim and after a lost claim race.
pub(crate) fn decision_outcome(decision: Decision) -> Option<Result<(), ExecuteError>> {
    match decision {
        // Fresh: the caller claims and dispatches.
        Decision::Fresh => None,
        // A different command under an existing key: refuse the rewrite, never overwrite the record.
        Decision::Conflict => Some(Err(ExecuteError::Conflict)),
        // In flight: recovery owns it. Never re-record or re-dispatch; a distinct
        // not-yet-succeeded signal, never `Ok`.
        Decision::InProgress(_) => Some(Err(ExecuteError::InProgress)),
        // Consumed terminal replay: Applied/Undone are a no-op `Ok`; a dead-lettered `Failed`
        // replays the failure (never a silent `Ok` for a failed action).
        Decision::TerminalReplay(Terminal::Applied | Terminal::Undone) => Some(Ok(())),
        Decision::TerminalReplay(Terminal::Failed(FailedWhy::Unrecorded)) => Some(Err(ExecuteError::Failed)),
        // The exposure dead-letter, named. Same class as `Failed` (consumed, never
        // re-dispatched, never a silent `Ok`), and the reference is the actionable part. It is
        // the blocking obligation's engine id, never the provider-native atom; see
        // [`CommandBus::decide`].
        Decision::TerminalReplay(Terminal::Failed(FailedWhy::Exposure(obligation))) => {
            Some(Err(ExecuteError::ExposureBlocked { obligation }))
        }
        // The plan arm's terminal, named: same class as `Failed`, carrying the value the
        // refusing transaction recorded.
        Decision::TerminalReplay(Terminal::Failed(FailedWhy::Plan { reason, member_ref })) => {
            Some(Err(ExecuteError::PlanRefused { reason, member_ref }))
        }
        // Unreachable for now; see `classify`.
        Decision::TerminalReplay(Terminal::Severed) => Some(Err(ExecuteError::Severed)),
        Decision::TerminalReplay(Terminal::ExternallySatisfied) => {
            Some(Err(ExecuteError::ExternallySatisfied))
        }
        // The operation is terminal either way; what the caller is owed is what the
        // historical axis says. That mapping lives in [`adjudicated_replay_outcome`], shared
        // with the contradicted-settlement path so an in-flight call and an identical replay
        // cannot answer differently about the same chain.
        Decision::TerminalReplay(Terminal::Adjudicated(history)) => {
            Some(Err(adjudicated_replay_outcome(history)))
        }
    }
}

/// The caller-visible result an adjudicated operation's historical axis implies. It is shared by
/// [`decision_outcome`]'s three `Adjudicated` arms and by the answer a contradicted settlement
/// owes its caller ([`DispatchSettlement::contradicted`]), so an in-flight call and an identical
/// replay cannot disagree about the same chain.
///
/// Every arm names the adjudication, so it returns an `ExecuteError` rather than a `Result`.
/// ADR-P013 forbids answering the resolved arms with the ordinary lifecycle's `Ok(())` or
/// `Err(Failed)`: each terminal returns "its own truthful `Err` class ... never the generic
/// dead-lettered `Err(Failed)` and never a silent `Ok`". That class is
/// `AdjudicatedLate(Applied | RefusedNoEffect)`. The operational axis is closed by decision in
/// all three arms (what the variant says); the historical axis is what the payload (or, for
/// `AdjudicatedUnresolved`, its absence) says.
pub(crate) fn adjudicated_replay_outcome(history: AdjudicatedHistory) -> ExecuteError {
    match history {
        // Nobody knows what the provider did.
        AdjudicatedHistory::Unresolved => ExecuteError::AdjudicatedUnresolved,
        // The effect provably happened, on an operation an adjudication closed. A replay must
        // never re-apply it, and must not read as an ordinary `Applied` no-op either: the
        // closure route is part of what the caller is owed.
        AdjudicatedHistory::ResolvedApplied => {
            ExecuteError::AdjudicatedLate(crate::attempt::LateAck::Applied)
        }
        // The effect provably did not happen and no retry is authorized. Still not the generic
        // dead-letter: a provider's deterministic rejection and an adjudicated closure whose
        // late ack proved no effect are different histories with different remedies.
        // Symmetric with the arm above.
        AdjudicatedHistory::ResolvedRefusedNoEffect => {
            ExecuteError::AdjudicatedLate(crate::attempt::LateAck::RefusedNoEffect)
        }
    }
}
