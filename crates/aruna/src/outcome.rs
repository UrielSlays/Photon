//! What the command bus answers: `ExecuteError`, `Executed`, the witness record, and the recovery report.

use crate::{ConnectorError, LogError};

#[cfg(doc)]
use crate::{prestate, Claim, Command, CommandBus, IntentLog};

/// Why a command could not be executed through the mutation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError {
    /// The durable intent could not be persisted. Under write-ahead ordering the apply was
    /// not attempted (or, post-apply, the status could not be reconciled); never silent loss.
    Log(LogError),
    /// The connector rejected the mutation below the seam.
    Connector(ConnectorError),
    /// Admission was refused before anything durable happened: the connector could not
    /// resolve a basis, or resolved one that is not structurally a basis. Distinct from
    /// [`ExecuteError::Log`]: this is a pre-durable, retryable signal. The refusal is raised
    /// ahead of `record()`, so nothing was written (no intent row, no ordering key, no
    /// dispatch) and the same command may be re-submitted once the resolver is seeded. `Log`
    /// means the opposite: the store itself is in doubt. The payload is the connector's own
    /// fixed, id-free refusal phrase (see `gmail::GmailBasisRefusal` /
    /// `jmap::JmapBasisRefusal`); it carries no provider-native handle.
    AdmissionRefused(String),
    /// Admission was refused by the derived-occupancy capacity check
    /// ([`Claim::CapacityRefused`]). Nothing durable was written (the same pre-durable contract
    /// as [`ExecuteError::AdmissionRefused`]), but the refusal is occupancy-shaped: retry once
    /// occupancy drains or a config change lands. The payload is the refusal's own display text
    /// (which inequality refused, and the observed numbers).
    CapacityRefused(String),
    /// A different command was submitted under an existing idempotency key (ADR-P013
    /// `Conflict`). The durable command is immutable; the rewrite is refused, never silently
    /// overwritten.
    Conflict,
    /// The intent for this key is still in flight (`Pending`/`Undoing`): recovery owns it; retry
    /// later. The 409-while-processing analog; never reported as success (ADR-P013
    /// `InProgress`).
    InProgress,
    /// An identical retry of an intent that terminally failed (dead-letter): the stored failure
    /// is replayed as an error, never a silent `Ok` (ADR-P013).
    Failed,
    /// The send-authorization check refused before the wire because an atom this operation would
    /// touch still carries an unresolved exposure, and closed the operation with the deterministic
    /// no-effect terminal. A dead-letter like [`ExecuteError::Failed`]; the payload makes it
    /// actionable.
    ///
    /// The payload names the blocking obligation. The refusal is written into the terminal's own
    /// fact payload and this variant is that value read back, so a dispatching call and an
    /// identical replay name the same thing. What it names is Photon-local, not provider-native:
    /// the crate's confinement discipline covers provider-native identifiers, not only content
    /// (`crate::jmap`'s `no_provider_ids_leak_into_surfaced_errors`;
    /// [`ExecuteError::AdmissionRefused`]). The raw `exposure_atom_key` encodes an account, a
    /// message and a mailbox, so it stays durable-internal and the caller gets the blocking
    /// `exposure_obligation`'s engine-minted opaque row id instead. That is a reference, not a
    /// dead end: [`IntentLog::exposure_obligation`] resolves it, and nothing evicts that row.
    ExposureBlocked {
        /// The blocking obligation's engine identity (see
        /// [`crate::attempt::ExposureBlock::obligation_id`]).
        obligation: String,
    },
    /// Undo is unavailable for this intent, with the mechanical reason. A
    /// [`prestate::UndoUnavailableReason::JournalGapUnexplained`] is an integrity warning, not a
    /// benign configuration message; render it accordingly.
    UndoUnavailable(crate::prestate::UndoUnavailableReason),
    /// Pair conflict: the observed state matches neither the captured pre-state nor the
    /// forward target. Refused, never blind-written; the remedy is a new forward action.
    UndoConflict,
    /// A replay of an identical fingerprint against a `Severed` operation: never
    /// re-dispatched, never a silent `Ok`.
    Severed,
    /// A replay of an identical fingerprint against an `ExternallySatisfied` operation: the
    /// target state was achieved by another actor; never re-dispatched, never undo-eligible.
    ExternallySatisfied,
    /// A replay of an identical fingerprint against an `Adjudicated` operation whose
    /// historical axis is still unknown: an operator has decided, and nobody knows what the
    /// provider did. Its resolved sibling is [`ExecuteError::AdjudicatedLate`].
    AdjudicatedUnresolved,
    /// A replay against an `Adjudicated` operation whose historical axis a `LATE_ACK_*` has since
    /// resolved: the `AdjudicatedLate(Applied | RefusedNoEffect)` class ADR-P013 names, carrying
    /// which resolution landed.
    ///
    /// This is not `Ok(())` / `Err(Failed)`. Mapping the resolved history onto the ordinary
    /// lifecycle's two answers erases the route, and the ADR forbids that pair by name: a replay
    /// returns "its own truthful `Err` class ... never the generic dead-lettered `Err(Failed)` and
    /// never a silent `Ok`". An operation closed by an authority-gated adjudication is neither an
    /// ordinary `Applied` no-op nor a provider rejection, and a late ack resolves the historical
    /// axis only: it never re-opens the operation or re-authorizes dispatch.
    ///
    /// Both polarities take this variant with a different payload, the engine's own late-ack
    /// vocabulary ([`crate::attempt::LateAck`]). For the caller the operation is terminal either
    /// way (never re-issue or re-dispatch), but `Applied` means the effect provably landed (a
    /// re-issue would duplicate it) and `RefusedNoEffect` that it provably did not (a new action
    /// is the remedy, never a retry of this key).
    AdjudicatedLate(crate::attempt::LateAck),
    /// A plan child refused by name with nothing written: by `record()`'s admission arm
    /// ([`Claim::PlanChildRefused`]), by [`CommandBus::execute`]'s first check (a plan link on a
    /// verb whose tier does not `requires_plan()` answers `NotARedVerb`), or by a plan
    /// entry point's episode status check ([`CommandBus::apply_plan_member`],
    /// [`CommandBus::preflight_plan`]).
    PlanChildRefused(crate::plan::PlanChildRefusal),
    /// A verb whose tier `requires_plan()` (`Trash`, `MarkSpam`) was submitted without a plan
    /// link. [`CommandBus::execute`] refuses it before anything is read or written, so every
    /// replay answers the same. A red-tier effect reaches the bus only as a plan child
    /// ([`Command::plan_child`]).
    PlanRequired,
    /// The send check's plan arm closed this child `Failed`: the refusal as its
    /// `FAILED_PRE_SEND` record rebuilds it ([`crate::plan::PlanSendRefusal::from_record`]),
    /// read back through [`IntentLog::plan_refusal`], so a dispatching call and an identical
    /// replay name the same value (as with [`ExecuteError::ExposureBlocked`]). A held refusal
    /// leaves the row open and is answered [`ExecuteError::InProgress`].
    PlanRefused { reason: crate::plan::PlanSendRefusal, member_ref: String },
}

/// What [`CommandBus::execute`] answers for an operation that is durably applied: the applied
/// result, and what became of the route's effect witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    pub witness: WitnessRecord,
}

closed_tokens! {
    /// Which step of the effect-witness write failed after the settlement committed. Content-free
    /// by type: the step, never the store's text.
    pub enum WitnessWriteFailure {
        /// Reading the operation's captured pre-state (its pre-effect label vector).
        PreStateRead => "pre_state_read",
        /// Writing the witness columns themselves.
        WitnessWrite => "witness_write",
    }
}

/// What became of an applied operation's effect witness, as the call that answered saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRecord {
    /// This call dispatched, the settlement committed, and the route's witness was persisted (or
    /// the route answered no label vector, so there was nothing to persist).
    Persisted,
    /// This call did not dispatch: an identical replay of an operation already applied (or
    /// otherwise settled `Ok`). The witness is whatever the dispatching call left, read through
    /// [`CommandBus::restoration`].
    NotDispatched,
    /// This call's dispatch applied and its settlement committed (the operation is durably
    /// `Applied` and its undo key is real), but the witness write that follows failed.
    /// Restoration is undetermined (no effect witness), the same class as a witness that cannot
    /// be read. Never an error: an error would discard the undo key of an applied operation and
    /// invite a retry that mints a second key over already-mutated state.
    WriteFailed(WitnessWriteFailure),
}

/// Outcome of a recovery sweep. A connector rejection leaves that intent in its non-terminal
/// state (transient and retryable, never hard-`Failed`; ADR-P013) and lists it in `failed` for
/// this sweep, but does not abort the sweep: later intents are still recovered. Only a
/// durable-log error aborts recovery (the store can no longer be trusted).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoverReport {
    pub recovered: usize,
    pub failed: Vec<(String, ConnectorError)>,
    /// Legacy `Undoing` rows this sweep mapped back to `Applied`. The old fast path stored
    /// `Undoing` on the parent before dispatching a blind inverse, so whether that inverse
    /// landed is unknowable. The sweep maps them to the last verified truth and names them
    /// here rather than healing them silently.
    pub legacy_undoing: Vec<String>,
    /// Legacy deferred-undo children this sweep mapped, kept as its own vector because it
    /// names a different row (the compensation, by its key) and a different repair.
    ///
    /// The old defer path flipped the parent `Undone` at scheduling and recorded the child
    /// under the old key shape. Recovery then hit the parent-already-`Undone` convergence
    /// short-circuit and marked that child `Applied` with no restore ever dispatched, so the
    /// provider silently stayed in forward state. The sweep now sets such a parent back to
    /// `Applied` (the last verified truth), terminalizes the child `Failed`, and names the
    /// child here. The parent regains an honest undo through the new path.
    pub legacy_compensations: Vec<String>,
    /// Undo children this sweep refused on a pair conflict: the observed current state matched
    /// neither the captured pre-state `P` nor the forward target `A`, so `drive_undo_child`
    /// terminalized the child `Failed` and left the parent truthfully `Applied`, with no blind
    /// write. The pair is durably settled, so it is neither a barrier nor a retryable `failed`
    /// entry; but the sweep names the refused undo, or a batch caller cannot tell a
    /// conflict-refused undo from one that never ran. Keyed by the child's own key, like
    /// `legacy_compensations`. The remedy is a new forward action, never a re-undo.
    pub undo_conflicts: Vec<String>,
    /// Keys this sweep settled `Applied` whose effect-witness write then failed, the recovery
    /// sweep's mirror of `Executed::witness`'s `WitnessRecord::WriteFailed`. Non-fatal: the
    /// sweep continues and the settlement stands (the operation is durably `Applied`); only the
    /// witness is unusable. A shell driver maps these keys back to plan members
    /// (`plan_child_command`'s idempotency key) as it does for `execute`'s own `WriteFailed`.
    pub witness_write_failed: Vec<String>,
    /// `Some((key, error))` names the intent whose connector error stopped the sweep, because
    /// that error ends the run (today: [`ConnectorError::credential_rejected`]). Every
    /// unreconciled intent the sweep had not yet reached is left untouched: not dispatched, not
    /// reconciled, not barrier-raised. `None` means the sweep ran to completion; an ordinary
    /// connector failure still lands in `failed` and the sweep continues past it.
    pub stopped_by: Option<(String, ConnectorError)>,
}
