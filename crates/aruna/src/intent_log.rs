//! The durable intent-log contract: the `IntentLog` trait, its outcome types, and `LogError`.

use crate::{
    Command, DeadLetterWrite, EffectEvidence, EffectWitness, EffectWitnessRow, FailureKind, Intent,
    IntentStatus, StatusPrecondition, StatusWrite, TransientCharge, UndoPairChild, UndoPairFlip,
};

#[cfg(doc)]
use crate::{prestate, ExecuteError, UndoPresentation};

/// An error from the durable intent log: I/O, serialization, or corruption below the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogError(pub String);

/// `GatedConnection::with_immediate_tx` is generic over the caller's error type, which costs
/// these two conversions. They cover only the two errors it raises itself (`BEGIN IMMEDIATE`
/// and `COMMIT`); every statement inside a transaction still maps its own error with its own
/// message.
impl From<rusqlite::Error> for LogError {
    fn from(e: rusqlite::Error) -> LogError {
        LogError(e.to_string())
    }
}

/// A writer-gate refusal (an unobtainable identity, a poisoned arbiter, a re-entrant
/// enrollment) is reported verbatim, never flattened into "the database is busy".
impl From<crate::writer_gate::GateError> for LogError {
    fn from(e: crate::writer_gate::GateError) -> LogError {
        LogError(e.to_string())
    }
}

/// The record is immutable per idempotency key: re-recording a different command under an
/// existing key is rejected, never overwritten (recovery would replay the wrong command).
pub(crate) fn key_rewrite_rejected(key: &str) -> LogError {
    LogError(format!(
        "idempotency key '{key}' already records a different command; refusing to overwrite the system-of-record"
    ))
}

/// Result of the atomic claim in `IntentLog::record`: did this call insert the fresh row, or
/// did a row for the key already exist? Only the inserter owns the dispatch, so `execute()`
/// cannot double-dispatch under same-key concurrency. A different command under an existing key
/// is still a `LogError`. (ADR-P013)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// This call inserted the fresh `Pending` row; the caller owns the dispatch.
    Inserted,
    /// A row for this key already existed (a concurrent or prior identical claim). The caller
    /// must not dispatch; it re-derives the decision from the existing row.
    AlreadyExisted,
    /// Admission was refused by the derived-occupancy capacity check, inside the same
    /// transaction; nothing durable was written. This is `Ok`, not `Err`, because like
    /// `AlreadyExisted` it is an ordinary admission answer, not a storage failure: the caller may
    /// retry once occupancy drains or a config change lands. The payload is the display text of
    /// the private `crate::capacity::CapacityRefusal` (which variant refused, and the observed
    /// numbers).
    CapacityRefused(String),
    /// The plan-child admission arm refused, by name, inside the same transaction; no `intents`
    /// row was written (same contract as `CapacityRefused`). Only a command carrying a plan link
    /// ([`Command::plan_child`]) can receive it.
    PlanChildRefused(crate::plan::PlanChildRefusal),
}

/// What a dispatch asks for when it claims an attempt: the ownership-establishing `CLAIM`
/// fact's content plus the compare half of compare-and-append.
///
/// `observed_attempts` is the durable dispatch episode the caller is acting on (the
/// `Intent::attempts` value from the read behind this decision). It makes the claim a
/// compare-and-append rather than a bare insert: a driver holding a read taken before another
/// driver charged the row is acting on a world that no longer exists, and its claim must lose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptClaim {
    /// 1-based attempt ordinal within the owning operation. Current callers always claim ordinal
    /// 1; retry lineage (ordinal > 1) is wired by the retry path against the predecessor's
    /// terminal verdict facts.
    pub ordinal: u64,
    /// The mandatory `(predecessor_attempt_id, reason)` for every ordinal > 1. `None` iff
    /// `ordinal == 1`; the grammar refuses either mismatch.
    pub predecessor: Option<crate::attempt::RetryPredecessor>,
    /// The dispatch episode the caller observed (`Intent::attempts` at its read).
    pub observed_attempts: u32,
}

/// The verdict of [`IntentLog::claim_attempt`]: is this dispatch mine to make?
///
/// A lost race is `AlreadyClaimed`, never an `Err`: the arbiters are SQL constraints
/// (`UNIQUE (attempt_id, revision)` and `UNIQUE (operation_id, attempt_ordinal)`), and losing
/// to one is the normal outcome of two drivers doing their job, as with
/// [`Claim::AlreadyExisted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// This driver owns the dispatch: either this call appended the `CLAIM` fact, or the
    /// operation's single attempt is already claimed and the caller's observation is still
    /// current (see the re-entry paragraph on [`IntentLog::claim_attempt`]).
    Won {
        /// The owned attempt's opaque id.
        attempt_id: String,
        /// Its ordinal.
        ordinal: u64,
        /// The chain revision this claim saw: `1` for a freshly minted attempt (the `CLAIM` fact
        /// this call appended), or the head revision of the attempt a re-entry joined.
        ///
        /// Re-entry is not exclusive: two drivers holding equally-current reads both win the same
        /// live attempt, and only one may put a verdict on it before the wire. Every pre-wire
        /// settlement carries this value back to [`IntentLog::settle_attempt`], which
        /// compare-and-appends against it, so a chain that moved since the caller's read (above all a
        /// peer's `SEND_AUTHORIZED`) refuses the settle instead of terminalizing an attempt that is
        /// on the wire.
        observed_revision: u64,
        /// The attempt's fact-derived class as this claim leaves it:
        /// [`crate::attempt::DerivedState::class`] over the chain just read (re-entry) or written
        /// (fresh mint, always [`crate::attempt::AttemptClass::PreIssuance`]), the same authority
        /// `attempt_head.derived_class` persists.
        ///
        /// A live attempt is one of two classes. `PreIssuance` is provably wire-free;
        /// `IssuedOrUnknown` has a committed `SEND_AUTHORIZED` and may have spent the wire under a
        /// driver that died before recording its verdict. Every pre-wire decision (above all the
        /// retry requalification, whose `C == A` arm writes a proven-no-wire terminal) is honest for
        /// the first and false for the second, so the caller is told which it holds rather than
        /// inferring it from the ordinal.
        class: crate::attempt::AttemptClass,
    },
    /// Not this driver's dispatch: the operation settled under it, the episode advanced under it,
    /// or it lost the constraint race. The caller must not reach the wire.
    AlreadyClaimed,
    /// Nobody's dispatch: the operation's attempt is `ISSUANCE_UNKNOWN` (`ACK_AMBIGUOUS`). It is
    /// operationally open, but there is no retry from `ACK_AMBIGUOUS`/`ISSUANCE_UNKNOWN`
    /// (adjudication is the only path), and it has already spent its one potentially effectful
    /// dispatch. Distinct from `AlreadyClaimed` because the reason is not a race: no driver may
    /// dispatch this operation until adjudication closes it.
    AwaitingAdjudication,
    /// The closed grammar refused the `CLAIM` (enforced by the single append function).
    RefusedByGrammar(crate::attempt::GrammarRefusal),
    /// The operation's `admitted_control_epoch` is no longer the current `control_epoch`: a sever
    /// landed under this driver. The caller parks; the sever machinery terminalizes.
    EpochFenced,
}

/// The verdict of [`IntentLog::authorize_send`]: may this dispatch touch the wire now, under
/// the epoch it was claimed under?
///
/// Three of the four variants are refusals, and two of those terminalize inside the refusing
/// transaction: a sever that fences the send terminalizes the attempt
/// `SEVERED_BEFORE_ISSUANCE`, and a failed authoritative exposure check refuses fail-closed,
/// pre-wire, with a deterministic no-effect terminal. A refusal that only said "no" would
/// strand the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendAuthOutcome {
    /// The `SEND_AUTHORIZED` fact is committed. The caller may enter the connector socket, and
    /// only the caller that got this answer may.
    Authorized {
        /// The exposure key this authorization copied into the fact payload.
        exposure_key: crate::attempt::ExposureKey,
    },
    /// The capture CAS refused: the operation's journal row is no longer the one this dispatch's
    /// decision was made against. Another driver's requalification re-prepared it (a versioned
    /// replace) between the decision and this authorization, so the `P` a later undo would restore
    /// is not the `P` this caller qualified against.
    ///
    /// Pre-wire and non-terminal: nothing was written or sent, and the loser re-runs
    /// requalification against the row as it now is.
    CaptureSuperseded {
        /// What the caller asserted its decision read.
        expected: CaptureBinding,
        /// What the durable row holds (`None` = no journal row at all).
        found: Option<u64>,
    },
    /// A sever fenced this send. Two shapes answer the same way: the epoch already moved
    /// (`control_epoch != claim.claim_epoch`), so the attempt is terminalized
    /// `SEVERED_BEFORE_ISSUANCE` and its operation `Severed` atomically with this refusal; or the
    /// belt: a sever is ticketed but not yet served (the epoch has not moved), caught by
    /// re-reading the gate's pending-sever state as this transaction's first act. The belt writes
    /// nothing, because the pending sever's own transaction (unblocked when this call returns)
    /// performs the identical terminalizing closure moments later on the un-authorized claim.
    EpochFenced,
    /// EXP-3: an unretired exposure obligation overlaps this operation's touched atoms and no
    /// risk acceptance can cover it (this build ships no acceptance capability). Refused
    /// fail-closed pre-wire, with the deterministic no-effect terminal (`FAILED_PRE_SEND`,
    /// proven-no-wire, operation `Failed`) written in the same transaction.
    ///
    /// This value stays at the store-trait level and keeps the provider-native atom: a caller of
    /// `authorize_send` holds the store, so it holds the atom already. The caller-facing boundary,
    /// [`ExecuteError::ExposureBlocked`] (returned by `execute`/`undo`/`recover`), carries the
    /// Photon-local obligation reference instead. The dispatch path never reads this field; it
    /// re-reads the row and answers what a replay answers (`CommandBus::authorization_refusal`,
    /// private), so no path leads from here to the public surface.
    ExposureBlocked {
        /// The first overlapping atom identity, named rather than a bare "no". Provider-native,
        /// so internal (see above).
        atom_key: String,
    },
    /// The closed grammar refused the `SEND_AUTHORIZED` append. The reachable case is
    /// [`crate::attempt::GrammarRefusal::DuplicateSendAuthorized`]: "at most one
    /// `SEND_AUTHORIZED`" makes a second driver with an equally-current read lose the wire (the
    /// residual named on [`IntentLog::claim_attempt`]).
    RefusedByGrammar(crate::attempt::GrammarRefusal),
    /// The plan-admission arm refused (the approval-binding contract, re-verified at send; see
    /// [`IntentLog::authorize_send`]'s plan rows). For an attempt this transaction found not yet
    /// authorized, a terminal refusal ([`crate::plan::PlanSendRefusal::is_terminal`]) wrote
    /// `FAILED_PRE_SEND` (proven-no-wire, with the typed `plan_refusal` record) and closed the
    /// operation `Failed` in this transaction; a held refusal wrote no fact and no status. For an
    /// attempt that already holds its `SEND_AUTHORIZED`, no refusal writes a fact or a status (it
    /// may have touched the wire).
    PlanRefused(crate::plan::PlanSendRefusal),
}

/// The capture CAS token: what a wire-bound dispatch asserts its decision was made against,
/// spent inside [`IntentLog::authorize_send`]'s transaction.
///
/// It closes this race: two recovery buses re-enter one operation's retry, each observes the
/// provider for itself, and the requalification replace commits independently of the
/// authorization that follows it. Bus A decides against generation `g`, bus B re-prepares to
/// `g+1`, and A, holding a decision about a row that no longer exists, dispatches. A later undo
/// would then restore B's snapshot, not the one A dispatched against. The authorizing
/// transaction is the only place the token can be spent: it is the last pre-wire boundary,
/// and SQLite's single writer linearizes it against the replace.
///
/// It is total, so it cannot be skipped: every caller states which shape its operation is and
/// the store checks it. `Generation(g)` requires a row at exactly `g`; `NoJournalRow` requires
/// that there is no row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBinding {
    /// This dispatch's decision read the operation's journal row at this exact
    /// `capture_generation`.
    Generation(u64),
    /// This operation owns no journal row, so the decision read none: a capture-off operation
    /// (forbidden a row), or an undo child (its `P` is the parent's row, which cannot be replaced
    /// under it; see [`IntentLog::authorize_send`]).
    NoJournalRow,
}

/// Does the caller's CAS token still describe the durable row? One predicate shared by both
/// stores' [`IntentLog::authorize_send`], so the mirror and the durable store cannot drift.
pub(crate) fn capture_binding_holds(capture: CaptureBinding, found: Option<u64>) -> bool {
    match (capture, found) {
        (CaptureBinding::Generation(expected), Some(actual)) => expected == actual,
        (CaptureBinding::NoJournalRow, None) => true,
        // A capture-on decision over a vanished row, and a "no row" assertion over a row that
        // exists, are the same thing: the caller decided against a world that has moved.
        _ => false,
    }
}

/// The belt: `authorize_send`'s first act inside its own `BEGIN IMMEDIATE`. Is a sever
/// ticketed right now? A separate fn because the gate handle must be captured outside the
/// closure (see `SqliteIntentLog::authorize_send`); production and its tests share it.
///
/// It closes a window ordinary enrollment blocking cannot see: a writer that enrolled before a
/// sever ticket rose is never parked by [`WriterGate::enroll`](crate::writer_gate::
/// WriterGate::enroll), so inside its transaction a sever can be pending with the epoch still
/// unbumped, which the ordinary `epoch != claim.claim_epoch` re-read cannot catch either. This
/// read asks the gate directly instead of asking what the gate has already made durable.
///
/// It writes nothing: refusing leaves the claim without a `SEND_AUTHORIZED` fact, which the
/// pending sever's own transaction will find and terminalize `SEVERED_BEFORE_ISSUANCE` through
/// its closure. The belt does not race or duplicate that closure; it only ensures this
/// transaction never authorizes ahead of it.
///
/// Lock order (see the `writer_gate` module doc): writers take gate then SQLite; this read is
/// SQLite then gate (already inside `BEGIN IMMEDIATE`), which is safe because a waiting sever
/// parks on the condvar with the gate's state mutex released.
pub(crate) fn belt_refuses_send_if_severing(
    gate: &crate::writer_gate::WriterGate,
) -> Result<Option<SendAuthOutcome>, LogError> {
    if gate
        .sever_raised()
        .map_err(|e| LogError(format!("authorize_send belt sever_raised: {e}")))?
    {
        return Ok(Some(SendAuthOutcome::EpochFenced));
    }
    Ok(None)
}

/// One read of an operation's captured pre-state: the value `P` and the generation it came
/// from. The pairing is the point: a decision about `atoms` is about a specific capture, and
/// reading the generation separately would leave a window in which the row is replaced between
/// the two reads, which is the race the CAS exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPreState {
    /// The journal row's `touched_atom` projection: the captured `P`.
    pub atoms: std::collections::BTreeMap<String, bool>,
    /// The row's `capture_generation`: the CAS token this value is bound to.
    pub capture_generation: u64,
    /// The same capture's full observed label vector
    /// ([`prestate::JournalRow::observed_label_vector_set`]), the pre-effect vector the bus hands
    /// [`IntentLog::record_effect_witness`]. `None` = the capture's read yielded none.
    pub observed_label_vector: Option<std::collections::BTreeSet<String>>,
}

/// The verdict of [`IntentLog::replace_journal_row`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalReplaceOutcome {
    /// The old row is gone and the new one is committed, in one transaction.
    Replaced {
        /// The new row's capture generation (the previous one plus one).
        generation: u64,
    },
    /// Refused: some attempt of this operation does not hold a proven-no-wire terminal, so it may
    /// already have had an effect, and a fresh capture would be the post-effect observation the
    /// design forbids. Fail closed; the caller parks.
    ///
    /// Residual: `ACK_REFUSED_NO_EFFECT` is a definitive no-effect refusal and re-capturing behind
    /// one would be safe by the same argument, but the design says "proven-no-wire terminal" and
    /// this implements those words rather than an extension. The cost is that a retry behind such
    /// a predecessor parks when the provider has diverged instead of re-preparing. Widening the
    /// predicate is a design question.
    RefusedAttemptNotProvenNoWire {
        /// The first attempt that blocks it.
        attempt_id: String,
    },
    /// No journal row exists for this operation. The caller decides whether that is legal
    /// (capture-off) or an explicit gap (`journal_required=1`); this call does not read the
    /// capture-mode binding.
    NoRowToReplace,
}

/// What the engine can say about one connector outcome before the attempt's facts are
/// consulted. Not the fact kind: which verdict fact an outcome becomes also depends on whether
/// the attempt was ever send-authorized, which only [`IntentLog::settle_attempt`]'s
/// transaction can read atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorVerdict {
    /// The operation's objective is verified: the provider response proves the requested effect
    /// (or, on a never-authorized attempt, the objective already held and no dispatch was needed).
    Applied,
    /// The connector failed, carrying the retry taxonomy and the connector's positive
    /// [`EffectEvidence`].
    Failed {
        /// The retry taxonomy (ADR-P013 (b)).
        kind: FailureKind,
        /// What the connector proved about the effect. The default is `Indeterminate`.
        evidence: EffectEvidence,
    },
    /// Not a connector outcome: a local decision taken before the wire, which is why this enum is
    /// named for what the engine can say rather than what a socket did.
    ///
    /// The retry-requalification gate observed the provider at the head of a retry and found the
    /// forward target already holding: another actor produced this operation's objective between
    /// attempts. Nothing was dispatched, so the attribution is proven-no-wire, but the operation
    /// is not `Applied` either, because the effect is not this operation's. It completes
    /// `EXTERNALLY_SATISFIED`.
    ExternallySatisfied,
}

/// What [`IntentLog::settle_attempt`] did: the verdict fact appended and what happened to the
/// operation's lifecycle in the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The verdict was recorded.
    Settled {
        /// Which verdict fact (the four terminal attributions, or `ACK_AMBIGUOUS`, which is not one).
        verdict: crate::attempt::FactKind,
        /// What became of the operation.
        lifecycle: SettledLifecycle,
    },
    /// The closed grammar refused the verdict append and nothing was written. The reachable
    /// shapes are races: a peer settled this attempt under us
    /// ([`crate::attempt::GrammarRefusal::PostTerminalAppend`]) or already recorded its ambiguity
    /// ([`crate::attempt::GrammarRefusal::DuplicateAckAmbiguous`]).
    RefusedByGrammar(crate::attempt::GrammarRefusal),
    /// The pre-wire compare-and-append lost; nothing was written. The caller decided this
    /// verdict before any wire (it never authorized the attempt) and the chain has moved since the
    /// read behind that decision, above all by a peer's `SEND_AUTHORIZED`: re-entry hands two
    /// equally-current drivers the same live attempt, and without this compare the one that stayed
    /// pre-wire could terminalize the one mid-dispatch (its real applied ack then refused
    /// `PostTerminalAppend`). Not an incident: the caller re-reads and exits silently, as for a
    /// lost claim race.
    SupersededPreWire {
        /// The head revision the caller's decision was taken against.
        observed_revision: u64,
        /// What the chain actually holds now.
        current_revision: u64,
    },
}

/// The operation-grain half of a settlement: every terminal-attribution fact updates the
/// operation lifecycle in the same transaction, completing only when no eligible retry remains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettledLifecycle {
    /// The operation reached a terminal status in the settling transaction.
    Completed(IntentStatus),
    /// A transient failure with retry budget remaining: the operation stays active in its retry
    /// gap, holding its tail position with no active attempt. The next dispatch claims a successor.
    RetryGap,
    /// `ISSUANCE_UNKNOWN` (`ACK_AMBIGUOUS`): neither completed nor retryable. It stays open
    /// awaiting adjudication, never dead-lettered as an ordinary failure and never re-dispatched.
    AwaitingAdjudication,
}

impl SettledLifecycle {
    /// Is the operation now terminal? The sweep's per-resource barrier asks this: a settled row is
    /// no longer an in-flight predecessor, and everything else still is.
    pub fn is_terminal(&self) -> bool {
        matches!(self, SettledLifecycle::Completed(_))
    }
}

/// What [`IntentLog::adjudicate`] did: the in-place control transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjudicationOutcome {
    /// The operational axis is closed and the record is durable.
    Adjudicated {
        /// The engine-minted `adjudication_record` id: the FK the `ADJUDICATED_UNRESOLVED` fact
        /// carries and the key later annotations hang on.
        adjudication_id: String,
        /// How many exposure obligation rows this transaction created (one per touched primitive
        /// atom of the attempt's own `SEND_AUTHORIZED` exposure key).
        obligations: u64,
    },
    /// The closed grammar refused and nothing was written. Reachable shapes: the attempt was never
    /// authorized ([`crate::attempt::GrammarRefusal::AdjudicationWithoutSendAuthorization`]), it
    /// already holds a terminal attribution (a peer settled it), or it is already adjudicated.
    RefusedByGrammar(crate::attempt::GrammarRefusal),
}

/// What [`IntentLog::record_late_ack`] did: the post-adjudication whitelist's resolution of
/// the historical axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LateAckOutcome {
    /// The late ack is recorded. The historical axis moved; the operational axis, the operation's
    /// terminal status, its tail position and any successor link did not.
    Resolved {
        /// What the historical axis now says.
        historical: crate::attempt::HistoricalAttribution,
        /// How many of this contributor's exposure obligations retired.
        retired: u64,
        /// How many durable notices this transaction wrote.
        notices: u64,
        /// Whether this transaction also flipped an undo parent to [`IntentStatus::Undone`] (a late
        /// `APPLIED` on a restore attempt is the verification that never arrived).
        parent_undone: bool,
    },
    /// A second, contradictory late ack is refused and the contradiction is durably recorded as
    /// an anomaly annotation on the adjudication record. The fact chain is unchanged.
    RefusedAsContradiction {
        /// The `adjudication_annotation` row this refusal wrote.
        annotation_id: String,
    },
    /// Any other grammar refusal; nothing was written. Reachable: a late ack on a chain that was
    /// never adjudicated, and a duplicate of the same polarity.
    RefusedByGrammar(crate::attempt::GrammarRefusal),
}

/// An operation's live (operationally active) attempt, as [`IntentLog::live_attempt`] reports
/// it. Three values, because a caller that must act on it needs all three: the class answers
/// "may I attribute anything to this operation?" (the sweep's dead-letter check); a caller
/// that must settle the attempt also needs its id (never a second lookup that could name a
/// different attempt) and the revision its decision was taken against, the input to the
/// pre-wire compare-and-append. Reading them apart would reopen the race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAttempt {
    /// The live attempt's opaque id.
    pub attempt_id: String,
    /// Its chain revision at the time of this read: what a pre-wire settlement
    /// compare-and-appends against ([`IntentLog::settle_attempt`]'s `pre_wire_at_revision`).
    pub revision: u64,
    /// Its fact-derived class: [`crate::attempt::AttemptClass::PreIssuance`] (claimed, never
    /// authorized) or [`crate::attempt::AttemptClass::IssuedOrUnknown`] (authorized, unacked),
    /// the only two a live attempt can hold.
    pub class: crate::attempt::AttemptClass,
}

/// The historical axis for an operation whose operational axis was closed by adjudication
/// ([`IntentLog::adjudicated_history`]).
///
/// Adjudication makes the two axes disagree deliberately: the operation is terminal
/// [`IntentStatus::Adjudicated`] while its attribution stays unknown until, if ever, a
/// `LATE_ACK_*` resolves it. Two read paths (the replay contract and the undo presentation)
/// read only the terminal status and kept answering "unresolved" for operations a late ack had
/// resolved. It is derived from the fact chain, never a projection column: the at-most-one
/// `LATE_ACK_*` the post-adjudication whitelist admits is the historical axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjudicatedHistory {
    /// No `LATE_ACK_*` has landed: the attribution is still unknown.
    Unresolved,
    /// `LATE_ACK_APPLIED`: the effect provably happened after all.
    ResolvedApplied,
    /// `LATE_ACK_REFUSED_NO_EFFECT`: the effect provably did not happen.
    ResolvedRefusedNoEffect,
}

/// One row of the unknown-age report ([`IntentLog::unknown_review`]): an attempt whose
/// historical attribution is `UNKNOWN` and whose operational axis is still open. A report only:
/// nothing in the engine consumes it, and the threshold surfaces, never auto-decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownReviewRow {
    /// The unresolved attempt's opaque id, which [`IntentLog::adjudicate`] would be called on.
    pub attempt_id: String,
    /// Its owning operation's user key (the operator's handle on it).
    pub idempotency_key: String,
    /// When the attempt became unknown: the `ACK_AMBIGUOUS` fact's clamped instant when one was
    /// recorded, else its `SEND_AUTHORIZED` instant.
    pub unknown_since: String,
    /// Whether it has been unknown longer than the caller's threshold
    /// ([`crate::attempt::UNKNOWN_REVIEW_AFTER_SECONDS`] is the engine's value).
    pub review_due: bool,
    /// The reconcile lifetime cap is reached, which surfaces the attempt for adjudication
    /// immediately, independent of age. There is no production reconcile writer yet, so the field
    /// is derived from the attempt's own fold and is `false` on every store written today. It is
    /// computed rather than stubbed so a later observation path surfaces through it.
    pub reconcile_cap_reached: bool,
}

/// The unknown-age report as a whole ([`IntentLog::unknown_review`]): the rows plus one fact
/// about the clock they were judged against.
///
/// The rollback flag is report-level because a backward wall-clock step is a property of the
/// store's clock, not of any one attempt; a per-row copy would be one bit repeated with chances
/// to disagree. The per-row consequence is that a detected backward step surfaces aging items
/// for immediate review, so under a rollback every listed row carries `review_due = true` and
/// the operator sees why on the report. Still a report: nothing in the engine reads either
/// field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnknownReviewReport {
    /// True when the caller's `now` sorts below the store's persisted fact-clock high water, the
    /// same comparison [`crate::attempt::clamped_now`] makes on the write side
    /// ([`crate::attempt::ClampedNow::backward_step_detected`]). It is needed because the clamp
    /// dates new facts `max(now, high-water)`, so under a rollback `unknown_since` is in the
    /// future relative to the caller's clock and the ordinary `unknown_since <= cutoff` test is
    /// false for the whole interval. Aging would freeze silently exactly when an operator most
    /// needs to see it.
    pub clock_rollback_detected: bool,
    /// The surfaced attempts, in the store's operation order.
    pub rows: Vec<UnknownReviewRow>,
}

/// One `exposure_obligation` as an operator sees it ([`IntentLog::exposure_obligation`]), the
/// resolution of the reference an [`ExecuteError::ExposureBlocked`] carries.
///
/// Deliberately not the whole row: `primitive_atom` and `provider_scope` are the provider-native
/// halves, and surfacing them would reopen the leak this exists to close (an operator asking
/// "what is blocking me?" would get account and message ids). It answers in the engine's own
/// terms: which attempt contributed it (an engine id, adjudicatable through
/// [`IntentLog::unknown_review`]'s rows), which episode it belongs to, which way the effect
/// moved the atom, when it was created and whether it has been retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureObligation {
    /// The engine-minted opaque row id the refusal surfaced.
    pub obligation_id: String,
    /// The effect direction the contributing operation's frozen basis named.
    pub direction: crate::attempt::ExposureDirection,
    /// The episode generation for the (unnamed here) atom.
    pub generation: i64,
    /// The attempt whose unresolved history created it: an engine id, and the handle that
    /// adjudication and `LATE_ACK_*` retirement are keyed on.
    pub contributor_attempt_id: String,
    /// When the obligation was created (RFC 3339 UTC, clamped-monotonic like every instant this
    /// engine writes).
    pub created_at: String,
    /// When the contributor's historical axis resolved; `None` while the obligation is live,
    /// which is the state in which it gates dispatches.
    pub retired_at: Option<String>,
}

/// What [`IntentLog::sever`] did, in one transaction: bump `control_epoch`, derive the
/// membership partition, write the canonical witness, terminalize the pre-issuance members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeverOutcome {
    /// The post-sever `control_epoch`. Every claim taken under an older epoch is fenced from here
    /// on, and this value identifies the sever event.
    pub epoch: i64,
    /// The sever witness this transaction wrote, as a verified value.
    pub witness: SeverWitness,
    /// How many operations this transaction terminalized [`IntentStatus::Severed`]: the
    /// operation members plus the claimed-unauthorized attempt members (witnessing without closing
    /// would strand them, consuming capacity and blocking their resource tails). `ISSUED_OR_UNKNOWN`
    /// members are not counted: they stay active until settlement or adjudication.
    pub terminalized: u64,
}

/// The sever witness as a verified value: the complete minimum audit element set. If the
/// post-sever audit is lost, this row is the only surviving evidence.
///
/// The member count is not a field: it is `members.len()`. The durable row persists it as its
/// own element, and the crate-internal reconciliation (`verify_sever_witness`, private) proves
/// the stored count and member set agree; a value carrying both independently could hold a
/// disagreement no reader could resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeverWitness {
    /// The engine-minted opaque row id.
    pub witness_id: String,
    /// The post-sever epoch (the row's unique key: one witness per sever).
    pub epoch: i64,
    /// The sever instant, clamped-monotonic like every attempt fact.
    pub severed_at: String,
    /// The seizing authority by reference, never PII substance.
    pub authority_ref: String,
    /// The tagged-union membership, in the canonical order the digest is computed over (bytewise
    /// ascending over each member's fully-encoded byte string).
    pub members: Vec<crate::attempt::WitnessMember>,
    /// SHA-384 over [`crate::attempt::encode_sever_witness`]'s bytes, lowercase hex.
    pub digest: String,
}

impl SeverWitness {
    /// The member count, always `members.len()` and never a second stored number this value
    /// could disagree with.
    pub fn member_count(&self) -> u64 {
        self.members.len() as u64
    }
}

/// Durable record of mutation intents. SQLite-backed in production, in-memory for fast tests.
/// All operations are fallible: a store-first system of record must be able to signal a failed
/// write so the bus can honor write-ahead ordering (a failed persist aborts the apply).
pub trait IntentLog {
    /// Record a command as a new `Pending` intent (the atomic claim), keyed by its idempotency
    /// key, and freeze its resolved native basis in the same transaction (BASIS-5). The basis is a
    /// previously obtained durable local resolver result (BASIS-2); `record` does no I/O beyond
    /// SQLite.
    ///
    /// Returns whether this call inserted the fresh row (`Claim::Inserted`: the caller owns the
    /// dispatch) or one already existed (`Claim::AlreadyExisted`). A different command under an
    /// existing key is a `LogError`: the durable command is immutable, and so is the basis an
    /// existing row already froze.
    fn record(
        &mut self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
    ) -> Result<Claim, LogError>;
    /// Look up a recorded intent by idempotency key.
    fn get(&self, idempotency_key: &str) -> Result<Option<Intent>, LogError>;
    /// The status-write path: a compare-and-set, never a bare assignment. The caller names the
    /// world it expects ([`StatusPrecondition`]); the store writes only if the row is still that
    /// world and otherwise reports what it holds ([`StatusWrite::Refused`]).
    ///
    /// There is no unconditional variant, and that absence is the fix. The bug class was a family
    /// of writes decided against a read and landing after a concurrent sever had terminalized the
    /// row, silently burying an audited disposition and reporting an outcome the ledger did not
    /// hold. Only a compare the store performs inside the write is safe against a second
    /// connection.
    ///
    /// The compare is against the status only. A write that must move an operation's lifecycle
    /// together with the fact that justifies it belongs in [`IntentLog::settle_attempt`], whose
    /// `terminalize_operation` applies the same guard inside that transaction.
    fn set_status_if(
        &mut self,
        idempotency_key: &str,
        precondition: StatusPrecondition,
        status: IntentStatus,
    ) -> Result<StatusWrite, LogError>;
    /// Fixture helper: read, then compare-and-set against what was read. A test constructing a
    /// durable shape has no expectation to name; it is stating a starting world.
    ///
    /// Provided, never overridden, and defined via [`IntentLog::set_status_if`], so even this
    /// cannot become the unconditional write the bug class is made of. A missing row is a
    /// `LogError`: a fixture naming a key the store does not hold is broken, not a silent no-op.
    fn set_status_forced(
        &mut self,
        idempotency_key: &str,
        status: IntentStatus,
    ) -> Result<(), LogError> {
        let Some(current) = self.get(idempotency_key)?.map(|intent| intent.status) else {
            return Err(LogError(format!(
                "set_status_forced: no intent '{idempotency_key}'"
            )));
        };
        match self.set_status_if(
            idempotency_key,
            StatusPrecondition::Exactly(current.clone()),
            status,
        )? {
            StatusWrite::Written => Ok(()),
            StatusWrite::Refused(actual) => Err(LogError(format!(
                "set_status_forced: '{idempotency_key}' moved from {current:?} to {actual:?} \
                 under the write"
            ))),
        }
    }
    /// The over-budget dead-letter as one transaction: the attempt-head predicate and the status
    /// transition joined, because apart they are a race.
    ///
    /// The recovery sweep's pre-dispatch cap self-heal used to ask `live_attempt` in one
    /// transaction ("is this operation quiescent?") and [`IntentLog::set_status_if`] in another. A
    /// peer that claims and appends `SEND_AUTHORIZED` between the two may put the mutation on the
    /// wire, and the `Failed` the sweep then writes is both a false attribution of no-effect and a
    /// terminal the peer's own ACK can never replace (`settle_attempt`'s lifecycle guard refuses to
    /// rewrite a settled disposition). One transaction is the only thing a second connection cannot
    /// slip past.
    ///
    /// The predicate is "no live attempt", not "no unknown attempt". Parking only on
    /// [`crate::attempt::AttemptClass::IssuedOrUnknown`] would dead-letter a live pre-issuance
    /// claim, but that claim is a peer's and still authorizable; a terminal over a live attempt
    /// leaves it dangling (see [`IntentLog::live_attempt`]). The budget counter cannot attribute
    /// anything to an attempt this driver does not own, so such an operation parks and waits for
    /// its owner or for adjudication, as `claim_dispatch`'s ambiguity arm does.
    ///
    /// The status half is the same compare as [`IntentLog::set_status_if`]
    /// ([`StatusPrecondition::NonTerminal`]): a settled disposition is never rewritten, and a
    /// refusal names what the row holds.
    /// The status half is the SAME compare [`IntentLog::set_status_if`] takes
    /// ([`StatusPrecondition::NonTerminal`], from the single authority): a settled disposition is
    /// never rewritten, and a refusal names what the row actually holds.
    fn dead_letter_if_quiescent(
        &mut self,
        idempotency_key: &str,
    ) -> Result<DeadLetterWrite, LogError>;
    /// The undo verification's pair transition as one transaction. The parent flips
    /// `Applied -> Undone` (or is already `Undone`, the crash-heal re-drive) and, when `child` says
    /// so, the child terminalizes `Applied`, both under a precondition that the child is still
    /// non-terminal.
    ///
    /// It is one transaction rather than two guarded writes because the no-op arm is wire-free and
    /// runs ahead of the epoch check (a sever must not strand an undo that needs no wire), which
    /// is exactly the arm a sever can land under: it decides from the caller's stale child read,
    /// and a sever in between has terminalized the child `Severed`. Guarding only the child write
    /// would still leave the parent flipped `Undone`, a durable claim that the undo verified. So
    /// the compare and both writes commit together or not at all, and the caller re-routes on the
    /// child's actual status.
    fn verify_undo_pair(
        &mut self,
        parent_key: &str,
        child_key: &str,
        child: UndoPairChild,
    ) -> Result<UndoPairFlip, LogError>;
    /// Every intent in a non-terminal state (`Pending` or `Undoing`), ordered by `seq`: recorded
    /// but not yet reconciled, which crash recovery resumes on restart.
    fn unreconciled(&self) -> Result<Vec<Intent>, LogError>;
    /// Every forward-kind intent held `Applied` whose local projection has not been written
    /// (`projected = 0`): any plan, any run, including one settled by `recover()` under a
    /// different plan's drive or one whose projection write failed earlier. Ordered by `seq`,
    /// oldest first, so a long-unprojected row is not starved. Never an undo child
    /// (`kind = 'undo'`): an undo's local-row consequences are a separate always-`Stale` contract.
    /// Each [`Intent`] carries [`Intent::basis_ingest_revision`], the freshness stamp
    /// [`crate::read_coordinator::ReadCoordinator::project_applied_intent`] compares against the
    /// row's current revision before writing.
    fn applied_unprojected_forward_intents(&self) -> Result<Vec<Intent>, LogError>;
    // There is deliberately no `mark_projected`: the only writer of `intents.projected` is
    // `crate::read_coordinator::ReadCoordinator::project_applied_intent`, which marks it in the
    // same transaction as the placement/header write (or the decision to skip it), so a crash
    // cannot fall between "the effect landed" and "the row says so".
    /// Charge one transient failure, and dead-letter only a quiescent operation, in one
    /// transaction (ADR-P013 (b)).
    ///
    /// The increment and the exhaustion transition are one durable write, so no dispatcher can see
    /// an over-budget non-terminal row and a crash cannot land half the pair.
    ///
    /// It uses the same predicate as [`IntentLog::dead_letter_if_quiescent`]. A single statement
    /// with only the non-terminal compare asks "has another authority closed this row" and says
    /// nothing about a live attempt, so the last unit of budget, spent by a boundary that owns no
    /// attempt (the capture pipeline's `observe` failure, reconciled at operation grain), wrote
    /// `Failed` over a peer's claimed-and-authorized dispatch: a false no-effect attribution and a
    /// terminal the peer's ACK can never replace. A dead-letter needs "this operation holds no
    /// live attempt", and both writers of a budget-exhaustion terminal now hold that rule.
    ///
    /// The charge survives the refusal: a parked dead-letter must not park the increment, or a
    /// transient failure under a peer's live attempt would be free and the budget would never
    /// exhaust. Charge first, terminalize only if quiescent; [`TransientCharge`] says which
    /// happened. A row that is already terminal, or missing, is charged nothing
    /// ([`TransientCharge::ChargeRefusedTerminal`]).
    ///
    /// Dual accounting: this charge is the only writer of `intents.attempts`, and the
    /// `attempt_fact` claim chain is a separate accounting that cannot be reconciled with it from
    /// facts alone. `FailureKind` is not in the fact grammar (a `CLAIM` fact records that a retry
    /// happened and what it followed, not why), and an ordinal-1 `CLAIM` carries no predecessor,
    /// so predecessor count equals `attempts` only where every charge was transient-with-retry
    /// (see the test `attempts_counter_matches_transient_charges_in_hermetic_histories` in
    /// `crates/aruna/src/lib.rs`). This counter remains the retry-budget authority; deriving it
    /// from fact-level retry-charge recording would be design work.
    fn charge_and_dead_letter_if_quiescent(
        &mut self,
        idempotency_key: &str,
        cap: u32,
    ) -> Result<TransientCharge, LogError>;
    /// Every intent in the terminal `Failed` (dead-letter) state, ordered by `seq`: the
    /// operator's view of the dead-letter queue (ADR-P013 (b)).
    fn dead_letters(&self) -> Result<Vec<Intent>, LogError>;
    /// The governing intent for an `(account, message_ref)`: the highest-`seq` intent recorded for
    /// that message, or `None`. Divergence correction reads this to apply the terminal guard and
    /// never correct a projection an in-flight intent still governs.
    fn latest_intent_for_message_ref(
        &self,
        account: &str,
        message_ref: &str,
    ) -> Result<Option<Intent>, LogError>;
    /// Is any non-terminal intent other than `exclude_idempotency_key`, with `seq` strictly below
    /// `before_seq`, either keyed on the same frozen native resource key as `native_key` or on the
    /// same `(account, fallback_message_ref)`? This is the head predicate: the native-keyed tail
    /// (BASIS-1), with the Photon-local ref as an overlapping second lane so a store holding both
    /// generations on one message orders safely in either direction. It is conservative on
    /// purpose: over-deferral parks work for the next sweep, while under-deferral reverses causal
    /// order.
    ///
    /// `account` scopes the fallback lane only: `native_key` is provider-scoped, while
    /// `message_ref` is Photon-local and meaningless without its account. Scoping the native lane
    /// by the local account let two Photon handles onto one provider resource overtake each other
    /// (see `non_terminal_native_predecessor_sql`; the SQL fragment and this contract are one rule).
    ///
    /// Self-exclusion is explicit (by key) rather than implied by the seq bound, because the two
    /// bounds answer different questions: PREPARE asks the strict at-head question (`before_seq` =
    /// the intent's own seq), while the bus's dispatch guard asks the whole-tail question
    /// (`before_seq` = `u64::MAX`), since an in-flight undo must also defer behind later
    /// same-resource work or an older undo defeats a newer action.
    fn has_non_terminal_native_predecessor(
        &self,
        native_key: &str,
        fallback_message_ref: &str,
        account: &str,
        before_seq: u64,
        exclude_idempotency_key: &str,
    ) -> Result<bool, LogError>;
    /// PREPARE, in one transaction: verify the intent is a `journal_required=1` forward intent,
    /// its bound config row exists (never head-equality), the current `control_epoch` equals
    /// `admitted_control_epoch`, and it is still at head, then insert the `pre_state` row.
    /// Insert-or-nothing; the row is the phase.
    ///
    /// A row no longer pre-dispatch answers on the axis it is off:
    /// [`crate::prestate::PrepareOutcome::Closed`] when terminal (a peer legitimately closed the
    /// operation under this capture), a `LogError` when not (a phase no writer here produces).
    /// Both implementations owe that split.
    /// writer in this engine produces). Both implementations owe that split.
    fn prepare(
        &mut self,
        idempotency_key: &str,
        journal: &crate::prestate::JournalRow,
    ) -> Result<crate::prestate::PrepareOutcome, LogError>;
    /// Does a `pre_state` row exist for this intent? (Dispatch eligibility is by inner join,
    /// `journal_required=1 => EXISTS pre_state`, never a flag.)
    fn prepared(&self, idempotency_key: &str) -> Result<bool, LogError>;
    /// The captured pre-state `P` of a forward operation: the journal row's `touched_atom`
    /// projection, validated against the operation's frozen basis on the way out of storage.
    ///
    /// [`IntentLog::undo_context`] also reads `P`, but is `&mut` because it advances the sticky
    /// undo-offer clock high-water, which a forward retry must not latch. This shares its read
    /// boundary (`JournalRow::validate`, the mirror of PREPARE's write-side check), because the
    /// retry gate compares this value against the provider and an inconsistent stored row would
    /// forge the comparison.
    ///
    /// It returns the row's `capture_generation` beside its value ([`CapturedPreState`]) in one
    /// read, because a decision about `P` is a decision about a specific capture and
    /// [`IntentLog::authorize_send`] spends that generation as a CAS token.
    ///
    /// `None` = no journal row (a capture-off or unprepared operation). A missing intent is an
    /// error.
    fn captured_pre_state(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<CapturedPreState>, LogError>;
    /// Persist what the route observed at effect, beside the operation. `pre` is the observe
    /// read's full vector (when the journal holds one); the ripple verdict is computed here from
    /// the operation's frozen closure (`FrozenBasis.touched_atoms` values, the label ids), so no
    /// caller can hand in a verdict. Refuses for an unknown key.
    ///
    /// Written once: a second record for an operation that already holds a persisted vector
    /// refuses, since it would overwrite evidence. A witness with no vector
    /// (`provider_label_vector: None`) persists nothing. With both vectors present and no frozen
    /// basis to take the closure from, it refuses rather than judge against a guessed closure. Both
    /// stores compute the row through `effect_witness_row`.
    fn record_effect_witness(
        &mut self,
        idempotency_key: &str,
        witness: &EffectWitness,
        pre: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<(), LogError>;
    /// The persisted effect witness of an operation. `Ok(None)` = the operation exists and no
    /// vector was persisted; a missing operation is an error. A stored value that does not read
    /// back as a witness (a non-canonical vector, a verdict without its vector, a token/set pairing
    /// `RippleVerdict::to_columns` cannot produce) is a `LogError`.
    fn effect_witness(&self, idempotency_key: &str) -> Result<Option<EffectWitnessRow>, LogError>;
    /// A versioned atomic replace of an operation's journal row, the one narrow exception to
    /// PREPARE's insert-or-nothing rule. The retry-requalification gate uses it when the provider
    /// has moved somewhere the existing capture cannot describe.
    ///
    /// Re-capture is otherwise forbidden because a post-effect observation poisons no-op
    /// detection. This is legal exactly where that does not apply: it refuses unless every attempt
    /// the operation has ever claimed holds a proven-no-wire terminal, so no effect of this
    /// operation exists for the new observation to follow. The check is fact-derived and made
    /// inside the writing transaction, with no status read.
    ///
    /// One transaction, delete plus insert (never update): a new capture is a new observation
    /// event with its own instant, epoch and offer deadline, and updating in place would leave the
    /// audit trail claiming one capture where there were two and hand the dormant tombstone lane a
    /// `journal_id` that no longer names what it named. `capture_generation` increments, so "old or
    /// new, never a blend" is decidable from the row itself. `pre_state` has no append-only trigger
    /// (unlike `engine_config`); insert-or-nothing is a posture, not a storage constraint.
    fn replace_journal_row(
        &mut self,
        idempotency_key: &str,
        journal: &crate::prestate::JournalRow,
    ) -> Result<JournalReplaceOutcome, LogError>;
    /// One read for the undo eligibility derivation: the parent's opaque `intent_id`, its journal
    /// row (captured `P` plus offer deadline) if any, tombstone presence, and the sticky
    /// effective-now. It advances the persisted time high-water (the clock-rollback latch), hence
    /// `&mut`. `None` = no such intent.
    fn undo_context(&mut self, idempotency_key: &str) -> Result<Option<UndoContext>, LogError>;
    /// Is the current `control_epoch` equal to this intent's `admitted_control_epoch`? The undo
    /// child's epoch check reads this (children own no journal row, so PREPARE's check never runs
    /// for them). A missing key is an error.
    fn admitted_epoch_is_current(&self, idempotency_key: &str) -> Result<bool, LogError>;
    /// Claim an attempt for this operation: the ownership transition every wire-bound dispatch
    /// takes before it may reach a connector socket, closing the double-drive family.
    ///
    /// One transaction, in order: read the operation row (owner id, status, dispatch episode,
    /// admitted epoch); compare it against what the caller observed; read the current
    /// `control_epoch`; fold the operation's attempt chain through the pure grammar core
    /// ([`crate::attempt::fold`]); ask the single legality predicate
    /// ([`crate::attempt::append_legal`], plus [`crate::attempt::retry_lineage_legal`] for
    /// ordinal > 1); append the `CLAIM` fact and upsert its `attempt_head`. Nothing here decides
    /// legality locally.
    ///
    /// The three compare halves each answer "is this dispatch still mine?" and map to
    /// `AlreadyClaimed` (a normal outcome, never an error):
    /// 1. the operation is already terminal (another driver settled it),
    /// 2. the durable episode moved (`attempts != observed_attempts`; another driver charged a
    ///    failure),
    /// 3. the `CLAIM` insert lost a SQL constraint race.
    ///
    /// Re-entry: when the operation's attempt at this ordinal already exists and all three compares
    /// pass, the answer is `Won` on the existing attempt, so a legitimate re-drive of a live
    /// episode (a crash between dispatch and status write; a parked child re-swept) rides the
    /// attempt it already claimed. Consequence: two drivers whose reads are both current both see
    /// `Won`. That residual is closed by the at-most-one `SEND_AUTHORIZED` (committed immediately
    /// before socket entry) and by re-dispatch becoming a new attempt once verdict facts exist.
    /// What this already closes is the stale-read family, which is the double-drive race.
    ///
    /// A stored chain that does not fold (a broken compare-and-append link, a non-canonical
    /// timestamp) is a [`LogError`]: never repaired, never silently re-claimed.
    fn claim_attempt(
        &mut self,
        idempotency_key: &str,
        claim: &AttemptClaim,
    ) -> Result<ClaimOutcome, LogError>;
    /// Authorize the send: the epoch-fenced boundary, committed immediately before connector
    /// socket entry. The connector may not touch the wire without its own committed
    /// `SEND_AUTHORIZED`.
    ///
    /// One transaction, in order:
    /// 1. fold the attempt's chain through the pure grammar core; every decision below is
    ///    fact-derived, never read-derived (a concurrent settle is as invisible to a status read
    ///    as at boot);
    /// 2. re-read `control_epoch` and compare it to the attempt's claim epoch. Unequal means a
    ///    sever landed under this driver: [`SendAuthOutcome::EpochFenced`], with the attempt
    ///    terminalized `SEVERED_BEFORE_ISSUANCE` and its operation `Severed` in this transaction.
    ///    Then the plan-admission arm: compare `plan` ([`crate::plan::PlanBinding`]) with the
    ///    row's plan link and, for a plan child, run the send-admission law (table below); a
    ///    refusal answers [`SendAuthOutcome::PlanRefused`];
    /// 3. derive the touched-atom exposure key from the operation's admission-frozen basis
    ///    ([`crate::attempt::ExposureKey::from_basis`]), here, from the operation's own row, so
    ///    no caller can supply a key of its own construction;
    /// 4. the EXP-3 check: any unretired `exposure_obligation` overlapping those atoms refuses
    ///    fail-closed ([`SendAuthOutcome::ExposureBlocked`]), with the deterministic no-effect
    ///    terminal written in the same transaction;
    /// 5. ask the single legality predicate and append `SEND_AUTHORIZED` plus the head projection.
    ///
    /// The at-most-one property is the point: "at most one `SEND_AUTHORIZED` after `CLAIM`"
    /// closes the residual [`IntentLog::claim_attempt`] names. Two drivers whose reads are both
    /// current both get `Won`, but only one can commit an authorization; the second is refused by
    /// the grammar (and by `UNIQUE (attempt_id, revision)` if they truly interleave).
    ///
    /// The commit-to-socket gap is irreducible: a crash between this commit and the connector's
    /// first byte leaves an authorized, possibly-unsent request (two generals; no local record
    /// closes it). What this boundary guarantees is that no new authorization can follow a sever.
    ///
    /// It also spends the capture CAS token. `capture` is what the caller's dispatch decision was
    /// made against ([`CaptureBinding`]), verified here against the durable `pre_state` row:
    ///
    /// | `capture` | legal iff | otherwise |
    /// |---|---|---|
    /// | `Generation(g)` | a journal row exists at `capture_generation == g` | [`SendAuthOutcome::CaptureSuperseded`] |
    /// | `NoJournalRow` | no journal row exists for this operation | [`SendAuthOutcome::CaptureSuperseded`] |
    ///
    /// It is checked here for the same reason as the epoch: this is the last pre-wire boundary,
    /// and SQLite's single writer linearizes it against [`IntentLog::replace_journal_row`], so a
    /// requalification that re-prepared the row under a peer's decision cannot also let that peer
    /// dispatch. The refusal is pre-wire and writes nothing; the loser re-runs requalification.
    ///
    /// `NoJournalRow` is checked, not merely declared. An undo child's `P` is its parent's row, and
    /// the child asserts `NoJournalRow` about itself, which holds because only the capture pipeline
    /// PREPAREs and it never runs for a child. The parent's row cannot move under the child either:
    /// the replace path refuses unless every attempt holds a proven-no-wire terminal, and an
    /// undoable parent is `Applied` only by way of an `ACK_APPLIED`. So the child needs no
    /// generation of its own, and the total check keeps an unasserted capture-on dispatch
    /// impossible rather than discouraged.
    ///
    /// `attempt_id` is the one the claim returned; an attempt owned by a different operation is a
    /// [`LogError`], never a silent authorization.
    ///
    /// The plan binding is total too. `plan` states whether the operation is a plan child
    /// (`Plain` for a row with no plan link, `Child` for one with a link). A mismatch in either
    /// direction is a [`LogError`] returned before the plan arm writes anything: a caller bug,
    /// never a skipped law. For a plan child the arm runs these rows in order, after the epoch
    /// check and before the EXP-3 check, reading durable rows and the capture the CAS just
    /// verified; the first that fails is the answer:
    ///
    /// | # | row | refusal | kind |
    /// |---|---|---|---|
    /// | 1 | an `execution_episode` row, `active`, with its `ready_at` marker | `NoEpisode` · `EpisodeHeld` (`paused`) · `EpisodeClosed` · `NotReady` | terminal · HELD · terminal · HELD |
    /// | 1b | the bus could form a grant verdict | `GrantRetired(Unavailable)` | HELD |
    /// | 2 | the `triage_plan` row reads back | — ([`LogError`]) | — |
    /// | 3 | `control_epoch` == the plan's | `PlanEpochMismatch` | terminal; also invalidates the episode |
    /// | 4 | `expires_at > effective_now` (sticky clock) | `Expired` | terminal; also invalidates the episode |
    /// | 5 | the child's member is a plan member | `NotAMember` | terminal |
    /// | 6 | the approval row exists and `validate_evidence` admits it | `EvidenceAbsent` · `EvidenceInvalid` | terminal |
    /// | 6b | a `Bypassed` plan minted under `backups: off` carries its frozen bypass notice | `BypassNoticeAbsent` | terminal |
    /// | 7 | the bus's grant verdict | `GrantRetired(Retired)` · `GrantRetired(PrincipalMismatch)` | terminal |
    /// | 8 | the backups head generation == the plan's `coverage_generation` | `CoverageDiverged` | terminal |
    /// | 9 | the plan froze `backups: off` (no snapshot row exists to check in S1) | `SnapshotAbsent` | terminal |
    /// | 10 | a capture exists and equals the member's approval-time state | `CaptureRequired` · `StateDiverged` | terminal |
    ///
    /// A terminal refusal of an attempt with no `SEND_AUTHORIZED` writes `FAILED_PRE_SEND`
    /// (proven-no-wire; reason `stale_not_attempted` for row 10's diff, `plan_refused` otherwise;
    /// the typed record is read back by [`IntentLog::plan_refusal`]) and the operation's `Failed`
    /// in this transaction. A held refusal, and any refusal of an already-authorized attempt,
    /// writes no fact and no status. The held refusals are rows 1 and 1b, answered before row 4
    /// reads the sticky clock; every outcome from row 4 on commits that read's latch advance,
    /// which is neither a fact nor a status.
    fn authorize_send(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        capture: CaptureBinding,
        plan: crate::plan::PlanBinding,
    ) -> Result<SendAuthOutcome, LogError>;
    /// Settle an attempt with the connector's outcome: the verdict path every wire-bound outcome
    /// comes through.
    ///
    /// One transaction: fold the attempt's chain, derive which verdict fact this outcome is (table
    /// below), append it plus the head projection, and move the operation's lifecycle. The last
    /// step is required: a terminal attribution and the lifecycle it justifies must land in the
    /// same write, or the ledger says "settled" while replay, capacity and the resource tail
    /// still see a live row.
    ///
    /// The mapping table (ack verdicts). The verdict fact is decided by the facts, never by a
    /// status read and never by [`FailureKind`] alone, which is a retry taxonomy and proves
    /// nothing about the wire:
    /// **The mapping table (ack verdicts).** The verdict fact is decided by the facts,
    /// never by a status read — and never by [`FailureKind`] alone, which is a retry taxonomy
    /// and proves nothing about the wire:
    ///
    /// | attempt state | outcome | fact | lifecycle |
    /// |---|---|---|---|
    /// | authorized | `Applied` | `ACK_APPLIED` | `Applied` |
    /// | NOT authorized | `Applied` | `FAILED_PRE_SEND` (proven-no-wire) | `Applied` |
    /// | NOT authorized | `Failed` | `FAILED_PRE_SEND` (proven-no-wire) | retry taxonomy |
    /// | authorized | `Failed` + `ProvenNoWire` | `FAILED_PRE_SEND` | retry taxonomy |
    /// | authorized | `Failed` + `ProvenRefusedNoEffect` | `ACK_REFUSED_NO_EFFECT` | retry taxonomy |
    /// | authorized | `Failed` + `Indeterminate` | `ACK_AMBIGUOUS` | awaiting adjudication |
    ///
    /// The two not-authorized rows carry proven-no-wire by construction rather than on the
    /// connector's word: the connector may not touch the wire without its own committed
    /// `SEND_AUTHORIZED`, so an attempt without one cannot have issued anything. (A
    /// pre-authorization `observe` did touch the provider, but it is a read, and the attribution
    /// is about the mutation's issuance.)
    ///
    /// The retry taxonomy row: `Deterministic` dead-letters `Failed` (ADR-P013 (b)). `Transient`
    /// charges the durable budget, dead-lettering `Failed` only on exhaustion and otherwise
    /// leaving the operation active in its retry gap.
    /// The settlement-epoch check: a settlement whose evidence proves no effect was issued
    /// re-reads `control_epoch` first, and if a sever landed under the dispatch the operation
    /// completes `Severed` ("no effect existed, no retry is authorized, the slot and tail
    /// release"). The attribution is untouched (the connector's proof does not become false
    /// because an epoch moved); only the lifecycle differs. It is decided once, from the verdict,
    /// before the lifecycle branch is chosen (see `settlement_proves_no_effect`). Deciding it
    /// inside the `ChargeTransient` branch missed a deterministic proven-no-wire refusal racing a
    /// sever, which resolved `Complete(Failed)` and skipped the check. The rule belongs to the
    /// evidence axis, so no lifecycle branch owns a copy.
    ///
    /// `ACK_AMBIGUOUS` is not a terminal attribution and spends no retry budget: there is no retry
    /// from `ACK_AMBIGUOUS`/`ISSUANCE_UNKNOWN` (adjudication is the only path).
    ///
    /// `pre_wire_at_revision` is the compare-and-append. `Some(r)` means this verdict was decided
    /// before any wire, against a chain read at revision `r`, and the settle refuses
    /// [`SettleOutcome::SupersededPreWire`] if the chain has moved. `None` means the caller holds
    /// this attempt's own `SEND_AUTHORIZED`, whose at-most-one property is its exclusivity, so the
    /// chain may move under it (an operator adjudicating a dispatch still in flight is a legal
    /// race, answered by the `LATE_ACK_*` conversion).
    ///
    /// The asymmetry is the property. The claim's re-entry arm is not exclusive (two drivers with
    /// equally-current reads both win the same live attempt), exactly one can authorize, and this
    /// compare stops the other from settling the attempt out from under it while it is on the wire.
    fn settle_attempt(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        verdict: ConnectorVerdict,
        retry_cap: u32,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<SettleOutcome, LogError>;
    /// Sever: the seizure primitive, one atomic transaction and the first production writer of the
    /// `control_epoch` singleton.
    ///
    /// In order:
    /// 1. bump `control_epoch`; from here every claim taken under the old epoch is fenced
    ///    (`claim_attempt`'s admitted-epoch check and [`IntentLog::authorize_send`]'s re-read);
    /// 2. derive the membership partition over every operation, fact-derived: lifecycle-terminal
    ///    means completed and absent from the witness; active with no non-terminal attempt is an
    ///    `OperationMember`/`NO_ACTIVE_ATTEMPT` (never-claimed work and the retry gap); active with
    ///    a non-terminal attempt is an `AttemptMember` classed by that attempt's own facts
    ///    (`SEVERED_BEFORE_ISSUANCE` if never authorized, `ISSUED_OR_UNKNOWN` if it was).
    ///    Membership is total: every active operation appears exactly once;
    /// 3. write the witness; its canonical encoding and SHA-384 digest come from the pure core
    ///    ([`crate::attempt::encode_sever_witness`]);
    /// 4. terminalize the members that can be closed truthfully: every `OperationMember`, and every
    ///    claimed-unauthorized attempt (its `SEVERED_BEFORE_ISSUANCE` fact, head, and the owning
    ///    operation's [`IntentStatus::Severed`]). Witnessing without closing would strand them,
    ///    consuming capacity and blocking their resource tails forever. Tail-order occupancy
    ///    releases through the terminal status alone, via the existing same-resource predecessor
    ///    join; there is no second release mechanism.
    ///
    /// `ISSUED_OR_UNKNOWN` members are not closed: non-issuance cannot be proven, so such a member
    /// is witnessed and stays active until a late ack settles it or adjudication closes it.
    /// Dead-lettering them would assert a truth the engine does not have.
    ///
    /// `authority_ref` is an opaque reference to the seizing authority, never PII. This enforces
    /// only its shape (non-empty, control-character-free, bounded); whether it resolves to a real
    /// principal is the caller's authority model, which an on-box engine cannot check.
    ///
    /// `now` is the caller's wall clock in canonical RFC 3339 UTC, clamped against the persisted
    /// fact high-water like every attempt fact, so a backward clock step cannot write a witness
    /// that sorts before the facts it closes.
    fn sever(&mut self, authority_ref: &str, now: &str) -> Result<SeverOutcome, LogError>;
    /// An operation's live attempt, with its id, revision and fact-derived class
    /// ([`LiveAttempt`]), or `None` when it has none (never claimed, or in the retry gap).
    ///
    /// Every decision that attributes something to an operation carrying an attempt (above all a
    /// dead-letter, which asserts no-effect) must read this and not the status column, which cannot
    /// distinguish "nothing happened" from "we do not know what happened". The same holds for
    /// every decision that terminalizes such an operation: the undo drive's crash-convergence heal
    /// writes a durable terminal from local rows, and a terminal written over a live attempt leaves
    /// that attempt dangling, still claimable and authorizable on an operation the ledger says is
    /// closed.
    fn live_attempt(&self, idempotency_key: &str) -> Result<Option<LiveAttempt>, LogError>;
    /// Adjudicate an issuance-unknown attempt: the in-place control transition.
    ///
    /// "Truthful ambiguity must not become a permanent engine freeze." This is where a human
    /// decides. It is not a new operation and consumes no slot: it is an authority-gated
    /// transition on the already-counted unknown operation, so net capacity changes by -1.
    /// One transaction, in order:
    /// 1. validate the authority reference, shape only (as [`IntentLog::sever`] does);
    /// 2. write the immutable `adjudication_record`: closed enums throughout
    ///    ([`crate::attempt::AdjudicationReason`], [`crate::attempt::AcceptedRisk`]), a
    ///    fact-derived content-free known-at snapshot, and the touched-atom exposure key copied
    ///    from the attempt's own `SEND_AUTHORIZED` payload (never re-derived, never read from
    ///    `pre_state`, which a capture-off attempt legally lacks). There is no free text on this
    ///    path and no caller-supplied opaque reference; that column stays NULL rather than
    ///    shape-gating bytes the engine cannot prove it minted;
    /// 3. append `ADJUDICATED_UNRESOLVED` carrying the record's FK, with the head projection;
    /// 4. move the operation to terminal [`IntentStatus::Adjudicated`] in the same transaction
    ///    (`ADJUDICATED_UNRESOLVED` is not a terminal-attribution fact, so lifecycle atomicity does
    ///    not reach it, and without the status here a crash window leaves the fact saying closed
    ///    while replay, capacity and the resource tail still see `Pending`);
    /// 5. create the durable exposure obligations, one `exposure_obligation` row per primitive
    ///    touched atom, direction-aware and generation-keyed (a later independent episode on the
    ///    same atom is a new generation; old rows never authorize or contaminate it).
    ///
    /// The two axes disagree deliberately. The historical axis stays `UNKNOWN` (a `LATE_ACK_*`
    /// may still resolve it, see [`IntentLog::record_late_ack`]) while the operational axis closes,
    /// releasing the capacity slot and resource tail occupancy and, for an undo attempt, returning
    /// the parent's presentation to `Applied` with the unresolved state surfaced
    /// ([`UndoPresentation::AppliedUndoUnresolved`]).
    ///
    /// `accepted_risk` is recorded and honored by nothing. This build has no risk-acceptance
    /// capability, so the exposure check in [`IntentLog::authorize_send`] refuses every overlap
    /// whatever was accepted here (`duplicate-effect-possible` authorizes exactly as much as
    /// `none-claimed`, which is nothing). The value is durable so the adjudicator's stated posture
    /// is on record when the capability lands.
    fn adjudicate(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        principal_ref: &str,
        reason: crate::attempt::AdjudicationReason,
        accepted_risk: crate::attempt::AcceptedRisk,
    ) -> Result<AdjudicationOutcome, LogError>;
    /// Record a post-adjudication late ack: the whitelist's resolution of the historical axis, in
    /// one transaction. It resolves history and nothing else. The operation is already terminal
    /// [`IntentStatus::Adjudicated`]; a late ack does not reopen it, restore its tail position,
    /// spend retry budget, or touch a `SUPERSEDED_BY` successor.
    ///
    /// Three things ride the same write:
    /// - exposure retirement: this contributor's unretired `exposure_obligation` rows retire,
    ///   since its historical axis is no longer unresolved. The check stays closed while any other
    ///   contributor's row on the atom is live, so "the last contributor resolves, the check goes
    ///   silent" follows from the join, not a second counter;
    /// - exposure notices: a `LATE_ACK_APPLIED` over an atom where another effect already resolved
    ///   `APPLIED` is a materialization, and a durable
    ///   [`crate::attempt::AnomalyKind::ExposureMaterialized`] annotation is written on the
    ///   adjudication record;
    /// - the undo-parent arm: a late `APPLIED` on an undo child's attempt is the verification that
    ///   never arrived, so the parent flips [`IntentStatus::Undone`] in this transaction (and its
    ///   presentation follows). A late `REFUSED_NO_EFFECT` does not: the restore provably did not
    ///   happen and the parent stays `Applied`.
    ///
    /// A contradictory second late ack is refused and the contradiction is durably annotated
    /// ([`LateAckOutcome::RefusedAsContradiction`]); the fact chain never records both.
    fn record_late_ack(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        ack: crate::attempt::LateAck,
    ) -> Result<LateAckOutcome, LogError>;
    /// The ancillary audit trail for a late non-definitive observation, which lives in the
    /// adjudication record's trail, never the closed grammar. The sibling of
    /// [`IntentLog::record_late_ack`]: a definitive answer after adjudication resolves the
    /// historical axis through a `LATE_ACK_*`, while an indeterminate one resolves nothing, so the
    /// grammar refuses it and it goes here. Returns the minted `adjudication_annotation` id.
    ///
    /// It decides nothing, which is why it is an annotation: no fact, lifecycle move, obligation
    /// retirement or notice. The operational axis stays closed by the operator's decision and the
    /// historical axis stays as unknown as it was; the observation is just not silently dropped.
    ///
    /// An attempt with no adjudication record is an incident (the caller has just been told by the
    /// grammar that the chain is adjudicated).
    fn annotate_late_ambiguous_observation(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
    ) -> Result<String, LogError>;
    /// The historical axis of an operation already closed by adjudication: has a post-adjudication
    /// `LATE_ACK_*` resolved it, and how ([`AdjudicatedHistory`])?
    ///
    /// Fact-derived: the at-most-one `LATE_ACK_*` the whitelist admits is the answer, and the
    /// status column cannot express it (it says `Adjudicated` either way). The replay contract and
    /// the undo presentation consult it only for an operation already known to be
    /// [`IntentStatus::Adjudicated`], so no ordinary path pays for it; a key with no such row
    /// answers [`AdjudicatedHistory::Unresolved`], since "no late ack exists" is exactly that.
    fn adjudicated_history(&self, idempotency_key: &str) -> Result<AdjudicatedHistory, LogError>;
    /// What the exposure check refused, if that closed this operation; `None` for every other
    /// `Failed` operation.
    ///
    /// Fact-derived, like [`IntentLog::adjudicated_history`]: the status column says `Failed` and
    /// cannot say why. The answer is the [`crate::attempt::ExposureBlock`] the check wrote in the
    /// transaction that refused, never a read-time re-derivation, which could disagree with the
    /// terminal it explains once obligations retire.
    ///
    /// Called only for an operation already known [`IntentStatus::Failed`], so no ordinary path
    /// pays for it. Its two halves are confined differently: only the Photon-local `obligation_id`
    /// reaches the caller, as [`ExecuteError::ExposureBlocked`]; the provider-native `atom_key`
    /// stays inside the engine.
    fn exposure_block(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::attempt::ExposureBlock>, LogError>;
    /// The typed plan-admission record on this operation's `FAILED_PRE_SEND` fact: the reader of
    /// what [`IntentLog::authorize_send`]'s plan arm wrote, taken from the fact chain as
    /// [`IntentLog::exposure_block`] reads its block (the first `FAILED_PRE_SEND` carrying one).
    /// `None` = no fact of this operation carries a record.
    fn plan_refusal(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::attempt::PlanRefusalRecord>, LogError>;
    /// Resolve the reference an [`ExecuteError::ExposureBlocked`] carries: the operator's path
    /// from an opaque obligation id to what the obligation is. `None` for an id this store never
    /// wrote.
    ///
    /// The refusal names a Photon-local row id instead of a provider-native atom key, and a
    /// pointer an operator cannot follow would trade one defect for another. Nothing in the engine
    /// reads it; like [`IntentLog::unknown_review`] it is a report, and no field authorizes
    /// anything. The answer is itself id-free ([`ExposureObligation`]): the obligation's engine
    /// identity, direction, generation, contributing attempt and instants, never `primitive_atom`
    /// or `provider_scope`.
    fn exposure_obligation(
        &self,
        obligation_id: &str,
    ) -> Result<Option<ExposureObligation>, LogError>;
    /// The unknown-age report: every attempt whose historical attribution is `UNKNOWN` and whose
    /// operational axis is still open, with the age verdict computed against
    /// `review_after_seconds` (the engine passes [`crate::attempt::UNKNOWN_REVIEW_AFTER_SECONDS`]).
    ///
    /// A report, never a decision: the threshold surfaces long-ambiguous attempts for a human and
    /// never auto-decides. Nothing in the engine reads it, and a threshold of zero surfaces
    /// everything without adjudicating anything.
    ///
    /// `now_unix_secs` is the caller's wall clock. The comparison is on canonical RFC 3339 UTC
    /// text via [`crate::prestate::rfc3339_utc`], which sorts lexicographically in chronological
    /// order, so the cutoff is one string comparison and no second date arithmetic exists.
    ///
    /// It also answers the clock question. The write side clamps every fact to
    /// `max(now, persisted high-water)`, so a backward wall-clock step would freeze this report's
    /// age verdict for the whole rollback interval. The same comparison the clamp makes is
    /// evaluated here, and a detected rollback is surfaced on
    /// [`UnknownReviewReport::clock_rollback_detected`] with every listed row forced `review_due`
    /// (immediate review instead of waiting for wall time to catch up). Both implementations use
    /// `unknown_review_rollback` as the one detector.
    fn unknown_review(
        &self,
        now_unix_secs: u64,
        review_after_seconds: u64,
    ) -> Result<UnknownReviewReport, LogError>;
    /// Record a new capacity configuration: validate, append a `kind='capacity'` act at the next
    /// generation, run the same fit-check as `crate::capacity::activation_fits` (private, so not a
    /// link) over current occupancy, and append the `kind='capacity_activated'` act in the same
    /// transaction when it fits (the no-traffic activation case). A reduction that does not fit
    /// stays pending: forward admission answers to the new bounds immediately, remedies keep
    /// answering to the bounds still active, and activation lands at whichever `settle_status`
    /// write first makes the pool fit (the `intents_status_activation` SQL trigger on the durable
    /// store, the sole status-side authority; this method's own fit-check is a separate authority
    /// over a different event, the config act itself, never a status write).
    fn record_capacity_config(
        &mut self,
        new: crate::capacity::CapacityConfig,
    ) -> Result<(), LogError>;
    /// The root commitment key's registered fingerprint (`key_custody.rs`). `None` = no key
    /// registered yet.
    fn registered_key_fingerprint(&self) -> Result<Option<String>, LogError>;
    /// Register the fingerprint once. A second call is a `LogError`; there is no rotation path.
    fn register_key_fingerprint(&mut self, fingerprint: &str) -> Result<(), LogError>;
    /// Append one knob act to `engine_config` (kind and payload from the typed act) and return
    /// the generation it landed at. Append-only by the table's own triggers. The payload is first
    /// re-read through its kind's reader (`KnobAct::checked_payload`): an act the reader refuses
    /// (`configured_k = 0`) is a [`LogError`] and nothing is appended.
    fn record_knob_act(&mut self, act: crate::config_knobs::KnobAct) -> Result<u64, LogError>;
    /// The three knobs in force, read in one transaction, each at the head act of its kind
    /// (highest generation) through the strict readers. A malformed head act refuses rather than
    /// falling back to the default: a knob nobody can read is not a knob.
    fn knob_state(&self) -> Result<crate::config_knobs::KnobState, LogError>;
    /// Mint a TriagePlan in one transaction: read the knobs in force, freeze each member's
    /// display and observed state from the store's own rows, derive the account key, mint every
    /// digest through `plan::PlanDigests::mint`, freeze the lane and mode, stamp `minted_at` from
    /// the sticky clock and `expires_at = minted_at + ttl`, run the plan's own shape check, and
    /// persist plan and members. Refuses a zero or out-of-range TTL, an unknown member, an empty
    /// set, and an unreadable knob, writing nothing.
    fn mint_plan(&mut self, root_key: &crate::commitment::CommitmentKey, spec: crate::plan::PlanSpec) -> Result<crate::plan::MintedPlan, crate::plan::PlanStoreError>;
    /// The stored plan, rebuilt from its row (every value parsed strictly, the presentation
    /// re-derived from the stored members) and run through `TriagePlan::validate_shape`; a stored
    /// row that fails any of it is a [`LogError`], never a plan. `None` = no such plan.
    fn plan(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::plan::TriagePlan>, LogError>;
    /// Record the positive decision: re-encode what the renderer says it showed, commit it under
    /// the plan's stored randomizer, build the evidence (PerMember; Aggregate with the re-derived
    /// sample; or Bypassed, binding the generation the plan froze at mint, where there is no
    /// screen and `rendered` is not consulted, refused `BypassGenerationMismatch` when the bypass
    /// knob's generation in force differs), run `plan::validate_evidence`, and persist, all in one
    /// transaction. Write-once per plan. Before building the evidence it runs `start_episode`'s two
    /// checks (record honesty, not a control): `control_epoch` equal to the plan's
    /// (`PlanStoreError::EpochMismatch`, nothing written), and `expires_at > effective_now` on the
    /// sticky clock (`PlanStoreError::Expired`, which keeps the latch advance as `start_episode`'s
    /// refusals do).
    fn record_approval(&mut self, root_key: &crate::commitment::CommitmentKey, plan_id: &crate::plan::PlanId, approver: &str, rendered: crate::plan::RenderedView) -> Result<crate::plan::ApprovalEvidence, crate::plan::PlanStoreError>;
    /// The plan's recorded evidence, read back strictly; `None` = not approved.
    fn approval(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::plan::ApprovalEvidence>, LogError>;
    /// Start the plan's episode, or resume its non-terminal one, in one transaction, refusing by
    /// name in this order: plan present, approved, `control_epoch` equal, not expired on the sticky
    /// clock (`expires_at <= effective_now` is expired), the existing episode not terminal
    /// (`Terminal`). A fresh start writes the head at generation 1 (status `active`, `claim_epoch`
    /// = the current epoch) and the journal's `start` row; a resume returns the head as read. The
    /// epoch and expiry refusals close an existing non-terminal episode first
    /// (`invalidated{epoch_mismatch}` / `invalidated{expired}`, one journaled transition committed
    /// with the refusal). Every outcome past the expiry check keeps the sticky clock's latch
    /// advance; no other refusal or resume writes anything.
    fn start_episode(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::EpisodeStart, crate::episode::EpisodeRefusal>;
    /// The plan's episode head, read strictly; `None` = no episode.
    fn episode(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::Episode>, LogError>;
    /// The status token alone (one column read). `None` = no episode.
    fn episode_status_check(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::EpisodeStatusToken>, LogError>;
    /// The preflight ready barrier. Sets `ready_at` in a transaction that first counts the plan's
    /// children holding a `send_authorized` fact and refuses `DispatchBegan` unless that count is
    /// zero. An already-set marker answers `AlreadyReady` and writes nothing; a terminal episode
    /// answers `Terminal`, a non-active one `NotActive`.
    fn mark_ready(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::ReadyOutcome, crate::episode::EpisodeRefusal>;
    /// `active | paused → invalidated{reason}`, guarded by
    /// `episode::assert_transition`. For `StalePreflight` the `mark_ready` zero-dispatch count
    /// runs first in the same transaction and refuses `DispatchBegan` if any child was
    /// send-authorized; the other reasons are not counted.
    fn invalidate_episode(&mut self, plan_id: &crate::plan::PlanId, reason: crate::episode::InvalidationReason) -> Result<(), crate::episode::EpisodeRefusal>;
    /// The exact-N predicate, decided in the transaction that writes it. First the epoch: a
    /// non-terminal episode (`active` or `paused`) whose plan's `control_epoch` is no longer the
    /// store's becomes `invalidated{epoch_mismatch}` whatever its children say (never a
    /// live-but-dead machine). Then an `active` episode whose every member holds a terminal child
    /// (each status parsed strictly and judged by `IntentStatus::is_terminal`) becomes `completed`;
    /// otherwise, at or past the plan's expiry on the sticky clock it becomes `invalidated{expired}`
    /// (the durable abandonment bound); otherwise `Incomplete` with the counts, the only write being
    /// the sticky clock's latch advance. A paused episode under the plan's own epoch answers
    /// `Incomplete` before the clock is read, and nothing is written.
    fn complete_episode_if_done(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::Completion, LogError>;
}

/// The rollback detector both [`IntentLog::unknown_review`] impls share: did the caller's wall
/// clock step backward relative to the facts this store holds? It re-enters
/// [`crate::attempt::clamped_now`]'s own comparison rather than defining a second rule, and so
/// inherits its shape check: a non-canonical stored high-water fails explicitly rather than
/// sorting low and silently answering "no rollback".
///
/// `high_water` is the empty string when the store holds no fact yet, the same absent-latch
/// convention the clamp takes, which can never be a rollback.
pub(crate) fn unknown_review_rollback(now_utc: &str, high_water: &str) -> Result<bool, LogError> {
    Ok(crate::attempt::clamped_now(now_utc, high_water)
        .map_err(|e| LogError(format!("unknown_review clock: {e}")))?
        .backward_step_detected)
}

/// What the undo eligibility derivation reads: one store round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoContext {
    /// The parent's opaque `intent_id`, from which the undo child's key is derived.
    pub parent_intent_id: String,
    /// The journal row's captured `P` (parsed `touched_atom`) and its offer deadline, when a
    /// row exists.
    pub journal: Option<CapturedJournal>,
    /// A `pre_state_tombstone` row exists for this intent (deletion provenance; dormant, seeded
    /// by hand in tests).
    pub tombstoned: bool,
    /// `max(now_utc, persisted high-water)`, already re-persisted as the new high-water (the
    /// sticky clock). RFC 3339 UTC; compare lexicographically.
    pub effective_now: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedJournal {
    /// Captured pre-state `P`: atom key to captured boolean.
    pub p: std::collections::BTreeMap<String, bool>,
    /// The offer deadline bound at capture.
    pub undo_offer_until: String,
}
