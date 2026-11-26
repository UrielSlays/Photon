//! The command bus: the execute, undo, and recovery paths over an `IntentLog` and a `Connector`.

use crate::command::action_to_parts;
use crate::decision::{
    adjudicated_replay_outcome, classify, decision_outcome, not_dispatched, Decision, FailedWhy,
    Terminal,
};
use crate::keys::{compensation_key, undo_child_key};
use crate::{
    prestate, AdjudicatedHistory, AttemptClaim, CaptureBinding, Claim, ClaimOutcome, Command,
    Connector, ConnectorError, ConnectorVerdict, DeadLetterWrite, EffectEvidence, EffectWitness,
    ExecuteError, Executed, ExposureObligation, FailureKind, GrantRatchet, GrantRefusal, Intent,
    IntentLog, IntentStatus, JournalReplaceOutcome, LateAckOutcome, LogError, NoGrantRatchet,
    RecoverReport, RestorationVerdict, SendAuthOutcome, SettleOutcome, StatusPrecondition,
    StatusWrite, TransientCharge, UndoPairChild, UndoPairFlip, UndoPresentation,
    UndoPresentationRead, UnknownReviewReport, WitnessRecord, WitnessWriteFailure,
};

/// How [`CommandBus::drive_undo_child`] left the pair it was handed. Both variants are `Ok`
/// (the drive reached a durable terminal) but mean opposite things about the undo, so the
/// shared drive states which instead of collapsing them into `()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UndoDriveOutcome {
    /// The undo is verified (restore applied, already-restored, or the no-op kill), or a
    /// crashed child converged onto its own terminal: parent `Undone`, child `Applied`.
    Verified,
    /// A legacy pre-stage-3 deferred-undo child was mapped, not driven: the parent went back
    /// to `Applied` (the last verified truth) and the child to `Failed`. The undo did not
    /// happen; the sweep names the child in [`RecoverReport::legacy_compensations`].
    LegacyMapped,
}

/// Who owns the drive of an undo child, decided by the atomic claim (the undo path's copy of
/// the ownership discipline [`CommandBus::execute`] has).
///
/// Passing the head predicate is not ownership: two `CommandBus` instances over one store can
/// both see no live same-resource predecessor and both drive the same child, the second
/// overwriting what the first restored. Only `record()`'s `Claim` settles it, being the one
/// step that is atomic across connections.
#[derive(Debug, Clone)]
enum UndoChildAdmission {
    /// This call inserted the child row: the caller owns the synchronous drive.
    Inserted(Intent),
    /// A concurrent peer holds the claim (or already did). The caller never drives; it
    /// answers from the row, as a replay does.
    Existing(Intent),
}


/// Discriminator for a pre-stage-3 deferred undo child: a compensation (`compensates` set),
/// non-terminal, with no frozen basis or one with empty `atom_targets`. A stage-2 store can
/// hold such a row live while its parent was already flipped `Undone` at scheduling.
///
/// Sound because [`IntentLog::record`] runs the admission tier on every fresh insert
/// ([`reject_inadmissible_basis`]), so rows minted by current code have non-empty targets;
/// weaken that check and this starts matching live children. Every entry point that consults
/// undo state must route through it: [`CommandBus::undo`] (maps the pair, then continues as a
/// fresh undo), [`CommandBus::recover`] (via [`CommandBus::drive_undo_child`]), and
/// [`CommandBus::undo_presentation`] (read-only: reports `Undoing`, mutates nothing).
fn is_legacy_deferred_child(child: &Intent) -> bool {
    child.command.compensates.is_some()
        && !child.status.is_terminal()
        && child
            .frozen_basis
            .as_ref()
            .is_none_or(|b| b.atom_targets.is_empty())
}

/// Mint the undo child command for a parent. Shared by both admission paths
/// ([`CommandBus::admit_undo_child`] and [`CommandBus::admit_noop_undo_child`]) so a no-op undo
/// and a dispatching one differ only in the basis they commit: the reserved key, the
/// descriptor inverse in the action column (used for ordering, projection and the link check;
/// dispatch never derives from it), the parent's principal/epoch/tier envelope, and the
/// explicit `compensates` link carrying the parent's user key.
fn mint_undo_child_command(parent: &Intent, child_key: &str) -> Command {
    // `Command::new` leaves `plan_child` None: an undo child is a plain inverse and carries no
    // plan link.
    let mut child = Command::new(
        child_key.to_string(),
        parent.command.account.clone(),
        parent.command.facet.clone(),
        parent.command.action.inverse(),
    );
    child.envelope = parent.command.envelope.clone();
    child.compensates = Some(parent.command.idempotency_key.clone());
    child
}

/// The transient-retry budget: the maximum number of dispatch attempts (the initial `execute()`
/// plus recovery re-dispatches) before a still-failing intent is dead-lettered to `Failed`
/// (ADR-P013 (b)). A transient error that recurs this often is treated as permanent. A
/// provisional default; the real connector may tune it with [`backoff_delay`]. Public so the
/// docs for `Intent::attempts` can link it.
pub const RETRY_CAP: u32 = 5;

/// Base delay before the first transient retry (provisional default; no clock is wired yet).
pub const BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);
/// Ceiling on the retry delay, bounding exponential growth.
pub const BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(60);

/// The provisional transient-retry backoff schedule (ADR-P013 (b)): an exponentially growing
/// delay `BACKOFF_BASE * 2^(attempts-1)`, saturating and capped at [`BACKOFF_CAP`]. Pure and
/// deterministic; a future recovery scheduler uses it to decide when a `Pending` intent is
/// next eligible to retry. `attempts == 0` yields the base delay (never zero, never a panic).
///
/// Do not wire this into a real retry path without full jitter in the same change:
/// exponential backoff without jitter produces synchronized retry waves that hammer a
/// recovering provider.
pub fn backoff_delay(attempts: u32) -> std::time::Duration {
    let exponent = attempts.saturating_sub(1).min(63);
    let factor = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let secs = BACKOFF_BASE
        .as_secs()
        .saturating_mul(factor)
        .min(BACKOFF_CAP.as_secs());
    std::time::Duration::from_secs(secs)
}

/// What [`CommandBus::resolve_admission_basis`] produced. Two values, because a resolver
/// refusal is only half an answer: whether it may be reported as `AdmissionRefused` depends on
/// a fact about the durable log that the resolver does not know.
enum AdmissionBasis {
    /// A validated fresh basis: this admission proceeds to `record()`.
    Fresh(prestate::FrozenBasis),
    /// The resolver refused, but the key is already durably claimed (a peer won the window
    /// between the caller's initial read and the resolution). Nothing about this admission is
    /// refusable any more; the payload is the existing row's own truth-table verdict.
    RacedToExistingRow(Result<(), ExecuteError>),
}

/// What the shared capture pipeline ([`CommandBus::ensure_prepared`]) decided about an
/// intent's dispatch eligibility: may it go to the wire now? "No" has two shapes that callers
/// must not conflate: the operation is still open (park), or it is closed forever (report what
/// a replay reports). Every caller handles all three variants.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PipelineVerdict {
    /// Capture is settled (journal row present, or none owed): the caller may dispatch.
    Proceed {
        /// Which capture this pipeline settled on: the CAS token the caller spends at the
        /// send-authorization boundary. The pipeline decides that an operation's journal row
        /// exists, so it is also what can name the generation a dispatch is bound to.
        capture: CaptureBinding,
    },
    /// `NotAtHead` / `EpochFenced`: the intent stays non-terminal and undispatched. `execute`
    /// signals in-flight; `recover` leaves it `Pending` and continues the sweep.
    Park,
    /// The operation was closed under this capture: PREPARE's own transaction found the row
    /// terminal (a sever's atomic closure, or a peer driver's settlement, landing in the
    /// pipeline's provider-read window). The payload is the disposition the row holds, which the
    /// caller reports through [`CommandBus::status_replay_outcome`]; a sweep skips it without a
    /// barrier, since a terminal row is not an in-flight predecessor.
    Closed(IntentStatus),
}

/// What the shared dispatch claim ([`CommandBus::claim_dispatch`]) decided. Two values, as for
/// [`PipelineVerdict`]: is this wire-bound dispatch mine to make? Every caller handles both.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchOwnership {
    /// This driver owns the attempt. Authorization is reachable from here, not the wire.
    Owned {
        /// The owned attempt's opaque id, which is what [`CommandBus::authorize_dispatch`]
        /// authorizes: the check names the value the claim returned rather than re-reading it.
        attempt_id: String,
        /// The attempt's ordinal within its operation: `1` for a first dispatch, `n+1` for a retry
        /// minted from the operation's own chain. A retry owes the requalification at the head
        /// before the send-authorization check; a first dispatch does not.
        ordinal: u64,
        /// The chain revision the claim observed: 1 for a freshly minted attempt, the live head for
        /// a re-entry. Every settlement the caller makes before authorizing passes this to
        /// [`CommandBus::settle_dispatch`], which compare-and-appends against it; after
        /// authorization the caller passes `None`, because its own at-most-one `SEND_AUTHORIZED`
        /// makes it the wire's owner.
        observed_revision: u64,
        /// The claimed attempt's fact-derived class, carried from [`ClaimOutcome::Won`]:
        /// `PreIssuance` for a fresh mint and for a re-entered unauthorized attempt, `IssuedOrUnknown`
        /// for a re-entered attempt whose `SEND_AUTHORIZED` is already committed.
        ///
        /// A caller may make a pre-wire decision only about a `PreIssuance` attempt. The ordinal
        /// cannot answer that: a crashed-authorized retry is handed back at its own ordinal, so
        /// "ordinal > 1" is true of an attempt that may already have spent the wire.
        class: crate::attempt::AttemptClass,
    },
    /// Refused, and the operation is terminal; carries the disposition it holds. A peer that
    /// settled (or a sever that closed) between the caller's read and this claim leaves a row
    /// nothing will sweep again; "in flight, recovery owns it" would be false, and in the sweep a
    /// barrier over it would strand every later intent on the resource. The caller answers
    /// through [`CommandBus::status_replay_outcome`], so a dispatching call and an identical
    /// replay give the same answer, as with [`DispatchAuthorization::Terminal`].
    Terminal(IntentStatus),
    /// Not this driver's dispatch and the operation is still active (another driver owns it, an
    /// unknown awaits adjudication, or a sever landed without closing this row): the caller must
    /// park, silently, without touching the wire.
    Park,
}

/// What [`CommandBus::settle_dispatch`] did, at engine grain.
///
/// There are three independent axes (plus `preempted`), and every caller owes an answer to all
/// of them: the recovery sweep asks whether the operation is still an in-flight predecessor
/// (`terminal`); a pre-wire caller must know whether its verdict was recorded at all (a lost
/// compare-and-append wrote nothing, and treating that as a settlement would report a
/// disposition the ledger does not hold); and a caller about to report its own outcome must
/// know whether the chain's answer outranks it. A caller that reads one field and drops the
/// rest is the defect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchSettlement {
    /// The operation is now lifecycle-terminal (read back from the store, never predicted).
    pub(crate) terminal: bool,
    /// The pre-wire compare-and-append lost: nothing was written, a peer owns the attempt.
    pub(crate) superseded_pre_wire: bool,
    /// The chain's own answer outranks the caller's verdict. Read back from the ledger, never
    /// inferred from what we sent; `None` whenever the caller's verdict stands.
    ///
    /// Two post-adjudication races produce it, both legal:
    ///
    /// * A contradictory late ack: this verdict raced an adjudication and was converted to a late
    ///   ack, and the at-most-one-late-ack rule refused it because the chain already holds the
    ///   opposite accepted late ack. The refusal is correct (the chain never records two
    ///   contradicting attributions, and the anomaly is annotated), but the caller is owed the
    ///   first accepted late ack's answer instead.
    /// * A late non-definitive observation: an `ACK_AMBIGUOUS` verdict arriving after
    ///   adjudication. The grammar refuses it and it lands in the adjudication record's
    ///   ancillary trail; the caller is owed the historical axis as it stands, normally
    ///   [`AdjudicatedHistory::Unresolved`] (an operator has decided; nobody knows what the
    ///   provider did).
    ///
    /// Both answer through one table ([`adjudicated_replay_outcome`]), so an in-flight call and
    /// an identical replay never disagree about the same chain.
    ///
    /// `None` on every other outcome, including a same-polarity duplicate late ack (the chain and
    /// the caller agree, so the caller's verdict stands).
    outranked: Option<AdjudicatedHistory>,
    /// The row was already terminal and this settlement wrote nothing. This matters for the
    /// operation-grain arm: a reconciliation with no attempt (the capture pipeline's own failure,
    /// which runs ahead of the dispatch claim) settles at operation grain, and its write is
    /// guarded on the non-terminal domain like every status write. When the guard refuses, the row
    /// holds a disposition another authority wrote (above all a sever that closed this operation
    /// while the observation was in flight), and the caller may not report its own failure over
    /// it. This carries what the row holds, and [`CommandBus::status_replay_outcome`] turns it
    /// into the caller's answer, identical to a replay of the same key.
    ///
    /// `None` whenever this settlement's own verdict is the row's disposition, including the
    /// attempt-carrying arms, where the guard lives inside `settle_attempt`'s transaction and the
    /// grammar's `PostTerminalAppend` refusal carries the same meaning.
    preempted: Option<IntentStatus>,
}

/// What the retry-requalification gate ([`CommandBus::requalify_retry_at_head`]) decided: the
/// retry reading of the capture table, plus the two answers only the store can give.
#[derive(Debug)]
enum RetryGate {
    /// Dispatch: the capture is still truthful (`C == P`), or has just been replaced with a
    /// fresh one, or the operation is capture-off and its frozen basis re-verified.
    Proceed {
        /// The capture this decision was made against: the row it read when it answered
        /// `C == P`, or the one its own replace just committed. The caller carries it to the
        /// send-authorization boundary, which refuses if a peer re-prepared the row meanwhile.
        capture: CaptureBinding,
    },
    /// The operation is done: `C == A`, and the terminal (`EXTERNALLY_SATISFIED`, with the
    /// attempt's proven-no-wire `FAILED_PRE_SEND`) is already committed. Nothing further is owed
    /// and nothing reached the wire.
    Closed,
    /// Fail-closed: the gate could not qualify this retry (a re-prepare refused, or the
    /// operation has no target vector to compare against). The operation stays non-terminal and
    /// undispatched, an in-flight predecessor like any park.
    Park,
    /// The gate's own provider read failed. Nothing was reconciled: the caller folds it into its
    /// single failure arm, which owns the taxonomy and the budget.
    Failed(ConnectorError),
}

/// What the shared send-authorization check ([`CommandBus::authorize_dispatch`]) decided.
/// `Authorized` is the only value from which a connector socket may be entered; the other two
/// are refusals, split by what the operation now is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchAuthorization {
    /// A `SEND_AUTHORIZED` fact is committed for this attempt under the current control epoch.
    Authorized,
    /// Refused, and the operation is terminal; carries the disposition it holds. Either the
    /// refusing transaction closed it ([`SendAuthOutcome::EpochFenced`],
    /// [`SendAuthOutcome::ExposureBlocked`]) or another already had (a sever closed our claim
    /// before our own check could); the caller does not care which. "Park, recovery owns it" would
    /// signal in-flight for a row that is settled forever and will never appear in
    /// `unreconciled()` again. The caller answers through [`CommandBus::status_replay_outcome`],
    /// so a dispatching call and an identical replay give the same answer.
    Terminal(IntentStatus),
    /// Refused while the operation is still active: an equally-current peer spent the wire (and
    /// has not settled), or an exposure check refused an already-authorized attempt without a
    /// terminal (`authorize_send` writes the no-effect terminal only where it is true). Nothing
    /// reached this driver's wire and the operation stays non-terminal, an in-flight predecessor
    /// like any park.
    Park,
}

/// One entry in [`CommandBus::recover`]'s per-resource ordering barrier: the sweep-local twin
/// of the head predicate's two lanes, tagged because the lanes are scoped differently.
///
/// A native resource key is provider-scoped, so it keys the barrier alone: tupling it with the
/// Photon-local account let two local handles onto one provider account and message raise and
/// check different entries, so the successor dispatched in the same sweep as its failed
/// predecessor and reversed causal order. A Photon-local `message_ref` is meaningless outside
/// its account, so it stays account-scoped. The tag also keeps the two spaces disjoint: a
/// native key and a local ref that spell the same text are different resources.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BarrierKey {
    /// The admission-frozen provider-native resource key. No account: it already names one.
    Native(String),
    /// `(account, message_ref)`: the Photon-local lane, for rows with no frozen basis (and, by
    /// the deliberate lane overlap, for rows that have one too).
    Local(String, String),
}

/// The single mutation boundary: records intent durably, dispatches to the connector, and
/// reconciles the intent's status with the outcome.
pub struct CommandBus<L: IntentLog, C: Connector> {
    log: L,
    connector: C,
    /// The grant ratchet the plan admission consults ([`GrantRatchet`]). Defaults to
    /// [`NoGrantRatchet`], so an unwired bus refuses every plan rather than skipping the check.
    /// `Send` because the shell keeps the bus behind a `Mutex` in its managed state.
    grant_ratchet: Box<dyn GrantRatchet + Send>,
    /// The store's root commitment key, as `key_custody::root_key_verified` answered it to
    /// whoever built the bus (in production the shell's `build_gmail_arm`, which refuses the arm
    /// when custody refuses). Read by `CommandBus::plan_binding`, which derives the plan account's
    /// key from it, and by [`CommandBus::root_key`]; `None` means every plan child's send
    /// authorization is refused with a `LogError`.
    pub(crate) root_key: Option<crate::commitment::CommitmentKey>,
}

impl<L: IntentLog, C: Connector> CommandBus<L, C> {
    pub fn new(log: L, connector: C) -> Self {
        Self { log, connector, grant_ratchet: Box::new(NoGrantRatchet), root_key: None }
    }

    /// Wire the grant ratchet, replacing the fail-closed [`NoGrantRatchet`] default.
    pub fn with_grant_ratchet(mut self, ratchet: Box<dyn GrantRatchet + Send>) -> Self {
        self.grant_ratchet = ratchet;
        self
    }

    /// Wire the root commitment key, as `key_custody::root_key_verified` answered it.
    pub fn with_root_key(mut self, key: crate::commitment::CommitmentKey) -> Self {
        self.root_key = Some(key);
        self
    }

    /// The grant ratchet this bus consults (the fail-closed default until one is wired).
    pub fn grant_ratchet(&self) -> &dyn GrantRatchet {
        self.grant_ratchet.as_ref()
    }

    /// The root commitment key this bus was built with (`None` = none wired). The shell uses it
    /// to mint, approve and derive a plan's sample, and the send check derives the plan account's
    /// key from it, so a caller holding the bus needs no second source of a root key.
    pub fn root_key(&self) -> Option<&crate::commitment::CommitmentKey> {
        self.root_key.as_ref()
    }

    /// Read access to the intent log (for inspection / projection).
    pub fn log(&self) -> &L {
        &self.log
    }

    /// Write access to the intent log; the plan and episode operations (`mint_plan`,
    /// `record_approval`, `start_episode`, ...) live on [`IntentLog`].
    pub fn log_mut(&mut self) -> &mut L {
        &mut self.log
    }

    /// The child command for a member, built by [`Command::plan_child`] so a driver never spells
    /// a key, verb or account itself.
    pub fn plan_child_command(&self, plan: &crate::plan::TriagePlan, member_ref: &str) -> Command {
        Command::plan_child(plan, member_ref)
    }

    /// The cheap episode-status check the plan entry points take first: `active` passes; no
    /// episode, or any other status, is refused by name.
    fn plan_episode_active(&self, plan_id: &crate::plan::PlanId) -> Result<(), ExecuteError> {
        match self.log.episode_status_check(plan_id).map_err(ExecuteError::Log)? {
            Some(crate::episode::EpisodeStatusToken::Active) => Ok(()),
            None => Err(ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::NoEpisode)),
            Some(other) => Err(ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::EpisodeNotActive(other))),
        }
    }

    /// The stored plan, or `PlanChildRefused(NoPlan)`.
    fn stored_plan(&self, plan_id: &crate::plan::PlanId) -> Result<crate::plan::TriagePlan, ExecuteError> {
        self.log
            .plan(plan_id)
            .map_err(ExecuteError::Log)?
            .ok_or(ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::NoPlan))
    }

    /// Preflight: re-observe every member through the connector's read-only calls (`resolve_basis`
    /// for its child command, then `observe` against that basis) with no store transaction open,
    /// and compare with its approval-time observed state ([`crate::plan::member_state_diff`]).
    /// An observation that does not answer for the basis's native identity is refused as
    /// `ensure_prepared` refuses it (a deterministic basis-rebound error), with nothing written.
    /// A deterministic `observe` failure (its message gone, say) is that member's divergence, every
    /// atom `observed: None`. A transient failure is an error with nothing written, and so is an
    /// auth-class one ([`ConnectorError::credential_rejected`]): an expired token says nothing
    /// about the member, so it never invalidates the episode.
    ///
    /// No divergence calls [`IntentLog::mark_ready`]. Any divergence refuses the whole run via
    /// [`IntentLog::invalidate_episode`] with `stale_preflight` naming each diverged member and its
    /// diff. Both writes go through the store's serialized barrier (they refuse once a child holds
    /// a `send_authorized` fact), answered as [`crate::plan::PreflightOutcome::Raced`]. A peer
    /// write that closed or paused the episode after the status check is answered as the cheap
    /// check would, `PlanChildRefused(EpisodeNotActive(token))`, never a store error.
    pub fn preflight_plan(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::plan::PreflightOutcome, ExecuteError> {
        use crate::episode::EpisodeRefusal;
        use crate::plan::{PlanChildRefusal, PreflightOutcome};
        let plan = self.stored_plan(plan_id)?;
        self.plan_episode_active(plan_id)?;
        let mut diverged: Vec<(String, Vec<crate::attempt::MemberDiff>)> = Vec::new();
        for member in &plan.members {
            let command = Command::plan_child(&plan, &member.message_ref);
            let basis = self
                .connector
                .resolve_basis(&command)
                .map_err(|e| ExecuteError::AdmissionRefused(format!("admission refused: {}", e.0)))?;
            let obs = match self.connector.observe(&command, &basis) {
                Ok(obs) => obs,
                Err(e) if e.kind == FailureKind::Deterministic && !e.credential_rejected => {
                    diverged.push((member.message_ref.clone(), crate::plan::member_state_diff(&member.observed_state, &std::collections::BTreeMap::new())));
                    continue;
                }
                Err(e) => return Err(ExecuteError::Connector(e)),
            };
            if obs.native_resource_key != basis.native_resource_key {
                return Err(ExecuteError::Connector(ConnectorError::deterministic_basis_rebound()));
            }
            let diff = crate::plan::member_state_diff(&member.observed_state, &obs.atoms);
            if !diff.is_empty() {
                diverged.push((member.message_ref.clone(), diff));
            }
        }
        let not_active = |token| Err(ExecuteError::PlanChildRefused(PlanChildRefusal::EpisodeNotActive(token)));
        if diverged.is_empty() {
            return match self.log.mark_ready(plan_id) {
                Ok(_) => Ok(PreflightOutcome::Ready),
                Err(EpisodeRefusal::DispatchBegan { .. }) => Ok(PreflightOutcome::Raced { diverged }),
                Err(EpisodeRefusal::Terminal(token) | EpisodeRefusal::NotActive(token)) => not_active(token),
                Err(e) => Err(ExecuteError::Log(LogError(format!("preflight mark_ready: {e}")))),
            };
        }
        match self.log.invalidate_episode(plan_id, crate::episode::InvalidationReason::StalePreflight { diverged: diverged.clone() }) {
            Ok(()) => Ok(PreflightOutcome::Refused { diverged }),
            // A child already holds a `send_authorized` fact: the wholesale refusal is no longer
            // committable, and the per-child recheck at the send check owns staleness.
            Err(EpisodeRefusal::DispatchBegan { .. }) => Ok(PreflightOutcome::Raced { diverged }),
            // Only a terminal episode has no edge into `invalidated`: a peer closed it first.
            Err(EpisodeRefusal::IllegalTransition { from, .. }) => not_active(from),
            Err(e) => Err(ExecuteError::Log(LogError(format!("preflight invalidate_episode: {e}")))),
        }
    }

    /// Drive one member: the cheap episode-status check, the child command, then
    /// [`CommandBus::execute`] (the single admission path; the law runs at its send check).
    pub fn apply_plan_member(&mut self, plan_id: &crate::plan::PlanId, member_ref: &str) -> Result<Executed, ExecuteError> {
        self.plan_episode_active(plan_id)?;
        let plan = self.stored_plan(plan_id)?;
        let command = Command::plan_child(&plan, member_ref);
        self.execute(&command)
    }

    /// The exact-N completion / expiry-abandonment predicate
    /// ([`IntentLog::complete_episode_if_done`]).
    pub fn settle_plan_progress(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::Completion, ExecuteError> {
        self.log.complete_episode_if_done(plan_id).map_err(ExecuteError::Log)
    }

    /// The minimal per-member read, from durable rows only, in plan member order: no child is
    /// `NotMinted`; a non-terminal child `InFlight`; `Applied` is `Applied`; `Failed` with a
    /// plan-admission record is `Refused{reason, diff}`; any other terminal is `Terminal(status)`.
    pub fn plan_member_states(&self, plan_id: &crate::plan::PlanId) -> Result<Vec<(String, crate::plan::MemberState)>, ExecuteError> {
        use crate::plan::MemberState;
        let plan = self.stored_plan(plan_id)?;
        let mut out = Vec::with_capacity(plan.members.len());
        for member in &plan.members {
            let key = Command::plan_child(&plan, &member.message_ref).idempotency_key;
            let state = match self.log.get(&key).map_err(ExecuteError::Log)? {
                None => MemberState::NotMinted,
                Some(intent) if !intent.status.is_terminal() => MemberState::InFlight,
                Some(intent) if intent.status == IntentStatus::Applied => MemberState::Applied,
                Some(intent) if intent.status == IntentStatus::Failed => match self.log.plan_refusal(&key).map_err(ExecuteError::Log)? {
                    Some(record) => MemberState::Refused { reason: record.reason, diff: record.diff },
                    None => MemberState::Terminal(IntentStatus::Failed),
                },
                Some(intent) => MemberState::Terminal(intent.status),
            };
            out.push((member.message_ref.clone(), state));
        }
        Ok(out)
    }

    /// Read access to the connector (for inspection in tests).
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// Projects the durable exposure block to the caller's reference. The refusing terminal's
    /// fact carries two identities, the provider-native `atom_key` (audit) and the Photon-local
    /// `obligation_id`; only the latter may cross the caller boundary. The idempotency decision
    /// and the terminal-replay projection both read it here so they cannot surface different
    /// halves.
    fn exposure_block_reference(&self, idempotency_key: &str) -> Result<Option<String>, LogError> {
        Ok(self
            .log
            .exposure_block(idempotency_key)?
            .map(|block| block.obligation_id))
    }

    /// The single idempotency decision, taken against the store: [`classify`] over the durable
    /// row, with the adjudicated history supplied for the one class that needs it. Every call
    /// site of the truth table goes through here (see [`decision_outcome`]). The extra store
    /// read happens only for an [`IntentStatus::Adjudicated`] row, so an ordinary replay pays
    /// nothing.
    fn decide(&self, existing: Option<&Intent>, command: &Command) -> Result<Decision, LogError> {
        let adjudicated = match existing.map(|intent| &intent.status) {
            Some(IntentStatus::Adjudicated) => {
                self.log.adjudicated_history(&command.idempotency_key)?
            }
            _ => AdjudicatedHistory::Unresolved,
        };
        // A `Failed` row's status cannot say why it failed, and one reason (the exposure check)
        // writes it into the fact chain. Only a `Failed` row pays for the read; the durable block's
        // two identities are split by [`CommandBus::exposure_block_reference`].
        let failed_why = match existing {
            Some(intent) if intent.status == IntentStatus::Failed => {
                self.failed_why(&command.idempotency_key, intent.command.plan_child.is_some())?
            }
            _ => FailedWhy::Unrecorded,
        };
        Ok(classify(existing, command, adjudicated, failed_why))
    }

    /// Projects a `Failed` row's fact chain to its caller-facing reason; [`CommandBus::decide`]
    /// and [`CommandBus::status_replay_outcome`] both ask here. For a plan child, the plan arm's
    /// record comes first ([`IntentLog::plan_refusal`], rebuilt strictly: a record that does not
    /// read back is a [`LogError`]); otherwise the exposure block's surfaceable half
    /// ([`CommandBus::exposure_block_reference`]).
    fn failed_why(&self, idempotency_key: &str, plan_child: bool) -> Result<FailedWhy, LogError> {
        if plan_child {
            if let Some(record) = self.log.plan_refusal(idempotency_key)? {
                let reason = crate::plan::PlanSendRefusal::from_record(&record)
                    .map_err(|e| LogError(format!("'{idempotency_key}': {e}")))?;
                return Ok(FailedWhy::Plan { reason, member_ref: record.member_ref });
            }
        }
        Ok(match self.exposure_block_reference(idempotency_key)? {
            Some(obligation) => FailedWhy::Exposure(obligation),
            None => FailedWhy::Unrecorded,
        })
    }

    /// Execute a command: record the intent durably (`Pending`) before dispatching, apply it
    /// below the seam, then reconcile to `Applied` on success.
    ///
    /// `Ok` means durably applied (or an identical replay of a settled `Ok`), with the effect
    /// witness outcome in [`Executed::witness`]. A witness write that fails after the settlement
    /// committed is [`WitnessRecord::WriteFailed`] inside that `Ok`: the operation is `Applied` and
    /// its undo key is real, so it is not an error that would discard the key.
    pub fn execute(&mut self, command: &Command) -> Result<Executed, ExecuteError> {
        // The bus's check of `RiskTier::requires_plan` (`record()`'s plan arms also use it as their
        // `NotARedVerb` head check): a red verb enters only as a plan child, and a plan link is carried
        // only by a red verb. Both are decided from the command alone before anything is read or
        // written, so every replay answers the same.
        match (command.plan_child.is_some(), command.action.risk_tier().requires_plan()) {
            (false, true) => return Err(ExecuteError::PlanRequired),
            (true, false) => return Err(ExecuteError::PlanChildRefused(crate::plan::PlanChildRefusal::NotARedVerb)),
            _ => {}
        }
        // Single idempotency decision (ADR-P013): classify against the durable log, then act on the
        // typed `Decision`. No status interpretation is duplicated here, and the exhaustive match makes
        // a new `IntentStatus` or decision class a compile error until handled.
        let existing = self
            .log
            .get(&command.idempotency_key)
            .map_err(ExecuteError::Log)?;
        // A non-fresh row resolves immediately via the shared truth table (`decision_outcome`).
        if let Some(outcome) =
            decision_outcome(self.decide(existing.as_ref(), command).map_err(ExecuteError::Log)?)
        {
            return not_dispatched(outcome);
        }
        // Fresh: the atomic claim is authoritative under same-key concurrency, since `record`
        // reports whether this call inserted the row. Only the inserter dispatches. A peer that
        // claimed the key between classify and record yields `AlreadyExisted`; we re-derive the
        // decision from the existing row and never re-dispatch. A different command is refused inside
        // `record` (a `LogError`), so the record is never overwritten. A failed persist aborts the
        // apply, so there is no unrecorded mutation (ADR-P013).
        //
        // BASIS-2: resolution consumes local durable resolver state; a missing or invalid basis
        // refuses admission with a named retryable error, never a stale fallback. It runs before
        // `record` so no provider resolution happens inside the admission transaction.
        let basis = match self.resolve_admission_basis(command)? {
            AdmissionBasis::Fresh(basis) => basis,
            // A peer claimed the key inside the resolution window: "nothing durable was written" is no
            // longer true, so the existing row's verdict is the answer (as for a lost claim race below).
            AdmissionBasis::RacedToExistingRow(outcome) => return not_dispatched(outcome),
        };
        match self.log.record(command, &basis) {
            Ok(Claim::Inserted) => {}
            Ok(Claim::AlreadyExisted) => {
                let now = self
                    .log
                    .get(&command.idempotency_key)
                    .map_err(ExecuteError::Log)?;
                return not_dispatched(
                    decision_outcome(self.decide(now.as_ref(), command).map_err(ExecuteError::Log)?)
                        .unwrap_or(Err(ExecuteError::InProgress)),
                );
            }
            // Refused by capacity, nothing durable written: the same "nothing happened yet" shape as
            // `AdmissionRefused`, with the occupancy-shaped typed string.
            Ok(Claim::CapacityRefused(refusal)) => return Err(ExecuteError::CapacityRefused(refusal)),
            // The plan-child admission arm refused, nothing written (only a plan-linked command meets it).
            Ok(Claim::PlanChildRefused(refusal)) => return Err(ExecuteError::PlanChildRefused(refusal)),
            Err(err) => {
                // `record` rejects a different command claimed under this key (a key-rewrite that won the
                // race between classify and record) as a `LogError`. On the claim path that is a `Conflict`,
                // not a storage failure, so re-read to disambiguate (a real persist error still surfaces as
                // `Log`).
                let now = self
                    .log
                    .get(&command.idempotency_key)
                    .map_err(ExecuteError::Log)?;
                if now.is_some_and(|existing| existing.command != *command) {
                    return Err(ExecuteError::Conflict);
                }
                return Err(ExecuteError::Log(err));
            }
        }
        // Tail ordering (ADR-P013): if a same-resource predecessor is still non-terminal, do not
        // dispatch now, since recovery would later reorder this against it (letting a deferred undo
        // defeat this newer action, or vice versa). Leave the claimed `Pending` intent for recovery to
        // sequence by `seq` and signal in-flight, never a false `Ok` for a not-yet-applied intent.
        // `execute` and `undo` share this rule.
        //
        // The deferral is terminal-aware: the predicate is about a predecessor, so it says nothing
        // about this row, and a sever committing between `record()` and here closes it (an active
        // operation with no live attempt completes `Severed` in the sever's own transaction).
        // "Recovery owns it" about a row nothing will sweep again would be false.
        if self.has_pending_same_resource_predecessor(command)? {
            return not_dispatched(self.park_or_replay(&command.idempotency_key));
        }
        // Observe, then PREPARE, through the pipeline that `recover` also runs. It names the capture
        // this dispatch is bound to, spent at the send-authorization check below.
        let capture = match self.ensure_prepared(command) {
            Ok(PipelineVerdict::Proceed { capture }) => capture,
            // Parks: the intent stays non-terminal and undispatched; recovery re-runs the pipeline.
            Ok(PipelineVerdict::Park) => return Err(ExecuteError::InProgress),
            // Closed under our own capture: a sever committed between `record()` and PREPARE's
            // transaction (it closes an active operation with no live attempt in its own write while the
            // pipeline observes the provider). The row is settled, so the answer is the truth table's,
            // as in the connector-failure arm below.
            Ok(PipelineVerdict::Closed(status)) => {
                return not_dispatched(self.status_replay_outcome(&command.idempotency_key, &status));
            }
            Err(ExecuteError::Connector(error)) => {
                // No attempt yet: the capture pipeline runs before the dispatch claim, so this failure has
                // no attempt to attribute to and reached no wire. The attempt-shaped axes cannot occur on a
                // no-attempt reconciliation (no chain to compare, no verdict fact to refuse), and `terminal`
                // is not asked because the answer is the connector error either way.
                //
                // Except when the row was already someone else's: the pipeline observes the provider, so a
                // sever can commit in that window and close this operation. The guard then wrote nothing, and
                // the caller is owed the sever, as an identical replay reads, not a fresh connector failure.
                let settled = self
                    .reconcile_connector_failure(&command.idempotency_key, None, &error, None)
                    .map_err(ExecuteError::Log)?;
                if let Some(status) = settled.preempted {
                    return not_dispatched(self.status_replay_outcome(&command.idempotency_key, &status));
                }
                return Err(ExecuteError::Connector(error));
            }
            Err(other) => return Err(other),
        };
        // The dispatch claim: the ownership transition immediately before the socket. The observed
        // transient count is 0 because this path is reached only on `Claim::Inserted`. Passing what
        // we observed (rather than re-reading) is the point of the compare-and-append: if a peer
        // charged a failure against this row since our insert, it dispatched, and our claim must lose.
        //
        // No retry requalification is owed here: the fact chain is empty, so the claim can only answer
        // ordinal 1. The requalification belongs to the retry re-entry point, `recover`'s forward arm
        // ([`CommandBus::requalify_retry_at_head`]).
        let attempt_id = match self.claim_dispatch(&command.idempotency_key, 0)? {
            DispatchOwnership::Owned { attempt_id, .. } => attempt_id,
            // The claim's own re-read found this operation closed: answer what an identical replay
            // answers, never "in flight" about a row nothing will sweep again.
            DispatchOwnership::Terminal(status) => {
                return not_dispatched(self.status_replay_outcome(&command.idempotency_key, &status))
            }
            // Someone else owns this dispatch and the operation is still open: nothing is owed and
            // nothing reached our wire, so in-flight is the signal.
            DispatchOwnership::Park => return Err(ExecuteError::InProgress),
        };
        // There is no pre-wire settlement on this path, so the claim's observed revision is unused and
        // both settling sites below pass `None`. The claim can re-enter (a peer racing between
        // `record()` and here claims first), but between here and the socket there is one check, the
        // send authorization, and a peer that already authorized makes it refuse
        // `DuplicateSendAuthorized`, which reports and writes nothing. Every settlement `execute`
        // makes comes from the driver holding this attempt's own `SEND_AUTHORIZED`, which is its
        // exclusivity.
        //
        // Send authorization is committed immediately before the socket, on the very next line:
        // nothing may sit between the authorization and the dispatch it authorizes.
        //
        // BASIS-6 here: `ensure_prepared` verifies the observation against the frozen basis only for
        // a capture-on operation that captures on this pass. It does not observe a capture-off
        // operation (`journal_required = 0`, which has no journal row but must still reach this
        // check), nor re-observe one whose journal row exists. So the exposure key is derived from the
        // operation's admission-frozen basis inside the authorizing transaction, never from a
        // re-resolution (dispatch never re-resolves).
        match self.authorize_dispatch(&command.idempotency_key, &attempt_id, capture)? {
            DispatchAuthorization::Authorized => {}
            // The refusing transaction closed this operation (a sever's check, or the exposure check's
            // deterministic no-effect terminal). Answer what an identical replay reads through the truth
            // table, never `InProgress` for a row that is settled forever.
            DispatchAuthorization::Terminal(status) => {
                return not_dispatched(self.status_replay_outcome(&command.idempotency_key, &status));
            }
            // Superseded, and the operation is still open: do not touch the wire. In-flight is the
            // signal every park gives.
            DispatchAuthorization::Park => return Err(ExecuteError::InProgress),
        }
        // Dispatch with the admission-frozen basis (BASIS-6): the basis `record()` committed and
        // `authorize_send` derived the exposure key from, so the identity checked and the identity the
        // wire may touch are the same value, handed to the connector rather than re-resolved.
        //
        // A connector error is reconciled against the intent's durable lifecycle (ADR-P013 (b), shared
        // with `recover`): a deterministic failure dead-letters to `Failed` immediately; a transient
        // one charges the retry budget (this initial dispatch is attempt 1) and stays `Pending` for the
        // next sweep until the cap is exhausted. Either way the rejection is surfaced, never a silent
        // `Ok`; an identical replay of a dead-lettered intent returns `Err::Failed` via the truth table.
        //
        // The dispatch is `apply_witnessed`: `apply` plus what the route observed at effect
        // ([`EffectWitness`]; `None` on connectors that keep the trait default).
        let witness = match self.connector.apply_witnessed(command, &basis) {
            Ok(witness) => witness,
            Err(error) => {
                let settled = self
                    .reconcile_connector_failure(
                        &command.idempotency_key,
                        Some(&attempt_id),
                        &error,
                        // No pre-wire compare on this path (see the claim above): `superseded_pre_wire` is
                        // unreachable here and not consulted below.
                        None,
                    )
                    .map_err(ExecuteError::Log)?;
                // ...unless the chain's own answer outranks this failure: an adjudication landed mid-flight,
                // and either an accepted late ack says the opposite of what the provider just reported, or the
                // race left the historical axis unresolved. The ledger is the authority, and the caller gets
                // what an identical replay reads, through the same truth table.
                if let Some(history) = settled.outranked {
                    return Err(adjudicated_replay_outcome(history));
                }
                return Err(ExecuteError::Connector(error));
            }
        };
        // The success verdict: `ACK_APPLIED` and the `Applied` lifecycle in one write. The status is
        // not set on its own, since reporting an operation complete without the fact that justifies it
        // is the read-derived attribution the design forbids.
        let settled = self
            .settle_dispatch(
                &command.idempotency_key,
                &attempt_id,
                ConnectorVerdict::Applied,
                None,
            )
            .map_err(ExecuteError::Log)?;
        // Persist the witness the route answered after the settlement committed (see
        // [`CommandBus::persist_effect_witness_step`] for the error posture). On this path a failed
        // write is the applied result's witness outcome, never an error: the operation is `Applied`.
        let witness = match self.persist_effect_witness_step(&command.idempotency_key, &witness) {
            Ok(()) => WitnessRecord::Persisted,
            Err((failure, _store_error)) => WitnessRecord::WriteFailed(failure),
        };
        // The same outranked rule on the success side.
        if let Some(history) = settled.outranked {
            return Err(adjudicated_replay_outcome(history));
        }
        Ok(Executed { witness })
    }

    /// Persist a dispatch's [`EffectWitness`]; `execute` and the `recover` sweep both call it
    /// after their success settlement so the two cannot drift. `pre` is the operation's captured
    /// observe read ([`CapturedPreState::observed_label_vector`]); `None` when the operation owns
    /// no journal row or its read yielded no vector (the verdict is then NULL, never guessed). A
    /// witness with no vector is not written at all.
    ///
    /// **Error posture.** This runs after the dispatch succeeded and its settlement committed, so a
    /// failure is a store failure after an effect. It touches only the witness columns and never
    /// the lifecycle. Both callers answer it the same non-fatal way: the operation is durably
    /// applied, so the failure is named, as [`WitnessRecord::WriteFailed`] on `execute` and as a
    /// key in [`RecoverReport::witness_write_failed`] on `recover`. It must not abort the whole
    /// sweep (stranding every later intent's provenance behind one witness-write failure) or
    /// discard the undo key and invite a second key for an applied operation. Pinned by
    /// `s1_a_witness_write_failure_after_the_effect_is_named_on_execute_and_on_recover_and_the_status_stays_applied`.
    ///
    /// The witness is persisted before the `outranked` check on purpose: the witness columns are
    /// the route's answer, not a status. An operation whose settlement was outranked by a
    /// mid-flight adjudication still carries what the wire returned, and readers derive status from
    /// the fact chain, never from the presence of an effect vector. Pinned by
    /// `a_late_ack_refused_as_contradiction_reports_the_chains_truth` (execute) and
    /// `s1_the_recovery_door_persists_the_witness_before_its_outranked_count` (recover).
    fn persist_effect_witness_step(
        &mut self,
        idempotency_key: &str,
        witness: &EffectWitness,
    ) -> Result<(), (WitnessWriteFailure, LogError)> {
        if witness.provider_label_vector.is_none() {
            return Ok(());
        }
        let pre = self
            .log
            .captured_pre_state(idempotency_key)
            .map_err(|e| (WitnessWriteFailure::PreStateRead, e))?
            .and_then(|captured| captured.observed_label_vector);
        self.log
            .record_effect_witness(idempotency_key, witness, pre.as_ref())
            .map_err(|e| (WitnessWriteFailure::WitnessWrite, e))
    }

    /// Admission-side basis resolution: where a connector-produced [`FrozenBasis`] becomes
    /// admissible, shared by [`CommandBus::execute`] and the deferred-undo compensation (its own
    /// admitted operation with its own freeze) so the two cannot drift.
    ///
    /// BASIS-2: a missing or invalid resolver basis refuses admission with a named retryable error,
    /// never a stale fallback. "Invalid" covers the resolver failing and the resolver succeeding
    /// with a basis that is not structurally a basis. `record()` commits whatever it is handed, so
    /// without this check a malformed basis (empty native key, so no tail-ordering key; zero atoms,
    /// so nothing to observe or restore) became durable JSON that failed only later, at PREPARE's
    /// re-parse or as open-time `FrozenBasisMissing` evidence, after the row was ordered against
    /// its peers. The structural rules come from the authority the storage round-trip uses
    /// ([`prestate::FrozenBasis::validate`], which `from_json` calls).
    ///
    /// Both halves surface as [`ExecuteError::AdmissionRefused`], not [`ExecuteError::Log`]. This
    /// runs ahead of `record()`, so a refusal means nothing durable was touched and the caller may
    /// re-submit; `Log` means "the store could not be trusted", which would wrongly tell the caller
    /// to stop retrying.
    ///
    /// That promise is checked. Between the caller's initial `get` and this resolution a peer can
    /// claim the key, and a refusal after that would be false. So a refusal re-reads the key, and
    /// if a row is now there the answer is that row's truth-table verdict ([`decision_outcome`]
    /// over [`classify`], as for the lost-claim race after `record()`). `AdmissionRefused`
    /// survives only when the key is still absent.
    fn resolve_admission_basis(&self, command: &Command) -> Result<AdmissionBasis, ExecuteError> {
        let refusal = match self.connector.resolve_basis(command) {
            Err(e) => ExecuteError::AdmissionRefused(format!("admission refused: {}", e.0)),
            Ok(basis) => match basis.validate_for_admission() {
                Ok(()) => return Ok(AdmissionBasis::Fresh(basis)),
                Err(e) => {
                    ExecuteError::AdmissionRefused(format!("admission refused: {e} (retryable)"))
                }
            },
        };
        // A failing store read is a genuine `Log` incident and outranks the refusal: we no longer
        // know whether anything durable exists.
        let now = self
            .log
            .get(&command.idempotency_key)
            .map_err(ExecuteError::Log)?;
        match now {
            None => Err(refusal),
            Some(_) => Ok(AdmissionBasis::RacedToExistingRow(
                // `Fresh` is unreachable (`now` is `Some`), but the fallback keeps the truth table's single
                // evaluation point here.
                decision_outcome(self.decide(now.as_ref(), command).map_err(ExecuteError::Log)?)
                    .unwrap_or(Err(ExecuteError::InProgress)),
            )),
        }
    }

    /// The dispatch-claim step every wire-bound dispatch passes before it may reach a connector
    /// socket, shared by `execute`, `recover`'s forward arm and `drive_undo_child` (like
    /// [`CommandBus::ensure_prepared`] and [`CommandBus::reconcile_connector_failure`]; three copies
    /// of an ownership rule is three rules).
    ///
    /// This closes the double-drive race: a second claim on a terminal attempt is refused, and no
    /// wire dispatch happens without an owned claim under the current epoch. `observed_attempts`
    /// is the dispatch episode the caller's read carried, so a driver acting on a stale read is
    /// distinguishable from one acting on a current one. See [`IntentLog::claim_attempt`] for the
    /// three compare halves and the residual.
    ///
    /// The claim is the ownership check only. Authorization is
    /// [`CommandBus::authorize_dispatch`], asked right after an `Owned` answer and right before the
    /// socket; it is what makes the residual on [`IntentLog::claim_attempt`] harmless: two drivers
    /// whose reads are both current both get `Owned`, and exactly one gets authorized.
    fn claim_dispatch(
        &mut self,
        idempotency_key: &str,
        observed_attempts: u32,
    ) -> Result<DispatchOwnership, ExecuteError> {
        let claim = AttemptClaim {
            // Every caller asks for ordinal 1, deliberately. A dispatcher does not choose which attempt
            // of an operation it is taking: the ordinal and its mandatory predecessor are properties of
            // the operation's own chain, and only the claim transaction can read that chain and append
            // against it atomically. The claim answers with the ordinal: 1 when there is no chain, n+1
            // (with the mandatory lineage) when the operation sits in its retry gap.
            ordinal: 1,
            predecessor: None,
            observed_attempts,
        };
        match self
            .log
            .claim_attempt(idempotency_key, &claim)
            .map_err(ExecuteError::Log)?
        {
            ClaimOutcome::Won {
                attempt_id,
                ordinal,
                observed_revision,
                class,
            } => Ok(DispatchOwnership::Owned {
                attempt_id,
                ordinal,
                observed_revision,
                class,
            }),
            // None of the three refusals may park blind. `AlreadyClaimed` shows why: the claim's first
            // compare half is "the operation is already terminal", so a peer that settled or a sever that
            // closed between the caller's read and this claim leaves a row closed forever. An unconditional
            // park would answer "in flight, recovery owns it" about a row that will never appear in
            // `unreconciled()` again and, in the sweep, raise a barrier that strands every later intent.
            //
            // All three arms re-read the row, as the authorization path does
            // ([`CommandBus::authorization_refusal`]): "not ours to claim" is about ownership, the
            // lifecycle is written by a different transaction, and which refusal asked is not an input.
            // Terminal: report what a replay reports; still active: park.
            ClaimOutcome::AlreadyClaimed
            // ISSUANCE_UNKNOWN: the operation is open and stays open until adjudication (no retry from
            // `ACK_AMBIGUOUS`/`ISSUANCE_UNKNOWN`, ever). A sweep parks rather than re-dispatching a
            // mutation that may have applied, and does not dead-letter it: a false `Failed` would claim
            // proof of no-effect that nobody has.
            | ClaimOutcome::AwaitingAdjudication
            // A sever landed between admission and dispatch. A dispatcher never terminalizes, but the
            // sever's own transaction may already have closed this operation (an active operation with no
            // live attempt completes `Severed` in that write), which is the terminal this re-read finds.
            | ClaimOutcome::EpochFenced => self.claim_refusal(idempotency_key),
            // The closed grammar refusing an ordinal-1 claim on a chainless attempt means the ledger is
            // not what this build wrote. Fail explicitly: a dispatcher that shrugs at a grammar refusal
            // dispatches unowned work.
            ClaimOutcome::RefusedByGrammar(refusal) => Err(ExecuteError::Log(LogError(format!(
                "dispatch claim for '{idempotency_key}' refused by the attempt grammar: {refusal}"
            )))),
        }
    }

    /// The send-authorization step: the last thing before a connector socket, shared by all
    /// three wire-bound entry points (like [`CommandBus::claim_dispatch`]).
    ///
    /// The commit-to-socket gap is irreducible: a crash between [`IntentLog::authorize_send`]'s
    /// commit and the connector's first byte leaves an authorized, possibly-unsent request (the
    /// two-generals problem), so the engine records `ISSUANCE_UNKNOWN` rather than claim a truth
    /// it cannot have. What this boundary does buy is that no new authorization can follow a
    /// sever: the transaction re-reads `control_epoch`, and SQLite's single writer linearizes it
    /// against the sever.
    ///
    /// The exposure key is derived inside the authorizing transaction from the operation's
    /// admission-frozen basis (the identity the wire may touch), never from a re-resolution or
    /// the `pre_state` row (a capture-off operation has none). What each caller guarantees at
    /// this point differs; see the three call sites.
    ///
    /// No refusal reaches the wire, but refusals leave the operation in different states, so
    /// every one, grammar refusals included, re-reads the row and returns a terminal as
    /// [`DispatchAuthorization::Terminal`]; the caller then answers what a replay answers rather
    /// than "in flight" about a row nothing will sweep again. Only an active operation parks.
    /// Grammar refusals mean "not ours to send", which is about attempt ownership and says
    /// nothing about the operation's lifecycle (different transactions write them). The
    /// reachable trace is `PostTerminalAppend`: a sever landing on our live, unauthorized claim
    /// closes the attempt `SEVERED_BEFORE_ISSUANCE` and the operation `Severed` together, and
    /// our check then finds that closure already written.
    fn authorize_dispatch(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        capture: CaptureBinding,
    ) -> Result<DispatchAuthorization, ExecuteError> {
        use crate::attempt::GrammarRefusal;
        // The total plan binding, stated from the row ([`CommandBus::plan_binding`]).
        let plan = self.plan_binding(idempotency_key)?;
        match self
            .log
            .authorize_send(idempotency_key, attempt_id, capture, plan)
            .map_err(ExecuteError::Log)?
        {
            SendAuthOutcome::Authorized { .. } => Ok(DispatchAuthorization::Authorized),
            // A sever linearized first. That transaction terminalized the attempt
            // `SEVERED_BEFORE_ISSUANCE` and its operation `Severed`; the dispatcher must not touch the
            // wire and reports the disposition that transaction wrote.
            SendAuthOutcome::EpochFenced => self.authorization_refusal(idempotency_key),
            // Exposure check: fail-closed, pre-wire, terminalized deterministically, except on the one
            // arm `authorize_send` names, where the refused attempt was already authorized and may have
            // touched the wire under an earlier episode: there the class is `ISSUED_OR_UNKNOWN`, no
            // terminal is written, and the operation stays active. The re-read tells the two apart.
            SendAuthOutcome::ExposureBlocked { .. } => self.authorization_refusal(idempotency_key),
            // The capture CAS refused: a peer's requalification re-prepared the journal row between this
            // driver's decision and this boundary, so the pre-state a later undo would restore is not the
            // one this dispatch was qualified against. Nothing was written or sent. "Not ours to send" is
            // about the capture and settles nothing about the operation's lifecycle, so the same re-read
            // applies.
            SendAuthOutcome::CaptureSuperseded { .. } => {
                self.authorization_refusal(idempotency_key)
            }
            // The three reachable refusals all mean "not ours to send":
            // - `DuplicateSendAuthorized`: another equally-current driver got the wire first (the
            //   residual [`IntentLog::claim_attempt`] names, closed here);
            // - `PostTerminalAppend`: the attempt settled under this driver;
            // - `SeveredAfterSendAuthorization`: a sever landed on an already-authorized attempt, so the
            //   check could not terminalize it `SEVERED_BEFORE_ISSUANCE`; non-issuance cannot be proven
            //   and the member stays `ISSUED_OR_UNKNOWN` for the sever to classify.
            // None is a store incident; reporting a normal race as one would be a dispatcher raising an
            // alarm about another dispatcher doing its job.
            //
            // None may park blind either: "not ours to send" is about the attempt and settles nothing
            // about the operation, so the re-read is owed. `PostTerminalAppend` shows why: a sever
            // landing on our live, unauthorized claim closes the attempt and the operation in one
            // transaction, and an unconditional park would then say "in flight" about a row nothing will
            // sweep again.
            SendAuthOutcome::RefusedByGrammar(
                GrammarRefusal::DuplicateSendAuthorized
                | GrammarRefusal::PostTerminalAppend { .. }
                | GrammarRefusal::SeveredAfterSendAuthorization,
            ) => self.authorization_refusal(idempotency_key),
            // Anything else means the ledger is not what this build wrote. Fail explicitly: a
            // dispatcher that shrugs at a grammar refusal dispatches unauthorized work.
            SendAuthOutcome::RefusedByGrammar(refusal) => Err(ExecuteError::Log(LogError(format!(
                "send authorization for '{idempotency_key}' refused by the attempt grammar: \
                 {refusal}"
            )))),
            // The plan arm refused. The same re-read applies: a terminal refusal closed the row in the
            // refusing transaction, so the caller answers what a replay reads; a held refusal (or a
            // refusal of an already-authorized attempt) left it open, and it parks.
            SendAuthOutcome::PlanRefused(_) => self.authorization_refusal(idempotency_key),
        }
    }

    /// The [`crate::plan::PlanBinding`] this bus states for an operation at the send check:
    /// `Plain` for a row with no plan link (and for a key with no row; the store answers that).
    /// For a plan child, the grant ratchet's verdict on the plan's `(grant_generation,
    /// provider_principal)` ([`GrantRatchet::admits`]) plus the plan account's key derived from the
    /// root key. A bus with no root key cannot bind a plan child: a [`LogError`] names it before
    /// anything is sent.
    fn plan_binding(&self, idempotency_key: &str) -> Result<crate::plan::PlanBinding, ExecuteError> {
        let link = self
            .log
            .get(idempotency_key)
            .map_err(ExecuteError::Log)?
            .and_then(|intent| intent.command.plan_child);
        let Some(link) = link else {
            return Ok(crate::plan::PlanBinding::Plain);
        };
        let plan = self.log.plan(&link.plan_id).map_err(ExecuteError::Log)?.ok_or_else(|| {
            ExecuteError::Log(LogError(format!("plan '{}' vanished under its child '{idempotency_key}'", link.plan_id.0)))
        })?;
        // Convert the ratchet's in-process `GrantRefusal` (which names both provider principals and
        // the ratchet's own sentence) to the content-free `GrantDenial` the check, the record and the
        // caller see; the principals and the sentence stop here.
        let grant = match self.grant_ratchet.admits(plan.grant_generation, &plan.provider_principal) {
            Ok(()) => crate::plan::GrantVerdict::Admitted,
            Err(GrantRefusal::Retired { generation, high_water }) => {
                crate::plan::GrantVerdict::Refused(crate::plan::GrantDenial::Retired { generation, high_water })
            }
            Err(GrantRefusal::PrincipalMismatch { .. }) => crate::plan::GrantVerdict::Refused(crate::plan::GrantDenial::PrincipalMismatch),
            Err(GrantRefusal::Unavailable(_)) => crate::plan::GrantVerdict::Refused(crate::plan::GrantDenial::Unavailable),
        };
        let root = self.root_key.as_ref().ok_or_else(|| {
            ExecuteError::Log(LogError(format!("no root key on this bus: plan child '{idempotency_key}' cannot be bound")))
        })?;
        let account_key = crate::commitment::derive_account_key(root, &plan.account)
            .map_err(|e| ExecuteError::Log(LogError(format!("plan child '{idempotency_key}': account key: {e}"))))?;
        Ok(crate::plan::PlanBinding::Child { grant, account_key })
    }

    /// The disposition an authorization refusal leaves behind, read from the row. Every refusal
    /// owes the same answer: is the operation closed (report it as a replay would) or merely
    /// superseded (park, since recovery owns it)? Which refusal asked is not an input: a refusal
    /// that terminalizes and one that lost a race can both find a closed row. The read is
    /// [`CommandBus::terminal_disposition`].
    fn authorization_refusal(
        &mut self,
        idempotency_key: &str,
    ) -> Result<DispatchAuthorization, ExecuteError> {
        Ok(match self.terminal_disposition(idempotency_key)? {
            Some(status) => DispatchAuthorization::Terminal(status),
            // Still open: the already-authorized exposure arm (no terminal, since non-issuance cannot
            // be proven), the losing racer of a live peer (`DuplicateSendAuthorized`) whose winner has not
            // settled, and the loser of the capture CAS. A missing row is not this path's to adjudicate:
            // nothing reached the wire, so in-flight is the signal.
            None => DispatchAuthorization::Park,
        })
    }

    /// The plain park answer, terminal-aware, for callers returning `Result<(), ExecuteError>`:
    /// terminal gives what an identical replay of this key answers; still active gives `InProgress`.
    fn park_or_replay(&mut self, idempotency_key: &str) -> Result<(), ExecuteError> {
        match self.terminal_disposition(idempotency_key)? {
            Some(status) => self.status_replay_outcome(idempotency_key, &status),
            None => Err(ExecuteError::InProgress),
        }
    }

    /// The undo drive's terminal-aware park answer. Every lost pre-wire compare in the undo
    /// family (the conflict settlement, both verification settlements, the crash-convergence
    /// settlement and the failure boundary) used to answer `InProgress` on the reasoning that a
    /// peer owns the attempt. That is true of the attempt and silent about the operation: the peer
    /// may have settled it, and a terminal child never appears in `unreconciled()` again, so
    /// nothing would revise the answer.
    ///
    /// So the row is asked, and a closed child gets what a replay of its key gets: an
    /// `Ok`-replaying terminal meaning the verification already happened (the routing of
    /// [`CommandBus::undo_settlement_outranks`]'s preemption arm).
    fn undo_drive_park(&mut self, child_key: &str) -> Result<UndoDriveOutcome, ExecuteError> {
        if let Some(status) = self.terminal_disposition(child_key)? {
            self.status_replay_outcome(child_key, &status)?;
            return Ok(UndoDriveOutcome::Verified);
        }
        Err(ExecuteError::InProgress)
    }

    /// The claim path's twin of [`CommandBus::authorization_refusal`]: a refusal settles nothing
    /// about the operation, so the row is asked. The two differ only in the type their callers
    /// switch on.
    fn claim_refusal(
        &mut self,
        idempotency_key: &str,
    ) -> Result<DispatchOwnership, ExecuteError> {
        Ok(match self.terminal_disposition(idempotency_key)? {
            Some(status) => DispatchOwnership::Terminal(status),
            None => DispatchOwnership::Park,
        })
    }

    /// The park-or-replay read: is this operation closed (report it as a replay would) or merely
    /// superseded (park, since recovery owns it)? `Some(status)` means terminal.
    ///
    /// Every site that would answer "in flight, recovery owns it" off a refusal (the claim, the
    /// authorization, the undo drive's epoch check, every lost pre-wire compare, the sweep's
    /// barrier decision) asks this, so a new park site inherits the rule.
    ///
    /// The read is a plain [`IntentLog::get`] and needs no guard: it decides no write, and a
    /// terminal is never rewritten, so a status seen terminal is terminal for good. A missing row
    /// answers `None` (park): nothing reached the wire, and inventing a disposition is not this
    /// read's job.
    fn terminal_disposition(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<IntentStatus>, ExecuteError> {
        Ok(self
            .log
            .get(idempotency_key)
            .map_err(ExecuteError::Log)?
            .map(|intent| intent.status)
            .filter(|status| status.is_terminal()))
    }

    /// The retry-requalification gate: the capture table read for a forward retry, run at the
    /// retry's head moment, after the claim and immediately before the send-authorization check.
    ///
    /// **What it closes.** The provider can move during the retry gap: `SetFlag(true)` capturing
    /// `false`, failing at connect, another client setting `true`, the retry no-opping, and undo
    /// later restoring a stale `false` breaks the no-op guarantee. The never-re-capture rule makes
    /// the gap dangerous: the captured `P` is frozen at the first pass, and every later attempt
    /// dispatches against a world that may have moved.
    ///
    /// **Where it runs.** Its one caller is [`CommandBus::recover`]'s forward arm, the engine's only
    /// forward-retry re-entry point. [`CommandBus::execute`] reaches its claim only on
    /// `Claim::Inserted` with an empty chain, so it always answers ordinal 1 and there is no retry
    /// to qualify. [`CommandBus::drive_undo_child`] also retries and requalifies on every drive,
    /// but through the undo reading of the same table (W-DEFERRED-STALE), which is not this gate's
    /// to duplicate.
    ///
    /// **Capture-off is a different obligation, not an exemption.** Such an operation has no `P` to
    /// compare, so its retry re-verifies only the frozen native basis (BASIS-6) and re-dispatches.
    /// No row is minted.
    ///
    /// The provider read happens outside any write transaction (BASIS-2), and a read failure is
    /// returned un-reconciled: the caller owns the reconcile boundary, so the budget is never
    /// charged twice.
    ///
    /// **This gate is pre-wire, and its one settlement says so.** It runs after the claim and
    /// before the send-authorization check, so the attempt may be one this driver re-entered and
    /// shares with an equally-current peer that is free to authorize it. The `ExternallySatisfied`
    /// terminal below therefore compare-and-appends against `observed_revision`: if the peer's
    /// `SEND_AUTHORIZED` landed, the settlement refuses instead of closing an attempt on the wire.
    fn requalify_retry_at_head(
        &mut self,
        intent: &Intent,
        attempt_id: &str,
        observed_revision: u64,
    ) -> Result<RetryGate, ExecuteError> {
        let key = intent.command.idempotency_key.clone();
        let Some(basis) = intent.frozen_basis.clone() else {
            // A legacy pre-stage-2 row has no frozen identity or target vector to compare. Fail closed:
            // the gate cannot qualify the retry. (The row is already an open-time integrity finding,
            // `FrozenBasisMissing`.)
            return Ok(RetryGate::Park);
        };
        // Capture-off: BASIS-6 only. Observe `C` on the frozen identity (dispatch never re-resolves)
        // and check the provider answered for it. A rebind is a deterministic no-effect refusal
        // decided on a local comparison.
        if !intent.journal_required {
            let obs = match self.connector.observe(&intent.command, &basis) {
                Ok(obs) => obs,
                Err(error) => return Ok(RetryGate::Failed(error)),
            };
            if obs.native_resource_key != basis.native_resource_key
                || !basis.touched_atoms.keys().all(|k| obs.atoms.contains_key(k))
            {
                return Ok(RetryGate::Failed(ConnectorError::deterministic_basis_rebound()));
            }
            // No row is allowed for such an operation, so its CAS token asserts there is none.
            return Ok(RetryGate::Proceed {
                capture: CaptureBinding::NoJournalRow,
            });
        }
        // Capture-on.
        if basis.atom_targets.is_empty() {
            // A stage-2 basis carries no target vector, so the table is undecidable. Fail closed, as
            // the undo path does for such a row.
            return Ok(RetryGate::Park);
        }
        // The value and its generation in one read: the decision is about this capture, and the
        // generation binds the authorization that follows to it.
        let captured = self
            .log
            .captured_pre_state(&key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| {
                // `journal_required=1` with no row on an operation that already dispatched: an integrity
                // failure (`JournalGapUnexplained`), never a benign re-dispatch.
                ExecuteError::Log(LogError(format!(
                    "retry requalification: journal-required operation '{key}' has no captured \
                     row (JournalGapUnexplained)"
                )))
            })?;
        // Every capture-on retry observes; there is no `P == A` shortcut. Such a shortcut would
        // skip the provider read on the argument that undo of the operation is killed anyway. But the
        // retry gap is where the world moves: another actor sets the atom off `A`, the retry then
        // dispatches blind and makes a real change, and undo stays killed by the stale `P == A`, so
        // the engine's change over that actor's state is unrestorable. Protection is the check order
        // of the retry table (`C == P` first, `crate::prestate::requalify_retry`): an unchanged world
        // still proceeds on the captured row without re-capture, because it was observed unchanged.
        let obs = match self.connector.observe(&intent.command, &basis) {
            Ok(obs) => obs,
            Err(error) => return Ok(RetryGate::Failed(error)),
        };
        // BASIS-6 at observation, as above.
        if obs.native_resource_key != basis.native_resource_key
            || !basis.touched_atoms.keys().all(|k| obs.atoms.contains_key(k))
        {
            return Ok(RetryGate::Failed(ConnectorError::deterministic_basis_rebound()));
        }
        let c: std::collections::BTreeMap<String, bool> = basis
            .touched_atoms
            .keys()
            .map(|k| (k.clone(), obs.atoms[k]))
            .collect();
        match crate::prestate::requalify_retry(&captured.atoms, &basis.atom_targets, &c) {
            // `C == P`: the capture still describes the world. Proceed on the existing row (no
            // re-capture) bound to the generation this decision read; a peer's replace afterwards makes
            // the statement false.
            crate::prestate::RetryRequalifyDecision::ProceedOnCapturedRow => {
                Ok(RetryGate::Proceed {
                    capture: CaptureBinding::Generation(captured.capture_generation),
                })
            }
            // `C == A`: the target already holds. The attempt's proven-no-wire terminal and the
            // operation's `EXTERNALLY_SATISFIED` lifecycle land in one transaction.
            crate::prestate::RetryRequalifyDecision::ExternallySatisfied => {
                // Pre-wire, so it compare-and-appends. A superseded answer means a peer holding the same
                // re-entered attempt authorized it while this gate read the provider: the attempt is not ours
                // to close, nothing of ours reached a wire, so park silently like any lost race.
                //
                // `outranked` cannot occur here: it exists only for a post-adjudication refusal, adjudication
                // is legal only on a send-authorized attempt, and this gate runs before the send
                // authorization on an attempt whose chain is one fresh `CLAIM`. `terminal` is not read: the
                // lifecycle just written is `EXTERNALLY_SATISFIED`, and `Closed` says so.
                let settled = self
                    .settle_dispatch(
                        &key,
                        attempt_id,
                        ConnectorVerdict::ExternallySatisfied,
                        Some(observed_revision),
                    )
                    .map_err(ExecuteError::Log)?;
                if settled.superseded_pre_wire {
                    Ok(RetryGate::Park)
                } else {
                    Ok(RetryGate::Closed)
                }
            }
            // Neither: re-prepare, the one narrow exception to insert-or-nothing PREPARE. The legality
            // condition (every attempt provably wire-free) is checked inside that transaction.
            crate::prestate::RetryRequalifyDecision::RePrepare => {
                let fresh = crate::prestate::journal_row_from_observation(&obs, &basis);
                match self
                    .log
                    .replace_journal_row(&key, &fresh)
                    .map_err(ExecuteError::Log)?
                {
                    // The generation the replace just minted is this decision's binding; the authorization may
                    // spend it only if nobody re-prepared again meanwhile.
                    JournalReplaceOutcome::Replaced { generation } => Ok(RetryGate::Proceed {
                        capture: CaptureBinding::Generation(generation),
                    }),
                    // Fail closed: an attempt may already have had an effect, so a fresh capture would be the
                    // post-effect observation the design forbids, and the stale one is no better. Park.
                    JournalReplaceOutcome::RefusedAttemptNotProvenNoWire { .. } => {
                        Ok(RetryGate::Park)
                    }
                    // Unreachable: `captured_pre_state` returned a row a moment ago and the engine has no
                    // deleter. Fail explicitly rather than dispatch against a vanished capture.
                    JournalReplaceOutcome::NoRowToReplace => Err(ExecuteError::Log(LogError(
                        format!("retry requalification: the journal row of '{key}' vanished"),
                    ))),
                }
            }
        }
    }

    /// The capture pipeline (observe, BASIS-6 verify, PREPARE), shared by
    /// [`CommandBus::execute`] and [`CommandBus::recover`] so the two cannot drift. Returns whether
    /// the caller may dispatch ([`PipelineVerdict::Proceed`]) or must leave the intent parked
    /// ([`PipelineVerdict::Park`]).
    ///
    /// A connector failure is returned un-reconciled: the caller owns the single reconcile
    /// boundary, so the retry budget is never charged twice for one read.
    fn ensure_prepared(&mut self, command: &Command) -> Result<PipelineVerdict, ExecuteError> {
        // Re-read the intent for its provenance (`journal_required`, bound at admission). `kind` is
        // not exposed on `Intent`; the forward discriminator is the command's compensation link, the
        // fact the admission statement derives `kind` from.
        let intent = self
            .log
            .get(&command.idempotency_key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| ExecuteError::Log(LogError("claimed intent vanished".into())))?;
        if !intent.journal_required || command.compensates.is_some() {
            // No row is owed, and that is the CAS token this dispatch carries: a capture-off operation is
            // forbidden a row, and an undo child's `P` is its parent's row, which cannot move under it
            // (the replace path refuses unless every attempt is provably wire-free, and an undoable
            // parent holds an `ACK_APPLIED`).
            return Ok(PipelineVerdict::Proceed {
                capture: CaptureBinding::NoJournalRow,
            });
        }
        // Never re-capture. The journal row's existence is the phase, so an intent that
        // crashed between prepare and dispatch resumes to the wire; re-observing could read
        // post-effect state and poison no-op detection at undo time.
        if self
            .log
            .prepared(&command.idempotency_key)
            .map_err(ExecuteError::Log)?
        {
            return Ok(PipelineVerdict::Proceed {
                capture: self.capture_binding_of(&command.idempotency_key)?,
            });
        }
        let basis = intent.frozen_basis.as_ref().ok_or_else(|| {
            ExecuteError::Log(LogError(
                "journal-required intent has no frozen_basis".into(),
            ))
        })?;
        // Observe: a provider read outside any write transaction (BASIS-2).
        let obs = self
            .connector
            .observe(command, basis)
            .map_err(ExecuteError::Connector)?;
        // BASIS-6 at observation: the answer must be for the frozen identity and cover the frozen
        // atoms. A rebind is a deterministic no-effect terminal, proven no-wire since it is decided
        // locally before any mutation is built. It reaches the reconcile boundary with no attempt:
        // this pipeline runs before the forward dispatch claim.
        if obs.native_resource_key != basis.native_resource_key
            || !basis.touched_atoms.keys().all(|k| obs.atoms.contains_key(k))
        {
            return Err(ExecuteError::Connector(
                ConnectorError::deterministic_basis_rebound(),
            ));
        }
        let journal = crate::prestate::journal_row_from_observation(&obs, basis);
        use crate::prestate::PrepareOutcome;
        match self
            .log
            .prepare(&command.idempotency_key, &journal)
            .map_err(ExecuteError::Log)?
        {
            PrepareOutcome::Prepared | PrepareOutcome::AlreadyPrepared => {
                Ok(PipelineVerdict::Proceed {
                    capture: self.capture_binding_of(&command.idempotency_key)?,
                })
            }
            // Park-over-terminal cannot happen here. Both arms answer from a transaction that already
            // passed the pre-dispatch guard: `prepare` decides it before the epoch check or the head
            // predicate, and neither answer falls through to them (a terminal row leaves as `Closed`,
            // and the only other non-pre-dispatch phase leaves as a `LogError`). So the row was
            // `Pending`/`EvidenceSnapshotWritten` in that transaction (`IntentStatus::is_pre_dispatch`)
            // and "in flight, recovery owns it" is true of it.
            PrepareOutcome::NotAtHead | PrepareOutcome::EpochFenced => Ok(PipelineVerdict::Park),
            // The park's twin: the row is closed (a sever, or a peer's settlement, inside the
            // provider-read window this pipeline opens). Hand the disposition up so the caller reports
            // what an identical replay reports.
            PrepareOutcome::Closed(status) => Ok(PipelineVerdict::Closed(status)),
        }
    }

    /// The CAS token for an operation whose journal row this driver did not just write, read
    /// back from the store. `Generation(g)` when a row exists, `NoJournalRow` otherwise. It is a
    /// read and can go stale in the caller's hand; [`IntentLog::authorize_send`]'s compare turns
    /// that staleness into a refusal instead of a dispatch.
    fn capture_binding_of(&self, idempotency_key: &str) -> Result<CaptureBinding, ExecuteError> {
        Ok(self
            .log
            .captured_pre_state(idempotency_key)
            .map_err(ExecuteError::Log)?
            .map(|captured| CaptureBinding::Generation(captured.capture_generation))
            .unwrap_or(CaptureBinding::NoJournalRow))
    }

    /// Undo a previously applied forward command by restoring its captured pre-state. No
    /// user-facing undo dispatches a blind inverse.
    ///
    /// The undo is an intent row of its own (`kind='undo'`, keyed by the crate-private
    /// `compensation_key` over the parent's opaque `intent_id` in the reserved `\u{1}` namespace,
    /// with its own frozen basis), admitted through the same ADR-P013 classifier as every
    /// operation and driven through `drive_undo_child`, shared with [`CommandBus::recover`]: the
    /// no-op kill (`P == A`, from the journal row and the frozen target vector), epoch and
    /// basis-match checks, observe `C`, the undo requalification table, then
    /// [`Connector::restore`] writing the captured `P` as a native delta.
    ///
    /// The parent flips `Undone` only at verification (restore verified, or no-op verified), never
    /// at scheduling: a deferred undo leaves the parent `Applied` and signals `InProgress`
    /// ("undoing" is a derived presentation, not a stored status). Unavailability is typed
    /// ([`ExecuteError::UndoUnavailable`]), never a blind-inverse fallback.
    pub fn undo(&mut self, idempotency_key: &str) -> Result<(), ExecuteError> {
        let parent = match self.log.get(idempotency_key).map_err(ExecuteError::Log)? {
            Some(parent) => parent,
            // An unknown key has nothing to undo: a no-op.
            None => return Ok(()),
        };
        // Only forward parents are undoable. An undo child (reserved-namespace key, carries the
        // compensation link) is itself an undo; undoing it would redo the original while the original
        // stays `Undone`. Refused as a no-op `Ok`.
        if parent.command.compensates.is_some() {
            return Ok(());
        }
        // Lifecycle check; exhaustive so a new status must take a position.
        let parent = match parent.status {
            IntentStatus::Applied => parent,
            // Not undoable yet: the forward effect is not established.
            IntentStatus::Pending | IntentStatus::EvidenceSnapshotWritten => {
                return Err(ExecuteError::InProgress)
            }
            // A dead-lettered intent is not a successful no-op; surface the dead-letter replay signal,
            // uniform with `execute`'s `Failed` answer.
            IntentStatus::Failed => return Err(ExecuteError::Failed),
            // Already undone: an idempotent replay, unless this `Undone` is the pre-stage-3
            // flip-at-scheduling state. Opening a store does not run `recover`, so a caller can reach
            // here first on a legacy store whose compensation is still live under the old key shape; a
            // bare `Ok` would report an unproven success while the provider may still hold the forward
            // state. If the pair maps, the parent is back at `Applied` and we continue as a fresh undo;
            // otherwise it is a genuine verified undo and the replay is `Ok`.
            IntentStatus::Undone => {
                if self
                    .map_legacy_deferred_child(idempotency_key)
                    .map_err(ExecuteError::Log)?
                    .is_none()
                {
                    return Ok(());
                }
                // Re-read: the mapping just moved this row back to `Applied`, and the checks below must see
                // the row as it is.
                self.log
                    .get(idempotency_key)
                    .map_err(ExecuteError::Log)?
                    .ok_or_else(|| ExecuteError::Log(LogError("undo parent vanished".into())))?
            }
            // Legacy pre-stage-3 rows only; current code never writes this status. Whether that old
            // blind inverse applied is unknowable, so `recover` maps such rows back to the last verified
            // truth and the undo may then be re-offered here.
            IntentStatus::Undoing => return Err(ExecuteError::InProgress),
            // A severed operation has no verified applied state to restore: not undo-eligible.
            IntentStatus::Severed => {
                return Err(ExecuteError::UndoUnavailable(
                    prestate::UndoUnavailableReason::Severed,
                ))
            }
            // In-place adjudication closed the operational axis: not undo-eligible by policy however
            // the historical axis later resolves.
            IntentStatus::Adjudicated => {
                return Err(ExecuteError::UndoUnavailable(
                    prestate::UndoUnavailableReason::Adjudicated,
                ))
            }
            // The retry-requalification no-op terminal: another actor already produced the forward
            // target, and a stale captured `P` must never reverse that change. Not undo-eligible.
            IntentStatus::ExternallySatisfied => {
                return Err(ExecuteError::UndoUnavailable(
                    prestate::UndoUnavailableReason::ExternallySatisfied,
                ))
            }
        };

        // One store read (`undo_context`, which also advances the sticky time high-water) feeds the
        // child lookup (it carries the parent's opaque `intent_id`) and, if no child exists, the
        // eligibility derivation below.
        let ctx = self
            .log
            .undo_context(idempotency_key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| ExecuteError::Log(LogError("undo parent vanished".into())))?;
        // An existing durable child outranks fresh eligibility. The child is idempotent by key and
        // answers the replay contract: verified gives `Ok`; terminally failed gives `Err` (no
        // re-undo; the remedy is a new forward action); non-terminal gives `InProgress`, since
        // recovery owns in-flight children (never a second child or a second driver; see
        // `existing_undo_child_verdict`).
        //
        // This runs before the eligibility derivation because that gates admission, and an existing
        // child admits nothing. In the other order, an undo admitted inside the offer window and
        // still deferred behind a predecessor would replay `UndoUnavailable(Expired)` once the offer
        // lapsed while `recover` kept driving the same child to a real restore.
        let child_key = undo_child_key(&ctx.parent_intent_id);
        if let Some(child) = self.log.get(&child_key).map_err(ExecuteError::Log)? {
            return self.existing_undo_child_verdict(&child);
        }
        // Eligibility: the admission check, reached only when no child exists. Every unavailability
        // is a named reason, with no fallback that guesses an inverse. The forward target vector `A`
        // is what the requalification table decides against; a pre-stage-3 row carries none and is
        // answered `PredatesSubstrate`.
        let has_targets = parent
            .frozen_basis
            .as_ref()
            .is_some_and(|b| !b.atom_targets.is_empty());
        let journal_view = ctx.journal.as_ref().map(|j| prestate::CapturedJournalView {
            p: j.p.clone(),
            undo_offer_until: j.undo_offer_until.clone(),
        });
        let p = match prestate::derive_undo_eligibility(
            parent.journal_required,
            has_targets,
            journal_view,
            ctx.tombstoned,
            &ctx.effective_now,
        ) {
            prestate::UndoEligibility::Unavailable(reason) => {
                return Err(ExecuteError::UndoUnavailable(reason));
            }
            // `P` is re-read inside the drive, but is also the left half of the no-op decision below.
            prestate::UndoEligibility::Eligible { p } => p,
        };
        // The no-op kill runs before any resolution. `P == A` is decided from the row alone: `P` is
        // the journal capture just read, `A` the parent's frozen target vector. Running it after
        // `admit_undo_child` made a local truth depend on a fresh resolver call that can refuse (an
        // unresolvable JMAP role mailbox, an absent state cursor), so a resolver outage failed an
        // undo the parent row alone proves dispatches nothing. Eligibility guarantees the basis; the
        // `if let` keeps that total.
        if let Some(parent_basis) = parent.frozen_basis.clone() {
            if prestate::noop_kill(&p, &parent_basis.atom_targets) {
                return match self.admit_noop_undo_child(&parent, &child_key, &parent_basis)? {
                    UndoChildAdmission::Inserted(child) => {
                        // The same tail-ordering check as the dispatching path
                        // ([`CommandBus::drive_undo_child_at_head`]): a live same-resource predecessor means
                        // `recover` sequences it, the child stays `Pending`, and the drive's no-op arm answers at its
                        // head moment (identically, since `P` and `A` are frozen). A deferral is `InProgress`, never
                        // a false `Ok`, and is terminal-aware: a sever landing on the child just inserted closes it.
                        if self.has_pending_same_resource_predecessor(&child.command)? {
                            return self.park_or_replay(&child.command.idempotency_key);
                        }
                        self.verify_undo(idempotency_key, &child, None, None).map(|_| ())
                    }
                    // A peer won the claim inside the window: the row is the answer, and the drive is the
                    // peer's.
                    UndoChildAdmission::Existing(child) => {
                        self.existing_undo_child_verdict(&child)
                    }
                };
            }
        }
        // Ownership, as in `execute`: only the caller whose admission inserted the child drives it
        // synchronously. A peer that won the claim owns its drive; this caller reads the row's verdict.
        match self.admit_undo_child(&parent, &child_key)? {
            UndoChildAdmission::Inserted(child) => self.drive_undo_child_at_head(&child),
            UndoChildAdmission::Existing(child) => self.existing_undo_child_verdict(&child),
        }
    }

    /// Derive the [`UndoPresentation`] for a forward intent (by user key), the read-time
    /// projection that replaces the stored `Undoing` status, plus its [`RestorationVerdict`] from
    /// the persisted effect witness ([`UndoPresentationRead`]). `Ok(None)` means no such intent.
    ///
    /// Presentation only: no ordering, capacity, head or recovery decision may consume it.
    /// `Undoing` here means a child is admitted and not yet terminal, which the stored lifecycle
    /// must not claim (the parent stays `Applied` until verification). The reads are `&mut` because
    /// [`IntentLog::undo_context`] advances the sticky time high-water; the projection uses it only
    /// for the parent's opaque `intent_id`, from which the child's key is derived.
    pub fn undo_presentation(
        &mut self,
        idempotency_key: &str,
    ) -> Result<Option<UndoPresentationRead>, ExecuteError> {
        let Some(parent) = self.log.get(idempotency_key).map_err(ExecuteError::Log)? else {
            return Ok(None);
        };
        // The restoration verdict: the parent's effect witness (`IntentLog::effect_witness`), read
        // beside the lifecycle reads below; `None` unless the forward effect landed.
        let restoration = self
            .restoration_of(idempotency_key, &parent.status)
            .map_err(ExecuteError::Log)?;
        let presentation = 'presentation: {
            // The retry-requalification terminal has a reason that a `None` answer would hide. It is
            // checked first because such an operation has no undo child and never will.
            if parent.status == IntentStatus::ExternallySatisfied {
                break 'presentation UndoPresentation::ExternallySatisfied;
            }
            if parent.status == IntentStatus::Undone {
                // ...unless this `Undone` is the pre-stage-3 flip-at-scheduling state with its compensation
                // still live. A parent plus an active child is `Undoing`, so showing "done" over a pending
                // legacy child would be false. Display only: the mapping belongs to undo/recover; a read
                // API mutates nothing.
                break 'presentation match self
                    .legacy_deferred_child(idempotency_key)
                    .map_err(ExecuteError::Log)?
                {
                    Some(_) => UndoPresentation::Undoing,
                    None => UndoPresentation::Undone,
                };
            }
            let ctx = self
                .log
                .undo_context(idempotency_key)
                .map_err(ExecuteError::Log)?
                .ok_or_else(|| ExecuteError::Log(LogError("presentation parent vanished".into())))?;
            let child_key = undo_child_key(&ctx.parent_intent_id);
            let child = self.log.get(&child_key).map_err(ExecuteError::Log)?;
            // The child's historical axis, read only when the child is adjudicated.
            let child_history = match child.as_ref().map(|child| &child.status) {
                Some(IntentStatus::Adjudicated) => self
                    .log
                    .adjudicated_history(&child_key)
                    .map_err(ExecuteError::Log)?,
                _ => AdjudicatedHistory::Unresolved,
            };
            match (parent.status, child.map(|child| child.status)) {
                (IntentStatus::Applied, Some(IntentStatus::Failed)) => {
                    UndoPresentation::AppliedUndoFailed
                }
                // The child's unknown was closed by decision, not evidence, so this arm asks the historical
                // axis before it speaks (answering `AppliedUndoUnresolved` forever would ignore a late ack
                // that proved what happened).
                (IntentStatus::Applied, Some(IntentStatus::Adjudicated)) => match child_history {
                    // Still nobody's knowledge: the message is as it was, and one restore may or may not have
                    // landed.
                    AdjudicatedHistory::Unresolved => UndoPresentation::AppliedUndoUnresolved,
                    // `LATE_ACK_REFUSED_NO_EFFECT`: the restore definitively did not happen and the parent is
                    // `Applied`, which is what `AppliedUndoFailed` already means. A separate variant would split
                    // one user-visible truth across two values; which path proved it is an audit question
                    // answered by the adjudication record.
                    AdjudicatedHistory::ResolvedRefusedNoEffect => UndoPresentation::AppliedUndoFailed,
                    // `LATE_ACK_APPLIED`: the restore provably landed. Normally unreachable, since that late-ack
                    // transaction flips the parent to `Undone` (answered above); this covers a parent some other
                    // path had already moved. The historical axis is evidence, so follow it.
                    AdjudicatedHistory::ResolvedApplied => UndoPresentation::Undone,
                },
                // The undo child's operation was closed by a sever, not a provider verdict. Surface it
                // distinctly; `None` would read as "no undo was ever attempted".
                (IntentStatus::Applied, Some(IntentStatus::Severed)) => {
                    UndoPresentation::AppliedUndoSevered
                }
                // Non-terminal per [`IntentStatus::is_terminal`], never a hand-enumerated variant list.
                (IntentStatus::Applied, Some(status)) if !status.is_terminal() => {
                    UndoPresentation::Undoing
                }
                _ => UndoPresentation::None,
            }
        };
        Ok(Some(UndoPresentationRead {
            presentation,
            restoration,
        }))
    }

    /// The [`RestorationVerdict`] of the operation under this key, as carried by
    /// [`CommandBus::undo_presentation`] but readable alone by callers that owe the verdict right
    /// after a verb applied. A pure read (`&self`, no sticky-clock advance). `Ok(None)` means no
    /// such operation, or its forward effect has not landed.
    pub fn restoration(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<RestorationVerdict>, ExecuteError> {
        match self.log.get(idempotency_key).map_err(ExecuteError::Log)? {
            None => Ok(None),
            Some(intent) => self
                .restoration_of(idempotency_key, &intent.status)
                .map_err(ExecuteError::Log),
        }
    }

    /// When an operation carries a restoration verdict: its forward effect landed, so `Applied`
    /// or `Undone` (whether the message is as it was is what the witness qualifies). Every other
    /// status has nothing to qualify.
    fn restoration_of(
        &self,
        idempotency_key: &str,
        status: &IntentStatus,
    ) -> Result<Option<RestorationVerdict>, LogError> {
        match status {
            IntentStatus::Applied | IntentStatus::Undone => Ok(Some(RestorationVerdict::of(
                self.log.effect_witness(idempotency_key)?.as_ref(),
            ))),
            _ => Ok(None),
        }
    }

    /// Public passthrough onto [`IntentLog::unknown_review`], the unknown-age report, as a
    /// first-class [`CommandBus`] method like [`CommandBus::undo_presentation`]. A report only:
    /// nothing here adjudicates.
    pub fn unknown_review(
        &self,
        now_unix_secs: u64,
        review_after_seconds: u64,
    ) -> Result<UnknownReviewReport, LogError> {
        self.log.unknown_review(now_unix_secs, review_after_seconds)
    }

    /// Public passthrough onto [`IntentLog::exposure_obligation`]: an operator holding an
    /// [`ExecuteError::ExposureBlocked`] resolves the reference it carries here, without reaching
    /// through [`CommandBus::log`]. The error names a Photon-local row id so that it names no
    /// provider identifier, and an operator who cannot follow it would just have a different
    /// unanswerable refusal. A report only: nothing in the engine reads it.
    pub fn exposure_obligation(
        &self,
        obligation_id: &str,
    ) -> Result<Option<ExposureObligation>, LogError> {
        self.log.exposure_obligation(obligation_id)
    }

    /// Reconcile one connector failure against an intent's durable lifecycle (ADR-P013 (b)). The
    /// deterministic-vs-transient decision lives here and is used by `execute`, `undo` and
    /// `recover`, so no dispatch path can drift.
    ///
    /// - Deterministic (validation, permission, missing target): dead-letter to `Failed`
    ///   immediately; it never succeeds on retry and does not touch the retry budget.
    /// - Transient: charge the retry budget atomically; dead-letter only once [`RETRY_CAP`] is
    ///   exhausted.
    ///
    /// The boundary also appends the failure's verdict fact, in the same durable write as the
    /// lifecycle change, so attribution and lifecycle never disagree. The mapping itself is
    /// [`IntentLog::settle_attempt`]'s table (it needs the attempt's facts, which only that
    /// transaction can read).
    ///
    /// `attempt` is `None` for a failure raised before any attempt was claimed: the capture
    /// pipeline ([`CommandBus::ensure_prepared`]) runs ahead of the claim, so an `observe` failure
    /// there has no attempt to attribute to and no wire was touched. Such a failure reconciles at
    /// operation grain, with no verdict to record.
    ///
    /// Returns the whole [`DispatchSettlement`], not a bare "is it terminal" bool. The bare bool
    /// dropped the other axes and caused live defects: an accepted late ack that contradicts the
    /// failure made the caller report a connector error while an identical replay reported
    /// success, and a lost pre-wire compare made the undo path report a failure over an attempt a
    /// peer owns and is dispatching.
    ///
    /// `terminal` keeps its meaning: an `ISSUANCE_UNKNOWN` settlement is not terminal (not
    /// dead-lettered, not retryable, awaiting adjudication), so a same-resource successor waits.
    fn reconcile_connector_failure(
        &mut self,
        idempotency_key: &str,
        attempt: Option<&str>,
        error: &ConnectorError,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<DispatchSettlement, LogError> {
        let Some(attempt_id) = attempt else {
            // Operation grain: no attempt, so no verdict fact and no chain to compare against. The
            // attempt-shaped axes are constructed `false`/`None` here.
            //
            // The guard: this arm's `Failed` used to be unconditional, but it is reached from the capture
            // pipeline, which observes the provider and can be slow. A sever committing in that window
            // terminalizes this attempt-less operation `Severed`, and the write buried an audited
            // disposition under a dead-letter this boundary had no authority to claim. The plain
            // `StatusPrecondition::NonTerminal` compare answers only "has another authority closed this
            // row", not "is there a live attempt": two drivers can capture the same unprepared operation,
            // driver A finishes PREPARE, claims, authorizes and enters apply while B's earlier observe is
            // still failing, and B's `Failed` lands over A's in-flight attempt. A's `ACK_APPLIED` could
            // then never replace it, closing the operation forever on a proof of no-effect nobody holds.
            //
            // A dead-letter attributes no effect, so it needs "this operation holds no live attempt"
            // joined to the status transition in one transaction:
            // [`IntentLog::dead_letter_if_quiescent`], the only spelling of "dead-letter this operation".
            let wrote_terminal = match error.kind {
                FailureKind::Deterministic => matches!(
                    self.log.dead_letter_if_quiescent(idempotency_key)?,
                    DeadLetterWrite::Written
                ),
                // The transient arm uses the same quiescence predicate. Its terminal used to ride a single
                // statement with only the non-terminal compare, so the last unit of budget spent here wrote
                // `Failed` over a peer's claimed-and-authorized dispatch. The charge and the guarded terminal
                // are now one transaction ([`IntentLog::charge_and_dead_letter_if_quiescent`]); the increment
                // survives a refusal, so a parked dead-letter never makes a transient failure free.
                FailureKind::Transient => matches!(
                    self.log
                        .charge_and_dead_letter_if_quiescent(idempotency_key, RETRY_CAP)?,
                    TransientCharge::ChargedAndDeadLettered
                ),
            };
            // Read back, never predict: `terminal` must be the store's answer, since every sweep's
            // barrier decision hangs on it.
            let actual = self.log.get(idempotency_key)?.map(|intent| intent.status);
            let terminal = actual.as_ref().is_some_and(IntentStatus::is_terminal);
            return Ok(DispatchSettlement {
                terminal,
                superseded_pre_wire: false,
                outranked: None,
                // Preempted: terminal, but not by us. The caller is owed that disposition's replay answer,
                // not this boundary's fresh failure.
                preempted: match actual {
                    Some(status) if terminal && !wrote_terminal => Some(status),
                    _ => None,
                },
            });
        };
        // Everything else is the settlement path's, verbatim: this boundary decides the failure
        // taxonomy and hands the verdict through without re-interpreting the ledger's answer.
        self.settle_dispatch(
            idempotency_key,
            attempt_id,
            ConnectorVerdict::Failed {
                kind: error.kind,
                evidence: error.effect_evidence,
            },
            pre_wire_at_revision,
        )
    }

    /// The verdict path, engine side: every connector outcome at every wire-bound entry point
    /// comes through here (like [`CommandBus::claim_dispatch`] and
    /// [`CommandBus::authorize_dispatch`]), and [`IntentLog::settle_attempt`] does the whole thing
    /// atomically. Returns the full [`DispatchSettlement`]; callers owe an answer to every axis.
    pub(crate) fn settle_dispatch(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        verdict: ConnectorVerdict,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<DispatchSettlement, LogError> {
        use crate::attempt::{FactKind, GrammarRefusal};
        // Every arm that must answer "is it terminal?" without having written the terminal itself
        // re-reads the row rather than predicting it.
        let from_store = |bus: &Self| -> Result<bool, LogError> {
            Ok(bus
                .log
                .get(idempotency_key)?
                .is_some_and(|intent| intent.status.is_terminal()))
        };
        match self.log.settle_attempt(
            idempotency_key,
            attempt_id,
            verdict,
            RETRY_CAP,
            pre_wire_at_revision,
        )? {
            SettleOutcome::Settled { lifecycle, .. } => Ok(DispatchSettlement {
                terminal: lifecycle.is_terminal(),
                superseded_pre_wire: false,
                outranked: None,
                // Attempt-carrying arms never preempt: their guard lives inside `settle_attempt`'s
                // transaction (`terminalize_operation`), and a row a peer closed makes the chain refuse
                // first, which the refusal arms below answer.
                preempted: None,
            }),
            // The adjudication race: the operator adjudicated while this connector call was in flight,
            // and then the provider answered definitively. The post-adjudication whitelist rightly
            // refuses an `ACK_*` on that chain (the operational axis is closed and an ack would reopen
            // it), but the answer is exactly what `LATE_ACK_*` exists for. Treating this legal race as a
            // store incident left the historical axis stuck at unknown and the exposure obligations
            // unretired over an answer the engine held.
            //
            // Only the two definitive kinds convert. `ACK_AMBIGUOUS` stays refused (a late non-definitive
            // observation resolves nothing) and takes the annotation arm below.
            //
            // The conversion reuses the late-ack path verbatim (at-most-one late ack, exposure retirement,
            // notices, the undo-parent flip), never a second implementation.
            SettleOutcome::RefusedByGrammar(GrammarRefusal::PostAdjudicationWhitelistViolation {
                kind: kind @ (FactKind::AckApplied | FactKind::AckRefusedNoEffect),
            }) => {
                let ack = if kind == FactKind::AckApplied {
                    crate::attempt::LateAck::Applied
                } else {
                    crate::attempt::LateAck::RefusedNoEffect
                };
                match self.log.record_late_ack(idempotency_key, attempt_id, ack)? {
                    // Resolved, or already resolved the same way: the ledger holds the honest record, agrees
                    // with this caller's verdict, and the operational answer is the row's own terminal status.
                    LateAckOutcome::Resolved { .. }
                    | LateAckOutcome::RefusedByGrammar(GrammarRefusal::DuplicateLateAck {
                        ..
                    }) => Ok(DispatchSettlement {
                        terminal: from_store(self)?,
                        superseded_pre_wire: false,
                        outranked: None,
                        preempted: None,
                    }),
                    // Refused as a contradiction: a second, contradictory late ack is refused and the
                    // contradiction is durably recorded as an anomaly annotation. Both are right, but reporting
                    // success would be wrong: the chain's accepted verdict is the opposite of the one just
                    // delivered, so an identical replay (reading that accepted late ack through
                    // `decision_outcome`) would answer the reverse.
                    //
                    // The first accepted late ack is the chain's truth and is what the caller is owed. It is read
                    // back (`adjudicated_history`), never inferred from the polarity we sent.
                    LateAckOutcome::RefusedAsContradiction { .. } => {
                        let history = self.log.adjudicated_history(idempotency_key)?;
                        if history == AdjudicatedHistory::Unresolved {
                            // A contradiction with nothing to contradict: the late-ack path and the history reader
                            // disagree about one chain. Fail explicitly.
                            return Err(LogError(format!(
                                "the verdict for '{idempotency_key}' was refused as a \
                                 CONTRADICTION, but the chain holds no accepted late ack for it \
                                 to contradict"
                            )));
                        }
                        Ok(DispatchSettlement {
                            terminal: from_store(self)?,
                            superseded_pre_wire: false,
                            outranked: Some(history),
                            preempted: None,
                        })
                    }
                    // Anything else means the whitelist and the late-ack path disagree about the same chain:
                    // fail explicitly.
                    LateAckOutcome::RefusedByGrammar(refusal) => Err(LogError(format!(
                        "the definitive verdict for '{idempotency_key}' raced an adjudication, \
                         and its late ack was refused by the attempt grammar: {refusal}"
                    ))),
                }
            }
            // The ambiguous outcome that raced adjudication, the other half of the same legal race:
            // the operator adjudicated mid-flight and the provider's answer was indeterminate (a
            // timeout, a 5xx, a truncated response). The verdict is `ACK_AMBIGUOUS`, which the whitelist
            // refuses correctly: a late non-definitive observation lives in the adjudication record's
            // ancillary audit trail, never the closed grammar.
            //
            // It is not a store incident. `recover` treats a `LogError` as fatal, so one operator decision
            // at the wrong moment aborted the whole sweep and stranded every unrelated intent. Instead
            // the observation is annotated (never silently dropped), nothing decides on it, and the caller
            // is owed the historical axis as it stands: normally `Unresolved`, read back rather than
            // assumed because a `LATE_ACK_*` may have landed in between.
            SettleOutcome::RefusedByGrammar(GrammarRefusal::PostAdjudicationWhitelistViolation {
                kind: FactKind::AckAmbiguous,
            }) => {
                self.log
                    .annotate_late_ambiguous_observation(idempotency_key, attempt_id)?;
                Ok(DispatchSettlement {
                    terminal: from_store(self)?,
                    superseded_pre_wire: false,
                    outranked: Some(self.log.adjudicated_history(idempotency_key)?),
                    preempted: None,
                })
            }
            // The two reachable refusals both mean "someone else already settled this": a peer's
            // verdict landed first (`PostTerminalAppend`), or a re-entered completion path met an
            // ambiguity already recorded (`DuplicateAckAmbiguous`). Neither is a store incident and
            // neither may claim a terminal this driver did not write: re-read and answer from the store.
            SettleOutcome::RefusedByGrammar(
                GrammarRefusal::PostTerminalAppend { .. } | GrammarRefusal::DuplicateAckAmbiguous,
            ) => Ok(DispatchSettlement {
                terminal: from_store(self)?,
                superseded_pre_wire: false,
                outranked: None,
                preempted: None,
            }),
            // The pre-wire compare lost: the chain moved under a decision taken before any wire. A peer
            // that re-entered the same live attempt is dispatching it. Nothing is owed and nothing may be
            // claimed about a terminal this driver did not write; re-read and report the store's answer.
            SettleOutcome::SupersededPreWire { .. } => Ok(DispatchSettlement {
                terminal: from_store(self)?,
                superseded_pre_wire: true,
                outranked: None,
                preempted: None,
            }),
            // Anything else means the ledger is not what this build wrote: fail explicitly.
            SettleOutcome::RefusedByGrammar(refusal) => Err(LogError(format!(
                "verdict for '{idempotency_key}' refused by the attempt grammar: {refusal}"
            ))),
        }
    }

    /// True if any intent other than `command` on the same provider-native resource is still
    /// non-terminal, so `recover` will (re)dispatch it and dispatching `command` now would race it.
    /// Both `execute` and `undo` defer behind such a predecessor (tail ordering).
    ///
    /// BASIS-1: the ordering key is the admission-frozen native resource key, not the Photon-local
    /// `message_ref`, so two local refs aliasing one provider object share one ordering domain. A
    /// row with no frozen basis is keyed on its local `message_ref`, which the log predicate's
    /// second lane compares against every candidate (not only NULL-basis ones), so mixed-generation
    /// rows on one message order safely in both directions.
    ///
    /// The whole tail is in scope (`before_seq = u64::MAX`) with `command`'s own key excluded: on
    /// `execute` the just-claimed row is the newest, so "every other non-terminal" and the strict
    /// at-head bound coincide; on `undo` an in-flight intent must also defer behind later
    /// same-resource work, or the older undo jumps past a newer action (see
    /// `an_undoing_retry_does_not_mint_a_tail_compensation_past_a_later_action`). PREPARE asks the
    /// strict at-head question separately, inside its own transaction.
    fn has_pending_same_resource_predecessor(
        &self,
        command: &Command,
    ) -> Result<bool, ExecuteError> {
        let message = action_to_parts(&command.action).1;
        // The intent's own admission-frozen native key; a command with no durable row yet (or a
        // pre-stage-2 row) is keyed on its local ref, which the predicate's fallback lane compares.
        let native_key = self
            .log
            .get(&command.idempotency_key)
            .map_err(ExecuteError::Log)?
            .and_then(|intent| intent.frozen_basis.map(|b| b.native_resource_key))
            .unwrap_or_else(|| message.clone());
        self.log
            .has_non_terminal_native_predecessor(
                &native_key,
                &message,
                &command.account,
                u64::MAX,
                &command.idempotency_key,
            )
            .map_err(ExecuteError::Log)
    }

    /// Admit the undo child: an intent of its own, through the same admission path every
    /// operation uses ([`CommandBus::resolve_admission_basis`]). `compensates` carries the
    /// parent's user key (the explicit, durable heal link `recover` trusts, never a key-text
    /// guess); the idempotency key is derived from the parent's opaque `intent_id` in the reserved
    /// namespace (content-free and uncollidable); the action column stores the descriptor inverse
    /// (ordering, projection and the link check only; dispatch never derives from it); and the
    /// child freezes its own basis at its admission moment (BASIS-5), which the drive's
    /// basis-match check compares against the parent's. The parent's status is not touched:
    /// scheduling is not completion, and the flip happens at verification inside the drive.
    ///
    /// Returns who owns the drive ([`UndoChildAdmission`]), with the same `Claim` discipline as
    /// [`CommandBus::execute`]: of two concurrent buses racing one parent, exactly one gets
    /// `Inserted` and drives.
    ///
    /// Re-checks the offer deadline at the durable admission boundary. The eligibility snapshot
    /// ([`prestate::derive_undo_eligibility`]) is taken before the child is admitted, then a fresh
    /// [`Connector::resolve_basis`] runs before [`IntentLog::record`], and the clock can cross
    /// `undo_offer_until` in that gap. A durable child outranks fresh eligibility on every later
    /// sweep, so a child admitted past the deadline would be driven by `recover` and restore
    /// outside the offer window. Eligibility is therefore re-derived here through the same
    /// authority and refused with its reason if the offer has lapsed.
    ///
    /// The check is local and wire-free: one [`IntentLog::undo_context`] read (its sticky-clock
    /// advance is idempotent) plus the pure derivation. Residual: this closes the resolve-sized
    /// window, not the tiny recheck-to-`record()` gap, which would need a single
    /// lifecycle-plus-deadline transaction.
    fn refuse_if_offer_lapsed(&mut self, parent: &Intent) -> Result<(), ExecuteError> {
        let ctx = self
            .log
            .undo_context(&parent.command.idempotency_key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| ExecuteError::Log(LogError("undo parent vanished".into())))?;
        let has_targets = parent
            .frozen_basis
            .as_ref()
            .is_some_and(|b| !b.atom_targets.is_empty());
        let journal_view = ctx.journal.as_ref().map(|j| prestate::CapturedJournalView {
            p: j.p.clone(),
            undo_offer_until: j.undo_offer_until.clone(),
        });
        if let prestate::UndoEligibility::Unavailable(reason) = prestate::derive_undo_eligibility(
            parent.journal_required,
            has_targets,
            journal_view,
            ctx.tombstoned,
            &ctx.effective_now,
        ) {
            return Err(ExecuteError::UndoUnavailable(reason));
        }
        Ok(())
    }

    fn admit_undo_child(
        &mut self,
        parent: &Intent,
        child_key: &str,
    ) -> Result<UndoChildAdmission, ExecuteError> {
        let child = mint_undo_child_command(parent, child_key);
        let basis = match self.resolve_admission_basis(&child)? {
            AdmissionBasis::Fresh(basis) => basis,
            // A peer admitted this child inside the resolution window: the row is the answer, and the
            // drive is the peer's.
            AdmissionBasis::RacedToExistingRow(_) => {
                return Ok(UndoChildAdmission::Existing(self.reread_undo_child(child_key)?));
            }
        };
        // The deadline re-check, after the slow resolve and immediately before the durable insert
        // ([`CommandBus::refuse_if_offer_lapsed`]): a resolver that crossed `undo_offer_until` must
        // not leave a durable child for `recover` to drive outside the window.
        self.refuse_if_offer_lapsed(parent)?;
        // The atomic claim is the ownership authority, as in `execute`: `AlreadyExisted` means a
        // concurrent peer won it, so we do not drive.
        let claim = self.log.record(&child, &basis).map_err(ExecuteError::Log)?;
        // A capacity refusal leaves no row to re-read; answer it directly, before
        // `reread_undo_child` would bury the reason under "admitted undo child vanished".
        let inserted = match claim {
            Claim::Inserted => true,
            Claim::AlreadyExisted => false,
            Claim::CapacityRefused(refusal) => return Err(ExecuteError::CapacityRefused(refusal)),
            // An undo child has no plan link, so the plan-child arm does not run for it; the variant is
            // answered as itself regardless.
            Claim::PlanChildRefused(refusal) => return Err(ExecuteError::PlanChildRefused(refusal)),
        };
        let child = self.reread_undo_child(child_key)?;
        Ok(if inserted {
            UndoChildAdmission::Inserted(child)
        } else {
            UndoChildAdmission::Existing(child)
        })
    }

    /// Read-only lookup of a parent's legacy deferred undo child by the old key shape
    /// (`compensation_key(parent user key)`, minted by the pre-stage-3 defer path). `Some` only
    /// when the row is a legacy pair member: linked to this parent and matching
    /// [`is_legacy_deferred_child`]. Mutates nothing, so display paths may call it.
    fn legacy_deferred_child(&self, parent_key: &str) -> Result<Option<Intent>, LogError> {
        Ok(self.log.get(&compensation_key(parent_key))?.filter(|child| {
            child.command.compensates.as_deref() == Some(parent_key)
                && is_legacy_deferred_child(child)
        }))
    }

    /// Map a legacy pair back to the last verified truth, shared by [`CommandBus::undo`] and
    /// [`CommandBus::drive_undo_child`] (and so [`CommandBus::recover`]). Whether the old blind
    /// inverse ever dispatched cannot be resolved, so the parent returns to `Applied` (never
    /// guessed forward to `Undone`), the child terminalizes `Failed`, and nothing is
    /// re-dispatched. The parent regains an honest undo through the new path: its stage-2
    /// journal row is intact and the new child key cannot collide with the legacy row.
    ///
    /// Two writes, convergence-safe rather than one transaction: a crash between them re-runs
    /// idempotently. The reset cannot regress a verified undo: a legacy pair's parent has empty
    /// `atom_targets` ([`is_legacy_deferred_child`]), so `derive_undo_eligibility` refuses any
    /// new undo on it (`PredatesSubstrate`) and it never reaches `verify_undo`.
    ///
    /// Both writes are compare-and-set. The parent reset was a `get` followed by an
    /// unconditional write, a TOCTOU whose compare now lives inside the write
    /// (`Exactly(Undone)`). The child write takes the non-terminal guard: a sever between the
    /// read and here may have closed it `Severed`, a more informative terminal than the `Failed`
    /// this writes. Either refusal converges rather than failing, since a parent already
    /// `Applied` or a child already terminal is the last verified truth.
    fn map_legacy_pair(&mut self, parent_key: &str, child_key: &str) -> Result<(), LogError> {
        // The two refusals are the two converged worlds, named rather than discarded.
        let _parent_already_reset = self.log.set_status_if(
            parent_key,
            StatusPrecondition::Exactly(IntentStatus::Undone),
            IntentStatus::Applied,
        )?;
        let _child_already_closed = self.log.set_status_if(
            child_key,
            StatusPrecondition::NonTerminal,
            IntentStatus::Failed,
        )?;
        Ok(())
    }

    /// Detect and map a parent's legacy deferred pair in one step, keyed by the parent's user
    /// key; returns the mapped child's key, or `None` when there is no legacy pair.
    fn map_legacy_deferred_child(&mut self, parent_key: &str) -> Result<Option<String>, LogError> {
        let Some(child) = self.legacy_deferred_child(parent_key)? else {
            return Ok(None);
        };
        let child_key = child.command.idempotency_key.clone();
        self.map_legacy_pair(parent_key, &child_key)?;
        Ok(Some(child_key))
    }

    /// Admit the undo child of a no-op undo (`P == A`) without a fresh resolution. Same command,
    /// key and claim discipline as [`CommandBus::admit_undo_child`]; the one difference is the
    /// basis it commits.
    ///
    /// Why the parent's frozen basis: a no-op child never reaches the wire. `P == A` is frozen at
    /// admission, so its only outcomes are [`CommandBus::verify_undo`] (a pair of status writes)
    /// or, if it defers behind a predecessor, the same no-op arm inside
    /// [`CommandBus::drive_undo_child`]. Its basis is documentary, so re-resolving it is
    /// unnecessary and a rebind risk (a resolver that retargeted the local ref would commit a basis
    /// naming a resource this undo never touched, or refuse and block a decision made from local
    /// rows alone). BASIS-5's fresh-freeze rule governs operations that can dispatch. The parent's
    /// basis would pass the drive's basis-match check trivially if a future caller drove this row.
    fn admit_noop_undo_child(
        &mut self,
        parent: &Intent,
        child_key: &str,
        parent_basis: &crate::prestate::FrozenBasis,
    ) -> Result<UndoChildAdmission, ExecuteError> {
        let child = mint_undo_child_command(parent, child_key);
        // The same deadline re-check as the resolving path: a durable no-op child also outranks the
        // offer check on later sweeps and verifies the parent `Undone`, so it must not be admitted
        // after the offer has lapsed ([`CommandBus::refuse_if_offer_lapsed`]).
        self.refuse_if_offer_lapsed(parent)?;
        // The atomic claim is the ownership authority here too: a peer that won the row owns its
        // drive, and we report the row's verdict.
        let claim = self.log.record(&child, parent_basis).map_err(ExecuteError::Log)?;
        // A capacity refusal leaves no row for `reread_undo_child` to find.
        let inserted = match claim {
            Claim::Inserted => true,
            Claim::AlreadyExisted => false,
            Claim::CapacityRefused(refusal) => return Err(ExecuteError::CapacityRefused(refusal)),
            // No plan link on an undo child (see `admit_undo_child`); answered as itself.
            Claim::PlanChildRefused(refusal) => return Err(ExecuteError::PlanChildRefused(refusal)),
        };
        let child = self.reread_undo_child(child_key)?;
        Ok(if inserted {
            UndoChildAdmission::Inserted(child)
        } else {
            UndoChildAdmission::Existing(child)
        })
    }

    /// Re-read a just-admitted undo child; its absence is a durable-log incident, not a state.
    fn reread_undo_child(&self, child_key: &str) -> Result<Intent, ExecuteError> {
        self.log
            .get(child_key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| ExecuteError::Log(LogError("admitted undo child vanished".into())))
    }

    /// Head check, then drive. Tail ordering (ADR-P013): a live same-resource predecessor means
    /// driving now would race `recover`'s (re)dispatch of it, so the child stays `Pending` for
    /// `recover` to sequence and requalifies at its own head moment, never against state as of
    /// undo admission. A deferral is `InProgress`, never a false `Ok`.
    ///
    /// The deferral is terminal-aware: the predicate is about a predecessor and says nothing about
    /// the child, which a sever since its insert may have closed. A closed child never appears in
    /// `unreconciled()` again, so `InProgress` about one would never be revised.
    fn drive_undo_child_at_head(&mut self, child: &Intent) -> Result<(), ExecuteError> {
        if self.has_pending_same_resource_predecessor(&child.command)? {
            return self.park_or_replay(&child.command.idempotency_key);
        }
        match self.drive_undo_child(child)? {
            UndoDriveOutcome::Verified => Ok(()),
            // Unreachable from here: [`CommandBus::undo`] looks the child up under the new key shape,
            // and a row there was admitted by code that cannot commit an empty target vector
            // (`reject_inadmissible_basis`). Only `recover` sweeps by durable status and can meet a
            // legacy child. The arm lives in the shared drive so both callers agree on what a legacy row
            // is; the mapping leaves the child `Failed`, which is the answer a `Failed` child always gets.
            UndoDriveOutcome::LegacyMapped => Err(ExecuteError::Failed),
        }
    }

    /// The undo drive, shared by [`CommandBus::undo`] and [`CommandBus::recover`] so the two paths
    /// cannot drift. In order: legacy-child mapping, crash-convergence short-circuit, the no-op
    /// kill (from the journal row plus the frozen `A`; no provider read, no dispatch), epoch check,
    /// basis-match check, observe `C` (BASIS-6 verified), the undo requalification decision,
    /// [`Connector::restore`] writing the captured `P` as a native delta, and the parent `Undone`
    /// at verification only.
    ///
    /// Heal order: the parent flips before the child terminalizes, so a crash in between leaves the
    /// child `Pending` and the re-drive converges. The short-circuit for a parent already `Undone`
    /// is safe to skip (`C == P` would give `AlreadyRestored`) but spends no provider read.
    ///
    /// The wire-free branches precede the epoch check. The check exists to stop wire effects under
    /// a stale control epoch, and the legacy mapping, convergence heal and no-op kill each write
    /// durable status from local rows alone and never reach `observe` or `restore`, so they are
    /// epoch-exempt. Running the check first stranded work two ways: after restore succeeded and
    /// `verify_undo` wrote the parent `Undone`, a crash before the child's terminal plus a sever
    /// meant every sweep fenced a completed undo into `InProgress` forever; and a `P == A` child
    /// that deferred behind a predecessor (so never met the pre-admission kill) met a bumped epoch
    /// and parked forever on a decision needing no provider read. A stranded `Pending` child also
    /// barriers all later work on that resource. After the reorder the check guards exactly the
    /// paths that can reach the wire, including the basis-match check
    /// (`recovery_completes_a_deferred_noop_undo_across_an_epoch_bump` pins both sides).
    ///
    /// The double-drive race is closed by [`CommandBus::claim_dispatch`], the atomic `CLAIM`
    /// fact, taken before the basis check and therefore before `observe` and `restore`, so a losing
    /// racer never reaches the wire path. The defect was that this drive acts on a caller-supplied
    /// `Intent` read with no atomic ownership transition, so two `CommandBus` instances over one
    /// store could both take a stale `Pending` read and double-drive. Pinned by
    /// `two_buses_over_one_store_never_double_drive_one_undo_child`. The same interleave across an
    /// epoch bump is handled by the sever primitive, which writes the epoch bump and the
    /// terminalizing facts.
    pub(crate) fn drive_undo_child(&mut self, child: &Intent) -> Result<UndoDriveOutcome, ExecuteError> {
        let parent_key = child.command.compensates.clone().ok_or_else(|| {
            ExecuteError::Log(LogError("undo child has no compensation link".into()))
        })?;
        let parent = self
            .log
            .get(&parent_key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| ExecuteError::Log(LogError("undo parent vanished".into())))?;
        // The mislink check, first, ahead of every arm below. It asks whether this row is the child
        // this parent mints at all, which nothing else does: the basis check compares the native
        // resource, so a mislinked row on the same resource passes it, and the two wire-free arms that
        // can flip a parent (convergence heal, no-op kill) run above it with no identity check. So a
        // `compensates` link pointing at an unrelated same-resource parent could mint a durable
        // `Undone` for an undo that was never that parent's
        // (`a_mislinked_compensation_never_heals_an_unrelated_parent`).
        //
        // The comparison is against [`mint_undo_child_command`] itself, the one place a child's shape
        // is defined, so it cannot drift and covers any field added there. The child's own key is fed
        // into the mint, so key shape is outside the comparison: a pre-stage-3 child carries the old
        // `compensation_key(parent user key)` and both shapes are legitimate. What remains (account,
        // facet, inverse action, envelope, compensation link) is what the old minting code produced
        // too, so the legacy arm below keeps working.
        if child.command != mint_undo_child_command(&parent, &child.command.idempotency_key) {
            return self.terminalize_undo_deterministic(
                child,
                // Pre-claim: the mislink check runs ahead of the dispatch claim, so there is no attempt to
                // attribute this refusal to.
                None,
                ConnectorError::deterministic(
                    "undo child is not the compensation this parent mints — mislinked, refused",
                ),
                // ...and no attempt means no chain to compare against.
                None,
            );
        }
        // The legacy deferred-undo arm, ahead of the convergence short-circuit, which is wrong for a
        // legacy row. A pre-stage-3 store can hold a deferred undo whose parent was flipped `Undone`
        // at scheduling with the compensation still `Pending`. Converging that child to `Applied`
        // would claim a restore that never ran: the old path never reached the wire, so the log said
        // "undone" while the provider stayed in the forward state.
        //
        // [`is_legacy_deferred_child`] decides what a legacy row is (here on the child this sweep
        // holds; in `undo` and `undo_presentation` by parent-key lookup), and
        // [`CommandBus::map_legacy_pair`] performs the one mapping (parent back to `Applied`, child
        // `Failed`), so the paths cannot drift or start matching live children.
        if is_legacy_deferred_child(child) {
            self.map_legacy_pair(&parent_key, &child.command.idempotency_key)
                .map_err(ExecuteError::Log)?;
            return Ok(UndoDriveOutcome::LegacyMapped);
        }
        // Crash-safe convergence: a re-driven child whose parent already flipped only needs its own
        // terminal. Heal-only (no observation, no dispatch), which is why it sits ahead of the epoch
        // check: the restore it converges already happened under the epoch that authorized it.
        if parent.status == IntentStatus::Undone {
            return self.converge_undo_child(child);
        }
        // The captured `P`, read here because the wire-free no-op kill below needs it. Only the read
        // moves up: a missing journal is not a no-op input, so its explicit answer stays below the
        // checks.
        let ctx = self
            .log
            .undo_context(&parent_key)
            .map_err(ExecuteError::Log)?
            .ok_or_else(|| ExecuteError::Log(LogError("undo parent vanished".into())))?;
        let captured_p = ctx.journal.map(|j| j.p);
        // The no-op kill, decided first from the journal row and the admission-frozen target vector
        // alone: no provider read, no dispatch. The parent flips at this verification. The `if let`
        // keeps the arm total, as in [`CommandBus::undo`]'s pre-admission twin; a parent with no basis
        // falls through to the hard binding below.
        //
        // This arm stays although `undo` kills the no-op before admitting a child: children driven by
        // `recover` (deferred behind a predecessor, or parked by the epoch check) arrive here without
        // that pre-admission check and requalify at their own head moment, where `P == A` must still
        // short-circuit ahead of any observation. Both sites use `prestate::noop_kill`.
        if let (Some(p), Some(targets)) = (
            captured_p.as_ref(),
            parent.frozen_basis.as_ref().map(|b| &b.atom_targets),
        ) {
            if prestate::noop_kill(p, targets) {
                return self.verify_undo(&parent_key, child, None, None);
            }
        }
        // Epoch check: from here down every path can reach the wire (`observe`, `restore`), and
        // this is the only check guarding them, since undo children own no journal row and PREPARE's
        // in-transaction check never runs for them. A sever between the child's admission and now
        // parks it, `Pending` and undispatched, for the sever machinery to terminalize.
        //
        // The park is not blind: the sever that moved the epoch terminalizes every active operation
        // with no live attempt in the same write, so this child may already be `Severed`.
        // `InProgress` over it would never be revised, since a terminal child never appears in
        // `unreconciled()` again. The row decides.
        if !self
            .log
            .admitted_epoch_is_current(&child.command.idempotency_key)
            .map_err(ExecuteError::Log)?
        {
            if let Some(status) = self.terminal_disposition(&child.command.idempotency_key)? {
                self.status_replay_outcome(&child.command.idempotency_key, &status)?;
                return Ok(UndoDriveOutcome::Verified);
            }
            return Err(ExecuteError::InProgress);
        }
        // The dispatch claim, which closes the double-drive race. Placement matters:
        // - Before the basis check, `observe` and `restore`, so a losing racer never reaches the wire
        //   path, nor the deterministic terminalization the basis check can write.
        // - After the three wire-free arms (legacy mapping, convergence heal, no-op kill), for the
        //   same reason as the epoch check: they write status from local rows alone and must not be
        //   stranded by a check that guards the wire.
        //
        // The observed episode is the one the caller's read carried (`child.attempts`), which is what
        // makes the stale-read family decidable: driver B holds a read from before A moved the row
        // and loses here.
        //
        // A child's retry mints ordinal n+1 here too and needs no separate requalification gate: this
        // whole function is the undo path's requalification, observing `C` and running the undo
        // table on every drive, so a deferred or retried child decides against the world as it is
        // now. The forward arm is where a retry owes an extra decision
        // ([`CommandBus::requalify_retry_at_head`]).
        //
        // `pre_wire` carries the claim's observed revision until this driver authorizes, then becomes
        // `None`. Every settlement before the restore socket compare-and-appends against it, so a peer
        // that re-entered the same live child attempt and authorized it cannot have it terminalized
        // from under it; after our own authorization the at-most-one `SEND_AUTHORIZED` is the
        // exclusivity, and the chain may legally move (adjudication).
        let (attempt_id, mut pre_wire) =
            match self.claim_dispatch(&child.command.idempotency_key, child.attempts)? {
                DispatchOwnership::Owned {
                    attempt_id,
                    observed_revision,
                    ..
                } => (attempt_id, Some(observed_revision)),
                // The claim's own re-read found this child closed: report the disposition a replay of the
                // child's key reads (as the authorization path does below). `Ok` means the child settled
                // `Applied`, which for an undo child is the verification.
                DispatchOwnership::Terminal(status) => {
                    self.status_replay_outcome(&child.command.idempotency_key, &status)?;
                    return Ok(UndoDriveOutcome::Verified);
                }
                // Another driver owns this child's dispatch and it is still open. Exit silently: nothing
                // observed, dispatched or written; in flight, as the epoch check above signals, and `recover`
                // treats it the same (barrier plus park).
                DispatchOwnership::Park => return Err(ExecuteError::InProgress),
            };
        let parent_basis = parent.frozen_basis.as_ref().ok_or_else(|| {
            ExecuteError::Log(LogError("undo parent has no frozen_basis".into()))
        })?;
        // Basis-match check: the child froze its own basis at its admission, and if the resolver
        // rebound the local ref between the two admissions the resource is no longer the one
        // captured: a deterministic refusal, never a retarget (BASIS-6). It stays below the epoch
        // check because it guards wire dispatch against a retargeted resource; the no-op kill never
        // consults the child's basis.
        //
        // The check compares the whole operand map and the role-to-id map, not just the native key.
        // A basis carries identity (the native key plus the resolved operands the decision is about)
        // and freshness (the provider cursor). Identity may not move between the two admissions, and
        // the native key alone cannot see all of it: a JMAP key names account plus email, so a role
        // that re-resolved to a different mailbox id leaves the key identical while the operands the
        // restore would write changed
        // (`jmap_move_undo_refuses_when_the_childs_operands_are_not_the_parents`).
        //
        // The operand map alone also cannot see a role permutation that preserves the id set: swap
        // which mailbox id the Inbox and Archive roles name and `touched_atoms` is identical while the
        // role-to-id direction is inverted, so the restore would write the parent's understanding onto
        // the opposite world. `role_bindings` is the only place that direction is known, so it is
        // compared too, closing the class `JmapConnector::reverify_role_basis` closes connector-side
        // (`undo_refuses_a_role_permutation_between_parent_and_child_admissions`). Legitimate undos
        // have equal maps; keyword verbs freeze empty `role_bindings` on both sides.
        let Some(child_basis) = child.frozen_basis.as_ref() else {
            return self
                .terminalize_undo_deterministic(
                    child,
                    Some(&attempt_id),
                    ConnectorError::deterministic_basis_rebound(),
                    // Pre-wire: every basis-rebind refusal here is decided from local rows or a verified
                    // observation, before this driver authorizes anything.
                    pre_wire,
                );
        };
        if child_basis.native_resource_key != parent_basis.native_resource_key
            || child_basis.touched_atoms != parent_basis.touched_atoms
            || child_basis.role_bindings != parent_basis.role_bindings
        {
            return self
                .terminalize_undo_deterministic(
                    child,
                    Some(&attempt_id),
                    ConnectorError::deterministic_basis_rebound(),
                    // Pre-wire: every basis-rebind refusal here is decided from local rows or a verified
                    // observation, before this driver authorizes anything.
                    pre_wire,
                );
        }
        let p = match captured_p {
            Some(p) => p,
            // The row vanished after admission (only the dormant expiry could do that): fail explicitly
            // and leave the child `Pending` for inspection. The answer keeps its slot behind the epoch and
            // basis-match checks so a mislinked child still dead-letters on the rebind refusal instead of
            // aborting the sweep with a store incident
            // (`recover_does_not_heal_a_mislinked_compensation`); only the read moved up.
            None => {
                return Err(ExecuteError::UndoUnavailable(
                    prestate::UndoUnavailableReason::JournalGapUnexplained,
                ))
            }
        };
        let a = &parent_basis.atom_targets;
        // Observe `C` on the frozen identity (a missing target is the connector's own deterministic
        // refusal; undo never recreates anything).
        //
        // The child's basis goes to the wire: identity was frozen at the parent's admission and
        // verified equal at the child's by the check above, and only freshness differs, which
        // legitimately advances because the forward move itself moves the cursor. On a conforming
        // JMAP provider a mailbox move changes both mailboxes' counts, so handing the connector the
        // parent's cursor made its state-cursor re-verification refuse every legitimate live
        // move-undo as a rebound (`jmap_move_undo_survives_the_forward_moves_own_state_advance`).
        // The connector now re-resolves the roles fresh and compares the resolved ids to the frozen
        // operands (`JmapConnector::reverify_role_basis`;
        // `jmap_undo_survives_a_cursor_advanced_by_a_third_party_between_admission_and_drive`), so
        // cursor equality is no longer part of the identity check. The child's operands are still the
        // identity verified equal.
        //
        // Everything downstream reads the parent's basis (native key, atom set, `A`, restore
        // operands). That is not a second authority: the check proved the two equal.
        let obs = match self.connector.observe(&parent.command, child_basis) {
            Ok(obs) => obs,
            Err(error) => {
                // Pre-wire: the observation runs before this driver authorizes anything.
                return self.reconcile_undo_connector_failure(
                    child,
                    Some(&attempt_id),
                    error,
                    pre_wire,
                );
            }
        };
        // BASIS-6 at observation, as the capture pipeline verifies it.
        if obs.native_resource_key != parent_basis.native_resource_key
            || !parent_basis
                .touched_atoms
                .keys()
                .all(|k| obs.atoms.contains_key(k))
        {
            return self
                .terminalize_undo_deterministic(
                    child,
                    Some(&attempt_id),
                    ConnectorError::deterministic_basis_rebound(),
                    // Pre-wire: every basis-rebind refusal here is decided from local rows or a verified
                    // observation, before this driver authorizes anything.
                    pre_wire,
                );
        }
        let c: std::collections::BTreeMap<String, bool> = parent_basis
            .touched_atoms
            .keys()
            .map(|k| (k.clone(), obs.atoms[k]))
            .collect();
        match prestate::requalify(&p, a, &c) {
            // `C == P`: the pre-state already holds (another client put it back): a recorded no-op undo,
            // verified without a dispatch.
            prestate::RequalifyDecision::AlreadyRestored => {
                // Wire-free and reached without authorizing, so it is a pre-wire settlement like the
                // conflict arm and carries the same compare.
                self.verify_undo(&parent_key, child, Some(&attempt_id), pre_wire)
            }
            // Neither `P` nor `A` (reachable for multi-atom pairs): refuse, never blind-write. The
            // child terminalizes; the parent stays `Applied` with the conflict surfaced, and there is no
            // re-undo (a new forward action is the remedy).
            prestate::RequalifyDecision::Conflict => {
                // Through the verdict path like every outcome: the refusal is decided from the verified
                // observation before any authorization, so the child's attempt records `FAILED_PRE_SEND`
                // (proven no wire) atomically with its `Failed` lifecycle. The typed `UndoConflict` tells the
                // caller why.
                //
                // Pre-wire (`pre_wire` is still `Some`; this arm never authorizes), so it compare-and-appends:
                // a peer that re-entered this attempt and got its `SEND_AUTHORIZED` in is dispatching a
                // restore, and a conflict decided against the older chain must not close it. A superseded
                // compare wrote nothing and reached no wire, so the signal is the in-flight park.
                //
                // The other axes: `outranked` cannot occur, since this verdict maps `FAILED_PRE_SEND` (never
                // an `ACK_*`) and the post-adjudication refusals fire only on ack kinds. `terminal` is not
                // asked: `UndoConflict` is this arm's answer and the sweep classifies on that signal.
                if self
                    .settle_dispatch(
                        &child.command.idempotency_key,
                        &attempt_id,
                        ConnectorVerdict::Failed {
                            kind: FailureKind::Deterministic,
                            evidence: EffectEvidence::ProvenNoWire,
                        },
                        pre_wire,
                    )
                    .map_err(ExecuteError::Log)?
                    .superseded_pre_wire
                {
                    // The park is terminal-aware: the peer that took this attempt may already have settled
                    // the child.
                    return self.undo_drive_park(&child.command.idempotency_key);
                }
                Err(ExecuteError::UndoConflict)
            }
            // `C == A`: the forward result still holds, so dispatch the delta restore, every value of
            // which comes from the captured `P`.
            prestate::RequalifyDecision::Restore => {
                // Send authorization sits here, between the decision and `Connector::restore`, and only on
                // this arm that reaches the wire: the other two decisions are wire-free, and checking them
                // would recreate the stranding class the epoch-check reorder closed. Undo children own no
                // journal row, so PREPARE's check never runs for them and this path needs its own boundary.
                //
                // BASIS-6 here is the strongest of the three paths: the observation was verified against the
                // parent's frozen basis just above, and the child's basis was proven equal to the parent's
                // before that, so the exposure key derived from the frozen basis is the identity just
                // verified against the provider.
                //
                // The gap remains: this authorization commits, then `restore` is called, and a crash between
                // leaves an authorized, possibly-unsent restore (irreducible, two generals; recorded).
                //
                // The capture CAS this path asserts: an undo child owns no journal row (the capture pipeline
                // never runs for a child), and its `P` is the parent's row, which cannot be replaced under
                // this drive: `replace_journal_row` refuses unless every attempt holds a proven-no-wire
                // terminal, and an undoable parent is `Applied` only by way of an `ACK_APPLIED`. The
                // assertion is checked at the call rather than assumed.
                match self.authorize_dispatch(
                    &child.command.idempotency_key,
                    &attempt_id,
                    CaptureBinding::NoJournalRow,
                )? {
                    DispatchAuthorization::Authorized => {}
                    // The refusing transaction closed this child. No restore and no write of our own: the
                    // disposition is durable, and this driver owes its caller that disposition's replay answer
                    // (the routing of the preemption arm in `undo_settlement_outranks`). `Ok` means the child
                    // settled `Applied`, a restore that landed, which for an undo child is the verification.
                    DispatchAuthorization::Terminal(status) => {
                        self.status_replay_outcome(&child.command.idempotency_key, &status)?;
                        return Ok(UndoDriveOutcome::Verified);
                    }
                    // Superseded by an equally-current peer, or refused over an unresolved exposure on an
                    // attempt that may already have issued: the child is still open, so recovery owns it.
                    DispatchAuthorization::Park => return Err(ExecuteError::InProgress),
                }
                // We own the wire now. The at-most-one `SEND_AUTHORIZED` just committed is this driver's
                // exclusivity, so the settlements below drop the pre-wire compare; the chain may legally move
                // under a dispatch in flight (an operator adjudicating it is a legal race).
                pre_wire = None;
                if let Err(error) =
                    self.connector.restore(&parent.command, parent_basis, &p)
                {
                    return self.reconcile_undo_connector_failure(
                        child,
                        Some(&attempt_id),
                        error,
                        pre_wire,
                    );
                }
                self.verify_undo(&parent_key, child, Some(&attempt_id), pre_wire)
            }
        }
    }

    /// The answer a durable status owes a caller: the replay contract, reached from a status
    /// rather than from a `Decision`. It re-enters [`classify`]'s table for a write that was
    /// refused because the row is already terminal, and for a lookup of a row someone else
    /// closed; both must answer what an identical replay answers (`decision_outcome` is the shared
    /// table, and the `Adjudicated` arm reads the historical axis from the ledger, never from the
    /// status column, which cannot express it).
    ///
    /// Exhaustive on [`IntentStatus`]: a new status must take a position on what a caller meeting
    /// it is owed.
    fn status_replay_outcome(
        &mut self,
        idempotency_key: &str,
        status: &IntentStatus,
    ) -> Result<(), ExecuteError> {
        let terminal = match status {
            IntentStatus::Applied => Terminal::Applied,
            IntentStatus::Undone => Terminal::Undone,
            // The same fact-chain read `decide` takes for a `Failed` row, through the same projection,
            // so the refusal a dispatching call surfaces and the one an identical replay surfaces are the
            // same value (the Photon-local reference, not the provider-native atom). The row is read here
            // because only a plan-linked row pays for the plan arm's record.
            IntentStatus::Failed => {
                let plan_child = self
                    .log
                    .get(idempotency_key)
                    .map_err(ExecuteError::Log)?
                    .is_some_and(|intent| intent.command.plan_child.is_some());
                Terminal::Failed(self.failed_why(idempotency_key, plan_child).map_err(ExecuteError::Log)?)
            }
            IntentStatus::Severed => Terminal::Severed,
            IntentStatus::ExternallySatisfied => Terminal::ExternallySatisfied,
            IntentStatus::Adjudicated => Terminal::Adjudicated(
                self.log
                    .adjudicated_history(idempotency_key)
                    .map_err(ExecuteError::Log)?,
            ),
            // Non-terminal: recovery owns it, the same in-flight signal every park gives. Never a false
            // `Ok` for work that has not happened.
            IntentStatus::Pending
            | IntentStatus::Undoing
            | IntentStatus::EvidenceSnapshotWritten => return Err(ExecuteError::InProgress),
        };
        decision_outcome(Decision::TerminalReplay(terminal))
            .expect("a TerminalReplay decision always carries an outcome")
    }

    /// The verdict for an undo child this caller does not own: one authority, so the replay
    /// lookup and the lost-claim race cannot disagree.
    ///
    /// Non-terminal is `InProgress`, never a drive: `recover` owns in-flight children and is the
    /// only re-drive path that runs under a durable sweep rather than an unclaimed replay. Never a
    /// false `Ok` for an undo that has not happened.
    ///
    /// A wildcard mapping (`Applied` is `Ok`, `Failed` is `Err(Failed)`, anything else
    /// `InProgress`) was wrong for the terminals a child can reach without being `Applied` or
    /// `Failed`: a sever closes it `Severed`, an adjudication `Adjudicated`. Both fell into the
    /// wildcard and answered "in flight, recovery owns it", but a terminal child never appears in
    /// `unreconciled()`, so the caller would wait forever for an undo the ledger had closed.
    /// Routing through [`CommandBus::status_replay_outcome`] answers each honestly and matches
    /// what a replay of the child's own key reads.
    fn existing_undo_child_verdict(&mut self, child: &Intent) -> Result<(), ExecuteError> {
        self.status_replay_outcome(&child.command.idempotency_key, &child.status)
    }

    /// The undo verification write, in one place so the three verified outcomes (no-op kill,
    /// already-restored, restore applied) agree on heal order: parent `Undone` first, then the
    /// child's own terminal. A crash between them leaves the child `Pending` and the re-drive
    /// converges (see [`CommandBus::drive_undo_child`]).
    ///
    /// Neither write is unconditional. Both go through [`IntentLog::verify_undo_pair`], which
    /// commits the parent flip only alongside proof that the child is still open: the no-op
    /// lineage decides from a caller's stale child read, above the epoch check, and a sever in
    /// that window may already have terminalized the child. The pair moves together or not at
    /// all, and a pair that moved re-routes on its actual disposition.
    ///
    /// "Verified" is the connector's definitive `Ok` plus the child attempt's own verdict fact:
    /// `attempt` carries the claimed attempt when the drive took one. It is `None` for the two
    /// arms that verify before the claim (the no-op kill and the crash-convergence heal), which
    /// are wire-free and must not be gated by machinery that guards the wire.
    ///
    /// The verdict path writes the child's lifecycle (`Applied`) with the fact that justifies
    /// it; the parent's `Undone` is a separate write and stays first.
    ///
    /// The settlement's answer is not assumed. On the `AlreadyRestored` arm this is reached with
    /// a live pre-wire compare (this driver authorized nothing), so:
    ///
    /// * a peer that re-entered the same child attempt and authorized it makes the
    ///   compare-and-append lose: nothing is written, the child stays non-terminal, and the peer
    ///   is dispatching a restore. Reporting `Verified` would claim a completion the ledger does
    ///   not hold;
    /// * the chain may have been adjudicated mid-drive, so its own answer outranks this
    ///   verification (the `outranked` axis of [`DispatchSettlement`]), answered by the table
    ///   [`decision_outcome`] gives a replay.
    ///
    /// The parent flip stays first and is not gated on the settlement. Settling first and
    /// flipping on acceptance would strand the pair across a crash: the child terminal
    /// `Applied` with the parent still `Applied`, which nothing sweeps (both rows would be
    /// terminal, so the convergence short-circuit never runs) and which `undo_presentation`
    /// reads as `None`. The current order's crash window (parent `Undone`, child `Pending`) is
    /// the one the heal order is built for.
    ///
    /// The flip is honest regardless of who owns the attempt: on `AlreadyRestored` it rests on
    /// this driver's own verified observation that `C == P`, and on the restore arm on a restore
    /// it authorized and completed. Ownership governs what this driver may report, which is what
    /// is gated here.
    fn verify_undo(
        &mut self,
        parent_key: &str,
        child: &Intent,
        attempt: Option<&str>,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<UndoDriveOutcome, ExecuteError> {
        let child_key = child.command.idempotency_key.as_str();
        // The pair transition, guarded and atomic. The parent flip used to be an unconditional write
        // that ran first, so a child a sever had terminalized under this drive's read was buried by a
        // durable "the undo verified". Both preconditions now commit together
        // ([`IntentLog::verify_undo_pair`]), and a pair that moved re-routes on what it holds.
        let child_disposition = match attempt {
            // Attempt-carrying lineages: the child's terminal belongs to the verdict path, in the same
            // write as the fact that justifies it. This transition only requires the child still open.
            Some(_) => UndoPairChild::LeaveToSettlement,
            // Wire-free lineages hold no attempt, so there is no verdict to record and the pair write
            // is the whole settlement.
            None => UndoPairChild::Terminalize,
        };
        match self
            .log
            .verify_undo_pair(parent_key, child_key, child_disposition)
            .map_err(ExecuteError::Log)?
        {
            UndoPairFlip::Flipped => {}
            // Another authority closed the child (a sever, an adjudication, a peer's verdict). Nothing
            // was written, so the answer is that disposition's replay outcome.
            UndoPairFlip::ChildMoved(Some(status)) => {
                // The definitive ack this driver may be holding. One of those authorities is in-place
                // adjudication, which this arm may not simply report: an operator closing the child's
                // operational axis while our restore was on the wire is a legal race, and the provider then
                // answered definitively. Returning here skipped the verdict path, so the `Ok` never became
                // `LATE_ACK_APPLIED`: the historical axis stayed unknown, the exposure obligations stayed
                // live, and the parent stayed `Applied` over a restoration the provider had confirmed.
                //
                // So an attempt-bearing adjudicated child settles first, through [`CommandBus::settle_dispatch`]
                // (which turns a definitive verdict on an adjudicated chain into its `LATE_ACK_*`, reusing
                // the at-most-one-late-ack, exposure retirement, notice and undo-parent-flip machinery).
                // Only then is the replay outcome read, so it derives from the accepted late ack.
                //
                // The sibling arms are exempt by trace. A sever never closes an `ISSUED_OR_UNKNOWN` member
                // (non-issuance cannot be proven), so `Severed` cannot be reached from the `Restore` lineage,
                // the only one with a wire result to convert. The one interleave that reaches it holds a claim
                // that was never authorized (closed `SEVERED_BEFORE_ISSUANCE`) under the wire-free
                // `AlreadyRestored` verification, where no provider answer exists to settle. `Applied`,
                // `Undone`, `Failed` and `ExternallySatisfied` are each a peer's completed settlement, which
                // `settle_attempt` would answer `PostTerminalAppend`, as `status_replay_outcome` says on its
                // own.
                if let (IntentStatus::Adjudicated, Some(attempt_id)) = (&status, attempt) {
                    let settled = self
                        .settle_dispatch(
                            child_key,
                            attempt_id,
                            ConnectorVerdict::Applied,
                            pre_wire_at_revision,
                        )
                        .map_err(ExecuteError::Log)?;
                    if settled.superseded_pre_wire {
                        // A peer re-entered this attempt and authorized it before our pre-wire compare: nothing was
                        // written and no wire is ours. Park silently, unless that peer has since closed the child.
                        return self.undo_drive_park(child_key);
                    }
                }
                // The chain's truth, read back, including the late ack just accepted.
                self.status_replay_outcome(child_key, &status)?;
                // A terminal that maps to `Ok` (an `Applied` child, a resolved-applied adjudication) means
                // the verification already happened: converge on it.
                return Ok(UndoDriveOutcome::Verified);
            }
            // A vanished row, or a parent that is neither `Applied` nor already `Undone`: the store is
            // not what any code in this build wrote. Fail explicitly.
            UndoPairFlip::ChildMoved(None) => {
                return Err(ExecuteError::Log(LogError(format!(
                    "verify_undo: the undo child '{child_key}' vanished under its verification"
                ))))
            }
            UndoPairFlip::ParentMoved(actual) => {
                return Err(ExecuteError::Log(LogError(format!(
                    "verify_undo: the undo parent '{parent_key}' holds {actual:?}, which is \
                     neither `Applied` nor an already-verified `Undone`"
                ))))
            }
        }
        // Attempt-carrying lineages owe a verdict; wire-free ones hold no attempt, so the pair write
        // is their whole settlement.
        if let Some(attempt_id) = attempt {
                let settled = self
                    .settle_dispatch(
                        &child.command.idempotency_key,
                        attempt_id,
                        ConnectorVerdict::Applied,
                        pre_wire_at_revision,
                    )
                    .map_err(ExecuteError::Log)?;
                if settled.superseded_pre_wire {
                    // Nothing written, no wire touched, the attempt is the peer's. Park silently like every
                    // lost race, never claiming a verification this driver did not settle.
                    return self.undo_drive_park(&child.command.idempotency_key);
                }
                if let Some(history) = settled.outranked {
                    // The chain's own answer outranks this verification. A `ResolvedApplied` history used to
                    // fall through to `Verified`, reporting an ordinary verified restore for a child an
                    // adjudication had closed and a late ack had resolved, while a replay of the child's key says
                    // `AdjudicatedLate(Applied)`. Every answer propagates now; none is a plain success.
                    return Err(adjudicated_replay_outcome(history));
                }
                // The pair transition proved the child open, but the verdict path is a second transaction
                // and a sever can land between them; `settle_attempt`'s guards then write nothing while
                // `terminal` is true either way. So read back the child's actual disposition: a terminal
                // other than the `Applied` this verification claims is someone else's, and is what the caller
                // is owed.
                let actual = self
                    .log
                    .get(child_key)
                    .map_err(ExecuteError::Log)?
                    .map(|row| row.status);
                match actual {
                    Some(IntentStatus::Applied) | None => {}
                    Some(status) if status.is_terminal() => {
                        self.status_replay_outcome(child_key, &status)?;
                    }
                    // Still open: the settlement did not complete it (a retry gap, an `ISSUANCE_UNKNOWN`
                    // awaiting adjudication); the settlement's own axes above answer those.
                    Some(_) => {}
                }
        }
        Ok(UndoDriveOutcome::Verified)
    }

    /// The crash-convergence heal, through the attempt ledger.
    ///
    /// `verify_undo` flips the parent `Undone` first, then terminalizes the child. A crash between
    /// leaves the child `Pending` with the parent already flipped, and this converges it; the
    /// restore is moot because the parent is `Undone`.
    ///
    /// It must not write the terminal bare. A bare status write leaves the operation terminal and
    /// its attempt not, which breaks lifecycle atomicity: an unsettled attempt is still
    /// authorizable, so an equally-current driver could put a restore on the wire for an undo the
    /// ledger had closed. The mapping is per attempt state:
    ///
    /// * No live attempt (the no-op kill's lineage, or a drive that crashed before claiming):
    ///   nothing to settle, and the bare status write is correct here only.
    /// * Claimed, never authorized (the `AlreadyRestored` lineage): `ConnectorVerdict::Applied`
    ///   through the verdict path, which `verdict_mapping` resolves for an unauthorized attempt to
    ///   the pair this situation is: the attempt records `FAILED_PRE_SEND` (proven no-wire; it
    ///   produced no effect, and the objective holds because of a restore it never sent) and the
    ///   operation completes `Applied`, in one transaction. It is a pre-wire settlement, so it
    ///   compare-and-appends against the revision the class read was taken at; a peer that
    ///   re-entered and authorized in between makes it lose and park.
    /// * Authorized, unacked (`ISSUED_OR_UNKNOWN`): nothing is written and the drive parks, as
    ///   `boot_quarantine` does: non-issuance cannot be proven, so nothing is re-authorized,
    ///   re-dispatched or settled, and adjudication is the only way out. A bare terminal would
    ///   close the operation, so the row leaves `unreconciled()` and no sweep revisits it, and a
    ///   later [`IntentLog::adjudicate`] would append its record and exposure obligations but could
    ///   not move the status, leaving the lifecycle saying "this undo verified" over a chain that
    ///   says nobody knows. Parking keeps the operation open and its resource barrier raised. The
    ///   parent stays `Undone` regardless: the flip is justified by the verified restore, not by
    ///   who owns the attempt.
    fn converge_undo_child(&mut self, child: &Intent) -> Result<UndoDriveOutcome, ExecuteError> {
        let key = &child.command.idempotency_key;
        let live = self.log.live_attempt(key).map_err(ExecuteError::Log)?;
        let Some(live) = live else {
            // Guarded like every status write: the child read that reached here can be arbitrarily
            // old, and a sever that closed the child since holds the disposition, not this bare `Applied`.
            match self
                .log
                .set_status_if(key, StatusPrecondition::NonTerminal, IntentStatus::Applied)
                .map_err(ExecuteError::Log)?
            {
                StatusWrite::Written => return Ok(UndoDriveOutcome::Verified),
                StatusWrite::Refused(Some(status)) => {
                    // Someone else closed it; answer with that. A terminal that replays `Ok` (an `Applied`
                    // child a peer converged first) means this convergence is already done.
                    self.status_replay_outcome(key, &status)?;
                    return Ok(UndoDriveOutcome::Verified);
                }
                StatusWrite::Refused(None) => {
                    return Err(ExecuteError::Log(LogError(format!(
                        "converge_undo_child: the undo child '{key}' vanished under its heal"
                    ))))
                }
            }
        };
        // Park-over-terminal cannot happen here. This park is decided from a fact-derived class,
        // not a refusal, and `IssuedOrUnknown` means a `SEND_AUTHORIZED` with no terminal attribution
        // and no adjudication. The operation cannot be lifecycle-terminal then: `settle_attempt`
        // writes the terminal attribution and lifecycle in one transaction, adjudication moves the
        // class before the status, a sever's `IssuedOrUnknown` disposition leaves the operation
        // alive, and `dead_letter_if_quiescent` refuses over a live attempt. So "in flight" is true
        // until the attempt's owner or an operator closes it.
        if live.class == crate::attempt::AttemptClass::IssuedOrUnknown {
            return Err(ExecuteError::InProgress);
        }
        let settled = self
            .settle_dispatch(
                key,
                &live.attempt_id,
                ConnectorVerdict::Applied,
                Some(live.revision),
            )
            .map_err(ExecuteError::Log)?;
        if settled.superseded_pre_wire {
            // A peer re-entered this attempt and authorized it while we were reading: the attempt is
            // not ours to close and its restore is in flight. Park silently through the terminal-aware
            // answer, since that peer may have finished.
            return self.undo_drive_park(key);
        }
        if let Some(history) = settled.outranked {
            // Cannot occur: a `PreIssuance` attempt carries no adjudication, so no post-adjudication
            // refusal can meet this verdict. Handled rather than discarded anyway, since reading one axis
            // of a settlement and dropping the rest is the defect this change closes; the ledger's answer
            // wins.
            return Err(adjudicated_replay_outcome(history));
        }
        Ok(UndoDriveOutcome::Verified)
    }

    /// Undo-side failure reconciliation: the same deterministic-vs-transient boundary every
    /// dispatch path uses ([`CommandBus::reconcile_connector_failure`]), charged against the child
    /// row and attributed to the child's attempt. Children own their budget and can dead-letter:
    /// the parent was never pre-flipped, so a child `Failed` leaves the parent `Applied` with the
    /// failure surfaced.
    ///
    /// The settlement's other axes are answered here too (the helper used to discard them and
    /// report the connector error unconditionally):
    ///
    /// * The observe-failure site passes a live pre-wire compare, so a peer that re-entered the
    ///   same child attempt and authorized it makes the compare lose: nothing is written and the
    ///   peer owns the restore. The drive's other pre-wire arms already answer `InProgress` there.
    /// * Either site can meet a chain the operator adjudicated mid-drive, whose answer then
    ///   outranks this failure as it outranks a success ([`DispatchSettlement`]).
    fn reconcile_undo_connector_failure(
        &mut self,
        child: &Intent,
        attempt: Option<&str>,
        error: ConnectorError,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<UndoDriveOutcome, ExecuteError> {
        let key = child.command.idempotency_key.clone();
        let settled = self
            .reconcile_connector_failure(&key, attempt, &error, pre_wire_at_revision)
            .map_err(ExecuteError::Log)?;
        self.undo_settlement_outranks(settled, &key, error)
    }

    /// Terminalize the child on a deterministic undo-side refusal (mislink, basis rebind): child
    /// `Failed`, parent untouched (it stays `Applied`; the undo did not happen).
    ///
    /// Every such refusal is decided from local rows or a verified observation, before any
    /// authorization, so where an attempt exists it is settled through the verdict path with the
    /// honest attribution (`FAILED_PRE_SEND`, proven no wire), never a bare status write.
    /// `attempt` is `None` for the mislink check, which runs ahead of the claim.
    ///
    /// All three attempt-carrying sites are basis-rebind refusals passing a live pre-wire compare;
    /// without the settlement's axes this claimed a deterministic dead-letter the ledger does not
    /// hold over an attempt a peer had already authorized.
    fn terminalize_undo_deterministic(
        &mut self,
        child: &Intent,
        attempt: Option<&str>,
        error: ConnectorError,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<UndoDriveOutcome, ExecuteError> {
        let settled = match attempt {
            Some(attempt_id) => self
                .settle_dispatch(
                    &child.command.idempotency_key,
                    attempt_id,
                    ConnectorVerdict::Failed {
                        kind: error.kind,
                        evidence: error.effect_evidence,
                    },
                    pre_wire_at_revision,
                )
                .map_err(ExecuteError::Log)?,
            // Pre-claim (the mislink check): no attempt, so no verdict fact and neither attempt-shaped
            // axis exists.
            //
            // This goes through the same dead-letter path as the forward arm. It is the engine's other
            // no-attempt failure write, and `NonTerminal` answers "did someone close this row", never
            // "does a peer hold a live attempt on it". The refusal a live attempt earns cannot occur here:
            // a mislinked child is mislinked forever (`record()` immutability freezes both the child
            // command and the parent it is compared against), so every driver refuses at this check and
            // none claims. A no-attempt dead-letter spelled differently from its twin is how this family
            // of bugs returns. The answer is read from the store rather than predicted.
            None => {
                let key = child.command.idempotency_key.clone();
                let (terminal, preempted) = match self
                    .log
                    .dead_letter_if_quiescent(&key)
                    .map_err(ExecuteError::Log)?
                {
                    DeadLetterWrite::Written => (true, None),
                    // Reachable only with a terminal row (the guard is the non-terminal domain) or none at all.
                    DeadLetterWrite::StatusMoved(actual) => (actual.is_some(), actual),
                    DeadLetterWrite::LiveAttempt(_) => (false, None),
                };
                DispatchSettlement {
                    terminal,
                    superseded_pre_wire: false,
                    outranked: None,
                    preempted,
                }
            }
        };
        self.undo_settlement_outranks(settled, &child.command.idempotency_key.clone(), error)
    }

    /// The undo drive's single projection of a settlement onto its outcome, shared by both
    /// reconciliation paths above so they cannot answer the same settlement differently.
    ///
    /// The order matches `verify_undo`: preemption and supersession first (nothing was written, so
    /// there is no verdict to report; the row or the attempt is someone else's), then the chain's
    /// outranking answer (something was written, but not what this driver said), then this
    /// driver's own connector error.
    fn undo_settlement_outranks(
        &mut self,
        settled: DispatchSettlement,
        idempotency_key: &str,
        error: ConnectorError,
    ) -> Result<UndoDriveOutcome, ExecuteError> {
        if let Some(status) = settled.preempted {
            // The row was already terminal when this settlement tried to write it. The caller is owed
            // that disposition, not this driver's failure; an `Ok`-replaying terminal means done.
            self.status_replay_outcome(idempotency_key, &status)?;
            return Ok(UndoDriveOutcome::Verified);
        }
        if settled.superseded_pre_wire {
            // The lost pre-wire compare, answered from the row rather than assumed in-flight: the peer
            // that owns the attempt may have closed the child.
            return self.undo_drive_park(idempotency_key);
        }
        if let Some(history) = settled.outranked {
            // A `ResolvedApplied` chain says the restore landed, and the late-ack path already flipped
            // the parent in its own transaction, so the pair is settled either way. The caller is still
            // owed the chain's own answer, which names the adjudication route on all three histories
            // rather than collapsing the resolved-applied one into an ordinary `Verified`.
            return Err(adjudicated_replay_outcome(history));
        }
        Err(ExecuteError::Connector(error))
    }

    /// Re-dispatch every intent left `Pending` by a crash between write-ahead and reconcile.
    /// At-least-once: re-apply is safe because the command carries a stable idempotency key.
    /// Returns a [`RecoverReport`] of what the sweep did.
    pub fn recover(&mut self) -> Result<RecoverReport, ExecuteError> {
        let unreconciled = self.log.unreconciled().map_err(ExecuteError::Log)?;
        let mut report = RecoverReport::default();
        // Per-resource ordering barrier: once an intent on a resource fails in this sweep, defer
        // every later intent on the same resource (account plus message target). Applying a later
        // dependent intent while its predecessor is still `Pending` would reverse their causal order
        // on the next sweep. Independent resources keep flowing.
        let mut blocked: std::collections::HashSet<BarrierKey> = std::collections::HashSet::new();
        for intent in unreconciled {
            let key = intent.command.idempotency_key.clone();
            // BASIS-1 and the two-lane overlap: the barrier carries the same overlapping key set as the
            // head predicate (the frozen native resource key and the Photon-local `message_ref`), so a
            // mixed-generation pair on one message barriers in both directions. One key per intent was the
            // hole: a prepared stage-2 successor checked its native key, missed the legacy row's
            // `message_ref` barrier, and `ensure_prepared`'s already-prepared short-circuit dispatched it
            // past its failed predecessor in the same sweep. Check any of the intent's keys; on
            // failure or park, raise all of them.
            //
            // The key is a tagged [`BarrierKey`]: the native member carries no account, so two local
            // handles onto one provider resource raise the same native barrier, and the tag keeps a native
            // key and a local ref that spell the same text apart.
            let account = intent.command.account.clone();
            let local_ref = action_to_parts(&intent.command.action).1;
            let barrier_keys: Vec<BarrierKey> = match &intent.frozen_basis {
                Some(basis) => vec![
                    BarrierKey::Native(basis.native_resource_key.clone()),
                    BarrierKey::Local(account, local_ref),
                ],
                None => vec![BarrierKey::Local(account, local_ref)],
            };
            if barrier_keys.iter().any(|k| blocked.contains(k)) {
                // An earlier intent on this resource failed this sweep; applying this one now would reorder
                // the causal chain. Defer it: it stays non-terminal and recovers on the next sweep after its
                // predecessor succeeds. Never dispatched, so it is not a failure.
                continue;
            }
            // Pre-dispatch cap self-heal (backstop). The atomic charge makes increment plus terminalize
            // one write, but a legacy or corrupt row (or any future non-atomic path) already at or over
            // budget must be dead-lettered before dispatch, never re-dispatched over the cap. Undo
            // children are subject to it too: their budget is their own, and terminalizing one leaves the
            // parent `Applied`.
            if intent.attempts >= RETRY_CAP {
                // Facts first, in one transaction with the write: a dead-letter attributes no effect
                // (`Failed` says the operation had no effect), and the counter cannot support that claim
                // about an attempt this driver does not own. This used to ask two entry points, and a peer
                // that claimed and authorized between them put a mutation on the wire under a terminal its
                // ACK could never replace. The predicate and the transition are now the single write in
                // [`IntentLog::dead_letter_if_quiescent`].
                match self
                    .log
                    .dead_letter_if_quiescent(&key)
                    .map_err(ExecuteError::Log)?
                {
                    // Dead-lettered, or already settled by a better-attributed authority. This sweep acts on a
                    // read from the top of the loop, and a sever committing mid-sweep may have closed the row.
                    // Either way it is no longer an in-flight predecessor, so the sweep moves on without raising
                    // the barrier. (`StatusMoved` is reachable only with a terminal or absent row.)
                    DeadLetterWrite::Written | DeadLetterWrite::StatusMoved(_) => {}
                    // A peer holds this operation's dispatch (claimed, possibly already on the wire). It stays
                    // open and parks behind the barrier until its owner settles it or an operator adjudicates, as
                    // `claim_dispatch`'s ambiguity arm does.
                    DeadLetterWrite::LiveAttempt(_) => {
                        for k in &barrier_keys {
                            blocked.insert(k.clone());
                        }
                    }
                }
                continue;
            }
            // Dispatch the action for the in-progress state, then reconcile to the matching terminal.
            // Re-apply is safe under the stable idempotency key. `attempt` is the dispatch this sweep
            // owns, when it took one; the verdict recorded below belongs to it. `None` means the outcome
            // happened before any claim (the capture pipeline's own failure), with no attempt to
            // attribute to.
            let mut attempt: Option<String> = None;
            // The retry-requalification gate's own provider-read failure, carried out of the gate so it
            // lands in the sweep's single failure arm below rather than a second copy of the reconcile
            // boundary.
            let mut return_early_failure: Option<ConnectorError> = None;
            // The pre-wire compare this sweep carries: `Some(r)` from the claim until this sweep
            // authorizes, then `None`, because the at-most-one `SEND_AUTHORIZED` is the exclusivity. It
            // matters because the sweep is the engine's re-entry point: the claim can hand this driver an
            // attempt a peer already owns, and a pre-wire failure decided against the older chain must not
            // terminalize an attempt that peer has put on the wire.
            let mut sweep_pre_wire: Option<u64> = None;
            // What this sweep's dispatch observed at effect, carried to the success arm below.
            let mut sweep_witness: Option<EffectWitness> = None;
            let (dispatch, terminal) = match intent.status {
                // Legacy pre-stage-3 rows only: the old fast path stored `Undoing` on the parent and then
                // dispatched a blind inverse, so whether it landed is unknowable. Current code never writes
                // this status. Map the row back to the last verified truth and report it (never guess it
                // forward to `Undone`, never re-dispatch); the undo offer, if still open, is then available
                // through the new path.
                IntentStatus::Undoing => {
                    // Guarded, with the report following the write: a sever that closed this legacy row under
                    // the sweep's read holds the disposition, and naming a row in `legacy_undoing` that this sweep
                    // did not map would claim a repair it did not perform.
                    match self
                        .log
                        .set_status_if(
                            &key,
                            StatusPrecondition::Exactly(IntentStatus::Undoing),
                            IntentStatus::Applied,
                        )
                        .map_err(ExecuteError::Log)?
                    {
                        StatusWrite::Written => report.legacy_undoing.push(key.clone()),
                        StatusWrite::Refused(_) => {}
                    }
                    continue;
                }
                // An undo child goes through `drive_undo_child`, the same code `undo` runs, so it
                // requalifies at its own head moment against provider state as it is now. No blind inverse
                // ever reaches the wire from here.
                _ if intent.command.compensates.is_some() => {
                    match self.drive_undo_child(&intent) {
                        // Verified (restore applied, already-restored, or the no-op kill): the drive already
                        // flipped the parent and terminalized the child.
                        Ok(UndoDriveOutcome::Verified) => {
                            report.recovered += 1;
                            continue;
                        }
                        // A legacy pre-stage-3 deferred undo, mapped back to the last verified truth inside the
                        // drive (parent `Applied`, child `Failed`). Not a recovery (nothing was driven) and not a
                        // barrier (both rows are settled); it is reported so an operator sees the discarded
                        // compensation instead of a store that silently healed itself.
                        Ok(UndoDriveOutcome::LegacyMapped) => {
                            report.legacy_compensations.push(key.clone());
                            continue;
                        }
                        // Parked by the epoch check, or still behind a predecessor: non-terminal, so an in-flight
                        // predecessor that raises the barrier.
                        Err(ExecuteError::InProgress) => {
                            for k in &barrier_keys {
                                blocked.insert(k.clone());
                            }
                            continue;
                        }
                        // The budget was already charged inside the drive (on the child's own row); a
                        // still-retryable child raises the barrier like any transient forward failure, a
                        // dead-lettered one does not.
                        Err(ExecuteError::Connector(error)) => {
                            let now_failed = self
                                .log
                                .get(&key)
                                .map_err(ExecuteError::Log)?
                                .is_some_and(|i| i.status == IntentStatus::Failed);
                            if !now_failed {
                                for k in &barrier_keys {
                                    blocked.insert(k.clone());
                                }
                            }
                            // A run-ending connector error (a credential rejection) stops the whole sweep: every
                            // remaining unreconciled intent stays untouched. Continuing would keep spending calls on a
                            // credential known to be dead.
                            if error.credential_rejected {
                                report.stopped_by = Some((key.clone(), error.clone()));
                                report.failed.push((key, error));
                                return Ok(report);
                            }
                            report.failed.push((key.clone(), error));
                            continue;
                        }
                        // Undo conflict: a deterministic terminal decided inside the drive; the child is already
                        // `Failed` and the parent stays `Applied`. Resolved, so not a barrier, but surfaced: a batch
                        // caller must see the undo this sweep refused, so the child key goes in the report's
                        // `undo_conflicts`.
                        Err(ExecuteError::UndoConflict) => {
                            report.undo_conflicts.push(key.clone());
                            continue;
                        }
                        // Each of these errors is a terminal replay answer: the drive found this child already
                        // closed by someone else and reported what a replay of its key reports. They come from
                        // [`CommandBus::status_replay_outcome`] over a status some check proved terminal, or from
                        // [`adjudicated_replay_outcome`] over a chain adjudication has closed. A settled child is not
                        // an in-flight predecessor, so the sweep continues without a barrier, like the forward arm's
                        // `Terminal` and `Closed` answers.
                        //
                        // Without this arm, a peer's `sever()` landing between the `unreconciled()` snapshot and the
                        // child's epoch check made it answer `Err(Severed)`, and the fatal catch-all below let one
                        // ordinary concurrent terminalization abort recovery of every other operation in the pass
                        // (`a_severed_undo_child_never_aborts_the_recovery_sweep`).
                        //
                        // - `Severed`: the kill switch closed the child; nothing was dispatched.
                        // - `ExternallySatisfied`: the no-effect terminal a requalification writes when `C == A`.
                        // - `AdjudicatedUnresolved` / `AdjudicatedLate(_)`: closed by adjudication, with the
                        //   historical axis unknown or resolved by a late ack. A late ack resolves attribution and
                        //   never re-authorizes dispatch, so both stay terminal.
                        // - `Failed` / `ExposureBlocked{..}`: a dead-lettered child row read back through
                        //   `status_replay_outcome`. This drive's own failure arrives as `Connector(_)`, one arm up,
                        //   which owns the budget charge and barrier decision.
                        //
                        // Not counted as `recovered` (nothing was driven) nor `failed` (no `ConnectorError`). Other
                        // answers keep their own arms: `UndoConflict`, `InProgress` (still open, a real barrier),
                        // `Connector(_)`, and `Log`/`UndoUnavailable` (a store incident, fatal below).
                        Err(
                            ExecuteError::Severed
                            | ExecuteError::ExternallySatisfied
                            | ExecuteError::AdjudicatedUnresolved
                            | ExecuteError::AdjudicatedLate(_)
                            | ExecuteError::Failed
                            | ExecuteError::ExposureBlocked { .. },
                        ) => continue,
                        // A durable-log error (or an explicit journal gap) is not something a sweep may paper over:
                        // the store can no longer be trusted.
                        Err(other) => return Err(other),
                    }
                }
                // A forward intent clears the same capture pipeline `execute` runs before it may reach the
                // wire: unprepared means it cannot have dispatched, so observe, verify and PREPARE first;
                // prepared means it is never re-captured (a post-effect observation poisons no-op detection).
                _ => match self.ensure_prepared(&intent.command) {
                    Ok(PipelineVerdict::Proceed { capture }) => {
                        // BASIS-6 needs a basis. The wire is handed the admission-frozen identity instead of
                        // re-resolving one, so a row with none cannot be dispatched, and the answer is the one
                        // `requalify_retry_at_head` gives such a row: park. A NULL basis is reachable only on a legacy
                        // pre-stage-2 row, already an open-time integrity finding (`FrozenBasisMissing`); retiring
                        // that generation is that scan's call. It is still an in-flight predecessor, so the barrier
                        // rises like any park.
                        let Some(frozen_basis) = intent.frozen_basis.clone() else {
                            for k in &barrier_keys {
                                blocked.insert(k.clone());
                            }
                            continue;
                        };
                        // The dispatch claim, the forward sweep's path through the same shared step `execute` and
                        // the undo drive use. The observed episode is the one this sweep read: a stale sweep (another
                        // driver charged or settled the row under it) loses here instead of dispatching a decision
                        // about a world that has moved.
                        match self.claim_dispatch(&key, intent.attempts)? {
                            DispatchOwnership::Owned {
                                attempt_id,
                                ordinal,
                                observed_revision,
                                class,
                            } => {
                                sweep_pre_wire = Some(observed_revision);
                                // The capture this dispatch is bound to: the pipeline's answer for a first dispatch,
                                // replaced by the retry gate's own, which re-reads (or replaces) the row, so its generation
                                // is the one this sweep's decision was made against.
                                let mut capture = capture;
                                // The retry-requalification gate: the engine's forward-retry re-entry point. `execute`
                                // dispatches an operation once and never loops, so an ordinal above 1 can only be minted
                                // here, by the claim's retry-gap arm. A retry requalifies its pre-state at the head before the
                                // send-authorization check: the provider can have moved during the gap, and the captured `P`
                                // is frozen at the first pass.
                                //
                                // Only for an attempt that is provably wire-free. The ordinal alone was the wrong test: an
                                // ordinal>1 retry that crashes after its `SEND_AUTHORIZED` commits is handed back at its own
                                // ordinal by the claim's re-entry arm, so "ordinal > 1" was true of an attempt that may have
                                // spent the wire, and this gate's `C == A` arm then wrote `FAILED_PRE_SEND{ProvenNoWire}` plus
                                // `EXTERNALLY_SATISFIED` over a request that may have applied at the provider: a proof of
                                // non-issuance nobody has.
                                //
                                // The claim now reports which attempt this is, and the test is positive (`PreIssuance`), so an
                                // unrecognized class does not requalify. An `IssuedOrUnknown` attempt falls through to the
                                // send-authorization check, whose at-most-one `SEND_AUTHORIZED` refuses it
                                // (`DuplicateSendAuthorized`) and whose refusal path parks the still-active operation. That
                                // matches the boot quarantine's rule for an authorized-unacked attempt (never re-authorize,
                                // re-dispatch or settle it). Adjudication is the only way out, surfaced by `unknown_review`.
                                if ordinal > 1 && class == crate::attempt::AttemptClass::PreIssuance
                                {
                                    match self.requalify_retry_at_head(
                                        &intent,
                                        &attempt_id,
                                        observed_revision,
                                    )? {
                                        RetryGate::Proceed { capture: gate } => capture = gate,
                                        // `C == A`: already terminal, in one transaction, with nothing on the wire. Not a failure
                                        // and not a barrier; the operation is done.
                                        RetryGate::Closed => {
                                            report.recovered += 1;
                                            continue;
                                        }
                                        // Fail closed, and not a blind barrier. Both reachable sources of this park are refusals
                                        // ("some attempt is not provably wire-free"; "a peer authorized the attempt under our
                                        // pre-wire compare"), and a peer that took the attempt may have settled the operation while
                                        // this gate read the provider. A terminal row is not an in-flight predecessor.
                                        RetryGate::Park => {
                                            if self.terminal_disposition(&key)?.is_none() {
                                                for k in &barrier_keys {
                                                    blocked.insert(k.clone());
                                                }
                                            }
                                            continue;
                                        }
                                        // The gate's own provider read failed. Fold it into the sweep's single failure arm,
                                        // attributed to the attempt this sweep owns, so the budget is charged once by the one
                                        // reconcile boundary.
                                        RetryGate::Failed(error) => {
                                            attempt = Some(attempt_id.clone());
                                            return_early_failure = Some(error);
                                        }
                                    }
                                }
                                if let Some(error) = return_early_failure {
                                    (Err(ExecuteError::Connector(error)), IntentStatus::Applied)
                                } else {
                                // Send authorization, immediately before this sweep's socket. The BASIS-6 statement is the
                                // same as `execute`'s (they share `ensure_prepared`). It must be here rather than at capture
                                // because a sweep's decision can be arbitrarily old by the time it reaches the wire, and the
                                // authority is the last pre-wire boundary.
                                match self.authorize_dispatch(&key, &attempt_id, capture)? {
                                    DispatchAuthorization::Authorized => {}
                                    // Closed by the refusing transaction. A terminal row is not an in-flight predecessor, so
                                    // the sweep moves on without raising the barrier. Raising it deferred every later intent on
                                    // the resource behind a row that had left `unreconciled()` forever.
                                    DispatchAuthorization::Terminal(_) => continue,
                                    // Superseded while still open: not ours to dispatch, and an in-flight predecessor. Raise
                                    // the barrier like any park and keep sweeping.
                                    DispatchAuthorization::Park => {
                                        for k in &barrier_keys {
                                            blocked.insert(k.clone());
                                        }
                                        continue;
                                    }
                                }
                                // We own the wire now: drop the pre-wire compare (see the local's note). The chain may
                                // legally move under a dispatch in flight.
                                sweep_pre_wire = None;
                                attempt = Some(attempt_id);
                                (
                                    // The frozen identity goes to the wire: the same value the exposure check and the
                                    // `SEND_AUTHORIZED` payload were derived from (BASIS-6: dispatch never re-resolves).
                                    self.connector
                                        .apply_witnessed(&intent.command, &frozen_basis)
                                        .map(|witness| sweep_witness = Some(witness))
                                        .map_err(ExecuteError::Connector),
                                    IntentStatus::Applied,
                                )
                                }
                            }
                            // Closed under this sweep's read. A terminal row has left `unreconciled()` forever, so the
                            // sweep moves on without raising the barrier, as the authorization arm does.
                            DispatchOwnership::Terminal(_) => continue,
                            // Not ours and still open: another driver owns it, or an unknown awaits adjudication. An
                            // in-flight predecessor like any park: raise the barrier and keep sweeping.
                            DispatchOwnership::Park => {
                                for k in &barrier_keys {
                                    blocked.insert(k.clone());
                                }
                                continue;
                            }
                        }
                    }
                    Ok(PipelineVerdict::Park) => {
                        // Not at head, or epoch-fenced: leave it `Pending` and keep sweeping. It is still an
                        // in-flight predecessor, so raise the barrier; a later same-resource intent that is already
                        // prepared must not overtake it. "Still `Pending`" is guaranteed because PREPARE refuses a
                        // non-pre-dispatch row with an error before it can answer either park (see
                        // [`CommandBus::ensure_prepared`]).
                        for k in &barrier_keys {
                            blocked.insert(k.clone());
                        }
                        continue;
                    }
                    // Closed under this sweep's own capture: a sever, or a peer driver's settlement, committed
                    // between this sweep's `unreconciled()` read and PREPARE's transaction. A terminal row is not
                    // an in-flight predecessor, so the sweep moves on without raising the barrier. It is not
                    // counted: this sweep recovered nothing and failed at nothing. The refusal used to be a
                    // `LogError`, which the catch-all below treats as fatal, so one legitimately closed operation
                    // aborted recovery of every other operation in the pass.
                    Ok(PipelineVerdict::Closed(_)) => continue,
                    // A capture failure is a connector failure on this intent: fold it into the sweep's single
                    // failure arm below, which charges the retry budget once.
                    Err(err) => (Err(err), IntentStatus::Applied),
                },
            };
            match dispatch {
                Ok(()) => {
                    // Forward intents only: an undo child never reaches this arm (it returned out of the
                    // drive above, which heals at verification).
                    //
                    // The success verdict: `ACK_APPLIED` and the terminal status in one write. A sweep that
                    // reached this arm always owns an attempt (the claim is the only road to the socket); the
                    // fallback below is the shape a future non-claiming success path would take, and writes no
                    // verdict it cannot justify.
                    let outranked = match attempt.as_deref() {
                        Some(attempt_id) => {
                            // Post-authorization: this sweep holds the attempt's own `SEND_AUTHORIZED`, so no pre-wire
                            // compare is passed and `superseded_pre_wire` cannot occur.
                            self.settle_dispatch(&key, attempt_id, ConnectorVerdict::Applied, None)
                                .map_err(ExecuteError::Log)?
                                .outranked
                        }
                        None => {
                            // Guarded like every status write. Documented as unreachable (a sweep that reached the
                            // socket owns an attempt); a refusal here would mean the row was closed under the dispatch,
                            // which this sweep may not count as a recovery.
                            let _wrote = self
                                .log
                                .set_status_if(
                                    &key,
                                    StatusPrecondition::NonTerminal,
                                    terminal.clone(),
                                )
                                .map_err(ExecuteError::Log)?;
                            None
                        }
                    };
                    // The same persistence `execute` performs, through the same helper, but non-fatal here
                    // too: the settlement above already committed this intent `Applied`, so a `?` would abort
                    // the whole sweep and strand every later intent over a fact (the witness) that does not
                    // change what durably happened. `report.recovered` still counts it; only the witness write
                    // failed.
                    if let Some(witness) = sweep_witness.take() {
                        if let Err((_failure, _store_error)) = self.persist_effect_witness_step(&key, &witness) {
                            report.witness_write_failed.push(key.clone());
                        }
                    }
                    // An adjudication landed while this dispatch was in flight and the chain's own answer
                    // outranks this sweep's. The ledger holds the honest record, but this sweep did not recover
                    // the operation, and counting it would report a success the ledger contradicts. (`failed`
                    // carries a `ConnectorError` and there is none here: the provider answered, the chain
                    // disagreed.)
                    if outranked.is_none() {
                        report.recovered += 1;
                    }
                }
                // Reconcile the connector failure against the intent's lifecycle, with the same
                // `FailureKind` decision as `execute` (ADR-P013 (b)): deterministic dead-letters immediately;
                // transient charges the retry budget and dead-letters only on exhaustion. Then:
                // - Dead-lettered (terminal `Failed`): do not raise the barrier; a terminal intent is not an
                //   in-flight predecessor. (Accepted limitation: a later intent causally dependent on a
                //   dead-lettered predecessor proceeds independently; cross-intent dependency is deferred
                //   saga work, per the ADR-P013 (c) scope fence.)
                // - Still retryable: leave it non-terminal for the next sweep and raise the barrier so later
                //   same-resource intents defer behind it.
                // Either way it failed this sweep, so it is reported.
                Err(ExecuteError::Connector(error)) => {
                    // No compensation exemption survives here: the old undo path pre-flipped the original
                    // `Undone` at scheduling, so dead-lettering a compensation would have made the log lie, and
                    // the exemption existed only to cover that. Undo children reconcile inside the drive on their
                    // own budget, and nothing else carries a `compensates` link.
                    //
                    // This arm asks one question that answers all settlement axes: is the row still an in-flight
                    // predecessor? `terminal` answers it truthfully under every outcome because it is read back
                    // from the store. A lost pre-wire compare wrote nothing, so the row is whatever the winning
                    // peer left; an outranked settlement means the operation was adjudicated, which is terminal.
                    // The barrier decision below is right in both cases, and neither is reported as this sweep's
                    // own disposition: `report.failed` carries the connector error this sweep met, and the
                    // recovery count is not incremented on any failure arm.
                    let settled = self
                        .reconcile_connector_failure(
                            &key,
                            attempt.as_deref(),
                            &error,
                            sweep_pre_wire,
                        )
                        .map_err(ExecuteError::Log)?;
                    if !settled.terminal {
                        for k in &barrier_keys {
                            blocked.insert(k.clone());
                        }
                    }
                    // The same run-ending stop as the undo-child arm above: a credential rejection ends the
                    // sweep, leaving every later unreconciled intent untouched.
                    if error.credential_rejected {
                        report.stopped_by = Some((key.clone(), error.clone()));
                        report.failed.push((key, error));
                        return Ok(report);
                    }
                    report.failed.push((key, error));
                }
                // A durable-log error is fatal: the store can no longer be trusted.
                Err(other) => return Err(other),
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_grows_exponentially_and_is_capped() {
        // ADR-P013 (b): transient retries wait an exponentially-growing delay (base * 2^(n-1)) so a
        // struggling provider is backed off, not hammered — capped so the delay never grows
        // unbounded. This is the reserved schedule the future recovery scheduler consults; M0 has no
        // clock wired to it yet (and full jitter is added with that scheduler). PURE + deterministic.
        use std::time::Duration;
        assert_eq!(backoff_delay(1), Duration::from_secs(1), "first retry waits the base delay");
        assert_eq!(backoff_delay(2), Duration::from_secs(2));
        assert_eq!(backoff_delay(3), Duration::from_secs(4));
        assert_eq!(backoff_delay(4), Duration::from_secs(8));
        assert_eq!(backoff_delay(100), BACKOFF_CAP, "a large attempt count is capped, not unbounded");
        assert_eq!(backoff_delay(0), Duration::from_secs(1), "attempts=0 is defensive: base, never zero/panic");
    }
}
