//! The plan surfaces: the wire shapes, the refusal maps, the driver, and the commands that run them.

use serde::{Deserialize, Serialize};

use aruna::config_knobs::{ApprovalModeKnob, BackupsKnob, KnobAct, RedBypassKnob};
use aruna::episode::Completion;
use aruna::plan::{
    AdmissionLane, AggregateRender, ApprovalMode, MemberState, PlanId, PlanPresentation, PlanSpec,
    PlanVerb, PreflightOutcome, PresentationHeader, PresentationRow, PresentationSummary,
    RenderedView,
};
use aruna::{CommandBus, Connector, ExecuteError, Executed, IntentLog, WitnessRecord};

use crate::error::{run_ending_connector_disposition, MemberDiffView, PlanWireToken, SurfaceError};
use crate::ipc::{ProjectionState, RestorationView};
use crate::plumbing::{admit_provider, lock_bus, with_provider};
use crate::provider::mutation_fence;
use crate::session::PhotonSession;
use crate::single_flight::{InFlight, InFlightClaim, OperationKind};
use crate::state::PhotonState;
use crate::verbs::{projection_after_effect, restoration_after_verb};

/// How long a minted plan's approval window stays open (`PlanSpec::ttl_seconds`): 24 hours. The
/// design names no TTL, only the strict `expires_at` boundary (`effective_now < expires_at`,
/// bound into the plan and re-verified in every child's send transaction), so the length is a
/// choice made here, in one constant.
pub const PLAN_TTL_SECONDS: u64 = 24 * 3600;
const _: () = assert!(
    PLAN_TTL_SECONDS > 0,
    "a plan born expired is not a plan (PlanStoreError::TtlZero)"
);

/// The canonical presentation's header (`aruna::plan::PresentationHeader`), field by field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanHeaderView {
    /// The Photon account partition the plan is for, never the provider principal.
    pub account: String,
    /// `trash` | `mark_spam` (`PlanVerb::as_token`).
    pub verb: String,
    pub tier: String,
    pub count: u32,
    pub backup_coverage: bool,
    /// The verb-specific warning, present exactly when `backup_coverage` is false.
    pub warning: Option<String>,
}

/// The canonical presentation's summary (`aruna::plan::PresentationSummary`), field by field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummaryView {
    pub count: u32,
    /// `(domain, count)`, in the engine's order (count descending, then domain bytes), parsed
    /// senders' domains only.
    pub sender_domains: Vec<(String, u32)>,
    /// Members whose From header was absent or empty — "sender domain unavailable for N members".
    pub sender_domain_unavailable: u32,
    /// Members whose From header does not parse under the grammar at all — "malformed sender
    /// header for N members — normalized text shown".
    pub sender_header_malformed: u32,
    /// Members whose From header parses but is not exactly one mailbox (a group or a mailbox list
    /// of more than one): "valid sender syntax Photon does not attribute for N members (group or
    /// multiple mailboxes) — no sender address".
    pub sender_header_unsupported: u32,
    pub date_min: String,
    pub date_max: String,
    pub total_size: Option<u64>,
}

/// One canonical row (`aruna::plan::PresentationRow`): the display the plan froze at mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRowView {
    pub message_ref: String,
    pub sender: String,
    /// The address half, frozen and carried separately from `sender`. The renderer isolates both
    /// in their own `<bdi>`, like the inbox row's `from_name`/`from_addr`.
    pub sender_address: String,
    /// The frozen member's sender status token. The renderer shows a non-`ok` status outside the
    /// address isolate, as its own element, never as synthesized text inside it.
    pub sender_status: String,
    /// The addr-spec's local part alone (empty unless `sender_status == "ok"`). The renderer
    /// places it in the local `<bdi>` and never derives the local/domain boundary by searching
    /// `sender_address` for an `@` (a domain-literal may carry its own `@`).
    pub sender_local: String,
    /// The addr-spec's domain half alone (empty unless `sender_status == "ok"`), for the domain
    /// `<bdi>`. See `sender_local`.
    pub sender_domain: String,
    pub subject: String,
    pub date: String,
    pub size: Option<u64>,
}

/// The canonical presentation, verbatim (`PlanPresentation`): what the renderer shows and hands
/// back on approve. Rows are in the plan's canonical order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPresentationView {
    pub header: PlanHeaderView,
    pub summary: PlanSummaryView,
    pub rows: Vec<PlanRowView>,
}

impl From<PresentationHeader> for PlanHeaderView {
    fn from(h: PresentationHeader) -> Self {
        Self {
            account: h.account,
            verb: h.verb.as_token().to_string(),
            tier: h.tier,
            count: h.count,
            backup_coverage: h.backup_coverage,
            warning: h.warning,
        }
    }
}

impl From<PresentationSummary> for PlanSummaryView {
    fn from(s: PresentationSummary) -> Self {
        Self {
            count: s.count,
            sender_domains: s.sender_domains,
            sender_domain_unavailable: s.sender_domain_unavailable,
            sender_header_malformed: s.sender_header_malformed,
            sender_header_unsupported: s.sender_header_unsupported,
            date_min: s.date_min,
            date_max: s.date_max,
            total_size: s.total_size,
        }
    }
}

impl From<PresentationRow> for PlanRowView {
    fn from(r: PresentationRow) -> Self {
        Self {
            message_ref: r.message_ref,
            sender: r.sender,
            sender_address: r.sender_address,
            sender_status: r.sender_status,
            sender_local: r.sender_local,
            sender_domain: r.sender_domain,
            subject: r.subject,
            date: r.date,
            size: r.size,
        }
    }
}

impl From<PlanPresentation> for PlanPresentationView {
    fn from(p: PlanPresentation) -> Self {
        Self {
            header: p.header.into(),
            summary: p.summary.into(),
            rows: p.rows.into_iter().map(PlanRowView::from).collect(),
        }
    }
}

/// The approve command's answer when what the renderer handed back is not the plan's view. It is
/// the send fence's own token for the same fact (`PlanSendRefusal::EvidenceInvalid`).
fn evidence_invalid() -> SurfaceError {
    SurfaceError::plan_whole(PlanWireToken::EvidenceInvalid)
}

impl PlanHeaderView {
    /// Back into the engine's header, field by field. A verb the engine does not know cannot be a
    /// view any plan had, so it is `evidence_invalid`, never a guessed verb.
    fn into_engine(self) -> Result<PresentationHeader, SurfaceError> {
        Ok(PresentationHeader {
            account: self.account,
            verb: PlanVerb::from_token(&self.verb).map_err(|_| evidence_invalid())?,
            tier: self.tier,
            count: self.count,
            backup_coverage: self.backup_coverage,
            warning: self.warning,
        })
    }
}

impl From<PlanSummaryView> for PresentationSummary {
    fn from(s: PlanSummaryView) -> Self {
        Self {
            count: s.count,
            sender_domains: s.sender_domains,
            sender_domain_unavailable: s.sender_domain_unavailable,
            sender_header_malformed: s.sender_header_malformed,
            sender_header_unsupported: s.sender_header_unsupported,
            date_min: s.date_min,
            date_max: s.date_max,
            total_size: s.total_size,
        }
    }
}

impl From<PlanRowView> for PresentationRow {
    fn from(r: PlanRowView) -> Self {
        Self {
            message_ref: r.message_ref,
            sender: r.sender,
            sender_address: r.sender_address,
            sender_status: r.sender_status,
            sender_local: r.sender_local,
            sender_domain: r.sender_domain,
            subject: r.subject,
            date: r.date,
            size: r.size,
        }
    }
}

impl PlanPresentationView {
    fn into_engine(self) -> Result<PlanPresentation, SurfaceError> {
        Ok(PlanPresentation {
            header: self.header.into_engine()?,
            summary: self.summary.into(),
            rows: self.rows.into_iter().map(PresentationRow::from).collect(),
        })
    }
}

/// The plan's frozen admission lane (`aruna::plan::AdmissionLane`): the screen the renderer owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneView {
    PerMember,
    Aggregate,
    Bypassed,
}

/// What `plan_mint` / `plan_review` answer: the canonical presentation and, for the aggregate
/// lane, the derived sample. No plan digest or randomizer crosses; the renderer gets rows and
/// hands rows back, and the engine recomputes the commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanReviewView {
    pub plan_id: String,
    pub lane: LaneView,
    pub presentation: PlanPresentationView,
    /// Aggregate lane only: the plan's `effective_k`.
    pub sample_k: Option<u32>,
    /// Aggregate lane only: the derived sample (`aruna::plan::derive_sample`), each row the
    /// canonical row for its ref, in derived order.
    pub sample_rows: Option<Vec<PlanRowView>>,
    /// RFC 3339 UTC: the end of the approval window.
    pub expires_at: String,
    pub approved: bool,
    /// The plan's episode is terminal (completed, cancelled or invalidated), so no apply can run
    /// it again. An approved plan that is not terminal (approved and never applied, or a run that
    /// stopped before every member was attempted) can be applied again, and the review offers
    /// that as its control.
    pub terminal: bool,
    /// The plan's frozen bypass-lane notice (`TriagePlan::bypass_notice`, the value
    /// `MintedPlan::bypass_notice` hands the mint's caller): the verb's uncovered-backup warning,
    /// present exactly when the plan froze the `bypassed` lane under `backups: off` (the bypass
    /// waives the screen, never the notice). The renderer shows it as a non-blocking line before
    /// the apply; `None` on every other plan.
    pub bypass_notice: Option<String>,
}

/// What the renderer says it showed (the echo the engine commits against). `full_list` carries
/// the presentation it rendered; `aggregate` the header, summary and sample it rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RenderedViewWire {
    FullList {
        presentation: PlanPresentationView,
    },
    Aggregate {
        header: PlanHeaderView,
        summary: PlanSummaryView,
        sample_k: u32,
        sample_rows: Vec<PlanRowView>,
    },
}

impl RenderedViewWire {
    /// Into the engine's `RenderedView`, field by field and row by row, with no reordering or
    /// substitution: the engine must receive what the renderer said it showed.
    fn into_engine(self) -> Result<RenderedView, SurfaceError> {
        Ok(match self {
            RenderedViewWire::FullList { presentation } => {
                RenderedView::FullList(presentation.into_engine()?)
            }
            RenderedViewWire::Aggregate {
                header,
                summary,
                sample_k,
                sample_rows,
            } => RenderedView::Aggregate(AggregateRender {
                header: header.into_engine()?,
                summary: summary.into(),
                sample_k,
                sample_rows: sample_rows.into_iter().map(PresentationRow::from).collect(),
            }),
        })
    }
}

/// What `plan_approve` answers: the evidence's comprehension token (`per_member` | `aggregate` |
/// `bypassed`) and the approver it recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanApproveOutcome {
    pub plan_id: String,
    pub comprehension: String,
    pub approver: String,
}

/// One member's state (`aruna::plan::MemberState`, the minimal read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MemberStateView {
    NotMinted,
    InFlight,
    Applied,
    /// The send fence refused the child: the engine's token and (for `state_diverged`) the diff.
    Refused {
        reason: String,
        diff: Vec<MemberDiffView>,
    },
    /// Any other terminal status, by its lifecycle token.
    Terminal { status: String },
}

impl From<MemberState> for MemberStateView {
    fn from(s: MemberState) -> Self {
        match s {
            MemberState::NotMinted => MemberStateView::NotMinted,
            MemberState::InFlight => MemberStateView::InFlight,
            MemberState::Applied => MemberStateView::Applied,
            MemberState::Refused { reason, diff } => MemberStateView::Refused {
                reason,
                diff: diff.into_iter().map(MemberDiffView::from).collect(),
            },
            // The engine's own durable spelling (`aruna::status_to_str`) — one map, no shell copy.
            MemberState::Terminal(status) => MemberStateView::Terminal {
                status: aruna::status_to_str(&status).to_string(),
            },
        }
    }
}

/// What the preflight decided (`aruna::plan::PreflightOutcome`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PreflightView {
    Ready,
    /// The whole run was refused: these members diverged, each with its atom diff.
    Refused {
        diverged: Vec<(String, Vec<MemberDiffView>)>,
    },
    /// Another driver already crossed the barrier; the per-child recheck owns staleness.
    Raced,
}

impl From<PreflightOutcome> for PreflightView {
    fn from(p: PreflightOutcome) -> Self {
        match p {
            PreflightOutcome::Ready => PreflightView::Ready,
            PreflightOutcome::Refused { diverged } => PreflightView::Refused {
                diverged: diverged
                    .into_iter()
                    .map(|(member, diff)| {
                        (member, diff.into_iter().map(MemberDiffView::from).collect())
                    })
                    .collect(),
            },
            PreflightOutcome::Raced { .. } => PreflightView::Raced,
        }
    }
}

/// One applied plan member's undo offer: the member, the key the existing `undo` command undoes
/// it by, and the restoration verdict its effect witness allows. The verdict is read when the run
/// ends, right after the member applied (`restoration_after_verb`), so it travels with the offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanUndoKeyView {
    pub member_ref: String,
    pub undo_key: String,
    /// `None` only if the child's forward effect has not landed, never for an applied member; a
    /// failed witness read is `unreadable`, not an absent offer.
    pub restoration: Option<RestorationView>,
}

/// What `plan_apply` answers: the preflight, every member's state in canonical order, the
/// episode's completion token, and the local projection's honesty (the same dual outcome
/// `VerbOutcome` carries). When the run stopped before every member was attempted, it also says
/// why: a run-ending error never discards what the run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanApplyOutcome {
    pub plan_id: String,
    /// `None` = the run stopped before the preflight decided (its reason is `stopped`).
    pub preflight: Option<PreflightView>,
    pub members: Vec<(String, MemberStateView)>,
    /// `completed` | `incomplete` | `invalidated:<reason kind>` | the status token of an episode
    /// that was already terminal | `no_episode`.
    pub completion: String,
    pub projection: ProjectionState,
    /// Members whose child was already settled (applied, refused, any other terminal status) when
    /// this run reached them: skipped, never re-driven. Their state is in `members`.
    pub skipped: Vec<String>,
    /// Members whose child was in flight (held) when this run reached them: re-driven through
    /// `CommandBus::recover`. What that left is their state in `members`.
    pub held: Vec<String>,
    /// One offer per applied member ([`PlanUndoKeyView`]), in reverse canonical order, the order
    /// the renderer's undo walks them (one `undo` call per child, last first). A refused, held or
    /// unminted member has no offer: nothing of it landed to undo.
    pub undo_keys: Vec<PlanUndoKeyView>,
    /// The plan's frozen bypass-lane notice ([`PlanReviewView::bypass_notice`]), carried so the
    /// outcome toast repeats it.
    pub bypass_notice: Option<String>,
    /// The refusal that ended the run before every member was attempted: one that recorded
    /// nothing for the member it met (an episode no longer active, a basis that would not
    /// resolve, a capacity refusal, an auth-class preflight read), or a store error. It is
    /// carried beside everything the run did do. `None` means the run went to its end. A stop does
    /// not close the episode, so the approved plan can be applied again.
    pub stopped: Option<SurfaceError>,
}

/// The wire completion of a run whose post-run settle failed. The run could not read what the
/// episode became, so it names none (never a guessed `incomplete` or `completed`). The renderer
/// treats it as not an ended episode (`src/state.ts` `reopensReviewAfterRun`).
const COMPLETION_UNDETERMINED: &str = "undetermined";

fn completion_token(c: &Completion) -> String {
    match c {
        Completion::Completed => "completed".to_string(),
        Completion::Incomplete { .. } => "incomplete".to_string(),
        Completion::Invalidated(reason) => format!("invalidated:{}", reason.kind()),
        Completion::AlreadyTerminal(status) => status.as_token().to_string(),
        Completion::NoEpisode => "no_episode".to_string(),
    }
}

/// The typed knob command's act (`aruna::config_knobs::KnobAct`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnobActWire {
    Backups { on: bool },
    RedBypass { on: bool },
    /// `mode`: `full_list` | `summary_sample`; `configured_k` only (and required) with
    /// `summary_sample`, and at least 1 — the knob's own reader decides.
    ApprovalMode {
        mode: String,
        configured_k: Option<u32>,
    },
}

/// What `set_knob` answers: the `engine_config` generation the act landed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnobOutcome {
    pub generation: u64,
}

/// The wire act, as the engine's typed act. The approval mode goes through the knob's own strict
/// reader (`ApprovalModeKnob::from_engine_payload`), so an unknown mode, a missing or zero
/// `configured_k`, or a `configured_k` on `full_list` is refused with the reader's sentence and
/// nothing is appended.
fn knob_act_from_wire(act: KnobActWire) -> Result<KnobAct, SurfaceError> {
    Ok(match act {
        KnobActWire::Backups { on } => {
            KnobAct::Backups(if on { BackupsKnob::On } else { BackupsKnob::Off })
        }
        KnobActWire::RedBypass { on } => {
            KnobAct::RedBypass(if on { RedBypassKnob::On } else { RedBypassKnob::Off })
        }
        KnobActWire::ApprovalMode { mode, configured_k } => {
            let payload = match configured_k {
                None => serde_json::json!({ "mode": mode }),
                Some(k) => serde_json::json!({ "mode": mode, "configured_k": k }),
            };
            KnobAct::ApprovalMode(
                // Terminal: a malformed knob payload is a deterministic parse failure, and
                // retrying the identical payload cannot succeed.
                ApprovalModeKnob::from_engine_payload(&payload.to_string()).map_err(|e| {
                    SurfaceError::Refused {
                        reason: e.to_string(),
                        terminal: true,
                    }
                })?,
            )
        }
    })
}

/// A pure-core plan refusal as its token, one per variant.
fn plan_refusal_token(r: &aruna::plan::PlanRefusal) -> PlanWireToken {
    use aruna::plan::PlanRefusal as R;
    use PlanWireToken as T;
    match r {
        R::EmptyMembers => T::EmptyMembers,
        R::ConflictingDuplicate(_) => T::ConflictingDuplicate,
        R::HeaderCountMismatch { .. } => T::HeaderCountMismatch,
        R::WarningShape(_) => T::WarningShape,
        R::HeaderDiverges(_) => T::HeaderDiverges,
        R::PresentationRowCount { .. } => T::PresentationRowCount,
        R::PresentationRowDiverges(_) => T::PresentationRowDiverges,
        R::ConfiguredKZero => T::ConfiguredKZero,
        R::Commitment(_) => T::Commitment,
        R::LaneMismatch { .. } => T::LaneMismatch,
        R::PlanIdMismatch { .. } => T::PlanIdMismatch,
        R::ApproverMissing => T::ApproverMissing,
        R::ViewMismatch => T::ViewMismatch,
        R::SampleMismatch(_) => T::SampleMismatch,
        R::SampleKMismatch { .. } => T::SampleKMismatch,
        R::BypassGenerationMismatch { .. } => T::BypassGenerationMismatch,
        R::UnknownVerb(_) => T::UnknownVerb,
        R::PlanShape(_) => T::PlanShape,
    }
}

/// The plan store's refusals, by name. An approval whose evidence does not validate (the rendered
/// view is not the plan's, the sample is not the derived one, the lane, k or plan disagree, no
/// approver) is the whole-plan `evidence_invalid` refusal. A bypass-lane plan whose bypass knob
/// moved since mint gets its own whole-plan token, `bypass_generation_mismatch`, whose cure is a
/// re-plan and whose copy says so. Every other refusal is `PlanChildRefused` with its token; a
/// store failure (including a knob act in force that its reader refuses) is `Store`; the two TTL
/// refusals keep the store's sentence.
fn plan_store_error(e: aruna::plan::PlanStoreError) -> SurfaceError {
    use aruna::plan::{PlanRefusal as R, PlanStoreError as E};
    use PlanWireToken as T;
    let token = match e {
        E::Refused(R::BypassGenerationMismatch { .. }) => {
            return SurfaceError::plan_whole(T::BypassGenerationMismatch)
        }
        E::Refused(
            R::ViewMismatch
            | R::SampleMismatch(_)
            | R::SampleKMismatch { .. }
            | R::LaneMismatch { .. }
            | R::PlanIdMismatch { .. }
            | R::ApproverMissing,
        ) => return evidence_invalid(),
        E::Refused(ref r) => plan_refusal_token(r),
        E::UnknownMember(_) => T::UnknownMember,
        E::PlanNotFound(_) => T::NoPlan,
        E::AlreadyApproved => T::AlreadyApproved,
        E::EpochMismatch { .. } => T::EpochMismatch,
        E::Expired { .. } => T::Expired,
        E::Knob(_) => {
            return SurfaceError::Store {
                reason: e.to_string(),
            }
        }
        E::Store(reason) => return SurfaceError::Store { reason },
        // Terminal: a deterministic TTL configuration error; retrying the identical mint request
        // cannot succeed.
        E::TtlZero | E::TtlOutOfRange => {
            return SurfaceError::Refused {
                reason: e.to_string(),
                terminal: true,
            }
        }
    };
    SurfaceError::plan_child(token)
}

/// `IntentLog::start_episode`'s refusals, by name: the tokens a plan child's refusal already
/// spells for the same facts (`no_plan`, `not_approved`, `epoch_mismatch`, `expired`) and the
/// send fence's for a terminal or paused episode (`episode_closed`, `episode_held`).
fn episode_refusal(e: aruna::episode::EpisodeRefusal) -> SurfaceError {
    use aruna::episode::EpisodeRefusal as E;
    use PlanWireToken as T;
    let token = match &e {
        E::NoPlan => T::NoPlan,
        E::NotApproved => T::NotApproved,
        E::EpochMismatch { .. } => T::EpochMismatch,
        E::Expired { .. } => T::Expired,
        E::Terminal(_) => T::EpisodeClosed,
        E::NotActive(_) => T::EpisodeHeld,
        E::NoEpisode => T::NoEpisode,
        E::DispatchBegan { .. } => T::DispatchBegan,
        E::Store(reason) | E::Malformed(reason) => {
            return SurfaceError::Store {
                reason: reason.clone(),
            }
        }
        E::IllegalTransition { .. } | E::GenerationConflict { .. } => {
            return SurfaceError::Internal {
                reason: e.to_string(),
            }
        }
    };
    SurfaceError::plan_child(token)
}

/// The root key the bus was built with. Every plan command works under it; the harness builds no
/// bus without one, so this refusal covers a bus built some other way.
fn bus_root_key<L: IntentLog, C: Connector>(
    bus: &CommandBus<L, C>,
) -> Result<aruna::commitment::CommitmentKey, SurfaceError> {
    bus.root_key()
        .cloned()
        .ok_or_else(|| SurfaceError::Internal {
            reason: "the mutation boundary holds no root commitment key".to_string(),
        })
}

/// The review of a stored plan: its canonical presentation, whether it carries its approval and,
/// for the aggregate lane, the derived sample mapped to the canonical rows by identity in the
/// order `derive_sample` returned them.
fn review_view_for<L: IntentLog, C: Connector>(
    bus: &CommandBus<L, C>,
    plan_id: &PlanId,
) -> Result<PlanReviewView, SurfaceError> {
    let plan = bus
        .log()
        .plan(plan_id)
        .map_err(SurfaceError::store)?
        .ok_or_else(|| SurfaceError::plan_child(PlanWireToken::NoPlan))?;
    let approved = bus
        .log()
        .approval(plan_id)
        .map_err(SurfaceError::store)?
        .is_some();
    let terminal = bus
        .log()
        .episode_status_check(plan_id)
        .map_err(SurfaceError::store)?
        .is_some_and(aruna::episode::EpisodeStatusToken::is_terminal);
    let canonical = plan.digests.presentation_view.clone();
    let (lane, sample_k, sample_rows) = match plan.admission_lane {
        AdmissionLane::PerMember => (LaneView::PerMember, None, None),
        AdmissionLane::Bypassed { .. } => (LaneView::Bypassed, None, None),
        AdmissionLane::Aggregate => {
            // The stored plan passed its own shape check (`IntentLog::plan`), which pairs the
            // aggregate lane with the summary_sample mode; this arm names the other case anyway.
            let ApprovalMode::SummarySample { effective_k, .. } = plan.approval_mode else {
                return Err(SurfaceError::Store {
                    reason: "an aggregate plan without the summary_sample mode".to_string(),
                });
            };
            let key = aruna::commitment::derive_account_key(&bus_root_key(bus)?, &plan.account)
                .map_err(|e| SurfaceError::Internal {
                    reason: format!("the plan account's commitment key: {e}"),
                })?;
            let sample =
                aruna::plan::derive_sample(&key, &plan.digests, &plan.members, effective_k)
                    .map_err(|r| SurfaceError::plan_child(plan_refusal_token(&r)))?;
            let rows = sample
                .iter()
                .map(|member| {
                    canonical
                        .rows
                        .iter()
                        .find(|row| &row.message_ref == member)
                        .cloned()
                        .map(PlanRowView::from)
                        .ok_or_else(|| SurfaceError::Store {
                            reason: "a sampled member has no canonical row".to_string(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            (LaneView::Aggregate, Some(effective_k), Some(rows))
        }
    };
    Ok(PlanReviewView {
        plan_id: plan.plan_id.0.clone(),
        lane,
        presentation: canonical.into(),
        sample_k,
        sample_rows,
        expires_at: plan.expires_at.clone(),
        approved,
        terminal,
        bypass_notice: plan.bypass_notice.clone(),
    })
}

/// Mint a plan under the bus's root key (the store freezes the members' display and state from
/// its own rows) and answer its review.
fn plan_mint_on<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    spec: PlanSpec,
) -> Result<PlanReviewView, SurfaceError> {
    let root = bus_root_key(bus)?;
    let minted = bus
        .log_mut()
        .mint_plan(&root, spec)
        .map_err(plan_store_error)?;
    review_view_for(bus, &minted.plan_id)
}

/// Record the positive decision against what the renderer says it showed. `rendered` goes to the
/// engine as handed back and the engine recomputes the view commitment, so a substituted or
/// reordered row is `evidence_invalid` and nothing is recorded.
///
/// A plan frozen on the bypass lane is refused by name, `bypass_lane_no_screen`, and nothing is
/// recorded: that lane has no screen, so no rendered view exists to echo, and its only approver
/// is the mechanical path `plan_apply` runs ([`approve_bypassed_on`]). This is hygiene, not a
/// control: the renderer is same-process code, and the refusal prevents a renderer bug from
/// recording a "bypassed" approval with any view and any approver.
fn plan_approve_on<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    plan_id: &PlanId,
    rendered: RenderedViewWire,
    approver: &str,
) -> Result<PlanApproveOutcome, SurfaceError> {
    let lane = bus
        .log()
        .plan(plan_id)
        .map_err(SurfaceError::store)?
        .ok_or_else(|| SurfaceError::plan_child(PlanWireToken::NoPlan))?
        .admission_lane;
    if matches!(lane, AdmissionLane::Bypassed { .. }) {
        return Err(SurfaceError::plan_child(PlanWireToken::BypassLaneNoScreen));
    }
    let root = bus_root_key(bus)?;
    let rendered = rendered.into_engine()?;
    let evidence = bus
        .log_mut()
        .record_approval(&root, plan_id, approver, rendered)
        .map_err(plan_store_error)?;
    Ok(PlanApproveOutcome {
        plan_id: plan_id.0.clone(),
        comprehension: evidence.comprehension.as_token().to_string(),
        approver: evidence.approver,
    })
}

/// The approver the bypass lane's mechanical approval records, spelled as the engine's own tests
/// spell it (`crates/aruna/src/lib.rs`, `crates/aruna/src/plan.rs`'s `validate_evidence` tests):
/// no person saw a screen, and the evidence says so.
const BYPASS_APPROVER: &str = "mechanical";

/// The bypass lane: "the bypass waives the screen, never the machine's own safety or honesty". A
/// plan whose frozen admission lane is `Bypassed` gets no review screen, so no echo comes back
/// through `plan_approve`; this records the mechanical approval instead, through the same engine
/// entry point (`IntentLog::record_approval`). The engine builds the evidence itself
/// (`Comprehension::Bypassed { bypass_config_generation }` from the generation the plan froze at
/// mint, its own presentation digest, `rendered` not consulted) and refuses with
/// `BypassGenerationMismatch` (`bypass_generation_mismatch` here, nothing recorded) when the
/// bypass knob moved since. It is shell-internal: `plan_apply` is its one caller, and
/// `plan_approve`'s wire contract is unchanged.
///
/// It decides from the plan's frozen lane, never the knob in force: a per-member or aggregate
/// plan minted before the bypass was switched on still owes its screen and answers `Ok(None)`
/// with nothing recorded, as does a plan that already carries its approval (a resumed run).
fn approve_bypassed_on<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    plan_id: &PlanId,
) -> Result<Option<PlanApproveOutcome>, SurfaceError> {
    let plan = bus
        .log()
        .plan(plan_id)
        .map_err(SurfaceError::store)?
        .ok_or_else(|| SurfaceError::plan_child(PlanWireToken::NoPlan))?;
    if !matches!(plan.admission_lane, AdmissionLane::Bypassed { .. }) {
        return Ok(None);
    }
    if bus
        .log()
        .approval(plan_id)
        .map_err(SurfaceError::store)?
        .is_some()
    {
        return Ok(None);
    }
    let root = bus_root_key(bus)?;
    let rendered = RenderedView::FullList(plan.digests.presentation_view.clone());
    let evidence = bus
        .log_mut()
        .record_approval(&root, plan_id, BYPASS_APPROVER, rendered)
        .map_err(plan_store_error)?;
    Ok(Some(PlanApproveOutcome {
        plan_id: plan_id.0.clone(),
        comprehension: evidence.comprehension.as_token().to_string(),
        approver: evidence.approver,
    }))
}

/// One run of the plan driver, in the engine's own values ([`plan_apply_outcome`] projects it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanDrive {
    /// `None` = the run stopped before the preflight decided (`stopped` says why).
    preflight: Option<PreflightOutcome>,
    /// The member read after the run or, when that read failed, the members' last known states
    /// ([`RunProgress::members`]).
    members: Vec<(String, MemberState)>,
    /// `None` means the post-run settle (`settle_plan_progress`) failed, so the run could not read
    /// what the episode became. It is answered `undetermined` on the wire
    /// ([`COMPLETION_UNDETERMINED`]), never a guessed completion.
    completion: Option<Completion>,
    /// Members already settled when the run reached them: skipped.
    skipped: Vec<String>,
    /// Members in flight when the run reached them: re-driven through `CommandBus::recover`.
    held: Vec<String>,
    /// The undo offer of every applied member, in reverse canonical order.
    undo_keys: Vec<PlanUndoKeyView>,
    /// The plan's frozen bypass-lane notice (`TriagePlan::bypass_notice`).
    bypass_notice: Option<String>,
    /// The refusal that ended the run before every member was attempted.
    stopped: Option<SurfaceError>,
}

/// What a run did before it ended — filled in as it goes, so a run-ending error keeps it.
#[derive(Default)]
struct RunProgress {
    preflight: Option<PreflightOutcome>,
    skipped: Vec<String>,
    held: Vec<String>,
    /// Each member this run applied whose effect-witness write then failed.
    witness_write_failed: Vec<String>,
    /// The members' last known states: the pre-run read (`drive_members`' own `before`), with each
    /// member this run's own dispatch applied moved to `Applied` (an `Ok(Executed)` answer is
    /// "durably applied", per `aruna::Executed`). Every other member keeps the state it had when
    /// the run began, since the run cannot prove what a refused, failed or held member became
    /// without the read that failed. Empty when the run stopped before that pre-run read.
    /// `drive_plan` answers these only when its own post-run member read fails.
    members: Vec<(String, MemberState)>,
}

/// The plan driver: start (or resume) the plan's episode, preflight, each member in canonical
/// order when the preflight is `Ready` or `Raced`, the exact-N settle, then the member read. What
/// the run does with a member follows the member's durable state when it reaches it
/// (`plan_member_states`, read once before the loop):
/// - Not minted: `apply_plan_member`. A `PlanRefused` is recorded by the engine (the child closes
///   `Failed` with the refusal) and the loop continues; so does any other refusal that left the
///   member's child recorded (a provider refusal that closed it `Failed`, a transient failure that
///   left it in flight), whose outcome is read back below. A refusal that recorded nothing for the
///   member (an episode no longer active, a basis that would not resolve, a capacity refusal) and
///   every store error end the run, since the next member would meet the same wall. So does the
///   connector's capability refusal (`unsupported_capability`) even though it recorded the child
///   `Failed`: a plan has one verb, so every member meets it. What the local projection owes for
///   applied members is a store-wide question `plan_projection_writes` answers on its own.
/// - Settled (applied, refused, any other terminal status such as `Failed` or `Undone`): skipped
///   and reported (`skipped`). A settled child is never re-driven, and its replay never stops the
///   run.
/// - In flight (held): re-driven through `CommandBus::recover`, which sweeps every unreconciled
///   operation, not only this plan's, and reported (`held`). Its outcome is its state in the read
///   after the loop; one sweep serves every held member.
///
/// `Raced` still drives the members: another driver's first dispatch, or an earlier run of this
/// plan, crossed the barrier, and the send fence's per-child recheck owns staleness from there
/// (`PreflightOutcome::Raced`). A `Refused` preflight invalidated the episode, so no member is
/// attempted.
///
/// A run-ending error never discards what the run did. Once the episode has started, an error
/// that ends the run (at the preflight or at a member) still settles the episode's progress and
/// reads every member's state, and the outcome carries the error as `stopped` beside the members
/// that applied, their undo offers and the ones never attempted. The error is answered bare only
/// before the episode started (no plan, an unapproved plan, a closed episode).
///
/// After a provider effect, a bookkeeping failure is a labelled field of the outcome, never a
/// replacement of it. A failed settle answers `completion: None` (`undetermined` on the wire); a
/// failed member read answers the members' last known states ([`RunProgress::members`]); and the
/// failure becomes the `stopped` reason unless the run had already stopped for its own reason,
/// which is kept.
fn drive_plan<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    plan_id: &PlanId,
    fence_reason: Option<&str>,
) -> Result<PlanDrive, SurfaceError> {
    let plan = bus
        .log()
        .plan(plan_id)
        .map_err(SurfaceError::store)?
        .ok_or_else(|| SurfaceError::plan_child(PlanWireToken::NoPlan))?;
    bus.log_mut()
        .start_episode(plan_id)
        .map_err(episode_refusal)?;
    let mut progress = RunProgress::default();
    let mut stopped = drive_members(bus, &plan, fence_reason, &mut progress).err();
    // What the run did is read even when it stopped; a read that itself fails degrades the report
    // (see this function's doc) rather than replacing it.
    let completion = match bus.settle_plan_progress(plan_id) {
        Ok(completion) => Some(completion),
        Err(e) => {
            stopped.get_or_insert_with(|| SurfaceError::execute(e));
            None
        }
    };
    let members = match bus.plan_member_states(plan_id) {
        Ok(members) => members,
        Err(e) => {
            stopped.get_or_insert_with(|| SurfaceError::execute(e));
            std::mem::take(&mut progress.members)
        }
    };
    // The undo route: the applied children, last first (the order the renderer's undo walks them
    // through the existing `undo` command), each with the restoration verdict its effect witness
    // allows. A member whose witness write failed in this run says so.
    let undo_keys = members
        .iter()
        .rev()
        .filter(|(_, state)| *state == MemberState::Applied)
        .map(|(member, _)| {
            let undo_key = bus.plan_child_command(&plan, member).idempotency_key;
            let restoration = if progress.witness_write_failed.contains(member) {
                Some(RestorationView::WitnessWriteFailed)
            } else {
                restoration_after_verb(bus, &undo_key)
            };
            PlanUndoKeyView {
                member_ref: member.clone(),
                restoration,
                undo_key,
            }
        })
        .collect();
    // What the local projection still owes is answered by the store-derived writer
    // (`plan_projection_writes`, `plan_apply_door`) from the single source of truth
    // (`IntentLog::applied_unprojected_forward_intents`), for every plan, not just the one just
    // driven. A second, run-window derivation here (a before/after diff of this plan's own member
    // states) would be a second mechanism answering the same question.
    Ok(PlanDrive {
        preflight: progress.preflight,
        members,
        completion,
        skipped: progress.skipped,
        held: progress.held,
        undo_keys,
        bypass_notice: plan.bypass_notice,
        stopped,
    })
}

/// The run between the episode start and the settle: the preflight, then each member
/// ([`drive_plan`]'s rules). `Err` is the refusal that ended the run; what it did before is in
/// `progress` and in the store.
fn drive_members<L: IntentLog, C: Connector>(
    bus: &mut CommandBus<L, C>,
    plan: &aruna::plan::TriagePlan,
    fence_reason: Option<&str>,
    progress: &mut RunProgress,
) -> Result<(), SurfaceError> {
    let plan_id = &plan.plan_id;
    let preflight = bus
        .preflight_plan(plan_id)
        .map_err(|e| SurfaceError::execute_fenced(e, fence_reason))?;
    let run = matches!(preflight, PreflightOutcome::Ready | PreflightOutcome::Raced { .. });
    progress.preflight = Some(preflight);
    if !run {
        return Ok(());
    }
    let before = bus
        .plan_member_states(plan_id)
        .map_err(SurfaceError::execute)?;
    // The members' last known states, kept current as this run proves an apply (see
    // `RunProgress::members`).
    progress.members = before.clone();
    let mut swept = false;
    // The keys one sweep names in `RecoverReport::witness_write_failed`: a superset over every
    // unreconciled intent, not only this plan's. It is filled in once the sweep runs, so every
    // held member below (the one that triggered it and any later one in this plan) can ask "was
    // my key in it?" the way `execute`'s own `WriteFailed` is asked for a not-minted member.
    let mut swept_witness_failed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (member, state) in before {
        match state {
            MemberState::NotMinted => match bus.apply_plan_member(plan_id, &member) {
                // This run's dispatch applied the child. (A `NotDispatched` answer is a settled row
                // this call only read back, not this run's.) What counts as "applied" for the
                // local projection is decided store-wide by `plan_projection_writes`; this arm
                // only owes the write-failed witness list.
                Ok(Executed { witness }) => {
                    if let Some(known) = progress.members.iter_mut().find(|(m, _)| *m == member) {
                        known.1 = MemberState::Applied;
                    }
                    if let WitnessRecord::WriteFailed(_) = witness {
                        progress.witness_write_failed.push(member);
                    }
                }
                Err(ExecuteError::PlanRefused { .. }) => {}
                // A store error from `apply_plan_member` can land after the connector's effect
                // (the settlement write, the read-back), and nothing here can tell which side of
                // the effect it came from, so the stop says the member's effect may have landed,
                // never that nothing happened.
                Err(ExecuteError::Log(e)) => {
                    return Err(SurfaceError::Store {
                        reason: format!(
                            "{} — member {member}'s effect may have landed at the provider; a refresh re-reads it",
                            e.0
                        ),
                    })
                }
                // A run-ending connector disposition (the capability map refuses the plan's verb,
                // or the credential was rejected mid-run) ends the run by that disposition's own
                // name even though this member's child was recorded `Failed`: every remaining
                // member would meet the same wall, and continuing would fail each in turn under a
                // name that hides the one actionable fact. [`run_ending_connector_disposition`] is
                // the one classifier. It is checked before the recorded-or-bare branch below,
                // which would otherwise treat a recorded `Failed` as "this member's own outcome"
                // and move on.
                Err(ExecuteError::Connector(c)) if run_ending_connector_disposition(&c).is_some() => {
                    return Err(run_ending_connector_disposition(&c).expect("guard proved Some"))
                }
                Err(other) => {
                    let key = bus.plan_child_command(plan, &member).idempotency_key;
                    let recorded = bus.log().get(&key).map_err(SurfaceError::store)?;
                    if recorded.is_none() {
                        return Err(SurfaceError::execute_fenced(other, fence_reason));
                    }
                }
            },
            MemberState::InFlight => {
                // The member's provenance is recorded first, before the fallible sweep call that
                // could exit this function. Recording after `recover()?` would lose a held member
                // from `progress.held` whenever the sweep itself returned an error, even though
                // `recover()` had already durably applied it. This is the run's own report of
                // what was in flight; what the local projection owes is decided store-wide, not
                // derived from this vector.
                progress.held.push(member.clone());
                if !swept {
                    let report = bus
                        .recover()
                        .map_err(|e| SurfaceError::execute_fenced(e, fence_reason))?;
                    // The sweep stops at its own run-ending connector error
                    // (`RecoverReport::stopped_by`). It is surfaced here through the same
                    // classifier as the dispatch arm above, rather than inspecting only
                    // `witness_write_failed` and discarding `failed`/`stopped_by`, which would
                    // let a credential rejection during a held-member re-drive go unnoticed.
                    if let Some((_, connector_error)) = &report.stopped_by {
                        if let Some(surface) = run_ending_connector_disposition(connector_error) {
                            return Err(surface);
                        }
                    }
                    swept_witness_failed = report.witness_write_failed.into_iter().collect();
                    swept = true;
                }
                let key = bus.plan_child_command(plan, &member).idempotency_key;
                if swept_witness_failed.contains(&key) {
                    progress.witness_write_failed.push(member);
                }
            }
            MemberState::Applied | MemberState::Refused { .. } | MemberState::Terminal(_) => {
                progress.skipped.push(member)
            }
        }
    }
    Ok(())
}

fn plan_apply_outcome(
    plan_id: &PlanId,
    drive: PlanDrive,
    projection: ProjectionState,
) -> PlanApplyOutcome {
    PlanApplyOutcome {
        plan_id: plan_id.0.clone(),
        preflight: drive.preflight.map(PreflightView::from),
        members: drive
            .members
            .into_iter()
            .map(|(member, state)| (member, state.into()))
            .collect(),
        completion: drive
            .completion
            .as_ref()
            .map_or_else(|| COMPLETION_UNDETERMINED.to_string(), completion_token),
        projection,
        skipped: drive.skipped,
        held: drive.held,
        undo_keys: drive.undo_keys,
        bypass_notice: drive.bypass_notice,
        stopped: drive.stopped,
    }
}

/// Why a plan's local projection is stale when a member is still in flight: its effect may or may
/// not have landed, so its row was not written.
const PLAN_MEMBER_IN_FLIGHT_REASON: &str =
    "a plan member is still in flight; its row was not updated";

/// The RED rule: a RED verb command never dispatches. It mints a one-member plan through the
/// same mint path a multi-member plan takes and answers the review; the effect happens only
/// through `plan_apply`, after `plan_approve` recorded the positive decision against what the
/// renderer showed.
pub(crate) async fn red_verb_door(
    state: &PhotonState,
    verb: PlanVerb,
    account: String,
    message_ref: String,
) -> Result<PlanReviewView, SurfaceError> {
    plan_mint_door(
        state,
        account,
        verb.as_token().to_string(),
        vec![message_ref],
        None,
    )
    .await
}

/// Mint a plan over the renderer's member identities (the store freezes their display and state
/// from its own rows), bound to the grant of the published arm whose bus mints it.
pub(crate) async fn plan_mint_door(
    state: &PhotonState,
    account: String,
    verb: String,
    member_refs: Vec<String>,
    rationale: Option<String>,
) -> Result<PlanReviewView, SurfaceError> {
    let account = state.account(&account)?;
    let verb = PlanVerb::from_token(&verb).map_err(|r| SurfaceError::plan_child(plan_refusal_token(&r)))?;
    let (provider, grant_generation, provider_principal) = state.gmail_with_grant()?;
    // Store work under the bus's own mutex, on the blocking pool; no provider I/O happens here.
    with_provider(provider, move |p| {
        let mut bus = lock_bus(p)?;
        plan_mint_on(
            &mut *bus,
            PlanSpec {
                account,
                provider_principal,
                grant_generation,
                verb,
                member_refs,
                rationale,
                ttl_seconds: PLAN_TTL_SECONDS,
            },
        )
    })
    .await
}

pub(crate) async fn plan_review_door(
    state: &PhotonState,
    plan_id: String,
) -> Result<PlanReviewView, SurfaceError> {
    let provider = state.gmail()?;
    with_provider(provider, move |p| {
        review_view_for(&*lock_bus(p)?, &PlanId(plan_id))
    })
    .await
}

pub(crate) async fn plan_approve_door(
    state: &PhotonState,
    plan_id: String,
    rendered: RenderedViewWire,
    approver: String,
) -> Result<PlanApproveOutcome, SurfaceError> {
    let provider = state.gmail()?;
    with_provider(provider, move |p| {
        plan_approve_on(&mut *lock_bus(p)?, &PlanId(plan_id), rendered, &approver)
    })
    .await
}

/// The single-flight claim a `plan_apply` holds for its whole run: its own kind, per plan.
fn plan_apply_claim<'a>(
    inflight: &'a InFlight,
    plan_id: &str,
) -> Result<InFlightClaim<'a>, SurfaceError> {
    let kind = OperationKind::Plan(plan_id.to_string());
    inflight
        .claim(kind.clone())
        .ok_or_else(|| SurfaceError::busy(&kind))
}

/// Run the plan ([`drive_plan`]) under one single-flight claim per plan. The credential is
/// admitted first ([`admit_provider`]: reconcile the file, renew an expired token, as the
/// provider-read commands do); an expired credential that cannot be renewed is its named
/// `credential_expired` refusal and the plan is not touched. A plan frozen on the bypass lane
/// then records its mechanical approval ([`approve_bypassed_on`]; no screen, so no echo came back
/// through `plan_approve`) under the same bus lock. Then the local projection is written for the
/// members this run applied (never one it skipped), through the post-verb path `run_verb` takes,
/// including when the run stopped. The reported projection is `run_verb`'s dual outcome over
/// those writes: `Current` when every write landed, `Stale` with the first write's reason
/// otherwise, and `Stale` when a member is still in flight (its effect may or may not have
/// landed, so its row was not written).
pub(crate) async fn plan_apply_door(
    state: &PhotonState,
    plan_id: String,
) -> Result<PlanApplyOutcome, SurfaceError> {
    let _claim = plan_apply_claim(&state.inflight, &plan_id)?;
    let provider = admit_provider(state).await?;
    let session = state.session()?;
    // As in `run_verb`: the fence sentence is read before the dispatch and carried in. This
    // command is past `state.gmail()?`, so the arm in hand is the Gmail one.
    let (_mutations_live, fence_reason) =
        mutation_fence(&state.credential.snapshot().provider, None);
    let id = PlanId(plan_id);
    let driven = id.clone();
    // Provider I/O (preflight observations, member dispatches) through the mutation boundary,
    // with no session lock held. The store-wide unprojected work list is read in this same bus
    // acquisition, right after the drive: every forward intent the store says is `Applied` but
    // never had its local projection written, from any plan's earlier run or any plan's
    // `recover()` sweep, not scoped to the plan just driven. The unified writer derives the
    // account and delta per intent from the intent's own stored `Action`, so nothing here needs
    // the plan row a second time (`drive_plan` already read and validated it once).
    let (drive, unprojected) = with_provider(provider, move |p| {
        let mut bus = lock_bus(p)?;
        approve_bypassed_on(&mut *bus, &driven)?;
        let drive = drive_plan(&mut *bus, &driven, fence_reason.as_deref())?;
        let unprojected = bus
            .log()
            .applied_unprojected_forward_intents()
            .map_err(SurfaceError::store)?;
        Ok((drive, unprojected))
    })
    .await?;
    // Re-acquire to write. As in `run_verb`, a projection failure is not a plan failure: it is
    // the `Stale` arm, returned for the UI to render. It writes the store-wide catch-up list
    // (which already includes this run's own freshly applied members; see
    // `plan_projection_writes`) in the same session acquisition. `plan_projection_writes` calls
    // `ReadCoordinator::project_applied_intent`, which marks `projected` in the same transaction
    // as the placement/header write (or the decision to skip it), so no later acquisition is
    // needed; `newly_projected_keys` is informational only. The members may already have applied
    // at the provider, so a failed session re-acquisition here is folded into the projection's
    // `Stale` arm ([`projection_after_effect`]), never a bare error that discards the run's
    // outcome.
    let run = drive.clone();
    let projection = projection_after_effect(session, move |s| {
        let (projection, _newly_projected_keys) = plan_projection_writes(s, &run.members, unprojected);
        projection
    })
    .await;
    Ok(plan_apply_outcome(&id, drive, projection))
}

/// The local projection writer: one writer, one source of truth (the store), with no per-plan
/// before/after derivation beside it to disagree with.
///
/// `unprojected` is every forward-kind intent the store says is `Applied` but never had its local
/// projection written: this run's own members (read back through the same bus acquisition
/// `drive_plan` ran in, before anything is marked `projected`), an earlier run of this plan, or
/// any other plan's `recover()` sweep. Each is written through
/// [`aruna::read_coordinator::ReadCoordinator::project_applied_intent`], keyed by the intent
/// alone: it reads its own row and derives account, message ref, delta and basis from it, since a
/// caller-derived delta or basis could disagree with that row and yield a false `Current`. It
/// marks `intents.projected` in the same transaction as the placement/header write (or the
/// decision to skip it).
///
/// `plan_members` is the plan just driven, for one check that stays per-plan because it concerns a
/// member's presence rather than a write: a member still in flight when the run ended also makes
/// the projection `Stale`, since its effect may or may not have landed and the UI must not render
/// it as settled.
///
/// Returns the combined [`ProjectionState`] and the idempotency keys touched: every key the
/// projection path returned `Ok` for (`Written`, `SupersededByNewerObservation` or
/// `NotApplicable`), since all three mean it has finished with that key. Only an `Err` (a real
/// write failure) is excluded and folds into `Stale`.
fn plan_projection_writes(
    session: &mut PhotonSession,
    plan_members: &[(String, MemberState)],
    unprojected: Vec<aruna::Intent>,
) -> (ProjectionState, Vec<String>) {
    let mut newly_projected = Vec::new();
    let mut stale: Option<String> = None;
    for intent in &unprojected {
        match session
            .coordinator
            .project_applied_intent(&intent.command.idempotency_key)
        {
            Ok(_written_skipped_or_not_applicable) => {
                newly_projected.push(intent.command.idempotency_key.clone())
            }
            Err(e) => {
                stale.get_or_insert(e.0);
            }
        }
    }
    if stale.is_none() && plan_members.iter().any(|(_, s)| *s == MemberState::InFlight) {
        stale = Some(PLAN_MEMBER_IN_FLIGHT_REASON.to_string());
    }
    let state = match stale {
        Some(reason) => ProjectionState::Stale { reason },
        None => ProjectionState::Current,
    };
    (state, newly_projected)
}

/// The typed knob command: the act is re-read through its kind's own strict reader, then
/// appended to the store's `engine_config` ledger through the bus's intent log.
pub(crate) async fn set_knob_door(state: &PhotonState, act: KnobActWire) -> Result<KnobOutcome, SurfaceError> {
    let act = knob_act_from_wire(act)?;
    let provider = state.gmail()?;
    with_provider(provider, move |p| {
        let generation = lock_bus(p)?
            .log_mut()
            .record_knob_act(act)
            .map_err(SurfaceError::store)?;
        Ok(KnobOutcome { generation })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use aruna::gmail::{GmailConnector, GmailMessageId, GmailTransport, GmailUserId};
    use aruna::message_store::SqliteMessageStore;
    use aruna::read_coordinator::VerbDelta;
    use aruna::read_surface::HeaderSummary;
    use aruna::{Action, Command, Facet, SqliteIntentLog, UndoPresentation};

    use crate::provider::{FixedGmailAccount, Provider, StoreMessageRefs, MUTATIONS_FENCED_REASON};
    use crate::session::{PageAnchor, PageFacts};
    use crate::tests::fixtures::{
        gmail_arm_state, gmail_arm_state_expiring, inbox_refs, page_row, plan_bus,
        s1_fold_message_ref, session_for, R1LabelConnector, SessionTemp,
        R2_3_WITNESS_WRITE_FAILPOINT,
    };
    use crate::token_refresh::Cure;
    use crate::verbs::verb_on_bus;

    // ===========================================================================================
    // The plan surfaces: typed refusals, the ten doors, the driver.
    //
    // The doors that touch only the store (mint · review · approve · the knob) are driven through
    // their own async bodies over a REAL Gmail arm — its bus carries the shell ratchet and a root
    // key verified into the store, and no network is touched: the mint and the approval read
    // and write the store alone. The plan DRIVER (start → preflight → members → settle) observes
    // and dispatches through the connector, so it is driven generically over the engine's
    // counting test connector and a real SQLite store.
    // ===========================================================================================

    #[test]
    fn a_plan_apply_is_single_flight_per_plan_under_its_own_kind() {
        let inflight = InFlight::default();
        assert_eq!(OperationKind::Plan("p1".into()).label(), "plan:p1");
        let held = plan_apply_claim(&inflight, "p1").expect("the first apply claims the plan");
        assert_eq!(
            plan_apply_claim(&inflight, "p1").err(),
            Some(SurfaceError::Busy {
                operation: "plan:p1".into()
            }),
            "a second apply of the SAME plan is refused while the first runs"
        );
        assert!(
            plan_apply_claim(&inflight, "p2").is_ok(),
            "another plan is another slot"
        );
        assert!(
            inflight.claim(OperationKind::Verb("p1".into())).is_some(),
            "a plan slot never blocks a verb on a message that happens to share the id"
        );
        drop(held);
        assert!(plan_apply_claim(&inflight, "p1").is_ok(), "released on drop");
    }

    /// A Gmail-arm session (the REAL bus: shell ratchet + a root key verified into the store)
    /// whose store holds `n` inbox rows, and their Photon refs in page order.
    /// The directory's guard comes back FIRST: `let (dir, state, refs) =..` drops the
    /// state before the guard deletes.
    fn s1_armed_with_inbox(tag: &str, n: usize) -> (aruna::test_temp::TempDir, PhotonState, Vec<String>) {
        let (dir, state) = gmail_arm_state(tag);
        let session = state.session().expect("the store opens");
        let rows: Vec<HeaderSummary> = (0..n)
            .map(|i| page_row(&format!("P{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &rows,
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("a page-1 absorb writes the rows");
        let refs = inbox_refs(&session);
        assert_eq!(refs.len(), n, "the witness's premise: {n} inbox rows");
        (dir, state, refs)
    }

    fn s1_count(dir: &Path, table: &str) -> i64 {
        rusqlite::Connection::open(dir.join("store.sqlite"))
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table};"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn trash_and_mark_spam_mint_a_one_member_plan_through_the_mint_door_and_never_dispatch() {
        let (dir, state, refs) = s1_armed_with_inbox("s1-red-doors", 2);
        for (verb, target) in [(PlanVerb::Trash, &refs[0]), (PlanVerb::MarkSpam, &refs[1])] {
            let review = tauri::async_runtime::block_on(red_verb_door(
                &state,
                verb,
                "acct".to_string(),
                target.clone(),
            ))
            .unwrap_or_else(|e| panic!("{verb:?} mints a one-member plan: {e:?}"));
            assert_eq!(review.lane, LaneView::PerMember);
            assert!(!review.approved, "minted, never approved by the door");
            assert_eq!(review.presentation.header.verb, verb.as_token());
            assert_eq!(review.presentation.header.tier, "red");
            assert_eq!(review.presentation.header.count, 1);
            assert_eq!(
                review
                    .presentation
                    .rows
                    .iter()
                    .map(|r| r.message_ref.as_str())
                    .collect::<Vec<_>>(),
                vec![target.as_str()]
            );
            assert_eq!((review.sample_k, review.sample_rows.as_ref()), (None, None));
            // The backups default is ON: coverage on, no warning.
            assert!(review.presentation.header.backup_coverage);
            assert_eq!(review.presentation.header.warning, None);
        }
        // NEVER A DISPATCH: the doors minted two plans and wrote no intent at all.
        assert_eq!(s1_count(&dir, "triage_plan"), 2);
        assert_eq!(s1_count(&dir, "intents"), 0, "a RED verb door never dispatches");
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn plan_approve_commits_against_what_the_renderer_says_it_showed() {
        use tauri::async_runtime::block_on;
        let (dir, state, refs) = s1_armed_with_inbox("s1-approve", 2);
        let review = block_on(plan_mint_door(
            &state,
            "acct".into(),
            "trash".into(),
            refs.clone(),
            None,
        ))
        .expect("mint");
        let id = review.plan_id.clone();
        assert_eq!(block_on(plan_review_door(&state, id.clone())).as_ref(), Ok(&review));
        // A SUBSTITUTED row: the renderer claims it showed a subject the plan never froze.
        let mut substituted = review.presentation.clone();
        substituted.rows[0].subject = "a subject the plan never froze".to_string();
        assert_eq!(
            block_on(plan_approve_door(
                &state,
                id.clone(),
                RenderedViewWire::FullList {
                    presentation: substituted
                },
                "operator".into()
            )),
            Err(SurfaceError::PlanRefused {
                reason: "evidence_invalid".into(),
                member_ref: None,
                diff: vec![]
            })
        );
        assert!(
            !block_on(plan_review_door(&state, id.clone())).unwrap().approved,
            "a refused approval records nothing"
        );
        // EXACTLY what was rendered: the engine commits it.
        assert_eq!(
            block_on(plan_approve_door(
                &state,
                id.clone(),
                RenderedViewWire::FullList {
                    presentation: review.presentation.clone()
                },
                "operator".into()
            )),
            Ok(PlanApproveOutcome {
                plan_id: id.clone(),
                comprehension: "per_member".into(),
                approver: "operator".into()
            })
        );
        assert!(block_on(plan_review_door(&state, id.clone())).unwrap().approved);
        // Write-once.
        assert_eq!(
            block_on(plan_approve_door(
                &state,
                id.clone(),
                RenderedViewWire::FullList {
                    presentation: review.presentation.clone()
                },
                "operator".into()
            )),
            Err(SurfaceError::PlanChildRefused {
                reason: "already_approved".into()
            })
        );
        // The mint door's preconditions refuse by name, never by prose.
        let child = |reason: &str| {
            Err(SurfaceError::PlanChildRefused {
                reason: reason.to_string(),
            })
        };
        assert_eq!(
            block_on(plan_mint_door(&state, "acct".into(), "delete".into(), refs.clone(), None)),
            child("unknown_verb")
        );
        assert_eq!(
            block_on(plan_mint_door(
                &state,
                "acct".into(),
                "trash".into(),
                vec!["no-such-ref".into()],
                None
            )),
            child("unknown_member")
        );
        assert_eq!(
            block_on(plan_mint_door(&state, "acct".into(), "trash".into(), vec![], None)),
            child("empty_members")
        );
        assert_eq!(block_on(plan_review_door(&state, "0".repeat(32))), child("no_plan"));
        assert!(
            matches!(
                block_on(plan_mint_door(&state, "someone-else".into(), "trash".into(), refs, None)),
                Err(SurfaceError::Refused { .. })
            ),
            "the single-account rule holds at the mint door too"
        );
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_aggregate_review_carries_the_derived_sample_in_derived_order_and_the_knob_door_refuses_by_the_readers_sentence(
    ) {
        use tauri::async_runtime::block_on;
        let (dir, state, refs) = s1_armed_with_inbox("s1-aggregate", 5);
        let acts_before = s1_count(&dir, "engine_config");
        let knob = |mode: &str, configured_k: Option<u32>| {
            block_on(set_knob_door(
                &state,
                KnobActWire::ApprovalMode {
                    mode: mode.to_string(),
                    configured_k,
                },
            ))
        };
        for (mode, k, sentence) in [
            ("summary_sample", Some(0), "configured_k must be >= 1"),
            ("sideways", None, "unknown mode 'sideways'"),
            ("full_list", Some(3), "full_list carries no configured_k"),
        ] {
            match knob(mode, k) {
                Err(SurfaceError::Refused { reason, .. }) => {
                    assert!(reason.contains(sentence), "the reader's own sentence: {reason}")
                }
                other => panic!("{mode}/{k:?} must be refused by the knob's reader: {other:?}"),
            }
        }
        assert_eq!(
            s1_count(&dir, "engine_config"),
            acts_before,
            "a refused act appends nothing"
        );
        let landed = knob("summary_sample", Some(3)).expect("the act lands");
        assert!(landed.generation >= 1);
        assert!(block_on(set_knob_door(&state, KnobActWire::Backups { on: false })).is_ok());

        // DERIVED order: the engine's own `derive_sample` over the stored plan,
        // under the plan account's key derived from the bus's root key.
        let derived = |plan_id: &str| -> Vec<String> {
            let Provider::Gmail(arm) = state.credential.snapshot().provider else {
                panic!("the arm is built");
            };
            let bus = lock_bus(&arm).unwrap();
            let plan = aruna::IntentLog::plan(bus.log(), &PlanId(plan_id.to_string()))
                .unwrap()
                .unwrap();
            let key = aruna::commitment::derive_account_key(bus.root_key().unwrap(), "acct")
                .unwrap();
            aruna::plan::derive_sample(&key, &plan.digests, &plan.members, 3).unwrap()
        };
        // Each plan's sample seed is minted fresh, so its derived order is a fresh draw: mint
        // until one plan's sample is NOT already in canonical (sorted) order — the witness's
        // premise, so a renderer-side or shell-side sort cannot pass for the derived order.
        // (A sorted draw is one in 3! = 6; twenty in a row is ~3e-16.)
        let (review, expected) = (0..20)
            .find_map(|_| {
                let review =
                    block_on(plan_mint_door(&state, "acct".into(), "trash".into(), refs.clone(), None))
                        .expect("mint");
                let expected = derived(&review.plan_id);
                let mut sorted = expected.clone();
                sorted.sort();
                (sorted != expected).then_some((review, expected))
            })
            .expect("a derived sample out of canonical order within twenty mints");
        assert_eq!(review.lane, LaneView::Aggregate);
        assert_eq!(review.sample_k, Some(3));
        // backups OFF ⇒ coverage off and the verb-specific warning, verbatim.
        assert!(!review.presentation.header.backup_coverage);
        assert_eq!(
            review.presentation.header.warning.as_deref(),
            Some(aruna::plan::TRASH_UNCOVERED_WARNING)
        );
        let sample = review.sample_rows.clone().expect("the aggregate lane carries its sample");
        assert_eq!(
            sample.iter().map(|r| r.message_ref.clone()).collect::<Vec<_>>(),
            expected
        );
        for row in &sample {
            assert!(
                review.presentation.rows.contains(row),
                "a sampled row is the canonical row for its ref, verbatim"
            );
        }
        // The aggregate echo approves only in the derived order.
        let echo = |sample_rows: Vec<PlanRowView>| RenderedViewWire::Aggregate {
            header: review.presentation.header.clone(),
            summary: review.presentation.summary.clone(),
            sample_k: 3,
            sample_rows,
        };
        let mut reordered = sample.clone();
        reordered.reverse();
        assert_eq!(
            block_on(plan_approve_door(
                &state,
                review.plan_id.clone(),
                echo(reordered),
                "operator".into()
            )),
            Err(SurfaceError::PlanRefused {
                reason: "evidence_invalid".into(),
                member_ref: None,
                diff: vec![]
            })
        );
        assert_eq!(
            block_on(plan_approve_door(
                &state,
                review.plan_id.clone(),
                echo(sample),
                "operator".into()
            ))
            .map(|o| o.comprehension),
            Ok("aggregate".to_string())
        );
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The knob door's route: each wire act is ITS knob with ITS value — nothing inverted, nothing
    /// crossed — and the wire tags are the ones `src/ipc.ts` mirrors.
    #[test]
    fn the_knob_door_routes_each_wire_act_to_its_own_knob() {
        use aruna::config_knobs::{ApprovalModeKnob, BackupsKnob, KnobAct, RedBypassKnob};
        let routed = |act: KnobActWire| knob_act_from_wire(act).expect("a readable act routes");
        assert_eq!(
            routed(KnobActWire::Backups { on: true }),
            KnobAct::Backups(BackupsKnob::On)
        );
        assert_eq!(
            routed(KnobActWire::Backups { on: false }),
            KnobAct::Backups(BackupsKnob::Off)
        );
        assert_eq!(
            routed(KnobActWire::RedBypass { on: true }),
            KnobAct::RedBypass(RedBypassKnob::On)
        );
        assert_eq!(
            routed(KnobActWire::RedBypass { on: false }),
            KnobAct::RedBypass(RedBypassKnob::Off)
        );
        assert_eq!(
            routed(KnobActWire::ApprovalMode {
                mode: "full_list".into(),
                configured_k: None
            }),
            KnobAct::ApprovalMode(ApprovalModeKnob::FullList)
        );
        assert_eq!(
            routed(KnobActWire::ApprovalMode {
                mode: "summary_sample".into(),
                configured_k: Some(4)
            }),
            KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 4 })
        );
        for (act, wire) in [
            (
                KnobActWire::Backups { on: false },
                serde_json::json!({ "kind": "backups", "on": false }),
            ),
            (
                KnobActWire::RedBypass { on: true },
                serde_json::json!({ "kind": "red_bypass", "on": true }),
            ),
            (
                KnobActWire::ApprovalMode {
                    mode: "summary_sample".into(),
                    configured_k: Some(4),
                },
                serde_json::json!({ "kind": "approval_mode", "mode": "summary_sample", "configured_k": 4 }),
            ),
        ] {
            assert_eq!(serde_json::to_value(&act).unwrap(), wire);
            assert_eq!(serde_json::from_value::<KnobActWire>(wire).unwrap(), act);
        }
    }

    /// An `Applied`, unprojected forward intent — the exact shape
    /// `IntentLog::applied_unprojected_forward_intents` hands the writer, minted BY HAND (no bus
    /// in scope) following the rule that the store's forward
    /// log is the fixture, never a hand-built `PlanDrive`/`RunProgress`.
    ///
    /// The door reads the intent row
    /// DIRECTLY from the `intents` table by key alone (account, message_ref, action_kind, status,
    /// projected, basis_ingest_revision) — it accepts NONE of those from the caller any more — so
    /// this fixture must insert a REAL row, never a bare in-memory `Intent` with nothing behind
    /// it in the store. The earlier in-memory-only shape worked only because the earlier door
    /// took every field from the caller and its own marker UPDATE silently matched zero rows for
    /// a key the table never held at all — precisely the shape of the earlier false-Current bug, now
    /// closed. The raw-SQL insert mirrors the engine's own hand-seeded fixture shape
    /// (`crates/aruna/src/lib.rs`'s `seed_intent`); `basis_ingest_revision` is the one column
    /// every caller of this fixture actually varies, so it is taken as a parameter rather than
    /// fixed at `Some(1)` the way the earlier fixture fixed it.
    fn applied_unprojected_intent(
        path: &std::path::Path,
        key: &str,
        member_ref: &str,
        basis_ingest_revision: Option<i64>,
    ) -> aruna::Intent {
        rusqlite::Connection::open(path)
            .expect("raw connection")
            .execute(
                "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                      status, seq, intent_id, kind, journal_required,
                                      capture_mode_generation, admitted_control_epoch,
                                      basis_ingest_revision, projected)
                 VALUES (?1, 'acct', 'mail', 'trash', ?2,
                         'applied', (SELECT COALESCE(MAX(seq), 0) + 1 FROM intents),
                         lower(hex(randomblob(16))), 'forward', 1, 1, 1, ?3, 0);",
                rusqlite::params![key, member_ref, basis_ingest_revision],
            )
            .expect("seed a real applied+unprojected intent row");
        aruna::Intent {
            command: Command::new(
                key,
                "acct",
                aruna::Facet::Mail,
                aruna::Action::Trash { message_ref: member_ref.to_string() },
            ),
            status: aruna::IntentStatus::Applied,
            seq: 1,
            attempts: 0,
            frozen_basis: None,
            journal_required: true,
            projected: false,
            basis_ingest_revision,
        }
    }

    /// The plan door's projection writer (`plan_projection_writes`): every `Applied`+unprojected
    /// intent the store hands it is written through `apply_verb_delta`; a member the store never
    /// names (refused, unminted, or already projected) is untouched; the outcome is `Current` only
    /// when every write landed and nothing in the plan is still in flight.
    /// This test is written against the store — it used to hand-build a
    /// `PlanDrive` naming `refs[1]`/`refs[2]` Refused/NotMinted and rely on the now-DELETED
    /// `applied_this_run` field to filter them out before the write; the store-derived writer never
    /// sees them AT ALL (they were never `Applied`, so `applied_unprojected_forward_intents` would
    /// never name them) — the stronger, single-source proof of the same "applied rows only"
    /// property, one mechanism instead of two.
    #[test]
    fn the_plan_projection_writes_applied_rows_only_and_reports_what_it_could_not_write() {
        let (path, _state, session) = session_for("s1-plan-projection");
        let rows: Vec<HeaderSummary> = (0..3)
            .map(|i| page_row(&format!("J{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &rows,
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb");
        let refs = inbox_refs(&session);
        // Only refs[0] was ever `Applied` — refs[1] (Refused) and refs[2] (NotMinted) never reach
        // the store's unprojected-forward-intents list, so `plan_members` here is a witness for
        // the in-flight check ALONE, never a work list.
        let plan_members = vec![
            (refs[0].clone(), MemberState::Applied),
            (
                refs[1].clone(),
                MemberState::Refused {
                    reason: "snapshot_absent".into(),
                    diff: vec![],
                },
            ),
            (refs[2].clone(), MemberState::NotMinted),
        ];
        // `applied_unprojected_intent`'s own `Some(1)` basis assumes a
        // SINGLE absorbed row; this test absorbs three and reads them back through
        // `folder_first_page`'s (newest-first) order, so `refs[0]`'s ACTUAL ingest revision is not
        // 1 — irrelevant to what this test is about (the writer-selection and in-flight-staleness
        // rules), so the basis is widened to "always fresh enough" rather than hand-computed.
        let intent = applied_unprojected_intent(&path, "k0", &refs[0], Some(i64::MAX));
        let (projection, newly_projected) = plan_projection_writes(
            &mut session.lock().expect("session lock"),
            &plan_members,
            vec![intent],
        );
        assert_eq!(projection, ProjectionState::Current);
        assert_eq!(newly_projected, vec!["k0".to_string()], "the mark the caller owes the store");
        assert_eq!(
            inbox_refs(&session),
            vec![refs[1].clone(), refs[2].clone()],
            "only the APPLIED member left the inbox"
        );
        // A member still in flight: its row was not written, so the projection is Stale — with NO
        // unprojected intent at all (nothing for this run to have applied yet).
        let in_flight = vec![(refs[1].clone(), MemberState::InFlight)];
        assert_eq!(
            plan_projection_writes(&mut session.lock().expect("session lock"), &in_flight, vec![]),
            (
                ProjectionState::Stale {
                    reason: PLAN_MEMBER_IN_FLIGHT_REASON.to_string()
                },
                Vec::new()
            )
        );
        assert_eq!(inbox_refs(&session).len(), 2, "an in-flight member's row is untouched");
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// A marker/write failure AFTER
    /// the effect already applied folds into `ProjectionState::Stale`, never `?`-propagated past
    /// the writer — `plan_projection_writes` itself never returns a `Result`, so there is no error
    /// channel here to leak one through (the same shape `apply_verb_delta`'s doc always required
    /// of the earlier single-member writer). The STRUCTURAL half of this claim — that the
    /// outcome's applied members and undo keys survive a Stale projection — is `plan_apply_outcome`'s
    /// own signature: `drive: PlanDrive` and `projection: ProjectionState` are independent
    /// parameters, computed before and after the writer runs respectively, so a Stale projection
    /// cannot retroactively erase what `drive` already recorded — never re-tested end-to-end here
    /// through a full `plan_apply_door` (which needs a live `PhotonState` + provider), since the
    /// type signature already makes it true by construction.
    #[test]
    fn a_marker_failure_after_the_effect_keeps_the_applied_report() {
        let (path, _state, session) = session_for("s1-p3-marker-failure");
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &[page_row("M000", 1_758_672_000_000)],
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb");
        let refs = inbox_refs(&session);
        let message_ref = refs[0].clone();

        // The SAME failpoint-trigger idiom this file's own `R2_3_WITNESS_WRITE_FAILPOINT` uses:
        // fail the header half of the placement-moving pair `write_verb_delta_tx` writes, inside
        // `project_applied_intent`'s own transaction.
        rusqlite::Connection::open(&path)
            .expect("raw connection")
            .execute_batch(
                "CREATE TRIGGER p3_marker_failure_failpoint BEFORE UPDATE OF mailbox ON message_header
                   BEGIN SELECT RAISE(ABORT, 'failpoint: header write failed'); END;",
            )
            .expect("install the failpoint");

        let intent = applied_unprojected_intent(&path, "k-marker-failure", &message_ref, Some(1));
        let (projection, newly_projected) = plan_projection_writes(
            &mut session.lock().expect("session lock"),
            &[],
            vec![intent],
        );
        match &projection {
            ProjectionState::Stale { reason } => {
                assert!(reason.contains("failpoint"), "the REAL reason, verbatim: {reason}");
            }
            ProjectionState::Current => panic!("an injected write failure must not read Current"),
        }
        assert!(
            newly_projected.is_empty(),
            "the failed key is never reported as newly projected: {newly_projected:?}"
        );
        // The row itself: untouched — the failure rolled back inside the door's own transaction.
        assert!(inbox_refs(&session).contains(&message_ref), "the row never moved");
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// Reproduction probe, copied in verbatim. Original doc, verbatim:
    ///
    /// The crash between the catch-up writer's two commits, modeled with the SAME hand-built
    /// `applied_unprojected_intent` fixture and the SAME production `plan_projection_writes` door
    /// the test above drives — never `mark_projected` (so the intent stays exactly what an
    /// unprojected store row would still hand the writer on a later run: this same `Intent`,
    /// `projected: false`, run through `plan_projection_writes` a second time).
    #[test]
    fn a_delayed_projection_never_overwrites_a_newer_observation() {
        let (path, _state, session) = session_for("driver-r5-p5");
        // The message starts in the Inbox.
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &[page_row("K000", 1_758_672_000_000)],
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb page 1");
        let refs = inbox_refs(&session);
        let message_ref = refs[0].clone();

        // An EARLIER run of the catch-up writer already applied this plan member's Trash delta —
        // through the SAME production door, never `apply_verb_delta` directly — but crashed before
        // the follow-up `mark_projected` (`plan_apply_door`'s own doc: "a crash between the two
        // leaves the row projected = 0, and the next run... finds it again... and simply
        // retries").
        let intent = applied_unprojected_intent(&path, "k-driver-r5-p5", &message_ref, Some(1));
        let (proj1, newly1) = plan_projection_writes(&mut session.lock().expect("session lock"), &[], vec![intent.clone()]);
        assert_eq!(proj1, ProjectionState::Current);
        assert_eq!(newly1, vec!["k-driver-r5-p5".to_string()]);
        assert!(
            inbox_refs(&session).is_empty(),
            "the earlier (crashed) run moved the message to Trash"
        );

        // A NEWER local observation: a later provider sync re-lists the SAME message as (again)
        // in the Inbox.
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &[page_row("K000", 1_758_672_005_000)],
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb page 2 — the newer observation");
        assert_eq!(
            inbox_refs(&session),
            vec![message_ref.clone()],
            "the newer observation put it back in the inbox"
        );

        // The production catch-up writer, re-driven — the SAME hand-built intent, since nothing
        // ever called `mark_projected` for its key (exactly what a real store's own
        // `applied_unprojected_forward_intents()` would still hand back).
        let (proj2, newly2) = plan_projection_writes(&mut session.lock().expect("session lock"), &[], vec![intent]);
        assert_eq!(proj2, ProjectionState::Current);
        assert_eq!(newly2, vec!["k-driver-r5-p5".to_string()]);

        // RED at 6c49b97: `write_verb_delta` unconditionally overwrites the placement — the
        // delayed Trash delta clobbers the newer Inbox observation.
        assert_eq!(
            inbox_refs(&session),
            vec![message_ref],
            "the newer observation must still win — the message must still read Inbox"
        );
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// A SKIP IS NEVER `Current`. The
    /// schedule: an intent is recorded (and settles `Applied`) at revision 1; a refresh — a newer
    /// LOCAL observation — bumps the SAME message's header to revision 2 BEFORE this intent's own
    /// effect is ever projected. The provider effect genuinely happened, but the local revision it
    /// was recorded against is now stale, so the door SKIPS the write
    /// (`SupersededByNewerObservation`) rather than risk overwriting the newer observation. Pre-
    /// fix the shell's `From<Result<ProjectionWrite, LogError>>` folded BOTH `Ok` arms into
    /// `Current` — a false claim that the row now reflects this intent's own effect, when the
    /// write never ran at all.
    #[test]
    fn a_skip_answers_stale_never_current() {
        let (path, _state, session) = session_for("s1-r6-skip-stale");
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &[page_row("SKIP000", 1_758_672_000_000)],
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb page 1 — the message at revision 1");
        let refs = inbox_refs(&session);
        let message_ref = refs[0].clone();

        // Recorded (and settled Applied) at revision 1 — a real row behind the door's own key.
        let _intent = applied_unprojected_intent(&path, "k-r6-skip-stale", &message_ref, Some(1));

        // A refresh lands BEFORE this intent's own effect is ever projected — the SAME message
        // observed again, bumping its header past the basis this intent was recorded against.
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &[page_row("SKIP000", 1_758_672_005_000)],
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb page 2 — the newer observation (revision 2)");

        let projection = ProjectionState::from(
            session
                .lock()
                .expect("session lock")
                .coordinator
                .project_applied_intent("k-r6-skip-stale"),
        );
        match projection {
            ProjectionState::Stale { .. } => {}
            ProjectionState::Current => panic!(
                "RED at the pin: a superseded/skipped write must never read Current — the row \
                 does not reflect this intent's own effect"
            ),
        }
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// The observation a test connector answers for a Trash member still in the Inbox.
    const S1_IN_INBOX: [(&str, bool); 2] = [("membership:INBOX", true), ("label:TRASH", false)];

    /// A bus over a REAL store holding `n` inbox rows, with the engine's counting test connector,
    /// the engine's in-memory ratchet admitting `me@e` at generation 1, and a root key verified
    /// into the store — and the rows' refs in CANONICAL (byte) order, the plan's member order.
    fn s1_driver_bus(
        tag: &str,
        n: usize,
        connector: aruna::CountingConnector,
    ) -> (
        SessionTemp,
        CommandBus<SqliteIntentLog, aruna::CountingConnector>,
        Vec<String>,
    ) {
        let (path, _state, session) = session_for(tag);
        let rows: Vec<HeaderSummary> = (0..n)
            .map(|i| page_row(&format!("D{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page(
                "acct",
                &rows,
                None,
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("absorb");
        let mut refs = inbox_refs(&session);
        refs.sort();
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let root = aruna::key_custody::root_key_verified(
            &aruna::key_custody::InMemoryCustody::new(),
            &mut log,
        )
        .unwrap();
        let bus = CommandBus::new(log, connector)
            .with_grant_ratchet(Box::new(aruna::InMemoryGrantRatchet {
                high_water: Some(1),
                principal: "me@e".into(),
            }))
            .with_root_key(root);
        (path, bus, refs)
    }

    fn s1_approved_trash_plan(
        bus: &mut CommandBus<SqliteIntentLog, aruna::CountingConnector>,
        refs: &[String],
    ) -> PlanId {
        let review = plan_mint_on(
            bus,
            aruna::plan::PlanSpec {
                account: "acct".into(),
                provider_principal: "me@e".into(),
                grant_generation: 1,
                verb: PlanVerb::Trash,
                member_refs: refs.to_vec(),
                rationale: None,
                ttl_seconds: PLAN_TTL_SECONDS,
            },
        )
        .expect("mint");
        let id = PlanId(review.plan_id.clone());
        plan_approve_on(
            bus,
            &id,
            RenderedViewWire::FullList {
                presentation: review.presentation,
            },
            "operator",
        )
        .expect("approve");
        id
    }

    #[test]
    fn the_plan_driver_runs_every_member_and_a_member_refusal_never_aborts_the_loop() {
        use aruna::episode::Completion;
        use aruna::plan::{MemberState, PreflightOutcome};
        // (a) backups ON — the default: every member's send fence refuses `snapshot_absent`
        // (S-SNAP is not built). Each refusal is RECORDED and the loop continues to the next
        // member (neighbours continue); nothing reaches the wire.
        let (path, mut bus, refs) =
            s1_driver_bus("s1-driver-refused", 3, aruna::CountingConnector::observing(&S1_IN_INBOX));
        let id = s1_approved_trash_plan(&mut bus, &refs);
        let drive = drive_plan(&mut bus, &id, None).expect("the driver runs");
        assert_eq!(drive.preflight, Some(PreflightOutcome::Ready));
        assert_eq!(drive.stopped, None, "the run went to its end");
        assert_eq!(
            drive.members,
            refs.iter()
                .map(|r| (
                    r.clone(),
                    MemberState::Refused {
                        reason: "snapshot_absent".into(),
                        diff: vec![]
                    }
                ))
                .collect::<Vec<_>>(),
            "EVERY member was attempted — a refusal never aborts the loop"
        );
        assert_eq!(drive.completion, Some(Completion::Completed));
        assert_eq!(bus.connector().apply_count(), 0, "nothing reached the wire");
        drop(bus);
        std::fs::remove_file(&path).ok();

        // (b) backups OFF: every member applies, in canonical order, exact-N completion.
        let (path, mut bus, refs) =
            s1_driver_bus("s1-driver-applied", 2, aruna::CountingConnector::observing(&S1_IN_INBOX));
        bus.log_mut()
            .record_knob_act(aruna::config_knobs::KnobAct::Backups(
                aruna::config_knobs::BackupsKnob::Off,
            ))
            .unwrap();
        let id = s1_approved_trash_plan(&mut bus, &refs);
        let drive = drive_plan(&mut bus, &id, None).expect("the driver runs");
        assert_eq!(
            drive.members,
            refs.iter()
                .map(|r| (r.clone(), MemberState::Applied))
                .collect::<Vec<_>>()
        );
        assert_eq!(drive.completion, Some(Completion::Completed));
        assert_eq!(bus.connector().apply_count(), 2);
        // The wire shape the renderer branches on (the skipped and
        // held members, the applied children's undo keys last first, the bypass notice).
        let plan = bus.log().plan(&id).unwrap().unwrap();
        let key = |member: &str| bus.plan_child_command(&plan, member).idempotency_key;
        let (k0, k1) = (key(&refs[0]), key(&refs[1]));
        let outcome = plan_apply_outcome(&id, drive, ProjectionState::Current);
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            serde_json::json!({
                "plan_id": id.0,
                "preflight": { "outcome": "ready" },
                "members": [[refs[0], { "state": "applied" }], [refs[1], { "state": "applied" }]],
                "completion": "completed",
                "projection": { "state": "current" },
                "skipped": [],
                "held": [],
                "undo_keys": [
                    { "member_ref": refs[1], "undo_key": k1, "restoration": { "verdict": "no_effect_witness" } },
                    { "member_ref": refs[0], "undo_key": k0, "restoration": { "verdict": "no_effect_witness" } }
                ],
                "bypass_notice": null,
                "stopped": null
            })
        );
        drop(bus);
        std::fs::remove_file(&path).ok();

        // (c) a diverged preflight refuses the whole run: no member is attempted.
        let (path, mut bus, refs) =
            s1_driver_bus("s1-driver-stale", 2, aruna::CountingConnector::new());
        let id = s1_approved_trash_plan(&mut bus, &refs);
        let drive = drive_plan(&mut bus, &id, None).expect("the driver runs");
        assert!(matches!(drive.preflight, Some(PreflightOutcome::Refused { .. })));
        assert!(drive
            .members
            .iter()
            .all(|(_, s)| *s == MemberState::NotMinted));
        assert_eq!(bus.connector().apply_count(), 0);
        let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current))
            .unwrap();
        assert_eq!(wire["preflight"]["outcome"], "refused");
        assert_eq!(
            wire["preflight"]["diverged"][0][1][0],
            serde_json::json!({ "atom": "membership:INBOX", "expected": true, "observed": false })
        );
        assert_eq!(wire["members"][0][1], serde_json::json!({ "state": "not_minted" }));
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// A STATEFUL plan-verb connector for the driver tests: every member reads as an Inbox message
    /// until its Trash lands (then it reads trashed) and again once restored. Scripted per member:
    /// `deterministic` refuses every dispatch (the provider answered: no effect); `transient_once`
    /// fails the FIRST dispatch proven pre-wire (the child stays in flight); `diverge_after_first`
    /// reads trashed from its SECOND observation on (the preflight passes, the capture diverges, so
    /// the send fence refuses `state_diverged`). Applies and restores are recorded in order.
    #[derive(Default)]
    struct S1ScriptedConnector {
        trashed: std::cell::RefCell<BTreeSet<String>>,
        deterministic: BTreeSet<String>,
        transient_once: std::cell::RefCell<BTreeSet<String>>,
        diverge_after_first: Option<String>,
        observes: std::cell::RefCell<std::collections::BTreeMap<String, usize>>,
        applied: std::cell::RefCell<Vec<String>>,
        restored: std::cell::RefCell<Vec<String>>,
    }

    impl Connector for S1ScriptedConnector {
        fn apply(
            &self,
            command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
        ) -> Result<(), aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            if self.deterministic.contains(&member) {
                return Err(aruna::ConnectorError::deterministic("test: the provider refused")
                    .proven_refused_no_effect());
            }
            if self.transient_once.borrow_mut().remove(&member) {
                return Err(aruna::ConnectorError::transient("test: connect refused").proven_no_wire());
            }
            self.trashed.borrow_mut().insert(member.clone());
            self.applied.borrow_mut().push(member);
            Ok(())
        }
        fn resolve_basis(
            &self,
            command: &Command,
        ) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
            Ok(aruna::test_support::fixture_basis(command))
        }
        fn observe(
            &self,
            command: &Command,
            basis: &aruna::prestate::FrozenBasis,
        ) -> Result<aruna::prestate::Observation, aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            let seen = {
                let mut observes = self.observes.borrow_mut();
                let n = observes.entry(member.clone()).or_insert(0);
                *n += 1;
                *n
            };
            let trashed = self.trashed.borrow().contains(&member)
                || (self.diverge_after_first.as_deref() == Some(member.as_str()) && seen > 1);
            Ok(aruna::test_support::fixture_observation_with(
                basis,
                &[("label:TRASH", trashed), ("membership:INBOX", !trashed)],
            ))
        }
        fn restore(
            &self,
            command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
            _p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            self.trashed.borrow_mut().remove(&member);
            self.restored.borrow_mut().push(member);
            Ok(())
        }
    }

    /// `s1_driver_bus`'s store and ratchet over the scripted connector, `backups: off` recorded
    /// (so an admitted member reaches the wire), and a full-list Trash plan over every row approved.
    fn s1_fold_bus(
        tag: &str,
        n: usize,
        script: impl FnOnce(&[String]) -> S1ScriptedConnector,
    ) -> (SessionTemp, CommandBus<SqliteIntentLog, S1ScriptedConnector>, Vec<String>, PlanId) {
        let (path, _state, session) = session_for(tag);
        let rows: Vec<HeaderSummary> = (0..n)
            .map(|i| page_row(&format!("F{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page("acct", &rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
            .expect("absorb");
        let mut refs = inbox_refs(&session);
        refs.sort();
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let root = aruna::key_custody::root_key_verified(&aruna::key_custody::InMemoryCustody::new(), &mut log)
            .unwrap();
        log.record_knob_act(aruna::config_knobs::KnobAct::Backups(aruna::config_knobs::BackupsKnob::Off))
            .unwrap();
        let connector = script(&refs);
        let mut bus = CommandBus::new(log, connector)
            .with_grant_ratchet(Box::new(aruna::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
            .with_root_key(root);
        let review = plan_mint_on(
            &mut bus,
            aruna::plan::PlanSpec {
                account: "acct".into(),
                provider_principal: "me@e".into(),
                grant_generation: 1,
                verb: PlanVerb::Trash,
                member_refs: refs.clone(),
                rationale: None,
                ttl_seconds: PLAN_TTL_SECONDS,
            },
        )
        .expect("mint");
        let id = PlanId(review.plan_id.clone());
        plan_approve_on(&mut bus, &id, RenderedViewWire::FullList { presentation: review.presentation }, "operator")
            .expect("approve");
        (path, bus, refs, id)
    }

    // ===========================================================================================
    // Drive_plan continues past settled members and recovers held ones
    // ===========================================================================================

    #[test]
    fn a_failed_member_never_stops_the_members_after_it() {
        use aruna::plan::MemberState;
        let (path, mut bus, refs, id) = s1_fold_bus("s1-fold-failed", 3, |refs| S1ScriptedConnector {
            deterministic: [refs[0].clone()].into_iter().collect(),
            ..Default::default()
        });
        let drive = drive_plan(&mut bus, &id, None).expect("the driver runs past a failed member");
        assert_eq!(
            drive.members,
            vec![
                (refs[0].clone(), MemberState::Terminal(aruna::IntentStatus::Failed)),
                (refs[1].clone(), MemberState::Applied),
                (refs[2].clone(), MemberState::Applied),
            ],
            "member 1 Failed ⇒ members 2..N apply"
        );
        assert_eq!(*bus.connector().applied.borrow(), vec![refs[1].clone(), refs[2].clone()]);
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_held_member_is_re_driven_through_recovery_and_settled_members_are_skipped() {
        use aruna::plan::MemberState;
        // Run 1: member 1's first dispatch fails proven pre-wire (its child stays IN FLIGHT),
        // member 2 is refused by the provider (Failed), member 3 applies.
        let (path, mut bus, refs, id) = s1_fold_bus("s1-fold-held", 3, |refs| S1ScriptedConnector {
            transient_once: std::cell::RefCell::new([refs[0].clone()].into_iter().collect()),
            deterministic: [refs[1].clone()].into_iter().collect(),
            ..Default::default()
        });
        let first = drive_plan(&mut bus, &id, None).expect("run 1 continues past the held member");
        assert_eq!(
            first.members,
            vec![
                (refs[0].clone(), MemberState::InFlight),
                (refs[1].clone(), MemberState::Terminal(aruna::IntentStatus::Failed)),
                (refs[2].clone(), MemberState::Applied),
            ]
        );
        assert!(
            first.skipped.is_empty() && first.held.is_empty(),
            "run 1 found every member unminted: {:?} / {:?}",
            first.skipped,
            first.held
        );
        assert!(matches!(first.completion, Some(aruna::episode::Completion::Incomplete { .. })));
        // Run 2: the held member is RE-DRIVEN through recovery (the transient is spent, so it
        // applies); the settled two are skipped — neither re-driven nor allowed to stop the run.
        let second = drive_plan(&mut bus, &id, None).expect("run 2 resumes");
        assert_eq!(
            second.members,
            vec![
                (refs[0].clone(), MemberState::Applied),
                (refs[1].clone(), MemberState::Terminal(aruna::IntentStatus::Failed)),
                (refs[2].clone(), MemberState::Applied),
            ]
        );
        assert_eq!(
            *bus.connector().applied.borrow(),
            vec![refs[2].clone(), refs[0].clone()],
            "recovery re-drove the held member; the applied one was never re-dispatched"
        );
        assert_eq!(second.held, vec![refs[0].clone()], "the held member is reported");
        assert_eq!(second.skipped, vec![refs[1].clone(), refs[2].clone()], "the settled members are reported");
        assert_eq!(second.completion, Some(aruna::episode::Completion::Completed));
        let wire = serde_json::to_value(plan_apply_outcome(&id, second, ProjectionState::Current)).unwrap();
        assert_eq!(wire["held"], serde_json::json!([refs[0]]));
        assert_eq!(wire["skipped"], serde_json::json!([refs[1], refs[2]]));
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// A connector that goes IN FLIGHT once (a proven-pre-wire transient) then applies with a REAL
    /// effect witness (a non-empty label vector) — the shape the R2_3 witness-write failpoint needs
    /// to fire on (`S1ScriptedConnector`'s default `apply_witnessed` produces an EMPTY witness, so
    /// the failpoint's trigger — armed on the witness UPDATE — never runs against it).
    #[derive(Default)]
    struct S1HeldWitnessConnector {
        transient_once: std::cell::RefCell<std::collections::BTreeSet<String>>,
        trashed: std::cell::RefCell<std::collections::BTreeSet<String>>,
    }
    impl Connector for S1HeldWitnessConnector {
        fn apply(&self, command: &Command, basis: &aruna::prestate::FrozenBasis) -> Result<(), aruna::ConnectorError> {
            self.apply_witnessed(command, basis).map(|_| ())
        }
        fn apply_witnessed(
            &self,
            command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
        ) -> Result<aruna::EffectWitness, aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            if self.transient_once.borrow_mut().remove(&member) {
                return Err(aruna::ConnectorError::transient("test: connect refused").proven_no_wire());
            }
            self.trashed.borrow_mut().insert(member);
            Ok(aruna::EffectWitness { provider_label_vector: Some(["TRASH".to_string()].into_iter().collect()) })
        }
        fn resolve_basis(&self, command: &Command) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
            Ok(aruna::test_support::fixture_basis(command))
        }
        fn observe(
            &self,
            command: &Command,
            basis: &aruna::prestate::FrozenBasis,
        ) -> Result<aruna::prestate::Observation, aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            let trashed = self.trashed.borrow().contains(&member);
            Ok(aruna::test_support::fixture_observation_with(basis, &[("label:TRASH", trashed), ("membership:INBOX", !trashed)]))
        }
        fn restore(
            &self,
            _command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
            _p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), aruna::ConnectorError> {
            Ok(())
        }
    }

    /// A HELD member re-driven through
    /// `recover()` whose effect-witness write then fails is STILL counted `Applied` and STILL
    /// unprojected in the store — the OLD derivation (`progress.held.contains(member)`, `held`
    /// pushed AFTER the fallible `recover()` call) risked losing it from the run-window
    /// `applied_this_run` vector. That
    /// vector, and the whole per-run derivation it lived in, is DELETED — the store's own
    /// `applied_unprojected_forward_intents` is asked directly here instead, so the property this
    /// test proves ("the held member's recovery-sweep apply is visible to the projection writer,
    /// even though its witness write failed") no longer depends on any in-loop bookkeeping at all.
    #[test]
    fn a_held_members_witness_write_failure_still_counts_applied_this_run() {
        use aruna::plan::MemberState;
        let (path, mut bus, refs) = plan_bus("s1-fold-r3-p-b", 1, |_| S1HeldWitnessConnector::default());
        bus.connector().transient_once.borrow_mut().insert(refs[0].clone());
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let first = drive_plan(&mut bus, &id, None).expect("run 1 holds the member");
        assert_eq!(first.members, vec![(refs[0].clone(), MemberState::InFlight)]);
        assert!(
            bus.log().applied_unprojected_forward_intents().expect("read unprojected").is_empty(),
            "nothing applied yet"
        );
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(R2_3_WITNESS_WRITE_FAILPOINT)
            .expect("arm the failpoint");
        let second = drive_plan(&mut bus, &id, None).expect("run 2 resumes despite the witness-write failure");
        assert_eq!(second.members, vec![(refs[0].clone(), MemberState::Applied)]);
        let unprojected = bus.log().applied_unprojected_forward_intents().expect("read unprojected");
        assert_eq!(
            unprojected.iter().map(|i| s1_fold_message_ref(&i.command.action)).collect::<Vec<_>>(),
            vec![refs[0].clone()],
            "the held member's recovery-sweep apply IS visible to the writer, even though its witness write failed"
        );
        assert_eq!(second.completion, Some(aruna::episode::Completion::Completed));
        assert_eq!(second.undo_keys.len(), 1, "the applied member keeps its undo offer");
        assert_eq!(
            second.undo_keys[0].restoration,
            Some(RestorationView::WitnessWriteFailed),
            "the undo offer is honest about the unrecorded witness"
        );
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// A connector whose `apply` refuses one named member with a `credential_rejected` connector
    /// error (an HTTP 401-class provider answer) — deterministic, so the child dead-letters
    /// `Failed` immediately, exactly the shape that "leaves a recorded Failed child".
    #[derive(Default)]
    struct S1CredentialRejectedConnector {
        reject: std::cell::RefCell<std::collections::BTreeSet<String>>,
    }
    impl Connector for S1CredentialRejectedConnector {
        fn apply(&self, command: &Command, _basis: &aruna::prestate::FrozenBasis) -> Result<(), aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            if self.reject.borrow().contains(&member) {
                return Err(aruna::ConnectorError::deterministic("test: 401 unauthorized").credential_rejected());
            }
            Ok(())
        }
        fn resolve_basis(&self, command: &Command) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
            Ok(aruna::test_support::fixture_basis(command))
        }
        fn observe(
            &self,
            _command: &Command,
            basis: &aruna::prestate::FrozenBasis,
        ) -> Result<aruna::prestate::Observation, aruna::ConnectorError> {
            Ok(aruna::test_support::fixture_observation_with(basis, &[("label:TRASH", false), ("membership:INBOX", true)]))
        }
        fn restore(
            &self,
            _command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
            _p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), aruna::ConnectorError> {
            Ok(())
        }
    }

    /// A `credential_rejected`
    /// connector error DURING a member's dispatch (not at preflight — preflight's own observe
    /// succeeds here) ENDS THE RUN. The OLD rule treated the recorded `Failed` child as "this
    /// member's own outcome" and moved on to the next member, which would meet the identical
    /// expired-credential wall and fail too, one at a time, under a name that never says WHY. The
    /// fix: every LATER member stays untouched (`NotMinted`), so it is retryable once the
    /// credential is current again. Asserts the TYPED kind, never a `credential_rejected: `
    /// string prefix a caller had to parse out of `Refused`'s free-text `reason` (the pre-B2
    /// shape) — the stop is `SurfaceError::CredentialRejected` by itself, no `reason` field to
    /// carry a connector message onto the wire at all.
    #[test]
    fn a_credential_rejected_mid_run_ends_the_run_leaving_later_members_retryable() {
        use aruna::plan::MemberState;
        let (path, mut bus, refs) = plan_bus("s1-fold-r3-r3-2", 2, |_| S1CredentialRejectedConnector::default());
        bus.connector().reject.borrow_mut().insert(refs[0].clone());
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let drive = drive_plan(&mut bus, &id, None).expect("the run answers its outcome, not a bare error");
        assert_eq!(
            drive.stopped,
            Some(SurfaceError::CredentialRejected),
            "the stop is its own typed kind, never a Refused string a caller must parse"
        );
        assert_eq!(drive.members[1], (refs[1].clone(), MemberState::NotMinted), "member 2 was NEVER attempted — still retryable");
        // `applied_this_run` is deleted; the equivalent
        // store-derived proof is that nothing forward is `Applied`+unprojected at all.
        assert!(
            bus.log().applied_unprojected_forward_intents().expect("read unprojected").is_empty(),
            "nothing applied this run"
        );
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// A connector that logs EVERY `apply` attempt by member (success or failure) — member 0 goes
    /// IN FLIGHT on its first call (a proven-pre-wire transient) and is rejected on its SECOND
    /// (recovery's redispatch) with a `credential_rejected` connector error; every other member
    /// always succeeds. Built to witness exactly which
    /// members the driver ever touched.
    #[derive(Default)]
    struct S1RecoveryCredentialRejectedConnector {
        calls: std::cell::RefCell<Vec<String>>,
        transient_once: std::cell::RefCell<std::collections::BTreeSet<String>>,
        reject_on_retry: std::cell::RefCell<std::collections::BTreeSet<String>>,
    }
    impl Connector for S1RecoveryCredentialRejectedConnector {
        fn apply(&self, command: &Command, _basis: &aruna::prestate::FrozenBasis) -> Result<(), aruna::ConnectorError> {
            let member = s1_fold_message_ref(&command.action);
            self.calls.borrow_mut().push(member.clone());
            if self.transient_once.borrow_mut().remove(&member) {
                return Err(aruna::ConnectorError::transient("test: connect refused").proven_no_wire());
            }
            if self.reject_on_retry.borrow().contains(&member) {
                return Err(aruna::ConnectorError::deterministic("test: 401 unauthorized")
                    .credential_rejected()
                    .proven_refused_no_effect());
            }
            Ok(())
        }
        fn resolve_basis(&self, command: &Command) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
            Ok(aruna::test_support::fixture_basis(command))
        }
        fn observe(
            &self,
            _command: &Command,
            basis: &aruna::prestate::FrozenBasis,
        ) -> Result<aruna::prestate::Observation, aruna::ConnectorError> {
            Ok(aruna::test_support::fixture_observation_with(basis, &[("label:TRASH", false), ("membership:INBOX", true)]))
        }
        fn restore(
            &self,
            _command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
            _p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), aruna::ConnectorError> {
            Ok(())
        }
    }

    /// A credential rejection
    /// MET DURING RECOVERY (a held member's re-drive, not a fresh `NotMinted` dispatch) must stop
    /// the run exactly like the dispatch-path stop above — the OLD rule only ever inspected
    /// `RecoverReport::witness_write_failed` and silently discarded `RecoverReport::failed`, so
    /// the sweep dead-lettered the held member `Failed` and the loop then walked on to every
    /// sibling member as if nothing run-ending had happened.
    ///
    /// Member 0 is put IN FLIGHT by a DIRECT `apply_plan_member` call (never through `drive_plan`,
    /// so members 1 and 2 are not touched by that call at all); the one `drive_plan` call in this
    /// test is then entirely the RECOVERY run.
    #[test]
    fn a_credential_rejection_during_recovery_stops_the_run_leaving_later_members_untouched() {
        use aruna::plan::MemberState;
        let (path, mut bus, refs) = plan_bus("s1-fold-r4-e", 3, |_| S1RecoveryCredentialRejectedConnector::default());
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        // Run 1: EVERY member's first dispatch fails proven pre-wire (transient) — all three go
        // IN FLIGHT; a transient failure never stops the run, so the loop reaches every member.
        for r in &refs {
            bus.connector().transient_once.borrow_mut().insert(r.clone());
        }
        let first = drive_plan(&mut bus, &id, None).expect("run 1 continues past every held member");
        assert_eq!(
            first.members,
            vec![
                (refs[0].clone(), MemberState::InFlight),
                (refs[1].clone(), MemberState::InFlight),
                (refs[2].clone(), MemberState::InFlight),
            ],
            "precondition: all three members are held after run 1"
        );
        assert_eq!(*bus.connector().calls.borrow(), refs.clone(), "run 1 touched every member exactly once");
        bus.connector().calls.borrow_mut().clear();
        // Run 2 IS the recovery run: member 0 (canonical order — the lowest `seq`, so `recover()`'s
        // sweep meets it FIRST) is scripted to answer `credential_rejected` on its redispatch.
        bus.connector().reject_on_retry.borrow_mut().insert(refs[0].clone());
        let second = drive_plan(&mut bus, &id, None).expect("the run answers its outcome, not a bare error");
        assert_eq!(
            second.stopped,
            Some(SurfaceError::CredentialRejected),
            "the recovery sweep's own run-ending connector error stops the run, exactly like a fresh dispatch's"
        );
        assert_eq!(
            *bus.connector().calls.borrow(),
            vec![refs[0].clone()],
            "the recovery sweep redispatched ONLY member 0 before its credential_rejected stopped it — \
             members 1 and 2 were never redispatched at all"
        );
        assert_eq!(
            bus.plan_member_states(&id).unwrap(),
            vec![
                (refs[0].clone(), MemberState::Terminal(aruna::IntentStatus::Failed)),
                (refs[1].clone(), MemberState::InFlight),
                (refs[2].clone(), MemberState::InFlight),
            ],
            "members 1 and 2 stay IN FLIGHT, untouched — the OLD rule would have redispatched and \
             settled them in this same sweep"
        );
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    // ===========================================================================================
    // The bypass lane skips the screen; the undo route for plan members
    // ===========================================================================================

    #[test]
    fn the_bypass_lane_approves_mechanically_under_the_frozen_generation_and_carries_its_notice() {
        use aruna::config_knobs::{BackupsKnob, KnobAct, RedBypassKnob};
        use aruna::plan::{AdmissionLane, Comprehension, MemberState};
        let (path, mut bus, refs) =
            s1_driver_bus("s1-fold-bypass", 5, aruna::CountingConnector::observing(&S1_IN_INBOX));
        let spec = |member: &str| aruna::plan::PlanSpec {
            account: "acct".into(),
            provider_principal: "me@e".into(),
            grant_generation: 1,
            verb: PlanVerb::Trash,
            member_refs: vec![member.to_string()],
            rationale: None,
            ttl_seconds: PLAN_TTL_SECONDS,
        };
        bus.log_mut().record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        let frozen = bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();

        // (a) Minted under the bypass with backups off: the bypass lane, with its frozen notice.
        let review = plan_mint_on(&mut bus, spec(&refs[0])).expect("mint");
        assert_eq!(review.lane, LaneView::Bypassed);
        assert_eq!(review.bypass_notice.as_deref(), Some(PlanVerb::Trash.uncovered_warning()));
        assert!(!review.approved, "minting approves nothing");
        let id = PlanId(review.plan_id.clone());

        // (b) The mechanical approval, through the engine's one approval door, binds the
        // generation the plan FROZE at mint — and a second call records nothing more.
        let approved = approve_bypassed_on(&mut bus, &id)
            .expect("the door answers")
            .expect("a bypass-lane plan is approved mechanically");
        assert_eq!(
            (approved.comprehension.as_str(), approved.approver.as_str()),
            ("bypassed", BYPASS_APPROVER)
        );
        assert_eq!(BYPASS_APPROVER, "mechanical");
        assert_eq!(
            bus.log().plan(&id).unwrap().unwrap().admission_lane,
            AdmissionLane::Bypassed { bypass_config_generation: frozen }
        );
        assert_eq!(
            bus.log().approval(&id).unwrap().expect("recorded").comprehension,
            Comprehension::Bypassed { bypass_config_generation: frozen }
        );
        assert_eq!(approve_bypassed_on(&mut bus, &id).expect("answers"), None);
        let drive = drive_plan(&mut bus, &id, None).expect("the bypass plan runs");
        assert_eq!(drive.members, vec![(refs[0].clone(), MemberState::Applied)]);
        let outcome = plan_apply_outcome(&id, drive, ProjectionState::Current);
        assert_eq!(
            outcome.bypass_notice.as_deref(),
            Some(PlanVerb::Trash.uncovered_warning()),
            "the outcome repeats the notice"
        );

        // (c) The bypass knob MOVED since mint: the frozen generation is no longer the one in
        // force — refused by name (`evidence_invalid`), nothing recorded, nothing runs.
        let stale = PlanId(plan_mint_on(&mut bus, spec(&refs[1])).expect("mint").plan_id);
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::Off)).unwrap();
        let current = bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
        assert_ne!(current, frozen);
        assert_eq!(
            approve_bypassed_on(&mut bus, &stale).unwrap_err(),
            SurfaceError::plan_whole(PlanWireToken::BypassGenerationMismatch)
        );
        assert!(bus.log().approval(&stale).unwrap().is_none());

        // (d) A plan frozen on a SCREEN lane owes its screen even with the bypass on NOW: this
        // path approves nothing for it — and it never carries the notice (backups are off, so
        // its header carries the verb warning, which is the SCREEN's line, not the bypass notice).
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::Off)).unwrap();
        let screen = plan_mint_on(&mut bus, spec(&refs[2])).expect("mint");
        assert_eq!(screen.lane, LaneView::PerMember);
        assert!(screen.presentation.header.warning.is_some());
        assert_eq!(screen.bypass_notice, None, "a non-bypass plan never carries the notice");
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
        let screen_id = PlanId(screen.plan_id);
        assert_eq!(approve_bypassed_on(&mut bus, &screen_id).expect("answers"), None);
        assert!(bus.log().approval(&screen_id).unwrap().is_none(), "no screen, no approval");

        // (e) The bypass lane with backups ON: no screen, and no notice (nothing is uncovered).
        bus.log_mut().record_knob_act(KnobAct::Backups(BackupsKnob::On)).unwrap();
        let covered = plan_mint_on(&mut bus, spec(&refs[3])).expect("mint");
        assert_eq!(covered.lane, LaneView::Bypassed);
        assert_eq!(covered.bypass_notice, None);
        assert_eq!(bus.connector().apply_count(), 1, "only the approved bypass plan ran");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_applied_children_undo_last_first_and_a_refused_one_is_not_undone() {
        use aruna::plan::MemberState;
        let (path, mut bus, refs, id) = s1_fold_bus("s1-fold-undo", 3, |refs| S1ScriptedConnector {
            diverge_after_first: Some(refs[1].clone()),
            ..Default::default()
        });
        let drive = drive_plan(&mut bus, &id, None).expect("the driver runs");
        assert_eq!(drive.members[0], (refs[0].clone(), MemberState::Applied));
        assert!(
            matches!(&drive.members[1].1, MemberState::Refused { reason, .. } if reason == "state_diverged"),
            "member 2 is refused at the send fence: {:?}",
            drive.members[1]
        );
        assert_eq!(drive.members[2], (refs[2].clone(), MemberState::Applied));
        let plan = bus.log().plan(&id).unwrap().unwrap();
        let (k0, k1, k2) = (
            bus.plan_child_command(&plan, &refs[0]).idempotency_key,
            bus.plan_child_command(&plan, &refs[1]).idempotency_key,
            bus.plan_child_command(&plan, &refs[2]).idempotency_key,
        );
        let outcome = plan_apply_outcome(&id, drive, ProjectionState::Current);
        assert_eq!(
            outcome
                .undo_keys
                .iter()
                .map(|offer| (offer.member_ref.clone(), offer.undo_key.clone()))
                .collect::<Vec<_>>(),
            vec![(refs[2].clone(), k2.clone()), (refs[0].clone(), k0.clone())],
            "the APPLIED children only, in REVERSE canonical order"
        );
        assert_eq!(
            serde_json::to_value(&outcome).unwrap()["undo_keys"],
            serde_json::json!([
                { "member_ref": refs[2], "undo_key": k2, "restoration": { "verdict": "no_effect_witness" } },
                { "member_ref": refs[0], "undo_key": k0, "restoration": { "verdict": "no_effect_witness" } }
            ])
        );
        // The renderer's undo walk: one existing `undo` door call per key, in the order given.
        for key in outcome.undo_keys.iter().map(|offer| &offer.undo_key) {
            bus.undo(key).expect("the child undoes");
            assert_eq!(
                bus.undo_presentation(key).unwrap().expect("exists").presentation,
                UndoPresentation::Undone
            );
        }
        assert_eq!(
            *bus.connector().restored.borrow(),
            vec![refs[2].clone(), refs[0].clone()],
            "last first"
        );
        assert_eq!(
            bus.log().get(&k1).unwrap().expect("the refused child").status,
            aruna::IntentStatus::Failed,
            "the refused child was not undone"
        );
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_member_status_token_is_the_engines_own_spelling() {
        // The shell keeps no second copy of the status map: a terminal member's token is
        // `aruna::status_to_str`'s.
        assert_eq!(
            MemberStateView::from(aruna::plan::MemberState::Terminal(aruna::IntentStatus::ExternallySatisfied)),
            MemberStateView::Terminal { status: "externally_satisfied".to_string() }
        );
    }

    fn plan_spec(members: &[String], verb: PlanVerb) -> PlanSpec {
        PlanSpec {
            account: "acct".into(),
            provider_principal: "me@e".into(),
            grant_generation: 1,
            verb,
            member_refs: members.to_vec(),
            rationale: None,
            ttl_seconds: PLAN_TTL_SECONDS,
        }
    }

    /// A full-list plan over `members`, minted and approved through the shell's own doors.
    fn approved_plan<C: Connector>(
        bus: &mut CommandBus<SqliteIntentLog, C>,
        members: &[String],
        verb: PlanVerb,
    ) -> PlanId {
        let review = plan_mint_on(bus, plan_spec(members, verb)).expect("mint");
        let id = PlanId(review.plan_id.clone());
        plan_approve_on(bus, &id, RenderedViewWire::FullList { presentation: review.presentation }, "operator")
            .expect("approve");
        id
    }

    // ===========================================================================================
    // Each test below was written FIRST and run against the pre-fix code.
    // ===========================================================================================

    /// The verdict is known when a member applies, so the plan's undo
    /// OFFER carries it — per applied member, beside its undo key — rather than only the undo walk
    /// after the fact.
    #[test]
    fn each_applied_members_undo_offer_carries_its_restoration_verdict() {
        let (path, mut bus, refs) = plan_bus("e-r1-f1", 2, |_| R1LabelConnector::default());
        bus.connector().witness.set(true);
        bus.connector().ripple.borrow_mut().insert(
            refs[0].clone(),
            vec!["IMPORTANT".to_string(), "Label_11".to_string(), "Label_12".to_string()],
        );
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let drive = drive_plan(&mut bus, &id, None).expect("the driver runs");
        let plan = bus.log().plan(&id).unwrap().unwrap();
        let (k0, k1) = (
            bus.plan_child_command(&plan, &refs[0]).idempotency_key,
            bus.plan_child_command(&plan, &refs[1]).idempotency_key,
        );
        let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current)).unwrap();
        assert_eq!(
            wire["undo_keys"],
            serde_json::json!([
                { "member_ref": refs[1], "undo_key": k1, "restoration": { "verdict": "within_closure" } },
                {
                    "member_ref": refs[0],
                    "undo_key": k0,
                    "restoration": { "verdict": "outside_closure", "system_labels": ["IMPORTANT"], "user_label_count": 2 }
                }
            ]),
            "each applied member's undo offer carries its verdict, last first"
        );
        assert!(!wire.to_string().contains("Label_1"), "a user label id never crosses: {wire}");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// Member 1 applies, member 2 stops resolving at its dispatch. The
    /// run ENDS there (the next member would meet the same wall) — but the door answers the run's
    /// OUTCOME carrying why it stopped, never a bare refusal that throws member 1's report away;
    /// and the approved, still-active plan re-applies once the member resolves again.
    #[test]
    fn a_run_that_stops_mid_way_answers_what_it_applied_and_why_and_the_plan_re_applies() {
        let (path, mut bus, refs) = plan_bus("e-r1-f2", 3, |_| R1LabelConnector::default());
        *bus.connector().resolve_fail_after.borrow_mut() = Some((refs[1].clone(), 1));
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let drive = drive_plan(&mut bus, &id, None).expect("a run that stops still answers its outcome");
        let plan = bus.log().plan(&id).unwrap().unwrap();
        let k0 = bus.plan_child_command(&plan, &refs[0]).idempotency_key;
        let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current)).unwrap();
        assert_eq!(wire["preflight"], serde_json::json!({ "outcome": "ready" }));
        assert_eq!(
            wire["members"],
            serde_json::json!([
                [refs[0], { "state": "applied" }],
                [refs[1], { "state": "not_minted" }],
                [refs[2], { "state": "not_minted" }]
            ])
        );
        assert_eq!(wire["undo_keys"].as_array().map(Vec::len), Some(1), "{wire}");
        assert_eq!(wire["undo_keys"][0]["member_ref"], serde_json::json!(refs[0]));
        assert_eq!(wire["undo_keys"][0]["undo_key"], serde_json::json!(k0));
        assert_eq!(
            wire["stopped"],
            // AdmissionRefused classifies transient (its own doc:
            // "documented-RETRYABLE... the SAME command may simply be re-submitted").
            serde_json::json!({ "kind": "refused", "reason": "admission refused: test: the message no longer resolves", "terminal": false })
        );
        assert_eq!(wire["completion"], "incomplete");
        assert_eq!(*bus.connector().applied.borrow(), vec![refs[0].clone()]);
        // The review the renderer re-reads after the stop: approved and NOT terminal — its control
        // is Apply (render.ts).
        let review = review_view_for(&bus, &id).expect("the review reads");
        assert!(review.approved && !review.terminal, "approved, not terminal: {review:?}");
        // The run never closed the episode: once the member resolves, the SAME approved plan runs
        // on, skipping the member that already applied.
        *bus.connector().resolve_fail_after.borrow_mut() = None;
        let again = drive_plan(&mut bus, &id, None).expect("the plan re-applies");
        let wire = serde_json::to_value(plan_apply_outcome(&id, again, ProjectionState::Current)).unwrap();
        assert_eq!(wire["stopped"], serde_json::Value::Null);
        assert_eq!(wire["skipped"], serde_json::json!([refs[0]]));
        assert_eq!(wire["completion"], "completed");
        assert_eq!(
            *bus.connector().applied.borrow(),
            vec![refs[0].clone(), refs[1].clone(), refs[2].clone()]
        );
        assert!(review_view_for(&bus, &id).expect("the review reads").terminal, "a completed plan is terminal");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// Mimics `plan_apply_door`'s own drive-then-project exactly: read the store's unprojected
    /// forward intents, then run them through the ONE writer (`plan_projection_writes`) — so a
    /// test using this helper exercises the real production path, never a hand-rolled substitute
    /// for it. THE PROJECTION DOOR: the SEPARATE mark step this helper
    /// used to run afterward (`bus.log_mut().mark_projected(key)`, one bus acquisition later) is
    /// DELETED along with `plan_apply_door`'s own — `plan_projection_writes` now marks every key
    /// it touches inside `ReadCoordinator::project_applied_intent`'s own transaction, so there is
    /// nothing left for a caller with a bus in scope to do afterward.
    fn project_and_mark<L: IntentLog, C: Connector>(
        bus: &mut CommandBus<L, C>,
        session: &Arc<Mutex<PhotonSession>>,
        plan_members: &[(String, MemberState)],
    ) -> ProjectionState {
        let unprojected = bus.log().applied_unprojected_forward_intents().expect("read unprojected");
        let (state, _newly_projected) =
            plan_projection_writes(&mut session.lock().expect("session lock"), plan_members, unprojected);
        state
    }

    /// Reproduction: run 1 applies member 0 and stops at
    /// member 1; the door projects member 0's trash. A refresh then OBSERVES another client's
    /// restore: member 0's row is back in the Inbox. Run 2 SKIPS member 0 (already settled — it
    /// sends nothing for it) and applies members 1 and 2. The projection after run 2 writes ONLY
    /// what run 2 applied: member 0's row keeps the newer observation, never its historical delta
    /// replayed over it.
    #[test]
    fn a_resumed_run_projects_only_the_members_it_applied_never_a_skipped_members_old_delta() {
        let (path, _state, session) = session_for("cli-r1-c2");
        let rows: Vec<HeaderSummary> = (0..3)
            .map(|i| page_row(&format!("C{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        let absorb = |rows: &[HeaderSummary]| {
            session
                .lock()
                .expect("session lock")
                .absorb_page("acct", rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
                .expect("absorb");
        };
        absorb(&rows);
        let mut refs = inbox_refs(&session);
        refs.sort();
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let root = aruna::key_custody::root_key_verified(&aruna::key_custody::InMemoryCustody::new(), &mut log)
            .unwrap();
        log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        let mut bus = CommandBus::new(log, R1LabelConnector::default())
            .with_grant_ratchet(Box::new(aruna::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
            .with_root_key(root);
        // Run 1: member 0 applies; member 1 stops resolving at its dispatch, so the run stops.
        *bus.connector().resolve_fail_after.borrow_mut() = Some((refs[1].clone(), 1));
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let run1 = drive_plan(&mut bus, &id, None).expect("run 1 answers its outcome");
        assert_eq!(run1.members[0], (refs[0].clone(), MemberState::Applied));
        assert!(run1.skipped.is_empty());
        assert_eq!(project_and_mark(&mut bus, &session, &run1.members), ProjectionState::Current);
        assert_eq!(inbox_refs(&session).len(), 2, "run 1 projected member 0's trash");
        assert!(!inbox_refs(&session).contains(&refs[0]));
        // A refresh observes the mailbox: another client restored member 0 to the Inbox.
        absorb(&rows);
        assert!(inbox_refs(&session).contains(&refs[0]), "the refresh wrote the newer observation");
        // Run 2: member 0 is SKIPPED; members 1 and 2 apply.
        *bus.connector().resolve_fail_after.borrow_mut() = None;
        let run2 = drive_plan(&mut bus, &id, None).expect("run 2 answers its outcome");
        assert_eq!(run2.skipped, vec![refs[0].clone()]);
        assert_eq!(run2.completion, Some(aruna::episode::Completion::Completed));
        assert_eq!(project_and_mark(&mut bus, &session, &run2.members), ProjectionState::Current);
        assert_eq!(
            inbox_refs(&session),
            vec![refs[0].clone()],
            "run 2 projected members 1 and 2 only; member 0's row keeps the refresh's newer observation"
        );
        drop(bus);
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// Reproduction:
    /// a partial run applies member 0, a newer Inbox refresh observes another client
    /// restoring it, and the retry FAILS AT PREFLIGHT — it reaches no member, so `skipped` is empty
    /// while `members` still reports member 0 `Applied` from the earlier run. The retry sent nothing,
    /// so it projects nothing: member 0's row keeps the refresh's newer observation.
    #[test]
    fn a_retry_that_fails_at_preflight_projects_nothing_an_earlier_run_applied() {
        let (path, _state, session) = session_for("cli-r2-r2-2");
        let rows: Vec<HeaderSummary> = (0..2)
            .map(|i| page_row(&format!("D{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        let absorb = |rows: &[HeaderSummary]| {
            session
                .lock()
                .expect("session lock")
                .absorb_page("acct", rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
                .expect("absorb");
        };
        absorb(&rows);
        let mut refs = inbox_refs(&session);
        refs.sort();
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let root = aruna::key_custody::root_key_verified(&aruna::key_custody::InMemoryCustody::new(), &mut log)
            .unwrap();
        log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        let mut bus = CommandBus::new(log, R1LabelConnector::default())
            .with_grant_ratchet(Box::new(aruna::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
            .with_root_key(root);
        // Run 1: member 0 applies; member 1 stops resolving at its dispatch, so the run stops.
        *bus.connector().resolve_fail_after.borrow_mut() = Some((refs[1].clone(), 1));
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let run1 = drive_plan(&mut bus, &id, None).expect("run 1 answers its outcome");
        assert_eq!(run1.members[0], (refs[0].clone(), MemberState::Applied));
        // `run1.applied_this_run` is DELETED — the equivalent
        // store-derived proof, read straight from the ONE source `plan_projection_writes` itself
        // reads from, BEFORE this run's own write below marks it `projected`.
        let unprojected_after_run1 = bus.log().applied_unprojected_forward_intents().expect("read unprojected");
        assert_eq!(
            unprojected_after_run1.iter().map(|i| s1_fold_message_ref(&i.command.action)).collect::<Vec<_>>(),
            vec![refs[0].clone()],
            "run 1 recorded exactly what it applied, as it applied it — the store's own list, not a run-window diff"
        );
        assert_eq!(project_and_mark(&mut bus, &session, &run1.members), ProjectionState::Current);
        assert!(!inbox_refs(&session).contains(&refs[0]), "run 1 projected member 0's trash");
        // A newer refresh observes the mailbox: another client restored member 0 to the Inbox.
        absorb(&rows);
        assert!(inbox_refs(&session).contains(&refs[0]), "the refresh wrote the newer observation");
        // Run 2 — the retry: every observation fails transiently, so the run stops AT PREFLIGHT.
        *bus.connector().resolve_fail_after.borrow_mut() = None;
        bus.connector().observe_fail.set(true);
        let run2 = drive_plan(&mut bus, &id, None).expect("run 2 answers its outcome");
        assert_eq!(run2.preflight, None, "the retry stopped before its preflight decided");
        assert!(run2.stopped.is_some(), "and says why it stopped");
        assert!(run2.skipped.is_empty(), "it reached no member, so it skipped none");
        assert_eq!(run2.members[0], (refs[0].clone(), MemberState::Applied), "member 0 is Applied — by run 1");
        // Before the fix: member 0 was already marked `projected` by
        // run 1's OWN `project_and_mark` above — with the run-window derivation deleted, the ONLY
        // thing left that could wrongly re-name it is the store itself, and it does not: the list
        // is empty, exactly like the deleted `applied_this_run` was for this stopped-at-preflight
        // retry, but now proven from the ONE mechanism instead of two agreeing by construction.
        assert!(
            bus.log().applied_unprojected_forward_intents().expect("read unprojected").is_empty(),
            "the retry applied nothing new, and run 1's own member is already marked projected"
        );
        project_and_mark(&mut bus, &session, &run2.members);
        assert!(
            inbox_refs(&session).contains(&refs[0]),
            "a retry that sent nothing projects nothing: member 0's row keeps the refresh's newer observation"
        );
        // Run 3: the observations answer again — member 1 applies IN THIS RUN and is projected;
        // member 0 is skipped, and its row still keeps the newer observation.
        bus.connector().observe_fail.set(false);
        let run3 = drive_plan(&mut bus, &id, None).expect("run 3 answers its outcome");
        assert_eq!(run3.skipped, vec![refs[0].clone()]);
        let unprojected_after_run3 = bus.log().applied_unprojected_forward_intents().expect("read unprojected");
        assert_eq!(
            unprojected_after_run3.iter().map(|i| s1_fold_message_ref(&i.command.action)).collect::<Vec<_>>(),
            vec![refs[1].clone()],
            "run 3 applied member 1 only — member 0 stays marked projected from run 1"
        );
        assert_eq!(project_and_mark(&mut bus, &session, &run3.members), ProjectionState::Current);
        assert_eq!(
            inbox_refs(&session),
            vec![refs[0].clone()],
            "member 1 (applied in run 3) projected; member 0 keeps the newer observation"
        );
        drop(bus);
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// Cross-plan projection: `plan_projection_writes`
    /// projects a member from a DIFFERENT plan (or an earlier run of ANY plan) that the store still
    /// holds `Applied` and unprojected — the exact cross-plan/cross-run gap a per-plan run-window
    /// diff cannot see by construction (it only ever reads THIS plan's own member states). Mimics
    /// b0 was already `Applied` by plan A's cross-plan `recover()` sweep BEFORE this
    /// run (of a DIFFERENT plan) even started, so THIS plan's own drive found nothing new — with
    /// the per-plan run-window mechanism now DELETED, `plan_members` below is named to
    /// the writer for the in-flight check ONLY; b0 reaches it EXCLUSIVELY through the store-derived
    /// `unprojected` list, proving that list is the sole and sufficient source, not a supplement
    /// beside a second mechanism that no longer exists.
    #[test]
    fn the_supplemental_sweep_projects_a_cross_plan_unprojected_member() {
        let (path, _state, session) = session_for("s1-fold-r4-p-wide");
        let rows: Vec<HeaderSummary> = (0..1)
            .map(|i| page_row(&format!("W{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page("acct", &rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
            .expect("absorb");
        let refs = inbox_refs(&session);
        let member_ref = refs[0].clone();

        // This plan's OWN members: nothing in flight, nothing new this run.
        let plan_members = vec![(member_ref.clone(), MemberState::Applied)];
        // The store-derived work list: a DIFFERENT plan's member, still Applied, never projected —
        // exactly what `applied_unprojected_forward_intents` answers after a cross-plan sweep.
        let unprojected = vec![applied_unprojected_intent(&path, "b0-key", &member_ref, Some(1))];

        assert!(inbox_refs(&session).contains(&member_ref), "precondition: the row still reads Inbox");
        let (projection, newly_projected) = {
            let mut s = session.lock().expect("session lock");
            plan_projection_writes(&mut s, &plan_members, unprojected)
        };
        assert_eq!(projection, ProjectionState::Current, "the store-derived sweep closed the ONLY gap");
        assert_eq!(newly_projected, vec!["b0-key".to_string()]);
        assert!(
            !inbox_refs(&session).contains(&member_ref),
            "the cross-plan member's row is now projected (Trashed) — B2's own bug in seat 1's probe, now proven by the sole writer"
        );
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// A scripted Gmail transport for the REAL `GmailConnector::new`: every read
    /// answers `{INBOX}`; every WRITE is counted and refused, so a zero count proves no write reached
    /// the transport.
    #[derive(Default)]
    struct R2CountingTransport {
        writes: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl R2CountingTransport {
        fn write(&self) -> aruna::gmail::GmailError {
            self.writes.set(self.writes.get() + 1);
            aruna::gmail::GmailError::Unknown
        }
    }

    impl GmailTransport for R2CountingTransport {
        fn modify_labels(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
            _request: &aruna::gmail::GmailModifyRequest,
        ) -> Result<(), aruna::gmail::GmailError> {
            Err(self.write())
        }
        fn modify_labels_observed(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
            _request: &aruna::gmail::GmailModifyRequest,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            Err(self.write())
        }
        fn trash_message(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            Err(self.write())
        }
        fn untrash_message(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            Err(self.write())
        }
        fn message_labels(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            Ok(["INBOX".to_string()].into_iter().collect())
        }
    }

    /// The shell's connector is `GmailConnector::new`, which publishes `m1_verbs()`, so every triage
    /// verb is refused at the connector — and that refusal crosses IPC as its OWN token,
    /// `unsupported_capability`, never the fence's sentence or a fallback. Untrash / UnmarkSpam
    /// through `run_verb`'s dispatch; Trash / MarkSpam through the plan doors at apply. THE ORDER, as
    /// it is: the send fence first (under `backups: on` a RED child refuses `snapshot_absent` and
    /// never reaches the connector), then the connector's capability map, then the transport's write
    /// gate — which nothing reaches (zero writes).
    #[test]
    fn a_real_gmail_connector_new_answers_every_triage_verb_unsupported_capability_by_name() {
        let writes = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let transport = R2CountingTransport { writes: std::rc::Rc::clone(&writes) };
        let (path, mut bus, refs) = plan_bus("council-r2-r2-1", 5, |path| {
            GmailConnector::new(
                transport,
                FixedGmailAccount(GmailUserId("me@e".to_string())),
                StoreMessageRefs(SqliteMessageStore::open(path).expect("the ref resolver opens")),
            )
        });
        let expected = serde_json::json!({ "kind": "unsupported_capability" });
        // YELLOW — run_verb's dispatch (`verb_on_bus`), under the production arm's fence sentence.
        for (key, action) in [
            ("k-r2-1-untrash", Action::Untrash { message_ref: refs[0].clone() }),
            ("k-r2-1-unmark-spam", Action::UnmarkSpam { message_ref: refs[1].clone() }),
        ] {
            let command = Command::new(key.to_string(), "acct".to_string(), Facet::Mail, action);
            let refusal = verb_on_bus(&mut bus, &command, Some(MUTATIONS_FENCED_REASON)).expect_err("m1_verbs() refuses the verb");
            assert_eq!(serde_json::to_value(&refusal).unwrap(), expected, "{key}");
        }
        // RED — the plan doors at apply (`backups: off`, so the child passes the send fence and
        // meets the connector): the run ends BY THAT NAME at its first member, the rest untouched.
        for (verb, members) in [(PlanVerb::Trash, &refs[0..2]), (PlanVerb::MarkSpam, &refs[2..4])] {
            let id = approved_plan(&mut bus, members, verb);
            let drive = drive_plan(&mut bus, &id, Some(MUTATIONS_FENCED_REASON)).expect("the run answers its outcome");
            // `drive.applied_this_run` is deleted; the store
            // itself is the equivalent witness that nothing forward landed `Applied`.
            assert!(
                bus.log().applied_unprojected_forward_intents().expect("read unprojected").is_empty(),
                "{verb:?}: nothing applied"
            );
            let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current)).unwrap();
            assert_eq!(wire["stopped"], expected, "{verb:?}: {wire}");
            assert_eq!(wire["members"][1][1], serde_json::json!({ "state": "not_minted" }), "{verb:?}: the second member is never attempted");
        }
        assert_eq!(writes.get(), 0, "no write reached the transport — the capability map answered first");
        // THE ORDER, as it is: under `backups: on` a RED child is refused by the SEND FENCE
        // (`snapshot_absent`) before the connector is reached — the capability map never answers.
        bus.log_mut().record_knob_act(KnobAct::Backups(BackupsKnob::On)).unwrap();
        let id = approved_plan(&mut bus, &refs[4..5], PlanVerb::Trash);
        let drive = drive_plan(&mut bus, &id, Some(MUTATIONS_FENCED_REASON)).expect("the run answers its outcome");
        let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current)).unwrap();
        assert_eq!(wire["stopped"], serde_json::Value::Null, "{wire}");
        assert_eq!(
            wire["members"],
            serde_json::json!([[refs[4], { "state": "refused", "reason": "snapshot_absent", "diff": [] }]]),
            "the send fence answers first"
        );
        assert_eq!(writes.get(), 0);
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// The PLAN door: a member whose witness write fails after its
    /// settlement is applied — the run goes on to its neighbours, its undo offer names the
    /// unrecorded witness, and the projection writes it.
    #[test]
    fn a_plan_members_witness_write_failure_keeps_its_undo_offer_names_it_and_projects_it() {
        let (path, _state, session) = session_for("cli-r2-r2-3-plan");
        let rows: Vec<HeaderSummary> = (0..2)
            .map(|i| page_row(&format!("W{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page("acct", &rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
            .expect("absorb");
        let mut refs = inbox_refs(&session);
        refs.sort();
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let root = aruna::key_custody::root_key_verified(&aruna::key_custody::InMemoryCustody::new(), &mut log)
            .unwrap();
        log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        let mut bus = CommandBus::new(log, R1LabelConnector::default())
            .with_grant_ratchet(Box::new(aruna::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
            .with_root_key(root);
        bus.connector().witness.set(true);
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(R2_3_WITNESS_WRITE_FAILPOINT)
            .expect("arm the failpoint");
        let drive = drive_plan(&mut bus, &id, None).expect("the run answers its outcome");
        assert_eq!(drive.stopped, None, "a witness write that failed after settlement is not a run-ending error");
        // `drive.applied_this_run` is deleted; the store's own
        // unprojected list is the equivalent, single-source proof that both members landed.
        let mut unprojected_refs: Vec<String> = bus
            .log()
            .applied_unprojected_forward_intents()
            .expect("read unprojected")
            .iter()
            .map(|i| s1_fold_message_ref(&i.command.action))
            .collect();
        unprojected_refs.sort();
        assert_eq!(unprojected_refs, refs, "both members applied in this run");
        assert!(drive.undo_keys.iter().all(|k| k.restoration == Some(RestorationView::WitnessWriteFailed)), "{:?}", drive.undo_keys);
        assert_eq!(drive.undo_keys.len(), 2, "each applied member keeps its undo offer");
        assert_eq!(
            project_and_mark(&mut bus, &session, &drive.members),
            ProjectionState::Current
        );
        assert!(inbox_refs(&session).is_empty(), "the projection wrote both applied members");
        drop(bus);
        drop(session);
        std::fs::remove_file(&path).ok();
    }

    /// A scripted Gmail transport under the REAL `GmailConnector` (its own classification of a
    /// provider answer, `aruna::gmail::classify_gmail_error`): every message reads `{INBOX}` until
    /// trashed; while `expired` is set, every read and write answers HTTP 401
    /// (`GmailError::Unauthorized`) — an access token that aged out.
    #[derive(Default)]
    struct R1GmailTransport {
        expired: std::rc::Rc<std::cell::Cell<bool>>,
        trashed: std::cell::RefCell<BTreeSet<String>>,
        /// When set, `expired` flips true itself the instant ONE
        /// `trash_message` succeeds — the credential aging out BETWEEN two members' dispatch,
        /// never at preflight (this struct's OTHER tests already cover that, flipping `expired`
        /// from outside before the run starts). Default `false`: every existing test using this
        /// fixture is unaffected.
        auto_expire_after_first_trash: bool,
    }

    impl GmailTransport for R1GmailTransport {
        fn modify_labels(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
            _request: &aruna::gmail::GmailModifyRequest,
        ) -> Result<(), aruna::gmail::GmailError> {
            Err(aruna::gmail::GmailError::Unknown)
        }
        fn modify_labels_observed(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
            _request: &aruna::gmail::GmailModifyRequest,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            Err(aruna::gmail::GmailError::Unknown)
        }
        fn trash_message(
            &self,
            _user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            if self.expired.get() {
                return Err(aruna::gmail::GmailError::Unauthorized);
            }
            self.trashed.borrow_mut().insert(message.0.clone());
            if self.auto_expire_after_first_trash {
                self.expired.set(true);
            }
            Ok(["TRASH".to_string()].into_iter().collect())
        }
        fn untrash_message(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            Err(aruna::gmail::GmailError::Unknown)
        }
        fn message_labels(
            &self,
            _user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, aruna::gmail::GmailError> {
            if self.expired.get() {
                return Err(aruna::gmail::GmailError::Unauthorized);
            }
            let label = if self.trashed.borrow().contains(&message.0) { "TRASH" } else { "INBOX" };
            Ok([label.to_string()].into_iter().collect())
        }
    }

    /// An EXPIRED access token at the preflight is an auth
    /// failure, not "every member diverged". Through the real Gmail connector's classification:
    /// the preflight writes nothing and leaves the episode ACTIVE, the run answers a NAMED auth
    /// stop, and once the credential is fine the same approved plan runs.
    #[test]
    fn an_expired_access_token_at_preflight_invalidates_nothing_and_the_plan_runs_once_the_credential_is_fine() {
        let expired = std::rc::Rc::new(std::cell::Cell::new(false));
        let transport = R1GmailTransport { expired: std::rc::Rc::clone(&expired), ..Default::default() };
        let (path, mut bus, refs) = plan_bus("e-r1-f3-drive", 2, |path| {
            GmailConnector::with_capabilities(
                transport,
                FixedGmailAccount(GmailUserId("me@e".to_string())),
                StoreMessageRefs(SqliteMessageStore::open(path).expect("the ref resolver opens")),
                aruna::gmail::CapabilityMap::triage_verbs(),
            )
        });
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        expired.set(true);
        let drive = drive_plan(&mut bus, &id, None).expect("the run answers its outcome");
        let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current)).unwrap();
        assert_eq!(
            wire["preflight"],
            serde_json::Value::Null,
            "an auth failure is not a preflight verdict — no member 'changed since approval': {wire}"
        );
        // CHANGED expectation — the OLD rule let a
        // credential-rejected connector error bubble through `execute_fenced`/`execute` with
        // neither function's mapping consulting `credential_rejected` at all, so it surfaced as a
        // generic `Refused` carrying the connector's own message. `run_ending_connector_disposition`
        // (consulted from `SurfaceError::execute`, which `execute_fenced` falls through to) now
        // answers this by its own typed kind here too, same as a dispatch-time rejection already
        // did — no `reason` field: the operator sentence is fixed, rendered by kind, never the
        // connector's own message.
        assert_eq!(wire["stopped"]["kind"], "credential_rejected", "{wire}");
        assert_eq!(wire["stopped"].as_object().unwrap().len(), 1, "no reason field rides along: {wire}");
        assert_eq!(
            bus.log().episode_status_check(&id).unwrap(),
            Some(aruna::episode::EpisodeStatusToken::Active),
            "nothing invalidated the plan"
        );
        assert_eq!(
            wire["members"],
            serde_json::json!([[refs[0], { "state": "not_minted" }], [refs[1], { "state": "not_minted" }]])
        );
        // The credential is fine again: the SAME approved plan runs.
        expired.set(false);
        let again = drive_plan(&mut bus, &id, None).expect("the plan re-applies");
        let wire = serde_json::to_value(plan_apply_outcome(&id, again, ProjectionState::Current)).unwrap();
        assert_eq!(wire["preflight"], serde_json::json!({ "outcome": "ready" }));
        assert_eq!(
            wire["members"],
            serde_json::json!([[refs[0], { "state": "applied" }], [refs[1], { "state": "applied" }]])
        );
        assert_eq!(wire["completion"], "completed");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// The SAME wall as `e_r1_f3_an_expired_access_token_at_preflight_…`
    /// above, but MID-RUN — preflight's own reads succeed (the credential is still good then),
    /// and the wall is hit only once member 1's `trash_message` succeeds and ages the token out
    /// from under member 2. Through the REAL `GmailConnector`'s own classification
    /// (`aruna::gmail::classify_gmail_error` + `provider_rejection`'s `GmailError::Unauthorized`
    /// ⇒ `credential_rejected()` tagging, unit-witnessed by
    /// `the_auth_family_alone_is_tagged_credential_rejected_and_named` in `crates/aruna/src/gmail.rs`)
    /// Never the hand-rolled `S1CredentialRejectedConnector` fixture the test above uses —
    /// this is the SAME stop reaching the shell from the ACTUAL connector's wire-error mapping,
    /// end to end, over THREE members so the shape is unambiguous: member 1 lands `applied`,
    /// member 2 (whose dispatch hit the 401, and so dead-lettered `Failed` before the run-ending
    /// `Err` propagated — `reconcile_connector_failure` records BEFORE surfacing the connector
    /// error, same as every other deterministic dispatch failure) is terminal, member 3 stays
    /// `not_minted` (never even attempted — still retryable), and the run's `stopped` is the
    /// TYPED `CredentialRejected` kind, carrying nothing of the connector's own message onto the
    /// wire.
    #[test]
    fn a_credential_rejected_mid_run_through_the_real_gmail_connector_is_the_typed_kind() {
        use aruna::plan::MemberState;
        let expired = std::rc::Rc::new(std::cell::Cell::new(false));
        let transport = R1GmailTransport {
            expired: std::rc::Rc::clone(&expired),
            auto_expire_after_first_trash: true,
            ..Default::default()
        };
        let (path, mut bus, refs) = plan_bus("s1-fold-r3-b2-real-connector", 3, |path| {
            GmailConnector::with_capabilities(
                transport,
                FixedGmailAccount(GmailUserId("me@e".to_string())),
                StoreMessageRefs(SqliteMessageStore::open(path).expect("the ref resolver opens")),
                aruna::gmail::CapabilityMap::triage_verbs(),
            )
        });
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let drive = drive_plan(&mut bus, &id, None).expect("the run answers its outcome, not a bare error");
        assert_eq!(
            drive.stopped,
            Some(SurfaceError::CredentialRejected),
            "the real connector's 401 reaches the shell as the typed kind, never a Refused string"
        );
        assert_eq!(drive.members[0], (refs[0].clone(), MemberState::Applied), "member 1 landed before the token aged out");
        assert_eq!(
            drive.members[1],
            (refs[1].clone(), MemberState::Terminal(aruna::IntentStatus::Failed)),
            "member 2's own dispatch hit the 401 and dead-lettered — recorded, not silently dropped"
        );
        assert_eq!(drive.members[2], (refs[2].clone(), MemberState::NotMinted), "member 3 was NEVER attempted — still retryable");
        assert!(expired.get(), "the fixture's own flip actually fired");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// `plan_apply` ADMITS the credential (reconcile + renew, [`admit_provider`]) before it
    /// touches the plan — as the read doors do. An expired credential that cannot be renewed
    /// (hermetic: this temp secrets dir has no `client_secret.json`, so the renewal fails locally,
    /// before any wire) answers the NAMED auth refusal, and the plan is never reached: the door
    /// does not even find out that this plan was never approved.
    #[test]
    fn plan_apply_admits_the_credential_before_it_touches_the_plan() {
        let (dir, state) = gmail_arm_state_expiring("e-r1-f3-door", 42);
        let session = state.session().expect("the store opens");
        let rows: Vec<HeaderSummary> = (0..2)
            .map(|i| page_row(&format!("Q{i:03}"), 1_758_672_000_000 + i as i64 * 1_000))
            .collect();
        session
            .lock()
            .expect("session lock")
            .absorb_page("acct", &rows, None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
            .expect("absorb");
        let refs = inbox_refs(&session);
        let review = tauri::async_runtime::block_on(plan_mint_door(&state, "acct".into(), "trash".into(), refs, None))
            .expect("minting reads and writes the store only");
        match tauri::async_runtime::block_on(plan_apply_door(&state, review.plan_id.clone())) {
            Err(SurfaceError::CredentialExpired { expires_at, cure, .. }) => {
                assert_eq!(expires_at, 42);
                assert_eq!(cure, Cure::ClientConfig, "the renewal failed locally on the client config");
            }
            other => panic!("plan_apply must admit the credential before it touches the plan: {other:?}"),
        }
        assert_eq!(s1_count(&dir, "execution_episode"), 0, "no episode was started");
        assert_eq!(s1_count(&dir, "intents"), 0, "nothing was dispatched");
        drop(session);
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// EVERY `EpisodeRefusal` variant, its own row.
    #[test]
    fn every_episode_refusal_projects_by_its_own_name() {
        use aruna::episode::{EpisodeRefusal as E, EpisodeStatusToken as T};
        let child = |token: &str| SurfaceError::PlanChildRefused { reason: token.to_string() };
        let conflict = E::GenerationConflict { expected: 1, found: 2 };
        let illegal = E::IllegalTransition { from: T::Completed, to: T::Active };
        let table: Vec<(E, SurfaceError)> = vec![
            (E::NoPlan, child("no_plan")),
            (E::NotApproved, child("not_approved")),
            (E::EpochMismatch { plan: 1, current: 2 }, child("epoch_mismatch")),
            (E::Expired { expires_at: "a".into(), effective_now: "b".into() }, child("expired")),
            (E::Terminal(T::Completed), child("episode_closed")),
            (E::NotActive(T::Paused), child("episode_held")),
            (E::NoEpisode, child("no_episode")),
            (E::DispatchBegan { send_authorized_children: 1 }, child("dispatch_began")),
            (E::Store("s".into()), SurfaceError::Store { reason: "s".into() }),
            (E::Malformed("m".into()), SurfaceError::Store { reason: "m".into() }),
            (illegal.clone(), SurfaceError::Internal { reason: illegal.to_string() }),
            (conflict.clone(), SurfaceError::Internal { reason: conflict.to_string() }),
        ];
        // One row per variant: a variant added to the engine's enum is a compile error here.
        let row = |e: &E| match e {
            E::NoPlan => 0,
            E::NotApproved => 1,
            E::EpochMismatch { .. } => 2,
            E::Expired { .. } => 3,
            E::Terminal(_) => 4,
            E::NotActive(_) => 5,
            E::NoEpisode => 6,
            E::DispatchBegan { .. } => 7,
            E::Store(_) => 8,
            E::Malformed(_) => 9,
            E::IllegalTransition { .. } => 10,
            E::GenerationConflict { .. } => 11,
        };
        for (i, (refusal, expected)) in table.into_iter().enumerate() {
            assert_eq!(row(&refusal), i, "the table is in variant order");
            assert_eq!(episode_refusal(refusal.clone()), expected, "{refusal:?}");
        }
    }

    /// EVERY `PlanStoreError` variant, and every
    /// `PlanRefusal` a store refusal can carry, its own row — the evidence group is
    /// `evidence_invalid`, the bypass generation its OWN token.
    #[test]
    fn every_plan_store_error_projects_by_its_own_name() {
        use aruna::plan::{
            AdmissionLane, Comprehension, HeaderField, PlanRefusal as R, PlanShapeRule, PlanStoreError as E,
            WarningShapeRule,
        };
        let child = |token: &str| SurfaceError::PlanChildRefused { reason: token.to_string() };
        let whole = |token: &str| SurfaceError::PlanRefused { reason: token.to_string(), member_ref: None, diff: vec![] };
        let refusals: Vec<(R, SurfaceError)> = vec![
            (R::EmptyMembers, child("empty_members")),
            (R::ConflictingDuplicate("m".into()), child("conflicting_duplicate")),
            (R::HeaderCountMismatch { header: 1, members: 2 }, child("header_count_mismatch")),
            (R::WarningShape(WarningShapeRule::ALL[0]), child("warning_shape")),
            (R::HeaderDiverges(HeaderField::Account), child("header_diverges")),
            (R::PresentationRowCount { rows: 1, members: 2 }, child("presentation_row_count")),
            (R::PresentationRowDiverges("m".into()), child("presentation_row_diverges")),
            (R::ConfiguredKZero, child("configured_k_zero")),
            (R::Commitment(aruna::commitment::CommitmentError::TagHex), child("commitment")),
            (R::LaneMismatch { plan: AdmissionLane::PerMember, evidence: Comprehension::PerMember }, whole("evidence_invalid")),
            (R::PlanIdMismatch { plan: PlanId("a".into()), evidence: PlanId("b".into()) }, whole("evidence_invalid")),
            (R::ApproverMissing, whole("evidence_invalid")),
            (R::ViewMismatch, whole("evidence_invalid")),
            (R::SampleMismatch("m".into()), whole("evidence_invalid")),
            (R::SampleKMismatch { plan: 1, evidence: 2 }, whole("evidence_invalid")),
            (R::BypassGenerationMismatch { plan: 1, current: 2 }, whole("bypass_generation_mismatch")),
            (R::UnknownVerb("v".into()), child("unknown_verb")),
            (R::PlanShape(PlanShapeRule::ALL[0]), child("plan_shape")),
        ];
        let refusal_row = |r: &R| match r {
            R::EmptyMembers => 0,
            R::ConflictingDuplicate(_) => 1,
            R::HeaderCountMismatch { .. } => 2,
            R::WarningShape(_) => 3,
            R::HeaderDiverges(_) => 4,
            R::PresentationRowCount { .. } => 5,
            R::PresentationRowDiverges(_) => 6,
            R::ConfiguredKZero => 7,
            R::Commitment(_) => 8,
            R::LaneMismatch { .. } => 9,
            R::PlanIdMismatch { .. } => 10,
            R::ApproverMissing => 11,
            R::ViewMismatch => 12,
            R::SampleMismatch(_) => 13,
            R::SampleKMismatch { .. } => 14,
            R::BypassGenerationMismatch { .. } => 15,
            R::UnknownVerb(_) => 16,
            R::PlanShape(_) => 17,
        };
        for (i, (refusal, expected)) in refusals.into_iter().enumerate() {
            assert_eq!(refusal_row(&refusal), i, "the table is in variant order");
            assert_eq!(plan_store_error(E::Refused(refusal.clone())), expected, "{refusal:?}");
        }
        let ttl_zero = E::TtlZero.to_string();
        let ttl_range = E::TtlOutOfRange.to_string();
        let knob = E::Knob("k".into()).to_string();
        let store_errors: Vec<(E, SurfaceError)> = vec![
            (E::UnknownMember("m".into()), child("unknown_member")),
            (E::PlanNotFound(PlanId("p".into())), child("no_plan")),
            (E::AlreadyApproved, child("already_approved")),
            (E::Knob("k".into()), SurfaceError::Store { reason: knob }),
            (E::TtlZero, SurfaceError::Refused { reason: ttl_zero, terminal: true }),
            (E::TtlOutOfRange, SurfaceError::Refused { reason: ttl_range, terminal: true }),
            (E::EpochMismatch { plan: 1, current: 2 }, child("epoch_mismatch")),
            (E::Expired { expires_at: "a".into(), effective_now: "b".into() }, child("expired")),
            (E::Store("s".into()), SurfaceError::Store { reason: "s".into() }),
        ];
        let store_row = |e: &E| match e {
            E::Refused(_) => usize::MAX,
            E::UnknownMember(_) => 0,
            E::PlanNotFound(_) => 1,
            E::AlreadyApproved => 2,
            E::Knob(_) => 3,
            E::TtlZero => 4,
            E::TtlOutOfRange => 5,
            E::EpochMismatch { .. } => 6,
            E::Expired { .. } => 7,
            E::Store(_) => 8,
        };
        for (i, (error, expected)) in store_errors.into_iter().enumerate() {
            assert_eq!(store_row(&error), i, "the table is in variant order");
            assert_eq!(plan_store_error(error.clone()), expected, "{error:?}");
        }
    }

    /// Every `PlanRefusal` has ITS token in the closed table — read directly, because the
    /// evidence group never reaches this map through `plan_store_error` (the approve door answers
    /// those `evidence_invalid`) and a row reached only by `derive_sample` or the verb parse would
    /// otherwise be unwitnessed.
    #[test]
    fn every_plan_refusal_has_its_own_token() {
        use aruna::plan::{AdmissionLane, Comprehension, HeaderField, PlanRefusal as R, PlanShapeRule, WarningShapeRule};
        let table: Vec<(R, &str)> = vec![
            (R::EmptyMembers, "empty_members"),
            (R::ConflictingDuplicate("m".into()), "conflicting_duplicate"),
            (R::HeaderCountMismatch { header: 1, members: 2 }, "header_count_mismatch"),
            (R::WarningShape(WarningShapeRule::ALL[0]), "warning_shape"),
            (R::HeaderDiverges(HeaderField::Account), "header_diverges"),
            (R::PresentationRowCount { rows: 1, members: 2 }, "presentation_row_count"),
            (R::PresentationRowDiverges("m".into()), "presentation_row_diverges"),
            (R::ConfiguredKZero, "configured_k_zero"),
            (R::Commitment(aruna::commitment::CommitmentError::TagHex), "commitment"),
            (R::LaneMismatch { plan: AdmissionLane::PerMember, evidence: Comprehension::PerMember }, "lane_mismatch"),
            (R::PlanIdMismatch { plan: PlanId("a".into()), evidence: PlanId("b".into()) }, "plan_id_mismatch"),
            (R::ApproverMissing, "approver_missing"),
            (R::ViewMismatch, "view_mismatch"),
            (R::SampleMismatch("m".into()), "sample_mismatch"),
            (R::SampleKMismatch { plan: 1, evidence: 2 }, "sample_k_mismatch"),
            (R::BypassGenerationMismatch { plan: 1, current: 2 }, "bypass_generation_mismatch"),
            (R::UnknownVerb("v".into()), "unknown_verb"),
            (R::PlanShape(PlanShapeRule::ALL[0]), "plan_shape"),
        ];
        let distinct: BTreeSet<&str> = table.iter().map(|(_, token)| *token).collect();
        assert_eq!(distinct.len(), table.len(), "one token per variant");
        for (refusal, token) in table {
            assert_eq!(plan_refusal_token(&refusal).as_token(), token, "{refusal:?}");
        }
    }

    /// The per-verb route-correct witness for the plan
    /// door's projection: a Trash plan's applied members are projected Trashed, a MarkSpam plan's
    /// SpamSet — never the other verb's delta. The
    /// door-local `plan_verb_delta(PlanVerb) -> VerbDelta` this test used to call directly is
    /// DELETED — dead code once `plan_projection_writes` started deriving every write's delta
    /// PER INTENT from its own stored `Action` (`verb_delta_for_action`), never from the plan's
    /// verb a second time. The SAME route-correctness property is proven end-to-end here through
    /// the path production code actually takes: a plan member's child command action comes from
    /// `PlanVerb::action` (`crates/aruna/src/plan.rs`), and the writer's delta comes from that
    /// action through `verb_delta_for_action` — chained, never the old shortcut.
    #[test]
    fn a_plan_projects_its_own_verbs_delta() {
        let table = [(PlanVerb::Trash, VerbDelta::Trashed), (PlanVerb::MarkSpam, VerbDelta::SpamSet(true))];
        assert_eq!(table.len(), PlanVerb::ALL.len(), "one row per plan verb");
        for (verb, delta) in table {
            let action = verb.action("m1");
            let (derived, message_ref) = aruna::read_coordinator::verb_delta_for_action(&action);
            assert_eq!(derived, delta, "{verb:?}");
            assert_eq!(message_ref, "m1");
        }
    }

    /// A bypass-lane plan whose bypass knob moved since mint is
    /// refused by ITS OWN token — the `bypass_generation_mismatch` copy row ("re-plan") is
    /// reachable — and nothing is recorded.
    #[test]
    fn a_bypass_knob_moved_since_mint_is_refused_by_its_own_token() {
        let (path, mut bus, refs) =
            s1_driver_bus("e-r1-f10", 1, aruna::CountingConnector::observing(&S1_IN_INBOX));
        bus.log_mut().record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
        let review = plan_mint_on(&mut bus, plan_spec(&refs, PlanVerb::Trash)).expect("mint");
        assert_eq!(review.lane, LaneView::Bypassed);
        let id = PlanId(review.plan_id);
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::Off)).unwrap();
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
        assert_eq!(
            approve_bypassed_on(&mut bus, &id),
            Err(SurfaceError::PlanRefused {
                reason: "bypass_generation_mismatch".into(),
                member_ref: None,
                diff: vec![]
            })
        );
        assert!(bus.log().approval(&id).unwrap().is_none(), "nothing recorded");
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// The WIRE approve door refuses a plan frozen
    /// on the bypass lane by name — that lane has no screen, and the mechanical path
    /// (`approve_bypassed_on`, inside `plan_apply`) is its only approver. Nothing is recorded,
    /// whatever view the renderer hands back.
    #[test]
    fn the_wire_approve_door_refuses_a_bypass_lane_plan_by_name() {
        let (path, mut bus, refs) =
            s1_driver_bus("e-r1-f11", 2, aruna::CountingConnector::observing(&S1_IN_INBOX));
        bus.log_mut().record_knob_act(KnobAct::RedBypass(RedBypassKnob::On)).unwrap();
        let review = plan_mint_on(&mut bus, plan_spec(&refs, PlanVerb::Trash)).expect("mint");
        assert_eq!(review.lane, LaneView::Bypassed);
        let id = PlanId(review.plan_id.clone());
        let mut junk = review.presentation.clone();
        junk.rows[0].subject = "never rendered".into();
        junk.rows.reverse();
        for view in [junk, review.presentation.clone()] {
            assert_eq!(
                plan_approve_on(&mut bus, &id, RenderedViewWire::FullList { presentation: view }, "operator"),
                Err(SurfaceError::PlanChildRefused { reason: "bypass_lane_no_screen".into() })
            );
        }
        assert!(bus.log().approval(&id).unwrap().is_none(), "nothing recorded");
        // The mechanical path still approves it.
        assert!(approve_bypassed_on(&mut bus, &id).expect("answers").is_some());
        drop(bus);
        std::fs::remove_file(&path).ok();
    }

    /// A connector that, on its FIRST apply, renames the store's `triage_plan` table from a
    /// second connection — a PERSISTENT store failure every later plan read meets
    /// (`settle_plan_progress` and `plan_member_states` both read the plan row), while the
    /// member's own settlement (an `intents` write) still lands. The provider effect has happened
    /// by the time the failure exists — exactly the order that matters here.
    struct R6StoreBreaksOnApplyConnector {
        path: PathBuf,
        broke: std::cell::Cell<bool>,
    }
    impl Connector for R6StoreBreaksOnApplyConnector {
        fn apply(&self, _command: &Command, _basis: &aruna::prestate::FrozenBasis) -> Result<(), aruna::ConnectorError> {
            if !self.broke.replace(true) {
                let conn = rusqlite::Connection::open(&self.path).expect("a second connection to the store");
                conn.busy_timeout(std::time::Duration::from_secs(5)).expect("busy timeout");
                conn.execute_batch("ALTER TABLE triage_plan RENAME TO triage_plan_unreadable;")
                    .expect("break the plan table after the effect");
            }
            Ok(())
        }
        fn resolve_basis(&self, command: &Command) -> Result<aruna::prestate::FrozenBasis, aruna::ResolveBasisError> {
            Ok(aruna::test_support::fixture_basis(command))
        }
        fn observe(
            &self,
            _command: &Command,
            basis: &aruna::prestate::FrozenBasis,
        ) -> Result<aruna::prestate::Observation, aruna::ConnectorError> {
            Ok(aruna::test_support::fixture_observation_with(basis, &[("label:TRASH", false), ("membership:INBOX", true)]))
        }
        fn restore(
            &self,
            _command: &Command,
            _basis: &aruna::prestate::FrozenBasis,
            _p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), aruna::ConnectorError> {
            Ok(())
        }
    }

    // ===========================================================================================
    // After a provider effect, a bookkeeping failure is a labelled
    // field of the outcome, never a replacement of it
    // ===========================================================================================

    /// The member APPLIED at the provider, then the store stopped answering the plan
    /// reads. `drive_plan`'s two post-run reads (`settle_plan_progress`, `plan_member_states`)
    /// used to `map_err(bare)?` — throwing away the applied member, its undo offer and the whole
    /// report. The outcome is kept: the members' LAST KNOWN states (the applied one `applied`),
    /// its undo offer, the store failure as the stop, and a completion the run could not read
    /// (`undetermined`), never a guessed one.
    #[test]
    fn a_store_failure_in_the_post_run_reads_keeps_the_drive_outcome() {
        let (path, mut bus, refs) = plan_bus("r6-e3-post-run-reads", 1, |p| R6StoreBreaksOnApplyConnector {
            path: p.to_path_buf(),
            broke: std::cell::Cell::new(false),
        });
        let id = approved_plan(&mut bus, &refs, PlanVerb::Trash);
        let drive = drive_plan(&mut bus, &id, None)
            .expect("the member applied at the provider: the run answers its outcome, never a bare store error");
        let wire = serde_json::to_value(plan_apply_outcome(&id, drive, ProjectionState::Current)).unwrap();
        assert_eq!(wire["members"], serde_json::json!([[refs[0], { "state": "applied" }]]), "{wire}");
        assert_eq!(wire["undo_keys"].as_array().map(Vec::len), Some(1), "the applied member keeps its undo offer: {wire}");
        assert_eq!(wire["stopped"]["kind"], "store", "the store failure is the stop: {wire}");
        assert_eq!(wire["completion"], "undetermined", "a completion the run could not read is never guessed: {wire}");
        drop(bus);
        drop(path);
    }
}
