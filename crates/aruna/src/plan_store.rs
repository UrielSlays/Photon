//! The plan store half both stores share, and the execution episode's durable transaction bodies.

use rusqlite::OptionalExtension;

use crate::adjudication::mint_opaque_id;
use crate::command::plan_child_key;
use crate::intent::status_from_str;
use crate::{Action, CaptureBinding, Command, LogError};

// ---------------------------------------------------------------------------------------
// Plan store: the parts both stores share. Each store gathers its own facts and hands them to
// one assembler and one evidence builder, so the in-memory twin refuses what SQLite refuses.
// ---------------------------------------------------------------------------------------

/// One member's facts as a store reads them: the `message_header` row's display fields and the
/// `message_placement` row's placement, both on `(account, message_ref)`. A member missing
/// either row is unknown to the store ([`crate::plan::PlanStoreError::UnknownMember`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanMemberFacts {
    pub(crate) message_ref: String,
    pub(crate) from_addr: String,
    /// The header row's `from_status` / `from_domain`: the RFC 5322 §3.4 parse the row's write
    /// path derived from `from_addr` (`mailbox::sender_facts`).
    pub(crate) from_status: crate::mailbox::SenderStatus,
    pub(crate) from_domain: Option<String>,
    /// The header row's `from_name` / `subject` as stored — on the ingest path, the text the
    /// chokepoint (`read_coordinator` → `header_normalize::normalize_display`) wrote.
    pub(crate) from_name: String,
    pub(crate) subject: String,
    /// `message_header.received_at` — epoch MILLISECONDS on both providers (`src/state.ts:34`:
    /// Gmail `internalDate`, JMAP `receivedAt` mapped to ms in `aruna-jmap`'s transport).
    pub(crate) received_at_ms: i64,
    pub(crate) placement: crate::read_model::Placement,
}

/// The closure atom a local placement asserts true, read off the atom table
/// (`gmail::gmail_atom_targets`): Inbox asserts the atom `Unarchive` drives true, Trash the
/// atom `Trash` drives true, Spam the atom `MarkSpam` drives true; an Archived message
/// asserts none of them.
fn placement_asserted_atom(placement: crate::read_model::Placement) -> Option<String> {
    use crate::read_model::Placement;
    let driven_true = |action: Action| {
        crate::gmail::gmail_atom_targets(&action)
            .into_iter()
            .find(|(_, target)| *target)
            .map(|(atom, _)| atom)
    };
    match placement {
        Placement::Inbox => driven_true(Action::Unarchive { message_ref: String::new() }),
        Placement::Trash => driven_true(Action::Trash { message_ref: String::new() }),
        Placement::Spam => driven_true(Action::MarkSpam { message_ref: String::new() }),
        Placement::Archive => None,
    }
}

/// Freeze one member from the store's own facts. The display comes from the header row:
/// `sender` (the name half, or empty) and `sender_address` (`<addr>` beside a name, else the
/// bare address) stay separate fields and each goes through
/// `header_normalize::normalize_display`. The date is the RFC 3339 UTC second of
/// `received_at`; size is unavailable. The observed closure state is the local placement
/// belief at mint (`CommandBus::preflight_plan` re-observes against it, and
/// `IntentLog::authorize_send`'s plan arm compares each child's capture with it), and the
/// forward target is the verb's atom closure.
///
/// Both display fields are copies; the member's identity is its `message_ref`. The address
/// half is normalized too because `from_addr` is stored raw, and a remote sender's Cf/bidi
/// codepoints would otherwise reach the approval rows and the summary's sender domains.
///
/// The member also freezes its structured sender, the header row's RFC 5322 §3.4 parse
/// (`from_status`, and `from_addr` / `from_domain` when it is `ok`). The summary's sender
/// domains come from that, never from the display text. The parsed addr-spec and domain are
/// not re-normalized: the parser admits no codepoint that normalization would strip (see
/// `mailbox`, "What an address may contain"), so an address that could render as another is
/// `malformed`, never a merged domain.
fn frozen_plan_member(
    verb: crate::plan::PlanVerb,
    facts: PlanMemberFacts,
) -> Result<crate::plan::PlanMember, crate::plan::PlanStoreError> {
    let forward_target = crate::gmail::gmail_atom_targets(&verb.action(&facts.message_ref));
    let asserted = placement_asserted_atom(facts.placement);
    let observed_state = forward_target
        .keys()
        .map(|atom| (atom.clone(), asserted.as_deref() == Some(atom.as_str())))
        .collect();
    let secs = u64::try_from(facts.received_at_ms.div_euclid(1000)).map_err(|_| {
        crate::plan::PlanStoreError::Store(format!(
            "member '{}': received_at {} ms is before the epoch",
            facts.message_ref, facts.received_at_ms
        ))
    })?;
    // `sender` and `sender_address` are frozen separately so the render side can isolate them
    // into two `<bdi>`s. Together they carry the same visible text as the earlier composed
    // `{name} <{addr}>` form (bare address when there is no name).
    let sender = crate::header_normalize::normalize_display(&facts.from_name);
    let sender_address_source = if facts.from_name.is_empty() {
        facts.from_addr.clone()
    } else {
        format!("<{}>", facts.from_addr)
    };
    let sender_address = crate::header_normalize::normalize_display(&sender_address_source);
    let parsed_addr = (facts.from_status == crate::mailbox::SenderStatus::Ok).then(|| facts.from_addr.clone());
    // The local part comes from re-parsing the stored `from_addr` (see `ParsedMailbox::local_part`),
    // never from splitting it on `@`.
    let parsed_local = (facts.from_status == crate::mailbox::SenderStatus::Ok)
        .then(|| crate::mailbox::parse_mailbox(&facts.from_addr).local_part);
    let sender_parse = crate::plan::FrozenSender::from_columns(facts.from_status, parsed_local, parsed_addr, facts.from_domain.clone())
        .ok_or_else(|| {
            crate::plan::PlanStoreError::Store(format!(
                "member '{}': the header row's sender status '{}' disagrees with its domain",
                facts.message_ref,
                facts.from_status.as_token()
            ))
        })?;
    Ok(crate::plan::PlanMember {
        message_ref: facts.message_ref,
        display: crate::plan::FrozenDisplay {
            sender,
            sender_address,
            sender_parse,
            subject: facts.subject,
            date: crate::prestate::rfc3339_utc(secs),
            size: None,
        },
        observed_state,
        forward_target,
    })
}

/// The spec refusals that need no store at all, checked by both stores before any read.
pub(crate) fn plan_spec_preflight(spec: &crate::plan::PlanSpec) -> Result<(), crate::plan::PlanStoreError> {
    if spec.ttl_seconds == 0 {
        return Err(crate::plan::PlanStoreError::TtlZero);
    }
    Ok(())
}

/// What a mint reads from its store inside its one transaction, besides the members.
pub(crate) struct PlanMintInputs {
    pub(crate) knobs: crate::config_knobs::KnobState,
    pub(crate) control_epoch: i64,
    /// The sticky clock's `effective_now`, already latched.
    pub(crate) minted_at: String,
}

/// The assembler both stores' `mint_plan` call: canonical members from the store's facts, the
/// account key and its key reference (`photon.account.<account>`, epoch 1), the header (tier
/// [`crate::plan::PLAN_TIER`]; coverage and the verb's warning from the backups knob), every
/// digest through `PlanDigests::mint`, the lane and mode the knobs freeze, the expiry, and
/// the plan's own shape check. A plan the core would refuse is never handed back to be stored.
pub(crate) fn assemble_plan(
    root_key: &crate::commitment::CommitmentKey,
    spec: crate::plan::PlanSpec,
    plan_id: crate::plan::PlanId,
    facts: Vec<PlanMemberFacts>,
    inputs: PlanMintInputs,
) -> Result<crate::plan::TriagePlan, crate::plan::PlanStoreError> {
    use crate::config_knobs::{ApprovalModeKnob, BackupsKnob};
    use crate::plan::{
        admission_lane_for, canonical_members, effective_k, ApprovalMode, PlanDigests, PlanStoreError,
        PresentationHeader, TriagePlan, PLAN_TIER,
    };
    let members = canonical_members(
        facts
            .into_iter()
            .map(|f| frozen_plan_member(spec.verb, f))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let count = u32::try_from(members.len())
        .map_err(|_| PlanStoreError::Store(format!("{} members exceed the header's u32 count", members.len())))?;
    let key_ref = crate::commitment::CommitmentKeyRef::new(&format!("photon.account.{}", spec.account), 1)?;
    let account_key = crate::commitment::derive_account_key(root_key, &spec.account)?;
    let backups_on = inputs.knobs.backups.value == BackupsKnob::On;
    let header = PresentationHeader {
        account: spec.account.clone(),
        verb: spec.verb,
        tier: PLAN_TIER.to_string(),
        count,
        backup_coverage: backups_on,
        warning: (!backups_on).then(|| spec.verb.uncovered_warning().to_string()),
    };
    let digests = PlanDigests::mint(&account_key, &key_ref, &spec.account, &spec.provider_principal, spec.verb, &members, &header)?;
    let admission_lane = admission_lane_for(inputs.knobs.approval_mode.value, inputs.knobs.red_bypass);
    let approval_mode = match inputs.knobs.approval_mode.value {
        ApprovalModeKnob::FullList => ApprovalMode::FullList,
        ApprovalModeKnob::SummarySample { configured_k } => ApprovalMode::SummarySample {
            configured_k,
            effective_k: effective_k(configured_k, members.len())?,
        },
    };
    let minted_secs = crate::prestate::unix_secs_from_rfc3339_utc(&inputs.minted_at)
        .ok_or_else(|| PlanStoreError::Store(format!("the sticky clock answered a non-canonical instant {:?}", inputs.minted_at)))?;
    let expires_at = minted_secs
        .checked_add(spec.ttl_seconds)
        .map(crate::prestate::rfc3339_utc)
        .filter(|t| crate::prestate::is_canonical_rfc3339_utc(t))
        .ok_or(PlanStoreError::TtlOutOfRange)?;
    // The bypass-lane notice is frozen at mint: the verb's warning exactly when the lane is
    // `Bypassed` and backups are off. It sits outside every digest because it is an admission
    // check, not a bound input.
    let bypass_notice = TriagePlan::bypass_notice_for(spec.verb, admission_lane, backups_on);
    let plan = TriagePlan {
        plan_id,
        account: spec.account,
        provider_principal: spec.provider_principal,
        grant_generation: spec.grant_generation,
        control_epoch: inputs.control_epoch,
        verb: spec.verb,
        rationale: spec.rationale,
        minted_at: inputs.minted_at,
        expires_at,
        members,
        admission_lane,
        approval_mode,
        coverage_generation: inputs.knobs.backups.generation,
        backups_on,
        bypass_notice,
        digests,
        key_ref,
    };
    plan.validate_shape()?;
    Ok(plan)
}

/// The evidence builder both stores' `record_approval` call: the view commitment over what
/// the renderer says it showed, under the plan's stored randomizer and the account key, plus
/// the comprehension the plan's lane calls for. Aggregate: the re-derived sample of the plan's
/// `effective_k`. Bypassed: the plan's own presentation digest and the bypass generation it
/// froze at mint (`rendered` is not consulted). `plan::validate_evidence` then runs, and
/// evidence that does not validate is never returned, so never written.
pub(crate) fn build_approval_evidence(
    root_key: &crate::commitment::CommitmentKey,
    plan: &crate::plan::TriagePlan,
    approver: &str,
    approved_at: String,
    rendered: crate::plan::RenderedView,
    current_bypass_generation: u64,
) -> Result<crate::plan::ApprovalEvidence, crate::plan::PlanStoreError> {
    use crate::plan::{
        derive_sample, validate_evidence, view_commitment, AdmissionLane, ApprovalEvidence, ApprovalMode, Comprehension,
        PlanRefusal,
    };
    plan.validate_shape()?;
    let key = crate::commitment::derive_account_key(root_key, &plan.account)?;
    let (view_digest, comprehension) = match plan.admission_lane {
        AdmissionLane::PerMember => (view_commitment(&key, &plan.key_ref, &plan.digests, &rendered)?, Comprehension::PerMember),
        AdmissionLane::Aggregate => {
            let ApprovalMode::SummarySample { effective_k, .. } = plan.approval_mode else {
                return Err(PlanRefusal::PlanShape(crate::plan::PlanShapeRule::AggregateLaneRequiresSummarySample).into());
            };
            let sample_members = derive_sample(&key, &plan.digests, &plan.members, effective_k)?;
            (
                view_commitment(&key, &plan.key_ref, &plan.digests, &rendered)?,
                Comprehension::Aggregate { shape_digest: plan.digests.shape, sample_k: effective_k, sample_members },
            )
        }
        // The generation the plan froze at mint, not the one in force now: `validate_evidence`
        // compares the two and refuses `BypassGenerationMismatch` when the knob moved since mint.
        AdmissionLane::Bypassed { bypass_config_generation } => (
            plan.digests.presentation,
            Comprehension::Bypassed { bypass_config_generation },
        ),
    };
    let evidence = ApprovalEvidence {
        plan_id: plan.plan_id.clone(),
        approver: approver.to_string(),
        approved_at,
        view_digest,
        comprehension,
        decision: crate::plan::Decision::Approved,
    };
    validate_evidence(&key, plan, &evidence, current_bypass_generation)?;
    Ok(evidence)
}

/// The plan stores' transaction error on the durable store: a typed refusal (the transaction
/// rolls back and the refusal surfaces as itself) or a store failure (surfaces as
/// `PlanStoreError::Store`). Crate-private, so it can take the gate's error type.
pub(crate) enum PlanTxError {
    Plan(crate::plan::PlanStoreError),
    Log(LogError),
}
impl From<crate::writer_gate::GateError> for PlanTxError {
    fn from(e: crate::writer_gate::GateError) -> Self {
        PlanTxError::Log(LogError::from(e))
    }
}
impl From<rusqlite::Error> for PlanTxError {
    fn from(e: rusqlite::Error) -> Self {
        PlanTxError::Log(LogError::from(e))
    }
}
impl From<LogError> for PlanTxError {
    fn from(e: LogError) -> Self {
        PlanTxError::Log(e)
    }
}
impl From<crate::plan::PlanStoreError> for PlanTxError {
    fn from(e: crate::plan::PlanStoreError) -> Self {
        PlanTxError::Plan(e)
    }
}
impl From<PlanTxError> for crate::plan::PlanStoreError {
    fn from(e: PlanTxError) -> Self {
        match e {
            PlanTxError::Plan(e) => e,
            PlanTxError::Log(e) => crate::plan::PlanStoreError::Store(e.0),
        }
    }
}

// The execution episode: the durable store's in-transaction halves. Each `SqliteIntentLog`
// episode method opens one immediate transaction and calls one of these; every write goes
// through `write_episode_in` (generation compare-and-set plus the journal row). A refusal is
// answered as `Ok(Err(refusal))` so the transaction commits: nothing has been written before
// a refusal except the sticky clock's latch, which an evaluation that read the clock keeps.

/// One episode write: the head's next state and the journal row's event and instant.
/// `write_episode_in` (durable) and `InMemoryIntentLog::write_episode` (twin) apply it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EpisodeWrite {
    pub(crate) status: crate::episode::EpisodeStatus,
    pub(crate) ready_at: Option<String>,
    pub(crate) completed_at: Option<String>,
    pub(crate) event: crate::episode::EpisodeEvent,
    pub(crate) at: String,
}

/// The plan's episode head, read strictly: the status and its reason through
/// `EpisodeStatus::from_columns`, the generation checked `>= 1`. A stored value this build
/// cannot have written is a `LogError`. `None` means no episode.
pub(crate) fn read_episode_in(conn: &rusqlite::Connection, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::Episode>, LogError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, Option<String>, i64, i64, String, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT episode_id, status, status_reason, generation, claim_epoch, started_at, ready_at, completed_at
               FROM execution_episode WHERE plan_id = ?1;",
            rusqlite::params![plan_id.0],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("episode read: {e}")))?;
    let Some((episode_id, status, reason, generation, claim_epoch, started_at, ready_at, completed_at)) = row else {
        return Ok(None);
    };
    let status = crate::episode::EpisodeStatus::from_columns(&status, reason.as_deref())
        .map_err(|e| LogError(format!("episode '{}' does not read back: {e}", plan_id.0)))?;
    let generation = u64::try_from(generation)
        .ok()
        .filter(|g| *g >= 1)
        .ok_or_else(|| LogError(format!("episode '{}' has generation {generation}", plan_id.0)))?;
    Ok(Some(crate::episode::Episode { plan_id: plan_id.clone(), episode_id, status, generation, claim_epoch, started_at, ready_at, completed_at }))
}

/// The zero-dispatch count: how many of the plan's children own a `send_authorized` fact
/// (`attempt_fact.operation_id` is the child's `intents.intent_id`). `mark_ready` and a
/// `StalePreflight` invalidation refuse unless it is zero.
fn send_authorized_children_in(conn: &rusqlite::Connection, plan_id: &crate::plan::PlanId) -> Result<u64, LogError> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT i.intent_id)
               FROM attempt_fact f JOIN intents i ON i.intent_id = f.operation_id
              WHERE i.plan_id = ?1 AND f.fact_kind = ?2;",
            rusqlite::params![plan_id.0, crate::attempt::FactKind::SendAuthorized.as_sql()],
            |r| r.get(0),
        )
        .map_err(|e| LogError(format!("episode zero-dispatch count: {e}")))?;
    Ok(n as u64)
}

/// The episode write on the durable store: a compare-and-set on the head's generation
/// (`UPDATE ... WHERE plan_id = ?1 AND generation = ?2`). Anything but exactly one changed row
/// answers `GenerationConflict` (or `NoEpisode`) with nothing written. Then one
/// `episode_journal` row at the new generation. Returns the new generation. Runs inside the
/// caller's transaction.
pub(crate) fn write_episode_in(
    tx: &rusqlite::Transaction<'_>,
    plan_id: &crate::plan::PlanId,
    expected: u64,
    w: &EpisodeWrite,
) -> Result<Result<u64, crate::episode::EpisodeRefusal>, LogError> {
    let reason = w.status.reason_json();
    let token = w.status.token().as_token();
    let changed = tx
        .execute(
            "UPDATE execution_episode
                SET status = ?3, status_reason = ?4, generation = generation + 1,
                    ready_at = ?5, completed_at = ?6, updated_at = ?7
              WHERE plan_id = ?1 AND generation = ?2;",
            rusqlite::params![plan_id.0, expected as i64, token, reason, w.ready_at, w.completed_at, w.at],
        )
        .map_err(|e| LogError(format!("episode write: {e}")))?;
    if changed != 1 {
        let found: Option<i64> = tx
            .query_row("SELECT generation FROM execution_episode WHERE plan_id = ?1;", rusqlite::params![plan_id.0], |r| r.get(0))
            .optional()
            .map_err(|e| LogError(format!("episode write: generation read: {e}")))?;
        return Ok(Err(match found {
            Some(found) => crate::episode::EpisodeRefusal::GenerationConflict { expected, found: found as u64 },
            None => crate::episode::EpisodeRefusal::NoEpisode,
        }));
    }
    let next = expected + 1;
    tx.execute(
        "INSERT INTO episode_journal (plan_id, generation, status, reason, event, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
        rusqlite::params![plan_id.0, next as i64, token, reason, w.event.as_token(), w.at],
    )
    .map_err(|e| LogError(format!("episode journal append: {e}")))?;
    Ok(Ok(next))
}

/// The plan-expiry clock on the durable store: the stored `expires_at` must be canonical,
/// because it is compared lexicographically, which is time order only for the canonical
/// RFC 3339 spelling. The answer is [`sticky_effective_now`].
fn plan_clock_in(tx: &rusqlite::Transaction<'_>, plan_id: &crate::plan::PlanId, expires_at: &str, door: &str) -> Result<String, LogError> {
    if !crate::prestate::is_canonical_rfc3339_utc(expires_at) {
        return Err(LogError(format!("{door}: plan '{}' has a non-canonical expires_at", plan_id.0)));
    }
    sticky_effective_now(tx, door)
}

/// `start_episode`'s transaction body; see [`IntentLog::start_episode`] for the order. The
/// episode id comes from [`mint_opaque_id`].
pub(crate) fn start_episode_in(
    tx: &rusqlite::Transaction<'_>,
    plan_id: &crate::plan::PlanId,
) -> Result<Result<crate::episode::EpisodeStart, crate::episode::EpisodeRefusal>, LogError> {
    use crate::episode::{Episode, EpisodeEvent, EpisodeRefusal as R, EpisodeStart, EpisodeStatus, InvalidationReason};
    let plan: Option<(i64, String)> = tx
        .query_row("SELECT control_epoch, expires_at FROM triage_plan WHERE plan_id = ?1;", rusqlite::params![plan_id.0], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .map_err(|e| LogError(format!("start_episode: plan read: {e}")))?;
    let Some((plan_epoch, expires_at)) = plan else {
        return Ok(Err(R::NoPlan));
    };
    let approved: bool = tx
        .query_row("SELECT EXISTS(SELECT 1 FROM approval_evidence WHERE plan_id = ?1);", rusqlite::params![plan_id.0], |r| r.get(0))
        .map_err(|e| LogError(format!("start_episode: approval read: {e}")))?;
    if !approved {
        return Ok(Err(R::NotApproved));
    }
    let current: i64 = tx
        .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))
        .map_err(|e| LogError(format!("start_episode: epoch read: {e}")))?;
    // The resume path closes what it refuses: an existing non-terminal episode of an
    // epoch-moved or expired plan is invalidated inside this (committing) transaction, never
    // left live-but-dead. The transition table decides; a terminal episode keeps its status.
    if current != plan_epoch {
        let _ = invalidate_episode_in_tx(tx, plan_id, &InvalidationReason::EpochMismatch { plan: plan_epoch, current })?;
        return Ok(Err(R::EpochMismatch { plan: plan_epoch, current }));
    }
    let now = plan_clock_in(tx, plan_id, &expires_at, "start_episode")?;
    if expires_at.as_str() <= now.as_str() {
        let _ = invalidate_episode_in_tx(tx, plan_id, &InvalidationReason::Expired)?;
        return Ok(Err(R::Expired { expires_at, effective_now: now }));
    }
    if let Some(existing) = read_episode_in(tx, plan_id)? {
        let token = existing.status.token();
        return Ok(if token.is_terminal() { Err(R::Terminal(token)) } else { Ok(EpisodeStart::Resumed(existing)) });
    }
    let episode = Episode {
        plan_id: plan_id.clone(),
        episode_id: mint_opaque_id(tx, "start_episode")?,
        status: EpisodeStatus::Active,
        generation: 1,
        // Equal to the plan's `control_epoch`, since this line is reached only past the
        // `current != plan_epoch` refusal. Nothing reads it; the column predates this schema.
        claim_epoch: current,
        started_at: now.clone(),
        ready_at: None,
        completed_at: None,
    };
    let token = episode.status.token().as_token();
    tx.execute(
        "INSERT INTO execution_episode (plan_id, episode_id, status, status_reason, generation, claim_epoch, started_at, updated_at)
         VALUES (?1, ?2, ?3, NULL, 1, ?4, ?5, ?5);",
        rusqlite::params![plan_id.0, episode.episode_id, token, current, now],
    )
    .map_err(|e| LogError(format!("start_episode: head insert: {e}")))?;
    tx.execute(
        "INSERT INTO episode_journal (plan_id, generation, status, reason, event, at) VALUES (?1, 1, ?2, NULL, ?3, ?4);",
        rusqlite::params![plan_id.0, token, EpisodeEvent::Start.as_token(), now],
    )
    .map_err(|e| LogError(format!("start_episode: journal append: {e}")))?;
    Ok(Ok(EpisodeStart::Started(episode)))
}

/// `mark_ready`'s transaction body; see [`IntentLog::mark_ready`].
pub(crate) fn mark_ready_in(
    tx: &rusqlite::Transaction<'_>,
    plan_id: &crate::plan::PlanId,
) -> Result<Result<crate::episode::ReadyOutcome, crate::episode::EpisodeRefusal>, LogError> {
    use crate::episode::{EpisodeEvent, EpisodeRefusal as R, EpisodeStatusToken, ReadyOutcome};
    let Some(e) = read_episode_in(tx, plan_id)? else {
        return Ok(Err(R::NoEpisode));
    };
    let token = e.status.token();
    if token.is_terminal() {
        return Ok(Err(R::Terminal(token)));
    }
    if token != EpisodeStatusToken::Active {
        return Ok(Err(R::NotActive(token)));
    }
    if e.ready_at.is_some() {
        return Ok(Ok(ReadyOutcome::AlreadyReady));
    }
    let began = send_authorized_children_in(tx, plan_id)?;
    if began > 0 {
        return Ok(Err(R::DispatchBegan { send_authorized_children: began }));
    }
    let now = sticky_effective_now(tx, "mark_ready")?;
    let w = EpisodeWrite { status: e.status.clone(), ready_at: Some(now.clone()), completed_at: e.completed_at.clone(), event: EpisodeEvent::Ready, at: now };
    Ok(write_episode_in(tx, plan_id, e.generation, &w)?.map(|_| ReadyOutcome::Ready))
}

/// `invalidate_episode`'s transaction body; see [`IntentLog::invalidate_episode`].
/// Crate-visible so a caller already inside a transaction can invalidate in it:
/// `authorize_send`'s plan arm calls it for an expired or epoch-moved plan.
pub(crate) fn invalidate_episode_in_tx(
    tx: &rusqlite::Transaction<'_>,
    plan_id: &crate::plan::PlanId,
    reason: &crate::episode::InvalidationReason,
) -> Result<Result<(), crate::episode::EpisodeRefusal>, LogError> {
    use crate::episode::{assert_transition, EpisodeEvent, EpisodeRefusal as R, EpisodeStatus, EpisodeStatusToken, InvalidationReason};
    let Some(e) = read_episode_in(tx, plan_id)? else {
        return Ok(Err(R::NoEpisode));
    };
    if let Err(refusal) = assert_transition(e.status.token(), EpisodeStatusToken::Invalidated) {
        return Ok(Err(refusal));
    }
    if matches!(reason, InvalidationReason::StalePreflight { .. }) {
        let began = send_authorized_children_in(tx, plan_id)?;
        if began > 0 {
            return Ok(Err(R::DispatchBegan { send_authorized_children: began }));
        }
    }
    let now = sticky_effective_now(tx, "invalidate_episode")?;
    let w = EpisodeWrite {
        status: EpisodeStatus::Invalidated(reason.clone()),
        ready_at: e.ready_at.clone(),
        completed_at: e.completed_at.clone(),
        event: EpisodeEvent::Transition,
        at: now,
    };
    Ok(write_episode_in(tx, plan_id, e.generation, &w)?.map(|_| ()))
}

/// The send-admission checks on the durable store: the rows [`IntentLog::authorize_send`]'s
/// table lists, in order, inside its transaction. Returns the first refusal, or `None` when
/// admitted. It writes only row 4's sticky-clock latch advance; the caller writes the terminal.
///
/// Row 4 treats `expires_at <= effective_now` as expired, as `record()`'s arm
/// (`plan_child_admission`) does. The undo offer draws that instant the other way
/// (`prestate::derive_undo_eligibility` expires on `effective_now > undo_offer_until`).
/// Row 10 compares over the capture's `touched_atom` projection, the row whose
/// `capture_generation` the caller's CAS token just matched.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_send_admission(
    tx: &rusqlite::Transaction<'_>,
    plan_id: &crate::plan::PlanId,
    member_ref: &str,
    idempotency_key: &str,
    grant: &crate::plan::GrantVerdict,
    account_key: &crate::commitment::CommitmentKey,
    capture: CaptureBinding,
) -> Result<Option<crate::plan::PlanSendRefusal>, LogError> {
    use crate::episode::EpisodeStatusToken as T;
    use crate::plan::PlanSendRefusal as R;
    // 1. The episode's status token and ready marker — two columns, not the typed head.
    let episode: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT status, ready_at FROM execution_episode WHERE plan_id = ?1;",
            rusqlite::params![plan_id.0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("authorize_send plan admission: episode read: {e}")))?;
    let Some((status, ready_at)) = episode else {
        return Ok(Some(R::NoEpisode));
    };
    let status = T::from_token(&status)
        .ok_or_else(|| LogError(format!("authorize_send plan admission: episode status token '{status}' is not one this build writes")))?;
    match status {
        T::Active => {}
        T::Paused => return Ok(Some(R::EpisodeHeld(status))),
        T::Cancelled | T::Completed | T::Invalidated => return Ok(Some(R::EpisodeClosed(status))),
    }
    if ready_at.is_none() {
        return Ok(Some(R::NotReady));
    }
    // 1b. The grant verdict could not be formed (no ratchet, or an unreadable high-water):
    //     held. This is decided before any read of the clock and writes nothing.
    if let crate::plan::GrantVerdict::Refused(crate::plan::GrantDenial::Unavailable) = grant {
        return Ok(Some(R::GrantRetired(crate::plan::GrantDenial::Unavailable)));
    }
    // 2. The plan, through its read boundary (a row that does not read back is a store error).
    let plan = read_plan_in(tx, plan_id)?
        .ok_or_else(|| LogError(format!("authorize_send plan admission: plan '{}' vanished under its child", plan_id.0)))?;
    // 3. The control epoch (the plan's, beside the attempt's own fence the caller ran).
    let current: i64 = tx
        .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))
        .map_err(|e| LogError(format!("authorize_send plan admission: epoch read: {e}")))?;
    if current != plan.control_epoch {
        return Ok(Some(R::PlanEpochMismatch { plan: plan.control_epoch, current }));
    }
    // 4. Expiry on the sticky clock (`read_plan_in` refused a non-canonical `expires_at`).
    let now = sticky_effective_now(tx, "authorize_send")?;
    if plan.expires_at.as_str() <= now.as_str() {
        return Ok(Some(R::Expired { expires_at: plan.expires_at.clone(), effective_now: now }));
    }
    // 5. Membership.
    let Some(member) = plan.member(member_ref) else {
        return Ok(Some(R::NotAMember));
    };
    // 6. Evidence: present, and admitted by the pure core under the account key and the
    //    red-bypass generation in force.
    let Some(evidence) = read_evidence_in(tx, plan_id)? else {
        return Ok(Some(R::EvidenceAbsent));
    };
    let knobs = knob_state_in(tx)?.map_err(|e| LogError(format!("authorize_send plan admission: knob state: {e}")))?;
    if let Err(refusal) = crate::plan::validate_evidence(account_key, &plan, &evidence, knobs.red_bypass.generation) {
        return Ok(Some(R::EvidenceInvalid(refusal)));
    }
    // 6b. The bypass-lane notice: a `Bypassed` plan minted under `backups: off` must carry its
    //     frozen notice (that journaled emission is itself a bypass-lane admission check).
    if matches!(plan.admission_lane, crate::plan::AdmissionLane::Bypassed { .. }) && !plan.backups_on && plan.bypass_notice.is_none() {
        return Ok(Some(R::BypassNoticeAbsent));
    }
    // 7. The grant — the bus's ratchet verdict (`Unavailable` was row 1b).
    if let crate::plan::GrantVerdict::Refused(refusal) = grant {
        return Ok(Some(R::GrantRetired(*refusal)));
    }
    // 8. Coverage: the backups knob's head generation, not its value (an off→on→off round trip
    //    lands on a new generation).
    if plan.coverage_generation != knobs.backups.generation {
        return Ok(Some(R::CoverageDiverged { plan: plan.coverage_generation, current: knobs.backups.generation }));
    }
    // 9. The snapshot row — this build has none to check.
    if plan.backups_on {
        return Ok(Some(R::SnapshotAbsent));
    }
    // 10. The member's approval-time state against the CAS-bound capture.
    if capture == CaptureBinding::NoJournalRow {
        return Ok(Some(R::CaptureRequired));
    }
    let captured: String = tx
        .query_row(
            "SELECT p.touched_atom FROM pre_state p JOIN intents i ON i.intent_id = p.intent_id WHERE i.idempotency_key = ?1;",
            rusqlite::params![idempotency_key],
            |r| r.get(0),
        )
        .map_err(|e| LogError(format!("authorize_send plan admission: capture read: {e}")))?;
    let captured: std::collections::BTreeMap<String, bool> = serde_json::from_str(&captured)
        .map_err(|e| LogError(format!("authorize_send plan admission: capture is not a Boolean atom map: {e}")))?;
    let diff = crate::plan::member_state_diff(&member.observed_state, &captured);
    if !diff.is_empty() {
        return Ok(Some(R::StateDiverged { diff }));
    }
    Ok(None)
}

/// `complete_episode_if_done`'s transaction body; see [`IntentLog::complete_episode_if_done`].
///
/// The children are read and each status parsed strictly in Rust (`status_from_str`, then
/// `IntentStatus::is_terminal`) rather than filtered in SQL: an unknown status token is a
/// `LogError`, never silently counted as terminal (which would complete a plan early) or as
/// non-terminal. Children are joined to the plan's members, so only a member's child counts.
pub(crate) fn complete_episode_if_done_in(tx: &rusqlite::Transaction<'_>, plan_id: &crate::plan::PlanId) -> Result<crate::episode::Completion, LogError> {
    use crate::episode::{assert_transition, Completion, EpisodeEvent, EpisodeStatus, EpisodeStatusToken, InvalidationReason};
    let Some(e) = read_episode_in(tx, plan_id)? else {
        return Ok(Completion::NoEpisode);
    };
    let token = e.status.token();
    if token.is_terminal() {
        return Ok(Completion::AlreadyTerminal(token));
    }
    let (total, expires_at, plan_epoch): (i64, String, i64) = tx
        .query_row(
            "SELECT (SELECT COUNT(*) FROM plan_member WHERE plan_id = ?1), expires_at, control_epoch FROM triage_plan WHERE plan_id = ?1;",
            rusqlite::params![plan_id.0],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|e| LogError(format!("complete_episode_if_done: plan read: {e}")))?;
    // The epoch terminal is decided before the exact-N branch. A sever closes every pending
    // child `Severed`, so without this the exact-N predicate would read those closures as a
    // `completed` plan, or leave an unminted member's episode `active` until expiry.
    let current: i64 = tx
        .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))
        .map_err(|e| LogError(format!("complete_episode_if_done: epoch read: {e}")))?;
    if current != plan_epoch {
        let reason = InvalidationReason::EpochMismatch { plan: plan_epoch, current };
        invalidate_episode_in_tx(tx, plan_id, &reason)?.map_err(|r| LogError(format!("complete_episode_if_done: {r}")))?;
        return Ok(Completion::Invalidated(reason));
    }
    let total = total as u64;
    let (mut minted, mut terminal) = (0u64, 0u64);
    {
        let mut stmt = tx
            .prepare(
                "SELECT i.status FROM plan_member m
                   JOIN intents i ON i.plan_id = m.plan_id AND i.plan_member = m.message_ref
                  WHERE m.plan_id = ?1;",
            )
            .map_err(|e| LogError(format!("complete_episode_if_done: children read: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![plan_id.0], |r| r.get::<_, String>(0))
            .map_err(|e| LogError(format!("complete_episode_if_done: children read: {e}")))?;
        for status in rows {
            let status = status.map_err(|e| LogError(format!("complete_episode_if_done: children read: {e}")))?;
            minted += 1;
            if status_from_str(&status)?.is_terminal() {
                terminal += 1;
            }
        }
    }
    if token != EpisodeStatusToken::Active {
        return Ok(Completion::Incomplete { total, minted, terminal });
    }
    let now = plan_clock_in(tx, plan_id, &expires_at, "complete_episode_if_done")?;
    let (status, completion) = if total > 0 && terminal == total {
        (EpisodeStatus::Completed, Completion::Completed)
    } else if expires_at.as_str() <= now.as_str() {
        (EpisodeStatus::Invalidated(InvalidationReason::Expired), Completion::Invalidated(InvalidationReason::Expired))
    } else {
        return Ok(Completion::Incomplete { total, minted, terminal });
    };
    assert_transition(token, status.token()).map_err(|r| LogError(format!("complete_episode_if_done: {r}")))?;
    let completed_at = matches!(status, EpisodeStatus::Completed).then(|| now.clone()).or(e.completed_at.clone());
    let w = EpisodeWrite { status, ready_at: e.ready_at.clone(), completed_at, event: EpisodeEvent::Transition, at: now };
    write_episode_in(tx, plan_id, e.generation, &w)?.map_err(|r| LogError(format!("complete_episode_if_done: {r}")))?;
    Ok(completion)
}

/// The cheap plan-child admission at `record()` on the durable store, called inside its
/// admission transaction for a command carrying a plan link. In order: a RED verb, the plan
/// row exists, its account, its verb over the linked member, the derived child key
/// ([`plan_child_key`]), the plan's approval row, the episode row with its `active` status
/// and `ready_at` marker, the member row, the control epoch, and the expiry on the sticky
/// clock. The first that fails is the answer, as a named [`crate::plan::PlanChildRefusal`];
/// `Ok(None)` admits.
///
/// It reads a few columns and two EXISTS probes rather than `read_plan_in`, which rebuilds and
/// shape-checks the whole plan (O(members)) on every child. It writes nothing before the
/// expiry check, whose [`sticky_effective_now`] latch advance commits with `record()`'s
/// transaction on every later outcome, `Expired` included, so a wall-clock rollback cannot
/// re-open an expired plan.
pub(crate) fn plan_child_admission(
    tx: &rusqlite::Transaction<'_>,
    command: &Command,
    link: &crate::plan::PlanChildLink,
) -> Result<Option<crate::plan::PlanChildRefusal>, LogError> {
    use crate::plan::PlanChildRefusal as R;
    if !command.action.risk_tier().requires_plan() {
        return Ok(Some(R::NotARedVerb));
    }
    let plan: Option<(String, String, i64, String)> = tx
        .query_row(
            "SELECT account, verb, control_epoch, expires_at FROM triage_plan WHERE plan_id = ?1;",
            rusqlite::params![link.plan_id.0],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("plan child admission: plan read: {e}")))?;
    let Some((account, verb, plan_epoch, expires_at)) = plan else {
        return Ok(Some(R::NoPlan));
    };
    if account != command.account {
        return Ok(Some(R::AccountMismatch));
    }
    let verb = crate::plan::PlanVerb::from_token(&verb)
        .map_err(|e| LogError(format!("plan child admission: stored verb: {e:?}")))?;
    if verb.action(&link.member_ref) != command.action {
        return Ok(Some(R::VerbMismatch));
    }
    if command.idempotency_key != plan_child_key(&account, link) {
        return Ok(Some(R::KeyMismatch));
    }
    let approved: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM approval_evidence WHERE plan_id = ?1);",
            rusqlite::params![link.plan_id.0],
            |r| r.get(0),
        )
        .map_err(|e| LogError(format!("plan child admission: approval read: {e}")))?;
    if !approved {
        return Ok(Some(R::NotApproved));
    }
    // The episode leg: the status token and the ready marker only, two columns rather than the
    // typed head (`read_episode_in` also parses the reason JSON).
    let episode: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT status, ready_at FROM execution_episode WHERE plan_id = ?1;",
            rusqlite::params![link.plan_id.0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("plan child admission: episode read: {e}")))?;
    let Some((status, ready_at)) = episode else {
        return Ok(Some(R::NoEpisode));
    };
    let token = crate::episode::EpisodeStatusToken::from_token(&status)
        .ok_or_else(|| LogError(format!("plan child admission: episode status token '{status}' is not one this build writes")))?;
    if token != crate::episode::EpisodeStatusToken::Active {
        return Ok(Some(R::EpisodeNotActive(token)));
    }
    if ready_at.is_none() {
        return Ok(Some(R::NotReady));
    }
    let member: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM plan_member WHERE plan_id = ?1 AND message_ref = ?2);",
            rusqlite::params![link.plan_id.0, link.member_ref],
            |r| r.get(0),
        )
        .map_err(|e| LogError(format!("plan child admission: member read: {e}")))?;
    if !member {
        return Ok(Some(R::NotAMember(link.member_ref.clone())));
    }
    let current: i64 = tx
        .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))
        .map_err(|e| LogError(format!("plan child admission: epoch read: {e}")))?;
    if current != plan_epoch {
        return Ok(Some(R::EpochMismatch { plan: plan_epoch, current }));
    }
    // The stored expiry is compared lexicographically, which is time order only for the
    // canonical RFC 3339 spelling; a stored value outside it is a store error, never compared.
    if !crate::prestate::is_canonical_rfc3339_utc(&expires_at) {
        return Err(LogError(format!("plan child admission: plan '{}' has a non-canonical expires_at", link.plan_id.0)));
    }
    let now = sticky_effective_now(tx, "record")?;
    // `expires_at <= now` is expired: at the expiry instant the plan is already expired. The
    // undo offer draws that instant the other way: `prestate::derive_undo_eligibility` expires
    // on `effective_now > undo_offer_until`.
    if expires_at.as_str() <= now.as_str() {
        return Ok(Some(R::Expired { expires_at, effective_now: now }));
    }
    Ok(None)
}

/// The sticky clock on the durable store, shared by `undo_context`, the plan mint
/// (`minted_at`) and the approval (`approved_at`). Runs inside the caller's transaction: the
/// stored latch is validated as stored (a non-canonical latch refuses and is never repaired),
/// `effective_now = max(now, latch)` is taken over cleared values, the governing value is
/// re-checked, and the max is latched back (`MAX(...)` in the upsert, so the latch never goes
/// down). `door` names the caller in the refusal.
pub(crate) fn sticky_effective_now(tx: &rusqlite::Transaction<'_>, door: &str) -> Result<String, LogError> {
    // Validate the latch on the raw stored value, before it enters any comparison. `max_seen`
    // is a bare TEXT column and instants are ordered lexicographically, so corruption is
    // directional: a value sorting high would win the MAX and surface, but one sorting low
    // (any byte below `'0'`) would lose it, leaving `effective_now` canonical and the
    // corruption silently overwritten by the advance below. That would destroy the only
    // durable evidence behind the sticky-expiry invariant. Absent is fine: a first run has
    // nothing to clear, and `''` sorts below every real instant. Returning here drops the
    // transaction unwritten: refused, never repaired.
    let stored_latch: Option<String> = tx
        .query_row(
            "SELECT max_seen FROM time_high_water WHERE id = 1;",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| LogError(e.to_string()))?;
    if stored_latch
        .as_deref()
        .is_some_and(|raw| !crate::prestate::is_canonical_rfc3339_utc(raw))
    {
        return Err(LogError(format!(
            "{door}: non-canonical time high-water latch"
        )));
    }
    // The sticky clock: effective_now = max(now, high-water); persist the max back. RFC 3339
    // UTC seconds are fixed-width, so lexicographic order is time order, and the max is taken
    // in Rust over a latch this read has already cleared.
    let now: String = tx
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [], |r| {
            r.get(0)
        })
        .map_err(|e| LogError(e.to_string()))?;
    let effective_now = match stored_latch {
        Some(latch) if latch > now => latch,
        _ => now,
    };
    // The same boundary for the value that governs: the latch is known canonical, so this
    // guards the other input, the wall clock the store rendered.
    if !crate::prestate::is_canonical_rfc3339_utc(&effective_now) {
        return Err(LogError(format!(
            "{door}: non-canonical time high-water latch"
        )));
    }
    tx.execute(
        "INSERT INTO time_high_water (id, max_seen) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET max_seen = MAX(max_seen, excluded.max_seen);",
        rusqlite::params![effective_now],
    )
    .map_err(|e| LogError(e.to_string()))?;
    Ok(effective_now)
}

/// The head act of one knob kind on the durable ledger, as `(generation, payload)`; the one
/// read shared by `knob_state`, the plan mint and the approval.
fn knob_head_in(conn: &rusqlite::Connection, kind: &str) -> Result<Option<(u64, String)>, LogError> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT generation, payload FROM engine_config WHERE kind = ?1
              ORDER BY generation DESC LIMIT 1;",
            rusqlite::params![kind],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("knob_state read ({kind}): {e}")))?;
    row.map(|(generation, payload)| {
        u64::try_from(generation)
            .map(|generation| (generation, payload))
            .map_err(|_| LogError(format!("knob_state: generation {generation} is negative")))
    })
    .transpose()
}

/// The three knobs in force on the durable ledger, read over `conn` (a transaction the caller
/// holds, so the three heads are one snapshot). The outer error is the store's; the inner one
/// is a head act its strict reader refused.
pub(crate) fn knob_state_in(
    conn: &rusqlite::Connection,
) -> Result<Result<crate::config_knobs::KnobState, crate::config_knobs::KnobError>, LogError> {
    use crate::config_knobs::{KnobState, KIND_APPROVAL_MODE, KIND_BACKUPS, KIND_RED_BYPASS};
    let approval_mode = knob_head_in(conn, KIND_APPROVAL_MODE)?;
    let backups = knob_head_in(conn, KIND_BACKUPS)?;
    let red_bypass = knob_head_in(conn, KIND_RED_BYPASS)?;
    fn borrowed(head: &Option<(u64, String)>) -> Option<(u64, &str)> {
        head.as_ref().map(|(generation, payload)| (*generation, payload.as_str()))
    }
    Ok(KnobState::from_head_acts(borrowed(&approval_mode), borrowed(&backups), borrowed(&red_bypass)))
}

/// Every `triage_plan` column, in the order the insert binds and the read selects.
const TRIAGE_PLAN_COLUMNS: &str = "plan_id, account, provider_principal, grant_generation, \
    control_epoch, verb, tier, rationale, minted_at, expires_at, member_count, admission_lane, \
    bypass_config_generation, approval_mode, configured_k, effective_k, coverage_generation, \
    backups_on, warning, set_digest, set_randomizer, state_digest, state_randomizer, \
    presentation_digest, presentation_randomizer, shape_digest, shape_randomizer, sample_seed, \
    sample_seed_randomizer, aggregate_view_randomizer, key_ref_namespace, key_ref_epoch, bypass_notice";

/// The members a mint asked for, read from the durable store's own rows (header JOIN placement,
/// account-scoped), deduplicated and in ref order. The first ref with no row refuses the mint.
pub(crate) fn read_member_facts_in(
    conn: &rusqlite::Connection,
    account: &str,
    member_refs: &[String],
) -> Result<Vec<PlanMemberFacts>, PlanTxError> {
    let unique: std::collections::BTreeSet<&String> = member_refs.iter().collect();
    let mut facts = Vec::with_capacity(unique.len());
    for message_ref in unique {
        #[allow(clippy::type_complexity)]
        let row: Option<(String, String, String, i64, String, String, Option<String>)> = conn
            .query_row(
                "SELECT h.from_addr, h.from_name, h.subject, h.received_at, p.placement, h.from_status, h.from_domain
                   FROM message_header h
                   JOIN message_placement p ON p.account = h.account AND p.message_ref = h.message_ref
                  WHERE h.account = ?1 AND h.message_ref = ?2;",
                rusqlite::params![account, message_ref],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .optional()?;
        let Some((from_addr, from_name, subject, received_at_ms, placement, from_status, from_domain)) = row else {
            return Err(crate::plan::PlanStoreError::UnknownMember(message_ref.clone()).into());
        };
        let from_status = crate::mailbox::SenderStatus::from_token(&from_status).ok_or_else(|| {
            crate::plan::PlanStoreError::Store(format!("member '{message_ref}': unknown sender status '{from_status}'"))
        })?;
        facts.push(PlanMemberFacts {
            message_ref: message_ref.clone(),
            from_addr,
            from_status,
            from_domain,
            from_name,
            subject,
            received_at_ms,
            placement: crate::read_model::Placement::from_token(&placement)?,
        });
    }
    Ok(facts)
}

/// Persist a minted plan: the `triage_plan` row and its N `plan_member` rows.
pub(crate) fn insert_plan_rows(tx: &rusqlite::Transaction<'_>, plan: &crate::plan::TriagePlan) -> Result<(), LogError> {
    use crate::plan::{AdmissionLane, ApprovalMode};
    let as_i64 = |what: &str, v: u64| i64::try_from(v).map_err(|_| LogError(format!("insert plan: {what} {v} exceeds i64")));
    let bypass_config_generation = match plan.admission_lane {
        AdmissionLane::Bypassed { bypass_config_generation } => Some(as_i64("bypass_config_generation", bypass_config_generation)?),
        AdmissionLane::PerMember | AdmissionLane::Aggregate => None,
    };
    let (configured_k, effective_k) = match plan.approval_mode {
        ApprovalMode::FullList => (None, None),
        ApprovalMode::SummarySample { configured_k, effective_k } => (Some(i64::from(configured_k)), Some(i64::from(effective_k))),
    };
    let header = &plan.digests.presentation_view.header;
    let stored = plan.digests.to_stored();
    let placeholders = (1..=33).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
    tx.execute(
        &format!("INSERT INTO triage_plan ({TRIAGE_PLAN_COLUMNS}) VALUES ({placeholders});"),
        rusqlite::params![
            plan.plan_id.0,
            plan.account,
            plan.provider_principal,
            as_i64("grant_generation", plan.grant_generation)?,
            plan.control_epoch,
            plan.verb.as_token(),
            header.tier,
            plan.rationale,
            plan.minted_at,
            plan.expires_at,
            i64::from(header.count),
            plan.admission_lane.as_token(),
            bypass_config_generation,
            plan.approval_mode.as_token(),
            configured_k,
            effective_k,
            as_i64("coverage_generation", plan.coverage_generation)?,
            plan.backups_on,
            header.warning,
            stored.set,
            stored.set_randomizer,
            stored.state,
            stored.state_randomizer,
            stored.presentation,
            stored.presentation_randomizer,
            stored.shape,
            stored.shape_randomizer,
            stored.sample_seed,
            stored.sample_seed_randomizer,
            stored.aggregate_view_randomizer,
            plan.key_ref.namespace_key_id(),
            as_i64("key_ref_epoch", plan.key_ref.key_epoch())?,
            plan.bypass_notice,
        ],
    )
    .map_err(|e| LogError(format!("insert triage_plan: {e}")))?;
    for m in &plan.members {
        tx.execute(
            "INSERT INTO plan_member (plan_id, message_ref, sender, subject, date, size, observed_state, forward_target,
                                      sender_status, sender_local, sender_addr, sender_domain, sender_address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13);",
            rusqlite::params![
                plan.plan_id.0,
                m.message_ref,
                m.display.sender,
                m.display.subject,
                m.display.date,
                m.display.size.map(|s| as_i64("size", s)).transpose()?,
                crate::plan::encode_atom_map(&m.observed_state),
                crate::plan::encode_atom_map(&m.forward_target),
                m.display.sender_parse.status().as_token(),
                m.display.sender_parse.local(),
                m.display.sender_parse.addr(),
                m.display.sender_parse.domain(),
                m.display.sender_address,
            ],
        )
        .map_err(|e| LogError(format!("insert plan_member: {e}")))?;
    }
    Ok(())
}

/// One `triage_plan` row as SQLite hands it back — raw, before any of it is believed.
struct RawPlanRow {
    account: String,
    provider_principal: String,
    grant_generation: i64,
    control_epoch: i64,
    verb: String,
    tier: String,
    rationale: Option<String>,
    minted_at: String,
    expires_at: String,
    member_count: i64,
    admission_lane: String,
    bypass_config_generation: Option<i64>,
    approval_mode: String,
    configured_k: Option<i64>,
    effective_k: Option<i64>,
    coverage_generation: i64,
    backups_on: i64,
    warning: Option<String>,
    stored: crate::plan::StoredDigests,
    key_ref_namespace: String,
    key_ref_epoch: i64,
    bypass_notice: Option<String>,
}

/// The read boundary for a stored plan: every column parsed strictly (closed tokens, the
/// lane's and mode's companion columns present exactly when their token needs them, canonical
/// instants, non-negative numbers), the members decoded strictly and canonicalized, the
/// digest family and the presentation rebuilt (`PlanDigests::from_stored`), and the result
/// run through `TriagePlan::validate_shape`. Any failure is the reason string, never a plan.
fn plan_from_row(
    plan_id: &crate::plan::PlanId,
    row: RawPlanRow,
    members: Vec<crate::plan::PlanMember>,
) -> Result<crate::plan::TriagePlan, String> {
    use crate::plan::{
        canonical_members, AdmissionLane, ApprovalMode, PlanDigests, PlanVerb, PresentationHeader, TriagePlan, PLAN_TIER,
    };
    let unsigned = |what: &str, v: i64| u64::try_from(v).map_err(|_| format!("{what} {v} is negative"));
    let verb = PlanVerb::from_token(&row.verb).map_err(|e| format!("{e:?}"))?;
    if row.tier != PLAN_TIER {
        return Err(format!("tier '{}' is not '{PLAN_TIER}'", row.tier));
    }
    let admission_lane = match (row.admission_lane.as_str(), row.bypass_config_generation) {
        ("per_member", None) => AdmissionLane::PerMember,
        ("aggregate", None) => AdmissionLane::Aggregate,
        ("bypassed", Some(g)) => AdmissionLane::Bypassed { bypass_config_generation: unsigned("bypass_config_generation", g)? },
        (lane, g) => return Err(format!("admission_lane '{lane}' with bypass_config_generation {g:?}")),
    };
    let approval_mode = match (row.approval_mode.as_str(), row.configured_k, row.effective_k) {
        ("full_list", None, None) => ApprovalMode::FullList,
        ("summary_sample", Some(c), Some(e)) => ApprovalMode::SummarySample {
            configured_k: u32::try_from(c).map_err(|_| format!("configured_k {c} is not a u32"))?,
            effective_k: u32::try_from(e).map_err(|_| format!("effective_k {e} is not a u32"))?,
        },
        (mode, c, e) => return Err(format!("approval_mode '{mode}' with configured_k {c:?}, effective_k {e:?}")),
    };
    let backups_on = match row.backups_on {
        0 => false,
        1 => true,
        other => return Err(format!("backups_on {other}")),
    };
    for (what, t) in [("minted_at", &row.minted_at), ("expires_at", &row.expires_at)] {
        if !crate::prestate::is_canonical_rfc3339_utc(t) {
            return Err(format!("{what} is not a canonical RFC-3339 UTC instant"));
        }
    }
    let header = PresentationHeader {
        account: row.account.clone(),
        verb,
        tier: row.tier,
        count: u32::try_from(row.member_count).map_err(|_| format!("member_count {} is not a u32", row.member_count))?,
        backup_coverage: backups_on,
        warning: row.warning,
    };
    let members = canonical_members(members).map_err(|e| format!("{e:?}"))?;
    let key_ref = crate::commitment::CommitmentKeyRef::new(&row.key_ref_namespace, unsigned("key_ref_epoch", row.key_ref_epoch)?)
        .map_err(|e| format!("key_ref: {e}"))?;
    let digests = PlanDigests::from_stored(&key_ref, &row.stored, &header, &members).map_err(|e| format!("{e:?}"))?;
    let plan = TriagePlan {
        plan_id: plan_id.clone(),
        account: row.account,
        provider_principal: row.provider_principal,
        grant_generation: unsigned("grant_generation", row.grant_generation)?,
        control_epoch: row.control_epoch,
        verb,
        rationale: row.rationale,
        minted_at: row.minted_at,
        expires_at: row.expires_at,
        members,
        admission_lane,
        approval_mode,
        coverage_generation: unsigned("coverage_generation", row.coverage_generation)?,
        backups_on,
        bypass_notice: row.bypass_notice,
        digests,
        key_ref,
    };
    plan.validate_shape().map_err(|e| format!("{e:?}"))?;
    Ok(plan)
}

/// Read one stored plan through the read boundary ([`plan_from_row`]). `conn` is a transaction
/// the caller holds, so the plan row and its member rows are one snapshot.
pub(crate) fn read_plan_in(
    conn: &rusqlite::Connection,
    plan_id: &crate::plan::PlanId,
) -> Result<Option<crate::plan::TriagePlan>, LogError> {
    let row = conn
        .query_row(
            &format!("SELECT {TRIAGE_PLAN_COLUMNS} FROM triage_plan WHERE plan_id = ?1;"),
            rusqlite::params![plan_id.0],
            |r| {
                Ok(RawPlanRow {
                    account: r.get(1)?,
                    provider_principal: r.get(2)?,
                    grant_generation: r.get(3)?,
                    control_epoch: r.get(4)?,
                    verb: r.get(5)?,
                    tier: r.get(6)?,
                    rationale: r.get(7)?,
                    minted_at: r.get(8)?,
                    expires_at: r.get(9)?,
                    member_count: r.get(10)?,
                    admission_lane: r.get(11)?,
                    bypass_config_generation: r.get(12)?,
                    approval_mode: r.get(13)?,
                    configured_k: r.get(14)?,
                    effective_k: r.get(15)?,
                    coverage_generation: r.get(16)?,
                    backups_on: r.get(17)?,
                    warning: r.get(18)?,
                    stored: crate::plan::StoredDigests {
                        set: r.get(19)?,
                        set_randomizer: r.get(20)?,
                        state: r.get(21)?,
                        state_randomizer: r.get(22)?,
                        presentation: r.get(23)?,
                        presentation_randomizer: r.get(24)?,
                        shape: r.get(25)?,
                        shape_randomizer: r.get(26)?,
                        sample_seed: r.get(27)?,
                        sample_seed_randomizer: r.get(28)?,
                        aggregate_view_randomizer: r.get(29)?,
                    },
                    key_ref_namespace: r.get(30)?,
                    key_ref_epoch: r.get(31)?,
                    bypass_notice: r.get(32)?,
                })
            },
        )
        .optional()
        .map_err(|e| LogError(format!("plan '{}' read: {e}", plan_id.0)))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let does_not_read_back = |why: String| LogError(format!("plan '{}' does not read back: {why}", plan_id.0));
    #[allow(clippy::type_complexity)]
    let raw_members: Vec<((String, String, String, String, Option<i64>, String, String, String), (String, Option<String>, Option<String>, Option<String>))> = conn
        .prepare(
            "SELECT message_ref, sender, subject, date, size, observed_state, forward_target,
                    sender_status, sender_local, sender_addr, sender_domain, sender_address
               FROM plan_member WHERE plan_id = ?1 ORDER BY message_ref;",
        )
        .and_then(|mut stmt| {
            stmt.query_map(rusqlite::params![plan_id.0], |r| {
                Ok((
                    (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(11)?),
                    (r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?),
                ))
            })?
            .collect()
        })
        .map_err(|e| LogError(format!("plan '{}' members read: {e}", plan_id.0)))?;
    let mut members = Vec::with_capacity(raw_members.len());
    for ((message_ref, sender, subject, date, size, observed_state, forward_target, sender_address), (sender_status, sender_local, sender_addr, sender_domain)) in raw_members {
        let atoms = |what: &str, text: &str| {
            crate::plan::decode_atom_map(text).ok_or_else(|| does_not_read_back(format!("member '{message_ref}' {what} is not the canonical atom map")))
        };
        // The local-part column and the structured sender are read strictly: an unknown status
        // token, or columns that disagree, is a member that does not read back.
        let sender_parse = crate::mailbox::SenderStatus::from_token(&sender_status)
            .and_then(|status| crate::plan::FrozenSender::from_columns(status, sender_local, sender_addr, sender_domain))
            .ok_or_else(|| does_not_read_back(format!("member '{message_ref}' sender '{sender_status}' is not a frozen sender")))?;
        members.push(crate::plan::PlanMember {
            display: crate::plan::FrozenDisplay {
                sender,
                sender_address,
                sender_parse,
                subject,
                date,
                size: size
                    .map(|s| u64::try_from(s).map_err(|_| does_not_read_back(format!("member '{message_ref}' size {s} is negative"))))
                    .transpose()?,
            },
            observed_state: atoms("observed_state", &observed_state)?,
            forward_target: atoms("forward_target", &forward_target)?,
            message_ref,
        });
    }
    plan_from_row(plan_id, row, members).map(Some).map_err(does_not_read_back)
}

/// Persist validated evidence: the one `approval_evidence` row a plan may carry.
pub(crate) fn insert_evidence_row(tx: &rusqlite::Transaction<'_>, e: &crate::plan::ApprovalEvidence) -> Result<(), LogError> {
    use crate::plan::Comprehension;
    let (shape_digest, sample_k, sample_members, bypass_config_generation) = match &e.comprehension {
        Comprehension::PerMember => (None, None, None, None),
        Comprehension::Aggregate { shape_digest, sample_k, sample_members } => {
            (Some(shape_digest.hex()), Some(i64::from(*sample_k)), Some(crate::plan::encode_sample(sample_members)), None)
        }
        Comprehension::Bypassed { bypass_config_generation } => (
            None,
            None,
            None,
            Some(i64::try_from(*bypass_config_generation).map_err(|_| LogError("insert evidence: bypass_config_generation exceeds i64".into()))?),
        ),
    };
    tx.execute(
        "INSERT INTO approval_evidence (plan_id, approver, approved_at, decision, view_digest, comprehension,
                                        shape_digest, sample_k, sample_members, bypass_config_generation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
        rusqlite::params![
            e.plan_id.0,
            e.approver,
            e.approved_at,
            e.decision.as_token(),
            e.view_digest.hex(),
            e.comprehension.as_token(),
            shape_digest,
            sample_k,
            sample_members,
            bypass_config_generation,
        ],
    )
    .map_err(|err| LogError(format!("insert approval_evidence: {err}")))?;
    Ok(())
}

/// The read boundary for stored evidence: the decision token, a canonical `approved_at`, a
/// strict tag, and the comprehension's companion columns present exactly when its token needs
/// them (the sample decoded strictly).
pub(crate) fn read_evidence_in(
    conn: &rusqlite::Connection,
    plan_id: &crate::plan::PlanId,
) -> Result<Option<crate::plan::ApprovalEvidence>, LogError> {
    use crate::plan::{ApprovalEvidence, Comprehension, Decision as PlanDecision};
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, String, String, String, Option<String>, Option<i64>, Option<String>, Option<i64>)> = conn
        .query_row(
            "SELECT approver, approved_at, decision, view_digest, comprehension, shape_digest, sample_k,
                    sample_members, bypass_config_generation
               FROM approval_evidence WHERE plan_id = ?1;",
            rusqlite::params![plan_id.0],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
        )
        .optional()
        .map_err(|e| LogError(format!("approval '{}' read: {e}", plan_id.0)))?;
    let Some((approver, approved_at, decision, view_digest, comprehension, shape_digest, sample_k, sample_members, bypass)) = row else {
        return Ok(None);
    };
    let refuse = |why: String| LogError(format!("approval '{}' does not read back: {why}", plan_id.0));
    if decision != PlanDecision::Approved.as_token() {
        return Err(refuse(format!("decision '{decision}'")));
    }
    if !crate::prestate::is_canonical_rfc3339_utc(&approved_at) {
        return Err(refuse("approved_at is not a canonical RFC-3339 UTC instant".into()));
    }
    let tag = |what: &str, hex: &str| crate::commitment::CommitmentTag::from_hex(hex).map_err(|e| refuse(format!("{what}: {e}")));
    let comprehension = match (comprehension.as_str(), shape_digest, sample_k, sample_members, bypass) {
        ("per_member", None, None, None, None) => Comprehension::PerMember,
        ("aggregate", Some(shape), Some(k), Some(members), None) => Comprehension::Aggregate {
            shape_digest: tag("shape_digest", &shape)?,
            sample_k: u32::try_from(k).map_err(|_| refuse(format!("sample_k {k} is not a u32")))?,
            sample_members: crate::plan::decode_sample(&members).ok_or_else(|| refuse("sample_members is not the canonical sample".into()))?,
        },
        ("bypassed", None, None, None, Some(g)) => Comprehension::Bypassed {
            bypass_config_generation: u64::try_from(g).map_err(|_| refuse(format!("bypass_config_generation {g} is negative")))?,
        },
        (token, ..) => return Err(refuse(format!("comprehension '{token}' with the wrong companion columns"))),
    };
    Ok(Some(ApprovalEvidence {
        plan_id: plan_id.clone(),
        approver,
        approved_at,
        view_digest: tag("view_digest", &view_digest)?,
        comprehension,
        decision: PlanDecision::Approved,
    }))
}
