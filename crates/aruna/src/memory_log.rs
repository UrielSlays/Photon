//! The in-memory `IntentLog` twin.

use std::collections::HashMap;

use crate::command::{action_message_ref, plan_child_key};
use crate::connector::{effect_witness_already_recorded, effect_witness_row};
use crate::intent::status_precondition_holds;
use crate::intent_log::{capture_binding_holds, key_rewrite_rejected, unknown_review_rollback};
use crate::keys::{reject_inadmissible_basis, reject_reserved_user_key, reject_unreadable_basis};
use crate::plan_store::{
    assemble_plan, build_approval_evidence, plan_spec_preflight, EpisodeWrite, PlanMemberFacts,
    PlanMintInputs,
};
use crate::settle::{retry_reason_of, settlement_proves_no_effect, verdict_mapping, LifecycleIntent};
use crate::sever::{
    canonical_witness_order, live_attempt_from, sever_disposition, validated_authority_ref,
    witness_member_set_json, SeverDisposition,
};
use crate::{
    AdjudicatedHistory, AdjudicationOutcome, AttemptClaim, CaptureBinding, CapturedJournal,
    CapturedPreState, Claim, ClaimOutcome, Command, ConnectorVerdict, DeadLetterWrite,
    EffectWitness, EffectWitnessRow, ExposureObligation, Intent, IntentLog, IntentStatus,
    JournalReplaceOutcome, LateAckOutcome, LiveAttempt, LogError, SendAuthOutcome, SettleOutcome,
    SettledLifecycle, SeverOutcome, SeverWitness, StatusPrecondition, StatusWrite, TransientCharge,
    UndoContext, UndoPairChild, UndoPairFlip, UnknownReviewReport, UnknownReviewRow,
};

#[cfg(doc)]
use crate::{prestate, SqliteIntentLog};

/// One in-memory `pre_state` row: the journal projection plus the fields PREPARE materializes
/// at insert time in SQL (`strftime(...)`, the bound epoch and generation), so the mirror stores
/// the same facts the durable table does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryJournal {
    /// The observed/touched/operands projection PREPARE was handed.
    pub row: crate::prestate::JournalRow,
    /// RFC 3339 UTC capture instant (`fetched_at`).
    pub fetched_at: String,
    /// `fetched_at` + [`prestate::UNDO_OFFER_SECONDS`], bound at capture.
    pub undo_offer_until: String,
    /// The control epoch PREPARE committed under (`captured_epoch`).
    pub captured_epoch: i64,
    /// The bound capture-mode generation (`mode_generation`).
    pub mode_generation: i64,
    /// Which capture this row is: 1 from PREPARE, incremented by every retry-requalification
    /// re-prepare (the durable table's `capture_generation`).
    pub capture_generation: u64,
}

/// In-memory `IntentLog` for tests and early development.
///
/// This log does not enroll in a `crate::writer_gate::WriterGate` (private, so not a link). The
/// gate is keyed on a store file's proven identity, and there is no file here; the same holds
/// for every in-memory sibling in this crate.
///
/// # Parity with [`SqliteIntentLog`]
///
/// This is what the fast tests and bus-level proofs exercise, so a surface the durable store
/// implements and this one does not is untested, and a divergence means the two answer the same
/// store differently. Every verb was swept against the durable implementation; the divergences
/// that remain are listed here with their reason:
///
/// * No `adjudication_record` mirror. The closed vocabularies (`AdjudicationReason`,
///   `AcceptedRisk`) are enforced by that table's `CHECK` constraints and guarded against the
///   enums by `attempt.rs`'s DDL guard test, so nothing this log stored would be checked by
///   anything. Everything the engine reads afterwards (fact, status, obligations,
///   annotations) is mirrored. (See [`IntentLog::adjudicate`]'s impl.)
/// * No config ledger. The bound act is the compiled generation-1 default `record` binds, so
///   the config existence check cannot fail here. (See [`IntentLog::prepare`]'s impl.)
/// * No boot quarantine or open-time head verification. This log has no reopen, so there is no
///   crashed store to classify, no `attempt_head` projection to re-verify (the fold is the
///   only authority here), and no orphan-chain probe.
/// * No `intent_id`. An attempt's owner on this log is the idempotency key; the grammar reads
///   only the owner's identity and immutability, never its shape.
/// * Annotations carry no `created_at`. Nothing here compares annotation instants; obligation
///   retirement instants, which the exposure-materialization window does compare, are mirrored.
/// * No ingest read side. The plan mint freezes members from a header mirror and a placement
///   mirror that only `#[cfg(test)]` seams fill, so outside the crate's own tests every member
///   is unknown and every mint refuses `UnknownMember`. The plans, evidence and the
///   sticky-clock latch the plan paths advance are mirrored; the durable transaction's rollback
///   is mirrored by restoring the latch when a mint or approval refuses after reading the
///   clock.
pub struct InMemoryIntentLog {
    entries: HashMap<String, Intent>,
    next_seq: u64,
    /// The `pre_state` mirror, keyed by idempotency key (this log mints no `intent_id`). Its
    /// existence is the PREPARE phase; there is no `prepared` flag here either.
    pub(crate) pre_state: HashMap<String, InMemoryJournal>,
    /// The `time_high_water` latch mirror: the maximum wall clock any undo evaluation has seen.
    /// Empty string = never evaluated, which sorts below every RFC 3339 instant (the same
    /// `MAX(now, max_seen)` the SQL does).
    pub(crate) time_high_water: String,
    /// The `pre_state_tombstone` mirror (deletion provenance). Dormant: nothing in the engine
    /// writes it, and tests seed it by hand as the SQLite arm does.
    tombstones: std::collections::BTreeSet<String>,
    /// The `attempt_fact` mirror: the whole ledger in append order. An attempt's owner here is
    /// the idempotency key (this log mints no `intent_id`); the grammar reads only its identity and
    /// immutability.
    pub(crate) attempt_facts: Vec<crate::attempt::Fact>,
    /// Monotonic source of opaque attempt ids (SQLite uses `randomblob(16)`).
    next_attempt: u64,
    /// The `control_epoch` singleton mirror, seeded 1 as the durable bootstrap does and written
    /// only by [`IntentLog::sever`].
    control_epoch: i64,
    /// The `intents.admitted_control_epoch` column, mirrored as a side map because `Intent` is the
    /// public row shape and the durable log does not expose this column on it either. The binding
    /// is required: without it `ClaimOutcome::EpochFenced` was unreachable here, and an operation
    /// that survives a sever active (an `ISSUED_OR_UNKNOWN` member, which a sever may not close)
    /// was handed dispatch ownership by the mirror that the durable store fences.
    admitted_epochs: HashMap<String, i64>,
    /// The `sever_witness` mirror: one verified witness per sever, in sever order.
    sever_witnesses: Vec<SeverWitness>,
    /// The `exposure_obligation` mirror. It makes the exposure check on this log real rather than
    /// vacuous: a fake whose check can never refuse would let bus-level tests pass a check the
    /// durable engine would have refused.
    exposure_obligations: Vec<InMemoryObligation>,
    /// The `adjudication_annotation` mirror, in append order.
    adjudication_annotations: Vec<InMemoryAnnotation>,
    /// Monotonic source of opaque adjudication row ids (SQLite uses `randomblob(16)`).
    next_adjudication: u64,
    /// The same, for exposure obligation row ids (the refusal surfaces one).
    next_obligation: u64,
    /// The current capacity bounds this fake admits against (mirrors the durable `engine_config`
    /// answer "the act named by the latest activation"). Starts at [`crate::capacity::DEFAULT`],
    /// the first-run answer the durable store has before any capacity act.
    capacity_current: crate::capacity::CapacityConfig,
    /// The newest not-yet-activated capacity config, if [`Self::record_capacity_config`] was
    /// given one that did not fit: `(generation, bounds)`, mirroring
    /// [`crate::capacity::EffectiveBounds::pending`]. A releasing status write that makes the
    /// pending bounds fit promotes them to current via `activate_pending_if_fits`, the twin of the
    /// SQL trigger. (Activating only at the next `record_capacity_config` let this fake admit an
    /// operation the durable engine refuses, the weaker-gate failure the `exposure_obligations`
    /// doc names as what a fake must never do.)
    capacity_pending: Option<(i64, crate::capacity::CapacityConfig)>,
    /// Monotonic generation counter for [`Self::capacity_pending`]. This log has no real
    /// `engine_config` ledger, so the number only orders. Knob acts advance the same counter, so
    /// capacity and knob generations interleave as `engine_config.generation` does (seeded 1, the
    /// durable first-run act's generation, so a first knob act lands at 2 on both stores).
    capacity_generation: i64,
    /// The knob-act half of the `engine_config` mirror: every [`IntentLog::record_knob_act`] as
    /// `(generation, kind, payload)`, append-only. Held as the payload rather than the typed act so
    /// [`IntentLog::knob_state`] reads it through the same strict readers the durable store does; a
    /// head act SQLite would refuse, this twin refuses too.
    knob_acts: Vec<(u64, &'static str, String)>,
    /// The `commitment_key_registry` mirror: the root key's registered fingerprint, write-once
    /// like the durable row.
    commitment_key_fingerprint: Option<String>,
    /// The `intents.effect_label_vector` / `ripple_verdict` / `ripple_unexpected` mirror, keyed by
    /// idempotency key, as a side map for the reason `admitted_epochs` gives. An entry exists
    /// exactly when the durable row holds a non-NULL `effect_label_vector`; write-once like the
    /// durable guard.
    effect_witnesses: HashMap<String, EffectWitnessRow>,
    /// The read side a plan mint freezes from, keyed `(account, message_ref)`: the
    /// `message_header` mirror's display facts and the `message_placement` mirror's placement. This
    /// log models no ingest, so tests seed both (`seed_header_for_test` /
    /// `seed_placement_for_test`); a member missing either is unknown, as SQLite's JOIN answers.
    plan_headers: std::collections::BTreeMap<(String, String), PlanHeaderMirror>,
    plan_placements: std::collections::BTreeMap<(String, String), crate::read_model::Placement>,
    /// The `triage_plan` and `plan_member` mirror: each minted plan, write-once.
    pub(crate) plans: std::collections::BTreeMap<crate::plan::PlanId, crate::plan::TriagePlan>,
    /// The `approval_evidence` mirror: one per plan, write-once.
    approvals: std::collections::BTreeMap<crate::plan::PlanId, crate::plan::ApprovalEvidence>,
    /// The `execution_episode` mirror: one head per plan, written after the start only through
    /// [`InMemoryIntentLog::write_episode`] (the generation compare-and-set).
    pub(crate) episodes: std::collections::BTreeMap<crate::plan::PlanId, crate::episode::Episode>,
    /// The `episode_journal` mirror: one row per episode write, append-only.
    pub(crate) episode_journal: Vec<InMemoryEpisodeJournalRow>,
    /// Monotonic source of episode ids (SQLite mints them with `mint_opaque_id`).
    next_episode: u64,
}

/// One `message_header` mirror row as the plan mint reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanHeaderMirror {
    from_addr: String,
    /// `message_header.from_status` / `from_domain`, derived from `from_addr` as the durable
    /// write path derives them (`mailbox::sender_facts`).
    from_status: crate::mailbox::SenderStatus,
    from_domain: Option<String>,
    from_name: String,
    subject: String,
    received_at_ms: i64,
}

/// One `exposure_obligation` row as this log holds it: the exposure key, its contributor, and
/// when it retired.
///
/// Retirement is an instant, not a boolean. The mirror used to keep a boolean because nothing
/// here compared retirement instants, which was the defect: the durable exposure scan is
/// windowed on `retired_at` against the applying attempt's authorization instant (the non-bleed
/// rule), so a mirror with no instant could not express the window and annotated across settled
/// episodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryObligation {
    /// The engine-minted opaque row id, the durable table's primary key. Mirrored because it is
    /// what an exposure refusal surfaces; without it the mirror could not answer the
    /// caller-facing half of the check's decision.
    pub obligation_id: String,
    /// The account/provider scope as the frozen basis states it (the provider-native resource
    /// key): durable audit scope, never a lookup key.
    pub provider_scope: String,
    /// The primitive atom identity, already fully provider-scoped, so the whole identity every
    /// lookup here keys on.
    pub atom_key: String,
    /// The effect direction the contributor's frozen basis named.
    pub direction: crate::attempt::ExposureDirection,
    /// The episode generation for this atom.
    pub generation: i64,
    /// The attempt whose unresolved history created it.
    pub contributor_attempt_id: String,
    /// When the contributor's historical axis resolved (`None` = still unresolved), as the same
    /// canonical RFC 3339 UTC text the durable `retired_at` column holds.
    pub retired_at: Option<String>,
}

impl InMemoryObligation {
    /// Has this obligation retired? The predicate every check asks, so the `Option` is read one
    /// way only.
    pub fn retired(&self) -> bool {
        self.retired_at.is_some()
    }
}

/// One `adjudication_annotation` row as this log holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryAnnotation {
    /// The adjudication record it hangs on.
    pub adjudication_id: String,
    /// Which of the closed annotation kinds.
    pub kind: crate::attempt::AnomalyKind,
    /// The other attempt this annotation is about, when the kind carries one.
    pub related_attempt_id: Option<String>,
    /// The content-free exposure atom identity, when the kind carries one.
    pub atom_key: Option<String>,
}

impl Default for InMemoryIntentLog {
    /// Hand-written rather than derived because `control_epoch` is seeded 1 and a derived
    /// `Default` would seed it 0; a mirror whose epoch check starts below the durable store's
    /// answers a different question.
    fn default() -> Self {
        InMemoryIntentLog {
            entries: HashMap::new(),
            next_seq: 0,
            pre_state: HashMap::new(),
            time_high_water: String::new(),
            tombstones: std::collections::BTreeSet::new(),
            attempt_facts: Vec::new(),
            next_attempt: 0,
            control_epoch: 1,
            admitted_epochs: HashMap::new(),
            sever_witnesses: Vec::new(),
            exposure_obligations: Vec::new(),
            adjudication_annotations: Vec::new(),
            next_adjudication: 0,
            next_obligation: 0,
            capacity_current: crate::capacity::DEFAULT,
            capacity_pending: None,
            capacity_generation: 1,
            knob_acts: Vec::new(),
            commitment_key_fingerprint: None,
            effect_witnesses: HashMap::new(),
            plan_headers: std::collections::BTreeMap::new(),
            plan_placements: std::collections::BTreeMap::new(),
            plans: std::collections::BTreeMap::new(),
            approvals: std::collections::BTreeMap::new(),
            episodes: std::collections::BTreeMap::new(),
            episode_journal: Vec::new(),
            next_episode: 0,
        }
    }
}

impl InMemoryIntentLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test seam: append a raw knob-act row (any payload, readable or not) at the next
    /// generation, the twin of a direct `INSERT INTO engine_config`.
    /// [`IntentLog::record_knob_act`] re-reads every act through its kind's reader first
    /// (`KnobAct::checked_payload`), so a malformed head act enters only through here.
    #[cfg(test)]
    pub(crate) fn append_raw_knob_act_for_test(&mut self, kind: &'static str, payload: &str) -> u64 {
        self.append_knob_row(kind, payload.to_string())
    }

    /// Test seam: seed a `message_header` mirror row for the plan mint, the twin of an ingested
    /// header (this log models no ingest, so the text is taken as given). The sender status and
    /// domain are derived from `from_addr` as the durable row's write path derives them
    /// (`message_header::upsert_header_row` and `mailbox::sender_facts`).
    #[cfg(test)]
    pub(crate) fn seed_header_for_test(&mut self, account: &str, message_ref: &str, from_addr: &str, from_name: &str, subject: &str, received_at_ms: i64) {
        let (from_status, from_domain) = crate::mailbox::sender_facts(from_addr);
        self.plan_headers.insert(
            (account.to_string(), message_ref.to_string()),
            PlanHeaderMirror {
                from_addr: from_addr.to_string(),
                from_status,
                from_domain,
                from_name: from_name.to_string(),
                subject: subject.to_string(),
                received_at_ms,
            },
        );
    }

    /// Test seam: seed a `message_placement` mirror row for the plan mint.
    #[cfg(test)]
    pub(crate) fn seed_placement_for_test(&mut self, account: &str, message_ref: &str, placement: crate::read_model::Placement) {
        self.plan_placements.insert((account.to_string(), message_ref.to_string()), placement);
    }

    /// The durable `plan_child_admission`, mirrored over this twin's `plans` / `approvals` maps and
    /// its `control_epoch` / sticky clock: the same checks in the same order with the same refusal
    /// values. As in the durable arm, the expiry check latches the clock and nothing else is
    /// written.
    fn plan_child_admission(
        &mut self,
        command: &Command,
        link: &crate::plan::PlanChildLink,
    ) -> Result<Option<crate::plan::PlanChildRefusal>, LogError> {
        use crate::plan::PlanChildRefusal as R;
        if !command.action.risk_tier().requires_plan() {
            return Ok(Some(R::NotARedVerb));
        }
        let Some(plan) = self.plans.get(&link.plan_id) else {
            return Ok(Some(R::NoPlan));
        };
        if plan.account != command.account {
            return Ok(Some(R::AccountMismatch));
        }
        if plan.verb.action(&link.member_ref) != command.action {
            return Ok(Some(R::VerbMismatch));
        }
        if command.idempotency_key != plan_child_key(&plan.account, link) {
            return Ok(Some(R::KeyMismatch));
        }
        if !self.approvals.contains_key(&link.plan_id) {
            return Ok(Some(R::NotApproved));
        }
        let Some(episode) = self.episodes.get(&link.plan_id) else {
            return Ok(Some(R::NoEpisode));
        };
        let token = episode.status.token();
        if token != crate::episode::EpisodeStatusToken::Active {
            return Ok(Some(R::EpisodeNotActive(token)));
        }
        if episode.ready_at.is_none() {
            return Ok(Some(R::NotReady));
        }
        if plan.member(&link.member_ref).is_none() {
            return Ok(Some(R::NotAMember(link.member_ref.clone())));
        }
        if plan.control_epoch != self.control_epoch {
            return Ok(Some(R::EpochMismatch { plan: plan.control_epoch, current: self.control_epoch }));
        }
        let expires_at = plan.expires_at.clone();
        if !crate::prestate::is_canonical_rfc3339_utc(&expires_at) {
            return Err(LogError(format!("plan child admission: plan '{}' has a non-canonical expires_at", link.plan_id.0)));
        }
        let now = self.sticky_effective_now("record")?;
        if expires_at.as_str() <= now.as_str() {
            return Ok(Some(R::Expired { expires_at, effective_now: now }));
        }
        Ok(None)
    }

    /// The durable `plan_send_admission`, mirrored over this twin's maps: the same rows in the
    /// same order with the same refusal values. As in the durable arm, its one write is row 4's
    /// sticky-clock latch advance.
    fn plan_send_admission(
        &mut self,
        link: &crate::plan::PlanChildLink,
        idempotency_key: &str,
        grant: &crate::plan::GrantVerdict,
        account_key: &crate::commitment::CommitmentKey,
        capture: CaptureBinding,
    ) -> Result<Option<crate::plan::PlanSendRefusal>, LogError> {
        use crate::episode::EpisodeStatusToken as T;
        use crate::plan::PlanSendRefusal as R;
        // 1.
        let Some((status, ready)) = self.episodes.get(&link.plan_id).map(|e| (e.status.token(), e.ready_at.is_some())) else {
            return Ok(Some(R::NoEpisode));
        };
        match status {
            T::Active => {}
            T::Paused => return Ok(Some(R::EpisodeHeld(status))),
            T::Cancelled | T::Completed | T::Invalidated => return Ok(Some(R::EpisodeClosed(status))),
        }
        if !ready {
            return Ok(Some(R::NotReady));
        }
        // 1b.
        if let crate::plan::GrantVerdict::Refused(crate::plan::GrantDenial::Unavailable) = grant {
            return Ok(Some(R::GrantRetired(crate::plan::GrantDenial::Unavailable)));
        }
        // 2.
        let plan = self
            .plan(&link.plan_id)?
            .ok_or_else(|| LogError(format!("authorize_send plan admission: plan '{}' vanished under its child", link.plan_id.0)))?;
        // 3.
        if plan.control_epoch != self.control_epoch {
            return Ok(Some(R::PlanEpochMismatch { plan: plan.control_epoch, current: self.control_epoch }));
        }
        // 4.
        let now = self.plan_clock(&link.plan_id, &plan.expires_at, "authorize_send")?;
        if plan.expires_at.as_str() <= now.as_str() {
            return Ok(Some(R::Expired { expires_at: plan.expires_at.clone(), effective_now: now }));
        }
        // 5.
        let Some(member) = plan.member(&link.member_ref) else {
            return Ok(Some(R::NotAMember));
        };
        // 6.
        let Some(evidence) = self.approvals.get(&link.plan_id) else {
            return Ok(Some(R::EvidenceAbsent));
        };
        let knobs = self
            .knob_state_typed()
            .map_err(|e| LogError(format!("authorize_send plan admission: knob state: {e}")))?;
        if let Err(refusal) = crate::plan::validate_evidence(account_key, &plan, evidence, knobs.red_bypass.generation) {
            return Ok(Some(R::EvidenceInvalid(refusal)));
        }
        // 6b.
        if matches!(plan.admission_lane, crate::plan::AdmissionLane::Bypassed { .. }) && !plan.backups_on && plan.bypass_notice.is_none() {
            return Ok(Some(R::BypassNoticeAbsent));
        }
        // 7.
        if let crate::plan::GrantVerdict::Refused(refusal) = grant {
            return Ok(Some(R::GrantRetired(*refusal)));
        }
        // 8.
        if plan.coverage_generation != knobs.backups.generation {
            return Ok(Some(R::CoverageDiverged { plan: plan.coverage_generation, current: knobs.backups.generation }));
        }
        // 9.
        if plan.backups_on {
            return Ok(Some(R::SnapshotAbsent));
        }
        // 10.
        if capture == CaptureBinding::NoJournalRow {
            return Ok(Some(R::CaptureRequired));
        }
        let journal = self
            .pre_state
            .get(idempotency_key)
            .ok_or_else(|| LogError(format!("authorize_send plan admission: '{idempotency_key}' has no capture under a Generation binding")))?;
        let captured: std::collections::BTreeMap<String, bool> = serde_json::from_str(&journal.row.touched_atom)
            .map_err(|e| LogError(format!("authorize_send plan admission: capture is not a Boolean atom map: {e}")))?;
        let diff = crate::plan::member_state_diff(&member.observed_state, &captured);
        if !diff.is_empty() {
            return Ok(Some(R::StateDiverged { diff }));
        }
        Ok(None)
    }

    /// The episode write on the twin, mirroring the durable `write_episode_in`: a compare-and-set
    /// on the head's generation (a head no longer at `expected` answers `GenerationConflict` and
    /// nothing changes), then the head update and one journal row. Returns the new generation.
    pub(crate) fn write_episode(&mut self, plan_id: &crate::plan::PlanId, expected: u64, w: &EpisodeWrite) -> Result<u64, crate::episode::EpisodeRefusal> {
        use crate::episode::EpisodeRefusal as R;
        let Some(head) = self.episodes.get_mut(plan_id) else {
            return Err(R::NoEpisode);
        };
        if head.generation != expected {
            return Err(R::GenerationConflict { expected, found: head.generation });
        }
        head.status = w.status.clone();
        head.ready_at = w.ready_at.clone();
        head.completed_at = w.completed_at.clone();
        head.generation = expected + 1;
        self.episode_journal.push(InMemoryEpisodeJournalRow {
            plan_id: plan_id.clone(),
            generation: expected + 1,
            status: w.status.token(),
            reason: w.status.reason_json(),
            event: w.event,
            at: w.at.clone(),
        });
        Ok(expected + 1)
    }

    /// The durable `send_authorized_children_in`, mirrored: how many of the plan's children (rows
    /// whose link names this plan) own a `send_authorized` fact. This twin's fact owner is the
    /// idempotency key.
    fn send_authorized_children(&self, plan_id: &crate::plan::PlanId) -> u64 {
        self.attempt_facts
            .iter()
            .filter(|f| f.kind == crate::attempt::FactKind::SendAuthorized)
            .filter(|f| {
                self.entries
                    .get(&f.operation_id)
                    .and_then(|i| i.command.plan_child.as_ref())
                    .is_some_and(|l| l.plan_id == *plan_id)
            })
            .map(|f| f.operation_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u64
    }

    /// The plan-expiry clock on the twin (the durable `plan_clock_in`, mirrored): the stored
    /// `expires_at` must be canonical, since it is compared lexicographically, and the answer is
    /// the twin's sticky clock.
    fn plan_clock(&mut self, plan_id: &crate::plan::PlanId, expires_at: &str, door: &str) -> Result<String, LogError> {
        if !crate::prestate::is_canonical_rfc3339_utc(expires_at) {
            return Err(LogError(format!("{door}: plan '{}' has a non-canonical expires_at", plan_id.0)));
        }
        self.sticky_effective_now(door)
    }

    /// The sticky clock, mirrored: the twin's one helper, shared by `undo_context` and the plan
    /// paths. The latch is validated as stored (the empty initial latch is "absent", not corrupt;
    /// a non-canonical one refuses and is never repaired), `effective_now = max(now, latch)`, the
    /// governing value is re-checked, and the max is latched back.
    fn sticky_effective_now(&mut self, door: &str) -> Result<String, LogError> {
        // Validate the latch on the raw stored value before it enters any comparison, as the SQLite
        // twin does: a latch sorting low loses the max and would otherwise be silently overwritten,
        // taking the sticky-expiry evidence with it. The empty initial latch is "absent", not corrupt.
        if !self.time_high_water.is_empty()
            && !crate::prestate::is_canonical_rfc3339_utc(&self.time_high_water)
        {
            return Err(LogError(format!(
                "{door}: non-canonical time high-water latch"
            )));
        }
        // The sticky clock: `effective_now = max(now, latch)`, latched back. The empty initial latch
        // sorts below every RFC 3339 instant, so the first evaluation takes `now`, as
        // `MAX(strftime(...), COALESCE(..., ''))` does.
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let effective_now = if now > self.time_high_water {
            now
        } else {
            self.time_high_water.clone()
        };
        // The same boundary for the clock. The latch folds into `effective_now`, so a corrupt latch
        // that governs (won the max, the only direction that can move the decision) surfaces here:
        // refuse, never silently repair, never persist.
        if !crate::prestate::is_canonical_rfc3339_utc(&effective_now) {
            return Err(LogError(format!(
                "{door}: non-canonical time high-water latch"
            )));
        }
        self.time_high_water = effective_now.clone();
        Ok(effective_now)
    }

    /// The knob state with the strict reader's own error: `knob_state` maps it to a [`LogError`],
    /// the plan mint to `PlanStoreError::Knob`.
    fn knob_state_typed(&self) -> Result<crate::config_knobs::KnobState, crate::config_knobs::KnobError> {
        use crate::config_knobs::{KnobState, KIND_APPROVAL_MODE, KIND_BACKUPS, KIND_RED_BYPASS};
        // The head act of a kind is its highest generation (the durable `ORDER BY generation DESC
        // LIMIT 1`), never "the first one recorded".
        let head = |kind: &str| {
            self.knob_acts
                .iter()
                .filter(|(_, k, _)| *k == kind)
                .max_by_key(|(generation, _, _)| *generation)
                .map(|(generation, _, payload)| (*generation, payload.as_str()))
        };
        KnobState::from_head_acts(head(KIND_APPROVAL_MODE), head(KIND_BACKUPS), head(KIND_RED_BYPASS))
    }

    /// The members a mint asked for, read from the mirrors (header and placement,
    /// account-scoped), deduplicated and in ref order, as the durable JOIN answers.
    fn plan_member_facts(&self, account: &str, member_refs: &[String]) -> Result<Vec<PlanMemberFacts>, crate::plan::PlanStoreError> {
        let unique: std::collections::BTreeSet<&String> = member_refs.iter().collect();
        unique
            .into_iter()
            .map(|message_ref| {
                let key = (account.to_string(), message_ref.clone());
                match (self.plan_headers.get(&key), self.plan_placements.get(&key)) {
                    (Some(h), Some(placement)) => Ok(PlanMemberFacts {
                        message_ref: message_ref.clone(),
                        from_addr: h.from_addr.clone(),
                        from_status: h.from_status,
                        from_domain: h.from_domain.clone(),
                        from_name: h.from_name.clone(),
                        subject: h.subject.clone(),
                        received_at_ms: h.received_at_ms,
                        placement: *placement,
                    }),
                    _ => Err(crate::plan::PlanStoreError::UnknownMember(message_ref.clone())),
                }
            })
            .collect()
    }

    /// The single append into the knob mirror, used by [`IntentLog::record_knob_act`] and the test
    /// seam above: advance the shared ledger generation, push, return it.
    fn append_knob_row(&mut self, kind: &'static str, payload: String) -> u64 {
        self.capacity_generation += 1;
        // Seeded 1 and only incremented, so the counter is positive and the cast is lossless.
        let generation = self.capacity_generation as u64;
        self.knob_acts.push((generation, kind, payload));
        generation
    }

    /// This log's `sever_witness` mirror, for test inspection (the twin of reading the durable
    /// table), never a second authority.
    pub fn sever_witnesses(&self) -> &[SeverWitness] {
        &self.sever_witnesses
    }

    /// Inspect this log's `pre_state` mirror row for an intent, if PREPARE inserted one: the
    /// twin of joining `pre_state` to `intents`, for tests, never a phase flag (the row's existence
    /// is the phase; see [`IntentLog::prepared`]).
    pub fn journal(&self, idempotency_key: &str) -> Option<&InMemoryJournal> {
        self.pre_state.get(idempotency_key)
    }

    /// Seed an expiry tombstone for an intent. Destruction is dormant, so no engine path writes
    /// one; this is the twin of the SQLite tests' hand-INSERT and lets the
    /// `Expired { tombstoned: true }` arm be driven on this log too.
    pub fn seed_tombstone(&mut self, idempotency_key: &str) {
        self.tombstones.insert(idempotency_key.to_string());
    }

    /// Back-date one contributor's already-retired obligations: the twin of the SQLite tests'
    /// hand-`UPDATE exposure_obligation SET retired_at = ...`. `created_at` is RFC 3339 seconds, so
    /// two events inside one test share a timestamp and the "episode settled before this attempt
    /// was authorized" ordering cannot be raced against the wall clock. It seeds nothing that was
    /// not already retired: it moves an instant, never resolves an obligation.
    pub fn seed_obligation_retirement(&mut self, contributor_attempt_id: &str, retired_at: &str) {
        for obligation in self
            .exposure_obligations
            .iter_mut()
            .filter(|o| o.retired() && o.contributor_attempt_id == contributor_attempt_id)
        {
            obligation.retired_at = Some(retired_at.to_string());
        }
    }

    /// Fold one stored attempt's chain through the pure core. A chain that does not fold is a
    /// `LogError`: the fold is the authority, the mirror is not.
    fn fold_stored_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<crate::attempt::DerivedState, LogError> {
        self.fold_stored_attempt_if_present(attempt_id)?
            .ok_or_else(|| {
                LogError(format!(
                    "attempt '{attempt_id}' does not fold: {}",
                    crate::attempt::FoldDefect::EmptyChain
                ))
            })
    }

    /// The mirror of the durable [`fold_stored_attempt_if_present`]: `Ok(None)` = the attempt does
    /// not exist, every `Err` = the chain is malformed. One rule in two stores, so the two claim
    /// paths answer a corrupt lineage identically.
    fn fold_stored_attempt_if_present(
        &self,
        attempt_id: &str,
    ) -> Result<Option<crate::attempt::DerivedState>, LogError> {
        let chain: Vec<crate::attempt::Fact> = self
            .attempt_facts
            .iter()
            .filter(|f| f.attempt_id == attempt_id)
            .cloned()
            .collect();
        if chain.is_empty() {
            return Ok(None);
        }
        crate::attempt::fold(&chain)
            .map(Some)
            .map_err(|d| LogError(format!("attempt '{attempt_id}' does not fold: {d}")))
    }

    /// This log's `attempt_fact` mirror, for test inspection (the twin of reading the durable
    /// table), never a second authority.
    pub fn attempt_facts(&self) -> &[crate::attempt::Fact] {
        &self.attempt_facts
    }

    /// This log's `exposure_obligation` mirror, in creation order.
    pub fn exposure_obligations(&self) -> &[InMemoryObligation] {
        &self.exposure_obligations
    }

    /// This log's `adjudication_annotation` mirror (durable notices), in append order.
    pub fn adjudication_annotations(&self) -> &[InMemoryAnnotation] {
        &self.adjudication_annotations
    }

    /// The generation for a new obligation, by the rule the durable path applies
    /// (`obligation_generation`): a live episode is joined, a settled one is succeeded.
    fn obligation_generation(&self, atom_key: &str) -> i64 {
        let live = self
            .exposure_obligations
            .iter()
            .filter(|o| !o.retired() && o.atom_key == atom_key)
            .map(|o| o.generation)
            .max();
        match live {
            Some(generation) => generation,
            None => {
                self.exposure_obligations
                    .iter()
                    .filter(|o| o.atom_key == atom_key)
                    .map(|o| o.generation)
                    .max()
                    .unwrap_or(0)
                    + 1
            }
        }
    }

    /// The multi-contributor exposure-materialization trace, mirrored clause for clause from
    /// `note_exposure_materialization`. One copy, called from both orders (the settling
    /// `ACK_APPLIED` and the resolving `LATE_ACK_APPLIED`), because which of the two effects
    /// resolves first must not decide whether a notice exists.
    ///
    /// The window matters: contributors are scoped to obligations still live at this attempt's own
    /// effect-release boundary (`retired_at IS NULL OR retired_at >= <this attempt's
    /// SEND_AUTHORIZED>`), the non-bleed rule that a later independent episode on an atom is a new
    /// generation that old state neither authorizes nor contaminates. Without it, an ordinary
    /// operation on a long-settled message minted a false `exposure-materialized` notice against a
    /// stranger's adjudication record.
    fn note_exposure_materialization(
        &mut self,
        attempt_id: &str,
        exposure_key: &crate::attempt::ExposureKey,
        own_adjudication_id: Option<&str>,
    ) -> Result<u64, LogError> {
        use crate::attempt::{AnomalyKind, FactKind};
        // Read from the chain, never predicted: an attempt reaching here has a definitive APPLIED,
        // which the grammar admits only after a `SEND_AUTHORIZED`.
        let authorized_at = self
            .attempt_facts
            .iter()
            .find(|f| f.attempt_id == attempt_id && f.kind == FactKind::SendAuthorized)
            .map(|f| f.created_at.clone())
            .ok_or_else(|| {
                LogError(format!(
                    "materialization scan: attempt '{attempt_id}' applied without a \
                     SEND_AUTHORIZED fact to date its exposure window by"
                ))
            })?;
        // Annotations are collected before any is written: every fold below borrows `self`, and a
        // contributor the scan cannot resolve is a store defect that must leave nothing half-written.
        let mut pending: Vec<InMemoryAnnotation> = Vec::new();
        let mut notices = 0u64;
        for atom in &exposure_key.atoms {
            let mut contributors: Vec<String> = Vec::new();
            for obligation in self.exposure_obligations.iter().filter(|o| {
                o.atom_key == atom.atom_key
                    && o.contributor_attempt_id != attempt_id
                    && o.retired_at
                        .as_ref()
                        .is_none_or(|retired| *retired >= authorized_at)
            }) {
                if !contributors.contains(&obligation.contributor_attempt_id) {
                    contributors.push(obligation.contributor_attempt_id.clone());
                }
            }
            for other in contributors {
                let state = self.fold_stored_attempt(&other)?;
                // An obligation exists only where an adjudication wrote one, so a contributor with no
                // record is a store defect, not a case to skip quietly.
                let Some(record) = state.adjudication_id.clone() else {
                    return Err(LogError(format!(
                        "exposure obligation names contributor attempt '{other}', which holds \
                         no adjudication record"
                    )));
                };
                // Proven no effect is not "unresolved": no notice at all is the truth.
                if state.late_ack == Some(FactKind::LateAckRefusedNoEffect) {
                    continue;
                }
                let kind = if state.late_ack == Some(FactKind::LateAckApplied) {
                    AnomalyKind::ExposureMaterialized
                } else {
                    AnomalyKind::AppliedOverUnresolved
                };
                pending.push(InMemoryAnnotation {
                    adjudication_id: record,
                    kind,
                    related_attempt_id: Some(attempt_id.to_string()),
                    atom_key: Some(atom.atom_key.clone()),
                });
                if kind == AnomalyKind::ExposureMaterialized {
                    notices += 1;
                }
            }
        }
        // The other order: a same-atom effect applied while this exposure was unresolved, and this
        // resolution makes it two applied effects.
        if let Some(record) = own_adjudication_id {
            let half = self
                .adjudication_annotations
                .iter()
                .chain(pending.iter())
                .any(|a| {
                    a.adjudication_id == record && a.kind == AnomalyKind::AppliedOverUnresolved
                });
            if half {
                pending.push(InMemoryAnnotation {
                    adjudication_id: record.to_string(),
                    kind: AnomalyKind::ExposureMaterialized,
                    related_attempt_id: Some(attempt_id.to_string()),
                    atom_key: None,
                });
                notices += 1;
            }
        }
        self.adjudication_annotations.extend(pending);
        Ok(notices)
    }

    /// The adjudication audit edge, mirrored from `link_supersessions`: link every adjudicated
    /// attempt whose unretired exposure this newly admitted operation overlaps to that operation,
    /// as its first successor.
    ///
    /// It returns the facts to append rather than appending them, so the caller makes the edge and
    /// the admission one write here too: the durable guarantee is that a store never holds an
    /// overlapping successor whose edge is missing, so a failure must leave the entry uninserted.
    /// Nothing is spent when nothing overlaps; the empty case returns before the clock is read.
    fn supersession_edges(
        &self,
        successor_operation_id: &str,
        exposure_key: &crate::attempt::ExposureKey,
    ) -> Result<Vec<crate::attempt::Fact>, LogError> {
        use crate::attempt::{Fact, FactKind, FactPayload};
        let mut candidates: Vec<String> = Vec::new();
        for atom in &exposure_key.atoms {
            for obligation in self
                .exposure_obligations
                .iter()
                .filter(|o| !o.retired() && o.atom_key == atom.atom_key)
            {
                if !candidates.contains(&obligation.contributor_attempt_id) {
                    candidates.push(obligation.contributor_attempt_id.clone());
                }
            }
        }
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let created_at = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("admission clock: {e}")))?
            .value;
        let mut edges: Vec<Fact> = Vec::new();
        for attempt_id in candidates {
            let state = self.fold_stored_attempt(&attempt_id)?;
            // Only on an adjudicated attempt, and only for the first successor.
            if state.adjudication_id.is_none() || state.superseded_by.is_some() {
                continue;
            }
            let Some(claim) = state.claim.as_ref() else {
                return Err(LogError(format!(
                    "supersession: attempt '{attempt_id}' has no CLAIM"
                )));
            };
            let fact = Fact {
                operation_id: claim.operation_id.clone(),
                attempt_id: attempt_id.clone(),
                revision: state.current_revision + 1,
                kind: FactKind::SupersededBy,
                basis_epoch: self.control_epoch,
                created_at: created_at.clone(),
                payload: FactPayload::SupersededBy {
                    successor_operation_id: successor_operation_id.to_string(),
                },
                prior_revision: Some(state.current_revision),
            };
            // The grammar cannot refuse this: the state was just folded and satisfies the whitelist. A
            // refusal means the fold and the grammar disagree; fail explicitly rather than admit a
            // successor whose audit edge silently did not happen.
            if let Err(refusal) = crate::attempt::append_legal(&state, &fact) {
                return Err(LogError(format!(
                    "supersession: the audit edge on attempt '{attempt_id}' was refused by the \
                     grammar: {refusal}"
                )));
            }
            edges.push(fact);
        }
        Ok(edges)
    }

    /// Write a terminal status without overwriting one another authority already wrote, the
    /// mirror of the SQLite path's `NON_TERMINAL_STATUS_SQL` guard. Returns the row's actual status
    /// afterwards, since a skipped guarded write must not be reported as the status it asked for.
    fn terminalize(&mut self, idempotency_key: &str, status: IntentStatus) -> IntentStatus {
        let after = match self.entries.get_mut(idempotency_key) {
            Some(intent) => {
                if !intent.status.is_terminal() {
                    intent.status = status;
                }
                intent.status.clone()
            }
            None => status,
        };
        self.activate_pending_if_fits();
        after
    }

    /// The live occupancy of this log's map, by the durable arm's counting rule
    /// (`NON_TERMINAL_STATUS_SQL` split on `compensates`), in one place for the three callers
    /// (admission, config fit-check, pending activation).
    fn live_occupancy(&self) -> crate::capacity::Occupancy {
        let (mut active_forward, mut active_undo) = (0u32, 0u32);
        for intent in self.entries.values() {
            if !intent.status.is_terminal() {
                if intent.command.compensates.is_some() {
                    active_undo += 1;
                } else {
                    active_forward += 1;
                }
            }
        }
        crate::capacity::Occupancy { active_forward, active_undo }
    }

    /// This fake's twin of the `intents_status_activation` trigger: after any status write, a
    /// pending capacity reduction that now fits becomes current. Leaving it pending until the next
    /// `record_capacity_config` let a subsequent admission answer to the stale current bounds and
    /// insert an operation the durable trigger would have refused, the fake-with-a-weaker-gate
    /// failure the `exposure_obligations` field documents. Called after every status-writing path
    /// (the same event the SQL trigger rides); idempotent, a no-op once nothing is pending.
    fn activate_pending_if_fits(&mut self) {
        let Some((_, pending)) = self.capacity_pending else {
            return;
        };
        if crate::capacity::activation_fits(self.live_occupancy(), &pending) {
            self.capacity_current = pending;
            self.capacity_pending = None;
        }
    }
}

impl IntentLog for InMemoryIntentLog {
    fn record(
        &mut self,
        command: &Command,
        basis: &crate::prestate::FrozenBasis,
    ) -> Result<Claim, LogError> {
        reject_reserved_user_key(command)?;
        reject_unreadable_basis(basis)?;
        // Immutability (as in `SqliteIntentLog`): re-recording a different command under an existing
        // key is rejected; an identical re-record is a no-op that preserves the existing status and
        // seq (never regresses to `Pending`, ADR-P013) and reports `AlreadyExisted` so the caller does
        // not double-dispatch.
        if let Some(existing) = self.entries.get(&command.idempotency_key) {
            if existing.command != *command {
                return Err(key_rewrite_rejected(&command.idempotency_key));
            }
            return Ok(Claim::AlreadyExisted);
        }
        // Fresh insert: the admission tier applies (see `reject_inadmissible_basis`); the replay
        // above never reaches it.
        reject_inadmissible_basis(basis)?;
        // The plan-child admission, mirrored over this twin's maps; a refusal returns before
        // anything below writes (the durable arm's contract, same values).
        if let Some(link) = command.plan_child.clone() {
            if let Some(refusal) = self.plan_child_admission(command, &link)? {
                return Ok(Claim::PlanChildRefused(refusal));
            }
        }
        // The same derived-occupancy check the SQLite arm runs, counted the same way over this
        // log's own map.
        let occupancy = self.live_occupancy();
        let admission_kind = if command.compensates.is_some() {
            crate::capacity::AdmissionKind::Undo
        } else {
            crate::capacity::AdmissionKind::Forward
        };
        // While a reduction is pending, forward admission answers to the new (pending) bounds
        // immediately and remedies keep answering to the bounds still current, so the reserve stays
        // honest for whichever pool a forward is admitted into and undo/remedy traffic is never
        // starved by a reduction that has not yet released enough of the pool to activate.
        let bounds = match (&admission_kind, &self.capacity_pending) {
            (crate::capacity::AdmissionKind::Forward, Some((_, pending))) => pending,
            _ => &self.capacity_current,
        };
        match crate::capacity::admission_check(admission_kind, 1, occupancy, bounds) {
            Ok(()) => {}
            Err(crate::capacity::CapacityError::Refused(refusal)) => {
                return Ok(Claim::CapacityRefused(refusal.to_string()));
            }
            Err(crate::capacity::CapacityError::Domain(e)) => {
                return Err(LogError(format!(
                    "admission refused: capacity domain error: {e}"
                )));
            }
        }
        // The audit edge, inside the admission: computed before the row exists so a link this build
        // cannot write leaves no successor behind (the mirror of "the link commits atomically with
        // the successor's admission"). It is an audit pointer only: nothing gates on it, and the
        // exposure refusal this successor will meet at the send check is decided by the obligation
        // rows.
        let edges = self.supersession_edges(
            &command.idempotency_key,
            &crate::attempt::ExposureKey::from_basis(basis),
        )?;
        self.next_seq += 1;
        self.attempt_facts.extend(edges);
        // The `admitted_control_epoch` binding, mirrored: the epoch this operation was admitted
        // under is what `claim_attempt` and `admitted_epoch_is_current` compare against.
        self.admitted_epochs
            .insert(command.idempotency_key.clone(), self.control_epoch);
        self.entries.insert(
            command.idempotency_key.clone(),
            Intent {
                command: command.clone(),
                status: IntentStatus::Pending,
                seq: self.next_seq,
                attempts: 0,
                // BASIS-5: the freeze is part of the same (here trivially atomic) claim.
                frozen_basis: Some(basis.clone()),
                // This log models no config ledger (no `engine_config` table, no mode generation to bind),
                // so it binds the compiled default the SQLite first-run act also writes at generation 1:
                // capture on, a journal is owed. A fake with no mode is not a fake with mode off.
                journal_required: true,
                // A freshly recorded intent is `Pending`, so this is meaningless either way; `false` is the
                // column's own default.
                projected: false,
                // This fake models no `message_header` table, so there is no basis to freeze: honestly
                // `None`, never a guessed revision.
                basis_ingest_revision: None,
            },
        );
        Ok(Claim::Inserted)
    }

    fn get(&self, idempotency_key: &str) -> Result<Option<Intent>, LogError> {
        Ok(self.entries.get(idempotency_key).cloned())
    }

    fn set_status_if(
        &mut self,
        idempotency_key: &str,
        precondition: StatusPrecondition,
        status: IntentStatus,
    ) -> Result<StatusWrite, LogError> {
        // The mirror of the SQLite path over the map: the same precondition vocabulary, with the
        // non-terminal arm reading the same authority (`is_terminal` here, `NON_TERMINAL_STATUS_SQL`
        // there).
        let Some(intent) = self.entries.get_mut(idempotency_key) else {
            return Ok(StatusWrite::Refused(None));
        };
        if !status_precondition_holds(&precondition, &intent.status) {
            return Ok(StatusWrite::Refused(Some(intent.status.clone())));
        }
        intent.status = status;
        // The trigger twin rides every status write (see its doc).
        self.activate_pending_if_fits();
        Ok(StatusWrite::Written)
    }

    fn dead_letter_if_quiescent(
        &mut self,
        idempotency_key: &str,
    ) -> Result<DeadLetterWrite, LogError> {
        // The mirror of the durable path: the head predicate first, then the same non-terminal
        // compare, both through the same projections ([`IntentLog::live_attempt`] here is
        // `sever_disposition`'s answer, one rule in one place). This log is single-threaded, so "one
        // transaction" means checking everything before writing anything.
        if let Some(live) = self.live_attempt(idempotency_key)? {
            return Ok(DeadLetterWrite::LiveAttempt(live.class));
        }
        match self.set_status_if(
            idempotency_key,
            StatusPrecondition::NonTerminal,
            IntentStatus::Failed,
        )? {
            StatusWrite::Written => Ok(DeadLetterWrite::Written),
            StatusWrite::Refused(actual) => Ok(DeadLetterWrite::StatusMoved(actual)),
        }
    }

    fn verify_undo_pair(
        &mut self,
        parent_key: &str,
        child_key: &str,
        child: UndoPairChild,
    ) -> Result<UndoPairFlip, LogError> {
        // As in the durable transaction, both preconditions are decided before any write, so a
        // refusal leaves the pair as it was (single-threaded, so "one transaction" is "check
        // everything first").
        let child_status = self.entries.get(child_key).map(|c| c.status.clone());
        if child_status.as_ref().is_none_or(IntentStatus::is_terminal) {
            return Ok(UndoPairFlip::ChildMoved(child_status));
        }
        let parent_status = self.entries.get(parent_key).map(|p| p.status.clone());
        if !matches!(
            parent_status,
            Some(IntentStatus::Applied | IntentStatus::Undone)
        ) {
            return Ok(UndoPairFlip::ParentMoved(parent_status));
        }
        if let Some(parent) = self.entries.get_mut(parent_key) {
            parent.status = IntentStatus::Undone;
        }
        if child == UndoPairChild::Terminalize {
            if let Some(child) = self.entries.get_mut(child_key) {
                child.status = IntentStatus::Applied;
            }
        }
        // Once for the pair: the trigger fires per row, but activation is monotonic (pending either
        // fits at the pair's final occupancy or it does not).
        self.activate_pending_if_fits();
        Ok(UndoPairFlip::Flipped)
    }

    fn unreconciled(&self) -> Result<Vec<Intent>, LogError> {
        // The status domain, from the single authority, never a hand-enumerated subset.
        let mut unreconciled: Vec<Intent> = self
            .entries
            .values()
            .filter(|intent| !intent.status.is_terminal())
            .cloned()
            .collect();
        unreconciled.sort_by_key(|intent| intent.seq);
        Ok(unreconciled)
    }

    fn applied_unprojected_forward_intents(&self) -> Result<Vec<Intent>, LogError> {
        let mut intents: Vec<Intent> = self
            .entries
            .values()
            .filter(|intent| {
                intent.status == IntentStatus::Applied && !intent.projected && intent.command.compensates.is_none()
            })
            .cloned()
            .collect();
        intents.sort_by_key(|intent| intent.seq);
        Ok(intents)
    }

    fn charge_and_dead_letter_if_quiescent(
        &mut self,
        idempotency_key: &str,
        cap: u32,
    ) -> Result<TransientCharge, LogError> {
        // The mirror of the durable path, in the same order: the settled-row refusal, then the
        // charge, then the head predicate, through the same projection ([`IntentLog::live_attempt`],
        // `sever_disposition`'s answer). Single-threaded, so "one transaction" means deciding
        // everything that can refuse before writing anything that cannot be taken back; the charge is
        // the only write ahead of the predicate, and it must survive the refusal.
        let Some(intent) = self.entries.get_mut(idempotency_key) else {
            return Ok(TransientCharge::ChargeRefusedTerminal(None));
        };
        if intent.status.is_terminal() {
            return Ok(TransientCharge::ChargeRefusedTerminal(Some(
                intent.status.clone(),
            )));
        }
        intent.attempts += 1;
        let over_budget = intent.attempts >= cap;
        if !over_budget {
            return Ok(TransientCharge::ChargedOnly);
        }
        // The head predicate: a terminal written over a live attempt leaves that attempt dangling,
        // so an exhausted budget is not by itself authority to close the operation.
        if self.live_attempt(idempotency_key)?.is_some() {
            return Ok(TransientCharge::ChargedOnly);
        }
        // ...and the status transition, under the same non-terminal compare `set_status_if` takes
        // (nothing could have moved the row under this single-threaded log, so the compare can only
        // agree; it is here because the domain comes from the single authority).
        match self.set_status_if(
            idempotency_key,
            StatusPrecondition::NonTerminal,
            IntentStatus::Failed,
        )? {
            StatusWrite::Written => Ok(TransientCharge::ChargedAndDeadLettered),
            // Unreachable, so explicit, as in the durable path: the row was read non-terminal above and
            // only this call has touched it since, so a refusal would mean the compare and the read
            // describe one store differently. Never a quiet answer that would also have to describe a
            // charge that did happen as refused.
            StatusWrite::Refused(actual) => Err(LogError(format!(
                "charge_and_dead_letter: '{idempotency_key}' read non-terminal and then refused \
                 the non-terminal compare in the same call (now {actual:?})"
            ))),
        }
    }

    fn dead_letters(&self) -> Result<Vec<Intent>, LogError> {
        let mut dead: Vec<Intent> = self
            .entries
            .values()
            .filter(|intent| matches!(intent.status, IntentStatus::Failed))
            .cloned()
            .collect();
        dead.sort_by_key(|intent| intent.seq);
        Ok(dead)
    }

    fn latest_intent_for_message_ref(
        &self,
        account: &str,
        message_ref: &str,
    ) -> Result<Option<Intent>, LogError> {
        Ok(self
            .entries
            .values()
            .filter(|i| {
                i.command.account == account
                    && action_message_ref(&i.command.action) == message_ref
            })
            .max_by_key(|i| i.seq)
            .cloned())
    }

    fn has_non_terminal_native_predecessor(
        &self,
        native_key: &str,
        fallback_message_ref: &str,
        account: &str,
        before_seq: u64,
        exclude_idempotency_key: &str,
    ) -> Result<bool, LogError> {
        // Mirrors the SQLite predicate over the map: same seq bound, same non-terminal domain
        // (`is_terminal` here, `NON_TERMINAL_STATUS_SQL` there), and the same two overlapping lanes
        // with the same per-lane scoping.
        //
        // This used to match on the candidate's own basis (native key when it had one, `message_ref`
        // when it did not), which made the lanes a partition and let a NULL-basis caller pass a newer
        // frozen-basis row on the same message. The `message_ref` lane now applies to every
        // candidate, as lane 2 of `non_terminal_native_predecessor_sql` does. Conservative by design:
        // over-deferral parks, under-deferral corrupts order.
        //
        // The account filter also sat outside both lanes, carrying the same cross-handle overtake.
        // The native lane keys on the native key alone (provider-scoped); only the Photon-local
        // `message_ref` lane is account-scoped.
        Ok(self.entries.values().any(|other| {
            other.seq < before_seq
                && other.command.idempotency_key != exclude_idempotency_key
                && !other.status.is_terminal()
                && (other
                    .frozen_basis
                    .as_ref()
                    .is_some_and(|basis| basis.native_resource_key == native_key)
                    || (other.command.account == account
                        && action_message_ref(&other.command.action) == fallback_message_ref))
        }))
    }

    fn prepare(
        &mut self,
        idempotency_key: &str,
        journal: &crate::prestate::JournalRow,
    ) -> Result<crate::prestate::PrepareOutcome, LogError> {
        use crate::prestate::PrepareOutcome;
        let intent = self
            .entries
            .get(idempotency_key)
            .ok_or_else(|| LogError(format!("prepare read: no intent '{idempotency_key}'")))?;
        // `kind` is not a column here; it is derived from the compensation link, as the SQLite
        // admission statement's `CASE WHEN compensates IS NULL THEN 'forward' ELSE 'undo'` does.
        if intent.command.compensates.is_some() || !intent.journal_required {
            return Err(LogError(format!(
                "prepare refused: intent '{idempotency_key}' is not a journal-required forward intent"
            )));
        }
        let basis = intent.frozen_basis.clone().ok_or_else(|| {
            LogError(format!(
                "prepare refused: intent '{idempotency_key}' has no frozen_basis"
            ))
        })?;
        // Same boundary rule as the SQLite impl: the row is the phase, so validate it against the
        // frozen basis before it can persist.
        journal
            .validate(&basis)
            .map_err(|e| LogError(format!("prepare refused: {e}")))?;
        // Never persist a label vector its own read boundary would refuse.
        journal
            .observed_label_vector_set()
            .map_err(|e| LogError(format!("prepare refused: {}", e.0)))?;
        // Already prepared? Never re-capture.
        if self.pre_state.contains_key(idempotency_key) {
            return Ok(PrepareOutcome::AlreadyPrepared);
        }
        // A pre-dispatch state is required on the insert path, the same axis as the SQLite impl
        // (`IntentStatus::is_pre_dispatch`): a post-effect observation is never journaled. And the
        // same split: a terminal row is a peer's normal closure and is answered as one; only the
        // non-terminal-yet-not-pre-dispatch phase (`Undoing`) is a store defect. See the SQLite twin.
        if !intent.status.is_pre_dispatch() {
            if intent.status.is_terminal() {
                return Ok(PrepareOutcome::Closed(intent.status.clone()));
            }
            return Err(LogError(format!(
                "prepare refused: intent '{idempotency_key}' is '{:?}', not pre-dispatch \
                 — a post-effect observation is never journaled",
                intent.status
            )));
        }
        // This log models no config ledger. Its bound config act is the compiled generation-1
        // default `record` binds, so the bound row always exists and the config existence check
        // cannot fail here.
        //
        // The epoch check does apply here: the mirror has a `control_epoch` that `sever` bumps, and
        // `record` binds the admitted one. A sever between admission and PREPARE parks the intent on
        // this path too.
        let mode_generation = 1;
        let captured_epoch = self.control_epoch;
        let admitted = *self.admitted_epochs.get(idempotency_key).ok_or_else(|| {
            LogError(format!("prepare refused: no admitted epoch for '{idempotency_key}'"))
        })?;
        if captured_epoch != admitted {
            return Ok(PrepareOutcome::EpochFenced);
        }
        let message_ref = action_message_ref(&intent.command.action).to_string();
        let (native_key, account, seq) = (
            basis.native_resource_key.clone(),
            intent.command.account.clone(),
            intent.seq,
        );
        if self.has_non_terminal_native_predecessor(
            &native_key,
            &message_ref,
            &account,
            seq,
            idempotency_key,
        )? {
            return Ok(PrepareOutcome::NotAtHead);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.pre_state.insert(
            idempotency_key.to_string(),
            InMemoryJournal {
                row: journal.clone(),
                fetched_at: crate::prestate::rfc3339_utc(now),
                undo_offer_until: crate::prestate::rfc3339_utc(
                    now + crate::prestate::UNDO_OFFER_SECONDS,
                ),
                captured_epoch,
                mode_generation,
                capture_generation: 1,
            },
        );
        Ok(PrepareOutcome::Prepared)
    }

    fn prepared(&self, idempotency_key: &str) -> Result<bool, LogError> {
        Ok(self.pre_state.contains_key(idempotency_key))
    }

    fn captured_pre_state(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<CapturedPreState>, LogError> {
        let intent = self.entries.get(idempotency_key).ok_or_else(|| {
            LogError(format!("captured_pre_state: no intent '{idempotency_key}'"))
        })?;
        let Some(journal) = self.pre_state.get(idempotency_key) else {
            return Ok(None);
        };
        // The SQLite read boundary, mirrored: one rule, two stores.
        if let Some(basis) = intent.frozen_basis.as_ref() {
            journal.row.validate(basis).map_err(|e| {
                LogError(format!(
                    "captured_pre_state: inconsistent persisted journal row: {e}"
                ))
            })?;
        }
        // The value and the generation it came from, in one read.
        Ok(Some(CapturedPreState {
            atoms: serde_json::from_str(&journal.row.touched_atom)
                .map_err(|e| LogError(format!("captured_pre_state: corrupt touched_atom: {e}")))?,
            capture_generation: journal.capture_generation,
            observed_label_vector: journal.row.observed_label_vector_set()?,
        }))
    }

    fn record_effect_witness(
        &mut self,
        idempotency_key: &str,
        witness: &EffectWitness,
        pre: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<(), LogError> {
        let intent = self.entries.get(idempotency_key).ok_or_else(|| {
            LogError(format!("record_effect_witness refused: no operation '{idempotency_key}'"))
        })?;
        // The durable guard, mirrored: a persisted vector is never overwritten.
        if self.effect_witnesses.contains_key(idempotency_key) {
            return Err(effect_witness_already_recorded(idempotency_key));
        }
        let row = effect_witness_row(idempotency_key, witness, pre, intent.frozen_basis.as_ref())?;
        // No vector observed ⇒ nothing persisted (the durable write stores NULLs).
        if row.effect_label_vector.is_some() {
            self.effect_witnesses.insert(idempotency_key.to_string(), row);
        }
        Ok(())
    }

    fn effect_witness(&self, idempotency_key: &str) -> Result<Option<EffectWitnessRow>, LogError> {
        if !self.entries.contains_key(idempotency_key) {
            return Err(LogError(format!("effect_witness: no operation '{idempotency_key}'")));
        }
        Ok(self.effect_witnesses.get(idempotency_key).cloned())
    }

    fn replace_journal_row(
        &mut self,
        idempotency_key: &str,
        journal: &crate::prestate::JournalRow,
    ) -> Result<JournalReplaceOutcome, LogError> {
        use crate::attempt::AttemptClass;
        let intent = self.entries.get(idempotency_key).ok_or_else(|| {
            LogError(format!("replace_journal_row: no intent '{idempotency_key}'"))
        })?;
        let basis = intent.frozen_basis.clone().ok_or_else(|| {
            LogError(format!(
                "replace_journal_row refused: intent '{idempotency_key}' has no frozen_basis"
            ))
        })?;
        journal
            .validate(&basis)
            .map_err(|e| LogError(format!("replace_journal_row refused: {e}")))?;
        journal
            .observed_label_vector_set()
            .map_err(|e| LogError(format!("replace_journal_row refused: {}", e.0)))?;
        if !self.pre_state.contains_key(idempotency_key) {
            return Ok(JournalReplaceOutcome::NoRowToReplace);
        }
        // The same fact-derived legality condition the durable path holds (its full argument
        // lives there): every attempt of the operation must be provably wire-free.
        let attempt_ids: Vec<String> = self
            .attempt_facts
            .iter()
            .filter(|f| {
                f.kind == crate::attempt::FactKind::Claim && f.operation_id == idempotency_key
            })
            .map(|f| f.attempt_id.clone())
            .collect();
        for attempt_id in &attempt_ids {
            let state = self.fold_stored_attempt(attempt_id)?;
            let class = state.class().ok_or_else(|| {
                LogError(format!(
                    "replace_journal_row: attempt '{attempt_id}' folds to no class"
                ))
            })?;
            if !matches!(
                class,
                AttemptClass::PreIssuance
                    | AttemptClass::TerminalFailedPreSend
                    | AttemptClass::TerminalSeveredBeforeIssuance
            ) {
                return Ok(JournalReplaceOutcome::RefusedAttemptNotProvenNoWire {
                    attempt_id: attempt_id.clone(),
                });
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Remove then insert, mirroring the durable delete plus insert: the mirror stores
        // a fresh capture, not an edited one.
        let previous = self
            .pre_state
            .remove(idempotency_key)
            .expect("the row was there a moment ago");
        let generation = previous
            .capture_generation
            .checked_add(1)
            .ok_or_else(|| LogError("replace_journal_row: capture generation overflow".into()))?;
        self.pre_state.insert(
            idempotency_key.to_string(),
            InMemoryJournal {
                row: journal.clone(),
                fetched_at: crate::prestate::rfc3339_utc(now),
                undo_offer_until: crate::prestate::rfc3339_utc(
                    now + crate::prestate::UNDO_OFFER_SECONDS,
                ),
                captured_epoch: self.control_epoch,
                mode_generation: previous.mode_generation,
                capture_generation: generation,
            },
        );
        Ok(JournalReplaceOutcome::Replaced { generation })
    }

    fn undo_context(&mut self, idempotency_key: &str) -> Result<Option<UndoContext>, LogError> {
        if !self.entries.contains_key(idempotency_key) {
            return Ok(None);
        }
        // The read boundary for the persisted journal row, the mirror of PREPARE's write-side
        // `JournalRow::validate` and of `FrozenBasis::from_json`'s validation on the way in from
        // storage, so the two directions cannot drift. `undo_context` hands `touched_atom` to
        // `drive_undo_child` as `P`, so a syntactically valid but inconsistent stored row (an
        // earlier-branch build, or valid-text on-disk corruption) would forge a false no-op or a wrong
        // restore. The basis is cloned out so the immutable borrow of `entries` does not entangle the
        // `pre_state` read below. Validate only when a basis exists: a legacy row without one keeps
        // the `PredatesSubstrate` degradation path, as PREPARE does.
        let basis = self
            .entries
            .get(idempotency_key)
            .and_then(|i| i.frozen_basis.clone());
        let journal = self
            .pre_state
            .get(idempotency_key)
            .map(|j| -> Result<CapturedJournal, LogError> {
                if let Some(basis) = basis.as_ref() {
                    j.row.validate(basis).map_err(|e| {
                        LogError(format!(
                            "undo_context: inconsistent persisted journal row: {e}"
                        ))
                    })?;
                }
                let p: std::collections::BTreeMap<String, bool> =
                    serde_json::from_str(&j.row.touched_atom).map_err(|e| {
                        LogError(format!("undo_context: corrupt touched_atom: {e}"))
                    })?;
                // The store boundary for the offer deadline: deadlines are ordered lexicographically, which
                // is time order only over the canonical shape. A malformed value fails explicitly here rather
                // than failing open there.
                if !crate::prestate::is_canonical_rfc3339_utc(&j.undo_offer_until) {
                    return Err(LogError(
                        "undo_context: non-canonical undo_offer_until".into(),
                    ));
                }
                Ok(CapturedJournal {
                    p,
                    undo_offer_until: j.undo_offer_until.clone(),
                })
            })
            .transpose()?;
        // The sticky clock, mirrored: the twin's one helper
        // (`InMemoryIntentLog::sticky_effective_now`), shared with the plan paths.
        let effective_now = self.sticky_effective_now("undo_context")?;
        Ok(Some(UndoContext {
            // This log mints no opaque `intent_id`, so the user key is its operation identity. The undo
            // child's reserved key therefore derives from the user key here and the opaque id on SQLite;
            // both are content-free and uncollidable in their own namespace.
            parent_intent_id: idempotency_key.to_string(),
            journal,
            tombstoned: self.tombstones.contains(idempotency_key),
            effective_now,
        }))
    }

    fn admitted_epoch_is_current(&self, idempotency_key: &str) -> Result<bool, LogError> {
        // A real comparison: the mirror has a `control_epoch` that `sever` bumps, and `record` writes
        // the per-operation binding. A missing key is still an error; the contract's explicit
        // failure is the part a fake must not soften.
        let admitted = self.admitted_epochs.get(idempotency_key).ok_or_else(|| {
            LogError(format!(
                "admitted_epoch_is_current: no intent '{idempotency_key}'"
            ))
        })?;
        Ok(*admitted == self.control_epoch)
    }

    fn claim_attempt(
        &mut self,
        idempotency_key: &str,
        claim: &AttemptClaim,
    ) -> Result<ClaimOutcome, LogError> {
        use crate::attempt::{DerivedState, Fact, FactKind, FactPayload};
        let intent = self.entries.get(idempotency_key).ok_or_else(|| {
            LogError(format!("claim_attempt: no intent '{idempotency_key}'"))
        })?;
        // COMPARE 1 — the operation settled under this driver.
        if intent.status.is_terminal() {
            return Ok(ClaimOutcome::AlreadyClaimed);
        }
        // COMPARE 2 — the durable dispatch episode moved under this driver.
        if intent.attempts != claim.observed_attempts {
            return Ok(ClaimOutcome::AlreadyClaimed);
        }
        // The claim-path epoch check. The admitted-epoch binding lives in `admitted_epochs` (written
        // by `record`), so this refuses exactly where the durable path does, before the
        // latest-attempt lookup, which is what fences an operation that survives a sever active (an
        // `ISSUED_OR_UNKNOWN` member the sever may not close) rather than handing it back as a
        // re-entry win.
        let epoch = self.control_epoch;
        let admitted = *self.admitted_epochs.get(idempotency_key).ok_or_else(|| {
            LogError(format!(
                "claim_attempt: no admitted epoch for '{idempotency_key}'"
            ))
        })?;
        if epoch != admitted {
            return Ok(ClaimOutcome::EpochFenced);
        }
        let owner = idempotency_key.to_string();
        // The operation's highest-ordinal attempt, if any, folded through the pure core as the
        // SQLite arm does (same three arms; the full argument lives there).
        let latest: Option<(String, u64)> = self
            .attempt_facts
            .iter()
            .filter_map(|f| match (&f.kind, &f.payload) {
                (FactKind::Claim, FactPayload::Claim { ordinal, .. })
                    if f.operation_id == owner =>
                {
                    Some((f.attempt_id.clone(), *ordinal))
                }
                _ => None,
            })
            .max_by_key(|(_, ordinal)| *ordinal);
        let mut ordinal = claim.ordinal;
        let mut predecessor = claim.predecessor.clone();
        if let Some((latest_id, latest_ordinal)) = latest {
            if latest_ordinal >= claim.ordinal {
                let state = self.fold_stored_attempt(&latest_id)?;
                // `ISSUANCE_UNKNOWN`: no retry and no re-entry.
                if state.ambiguous_recorded && state.terminal_attribution.is_none() {
                    return Ok(ClaimOutcome::AwaitingAdjudication);
                }
                if state.operational == crate::attempt::OperationalAxis::Active {
                    // The re-entry arm (see the trait doc): all three compares passed, so this driver's
                    // observation is current and the attempt it already claimed is the one it owns. It carries the
                    // head revision it saw, because that ownership is shared with any equally-current peer.
                    return Ok(ClaimOutcome::Won {
                        attempt_id: latest_id,
                        ordinal: latest_ordinal,
                        observed_revision: state.current_revision,
                        // The re-entered attempt's class, from the fold: `IssuedOrUnknown` means a peer's (or a
                        // crashed driver's) `SEND_AUTHORIZED` is already committed.
                        class: state.class().ok_or_else(|| {
                            LogError("claim_attempt: a claimed attempt has no class".into())
                        })?,
                    });
                }
                // The retry gap: the successor's ordinal and mandatory lineage derive from the operation's
                // own chain.
                match retry_reason_of(&state) {
                    Some(reason) => {
                        ordinal = latest_ordinal + 1;
                        predecessor = Some(crate::attempt::RetryPredecessor {
                            attempt_id: latest_id,
                            reason,
                        });
                    }
                    None => return Ok(ClaimOutcome::AlreadyClaimed),
                }
            }
        }
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let clamped = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("claim_attempt clock: {e}")))?;
        self.next_attempt += 1;
        let fact = Fact {
            operation_id: owner,
            attempt_id: format!("mem-attempt-{}", self.next_attempt),
            revision: 1,
            kind: FactKind::Claim,
            basis_epoch: epoch,
            created_at: clamped.value,
            payload: FactPayload::Claim {
                ordinal,
                predecessor: predecessor.clone(),
            },
            prior_revision: None,
        };
        // The single legality predicate: the grammar has one home and this is its entry point.
        if let Err(refusal) = crate::attempt::append_legal(&DerivedState::empty(), &fact) {
            return Ok(ClaimOutcome::RefusedByGrammar(refusal));
        }
        if let Some(link) = predecessor.as_ref() {
            // An absent predecessor is not a store incident: the pure core has the refusal for it
            // (`PredecessorUnclaimed`), reached by handing it the empty state. A malformed one is a
            // different question with a different answer (see the durable path's note); the two must not
            // diverge.
            let predecessor = self
                .fold_stored_attempt_if_present(&link.attempt_id)?
                .unwrap_or_else(DerivedState::empty);
            let has_successor = self.attempt_facts.iter().any(|f| {
                f.kind == FactKind::Claim
                    && matches!(&f.payload, FactPayload::Claim { predecessor: Some(p), .. }
                        if p.attempt_id == link.attempt_id)
            });
            if let Err(refusal) =
                crate::attempt::retry_lineage_legal(&fact, &predecessor, has_successor)
            {
                return Ok(ClaimOutcome::RefusedByGrammar(refusal));
            }
        }
        let attempt_id = fact.attempt_id.clone();
        let revision = fact.revision;
        self.attempt_facts.push(fact);
        Ok(ClaimOutcome::Won {
            attempt_id,
            ordinal,
            // A freshly minted attempt's chain is exactly this `CLAIM` fact...
            observed_revision: revision,
            // ...so its class is claimed, never authorized, stated through the grammar's own vocabulary
            // rather than re-derived.
            class: crate::attempt::AttemptClass::PreIssuance,
        })
    }

    fn authorize_send(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        capture: CaptureBinding,
        plan: crate::plan::PlanBinding,
    ) -> Result<SendAuthOutcome, LogError> {
        use crate::attempt::{ExposureKey, Fact, FactKind, FactPayload};
        // Everything this path needs from the operation row, taken up front: the check below
        // terminalizes, and a live borrow of `entries` across that write is a borrow of the world it
        // is about to change. The Photon-local account handle is not taken: the exposure scope is the
        // provider's and lives inside the frozen basis.
        let basis = {
            let intent = self.entries.get(idempotency_key).ok_or_else(|| {
                LogError(format!("authorize_send: no intent '{idempotency_key}'"))
            })?;
            intent.frozen_basis.clone()
        };
        let state = self.fold_stored_attempt(attempt_id)?;
        let claim = state.claim.clone().ok_or_else(|| {
            LogError(format!(
                "authorize_send: attempt '{attempt_id}' has no CLAIM to authorize"
            ))
        })?;
        // The owner here is the idempotency key (this log mints no opaque `intent_id`).
        if claim.operation_id != idempotency_key {
            return Err(LogError(format!(
                "authorize_send: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                claim.operation_id
            )));
        }
        // The capture CAS, mirrored from the durable path, ahead of every write below because a
        // refusal here must leave nothing behind.
        let found = self
            .pre_state
            .get(idempotency_key)
            .map(|journal| journal.capture_generation);
        if !capture_binding_holds(capture, found) {
            return Ok(SendAuthOutcome::CaptureSuperseded {
                expected: capture,
                found,
            });
        }
        let exposure_key = match basis.as_ref() {
            Some(basis) => ExposureKey::from_basis(basis),
            // The legacy NULL-basis arm, as in the SQLite path.
            None => ExposureKey::legacy_unscoped(),
        };
        // The epoch check, reachable here since the log has a `control_epoch` mirror the sever
        // bumps. The sever already closed every claimed-unauthorized attempt it could see; this is the
        // belt for the ones it could not, an attempt whose operation was lifecycle-terminal at the
        // sever (completed, so absent from the witness). Terminalizing here is the same atomic pairing
        // as the SQLite path: a refusal that only said "no" would strand it.
        if self.control_epoch != claim.claim_epoch {
            let now = crate::prestate::rfc3339_utc(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            let max_persisted = self
                .attempt_facts
                .iter()
                .map(|f| f.created_at.clone())
                .max()
                .unwrap_or_default();
            let clamped = crate::attempt::clamped_now(&now, &max_persisted)
                .map_err(|e| LogError(format!("authorize_send clock: {e}")))?;
            let severed = Fact {
                operation_id: claim.operation_id.clone(),
                attempt_id: attempt_id.to_string(),
                revision: state.current_revision + 1,
                kind: FactKind::SeveredBeforeIssuance,
                basis_epoch: self.control_epoch,
                created_at: clamped.value,
                payload: FactPayload::None,
                prior_revision: Some(state.current_revision),
            };
            // The one reachable refusal: the attempt is already authorized, so `SEVERED_BEFORE_ISSUANCE`
            // would be a non-issuance we cannot prove. It stays `ISSUED_OR_UNKNOWN` for the sever to
            // classify.
            if let Err(refusal) = crate::attempt::append_legal(&state, &severed) {
                return Ok(SendAuthOutcome::RefusedByGrammar(refusal));
            }
            self.attempt_facts.push(severed);
            self.terminalize(idempotency_key, IntentStatus::Severed);
            return Ok(SendAuthOutcome::EpochFenced);
        }
        // The plan-admission arm, mirrored: the durable binding check with its rows in the same
        // order over this twin's maps (`plan_send_admission` below), the same refusal values and
        // writes. For a terminal refusal of a never-authorized attempt that is `FAILED_PRE_SEND` plus
        // `Failed` and, for an expired or epoch-moved plan, the episode invalidation; nothing else.
        let link = self.entries.get(idempotency_key).and_then(|i| i.command.plan_child.clone());
        match (link, &plan) {
            (None, crate::plan::PlanBinding::Plain) => {}
            (Some(link), crate::plan::PlanBinding::Child { grant, account_key }) => {
                if let Some(refusal) = self.plan_send_admission(&link, idempotency_key, grant, account_key, capture)? {
                    if refusal.is_terminal() && !state.send_authorized {
                        let now = crate::prestate::rfc3339_utc(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        );
                        let max_persisted = self
                            .attempt_facts
                            .iter()
                            .map(|f| f.created_at.clone())
                            .max()
                            .unwrap_or_default();
                        let clamped = crate::attempt::clamped_now(&now, &max_persisted)
                            .map_err(|e| LogError(format!("authorize_send clock: {e}")))?;
                        let closed = Fact {
                            operation_id: claim.operation_id.clone(),
                            attempt_id: attempt_id.to_string(),
                            revision: state.current_revision + 1,
                            kind: FactKind::FailedPreSend,
                            basis_epoch: self.control_epoch,
                            created_at: clamped.value,
                            payload: FactPayload::FailedPreSend {
                                wire_evidence: crate::attempt::WireEvidence::ProvenNoWire,
                                reason: refusal.pre_send_reason(),
                                exposure_block: None,
                                plan_refusal: Some(refusal.record(&link.member_ref)),
                            },
                            prior_revision: Some(state.current_revision),
                        };
                        if let Err(g) = crate::attempt::append_legal(&state, &closed) {
                            return Ok(SendAuthOutcome::RefusedByGrammar(g));
                        }
                        self.attempt_facts.push(closed);
                        self.terminalize(idempotency_key, IntentStatus::Failed);
                        let invalidation = match &refusal {
                            crate::plan::PlanSendRefusal::Expired { .. } => Some(crate::episode::InvalidationReason::Expired),
                            crate::plan::PlanSendRefusal::PlanEpochMismatch { plan, current } => {
                                Some(crate::episode::InvalidationReason::EpochMismatch { plan: *plan, current: *current })
                            }
                            _ => None,
                        };
                        if let Some(reason) = invalidation {
                            // Transition-guarded, as in the durable path: an episode already terminal keeps its status.
                            // Only a store failure surfaces.
                            if let Err(crate::episode::EpisodeRefusal::Store(e)) = self.invalidate_episode(&link.plan_id, reason) {
                                return Err(LogError(e));
                            }
                        }
                    }
                    return Ok(SendAuthOutcome::PlanRefused(refusal));
                }
            }
            (link, binding) => {
                return Err(LogError(format!(
                    "authorize_send: '{idempotency_key}' carries {} and the caller's binding is {} — a caller bug, never a skipped law",
                    if link.is_some() { "a plan link" } else { "no plan link" },
                    if matches!(binding, crate::plan::PlanBinding::Plain) { "Plain" } else { "Child" }
                )));
            }
        }
        // The exposure check, mirrored. This log now holds obligations (its `adjudicate` writes
        // them), so the check is real here: any unretired row over a touched atom refuses
        // fail-closed, pre-wire, with the deterministic no-effect terminal. The durable path's
        // argument for the two shapes of refusal (already authorized: no fact, stays
        // `ISSUED_OR_UNKNOWN`; never authorized: the terminal is true and is written) is there; this
        // mirror answers identically so the fast tests test the engine that ships.
        //
        // It also names the blocking row, not just the atom: the durable overlap query selects
        // `obligation_id`, and the mirror's `find` returns the same pair, because that Photon-local id
        // is the half the caller is told about.
        if let Some((atom_key, obligation_id)) = exposure_key.atoms.iter().find_map(|atom| {
            self.exposure_obligations
                .iter()
                .find(|o| !o.retired() && o.atom_key == atom.atom_key)
                .map(|o| (atom.atom_key.clone(), o.obligation_id.clone()))
        }) {
            if state.send_authorized {
                return Ok(SendAuthOutcome::ExposureBlocked { atom_key });
            }
            let now = crate::prestate::rfc3339_utc(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            let max_persisted = self
                .attempt_facts
                .iter()
                .map(|f| f.created_at.clone())
                .max()
                .unwrap_or_default();
            let clamped = crate::attempt::clamped_now(&now, &max_persisted)
                .map_err(|e| LogError(format!("authorize_send clock: {e}")))?;
            let blocked = Fact {
                operation_id: claim.operation_id.clone(),
                attempt_id: attempt_id.to_string(),
                revision: state.current_revision + 1,
                kind: FactKind::FailedPreSend,
                basis_epoch: self.control_epoch,
                created_at: clamped.value,
                payload: FactPayload::FailedPreSend {
                    wire_evidence: crate::attempt::WireEvidence::ProvenNoWire,
                    reason: crate::attempt::PreSendReason::Failure,
                    // What refused, durably, as in the SQLite path: the internal atom and the surfaceable
                    // obligation reference, one writer, one write.
                    exposure_block: Some(crate::attempt::ExposureBlock {
                        atom_key: atom_key.clone(),
                        obligation_id,
                    }),
                    plan_refusal: None,
                },
                prior_revision: Some(state.current_revision),
            };
            if let Err(refusal) = crate::attempt::append_legal(&state, &blocked) {
                return Ok(SendAuthOutcome::RefusedByGrammar(refusal));
            }
            self.attempt_facts.push(blocked);
            self.terminalize(idempotency_key, IntentStatus::Failed);
            return Ok(SendAuthOutcome::ExposureBlocked { atom_key });
        }
        // At most one per attempt, as in the SQLite path. Nothing local decides it: the single
        // legality predicate below is the whole rule, with no counter pre-empting it.
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let clamped = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("authorize_send clock: {e}")))?;
        let fact = Fact {
            operation_id: claim.operation_id.clone(),
            attempt_id: attempt_id.to_string(),
            revision: state.current_revision + 1,
            kind: FactKind::SendAuthorized,
            basis_epoch: claim.claim_epoch,
            created_at: clamped.value,
            payload: FactPayload::SendAuthorized {
                exposure_key: exposure_key.clone(),
            },
            prior_revision: Some(state.current_revision),
        };
        // The single legality predicate, "at most one `SEND_AUTHORIZED`" included.
        if let Err(refusal) = crate::attempt::append_legal(&state, &fact) {
            return Ok(SendAuthOutcome::RefusedByGrammar(refusal));
        }
        self.attempt_facts.push(fact);
        Ok(SendAuthOutcome::Authorized { exposure_key })
    }

    fn settle_attempt(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        verdict: ConnectorVerdict,
        retry_cap: u32,
        pre_wire_at_revision: Option<u64>,
    ) -> Result<SettleOutcome, LogError> {
        use crate::attempt::Fact;
        let state = self.fold_stored_attempt(attempt_id)?;
        let claim = state.claim.as_ref().ok_or_else(|| {
            LogError(format!(
                "settle_attempt: attempt '{attempt_id}' has no CLAIM to settle"
            ))
        })?;
        // The owner here is the idempotency key (this log mints no opaque `intent_id`).
        if claim.operation_id != idempotency_key {
            return Err(LogError(format!(
                "settle_attempt: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                claim.operation_id
            )));
        }
        // The pre-wire compare-and-append, mirrored: a fake that let a stale pre-wire verdict
        // through would hide the race the durable path refuses.
        if let Some(observed_revision) = pre_wire_at_revision {
            if state.current_revision != observed_revision {
                return Ok(SettleOutcome::SupersededPreWire {
                    observed_revision,
                    current_revision: state.current_revision,
                });
            }
        }
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let clamped = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("settle_attempt clock: {e}")))?;
        // The claim's epoch, copied out before the lifecycle writes below borrow `self`.
        let claim_epoch = claim.claim_epoch;
        // The mapping: the one table, shared with the SQLite path.
        let (kind, payload, intent) = verdict_mapping(state.send_authorized, verdict);
        // The settlement-epoch check is mirrored at the same site, decided from the verdict's
        // evidence once ahead of the lifecycle branches.
        let epoch_fenced =
            self.control_epoch != claim_epoch && settlement_proves_no_effect(kind, &payload);
        let fact = Fact {
            operation_id: claim.operation_id.clone(),
            attempt_id: attempt_id.to_string(),
            revision: state.current_revision + 1,
            kind,
            // The epoch this fact is written under, not the one the attempt was claimed under. The
            // durable path stamps the `control_epoch` its own transaction read; stamping
            // `claim.claim_epoch` differs exactly when a verdict lands after a sever moved the epoch.
            // Back-dating a fact into the dead epoch matters because `basis_epoch` is what the
            // epoch-scoped reads compare against, so the same history would answer "written under the
            // current epoch?" differently on the two stores.
            basis_epoch: self.control_epoch,
            created_at: clamped.value,
            payload,
            prior_revision: Some(state.current_revision),
        };
        if let Err(refusal) = crate::attempt::append_legal(&state, &fact) {
            return Ok(SettleOutcome::RefusedByGrammar(refusal));
        }
        self.attempt_facts.push(fact);
        // The other order of the exposure-materialization trace: this attempt's effect provably
        // happened. If an exposure that was unresolved at this attempt's authorization covers an atom
        // it touched, that is the multi-contributor trace, recorded on the other party's adjudication
        // record. The durable path has always done this here; the mirror ran only the late-ack order,
        // so "which effect resolves first must not decide whether a notice exists" held on one store
        // and not the other.
        if kind == crate::attempt::FactKind::AckApplied {
            if let Some(exposure_key) = state.exposure_key.clone() {
                let own = state.adjudication_id.clone();
                self.note_exposure_materialization(attempt_id, &exposure_key, own.as_deref())?;
            }
        }
        let lifecycle = if epoch_fenced {
            // The epoch check, for every lifecycle this verdict could otherwise have taken.
            SettledLifecycle::Completed(self.terminalize(idempotency_key, IntentStatus::Severed))
        } else {
            match intent {
                LifecycleIntent::Complete(status) => {
                    // Read back, never predicted, as in the durable path.
                    SettledLifecycle::Completed(self.terminalize(idempotency_key, status))
                }
                LifecycleIntent::AwaitingAdjudication => SettledLifecycle::AwaitingAdjudication,
                LifecycleIntent::ChargeTransient => {
                    // The charge inline, as the durable settlement transaction does, and not
                    // [`IntentLog::charge_and_dead_letter_if_quiescent`]: the verdict fact appended above is this
                    // attempt's terminal, and the claim grammar permits at most one live attempt per operation
                    // (`sever_disposition` refuses more by name), so the operation is quiescent here. The
                    // guarded call would re-derive a fold this settlement just wrote and answer the same.
                    let terminal = match self.entries.get_mut(idempotency_key) {
                        Some(intent) => {
                            intent.attempts += 1;
                            // Only a non-terminal row can be dead-lettered; a settled outcome is never rewritten.
                            if intent.attempts >= retry_cap && !intent.status.is_terminal() {
                                intent.status = IntentStatus::Failed;
                                true
                            } else {
                                false
                            }
                        }
                        None => false,
                    };
                    // The trigger twin rides every status write (this arm writes `Failed` directly rather than
                    // through `terminalize`).
                    self.activate_pending_if_fits();
                    if terminal {
                        SettledLifecycle::Completed(IntentStatus::Failed)
                    } else {
                        SettledLifecycle::RetryGap
                    }
                }
            }
        };
        Ok(SettleOutcome::Settled { verdict: kind, lifecycle })
    }

    fn sever(&mut self, authority_ref: &str, now: &str) -> Result<SeverOutcome, LogError> {
        use crate::attempt::{Fact, FactKind, FactPayload, WitnessClass, WitnessMember};
        let authority_ref = validated_authority_ref(authority_ref)?;
        // Validate everything fallible before any mutation. The durable path runs inside one
        // `Immediate` transaction, so a `?` on any step drops it uncommitted, epoch bump included.
        // This mirror has no rollback, so parity is structural: the epoch it will take is computed
        // here and `self.control_epoch` is untouched until every fallible step below has succeeded.
        // This closes a bug where a non-canonical `now` raised the epoch and then failed, leaving
        // every admitted operation fenced with no witness and no closures to explain it.
        let epoch = self.control_epoch + 1;
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let severed_at = crate::attempt::clamped_now(now, &max_persisted)
            .map_err(|e| LogError(format!("sever clock: {e}")))?
            .value;
        // The partition. The durable path reads its active set `ORDER BY seq`; this mirror sorts by
        // the same order so both derive the same member set from the same state (the canonical
        // order below makes it immaterial to the digest anyway).
        let mut actives: Vec<(u64, String)> = self
            .entries
            .iter()
            .filter(|(_, intent)| !intent.status.is_terminal())
            .map(|(key, intent)| (intent.seq, key.clone()))
            .collect();
        actives.sort();
        let mut members: Vec<WitnessMember> = Vec::new();
        let mut closures: Vec<(String, SeverDisposition)> = Vec::new();
        for (_, key) in actives {
            // The owner here is the idempotency key (this log mints no opaque `intent_id`).
            let mut live: Vec<(String, crate::attempt::DerivedState)> = Vec::new();
            let mut claims: Vec<(u64, String)> = self
                .attempt_facts
                .iter()
                .filter_map(|f| match (&f.kind, &f.payload) {
                    (FactKind::Claim, FactPayload::Claim { ordinal, .. })
                        if f.operation_id == key =>
                    {
                        Some((*ordinal, f.attempt_id.clone()))
                    }
                    _ => None,
                })
                .collect();
            claims.sort();
            for (_, attempt_id) in claims {
                let state = self.fold_stored_attempt(&attempt_id)?;
                if state.operational == crate::attempt::OperationalAxis::Active {
                    live.push((attempt_id, state));
                }
            }
            let disposition = sever_disposition(&key, &live)?;
            members.push(match &disposition {
                SeverDisposition::OperationMember => WitnessMember::Operation {
                    operation_id: key.clone().into_bytes(),
                },
                SeverDisposition::ClosedBeforeIssuance {
                    attempt_id,
                    revision,
                } => WitnessMember::Attempt {
                    attempt_id: attempt_id.clone().into_bytes(),
                    attempt_revision: *revision,
                    class_at_sever: WitnessClass::SeveredBeforeIssuance,
                },
                SeverDisposition::IssuedOrUnknown {
                    attempt_id,
                    revision,
                } => WitnessMember::Attempt {
                    attempt_id: attempt_id.clone().into_bytes(),
                    attempt_revision: *revision,
                    class_at_sever: WitnessClass::IssuedOrUnknown,
                },
            });
            closures.push((key, disposition));
        }
        // The witness: the same pure-core encoding authority as the durable path.
        let members = canonical_witness_order(members);
        let digest = crate::attempt::sever_witness_digest_hex(&members);
        // The codec is exercised here too, not only durably: a member this build could not persist
        // is a member neither store may witness.
        witness_member_set_json(&members)?;
        let witness = SeverWitness {
            witness_id: format!("mem-witness-{}", self.sever_witnesses.len() + 1),
            epoch,
            severed_at: severed_at.clone(),
            authority_ref,
            members,
            digest,
        };
        // The closures, prepared first and applied second. The closure facts are built and put
        // through the grammar here, while nothing has been mutated: a refusal on the third member must
        // not leave the first two terminalized behind a raised epoch, which is what the durable
        // rollback prevents.
        let mut prepared: Vec<(String, Option<Fact>)> = Vec::new();
        for (key, disposition) in closures {
            match disposition {
                SeverDisposition::IssuedOrUnknown { .. } => {}
                SeverDisposition::OperationMember => prepared.push((key, None)),
                SeverDisposition::ClosedBeforeIssuance {
                    attempt_id,
                    revision,
                } => {
                    let state = self.fold_stored_attempt(&attempt_id)?;
                    let fact = Fact {
                        operation_id: key.clone(),
                        attempt_id: attempt_id.clone(),
                        revision: revision + 1,
                        kind: FactKind::SeveredBeforeIssuance,
                        basis_epoch: epoch,
                        created_at: severed_at.clone(),
                        payload: FactPayload::None,
                        prior_revision: Some(revision),
                    };
                    if let Err(refusal) = crate::attempt::append_legal(&state, &fact) {
                        return Err(LogError(format!(
                            "sever: the closure of attempt '{attempt_id}' was refused by the \
                             grammar: {refusal}"
                        )));
                    }
                    prepared.push((key, Some(fact)));
                }
            }
        }
        // The commit point. Everything below is infallible, this mirror's stand-in for the durable
        // `tx.commit()`: from here the sever happened, whole.
        self.control_epoch = epoch;
        self.sever_witnesses.push(witness.clone());
        let mut terminalized = 0u64;
        for (key, fact) in prepared {
            if let Some(fact) = fact {
                self.attempt_facts.push(fact);
            }
            self.terminalize(&key, IntentStatus::Severed);
            terminalized += 1;
        }
        Ok(SeverOutcome {
            epoch,
            witness,
            terminalized,
        })
    }

    fn live_attempt(&self, idempotency_key: &str) -> Result<Option<LiveAttempt>, LogError> {
        // An attempt's owner here is the key itself (this log mints no opaque `intent_id`).
        //
        // Through `sever_disposition`, the one copy of the rule. The loop this replaced answered with
        // whichever live attempt it saw last, so an operation holding more than one (a store defect
        // the durable path refuses by name: the claim grammar permits exactly one, and the partition
        // is total only because of it) read back here as an ordinary class.
        let mut live: Vec<(String, crate::attempt::DerivedState)> = Vec::new();
        for claim in self
            .attempt_facts
            .iter()
            .filter(|f| f.kind == crate::attempt::FactKind::Claim && f.operation_id == idempotency_key)
        {
            let state = self.fold_stored_attempt(&claim.attempt_id)?;
            if state.operational == crate::attempt::OperationalAxis::Active {
                live.push((claim.attempt_id.clone(), state));
            }
        }
        Ok(live_attempt_from(sever_disposition(idempotency_key, &live)?))
    }

    fn adjudicate(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        principal_ref: &str,
        _reason: crate::attempt::AdjudicationReason,
        _accepted_risk: crate::attempt::AcceptedRisk,
    ) -> Result<AdjudicationOutcome, LogError> {
        use crate::attempt::{Fact, FactKind, FactPayload};
        // The same shape check the durable path holds: a fake that accepted an authority reference
        // the engine refuses would hide that refusal from every fast test. The validated value has no
        // home here: this log keeps no `adjudication_record` mirror (the closed vocabularies are
        // enforced by that table's `CHECK` constraints and guarded by `attempt.rs`'s DDL guard test),
        // so `reason` and `accepted_risk` are recorded by the durable path alone. What this log does
        // mirror is everything the engine reads afterwards: the fact, status, obligations and
        // annotations.
        let _authority = validated_authority_ref(principal_ref)?;
        let state = self.fold_stored_attempt(attempt_id)?;
        let claim = state.claim.clone().ok_or_else(|| {
            LogError(format!(
                "adjudicate: attempt '{attempt_id}' has no CLAIM to adjudicate"
            ))
        })?;
        if claim.operation_id != idempotency_key {
            return Err(LogError(format!(
                "adjudicate: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                claim.operation_id
            )));
        }
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let clamped = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("adjudicate clock: {e}")))?;
        self.next_adjudication += 1;
        let adjudication_id = format!("mem-adjudication-{}", self.next_adjudication);
        let fact = Fact {
            operation_id: claim.operation_id.clone(),
            attempt_id: attempt_id.to_string(),
            revision: state.current_revision + 1,
            kind: FactKind::AdjudicatedUnresolved,
            basis_epoch: self.control_epoch,
            created_at: clamped.value,
            payload: FactPayload::Adjudicated {
                adjudication_id: adjudication_id.clone(),
            },
            prior_revision: Some(state.current_revision),
        };
        // The grammar first, as in the durable path: no obligation may outlive a refused fact.
        if let Err(refusal) = crate::attempt::append_legal(&state, &fact) {
            return Ok(AdjudicationOutcome::RefusedByGrammar(refusal));
        }
        let exposure_key = state.exposure_key.clone().ok_or_else(|| {
            LogError(format!(
                "adjudicate: attempt '{attempt_id}' passed the grammar without an authorization \
                 payload — the fold and the grammar disagree"
            ))
        })?;
        self.attempt_facts.push(fact);
        self.terminalize(idempotency_key, IntentStatus::Adjudicated);
        let mut obligations = 0u64;
        for atom in &exposure_key.atoms {
            let generation = self.obligation_generation(&atom.atom_key);
            // The mirror's opaque row id: the durable `mint_opaque_id` in this log's monotonic spelling
            // (like `mem-adjudication-N`).
            self.next_obligation += 1;
            self.exposure_obligations.push(InMemoryObligation {
                obligation_id: format!("mem-obligation-{}", self.next_obligation),
                provider_scope: exposure_key.provider_scope.clone(),
                atom_key: atom.atom_key.clone(),
                direction: atom.direction,
                generation,
                contributor_attempt_id: attempt_id.to_string(),
                retired_at: None,
            });
            obligations += 1;
        }
        Ok(AdjudicationOutcome::Adjudicated {
            adjudication_id,
            obligations,
        })
    }

    fn record_late_ack(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
        ack: crate::attempt::LateAck,
    ) -> Result<LateAckOutcome, LogError> {
        use crate::attempt::{AnomalyKind, Fact, FactPayload, GrammarRefusal, LateAck};
        let state = self.fold_stored_attempt(attempt_id)?;
        let claim = state.claim.clone().ok_or_else(|| {
            LogError(format!("record_late_ack: attempt '{attempt_id}' has no CLAIM"))
        })?;
        if claim.operation_id != idempotency_key {
            return Err(LogError(format!(
                "record_late_ack: attempt '{attempt_id}' is owned by operation '{}', not by \
                 '{idempotency_key}'",
                claim.operation_id
            )));
        }
        let now = crate::prestate::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        let max_persisted = self
            .attempt_facts
            .iter()
            .map(|f| f.created_at.clone())
            .max()
            .unwrap_or_default();
        let clamped = crate::attempt::clamped_now(&now, &max_persisted)
            .map_err(|e| LogError(format!("record_late_ack clock: {e}")))?;
        // One instant for the fact, the retirement and the annotations, mirroring the durable
        // `created_at` discipline.
        let clamped_now = clamped.value.clone();
        let fact = Fact {
            operation_id: claim.operation_id.clone(),
            attempt_id: attempt_id.to_string(),
            revision: state.current_revision + 1,
            kind: ack.fact_kind(),
            basis_epoch: self.control_epoch,
            created_at: clamped.value,
            payload: FactPayload::None,
            prior_revision: Some(state.current_revision),
        };
        match crate::attempt::append_legal(&state, &fact) {
            Err(GrammarRefusal::ContradictoryLateAckAnomaly { .. }) => {
                let record = state.adjudication_id.clone().ok_or_else(|| {
                    LogError(format!(
                        "record_late_ack: attempt '{attempt_id}' contradicts a late ack it has \
                         no adjudication record for"
                    ))
                })?;
                self.next_adjudication += 1;
                let annotation_id = format!("mem-annotation-{}", self.next_adjudication);
                self.adjudication_annotations.push(InMemoryAnnotation {
                    adjudication_id: record,
                    kind: AnomalyKind::ContradictoryLateAck,
                    related_attempt_id: Some(attempt_id.to_string()),
                    atom_key: None,
                });
                return Ok(LateAckOutcome::RefusedAsContradiction { annotation_id });
            }
            Err(refusal) => return Ok(LateAckOutcome::RefusedByGrammar(refusal)),
            Ok(()) => {}
        }
        self.attempt_facts.push(fact);
        // This contributor's rows retire; every other contributor's stay live.
        let mut retired = 0u64;
        for obligation in self
            .exposure_obligations
            .iter_mut()
            .filter(|o| !o.retired() && o.contributor_attempt_id == attempt_id)
        {
            obligation.retired_at = Some(clamped_now.clone());
            retired += 1;
        }
        let mut notices = 0u64;
        let mut parent_undone = false;
        if ack == LateAck::Applied {
            // The exposure-materialization trace and the other order's half-trace, through the shared
            // copy of the rule. The hand-written scan that lived here was generation-unscoped (it read
            // every obligation row on the atom, retired or not), which is the bleed the shared helper's
            // window closes.
            if let Some(exposure_key) = state.exposure_key.clone() {
                let own = state.adjudication_id.clone();
                notices =
                    self.note_exposure_materialization(attempt_id, &exposure_key, own.as_deref())?;
            }
            // The undo-parent arm. With no opaque `intent_id`, the parent link is the child's
            // `compensates` (the parent's user key), the same durable link `recover` trusts.
            let parent_key = self
                .entries
                .get(idempotency_key)
                .and_then(|child| child.command.compensates.clone());
            if let Some(parent_key) = parent_key {
                if let Some(parent) = self.entries.get_mut(&parent_key) {
                    if parent.status == IntentStatus::Applied {
                        parent.status = IntentStatus::Undone;
                        parent_undone = true;
                    }
                }
            }
            // The trigger twin rides every status write.
            self.activate_pending_if_fits();
        }
        Ok(LateAckOutcome::Resolved {
            historical: ack.attribution(),
            retired,
            notices,
            parent_undone,
        })
    }

    fn annotate_late_ambiguous_observation(
        &mut self,
        idempotency_key: &str,
        attempt_id: &str,
    ) -> Result<String, LogError> {
        use crate::attempt::AnomalyKind;
        let state = self.fold_stored_attempt(attempt_id)?;
        let claim = state.claim.clone().ok_or_else(|| {
            LogError(format!(
                "annotate_late_ambiguous: attempt '{attempt_id}' has no CLAIM"
            ))
        })?;
        // An attempt's owner here is the key itself (this log mints no opaque `intent_id`).
        if claim.operation_id != idempotency_key {
            return Err(LogError(format!(
                "annotate_late_ambiguous: attempt '{attempt_id}' is owned by operation '{}', \
                 not by '{idempotency_key}'",
                claim.operation_id
            )));
        }
        let record = state.adjudication_id.clone().ok_or_else(|| {
            LogError(format!(
                "annotate_late_ambiguous: attempt '{attempt_id}' carries a late observation \
                 but no adjudication record to hang it on"
            ))
        })?;
        self.next_adjudication += 1;
        let annotation_id = format!("mem-annotation-{}", self.next_adjudication);
        self.adjudication_annotations.push(InMemoryAnnotation {
            adjudication_id: record,
            kind: AnomalyKind::LateAmbiguousObservation,
            related_attempt_id: Some(attempt_id.to_string()),
            atom_key: None,
        });
        Ok(annotation_id)
    }

    fn adjudicated_history(&self, idempotency_key: &str) -> Result<AdjudicatedHistory, LogError> {
        // The operation's attempts are its facts' `operation_id`, which here is the key.
        let resolved = self
            .attempt_facts
            .iter()
            .filter(|fact| fact.operation_id == idempotency_key)
            .find_map(|fact| match fact.kind {
                crate::attempt::FactKind::LateAckApplied => {
                    Some(AdjudicatedHistory::ResolvedApplied)
                }
                crate::attempt::FactKind::LateAckRefusedNoEffect => {
                    Some(AdjudicatedHistory::ResolvedRefusedNoEffect)
                }
                _ => None,
            });
        Ok(resolved.unwrap_or(AdjudicatedHistory::Unresolved))
    }

    fn exposure_block(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::attempt::ExposureBlock>, LogError> {
        // The durable path's twin: this operation's own `FAILED_PRE_SEND` facts, the first one
        // carrying a block wins. `operation_id` is the key on this log.
        Ok(self
            .attempt_facts
            .iter()
            .filter(|f| f.operation_id == idempotency_key)
            .find_map(|f| match &f.payload {
                crate::attempt::FactPayload::FailedPreSend {
                    exposure_block: Some(block),
                    ..
                } => Some(block.clone()),
                _ => None,
            }))
    }

    fn plan_refusal(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<crate::attempt::PlanRefusalRecord>, LogError> {
        // The durable path's twin: this operation's own `FAILED_PRE_SEND` facts, the first one
        // carrying a plan record wins. `operation_id` is the key on this log.
        Ok(self
            .attempt_facts
            .iter()
            .filter(|f| f.operation_id == idempotency_key)
            .find_map(|f| match &f.payload {
                crate::attempt::FactPayload::FailedPreSend { plan_refusal: Some(record), .. } => Some(record.clone()),
                _ => None,
            }))
    }

    fn exposure_obligation(
        &self,
        obligation_id: &str,
    ) -> Result<Option<ExposureObligation>, LogError> {
        // The mirror's resolver, projecting the columns the durable one projects and dropping
        // `primitive_atom`/`provider_scope` rather than handing the provider's identifiers back.
        Ok(self
            .exposure_obligations
            .iter()
            .find(|o| o.obligation_id == obligation_id)
            .map(|o| ExposureObligation {
                obligation_id: o.obligation_id.clone(),
                direction: o.direction,
                generation: o.generation,
                contributor_attempt_id: o.contributor_attempt_id.clone(),
                // This log keeps no creation instant on the mirror row (nothing has read one); the
                // obligation is created in the same transaction as its contributor's adjudication fact, so
                // that fact's clamped instant is it.
                created_at: self
                    .attempt_facts
                    .iter()
                    .find(|f| {
                        f.attempt_id == o.contributor_attempt_id
                            && f.kind == crate::attempt::FactKind::AdjudicatedUnresolved
                    })
                    .map(|f| f.created_at.clone())
                    .unwrap_or_default(),
                retired_at: o.retired_at.clone(),
            }))
    }

    fn unknown_review(
        &self,
        now_unix_secs: u64,
        review_after_seconds: u64,
    ) -> Result<UnknownReviewReport, LogError> {
        use crate::attempt::{AttemptClass, FactKind};
        let cutoff =
            crate::prestate::rfc3339_utc(now_unix_secs.saturating_sub(review_after_seconds));
        // The clock question, asked with the write side's own comparison. The high-water is this
        // log's whole fact ledger, the same maximum every write path here clamps against.
        let clock_rollback_detected = unknown_review_rollback(
            &crate::prestate::rfc3339_utc(now_unix_secs),
            self.attempt_facts
                .iter()
                .map(|f| f.created_at.as_str())
                .max()
                .unwrap_or_default(),
        )?;
        let mut report = Vec::new();
        // In the durable path's order (`ORDER BY i.seq`). The scan used to walk the fact log in
        // append (claim) order, which differs once two operations are admitted before either is
        // claimed. An operator's review report is one read from a decision; both stores must present
        // it the same way.
        let mut claims: Vec<(u64, &crate::attempt::Fact)> = self
            .attempt_facts
            .iter()
            .filter(|f| f.kind == FactKind::Claim)
            .map(|f| {
                (
                    self.entries
                        .get(&f.operation_id)
                        .map(|intent| intent.seq)
                        .unwrap_or(u64::MAX),
                    f,
                )
            })
            .collect();
        claims.sort_by_key(|(seq, _)| *seq);
        for (_, claim) in claims {
            let attempt_id = claim.attempt_id.clone();
            let state = self.fold_stored_attempt(&attempt_id)?;
            if state.class() != Some(AttemptClass::IssuedOrUnknown) {
                continue;
            }
            let unknown_since = self
                .attempt_facts
                .iter()
                .filter(|f| f.attempt_id == attempt_id)
                .rev()
                .find(|f| f.kind == FactKind::AckAmbiguous)
                .or_else(|| {
                    self.attempt_facts
                        .iter()
                        .find(|f| f.attempt_id == attempt_id && f.kind == FactKind::SendAuthorized)
                })
                .map(|f| f.created_at.clone())
                .ok_or_else(|| {
                    LogError(format!(
                        "unknown_review: attempt '{attempt_id}' classifies ISSUED_OR_UNKNOWN with \
                         no authorization fact"
                    ))
                })?;
            report.push(UnknownReviewRow {
                attempt_id,
                idempotency_key: claim.operation_id.clone(),
                // A detected rollback is review-now, unconditionally: the age verdict is what the clamp
                // froze, so deferring to it would read the very number the rollback corrupted.
                review_due: clock_rollback_detected || unknown_since <= cutoff,
                unknown_since,
                reconcile_cap_reached: state.reconcile_count
                    >= crate::attempt::GrammarLimits::DEFAULT.reconcile_lifetime_cap,
            });
        }
        Ok(UnknownReviewReport {
            clock_rollback_detected,
            rows: report,
        })
    }

    fn record_capacity_config(
        &mut self,
        new: crate::capacity::CapacityConfig,
    ) -> Result<(), LogError> {
        new.validate()
            .map_err(|e| LogError(format!("record_capacity_config refused: {e}")))?;
        self.capacity_generation += 1;
        // The same fit-check `activation_fits` answers, over current occupancy: the fake's no-traffic
        // activation arm, like the durable `record_capacity_config`'s own. (`activate_pending_if_fits`,
        // the trigger twin every status-writing path runs, is the other activation path; see the
        // `capacity_pending` field doc.)
        let occupancy = self.live_occupancy();
        if crate::capacity::activation_fits(occupancy, &new) {
            self.capacity_current = new;
            self.capacity_pending = None;
        } else {
            // Latest-generation-wins: a second non-fitting call supersedes whatever was pending, as the
            // durable ledger's newest-capacity-act rule does (`effective_bounds`).
            self.capacity_pending = Some((self.capacity_generation, new));
        }
        Ok(())
    }

    fn registered_key_fingerprint(&self) -> Result<Option<String>, LogError> {
        Ok(self.commitment_key_fingerprint.clone())
    }

    fn register_key_fingerprint(&mut self, fingerprint: &str) -> Result<(), LogError> {
        if fingerprint.is_empty() {
            return Err(LogError("register_key_fingerprint: empty fingerprint".into()));
        }
        // Twin parity: SQLite's `length()` stops at the first NUL, so the DDL `CHECK` refuses a
        // NUL-led fingerprint; the twin refuses any NUL (never weaker than production).
        if fingerprint.contains('\0') {
            return Err(LogError("register_key_fingerprint: fingerprint carries a NUL".into()));
        }
        if self.commitment_key_fingerprint.is_some() {
            return Err(LogError("commitment_key_registry is write-once".into()));
        }
        self.commitment_key_fingerprint = Some(fingerprint.to_string());
        Ok(())
    }

    fn record_knob_act(&mut self, act: crate::config_knobs::KnobAct) -> Result<u64, LogError> {
        // The durable store's refusal, mirrored: the payload is re-read through its kind's reader
        // before anything is appended.
        let payload = act.checked_payload().map_err(|e| LogError(format!("record_knob_act: {e}")))?;
        Ok(self.append_knob_row(act.kind(), payload))
    }

    fn knob_state(&self) -> Result<crate::config_knobs::KnobState, LogError> {
        self.knob_state_typed().map_err(|e| LogError(format!("knob_state: {e}")))
    }

    fn mint_plan(&mut self, root_key: &crate::commitment::CommitmentKey, spec: crate::plan::PlanSpec) -> Result<crate::plan::MintedPlan, crate::plan::PlanStoreError> {
        use crate::plan::{MintedPlan, PlanId, PlanStoreError};
        plan_spec_preflight(&spec)?;
        let plan_id = PlanId::mint()?;
        let facts = self.plan_member_facts(&spec.account, &spec.member_refs)?;
        let knobs = self.knob_state_typed().map_err(|e| PlanStoreError::Knob(e.to_string()))?;
        // The latch advance is the one write before the assembler can still refuse: on a refusal
        // it is put back — the twin's analogue of the durable transaction's rollback.
        let latch_before = self.time_high_water.clone();
        let minted_at = self.sticky_effective_now("mint_plan").map_err(|e| PlanStoreError::Store(e.0))?;
        let inputs = PlanMintInputs { knobs, control_epoch: self.control_epoch, minted_at };
        let plan = match assemble_plan(root_key, spec, plan_id, facts, inputs) {
            Ok(plan) => plan,
            Err(refusal) => {
                self.time_high_water = latch_before;
                return Err(refusal);
            }
        };
        if self.plans.contains_key(&plan.plan_id) {
            self.time_high_water = latch_before;
            return Err(PlanStoreError::Store(format!("plan id '{}' is already minted", plan.plan_id.0)));
        }
        let minted = MintedPlan::of(&plan);
        self.plans.insert(plan.plan_id.clone(), plan);
        Ok(minted)
    }

    fn plan(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::plan::TriagePlan>, LogError> {
        // The durable read boundary's last step, mirrored: a stored plan that fails its own shape
        // check is a store error, never a plan.
        self.plans
            .get(plan_id)
            .map(|plan| {
                plan.validate_shape()
                    .map_err(|e| LogError(format!("plan '{}' does not read back: {e:?}", plan_id.0)))?;
                Ok(plan.clone())
            })
            .transpose()
    }

    fn record_approval(&mut self, root_key: &crate::commitment::CommitmentKey, plan_id: &crate::plan::PlanId, approver: &str, rendered: crate::plan::RenderedView) -> Result<crate::plan::ApprovalEvidence, crate::plan::PlanStoreError> {
        use crate::plan::PlanStoreError;
        let plan = self
            .plan(plan_id)
            .map_err(|e| PlanStoreError::Store(e.0))?
            .ok_or_else(|| PlanStoreError::PlanNotFound(plan_id.clone()))?;
        if self.approvals.contains_key(plan_id) {
            return Err(PlanStoreError::AlreadyApproved);
        }
        // The durable path's two checks, mirrored: the epoch refusal writes nothing; the expiry
        // refusal keeps the latch advance (the durable one commits it).
        if plan.control_epoch != self.control_epoch {
            return Err(PlanStoreError::EpochMismatch { plan: plan.control_epoch, current: self.control_epoch });
        }
        let knobs = self.knob_state_typed().map_err(|e| PlanStoreError::Knob(e.to_string()))?;
        let latch_before = self.time_high_water.clone();
        let approved_at = self.sticky_effective_now("record_approval").map_err(|e| PlanStoreError::Store(e.0))?;
        if plan.expires_at.as_str() <= approved_at.as_str() {
            return Err(PlanStoreError::Expired { expires_at: plan.expires_at.clone(), effective_now: approved_at });
        }
        match build_approval_evidence(root_key, &plan, approver, approved_at, rendered, knobs.red_bypass.generation) {
            Ok(evidence) => {
                self.approvals.insert(plan_id.clone(), evidence.clone());
                Ok(evidence)
            }
            Err(refusal) => {
                self.time_high_water = latch_before;
                Err(refusal)
            }
        }
    }

    fn approval(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::plan::ApprovalEvidence>, LogError> {
        Ok(self.approvals.get(plan_id).cloned())
    }

    fn start_episode(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::EpisodeStart, crate::episode::EpisodeRefusal> {
        use crate::episode::{Episode, EpisodeEvent, EpisodeRefusal as R, EpisodeStart, EpisodeStatus};
        // The durable `start_episode_in`, mirrored: the same checks in the same order.
        let Some(plan) = self.plans.get(plan_id) else {
            return Err(R::NoPlan);
        };
        let (plan_epoch, expires_at) = (plan.control_epoch, plan.expires_at.clone());
        if !self.approvals.contains_key(plan_id) {
            return Err(R::NotApproved);
        }
        // The durable resume path's invalidation, mirrored; a terminal episode's transition refusal
        // is dropped there too.
        if plan_epoch != self.control_epoch {
            let current = self.control_epoch;
            if self.episodes.get(plan_id).is_some_and(|e| !e.status.token().is_terminal()) {
                self.invalidate_episode(plan_id, crate::episode::InvalidationReason::EpochMismatch { plan: plan_epoch, current })?;
            }
            return Err(R::EpochMismatch { plan: plan_epoch, current });
        }
        let now = self.plan_clock(plan_id, &expires_at, "start_episode")?;
        if expires_at.as_str() <= now.as_str() {
            if self.episodes.get(plan_id).is_some_and(|e| !e.status.token().is_terminal()) {
                self.invalidate_episode(plan_id, crate::episode::InvalidationReason::Expired)?;
            }
            return Err(R::Expired { expires_at, effective_now: now });
        }
        if let Some(existing) = self.episodes.get(plan_id) {
            let token = existing.status.token();
            return if token.is_terminal() { Err(R::Terminal(token)) } else { Ok(EpisodeStart::Resumed(existing.clone())) };
        }
        self.next_episode += 1;
        let episode = Episode {
            plan_id: plan_id.clone(),
            episode_id: format!("mem-episode-{}", self.next_episode),
            status: EpisodeStatus::Active,
            generation: 1,
            // Equal to the plan's epoch by construction (the refusal above).
            claim_epoch: self.control_epoch,
            started_at: now.clone(),
            ready_at: None,
            completed_at: None,
        };
        self.episodes.insert(plan_id.clone(), episode.clone());
        self.episode_journal.push(InMemoryEpisodeJournalRow { plan_id: plan_id.clone(), generation: 1, status: episode.status.token(), reason: None, event: EpisodeEvent::Start, at: now });
        Ok(EpisodeStart::Started(episode))
    }

    fn episode(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::Episode>, LogError> {
        Ok(self.episodes.get(plan_id).cloned())
    }

    fn episode_status_check(&self, plan_id: &crate::plan::PlanId) -> Result<Option<crate::episode::EpisodeStatusToken>, LogError> {
        Ok(self.episodes.get(plan_id).map(|e| e.status.token()))
    }

    fn mark_ready(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::ReadyOutcome, crate::episode::EpisodeRefusal> {
        use crate::episode::{EpisodeEvent, EpisodeRefusal as R, EpisodeStatusToken, ReadyOutcome};
        let Some(e) = self.episodes.get(plan_id).cloned() else {
            return Err(R::NoEpisode);
        };
        let token = e.status.token();
        if token.is_terminal() {
            return Err(R::Terminal(token));
        }
        if token != EpisodeStatusToken::Active {
            return Err(R::NotActive(token));
        }
        if e.ready_at.is_some() {
            return Ok(ReadyOutcome::AlreadyReady);
        }
        let began = self.send_authorized_children(plan_id);
        if began > 0 {
            return Err(R::DispatchBegan { send_authorized_children: began });
        }
        let now = self.sticky_effective_now("mark_ready")?;
        let w = EpisodeWrite { status: e.status.clone(), ready_at: Some(now.clone()), completed_at: e.completed_at.clone(), event: EpisodeEvent::Ready, at: now };
        self.write_episode(plan_id, e.generation, &w).map(|_| ReadyOutcome::Ready)
    }

    fn invalidate_episode(&mut self, plan_id: &crate::plan::PlanId, reason: crate::episode::InvalidationReason) -> Result<(), crate::episode::EpisodeRefusal> {
        use crate::episode::{assert_transition, EpisodeEvent, EpisodeRefusal as R, EpisodeStatus, EpisodeStatusToken, InvalidationReason};
        let Some(e) = self.episodes.get(plan_id).cloned() else {
            return Err(R::NoEpisode);
        };
        assert_transition(e.status.token(), EpisodeStatusToken::Invalidated)?;
        if matches!(reason, InvalidationReason::StalePreflight { .. }) {
            let began = self.send_authorized_children(plan_id);
            if began > 0 {
                return Err(R::DispatchBegan { send_authorized_children: began });
            }
        }
        let now = self.sticky_effective_now("invalidate_episode")?;
        let w = EpisodeWrite { status: EpisodeStatus::Invalidated(reason), ready_at: e.ready_at.clone(), completed_at: e.completed_at.clone(), event: EpisodeEvent::Transition, at: now };
        self.write_episode(plan_id, e.generation, &w).map(|_| ())
    }

    fn complete_episode_if_done(&mut self, plan_id: &crate::plan::PlanId) -> Result<crate::episode::Completion, LogError> {
        use crate::episode::{assert_transition, Completion, EpisodeEvent, EpisodeStatus, EpisodeStatusToken, InvalidationReason};
        let Some(e) = self.episodes.get(plan_id).cloned() else {
            return Ok(Completion::NoEpisode);
        };
        let token = e.status.token();
        if token.is_terminal() {
            return Ok(Completion::AlreadyTerminal(token));
        }
        let plan_epoch = self
            .plans
            .get(plan_id)
            .ok_or_else(|| LogError(format!("complete_episode_if_done: plan '{}' vanished under its episode", plan_id.0)))?
            .control_epoch;
        // The durable epoch terminal, mirrored: decided before the exact-N branch, for an active or
        // paused episode alike.
        if plan_epoch != self.control_epoch {
            let reason = InvalidationReason::EpochMismatch { plan: plan_epoch, current: self.control_epoch };
            self.invalidate_episode(plan_id, reason.clone()).map_err(|r| LogError(format!("complete_episode_if_done: {r}")))?;
            return Ok(Completion::Invalidated(reason));
        }
        let plan = self
            .plans
            .get(plan_id)
            .ok_or_else(|| LogError(format!("complete_episode_if_done: plan '{}' vanished under its episode", plan_id.0)))?;
        let expires_at = plan.expires_at.clone();
        let members: std::collections::BTreeSet<&str> = plan.members.iter().map(|m| m.message_ref.as_str()).collect();
        let total = members.len() as u64;
        // One child per member (the durable partial UNIQUE index; `record()` refuses a second key
        // for one member here by `KeyMismatch`), counted over the members only.
        let (mut minted, mut terminal) = (0u64, 0u64);
        for intent in self.entries.values() {
            if let Some(link) = &intent.command.plan_child {
                if link.plan_id == *plan_id && members.contains(link.member_ref.as_str()) {
                    minted += 1;
                    if intent.status.is_terminal() {
                        terminal += 1;
                    }
                }
            }
        }
        if token != EpisodeStatusToken::Active {
            return Ok(Completion::Incomplete { total, minted, terminal });
        }
        let now = self.plan_clock(plan_id, &expires_at, "complete_episode_if_done")?;
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
        self.write_episode(plan_id, e.generation, &w).map_err(|r| LogError(format!("complete_episode_if_done: {r}")))?;
        Ok(completion)
    }
}

/// One `episode_journal` mirror row — the durable row's columns, typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InMemoryEpisodeJournalRow {
    pub(crate) plan_id: crate::plan::PlanId,
    pub(crate) generation: u64,
    pub(crate) status: crate::episode::EpisodeStatusToken,
    pub(crate) reason: Option<String>,
    pub(crate) event: crate::episode::EpisodeEvent,
    at: String,
}
