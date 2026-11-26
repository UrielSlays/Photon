//! PREPARE and admission: insert-or-nothing capture, basis refusals, and the recovery pipeline.

use super::*;
use crate::fixtures::{fixture_basis, fixture_observation, fixture_restore};

// --: PREPARE — insert-or-nothing at the head (§2.2b) --------------------------

#[test]
fn execute_observes_prepares_then_dispatches_when_journal_required() {
    // §2.2 pipeline + PRE-STATE-BEFORE-DISPATCH: observe → PREPARE (row inserted) →
    // apply. Capture-on is generation-1 default (stage-1 first-run act).
    let path = unique_temp_db_path("prepare-pipeline");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-prep-1")).unwrap();
    assert_eq!(bus.connector().observe_count(), 1, "exactly one observation");
    assert_eq!(bus.connector().apply_count(), 1);
    let conn = raw_conn(&path);
    let (observed, source, cap_epoch): (String, String, i64) = conn
        .query_row(
            "SELECT p.observed, p.source, p.captured_epoch FROM pre_state p
                  JOIN intents i ON i.intent_id = p.intent_id
                 WHERE i.idempotency_key = 'k-prep-1';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(source, "live_read");
    assert_eq!(cap_epoch, 1);
    assert!(
        observed.contains("membership:INBOX"),
        "typed observed projection, got {observed}"
    );
    // Dispatch happened AFTER prepare: the connector's observe fired before apply.
    assert!(bus.connector().observed_before_applied());
    drop(conn);
    std::fs::remove_file(&path).ok();
}

#[test]
fn capture_off_dispatches_without_observation_or_row() {
    // §1c/§2.2b capture-off contract: journal_required=0 ⇒ no observe, no row — and the
    // capture-off scan direction treats any such row as ILLEGAL.
    let path = unique_temp_db_path("capture-off");
    SqliteIntentLog::open(&path).expect("bootstrap the store + its generation-1 act");
    append_config_act(&path, r#"{"capture":"off"}"#); // generation 2 act
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-off-1")).unwrap();
    assert_eq!(bus.connector().observe_count(), 0);
    assert_eq!(bus.connector().apply_count(), 1, "capture-off still dispatches");
    let rows: i64 = raw_conn(&path)
        .query_row("SELECT COUNT(*) FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    // NON-VACUITY CONTROL: "no row" must be capture-OFF's doing, not "the pipeline does
    // nothing". Turn capture back ON (a NEW act — the ledger is append-only) and admit a
    // second operation on the SAME store: that one DOES observe and DOES journal, and the
    // capture-off operation still owns no row.
    append_config_act(&path, r#"{"capture":"on"}"#); // generation 3
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&Command::new(
        "k-on-1",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-2".into(),
        },
    ))
    .unwrap();
    assert_eq!(bus.connector().observe_count(), 1, "capture-on observes");
    let journalled: Vec<String> = raw_conn(&path)
        .prepare(
            "SELECT i.idempotency_key FROM pre_state p
                   JOIN intents i ON i.intent_id = p.intent_id;",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        journalled,
        vec!["k-on-1".to_string()],
        "only the capture-ON operation owns a journal row"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_in_memory_log_mirrors_prepare_semantically() {
    // The fake is a MIRROR, not a stub: PREPARE inserts the same facts the durable table
    // holds (§2.3 projection + materialized timestamps + the bound epoch/generation), the
    // row's EXISTENCE is the phase, and a second PREPARE never re-captures (§2.2).
    // Through the bus first: capture-on is this log's stated default, so execute observes
    // and prepares exactly as it does on SQLite.
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::new());
    bus.execute(&archive_cmd("k-mem-1")).unwrap();
    assert_eq!(bus.connector().observe_count(), 1);
    assert!(bus.log().prepared("k-mem-1").unwrap());
    let journal = bus.log().journal("k-mem-1").expect("PREPARE inserted a row");
    assert!(
        journal.row.observed.contains("membership:INBOX"),
        "typed observed projection, got {}",
        journal.row.observed
    );
    assert_eq!(journal.captured_epoch, 1, "this log's epoch is the constant 1");
    assert_eq!(journal.mode_generation, 1, "the compiled first-run act");
    assert!(
        journal.undo_offer_until > journal.fetched_at,
        "the offer window is bound AT capture ({} → {})",
        journal.fetched_at,
        journal.undo_offer_until
    );

    // NEVER re-capture (§2.2): a second PREPARE reports AlreadyPrepared and rewrites
    // nothing — driven at the log level, since only the bus's ONE pipeline may call it.
    let mut log = InMemoryIntentLog::new();
    let cmd = archive_cmd("k-mem-2");
    let basis = fixture_basis(&cmd);
    log.record(&cmd, &basis).unwrap();
    let first = prestate::journal_row_from_observation(&fixture_observation(&basis), &basis);
    assert_eq!(
        log.prepare("k-mem-2", &first).unwrap(),
        prestate::PrepareOutcome::Prepared
    );
    let before = log.journal("k-mem-2").expect("row").clone();
    // A WELL-FORMED second row (validation runs before the AlreadyPrepared check —
    // the boundary refuses malformed rows outright, so the never-re-capture
    // claim is proven with a row that would otherwise be insertable).
    let overwrite = prestate::JournalRow {
        request_id: Some("would-be-second-read".into()),
        ..prestate::journal_row_from_observation(&fixture_observation(&basis), &basis)
    };
    assert_eq!(
        log.prepare("k-mem-2", &overwrite).unwrap(),
        prestate::PrepareOutcome::AlreadyPrepared
    );
    assert_eq!(
        log.journal("k-mem-2"),
        Some(&before),
        "an already-prepared row is never overwritten"
    );
}

/// Bumps the durable control epoch from INSIDE `observe` — i.e. between the admission
/// transaction (which bound `admitted_control_epoch`) and PREPARE. Stands in for the
/// stage-4 sever, which is the only real producer of an epoch bump.
struct EpochBumpingConnector {
    path: std::path::PathBuf,
    apply_count: std::cell::Cell<usize>,
}
impl EpochBumpingConnector {
    fn new(path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            apply_count: std::cell::Cell::new(0),
        }
    }
    fn apply_count(&self) -> usize {
        self.apply_count.get()
    }
}
impl Connector for EpochBumpingConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_count.set(self.apply_count.get() + 1);
        Ok(())
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(fixture_basis(command))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        let conn = rusqlite::Connection::open(&self.path)
            .map_err(|e| ConnectorError::transient(e.to_string()))?;
        conn.execute("UPDATE control_epoch SET epoch = 2 WHERE id = 1;", [])
            .map_err(|e| ConnectorError::transient(e.to_string()))?;
        Ok(fixture_observation(basis))
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)
    }
}

#[test]
fn prepare_is_epoch_fenced_and_parks_the_intent() {
    // §2.2b: control_epoch ≠ admitted_control_epoch at PREPARE ⇒ the sever fence — the
    // intent PARKS (Pending, undispatched, no row). Stage-4 sever terminalizes; the bump
    // here stands in for it. The bump lands BETWEEN admission and PREPARE by riding the
    // observe seam, so the fence is exercised through the REAL execute pipeline (the
    // plan's recover-driven arrangement belongs to which is not this change).
    let path = unique_temp_db_path("epoch-fence");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        EpochBumpingConnector::new(&path),
    );
    let parked = bus.execute(&archive_cmd("k-fence-1"));
    assert!(
        matches!(parked, Err(ExecuteError::InProgress)),
        "a fenced PREPARE parks the intent for recovery, got {parked:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        0,
        "a fenced intent must not dispatch"
    );
    let status: String = raw_conn(&path)
        .query_row(
            "SELECT status FROM intents WHERE idempotency_key='k-fence-1';",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "pending", "the fenced intent PARKS");
    let rows: i64 = raw_conn(&path)
        .query_row("SELECT COUNT(*) FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "insert-or-nothing: a fenced PREPARE inserts NOTHING");
    std::fs::remove_file(&path).ok();
}

#[test]
fn admitted_epoch_is_current_flips_on_hand_bumped_epoch() {
    // The undo child's epoch fence reads this: undo children own no journal row, so
    // PREPARE's in-transaction fence never runs for them. Hand-bumping the singleton
    // stands in for the stage-4 sever (the stage-2 pattern).
    let path = unique_temp_db_path("undo-epoch-current");
    {
        let mut bus = sqlite_bus_with_counting_connector(&path);
        bus.execute(&archive_cmd("k-epoch-cur")).unwrap();
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    assert!(
        log.admitted_epoch_is_current("k-epoch-cur").unwrap(),
        "admitted at epoch 1, current epoch is 1"
    );
    raw_conn(&path)
        .execute("UPDATE control_epoch SET epoch = 2 WHERE id = 1;", [])
        .expect("hand-bump the control epoch");
    assert!(
        !log.admitted_epoch_is_current("k-epoch-cur").unwrap(),
        "a severed fence makes the admitted epoch stale"
    );
    assert!(
        log.admitted_epoch_is_current("k-epoch-missing").is_err(),
        "a missing key is an ERROR — never a silent 'current'"
    );
    std::fs::remove_file(&path).ok();
}

/// `resolve_basis` freezes the OLD native identity; `observe` answers for a DIFFERENT one —
/// the provider rebound the local ref between admission and capture (BASIS-6 at observation).
struct RebindingConnector {
    frozen: String,
    observed: String,
    apply_count: std::cell::Cell<usize>,
}
impl RebindingConnector {
    fn new(frozen: &str, observed: &str) -> Self {
        Self {
            frozen: frozen.to_string(),
            observed: observed.to_string(),
            apply_count: std::cell::Cell::new(0),
        }
    }
    fn apply_count(&self) -> usize {
        self.apply_count.get()
    }
}
impl Connector for RebindingConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_count.set(self.apply_count.get() + 1);
        Ok(())
    }
    fn resolve_basis(&self, _c: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(test_basis(&self.frozen))
    }
    fn observe(
        &self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(&test_basis(&self.observed)))
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)
    }
}

/// A connector whose `resolve_basis` REFUSES — the documented-retryable BASIS-2 arm (the
/// resolver has no seed yet, a role is not cached, a store read faulted). Nothing durable
/// happens: the refusal is raised BEFORE `record()`.
struct RefusingBasisConnector;
impl Connector for RefusingBasisConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        panic!("a refused admission must never reach the connector's apply");
    }
    fn resolve_basis(&self, _c: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Err(ResolveBasisError("test: resolver unseeded (retryable)".into()))
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(basis))
    }
    fn restore(
        &self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
        _p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        panic!("a refused admission must never reach the connector's restore");
    }
}

#[test]
fn a_basis_refusal_is_not_reported_as_a_durable_store_failure() {
    // BASIS-2 refusals are PRE-durable and documented-RETRYABLE: nothing was recorded, so
    // the same command may simply be re-submitted. `ExecuteError::Log`'s public contract is
    // the opposite signal — "the durable intent could not be persisted", the store is in
    // doubt — so mapping a refusal onto it tells a caller to treat a re-submittable command
    // as a storage incident. The refusal needs its own variant.
    let path = unique_temp_db_path("basis-refusal-variant");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        RefusingBasisConnector,
    );
    let err = bus.execute(&archive_cmd("k-refused")).unwrap_err();
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "a refused admission commits NO intent row"
    );
    assert!(
        matches!(err, ExecuteError::AdmissionRefused(ref m) if m.contains("resolver unseeded")),
        "a pre-durable retryable refusal is its own signal, not a store failure, got {err:?}"
    );
    std::fs::remove_file(&path).ok();
}

/// An `IntentLog` that models a PEER claiming the key in the window `execute()` cannot see:
/// between its initial `get` (the classify read) and the basis resolution that follows.
/// `get` answers `None` for the FIRST call and the peer's durable row for every call after.
///
/// Nothing else is exercised: with a refusing resolver, `execute()` returns before it reaches
/// the atomic claim — which is precisely the defect (the refusal is raised in a window where
/// "nothing durable was written" has already stopped being true).
struct PeerClaimsBetweenGetAndResolveLog {
    peer: Option<Intent>,
    gets: std::cell::Cell<usize>,
}

impl PeerClaimsBetweenGetAndResolveLog {
    fn new(peer: Option<Intent>) -> Self {
        Self {
            peer,
            gets: std::cell::Cell::new(0),
        }
    }
}

impl IntentLog for PeerClaimsBetweenGetAndResolveLog {
    fn get(&self, key: &str) -> Result<Option<Intent>, LogError> {
        let n = self.gets.get();
        self.gets.set(n + 1);
        if n == 0 {
            return Ok(None); // execute's classify read: the key really was free.
        }
        Ok(self
            .peer
            .clone()
            .filter(|i| i.command.idempotency_key == key))
    }
    fn record(&mut self, _: &Command, _: &prestate::FrozenBasis) -> Result<Claim, LogError> {
        unreachable!("a refused admission never reaches the claim")
    }
    fn set_status_if(
        &mut self,
        _: &str,
        _: StatusPrecondition,
        _: IntentStatus,
    ) -> Result<StatusWrite, LogError> {
        unimplemented!()
    }
    fn dead_letter_if_quiescent(&mut self, _: &str) -> Result<DeadLetterWrite, LogError> {
        unimplemented!()
    }
    fn verify_undo_pair(
        &mut self,
        _: &str,
        _: &str,
        _: UndoPairChild,
    ) -> Result<UndoPairFlip, LogError> {
        unimplemented!()
    }
    fn unreconciled(&self) -> Result<Vec<Intent>, LogError> {
        unimplemented!()
    }
    fn applied_unprojected_forward_intents(&self) -> Result<Vec<Intent>, LogError> {
        unimplemented!()
    }
    fn charge_and_dead_letter_if_quiescent(
        &mut self,
        _: &str,
        _: u32,
    ) -> Result<TransientCharge, LogError> {
        unimplemented!()
    }
    fn dead_letters(&self) -> Result<Vec<Intent>, LogError> {
        unimplemented!()
    }
    fn latest_intent_for_message_ref(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<Intent>, LogError> {
        unimplemented!()
    }
    fn has_non_terminal_native_predecessor(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: u64,
        _: &str,
    ) -> Result<bool, LogError> {
        unimplemented!()
    }
    fn prepare(
        &mut self,
        _: &str,
        _: &prestate::JournalRow,
    ) -> Result<prestate::PrepareOutcome, LogError> {
        unimplemented!()
    }
    fn prepared(&self, _: &str) -> Result<bool, LogError> {
        unimplemented!()
    }
    /// This log never journals, so the retry gate never reads it.
    fn captured_pre_state(
        &self,
        _: &str,
    ) -> Result<Option<crate::CapturedPreState>, LogError> {
        unimplemented!()
    }
    /// No dispatch on this log reaches a witnessed success.
    fn record_effect_witness(
        &mut self,
        _: &str,
        _: &EffectWitness,
        _: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<(), LogError> {
        unimplemented!()
    }
    fn effect_witness(&self, _: &str) -> Result<Option<EffectWitnessRow>, LogError> {
        unimplemented!()
    }
    fn replace_journal_row(
        &mut self,
        _: &str,
        _: &crate::prestate::JournalRow,
    ) -> Result<JournalReplaceOutcome, LogError> {
        unimplemented!()
    }
    fn undo_context(&mut self, _: &str) -> Result<Option<UndoContext>, LogError> {
        unimplemented!()
    }
    fn admitted_epoch_is_current(&self, _: &str) -> Result<bool, LogError> {
        unimplemented!()
    }
        fn claim_attempt(
        &mut self,
        _: &str,
        _: &AttemptClaim,
    ) -> Result<ClaimOutcome, LogError> {
        unimplemented!()
    }
        fn authorize_send(
        &mut self,
        _: &str,
        _: &str,
        _: CaptureBinding,
        _: crate::plan::PlanBinding,
    ) -> Result<SendAuthOutcome, LogError> {
        unimplemented!()
    }
    fn settle_attempt(
        &mut self,
        _: &str,
        _: &str,
        _: ConnectorVerdict,
        _: u32,
        _: Option<u64>,
    ) -> Result<SettleOutcome, LogError> {
        unimplemented!()
    }
    fn sever(&mut self, _: &str, _: &str) -> Result<SeverOutcome, LogError> {
        unimplemented!()
    }
    /// This double holds NO fact chain, so it has no live attempt to classify — the
    /// honest answer, not a permissive default (the sweep reads it before it dead-letters).
    fn live_attempt(&self, _: &str) -> Result<Option<LiveAttempt>, LogError> {
        Ok(None)
    }
    /// ...and no §5.2d substrate either. These two doors are UNIMPLEMENTED rather than
    /// answered permissively: a double that "adjudicated" nothing would let a caller believe
    /// an unknown was closed. The REPORT is the honest empty (no chain, no unknowns).
    fn adjudicate(
        &mut self,
        _: &str,
        _: &str,
        _: &str,
        _: crate::attempt::AdjudicationReason,
        _: crate::attempt::AcceptedRisk,
    ) -> Result<AdjudicationOutcome, LogError> {
        unimplemented!()
    }
    fn record_late_ack(
        &mut self,
        _: &str,
        _: &str,
        _: crate::attempt::LateAck,
    ) -> Result<LateAckOutcome, LogError> {
        unimplemented!()
    }
    fn annotate_late_ambiguous_observation(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<String, LogError> {
        unimplemented!()
    }
    /// No fact chain ⇒ no `LATE_ACK_*` ⇒ nothing has resolved. Honest, not permissive:
    /// `Unresolved` is what "no late ack exists" means on every impl.
    fn adjudicated_history(&self, _: &str) -> Result<AdjudicatedHistory, LogError> {
        Ok(AdjudicatedHistory::Unresolved)
    }
    /// No fact chain ⇒ no `FAILED_PRE_SEND` ⇒ no exposure block to name.
    fn exposure_block(
        &self,
        _: &str,
    ) -> Result<Option<crate::attempt::ExposureBlock>, LogError> {
        Ok(None)
    }
    /// …and no plan-admission record either.
    fn plan_refusal(&self, _: &str) -> Result<Option<crate::attempt::PlanRefusalRecord>, LogError> {
        Ok(None)
    }
    fn exposure_obligation(&self, _: &str) -> Result<Option<ExposureObligation>, LogError> {
        Ok(None)
    }
    fn unknown_review(&self, _: u64, _: u64) -> Result<UnknownReviewReport, LogError> {
        Ok(UnknownReviewReport::default())
    }
    fn record_capacity_config(
        &mut self,
        _: crate::capacity::CapacityConfig,
    ) -> Result<(), LogError> {
        unimplemented!()
    }
    fn registered_key_fingerprint(&self) -> Result<Option<String>, LogError> {
        unimplemented!()
    }
    fn register_key_fingerprint(&mut self, _: &str) -> Result<(), LogError> {
        unimplemented!()
    }
    fn record_knob_act(&mut self, _: crate::config_knobs::KnobAct) -> Result<u64, LogError> {
        unimplemented!()
    }
    fn knob_state(&self) -> Result<crate::config_knobs::KnobState, LogError> {
        unimplemented!()
    }
    fn mint_plan(&mut self, _: &crate::commitment::CommitmentKey, _: crate::plan::PlanSpec) -> Result<crate::plan::MintedPlan, crate::plan::PlanStoreError> {
        unimplemented!()
    }
    fn plan(&self, _: &crate::plan::PlanId) -> Result<Option<crate::plan::TriagePlan>, LogError> {
        unimplemented!()
    }
    fn record_approval(&mut self, _: &crate::commitment::CommitmentKey, _: &crate::plan::PlanId, _: &str, _: crate::plan::RenderedView) -> Result<crate::plan::ApprovalEvidence, crate::plan::PlanStoreError> {
        unimplemented!()
    }
    fn approval(&self, _: &crate::plan::PlanId) -> Result<Option<crate::plan::ApprovalEvidence>, LogError> {
        unimplemented!()
    }
    fn start_episode(&mut self, _: &crate::plan::PlanId) -> Result<crate::episode::EpisodeStart, crate::episode::EpisodeRefusal> {
        unimplemented!()
    }
    fn episode(&self, _: &crate::plan::PlanId) -> Result<Option<crate::episode::Episode>, LogError> {
        unimplemented!()
    }
    fn episode_status_check(&self, _: &crate::plan::PlanId) -> Result<Option<crate::episode::EpisodeStatusToken>, LogError> {
        unimplemented!()
    }
    fn mark_ready(&mut self, _: &crate::plan::PlanId) -> Result<crate::episode::ReadyOutcome, crate::episode::EpisodeRefusal> {
        unimplemented!()
    }
    fn invalidate_episode(&mut self, _: &crate::plan::PlanId, _: crate::episode::InvalidationReason) -> Result<(), crate::episode::EpisodeRefusal> {
        unimplemented!()
    }
    fn complete_episode_if_done(&mut self, _: &crate::plan::PlanId) -> Result<crate::episode::Completion, LogError> {
        unimplemented!()
    }
}

#[test]
fn a_resolver_failure_after_a_peer_claimed_the_key_reports_the_row_not_admission_refused() {
    // THE RED. `AdmissionRefused` carries a documented PROMISE: the refusal was
    // raised BEFORE `record()`, so nothing durable was touched and the caller may simply
    // re-submit. Between execute's initial `get` and `resolve_admission_basis` there is a
    // window in which a peer can claim the key — and a resolver failure landing after that
    // claim still surfaced `AdmissionRefused` while a Pending/Applied/Failed row EXISTED. The
    // promise was false: a caller re-submitting "because nothing was written" is talking about
    // a key that is already durably owned, and the truth-table signal it needed
    // (InProgress / Ok-replay / Failed) was replaced by a refusal.
    //
    // The whole truth table, driven off the SAME `decision_outcome(classify(...))` path the
    // record-race arm already uses — plus the control arm that keeps the fix honest: a key
    // that is GENUINELY still absent must still refuse.
    let cmd = archive_cmd("k-raced");
    let peer_with = |status| {
        Some(Intent {
            command: cmd.clone(),
            status,
            seq: 1,
            attempts: 0,
            frozen_basis: Some(test_basis("prov:acct-1/msg-1")),
            journal_required: true,
            projected: false,
            basis_ingest_revision: None,
        })
    };
    /// The expected outcome of one arm, as a predicate over the surfaced error.
    type ArmExpectation = fn(&ExecuteError) -> bool;
    let cases: [(&str, Option<Intent>, ArmExpectation); 3] = [
        ("pending", peer_with(IntentStatus::Pending), |e| {
            matches!(e, ExecuteError::InProgress)
        }),
        ("failed", peer_with(IntentStatus::Failed), |e| {
            matches!(e, ExecuteError::Failed)
        }),
        // The CONTROL: no peer, no row — `AdmissionRefused`'s promise still holds, so the
        // refusal must survive the fix untouched.
        ("absent", None, |e| {
            matches!(e, ExecuteError::AdmissionRefused(_))
        }),
    ];
    for (tag, peer, expected) in cases {
        let mut bus = CommandBus::new(
            PeerClaimsBetweenGetAndResolveLog::new(peer),
            RefusingBasisConnector,
        );
        let err = bus
            .execute(&cmd)
            .expect_err("every arm here is a non-Ok outcome");
        assert!(
            expected(&err),
            "{tag}: a resolver failure must report the DURABLE truth for this key, \
             not a refusal that claims nothing was written; got {err:?}"
        );
    }
    // …and the terminal-replay arm, whose truth-table verdict is `Ok` — a refusal here would
    // have reported failure for an operation that already SUCCEEDED.
    let mut bus = CommandBus::new(
        PeerClaimsBetweenGetAndResolveLog::new(peer_with(IntentStatus::Applied)),
        RefusingBasisConnector,
    );
    assert_eq!(
        bus.execute(&cmd),
        Ok(Executed { witness: WitnessRecord::NotDispatched }),
        "an Applied row a peer committed is a consumed replay, never an admission refusal"
    );
}

#[test]
fn prepare_refuses_after_dispatch_but_stays_idempotent_on_an_existing_row() {
    // PREPARE never read `status` — a direct caller could
    // journal a POST-EFFECT observation onto an Applied/Undoing/Undone intent (§2.2:
    // post-effect observation poisons no-op detection) and flip `prepared()` true,
    // suppressing the open-time JournalGapUnexplained evidence. The INSERT path now
    // requires pre-dispatch `Pending`; an existing row still answers AlreadyPrepared
    // (idempotent — the row, not the status, is the phase).
    //
    // …AND THE REFUSAL IS TYPED ON THE AXIS IT IS OFF (preemptive). The
    // property this witness exists for is UNCHANGED and re-asserted on both halves below:
    // no journal row is ever written and the reverse-gap evidence survives. What changed is
    // the ANSWER — a TERMINAL row is a peer's legitimate closure, so it is reported as one
    // (`PrepareOutcome::Closed`) rather than as a corrupt store; the only NON-terminal
    // non-pre-dispatch phase (`Undoing`) is a store no writer here produces, and still
    // fails LOUD.
    let cmd = Command::new(
        "k-post-effect".to_string(),
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let basis = fixture_basis(&cmd);
    let row = prestate::journal_row_from_observation(&fixture_observation(&basis), &basis);
    let path = unique_temp_db_path("prepare-post-dispatch");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    log.record(&cmd, &basis).unwrap();
    log.set_status_forced("k-post-effect", IntentStatus::Applied).unwrap();
    assert_eq!(
        log.prepare("k-post-effect", &row)
            .expect("a TERMINAL row is a closure, not a store error"),
        prestate::PrepareOutcome::Closed(IntentStatus::Applied),
        "a dispatched intent must never gain a post-effect journal row — it is reported CLOSED"
    );
    assert!(!log.prepared("k-post-effect").unwrap());
    let report = store_open::integrity_scan(&log.conn).unwrap();
    assert!(
        report.iter().any(|e| matches!(e, IntegrityEvidence::JournalGapUnexplained { key } if key == "k-post-effect")),
        "the reverse-gap evidence must SURVIVE the refused post-effect PREPARE; got {report:?}"
    );
    // THE FAIL-LOUD HALF, on the same row: neither pre-dispatch NOR terminal.
    log.set_status_forced("k-post-effect", IntentStatus::Undoing).unwrap();
    let refused = log.prepare("k-post-effect", &row);
    assert!(
        matches!(&refused, Err(LogError(message)) if message.contains("not pre-dispatch")),
        "a phase PREPARE must never meet live stays a hard store error; got {refused:?}"
    );
    assert!(!log.prepared("k-post-effect").unwrap());
    let mut mem = InMemoryIntentLog::new();
    mem.record(&cmd, &basis).unwrap();
    mem.set_status_forced("k-post-effect", IntentStatus::Applied).unwrap();
    assert_eq!(
        mem.prepare("k-post-effect", &row)
            .expect("the in-memory boundary answers identically"),
        prestate::PrepareOutcome::Closed(IntentStatus::Applied)
    );
    assert!(!mem.prepared("k-post-effect").unwrap());
    mem.set_status_forced("k-post-effect", IntentStatus::Undoing).unwrap();
    assert!(
        mem.prepare("k-post-effect", &row).is_err(),
        "…and refuses the non-terminal off-axis phase identically"
    );
    assert!(!mem.prepared("k-post-effect").unwrap());
}

#[test]
fn a_malformed_journal_row_is_refused_by_the_prepare_boundary_on_both_impls() {
    // The journal row IS the PREPARE phase — a direct
    // `IntentLog::prepare` caller persisting garbage strings would flip `prepared()`
    // true and recovery would then skip the real observation before dispatching (a
    // false restoration witness). The boundary validates the row against the intent's
    // frozen basis (JournalRow::validate — the FrozenBasis::validate twin).
    let garbage = prestate::JournalRow {
        observed: "not json".into(),
        touched_atom: "{}".into(),
        resolved_operands: "[]".into(),
        request_id: None,
        observed_label_vector: None,
    };
    let cmd = Command::new(
        "k-prep-boundary".to_string(),
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let path = unique_temp_db_path("prepare-boundary-validate");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    record_basis(&mut log, &cmd).unwrap();
    log.prepare("k-prep-boundary", &garbage)
        .expect_err("the PREPARE boundary must refuse a row it could not honor");
    assert!(
        !log.prepared("k-prep-boundary").unwrap(),
        "a refused PREPARE leaves the intent unprepared"
    );
    let rows: i64 = log
        .conn
        .query_row("SELECT COUNT(*) FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "insert-or-nothing: a refused PREPARE inserts NOTHING");
    let mut mem = InMemoryIntentLog::new();
    record_basis(&mut mem, &cmd).unwrap();
    mem.prepare("k-prep-boundary", &garbage)
        .expect_err("the in-memory boundary refuses identically");
    assert!(!mem.prepared("k-prep-boundary").unwrap());
}

#[test]
fn record_refuses_a_fresh_basis_without_atom_targets() {
    // `CommandBus::resolve_admission_basis` is a BELT, not THE
    // boundary — a direct `IntentLog::record` caller reached the durable store with a
    // basis carrying NO forward target vector `A`, and a row admitted without `A`
    // cannot answer the §3.2 requalification table or the §4.1 no-op kill later. Both
    // impls now run the ADMISSION tier (`FrozenBasis::validate_for_admission`) on the
    // FRESH-INSERT path. A REPLAY against an EXISTING (legacy stage-2) row must NOT be
    // re-validated: those rows keep replaying identically, or every legacy retry turns
    // into an error the caller cannot act on.
    let no_targets = prestate::FrozenBasis {
        atom_targets: std::collections::BTreeMap::new(),
        ..test_basis("prov:acct-1/NATIVE")
    };
    assert!(
        no_targets.validate().is_ok(),
        "precondition: an empty target vector is STORAGE-tier legal (legacy rows re-read)"
    );
    let cmd = archive_cmd("k-no-targets");

    // ARM 1 — the FRESH insert is refused on BOTH impls, and commits nothing.
    let path = unique_temp_db_path("record-admission-targets");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let err = log
        .record(&cmd, &no_targets)
        .expect_err("a fresh row with no forward target vector is not admissible");
    assert!(
        format!("{err:?}").contains("atom_targets"),
        "the refusal NAMES the missing target vector; got {err:?}"
    );
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "a refused record commits NOTHING"
    );
    let mut mem = InMemoryIntentLog::new();
    mem.record(&cmd, &no_targets)
        .expect_err("the in-memory boundary refuses identically");
    assert!(mem.get("k-no-targets").unwrap().is_none());

    // ARM 2 — a REPLAY against an EXISTING legacy row (stage-2 shape: empty targets)
    // still classifies normally. The admission tier is a FRESH-path check only.
    seed_intent_on_message(
        &raw_conn(&path),
        "k-no-targets",
        "msg-1",
        "applied",
        Some(&no_targets.to_json().unwrap()),
    );
    assert_eq!(
        log.record(&cmd, &no_targets)
            .expect("a legacy replay is never re-validated"),
        Claim::AlreadyExisted,
        "the existing row IS the answer — same verdict as before stage 3"
    );
    assert_eq!(
        status_str(&path, "k-no-targets"),
        "applied",
        "…and the replay never regresses the existing row"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_malformed_basis_is_refused_by_the_log_boundary_itself_on_both_impls() {
    // `execute()` validates before `record()`, but `record()`
    // IS the durable boundary — a direct `IntentLog::record` caller handing a
    // structurally invalid basis must be refused THERE, or the store commits a row that
    // `get()`/`unreconciled()` later refuse to re-parse, aborting every recovery sweep.
    // Parse-don't-validate: the boundary never persists a value it cannot re-read.
    let invalid = prestate::FrozenBasis {
        native_resource_key: String::new(),
        touched_atoms: std::collections::BTreeMap::new(),
        atom_targets: std::collections::BTreeMap::new(),
        role_bindings: std::collections::BTreeMap::new(),
        freshness: prestate::Freshness::ImmutableConstants,
    };
    let cmd = Command::new(
        "k-log-boundary".to_string(),
        "acct",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let path = unique_temp_db_path("log-boundary-validate");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let err = log
        .record(&cmd, &invalid)
        .expect_err("the durable boundary must refuse a basis it could not re-read");
    assert!(
        format!("{err:?}").contains("basis"),
        "a named refusal, got {err:?}"
    );
    let rows: i64 = raw_conn(&path)
        .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "a refused record commits NOTHING");
    assert!(
        log.unreconciled().expect("the sweep must still read").is_empty(),
        "the recovery sweep stays readable after the refusal"
    );
    let mut mem = InMemoryIntentLog::new();
    mem.record(&cmd, &invalid)
        .expect_err("the in-memory boundary refuses identically");
    assert!(mem.get("k-log-boundary").unwrap().is_none());
}

#[test]
fn a_malformed_resolved_basis_refuses_admission_and_commits_nothing() {
    // BASIS-1/-5: the frozen basis IS the durable ordering key and the operand record. A
    // basis with no touched atoms names nothing to order on and nothing to restore, and one
    // with an empty native key cannot key the tail at all — `from_json` has always refused
    // exactly these shapes, but `execute()` passed the connector's in-memory value straight
    // to `record()`, committing unusable JSON that only fails LATER (at PREPARE's re-parse,
    // or as open-time `FrozenBasisMissing` evidence). Validate at the boundary instead: the
    // structural checks are ONE authority (`FrozenBasis::validate`, which `from_json` calls),
    // and a resolver that produces an invalid basis is refused with the SAME named-retryable
    // admission-refusal shape as a resolver that fails outright.
    for (tag, basis) in [
        (
            "no-atoms",
            prestate::FrozenBasis {
                native_resource_key: "prov:acct/native-9".to_string(),
                touched_atoms: std::collections::BTreeMap::new(),
                atom_targets: std::collections::BTreeMap::new(),
                role_bindings: std::collections::BTreeMap::new(),
                freshness: prestate::Freshness::ImmutableConstants,
            },
        ),
        (
            "empty-native-key",
            prestate::FrozenBasis {
                native_resource_key: String::new(),
                ..test_basis("unused")
            },
        ),
    ] {
        let path = unique_temp_db_path(&format!("malformed-basis-{tag}"));
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            MalformedBasisConnector::new(basis),
        );
        let err = bus.execute(&archive_cmd("k-bad-basis")).unwrap_err();
        // THE primary witness: pre-fix the malformed basis sailed past `record()` and a
        // Pending intent row was COMMITTED carrying unusable JSON (the failure only surfaced
        // later, on re-read/PREPARE). Post-fix: refusal at the boundary, zero rows.
        assert_eq!(
            raw_conn(&path)
                .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "{tag}: a refused admission commits NO intent row"
        );
        assert!(
            matches!(err, ExecuteError::AdmissionRefused(ref m) if m.contains("admission refused")),
            "{tag}: a malformed basis must be refused at admission like any resolver \
             failure — SAME pre-durable retryable signal, got {err:?}"
        );
        assert_eq!(
            bus.connector().apply_count(),
            0,
            "{tag}: nothing reached the wire"
        );
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn observation_binding_mismatch_terminalizes_no_effect() {
    // BASIS-6 at observation: a mismatch found at initial capture terminalizes
    // the operation no-effect: the deterministic-failure path (Failed, named error). It is
    // found in the CAPTURE pipeline, which runs ahead of the dispatch claim, so it carries
    // no attempt and no verdict fact — the operation-grain half of the stage-4
    // boundary. The provider answered for a DIFFERENT native id than the frozen basis.
    let path = unique_temp_db_path("basis-mismatch");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        RebindingConnector::new("prov:acct/OLD", "prov:acct/NEW"),
    );
    let err = bus.execute(&archive_cmd("k-rebind-1")).unwrap_err();
    assert!(matches!(err, ExecuteError::Connector(_)), "got {err:?}");
    let status: String = raw_conn(&path)
        .query_row(
            "SELECT status FROM intents WHERE idempotency_key='k-rebind-1';",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "failed", "basis rebind = deterministic no-effect terminal");
    assert_eq!(bus.connector().apply_count(), 0, "nothing reached the wire");
    let rows: i64 = raw_conn(&path)
        .query_row("SELECT COUNT(*) FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "a rebind never journals");
    std::fs::remove_file(&path).ok();
}

// --: recovery runs the SAME pipeline (§2.2 crash rules) -----------------------

#[test]
fn recovery_captures_then_dispatches_an_unprepared_intent() {
    // §2.2: unprepared ⇒ cannot have dispatched ⇒ recovery waits-for-head, captures,
    // prepares, dispatches. This is the crash-between-admission-and-prepare arm
    // (W-CAPTURE-HEAD): admission committed, then the process died.
    let path = unique_temp_db_path("recover-unprepared");
    {
        // "crash": record only — the admission transaction committed, no pipeline ran.
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k-rec-1")).unwrap();
    }
    assert_eq!(raw_count(&path, "pre_state"), 0, "precondition: unprepared");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.recover().unwrap();
    assert_eq!(
        bus.connector().observe_count(),
        1,
        "recovery observed before dispatch"
    );
    assert_eq!(bus.connector().apply_count(), 1);
    assert!(
        bus.connector().observed_before_applied(),
        "PRE-STATE-BEFORE-DISPATCH holds on the recovery path too"
    );
    assert_eq!(
        raw_count(&path, "pre_state"),
        1,
        "recovery prepared before dispatching"
    );
    assert_eq!(
        bus.log().get("k-rec-1").unwrap().unwrap().status,
        IntentStatus::Applied
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recovery_never_recaptures_a_prepared_intent() {
    // §2.2: prepared ⇒ NEVER re-capture (a post-effect observation poisons no-op
    // detection). The crash was between PREPARE and dispatch, built here with the
    // existing transient-failing connector: `AlwaysFailConnector` observes normally, so
    // execute prepares, then its apply fails transiently and the intent stays Pending.
    let path = unique_temp_db_path("recover-prepared");
    {
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            AlwaysFailConnector,
        );
        let parked = bus.execute(&archive_cmd("k-rec-2"));
        assert!(
            matches!(parked, Err(ExecuteError::Connector(_))),
            "precondition: the dispatch failed transiently, got {parked:?}"
        );
        assert_eq!(
            bus.log().get("k-rec-2").unwrap().unwrap().status,
            IntentStatus::Pending,
            "precondition: still non-terminal"
        );
    }
    assert_eq!(raw_count(&path, "pre_state"), 1, "precondition: prepared");
    let journal_before: String = raw_conn(&path)
        .query_row("SELECT journal_id FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    let captured_before: String = raw_conn(&path)
        .query_row("SELECT observed FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.recover().unwrap();
    // §2.2's rule is NEVER RE-CAPTURE, and re-capture is what the four assertions below
    // measure: one row, the same row, the same captured bytes.
    //
    // The retry DOES take a provider READ: the
    // retry-requalification gate observes `C` at the head of every capture-ON retry, and it
    // must — that observation is the only thing that can tell an unchanged world from one
    // another actor moved during the retry gap. A READ is not a CAPTURE. This assertion
    // used to demand ZERO reads, and it only held because a `P == A` pre-guard skipped the
    // gate entirely; that guard was the hole named, and the property this witness
    // exists for (the journal row is untouched) is unaffected by its deletion.
    assert_eq!(
        bus.connector().observe_count(),
        1,
        "the retry requalifies with ONE read, and never more"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "recovery dispatched from the existing row"
    );
    assert_eq!(raw_count(&path, "pre_state"), 1, "no second journal row");
    let journal_after: String = raw_conn(&path)
        .query_row("SELECT journal_id FROM pre_state;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        journal_before, journal_after,
        "the captured row is never rewritten"
    );
    assert_eq!(
        captured_before,
        raw_conn(&path)
            .query_row("SELECT observed FROM pre_state;", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "…and its captured bytes are the FIRST pass's, not the retry's observation"
    );
    assert_eq!(
        capture_generation_of(&path, "k-rec-2"),
        1,
        "generation 1: PREPARE's capture, never re-prepared"
    );
    std::fs::remove_file(&path).ok();
}
