//! The forward execute path: idempotent replay, dead-letters, recovery, and the head ordering domain.

use super::*;
use crate::fixtures::{fixture_observation, fixture_restore};

#[test]
fn executing_a_command_marks_the_intent_applied_when_the_connector_succeeds() {
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), AlwaysOkConnector);
    let cmd = archive_cmd("k1");

    bus.execute(&cmd).expect("execute should succeed");

    let intent = bus.log().get("k1").expect("get should succeed").expect("intent should be recorded");
    assert_eq!(intent.status, IntentStatus::Applied);
}

#[test]
fn executing_the_same_command_twice_dispatches_to_the_connector_only_once() {
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::new());
    let cmd = archive_cmd("k1");

    bus.execute(&cmd).expect("first execute should succeed");
    bus.execute(&cmd).expect("second execute should be a no-op");

    assert_eq!(bus.connector().apply_count(), 1);
    assert_eq!(
        bus.log().get("k1").expect("get should succeed").expect("intent recorded").status,
        IntentStatus::Applied
    );
}

#[test]
fn a_failed_connector_leaves_the_intent_pending_for_retry_not_failed() {
    // ADR-P013: a connector failure is transient-retryable by default — execute surfaces the
    // error but leaves the intent in its non-terminal Pending state for the next recovery sweep,
    // matching recover. It does NOT hard-enter Failed (that conflated transient with
    // deterministic; Failed is the reserved dead-letter for the provider work).
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), AlwaysFailConnector);
    let cmd = archive_cmd("k1");

    let result = bus.execute(&cmd);

    assert!(
        matches!(result, Err(ExecuteError::Connector(_))),
        "execute should surface the connector error, got {result:?}"
    );
    assert_eq!(
        bus.log().get("k1").expect("get should succeed").expect("intent should be recorded").status,
        IntentStatus::Pending,
        "a transient connector failure stays Pending (retryable), never hard-Failed"
    );
}

struct FailingRecordIntentLog;

impl IntentLog for FailingRecordIntentLog {
    fn record(
        &mut self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
    ) -> Result<Claim, LogError> {
        Err(LogError("simulated persist failure".into()))
    }
    fn get(&self, _idempotency_key: &str) -> Result<Option<Intent>, LogError> {
        Ok(None)
    }
    fn set_status_if(
        &mut self,
        _key: &str,
        _precondition: StatusPrecondition,
        _status: IntentStatus,
    ) -> Result<StatusWrite, LogError> {
        Ok(StatusWrite::Written)
    }
    /// This log holds nothing (`record` always fails), so no operation of its can be over
    /// budget and the sweep's self-heal never reaches it.
    fn dead_letter_if_quiescent(&mut self, _: &str) -> Result<DeadLetterWrite, LogError> {
        Ok(DeadLetterWrite::StatusMoved(None))
    }
    fn verify_undo_pair(
        &mut self,
        _: &str,
        _: &str,
        _: UndoPairChild,
    ) -> Result<UndoPairFlip, LogError> {
        Ok(UndoPairFlip::Flipped)
    }
    fn unreconciled(&self) -> Result<Vec<Intent>, LogError> {
        Ok(Vec::new())
    }
    fn applied_unprojected_forward_intents(&self) -> Result<Vec<Intent>, LogError> {
        Ok(Vec::new())
    }
    fn charge_and_dead_letter_if_quiescent(
        &mut self,
        _idempotency_key: &str,
        _cap: u32,
    ) -> Result<TransientCharge, LogError> {
        Ok(TransientCharge::ChargeRefusedTerminal(None))
    }
    fn dead_letters(&self) -> Result<Vec<Intent>, LogError> {
        Ok(Vec::new())
    }
    fn latest_intent_for_message_ref(
        &self,
        _account: &str,
        _message_ref: &str,
    ) -> Result<Option<Intent>, LogError> {
        Ok(None)
    }
    fn has_non_terminal_native_predecessor(
        &self,
        _native_key: &str,
        _fallback_message_ref: &str,
        _account: &str,
        _before_seq: u64,
        _exclude_idempotency_key: &str,
    ) -> Result<bool, LogError> {
        // This log holds nothing (record always fails), so nothing can ever block a head.
        Ok(false)
    }
    fn prepare(
        &mut self,
        _idempotency_key: &str,
        _journal: &prestate::JournalRow,
    ) -> Result<prestate::PrepareOutcome, LogError> {
        // record always fails, so execute never reaches PREPARE on this log.
        unreachable!("FailingRecordIntentLog never admits an intent to prepare")
    }
    fn prepared(&self, _idempotency_key: &str) -> Result<bool, LogError> {
        Ok(false)
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
    fn undo_context(&mut self, _key: &str) -> Result<Option<UndoContext>, LogError> {
        // This log holds nothing (record always fails), so no intent can be undone.
        Ok(None)
    }
    fn admitted_epoch_is_current(&self, key: &str) -> Result<bool, LogError> {
        // Same honest answer as `get`: there is no such row, and the contract says a
        // missing key is an error.
        Err(LogError(format!(
            "admitted_epoch_is_current: no intent '{key}'"
        )))
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
fn recover_redispatches_a_pending_intent_after_a_crash() {
    // Crash-recovery: an intent recorded Pending but never Applied — the
    // process died between write-ahead and reconcile — must be re-dispatched on restart,
    // not silently stranded. Re-dispatch is at-least-once; idempotency makes re-apply
    // safe (the resume model).
    let path = unique_temp_db_path("crash-recover");
    let cmd = archive_cmd("k1");

    // Simulate a crash AFTER the write-ahead record but BEFORE apply/Applied:
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &cmd).expect("record"); // leaves it Pending
    } // process "dies" — connection dropped

    // Restart: reopen the durable log and recover.
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, RecordingConnector::new());

    let report = bus.recover().expect("recover should succeed");

    assert_eq!(report.recovered, 1, "one pending intent should be recovered");
    assert_eq!(
        bus.connector().applied_actions(),
        vec![Action::Archive {
            message_ref: "msg-1".into()
        }],
        "the pending command must be re-dispatched below the seam"
    );
    assert_eq!(
        bus.log()
            .get("k1")
            .expect("get should succeed")
            .expect("intent")
            .status,
        IntentStatus::Applied
    );
    std::fs::remove_file(&path).ok();
}

struct FailFirstConnector {
    failed_once: std::cell::Cell<bool>,
    applied: std::cell::RefCell<Vec<Action>>,
}
impl FailFirstConnector {
    fn new() -> Self {
        Self {
            failed_once: std::cell::Cell::new(false),
            applied: std::cell::RefCell::new(Vec::new()),
        }
    }
    fn applied_actions(&self) -> Vec<Action> {
        self.applied.borrow().clone()
    }
}
impl Connector for FailFirstConnector {
    fixture_seam!();
    fn apply(&self, command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        if !self.failed_once.get() {
            self.failed_once.set(true);
            return Err(retryable_transient("transient"));
        }
        self.applied.borrow_mut().push(command.action.clone());
        Ok(())
    }
}

#[test]
fn recover_does_not_abort_the_sweep_on_a_connector_failure() {
    // One transient connector failure must NOT strand every later intent. The
    // sweep continues; the failed intent is marked Failed and reported (not silently dropped,
    // not fatal to the rest). Only a durable-log error is fatal.
    let path = unique_temp_db_path("recover-resilient");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k1")).expect("r1");
        record_basis(&mut log, &Command::new(
            "k2",
            "acct-1",
            Facet::Mail,
            Action::Archive { message_ref: "m2".into() },
        ))
        .expect("r2");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, FailFirstConnector::new());

    let report = bus.recover().expect("recover should not fail on a connector error");

    assert_eq!(report.recovered, 1, "k2 still recovered despite k1 failing");
    assert_eq!(report.failed.len(), 1, "k1's transient failure is reported");
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Pending,
        "a transient connector failure leaves the intent retryable, not terminal Failed"
    );
    assert_eq!(
        bus.log().get("k2").expect("g").expect("i").status,
        IntentStatus::Applied
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_failed_record_aborts_the_apply_write_ahead() {
    // Write-ahead invariant: persist the intent BEFORE applying; a failed
    // persist must abort — the connector is never called, no silent data loss.
    let mut bus = CommandBus::new(FailingRecordIntentLog, CountingConnector::new());

    let result = bus.execute(&archive_cmd("k1"));

    assert!(matches!(result, Err(ExecuteError::Log(_))));
    assert_eq!(
        bus.connector().apply_count(),
        0,
        "apply must not run when the durable persist failed"
    );
}

#[test]
fn recover_fails_closed_on_a_corrupt_status_row() {
    // Recover filtered unreconciled rows by status IN SQL, so a corrupt/unknown
    // status was excluded BEFORE parsing — recovery reported success while a bad durable row sat
    // unrecovered (fail-OPEN). A system-of-record must fail CLOSED: surface the bad row as a
    // LogError, never silently skip it.
    let path = unique_temp_db_path("recover-corrupt-status");
    SqliteIntentLog::open(&path).expect("open creates schema");

    let conn = rusqlite::Connection::open(&path).expect("raw open");
    conn.execute(
        // A hand-seeded row must supply the admission-binding columns
        // `record()` now binds — they are NOT NULL by DDL. The corruption under test is
        // the STATUS token, not the binding.
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref, status, seq,
                                  intent_id, kind, journal_required, capture_mode_generation,
                                  admitted_control_epoch, frozen_basis)
             VALUES ('k1', 'acct-1', 'mail', 'archive', 'msg-1', 'BOGUS_STATUS', 1,
                     '00000000000000000000000000000001', 'forward', 1, 1, 1,
                     '{\"native_resource_key\":\"test:msg-1\",\"touched_atoms\":{\"membership:INBOX\":\"INBOX\"},\"freshness\":\"immutable_constants\"}');",
        [],
    )
    .expect("inject corrupt row");
    drop(conn);

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        RecordingConnector::new(),
    );
    let result = bus.recover();

    assert!(
        matches!(result, Err(ExecuteError::Log(_))),
        "a corrupt status row must fail recovery CLOSED, got {result:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_recovery_barrier_blocks_across_generations_on_one_message() {
    // The sweep barrier recorded ONE key per intent — a
    // retryable legacy (NULL-basis) predecessor barriers under its message_ref while a
    // later PREPARED stage-2 row on the same message keys its native resource key,
    // missing the barrier; ensure_prepared short-circuits on the existing journal row
    // and the successor dispatches in the same sweep, reversing causal order. The
    // barrier must carry the SAME two-lane overlap as the head predicate:
    // check ANY of the intent's keys, raise ALL of them.
    //
    // WHAT THE LEGACY PREDECESSOR DOES NOW. It PARKS instead of
    // failing: `apply` consumes the admission-frozen basis (BASIS-6 — dispatch never
    // re-resolves), and a NULL-basis row has none to hand it, so it can no longer reach a
    // connector at all. The park raises the barrier exactly as the failure did, which is
    // the property under test here and is asserted unchanged below; the row stays
    // non-terminal, undispatched, and visible as the open-time `FrozenBasisMissing`
    // integrity finding it already was. (Its retry was ALREADY parked for the same reason
    // by `requalify_retry_at_head`'s legacy arm; this makes the first pass agree with it.)
    let path = unique_temp_db_path("recover-mixed-generation-barrier");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        // seq 1 — the LEGACY predecessor: NULL basis (pre-stage-2 row), capture-off,
        // Pending. Seeded raw: this store state is exactly what a stage-1-written
        // store looks like when a stage-2 binary recovers it.
        log.conn
            .execute(
                "INSERT INTO intents (idempotency_key, account, facet, action_kind,
                                          message_ref, status, seq, intent_id, kind,
                                          journal_required, capture_mode_generation,
                                          admitted_control_epoch, frozen_basis)
                     VALUES ('k-legacy', 'acct-1', 'mail', 'archive', 'msg-1', 'pending', 1,
                             lower(hex(randomblob(16))), 'forward', 0, 1, 1, NULL);",
                [],
            )
            .expect("seed legacy predecessor");
        // seq 2 — the stage-2 successor on the SAME message, already PREPARED.
        record_basis(
            &mut log,
            &Command::new(
                "k-newer",
                "acct-1",
                Facet::Mail,
                Action::Unarchive {
                    message_ref: "msg-1".into(),
                },
            ),
        )
        .expect("record newer");
        log.conn
            .execute(
                "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom,
                                            resolved_operands, fetched_at, source,
                                            captured_epoch, mode_generation, undo_offer_until)
                     SELECT 'j-newer', intent_id, '{}', '{}', '{}', '1970-01-01T00:00:00Z',
                            'live_read', 1, 1, '1970-01-08T00:00:00Z'
                       FROM intents WHERE idempotency_key = 'k-newer';",
                [],
            )
            .expect("seed the successor's journal row");
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        FailFirstConnector::new(), // k-legacy (seq 1) fails transiently; the rest record
    );
    let report = bus.recover().expect("sweep survives");
    let applied = bus.connector().applied_actions();
    assert!(
        !applied.contains(&Action::Unarchive {
            message_ref: "msg-1".into()
        }),
        "the prepared stage-2 successor must DEFER behind the undispatchable legacy \
         predecessor; applied={applied:?}"
    );
    assert!(
        applied.is_empty(),
        "a NULL-basis row has no frozen identity to hand the wire — it must never reach a \
         connector; applied={applied:?}"
    );
    assert_eq!(
        status_str(&path, "k-legacy"),
        "pending",
        "the parked legacy row stays non-terminal: a dispatcher never dead-letters what an \
         integrity scan owns"
    );
    assert_eq!(
        report.recovered, 0,
        "and nothing was recovered this sweep — the barrier held both rows"
    );
}

#[test]
fn the_recovery_barrier_native_key_is_never_diluted_by_the_photon_account() {
    // THE RED for, recovery arm. `barrier_keys` tupled the native
    // key WITH the Photon-local account — so two local handles resolving to ONE provider
    // account+message raised, and checked, DIFFERENT barrier entries. seq 1 fails this
    // sweep under handle `acct-1`; seq 2, already PREPARED under handle `acct-2`,
    // short-circuits `ensure_prepared` and dispatches in the SAME sweep, reversing causal
    // order on one provider object. The native member of the barrier key must carry NO
    // account (it is provider-scoped by construction, BASIS-4); only the Photon-local
    // `message_ref` member stays account-scoped.
    let path = unique_temp_db_path("recover-cross-account-native-barrier");
    let one_resource = prestate::FrozenBasis {
        native_resource_key: "prov:acct/N".to_string(),
        touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
            .into_iter()
            .collect(),
        atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
        role_bindings: std::collections::BTreeMap::new(),
        freshness: prestate::Freshness::ImmutableConstants,
    };
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        // seq 1 — handle `acct-1`, local ref `ref-a`.
        log.record(
            &Command::new(
                "k-handle-a",
                "acct-1",
                Facet::Mail,
                Action::Archive {
                    message_ref: "ref-a".into(),
                },
            ),
            &one_resource,
        )
        .expect("record handle a");
        // seq 2 — handle `acct-2`, local ref `ref-b`, SAME provider resource, already
        // PREPARED (the journal row is the phase; `ensure_prepared` short-circuits).
        log.record(
            &Command::new(
                "k-handle-b",
                "acct-2",
                Facet::Mail,
                Action::Unarchive {
                    message_ref: "ref-b".into(),
                },
            ),
            &one_resource,
        )
        .expect("record handle b");
        log.conn
            .execute(
                "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom,
                                            resolved_operands, fetched_at, source,
                                            captured_epoch, mode_generation, undo_offer_until)
                     SELECT 'j-handle-b', intent_id,
                            '{\"membership:INBOX\":false}', '{\"membership:INBOX\":false}',
                            '{\"membership:INBOX\":\"INBOX\"}', '1970-01-01T00:00:00Z',
                            'live_read', 1, 1, '1970-01-08T00:00:00Z'
                       FROM intents WHERE idempotency_key = 'k-handle-b';",
                [],
            )
            .expect("seed the successor's journal row");
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        FailFirstConnector::new(), // k-handle-a (seq 1) fails transiently; the rest record
    );
    let report = bus.recover().expect("sweep survives");
    let applied = bus.connector().applied_actions();
    assert!(
        !applied.contains(&Action::Unarchive {
            message_ref: "ref-b".into()
        }),
        "the SECOND Photon handle's prepared intent must DEFER behind the failed \
         same-native predecessor; applied={applied:?}"
    );
    assert!(
        report.failed.iter().any(|(k, _)| k == "k-handle-a"),
        "the predecessor's failure is reported"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_defers_a_later_intent_behind_an_earlier_failure_on_the_same_resource() {
    // Recover walks intents in seq order but, on a transient connector failure,
    // logs it and continues. Two intents on the SAME resource (Archive then Unarchive of one
    // message) would then apply out of order — the later one now, the failed earlier one on the
    // next sweep — reversing causal order → wrong final provider state. A failure must raise a
    // per-resource barrier: defer later same-resource intents. INDEPENDENT resources keep
    // flowing (must not re-strand the sweep).
    let path = unique_temp_db_path("recover-resource-barrier");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k1")).expect("r1"); // seq1: Archive msg-1
        record_basis(&mut log, &Command::new(
            "k2",
            "acct-1",
            Facet::Mail,
            Action::Unarchive {
                message_ref: "msg-1".into(),
            },
        ))
        .expect("r2"); // seq2: SAME resource as k1
        record_basis(&mut log, &Command::new(
            "k3",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-2".into(),
            },
        ))
        .expect("r3"); // seq3: independent resource
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        FailFirstConnector::new(), // fails the first dispatch, records the rest
    );

    let report = bus
        .recover()
        .expect("a connector failure must not be fatal to the sweep");
    let applied = bus.connector().applied_actions();

    assert!(
        !applied.contains(&Action::Unarchive {
            message_ref: "msg-1".into()
        }),
        "later same-resource intent must be DEFERRED, not applied out of order; applied={applied:?}"
    );
    assert!(
        applied.contains(&Action::Archive {
            message_ref: "msg-2".into()
        }),
        "an independent resource must still be recovered; applied={applied:?}"
    );
    assert!(
        report.failed.iter().any(|(k, _)| k == "k1"),
        "k1's transient failure is reported"
    );
    // Deferred, not lost: k2 stays Pending for the next sweep (after k1 succeeds).
    assert_eq!(
        bus.log().get("k2").expect("g").expect("i").status,
        IntentStatus::Pending,
        "the deferred intent must remain Pending, recoverable on the next sweep"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn execute_rejects_a_different_command_reusing_an_applied_key() {
    // Execute short-circuits an already-Applied key as a no-op. If a caller
    // reuses that key for a DIFFERENT command (stale UI / bug), the no-op returned success while
    // the new mutation never reached the connector — silently dropped. Reuse with a different
    // payload must be REJECTED, not reported as a successful no-op.
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::new());
    bus.execute(&archive_cmd("k1")).expect("first execute applies");
    assert_eq!(bus.connector().apply_count(), 1);

    let result = bus.execute(&Command::new(
        "k1",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "DIFFERENT".into(),
        },
    ));

    assert!(
        matches!(result, Err(ExecuteError::Conflict)),
        "reusing an Applied key for a different command must be rejected as a Conflict, got {result:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "the rejected reuse must NOT reach the connector"
    );
}

#[test]
fn execute_rejects_a_same_key_under_a_different_principal_as_conflict() {
    // ADR-P013: the idempotency fingerprint includes the ActionEnvelope. A same-key submission
    // under a DIFFERENT principal is a Conflict, not a replay — you cannot replay another
    // principal's key.
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), CountingConnector::new());
    let mut first = archive_cmd("k1");
    first.envelope.principal = Some("user:alice".into());
    bus.execute(&first).expect("first execute applies");

    let mut second = archive_cmd("k1"); // same key + action, DIFFERENT principal
    second.envelope.principal = Some("user:mallory".into());
    let result = bus.execute(&second);

    assert!(
        matches!(result, Err(ExecuteError::Conflict)),
        "a same-key submission under a different principal must be a Conflict, got {result:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "the conflicting submission must never reach the connector"
    );
}

#[test]
fn execute_replays_a_failed_intent_as_an_error_never_ok() {
    // ADR-P013: `Failed` is the reserved terminal dead-letter. An identical retry of a
    // dead-lettered intent must replay the failure (Err::Failed), NEVER a silent Ok — reporting
    // success for a permanently-failed action is exactly the audit lie this gate forbids. `Failed`
    // is unreachable by M0 code paths, so seed it directly to exercise the reserved branch (and
    // keep a future refactor from silently flipping it to Ok).
    let path = unique_temp_db_path("execute-replay-failed");
    let cmd = archive_cmd("k1");
    SqliteIntentLog::open(&path).expect("open creates schema");

    let conn = rusqlite::Connection::open(&path).expect("raw open");
    conn.execute(
        // Supply the NOT NULL admission-binding columns (see above).
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref, status, seq,
                                  intent_id, kind, journal_required, capture_mode_generation,
                                  admitted_control_epoch, frozen_basis)
             VALUES ('k1', 'acct-1', 'mail', 'archive', 'msg-1', 'failed', 1,
                     '00000000000000000000000000000001', 'forward', 1, 1, 1,
                     '{\"native_resource_key\":\"test:msg-1\",\"touched_atoms\":{\"membership:INBOX\":\"INBOX\"},\"freshness\":\"immutable_constants\"}');",
        [],
    )
    .expect("seed a Failed row matching cmd's fingerprint");
    drop(conn);

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        CountingConnector::new(),
    );
    let result = bus.execute(&cmd);

    assert!(
        matches!(result, Err(ExecuteError::Failed)),
        "an identical retry of a Failed intent must replay the failure, never Ok; got {result:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        0,
        "a Failed terminal replay must not re-dispatch"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn execute_dead_letters_a_deterministically_failed_command() {
    // ADR-P013 (b): a connector failure classified DETERMINISTIC (validation / permission /
    // missing-target — not worth retrying) dead-letters the intent to the terminal `Failed`
    // state immediately, instead of leaving it `Pending` for an endless retry. This gives the
    // reserved TerminalReplay(Failed) branch its first REAL producer. The error-POLICY taxonomy
    // (which provider errors are deterministic vs transient) stays deferred to the real
    // connector; the mock declares the kind directly.
    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        DeterministicFailConnector::new("message not found"),
    );
    let cmd = archive_cmd("k1");

    let first = bus.execute(&cmd);
    assert!(
        matches!(first, Err(ExecuteError::Connector(_))),
        "the first deterministic failure surfaces the connector rejection; got {first:?}"
    );

    let intent = bus.log().get("k1").expect("get").expect("intent recorded");
    assert_eq!(
        intent.status,
        IntentStatus::Failed,
        "a deterministic connector failure must dead-letter the intent to terminal Failed, \
         never leave it Pending for an endless retry"
    );

    // An identical retry of the dead-lettered intent replays the failure as Err::Failed —
    // never a silent Ok, and never re-dispatched to the connector (ADR-P013 truth table).
    let replay = bus.execute(&cmd);
    assert!(
        matches!(replay, Err(ExecuteError::Failed)),
        "replaying a dead-lettered intent must return Err::Failed; got {replay:?}"
    );
}

#[test]
fn recover_dead_letters_a_transient_intent_after_the_retry_cap() {
    // ADR-P013 (b): a TRANSIENT failure is retried, not failed — but not forever. A transient
    // error that recurs past the retry cap is effectively permanent (the canonical DLQ rule), so
    // the intent is dead-lettered to terminal `Failed` (retry-budget exhaustion) instead of being
    // swept forever. The backoff schedule BETWEEN attempts is a separate concern (backoff_delay).
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), AlwaysFailConnector);
    let cmd = archive_cmd("k1");

    // Initial dispatch fails transiently and burns the first attempt; the intent stays Pending.
    assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_))));
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Pending,
        "one transient failure must not dead-letter — it is retryable"
    );

    // Each recovery sweep retries and burns another attempt. The cap counts TOTAL dispatch
    // attempts; the initial execute was attempt 1, so RETRY_CAP-1 more failures exhaust it.
    for _ in 0..(RETRY_CAP - 1) {
        bus.recover().expect("recovery sweep runs");
    }

    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Failed,
        "a transient failure retried past the cap must dead-letter to Failed (budget exhaustion)"
    );
    assert!(
        bus.log().unreconciled().unwrap().is_empty(),
        "a dead-lettered intent is terminal and must no longer be swept for retry"
    );
}

#[test]
fn recover_dead_letters_a_deterministic_failure_immediately() {
    // ADR-P013 (b) (RecoverFailureKindParity): recover must honor
    // FailureKind exactly as execute does. A DETERMINISTIC failure during recovery dead-letters
    // AT ONCE (it will never succeed) — it must NOT be retried to the cap like a transient one,
    // and must NOT burn the transient retry budget.
    struct TransientThenDeterministic {
        calls: std::cell::Cell<u32>,
    }
    impl Connector for TransientThenDeterministic {
        fixture_seam!();
        fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            if n == 0 {
                Err(retryable_transient("first attempt is transient"))
            } else {
                Err(definitive_refusal("now permanently rejected"))
            }
        }
    }

    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        TransientThenDeterministic { calls: std::cell::Cell::new(0) },
    );
    let cmd = archive_cmd("k1");

    // First dispatch fails transiently → Pending, attempt 1.
    assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_))));
    assert_eq!(bus.log().get("k1").unwrap().unwrap().status, IntentStatus::Pending);

    // recover's re-dispatch fails DETERMINISTICALLY → dead-letter immediately, NOT after the cap.
    bus.recover().expect("recovery sweep runs");
    let intent = bus.log().get("k1").unwrap().unwrap();
    assert_eq!(
        intent.status,
        IntentStatus::Failed,
        "a deterministic failure during recover() must dead-letter immediately, not retry to cap"
    );
    assert_eq!(
        intent.attempts, 1,
        "a deterministic dead-letter must NOT burn the transient retry budget"
    );
}

#[test]
fn recover_self_heals_an_over_budget_row_before_dispatching() {
    // Backstop / defense-in-depth: a non-terminal row already at/over
    // RETRY_CAP (a legacy/corrupt row, or a crash before the atomic charge) must be terminalized
    // to Failed by recover BEFORE any dispatch — never re-dispatched over budget.
    let path = unique_temp_db_path("recover-over-budget-selfheal");
    let cmd = archive_cmd("k1");
    SqliteIntentLog::open(&path).expect("schema");
    let conn = rusqlite::Connection::open(&path).expect("raw");
    conn.execute(
        // Supply the NOT NULL admission-binding columns (see above).
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref, status, seq, attempts,
                                  intent_id, kind, journal_required, capture_mode_generation,
                                  admitted_control_epoch, frozen_basis)
             VALUES ('k1','acct-1','mail','archive','msg-1','pending',1,99,
                     '00000000000000000000000000000001', 'forward', 1, 1, 1,
                     '{\"native_resource_key\":\"test:msg-1\",\"touched_atoms\":{\"membership:INBOX\":\"INBOX\"},\"freshness\":\"immutable_constants\"}');",
        [],
    )
    .expect("seed an over-budget Pending row");
    drop(conn);
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        CountingConnector::new(),
    );
    bus.recover().expect("recovery sweep");
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Failed,
        "an over-budget non-terminal row must be dead-lettered by recover() before dispatch"
    );
    assert_eq!(
        bus.connector().apply_count(),
        0,
        "recover() must NOT dispatch an over-budget row"
    );
    let _ = cmd;
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_fresh_execute_defers_behind_a_pending_same_resource_predecessor() {
    // TailOrderedMutationInvariant (ExecuteOvertakesPendingResource):
    // a fresh execute on a resource with a non-terminal predecessor must NOT dispatch inline (it
    // would let recover reorder the two — e.g. a deferred undo could defeat this newer action).
    // It is recorded Pending and signals InProgress; recover then sequences predecessor-then-this
    // by seq, so the later command takes its correct tail position.
    let path = unique_temp_db_path("execute-defers-same-resource");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        FailSecondConnector::new(),
    );
    bus.execute(&archive_cmd("k1")).expect("k1 archive applies"); // apply #1 ok
    let _ = bus.execute(&Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    )); // apply #2 fails → k2 Pending predecessor
    assert_eq!(
        bus.log().get("k2").expect("g").expect("i").status,
        IntentStatus::Pending
    );

    let k3 = Command::new(
        "k3",
        "acct-1",
        Facet::Mail,
        Action::Unarchive {
            message_ref: "msg-1".into(),
        },
    );
    let r = bus.execute(&k3);
    assert!(
        matches!(r, Err(ExecuteError::InProgress)),
        "a deferred execute signals in-flight (recovery owns it), got {r:?}"
    );
    assert_eq!(
        bus.log().get("k3").expect("g").expect("i").status,
        IntentStatus::Pending,
        "k3 is recorded Pending, NOT dispatched ahead of its predecessor"
    );

    bus.recover().expect("recover sequences k2 then k3");
    assert_eq!(
        bus.connector().applied.borrow().last(),
        Some(&Action::Unarchive {
            message_ref: "msg-1".into()
        }),
        "k3 must sequence AFTER k2 (its tail position), not overtake it"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn risk_tier_never_flows_into_the_reserved_envelope_tier() {
    // The no-flow guard: classification is pure metadata. Execute a SetFlag
    // through the durable bus, call risk_tier on it, and prove the reserved tier column is
    // still NULL — nothing wired the static classification into the governance runtime.
    let path = unique_temp_db_path("risk-tier-no-flow");
    let log = SqliteIntentLog::open(&path).expect("open");
    let connector = CountingConnector::default();
    let mut bus = CommandBus::new(log, connector);
    let action = Action::SetFlag { message_ref: "m1".into(), flag: MailFlag::Seen, value: true };
    let _ = action.risk_tier(); // classification happens — and must go nowhere
    let cmd = Command::new("k-noflow", "acct", Facet::Mail, action);
    bus.execute(&cmd).expect("execute");
    let stored = bus.log().get("k-noflow").expect("read").expect("row");
    assert_eq!(stored.command.envelope.tier, None, "reserved tier must stay NULL");
    std::fs::remove_file(&path).ok();
}

/// A connector whose resolver maps DIFFERENT local `message_ref`s onto the SAME provider
/// native key (the aliasing case BASIS-1 exists for), and whose `apply` always fails
/// TRANSIENTLY so the first intent stays non-terminal (`Pending`) — the house
/// Pending-holding fixture shape (cf. `FailFirstConnector`, lib.rs), with a resolver map
/// injected. Applies are counted (attempts included: a dispatch that reached the wire and
/// failed still reached the wire).
struct AliasingConnector {
    aliases: std::collections::HashMap<String, String>,
    apply_count: std::cell::Cell<usize>,
}
impl AliasingConnector {
    fn new(aliases: &[(&str, &str)]) -> Self {
        Self {
            aliases: aliases
                .iter()
                .map(|(r, native)| (r.to_string(), native.to_string()))
                .collect(),
            apply_count: std::cell::Cell::new(0),
        }
    }
    fn apply_count(&self) -> usize {
        self.apply_count.get()
    }
}
impl Connector for AliasingConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_count.set(self.apply_count.get() + 1);
        Err(retryable_transient("held pending"))
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        let message_ref = action_message_ref(&command.action);
        let native = self.aliases.get(message_ref).ok_or_else(|| {
            ResolveBasisError(format!("no alias mapping for '{message_ref}'"))
        })?;
        Ok(prestate::FrozenBasis {
            native_resource_key: native.clone(),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
            role_bindings: std::collections::BTreeMap::new(),
            freshness: prestate::Freshness::ImmutableConstants,
        })
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
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)
    }
}

fn alias_cmd(key: &str, message_ref: &str) -> Command {
    alias_cmd_for("acct-1", key, message_ref)
}

/// The same aliasing Archive, issued through an EXPLICIT Photon-local account handle —
/// the cross-handle arm (two local handles onto ONE provider account+message).
fn alias_cmd_for(account: &str, key: &str, message_ref: &str) -> Command {
    Command::new(
        key,
        account,
        Facet::Mail,
        Action::Archive {
            message_ref: message_ref.into(),
        },
    )
}

#[test]
fn w_capture_head_aliased_local_refs_enter_one_ordering_domain() {
    // BASIS-1: two local refs aliasing ONE provider object enter ONE ordering domain — a
    // later-admitted alias can never overtake an earlier same-native operation. RED on
    // message_ref-keyed ordering (the pre-stage-2 semantics).
    let log = InMemoryIntentLog::new();
    // A connector whose resolver maps BOTH "ref-a" and "ref-b" to native "prov:acct/N".
    let connector = AliasingConnector::new(&[("ref-a", "prov:acct/N"), ("ref-b", "prov:acct/N")]);
    let mut bus = CommandBus::new(log, connector);
    // First command occupies the native resource and stays non-terminal (the connector's
    // transient refusal holds it `Pending`).
    let r1 = bus.execute(&alias_cmd("k-alias-1", "ref-a"));
    assert!(matches!(
        r1,
        Err(ExecuteError::Connector(_)) | Err(ExecuteError::InProgress) | Ok(_)
    ));
    assert_eq!(
        bus.log().get("k-alias-1").unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the first intent still occupies the native resource"
    );
    // Second command via the OTHER local ref must be head-gated behind the first.
    let r2 = bus.execute(&alias_cmd("k-alias-2", "ref-b"));
    assert!(
        matches!(r2, Err(ExecuteError::InProgress)),
        "an aliased ref must queue behind the live native resource, got {r2:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "the alias must NOT have dispatched"
    );
}

/// THE RED for, in-memory arm. Two DIFFERENT Photon-local account
/// handles (`acct-1`, `acct-2`) whose resolvers map onto ONE provider account+message, so
/// both intents carry the SAME native key. The head predicate scoped its NATIVE lane by the
/// Photon-local `account`, so each handle's intents were invisible to the other's head check
/// and the second dispatched straight past the live first (cross-handle overtake; recovery
/// can then apply the OLDER mutation last). The native key is provider-scoped BY
/// CONSTRUCTION (BASIS-4) — it must never be re-scoped by a Photon-local handle.
#[test]
fn w_capture_head_two_photon_handles_on_one_native_key_enter_one_ordering_domain() {
    let connector =
        AliasingConnector::new(&[("ref-a", "prov:acct/N"), ("ref-b", "prov:acct/N")]);
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), connector);
    let r1 = bus.execute(&alias_cmd_for("acct-1", "k-xacct-1", "ref-a"));
    assert!(matches!(
        r1,
        Err(ExecuteError::Connector(_)) | Err(ExecuteError::InProgress) | Ok(_)
    ));
    assert_eq!(
        bus.log().get("k-xacct-1").unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the first handle's intent still occupies the native resource"
    );
    let r2 = bus.execute(&alias_cmd_for("acct-2", "k-xacct-2", "ref-b"));
    assert!(
        matches!(r2, Err(ExecuteError::InProgress)),
        "a SECOND Photon handle onto the same provider resource must queue behind the \
         live native resource, got {r2:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "the cross-handle alias must NOT have dispatched"
    );
}

/// The SAME RED against the durable predicate (`non_terminal_native_predecessor_sql`) —
/// the in-memory mirror and the SQL fragment are two implementations of one gate, so the
/// witness runs on both.
#[test]
fn the_head_predicate_native_lane_is_not_scoped_by_the_photon_account_in_sqlite() {
    let path = unique_temp_db_path("xacct-native-head");
    let connector =
        AliasingConnector::new(&[("ref-a", "prov:acct/N"), ("ref-b", "prov:acct/N")]);
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), connector);
    let _ = bus.execute(&alias_cmd_for("acct-1", "k-xacct-sql-1", "ref-a"));
    assert_eq!(
        bus.log().get("k-xacct-sql-1").unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the first handle's intent still occupies the native resource"
    );
    let r2 = bus.execute(&alias_cmd_for("acct-2", "k-xacct-sql-2", "ref-b"));
    assert!(
        matches!(r2, Err(ExecuteError::InProgress)),
        "the durable head predicate must gate the second handle too, got {r2:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "the cross-handle alias must NOT have dispatched"
    );
    std::fs::remove_file(&path).ok();
}

// ---- THE MIXED-GENERATION HEAD GATE: a NULL-basis caller vs a frozen-basis row ---------

#[test]
fn a_null_basis_head_check_is_blocked_by_a_frozen_basis_row_on_the_same_message() {
    // THE RED. MIXED generations on ONE message escaped BOTH lanes:
    //   - the caller has NO frozen basis (a pre-stage-2 row), so it keys the head check on its
    //     Photon-local `message_ref` — which is not any row's NATIVE key, so lane 1 misses;
    //   - the blocking row is NEWER and DOES carry a frozen basis, so lane 2's
    //     `frozen_basis IS NULL` restriction on the CANDIDATE excluded it too.
    // Neither lane matched, the gate answered "head is clear", and the legacy operation
    // dispatched straight past a live non-terminal peer on the same message.
    let path = unique_temp_db_path("mixed-lane-head");
    SqliteIntentLog::open(&path).expect("bootstrap");
    {
        let conn = raw_conn(&path);
        seed_intent_on_message(&conn, "k-legacy", "msg-1", "applied", None);
        seed_intent_on_message(
            &conn,
            "k-newer",
            "msg-1",
            "pending",
            Some(&test_basis("prov:acct-1/NATIVE").to_json().unwrap()),
        );
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    // Exactly the arguments `has_pending_same_resource_predecessor` builds for a NULL-basis
    // row: the local ref stands in for the native key AND is the fallback ref.
    assert!(
        log.has_non_terminal_native_predecessor("msg-1", "msg-1", "acct-1", u64::MAX, "k-legacy")
            .unwrap(),
        "a NON-terminal row on the same (account, message_ref) must hold the head REGARDLESS \
         of whether it carries a frozen basis"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_in_memory_head_predicate_mirrors_the_unrestricted_message_ref_lane() {
    // The mirror half of the SAME defect: the in-memory predicate matched a candidate on its
    // native key XOR its message_ref (a `match` on the candidate's basis), so a candidate WITH
    // a basis was never compared on message_ref at all. Both impls answer one question.
    let mut log = InMemoryIntentLog::new();
    let newer = Command::new(
        "k-newer",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    log.record(&newer, &test_basis("prov:acct-1/NATIVE"))
        .expect("record leaves it Pending");
    assert!(
        log.has_non_terminal_native_predecessor("msg-1", "msg-1", "acct-1", u64::MAX, "k-legacy")
            .unwrap(),
        "the in-memory lane 2 must match on (account, message_ref) regardless of the \
         candidate's frozen basis"
    );
}
