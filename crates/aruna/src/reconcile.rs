//! Divergence correction: correct a wrong optimistic projection from provider truth, but only
//! when the governing intent is terminal, so an in-flight optimistic mutation is never
//! clobbered. `Corrected { changed }` reports whether anything was actually corrected.

use crate::message_store::{Corrected, SqliteMessageStore};
use crate::read_model::{Placement, ProviderPlacement};
use crate::{Intent, IntentLog, LogError};

/// An error from divergence correction: a store/log error, or a provider-truth fetch failure
/// (surfaced, never swallowed into a false convergence).
#[derive(Debug)]
pub enum ReconcileError {
    Store(LogError),
    Provider(String),
}

impl From<LogError> for ReconcileError {
    fn from(e: LogError) -> Self {
        ReconcileError::Store(e)
    }
}

/// The terminal governing intent for `(account, message_ref)`, if one currently governs; it
/// authorizes a correction. `None` when no intent governs or the latest is still in flight.
/// Captured before the provider fetch and re-checked after, comparing the durable `seq`
/// identity: the same terminal intent must still govern, or `truth` may be stale relative to a
/// newer mutation recorded during the fetch (a check that only required "still terminal" would
/// let a newer `Applied` intent pass with stale truth).
fn terminal_governing_intent(
    log: &impl IntentLog,
    account: &str,
    message_ref: &str,
) -> Result<Option<Intent>, ReconcileError> {
    Ok(match log.latest_intent_for_message_ref(account, message_ref)? {
        Some(intent) if intent.status.is_terminal() => Some(intent),
        _ => None,
    })
}

/// Correct the optimistic placement of `(account, message_ref)` from provider truth.
/// - No row or no governing intent: nothing to correct (`changed: false`).
/// - Governing intent non-terminal (in flight): skip (`changed: false`); the optimistic
///   placement is unconfirmed, not wrong.
/// - Otherwise fetch provider truth and overwrite only if diverged; `changed` reports which.
pub fn reconcile_divergence(
    log: &impl IntentLog,
    store: &mut SqliteMessageStore,
    provider: &impl ProviderPlacement,
    account: &str,
    message_ref: &str,
) -> Result<Corrected, ReconcileError> {
    // Only correct a confirmed (terminal) intent's projection. Capture its identity (durable
    // seq) so the post-fetch re-check can require that the same intent still governs.
    let governing = match terminal_governing_intent(log, account, message_ref)? {
        Some(intent) => intent,
        None => return Ok(Corrected { changed: false }),
    };

    // The provider-opaque message id is needed to query truth. Use the fallible lookup so a
    // store read error surfaces here, never a silent "nothing to correct".
    //
    // `Ok(None)` (a genuinely absent projection row) is a correct no-op: a ref that was never
    // optimistically projected has no belief that could be wrong. If the optimistic-apply
    // pipeline later co-writes the intent and projection, a `None` under a terminal intent
    // could instead mean a crash split two non-atomic writes, and the missing row should be
    // rebuilt or surfaced. That distinction cannot be drawn today (nothing co-writes the
    // projection, so "terminal + no row" just means "not projected").
    let email_id = match store.resolve_email_id(account, message_ref)? {
        Some(id) => id,
        None => return Ok(Corrected { changed: false }),
    };

    let truth: Placement = provider
        .fetch_placement(account, &email_id)
        .map_err(|e| ReconcileError::Provider(format!("{e:?}")))?;

    // Re-check after the (slow) provider fetch and require that the same terminal intent still
    // governs (durable seq identity). A concurrent sweep could have recorded a newer intent
    // during `fetch_placement`, either still pending or already applied; either way `truth` was
    // fetched relative to the old intent and is now stale, so correcting would clobber the
    // newer mutation's placement. A still-terminal but different intent must skip too.
    // The small window between this re-check and `correct_placement` is not closed here;
    // callers are serialized through `&mut`, so no concurrent sweep exists yet.
    match terminal_governing_intent(log, account, message_ref)? {
        Some(latest) if latest.seq == governing.seq => {}
        _ => return Ok(Corrected { changed: false }),
    }

    Ok(store.correct_placement(account, message_ref, truth)?)
}

#[cfg(test)]
mod tests {
    use crate::derive_idempotency_key;
    use crate::message_store::{Corrected, SqliteMessageStore};
    use crate::read_model::{Placement, ProviderMessageId, ProviderPlacement};
    use crate::reconcile::reconcile_divergence;
    use crate::{
        Action, AdjudicationOutcome, Claim, Command, ConnectorError, Facet, Intent, IntentLog,
        IntentStatus, LateAckOutcome, LogError, SqliteIntentLog, UnknownReviewReport,
    };

    /// minted by the ONE guard (`crate::test_temp`) — unique per call,
    /// the store family removed on `Drop`, a leak a loud failure.
    fn unique_temp_db_path(tag: &str) -> crate::test_temp::TempFile {
        crate::test_temp::TempFile::sqlite(&format!("aruna-reconcile-{tag}"))
    }

    struct FakeProvider(Placement);
    impl ProviderPlacement for FakeProvider {
        fn fetch_placement(
            &self,
            _a: &str,
            _id: &ProviderMessageId,
        ) -> Result<Placement, ConnectorError> {
            Ok(self.0)
        }
    }

    /// An IntentLog that returns a scripted `(status, seq)` per successive
    /// `latest_intent_for_message_ref` call — call 0 = pre-fetch gate, call 1 = post-fetch re-check —
    /// to simulate a concurrent intent recorded during `fetch_placement`. Only that one method is
    /// exercised by reconcile.
    struct RacingLog {
        responses: Vec<(IntentStatus, u64)>,
        calls: std::cell::Cell<usize>,
    }
    impl IntentLog for RacingLog {
        fn record(
            &mut self,
            _: &Command,
            _: &crate::prestate::FrozenBasis,
        ) -> Result<Claim, LogError> {
            unimplemented!()
        }
        fn get(&self, _: &str) -> Result<Option<Intent>, LogError> {
            unimplemented!()
        }
        fn set_status_if(
            &mut self,
            _: &str,
            _: crate::StatusPrecondition,
            _: IntentStatus,
        ) -> Result<crate::StatusWrite, LogError> {
            unimplemented!()
        }
        fn dead_letter_if_quiescent(&mut self, _: &str) -> Result<crate::DeadLetterWrite, LogError> {
            unimplemented!()
        }
        fn verify_undo_pair(
            &mut self,
            _: &str,
            _: &str,
            _: crate::UndoPairChild,
        ) -> Result<crate::UndoPairFlip, LogError> {
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
        ) -> Result<crate::TransientCharge, LogError> {
            unimplemented!()
        }
        fn dead_letters(&self) -> Result<Vec<Intent>, LogError> {
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
            _: &crate::prestate::JournalRow,
        ) -> Result<crate::prestate::PrepareOutcome, LogError> {
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
        /// Reconcile never dispatches, so no witness reaches this log.
        fn record_effect_witness(
            &mut self,
            _: &str,
            _: &crate::EffectWitness,
            _: Option<&std::collections::BTreeSet<String>>,
        ) -> Result<(), LogError> {
            unimplemented!()
        }
        fn effect_witness(&self, _: &str) -> Result<Option<crate::EffectWitnessRow>, LogError> {
            unimplemented!()
        }
        fn replace_journal_row(
            &mut self,
            _: &str,
            _: &crate::prestate::JournalRow,
        ) -> Result<crate::JournalReplaceOutcome, LogError> {
            unimplemented!()
        }
        fn undo_context(&mut self, _: &str) -> Result<Option<crate::UndoContext>, LogError> {
            unimplemented!()
        }
        fn admitted_epoch_is_current(&self, _: &str) -> Result<bool, LogError> {
            unimplemented!()
        }
        fn claim_attempt(
            &mut self,
            _: &str,
            _: &crate::AttemptClaim,
        ) -> Result<crate::ClaimOutcome, LogError> {
            unimplemented!()
        }
        fn authorize_send(
            &mut self,
            _: &str,
            _: &str,
            _: crate::CaptureBinding,
            _: crate::plan::PlanBinding,
        ) -> Result<crate::SendAuthOutcome, LogError> {
            unimplemented!()
        }
        fn settle_attempt(
            &mut self,
            _: &str,
            _: &str,
            _: crate::ConnectorVerdict,
            _: u32,
            _: Option<u64>,
        ) -> Result<crate::SettleOutcome, LogError> {
            unimplemented!()
        }
        fn sever(&mut self, _: &str, _: &str) -> Result<crate::SeverOutcome, LogError> {
            unimplemented!()
        }
        /// This double holds NO fact chain, so it has no live attempt to classify.
        fn live_attempt(&self, _: &str) -> Result<Option<crate::LiveAttempt>, LogError> {
            Ok(None)
        }
        fn annotate_late_ambiguous_observation(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<String, LogError> {
            unimplemented!()
        }
        /// This double models no §5.2d substrate, and the reconcile
        /// projection never reaches those doors. UNIMPLEMENTED rather than permissively
        /// answered — a fake that "adjudicated" nothing would let a caller believe an unknown
        /// was closed; the REPORT is the honest empty (no chain, no unknowns).
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
        /// No fact chain ⇒ no `LATE_ACK_*` ⇒ nothing has resolved.
        fn adjudicated_history(&self, _: &str) -> Result<crate::AdjudicatedHistory, LogError> {
            Ok(crate::AdjudicatedHistory::Unresolved)
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
        /// …and no obligations either, so no reference this log wrote resolves.
        fn exposure_obligation(
            &self,
            _: &str,
        ) -> Result<Option<crate::ExposureObligation>, LogError> {
            Ok(None)
        }
        fn unknown_review(&self, _: u64, _: u64) -> Result<UnknownReviewReport, LogError> {
            Ok(UnknownReviewReport::default())
        }
        fn latest_intent_for_message_ref(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<Intent>, LogError> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            let (status, seq) = self.responses[n].clone();
            Ok(Some(Intent {
                command: Command::new(
                    derive_idempotency_key("acct", &Facet::Mail, "m1-logical"),
                    "acct",
                    Facet::Mail,
                    Action::Archive {
                        message_ref: "m1".into(),
                    },
                ),
                status,
                seq,
                attempts: 0,
                // Only `latest_intent_for_message_ref` is exercised here, and reconcile reads
                // status + seq only — the capture fields are inert for this fake.
                frozen_basis: None,
                journal_required: true,
                projected: false,
                basis_ingest_revision: None,
            }))
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

    /// Drive reconcile with a scripted racing log and assert it SKIPS (no clobber). Shared by both
    /// race variants.
    fn assert_race_skips(tag: &str, responses: Vec<(IntentStatus, u64)>) {
        let path = unique_temp_db_path(tag);
        let _log = SqliteIntentLog::open(&path).unwrap(); // creates the message_placement table
        let mut store = SqliteMessageStore::open(&path).unwrap();
        store
            .record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), Placement::Archive)
            .unwrap();
        let racing = RacingLog {
            responses,
            calls: std::cell::Cell::new(0),
        };
        let provider = FakeProvider(Placement::Inbox); // would clobber Archive→Inbox if not skipped
        let out = reconcile_divergence(&racing, &mut store, &provider, "acct", "m1").unwrap();
        assert_eq!(
            out,
            Corrected { changed: false },
            "a race recorded during fetch must skip, not clobber"
        );
        assert_eq!(
            store.placement("acct", "m1").unwrap(),
            Some(Placement::Archive),
            "the optimistic belief must be preserved"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn race_to_pending_during_fetch_is_not_clobbered() {
        // Pre-fetch: terminal Applied (seq 5). Post-fetch: a concurrent in-flight Pending (seq 6)
        // now governs → not terminal → skip.
        assert_race_skips(
            "race-pending",
            vec![(IntentStatus::Applied, 5), (IntentStatus::Pending, 6)],
        );
    }

    #[test]
    fn race_to_a_newer_terminal_during_fetch_is_not_clobbered() {
        // Pre-fetch: terminal Applied (seq 5). Post-fetch: a NEWER terminal Applied (seq 6) — still
        // terminal, but a DIFFERENT intent, so `truth` is stale; the seq-identity re-check must skip
        // rather than overwrite the newer mutation's placement (2026-06-25).
        assert_race_skips(
            "race-newer-terminal",
            vec![(IntentStatus::Applied, 5), (IntentStatus::Applied, 6)],
        );
    }

    /// Build a log+store sharing one DB: record an intent for `m1`, force `status`, and seed the
    /// optimistic placement. Returns (path, log, store) — the guard FIRST, so it drops last.
    fn setup(
        tag: &str,
        status: IntentStatus,
        optimistic: Placement,
    ) -> (crate::test_temp::TempFile, SqliteIntentLog, SqliteMessageStore) {
        let path = unique_temp_db_path(tag);
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let cmd = Command::new(
            derive_idempotency_key("acct", &Facet::Mail, "m1-logical"),
            "acct",
            Facet::Mail,
            Action::Archive {
                message_ref: "m1".into(),
            },
        );
        log.record(
            &cmd,
            &crate::prestate::FrozenBasis {
                // Through the ONE encoding authority, like every real connector — never a
                // hand-spelled key shape (PR).
                native_resource_key: crate::prestate::native_resource_key(
                    crate::FIXTURE_KEY_PROVIDER,
                    &["m1"],
                ),
                touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                    .into_iter()
                    .collect(),
                atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
                role_bindings: std::collections::BTreeMap::new(),
                freshness: crate::prestate::Freshness::ImmutableConstants,
            },
        )
        .unwrap();
        log.set_status_forced(&cmd.idempotency_key, status).unwrap();
        let mut store = SqliteMessageStore::open(&path).unwrap();
        store
            .record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), optimistic)
            .unwrap();
        (path, log, store)
    }

    #[test]
    fn diverged_terminal_intent_is_corrected_to_provider_truth() {
        let (path, log, mut store) = setup("diverge", IntentStatus::Applied, Placement::Archive);
        let provider = FakeProvider(Placement::Inbox);
        let out = reconcile_divergence(&log, &mut store, &provider, "acct", "m1").unwrap();
        assert_eq!(out, Corrected { changed: true });
        assert_eq!(store.placement("acct", "m1").unwrap(), Some(Placement::Inbox));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn converged_terminal_intent_is_a_noop() {
        let (path, log, mut store) = setup("agree", IntentStatus::Applied, Placement::Archive);
        let provider = FakeProvider(Placement::Archive);
        let out = reconcile_divergence(&log, &mut store, &provider, "acct", "m1").unwrap();
        assert_eq!(out, Corrected { changed: false });
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn in_flight_intent_is_skipped_never_clobbered() {
        // Pending (non-terminal) optimistic Archive vs provider Inbox: must NOT correct.
        let (path, log, mut store) = setup("inflight", IntentStatus::Pending, Placement::Archive);
        let provider = FakeProvider(Placement::Inbox);
        let out = reconcile_divergence(&log, &mut store, &provider, "acct", "m1").unwrap();
        assert_eq!(out, Corrected { changed: false });
        assert_eq!(
            store.placement("acct", "m1").unwrap(),
            Some(Placement::Archive)
        );
        std::fs::remove_file(&path).ok();
    }
}
