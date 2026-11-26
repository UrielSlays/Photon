//! Undo: the undo child, its drive and verification, the eligibility read, and the legacy pairs.

use super::*;
use crate::fixtures::{fixture_basis, fixture_observation, fixture_restore, FIXTURE_KEY_PROVIDER};
use crate::keys::{compensation_key, undo_child_key};

#[test]
fn undoing_an_applied_command_records_the_undo_and_marks_it_undone() {
    // The stage-3 contract (§3/§4): undo does not dispatch the action's inverse — it
    // requalifies and restores the CAPTURED pre-state through its OWN admitted child
    // intent. This fixture's forward target A equals the pre-state it observes (P == A —
    // an archive of a message already out of INBOX), so §4.1's no-op kill fires: nothing
    // reaches the wire at all, and the parent is `Undone` on the no-op VERIFICATION.
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), RecordingConnector::new());
    bus.execute(&archive_cmd("k1")).expect("execute should succeed");

    bus.undo("k1").expect("undo should succeed");

    assert_eq!(
        bus.connector().applied_actions(),
        vec![Action::Archive {
            message_ref: "msg-1".into()
        }],
        "the blind inverse is DELETED — no Unarchive is ever dispatched"
    );
    assert!(
        bus.connector().restored().is_empty(),
        "P == A: there is nothing to write back"
    );
    assert_eq!(
        bus.log().get("k1").expect("get should succeed").expect("intent recorded").status,
        IntentStatus::Undone
    );
    // The undo is an operation of its own, terminal on its own row (this log mints no
    // opaque intent_id, so its child key rides the user key — see `undo_context`).
    let child = bus
        .log()
        .get(&undo_child_key("k1"))
        .expect("get")
        .expect("the undo child was admitted");
    assert_eq!(child.status, IntentStatus::Applied);
    assert_eq!(child.command.compensates.as_deref(), Some("k1"));
}

#[test]
fn undo_retries_a_child_whose_restore_failed_transiently() {
    // Reworked TWICE. The property is unchanged: a failed undo DISPATCH must be
    // RETRYABLE, never silently no-op'd — the child stays non-terminal and its restore
    // eventually lands. What changed is WHO retries: the child row is
    // in flight and unclaimed, so recovery owns it, exactly as recovery owns every other
    // non-terminal row. A second undo reports `InProgress` instead of re-driving a child
    // it never claimed — two buses over one store could otherwise both "retry" it and
    // double-restore.
    let path = unique_temp_db_path("undo-retry");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("execute applies Archive");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(retryable_transient("transient restore"), 1);

    let first = bus.undo("k1"); // the restore fails once → the child stays retryable
    assert!(first.is_err(), "first undo should surface the connector error");
    assert_eq!(
        status_str(&path, "k1"),
        "applied",
        "a failed undo NEVER flips the parent — it did not happen"
    );

    // The replay does not own the in-flight child; it says so rather than re-driving.
    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "an unclaimed in-flight child is recovery's, never a replay's"
    );
    assert_eq!(bus.connector().restore_count(), 0, "…and the replay dispatched nothing");

    bus.recover().expect("the sweep re-drives the retryable child");

    assert_eq!(bus.connector().restore_count(), 1, "the retry dispatched the restore");
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Undone,
        "a retried undo must reach Undone"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn admit_undo_child_rows_carry_compensates_not_null() {
    // SCHEMA: occupancy derivation (`capacity.rs::Occupancy`) discriminates
    // forward from undo by `compensates IS NULL`/`IS NOT NULL` alone — the ONE column the
    // `COUNT(*) FILTER (…)` reads. `mint_undo_child_command` sets `compensates =
    // Some(parent.idempotency_key)` UNCONDITIONALLY, so every row `CommandBus::
    // admit_undo_child` (the FRESH admission door, not the §4.1 no-op door) claims must carry
    // it durably — this witness reads the raw column, not the in-memory `Command`, so it
    // proves the SCHEMA property the admission COUNT relies on, not merely the struct's.
    let path = unique_temp_db_path("admit-undo-child-compensates-not-null");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("execute applies Archive");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore:
    // the FRESH `admit_undo_child` door, never the §4.1 no-op kill (which never durably
    // inserts a second row at all).
    bus.undo("k1").expect("undo completes — no scripted failure");

    let child_key = undo_child_key(&opaque_intent_id(&path, "k1"));
    let raw_compensates: Option<String> = raw_conn(&path)
        .query_row(
            "SELECT compensates FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![child_key],
            |r| r.get(0),
        )
        .expect("the admitted undo child row exists");
    assert_eq!(
        raw_compensates.as_deref(),
        Some("k1"),
        "the undo child's `compensates` column must be NOT NULL and name its parent — this \
         is the discrimination `Occupancy`'s `active_forward`/`active_undo` COUNTs depend on"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_never_strands_a_legacy_undoing_row_on_a_connector() {
    // Reworked by the old sweep re-dispatched a blind inverse for
    // an `Undoing` row, so a connector error could strand it (Failed ⇒ `unreconciled()`
    // skips it and undo won't pick it up). Stage 3 removes the class outright — a
    // legacy `Undoing` row is never dispatched AT ALL, so no connector disposition can
    // strand it: it maps to the last VERIFIED truth in ONE sweep and is named in the
    // report. Its undo offer, if still open, is available again through the new path.
    let path = unique_temp_db_path("undo-recover-retry");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k1")).expect("rec");
        log.set_status_forced("k1", IntentStatus::Undoing)
            .expect("hand-seed the legacy mid-flight row");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    // A connector that fails EVERY dispatch: under the old arm this stranded the row.
    let mut bus = CommandBus::new(log, DeterministicFailConnector::new("never called"));

    let r1 = bus.recover().expect("recover (log) ok");

    assert_eq!(r1.recovered, 0, "a mapped legacy row is not a recovery");
    assert!(r1.failed.is_empty(), "nothing was dispatched, so nothing failed");
    assert_eq!(
        r1.legacy_undoing,
        vec!["k1".to_string()],
        "the sweep NAMES the legacy row it mapped"
    );
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Applied,
        "mapped to the last VERIFIED truth — never stranded, never guessed to Undone"
    );
    assert_eq!(
        bus.recover().expect("recover (log) ok").legacy_undoing.len(),
        0,
        "and it is settled in ONE sweep: the second sweep has nothing left to map"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_refuses_to_finish_an_interrupted_legacy_undo_by_guesswork() {
    // Undo must be recoverable; REWORKED at stage 3. The old sweep
    // "finished" an `Undoing` row by RE-DISPATCHING the inverse — but nothing in the
    // store says whether the first inverse landed, so the re-apply was a blind write on
    // a coin-flip premise (undoing an already-undone archive re-adds the message to
    // INBOX). Recoverability now comes from the CHILD row and the captured pre-state,
    // not from re-guessing: the legacy row maps back to the last VERIFIED truth, is
    // NAMED in the report, and the offer (if open) is re-exercisable through undo.
    let path = unique_temp_db_path("undo-recover");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k1")).expect("rec");
        log.set_status_forced("k1", IntentStatus::Undoing).expect("mark undoing"); // crashed mid-undo
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, RecordingConnector::new());

    let report = bus.recover().expect("recover");

    assert!(
        bus.connector().applied_actions().is_empty(),
        "NOTHING is dispatched to 'finish' an unknowable mid-flight — the blind inverse is dead"
    );
    assert_eq!(
        report.legacy_undoing,
        vec!["k1".to_string()],
        "the sweep reports the ambiguity instead of resolving it by guesswork"
    );
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Applied,
        "the row settles at the last VERIFIED truth, never a manufactured `undone`"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn execute_does_not_reapply_a_command_whose_undo_child_is_in_flight() {
    // ADR-P013 / lib.rs:636, reworked to the stage-3 lifecycle: an in-flight undo
    // no longer lives in the PARENT's status (the stored `Undoing` is dead — §4.5), it
    // lives in the child row. A stale `execute()` retry of the original command must
    // still neither re-record nor re-dispatch: the parent is terminal `Applied`, so the
    // truth table answers a no-op replay `Ok`, and the in-flight undo child survives
    // untouched.
    let path = unique_temp_db_path("execute-during-undoing");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("execute applies");
    // A live same-resource predecessor holds the undo child undriven (in flight).
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let peer = Command::new(
            "k-peer",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".into(),
            },
        );
        let basis = bus.connector().resolve_basis(&peer).unwrap();
        log.record(&peer, &basis).expect("seed the pending peer");
    }
    assert!(matches!(bus.undo("k1"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k1"));
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the undo is in flight, on its OWN row"
    );
    let applied_before = bus.connector().apply_count();

    let result = bus.execute(&archive_cmd("k1")); // stale retry of the ORIGINAL command

    assert!(
        result.is_ok(),
        "an Applied parent is a consumed replay — a no-op Ok; got {result:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        applied_before,
        "the original action must NOT be re-dispatched"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "the in-flight undo child must survive the stale retry"
    );
    assert_eq!(status_str(&path, "k1"), "applied");
    std::fs::remove_file(&path).ok();
}

#[test]
fn execute_does_not_resurrect_an_undone_command() {
    // ADR-P013: re-executing an `Undone` key with the same command must NOT
    // resurrect the mutation. The gate classifies `Undone` as `TerminalReplay` — a no-op `Ok`
    // that never re-records or re-applies.
    let path = unique_temp_db_path("execute-after-undone");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        RecordingConnector::new(),
    );
    bus.execute(&archive_cmd("k1")).expect("execute applies");
    bus.undo("k1").expect("undo completes"); // inverse succeeds -> Undone
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Undone
    );
    let applied_before = bus.connector().applied_actions();

    let result = bus.execute(&archive_cmd("k1")); // stale retry of the original

    assert!(
        result.is_ok(),
        "an Undone terminal replay is a no-op Ok, got {result:?}"
    );
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Undone,
        "the deliberately-undone mutation must STAY undone, not be resurrected to Applied"
    );
    assert_eq!(
        bus.connector().applied_actions(),
        applied_before,
        "the original action must NOT be re-dispatched"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_dead_letters_a_deterministic_restore_failure_after_a_transient_one() {
    // ADR-P013 (b) /, reworked to the stage-3
    // dispatch: the undo path honors FailureKind on the CHILD row. The restore fails
    // TRANSIENTLY first (charged, under cap, the child stays retryable), then
    // DETERMINISTICALLY on the re-drive → dead-letter at once rather than retrying to
    // the cap. The parent is never dead-lettered by an undo: it stays truthfully
    // `Applied`, because the undo simply did not happen.
    //
    // The RE-DRIVE is recover's: the child is in flight and this
    // caller never claimed it, so a replaying undo answers `InProgress`. The drive is
    // the SAME chokepoint either way — which is exactly why the two paths cannot drift on
    // the FailureKind decision this witness is about.
    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("archive applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(retryable_transient("restore transient once"), 1);

    assert!(matches!(bus.undo("k1"), Err(ExecuteError::Connector(_))));
    let child = bus.log().get(&undo_child_key("k1")).unwrap().unwrap();
    assert_eq!(child.status, IntentStatus::Pending, "transient ⇒ still retryable");
    assert_eq!(child.attempts, 1, "charged against the CHILD's own budget");

    bus.connector()
        .fail_restore(definitive_refusal("restore permanently rejected"), u32::MAX);
    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "the replay does not own the in-flight child"
    );
    let report = bus.recover().expect("the sweep re-drives it");
    assert_eq!(report.failed.len(), 1, "the sweep reports the failed re-drive");
    assert_eq!(
        bus.log().get(&undo_child_key("k1")).unwrap().unwrap().status,
        IntentStatus::Failed,
        "a deterministic restore failure must dead-letter the child, not retry to cap"
    );
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Applied,
        "the parent stays truthfully Applied — the undo did not happen"
    );
}

#[test]
fn undo_carries_the_original_envelope_onto_the_child_and_the_restore() {
    // Reworked to the stage-3 dispatch: an undo must stay in the originating
    // governance context (principal/epoch/tier), never a reset all-None one, or an
    // evidence/authorization layer sees it as a different/unauthenticated actor. Two
    // carriers now: the admitted CHILD row copies the parent's envelope, and the restore
    // is dispatched with the PARENT's own command.
    #[derive(Default)]
    struct EnvelopeCapturingConnector {
        applied: std::cell::RefCell<Vec<Command>>,
        restored: std::cell::RefCell<Vec<Command>>,
        observations: std::cell::Cell<usize>,
    }
    impl Connector for EnvelopeCapturingConnector {
        fn apply(&self, command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
            self.applied.borrow_mut().push(command.clone());
            Ok(())
        }
        fn resolve_basis(
            &self,
            command: &Command,
        ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
            Ok(fixture_basis(command))
        }
        /// The FIRST observation (the forward capture) sees the message IN inbox, so
        /// `P ≠ A`; the undo's observation sees the forward result (`C == A`), which is
        /// the §3.2 arm that actually dispatches a restore.
        fn observe(
            &self,
            _command: &Command,
            basis: &prestate::FrozenBasis,
        ) -> Result<prestate::Observation, ConnectorError> {
            let n = self.observations.get();
            self.observations.set(n + 1);
            Ok(prestate::Observation {
                native_resource_key: basis.native_resource_key.clone(),
                atoms: [("membership:INBOX".to_string(), n == 0)]
                    .into_iter()
                    .collect(),
                request_id: None,
                provider_label_vector: None,
            })
        }
        fn restore(
            &self,
            command: &Command,
            basis: &prestate::FrozenBasis,
            p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), ConnectorError> {
            fixture_restore(basis, p)?;
            self.restored.borrow_mut().push(command.clone());
            Ok(())
        }
    }

    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        EnvelopeCapturingConnector::default(),
    );
    let mut cmd = archive_cmd("k1");
    cmd.envelope.principal = Some("user:clinton".into());
    cmd.envelope.epoch = Some(7);
    bus.execute(&cmd).expect("execute applies");
    bus.undo("k1").expect("undo completes");

    let child = bus
        .log()
        .get(&undo_child_key("k1"))
        .expect("g")
        .expect("the undo child was admitted");
    assert_eq!(
        child.command.envelope, cmd.envelope,
        "the child must carry the originating envelope, not a reset all-None one"
    );
    let restored = bus.connector().restored.borrow();
    let dispatched = restored.last().expect("a restore was dispatched");
    assert_eq!(
        dispatched.envelope, cmd.envelope,
        "the restore rides the PARENT's command, so it is in the same context"
    );
    assert_eq!(
        bus.connector().applied.borrow().len(),
        1,
        "no inverse action is ever applied"
    );
}

#[test]
fn undo_is_not_defeated_by_a_later_pending_same_resource_intent() {
    // Reworked to the stage-3 contract: k1 Archive(msg-1)
    // is Applied; k2 Archive(msg-1) is recorded but left Pending by a transient connector
    // failure (a same-resource predecessor). undo must NOT drive inline — it would
    // race recover's re-apply of k2 and end archived. It DEFERS an undo child at the
    // seq tail; recover then re-applies k2 and drives the child at ITS head moment,
    // where §3.2 requalifies (C == A ⇒ Restore) and the connector writes the CAPTURED
    // pre-state back. The user's undo still wins — but by RESTORING P, never by applying
    // an inverse action.
    let path = unique_temp_db_path("undo-vs-pending-same-resource");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("k1 archive applies"); // apply #1 ok, P = {INBOX:true}
    bus.connector().fail_apply(1);
    let _ = bus.execute(&Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    )); // apply #2 fails transiently → k2 left Pending (same resource as k1)
    assert_eq!(
        bus.log().get("k2").expect("g").expect("i").status,
        IntentStatus::Pending,
        "precondition: k2 is a pending same-resource predecessor"
    );

    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "the undo DEFERS behind its predecessor — in flight, never a false Ok"
    );
    assert_eq!(bus.connector().restore_count(), 0, "nothing dispatched inline");
    assert_eq!(
        status_str(&path, "k1"),
        "applied",
        "…and the parent does not pre-flip at scheduling"
    );
    // k2's re-apply lands DURING the sweep, so the observed state at the child's head is
    // the forward target: C == A. The double is told to make that true the way a provider
    // does — at the apply — rather than by pre-setting it: since stage 4 the
    // forward RETRY observes the provider too, and a pre-set target would make k2's own
    // requalification (correctly) read "somebody already archived it", which is not the
    // world this witness is about.
    bus.connector().apply_lands();

    bus.recover().expect("recovery sequences k2, then the undo child at its head");

    assert_eq!(
        bus.connector().restore_count(),
        1,
        "the child drove at its head and dispatched the delta restore"
    );
    assert_eq!(
        bus.connector().restored()[0].1,
        atoms(&[("membership:INBOX", true)]),
        "the user's undo wins by writing the CAPTURED P back — not by re-archiving or \
         by applying an inverse action"
    );
    assert_eq!(
        bus.connector().apply_count(),
        2,
        "exactly the two FORWARD applies (k1, then k2's re-apply) ever dispatched"
    );
    assert_eq!(
        status_str(&path, "k1"),
        "undone",
        "the parent flips only now, at VERIFICATION"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_dead_letters_a_deferred_undo_child_on_its_own_budget() {
    // INVERTED by and the inversion is the point. The old
    // rule ("never dead-letter a compensation") existed ONLY to cover a lie: the old
    // path flipped the original `Undone` at SCHEDULING, so terminalizing the
    // compensation would have left the log claiming an undo that never happened. Stage 3
    // never pre-flips, so the exemption has nothing left to protect: a permanently
    // refusing restore dead-letters the CHILD on its own budget, and the parent stays
    // truthfully `applied` with the failure surfaced — no lie to cover, no saga row
    // retrying forever behind a false `Undone`.
    let path = unique_temp_db_path("compensation-not-dead-lettered");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("k1 archive applies");
    bus.connector().fail_apply(1);
    let _ = bus.execute(&Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    )); // transient fail → k2 Pending (same resource as k1)
    assert_eq!(bus.log().get("k2").unwrap().unwrap().status, IntentStatus::Pending);
    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "the undo defers behind k2 as an undo CHILD"
    );
    // The restore permanently refuses (a deterministic provider rejection).
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(definitive_refusal("restore cannot apply"), u32::MAX);

    // recover re-applies k2 (ok), then drives the child, whose restore is refused.
    let report = bus.recover().expect("recovery sweep runs");

    let child_key = undo_child_key(&opaque_intent_id(&path, "k1"));
    let child = bus.log().get(&child_key).expect("get").expect("the child exists");
    assert_eq!(
        child.status,
        IntentStatus::Failed,
        "a deterministic restore refusal dead-letters the CHILD — no exemption survives"
    );
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Applied,
        "…and that is HONEST precisely because the parent was never pre-flipped: the \
         forward action still stands, and the log says so"
    );
    assert_eq!(
        report.failed.len(),
        1,
        "the refusal is reported against the child's own key"
    );
    assert_eq!(report.failed[0].0, child_key);
    assert_eq!(bus.connector().restore_count(), 0, "nothing was written");
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_surfaces_a_deferred_undo_conflict_it_refused() {
    // Recover's undo-child arm terminalized a §3.2 CONFLICT child
    // `Failed` and left the parent truthfully `Applied` (correct) but `continue`d
    // SILENTLY — RecoverReport carried no trace of the undo the sweep refused, so a caller
    // sweeping a batch could not tell a conflict-refused undo from one that never ran. The
    // conflict is now NAMED in `undo_conflicts` (fail-loud, UNDETERMINED-never-silent); the
    // child-Failed + parent-Applied behavior is unchanged.
    let path = unique_temp_db_path("recover-surfaces-undo-conflict");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::pair(true, false),
    );
    // Forward archive of the §3.1a pair: P (captured) ≠ A (the move target).
    bus.execute(&archive_cmd("k1")).expect("k1 archive applies");
    // A same-resource successor fails transiently ⇒ Pending, so the undo must DEFER and be
    // driven by recover rather than synchronously.
    bus.connector().fail_apply(1);
    let _ = bus.execute(&Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    ));
    assert_eq!(bus.log().get("k2").unwrap().unwrap().status, IntentStatus::Pending);
    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "the undo defers behind k2 as a Pending undo CHILD"
    );
    // The provider reaches the pair's reachable THIRD state ({both}): C matches NEITHER P
    // nor A ⇒ the drive refuses with a §3.2 conflict.
    bus.connector().set_state(atoms(&[
        ("membership:mb-i", true),
        ("membership:mb-a", true),
    ]));

    let report = bus.recover().expect("recovery sweep runs");

    let child_key = undo_child_key(&opaque_intent_id(&path, "k1"));
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Failed,
        "the conflict terminalizes the child (unchanged behavior)"
    );
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Applied,
        "the parent stays truthfully Applied (unchanged behavior)"
    );
    assert_eq!(
        report.undo_conflicts,
        vec![child_key],
        "the refused undo conflict is SURFACED in the report, not swallowed"
    );
    assert!(
        report.failed.is_empty(),
        "a resolved conflict is not a retryable failure"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_undo_child_starts_with_its_own_retry_budget_not_the_parents() {
    // Rework: the durable `attempts` counter must not be shared across the
    // forward-apply phase and a later undo — an intent that only reached `Applied` after
    // transient apply-retries would otherwise carry that count into the undo dispatch and
    // dead-letter it far short of the documented cap. Stage 3 makes that STRUCTURAL: the
    // undo is a row of its own, so its budget is its own by construction (the old
    // `reset_attempts` call — and the trait method — are DELETED).
    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        UndoStageConnector::single(false, true),
    );
    bus.connector().fail_apply(4); // the forward apply is flaky 4 times
    let cmd = archive_cmd("k1");
    assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_)))); // attempt 1, Pending
    for _ in 0..4 {
        bus.recover().expect("recovery sweep");
    }
    let applied = bus.log().get("k1").unwrap().unwrap();
    assert_eq!(applied.status, IntentStatus::Applied, "k1 applies after transient retries");
    assert_eq!(applied.attempts, 4, "the apply phase accumulated 4 transient attempts");

    // The undo's restore fails transiently: it must be CHARGED, and charged to the child.
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(retryable_transient("restore transient"), u32::MAX);
    assert!(matches!(bus.undo("k1"), Err(ExecuteError::Connector(_))));

    let child = bus.log().get(&undo_child_key("k1")).unwrap().unwrap();
    assert_eq!(
        child.attempts, 1,
        "attempt 1 of {RETRY_CAP} on the CHILD's own budget — the parent's burned counter \
         is not inherited"
    );
    assert_eq!(
        child.status,
        IntentStatus::Pending,
        "so the undo is still retryable, not dead-lettered by the apply phase's count"
    );
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().attempts,
        4,
        "and the parent's own counter is untouched by the undo"
    );
}

#[test]
fn undo_direct_dead_letters_a_deterministic_restore_failure() {
    // SingleFailureReconciliationBoundary, reworked: the undo
    // dispatch routes its failures through the SAME reconcile choke point as
    // execute/recover. A deterministic restore failure dead-letters the CHILD at once
    // instead of leaving it in flight with the cap silently bypassed — and the PARENT
    // stays truthfully `Applied` (stage 3 never pre-flips it).
    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("archive applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(definitive_refusal("restore rejected"), u32::MAX);
    assert!(matches!(bus.undo("k1"), Err(ExecuteError::Connector(_))));
    assert_eq!(
        bus.log().get(&undo_child_key("k1")).unwrap().unwrap().status,
        IntentStatus::Failed,
        "a deterministic restore failure must dead-letter the child immediately"
    );
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Applied,
        "the parent is never dead-lettered by its own undo"
    );
}

#[test]
fn undo_direct_transient_restore_dead_letters_the_child_at_the_cap() {
    // Reworked: a transient restore failure charges the CHILD's
    // budget through the choke point, so repeated retries dead-letter at RETRY_CAP rather
    // than bypassing the cap forever. The first attempt is undo's own (it claimed the
    // child); every RETRY is recovery's, because an in-flight child it never claimed is
    // not a replay's to drive. The budget is the CHILD's either way —
    // the ONE reconcile boundary inside the ONE chokepoint.
    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("archive applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(retryable_transient("restore transient"), u32::MAX);
    let _ = bus.undo("k1");
    for _ in 1..RETRY_CAP {
        bus.recover().expect("the sweep retries the in-flight child");
    }
    assert_eq!(
        bus.log().get(&undo_child_key("k1")).unwrap().unwrap().status,
        IntentStatus::Failed,
        "repeated retries with a transient restore dead-letter the child at the cap"
    );
    assert_eq!(
        bus.log().get("k1").unwrap().unwrap().status,
        IntentStatus::Applied,
        "…and the parent still says, truthfully, that the forward action stands"
    );
}

#[test]
fn undo_of_a_dead_lettered_intent_returns_failed_not_a_silent_ok() {
    // Undo of a dead-lettered row must NOT be reported as a
    // successful no-op — the operation did not succeed. It surfaces the dead-letter
    // replay signal `Err::Failed`, uniform with execute's Failed → Err::Failed contract
    // (ADR-P013 return-signal: never Ok for a not-succeeded operation). Stage 3 splits
    // the two lineages honestly: a failed FORWARD parent answers here; a failed UNDO
    // answers off the CHILD row (see `w_undo_target_kind_and_duplicate_and_replay`).
    let mut bus = CommandBus::new(
        InMemoryIntentLog::new(),
        DeterministicFailConnector::new("archive rejected"),
    );
    assert!(matches!(
        bus.execute(&archive_cmd("k1")),
        Err(ExecuteError::Connector(_))
    ));
    assert_eq!(bus.log().get("k1").unwrap().unwrap().status, IntentStatus::Failed);

    let attempt = bus.undo("k1");

    assert!(
        matches!(attempt, Err(ExecuteError::Failed)),
        "undo() of a dead-lettered intent must return Err::Failed, not a silent Ok; got {attempt:?}"
    );
}

#[test]
fn recover_self_heals_an_undo_child_that_crashed_after_the_parent_flip() {
    // CompensationLinkageAtomicity, rework: the two-write crash
    // window still exists, but stage 3 REVERSED its order. The drive flips the parent
    // `Undone` at verification FIRST, then terminalizes the child — so the surviving
    // window is parent Undone + child Pending (never the old "original lags at Applied
    // while its compensation is durable"). recover must converge that window on the
    // child's own terminal, and — because the parent's flip already RECORDS the verified
    // outcome — WITHOUT a second dispatch or even a provider read. A store written by a
    // previous process is the shape here: the rows are hand-seeded, not driven.
    let path = unique_temp_db_path("undo-crash-selfheal");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k1")).expect("rec k1");
        log.set_status_forced("k1", IntentStatus::Undone)
            .expect("the verified parent flip is durable");
        // The undo child, durable with its explicit `compensates` link, but its own
        // terminal never landed (the crash window):
        let mut child = Command::new(
            "k1:undo",
            "acct-1",
            Facet::Mail,
            Action::Unarchive {
                message_ref: "msg-1".into(),
            },
        );
        child.compensates = Some("k1".into());
        record_basis(&mut log, &child).expect("rec the undo child");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, RecordingConnector::new());

    let report = bus.recover().expect("recover converges the crashed child");

    assert_eq!(
        bus.log().get("k1:undo").expect("g").expect("i").status,
        IntentStatus::Applied,
        "the re-drive converges the child on its own terminal"
    );
    assert!(
        bus.connector().applied_actions().is_empty(),
        "NO second dispatch: the parent's `undone` already records the verified outcome"
    );
    assert!(
        bus.connector().restored().is_empty(),
        "…and no restore either — the short-circuit spends not even a provider read"
    );
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Undone,
        "the parent's verified truth is untouched by the convergence"
    );
    assert_eq!(report.recovered, 1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_refuses_a_role_permutation_between_parent_and_child_admissions() {
    // Role-keyed class, undo-consumer half. The rework closed the
    // class connector-side (`JmapConnector::reverify_role_basis`) but the ENGINE's
    // parent/child basis-match gate in `drive_undo_child` still compared only the native
    // key + the touched-atom id SET — never `role_bindings`. When JMAP Inbox/Archive roles
    // are PERMUTED between the parent (forward) admission and the undo-child admission, both
    // bases keep the SAME native key and the SAME touched-atom id-set (the operand map is
    // unchanged; only the role→id DIRECTION inverted), so the id-set gate passed and the
    // undo proceeded across a real role rebound — restoring with the parent's basis while
    // the child was admitted against the swapped world. A role permutation the operand map
    // alone cannot see is a real rebound and must refuse DETERMINISTICALLY, exactly as the
    // connector-side gate now does.
    //
    // The in-crate fixture connectors mint bases with EMPTY role_bindings, so the pair is
    // hand-seeded via the log: a real forward parent (through execute, so config/epoch and
    // the captured journal exist), then its basis + captured P patched to a two-operand role
    // basis, and its undo CHILD inserted with the SAME native key + SAME touched-atom id-set
    // but a role→id PERMUTATION. The child is then driven through the REAL recover consumer
    // whose observe would otherwise ACCEPT (state == A ⇒ Restore) — so only the gate can
    // refuse it.
    const PARENT_BASIS: &str = r#"{"native_resource_key":"test:msg-1","touched_atoms":{"membership:aa":"aa","membership:bb":"bb"},"atom_targets":{"membership:aa":false,"membership:bb":true},"role_bindings":{"inbox":"aa","archive":"bb"},"freshness":"immutable_constants"}"#;
    // SAME native key, SAME touched-atom id-set, SAME A — only the role→id map is inverted.
    const CHILD_BASIS: &str = r#"{"native_resource_key":"test:msg-1","touched_atoms":{"membership:aa":"aa","membership:bb":"bb"},"atom_targets":{"membership:aa":false,"membership:bb":true},"role_bindings":{"inbox":"bb","archive":"aa"},"freshness":"immutable_constants"}"#;

    let path = unique_temp_db_path("undo-role-permutation");
    // A real forward parent through the real path — stands up config/epoch and a captured
    // journal row the drive later reads.
    {
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            UndoStageConnector::single(false, true),
        );
        bus.execute(&archive_cmd("k1")).expect("parent archive applies");
    }
    // Hand-seed the role-keyed pair the fixtures cannot mint.
    {
        let conn = raw_conn(&path);
        let parent_intent_id: String = conn
            .query_row(
                "SELECT intent_id FROM intents WHERE idempotency_key='k1';",
                [],
                |r| r.get(0),
            )
            .expect("parent intent_id");
        conn.execute(
            "UPDATE intents SET frozen_basis=?1 WHERE idempotency_key='k1';",
            rusqlite::params![PARENT_BASIS],
        )
        .expect("patch the parent's frozen basis to a role-keyed two-operand basis");
        // Captured P keyed to the new atoms and DISTINCT from A, so the §4.1 no-op kill never
        // fires and the drive reaches the basis-match gate / observe. `observed` and
        // `resolved_operands` are patched ALONGSIDE the basis so the seeded row stays
        // consistent with `undo_context`'s read-boundary `JournalRow::validate`: observed == touched_atom (M1 projection) and resolved_operands equals the
        // patched basis's operand map — the role permutation under test lives in
        // `role_bindings`, not in these content-free projections.
        conn.execute(
            "UPDATE pre_state SET observed=?1, touched_atom=?1, resolved_operands=?2
                   WHERE intent_id=?3;",
            rusqlite::params![
                r#"{"membership:aa":true,"membership:bb":false}"#,
                r#"{"membership:aa":"aa","membership:bb":"bb"}"#,
                parent_intent_id
            ],
        )
        .expect("patch the captured pre-state P");
        // The undo child: reserved key, kind=undo, compensates=k1, roles SWAPPED.
        conn.execute(
            "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref, status,
                                      compensates, seq, intent_id, kind, journal_required,
                                      capture_mode_generation, admitted_control_epoch, frozen_basis)
                 VALUES (char(1)||'k1-undo','acct-1','mail','unarchive','msg-1','pending',
                         'k1', 2, '00000000000000000000000000000002', 'undo', 0, 1, 1, ?1);",
            rusqlite::params![CHILD_BASIS],
        )
        .expect("seed the swapped-role undo child");
    }
    // Drive the pending child through the REAL recover consumer. Its observe would
    // otherwise accept — provider state == A ⇒ Restore.
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    bus.connector()
        .set_state(atoms(&[("membership:aa", false), ("membership:bb", true)]));

    let report = bus.recover().expect("the sweep drives the pending child");

    assert_eq!(
        bus.connector().observe_count(),
        0,
        "the role-permutation gate refuses BEFORE any provider read"
    );
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "NO restore may be dispatched across an id-set-preserving role rebound"
    );
    assert_eq!(
        status_str(&path, "k1"),
        "applied",
        "the parent stays truthfully Applied — the undo did not happen"
    );
    assert_eq!(
        status_str(&path, "\u{1}k1-undo"),
        "failed",
        "the swapped-role child terminalizes Failed (deterministic basis rebound)"
    );
    assert_eq!(report.recovered, 0, "nothing was healed");
    assert_eq!(report.failed.len(), 1, "the deterministic refusal is reported");
    std::fs::remove_file(&path).ok();
}

#[test]
fn recovery_heals_a_completed_undo_child_across_an_epoch_bump() {
    // CONVERGENCE PRECEDES THE FENCE. The drive's admitted-epoch
    // fence used to run BEFORE the parent-`Undone` convergence short-circuit, which
    // stranded a COMPLETED undo forever: restore succeeded, `verify_undo` wrote the
    // parent `Undone`, the process crashed before the child's own terminal landed, and a
    // sever/epoch bump arrived before recovery. Every later sweep then hit the fence
    // first, returned `InProgress`, left the child `Pending` — and, because a non-terminal
    // child raises the per-resource barrier, blocked every later operation on that
    // resource too.
    //
    // The convergence branch is HEAL-ONLY: it writes one status and reaches neither the
    // wire nor a provider read, so it is epoch-safe BY CONSTRUCTION. The fence exists to
    // stop WIRE EFFECTS under a stale epoch, and after the reorder it guards exactly the
    // paths that can reach one (observe / restore).
    let path = unique_temp_db_path("undo-converge-epoch");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("k1")).expect("rec k1");
        log.set_status_forced("k1", IntentStatus::Undone)
            .expect("the verified parent flip is durable");
        let mut child = Command::new(
            "k1:undo",
            "acct-1",
            Facet::Mail,
            Action::Unarchive {
                message_ref: "msg-1".into(),
            },
        );
        child.compensates = Some("k1".into());
        record_basis(&mut log, &child).expect("rec the undo child");
    }
    // The sever lands in the crash window, before recovery ever runs.
    raw_conn(&path)
        .execute("UPDATE control_epoch SET epoch = 2 WHERE id = 1;", [])
        .expect("hand-bump the control epoch (stands in for the stage-4 sever)");
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, RecordingConnector::new());

    let report = bus.recover().expect("recover heals across the bump");

    assert_eq!(
        bus.log().get("k1:undo").expect("g").expect("i").status,
        IntentStatus::Applied,
        "a COMPLETED undo converges on its own terminal — a stale epoch cannot strand it"
    );
    assert_eq!(report.recovered, 1);
    assert!(
        bus.connector().applied_actions().is_empty(),
        "heal-only: nothing reached the wire"
    );
    assert!(
        bus.connector().restored().is_empty(),
        "…and not even a provider read, which is WHY the fence does not apply here"
    );
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Undone,
        "the parent's verified truth is untouched"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_does_not_let_a_coincidental_undo_suffixed_key_corrupt_an_unrelated_intent() {
    // Recovery heals an original ONLY via the EXPLICIT `compensates` link, never a key
    // text guess. A user command literally keyed "foo:undo" — even one that IS the inverse of a
    // "foo" archive — has `compensates: None`, so recovering it must leave "foo" untouched.
    let path = unique_temp_db_path("undo-suffix-coincidence");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("foo")).expect("rec foo");
        log.set_status_forced("foo", IntentStatus::Applied).expect("foo applied");
        // A user command that LOOKS exactly like a compensation (key + inverse action) but carries
        // no explicit link — the worst case for a key-suffix heuristic, harmless for the link.
        let coincidental = Command::new(
            "foo:undo",
            "acct-1",
            Facet::Mail,
            Action::Unarchive {
                message_ref: "msg-1".into(),
            },
        );
        assert!(coincidental.compensates.is_none(), "user command has no link");
        record_basis(&mut log, &coincidental).expect("rec coincidental");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, RecordingConnector::new());
    bus.recover().expect("recover");
    assert_eq!(
        bus.log().get("foo").expect("g").expect("i").status,
        IntentStatus::Applied,
        "an unlinked `foo:undo` must NOT mark the unrelated `foo` Undone"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_undo_retry_re_drives_the_same_child_never_mints_a_second_past_a_later_action() {
    // Reworked to the stage-3 shape: a RETRY of an in-flight undo must keep the
    // child in the `seq` slot it was ADMITTED into, never mint a new tail row that jumps
    // past a later same-resource action (which would let the older undo wrongly defeat
    // the newer one). The key IS the invariant — `compensation_key(parent intent_id)` is
    // idempotent — so the retry re-drives the SAME row, and while a later action holds
    // the resource that drive is `InProgress`. Sequence: archive k1 (Applied); undo's
    // restore fails transiently → the child is in flight; archive k3 (same resource)
    // defers behind it; retry undo → InProgress, still exactly ONE child.
    // (recover-driven sequencing of the pair is
    // `undo_is_not_defeated_by_a_later_pending_same_resource_intent`.)
    let path = unique_temp_db_path("undoing-retry-no-tail");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k1")).expect("k1 archive applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(retryable_transient("restore transient"), u32::MAX);
    let first = bus.undo("k1"); // the restore fails -> the child stays in flight
    assert!(first.is_err(), "first undo surfaces the restore failure");
    let child_key = undo_child_key(&opaque_intent_id(&path, "k1"));
    let child_seq = bus.log().get(&child_key).unwrap().unwrap().seq;
    assert_eq!(status_str(&path, "k1"), "applied", "the parent never pre-flips");

    // A later same-resource action defers behind the in-flight undo child.
    let k3 = Command::new(
        "k3",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    assert!(matches!(bus.execute(&k3), Err(ExecuteError::InProgress)));

    // Retry the undo while k3 is pending: it stays in its slot, and no second child.
    assert!(matches!(bus.undo("k1"), Err(ExecuteError::InProgress)));
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents WHERE kind = 'undo';", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "an undo retry must not create a second, later-ordered undo intent"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().seq,
        child_seq,
        "…and the one child keeps the seq slot it was admitted into"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_does_not_heal_a_mislinked_compensation() {
    // (defense in depth), reworked by stage 3 and RE-POINTED by
    // The old post-dispatch `action.inverse()` link check died with the blind
    // inverse it guarded; restored it — stronger, and at the chokepoint's ENTRY — as
    // the MISLINK GATE, which refuses any row that is not the child
    // [`mint_undo_child_command`] would mint for this parent. This row is exactly that: a
    // link to `base` carrying a DIFFERENT message's action (and, downstream, a basis
    // frozen on that other message), so it now dead-letters at the mislink gate, strictly
    // ahead of the basis-match gate it used to reach.
    //
    // The BASIS-MATCH gate is not thereby untested: it keeps its own witness on a
    // WELL-FORMED child whose resolved operands moved
    // (`jmap::tests::jmap_move_undo_refuses_when_the_childs_operands_are_not_the_parents`)
    // — the only shape that can reach it. Either way the linked intent is left untouched
    // and the sweep keeps going.
    let path = unique_temp_db_path("mislinked-compensation");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("base")).expect("rec base"); // base = Archive(msg-1)
        log.set_status_forced("base", IntentStatus::Applied)
            .expect("base applied");
        // Links to `base`, but its OWN basis is frozen on a different message.
        let mut bad = Command::new(
            "base:undo",
            "acct-1",
            Facet::Mail,
            Action::Unarchive {
                message_ref: "msg-2".into(),
            },
        );
        bad.compensates = Some("base".into());
        record_basis(&mut log, &bad).expect("rec mislinked");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, UndoStageConnector::single(false, true));

    let report = bus.recover().expect("one refused child never aborts the sweep");

    assert_eq!(
        bus.log().get("base").expect("g").expect("i").status,
        IntentStatus::Applied,
        "a mislinked compensation must NOT mark the linked intent Undone"
    );
    assert_eq!(
        bus.log().get("base:undo").expect("g").expect("i").status,
        IntentStatus::Failed,
        "…it dead-letters on a deterministic refusal (the mislink gate, r6)"
    );
    assert_eq!(bus.connector().restore_count(), 0, "and writes NOTHING");
    assert_eq!(report.failed.len(), 1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_mislinked_compensation_never_heals_an_unrelated_parent() {
    // THE RED. The old `recover()` heal validated
    // `original.command.action.inverse() == child.action` (and the account) BEFORE
    // healing; the stage-3 rework dropped that check and leaned entirely on the
    // BASIS-MATCH gate — while `Command::compensates`' doc went on PROMISING it. The
    // claim outran the witness, and the gate cannot cover the hole: it compares the
    // native RESOURCE, so a mislinked row on the SAME resource sails through it — and the
    // §4.1 no-op arm (`P == A`) sits AHEAD of the gate with no identity check at all.
    //
    // The shape below is the cheapest reachable instance: a compensation row linked to a
    // parent it is NOT the inverse of (same action, same message), on a parent whose
    // journal says `P == A`. Pre-fix, the sweep drove it straight into the no-op arm and
    // flipped the parent `Undone` — a durable claim that an undo happened, minted by a
    // row that never was this parent's undo.
    let path = unique_temp_db_path("mislink-heals-unrelated-parent");
    {
        // A = "not in INBOX" and the capture-time truth is the same ⇒ P == A.
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            UndoStageConnector::single(false, false),
        );
        bus.execute(&archive_cmd("base")).expect("the forward archive applies");
        assert_eq!(status_str(&path, "base"), "applied", "precondition");
    }
    {
        // The mislink: it NAMES `base` and sits on `base`'s own resource (so the
        // basis-match gate is satisfied), but its action is `base`'s action — not its
        // INVERSE. No door this parent has ever minted such a child.
        let mut log = SqliteIntentLog::open(&path).expect("reopen");
        let mut bad = Command::new(
            "base:mislink",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".into(),
            },
        );
        bad.compensates = Some("base".into());
        record_basis(&mut log, &bad).expect("seed the mislinked compensation");
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, false),
    );

    let report = bus.recover().expect("one refused child never aborts the sweep");

    assert_eq!(
        status_str(&path, "base"),
        "applied",
        "a mislinked compensation must NEVER flip its named parent — not even through \
         the wire-free no-op arm"
    );
    assert_eq!(
        status_str(&path, "base:mislink"),
        "failed",
        "…it terminalizes on the deterministic mislink refusal"
    );
    assert_eq!(report.failed.len(), 1, "and it is REPORTED, never silently swallowed");
    assert_eq!(bus.connector().restore_count(), 0, "nothing is written back");
    std::fs::remove_file(&path).ok();
}

#[test]
fn recover_fails_loud_when_an_undo_child_has_lost_its_parents_journal_row() {
    // The §4.4 `JournalGapUnexplained` answer inside the SWEEP. A child admitted against
    // a captured pre-state whose journal row is GONE cannot be driven: there is no P to
    // restore and no honest way to invent one. That is a statement about the STORE, not
    // about one connector call, so it is NOT swallowed into `report.failed` — the sweep
    // fails loud (the same class as a durable-log error) and the linked parent is left
    // exactly as it was. (§6 destruction is dormant, so today only external tampering
    // reaches this; stage 4's grammar is what will terminalize such a child.)
    let path = unique_temp_db_path("undo-child-journal-gap");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &archive_cmd("base")).expect("rec base");
        log.set_status_forced("base", IntentStatus::Applied).expect("base applied");
        let mut child = Command::new(
            "base:undo",
            "acct-1",
            Facet::Mail,
            Action::Unarchive {
                message_ref: "msg-1".into(),
            },
        );
        child.compensates = Some("base".into());
        record_basis(&mut log, &child).expect("rec the child");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let mut bus = CommandBus::new(log, UndoStageConnector::single(false, true));

    let swept = bus.recover();

    assert_eq!(
        swept,
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::JournalGapUnexplained
        )),
        "an unexplained journal gap is fail-loud, never a benign sweep result"
    );
    assert_eq!(
        bus.log().get("base").expect("g").expect("i").status,
        IntentStatus::Applied,
        "the linked parent is untouched"
    );
    assert_eq!(bus.connector().restore_count(), 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_user_command_keyed_like_the_old_undo_suffix_does_not_block_a_deferred_undo() {
    // Compensation keys live in a RESERVED namespace, so a normal command keyed exactly
    // "<orig>:undo" no longer collides with (and blocks) the deferred undo of <orig>.
    let path = unique_temp_db_path("undo-key-reserved");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        FailSecondConnector::new(),
    );
    bus.execute(&archive_cmd("k1")).expect("k1 archive applies"); // apply #1 ok
    // A pending same-resource predecessor forces undo down the defer path.
    let _ = bus.execute(&Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    )); // apply #2 fails → k2 Pending (msg-1)
    // A normal user command literally keyed "k1:undo" on a DIFFERENT resource (succeeds, Applied).
    bus.execute(&Command::new(
        "k1:undo",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-other".into(),
        },
    ))
    .expect("a user command keyed k1:undo is allowed (not the reserved namespace)"); // apply #3 ok

    // The deferred undo must still admit its child (reserved key) without colliding —
    // and a deferral is `InProgress`, never a false Ok (stage 3: scheduling is not
    // completion).
    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "the deferred undo is in flight, not blocked by the user's k1:undo key"
    );
    assert!(
        bus.log()
            .get(&undo_child_key(&opaque_intent_id(&path, "k1")))
            .unwrap()
            .is_some(),
        "the undo child was admitted under the RESERVED key, which no user key can claim"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undoing_an_undo_child_is_a_no_op() {
    // Rework: an undo CHILD is internal (`compensates.is_some()`) and is
    // itself already an undo. Calling undo on its durable key must dispatch NOTHING
    // (undoing it would redo the original while the original stays Undone) — the §4.5
    // target-eligibility gate answers it as a no-op Ok.
    let path = unique_temp_db_path("undo-compensation-noop");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        FailSecondConnector::new(),
    );
    bus.execute(&archive_cmd("k1")).expect("k1 applies"); // apply #1 ok
    let _ = bus.execute(&Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    )); // apply #2 fails → k2 Pending predecessor
    assert!(
        matches!(bus.undo("k1"), Err(ExecuteError::InProgress)),
        "the undo defers behind k2 — its child is admitted, undriven"
    );
    // Clear the predecessor, then let RECOVERY drive the in-flight child at its head — the
    // one re-drive path, since undo's replay never owned it.
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'failed' WHERE idempotency_key = 'k2';",
            [],
        )
        .expect("terminalize the predecessor");
    bus.recover().expect("the child drives at its head moment");

    let child_key = undo_child_key(&opaque_intent_id(&path, "k1"));
    let child = bus.log().get(&child_key).expect("g").expect("child exists");
    assert_eq!(child.status, IntentStatus::Applied);
    assert!(child.command.compensates.is_some());

    let before = bus.connector().applied.borrow().len();
    bus.undo(&child_key).expect("undo on an undo child is Ok");
    assert_eq!(
        bus.connector().applied.borrow().len(),
        before,
        "undoing an undo child must NOT dispatch anything (no redo of the original)"
    );
    assert_eq!(
        bus.log().get("k1").expect("g").expect("i").status,
        IntentStatus::Undone,
        "the original stays Undone"
    );
    std::fs::remove_file(&path).ok();
}

// ---- Stage 3: the store side of the §4.4 eligibility read -----------------------

#[test]
fn undo_context_reads_row_and_latches_time_high_water() {
    // §4.4 Expired is STICKY: derived past `undo_offer_until` it is
    // durably latched against a persisted time high-water mark; a wall-clock rollback
    // never re-opens an expired offer, and an ambiguous clock evaluates fail-closed as
    // expired. This is the store half: ONE read that hands the derivation the parent's
    // opaque intent_id, the captured P + deadline, tombstone presence, and an
    // effective-now that is `max(wall clock, persisted high-water)` — re-persisted.
    let path = unique_temp_db_path("undo-context");
    {
        let mut bus = sqlite_bus_with_counting_connector(&path);
        bus.execute(&archive_cmd("k-ctx-1")).unwrap();
    }
    // Push the OFFER deadline far into the past. The row still EXISTS (§6 destruction
    // is dormant) — the offer lapsed, the bytes did not.
    raw_conn(&path)
        .execute(
            "UPDATE pre_state SET undo_offer_until = '1970-01-08T00:00:00Z';",
            [],
        )
        .expect("hand-expire the offer");
    let mut log = SqliteIntentLog::open(&path).expect("reopen");
    let ctx = log
        .undo_context("k-ctx-1")
        .expect("undo_context reads")
        .expect("the parent intent exists");
    let journal = ctx
        .journal
        .as_ref()
        .expect("a journal-required forward intent owns a row");
    assert_eq!(journal.undo_offer_until, "1970-01-08T00:00:00Z");
    assert_eq!(
        journal.p,
        [("membership:INBOX".to_string(), false)]
            .into_iter()
            .collect::<std::collections::BTreeMap<String, bool>>(),
        "the captured P is the journal row's touched_atom map, parsed"
    );
    assert!(!ctx.tombstoned, "no §6 tombstone was ever written");
    assert!(
        !ctx.parent_intent_id.is_empty(),
        "the parent's OPAQUE intent_id rides the context (the undo child's key needs it)"
    );
    assert!(
        ctx.effective_now.as_str() > "1970-01-08T00:00:00Z",
        "the real wall clock is far past the hand-set deadline, got {}",
        ctx.effective_now
    );
    // The latch was ADVANCED and PERSISTED by that very read.
    let latched: String = raw_conn(&path)
        .query_row("SELECT max_seen FROM time_high_water WHERE id = 1;", [], |r| {
            r.get(0)
        })
        .expect("the read persisted a high-water row");
    assert_eq!(latched, ctx.effective_now);

    // W-EXPIRE clock-rollback arm: a high-water ABOVE the wall clock governs — the
    // rollback can never re-open an expired offer.
    raw_conn(&path)
        .execute(
            "UPDATE time_high_water SET max_seen = '2999-01-01T00:00:00Z' WHERE id = 1;",
            [],
        )
        .expect("simulate a latch ahead of the wall clock");
    let rolled = log
        .undo_context("k-ctx-1")
        .expect("undo_context reads")
        .expect("the parent intent exists");
    assert_eq!(
        rolled.effective_now, "2999-01-01T00:00:00Z",
        "the persisted latch governs, not the wall clock"
    );

    // An unknown key is None, not an error — undo answers it as a no-op.
    assert!(log.undo_context("k-ctx-absent").expect("reads").is_none());
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_context_fails_loud_on_a_corrupt_deadline_or_latch() {
    // `undo_offer_until` and `time_high_water.max_seen` are bare TEXT
    // columns, and the §4.4 derivation compares them LEXICOGRAPHICALLY. A malformed value
    // is therefore not merely wrong, it is DIRECTIONAL: a deadline sorting above every
    // real instant reads as "the offer is still open" (fail OPEN), and a latch sorting
    // above every real instant poisons the SQL MAX. The engine's posture on malformed
    // persisted state is fail-closed/fail-loud (see the corrupt-`touched_atom` arm right
    // above), so the read REFUSES at the store boundary — and never silently repairs.
    //
    // WIDENED by: the latch is now validated AS STORED, before it enters any
    // comparison, so both sort directions are covered — the low-sorting half has its own
    // witness in `a_low_sorting_corrupt_latch_fails_loud_never_silently_repaired`. This
    // arm keeps the HIGH-sorting half, which is the one that used to govern the MAX.
    let path = unique_temp_db_path("corrupt-time-values");
    {
        let mut bus = sqlite_bus_with_counting_connector(&path);
        bus.execute(&archive_cmd("k-corrupt")).unwrap();
    }
    raw_conn(&path)
        .execute("UPDATE pre_state SET undo_offer_until = 'nope-XYZ';", [])
        .expect("hand-corrupt the offer deadline");
    let mut log = SqliteIntentLog::open(&path).expect("reopen");
    let err = log
        .undo_context("k-corrupt")
        .expect_err("a malformed deadline must FAIL LOUD — never fail open");
    assert!(
        err.0.contains("undo_offer_until"),
        "the error NAMES the field, got {}",
        err.0
    );
    assert!(
        !err.0.contains("XYZ") && !err.0.contains("k-corrupt"),
        "no persisted value or id rides the message, got {}",
        err.0
    );

    // The LATCH arm: restore a good deadline, poison the high-water instead.
    let conn = raw_conn(&path);
    conn.execute(
        "UPDATE pre_state SET undo_offer_until = '2999-01-01T00:00:00Z';",
        [],
    )
    .expect("restore a canonical deadline");
    conn.execute(
        "INSERT INTO time_high_water (id, max_seen) VALUES (1, 'zzz-not-a-time')
             ON CONFLICT(id) DO UPDATE SET max_seen = excluded.max_seen;",
        [],
    )
    .expect("hand-corrupt the sticky-clock latch");
    drop(conn);
    let err = log
        .undo_context("k-corrupt")
        .expect_err("a corrupt latch poisons MAX() — fail loud, never fail open");
    assert!(
        err.0.contains("high-water"),
        "the error NAMES the latch, got {}",
        err.0
    );
    assert!(
        !err.0.contains("zzz"),
        "no persisted value rides the message, got {}",
        err.0
    );
    let still: String = raw_conn(&path)
        .query_row("SELECT max_seen FROM time_high_water WHERE id = 1;", [], |r| {
            r.get(0)
        })
        .expect("the latch row is still there");
    assert_eq!(
        still, "zzz-not-a-time",
        "a corrupt latch is REFUSED, never silently repaired by the read"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_low_sorting_corrupt_latch_fails_loud_never_silently_repaired() {
    // THE RED — THE OTHER HALF OF THE CORRUPTION CLASS. validated
    // the offer deadline and the COMPUTED `effective_now`, which catches only a latch
    // that sorts HIGH (one that wins the MAX). A latch corrupted LOW — `'!'`, or any byte
    // below `'0'` — LOSES the MAX, so `effective_now` came back perfectly canonical, the
    // read returned `Ok`, and the corruption was SILENTLY OVERWRITTEN by the advance.
    // That is not benign: the latch IS the §4.4 sticky-expiry invariant, so a wall-clock
    // ROLLBACK landing on a store whose latch was destroyed re-opens an offer the
    // invariant exists to keep expired — and nothing ever surfaced that it happened.
    //
    // The rule this closes is stated wholesale on [`prestate::is_canonical_rfc3339_utc`]:
    // no stored timestamp participates in ANY comparison, MAX or decision without
    // clearing that shape authority AT ITS READ BOUNDARY first.
    let path = unique_temp_db_path("low-sorting-corrupt-latch");
    {
        let mut bus = sqlite_bus_with_counting_connector(&path);
        bus.execute(&archive_cmd("k-low")).unwrap();
    }
    raw_conn(&path)
        .execute(
            "INSERT INTO time_high_water (id, max_seen) VALUES (1, '!')
                 ON CONFLICT(id) DO UPDATE SET max_seen = excluded.max_seen;",
            [],
        )
        .expect("hand-corrupt the latch BELOW every real instant");

    let mut log = SqliteIntentLog::open(&path).expect("reopen");
    let err = log
        .undo_context("k-low")
        .expect_err("a corrupt latch must FAIL LOUD whichever way it sorts");

    assert!(
        err.0.contains("high-water"),
        "the error NAMES the latch, got {}",
        err.0
    );
    assert!(
        !err.0.contains('!') && !err.0.contains("k-low"),
        "no persisted value or id rides the message, got {}",
        err.0
    );
    let still: String = raw_conn(&path)
        .query_row("SELECT max_seen FROM time_high_water WHERE id = 1;", [], |r| {
            r.get(0)
        })
        .expect("the latch row is still there");
    assert_eq!(
        still, "!",
        "REFUSED, not repaired: the read must not overwrite the corruption it found"
    );

    // The in-memory twin carries the SAME boundary — one rule, both implementations of
    // the trait (a fake that softened it would hide the class from every fake-driven
    // witness in this suite).
    let mut mem = InMemoryIntentLog::new();
    mem.record(&archive_cmd("k-low-mem"), &fixture_basis(&archive_cmd("k-low-mem")))
        .expect("record");
    mem.time_high_water = "!".to_string();
    let mem_err = mem
        .undo_context("k-low-mem")
        .expect_err("the in-memory latch clears the same shape authority");
    assert!(
        mem_err.0.contains("high-water"),
        "the in-memory error NAMES the latch too, got {}",
        mem_err.0
    );
    assert_eq!(
        mem.time_high_water, "!",
        "…and it is refused, not silently advanced over"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_context_refuses_a_persisted_row_whose_values_are_inconsistent() {
    // THE READ BOUNDARY for the persisted journal row. added
    // `JournalRow::validate` at the WRITE boundary (PREPARE), and `FrozenBasis::from_json`
    // validates a basis on the way IN from storage so the two directions can never drift.
    // `undo_context` did NEITHER: it read the persisted `touched_atom` and handed it to
    // `drive_undo_child` as `P` WITHOUT re-validating the row against the frozen basis. A
    // stage-3 store with a syntactically-valid-but-inconsistent row (an earlier-branch
    // build, or valid-text on-disk corruption) was therefore TRUSTED — observed
    // {INBOX:false} but touched_atom forged to {INBOX:true} makes `P` diverge from the
    // real observation, so §4.1's `P == A` no-op kill (or a delta restore) fires on a
    // value the forward command never captured: a false no-op, or a restore of wrong
    // values, with nothing surfaced. This mirrors the read-boundary validate on the way in
    // from storage — CORRECTNESS / fail-loud on an inconsistent persisted row (id-free,
    // value-free), NOT a prevention control against a box owner.
    //
    // GREEN arm first: a CONSISTENT persisted row still returns Ok and carries its P.
    let green = unique_temp_db_path("undo-ctx-consistent");
    {
        let mut bus = sqlite_bus_with_counting_connector(&green);
        bus.execute(&archive_cmd("k-good")).unwrap();
    }
    let mut good = SqliteIntentLog::open(&green).expect("reopen");
    let ctx = good
        .undo_context("k-good")
        .expect("a consistent persisted row validates on read")
        .expect("the parent intent exists");
    assert_eq!(
        ctx.journal
            .as_ref()
            .expect("a journal-required forward intent owns a row")
            .p,
        [("membership:INBOX".to_string(), false)]
            .into_iter()
            .collect::<std::collections::BTreeMap<String, bool>>(),
        "the untampered row's captured P still rides the context"
    );
    std::fs::remove_file(&green).ok();

    // RED arm: forge `touched_atom` to a valid JSON map with the SAME key but a DIFFERENT
    // Boolean than `observed`. The row parses fine (the corrupt-`touched_atom` arm never
    // fires) and its key-set still equals the frozen atoms — the ONLY thing wrong is that
    // its VALUE diverges from the observation, exactly the forged-P a false no-op needs.
    let path = unique_temp_db_path("undo-ctx-inconsistent");
    {
        let mut bus = sqlite_bus_with_counting_connector(&path);
        bus.execute(&archive_cmd("k-forged")).unwrap();
    }
    raw_conn(&path)
        .execute(
            r#"UPDATE pre_state SET touched_atom = '{"membership:INBOX":true}';"#,
            [],
        )
        .expect("forge a value-inconsistent-but-syntactically-valid touched_atom");
    let mut log = SqliteIntentLog::open(&path).expect("reopen");
    let err = log
        .undo_context("k-forged")
        .expect_err("an inconsistent persisted row must FAIL LOUD, never a false no-op");
    assert!(
        err.0.contains("inconsistent") || err.0.contains("diverge"),
        "the error NAMES the inconsistency, got {}",
        err.0
    );
    assert!(
        !err.0.contains("k-forged") && !err.0.contains("INBOX"),
        "no persisted value or id rides the message, got {}",
        err.0
    );
    std::fs::remove_file(&path).ok();

    // The in-memory twin carries the SAME read boundary — one rule, both trait impls.
    let cmd = Command::new(
        "k-forged-mem".to_string(),
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let mut mem = InMemoryIntentLog::new();
    record_basis(&mut mem, &cmd).unwrap();
    let basis = fixture_basis(&cmd);
    let row = prestate::journal_row_from_observation(&fixture_observation(&basis), &basis);
    assert_eq!(
        mem.prepare("k-forged-mem", &row).unwrap(),
        prestate::PrepareOutcome::Prepared
    );
    // Hand-forge the mirror row's touched_atom to diverge in VALUE from observed.
    let observed = mem.pre_state.get("k-forged-mem").unwrap().row.observed.clone();
    let parsed: std::collections::BTreeMap<String, bool> =
        serde_json::from_str(&observed).unwrap();
    let forged: std::collections::BTreeMap<String, bool> =
        parsed.into_iter().map(|(k, v)| (k, !v)).collect();
    mem.pre_state.get_mut("k-forged-mem").unwrap().row.touched_atom =
        serde_json::to_string(&forged).unwrap();
    let mem_err = mem
        .undo_context("k-forged-mem")
        .expect_err("the in-memory read boundary refuses the inconsistent row too");
    assert!(
        mem_err.0.contains("inconsistent") || mem_err.0.contains("diverge"),
        "the in-memory error NAMES the inconsistency too, got {}",
        mem_err.0
    );
}

#[test]
fn a_failed_undo_cannot_erase_the_reverse_gap_evidence() {
    // An anomalous journal-required Applied row without its
    // pre_state row is reported by the scan — but a fast-path undo that dead-letters
    // moves it Applied → Undoing → Failed, and the wire-reached arm then dropped it
    // silently. The Failed state is genuinely AMBIGUOUS post-hoc (a pre-dispatch
    // dead-letter legitimately has no row; the store cannot reconstruct which lineage
    // produced 'failed'), so such rows are surfaced CONSERVATIVELY under their own
    // honestly-worded variant — never as JournalGapUnexplained, never silently.
    let cmd = Command::new(
        "k-undo-erase".to_string(),
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let basis = fixture_basis(&cmd);
    let path = unique_temp_db_path("failed-gap-evidence");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    log.record(&cmd, &basis).unwrap();
    // The anomalous lineage: Applied without a journal row (only reachable through
    // states the schema admits but our code paths cannot produce — the scan's raison
    // d'être), then terminalized Failed by a dead-lettered undo.
    log.set_status_forced("k-undo-erase", IntentStatus::Applied).unwrap();
    assert!(
        store_open::integrity_scan(&log.conn).unwrap().iter().any(|e| matches!(
            e,
            IntegrityEvidence::JournalGapUnexplained { key } if key == "k-undo-erase"
        )),
        "the gap is evidence while Applied"
    );
    log.set_status_forced("k-undo-erase", IntentStatus::Failed).unwrap();
    let report = store_open::integrity_scan(&log.conn).unwrap();
    assert!(
        report.iter().any(|e| matches!(
            e,
            IntegrityEvidence::JournalAbsentAtFailure { key } if key == "k-undo-erase"
        )),
        "terminalizing Failed must not ERASE the evidence — it degrades it honestly; got {report:?}"
    );
    assert!(
        !report.iter().any(|e| matches!(
            e,
            IntegrityEvidence::JournalGapUnexplained { key } if key == "k-undo-erase"
        )),
        "a Failed row is never claimed as a PROVEN gap — the lineage is ambiguous"
    );
}

// ---- Stage 3: the undo rework — §3.2 requalification + §4.1/§4.4/§4.5 ------------

#[test]
fn w_noop_undo_of_a_noop_forward_manufactures_nothing() {
    // W-NOOP — THE exit-criterion witness. Forward: Archive of a message NOT in
    // INBOX (the fixture connector observes `membership:INBOX = false`, and its frozen
    // forward target A is `false` too) applies as a provider no-op. §4.1: P == A ⇒ the
    // undo is a RECORDED no-op — decided from the journal row + frozen A alone, nothing
    // observed, nothing dispatched, nothing restored, parent `Undone` (no-op verified).
    // RED premise (pre-fix bytes): the blind inverse dispatches Unarchive and ADDS the
    // message to INBOX — a state change the forward action never made.
    let path = unique_temp_db_path("w-noop");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-noop"))
        .expect("the forward archive applies");
    assert_eq!(bus.connector().apply_count(), 1, "precondition: one forward dispatch");

    bus.undo("k-noop").expect("undo of a no-op forward is a recorded no-op");

    assert_eq!(
        bus.connector().restore_count(),
        0,
        "P == A: there is nothing to restore"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "NO inverse is dispatched — a blind Unarchive would ADD the message to INBOX"
    );
    assert_eq!(
        bus.log().get("k-noop").expect("g").expect("i").status,
        IntentStatus::Undone,
        "the parent flips Undone at the no-op VERIFICATION"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn two_buses_over_one_store_never_double_drive_one_undo_child() {
    // ═══ THE DOUBLE-DRIVE RACE — witnesses 1 and 2 in one scripted
    // interleave (the issue's discharge conditions 1 and 2). ═══
    //
    // trace: "driver A completes the restore and terminalizes the child → a newer
    // forward action admits (head now clear) and applies → driver B, holding a stale
    // Pending read taken before A terminalized, dispatches the stale restore of captured
    // P over the newer action's effect."
    //
    // THE ARM WITNESSED HERE, precisely: A's restore reaches the wire and comes back a
    // DETERMINISTIC refusal, so the child terminalizes `Failed` and the parent stays
    // truthfully `Applied`. (The arm where A's restore SUCCEEDS is already intercepted by
    // the stage-3 heal-order convergence short-circuit — `parent.status == Undone` — which
    // is a status read on a DIFFERENT row, not an ownership transition: it covers exactly
    // the one arm where the parent flipped, and leaves every terminalization that does NOT
    // flip the parent — deterministic refusal, §3.2 conflict, dead-letter — wide open.
    // Same defect, same absent machinery: the drive has NO atomic ownership transition.)
    //
    // The two buses are two SqliteIntentLog connections onto one file — "two buses
    // over one store"; the in-memory log cannot express it.
    let path = unique_temp_db_path("issue62-two-bus-double-drive");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus_a = CommandBus::new(SqliteIntentLog::open(&path).expect("open A"), wire.clone());
    let mut bus_b = CommandBus::new(SqliteIntentLog::open(&path).expect("open B"), wire.clone());

    // The forward action applies through A, capturing P = {INBOX: true}; A = {INBOX: false}.
    bus_a.execute(&archive_cmd("k-62")).expect("the forward archive applies");
    // The provider now holds A, so the undo requalifies to RESTORE (C == A).
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    // The undo child is admitted but DEFERRED behind a live same-resource predecessor, so
    // it sits `Pending` — the row both drivers will read.
    seed_pending_peer(&path, &bus_a, "k-62-peer");
    assert!(matches!(bus_a.undo("k-62"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-62"));
    terminalize_peer(&path, "k-62-peer");

    // ── B's sweep read, taken BEFORE A drives: the stale `Pending` read the race depends on. ──
    let stale_child = bus_b
        .log()
        .get(&child_key)
        .unwrap()
        .expect("B sees the Pending child");
    assert_eq!(
        stale_child.status,
        IntentStatus::Pending,
        "precondition: B's read is the Pending child, taken before A terminalized it"
    );

    // ── A drives the child to TERMINAL. The restore reaches the wire (touch 1) and the
    //    provider refuses deterministically ⇒ child `Failed`, parent still `Applied`. ──
    wire.wire().fail_restore(
        definitive_refusal("provider refused the restore"),
        1,
    );
    bus_a.recover().expect("A's sweep drives the child");
    assert_eq!(
        wire.wire().restore_call_count(),
        1,
        "A's drive touched the wire exactly once"
    );
    assert_eq!(
        bus_a.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Failed,
        "A terminalized the child"
    );
    assert_eq!(status_str(&path, "k-62"), "applied", "the parent never flipped");

    // ── A NEWER forward action admits and applies: the head is clear (both rows are
    //    terminal), and its effect is now the live provider state. ──
    bus_a
        .execute(&archive_cmd("k-62-newer"))
        .expect("the newer action applies over the cleared head");
    assert_eq!(wire.wire().apply_count(), 2, "two forward effects on the wire");

    // ── B DRIVES ITS STALE READ. This is the defect: no atomic ownership transition, so
    //    nothing in the drive asks whether this dispatch is still B's to make. ──
    let outcome = bus_b.drive_undo_child(&stale_child);

    // WITNESS 2 (the close): B refuses at the CLAIM boundary. Pre-fix this is 2 — the
    // stale restore of captured P goes out over the newer action's effect.
    assert_eq!(
        wire.wire().restore_call_count(),
        1,
        "the stale drive must not reach the wire a second time (#62 witness 1/2)"
    );
    assert!(
        wire.wire().restored().is_empty(),
        "…and no captured P is written over the newer action's effect, got {:?}",
        wire.wire().restored()
    );
    // …and it exits with the DISPOSITION, not with "in flight". B lost
    // the claim because the operation is already TERMINAL — the claim door's own first
    // compare half — and the child is `Failed` FOREVER: a terminal row never appears in
    // `unreconciled()` again, so no sweep will ever revise an `InProgress` answer about it.
    // What B is owed is what an identical replay of the child's key reads, exactly as the
    // AUTHORIZATION door has owed it since. (The witness's own property — a losing
    // racer never touches the wire and never appends a second CLAIM — is asserted above and
    // below and is unchanged.)
    assert_eq!(
        outcome,
        Err(ExecuteError::Failed),
        "a losing racer answers what a replay answers over a row that is closed forever; \
         got {outcome:?}"
    );
    assert_eq!(
        bus_b.undo("k-62"),
        outcome.map(|_| ()),
        "…and that answer IS the replay's: the drive and an identical replay never disagree"
    );
    // "no second CLAIM on a terminal attempt" — the issue's own words. The child operation
    // holds exactly the ONE claim A took.
    let child_owner = opaque_intent_id(&path, &child_key);
    assert_eq!(
        claim_count(&path, &child_owner),
        1,
        "the losing drive appended no second CLAIM"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_stale_undo_requalifies_restore_noop_and_conflict() {
    // W-STALE — the §3.2 three-way table driven THROUGH the bus, all three decisions.
    // Case RESTORE (C == A): the forward result still holds ⇒ the delta restore is
    // dispatched carrying the CAPTURED P (never the action direction).
    let path = unique_temp_db_path("w-stale-restore");
    {
        // Forward: A = "not in INBOX", provider truth at capture = IN inbox ⇒ P ≠ A.
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            UndoStageConnector::single(false, true),
        );
        bus.execute(&archive_cmd("k-restore")).expect("forward applies");
        // The forward landed: C == A.
        bus.connector().set_state(atoms(&[("membership:INBOX", false)]));

        bus.undo("k-restore").expect("C == A ⇒ restore");

        assert_eq!(bus.connector().restore_count(), 1, "the delta restore dispatched");
        assert_eq!(
            bus.connector().restored()[0].1,
            atoms(&[("membership:INBOX", true)]),
            "the restore writes the CAPTURED P, not the action's inverse direction"
        );
        assert_eq!(bus.connector().apply_count(), 1, "no inverse apply, ever");
        assert_eq!(status_str(&path, "k-restore"), "undone");
    }
    std::fs::remove_file(&path).ok();

    // Case ALREADY-RESTORED (C == P): another client already put it back ⇒ a recorded
    // no-op undo, no dispatch, parent Undone.
    let path = unique_temp_db_path("w-stale-noop");
    {
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            UndoStageConnector::single(false, true),
        );
        bus.execute(&archive_cmd("k-already")).expect("forward applies");
        // The provider truth never left P (C == P).
        bus.undo("k-already").expect("C == P ⇒ recorded no-op");
        assert_eq!(bus.connector().restore_count(), 0, "nothing to write back");
        assert_eq!(status_str(&path, "k-already"), "undone");
    }
    std::fs::remove_file(&path).ok();

    // Case CONFLICT (§3.1a pair, C == {both}): matches NEITHER P nor A ⇒ refuse, never
    // blind-write. The CHILD dead-letters; the parent stays truthfully `applied`.
    let path = unique_temp_db_path("w-stale-conflict");
    {
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            UndoStageConnector::pair(true, false),
        );
        bus.execute(&archive_cmd("k-conflict")).expect("forward applies");
        bus.connector().set_state(atoms(&[
            ("membership:mb-a", true),
            ("membership:mb-i", true),
        ]));

        let conflict = bus.undo("k-conflict");

        assert!(
            matches!(conflict, Err(ExecuteError::UndoConflict)),
            "the pair's reachable third state is REFUSED, got {conflict:?}"
        );
        assert_eq!(bus.connector().restore_count(), 0, "never a blind write");
        assert_eq!(
            status_str(&path, "k-conflict"),
            "applied",
            "the parent stays truthfully Applied — the undo did not happen"
        );
        let child = undo_child_key(&opaque_intent_id(&path, "k-conflict"));
        assert_eq!(
            bus.log().get(&child).unwrap().unwrap().status,
            IntentStatus::Failed,
            "the conflict terminalizes the CHILD; the remedy is a new forward action"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_stale_missing_target_refuses_never_recreates() {
    // §3.2 domain precondition: the requalification read finds the message GONE ⇒ the
    // connector's DETERMINISTIC refusal. The undo refuses — it never dispatches, and it
    // never recreates the message to have something to restore onto.
    let path = unique_temp_db_path("w-stale-missing");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-missing")).expect("forward applies");
    bus.connector()
        .fail_observe(ConnectorError::deterministic("missing target"));

    let refused = bus.undo("k-missing");

    assert!(
        matches!(&refused, Err(ExecuteError::Connector(e)) if e.kind == FailureKind::Deterministic),
        "a missing target is a deterministic refusal, got {refused:?}"
    );
    assert_eq!(bus.connector().restore_count(), 0, "never dispatched");
    assert_eq!(bus.connector().apply_count(), 1, "never recreated");
    assert_eq!(status_str(&path, "k-missing"), "applied");
    let child = undo_child_key(&opaque_intent_id(&path, "k-missing"));
    assert_eq!(
        bus.log().get(&child).unwrap().unwrap().status,
        IntentStatus::Failed,
        "the deterministic refusal dead-letters the child"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_undo_target_kind_and_duplicate_and_replay() {
    // W-UNDO-TARGET-KIND: a PENDING parent is not undoable yet (§4.5 ⇒ InProgress), and
    // an undo CHILD is never user-undoable (undo-of-undo is a no-op Ok).
    // W-UNDO-REPLAY: after a VERIFIED undo ⇒ Ok no-op; after a TERMINALLY FAILED undo ⇒
    // Err (no re-undo; the remedy is a new forward action). (W-UNDO-DUPLICATE — a second
    // undo while the child is still active — rides the deferral window in
    // `w_deferred_truth_parent_flips_only_at_verification`, the only shape where the
    // child is admitted but undriven.)
    let path = unique_temp_db_path("w-undo-kind");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    // A Pending parent (its dispatch never happened): not undoable YET.
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let cmd = archive_cmd("k-pending");
        let basis = bus.connector().resolve_basis(&cmd).unwrap();
        log.record(&cmd, &basis).expect("seed a Pending parent");
    }
    assert!(
        matches!(bus.undo("k-pending"), Err(ExecuteError::InProgress)),
        "a Pending parent classifies InProgress, never a silent undo"
    );

    // A verified undo, then its replay arms.
    let cmd = Command::new(
        "k-replay",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-replay".into(),
        },
    );
    bus.execute(&cmd).expect("forward applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    bus.undo("k-replay").expect("the undo verifies");
    assert_eq!(bus.connector().restore_count(), 1);
    // W-UNDO-REPLAY (verified): a second undo is an idempotent no-op Ok.
    bus.undo("k-replay").expect("replay of a verified undo is Ok");
    assert_eq!(bus.connector().restore_count(), 1, "no second restore");
    // W-UNDO-TARGET-KIND: the child's own key is never user-undoable.
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-replay"));
    bus.undo(&child_key).expect("undo-of-undo is a no-op Ok");
    assert_eq!(bus.connector().restore_count(), 1, "undo-of-undo dispatches NOTHING");
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "…and never re-applies the forward (only k-replay's own dispatch happened)"
    );

    // W-UNDO-REPLAY (failed): a terminally failed undo is not re-undoable.
    let dead = Command::new(
        "k-dead",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-dead".into(),
        },
    );
    bus.connector().set_state(atoms(&[("membership:INBOX", true)])); // capture P ≠ A
    bus.execute(&dead).expect("forward applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(definitive_refusal("restore rejected"), u32::MAX);
    assert!(matches!(bus.undo("k-dead"), Err(ExecuteError::Connector(_))));
    let retry = bus.undo("k-dead");
    assert!(
        matches!(retry, Err(ExecuteError::Failed)),
        "a terminally failed undo replays as Err, never a silent Ok; got {retry:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_deferred_truth_parent_flips_only_at_verification() {
    // W-DEFERRED-TRUTH (§4.5): SCHEDULING IS NOT COMPLETION. Defer an undo behind a live
    // same-resource predecessor: the child row is Pending and the parent's STORED status
    // stays `applied` — the old flip-at-scheduling (which called durable scheduling
    // "Undone") is DEAD. Only when the child actually drives and verifies does the
    // parent flip. (recover-driven deferred completion is
    // `w_deferred_stale_recovery_requalifies_at_its_head_moment`; the completion half
    // here drives the SAME chokepoint through undo's own re-entry.)
    let path = unique_temp_db_path("w-deferred-truth");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-def")).expect("forward applies");
    // A live same-resource predecessor: a second intent on the SAME message, left Pending.
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let peer = Command::new(
            "k-def-peer",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".into(),
            },
        );
        let basis = bus.connector().resolve_basis(&peer).unwrap();
        log.record(&peer, &basis).expect("seed the pending peer");
    }

    let deferred = bus.undo("k-def");

    assert!(
        matches!(deferred, Err(ExecuteError::InProgress)),
        "a deferred undo is IN FLIGHT, never a false Ok; got {deferred:?}"
    );
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-def"));
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "the child is admitted and tail-ordered, awaiting its head moment"
    );
    assert_eq!(
        status_str(&path, "k-def"),
        "applied",
        "THE FLIP IS NOT AT SCHEDULING — the parent is still truthfully Applied"
    );
    assert_eq!(bus.connector().restore_count(), 0, "nothing dispatched yet");
    // W-UNDO-DUPLICATE: a second undo while that child is active is InProgress, and the
    // KEY is the invariant — no second child is ever minted.
    assert!(matches!(bus.undo("k-def"), Err(ExecuteError::InProgress)));
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents WHERE kind = 'undo';", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "a duplicate undo answers from the SAME child, never mints a second"
    );

    // Clear the predecessor; the child now reaches its head and requalifies THERE. The
    // completion runs through recover — since that is the ONLY
    // re-drive path, because a replay never claimed this child (`recover()` owns in-flight
    // rows). Same chokepoint, so the requalify-at-head property is unchanged.
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'failed' WHERE idempotency_key = 'k-def-peer';",
            [],
        )
        .expect("terminalize the predecessor");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    bus.recover().expect("the child drives at its head moment");
    assert_eq!(bus.connector().restore_count(), 1, "the restore dispatched at the head");
    assert_eq!(
        status_str(&path, "k-def"),
        "undone",
        "the parent flips at VERIFICATION"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_undo_replay_never_re_drives_an_in_flight_child() {
    // UNDO DRIVE OWNERSHIP. `execute()` has always had this
    // discipline: only the caller whose `record()` returned `Claim::Inserted` drives the
    // row, so two concurrent `CommandBus` instances over ONE store cannot double-dispatch.
    // The undo replay path had no such rule — an existing non-terminal child was simply
    // re-driven, and the head predicate is NOT an ownership claim: two buses can both read
    // "no live predecessor" and both drive the same child, the second overwriting the
    // state the first restored.
    //
    // The cure mirrors execute: a replay that finds an existing non-terminal child
    // returns `InProgress` — recovery owns in-flight children, which is already
    // `recover()`'s contract — and only a FRESH admission (the caller that actually
    // inserted the row) drives synchronously.
    //
    // The arrangement removes every OTHER reason a replay could decline: the predecessor
    // that deferred the child is terminalized first, so the head predicate is satisfied
    // and OWNERSHIP is the only thing left that can hold the drive back.
    let path = unique_temp_db_path("undo-drive-ownership");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-own")).expect("forward applies");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let peer = Command::new(
            "k-own-peer",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".into(),
            },
        );
        let basis = bus.connector().resolve_basis(&peer).unwrap();
        log.record(&peer, &basis).expect("seed the pending peer");
    }
    // The admitting call: the child is durable, Pending and UNDRIVEN (deferred).
    assert!(matches!(bus.undo("k-own"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-own"));
    // Clear the predecessor and make the provider truth requalify (C == A ⇒ Restore), so
    // a re-driving replay WOULD reach the wire.
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'failed' WHERE idempotency_key = 'k-own-peer';",
            [],
        )
        .expect("terminalize the predecessor");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    let restores = bus.connector().restore_count();
    let observes = bus.connector().observe_count();

    let replay = bus.undo("k-own");

    assert!(
        matches!(replay, Err(ExecuteError::InProgress)),
        "a replay does not own the in-flight child — recovery does; got {replay:?}"
    );
    assert_eq!(
        bus.connector().restore_count(),
        restores,
        "the replay dispatched NOTHING"
    );
    assert_eq!(
        bus.connector().observe_count(),
        observes,
        "…and spent not even a provider read"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "the child is untouched, still awaiting its owner"
    );
    assert_eq!(status_str(&path, "k-own"), "applied");
    // THE ONE re-drive path — and the honest one: recovery drives the chokepoint.
    let report = bus.recover().expect("recovery owns the in-flight child");
    assert_eq!(report.recovered, 1);
    assert_eq!(
        bus.connector().restore_count(),
        restores + 1,
        "recovery — not the replay — dispatched the restore"
    );
    assert_eq!(status_str(&path, "k-own"), "undone");
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_presentation_derives_undoing_from_parent_plus_child() {
    // §4.5 LIFECYCLE vs PRESENTATION: "undoing" is DERIVED (parent `Applied` + a live
    // undo child), NEVER stored — the stored status stays the last VERIFIED truth, which
    // is what ordering, capacity and recovery read. The projection is user-facing only.
    let path = unique_temp_db_path("undo-presentation");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-pres")).expect("forward applies");
    // No undo child yet: the projection mirrors the lifecycle (nothing to present).
    assert_eq!(
        bus.undo_presentation("k-pres").expect("projection reads").map(|r| r.presentation),
        Some(UndoPresentation::None),
        "an Applied parent with no undo child presents nothing"
    );
    // An unknown key has no projection at all.
    assert_eq!(bus.undo_presentation("k-nobody").expect("projection reads"), None);

    // Defer an undo behind a live same-resource predecessor: the child is admitted and
    // Pending while the parent's STORED status is still `applied`.
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let peer = Command::new(
            "k-pres-peer",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".into(),
            },
        );
        let basis = bus.connector().resolve_basis(&peer).unwrap();
        log.record(&peer, &basis).expect("seed the pending peer");
    }
    assert!(matches!(bus.undo("k-pres"), Err(ExecuteError::InProgress)));
    assert_eq!(
        status_str(&path, "k-pres"),
        "applied",
        "the STORED lifecycle is untouched — scheduling is not completion"
    );
    assert_eq!(
        bus.undo_presentation("k-pres").expect("projection reads").map(|r| r.presentation),
        Some(UndoPresentation::Undoing),
        "PRESENTATION says 'undoing' — derived from parent Applied + a non-terminal child"
    );

    // Completion: recovery drives the in-flight child at its head and it verifies ⇒ the
    // projection is Undone. (recover owns in-flight children)
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'failed' WHERE idempotency_key = 'k-pres-peer';",
            [],
        )
        .expect("terminalize the predecessor");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    bus.recover().expect("the child drives at its head moment");
    assert_eq!(status_str(&path, "k-pres"), "undone");
    assert_eq!(
        bus.undo_presentation("k-pres").expect("projection reads").map(|r| r.presentation),
        Some(UndoPresentation::Undone)
    );
    std::fs::remove_file(&path).ok();

    // A CONFLICT-failed undo (§3.2 pair, C == {both}): the parent is truthfully still
    // `applied`, and the projection surfaces the failed undo rather than hiding it.
    let path = unique_temp_db_path("undo-presentation-conflict");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::pair(true, false),
    );
    bus.execute(&archive_cmd("k-pres-conflict"))
        .expect("forward applies");
    bus.connector().set_state(atoms(&[
        ("membership:mb-a", true),
        ("membership:mb-i", true),
    ]));
    assert!(matches!(
        bus.undo("k-pres-conflict"),
        Err(ExecuteError::UndoConflict)
    ));
    assert_eq!(status_str(&path, "k-pres-conflict"), "applied");
    assert_eq!(
        bus.undo_presentation("k-pres-conflict")
            .expect("projection reads")
            .map(|r| r.presentation),
        Some(UndoPresentation::AppliedUndoFailed),
        "a terminally failed undo is SURFACED (parent Applied + child Failed)"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_undo_authority_epoch_fence_parks_the_child() {
    // W-UNDO-AUTHORITY: the child binds `admitted_control_epoch` at ITS admission; a
    // control-epoch bump before the drive PARKS it — no observe, no dispatch, no
    // restore, the row stays Pending (stage-4 sever terminalizes it). Undo children own
    // no journal row, so PREPARE's in-transaction fence never runs for them: this fence
    // is the drive's own.
    //
    // The re-entry is recover's, and DELIBERATELY so: a replaying undo
    // now answers `InProgress` from the ownership rule alone, which would make this
    // witness vacuous — it would prove nothing about the fence. recover is the path that
    // actually enters the chokepoint, so the fence is what parks the child here. It also
    // pins the reorder's boundary from the other side: this child's parent is still
    // `Applied`, so the heal-only branches do NOT apply and the fence is reached.
    let path = unique_temp_db_path("w-undo-authority");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-auth")).expect("forward applies");
    // Admit the child but leave it undriven: a live same-resource predecessor defers it.
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let peer = Command::new(
            "k-auth-peer",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".into(),
            },
        );
        let basis = bus.connector().resolve_basis(&peer).unwrap();
        log.record(&peer, &basis).expect("seed the pending peer");
    }
    assert!(matches!(bus.undo("k-auth"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-auth"));

    // The sever lands between the child's admission and its drive.
    let conn = raw_conn(&path);
    conn.execute(
        "UPDATE intents SET status = 'failed' WHERE idempotency_key = 'k-auth-peer';",
        [],
    )
    .expect("clear the predecessor so ONLY the fence can park it");
    conn.execute("UPDATE control_epoch SET epoch = 2 WHERE id = 1;", [])
        .expect("hand-bump the control epoch (stands in for the stage-4 sever)");
    drop(conn);
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));

    let report = bus.recover().expect("the sweep reaches the chokepoint");

    assert_eq!(
        report.recovered, 0,
        "a fenced child PARKS (in flight), never counted as recovered"
    );
    assert!(report.failed.is_empty(), "…and parking is not a failure");
    assert_eq!(bus.connector().restore_count(), 0, "a fenced child dispatches NOTHING");
    assert_eq!(
        bus.connector().observe_count(),
        1,
        "…and spends no provider read: the ONE observe is the FORWARD capture"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "the child parks Pending for the stage-4 sever, never terminalizes itself"
    );
    assert_eq!(status_str(&path, "k-auth"), "applied", "the parent is untouched");
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_undo_namespace_key_rides_the_parent_intent_id() {
    // §4.5 +: the undo child's idempotency key is
    // `undo_child_key(parent's OPAQUE intent_id)` = `\u{1}undo\u{1}<intent_id>` — engine-
    // reserved (`\u{1}` namespace), uncollidable, CONTENT-FREE (no user key text), and in
    // a domain PROVABLY DISJOINT from the legacy `compensation_key` shape (the reserved
    // char, not `:`, is the delimiter). The stage-1 reserved-namespace rejection for
    // user-submitted keys is untouched (see `record_rejects_a_normal_command_…`).
    let path = unique_temp_db_path("w-undo-namespace");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-ns")).expect("forward applies");
    bus.undo("k-ns").expect("undo runs");

    let parent_intent_id = opaque_intent_id(&path, "k-ns");
    let expected = format!("\u{1}undo\u{1}{parent_intent_id}");
    let (child_key, kind, compensates, parent_link): (String, String, String, String) =
        raw_conn(&path)
            .query_row(
                "SELECT c.idempotency_key, c.kind, c.compensates, c.parent_intent_id
                       FROM intents c WHERE c.kind = 'undo';",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("exactly one undo child exists");
    assert_eq!(child_key, expected, "the key rides the parent's OPAQUE intent_id");
    assert_eq!(kind, "undo", "admitted through the SAME classifier as every operation");
    assert_eq!(
        compensates, "k-ns",
        "the durable heal LINK is the parent's user key"
    );
    assert_eq!(parent_link, parent_intent_id);
    assert!(
        !child_key.contains("k-ns"),
        "content-free: no user key text rides the reserved namespace"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_expire_expired_offer_refuses_with_sticky_reason() {
    // W-EXPIRE — the §4.4 offer deadline, all three arms. RETAINED ROW: past the
    // deadline the OFFER lapsed, the bytes did not (§6 destruction is dormant), so the
    // reason is `Expired { tombstoned: false }` and the row is still there. CLOCK
    // ROLLBACK: a persisted high-water ABOVE the wall clock governs — an expired offer
    // can never be re-opened by moving the clock back. TOMBSTONE: deletion provenance
    // rides the same answer.
    let path = unique_temp_db_path("w-expire");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-exp")).expect("forward applies");
    raw_conn(&path)
        .execute(
            "UPDATE pre_state SET undo_offer_until = '1970-01-08T00:00:00Z';",
            [],
        )
        .expect("hand-expire the offer");

    let expired = bus.undo("k-exp");

    assert_eq!(
        expired,
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::Expired { tombstoned: false }
        )),
        "the reason renders from the DEADLINE, never from a tombstone"
    );
    assert_eq!(bus.connector().apply_count(), 1, "no blind inverse fallback");
    assert_eq!(
        raw_count(&path, "pre_state"),
        1,
        "the OFFER lapsed — the row did not"
    );
    assert_eq!(status_str(&path, "k-exp"), "applied");
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents WHERE kind = 'undo';", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "an unavailable undo admits NO child"
    );

    // Clock-rollback arm: the offer deadline is far in the FUTURE, but the persisted
    // high-water is further still — the latch governs, so it stays expired.
    let conn = raw_conn(&path);
    conn.execute(
        "UPDATE pre_state SET undo_offer_until = '2100-01-01T00:00:00Z';",
        [],
    )
    .expect("re-open the offer window on the wall clock");
    conn.execute(
        "INSERT INTO time_high_water (id, max_seen) VALUES (1, '2999-01-01T00:00:00Z')
             ON CONFLICT(id) DO UPDATE SET max_seen = excluded.max_seen;",
        [],
    )
    .expect("latch a high-water past the deadline");
    drop(conn);
    assert_eq!(
        bus.undo("k-exp"),
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::Expired { tombstoned: false }
        )),
        "STICKY: a wall-clock rollback never re-opens an expired offer"
    );

    // Tombstone arm: the row is gone and §6 left provenance — same answer, with it.
    let conn = raw_conn(&path);
    seed_tombstone(&conn, "k-exp", "j-exp");
    conn.execute("DELETE FROM pre_state;", []).expect("§6 destruction ran");
    drop(conn);
    assert_eq!(
        bus.undo("k-exp"),
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::Expired { tombstoned: true }
        )),
        "deletion provenance rides the SAME reason — never a bare gap"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_refuses_on_a_corrupt_offer_deadline() {
    // END TO END: a malformed persisted deadline that sorts ABOVE
    // every real instant used to read as "the offer is still open" — undo admitted a
    // child and dispatched a RESTORE outside any window. Fail-closed/fail-loud now:
    // the store boundary refuses the row, undo answers `Err(Log(..))`, and NOTHING is
    // dispatched or admitted.
    let path = unique_temp_db_path("undo-corrupt-deadline");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-cd")).expect("forward applies");
    raw_conn(&path)
        .execute("UPDATE pre_state SET undo_offer_until = 'nope-XYZ';", [])
        .expect("hand-corrupt the offer deadline");

    let refused = bus.undo("k-cd");

    assert!(
        matches!(refused, Err(ExecuteError::Log(_))),
        "a corrupt deadline is an INTEGRITY refusal, not an offer, got {refused:?}"
    );
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "nothing was dispatched on a corrupt deadline"
    );
    assert_eq!(status_str(&path, "k-cd"), "applied", "the parent is untouched");
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents WHERE kind = 'undo';", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "a refused undo admits NO child"
    );
    std::fs::remove_file(&path).ok();
}

/// A connector that EXPIRES the offer deadline the instant it resolves an UNDO child's
/// basis — the DETERMINISTIC stand-in for wall-clock crossing `undo_offer_until` DURING
/// admission. Forward resolves are untouched, so undo's §4.4
/// eligibility snapshot — taken just BEFORE the child's resolve — still saw an OPEN offer;
/// the offer lapses only inside the admission gap the finding is about. Otherwise a plain
/// single-atom undo connector with `P != A` (so undo takes the RESOLVING path, not the
/// no-op kill). This models the PASSAGE OF TIME in the gap, not an impossible store.
struct ExpireOnUndoResolveConnector {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
}
impl ExpireOnUndoResolveConnector {
    fn new(path: &std::path::Path) -> Self {
        Self {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
        }
    }
    fn restore_count(&self) -> usize {
        self.inner.restore_count()
    }
}
impl Connector for ExpireOnUndoResolveConnector {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        // Only the undo child (its `compensates` link is set) trips the expiry — the
        // forward admission that seeded the journal resolves against an OPEN offer.
        if command.compensates.is_some() {
            rusqlite::Connection::open(&self.path)
                .expect("open a peer connection to expire the offer")
                .execute(
                    "UPDATE pre_state SET undo_offer_until = '1970-01-08T00:00:00Z';",
                    [],
                )
                .expect("the deadline crosses while the undo child is being admitted");
        }
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.inner.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.inner.restore(command, basis, p)
    }
}

#[test]
fn undo_child_admission_rechecks_the_offer_deadline() {
    // A TOCTOU on the §4.4 offer deadline. undo takes the
    // eligibility snapshot (offer OPEN) and only THEN does `admit_undo_child` resolve a
    // fresh basis before the durable `record()` insert. Wall-clock advances across that
    // resolve; if it crosses `undo_offer_until` before the child is durably inserted, the
    // child is admitted OUTSIDE the window — and a durable child bypasses §4.4 on every
    // later sweep (the precedence rule), so recover would drive it and verify the
    // parent `Undone` past the deadline. The admission boundary must RE-CHECK.
    let path = unique_temp_db_path("undo-admit-deadline");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        ExpireOnUndoResolveConnector::new(&path),
    );
    bus.execute(&archive_cmd("k-tt")).expect("forward applies");
    // Precondition: at eligibility time the offer is OPEN (the fresh capture's window is in
    // the future) and `P != A`, so undo takes the RESOLVING admission path — where the
    // connector then expires the offer mid-resolve.

    let admitted = bus.undo("k-tt");

    assert_eq!(
        admitted,
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::Expired { tombstoned: false }
        )),
        "the deadline crossed DURING admission — the child must be REFUSED, never admitted"
    );
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents WHERE kind = 'undo';", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "a post-deadline admission inserts NO durable child for recover() to drive later"
    );
    assert_eq!(
        status_str(&path, "k-tt"),
        "applied",
        "the parent stays truthfully Applied — the undo did NOT happen"
    );
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "nothing was restored outside the offer window"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_admitted_undo_child_outlives_offer_expiry_replay_says_in_progress() {
    // TWO ANSWERS, ONE TRUTH. The §4.4 eligibility derivation ran
    // BEFORE the existing-child lookup, so an undo ADMITTED inside the offer window and
    // still in flight started reporting `UndoUnavailable(Expired)` the moment the offer
    // lapsed — while recover went right on driving that SAME durable child to a real
    // restore. A DURABLE child status outranks fresh-admission eligibility: the offer
    // gates ADMISSION only, and nothing is admitted here.
    let path = unique_temp_db_path("child-outlives-offer");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-oe")).expect("forward applies");
    seed_pending_peer(&path, &bus, "k-oe-peer");
    assert!(
        matches!(bus.undo("k-oe"), Err(ExecuteError::InProgress)),
        "precondition: the undo is ADMITTED in-window and deferred behind its predecessor"
    );
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-oe"));
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the child is durable and awaiting ITS head moment"
    );
    // …and the offer lapses while the child waits.
    raw_conn(&path)
        .execute(
            "UPDATE pre_state SET undo_offer_until = '1970-01-08T00:00:00Z';",
            [],
        )
        .expect("hand-expire the offer under the in-flight child");

    let replay = bus.undo("k-oe");

    assert_eq!(
        replay,
        Err(ExecuteError::InProgress),
        "an ADMITTED child is IN FLIGHT — never `UndoUnavailable`, which recovery contradicts"
    );
    // …and RECOVERY honors that admitted child: it completes and the parent lands undone.
    terminalize_peer(&path, "k-oe-peer");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    let report = bus.recover().expect("the sweep drives the admitted child");
    assert_eq!(report.recovered, 1);
    assert_eq!(
        bus.connector().restore_count(),
        1,
        "the undo the replay called 'unavailable' really did happen"
    );
    assert_eq!(status_str(&path, "k-oe"), "undone");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_failed_undo_child_replays_failed_even_after_offer_expiry() {
    // The same precedence, TERMINAL arm: a child that DIED is the durable answer to the
    // replay (`Err(Failed)` — no re-undo; the remedy is a new forward action), and a
    // lapsed offer cannot rewrite that into `UndoUnavailable(Expired)`.
    let path = unique_temp_db_path("failed-child-after-expiry");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-fe")).expect("forward applies");
    seed_pending_peer(&path, &bus, "k-fe-peer");
    assert!(matches!(bus.undo("k-fe"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-fe"));
    let conn = raw_conn(&path);
    conn.execute(
        "UPDATE intents SET status = 'failed' WHERE idempotency_key = ?1;",
        rusqlite::params![child_key],
    )
    .expect("hand-dead-letter the child (stands in for a budget-exhausted restore)");
    conn.execute(
        "UPDATE pre_state SET undo_offer_until = '1970-01-08T00:00:00Z';",
        [],
    )
    .expect("hand-expire the offer");
    drop(conn);

    assert_eq!(
        bus.undo("k-fe"),
        Err(ExecuteError::Failed),
        "the child's DURABLE terminal is the answer; an expired offer does not rewrite it"
    );
    assert_eq!(
        status_str(&path, "k-fe"),
        "applied",
        "…and the parent stays truthfully Applied: the undo did NOT happen"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_gap_and_capture_off_answers() {
    // The remaining two §4.4 reasons, end to end. JOURNAL GAP: `journal_required=1`,
    // Applied, no row, no tombstone — the fail-loud INTEGRITY answer, never a benign
    // configuration message. CAPTURE OFF: `journal_required=0` names its own reason —
    // the blind-inverse fallback is DEAD, so an operation captured with no pre-state is
    // simply not undoable.
    let path = unique_temp_db_path("w-gap");
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-gap")).expect("forward applies");
    raw_conn(&path)
        .execute("DELETE FROM pre_state;", [])
        .expect("hand-delete the journal row with NO tombstone");

    assert_eq!(
        bus.undo("k-gap"),
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::JournalGapUnexplained
        )),
        "an unexplained gap is fail-loud"
    );
    assert_eq!(bus.connector().apply_count(), 1, "never a blind inverse");
    std::fs::remove_file(&path).ok();

    let path = unique_temp_db_path("w-capture-off");
    SqliteIntentLog::open(&path).expect("bootstrap");
    append_config_act(&path, r#"{"capture":"off"}"#);
    let mut bus = sqlite_bus_with_counting_connector(&path);
    bus.execute(&archive_cmd("k-off")).expect("forward applies");
    assert_eq!(
        bus.undo("k-off"),
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::CaptureDisabled
        )),
        "capture was off for THIS operation — say so; never guess an inverse"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "THE DEAD FALLBACK: no pre-state means no undo, not a blind inverse"
    );
    assert_eq!(status_str(&path, "k-off"), "applied");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_legacy_null_basis_undo_is_refused_and_never_reaches_the_wire() {
    // The END-TO-END shape of that case, reworked by stage 3: undoing a legacy pre-stage-2
    // `applied` intent while a NEWER non-terminal intent (with a frozen basis) is live on
    // the SAME message. Nothing may reach the wire ahead of that peer — and now nothing
    // reaches it AT ALL: a row with no frozen basis carries no forward target vector `A`,
    // so §4.4 answers `PredatesSubstrate` (a NAMED refusal) instead of guessing an
    // inverse. The ordering question is moot because the dispatch never happens.
    let path = unique_temp_db_path("legacy-undo-overtake");
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
    let mut bus = sqlite_bus_with_counting_connector(&path);

    let refused = bus.undo("k-legacy");

    assert_eq!(
        refused,
        Err(ExecuteError::UndoUnavailable(
            prestate::UndoUnavailableReason::PredatesSubstrate
        )),
        "a pre-substrate row is answered honestly, never guessed at"
    );
    assert_eq!(
        bus.connector().apply_count(),
        0,
        "the legacy undo must NOT have dispatched anything past the live peer"
    );
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM intents WHERE kind = 'undo';", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "an unavailable undo admits NO child"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_deferred_stale_recovery_requalifies_at_its_head_moment() {
    // W-DEFERRED-STALE: a DEFERRED undo requalifies when IT reaches the head — against
    // provider state as it is THEN, never as it was at undo admission. The forward
    // archive captures P = {INBOX: true}; the undo defers behind a live same-resource
    // predecessor; while it waits ANOTHER CLIENT puts the message back (C moves to P).
    // recover must drive the child through the ONE chokepoint and decide
    // AlreadyRestored: nothing restored, nothing applied, the parent Undone.
    let path = unique_temp_db_path("w-deferred-stale");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-ds")).expect("forward applies");
    seed_pending_peer(&path, &bus, "k-ds-peer");
    // At undo-admission time the forward result still held (C == A) — a Restore.
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    assert!(
        matches!(bus.undo("k-ds"), Err(ExecuteError::InProgress)),
        "the undo defers behind its live predecessor"
    );
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-ds"));
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the child awaits ITS head moment"
    );
    // …and the world MOVED while it waited: another client restored the pre-state.
    terminalize_peer(&path, "k-ds-peer");
    bus.connector().set_state(atoms(&[("membership:INBOX", true)]));

    let report = bus.recover().expect("the sweep drives the deferred child");

    assert_eq!(report.recovered, 1, "the child terminalized through the sweep");
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "requalified at ITS head: C == P ⇒ there is nothing left to write back"
    );
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "NO blind inverse — only the forward action ever dispatched"
    );
    assert_eq!(
        status_str(&path, "k-ds"),
        "undone",
        "the parent flips at the no-op VERIFICATION, not at scheduling"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Applied
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recovery_finishes_a_crashed_undo_child_convergently() {
    // HEAL ORDER convergence: the drive flips the parent `Undone` BEFORE terminalizing
    // the child, so a crash in between leaves parent Undone + child Pending. The
    // re-drive must converge on the child's own terminal with NO second dispatch — the
    // parent-already-Undone short-circuit spends not even a provider read to learn it.
    let path = unique_temp_db_path("undo-child-converge");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-crash")).expect("forward applies");
    seed_pending_peer(&path, &bus, "k-crash-peer");
    assert!(matches!(bus.undo("k-crash"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-crash"));
    terminalize_peer(&path, "k-crash-peer");
    // THE CRASH WINDOW: the parent flip is durable, the child's terminal is not.
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'undone' WHERE idempotency_key = 'k-crash';",
            [],
        )
        .expect("hand-arrange the heal-order crash window");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));

    let report = bus.recover().expect("the sweep re-drives the crashed child");

    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Applied,
        "the re-drive converges on the child's own terminal"
    );
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "…and dispatches NOTHING a second time"
    );
    assert_eq!(bus.connector().apply_count(), 1, "never a blind inverse");
    assert_eq!(status_str(&path, "k-crash"), "undone");
    assert_eq!(report.recovered, 1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn recovery_maps_legacy_undoing_rows_to_applied_with_a_note() {
    // SCOPE FENCE (pre-stage-3 dev stores only): the OLD fast path stored `undoing` on
    // the PARENT and then dispatched a blind inverse, so whether that inverse landed is
    // unknowable BY CONSTRUCTION — the exact blindness this stage kills. recover maps
    // such a row back to the last VERIFIED truth (`applied`) and REPORTS it; it never
    // re-dispatches an inverse to "finish" it. The undo offer, if still open, is then
    // available through the new path.
    let path = unique_temp_db_path("legacy-undoing-row");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-legacy")).expect("forward applies");
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'undoing' WHERE idempotency_key = 'k-legacy';",
            [],
        )
        .expect("hand-seed the legacy mid-flight row");

    let report = bus.recover().expect("the sweep maps it honestly");

    assert_eq!(
        status_str(&path, "k-legacy"),
        "applied",
        "mapped back to the last VERIFIED truth — never guessed forward to `undone`"
    );
    assert_eq!(
        report.legacy_undoing,
        vec!["k-legacy".to_string()],
        "…and the report SAYS so, rather than healing it silently"
    );
    assert_eq!(report.recovered, 0, "a mapped legacy row is not a recovery");
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "no inverse is dispatched to 'finish' an unknowable mid-flight"
    );
    assert_eq!(bus.connector().restore_count(), 0);
    std::fs::remove_file(&path).ok();
}

/// Hand-seed A PRE-STAGE-3 DEFERRED-UNDO PAIR on `msg-1` — the exact stage-2 shape the
/// migration door delivers: the parent flipped `undone` AT SCHEDULING (the lie stage 3
/// killed) over an intact stage-2 journal capture (`P` = in INBOX, offer open), plus a
/// still-`pending` compensation under the OLD key shape
/// (`compensation_key(parent USER key)`) — and BOTH rows carry stage-2 basis bytes, with
/// NO `atom_targets`. Returns the legacy child's key. The store is NOT recovered — every
/// witness that uses this decides what a caller meets on a freshly-opened legacy store.
fn seed_legacy_deferred_pair(path: &std::path::Path, parent_key: &str) -> String {
    // THE STAGE-2 BYTES, VERBATIM. `origin/main`'s `FrozenBasis` had no
    // `atom_targets` field at all, so NO row a stage-2 build wrote can carry one — and both
    // rows of a legacy deferred pair were written by that build. Giving the PARENT a target
    // vector modelled a store that has never existed and let this fixture "prove" an undo the
    // real upgraded store cannot serve. The JSON is written LITERALLY, without the key,
    // because that is exactly what a stage-2 row deserializes from (serde default ⇒ empty) —
    // a `FrozenBasis { atom_targets: BTreeMap::new(), .. }` round-trip would emit
    // `"atom_targets":{}`, which is stage-3 bytes that merely happen to be empty.
    let native_key = prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &["msg-1"]);
    let stage2_basis_json = format!(
        r#"{{"native_resource_key":{},"touched_atoms":{{"membership:INBOX":"INBOX"}},"freshness":"immutable_constants"}}"#,
        serde_json::to_string(&native_key).expect("a string always serializes")
    );
    assert!(
        prestate::FrozenBasis::from_json(&stage2_basis_json)
            .expect("stage-2 bytes stay READABLE — storage tolerates legacy rows")
            .atom_targets
            .is_empty(),
        "the seed must deserialize to an EMPTY target vector — that IS the legacy shape"
    );
    let parent_basis_json = stage2_basis_json.clone();
    let legacy_child_basis_json = stage2_basis_json;
    let legacy_child_key = compensation_key(parent_key); // THE OLD SHAPE: the parent's USER key
    let conn = raw_conn(path);
    seed_intent_on_message(
        &conn,
        parent_key,
        "msg-1",
        "undone", // the old flip-at-SCHEDULING
        Some(&parent_basis_json),
    );
    conn.execute(
        "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom,
                                    resolved_operands, fetched_at, source, captured_epoch,
                                    mode_generation, undo_offer_until)
             SELECT ?3, i.intent_id, ?1, ?1, ?2, '2026-01-01T00:00:00Z', 'live_read',
                    1, 1, '2100-01-01T00:00:00Z'
               FROM intents i WHERE i.idempotency_key = ?4;",
        rusqlite::params![
            r#"{"membership:INBOX":true}"#,
            r#"{"membership:INBOX":"INBOX"}"#,
            format!("j-{parent_key}"),
            parent_key
        ],
    )
    .expect("seed the stage-2 journal capture (P = in INBOX, offer still open)");
    conn.execute(
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                  status, compensates, seq, intent_id, kind,
                                  parent_intent_id, journal_required,
                                  capture_mode_generation, admitted_control_epoch,
                                  frozen_basis)
             SELECT ?1, 'acct-1', 'mail', 'unarchive', 'msg-1', 'pending', ?3,
                    (SELECT COALESCE(MAX(seq), 0) + 1 FROM intents),
                    lower(hex(randomblob(16))), 'undo', p.intent_id, 1, 1, 1, ?2
               FROM intents p WHERE p.idempotency_key = ?3;",
        rusqlite::params![legacy_child_key, legacy_child_basis_json, parent_key],
    )
    .expect("seed the legacy DEFERRED undo child under the OLD key shape");
    legacy_child_key
}

#[test]
fn a_legacy_deferred_undo_maps_honestly_and_degrades_predates_substrate() {
    // THE SILENT DISCARD. A pre-stage-3 store can hold a DEFERRED
    // undo, and its shape is entirely different from the `undoing`-parent row the other
    // legacy arm maps: the old defer path flipped the parent `undone` AT SCHEDULING and
    // recorded the child under the OLD key shape (`compensation_key(parent USER key)`)
    // with a stage-2 basis (no target vector). recover then hit `drive_undo_child`'s
    // parent-already-`Undone` convergence short-circuit, marked that child `Applied`,
    // and NOTHING was ever restored — the provider silently stayed in FORWARD state
    // while the log claimed `undone`. That is precisely the lie this stage exists to
    // kill, arriving through the migration door instead of the live one.
    //
    // The mapping mirrors `legacy_undoing`: back to the last VERIFIED truth
    // (`applied` — whether the old inverse ever dispatched is unresolvable BY
    // CONSTRUCTION), the child `Failed`, and NAMED in the report.
    //
    // AND THERE THE HONESTY STOPS (this tail used to claim the parent
    // "regains undo", on a fixture that gave the PARENT a stage-3 target vector no
    // stage-2 build could ever have written). A REAL upgraded legacy pair has an EMPTY
    // `A` on BOTH rows, and §3.2's requalification is undecidable without it — so the
    // mapped parent degrades to the NAMED `UndoUnavailable(PredatesSubstrate)`, and the
    // remedy is a NEW FORWARD ACTION. No backfill: pre-release, zero durable population,
    // No migration machine. The refusal is the whole point — a guess here
    // would be the same lie through a politer door.
    //
    // NOTE the src is UNTOUCHED by this rework: the degradation already falls out of
    // `atom_targets`-empty. What was wrong was the fixture, and therefore the claim.
    let path = unique_temp_db_path("legacy-deferred-undo");
    SqliteIntentLog::open(&path).expect("bootstrap");
    let legacy_child_key = seed_legacy_deferred_pair(&path, "k-ld");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );

    let report = bus.recover().expect("the sweep maps it honestly");

    assert_eq!(
        status_str(&path, "k-ld"),
        "applied",
        "back to the last VERIFIED truth — the flip-at-scheduling was the lie stage 3 killed"
    );
    assert_eq!(
        status_str(&path, &legacy_child_key),
        "failed",
        "the legacy child is TERMINALIZED — never silently `applied` with no restore"
    );
    assert_eq!(
        report.legacy_compensations,
        vec![legacy_child_key.clone()],
        "…and the report NAMES it, rather than healing it silently"
    );
    assert_eq!(report.recovered, 0, "a mapped legacy row is not a recovery");
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "the MAPPING dispatches nothing — it only stops the log from lying"
    );

    // …and the mapped parent DEGRADES, typed and named — never a blind inverse, never a
    // guessed `A`.
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    let unavailable = bus.undo("k-ld");
    assert!(
        matches!(
            unavailable,
            Err(ExecuteError::UndoUnavailable(
                prestate::UndoUnavailableReason::PredatesSubstrate
            ))
        ),
        "a stage-2 row has NO forward target vector: the honest answer is the named \
         unavailability, got: {unavailable:?}"
    );
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "nothing is written back off a basis that cannot answer the §3.2 table"
    );
    assert_eq!(
        status_str(&path, "k-ld"),
        "applied",
        "the parent stays truthfully applied — the remedy is a NEW forward action"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_child_failures_deadletter_on_their_own_budget() {
    // The old compensation dead-letter EXEMPTION is DEAD. It existed only because the
    // old path pre-flipped the parent `Undone` at SCHEDULING, so terminalizing the
    // compensation would have made the log lie (parent Undone, provider still applied).
    // Stage 3 never pre-flips: a transiently failing restore charges the CHILD's own
    // budget through the ONE reconcile boundary and dead-letters at RETRY_CAP, while
    // the parent stays truthfully `applied`.
    let path = unique_temp_db_path("undo-child-budget");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-budget")).expect("forward applies");
    seed_pending_peer(&path, &bus, "k-budget-peer");
    assert!(matches!(bus.undo("k-budget"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-budget"));
    terminalize_peer(&path, "k-budget-peer");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)])); // C == A ⇒ Restore
    bus.connector()
        .fail_restore(retryable_transient("restore transient"), u32::MAX);

    let first = bus.recover().expect("the sweep drives the child");

    assert_eq!(
        first.failed.len(),
        1,
        "the CHILD's own failure is reported by the sweep"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().attempts,
        1,
        "attempt 1 of {RETRY_CAP} charged to the CHILD"
    );
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "still retryable below the cap"
    );
    for _ in 1..RETRY_CAP {
        bus.recover().expect("the retry sweeps");
    }
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Failed,
        "an undo child dead-letters on its OWN budget — no exemption"
    );
    assert_eq!(
        status_str(&path, "k-budget"),
        "applied",
        "…and the parent stays truthfully Applied: the undo did NOT happen"
    );
    assert_eq!(bus.connector().apply_count(), 1, "never a blind inverse");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_noop_undo_never_needs_the_resolver() {
    // §4.1 ORDERING. `P == A` is decided FROM THE ROW ALONE: both
    // halves are LOCAL (P = the journal capture, A = the parent's admission-frozen target
    // vector). The pre-fix flow ran eligibility → `admit_undo_child` (which RESOLVES a
    // fresh basis, and a resolver CAN refuse: a JMAP role mailbox that no longer resolves,
    // an absent state cursor) → drive, where the no-op kill lives. So a resolver refusal
    // blocked an undo the parent row alone PROVES is a no-op — `AdmissionRefused` for an
    // operation that would have dispatched NOTHING.
    let path = unique_temp_db_path("noop-undo-no-resolver");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        // A = "not in INBOX" AND the provider truth at capture is the same ⇒ P == A: the
        // forward archive of a message that was never in INBOX.
        UndoStageConnector::single(false, false),
    );
    bus.execute(&archive_cmd("k-nr")).expect("the forward archive applies");
    let observes_after_forward = bus.connector().observe_count();
    // …and THEN the resolver breaks (the field shape: a role mailbox stops resolving).
    bus.connector()
        .fail_resolve(ResolveBasisError("jmap: role mailbox unresolvable".into()));

    bus.undo("k-nr")
        .expect("a recorded no-op undo needs NO fresh resolution — it never reaches the wire");

    assert_eq!(
        status_str(&path, "k-nr"),
        "undone",
        "the parent flips at the no-op VERIFICATION, exactly as with a healthy resolver"
    );
    assert_eq!(
        status_str(&path, &undo_child_key(&opaque_intent_id(&path, "k-nr"))),
        "applied",
        "the no-op child is RECORDED and terminal — the undo is durably answered"
    );
    assert_eq!(bus.connector().restore_count(), 0, "P == A: nothing to restore");
    assert_eq!(bus.connector().apply_count(), 1, "never a blind inverse");
    assert_eq!(
        bus.connector().observe_count(),
        observes_after_forward,
        "and not even a provider READ was spent: the decision is local by construction"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recovery_completes_a_deferred_noop_undo_across_an_epoch_bump() {
    // A SEVER MUST NEVER STRAND WHAT NEEDS NO WIRE. The §4.1 no-op
    // kill (`P == A`) is decided from the parent's journal row plus its admission-frozen
    // target vector alone: no provider read, no dispatch. With the epoch fence ahead of
    // it, a no-op child that DEFERRED behind a live predecessor (so it never met undo's
    // pre-admission kill) and then met a control-epoch bump parked `Pending` FOREVER —
    // and, being non-terminal, barriered every later operation on that resource. The
    // synchronous path already completes exactly this undo fence-free.
    //
    // The two halves below are IDENTICAL but for `P == A`: same defer, same release, same
    // hand-bumped epoch, same sweep. The no-op completes; the wire-bound one still PARKS.
    let path = unique_temp_db_path("noop-deferred-epoch");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        // A = "not in INBOX" AND the capture-time provider truth is the same ⇒ P == A:
        // the forward archive of a message that was never in INBOX.
        UndoStageConnector::single(false, false),
    );
    bus.execute(&archive_cmd("k-nx")).expect("the forward archive applies");
    let observes_after_forward = bus.connector().observe_count();
    // The undo is admitted but DEFERRED: a live same-resource predecessor owns the head.
    seed_pending_peer(&path, &bus, "k-nx-peer");
    assert!(
        matches!(bus.undo("k-nx"), Err(ExecuteError::InProgress)),
        "the no-op undo defers behind its live predecessor"
    );
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-nx"));
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "precondition: the no-op child awaits ITS head moment"
    );
    assert_eq!(status_str(&path, "k-nx"), "applied", "…and the parent has not flipped");
    // The predecessor clears, and a sever lands before recovery reaches the child.
    terminalize_peer(&path, "k-nx-peer");
    raw_conn(&path)
        .execute("UPDATE control_epoch SET epoch = 2 WHERE id = 1;", [])
        .expect("hand-bump the control epoch (stands in for the stage-4 sever)");

    let report = bus.recover().expect("the sweep reaches the chokepoint");

    assert_eq!(
        report.recovered, 1,
        "the no-op child COMPLETES: an undo that needs no wire is not the fence's business"
    );
    assert!(report.failed.is_empty(), "…and it is not a failure either");
    assert_eq!(
        bus.log().get(&child_key).unwrap().unwrap().status,
        IntentStatus::Applied,
        "the child terminalizes instead of barriering the resource forever"
    );
    assert_eq!(
        status_str(&path, "k-nx"),
        "undone",
        "the parent flips at the no-op VERIFICATION, under a bumped epoch or not"
    );
    assert_eq!(bus.connector().restore_count(), 0, "P == A: nothing to restore");
    assert_eq!(bus.connector().apply_count(), 1, "never a blind inverse");
    assert_eq!(
        bus.connector().observe_count(),
        observes_after_forward,
        "and not one provider READ: the decision is local by construction"
    );

    // NEGATIVE GUARD — the fence is INTACT for wire-bound work. Same shape, but the
    // capture-time truth differs from the forward target (`P != A`), so the undo can only
    // be answered by observing and restoring: under the bumped epoch it must still PARK.
    let wire_path = unique_temp_db_path("wirebound-deferred-epoch");
    let mut wire_bus = CommandBus::new(
        SqliteIntentLog::open(&wire_path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    wire_bus.execute(&archive_cmd("k-nw")).expect("the forward archive applies");
    let wire_observes_after_forward = wire_bus.connector().observe_count();
    seed_pending_peer(&wire_path, &wire_bus, "k-nw-peer");
    assert!(
        matches!(wire_bus.undo("k-nw"), Err(ExecuteError::InProgress)),
        "the wire-bound undo defers behind its live predecessor too"
    );
    let wire_child_key = undo_child_key(&opaque_intent_id(&wire_path, "k-nw"));
    terminalize_peer(&wire_path, "k-nw-peer");
    raw_conn(&wire_path)
        .execute("UPDATE control_epoch SET epoch = 2 WHERE id = 1;", [])
        .expect("the same sever");

    let wire_report = wire_bus.recover().expect("the sweep reaches the chokepoint");

    assert_eq!(wire_report.recovered, 0, "a fenced wire-bound child PARKS, in flight");
    assert!(wire_report.failed.is_empty(), "…and parking is not a failure");
    assert_eq!(
        wire_bus.log().get(&wire_child_key).unwrap().unwrap().status,
        IntentStatus::Pending,
        "it stays Pending for the stage-4 sever machinery, never self-terminalizes"
    );
    assert_eq!(status_str(&wire_path, "k-nw"), "applied", "the parent is untouched");
    assert_eq!(wire_bus.connector().restore_count(), 0, "a fenced child dispatches NOTHING");
    assert_eq!(
        wire_bus.connector().observe_count(),
        wire_observes_after_forward,
        "…and spends no provider read: the fence precedes every wire-bound branch"
    );
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&wire_path).ok();
}

#[test]
fn undo_on_a_legacy_stage2_store_never_reports_success_it_cannot_prove() {
    // THE LEGACY FALSE-`Ok`. Opening a store does NOT run recover,
    // so a caller can reach undo first on a pre-stage-3 store whose parent was flipped
    // `undone` AT SCHEDULING with its compensation still `pending` under the OLD key
    // shape. The `IntentStatus::Undone => Ok(())` replay arm fired before any legacy
    // check: undo reported SUCCESS while the provider may still hold the FORWARD state
    // — the same lie stage 3 exists to kill, arriving through the migration door.
    //
    // THE CORE IS UNCHANGED — undo never reports a success it cannot prove. The TAIL is
    // rework WITH the fixture: on REAL stage-2 bytes BOTH rows carry an
    // empty target vector, so what undo can prove here is not a restore but the NAMED
    // unavailability. A false `Ok` and an unprovable `Ok` are the same lie, and the old
    // tail could only assert a restore because the seed handed the parent a stage-3 `A` no
    // stage-2 build could have written.
    let path = unique_temp_db_path("legacy-undo-false-ok");
    SqliteIntentLog::open(&path).expect("bootstrap");
    let legacy_child_key = seed_legacy_deferred_pair(&path, "k-lf");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, false),
    );

    // NO recover — the caller met the legacy store directly.
    let answered = bus.undo("k-lf");

    assert!(
        matches!(
            answered,
            Err(ExecuteError::UndoUnavailable(
                prestate::UndoUnavailableReason::PredatesSubstrate
            ))
        ),
        "NEVER an Ok it cannot prove: a stage-2 basis carries no `A`, so the honest answer \
         is the typed unavailability, got: {answered:?}"
    );
    assert_eq!(
        bus.connector().restore_count(),
        0,
        "and nothing reached the provider — no blind inverse behind the refusal"
    );
    assert_eq!(
        status_str(&path, "k-lf"),
        "applied",
        "the scheduling-time `undone` is still MAPPED back to the last VERIFIED truth — the \
         refusal never leaves the pre-flipped lie standing"
    );
    assert_eq!(
        status_str(&path, &legacy_child_key),
        "failed",
        "the legacy compensation is terminalized — never silently left pending"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn presentation_never_says_undone_over_a_pending_legacy_child() {
    // The READ face of the same legacy class (CC triage): `undo_presentation`
    // answered `Undone` off the parent's status alone, so a pre-flipped legacy parent with
    // a live compensation displayed a false "done". The parent + an ACTIVE child IS
    // `Undoing` — the presentation truth §4.5 defines. Read-only: the MAPPING belongs to
    // undo/recover, so the projection must not mutate a byte.
    let path = unique_temp_db_path("legacy-presentation");
    SqliteIntentLog::open(&path).expect("bootstrap");
    let legacy_child_key = seed_legacy_deferred_pair(&path, "k-lp");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, false),
    );

    assert_eq!(
        bus.undo_presentation("k-lp").expect("presentation reads").map(|r| r.presentation),
        Some(UndoPresentation::Undoing),
        "a pending legacy child means the undo is IN FLIGHT, never displayed as done"
    );
    assert_eq!(
        status_str(&path, "k-lp"),
        "undone",
        "the READ path mutates NOTHING — the parent row is untouched"
    );
    assert_eq!(
        status_str(&path, &legacy_child_key),
        "pending",
        "…and so is the child: recovery/undo() own the lifecycle, presentation only displays it"
    );
    std::fs::remove_file(&path).ok();
}
