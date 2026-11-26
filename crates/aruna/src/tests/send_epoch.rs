//! The attempt claim doors and the epoch-fenced `SEND_AUTHORIZED` boundary.

use super::*;
use crate::fixtures::FIXTURE_KEY_PROVIDER;
use crate::keys::undo_child_key;
use crate::sever::verify_sever_witness;

#[test]
fn the_forward_door_mints_one_claim_owned_by_the_operation() {
    // The claim door's POSITIVE shape, through the real `execute` path: exactly one CLAIM
    // fact, ordinal 1, owned by the operation's OPAQUE id (§5.2a: `operation_id` is THE
    // immutable owner, set at the CLAIM and identical on every fact of the attempt), under
    // the current epoch — and its `attempt_head` projection agreeing with the chain
    // (the head's safety sentence: re-derivable from the chain, never a second authority).
    let path = unique_temp_db_path("claim-forward-door");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-claim")).expect("the forward applies");
    let owner = opaque_intent_id(&path, "k-claim");
    let (attempt_id, ordinal, epoch, revision, prior): (String, i64, i64, i64, Option<i64>) =
        raw_conn(&path)
            .query_row(
                "SELECT attempt_id, attempt_ordinal, basis_epoch, revision, prior_revision
                       FROM attempt_fact WHERE operation_id = ?1 AND fact_kind = 'claim';",
                rusqlite::params![owner],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("the forward dispatch minted its CLAIM");
    assert_eq!(claim_count(&path, &owner), 1, "exactly one CLAIM per attempt");
    assert_eq!(ordinal, 1, "the first attempt of an operation is ordinal 1");
    assert_eq!(epoch, 1, "claimed under the current control epoch");
    assert_eq!(revision, 1, "the CLAIM is the chain's first fact");
    assert_eq!(prior, None, "…so it is appended against nothing");
    let (head_owner, head_revision, head_class): (String, i64, String) = raw_conn(&path)
        .query_row(
            "SELECT operation_id, current_revision, derived_class FROM attempt_head
                  WHERE attempt_id = ?1;",
            rusqlite::params![attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("the head projection was written in the same transaction");
    assert_eq!(head_owner, owner, "the head carries the same one owner");
    // The head is at the VERDICT now: the same dispatch that minted
    // the CLAIM went on to commit its `SEND_AUTHORIZED` immediately before the socket and
    // then its `ACK_APPLIED` when the provider proved the effect, so the projection this
    // door leaves behind is the settled one. The CLAIM fact itself — asserted above, at
    // revision 1 against nothing — is untouched.
    assert_eq!(head_revision, 3);
    assert_eq!(
        head_class, "applied",
        "claimed, authorized AND settled — the fact-derived class, never a status read"
    );
    assert_eq!(
        chain_kinds(&path, &attempt_id),
        vec!["claim", "send_authorized", "ack_applied"],
        "the whole chain a completed forward dispatch leaves this build"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_claim_door_refuses_an_attempt_whose_owner_drifted() {
    // W-ATTEMPT-OWNER, the immutability half: `operation_id` is THE immutable owner and is
    // "identical on every fact of the attempt". The pure fold already refuses drift; this
    // witnesses it THROUGH THE STORE DOOR — a hand-grown chain whose LAST fact names a
    // different owner makes the claim door fail LOUD, never silently re-claim or repair.
    let path = unique_temp_db_path("claim-owner-drift");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-owner")).expect("the forward applies");
    let owner = opaque_intent_id(&path, "k-owner");
    let (attempt_id, created_at): (String, String) = raw_conn(&path)
        .query_row(
            "SELECT attempt_id, created_at FROM attempt_fact
                  WHERE operation_id = ?1 AND fact_kind = 'claim';",
            rusqlite::params![owner],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the CLAIM exists");
    let conn = raw_conn(&path);
    // Revision 4, because the dispatch's own chain is three facts long now (CLAIM →
    // SEND_AUTHORIZED → ACK_APPLIED, the verdict the settlement writes) — the drift is grafted onto
    // the REAL chain rather than over it, which is a strictly better fixture: nothing about
    // the drift depends on the engine having left a gap.
    conn.execute(
        "INSERT INTO attempt_fact (operation_id, attempt_id, revision, fact_kind,
                                       attempt_ordinal, basis_epoch, created_at, payload,
                                       prior_revision)
             VALUES ('some-other-operation', ?1, 4, 'ack_applied', NULL, 1, ?2, '{}', 3);",
        rusqlite::params![attempt_id, created_at],
        )
        .expect("hand-grow a chain whose owner drifts mid-attempt");
    // Put the operation back in a claimable shape so ONLY the drift can decide the answer.
    conn.execute(
        "UPDATE intents SET status = 'pending' WHERE idempotency_key = 'k-owner';",
        [],
    )
    .expect("re-open the operation");
    drop(conn);

    let err = bus.recover().expect_err("a drifted chain is never dispatched over");

    match err {
        ExecuteError::Log(LogError(message)) => {
            assert!(
                message.contains("OwnerMismatch"),
                "the refusal NAMES the drift, got '{message}'"
            );
        }
        other => panic!("expected a fail-loud Log error, got {other:?}"),
    }
    assert_eq!(
        bus.connector().apply_count(),
        1,
        "…and nothing re-reached the wire"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_claim_door_refuses_an_attempt_the_grammar_has_closed() {
    // "No second CLAIM on a terminal attempt" at ATTEMPT grain — isolated from the
    // operation-grain compare by putting the operation row back to `pending`. The chain is
    // grown to a legal terminal (CLAIM → SEND_AUTHORIZED → ACK_APPLIED, with the head
    // projection maintained), and the door reads the FOLD, not the status.
    //
    // NOTHING is hand-grown any more: the dispatch's own verdict fact
    // closes the attempt, so the fixture is the engine's REAL chain — the strongest form of
    // this witness, since the closure it refuses over is the one production writes.
    let path = unique_temp_db_path("claim-closed-attempt");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-closed")).expect("the forward applies");
    let owner = opaque_intent_id(&path, "k-closed");
    let attempt_id = attempt_id_of(&path, "k-closed");
    assert_eq!(
        chain_kinds(&path, &attempt_id),
        vec!["claim", "send_authorized", "ack_applied"],
        "the dispatch's own verdict closed the attempt — no fixture required"
    );
    let conn = raw_conn(&path);
    conn.execute(
        "UPDATE intents SET status = 'pending' WHERE idempotency_key = 'k-closed';",
        [],
    )
    .expect("re-open the OPERATION so only the ATTEMPT's closure can refuse");
    drop(conn);

    let report = bus.recover().expect("the sweep reaches the claim door");

    assert_eq!(
        bus.connector().apply_count(),
        1,
        "an attempt the grammar has closed is never dispatched again"
    );
    assert_eq!(claim_count(&path, &owner), 1, "…and grows no second CLAIM");
    assert_eq!(report.recovered, 0, "the sweep parks it, silently");
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_claim_door_compares_before_it_appends_on_both_logs() {
    // PARITY, both `IntentLog` implementations, over the door's own contract: the three
    // compare halves and the grammar refusal. The in-memory log cannot express the double-drive race (one
    // process, one map) but it MUST agree about what the door decides, or the fast tests
    // are testing a different engine than the one that ships.
    let path = unique_temp_db_path("claim-door-parity");
    let mut sqlite = SqliteIntentLog::open(&path).expect("open");
    let mut memory = InMemoryIntentLog::new();
    let command = archive_cmd("k-parity");
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(&command)
        .expect("basis");
    sqlite.record(&command, &basis).expect("record (sqlite)");
    memory.record(&command, &basis).expect("record (memory)");
    let current = AttemptClaim {
        ordinal: 1,
        predecessor: None,
        observed_attempts: 0,
    };
    let stale = AttemptClaim {
        observed_attempts: 7,
        ..current.clone()
    };
    let retry_without_lineage = AttemptClaim {
        ordinal: 2,
        ..current.clone()
    };

    for (name, log) in [
        ("sqlite", &mut sqlite as &mut dyn IntentLog),
        ("memory", &mut memory as &mut dyn IntentLog),
    ] {
        let first = log.claim_attempt("k-parity", &current).expect(name);
        let attempt_id = match &first {
            ClaimOutcome::Won { attempt_id, .. } => attempt_id.clone(),
            other => panic!("{name}: the first claim must win, got {other:?}"),
        };
        assert_eq!(
            log.claim_attempt("k-parity", &current).expect(name),
            ClaimOutcome::Won {
                attempt_id,
                ordinal: 1,
                // The re-entry hands back the head revision it SAW — the `CLAIM` fact and
                // nothing after it, on both doors.
                observed_revision: 1,
                // …and the class it FOLDED from that same chain:
                // claimed, never authorized, on both doors. The parity witness is where a
                // mirror that answered a different class would be caught.
                class: crate::attempt::AttemptClass::PreIssuance,
            },
            "{name}: a driver whose observation is still current re-enters ITS attempt"
        );
        assert_eq!(
            log.claim_attempt("k-parity", &stale).expect(name),
            ClaimOutcome::AlreadyClaimed,
            "{name}: a driver whose episode moved under it LOSES (compare-and-append)"
        );
        assert!(
            matches!(
                log.claim_attempt("k-parity", &retry_without_lineage).expect(name),
                ClaimOutcome::RefusedByGrammar(
                    crate::attempt::GrammarRefusal::RetryOrdinalMissingPredecessor { ordinal: 2 }
                )
            ),
            "{name}: ordinal > 1 without lineage is a GRAMMAR refusal, not a claim"
        );
        log.set_status_forced("k-parity", IntentStatus::Applied).expect(name);
        assert_eq!(
            log.claim_attempt("k-parity", &current).expect(name),
            ClaimOutcome::AlreadyClaimed,
            "{name}: a settled operation is never re-claimed (#62's stale Pending read)"
        );
    }
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// W-SEND-EPOCH — the epoch-fenced `SEND_AUTHORIZED` boundary (design §5.2b / EXP-6)
// ═══════════════════════════════════════════════════════════════════════════════════

/// A `SqliteIntentLog`-independent question, asked from a SEPARATE connection so it can
/// only see what is COMMITTED: does this operation hold a `SEND_AUTHORIZED` fact under
/// the CURRENT `control_epoch`?
fn authorized_under_current_epoch(path: &std::path::Path, key: &str) -> bool {
    raw_conn(path)
        .query_row(
            "SELECT EXISTS(
                     SELECT 1 FROM attempt_fact
                      WHERE operation_id = (SELECT intent_id FROM intents
                                             WHERE idempotency_key = ?1)
                        AND fact_kind = 'send_authorized'
                        AND basis_epoch = (SELECT epoch FROM control_epoch WHERE id = 1));",
            rusqlite::params![key],
            |r| r.get::<_, i64>(0),
        )
        .expect("probe the committed authorization")
        == 1
}

struct ProbeInner {
    wire: UndoStageConnector,
    path: std::path::PathBuf,
    /// The operation key to interrogate at a `restore` socket entry: `Connector::restore`
    /// is handed the PARENT's command, while the operation being authorized is the undo
    /// CHILD, so the child's key is supplied by the test rather than inferred.
    undo_key: std::cell::RefCell<String>,
    /// One `(operation key, was it authorized?)` per socket entry, in order.
    entries: std::cell::RefCell<Vec<(String, bool)>>,
    /// Run a REAL sever inside the next `observe`. In `drive_undo_child` the observation
    /// sits BETWEEN the CLAIM and the restore, which is exactly the window §5.2b's
    /// W-SEND-EPOCH scripts as "claim → pause → sever → resume".
    sever_on_observe: std::cell::Cell<bool>,
}

/// A connector that answers ONE question at socket entry — "does the operation about to
/// touch this wire hold a COMMITTED authorization under the current epoch?" — and can
/// script an epoch bump into the claim-to-socket window.
#[derive(Clone)]
struct SocketEntryProbe(std::rc::Rc<ProbeInner>);

impl SocketEntryProbe {
    fn new(path: &std::path::Path, wire: UndoStageConnector) -> Self {
        SocketEntryProbe(std::rc::Rc::new(ProbeInner {
            wire,
            path: path.to_path_buf(),
            undo_key: std::cell::RefCell::new(String::new()),
            entries: std::cell::RefCell::new(Vec::new()),
            sever_on_observe: std::cell::Cell::new(false),
        }))
    }
    fn wire(&self) -> &UndoStageConnector {
        &self.0.wire
    }
    fn expect_undo(&self, key: &str) {
        *self.0.undo_key.borrow_mut() = key.to_string();
    }
    fn sever_on_next_observe(&self) {
        self.0.sever_on_observe.set(true);
    }
    fn entries(&self) -> Vec<(String, bool)> {
        self.0.entries.borrow().clone()
    }
    fn record_entry(&self, key: String) {
        let authorized = authorized_under_current_epoch(&self.0.path, &key);
        self.0.entries.borrow_mut().push((key, authorized));
    }
}

impl Connector for SocketEntryProbe {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.record_entry(command.idempotency_key.clone());
        self.0.wire.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.0.wire.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        if self.0.sever_on_observe.replace(false) {
            sever_from_control_plane(&self.0.path, "authority:test-control-plane");
        }
        self.0.wire.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        let key = self.0.undo_key.borrow().clone();
        self.record_entry(key);
        self.0.wire.restore(command, basis, p)
    }
}

#[test]
fn no_socket_entry_without_a_committed_send_authorization() {
    // W-SEND-EPOCH, the BOUNDARY half (§5.2b): "the connector may not touch the wire
    // without its own committed `SEND_AUTHORIZED`". All three wire-bound doors — forward
    // `execute`, forward `recover`, and the undo-child `restore` — asked the same way, by
    // a probe that interrogates the STORE from its own connection at the instant of socket
    // entry (so it sees only what is COMMITTED, which is the whole claim being made).
    let path = unique_temp_db_path("send-auth-socket-entry");
    let probe = SocketEntryProbe::new(&path, UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), probe.clone());

    // ── DOOR 1: forward `execute`. ──
    bus.execute(&archive_cmd("k-fwd")).expect("the forward applies");

    // ── DOOR 2: forward `recover`. A row admitted without dispatching (another driver's
    //    crash between admission and the wire) on its OWN resource, so no tail barrier. ──
    {
        let mut seed = SqliteIntentLog::open(&path).expect("open seed");
        let deferred = Command::new(
            "k-sweep",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-2".into(),
            },
        );
        let basis = probe.resolve_basis(&deferred).expect("basis");
        seed.record(&deferred, &basis).expect("admit without dispatching");
    }
    bus.recover().expect("the sweep dispatches it");

    // ── DOOR 3: the undo child's `restore`. The provider now holds `A`, so the §3.2
    //    decision is RESTORE and the restore socket is entered. ──
    probe.wire().set_state(atoms(&[("membership:INBOX", false)]));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-fwd"));
    probe.expect_undo(&child_key);
    bus.undo("k-fwd").expect("C == A ⇒ the delta restore dispatches");

    let entries = probe.entries();
    assert_eq!(
        entries.len(),
        3,
        "three socket entries, one per wire-bound door; got {entries:?}"
    );
    for (key, authorized) in &entries {
        assert!(
            authorized,
            "'{key}' entered the connector socket with NO committed SEND_AUTHORIZED under \
             the current epoch (§5.2b); entries: {entries:?}"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_epoch_bump_between_the_claim_and_the_socket_refuses_the_undo_restore() {
    // W-SEND-EPOCH, the EPOCH half, end-to-end through the undo door: claim → pause →
    // (sever) → resume, with the bump scripted into the `observe` that sits between
    // `drive_undo_child`'s CLAIM and its `restore`. The pre-claim epoch fence cannot see
    // it — it ran BEFORE the claim — so this is the boundary the send-auth fence exists
    // for, and nothing else in the drive asks the question again.
    let path = unique_temp_db_path("send-auth-epoch-undo");
    let probe = SocketEntryProbe::new(&path, UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), probe.clone());
    bus.execute(&archive_cmd("k-sev")).expect("the forward applies");
    probe.wire().set_state(atoms(&[("membership:INBOX", false)]));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-sev"));
    probe.expect_undo(&child_key);
    probe.sever_on_next_observe();

    let outcome = bus.undo("k-sev");

    assert_eq!(
        probe.wire().restore_call_count(),
        0,
        "a sever between the CLAIM and the socket must refuse the restore PRE-WIRE"
    );
    assert!(
        probe.wire().restored().is_empty(),
        "…and write no captured P, got {:?}",
        probe.wire().restored()
    );
    // …and the drive REPORTS the sever, never a silent `Ok` and never `InProgress`.
    //
    // THIS LINE READ `InProgress` UNTIL THE PREEMPTIVE FIX, and it was the defect
    // wearing the grammar's clothes. On THIS interleave the sever's own transaction closes
    // the attempt (`SEVERED_BEFORE_ISSUANCE`, asserted below) and the operation, so our
    // later fence finds the closure already written and `authorize_send` refuses through
    // the GRAMMAR (`PostTerminalAppend`) rather than answering `EpochFenced` — which 's
    // re-read did not cover. The row this witness itself asserts is `severed` forever, and
    // telling a caller to wait for it is telling it to wait for nothing. What the pre-wire
    // half of W-SEND-EPOCH proves is unchanged and still asserted above: no socket, no
    // restored `P`, no authorization.
    assert_eq!(
        outcome,
        Err(ExecuteError::Severed),
        "the refused drive surfaces the sever — never a silent Ok, and never in-flight over \
         a row that is closed forever; got {outcome:?}"
    );
    // The refusal TERMINALIZED, atomically: "witnessing without closing strands them".
    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "the fenced attempt's operation closes SEVERED in the sever's own transaction"
    );
    assert_eq!(
        status_str(&path, "k-sev"),
        "applied",
        "the parent stays truthfully applied — the undo never ran"
    );
    let attempt = attempt_id_of(&path, &child_key);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "severed_before_issuance"],
        "claimed, never authorized — the §5.2c class a sever reads"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt),
        0,
        "no authorization was ever committed under the stale epoch"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_store_fence_severs_a_forward_attempt_whose_epoch_moved_after_the_claim() {
    // The FORWARD doors' epoch arm, scripted where the two transactions actually meet.
    // `execute` and `recover` have NO connector call between the CLAIM and `apply` — the
    // fence IS the last thing before the socket by construction — so there is no in-bus
    // window to sever from; the interleave is scripted at the store door both forward
    // doors call. (The undo door's twin runs end-to-end above, where `observe` occupies
    // exactly that window.)
    //
    // TASK 7 CHANGED WHO AUTHORS THE CLOSURE, and this witness now says so. The epoch move
    // is a REAL sever, and a sever CLASSIFIES this attempt (claimed, never authorized =>
    // `SEVERED_BEFORE_ISSUANCE`) and CLOSES it in its own transaction — §5.2c's
    // "witnessing without closing strands them". The fence's job on this shape is
    // therefore to refuse and write NOTHING further; its own TERMINALIZING arm is
    // witnessed where it is the only thing that can act — on an attempt the sever could
    // not see, in
    // `a_completed_operations_live_attempt_is_absent_from_the_witness_and_fenced_at_the_socket`.
    // The invariant this witness has always been about is unchanged, and asserted last: no
    // authorization is EVER committed under a stale epoch.
    let path = unique_temp_db_path("send-auth-epoch-forward");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let command = archive_cmd("k-fwd-sev");
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(&command)
        .expect("basis");
    log.record(&command, &basis).expect("admit");
    let attempt_id = match log
        .claim_attempt(
            "k-fwd-sev",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the first claim must win, got {other:?}"),
    };

    let severed = sever_from_control_plane(&path, "authority:operator-forward");

    assert_eq!(
        member_class(&severed.witness, &attempt_id),
        Some(crate::attempt::WitnessClass::SeveredBeforeIssuance),
        "the sever CLASSIFIED the claimed-unauthorized attempt (§5.2c bullet 3)"
    );
    assert_eq!(
        status_str(&path, "k-fwd-sev"),
        "severed",
        "…and closed its operation in the SAME transaction as the witness"
    );
    assert_eq!(
        chain_kinds(&path, &attempt_id),
        vec!["claim", "severed_before_issuance"]
    );
    // THE FENCE, asked after the sever: it refuses, and writes nothing further — a closed
    // attempt is never authorized, and never closed twice.
    assert!(
        matches!(
            authorize(&mut log, "k-fwd-sev", &attempt_id).expect("fence"),
            SendAuthOutcome::RefusedByGrammar(
                crate::attempt::GrammarRefusal::PostTerminalAppend { .. }
            )
        ),
        "the post-sever issuance gate refuses a terminalized attempt"
    );
    assert_eq!(
        chain_kinds(&path, &attempt_id),
        vec!["claim", "severed_before_issuance"],
        "…and the refusal grew no second closure"
    );
    // A second ask never resurrects it either.
    assert!(matches!(
        authorize(&mut log, "k-fwd-sev", &attempt_id).expect("second ask"),
        SendAuthOutcome::RefusedByGrammar(_)
    ));
    assert_eq!(
        send_authorized_count(&path, &attempt_id),
        0,
        "THE INVARIANT, unchanged: no authorization is ever committed under a stale epoch"
    );
    verify_sever_witness(&witness_row(&path, severed.epoch)).expect("the witness reconciles");
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_belt_refuses_a_send_authorized_after_a_sever_tickets() {
    // THE BELT. The scenario the ordinary epoch fence above CANNOT see:
    // this writer's `authorize_send` ENROLLS (gate-level: `active_writer` flips true)
    // before any sever ticket exists, so `WriterGate::enroll`'s wait predicate is never
    // even re-evaluated against a pending sever — by the time this transaction is open, a
    // sever can be TICKETED (not yet served, epoch still unmoved), and the ordinary
    // `epoch != claim.claim_epoch` re-read a few lines into `authorize_send` would read the
    // OLD epoch and authorize anyway. The belt catches exactly this window by asking the
    // gate directly, as its FIRST act inside the transaction — never merely parking at
    // enrollment, which is the (already-witnessed) different property the
    // `a_pending_sever_blocks_new_enrollment` covers.
    //
    // TIMING-FREE. The rendezvous is REAL SQLite write-lock contention, not a clock or a
    // production pause seam: a second, UNGATED connection holds `BEGIN IMMEDIATE` open on
    // the store file BEFORE `authorize_send` runs. `authorize_send`'s own `enroll()` (an
    // in-process, gate-level operation) succeeds immediately — nothing else has enrolled —
    // flipping `active_writer` true; its SQL-level `BEGIN IMMEDIATE` then BLOCKS inside
    // SQLite's own busy machinery (`busy_timeout` 5000 ms, `raw_conn`'s durability profile)
    // waiting for the blocker's lock. That is exactly the design's named window ("sever
    // raised between enroll and BEGIN"): with the gate already reporting an active writer
    // but no SQL transaction open yet, a REAL `begin_sever()` on a second gate handle is
    // driven deterministically to `sever_pending == 1` (observed via gate state — no
    // sleep, no clock). Only THEN is the blocker's lock released, letting
    // `authorize_send`'s `BEGIN IMMEDIATE` proceed into its closure with the sever already
    // ticketed and unserved (its leader is parked behind THIS writer's still-live scope).
    let path = unique_temp_db_path("belt-refuses-send");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap + open");
    let command = archive_cmd("k-belt");
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(&command)
        .expect("basis");
    log.record(&command, &basis).expect("admit");
    let attempt_id = match log
        .claim_attempt(
            "k-belt",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the first claim must win, got {other:?}"),
    };

    // A second gate handle on the SAME identity, purely to observe/drive gate state — the
    // T6a-established pattern (`enrollment_spans_the_transaction_not_the_statement`).
    let observer = std::sync::Arc::new(
        crate::writer_gate::WriterGate::for_path(&path).expect("identity is obtainable"),
    );
    assert!(
        !observer.snapshot().expect("snapshot").active_writer,
        "no writer is enrolled before the drive starts"
    );

    // THE BLOCKER: an UNGATED raw connection holding the store's one SQL write lock, so
    // `authorize_send`'s own `BEGIN IMMEDIATE` is forced to wait. TEST MACHINERY ONLY —
    // this is not a claim about production contention, only a deterministic way to widen
    // the enroll-then-BEGIN window the design names.
    let blocker = raw_conn(&path);
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the blocker holds the write lock");

    let capture = log
        .captured_pre_state("k-belt")
        .ok()
        .flatten()
        .map(|c| CaptureBinding::Generation(c.capture_generation))
        .unwrap_or(CaptureBinding::NoJournalRow);
    let attempt_for_thread = attempt_id.clone();
    let writer = std::thread::spawn(move || {
        let outcome = log.authorize_send("k-belt", &attempt_for_thread, capture, crate::plan::PlanBinding::Plain);
        (log, outcome)
    });

    // The gate ALREADY reports the writer active — `enroll()` happens before `BEGIN
    // IMMEDIATE` — even while the SQL transaction itself is still blocked on the
    // blocker's lock.
    t6a_spin_until(
        "authorize_send enrolls before its BEGIN IMMEDIATE unblocks",
        || observer.snapshot().expect("snapshot").active_writer,
    );

    // Raise a REAL sever ticket now: `begin_sever` sets `sever_pending` SYNCHRONOUSLY,
    // under the state mutex, before it ever parks (writer_gate.rs) — so waiting for
    // `sever_pending == 1` is deterministic, no clock anywhere.
    let sever_observer = std::sync::Arc::clone(&observer);
    let sever_thread =
        std::thread::spawn(move || sever_observer.begin_sever("authority:belt-witness"));
    t6a_spin_until("the sever ticket is raised and pending", || {
        observer.snapshot().expect("snapshot").sever_pending == 1
    });
    assert!(
        observer.sever_raised().expect("sever_raised"),
        "the belt's own read must see the ticket"
    );

    // NOW release the SQL lock — `authorize_send`'s `BEGIN IMMEDIATE` proceeds into a
    // transaction whose FIRST act is the belt's re-read, with the sever still PENDING
    // (unserved: its leader is parked behind this writer's still-live scope).
    blocker
        .execute_batch("ROLLBACK;")
        .expect("release the write lock");
    drop(blocker);

    let (log, outcome) = writer.join().expect("authorize_send thread");
    assert_eq!(
        outcome.expect("authorize_send answers"),
        SendAuthOutcome::EpochFenced,
        "THE BELT: a sever pending at the transaction's first act refuses, even though \
         enrollment itself never parked (it succeeded before the ticket rose) and the \
         epoch has not moved yet"
    );
    assert_eq!(
        chain_kinds(&path, &attempt_id),
        vec!["claim"],
        "the belt writes NOTHING — no SEND_AUTHORIZED, no SEVERED_BEFORE_ISSUANCE: the \
         pending sever's own transaction performs that closure, not this refusal"
    );

    // Let the parked sever proceed now that the writer's scope has dropped, and release
    // its service cleanly (a leader dropped without completing resolves `Failed` on its
    // own, but this witness completes it explicitly so the assertion is about the belt,
    // not about `SeverEntry`'s Drop).
    let mut sever_entry = sever_thread
        .join()
        .expect("sever thread")
        .expect("the sever is finally served");
    assert!(
        sever_entry.is_leader(),
        "the lone requester leads its own service"
    );
    sever_entry
        .complete(crate::writer_gate::SeverOutcome::Failed {
            detail: "test-only completion — no real epoch bump; the production sever door \
                     (`IntentLog::sever`) and its epoch-bump race are exercised by the \
                     W-SEND-EPOCH witnesses above"
                .to_string(),
        })
        .expect("complete the service");

    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_sever_after_the_authorization_never_claims_non_issuance() {
    // §5.2c bullet 3, at the fence: "send fact without terminal attribution ⇒
    // `ISSUED_OR_UNKNOWN` (incl. the stamp-to-wire crash — we cannot prove non-issuance, so
    // we do not claim it)". So when the epoch moves under an ALREADY-authorized attempt,
    // the fence must NOT write `SEVERED_BEFORE_ISSUANCE` — the grammar refuses that lie,
    // the attempt keeps its honest class, and the refusal is a PARK for the dispatcher
    // rather than a store incident that would abort a sweep.
    let path = unique_temp_db_path("send-auth-sever-after-auth");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let command = archive_cmd("k-after");
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(&command)
        .expect("basis");
    log.record(&command, &basis).expect("admit");
    let attempt_id = match log
        .claim_attempt(
            "k-after",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the first claim must win, got {other:?}"),
    };
    assert!(matches!(
        authorize(&mut log, "k-after", &attempt_id).expect("authorize"),
        SendAuthOutcome::Authorized { .. }
    ));

    let severed = sever_from_control_plane(&path, "authority:operator-after");
    assert_eq!(
        member_class(&severed.witness, &attempt_id),
        Some(crate::attempt::WitnessClass::IssuedOrUnknown),
        "the sever WITNESSED it as ISSUED_OR_UNKNOWN and left it operationally alive — the              classification this refusal exists to protect"
    );

    assert_eq!(
        authorize(&mut log, "k-after", &attempt_id).expect("post-sever ask"),
        SendAuthOutcome::RefusedByGrammar(
            crate::attempt::GrammarRefusal::SeveredAfterSendAuthorization
        ),
        "the fence refuses — and refuses to fabricate a non-issuance it cannot prove"
    );
    assert_eq!(
        chain_kinds(&path, &attempt_id),
        vec!["claim", "send_authorized"],
        "the chain is untouched: ISSUED_OR_UNKNOWN is the truthful class"
    );
    assert_eq!(
        status_str(&path, "k-after"),
        "pending",
        "…and the operation is NOT closed by a fence that cannot classify it — the sever \
         primitive owns that classification"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn two_current_drivers_both_win_the_claim_but_only_one_wins_the_wire() {
    // ═══ THE RE-ENTRY RESIDUAL, CLOSED ═══
    // `IntentLog::claim_attempt`'s own words: "two drivers whose reads are BOTH current
    // still both see `Won`. That residual is closed by the epoch-fenced `SEND_AUTHORIZED`
    // boundary (at most one per attempt, committed immediately before socket entry)."
    // This is that witness, in topology (two buses, two connections, one file).
    //
    // The state both drivers legitimately read as current is the CRASH WINDOW between the
    // socket and the status write: the claim (and, after this change, the authorization) is
    // committed, the operation is still non-terminal, and the dispatch episode has not
    // moved. It is reconstructed by direct SQL — putting the two rows back exactly where a
    // crash at that instant leaves them — because no fault injection can stop the engine
    // between two of its own statements.
    let path = unique_temp_db_path("send-auth-reentry-residual");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus_a = CommandBus::new(SqliteIntentLog::open(&path).expect("open A"), wire.clone());
    let mut bus_b = CommandBus::new(SqliteIntentLog::open(&path).expect("open B"), wire.clone());
    bus_a.execute(&archive_cmd("k-once")).expect("the forward applies");
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-once"));

    // ── A drives the undo child: the restore reaches the wire (touch 1). ──
    bus_a.undo("k-once").expect("C == A ⇒ the delta restore dispatches");
    assert_eq!(wire.wire().restore_call_count(), 1, "A touched the wire once");
    let attempt = attempt_id_of(&path, &child_key);

    // ── THE CRASH WINDOW, reconstructed: A died between `Connector::restore` returning
    //    and `verify_undo`'s two status writes. Both rows go back to what they were. ──
    {
        let conn = raw_conn(&path);
        conn.execute(
            "UPDATE intents SET status = 'applied' WHERE idempotency_key = 'k-once';",
            [],
        )
        .expect("the parent had not flipped yet");
        conn.execute(
            "UPDATE intents SET status = 'pending' WHERE idempotency_key = ?1;",
            rusqlite::params![child_key],
        )
        .expect("the child had not terminalized yet");
    }
    // A newer actor re-archived the message, so the stale drive would once again decide
    // RESTORE — the wire touch is REACHABLE, which is what makes this a witness and not a
    // convergence short-circuit.
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));

    // ── B reads the child NOW: a perfectly CURRENT read (pending, episode 0). ──
    let child = bus_b
        .log()
        .get(&child_key)
        .unwrap()
        .expect("B sees the child");
    assert_eq!(child.status, IntentStatus::Pending);
    assert_eq!(child.attempts, 0, "the episode never moved — B's read is CURRENT");

    let outcome = bus_b.drive_undo_child(&child);

    assert_eq!(
        wire.wire().restore_call_count(),
        1,
        "ONE attempt = at most one potentially-effectful wire dispatch (§5.2b): the second \
         equally-current driver must not reach the socket"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt),
        1,
        "at most one SEND_AUTHORIZED per attempt — the grammar's own arbiter"
    );
    assert!(
        matches!(outcome, Err(ExecuteError::InProgress)),
        "the loser parks silently; got {outcome:?}"
    );
    assert_eq!(
        claim_count(&path, &opaque_intent_id(&path, &child_key)),
        1,
        "…and both drivers rode the ONE claim (the re-entry arm did its job)"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_re_driven_forward_dispatch_is_never_authorized_twice() {
    // The forward twin of the residual close, same crash window: `execute` reached the
    // socket and died before writing `Applied`. The next sweep's read is CURRENT (pending,
    // episode 0) and its claim legitimately re-enters — but the authorization is already
    // spent, so the sweep must not put a SECOND potentially-effectful dispatch on the wire.
    //
    // What this operation becomes is ISSUED-OR-UNKNOWN: authorized, unacked, never
    // re-authorized and never falsely settled (§5.2b). The verdict facts that settle it and
    // the retry LINEAGE that mints a fresh attempt for a legitimate re-send are the next
    // build steps; this change's job is that no second wire touch happens meanwhile.
    let path = unique_temp_db_path("send-auth-forward-reentry");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-crash")).expect("the forward applies");
    let attempt = attempt_id_of(&path, "k-crash");
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'pending' WHERE idempotency_key = 'k-crash';",
            [],
        )
        .expect("reconstruct the socket-to-status crash window");

    bus.recover().expect("the sweep re-reads a CURRENT pending row");

    assert_eq!(
        bus.connector().apply_count(),
        1,
        "the re-drive must not reach the wire a second time under one attempt"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt),
        1,
        "at most one SEND_AUTHORIZED per attempt"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_send_auth_fence_refuses_a_dispatch_overlapping_an_unresolved_exposure() {
    // EXP-3 / EXP-6, the gate that lives INSIDE the send-auth transaction. Nothing creates
    // `exposure_obligation` rows until the adjudication task writes them (it owns the
    // production writer), so this seeds one BY HAND — the same discipline the §6 tombstone
    // witnesses use — which is what makes the gate RED-provable NOW instead of vacuously
    // green until then.
    //
    // No risk-acceptance capability exists in this build (the plan's scope fence, EXP-10's
    // own fallback), so an overlap has exactly one honest answer: refuse fail-closed,
    // pre-wire, with a deterministic no-effect terminal.
    let path = unique_temp_db_path("send-auth-exposure-gate");
    let connector = UndoStageConnector::single(false, true);
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let contributor = archive_cmd("k-contrib");
    let blocked = Command::new(
        "k-blocked",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let disjoint = Command::new(
        "k-disjoint",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-9".into(),
        },
    );
    for command in [&contributor, &blocked, &disjoint] {
        let basis = connector.resolve_basis(command).expect("basis");
        log.record(command, &basis).expect("admit");
    }
    let claim = AttemptClaim {
        ordinal: 1,
        predecessor: None,
        observed_attempts: 0,
    };
    let claimed = |log: &mut SqliteIntentLog, key: &str| match log
        .claim_attempt(key, &claim)
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the first claim must win, got {other:?}"),
    };
    let contributor_attempt = claimed(&mut log, "k-contrib");
    let blocked_attempt = claimed(&mut log, "k-blocked");
    let disjoint_attempt = claimed(&mut log, "k-disjoint");

    // The obligation the adjudication task will one day write: one unretired row over the
    // primitive atom `k-contrib` may have touched.
    let overlapped = crate::attempt::exposure_atom_key(
        &prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &["msg-1"]),
        "membership:INBOX",
    );
    raw_conn(&path)
        .execute(
            "INSERT INTO exposure_obligation (obligation_id, provider_scope,
                                                  primitive_atom, direction, generation,
                                                  contributor_attempt_id, created_at)
                 VALUES ('obl-1', 'scope-1', ?1, 'clear', 1, ?2, '2026-08-08T00:00:00Z');",
            rusqlite::params![overlapped, contributor_attempt],
        )
        .expect("seed the unresolved obligation by hand");

    // EXP-5: an operation on a DIFFERENT resource is not gated by unrelated history.
    assert!(
        matches!(
            authorize(&mut log, "k-disjoint", &disjoint_attempt)
                .expect("disjoint"),
            SendAuthOutcome::Authorized { .. }
        ),
        "disjoint means disjoint — unrelated unresolved history gates nothing"
    );
    // EXP-3: the overlapping one refuses fail-closed, pre-wire.
    assert_eq!(
        authorize(&mut log, "k-blocked", &blocked_attempt)
            .expect("overlap"),
        SendAuthOutcome::ExposureBlocked {
            atom_key: overlapped
        },
        "an unresolved exposure over the touched atom refuses the authorization"
    );
    assert_eq!(
        send_authorized_count(&path, &blocked_attempt),
        0,
        "…so nothing was ever authorized to touch the wire"
    );
    assert_eq!(
        chain_kinds(&path, &blocked_attempt),
        vec!["claim", "failed_pre_send"],
        "the refusal IS the deterministic no-effect terminal (EXP-6), never a limbo"
    );
    assert_eq!(
        status_str(&path, "k-blocked"),
        "failed",
        "…and it closes the operation in the same transaction — never a held slot"
    );
    std::fs::remove_file(&path).ok();
}
