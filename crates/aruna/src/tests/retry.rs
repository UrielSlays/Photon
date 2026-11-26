//! Retry lineage, retry requalification, the transient budget, and the dual accounting.

use super::*;

#[test]
fn the_recovery_sweep_never_dead_letters_an_operation_whose_issuance_is_unknown() {
    // ROW (c), second arm — the FACTS-ONLY rule applied to `recover()` itself. The
    // pre-dispatch retry-cap self-heal decides from a RAW STATUS + COUNTER read; on an
    // operation holding an ISSUED_OR_UNKNOWN attempt that write claims proof of no-effect
    // that nobody has. CRAFT: real calls only — `charge_and_dead_letter_if_quiescent` under a
    // lifted cap is the engine's own budget writer.
    let path = unique_temp_db_path("boot-unknown-at-cap");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit(&mut log, &archive_of("k-cap", "msg-1"));
        for _ in 0..RETRY_CAP {
            assert_eq!(
                log.charge_and_dead_letter_if_quiescent("k-cap", u32::MAX)
                    .expect("charge the durable budget without terminalizing"),
                TransientCharge::ChargedOnly
            );
        }
        let attempt = claim_now(&mut log, "k-cap", RETRY_CAP);
        authorize_now(&mut log, "k-cap", &attempt);
        attempt
    };
    assert_eq!(attempts_of(&path, "k-cap"), i64::from(RETRY_CAP));

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    bus.recover().expect("sweep");

    assert_eq!(
        status_str(&path, "k-cap"),
        "pending",
        "a budget-exhausted operation whose attempt was AUTHORIZED is not dead-letterable \
         — `failed` would be a read-derived attribution of no-effect"
    );
    assert_eq!(chain_kinds(&path, &attempt), vec!["claim", "send_authorized"]);
    assert_eq!(bus.connector().apply_count(), 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_cap_self_heal_never_dead_letters_over_a_peers_live_claim() {
    // The PREDICATE half. The self-heal used to park only on an
    // `ISSUED_OR_UNKNOWN` live attempt and dead-letter everything else — so a peer's LIVE,
    // not-yet-authorized claim was buried under a terminal `Failed`. That peer may still
    // authorize and reach the wire (it holds the claim; nothing about a status column stops
    // `authorize_send`), and its ACK can then never replace the terminal. "A terminal
    // written over a live attempt leaves that attempt dangling — still claimable, still
    // authorizable, on an operation the ledger says is closed" ([`IntentLog::live_attempt`]).
    //
    // CRAFT: real calls only — the durable budget writer under a lifted cap, then the
    // ordinary claim door on a second driver's behalf.
    let path = unique_temp_db_path("r8-cap-live-claim");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit(&mut log, &archive_of("k-cap", "msg-1"));
        for _ in 0..RETRY_CAP {
            assert_eq!(
                log.charge_and_dead_letter_if_quiescent("k-cap", u32::MAX)
                    .expect("charge the durable budget without terminalizing"),
                TransientCharge::ChargedOnly
            );
        }
        // A PEER driver owns this operation's dispatch: claimed, not yet authorized.
        claim_now(&mut log, "k-cap", RETRY_CAP)
    };
    assert_eq!(attempts_of(&path, "k-cap"), i64::from(RETRY_CAP));

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    bus.recover().expect("sweep");

    assert_eq!(
        status_str(&path, "k-cap"),
        "pending",
        "an over-budget operation whose dispatch a PEER holds is not this sweep's to \
         dead-letter — the terminal would strand a claim that can still be authorized"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim"],
        "…and the sweep wrote nothing to the peer's attempt"
    );
    assert_eq!(bus.connector().apply_count(), 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_cap_self_heals_status_transition_fences_the_head_in_its_own_transaction() {
    // The ATOMICITY half — the interleave the predicate alone cannot
    // close, scripted across TWO CONNECTIONS onto one store (the in-memory log cannot
    // express it). The self-heal used to read the attempt head in one transaction and CAS
    // the status in another; a peer driver claiming and appending `SEND_AUTHORIZED` in that
    // window may reach the provider, while the sweep's `Failed` lands behind it and the ACK
    // can never replace a terminal.
    let path = unique_temp_db_path("r8-cap-window");
    let mut sweep = SqliteIntentLog::open(&path).expect("the sweep's connection");
    admit(&mut sweep, &archive_of("k-cap", "msg-1"));
    for _ in 0..RETRY_CAP {
        assert_eq!(
            sweep
                .charge_and_dead_letter_if_quiescent("k-cap", u32::MAX)
                .expect("charge the durable budget without terminalizing"),
            TransientCharge::ChargedOnly
        );
    }
    // ① THE SWEEP'S DECISION READ: no live attempt ⇒ "eligible for the dead-letter".
    assert!(
        sweep.live_attempt("k-cap").expect("head read").is_none(),
        "precondition: at the decision moment the operation holds no live attempt"
    );
    // ② THE WINDOW: a PEER driver, on its OWN connection, claims and AUTHORIZES.
    let attempt = {
        let mut peer = SqliteIntentLog::open(&path).expect("the peer's connection");
        let attempt = claim_now(&mut peer, "k-cap", RETRY_CAP);
        authorize_now(&mut peer, "k-cap", &attempt);
        attempt
    };
    // ③ THE SWEEP'S STATUS TRANSITION, taken on the read from ①.
    let wrote = sweep
        .dead_letter_if_quiescent("k-cap")
        .expect("the self-heal's status transition");

    assert_eq!(
        wrote,
        DeadLetterWrite::LiveAttempt(crate::attempt::AttemptClass::IssuedOrUnknown),
        "the transition must be decided against the head IN ITS OWN TRANSACTION — a peer \
         that authorized in the window owns the wire, and a dead-letter behind it is the \
         engine claiming proof of no-effect over a request that may already be issued"
    );
    assert_eq!(
        status_str(&path, "k-cap"),
        "pending",
        "…so nothing terminal was written over the live authorized attempt"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized"],
        "…and the peer's chain is untouched"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_over_budget_charge_never_dead_letters_over_a_peers_live_attempt() {
    // — the SAME class as the dead-letter door's, on the other door
    // that writes a terminal: the budget CHARGE. Its exhaustion arm carried the
    // `NonTerminal` compare and not the quiescence one, so the last unit of budget — spent
    // by the capture pipeline's attempt-less `observe` failure, which reconciles at
    // OPERATION grain — wrote `Failed` over a peer's claimed-and-AUTHORIZED dispatch. That
    // peer may already be on the provider's wire, and its ACK can never replace a terminal
    // ([`IntentLog::settle_attempt`]'s lifecycle guard).
    //
    // Scripted across TWO CONNECTIONS onto one store (the in-memory log cannot express it);
    // the peer's claim is taken at `RETRY_CAP - 1`, i.e. the budget it actually observed.
    // CRAFT: real calls only — the engine's own budget writer under a lifted cap for the
    // set-up, then the door under test at the REAL cap.
    let path = unique_temp_db_path("r13-charge-live");
    let mut sweep = SqliteIntentLog::open(&path).expect("the sweep's connection");
    admit(&mut sweep, &archive_of("k-cap", "msg-1"));
    for _ in 0..RETRY_CAP - 1 {
        assert_eq!(
            sweep
                .charge_and_dead_letter_if_quiescent("k-cap", u32::MAX)
                .expect("charge the durable budget without terminalizing"),
            TransientCharge::ChargedOnly
        );
    }
    // A PEER driver owns this operation's dispatch: claimed AND authorized — it may already
    // be on the provider's wire.
    let attempt = {
        let mut peer = SqliteIntentLog::open(&path).expect("the peer's connection");
        let attempt = claim_now(&mut peer, "k-cap", RETRY_CAP - 1);
        authorize_now(&mut peer, "k-cap", &attempt);
        attempt
    };
    // The sweep's own transient observe failure spends the LAST unit of budget.
    let charged = sweep
        .charge_and_dead_letter_if_quiescent("k-cap", RETRY_CAP)
        .expect("the over-budget charge");

    assert_eq!(
        charged,
        TransientCharge::ChargedOnly,
        "an exhausted budget is not by itself authority to close an operation whose \
         dispatch a peer holds — and the answer says so, so the caller reports no terminal \
         it did not write"
    );
    assert_eq!(
        attempts_of(&path, "k-cap"),
        i64::from(RETRY_CAP),
        "the charge itself always lands"
    );
    assert_eq!(
        status_str(&path, "k-cap"),
        "pending",
        "…but the dead-letter is not this caller's to write over a peer's live attempt"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized"],
        "…and the peer's chain is untouched"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_in_memory_cap_self_heal_answers_the_same_three_ways_over_its_mirror() {
    // ONE RULE, TWO DOORS. The mirror decides the SAME two things in the SAME order — the
    // head predicate first, then the non-terminal compare — and decides BOTH before writing
    // anything, which is what "one transaction" reduces to on a single-threaded log.
    let mut mem = InMemoryIntentLog::new();

    // QUIESCENT: no attempt was ever claimed, so the counter's attribution is honest and
    // the dead-letter is this sweep's to write.
    record_basis(&mut mem, &archive_cmd("k-quiet")).expect("admit");
    assert_eq!(
        mem.dead_letter_if_quiescent("k-quiet").expect("the door"),
        DeadLetterWrite::Written
    );
    assert_eq!(
        mem.get("k-quiet").expect("get").expect("row").status,
        IntentStatus::Failed
    );
    // …and a SETTLED row is never rewritten: the refusal NAMES what it holds, exactly as
    // `set_status_if`'s does — including for a row that does not exist at all.
    assert_eq!(
        mem.dead_letter_if_quiescent("k-quiet").expect("the door"),
        DeadLetterWrite::StatusMoved(Some(IntentStatus::Failed))
    );
    assert_eq!(
        mem.dead_letter_if_quiescent("k-absent").expect("the door"),
        DeadLetterWrite::StatusMoved(None)
    );

    // LIVE: a peer's CLAIM that has not authorized yet. It is still authorizable, so it is
    // still not ours to close — the predicate is "no live attempt", not "no unknown one".
    record_basis(&mut mem, &archive_of("k-live", "msg-live")).expect("admit");
    assert!(
        matches!(
            mem.claim_attempt(
                "k-live",
                &AttemptClaim {
                    ordinal: 1,
                    predecessor: None,
                    observed_attempts: 0,
                },
            )
            .expect("claim"),
            ClaimOutcome::Won { .. }
        ),
        "precondition: a peer holds this operation's dispatch"
    );
    assert_eq!(
        mem.dead_letter_if_quiescent("k-live").expect("the door"),
        DeadLetterWrite::LiveAttempt(crate::attempt::AttemptClass::PreIssuance)
    );
    assert_eq!(
        mem.get("k-live").expect("get").expect("row").status,
        IntentStatus::Pending,
        "…and the refusal wrote nothing"
    );
}

#[test]
fn the_in_memory_budget_charge_answers_the_same_three_ways_over_its_mirror() {
    // ONE RULE, TWO DOORS — the charge's mirror. Same order as
    // the durable door: the settled-row refusal, then the charge, then the head predicate.
    let mut mem = InMemoryIntentLog::new();

    // IN BUDGET: charged, nothing terminalized.
    record_basis(&mut mem, &archive_cmd("k-budget")).expect("admit");
    assert_eq!(
        mem.charge_and_dead_letter_if_quiescent("k-budget", 2)
            .expect("the door"),
        TransientCharge::ChargedOnly
    );
    assert_eq!(mem.get("k-budget").expect("get").expect("row").attempts, 1);
    // EXHAUSTED AND QUIESCENT: no attempt was ever claimed, so the counter's attribution is
    // honest and the dead-letter is this caller's to write — the property the retry cap IS.
    assert_eq!(
        mem.charge_and_dead_letter_if_quiescent("k-budget", 2)
            .expect("the door"),
        TransientCharge::ChargedAndDeadLettered
    );
    let row = mem.get("k-budget").expect("get").expect("row");
    assert_eq!((row.attempts, row.status), (2, IntentStatus::Failed));
    // A SETTLED row has no budget left to spend: nothing is charged and nothing is written,
    // and the refusal NAMES what the row holds — including for a row that does not exist.
    assert_eq!(
        mem.charge_and_dead_letter_if_quiescent("k-budget", 2)
            .expect("the door"),
        TransientCharge::ChargeRefusedTerminal(Some(IntentStatus::Failed))
    );
    assert_eq!(
        mem.get("k-budget").expect("get").expect("row").attempts,
        2,
        "…the counter did not move under the refusal"
    );
    assert_eq!(
        mem.charge_and_dead_letter_if_quiescent("k-absent", 2)
            .expect("the door"),
        TransientCharge::ChargeRefusedTerminal(None)
    );

    // EXHAUSTED WITH A PEER'S LIVE ATTEMPT: the charge LANDS (a transient failure under a
    // peer's dispatch is not free, or the budget would never exhaust) and the terminal does
    // NOT — a dead-letter here would claim proof of no-effect over an attempt that is still
    // authorizable.
    record_basis(&mut mem, &archive_of("k-live", "msg-live")).expect("admit");
    assert!(
        matches!(
            mem.claim_attempt(
                "k-live",
                &AttemptClaim {
                    ordinal: 1,
                    predecessor: None,
                    observed_attempts: 0,
                },
            )
            .expect("claim"),
            ClaimOutcome::Won { .. }
        ),
        "precondition: a peer holds this operation's dispatch"
    );
    assert_eq!(
        mem.charge_and_dead_letter_if_quiescent("k-live", 1)
            .expect("the door"),
        TransientCharge::ChargedOnly
    );
    let row = mem.get("k-live").expect("get").expect("row");
    assert_eq!(
        (row.attempts, row.status),
        (1, IntentStatus::Pending),
        "the budget was spent and the operation is still the peer's"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════
// RETRY LINEAGE + RETRY-REQUALIFICATION (design §5.2a,
// §3.2's table under its RETRY reading)
// ═══════════════════════════════════════════════════════════════════════════════════

/// The ordinals of every CLAIM an operation holds, in order.
fn ordinals_of(path: &std::path::Path, key: &str) -> Vec<i64> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT attempt_ordinal FROM attempt_fact
                  WHERE operation_id = (SELECT intent_id FROM intents WHERE idempotency_key = ?1)
                    AND fact_kind = 'claim' ORDER BY attempt_ordinal;",
        )
        .expect("prepare");
    let out = stmt
        .query_map(rusqlite::params![key], |r| r.get::<_, i64>(0))
        .expect("query")
        .map(|o| o.expect("row"))
        .collect();
    out
}

/// The attempt id an operation claimed at a given ordinal.
fn attempt_at_ordinal(path: &std::path::Path, key: &str, ordinal: i64) -> String {
    raw_conn(path)
        .query_row(
            "SELECT attempt_id FROM attempt_fact
                  WHERE operation_id = (SELECT intent_id FROM intents WHERE idempotency_key = ?1)
                    AND fact_kind = 'claim' AND attempt_ordinal = ?2;",
            rusqlite::params![key, ordinal],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("no claim at ordinal {ordinal} for '{key}': {e}"))
}

/// The predecessor attempt id a CLAIM payload names (`None` on ordinal 1).
fn predecessor_of(path: &std::path::Path, attempt_id: &str) -> Option<String> {
    raw_conn(path)
        .query_row(
            "SELECT json_extract(payload, '$.predecessor_attempt_id') FROM attempt_fact
                  WHERE attempt_id = ?1 AND fact_kind = 'claim';",
            rusqlite::params![attempt_id],
            |r| r.get(0),
        )
        .expect("the attempt holds a CLAIM")
}

fn pre_state_count(path: &std::path::Path) -> i64 {
    raw_conn(path)
        .query_row("SELECT COUNT(*) FROM pre_state;", [], |r| r.get(0))
        .expect("count rows")
}

#[test]
fn w_retry_lineage_refuses_an_ordinal_above_one_without_its_mandatory_predecessor() {
    // ATTEMPT-ORDINAL/RETRY-TOTALITY (§5.2a): "ordinal 1 carries NO predecessor; every
    // ordinal > 1 carries exactly one (predecessor_attempt_id, reason) in its CLAIM
    // payload — mandatory, atomic with the claim". At the STORE door: a caller naming an
    // ordinal the operation has not reached is minted VERBATIM, so the grammar is what
    // judges it — and it refuses, rather than inventing a lineage nobody asserted.
    let path = unique_temp_db_path("t9-lineage-missing-predecessor");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-lin-1");

    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    let outcome = log
        .claim_attempt(
            "k-lin-1",
            &AttemptClaim {
                ordinal: 2,
                predecessor: None,
                observed_attempts: 1,
            },
        )
        .expect("the door answers");
    assert!(
        matches!(
            outcome,
            ClaimOutcome::RefusedByGrammar(
                crate::attempt::GrammarRefusal::RetryOrdinalMissingPredecessor { ordinal: 2 }
            )
        ),
        "a retry ordinal with no predecessor is refused by the CLOSED grammar; got {outcome:?}"
    );
    assert_eq!(
        ordinals_of(&path, "k-lin-1"),
        vec![1],
        "…and nothing was appended"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_retry_lineage_the_store_can_never_hold_two_claims_at_one_ordinal() {
    // `UNIQUE (operation_id, attempt_ordinal)` is the MECHANICAL arbiter §5.2a names, and
    // the door reads it back rather than hand-rolling an error.
    //
    // HONEST SCOPE, stated rather than implied: the door cannot be MADE to hit this
    // constraint from outside, because its read of the operation's highest ordinal and its
    // INSERT are one IMMEDIATE transaction — no writer can interleave between them. So the
    // arm has TWO halves, and both are asserted: (a) the constraint itself refuses a
    // duplicate (the arbiter exists and is load-bearing — proved by a direct write, the
    // same discipline the append-only trigger witnesses use), and (b) the DOOR, asked
    // twice for the same ordinal, re-enters or succeeds the existing attempt instead of
    // minting a second claim at it.
    let path = unique_temp_db_path("t9-lineage-duplicate-ordinal");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-lin-2");
    let owner = opaque_intent_id(&path, "k-lin-2");

    // (a) THE ARBITER.
    let duplicate = raw_conn(&path).execute(
        "INSERT INTO attempt_fact (operation_id, attempt_id, revision, fact_kind,
                                       attempt_ordinal, basis_epoch, created_at, payload,
                                       prior_revision)
             VALUES (?1, 'forged-attempt', 1, 'claim', 1, 1, '2026-01-01T00:00:00Z',
                     '{\"ordinal\":1}', NULL);",
        rusqlite::params![owner],
    );
    assert!(
        duplicate.is_err(),
        "UNIQUE (operation_id, attempt_ordinal) must refuse a second CLAIM at ordinal 1"
    );

    // (b) THE DOOR, asked for an ordinal the operation already holds.
    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    let outcome = log
        .claim_attempt(
            "k-lin-2",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 1,
            },
        )
        .expect("the door answers");
    assert!(
        matches!(&outcome, ClaimOutcome::Won { ordinal, .. } if *ordinal == 2),
        "the door derives the SUCCESSOR from the chain — it never mints a second claim at \
         an ordinal the operation already holds; got {outcome:?}"
    );
    assert_eq!(ordinals_of(&path, "k-lin-2"), vec![1, 2]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_retry_lineage_refuses_a_skipped_ordinal() {
    // "successor ordinal = predecessor ordinal + 1" (§5.2a). The store door hands the
    // caller's own lineage to the ONE cross-attempt predicate when the caller names an
    // ordinal past the operation's head, and a gap in the sequence is refused.
    let path = unique_temp_db_path("t9-lineage-skipped-ordinal");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-lin-3");
    let first = attempt_at_ordinal(&path, "k-lin-3", 1);

    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    let outcome = log
        .claim_attempt(
            "k-lin-3",
            &AttemptClaim {
                ordinal: 3,
                predecessor: Some(crate::attempt::RetryPredecessor {
                    attempt_id: first,
                    reason: crate::attempt::RetryReason::FailedPreSend,
                }),
                observed_attempts: 1,
            },
        )
        .expect("the door answers");
    assert!(
        matches!(
            outcome,
            ClaimOutcome::RefusedByGrammar(
                crate::attempt::GrammarRefusal::OrdinalNotPredecessorPlusOne {
                    predecessor_ordinal: 1,
                    offered: 3
                }
            )
        ),
        "ordinal 3 behind an ordinal-1 predecessor is a SKIPPED ordinal; got {outcome:?}"
    );
    assert_eq!(ordinals_of(&path, "k-lin-3"), vec![1]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_malformed_predecessor_is_corruption_not_an_unclaimed_attempt() {
    // ═══ ═══ The cross-attempt lineage check used to read its
    // predecessor as `fold_stored_attempt(..).unwrap_or_else(|_| DerivedState::empty())`,
    // and the empty state is what the grammar names `PredecessorUnclaimed`. So EVERY way
    // that read could fail — a chain that does not fold, an `attempt_head` that disagrees
    // with its own chain, an unreadable payload — arrived at the caller as a ROUTINE
    // grammar refusal, indistinguishable from "you named an attempt that does not exist".
    // Durable corruption presented as an ordinary "no", and the driver's honest response to
    // an ordinary no is to try something else.
    //
    // The head/fold-divergence class already has a rule everywhere ELSE in this build
    // (the boot chokepoint refuses the open; `fold_stored_attempt`'s own probe is a
    // `LogError`); this one door swallowed it. Only an attempt that is ACTUALLY ABSENT is
    // unclaimed — the fence below pins that half.
    let path = unique_temp_db_path("t9-lineage-corrupt-predecessor");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let first = admit_and_claim(&mut log, &archive_of("k-lin-corrupt", "msg-1"));
    // CRAFT: the corruption lands under the ALREADY-OPEN engine, because that is the only
    // shape this door can meet — a reopen would be refused by the boot quarantine, which is
    // the very asymmetry the finding is about.
    let bumped = raw_conn(&path)
        .execute(
            "UPDATE attempt_head SET current_revision = current_revision + 1
                  WHERE attempt_id = ?1;",
            rusqlite::params![first],
        )
        .expect("the head row is writable — nothing in the schema stops this");
    assert_eq!(
        bumped, 1,
        "the premise: the predecessor's projection now disagrees with its chain"
    );

    // Ordinal 2 with an EXPLICIT lineage: the door's own head lookup is skipped (the
    // caller named an ordinal past the operation's head), so the ONLY read of the
    // predecessor is the cross-attempt one.
    let outcome = log.claim_attempt(
        "k-lin-corrupt",
        &AttemptClaim {
            ordinal: 2,
            predecessor: Some(crate::attempt::RetryPredecessor {
                attempt_id: first.clone(),
                reason: crate::attempt::RetryReason::FailedPreSend,
            }),
            observed_attempts: 0,
        },
    );

    let error = match outcome {
        Ok(other) => panic!(
            "a predecessor whose projection diverges from its chain is DURABLE CORRUPTION \
             — it must fail loud, not answer a routine refusal; got {other:?}"
        ),
        Err(e) => e.0,
    };
    assert!(
        error.contains(&first) && error.contains("diverges from its chain"),
        "the refusal must name the attempt and the divergence, got: {error}"
    );
    assert_eq!(
        ordinals_of(&path, "k-lin-corrupt"),
        vec![1],
        "…and nothing was appended: the door's transaction dropped uncommitted"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_absent_predecessor_is_still_the_ordinary_unclaimed_refusal() {
    // THE OTHER HALF of, and the over-refusal fence: making corruption loud must
    // not make an ABSENT predecessor loud too. An attempt id nobody ever claimed has no
    // chain AND no head row — it does not exist, and the grammar's own honest word for a
    // lineage that names it is `PredecessorUnclaimed`. That stays a routine refusal.
    let path = unique_temp_db_path("t9-lineage-absent-predecessor");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    admit_and_claim(&mut log, &archive_of("k-lin-absent", "msg-1"));

    let outcome = log
        .claim_attempt(
            "k-lin-absent",
            &AttemptClaim {
                ordinal: 2,
                predecessor: Some(crate::attempt::RetryPredecessor {
                    attempt_id: "attempt-that-was-never-claimed".into(),
                    reason: crate::attempt::RetryReason::FailedPreSend,
                }),
                observed_attempts: 0,
            },
        )
        .expect("an absent predecessor is a REFUSAL, never a store error");

    assert!(
        matches!(
            outcome,
            ClaimOutcome::RefusedByGrammar(
                crate::attempt::GrammarRefusal::PredecessorUnclaimed
            )
        ),
        "an attempt that does not exist is UNCLAIMED — the grammar's own answer; got \
         {outcome:?}"
    );
    assert_eq!(ordinals_of(&path, "k-lin-absent"), vec![1]);
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_retry_lineage_a_predecessor_never_gains_a_second_successor() {
    // "the predecessor … has no other retry successor" (§5.2a). At the STORE door this is
    // structural rather than merely checked: the door DERIVES the successor from the
    // operation's own chain head, so a caller asking for a second successor of an
    // already-succeeded attempt gets the chain's next ordinal — never a fork.
    let path = unique_temp_db_path("t9-lineage-two-successors");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(2);
    park_in_the_retry_gap(&mut bus, "k-lin-4");
    bus.recover().expect("the first retry sweep");
    assert_eq!(ordinals_of(&path, "k-lin-4"), vec![1, 2], "attempt 2 exists");
    let first = attempt_at_ordinal(&path, "k-lin-4", 1);
    let second = attempt_at_ordinal(&path, "k-lin-4", 2);
    assert_eq!(
        predecessor_of(&path, &second),
        Some(first.clone()),
        "attempt 2's mandatory lineage names attempt 1"
    );

    // Ask, explicitly, for a SECOND successor of attempt 1.
    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    let outcome = log
        .claim_attempt(
            "k-lin-4",
            &AttemptClaim {
                ordinal: 2,
                predecessor: Some(crate::attempt::RetryPredecessor {
                    attempt_id: first.clone(),
                    reason: crate::attempt::RetryReason::FailedPreSend,
                }),
                observed_attempts: 2,
            },
        )
        .expect("the door answers");
    assert!(
        matches!(&outcome, ClaimOutcome::Won { ordinal, .. } if *ordinal == 3),
        "the door succeeds the CHAIN HEAD, not the caller's chosen predecessor; got \
         {outcome:?}"
    );
    let third = attempt_at_ordinal(&path, "k-lin-4", 3);
    assert_eq!(
        predecessor_of(&path, &third),
        Some(second),
        "attempt 3 succeeds attempt 2 — attempt 1 keeps its ONE successor"
    );
    let successors: i64 = raw_conn(&path)
        .query_row(
            "SELECT COUNT(*) FROM attempt_fact WHERE fact_kind = 'claim'
                   AND json_extract(payload, '$.predecessor_attempt_id') = ?1;",
            rusqlite::params![first],
            |r| r.get(0),
        )
        .expect("count successors");
    assert_eq!(successors, 1, "a predecessor has AT MOST ONE retry successor");
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_retry_lineage_a_deterministic_predecessor_yields_no_retry_claim() {
    // Retry eligibility requires "the predecessor's failure be TRANSIENT under the
    // engine's existing `FailureKind` taxonomy" (§5.2a; ADR-P013 (b): a deterministic
    // refusal dead-letters). There is no second taxonomy for this: the DETERMINISTIC
    // verdict dead-letters the OPERATION in the settling transaction, so the claim door's
    // first compare already refuses — and the sweep never reaches a wire.
    let path = unique_temp_db_path("t9-lineage-deterministic-predecessor");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply_with(
        ConnectorError::deterministic("the provider refused it outright").proven_no_wire(),
        1,
    );
    let outcome = bus.execute(&archive_cmd("k-lin-5"));
    assert!(matches!(outcome, Err(ExecuteError::Connector(_))));
    assert_eq!(status_str(&path, "k-lin-5"), "failed", "dead-lettered at once");

    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    let claim = log
        .claim_attempt(
            "k-lin-5",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("the door answers");
    assert_eq!(
        claim,
        ClaimOutcome::AlreadyClaimed,
        "no retry claim is minted behind a deterministic terminal"
    );
    bus.recover().expect("the sweep");
    assert_eq!(
        ordinals_of(&path, "k-lin-5"),
        vec![1],
        "the operation holds exactly the one attempt that failed deterministically"
    );
    assert_eq!(wire.wire().apply_count(), 0, "and nothing reached the wire");
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_capture_head_retry_proceeds_on_the_existing_row_when_the_provider_still_matches_p() {
    // §3.2 under the RETRY reading, branch `C == P` (§5.2a): "the existing
    // capture is still truthful — proceed on the existing row". The journal row is NOT
    // re-captured (§2.2's never-re-capture rule holds), and the retry dispatches.
    let path = unique_temp_db_path("t9-requalify-c-equals-p");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-p");
    let before = journal_row_of(&path, "k-req-p");

    // The provider has NOT moved: C == P == {INBOX: true}.
    let report = bus.recover().expect("the retry sweep");

    assert_eq!(report.recovered, 1, "the retry completed");
    assert_eq!(wire.wire().apply_count(), 1, "…on the wire, exactly once");
    assert_eq!(
        journal_row_of(&path, "k-req-p"),
        before,
        "NO journal REPLACE: `C == P` proceeds on the existing row"
    );
    assert_eq!(pre_state_count(&path), 1, "one row, still one row");
    assert_eq!(status_str(&path, "k-req-p"), "applied");
    assert_eq!(ordinals_of(&path, "k-req-p"), vec![1, 2]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_capture_head_retry_closes_externally_satisfied_when_the_target_already_holds() {
    // §5.2a, the whole named class: `SetFlag(true)` capturing `false`,
    // failing at connect, ANOTHER CLIENT setting `true`, and the retry no-opping — after
    // which undo would restore a stale `false` over the other actor's change.
    //
    // `C == A` ⇒ the target ALREADY HOLDS ⇒ the ATTEMPT closes `FAILED_PRE_SEND` with the
    // deterministic reason `externally-satisfied` (proven-no-wire BY CONSTRUCTION — the
    // gate runs before the send-auth, so nothing was dispatched) and the SAME transaction
    // transitions the OPERATION to the P013 terminal `EXTERNALLY_SATISFIED`.
    let path = unique_temp_db_path("t9-requalify-c-equals-a");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-a");

    // ANOTHER ACTOR produced the forward target between the attempts.
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    bus.recover().expect("the retry sweep");

    assert_eq!(
        wire.wire().apply_count(),
        0,
        "nothing reached the wire: the objective already held"
    );
    assert_eq!(
        status_str(&path, "k-req-a"),
        "externally_satisfied",
        "the OPERATION's P013 terminal"
    );
    let second = attempt_at_ordinal(&path, "k-req-a", 2);
    assert_eq!(
        chain_kinds(&path, &second),
        vec!["claim", "failed_pre_send"],
        "the ATTEMPT closes proven-no-wire, never send-authorized"
    );
    let reason: String = raw_conn(&path)
        .query_row(
            "SELECT json_extract(payload, '$.reason') FROM attempt_fact
                  WHERE attempt_id = ?1 AND fact_kind = 'failed_pre_send';",
            rusqlite::params![second],
            |r| r.get(0),
        )
        .expect("the verdict fact carries its reason");
    assert_eq!(
        reason, "externally_satisfied",
        "the deterministic reason the design names, recorded rather than inferred"
    );
    assert_eq!(
        pre_state_count(&path),
        1,
        "the journal row is RETAINED for audit (codex r36 P1) — it simply can never \
         offer a restore"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_externally_satisfied_operation_is_undo_ineligible_replays_err_and_never_re_dispatches() {
    // The three consequences §5.2a attaches to the terminal, all at once:
    // undo-INELIGIBLE with the honest reason (§4.5 gate) · identical-fingerprint replay ⇒
    // the truthful `Err`-class outcome, never a silent `Ok` and never a re-dispatch ·
    // recovery reads the STATUS, so a crash can never mistake it for an ordinary `Applied`
    // carrying a stale `P`.
    let path = unique_temp_db_path("t9-externally-satisfied-consequences");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-x");
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    bus.recover().expect("the retry sweep");
    assert_eq!(status_str(&path, "k-req-x"), "externally_satisfied");

    let undo = bus.undo("k-req-x");
    assert!(
        matches!(
            undo,
            Err(ExecuteError::UndoUnavailable(
                prestate::UndoUnavailableReason::ExternallySatisfied
            ))
        ),
        "a stale captured P must never reverse the other actor's change; got {undo:?}"
    );
    let replay = bus.execute(&archive_cmd("k-req-x"));
    assert!(
        matches!(replay, Err(ExecuteError::ExternallySatisfied)),
        "an identical-fingerprint replay returns the truthful Err class; got {replay:?}"
    );
    let report = bus.recover().expect("a later sweep");
    assert_eq!(report.recovered, 0);
    assert_eq!(wire.wire().apply_count(), 0, "recovery never re-dispatches it");
    assert_eq!(
        bus.undo_presentation("k-req-x").expect("presentation").map(|r| r.presentation),
        Some(UndoPresentation::ExternallySatisfied),
        "the presentation projection surfaces it distinctly — never conflated with a \
         provider failure and never a bare 'nothing to say'"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_capture_head_retry_re_prepares_through_the_one_versioned_journal_replace() {
    // "any other divergence ⇒ RE-PREPARE with a fresh capture via the ONE narrow exception
    // to §2.2b's insert-or-nothing PREPARE: a VERSIONED atomic REPLACE of
    // the journal row". The JMAP-shaped PAIR is what makes the third state reachable
    // (§3.1a): an external client can leave the message in BOTH mailboxes.
    let path = unique_temp_db_path("t9-requalify-re-prepare");
    let wire = SharedWire::new(UndoStageConnector::pair(true, false));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-d");
    let (old_id, old_observed, _) = journal_row_of(&path, "k-req-d");
    assert!(
        old_observed.contains("\"membership:mb-a\":false"),
        "the ORIGINAL capture: not yet in the archive mailbox — got {old_observed}"
    );

    // A third state: neither `P` nor `A` — the message is now in BOTH mailboxes.
    wire.wire().set_state(atoms(&[
        ("membership:mb-i", true),
        ("membership:mb-a", true),
    ]));
    bus.recover().expect("the retry sweep");

    let (new_id, new_observed, new_touched) = journal_row_of(&path, "k-req-d");
    assert_eq!(pre_state_count(&path), 1, "exactly one row — the OLD one is GONE");
    assert_ne!(new_id, old_id, "a REPLACE, not an update in place");
    assert_eq!(
        new_observed, new_touched,
        "the new row's two projections agree (JournalRow::validate's own rule)"
    );
    assert!(
        new_observed.contains("\"membership:mb-a\":true"),
        "the new row carries the FRESH capture — got {new_observed}"
    );
    let generation: i64 = raw_conn(&path)
        .query_row(
            "SELECT p.capture_generation FROM pre_state p JOIN intents i
                   ON i.intent_id = p.intent_id WHERE i.idempotency_key = 'k-req-d';",
            [],
            |r| r.get(0),
        )
        .expect("the row is versioned");
    assert_eq!(generation, 2, "the REPLACE is VERSIONED");
    assert_eq!(status_str(&path, "k-req-d"), "applied");
    assert_eq!(wire.wire().apply_count(), 1, "…and the retry then dispatched");
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_capture_head_a_failed_journal_replace_leaves_the_old_row_complete_never_a_blend() {
    // "executed in one writer transaction so a crash leaves either the old or the new
    // complete row, never a blend" (§5.2a).
    //
    // WHICH TECHNIQUE: a MID-TRANSACTION ERROR INJECTION, not a process kill — a
    // `BEFORE INSERT` trigger on `pre_state` aborts the INSERT half AFTER the DELETE half
    // has already run inside the same transaction. That is precisely the interior state a
    // crash would freeze, and SQLite's atomicity is what has to make it invisible. (A real
    // power cut is out of reach here and is the design's own named conditional residual.)
    let path = unique_temp_db_path("t9-replace-crash-atomicity");
    let wire = SharedWire::new(UndoStageConnector::pair(true, false));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-crash");
    let before = journal_row_of(&path, "k-req-crash");

    raw_conn(&path)
        .execute_batch(
            "CREATE TRIGGER t9_replace_failpoint BEFORE INSERT ON pre_state
                   BEGIN SELECT RAISE(ABORT, 'failpoint: the writer died mid-replace'); END;",
        )
        .expect("arm the failpoint");

    let fresh = crate::prestate::JournalRow {
        observed: r#"{"membership:mb-a":true,"membership:mb-i":true}"#.into(),
        touched_atom: r#"{"membership:mb-a":true,"membership:mb-i":true}"#.into(),
        resolved_operands: r#"{"membership:mb-a":"mb-a","membership:mb-i":"mb-i"}"#.into(),
        request_id: None,
        observed_label_vector: None,
    };
    let mut log = SqliteIntentLog::open(&path).expect("the replacing driver");
    let outcome = log.replace_journal_row("k-req-crash", &fresh);
    assert!(
        outcome.is_err(),
        "the injected failure must surface, never be absorbed; got {outcome:?}"
    );

    raw_conn(&path)
        .execute_batch("DROP TRIGGER t9_replace_failpoint;")
        .expect("disarm");
    assert_eq!(pre_state_count(&path), 1, "OLD-or-NEW — never zero rows");
    assert_eq!(
        journal_row_of(&path, "k-req-crash"),
        before,
        "the OLD row is COMPLETE and untouched — never a blend"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_capture_head_a_capture_off_retry_re_verifies_the_basis_and_mints_no_row() {
    // "Capture-OFF operations (`journal_required=0`) have no `P`, no row, and no undo —
    // their retry path verifies ONLY the frozen native basis (BASIS-6) and re-dispatches
    // (the requalification algorithm must not force a row §2.2b forbids)."
    let path = unique_temp_db_path("t9-requalify-capture-off");
    SqliteIntentLog::open(&path).expect("bootstrap the store + its generation-1 act");
    append_config_act(&path, r#"{"capture":"off"}"#);
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-off");
    assert_eq!(
        wire.wire().observe_count(),
        0,
        "capture-off never observed on the first pass"
    );

    bus.recover().expect("the retry sweep");

    assert_eq!(
        wire.wire().observe_count(),
        1,
        "the RETRY re-verifies the frozen native basis — the BASIS-6 read, and only that"
    );
    assert_eq!(pre_state_count(&path), 0, "and mints NO row (§2.2b forbids one)");
    assert_eq!(wire.wire().apply_count(), 1, "…then re-dispatches");
    assert_eq!(status_str(&path, "k-req-off"), "applied");
    assert_eq!(ordinals_of(&path, "k-req-off"), vec![1, 2]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_retry_claim_after_a_sever_never_reaches_the_wire() {
    // Retry eligibility ADDITIONALLY requires "the attempt's claim epoch equal to the
    // CURRENT `control_epoch`" (§5.2a). The `sever` is what makes the
    // condition real: an operation sitting in its retry gap is an `OperationMember` with
    // NO_ACTIVE_ATTEMPT, so the sever transaction terminalizes it — and the next sweep's
    // claim finds a settled operation instead of a retry.
    let path = unique_temp_db_path("t9-retry-after-sever");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(1);
    park_in_the_retry_gap(&mut bus, "k-req-sev");

    sever_from_control_plane(&path, "authority:test-operator");

    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    let claim = log
        .claim_attempt(
            "k-req-sev",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 1,
            },
        )
        .expect("the door answers");
    assert_eq!(
        claim,
        ClaimOutcome::AlreadyClaimed,
        "no retry claim behind a sever"
    );
    bus.recover().expect("the sweep");
    assert_eq!(wire.wire().apply_count(), 0, "nothing reached the wire");
    assert_eq!(status_str(&path, "k-req-sev"), "severed");
    assert_eq!(ordinals_of(&path, "k-req-sev"), vec![1]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn retry_lineage_still_dead_letters_on_the_existing_transient_budget() {
    // "the durable retry budget (`RETRY_CAP`) un-exhausted" (§5.2a). The fact chain records
    // lineage; `intents.attempts` stays the BUDGET authority (the plan's own scope fence),
    // and exhaustion still dead-letters through the existing charge path.
    let path = unique_temp_db_path("t9-retry-budget");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply(u32::MAX);
    park_in_the_retry_gap(&mut bus, "k-req-cap");
    for _ in 0..(RETRY_CAP - 1) {
        bus.recover().expect("a retry sweep");
    }
    assert_eq!(
        status_str(&path, "k-req-cap"),
        "failed",
        "budget exhaustion dead-letters, exactly as it always did"
    );
    assert_eq!(
        ordinals_of(&path, "k-req-cap"),
        (1..=i64::from(RETRY_CAP)).collect::<Vec<_>>(),
        "every retry was a FRESH attempt with its own claim — one ordinal per charge"
    );
    assert_eq!(wire.wire().apply_count(), 0);
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// The truthful dual-accounting relation. `intents.attempts` (the
// transient-retry BUDGET authority) and the `attempt_fact` claim chain (LINEAGE /
// attribution) are two accountings of overlapping information, never one. `FailureKind`
// is not recorded in the fact grammar, so it can never be re-derived from facts — and an
// ordinal-1 CLAIM carries no predecessor by construction, so predecessor-count equals
// attempts only in the narrow history where every charge was transient-with-retry. The v1
// equality (`attempts == predecessor-count`, general) is refuted by execution (5 ≠ 4)
// and is never asserted here, in any form.
// ═══════════════════════════════════════════════════════════════════════════════════

/// The truthful relation between the two accountings, driven through the REAL bus/connector
/// path with a HERMETIC double (`SharedWire` over `UndoStageConnector::fail_apply`, which
/// injects exactly `FailureKind::Transient` — `apply`'s doc: "the retryable class") so the
/// harness itself knows every charge it caused. Three stages, one relation each:
///
/// - **0 transient failures:** a clean first apply. `attempts == 0`, one claim (ordinal 1,
///   no predecessor) — the counter never moves when nothing was ever charged.
/// - **1 transient failure:** `attempts == 1`, two claims (ordinal 1 → no predecessor;
///   ordinal 2 → predecessor = ordinal 1's attempt id).
/// - **`RETRY_CAP` transient failures (every charge transient-with-retry, exhausting the
///   budget):** `attempts == RETRY_CAP`, ordinals `1..=RETRY_CAP`, each ordinal `>1` naming
///   its immediate predecessor. Only in THIS specific history is `predecessor-count ==
///   attempts − 1` — asserted below as a property of this history's own shape (the ordinal
///   chain), never as a general reconciliation between the fact chain and the counter.
///
/// **THE RESIDUAL, STATED HERE AND ON `intents.attempts`'s DDL comment and on
/// [`IntentLog::charge_and_dead_letter_if_quiescent`]'s doc:** the two accountings are NOT
/// equivalent and cannot be reconciled from facts alone — `FailureKind` lives outside the
/// fact grammar entirely (a claim fact records that a retry happened and what it followed,
/// never WHY the predecessor failed), so no query over `attempt_fact` can recover "how many
/// of these charges were transient" without the counter. The counter REMAINS the budget
/// authority. A future consolidation (fact-level retry-charge recording, so the counter
/// could be derived rather than independently written) is design-gate work, deliberately
/// not smuggled in here.
#[test]
fn attempts_counter_matches_transient_charges_in_hermetic_histories() {
    // ── Stage 0: zero transient failures — attempts must stay at zero. ──
    {
        let path = unique_temp_db_path("t10-dual-0");
        let wire = SharedWire::new(UndoStageConnector::single(false, true));
        let mut bus =
            CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
        bus.execute(&archive_cmd("k-dual-0"))
            .expect("the clean forward apply — the harness injected no failures");
        assert_eq!(
            attempts_of(&path, "k-dual-0"),
            0,
            "the harness charged zero transient failures — the counter must agree"
        );
        assert_eq!(ordinals_of(&path, "k-dual-0"), vec![1]);
        let only = attempt_at_ordinal(&path, "k-dual-0", 1);
        assert_eq!(
            predecessor_of(&path, &only),
            None,
            "ordinal 1 carries no predecessor"
        );
        std::fs::remove_file(&path).ok();
    }

    // ── Stage 1: exactly one transient failure, then a retry that lands. ──
    {
        let path = unique_temp_db_path("t10-dual-1");
        let wire = SharedWire::new(UndoStageConnector::single(false, true));
        let mut bus =
            CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
        wire.wire().fail_apply(1);
        park_in_the_retry_gap(&mut bus, "k-dual-1");
        let report = bus.recover().expect("the retry sweep lands");
        assert_eq!(report.recovered, 1);
        assert_eq!(
            attempts_of(&path, "k-dual-1"),
            1,
            "the harness charged exactly one transient failure — the counter must agree"
        );
        assert_eq!(ordinals_of(&path, "k-dual-1"), vec![1, 2]);
        let first = attempt_at_ordinal(&path, "k-dual-1", 1);
        let second = attempt_at_ordinal(&path, "k-dual-1", 2);
        assert_eq!(
            predecessor_of(&path, &first),
            None,
            "ordinal 1 carries no predecessor"
        );
        assert_eq!(
            predecessor_of(&path, &second),
            Some(first),
            "ordinal 2 names ordinal 1 as its predecessor"
        );
        assert_eq!(status_str(&path, "k-dual-1"), "applied");
        std::fs::remove_file(&path).ok();
    }

    // ── Stage RETRY_CAP: every charge transient-with-retry, exhausting the budget. ──
    {
        let path = unique_temp_db_path("t10-dual-cap");
        let wire = SharedWire::new(UndoStageConnector::single(false, true));
        let mut bus =
            CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
        wire.wire().fail_apply(u32::MAX);
        park_in_the_retry_gap(&mut bus, "k-dual-cap");
        for _ in 0..(RETRY_CAP - 1) {
            bus.recover().expect("a retry sweep");
        }
        assert_eq!(
            status_str(&path, "k-dual-cap"),
            "failed",
            "budget exhaustion dead-letters"
        );
        assert_eq!(
            attempts_of(&path, "k-dual-cap"),
            i64::from(RETRY_CAP),
            "the harness charged exactly RETRY_CAP transient failures — the counter must \
             agree"
        );
        let ordinals = ordinals_of(&path, "k-dual-cap");
        assert_eq!(
            ordinals,
            (1..=i64::from(RETRY_CAP)).collect::<Vec<_>>(),
            "one ordinal per charge — every retry was a fresh claim"
        );
        // ⛔ THE HONEST FORM: assert the ordinal/predecessor SHAPE directly — never
        // `attempts == predecessor-count` as a general relation (the v1 equality,
        // refuted by execution: that arithmetic left 5 ≠ 4 standing).
        for &ordinal in &ordinals {
            let id = attempt_at_ordinal(&path, "k-dual-cap", ordinal);
            let predecessor = predecessor_of(&path, &id);
            if ordinal == 1 {
                assert_eq!(predecessor, None, "ordinal 1 carries no predecessor");
            } else {
                let expected = attempt_at_ordinal(&path, "k-dual-cap", ordinal - 1);
                assert_eq!(
                    predecessor,
                    Some(expected),
                    "ordinal {ordinal} names its immediate predecessor"
                );
            }
        }
        // Named ONLY as a property of THIS history (every charge transient-with-retry) —
        // never generalized to a claim that the two accountings reconcile.
        let predecessor_count = ordinals.iter().filter(|&&o| o > 1).count() as i64;
        assert_eq!(
            predecessor_count,
            attempts_of(&path, "k-dual-cap") - 1,
            "in THIS history (every charge transient-with-retry) predecessor-count == \
             attempts − 1 — a property of this specific all-transient-with-retry history, \
             never a general relation between the fact chain and the counter"
        );
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn one_attempt_is_authorized_exactly_once_however_the_operations_counter_moves() {
    // ═══ THE EPISODE-STAGING DELETION WITNESS ═══
    // An earlier version shipped a `dispatch_episode` field so a re-entered attempt could be
    // authorized AGAIN at a LATER episode — staging, explicitly, "until a retry becomes a
    // NEW attempt". With real lineage that day is here: every retry claims its own
    // attempt, so §5.2a's rule is the strict one again — AT MOST ONE `SEND_AUTHORIZED`
    // per attempt, full stop, whatever the operation's durable counter says.
    //
    // The counter is advanced BY HAND in both arms precisely because no production path can
    // now produce these shapes: an authorized-unacked attempt IS ISSUANCE_UNKNOWN and must
    // never be re-authorized, and a SETTLED attempt is settled. This is the probe a
    // re-introduced episode escape hatch would fail — and on pre-task bytes it failed
    // twice over, the hatch authorizing even an attempt that had already ACKED APPLIED.
    let path = unique_temp_db_path("t9-episode-deleted");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-ep")).expect("the forward applies");
    let settled = attempt_at_ordinal(&path, "k-ep", 1);
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'pending', attempts = attempts + 3
                  WHERE idempotency_key = 'k-ep';",
            [],
        )
        .expect("an ADVANCED episode over a SETTLED attempt");

    let mut log = SqliteIntentLog::open(&path).expect("a second driver");
    // ARM 1 — a SETTLED attempt. The grammar's post-terminal rule answers, which it never
    // got the chance to do while the episode branch returned above it.
    let outcome = authorize(&mut log, "k-ep", &settled).expect("the door answers");
    assert!(
        matches!(
            outcome,
            SendAuthOutcome::RefusedByGrammar(
                crate::attempt::GrammarRefusal::PostTerminalAppend { .. }
            )
        ),
        "an advanced counter must not re-authorize a SETTLED attempt; got {outcome:?}"
    );
    assert_eq!(send_authorized_count(&path, &settled), 1);

    // ARM 2 — the shape §5.2a's rule is actually about: an attempt that is authorized and
    // UNACKED (ISSUANCE_UNKNOWN), under an operation whose counter has since moved. Built
    // through the store doors, because that is the only honest way to hold one.
    let mut log = SqliteIntentLog::open(&path).expect("the admitting driver");
    let cmd = Command::new(
        "k-ep-2",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-2".into(),
        },
    );
    admit(&mut log, &cmd);
    let live = claim_now(&mut log, "k-ep-2", 0);
    assert!(matches!(
        authorize(&mut log, "k-ep-2", &live).expect("the door answers"),
        SendAuthOutcome::Authorized { .. }
    ));
    raw_conn(&path)
        .execute(
            "UPDATE intents SET attempts = attempts + 2 WHERE idempotency_key = 'k-ep-2';",
            [],
        )
        .expect("the episode advances under an authorized-unacked attempt");
    let outcome = authorize(&mut log, "k-ep-2", &live).expect("the door answers");
    assert!(
        matches!(
            outcome,
            SendAuthOutcome::RefusedByGrammar(
                crate::attempt::GrammarRefusal::DuplicateSendAuthorized
            )
        ),
        "one attempt, one authorization — the episode is not an escape hatch; got \
         {outcome:?}"
    );
    assert_eq!(send_authorized_count(&path, &live), 1);
    std::fs::remove_file(&path).ok();
}
