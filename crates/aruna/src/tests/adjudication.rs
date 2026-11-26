//! Adjudication, late acks, and the exposure obligations.

use super::*;
use crate::fixtures::FIXTURE_KEY_PROVIDER;
use crate::keys::undo_child_key;

// ═══════════════════════════════════════════════════════════════════════════════════
// §5.2d IN-PLACE ADJUDICATION + the EXP-1..10 obligations.
//
// THE POSTURE THESE WITNESSES PIN: this build ships NO risk-acceptance capability
// (EXP-4 deferred under EXP-10's own fallback clause), so every unresolved overlap
// refuses fail-closed at the send-auth fence. The Cartesian mutant — acceptances
// `(atom A, duplicate)` + `(atom B, reversal)` must not authorize `(atom A, reversal)`
// — holds VACUOUSLY here and is recorded as such: an acceptance-less build has nothing
// that could mis-authorize, and there is no API through which a test could try.
// ═══════════════════════════════════════════════════════════════════════════════════

/// The engine-minted opaque id of the ONE LIVE obligation over an atom — the value an
/// EXP-3 refusal surfaces to the caller. Read from the store's own
/// table, so a witness asserting on the surfaced reference is asserting that the engine
/// named the row that actually blocked it.
fn live_obligation_id(path: &std::path::Path, atom_key: &str) -> String {
    raw_conn(path)
        .query_row(
            "SELECT obligation_id FROM exposure_obligation
                  WHERE primitive_atom = ?1 AND retired_at IS NULL;",
            rusqlite::params![atom_key],
            |r| r.get(0),
        )
        .expect("the atom has exactly one live obligation")
}

/// The successor operation ids an attempt's `SUPERSEDED_BY` facts name.
fn successors_of(path: &std::path::Path, attempt_id: &str) -> Vec<String> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT json_extract(payload, '$.successor_operation_id') FROM attempt_fact
                  WHERE attempt_id = ?1 AND fact_kind = 'superseded_by' ORDER BY revision;",
        )
        .expect("prepare");
    let ids = stmt
        .query_map(rusqlite::params![attempt_id], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|k| k.expect("row"))
        .collect();
    ids
}

#[test]
fn w_unknown_supersede_links_the_first_overlapping_successor_and_only_the_first() {
    // ═══ W-UNKNOWN-SUPERSEDE ═══ §5.2d's AUDIT EDGE, whole: "`SUPERSEDED_BY` links an
    // adjudicated attempt to the FIRST overlapping admission that succeeds it — at most
    // one, legal only on adjudicated attempts; later overlapping admissions carry no edge
    // … the link commits atomically with the successor's admission, before any preparation
    // or dispatch. The edge is an audit pointer; the gate never rides it."
    //
    // The last clause is the one with teeth, and it is asserted here twice: the SECOND
    // overlapping admission is ADMITTED and EDGE-FREE (the W-EXPOSURE arm "third
    // overlapping admission after the edge is consumed ⇒ gated AND admitted, edge-free"),
    // and BOTH successors are refused at the fence by the OBLIGATION, not by the edge.
    let path = unique_temp_db_path("t10-supersede");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    adjudicate_now(&mut log, "k-unknown", &attempt);

    // FIRST overlapping admission ⇒ the edge.
    let first = archive_of("k-successor-1", "msg-1");
    record_basis(&mut log, &first).expect("admit the first successor");
    assert_eq!(
        successors_of(&path, &attempt),
        vec![opaque_intent_id(&path, "k-successor-1")],
        "the first overlapping admission is linked, by OPERATION id"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec![
            "claim",
            "send_authorized",
            "ack_ambiguous",
            "adjudicated_unresolved",
            "superseded_by"
        ],
        "the edge is a fact of the adjudicated attempt's own chain"
    );

    // SECOND overlapping admission ⇒ admitted, and NO second edge.
    let second = archive_of("k-successor-2", "msg-1");
    record_basis(&mut log, &second).expect("admit the second successor");
    assert!(
        log.get("k-successor-2").expect("get").is_some(),
        "a later overlapping admission is ADMITTED — the edge is not an admission gate"
    );
    assert_eq!(
        successors_of(&path, &attempt).len(),
        1,
        "AT MOST ONE successor per adjudicated attempt; later admissions carry no edge"
    );

    // A DISJOINT admission never touches the edge either (EXP-5 at the audit grain).
    let disjoint = archive_of("k-elsewhere", "msg-9");
    record_basis(&mut log, &disjoint).expect("admit the disjoint operation");
    assert_eq!(successors_of(&path, &attempt).len(), 1);

    // AND THE GATE DOES NOT RIDE THE EDGE: both successors refuse at the fence, the
    // linked one and the edge-free one alike, because the OBLIGATION is what gates.
    for key in ["k-successor-1", "k-successor-2"] {
        let claimed = claim_now(&mut log, key, 0);
        assert_eq!(
            authorize(&mut log, key, &claimed).expect("fence"),
            SendAuthOutcome::ExposureBlocked {
                atom_key: fixture_atom("msg-1")
            },
            "{key} refuses on the unresolved exposure, edge or no edge"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_successor_link_atomic_the_edge_and_the_admission_are_one_write() {
    // ═══ W-SUCCESSOR-LINK-ATOMIC ═══ both arms of the crash window §5.2d closes with
    // "the link commits atomically with the successor's admission".
    //
    // CRASH BEFORE THE LINK: a store can never hold an overlapping successor whose edge
    // is missing. No fault injection can stop the engine between two of its own
    // statements, so the failure is injected THROUGH the store, in the shape a real defect
    // would take: an obligation naming a contributor whose chain does not fold. The
    // admission INSERT has already run when the link fails — and the row must not exist
    // afterwards, which is only true if the two are one transaction.
    //
    // CRASH AFTER THE LINK: the successful pair is durable together, and an idempotent
    // REPLAY of the same admission adds no second edge.
    let path = unique_temp_db_path("t10-link-atomic");
    let mut log = SqliteIntentLog::open(&path).expect("open");

    // ---- the BEFORE arm ----
    let conn = raw_conn(&path);
    conn.execute(
        "INSERT INTO attempt_head (attempt_id, operation_id, current_revision,
                                       derived_class, last_verified_revision, verified_state)
             VALUES ('ghost-attempt', 'ghost-op', 1, 'issued_or_unknown', 1, '{}');",
        [],
    )
    .expect("seed a head whose chain does not exist");
    conn.execute(
        "INSERT INTO exposure_obligation (obligation_id, provider_scope, primitive_atom,
                                              direction, generation, contributor_attempt_id,
                                              created_at)
             VALUES ('obl-ghost', 'scope-ghost', ?1, 'clear', 1, 'ghost-attempt',
                     '2026-08-08T00:00:00Z');",
        rusqlite::params![fixture_atom("msg-ghost")],
    )
    .expect("seed the defective obligation");
    drop(conn);

    let doomed = archive_of("k-doomed", "msg-ghost");
    let refused = record_basis(&mut log, &doomed);
    assert!(
        refused.is_err(),
        "a link that cannot be written must fail the admission LOUDLY, got {refused:?}"
    );
    assert!(
        log.get("k-doomed").expect("get").is_none(),
        "THE ARM: the admission rolled back with the edge — no successor exists without \
         the link that was owed"
    );

    // ---- the AFTER arm ----
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    adjudicate_now(&mut log, "k-unknown", &attempt);
    let successor = archive_of("k-successor", "msg-1");
    assert_eq!(
        record_basis(&mut log, &successor).expect("admit"),
        Claim::Inserted
    );
    assert!(log.get("k-successor").expect("get").is_some());
    assert_eq!(successors_of(&path, &attempt).len(), 1, "the pair is durable together");
    assert_eq!(
        record_basis(&mut log, &successor).expect("replay"),
        Claim::AlreadyExisted
    );
    assert_eq!(
        successors_of(&path, &attempt).len(),
        1,
        "a REPLAYED admission is not a second successor"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_late_ack_after_adjudication_resolves_the_historical_axis_only() {
    // ═══ W-LATE-ACK-AFTER-ADJUDICATION ═══ "the historical axis resolves; operational
    // axis, tail, slot, and successor untouched." Every one of those four is asserted.
    let path = unique_temp_db_path("t10-late-ack");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    let record = adjudicate_now(&mut log, "k-unknown", &attempt);
    assert_eq!(
        adjudication_id_of(&path, &attempt),
        record,
        "the record is filed under the attempt, and its id is the FK the fact carries"
    );
    let successor = archive_of("k-successor", "msg-1");
    record_basis(&mut log, &successor).expect("admit the successor");
    let edge_before = successors_of(&path, &attempt);
    let tail_before = log
        .has_non_terminal_native_predecessor(
            &prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &["msg-1"]),
            "msg-1",
            "acct-1",
            u64::MAX,
            "k-successor",
        )
        .expect("tail");

    let outcome = log
        .record_late_ack("k-unknown", &attempt, crate::attempt::LateAck::Applied)
        .expect("late ack");

    assert_eq!(
        outcome,
        LateAckOutcome::Resolved {
            historical: crate::attempt::HistoricalAttribution::Applied,
            retired: 1,
            notices: 0,
            parent_undone: false,
        },
        "the historical axis resolves and this contributor's obligation retires"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec![
            "claim",
            "send_authorized",
            "ack_ambiguous",
            "adjudicated_unresolved",
            "superseded_by",
            "late_ack_applied"
        ]
    );
    // OPERATIONAL: untouched. The operation stays terminal-adjudicated and the head still
    // classifies ADJUDICATED-open-historical — a late ack is not a reopening.
    assert_eq!(status_str(&path, "k-unknown"), "adjudicated");
    assert_eq!(
        raw_conn(&path)
            .query_row(
                "SELECT derived_class FROM attempt_head WHERE attempt_id = ?1;",
                rusqlite::params![attempt],
                |r| r.get::<_, String>(0)
            )
            .expect("head"),
        "adjudicated_unresolved"
    );
    // TAIL: released at ADJUDICATION and not re-taken by the late ack.
    assert!(!tail_before, "adjudication already released the tail");
    assert!(!log
        .has_non_terminal_native_predecessor(
            &prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &["msg-1"]),
            "msg-1",
            "acct-1",
            u64::MAX,
            "k-successor",
        )
        .expect("tail"));
    // SUCCESSOR: the edge is exactly what it was.
    assert_eq!(successors_of(&path, &attempt), edge_before);
    // …and the record itself is untouched (immutable): the resolution lives in the CHAIN.
    assert_eq!(annotation_kinds(&path, &record), Vec::<String>::new());
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_late_ack_applied_on_an_undo_child_flips_the_parent_undone_in_one_transaction() {
    // The UNDO-PARENT arm of W-LATE-ACK-AFTER-ADJUDICATION. An undo child whose restore
    // was ISSUANCE-UNKNOWN and then adjudicated leaves the parent `Applied` with the
    // unresolved state SURFACED (§5.2d) — and if the ack finally arrives, the parent's
    // `Undone` is written in the SAME transaction as the late ack, because a two-write
    // form has a crash window in which history says restored and the parent does not.
    let path = unique_temp_db_path("t10-undo-parent");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let parent = archive_of("k-parent", "msg-p");
    record_basis(&mut log, &parent).expect("admit the parent");
    log.set_status_forced("k-parent", IntentStatus::Applied).expect("apply");
    let parent_id = opaque_intent_id(&path, "k-parent");
    let child_key = undo_child_key(&parent_id);
    let mut child = archive_of(&child_key, "msg-p");
    child.compensates = Some("k-parent".into());
    record_basis(&mut log, &child).expect("admit the undo child");
    let attempt = unknown_attempt(&mut log, &child);
    adjudicate_now(&mut log, &child_key, &attempt);

    // THE PRESENTATION, before the ack: `Applied`, with the unresolved half surfaced.
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    assert_eq!(
        bus.undo_presentation("k-parent").expect("presentation").map(|r| r.presentation),
        Some(UndoPresentation::AppliedUndoUnresolved),
        "§5.2d: the parent returns to Applied WITH the unresolved state surfaced"
    );

    let outcome = log
        .record_late_ack(&child_key, &attempt, crate::attempt::LateAck::Applied)
        .expect("late ack");

    assert!(
        matches!(
            outcome,
            LateAckOutcome::Resolved {
                parent_undone: true,
                ..
            }
        ),
        "the late APPLIED is the verification that never arrived, got {outcome:?}"
    );
    assert_eq!(status_str(&path, "k-parent"), "undone");
    assert_eq!(
        status_str(&path, &child_key),
        "adjudicated",
        "…and the CHILD's operational closure is untouched by it"
    );
    assert_eq!(
        bus.undo_presentation("k-parent").expect("presentation").map(|r| r.presentation),
        Some(UndoPresentation::Undone)
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_contradictory_second_late_ack_is_refused_and_durably_annotated() {
    // §5.2a's named case: "a second, CONTRADICTORY late ack is REFUSED and the
    // contradiction is durably recorded as an anomaly annotation on the adjudication
    // record". Both halves — the chain never holds two attributions, AND the incident is
    // not silently dropped. Plus the DUPLICATE (same polarity) arm, which is a plain
    // grammar refusal and owes no annotation.
    let path = unique_temp_db_path("t10-contradiction");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    let record = adjudicate_now(&mut log, "k-unknown", &attempt);
    log.record_late_ack("k-unknown", &attempt, crate::attempt::LateAck::Applied)
        .expect("the first late ack lands");
    let before = chain_kinds(&path, &attempt);

    let contradiction = log
        .record_late_ack(
            "k-unknown",
            &attempt,
            crate::attempt::LateAck::RefusedNoEffect,
        )
        .expect("the contradiction is an outcome, never an error");

    assert!(
        matches!(contradiction, LateAckOutcome::RefusedAsContradiction { .. }),
        "got {contradiction:?}"
    );
    assert_eq!(chain_kinds(&path, &attempt), before, "the chain is UNCHANGED");
    assert_eq!(
        annotation_kinds(&path, &record),
        vec!["contradictory-late-ack"],
        "…and the contradiction is durable on the adjudication record"
    );

    // The SAME polarity again is a duplicate, not a contradiction: refused, no annotation.
    let duplicate = log
        .record_late_ack("k-unknown", &attempt, crate::attempt::LateAck::Applied)
        .expect("duplicate");
    assert_eq!(
        duplicate,
        LateAckOutcome::RefusedByGrammar(crate::attempt::GrammarRefusal::DuplicateLateAck {
            existing: crate::attempt::FactKind::LateAckApplied
        })
    );
    assert_eq!(
        annotation_kinds(&path, &record),
        vec!["contradictory-late-ack"],
        "a duplicate is not an anomaly — no second annotation"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_unknown_same_resource_holds_the_tail_until_adjudication_releases_it() {
    // ═══ W-UNKNOWN-SAME-RESOURCE ═══ an ISSUANCE_UNKNOWN operation is NOT terminal, so
    // it holds its resource tail — a same-resource successor must wait behind a dispatch
    // whose effect nobody can describe. §5.2d's in-place closure is what releases it, and
    // the release is by virtue of the TERMINAL STATUS alone, through the existing
    // same-resource predecessor join: no second release mechanism exists.
    let path = unique_temp_db_path("t10-same-resource");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    let successor = archive_of("k-after", "msg-1");
    record_basis(&mut log, &successor).expect("admit the successor");
    let native = prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &["msg-1"]);
    let tail = |log: &SqliteIntentLog| {
        log.has_non_terminal_native_predecessor(&native, "msg-1", "acct-1", u64::MAX, "k-after")
            .expect("tail")
    };

    assert!(
        tail(&log),
        "an unknown operation holds the tail — it is neither completed nor retryable"
    );
    assert_eq!(status_str(&path, "k-unknown"), "pending");

    adjudicate_now(&mut log, "k-unknown", &attempt);

    assert_eq!(status_str(&path, "k-unknown"), "adjudicated");
    assert!(
        !tail(&log),
        "the in-place closure releases the tail — through the status, not a second door"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn exp_3_the_gate_is_fed_by_real_obligations_and_exp_5_leaves_disjoint_atoms_alone() {
    // EXP-3 + EXP-6 + EXP-5, with the obligation rows written by the PRODUCTION writer
    // (An earlier test proved the join over a hand-seeded row; this proves the writer feeding it).
    //
    // No risk-acceptance capability exists in this build, so an overlap has exactly one
    // honest answer: refuse fail-closed, pre-wire, with a deterministic no-effect terminal.
    let path = unique_temp_db_path("t10-exp3");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    adjudicate_now(&mut log, "k-unknown", &attempt);
    assert_eq!(
        obligation_rows(&path),
        vec![(
            fixture_atom("msg-1"),
            "clear".to_string(),
            1,
            attempt.clone(),
            false
        )],
        "EXP-2/EXP-1: one durable row per touched atom, direction-aware, generation-keyed"
    );

    let blocked = archive_of("k-blocked", "msg-1");
    record_basis(&mut log, &blocked).expect("admit");
    let blocked_attempt = claim_now(&mut log, "k-blocked", 0);
    let disjoint = archive_of("k-disjoint", "msg-9");
    record_basis(&mut log, &disjoint).expect("admit");
    let disjoint_attempt = claim_now(&mut log, "k-disjoint", 0);

    assert!(
        matches!(
            authorize(&mut log, "k-disjoint", &disjoint_attempt)
                .expect("disjoint"),
            SendAuthOutcome::Authorized { .. }
        ),
        "EXP-5: disjoint means disjoint"
    );
    assert_eq!(
        authorize(&mut log, "k-blocked", &blocked_attempt)
            .expect("overlap"),
        SendAuthOutcome::ExposureBlocked {
            atom_key: fixture_atom("msg-1")
        }
    );
    assert_eq!(
        send_authorized_count(&path, &blocked_attempt),
        0,
        "nothing was ever authorized to touch the wire"
    );
    assert_eq!(
        chain_kinds(&path, &blocked_attempt),
        vec!["claim", "failed_pre_send"],
        "the refusal IS the deterministic no-effect terminal (EXP-6), never a limbo"
    );
    assert_eq!(status_str(&path, "k-blocked"), "failed");
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_exposure_blocked_dispatch_answers_exactly_what_a_replay_answers() {
    // Arm 1 — the EXP-3 deterministic close, seen from the CALLER. The
    // refusing transaction terminalizes the operation `Failed` in its own write (asserted
    // by the EXP-3 witness above), so the row is terminal FOREVER the moment `execute`
    // returns. Answering `InProgress` there tells the caller "recovery owns it, retry
    // later" about a row nothing will ever sweep again — while an identical replay, one
    // line later, reads the dead-letter through the ONE truth table. Two answers, one
    // truth: the §7a replay contract says a door and its replay never disagree.
    let path = unique_temp_db_path("r8-exp-blocked-answer");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    adjudicate_now(&mut log, "k-unknown", &attempt);
    drop(log);

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    let blocked = archive_of("k-blocked", "msg-1");
    let answer = bus.execute(&blocked);
    assert_eq!(
        status_str(&path, "k-blocked"),
        "failed",
        "precondition: the gate closed the operation deterministically, pre-wire"
    );
    assert_eq!(bus.connector().apply_count(), 0, "…with nothing on the wire");

    let replay = bus.execute(&blocked);
    assert_eq!(
        replay,
        Err(ExecuteError::ExposureBlocked {
            obligation: live_obligation_id(&path, &fixture_atom("msg-1")),
        }),
        "precondition: the replay reads the dead-letter through the truth table — which since \
         codex-CLI r10 P2-2 also names WHAT refused, because the refusing transaction wrote it \
         into the terminal's own fact payload, and since r11 P2 names it as the BLOCKING \
         OBLIGATION's engine id rather than the provider-native atom (this arm's dead-letter \
         class is unchanged; only its evidence deepened)"
    );
    assert_eq!(
        answer, replay,
        "the dispatching call must surface the terminal its own authorization wrote, never \
         an in-flight signal for an operation that is closed forever"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_exposure_blocked_dispatch_names_what_blocked_it_and_never_the_provider_ids() {
    // 2026-08-08. `authorize_send` has ALWAYS known what refused
    // (`SendAuthOutcome::ExposureBlocked { atom_key }`) and the dispatch arm dropped it on
    // the floor — so with several gated resources the operator met a bare `Err(Failed)` and
    // could not tell WHICH exposure closed the operation, nor find out afterwards, because
    // nothing durable recorded it either. The pre-fix RED, verbatim:
    //     RED: the refusal names NO atom: Err(Failed)
    //
    // ═══ — AND THEN IT NAMED THE WRONG THING ═══
    //  surfaced the RAW `exposure_atom_key`, on the argument that it is content-free.
    // True, and beside the point: this crate's confinement discipline covers provider
    // IDENTIFIERS (`jmap::no_provider_ids_leak_into_surfaced_errors`; both connectors'
    // fixed, id-free refusal phrases), and that key encodes the account, the message and
    // the mailbox. The pre-fix RED, verbatim:
    //     provider id msg-2 leaked into the surfaced refusal:
    //     ["photon.exposure-atom.v1","[\"test\",\"msg-2\"]","membership:INBOX"]
    //
    // So the caller is given the BLOCKING OBLIGATION's engine-minted row id instead, and
    // this witness asserts all three halves at once: the leak's ABSENCE, the reference's
    // PRESENCE (the right obligation, not merely some opaque string), and its
    // RESOLVABILITY through the engine's own door.
    //
    // TWO unresolved obligations on DIFFERENT atoms, so "names a blocker" and "names the
    // RIGHT blocker" are separable — a fix that hard-coded the first live obligation would
    // pass the first assertion and fail the second.
    //
    // AND THE REPLAY MUST AGREE. The reference is surfaced only because the refusing
    // transaction wrote it into its own `FAILED_PRE_SEND` payload, so the §7a contract this
    // arm already owed ("a door and its replay never disagree") still holds — both sides
    // read the SAME durable fact, which is what replay-equality argument rests on and
    // what the opaque form leaves untouched.
    let path = unique_temp_db_path("r10-exposure-names-blocker");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    for (key, message_ref) in [("k-u1", "msg-1"), ("k-u2", "msg-2")] {
        let command = archive_of(key, message_ref);
        let attempt = unknown_attempt(&mut log, &command);
        adjudicate_now(&mut log, key, &attempt);
    }
    assert_eq!(
        obligation_rows(&path).len(),
        2,
        "precondition: two unresolved exposures, on two different atoms"
    );
    drop(log);
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    let blocked = archive_of("k-blocked", "msg-2");
    let answer = bus.execute(&blocked);
    let surfaced = match &answer {
        Err(ExecuteError::ExposureBlocked { obligation }) => obligation.clone(),
        other => panic!("the exposure gate must refuse, got {other:?}"),
    };
    // (1) NO PROVIDER IDENTIFIER CROSSES THE BOUNDARY — the `jmap` confinement witness's
    // assertion, extended to this error. The seeds are the provider-native components the
    // fixture's frozen basis is built from.
    for provider_id in ["msg-2", "msg-1", FIXTURE_KEY_PROVIDER] {
        assert!(
            !surfaced.contains(provider_id),
            "provider id {provider_id} leaked into the surfaced refusal: {surfaced}"
        );
    }
    assert!(
        !surfaced.contains("membership:INBOX") && !surfaced.contains("exposure-atom"),
        "…and neither does the atom encoding itself: {surfaced}"
    );
    // (2) IT NAMES THE RIGHT BLOCKER — the live obligation over the atom THIS operation
    // touches, never the other one.
    assert_eq!(
        surfaced,
        live_obligation_id(&path, &fixture_atom("msg-2")),
        "the refusal names the OBLIGATION whose unresolved exposure closed it — and the \
         right one"
    );
    assert_ne!(
        surfaced,
        live_obligation_id(&path, &fixture_atom("msg-1")),
        "…which a fix that surfaced any live obligation would fail"
    );
    assert_eq!(bus.connector().apply_count(), 0, "…with nothing on the wire");
    assert_eq!(
        status_str(&path, "k-blocked"),
        "failed",
        "…and the operation is the same deterministic dead-letter it always was"
    );

    // (3) IT RESOLVES, THROUGH THE ENGINE — not a dead-end token. The operator's path from
    // the refusal to the work that must be adjudicated: the obligation names its
    // CONTRIBUTOR (an engine id), which is exactly what `unknown_review` lists and what
    // `adjudicate` is called on.
    let resolved = bus
        .exposure_obligation(&surfaced)
        .expect("the reference resolves")
        .expect("…to a row this store holds");
    assert_eq!(resolved.obligation_id, surfaced);
    assert_eq!(
        resolved.contributor_attempt_id,
        attempt_id_of(&path, "k-u2"),
        "…and it points at the attempt whose unresolved history created the exposure"
    );
    assert_eq!(resolved.generation, 1, "EXP-9: the atom's first episode");
    assert_eq!(
        resolved.direction,
        crate::attempt::ExposureDirection::Clear,
        "the archive verb CLEARS the membership atom"
    );
    assert!(
        resolved.retired_at.is_none(),
        "…and it is LIVE, which is why it gates at all"
    );
    assert_eq!(
        bus.exposure_obligation("no-such-obligation")
            .expect("an unknown id is not an error"),
        None
    );

    let replay = bus.execute(&blocked);
    assert_eq!(
        answer, replay,
        "the §7a replay contract, unweakened: an identical replay names the SAME blocker, \
         which it can only do because the refusing transaction recorded it DURABLY — one \
         fact, read by both sides"
    );
    // THE DURABLE HOME, asserted directly: BOTH identities are in the refusing terminal's
    // own fact payload, not reconstructed at read time from live obligations (which
    // retire). The RAW ATOM STAYS HERE — internal, and the EXP-3 join key — while only the
    // obligation id above ever crosses the caller boundary.
    assert_eq!(
        bus.log()
            .exposure_block("k-blocked")
            .expect("read the terminal's own payload"),
        Some(crate::attempt::ExposureBlock {
            atom_key: fixture_atom("msg-2"),
            obligation_id: surfaced.clone(),
        })
    );
    assert_eq!(
        bus.log()
            .exposure_block("k-u1")
            .expect("read an operation that no exposure gate ever refused"),
        None,
        "an ordinary operation names no block — the field has ONE writer, the EXP-3 gate"
    );
    // The internal half is the crate's injective encoding of the frozen native resource key
    // and the primitive atom NAME — provider identifiers, which is exactly why it is the
    // half that stays inside.
    assert_eq!(
        fixture_atom("msg-2"),
        crate::attempt::exposure_atom_key(
            &prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &["msg-2"]),
            "membership:INBOX",
        )
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn exp_2_a_capture_off_ambiguous_attempt_still_creates_an_obligation_that_gates() {
    // EXP-2, verbatim: "Capture-off (`journal_required=0`) does not exempt it." The
    // exposure key rides the ATTEMPT (copied from the admission-frozen basis into
    // `SEND_AUTHORIZED`), never the journal row — which is exactly why moved
    // it there: a capture-off operation legally HAS no journal row, and the gate must
    // still reach it.
    let path = unique_temp_db_path("t10-capture-off");
    // The config ledger exists only once the store is open — the act rides generation 2,
    // exactly as the capture-off witnesses of stages 2/3 do.
    let mut log = SqliteIntentLog::open(&path).expect("open");
    append_config_act(&path, r#"{"capture":"off"}"#);
    let unknown = archive_of("k-off", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    assert_eq!(
        raw_conn(&path)
            .query_row(
                "SELECT journal_required FROM intents WHERE idempotency_key = 'k-off';",
                [],
                |r| r.get::<_, i64>(0)
            )
            .expect("row"),
        0,
        "precondition: this operation was admitted capture-OFF"
    );
    assert_eq!(
        raw_conn(&path)
            .query_row("SELECT COUNT(*) FROM pre_state;", [], |r| r.get::<_, i64>(0))
            .expect("count"),
        0,
        "precondition: it owns no journal row, and legally may not"
    );

    adjudicate_now(&mut log, "k-off", &attempt);

    assert_eq!(
        obligation_rows(&path).len(),
        1,
        "the obligation exists with no journal row anywhere in the store"
    );
    let blocked = archive_of("k-blocked", "msg-1");
    record_basis(&mut log, &blocked).expect("admit");
    let blocked_attempt = claim_now(&mut log, "k-blocked", 0);
    assert_eq!(
        authorize(&mut log, "k-blocked", &blocked_attempt)
            .expect("overlap"),
        SendAuthOutcome::ExposureBlocked {
            atom_key: fixture_atom("msg-1")
        },
        "…and it GATES"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn exp_8_the_gate_goes_silent_only_when_the_last_contributor_resolves() {
    // EXP-8: "no exposure state retires while an unresolved contributor exists". Two
    // contributors over ONE atom (both authorized before either obligation existed — the
    // only way two same-atom effects can be in flight in an acceptance-less build), and
    // the gate stays closed until the SECOND resolves. Retirement is driven by the
    // HISTORICAL axis, "never by a separate counter's arithmetic".
    let path = unique_temp_db_path("t10-exp8");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let a = archive_of("k-a", "msg-1");
    let b = archive_of("k-b", "msg-1");
    let attempt_a = unknown_attempt(&mut log, &a);
    let attempt_b = unknown_attempt(&mut log, &b);
    adjudicate_now(&mut log, "k-a", &attempt_a);
    adjudicate_now(&mut log, "k-b", &attempt_b);
    assert_eq!(
        obligation_rows(&path)
            .iter()
            .map(|(_, _, generation, _, _)| *generation)
            .collect::<Vec<_>>(),
        vec![1, 1],
        "two contributors joined ONE live episode — the same generation"
    );
    // A fresh probe operation per attempt: the gate's refusal is TERMINAL for the refused
    // one, so reusing it would be measuring a dead row rather than the gate.
    let probe = |log: &mut SqliteIntentLog, key: &str| {
        let command = archive_of(key, "msg-1");
        record_basis(log, &command).expect("admit");
        let attempt = claim_now(log, key, 0);
        authorize(log, key, &attempt).expect("fence")
    };

    assert!(matches!(
        probe(&mut log, "k-probe-1"),
        SendAuthOutcome::ExposureBlocked { .. }
    ));
    log.record_late_ack("k-a", &attempt_a, crate::attempt::LateAck::Applied)
        .expect("the first contributor resolves");
    assert!(
        matches!(
            probe(&mut log, "k-probe-2"),
            SendAuthOutcome::ExposureBlocked { .. }
        ),
        "one contributor resolving is not the episode resolving"
    );

    log.record_late_ack(
        "k-b",
        &attempt_b,
        crate::attempt::LateAck::RefusedNoEffect,
    )
    .expect("the LAST contributor resolves");

    assert!(
        matches!(
            probe(&mut log, "k-probe-3"),
            SendAuthOutcome::Authorized { .. }
        ),
        "the last contributor's resolution silences the gate"
    );
    assert!(
        obligation_rows(&path)
            .iter()
            .all(|(_, _, _, _, retired)| *retired),
        "every row retired — and none was deleted (nothing evicts, EXP-10)"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn exp_7_both_applied_on_one_atom_leaves_a_durable_notice_in_either_order() {
    // EXP-7: "if later attribution establishes that … an accepted duplicate/reversal risk
    // actually materialized — including the multi-contributor trace where two same-atom
    // effects both resolve APPLIED — a durable notice exists and is discoverable from the
    // relevant adjudication … records."
    //
    // BOTH ORDERS, because which effect resolves first must not decide whether the notice
    // exists: (A) the peer applies while the exposure is unresolved, then the late ack
    // lands; (B) the late ack lands FIRST, then the overlapping peer's own effect resolves.
    //
    // In BOTH arms the peer is authorized while the episode is LIVE — genuinely in flight
    // across it. rework arm B, which used to admit its peer
    // AFTER the episode had fully settled and assert a notice anyway: that is not "the
    // other order", it is a LATER INDEPENDENT operation, and labelling it a materialization
    // is exactly the EXP-9 bleed the fold closed (its own witness:
    // `a_later_independent_apply_on_a_settled_atom_is_not_a_materialization`).
    // Nothing here is weakened — arm B still asserts the notice FIRES, over a real overlap.
    let path = unique_temp_db_path("t10-exp7");
    let mut log = SqliteIntentLog::open(&path).expect("open");

    // ---- ORDER A ----
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    // The peer authorizes BEFORE the obligation exists — the only way an overlapping
    // effect can be in flight when the gate has no acceptance to consult.
    let peer = archive_of("k-peer", "msg-1");
    record_basis(&mut log, &peer).expect("admit");
    let peer_attempt = claim_now(&mut log, "k-peer", 0);
    assert!(matches!(
        authorize(&mut log, "k-peer", &peer_attempt).expect("authorize"),
        SendAuthOutcome::Authorized { .. }
    ));
    let record = adjudicate_now(&mut log, "k-unknown", &attempt);
    log.settle_attempt("k-peer", &peer_attempt, ConnectorVerdict::Applied, RETRY_CAP, None)
        .expect("the peer's effect provably happened");
    assert_eq!(
        annotation_kinds(&path, &record),
        vec!["applied-over-unresolved"],
        "the durable HALF of the trace, recorded when the peer applied"
    );

    let outcome = log
        .record_late_ack("k-unknown", &attempt, crate::attempt::LateAck::Applied)
        .expect("late ack");
    assert!(
        matches!(outcome, LateAckOutcome::Resolved { notices: 1, .. }),
        "both applied ⇒ the materialization notice fires, got {outcome:?}"
    );
    assert_eq!(
        annotation_kinds(&path, &record),
        vec!["applied-over-unresolved", "exposure-materialized"]
    );

    // ---- ORDER B ----
    let second = archive_of("k-unknown-2", "msg-2");
    let second_attempt = unknown_attempt(&mut log, &second);
    // The peer is in flight ACROSS the episode: authorized before the obligation exists
    // (the only overlap a build with no risk-acceptance capability can produce), and it
    // settles after the late ack has already resolved the other contributor.
    let late_peer = archive_of("k-peer-2", "msg-2");
    record_basis(&mut log, &late_peer).expect("admit");
    let late_peer_attempt = claim_now(&mut log, "k-peer-2", 0);
    assert!(
        matches!(
            authorize(&mut log, "k-peer-2", &late_peer_attempt)
                .expect("authorize"),
            SendAuthOutcome::Authorized { .. }
        ),
        "precondition: the peer is on the wire before the obligation exists"
    );
    let second_record = adjudicate_now(&mut log, "k-unknown-2", &second_attempt);
    log.record_late_ack(
        "k-unknown-2",
        &second_attempt,
        crate::attempt::LateAck::Applied,
    )
    .expect("the late ack lands FIRST");
    assert_eq!(
        annotation_kinds(&path, &second_record),
        Vec::<String>::new(),
        "nothing has materialized yet — one applied effect is not two"
    );
    log.settle_attempt(
        "k-peer-2",
        &late_peer_attempt,
        ConnectorVerdict::Applied,
        RETRY_CAP,
        None,
    )
    .expect("the peer's effect provably happened");

    assert_eq!(
        annotation_kinds(&path, &second_record),
        vec!["exposure-materialized"],
        "the RETIRED obligation is still the evidence the episode the peer overlapped \
         existed — the notice does not depend on which effect resolved first"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn exp_9_a_later_episode_on_a_settled_atom_is_a_new_generation() {
    // EXP-9: "after an atom's exposure fully resolves and settles, a later independent
    // unresolved episode on that atom is a NEW exposure generation — old acceptances and
    // old notices never authorize or contaminate it." NON-BLEED, in both directions: the
    // new episode gates on its own, and the old rows stay retired.
    let path = unique_temp_db_path("t10-exp9");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let first = archive_of("k-first", "msg-1");
    let first_attempt = unknown_attempt(&mut log, &first);
    adjudicate_now(&mut log, "k-first", &first_attempt);
    log.record_late_ack("k-first", &first_attempt, crate::attempt::LateAck::Applied)
        .expect("the episode settles");
    assert_eq!(
        obligation_rows(&path),
        vec![(
            fixture_atom("msg-1"),
            "clear".to_string(),
            1,
            first_attempt.clone(),
            true
        )]
    );

    // A NEW, INDEPENDENT unresolved episode on the SAME atom.
    let second = archive_of("k-second", "msg-1");
    let second_attempt = unknown_attempt(&mut log, &second);
    adjudicate_now(&mut log, "k-second", &second_attempt);

    let rows = obligation_rows(&path);
    assert_eq!(rows.len(), 2, "nothing was evicted or reused");
    assert_eq!(
        rows[0],
        (
            fixture_atom("msg-1"),
            "clear".to_string(),
            1,
            first_attempt,
            true
        ),
        "the settled generation is untouched by the new episode"
    );
    assert_eq!(
        rows[1],
        (
            fixture_atom("msg-1"),
            "clear".to_string(),
            2,
            second_attempt,
            false
        ),
        "…and the new episode is generation 2, live"
    );
    let probe = archive_of("k-probe", "msg-1");
    record_basis(&mut log, &probe).expect("admit");
    let probe_attempt = claim_now(&mut log, "k-probe", 0);
    assert_eq!(
        authorize(&mut log, "k-probe", &probe_attempt).expect("fence"),
        SendAuthOutcome::ExposureBlocked {
            atom_key: fixture_atom("msg-1")
        },
        "the NEW generation gates on its own — the retired one authorizes nothing"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_unknown_review_report_surfaces_long_unknown_attempts_and_decides_nothing() {
    // §5.2d's `unknown_review_after` (config, default 7 days): it SURFACES — never
    // auto-decides. The report is asserted at BOTH ends of the threshold, and the store is
    // asserted UNCHANGED by having read it.
    let path = unique_temp_db_path("t10-review");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    let settled = archive_of("k-settled", "msg-2");
    let settled_attempt = unknown_attempt(&mut log, &settled);
    adjudicate_now(&mut log, "k-settled", &settled_attempt);
    let chain_before = chain_kinds(&path, &attempt);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Threshold 0: everything unresolved is due for review.
    let due = log.unknown_review(now, 0).expect("report");
    assert_eq!(
        due.rows.len(),
        1,
        "only the UNRESOLVED attempt is listed: {due:?}"
    );
    assert_eq!(due.rows[0].attempt_id, attempt);
    assert_eq!(due.rows[0].idempotency_key, "k-unknown");
    assert!(due.rows[0].review_due);
    assert!(
        !due.rows[0].reconcile_cap_reached,
        "no RECONCILE writer exists in this build, so the cap is not reached"
    );
    assert!(
        !due.clock_rollback_detected,
        "the clock did not step back, so the age verdict is the ORDINARY one"
    );

    // The declared threshold: nothing is 7 days old in a test that just ran.
    let fresh = log
        .unknown_review(now, crate::attempt::UNKNOWN_REVIEW_AFTER_SECONDS)
        .expect("report");
    assert_eq!(
        fresh.rows.len(),
        1,
        "it is still SURFACED, with its age verdict"
    );
    assert!(!fresh.rows[0].review_due);
    assert!(!fresh.clock_rollback_detected);

    // AND IT DECIDED NOTHING.
    assert_eq!(chain_kinds(&path, &attempt), chain_before);
    assert_eq!(status_str(&path, "k-unknown"), "pending");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_backward_clock_step_surfaces_every_unknown_row_for_immediate_review() {
    // 2026-08-08 — §5.2a, transcribed on
    // `ClampedNow::backward_step_detected`: a detected backward wall-clock step "SURFACES
    // aging-policy items for IMMEDIATE review instead of waiting for wall time to catch up".
    //
    // THE CLAMP IS WHAT MAKES THIS BITE. `clamped_now` dates every fact `max(now,
    // high-water)` and hands the write door a `backward_step_detected` flag it DISCARDS —
    // so after a rollback `unknown_since` is a FUTURE instant relative to the operator's
    // clock, the `unknown_since <= cutoff` verdict is false for the WHOLE rollback interval,
    // and the review report goes quiet exactly when the clock is untrustworthy. The RED
    // this closes, verbatim from the pre-fix bytes: a store whose facts are dated NOW, read
    // with a `now` one day earlier, answered
    //   `[UnknownReviewRow { …, unknown_since: "2026-08-09T04:06:10Z", review_due: false, … }]`
    // and carried no flag at all.
    //
    // Detected at the READ, with the SAME comparison the clamp makes — never a second rule.
    // BOTH impls, because the fast tests must test the engine that ships.
    let path = unique_temp_db_path("r10-rollback-review");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let _attempt = unknown_attempt(&mut log, &unknown);
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // The wall clock steps BACKWARD one day, over a store whose facts are dated NOW.
    let rolled_back = real_now - 86_400;
    let report = log.unknown_review(rolled_back, 0).expect("report");
    assert!(
        report.clock_rollback_detected,
        "the caller's now sorts below the persisted fact clock — that IS the rollback"
    );
    assert_eq!(report.rows.len(), 1, "the unknown attempt is listed: {report:?}");
    assert!(
        report.rows[0].review_due,
        "…and it is due for review NOW, not once wall time catches up: {report:?}"
    );
    assert!(
        report.rows[0].unknown_since > crate::prestate::rfc3339_utc(rolled_back),
        "the witness: the clamped `unknown_since` is in the FUTURE relative to this clock, \
         which is precisely what the ordinary age verdict cannot see"
    );

    let mut mem = InMemoryIntentLog::new();
    record_basis(&mut mem, &unknown).expect("admit");
    let mem_attempt = match mem
        .claim_attempt(
            "k-unknown",
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
        authorize(&mut mem, "k-unknown", &mem_attempt).expect("authorize"),
        SendAuthOutcome::Authorized { .. }
    ));
    mem.settle_attempt(
        "k-unknown",
        &mem_attempt,
        ConnectorVerdict::Failed {
            kind: FailureKind::Transient,
            evidence: EffectEvidence::Indeterminate,
        },
        RETRY_CAP,
        None,
    )
    .expect("settle");
    let mem_report = mem.unknown_review(rolled_back, 0).expect("report");
    assert!(
        mem_report.clock_rollback_detected,
        "the in-memory door answers identically: {mem_report:?}"
    );
    assert_eq!(mem_report.rows.len(), 1);
    assert!(mem_report.rows[0].review_due, "{mem_report:?}");

    // AND A FORWARD CLOCK IS UNTOUCHED — the flag is a detector, not a switch that leaves
    // the ordinary age verdict permanently on.
    let forward = log
        .unknown_review(real_now, crate::attempt::UNKNOWN_REVIEW_AFTER_SECONDS)
        .expect("report");
    assert!(!forward.clock_rollback_detected);
    assert!(
        !forward.rows[0].review_due,
        "nothing is 7 days old in a test that just ran: {forward:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_unknown_review_report_is_reachable_through_the_command_bus_not_only_the_log() {
    // `CommandBus::unknown_review` is the first-class public verb —
    // before this change the report was reachable only via `IntentLog::unknown_review`
    // through `bus.log()`'s inspection escape hatch. The bus-level passthrough must agree
    // with the log directly, byte for byte.
    let path = unique_temp_db_path("t11-review-via-bus");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown-bus", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    let bus = CommandBus::new(log, AlwaysOkConnector);

    let via_bus = bus.unknown_review(0, 0).expect("report via the bus");
    let via_log = bus.log().unknown_review(0, 0).expect("report via the log directly");
    assert_eq!(
        via_bus, via_log,
        "the bus passthrough must return exactly what the log's own verb returns"
    );
    assert_eq!(
        via_bus.rows.len(),
        1,
        "the unresolved attempt is listed: {via_bus:?}"
    );
    assert_eq!(via_bus.rows[0].attempt_id, attempt);
    assert_eq!(via_bus.rows[0].idempotency_key, "k-unknown-bus");
    // `now = 0` is the epoch, which sorts below every fact this store holds — a rollback by
    // the clamp's own comparison, so the passthrough carries the flag through too.
    assert!(via_bus.clock_rollback_detected, "{via_bus:?}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn exp_10_outstanding_unresolved_exposure_surfaces_in_the_integrity_report() {
    // EXP-10's capacity posture, made VISIBLE. Nothing evicts an obligation, and the gate
    // fails closed on every overlap — so the growth of the table is reported at open, and
    // an operator seeing refusals can see how many unresolved exposures are causing them.
    // (The gate's own cost is a keyed join per touched atom; it does not read this count.)
    let path = unique_temp_db_path("t10-exp10");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-unknown", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    adjudicate_now(&mut log, "k-unknown", &attempt);
    drop(log);

    let reopened = SqliteIntentLog::open(&path).expect("reopen");
    assert!(
        reopened.integrity_report().iter().any(|e| matches!(
            e,
            IntegrityEvidence::UnresolvedExposureOutstanding {
                unretired: 1,
                total: 1
            }
        )),
        "the outstanding obligation is surfaced at open: {:?}",
        reopened.integrity_report()
    );
    drop(reopened);

    let mut log = SqliteIntentLog::open(&path).expect("reopen");
    log.record_late_ack("k-unknown", &attempt, crate::attempt::LateAck::Applied)
        .expect("resolve");
    drop(log);

    let settled = SqliteIntentLog::open(&path).expect("reopen");
    assert!(
        !settled.integrity_report().iter().any(|e| matches!(
            e,
            IntegrityEvidence::UnresolvedExposureOutstanding { .. }
        )),
        "a fully retired table is not outstanding — but the ROW is still there: {:?}",
        settled.integrity_report()
    );
    assert_eq!(obligation_rows(&path).len(), 1, "nothing evicts");
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_in_memory_door_adjudicates_gates_and_retires_like_the_durable_one() {
    // BOTH IMPLS. The in-memory log now holds the §5.2d substrate too, so the EXP-3 gate
    // is REAL on it rather than vacuous — a fake whose fence can never refuse would let
    // every fast test pass a boundary the durable engine would have closed.
    let mut log = InMemoryIntentLog::new();
    let unknown = archive_cmd("k-unknown");
    record_basis(&mut log, &unknown).expect("admit");
    let attempt = match log
        .claim_attempt(
            "k-unknown",
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
        authorize(&mut log, "k-unknown", &attempt).expect("authorize"),
        SendAuthOutcome::Authorized { .. }
    ));
    log.settle_attempt(
        "k-unknown",
        &attempt,
        ConnectorVerdict::Failed {
            kind: FailureKind::Transient,
            evidence: EffectEvidence::Indeterminate,
        },
        RETRY_CAP,
        None,
    )
    .expect("settle");

    let outcome = log
        .adjudicate(
            "k-unknown",
            &attempt,
            "authority:operator",
            crate::attempt::AdjudicationReason::OperatorAbandonedUnresolved,
            crate::attempt::AcceptedRisk::NoneClaimed,
        )
        .expect("adjudicate");

    assert!(
        matches!(
            outcome,
            AdjudicationOutcome::Adjudicated { obligations: 1, .. }
        ),
        "got {outcome:?}"
    );
    assert_eq!(
        log.get("k-unknown").expect("get").expect("row").status,
        IntentStatus::Adjudicated
    );
    assert_eq!(log.exposure_obligations().len(), 1);
    assert!(!log.exposure_obligations()[0].retired());

    // The gate, on the same atom (`archive_cmd` is msg-1 for every key).
    let blocked = archive_cmd("k-blocked");
    record_basis(&mut log, &blocked).expect("admit");
    let blocked_attempt = match log
        .claim_attempt(
            "k-blocked",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("claim: {other:?}"),
    };
    assert!(
        matches!(
            authorize(&mut log, "k-blocked", &blocked_attempt)
                .expect("fence"),
            SendAuthOutcome::ExposureBlocked { .. }
        ),
        "the in-memory fence refuses the overlap fail-closed too"
    );
    assert_eq!(
        log.get("k-blocked").expect("get").expect("row").status,
        IntentStatus::Failed,
        "…with the deterministic no-effect terminal, in the same call"
    );

    // EXP-8 on this log too.
    let resolved = log
        .record_late_ack("k-unknown", &attempt, crate::attempt::LateAck::Applied)
        .expect("late ack");
    assert!(
        matches!(resolved, LateAckOutcome::Resolved { retired: 1, .. }),
        "got {resolved:?}"
    );
    assert!(log.exposure_obligations()[0].retired());
    let after = archive_cmd("k-after");
    record_basis(&mut log, &after).expect("admit");
    let after_attempt = match log
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
        other => panic!("claim: {other:?}"),
    };
    assert!(
        matches!(
            authorize(&mut log, "k-after", &after_attempt).expect("fence"),
            SendAuthOutcome::Authorized { .. }
        ),
        "the retired obligation gates nothing"
    );
}
