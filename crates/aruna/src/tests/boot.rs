//! Boot quarantine and open-time verification of the attempt chain.

use super::*;
use crate::fact_store::{verified_state_from_json, verified_state_json};

/// Every `attempt_head` row as `(attempt_id, derived_class, current_revision,
/// last_verified_revision)` — the projection columns the boot quarantine keys on.
fn head_rows(path: &std::path::Path) -> Vec<(String, String, i64, i64)> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT attempt_id, derived_class, current_revision, last_verified_revision
                   FROM attempt_head ORDER BY attempt_id;",
        )
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    rows
}

// ═══════════════════════════════════════════════════════════════════════════════════
// BOOT QUARANTINE. Design §5.2b's boot bullet: "on start, before
// any dispatch, every non-terminal attempt is classified from its FACTS; no read-derived
// attribution, ever" — plus §5.2a's INCREMENTAL open-time verification (verify only the
// facts appended since `last_verified_revision`, advance the baseline, O(delta)) and the
// head's safety sentence enforced as a FAIL-LOUD OPEN REFUSAL.
//
// THE CRAFTED-STORE REOPEN MATRIX. Every row says how its store was built: REAL ENGINE
// CALLS wherever a shape is reachable through the doors, DIRECT SQL only where the
// production writer closes the very window under test (each such row says so at the site).
// ═══════════════════════════════════════════════════════════════════════════════════

/// The `attempt_head` row's verified baseline `(last_verified_revision, verified_state)`.
fn baseline_of(path: &std::path::Path, attempt_id: &str) -> (i64, String) {
    raw_conn(path)
        .query_row(
            "SELECT last_verified_revision, verified_state FROM attempt_head
                  WHERE attempt_id = ?1;",
            rusqlite::params![attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the attempt has a head")
}

#[test]
fn the_verified_state_snapshot_round_trips_losslessly() {
    // The BASELINE contract (§5.2a): open-time verification replays the delta FROM this
    // snapshot, so anything the snapshot drops is a rule the delta is judged without. The
    // chain below carries every field the fold has — lineage, episode, exposure key, the
    // changed-only reconcile baseline, adjudication and a late ack — and the round-trip
    // must be the identity.
    use crate::attempt::{
        ExposureAtom, ExposureDirection, ExposureKey, Fact, FactKind, FactPayload,
        RetryPredecessor, RetryReason,
    };
    let at = "2026-08-08T00:00:00Z";
    let f = |revision: u64, kind: FactKind, payload: FactPayload| Fact {
        operation_id: "op-1".into(),
        attempt_id: "att-2".into(),
        revision,
        kind,
        basis_epoch: 4,
        created_at: at.into(),
        payload,
        prior_revision: if revision == 1 { None } else { Some(revision - 1) },
    };
    let chain = vec![
        f(
            1,
            FactKind::Claim,
            FactPayload::Claim {
                ordinal: 2,
                predecessor: Some(RetryPredecessor {
                    attempt_id: "att-1".into(),
                    reason: RetryReason::AckRefusedNoEffect,
                }),
            },
        ),
        f(
            2,
            FactKind::SendAuthorized,
            FactPayload::SendAuthorized {
                exposure_key: ExposureKey {
                    provider_scope: "res-1".into(),
                    atoms: vec![ExposureAtom {
                        atom_key: "res-1\u{1f}membership:INBOX".into(),
                        direction: ExposureDirection::Clear,
                    }],
                },
            },
        ),
        f(
            3,
            FactKind::ReconcileStateDiffers,
            FactPayload::Reconcile {
                observation: "differs".into(),
            },
        ),
        f(4, FactKind::AckAmbiguous, FactPayload::None),
        f(
            5,
            FactKind::AdjudicatedUnresolved,
            FactPayload::Adjudicated {
                adjudication_id: "adj-1".into(),
            },
        ),
        f(6, FactKind::LateAckApplied, FactPayload::None),
    ];
    let state = crate::attempt::fold(&chain).expect("the chain folds");

    let round_tripped =
        verified_state_from_json(&verified_state_json(&state)).expect("it parses back");

    assert_eq!(round_tripped, state, "the snapshot is the fold, losslessly");
    assert!(
        verified_state_from_json("{\"current_revision\":3}")
            .expect_err("a partial snapshot is refused")
            .0
            .contains("was not written by this build"),
        "parse-don't-validate: a snapshot missing a field is never defaulted into one"
    );
}

#[test]
fn an_attempt_chain_with_no_head_row_refuses_the_open() {
    // Boot verified every `attempt_head` against its chain — and only
    // that direction. A chain whose head row is GONE has nothing to iterate over, so the
    // orphan sailed through quarantine unclassified and unrefused, and every door
    // downstream then read an attempt the boot-time projections do not cover:
    // `unknown_review` scans HEADS (the orphan is invisible to the operator's review
    // report), `live_attempt` and the sever partition fold the CHAIN (it is very
    // much visible to dispatch). Two authorities disagreeing about the same attempt is the
    // head/fold-divergence class, which refuses the open.
    let path = unique_temp_db_path("orphan-chain-open");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit_and_claim(&mut log, &archive_of("k-orphan", "msg-1"))
    };
    let deleted = raw_conn(&path)
        .execute(
            "DELETE FROM attempt_head WHERE attempt_id = ?1;",
            rusqlite::params![attempt],
        )
        .expect("the head row is deletable — nothing in the schema stops this");
    assert_eq!(deleted, 1, "the premise: the head row existed and is now gone");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim"],
        "…and the FACTS are untouched: this is an orphan chain, not a deleted attempt"
    );

    let refusal = open_refusal(&path);
    assert!(
        refusal.contains(&attempt) && refusal.contains("no attempt_head row"),
        "the open must name the orphan chain it refused over, got: {refusal}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_append_whose_head_update_matches_no_row_fails_loud_instead_of_orphaning() {
    // The WRITE-side half. `append_fact_with_head` issued the head
    // UPDATE and threw away rusqlite's affected-row count, so an append onto an attempt
    // whose head row is missing wrote the FACT and silently updated NOTHING — manufacturing
    // exactly the orphan the boot check above refuses, inside a transaction that then
    // committed. The count is the free, exact witness; a zero is a `LogError` and the
    // append's transaction rolls back.
    //
    // WHICH AUTHORITY REFUSES THIS TODAY, honestly. The READ probe now
    // fires first: every one of these doors folds the attempt through
    // `fold_stored_attempt` before it appends, and a nonempty chain with no head row is an
    // `Err` there. The write-side row count is therefore belt-and-braces — inside one
    // IMMEDIATE transaction SQLite's single writer forbids the head vanishing between the
    // probe and the UPDATE — and it is KEPT because `append_fact_with_head` must not depend
    // on a caller having probed. The invariant this witness states is unchanged: a fact
    // never lands without the projection it must maintain.
    let path = unique_temp_db_path("orphan-chain-append");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let attempt = admit_and_claim(&mut log, &archive_of("k-orphan-append", "msg-1"));
    // THE POSITIVE CONTROL, taken first: the same door, with the projection present, appends
    // normally. Without it the witness below could be satisfied by a door that always
    // refuses. (It runs before the delete because an orphan chain refuses the OPEN — this
    // store cannot be reopened once the head is gone.)
    let healthy = admit_and_claim(&mut log, &archive_of("k-orphan-append-ok", "msg-2"));
    authorize_now(&mut log, "k-orphan-append-ok", &healthy);
    assert_eq!(
        chain_kinds(&path, &healthy),
        vec!["claim", "send_authorized"],
        "the premise: this door appends when the head it must maintain exists"
    );
    raw_conn(&path)
        .execute(
            "DELETE FROM attempt_head WHERE attempt_id = ?1;",
            rusqlite::params![attempt],
        )
        .expect("delete the head under the open engine");

    let outcome = authorize(&mut log, "k-orphan-append", &attempt);

    let error = match outcome {
        Ok(other) => panic!("an append onto a headless chain must fail loud, got {other:?}"),
        Err(e) => e.0,
    };
    assert!(
        error.contains("attempt_head") && error.contains(&attempt),
        "the refusal must name the projection it could not maintain, got: {error}"
    );
    drop(log);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim"],
        "the refused append rolled back — no SEND_AUTHORIZED fact survives without its head"
    );
    std::fs::remove_file(&path).ok();
}

/// Hand-corrupt the exposure key inside a `SEND_AUTHORIZED` payload on a CLOSED store — a
/// fact BEHIND the head's verified watermark whose revision, class and owner are all left
/// exactly as the engine wrote them. The append-only UPDATE trigger is dropped for the edit
/// and left dropped (the next open's own `CREATE TRIGGER IF NOT EXISTS` restores it), so the
/// craft models corruption AT REST rather than a door this engine owns.
fn corrupt_authorized_scope(path: &std::path::Path, attempt_id: &str, scope: &str) {
    let conn = raw_conn(path);
    conn.execute_batch("DROP TRIGGER IF EXISTS attempt_fact_no_update;")
        .expect("drop the append-only guard for the craft");
    let raw: String = conn
        .query_row(
            "SELECT payload FROM attempt_fact
                  WHERE attempt_id = ?1 AND fact_kind = 'send_authorized';",
            rusqlite::params![attempt_id],
            |r| r.get(0),
        )
        .expect("the attempt holds a SEND_AUTHORIZED fact");
    let mut payload: serde_json::Value =
        serde_json::from_str(&raw).expect("the stored payload is JSON");
    payload["exposure_key"]["provider_scope"] = serde_json::json!(scope);
    conn.execute(
        "UPDATE attempt_fact SET payload = ?2
              WHERE attempt_id = ?1 AND fact_kind = 'send_authorized';",
        rusqlite::params![attempt_id, payload.to_string()],
    )
    .expect("hand-edit the authorization payload");
}

#[test]
fn a_live_door_refuses_a_head_whose_verified_baseline_lost_to_its_chain() {
    // ═══ ═══ The in-transaction head probe fetched THREE projected
    // fields — revision, class, owner — and compared only those. A fact BEHIND
    // `last_verified_revision`, corrupted at rest without moving any of the three, therefore
    // passed the probe at every live door: the head's own persisted `verified_state` (the
    // snapshot the engine proved correct in the transaction that wrote it) was never
    // consulted, so the fold's word was checked against three columns and nothing checked
    // the fold. boot skip named this exact residual and pointed HERE to close it.
    //
    // The corruption below is the damaging one: the SEND_AUTHORIZED payload's exposure key
    // is what §5.2d COPIES (never re-derives) into the adjudication record and into every
    // EXP-2 obligation row — so a forged `provider_scope` behind the watermark retargets the
    // durable obligation that gates every later overlapping admission past EXP-3.
    let path = unique_temp_db_path("r15-live-baseline");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        unknown_attempt(&mut log, &archive_of("k-r15-baseline", "msg-r15"))
    };
    let (_, class, revision, watermark) = head_rows(&path)
        .into_iter()
        .find(|(id, ..)| id == &attempt)
        .expect("the attempt has a head row");
    assert_eq!(
        (class.as_str(), revision, watermark),
        ("issued_or_unknown", 3, 3),
        "the premise: a LIVE attempt whose head was verified by the very append that wrote it"
    );
    corrupt_authorized_scope(&path, &attempt, "provider-scope-the-basis-never-froze");

    // The reopen is CLEAN, and must be: §5.2a's open-time verification is O(delta), the delta
    // here is empty, and boot therefore never re-reads the corrupted prefix fact. This is the
    // LIVE door's job, not boot's.
    let mut log =
        SqliteIntentLog::open(&path).expect("the reopen is clean — boot verifies only the delta");

    let outcome = log.adjudicate(
        "k-r15-baseline",
        &attempt,
        "authority:operator-adjudicator",
        crate::attempt::AdjudicationReason::PresumedTransportLoss,
        crate::attempt::AcceptedRisk::NoneClaimed,
    );

    let error = match outcome {
        Ok(landed) => panic!(
            "THE RED: the live door adjudicated on an exposure key the frozen basis never \
             produced, got {landed:?}"
        ),
        Err(e) => e.0,
    };
    assert!(
        error.contains(&attempt) && error.contains("diverges from its chain"),
        "the probe must name the attempt whose persisted baseline its own chain no longer \
         folds to, got: {error}"
    );
    drop(log);
    assert!(
        obligation_rows(&path).is_empty(),
        "…and nothing durable was minted over the forged scope: no EXP-2 obligation exists"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_ambiguous"],
        "…and no ADJUDICATED_UNRESOLVED fact landed either — the transaction rolled back"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_live_reader_refuses_a_nonempty_chain_whose_head_row_is_gone() {
    // ═══ ═══ The in-transaction probe treated an ABSENT head row as
    // "nothing to compare against" and returned the fold as valid. Boot refuses the open over
    // exactly that shape (the ORPHAN anti-join), but a head deleted MID-SESSION — by a peer
    // process, a sync agent, a restore — is not seen again until the next restart, and every
    // live door in between reads an attempt the projections do not cover.
    //
    // The SEVER is the discriminating door: an ISSUED_OR_UNKNOWN member is witnessed and
    // deliberately LEFT ALIVE (no append), so `append_fact_with_head`'s write-side row-count
    // witness never fires and the fold's own answer is the only thing between the orphan and
    // a durable §5.1 witness that names it as live.
    let path = unique_temp_db_path("r15-headless-reader");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let attempt = admit_and_claim(&mut log, &archive_of("k-r15-headless", "msg-r15h"));
    authorize_now(&mut log, "k-r15-headless", &attempt);

    let deleted = raw_conn(&path)
        .execute(
            "DELETE FROM attempt_head WHERE attempt_id = ?1;",
            rusqlite::params![attempt],
        )
        .expect("the head row is deletable — nothing in the schema stops this");
    assert_eq!(deleted, 1, "the premise: the head row existed and is now gone");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized"],
        "…and the FACTS are untouched: this is an orphan chain, not a deleted attempt"
    );

    let severed = log.sever("authority:operator-r15", &sever_now());

    let error = match severed {
        Ok(outcome) => panic!(
            "THE RED: the sever folded a headless chain, called it live and witnessed it, \
             got {outcome:?}"
        ),
        Err(e) => e.0,
    };
    assert!(
        error.contains(&attempt) && error.contains("attempt_head"),
        "the live reader must name the orphan chain it refused over, got: {error}"
    );
    drop(log);
    assert!(
        witness_rows(&path).is_empty(),
        "…and no sever witness was durably written over an attempt no projection covers"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn boot_quarantine_terminalizes_a_stale_epoch_claimed_unauthorized_attempt() {
    // ROW. CRAFT: real engine calls for every FACT (`record` + `claim_attempt`); the
    // epoch move is a DIRECT `control_epoch` UPDATE, because the production writer
    // (`IntentLog::sever`) closes this window itself — a real sever terminalizes the
    // claimed-unauthorized member in its own transaction, so the shape only survives when
    // the bump and the closure came apart. Row below builds the SAME class with real
    // calls only, through the sever's documented operation-grain blind spot.
    let path = unique_temp_db_path("boot-stale-epoch");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit_and_claim(&mut log, &archive_of("k-stale", "msg-1"))
    };
    raw_conn(&path)
        .execute("UPDATE control_epoch SET epoch = epoch + 1 WHERE id = 1;", [])
        .expect("bump the fence under the crashed bus");

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    let report = bus.recover().expect("sweep");

    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "severed_before_issuance"],
        "a claim taken under a dead epoch can never be authorized — BOOT closes it from \
         its FACTS, before any dispatch, rather than leaving a live attempt behind a fence"
    );
    assert_eq!(
        status_str(&path, "k-stale"),
        "severed",
        "fact + head + operation, one transaction (§5.2c's closure shape)"
    );
    assert_eq!(bus.connector().apply_count(), 0, "nothing reached the wire");
    assert_eq!(report.recovered, 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn boot_quarantine_closes_the_live_attempt_a_real_sever_could_not_see() {
    // ROW — the same class, REAL CALLS ONLY. §5.2c bullet 1 is at OPERATION grain: an
    // operation whose lifecycle is already terminal is ABSENT from the witness, so a real
    // sever cannot close its still-live attempt (the in-memory partition witness above
    // asserts exactly that absence). The attempt survives claimed under a dead epoch, and
    // BOOT is the only thing left that can classify it.
    let path = unique_temp_db_path("boot-sever-blindspot");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let attempt = admit_and_claim(&mut log, &archive_of("k-blind", "msg-1"));
        log.set_status_forced("k-blind", IntentStatus::Failed)
            .expect("a peer settled the operation under this driver");
        attempt
    };
    let severed = sever_from_control_plane(&path, "authority:test-operator");
    assert_eq!(
        member_class(&severed.witness, &attempt),
        None,
        "the lifecycle-terminal operation is absent from the witness, live attempt and all"
    );

    let bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );

    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "severed_before_issuance"],
        "boot classifies the ATTEMPT from its own facts — the sever's operation-grain \
         partition never saw it"
    );
    assert_eq!(
        status_str(&path, "k-blind"),
        "failed",
        "…and boot does not rewrite a lifecycle that is already terminal: it closes the \
         attempt, nothing else"
    );
    drop(bus);
    std::fs::remove_file(&path).ok();
}

#[test]
fn boot_quarantine_leaves_a_current_epoch_claim_dispatchable() {
    // ROW (b) — THE OVER-REFUSAL FENCE. CRAFT: real calls only (`record` + `claim_attempt`,
    // then the process "crashes" before the authorization). The claim is under the CURRENT
    // epoch, so quarantine has nothing to say about it and the ordinary doors still own it.
    let path = unique_temp_db_path("boot-current-epoch");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit_and_claim(&mut log, &archive_of("k-live", "msg-1"))
    };

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    let report = bus.recover().expect("sweep");

    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_applied"],
        "quarantine must not over-refuse: a current-epoch pre-authorization claim still \
         flows through the ordinary CLAIM → SEND_AUTHORIZED → verdict doors"
    );
    assert_eq!(status_str(&path, "k-live"), "applied");
    assert_eq!(bus.connector().apply_count(), 1);
    assert_eq!(report.recovered, 1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn boot_never_rewrites_a_fully_verified_settled_head() {
    // ═══ ═══ Boot loaded EVERY `attempt_head` row — snapshot JSON and
    // all — re-verified it, and then issued an `UPDATE` per row, forever. But
    // `append_fact_with_head` writes `last_verified_revision = current_revision` in the very
    // transaction that appends the fact, so in a healthy store the delta is ALWAYS empty and
    // that UPDATE always rewrote the identical bytes back. Every reopen therefore paid N
    // durable writes (and N WAL frames, and N snapshot parses + folds) for attempts that
    // finished months ago and cannot change again.
    //
    // The skip set is exactly: a head whose watermark EQUALS its current revision (there is
    // no delta to verify) AND whose derived class is terminally attributed (the chain is
    // finished, and the quarantine's classification arm has nothing to say about it — it
    // acts only on `pre_issuance`). Live classes are still loaded and still verified: that
    // is the quarantine's whole job, and `adjudicated_unresolved` counts as live because its
    // HISTORICAL axis is still open (a `LATE_ACK_*` may still land on it).
    //
    // RESIDUAL, named and honest: a settled-terminal head that is corrupted AT REST is now
    // caught when a door READS it (`fold_stored_attempt`'s head==fold probe, which every
    // live door runs) rather than at boot. That is the same evidence posture the whole
    // §5.2a design already takes — open-time verification is O(delta) by construction, so it
    // never re-reads a verified prefix either — and nothing in this build writes to a
    // settled-terminal chain, so the only way its bytes change is a corruption boot could
    // not have prevented anyway.
    let path = unique_temp_db_path("boot-verified-head-updates");
    let closed: Vec<String> = {
        let mut bus = CommandBus::new(
            SqliteIntentLog::open(&path).expect("open"),
            UndoStageConnector::single(false, true),
        );
        for i in 0..4 {
            bus.execute(&archive_of(&format!("k-closed-{i}"), &format!("msg-{i}")))
                .expect("the operation applies and its attempt settles terminal");
        }
        drop(bus);
        (0..4)
            .map(|i| attempt_id_of(&path, &format!("k-closed-{i}")))
            .collect()
    };
    assert_eq!(
        head_rows(&path).len(),
        4,
        "the premise: four settled attempts, all fully verified by their own appends"
    );
    for (attempt, class, revision, watermark) in head_rows(&path) {
        assert_eq!(class, "applied", "attempt '{attempt}' settled terminal");
        assert_eq!(
            revision, watermark,
            "attempt '{attempt}' was verified by the transaction that wrote it"
        );
    }

    // THE POSITIVE CONTROL, crafted before the instrument so boot meets both shapes in one
    // pass: one of those very heads is rolled back to the never-verified watermark (the
    // shape an interrupted boot, or a store written before the baseline advance existed,
    // leaves behind). Its class is settled — so if the skip keyed on CLASS ALONE it would
    // sail through UNVERIFIED, which is the over-skip this control forbids.
    let lagging = closed[0].clone();
    raw_conn(&path)
        .execute(
            "UPDATE attempt_head SET last_verified_revision = 0, verified_state = ?2
                  WHERE attempt_id = ?1;",
            rusqlite::params![
                lagging,
                verified_state_json(&crate::attempt::DerivedState::empty())
            ],
        )
        .expect("roll one head back to the pristine baseline");

    // THE INSTRUMENT: a probe table + an AFTER UPDATE trigger on `attempt_head`, installed
    // between two opens. Boot's own writes are what fire it, so this counts the real thing
    // rather than a re-implementation of it.
    raw_conn(&path)
        .execute_batch(
            "CREATE TABLE boot_head_update_probe (attempt_id TEXT NOT NULL);
                 CREATE TRIGGER boot_head_update_probe_t AFTER UPDATE ON attempt_head
                   BEGIN INSERT INTO boot_head_update_probe (attempt_id)
                         VALUES (NEW.attempt_id); END;",
        )
        .expect("instrument the head projection");

    drop(SqliteIntentLog::open(&path).expect("reopen runs the boot quarantine"));

    let updated: Vec<String> = {
        let conn = raw_conn(&path);
        let mut stmt = conn
            .prepare("SELECT attempt_id FROM boot_head_update_probe ORDER BY attempt_id;")
            .expect("prepare");
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        rows
    };
    assert_eq!(
        updated,
        vec![lagging.clone()],
        "boot must write EXACTLY the head whose baseline actually advances — the three \
         fully-verified settled heads are not loaded, not re-folded and not rewritten"
    );
    assert_eq!(
        head_rows(&path)
            .into_iter()
            .filter(|(id, _, _, _)| id == &lagging)
            .map(|(_, _, revision, watermark)| (revision, watermark))
            .collect::<Vec<_>>(),
        vec![(3, 3)],
        "…and the one it did write is now caught up: the delta was verified, not skipped"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn boot_quarantine_never_reauthorizes_an_authorized_unacked_attempt() {
    // ROW (c) — ISSUED_OR_UNKNOWN. CRAFT: real calls only — `record` + `claim_attempt` +
    // `authorize_send`, then the bus is dropped WITHOUT entering the socket, which is
    // precisely the commit-to-socket gap a crash leaves (§5.2b truth 3).
    let path = unique_temp_db_path("boot-issued-unknown");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let attempt = admit_and_claim(&mut log, &archive_of("k-unknown", "msg-1"));
        authorize_now(&mut log, "k-unknown", &attempt);
        attempt
    };

    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    let report = bus.recover().expect("sweep");

    assert_eq!(
        bus.connector().apply_count(),
        0,
        "we cannot prove non-issuance — the one potentially effectful wire dispatch this \
         attempt is allowed has already been spent"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt),
        1,
        "never RE-authorized"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized"],
        "and never falsely settled: no verdict fact exists that nobody witnessed"
    );
    assert_eq!(
        status_str(&path, "k-unknown"),
        "pending",
        "the honest state is a durable, visible open unknown — not a terminal"
    );
    assert_eq!(report.recovered, 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_attempt_head_that_diverges_from_its_chain_refuses_the_open() {
    // ROW (d), arm 1 — the head's §5.2a safety sentence, enforced. CRAFT: real calls for
    // the chain, then a DIRECT UPDATE of the `attempt_head` PROJECTION (it carries no
    // append-only trigger — it is a derived restatement, and this is exactly the drift the
    // sentence forbids).
    let path = unique_temp_db_path("boot-head-divergence");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit_and_claim(&mut log, &archive_of("k-drift", "msg-1"))
    };
    raw_conn(&path)
        .execute(
            "UPDATE attempt_head SET derived_class = 'issued_or_unknown' WHERE attempt_id = ?1;",
            rusqlite::params![attempt],
        )
        .expect("hand-edit the projection");

    let refusal = open_refusal(&path);

    assert!(
        refusal.contains("diverges from its chain"),
        "a projection that disagrees with the chain is a SECOND authority — fail loud, \
         never a silent re-derive: {refusal}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_illegal_fact_appended_behind_the_baseline_refuses_the_open() {
    // ROW (d), arm 2 — the O(delta) re-verification doing its actual job. CRAFT: real calls
    // for the chain, then a DIRECT INSERT of a fact the CLOSED grammar would have refused
    // (a SECOND `send_authorized`) with the head moved to match it and the baseline left
    // behind — the shape "the projection launders a defect" takes.
    let path = unique_temp_db_path("boot-illegal-delta");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let attempt = admit_and_claim(&mut log, &archive_of("k-forge", "msg-1"));
        authorize_now(&mut log, "k-forge", &attempt);
        attempt
    };
    let conn = raw_conn(&path);
    conn.execute(
        "INSERT INTO attempt_fact (operation_id, attempt_id, revision, fact_kind,
                                       attempt_ordinal, basis_epoch, created_at, payload,
                                       prior_revision)
             SELECT operation_id, attempt_id, 3, 'send_authorized', NULL, basis_epoch,
                    created_at, payload, 2
               FROM attempt_fact WHERE attempt_id = ?1 AND revision = 2;",
        rusqlite::params![attempt],
    )
    .expect("forge a second authorization");
    conn.execute(
        "UPDATE attempt_head SET current_revision = 3, last_verified_revision = 2
              WHERE attempt_id = ?1;",
        rusqlite::params![attempt],
    )
    .expect("move the head over the forged fact");

    let refusal = open_refusal(&path);

    assert!(
        refusal.contains("DuplicateSendAuthorized"),
        "the fold is the authority the head is checked against, so it must not launder a \
         stored fact the append door would have refused: {refusal}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_time_verification_replays_only_the_delta_and_advances_the_baseline() {
    // §5.2a's INCREMENTAL verification, both halves. CRAFT: real calls for the chain, then
    // a DIRECT roll-back of `last_verified_revision` (the watermark column, a projection
    // value) to model a baseline that lags its chain — the state a build whose appends did
    // not advance the watermark would leave, and the only state in which the delta is
    // non-empty at all.
    let path = unique_temp_db_path("boot-incremental");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let attempt = admit_and_claim(&mut log, &archive_of("k-delta", "msg-1"));
        authorize_now(&mut log, "k-delta", &attempt);
        attempt
    };
    let verified_at_claim = {
        let conn = raw_conn(&path);
        let state: String = conn
            .query_row(
                "SELECT verified_state FROM attempt_head WHERE attempt_id = ?1;",
                rusqlite::params![attempt],
                |r| r.get(0),
            )
            .expect("head");
        state
    };
    assert_eq!(baseline_of(&path, &attempt).0, 2, "appends advance it today");
    // Roll the baseline back to the CLAIM, keeping a snapshot that is the honest fold at
    // revision 1 — the delta is then the `send_authorized` fact alone.
    raw_conn(&path)
        .execute(
            "UPDATE attempt_head SET last_verified_revision = 1, verified_state = ?2
                  WHERE attempt_id = ?1;",
            rusqlite::params![
                attempt,
                verified_at_claim.replace(
                    "\"current_revision\":2",
                    "\"current_revision\":1"
                ).replace("\"send_authorized\":true", "\"send_authorized\":false")
            ],
        )
        .expect("roll the watermark back");

    let log = SqliteIntentLog::open(&path).expect("the delta verifies");

    assert_eq!(
        head_of(&path, &attempt),
        (2, "issued_or_unknown".to_string(), 2),
        "open replays only the facts appended SINCE the baseline and ADVANCES it — the \
         next boot's delta is empty (§5.2a, O(delta))"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_broken_sever_witness_surfaces_as_open_time_evidence_not_a_refusal() {
    // ROW (e) — the sever reconciliation authority (`verify_sever_witness`) wired into the
    // open-time report. CRAFT: real calls for the real witness, then a DIRECT INSERT of a
    // FORGED row at a fresh epoch (`sever_witness`'s append-only triggers refuse every
    // rewrite, so a forgery can only ever be a new row). The witness is AUDIT SUBSTRATE,
    // never a dispatch gate: it is EVIDENCE, and the store still opens (§2.2b's
    // evidence-never-refuses posture).
    let path = unique_temp_db_path("boot-broken-witness");
    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit(&mut log, &archive_of("k-witness", "msg-1"));
        log.sever("authority:test-operator", &sever_now())
            .expect("a real sever");
    }
    raw_conn(&path)
        .execute(
            "INSERT INTO sever_witness (witness_id, epoch, severed_at, authority_ref,
                                            member_count, member_set, digest)
                 VALUES ('forged-witness', 99, '2026-01-01T00:00:00Z', 'authority:forged',
                         7, '[]', 'deadbeef');",
            [],
        )
        .expect("forge a witness row");

    let log = SqliteIntentLog::open(&path).expect("the store still OPENS");

    assert!(
        log.integrity_report().iter().any(|e| matches!(
            e,
            IntegrityEvidence::SeverWitnessUnreconciled { witness_id, .. }
                if witness_id == "forged-witness"
        )),
        "an epoch-only or membership-only witness FAILS reconciliation, and the failure is \
         SURFACED: {:?}",
        log.integrity_report()
    );
    assert!(
        log.integrity_report().iter().all(|e| !matches!(
            e,
            IntegrityEvidence::SeverWitnessUnreconciled { witness_id, .. }
                if witness_id != "forged-witness"
        )),
        "…while the REAL witness reconciles and says nothing"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}
