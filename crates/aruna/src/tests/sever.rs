//! The sever primitive, the coalescing sever service, and the seize bound.

use super::*;
use crate::intent::status_from_str;
use crate::keys::undo_child_key;
use crate::sever::{install_sever_seam, verify_sever_witness, SeverSeam};

// ═══════════════════════════════════════════════════════════════════════════════════
// THE SEVER PRIMITIVE (design §5.1 witness + §5.2c partition).
// W-SEIZE-RACE · W-SEIZE-ADMIT · W-SEIZE-CLASS-FREEZE · W-SEIZE-BLIND · the membership
// TOTALITY property · double-drive witness 3.
// ═══════════════════════════════════════════════════════════════════════════════════

/// Every OPERATION a witness names, resolved through the store: an `OperationMember` names
/// its operation directly, an `AttemptMember` through its attempt's immutable owner.
fn witnessed_operations(path: &std::path::Path, witness: &SeverWitness) -> Vec<String> {
    use crate::attempt::WitnessMember;
    let conn = raw_conn(path);
    witness
        .members
        .iter()
        .map(|m| match m {
            WitnessMember::Operation { operation_id } => {
                String::from_utf8(operation_id.clone()).expect("utf-8 id")
            }
            WitnessMember::Attempt { attempt_id, .. } => {
                let attempt_id = String::from_utf8(attempt_id.clone()).expect("utf-8 id");
                conn.query_row(
                    "SELECT operation_id FROM attempt_fact WHERE attempt_id = ?1 LIMIT 1;",
                    rusqlite::params![attempt_id],
                    |r| r.get::<_, String>(0),
                )
                .unwrap_or_else(|e| panic!("attempt '{attempt_id}' has no owner: {e}"))
            }
        })
        .collect()
}

#[test]
fn w_seize_race_a_send_authorization_and_a_sever_linearize_in_both_orders() {
    // ═══ W-SEIZE-RACE ═══ §5.2b: "SQLite's single writer is what linearizes them against
    // the sever transaction — so exactly one of {send-auth, sever} goes first, and both
    // orders are safe." The BOTH-SIDES witness: whichever order the two transactions take,
    // EXACTLY ONE of these two truths holds, never both and never neither:
    //   (a) the authorization REFUSED and the attempt is closed SEVERED_BEFORE_ISSUANCE, or
    //   (b) the authorization COMMITTED and the sever classified it ISSUED_OR_UNKNOWN.
    // Two logs over one file — two independent drivers over one durable store (the double-drive race's
    // topology), which is the only place this race exists.
    for sever_first in [true, false] {
        let path = unique_temp_db_path(&format!("seize-race-{sever_first}"));
        let mut driver = SqliteIntentLog::open(&path).expect("open driver");
        let mut control = SqliteIntentLog::open(&path).expect("open control");
        let command = archive_of("k-race", "msg-race");
        let attempt = admit_and_claim(&mut driver, &command);

        let (outcome, witness) = if sever_first {
            let severed = control.sever("authority:operator-1", &sever_now()).expect("sever");
            (
                authorize(&mut driver, "k-race", &attempt).expect("authorize"),
                severed.witness,
            )
        } else {
            let outcome = authorize(&mut driver, "k-race", &attempt).expect("authorize");
            let severed = control.sever("authority:operator-1", &sever_now()).expect("sever");
            (outcome, severed.witness)
        };

        let refused = !matches!(outcome, SendAuthOutcome::Authorized { .. });
        let refused_and_closed = refused
            && member_class(&witness, &attempt)
            == Some(crate::attempt::WitnessClass::SeveredBeforeIssuance)
            && chain_kinds(&path, &attempt) == vec!["claim", "severed_before_issuance"]
            && status_str(&path, "k-race") == "severed";
        let authorized_and_unknown = matches!(outcome, SendAuthOutcome::Authorized { .. })
            && member_class(&witness, &attempt)
                == Some(crate::attempt::WitnessClass::IssuedOrUnknown)
            && chain_kinds(&path, &attempt) == vec!["claim", "send_authorized"]
            && status_str(&path, "k-race") == "pending";
        assert!(
            refused_and_closed ^ authorized_and_unknown,
            "sever_first={sever_first}: EXACTLY ONE of {{refused+SEVERED_BEFORE_ISSUANCE, \
             authorized+ISSUED_OR_UNKNOWN}} must hold. outcome={outcome:?}, class={:?}, \
             chain={:?}, status={}",
            member_class(&witness, &attempt),
            chain_kinds(&path, &attempt),
            status_str(&path, "k-race"),
        );
        // The wire-facing invariant behind the disjunction: an authorization committed
        // under the OLD epoch is exactly what the sever witnessed as ISSUED_OR_UNKNOWN, and
        // no authorization exists on the severed side at all.
        assert_eq!(
            send_authorized_count(&path, &attempt),
            i64::from(authorized_and_unknown),
            "sever_first={sever_first}: the authorization count IS the side of the race"
        );
        // Whichever side won, the witness is one verifiable row.
        verify_sever_witness(&witness_row(&path, witness.epoch))
            .expect("the witness reconciles whichever order the two transactions took");
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn w_seize_admit_the_witness_carries_every_element_and_reconciles_or_fails() {
    // ═══ W-SEIZE-ADMIT ═══ §5.1: the row persists "the COMPLETE ADR-P008 element-(3)
    // minimum … if the post-sever audit is lost, this row is the only surviving evidence":
    // post-sever epoch · timestamp · seizing-authority REFERENCE · member count · member
    // set · digest. "W-SEIZE-ADMIT verifies every field through reconciliation (an
    // epoch-only or membership-only witness FAILS)." Plus §5.2c's closure assertion:
    // "post-sever, the member operations are terminal and their resources unblocked".
    let path = unique_temp_db_path("seize-admit");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unclaimed = archive_of("k-admit-unclaimed", "msg-a");
    let claimed = archive_of("k-admit-claimed", "msg-b");
    admit(&mut log, &unclaimed);
    let claimed_attempt = admit_and_claim(&mut log, &claimed);
    let unclaimed_op = opaque_intent_id(&path, "k-admit-unclaimed");

    let severed = log.sever("authority:operator-7", &sever_now()).expect("sever");

    // ── EVERY ELEMENT, in the ROW (not merely in the returned value). ──
    let row = witness_row(&path, severed.epoch);
    assert_eq!(row.epoch, severed.epoch, "the POST-sever epoch");
    assert_eq!(row.epoch, 2, "…which is the seeded 1, bumped once by this sever");
    assert!(
        prestate::is_canonical_rfc3339_utc(&row.severed_at),
        "the sever TIMESTAMP, canonical: '{}'",
        row.severed_at
    );
    assert_eq!(row.authority_ref, "authority:operator-7", "the authority REFERENCE");
    assert_eq!(row.member_count, 2, "the member COUNT");
    assert!(!row.member_set.is_empty(), "the member SET");
    assert_eq!(row.digest.len(), 96, "the SHA-384 DIGEST, lowercase hex (48 bytes)");
    assert!(!row.witness_id.trim().is_empty(), "the row's own opaque id");

    // ── RECONCILIATION: the digest RECOMPUTES from the stored member set. ──
    let verified = verify_sever_witness(&row).expect("the witness reconciles");
    assert_eq!(verified.members, severed.witness.members);
    assert_eq!(
        verified.digest,
        crate::attempt::sever_witness_digest_hex(&verified.members),
        "the stored digest IS the canonical digest of the stored member set"
    );

    // ── THE HAND-BROKEN ROWS. Each is seeded as a real row (the append-only triggers
    //    refuse an UPDATE, so a forger writes a NEW row) and read back through the same
    //    door the integrity scan will use. ──
    let conn = raw_conn(&path);
    let seed_broken = |epoch: i64, authority: &str, count: i64, members: &str, digest: &str| {
        conn.execute(
            "INSERT INTO sever_witness (witness_id, epoch, severed_at, authority_ref,
                                            member_count, member_set, digest)
                 VALUES (?1, ?2, '2026-08-08T00:00:00Z', ?3, ?4, ?5, ?6);",
            rusqlite::params![
                format!("forged-{epoch}"),
                epoch,
                authority,
                count,
                members,
                digest
            ],
        )
        .expect("seed a hand-broken witness row");
    };
    // (1) EPOCH-ONLY: the epoch and nothing else — no authority, no members, no digest.
    seed_broken(101, "", 0, "[]", "");
    // (2) MEMBERSHIP-ONLY: the member set, with the digest struck out.
    seed_broken(102, "authority:x", 2, &row.member_set, "");
    // (3) MEMBERSHIP EDITED, digest kept: a member removed after the fact.
    let one_member = serde_json::to_string(
        &serde_json::from_str::<Vec<serde_json::Value>>(&row.member_set).unwrap()[..1],
    )
    .unwrap();
    seed_broken(103, "authority:x", 1, &one_member, &row.digest);
    // (4) COUNT vs MEMBERSHIP disagreement.
    seed_broken(104, "authority:x", 9, &row.member_set, &row.digest);
    for epoch in [101, 102, 103, 104] {
        let forged = witness_row(&path, epoch);
        let verdict = verify_sever_witness(&forged);
        assert!(
            verdict.is_err(),
            "the hand-broken witness at epoch {epoch} must FAIL reconciliation, got {verdict:?}"
        );
    }
    drop(conn);

    // ── THE CLOSURE (§5.2c): "witnessing without closing strands them
    //    — they would consume capacity and block their resource tails forever". ──
    assert_eq!(severed.terminalized, 2, "both members closed in the sever transaction");
    assert_eq!(status_str(&path, "k-admit-unclaimed"), "severed");
    assert_eq!(status_str(&path, "k-admit-claimed"), "severed");
    assert_eq!(
        chain_kinds(&path, &claimed_attempt),
        vec!["claim", "severed_before_issuance"],
        "the claimed-unauthorized attempt gained its closure FACT, not just a status"
    );
    assert_eq!(
        head_of(&path, &claimed_attempt).1,
        "severed_before_issuance",
        "…and the head projection moved with it, in the same transaction"
    );
    assert_eq!(
        member_class(&severed.witness, &unclaimed_op),
        Some(crate::attempt::WitnessClass::NoActiveAttempt),
        "the never-claimed operation is an OperationMember"
    );
    // THE TAIL IS UNBLOCKED: a NEW operation on the severed operation's own resource
    // admits and dispatches — the terminal status released the same-resource barrier with
    // no second release mechanism anywhere.
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_of("k-admit-successor", "msg-a"))
        .expect("the severed member's resource tail is free");
    assert_eq!(status_str(&path, "k-admit-successor"), "applied");
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_seize_class_freeze_witnesses_both_member_forms_and_both_live_classes() {
    // ═══ W-SEIZE-CLASS-FREEZE ═══ §5.1's TAGGED UNION, all four shapes in ONE sever:
    //   OperationMember  — never-claimed work …………………………… NO_ACTIVE_ATTEMPT
    //   OperationMember  — the RETRY GAP (a terminally-failed attempt, budget left)
    //   AttemptMember    — claimed, never authorized ………… SEVERED_BEFORE_ISSUANCE
    //   AttemptMember    — authorized, unacked …………………………… ISSUED_OR_UNKNOWN
    // "an attempt-only tuple could not represent admitted-unclaimed work" (§5.1), and
    // the retry gap is the arm §5.2c's rework exists for: attempt-grain terminal
    // attribution is NOT operation-grain completion.
    let path = unique_temp_db_path("seize-class-freeze");
    let mut log = SqliteIntentLog::open(&path).expect("open");

    let never = archive_of("k-never", "msg-never");
    admit(&mut log, &never);

    let gap = archive_of("k-gap", "msg-gap");
    let gap_attempt = admit_and_claim(&mut log, &gap);
    let settled = log
        .settle_attempt(
            "k-gap",
            &gap_attempt,
            ConnectorVerdict::Failed {
                kind: FailureKind::Transient,
                evidence: EffectEvidence::Indeterminate,
            },
            RETRY_CAP,
            None,
        )
        .expect("settle the gap operation's first attempt");
    assert!(
        matches!(
            settled,
            SettleOutcome::Settled {
                lifecycle: SettledLifecycle::RetryGap,
                ..
            }
        ),
        "precondition: a terminally-failed attempt with budget left leaves the OPERATION \
         active in its retry gap, got {settled:?}"
    );

    let claimed = archive_of("k-claimed", "msg-claimed");
    let claimed_attempt = admit_and_claim(&mut log, &claimed);

    let authorized = archive_of("k-authorized", "msg-authorized");
    let authorized_attempt = admit_and_claim(&mut log, &authorized);
    assert!(matches!(
        authorize(&mut log, "k-authorized", &authorized_attempt)
            .expect("authorize"),
        SendAuthOutcome::Authorized { .. }
    ));

    let severed = log.sever("authority:operator-3", &sever_now()).expect("sever");
    let witness = severed.witness;

    use crate::attempt::WitnessClass;
    assert_eq!(witness.member_count(), 4, "four active operations, four members");
    assert_eq!(
        member_class(&witness, &opaque_intent_id(&path, "k-never")),
        Some(WitnessClass::NoActiveAttempt),
        "never-claimed ⇒ OperationMember"
    );
    assert_eq!(
        member_class(&witness, &opaque_intent_id(&path, "k-gap")),
        Some(WitnessClass::NoActiveAttempt),
        "THE RETRY GAP ⇒ OperationMember (its failed attempt is attempt-grain HISTORY, \
         never a second classification)"
    );
    assert_eq!(
        member_class(&witness, &claimed_attempt),
        Some(WitnessClass::SeveredBeforeIssuance),
        "claimed, never authorized ⇒ AttemptMember/SEVERED_BEFORE_ISSUANCE"
    );
    assert_eq!(
        member_class(&witness, &authorized_attempt),
        Some(WitnessClass::IssuedOrUnknown),
        "authorized, unacked ⇒ AttemptMember/ISSUED_OR_UNKNOWN"
    );
    // The retry-gap operation's OWN terminal attempt is NOT a member: it is closed, and a
    // closed attempt has no live class (that is exactly why the operation is the member).
    assert_eq!(
        member_class(&witness, &gap_attempt),
        None,
        "the gap operation's terminally-failed attempt is not a second member"
    );

    // THE LIFECYCLE HALF: three closed, one deliberately left open.
    assert_eq!(status_str(&path, "k-never"), "severed");
    assert_eq!(status_str(&path, "k-gap"), "severed");
    assert_eq!(status_str(&path, "k-claimed"), "severed");
    assert_eq!(
        status_str(&path, "k-authorized"),
        "pending",
        "ISSUED_OR_UNKNOWN is witnessed and left ACTIVE: we cannot prove non-issuance, so \
         we do not claim it — settlement or adjudication closes it, never a sever"
    );
    assert_eq!(severed.terminalized, 3);
    assert_eq!(
        chain_kinds(&path, &authorized_attempt),
        vec!["claim", "send_authorized"],
        "…and NOTHING was appended to it"
    );
    verify_sever_witness(&witness_row(&path, severed.epoch)).expect("reconciles");
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_seize_blind_the_witness_row_holds_no_content() {
    // ═══ W-SEIZE-BLIND ═══ §5.1: the authority is recorded "by reference, never PII
    // substance", and the membership is opaque engine ids. The RAW ROW is asserted over —
    // every column concatenated — because a content leak that only the value type hides
    // is still on disk. (§5.1's own accepted residual, named: count, timing and
    // id-linkability ARE exposed; content-blind is not traffic-blind.)
    let path = unique_temp_db_path("seize-blind");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    // Every field a caller controls carries a distinctive token.
    let command = Command::new(
        "k-quarterly-layoffs-memo",
        "acct-ceo@example.test",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-confidential-42".into(),
        },
    );
    let attempt = admit_and_claim(&mut log, &command);
    let severed = log
        .sever("authority:session-ref-9f2", &sever_now())
        .expect("sever");

    let row = witness_row(&path, severed.epoch);
    let all_columns = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        row.witness_id,
        row.epoch,
        row.severed_at,
        row.authority_ref,
        row.member_count,
        row.member_set,
        row.digest
    );
    for content in [
        "k-quarterly-layoffs-memo",
        "quarterly",
        "layoffs",
        "acct-ceo@example.test",
        "example.test",
        "msg-confidential-42",
        "confidential",
    ] {
        assert!(
            !all_columns.contains(content),
            "the witness row leaks '{content}': {all_columns}"
        );
    }
    // Positively: every member id is an OPAQUE engine id (32 hex chars), never a key.
    use crate::attempt::WitnessMember;
    for member in &severed.witness.members {
        let id = match member {
            WitnessMember::Operation { operation_id } => operation_id.clone(),
            WitnessMember::Attempt { attempt_id, .. } => attempt_id.clone(),
        };
        let id = String::from_utf8(id).expect("utf-8 id");
        assert_eq!(id.len(), 32, "opaque 16-byte hex id, got '{id}'");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "opaque hex id, got '{id}'"
        );
    }
    assert_eq!(
        severed.witness.members.len(),
        1,
        "one active operation, one member — the claimed attempt"
    );
    assert!(
        all_columns.contains(&attempt),
        "…and the member IS that attempt's opaque id (the linkability §5.1 accepts)"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_sever_membership_is_total_over_active_operations_across_interleaves() {
    // ═══ MEMBERSHIP TOTALITY (§5.1/§5.2c) ═══ "Membership is therefore TOTAL over active
    // operations: every active operation appears exactly once, as an AttemptMember (a
    // non-terminal attempt exists) or an OperationMember (none does)" — and a
    // LIFECYCLE-TERMINAL operation is ABSENT (§5.2c bullet 1: COMPLETED).
    //
    // Property-style over generated interleaves: the same seven operation SHAPES are built
    // in every rotation of their order (the store's seq order, the retry gap's history and
    // the undo child's admission all move with it), and the property is re-asserted on each
    // freshly-built store.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        NeverClaimed,
        Claimed,
        Authorized,
        RetryGap,
        CompletedApplied,
        DeadLettered,
        UndoChild,
    }
    use Shape::*;
    let shapes = [
        NeverClaimed,
        Claimed,
        Authorized,
        RetryGap,
        CompletedApplied,
        DeadLettered,
        UndoChild,
    ];

    for rotation in 0..shapes.len() {
        let path = unique_temp_db_path(&format!("seize-totality-{rotation}"));
        // The ACTIVE set this interleave built, by idempotency key — the expected
        // membership, derived from the SHAPES rather than from the code under test.
        let mut expected_active: Vec<String> = Vec::new();
        {
            let mut log = SqliteIntentLog::open(&path).expect("open");
            for step in 0..shapes.len() {
                let shape = shapes[(rotation + step) % shapes.len()];
                let key = format!("k-{rotation}-{step}");
                let message = format!("msg-{rotation}-{step}");
                let command = archive_of(&key, &message);
                match shape {
                    NeverClaimed => {
                        admit(&mut log, &command);
                        expected_active.push(key);
                    }
                    Claimed => {
                        admit_and_claim(&mut log, &command);
                        expected_active.push(key);
                    }
                    Authorized => {
                        let attempt = admit_and_claim(&mut log, &command);
                        authorize(&mut log, &key, &attempt).expect("authorize");
                        expected_active.push(key);
                    }
                    RetryGap => {
                        let attempt = admit_and_claim(&mut log, &command);
                        log.settle_attempt(
                            &key,
                            &attempt,
                            ConnectorVerdict::Failed {
                                kind: FailureKind::Transient,
                                evidence: EffectEvidence::Indeterminate,
                            },
                            RETRY_CAP,
                            None,
                        )
                        .expect("settle into the retry gap");
                        expected_active.push(key);
                    }
                    CompletedApplied => {
                        let attempt = admit_and_claim(&mut log, &command);
                        authorize(&mut log, &key, &attempt).expect("authorize");
                        log.settle_attempt(&key, &attempt, ConnectorVerdict::Applied, RETRY_CAP, None)
                            .expect("settle applied");
                    }
                    DeadLettered => {
                        let attempt = admit_and_claim(&mut log, &command);
                        log.settle_attempt(
                            &key,
                            &attempt,
                            ConnectorVerdict::Failed {
                                kind: FailureKind::Deterministic,
                                evidence: EffectEvidence::ProvenNoWire,
                            },
                            RETRY_CAP,
                            None,
                        )
                        .expect("settle dead-lettered");
                    }
                    UndoChild => {
                        // The forward parent applies through a real bus, then its undo child
                        // is admitted and left PENDING behind a live same-resource peer —
                        // the shape the double-drive race is about, and an ordinary active operation here.
                        let mut bus = CommandBus::new(
                            SqliteIntentLog::open(&path).expect("open bus"),
                            UndoStageConnector::single(false, true),
                        );
                        bus.execute(&command).expect("the forward applies");
                        let peer_key = format!("k-peer-{rotation}-{step}");
                        {
                            let mut peer_log = SqliteIntentLog::open(&path).expect("open peer");
                            let peer = archive_of(&peer_key, &message);
                            admit(&mut peer_log, &peer);
                        }
                        expected_active.push(peer_key);
                        bus.connector()
                            .set_state(atoms(&[("membership:INBOX", false)]));
                        assert!(matches!(bus.undo(&key), Err(ExecuteError::InProgress)));
                        let child = undo_child_key(&opaque_intent_id(&path, &key));
                        assert_eq!(status_str(&path, &child), "pending");
                        expected_active.push(child);
                    }
                }
            }
        }

        // The store's OWN answer to "which operations are active", read before the sever.
        let active_before: Vec<String> = {
            let conn = raw_conn(&path);
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT idempotency_key FROM intents WHERE status IN \
                     {NON_TERMINAL_STATUS_SQL} ORDER BY seq;"
                ))
                .expect("prepare");
            let keys = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .expect("query")
                .map(|k| k.expect("row"))
                .collect();
            keys
        };
        expected_active.sort();
        let mut active_sorted = active_before.clone();
        active_sorted.sort();
        assert_eq!(
            active_sorted, expected_active,
            "rotation {rotation}: the shapes and the store must agree on what is ACTIVE \
             before the sever"
        );

        let mut log = SqliteIntentLog::open(&path).expect("reopen");
        let severed = log.sever("authority:operator-total", &sever_now()).expect("sever");
        let witnessed = witnessed_operations(&path, &severed.witness);

        // EXACTLY ONCE, and only for the active.
        let mut witnessed_keys: Vec<String> = witnessed
            .iter()
            .map(|op| {
                raw_conn(&path)
                    .query_row(
                        "SELECT idempotency_key FROM intents WHERE intent_id = ?1;",
                        rusqlite::params![op],
                        |r| r.get::<_, String>(0),
                    )
                    .unwrap_or_else(|e| panic!("member '{op}' is not an operation: {e}"))
            })
            .collect();
        witnessed_keys.sort();
        assert_eq!(
            witnessed_keys, expected_active,
            "rotation {rotation}: every ACTIVE operation appears EXACTLY ONCE and every \
             lifecycle-terminal one is ABSENT"
        );
        assert_eq!(
            severed.witness.member_count() as usize,
            expected_active.len(),
            "rotation {rotation}: the member COUNT is the active-operation count"
        );
        verify_sever_witness(&witness_row(&path, severed.epoch))
            .unwrap_or_else(|e| panic!("rotation {rotation}: the witness must reconcile: {e:?}"));
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn issue_62_witness_3_a_stale_drive_across_a_sever_classifies_by_facts_and_never_dispatches() {
    // ═══ DOUBLE-DRIVE WITNESS 3 ═══
    //   "3. The sever/arbiter variant: the same interleave across an epoch bump classifies
    //       via facts, never re-dispatches."
    // The topology is witnesses 1/2's exactly: two buses over ONE SQLite store, B holding a
    // stale `Pending` read of the undo child taken before anything moved. What moves under
    // B this time is a SEVER — a third driver bumping the epoch, witnessing the child and
    // closing it in one transaction. B's drive must classify from the durable FACTS the
    // sever wrote, refuse, and never reach the wire.
    let path = unique_temp_db_path("issue62-w3-sever-interleave");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus_a = CommandBus::new(SqliteIntentLog::open(&path).expect("open A"), wire.clone());
    let mut bus_b = CommandBus::new(SqliteIntentLog::open(&path).expect("open B"), wire.clone());

    bus_a.execute(&archive_cmd("k-62-w3")).expect("the forward archive applies");
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    // The undo child is admitted but DEFERRED behind a live same-resource predecessor, so
    // it sits `Pending` — the row both drivers read.
    seed_pending_peer(&path, &bus_a, "k-62-w3-peer");
    assert!(matches!(bus_a.undo("k-62-w3"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-62-w3"));
    terminalize_peer(&path, "k-62-w3-peer");

    // ── B's sweep read, taken BEFORE the sever: the stale `Pending` read the race depends on. ──
    let stale_child = bus_b
        .log()
        .get(&child_key)
        .unwrap()
        .expect("B sees the Pending child");
    assert_eq!(stale_child.status, IntentStatus::Pending, "precondition: B's read is Pending");

    // ── THE SEVER, from a third driver (the seizing authority is not a dispatcher). ──
    let severed = {
        let mut control = SqliteIntentLog::open(&path).expect("open control");
        control.sever("authority:kill-switch", &sever_now()).expect("sever")
    };
    assert_eq!(
        member_class(&severed.witness, &opaque_intent_id(&path, &child_key)),
        Some(crate::attempt::WitnessClass::NoActiveAttempt),
        "the never-claimed undo child is witnessed as an OperationMember"
    );
    assert_eq!(status_str(&path, &child_key), "severed", "…and closed by the sever");

    // ── B DRIVES ITS STALE READ, across the epoch bump. ──
    let outcome = bus_b.drive_undo_child(&stale_child);

    assert_eq!(
        wire.wire().restore_call_count(),
        0,
        "#62 witness 3: the stale drive must not reach the wire across a sever"
    );
    assert!(
        wire.wire().restored().is_empty(),
        "…and no captured P is written over anything, got {:?}",
        wire.wire().restored()
    );
    // …and it CLASSIFIES rather than parks. The transaction that moved
    // the epoch is the SEVER, and §5.2c has it close every active operation with no live
    // attempt in that same write — the assertion three lines above proves it did exactly
    // that to this child. `InProgress` about a row that is `severed` forever is the 
    // defect one door over: nothing will ever sweep it again. The wire property this
    // witness exists for (no dispatch, no CLAIM under a stale epoch) is unchanged.
    assert_eq!(
        outcome,
        Err(ExecuteError::Severed),
        "a losing racer across a sever answers the SEVER — never a silent Ok, and never \
         'in flight' about a row the kill switch closed; got {outcome:?}"
    );
    assert_eq!(
        bus_b.undo("k-62-w3"),
        Err(ExecuteError::Severed),
        "…which is exactly what an identical replay reads (§7a)"
    );
    // CLASSIFIED VIA FACTS, never re-dispatched: no CLAIM was ever taken on the child, so
    // the sever's OperationMember classification is still the whole truth about it.
    let child_op = opaque_intent_id(&path, &child_key);
    assert_eq!(
        claim_count(&path, &child_op),
        0,
        "the refused drive appended no CLAIM under the stale epoch"
    );
    assert_eq!(status_str(&path, &child_key), "severed", "…and nothing re-opened it");
    assert_eq!(
        status_str(&path, "k-62-w3"),
        "applied",
        "the parent stays truthfully applied — the undo never ran"
    );
    // Stage 4 (presentation gap closed): the sever that closed the undo child
    // is surfaced distinctly from `bus_b`'s own presentation projection — never silently
    // indistinguishable from "no undo was ever attempted" (`None`) and never conflated with
    // a provider `Failed`.
    assert_eq!(
        bus_b.undo_presentation("k-62-w3").expect("presentation").map(|r| r.presentation),
        Some(UndoPresentation::AppliedUndoSevered),
        "a severed undo child must be surfaced distinctly, not silently folded into \
         \"nothing to say\" or a provider failure"
    );
    verify_sever_witness(&witness_row(&path, severed.epoch)).expect("the witness reconciles");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_completed_operations_live_attempt_is_absent_from_the_witness_and_fenced_at_the_socket() {
    // §5.2c bullet 1 (COMPLETED ⇒ ABSENT) and the BELT it leaves behind, together. An
    // operation whose LIFECYCLE is already terminal is absent from the witness even if an
    // attempt of its own is still live — the partition is at OPERATION grain. The attempt
    // is therefore NOT closed by the sever, and §5.2c's "the issuance gate's post-sever
    // refusal remains the belt" is what stops it: the send-auth fence refuses it and
    // terminalizes it `SEVERED_BEFORE_ISSUANCE` in its own transaction.
    //
    // The state is reconstructed by direct SQL because no fault injection can stop the
    // engine between two of its own statements: it is the crash window in which a peer
    // settled the OPERATION while this driver still held a claimed, unauthorized attempt.
    let path = unique_temp_db_path("seize-completed-absent");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let command = archive_of("k-completed", "msg-completed");
    let attempt = admit_and_claim(&mut log, &command);
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'applied' WHERE idempotency_key = 'k-completed';",
            [],
        )
        .expect("a peer settled the operation under this driver");

    let severed = log.sever("authority:operator-belt", &sever_now()).expect("sever");

    assert_eq!(
        severed.witness.member_count(),
        0,
        "a LIFECYCLE-TERMINAL operation is ABSENT from the witness (§5.2c bullet 1), \
         whatever its attempts say"
    );
    assert_eq!(severed.terminalized, 0);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim"],
        "…so the sever wrote nothing to its live attempt"
    );
    // THE BELT.
    assert_eq!(
        authorize(&mut log, "k-completed", &attempt).expect("fence"),
        SendAuthOutcome::EpochFenced,
        "the post-sever issuance gate refuses what the sever could not see"
    );
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "severed_before_issuance"],
        "…terminalizing it in the refusing transaction"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt),
        0,
        "no authorization ever existed under the new epoch"
    );
    assert_eq!(
        status_str(&path, "k-completed"),
        "applied",
        "and the operation's already-terminal status is never overwritten"
    );
    // An empty sever is a real, witnessable event — the count is 0 and the row still
    // reconciles (the pure core's own zero-member arm, now durable).
    verify_sever_witness(&witness_row(&path, severed.epoch)).expect("an empty sever reconciles");
    std::fs::remove_file(&path).ok();
}

/// The undo drive's PROVIDER READ, used as the one place an engine CAN be stopped between
/// two of its own statements: `drive_undo_child` observes `C` after its CLAIM and before
/// the send-authorization fence, so a peer acting inside `observe` lands exactly in the
/// window §5.2c's "belt" describes — a live, unauthorized attempt whose OPERATION a peer
/// has already closed, meeting a bumped control epoch at the fence.
struct SeverInsideTheObserveWindow {
    wire: UndoStageConnector,
    path: std::path::PathBuf,
    armed: std::cell::Cell<bool>,
}

impl SeverInsideTheObserveWindow {
    fn new(path: &std::path::Path) -> Self {
        Self {
            wire: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::Cell::new(false),
        }
    }
    /// Arm the peer for the NEXT observation only (the forward pass observes too).
    fn arm(&self) {
        self.armed.set(true);
    }
}

impl Connector for SeverInsideTheObserveWindow {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.wire.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.wire.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        let observed = self.wire.observe(command, basis)?;
        if self.armed.replace(false) {
            // A peer SETTLES the child operation (the crash/race shape §5.2c bullet 1
            // names: a lifecycle-terminal operation is ABSENT from a sever's witness, so
            // its live attempt survives the sever unclosed)…
            raw_conn(&self.path)
                .execute(
                    "UPDATE intents SET status = 'failed'
                          WHERE kind = 'undo' AND status = 'pending';",
                    [],
                )
                .expect("a peer settled the child under this driver");
            // …and an authority SEVERS, bumping the control epoch under the live claim.
            SqliteIntentLog::open(&self.path)
                .expect("the peer's connection")
                .sever("authority:operator-r8", &sever_now())
                .expect("sever");
        }
        Ok(observed)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.wire.restore(command, basis, p)
    }
}

#[test]
fn an_epoch_fenced_restore_answers_exactly_what_a_replay_answers() {
    // Arm 2 — the §5.2b epoch fence, seen from the CALLER. The refusing
    // transaction is the one that terminalizes (`SEVERED_BEFORE_ISSUANCE` + the operation's
    // lifecycle), so by the time `authorize_send` answers, the row is terminal FOREVER.
    // Reporting `InProgress` there is the drive telling its caller to wait for a
    // compensation the ledger has closed — while an identical replay, one call later,
    // answers the terminal through the ONE truth table.
    let path = unique_temp_db_path("r8-epoch-fenced-answer");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        SeverInsideTheObserveWindow::new(&path),
    );
    bus.execute(&archive_cmd("k-fence"))
        .expect("the forward archive applies, capturing P = {INBOX: true}");
    // The provider now holds the forward target, so the undo requalifies to RESTORE — the
    // ONE §3.2 arm that reaches the send-authorization fence.
    bus.connector()
        .wire
        .set_state(atoms(&[("membership:INBOX", false)]));
    bus.connector().arm();

    let answer = bus.undo("k-fence");

    assert_eq!(
        raw_conn(&path)
            .query_row(
                "SELECT status FROM intents WHERE kind = 'undo';",
                [],
                |r| r.get::<_, String>(0)
            )
            .expect("the child row"),
        "failed",
        "precondition: the child is terminal by the time the fence answered"
    );
    assert_eq!(
        bus.connector().wire.restore_call_count(),
        0,
        "precondition: the fence refused pre-wire — no restore was dispatched"
    );

    let replay = bus.undo("k-fence");
    assert_eq!(
        replay,
        Err(ExecuteError::Failed),
        "precondition: the replay reads the closed child through the truth table"
    );
    assert_eq!(
        answer, replay,
        "the drive must surface the terminal the fence's own transaction wrote, never an \
         in-flight signal for a compensation that is closed forever"
    );
    std::fs::remove_file(&path).ok();
}

/// What a PEER does inside [`PeerInsideTheObserveWindow`]'s window — the two shapes that
/// make the send-authorization door answer a GRAMMAR REFUSAL rather than a fence, split by
/// what they leave the OPERATION as. Both are the same window the belt describes (a live
/// claim, observed, not yet authorized); they differ only in what the peer writes.
enum ObserveWindowPeer {
    /// SEVER over the live, unauthorized claim — so §5.2c's `ClosedBeforeIssuance`
    /// disposition terminalizes the ATTEMPT (`SEVERED_BEFORE_ISSUANCE`) and the OPERATION
    /// (`Severed`) in the sever's own transaction. Our later `authorize_send` then meets a
    /// chain that is already closed and refuses `PostTerminalAppend` — a grammar refusal
    /// over a row that is terminal forever.
    SeverOverTheLiveClaim,
    /// AUTHORIZE the same live claim — an equally-current peer spending the wire first. The
    /// operation stays open, and our own append refuses `DuplicateSendAuthorized`.
    AuthorizeTheLiveClaim,
}

/// The belt's window again ([`SeverInsideTheObserveWindow`]), aimed at the arm the 
/// earlier fix deliberately left open: the GRAMMAR refusals. Same seam — `drive_undo_child`
/// observes `C` after its CLAIM and before the send-authorization fence — but the peer here
/// leaves the claim LIVE, so `authorize_send` answers `RefusedByGrammar` instead of
/// `EpochFenced`.
struct PeerInsideTheObserveWindow {
    wire: UndoStageConnector,
    path: std::path::PathBuf,
    peer: ObserveWindowPeer,
    armed: std::cell::Cell<bool>,
}

impl PeerInsideTheObserveWindow {
    fn new(path: &std::path::Path, peer: ObserveWindowPeer) -> Self {
        Self {
            wire: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            peer,
            armed: std::cell::Cell::new(false),
        }
    }
    /// Arm the peer for the NEXT observation only (the forward pass observes too).
    fn arm(&self) {
        self.armed.set(true);
    }
    /// The undo child's key and the attempt this driver claimed a moment ago, read from the
    /// ledger the way a genuinely separate process would have to.
    fn live_undo_claim(&self) -> (String, String) {
        raw_conn(&self.path)
            .query_row(
                "SELECT i.idempotency_key, h.attempt_id
                       FROM attempt_head h JOIN intents i ON i.intent_id = h.operation_id
                      WHERE i.kind = 'undo';",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("the undo child holds a claimed attempt")
    }
}

impl Connector for PeerInsideTheObserveWindow {
    fn apply(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<(), ConnectorError> {
        self.wire.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.wire.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        let observed = self.wire.observe(command, basis)?;
        if self.armed.replace(false) {
            match self.peer {
                ObserveWindowPeer::SeverOverTheLiveClaim => {
                    SqliteIntentLog::open(&self.path)
                        .expect("the peer's connection")
                        .sever("authority:operator-preempt", &sever_now())
                        .expect("sever");
                }
                ObserveWindowPeer::AuthorizeTheLiveClaim => {
                    let (key, attempt) = self.live_undo_claim();
                    let mut peer =
                        SqliteIntentLog::open(&self.path).expect("the peer's connection");
                    let authorized =
                        authorize(&mut peer, &key, &attempt).expect("the peer authorizes");
                    assert!(
                        matches!(authorized, SendAuthOutcome::Authorized { .. }),
                        "precondition: the peer really did spend this attempt's one \
                         authorization"
                    );
                }
            }
        }
        Ok(observed)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.wire.restore(command, basis, p)
    }
}

#[test]
fn a_grammar_refused_authorization_over_a_terminal_row_answers_what_a_replay_answers() {
    // ═══ PREEMPTIVE FIX — the hole the earlier fix's own scoping note named ═══
    //  closed the two TERMINALIZING refusals (`EpochFenced`, `ExposureBlocked`) and wrote,
    // at the door, that the re-read was "scoped to those two ANSWERS, not to 'any terminal
    // row'". This is the trace that makes the leftover arm bite, and it needs no new
    // machinery — only the ORDER §5.2c already permits:
    //
    //   1. the drive CLAIMS the undo child (live attempt, unauthorized);
    //   2. a sever lands inside `observe` — §5.2c's `ClosedBeforeIssuance` disposition, so
    //      the SEVER's transaction appends `SEVERED_BEFORE_ISSUANCE` to that very attempt
    //      and terminalizes the operation `Severed`;
    //   3. our `authorize_send` reaches the epoch fence, tries to write the same closure,
    //      and the grammar refuses it `PostTerminalAppend` — because the sever already did.
    //
    // The refusal is a GRAMMAR refusal, so the door parked: `InProgress`, forever, over a
    // row that is `Severed` forever and will never appear in `unreconciled()` again. Same
    // defect named, reached through the arm left.
    let path = unique_temp_db_path("s4-preempt-grammar-terminal");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerInsideTheObserveWindow::new(&path, ObserveWindowPeer::SeverOverTheLiveClaim),
    );
    bus.execute(&archive_cmd("k-preempt"))
        .expect("the forward archive applies, capturing P = {INBOX: true}");
    // The provider holds the forward target, so the undo requalifies to RESTORE — the ONE
    // §3.2 arm that reaches the send-authorization fence.
    bus.connector()
        .wire
        .set_state(atoms(&[("membership:INBOX", false)]));
    bus.connector().arm();

    let answer = bus.undo("k-preempt");

    let child_key: String = raw_conn(&path)
        .query_row(
            "SELECT idempotency_key FROM intents WHERE kind = 'undo';",
            [],
            |r| r.get(0),
        )
        .expect("the child row");
    assert_eq!(
        status_str(&path, &child_key),
        "severed",
        "precondition: the SEVER's own transaction closed the child"
    );
    assert_eq!(
        chain_kinds(&path, &attempt_of(&path, &child_key)),
        vec!["claim", "severed_before_issuance"],
        "precondition: …and closed its live attempt, which is WHY the later \
         `authorize_send` refuses through the grammar rather than the fence"
    );
    assert_eq!(
        bus.connector().wire.restore_call_count(),
        0,
        "precondition: the refusal was pre-wire — no restore was dispatched"
    );

    let replay = bus.undo("k-preempt");
    assert_eq!(
        replay,
        Err(ExecuteError::Severed),
        "precondition: the replay reads the closed child through the ONE truth table"
    );
    assert_eq!(
        answer, replay,
        "a GRAMMAR-refused authorization owes its caller exactly what a replay owes it — \
         never `InProgress` about a compensation the sever closed forever"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_grammar_refused_authorization_over_a_still_live_row_still_parks() {
    // THE FENCE on the arm above: the re-read decides from the ROW, so the losing racer of
    // a still-live peer must keep parking. An equally-current driver authorized this very
    // attempt first; our append refuses `DuplicateSendAuthorized`; the operation is open,
    // nothing of ours reached the wire, and `InProgress` is the honest signal — the peer
    // (or recovery) genuinely does own it. Turning THIS into a terminal answer would be the
    // mirror-image lie of the one the test above closes.
    let path = unique_temp_db_path("s4-preempt-grammar-live");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerInsideTheObserveWindow::new(&path, ObserveWindowPeer::AuthorizeTheLiveClaim),
    );
    bus.execute(&archive_cmd("k-live"))
        .expect("the forward archive applies, capturing P = {INBOX: true}");
    bus.connector()
        .wire
        .set_state(atoms(&[("membership:INBOX", false)]));
    bus.connector().arm();

    let answer = bus.undo("k-live");

    let child_key: String = raw_conn(&path)
        .query_row(
            "SELECT idempotency_key FROM intents WHERE kind = 'undo';",
            [],
            |r| r.get(0),
        )
        .expect("the child row");
    assert_eq!(
        answer,
        Err(ExecuteError::InProgress),
        "a superseded racer over an OPEN row parks — the re-read must not manufacture a \
         terminal the ledger has not written"
    );
    assert_eq!(
        status_str(&path, &child_key),
        "pending",
        "…and the child is still open, which is exactly why parking is honest"
    );
    assert_eq!(
        send_authorized_count(&path, &attempt_of(&path, &child_key)),
        1,
        "the peer's authorization is the only one: at most one per attempt (§5.2a)"
    );
    assert_eq!(
        bus.connector().wire.restore_call_count(),
        0,
        "and this driver never touched the wire"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_sever_refuses_an_authority_reference_that_is_not_a_reference() {
    // §5.1 records the seizing authority BY REFERENCE. This door enforces the SHAPE of
    // that reference and says so: a witness with no authority is not evidence, and a
    // reference is a token rather than free text. (What a reference MEANS is the caller's
    // authority model — an on-box engine cannot check it. Out of scope (code already running with the user's privileges), stated at the door.)
    let path = unique_temp_db_path("seize-authority-shape");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    for bad in ["", "   ", "operator\nwith a newline"] {
        let refused = log.sever(bad, &sever_now());
        assert!(refused.is_err(), "authority '{bad}' must be refused, got {refused:?}");
    }
    assert!(
        log.sever(&"x".repeat(257), &sever_now()).is_err(),
        "an unbounded reference is refused"
    );
    // NOTHING was bumped or written by any refusal: the door validates before it opens.
    let epoch: i64 = raw_conn(&path)
        .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| r.get(0))
        .expect("epoch");
    assert_eq!(epoch, 1, "a refused sever never bumps the fence");
    assert!(witness_rows(&path).is_empty(), "…and writes no witness");
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_in_memory_sever_derives_the_same_partition_over_its_mirror() {
    // The in-memory door is the SAME semantics over its maps — the §5.2c partition, the
    // canonical digest, and the atomic closure. (Its operation ids are its idempotency
    // KEYS, the stated premise every attempt door on this log carries, so the durable
    // witness's content-blindness is witnessed on the SQLite arm, which is where §5.1's
    // row lives.)
    let mut log = InMemoryIntentLog::new();
    let never = archive_of("k-mem-never", "msg-1");
    let claimed = archive_of("k-mem-claimed", "msg-2");
    let authorized = archive_of("k-mem-authorized", "msg-3");
    for command in [&never, &claimed, &authorized] {
        let basis = UndoStageConnector::single(false, true)
            .resolve_basis(command)
            .expect("basis");
        log.record(command, &basis).expect("admit");
    }
    let claimed_attempt = match log
        .claim_attempt(
            "k-mem-claimed",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("won, got {other:?}"),
    };
    let authorized_attempt = match log
        .claim_attempt(
            "k-mem-authorized",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("won, got {other:?}"),
    };
    authorize(&mut log, "k-mem-authorized", &authorized_attempt)
        .expect("authorize");

    let severed = log.sever("authority:mem-operator", &sever_now()).expect("sever");

    use crate::attempt::WitnessClass;
    assert_eq!(severed.epoch, 2, "the mirror's fence is seeded 1 and bumped once");
    assert_eq!(severed.witness.member_count(), 3);
    assert_eq!(
        member_class(&severed.witness, "k-mem-never"),
        Some(WitnessClass::NoActiveAttempt)
    );
    assert_eq!(
        member_class(&severed.witness, &claimed_attempt),
        Some(WitnessClass::SeveredBeforeIssuance)
    );
    assert_eq!(
        member_class(&severed.witness, &authorized_attempt),
        Some(WitnessClass::IssuedOrUnknown)
    );
    assert_eq!(
        severed.witness.digest,
        crate::attempt::sever_witness_digest_hex(&severed.witness.members),
        "the same canonical digest authority as the durable door"
    );
    assert_eq!(
        log.get("k-mem-never").unwrap().unwrap().status,
        IntentStatus::Severed
    );
    assert_eq!(
        log.get("k-mem-claimed").unwrap().unwrap().status,
        IntentStatus::Severed
    );
    assert_eq!(
        log.get("k-mem-authorized").unwrap().unwrap().status,
        IntentStatus::Pending,
        "ISSUED_OR_UNKNOWN stays active here too"
    );
    assert_eq!(log.sever_witnesses().len(), 1, "the mirror keeps the witness");
    // The fence the sever armed: a post-sever authorization of the claim taken under the
    // old epoch refuses (the belt, mirrored).
    // The BELT arm, mirrored: an operation whose LIFECYCLE is already terminal is ABSENT
    // from the witness (§5.2c bullet 1), so the sever cannot close its still-live attempt
    // — the issuance gate is what refuses it.
    let late = archive_of("k-mem-late", "msg-4");
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(&late)
        .expect("basis");
    log.record(&late, &basis).expect("admit");
    let late_attempt = match log
        .claim_attempt(
            "k-mem-late",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("won, got {other:?}"),
    };
    log.set_status_forced("k-mem-late", IntentStatus::Applied)
        .expect("a peer settled the operation under this driver");
    let second = log
        .sever("authority:mem-operator-2", &sever_now())
        .expect("a second sever");
    assert_eq!(
        member_class(&second.witness, &late_attempt),
        None,
        "the lifecycle-terminal operation is ABSENT from the second witness, live attempt              and all (§5.2c bullet 1 is at OPERATION grain)"
    );
    assert_eq!(
        member_class(&second.witness, &authorized_attempt),
        Some(WitnessClass::IssuedOrUnknown),
        "…while the still-active unknown is witnessed again, by every sever it survives"
    );
    assert_eq!(second.witness.member_count(), 1);
    assert_eq!(
        authorize(&mut log, "k-mem-late", &late_attempt).expect("fence"),
        SendAuthOutcome::EpochFenced,
        "…and a claim taken under the older epoch can never be authorized"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════
// The PUBLIC control-epoch reader (design §2 S3's `session_status` epoch/
// severed state). `SqliteIntentLog::control_epoch` reads the same singleton row every
// internal fence reads; it invents no second query form.
// ═══════════════════════════════════════════════════════════════════════════════════

#[test]
fn t9b_control_epoch_reads_the_seeded_singleton_and_the_post_sever_bump() {
    let path = unique_temp_db_path("t9b-control-epoch");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    assert_eq!(
        log.control_epoch().expect("read epoch"),
        1,
        "a fresh store is seeded at epoch 1, exactly as `store_open`'s bootstrap seeds it"
    );

    log.sever("authority:t9b-operator", &sever_now())
        .expect("sever");

    assert_eq!(
        log.control_epoch().expect("read epoch"),
        2,
        "sever is the singleton's only writer, and it bumps epoch 1 → 2"
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// SEVER COALESCING: ONE bump per service, the child attribution table,
// durable acks. The windows are design :786-820, transcribed exactly:
//   · a request arriving while a service is PENDING OR SERVING shares that service —
//     one epoch bump total;
//   · in-snapshot arrivals (before the leader's witness snapshot closes, ≤
//     `sever_joiner_cap`) are recorded as `sever_attribution` rows committed ATOMICALLY
//     in the LEADER's transaction;
//   · overflow joiners AND post-snapshot arrivals get NO second bump and NO new ticket —
//     each appends its OWN durable row against the already-bumped epoch and returns the
//     shared outcome only after that row is durable;
//   · a NEW service/ticket exists ONLY for a request arriving after the prior service
//     has COMPLETED.
//
// TIMING-FREE. The service window is widened by a REAL SQLite write-lock blocker (the
// writer-gate pattern): the leader's `BEGIN IMMEDIATE` parks inside SQLite's own busy
// machinery while the joiners — whose `begin_sever` is pure gate state — arrive. Every
// wait is a spin on GATE STATE or on STORE STATE, never on a clock; the hang guard is a
// deadlock diagnostic, not a latency assertion.
// ═══════════════════════════════════════════════════════════════════════════════════

/// A store whose `sever_joiner_cap` is 1 — the small-cap fixture that makes the OVERFLOW
/// window reachable with a handful of threads instead of seventeen.
fn t7_small_cap_config() -> crate::capacity::CapacityConfig {
    crate::capacity::CapacityConfig {
        max_active_ops: 64,
        undo_reserve: 1,
        writer_chunk_budget_ms: 50,
        sever_watchdog_ms: 5000,
        sever_joiner_cap: 1,
    }
}

fn t7_epoch(path: &std::path::Path) -> i64 {
    raw_conn(path)
        .query_row("SELECT epoch FROM control_epoch WHERE id = 1;", [], |r| {
            r.get(0)
        })
        .expect("control epoch")
}

/// `(epoch, authority_ref)` per witness row, oldest epoch first. The `authority_ref` is the
/// LEADER's — that is how a witness names which requester actually served.
fn t7_witness_rows(path: &std::path::Path) -> Vec<(i64, String)> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare("SELECT epoch, authority_ref FROM sever_witness ORDER BY epoch;")
        .expect("witness prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("witness read")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("witness read");
    rows
}

/// `(epoch, requester_ref, kind)` per attribution row, in insert order.
fn t7_attribution_rows(path: &std::path::Path) -> Vec<(i64, String, String)> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT epoch, requester_ref, kind FROM sever_attribution
                  ORDER BY rowid;",
        )
        .expect("attribution prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("attribution read")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("attribution read");
    rows
}

/// A writer that CHURNS against the same store for the whole service window: repeated
/// enrolled `record` calls on ONE key (the second and later ones land on
/// `ON CONFLICT DO NOTHING`, so occupancy never grows and the capacity door never
/// refuses). Returns `(stop flag, successes, handle)`.
#[allow(clippy::type_complexity)]
fn t7_spawn_churn(
    path: &std::path::Path,
    key: &str,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::thread::JoinHandle<Option<String>>,
) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let mut log = SqliteIntentLog::open(path).expect("churn open");
    let command = archive_of(key, &format!("m-{key}"));
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(&command)
        .expect("basis");
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let successes = std::sync::Arc::new(AtomicUsize::new(0));
    let handle = {
        let (stop, successes) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&successes));
        std::thread::spawn(move || {
            let mut first_error = None;
            while !stop.load(Ordering::SeqCst) {
                match log.record(&command, &basis) {
                    Ok(_) => {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => {
                        first_error.get_or_insert(e.0);
                        break;
                    }
                }
            }
            drop(log);
            first_error
        })
    };
    (stop, successes, handle)
}

#[test]
fn coalesced_severs_share_one_epoch_bump() {
    // design :786-820. K=4 concurrent `sever()` calls on ONE store while a writer churns:
    // exactly ONE `control_epoch` increment, ONE `sever_witness` row, every call returns
    // the SAME outcome, and `sever_attribution` carries one row per NON-leader requester
    // with the right kinds (cap 1 ⇒ one in-snapshot joiner, the rest overflow).
    use std::sync::atomic::Ordering;
    let path = unique_temp_db_path("t7-coalesce");
    let mut log0 = SqliteIntentLog::open(&path).expect("bootstrap + open");
    log0.record_capacity_config(t7_small_cap_config())
        .expect("the small-cap fixture");
    admit(&mut log0, &archive_of("k-t7c-a", "m-a"));
    admit(&mut log0, &archive_of("k-t7c-b", "m-b"));

    let severers: Vec<SqliteIntentLog> = (0..4)
        .map(|_| SqliteIntentLog::open(&path).expect("requester open"))
        .collect();
    let (stop, churned, churn) = t7_spawn_churn(&path, "k-t7c-churn");
    t6a_spin_until("the churning writer has written at least once", || {
        churned.load(Ordering::SeqCst) >= 1
    });

    let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
    // THE BLOCKER: TEST MACHINERY ONLY — a raw, ungated connection holding the store's one
    // SQL write lock so the leader's `BEGIN IMMEDIATE` parks while the joiners arrive.
    let blocker = raw_conn(&path);
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the coalescing blocker holds the write lock");

    let refs: Vec<String> = (0..4).map(|i| format!("authority:t7c-req-{i}")).collect();
    let mut handles = Vec::new();
    for (i, mut log) in severers.into_iter().enumerate() {
        let requester = refs[i].clone();
        handles.push(std::thread::spawn(move || {
            let outcome = log.sever(&requester, &sever_now());
            drop(log);
            outcome
        }));
    }
    t6a_spin_until("all three non-leaders joined the ONE open service", || {
        let s = observer.snapshot().expect("snapshot");
        s.service_open
            && s.in_snapshot_joiners + s.overflow_joiners + s.post_snapshot_requests == 3
    });
    blocker
        .execute_batch("ROLLBACK;")
        .expect("release the write lock");
    drop(blocker);

    let outcomes: Vec<SeverOutcome> = handles
        .into_iter()
        .map(|h| h.join().expect("sever thread").expect("sever answers"))
        .collect();
    stop.store(true, Ordering::SeqCst);
    assert_eq!(churn.join().expect("churn thread"), None, "the churn writer");

    // ── ONE bump, ONE witness ──
    assert_eq!(t7_epoch(&path), 2, "four coalesced requests, ONE epoch bump");
    let witnesses = t7_witness_rows(&path);
    assert_eq!(witnesses.len(), 1, "ONE service ⇒ ONE witness row");
    let (witness_epoch, leader_ref) = witnesses[0].clone();
    assert_eq!(witness_epoch, 2);
    assert!(refs.contains(&leader_ref), "the witness names a requester");

    // ── ONE shared outcome ──
    for outcome in &outcomes {
        assert_eq!(
            outcome, &outcomes[0],
            "every coalesced requester returns the ONE shared outcome"
        );
    }
    assert_eq!(outcomes[0].epoch, 2);
    assert_eq!(outcomes[0].witness.authority_ref, leader_ref);
    assert!(
        outcomes[0].terminalized >= 1,
        "the service did real work: {outcomes:?}"
    );

    // ── one attribution row per NON-leader, right kinds ──
    let rows = t7_attribution_rows(&path);
    assert!(
        rows.iter().all(|(epoch, _, _)| *epoch == 2),
        "every attribution lands against the ONE bumped epoch: {rows:?}"
    );
    let mut recorded: Vec<String> = rows.iter().map(|(_, r, _)| r.clone()).collect();
    recorded.sort();
    let mut expected: Vec<String> = refs.iter().filter(|r| **r != leader_ref).cloned().collect();
    expected.sort();
    assert_eq!(
        recorded, expected,
        "one durable row per non-leader requester — the leader's own attribution is its \
         witness row's authority_ref"
    );
    let kinds = |k: &str| rows.iter().filter(|(_, _, kind)| kind == k).count();
    assert_eq!(
        (kinds("in-snapshot"), kinds("overflow-joiner"), kinds("post-snapshot")),
        (1, 2, 0),
        "cap 1 ⇒ exactly ONE in-snapshot joiner rides the leader's transaction; the rest \
         overflow and append their own: {rows:?}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn a_new_service_begins_only_after_the_prior_completes() {
    // The store-level twin of the gate witness (writer_gate.rs). A request arriving while
    // a service is pending/serving NEVER mints a ticket and NEVER bumps a second epoch; a
    // request arriving after the prior service COMPLETED gets its own bump, and the epochs
    // of DISTINCT services land in ticket order.
    let path = unique_temp_db_path("t7-one-service");
    let mut log0 = SqliteIntentLog::open(&path).expect("bootstrap + open");
    log0.record_capacity_config(t7_small_cap_config())
        .expect("the small-cap fixture");
    admit(&mut log0, &archive_of("k-t7n-a", "m-a"));

    let mut leaderish: Vec<SqliteIntentLog> = (0..2)
        .map(|_| SqliteIntentLog::open(&path).expect("requester open"))
        .collect();
    let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
    assert_eq!(observer.snapshot().expect("snapshot").next_ticket, 1);

    // ── SERVICE ONE: two requests, coalesced ──
    let blocker = raw_conn(&path);
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the one-service blocker holds the write lock");
    let mut second = leaderish.pop().expect("two requesters");
    let mut first = leaderish.pop().expect("two requesters");
    let a = std::thread::spawn(move || {
        let out = first.sever("authority:t7n-first", &sever_now());
        (out, first)
    });
    t6a_spin_until("the first request opened a service", || {
        observer.snapshot().expect("snapshot").service_open
    });
    let b = std::thread::spawn(move || {
        let out = second.sever("authority:t7n-second", &sever_now());
        (out, second)
    });
    t6a_spin_until("the second request JOINED rather than ticketed", || {
        let s = observer.snapshot().expect("snapshot");
        s.in_snapshot_joiners + s.overflow_joiners + s.post_snapshot_requests == 1
    });
    assert_eq!(
        observer.snapshot().expect("snapshot").next_ticket,
        2,
        "a joiner mints NO ticket — one service has been ticketed, not two"
    );
    blocker
        .execute_batch("ROLLBACK;")
        .expect("release the write lock");
    drop(blocker);
    let (out_a, mut log_a) = a.join().expect("first thread");
    let (out_b, log_b) = b.join().expect("second thread");
    let out_a = out_a.expect("first answers");
    let out_b = out_b.expect("second answers");
    assert_eq!(out_a, out_b, "both requests share the ONE outcome");
    assert_eq!(out_a.epoch, 2);
    assert_eq!(t7_epoch(&path), 2, "TWO requests, ONE bump");
    assert_eq!(t7_witness_rows(&path).len(), 1);
    assert_eq!(t7_attribution_rows(&path).len(), 1, "one non-leader");
    let s = observer.snapshot().expect("snapshot");
    assert_eq!((s.next_ticket, s.serving_ticket, s.sever_pending), (2, 2, 0));
    assert!(!s.service_open, "the service completed");
    drop(log_b);

    // ── SERVICE TWO: a request AFTER completion gets its own ticket and its own bump ──
    admit(&mut log_a, &archive_of("k-t7n-b", "m-b"));
    let out_c = log_a
        .sever("authority:t7n-third", &sever_now())
        .expect("the post-completion request serves itself");
    assert_eq!(out_c.epoch, 3, "a NEW service bumps again");
    assert_eq!(t7_epoch(&path), 3);
    let witnesses = t7_witness_rows(&path);
    assert_eq!(
        witnesses.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
        vec![2, 3],
        "the epochs of DISTINCT services land in ticket order"
    );
    assert_eq!(
        witnesses[1].1, "authority:t7n-third",
        "the second service's leader is the post-completion requester"
    );
    assert_eq!(
        t7_attribution_rows(&path).len(),
        1,
        "a SOLO service records no attribution child — its leader is the witness"
    );
    let s = observer.snapshot().expect("snapshot");
    assert_eq!((s.next_ticket, s.serving_ticket), (3, 3));
    assert_eq!(s.sever_pending, 0, "no ticket outlives its service");

    drop(log_a);
    std::fs::remove_file(&path).ok();
}

#[test]
fn post_snapshot_arrival_gets_no_second_bump() {
    // design :811-820. The join window CLOSES at the leader's witness snapshot — "witness
    // metadata commits atomically per §5.1, a joiner cannot be added to a running
    // transaction". A request landing AFTER that close but BEFORE the service completes
    // therefore needs NO second epoch bump (the leader's bump already stopped every
    // writer) and mints NO ticket; it records its OWN attribution against the
    // already-bumped epoch and returns the shared outcome.
    //
    // The window [close_snapshot .. complete] is entered DETERMINISTICALLY, not by timing:
    // the leader parks on the `AfterCloseSnapshot` seam until it observes the arrival, and
    // the arriving thread parks on gate state until it observes the close. Neither side
    // consults a clock.
    let path = unique_temp_db_path("t7-post-snapshot");
    let mut log0 = SqliteIntentLog::open(&path).expect("bootstrap + open");
    log0.record_capacity_config(t7_small_cap_config())
        .expect("the small-cap fixture");
    admit(&mut log0, &archive_of("k-t7p-a", "m-a"));

    let mut leader_log = SqliteIntentLog::open(&path).expect("leader open");
    let mut post_log = SqliteIntentLog::open(&path).expect("post-snapshot open");
    let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");

    let leader = {
        let seam_gate = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
        std::thread::spawn(move || {
            install_sever_seam(Box::new(move |point, _requester| {
                if point == SeverSeam::AfterCloseSnapshot {
                    t6a_spin_until("a post-snapshot requester arrived", || {
                        seam_gate.snapshot().expect("snapshot").post_snapshot_requests == 1
                    });
                }
            }));
            let outcome = leader_log.sever("authority:t7p-leader", &sever_now());
            (outcome, leader_log)
        })
    };
    t6a_spin_until("the leader's witness snapshot CLOSED", || {
        observer.snapshot().expect("snapshot").snapshot_closed
    });
    let post = post_log
        .sever("authority:t7p-post", &sever_now())
        .expect("the post-snapshot requester answers");
    let (leader_outcome, leader_log) = leader.join().expect("leader thread");
    let leader_outcome = leader_outcome.expect("the leader answers");

    assert_eq!(t7_epoch(&path), 2, "a post-snapshot arrival gets NO second bump");
    assert_eq!(t7_witness_rows(&path).len(), 1, "ONE service, ONE witness");
    assert_eq!(
        post, leader_outcome,
        "the post-snapshot requester returns the SHARED outcome"
    );
    assert_eq!(
        t7_attribution_rows(&path),
        vec![(
            2,
            "authority:t7p-post".to_string(),
            "post-snapshot".to_string()
        )],
        "its OWN durable row against the already-bumped epoch — and nothing else, because \
         the in-snapshot list was empty when the window closed"
    );
    let s = observer.snapshot().expect("snapshot");
    assert_eq!(
        (s.next_ticket, s.serving_ticket, s.sever_pending),
        (2, 2, 0),
        "ONE ticket was ever minted — the post-snapshot requester took none"
    );

    drop(leader_log);
    drop(post_log);
    drop(log0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_seize_admit_unacknowledged_overflow_joiner_crash() {
    // §7c's W-SEIZE-ADMIT gains this arm from design: a crash between the LEADER's
    // commit and an OVERFLOW joiner's own attribution append leaves that request
    // truthfully UNACKNOWLEDGED — absent from the record, never confirmed-then-lost. The
    // kill effect itself was never at risk.
    //
    // THE CRASH SEAM, and why the return path is PROVABLY not reached: the overflow joiner
    // runs on its own thread, which installs a `BeforeAttributionAppend` seam that PANICS.
    // `sever()` therefore unwinds from inside itself and produces NO VALUE AT ALL —
    // `JoinHandle::join()` yields `Err(panic payload)`, not `Ok(Ok(..))` and not
    // `Ok(Err(..))`. There is no branch on which that requester was told anything.
    let path = unique_temp_db_path("t7-unacked-crash");
    let mut log0 = SqliteIntentLog::open(&path).expect("bootstrap + open");
    log0.record_capacity_config(t7_small_cap_config())
        .expect("the small-cap fixture (joiner cap 1 makes OVERFLOW reachable)");
    admit(&mut log0, &archive_of("k-t7u-a", "m-a"));

    let mut leader_log = SqliteIntentLog::open(&path).expect("leader open");
    let mut in_snapshot_log = SqliteIntentLog::open(&path).expect("in-snapshot open");
    let mut overflow_log = SqliteIntentLog::open(&path).expect("overflow open");
    let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");

    // THE BLOCKER (test machinery): holds the store's one SQL write lock so the leader's
    // `BEGIN IMMEDIATE` parks and the roles become deterministic — leader, then exactly one
    // in-snapshot joiner (cap 1), then one overflow joiner.
    let blocker = raw_conn(&path);
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the unacknowledged-crash blocker holds the write lock");

    let leader = std::thread::spawn(move || {
        let outcome = leader_log.sever("authority:t7u-leader", &sever_now());
        (outcome, leader_log)
    });
    t6a_spin_until("the leader opened its service", || {
        observer.snapshot().expect("snapshot").service_open
    });
    let in_snapshot = std::thread::spawn(move || {
        let outcome = in_snapshot_log.sever("authority:t7u-in-snapshot", &sever_now());
        (outcome, in_snapshot_log)
    });
    t6a_spin_until("the in-snapshot joiner joined", || {
        observer.snapshot().expect("snapshot").in_snapshot_joiners == 1
    });
    let crasher = std::thread::spawn(move || {
        install_sever_seam(Box::new(|point, requester| {
            if point == SeverSeam::BeforeAttributionAppend {
                panic!(
                    "test seam: simulated crash before '{requester}' appended its own \
                     sever attribution"
                );
            }
        }));
        overflow_log.sever("authority:t7u-overflow", &sever_now())
    });
    t6a_spin_until("the overflow joiner joined", || {
        observer.snapshot().expect("snapshot").overflow_joiners == 1
    });
    blocker
        .execute_batch("ROLLBACK;")
        .expect("release the write lock");
    drop(blocker);

    let (leader_outcome, leader_log) = leader.join().expect("leader thread");
    let leader_outcome = leader_outcome.expect("the leader answers");
    let (in_snapshot_outcome, in_snapshot_log) = in_snapshot.join().expect("joiner thread");
    assert_eq!(
        in_snapshot_outcome.expect("the in-snapshot joiner answers"),
        leader_outcome,
        "the joiner that DID get its row shares the outcome"
    );
    let panic_payload = crasher
        .join()
        .expect_err("the overflow joiner UNWOUND — `sever()` never returned any value");
    let message = panic_payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        message.contains("simulated crash before 'authority:t7u-overflow'"),
        "the seam fired on the overflow joiner's own append, not somewhere else: {message}"
    );

    // REOPEN — every claim below is read from a FRESH connection over the durable file
    // (and the reopen runs boot quarantine, which reconciles every stored witness row).
    drop(leader_log);
    drop(in_snapshot_log);
    drop(log0);
    let reopened = SqliteIntentLog::open(&path).expect("reopen");
    assert_eq!(
        reopened.control_epoch().expect("epoch"),
        2,
        "THE EPOCH IS BUMPED — the kill effect was never at risk"
    );
    let status: String = raw_conn(&path)
        .query_row(
            "SELECT status FROM intents WHERE idempotency_key = 'k-t7u-a';",
            [],
            |r| r.get(0),
        )
        .expect("status");
    assert_eq!(
        status_from_str(&status).expect("status token"),
        IntentStatus::Severed,
        "THE KILL EFFECT IS INTACT — the leader's transaction closed its members"
    );
    let rows = t7_attribution_rows(&path);
    assert_eq!(
        rows,
        vec![(
            2,
            "authority:t7u-in-snapshot".to_string(),
            "in-snapshot".to_string()
        )],
        "the in-snapshot joiner's row rode the leader's transaction and survived — and \
         the exact-vector form IS the overflow-absence claim: the crashed overflow \
         joiner ('authority:t7u-overflow') is truthfully unacknowledged, absent from the \
         record (#24-1b codex-r8 F7: a separate absence assert here could never fail \
         independently of this equality and was deleted as vacuous)"
    );

    drop(reopened);
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// W-SEIZE-BOUND STRUCTURAL (timing-free). Lives HERE, in lib.rs's own
// test module, rather than in `tests/capacity_seize_bound.rs` (the capacity benchmark's file):
// `writer_gate`'s `WriterGate`/`GateSnapshot`/`SeverEntry` — the oracle every witness
// below spins on — are `pub(crate)`, unreachable from an external integration test crate
// (which sees only `aruna`'s `pub` surface). Every wait below is a spin on GATE STATE,
// never a clock; the bounded `started.elapsed()` checks are DEADLOCK diagnostics (the
// codebase's own convention — see e.g. `a_header_store_write_waits_behind_a_pending_sever`
// in `message_header.rs`), never a latency assertion.
// ═══════════════════════════════════════════════════════════════════════════════════

fn t9_summary(id: &str, received_at: i64, subject: &str) -> crate::read_surface::HeaderSummary {
    crate::read_surface::HeaderSummary {
        provider_id: crate::read_model::ProviderMessageId(id.to_string()),
        received_at,
        from_addr: "t9@example.test".to_string(),
        from_name: "T9".to_string(),
        subject: subject.to_string(),
        seen: false,
        flagged: false,
        attachments: crate::read_surface::AttachmentPresence::default(),
    }
}

#[test]
fn w_seize_bound_barrier_schedule() {
    // FOUR writers of MIXED KINDS — the FOUR
    // production write doors wired into the ONE shared gate
    // (`SqliteIntentLog::record`, `SqliteMessageHeaderStore::record_header`,
    // `ReadCoordinator::ingest_page`, `ReadCoordinator::apply_verb_delta`) — released
    // together off a `Barrier` so all four race to enroll at once. Only ONE can win the
    // gate-level race (`active_writer` is a `bool`, not a counter — "at most one" is a
    // TYPE fact, T5's own `at_most_one_enrolled_writer`); this witness proves the
    // property holds ACROSS the four different production surfaces, not merely for a raw
    // synthetic loop, and that a sever ticket raised while the winner is still enrolled
    // blocks every OTHER door's enrollment regardless of which one it is — a shared
    // aggregate "completed" tally (never per-door) is the oracle, so the assertion holds
    // no matter which of the four happens to win the race.
    let path = unique_temp_db_path("t9-barrier-schedule");
    let mut log0 = SqliteIntentLog::open(&path).expect("bootstrap + open");
    admit(&mut log0, &archive_of("k-t9-seed", "m-seed"));
    let mut coord0 = crate::read_coordinator::ReadCoordinator::open(&path).expect("coordinator open");
    let verb_refs = coord0
        .ingest_page("acct-1", &[t9_summary("t9-verb-seed", 1, "verb seed")])
        .expect("prime the verb-delta target");
    let verb_ref = verb_refs.into_iter().next().expect("one ingested row");
    drop(coord0);
    drop(log0);

    let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
    assert!(!observer.snapshot().expect("snapshot").active_writer);

    // Open every door's connection BEFORE the blocker takes the write lock — `open()`
    // itself needs to write (DDL/verification), so opening it AFTER the blocker would hit
    // `SQLITE_BUSY` instead of exercising the property under test (the T6c/T7 precedent:
    // every existing witness opens its handles first, then blocks).
    let log_w0 = SqliteIntentLog::open(&path).expect("w0 open");
    let headers_w1 = crate::message_header::SqliteMessageHeaderStore::open(&path).expect("w1 open");
    let coord_w2 = crate::read_coordinator::ReadCoordinator::open(&path).expect("w2 open");
    let coord_w3 = crate::read_coordinator::ReadCoordinator::open(&path).expect("w3 open");

    // THE BLOCKER (test machinery, the T6c/T7 pattern): an ungated raw connection holding
    // the store's one SQL write lock, so whichever of the four doors wins the gate-level
    // enroll race is forced to PARK at its own `BEGIN IMMEDIATE` — widening the window
    // deterministically instead of racing a clock.
    let blocker = raw_conn(&path);
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the barrier-schedule blocker holds the write lock");

    let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut handles = Vec::new();

    {
        let (completed, start) = (std::sync::Arc::clone(&completed), std::sync::Arc::clone(&start));
        let mut log = log_w0;
        handles.push(std::thread::spawn(move || {
            start.wait();
            admit(&mut log, &archive_of("k-t9-w0", "m-w0"));
            completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    {
        let (completed, start) = (std::sync::Arc::clone(&completed), std::sync::Arc::clone(&start));
        let mut headers = headers_w1;
        handles.push(std::thread::spawn(move || {
            start.wait();
            headers
                .record_header("acct-1", "t9-hdr", "Inbox", 0, "c@e.test", "C", "subj", false, false)
                .expect("header write");
            completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    {
        let (completed, start) = (std::sync::Arc::clone(&completed), std::sync::Arc::clone(&start));
        let mut coord = coord_w2;
        handles.push(std::thread::spawn(move || {
            start.wait();
            coord
                .ingest_page("acct-1", &[t9_summary("t9-coord", 2, "coord")])
                .expect("ingest");
            completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    {
        let (completed, start, verb_ref) =
            (std::sync::Arc::clone(&completed), std::sync::Arc::clone(&start), verb_ref.clone());
        let mut coord = coord_w3;
        handles.push(std::thread::spawn(move || {
            start.wait();
            let _ = coord.apply_verb_delta("acct-1", &verb_ref, crate::read_coordinator::VerbDelta::StarSet(true));
            completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }

    // Exactly one of the four wins the gate-level race and parks at SQL behind the
    // blocker; the other three park at `enroll()` itself. Either way, NONE has completed.
    t6a_spin_until("one writer enrolled (gate-level) and blocks at SQL; the other three are parked at enroll()", || {
        let s = observer.snapshot().expect("snapshot");
        s.active_writer && s.enroll_waiters >= 3
    });
    assert_eq!(
        completed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no door proceeds while the ONE slot is held"
    );

    // Raise a sever WHILE the winner still holds the slot.
    let sever_gate = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
    let sever_thread = std::thread::spawn(move || sever_gate.begin_sever("authority:t9-barrier"));
    t6a_spin_until("the sever ticket is raised", || {
        observer.snapshot().expect("snapshot").sever_pending == 1
    });

    // Release the winner's SQL block: its own write completes (it enrolled before the
    // ticket existed) and its scope drops.
    blocker.execute_batch("ROLLBACK;").expect("release the write lock");
    drop(blocker);

    // The three still-parked doors must NOT enroll next — the pending sever wins the freed
    // slot by construction (`enroll()`'s predicate re-checks `sever_pending`, `enroll_
    // service` does not) — witnessed by the SAME timing-free counter T5 uses.
    t6a_spin_until("a parked writer yields to the pending sever", || {
        observer.snapshot().expect("snapshot").enroll_yields_to_sever > 0
    });
    // `<= 1`, not `== 1`: the gate-level order (winner's scope must drop, i.e.
    // `active_writer` must go false, before ANY yield can be recorded) is guaranteed by
    // construction, but whether the WINNER thread's own post-scope Rust bookkeeping
    // (`completed.fetch_add`, which runs strictly after its write call returns) has been
    // scheduled by the time some OTHER thread's condvar wake observes the yield is not —
    // those are two independent threads racing after the SAME gate event. The property
    // this witness proves is "never more than the winner", not "the winner's own counter
    // update always wins that race".
    assert!(
        completed.load(std::sync::atomic::Ordering::SeqCst) <= 1,
        "the sever observed AT MOST ONE in-flight enrollment (the race's winner) — the \
         other three stay parked behind the pending ticket, regardless of which production \
         door each one calls"
    );

    let mut entry = sever_thread.join().expect("sever thread").expect("begin_sever");
    assert!(entry.is_leader(), "the only requester leads");
    entry
        .complete(crate::writer_gate::SeverOutcome::Served { epoch: 999 })
        .expect("complete");

    for h in handles {
        h.join().expect("writer thread");
    }
    assert_eq!(
        completed.load(std::sync::atomic::Ordering::SeqCst),
        4,
        "anti-vacuous: all four doors DO enroll once the service completes"
    );

    std::fs::remove_file(&path).ok();
}

/// THE RED for **the caller's row generator runs OUTSIDE the enrolled
/// scope.**
///
/// `bulk_load_headers` used to call `next_row` from INSIDE the chunk's own
/// `with_immediate_tx` closure, so every millisecond the CALLER spent producing a row was a
/// millisecond the store's one writer slot was held — work the chunk budget (a count of
/// WRITES) never claimed to bound and cannot see. The fix materializes the chunk first; this
/// witness is the oracle that says so, and it is structural rather than a timing claim: the
/// generator reads the gate's own thread-local held-scope counter at the moment it runs.
///
/// Pre-fix that counter reads 1 (this thread holds the chunk's `WriteScope`); post-fix it
/// reads 0. The flag is COLLECTED and asserted at the end rather than panicking inside the
/// closure, so the pre-fix failure is this witness's own message and not an unwind through a
/// rolled-back transaction. Anti-vacuity is the second assertion: the generator must actually
/// have RUN (and across more than one chunk), or a door that never called it would pass.
#[test]
fn bulk_chunk_rows_are_generated_outside_the_enrolled_scope() {
    const ROWS_PER_CHUNK: usize = 4;
    const TOTAL_ROWS: usize = 10;

    let path = unique_temp_db_path("r3-generate-outside-scope");
    let _log = SqliteIntentLog::open(&path).expect("bootstrap + open");
    let mut store =
        crate::message_header::SqliteMessageHeaderStore::open(&path).expect("header store");

    let mut calls = 0usize;
    let mut max_held_scopes = 0u32;
    let written = store
        .bulk_load_headers(ROWS_PER_CHUNK, || {
            max_held_scopes = max_held_scopes.max(crate::writer_gate::held_scopes());
            let i = calls;
            calls += 1;
            if i >= TOTAL_ROWS {
                return None;
            }
            Some(crate::message_header::BulkHeaderRow {
                account: "acct-1".to_string(),
                message_ref: format!("r3-bulk-{i}"),
                mailbox: "Inbox".to_string(),
                received_at: i as i64,
                from_addr: "r3@example.test".to_string(),
                from_name: "R3".to_string(),
                subject: "generated outside the scope".to_string(),
                seen: false,
                flagged: false,
            })
        })
        .expect("bulk_load_headers");

    assert_eq!(written, TOTAL_ROWS, "every row lands");
    assert!(
        calls > ROWS_PER_CHUNK,
        "anti-vacuous: the generator ran across MORE THAN ONE chunk ({calls} calls) — a \
         single-chunk load could hold its scope for the whole generation and still pass"
    );
    assert_eq!(
        max_held_scopes, 0,
        "the row generator ran while this thread held {max_held_scopes} WriteScope(s) — the \
         caller's per-row work belongs OUTSIDE the enrolled chunk transaction, or the chunk \
         budget (a count of WRITES) stops bounding how long the writer slot is held"
    );

    drop(_log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn sever_waits_at_most_one_chunk_under_bulk_import() {
    // A sever ticket raised WHILE
    // T6b's chunked `bulk_load_headers` is mid-import must not preempt the CURRENT chunk
    // (that transaction is already enrolled and runs to its own commit undisturbed), and
    // the NEXT chunk must not begin until the sever's service has completed — "at most one
    // chunk's wait", the same property `enroll_yields_to_sever` witnesses for an ordinary
    // writer, exercised here across a REAL multi-chunk bulk import instead of a single
    // enrolled write.
    //
    // ORDER, not time: `rows_emitted` is a shared counter the row-generator bumps on every
    // call `bulk_load_headers` makes to it. The moment `enroll_yields_to_sever` advances, the
    // NEXT chunk's own `enroll()` call is PROVABLY parked (it re-evaluated its predicate,
    // `!active_writer`, i.e. the prior chunk had already dropped its scope, and yielded
    // because `sever_pending>0`) — and `rows_emitted` is frozen from that instant until this
    // test completes the service, because the loop's ONLY other statement is that enroll.
    //
    //  shifted WHERE in the loop those calls happen — the chunk is now
    // materialized BEFORE its `with_immediate_tx`, not inside it — so the freeze argument is
    // now "the parked chunk has already generated its rows and cannot generate more until it
    // is admitted", where it used to be "the parked chunk has not generated any yet". Same
    // freeze, one chunk further along; TOTAL_ROWS is raised to keep the anti-vacuity margin
    // below (the yield must leave rows unemitted) the two chunks it was, rather than the one
    // the shift would otherwise have left.
    const ROWS_PER_CHUNK: usize = 2;
    const TOTAL_ROWS: usize = 14;

    let path = unique_temp_db_path("t9-bulk-chunk-wait");
    let _log = SqliteIntentLog::open(&path).expect("bootstrap + open");
    let mut store = crate::message_header::SqliteMessageHeaderStore::open(&path).expect("header store open");

    let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
    let rows_emitted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let importer = {
        let rows_emitted = std::sync::Arc::clone(&rows_emitted);
        std::thread::spawn(move || {
            store
                .bulk_load_headers(ROWS_PER_CHUNK, move || {
                    let i = rows_emitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if i >= TOTAL_ROWS {
                        return None;
                    }
                    Some(crate::message_header::BulkHeaderRow {
                        account: "acct-1".to_string(),
                        message_ref: format!("t9-bulk-{i}"),
                        mailbox: "Inbox".to_string(),
                        received_at: i as i64,
                        from_addr: "t9@example.test".to_string(),
                        from_name: "T9".to_string(),
                        subject: "bulk chunk wait".to_string(),
                        seen: false,
                        flagged: false,
                    })
                })
                .expect("bulk_load_headers")
        })
    };

    // Mid-import: at least one full chunk requested, more remain (TOTAL_ROWS > ROWS_PER_CHUNK).
    t6a_spin_until("the import has emitted at least one full chunk", || {
        rows_emitted.load(std::sync::atomic::Ordering::SeqCst) >= ROWS_PER_CHUNK
    });

    let sever_gate = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
    let sever_thread = std::thread::spawn(move || sever_gate.begin_sever("authority:t9-bulk"));
    t6a_spin_until("the sever ticket is raised", || {
        observer.snapshot().expect("snapshot").sever_pending == 1
    });

    // The NEXT chunk that tries to enroll must yield to the pending ticket rather than
    // proceed — this is the "before the next chunk begins" half of the property.
    t6a_spin_until("a not-yet-started chunk yields to the pending sever", || {
        observer.snapshot().expect("snapshot").enroll_yields_to_sever > 0
    });
    let frozen = rows_emitted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        frozen < TOTAL_ROWS,
        "anti-vacuous: the sever interjected MID-import (some rows still unemitted at the \
         yield), not after the whole import had already finished — got frozen={frozen}"
    );

    // Complete the service — this is the "after the CURRENT chunk's scope drops" half:
    // the chunk that was in flight when the ticket was raised had already committed (its
    // own next_row calls are counted in `frozen`) and this leader took the freed slot
    // clean, never interrupting an in-flight transaction.
    let mut entry = sever_thread.join().expect("sever thread").expect("begin_sever");
    assert!(entry.is_leader(), "the only requester leads");
    entry
        .complete(crate::writer_gate::SeverOutcome::Served { epoch: 999 })
        .expect("complete");

    let written = importer.join().expect("importer thread");
    assert_eq!(
        written, TOTAL_ROWS,
        "anti-vacuous: the import RESUMES and finishes once the service completes"
    );
    assert!(
        rows_emitted.load(std::sync::atomic::Ordering::SeqCst) >= frozen,
        "rows_emitted only ever grows"
    );

    drop(_log);
    std::fs::remove_file(&path).ok();
}
