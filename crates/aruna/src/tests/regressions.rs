//! Stage 4 regression witnesses.

use super::*;
use crate::keys::undo_child_key;

// ═══════════════════════════════════════════════════════════════════════════════════
// Stage 4 regression witnesses. Every one of these went RED against the
// earlier tree before the fix beside it existed.
// ═══════════════════════════════════════════════════════════════════════════════════

#[test]
fn a_retry_requalifies_even_when_the_capture_equals_the_target() {
    // ═══ ═══ THE `P == A` SHORT-CIRCUIT WAS A HOLE, not a shortcut.
    // 's trace, verbatim in structure: an initial NO-OP attempt (`P == A`) fails
    // proven-pre-wire; ANOTHER ACTOR moves the provider off `A` during the retry gap; the
    // retry dispatches BLIND against a capture that no longer describes the world, makes a
    // REAL change, and undo stays killed by `P == A` — so the other actor's state is
    // unrestorable.
    //
    // The fold DELETES the pre-guard: every capture-ON retry runs the §3.2 RETRY decision,
    // whose check ORDER (`C == P` first) is what protects the unchanged-`P == A` world
    // honestly — by observing it, not by assuming it.
    let path = unique_temp_db_path("r1-p1-retry-noop-guard");
    // `P == A` BY CONSTRUCTION: the forward target is `membership:INBOX = false` and the
    // provider already holds `false` when the capture is taken.
    let wire = SharedWire::new(UndoStageConnector::single(false, false));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    wire.wire().fail_apply_with(
        ConnectorError::transient("connect refused").proven_no_wire(),
        1,
    );
    let first = bus.execute(&archive_cmd("k-r1-p1"));
    assert!(
        matches!(first, Err(ExecuteError::Connector(_))),
        "precondition: attempt 1 fails proven-pre-wire into the retry gap, got {first:?}"
    );
    assert_eq!(
        journal_row_of(&path, "k-r1-p1").1,
        r#"{"membership:INBOX":false}"#,
        "precondition: the captured P equals the frozen target A"
    );

    // ── ANOTHER ACTOR MOVES THE PROVIDER, inside the retry gap. ──
    wire.wire().set_state(atoms(&[("membership:INBOX", true)]));
    bus.recover().expect("the sweep runs the retry");

    assert_eq!(
        journal_row_of(&path, "k-r1-p1").1,
        r#"{"membership:INBOX":true}"#,
        "the retry must RE-PREPARE against the world it is actually dispatching into — a \
         capture frozen at `false` would make undo restore a state that stopped being true"
    );
    assert_eq!(
        capture_generation_of(&path, "k-r1-p1"),
        2,
        "…and say WHICH capture it is: the versioned REPLACE, not a silent blend"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_exposure_gate_scopes_by_provider_identity_not_the_local_alias() {
    // ═══ ═══ EXP-1's scope is "account/PROVIDER scope … derived from the
    // operation's immutable frozen basis — never from a re-resolved local alias". The gate
    // joined on `intents.account`, the PHOTON-LOCAL handle. Two local account handles that
    // resolve to ONE provider account produce the SAME provider-native atom key and
    // DIFFERENT `account` values, so the join missed the live obligation and an overlapping
    // wire effect was authorized.
    //
    // The fixture basis keys its native resource key on the message alone — exactly the
    // shape a provider-scoped key has for two local aliases of one provider mailbox (the
    // real connectors embed the PROVIDER account id in the key, `jmap.rs:1067` /
    // `gmail.rs:631`, which is why the local column can leave the join entirely).
    let path = unique_temp_db_path("r1-p1-exposure-alias");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = Command::new(
        "k-alias-a",
        "acct-alpha",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let attempt = unknown_attempt(&mut log, &unknown);
    adjudicate_now(&mut log, "k-alias-a", &attempt);

    // The SAME provider resource, admitted under the OTHER local account handle.
    let peer = Command::new(
        "k-alias-b",
        "acct-beta",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    record_basis(&mut log, &peer).expect("admit");
    let peer_attempt = claim_now(&mut log, "k-alias-b", 0);
    assert_eq!(
        authorize(&mut log, "k-alias-b", &peer_attempt).expect("fence"),
        SendAuthOutcome::ExposureBlocked {
            atom_key: fixture_atom("msg-1")
        },
        "the live obligation covers the PROVIDER atom; a second local alias of the same \
         provider account may not walk past it"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_definitive_ack_racing_an_adjudication_becomes_its_late_ack() {
    // ═══ ═══ The operator adjudicates while the connector call is IN
    // FLIGHT. The returning DEFINITIVE ack hits the post-adjudication whitelist and is
    // refused — and the verdict door turned that legal race into a fail-loud store
    // incident, leaving the HISTORICAL axis stuck at UNKNOWN and the obligations unretired
    // even though the provider had just answered definitively.
    //
    // The fold routes the definitive outcome through the late-ack path (the late-ack path's own
    // machinery, reused — never duplicated): ≤1 late ack, EXP-8 retirement, EXP-7 notices,
    // the undo-parent flip.
    let path = unique_temp_db_path("r1-p1-racing-definitive-ack");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let cmd = archive_of("k-race", "msg-1");
    let attempt = admit_and_claim(&mut log, &cmd);
    assert!(
        matches!(
            authorize(&mut log, "k-race", &attempt).expect("fence"),
            SendAuthOutcome::Authorized { .. }
        ),
        "precondition: the attempt is authorized and the request is on the wire"
    );
    // ── MID-FLIGHT: the operator decides. ──
    adjudicate_now(&mut log, "k-race", &attempt);
    assert_eq!(
        obligation_rows(&path)
            .iter()
            .filter(|(_, _, _, _, retired)| !*retired)
            .count(),
        1,
        "precondition: the adjudication left one LIVE obligation"
    );
    drop(log);

    // ── …and THEN the definitive ack comes back. ──
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("bus"), AlwaysOkConnector);
    let settled = bus
        // POST-AUTHORIZATION (this is the ack of a dispatch that owned the wire), so no
        // pre-wire compare — which is exactly what lets the chain move under it and this
        // race reach the late-ack door at all.
        .settle_dispatch("k-race", &attempt, ConnectorVerdict::Applied, None)
        .expect("a definitive ack after an adjudication is a RACE, never a store incident");
    assert!(settled.terminal, "the operation is (and stays) terminal");
    assert!(!settled.superseded_pre_wire);
    assert!(
        chain_kinds(&path, &attempt).contains(&"late_ack_applied".to_string()),
        "the definitive outcome must land through the LATE-ACK door: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert!(
        obligation_rows(&path)
            .iter()
            .all(|(_, _, _, _, retired)| *retired),
        "…and EXP-8 retirement rides it: the historical axis is no longer unresolved"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_resolved_adjudication_replays_as_adjudicated_late_never_plain_success() {
    // ═══ REWORKED ═══ "unknown at decision time ≠
    // unknown forever" (§5.2d). After a RESOLVING late ack the replay contract still
    // answered `AdjudicatedUnresolved` — the engine holding a truth in its ledger and
    // telling the caller it did not have one. read the historical axis, and then
    // PROJECTED it onto the ordinary lifecycle's answers: `Ok(())` for resolved-applied,
    // `Err(Failed)` for resolved-refused. Both are forbidden by the very ADR-P013 clause
    // this class exists to satisfy — "an identical-fingerprint replay against each returns
    // its OWN truthful `Err` class … never the generic dead-lettered `Err(Failed)` and never
    // a silent `Ok`" — so a caller could not tell an operation closed THROUGH ADJUDICATION
    // from an ordinary `Applied` no-op or an ordinary provider dead-letter. The assertions
    // below are the contract's, not the projection's.
    let path = unique_temp_db_path("r1-p2-adjudicated-replay");
    let mut log = SqliteIntentLog::open(&path).expect("open");

    let applied = archive_of("k-replay-applied", "msg-1");
    let a = unknown_attempt(&mut log, &applied);
    adjudicate_now(&mut log, "k-replay-applied", &a);
    log.record_late_ack("k-replay-applied", &a, crate::attempt::LateAck::Applied)
        .expect("the historical axis resolves APPLIED");

    let refused = archive_of("k-replay-refused", "msg-2");
    let r = unknown_attempt(&mut log, &refused);
    adjudicate_now(&mut log, "k-replay-refused", &r);
    log.record_late_ack(
        "k-replay-refused",
        &r,
        crate::attempt::LateAck::RefusedNoEffect,
    )
    .expect("the historical axis resolves REFUSED_NO_EFFECT");

    let open = archive_of("k-replay-open", "msg-3");
    let o = unknown_attempt(&mut log, &open);
    adjudicate_now(&mut log, "k-replay-open", &o);
    drop(log);

    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("bus"), AlwaysOkConnector);
    assert_eq!(
        bus.execute(&applied),
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::Applied
        )),
        "a resolved-APPLIED operation is still an operation an ADJUDICATION closed: the \
         replay names that route AND its resolution, never the plain `Ok(())` an ordinary \
         `Applied` terminal replays"
    );
    assert_eq!(
        bus.execute(&refused),
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::RefusedNoEffect
        )),
        "…and the refused resolution takes the SAME route, symmetrically — never the \
         generic dead-lettered `Err(Failed)` a provider rejection produces"
    );
    assert_eq!(
        bus.execute(&open),
        Err(ExecuteError::AdjudicatedUnresolved),
        "…and an unresolved one still says so"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_presentation_after_a_late_refused_ack_stops_saying_unresolved() {
    // ═══ ═══ `LATE_ACK_REFUSED_NO_EFFECT` on an undo child's attempt is
    // PROOF the restore did not happen. The presentation kept answering
    // `AppliedUndoUnresolved` forever — "nobody knows" over a fact the ledger holds.
    let path = unique_temp_db_path("r1-p2-undo-presentation-refused");
    let wire = SharedWire::new(UndoStageConnector::single(false, true));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    bus.execute(&archive_cmd("k-undo-refused"))
        .expect("the forward action applies");
    // C == A ⇒ the undo requalifies to RESTORE…
    wire.wire().set_state(atoms(&[("membership:INBOX", false)]));
    // …and the restore's answer is lost on the wire ⇒ ISSUANCE_UNKNOWN.
    wire.wire()
        .fail_restore(ConnectorError::transient("connection lost mid-restore"), 1);
    let undo = bus.undo("k-undo-refused");
    assert!(
        undo.is_err(),
        "precondition: the restore's outcome is unknown, got {undo:?}"
    );
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-undo-refused"));
    let child_attempt = attempt_of(&path, &child_key);
    assert_eq!(
        status_str(&path, "k-undo-refused"),
        "applied",
        "precondition: the parent is truthfully still `applied`"
    );

    let mut log = SqliteIntentLog::open(&path).expect("store handle");
    adjudicate_now(&mut log, &child_key, &child_attempt);
    let resolved = log
        .record_late_ack(
            &child_key,
            &child_attempt,
            crate::attempt::LateAck::RefusedNoEffect,
        )
        .expect("the provider's definitive answer finally arrives");
    assert!(
        matches!(
            resolved,
            LateAckOutcome::Resolved {
                parent_undone: false,
                ..
            }
        ),
        "precondition: a refused restore never flips the parent, got {resolved:?}"
    );
    drop(log);

    assert_eq!(
        bus.undo_presentation("k-undo-refused").expect("projection").map(|r| r.presentation),
        Some(UndoPresentation::AppliedUndoFailed),
        "the restore DEFINITIVELY did not happen — the presentation must say so, not \
         `unresolved` forever"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_later_independent_apply_on_a_settled_atom_is_not_a_materialization() {
    // ═══ ═══ EXP-9's NON-BLEED: "after an atom's exposure fully resolves
    // and settles, a later independent unresolved episode on that atom is a NEW exposure
    // generation — old acceptances and OLD NOTICES never authorize or contaminate it." The
    // materialization scan read EVERY obligation row on the atom, retired or not, so an
    // ordinary later operation on a long-settled message minted a false
    // `exposure-materialized` notice against a stranger's adjudication record.
    let path = unique_temp_db_path("r1-p2-materialization-bleed");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-settled", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    let record = adjudicate_now(&mut log, "k-settled", &attempt);
    log.record_late_ack("k-settled", &attempt, crate::attempt::LateAck::Applied)
        .expect("the episode SETTLES");
    // The episode closed LONG before the operation below was ever admitted. Stated as a
    // date rather than raced against the clock: `created_at` is RFC-3339 SECONDS, so two
    // events inside one test can share a timestamp, and the ordering under test ("retired
    // before the later attempt was authorized") is what this line makes unambiguous.
    raw_conn(&path)
        .execute(
            "UPDATE exposure_obligation SET retired_at = '2020-01-01T00:00:00Z';",
            [],
        )
        .expect("the episode settled long ago");

    // A FRESH, INDEPENDENT operation on the same atom — it overlaps nothing live.
    let later = archive_of("k-later", "msg-1");
    record_basis(&mut log, &later).expect("admit");
    let later_attempt = claim_now(&mut log, "k-later", 0);
    assert!(
        matches!(
            authorize(&mut log, "k-later", &later_attempt).expect("fence"),
            SendAuthOutcome::Authorized { .. }
        ),
        "precondition: the settled episode gates nothing"
    );
    log.settle_attempt(
        "k-later",
        &later_attempt,
        ConnectorVerdict::Applied,
        RETRY_CAP,
        None,
    )
    .expect("its effect provably happened");

    assert_eq!(
        annotation_kinds(&path, &record),
        Vec::<String>::new(),
        "a later independent effect on a settled atom is not the materialization of \
         anybody's accepted risk"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_late_refused_contributor_is_never_annotated_as_unresolved() {
    // ═══ ═══ A contributor whose late ack said REFUSED_NO_EFFECT is
    // PROVEN to have had no effect. The annotation writer's two-way branch treated
    // "not LATE_ACK_APPLIED" as "still unknown" and wrote the `applied-over-unresolved`
    // half-trace against it — a durable claim of ambiguity over a settled fact.
    let path = unique_temp_db_path("r1-p2-late-refused-contributor");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let unknown = archive_of("k-refused", "msg-1");
    let attempt = unknown_attempt(&mut log, &unknown);
    // The peer authorizes BEFORE the obligation exists — the only way an overlapping effect
    // can be in flight in a build with no risk-acceptance capability.
    let peer = archive_of("k-peer", "msg-1");
    record_basis(&mut log, &peer).expect("admit");
    let peer_attempt = claim_now(&mut log, "k-peer", 0);
    assert!(
        matches!(
            authorize(&mut log, "k-peer", &peer_attempt).expect("fence"),
            SendAuthOutcome::Authorized { .. }
        ),
        "precondition: no obligation exists yet"
    );
    let record = adjudicate_now(&mut log, "k-refused", &attempt);
    log.record_late_ack(
        "k-refused",
        &attempt,
        crate::attempt::LateAck::RefusedNoEffect,
    )
    .expect("the contributor is PROVEN to have had no effect");
    log.settle_attempt("k-peer", &peer_attempt, ConnectorVerdict::Applied, RETRY_CAP, None)
        .expect("the peer's effect provably happened");

    assert_eq!(
        annotation_kinds(&path, &record),
        Vec::<String>::new(),
        "there is nothing unresolved to annotate: the contributor proved no effect"
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// — the four edges, each with its own RED.
// ═══════════════════════════════════════════════════════════════════════════════════

#[test]
fn a_re_entry_peer_may_not_settle_an_attempt_the_owner_authorized() {
    // ═══ ═══ THE RE-ENTRY ARM handed a SECOND worker settlement
    // authority over a peer's ACTIVE attempt. Two recovery drivers read the same retry gap:
    //   A claims the successor attempt (the retry-gap arm mints it) and AUTHORIZES it;
    //   B arrives with an equally-current read, hits the RE-ENTRY arm on that same attempt,
    //   obtains a PRE-WIRE verdict (`C == A` ⇒ ExternallySatisfied) and terminalizes it.
    // A's real applied ack then refuses `PostTerminalAppend` — the operation records
    // EXTERNALLY_SATISFIED for an effect A actually put on the wire.
    //
    // Two logs over ONE file: two independent drivers over one durable store (the double-drive race's
    // topology, the same shape `w_seize_race_…` uses — it is the only place this race lives).
    let path = unique_temp_db_path("reentry-settlement-authority");
    let mut a = SqliteIntentLog::open(&path).expect("open driver A");
    let mut b = SqliteIntentLog::open(&path).expect("open driver B");
    let command = archive_of("k-reentry", "msg-reentry");
    admit(&mut a, &command);

    // Attempt 1 fails TRANSIENTLY (proven no wire) ⇒ the operation sits in its §5.2c retry
    // gap: lifecycle-ACTIVE, no live attempt, `attempts` charged to 1.
    let first = claim_now(&mut a, "k-reentry", 0);
    assert!(matches!(
        authorize(&mut a, "k-reentry", &first).expect("authorize 1"),
        SendAuthOutcome::Authorized { .. }
    ));
    a.settle_attempt(
        "k-reentry",
        &first,
        ConnectorVerdict::Failed {
            kind: FailureKind::Transient,
            evidence: EffectEvidence::ProvenNoWire,
        },
        RETRY_CAP,
        None,
    )
    .expect("settle 1");

    // A wins the retry gap and mints the SUCCESSOR attempt…
    let retry = claim_now(&mut a, "k-reentry", 1);
    assert_ne!(retry, first, "the retry is a FRESH attempt (Task 9)");
    // …and B, holding an equally-current read, re-enters the very same attempt.
    let (reentered, b_saw) = match b
        .claim_attempt(
            "k-reentry",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 1,
            },
        )
        .expect("B's claim")
    {
        ClaimOutcome::Won {
            attempt_id,
            observed_revision,
            ..
        } => (attempt_id, observed_revision),
        other => panic!("B re-enters the live attempt, got {other:?}"),
    };
    assert_eq!(reentered, retry, "precondition: BOTH drivers hold one attempt");
    assert_eq!(b_saw, 1, "B's read saw the CLAIM and nothing after it");

    // A authorizes and enters its socket. B's pre-wire verdict is now STALE.
    assert!(matches!(
        authorize(&mut a, "k-reentry", &retry).expect("authorize 2"),
        SendAuthOutcome::Authorized { .. }
    ));
    let b_settle = b
        .settle_attempt(
            "k-reentry",
            &retry,
            ConnectorVerdict::ExternallySatisfied,
            RETRY_CAP,
            // B never authorized: its verdict is PRE-WIRE, so it compare-and-appends.
            Some(b_saw),
        )
        .expect("B settles");
    assert_eq!(
        b_settle,
        SettleOutcome::SupersededPreWire {
            observed_revision: 1,
            current_revision: 2,
        },
        "B's PRE-WIRE settlement was decided against a chain that has since moved — it must \
         REFUSE, not close a peer's authorized attempt"
    );
    assert_eq!(
        chain_kinds(&path, &retry),
        vec!["claim", "send_authorized"],
        "nothing of B's may be on the chain"
    );

    // …and A's REAL applied ack lands.
    let a_settle = a
        // POST-AUTHORIZATION: A holds this attempt's `SEND_AUTHORIZED`, which IS its
        // exclusivity — so it settles without a compare, and lands.
        .settle_attempt("k-reentry", &retry, ConnectorVerdict::Applied, RETRY_CAP, None)
        .expect("A settles");
    assert!(
        matches!(
            a_settle,
            SettleOutcome::Settled {
                verdict: crate::attempt::FactKind::AckApplied,
                lifecycle: SettledLifecycle::Completed(IntentStatus::Applied),
            }
        ),
        "the driver that owns the wire must be able to record what it did, got {a_settle:?}"
    );
    assert_eq!(status_str(&path, "k-reentry"), "applied");
}

#[test]
fn a_refused_in_memory_sever_advances_nothing() {
    // ═══ ═══ The mirror bumped the epoch BEFORE validating `now`, so a
    // sever that FAILED still raised the fence — with no witness and no closures, which is
    // the worst of both: every admitted operation is fenced, and nothing records why. The
    // durable door's transaction ROLLS BACK, and that is the parity target.
    let mut log = InMemoryIntentLog::new();
    let command = archive_cmd("k-sever-clock");
    record_basis(&mut log, &command).expect("admit");

    let refused = log.sever("authority:operator-1", "not-a-canonical-instant");
    assert!(
        refused.is_err(),
        "a non-canonical sever instant must refuse, got {refused:?}"
    );
    assert!(
        log.admitted_epoch_is_current("k-sever-clock").expect("fence"),
        "a REFUSED sever fences nothing"
    );
    let good = log
        .sever("authority:operator-1", "2026-08-08T00:00:00Z")
        .expect("the honest sever");
    assert_eq!(
        good.epoch, 2,
        "the first SUCCESSFUL sever writes epoch 2 — the refused one advanced nothing"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Stage 4 regression witnesses. Every one of these went RED against the
// earlier tree before the fix beside it existed.
// ═══════════════════════════════════════════════════════════════════════════════════

/// Rebuild `pre_state` in the shape `origin/main`'s DDL creates — WITHOUT
/// `capture_generation`. This is the exact table a store minted by a pre-stage-4 binary
/// carries, transcribed from `git show origin/main:crates/aruna/src/store_open.rs`
/// (SCHEMA_DDL_STATIC, `CREATE TABLE IF NOT EXISTS pre_state`), so the witness below is
/// about a REAL population and not a synthetic mutation.
fn shrink_pre_state_to_main_shape(path: &std::path::Path) {
    let conn = raw_conn(path);
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF;
             BEGIN;
             CREATE TABLE pre_state_main_shape (
                 journal_id        TEXT NOT NULL UNIQUE,
                 intent_id         TEXT NOT NULL UNIQUE REFERENCES intents(intent_id),
                 observed          TEXT NOT NULL,
                 touched_atom      TEXT NOT NULL,
                 resolved_operands TEXT NOT NULL,
                 fetched_at        TEXT NOT NULL,
                 source            TEXT NOT NULL,
                 request_id        TEXT,
                 captured_epoch    INTEGER NOT NULL,
                 mode_generation   INTEGER NOT NULL,
                 undo_offer_until  TEXT NOT NULL
             );
             INSERT INTO pre_state_main_shape
                 SELECT journal_id, intent_id, observed, touched_atom, resolved_operands,
                        fetched_at, source, request_id, captured_epoch, mode_generation,
                        undo_offer_until
                   FROM pre_state;
             DROP TABLE pre_state;
             ALTER TABLE pre_state_main_shape RENAME TO pre_state;
             COMMIT;",
    )
    .expect("rebuild pre_state in origin/main's shape");
}

/// Does the store's `pre_state` carry `capture_generation`?
fn pre_state_has_capture_generation(path: &std::path::Path) -> bool {
    raw_conn(path)
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('pre_state')
                  WHERE name = 'capture_generation';",
            [],
            |r| r.get::<_, i64>(0),
        )
        .expect("table_info")
        > 0
}

#[test]
fn a_main_shaped_v8_store_is_upgraded_in_place_at_open() {
    // ═══ ═══ `CREATE TABLE IF NOT EXISTS` does not ALTER an existing
    // table. A store minted by `origin/main` is v8 — the preflight admits it, the header
    // matches, the version stamp matches — and its `pre_state` has NO `capture_generation`
    // column. Every stage-4 statement that names that column then fails DEEP, at a
    // retry-requalification RE-PREPARE, instead of at the one door whose job is to decide
    // whether this binary may use this store.
    let path = unique_temp_db_path("r4-p1-main-shaped-store");
    // A REAL v8 store, then its `pre_state` reduced to exactly what main's DDL creates.
    drop(SqliteIntentLog::open(&path).expect("mint the store"));
    shrink_pre_state_to_main_shape(&path);
    assert!(
        !pre_state_has_capture_generation(&path),
        "precondition: the store is main-shaped — no `capture_generation` column"
    );

    // The open must bring it up to THIS binary's shape…
    let wire = SharedWire::new(UndoStageConnector::single(false, false));
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire.clone());
    assert!(
        pre_state_has_capture_generation(&path),
        "an in-version column this branch ADDED to a table origin/main already created must \
         be added at the open chokepoint — otherwise every store from main fails deep"
    );

    // …and the RE-PREPARE that names the column must work, not explode.
    wire.wire().fail_apply_with(
        ConnectorError::transient("connect refused").proven_no_wire(),
        1,
    );
    let first = bus.execute(&archive_cmd("k-r4-p1"));
    assert!(
        matches!(first, Err(ExecuteError::Connector(_))),
        "precondition: attempt 1 fails proven-pre-wire into the retry gap, got {first:?}"
    );
    wire.wire().set_state(atoms(&[("membership:INBOX", true)]));
    bus.recover().expect("the sweep runs the retry requalification");
    assert_eq!(
        capture_generation_of(&path, "k-r4-p1"),
        2,
        "the versioned RE-PREPARE lands on an upgraded store exactly as on a fresh one"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn codex_r4_p1_an_added_column_carries_its_check_through_the_alter() {
    // The upgrade above rides `ALTER TABLE … ADD COLUMN … CHECK (…)`. SQLite forbids
    // UNIQUE/PRIMARY KEY and non-constant defaults on ADD COLUMN; a CHECK is ALLOWED, and
    // the honest-at-the-site note the fix would otherwise owe ("new stores get the CHECK,
    // upgraded ones do not") is therefore NOT owed. Pinned here rather than asserted in
    // prose, because the whole upgrade's integrity claim rests on it.
    let path = unique_temp_db_path("r4-p1-alter-check");
    drop(SqliteIntentLog::open(&path).expect("mint the store"));
    shrink_pre_state_to_main_shape(&path);
    drop(SqliteIntentLog::open(&path).expect("open upgrades the table"));
    let conn = raw_conn(&path);
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pre_state';",
            [],
            |r| r.get(0),
        )
        .expect("the table's stored DDL");
    assert!(
        sql.contains("capture_generation") && sql.contains("capture_generation >= 1"),
        "the CHECK must ride the ALTER — an upgraded store is not allowed to be weaker \
         than a fresh one: {sql}"
    );
    // …and it is ENFORCED, not merely recorded.
    let violated = conn.execute(
        "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom,
                                    resolved_operands, fetched_at, source, captured_epoch,
                                    mode_generation, undo_offer_until, capture_generation)
             VALUES ('j-0', 'i-0', '{}', '{}', '{}', '2026-08-08T00:00:00Z', 'live_read',
                     1, 1, '2026-08-08T00:00:00Z', 0);",
        [],
    );
    assert!(
        format!("{violated:?}").contains("CHECK"),
        "generation 0 must be refused by the upgraded table's own CHECK, got {violated:?}"
    );
    std::fs::remove_file(&path).ok();
}

/// A connector whose `observe` lets a PEER re-enter the very attempt this driver claimed,
/// between the claim and the verification — the §3.2 `AlreadyRestored` interleave. The peer
/// authorizes (a real `SEND_AUTHORIZED` append), which moves the chain past the revision
/// this driver's pre-wire compare was armed at.
struct PeerAuthorizesDuringUndoObserve {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
    /// The CHILD key the peer re-enters; `None` until the test arms it. The attempt id is
    /// read from the store INSIDE `observe` — the drive's claim has committed by then, and
    /// that is exactly the window the interleave lives in.
    armed: std::cell::RefCell<Option<String>>,
}

impl Connector for PeerAuthorizesDuringUndoObserve {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.inner.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.inner.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        if let Some(child_key) = self.armed.borrow_mut().take() {
            // THE PEER, on its own connection onto the same store, re-entering the attempt
            // the drive claimed a moment ago.
            let attempt = attempt_of(&self.path, &child_key);
            let mut peer = SqliteIntentLog::open(&self.path).expect("peer opens the store");
            match authorize(&mut peer, &child_key, &attempt).expect("peer authorizes") {
                SendAuthOutcome::Authorized { .. } => {}
                other => panic!("the peer's re-entry must authorize, got {other:?}"),
            }
        }
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
fn a_superseded_pre_wire_verification_never_claims_verified() {
    // ═══ ═══ `verify_undo` DISCARDED the settlement's answer. On the
    // §3.2 `AlreadyRestored` arm the settle is PRE-WIRE (this driver never authorized), so
    // a peer that re-entered the same live child attempt and got its `SEND_AUTHORIZED` in
    // makes the compare-and-append LOSE — nothing is written, the child stays non-terminal,
    // and the peer is dispatching a restore right now. The drive returned `Verified` anyway:
    // a success claimed over a settlement that did not happen.
    let path = unique_temp_db_path("r4-p1-undo-verify-superseded");
    // `single(a=false, c=true)`: the forward target is `INBOX=false`, the provider holds
    // `INBOX=true`, and `apply` does NOT land — so at undo time C == P and §3.2 answers
    // `AlreadyRestored` (P != A, so the §4.1 no-op kill does not fire first).
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        PeerAuthorizesDuringUndoObserve {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
            armed: std::cell::RefCell::new(None),
        },
    );
    bus.execute(&archive_cmd("k-r4-p2")).expect("the forward action applies");

    // Admit the child WITHOUT driving it (a live same-resource predecessor defers it), so
    // the test can arm the peer against the child's own attempt at the right instant.
    seed_pending_peer(&path, &bus, "k-r4-p2-peer");
    assert!(matches!(bus.undo("k-r4-p2"), Err(ExecuteError::InProgress)));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-r4-p2"));
    terminalize_peer(&path, "k-r4-p2-peer");
    let child = bus.log().get(&child_key).unwrap().expect("the deferred child");
    assert_eq!(child.status, IntentStatus::Pending, "precondition");

    // The drive claims the attempt, then `observe` lets the peer authorize it, then §3.2
    // answers `AlreadyRestored` and the verification's pre-wire compare LOSES.
    *bus.connector().armed.borrow_mut() = Some(child_key.clone());
    let outcome = bus.drive_undo_child(&child);

    assert!(
        matches!(outcome, Err(ExecuteError::InProgress)),
        "a LOST pre-wire compare wrote nothing and reached no wire — the peer owns the \
         attempt now, and this driver may not report a verification it did not settle; \
         got {outcome:?}"
    );
    assert!(
        !bus.log()
            .get(&child_key)
            .unwrap()
            .expect("child")
            .status
            .is_terminal(),
        "…and the child row proves it: the settlement never landed"
    );
    // THE PARENT FLIP IS DELIBERATELY NOT ROLLED BACK, and this pins it: the flip is
    // justified by THIS driver's own verified `C == P` observation, not by attempt
    // ownership, and it is what keeps the heal-order convergence promise intact (parent
    // `Undone` + non-terminal child ⇒ the re-drive converges). See `verify_undo`'s header
    // for why the alternative — settle first, flip on acceptance — strands the pair instead.
    assert_eq!(
        status_str(&path, "k-r4-p2"),
        "undone",
        "the parent's truth is the observation, not the ledger race; the heal order stands"
    );
    std::fs::remove_file(&path).ok();
}

/// A connector that ADJUDICATES the in-flight attempt and lands a `LATE_ACK_REFUSED_NO_EFFECT`
/// on it — all INSIDE the dispatch, i.e. while it is on the wire — and then answers `Ok`
/// (the applied verdict that arrives after the operator has already decided).
///
/// The dispatch is `apply_witnessed` (the bus's door), and it answers a
/// label vector the way the Gmail routes do — [`ADJUDICATED_ROUTE_ANSWER`] — so what the
/// outranked arm persists is observable; `apply` is its projection.
struct AdjudicateAndRefuseDuringApply {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
}

/// The label vector [`AdjudicateAndRefuseDuringApply`]'s route answers with.
const ADJUDICATED_ROUTE_ANSWER: &str = "CATEGORY_UPDATES";

impl Connector for AdjudicateAndRefuseDuringApply {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_witnessed(command, basis).map(|_| ())
    }
    fn apply_witnessed(
        &self,
        command: &Command,
        _basis: &prestate::FrozenBasis,
    ) -> Result<EffectWitness, ConnectorError> {
        let key = command.idempotency_key.as_str();
        let attempt = attempt_id_of(&self.path, key);
        let mut side = SqliteIntentLog::open(&self.path).expect("the control plane opens");
        adjudicate_now(&mut side, key, &attempt);
        // …and the FIRST late ack the chain accepts says the effect did NOT happen.
        let first = side
            .record_late_ack(key, &attempt, crate::attempt::LateAck::RefusedNoEffect)
            .expect("the first late ack lands");
        assert!(
            matches!(first, LateAckOutcome::Resolved { .. }),
            "precondition: the REFUSED late ack is the chain's ACCEPTED truth, got {first:?}"
        );
        Ok(EffectWitness {
            provider_label_vector: Some([ADJUDICATED_ROUTE_ANSWER.to_string()].into_iter().collect()),
        })
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
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
fn a_late_ack_refused_as_contradiction_reports_the_chains_truth() {
    // ═══ ═══ The operator adjudicates mid-flight and a
    // `LATE_ACK_REFUSED_NO_EFFECT` lands FIRST. The in-flight `Applied` then returns, is
    // converted to a late ack by the whitelist arm, and is REFUSED AS A CONTRADICTION —
    // correctly: §5.2a's chain never records two contradicting attributions, and the
    // anomaly is durably annotated. But the settle arm mapped that refusal to a SUCCESSFUL
    // settlement, so `execute` answered `Ok(())` — "your action landed" — over a ledger
    // whose ACCEPTED verdict says it provably did not. An identical replay reads the
    // accepted verdict and answers the same thing: two answers, one truth.
    //
    // WHAT that one truth IS was reworked by: the resolved-refused answer is
    // `AdjudicatedLate(RefusedNoEffect)`, not the generic dead-letter `Failed` this test
    // used to name. The property under test is untouched — the in-flight answer equals the
    // replay answer, and neither is a silent `Ok`.
    let path = unique_temp_db_path("r4-p1-late-ack-contradiction");
    let command = archive_cmd("k-r4-p3");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        AdjudicateAndRefuseDuringApply {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
        },
    );

    let answered = bus.execute(&command);
    let attempt = attempt_id_of(&path, "k-r4-p3");

    assert!(
        chain_kinds(&path, &attempt).contains(&"late_ack_refused_no_effect".to_string()),
        "precondition: the ACCEPTED late ack is the refused-no-effect one: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert!(
        !chain_kinds(&path, &attempt).contains(&"late_ack_applied".to_string()),
        "precondition: the contradicting APPLIED late ack was refused — the chain is unchanged"
    );
    assert_eq!(
        answered,
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::RefusedNoEffect
        )),
        "the caller is owed the FIRST ACCEPTED late ack's truth — the effect provably did \
         not happen, on an operation an adjudication closed — never a silent `Ok` for an \
         action the ledger says never landed"
    );
    // The OUTRANKED arm still carries what the wire returned. The witness is
    // persisted BEFORE the `outranked` return (`persist_effect_witness_step`'s doc) because it
    // is the route's ANSWER, never a status — the status asserted above comes from the fact
    // chain. No verdict: this fixture's `observe` holds no label set, so there is no pre
    // vector to judge the delta against.
    assert_eq!(
        bus.log().effect_witness("k-r4-p3").unwrap(),
        Some(EffectWitnessRow {
            effect_label_vector: Some(
                [ADJUDICATED_ROUTE_ANSWER.to_string()].into_iter().collect()
            ),
            ripple_verdict: None,
        }),
        "an outranked settlement keeps the route's answer beside the operation"
    );

    // …and it agrees with the replay, which is the whole point.
    let mut replay = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        AlwaysOkConnector,
    );
    assert_eq!(
        replay.execute(&command),
        Err(ExecuteError::AdjudicatedLate(
            crate::attempt::LateAck::RefusedNoEffect
        )),
        "the in-flight answer and the replay answer are ONE truth table"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_the_recovery_door_persists_the_witness_before_its_outranked_count() {
    // The RECOVERY door's face of
    // `a_late_ack_refused_as_contradiction_reports_the_chains_truth` (the
    // mutant M4 — the sweep skipping the witness when outranked — survived
    // `-p aruna --lib`, 833/833). A pending intent's FIRST dispatch rides
    // `recover()`; the operator adjudicates it mid-flight and a `LATE_ACK_REFUSED_NO_EFFECT`
    // lands first, so the sweep's `Applied` settlement is OUTRANKED — and the route's answer
    // is still persisted beside the operation, because the sweep persists it BEFORE its
    // `outranked.is_none()` count (`persist_effect_witness_step`'s doc).
    let path = unique_temp_db_path("s1-recover-outranked-witness");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        AdjudicateAndRefuseDuringApply {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
        },
    );
    // Admit the intent WITHOUT dispatching it: a live same-resource predecessor defers it,
    // so its one and only attempt is the sweep's (the fixture adjudicates THAT attempt).
    seed_pending_peer(&path, &bus, "k-rec-outranked-peer");
    let deferred = bus.execute(&archive_cmd("k-rec-outranked"));
    assert!(
        matches!(deferred, Err(ExecuteError::InProgress)),
        "precondition: the intent defers behind its live predecessor, got {deferred:?}"
    );
    assert_eq!(
        bus.log().get("k-rec-outranked").unwrap().expect("admitted").status,
        IntentStatus::Pending,
        "precondition: admitted, pending, never dispatched"
    );
    terminalize_peer(&path, "k-rec-outranked-peer");

    let report = bus.recover().expect("the sweep dispatches the pending intent");

    let attempt = attempt_id_of(&path, "k-rec-outranked");
    assert!(
        chain_kinds(&path, &attempt).contains(&"late_ack_refused_no_effect".to_string()),
        "precondition: the chain's ACCEPTED truth is the refused-no-effect late ack, so the \
         sweep's settlement was outranked: {:?}",
        chain_kinds(&path, &attempt)
    );
    assert_eq!(
        report.recovered, 0,
        "an outranked settlement is not a recovery this sweep may count: {report:?}"
    );
    assert_eq!(
        bus.log().effect_witness("k-rec-outranked").unwrap(),
        Some(EffectWitnessRow {
            effect_label_vector: Some(
                [ADJUDICATED_ROUTE_ANSWER.to_string()].into_iter().collect()
            ),
            ripple_verdict: None,
        }),
        "the RECOVERY door keeps the route's answer beside an outranked operation, like the \
         execute door"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_corrupted_head_owner_refuses_the_open() {
    // ═══ ═══ `attempt_head.operation_id` is the ONE projected column boot
    // never loaded, so the owner the projection names was never compared with the owner the
    // FOLD derives from the CLAIM fact. That is the head/fold-divergence class exactly — a
    // second authority for "whose attempt is this" — and its rule is already written: it
    // REFUSES THE OPEN.
    let path = unique_temp_db_path("r4-p2-head-owner");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit_and_claim(&mut log, &archive_of("k-r4-owner", "msg-1"))
    };
    raw_conn(&path)
        .execute(
            "UPDATE attempt_head SET operation_id = 'not-the-claims-owner'
                  WHERE attempt_id = ?1;",
            rusqlite::params![attempt],
        )
        .expect("hand-edit the projection");

    let refusal = open_refusal(&path);

    assert!(
        refusal.contains("diverges from its chain"),
        "a projection naming an owner the chain does not is a SECOND authority: {refusal}"
    );
    std::fs::remove_file(&path).ok();
}

/// Hand-corrupt `attempt_fact.attempt_ordinal` on a CLOSED store. The append-only UPDATE
/// trigger is dropped for the edit and left dropped — the next open's own DDL restores it
/// (`CREATE TRIGGER IF NOT EXISTS`), so the craft models on-disk corruption rather than a
/// door this engine owns.
fn corrupt_ordinal_column(
    path: &std::path::Path,
    attempt_id: &str,
    fact_kind: &str,
    ordinal: Option<i64>,
) {
    let conn = raw_conn(path);
    conn.execute_batch("DROP TRIGGER IF EXISTS attempt_fact_no_update;")
        .expect("drop the append-only guard for the craft");
    conn.execute(
        "UPDATE attempt_fact SET attempt_ordinal = ?3
              WHERE attempt_id = ?1 AND fact_kind = ?2;",
        rusqlite::params![attempt_id, fact_kind, ordinal],
    )
    .expect("hand-edit the ordinal column");
}

#[test]
fn a_corrupted_claim_ordinal_column_refuses_the_open() {
    // ═══ ═══ `attempt_fact.attempt_ordinal` is the SQL half of
    // ATTEMPT-ORDINAL/RETRY-TOTALITY (`UNIQUE (operation_id, attempt_ordinal)`), and the
    // fact reader never selected it — so the column the retry-lineage referee is keyed on
    // was free to disagree with the CLAIM payload the grammar folds. Two authorities for one
    // ordinal; the reader must marry them or the referee is unchecked.
    let path = unique_temp_db_path("r4-p2-claim-ordinal");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        admit_and_claim(&mut log, &archive_of("k-r4-ordinal", "msg-1"))
    };
    corrupt_ordinal_column(&path, &attempt, "claim", Some(7));

    let refusal = open_refusal(&path);

    assert!(
        refusal.contains("attempt_ordinal"),
        "the stored ordinal column and the CLAIM payload's ordinal are one value in two \
         places — a disagreement is fail-loud, never a read the grammar silently believes: \
         {refusal}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_non_claim_fact_may_not_carry_an_ordinal() {
    // The other half of the same marriage: every NON-claim fact's ordinal column is NULL by
    // construction (that is what keeps only the one CLAIM row in `UNIQUE (operation_id,
    // attempt_ordinal)`). A non-NULL there silently enrolls a second row in the retry-lineage
    // referee's uniqueness.
    let path = unique_temp_db_path("r4-p2-nonclaim-ordinal");
    let attempt = {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        let attempt = admit_and_claim(&mut log, &archive_of("k-r4-nonclaim", "msg-1"));
        authorize_now(&mut log, "k-r4-nonclaim", &attempt);
        attempt
    };
    corrupt_ordinal_column(&path, &attempt, "send_authorized", Some(2));

    let refusal = open_refusal(&path);

    assert!(
        refusal.contains("attempt_ordinal"),
        "a non-CLAIM fact carrying an ordinal is a forged enrolment in the retry-lineage \
         referee's uniqueness: {refusal}"
    );
    std::fs::remove_file(&path).ok();
}
