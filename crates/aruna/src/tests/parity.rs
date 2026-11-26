//! The in-memory parity class: the twin answers every stage-4 door the way the durable store does.

use super::*;

// ═══════════════════════════════════════════════════════════════════════════════════
// THE IN-MEMORY PARITY CLASS, closed WHOLESALE.
//
// `InMemoryIntentLog` is not a toy: it is what the fast tests — and every bus-level
// proof written against it — actually exercise. A surface the durable door implements
// and the mirror does not is a surface whose engine-level property is UNTESTED by all
// of those proofs, and (worse) one where the two doors answer the same store
// differently. named three divergences; the sweep below is over the WHOLE stage-4
// surface, and every deviation that remains is a NAMED absence with its reason at its
// own site.
// ═══════════════════════════════════════════════════════════════════════════════════

/// Drive one operation on the in-memory log to ISSUANCE_UNKNOWN: admit, claim, authorize,
/// settle ambiguous. The mirror of the durable tests' `unknown_attempt`.
fn in_memory_unknown_attempt(log: &mut InMemoryIntentLog, command: &Command) -> String {
    record_basis(log, command).expect("admit");
    let attempt = in_memory_claim(log, &command.idempotency_key);
    in_memory_authorize(log, &command.idempotency_key, &attempt);
    log.settle_attempt(
        &command.idempotency_key,
        &attempt,
        ConnectorVerdict::Failed {
            kind: FailureKind::Transient,
            evidence: EffectEvidence::Indeterminate,
        },
        RETRY_CAP,
        None,
    )
    .expect("settle ambiguous");
    attempt
}

fn in_memory_adjudicate(log: &mut InMemoryIntentLog, key: &str, attempt: &str) -> String {
    match log
        .adjudicate(
            key,
            attempt,
            "authority:operator",
            crate::attempt::AdjudicationReason::OperatorAbandonedUnresolved,
            crate::attempt::AcceptedRisk::NoneClaimed,
        )
        .expect("adjudicate")
    {
        AdjudicationOutcome::Adjudicated {
            adjudication_id, ..
        } => adjudication_id,
        other => panic!("adjudication must be granted, got {other:?}"),
    }
}

/// The annotation kinds hanging on one adjudication record, in append order — the
/// in-memory twin of `annotation_kinds`.
fn in_memory_annotation_kinds(log: &InMemoryIntentLog, record: &str) -> Vec<String> {
    log.adjudication_annotations()
        .iter()
        .filter(|a| a.adjudication_id == record)
        .map(|a| a.kind.as_sql().to_string())
        .collect()
}

#[test]
fn in_memory_settle_applied_writes_the_exposure_materialization_trace() {
    // ═══ ═══ The durable `settle_attempt` runs EXP-7's OTHER ORDER on an
    // `ACK_APPLIED`: "which of the two effects resolves first must not decide whether a
    // notice exists". The mirror ran only the late-ack order, so a peer's provable effect
    // over somebody's unresolved exposure left NO trace on this log at all — and every
    // bus-level test of that arm was passing against a door that does not write it.
    let mut log = InMemoryIntentLog::new();
    let unknown = archive_cmd("k-unknown");
    let attempt = in_memory_unknown_attempt(&mut log, &unknown);

    // The peer authorizes BEFORE the obligation exists — the only way an overlapping effect
    // can be in flight in a build with no risk-acceptance capability (the durable tests'
    // own craft).
    let peer = archive_cmd("k-peer");
    record_basis(&mut log, &peer).expect("admit");
    let peer_attempt = in_memory_claim(&mut log, "k-peer");
    in_memory_authorize(&mut log, "k-peer", &peer_attempt);

    let record = in_memory_adjudicate(&mut log, "k-unknown", &attempt);
    log.settle_attempt("k-peer", &peer_attempt, ConnectorVerdict::Applied, RETRY_CAP, None)
        .expect("the peer's effect provably happened");

    assert_eq!(
        in_memory_annotation_kinds(&log, &record),
        vec!["applied-over-unresolved".to_string()],
        "the durable half-trace is owed on the SETTLE order too, not only the late-ack one"
    );
    assert_eq!(
        log.adjudication_annotations()[0].atom_key.as_deref(),
        Some(fixture_atom("msg-1").as_str()),
        "…and it names the atom the two effects share"
    );
}

#[test]
fn in_memory_admission_links_the_first_overlapping_successor_and_only_the_first() {
    // ═══ ═══ §5.2d's AUDIT EDGE. The durable admission writes
    // `SUPERSEDED_BY` onto every adjudicated attempt whose unresolved exposure the new
    // operation overlaps, atomically with the admission. The mirror wrote none, so the
    // "at most one, first only" property had no fast-test coverage at all.
    let mut log = InMemoryIntentLog::new();
    let unknown = archive_cmd("k-unknown");
    let attempt = in_memory_unknown_attempt(&mut log, &unknown);
    in_memory_adjudicate(&mut log, "k-unknown", &attempt);

    record_basis(&mut log, &archive_cmd("k-successor-1")).expect("admit the first successor");
    let successors: Vec<String> = log
        .attempt_facts()
        .iter()
        .filter(|f| f.attempt_id == attempt)
        .filter_map(|f| match &f.payload {
            crate::attempt::FactPayload::SupersededBy {
                successor_operation_id,
            } => Some(successor_operation_id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        successors,
        vec!["k-successor-1".to_string()],
        "the first overlapping admission is linked (this log's operation id IS the key)"
    );

    // A SECOND overlapping admission is ADMITTED and carries NO edge; a DISJOINT one never
    // touches it either.
    record_basis(&mut log, &archive_cmd("k-successor-2")).expect("admit the second");
    let disjoint = Command::new(
        "k-elsewhere",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-9".into(),
        },
    );
    record_basis(&mut log, &disjoint).expect("admit the disjoint operation");
    assert!(
        log.get("k-successor-2").expect("get").is_some(),
        "the edge is an audit pointer, never an admission gate"
    );
    assert_eq!(
        log.attempt_facts()
            .iter()
            .filter(|f| f.kind == crate::attempt::FactKind::SupersededBy)
            .count(),
        1,
        "AT MOST ONE successor per adjudicated attempt"
    );
}

#[test]
fn in_memory_late_ack_scopes_the_materialization_scan_to_the_live_episode() {
    // ═══ ═══ EXP-9's NON-BLEED, which the durable scan enforces with a
    // WINDOW (`retired_at IS NULL OR retired_at >= <this attempt's SEND_AUTHORIZED>`) and
    // the mirror enforced not at all: its scan read EVERY obligation row on the atom, so a
    // NEW episode's resolution minted a false `exposure-materialized` notice against a
    // long-settled stranger's adjudication record.
    let mut log = InMemoryIntentLog::new();

    // EPISODE 1: adjudicated and fully resolved.
    let first = archive_cmd("k-episode-1");
    let first_attempt = in_memory_unknown_attempt(&mut log, &first);
    let first_record = in_memory_adjudicate(&mut log, "k-episode-1", &first_attempt);
    log.record_late_ack(
        "k-episode-1",
        &first_attempt,
        crate::attempt::LateAck::Applied,
    )
    .expect("episode 1 SETTLES");
    // It settled LONG before anything below was authorized. Stated as a date rather than
    // raced against the clock: `created_at` is RFC-3339 SECONDS, so two events inside one
    // test share a timestamp — exactly the reason the durable twin back-dates by hand.
    log.seed_obligation_retirement(&first_attempt, "2020-01-01T00:00:00Z");

    // EPISODE 2: a fresh, independent unknown on the same atom, adjudicated and then
    // resolved. Its resolution is about ITS episode and nobody else's.
    let second = archive_cmd("k-episode-2");
    let second_attempt = in_memory_unknown_attempt(&mut log, &second);
    in_memory_adjudicate(&mut log, "k-episode-2", &second_attempt);
    log.record_late_ack(
        "k-episode-2",
        &second_attempt,
        crate::attempt::LateAck::Applied,
    )
    .expect("episode 2 resolves");

    assert_eq!(
        in_memory_annotation_kinds(&log, &first_record),
        Vec::<String>::new(),
        "a settled episode is not contaminated by the next one (EXP-9)"
    );
}

#[test]
fn in_memory_claim_is_epoch_fenced_exactly_where_the_durable_one_is() {
    // THE SWEEP'S OWN FIND (not one of three): `claim_attempt` documented
    // `ClaimOutcome::EpochFenced` as UNREACHABLE on this log because it modelled no
    // per-operation admitted epoch. That absence is not inert — an operation that survives
    // a sever ACTIVE (its attempt is ISSUED_OR_UNKNOWN, which a sever may not close) is
    // fenced by the durable door and was handed straight back as a re-entry WIN by the
    // mirror. A fake that grants dispatch ownership the engine refuses is worse than a
    // fake that lacks the surface.
    let mut log = InMemoryIntentLog::new();
    let command = archive_cmd("k-survives");
    record_basis(&mut log, &command).expect("admit");
    let attempt = in_memory_claim(&mut log, "k-survives");
    in_memory_authorize(&mut log, "k-survives", &attempt);

    let severed = log
        .sever("authority:test-operator", "2026-08-08T00:00:00Z")
        .expect("sever");
    assert_eq!(
        log.get("k-survives").expect("get").expect("row").status,
        IntentStatus::Pending,
        "precondition: an ISSUED_OR_UNKNOWN member is witnessed and left ALIVE"
    );
    assert!(severed.epoch > 1, "precondition: the fence moved");

    assert!(
        !log.admitted_epoch_is_current("k-survives").expect("fence"),
        "the operation was admitted under a fence that is gone"
    );
    assert_eq!(
        log.claim_attempt(
            "k-survives",
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim"),
        ClaimOutcome::EpochFenced,
        "the epoch check runs BEFORE the latest-attempt lookup, on both doors"
    );
}

#[test]
fn in_memory_live_attempt_uses_the_one_partition_rule() {
    // THE SWEEP'S SECOND FIND. The durable `live_attempt` answers through
    // `sever_disposition` — the ONE copy of the rule — which FAILS LOUD when an operation
    // holds more than one live attempt ("the CLAIM grammar permits exactly one, and the
    // §5.2c partition is total only because of it"). The mirror ran its own loop and
    // silently answered with the LAST live attempt it happened to see, so a store defect
    // the durable door refuses read back as an ordinary class here.
    //
    // CRAFT: the second live claim is seeded onto the mirror by hand, exactly as the
    // durable tests seed a defective row through `raw_conn` — the CLAIM door refuses to
    // mint one, which is the point.
    let mut log = InMemoryIntentLog::new();
    let command = archive_cmd("k-two-live");
    record_basis(&mut log, &command).expect("admit");
    let first = in_memory_claim(&mut log, "k-two-live");
    log.attempt_facts.push(crate::attempt::Fact {
        operation_id: "k-two-live".to_string(),
        attempt_id: "mem-attempt-hand-seeded".to_string(),
        revision: 1,
        kind: crate::attempt::FactKind::Claim,
        basis_epoch: 1,
        created_at: "2026-08-08T00:00:00Z".to_string(),
        payload: crate::attempt::FactPayload::Claim {
            ordinal: 2,
            // The lineage the FOLD requires of any ordinal > 1. It names the first attempt,
            // which is still LIVE — which is precisely the defect: two live attempts, one
            // operation. (The CLAIM door's own `retry_lineage_legal` refuses this; only a
            // hand-seeded row can reach it, exactly as in the durable tests.)
            predecessor: Some(crate::attempt::RetryPredecessor {
                attempt_id: first.clone(),
                reason: crate::attempt::RetryReason::FailedPreSend,
            }),
        },
        prior_revision: None,
    });
    assert_ne!(first, "mem-attempt-hand-seeded");

    let answer = log.live_attempt("k-two-live");
    assert!(
        answer.is_err(),
        "two live attempts on one operation is a fail-loud store defect on BOTH doors, \
         got {answer:?}"
    );
}
