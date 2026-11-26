//! The verdict-mapping table: every connector outcome appends its verdict fact.

use super::*;
use crate::keys::undo_child_key;

// ═══════════════════════════════════════════════════════════════════════════════════
// THE VERDICT-MAPPING TABLE (design §5.2a/§5.2b) — every connector
// outcome appends its verdict fact at the ONE reconcile boundary, with the operation's
// lifecycle moving in the SAME transaction.
// ═══════════════════════════════════════════════════════════════════════════════════

/// Every attempt id an operation holds, in ordinal order (a retry mints a NEW one).
fn attempt_ids_of(path: &std::path::Path, key: &str) -> Vec<String> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT attempt_id FROM attempt_fact
                  WHERE operation_id = (SELECT intent_id FROM intents WHERE idempotency_key = ?1)
                    AND fact_kind = 'claim' ORDER BY attempt_ordinal;",
        )
        .expect("prepare");
    let ids = stmt
        .query_map(rusqlite::params![key], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|k| k.expect("row"))
        .collect();
    ids
}

#[test]
fn a_successful_dispatch_appends_its_ack_applied_verdict() {
    // ROW (a). Success ⇒ `ACK_APPLIED`, with the operation `Applied` and the head's
    // `last_verified_revision` advanced to the FINAL revision — one transaction (§5.2a
    // LIFECYCLE ATOMICITY +).
    let path = unique_temp_db_path("verdict-applied");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );

    bus.execute(&archive_cmd("k-ok")).expect("the forward applies");

    let attempt = attempt_id_of(&path, "k-ok");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_applied"],
        "the provider response definitively proves the effect — the verdict is a FACT, not \
         an inference from the status column"
    );
    assert_eq!(status_str(&path, "k-ok"), "applied");
    assert_eq!(
        head_of(&path, &attempt),
        (3, "applied".to_string(), 3),
        "every finalization advances `last_verified_revision` to the final revision in the \
         SAME txn (§5.2a codex r32/r33 P1)"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_definitive_provider_refusal_appends_ack_refused_no_effect() {
    // ROW (b). A provider that ANSWERED and rejected before any effect (4xx-class) is
    // `ACK_REFUSED_NO_EFFECT` — definitive proof of rejection, so the operation
    // dead-letters in the same transaction (ADR-P013 (b), unchanged).
    let path = unique_temp_db_path("verdict-refused");
    let wire = UndoStageConnector::single(false, true);
    wire.fail_apply_with(definitive_refusal("provider rejected the mutation"), u32::MAX);
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire);

    let answered = bus.execute(&archive_cmd("k-4xx"));

    assert!(matches!(answered, Err(ExecuteError::Connector(_))));
    let attempt = attempt_id_of(&path, "k-4xx");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_refused_no_effect"],
        "a DEFINITIVE refusal is a terminal attribution — never the ambiguous verdict"
    );
    assert_eq!(
        status_str(&path, "k-4xx"),
        "failed",
        "deterministic ⇒ dead-lettered in the verdict's own transaction"
    );
    assert_eq!(
        head_of(&path, &attempt),
        (3, "refused_no_effect".to_string(), 3),
        "the head projects the fact-derived class and the verified baseline"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_pre_authorization_failure_appends_failed_pre_send_and_keeps_the_retry_budget() {
    // ROW (c). The undo drive CLAIMS before it observes, so an `observe` failure is a
    // POST-CLAIM, PRE-AUTHORIZATION engine-side failure: no `SEND_AUTHORIZED` exists, so
    // no wire could have been touched — `FAILED_PRE_SEND`, and the EXISTING transient
    // retry semantics are untouched (budget charged, operation left ACTIVE).
    let path = unique_temp_db_path("verdict-pre-auth");
    let wire = UndoStageConnector::single(false, true);
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire);
    bus.execute(&archive_cmd("k-pre")).expect("the forward applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    bus.connector()
        .fail_observe(retryable_transient("undo observation failed mid-flight"));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-pre"));

    let answered = bus.undo("k-pre");

    assert!(matches!(answered, Err(ExecuteError::Connector(_))));
    let attempt = attempt_id_of(&path, &child_key);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "failed_pre_send"],
        "claimed, never authorized: the failure is proven no-effect BY CONSTRUCTION"
    );
    assert_eq!(
        status_str(&path, &child_key),
        "pending",
        "transient + budget remaining ⇒ the operation stays lifecycle-ACTIVE"
    );
    assert_eq!(
        attempts_of(&path, &child_key),
        1,
        "the retry budget is charged exactly once, in the verdict's own transaction"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_post_authorization_failure_proven_no_wire_stays_retryable() {
    // ROWS (d) + (f) + the retry that (c)'s "existing semantics preserved" promises. A
    // POST-authorization failure carrying the connector's POSITIVE proven-no-wire proof is
    // `FAILED_PRE_SEND` (§5.2a) — retryable, so the operation holds its
    // tail position, and the next sweep dispatches a NEW attempt (the §5.2c retry gap).
    let path = unique_temp_db_path("verdict-proven-no-wire");
    let wire = UndoStageConnector::single(false, true);
    wire.fail_apply_with(retryable_transient("connect refused"), 1);
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire);

    let answered = bus.execute(&archive_cmd("k-pnw"));

    assert!(matches!(answered, Err(ExecuteError::Connector(_))));
    let first = attempt_ids_of(&path, "k-pnw");
    assert_eq!(first.len(), 1, "one attempt so far");
    assert_eq!(
        chain_kinds(&path, &first[0]),
        vec!["claim", "send_authorized", "failed_pre_send"],
        "proven-no-wire post-auth ⇒ FAILED_PRE_SEND, never ISSUANCE_UNKNOWN — classifying a \
         safely-retryable outage as unknown would burn the slot and demand adjudication"
    );
    assert_eq!(
        status_str(&path, "k-pnw"),
        "pending",
        "LIFECYCLE ATOMICITY: it completes ONLY when no eligible retry remains"
    );
    assert_eq!(attempts_of(&path, "k-pnw"), 1);
    assert_eq!(
        head_of(&path, &first[0]),
        (3, "failed_pre_send".to_string(), 3),
        "the terminal attribution advances the verified baseline too"
    );

    // (f) TAIL POSITION: the operation is still ACTIVE, so a same-resource successor is
    // still blocked behind it.
    assert!(
        matches!(bus.execute(&archive_cmd("k-succ")), Err(ExecuteError::InProgress)),
        "a lifecycle-ACTIVE operation in its retry gap still holds its tail position"
    );

    // …and the retry itself: a NEW attempt, with the lineage the grammar demands.
    bus.recover().expect("the sweep retries");
    let after = attempt_ids_of(&path, "k-pnw");
    assert_eq!(
        after.len(),
        2,
        "a retry is a NEW attempt against a terminally-attributed predecessor (§5.2a \
         ATTEMPT-ORDINAL/RETRY-TOTALITY), never a second wire touch on the old one"
    );
    assert_eq!(
        chain_kinds(&path, &after[1]),
        vec!["claim", "send_authorized", "ack_applied"],
        "the successor attempt runs the whole boundary again and settles APPLIED"
    );
    assert_eq!(status_str(&path, "k-pnw"), "applied");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_post_authorization_failure_of_unknown_issuance_is_never_retried() {
    // ROW (e). ISSUANCE_UNKNOWN: an UNPROVEN post-authorization failure is `ACK_AMBIGUOUS`
    // — not a terminal attribution, so the operation is NOT dead-lettered as an ordinary
    // `Failed`; and no retry is EVER legal from it (§5.2a: "adjudication is the only
    // path"), so recover must not re-dispatch it.
    let path = unique_temp_db_path("verdict-ambiguous");
    let wire = UndoStageConnector::single(false, true);
    wire.fail_apply_with(
        ConnectorError::transient("the provider closed the connection after the POST"),
        u32::MAX,
    );
    let mut bus = CommandBus::new(SqliteIntentLog::open(&path).expect("open"), wire);

    let answered = bus.execute(&archive_cmd("k-unknown"));

    assert!(matches!(answered, Err(ExecuteError::Connector(_))));
    let attempt = attempt_id_of(&path, "k-unknown");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_ambiguous"],
        "unproven post-auth ⇒ ISSUANCE_UNKNOWN; an ack verdict requires positive proof"
    );
    assert_eq!(
        status_str(&path, "k-unknown"),
        "pending",
        "NOT dead-lettered as an ordinary failure — it stays open, awaiting adjudication"
    );
    assert_eq!(
        attempts_of(&path, "k-unknown"),
        0,
        "no retry is authorized, so no retry budget is spent"
    );
    assert_eq!(
        head_of(&path, &attempt).1,
        "issued_or_unknown",
        "the head class is the honest one: we cannot prove issuance either way"
    );

    let report = bus.recover().expect("the sweep runs");

    assert_eq!(
        bus.connector().apply_count() + bus.connector().restore_call_count(),
        0,
        "NO RETRY EVER from an ambiguous attempt — recover() must not touch the wire again"
    );
    assert_eq!(report.recovered, 0);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_ambiguous"],
        "…and the sweep grows no second ambiguous verdict either (at most one per attempt)"
    );
    assert_eq!(
        attempt_ids_of(&path, "k-unknown").len(),
        1,
        "…and mints no successor attempt: the retry gap is only reachable from a TERMINAL \
         attribution, which ISSUANCE_UNKNOWN is not"
    );
    assert_eq!(status_str(&path, "k-unknown"), "pending");
    std::fs::remove_file(&path).ok();
}

/// A connector that bumps `control_epoch` INSIDE `apply` and then fails proven-no-wire —
/// the interleave: a settlement that lands AFTER a sever.
struct SeverDuringApply {
    inner: UndoStageConnector,
    path: std::path::PathBuf,
}

impl Connector for SeverDuringApply {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        // A REAL sever, mid-dispatch: this attempt is ALREADY authorized, so §5.2c
        // classifies it ISSUED_OR_UNKNOWN and the sever leaves it alive — the settlement
        // below is what must notice the moved epoch.
        sever_from_control_plane(&self.path, "authority:mid-dispatch");
        Err(retryable_transient("connect refused after the sever"))
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
fn a_proven_no_wire_settlement_under_a_newer_epoch_severs_instead_of_waiting() {
    // ROW (g), the SETTLEMENT-EPOCH arm (§5.2a): "a proven-no-wire settlement
    // landing AFTER a sever must not leave the operation active-with-budget behind an epoch
    // that will refuse its retry forever". The settling transaction's own epoch check
    // terminalizes it `Severed` instead — the sever's classification, completed honestly.
    let path = unique_temp_db_path("verdict-settlement-epoch");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        SeverDuringApply {
            inner: UndoStageConnector::single(false, true),
            path: path.to_path_buf(),
        },
    );

    let answered = bus.execute(&archive_cmd("k-late-sever"));

    assert!(matches!(answered, Err(ExecuteError::Connector(_))));
    let attempt = attempt_id_of(&path, "k-late-sever");
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "failed_pre_send"],
        "the ATTRIBUTION stays truthful — the connector proved no wire, and a sever cannot \
         make that untrue (SEVERED_BEFORE_ISSUANCE is legal only pre-authorization)"
    );
    assert_eq!(
        status_str(&path, "k-late-sever"),
        "severed",
        "…but the LIFECYCLE completes: no retry is authorized under the new epoch, so the \
         tail position releases instead of stranding forever"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_undo_child_restore_appends_its_own_verdict() {
    // The undo door's half of the table: the child's attempt carries the verdict for its
    // OWN dispatch (§5.2b applies at all three wire-bound doors, not just the forward two).
    let path = unique_temp_db_path("verdict-undo-child");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        UndoStageConnector::single(false, true),
    );
    bus.execute(&archive_cmd("k-undo-v")).expect("the forward applies");
    bus.connector().set_state(atoms(&[("membership:INBOX", false)]));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-undo-v"));

    bus.undo("k-undo-v").expect("C == A ⇒ the delta restore dispatches");

    let attempt = attempt_id_of(&path, &child_key);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "send_authorized", "ack_applied"],
        "a verified restore is the child attempt's own ACK_APPLIED"
    );
    assert_eq!(status_str(&path, &child_key), "applied");
    assert_eq!(status_str(&path, "k-undo-v"), "undone");
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_deterministic_undo_refusal_appends_failed_pre_send_on_the_child() {
    // The undo door's deterministic arm: the §3.2 CONFLICT and the basis-rebind refusals
    // are engine-side, PRE-authorization decisions — proven no-effect, dead-lettered.
    let path = unique_temp_db_path("verdict-undo-conflict");
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("open"),
        // P = {inbox, not archived} — genuinely different from the forward target A, so
        // the §4.1 no-op kill does not fire and the drive reaches the §3.2 table.
        UndoStageConnector::pair(true, false),
    );
    bus.execute(&archive_cmd("k-conflict")).expect("the forward applies");
    // Neither P nor A: the §3.2 third state an external client produced.
    bus.connector()
        .set_state(atoms(&[("membership:mb-i", true), ("membership:mb-a", true)]));
    let child_key = undo_child_key(&opaque_intent_id(&path, "k-conflict"));

    let answered = bus.undo("k-conflict");

    assert!(matches!(answered, Err(ExecuteError::UndoConflict)));
    let attempt = attempt_id_of(&path, &child_key);
    assert_eq!(
        chain_kinds(&path, &attempt),
        vec!["claim", "failed_pre_send"],
        "refused before any authorization — the attempt records that no effect exists"
    );
    assert_eq!(status_str(&path, &child_key), "failed");
    assert_eq!(
        status_str(&path, "k-conflict"),
        "applied",
        "the parent stays truthfully applied — the undo never ran"
    );
    std::fs::remove_file(&path).ok();
}
