//! Capacity admission, the `settle_status` chokepoint, and pending capacity reductions.

use super::*;
use rusqlite::OptionalExtension;

use crate::sqlite_log::read_effective_bounds;

/// Append a `kind='capacity'` act at the next generation, RAW (the
/// trigger's own kind filter, `kind = 'capacity'`, is what makes it a PENDING candidate —
/// `append_config_act`'s `'mode_change'` kind is invisible to it on purpose). Returns the
/// generation it landed at, so a witness can name the exact generation it expects
/// activated.
fn append_capacity_act(path: &std::path::Path, payload: &str) -> i64 {
    let conn = raw_conn(path);
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config),
                     strftime('%s','now'), 'capacity', ?1);",
        rusqlite::params![payload],
    )
    .expect("append capacity act");
    conn.query_row("SELECT MAX(generation) FROM engine_config;", [], |r| r.get(0))
        .expect("read back generation")
}

/// Append a RAW `kind='capacity_activated'` act carrying `payload` verbatim — the only
/// door a malformed activation pointer fits through (F-A: the API writes
/// this act through `json_object`, so raw SQL or corruption is the only way one enters).
fn append_activation_act(path: &std::path::Path, payload: &str) -> i64 {
    let conn = raw_conn(path);
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config),
                     strftime('%s','now'), 'capacity_activated', ?1);",
        rusqlite::params![payload],
    )
    .expect("append capacity_activated act");
    conn.query_row("SELECT MAX(generation) FROM engine_config;", [], |r| r.get(0))
        .expect("read back generation")
}

/// The generation the LATEST `kind='capacity_activated'` act names, if one exists — a
/// raw-SQL ORACLE over the ledger, for witnesses that assert directly on it without going
/// through `record_capacity_config`.
///
/// **DELIBERATELY NOT routed through `capacity::parse_activation_pointer`** (a named exception to the one-authority sweep): this is the INDEPENDENT
/// observer the production readers are checked AGAINST, and an oracle that shares the
/// parser it is meant to catch proves nothing — the same reason
/// `unbounded_activation_fit_predicate_sql` and `store_open`'s
/// `split_autocommit_capacity_read` keep their own frozen copies. It sees only well-formed
/// pointers the API itself wrote, so its `json_extract` never meets a shape the production
/// authority would refuse; witnesses that PLANT a malformed pointer assert through the
/// production readers instead
/// (`codex_r5_a_null_activation_pointer_refuses_the_admission_read`).
fn latest_activated_generation(path: &std::path::Path) -> Option<i64> {
    raw_conn(path)
        .query_row(
            "SELECT CAST(json_extract(payload, '$.activates_generation') AS INTEGER)
                   FROM engine_config WHERE kind = 'capacity_activated'
                  ORDER BY generation DESC LIMIT 1;",
            [],
            |r| r.get(0),
        )
        .optional()
        .expect("read latest activation")
}

/// Every `kind='capacity_activated'` act's named generation, in ledger (append) order —
/// for witnesses that must count activations, not just read the latest one. Same
/// independent-oracle disposition as [`latest_activated_generation`]; see its doc.
fn all_activated_generations(path: &std::path::Path) -> Vec<i64> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT CAST(json_extract(payload, '$.activates_generation') AS INTEGER)
                   FROM engine_config WHERE kind = 'capacity_activated' ORDER BY generation;",
        )
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

#[test]
fn admission_refuses_at_cap_with_distinct_reasons() {
    // A SMALL capacity config,
    // injected through `record_capacity_config` (its own door — a raw `append_
    // config_act`, kind='mode_change', is now invisible to `effective_bounds`, which
    // reads ONLY `kind='capacity'` acts). Occupancy is empty at this point, so the
    // config transaction's own no-traffic fit-check activates it immediately — exactly
    // the "one act, immediately current" behavior this test always relied on.
    let path = unique_temp_db_path("admission-cap");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap the store + its generation-1 act");
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config"); // max_active_ops=64 (the domain FLOOR), undo_reserve=32 -> forward_bound=32.
    // Fill the forward reserve EXACTLY (32 forward, non-terminal Pending rows).
    for i in 0..32 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    // Fill the rest of the total cap with undo occupancy (32 more, total=64=max).
    for i in 0..32 {
        let mut cmd = archive_cmd(&format!("k-undo-{i}"));
        cmd.compensates = Some(format!("k-fwd-{i}"));
        assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    }
    // A further FORWARD claim refuses on the RESERVE (32 active_forward + 1 > 32) even
    // though the total has no room either — the reserve is checked first (both must
    // hold; the reserve is the tighter of the two here).
    let forward_refusal = record_basis(&mut log, &archive_cmd("k-fwd-overflow")).unwrap();
    let forward_msg = match forward_refusal {
        Claim::CapacityRefused(msg) => msg,
        other => panic!("expected a forward CapacityRefused, got {other:?}"),
    };
    assert!(
        forward_msg.contains("forward"),
        "expected the forward-reserve message, got: {forward_msg}"
    );
    // A further UNDO claim refuses on the TOTAL cap (64 + 1 > 64) — the reserve never
    // gates undo, so this is the OTHER inequality, and its message says so.
    let mut undo_overflow = archive_cmd("k-undo-overflow");
    undo_overflow.compensates = Some("k-fwd-0".into());
    let undo_refusal = record_basis(&mut log, &undo_overflow).unwrap();
    let undo_msg = match undo_refusal {
        Claim::CapacityRefused(msg) => msg,
        other => panic!("expected an undo CapacityRefused, got {other:?}"),
    };
    assert!(
        undo_msg.contains("max_active_ops"),
        "expected the total-cap message, got: {undo_msg}"
    );
    // DISTINCT reasons: the two refusals name different inequalities.
    assert_ne!(forward_msg, undo_msg);
    assert!(
        !undo_msg.contains("forward"),
        "the total-cap message must not read like a forward-reserve one, got: {undo_msg}"
    );
    // NOTHING durable was written by either refusal: exactly 64 intents remain.
    let count: i64 = raw_conn(&path)
        .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 64, "a capacity refusal must leave nothing behind");
    std::fs::remove_file(&path).ok();
}

/// The derived occupancy COUNT (design §5.3): every non-terminal `intents` row, over the
/// ONE authority (`NON_TERMINAL_STATUS_SQL`) — the same predicate `record`'s admission
/// door counts against, read RAW so the assertion is independent of the admission path.
fn non_terminal_count(path: &std::path::Path) -> i64 {
    raw_conn(path)
        .query_row(
            &format!("SELECT COUNT(*) FROM intents WHERE status IN {NON_TERMINAL_STATUS_SQL};"),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// The small 64/32 capacity fixture `admission_refuses_at_cap_with_distinct_reasons`
/// established, reused here for the at-cap drain witnesses.
const T3_CAPACITY_PAYLOAD: &str = r#"{"capture":"on","capacity":{"max_active_ops":64,
        "undo_reserve":32,"writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,
        "sever_joiner_cap":16}}"#;

/// The [`crate::capacity::CapacityConfig`] the [`T3_CAPACITY_PAYLOAD`] JSON names —
/// `record_capacity_config` takes a typed config, not a raw payload, so
/// every T3-era fixture site now goes through this constant instead of a raw ledger
/// insert (a raw `kind='mode_change'` act is invisible to `effective_bounds`, which
/// reads only `kind='capacity'`/`'capacity_activated'` acts).
fn t3_capacity_config() -> crate::capacity::CapacityConfig {
    crate::capacity::CapacityConfig {
        max_active_ops: 64,
        undo_reserve: 32,
        writer_chunk_budget_ms: 50,
        sever_watchdog_ms: 5000,
        sever_joiner_cap: 16,
    }
}

#[test]
fn w_adjudication_at_cap() {
    // Adjudication is a CONTROL transition, not a
    // new operation — no admission door gates `adjudicate`'s own transaction. This fills
    // the 64/32 fixture to TOTAL cap, with ONE of the 32 forward slots driven to
    // ISSUANCE_UNKNOWN through the real doors, then adjudicates it AT CAP: it must
    // succeed with zero headroom, occupancy must drop by exactly one, and the freed slot
    // must let the NEXT forward admission through.
    let path = unique_temp_db_path("t3-adjudication-at-cap");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // Empty pool ⇒ the config transaction's own no-traffic fit-check activates this
    // immediately — the same "one act, immediately current" shape as before.
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config"); // generation 2
    // One forward slot is an ISSUANCE_UNKNOWN attempt, driven through admit/claim/
    // authorize/settle(indeterminate) — the REAL doors §5.2d adjudicates.
    let unknown = archive_of("k-fwd-unknown", "msg-unknown");
    let attempt = unknown_attempt(&mut log, &unknown);
    // The other 31 forward slots (reserve bound = max_active_ops(64) - undo_reserve(32)
    // = 32, and the unknown above already claims one) are plain Pending forwards.
    for i in 0..31 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    // The remaining 32 slots are undo occupancy, filling the TOTAL cap to exactly 64.
    for i in 0..32 {
        let mut cmd = archive_cmd(&format!("k-undo-{i}"));
        cmd.compensates = Some(format!("origin-{i}"));
        assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    }
    assert_eq!(non_terminal_count(&path), 64, "the pool is at TOTAL cap");
    // AT CAP, zero headroom: adjudicate the unknown attempt. It must succeed — no
    // capacity check runs on this transaction.
    adjudicate_now(&mut log, "k-fwd-unknown", &attempt);
    assert_eq!(status_str(&path, "k-fwd-unknown"), "adjudicated");
    assert_eq!(
        non_terminal_count(&path),
        63,
        "adjudication is a net -1: one fewer non-terminal row"
    );
    // The freed slot lets the NEXT forward admission through.
    assert_eq!(
        record_basis(&mut log, &archive_cmd("k-fwd-after-adjudication")).unwrap(),
        Claim::Inserted,
        "the drained slot admits a fresh forward claim"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn w_unknown_exhaustion_at_cap() {
    // An ISSUANCE_UNKNOWN operation is NOT terminal
    // — it holds its slot exactly like any other in-flight op (W-UNKNOWN-SAME-RESOURCE's
    // same premise, applied to capacity). A pool whose ENTIRE forward reserve is
    // ISSUANCE_UNKNOWN, topped off by undo occupancy to the TOTAL cap, refuses EVERY
    // further admission of EITHER polarity — and ONE in-place adjudication is the only
    // door that drains a slot back open.
    let path = unique_temp_db_path("t3-unknown-exhaustion");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config"); // generation 2
    // Fill the entire forward reserve (32) with ISSUANCE_UNKNOWN attempts.
    let mut unknowns = Vec::new();
    for i in 0..32 {
        let key = format!("k-fwd-unknown-{i}");
        let unknown = archive_of(&key, &format!("msg-{i}"));
        let attempt = unknown_attempt(&mut log, &unknown);
        unknowns.push((key, attempt));
    }
    // Fill the rest of the TOTAL cap (32 more) with plain undo occupancy.
    for i in 0..32 {
        let mut cmd = archive_cmd(&format!("k-undo-{i}"));
        cmd.compensates = Some(format!("origin-{i}"));
        assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    }
    assert_eq!(
        non_terminal_count(&path),
        64,
        "the pool is at TOTAL cap, entirely unknowns + undo remedies"
    );
    // EVERY further admission refuses — both polarities.
    let forward_refusal = record_basis(&mut log, &archive_cmd("k-fwd-overflow")).unwrap();
    assert!(
        matches!(forward_refusal, Claim::CapacityRefused(ref msg) if msg.contains("forward")),
        "expected a forward-reserve refusal, got {forward_refusal:?}"
    );
    let mut undo_overflow = archive_cmd("k-undo-overflow");
    undo_overflow.compensates = Some("origin-overflow".into());
    let undo_refusal = record_basis(&mut log, &undo_overflow).unwrap();
    assert!(
        matches!(undo_refusal, Claim::CapacityRefused(_)),
        "expected a total-cap refusal, got {undo_refusal:?}"
    );
    // ONE in-place adjudication drains exactly one slot.
    let (key, attempt) = &unknowns[0];
    adjudicate_now(&mut log, key, attempt);
    assert_eq!(non_terminal_count(&path), 63);
    // Admission recovers: the UNDO admission that just refused now admits (complementary
    // to `w_adjudication_at_cap`'s forward-recovery check — recovery is not
    // polarity-specific).
    let mut undo_recovered = archive_cmd("k-undo-recovered");
    undo_recovered.compensates = Some("origin-recovered".into());
    assert_eq!(
        record_basis(&mut log, &undo_recovered).unwrap(),
        Claim::Inserted,
        "the drained slot admits the previously-refused remedy"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn undo_backpressure_is_explicit_when_remedies_fill_the_pool() {
    // When remedies fill the
    // pool to the TOTAL cap, the undo refusal must not leave the caller to guess at the
    // one door that is always admissible to drain it — the message NAMES in-place
    // adjudication. This fills the reserve with ONE ISSUANCE_UNKNOWN forward + 31 plain
    // forwards, tops the pool off with 32 undo remedies to the TOTAL cap, checks the
    // refusal's own words, then adjudicates the unknown to prove the message's claim is
    // literally true: the SAME remedy that just refused now admits.
    let path = unique_temp_db_path("t3-undo-backpressure");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config"); // generation 2
    let unknown = archive_of("k-fwd-unknown", "msg-unknown");
    let attempt = unknown_attempt(&mut log, &unknown);
    for i in 0..31 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    for i in 0..32 {
        let mut cmd = archive_cmd(&format!("k-undo-{i}"));
        cmd.compensates = Some(format!("origin-{i}"));
        assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    }
    assert_eq!(non_terminal_count(&path), 64, "remedies fill the pool to the TOTAL cap");
    // The pool is FULL: a further undo (remedy) refuses on the TOTAL cap — and the
    // message must NAME adjudication as the drain.
    let mut undo_overflow = archive_cmd("k-undo-overflow");
    undo_overflow.compensates = Some("origin-overflow".into());
    let undo_refusal = record_basis(&mut log, &undo_overflow).unwrap();
    let undo_msg = match undo_refusal {
        Claim::CapacityRefused(msg) => msg,
        other => panic!("expected an undo CapacityRefused, got {other:?}"),
    };
    assert!(
        undo_msg.contains("in-place adjudication is always admissible to drain"),
        "the refusal must name adjudication as the drain (design §5.3's honest-\
         backpressure sentence), got: {undo_msg}"
    );
    // Prove the message's claim is literally true: adjudicating the unknown drains a
    // slot, and the SAME kind of remedy that just refused now admits.
    adjudicate_now(&mut log, "k-fwd-unknown", &attempt);
    assert_eq!(non_terminal_count(&path), 63);
    let mut undo_retry = archive_cmd("k-undo-retry");
    undo_retry.compensates = Some("origin-retry".into());
    assert_eq!(
        record_basis(&mut log, &undo_retry).unwrap(),
        Claim::Inserted,
        "the drain the message promised actually admits the remedy"
    );
    std::fs::remove_file(&path).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// The settle_status chokepoint + pending capacity reductions (design
// §5.3 CONFIGURATION-DOMAIN-PINNING: ONE activation
// authority — the SQL trigger — per event; admission and activation are DIFFERENT
// questions, never compared to each other).
// ═══════════════════════════════════════════════════════════════════════════════════

/// A raw `kind='capacity'` act's JSON payload for `cfg` — the SAME shape
/// `record_capacity_config` writes, for witnesses that plant a PENDING act directly
/// (bypassing the API's own no-traffic activation) to isolate the SQL trigger.
fn capacity_payload_json(cfg: &crate::capacity::CapacityConfig) -> String {
    format!(
        "{{\"capture\":\"on\",\"capacity\":{{\"max_active_ops\":{},\"undo_reserve\":{},\
         \"writer_chunk_budget_ms\":{},\"sever_watchdog_ms\":{},\"sever_joiner_cap\":{}}}}}",
        cfg.max_active_ops,
        cfg.undo_reserve,
        cfg.writer_chunk_budget_ms,
        cfg.sever_watchdog_ms,
        cfg.sever_joiner_cap,
    )
}

#[test]
fn any_status_write_fires_activation() {
    // THE POSITIVE CONTROL (prior art, `statu5` control, sqlite.org
    // lang_createtrigger §2): `UPDATE OF` column names are NOT validated — a typo
    // trigger is silently accepted and never fires. This drives a deliberately
    // alternate-spelled raw UPDATE (reordered whitespace, newline-split — never the
    // engine's own call shape) and asserts the trigger's NAME and its `status` column
    // actually bound to something.
    let path = unique_temp_db_path("t4-positive-control");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t4-positive-control")).unwrap();
    // A pending, TRIVIALLY-FITTING reduction, planted RAW — bypassing
    // `record_capacity_config`'s own no-traffic fit-check so this witness observes the
    // SQL trigger, and only the SQL trigger.
    let pending_gen = append_capacity_act(&path, T3_CAPACITY_PAYLOAD);
    assert_eq!(latest_activated_generation(&path), None, "pending, not yet activated");
    raw_conn(&path)
        .execute(
            "UPDATE\n  intents\nSET\n  status = 'applied'\n WHERE idempotency_key = \
             'k-t4-positive-control';",
            [],
        )
        .expect("the deliberately alternate-spelled raw status UPDATE");
    assert_eq!(
        latest_activated_generation(&path),
        Some(pending_gen),
        "a raw, alternate-spelled UPDATE OF status must still fire \
         `intents_status_activation` — the trigger rides the COLUMN, not a call site"
    );
    std::fs::remove_file(&path).ok();
}

/// Drive ONE `(occupancy, bounds)` pair through the TRIGGER's own SQL
/// fit predicate on a scratch store: seed occupancy, plant `cfg` as a PENDING (raw)
/// capacity act, fire a status write that does NOT itself change the non-terminal count
/// (a terminal→terminal flip, `Applied -> Undone`, via `set_status_if`'s `Exactly`
/// precondition — "any status write" includes these too), and report whether activation
/// landed. The counterpart to `capacity::activation_fits` in
/// `both_authorities_agree_at_the_edges`.
fn trigger_observes_fit(
    active_forward: u32,
    active_undo: u32,
    cfg: crate::capacity::CapacityConfig,
) -> bool {
    let path = unique_temp_db_path("t4-edge");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    for i in 0..active_forward {
        record_basis(&mut log, &archive_of(&format!("k-fwd-{i}"), &format!("m-fwd-{i}")))
            .unwrap();
    }
    for i in 0..active_undo {
        let mut cmd = archive_of(&format!("k-undo-{i}"), &format!("m-undo-{i}"));
        cmd.compensates = Some(format!("origin-{i}"));
        record_basis(&mut log, &cmd).unwrap();
    }
    record_basis(&mut log, &archive_of("k-observer", "m-observer")).unwrap();
    assert_eq!(
        log.set_status_if(
            "k-observer",
            StatusPrecondition::NonTerminal,
            IntentStatus::Applied,
        )
        .unwrap(),
        StatusWrite::Written
    );
    append_capacity_act(&path, &capacity_payload_json(&cfg));
    assert_eq!(
        log.set_status_if(
            "k-observer",
            StatusPrecondition::Exactly(IntentStatus::Applied),
            IntentStatus::Undone,
        )
        .unwrap(),
        StatusWrite::Written
    );
    let activated = latest_activated_generation(&path).is_some();
    std::fs::remove_file(&path).ok();
    activated
}

/// A `kind='capacity'` payload that is NOT parseable JSON: truncated mid-object, so
/// `json_valid` is false and a bare `json_extract` over it RAISES.
const MALFORMED_CAPACITY_PAYLOAD: &str = "{\"capture\":\"on\",\"capacity\":";

/// **A MALFORMED CAPACITY ACT MUST NOT WEDGE THE STATUS COLUMN.**
///
/// `intents_status_activation`'s `WHEN` clause reads `engine_config.payload` with
/// `json_extract`, and a bare `json_extract` over malformed JSON does not return NULL — it
/// RAISES ("malformed JSON"), from inside the trigger, aborting the statement that fired it.
/// The trigger rides the COLUMN, so pre-fix that made EVERY `intents.status` write in the
/// store fail for as long as the act sat in the ledger: adjudication, sever drainage,
/// terminalization — the store wedges on one unreadable config row.
///
/// **How such a row gets there, and why the guard is fail-SAFE and not fail-SILENT.**
/// `record_capacity_config` parses through `CapacityConfig::from_engine_payload`, which
/// REFUSES unreadable JSON (`CapacityConfigError::Unreadable`,
/// `crates/aruna/src/capacity.rs:231-232`), so the API door never writes one — raw SQL or
/// file corruption is the only way in. Once in, the honest semantics are:
///
/// - it can never ACTIVATE (it never "fits": a bound nobody can read is not a bound met),
///   and the guarded `WHEN` clause is simply FALSE — the act is INERT, not applied;
/// - and it is never silently treated as absent on the READ side either: `record`'s own
///   admission read (`read_effective_bounds` → `capacity::effective_bounds` →
///   `from_engine_payload`) REFUSES, so the malformed act is loud exactly where a wrong
///   capacity answer would matter. Asserted below, in this same witness, so the two halves
///   can never drift apart.
#[test]
fn codex_r4_f1_a_malformed_capacity_act_is_inert_not_a_wedge() {
    let path = unique_temp_db_path("t4-malformed-capacity-act");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-malformed-wedge")).unwrap();

    // RAW, because that is the only door it fits through (see the doc above).
    let malformed_gen = append_capacity_act(&path, MALFORMED_CAPACITY_PAYLOAD);

    // 1. THE STATUS COLUMN STILL WORKS. Pre-fix this is `Err(... malformed JSON ...)`.
    let write = log.set_status_if(
        "k-malformed-wedge",
        StatusPrecondition::NonTerminal,
        IntentStatus::Applied,
    );
    assert_eq!(
        write.map_err(|e| e.0),
        Ok(StatusWrite::Written),
        "a malformed capacity act must not abort an unrelated intents.status write — the \
         activation trigger's JSON reads are guarded by `json_valid`, so an unreadable act \
         makes the WHEN clause FALSE instead of raising"
    );

    // 2. AND IT IS INERT: an act whose bounds nobody can read never activates.
    assert_eq!(
        latest_activated_generation(&path),
        None,
        "generation {malformed_gen} is unreadable — it must never be recorded as activated"
    );

    // 3. FAIL-SAFE, NOT FAIL-SILENT: the READ side refuses the same act rather than
    //    defaulting past it. THE CAPACITY DERIVATION ITSELF, first and by name — this is
    //    the read the trigger's inertness is paired with, and `from_engine_payload`'s
    //    `Unreadable` is what makes "cannot activate" mean "nobody reads it as bounds"
    //    rather than "nobody notices it".
    let derived = crate::capacity::effective_bounds(
        &[(malformed_gen, MALFORMED_CAPACITY_PAYLOAD.to_string())],
        // As if an activation row at the next generation named the malformed act — the
        // honest ordering, so the refusal exercised is the PAYLOAD's, not a shape's.
        Some((malformed_gen + 1, malformed_gen)),
    );
    assert!(
        matches!(derived, Err(crate::capacity::CapacityConfigError::Unreadable { .. })),
        "the capacity read side must REFUSE an unreadable act, never default past it; \
         got: {derived:?}"
    );

    // 4. …and ADMISSION therefore refuses too, naming the unreadable act. The `engine_config`
    //    ledger is read by TWO admission gates and the malformed row is loud at whichever
    //    reaches it first — here the capture-mode gate (`capture_mode_is_on`, which parses
    //    the same act's payload and is checked ahead of the capacity read). Asserted on the
    //    act it names rather than on which gate names it: the property is "no write is
    //    admitted past an unreadable config act", not the order of two refusals.
    let admission = record_basis(&mut log, &archive_cmd("k-after-malformed"));
    let reason = admission.expect_err("admission must refuse over an unreadable config act").0;
    assert!(
        reason.contains(&format!("config act generation {malformed_gen}"))
            && reason.contains("is not a readable config act"),
        "admission must REFUSE over the malformed act, naming it, never default past it; \
         got: {reason}"
    );
    std::fs::remove_file(&path).ok();
}

/// A `kind='capacity'` payload whose `max_active_ops` is `i64::MAX` — syntactically VALID
/// JSON (`json_valid` is true), but a NUMBER `record_capacity_config`'s own `validate()`
/// would never accept (`crates/aruna/src/capacity.rs:175-206`: the domain is `64..=8192`
/// for `max_active_ops`, `1..max_active_ops` for `undo_reserve`). RAW, because that is the
/// only door it fits through — see `an_out_of_domain_capacity_act_is_inert_not_an_overflow_abort`'s own doc for why no Rust writer can
/// emit this act.
const OUT_OF_DOMAIN_CAPACITY_PAYLOAD: &str =
    "{\"capture\":\"on\",\"capacity\":{\"max_active_ops\":9223372036854775807,\
     \"undo_reserve\":64,\"writer_chunk_budget_ms\":50,\"sever_watchdog_ms\":5000,\
     \"sever_joiner_cap\":16}}";

/// **AN OUT-OF-DOMAIN CAPACITY ACT MUST NOT OVERFLOW THE
/// ACTIVATION PROBE'S `LIMIT`.**
///
/// `intents_status_activation`'s `WHEN` clause (`store_open::activation_fit_predicate_sql`)
/// and its probe stop (then a per-firing SQL derivation of the newest act's bound) both
/// used to read `$.capacity.max_active_ops` guarded only by `json_valid` — proof the
/// payload PARSES, not that the number it parsed to is representable where the trigger
/// needs it. A syntactically-valid `max_active_ops: 9223372036854775807` made the
/// derivation's `... + 1` overflow SQLite's 64-bit integer arithmetic; SQLite's own
/// overflow rule widens the result to REAL rather than raising, and `LIMIT` demands an
/// INTEGER — so the widened REAL raised "datatype mismatch" from inside the
/// trigger's `WHEN` clause, aborting the `intents.status` UPDATE that fired it. Pre-fix that
/// made EVERY status write in the store fail for as long as the act sat in the ledger — the
/// SAME wedge shape `codex_r4_f1_a_malformed_capacity_act_is_inert_not_a_wedge` closes,
/// narrower: this time the JSON is perfectly readable, only the NUMBER is out of domain.
/// *(later made the probe stop a compile-time CONSTANT —
/// `store_open::activation_probe_limit`, the domain ceiling + 1 — which closes THIS
/// overflow class by construction: there is no per-act arithmetic left to overflow. The
/// witness below stands unchanged as the behavioral fence: an out-of-domain act stays
/// inert and no status write is ever aborted, whatever machinery sits behind the stop.)*
///
/// **How such a row gets there, verified at the byte, not merely claimed.** `RawCapacity`'s
/// `max_active_ops` field is `u32` (`crates/aruna/src/capacity.rs:240`), and
/// `9223372036854775807` overflows `u32`, so `serde` refuses the DESERIALIZE before
/// `CapacityConfig::validate` (`capacity.rs:175-206`) ever runs. `record_capacity_config`
/// parses every act through `CapacityConfig::from_engine_payload`
/// (`capacity.rs:237`/`capacity.rs:292`), so the API door never writes one — raw SQL or
/// file corruption is the only way in, asserted as step 0 below, on the SAME bytes the SQL
/// side is about to be driven with (never a copy that could drift from what the trigger
/// actually sees).
///
/// **The fix (`store_open::capacity_domain_guard_sql`) makes out-of-domain INERT, the same
/// semantics as unreadable**, not merely non-crashing: `activation_fit_predicate_sql`'s
/// guard makes both its comparisons NULL, so the `WHEN` clause is FALSE and the act
/// never activates either — asserted as step 2 below. (The older probe-stop derivation
/// carried its own copy of the guard; the constant stop needs none.)
#[test]
fn an_out_of_domain_capacity_act_is_inert_not_an_overflow_abort() {
    // 0. THE RUST READ SIDE ALREADY REFUSES THIS EXACT PAYLOAD, checked before the trigger
    //    is exercised at all.
    let read =
        crate::capacity::CapacityConfig::from_engine_payload(OUT_OF_DOMAIN_CAPACITY_PAYLOAD);
    assert!(
        matches!(read, Err(crate::capacity::CapacityConfigError::Unreadable { .. })),
        "the Rust read side must refuse an out-of-domain max_active_ops before it ever \
         reaches validate() — u32 deserialization itself must refuse i64::MAX; got: {read:?}"
    );

    let path = unique_temp_db_path("t6-out-of-domain-capacity-act");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-out-of-domain")).unwrap();

    // RAW, because that is the only door it fits through (see the payload's own doc, and
    // step 0 above, on these SAME bytes).
    let out_of_domain_gen = append_capacity_act(&path, OUT_OF_DOMAIN_CAPACITY_PAYLOAD);

    // 1. THE STATUS COLUMN STILL WORKS. Pre-fix this is `Err(... datatype mismatch ...)`.
    let write = log.set_status_if(
        "k-out-of-domain",
        StatusPrecondition::NonTerminal,
        IntentStatus::Applied,
    );
    assert_eq!(
        write.map_err(|e| e.0),
        Ok(StatusWrite::Written),
        "an out-of-domain capacity act must not abort an unrelated intents.status write — \
         the activation trigger's probe LIMIT is domain-guarded, so an out-of-domain \
         max_active_ops makes the WHEN clause FALSE instead of overflowing the LIMIT"
    );

    // 2. AND IT IS INERT: an act whose bounds are out of domain never activates.
    assert_eq!(
        latest_activated_generation(&path),
        None,
        "generation {out_of_domain_gen} is out of domain — it must never be recorded as \
         activated"
    );

    // 3. THE CLAMP DID NOT DEADEN THE TRIGGER: a subsequent VALID pending act still
    //    activates normally. `k-out-of-domain` is the only intent in this store, so its
    //    own occupancy trivially fits the 64/32 fixture.
    let valid_gen = append_capacity_act(&path, &capacity_payload_json(&t3_capacity_config()));
    assert_eq!(
        log.set_status_if(
            "k-out-of-domain",
            StatusPrecondition::Exactly(IntentStatus::Applied),
            IntentStatus::Undone,
        )
        .unwrap(),
        StatusWrite::Written
    );
    assert_eq!(
        latest_activated_generation(&path),
        Some(valid_gen),
        "a VALID pending act appended after the out-of-domain one must still activate \
         normally — the domain guard must gate the ONE out-of-domain act, not the trigger \
         itself"
    );
    std::fs::remove_file(&path).ok();
}

/// **A WRONG-TYPED ACTIVATION POINTER MUST NOT LET A FRESH
/// ACTIVATION ROW HIDE THE CORRUPT ONE.**
///
/// `intents_status_activation`'s activation-pointer read (`store_open::schema_ddl`) was
/// guarded by `json_valid(a.payload)` alone — proof the payload PARSES, not that
/// `$.activates_generation` is the INTEGER the CAST assumes. `CAST('garbage' AS INTEGER)`
/// does not raise and does not return NULL; SQLite coerces a non-numeric-prefixed string to
/// `0`. Pre-fix that `0` flowed straight through the `COALESCE(..., c.generation)` inside
/// the correlated subquery — landing on `0`, not the intended `c.generation` fallback —
/// so the OUTER comparison became `c.generation > 0`, true for every real generation
/// (`engine_config.generation` is `CHECK (generation >= 1)`). The trigger then fired and
/// appended a FRESH, well-typed `capacity_activated` row activating the pending act — and
/// because every Rust reader (`capacity::parse_activation_pointer` via
/// `read_effective_bounds`/`capacity_config_at_open`) reads only the NEWEST
/// `capacity_activated` row, that fresh row buried the corrupt one where no reader would
/// ever see it again.
///
/// **THE FIX, BOTH DIRECTIONS.** Gating the CAST behind
/// `json_type(a.payload, '$.activates_generation') = 'integer' AND CAST(...) >= 1` makes a
/// wrong-typed (or sub-1, colliding with the ledger's own NEVER-ACTIVATED sentinel) pointer
/// fall to the SAME `CASE`-with-no-`ELSE` `NULL` an unreadable payload already produced, so
/// `COALESCE(NULL, c.generation)` resolves to `c.generation` — the intended fallback — and
/// `c.generation > c.generation` is FALSE:
/// - a PENDING act is never wrongly read as "already activated" (the comparison is false,
///   not true, so `record`'s admission read and every other consumer keep seeing it as
///   pending, exactly as an unreadable pointer already left it — never silently applied);
/// - AND no NEW activation row may append while the corrupt row is the newest — the `WHEN`
///   clause is false, so the `INSERT` never runs, so the corrupt row STAYS the newest
///   `capacity_activated` row, visible to every Rust reader, which refuses it BY NAME. The
///   trigger goes genuinely INERT rather than papering over the corruption with a fresh,
///   readable row.
#[test]
fn a_wrong_typed_activation_pointer_must_not_hide_behind_a_fresh_activation_row() {
    let path = unique_temp_db_path("t7-f2-wrong-typed-activation-pointer");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t7-f2-wrong-typed")).unwrap();

    // An older, valid, PENDING capacity act — not yet activated. Trivially fits (this is
    // the only intent in the store), so the trigger's own occupancy conjuncts are not what
    // is under test here.
    let pending_gen = append_capacity_act(&path, T3_CAPACITY_PAYLOAD);
    assert_eq!(latest_activated_generation(&path), None, "pending, not yet activated");

    // THE FAULT: the NEWEST `capacity_activated` row is present, WELL-FORMED JSON
    // (`json_valid` is true), but its `activates_generation` member is a STRING — plantable
    // only by raw SQL or corruption, never by the API's own `json_object('activates_
    // generation', <integer>)` writer.
    append_activation_act(&path, r#"{"activates_generation":"garbage"}"#);

    let count_activation_rows = || -> i64 {
        raw_conn(&path)
            .query_row(
                "SELECT COUNT(*) FROM engine_config WHERE kind = 'capacity_activated';",
                [],
                |r| r.get(0),
            )
            .expect("count activation rows")
    };
    assert_eq!(
        count_activation_rows(),
        1,
        "the fault's own precondition: exactly one (corrupt) activation row exists"
    );

    // Drive the status write that fires the trigger. Pre-fix this appends a SECOND
    // (well-typed) activation row; post-fix it must not.
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'applied' \
             WHERE idempotency_key = 'k-t7-f2-wrong-typed';",
            [],
        )
        .expect("the status write itself must not be aborted by the wrong-typed pointer");

    // THE WITNESS: still exactly one activation row — the trigger stayed inert rather than
    // burying the corrupt row under a fresh, valid-looking one.
    assert_eq!(
        count_activation_rows(),
        1,
        "a wrong-typed activation pointer must leave the trigger INERT — no fresh \
         activation row may append while the corrupt row is the newest, or it hides the \
         corruption from every Rust reader (which only ever reads the newest row)"
    );

    // …and the corrupt row is STILL the newest one, and the strict parse authority still
    // REFUSES it by name — never silently superseded, never silently read as absent.
    let newest_payload = raw_conn(&path)
        .query_row(
            "SELECT payload FROM engine_config WHERE kind = 'capacity_activated' \
              ORDER BY generation DESC LIMIT 1;",
            [],
            |r| r.get::<_, String>(0),
        )
        .expect("read the newest activation payload");
    assert_eq!(
        newest_payload,
        r#"{"activates_generation":"garbage"}"#,
        "the corrupt row must still be the newest — nothing may have been appended over it"
    );
    assert!(
        crate::capacity::parse_activation_pointer(&newest_payload).is_err(),
        "the strict parse authority must still refuse the newest activation row"
    );

    assert!(pending_gen > 0);
    std::fs::remove_file(&path).ok();
}

/// **A NUMERIC-PREFIXED `capacity.*` FIELD MUST NOT
/// BYPASS THE DOMAIN GUARD.**
///
/// The sweep of every `CAST` in the trigger SQL turned up a second instance of the
/// SAME class the activation-pointer fix above closes, one door over:
/// `store_open::capacity_domain_guard_sql`'s own doc claimed "only a missing/wrong-typed/
/// out-of-range NUMBER can make a `BETWEEN` here false" — true for a NON-numeric string
/// (`CAST('garbage' AS INTEGER)` is `0`, always out of `[64, 8192]`), but SQLite's `CAST`
/// to `INTEGER` takes the LEADING numeric prefix of a string rather than refusing it:
/// `CAST('100abc' AS INTEGER)` is `100`, not `0` — a wrong-typed `max_active_ops` can
/// coerce to a value that lands INSIDE the domain and the `BETWEEN` reads it as
/// legitimately in-domain. `an_out_of_domain_capacity_act_is_inert_not_an_overflow_abort`'s own invariant ("out-of-domain is INERT
/// end-to-end") is exactly what this defeats: a malformed act the Rust side
/// (`CapacityConfig::from_engine_payload`, whose `RawCapacity::max_active_ops` is `u32`
/// and refuses a JSON string outright) would REFUSE can still pass the SQL guard, fire the
/// trigger, and activate — landing an unreadable act as `current` and wedging every future
/// admission exactly the way `codex_r4_f1_a_malformed_capacity_act_is_inert_not_a_wedge`/`an_out_of_domain_capacity_act_is_inert_not_an_overflow_abort` already closed for the other two
/// corruption shapes.
#[test]
fn codex_r7_f2_sweep_a_numeric_prefixed_capacity_field_must_not_bypass_the_domain_guard() {
    const NUMERIC_PREFIX_PAYLOAD: &str = r#"{"capture":"on","capacity":{"max_active_ops":"100abc","undo_reserve":16,"writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#;

    // 0. THE RUST READ SIDE ALREADY REFUSES THIS EXACT PAYLOAD — `max_active_ops` is `u32`
    //    in `RawCapacity`, and serde refuses a JSON STRING there outright, coercion or not.
    let read = crate::capacity::CapacityConfig::from_engine_payload(NUMERIC_PREFIX_PAYLOAD);
    assert!(
        matches!(read, Err(crate::capacity::CapacityConfigError::Unreadable { .. })),
        "the Rust read side must refuse a string `max_active_ops`, numeric-prefixed or not; \
         got: {read:?}"
    );

    let path = unique_temp_db_path("t7-f2-sweep-numeric-prefix");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t7-f2-sweep-numeric-prefix")).unwrap();

    // RAW, because that is the only door it fits through — the API's own writer parses
    // through the same strict authority step 0 already exercised.
    let malformed_gen = append_capacity_act(&path, NUMERIC_PREFIX_PAYLOAD);

    // 1. THE STATUS COLUMN STILL WORKS — same fail-safe-not-a-wedge property as /.
    let write = log.set_status_if(
        "k-t7-f2-sweep-numeric-prefix",
        StatusPrecondition::NonTerminal,
        IntentStatus::Applied,
    );
    assert_eq!(
        write.map_err(|e| e.0),
        Ok(StatusWrite::Written),
        "a numeric-prefixed wrong-typed capacity act must not abort an unrelated \
         intents.status write"
    );

    // 2. THE WITNESS: a numeric-prefixed wrong-typed act must never activate. Pre-fix, the
    //    domain guard's own `BETWEEN` reads the coerced `100` as in-domain and this
    //    generation activates.
    assert_eq!(
        latest_activated_generation(&path),
        None,
        "generation {malformed_gen} is wrong-typed (a numeric-prefixed STRING, not a JSON \
         number) — it must never be recorded as activated, exactly like every other \
         malformed-act shape"
    );
    std::fs::remove_file(&path).ok();
}

/// **AN OUT-OF-ORDER RAW ACTIVATION ROW PREFILTERS THE TRIGGER
/// INERT (the named fail-closed edge of the json-free prefilter).**
///
/// The 250ms-gate fix put a json-free prefilter in front of the trigger's json
/// machinery: "newest `capacity` act generation > newest `capacity_activated` ROW
/// generation". Under first-party append discipline the prefilter and the pointer
/// question agree (see the trigger's own comment in `store_open::schema_ddl` for the
/// argument); the ONE divergent shape is a raw activation row whose generation was
/// planted AHEAD of the act counter — no first-party writer produces it (both activation
/// writers append at global MAX(generation)+1 and activate the newest act), raw SQL or
/// corruption only. The earlier clause read only that row's POINTER (older than the
/// pending act) and ACTIVATED behind it; the prefilter reads the ROW as newest and stays
/// INERT — fail-closed, the same direction `a_wrong_typed_activation_pointer_must_not_hide_behind_a_fresh_activation_row`'s corrupt-pointer semantics
/// already committed to (nothing appends behind a suspect newest row; the row stays
/// visible; the Rust read side keeps its own verdict). RED against the earlier trigger
/// (a fresh activation row appends here), GREEN after.
#[test]
fn codex_r8_f1_an_out_of_order_activation_row_prefilters_inert() {
    let path = unique_temp_db_path("t8-f1-out-of-order-activation");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t8-f1-out-of-order")).unwrap();

    // A valid PENDING capacity act (fits trivially — one intent in the store)…
    let pending_gen = append_capacity_act(&path, T3_CAPACITY_PAYLOAD);
    // …and the fault: a well-formed activation row planted OUT OF ORDER — generation far
    // ahead of the act counter, pointer naming a generation OLDER than the pending act.
    raw_conn(&path)
        .execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES (?1, strftime('%s','now'), 'capacity_activated',
                         json_object('activates_generation', 1));",
            rusqlite::params![pending_gen + 1000],
        )
        .expect("plant the out-of-order activation row");

    let count_activation_rows = || -> i64 {
        raw_conn(&path)
            .query_row(
                "SELECT COUNT(*) FROM engine_config WHERE kind = 'capacity_activated';",
                [],
                |r| r.get(0),
            )
            .expect("count activation rows")
    };
    assert_eq!(count_activation_rows(), 1, "precondition: exactly the planted row");

    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'applied' \
             WHERE idempotency_key = 'k-t8-f1-out-of-order';",
            [],
        )
        .expect("the status write itself must not be aborted by the planted row");

    assert_eq!(
        count_activation_rows(),
        1,
        "an out-of-order activation row must leave the trigger INERT — the prefilter \
         reads the ROW as newest and refuses to activate behind it (the pre-r8 clause \
         read only its pointer and appended a fresh activation row here)"
    );
    assert!(pending_gen > 0);
    std::fs::remove_file(&path).ok();
}

/// **THE SQL DOMAIN GUARD MIRRORS ALL
/// FIVE `validate()` FIELDS, NOT TWO.**
///
/// the guard mirrored `max_active_ops` and `undo_reserve` only, so a payload
/// in-domain on those two but carrying a zero in any of the OTHER three fields
/// `validate()` refuses (`writer_chunk_budget_ms` / `sever_watchdog_ms` /
/// `sever_joiner_cap`) — or a value above `u32::MAX`, which the serde parse refuses
/// before `validate()` ever runs — passed the SQL guard and ACTIVATED off an unrelated
/// status write while every Rust reader refused it by name: the same one-door-over defeat
/// of "out-of-domain is INERT end-to-end" the sweep closed for numeric-prefixed
/// strings. Each payload below is refused by the Rust authority (asserted as the
/// positive control) and must now be equally inert at the trigger. RED against the
/// two-field guard (the zero-joiner-cap arm activates), GREEN after.
#[test]
fn a_rust_refused_capacity_act_must_not_activate_through_the_sql_guard() {
    const CASES: &[(&str, &str)] = &[
        (
            "sever_joiner_cap zero",
            r#"{"capture":"on","capacity":{"max_active_ops":64,"undo_reserve":32,"writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":0}}"#,
        ),
        (
            "writer_chunk_budget_ms zero",
            r#"{"capture":"on","capacity":{"max_active_ops":64,"undo_reserve":32,"writer_chunk_budget_ms":0,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#,
        ),
        (
            "sever_watchdog_ms zero",
            r#"{"capture":"on","capacity":{"max_active_ops":64,"undo_reserve":32,"writer_chunk_budget_ms":50,"sever_watchdog_ms":0,"sever_joiner_cap":16}}"#,
        ),
        (
            "writer_chunk_budget_ms above u32::MAX (the serde parse's own refusal bound)",
            r#"{"capture":"on","capacity":{"max_active_ops":64,"undo_reserve":32,"writer_chunk_budget_ms":4294967296,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#,
        ),
    ];
    for (label, payload) in CASES {
        // Positive control: the Rust authority refuses this exact payload.
        let read = crate::capacity::CapacityConfig::from_engine_payload(payload);
        assert!(
            read.is_err(),
            "{label}: the Rust read side must refuse this payload; got {read:?}"
        );

        let path = unique_temp_db_path("t8-f4-domain-guard");
        let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
        record_basis(&mut log, &archive_cmd("k-t8-f4-domain")).unwrap();
        append_capacity_act(&path, payload);

        raw_conn(&path)
            .execute(
                "UPDATE intents SET status = 'applied' \
                 WHERE idempotency_key = 'k-t8-f4-domain';",
                [],
            )
            .expect("the status write itself must not be aborted by the out-of-domain act");

        let activation_rows: i64 = raw_conn(&path)
            .query_row(
                "SELECT COUNT(*) FROM engine_config WHERE kind = 'capacity_activated';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            activation_rows, 0,
            "{label}: an act the Rust domain refuses must be INERT at the trigger too — \
             out-of-domain is inert END-TO-END, all five fields"
        );
        drop(log);
        std::fs::remove_file(&path).ok();
    }
}

/// **THE ADMISSION READ FETCHES TWO ROWS, AND A SUPERSEDED ACT IS
/// NEITHER FETCHED NOR PARSED (the equivalence pin for the bounded ledger read).**
///
/// `read_effective_bounds` used to materialize EVERY `kind='capacity'` act inside the
/// enrolled admission transaction — unbounded work a pending sever waits behind, on a
/// derivation whose own contract parses at most the activated act and the newest pending
/// one. The bounded fetch must be OBSERVABLY equivalent, and the sharpest observable is
/// the malformed-superseded shape: an unreadable act BETWEEN two activations was never
/// parsed before (only fetched and dropped) and must still refuse nothing now — while the
/// same unreadable act as the NEWEST (pending) act refuses by name, before and after.
/// Not a RED witness (both forms pass it; the fold's harm was the unbounded fetch, whose
/// bound is visible in the SQL — a PK lookup + a `LIMIT 1`); this pins the semantics the
/// perf rework claims to preserve.
#[test]
fn a_superseded_malformed_act_stays_unparsed_by_the_admission_read() {
    let path = unique_temp_db_path("t8-f3-superseded-unparsed");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // Activate a first config through the API door (no traffic — activates immediately).
    log.record_capacity_config(t3_capacity_config()).expect("first config");
    // Plant a MALFORMED capacity act raw…
    append_capacity_act(&path, "{ this is not json");
    // …give the capture carry-forward a readable act to stand on (`record_capacity_config`
    // reads the newest NON-activation act for the capture mode, and the malformed plant is
    // exactly that until something readable lands past it — a separate door from the
    // capacity derivation under test here)…
    append_config_act(&path, r#"{"capture":"on"}"#);
    // …then supersede it through the API door: the newer act activates (no traffic), so
    // the malformed act is now BETWEEN activations — superseded, never parsed.
    let mut second = t3_capacity_config();
    second.max_active_ops = 128;
    second.undo_reserve = 32;
    log.record_capacity_config(second).expect("second config supersedes the malformed act");

    let mut probe = raw_conn(&path);
    let tx = probe.transaction().expect("read transaction");
    let derived = read_effective_bounds(&tx).expect(
        "a malformed SUPERSEDED act must not refuse the admission read — it was never \
         parsed under the whole-ledger fetch and must stay unparsed under the two-row one",
    );
    assert_eq!(derived.current.max_active_ops, 128, "the second act is CURRENT");
    assert_eq!(derived.pending, None, "nothing is pending past the second activation");
    drop(tx);

    // The CONTROL: the same malformed shape as the NEWEST act is pending — and refuses.
    append_capacity_act(&path, "{ this is not json");
    let tx = probe.transaction().expect("read transaction");
    assert!(
        read_effective_bounds(&tx).is_err(),
        "a malformed PENDING act must refuse the admission read by name, exactly as the \
         whole-ledger fetch always did"
    );
    drop(tx);
    std::fs::remove_file(&path).ok();
}

/// **AN OVER-CAP LEGACY POPULATION IS
/// REPORTED AT OPEN, NOT SILENTLY CARRIED.**
///
/// `origin/main` admitted intents with no capacity substrate at all, so a fully
/// legitimate v9 store can carry more active operations than this branch's bounds admit —
/// and a same-version reopen runs no migration hook that could confront the population.
/// The admission doors self-correct (both inequalities read LIVE occupancy, so new work
/// refuses until drain brings it back inside), but pre-fix the STATE ITSELF was silent:
/// nothing anywhere recorded that the store stood over cap. The fold adds the
/// [`IntegrityEvidence::OccupancyExceedsBounds`] arm to the §2.2b open-time scan — a
/// mirror (report, no refusal, no mutation: severing or clamping a legitimate historical
/// population would be a cop posture). RED against the earlier scan (no such row exists),
/// GREEN after.
#[test]
fn an_over_cap_legacy_population_is_reported_at_open() {
    let path = unique_temp_db_path("t8-f2-over-cap-legacy");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // The healthy control first: a fresh in-bounds store reports NO occupancy row.
    assert!(
        !log.integrity_report().iter().any(|e| matches!(
            e,
            IntegrityEvidence::OccupancyExceedsBounds { .. }
        )),
        "a fresh store must not report over-cap occupancy"
    );
    record_basis(&mut log, &archive_cmd("k-t8-f2-seed")).unwrap();
    drop(log);

    // Simulate main's legitimate history: 1100 active forward intents in a store with NO
    // capacity acts. RAW cloning, because HEAD's own doors refuse past the default cap —
    // which is precisely why a populated main-era store is the only way this state
    // arises, and why the open path is the only place left to say so.
    raw_conn(&path)
        .execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1099)
                 INSERT INTO intents (idempotency_key, account, facet, action_kind,
                                      message_ref, status, principal, epoch, evidence_ref,
                                      snapshot_ref, tier, compensates, seq, attempts,
                                      intent_id, kind, parent_intent_id, journal_required,
                                      capture_mode_generation, admitted_control_epoch,
                                      batch_id, frozen_basis)
                 SELECT idempotency_key || '-precap-' || n.i, account, facet, action_kind,
                        message_ref, status, principal, epoch, evidence_ref,
                        snapshot_ref, tier, compensates, seq, attempts,
                        intent_id || '-precap-' || n.i, kind, parent_intent_id,
                        journal_required, capture_mode_generation, admitted_control_epoch,
                        batch_id, frozen_basis
                   FROM intents, n WHERE idempotency_key = 'k-t8-f2-seed';",
            [],
        )
        .expect("raw-clone the pre-capacity population");

    // Same-version reopen — no migration path runs; the scan is the only voice.
    let reopened = SqliteIntentLog::open(&path).expect("HEAD accepts the legacy store");
    let over_cap = reopened.integrity_report().iter().find_map(|e| match e {
        IntegrityEvidence::OccupancyExceedsBounds {
            active_forward,
            active_undo,
            max_active_ops,
            undo_reserve,
        } => Some((*active_forward, *active_undo, *max_active_ops, *undo_reserve)),
        _ => None,
    });
    assert_eq!(
        over_cap,
        Some((1100, 0, 1024, 64)),
        "an over-cap legacy population must surface in the open-time integrity report \
         with the observed numbers — the silent self-correction was the finding"
    );
    drop(reopened);
    std::fs::remove_file(&path).ok();
}

/// **A DUPLICATE JSON MEMBER MUST NOT
/// SPLIT THE SQL AND RUST VERDICTS.** SQLite's `json_extract` answers from the FIRST
/// duplicate member; serde's named-field visitors refuse the duplicate outright. Third
/// appearance of the SQL-reads-what-Rust-refuses class (numeric-prefix, unmirrored
/// fields) — closed WHOLESALE for the syntactic family by
/// `store_open::no_duplicate_members_sql` (any member, any level the guards read, present
/// or future). Two arms: a duplicate capacity FIELD must not activate through the
/// trigger, and a duplicate-member ACTIVATION POINTER must not be buried under a fresh
/// clean row (the hiding shape, one door over). RED against the earlier guard,
/// GREEN after.
#[test]
fn a_duplicate_json_member_must_not_split_the_sql_and_rust_verdicts() {
    // ── Arm 1: the duplicate capacity field (first member in-domain, second refused). ──
    const DUP_JOINER_PAYLOAD: &str = r#"{"capture":"on","capacity":{"max_active_ops":64,"undo_reserve":32,"writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16,"sever_joiner_cap":0}}"#;
    let read = crate::capacity::CapacityConfig::from_engine_payload(DUP_JOINER_PAYLOAD);
    assert!(
        read.is_err(),
        "the Rust read side must refuse a duplicate capacity member; got {read:?}"
    );

    let path = unique_temp_db_path("t9-f1-dup-capacity-member");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t9-f1-dup")).unwrap();
    append_capacity_act(&path, DUP_JOINER_PAYLOAD);
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'applied' WHERE idempotency_key = 'k-t9-f1-dup';",
            [],
        )
        .expect("the status write must not be aborted by the duplicate-member act");
    let activation_rows: i64 = raw_conn(&path)
        .query_row(
            "SELECT COUNT(*) FROM engine_config WHERE kind = 'capacity_activated';",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        activation_rows, 0,
        "a duplicate-member capacity act (SQL reads the first member, Rust refuses the \
         duplicate) must be INERT at the trigger — SQL must never activate what Rust \
         refuses"
    );
    drop(log);
    std::fs::remove_file(&path).ok();

    // ── Arm 2: the duplicate-member activation pointer (first member a valid integer). ──
    let path = unique_temp_db_path("t9-f1-dup-pointer");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t9-f1-dup-ptr")).unwrap();
    const DUP_POINTER_PAYLOAD: &str =
        r#"{"activates_generation":1,"activates_generation":"garbage"}"#;
    assert!(
        crate::capacity::parse_activation_pointer(DUP_POINTER_PAYLOAD).is_err(),
        "the strict parse authority must refuse a duplicate-member pointer"
    );
    // ORDER MATTERS: the corrupt activation row lands
    // FIRST and the capacity act SECOND, so the act OUTDATES the row and the 
    // generation prefilter passes — the pointer guard below is then the DECIDING
    // conjunct. The ordering (act first) let the prefilter reject the whole scenario
    // and this arm stayed green with the pointer guard disabled.
    append_activation_act(&path, DUP_POINTER_PAYLOAD);
    let pending_gen = append_capacity_act(&path, T3_CAPACITY_PAYLOAD);

    let count_activation_rows = || -> i64 {
        raw_conn(&path)
            .query_row(
                "SELECT COUNT(*) FROM engine_config WHERE kind = 'capacity_activated';",
                [],
                |r| r.get(0),
            )
            .expect("count activation rows")
    };
    assert_eq!(count_activation_rows(), 1, "precondition: the corrupt row is newest");
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'applied' \
             WHERE idempotency_key = 'k-t9-f1-dup-ptr';",
            [],
        )
        .expect("the status write must not be aborted by the duplicate-member pointer");
    assert_eq!(
        count_activation_rows(),
        1,
        "a duplicate-member activation pointer must leave the trigger INERT — pre-fix \
         the SQL side read the first (valid) member, saw generation {pending_gen} as \
         pending, and buried the corrupt row under a fresh clean one exactly as r7 F2 \
         forbids"
    );
    let newest_payload = raw_conn(&path)
        .query_row(
            "SELECT payload FROM engine_config WHERE kind = 'capacity_activated' \
              ORDER BY generation DESC LIMIT 1;",
            [],
            |r| r.get::<_, String>(0),
        )
        .expect("read the newest activation payload");
    assert_eq!(
        newest_payload, DUP_POINTER_PAYLOAD,
        "the corrupt row must still be the newest — visible, refused by name, never \
         silently superseded"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// **THE IN-MEMORY LOG ACTIVATES A
/// FITTING PENDING REDUCTION ON A RELEASING STATUS WRITE, EXACTLY AS THE TRIGGER DOES.**
///
/// Pre-fix the fake's `capacity_pending` doc carried the gap as a named residual, and
/// uted its consequence: a settle made a pending reduction fit WITHOUT
/// activating it, so later undo admissions answered to the stale CURRENT bounds and the
/// pool grew past the reduction the durable trigger would have enforced — a fake with a
/// weaker gate than production, the exact failure the type's own `exposure_obligations`
/// doc exists to forbid. RED against the earlier fake (the 17th undo admits), GREEN after.
#[test]
fn the_in_memory_log_activates_a_fitting_reduction_on_a_releasing_write() {
    let mut log = InMemoryIntentLog::default();
    // 49 forwards under the compiled DEFAULT (1024/64) — all admit.
    for i in 0..49 {
        let cmd = archive_cmd(&format!("k-t9-f3-fwd-{i}"));
        assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    }
    // A 64/16 reduction: forward bound 48 < 49 live forwards ⇒ PENDING, not current.
    let reduction = crate::capacity::CapacityConfig {
        max_active_ops: 64,
        undo_reserve: 16,
        ..crate::capacity::DEFAULT
    };
    log.record_capacity_config(reduction).expect("the reduction is recorded pending");

    // The RELEASING write: settle one forward to a terminal — occupancy drops to 48,
    // the reduction now fits (48 <= 48 forward, 48 <= 64 total) and MUST activate.
    assert_eq!(
        log.set_status_if(
            "k-t9-f3-fwd-0",
            StatusPrecondition::NonTerminal,
            IntentStatus::Applied,
        )
        .unwrap(),
        StatusWrite::Written
    );

    // Undo admissions answer to the CURRENT bounds only (design) —
    // so they are the discriminating probe for WHICH bounds are current. Against the
    // activated 64-total cap, exactly 16 admit (48 + 16 = 64)…
    for i in 0..16 {
        let mut undo = archive_cmd(&format!("k-t9-f3-undo-{i}"));
        undo.compensates = Some(format!("k-t9-f3-fwd-{}", i + 1));
        assert_eq!(
            record_basis(&mut log, &undo).unwrap(),
            Claim::Inserted,
            "undo {i} fits inside the activated 64-op total"
        );
    }
    // …and the 17th REFUSES. Pre-fix the reduction was still pending, undos answered to
    // the DEFAULT 1024-op total, and this admission INSERTED the 65th active operation.
    let mut over = archive_cmd("k-t9-f3-undo-over");
    over.compensates = Some("k-t9-f3-fwd-17".to_string());
    assert!(
        matches!(record_basis(&mut log, &over).unwrap(), Claim::CapacityRefused(_)),
        "the 17th undo must refuse against the ACTIVATED reduction — admitting it means \
         the releasing write never activated the fitting pending bounds"
    );
}

/// **A DUPLICATE *UNKNOWN* MEMBER IS
/// READABLE ON BOTH SIDES: the guard mirrors serde, it does not out-strict it.**
///
/// The duplicate guard refused ANY duplicated member — but serde's named-field
/// visitors SKIP unknown members, duplicates included, so a payload carrying a duplicated
/// extension member was Rust-READABLE while the SQL guard left it trigger-inert: the
/// INVERSE divergence (SQL refuses what Rust accepts), parking a legitimately-activatable
/// act as pending and leaving undo admission on stale larger bounds. The guard is now
/// per-KNOWN-key (`no_duplicate_known_members_sql`) — this is the inverse control the 
/// witness lacked. RED against the count-vs-distinct guard (no activation appends),
/// GREEN with the serde-exact mirror.
#[test]
fn a_duplicate_unknown_member_is_readable_on_both_sides() {
    const DUP_UNKNOWN_PAYLOAD: &str = r#"{"capture":"on","capacity":{"max_active_ops":64,"undo_reserve":32,"writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16,"ext":"a","ext":"b"}}"#;
    // Positive control: the Rust authority READS this payload (unknown duplicates are
    // skipped by serde, exactly like unknown singletons).
    let read = crate::capacity::CapacityConfig::from_engine_payload(DUP_UNKNOWN_PAYLOAD)
        .expect("serde skips duplicated UNKNOWN members — this payload is Rust-readable");
    assert_eq!(read, t3_capacity_config());

    let path = unique_temp_db_path("t10-f1-dup-unknown");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    record_basis(&mut log, &archive_cmd("k-t10-f1-dup-unknown")).unwrap();
    let gen = append_capacity_act(&path, DUP_UNKNOWN_PAYLOAD);
    raw_conn(&path)
        .execute(
            "UPDATE intents SET status = 'applied' \
             WHERE idempotency_key = 'k-t10-f1-dup-unknown';",
            [],
        )
        .expect("the status write must not be aborted");
    assert_eq!(
        latest_activated_generation(&path),
        Some(gen),
        "a Rust-readable act (duplicate UNKNOWN member) must ACTIVATE through the \
         trigger — a guard stricter than serde is the same divergence class pointed the \
         other way"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// **AN OBJECT-LESS CAPACITY ACT
/// FAILS CLOSED, NEVER WIDE.**
///
/// `from_engine_payload`'s absent-`capacity` arm returned the documented DEFAULT — a
/// builder convenience that was a live WIDENING on the read side: a raw `kind='capacity'`
/// act with no capacity object parsed as DEFAULT (1024/64), sat as the newest PENDING
/// act, and design dual-bound rule answered FORWARD admission from those wide
/// pending bounds (uted 64 admissions against a configured 64/1). The arm now
/// REFUSES, which lands the act in the same loud place every other unreadable act
/// already lives: `read_effective_bounds` refuses admission BY NAME until the junk row
/// is dealt with (the / family posture — fail-safe and loud, never fail-wide).
/// RED against the DEFAULT-parsing arm (the 33rd forward ADMITS), GREEN after.
#[test]
fn an_object_less_capacity_act_fails_closed_not_wide() {
    const OBJECT_LESS_PAYLOAD: &str = r#"{"capture":"on"}"#;
    // Positive control: the Rust authority now refuses the absent object.
    assert!(
        crate::capacity::CapacityConfig::from_engine_payload(OBJECT_LESS_PAYLOAD).is_err(),
        "an object-less payload must refuse the capacity parse (r10 F2)"
    );

    let path = unique_temp_db_path("t10-f2-object-less");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // The 64/32 fixture through the API door — activates on the empty store; its forward
    // bound is 32.
    log.record_capacity_config(t3_capacity_config()).expect("configure 64/32");
    for i in 0..32 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-t10-f2-fwd-{i}"))).unwrap(),
            Claim::Inserted,
            "forward {i} fits the configured forward bound"
        );
    }
    // THE FAULT: a raw capacity act with no capacity object, now the newest pending act.
    append_capacity_act(&path, OBJECT_LESS_PAYLOAD);
    // Pre-fix: the act parsed as DEFAULT (forward bound 960) and dual-bound rule
    // ADMITTED this forward far past the configured 32. Post-fix: the admission read
    // refuses the unreadable ledger by name — loud, never wide.
    let over = record_basis(&mut log, &archive_cmd("k-t10-f2-fwd-over"));
    let err = over.expect_err(
        "an object-less capacity act must fail admission CLOSED (unreadable ledger), \
         never widen it to the compiled DEFAULT",
    );
    assert!(
        err.0.contains("unreadable"),
        "the refusal names the unreadable ledger: {err:?}"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// **A FUTURE ACTIVATION
/// POINTER CANNOT RESERVE THE NEXT ACT.**
///
/// Both first-party activation writers activate an act that already exists and append at
/// global MAX+1, so an honest row's pointer is strictly below its own generation. A raw
/// row pointing at a FUTURE generation is a planted reservation: it lies inert until an
/// honest `record_capacity_config` lands its act at exactly that generation — and the
/// pre-fix read then seated that never-fitted act as CURRENT, bypassing BOTH fit
/// authorities through two entirely honest API calls (widened undo admission from
/// a configured 64 to 8192 this way). The read now refuses a pointer that does not name
/// its own past. RED against the earlier read (the undo below ADMITS against the planted
/// reduction), GREEN after.
#[test]
fn codex_r13_f1_a_future_activation_pointer_cannot_reserve_the_next_act() {
    let path = unique_temp_db_path("t13-f1-future-pointer");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // 49 forwards under the compiled DEFAULT — all admit.
    for i in 0..49 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-t13-f1-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    // THE PLANT: a well-formed activation row at the ordinary next generation whose
    // pointer names the generation AFTER it — the future. Raw is the only door: both
    // honest writers point at an act that already exists.
    let conn = raw_conn(&path);
    let next_gen: i64 = conn
        .query_row("SELECT MAX(generation) + 1 FROM engine_config;", [], |r| r.get(0))
        .unwrap();
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES (?1, strftime('%s','now'), 'capacity_activated',
                     json_object('activates_generation', ?2));",
        rusqlite::params![next_gen, next_gen + 1],
    )
    .expect("plant the future-pointer activation row");
    drop(conn);

    // THE HONEST STEP THE RESERVATION WAS WAITING FOR: a NON-fitting reduction (forward
    // bound 48 < 49 live forwards) appended through the API — it lands at exactly the
    // reserved generation, and neither fit authority ever passes it.
    let reduction = crate::capacity::CapacityConfig {
        max_active_ops: 64,
        undo_reserve: 16,
        ..crate::capacity::DEFAULT
    };
    log.record_capacity_config(reduction)
        .expect("the honest append itself succeeds — the reduction is merely pending");

    // THE PROBE, on's own axis: undo admission answers to CURRENT bounds only.
    // Pre-fix, CURRENT is now the never-fitted 64/16 (or an 8192 enlargement, planted
    // the same way) and this undo ADMITS against it. Post-fix, the read refuses the
    // planted row by name — loud, until an honest activation row supersedes it.
    let mut undo = archive_cmd("k-t13-f1-undo");
    undo.compensates = Some("k-t13-f1-fwd-0".to_string());
    let outcome = record_basis(&mut log, &undo);
    let err = outcome.expect_err(
        "a future activation pointer must refuse the admission read — honoring it seats \
         a never-fitted act as CURRENT",
    );
    assert!(
        err.0.contains("not in its own past"),
        "the refusal names the future-pointer shape: {err:?}"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// **A CAPACITY ACT STRANDED BETWEEN THE POINTER AND ITS OWN
/// ACTIVATION ROW IS A REFUSED SHAPE, NEVER A PENDING ACT.** Both first-party activation
/// writers activate the newest capacity act they can see and append their row at global
/// MAX+1, so no honest ledger carries an act with `pointer < act < activation row`. The
/// status trigger's JSON-free integer prefilter (`MAX(capacity) >
/// MAX(capacity_activated)`, `store_open.rs`) is EXACT on honest ledgers for the same
/// reason — there, "a pending act exists" and "the newest capacity act outranks the
/// newest activation row" are the same fact. Pre-fix, the Rust derivation read a planted
/// gap act as PENDING: a reduction the trigger could then never activate (its prefilter
/// stays false forever), so releasing status writes never ran the fit predicate and
/// admissions kept the old, wider bounds — silently, indefinitely. Post-fix the
/// derivation refuses the shape by name — loud, and CONSISTENT with the trigger's own
/// inability to see it — until an honest activation row supersedes the planted one, the
/// standing recovery story.
#[test]
fn codex_r14_f2_an_act_stranded_behind_the_activation_row_refuses_the_read() {
    let path = unique_temp_db_path("r14-f2-stranded-act");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // Honest base: the 64/32 config, activated by its own no-traffic fit-check.
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config");
    let honest_gen = latest_activated_generation(&path)
        .expect("the 64/32 act is CURRENT before the plant");

    // THE PLANT, two raw rows: a VALID capacity act (only the ORDERING is dishonest),
    // then a NEWER activation row whose pointer re-names the OLD generation — leaving
    // the new act stranded between the pointer and the row. Raw is the only door: both
    // honest writers activate the newest act they can see.
    let stranded = append_capacity_act(
        &path,
        "{\"capture\":\"on\",\"capacity\":{\"max_active_ops\":4096,\"undo_reserve\":64,\
         \"writer_chunk_budget_ms\":50,\"sever_watchdog_ms\":5000,\"sever_joiner_cap\":16}}",
    );
    let row_gen =
        append_activation_act(&path, &format!("{{\"activates_generation\":{honest_gen}}}"));
    assert!(
        honest_gen < stranded && stranded < row_gen,
        "the plant must leave the act strictly between the pointer and its activation row"
    );

    // THE WEDGE PREMISE, at the bytes: the activation trigger's integer prefilter can
    // never fire on this ledger — the newest capacity act does not outrank the newest
    // activation row, so no status write will ever run the fit predicate against it.
    let (max_cap, max_row): (i64, i64) = raw_conn(&path)
        .query_row(
            "SELECT (SELECT MAX(generation) FROM engine_config WHERE kind = 'capacity'),
                        (SELECT MAX(generation) FROM engine_config
                          WHERE kind = 'capacity_activated');",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read the two prefilter maxima");
    assert!(
        max_cap < max_row,
        "the trigger prefilter must be provably blind to the stranded act \
         ({max_cap} vs {max_row})"
    );

    // 1. THE DERIVATION, by name. Pre-fix this is `Ok` with the stranded act as
    //    PENDING — a pending act nothing can ever activate.
    let mut probe = raw_conn(&path);
    let tx = probe.transaction().expect("read transaction");
    let reason = read_effective_bounds(&tx).expect_err(
        "an act stranded behind the newest activation row must REFUSE the read — \
         honoring it as pending wedges the reduction forever",
    );
    assert!(
        reason.0.contains("stranded behind"),
        "the refusal names the stranded-act shape: {reason:?}"
    );
    drop(tx);

    // 2. THE ADMISSION DOOR: the same refusal, loud — instead of admitting against the
    //    old bounds while the planted reduction silently never lands.
    let err = record_basis(&mut log, &archive_cmd("k-r14-f2-probe"))
        .expect_err("the admission read must refuse the stranded-act ledger by name");
    assert!(
        err.0.contains("stranded behind"),
        "the admission refusal names the shape: {err:?}"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

/// **A PRESENT-BUT-NULL ACTIVATION POINTER MUST REFUSE
/// EVERY CAPACITY READ, NEVER REVERT `current` TO THE COMPILED DEFAULT.**
///
/// The third member of the fail-open-parse family (`{"capacity":null}`, malformed
/// `kind='capacity'` JSON, this one), and the reason the family closed WHOLESALE onto
/// one strict parse authority (`capacity::parse_activation_pointer`) instead of a third
/// per-site patch. Pre-fix, the activation read was
/// `CAST(json_extract(payload,'$.activates_generation') AS INTEGER)` collected as
/// `Option<i64>` and then `.optional().flatten()`-ed: an act whose pointer is PRESENT and
/// JSON `null` (or missing, or a string, or negative) yields SQL NULL, which flattens to
/// exactly the `None` that means **no activation has ever landed**. `effective_bounds`
/// then seats `capacity::DEFAULT` (1024/64) as CURRENT and re-offers the operator's real
/// act as PENDING — so a store deliberately configured down to 64 slots silently admits
/// against 1024, and undo admission runs 960 slots past the configured total.
///
/// This witness drives the harm end to end: the pool is filled to the CONFIGURED total
/// (64) through the real admission door, the null pointer is appended RAW, and the next
/// undo claim is asked for. Post-fix every capacity read REFUSES by name; pre-fix the
/// claim is ADMITTED, which is the finding.
#[test]
fn codex_r5_a_null_activation_pointer_refuses_the_admission_read() {
    let path = unique_temp_db_path("r5-null-activation-pointer");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    // The 64/32 fixture, through the API door. Occupancy is empty, so the config
    // transaction's own no-traffic fit-check activates it immediately.
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config");
    let configured_gen =
        latest_activated_generation(&path).expect("the 64/32 act is CURRENT before the fault");

    // Fill the CONFIGURED pool exactly: 32 forward (the reserve bound) + 32 undo = 64.
    for i in 0..32 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    for i in 0..32 {
        let mut cmd = archive_cmd(&format!("k-undo-{i}"));
        cmd.compensates = Some(format!("k-fwd-{i}"));
        assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    }
    // ANTI-VACUITY: at the configured bounds this store is FULL — one more undo refuses.
    let mut at_cap = archive_cmd("k-undo-at-cap");
    at_cap.compensates = Some("k-fwd-0".into());
    assert!(
        matches!(record_basis(&mut log, &at_cap).unwrap(), Claim::CapacityRefused(_)),
        "the 64-slot config must really be CURRENT before the fault is injected"
    );

    // THE FAULT: a NEWER activation act whose pointer is present and null.
    let null_gen = append_activation_act(&path, r#"{"activates_generation":null}"#);

    // 1. THE DERIVATION ITSELF, by name. Pre-fix this is
    //    `Ok(EffectiveBounds { current: DEFAULT(1024/64), pending: Some((2, 64/32)) })` —
    //    the exact "reverts current to DEFAULT while pending stays" shape the finding
    //    describes.
    let mut probe = raw_conn(&path);
    let tx = probe.transaction().expect("read transaction");
    let derived = read_effective_bounds(&tx);
    let reason = derived
        .as_ref()
        .err()
        .map(|e| e.0.clone())
        .unwrap_or_else(|| {
            panic!(
                "a PRESENT-but-null activation pointer at generation {null_gen} must REFUSE \
                 the capacity read, never read as `no activation` and revert CURRENT to the \
                 compiled default; got: {derived:?}"
            )
        });
    assert!(
        reason.contains("capacity ledger is unreadable"),
        "the refusal must name the unreadable ledger; got: {reason}"
    );
    drop(tx);
    drop(probe);

    // 2. AND THE HARM IS CLOSED AT THE DOOR: the next undo claim REFUSES rather than
    //    being admitted against bounds nobody configured. Pre-fix this returns
    //    `Claim::Inserted` — occupancy 64 is nowhere near DEFAULT's 1024 total cap.
    let mut over = archive_cmd("k-undo-past-the-configured-total");
    over.compensates = Some("k-fwd-1".into());
    let admission = record_basis(&mut log, &over);
    let admission_reason = admission
        .as_ref()
        .err()
        .map(|e| e.0.clone())
        .unwrap_or_else(|| {
            panic!(
                "generation {configured_gen} configured a 64-slot total and occupancy is \
                 already 64 — an unreadable activation pointer must REFUSE the claim, never \
                 admit it against the compiled 1024-slot default; got: {admission:?}"
            )
        });
    assert!(
        admission_reason.contains("capacity ledger is unreadable"),
        "admission must refuse over the unreadable activation act, naming it; got: \
         {admission_reason}"
    );

    // 3. NOTHING DURABLE: the refusal wrote no row.
    assert_eq!(
        non_terminal_count(&path),
        64,
        "a refusal over an unreadable activation act must leave nothing behind"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn both_authorities_agree_at_the_edges() {
    // The DUAL-AUTHORITY-DRIFT guard: `activation_fits` (capacity.rs) and the
    // trigger's own SQL fit predicate must agree at every §7c edge, adapted to the
    // 64/32 fixture. Both are ACTIVATION questions (current-state, no batch) — NEVER
    // compared to `admission_check` (its own edge table; domain correction:
    // admission and activation are different questions on purpose).
    let cfg = t3_capacity_config(); // max=64, reserve=32, forward_bound=32
    let edges: &[(&str, u32, u32)] = &[
        ("at the forward bound", 32, 0),
        ("one under the forward bound", 31, 0),
        ("one PAST the forward bound", 33, 0),
        ("at the total cap", 0, 64),
        ("one PAST the total cap", 0, 65),
        ("at both bounds simultaneously (the reserve edge)", 32, 32),
    ];
    for (label, active_forward, active_undo) in edges.iter().copied() {
        let occ = crate::capacity::Occupancy { active_forward, active_undo };
        let predicted = crate::capacity::activation_fits(occ, &cfg);
        let observed = trigger_observes_fit(active_forward, active_undo, cfg);
        assert_eq!(
            predicted, observed,
            "{label} (forward={active_forward}, undo={active_undo}): activation_fits \
             says {predicted}, the trigger's own SQL predicate says {observed} — the two \
             authorities must never disagree"
        );
    }
}

/// The activation fit predicate EXACTLY as `intents_status_activation` carried it before
/// Two unbounded `COUNT(*)`s over the whole non-terminal domain. Frozen
/// here on purpose — this is the REFERENCE the LIMIT-bounded rewrite is checked against, so
/// it must NOT be shared with the production text (a shared text would drift together and
/// prove nothing).
fn unbounded_activation_fit_predicate_sql() -> String {
    format!(
        "(SELECT COUNT(*) FILTER (WHERE compensates IS NULL)
                FROM intents WHERE status IN {NON_TERMINAL_STATUS_SQL})
             <= CAST(json_extract(c.payload, '$.capacity.max_active_ops') AS INTEGER)
                - CAST(json_extract(c.payload, '$.capacity.undo_reserve') AS INTEGER)
             AND (SELECT COUNT(*) FROM intents WHERE status IN {NON_TERMINAL_STATUS_SQL})
             <= CAST(json_extract(c.payload, '$.capacity.max_active_ops') AS INTEGER)",
        NON_TERMINAL_STATUS_SQL = crate::NON_TERMINAL_STATUS_SQL
    )
}

/// Evaluate one fit predicate against the store's CURRENT occupancy and its newest pending
/// `capacity` act — the same `c` binding the trigger's own `WHEN` clause uses.
fn evaluate_fit_predicate(conn: &rusqlite::Connection, fit: &str) -> bool {
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM engine_config c
                 WHERE c.kind = 'capacity'
                   AND c.generation = (SELECT MAX(generation) FROM engine_config
                                        WHERE kind = 'capacity')
                   AND {fit});"
    );
    conn.query_row(&sql, [], |r| r.get::<_, i64>(0)).expect("fit predicate") == 1
}

/// THE EQUIVALENCE GUARD for the LIMIT-bounded occupancy probes.
///
/// The rewrite's whole claim is "the scan may stop at `bound + 1`, because the comparison
/// only distinguishes `<= bound` from `> bound`". That claim is exactly one thing: the two
/// predicates return the SAME verdict on the same store. This drives both texts — the frozen
/// unbounded one and the production one (`store_open::activation_fit_predicate_sql`, the
/// bytes the trigger itself carries) — over
/// `both_authorities_agree_at_the_edges`'s own edge table PLUS a case where the limit
/// provably BINDS, and asserts they never disagree.
///
/// **Anti-vacuity, stated because this witness cannot go RED against the pre-fix bytes** (the
/// pre-fix bytes ARE one of the two things it compares): the edge table alone would never
/// exercise a truncated count — every edge sits at or within one row of its bound, so a
/// `LIMIT` that was too small by a mile would still agree there. The saturating row is what
/// makes the comparison discriminating, and it asserts its own premise: the evaluated limit
/// is strictly BELOW the live occupancy, so the new form's counts are provably truncated
/// while the old form's are not. Verified discriminating by mutation: changing the limit
/// expression's `+ 1` to `+ 0` makes exactly this witness fail on the at-bound edges.
#[test]
fn the_limit_bounded_activation_probes_agree_with_the_unbounded_form() {
    let bounded = crate::store_open::activation_fit_predicate_sql();
    let unbounded = unbounded_activation_fit_predicate_sql();

    // (label, forward, undo, cfg) — the T4 edge table, then the SATURATING case.
    let cfg = t3_capacity_config(); // max=64, reserve=32, forward_bound=32
    let cases: &[(&str, u32, u32, crate::capacity::CapacityConfig)] = &[
        ("at the forward bound", 32, 0, cfg),
        ("one under the forward bound", 31, 0, cfg),
        ("one PAST the forward bound", 33, 0, cfg),
        ("at the total cap", 0, 64, cfg),
        ("one PAST the total cap", 0, 65, cfg),
        ("at both bounds simultaneously (the reserve edge)", 32, 32, cfg),
        // SATURATING: occupancy PAST the CONSTANT stop (made the probe
        // LIMIT the compile-time constant `MAX_ACTIVE_OPS_MAX + 1` = 8193 — see
        // `store_open::activation_probe_limit`'s doc; the older 65-row saturating case
        // stopped truncating anything the moment the per-act derivation was deleted). One
        // row is seeded through the real admission door, then raw-cloned to 8194
        // non-terminal rows (admission itself would refuse long before the stop — raw is
        // the only door to a pool this size, which is fine: the predicate under test
        // reads rows, not admissions). Both counts truncate in the bounded form, complete
        // in the unbounded one, and the verdicts must still match (both refuse the 64/32
        // act).
        ("far PAST the constant stop (the limit binds)", 1, 0, cfg),
    ];

    for (label, active_forward, active_undo, cfg) in cases.iter().copied() {
        let path = unique_temp_db_path("t4-limit-equivalence");
        let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
        for i in 0..active_forward {
            record_basis(&mut log, &archive_of(&format!("k-fwd-{i}"), &format!("m-fwd-{i}")))
                .unwrap();
        }
        for i in 0..active_undo {
            let mut cmd = archive_of(&format!("k-undo-{i}"), &format!("m-undo-{i}"));
            cmd.compensates = Some(format!("origin-{i}"));
            record_basis(&mut log, &cmd).unwrap();
        }
        // The saturating case's raw cloning past the constant stop — see the case's own
        // comment in the table above.
        if label.starts_with("far PAST") {
            raw_conn(&path)
                .execute(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 8193)
                         INSERT INTO intents (idempotency_key, account, facet, action_kind,
                                              message_ref, status, principal, epoch, evidence_ref,
                                              snapshot_ref, tier, compensates, seq, attempts,
                                              intent_id, kind, parent_intent_id, journal_required,
                                              capture_mode_generation, admitted_control_epoch,
                                              batch_id, frozen_basis)
                         SELECT idempotency_key || '-sat-' || n.i, account, facet, action_kind,
                                message_ref, status, principal, epoch, evidence_ref,
                                snapshot_ref, tier, compensates, seq, attempts,
                                intent_id || '-sat-' || n.i, kind, parent_intent_id,
                                journal_required, capture_mode_generation, admitted_control_epoch,
                                batch_id, frozen_basis
                           FROM intents, n WHERE idempotency_key = 'k-fwd-0';",
                    [],
                )
                .expect("raw-clone the saturating pool");
        }
        append_capacity_act(&path, &capacity_payload_json(&cfg));

        let conn = raw_conn(&path);
        let old = evaluate_fit_predicate(&conn, &unbounded);
        let new = evaluate_fit_predicate(&conn, &bounded);
        assert_eq!(
            old, new,
            "{label} (forward={active_forward}, undo={active_undo}, max={}, reserve={}): the \
             unbounded fit predicate says {old}, the LIMIT-bounded one says {new} — a LIMIT \
             may shorten the scan and must never move the answer",
            cfg.max_active_ops, cfg.undo_reserve
        );

        if label.starts_with("far PAST") {
            // The premise of the saturating case, asserted rather than assumed: the
            // EVALUATED stop (act-derived again since max+1 for an
            // in-domain act, the constant ceiling as the fallback) sits far below the
            // cloned pool, so both probes provably truncate.
            let limit: i64 = conn
                .query_row(
                    &format!("SELECT {};", crate::store_open::activation_probe_limit_sql()),
                    [],
                    |r| r.get(0),
                )
                .expect("the probe limit is itself an evaluable expression");
            assert_eq!(
                limit, 65,
                "the 64/32 act's act-derived stop is max_active_ops + 1 (#24-1b \
                 codex-r13 F2; the constant ceiling {} is the FALLBACK arm, pinned by \
                 its own fn)",
                crate::store_open::activation_probe_limit()
            );
            let active: i64 = conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM intents WHERE status IN {};",
                        crate::NON_TERMINAL_STATUS_SQL
                    ),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                limit < active,
                "anti-vacuous: this case must TRUNCATE — probe limit {limit} against {active} \
                 live non-terminal rows"
            );
        }
        drop(conn);
        drop(log);
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn capacity_act_appends_and_activates_when_fitting() {
    // design — the NO-TRAFFIC activation: an empty pool trivially fits ANY smaller
    // bounds, so `record_capacity_config`'s OWN fit-check activates it in the SAME
    // transaction as the append — no status write required at all.
    let path = unique_temp_db_path("t4-no-traffic-activation");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config");
    assert!(
        latest_activated_generation(&path).is_some(),
        "an empty pool trivially fits ANY smaller bounds"
    );
    assert_eq!(
        all_activated_generations(&path).len(),
        1,
        "exactly ONE activation act — the config transaction's fit-check must not \
         double-fire"
    );
    // Prove it is genuinely ACTIVE, not merely recorded: the SMALL bounds gate
    // admission right now, with no further act.
    for i in 0..32 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    let refusal = record_basis(&mut log, &archive_cmd("k-fwd-overflow")).unwrap();
    assert!(
        matches!(refusal, Claim::CapacityRefused(_)),
        "the 64/32 bounds must be ACTIVE, not merely pending: {refusal:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn capacity_reduction_pends_while_occupancy_exceeds() {
    // design — DUAL-BOUND EVALUATION: while a reduction sits pending, FORWARD
    // admission answers to the NEW (pending) bounds immediately; UNDO/remedy admission
    // keeps answering to the bounds still CURRENT (activation has not yet released
    // enough of the pool for the trigger to fire).
    let path = unique_temp_db_path("t4-dual-bound");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    for i in 0..50 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted,
            "50 is well inside DEFAULT's 960 forward reserve"
        );
    }
    // 64/32: forward_bound=32 — 50 already exceeds it, so this reduction does NOT fit
    // and stays PENDING.
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config");
    assert_eq!(latest_activated_generation(&path), None, "the reduction does not fit yet");
    // FORWARD admission answers to the NEW (pending, 32) bound immediately.
    let forward_refusal = record_basis(&mut log, &archive_cmd("k-fwd-pending-check")).unwrap();
    assert!(
        matches!(forward_refusal, Claim::CapacityRefused(ref m) if m.contains("forward")),
        "forward admission must answer to the PENDING bounds, got {forward_refusal:?}"
    );
    // UNDO/remedy admission keeps answering to the bounds still CURRENT (DEFAULT, 1024
    // total) — it must ADMIT, because the reduction has not activated.
    let mut undo = archive_cmd("k-undo-pending-check");
    undo.compensates = Some("origin-pending-check".into());
    assert_eq!(
        record_basis(&mut log, &undo).unwrap(),
        Claim::Inserted,
        "undo/remedy admission must answer to the bounds still CURRENT, not the pending \
         reduction"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn reduction_activates_at_the_releasing_transaction() {
    let path = unique_temp_db_path("t4-releasing-activation");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    let mut keys = Vec::new();
    for i in 0..40 {
        let key = format!("k-fwd-{i}");
        assert_eq!(record_basis(&mut log, &archive_cmd(&key)).unwrap(), Claim::Inserted);
        keys.push(key);
    }
    // fwd_bound=32; 40 does not fit.
    log.record_capacity_config(t3_capacity_config())
        .expect("capacity config");
    assert_eq!(latest_activated_generation(&path), None);
    // Settle rows down to 33 — still one PAST the bound: must stay pending.
    for key in &keys[..7] {
        assert_eq!(
            log.set_status_if(key, StatusPrecondition::NonTerminal, IntentStatus::Applied)
                .unwrap(),
            StatusWrite::Written
        );
    }
    assert_eq!(
        latest_activated_generation(&path),
        None,
        "33 active forward still exceeds the 32 bound"
    );
    // The 8th settling write crosses the fit — activation lands ATOMICALLY in THAT
    // very transaction, with no further traffic.
    assert_eq!(
        log.set_status_if(&keys[7], StatusPrecondition::NonTerminal, IntentStatus::Applied)
            .unwrap(),
        StatusWrite::Written
    );
    assert!(
        latest_activated_generation(&path).is_some(),
        "the settling write that crossed the fit must activate the pending reduction"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn boot_quarantine_releases_activate_a_pending_reduction() {
    // The worst case: crash-reopen with a pending reduction, quarantine
    // terminalizes the fitting slots, activation lands IN the quarantine transaction —
    // no further traffic needed.
    let path = unique_temp_db_path("t4-boot-quarantine-activation");
    {
        let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
        // 32 plain, never-claimed forward-pending rows — boot_quarantine's
        // per-attempt-head loop never touches an intent with no attempt chain.
        for i in 0..32 {
            assert_eq!(
                record_basis(
                    &mut log,
                    &archive_of(&format!("k-fwd-{i}"), &format!("m-fwd-{i}"))
                )
                .unwrap(),
                Claim::Inserted
            );
        }
        // The 33rd is the crafted case (row a2): claimed, then the control epoch
        // moves under it — boot's stale-epoch closure is the ONLY thing that
        // terminalizes this one (a real `sever` closes it itself, so the shape only
        // survives when the bump and the closure came apart).
        admit_and_claim(&mut log, &archive_of("k-stale", "m-stale"));
    }
    assert_eq!(non_terminal_count(&path), 33, "32 plain + 1 claimed, all non-terminal");
    {
        let mut log = SqliteIntentLog::open(&path).expect("reopen to plant the reduction");
        // 33 exceeds the 64/32 fixture's forward_bound=32 — pends.
        log.record_capacity_config(t3_capacity_config())
            .expect("capacity config");
    }
    assert_eq!(latest_activated_generation(&path), None, "33 still exceeds the bound");
    raw_conn(&path)
        .execute("UPDATE control_epoch SET epoch = epoch + 1 WHERE id = 1;", [])
        .expect("bump the fence under the crashed claim");
    // REOPEN: boot_quarantine terminalizes the stale-epoch claim `Severed` (through
    // `terminalize_operation` -> `settle_status`) — ONE fewer non-terminal forward row,
    // crossing the fit — with NO further traffic.
    let _log = SqliteIntentLog::open(&path).expect("reopen — boot_quarantine runs here");
    assert_eq!(
        status_str(&path, "k-stale"),
        "severed",
        "boot_quarantine must have closed the stale-epoch claim"
    );
    assert_eq!(non_terminal_count(&path), 32, "one fewer non-terminal row after quarantine");
    assert!(
        latest_activated_generation(&path).is_some(),
        "boot_quarantine's OWN terminalization must fire the activation trigger — no \
         further traffic needed"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn pending_reduction_survives_restart() {
    let path = unique_temp_db_path("t4-pending-survives-restart");
    {
        let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
        for i in 0..40 {
            assert_eq!(
                record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
                Claim::Inserted
            );
        }
        log.record_capacity_config(t3_capacity_config())
            .expect("capacity config");
    }
    assert_eq!(latest_activated_generation(&path), None, "still pending before restart");
    let mut log = SqliteIntentLog::open(&path).expect("reopen");
    assert_eq!(
        latest_activated_generation(&path),
        None,
        "the pending reduction must survive the restart, not silently vanish or activate"
    );
    let refusal = record_basis(&mut log, &archive_cmd("k-fwd-after-restart")).unwrap();
    assert!(
        matches!(refusal, Claim::CapacityRefused(ref m) if m.contains("forward")),
        "the pending 32-forward bound must still gate admission after reopen: {refusal:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_increase_that_shrinks_the_forward_domain_pends_too() {
    // `max_active_ops` going UP is not the same question as the FORWARD DOMAIN growing:
    // a reserve that grows FASTER than the cap shrinks `forward_bound` even while the
    // total cap increases.
    let path = unique_temp_db_path("t4-increase-shrinks-forward");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    for i in 0..150 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted,
            "150 is well inside DEFAULT's 960 forward reserve"
        );
    }
    let increased = crate::capacity::CapacityConfig {
        max_active_ops: 2000, // an INCREASE over DEFAULT's 1024
        undo_reserve: 1900,   // grows FASTER — forward_bound=100, BELOW DEFAULT's 960
        writer_chunk_budget_ms: 50,
        sever_watchdog_ms: 5000,
        sever_joiner_cap: 16,
    };
    log.record_capacity_config(increased).expect("capacity config");
    assert_eq!(
        latest_activated_generation(&path),
        None,
        "max_active_ops increased, but 150 active_forward exceeds the NEW forward_bound \
         (100) — the reduction in the FORWARD DOMAIN still pends, regardless of the \
         total cap's own direction"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn two_pending_capacity_acts_latest_generation_wins() {
    let path = unique_temp_db_path("t4-two-pending-latest-wins");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap");
    for i in 0..40 {
        assert_eq!(
            record_basis(&mut log, &archive_cmd(&format!("k-fwd-{i}"))).unwrap(),
            Claim::Inserted
        );
    }
    // g1: forward_bound=20 — 40 exceeds it, pends.
    let g1 = crate::capacity::CapacityConfig {
        max_active_ops: 100,
        undo_reserve: 80,
        writer_chunk_budget_ms: 50,
        sever_watchdog_ms: 5000,
        sever_joiner_cap: 16,
    };
    log.record_capacity_config(g1).expect("capacity config g1");
    assert_eq!(latest_activated_generation(&path), None);
    // g2: forward_bound=32 — 40 STILL exceeds it (does not accidentally activate), but
    // SUPERSEDES g1 as the pending target (the OLDER unactivated act).
    let g2 = crate::capacity::CapacityConfig {
        max_active_ops: 100,
        undo_reserve: 68,
        writer_chunk_budget_ms: 50,
        sever_watchdog_ms: 5000,
        sever_joiner_cap: 16,
    };
    log.record_capacity_config(g2).expect("capacity config g2");
    assert_eq!(latest_activated_generation(&path), None, "g2 still does not fit at 40");
    // Settle down to exactly 32 — this fits g2 (32<=32) but NOT g1 (32>20). If the
    // OLDER, superseded g1 were still governing, nothing would activate here.
    for i in 0..8 {
        let key = format!("k-fwd-{i}");
        assert_eq!(
            log.set_status_if(&key, StatusPrecondition::NonTerminal, IntentStatus::Applied)
                .unwrap(),
            StatusWrite::Written
        );
    }
    assert!(
        latest_activated_generation(&path).is_some(),
        "activation at forward=32 proves g2 (the NEWER pending act) governs, not the \
         superseded g1"
    );
    std::fs::remove_file(&path).ok();
}
