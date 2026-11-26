//! The engine-config ledger: capture mode, knob acts, and unknown kinds.

use super::*;
use crate::sqlite_log::{capture_mode_is_on, CAPTURE_KINDS, ENGINE_CONFIG_KINDS};

#[test]
fn a_duplicate_capture_key_refuses_instead_of_last_wins() {
    // Serde_json::Value keeps the LAST duplicate top-level member, so
    // {"capture":"on","capture":"off"} was admitted as OFF — and reversing the
    // order flipped the verdict. Ambiguous provenance on the verdict-bearing field
    // refuses (design §1c); the strict single-key forms still parse.
    assert!(
        capture_mode_is_on(2, r#"{"capture":"on","capture":"off"}"#).is_err(),
        "duplicate capture keys must refuse"
    );
    assert!(
        capture_mode_is_on(2, r#"{"capture":"off","capture":"on"}"#).is_err(),
        "duplicate capture keys must refuse in either order"
    );
    assert!(capture_mode_is_on(2, r#"{"capture":"on","retention":"dormant"}"#).unwrap());
    assert!(!capture_mode_is_on(2, r#"{"capture":"off"}"#).unwrap());
}

#[test]
fn replay_semantics_survive_an_unreadable_current_config() {
    // Duplicate-claim resolution must come BEFORE config validation in the
    // admission transaction — an existing row already carries its admission provenance,
    // and ADR-P013's replay contract (identical retry ⇒ AlreadyExisted; different
    // command ⇒ the rewrite rejection) must not depend on the CURRENT config head
    // being readable.
    let path = unique_temp_db_path("replay-vs-config");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let cmd = Command::new(
        "k-replay-cfg", "acct", Facet::Mail,
        Action::Archive { message_ref: "m-1".into() },
    );
    assert_eq!(record_basis(&mut log, &cmd).unwrap(), Claim::Inserted);
    // Wedge the config head with an unreadable act — of a kind the capture-mode read
    // GOVERNS by (`CAPTURE_KINDS`, C6.0): a KNOWN kind outside that list (a knob kind,
    // `capacity_activated`) is skipped by the read and would wedge nothing (an UNKNOWN kind at
    // the head refuses by name since the `read_capture_act`).
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES (2, strftime('%s','now'), 'mode_change', 'not-json');",
        [],
    ).unwrap();
    assert!(
        record_basis(&mut log, &archive_cmd("k-replay-cfg-fresh")).is_err(),
        "the wedge is real: a NEW admission refuses on the unreadable head act"
    );
    drop(conn);
    assert_eq!(
        record_basis(&mut log, &cmd).unwrap(),
        Claim::AlreadyExisted,
        "an identical replay resolves from the durable row, config unread"
    );
    let mut other = cmd.clone();
    other.action = Action::Unarchive { message_ref: "m-1".into() };
    let err = record_basis(&mut log, &other).unwrap_err();
    assert!(
        err.0.contains("already records a different command"),
        "a conflicting replay is the rewrite rejection, not a config error: {}",
        err.0
    );
}

#[test]
fn capture_mode_is_parsed_from_json_not_matched_as_a_substring() {
    // The head config act's capture mode was decided by a SQL
    // `payload LIKE '%"capture":"on"%'` substring match. Any serializer that emits a
    // space after the colon (pretty-printed JSON — `serde_json::to_string_pretty`, an
    // operator-written act, a future writer) misses the pattern and the admission
    // SILENTLY binds journal_required=0: capture is ON but the intent records that no
    // pre-state journal is owed. Fail-open on a provenance column. The mode must come
    // from a strict Rust-side JSON parse of the top-level "capture" field.
    let path = unique_temp_db_path("capture-pretty");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        crate::store_open::pin_durability_profile(&conn).unwrap();
        conn.execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES (2, strftime('%s','now'), 'mode_change', ?1);",
            rusqlite::params![
                "{\n  \"capture\": \"on\",\n  \"retention\": \"dormant\"\n}"
            ],
        )
        .unwrap();
    }
    record_basis(&mut log, &archive_cmd("k-capture-pretty")).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (jr, cmg): (i64, i64) = conn
        .query_row(
            "SELECT journal_required, capture_mode_generation
                 FROM intents WHERE idempotency_key='k-capture-pretty';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(cmg, 2, "the head act governs admission");
    assert_eq!(
        jr, 1,
        "pretty-printed `\"capture\": \"on\"` is capture ON — journal_required must be 1"
    );
}

#[test]
fn admission_refuses_when_the_head_config_act_is_unparseable() {
    // Fail-closed arm (design §1c + the fail-loud tenet): a malformed or
    // schema-violating head config act must REFUSE admission, never be read as
    // "capture is off". Silence about the mode is not the same as a recorded OFF.
    let path = unique_temp_db_path("capture-malformed");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        crate::store_open::pin_durability_profile(&conn).unwrap();
        conn.execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES (2, strftime('%s','now'), 'mode_change', ?1);",
            rusqlite::params!["{\n  \"capture\": \"on\"\n}"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES (3, strftime('%s','now'), 'mode_change', ?1);",
            rusqlite::params!["not-json"],
        )
        .unwrap();
    }
    let err = record_basis(&mut log, &archive_cmd("k-capture-malformed"))
        .expect_err("an unparseable head config act must refuse admission");
    let msg = err.0;
    assert!(
        msg.contains("config"),
        "the refusal must name the config act: {msg}"
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM intents WHERE idempotency_key='k-capture-malformed';",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "a refused admission must insert no row");
}

#[test]
fn s1_knob_acts_are_appended_with_generations_and_the_head_act_governs_on_both_stores() {
    use crate::config_knobs::*;
    let path = unique_temp_db_path("knobs");
    for mut log in [Box::new(SqliteIntentLog::open(&path).unwrap()) as Box<dyn IntentLog>, Box::new(InMemoryIntentLog::new())] {
        assert_eq!(log.knob_state().unwrap(), KnobState::defaults());
        let g1 = log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap();
        let g2 = log.record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 10 })).unwrap();
        let g3 = log.record_knob_act(KnobAct::Backups(BackupsKnob::On)).unwrap();
        assert!(g1 < g2 && g2 < g3, "generations are monotonic across kinds — one ledger");
        let s = log.knob_state().unwrap();
        assert_eq!(s.backups, InForce { value: BackupsKnob::On, generation: g3 }, "the HEAD act of the kind governs");
        assert_eq!(s.approval_mode, InForce { value: ApprovalModeKnob::SummarySample { configured_k: 10 }, generation: g2 });
        assert_eq!(s.red_bypass.generation, 0);
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_a_malformed_head_knob_act_refuses_knob_state_on_both_stores_never_the_default() {
    use crate::config_knobs::*;
    // `record_knob_act` re-reads every act through its kind's reader before it stores it
    // (`KnobAct::checked_payload`), so the malformed head enters RAW: a direct INSERT on the
    // durable ledger (the corruption / out-of-band writer shape), the twin's test seam on the
    // mirror. Looped over ALL THREE kinds: the backups-only form left a
    // malformed bypass head falling back to Off unwitnessed.
    let head_of = |s: &KnobState, kind: &str| -> (KnobAct, u64) {
        match kind {
            KIND_APPROVAL_MODE => (KnobAct::ApprovalMode(s.approval_mode.value), s.approval_mode.generation),
            KIND_BACKUPS => (KnobAct::Backups(s.backups.value), s.backups.generation),
            KIND_RED_BYPASS => (KnobAct::RedBypass(s.red_bypass.value), s.red_bypass.generation),
            other => panic!("not a knob kind: {other}"),
        }
    };
    // (kind, a readable act it held before, the malformed head, the repair act)
    let cases: [(&'static str, KnobAct, &str, KnobAct); 3] = [
        (KIND_APPROVAL_MODE, KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 3 }), r#"{"mode":"maybe"}"#, KnobAct::ApprovalMode(ApprovalModeKnob::FullList)),
        (KIND_BACKUPS, KnobAct::Backups(BackupsKnob::Off), r#"{"backups":"maybe"}"#, KnobAct::Backups(BackupsKnob::On)),
        (KIND_RED_BYPASS, KnobAct::RedBypass(RedBypassKnob::On), r#"{"bypass":"maybe"}"#, KnobAct::RedBypass(RedBypassKnob::On)),
    ];
    assert_eq!(cases.map(|(kind, ..)| kind), KNOB_KINDS, "every knob kind, once");
    for (kind, before, malformed, repair) in cases {
        let path = unique_temp_db_path("knobs-malformed");
        let mut sqlite = SqliteIntentLog::open(&path).unwrap();
        sqlite.record_knob_act(before).unwrap();
        raw_conn(&path)
            .execute(
                "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                     VALUES ((SELECT MAX(generation) + 1 FROM engine_config), strftime('%s','now'), ?1, ?2);",
                rusqlite::params![kind, malformed],
            )
            .unwrap();
        let mut twin = InMemoryIntentLog::new();
        twin.record_knob_act(before).unwrap();
        twin.append_raw_knob_act_for_test(kind, malformed);
        for log in [&mut sqlite as &mut dyn IntentLog, &mut twin] {
            let err = log
                .knob_state()
                .expect_err("a malformed HEAD act refuses — never the default, never the older readable act");
            assert!(err.0.contains(&format!("'{kind}'")) && err.0.contains("maybe"), "{kind}: refused BY NAME: {err:?}");
            // The repair is a NEW act: once a readable act heads the kind again, it governs.
            let g = log.record_knob_act(repair).unwrap();
            assert_eq!(head_of(&log.knob_state().unwrap(), kind), (repair, g), "{kind}: the repair act governs");
        }
        drop(sqlite);
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn s1_a_knob_act_its_own_reader_refuses_is_refused_at_set_time_on_both_stores() {
    // (design v7 §3: the approval-mode knob REFUSES a non-positive value
    // at set-time AND plan freeze refuses one defensively). `KnobAct` is typed, but
    // `SummarySample { configured_k: 0 }` is a value the approval-mode reader refuses: stored,
    // it would head the kind as an act nobody can read and refuse every later mint.
    use crate::config_knobs::*;
    let path = unique_temp_db_path("knob-k-zero");
    for mut log in [Box::new(SqliteIntentLog::open(&path).unwrap()) as Box<dyn IntentLog>, Box::new(InMemoryIntentLog::new())] {
        let g = log.record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 3 })).unwrap();
        let err = log
            .record_knob_act(KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 0 }))
            .expect_err("configured_k = 0 is refused at set time");
        assert_eq!(err.0, "record_knob_act: triage_approval_mode: configured_k must be >= 1");
        assert_eq!(
            log.knob_state().unwrap().approval_mode,
            InForce { value: ApprovalModeKnob::SummarySample { configured_k: 3 }, generation: g },
            "the previous act still heads the kind"
        );
        assert_eq!(log.record_knob_act(KnobAct::Backups(BackupsKnob::Off)).unwrap(), g + 1, "the refused act took no generation: nothing was appended");
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_a_knob_act_never_shadows_the_capture_mode_the_admission_reads_bind() {
    // A knob payload restates no `"capture"` (its strict reader refuses any other member), so
    // BOTH capture-mode reads — `record`'s admission read and `record_capacity_config`'s
    // carry-forward — skip the knob kinds. Without that, the first knob act becomes "the
    // latest act that is not a `capacity_activated` pointer", carries no `"capture"`, and
    // every later admission refuses on a missing field.
    use crate::config_knobs::*;
    let path = unique_temp_db_path("knobs-capture");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    for act in [
        KnobAct::Backups(BackupsKnob::Off),
        KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 3 }),
        KnobAct::RedBypass(RedBypassKnob::On),
    ] {
        log.record_knob_act(act).unwrap();
    }
    record_basis(&mut log, &archive_cmd("k-after-knobs")).expect("a knob act never refuses admission");
    log.record_capacity_config(crate::capacity::DEFAULT)
        .expect("…nor the capacity act's capture carry-forward");
    log.record_knob_act(KnobAct::Backups(BackupsKnob::On)).unwrap();
    record_basis(&mut log, &archive_cmd("k-after-capacity")).expect("a knob act past a capacity act admits too");
    let conn = raw_conn(&path);
    let provenance = |key: &str| -> (i64, i64) {
        conn.query_row(
            "SELECT journal_required, capture_mode_generation FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(provenance("k-after-knobs"), (1, 1), "capture binds the first-run act (on, generation 1) — never a knob act");
    let (capacity_generation, capacity_payload): (i64, String) = conn
        .query_row(
            "SELECT generation, payload FROM engine_config WHERE kind = 'capacity' ORDER BY generation DESC LIMIT 1;",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(capacity_payload.starts_with(r#"{"capture":"on","#), "the capacity act restated the capture mode in force: {capacity_payload}");
    assert_eq!(provenance("k-after-capacity"), (1, capacity_generation), "the capacity act governs capture; the knob act after it is skipped");
    drop(conn);
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_an_unknown_config_kind_at_the_ledger_head_refuses_admission_by_name_and_one_below_the_head_is_history() {
    // REWRITTEN. Its C6.0 form
    // (`s1_a_future_config_kind_never_shadows_the_capture_mode_the_admission_reads_bind`)
    // asserted the QUIET behaviour: a kind outside `CAPTURE_KINDS` was skipped by the capture
    // read, so a future kind that DOES restate the capture mode would have been skipped too,
    // without a word — the positive list failed quiet on exactly the kind it cannot know. The
    // capture predicate is now a PARTITION of the kinds this build writes
    // (`ENGINE_CONFIG_KINDS` = `CAPTURE_KINDS` ∪ `capacity_activated` ∪ `KNOB_KINDS`): a kind
    // outside it at the ledger HEAD refuses admission — and the capacity carry-forward, which
    // makes the same read — by name; one BELOW the head is history, and the latest
    // capture-carrying act governs past it.
    let path = unique_temp_db_path("capture-future-kind");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let conn = raw_conn(&path);
    let append = |kind: &str, payload: &str| -> i64 {
        conn.execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES ((SELECT MAX(generation) + 1 FROM engine_config), strftime('%s','now'), ?1, ?2);",
            rusqlite::params![kind, payload],
        )
        .unwrap();
        conn.query_row("SELECT MAX(generation) FROM engine_config;", [], |r| r.get(0)).unwrap()
    };
    let provenance = |key: &str| -> (i64, i64) {
        conn.query_row(
            "SELECT journal_required, capture_mode_generation FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    let intents = || -> i64 { conn.query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0)).unwrap() };
    // A capture:on act the read governs by (the tests' `mode_change` kind), then a kind this
    // build does not know, appended raw after it — the ledger HEAD.
    append("mode_change", r#"{"capture":"on"}"#);
    let future = append("zzz_future", "{}");
    let sentence = |door: &str| {
        format!(
            "{door} refused: engine_config kind 'zzz_future' at generation {future} is not one this build knows — \
             refusing rather than guessing whether it carries the capture mode"
        )
    };
    let err = record_basis(&mut log, &archive_cmd("k-at-future-head")).expect_err("an unknown kind at the head refuses admission");
    assert_eq!(err.0, sentence("admission"));
    assert_eq!(intents(), 0, "nothing admitted");
    let err = log.record_capacity_config(crate::capacity::DEFAULT).expect_err("…and the capacity carry-forward, which makes the same read");
    assert_eq!(err.0, sentence("record_capacity_config"));
    // A capture-carrying act after it: the unknown row is BELOW the head now — history, never
    // a refusal — and the latest capture-carrying act governs past it.
    let off = append("mode_change", r#"{"capture":"off"}"#);
    record_basis(&mut log, &archive_cmd("k-off")).expect("an unknown kind below the head never refuses");
    assert_eq!(provenance("k-off"), (0, off), "the latest capture-carrying act governs, past the unknown kind");
    log.record_capacity_config(crate::capacity::DEFAULT).expect("…nor does the carry-forward refuse on it");
    let (capacity, capacity_payload): (i64, String) = conn
        .query_row("SELECT generation, payload FROM engine_config WHERE kind = 'capacity' ORDER BY generation DESC LIMIT 1;", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert!(capacity_payload.starts_with(r#"{"capture":"off","#), "the capacity act restated the capture mode in force: {capacity_payload}");
    // A KNOWN kind that carries no capture mode at the head (a knob act) is skipped, as C1
    // witnessed: the capacity act still governs.
    log.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    record_basis(&mut log, &archive_cmd("k-after-knob")).expect("a knob act at the head never refuses admission");
    assert_eq!(provenance("k-after-knob"), (0, capacity), "a knob act is skipped by the capture read");
    drop(conn);
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_every_engine_config_writer_s_kind_is_listed_iff_it_carries_capture() {
    // The positive list is derived from the WRITERS, so it is checked against what they
    // write: run every `engine_config` writer this crate has (the first-run act at open,
    // `record_capacity_config`'s capacity act + its activation pointer, the three knob
    // kinds, and the tests' raw `mode_change` act), then require, row by row, that a kind is
    // in `CAPTURE_KINDS` EXACTLY when its payload carries a readable capture mode.
    use crate::config_knobs::*;
    let path = unique_temp_db_path("capture-kinds-writers");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    log.record_capacity_config(crate::capacity::DEFAULT).unwrap();
    for act in [
        KnobAct::Backups(BackupsKnob::Off),
        KnobAct::ApprovalMode(ApprovalModeKnob::SummarySample { configured_k: 3 }),
        KnobAct::RedBypass(RedBypassKnob::On),
    ] {
        log.record_knob_act(act).unwrap();
    }
    append_config_act(&path, r#"{"capture":"off"}"#);
    let conn = raw_conn(&path);
    let rows: Vec<(i64, String, String)> = conn
        .prepare("SELECT generation, kind, payload FROM engine_config ORDER BY generation;")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut kinds_seen = std::collections::BTreeSet::new();
    for (generation, kind, payload) in &rows {
        let carries = capture_mode_is_on(*generation, payload).is_ok();
        assert_eq!(CAPTURE_KINDS.contains(&kind.as_str()), carries, "kind '{kind}' (payload {payload}): listed iff it carries the capture mode");
        kinds_seen.insert(kind.clone());
    }
    for kind in CAPTURE_KINDS {
        assert!(kinds_seen.contains(kind), "every listed kind has a writer: '{kind}' was never written");
    }
    for kind in ["capacity_activated"].iter().chain(KNOB_KINDS.iter()) {
        assert!(kinds_seen.contains(*kind), "the non-carrying writer '{kind}' ran");
        assert!(!CAPTURE_KINDS.contains(kind), "'{kind}' carries no capture mode and is never listed");
    }
    // THE PARTITION: `ENGINE_CONFIG_KINDS` is exactly the kinds these
    // writers produced — every row's kind is in it (so none of them refuses at the head), and
    // every kind in it was written — with no kind twice.
    let known: std::collections::BTreeSet<String> = ENGINE_CONFIG_KINDS.iter().map(|k| k.to_string()).collect();
    assert_eq!(known.len(), ENGINE_CONFIG_KINDS.len(), "no kind is listed twice");
    assert_eq!(known, kinds_seen, "ENGINE_CONFIG_KINDS is the set of kinds this build writes");
    let union: std::collections::BTreeSet<String> = CAPTURE_KINDS.iter().chain(["capacity_activated"].iter()).chain(KNOB_KINDS.iter()).map(|k| k.to_string()).collect();
    assert_eq!(known, union, "…and the union of the three lists");
    drop(conn);
    drop(log);
    std::fs::remove_file(&path).ok();
}
