//! Store open, schema and upgrade, enrollment, the record door, and the open-time integrity scan.

use super::*;
use crate::intent::NATIVE_KEY_EXPR_SQL;
use crate::keys::compensation_key;

#[test]
fn latest_intent_for_message_ref_returns_highest_seq() {
    let path = unique_temp_db_path("latest-intent");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let c1 = Command::new(
        derive_idempotency_key("acct", &Facet::Mail, "first"),
        "acct",
        Facet::Mail,
        Action::Archive {
            message_ref: "m1".into(),
        },
    );
    let c2 = Command::new(
        derive_idempotency_key("acct", &Facet::Mail, "second"),
        "acct",
        Facet::Mail,
        Action::Unarchive {
            message_ref: "m1".into(),
        },
    );
    record_basis(&mut log, &c1).unwrap();
    record_basis(&mut log, &c2).unwrap();
    let latest = log
        .latest_intent_for_message_ref("acct", "m1")
        .unwrap()
        .unwrap();
    assert_eq!(latest.command.idempotency_key, c2.idempotency_key);
    // Terminal vs in-flight classification.
    assert!(!IntentStatus::Pending.is_terminal());
    assert!(IntentStatus::Applied.is_terminal());
    assert!(IntentStatus::Undone.is_terminal());
    assert!(IntentStatus::Failed.is_terminal());
    assert!(!IntentStatus::Undoing.is_terminal());
    assert!(!IntentStatus::EvidenceSnapshotWritten.is_terminal());
    std::fs::remove_file(&path).ok();
}

#[test]
fn optimistic_placement_and_intent_record_are_consistent_across_reopen() {
    // M0 DoD §2 durability: the optimistic projection and its governing intent share one DB,
    // so both survive a drop-and-reopen (process-death analog). NOTE (accepted edge): this
    // proves per-statement durability; whether the optimistic write must join the intent
    // `record()` in a SINGLE transaction (closing the tiny record↔placement crash window) is a
    // boundary the pressure-tests. If they require it, tighten without changing this test.
    let path = unique_temp_db_path("optimistic-consistency");
    {
        let mut log = SqliteIntentLog::open(&path).unwrap();
        let cmd = Command::new(
            derive_idempotency_key("acct", &Facet::Mail, "m1-logical"),
            "acct",
            Facet::Mail,
            Action::Archive {
                message_ref: "m1".into(),
            },
        );
        record_basis(&mut log, &cmd).unwrap();
        let mut store = crate::message_store::SqliteMessageStore::open(&path).unwrap();
        store
            .record_optimistic_placement(
                "acct",
                "m1",
                &crate::read_model::ProviderMessageId("E1".into()),
                crate::read_model::Placement::Archive,
            )
            .unwrap();
    } // drop everything (process-death analog)
    let log = SqliteIntentLog::open(&path).unwrap();
    let store = crate::message_store::SqliteMessageStore::open(&path).unwrap();
    assert!(log
        .latest_intent_for_message_ref("acct", "m1")
        .unwrap()
        .is_some());
    assert_eq!(
        store.placement("acct", "m1").unwrap(),
        Some(crate::read_model::Placement::Archive)
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn message_placement_table_exists_after_open() {
    let path = unique_temp_db_path("placement-table");
    let log = SqliteIntentLog::open(&path).unwrap();
    // The table must exist (querying it must not error).
    let count: i64 = log
        .conn
        .query_row("SELECT COUNT(*) FROM message_placement", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn message_header_schema_exists_after_open_and_version_is_10() {
    let path = unique_temp_db_path("mh-schema");
    let _log = SqliteIntentLog::open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    // table present
    conn.query_row("SELECT COUNT(*) FROM message_header", [], |r| r.get::<_, i64>(0))
        .expect("message_header table must exist");
    // folder index present
    let idx: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_folder'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1, "idx_folder must exist");
    // FTS5 virtual table present + insert trigger indexes the row
    // The column list is EXHAUSTIVE on purpose: `seen`/`flagged` carry DEFAULT 0,
    // so an INSERT that omitted them would keep passing while saying nothing about them —
    // a raw-SQL fixture that quietly stops covering the table it is asserting on.
    conn.execute_batch(
        "INSERT INTO message_header(account,message_ref,mailbox,received_at,from_addr,from_name,subject,seen,flagged)
                 VALUES ('a','m1','Inbox',1,'x@y.z','X','hello world',1,0);",
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT seen, flagged FROM message_header WHERE account='a' AND message_ref='m1';",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        )
        .unwrap(),
        (1, 0),
        "the v9 state columns round-trip through the raw table"
    );
    let hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM message_header_fts WHERE message_header_fts MATCH 'hello'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hits, 1, "FTS insert trigger must index the row");
    // version bumped (stamped into PRAGMA user_version)
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 10, "SCHEMA_VERSION must be 10 (#75 S1: triage_plan / plan_member / approval_evidence / commitment_key_registry + the effect-witness columns)");
    std::fs::remove_file(&path).ok();
}

#[test]
fn schema_version_is_pinned_with_rationale() {
    // The plan/approval tables (`triage_plan`, `plan_member`,
    // `approval_evidence`) + the commitment key registry + the effect-witness columns. v8
    // stays the upgradable floor; a v9 store upgrades in place (the tables are new, so
    // `CREATE TABLE IF NOT EXISTS` creates them whole inside the open's one transaction).
    assert_eq!(
        SCHEMA_VERSION, 10,
        "SCHEMA_VERSION must be 10 (#75 S1: triage_plan / plan_member / approval_evidence / commitment_key_registry + the effect-witness columns)"
    );
}

#[test]
fn s1_the_plan_tables_exist_are_append_only_and_a_v9_store_upgrades_in_one_transaction() {
    let path = unique_temp_db_path("s1-tables");
    let log = SqliteIntentLog::open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    for table in ["triage_plan", "plan_member", "approval_evidence"] {
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1", [table], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "{table}");
    }
    let v: i64 = conn.query_row("PRAGMA user_version;", [], |r| r.get(0)).unwrap();
    assert_eq!(v, 10);
    drop(log);
    const PLAN_COLUMNS: &str = "plan_id, account, provider_principal, grant_generation, control_epoch, verb, tier, minted_at, expires_at, member_count, admission_lane, approval_mode, coverage_generation, backups_on, set_digest, set_randomizer, state_digest, state_randomizer, presentation_digest, presentation_randomizer, shape_digest, shape_randomizer, sample_seed, sample_seed_randomizer, aggregate_view_randomizer, key_ref_namespace, key_ref_epoch";
    let plan_row = |plan_id: &str, verb: &str, tier: &str| format!("INSERT INTO triage_plan ({PLAN_COLUMNS}) VALUES ('{plan_id}','a','pr',1,1,'{verb}','{tier}','t','t2',1,'per_member','full_list',0,1,'s','r','s','r','s','r','s','r','s','r','r','ns',1)");
    conn.execute_batch(&plan_row("p", "trash", "red")).unwrap();
    // Append-only: UPDATE/DELETE on triage_plan are refused by trigger…
    assert!(conn.execute("UPDATE triage_plan SET rationale='x' WHERE plan_id='p'", []).is_err());
    assert!(conn.execute("DELETE FROM triage_plan WHERE plan_id='p'", []).is_err());
    // …and so is a REPLACE (its implicit DELETE fires no delete trigger under the default
    // recursive_triggers=off — the `commitment_key_registry_no_replace` class).
    assert!(conn.execute_batch(&plan_row("p", "mark_spam", "red").replacen("INSERT INTO", "INSERT OR REPLACE INTO", 1)).is_err(), "INSERT OR REPLACE cannot rewrite a plan row");
    let verb: String = conn.query_row("SELECT verb FROM triage_plan WHERE plan_id='p'", [], |r| r.get(0)).unwrap();
    assert_eq!(verb, "trash", "the plan row is untouched");
    // Closed CHECK vocabularies.
    assert!(conn.execute_batch(&plan_row("q", "delete", "red")).is_err(), "the verb CHECK refuses anything outside the closed set");
    assert!(conn.execute_batch(&plan_row("q", "trash", "yellow")).is_err(), "the tier CHECK admits RED only");
    // plan_member: append-only, REPLACE-proof, bounded by the plan's frozen member count.
    let member = |r: &str, subject: &str| format!("INSERT INTO plan_member (plan_id, message_ref, sender, subject, date, size, observed_state, forward_target) VALUES ('p','{r}','s','{subject}','d',NULL,'{{}}','{{}}')");
    conn.execute_batch(&member("m1", "one")).unwrap();
    assert!(conn.execute("UPDATE plan_member SET subject='x' WHERE plan_id='p'", []).is_err());
    assert!(conn.execute("DELETE FROM plan_member WHERE plan_id='p'", []).is_err());
    assert!(conn.execute_batch(&member("m1", "forged").replacen("INSERT INTO", "INSERT OR REPLACE INTO", 1)).is_err(), "INSERT OR REPLACE cannot rewrite a member row");
    assert!(conn.execute_batch(&member("m2", "appended")).is_err(), "a member beyond the plan's frozen member_count is refused — a minted plan is never edited");
    // approval_evidence: FK to a real plan, closed decision + comprehension, append-only.
    let evidence = |plan_id: &str, decision: &str, comprehension: &str| format!("INSERT INTO approval_evidence (plan_id, approver, approved_at, decision, view_digest, comprehension) VALUES ('{plan_id}','c','t','{decision}','v','{comprehension}')");
    assert!(conn.execute_batch(&evidence("nope", "approved", "per_member")).is_err(), "evidence names a stored plan (FK)");
    assert!(conn.execute_batch(&evidence("p", "refused", "per_member")).is_err(), "the only decision is 'approved'");
    assert!(conn.execute_batch(&evidence("p", "approved", "vibes")).is_err(), "the comprehension CHECK is closed");
    conn.execute_batch(&evidence("p", "approved", "per_member")).unwrap();
    assert!(conn.execute("UPDATE approval_evidence SET approver='x' WHERE plan_id='p'", []).is_err());
    assert!(conn.execute("DELETE FROM approval_evidence WHERE plan_id='p'", []).is_err());
    assert!(conn.execute_batch(&evidence("p", "approved", "bypassed").replacen("INSERT INTO", "INSERT OR REPLACE INTO", 1)).is_err(), "INSERT OR REPLACE cannot rewrite the evidence");
    drop(conn);

    // A v9 store: the three tables absent, stamped 9.
    let shrink_to_v9 = |path: &std::path::Path| {
        let conn = raw_conn(path);
        conn.execute_batch("PRAGMA foreign_keys=OFF; BEGIN; DROP TABLE approval_evidence; DROP TABLE plan_member; DROP TABLE triage_plan; COMMIT;").unwrap();
        conn.pragma_update(None, "user_version", 9i64).unwrap();
    };
    let v9 = unique_temp_db_path("s1-tables-v9");
    drop(SqliteIntentLog::open(&v9).unwrap());
    shrink_to_v9(&v9);
    let table_count = |path: &std::path::Path| -> i64 {
        raw_conn(path)
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('triage_plan','plan_member','approval_evidence')", [], |r| r.get(0))
            .unwrap()
    };
    let version = |path: &std::path::Path| -> i64 { raw_conn(path).query_row("PRAGMA user_version;", [], |r| r.get(0)).unwrap() };
    assert_eq!((table_count(&v9), version(&v9)), (0, 9), "precondition: a v9-shaped store");
    // ONE transaction: an upgrade that fails part-way (a planted index squats the LAST new
    // table's name, so `triage_plan` and `plan_member` are created first and then the batch
    // aborts) leaves the store exactly v9 — no half-created table, no stamp.
    raw_conn(&v9).execute_batch("CREATE INDEX approval_evidence ON engine_config(kind);").unwrap();
    let err = SqliteIntentLog::open(&v9).err().expect("the squatted name aborts the upgrade");
    assert!(err.to_string().contains("approval_evidence"), "the refusal names the object: {err}");
    assert_eq!((table_count(&v9), version(&v9)), (0, 9), "the aborted upgrade left no table and no stamp");
    raw_conn(&v9).execute_batch("DROP INDEX approval_evidence;").unwrap();
    drop(SqliteIntentLog::open(&v9).expect("a v9 store OPENS under a v10 binary"));
    assert_eq!((table_count(&v9), version(&v9)), (3, 10), "the upgrade created the three tables and stamped v10");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&v9).ok();
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Store v9: the FLAGS columns and the identity inverse.
//
// Three witnesses, one shape: (1) what a FRESH v9 store carries, (2) that a real v8
// store reaches that same shape THROUGH the open-time upgrade, and (3) that the
// upgrade refuses — loudly, by name — rather than choosing which of two legacy
// placement rows sharing a provider identity gets to survive the new UNIQUE index.
// ═══════════════════════════════════════════════════════════════════════════════════

/// Reduce a freshly minted store to the shape a **v8** binary created and stamp it v8:
/// `message_header` WITHOUT `seen`/`flagged` (nor `ingest_revision`, the
/// accretion that arrived after them, nor `from_status`/`from_domain`, the
/// accretion after that), no `ingest_revision_seq` and none of its bump
/// triggers (the accretion after THAT), and no `(account, email_id)` identity
/// inverse on `message_placement`. The same discipline as
/// `shrink_pre_state_to_main_shape` — the witness is about a REAL prior population, not
/// a synthetic mutation.
///
/// Dropped in REVERSE declaration order, so what is left is a genuine prefix of the v9
/// table and the upgrade's own ALTERs re-append them in `IN_VERSION_COLUMN_UPGRADES` order
/// — column ORDER is part of the fingerprint this witness compares, and a v8 store that
/// somehow kept a later column would not be a v8 store.
///
/// The revision triggers come off FIRST and are not optional bookkeeping: they name
/// `NEW.ingest_revision`, and SQLite validates a trigger body against the post-ALTER table
/// at `DROP COLUMN` time ("error in trigger … after drop column: no such column"). A v8
/// store never had them, so dropping them is the faithful shape AND the thing that makes
/// the column drop legal.
fn shrink_store_to_v8_shape(path: &std::path::Path) {
    let conn = raw_conn(path);
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF;
             BEGIN;
             DROP INDEX IF EXISTS idx_message_placement_identity;
             DROP TRIGGER IF EXISTS message_header_ingest_revision_au;
             DROP TRIGGER IF EXISTS message_header_ingest_revision_ai;
             DROP TABLE IF EXISTS ingest_revision_seq;
             ALTER TABLE message_header DROP COLUMN from_domain;
             ALTER TABLE message_header DROP COLUMN from_status;
             ALTER TABLE message_header DROP COLUMN ingest_revision;
             ALTER TABLE message_header DROP COLUMN flagged;
             ALTER TABLE message_header DROP COLUMN seen;
             COMMIT;",
    )
    .expect("rebuild the store in v8's shape");
    conn.pragma_update(None, "user_version", 8i64)
        .expect("stamp v8");
}

#[test]
fn v9_fresh_store_carries_the_flag_columns_and_the_identity_inverse() {
    // §2 S1 FLAGS + IDENTITY, at the fresh-bootstrap door.
    let path = unique_temp_db_path("v9-fresh-shape");
    drop(SqliteIntentLog::open(&path).expect("mint the store"));
    let conn = raw_conn(&path);

    for column in ["seen", "flagged"] {
        let (ty, notnull, dflt): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT type, \"notnull\", dflt_value FROM pragma_table_info('message_header')
                      WHERE name = ?1;",
                [column],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap_or_else(|e| panic!("message_header must carry `{column}`: {e}"));
        assert_eq!(
            (ty.as_str(), notnull, dflt.as_deref()),
            ("INTEGER", 1, Some("0")),
            "`{column}` must be INTEGER NOT NULL DEFAULT 0"
        );
    }

    let (uniq, partial): (i64, i64) = conn
        .query_row(
            "SELECT \"unique\", partial FROM pragma_index_list('message_placement')
                  WHERE name = 'idx_message_placement_identity';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the identity inverse index must exist on message_placement");
    assert_eq!(
        (uniq, partial),
        (1, 0),
        "the identity inverse must be a TOTAL UNIQUE index — a duplicate mint has to be \
         impossible, not merely unlikely"
    );
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_index_info('idx_message_placement_identity') ORDER BY seqno;")
        .expect("index_info prepare")
        .query_map([], |r| r.get::<_, String>(0))
        .expect("index_info query")
        .map(|r| r.expect("index_info row"))
        .collect();
    assert_eq!(cols, vec!["account", "email_id"]);
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_v8_store_upgrades_in_place_to_a_schema_equal_to_a_fresh_v9_store() {
    // The in-place upgrade contract: a legitimate v8 store is not refused and not
    // silently half-migrated — it OPENS, and what it carries afterwards is what a store
    // this binary minted from nothing carries. Same discipline as
    // `a_main_shaped_v8_store_is_upgraded_in_place_at_open`, widened from
    // one column to the whole schema.
    let fresh = unique_temp_db_path("v9-equiv-fresh");
    drop(SqliteIntentLog::open(&fresh).expect("mint a fresh v9 store"));
    let want = schema_fingerprint(&fresh);

    let upgraded = unique_temp_db_path("v9-equiv-upgraded");
    drop(SqliteIntentLog::open(&upgraded).expect("mint the store"));
    shrink_store_to_v8_shape(&upgraded);
    assert_ne!(
        schema_fingerprint(&upgraded),
        want,
        "precondition: the v8-shaped store must actually differ before the upgrade"
    );
    assert_eq!(
        raw_conn(&upgraded)
            .query_row("PRAGMA user_version;", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        8,
        "precondition: the store is stamped v8"
    );

    drop(SqliteIntentLog::open(&upgraded).expect("a v8 store must OPEN under a v9 binary"));

    assert_eq!(
        schema_fingerprint(&upgraded),
        want,
        "an upgraded v8 store must end up schema-identical to a fresh v9 store"
    );
    std::fs::remove_file(&fresh).ok();
    std::fs::remove_file(&upgraded).ok();
}

/// THE RED for a v8 store's DISPLAY headers predate the normalization
/// chokepoint, and the v9 upgrade left them exactly as the provider wrote them.
///
/// `normalize_display` (`crate::header_normalize`) landed WITH the read side, so every
/// header row a v8 binary wrote went in unnormalized: a `U+202E` RIGHT-TO-LEFT OVERRIDE in a
/// subject, a CR/LF-injected fake chrome line in a display name. Adding the columns and
/// stamping v9 changed nothing about those bytes, so the FIRST thing an upgraded store renders
/// is the payload the chokepoint exists to strip — the chokepoint only ever guarded rows
/// arriving AFTER it. The migration therefore has to carry the existing population across too,
/// through the SAME function (never a second normalizer), on `from_name` + `subject` ONLY:
/// `from_addr` is identity bytes and must round-trip verbatim (`header_normalize`'s module doc).
#[test]
fn a_v8_stores_legacy_display_headers_are_normalized_by_the_upgrade() {
    let path = unique_temp_db_path("v9-legacy-header-normalize");
    drop(SqliteIntentLog::open(&path).expect("mint the store"));
    shrink_store_to_v8_shape(&path);
    {
        let conn = raw_conn(&path);
        let mut stmt = conn
            .prepare(
                "INSERT INTO message_header
                        (account, message_ref, mailbox, received_at, from_addr, from_name, subject)
                      VALUES (?1, ?2, 'Inbox', ?3, ?4, ?5, ?6);",
            )
            .expect("prepare the legacy insert");
        // A v8 row carrying exactly what the chokepoint would have stripped.
        stmt.execute(rusqlite::params![
            "acct",
            "m-bidi",
            1_000i64,
            // The ADDRESS carries a hostile-looking byte too — and it must survive UNTOUCHED.
            "we\u{202E}ird@example.com",
            "Pay\u{202E}roll",
            "invoice\u{202E}fdp.exe",
        ])
        .expect("seed the bidi row");
        stmt.execute(rusqlite::params![
            "acct",
            "m-crlf",
            900i64,
            "ann@example.com",
            "Ann\u{200D}ounce",
            "Payroll\r\n-- Photon: sender verified --",
        ])
        .expect("seed the newline-injected row");
        // A row that is ALREADY clean: the migration must leave it byte-identical.
        stmt.execute(rusqlite::params![
            "acct",
            "m-clean",
            800i64,
            "ok@example.com",
            "Grüße aus München",
            "日本語の件名",
        ])
        .expect("seed the clean row");
    }

    drop(SqliteIntentLog::open(&path).expect("a v8 store must OPEN under a v9 binary"));

    let conn = raw_conn(&path);
    let row = |message_ref: &str| -> (String, String, String) {
        conn.query_row(
            "SELECT from_addr, from_name, subject FROM message_header
                  WHERE account = 'acct' AND message_ref = ?1;",
            [message_ref],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_else(|e| panic!("read {message_ref}: {e}"))
    };

    let (addr, name, subject) = row("m-bidi");
    assert_eq!(
        subject, "invoicefdp.exe",
        "the persisted RIGHT-TO-LEFT OVERRIDE must be stripped by the upgrade, not rendered"
    );
    assert_eq!(name, "Payroll");
    assert_eq!(
        addr, "we\u{202E}ird@example.com",
        "from_addr is IDENTITY: the migration must not route it through normalize_display"
    );

    let (_, name, subject) = row("m-crlf");
    assert_eq!(subject, "Payroll -- Photon: sender verified --");
    assert_eq!(name, "Announce");

    let (addr, name, subject) = row("m-clean");
    assert_eq!(
        (addr.as_str(), name.as_str(), subject.as_str()),
        ("ok@example.com", "Grüße aus München", "日本語の件名"),
        "an already-clean row is left byte-identical"
    );

    // The FTS index rides the UPDATE trigger, so the normalized text is what search sees —
    // never the stripped-out original left behind in the external-content index.
    let hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM message_header_fts WHERE message_header_fts MATCH 'invoicefdp';",
            [],
            |r| r.get(0),
        )
        .expect("fts read");
    assert_eq!(hits, 1, "the FTS row follows the normalized subject");

    drop(conn);
    std::fs::remove_file(&path).ok();
}

/// THE RED for — the v9 duplicate-identity pre-scan is an UPGRADE guard, and it
/// was running on EVERY open.
///
/// It is a full `GROUP BY account, email_id` aggregate over `message_placement`, and on a
/// store already stamped v9 it can only ever answer "none": the v9 DDL created
/// `idx_message_placement_identity` UNIQUE in the same transaction that stamped the version,
/// so a colliding pair is structurally impossible while that index stands. Every open of a
/// large mailbox therefore paid a full scan of the placement table to prove a constraint SQLite
/// is already enforcing. Guarding it on `current < SCHEMA_VERSION` is what makes it a
/// migration step.
///
/// The witness has to poison the store out of band — drop the index, insert the pair — because
/// that is the only way a v9 store can hold one at all. Pre-fix the scan finds it and refuses
/// by name; post-fix the scan never runs. (What the reopen then does with a hand-edited store
/// is not this test's claim, and is not asserted: it is the DDL's index rebuild meeting bad
/// data, an intact-store impossibility.)
#[test]
fn the_v9_duplicate_identity_scan_is_an_upgrade_step_not_an_every_open_scan() {
    let path = unique_temp_db_path("v9-scan-upgrade-only");
    drop(SqliteIntentLog::open(&path).expect("mint a v9 store"));
    {
        let conn = raw_conn(&path);
        assert_eq!(
            conn.query_row("PRAGMA user_version;", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION,
            "the store under test is already at the current version"
        );
        // OUT OF BAND: on an intact v9 store the UNIQUE index makes this pair impossible.
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_message_placement_identity;
                 INSERT INTO message_placement (account, message_ref, email_id, placement)
                     VALUES ('acct', 'm-first', 'E-COLLIDE', 'Inbox'),
                            ('acct', 'm-second', 'E-COLLIDE', 'Archive');",
        )
        .expect("poison the store by hand");
    }

    let text = match SqliteIntentLog::open(&path) {
        Err(e) => format!("{e}"),
        Ok(_) => String::new(),
    };
    assert!(
        !text.contains("DUPLICATE-PLACEMENT-IDENTITY"),
        "the migration pre-scan must not run on a store already stamped v{SCHEMA_VERSION} — \
         it is an upgrade step, not a per-open audit: {text}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn a_v8_store_with_duplicate_placement_identity_refuses_the_upgrade_by_name() {
    // The legacy-data hazard the UNIQUE index creates: v8 had no `(account, email_id)`
    // constraint, so a real store CAN hold two refs pointing at one provider message.
    // Creating the index over that population would either abort inside `CREATE UNIQUE
    // INDEX` with a bare SQLite constraint string, or tempt a dedupe that silently
    // decides which of the operator's rows is the real one. Neither is acceptable: the
    // upgrade REFUSES, by name, with the colliding identity in the message, and leaves
    // the data exactly as it found it.
    let path = unique_temp_db_path("v9-dup-identity");
    drop(SqliteIntentLog::open(&path).expect("mint the store"));
    shrink_store_to_v8_shape(&path);
    {
        let conn = raw_conn(&path);
        conn.execute_batch(
            "INSERT INTO message_placement (account, message_ref, email_id, placement)
                     VALUES ('acct', 'm-first', 'E-COLLIDE', 'Inbox'),
                            ('acct', 'm-second', 'E-COLLIDE', 'Archive'),
                            ('acct', 'm-other', 'E-FINE', 'Inbox');",
        )
        .expect("seed the legacy duplicate");
    }

    let text = match SqliteIntentLog::open(&path) {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("a duplicated placement identity must refuse the upgrade"),
    };
    assert!(
        text.contains("DUPLICATE-PLACEMENT-IDENTITY"),
        "the refusal must be NAMED, not a bare constraint failure: {text}"
    );
    assert!(
        text.contains("E-COLLIDE") && text.contains("acct"),
        "the refusal must name the colliding identity so an operator can act on it: {text}"
    );
    assert!(
        !text.contains("UNIQUE constraint failed"),
        "the pre-scan must refuse BEFORE the index build, not surface SQLite's raw \
         constraint error: {text}"
    );

    // Nothing was deduped, nothing was stamped forward.
    let conn = raw_conn(&path);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM message_placement;", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3,
        "a refused upgrade never deletes the operator's rows"
    );
    assert_eq!(
        conn.query_row("PRAGMA user_version;", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        8,
        "a refused upgrade never stamps the newer version"
    );
    drop(conn);
    std::fs::remove_file(&path).ok();
}

#[test]
fn recording_a_command_yields_a_pending_intent() {
    let mut log = InMemoryIntentLog::new();
    let cmd = archive_cmd("k1");

    record_basis(&mut log, &cmd).expect("record should succeed");

    let intent = log
        .get("k1")
        .expect("get should succeed")
        .expect("intent should exist after record");
    assert_eq!(intent.status, IntentStatus::Pending);
    assert_eq!(intent.command, cmd);
}

#[test]
fn a_command_carries_a_reserved_empty_action_envelope() {
    // D6.1: the command bus carries the ActionEnvelope shape from line one —
    // reserved (all None) until the moat pass, but present so governance attaches
    // without a spine transplant.
    let cmd = archive_cmd("k1");

    assert_eq!(cmd.envelope, ActionEnvelope::default());
    assert!(cmd.envelope.principal.is_none());
    assert!(cmd.envelope.epoch.is_none());
    assert!(cmd.envelope.evidence_ref.is_none());
    assert!(cmd.envelope.tier.is_none());
}

#[test]
fn sqlite_intent_log_persists_an_intent_across_reopen() {
    // Store-first: the durable intent log must survive process restart — the
    // property that justifies M0 existing. Crash-recovery depends on it.
    let path = unique_temp_db_path("persist-reopen");
    let cmd = archive_cmd("k1");

    {
        let mut log = SqliteIntentLog::open(&path).expect("open log");
        record_basis(&mut log, &cmd).expect("record should succeed");
    } // dropped → connection closed, like a process restart

    let log = SqliteIntentLog::open(&path).expect("reopen log");
    let intent = log
        .get("k1")
        .expect("get should succeed")
        .expect("intent survives reopen");
    assert_eq!(intent.status, IntentStatus::Pending);
    assert_eq!(intent.command, cmd);

    std::fs::remove_file(&path).ok();
}

#[test]
fn sqlite_intent_log_round_trips_a_reserved_envelope() {
    // The ActionEnvelope must be reserved in the SQLite SCHEMA, not just the
    // struct — else populating it at the moat pass is a log migration. M0 never sets these
    // fields, but the schema must carry them so they round-trip.
    let path = unique_temp_db_path("envelope-roundtrip");
    let mut cmd = archive_cmd("k1");
    cmd.envelope = ActionEnvelope {
        principal: Some("user:clinton".into()),
        epoch: Some(7),
        evidence_ref: Some("ev-123".into()),
        snapshot_ref: Some("snap-123".into()),
        tier: Some("isolated".into()),
    };

    {
        let mut log = SqliteIntentLog::open(&path).expect("open");
        record_basis(&mut log, &cmd).expect("record should succeed");
    }
    let log = SqliteIntentLog::open(&path).expect("reopen");
    let intent = log
        .get("k1")
        .expect("get should succeed")
        .expect("intent survives");

    assert_eq!(intent.command.envelope, cmd.envelope);
    std::fs::remove_file(&path).ok();
}

#[test]
fn intents_carry_a_monotonic_durable_sequence() {
    // Crash-atomic durable mutation: replay needs a durable monotonic order
    // axis (separate from the idempotency-key PK), else recover replays in undefined
    // order and non-commutative mutations can re-apply reversed.
    let path = unique_temp_db_path("durable-seq");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    record_basis(&mut log, &archive_cmd("k1")).expect("r1");
    record_basis(&mut log, &Command::new(
        "k2",
        "acct-1",
        Facet::Mail,
        Action::Unarchive { message_ref: "m".into() },
    ))
    .expect("r2");

    let first = log.get("k1").expect("get").expect("k1").seq;
    let second = log.get("k2").expect("get").expect("k2").seq;

    assert!(first < second, "a later record gets a higher durable sequence");
    std::fs::remove_file(&path).ok();
}

#[test]
fn get_returns_log_error_on_a_corrupt_status_row_not_panic() {
    // A corrupt/unknown stored enum must surface as LogError via the fallible
    // API, not unwind the process — one bad durable row can't crash startup/recovery.
    let path = unique_temp_db_path("corrupt-status");
    SqliteIntentLog::open(&path).expect("open creates schema");

    let conn = rusqlite::Connection::open(&path).expect("raw open");
    conn.execute(
        // A hand-seeded row must supply the admission-binding columns
        // `record()` now binds — they are NOT NULL by DDL. The corruption under test is
        // the STATUS token, not the binding.
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref, status, seq,
                                  intent_id, kind, journal_required, capture_mode_generation,
                                  admitted_control_epoch, frozen_basis)
             VALUES ('k1', 'acct-1', 'mail', 'archive', 'msg-1', 'BOGUS_STATUS', 1,
                     '00000000000000000000000000000001', 'forward', 1, 1, 1,
                     '{\"native_resource_key\":\"test:msg-1\",\"touched_atoms\":{\"membership:INBOX\":\"INBOX\"},\"freshness\":\"immutable_constants\"}');",
        [],
    )
    .expect("inject corrupt row");
    drop(conn);

    let log = SqliteIntentLog::open(&path).expect("reopen");
    let result = log.get("k1");

    assert!(
        matches!(result, Err(LogError(_))),
        "corrupt status must surface as LogError, got {result:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_refuses_a_pre_v8_database_without_mutating_it() {
    // Stage 1, design §7a SCHEMA-V8-CUTOVER-CONTRACT (Option A): the v7 contract
    // auto-stamped an older pre-release DB to the current SCHEMA_VERSION. That behavior is
    // DELETED — a v8 binary REFUSES any pre-v8 store with an operator-visible reset message
    // and mutates nothing (not one byte of the main file, not one sidecar).
    let path = unique_temp_db_path("prev8-refused");
    // Hand-build a v7-shaped store: real SQLite file, user_version=7, application_id
    // unstamped (0) — exactly what every real baseline v7 store looks like (design §7a:
    // SqliteIntentLog::open never stamped application_id).
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE intents (idempotency_key TEXT PRIMARY KEY);")
            .unwrap();
        conn.pragma_update(None, "user_version", 7).unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    // (`unwrap_err` is unavailable: SqliteIntentLog is deliberately not Debug — a Debug
    // impl over a live Connection is API surface this stage does not want.)
    let err = match SqliteIntentLog::open(&path) {
        Ok(_) => panic!("a pre-v8 store must be refused, not opened"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("pre-v8"), "refusal must name the class: {msg}");
    assert!(msg.contains("reset"), "refusal must name the reset/export path: {msg}");
    let after = std::fs::read(&path).unwrap();
    assert_eq!(before, after, "a refused open must be byte-stable");
    for ext in ["-wal", "-shm", "-journal"] {
        assert!(
            !std::path::Path::new(&format!("{}{ext}", path.display())).exists(),
            "a refused open must not mint a {ext} sidecar"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn record_binds_admission_provenance_columns() {
    // Design §1c MODE-GENERATION-BOUND-TO-INTENT: journal_required +
    // capture_mode_generation + admitted_control_epoch are bound AT ADMISSION, in the
    // admission transaction, as PROVENANCE; `intent_id` is the opaque operation identity.
    let path = unique_temp_db_path("admission");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let cmd = Command::new(
        "k-admission-1",
        "acct",
        Facet::Mail,
        Action::Archive {
            message_ref: "m-1".into(),
        },
    );
    record_basis(&mut log, &cmd).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (intent_id, kind, jr, cmg, ace): (String, String, i64, i64, i64) = conn
        .query_row(
            "SELECT intent_id, kind, journal_required, capture_mode_generation,
                        admitted_control_epoch
                 FROM intents WHERE idempotency_key='k-admission-1';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(intent_id.len(), 32, "opaque 16-byte hex id, got '{intent_id}'");
    assert!(intent_id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(kind, "forward");
    assert_eq!(
        jr, 1,
        "generation-1 capture mode is ON (first-run act) ⇒ journal_required=1"
    );
    assert_eq!(cmg, 1);
    assert_eq!(ace, 1);
}

#[test]
fn an_authority_encoded_native_key_survives_the_sqlite_native_lane() {
    // follow-through: the injective encoding embeds QUOTES and
    // BACKSLASHES, and the durable native lane reads the key back out of a JSON column
    // (`json_extract(frozen_basis, '$.native_resource_key')`) through an EXPRESSION INDEX.
    // So the escaping has to survive two nestings and still compare equal to the raw bind
    // param — otherwise the ordering key silently stops matching and every intent looks
    // like it is at head. Components chosen to be exactly the ones a separator-join
    // conflated.
    let path = unique_temp_db_path("encoded-key-native-lane");
    let key = prestate::native_resource_key("prov", &["a\"b\\", "c/d"]);
    let other = prestate::native_resource_key("prov", &["a\"b", "\\c/d"]);
    assert_ne!(key, other, "precondition: the two component splits differ");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    log.record(
        &Command::new(
            "k-encoded",
            "acct-1",
            Facet::Mail,
            Action::Archive {
                message_ref: "ref-a".into(),
            },
        ),
        &test_basis(&key),
    )
    .expect("record");
    assert!(
        log.has_non_terminal_native_predecessor(&key, "ref-z", "acct-9", u64::MAX, "k-other")
            .expect("predicate"),
        "the escaped native key must match itself through json_extract + the expression index"
    );
    assert!(
        !log.has_non_terminal_native_predecessor(&other, "ref-z", "acct-9", u64::MAX, "k-other")
            .expect("predicate"),
        "a DIFFERENT component split must not match — that is the whole injectivity point"
    );
    drop(log);
    std::fs::remove_file(&path).ok();
}

#[test]
fn record_freezes_the_native_basis_in_the_admission_transaction() {
    // BASIS-5: ONE admission transaction atomically mints the operation AND freezes the
    // native basis (+ freshness provenance) into frozen_basis. Immutable thereafter.
    let path = unique_temp_db_path("freeze-basis");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let cmd = archive_cmd("k-fb-1");
    let basis = test_basis("prov:acct/native-9");
    log.record(&cmd, &basis).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let stored: String = conn
        .query_row(
            "SELECT frozen_basis FROM intents WHERE idempotency_key='k-fb-1';",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let parsed = prestate::FrozenBasis::from_json(&stored).unwrap();
    assert_eq!(parsed, basis, "the stored basis round-trips exactly");
    // …and it is READ BACK onto the intent, beside the §1c admission provenance the same
    // transaction bound (generation-1 capture is ON ⇒ this operation owes a journal row).
    let intent = log.get("k-fb-1").unwrap().unwrap();
    assert_eq!(intent.frozen_basis, Some(basis));
    assert!(intent.journal_required);
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_bootstraps_fresh_and_reopens_verified() {
    let path = unique_temp_db_path("version-roundtrip");
    {
        let _log = SqliteIntentLog::open(&path).unwrap();
    } // fresh bootstrap
    {
        let _log = SqliteIntentLog::open(&path).unwrap();
    } // verified reopen
    let conn = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    let a: i64 = conn
        .query_row("PRAGMA application_id;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, SCHEMA_VERSION);
    assert_eq!(a as u32, crate::store_open::APPLICATION_ID);
    // reopen did NOT append a second first-run act
    let acts: i64 = conn
        .query_row("SELECT COUNT(*) FROM engine_config;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(acts, 1);
}

// ─────────────────────────────────────────────────────────────────────────
// THE ENROLLED WRITE DOOR + THE PREFLIGHT LOCK LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn enrollment_spans_the_transaction_not_the_statement() {
    // design §5.3, made STRUCTURAL (the 261 ms probe class): an enrolled write
    // holds the gate from before `BEGIN IMMEDIATE` until after the commit — not merely
    // around one statement. The RED this witness was written against is one line: release
    // the `WriteScope` right after `enroll()` and run the transaction outside it. Nothing
    // else in the suite notices; this does.
    //
    // TIMING-FREE: the pause is a `Barrier` rendezvous INSIDE the transaction, so when the
    // main thread proceeds, the transaction is provably open. The second thread's parking
    // is read off the gate's own `enroll_waiters`, not off a clock.
    use std::sync::atomic::{AtomicBool, Ordering};
    let path = unique_temp_db_path("enrollment-spans-txn");
    let mut log = SqliteIntentLog::open(&path).expect("bootstrap + open");

    // A SECOND handle on the same FILE IDENTITY: the registry keys on the file, so this
    // observes the very arbiter the log's own connection enrolls in.
    let observer = std::sync::Arc::new(
        crate::writer_gate::WriterGate::for_path(&path).expect("identity is obtainable"),
    );
    assert!(
        !observer.snapshot().expect("snapshot").active_writer,
        "no writer is enrolled before the transaction starts"
    );

    let paused = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(AtomicBool::new(false));

    let writer = {
        let (paused, release) = (std::sync::Arc::clone(&paused), std::sync::Arc::clone(&release));
        std::thread::spawn(move || {
            log.with_immediate_tx(|tx| {
                // A real write, so this is a transaction the arbiter must be spanning.
                tx.execute(
                    "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                         VALUES ((SELECT MAX(generation) + 1 FROM engine_config),
                                 strftime('%s','now'), 'capture', '{\"capture\":\"on\"}');",
                    [],
                )
                .map_err(|e| LogError(format!("witness write: {e}")))?;
                paused.wait(); // ── the transaction is OPEN from here ──
                while !release.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                Ok(())
            })
            .expect("the paused transaction commits");
            log
        })
    };

    paused.wait();
    // ── THE WITNESS ── the transaction is open and paused; the gate still reports a live
    // writer. With enrollment scoped to the statement, this is `false`.
    assert!(
        observer.snapshot().expect("snapshot").active_writer,
        "the gate must report an ACTIVE WRITER for the whole span of an enrolled \
         transaction — enrollment brackets the transaction, not a statement"
    );

    // …and the consequence that matters: a second writer CANNOT enroll while it is open.
    let contender = {
        let observer = std::sync::Arc::clone(&observer);
        std::thread::spawn(move || {
            let scope = observer.enroll().expect("the contender eventually enrolls");
            drop(scope);
        })
    };
    // The contender is PARKED (gate state, no clock). Under the statement-scoped RED it
    // enrolls straight through and this never becomes true — the hang guard then reports
    // exactly that.
    t6a_spin_until("the contender parks behind the open transaction", || {
        observer.snapshot().expect("snapshot").enroll_waiters == 1
    });

    release.store(true, Ordering::SeqCst);
    let log = writer.join().expect("writer thread");
    contender.join().expect("contender thread");
    assert!(
        !observer.snapshot().expect("snapshot").active_writer,
        "the scope is released once the transaction is torn down"
    );
    drop(log);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn every_open_of_one_identity_reuses_the_retained_header_descriptor() {
    // THE PREFLIGHT LOCK LIFECYCLE, primary realization: ONE registry-owned
    // descriptor per identity, opened once and REUSED with positioned reads. The oracle is
    // the keeper's own `File::open` count for this identity — production's number, not a
    // proxy: TWO full opens (each of which runs the preflight, and the first of which runs
    // it up to TWICE through the lost-race loop) must leave it at exactly 1.
    let path = unique_temp_db_path("retained-descriptor");
    let duplicates_before = crate::writer_gate::retained_duplicates_for_test();
    let first = SqliteIntentLog::open(&path).expect("bootstrap + open");
    let opens_after_first = crate::writer_gate::retained_header_opens_for_test(&path);
    let second = SqliteIntentLog::open(&path).expect("second open of the same store");
    let opens_after_second = crate::writer_gate::retained_header_opens_for_test(&path);

    assert_eq!(
        opens_after_first, 1,
        "the first open must open the header descriptor exactly once"
    );
    assert_eq!(
        opens_after_second, 1,
        "a second open of the SAME identity must REUSE the retained descriptor — every \
         additional open/close of the store file is a POSIX-advisory-lock cancellation \
         (sqlite.org howtocorrupt §2.2)"
    );
    assert_eq!(
        crate::writer_gate::retained_header_descriptors_for_test(&path),
        1,
        "exactly ONE descriptor is retained for the identity"
    );
    assert_eq!(
        crate::writer_gate::retained_duplicates_for_test(),
        duplicates_before,
        "no duplicate descriptor was needed (and had one been opened, it would have been \
         RETAINED — never dropped)"
    );
    drop(first);
    drop(second);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_second_open_of_the_same_store_does_not_cancel_locks() {
    // THE PREFLIGHT LOCK LIFECYCLE, at the shipped shell's own shape: the app performs TWO
    // `SqliteIntentLog::open` calls per process (`src-tauri/src/lib.rs` session + bus). The
    // Finding, demonstrated on a memfd probe: the second open's `read_raw_header`
    // used to `File::open` + DROP a bare descriptor on the store while the first open's
    // connections held locks — and on unix, closing ANY descriptor to a file cancels the
    // whole PROCESS's POSIX advisory locks on it (sqlite.org howtocorrupt §2.2).
    //
    // WHAT THIS WITNESS CAN AND CANNOT SEE, stated plainly. POSIX record locks are
    // PER-PROCESS, so the cancellation itself is invisible from inside this process — the
    // conflicting lock has to come from a SECOND PROCESS (that is exactly what the
    // memfd probe did, and its result is the evidence of record). What this witness
    // carries instead is the STRUCTURAL oracle, which is the property the fix actually
    // establishes: a second full open of the same identity — preflight and all — performs
    // NO further `open()` of the store file, so there is no descriptor for anyone to close
    // and the cancellation is unrepresentable rather than merely avoided. On Windows there
    // are no POSIX advisory locks at all, so the hold-survival arms below are trivially
    // true there (the plan's "n/a, stated"); the witness is deliberately NOT `#[cfg(unix)]`
    // so that it compiles and runs on every platform in the matrix, with unix the platform
    // where its liveness arms carry weight.
    //
    // Connection A holds a READ transaction, not a write one, on purpose: a held WAL
    // WRITER lock would make the second open's own DDL transaction wait out `busy_timeout`
    // and fail SQLITE_BUSY, which would test SQLite's busy machinery instead of this fix.
    // A reader holds the main-database SHARED lock — the very lock at risk — while leaving
    // the second open free to run its whole path.
    let path = unique_temp_db_path("second-open-keeps-locks");
    let first = SqliteIntentLog::open(&path).expect("bootstrap + open");
    let mut conn_a = crate::store_open::open_verified_connection(&path).expect("conn A");
    let tx_a = conn_a
        .ungated_conn_mut()
        .transaction()
        .expect("A begins a read transaction");
    let before: i64 = tx_a
        .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0))
        .expect("A's read takes its locks");

    let opens_before = crate::writer_gate::retained_header_opens_for_test(&path);
    let second = SqliteIntentLog::open(&path).expect("a second full open of the same store");
    assert_eq!(
        crate::writer_gate::retained_header_opens_for_test(&path),
        opens_before,
        "a second open must add NO descriptor to the store file — an open/read/close of a              locked file cancels this process's POSIX advisory locks on it"
    );
    // …and A is intact: same snapshot, and its transaction still completes.
    let after: i64 = tx_a
        .query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get(0))
        .expect("A still reads after the second open");
    assert_eq!(before, after, "A's read transaction is undisturbed");
    tx_a.commit().expect("A's transaction still commits");
    // A can still WRITE through its own gated door afterwards.
    conn_a
        .with_immediate_tx(|tx| {
            tx.execute("UPDATE control_epoch SET epoch = epoch WHERE id = 1;", [])
                .map_err(|e| LogError(format!("A's post-open write: {e}")))
        })
        .expect("A writes after the second open");

    // ── THE LOST-RACE ARM ── two concurrent FIRST openers of an ABSENT path:
    // the loser re-runs the preflight, so one open reads the header TWICE. A dedup-DROP of
    // that second descriptor would itself be the cancellation; retention/reuse is what
    // makes the singular wording ("the preflight descriptor") true of the plural reality.
    let raced = unique_temp_db_path("second-open-lost-race");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let openers: Vec<_> = (0..2)
        .map(|_| {
            let (p, b) = (raced.to_path_buf(), std::sync::Arc::clone(&barrier));
            std::thread::spawn(move || {
                b.wait();
                SqliteIntentLog::open(&p).map_err(|e| e.to_string())
            })
        })
        .collect();
    let logs: Vec<_> = openers
        .into_iter()
        .map(|h| {
            h.join()
                .expect("opener thread")
                .expect("both racing first-openers end up with a usable store")
        })
        .collect();
    assert_eq!(
        crate::writer_gate::retained_header_opens_for_test(&raced),
        1,
        "even a RACED fresh install, whose loser re-runs the preflight, opens the header              descriptor exactly once for the identity"
    );

    let mut conn_b = crate::store_open::open_verified_connection(&raced).expect("conn B");
    let tx_b = conn_b
        .ungated_conn_mut()
        .transaction()
        .expect("B begins a read transaction");
    tx_b.query_row("SELECT COUNT(*) FROM intents;", [], |r| r.get::<_, i64>(0))
        .expect("B's read takes its locks");
    let opens_mid_hold = crate::writer_gate::retained_header_opens_for_test(&raced);
    let third = std::thread::spawn({
        let p = raced.to_path_buf();
        move || SqliteIntentLog::open(&p).map_err(|e| e.to_string())
    })
    .join()
    .expect("third opener thread")
    .expect("a third open arriving mid-hold succeeds");
    assert_eq!(
        crate::writer_gate::retained_header_opens_for_test(&raced),
        opens_mid_hold,
        "an opener arriving while a lock is held adds no descriptor either"
    );
    tx_b.commit().expect("B's transaction still commits");

    drop(first);
    drop(second);
    drop(conn_a);
    drop(logs);
    drop(third);
    drop(conn_b);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&raced);
}

#[test]
fn concurrent_first_openers_of_an_absent_store_all_succeed() {
    // Two openers of the same ABSENT path both take the fresh-bootstrap
    // branch. The destination-scoped init lock serializes them and the no-replace rename
    // correctly refuses to clobber the winner — but the LOSER used to surface that
    // refusal to its caller as an error. Losing the install race is not a failure to
    // open: the store the loser wanted now exists, and it must reopen the winner's.
    // Repeated so the interleaving is hit reliably; every round must end Ok for BOTH.
    for round in 0..16 {
        let path = unique_temp_db_path(&format!("bootstrap-race-{round}"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let p = path.to_path_buf();
                let b = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    SqliteIntentLog::open(&p).map(|_| ()).map_err(|e| e.to_string())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, r) in results.iter().enumerate() {
            assert!(
                r.is_ok(),
                "round {round}, opener {i}: a concurrent first-opener must end up with a \
                 usable store, got {r:?}"
            );
        }
        for ext in ["-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn open_recovers_a_stale_header_v8_store_through_the_probe() {
    // Case (c): a crash right after the v8 stamp can leave the main header stale while
    // the truth lives in -wal. Construct: suppress autocheckpoint, stamp v8 inside WAL,
    // copy the file family mid-state, and require the copy to open successfully.
    let path = unique_temp_db_path("stale-header");
    {
        let _log = SqliteIntentLog::open(&path).unwrap();
    }
    let conn = rusqlite::Connection::open(&path).unwrap();
    crate::store_open::pin_durability_profile(&conn).unwrap();
    conn.execute_batch("PRAGMA wal_autocheckpoint=0;").unwrap();
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                  VALUES (2, strftime('%s','now'), 'test_act', '{}');",
        [],
    )
    .unwrap();
    // main header user_version may now trail the WAL; copy the family mid-state
    let copy = unique_temp_db_path("stale-header-copy");
    std::fs::copy(&path, &copy).unwrap();
    std::fs::copy(
        format!("{}-wal", path.display()),
        format!("{}-wal", copy.display()),
    )
    .unwrap();
    drop(conn);
    let log = SqliteIntentLog::open(&copy);
    assert!(
        log.is_ok(),
        "a v8 store with a hot WAL must open via the recovery probe: {:?}",
        log.err()
    );
}

#[test]
fn open_refuses_a_future_db_without_mutating_its_schema() {
    // A DB written by a NEWER binary carries a future user_version and need NOT have this version's
    // tables. Refusing it must run NO schema DDL — the guard precedes the CREATEs.
    let path = unique_temp_db_path("future-db");
    {
        let conn = rusqlite::Connection::open(&path).expect("raw open");
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("seed a future version");
    }
    assert!(
        SqliteIntentLog::open(&path).is_err(),
        "a DB newer than SCHEMA_VERSION must be refused"
    );
    // The refused open must have added NONE of this version's objects to the future layout.
    let conn = rusqlite::Connection::open(&path).expect("raw open");
    let table_count = |name: &str| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1;",
            [name],
            |r| r.get(0),
        )
        .expect("sqlite_master query")
    };
    assert_eq!(table_count("intents"), 0, "refused open must not create `intents`");
    assert_eq!(
        table_count("message_header"),
        0,
        "refused open must not create `message_header`"
    );
    drop(conn);
    std::fs::remove_file(&path).ok();
}

#[test]
fn sqlite_record_rejects_a_different_command_under_an_existing_key() {
    // The durable command for an idempotency key IS the system-of-record and is
    // immutable. A re-record with a DIFFERENT payload under the same key (caller bug / stale UI)
    // must be REJECTED — never silently overwrite the entry, which recovery would then replay
    // under the original seq. An identical re-record stays a safe retry.
    let path = unique_temp_db_path("record-immutable-key");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    record_basis(&mut log, &archive_cmd("k1")).expect("first record");

    let conflicting = Command::new(
        "k1",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "DIFFERENT".into(),
        },
    );
    let result = record_basis(&mut log, &conflicting);

    assert!(
        matches!(result, Err(LogError(_))),
        "a different command under an existing key must be rejected, got {result:?}"
    );
    assert_eq!(
        log.get("k1").expect("get").expect("intent").command.action,
        Action::Archive {
            message_ref: "msg-1".into()
        },
        "the original durable command must survive a rejected rewrite"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn in_memory_record_rejects_a_different_command_under_an_existing_key() {
    // Same immutability contract for the in-memory log — the IntentLog contract is uniform.
    let mut log = InMemoryIntentLog::new();
    record_basis(&mut log, &archive_cmd("k1")).expect("first record");

    let result = record_basis(&mut log, &Command::new(
        "k1",
        "acct-1",
        Facet::Mail,
        Action::Unarchive {
            message_ref: "msg-1".into(),
        },
    ));

    assert!(
        matches!(result, Err(LogError(_))),
        "a different command under an existing key must be rejected, got {result:?}"
    );
    assert_eq!(
        log.get("k1").expect("g").expect("i").command.action,
        Action::Archive {
            message_ref: "msg-1".into()
        },
        "the original durable command must survive a rejected rewrite"
    );
}

#[test]
fn sqlite_key_immutability_is_enforced_atomically_in_the_insert() {
    // Immutability must live in the INSERT (an atomic conditional ON CONFLICT),
    // not a separate get pre-check two concurrent connections could both pass. Prove the SQL
    // itself rejects: a SECOND connection recording the same key with a different command is
    // rejected and the original durable command survives.
    let path = unique_temp_db_path("sqlite-atomic-immutability");
    let mut a = SqliteIntentLog::open(&path).expect("open A");
    record_basis(&mut a, &archive_cmd("k1")).expect("A records msg-1");

    let mut b = SqliteIntentLog::open(&path).expect("open B (separate connection)");
    let result = record_basis(&mut b, &Command::new(
        "k1",
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-2".into(),
        },
    ));

    assert!(
        matches!(result, Err(LogError(_))),
        "the INSERT must reject a different payload under an existing key, got {result:?}"
    );
    assert_eq!(
        b.get("k1").expect("g").expect("i").command.action,
        Action::Archive {
            message_ref: "msg-1".into()
        },
        "the original durable command must survive the rejected concurrent rewrite"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn dead_letters_lists_only_failed_intents_in_seq_order() {
    // ADR-P013 (b): the dead-letter lifecycle must let an operator INSPECT what was
    // dead-lettered. dead_letters returns every terminal `Failed` intent ordered by durable
    // seq — and ONLY those (Applied / Undone / Pending are not dead letters). Exercised on the
    // SQLite store so the real query + fail-closed row parsing are covered.
    let path = unique_temp_db_path("dead-letters-inspect");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    record_basis(&mut log, &archive_cmd("k-applied")).unwrap();
    record_basis(&mut log, &archive_cmd("k-dead")).unwrap();
    record_basis(&mut log, &archive_cmd("k-pending")).unwrap();
    log.set_status_forced("k-applied", IntentStatus::Applied).unwrap();
    log.set_status_forced("k-dead", IntentStatus::Failed).unwrap();

    let dead = log.dead_letters().expect("dead_letters query");
    assert_eq!(dead.len(), 1, "only the Failed intent is a dead letter");
    assert_eq!(dead[0].command.idempotency_key, "k-dead");
    assert_eq!(dead[0].status, IntentStatus::Failed);
    std::fs::remove_file(&path).ok();
}

#[test]
fn record_reports_inserted_then_already_existed_for_an_identical_concurrent_claim() {
    // ADR-P013 /: the atomic claim must distinguish "THIS call inserted the fresh
    // row" from "a row already existed", so two same-key executes can't both dispatch. A second
    // connection recording the identical key after the first gets `AlreadyExisted`, not a second
    // insert — that signal is what lets execute refuse to double-dispatch.
    let path = unique_temp_db_path("claim-inserted-vs-existing");
    let cmd = archive_cmd("k1");
    let mut a = SqliteIntentLog::open(&path).expect("open A");
    let mut b = SqliteIntentLog::open(&path).expect("open B (separate connection)");

    assert_eq!(record_basis(&mut a, &cmd).expect("A claims fresh"), Claim::Inserted);
    assert_eq!(
        record_basis(&mut b, &cmd).expect("B sees the existing claim"),
        Claim::AlreadyExisted,
        "the second claimant must NOT re-insert or own the dispatch"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn record_rejects_a_normal_command_in_the_reserved_namespace() {
    // The reserved compensation namespace is engine-only — a normal command (no link)
    // cannot claim it, which is what guarantees an auto-minted compensation key is always free.
    let mut log = InMemoryIntentLog::new();
    let intruder = Command::new(
        compensation_key("k1"),
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "m".into(),
        },
    );
    assert!(
        record_basis(&mut log, &intruder).is_err(),
        "a non-compensation command must not claim the reserved internal namespace"
    );
}

/// `projected` arrives in-version, `DEFAULT 0`, and the
/// upgrade BACKFILLS `projected = 1` for every row already `applied` at upgrade time — the
/// earlier behaviour assumed those rows were already correctly projected (the OLD
/// `applied_this_run` before/after diff was this build's only mechanism, and it ran at the
/// time each of those rows applied); re-projecting them now would risk overwriting a NEWER
/// observation a refresh has since written with a stale, possibly-ancient delta.
#[test]
fn projected_backfills_true_for_an_already_applied_row_on_an_upgraded_store() {
    let path = unique_temp_db_path("s1-p-backfill");
    {
        let mut log = SqliteIntentLog::open(&path).expect("mint the store");
        record_basis(&mut log, &s1_trash_cmd("k-applied", "msg-applied")).expect("record k-applied");
        log.set_status_forced("k-applied", IntentStatus::Applied).expect("force applied");
        record_basis(&mut log, &s1_trash_cmd("k-pending", "msg-pending")).expect("record k-pending");
    }
    // Simulate an EARLIER build's store: the column never existed, so both rows read as if
    // `projected` were never set at all.
    raw_conn(&path).execute_batch("ALTER TABLE intents DROP COLUMN projected;").expect("reduce to pre-fold shape");
    drop(SqliteIntentLog::open(&path).expect("reopen upgrades the table"));
    let projected = |key: &str| -> i64 {
        raw_conn(&path)
            .query_row("SELECT projected FROM intents WHERE idempotency_key = ?1;", [key], |r| r.get(0))
            .expect("row exists")
    };
    assert_eq!(projected("k-applied"), 1, "an already-Applied row backfills projected = 1");
    assert_eq!(projected("k-pending"), 0, "a non-Applied row backfills projected = 0 (the column default)");
    std::fs::remove_file(&path).ok();
}

/// The STORE-DERIVED work list — every FORWARD-kind
/// intent that is `Applied` and not yet `projected`, regardless of which plan (or no plan at
/// all) it belongs to. the OLD bare `mark_projected` door this test
/// used to exercise here is DELETED — marking now happens ONLY inside
/// `ReadCoordinator::project_applied_intent`'s own transaction (never reachable generically
/// over `Box<dyn IntentLog>`, since it needs the coordinator's `message_header` table, which
/// `InMemoryIntentLog` does not model) — covered by
/// `read_coordinator::tests::r5_*` and the driver's own `driver_r5_p4_*`/`driver_r5_p5_*`
/// witnesses (`src-tauri/src/lib.rs`) instead.
#[test]
fn applied_unprojected_forward_intents_filters_forward_applied_unprojected_only() {
    let basis = crate::prestate::FrozenBasis::for_test_trash();
    // The guard is BOUND here, before the store it names — it was
    // passed BY VALUE into `open` (dropped there, the store still open ⇒ the 14:41 leak).
    let path = unique_temp_db_path("s1-p-sweep");
    for mut log in [Box::new(SqliteIntentLog::open(&path).unwrap()) as Box<dyn IntentLog>, Box::new(InMemoryIntentLog::new()) as Box<dyn IntentLog>] {
        // k-applied: forward, Applied, unprojected — IN the work list.
        let applied = s1_trash_cmd("k-applied", "msg-applied");
        log.record(&applied, &basis).unwrap();
        log.set_status_forced("k-applied", IntentStatus::Applied).unwrap();
        // k-pending: forward, still Pending — NOT in the work list (not Applied).
        log.record(&s1_trash_cmd("k-pending", "msg-pending"), &basis).unwrap();
        // k-undo: an UNDO child (compensates = Some), Applied — NOT in the work list: undo's
        // local-row consequences are the separate, deliberately-always-Stale `undo()` contract.
        let undo_child = Command {
            compensates: Some("k-applied".to_string()),
            ..s1_trash_cmd("k-undo", "msg-applied")
        };
        log.record(&undo_child, &basis).unwrap();
        log.set_status_forced("k-undo", IntentStatus::Applied).unwrap();

        let work = log.applied_unprojected_forward_intents().unwrap();
        assert_eq!(
            work.iter().map(|i| i.command.idempotency_key.as_str()).collect::<Vec<_>>(),
            vec!["k-applied"],
            "only the forward, Applied, unprojected intent is in the work list"
        );
    }
}

// --: the open-time integrity scan (§2.2b both directions + capture-off) -------

/// Hand-seed a `pre_state` row attached to a seeded intent (every NOT NULL column).
fn seed_pre_state_row(conn: &rusqlite::Connection, key: &str, journal_id: &str) {
    conn.execute(
        "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom,
                                    resolved_operands, fetched_at, source, captured_epoch,
                                    mode_generation, undo_offer_until)
             SELECT ?2, i.intent_id, '{}', '{}', '{}', '2026-01-01T00:00:00Z', 'live_read',
                    1, 1, '2026-01-08T00:00:00Z'
               FROM intents i WHERE i.idempotency_key = ?1;",
        rusqlite::params![key, journal_id],
    )
    .expect("seed pre_state");
}

#[test]
fn integrity_scan_surfaces_reverse_gap_capture_off_and_missing_basis_but_honors_tombstones() {
    // §2.2b SQLITE-FK-ENFORCEMENT-GATE: the open-time scan covers BOTH directions plus
    // the capture-off direction, and the reverse-gap scan EXCLUDES tombstoned parents.
    let path = build_store_with("scan-evidence", |conn| {
        let basis = |n: &str| {
            format!(
                r#"{{"native_resource_key":"{n}","touched_atoms":{{"a":"a"}},"freshness":"immutable_constants"}}"#
            )
        };
        // (a) reverse gap: journal_required=1 forward intent, DISPATCHED (applied), no row.
        seed_intent(conn, "k-gap", "applied", 1, "forward", Some(&basis("t:1")));
        // (b) capture-off row: journal_required=0 parent WITH a pre_state row (illegal).
        seed_intent(conn, "k-off", "applied", 0, "forward", Some(&basis("t:2")));
        seed_pre_state_row(conn, "k-off", "j-off");
        // (c) tombstoned parent: journal_required=1, applied, no row — but tombstone exists.
        seed_intent(conn, "k-tomb", "applied", 1, "forward", Some(&basis("t:3")));
        seed_tombstone(conn, "k-tomb", "j-tomb");
        // (d) non-terminal intent with NULL frozen_basis (a pre-stage-2 row).
        seed_intent(conn, "k-nobasis", "pending", 1, "forward", None);
        // (e) a `failed` PRE-DISPATCH terminal legitimately owns no row — never a gap.
        seed_intent(conn, "k-failed", "failed", 1, "forward", Some(&basis("t:5")));
    });
    let report = open_integrity_report(&path);
    assert!(
        report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::JournalGapUnexplained { key } if key == "k-gap")),
        "got {report:?}"
    );
    assert!(
        report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::CaptureOffRow { key } if key == "k-off")),
        "got {report:?}"
    );
    assert!(
        report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::FrozenBasisMissing { key } if key == "k-nobasis")),
        "got {report:?}"
    );
    assert!(
        !report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::JournalGapUnexplained { key } if key == "k-tomb")),
        "a tombstoned parent's absence is EXPLAINED (renders Expired at stage 3) — never \
         JournalGapUnexplained; got {report:?}"
    );
    assert!(
        !report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::JournalGapUnexplained { key } if key == "k-failed")),
        "a `failed` pre-dispatch terminal never reached the wire, so it owes no row; got {report:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_malformed_frozen_basis_is_reported_by_the_scan_not_an_index_build_that_kills_the_open() {
    // THE RED. `evidence NEVER refuses the open` is the §2.2b contract: a store
    // holding rows an operator must inspect has to OPEN so they can inspect them. But the §7a
    // native-key expression index was `json_extract(frozen_basis, '$.native_resource_key')`
    // UNGUARDED, and SQLite evaluates the index expression over every existing row while
    // BUILDING the index — `json_extract` ABORTS on malformed JSON. So the FIRST open that
    // creates the index over a store already holding a malformed non-NULL `frozen_basis` died
    // inside `CREATE INDEX`, before `integrity_scan` could report a single thing. The DDL
    // became a cop, and the one row the scan exists to surface was the one that locked the
    // operator out.
    //
    // The store shape is exactly the real one: a v8 store created by STAGE 1 (which had no
    // native-key index yet), holding a malformed basis, meeting a stage-2 binary for the first
    // time — reproduced by dropping the index before seeding.
    let path = build_store_with("malformed-basis-index", |conn| {
        conn.execute_batch("DROP INDEX IF EXISTS idx_intents_native_key;")
            .expect("simulate a stage-1 v8 store: no native-key index yet");
        // A NON-NULL frozen_basis that is not JSON at all — the shape `json_extract` aborts on.
        seed_intent(conn, "k-malformed", "pending", 1, "forward", Some("not json"));
        // …and JSON that parses but is not a FrozenBasis is the scan's business too.
        seed_intent(conn, "k-wrongshape", "pending", 1, "forward", Some(r#"{"a":1}"#));
        // A healthy neighbour must keep working — the guard must not blind the index.
        seed_intent(
            conn,
            "k-ok",
            "pending",
            1,
            "forward",
            Some(r#"{"native_resource_key":"t:ok","touched_atoms":{"a":"a"},"freshness":"immutable_constants"}"#),
        );
    });
    let report = open_integrity_report(&path);
    for key in ["k-malformed", "k-wrongshape"] {
        assert!(
            report
                .iter()
                .any(|e| matches!(e, IntegrityEvidence::FrozenBasisMissing { key: k } if k == key)),
            "the malformed basis must be REPORTED, got {report:?}"
        );
    }
    assert!(
        !report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::FrozenBasisMissing { key: k } if k == "k-ok")),
        "the healthy row is not evidence; got {report:?}"
    );
    // …and the guarded index still SERVES the native-key lookup — a malformed-safe expression
    // that no consumer query matches would be an index in name only (SQLite expression-index
    // matching is TEXTUAL).
    let conn = raw_conn(&path);
    let plan: String = conn
        .query_row(
            &format!("EXPLAIN QUERY PLAN SELECT seq FROM intents WHERE {NATIVE_KEY_EXPR_SQL} = 'x';"),
            [],
            |r| r.get(3),
        )
        .expect("plan");
    assert!(
        plan.to_uppercase().contains("USING INDEX"),
        "the guarded native-key expression must still ride the index, got: {plan}"
    );
    drop(conn);
    std::fs::remove_file(&path).ok();
}

#[test]
fn the_three_stage_4_statuses_are_terminal_pre_dispatch_ineligible_and_undo_refused() {
    // All three P013 status-set additions are terminal (never
    // re-dispatched), never pre-dispatch-eligible (no fresh pre-state journal row may
    // attach), and undo-INELIGIBLE with a NAMED, mechanical reason (§4.5 gate) — never a
    // guessed inverse.
    for status in [
        IntentStatus::Severed,
        IntentStatus::Adjudicated,
        IntentStatus::ExternallySatisfied,
    ] {
        assert!(status.is_terminal(), "{status:?} must be terminal");
        assert!(
            !status.is_pre_dispatch(),
            "{status:?} must not be pre-dispatch-eligible"
        );
    }

    let basis = test_basis("m1");
    for (status, expected) in [
        (
            IntentStatus::Severed,
            prestate::UndoUnavailableReason::Severed,
        ),
        (
            IntentStatus::Adjudicated,
            prestate::UndoUnavailableReason::Adjudicated,
        ),
        (
            IntentStatus::ExternallySatisfied,
            prestate::UndoUnavailableReason::ExternallySatisfied,
        ),
    ] {
        let mut log = InMemoryIntentLog::new();
        let command = Command::new(
            derive_idempotency_key("acct", &Facet::Mail, "one"),
            "acct",
            Facet::Mail,
            Action::Archive {
                message_ref: "m1".into(),
            },
        );
        log.record(&command, &basis).unwrap();
        log.set_status_forced(&command.idempotency_key, status.clone())
            .unwrap();
        let mut bus = CommandBus::new(log, AlwaysOkConnector);
        let err = bus.undo(&command.idempotency_key).unwrap_err();
        assert_eq!(
            err,
            ExecuteError::UndoUnavailable(expected),
            "{status:?} must refuse undo with its own honest reason"
        );
        // Stage 4 (presentation distinctness, test-witnessed): an
        // identical-fingerprint replay against each new terminal returns ITS OWN `Err`
        // class through the real `execute()` API — never the generic `ExecuteError::Failed`
        // a provider rejection would produce, and never a silent `Ok`.
        let expected_replay_err = match &status {
            IntentStatus::Severed => ExecuteError::Severed,
            IntentStatus::Adjudicated => ExecuteError::AdjudicatedUnresolved,
            IntentStatus::ExternallySatisfied => ExecuteError::ExternallySatisfied,
            other => panic!("unexpected status in this table: {other:?}"),
        };
        let replay = bus.execute(&command);
        assert_eq!(
            replay,
            Err(expected_replay_err),
            "{status:?}: an identical-fingerprint replay must surface its own truthful \
             Err class, never the generic provider-failure `Failed`"
        );
    }
}

#[test]
fn integrity_scan_covers_every_non_terminal_status_not_just_pending_and_undoing() {
    // THE CLASS, arm (a): the missing-basis scan hand-enumerated `('pending','undoing')`
    // while `IntentStatus::is_terminal` treats `evidence_snapshot_written` as NON-terminal
    // too. A row in that status with a NULL/malformed basis is still to be ordered and
    // dispatched, so its untrustworthy tail key is exactly what this scan exists to surface
    // — and it was invisible. The scan must cover the STATUS DOMAIN, not two of its members.
    let path = build_store_with("scan-esw", |conn| {
        seed_intent(conn, "k-esw-nobasis", "evidence_snapshot_written", 1, "forward", None);
    });
    let report = open_integrity_report(&path);
    assert!(
        report.iter().any(|e| matches!(
            e,
            IntegrityEvidence::FrozenBasisMissing { key } if key == "k-esw-nobasis"
        )),
        "a NON-terminal `evidence_snapshot_written` row with no basis is the same evidence \
         as a `pending` one; got {report:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn an_evidence_snapshot_written_predecessor_blocks_the_head_gate() {
    // THE CLASS, arm (b): the tail-ordering head gate
    // (`has_non_terminal_native_predecessor`, both impls + PREPARE's in-txn re-verify) also
    // hand-enumerated the two tokens. An `evidence_snapshot_written` predecessor is
    // NON-terminal — `classify` routes it to `Decision::InProgress`, recovery owns it — so a
    // later same-native operation that overtakes it reverses their causal order, the exact
    // TailOrderedMutationInvariant violation the gate exists to prevent.
    let path = unique_temp_db_path("head-gate-esw");
    SqliteIntentLog::open(&path).expect("bootstrap");
    {
        let conn = raw_conn(&path);
        // A lower-seq predecessor on the SAME native resource key, non-terminal.
        conn.execute(
            "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                      status, seq, intent_id, kind, journal_required,
                                      capture_mode_generation, admitted_control_epoch, frozen_basis)
                 VALUES ('k-esw-pred', 'acct-1', 'mail', 'archive', 'msg-1',
                         'evidence_snapshot_written', 1, lower(hex(randomblob(16))), 'forward', 1,
                         1, 1, ?1);",
            rusqlite::params![test_basis("prov:acct-1/msg-1").to_json().unwrap()],
        )
        .expect("seed predecessor");
    }
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(&path).expect("reopen"),
        MalformedBasisConnector::new(test_basis("prov:acct-1/msg-1")),
    );
    let r = bus.execute(&archive_cmd("k-esw-succ"));
    assert!(
        matches!(r, Err(ExecuteError::InProgress)),
        "a NON-terminal `evidence_snapshot_written` predecessor must hold the head, got {r:?}"
    );
    assert_eq!(
        bus.connector().apply_count(),
        0,
        "the successor must NOT have overtaken its predecessor onto the wire"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn recovery_sweeps_every_non_terminal_status() {
    // THE CLASS, arm (c) — found by the sweep, not named in the finding: BOTH `unreconciled()`
    // impls filtered to the same two tokens, so an `evidence_snapshot_written` row was
    // invisible to `recover()` FOREVER — durably in-flight and never swept, the fail-OPEN
    // shape `unreconciled()`'s own parse-then-filter discipline exists to prevent. (recover's
    // dispatch arm already handled it: its forward match is `_ =>`.)
    let path = unique_temp_db_path("recover-esw");
    SqliteIntentLog::open(&path).expect("bootstrap");
    {
        let conn = raw_conn(&path);
        conn.execute(
            "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                      status, seq, intent_id, kind, journal_required,
                                      capture_mode_generation, admitted_control_epoch, frozen_basis)
                 VALUES ('k-esw-rec', 'acct-1', 'mail', 'archive', 'msg-1',
                         'evidence_snapshot_written', 1, lower(hex(randomblob(16))), 'forward', 1,
                         1, 1, ?1);",
            rusqlite::params![test_basis("prov:acct-1/msg-1").to_json().unwrap()],
        )
        .expect("seed");
    }
    let mut bus = sqlite_bus_with_counting_connector(&path);
    let report = bus.recover().expect("sweep");
    assert_eq!(
        report.recovered, 1,
        "a non-terminal row must be SWEPT, whichever non-terminal status it holds"
    );
    assert_eq!(
        bus.log().get("k-esw-rec").unwrap().unwrap().status,
        IntentStatus::Applied
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn integrity_scan_is_clean_on_a_healthy_store() {
    // Non-vacuity: the store is scanned on the SECOND open, after a real journal-required
    // forward operation has been observed, prepared and applied through the pipeline.
    let path = unique_temp_db_path("scan-clean");
    {
        let mut bus = sqlite_bus_with_counting_connector(&path);
        bus.execute(&archive_cmd("k-ok")).unwrap();
    }
    assert_eq!(raw_count(&path, "pre_state"), 1, "precondition: journalled");
    assert_eq!(
        open_integrity_report(&path),
        Vec::new(),
        "a healthy store yields NO evidence"
    );
    std::fs::remove_file(&path).ok();
}

// ---- THE PER-ROW-DEFECT CLASS: a scanned row's defect is EVIDENCE, never a closed door ----

#[test]
fn a_non_text_frozen_basis_is_evidence_not_an_unopenable_store() {
    // THE RED — the SECOND appearance of the class. §2.2b's contract is
    // "evidence NEVER refuses the open": a store holding rows an operator must inspect has to
    // OPEN so they can inspect them. closed the DDL half (an unguarded index expression
    // aborting on malformed JSON while BUILDING). The SCAN half was still open: it read
    // `frozen_basis` as `Option<String>`, so a row whose column holds a BLOB (any writer, any
    // corruption, any hand-repair) raised `InvalidColumnType` INSIDE the scan and made the
    // store unopenable — the row the scan exists to surface, once again locking the operator
    // out of the store.
    let path = build_store_with("blob-basis-scan", |conn| {
        conn.execute(
            "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                      status, seq, intent_id, kind, journal_required,
                                      capture_mode_generation, admitted_control_epoch, frozen_basis)
                 VALUES ('k-blob-basis', 'acct-1', 'mail', 'archive', 'msg-1',
                         'pending', 1, lower(hex(randomblob(16))), 'forward', 1, 1, 1, ?1);",
            rusqlite::params![vec![0x00u8, 0xff, 0x00, 0xff]],
        )
        .expect("seed a BLOB frozen_basis");
    });
    let report = open_integrity_report(&path);
    assert!(
        report.iter().any(|e| matches!(
            e,
            IntegrityEvidence::FrozenBasisMissing { key } if key == "k-blob-basis"
        )),
        "a non-TEXT frozen_basis is a per-ROW defect — evidence, not an open failure; \
         got {report:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_row_whose_own_key_is_unreadable_is_evidence_not_an_open_failure() {
    // The COMPLEMENT, taken to its limit: if even the row's IDENTITY column is not TEXT, the
    // defect still cannot be attributed to a key — but it still must not close the store. The
    // row is reported by its SQLite `rowid` instead. This row is a journal gap (applied,
    // journal_required=1, forward, no pre_state row and no tombstone), so it is the FIRST
    // scan that meets it — the class is per-scan, not per-column.
    let path = build_store_with("blob-key-scan", |conn| {
        conn.execute(
            "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                      status, seq, intent_id, kind, journal_required,
                                      capture_mode_generation, admitted_control_epoch, frozen_basis)
                 VALUES (?1, 'acct-1', 'mail', 'archive', 'msg-1',
                         'applied', 1, lower(hex(randomblob(16))), 'forward', 1, 1, 1, NULL);",
            rusqlite::params![vec![0xde_u8, 0xad, 0xbe, 0xef]],
        )
        .expect("seed a BLOB idempotency_key");
    });
    let rowid: i64 = raw_conn(&path)
        .query_row("SELECT rowid FROM intents;", [], |r| r.get(0))
        .expect("the seeded row's rowid");
    let report = open_integrity_report(&path);
    assert!(
        report
            .iter()
            .any(|e| matches!(e, IntegrityEvidence::UnreadableRow { rowid: r } if *r == rowid)),
        "an unreadable row IDENTITY is still evidence — reported by rowid; got {report:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn commitment_key_registry_is_one_row_that_is_written_once_and_read_back_on_both_stores() {
    // (No `use KeyRegistry` here: with `IntentLog` in scope too, every call below would be
    // E0034-ambiguous. These are the `IntentLog` methods; the blanket `KeyRegistry` impl is
    // witnessed by the next test.)
    // SQLite
    let path = unique_temp_db_path("key-registry");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    assert_eq!(log.registered_key_fingerprint().unwrap(), None);
    assert!(log.register_key_fingerprint("").is_err(), "an empty fingerprint is refused");
    assert_eq!(log.registered_key_fingerprint().unwrap(), None, "and registers nothing");
    // A NUL-led fingerprint is refused by the DDL CHECK: SQLite's `length()` stops at the
    // first NUL, so a NUL-led value measures 0. The twin below must refuse it too.
    assert!(log.register_key_fingerprint("\u{0}ab").is_err(), "a NUL-led fingerprint is refused");
    assert_eq!(log.registered_key_fingerprint().unwrap(), None, "and registers nothing");
    log.register_key_fingerprint("aa".repeat(48).as_str()).unwrap();
    assert_eq!(log.registered_key_fingerprint().unwrap().as_deref(), Some("aa".repeat(48).as_str()));
    assert!(log.register_key_fingerprint("bb").is_err(), "a second registration is refused");
    drop(log);
    let log = SqliteIntentLog::open(&path).unwrap();
    assert_eq!(log.registered_key_fingerprint().unwrap().as_deref(), Some("aa".repeat(48).as_str()), "durable across reopen");
    // The row is append-only at the DDL: UPDATE and DELETE are refused by trigger (a lost row
    // is a box-owner act, never something a shipped path can do).
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert!(conn.execute("UPDATE commitment_key_registry SET fingerprint = 'x' WHERE id = 1", []).is_err());
    assert!(conn.execute("DELETE FROM commitment_key_registry WHERE id = 1", []).is_err());
    // ...and so is a REPLACE: its implicit DELETE of the conflicting row fires NO delete
    // trigger under SQLite's default `recursive_triggers=off` (engine_config's),
    // so only a BEFORE INSERT guard stops it rewriting the row in place.
    assert!(conn
        .execute(
            "INSERT OR REPLACE INTO commitment_key_registry (id, fingerprint, registered_at) VALUES (1, 'x', 'x')",
            [],
        )
        .is_err());
    assert_eq!(log.registered_key_fingerprint().unwrap().as_deref(), Some("aa".repeat(48).as_str()), "the row is unchanged");
    // ...and so is every other overwrite spelling SQLite has : an
    // UPSERT, INSERT OR IGNORE (refused or a no-op — the row set is what is asserted), the
    // REPLACE statement, and UPDATE OR REPLACE. The row set is compared whole, so a second
    // row slipped in beside the first is caught too.
    let rows = |c: &rusqlite::Connection| -> Vec<(i64, String, String)> {
        let mut stmt = c.prepare("SELECT id, fingerprint, registered_at FROM commitment_key_registry ORDER BY rowid").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
    };
    let before = rows(&conn);
    assert_eq!(before.len(), 1);
    assert!(
        conn.execute(
            "INSERT INTO commitment_key_registry (id, fingerprint, registered_at) VALUES (1, 'x', 't') ON CONFLICT(id) DO UPDATE SET fingerprint = 'x'",
            [],
        )
        .is_err(),
        "an UPSERT is refused"
    );
    let _ = conn.execute("INSERT OR IGNORE INTO commitment_key_registry (id, fingerprint, registered_at) VALUES (1, 'x', 't')", []);
    assert_eq!(rows(&conn), before, "INSERT OR IGNORE leaves the row set unchanged");
    assert!(
        conn.execute("REPLACE INTO commitment_key_registry (id, fingerprint, registered_at) VALUES (1, 'x', 't')", []).is_err(),
        "REPLACE INTO is refused"
    );
    assert!(
        conn.execute("UPDATE OR REPLACE commitment_key_registry SET fingerprint = 'x' WHERE id = 1", []).is_err(),
        "UPDATE OR REPLACE is refused"
    );
    assert_eq!(rows(&conn), before, "the row set is unchanged after all four");
    drop(conn);
    drop(log);
    std::fs::remove_file(&path).ok();
    // In-memory twin, same contract
    let mut mem = InMemoryIntentLog::new();
    assert_eq!(mem.registered_key_fingerprint().unwrap(), None);
    assert!(mem.register_key_fingerprint("").is_err(), "the twin refuses an empty fingerprint too");
    assert_eq!(mem.registered_key_fingerprint().unwrap(), None);
    assert!(mem.register_key_fingerprint("\u{0}ab").is_err(), "the twin refuses a NUL fingerprint like SQLite's length() CHECK");
    assert_eq!(mem.registered_key_fingerprint().unwrap(), None);
    mem.register_key_fingerprint("cc").unwrap();
    assert!(mem.register_key_fingerprint("dd").is_err());
    assert_eq!(mem.registered_key_fingerprint().unwrap().as_deref(), Some("cc"));
}

#[test]
fn every_intent_log_is_the_key_registry_the_custody_door_verifies_against() {
    // The blanket `impl<L: IntentLog> KeyRegistry for L` (key_custody.rs): the door reads and
    // writes THIS store's row, the row is what a reopen verifies against, and a store
    // refusal surfaces as `CustodyError::Registry`.
    use crate::commitment::{key_fingerprint, CommitmentKey};
    use crate::key_custody::{root_key_verified, CustodyError, InMemoryCustody, KeyRegistry};
    let path = unique_temp_db_path("key-registry-door");
    let custody = InMemoryCustody::new();
    let mut log = SqliteIntentLog::open(&path).unwrap();
    let key = root_key_verified(&custody, &mut log).unwrap();
    assert_eq!(
        IntentLog::registered_key_fingerprint(&log).unwrap(),
        Some(key_fingerprint(&key)),
        "the door registered the minted key's fingerprint in the store's own row"
    );
    drop(log);
    let mut log = SqliteIntentLog::open(&path).unwrap();
    assert_eq!(root_key_verified(&custody, &mut log).unwrap(), key, "a reopen verifies against the durable row");
    let other = InMemoryCustody::holding(CommitmentKey::from_bytes(&[9u8; 48]).unwrap());
    assert!(matches!(
        root_key_verified(&other, &mut log).unwrap_err(),
        CustodyError::FingerprintMismatch { ref registered, .. } if *registered == key_fingerprint(&key)
    ));
    assert!(matches!(
        root_key_verified(&InMemoryCustody::new(), &mut log).unwrap_err(),
        CustodyError::RegisteredButAbsent { .. }
    ));
    assert!(matches!(
        KeyRegistry::register_key_fingerprint(&mut log, "ff").unwrap_err(),
        CustodyError::Registry(ref why) if why.contains("write-once")
    ));
    drop(log);
    std::fs::remove_file(&path).ok();
    // The in-memory twin, same door, same contract.
    let mut mem = InMemoryIntentLog::new();
    let held = CommitmentKey::from_bytes(&[5u8; 48]).unwrap();
    assert_eq!(root_key_verified(&InMemoryCustody::holding(held.clone()), &mut mem).unwrap(), held);
    assert_eq!(IntentLog::registered_key_fingerprint(&mem).unwrap(), Some(key_fingerprint(&held)));
    assert!(matches!(
        KeyRegistry::register_key_fingerprint(&mut mem, "ff").unwrap_err(),
        CustodyError::Registry(ref why) if why.contains("write-once")
    ));
}

#[test]
fn a_commitment_minted_through_custody_is_verifiable_by_the_key_holder_and_by_nobody_else() {
    use crate::commitment::*;
    use crate::key_custody::{root_key_verified, InMemoryCustody};
    let custody = InMemoryCustody::new();
    let mut mem = InMemoryIntentLog::new();
    let root = root_key_verified(&custody, &mut mem).unwrap();
    let account_key = derive_account_key(&root, "someone@example.com").unwrap();
    let domain = CommitmentDomain::new(
        "photon.triage.presentation",
        CommitmentDisposition::EnvelopeCommitmentOnly,
        CommitmentKeyRef::new("photon.account.someone@example.com", 1).unwrap(),
    )
    .unwrap();
    let (tag, profile) = commit_over(&account_key, &domain, b"canonical presentation bytes").unwrap();
    let r = Randomizer::from_hex(&profile.randomizer).unwrap();
    assert!(verify_tag(&account_key, &domain, &r, b"canonical presentation bytes", &tag));
    // Another account's key — derived from the SAME root — verifies nothing.
    let other = derive_account_key(&root, "other@example.com").unwrap();
    assert!(!verify_tag(&other, &domain, &r, b"canonical presentation bytes", &tag));
    // A second commitment over IDENTICAL bytes carries a DIFFERENT randomizer and tag
    // (no keyless correlation of repeated mailbox sets across journal entries).
    let (tag2, profile2) = commit_over(&account_key, &domain, b"canonical presentation bytes").unwrap();
    assert_ne!(profile.randomizer, profile2.randomizer);
    assert_ne!(tag, tag2);
    assert_eq!(profile.domain_separator, profile2.domain_separator);
}
