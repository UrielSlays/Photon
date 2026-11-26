//! The effect witness persisted beside the operation and read by the undo presentation.

use super::*;

// ---- the effect witness, persisted beside the operation ----

fn s1_label_set(s: &[&str]) -> std::collections::BTreeSet<String> {
    s.iter().map(|x| x.to_string()).collect()
}

#[test]
fn s1_the_effect_witness_and_the_observed_vector_are_persisted_beside_the_operation_on_both_stores() {
    use std::collections::BTreeSet;
    let set = |s: &[&str]| -> BTreeSet<String> { s.iter().map(|x| x.to_string()).collect() };
    let path = unique_temp_db_path("effect-witness");
    for mut log in [Box::new(SqliteIntentLog::open(&path).unwrap()) as Box<dyn IntentLog>, Box::new(InMemoryIntentLog::new())] {
        let cmd = Command::new("k-w", "acct", Facet::Mail, Action::Trash { message_ref: "msg-1".into() });
        log.record(&cmd, &crate::prestate::FrozenBasis::for_test_trash()).unwrap(); // seam: a valid Trash basis
        assert_eq!(log.effect_witness("k-w").unwrap(), None, "no effect yet, no witness");
        log.record_effect_witness("k-w", &EffectWitness { provider_label_vector: Some(set(&["TRASH", "STARRED"])) }, Some(&set(&["INBOX", "STARRED"]))).unwrap();
        let row = log.effect_witness("k-w").unwrap().expect("persisted");
        assert_eq!(row.effect_label_vector, Some(set(&["TRASH", "STARRED"])));
        assert_eq!(row.ripple_verdict, Some(crate::prestate::RippleVerdict::WithinClosure));
        assert!(log.record_effect_witness("missing-key", &EffectWitness::default(), None).is_err(), "no operation, no witness");
        // …and the refusal is about the KEY, not the empty witness.
        assert!(
            log.record_effect_witness("missing-key", &EffectWitness { provider_label_vector: Some(set(&["TRASH"])) }, Some(&set(&["INBOX"]))).is_err(),
            "no operation, no witness — even a full one"
        );
        assert!(log.effect_witness("missing-key").is_err(), "a missing operation is an error, not an absent witness");

        // An effect is observed ONCE: a second record would overwrite evidence, so it refuses
        // (with a vector or without one) and the first witness survives unchanged.
        assert!(log.record_effect_witness("k-w", &EffectWitness { provider_label_vector: Some(set(&["TRASH"])) }, Some(&set(&["INBOX"]))).is_err());
        assert!(log.record_effect_witness("k-w", &EffectWitness::default(), None).is_err());
        assert_eq!(log.effect_witness("k-w").unwrap(), Some(row));

        // OUTSIDE the closure: the verdict AND its unexpected atoms read back exactly.
        log.record(&s1_trash_cmd("k-o", "msg-2"), &crate::prestate::FrozenBasis::for_test_trash()).unwrap();
        log.record_effect_witness("k-o", &EffectWitness { provider_label_vector: Some(set(&["TRASH"])) }, Some(&set(&["INBOX", "IMPORTANT"]))).unwrap();
        assert_eq!(
            log.effect_witness("k-o").unwrap(),
            Some(EffectWitnessRow {
                effect_label_vector: Some(set(&["TRASH"])),
                ripple_verdict: Some(crate::prestate::RippleVerdict::OutsideClosure { unexpected: set(&["IMPORTANT"]) }),
            })
        );

        // No pre-effect vector (no journal row holds one): the post vector persists and the
        // verdict is NULL — nothing to judge the delta against, never a guessed verdict.
        log.record(&s1_trash_cmd("k-n", "msg-3"), &crate::prestate::FrozenBasis::for_test_trash()).unwrap();
        log.record_effect_witness("k-n", &EffectWitness { provider_label_vector: Some(set(&["TRASH"])) }, None).unwrap();
        assert_eq!(
            log.effect_witness("k-n").unwrap(),
            Some(EffectWitnessRow { effect_label_vector: Some(set(&["TRASH"])), ripple_verdict: None })
        );

        // The closure is the frozen basis label ids (its VALUES), never its atom keys: a
        // delta of exactly {TRASH, INBOX} is within it.
        log.record(&s1_trash_cmd("k-v", "msg-4"), &crate::prestate::FrozenBasis::for_test_trash()).unwrap();
        log.record_effect_witness("k-v", &EffectWitness { provider_label_vector: Some(set(&["TRASH"])) }, Some(&set(&["INBOX"]))).unwrap();
        assert_eq!(log.effect_witness("k-v").unwrap().unwrap().ripple_verdict, Some(crate::prestate::RippleVerdict::WithinClosure));

        // A route that observed NOTHING persists nothing.
        log.record(&s1_trash_cmd("k-z", "msg-5"), &crate::prestate::FrozenBasis::for_test_trash()).unwrap();
        log.record_effect_witness("k-z", &EffectWitness::default(), Some(&set(&["INBOX"]))).unwrap();
        assert_eq!(log.effect_witness("k-z").unwrap(), None);
    }
    // SQLite holds the verdict as the tokens its CHECK names, and the vectors as canonical arrays.
    let conn = raw_conn(&path);
    let cols = |key: &str| -> (Option<String>, Option<String>, Option<String>) {
        conn.query_row(
            "SELECT effect_label_vector, ripple_verdict, ripple_unexpected FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("the operation row")
    };
    let some = |s: &str| Some(s.to_string());
    assert_eq!(cols("k-w"), (some(r#"["STARRED","TRASH"]"#), some("within_closure"), None));
    assert_eq!(cols("k-o"), (some(r#"["TRASH"]"#), some("outside_closure"), some(r#"["IMPORTANT"]"#)));
    assert_eq!(cols("k-n"), (some(r#"["TRASH"]"#), None, None));
    assert_eq!(cols("k-z"), (None, None, None));
    drop(conn);
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_a_stored_witness_that_does_not_read_back_is_a_log_error() {
    // The read boundary of `effect_witness` on the durable store: every shape
    // `record_effect_witness` cannot write — and the CHECKs alone do not forbid — refuses
    // loudly instead of reading back as a witness.
    let path = unique_temp_db_path("s1-witness-corrupt");
    let mut log = SqliteIntentLog::open(&path).unwrap();
    log.record(&s1_trash_cmd("k-bad", "msg-1"), &crate::prestate::FrozenBasis::for_test_trash())
        .unwrap();
    drop(log);
    for (vector, verdict, unexpected) in [
        (Some(r#"["TRASH","INBOX"]"#), None, None),
        (Some("not json"), None, None),
        (None, Some("within_closure"), None),
        (Some(r#"["TRASH"]"#), Some("outside_closure"), Some("[]")),
        (Some(r#"["TRASH"]"#), Some("outside_closure"), Some(r#"["X","A"]"#)),
    ] {
        raw_conn(&path)
            .execute(
                "UPDATE intents SET effect_label_vector = ?1, ripple_verdict = ?2, ripple_unexpected = ?3
                      WHERE idempotency_key = 'k-bad';",
                rusqlite::params![vector, verdict, unexpected],
            )
            .expect("the CHECKs admit this shape — the read boundary is what must refuse it");
        let log = SqliteIntentLog::open(&path).unwrap();
        assert!(
            log.effect_witness("k-bad").is_err(),
            "({vector:?}, {verdict:?}, {unexpected:?}) must not read back as a witness"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_a_label_vector_its_read_would_refuse_is_refused_at_prepare_and_replace_on_both_stores() {
    // The write-side twin of `observed_label_vector_set`: the journal never persists a vector
    // its own read boundary would refuse (the `JournalRow::validate` discipline for the atom
    // maps, applied to the one field `validate` does not read).
    let path = unique_temp_db_path("s1-prepare-vector");
    for mut log in [Box::new(SqliteIntentLog::open(&path).unwrap()) as Box<dyn IntentLog>, Box::new(InMemoryIntentLog::new())] {
        let basis = crate::prestate::FrozenBasis::for_test_trash();
        log.record(&s1_trash_cmd("k-p", "msg-1"), &basis).unwrap();
        let obs = crate::prestate::Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: [("label:TRASH".to_string(), false), ("membership:INBOX".to_string(), true)]
                .into_iter()
                .collect(),
            request_id: None,
            provider_label_vector: Some(s1_label_set(&["INBOX", "STARRED"])),
        };
        let good = crate::prestate::journal_row_from_observation(&obs, &basis);
        let unsorted = crate::prestate::JournalRow {
            observed_label_vector: Some(r#"["STARRED","INBOX"]"#.to_string()),
            ..good.clone()
        };
        assert!(log.prepare("k-p", &unsorted).is_err(), "a non-canonical vector must not be journaled");
        assert!(!log.prepared("k-p").unwrap(), "the refusal wrote nothing");
        assert_eq!(log.prepare("k-p", &good).unwrap(), crate::prestate::PrepareOutcome::Prepared);
        assert!(
            log.replace_journal_row("k-p", &unsorted).is_err(),
            "the one narrow REPLACE exception holds the same write-side rule"
        );
        assert_eq!(
            log.captured_pre_state("k-p").unwrap().unwrap().observed_label_vector,
            Some(s1_label_set(&["INBOX", "STARRED"])),
            "the canonical capture is the one that stands"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn s1_the_witness_columns_are_added_in_version_and_carry_their_checks_on_a_fresh_and_an_upgraded_store() {
    // The three `intents` columns and the one `pre_state` column arrive through
    // `IN_VERSION_COLUMN_UPGRADES` (SCHEMA_VERSION stays 9). An UPGRADED store — one an
    // earlier build of v9 created without them — must come up with the columns AND the same
    // CHECKs a fresh store has.
    let fresh = unique_temp_db_path("s1-witness-cols-fresh");
    drop(SqliteIntentLog::open(&fresh).expect("mint the store"));
    let upgraded = unique_temp_db_path("s1-witness-cols-upgraded");
    drop(SqliteIntentLog::open(&upgraded).expect("mint the store"));
    raw_conn(&upgraded)
        .execute_batch(
            "ALTER TABLE intents DROP COLUMN ripple_unexpected;
                 ALTER TABLE intents DROP COLUMN ripple_verdict;
                 ALTER TABLE intents DROP COLUMN effect_label_vector;
                 ALTER TABLE pre_state DROP COLUMN observed_label_vector;",
        )
        .expect("reduce the store to the pre-B8 v9 shape");
    let has = |path: &std::path::Path, table: &str, column: &str| -> bool {
        raw_conn(path)
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2;",
                rusqlite::params![table, column],
                |r| r.get::<_, i64>(0),
            )
            .expect("table_info")
            > 0
    };
    assert!(!has(&upgraded, "intents", "ripple_verdict"), "precondition: pre-B8 shape");
    drop(SqliteIntentLog::open(&upgraded).expect("open upgrades the tables"));
    for path in [&fresh, &upgraded] {
        for (table, column) in [
            ("intents", "effect_label_vector"),
            ("intents", "ripple_verdict"),
            ("intents", "ripple_unexpected"),
            ("pre_state", "observed_label_vector"),
        ] {
            assert!(has(path, table, column), "{table}.{column} missing on {path:?}");
        }
        let mut log = SqliteIntentLog::open(path).expect("reopen");
        log.record(&s1_trash_cmd("k-c", "msg-1"), &crate::prestate::FrozenBasis::for_test_trash())
            .expect("record");
        drop(log);
        let conn = raw_conn(path);
        let write = |verdict: Option<&str>, unexpected: Option<&str>| {
            conn.execute(
                "UPDATE intents SET ripple_verdict = ?1, ripple_unexpected = ?2 WHERE idempotency_key = 'k-c';",
                rusqlite::params![verdict, unexpected],
            )
        };
        for (verdict, unexpected) in [
            (Some("bogus"), None),
            (Some("outside_closure"), None),
            (Some("within_closure"), Some(r#"["X"]"#)),
            (None, Some(r#"["X"]"#)),
        ] {
            let refused = write(verdict, unexpected);
            assert!(
                format!("{refused:?}").contains("CHECK"),
                "({verdict:?}, {unexpected:?}) must be refused by the table CHECK on {path:?}, got {refused:?}"
            );
        }
        for (verdict, unexpected) in [
            (None, None),
            (Some("within_closure"), None),
            (Some("outside_closure"), Some(r#"["X"]"#)),
        ] {
            write(verdict, unexpected).unwrap_or_else(|e| {
                panic!("({verdict:?}, {unexpected:?}) is a legal shape on {path:?}: {e}")
            });
        }
    }
    std::fs::remove_file(&fresh).ok();
    std::fs::remove_file(&upgraded).ok();
}

/// A connector that answers the way the Gmail routes answer — `observe`
/// hands back the FULL pre-effect label set beside the atom projection, `apply_witnessed` hands
/// back the post-effect set of the route — over the VALID Trash seam basis. `FakeGmail` is
/// private to `gmail::tests`, so the bus-level witnesses ride this double: what they pin is the
/// BUS (which door it dispatches through, and what it persists), not the Gmail routes (the
/// tests in `gmail.rs` pin those).
///
/// Its plain `apply` makes the SAME effect and yields NO vector — so a bus door that dispatched
/// through `apply` instead of `apply_witnessed` persists nothing, and the witnesses see it.
struct WitnessingConnector {
    pre: std::collections::BTreeSet<String>,
    post: std::collections::BTreeSet<String>,
    /// Fail this many leading dispatches TRANSIENTLY, proven pre-wire (the recovery setup).
    fail_first: std::cell::Cell<usize>,
    dispatches: std::cell::Cell<usize>,
    /// `false` = `observe` yields NO label vector (the journal then holds
    /// no pre-effect vector, so the witness row persists with no verdict).
    observe_vector: bool,
}

impl WitnessingConnector {
    fn new(pre: &[&str], post: &[&str]) -> Self {
        WitnessingConnector {
            pre: s1_label_set(pre),
            post: s1_label_set(post),
            fail_first: std::cell::Cell::new(0),
            dispatches: std::cell::Cell::new(0),
            observe_vector: true,
        }
    }
    fn failing_first(self, n: usize) -> Self {
        self.fail_first.set(n);
        self
    }
    fn observing_no_vector(mut self) -> Self {
        self.observe_vector = false;
        self
    }
}

impl Connector for WitnessingConnector {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_witnessed(command, basis).map(|_| ())
    }
    fn apply_witnessed(
        &self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
    ) -> Result<EffectWitness, ConnectorError> {
        self.dispatches.set(self.dispatches.get() + 1);
        if self.fail_first.get() > 0 {
            self.fail_first.set(self.fail_first.get() - 1);
            return Err(ConnectorError::transient("test: connect refused").proven_no_wire());
        }
        Ok(EffectWitness { provider_label_vector: Some(self.post.clone()) })
    }
    fn resolve_basis(&self, _command: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(prestate::FrozenBasis::for_test_trash())
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(prestate::Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: basis
                .touched_atoms
                .iter()
                .map(|(atom, label)| (atom.clone(), self.pre.contains(label)))
                .collect(),
            request_id: None,
            provider_label_vector: self.observe_vector.then(|| self.pre.clone()),
        })
    }
    fn restore(
        &self,
        _command: &Command,
        _basis: &prestate::FrozenBasis,
        _p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        unreachable!("no B8 witness undoes")
    }
}

// Since `execute` refuses a bare RED verb (`PlanRequired`), these door
// witnesses drive their Trash as a PLAN CHILD of a ready, `backups: off` plan over one Inbox
// member ([`s1_plan_ready`] / [`s1_plan_bus`]); the connector's observe agrees with the
// member's approval-time state (INBOX set, TRASH clear), so the send fence admits it.
fn s1_execute_door_witness<L: IntentLog>(mut log: L, members: &[String], store: &str) {
    let plan = s1_plan_ready(&mut log, members);
    let child = Command::plan_child(&plan, &members[0]);
    let key = child.idempotency_key.clone();
    let mut bus = s1_plan_bus(log, WitnessingConnector::new(&["INBOX", "STARRED"], &["TRASH", "STARRED"]));
    bus.execute(&child).expect("the Trash applies");
    assert_eq!(bus.connector().dispatches.get(), 1);
    // `pre` is the OBSERVE read, carried on the journal row as `observed_label_vector`…
    assert_eq!(
        bus.log().captured_pre_state(&key).unwrap().expect("journaled").observed_label_vector,
        Some(s1_label_set(&["INBOX", "STARRED"])),
        "{store}"
    );
    // …and the answer of the ROUTE is persisted beside the operation, judged against it.
    assert_eq!(
        bus.log().effect_witness(&key).unwrap(),
        Some(EffectWitnessRow {
            effect_label_vector: Some(s1_label_set(&["TRASH", "STARRED"])),
            ripple_verdict: Some(prestate::RippleVerdict::WithinClosure),
        }),
        "{store}"
    );
}

fn s1_execute_door_ripple<L: IntentLog>(mut log: L, members: &[String], store: &str) {
    let plan = s1_plan_ready(&mut log, members);
    let child = Command::plan_child(&plan, &members[0]);
    let mut bus = s1_plan_bus(log, WitnessingConnector::new(&["INBOX", "IMPORTANT"], &["TRASH"]));
    bus.execute(&child).expect("the Trash applies");
    assert_eq!(
        bus.log().effect_witness(&child.idempotency_key).unwrap().expect("persisted").ripple_verdict,
        Some(prestate::RippleVerdict::OutsideClosure { unexpected: s1_label_set(&["IMPORTANT"]) }),
        "{store}"
    );
}

#[test]
fn s1_the_bus_persists_the_effect_witness_the_route_answered_on_the_execute_door() {
    let msg1 = vec!["msg-1".to_string()];
    s1_execute_door_witness(s1_twin_seeded(&["msg-1"]), &msg1, "memory");
    let path = unique_temp_db_path("s1-bus-witness");
    let log = SqliteIntentLog::open(&path).unwrap();
    let refs = s1_sqlite_seeded(&path, 1);
    s1_execute_door_witness(log, &refs, "sqlite");
    std::fs::remove_file(&path).ok();
    s1_execute_door_ripple(s1_twin_seeded(&["msg-1"]), &msg1, "memory");
    let path = unique_temp_db_path("s1-bus-ripple");
    let log = SqliteIntentLog::open(&path).unwrap();
    let refs = s1_sqlite_seeded(&path, 1);
    s1_execute_door_ripple(log, &refs, "sqlite");
    std::fs::remove_file(&path).ok();
    // A connector on the trait default observes no vector: the bus persists nothing.
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), AlwaysOkConnector);
    bus.execute(&archive_cmd("k-plain")).expect("applies");
    assert_eq!(bus.log().effect_witness("k-plain").unwrap(), None);
}

fn s1_recovery_door_witness<L: IntentLog>(mut log: L, members: &[String], store: &str) {
    let plan = s1_plan_ready(&mut log, members);
    let child = Command::plan_child(&plan, &members[0]);
    let key = child.idempotency_key.clone();
    let mut bus = s1_plan_bus(
        log,
        WitnessingConnector::new(&["INBOX", "STARRED"], &["TRASH", "STARRED"]).failing_first(1),
    );
    let first = bus.execute(&child);
    assert!(
        matches!(first, Err(ExecuteError::Connector(_))),
        "precondition: attempt 1 fails proven-pre-wire into the retry gap, got {first:?} ({store})"
    );
    assert_eq!(bus.log().effect_witness(&key).unwrap(), None, "a failed dispatch observed nothing ({store})");
    let report = bus.recover().expect("the sweep re-dispatches");
    assert_eq!(report.recovered, 1, "{store}");
    assert_eq!(bus.connector().dispatches.get(), 2, "{store}");
    assert_eq!(
        bus.log().effect_witness(&key).unwrap(),
        Some(EffectWitnessRow {
            effect_label_vector: Some(s1_label_set(&["TRASH", "STARRED"])),
            ripple_verdict: Some(prestate::RippleVerdict::WithinClosure),
        }),
        "the RECOVERY door dispatches through apply_witnessed and persists the witness too ({store})"
    );
}

#[test]
fn s1_the_bus_persists_the_effect_witness_the_route_answered_on_the_recovery_door() {
    s1_recovery_door_witness(s1_twin_seeded(&["msg-1"]), &["msg-1".to_string()], "memory");
    let path = unique_temp_db_path("s1-bus-recovery-witness");
    let log = SqliteIntentLog::open(&path).unwrap();
    let refs = s1_sqlite_seeded(&path, 1);
    s1_recovery_door_witness(log, &refs, "sqlite");
    std::fs::remove_file(&path).ok();
}

// THE UNDO PRESENTATION READS THE EFFECT WITNESS. The reader rule is
// `store_open.rs`'s DDL comment: a NULL witness on an Applied operation reads as UNDETERMINED,
// never as within-closure. Each shape below runs on BOTH stores.

/// A plan-child Trash over `members[0]` through a [`WitnessingConnector`] (`pre` observed at
/// PREPARE unless `observe_vector` is false; `post` answered by the route), then the undo
/// presentation's read of it.
fn e7_read_after_trash<L: IntentLog>(
    mut log: L,
    members: &[String],
    pre: &[&str],
    post: &[&str],
    observe_vector: bool,
) -> UndoPresentationRead {
    let plan = s1_plan_ready(&mut log, members);
    let child = Command::plan_child(&plan, &members[0]);
    let connector = WitnessingConnector::new(pre, post);
    let connector = if observe_vector { connector } else { connector.observing_no_vector() };
    let mut bus = s1_plan_bus(log, connector);
    bus.execute(&child).expect("the Trash applies");
    bus.undo_presentation(&child.idempotency_key)
        .expect("the presentation reads")
        .expect("the operation exists")
}

fn e7_restoration_shapes<L: IntentLog>(fresh: &dyn Fn() -> (L, Vec<String>), store: &str) {
    // OutsideClosure { IMPORTANT } ⇒ UNDETERMINED, naming it.
    let (log, refs) = fresh();
    let read = e7_read_after_trash(log, &refs, &["INBOX", "IMPORTANT"], &["TRASH"], true);
    assert_eq!(read.presentation, UndoPresentation::None, "{store}");
    let verdict = read.restoration.expect("an Applied operation carries a restoration verdict");
    assert_eq!(verdict, RestorationVerdict::OutsideClosure { unexpected: s1_label_set(&["IMPORTANT"]) }, "{store}");
    assert_eq!(
        verdict.undetermined_line().as_deref(),
        Some("restoration UNDETERMINED (labels outside the declared closure changed: IMPORTANT)"),
        "{store}"
    );
    // The banking rule of `live_readside.rs` `sanitize_minimal_capture`: system labels NAMED,
    // user labels COUNTED — a provider-native `Label_*` id never reaches the sentence.
    let (log, refs) = fresh();
    let read = e7_read_after_trash(log, &refs, &["INBOX", "IMPORTANT", "Label_7", "Label_9"], &["TRASH"], true);
    let line = read.restoration.expect("a verdict").undetermined_line().expect("undetermined");
    assert_eq!(line, "restoration UNDETERMINED (labels outside the declared closure changed: IMPORTANT, 2 user labels)", "{store}");
    assert!(!line.contains("Label_"), "{store}: {line}");
    let (log, refs) = fresh();
    let read = e7_read_after_trash(log, &refs, &["INBOX", "Label_7"], &["TRASH"], true);
    assert_eq!(
        read.restoration.expect("a verdict").undetermined_line().as_deref(),
        Some("restoration UNDETERMINED (labels outside the declared closure changed: 1 user label)"),
        "{store}"
    );
    // A witness row with no verdict — no pre-effect vector was journaled.
    let (log, refs) = fresh();
    let read = e7_read_after_trash(log, &refs, &["INBOX"], &["TRASH"], false);
    let verdict = read.restoration.expect("a verdict");
    assert_eq!(verdict, RestorationVerdict::NoPreEffectVector, "{store}");
    assert_eq!(
        verdict.undetermined_line().as_deref(),
        Some("restoration UNDETERMINED (no pre-effect vector)"),
        "{store}"
    );
    // WithinClosure ⇒ the ordinary offer, unchanged: no line at all.
    let (log, refs) = fresh();
    let read = e7_read_after_trash(log, &refs, &["INBOX", "STARRED"], &["TRASH", "STARRED"], true);
    assert_eq!(read.presentation, UndoPresentation::None, "{store}");
    assert_eq!(read.restoration, Some(RestorationVerdict::WithinClosure), "{store}");
    assert_eq!(RestorationVerdict::WithinClosure.undetermined_line(), None, "{store}");
}

/// A NULL witness on an Applied operation (a connector on the trait default, which observes
/// no vector) — and the same operation once UNDONE: its forward effect landed, so the
/// restoration claim is still the witness's to qualify.
fn e7_null_witness<L: IntentLog>(log: L, store: &str) {
    let mut bus = CommandBus::new(log, CountingConnector::new());
    bus.execute(&archive_cmd("k-e7-null")).expect("the archive applies");
    let read = bus.undo_presentation("k-e7-null").expect("reads").expect("exists");
    assert_eq!(read.presentation, UndoPresentation::None, "{store}");
    let verdict = read.restoration.expect("an Applied operation carries a restoration verdict");
    assert_eq!(verdict, RestorationVerdict::NoEffectWitness, "{store}");
    assert_eq!(
        verdict.undetermined_line().as_deref(),
        Some("restoration UNDETERMINED (no effect witness)"),
        "{store}"
    );
    assert_eq!(bus.restoration("k-e7-null").expect("reads"), Some(RestorationVerdict::NoEffectWitness), "{store}");
    bus.undo("k-e7-null").expect("the undo verifies");
    let read = bus.undo_presentation("k-e7-null").expect("reads").expect("exists");
    assert_eq!(read.presentation, UndoPresentation::Undone, "{store}");
    assert_eq!(read.restoration, Some(RestorationVerdict::NoEffectWitness), "{store}: an Undone operation's forward effect landed");
    // No operation, no claim.
    assert_eq!(bus.undo_presentation("k-e7-nobody").expect("reads"), None, "{store}");
    assert_eq!(bus.restoration("k-e7-nobody").expect("reads"), None, "{store}");
}

#[test]
fn e7_the_undo_presentation_reads_the_effect_witness_on_both_stores() {
    e7_restoration_shapes(&|| (s1_twin_seeded(&["msg-1"]), vec!["msg-1".to_string()]), "memory");
    let paths = std::cell::RefCell::new(Vec::new());
    e7_restoration_shapes(
        &|| {
            let path = unique_temp_db_path("e7-restoration");
            let log = SqliteIntentLog::open(&path).unwrap();
            let refs = s1_sqlite_seeded(&path, 1);
            paths.borrow_mut().push(path);
            (log, refs)
        },
        "sqlite",
    );
    e7_null_witness(InMemoryIntentLog::new(), "memory");
    let path = unique_temp_db_path("e7-null-witness");
    e7_null_witness(SqliteIntentLog::open(&path).unwrap(), "sqlite");
    paths.borrow_mut().push(path);
    for path in paths.into_inner() {
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn e7_a_pending_or_failed_operation_carries_no_restoration_claim() {
    // Only an operation whose forward effect LANDED has a restoration to qualify.
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), DeterministicFailConnector::new("refused"));
    assert!(bus.execute(&archive_cmd("k-e7-failed")).is_err());
    assert_eq!(bus.log().get("k-e7-failed").unwrap().expect("recorded").status, IntentStatus::Failed);
    assert_eq!(bus.undo_presentation("k-e7-failed").unwrap().expect("exists").restoration, None);
    let mut bus = CommandBus::new(InMemoryIntentLog::new(), AlwaysFailConnector);
    assert!(bus.execute(&archive_cmd("k-e7-pending")).is_err());
    assert_eq!(bus.log().get("k-e7-pending").unwrap().expect("recorded").status, IntentStatus::Pending);
    assert_eq!(bus.restoration("k-e7-pending").unwrap(), None);
}

/// A failpoint on the witness columns' one writer (`record_effect_witness`'s UPDATE), in the
/// `t9_replace_failpoint` technique: the store's own write path raises, so the error the bus
/// sees is the production store's `LogError`, not a double's.
const S1_WITNESS_WRITE_FAILPOINT: &str =
    "CREATE TRIGGER s1_witness_write_failpoint BEFORE UPDATE OF effect_label_vector ON intents
           BEGIN SELECT RAISE(ABORT, 'failpoint: the witness write failed'); END;";

#[test]
fn s1_a_witness_write_failure_after_the_effect_is_named_on_execute_and_on_recover_and_the_status_stays_applied() {
    // Both doors now
    // answer the SAME non-fatal shape (the fold extended the rule from `execute` to
    // `recover`, closing the gap: the OLD `Err(ExecuteError::Log)` aborted the WHOLE sweep
    // over one intent's witness-write failure, stranding a durably-`Applied` member's
    // provenance — `plan_projection_writes` then answered `Current` while the row stayed
    // stale). The witness write runs AFTER the settlement committed, and the settled status
    // stays exactly as the settlement wrote it.
    //
    // The EXECUTE door: the operation is durably APPLIED, so
    // `execute` answers the applied result — with the witness failure NAMED, never an error
    // that would discard the undo key and invite a second key for an applied operation.
    // (the Trash is a plan child — a bare RED verb is `PlanRequired`.)
    let path = unique_temp_db_path("s1-witness-write-failure-execute");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let refs = s1_sqlite_seeded(&path, 1);
    let child = Command::plan_child(&s1_plan_ready(&mut log, &refs), &refs[0]);
    let mut bus = s1_plan_bus(log, WitnessingConnector::new(&["INBOX"], &["TRASH"]));
    raw_conn(&path)
        .execute_batch(S1_WITNESS_WRITE_FAILPOINT)
        .expect("arm the failpoint");
    let answered = bus.execute(&child);
    assert_eq!(
        answered,
        Ok(Executed { witness: WitnessRecord::WriteFailed(WitnessWriteFailure::WitnessWrite) }),
        "an APPLIED operation whose witness write failed answers the applied result, the failure named"
    );
    // A retry under the SAME key re-dispatches nothing and mints nothing: it is the settled
    // operation's replay, and its restoration reads UNDETERMINED (no effect witness).
    assert_eq!(bus.execute(&child), Ok(Executed { witness: WitnessRecord::NotDispatched }));
    assert_eq!(bus.restoration(&child.idempotency_key).unwrap(), Some(RestorationVerdict::NoEffectWitness));
    assert_eq!(bus.connector().dispatches.get(), 1, "the effect was dispatched once");
    assert_eq!(
        bus.log().get(&child.idempotency_key).unwrap().expect("row").status,
        IntentStatus::Applied,
        "the settled status stands — the helper never writes the lifecycle"
    );
    assert_eq!(bus.log().effect_witness(&child.idempotency_key).unwrap(), None, "no witness was written");
    std::fs::remove_file(&path).ok();

    // The RECOVERY door: the same helper, the same posture — the sweep returns the error.
    let path = unique_temp_db_path("s1-witness-write-failure-recover");
    let mut log = SqliteIntentLog::open(&path).expect("open");
    let refs = s1_sqlite_seeded(&path, 1);
    let child = Command::plan_child(&s1_plan_ready(&mut log, &refs), &refs[0]);
    let mut bus = s1_plan_bus(log, WitnessingConnector::new(&["INBOX"], &["TRASH"]).failing_first(1));
    let first = bus.execute(&child);
    assert!(
        matches!(first, Err(ExecuteError::Connector(_))),
        "precondition: attempt 1 fails proven-pre-wire into the retry gap, got {first:?}"
    );
    raw_conn(&path)
        .execute_batch(S1_WITNESS_WRITE_FAILPOINT)
        .expect("arm the failpoint");
    let swept = bus.recover().expect("the sweep does not abort over a witness-write failure");
    assert_eq!(swept.recovered, 1, "the member is still counted recovered — it IS durably Applied");
    assert_eq!(
        swept.witness_write_failed,
        vec![child.idempotency_key.clone()],
        "the witness failure is NAMED, never silently dropped and never fatal to the sweep"
    );
    assert_eq!(bus.connector().dispatches.get(), 2, "the sweep re-dispatched once");
    assert_eq!(
        bus.log().get(&child.idempotency_key).unwrap().expect("row").status,
        IntentStatus::Applied,
        "the sweep's settled status stands"
    );
    assert_eq!(bus.log().effect_witness(&child.idempotency_key).unwrap(), None, "no witness was written");
    std::fs::remove_file(&path).ok();
}
