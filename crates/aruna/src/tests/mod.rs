//! Engine-level tests that drive the stores and the command bus together, and the fixtures they share.

use super::*;
use crate::fixtures::{fixture_basis, fixture_observation, fixture_restore, FIXTURE_KEY_PROVIDER};
use crate::sever::{read_sever_witnesses, RawSeverWitness};

/// Give a fixture connector the pre-state seam methods (`resolve_basis` + `observe` +
/// the stage-3 `restore`, which only enforces the delta-grain precondition) with
/// the SHARED fixture shape: a deterministic native basis keyed on the command's
/// `message_ref` and a stateless observation. These fixtures assert on DISPATCH, not on
/// pre-state, so one identical shape across all of them keeps the seam out of their way
/// — a fixture that needs its own basis writes the two methods by hand instead.
macro_rules! fixture_seam {
    () => {
        fn resolve_basis(
            &self,
            command: &Command,
        ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
            Ok(fixture_basis(command))
        }
        fn observe(
            &self,
            _command: &Command,
            basis: &prestate::FrozenBasis,
        ) -> Result<prestate::Observation, ConnectorError> {
            Ok(fixture_observation(basis))
        }
        fn restore(
            &self,
            _command: &Command,
            basis: &prestate::FrozenBasis,
            p: &std::collections::BTreeMap<String, bool>,
        ) -> Result<(), ConnectorError> {
            fixture_restore(basis, p)
        }
    };
}

mod adjudication;
mod boot;
mod capacity;
mod config;
mod execute;
mod parity;
mod plan;
mod prepare;
mod regressions;
mod retry;
mod send_epoch;
mod settlement;
mod sever;
mod store;
mod tripwires;
mod undo;
mod verdict;
mod witness;

/// Authorize through the store door with the CAS token the operation's CURRENT journal row
/// implies — which is exactly what a driver holding a fresh
/// read carries there.
///
/// The witnesses that predate the token are about the epoch fence, the exposure gate, the
/// grammar and the at-most-one rule; they state the capture the way every live door states
/// it, through ONE helper, instead of re-spelling a binding each of them is not about. A
/// witness that IS about the binding names it literally at the call (see
/// `the_authorization_consumes_the_generation_its_decision_read`).
fn authorize<L: IntentLog>(
    log: &mut L,
    idempotency_key: &str,
    attempt_id: &str,
) -> Result<SendAuthOutcome, LogError> {
    let capture = log
        .captured_pre_state(idempotency_key)
        // A key with no intent row at all is a legal shape for the doors that fail loud on
        // one; it simply owns no capture.
        .ok()
        .flatten()
        .map(|captured| CaptureBinding::Generation(captured.capture_generation))
        .unwrap_or(CaptureBinding::NoJournalRow);
    log.authorize_send(idempotency_key, attempt_id, capture, crate::plan::PlanBinding::Plain)
}

/// Record through the two-arg admission API (BASIS-5), freezing the basis a fixture
/// connector would have resolved for THIS command — the same shape `execute()` freezes in
/// production. Tests that assert ON the basis pass it explicitly instead.
fn record_basis<L: IntentLog>(log: &mut L, command: &Command) -> Result<Claim, LogError> {
    log.record(command, &fixture_basis(command))
}

fn archive_cmd(key: &str) -> Command {
    Command::new(
        key,
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    )
}

/// The byte-comparable projection of a store's SCHEMA — the thing the fresh-vs-upgraded
/// equivalence witness compares. Deliberately NOT `sqlite_master.sql`: `ALTER TABLE …
/// ADD COLUMN` appends the new column to the STORED TEXT after the table constraints,
/// while a fresh `CREATE TABLE` carries it inline, so the raw DDL text differs by
/// construction even when the two schemas are identical. What must be equal is the
/// column vector (order, type, NOT NULL, DEFAULT, PK rank), the index set with its
/// uniqueness and indexed columns, and the version stamp — all of which this renders
/// as one deterministic string.
fn schema_fingerprint(path: &std::path::Path) -> String {
    let conn = raw_conn(path);
    let mut out = String::new();
    out.push_str(&format!(
        "user_version={}\n",
        conn.query_row("PRAGMA user_version;", [], |r| r.get::<_, i64>(0))
            .expect("user_version")
    ));
    let objects: Vec<(String, String, String)> = conn
        .prepare("SELECT type, name, tbl_name FROM sqlite_master ORDER BY type, name;")
        .expect("sqlite_master prepare")
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("sqlite_master query")
        .map(|r| r.expect("sqlite_master row"))
        .collect();
    for (kind, name, tbl) in objects {
        out.push_str(&format!("{kind} {name} (on {tbl})\n"));
        if kind != "table" {
            continue;
        }
        let cols: Vec<String> = conn
            .prepare(
                "SELECT cid, name, type, \"notnull\", ifnull(dflt_value, '<none>'), pk
                       FROM pragma_table_info(?1) ORDER BY cid;",
            )
            .expect("table_info prepare")
            .query_map([&name], |r| {
                Ok(format!(
                    "    col[{}] {} {} notnull={} default={} pk={}",
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?
                ))
            })
            .expect("table_info query")
            .map(|r| r.expect("table_info row"))
            .collect();
        for c in cols {
            out.push_str(&c);
            out.push('\n');
        }
        let indexes: Vec<(String, i64, String, i64)> = conn
            .prepare(
                "SELECT name, \"unique\", origin, partial
                       FROM pragma_index_list(?1) ORDER BY name;",
            )
            .expect("index_list prepare")
            .query_map([&name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("index_list query")
            .map(|r| r.expect("index_list row"))
            .collect();
        for (iname, uniq, origin, partial) in indexes {
            let icols: Vec<String> = conn
                .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno;")
                .expect("index_info prepare")
                .query_map([&iname], |r| r.get::<_, Option<String>>(0))
                .expect("index_info query")
                .map(|r| r.expect("index_info row").unwrap_or_else(|| "<expr>".into()))
                .collect();
            out.push_str(&format!(
                "    idx {iname} unique={uniq} origin={origin} partial={partial} \
                 cols=[{}]\n",
                icols.join(",")
            ));
        }
    }
    out
}

/// The store path every test in this module mints — now minted by
/// the ONE guard (`crate::test_temp`), which names it `aruna-test-{tag}-{pid}-{nanos}-{seq}`,
/// removes it with its `-wal`/`-shm`/`-journal`/`.photon-init.lock` siblings on `Drop`, and
/// panics naming a leak instead of swallowing it. The guard this helper used to return
/// (`TempDbGuard`) implemented `AsRef<Path>`, so
/// `SqliteIntentLog::open(unique_temp_db_path(..))` compiled, moved the guard INTO `open`, and
/// dropped it there while the store stayed open — the delete failed on Windows and the
/// `aruna-test-s1-p-sweep-*.sqlite` of 2026-09-25 14:41 leaked. That spelling no longer
/// compiles: bind the guard, pass `&path`.
fn unique_temp_db_path(tag: &str) -> TempDbGuard {
    crate::test_temp::TempFile::sqlite(&format!("aruna-test-{tag}"))
}

type TempDbGuard = crate::test_temp::TempFile;

// RED. Was written and run against the PRE-FIX bytes, which
// returned a bare PathBuf with no Drop side effect, so it FAILED at runtime (paste in the
// commit): `the sqlite file must be gone once the guard drops`.
#[test]
fn unique_temp_db_path_deletes_its_file_and_sqlite_siblings_on_drop() {
    let path;
    let wal;
    let shm;
    let lock;
    {
        let guard = unique_temp_db_path("drop-guard-sqlite");
        path = guard.to_path_buf();
        wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
        shm = std::path::PathBuf::from(format!("{}-shm", path.display()));
        lock = std::path::PathBuf::from(format!("{}.photon-init.lock", path.display()));
        std::fs::write(&path, b"main").unwrap();
        std::fs::write(&wal, b"wal").unwrap();
        std::fs::write(&shm, b"shm").unwrap();
        std::fs::write(&lock, b"").unwrap();
        assert!(
            path.exists() && wal.exists() && shm.exists() && lock.exists(),
            "precondition: the file and its sqlite siblings exist before the guard drops"
        );
    }
    assert!(!path.exists(), "the sqlite file must be gone once the guard drops");
    assert!(!wal.exists(), "the -wal sibling must be gone once the guard drops");
    assert!(!shm.exists(), "the -shm sibling must be gone once the guard drops");
    assert!(!lock.exists(), "the .photon-init.lock sibling must be gone once the guard drops");
}

// RED companion: two calls in the same process must never mint the same path.
#[test]
fn unique_temp_db_path_never_shares_a_path_across_two_calls_in_one_process() {
    let a = unique_temp_db_path("same-tag");
    let b = unique_temp_db_path("same-tag");
    let a_owned: std::path::PathBuf = a.to_path_buf();
    let b_owned: std::path::PathBuf = b.to_path_buf();
    assert_ne!(a_owned, b_owned, "two calls in the same process must never mint the same path");
}

/// A minimal well-formed frozen basis (BASIS-1/-3/-4 shape) for the native key under test.
fn test_basis(native_resource_key: &str) -> prestate::FrozenBasis {
    prestate::FrozenBasis {
        native_resource_key: native_resource_key.to_string(),
        touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
            .into_iter()
            .collect(),
        atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
        role_bindings: std::collections::BTreeMap::new(),
        freshness: prestate::Freshness::ImmutableConstants,
    }
}

/// Deadlock diagnostic only, never a latency assertion (the `writer_gate.rs` convention).
const T6A_HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(15);

fn t6a_spin_until(label: &str, mut cond: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !cond() {
        assert!(
            started.elapsed() <= T6A_HANG_GUARD,
            "HANG GUARD: `{label}` never became true"
        );
        std::thread::yield_now();
    }
}

/// Fails the SECOND apply (transient), records the rest — leaves a same-resource predecessor
/// Pending for the tail-ordering tests.
struct FailSecondConnector {
    n: std::cell::Cell<usize>,
    applied: std::cell::RefCell<Vec<Action>>,
}
impl FailSecondConnector {
    fn new() -> Self {
        Self {
            n: std::cell::Cell::new(0),
            applied: std::cell::RefCell::new(Vec::new()),
        }
    }
}
impl Connector for FailSecondConnector {
    fixture_seam!();
    fn apply(&self, command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        let n = self.n.get() + 1;
        self.n.set(n);
        if n == 2 {
            return Err(retryable_transient("transient (second apply)"));
        }
        self.applied.borrow_mut().push(command.action.clone());
        Ok(())
    }
}

fn s1_trash_cmd(key: &str, message_ref: &str) -> Command {
    Command::new(key, "acct", Facet::Mail, Action::Trash { message_ref: message_ref.into() })
}

/// A fixed root key for the plan-child bus tests (both stores' mints take the key they are
/// handed).
pub(crate) fn test_root_key() -> crate::commitment::CommitmentKey {
    crate::commitment::CommitmentKey::from_bytes(&[0x42u8; 48]).unwrap()
}

/// A twin holding each member as an Inbox message of `acct` (the plan mint's read side).
pub(crate) fn s1_twin_seeded(members: &[&str]) -> InMemoryIntentLog {
    let mut twin = InMemoryIntentLog::new();
    for (i, m) in members.iter().enumerate() {
        twin.seed_header_for_test("acct", m, &format!("sender{i}@list.example"), "", &format!("subject {m}"), 1_758_672_000_000 + i as i64 * 1_000);
        twin.seed_placement_for_test("acct", m, crate::read_model::Placement::Inbox);
    }
    twin
}

/// `n` Inbox messages of `acct` ingested into the durable store at `path` through the read
/// side's own door; the refs it minted, in order.
pub(crate) fn s1_sqlite_seeded(path: &std::path::Path, n: usize) -> Vec<String> {
    let rows: Vec<crate::read_surface::HeaderSummary> = (1..=n)
        .map(|i| crate::read_surface::HeaderSummary {
            provider_id: crate::read_model::ProviderMessageId(format!("P-{i}")),
            received_at: 1_758_672_000_000 + i as i64 * 1_000,
            from_addr: format!("sender{i}@list.example"),
            from_name: String::new(),
            subject: format!("subject {i}"),
            seen: false,
            flagged: false,
            attachments: crate::read_surface::AttachmentPresence::default(),
        })
        .collect();
    crate::read_coordinator::ReadCoordinator::open(path).unwrap().ingest_page("acct", &rows).unwrap()
}

/// Over seeded members: `backups: off`, a Trash plan minted under [`test_root_key`] and
/// approved (full list), its episode started and marked ready. Returns the plan as read back.
pub(crate) fn s1_plan_ready<L: IntentLog>(log: &mut L, members: &[String]) -> crate::plan::TriagePlan {
    use crate::plan::{PlanSpec, RenderedView};
    let root = test_root_key();
    log.record_knob_act(crate::config_knobs::KnobAct::Backups(crate::config_knobs::BackupsKnob::Off)).unwrap();
    let minted = log.mint_plan(&root, PlanSpec { member_refs: members.to_vec(), ..PlanSpec::for_test("acct") }).unwrap();
    log.record_approval(&root, &minted.plan_id, "clinton", RenderedView::FullList(minted.presentation.clone())).unwrap();
    log.start_episode(&minted.plan_id).unwrap();
    log.mark_ready(&minted.plan_id).unwrap();
    log.plan(&minted.plan_id).unwrap().unwrap()
}

/// A bus that can authorize a plan child: an admitting ratchet (`me@e`, high-water 1 — the
/// plan's grant generation) and [`test_root_key`].
pub(crate) fn s1_plan_bus<L: IntentLog, C: Connector>(log: L, connector: C) -> CommandBus<L, C> {
    CommandBus::new(log, connector)
        .with_grant_ratchet(Box::new(crate::InMemoryGrantRatchet { high_water: Some(1), principal: "me@e".into() }))
        .with_root_key(test_root_key())
}

/// A raw second connection on the same store, pinned to the house durability profile —
/// the shape every SQL-level assertion in this module already uses.
fn raw_conn(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("raw open");
    crate::store_open::pin_durability_profile(&conn).expect("profile");
    conn
}

/// Append a config act at the next generation (the §1c ledger is append-only; a NEW act,
/// never a rewrite). The engine binds the HEAD generation at admission.
fn append_config_act(path: &std::path::Path, payload: &str) {
    let conn = raw_conn(path);
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config),
                     strftime('%s','now'), 'mode_change', ?1);",
        rusqlite::params![payload],
    )
    .expect("append config act");
}

fn sqlite_bus_with_counting_connector(
    path: &std::path::Path,
) -> CommandBus<SqliteIntentLog, CountingConnector> {
    CommandBus::new(
        SqliteIntentLog::open(path).expect("open"),
        CountingConnector::new(),
    )
}

/// A connector whose `resolve_basis` returns a STRUCTURALLY MALFORMED basis — the shape
/// `FrozenBasis::from_json` has always refused (empty native key / zero atoms), but which
/// never had to survive a round-trip because `execute()` handed the in-memory value straight
/// to `record()`.
struct MalformedBasisConnector {
    basis: prestate::FrozenBasis,
    apply_count: std::cell::Cell<usize>,
}
impl MalformedBasisConnector {
    fn new(basis: prestate::FrozenBasis) -> Self {
        Self {
            basis,
            apply_count: std::cell::Cell::new(0),
        }
    }
    fn apply_count(&self) -> usize {
        self.apply_count.get()
    }
}
impl Connector for MalformedBasisConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_count.set(self.apply_count.get() + 1);
        Ok(())
    }
    fn resolve_basis(&self, _c: &Command) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        Ok(self.basis.clone())
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        Ok(fixture_observation(basis))
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        fixture_restore(basis, p)
    }
}

/// Count rows in a store table through a raw second connection.
fn raw_count(path: &std::path::Path, table: &str) -> i64 {
    raw_conn(path)
        .query_row(&format!("SELECT COUNT(*) FROM {table};"), [], |r| r.get(0))
        .expect("count")
}

/// Hand-seed ONE `intents` row with every NOT NULL admission column supplied — the same
/// raw-SQL shape the other hand-seeded rows in this module use, parameterized over the
/// facts the scan reads (status, `journal_required`, `kind`, `frozen_basis`).
fn seed_intent(
    conn: &rusqlite::Connection,
    key: &str,
    status: &str,
    journal_required: i64,
    kind: &str,
    frozen_basis: Option<&str>,
) {
    conn.execute(
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                  status, seq, intent_id, kind, journal_required,
                                  capture_mode_generation, admitted_control_epoch, frozen_basis)
             VALUES (?1, 'acct-1', 'mail', 'archive', ?1,
                     ?2, (SELECT COALESCE(MAX(seq), 0) + 1 FROM intents),
                     lower(hex(randomblob(16))), ?3, ?4, 1, 1, ?5);",
        rusqlite::params![key, status, kind, journal_required, frozen_basis],
    )
    .expect("seed intent");
}

/// Hand-seed an expiry tombstone for a seeded intent (§6 — the reverse gap's ONLY
/// stage-2 explainer).
fn seed_tombstone(conn: &rusqlite::Connection, key: &str, journal_id: &str) {
    conn.execute(
        "INSERT INTO pre_state_tombstone (journal_id, intent_id, expired_at)
             SELECT ?2, i.intent_id, '2026-01-08T00:00:00Z'
               FROM intents i WHERE i.idempotency_key = ?1;",
        rusqlite::params![key, journal_id],
    )
    .expect("seed tombstone");
}

/// Bootstrap a v8 store, run `seed` over a raw second connection, and return the path —
/// so the NEXT open is the one whose integrity scan is under test.
fn build_store_with(
    tag: &str,
    seed: impl FnOnce(&rusqlite::Connection),
) -> TempDbGuard {
    let path = unique_temp_db_path(tag);
    SqliteIntentLog::open(&path).expect("bootstrap");
    let conn = raw_conn(&path);
    seed(&conn);
    drop(conn);
    path
}

/// The scan's report as the driver reads it: open the store, take the report the open
/// chokepoint computed.
fn open_integrity_report(path: &std::path::Path) -> Vec<IntegrityEvidence> {
    SqliteIntentLog::open(path)
        .expect("evidence NEVER refuses the open")
        .integrity_report()
        .to_vec()
}

/// Hand-seed ONE `intents` row with an EXPLICIT `message_ref` (the shape the mixed
/// legacy/new head-gate witnesses need — `seed_intent` binds `message_ref` to the key).
fn seed_intent_on_message(
    conn: &rusqlite::Connection,
    key: &str,
    message_ref: &str,
    status: &str,
    frozen_basis: Option<&str>,
) {
    conn.execute(
        "INSERT INTO intents (idempotency_key, account, facet, action_kind, message_ref,
                                  status, seq, intent_id, kind, journal_required,
                                  capture_mode_generation, admitted_control_epoch, frozen_basis)
             VALUES (?1, 'acct-1', 'mail', 'archive', ?2,
                     ?3, (SELECT COALESCE(MAX(seq), 0) + 1 FROM intents),
                     lower(hex(randomblob(16))), 'forward', 1, 1, 1, ?4);",
        rusqlite::params![key, message_ref, status, frozen_basis],
    )
    .expect("seed intent on message");
}

/// A connector whose FROZEN atom set + target vector `A` and whose PROVIDER TRUTH are
/// both settable — the shape the §3.2 requalification arms need: `P` freezes at capture,
/// then "another client" moves `C` before the undo is driven. Observe and restore
/// failures are scriptable so the deterministic-refusal and child-budget arms can be
/// driven through the REAL bus. Built on the fixture pattern (native key through
/// [`prestate::native_resource_key`], the ONE encoding authority).
struct UndoStageConnector {
    atoms: std::collections::BTreeMap<String, String>,
    targets: std::collections::BTreeMap<String, bool>,
    state: std::cell::RefCell<std::collections::BTreeMap<String, bool>>,
    /// A BROKEN RESOLVER (the live JMAP shape: a missing role mailbox or an absent state
    /// cursor refuses the basis). Set it and every later admission REFUSES — which is
    /// exactly the condition the §4.1 no-op kill must survive.
    resolve_error: std::cell::RefCell<Option<ResolveBasisError>>,
    observe_error: std::cell::RefCell<Option<ConnectorError>>,
    restore_error: std::cell::RefCell<Option<ConnectorError>>,
    restore_failures_left: std::cell::Cell<u32>,
    /// The scripted `apply` failure, when the witness cares WHICH failure it is
    /// (`fail_apply_with`); `None` keeps `fail_apply`'s plain transient.
    apply_error: std::cell::RefCell<Option<ConnectorError>>,
    apply_failures_left: std::cell::Cell<u32>,
    apply_count: std::cell::Cell<usize>,
    /// Every `restore` DISPATCH this double was entered with — success or scripted
    /// failure. `restore_count` counts EFFECTS (the `restored` log); this counts WIRE
    /// TOUCHES, which is the quantity the one-wire/ownership witnesses are about: a
    /// restore that reached the connector and came back refused still went out.
    restore_calls: std::cell::Cell<usize>,
    /// Every `observe` this double answered — the PROVIDER READ counter, so a witness can
    /// assert a path spent not even a read (the undo-ownership arm).
    observe_count: std::cell::Cell<usize>,
    /// Does a SUCCESSFUL `apply` move the provider to the forward target, as a real one
    /// does? OFF by default so the existing witnesses that script provider state by hand
    /// keep meaning what they meant; ON where a witness needs the effect to land at the
    /// moment the dispatch lands rather than before it (the retry
    /// gate observes the provider, so "the state a later step will produce" can no longer
    /// be pre-set without the retry seeing it too).
    apply_lands: std::cell::Cell<bool>,
    restored: std::cell::RefCell<Vec<(String, std::collections::BTreeMap<String, bool>)>>,
}

impl UndoStageConnector {
    /// ONE Boolean atom (`membership:INBOX`): forward target `a`, provider truth `c`.
    fn single(a: bool, c: bool) -> Self {
        Self::new(
            [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            [("membership:INBOX".to_string(), a)].into_iter().collect(),
            [("membership:INBOX".to_string(), c)].into_iter().collect(),
        )
    }
    /// The §3.1a JMAP-shaped PAIR: archive is a MOVE, so the pair has reachable third
    /// states ({both}, {neither}) an external client can produce.
    fn pair(i: bool, arch: bool) -> Self {
        Self::new(
            [
                ("membership:mb-i".to_string(), "mb-i".to_string()),
                ("membership:mb-a".to_string(), "mb-a".to_string()),
            ]
            .into_iter()
            .collect(),
            [
                ("membership:mb-i".to_string(), false),
                ("membership:mb-a".to_string(), true),
            ]
            .into_iter()
            .collect(),
            [
                ("membership:mb-i".to_string(), i),
                ("membership:mb-a".to_string(), arch),
            ]
            .into_iter()
            .collect(),
        )
    }
    fn new(
        atoms: std::collections::BTreeMap<String, String>,
        targets: std::collections::BTreeMap<String, bool>,
        state: std::collections::BTreeMap<String, bool>,
    ) -> Self {
        Self {
            atoms,
            targets,
            state: std::cell::RefCell::new(state),
            resolve_error: std::cell::RefCell::new(None),
            observe_error: std::cell::RefCell::new(None),
            restore_error: std::cell::RefCell::new(None),
            restore_failures_left: std::cell::Cell::new(0),
            apply_error: std::cell::RefCell::new(None),
            apply_failures_left: std::cell::Cell::new(0),
            apply_count: std::cell::Cell::new(0),
            restore_calls: std::cell::Cell::new(0),
            observe_count: std::cell::Cell::new(0),
            apply_lands: std::cell::Cell::new(false),
            restored: std::cell::RefCell::new(Vec::new()),
        }
    }
    /// "Another client moved the message" — the state a later `observe` answers with.
    fn set_state(&self, state: std::collections::BTreeMap<String, bool>) {
        *self.state.borrow_mut() = state;
    }
    /// From here on, a SUCCESSFUL `apply` moves the provider to the forward target.
    fn apply_lands(&self) {
        self.apply_lands.set(true);
    }
    /// Break the RESOLVER from here on (JMAP role/state-cursor absence in the field).
    fn fail_resolve(&self, error: ResolveBasisError) {
        *self.resolve_error.borrow_mut() = Some(error);
    }
    fn fail_observe(&self, error: ConnectorError) {
        *self.observe_error.borrow_mut() = Some(error);
    }
    /// Fail the next `times` restores with `error` (`u32::MAX` = always).
    fn fail_restore(&self, error: ConnectorError, times: u32) {
        *self.restore_error.borrow_mut() = Some(error);
        self.restore_failures_left.set(times);
    }
    /// Fail the next `times` FORWARD applies transiently — for burning the parent's own
    /// retry budget before an undo is asked for.
    fn fail_apply(&self, times: u32) {
        self.apply_failures_left.set(times);
    }
    /// Fail the next `times` FORWARD applies with a SPECIFIC error (`u32::MAX` = always) —
    /// the verdict-mapping table's input axis: the taxonomy kind AND the connector's
    /// positive [`EffectEvidence`] both matter now.
    fn fail_apply_with(&self, error: ConnectorError, times: u32) {
        *self.apply_error.borrow_mut() = Some(error);
        self.apply_failures_left.set(times);
    }
    fn apply_count(&self) -> usize {
        self.apply_count.get()
    }
    fn observe_count(&self) -> usize {
        self.observe_count.get()
    }
    fn restore_count(&self) -> usize {
        self.restored.borrow().len()
    }
    /// WIRE TOUCHES, not effects — see [`UndoStageConnector::restore_calls`].
    fn restore_call_count(&self) -> usize {
        self.restore_calls.get()
    }
    fn restored(&self) -> Vec<(String, std::collections::BTreeMap<String, bool>)> {
        self.restored.borrow().clone()
    }
}

impl Connector for UndoStageConnector {
    fn apply(&self, _command: &Command, _basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        let left = self.apply_failures_left.get();
        if left > 0 {
            if left != u32::MAX {
                self.apply_failures_left.set(left - 1);
            }
            return Err(self
                .apply_error
                .borrow()
                .clone()
                // `fail_apply`'s plain transient models a NETWORK failure before the
                // mutation went out — the retryable class, so it says so (§5.2b: an
                // unproven post-auth failure is ISSUANCE_UNKNOWN, never retried).
                .unwrap_or_else(|| ConnectorError::transient("apply flaky").proven_no_wire()));
        }
        self.apply_count.set(self.apply_count.get() + 1);
        if self.apply_lands.get() {
            *self.state.borrow_mut() = self.targets.clone();
        }
        Ok(())
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        if let Some(error) = self.resolve_error.borrow().clone() {
            return Err(error);
        }
        Ok(prestate::FrozenBasis {
            native_resource_key: prestate::native_resource_key(
                FIXTURE_KEY_PROVIDER,
                &[action_message_ref(&command.action)],
            ),
            touched_atoms: self.atoms.clone(),
            atom_targets: self.targets.clone(),
            role_bindings: std::collections::BTreeMap::new(),
            freshness: prestate::Freshness::ImmutableConstants,
        })
    }
    fn observe(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.observe_count.set(self.observe_count.get() + 1);
        if let Some(error) = self.observe_error.borrow().clone() {
            return Err(error);
        }
        Ok(prestate::Observation {
            native_resource_key: basis.native_resource_key.clone(),
            atoms: self.state.borrow().clone(),
            request_id: None,
            provider_label_vector: None,
        })
    }
    fn restore(
        &self,
        _command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.restore_calls.set(self.restore_calls.get() + 1);
        let left = self.restore_failures_left.get();
        if left > 0 {
            if left != u32::MAX {
                self.restore_failures_left.set(left - 1);
            }
            return Err(self
                .restore_error
                .borrow()
                .clone()
                .expect("a scripted restore failure carries its error"));
        }
        fixture_restore(basis, p)?;
        self.restored
            .borrow_mut()
            .push((basis.native_resource_key.clone(), p.clone()));
        Ok(())
    }
}

/// The Boolean atom map literal these witnesses read as `C`/`P`.
fn atoms(pairs: &[(&str, bool)]) -> std::collections::BTreeMap<String, bool> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

/// ONE provider behind TWO engines (topology). `CommandBus` owns its connector by
/// value, so a two-bus witness cannot simply hand the same double to both — and two
/// independent doubles would count two SEPARATE wires, which is exactly the thing the
/// witness must not assume away: the provider is one provider however many engines an
/// embedder points at one store. `Rc` (not `Arc`) because `Connector` carries no `Send`
/// bound and the interleave is scripted on one thread — the concurrency being modelled is
/// two INDEPENDENT DRIVERS over one durable store, not two OS threads.
#[derive(Clone)]
struct SharedWire(std::rc::Rc<UndoStageConnector>);

impl SharedWire {
    fn new(inner: UndoStageConnector) -> Self {
        SharedWire(std::rc::Rc::new(inner))
    }
    /// The shared double itself — counters, scripted failures, provider state.
    fn wire(&self) -> &UndoStageConnector {
        &self.0
    }
}

impl Connector for SharedWire {
    fn apply(&self, command: &Command, basis: &prestate::FrozenBasis) -> Result<(), ConnectorError> {
        self.0.apply(command, basis)
    }
    fn resolve_basis(
        &self,
        command: &Command,
    ) -> Result<prestate::FrozenBasis, ResolveBasisError> {
        self.0.resolve_basis(command)
    }
    fn observe(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
    ) -> Result<prestate::Observation, ConnectorError> {
        self.0.observe(command, basis)
    }
    fn restore(
        &self,
        command: &Command,
        basis: &prestate::FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        self.0.restore(command, basis, p)
    }
}

/// How many `CLAIM` facts exist for an operation (the owner id, not the user key).
fn claim_count(path: &std::path::Path, operation_id: &str) -> i64 {
    raw_conn(path)
        .query_row(
            "SELECT COUNT(*) FROM attempt_fact WHERE operation_id = ?1 AND fact_kind = 'claim';",
            rusqlite::params![operation_id],
            |r| r.get(0),
        )
        .expect("count claims")
}

/// How many `SEND_AUTHORIZED` facts an attempt's chain holds (the at-most-one property).
fn send_authorized_count(path: &std::path::Path, attempt_id: &str) -> i64 {
    raw_conn(path)
        .query_row(
            "SELECT COUNT(*) FROM attempt_fact
                  WHERE attempt_id = ?1 AND fact_kind = 'send_authorized';",
            rusqlite::params![attempt_id],
            |r| r.get(0),
        )
        .expect("count authorizations")
}

/// The one attempt id an operation holds (this build claims ordinal 1 only).
fn attempt_id_of(path: &std::path::Path, key: &str) -> String {
    raw_conn(path)
        .query_row(
            "SELECT attempt_id FROM attempt_fact
                  WHERE operation_id = (SELECT intent_id FROM intents WHERE idempotency_key = ?1)
                    AND fact_kind = 'claim';",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .expect("the operation holds a CLAIM")
}

/// The fact kinds of an attempt's chain, in revision order.
fn chain_kinds(path: &std::path::Path, attempt_id: &str) -> Vec<String> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT fact_kind FROM attempt_fact WHERE attempt_id = ?1 ORDER BY revision;",
        )
        .expect("prepare");
    let kinds = stmt
        .query_map(rusqlite::params![attempt_id], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|k| k.expect("row"))
        .collect();
    kinds
}

/// A REAL SEVER, from a control-plane driver of its own. This replaced the direct-SQL
/// epoch bump these witnesses were built on: `IntentLog::sever` is the production writer
/// of `control_epoch`, so every epoch move a witness scripts is now the whole primitive —
/// the bump, the §5.2c partition, the §5.1 witness row and the member closures — and the
/// fence is being witnessed against the transaction it actually races.
fn sever_from_control_plane(path: &std::path::Path, authority_ref: &str) -> SeverOutcome {
    let mut control = SqliteIntentLog::open(path).expect("open the severing driver");
    control.sever(authority_ref, &sever_now()).expect("sever")
}

/// The parent's OPAQUE `intent_id` — what the undo child's reserved key rides (§4.5).
fn opaque_intent_id(path: &std::path::Path, key: &str) -> String {
    raw_conn(path)
        .query_row(
            "SELECT intent_id FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .expect("the intent exists")
}

fn status_str(path: &std::path::Path, key: &str) -> String {
    raw_conn(path)
        .query_row(
            "SELECT status FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .expect("the intent exists")
}

/// Seed a live same-resource predecessor on `msg-1` so the next undo DEFERS its child
/// (Pending, undriven) — the only shape in which recover owns the drive.
fn seed_pending_peer<C: Connector>(
    path: &std::path::Path,
    bus: &CommandBus<SqliteIntentLog, C>,
    key: &str,
) {
    let mut log = SqliteIntentLog::open(path).expect("open");
    let peer = Command::new(
        key,
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: "msg-1".into(),
        },
    );
    let basis = bus.connector().resolve_basis(&peer).expect("resolve peer basis");
    log.record(&peer, &basis).expect("seed the pending peer");
}

/// Terminalize a seeded peer so ONLY the deferred undo child is left non-terminal.
fn terminalize_peer(path: &std::path::Path, key: &str) {
    raw_conn(path)
        .execute(
            "UPDATE intents SET status = 'failed' WHERE idempotency_key = ?1;",
            rusqlite::params![key],
        )
        .expect("terminalize the predecessor");
}

/// A retryable transient whose connector PROVED no request bytes left the host — the
/// Gmail connect-stage class (`send_stage_verdict`'s `is_connect()` arm). The fixtures
/// that model "the network failed before the mutation went out" say so explicitly, because
/// under §5.2b absence of proof is never proof.
fn retryable_transient(message: &str) -> ConnectorError {
    ConnectorError::transient(message).proven_no_wire()
}

/// A DEFINITIVE provider refusal: the provider answered and rejected before any effect
/// (the 4xx-class validation/permission/missing-target response).
fn definitive_refusal(message: &str) -> ConnectorError {
    ConnectorError::deterministic(message).proven_refused_no_effect()
}

/// The `attempt_head` projection row: `(current_revision, derived_class,
/// last_verified_revision)`.
fn head_of(path: &std::path::Path, attempt_id: &str) -> (i64, String, i64) {
    raw_conn(path)
        .query_row(
            "SELECT current_revision, derived_class, last_verified_revision
                   FROM attempt_head WHERE attempt_id = ?1;",
            rusqlite::params![attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("the attempt has a head")
}

/// The operation's durable dispatch EPISODE (`intents.attempts` — the retry budget).
fn attempts_of(path: &std::path::Path, key: &str) -> i64 {
    raw_conn(path)
        .query_row(
            "SELECT attempts FROM intents WHERE idempotency_key = ?1;",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .expect("the intent exists")
}

/// The caller's wall clock, in the ONE canonical spelling the sever door accepts.
fn sever_now() -> String {
    prestate::rfc3339_utc(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// An archive command on a NAMED resource — several operations in one store need several
/// resources, or the tail barrier (not the thing under test here) decides the outcome.
fn archive_of(key: &str, message_ref: &str) -> Command {
    Command::new(
        key,
        "acct-1",
        Facet::Mail,
        Action::Archive {
            message_ref: message_ref.into(),
        },
    )
}

/// Admit one operation through the durable door, with a real frozen basis.
fn admit(log: &mut SqliteIntentLog, command: &Command) {
    let basis = UndoStageConnector::single(false, true)
        .resolve_basis(command)
        .expect("basis");
    log.record(command, &basis).expect("admit");
}

/// Admit + CLAIM: the claimed-unauthorized shape (§5.2c bullet 3, first arm).
fn admit_and_claim(log: &mut SqliteIntentLog, command: &Command) -> String {
    admit(log, command);
    claim_now(log, &command.idempotency_key, 0)
}

/// Claim at the caller's observed episode, expecting to win.
fn claim_now(log: &mut SqliteIntentLog, key: &str, observed_attempts: u32) -> String {
    match log
        .claim_attempt(
            key,
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the first claim must win, got {other:?}"),
    }
}

/// Every `sever_witness` row in the store, RAW (unreconciled) — the shape §5.1 persists.
fn witness_rows(path: &std::path::Path) -> Vec<RawSeverWitness> {
    read_sever_witnesses(&raw_conn(path)).expect("read the sever witnesses")
}

/// The one witness row written at `epoch`, RAW.
fn witness_row(path: &std::path::Path, epoch: i64) -> RawSeverWitness {
    witness_rows(path)
        .into_iter()
        .find(|r| r.epoch == epoch)
        .unwrap_or_else(|| panic!("no sever witness row at epoch {epoch}"))
}

/// The class a witness recorded for one member, keyed by the id the caller knows.
fn member_class(
    witness: &SeverWitness,
    id: &str,
) -> Option<crate::attempt::WitnessClass> {
    use crate::attempt::{WitnessClass, WitnessMember};
    witness.members.iter().find_map(|m| match m {
        WitnessMember::Operation { operation_id } if operation_id == id.as_bytes() => {
            Some(WitnessClass::NoActiveAttempt)
        }
        WitnessMember::Attempt {
            attempt_id,
            class_at_sever,
            ..
        } if attempt_id == id.as_bytes() => Some(*class_at_sever),
        _ => None,
    })
}

/// Authorize through the REAL door and stop there: the store is left in the
/// commit-to-socket gap (§5.2b truth 3) — exactly what a crash in that window leaves.
fn authorize_now(log: &mut SqliteIntentLog, key: &str, attempt_id: &str) {
    match authorize(log, key, attempt_id).expect("authorize") {
        SendAuthOutcome::Authorized { .. } => {}
        other => panic!("the first authorization must be granted, got {other:?}"),
    }
}

/// Open the store expecting a REFUSAL, and hand back its message (`SqliteIntentLog` is not
/// `Debug`, so `expect_err` is not available).
fn open_refusal(path: &std::path::Path) -> String {
    match SqliteIntentLog::open(path) {
        Ok(_) => panic!("the open must refuse"),
        Err(e) => format!("{e}"),
    }
}

/// The journal row an operation owns: `(journal_id, observed, touched_atom)`.
fn journal_row_of(path: &std::path::Path, key: &str) -> (String, String, String) {
    raw_conn(path)
        .query_row(
            "SELECT p.journal_id, p.observed, p.touched_atom FROM pre_state p
                   JOIN intents i ON i.intent_id = p.intent_id
                  WHERE i.idempotency_key = ?1;",
            rusqlite::params![key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("the operation owns a journal row")
}

/// A capture-ON forward operation parked in its §5.2c RETRY GAP: attempt 1 claimed,
/// authorized, dispatched and settled `FAILED_PRE_SEND` (transient + proven-no-wire),
/// the operation still `Pending` with one charge on its durable budget.
fn park_in_the_retry_gap(bus: &mut CommandBus<SqliteIntentLog, SharedWire>, key: &str) {
    let outcome = bus.execute(&archive_cmd(key));
    assert!(
        matches!(outcome, Err(ExecuteError::Connector(_))),
        "the scripted transient failure is the retry gap's entry; got {outcome:?}"
    );
}

/// Drive an operation to ISSUANCE_UNKNOWN through the REAL doors — admit, claim,
/// authorize, and take an INDETERMINATE connector failure. This is the only state §5.2d
/// adjudicates, and it is reached here the way production reaches it.
fn unknown_attempt(log: &mut SqliteIntentLog, command: &Command) -> String {
    let key = command.idempotency_key.as_str();
    let attempt = admit_and_claim(log, command);
    authorize_unknown(log, key, &attempt);
    attempt
}

/// The authorize+ambiguous half of [`unknown_attempt`], for an already-claimed attempt.
fn authorize_unknown(log: &mut SqliteIntentLog, key: &str, attempt: &str) {
    assert!(
        matches!(
            authorize(log, key, attempt).expect("authorize"),
            SendAuthOutcome::Authorized { .. }
        ),
        "precondition: the attempt authorizes"
    );
    let settled = log
        .settle_attempt(
            key,
            attempt,
            ConnectorVerdict::Failed {
                kind: FailureKind::Transient,
                evidence: EffectEvidence::Indeterminate,
            },
            RETRY_CAP,
            None,
        )
        .expect("settle");
    assert!(
        matches!(
            settled,
            SettleOutcome::Settled {
                lifecycle: SettledLifecycle::AwaitingAdjudication,
                ..
            }
        ),
        "precondition: an indeterminate failure is ISSUANCE_UNKNOWN, got {settled:?}"
    );
}

/// Adjudicate through the durable door, expecting it to land; returns the record id.
fn adjudicate_now(log: &mut SqliteIntentLog, key: &str, attempt: &str) -> String {
    match log
        .adjudicate(
            key,
            attempt,
            "authority:operator-adjudicator",
            crate::attempt::AdjudicationReason::PresumedTransportLoss,
            crate::attempt::AcceptedRisk::NoneClaimed,
        )
        .expect("adjudicate")
    {
        AdjudicationOutcome::Adjudicated {
            adjudication_id, ..
        } => adjudication_id,
        other => panic!("the adjudication must land, got {other:?}"),
    }
}

/// The EXP-1 atom identity of the fixture connector's ONE atom on a message.
fn fixture_atom(message_ref: &str) -> String {
    crate::attempt::exposure_atom_key(
        &prestate::native_resource_key(FIXTURE_KEY_PROVIDER, &[message_ref]),
        "membership:INBOX",
    )
}

/// Every `exposure_obligation` row: `(atom, direction, generation, contributor, retired)`.
fn obligation_rows(path: &std::path::Path) -> Vec<(String, String, i64, String, bool)> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT primitive_atom, direction, generation, contributor_attempt_id,
                        retired_at IS NOT NULL
                   FROM exposure_obligation ORDER BY rowid;",
        )
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)? == 1,
            ))
        })
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    rows
}

/// The adjudication record id of an attempt (one per adjudicated attempt).
fn adjudication_id_of(path: &std::path::Path, attempt_id: &str) -> String {
    raw_conn(path)
        .query_row(
            "SELECT adjudication_id FROM adjudication_record WHERE attempt_id = ?1;",
            rusqlite::params![attempt_id],
            |r| r.get(0),
        )
        .expect("the attempt holds an adjudication record")
}

/// The annotation kinds hanging on one adjudication record, in append order.
fn annotation_kinds(path: &std::path::Path, adjudication_id: &str) -> Vec<String> {
    let conn = raw_conn(path);
    let mut stmt = conn
        .prepare(
            "SELECT kind FROM adjudication_annotation WHERE adjudication_id = ?1
                  ORDER BY rowid;",
        )
        .expect("prepare");
    let kinds = stmt
        .query_map(rusqlite::params![adjudication_id], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|k| k.expect("row"))
        .collect();
    kinds
}

/// The `pre_state.capture_generation` an operation's journal row carries — WHICH capture
/// it is (1 = PREPARE's, 2+ = a retry-requalification RE-PREPARE's).
fn capture_generation_of(path: &std::path::Path, key: &str) -> i64 {
    raw_conn(path)
        .query_row(
            "SELECT p.capture_generation FROM pre_state p
                   JOIN intents i ON i.intent_id = p.intent_id
                  WHERE i.idempotency_key = ?1;",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .expect("the operation owns a journal row")
}

/// The one attempt an operation's head projection holds (these witnesses drive exactly
/// one attempt per operation).
fn attempt_of(path: &std::path::Path, key: &str) -> String {
    raw_conn(path)
        .query_row(
            "SELECT h.attempt_id FROM attempt_head h
                   JOIN intents i ON i.intent_id = h.operation_id
                  WHERE i.idempotency_key = ?1;",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .expect("the operation holds an attempt")
}

fn in_memory_claim(log: &mut InMemoryIntentLog, key: &str) -> String {
    match log
        .claim_attempt(
            key,
            &AttemptClaim {
                ordinal: 1,
                predecessor: None,
                observed_attempts: 0,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Won { attempt_id, .. } => attempt_id,
        other => panic!("the claim must win, got {other:?}"),
    }
}

fn in_memory_authorize(log: &mut InMemoryIntentLog, key: &str, attempt: &str) {
    match authorize(log, key, attempt).expect("authorize") {
        SendAuthOutcome::Authorized { .. } => {}
        other => panic!("the authorization must be granted, got {other:?}"),
    }
}
