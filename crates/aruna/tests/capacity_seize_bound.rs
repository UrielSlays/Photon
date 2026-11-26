//! The pinned-profile contention benchmark (PHOTON_PERF-gated), gated exactly
//! like `perf_floor_gates.rs:58`: default `cargo test` returns immediately, `PHOTON_PERF=1` runs
//! the real thing.
//!
//! Run: `PHOTON_PERF=1 cargo test --manifest-path crates/aruna/Cargo.toml --test
//! capacity_seize_bound -- --nocapture`
//!
//! ## What this measures (design §5.3, the scope-fence's 250ms contention benchmark)
//!
//! At the DEFAULT cap (1024 active operations), under N=4 background writers of each of TWO
//! shapes, K re-seed+sever cycles time `begin_sever -> completion` (measured here at the
//! `IntentLog::sever` call boundary, which brackets exactly that window: `sever()`'s body calls
//! `WriterGate::begin_sever` as its first act and returns only after the coalesced service is
//! durably complete). HARD gate: `max <= 250ms` per (population, pending-reduction) arm.
//!
//! ## Seeding approach (stated per the plan's own instruction)
//!
//! Plain `IntentLog::record` calls on freshly-constructed `Command`/`FrozenBasis` values built
//! the same way the crate's own internal `fixture_basis` test helper does (a stateless,
//! provider-constant basis — `native_resource_key` + one `membership:INBOX` touched atom) — NOT
//! a hermetic connector. §5.3's admission door only needs a well-formed frozen basis to count an
//! operation as occupying a slot; nothing about the SEVER latency this file measures depends on
//! what a connector would have resolved, and `record()` never calls a connector itself. This
//! matches the dispatch's own permission ("a hermetic connector is NOT needed if record()-level
//! seeding suffices").
//!
//! ## TRUE 1024, not 960
//!
//! Plain forward `record()` calls alone can never reach 1024: forward admission answers to
//! `active_forward + batch <= max_active_ops - undo_reserve` (960 at DEFAULT bounds), so
//! `reseed_to_cap` — looping `record()` until `Claim::CapacityRefused` — stops at 960 by
//! construction and never touches the 64-slot PROTECTED UNDO RESERVE at all. Pre-fix this file
//! measured `sever()` over a 960-row pool while calling it "the 1024-op gate".
//!
//! An UNDO (remedy) claim answers to the total cap ONLY (design §5.3's whole point — the
//! reserve exists to keep exactly that headroom free for it), so filling the reserve needs 64
//! rows with `Command.compensates.is_some()`. That field is deliberately `pub(crate)` (its own
//! doc: "so an external caller cannot inject a link pointing at an unrelated intent"), and this
//! file is an EXTERNAL integration test — it sees only `aruna`'s public surface. The one public
//! door that mints such a row is `CommandBus::undo()`, via [`seed_undo_reserve`]; see that
//! function's doc for the three-admission recipe (parent / blocker / deferred child) the
//! engine's OWN `has_pending_same_resource_predecessor` machinery makes necessary — every public
//! fixture connector this crate exposes reports the SAME stateless observation the forward
//! target is built from, so the ordinary §4.1 no-op-kill path resolves an undo child straight to
//! a TERMINAL status (occupying nothing) unless something keeps it deferred.
//!
//! Each cycle's true-1024 seed order is REMEDIES FIRST, then `reseed_to_cap`: every remedy
//! unit's own transient forward admission (the parent, before it reaches `Applied` and drops
//! out of occupancy) needs no reserve headroom while occupancy is still ~0, and `reseed_to_cap`
//! afterward fills the remaining `960 - 64 = 896` forward slots the 64 blockers left. The
//! resulting member count — asserted via a raw `COUNT(*)` immediately before every `sever()`
//! call, never inferred from what was requested — is exactly 1024 per cycle.
//!
//! ## Why a `sever()` call always re-seeds THE WHOLE POOL, and the K reduction
//!
//! `sever()`'s kill transaction (`lead_sever_service` in `lib.rs`) partitions and terminalizes
//! **every** currently non-terminal intent in the store — its `SELECT ... WHERE status IN
//! NON_TERMINAL_STATUS_SQL` carries no `LIMIT` and no account filter. So a sever at cap does not
//! leave 1023 operations behind for the next cycle to reuse: the pool is empty the instant the
//! transaction commits, and "K cycles at cap" means K full re-admissions of 1024 fresh operations
//! each, not one seed followed by K severs. The plan's own text anticipates this ("K=50 ... is
//! expensive at 1024 ... K=10 if 50 is impractical; state it") — this file states it: with 2
//! populations x 2 arms (with/without a pending reduction) that is 4 x K re-seeds of 1024 rows
//! plus 4 x K full-pool severs, and a from-scratch local run at K=50 ran past the 10-minute class
//! this benchmark is meant to stay inside (perf_floor_gates.rs's 1M-row corpus build is the same
//! order of magnitude of work, once). K=10 keeps the gate honest — every one of the 40 cycles is
//! still a genuine at-cap sever under real writer contention, timed independently, and the gate
//! is `max`, never an average that a shorter run could flatter.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use aruna::capacity::CapacityConfig;
use aruna::message_header::SqliteMessageHeaderStore;
use aruna::prestate::{native_resource_key, rfc3339_utc, FrozenBasis, Freshness};
use aruna::read_coordinator::{ProjectionWrite, ReadCoordinator};
use aruna::read_model::ProviderMessageId;
use aruna::read_surface::{AttachmentPresence, HeaderSummary};
use aruna::{
    Action, AlwaysOkConnector, AttemptClaim, CaptureBinding, Claim, ClaimOutcome, Command,
    CommandBus, ExecuteError, Facet, IntentLog, IntentStatus, MailFlag, SqliteIntentLog,
};

/// K full re-seed+sever cycles per (population, arm) — see the module doc's "Why a `sever()`
/// call always re-seeds THE WHOLE POOL" section for why 50 was assessed impractical and this is
/// the stated reduction.
const K: usize = 10;
/// N=4 background writers per population (design's own N=4, both §5.3 mixed writers and §7c
/// send-authorizers — this file runs BOTH, per the fold discharging the design's own
/// apparent conflict by doing both).
const N_WRITERS: usize = 4;
/// The HARD gate (design's own scope-fence: "the 250 ms contention benchmark").
const HARD_GATE_US: u128 = 250_000;

const DEFAULT_CAPACITY_JSON: &str = r#"{"capacity":{"max_active_ops":1024,"undo_reserve":64,
    "writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#;
/// A capacity act that does NOT fit a store re-seeded to the 1024 default cap — planted AFTER
/// re-seeding, so it stays PENDING through (almost all of) the sever that follows: design's
/// "the trigger's expensive path — the WHEN clause evaluates full occupancy each status
/// write".
// (EXECUTED): the earlier 960/64 fixture ACTIVATED at closure ~127 of a
// 1024-member sever (forward bound 896 fits almost immediately as members drain), leaving
// ~897 of the arm's status writes on the CHEAP prefilter — the 250ms PASS was not bounding
// the expensive path it claimed. The DOMAIN-FLOOR reduction (64/32, the smallest forward
// bound an in-domain act can carry) stays pending until closure ~992, so ~97% of the sever's
// firings now ride the full WHEN clause — the honest worst case.
const PENDING_REDUCTION_JSON: &str = r#"{"capacity":{"max_active_ops":64,"undo_reserve":32,
    "writer_chunk_budget_ms":50,"sever_watchdog_ms":5000,"sever_joiner_cap":16}}"#;

/// minted by the ONE guard (`aruna::test_temp`) — unique per call, the
/// store family removed when the guard drops, a leak a loud failure. Bind it before the store.
fn unique_temp_db_path(tag: &str) -> aruna::test_temp::TempFile {
    aruna::test_temp::TempFile::sqlite(&format!("aruna-seize-bound-{tag}"))
}

fn archive_cmd(key: &str, message_ref: &str) -> Command {
    Command::new(
        key,
        "acct-bench",
        Facet::Mail,
        Action::Archive { message_ref: message_ref.to_string() },
    )
}

/// The SAME stateless, provider-constant basis shape `lib.rs`'s own `fixture_basis` test helper
/// builds — see the module doc's "Seeding approach" section.
fn fixture_basis_for(command: &Command) -> FrozenBasis {
    let message_ref = match &command.action {
        Action::Archive { message_ref } => message_ref.clone(),
        other => panic!("fixture_basis_for: unexpected action {other:?}"),
    };
    FrozenBasis {
        native_resource_key: native_resource_key("bench-fixture", &[&message_ref]),
        touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
            .into_iter()
            .collect(),
        atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
        role_bindings: BTreeMap::new(),
        freshness: Freshness::ImmutableConstants,
    }
}

fn sever_now() -> String {
    rfc3339_utc(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

fn capacity_config(json: &str) -> CapacityConfig {
    CapacityConfig::from_engine_payload(json).expect("the benchmark's own capacity JSON is valid")
}

/// Re-admit fresh operations, under WHATEVER bounds currently apply, until the derived-occupancy
/// admission door refuses (`Claim::CapacityRefused`) — i.e. until the pool is at cap (or as close
/// to it as the current bounds allow, which matters for the pending-reduction arm: forward
/// admissions answer to the NEW, smaller bounds the instant a reduction is planted — design).
/// Returns how many fresh operations THIS call admitted.
fn reseed_to_cap(log: &mut SqliteIntentLog, tag_prefix: &str) -> usize {
    let mut admitted = 0usize;
    let mut i = 0usize;
    loop {
        let key = format!("{tag_prefix}-{i}");
        i += 1;
        let cmd = archive_cmd(&key, &format!("m-{key}"));
        let basis = fixture_basis_for(&cmd);
        match log.record(&cmd, &basis) {
            Ok(Claim::Inserted) => admitted += 1,
            Ok(Claim::CapacityRefused(_)) => break,
            // A fresh key should never already exist; tolerate it rather than fail the
            // benchmark if it somehow does (defensive, not expected).
            Ok(Claim::AlreadyExisted) => {}
            // Only a command carrying a plan link can meet the plan-child arm, and
            // an archive command carries none.
            Ok(Claim::PlanChildRefused(r)) => panic!("reseed_to_cap: a plan-child refusal on an unlinked command: {r:?}"),
            Err(e) => panic!("reseed_to_cap: record failed unexpectedly: {e:?}"),
        }
        assert!(i < 20_000, "reseed_to_cap: did not reach cap within a sane attempt bound");
    }
    admitted
}

/// fill `count` slots of the PROTECTED UNDO RESERVE `reseed_to_cap` cannot
/// reach (see the module doc's "TRUE 1024" section for why). `Command.compensates` is
/// deliberately `pub(crate)`, so `CommandBus::undo()` is the one PUBLIC door this external test
/// can use to mint a `compensates.is_some()` row — and every public fixture connector answers
/// `observe()` with the SAME stateless observation the forward target is built from, so `P == A`
/// structurally for every fixture-driven undo: the §4.1 no-op kill always fires and, left alone,
/// resolves the child SYNCHRONOUSLY to a TERMINAL status (`undoing_an_applied_command_records_
/// the_undo_and_marks_it_undone`'s own child ends `Applied`, occupying nothing).
///
/// The engine's OWN `has_pending_same_resource_predecessor` (`lib.rs`) is what defers that: even
/// inside the no-op-kill branch, an undo child whose (account, message_ref) still carries a LIVE
/// non-terminal predecessor is parked (`park_or_replay` -> `Err(InProgress)`) rather than
/// resolved, and stays `Pending` — non-terminal, `compensates.is_some()`, exactly the reserve
/// row this benchmark needs. So each remedy unit is THREE admissions sharing one message ref:
///
/// 1. **parent** — a plain forward, driven through `CommandBus::execute` all the way to
///    `Applied` (TERMINAL — occupies nothing once done). Run FIRST, while occupancy is still
///    ~0, so this admission's own momentary forward-reserve headroom never competes with the
///    blocker below.
/// 2. **blocker** — a plain forward on the SAME message ref, admitted directly via `record()`
///    (never executed) so it stays `Pending` forever — the row that actually consumes one of
///    the 1024 slots, and the live predecessor that keeps the child below from resolving
///    synchronously.
/// 3. **`bus.undo(parent)`** — admits the child, sees `blocker` still non-terminal on the same
///    `(account, message_ref)`, and defers it. Asserted as `Err(ExecuteError::InProgress)`
///    rather than swallowed: a future engine change that resolves this synchronously must fail
///    LOUD here, never silently under-seed the reserve again.
///
/// Call this BEFORE `reseed_to_cap` each cycle — see the module doc's seed-ordering note.
fn seed_undo_reserve(path: &std::path::Path, tag: &str, count: usize) {
    let mut bus = CommandBus::new(
        SqliteIntentLog::open(path).expect("seed_undo_reserve: bus log open"),
        AlwaysOkConnector,
    );
    let mut blocker_log =
        SqliteIntentLog::open(path).expect("seed_undo_reserve: blocker log open");
    for i in 0..count {
        let message_ref = format!("m-remedy-{tag}-{i}");
        let parent_key = format!("remedy-parent-{tag}-{i}");
        let blocker_key = format!("remedy-blocker-{tag}-{i}");

        let parent_cmd = archive_cmd(&parent_key, &message_ref);
        bus.execute(&parent_cmd)
            .expect("seed_undo_reserve: parent execute must succeed (AlwaysOkConnector)");
        assert_eq!(
            bus.log()
                .get(&parent_key)
                .expect("seed_undo_reserve: parent get")
                .expect("seed_undo_reserve: parent row must exist")
                .status,
            IntentStatus::Applied,
            "seed_undo_reserve: undo() is eligible only once the parent reaches Applied"
        );

        let blocker_cmd = archive_cmd(&blocker_key, &message_ref);
        let blocker_basis = fixture_basis_for(&blocker_cmd);
        match blocker_log.record(&blocker_cmd, &blocker_basis) {
            Ok(Claim::Inserted) => {}
            other => panic!("seed_undo_reserve: blocker admission failed: {other:?}"),
        }

        let outcome = bus.undo(&parent_key);
        assert!(
            matches!(outcome, Err(ExecuteError::InProgress)),
            "seed_undo_reserve: expected the child to defer behind its live blocker \
             (Err(InProgress)), got {outcome:?} — the reserve seeding contract broke"
        );
    }
}

/// The SHARED background-writer harness: spawn `N_WRITERS` threads running `body` until told to
/// stop, return the stop flag (for the caller to flip) and the join handles plus a PER-THREAD
/// iteration counter (for the evidence file's "background load" line AND the per-writer
/// progress assertion in [`stop_population`]).
///
/// **READINESS-BARRIERED.** Spawning a thread proves nothing about it
/// RUNNING — pre-fix, an arm could start its timed cycles while some of the four required
/// writers were still inside their first lazy open, so "N=4 background writers" was a spawn
/// count, not a contention fact, and the aggregate post-stop counter could not tell a
/// never-ran writer from a slow one. Each writer now executes ONE real `body` iteration
/// (which performs its thread-local open and a genuine write) and then waits on a barrier;
/// this function returns only after every writer has crossed it — so the timed section never
/// begins before all `count` writers have demonstrably written. The per-thread counters make
/// the DURING-the-arm progress assertable at stop: `>= 2` means at least one iteration past
/// the readiness one (see `stop_population`).
fn spawn_writers<F>(
    count: usize,
    body: F,
) -> (Arc<AtomicBool>, Arc<Vec<AtomicUsize>>, Vec<std::thread::JoinHandle<()>>)
where
    F: Fn(usize) + Send + Clone + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let iterations: Arc<Vec<AtomicUsize>> =
        Arc::new((0..count).map(|_| AtomicUsize::new(0)).collect());
    let ready = Arc::new(std::sync::Barrier::new(count + 1));
    let mut handles = Vec::with_capacity(count);
    for idx in 0..count {
        let stop = Arc::clone(&stop);
        let iterations = Arc::clone(&iterations);
        let ready = Arc::clone(&ready);
        let body = body.clone();
        handles.push(std::thread::spawn(move || {
            // One REAL iteration before the barrier — the readiness proof, not a warm-up.
            body(idx);
            let mut n = 1usize;
            ready.wait();
            while !stop.load(Ordering::Relaxed) {
                body(idx);
                n += 1;
            }
            iterations[idx].store(n, Ordering::Relaxed);
        }));
    }
    ready.wait();
    (stop, iterations, handles)
}

fn summary(id: &str, received_at: i64, subject: &str) -> HeaderSummary {
    HeaderSummary {
        provider_id: ProviderMessageId(id.to_string()),
        received_at,
        from_addr: "bench@example.test".to_string(),
        from_name: "Bench".to_string(),
        subject: subject.to_string(),
        seen: false,
        flagged: false,
        attachments: AttachmentPresence::default(),
    }
}

/// Population (a): N=4 MIXED writers — admission attempts, header upserts, coordinator ingest,
/// and verb-delta-shaped writes, round-robin, reusing proven CHURN shapes (a fixed key
/// per writer per role, so background load never competes with the main cycle's own re-seed key
/// space and never grows the pool the capacity math is about). "Admission attempts" churns the
/// SAME key every iteration, `t7_spawn_churn`'s own shape (`lib.rs`): the
/// duplicate-claim path resolves BEFORE the capacity check even runs, so it enrolls and
/// contends the write lock without ever touching occupancy.
fn run_mixed_population(path: &std::path::Path, tag: &str) -> Arc<Vec<AtomicUsize>> {
    let path = path.to_path_buf();
    let tag = tag.to_string();
    let (stop, iterations, handles) = spawn_writers(N_WRITERS, {
        let path = path.clone();
        let tag = tag.clone();
        move |idx: usize| {
            thread_local! {
                static STATE: std::cell::RefCell<Option<MixedState>> = const { std::cell::RefCell::new(None) };
            }
            STATE.with(|cell| {
                let mut slot = cell.borrow_mut();
                if slot.is_none() {
                    *slot = Some(MixedState::open(&path, &tag, idx));
                }
                slot.as_mut().unwrap().step();
            });
        }
    });
    // The caller owns lifecycle (stop + join); stash both on the shared iterations handle's
    // companion via a leaked closure is unnecessary — return handles through a side channel.
    POPULATION_HANDLES.with(|c| c.borrow_mut().push((stop, Arc::clone(&iterations), handles)));
    iterations
}

/// (stop flag, per-thread iteration counters, join handles) for one running population — named
/// so the thread-local below stays under clippy's `type_complexity` threshold.
type PopulationHandle = (Arc<AtomicBool>, Arc<Vec<AtomicUsize>>, Vec<std::thread::JoinHandle<()>>);

thread_local! {
    // Test-harness plumbing only: `spawn_writers` cannot return the (stop, handles) pair AND a
    // plain iteration counter through one `Arc` without a second type — this keeps
    // `run_mixed_population`/`run_send_authorizer_population`'s call sites to "start, get a
    // counter, stop later" without a bespoke struct per population. Cleared per combination by
    // `stop_population`.
    static POPULATION_HANDLES: std::cell::RefCell<Vec<PopulationHandle>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn stop_population() {
    POPULATION_HANDLES.with(|c| {
        for (stop, iterations, handles) in c.borrow_mut().drain(..) {
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                h.join().expect("background writer thread");
            }
            // per-writer progress, asserted — `>= 2` is the readiness
            // iteration PLUS at least one inside the arm's own window. An arm whose latency
            // table was produced with a writer that never ran during it is not the N=4
            // contention the gate claims to measure.
            for (idx, n) in iterations.iter().enumerate() {
                let n = n.load(Ordering::Relaxed);
                assert!(
                    n >= 2,
                    "background writer {idx} made no progress during the arm (iterations={n}) \
                     — the N=4 contention premise did not hold for this cycle"
                );
            }
        }
    });
}

struct MixedState {
    log: SqliteIntentLog,
    headers: SqliteMessageHeaderStore,
    coord: ReadCoordinator,
    churn_admit_cmd: Command,
    churn_admit_basis: FrozenBasis,
    header_key: String,
    coord_provider: String,
    /// (build item (c)): the verb-delta step's REAL intent — one
    /// applied, unprojected, forward `SetFlag{Flagged}` row per writer on `verb_ref`, admitted
    /// through the public door at `open` (occupancy is ~128 then: the undo reserve only), so
    /// every `step() % 4 == 3` projects it through `project_applied_intent` and asserts
    /// `Written`. See `step()` for why it is RE-ARMED rather than re-admitted.
    verb_key: String,
    verb_ref: String,
    /// The re-arm connection (see `step()`), with a busy timeout: it contends the SAME write
    /// lock as every other writer here, and a busy error must wait, never fail the step.
    rearm: rusqlite::Connection,
    step: u64,
}

impl MixedState {
    fn open(path: &std::path::Path, tag: &str, idx: usize) -> Self {
        let mut coord = ReadCoordinator::open(path).expect("mixed writer coordinator open");
        let verb_provider = format!("bgw-verb-{tag}-{idx}");
        let refs = coord
            .ingest_page("acct-bench", &[summary(&verb_provider, 1, "verb seed")])
            .expect("prime the verb-delta target");
        let verb_ref = refs.into_iter().next().expect("one ingested row");
        let churn_key = format!("bgw-admit-{tag}-{idx}");
        let churn_admit_cmd = archive_cmd(&churn_key, &format!("m-{churn_key}"));
        let churn_admit_basis = fixture_basis_for(&churn_admit_cmd);
        let mut log = SqliteIntentLog::open(path).expect("mixed writer intent log open");
        // The verb-delta step's real intent: admitted through `record()` (which freezes the
        // header's CURRENT `ingest_revision` as its basis), then settled `Applied` through the
        // fixture door — terminal, so it occupies no capacity slot the gate's 1024 count reads.
        let verb_key = format!("bgw-verb-intent-{tag}-{idx}");
        let verb_cmd = Command::new(
            verb_key.as_str(),
            "acct-bench",
            Facet::Mail,
            Action::SetFlag { message_ref: verb_ref.clone(), flag: MailFlag::Flagged, value: true },
        );
        let verb_basis = fixture_basis_for(&archive_cmd(&verb_key, &verb_ref));
        match log.record(&verb_cmd, &verb_basis) {
            Ok(Claim::Inserted) => {}
            other => panic!("mixed writer: the verb-delta intent must be admitted at open: {other:?}"),
        }
        log.set_status_forced(&verb_key, IntentStatus::Applied)
            .expect("mixed writer: settle the verb-delta intent Applied");
        let rearm = rusqlite::Connection::open(path).expect("mixed writer re-arm connection");
        rearm
            .busy_timeout(std::time::Duration::from_secs(30))
            .expect("mixed writer re-arm busy timeout");
        MixedState {
            log,
            headers: SqliteMessageHeaderStore::open(path).expect("mixed writer header open"),
            coord,
            churn_admit_cmd,
            churn_admit_basis,
            header_key: format!("bgw-hdr-{tag}-{idx}"),
            coord_provider: format!("bgw-coord-{tag}-{idx}"),
            verb_key,
            verb_ref,
            rearm,
            step: 0,
        }
    }

    fn step(&mut self) {
        match self.step % 4 {
            0 => {
                let _ = self.log.record(&self.churn_admit_cmd, &self.churn_admit_basis);
            }
            1 => {
                let _ = self.headers.record_header(
                    "acct-bench",
                    &self.header_key,
                    "Inbox",
                    0,
                    "c@e.test",
                    "C",
                    "churn subject",
                    false,
                    false,
                );
            }
            2 => {
                let row = summary(&self.coord_provider, 2, "coord churn");
                let _ = self.coord.ingest_page("acct-bench", &[row]);
            }
            3 => {
                // (build item (c)): the door is keyed by the intent
                // ALONE, so this step projects a REAL applied intent and asserts `Written` — the
                // landed version passed the fake key `"bench-noop"`, which the key-only door
                // answers `NotApplicable` without writing, and discarded the result, so the
                // verb-delta contention this population claims measured nothing while green.
                //
                // RE-ARMED, not re-admitted: `projected` is one-way, so each projection needs an
                // unprojected row, and a fresh `record()` per step is refused
                // (`Claim::CapacityRefused`) exactly while the pool sits at cap — the timed sever
                // window this benchmark exists to measure. So the writer's ONE real intent is
                // re-armed by a raw fixture write (`projected = 0`, basis = the header's current
                // revision — no public door un-projects an intent, by design). That write is NOT
                // enrolled in the writer gate: it is one small extra SQLite write-lock contender
                // per rotation, stated here rather than hidden.
                self.rearm
                    .execute(
                        "UPDATE intents SET projected = 0,
                                basis_ingest_revision = (SELECT ingest_revision FROM message_header
                                                          WHERE account = 'acct-bench' AND message_ref = ?2)
                          WHERE idempotency_key = ?1;",
                        rusqlite::params![self.verb_key, self.verb_ref],
                    )
                    .expect("mixed writer: re-arm the verb-delta intent");
                let outcome = self.coord.project_applied_intent(&self.verb_key);
                assert_eq!(
                    outcome,
                    Ok(ProjectionWrite::Written),
                    "the verb-delta step must drive a real projection write"
                );
            }
            _ => unreachable!(),
        }
        self.step += 1;
    }
}

/// Population (b): N=4 send-authorizer-shaped writers — fresh admit -> claim -> authorize per
/// iteration (the /stage-4 shape: `AttemptClaim { ordinal: 1, predecessor: None,
/// observed_attempts: 0 }` then `authorize_send(.., CaptureBinding::NoJournalRow)`, matching the
/// belt witness `the_belt_refuses_a_send_authorized_after_a_sever_tickets`'s own use of
/// `NoJournalRow` for a command that never rode the capture/PREPARE pipeline). Fresh distinct
/// keys per iteration (a claim+authorize loop cannot churn one key — SEND_AUTHORIZED is
/// at-most-one per attempt): most iterations land `CapacityRefused` once the pool is at cap,
/// which is still real write-lock contention (the capacity check runs INSIDE the enrolled
/// `Immediate` transaction), and the rest exercise claim_attempt/authorize_send's own enrolled
/// doors.
fn run_send_authorizer_population(path: &std::path::Path, tag: &str) -> Arc<Vec<AtomicUsize>> {
    let path = path.to_path_buf();
    let tag = tag.to_string();
    let (stop, iterations, handles) = spawn_writers(N_WRITERS, move |idx: usize| {
        thread_local! {
            static LOG: std::cell::RefCell<Option<(SqliteIntentLog, u64)>> = const { std::cell::RefCell::new(None) };
        }
        LOG.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.is_none() {
                *slot = Some((SqliteIntentLog::open(&path).expect("send-authorizer open"), 0));
            }
            let (log, n) = slot.as_mut().unwrap();
            let key = format!("bgw-auth-{tag}-{idx}-{n}");
            *n += 1;
            let cmd = archive_cmd(&key, &format!("m-{key}"));
            let basis = fixture_basis_for(&cmd);
            if let Ok(Claim::Inserted) = log.record(&cmd, &basis) {
                if let Ok(ClaimOutcome::Won { attempt_id, .. }) = log.claim_attempt(
                    &key,
                    &AttemptClaim { ordinal: 1, predecessor: None, observed_attempts: 0 },
                ) {
                    let _ = log.authorize_send(&key, &attempt_id, CaptureBinding::NoJournalRow, aruna::plan::PlanBinding::Plain);
                }
            }
        });
    });
    POPULATION_HANDLES.with(|c| c.borrow_mut().push((stop, Arc::clone(&iterations), handles)));
    iterations
}

/// The measured result of one (population, arm) combination.
struct ArmResult {
    population: &'static str,
    pending_reduction: bool,
    latencies_us: Vec<u128>,
    background_ops: usize,
    seeded_total: usize,
}

impl ArmResult {
    fn min(&self) -> u128 {
        *self.latencies_us.iter().min().unwrap()
    }
    fn max(&self) -> u128 {
        *self.latencies_us.iter().max().unwrap()
    }
    fn pct(&self, p: f64) -> u128 {
        let mut sorted = self.latencies_us.clone();
        sorted.sort_unstable();
        sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
    }
}

/// The TRUE member count `sever()` is about to sweep — a raw `COUNT(*)` over the SAME
/// `NON_TERMINAL_STATUS_SQL` domain the engine's own `sever()` and admission door use (its
/// exact literal, `('pending','undoing','evidence_snapshot_written')` — `lib.rs`'s
/// `NON_TERMINAL_STATUS_SQL`), read on a PLAIN connection so this never competes with the
/// writer gate.: this is the honest oracle for "did seeding actually reach
/// 1024", never inferred from what was requested.
fn active_member_count(path: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(path).expect("active_member_count: probe connection");
    conn.query_row(
        "SELECT COUNT(*) FROM intents \
         WHERE status IN ('pending','undoing','evidence_snapshot_written');",
        [],
        |r| r.get(0),
    )
    .expect("active_member_count: count query")
}

/// (stop flag, join handles) return type shared with `spawn`'s companion per-thread iteration
/// counters — see [`PopulationSpawner`].
type PopulationSpawner = fn(&std::path::Path, &str) -> Arc<Vec<AtomicUsize>>;

/// Run K re-seed+sever cycles on `log`, optionally planting a non-fitting pending reduction
/// AFTER each re-seed (so it stays pending through that cycle's sever — see the module doc).
/// Returns the per-cycle `begin_sever -> completion` latencies (microseconds), the total
/// number of active members re-seeded across all K cycles, and the total background-writer
/// iteration count.
///
/// **background writers are spawned PER CYCLE, AFTER `seed_undo_reserve`
/// completes, never before it.** `seed_undo_reserve`'s three-admission-per-remedy-unit recipe
/// needs to land exactly 64 forward-kind admissions while the pool still has room; the
/// send-authorizer population never throttles (every iteration is a FRESH forward admission,
/// four threads racing), and empirically it can saturate the ENTIRE 960-slot forward pool
/// before `seed_undo_reserve`'s single-threaded sequential recipe gets even its FIRST turn
/// (observed pre-fix: `active_forward=960` already, on `seed_undo_reserve`'s very first
/// blocker admission of a cycle — panicking the gate). Contention during `reseed_to_cap` and
/// `sever()` itself is unaffected: both already tolerate (or, for `sever()`, are the very
/// thing this benchmark exists to measure under) concurrent admission from other writers —
/// only the deterministic reserve-seeding step needs to run alone.
fn run_cycles(
    log: &mut SqliteIntentLog,
    path: &std::path::Path,
    tag: &str,
    pending_reduction: bool,
    spawn: PopulationSpawner,
) -> (Vec<u128>, usize, usize) {
    let mut latencies = Vec::with_capacity(K);
    let mut seeded_total = 0usize;
    let mut background_ops = 0usize;
    for cycle in 0..K {
        if pending_reduction {
            // Restore full bounds first — occupancy is 0 after the prior cycle's sever (or this
            // is cycle 0, first-run default), so this activates IMMEDIATELY (the config
            // transaction's own no-traffic fit-check, design), and the next re-seed can
            // reach the real 1024 cap again.
            log.record_capacity_config(capacity_config(DEFAULT_CAPACITY_JSON))
                .expect("restore the default capacity bounds");
        }
        // the 64-slot PROTECTED UNDO RESERVE FIRST, RACE-FREE (no
        // background writers live yet this cycle — see this function's own doc) — THEN spawn
        // this cycle's background writers, THEN plain forwards up to the 960 forward bound
        // the reserve leaves behind.
        seed_undo_reserve(path, &format!("undo-{tag}-{cycle}"), 64);
        let iterations = spawn(path, &format!("{tag}-{cycle}"));
        reseed_to_cap(log, &format!("seed-{tag}-{cycle}"));
        let member_count = active_member_count(path);
        assert_eq!(
            member_count, 1024,
            "cycle {cycle} ({tag}): the true-1024 seed landed {member_count} active members, \
             not 1024 — the sever witness must sweep the real workload this gate claims"
        );
        seeded_total += member_count as usize;
        if pending_reduction {
            // Plant the non-fitting reduction AFTER re-seeding (a plant BEFORE re-seeding would
            // cap admission at the SMALLER bound immediately — design, "forwards admit
            // against NEW bounds").
            log.record_capacity_config(capacity_config(PENDING_REDUCTION_JSON))
                .expect("plant the pending reduction");
        }
        let authority = format!("authority:bench-{tag}-{cycle}");
        let now = sever_now();
        let t0 = Instant::now();
        let outcome = log.sever(&authority, &now).expect("sever must succeed under contention");
        let elapsed_us = t0.elapsed().as_micros();
        latencies.push(elapsed_us);
        assert!(
            outcome.terminalized > 0,
            "cycle {cycle} ({tag}): sever terminalized nothing — the re-seed did not land"
        );
        // NOT an exact `outcome.terminalized == member_count` equality: this cycle's
        // background writers are live from just after `seed_undo_reserve` onward, and an
        // admission landing in the gap between the `active_member_count` read above and
        // `sever()`'s own sweep would make an exact count a FLAKY assertion — the pre-sever
        // `member_count == 1024` check above is the honest, race-free oracle for "did seeding
        // reach 1024"; `terminalized` only needs to prove the sever actually did real work.
        stop_population();
        background_ops += iterations.iter().map(|c| c.load(Ordering::Relaxed)).sum::<usize>();
        drain_issued_survivors(log, path);
    }
    (latencies, seeded_total, background_ops)
}

/// **THE PER-CYCLE ISSUED-OR-UNKNOWN DRAIN (root-caused by store
/// autopsy 2026-08-12).** A send-authorizer writer's completed iteration leaves a
/// SEND-AUTHORIZED attempt, and a sever WITNESSES such a member but deliberately leaves it
/// ALIVE (`lead_sever_service`'s IssuedOrUnknown arm — §5.2c: non-issuance cannot be proven).
/// Nothing in this benchmark ever settled them, so they accumulated ACROSS cycles as
/// sever-immune occupancy — growing by every cycle's pre-cap writer window until the pool was
/// permanently full and `seed_undo_reserve`'s parent admission refused (autopsied: ~900
/// `bgw-auth-*` survivors, seq-interleaved BELOW the last severed row across nine witnessed
/// severs — they were skipped BY DESIGN, not raced past; whether a given 10-cycle run crossed
/// the threshold was a timing race, which is why earlier runs passed). The design's own drain
/// for exactly this class is ADJUDICATION (W-ADJUDICATION-AT-CAP — "adjudication is
/// the rescuer", no admission door), so each cycle drains its survivors the way production
/// would, OUTSIDE the timed sever window. Rows with no live attempt (or a PreIssuance one)
/// need nothing here: the next sever closes those as members.
fn drain_issued_survivors(log: &mut SqliteIntentLog, path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).expect("drain: probe connection");
    // The non-terminal domain's exact literal (`lib.rs`'s `NON_TERMINAL_STATUS_SQL`), same as
    // `active_member_count` above.
    let keys: Vec<String> = conn
        .prepare(
            "SELECT idempotency_key FROM intents
              WHERE status IN ('pending','undoing','evidence_snapshot_written');",
        )
        .expect("drain: prepare")
        .query_map([], |r| r.get(0))
        .expect("drain: query")
        .map(|r| r.expect("drain: row"))
        .collect();
    for key in keys {
        let Some(live) = log.live_attempt(&key).expect("drain: live_attempt") else {
            continue;
        };
        if live.class == aruna::attempt::AttemptClass::IssuedOrUnknown {
            log.adjudicate(
                &key,
                &live.attempt_id,
                "authority:bench-cycle-drain",
                aruna::attempt::AdjudicationReason::PresumedTransportLoss,
                aruna::attempt::AcceptedRisk::NoneClaimed,
            )
            .expect("drain: adjudicate the issued-or-unknown survivor");
        }
    }
}

/// WAL/checkpoint state, read via a plain connection to the same store file — REPORTED only, per
/// the design's own "checkpoint contribution UNDETERMINED" phrasing (the v2 checkpoint-oracle
/// that DID claim causation was executed-refuted earlier — a passive checkpoint probe
/// cannot distinguish an autocheckpoint-on history from an -off one after the fact).
struct WalState {
    autocheckpoint_pages: i64,
    /// `(busy, wal_frames, checkpointed_frames)` from `PRAGMA wal_checkpoint(PASSIVE)`.
    checkpoint: (i64, i64, i64),
}

fn read_wal_state(path: &std::path::Path) -> WalState {
    let conn = rusqlite::Connection::open(path).expect("wal-state probe connection");
    let autocheckpoint_pages: i64 = conn
        .pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))
        .expect("read wal_autocheckpoint");
    let checkpoint: (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(PASSIVE);", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("PRAGMA wal_checkpoint(PASSIVE)");
    WalState { autocheckpoint_pages, checkpoint }
}

/// (build item (c)): the mixed population's verb-delta step, witnessed
/// OUTSIDE the `PHOTON_PERF` gate — the gate itself returns immediately under a default `cargo
/// test`, so without this a step that silently stopped writing (the landed door answered the
/// fake key `"bench-noop"` with `NotApplicable`, and the result was discarded) stays green
/// forever. Two full rounds of the four-step rotation run here, so the verb-delta step executes
/// twice and asserts `Written` each time. The store is removed on the way out.
#[test]
fn the_mixed_writer_verb_step_projects_a_real_intent() {
    let path = unique_temp_db_path("r6-verb-step");
    drop(SqliteIntentLog::open(&path).expect("bootstrap"));
    let mut state = MixedState::open(&path, "r6-witness", 0);
    for _ in 0..8 {
        state.step();
    }
    assert_eq!(state.step, 8, "two full rotations ran, the verb-delta step twice");
}

#[test]
fn capacity_seize_bound_gate() {
    if std::env::var("PHOTON_PERF").ok().as_deref() != Some("1") {
        eprintln!("capacity_seize_bound skipped (set PHOTON_PERF=1 to run)");
        return;
    }

    let commit_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "UNKNOWN (git rev-parse failed — manually record the commit SHA)".to_string());

    let mut results: Vec<ArmResult> = Vec::new();
    let mut wal_lines: Vec<String> = Vec::new();

    let populations: [(&'static str, PopulationSpawner); 2] = [
        ("mixed", run_mixed_population),
        ("send-authorizer", run_send_authorizer_population),
    ];
    for (population_name, spawn) in populations {
        for pending_reduction in [false, true] {
            let arm_tag = format!("{population_name}-{}", if pending_reduction { "pending" } else { "nopending" });
            let path = unique_temp_db_path(&arm_tag);
            let mut log = SqliteIntentLog::open(&path).expect("bootstrap + open");

            let wal_before = read_wal_state(&path);

            let (latencies, seeded_total, background_ops) =
                run_cycles(&mut log, &path, &arm_tag, pending_reduction, spawn);

            let wal_after = read_wal_state(&path);
            wal_lines.push(format!(
                "- **{arm_tag}**: wal_autocheckpoint={ac} pages; wal_checkpoint(PASSIVE) before=(busy={b0}, wal_frames={w0}, checkpointed={c0}), \
                 after=(busy={b1}, wal_frames={w1}, checkpointed={c1}) — REPORTED ONLY, checkpoint contribution UNDETERMINED \
                 (a passive probe cannot distinguish an autocheckpoint-on history from an -off one after the fact, #24-1b Task 5).",
                ac = wal_before.autocheckpoint_pages,
                b0 = wal_before.checkpoint.0, w0 = wal_before.checkpoint.1, c0 = wal_before.checkpoint.2,
                b1 = wal_after.checkpoint.0, w1 = wal_after.checkpoint.1, c1 = wal_after.checkpoint.2,
            ));

            println!(
                "{arm_tag}: {n} cycles, seeded_total={seeded_total}, background_ops={background_ops}, \
                 latencies_us(min/p50/p95/max)={min}/{p50}/{p95}/{max}",
                n = latencies.len(),
                min = latencies.iter().min().unwrap(),
                p50 = pct(&latencies, 0.5),
                p95 = pct(&latencies, 0.95),
                max = latencies.iter().max().unwrap(),
            );

            drop(log);
            std::fs::remove_file(&path).ok();
            let wal_path = path.with_extension("sqlite-wal");
            let shm_path = path.with_extension("sqlite-shm");
            std::fs::remove_file(&wal_path).ok();
            std::fs::remove_file(&shm_path).ok();

            results.push(ArmResult {
                population: population_name,
                pending_reduction,
                latencies_us: latencies,
                background_ops,
                seeded_total,
            });
        }
    }

    // ── THE HARD GATE — max <= 250ms per arm. Assert AFTER every arm has run and its numbers
    // are captured/printed, so a failure still leaves the full picture on stdout. ──
    let mut failures = Vec::new();
    for r in &results {
        let max = r.max();
        if max > HARD_GATE_US {
            failures.push(format!(
                "{} / pending_reduction={}: max={}us > {}us gate",
                r.population, r.pending_reduction, max, HARD_GATE_US
            ));
        }
    }

    write_evidence(&results, &commit_sha, &wal_lines, &failures);

    assert!(
        failures.is_empty(),
        "the 250ms contention gate FAILED for: {failures:?} — see \
         docs/perf/1b-seize-bound-evidence.md for the full distribution"
    );
}

fn pct(sorted_input: &[u128], p: f64) -> u128 {
    let mut sorted = sorted_input.to_vec();
    sorted.sort_unstable();
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

fn write_evidence(results: &[ArmResult], commit_sha: &str, wal_lines: &[String], failures: &[String]) {
    let mut table = String::new();
    for r in results {
        table.push_str(&format!(
            "| {pop} | {pending} | {n} | {min:.1} | {p50:.1} | {p95:.1} | {max:.1} | {seeded} | {bg} | {verdict} |\n",
            pop = r.population,
            pending = if r.pending_reduction { "yes" } else { "no" },
            n = r.latencies_us.len(),
            min = r.min() as f64 / 1000.0,
            p50 = r.pct(0.5) as f64 / 1000.0,
            p95 = r.pct(0.95) as f64 / 1000.0,
            max = r.max() as f64 / 1000.0,
            seeded = r.seeded_total,
            bg = r.background_ops,
            verdict = if r.max() <= HARD_GATE_US { "PASS" } else { "FAIL" },
        ));
    }
    let overall_verdict = if failures.is_empty() { "PASS" } else { "FAIL" };
    let body = format!(
        "# #24-1b Task 8 — W-SEIZE-BOUND contention gate evidence\n\
         \n\
         Generated by `crates/aruna/tests/capacity_seize_bound.rs`. Command: \
         `PHOTON_PERF=1 cargo test --manifest-path crates/aruna/Cargo.toml --test capacity_seize_bound -- --nocapture`.\n\
         \n\
         Machine profile: OS `{os}` / SQLite `{sqlite}`. CPU model/core-count: NOT queryable from \
         `std`/the crate's existing deps on this platform — manually-recorded field for the driver \
         to fill in before this evidence is cited as a pinned-profile baseline.\n\
         \n\
         Commit SHA (at run time): `{commit_sha}`.\n\
         \n\
         Storage-liveness precondition (design r17, scope-fence): this bound is honest only on \
         LIVE storage — the watchdog surfaces a stall, it never preempts. This run assumes a live \
         local disk; a network/virtualized/throttled filesystem is a DIFFERENT profile and would \
         need its own evidence run, never this one cited in its place.\n\
         \n\
         K = {k} full re-seed+sever cycles per (population, pending-reduction) arm; N = {n} \
         background writers per arm. See the test file's module doc for why K was reduced from the \
         design's nominal 50 (a `sever()` call terminalizes the WHOLE active pool, so a cycle is a \
         full 1024-row re-admission, not one row).\n\
         \n\
         ## Latency distribution (ms) — HARD gate: max <= 250ms per arm\n\
         \n\
         | population | pending reduction | cycles | min | p50 | p95 | max | seeded (total ops) | background writer ops | verdict |\n\
         |---|---|---|---|---|---|---|---|---|---|\n\
         {table}\n\
         **Overall verdict: {overall_verdict}**\n\
         \n\
         ## WAL / checkpoint state (reported only — no causal claim)\n\
         \n\
         {wal}\n",
        os = std::env::consts::OS,
        sqlite = aruna::message_header::sqlite_version(),
        commit_sha = commit_sha,
        k = K,
        n = N_WRITERS,
        table = table.trim_end(),
        overall_verdict = overall_verdict,
        wal = wal_lines.join("\n"),
    );
    // RUNTIME read (Cargo sets this fresh per test-binary run), never
    // the COMPILE-TIME `env!` bake a reused stale binary would carry from another tree.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs");
    let dir = std::path::Path::new(&manifest_dir).join("../../docs/perf");
    std::fs::create_dir_all(&dir).expect("create the evidence directory");
    let file = dir.join("1b-seize-bound-evidence.md");
    // (EXECUTED) — REGENERATION MUST NOT DESTROY THE RECORD. The
    // machine-generated sections above describe THIS run; everything from `## FULL RECORD`
    // onward is the hand-appended run HISTORY (the gate's whole story, FAIL runs included —
    // "selective evidence is not evidence"), and the unconditional write used to erase it on
    // every PHOTON_PERF run: three earlier folds re-spliced it by hand, and the gate
    // finally flagged the destruction itself. The regen now carries the historical tail
    // forward verbatim; the record is still extended by hand per run.
    let body = match std::fs::read_to_string(&file) {
        Ok(existing) => merge_preserving_full_record(&existing, &body),
        Err(_) => body,
    };
    std::fs::write(file, body).expect("write evidence");
}

/// The FULL-RECORD-preserving merge for the evidence file: `regenerated` (this run's
/// machine-written sections) plus the `## FULL RECORD` tail of `existing`, verbatim. Pure, so
/// the always-on test below can discriminate it without a PHOTON_PERF run.
fn merge_preserving_full_record(existing: &str, regenerated: &str) -> String {
    match existing.find("\n## FULL RECORD") {
        Some(at) => format!("{}{}\n", regenerated.trim_end(), &existing[at..]),
        None => regenerated.to_string(),
    }
}

/// the destruction witness, runnable in every plain `cargo test`
/// (deliberately NOT PHOTON_PERF-gated: the defect was in the bookkeeping, not the timing).
#[test]
fn evidence_regeneration_preserves_the_full_record_tail() {
    let existing = "# header\n\nold tables\n\n## FULL RECORD — history\n\n| run | ... |\nnarrative\n";
    let regenerated = "# header\n\nnew tables\n";
    let merged = merge_preserving_full_record(existing, regenerated);
    assert!(
        merged.contains("## FULL RECORD — history") && merged.contains("| run | ... |"),
        "the FULL RECORD tail must survive regeneration verbatim: {merged}"
    );
    assert!(
        merged.contains("new tables") && !merged.contains("old tables"),
        "the machine-generated sections must be THIS run's: {merged}"
    );
    assert_eq!(
        merge_preserving_full_record("# no record here\n", regenerated),
        regenerated,
        "a file with no FULL RECORD section regenerates whole, unchanged behavior"
    );
}
