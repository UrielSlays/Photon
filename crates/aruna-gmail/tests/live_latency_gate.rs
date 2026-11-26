//! Env-gated LIVE latency witness for the §3 PERF-GATE (the Gmail
//! first-page latency gate). OPT-IN, mirroring `live_readside.rs`'s gate exactly: the drill
//! runs only when `PHOTON_GMAIL_IT=1`; absent (or any other value), it skips LOUDLY and the
//! default `cargo test` stays offline-green. Same env-var names, same empty-is-missing rule,
//! same "skip not panic when not opted in" idiom as the sibling read-side drill.
//!
//! This witness does NOT run the full read-side drill's attestation/preflight/manifest
//! machinery (`PHOTON_GMAIL_ATTESTATION`, `PHOTON_GMAIL_MODE`, `PHOTON_GMAIL_EVIDENCE_DIR`,
//! `PHOTON_GMAIL_403_TOKEN`, `PHOTON_GMAIL_A2_MSG` are all irrelevant here) — it needs only the
//! two vars that let it connect a real transport: `PHOTON_GMAIL_IT` (the opt-in switch) and
//! `PHOTON_GMAIL_ACCESS_TOKEN` (the bearer token). The read path is ungated by the
//! `DestructiveWriteGate` — `HttpGmailTransport::list_inbox_page` delegates straight to
//! `GatedTransport::list_inbox_page`, which never consults `self.gate` (only `modify_labels` does)
//! — so `HttpGmailTransport::connect` (the production, gate-closed constructor) is sufficient; no
//! `with_destructive_writes` call is needed or wanted for a read-only timing witness.
//!
//! # What is inside the measured interval, and why
//!
//! `[list_inbox_page + ReadCoordinator::ingest_page + refresh_reconcile]`, over a FRESH temp
//! store, against an unchanged budget. The §3 gate is about a first page APPEARING, and a page has
//! not appeared until it has been fetched, written and reconciled — which is exactly the three-step
//! sequence the shell's `refresh_inbox` runs (`src-tauri/src/lib.rs`). Timing the transport call
//! alone measured a segment no user experiences and silently exempted every store write from the
//! budget. The store is fresh per run so the ingest is the cold INSERT path rather than an UPDATE
//! over rows a previous run left behind.

use std::env::var;
use std::path::{Path, PathBuf};
use std::time::Instant;

use aruna::gmail::{GmailTransport, GmailUserId};
use aruna::read_coordinator::{ReadCoordinator, WindowAnchor};
use aruna::SqliteIntentLog;
use aruna_gmail::HttpGmailTransport;

/// The §3 gate's config; failing ⇒ the batch fallback decision fires (verify
/// the ≤50/batch cap at Google's origin FIRST — design tripwire).
const FIRST_PAGE_BUDGET_MS: u128 = 3_000;

/// The page the budget is DEFINED FOR: a full 50-row first page. The number is the
/// same one the request asks for, named once so the request and the premise cannot drift apart.
const FULL_FIRST_PAGE_ROWS: usize = 50;

/// Did the run actually measure what the §3 budget is about?
///
/// The budget is defined for a FULL first page over a several-hundred-message backlog. A short
/// page, or a page with no continuation token, means the drill account's backlog is depleted — the
/// run measured something faster and easier than the thing under budget, and passing it would be
/// trivially green. That is an ERROR naming the depleted fixture, not a pass and not a warning:
/// the previous `rows.is_empty()` check let every non-empty page (one row!) through.
///
/// A pure function so the premise is witnessed hermetically — the live run is opt-in and this
/// rule must not be provable only when a drill account happens to be reachable.
fn backlog_premise(rows: usize, has_continuation: bool) -> Result<(), String> {
    if rows != FULL_FIRST_PAGE_ROWS {
        return Err(format!(
            "live latency gate PREMISE FAILED: the drill account returned {rows} rows, not a full \
             {FULL_FIRST_PAGE_ROWS}-row page — the several-hundred-message backlog the §3 budget \
             is defined over is DEPLETED, so the measured time above is not the witness. Refill \
             the drill account's inbox (or point the lane at an account that has the backlog) and \
             re-run; do NOT read a short-page timing as a pass."
        ));
    }
    if !has_continuation {
        return Err(format!(
            "live latency gate PREMISE FAILED: the page was full ({rows} rows) but carried NO \
             continuation token — page 1 is the whole mailbox, which is not the \
             several-hundred-message backlog the §3 budget is defined over. Refill the drill \
             account's inbox and re-run."
        ));
    }
    Ok(())
}

/// A fresh, collision-free store for the drill and for the teardown's own hermetic witnesses,
/// minted by the engine's ONE guard: pid + nanos + a
/// per-process counter, and — past the drill's own loud teardown below, which removes the three
/// SQLite files — the guard removes the rest of the family when it drops, the engine's
/// `.photon-init.lock` included (the teardown never named it: one leaked
/// `photon-latency-witness-cleanup-open-handle-*.sqlite.photon-init.lock` per run).
fn witness_store_path(tag: &str) -> aruna::test_temp::TempFile {
    aruna::test_temp::TempFile::sqlite(&format!("photon-latency-witness-{tag}"))
}

/// The three files ONE SQLite store is: the database and its write-ahead-log sidecars. The store
/// this drill opens runs `journal_mode=WAL` (`aruna::store_open` pins it), so `-wal` — which holds
/// committed pages not yet checkpointed into the main file, i.e. REAL header data from a real
/// mailbox — is a file of its own, and `-shm` is its index.
fn sqlite_file_family(store_path: &Path) -> [PathBuf; 3] {
    let mut wal = store_path.as_os_str().to_owned();
    wal.push("-wal");
    let mut shm = store_path.as_os_str().to_owned();
    shm.push("-shm");
    [store_path.to_path_buf(), PathBuf::from(wal), PathBuf::from(shm)]
}

/// Delete the witness store — the WHOLE family, on EVERY exit path, and LOUDLY.
///
/// Three things this function is, each replacing something the old inline `remove_file(..).ok()`
/// closure was not:
///
/// - **The whole family.** `remove_file` on the `.sqlite` alone left `-wal` behind, and `-wal`
///   holds committed pages — real `From`/`Subject` bytes from a real mailbox — sitting in the
///   system temp dir after a green run.
/// - **Loud.** `.ok()` discarded the removal's `Result`, so every failure below reported a clean
///   teardown over a store still on disk. A failure now names the file it could not remove and
///   reaches the caller as an `Err`; the drill's own result is `and`-ed with it, so a passing
///   budget cannot mask a failed teardown.
/// - **Called with the handles already dropped.** On Windows an open SQLite connection makes
///   `remove_file` fail outright (POSIX unlink of an open file succeeds, which is why this bug
///   was invisible on the design's other two platforms) — so the caller scopes the log and
///   coordinator INSIDE the drill and cleans up after they are gone. Being loud is what makes a
///   future regression here visible instead of theoretical.
///
/// An ALREADY-ABSENT file is success, not an error: `-wal`/`-shm` are gone after a clean close,
/// and a teardown that demanded their presence would fail on the ordinary path.
fn cleanup_store_files(store_path: &Path) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();
    for file in sqlite_file_family(store_path) {
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                let reason = format!("could not remove {}: {e}", file.display());
                eprintln!("live latency gate TEARDOWN FAILED: {reason}");
                failures.push(reason);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "live latency gate: the witness store was NOT removed — real mailbox header data is \
             still on disk. {}",
            failures.join("; ")
        ))
    }
}

/// The live latency witness. Env-gated exactly like `live_readside_drills`: not opted in ⇒
/// loud skip, opted in ⇒ real wire call against the drill account.
#[test]
fn live_first_page_latency_witness() -> Result<(), String> {
    // Empty-string values are MISSING (byte-matches `live_readside.rs`'s `parse_drill_env`
    // rule: a broken shell export must never count as present).
    let var = |key: &str| var(key).ok().filter(|v: &String| !v.trim().is_empty());

    if var("PHOTON_GMAIL_IT").as_deref() != Some("1") {
        eprintln!(
            "live latency gate: PHOTON_GMAIL_IT != 1 — skipping (needs PHOTON_GMAIL_IT=1 and \
             PHOTON_GMAIL_ACCESS_TOKEN; default suite stays hermetic)"
        );
        return Ok(());
    }
    // FAIL CLOSED FROM HERE ON, byte-matching the sibling drill's contract
    // (`live_readside.rs`'s `parse_drill_env`: "opted in, every required var must be present and
    // non-empty — a missing one is an ERROR the caller panics on, NEVER a skip"). A silent `Ok`
    // here is a hidden failure: an obligation reported green with its drill never
    // executing, which is exactly what an operator who exported a broken token line would see.
    let Some(access_token) = var("PHOTON_GMAIL_ACCESS_TOKEN") else {
        return Err(
            "live latency gate: PHOTON_GMAIL_IT=1 but PHOTON_GMAIL_ACCESS_TOKEN is missing or \
             empty — the lane is opted in and cannot connect a real transport; this is an ERROR, \
             not a skip (unset PHOTON_GMAIL_IT to opt out)"
                .to_string(),
        );
    };

    // A FRESH store per run: the measured interval includes ingest, and ingesting
    // into a store that already holds the same page would measure UPDATE-shaped work over a warm
    // cache instead of the cold first-page path a user actually waits through.
    let store_path = witness_store_path("drill");

    // THE HANDLES LIVE INSIDE THE DRILL. `measure_first_page` opens the log and the
    // coordinator and DROPS them when it returns, so the teardown below runs against a store
    // nothing holds open — which is the difference between a deleted file and a silently-failed
    // `remove_file` on Windows. The two results are combined, never substituted: a passing budget
    // over a store still on disk is not a pass.
    let measured = measure_first_page(&access_token, &store_path);
    let cleaned = cleanup_store_files(&store_path);
    measured.and(cleaned)
}

/// The drill proper: connect, fetch page 1, ingest + reconcile it, print the number, grade the
/// premise and the budget. Every handle it opens dies with it — see the caller.
fn measure_first_page(access_token: &str, store_path: &Path) -> Result<(), String> {
    let transport = HttpGmailTransport::connect(access_token)
        .map_err(|e| format!("connect SUT transport: {e:?}"))?;
    let user = GmailUserId("me".to_string());

    // The intent log owns the schema, exactly as `PhotonSession::open` does it — the coordinator
    // opens over the file it created and never creates one itself.
    let log = SqliteIntentLog::open(store_path)
        .map_err(|e| format!("open the witness store at {}: {e}", store_path.display()))?;
    let mut coordinator =
        ReadCoordinator::open(store_path).map_err(|e| format!("open the read coordinator: {e}"))?;
    let account = "gmail:latency-witness";

    // THE MEASURED INTERVAL IS WHAT THE USER WAITS FOR: the §3 budget is about a
    // first page APPEARING, and a page has not appeared until it is fetched, ingested and
    // reconciled — `refresh_inbox` in the shell (`src-tauri/src/lib.rs`) runs exactly these three
    // in this order. Timing the transport call alone under-measured it by every store write.
    let start = Instant::now();
    let listed = transport.list_inbox_page(&user, FULL_FIRST_PAGE_ROWS as i64, None);
    let stored: Result<(), String> = match listed.as_ref() {
        Ok(page) => coordinator
            .ingest_page(account, &page.rows)
            .and_then(|_| {
                // The drill must reconcile exactly as `refresh_inbox` does, or it measures a path
                // the product does not run — including the conservative arm: a
                // page the transport could not verify as newest-first reconciles as NO COVERAGE
                // (an empty window), byte-for-byte what `PhotonSession::absorb_page` does with one.
                let (window, anchor): (&[_], WindowAnchor) = if page.chronological {
                    (
                        &page.rows,
                        // The transport's own answer about the RAW page rides through.
                        WindowAnchor::FirstPage {
                            raw_page_was_empty: page.raw_page_was_empty,
                            // …and so does whether the WALK ended here: an empty
                            // page that still offers a continuation covers nothing.
                            walk_exhausted: page.next.is_none(),
                        },
                    )
                } else {
                    (
                        &[],
                        WindowAnchor::FirstPage {
                            raw_page_was_empty: false,
                            walk_exhausted: false,
                        },
                    )
                };
                coordinator.refresh_reconcile(account, window, anchor)
            })
            .map(|_| ())
            .map_err(|e| e.0),
        // The transport already failed; there is nothing to store, and the transport's own error
        // is reported below.
        Err(_) => Ok(()),
    };
    let elapsed_ms = start.elapsed().as_millis();

    // The witness's number is the deliverable — printed regardless of pass/fail.
    let row_count = listed.as_ref().map(|p| p.rows.len()).unwrap_or(0);
    eprintln!(
        "live latency gate: first-page list_inbox_page + ingest_page + refresh_reconcile took \
         {elapsed_ms}ms, {row_count} rows (budget {FIRST_PAGE_BUDGET_MS}ms)"
    );

    // Every exit path from here is a plain `return`/`?`: the store handles above are dropped by
    // this function returning, and the CALLER owns the teardown. There is no early exit that can
    // skip it and none that can run it too soon.
    let page = listed.map_err(|e| format!("list_inbox_page transport error: {e:?}"))?;
    drop(coordinator);
    drop(log);

    // The store half's own failure is reported with the REAL reason rather than folded into the
    // timing: a witness that swallowed an ingest error would print a fast, meaningless number.
    stored.map_err(|reason| format!("ingest/reconcile error: {reason}"))?;

    // THE PREMISE, CHECKED BEFORE THE BUDGET. The measured number is already
    // printed above — that is the deliverable either way — but a run that did not fetch a full
    // backlog page did not measure the thing the budget is defined for, and reporting it as a pass
    // is a trivially-green witness. It is an error naming the depleted fixture.
    backlog_premise(page.rows.len(), page.next.is_some())?;

    if elapsed_ms > FIRST_PAGE_BUDGET_MS {
        return Err(format!(
            "§3 PERF-GATE RED: first-page fetch + ingest + reconcile took {elapsed_ms}ms > \
             {FIRST_PAGE_BUDGET_MS}ms budget over {row_count} rows — verify the ≤50/batch cap at \
             Google's origin FIRST, then the batch fallback decision fires"
        ));
    }
    Ok(())
}

/// NOT env-gated: the drill's teardown is a RULE — the store it writes holds real
/// header data from a real mailbox, so "the file is gone afterwards" must be a checked fact and
/// not a hope. Every arm is witnessed hermetically; a teardown provable only when a drill account
/// happens to be reachable is a teardown nothing checks.
#[test]
fn the_cleanup_removes_the_whole_sqlite_file_family_and_says_so_when_it_cannot() {
    // (a) THE WHOLE FAMILY. A `-wal` left behind is committed mailbox rows left on disk, and a
    // crash-closed (or still-open) store is exactly when it exists.
    let path = witness_store_path("cleanup-family");
    let family = sqlite_file_family(&path);
    for file in &family {
        std::fs::write(file, b"x").expect("seed the family");
    }
    cleanup_store_files(&path).expect("a removable family removes cleanly");
    for file in &family {
        assert!(
            !file.exists(),
            "every file of the store family must be gone, including the sidecars: {}",
            file.display()
        );
    }

    // (b) LOUD, NOT `.ok()`. A removal that fails must reach the caller as an error naming the
    // file — a swallowed failure reports a clean teardown over a store still sitting on disk. A
    // directory in the store path's place is the portable un-removable file.
    let blocked = witness_store_path("cleanup-blocked");
    std::fs::create_dir(&blocked).expect("stand up an un-removable path");
    let err = cleanup_store_files(&blocked)
        .expect_err("a failed removal is an ERROR, never a silent success");
    assert!(
        err.contains(&blocked.display().to_string()),
        "the error names the file it could not remove: {err}"
    );
    std::fs::remove_dir(&blocked).ok();

    // (c) THE WINDOWS FOOTGUN ITSELF: an OPEN store handle makes `remove_file` fail, and the
    // old `.ok()` turned that into a silent no-op. Windows-only because POSIX unlink of an open
    // file SUCCEEDS — the same code is correct on all three platforms, but only this one can
    // witness the swallowed failure.
    #[cfg(windows)]
    {
        let open = witness_store_path("cleanup-open-handle");
        let log = SqliteIntentLog::open(&open).expect("open the store");
        let coordinator = ReadCoordinator::open(&open).expect("open the coordinator");
        let held = cleanup_store_files(&open);
        assert!(
            held.is_err(),
            "a store still held open cannot be deleted on Windows — the teardown must SAY so, \
             never report a clean exit over a live file"
        );
        drop(coordinator);
        drop(log);
        cleanup_store_files(&open).expect("once the handles are dropped the file goes");
        assert!(!open.exists(), "and the drill's real exit path leaves nothing behind");
    }
}

/// NOT env-gated: pins the budget to the value the §3 design names (3s) so a silent edit to
/// `FIRST_PAGE_BUDGET_MS` trips a test even when the live run never runs.
#[test]
fn first_page_budget_ms_matches_the_design() {
    assert_eq!(
        FIRST_PAGE_BUDGET_MS, 3_000,
        "the §3 PERF-GATE design names a 3s first-page budget — this constant must match it \
         exactly, or be changed only alongside a design update"
    );
}

/// NOT env-gated: the backlog premise is a RULE, and a rule provable only when a
/// drill account happens to be reachable is a rule nothing checks. Every arm is witnessed here.
#[test]
fn the_backlog_premise_admits_only_a_full_page_with_a_continuation() {
    backlog_premise(FULL_FIRST_PAGE_ROWS, true).expect("a full page WITH a continuation is the premise");

    for (rows, has_continuation) in [
        (0usize, false),                       // the old warn-and-pass case
        (1, true),                             // one row was previously "not empty" ⇒ budget-checked
        (FULL_FIRST_PAGE_ROWS - 1, true),      // a nearly-full page is still not the premise
        (FULL_FIRST_PAGE_ROWS, false),         // full page, but page 1 IS the whole mailbox
    ] {
        let err = backlog_premise(rows, has_continuation)
            .expect_err("a depleted fixture must be an error, never a trivially-green pass");
        assert!(
            err.contains("PREMISE FAILED"),
            "the error must name the depleted fixture: {err}"
        );
    }
}
