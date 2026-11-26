//! M0 §5 floor-perf harness. Gated by PHOTON_PERF=1 so default `cargo test` stays fast.
//! Run: `PHOTON_PERF=1 cargo test --manifest-path crates/aruna/Cargo.toml --test perf_floor_gates -- --nocapture`
//!
//! Builds a deterministic 1M-row corpus once, measures the three search comparators + folder
//! first/deep pages, asserts the floors (p95 < floor AND max < 2x floor), runs the FTS5
//! integrity-check, captures EXPLAIN QUERY PLAN, and writes committed evidence.

use aruna::mem::engine_working_set_bytes;
use aruna::message_header::{sqlite_version, BulkHeaderRow, SqliteMessageHeaderStore};
use aruna::SqliteIntentLog;
use std::time::Instant;

const N: i64 = 1_000_000;
const MAILBOXES: &[&str] = &[
    "Inbox", "Archive", "Sent", "Drafts", "Spam", "Work", "Personal", "Receipts", "Travel", "News",
    "Family",
];
// Fixed word-lists -> a known, non-vacuous hit count for the benchmark term "report".
const SUBJECT_WORDS: &[&str] = &[
    "report", "invoice", "meeting", "update", "reminder", "summary", "draft", "notice", "alpha",
    "beta",
];
const NAME_WORDS: &[&str] = &[
    "amazon", "acme", "globex", "initech", "umbrella", "stark", "wayne", "wonka", "hooli",
    "piedpiper",
];

/// Tiny deterministic LCG so the corpus is reproducible without a dependency.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 16
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

/// Run `f` `iters` times, returning the sorted per-call microsecond samples + the last hit count.
fn time_n<F: FnMut() -> usize>(iters: usize, mut f: F) -> (Vec<u128>, usize) {
    let mut samples = Vec::with_capacity(iters);
    let mut last_hits = 0;
    for _ in 0..iters {
        let t = Instant::now();
        last_hits = f();
        samples.push(t.elapsed().as_micros());
    }
    samples.sort_unstable();
    (samples, last_hits)
}

#[test]
fn floor_perf_gates_at_1m() {
    if std::env::var("PHOTON_PERF").ok().as_deref() != Some("1") {
        eprintln!("perf harness skipped (set PHOTON_PERF=1 to run)");
        return;
    }
    // the ONE guard owns the 1M-row store (bound before it opens).
    let path = aruna::test_temp::TempFile::sqlite("aruna-perf");
    let _log = SqliteIntentLog::open(&path).unwrap();
    let mut s = SqliteMessageHeaderStore::open(&path).unwrap();

    // Build the 1M corpus via the CHUNKED, ENROLLED bulk-write door —
    // never the raw begin()/commit() pair, which is gone from the production surface. ---
    //
    // `rows_per_chunk` REALIZES the chunk-budget contract as a row count (see
    // `SqliteMessageHeaderStore::bulk_load_headers`'s doc for why the module itself cannot
    // measure elapsed time from inside a chunk): a small CALIBRATION batch of ordinary
    // single-row `record_header` writes, on a throwaway store so it never pollutes the real
    // corpus, times this box's actual per-row cost, and `rows_per_chunk` is chosen so
    // `rows_per_chunk * per_row_cost` stays at/under the writer_chunk_budget_ms default (50ms —
    // `capacity::DEFAULT.writer_chunk_budget_ms`; not re-exported on `aruna`'s public surface,
    // so pinned here as the documented default rather than imported).
    let rows_per_chunk = {
        const CALIBRATION_ROWS: i64 = 2_000;
        const WRITER_CHUNK_BUDGET_MS: f64 = 50.0;
        let calib_path = aruna::test_temp::TempFile::sqlite("aruna-perf-calib");
        let calib_log = SqliteIntentLog::open(&calib_path).unwrap();
        let mut calib = SqliteMessageHeaderStore::open(&calib_path).unwrap();
        let calib_start = Instant::now();
        for i in 0..CALIBRATION_ROWS {
            calib
                .record_header("acct", &format!("calib{i}"), "Inbox", 0, "c@e.test", "C", "calibration row", false, false)
                .unwrap();
        }
        let per_row_us =
            (calib_start.elapsed().as_micros() as f64 / CALIBRATION_ROWS as f64).max(0.001);
        // BOTH handles close before the file is removed, and the removal is
        // ASSERTED. The intent log's connection was bound as `_calib_log` and therefore lived to
        // the end of this block — past the `remove_file` below — so on Windows the delete failed
        // with "The process cannot access the file because it is being used by another process"
        // (os error 32, byte-verified) and the swallowing `.ok()` hid it: every perf run leaked
        // an `aruna-perf-calib-*.sqlite` into %TEMP%. Same lesson as `message_header.rs`'s
        // `cleanup` helper, which already takes its store BY VALUE for exactly this reason.
        drop(calib);
        drop(calib_log);
        std::fs::remove_file(&calib_path).unwrap_or_else(|e| {
            panic!(
                "the calibration store at {} must be removable once both handles are closed \
                 (a swallowed failure leaks one temp store per perf run): {e}",
                calib_path.display()
            )
        });
        // the lower bound is 1, not 200. A 200-row floor was silently
        // OVERRIDING this calibration's own measurement on a slow box: if `per_row_us` says
        // this box can only afford (say) 40 rows inside the 50ms `writer_chunk_budget_ms`
        // budget, clamping the result up to 200 rows spends ~5x that budget per chunk — the
        // harness measuring its own per-row cost and then ignoring what it measured. The
        // upper clamp (20_000) stays: it bounds a FAST box's chunk size so one chunk's own
        // enrollment span (and the writer-gate hold it implies) never grows unboundedly large
        // regardless of how cheap a single row is.
        ((WRITER_CHUNK_BUDGET_MS * 1000.0 / per_row_us) as usize).clamp(1, 20_000)
    };

    let build = Instant::now();
    let mut rng = 0x9E3779B97F4A7C15u64;
    // Independent oracle for the search term "report": counted in pure Rust during generation, with NO
    // SQL/FTS involvement. The timing is later accepted only if the FTS-backed count EQUALS this — so an
    // under-populated index or a shifted distribution can't yield an artificially-fast "passing" run
    // (2026-06-26). The prefix query is `report*`; in SUBJECT_WORDS only "report" starts
    // with "report", and no name/addr token does, so a row matches iff either subject word is "report".
    let mut expected_report_hits = 0i64;
    let mut i: i64 = 0;
    let written = s
        .bulk_load_headers(rows_per_chunk, || {
            if i >= N {
                return None;
            }
            // ~50% skew toward Inbox so deep-page / large-mailbox cases are exercised.
            let mbox = if lcg(&mut rng).is_multiple_of(2) {
                MAILBOXES[0]
            } else {
                MAILBOXES[(lcg(&mut rng) as usize) % MAILBOXES.len()]
            };
            let w1 = SUBJECT_WORDS[(lcg(&mut rng) as usize) % SUBJECT_WORDS.len()];
            let w2 = SUBJECT_WORDS[(lcg(&mut rng) as usize) % SUBJECT_WORDS.len()];
            let subj = format!("{w1} {w2}");
            if w1 == "report" || w2 == "report" {
                expected_report_hits += 1;
            }
            let name = NAME_WORDS[(lcg(&mut rng) as usize) % NAME_WORDS.len()];
            let ts = (lcg(&mut rng) % 200_000_000) as i64; // ~6 years of seconds
            let row = BulkHeaderRow {
                account: "acct".to_string(),
                message_ref: format!("m{i}"),
                mailbox: mbox.to_string(),
                received_at: ts,
                from_addr: format!("{name}@example.test"),
                from_name: name.to_string(),
                subject: subj,
                seen: false,
                flagged: false,
            };
            if i % 200_000 == 0 {
                println!("  building corpus: {i}/{N} rows ({:.0}s)", build.elapsed().as_secs_f64());
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
            i += 1;
            Some(row)
        })
        .unwrap();
    assert_eq!(written, N as usize, "bulk_load_headers must write every row of the corpus");
    // Fix (pre-existing break, traced to placement-joined paging
    // 66a44ce30c): `folder_first_page`/`folder_next_page` show ONLY rows whose `(account,
    // message_ref)` has a `message_placement` identity row, and this corpus never wrote any —
    // every folder read returned zero rows and the p95 harness unwrapped None. Backfill the
    // identity rows set-based (one statement; a per-row enrolled write x1M would swamp the
    // build). Raw test-only connection — the enrollment census exempts test writers, and the
    // corpus build is not a measured floor.
    {
        let raw = rusqlite::Connection::open(&path).unwrap();
        let placed: usize = raw
            .execute(
                "INSERT INTO message_placement(account, message_ref, email_id, placement)
                 SELECT account, message_ref, 'perf-' || message_ref, mailbox
                   FROM message_header;",
                [],
            )
            .unwrap();
        assert_eq!(placed, N as usize, "every corpus header needs its placement identity row");
    }
    let build_secs = build.elapsed().as_secs_f64();
    println!(
        "corpus built: {N} rows in {build_secs:.1}s ({rows_per_chunk} rows/chunk, calibrated \
         against the 50ms writer-chunk budget); measuring floors..."
    );

    // Reopen on a FRESH connection before measuring the "cold" first folder switch. The build+commit
    // above left the building connection's page/statement cache hot, which would make the cold sample
    // unrealistically fast and let a real first-switch-after-open regression slip the 100ms floor
    // (2026-06-26). A new connection clears connection-level warm state; the read paths
    // below only need &self, so the reopened store is immutable.
    drop(s);
    let s = SqliteMessageHeaderStore::open(&path).unwrap();

    // --- Folder switch: cold-first (fresh connection) + warm distribution + a deep page. ---
    let cold = {
        let t = Instant::now();
        let _ = s.folder_first_page("acct", "Inbox", 50).unwrap();
        t.elapsed().as_micros()
    };
    let (folder_samples, _) = time_n(50, || s.folder_first_page("acct", "Inbox", 50).unwrap().len());
    // deep page: walk 20 pages, time the 20th seek.
    let mut cur = s.folder_first_page("acct", "Inbox", 50).unwrap();
    for _ in 0..19 {
        let last = cur.last().unwrap().clone();
        cur = s
            .folder_next_page("acct", "Inbox", last.received_at, &last.message_ref, 50)
            .unwrap();
        if cur.is_empty() {
            break;
        }
    }
    let deep = {
        let last = cur.last().cloned();
        let t = Instant::now();
        if let Some(l) = last {
            let _ = s
                .folder_next_page("acct", "Inbox", l.received_at, &l.message_ref, 50)
                .unwrap();
        }
        t.elapsed().as_micros()
    };

    let mark = |label: &str| {
        use std::io::Write;
        println!("  {label} ({:.1}s)", build.elapsed().as_secs_f64());
        std::io::stdout().flush().ok();
    };
    mark("folder done; searching");
    // --- Search comparators. FTS gets a real distribution (20 samples); the LIKE baselines are
    // each a single 1M full scan (their job is only to show FTS wins — design §3.3), kept to one
    // shot so the harness stays fast. ---
    // The reopened connection above warmed only message_header/idx_folder pages (folder reads), not
    // the FTS index — so fts_samples[0] is the COLD first FTS query; the 20-sample p95/max therefore
    // already span cold->warm (no separate cold-search measurement needed).
    let (fts_samples, _) = time_n(20, || s.header_search("acct", "report", 50).unwrap().len());
    mark("fts search done");
    let (prefix_like, _) = time_n(1, || s.like_prefix_search("acct", "report", 50).unwrap().len());
    mark("prefix-like done");
    let (substr_like, _) = time_n(1, || s.like_substring_search("acct", "report", 50).unwrap().len());
    mark("substr-like done");

    // --- Plan evidence. (FTS external-content consistency with rank=1 is proven in the hermetic
    // test `re_recording_a_header_resyncs_fts_old_token_gone_new_token_found`; the rank=1 check
    // re-tokenizes the whole corpus, which is O(rows) and not a perf-floor metric, so it is NOT
    // re-run here at 1M — correctness belongs in the fast hermetic suite, perf in this harness.) ---
    let plan = s
        .explain_query_plan(
            "SELECT message_ref, received_at, from_addr, from_name, subject FROM message_header WHERE account=?1 AND mailbox=?2 ORDER BY received_at DESC, message_ref DESC LIMIT ?3;",
            &[&"acct", &"Inbox", &50i64],
        )
        .unwrap();

    // True total match count (NOT the LIMIT-50 page length) — the honest non-vacuity witness (C5).
    let true_hits = s.header_match_count("acct", "report").unwrap();
    mark(&format!("match_count={true_hits} done"));

    // Option: Some(bytes) = measured (Windows), None = unmeasured on this platform.
    let rss = engine_working_set_bytes();
    // Documented WebView2-baseline estimate (design §2); refine with a measured constant at M4.
    const WEBVIEW2_BASELINE_BYTES: u64 = 35_000_000;
    // Engine-process RSS budget: the engine holds the 1M-row DB on disk (small page cache), so it
    // must stay well under the Tauri ~30-50MB class. 50MB ceiling catches a regression that loads
    // the corpus into RAM (C5 — RSS must be GATED, not just reported).
    const ENGINE_RSS_BUDGET_BYTES: u64 = 50_000_000;

    // Assertions: p95 < floor AND max < 2x floor (design §4, C5). ---
    let folder_p95 = pct(&folder_samples, 0.95);
    let folder_max = *folder_samples.last().unwrap();
    let fts_p95 = pct(&fts_samples, 0.95);
    let fts_max = *fts_samples.last().unwrap();
    assert!(
        true_hits > 0 && true_hits < N,
        "search term must be non-vacuous (0<total_hits<N), got {true_hits}"
    );
    // The FTS-backed count must EQUAL the independent in-Rust corpus count — proves the index is fully
    // populated and the hit set is the real distribution, so the timing isn't fast for the wrong reason
    // (an under-populated index would under-count here and fail). (2026-06-26.)
    assert_eq!(
        true_hits, expected_report_hits,
        "FTS match count must equal the independently-counted corpus hits \
         (index fully populated): got {true_hits}, expected {expected_report_hits}"
    );
    // RSS floor: gate ONLY a real measurement. An unmeasured platform (None) is NOT silently
    // certified as passing — it is reported "not measured" in the evidence. The §5 floor targets the
    // Windows/Tauri box, so on Windows a missing measurement is a probe FAILURE, not an OK skip
    // (2026-06-26 — the old `rss == 0 ||` let a non-Windows run "prove" 0 MB).
    // `cfg!(windows)` (a compile-time bool) rather than `#[cfg(windows)]` (item stripping), so the
    // AST is IDENTICAL on every platform: the stripped form left an empty `None` arm on non-Windows
    // targets and clippy's `single_match` correctly red-flagged it there — a lint this crate's own
    // development box (Windows) could never reproduce. Caught by the 3-OS matrix on its first run.
    if let Some(bytes) = rss {
        assert!(
            bytes < ENGINE_RSS_BUDGET_BYTES,
            "engine RSS must stay under {ENGINE_RSS_BUDGET_BYTES} bytes, got {bytes}"
        );
    } else if cfg!(windows) {
        panic!("engine RSS probe returned no measurement on Windows (the §5 target platform)");
    }
    assert!(
        plan.contains("idx_folder") && !plan.to_uppercase().contains("USE TEMP B-TREE"),
        "folder plan must use idx_folder w/o temp sort: {plan}"
    );
    assert!(
        folder_p95 < 100_000 && folder_max < 200_000,
        "folder floor: p95<100ms AND max<200ms, got p95={folder_p95}us max={folder_max}us"
    );
    // The cold-first open and the deep (20th-page) seek are folder switches too — gate them at the
    // same <100ms floor, not just the warm distribution. Measured-but-ungated = not enforced: a
    // regression in either would otherwise pass and be written to evidence (2026-06-26).
    assert!(
        cold < 100_000 && deep < 100_000,
        "folder floor (cold/deep): cold<100ms AND deep<100ms, got cold={cold}us deep={deep}us"
    );
    assert!(
        fts_p95 < 1_000_000 && fts_max < 2_000_000,
        "search floor: p95<1s AND max<2s, got p95={fts_p95}us max={fts_max}us"
    );
    // The evidence states FTS5 is the fastest comparator; ASSERT the ordering so that claim is proven,
    // not merely printed (benchmark rigor — no claimed-but-unasserted result). FTS p95 must beat both
    // single-shot LIKE full scans; a comfortable margin at 1M, and a real regression if it inverts.
    let prefix_p50 = pct(&prefix_like, 0.5);
    let substr_p50 = pct(&substr_like, 0.5);
    assert!(
        fts_p95 < prefix_p50 && fts_p95 < substr_p50,
        "FTS5 must beat both LIKE scans: fts_p95={fts_p95}us prefix={prefix_p50}us substr={substr_p50}us"
    );

    // --- Write the committed evidence artifact. ---
    write_evidence(&EvidenceInput {
        build_secs,
        cold_us: cold,
        folder_samples: &folder_samples,
        deep_us: deep,
        fts_samples: &fts_samples,
        fts_hits: true_hits as usize,
        prefix_like_p50: pct(&prefix_like, 0.5),
        substr_like_p50: pct(&substr_like, 0.5),
        plan: &plan,
        rss,
        // The WebView2 + engine idle-RAM estimate is meaningful only when the engine RSS was
        // actually measured; otherwise it is None ("not measured"), never a baseline-only fiction.
        webview2_estimate: rss.map(|b| WEBVIEW2_BASELINE_BYTES + b),
    });
    // Close the SQLite handles BEFORE deleting the 1M-row temp DB — on Windows an open handle makes
    // remove_file fail and the file (often >100 MB) leaks (2026-06-26). Surface a
    // failed cleanup loudly instead of swallowing it, so a future leak is noticed not hidden.
    drop(s);
    drop(_log);
    if let Err(e) = std::fs::remove_file(&path) {
        eprintln!("warning: could not remove perf temp DB {}: {e}", path.display());
    }
}

struct EvidenceInput<'a> {
    build_secs: f64,
    cold_us: u128,
    folder_samples: &'a [u128],
    deep_us: u128,
    fts_samples: &'a [u128],
    fts_hits: usize,
    prefix_like_p50: u128,
    substr_like_p50: u128,
    plan: &'a str,
    rss: Option<u64>,
    webview2_estimate: Option<u64>,
}

fn write_evidence(e: &EvidenceInput) {
    let p = |s: &[u128], q: f64| pct(s, q);
    let body = format!(
        "# M0 §5 Floor-Gates — Evidence (generated by tests/perf_floor_gates.rs)

Host: {os} / SQLite {sqlite}. Corpus: 1,000,000 rows, seeded deterministic, build {build:.1}s.

## Folder switch (<100ms floor; gate p95<100ms AND max<200ms)
- cold-first: {cold:.1} ms
- p50 {fp50:.1} / p95 {fp95:.1} / p99 {fp99:.1} / max {fmax:.1} ms
- deep page (20th): {deep:.1} ms
- EXPLAIN QUERY PLAN: `{plan}`

## Header search (<1s floor; gate p95<1s AND max<2s) — 3 comparators on token 'report'
- FTS5 MATCH: p50 {sp50:.1} / p95 {sp95:.1} / p99 {sp99:.1} / max {smax:.1} ms  (true total hits={hits} of 1M)
- LIKE 'report%' (UNINDEXED column-prefix scan — no subject index; wrong semantic for token-anywhere): p50 {prefix:.1} ms
- LIKE '%report%' (substring strawman, full scan): p50 {substr:.1} ms
- Conclusion: FTS5 is the chosen index on the merits, NOT because the LIKE baselines breach the floor (at 1M both LIKE scans are still under 1s here). The reasons are (1) SEMANTIC — `LIKE 'term%'` matches only subjects that START with the term (wrong for token-anywhere search) and `LIKE '%term%'` full-scans every row; and (2) MARGIN — FTS5's inverted index is fastest above and stays flat as the corpus grows, while the LIKE scans are O(rows). The LIKE rows are comparators, not viable alternatives.
- FTS5 external-content consistency (rank=1): proven in the hermetic test suite (not re-run at 1M — O(rows) re-tokenization, not a perf-floor metric).

## Idle RAM (storage-floor proxy; integrated Tauri idle-RAM deferred to M4)
{rss_line}
{est_line}
",
        os = std::env::consts::OS,
        sqlite = sqlite_version(),
        build = e.build_secs,
        cold = e.cold_us as f64 / 1000.0,
        fp50 = p(e.folder_samples, 0.5) as f64 / 1000.0,
        fp95 = p(e.folder_samples, 0.95) as f64 / 1000.0,
        fp99 = p(e.folder_samples, 0.99) as f64 / 1000.0,
        fmax = *e.folder_samples.last().unwrap() as f64 / 1000.0,
        deep = e.deep_us as f64 / 1000.0,
        plan = e.plan,
        sp50 = p(e.fts_samples, 0.5) as f64 / 1000.0,
        sp95 = p(e.fts_samples, 0.95) as f64 / 1000.0,
        sp99 = p(e.fts_samples, 0.99) as f64 / 1000.0,
        smax = *e.fts_samples.last().unwrap() as f64 / 1000.0,
        hits = e.fts_hits,
        prefix = e.prefix_like_p50 as f64 / 1000.0,
        substr = e.substr_like_p50 as f64 / 1000.0,
        rss_line = match e.rss {
            Some(b) => format!("- engine working-set (measured): {:.1} MB", b as f64 / 1_000_000.0),
            None => format!(
                "- engine working-set: NOT MEASURED on {} (the §5 RAM floor is gated on Windows only)",
                std::env::consts::OS
            ),
        },
        est_line = match e.webview2_estimate {
            Some(b) => format!(
                "- WebView2-baseline + engine estimate: {:.1} MB (estimate, not a measured Tauri figure)",
                b as f64 / 1_000_000.0
            ),
            None =>
                "- WebView2-baseline + engine estimate: n/a (engine RSS not measured on this platform)"
                    .to_string(),
        },
    );
    // Integration tests run with CWD = crate root; resolve the WORKSPACE-root docs/perf from the
    // manifest dir (crates/aruna -> ../../) so the evidence lands where the design names it.
    // RUNTIME read (Cargo sets this fresh per test-binary run), never
    // the COMPILE-TIME `env!` bake a reused stale binary would carry from another tree.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs");
    let dir = std::path::Path::new(&manifest_dir).join("../../docs/perf");
    std::fs::create_dir_all(&dir).ok();
    std::fs::write(dir.join("m0-floor-gates-evidence.md"), body).expect("write evidence");
}
