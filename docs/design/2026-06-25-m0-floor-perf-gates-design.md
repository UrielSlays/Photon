# M0 §5 Floor-Perf Gates — Design

**Date:** 2026-06-25
**Milestone:** M0 (the proving slice) — Definition-of-Done §5, the **last** remaining M0 class.
**Status:** Implemented (see §8 for the review decisions).
**Base:** 164 hermetic tests green.

---

## 1. What this slice is (and is NOT)

M0 DoD §1–§4 are PROVEN on `main` (crash-recovery, divergence-correction, lost-ack/idempotent,
`*/set` shape). The **only** remaining M0 class is §5 — the **floor-perf gates**:

> **Floor gates:** header search **<1s @1M** messages · folder switch **<100ms** · idle RAM in the
> Tauri **~30–50MB** class. (the milestone plan M0 DoD §5.)

§5 is a **proving slice**, not a UI-build slice. Its architectural mandate is fixed by the engine
decision record:

- **D4** — SQLite is the *canonical metadata system-of-record*; "metadata indexing **only if
  benchmarks force it**" (`photon-engine-architecture-decision-20260621.md`).
- **D2** — native Rust hot-cores (full-text search / metadata indexing) are pulled in **only if
  benchmarks force it**.

So §5's job is to **run the benchmarks that either bless plain-indexed SQLite or force the
FTS5/native-hot-core escalation** — and to commit the evidence that settles that fork.

**The altitude:** the §5 floors are *integrated-UX* numbers — the Tauri RAM
figure includes WebView2 (per **D1**, most of the 30–50MB), and a real folder switch eventually also
runs counts/unread/flags/render. This slice proves the **storage-layer floor** beneath those: the
header-list page query, the header-search query, and the engine-process memory. We label the evidence
as the *storage floor*, and carry the *integrated* floors (true Tauri idle-RAM; folder switch incl.
counts/flags/render) to **M4** in the DoD ledger. M0 is declared **complete-at-the-storage-floor**, not
unconditionally (§7).

**In scope:** a real-but-minimal canonical header read-side (the kept schema + the two read paths the
floors name), a deterministic 1M-row synthetic corpus, an env-gated benchmark harness that asserts the
storage floors, and committed evidence.

**Explicitly OUT of scope (YAGNI):** the mail UI; flags/unread-counts; message body storage;
threading/conversation grouping; the Tauri app wiring; substring/infix search (deferred — see §3.3);
any read path the three floors do not exercise.

---

## 2. The honesty boundary on idle-RAM (named up front)

The Tauri app is an **excluded scaffold** (`exclude = ["src-tauri"]`), not wired to the engine. So
true integrated idle RAM (WebView2 + engine) cannot be measured in this slice. We do three honest
things instead, and **fabricate nothing**:

1. **Measure** engine-process working-set (RSS) holding the 1M-row DB open after the read paths run —
   this is the **proven** number.
2. **Bound** the integrated figure as a documented estimate: `(empty-WebView2 baseline) + (measured
   engine RSS)` against the 30–50MB class — the more honest measurement available now. The WebView2 baseline is a one-off measured/cited constant, labeled an *estimate*.
3. **Defer** true integrated Tauri-class idle-RAM to **M4** ("low-end Windows box perf validation," per
   the milestone plan M4).

SQLite holds the corpus on disk with a small page cache (default ~2 MB), so the engine process holding
a 1M-row DB open is expected to sit well under the class — the benchmark states the real number.

---

## 3. Architecture

Cargo workspace, engine crate `aruna` (sync, lean: rusqlite + serde, no async runtime). All §5 work
lands in `aruna` — pure local SQLite, no HTTP/TLS, so nothing touches `aruna-jmap`.

### 3.1 Schema — `message_header` (kept, canonical, minimal)

A NEW table, distinct from `message_placement` (placement is a *divergence-correction* concern;
headers are the *read-side list/search* concern — separate responsibilities, separate tables). Owned
by `SqliteIntentLog::open` (the one schema owner, as `message_placement` already is), bumping the
durable-log `_version`.

```
message_header(
    account     TEXT NOT NULL,   -- Photon-local account id
    message_ref TEXT NOT NULL,   -- Photon-local message ref (provider ids stay below the seam)
    mailbox     TEXT NOT NULL,   -- folder/mailbox the message is filed in (folder-switch filter)
    received_at INTEGER NOT NULL,-- unix epoch (ORDER BY in folder view; keyset cursor)
    from_addr   TEXT NOT NULL,
    from_name   TEXT NOT NULL,
    subject     TEXT NOT NULL,
    PRIMARY KEY (account, message_ref)
)
```

Range-scan index for folder-switch:
```
CREATE INDEX idx_folder ON message_header(account, mailbox, received_at, message_ref);
```
> Keyset pagination compares `(received_at, message_ref)` descending; including both in the index
> makes the filter+sort+cursor a contiguous index range scan, satisfying the `DESC` order without a
> temp B-tree sort. The returned text columns (`from_addr/from_name/subject`) are NOT in the index, so
> the page incurs a rowid fetch — but only for the `limit` rows returned (e.g. 50), which is
> negligible. This index is intentionally **non-covering**; the benchmark's EXPLAIN QUERY PLAN
> evidence (§4) decides whether a covering index is ever needed (almost certainly not for a bounded
> page).

**FTS5 search index — build ordering is load-bearing:** an external-content
FTS5 index does **not** backfill rows that existed before its sync triggers were created; a mismatched
content/index state makes `MATCH` silently inconsistent (SQLite forum-documented). So the harness
**creates the FTS table + its insert trigger BEFORE the corpus is inserted** (or rebuilds + runs
`INSERT INTO message_header_fts(message_header_fts) VALUES('integrity-check')` after backfill). Default
tokenizer + a prefix index (search semantics = token + prefix; see §3.3):
```
CREATE VIRTUAL TABLE message_header_fts USING fts5(
    subject, from_addr, from_name,
    content='message_header', content_rowid='rowid',
    prefix='2 3'
);
-- insert trigger created here, BEFORE corpus load:
CREATE TRIGGER message_header_ai AFTER INSERT ON message_header BEGIN
    INSERT INTO message_header_fts(rowid, subject, from_addr, from_name)
        VALUES (new.rowid, new.subject, new.from_addr, new.from_name);
END;
```
External-content (`content=`) keeps the text un-duplicated. Update/delete triggers are deferred until
the real write path needs them (the corpus is insert-only here) — but flagged as a live correctness
item at M1.

**Provider-id confinement (M0 invariant, preserved):** every column is Photon-local. No `accountId`,
Mailbox id, or Email id appears in `message_header`. `message_ref`/`mailbox` are Photon-local tokens.

### 3.2 Read path #1 — folder switch (`<100ms`)

`fn folder_first_page(account, mailbox, limit)` and `fn folder_next_page(account, mailbox, cursor:
(received_at, message_ref), limit)` — **two separate prepared statements**, not one with `?cursor IS
NULL OR …`. First page:
```sql
SELECT message_ref, received_at, from_addr, from_name, subject
  FROM message_header
 WHERE account = ?1 AND mailbox = ?2
 ORDER BY received_at DESC, message_ref DESC
 LIMIT ?3;
```
Next page adds `AND (received_at, message_ref) < (?cursor_ts, ?cursor_ref)` — a clean row-value seek.

**Keyset** (seek) pagination, not `LIMIT/OFFSET`. `idx_folder` serves the filter+sort+cursor; the
`limit` rows incur a bounded rowid fetch. **EXPLAIN QUERY PLAN evidence (§4) must show `idx_folder`
used and NO temp B-tree sort** on both statements. Floor measured = **first-page latency on a
cold-first mailbox open** (not warm-repeat only ), plus a **deep-page** sample into a
large mailbox to catch any planner degradation.

### 3.3 Read path #2 — header search (`<1s @1M`)

**Semantics pinned FIRST:**
header search is **token + prefix** — whole-word and prefix matches (typing `amaz` finds `amazon`),
the conventional meaning of mail header search. True substring/infix (`zon` inside `amazon`, which
needs an **FTS5 trigram** tokenizer) is **explicitly deferred** to a later slice — not an M0 floor.

`fn header_search(account, query, limit) -> Vec<HeaderRow>` via FTS5 `MATCH` (default tokenizer +
prefix index), filtered by `account`, ordered by `received_at DESC` (or rank — decided in the plan).

**The forcing experiment (honors D4's "only if benchmarks force it") — THREE comparators, apples to
apples on the same token+prefix query:**
1. **`LIKE '%term%'`** (substring) — the full-scan strawman; documents *why a scan is too slow*.
2. **`LIKE 'term%'`** (indexed prefix) — index-usable; the real "**is FTS even needed?**" comparator.
   If this clears <1s with margin for our token+prefix semantics, FTS5 is NOT forced and we ship the
   simpler index (and revisit this spec — we add no machinery the benchmark didn't force).
3. **FTS5 `MATCH`** — the inverted-index path; expected to be the winner that's forced.

The committed evidence records all three numbers so the D2/D4 fork is settled by data. Default
expectation: FTS5 is forced.

### 3.4 Idle-RAM probe

`fn engine_working_set_bytes() -> u64` — Windows `GetProcessMemoryInfo` (`WorkingSetSize`) via a
minimal FFI (~10 lines, no new heavy dep — preferred over `sysinfo` to keep the engine dep tree lean;
final call in the plan). Sampled after the corpus DB is open and both read paths have run. Reported as
the proven engine figure plus the `WebView2-baseline + engine-RSS` estimate (§2).

---

## 4. The benchmark harness + evidence

Pattern mirrors the existing env-gated heavy tests (`PHOTON_JMAP_IT=1` live lane): a `PHOTON_PERF=1`
gate keeps the 1M-row build out of the default `cargo test` (which stays hermetic + fast).

- **Corpus builder** — deterministic, seeded RNG (reproducible): 1,000,000 `message_header` rows across
  N mailboxes (Inbox + ~10 folders, realistic skew toward a large Inbox so deep-page/large-mailbox
  cases are exercised ), `received_at` spread over years, `subject`/`from_*` drawn from
  fixed word-lists so the chosen search term has a **known, non-trivial hit count** (non-vacuous: not
  0, not 1M). FTS table + trigger created **before** insert (§3.1); built in one transaction.
- **Measurement** — each query run M times; report **p50 / p95 / p99 / max**, with the **cold-first**
  run captured (warmup discarded for the distribution but the cold sample reported).
- **Assertions (tail-hardened):** a floor passes only if **p95 < floor AND
  max < 2× floor** (so a user-visible tail spike can't slip through a soft p95). `folder` first-page +
  deep-page, and `header_search` (FTS5), each gated; engine working-set < documented budget.
- **EXPLAIN QUERY PLAN evidence** — committed for both read paths (proves `idx_folder` used, no temp
  sort; proves the FTS path uses the FTS index).
- **FTS5 integrity** — the harness runs the FTS5 `integrity-check` and asserts the hit count matches a
  direct count, proving the external-content index is consistent.
- **Evidence artifact** — committed to `docs/perf/m0-floor-gates-evidence.md`: all three search
  comparators (LIKE-substring / LIKE-prefix / FTS5), folder first+deep, p50/p95/p99/max + cold sample,
  the EXPLAIN QUERY PLAN output, the engine-RSS figure + WebView2-baseline estimate, corpus params,
  host context (CPU / OS / SQLite version), and the commit SHA. **Evidence into the repo**, not a relay.

---

## 5. Testing strategy

- **Hermetic correctness tests (default `cargo test`)** — small-corpus (hundreds of rows) tests proving
  the read paths are *correct*: folder-switch returns the right rows in the right order; keyset
  pagination (both statements) has no gaps/overlaps across page boundaries; FTS5 `MATCH` returns the
  token+prefix matches and excludes non-matches; **FTS stays in sync after inserts AND the
  `integrity-check` passes**; a deliberately-mis-ordered build (FTS created after insert)
  is caught by the integrity assertion. Fast, non-vacuous — no 1M rows needed for correctness.
- **Gated perf harness (`PHOTON_PERF=1`)** — the 1M-row floor proof (§4). Not in default CI; run
  deliberately, evidence committed.
- **Provider-id confinement test** — structural assertion that `message_header` carries only
  Photon-local refs.

`cargo clippy --workspace --all-targets -- -D warnings` and `RUSTDOCFLAGS="-D warnings" cargo doc
--workspace --no-deps` stay green (`RUSTDOCFLAGS` MUST be quoted — unquoted, the shell splits it and the
doc gate silently no-ops).

---

## 6. Invariants this slice must preserve

1. **Provider-id confinement** — no provider-native handle enters `message_header`.
2. **One schema owner** — `message_header` + index + FTS table/trigger created by
   `SqliteIntentLog::open`; the `_version` is bumped.
3. **`aruna` stays sync + HTTP-free** — no async runtime, no HTTP/TLS dep in the engine crate.
4. **Default `cargo test` stays hermetic + fast** — the 1M build is gate-only.
5. **Semantics pinned before the benchmark** — token+prefix; the forcing experiment compares the same
   query across all three engines; substring/trigram is out of scope.
6. **FTS consistency proven, not assumed** — build-before-insert + `integrity-check` + hit-count.
7. **Tail-hardened floors** — p95 < floor AND max < 2× floor, cold-first captured.
8. **Honest RAM** — engine-RSS proven + WebView2-baseline estimate; integrated Tauri idle-RAM → M4; no
   fabricated figure.

---

## 7. What success looks like

- `message_header` canonical read-side + `idx_folder` + FTS5 (token+prefix) landed in `aruna`, behind
  the one schema owner, hermetic correctness + integrity tests green.
- `docs/perf/m0-floor-gates-evidence.md` committed: folder first+deep p95<100ms & max<2×; header-search
  FTS5 p95<1s & max<2×; the LIKE-substring and LIKE-prefix comparators documenting the forcing; EXPLAIN
  QUERY PLAN output; engine-RSS + WebView2-baseline estimate.
- **M0 DoD §5 storage-floor PROVEN → M0 complete-at-the-storage-floor.** The integrated floors (true
  Tauri idle-RAM; folder switch incl. counts/flags/render) are carried as **M4-validated** in the DoD
  ledger. The architecture is validated; EVOLVE is validated.

---

## 8. Review decisions

Independent review converged on one class: *make the proof stricter + the closure honest*.
Resolutions:

- **Search semantics:** **token + prefix** (FTS5 standard + prefix index). Substring/infix
  (trigram) **deferred**. The forcing experiment runs three comparators on this same query
  (LIKE-substring / LIKE-prefix / FTS5) so D4's "only if forced" is tested honestly. → §3.3
- **Tail gate:** **p95 < floor AND max < 2× floor**, cold-first captured. → §4
- **Idle-RAM honesty:** engine-RSS proven now + `WebView2-baseline + engine-RSS` estimate;
  integrated Tauri idle-RAM → M4; §7 says *storage-floor proven*, not "fully proven." → §2, §7
- **FTS5 external-content discipline:** build FTS table/trigger **before** corpus insert (or
  rebuild after) + `integrity-check` + hit-count in the correctness test. → §3.1, §5
- **Folder query rigor:** split first-page / next-page statements (no `IS NULL OR` seek-defeat);
  commit EXPLAIN QUERY PLAN; benchmark cold-first + deep pages, not warm-first only. → §3.2, §4
- **RAM-probe dependency:** hand-rolled `GetProcessMemoryInfo` FFI (no new dep) over `sysinfo`. → §3.4

A re-review is not required: the changes are design-level. Leaf edges are caught at the code stage.
