//! Canonical header read side: minimal headers, folder-list and FTS5 search read paths.

use std::path::Path;

use rusqlite::Connection;

use crate::LogError;

/// One header row returned by the read paths. Photon-local refs only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRow {
    pub message_ref: String,
    pub received_at: i64,
    pub from_addr: String,
    pub from_name: String,
    pub subject: String,
    pub seen: bool,
    pub flagged: bool,
}

/// One row for [`SqliteMessageHeaderStore::bulk_load_headers`]: the same fields
/// [`SqliteMessageHeaderStore::record_header`] takes, owned rather than borrowed so a caller's
/// row-generation closure can hand one to each `next_row` call without a lifetime tied to the
/// store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkHeaderRow {
    pub account: String,
    pub message_ref: String,
    pub mailbox: String,
    pub received_at: i64,
    pub from_addr: String,
    pub from_name: String,
    pub subject: String,
    pub seen: bool,
    pub flagged: bool,
}

/// SQLite-backed header read side over the intent-log DB. The `message_header` table and FTS
/// index are created by [`crate::SqliteIntentLog::open`] (the one schema owner), so open the
/// intent log first.
pub struct SqliteMessageHeaderStore {
    /// The connection plus this store file's writer gate, minted together at the single open
    /// path (see `store_open::GatedConnection`). `record_header` enrolls around its single
    /// autocommit statement (`GatedConnection::with_enrolled_write`); a bulk corpus load uses the
    /// chunked enrolled API instead (see [`Self::bulk_load_headers`]).
    conn: crate::store_open::GatedConnection,
}

impl SqliteMessageHeaderStore {
    /// Open the store over the intent-log DB at `path`. Does not create the schema (the intent
    /// log owns it), so open the intent log first.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        // The shared chokepoint; see `SqliteMessageStore::open` and
        // `store_open::open_verified_connection`.
        let conn = crate::store_open::open_verified_connection(path.as_ref())?;
        Ok(Self { conn })
    }

    /// Test-only view of this store's connection, so the write gate can be checked on it. Not API
    /// surface.
    #[cfg(test)]
    pub(crate) fn conn_for_test(&self) -> &Connection {
        &self.conn
    }

    /// Insert a header (the FTS index is kept in sync by the AFTER INSERT trigger). Idempotent on
    /// `(account, message_ref)`: a re-record overwrites the prior header.
    #[allow(clippy::too_many_arguments)]
    pub fn record_header(
        &mut self,
        account: &str,
        message_ref: &str,
        mailbox: &str,
        received_at: i64,
        from_addr: &str,
        from_name: &str,
        subject: &str,
        seen: bool,
        flagged: bool,
    ) -> Result<(), LogError> {
        // One home for the upsert text, [`upsert_header_row`]. This store owns a connection; the
        // read coordinator owns a transaction on its own connection and calls the same function,
        // so the header write cannot drift into two spellings.
        //
        // Enrolled: a single autocommit statement is still a write to the store file, and
        // `with_enrolled_write` brackets it with exactly one `WriteScope`.
        self.conn.with_enrolled_write(|conn| {
            upsert_header_row(
                conn,
                account,
                message_ref,
                mailbox,
                received_at,
                from_addr,
                from_name,
                subject,
                seen,
                flagged,
            )
        })
    }

    /// First keyset page of a mailbox (newest first). A separate statement from next-page so the
    /// paginated branch never carries an `IS NULL OR` that would defeat the index seek.
    ///
    /// Joined against `message_placement` identity. A `message_header` row with no backing
    /// `message_placement` row is legacy or orphaned data (an older-schema header, or one half of
    /// an ingest transaction that never landed the placement half): visible but unactionable,
    /// since every verb resolves its provider identity through `message_placement`, so such a row
    /// can be neither acted on nor safely removed, and ingest cannot tell "already have this" from
    /// "orphaned header" without this same check. The `EXISTS` correlated subquery probes
    /// `message_placement`'s primary key `(account, message_ref)` per candidate row, an index
    /// seek rather than a join that changes the outer access path, so `idx_folder` still drives
    /// the scan and the `ORDER BY` needs no temp sort (see
    /// `folder_first_page_placement_join_stays_index_driven_no_temp_sort`). Ingest can still mint
    /// a fresh, actionable row for the same provider id; this only hides the orphan.
    pub fn folder_first_page(
        &self,
        account: &str,
        mailbox: &str,
        limit: i64,
    ) -> Result<Vec<HeaderRow>, LogError> {
        let limit = clamp_limit(limit);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT message_ref, received_at, from_addr, from_name, subject, seen, flagged
                   FROM message_header h WHERE h.account=?1 AND h.mailbox=?2
                    AND EXISTS (SELECT 1 FROM message_placement p
                                 WHERE p.account = h.account AND p.message_ref = h.message_ref)
                  ORDER BY h.received_at DESC, h.message_ref DESC LIMIT ?3;",
            )
            .map_err(|e| LogError(format!("message_header prepare: {e}")))?;
        map_rows(&mut stmt, &[&account, &mailbox, &limit])
    }

    /// Next keyset page: rows strictly before the cursor `(received_at, message_ref)` in DESC
    /// order. A separate statement from first-page: the row-value `<` bound is a clean index
    /// seek with no `IS NULL OR` to defeat it.
    ///
    /// Same `message_placement` identity join as [`Self::folder_first_page`]. An orphaned row
    /// between two paired ones is skipped, never paged over as a keyset gap.
    pub fn folder_next_page(
        &self,
        account: &str,
        mailbox: &str,
        cursor_ts: i64,
        cursor_ref: &str,
        limit: i64,
    ) -> Result<Vec<HeaderRow>, LogError> {
        let limit = clamp_limit(limit);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT message_ref, received_at, from_addr, from_name, subject, seen, flagged
                   FROM message_header h
                  WHERE h.account=?1 AND h.mailbox=?2
                    AND (h.received_at, h.message_ref) < (?3, ?4)
                    AND EXISTS (SELECT 1 FROM message_placement p
                                 WHERE p.account = h.account AND p.message_ref = h.message_ref)
                  ORDER BY h.received_at DESC, h.message_ref DESC LIMIT ?5;",
            )
            .map_err(|e| LogError(format!("message_header prepare: {e}")))?;
        map_rows(&mut stmt, &[&account, &mailbox, &cursor_ts, &cursor_ref, &limit])
    }

    /// Token+prefix header search via FTS5. The user term is sanitized to a plain token and turned
    /// into a prefix query (`term*`), bound as a parameter, never concatenated into SQL. An
    /// empty or whitespace-only term returns no rows (a bare `*` is not a valid FTS query).
    pub fn header_search(
        &self,
        account: &str,
        query: &str,
        limit: i64,
    ) -> Result<Vec<HeaderRow>, LogError> {
        let limit = clamp_limit(limit);
        let term = sanitize_fts_term(query);
        if term.is_empty() {
            return Ok(Vec::new());
        }
        // Quote each token as a phrase before appending the prefix `*`, so FTS5 boolean operator
        // words (AND/OR/NOT/NEAR) are literals, not query syntax (unquoted `AND*` is a syntax
        // error and `report OR x` would silently broaden). Tokens are already alphanumeric
        // (sanitized), so they contain no `"` to escape.
        let fts_query = term
            .split_whitespace()
            .map(|t| format!("\"{t}\"*"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut stmt = self
            .conn
            .prepare(
                "SELECT h.message_ref, h.received_at, h.from_addr, h.from_name, h.subject,
                        h.seen, h.flagged
                   FROM message_header_fts f
                   JOIN message_header h ON h.rowid = f.rowid
                  WHERE f.message_header_fts MATCH ?1 AND h.account = ?2
                  ORDER BY h.received_at DESC, h.message_ref DESC LIMIT ?3;",
            )
            .map_err(|e| LogError(format!("header_search prepare: {e}")))?;
        map_rows(&mut stmt, &[&fts_query, &account, &limit])
    }

    /// Total number of messages a header search matches (no limit), the non-vacuity check for the
    /// perf harness (a `LIMIT`-bounded result length cannot prove `0 < hits < N`).
    pub fn header_match_count(&self, account: &str, query: &str) -> Result<i64, LogError> {
        let term = sanitize_fts_term(query);
        if term.is_empty() {
            return Ok(0);
        }
        let fts_query = term
            .split_whitespace()
            .map(|t| format!("\"{t}\"*"))
            .collect::<Vec<_>>()
            .join(" ");
        // Drive the FTS index first via a rowid subquery, then count the matching content rows for
        // the account. A direct `JOIN ... COUNT(*)` lets the planner flip to scanning the whole
        // content table and probing the FTS per row, catastrophic at 1M rows (caught by the perf
        // harness).
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM message_header
                  WHERE account = ?2
                    AND rowid IN (SELECT rowid FROM message_header_fts
                                   WHERE message_header_fts MATCH ?1);",
                rusqlite::params![fts_query, account],
                |r| r.get(0),
            )
            .map_err(|e| LogError(format!("header_match_count: {e}")))
    }

    /// Run FTS5's built-in `integrity-check`. Returns `Ok(true)` if the external-content index is
    /// consistent with the content table, `Ok(false)` if SQLite reports corruption, and
    /// propagates any other error. Shows the build-before-insert discipline held.
    ///
    /// `#[cfg(test)]` because FTS5's `integrity-check` is invoked by inserting into the special
    /// column, which makes it a writer-class statement (it blocks behind a held writer and holds
    /// the write lock against one). A production diagnostic surface must go through an enrolled
    /// `WriteScope`, never a bare `execute_batch`: an FTS integrity sweep over a large index is
    /// the unbounded hold the chunk budget exists to bound.
    #[cfg(test)]
    pub fn fts_integrity_ok(&self) -> Result<bool, LogError> {
        // rank=1 makes the integrity-check also verify the FTS index matches the external
        // content table (without it, only the index's internal consistency is checked, which
        // would not catch a content/index desync).
        match self.conn.execute_batch(
            "INSERT INTO message_header_fts(message_header_fts, rank) VALUES('integrity-check', 1);",
        ) {
            Ok(()) => Ok(true),
            // A real index/content desync surfaces as SQLITE_CORRUPT (extended
            // SQLITE_CORRUPT_VTAB), whose message is "database disk image is malformed", not
            // "corrupt". Match the error code, not the text, so a detected inconsistency is
            // reported as Ok(false) and never mistaken for an unrelated operational error.
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseCorrupt =>
            {
                Ok(false)
            }
            Err(e) => Err(LogError(format!("fts integrity-check: {e}"))),
        }
    }

    /// Return the joined `EXPLAIN QUERY PLAN` detail lines for a query: the committed evidence
    /// that a read path uses its intended index and avoids a temp B-tree sort.
    pub fn explain_query_plan(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<String, LogError> {
        let mut stmt = self
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .map_err(|e| LogError(format!("eqp prepare: {e}")))?;
        let rows = stmt
            .query_map(params, |r| r.get::<_, String>(3))
            .map_err(|e| LogError(format!("eqp query: {e}")))?;
        Ok(rows.filter_map(|r| r.ok()).collect::<Vec<_>>().join(" | "))
    }

    /// The ordered column names of `message_header`, showing the schema carries only Photon-local
    /// refs and no provider-native id (the confinement invariant).
    pub fn column_names(&self) -> Result<Vec<String>, LogError> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM pragma_table_info('message_header')")
            .map_err(|e| LogError(format!("table_info: {e}")))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| LogError(format!("table_info query: {e}")))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| LogError(format!("table_info row: {e}")))
    }

    /// The chunked bulk-write path. It replaces a raw `begin()`/`commit()` pair (a single
    /// unenrolled, unbounded transaction the perf harness held open across 1M rows) with an
    /// enrolled, chunk-bounded load: `next_row` is polled repeatedly and every row it returns is
    /// written inside the current chunk's `GatedConnection::with_immediate_tx` transaction (private,
    /// hence plain code font), one enrolled `WriteScope` per chunk, re-acquired between chunks and
    /// never held across the whole load.
    ///
    /// **The chunk budget is a row count, not a clock.** `rows_per_chunk` stands in for
    /// `writer_chunk_budget_ms` (`CapacityConfig::writer_chunk_budget_ms`, 50ms default) because
    /// elapsed time cannot be measured from inside a chunk: the scope `with_immediate_tx` enrolls
    /// is deliberately never handed to the closure, so a chunk cannot read its own elapsed time
    /// or self-truncate. The caller derives `rows_per_chunk` from its measured per-row write cost
    /// so that `rows_per_chunk * per_row_cost` stays at or under the budget (see
    /// `perf_floor_gates.rs`). A pending sever then waits behind at most one chunk. An oversized
    /// chunk buys its own sever wait, and not silently: the writer-gate belt reports every
    /// enrolled hold that exceeds the budget.
    ///
    /// Each chunk is materialized before its transaction opens (see the loop below), so only
    /// upserts run inside the enrolled span. Stops without writing a partial row when `next_row`
    /// returns `None`. A write failure inside a chunk rolls that chunk back (earlier completed
    /// chunks stay durable: the chunk is the atomic unit). Returns the total row count written.
    pub fn bulk_load_headers(
        &mut self,
        rows_per_chunk: usize,
        mut next_row: impl FnMut() -> Option<BulkHeaderRow>,
    ) -> Result<usize, LogError> {
        assert!(
            rows_per_chunk > 0,
            "bulk_load_headers: rows_per_chunk must be > 0 (it is the chunk-budget row count)"
        );
        let mut written = 0usize;
        let mut chunk: Vec<BulkHeaderRow> = Vec::with_capacity(rows_per_chunk);
        loop {
            // Materialize first, outside the enrollment. `next_row` is the caller's closure and
            // this method knows nothing about what it does (the perf harness's generator formats
            // strings and runs an LCG per call, and a future caller's could decode, decompress or
            // read a file). Calling it inside the chunk's transaction would hold the writer slot
            // for the caller's generation cost as well as the write cost, and the row count the
            // chunk budget is derived from would stop bounding the hold. Building the chunk here
            // keeps the enrolled span to upserts only, so `rows_per_chunk * per_row_write_cost`
            // is an accurate estimate of it.
            chunk.clear();
            while chunk.len() < rows_per_chunk {
                match next_row() {
                    Some(row) => chunk.push(row),
                    None => break,
                }
            }
            if chunk.is_empty() {
                break;
            }
            self.conn.with_immediate_tx(|tx| {
                for row in &chunk {
                    upsert_header_row(
                        tx,
                        &row.account,
                        &row.message_ref,
                        &row.mailbox,
                        row.received_at,
                        &row.from_addr,
                        &row.from_name,
                        &row.subject,
                        row.seen,
                        row.flagged,
                    )?;
                }
                Ok::<(), LogError>(())
            })?;
            written += chunk.len();
            // A short chunk means `next_row` answered `None` while filling it: the corpus is
            // exhausted and another pass would only re-ask a generator that has already said so.
            if chunk.len() < rows_per_chunk {
                break;
            }
        }
        Ok(written)
    }

    /// Unindexed column-prefix scan baseline (`subject LIKE 'term%'`, no index on `subject`).
    /// Two caveats: (1) this is a full scan, not an indexed prefix; (2) `subject`-prefix only
    /// matches subjects that start with the term, the wrong semantic for token-anywhere header
    /// search, so a column-prefix index is not a valid alternative to FTS5. It stands only as the
    /// cost of scanning text without the inverted index. User `%`/`_` are stripped so it stays a
    /// plain prefix.
    pub fn like_prefix_search(
        &self,
        account: &str,
        term: &str,
        limit: i64,
    ) -> Result<Vec<HeaderRow>, LogError> {
        let limit = clamp_limit(limit);
        let pat = format!("{}%", term.replace(['%', '_'], ""));
        let mut stmt = self
            .conn
            .prepare(
                "SELECT message_ref, received_at, from_addr, from_name, subject, seen, flagged
                   FROM message_header
                  WHERE account=?1 AND subject LIKE ?2 ORDER BY received_at DESC LIMIT ?3;",
            )
            .map_err(|e| LogError(format!("like-prefix prepare: {e}")))?;
        map_rows(&mut stmt, &[&account, &pat, &limit])
    }

    /// Substring strawman (`subject LIKE '%term%'`): the full-scan baseline showing why a scan is
    /// too slow and FTS5 is needed.
    pub fn like_substring_search(
        &self,
        account: &str,
        term: &str,
        limit: i64,
    ) -> Result<Vec<HeaderRow>, LogError> {
        let limit = clamp_limit(limit);
        let pat = format!("%{}%", term.replace(['%', '_'], ""));
        let mut stmt = self
            .conn
            .prepare(
                "SELECT message_ref, received_at, from_addr, from_name, subject, seen, flagged
                   FROM message_header
                  WHERE account=?1 AND subject LIKE ?2 ORDER BY received_at DESC LIMIT ?3;",
            )
            .map_err(|e| LogError(format!("like-substr prepare: {e}")))?;
        map_rows(&mut stmt, &[&account, &pat, &limit])
    }
}

/// The header upsert, as one text: the write behind both
/// [`SqliteMessageHeaderStore::record_header`] and the read coordinator's atomic ingest.
///
/// It takes `&Connection` rather than `&mut self` because `rusqlite::Transaction` derefs to
/// `Connection`: the coordinator must run this write and the `message_placement` write inside one
/// transaction, and a transaction cannot span two connections. Extracting the statement keeps the
/// ON CONFLICT clause (the FTS-resyncing UPDATE path and the `seen`/`flagged` columns) in one
/// home; a duplicated copy rots when the next column lands.
///
/// `prepare_cached` reuses the compiled statement across calls (the intent log and bulk corpus
/// build call this in a tight loop, and re-preparing per row is the dominant cost otherwise). On
/// a `Transaction` the cache is the underlying connection's, so the reuse survives the deref.
#[allow(clippy::too_many_arguments)]
pub(crate) fn upsert_header_row(
    conn: &Connection,
    account: &str,
    message_ref: &str,
    mailbox: &str,
    received_at: i64,
    from_addr: &str,
    from_name: &str,
    subject: &str,
    seen: bool,
    flagged: bool,
) -> Result<(), LogError> {
    let mut stmt = conn
        .prepare_cached(
            // `ingest_revision` is the version marker the reconcile's apply-phase
            // compare-and-set proves a row by, so a reader that materialized the row earlier can
            // tell it has not been re-confirmed since. This upsert is the only path provider
            // evidence enters `message_header` through (`record_header`, `bulk_load_headers` and
            // the coordinator's `ingest_row`), which makes the marker complete.
            //
            // The revision is store-monotonic, not per-row. A per-row number (`0` on insert,
            // `ingest_revision + 1` on conflict) goes away with the row on DELETE, so a reinsert
            // would restart at 0 and an older reconcile holding `decided_ingest_revision = 0`
            // would match the brand-new row, and its CAS would delete evidence written after the
            // verdict that condemned it.
            //
            // So the value is issued from `ingest_revision_seq`, one number per store (see
            // `store_open::schema_ddl`). `high_water + 1` is read here and the table's
            // `message_header_ingest_revision_ai`/`_au` triggers raise the high water to it,
            // inside this statement, so issue-and-record is atomic under SQLite's single-writer
            // rule and two writers can never take one number. Nothing lowers the high water, so
            // every value issued after a decision is strictly greater than the decided one,
            // whether or not the row was deleted in between. `excluded.ingest_revision` on the
            // conflict arm is that same value, computed once in the VALUES clause.
            //
            // `from_status` / `from_domain` are derived here from the `from_addr` this function
            // writes, by RFC 5322 §3.4 (`mailbox::sender_facts`), so no writer can store a sender
            // whose status or domain disagrees with its `from_addr`.
            "INSERT INTO message_header
                 (account, message_ref, mailbox, received_at, from_addr, from_name, subject,
                  seen, flagged, ingest_revision, from_status, from_domain)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                         (SELECT high_water FROM ingest_revision_seq WHERE id = 0) + 1, ?10, ?11)
             ON CONFLICT(account, message_ref) DO UPDATE SET
                 mailbox=excluded.mailbox, received_at=excluded.received_at,
                 from_addr=excluded.from_addr, from_name=excluded.from_name,
                 subject=excluded.subject, seen=excluded.seen, flagged=excluded.flagged,
                 ingest_revision=excluded.ingest_revision, from_status=excluded.from_status,
                 from_domain=excluded.from_domain;",
        )
        .map_err(|e| LogError(format!("message_header prepare: {e}")))?;
    let (from_status, from_domain) = crate::mailbox::sender_facts(from_addr);
    stmt.execute(rusqlite::params![
        account,
        message_ref,
        mailbox,
        received_at,
        from_addr,
        from_name,
        subject,
        seen as i64,
        flagged as i64,
        from_status.as_token(),
        from_domain
    ])
    .map_err(|e| LogError(format!("message_header write: {e}")))?;
    Ok(())
}

/// The bundled SQLite version string (host context for the perf evidence; keeps `rusqlite`
/// internal to `aruna` so the integration-test harness need not depend on it directly).
pub fn sqlite_version() -> &'static str {
    rusqlite::version()
}

/// Upper bound on a single read page. A caller-supplied `limit` is clamped into
/// `[1, MAX_PAGE_LIMIT]` before binding: a non-positive limit would become SQLite `LIMIT -1`
/// (unbounded, materializing the entire 1M-row folder and defeating the perf floor), and an
/// oversized one would do the same by degree. Clamping rather than rejecting keeps the read paths
/// infallible for the UI while guaranteeing a bounded query.
const MAX_PAGE_LIMIT: i64 = 1000;

/// Clamp a caller-supplied page limit into `[1, MAX_PAGE_LIMIT]` so it can never bind an
/// unbounded or pathologically large `LIMIT`.
fn clamp_limit(limit: i64) -> i64 {
    limit.clamp(1, MAX_PAGE_LIMIT)
}

/// Strip FTS5 syntax so a user term becomes a plain prefix token, not an injected FTS expression.
/// Keeps alphanumerics, collapses every other char to a space, then joins on single spaces.
fn sanitize_fts_term(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Run a prepared SELECT of the seven header columns (including `seen`/`flagged`) into
/// `HeaderRow`s.
fn map_rows(
    stmt: &mut rusqlite::Statement,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<HeaderRow>, LogError> {
    let rows = stmt
        .query_map(params, |r| {
            Ok(HeaderRow {
                message_ref: r.get(0)?,
                received_at: r.get(1)?,
                from_addr: r.get(2)?,
                from_name: r.get(3)?,
                subject: r.get(4)?,
                seen: r.get::<_, i64>(5)? != 0,
                flagged: r.get::<_, i64>(6)? != 0,
            })
        })
        .map_err(|e| LogError(format!("message_header read: {e}")))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| LogError(format!("message_header row: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the guard comes FIRST in the tuple — a tuple pattern's bindings
    /// drop right to left, so `let (path, s) = store(..)` closes the store before the guard deletes.
    fn store(tag: &str) -> (crate::test_temp::TempFile, SqliteMessageHeaderStore) {
        let path = crate::test_temp::TempFile::sqlite(&format!("aruna-mh-{tag}"));
        let _log = crate::SqliteIntentLog::open(&path).unwrap();
        let store = SqliteMessageHeaderStore::open(&path).unwrap();
        (path, store)
    }

    /// Drop the store's SQLite connection BEFORE deleting the temp DB. On Windows an open handle makes
    /// `remove_file` fail, and a swallowed error leaks `aruna-mh-*.sqlite` into %TEMP% on every normal
    /// `cargo test` run (2026-06-26). Takes the store by value so the handle is closed,
    /// then surfaces any cleanup failure instead of hiding it.
    fn cleanup(s: SqliteMessageHeaderStore, path: crate::test_temp::TempFile) {
        drop(s);
        // The guard removes the store family and panics naming any leak.
        drop(path);
    }

    /// RED: `record_header` is a projection WRITE to the store file — same
    /// property, same shape, as `message_store.rs`'s
    /// `a_message_store_write_waits_behind_a_pending_sever`: thread A holds a `WriteScope`
    /// (barrier-paused), thread B calls `record_header`, and the TIMING-FREE witness is the
    /// gate's own `enroll_waiters` counter. Pre-fix this store writes directly on
    /// `&Connection` with no `enroll()` call anywhere, so B races straight through and the HANG
    /// GUARD fires; post-fix (`GatedConnection::with_enrolled_write`) B parks behind A.
    #[test]
    fn a_header_store_write_waits_behind_a_pending_sever() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (path, mut s) = store("write-waits-behind-scope");
        let observer = Arc::new(
            crate::writer_gate::WriterGate::for_path(&path).expect("identity is obtainable"),
        );
        assert!(
            !observer.snapshot().expect("snapshot").active_writer,
            "no writer is enrolled before the held scope starts"
        );

        let paused = Arc::new(Barrier::new(2));
        let release = Arc::new(AtomicBool::new(false));

        let holder = {
            let observer = Arc::clone(&observer);
            let (paused, release) = (Arc::clone(&paused), Arc::clone(&release));
            thread::spawn(move || {
                let scope = observer.enroll().expect("the holder enrolls first");
                paused.wait(); // ── the scope is HELD from here ──
                while !release.load(Ordering::SeqCst) {
                    thread::yield_now();
                }
                drop(scope);
            })
        };
        paused.wait();

        let writer = thread::spawn(move || {
            s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "hello", false, false)
                .expect("the write eventually succeeds once the scope releases");
            s
        });

        let started = std::time::Instant::now();
        while observer.snapshot().expect("snapshot").enroll_waiters != 1 {
            assert!(
                started.elapsed() <= std::time::Duration::from_secs(15),
                "HANG GUARD: `record_header` never parked behind the held scope — it ran \
                 UNGATED while the store's writer gate was held"
            );
            thread::yield_now();
        }

        release.store(true, Ordering::SeqCst);
        holder.join().expect("holder thread");
        let s = writer.join().expect("writer thread");
        let landed: i64 = s
            .conn_for_test()
            .query_row(
                "SELECT COUNT(*) FROM message_header WHERE account='a' AND message_ref='m1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(landed, 1, "the header row must have landed once the scope released");
        cleanup(s, path);
    }

    #[test]
    fn records_and_counts_a_header() {
        let (path, mut s) = store("record");
        s.record_header("a", "m1", "Inbox", 100, "x@y.z", "X", "hello world", false, false)
            .unwrap();
        insert_placement(&s, "a", "m1", "E-m1");
        let page = s.folder_first_page("a", "Inbox", 10).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].message_ref, "m1");
        assert_eq!(page[0].subject, "hello world");
        cleanup(s, path);
    }

    #[test]
    fn keyset_paging_is_ordered_with_no_gaps_or_overlap() {
        let (path, mut s) = store("paging");
        // 5 rows in Inbox at received_at 10,20,30,40,50 + one in Archive (must be excluded).
        for (i, ts) in [(1, 10), (2, 20), (3, 30), (4, 40), (5, 50)] {
            s.record_header("a", &format!("m{i}"), "Inbox", ts, "x@y.z", "X", "subj", false, false)
                .unwrap();
            insert_placement(&s, "a", &format!("m{i}"), &format!("E-m{i}"));
        }
        s.record_header("a", "z9", "Archive", 99, "x@y.z", "X", "other", false, false)
            .unwrap();
        insert_placement(&s, "a", "z9", "E-z9");

        let p1 = s.folder_first_page("a", "Inbox", 2).unwrap();
        assert_eq!(
            p1.iter().map(|r| r.received_at).collect::<Vec<_>>(),
            vec![50, 40]
        );
        let cur = (p1[1].received_at, p1[1].message_ref.clone());
        let p2 = s.folder_next_page("a", "Inbox", cur.0, &cur.1, 2).unwrap();
        assert_eq!(
            p2.iter().map(|r| r.received_at).collect::<Vec<_>>(),
            vec![30, 20]
        );
        let cur = (p2[1].received_at, p2[1].message_ref.clone());
        let p3 = s.folder_next_page("a", "Inbox", cur.0, &cur.1, 2).unwrap();
        assert_eq!(p3.iter().map(|r| r.received_at).collect::<Vec<_>>(), vec![10]);
        // The Archive row never appeared in any Inbox page.
        cleanup(s, path);
    }

    #[test]
    fn header_search_matches_token_and_prefix_excludes_nonmatches() {
        let (path, mut s) = store("search");
        s.record_header("a", "m1", "Inbox", 10, "deals@amazon.com", "Amazon", "Your order shipped", false, false)
            .unwrap();
        s.record_header("a", "m2", "Inbox", 20, "ceo@acme.io", "Acme", "Quarterly meeting notes", false, false)
            .unwrap();
        // token match
        let r = s.header_search("a", "meeting", 10).unwrap();
        assert_eq!(
            r.iter().map(|h| h.message_ref.as_str()).collect::<Vec<_>>(),
            vec!["m2"]
        );
        // prefix match: "amaz" finds "Amazon"
        let r = s.header_search("a", "amaz", 10).unwrap();
        assert_eq!(
            r.iter().map(|h| h.message_ref.as_str()).collect::<Vec<_>>(),
            vec!["m1"]
        );
        // non-match
        assert!(s.header_search("a", "zebra", 10).unwrap().is_empty());
        cleanup(s, path);
    }

    #[test]
    fn header_search_empty_query_returns_empty() {
        let (path, mut s) = store("search-empty");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "hello", false, false)
            .unwrap();
        assert!(s.header_search("a", "   ", 10).unwrap().is_empty());
        cleanup(s, path);
    }

    #[test]
    fn fts_integrity_holds_for_normal_inserts() {
        let (path, mut s) = store("fts-integrity");
        for i in 0..50 {
            s.record_header("a", &format!("m{i}"), "Inbox", i, "x@y.z", "X", "alpha beta", false, false)
                .unwrap();
        }
        assert!(
            s.fts_integrity_ok().unwrap(),
            "FTS index must be consistent with the content table"
        );
        // hit-count sanity: every row contains "alpha"
        assert_eq!(s.header_search("a", "alpha", 100).unwrap().len(), 50);
        cleanup(s, path);
    }

    #[test]
    fn folder_first_page_uses_idx_folder_no_temp_sort() {
        let (path, s) = store("eqp");
        let plan = s
            .explain_query_plan(
                "SELECT message_ref, received_at, from_addr, from_name, subject
                   FROM message_header WHERE account=?1 AND mailbox=?2
                  ORDER BY received_at DESC, message_ref DESC LIMIT ?3;",
                &[&"a", &"Inbox", &10i64],
            )
            .unwrap();
        assert!(
            plan.contains("idx_folder"),
            "folder page must use idx_folder; plan was: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("USE TEMP B-TREE"),
            "folder page must not temp-sort; plan was: {plan}"
        );
        cleanup(s, path);
    }

    #[test]
    fn re_recording_a_header_resyncs_fts_old_token_gone_new_token_found() {
        let (path, mut s) = store("upsert-resync");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "alpha subject", false, false)
            .unwrap();
        assert_eq!(s.header_search("a", "alpha", 10).unwrap().len(), 1);
        // Re-record the SAME (account, message_ref) with a new subject (the UPSERT UPDATE path).
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "zebra subject", false, false)
            .unwrap();
        assert!(
            s.header_search("a", "alpha", 10).unwrap().is_empty(),
            "old token must no longer match after re-record"
        );
        assert_eq!(
            s.header_search("a", "zebra", 10).unwrap().len(),
            1,
            "new token must match after re-record"
        );
        assert!(s.fts_integrity_ok().unwrap(), "FTS must stay consistent across the UPDATE");
        cleanup(s, path);
    }

    #[test]
    fn clamp_limit_bounds_non_positive_and_oversized() {
        assert_eq!(clamp_limit(-1), 1, "a negative limit must clamp to 1, never bind LIMIT -1");
        assert_eq!(clamp_limit(0), 1, "zero must clamp to 1");
        assert_eq!(clamp_limit(50), 50, "an in-range limit passes through");
        assert_eq!(clamp_limit(i64::MAX), MAX_PAGE_LIMIT, "oversized clamps to the page ceiling");
    }

    #[test]
    fn a_non_positive_limit_is_bounded_not_unbounded() {
        let (path, mut s) = store("limit-clamp");
        // 5 rows: a negative limit (SQLite LIMIT -1 = unbounded) would return ALL of them; clamped to
        // 1 it returns exactly one — proof the read path can't be coerced into a full-folder scan.
        for i in 0..5 {
            s.record_header("a", &format!("m{i}"), "Inbox", i, "x@y.z", "X", "subj", false, false)
                .unwrap();
            insert_placement(&s, "a", &format!("m{i}"), &format!("E-m{i}"));
        }
        assert_eq!(
            s.folder_first_page("a", "Inbox", -1).unwrap().len(),
            1,
            "a negative folder limit must be clamped (bounded), not unbounded"
        );
        cleanup(s, path);
    }

    #[test]
    fn fts_integrity_reports_false_not_err_on_a_real_desync() {
        let (path, mut s) = store("fts-desync");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "alpha subject", false, false)
            .unwrap();
        assert!(s.fts_integrity_ok().unwrap(), "a synced index reports Ok(true)");
        // Force a real desync: drop the UPDATE trigger, then mutate the content so the FTS index keeps
        // the OLD tokens while the content row changed. integrity-check (rank=1) detects the mismatch
        // and SQLite raises SQLITE_CORRUPT whose message is "database disk image is malformed" — the
        // code path must return Ok(false), NOT Err (the substring "corrupt" is absent). (.)
        s.conn
            .execute_batch(
                "DROP TRIGGER message_header_au;
                 UPDATE message_header SET subject='zzzdesync' WHERE message_ref='m1';",
            )
            .unwrap();
        assert!(
            !s.fts_integrity_ok().unwrap(),
            "a desynced external-content index must report Ok(false), not Err"
        );
        cleanup(s, path);
    }

    #[test]
    fn fts_operator_words_are_treated_as_literals_not_syntax() {
        let (path, mut s) = store("fts-operators");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "the AND clause", false, false)
            .unwrap();
        s.record_header("a", "m2", "Inbox", 20, "x@y.z", "X", "unrelated note", false, false)
            .unwrap();
        // "AND" must be a literal token search (returns the row containing it), NOT a syntax error.
        let r = s.header_search("a", "AND", 10).unwrap();
        assert_eq!(
            r.iter().map(|h| h.message_ref.as_str()).collect::<Vec<_>>(),
            vec!["m1"]
        );
        // A bare operator that matches nothing returns empty, not Err.
        assert!(s.header_search("a", "OR", 10).unwrap().is_empty());
        cleanup(s, path);
    }

    #[test]
    fn keyset_paging_handles_duplicate_received_at_across_a_boundary() {
        let (path, mut s) = store("paging-ties");
        // Four rows all at received_at=10 — the page boundary falls amid a timestamp tie.
        for i in 0..4 {
            s.record_header("a", &format!("m{i}"), "Inbox", 10, "x@y.z", "X", "subj", false, false)
                .unwrap();
            insert_placement(&s, "a", &format!("m{i}"), &format!("E-m{i}"));
        }
        let p1 = s.folder_first_page("a", "Inbox", 2).unwrap();
        let cur = (p1[1].received_at, p1[1].message_ref.clone());
        let p2 = s.folder_next_page("a", "Inbox", cur.0, &cur.1, 2).unwrap();
        let mut seen: Vec<String> = p1.iter().chain(p2.iter()).map(|r| r.message_ref.clone()).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 4, "all 4 tied rows seen exactly once (no skip, no overlap)");
        cleanup(s, path);
    }

    #[test]
    fn header_match_count_is_the_true_total_not_a_limited_page() {
        let (path, mut s) = store("match-count");
        for i in 0..30 {
            s.record_header("a", &format!("m{i}"), "Inbox", i, "x@y.z", "X", "report ready", false, false)
                .unwrap();
        }
        // 30 matches, but a limited search returns only the page; the count is the true total.
        assert_eq!(s.header_search("a", "report", 5).unwrap().len(), 5);
        assert_eq!(s.header_match_count("a", "report").unwrap(), 30);
        cleanup(s, path);
    }

    #[test]
    fn record_header_round_trips_seen_and_flagged() {
        let (path, mut s) = store("flags-roundtrip");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "hello world", false, true)
            .unwrap();
        insert_placement(&s, "a", "m1", "E-m1");
        let page = s.folder_first_page("a", "Inbox", 10).unwrap();
        assert_eq!(page.len(), 1);
        assert!(!page[0].seen, "seen=false must round-trip as false");
        assert!(page[0].flagged, "flagged=true must round-trip as true");
        cleanup(s, path);
    }

    #[test]
    fn re_recording_a_header_flips_flagged_state() {
        let (path, mut s) = store("flags-flip");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "hello world", false, false)
            .unwrap();
        insert_placement(&s, "a", "m1", "E-m1");
        let page = s.folder_first_page("a", "Inbox", 10).unwrap();
        assert!(!page[0].flagged, "initial record must be unflagged");
        // The probe inverted: a star re-record CHANGES the existing row (UPSERT), it
        // does not create a second row or leave the old flag state stuck.
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "hello world", false, true)
            .unwrap();
        let page = s.folder_first_page("a", "Inbox", 10).unwrap();
        assert_eq!(page.len(), 1, "re-record must UPSERT the same row, not duplicate it");
        assert!(page[0].flagged, "re-record with flagged=true must flip the row to flagged");
        cleanup(s, path);
    }

    #[test]
    fn folder_next_page_also_selects_flags() {
        let (path, mut s) = store("flags-nextpage");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "subj", true, false)
            .unwrap();
        s.record_header("a", "m2", "Inbox", 20, "x@y.z", "X", "subj", false, true)
            .unwrap();
        insert_placement(&s, "a", "m1", "E-m1");
        insert_placement(&s, "a", "m2", "E-m2");
        let p1 = s.folder_first_page("a", "Inbox", 1).unwrap();
        assert_eq!(p1.len(), 1);
        assert!(!p1[0].seen, "m2 (newest) is unseen");
        assert!(p1[0].flagged, "m2 (newest) is flagged");
        let p2 = s
            .folder_next_page("a", "Inbox", p1[0].received_at, &p1[0].message_ref, 1)
            .unwrap();
        assert_eq!(p2.len(), 1);
        assert!(p2[0].seen, "m1 (page 2) is seen");
        assert!(!p2[0].flagged, "m1 (page 2) is not flagged");
        cleanup(s, path);
    }

    #[test]
    fn header_search_results_carry_flags_and_fts_indexing_is_unchanged() {
        let (path, mut s) = store("flags-search");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "Quarterly report ready", true, true)
            .unwrap();
        let r = s.header_search("a", "quarterly", 10).unwrap();
        assert_eq!(
            r.iter().map(|h| h.message_ref.as_str()).collect::<Vec<_>>(),
            vec!["m1"],
            "FTS token match must be unaffected by the added flag columns"
        );
        assert!(r[0].seen, "search result must carry seen");
        assert!(r[0].flagged, "search result must carry flagged");
        cleanup(s, path);
    }

    /// A header row with no `message_placement` identity is LEGACY/unactionable: a
    /// v8 store (or a header written before the placement half of an ingest transaction lands) can
    /// hold a `message_header` row that no `message_placement` row backs, and it must not be page-
    /// visible — visible-but-unactionable rows are neither removable through any verb (every verb
    /// resolves its provider identity through `message_placement`) nor safely re-mintable (ingest
    /// cannot tell "already have this" from "orphaned header" without the join this fold adds).
    fn insert_placement(s: &SqliteMessageHeaderStore, account: &str, message_ref: &str, email_id: &str) {
        s.conn_for_test()
            .execute(
                "INSERT INTO message_placement (account, message_ref, email_id, placement)
                     VALUES (?1, ?2, ?3, 'Inbox');",
                rusqlite::params![account, message_ref, email_id],
            )
            .unwrap();
    }

    #[test]
    fn folder_first_page_excludes_a_header_row_with_no_placement_identity() {
        let (path, mut s) = store("legacy-header-first-page");
        s.record_header("a", "paired", "Inbox", 20, "x@y.z", "X", "has a placement", false, false)
            .unwrap();
        s.record_header("a", "orphan", "Inbox", 10, "x@y.z", "X", "no placement row", false, false)
            .unwrap();
        insert_placement(&s, "a", "paired", "E-paired");
        // "orphan" is deliberately left WITHOUT a message_placement row.

        let page = s.folder_first_page("a", "Inbox", 10).unwrap();
        let refs: Vec<&str> = page.iter().map(|r| r.message_ref.as_str()).collect();
        assert_eq!(
            refs,
            vec!["paired"],
            "the unpaired legacy row must be invisible to the page; the paired row is unaffected"
        );
        cleanup(s, path);
    }

    #[test]
    fn folder_next_page_also_excludes_a_header_row_with_no_placement_identity() {
        let (path, mut s) = store("legacy-header-next-page");
        s.record_header("a", "newest", "Inbox", 30, "x@y.z", "X", "paired", false, false)
            .unwrap();
        s.record_header("a", "orphan", "Inbox", 20, "x@y.z", "X", "no placement row", false, false)
            .unwrap();
        s.record_header("a", "oldest", "Inbox", 10, "x@y.z", "X", "paired", false, false)
            .unwrap();
        insert_placement(&s, "a", "newest", "E-newest");
        insert_placement(&s, "a", "oldest", "E-oldest");

        let p1 = s.folder_first_page("a", "Inbox", 1).unwrap();
        assert_eq!(p1.len(), 1);
        assert_eq!(p1[0].message_ref, "newest");
        let p2 = s
            .folder_next_page("a", "Inbox", p1[0].received_at, &p1[0].message_ref, 10)
            .unwrap();
        let refs: Vec<&str> = p2.iter().map(|r| r.message_ref.as_str()).collect();
        assert_eq!(
            refs,
            vec!["oldest"],
            "the orphaned row between the two paired ones must be skipped, never paged over as a \
             gap in the keyset walk"
        );
        cleanup(s, path);
    }

    /// The query-plan witness (design §3.2/§4, C2): the placement join must not defeat
    /// `idx_folder` or force a temp-sort — a correlated `EXISTS` probe against
    /// `message_placement`'s own primary key is a per-row index seek, not a join that changes the
    /// outer query's access path or ORDER BY.
    #[test]
    fn folder_first_page_placement_join_stays_index_driven_no_temp_sort() {
        let (path, s) = store("legacy-header-eqp");
        let plan = s
            .explain_query_plan(
                "SELECT message_ref, received_at, from_addr, from_name, subject, seen, flagged
                   FROM message_header h WHERE h.account=?1 AND h.mailbox=?2
                    AND EXISTS (SELECT 1 FROM message_placement p
                                 WHERE p.account = h.account AND p.message_ref = h.message_ref)
                  ORDER BY h.received_at DESC, h.message_ref DESC LIMIT ?3;",
                &[&"a", &"Inbox", &10i64],
            )
            .unwrap();
        assert!(
            plan.contains("idx_folder"),
            "the outer folder page must still use idx_folder; plan was: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("USE TEMP B-TREE"),
            "the placement join must not force a temp sort; plan was: {plan}"
        );
        assert!(
            plan.to_uppercase().contains("MESSAGE_PLACEMENT"),
            "the plan must show the placement existence check running; plan was: {plan}"
        );
        cleanup(s, path);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // CLOSE B — `ingest_revision` is STORE-MONOTONIC.
    //
    // The DISCRIMINATING witness for the harm lives at the reconcile
    // (`read_coordinator.rs`'s `_r5_a_delete_and_reinsert_cannot_resurrect_a_stale_
    // reconcile_verdict`). These two own the MARKER's own property and its migration, so a
    // later change to the issuing statement fails here, by name, rather than at whichever
    // consumer happened to notice.
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// The `ingest_revision` one header row carries right now.
    fn revision_of(s: &SqliteMessageHeaderStore, account: &str, message_ref: &str) -> i64 {
        s.conn_for_test()
            .query_row(
                "SELECT ingest_revision FROM message_header WHERE account=?1 AND message_ref=?2;",
                rusqlite::params![account, message_ref],
                |r| r.get(0),
            )
            .expect("the header row exists")
    }

    #[test]
    fn a_reinserted_header_row_never_reuses_a_revision() {
        // THE PROPERTY, at its own level: the number is a property of the STORE, not of the
        // ROW, so it survives the row. Pre-fix the INSERT arm wrote a literal 0 and every
        // reinsert started over — which is what let an older reconcile's compare-and-set match
        // a row written after its verdict.
        let (path, mut s) = store("r5-monotonic-across-delete");
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "first", false, false)
            .unwrap();
        let first = revision_of(&s, "a", "m1");

        // A re-write bumps it (the contract, unchanged).
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "second", false, false)
            .unwrap();
        let second = revision_of(&s, "a", "m1");
        assert!(second > first, "a re-write must move the marker: {first} -> {second}");

        // THE ROW GOES — exactly what an intervening reconcile does.
        s.conn_for_test()
            .execute(
                "DELETE FROM message_header WHERE account='a' AND message_ref='m1';",
                [],
            )
            .unwrap();

        // …and comes back through the one ingest door. The value must be STRICTLY GREATER than
        // anything this store ever issued, not a fresh 0.
        s.record_header("a", "m1", "Inbox", 10, "x@y.z", "X", "reinserted", false, false)
            .unwrap();
        let reinserted = revision_of(&s, "a", "m1");
        assert!(
            reinserted > second,
            "a REINSERTED row must not reuse a revision the store has already issued \
             (deleted at {second}, reinserted at {reinserted}) — a decision naming {second} \
             would otherwise match a row written after it"
        );

        // A THIRD row is likewise above, so the number is one sequence for the whole store and
        // not a per-row counter that happens to have been carried over.
        s.record_header("a", "m2", "Inbox", 20, "x@y.z", "X", "other", false, false)
            .unwrap();
        assert!(revision_of(&s, "a", "m2") > reinserted);
        cleanup(s, path);
    }

    #[test]
    fn the_high_water_is_seeded_from_an_r4_era_stores_own_counters() {
        // THE MIGRATION HALF. A store written by the build carries per-row counters and no
        // `ingest_revision_seq` at all. Seeding the high water at 0 would re-issue numbers live
        // rows are still wearing — so the seed is `MAX(ingest_revision)` over the existing
        // population (`store_open::seed_ingest_revision_seq`), and the first value this build
        // issues is strictly greater than every value the previous one wrote.
        let (path, mut s) = store("r5-high-water-seed");
        s.record_header("a", "legacy", "Inbox", 10, "x@y.z", "X", "r4-era row", false, false)
            .unwrap();
        // Reduce to the earlier shape: no seq table, no bump triggers, and a per-row counter
        // sitting well above anything a zero-seeded high water would issue.
        s.conn_for_test()
            .execute_batch(
                "DROP TRIGGER IF EXISTS message_header_ingest_revision_au;
                 DROP TRIGGER IF EXISTS message_header_ingest_revision_ai;
                 DROP TABLE IF EXISTS ingest_revision_seq;
                 UPDATE message_header SET ingest_revision = 41 WHERE message_ref = 'legacy';",
            )
            .expect("reduce the store to the r4-era shape");
        drop(s);

        // Reopen through the real door: `schema_ddl` re-creates the table and its triggers, and
        // the seed runs inside the same schema transaction.
        let log = crate::SqliteIntentLog::open(&path).expect("reopen the r4-era store");
        let mut s = SqliteMessageHeaderStore::open(&path).expect("reopen the header store");
        let high_water: i64 = s
            .conn_for_test()
            .query_row("SELECT high_water FROM ingest_revision_seq WHERE id = 0;", [], |r| {
                r.get(0)
            })
            .expect("the seq row exists after the upgrade");
        assert_eq!(
            high_water, 41,
            "the high water must be seeded at the r4-era population's own MAX, never at 0"
        );

        // A NEW row clears the legacy counter…
        s.record_header("a", "fresh", "Inbox", 20, "x@y.z", "X", "post-upgrade", false, false)
            .unwrap();
        assert_eq!(revision_of(&s, "a", "fresh"), 42);
        // …and so does a re-write of the legacy row itself: forward, never back.
        s.record_header("a", "legacy", "Inbox", 10, "x@y.z", "X", "re-confirmed", false, false)
            .unwrap();
        assert_eq!(revision_of(&s, "a", "legacy"), 43);
        // BOTH handles close before the temp file is removed — the same discipline `cleanup`
        // itself encodes, and the exact leak found in the perf harness.
        drop(log);
        cleanup(s, path);
    }

    #[test]
    fn message_header_columns_are_photon_local_only() {
        let (path, s) = store("cols");
        let cols = s.column_names().unwrap();
        assert_eq!(
            cols,
            vec![
                "account",
                "message_ref",
                "mailbox",
                "received_at",
                "from_addr",
                "from_name",
                "subject",
                // v9 (§2 FLAGS): provider-NEUTRAL state, not provider identity — the
                // confinement invariant this test guards is about the native id, and 0/1
                // seen/flagged carry none of it.
                "seen",
                "flagged",
                // the reconcile CAS's version marker — a local write
                // counter, carrying no provider bytes at all.
                "ingest_revision",
                // (-1): a status token and the SENDER's domain
                // (derived from `from_addr`, sender data like it) — no provider-native id.
                "from_status",
                "from_domain",
            ],
            "no provider-native id column may appear in message_header"
        );
        cleanup(s, path);
    }

    /// (-1): the one write door derives `from_status` / `from_domain`
    /// from the `from_addr` it stores — every writer (`record_header` here) goes through it.
    #[test]
    fn the_write_door_derives_the_sender_status_and_domain_from_from_addr() {
        let (path, mut s) = store("sender-facts");
        let rows = [
            ("m1", "real@EVIL.example", Some("ok"), Some("evil.example")),
            ("m2", "", Some("unavailable"), None),
            ("m3", "<a@x.example> <b@y.example>", Some("malformed"), None),
        ];
        for (m, from, _, _) in &rows {
            s.record_header("a", m, "Inbox", 1, from, "", "s", false, false).unwrap();
        }
        for (m, _, status, domain) in &rows {
            let read: (Option<String>, Option<String>) = s
                .conn
                .query_row(
                    "SELECT from_status, from_domain FROM message_header WHERE account = 'a' AND message_ref = ?1;",
                    [m],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(read, (status.map(String::from), domain.map(String::from)), "{m}");
        }
        // A re-record rewrites both (the upsert arm).
        s.record_header("a", "m2", "Inbox", 1, "n@new.example", "", "s", false, false).unwrap();
        let read: (String, Option<String>) = s
            .conn
            .query_row("SELECT from_status, from_domain FROM message_header WHERE message_ref = 'm2';", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(read, ("ok".to_string(), Some("new.example".to_string())));
        cleanup(s, path);
    }
}
