//! The read coordinator: ingest (identity, atomic write, normalization, window-scoped
//! reconcile) and the post-verb projection fold (where the coordinator lives and what its
//! post-verb API may accept).
//!
//! # What this is, and what it is not
//!
//! A read-side module outside `CommandBus`, owning ingest, refresh/reconcile and post-verb
//! projection maintenance. It never admits an intent, never dispatches a verb, and never
//! touches the intent log's tables. The verb path calls into it after a verb has already
//! succeeded; it does not call the verb path.
//!
//! # Why it owns its own connection
//!
//! The header row and the `message_placement` row must be written in one transaction.
//! `SqliteMessageHeaderStore` and `SqliteMessageStore` each own a separate connection to the
//! same file, and a SQLite transaction cannot span two connections, so calling those two stores'
//! methods can never be atomic. The coordinator therefore opens its own connection through
//! `crate::store_open::open_verified_connection`, the chokepoint both stores use (ownership and
//! version verified, durability profile pinned, FK checks on), and runs both writes inside one
//! `Transaction`.
//!
//! The two writes are not re-spelled here. Each store's statement is a `pub(crate)` function
//! taking `&Connection` (`crate::message_header::upsert_header_row` and
//! `crate::message_store::upsert_placement_row`), which a `&Transaction` satisfies by deref. A
//! second copy of the header upsert would rot when the next column lands: it carries the
//! ON CONFLICT clause that keeps the external-content FTS index in sync, and the `seen` /
//! `flagged` columns. The identity lookup is shared the same way, as one text
//! (`crate::message_store::RESOLVE_REF_BY_EMAIL_ID_SQL`), because SQLite matches an index
//! against the query text it is given and both paths must use `idx_message_placement_identity`.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::header_normalize::normalize_display;
use crate::message_store::RESOLVE_REF_BY_EMAIL_ID_SQL;
use crate::read_model::{Placement, ProviderMessageId};
use crate::read_surface::HeaderSummary;
use crate::LogError;

/// The `message_header.mailbox` token for the inbox. The header table's `mailbox` is a display
/// folder name, not the `message_placement.placement` durable token ([`Placement::as_str`]
/// owns that one). The two are written together and must agree; [`Placement::mailbox`] is the
/// one mapping from a placement to these constants.
pub const MAILBOX_INBOX: &str = "Inbox";
/// The `message_header.mailbox` token for the archive. See [`MAILBOX_INBOX`].
pub const MAILBOX_ARCHIVE: &str = "Archive";
/// The `message_header.mailbox` token for the trash. See [`MAILBOX_INBOX`].
pub const MAILBOX_TRASH: &str = "Trash";
/// The `message_header.mailbox` token for spam. See [`MAILBOX_INBOX`].
pub const MAILBOX_SPAM: &str = "Spam";

/// The narrow, engine-known outcome of a verb that already succeeded, and the only content the
/// post-verb projection API accepts. It takes no renderer-supplied header content, so a
/// hostile webview cannot forge durable rows through a legitimate verb.
///
/// There is deliberately no header-content variant or field: a caller cannot pass a subject,
/// an address, a timestamp or a provider id through this path, because no such parameter
/// exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbDelta {
    /// `Action::Archive` applied: placement and mailbox move to Archive.
    Archived,
    /// `Action::Unarchive` applied: placement and mailbox move back to Inbox.
    Unarchived,
    /// `Action::SetFlag{flag: Flagged}` applied: the header's `flagged` bit takes this value.
    /// Placement and mailbox are not touched; starring does not move a message.
    StarSet(bool),
    /// `Action::Trash` applied: placement and mailbox move to Trash.
    Trashed,
    /// `Action::Untrash` applied: placement and mailbox move to Archive (All Mail), never to the
    /// inbox. That matches the declared closure (`aruna::gmail` `gmail_atom_targets`: the restore
    /// arms target `membership:INBOX → false`), whose INBOX half is a declared hypothesis. This
    /// arm follows the declaration and does not prove the provider behaviour; the live drill
    /// has not yet observed that the route's INBOX membership equals the declared target.
    Untrashed,
    /// `Action::MarkSpam` (`true`) / `Action::UnmarkSpam` (`false`) applied: `true` moves
    /// placement and mailbox to Spam, `false` moves them to Archive (the same declared
    /// hypothesis as [`VerbDelta::Untrashed`] for the restore direction).
    SpamSet(bool),
    /// `Action::SetFlag{flag: Seen}` applied: the header's `seen` bit takes this value.
    /// Placement and mailbox are not touched; reading a message does not move it.
    SeenSet(bool),
}

/// The `VerbDelta` a forward `Action` applied, plus the message ref it targets, derived from a
/// stored intent's own `Action`. For callers (the projection writer's store-derived work list)
/// that cannot know ahead of time which verb a given intent's plan minted. Total and 1:1: every
/// `Action` variant names exactly the `VerbDelta` that variant's doc comment declares.
pub fn verb_delta_for_action(action: &crate::Action) -> (VerbDelta, &str) {
    use crate::{Action, MailFlag};
    match action {
        Action::Archive { message_ref } => (VerbDelta::Archived, message_ref),
        Action::Unarchive { message_ref } => (VerbDelta::Unarchived, message_ref),
        Action::SetFlag { message_ref, flag: MailFlag::Flagged, value } => (VerbDelta::StarSet(*value), message_ref),
        Action::SetFlag { message_ref, flag: MailFlag::Seen, value } => (VerbDelta::SeenSet(*value), message_ref),
        Action::Trash { message_ref } => (VerbDelta::Trashed, message_ref),
        Action::Untrash { message_ref } => (VerbDelta::Untrashed, message_ref),
        Action::MarkSpam { message_ref } => (VerbDelta::SpamSet(true), message_ref),
        Action::UnmarkSpam { message_ref } => (VerbDelta::SpamSet(false), message_ref),
    }
}

/// The dual outcome of post-verb projection maintenance: the verb already succeeded, so the
/// only question left is whether the local projection now agrees with it.
///
/// [`ProjectionOutcome::Stale`] is returned (never an `Err`, never silence) when the projection
/// write failed after a successful verb. Its reason string is built from the real underlying
/// error; the UI surfaces it as a visible row state ("applied, projection stale"), so a row a
/// user just acted on cannot quietly render the old truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionOutcome {
    /// The projection was updated together with the verb; the row renders truthfully.
    Current,
    /// The verb applied but the projection write did not. Carries the real reason.
    Stale(String),
}

/// What a refresh actually re-checked: the window is authoritative only over the range it
/// covers, and everything outside it is stale rather than silently trusted.
///
/// `checked_through` is the oldest fetched row's `(received_at, message_ref)`, the window
/// floor, in the tuple ordering the keyset pagination uses. `stale_below` counts the local
/// Inbox rows this refresh did not decide: rows below the floor timestamp, plus rows sitting
/// exactly on the floor timestamp that the response did not return (the provider's page break
/// can fall inside a timestamp, so an equal-timestamp absentee may be on the next page). The UI
/// renders it as the freshness marker ("N rows below this point not re-checked").
///
/// It also counts every removal the apply phase withdrew: a row whose compare-and-set failed
/// because a concurrent writer changed it between the verdict and its application. Dropping it
/// silently would report a refresh as having decided rows it had not.
///
/// The count is snapshot-scoped on purpose. A row that becomes visible only after the
/// phase-one snapshot (a concurrent ingest, or an orphan header gaining placement identity
/// mid-reconcile) was never in this refresh's world; it is the next refresh's row, and fresher
/// than this refresh, not staler. Counting the post-snapshot set would need a set-level
/// revision, the same schema-gated version machinery as the placement-CAS residual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness {
    pub checked_through: Option<(i64, String)>,
    pub stale_below: usize,
}

/// Where the fetched window starts: the one thing the coordinator cannot infer from the rows,
/// and the thing that decides whether the window's coverage has an upper bound at all.
///
/// It is a caller assertion, not a derivation: a page of summaries looks identical whether it
/// came from page 1 or from a continuation token, so only the caller that issued the fetch
/// knows. v1 has one caller shape, the page-1 refresh; [`WindowAnchor::Interior`] exists so a
/// future continuation-anchored caller cannot silently inherit the open ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowAnchor {
    /// The window is the provider's first page, newest-first. Its coverage is open-ended above:
    /// page 1 is the newest page, so a local row newer than every fetched row and absent from
    /// the response was archived or moved externally. Bounding removal by the fetched window's
    /// newest tuple would let exactly that row escape removal forever, since it can never
    /// re-enter a page-1 window.
    FirstPage {
        /// Did the provider's page itself come back with no rows, before any client-side
        /// filtering?
        ///
        /// The coordinator cannot infer this, and it is the only input to the wipe-everything
        /// rule below. The window this method receives is the transport's mapped page, and
        /// both live transports drop rows from it: Gmail skips a message whose per-id metadata
        /// no longer says `INBOX` (`aruna-gmail`), JMAP skips an id its `Email/get` half did not
        /// answer for and one whose `mailboxIds` no longer carries the inbox (`aruna-jmap`). A
        /// page of five real messages can therefore arrive as zero rows, and reading that as "the
        /// Inbox is empty" would delete the entire local projection on the strength of a filter.
        ///
        /// `false` is always the safe value: it costs a conservative no-coverage refresh (stale,
        /// nothing removed) that the next refresh clears. `true` must mean the provider's own
        /// newest page was empty.
        raw_page_was_empty: bool,
        /// Did the provider's walk end with this page, i.e. did it hand back no continuation?
        ///
        /// The second half of the empty-inbox answer. "Page 1 came back empty" only means "the
        /// Inbox is empty" when page 1 was also the whole walk. Both live listing routes can
        /// answer an empty page while still offering the next one: Gmail's `messages.list` may
        /// return a `nextPageToken` with no `messages` array, and JMAP's `Email/query` may answer
        /// `ids: []` while `total` still exceeds the position. An empty page with a continuation
        /// pending is no coverage (the rows are further down the walk).
        ///
        /// `false` is the safe value here too.
        walk_exhausted: bool,
    },
    /// The window came from a continuation, so rows above its ceiling were never looked at and
    /// the coverage range is bounded at both ends.
    Interior,
}

/// The reconcile's chunk bound: how many removals one enrollment may apply before releasing
/// the store's writer slot and taking it again.
///
/// It is a row count, as `SqliteMessageHeaderStore::bulk_load_headers`'s `rows_per_chunk` is
/// (see that method's doc): `writer_chunk_budget_ms` cannot be measured from inside a chunk's
/// own transaction, because the `WriteScope` `with_immediate_tx` enrolls is never handed to
/// the closure. The bulk loader can push the derivation onto its caller; this method cannot,
/// since `refresh_reconcile` is called by the UI refresh path (`src-tauri`) and by the
/// live-latency gate, neither of which has a per-row cost measurement, and a tuning knob on a
/// public read-surface signature would push a capacity decision into the transport layer.
///
/// So the number is a conservative constant. One removal is two indexed statements (a `DELETE`
/// on `message_header`'s primary key and an `UPDATE` on `message_placement`'s), the same order
/// of work as one `bulk_load_headers` row, which calibrates to the thousands of rows per 50 ms
/// on the reference box (`perf_floor_gates.rs` clamps that at 20_000). 128 removals is roughly
/// an order of magnitude under the 50 ms default budget there, and still inside it on a box
/// ten times slower. A smaller chunk only shortens the wait a sever sees; the cost is one more
/// `BEGIN IMMEDIATE`/commit per 128 rows, not correctness.
pub(crate) const REMOVALS_PER_CHUNK: usize = 128;

/// The reconcile's local-row read, bounded by the window floor. `?3` is the floor timestamp;
/// the `received_at` term is the third column of `idx_folder`, so this is an index range scan
/// over exactly the rows the window can decide, not a walk of every Inbox row the account
/// holds. A const so the query plan itself is testable.
///
/// Every local-row read carries the same placement-identity EXISTS clause the folder paging
/// queries use: a legacy v8 header row with no placement identity is invisible to the UI, so
/// counting or deciding it here would double-count rows nobody can see and re-condemn rows the
/// page can never show.
///
/// Every local-row read also materializes `ingest_revision`, the version marker the apply
/// phase's compare-and-set proves the row by (see `message_header`'s column comment in
/// `store_open::schema_ddl`). It must be read in the same statement that decides the row;
/// re-reading it at apply time would compare the row to itself. The correlated `placement`
/// and `email_id` scalars ride the same statement for the same reason: they are the placement
/// row's values at decision time, the compare set of the apply phase's compare-and-set, and
/// together the complete non-key column set of `message_placement`. The EXISTS guard already
/// proves the row exists, so neither scalar is NULL here; all are the same
/// `message_placement` PK seek the plan assertion pins.
const LOCAL_ROWS_IN_WINDOW_SQL: &str =
    "SELECT message_ref, received_at, ingest_revision,
                             (SELECT p.placement FROM message_placement AS p
                               WHERE p.account = h.account AND p.message_ref = h.message_ref),
                             (SELECT p.email_id FROM message_placement AS p
                               WHERE p.account = h.account AND p.message_ref = h.message_ref)
                        FROM message_header AS h
                      WHERE account = ?1 AND mailbox = ?2 AND received_at >= ?3
                        AND EXISTS (SELECT 1 FROM message_placement AS p
                                     WHERE p.account = h.account AND p.message_ref = h.message_ref);";

/// The rows strictly below the window floor: undecidable, so they are counted through the
/// same index rather than materialized.
const LOCAL_ROWS_BELOW_FLOOR_COUNT_SQL: &str = "SELECT COUNT(*) FROM message_header AS h
                      WHERE account = ?1 AND mailbox = ?2 AND received_at < ?3
                        AND EXISTS (SELECT 1 FROM message_placement AS p
                                     WHERE p.account = h.account AND p.message_ref = h.message_ref);";

/// The unbounded read, reached only when an authoritative empty page 1 is about to remove
/// every local Inbox row, i.e. when the whole partition is the working set.
const LOCAL_ROWS_ALL_SQL: &str =
    "SELECT message_ref, received_at, ingest_revision,
                             (SELECT p.placement FROM message_placement AS p
                               WHERE p.account = h.account AND p.message_ref = h.message_ref),
                             (SELECT p.email_id FROM message_placement AS p
                               WHERE p.account = h.account AND p.message_ref = h.message_ref)
                        FROM message_header AS h
                      WHERE account = ?1 AND mailbox = ?2
                        AND EXISTS (SELECT 1 FROM message_placement AS p
                                     WHERE p.account = h.account AND p.message_ref = h.message_ref);";

/// The unbounded count: a no-coverage window decides nothing, so it needs the number of
/// undecided rows and not their refs.
const LOCAL_ROWS_ALL_COUNT_SQL: &str = "SELECT COUNT(*) FROM message_header AS h
                      WHERE account = ?1 AND mailbox = ?2
                        AND EXISTS (SELECT 1 FROM message_placement AS p
                                     WHERE p.account = h.account AND p.message_ref = h.message_ref);";

/// Run one of the local-row reads above. `floor` is bound as `?3` when the statement takes it.
///
/// Takes `&Connection`, not `&Transaction`: the reconcile's read phase runs outside any write
/// transaction (see [`ReadCoordinator::refresh_reconcile`]'s two-phase doc), and
/// `rusqlite::Transaction` derefs to `Connection`, so the one signature serves both callers.
fn read_local_rows(
    conn: &Connection,
    account: &str,
    sql: &str,
    floor: Option<i64>,
) -> Result<Vec<LocalRow>, LogError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| LogError(format!("read_coordinator local prepare: {e}")))?;
    let map = |r: &rusqlite::Row<'_>| {
        Ok(LocalRow {
            received_at: r.get::<_, i64>(1)?,
            message_ref: r.get::<_, String>(0)?,
            ingest_revision: r.get::<_, i64>(2)?,
            placement: r.get::<_, String>(3)?,
            email_id: r.get::<_, String>(4)?,
        })
    };
    let rows = match floor {
        Some(floor) => stmt.query_map(rusqlite::params![account, MAILBOX_INBOX, floor], map),
        None => stmt.query_map(rusqlite::params![account, MAILBOX_INBOX], map),
    }
    .map_err(|e| LogError(format!("read_coordinator local read: {e}")))?;
    rows.collect::<rusqlite::Result<Vec<LocalRow>>>()
        .map_err(|e| LogError(format!("read_coordinator local row: {e}")))
}

/// One materialized local Inbox row, as the reconcile's read phase decides it: the ordering key
/// (`received_at`), the identity (`message_ref`) and the version marker the apply phase's
/// compare-and-set proves the row by (`ingest_revision`). A named struct rather than a
/// widening tuple, since the third field only means "the value this row carried at decision
/// time".
#[derive(Debug, Clone)]
struct LocalRow {
    received_at: i64,
    message_ref: String,
    ingest_revision: i64,
    /// The `message_placement.placement` value at decision time, part of the apply phase's CAS,
    /// read in the same statement for the same reason `ingest_revision` is.
    placement: String,
    /// The `message_placement.email_id` value at decision time; with `placement` above, the
    /// complete non-key column set of the placement row.
    email_id: String,
}

/// One decided removal: which row, the `ingest_revision` it carried when the verdict was made,
/// and the placement row's full non-key state then. The apply phase deletes only a row still
/// carrying all of them.
#[derive(Debug, Clone)]
struct DecidedRemoval {
    message_ref: String,
    decided_ingest_revision: i64,
    decided_placement: String,
    decided_email_id: String,
}

/// Run one of the local-row COUNTs above: the same statements, answering how many rather than
/// which. Same `&Connection` signature, for the same reason as [`read_local_rows`].
fn count_local_rows(
    conn: &Connection,
    account: &str,
    sql: &str,
    floor: Option<i64>,
) -> Result<usize, LogError> {
    let n: i64 = match floor {
        Some(floor) => conn.query_row(sql, rusqlite::params![account, MAILBOX_INBOX, floor], |r| {
            r.get(0)
        }),
        None => conn.query_row(sql, rusqlite::params![account, MAILBOX_INBOX], |r| r.get(0)),
    }
    .map_err(|e| LogError(format!("read_coordinator local count: {e}")))?;
    Ok(n.max(0) as usize)
}

/// The read coordinator. Owns one verified connection to the store file the two read-side
/// stores also open; see the module doc for why it holds its own.
///
/// All three of its write transactions (ingest's identity lookup, mint-if-absent and
/// header/placement write; the reconcile's read and removal set; the verb projection's
/// placement and mailbox pair) use `crate::store_open::GatedConnection::with_immediate_tx`
/// (private, so not a doc link): one `BEGIN IMMEDIATE` transaction bracketed by one enrollment
/// that spans it, commit on `Ok`, rollback on `Err`.
///
/// `BEGIN IMMEDIATE` takes the RESERVED lock before the body runs a single statement. That
/// closes the read-then-write race a `BEGIN DEFERRED` transaction would leave: two ingesters
/// racing the same provider id could both run their identity SELECT before either takes a
/// write lock, both see `None`, and both mint a ref for the same message, with SQLite's
/// write-write conflict firing only at commit and only for the loser (`SQLITE_BUSY_SNAPSHOT`),
/// after the double mint already landed.
pub struct ReadCoordinator {
    /// Connection plus this store file's writer gate, minted together at one entry point (see
    /// `store_open::GatedConnection`). Every write transaction below goes through
    /// [`crate::store_open::GatedConnection::with_immediate_tx`]; the ungated escape
    /// (`ungated_conn_mut`) has no production caller on this type.
    conn: crate::store_open::GatedConnection,
}

impl ReadCoordinator {
    /// Open the coordinator over the intent-log DB at `path`. Does not create the schema (the
    /// intent log owns it), so open the intent log first, as for the two stores.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = crate::store_open::open_verified_connection(path.as_ref())?;
        Ok(Self { conn })
    }

    /// Ingest one fetched page of inbox summaries, newest-first, for `account`. Returns the
    /// `message_ref` of each row, in the order given.
    ///
    /// The atomic unit is the row: one ingest call per page row writes the header row and the
    /// `message_placement` row in one transaction. A failure part-way through a page leaves the
    /// earlier rows durable and complete (never a header without its identity row) and
    /// propagates the error rather than reporting a page that did not land.
    pub fn ingest_page(
        &mut self,
        account: &str,
        rows: &[HeaderSummary],
    ) -> Result<Vec<String>, LogError> {
        let mut refs = Vec::with_capacity(rows.len());
        for row in rows {
            refs.push(self.ingest_row(account, row)?);
        }
        Ok(refs)
    }

    /// One page row, one transaction: identity lookup, mint-if-absent, header write, placement
    /// write, commit. See [`Self::ingest_page`] for why the row is the atomic unit.
    fn ingest_row(&mut self, account: &str, row: &HeaderSummary) -> Result<String, LogError> {
        // Enrolled: `with_immediate_tx` brackets this whole transaction with one `WriteScope`
        // and commits on `Ok`.
        self.conn.with_immediate_tx(|tx| {
            // Identity first: the provider id is looked up before a ref is minted, so the same
            // message on a later page or refresh reuses the ref the verbs already know. The
            // UNIQUE index behind this lookup backstops it.
            let existing = resolve_ref_in_tx(tx, account, &row.provider_id)?;
            let message_ref = match existing {
                Some(existing) => existing,
                None => mint_message_ref(tx)?,
            };

            // Normalization chokepoint: the display strings pass through `normalize_display` on
            // their way to the durable row. `from_addr` deliberately does not: it is identity
            // bytes and must round-trip exactly as the provider sent them (see
            // `header_normalize`'s module doc).
            crate::message_header::upsert_header_row(
                tx,
                account,
                &message_ref,
                MAILBOX_INBOX,
                row.received_at,
                &row.from_addr,
                &normalize_display(&row.from_name),
                &normalize_display(&row.subject),
                row.seen,
                row.flagged,
            )?;
            crate::message_store::upsert_placement_row(
                tx,
                account,
                &message_ref,
                &row.provider_id,
                Placement::Inbox,
            )?;

            Ok(message_ref)
        })
    }

    /// Window-scoped removal reconcile. `window` is the contiguous page-run a refresh just
    /// fetched (newest first) and already ingested; the rows' provider ids are resolved back to
    /// local refs here. `anchor` says where that run started (see [`WindowAnchor`]); it is the
    /// caller's assertion, not something the rows show.
    ///
    /// # The coverage range
    ///
    /// - **Above.** A [`WindowAnchor::FirstPage`] window has no ceiling: page 1 is the newest
    ///   page, so an absent local row above the newest fetched row is externally gone, not
    ///   un-looked-at. A [`WindowAnchor::Interior`] window keeps a ceiling, since rows above it
    ///   were never fetched.
    /// - **Below.** Only rows strictly above the floor's timestamp are removal candidates. The
    ///   provider's page break can fall inside the floor timestamp, so an equal-timestamp row
    ///   the response omitted may be on the next page. Removing it on that evidence would delete
    ///   a live message, so it is reported undecided ([`Freshness::stale_below`]), unless there
    ///   is no next page to hide on (next section).
    ///
    /// # An exhausted first page has no "below"
    ///
    /// A [`WindowAnchor::FirstPage`] window whose walk ended there
    /// ([`WindowAnchor::FirstPage::walk_exhausted`]) is the complete provider Inbox, not just
    /// its newest slice. Every local Inbox row is inside its coverage, including rows below the
    /// floor timestamp and rows exactly on it: a local row absent from it is gone from the
    /// provider, and is removed rather than counted. [`Freshness::stale_below`] is `0` then. A
    /// non-exhausted `FirstPage` keeps the two rules above.
    ///
    /// Inside the coverage range the provider's answer is authoritative: a local Inbox row it
    /// did not return was archived or moved elsewhere. Its header row is removed (it drops out
    /// of the Inbox folder view), but its placement row is updated to Archive rather than
    /// removed, so the `(account, email_id) -> message_ref` identity mapping survives and a
    /// message that returns to the Inbox reuses its original ref instead of orphaning
    /// history/undo linkage. Everything else is left alone and counted.
    ///
    /// # The empty first page
    ///
    /// A page-1 window the provider returned empty is the empty Inbox, not an absent answer, and
    /// every local Inbox row is removed. Treating it as no coverage would be a permanent wrong
    /// answer: the rows would stay on screen marked stale, and no later refresh could clear
    /// them because page 1 keeps coming back empty.
    ///
    /// That rule fires only on `FirstPage { raw_page_was_empty: true, walk_exhausted: true }`.
    /// An empty window can be three different events:
    ///
    /// 1. the provider's page had nothing and the walk ended there: an answer;
    /// 2. the provider's page had rows and every one was filtered out above this call (see
    ///    [`WindowAnchor::FirstPage::raw_page_was_empty`]): no answer, and acting on it would
    ///    delete the whole local Inbox over a filter;
    /// 3. the provider's page was empty but handed back a continuation (see
    ///    [`WindowAnchor::FirstPage::walk_exhausted`]): no answer, since the rows are further
    ///    down a walk this window never reached.
    ///
    /// Both non-answers reconcile as no coverage: nothing removed, every local row counted as
    /// undecided. An empty [`WindowAnchor::Interior`] window is conservative for its own
    /// reason: it says only that this continuation returned nothing.
    ///
    /// # What the reconcile reads
    ///
    /// On a non-exhausted window (or an `Interior` one) the removal decision concerns only local
    /// rows at or above the floor's timestamp, so only that range is materialized (an
    /// `idx_folder` range scan, not a walk of the whole Inbox partition). Rows below the floor
    /// are undecidable and are counted into [`Freshness::stale_below`] through the same index.
    /// An exhausted nonempty `FirstPage` window is the exception: its coverage is the whole
    /// partition, so the read is the unbounded read the authoritative-empty-page case uses and
    /// nothing is counted into `stale_below`. Either way the "did the provider return this row?"
    /// test is a hash-set lookup, not a linear walk of the window.
    ///
    /// # Two phases; the atomic unit is the chunk
    ///
    /// A single `with_immediate_tx` that materialized every local Inbox row and then
    /// DELETEd/UPDATEd every absentee would hold the store's one writer slot without bound on
    /// the paths that read the whole partition, so a sever ticket raised meanwhile would wait
    /// for the entire reconcile. The bulk header loader closes the same shape the same way:
    ///
    /// 1. **The read runs ungated.** Resolving the window, materializing the local rows and
    ///    deciding which are absentees writes nothing, so it takes no `WriteScope`. It runs
    ///    inside one `BEGIN DEFERRED` read transaction, which takes no RESERVED lock but gives
    ///    one snapshot. Separate autocommit reads would let a writer landing between the
    ///    below-floor COUNT and the in-window materialization make the phase describe a state
    ///    that never existed, counting a row undecided and removing it in the same breath.
    /// 2. **The apply runs in chunks of `REMOVALS_PER_CHUNK` removals** (private, so not a doc
    ///    link), each one `with_immediate_tx` with the enrollment re-acquired between chunks. A
    ///    pending sever waits at most one chunk
    ///    (`a_sever_raised_mid_reconcile_waits_at_most_one_chunk`).
    ///
    /// The whole reconcile is therefore not one atomic unit: a reader between two chunks sees
    /// the earlier chunks' removals and not the later ones, and a chunk that fails leaves the
    /// earlier chunks durable. That is the same trade [`Self::ingest_page`] makes (the row is
    /// the atomic unit) and the chunked bulk loader makes. The property the reconcile owns is
    /// per-row (an absentee's header row goes and its placement row survives, together), and
    /// that pair never spans a chunk boundary.
    ///
    /// Reading outside the write transaction means a concurrent writer can change a row between
    /// the decision and its application, so each removal re-validates the state it was decided
    /// on: the header DELETE carries `AND mailbox = 'Inbox' AND ingest_revision = <the value
    /// read at decision time>`, and the placement UPDATE runs only if that DELETE found its row.
    /// That compare-and-set replaces the serialization the old single transaction gave.
    ///
    /// Both halves are load-bearing and catch different writers. `mailbox` catches a verb that
    /// moved the row out of the Inbox. `ingest_revision` catches the writer `mailbox` cannot
    /// see: a newer [`Self::ingest_page`] re-confirming this very message into the Inbox, which
    /// leaves `mailbox='Inbox'` and `received_at` unchanged, so an `mailbox`-only predicate
    /// would let the older reconcile delete the newer provider evidence. A failed compare skips
    /// the row (the newer state wins) and counts it into [`Freshness::stale_below`] as the
    /// undecided row it now is.
    pub fn refresh_reconcile(
        &mut self,
        account: &str,
        window: &[HeaderSummary],
        anchor: WindowAnchor,
    ) -> Result<Freshness, LogError> {
        // Phase 1: the read, ungated. Nothing below this point writes, so nothing holds the
        // store's one writer slot. See the method doc's two-phases section for the visibility
        // trade and the compare-and-set that bounds it.
        let (floor, stale_below, removals) = {
            // One snapshot across the whole read phase. The window's identity lookups, the
            // below-floor COUNT and the in-window materialization, as separate autocommit reads,
            // would each see their own snapshot, and a concurrent writer between two of them
            // would let the phase observe states that never coexisted: a row counted into
            // `stale_below` by the first statement and then materialized (and decided a removal)
            // by the second, reported as both undecided and removed.
            //
            // `BEGIN DEFERRED` is an ungated read transaction: one that only reads acquires no
            // RESERVED lock and enrolls in nothing, so the writer gate is untouched and a sever
            // still waits for at most one apply chunk. It is never committed; the
            // `Transaction`'s drop rolls it back and releases the snapshot.
            let snapshot = self
                .conn
                .conn()
                .unchecked_transaction()
                .map_err(|e| LogError(format!("read_coordinator read snapshot: {e}")))?;
            let conn: &Connection = &snapshot;
            // The provider's answer, in local terms. A window row whose provider id has no local
            // mapping is skipped: it has no local identity, so it can neither be removed nor bound
            // the coverage range. Skipping shrinks the window, the conservative direction, since a
            // narrower window can only re-check less, never remove more.
            let mut present: Vec<(i64, String)> = Vec::with_capacity(window.len());
            // The same set, keyed for lookup. A linear walk of `present` per local row would make
            // the reconcile O(local x window): 50k local rows against a 200-row page is ten
            // million string comparisons per refresh.
            let mut present_refs: HashSet<String> = HashSet::with_capacity(window.len());
            for row in window {
                if let Some(r) = resolve_ref_in_tx(conn, account, &row.provider_id)? {
                    present_refs.insert(r.clone());
                    present.push((row.received_at, r));
                }
            }

            // The window's extremes, in the same `(received_at, message_ref)` tuple ordering the
            // keyset pagination uses (`message_header.rs`'s row-value `<` bound). SQLite compares
            // TEXT with the BINARY collation by default, byte-wise like Rust's `str` Ord, so the
            // comparison here and the one the page query performs agree. The floor tuple is still
            // what `checked_through` reports (the cursor the next page would resume from), but
            // removal is decided on the timestamp alone (see the method doc).
            let ceiling = present.iter().max().cloned();
            let floor = present.iter().min().cloned();

            // An empty first page is a positive answer: the provider's newest page came back with
            // nothing in it, which says the Inbox is empty. Three guards, each excluding a
            // different impostor:
            //
            // - `window.is_empty()`, not `floor.is_none()`: a non-empty window whose rows all
            //   failed to resolve locally means the provider did return messages that we cannot
            //   name, and it keeps the conservative no-coverage treatment.
            // - `raw_page_was_empty`: an empty window whose raw page held rows is a
            //   filtered-to-zero page, and the filter is not the mailbox. Only the provider's own
            //   empty page authorizes the wipe.
            // - `walk_exhausted`: an empty page that still offers a continuation is a gap in the
            //   middle of a mailbox, not its end.
            let empty_first_page = window.is_empty()
                && matches!(
                    anchor,
                    WindowAnchor::FirstPage {
                        raw_page_was_empty: true,
                        walk_exhausted: true,
                    }
                );

            // Does this window's coverage reach all the way down, with no page break left ahead
            // of it to hide a below-floor row on? A nonempty exhausted `FirstPage` window is the
            // complete provider Inbox, so it reads and decides every local row, as the
            // authoritative-empty-page case below does. `floor.is_some()` (checked at the call
            // site) tells the two exhausted cases apart: empty stays on the `empty_first_page`
            // path, which already reads everything, and this flag only widens the nonempty path.
            let exhausted_nonempty_first_page = floor.is_some()
                && matches!(anchor, WindowAnchor::FirstPage { walk_exhausted: true, .. });

            // Local Inbox rows, read inside the same transaction that will delete some of them,
            // bounded by the window floor unless the walk that produced this window already
            // exhausted the provider's Inbox.
            //
            // Only a row at or above the floor's timestamp can be decided by a window that might
            // still have a page ahead of it (the removal test below is `row.0 > floor.0`), so rows
            // strictly below it are undecided and never need materializing: they are counted
            // straight into `stale_below` through the same `idx_folder` range the page query uses.
            // This is where the "already ingested" precondition is load-bearing: every window row
            // that resolved locally has a local header row with the same `received_at`, so no
            // `present` ref can hide below the floor and be miscounted as stale.
            //
            // An exhausted nonempty `FirstPage` window has no "ahead" left, so it takes the same
            // unbounded read as the authoritative-empty-page case: every local row is materialized
            // and decided, and none is pre-counted into `stale_below`.
            //
            // The floorless case splits: an authoritative empty page 1 must materialize every row
            // (it is about to delete all of them), while a no-coverage window decides nothing and
            // only needs the count.
            let mut stale_below = 0usize;
            let local: Vec<LocalRow> = match (&floor, empty_first_page) {
                (Some(_), _) if exhausted_nonempty_first_page => {
                    read_local_rows(conn, account, LOCAL_ROWS_ALL_SQL, None)?
                }
                (Some(floor), _) => {
                    stale_below += count_local_rows(
                        conn,
                        account,
                        LOCAL_ROWS_BELOW_FLOOR_COUNT_SQL,
                        Some(floor.0),
                    )?;
                    // Test seam: the instant between the COUNT and the materialization (see
                    // `seam`'s doc, `#[cfg(test)]` only).
                    #[cfg(test)]
                    seam::in_read_phase();
                    read_local_rows(conn, account, LOCAL_ROWS_IN_WINDOW_SQL, Some(floor.0))?
                }
                (None, true) => read_local_rows(conn, account, LOCAL_ROWS_ALL_SQL, None)?,
                (None, false) => {
                    stale_below += count_local_rows(conn, account, LOCAL_ROWS_ALL_COUNT_SQL, None)?;
                    Vec::new()
                }
            };

            // Each entry carries the `ingest_revision` the row held at decision time, the value
            // the apply phase's compare-and-set requires the row to still carry.
            let mut removals: Vec<DecidedRemoval> = Vec::new();
            let decide = |row: &LocalRow| DecidedRemoval {
                message_ref: row.message_ref.clone(),
                decided_ingest_revision: row.ingest_revision,
                decided_placement: row.placement.clone(),
                decided_email_id: row.email_id.clone(),
            };
            for row in &local {
                // No coverage at all (an empty or wholly unresolvable window): nothing was
                // re-checked, so nothing may be removed and every local row is undecided, unless
                // the emptiness is itself page 1's answer, in which case every local Inbox row is
                // externally gone. Leaving them undecided would be permanent: page 1 stays empty,
                // so no later refresh could decide them and the rows would sit on screen stale.
                let Some(floor) = &floor else {
                    if empty_first_page {
                        removals.push(decide(row));
                    } else {
                        stale_below += 1;
                    }
                    continue;
                };
                // The provider returned it: re-checked, current, neither removable nor stale.
                // O(1) against the keyed set.
                if present_refs.contains(&row.message_ref) {
                    continue;
                }
                // Strictly above the floor timestamp, never merely above the floor tuple, unless
                // the walk is exhausted: then no next page is left for an at-or-below-floor absentee
                // to hide on, so the tie-break resolves too and the row is a removal candidate.
                let above_floor = row.received_at > floor.0 || exhausted_nonempty_first_page;
                let below_ceiling = match anchor {
                    // Open-ended: nothing sits above page 1.
                    WindowAnchor::FirstPage { .. } => true,
                    WindowAnchor::Interior => {
                        ceiling.as_ref().is_some_and(|c| row.received_at < c.0)
                    }
                };
                if above_floor && below_ceiling {
                    removals.push(decide(row));
                } else {
                    stale_below += 1;
                }
            }

            (floor, stale_below, removals)
        };
        // The read snapshot ends here, with the block that opened it, before the first apply
        // chunk takes the writer slot. A read transaction held across the applies would be a
        // stale snapshot the writes then contradict.

        // Test seam: the instant between the decision and its application (see `seam`'s doc,
        // `#[cfg(test)]` only).
        #[cfg(test)]
        seam::between_phases();

        // Removals the apply phase declined because the row changed under the verdict. Each is
        // a row this refresh did not decide after all, so it lands in `stale_below` rather than
        // vanishing.
        let mut withdrawn = 0usize;

        // Phase 2: the apply, one enrollment per chunk. Each chunk is its own
        // `with_immediate_tx` (one `WriteScope` bracketing one `BEGIN IMMEDIATE` transaction),
        // released and re-acquired between chunks, so a sever ticket raised mid-reconcile waits
        // for the current chunk and never for the whole removal set. Immediate because these
        // statements write: a Deferred begin would hold a stale WAL snapshot and fail with
        // SQLITE_BUSY_SNAPSHOT against a concurrent writer instead of serializing.
        for chunk in removals.chunks(REMOVALS_PER_CHUNK) {
            let chunk_withdrawn = self.conn.with_immediate_tx(|tx| {
                let mut chunk_withdrawn = 0usize;
                for DecidedRemoval {
                    message_ref,
                    decided_ingest_revision,
                    decided_placement,
                    decided_email_id,
                } in chunk
                {
                    // The header row goes: it is the Inbox folder view, and the message is gone
                    // from the Inbox. The placement row does not: it is the durable
                    // `(account, email_id) -> message_ref` identity mapping, and deleting it would
                    // make a message that is later moved back to the Inbox re-resolve to nothing,
                    // so ingest would mint a fresh ref and orphan every verb/history/undo entry
                    // naming the original. Update it to Archive instead: truthful enough (the
                    // reconcile only knows the message left the Inbox, and Archive is the model's
                    // one non-Inbox placement) and identity-preserving, since a later re-ingest of
                    // the same provider id reuses the row (and `upsert_placement_row`'s
                    // `ON CONFLICT` moves the placement back to Inbox on that write).
                    //
                    // `AND mailbox = ?3` is the compare half of the compare-and-set the ungated
                    // read phase needs: this row was decided an absentee against a snapshot taken
                    // before any enrollment, and a concurrent `apply_verb_delta` may have moved it
                    // out of the Inbox since. Finding no row skips it, and the next refresh decides
                    // it again on fresh evidence.
                    //
                    // `AND ingest_revision = ?4` closes the interleaving `mailbox` cannot see: a
                    // newer `ingest_page` re-confirming this message into the Inbox between the
                    // verdict and this DELETE leaves `mailbox='Inbox'` and `received_at` unchanged,
                    // so the older reconcile would delete the newer provider evidence. That upsert
                    // bumps `ingest_revision`, so the predicate fails and the row is skipped: the
                    // newer state wins, the only defensible resolution between two provider answers
                    // about one message.
                    //
                    // `AND EXISTS (... p.placement = ?5 AND p.email_id = ?6)` is the placement half,
                    // closing the racer the header compares are blind to: a placement-only writer
                    // (`record_optimistic_placement` / `correct_placement`) committing between the
                    // verdict and this DELETE. Those touch `message_placement` alone, so the header
                    // pair matched, the header died, and the UPDATE below would overwrite the newer
                    // placement with Archive or archive a mapping rebound to a different provider
                    // identity on evidence for the old one. With both columns compared, the check
                    // covers the complete non-key column set of `message_placement` (derived from
                    // the schema: key, email_id, placement). A mismatch skips the pair, and because
                    // the pair runs inside one `BEGIN IMMEDIATE` transaction, a DELETE that passes
                    // cannot have the placement move before the UPDATE beneath it.
                    //
                    // Accepted residual: this is a value compare, so a placement-only round trip
                    // that lands back on the decided values inside the phase gap (A to B to A) is
                    // invisible to it. Closing that needs a placement version column, a schema
                    // change gated on the migration path. The round trip nets to the decided
                    // state, so the overwrite writes what the reconcile decided against a state
                    // byte-equal to the one it read.
                    let removed = tx
                        .execute(
                            "DELETE FROM message_header
                              WHERE account = ?1 AND message_ref = ?2 AND mailbox = ?3
                                AND ingest_revision = ?4
                                AND EXISTS (SELECT 1 FROM message_placement AS p
                                             WHERE p.account = ?1 AND p.message_ref = ?2
                                               AND p.placement = ?5 AND p.email_id = ?6);",
                            rusqlite::params![
                                account,
                                message_ref,
                                MAILBOX_INBOX,
                                decided_ingest_revision,
                                decided_placement,
                                decided_email_id
                            ],
                        )
                        .map_err(|e| LogError(format!("read_coordinator header removal: {e}")))?;
                    if removed == 0 {
                        // The row changed under us: moved out of the Inbox, or re-confirmed into
                        // it by a newer ingest. Its placement is whatever that writer set, and this
                        // reconcile has no standing to overwrite it. Counted, not silently dropped:
                        // a withdrawn verdict is an undecided row, and the caller is told through
                        // `stale_below`.
                        chunk_withdrawn += 1;
                        continue;
                    }
                    tx.execute(
                        "UPDATE message_placement SET placement = ?3
                          WHERE account = ?1 AND message_ref = ?2;",
                        rusqlite::params![
                            account,
                            message_ref,
                            Placement::withdrawal_default().as_str()
                        ],
                    )
                    .map_err(|e| LogError(format!("read_coordinator placement archive: {e}")))?;
                }
                Ok::<usize, LogError>(chunk_withdrawn)
            })?;
            withdrawn += chunk_withdrawn;
        }

        Ok(Freshness {
            checked_through: floor,
            stale_below: stale_below + withdrawn,
        })
    }

    /// Post-verb projection maintenance. Call after the verb succeeded, with the account, the
    /// message ref the verb named, and the narrow [`VerbDelta`]; no header content exists in
    /// this signature to forge.
    ///
    /// Returns [`ProjectionOutcome`], not a `Result`: a projection failure at this point is not
    /// a verb failure and must neither be raised as one nor swallowed. Every failure path lands
    /// in [`ProjectionOutcome::Stale`] carrying the real reason.
    // Narrowed to `pub(crate)`: the shell (`photon-app`) cannot call this directly, because
    // it names no `basis` or marker. Every shell caller goes through `project_applied_intent`,
    // which marks `projected` in the same transaction. This module's tests call it directly to
    // exercise the raw write path; the external `crates/aruna/tests/capacity_seize_bound.rs`
    // benchmark drives the write path through the public method instead (a placeholder key and
    // `basis: Some(i64::MAX)` so it always writes, to exercise write-lock contention).
    #[allow(dead_code)] // every remaining caller is #[cfg(test)] (this module's own
    // tests); a lib-only `cargo build` sees zero callers. Production writes go through
    // `project_applied_intent`, which calls `write_verb_delta_tx` directly.
    pub(crate) fn apply_verb_delta(
        &mut self,
        account: &str,
        message_ref: &str,
        delta: VerbDelta,
    ) -> ProjectionOutcome {
        match self.write_verb_delta(account, message_ref, delta) {
            Ok(()) => ProjectionOutcome::Current,
            // The reason is the real error, verbatim: the UI shows a stale row and the log shows
            // why. A generic "projection failed" would make the stale arm undiagnosable.
            Err(e) => ProjectionOutcome::Stale(e.0),
        }
    }

    /// The fallible half of [`Self::apply_verb_delta`], kept separate so the public method has no
    /// error channel to leak a projection failure through. Both writes of a placement-moving
    /// delta share one transaction: a stale projection must be the old projection, never a
    /// half-written one (a header in Archive over a placement row still saying Inbox would be a
    /// third state nothing in the model describes).
    ///
    /// Every `message_header` write here also draws a fresh `ingest_revision`. The marker's
    /// contract is that a row written after a verdict carries a revision the verdict cannot
    /// name, and it is a property of the row, not of ingest. Without it this ABA is possible:
    /// `refresh_reconcile` snapshots an Inbox row at revision X; the message is archived
    /// (`write_verb_delta` moves it without touching `ingest_revision`); it is unarchived, back
    /// at revision X and indistinguishable from the row the reconcile saw; the reconcile's apply
    /// phase then matches its `... AND ingest_revision = ?4` compare against X and
    /// deletes or archives a row the user visibly just acted on. So every `message_header`
    /// mutation in this function, the placement-moving pair and the flag-only `StarSet` /
    /// `SeenSet` writes alike, draws the same `(SELECT high_water FROM ingest_revision_seq
    /// WHERE id = 0) + 1` expression `upsert_header_row` issues (`message_header.rs:489`), which
    /// the table's `message_header_ingest_revision_ai`/`_au` triggers
    /// (`store_open::schema_ddl`) raise the high water to atomically in the same statement.
    ///
    /// The rule is uniform, not per-arm. `StarSet` alone cannot restore a row to the Inbox, and
    /// a flag flip changes no `mailbox`/`placement` value the reconcile's CAS compares against,
    /// so a narrower fix could have exempted it. It is not exempt: a future consumer of
    /// `ingest_revision` cannot be assumed to compare it only against placement-moving writes,
    /// since the marker means "this row changed since revision N", and a flag flip is a change.
    /// The cost is one redundant `ingest_revision_seq` read on a write that did not strictly
    /// need it, against a scan of exactly one row.
    #[allow(dead_code)] // every remaining caller is #[cfg(test)], via `apply_verb_delta` above.
    fn write_verb_delta(
        &mut self,
        account: &str,
        message_ref: &str,
        delta: VerbDelta,
    ) -> Result<(), LogError> {
        // Enrolled: `with_immediate_tx` brackets this whole transaction with one `WriteScope`
        // and commits on `Ok`.
        self.conn
            .with_immediate_tx(|tx| Self::write_verb_delta_tx(tx, account, message_ref, delta))
    }

    /// [`Self::write_verb_delta`]'s body, extracted so [`Self::project_applied_intent`] can run
    /// it inside the same transaction as its own freshness check and its `intents.projected`
    /// write: the marker and the placement write must be one atomic unit (a marker failure after
    /// the placement UPDATE must roll back both, never just the marker).
    fn write_verb_delta_tx(
        tx: &rusqlite::Transaction<'_>,
        account: &str,
        message_ref: &str,
        delta: VerbDelta,
    ) -> Result<(), LogError> {
        {
            match delta {
                VerbDelta::Archived
                | VerbDelta::Unarchived
                | VerbDelta::Trashed
                | VerbDelta::Untrashed
                | VerbDelta::SpamSet(_) => {
                    // No wildcard: every placement-moving delta names its destination, and the
                    // header folder is derived from it (`Placement::mailbox`), never spelled beside
                    // it.
                    let placement = match delta {
                        VerbDelta::Archived | VerbDelta::Untrashed | VerbDelta::SpamSet(false) => {
                            Placement::Archive
                        }
                        VerbDelta::Unarchived => Placement::Inbox,
                        VerbDelta::Trashed => Placement::Trash,
                        VerbDelta::SpamSet(true) => Placement::Spam,
                        VerbDelta::StarSet(_) | VerbDelta::SeenSet(_) => {
                            unreachable!("flag deltas do not move a message")
                        }
                    };
                    let mailbox = placement.mailbox();
                    let moved = tx
                        .execute(
                            "UPDATE message_placement SET placement = ?3
                              WHERE account = ?1 AND message_ref = ?2;",
                            rusqlite::params![account, message_ref, placement.as_str()],
                        )
                        .map_err(|e| LogError(format!("read_coordinator placement move: {e}")))?;
                    let refiled = tx
                        .execute(
                            "UPDATE message_header SET mailbox = ?3,
                                  ingest_revision =
                                      (SELECT high_water FROM ingest_revision_seq WHERE id = 0) + 1
                              WHERE account = ?1 AND message_ref = ?2;",
                            rusqlite::params![account, message_ref, mailbox],
                        )
                        .map_err(|e| LogError(format!("read_coordinator header move: {e}")))?;
                    // Both rows, separately. Admitting on `moved + refiled` against zero would be
                    // satisfied by a store carrying only one of the pair (a legacy row from before
                    // the ingest pair was atomic, a half-removed row, a damaged file), reporting
                    // `Current` over a projection where the placement had moved and the folder view
                    // had not, or the reverse: the third state `write_verb_delta`'s doc says
                    // nothing in the model describes. Each UPDATE must find its own row; either at
                    // zero rolls the transaction back (the `?` propagates the error through the
                    // enrolled closure) and surfaces as the Stale arm naming the absent table.
                    refuse_unprojected(moved, "message_placement", account, message_ref)?;
                    refuse_unprojected(refiled, "message_header", account, message_ref)?;
                }
                VerbDelta::StarSet(value) => {
                    // Star touches the flag and nothing else (no mailbox, no placement): a message
                    // does not move because it was starred. It still draws a fresh
                    // `ingest_revision` (see this function's doc, "The rule is uniform") because the
                    // row changed, and a later reconcile's CAS must be able to tell.
                    let flipped = tx
                        .execute(
                            "UPDATE message_header SET flagged = ?3,
                                  ingest_revision =
                                      (SELECT high_water FROM ingest_revision_seq WHERE id = 0) + 1
                              WHERE account = ?1 AND message_ref = ?2;",
                            rusqlite::params![account, message_ref, value as i64],
                        )
                        .map_err(|e| LogError(format!("read_coordinator flag write: {e}")))?;
                    // One row by design: starring does not move a message, so `message_header` is
                    // the whole projection of this delta and the same exactly-one rule applies.
                    refuse_unprojected(flipped, "message_header", account, message_ref)?;
                }
                VerbDelta::SeenSet(value) => {
                    // Seen touches the `seen` bit and nothing else: the `StarSet` arm's shape over
                    // the other flag column, with the same fresh `ingest_revision` and the same
                    // exactly-one-row rule.
                    let marked = tx
                        .execute(
                            "UPDATE message_header SET seen = ?3,
                                  ingest_revision =
                                      (SELECT high_water FROM ingest_revision_seq WHERE id = 0) + 1
                              WHERE account = ?1 AND message_ref = ?2;",
                            rusqlite::params![account, message_ref, value as i64],
                        )
                        .map_err(|e| LogError(format!("read_coordinator seen write: {e}")))?;
                    refuse_unprojected(marked, "message_header", account, message_ref)?;
                }
            }

            Ok(())
        }
    }

    /// The projecting caller's entry point, keyed by the intent alone. Taking
    /// `account`/`message_ref`/`delta`/`basis` from the caller allowed three bugs: (i) two
    /// intents recorded against the same observation could not both project (the first's write
    /// bumps `ingest_revision`, so the second read itself as superseded), closed by the sibling
    /// rule below for siblings on different columns (a same-column pair is deliberately
    /// superseded); (ii) an intent undone between the shell's enumeration and this method's own
    /// transaction still got written, closed by requiring exactly one row at
    /// `status = 'applied' AND projected = 0` before anything is derived; (iii) a
    /// caller-supplied `basis` could be stale relative to what the row now says, and the shell
    /// folded a skip into `Current`, closed by reading the row's own `basis_ingest_revision`
    /// here and by the shell mapping every skip to `Stale` (see `src-tauri/src/lib.rs`'s
    /// `From<Result<ProjectionWrite, LogError>>`).
    ///
    /// Inside one `with_immediate_tx`: SELECT the intent row by key and decode it through the
    /// intent read path (`INTENT_COLUMNS` → `raw_intent_from_row` → `intent_from_raw`); the
    /// delta is derived from the stored action via [`verb_delta_for_action`], never handed in.
    /// Anything other than exactly one forward row (`compensates IS NULL`, since an undo key
    /// would write the naive inverse `undo`'s doc forbids) with `status = 'applied' AND
    /// projected = 0` (no row, an undo compensation, `undone`, already projected, any other
    /// status) gives [`ProjectionWrite::NotApplicable`]: no placement write, no marker write,
    /// nothing to roll back.
    ///
    /// Otherwise it reads the header's current `ingest_revision` for (account, message_ref) and
    /// compares it against the row's own `basis_ingest_revision`. `Some(b)` with the row at or
    /// before `b` means the effect is still the newest truth, so `Self::write_verb_delta_tx`
    /// runs and the result is [`ProjectionWrite::Written`], with the sibling rule running in the
    /// same transaction. A row strictly newer than `b`, a `None` basis (no freshness claim to
    /// stand on), or no header row at all skips the write and gives
    /// [`ProjectionWrite::SupersededByNewerObservation`] (`write_verb_delta_tx` never runs
    /// against a missing row). In every branch past the precondition check the intent is marked
    /// `intents.projected = 1` in the same transaction, and that marker UPDATE (predicate
    /// `status = 'applied' AND projected = 0 AND compensates IS NULL`) must affect exactly one
    /// row (`refuse_unprojected`) or the whole transaction fails. That count check is a second
    /// line, not a race guard: under `BEGIN IMMEDIATE` no second connection can change the row
    /// between the SELECT and the marker, so it fires only if a statement inside this
    /// transaction moved the row or the precondition were loosened.
    ///
    /// **The sibling rule.** A local projection write to one column is not a newer observation
    /// for a sibling whose delta writes another column. After `write_verb_delta_tx` runs, every
    /// other still-unprojected forward intent for this (account, message_ref) whose
    /// `basis_ingest_revision` still equals the pre-write revision and whose delta writes a
    /// different column (placement, `flagged` or `seen`; see `ProjectionColumn`) is carried
    /// forward to the post-write revision, so star-then-archive (the CLI's case) writes both. A
    /// same-column sibling is never carried, in either order: it reads this write as newer, is
    /// superseded, and the shell answers `Stale`. Carrying every sibling gave a false `Current`
    /// (an earlier star projected after a later unstar re-starred a row the provider holds
    /// unstarred; an archive projected after a trash wrote Archive over a message Gmail keeps in
    /// TRASH), because a same-column local projection is information the sibling was decided
    /// without, and one per-row `ingest_revision` cannot say whether the sibling's delta still
    /// holds on top of it. A sibling recorded against an older observation (a refresh already
    /// superseded it before this write ran) is left alone and stays superseded.
    ///
    /// **Residual.** Every skip (superseded by a refresh, a `None` basis, a same-column
    /// sibling) leaves the row showing something the provider may not hold, and the only record
    /// is the `Stale` the shell answers once on the wire. A skipped delta on a row the Inbox
    /// refresh never re-lists (placed outside the Inbox, or below the window floor) stays wrong
    /// with nothing durable recording it. A durable "skipped" state, and freshness ordered
    /// against the effect (provider `historyId` / JMAP `state`, or the persisted post-effect
    /// label vector), need a design decision; no further local heuristic is added here.
    ///
    /// The local revision cannot order an observation against a provider effect.
    /// `basis_ingest_revision` is a local sequence number from the store's own high-water
    /// counter, unrelated to provider time. If the record happens, then a refresh bumps the
    /// local revision, then the provider effect settles, then this method projects, the row is
    /// "newer" by the local counter even though the intent's effect is the current provider
    /// truth, and this method cannot see through that. It cannot resolve the ordering; it makes
    /// the local answer honest: a skip is reported `Stale` (never `Current`), the intent is
    /// still marked `projected` (accounted for, never retried against a basis that can only get
    /// staler), and the next refresh reconciles the row against the provider. Ordering freshness
    /// against the provider (Gmail `historyId`, JMAP `state`, or a post-effect observation taken
    /// inside the effect's own transaction) is a design-level item.
    pub fn project_applied_intent(&mut self, idempotency_key: &str) -> Result<ProjectionWrite, LogError> {
        self.conn.with_immediate_tx(|tx| {
            // The row is decoded through the intent read path (`INTENT_COLUMNS` →
            // `raw_intent_from_row` → `intent_from_raw`), never by hand-parsing `action_kind`: a
            // corrupt stored value is a `LogError`, as on every other read site.
            let intent = tx
                .query_row(
                    &format!("SELECT {} FROM intents WHERE idempotency_key = ?1;", crate::INTENT_COLUMNS),
                    rusqlite::params![idempotency_key],
                    crate::raw_intent_from_row,
                )
                .optional()
                .map_err(|e| LogError(format!("read_coordinator project intent read: {e}")))?
                .map(crate::intent_from_raw)
                .transpose()?;

            let intent = match intent {
                None => {
                    return Ok(ProjectionWrite::NotApplicable {
                        reason: format!("no intent recorded under idempotency key {idempotency_key:?}"),
                    })
                }
                // An undo key never enters here: a compensation carries its parent's inverse
                // action, and writing that is the naive inverse `undo`'s doc forbids (the undo
                // restores the journaled pre-state, not the inverse verb).
                Some(intent) if intent.command.compensates.is_some() => {
                    return Ok(ProjectionWrite::NotApplicable {
                        reason: format!(
                            "intent {idempotency_key:?} is an undo compensation — never projected through this door"
                        ),
                    })
                }
                Some(intent) if intent.status != crate::IntentStatus::Applied => {
                    return Ok(ProjectionWrite::NotApplicable {
                        reason: format!(
                            "intent {idempotency_key:?} is {}, not applied — nothing to project",
                            crate::status_to_str(&intent.status)
                        ),
                    })
                }
                Some(intent) if intent.projected => {
                    return Ok(ProjectionWrite::NotApplicable {
                        reason: format!("intent {idempotency_key:?} is already projected"),
                    })
                }
                Some(intent) => intent,
            };

            let account = intent.command.account.as_str();
            let (delta, message_ref) = verb_delta_for_action(&intent.command.action);
            let basis = intent.basis_ingest_revision;

            let current_revision: Option<i64> = tx
                .query_row(
                    "SELECT ingest_revision FROM message_header WHERE account = ?1 AND message_ref = ?2;",
                    rusqlite::params![account, message_ref],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| LogError(format!("read_coordinator projection basis read: {e}")))?;

            let outcome = match (basis, current_revision) {
                (Some(b), Some(current)) if current <= b => {
                    Self::write_verb_delta_tx(tx, account, message_ref, delta)?;
                    let post_write_revision: i64 = tx
                        .query_row(
                            "SELECT ingest_revision FROM message_header WHERE account = ?1 AND message_ref = ?2;",
                            rusqlite::params![account, message_ref],
                            |r| r.get(0),
                        )
                        .map_err(|e| LogError(format!("read_coordinator post-write revision read: {e}")))?;
                    Self::carry_different_column_siblings_tx(
                        tx,
                        idempotency_key,
                        account,
                        message_ref,
                        delta,
                        b,
                        post_write_revision,
                    )?;
                    ProjectionWrite::Written
                }
                _ => ProjectionWrite::SupersededByNewerObservation,
            };

            let marked = tx
                .execute(
                    "UPDATE intents SET projected = 1
                      WHERE idempotency_key = ?1 AND status = 'applied' AND projected = 0
                        AND compensates IS NULL;",
                    rusqlite::params![idempotency_key],
                )
                .map_err(|e| LogError(format!("read_coordinator mark projected: {e}")))?;
            refuse_unprojected(marked, "intents", account, message_ref)?;

            Ok(outcome)
        })
    }

    /// The sibling rule: after `written` landed at `post_write_revision`, carry forward (from
    /// `basis` to `post_write_revision`) every other still-unprojected forward intent on this
    /// (account, message_ref) recorded against the same pre-write `basis` whose delta writes a
    /// different column ([`ProjectionColumn`]). A same-column sibling is never carried, in
    /// either seq order: this write is information that sibling was decided without, and one
    /// per-row `ingest_revision` cannot say whether the sibling's delta still holds on top of it.
    /// An earlier star projected after a later unstar would re-star a row the provider holds
    /// unstarred; an archive projected after a trash would write Archive over a message Gmail
    /// keeps in TRASH, because Gmail archive is `removeLabelIds INBOX` only. So a same-column
    /// sibling reads this write as newer, is superseded, and the shell answers `Stale`, never a
    /// false `Current`.
    ///
    /// Siblings are decoded through the intent read path, like the method's own row; the UPDATE
    /// is per key and re-checks `projected = 0 AND basis_ingest_revision = basis`.
    fn carry_different_column_siblings_tx(
        tx: &rusqlite::Transaction<'_>,
        idempotency_key: &str,
        account: &str,
        message_ref: &str,
        written: VerbDelta,
        basis: i64,
        post_write_revision: i64,
    ) -> Result<(), LogError> {
        let siblings: Vec<crate::Intent> = {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT {} FROM intents
                      WHERE account = ?1 AND message_ref = ?2 AND projected = 0
                        AND compensates IS NULL AND basis_ingest_revision = ?3
                        AND idempotency_key <> ?4
                      ORDER BY seq;",
                    crate::INTENT_COLUMNS
                ))
                .map_err(|e| LogError(format!("read_coordinator sibling read: {e}")))?;
            let raws = stmt
                .query_map(
                    rusqlite::params![account, message_ref, basis, idempotency_key],
                    crate::raw_intent_from_row,
                )
                .map_err(|e| LogError(format!("read_coordinator sibling read: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| LogError(format!("read_coordinator sibling read: {e}")))?;
            raws.into_iter().map(crate::intent_from_raw).collect::<Result<_, _>>()?
        };
        let written_column = ProjectionColumn::of(written);
        for sibling in siblings {
            let (sibling_delta, _) = verb_delta_for_action(&sibling.command.action);
            if ProjectionColumn::of(sibling_delta) == written_column {
                continue;
            }
            tx.execute(
                "UPDATE intents SET basis_ingest_revision = ?1
                  WHERE idempotency_key = ?2 AND projected = 0 AND basis_ingest_revision = ?3;",
                rusqlite::params![post_write_revision, sibling.command.idempotency_key, basis],
            )
            .map_err(|e| LogError(format!("read_coordinator sibling basis carry: {e}")))?;
        }
        Ok(())
    }
}

/// The three projection columns a [`VerbDelta`] writes, the partition
/// [`ReadCoordinator::write_verb_delta_tx`]'s match uses (placement-moving deltas write
/// `message_placement.placement` and `message_header.mailbox`; `StarSet` writes `flagged`;
/// `SeenSet` writes `seen`). The sibling rule carries a sibling forward only across a write to
/// a different column. No wildcard: a new `VerbDelta` must name its column here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionColumn {
    Placement,
    Flagged,
    Seen,
}

impl ProjectionColumn {
    fn of(delta: VerbDelta) -> Self {
        match delta {
            VerbDelta::Archived
            | VerbDelta::Unarchived
            | VerbDelta::Trashed
            | VerbDelta::Untrashed
            | VerbDelta::SpamSet(_) => ProjectionColumn::Placement,
            VerbDelta::StarSet(_) => ProjectionColumn::Flagged,
            VerbDelta::SeenSet(_) => ProjectionColumn::Seen,
        }
    }
}

/// What [`ReadCoordinator::project_applied_intent`] did with an `Applied` intent's
/// local-projection effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionWrite {
    /// The placement/header delta was written: a header row exists for (account, message_ref)
    /// and its current `ingest_revision` is at or before the intent's own basis (frozen at
    /// record time; possibly carried forward by the different-column sibling rule).
    Written,
    /// The placement/header write was skipped: the row is strictly newer than this intent's
    /// basis (a refresh observed the message after the effect was decided), or the intent
    /// carried no basis (no freshness claim to stand on). The intent is still marked
    /// `projected`, accounted for and never retried, but its effect must never overwrite a
    /// newer or unproven observation.
    SupersededByNewerObservation,
    /// The precondition failed: no intent exists under this key, it is not `status = 'applied'`
    /// (e.g. `undone` between the shell's enumeration and this transaction), or it is already
    /// `projected`. Nothing was written or marked; `reason` names which of the three it was.
    NotApplicable { reason: String },
}

/// A verb applied to a ref the projection has never heard of updated nothing, and reporting
/// `Current` for that would be a lie about a row that does not exist. Zero affected rows is a
/// stale reason, not a success.
///
/// Exactly one row, per table: `table` names which projection row this UPDATE was supposed to
/// find, so a placement-moving delta that found one row and not the other says which was
/// absent instead of reporting a success it half achieved. A count above one is refused too:
/// `(account, message_ref)` is a single projection row, and a store that answers with several
/// is not one this projection may commit onto.
fn refuse_unprojected(
    affected: usize,
    table: &str,
    account: &str,
    message_ref: &str,
) -> Result<(), LogError> {
    if affected != 1 {
        return Err(LogError(format!(
            "the {table} projection row for account {account:?} message_ref {message_ref:?} was \
             updated {affected} times (expected exactly 1) — the verb applied but the local \
             projection did not follow it"
        )));
    }
    Ok(())
}

/// The inverse identity lookup, run inside a coordinator transaction. Same text as
/// [`crate::message_store::SqliteMessageStore::resolve_ref_by_email_id`] (see
/// [`RESOLVE_REF_BY_EMAIL_ID_SQL`]) so both use `idx_message_placement_identity`, and
/// fallible the same way: only "no row" is `None`; a real store error propagates, because a
/// swallowed one would read as "no mapping" and mint a duplicate ref.
fn resolve_ref_in_tx(
    conn: &Connection,
    account: &str,
    id: &ProviderMessageId,
) -> Result<Option<String>, LogError> {
    conn.query_row(
        RESOLVE_REF_BY_EMAIL_ID_SQL,
        rusqlite::params![account, id.0],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| LogError(format!("read_coordinator identity resolve: {e}")))
}

/// Mint a fresh `message_ref`.
///
/// The shape is `lower(hex(randomblob(16)))`: SQLite's own CSPRNG, 128 random bits, the
/// spelling this crate uses for every opaque id (`mint_opaque_id`, behind `intent_id`,
/// `attempt_id` and the exposure row ids). The `msg-` prefix matches the ref shape the existing
/// connector tests use, so a ref reads as a ref wherever it surfaces.
///
/// An account-scoped counter was rejected: two ingests racing on one account would read the
/// same maximum and mint the same ref, and the `UNIQUE (account, email_id)` index would then
/// reject the second message rather than catching a duplicate mint. Randomness has no such
/// coupling.
fn mint_message_ref(conn: &Connection) -> Result<String, LogError> {
    let raw: String = conn
        .query_row("SELECT lower(hex(randomblob(16)));", [], |r| r.get(0))
        .map_err(|e| LogError(format!("read_coordinator ref mint: {e}")))?;
    Ok(format!("msg-{raw}"))
}

/// Test seams that make the two concurrency windows of `refresh_reconcile` observable. Both
/// are races whose harm is invisible unless a competing writer commits at one exact instant,
/// and neither instant is reachable from outside the method: one is between two statements of
/// the read phase, the other between the read phase and the apply. Threads and sleeps cannot
/// pin either deterministically.
///
/// A test arms a seam with a closure; the reconcile fires it once at the named instant and
/// disarms it. `#[cfg(test)]` throughout (the production call sites are `#[cfg(test)]`
/// statements, so a release build contains neither the hook nor a branch on it) and
/// thread-local, so parallel tests cannot arm each other's reconcile.
///
/// A seam is not a substitute for the property: each test that arms one also asserts that the
/// injected write landed, so a seam that silently did nothing cannot pass as a fix.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::RefCell;

    type Hook = RefCell<Option<Box<dyn FnMut()>>>;

    thread_local! {
        /// Fires inside phase 1, between the below-floor COUNT and the in-window
        /// materialization; the window closes with one read transaction.
        static IN_READ_PHASE: Hook = const { RefCell::new(None) };
        /// Fires between phase 1 and phase 2; the window closes with the `ingest_revision`
        /// compare-and-set.
        static BETWEEN_PHASES: Hook = const { RefCell::new(None) };
    }

    fn fire(key: &'static std::thread::LocalKey<Hook>) {
        // Taken, not borrowed across the call: the closure re-enters this module's crate (it
        // opens a second coordinator and writes), and a live `RefCell` borrow held across that
        // would be a latent panic. Taking also makes the hook one-shot.
        let hook = key.with(|h| h.borrow_mut().take());
        if let Some(mut f) = hook {
            f();
        }
    }

    pub(crate) fn in_read_phase() {
        fire(&IN_READ_PHASE);
    }

    pub(crate) fn between_phases() {
        fire(&BETWEEN_PHASES);
    }

    pub(crate) fn arm_in_read_phase(f: impl FnMut() + 'static) {
        IN_READ_PHASE.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(crate) fn arm_between_phases(f: impl FnMut() + 'static) {
        BETWEEN_PHASES.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_header::SqliteMessageHeaderStore;
    use crate::message_store::SqliteMessageStore;
    use crate::read_surface::AttachmentPresence;

    /// minted by the ONE guard (`crate::test_temp`) — unique per call,
    /// the store family removed on `Drop`, a leak a loud failure.
    fn unique_temp_db_path(tag: &str) -> crate::test_temp::TempFile {
        crate::test_temp::TempFile::sqlite(&format!("aruna-rc-{tag}"))
    }

    /// Bootstrap a store (the intent log owns the schema) and open a coordinator over it.
    /// The guard comes FIRST: `let (path, c) = coordinator(..)` drops `c` before the guard.
    fn coordinator(tag: &str) -> (crate::test_temp::TempFile, ReadCoordinator) {
        let path = unique_temp_db_path(tag);
        let _log = crate::SqliteIntentLog::open(&path).unwrap();
        let c = ReadCoordinator::open(&path).unwrap();
        (path, c)
    }

    /// A page-1 anchor stating what the RAW provider page held, for a walk that
    /// ENDED with that page — the ordinary v1 shape. Spelled out at every call
    /// site so no test can silently mean "empty inbox" when it meant "nonempty page".
    fn first_page(raw_page_was_empty: bool) -> WindowAnchor {
        WindowAnchor::FirstPage {
            raw_page_was_empty,
            walk_exhausted: true,
        }
    }

    fn summary(id: &str, received_at: i64, subject: &str) -> HeaderSummary {
        HeaderSummary {
            provider_id: ProviderMessageId(id.to_string()),
            received_at,
            from_addr: "sender@example.com".to_string(),
            from_name: "Sender".to_string(),
            subject: subject.to_string(),
            seen: false,
            flagged: false,
            attachments: AttachmentPresence::default(),
        }
    }

    /// Read every header row for an account, newest-first, through the real read path.
    fn headers(path: &std::path::Path, account: &str, mailbox: &str) -> Vec<crate::message_header::HeaderRow> {
        let s = SqliteMessageHeaderStore::open(path).unwrap();
        s.folder_first_page(account, mailbox, 100).unwrap()
    }

    /// The RAW `message_header.mailbox` column for one ref, read directly (never through
    /// `folder_first_page`/`headers()`, which join against
    /// `message_placement` identity and so are BLIND to a deliberately-orphaned header row, exactly
    /// the shape [`t7_e_a_header_row_without_its_placement_row_is_stale_too`] constructs on purpose.
    /// `None` when no header row exists for the ref at all.
    fn raw_header_mailbox(path: &std::path::Path, account: &str, message_ref: &str) -> Option<String> {
        let conn = raw(path);
        conn.query_row(
            "SELECT mailbox FROM message_header WHERE account=?1 AND message_ref=?2;",
            rusqlite::params![account, message_ref],
            |r| r.get(0),
        )
        .ok()
    }

    /// A raw verified connection on the same store — used to INJECT FAULTS (a `RAISE(ABORT)`
    /// trigger on `message_placement`) and to count rows outside the coordinator's own paths.
    fn raw(path: &std::path::Path) -> crate::store_open::GatedConnection {
        crate::store_open::open_verified_connection(path).unwrap()
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// SQLite's own answer for how it will run a statement (`EXPLAIN QUERY PLAN`), one detail
    /// string per plan step. The mechanical witness for a query BOUND by an index range versus one
    /// that walks every row of a partition.
    fn query_plan(conn: &Connection, sql: &str) -> Vec<String> {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        // The plan is decided at PREPARE time; the bindings only have to satisfy the arity.
        let holes: Vec<rusqlite::types::Value> = (0..stmt.parameter_count())
            .map(|_| rusqlite::types::Value::Null)
            .collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(holes), |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap();
        rows
    }

    /// Regression test: the reconcile's local read must be BOUNDED by the window floor,
    /// not a walk of every Inbox row the account holds.
    ///
    /// The scan itself is invisible from outside (same rows in, same rows out), so the witness is
    /// SQLite's own query plan: an unbounded `WHERE account = ? AND mailbox = ?` searches
    /// `idx_folder` on its first two columns and then walks every row under that prefix — an
    /// account with 50k local rows re-reads 50k rows to reconcile a 50-row window. The bounded form
    /// adds the `received_at` range term the index's third column already supports.
    #[test]
    fn the_reconcile_local_read_is_bounded_by_the_window_floor_not_the_whole_inbox() {
        let (path, c) = coordinator("plan-bound");
        let conn = raw(&path);

        let plan = query_plan(&conn, LOCAL_ROWS_IN_WINDOW_SQL);
        assert!(
            plan.iter()
                .any(|step| step.contains("idx_folder") && step.contains("received_at>")),
            "the window read must carry a received_at RANGE bound into idx_folder — otherwise it \
             walks every Inbox row of the account per reconcile; plan was {plan:?}"
        );
        let below = query_plan(&conn, LOCAL_ROWS_BELOW_FLOOR_COUNT_SQL);
        assert!(
            below
                .iter()
                .any(|step| step.contains("idx_folder") && step.contains("received_at<")),
            "and the rows BELOW the floor are COUNTED through the same index, never materialized; \
             plan was {below:?}"
        );

        drop(conn);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test: ingest and verb-projection writes must take the RESERVED lock at
    /// `BEGIN`, not defer it to their first write statement. The real race (two ingesters both
    /// reading the identity index as `None` and both minting a ref for the same provider id) is
    /// timing-dependent and not a deterministic unit-test witness; what IS deterministic is
    /// SQLite's own locking rule: `BEGIN IMMEDIATE` takes RESERVED synchronously at `BEGIN`, before
    /// a single statement runs inside the transaction, while `BEGIN DEFERRED` (the old
    /// `conn.transaction()` default) takes no lock at all until first use. So a second connection's
    /// own `BEGIN IMMEDIATE`, attempted the INSTANT after the write transaction begins and before
    /// its body has executed anything, must already be refused. Pre-fix
    /// (`conn.transaction()`, Deferred): this assertion FAILS — conn_b's `BEGIN IMMEDIATE` succeeds,
    /// because Deferred took no lock yet. Post-fix (`with_immediate_tx`, Immediate): conn_b is
    /// refused with `SQLITE_BUSY` on the spot.
    ///
    /// shape change: the transaction used to be an OWNED value the test could hold
    /// open across the assertion and `drop` afterward (`begin_write_tx` returned it directly). The
    /// enrolled door (`with_immediate_tx`) never hands a `Transaction` to the caller — the
    /// assertion therefore runs INSIDE the closure, where the transaction is provably still open,
    /// and the witness transaction is left to commit normally when the closure returns `Ok`.
    #[test]
    fn ingest_and_projection_writes_take_the_reserved_lock_at_begin_not_at_first_statement() {
        let (path, mut c) = coordinator("immediate-lock");
        let conn_b = raw(&path);
        // Fail fast on a lock conflict instead of retrying for the 5s default (this test wants the
        // INSTANT answer, not eventual success after a wait).
        conn_b.execute_batch("PRAGMA busy_timeout=0;").unwrap();

        c.conn
            .with_immediate_tx(|_tx| {
                let err = conn_b.execute_batch("BEGIN IMMEDIATE;").expect_err(
                    "a second writer must be refused the instant the first write tx begins",
                );
                let is_busy = matches!(
                    &err,
                    rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DatabaseBusy
                );
                assert!(
                    is_busy,
                    "expected SQLITE_BUSY from the second writer's own BEGIN IMMEDIATE, got {err:?}"
                );
                Ok::<(), LogError>(())
            })
            .expect("the witness transaction itself must commit cleanly");

        drop(conn_b);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// RED: the coordinator's write transactions still reach the connection
    /// through the NAMED ungated escape (`ungated_conn_mut`) — same property, same shape, as
    /// `message_store.rs`'s `a_message_store_write_waits_behind_a_pending_sever`: thread A holds
    /// a `WriteScope` on the store's writer gate (barrier-paused), thread B calls
    /// `ingest_page`, and the TIMING-FREE witness is the gate's own `enroll_waiters` counter.
    /// Pre-fix (`begin_write_tx` on the ungated escape, no `enroll()` anywhere on this path): B
    /// races straight through and the HANG GUARD fires. Post-fix (`GatedConnection::
    /// with_immediate_tx`): B parks behind A.
    #[test]
    fn a_read_coordinator_write_waits_behind_a_pending_sever() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (path, mut c) = coordinator("write-waits-behind-scope");
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
            let refs = c
                .ingest_page("acct", &[summary("E-gate", 100, "hi")])
                .expect("the write eventually succeeds once the scope releases");
            (c, refs)
        });

        let started = std::time::Instant::now();
        while observer.snapshot().expect("snapshot").enroll_waiters != 1 {
            assert!(
                started.elapsed() <= std::time::Duration::from_secs(15),
                "HANG GUARD: `ingest_page` never parked behind the held scope — it ran UNGATED \
                 while the store's writer gate was held"
            );
            thread::yield_now();
        }

        release.store(true, Ordering::SeqCst);
        holder.join().expect("holder thread");
        let (c, refs) = writer.join().expect("writer thread");
        assert_eq!(refs.len(), 1, "the ingest must have landed once the scope released");
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Deadlock diagnostic only, never a latency assertion (the `writer_gate.rs` convention,
    /// borrowed here verbatim from `lib.rs`'s `t6a_spin_until` — this module's tests cannot see
    /// that one, and duplicating six lines beats making a test helper public).
    fn spin_until(label: &str, mut cond: impl FnMut() -> bool) {
        let started = std::time::Instant::now();
        while !cond() {
            assert!(
                started.elapsed() <= std::time::Duration::from_secs(15),
                "HANG GUARD: `{label}` never became true"
            );
            std::thread::yield_now();
        }
    }

    /// Regression test: **a sever raised mid-reconcile waits AT MOST ONE CHUNK.**
    ///
    /// Pre-fix, `refresh_reconcile` materialized every local Inbox row and applied every removal
    /// under ONE `with_immediate_tx`, so a sever ticket raised while it ran waited for the whole
    /// reconcile — the unbounded-hold shape, second appearance. This witness is the
    /// `sever_waits_at_most_one_chunk_under_bulk_import` pattern pointed at this door.
    ///
    /// ORDER, NOT TIME. A raw `BEGIN IMMEDIATE` on a second connection owns SQLite's write lock,
    /// so the FIRST chunk enrolls at the gate (`active_writer` goes true) and then parks at SQL
    /// with nothing committed. The sever ticket is raised in that frozen state — proven frozen by
    /// the row count, not by a sleep — and releasing the blocker lets exactly the enrolled chunk
    /// run to its own commit. The moment `enroll_yields_to_sever` advances, the NEXT chunk's
    /// `enroll()` has provably re-evaluated its predicate and parked behind the ticket, so the
    /// removal count is frozen too, and it must read exactly ONE chunk's worth.
    ///
    /// The discriminator is that exact count. Pre-fix (equivalently: with `REMOVALS_PER_CHUNK`
    /// set to `usize::MAX`, which is the same one-enrollment-covers-everything shape) the single
    /// transaction removes ALL `SEEDED` rows before the sever ever gets the slot, and no second
    /// chunk exists to yield at all — so this witness fails at the HANG GUARD on that spin, and
    /// would fail on the count assertion behind it (`0`, not `SEEDED - REMOVALS_PER_CHUNK`).
    #[test]
    fn a_sever_raised_mid_reconcile_waits_at_most_one_chunk() {
        /// THREE chunks: enough that one chunk's application is unambiguously partial, cheap
        /// enough to seed in one transaction.
        const CHUNKS: usize = 3;
        let seeded = REMOVALS_PER_CHUNK * CHUNKS;

        let (path, mut c) = coordinator("reconcile-chunk-wait");
        // Seed the local Inbox directly, in ONE raw transaction — this is fixture construction,
        // not the property under test, and going through the enrolled per-row doors would cost
        // 2 x `seeded` separate commits.
        {
            let seed = raw(&path);
            seed.execute_batch("BEGIN IMMEDIATE;")
                .expect("the reconcile-chunk fixture seeds in one raw transaction");
            for i in 0..seeded {
                let message_ref = format!("msg-{i:04}");
                crate::message_header::upsert_header_row(
                    &seed,
                    "acct",
                    &message_ref,
                    MAILBOX_INBOX,
                    i as i64,
                    "s@e.com",
                    "S",
                    "subj",
                    false,
                    false,
                )
                .unwrap();
                crate::message_store::upsert_placement_row(
                    &seed,
                    "acct",
                    &message_ref,
                    &ProviderMessageId(format!("E{i:04}")),
                    Placement::Inbox,
                )
                .unwrap();
            }
            seed.execute_batch("COMMIT;").unwrap();
        }

        let observer = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
        let counter = raw(&path);
        let inbox_rows = || {
            count(
                &counter,
                "SELECT COUNT(*) FROM message_header WHERE mailbox = 'Inbox';",
            )
        };
        assert_eq!(inbox_rows(), seeded as i64, "the fixture is seeded");

        // The blocker owns SQLite's write lock; every gate-level step below happens while the
        // first chunk is enrolled but unable to write a single row.
        let blocker = raw(&path);
        blocker
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("the reconcile-chunk sever probe takes SQLite's write lock");

        // An AUTHORITATIVE empty page 1 — the path that removes every local Inbox row, i.e. the
        // one the unbounded hold was worst on.
        let reconciler = std::thread::spawn(move || {
            let fresh = c
                .refresh_reconcile("acct", &[], first_page(true))
                .expect("the reconcile completes once the service does");
            (c, fresh)
        });

        spin_until("the first chunk enrolls (and blocks at SQL)", || {
            observer.snapshot().expect("snapshot").active_writer
        });
        let sever_gate = crate::writer_gate::WriterGate::for_path(&path).expect("identity");
        let sever_thread =
            std::thread::spawn(move || sever_gate.begin_sever("authority:reconcile-chunk"));
        spin_until("the sever ticket is raised", || {
            observer.snapshot().expect("snapshot").sever_pending == 1
        });
        assert_eq!(
            inbox_rows(),
            seeded as i64,
            "anti-vacuous: the ticket is raised BEFORE this reconcile has committed a single \
             removal — what follows measures a wait, not a leftover"
        );

        blocker.execute_batch("ROLLBACK;").unwrap();
        drop(blocker);

        spin_until("the NEXT chunk yields to the pending sever", || {
            observer.snapshot().expect("snapshot").enroll_yields_to_sever > 0
        });
        assert_eq!(
            inbox_rows(),
            (seeded - REMOVALS_PER_CHUNK) as i64,
            "the sever waited for exactly ONE chunk: the enrolled chunk ran to its own commit \
             (never preempted), and the reconcile's remaining {} removals are parked behind the \
             ticket",
            seeded - REMOVALS_PER_CHUNK
        );

        let mut entry = sever_thread.join().expect("sever thread").expect("begin_sever");
        assert!(entry.is_leader(), "the only requester leads");
        entry
            .complete(crate::writer_gate::SeverOutcome::Served { epoch: 999 })
            .expect("complete");

        let (c, fresh) = reconciler.join().expect("reconciler thread");
        assert_eq!(
            inbox_rows(),
            0,
            "anti-vacuous: the reconcile RESUMES and removes the rest once the service completes"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: None,
                stale_below: 0,
            },
            "an authoritative empty page 1 leaves nothing undecided"
        );

        drop(counter);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // (a) ------------------------------------------------------------------------------------
    #[test]
    fn t7_a_the_same_provider_id_on_two_pages_reuses_one_ref_and_one_header_row() {
        let (path, mut c) = coordinator("dup-mint");
        let mut row = summary("E1", 100, "hello");
        row.seen = true;
        row.flagged = true;

        let first = c.ingest_page("acct", std::slice::from_ref(&row)).unwrap();
        // The SAME provider id arrives again on a later page / a later refresh.
        let second = c.ingest_page("acct", std::slice::from_ref(&row)).unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(
            first, second,
            "a provider id already mapped must REUSE its ref, never mint a second one"
        );
        assert!(
            first[0].starts_with("msg-"),
            "a minted ref carries the house prefix; got {:?}",
            first[0]
        );

        let conn = raw(&path);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM message_header;"), 1, "one header row");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM message_placement;"), 1, "one identity row");

        // seen/flagged flow from the HeaderSummary into the header row.
        let rows = headers(&path, "acct", MAILBOX_INBOX);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].seen, "HeaderSummary.seen must reach the header row");
        assert!(rows[0].flagged, "HeaderSummary.flagged must reach the header row");

        drop(conn);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // (b) ------------------------------------------------------------------------------------
    #[test]
    fn t7_b_an_ingested_row_is_actionable_by_construction() {
        let (path, mut c) = coordinator("actionable");
        let refs = c.ingest_page("acct", &[summary("E-actionable", 100, "hi")]).unwrap();

        // The verb path's own resolver — the seam CommandBus dispatches through — finds it.
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.resolve_email_id("acct", &refs[0]).unwrap(),
            Some(ProviderMessageId("E-actionable".into())),
            "a listed row must resolve to its provider id or its buttons are dead"
        );
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Inbox));

        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // (c) ------------------------------------------------------------------------------------
    #[test]
    fn t7_c_a_failed_placement_write_leaves_no_header_row() {
        let (path, mut c) = coordinator("atomicity");
        let conn = raw(&path);
        // FAULT INJECTION: the SECOND write (placement) aborts while the FIRST (header) already
        // succeeded inside the same transaction. A BEFORE INSERT trigger is the real fault here —
        // it leaves the identity SELECT (which runs first, before the mint) fully working, so the
        // only thing that fails is exactly write 2.
        conn.execute_batch(
            "CREATE TRIGGER poison_placement_insert BEFORE INSERT ON message_placement
             BEGIN SELECT RAISE(ABORT, 'injected placement write failure'); END;",
        )
        .unwrap();

        let err = c
            .ingest_page("acct", &[summary("E-atomic", 100, "should not persist")])
            .unwrap_err();
        assert!(
            err.0.contains("injected placement write failure"),
            "the real fault must propagate, not be masked: {}",
            err.0
        );

        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM message_header;"),
            0,
            "the header write must have rolled back with its transaction — a header row without \
             its identity row is an un-actionable ghost"
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM message_placement;"), 0);

        drop(conn);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Seed a local Inbox row directly (header + placement), with a CHOSEN ref — the reconcile
    /// tests need control over the `(received_at, message_ref)` tuple ordering, which minted refs
    /// (128-bit random by design) cannot give.
    fn seed_local(path: &std::path::Path, account: &str, message_ref: &str, email_id: &str, ts: i64) {
        let mut h = SqliteMessageHeaderStore::open(path).unwrap();
        h.record_header(account, message_ref, MAILBOX_INBOX, ts, "s@e.com", "S", "subj", false, false)
            .unwrap();
        let mut p = SqliteMessageStore::open(path).unwrap();
        p.record_optimistic_placement(account, message_ref, &ProviderMessageId(email_id.into()), Placement::Inbox)
            .unwrap();
    }

    /// A legacy header row with NO placement identity (the v8 orphan shape folder
    /// paging hides) must not be counted into `stale_below` — the footer would
    /// report rows nobody can see, forever.
    #[test]
    fn t7_d_a_placement_less_orphan_header_is_not_counted_stale() {
        let (path, mut c) = coordinator("reconcile-orphan-count");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        // The orphan: a header row only — no placement identity (pre-v9 legacy shape).
        {
            let mut h = SqliteMessageHeaderStore::open(&path).unwrap();
            h.record_header("acct", "msg-orphan", MAILBOX_INBOX, 10, "s@e.com", "S", "old", false, false)
                .unwrap();
        }
        // A NON-exhausted page-1 window covering just the top row: the orphan sits below the
        // floor, but it is invisible to the UI — the count must not include it.
        let window = vec![summary("E100", 100, "subj")];
        let fresh = c
            .refresh_reconcile(
                "acct",
                &window,
                WindowAnchor::FirstPage {
                    raw_page_was_empty: false,
                    walk_exhausted: false,
                },
            )
            .unwrap();
        assert_eq!(
            fresh.stale_below, 0,
            "an orphan the paging queries hide is not a stale row the footer may report"
        );
    }

    // (d) ------------------------------------------------------------------------------------
    #[test]
    fn t7_d_a_non_exhausted_window_reconcile_removes_in_window_absentees_and_keeps_below_window_rows() {
        // NON-exhausted (`walk_exhausted: false`): the walk did not end on this page, so a below-
        // floor absentee might still be sitting on a page this refresh never reached, and stays
        // undecided. See the exhausted sibling below for the opposite anchor.
        let (path, mut c) = coordinator("reconcile-window");
        // Five local Inbox rows, newest first: 100, 90, 80, 70, 60.
        for (r, e, ts) in [
            ("msg-100", "E100", 100),
            ("msg-090", "E090", 90),
            ("msg-080", "E080", 80),
            ("msg-070", "E070", 70),
            ("msg-060", "E060", 60),
        ] {
            seed_local(&path, "acct", r, e, ts);
        }

        // The provider's newest page of three: 100, 90, 70 — the 80 was archived externally, so
        // the provider's third-newest is now 70. The window covers [70 .. 100].
        let window = vec![
            summary("E100", 100, "subj"),
            summary("E090", 90, "subj"),
            summary("E070", 70, "subj"),
        ];
        let fresh = c
            .refresh_reconcile(
                "acct",
                &window,
                WindowAnchor::FirstPage {
                    raw_page_was_empty: false,
                    walk_exhausted: false,
                },
            )
            .unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-090", "msg-070", "msg-060"],
            "the in-window absentee (msg-080) is removed; the below-window row (msg-060) is not, \
             because the walk is not exhausted — a later page might still hold it"
        );
        // The removal keeps the identity row — only its header row goes, and its
        // placement is updated to Archive rather than deleted, so the identity mapping survives.
        let conn = raw(&path);
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM message_placement WHERE message_ref='msg-080' \
                 AND placement='archive';"
            ),
            1,
            "a removed row's placement row survives, moved to Archive — never deleted"
        );
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM message_placement;"),
            5,
            "every placement row survives a header removal; only the header row is dropped"
        );

        // The BOUNDARY row (equal to the window floor, and present in the response) stays and is
        // NOT counted as stale: the coverage range is inclusive at the floor.
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((70, "msg-070".to_string())),
                stale_below: 1,
            },
            "checked_through is the window floor; only the row strictly below it is stale"
        );

        drop(conn);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test: an EXHAUSTED nonempty first page reconciles ALL local rows, not
    /// just the ones at/above the window floor.
    ///
    /// Same seeding and the same window as the non-exhausted sibling above, with only the anchor's
    /// `walk_exhausted` flipped to `true`. That flip changes what the window MEANS: the walk ended
    /// here, so this window is not merely "the newest slice down to msg-070" — it is the complete
    /// provider Inbox. There is no later page left for msg-060 to be hiding on, so its absence from
    /// the response is exactly as authoritative as msg-080's: both are gone.
    #[test]
    fn t7_d_an_exhausted_first_page_reconciles_the_below_floor_row_too() {
        let (path, mut c) = coordinator("reconcile-window-exhausted");
        for (r, e, ts) in [
            ("msg-100", "E100", 100),
            ("msg-090", "E090", 90),
            ("msg-080", "E080", 80),
            ("msg-070", "E070", 70),
            ("msg-060", "E060", 60),
        ] {
            seed_local(&path, "acct", r, e, ts);
        }

        let window = vec![
            summary("E100", 100, "subj"),
            summary("E090", 90, "subj"),
            summary("E070", 70, "subj"),
        ];
        // `first_page(false)` is the ordinary v1 shape: `walk_exhausted: true`.
        let fresh = c.refresh_reconcile("acct", &window, first_page(false)).unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-090", "msg-070"],
            "both the in-window absentee (msg-080) AND the below-floor one (msg-060) are removed \
             — an exhausted first page IS the complete Inbox"
        );
        let conn = raw(&path);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM message_placement;"),
            5,
            "msg-080's and msg-060's placement rows survive their header rows' removal \
             (codex-r22 F1) — identity is never deleted, only moved to Archive"
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM message_placement WHERE placement='archive';"
            ),
            2,
            "both removed rows' placements moved to Archive"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((70, "msg-070".to_string())),
                stale_below: 0,
            },
            "nothing is left undecided on an exhausted walk"
        );

        drop(conn);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// THE EQUAL-TIMESTAMP BOUNDARY IS CONSERVATIVE ON A NON-EXHAUSTED WALK.
    ///
    /// A local row whose `received_at` EQUALS the window floor's timestamp and which the provider
    /// did not return may legitimately be sitting on the provider's next page: the keyset the
    /// provider paginates by is its own, and this refresh saw only one side of that timestamp. So
    /// an equal-timestamp absentee is NEVER removed — only rows STRICTLY ABOVE the floor timestamp
    /// are removal candidates — and it is counted honestly as undecided (`stale_below`) rather
    /// than silently trusted. That is true exactly as long as a next page CAN exist — see the
    /// exhausted sibling below for what changes when it cannot.
    #[test]
    fn t7_d_an_equal_timestamp_absentee_at_the_floor_is_kept_and_counted_undecided_when_not_exhausted() {
        let (path, mut c) = coordinator("reconcile-ties");
        // Three rows share received_at = 70; the provider returned only msg-070 of them, so the
        // floor tuple is (70,"msg-070"). Tuple order would put msg-zzz "inside" the window and
        // msg-000 "below" it — but neither was decided by this response, because the provider's
        // page break fell somewhere inside timestamp 70.
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-zzz", "Ezzz", 70);
        seed_local(&path, "acct", "msg-070", "E070", 70);
        seed_local(&path, "acct", "msg-000", "E000", 70);

        // The provider returns the newest row and the floor row only. NOT exhausted — a next page
        // could still exist.
        let window = vec![summary("E100", 100, "subj"), summary("E070", 70, "subj")];
        let fresh = c
            .refresh_reconcile(
                "acct",
                &window,
                WindowAnchor::FirstPage {
                    raw_page_was_empty: false,
                    walk_exhausted: false,
                },
            )
            .unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-zzz", "msg-070", "msg-000"],
            "NOTHING at the floor timestamp may be removed on an absence: msg-zzz's higher ref \
             does not prove the provider looked at it"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((70, "msg-070".to_string())),
                stale_below: 2,
            },
            "the two equal-timestamp absentees are UNDECIDED and counted as such; the returned \
             floor row itself was re-checked and is not stale"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test for the tie-break half — on an EXHAUSTED walk, an equal-timestamp
    /// absentee resolves too: there is no next page left for it to be hiding on, so it is removed
    /// exactly like a strictly-below-floor absentee is. Same seeding as the non-exhausted sibling
    /// above, only `walk_exhausted` flips to `true`.
    #[test]
    fn t7_d_an_equal_timestamp_absentee_at_the_floor_is_removed_when_the_walk_is_exhausted() {
        let (path, mut c) = coordinator("reconcile-ties-exhausted");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-zzz", "Ezzz", 70);
        seed_local(&path, "acct", "msg-070", "E070", 70);
        seed_local(&path, "acct", "msg-000", "E000", 70);

        let window = vec![summary("E100", 100, "subj"), summary("E070", 70, "subj")];
        // `first_page(false)` is the ordinary v1 shape: `walk_exhausted: true`.
        let fresh = c.refresh_reconcile("acct", &window, first_page(false)).unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-070"],
            "no later page can exist to be hiding msg-zzz or msg-000 on — both are removed"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((70, "msg-070".to_string())),
                stale_below: 0,
            },
            "nothing is left undecided on an exhausted walk"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// A PAGE-1 WINDOW HAS NO UPPER BOUND.
    ///
    /// Page 1 IS the newest page: there is nothing above it for a message to hide in. A local row
    /// newer than every row the provider returned and absent from that response was archived or
    /// moved externally, and a coverage range bounded by the fetched window's newest tuple would
    /// let it escape removal forever (it can never come back into a page-1 window).
    #[test]
    fn t7_d_a_page_one_window_removes_a_local_row_newer_than_every_fetched_row() {
        let (path, mut c) = coordinator("reconcile-open-ceiling");
        seed_local(&path, "acct", "msg-200", "E200", 200);
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-090", "E090", 90);

        // Page 1, newest-first — and msg-200 is not in it.
        let window = vec![summary("E100", 100, "subj"), summary("E090", 90, "subj")];
        let fresh = c.refresh_reconcile("acct", &window, first_page(false)).unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-090"],
            "a row NEWER than the provider's newest returned row is above nothing — page 1 is \
             authoritative up to +infinity, so an absentee there is removed"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((90, "msg-090".to_string())),
                stale_below: 0,
            }
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// The OTHER half of the anchor: an [`WindowAnchor::Interior`] window keeps its ceiling, so
    /// the same seeding that removes `msg-200` under `FirstPage` must LEAVE IT ALONE here — rows
    /// above a continuation-anchored window were never fetched and so were never decided.
    #[test]
    fn t7_d_an_interior_window_keeps_its_ceiling_and_removes_nothing_above_it() {
        let (path, mut c) = coordinator("reconcile-interior");
        seed_local(&path, "acct", "msg-200", "E200", 200);
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-095", "E095", 95);
        seed_local(&path, "acct", "msg-090", "E090", 90);

        // A continuation page: 100 down to 90, with 95 archived externally in between.
        let window = vec![summary("E100", 100, "subj"), summary("E090", 90, "subj")];
        let fresh = c
            .refresh_reconcile("acct", &window, WindowAnchor::Interior)
            .unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-200", "msg-100", "msg-090"],
            "the in-window absentee (msg-095) goes; the row ABOVE the ceiling (msg-200) is \
             un-looked-at on a continuation window and must survive"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((90, "msg-090".to_string())),
                stale_below: 1,
            },
            "msg-200 was not decided by this window, and says so"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn t7_d_an_empty_first_page_is_the_empty_inbox_and_clears_every_local_row() {
        // Regression test: an empty page 1 is not an ABSENCE of an answer — it IS the
        // answer: the provider's newest page is empty, so the Inbox is empty. Treating it as "no
        // coverage" left every cached row on screen, marked stale FOREVER (no later page-1 refresh
        // can ever decide them, because page 1 stays empty).
        let (path, mut c) = coordinator("reconcile-empty-first");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-090", "E090", 90);

        let fresh = c.refresh_reconcile("acct", &[], first_page(true)).unwrap();
        assert_eq!(
            fresh,
            Freshness { checked_through: None, stale_below: 0 },
            "nothing is left undecided: the empty first page decided all of it"
        );
        assert!(
            headers(&path, "acct", MAILBOX_INBOX).is_empty(),
            "every local Inbox header row must be gone"
        );
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", "msg-100").unwrap(),
            Some(Placement::Archive),
            "the placement row SURVIVES the header removal, moved to Archive (codex-r22 F1) — \
             deleting it here would orphan the (account, email_id) -> message_ref identity \
             mapping for a message that comes back to the Inbox later"
        );
        assert_eq!(store.placement("acct", "msg-090").unwrap(), Some(Placement::Archive));

        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test: a FILTERED-TO-ZERO page 1 is not an empty inbox.
    ///
    /// The window the coordinator receives is the transport's MAPPED page, and both live
    /// transports drop rows from it: Gmail skips a message whose per-id metadata get no longer
    /// says `INBOX`, JMAP skips an id its `Email/get` half did not answer for. A provider page
    /// holding rows can therefore arrive here EMPTY — and the empty-first-page rule then reads
    /// that as "the Inbox is empty" and deletes every local row. The raw page's emptiness is a
    /// fact only the caller that issued the fetch holds, so the caller must state it.
    #[test]
    fn t7_d_a_filtered_to_zero_first_page_is_not_an_authoritative_empty_inbox() {
        let (path, mut c) = coordinator("reconcile-filtered-empty");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-090", "E090", 90);

        // The provider's page 1 held rows; every one of them was filtered out above this call.
        let fresh = c
            .refresh_reconcile(
                "acct",
                &[],
                first_page(false),
            )
            .unwrap();

        assert_eq!(
            headers(&path, "acct", MAILBOX_INBOX).len(),
            2,
            "a page whose rows were all filtered out decides NOTHING — it is a no-coverage \
             refresh, not the empty inbox"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: None,
                stale_below: 2,
            },
            "and it says so honestly: both local rows are undecided"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test: a RAW-empty page 1 that is NOT the end of the walk.
    ///
    /// Same bytes on the wire as the authoritative-empty case above (`window: []`,
    /// `raw_page_was_empty: true`), and the opposite meaning: the provider handed back a
    /// continuation, so its rows are further down a walk this window never reached. Wiping here
    /// deleted the entire local projection on the strength of a page break.
    #[test]
    fn t7_d_a_raw_empty_first_page_with_the_walk_still_running_is_not_the_empty_inbox() {
        let (path, mut c) = coordinator("reconcile-empty-unfinished");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-090", "E090", 90);

        let fresh = c
            .refresh_reconcile(
                "acct",
                &[],
                WindowAnchor::FirstPage {
                    raw_page_was_empty: true,
                    walk_exhausted: false,
                },
            )
            .unwrap();

        assert_eq!(
            headers(&path, "acct", MAILBOX_INBOX).len(),
            2,
            "an empty page with a continuation pending is a GAP in the walk, not the end of the \
             mailbox — it may remove nothing"
        );
        assert_eq!(
            fresh,
            Freshness { checked_through: None, stale_below: 2 },
            "and it reports honest staleness instead of a wipe"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// The correctness half of the bounded read: rows OUTSIDE the window's range
    /// are neither removed nor mis-counted — on a NON-exhausted walk. See the exhausted sibling
    /// below for the opposite anchor, where the read is deliberately unbounded.
    ///
    /// The bounded read materializes only rows at or above the floor timestamp and COUNTS the rest
    /// through the index. This pins the arithmetic that swap depends on: every below-floor row
    /// still lands in `stale_below`, exactly once, and none of them is touched. (The perf claim
    /// itself is witnessed mechanically by the query-plan test above; this one witnesses that the
    /// recut is behaviour-preserving, which the rest of the reconcile suite also does.)
    #[test]
    fn rows_below_the_window_floor_are_counted_stale_and_never_removed_when_not_exhausted() {
        let (path, mut c) = coordinator("reconcile-below-floor");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-095", "E095", 95);
        seed_local(&path, "acct", "msg-090", "E090", 90);
        // Four rows strictly BELOW the window floor — outside the bounded read entirely.
        seed_local(&path, "acct", "msg-080", "E080", 80);
        seed_local(&path, "acct", "msg-070", "E070", 70);
        seed_local(&path, "acct", "msg-060", "E060", 60);
        seed_local(&path, "acct", "msg-050", "E050", 50);

        // Page 1 covers 100..=90; msg-095 was archived externally and is IN range. NOT exhausted —
        // a next page could still exist below this one.
        let window = vec![summary("E100", 100, "subj"), summary("E090", 90, "subj")];
        let fresh = c
            .refresh_reconcile(
                "acct",
                &window,
                WindowAnchor::FirstPage {
                    raw_page_was_empty: false,
                    walk_exhausted: false,
                },
            )
            .unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-090", "msg-080", "msg-070", "msg-060", "msg-050"],
            "the in-range absentee goes; every row below the floor is untouched"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((90, "msg-090".to_string())),
                stale_below: 4,
            },
            "and all four below-floor rows are counted undecided — counted, not materialized"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test: an EXHAUSTED nonempty first page reconciles ALL local rows, not
    /// just the ones at/above the window floor. Same seeding as the non-exhausted sibling above,
    /// only `walk_exhausted` flips to `true`: this window IS the complete provider Inbox, so the
    /// four below-floor rows are decided (and removed, being absent) instead of counted stale.
    #[test]
    fn an_exhausted_first_page_reconciles_every_row_below_the_floor_too() {
        let (path, mut c) = coordinator("reconcile-below-floor-exhausted");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-095", "E095", 95);
        seed_local(&path, "acct", "msg-090", "E090", 90);
        seed_local(&path, "acct", "msg-080", "E080", 80);
        seed_local(&path, "acct", "msg-070", "E070", 70);
        seed_local(&path, "acct", "msg-060", "E060", 60);
        seed_local(&path, "acct", "msg-050", "E050", 50);

        let window = vec![summary("E100", 100, "subj"), summary("E090", 90, "subj")];
        // `first_page(false)` is the ordinary v1 shape: `walk_exhausted: true`.
        let fresh = c.refresh_reconcile("acct", &window, first_page(false)).unwrap();

        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert_eq!(
            kept,
            vec!["msg-100", "msg-090"],
            "the in-range absentee (msg-095) AND all four below-floor rows are removed — an \
             exhausted first page IS the complete Inbox, so there is no next page left for any of \
             them to be hiding on"
        );
        assert_eq!(
            fresh,
            Freshness {
                checked_through: Some((90, "msg-090".to_string())),
                stale_below: 0,
            },
            "nothing is left undecided on an exhausted walk"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn t7_d_an_empty_interior_window_re_checks_nothing_and_removes_nothing() {
        // The OTHER half of the anchor, unchanged: an empty CONTINUATION page says only that this
        // continuation returned nothing — the rows above it were never in its coverage, so nothing
        // may be removed and everything is honestly undecided.
        let (path, mut c) = coordinator("reconcile-empty-interior");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-090", "E090", 90);

        let fresh = c.refresh_reconcile("acct", &[], WindowAnchor::Interior).unwrap();
        assert_eq!(
            fresh,
            Freshness { checked_through: None, stale_below: 2 },
            "an empty interior page is authoritative over nothing: no coverage, everything unchecked"
        );
        assert_eq!(headers(&path, "acct", MAILBOX_INBOX).len(), 2, "nothing may be removed");

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// Regression test: a reconcile removal PRESERVES PROVIDER IDENTITY.
    ///
    /// Deleting `message_placement` on an external-archive removal destroyed the
    /// `(account, email_id) -> message_ref` mapping THAT ROW IS. A message reconcile-removed
    /// from the Inbox and later moved back to it externally re-resolves through the SAME
    /// `resolve_ref_in_tx` identity lookup ingest always runs first — before this fold that
    /// lookup found nothing (the row was gone), so ingest minted a FRESH ref for a message every
    /// prior verb/history/undo entry already knew under its ORIGINAL ref, orphaning that
    /// linkage. After the fold: the removal UPDATEs the placement row to Archive instead of
    /// deleting it, so the identity mapping survives and the re-ingest reuses the original ref.
    #[test]
    fn t7_d_a_message_reconciled_out_of_the_inbox_keeps_its_ref_when_it_comes_back() {
        let (path, mut c) = coordinator("reconcile-identity-preserved");
        seed_local(&path, "acct", "msg-100", "E100", 100);
        seed_local(&path, "acct", "msg-080", "E080", 80);

        // Page 1: only msg-100 comes back — msg-080 was archived externally and is removed.
        let window = vec![summary("E100", 100, "subj")];
        c.refresh_reconcile("acct", &window, first_page(false)).unwrap();

        assert!(
            headers(&path, "acct", MAILBOX_INBOX)
                .into_iter()
                .all(|r| r.message_ref != "msg-080"),
            "msg-080's header row must have left the Inbox view"
        );
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", "msg-080").unwrap(),
            Some(Placement::Archive),
            "removal moves the placement row to Archive — it must not be deleted, or the \
             identity mapping it carries is destroyed with it"
        );
        drop(store);

        // The SAME provider message (E080) is fetched again — it moved back to the Inbox
        // externally, and a later refresh's page-1 window carries it once more.
        let refs = c.ingest_page("acct", &[summary("E080", 80, "subj")]).unwrap();
        assert_eq!(
            refs,
            vec!["msg-080".to_string()],
            "the ORIGINAL ref must be reused — minting a new one here orphans every prior \
             reference (history, undo, in-flight verbs) to this message"
        );
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", "msg-080").unwrap(),
            Some(Placement::Inbox),
            "the placement moves back to Inbox on the re-ingest write, under the SAME ref"
        );
        let kept: Vec<String> = headers(&path, "acct", MAILBOX_INBOX)
            .into_iter()
            .map(|r| r.message_ref)
            .collect();
        assert!(
            kept.contains(&"msg-080".to_string()),
            "the header row is re-created in the Inbox view, under the SAME ref"
        );

        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // (e) ------------------------------------------------------------------------------------
    #[test]
    fn t7_e_archive_moves_both_placement_and_mailbox() {
        let (path, mut c) = coordinator("verb-archive");
        let refs = c.ingest_page("acct", &[summary("E1", 100, "hi")]).unwrap();

        assert_eq!(
            c.apply_verb_delta("acct", &refs[0], VerbDelta::Archived),
            ProjectionOutcome::Current
        );
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Archive));
        assert!(headers(&path, "acct", MAILBOX_INBOX).is_empty(), "it left the Inbox folder view");
        assert_eq!(headers(&path, "acct", MAILBOX_ARCHIVE).len(), 1, "it is in the Archive view");

        // ...and back.
        assert_eq!(
            c.apply_verb_delta("acct", &refs[0], VerbDelta::Unarchived),
            ProjectionOutcome::Current
        );
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Inbox));
        assert_eq!(headers(&path, "acct", MAILBOX_INBOX).len(), 1);

        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn t7_e_star_flips_the_flag_and_never_touches_the_mailbox() {
        let (path, mut c) = coordinator("verb-star");
        let refs = c.ingest_page("acct", &[summary("E1", 100, "hi")]).unwrap();

        assert_eq!(
            c.apply_verb_delta("acct", &refs[0], VerbDelta::StarSet(true)),
            ProjectionOutcome::Current
        );
        let rows = headers(&path, "acct", MAILBOX_INBOX);
        assert_eq!(rows.len(), 1, "starring must not move the message out of the Inbox");
        assert!(rows[0].flagged, "StarSet(true) must set flagged");
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", &refs[0]).unwrap(),
            Some(Placement::Inbox),
            "StarSet must not touch placement"
        );

        assert_eq!(
            c.apply_verb_delta("acct", &refs[0], VerbDelta::StarSet(false)),
            ProjectionOutcome::Current
        );
        assert!(!headers(&path, "acct", MAILBOX_INBOX)[0].flagged, "StarSet(false) clears it");

        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn trashed_and_spam_deltas_move_placement_and_mailbox_together_and_restore_arms_return_to_archive() {
        let (path, mut c) = coordinator("s1-deltas");
        let refs = c.ingest_page("acct", &[summary("E1", 100, "hi")]).unwrap();
        let store = SqliteMessageStore::open(&path).unwrap();

        assert_eq!(c.apply_verb_delta("acct", &refs[0], VerbDelta::Trashed), ProjectionOutcome::Current);
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Trash));
        assert_eq!(headers(&path, "acct", MAILBOX_TRASH).len(), 1, "it is in the Trash view");
        assert!(headers(&path, "acct", MAILBOX_INBOX).is_empty(), "it left the Inbox view");

        assert_eq!(c.apply_verb_delta("acct", &refs[0], VerbDelta::Untrashed), ProjectionOutcome::Current);
        assert_eq!(
            store.placement("acct", &refs[0]).unwrap(),
            Some(Placement::Archive),
            "untrash returns to All Mail (Archive), never silently to the inbox"
        );
        assert_eq!(headers(&path, "acct", MAILBOX_ARCHIVE).len(), 1, "the header follows the placement");
        assert!(headers(&path, "acct", MAILBOX_TRASH).is_empty(), "it left the Trash view");
        assert!(headers(&path, "acct", MAILBOX_INBOX).is_empty(), "untrash does not re-add INBOX");

        assert_eq!(c.apply_verb_delta("acct", &refs[0], VerbDelta::SpamSet(true)), ProjectionOutcome::Current);
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Spam));
        assert_eq!(headers(&path, "acct", MAILBOX_SPAM).len(), 1, "it is in the Spam view");
        assert!(headers(&path, "acct", MAILBOX_ARCHIVE).is_empty(), "it left the Archive view");

        assert_eq!(c.apply_verb_delta("acct", &refs[0], VerbDelta::SpamSet(false)), ProjectionOutcome::Current);
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Archive));
        assert_eq!(headers(&path, "acct", MAILBOX_ARCHIVE).len(), 1);
        assert!(headers(&path, "acct", MAILBOX_SPAM).is_empty(), "it left the Spam view");

        assert_eq!(c.apply_verb_delta("acct", &refs[0], VerbDelta::SeenSet(true)), ProjectionOutcome::Current);
        let rows = headers(&path, "acct", MAILBOX_ARCHIVE);
        assert_eq!(rows.len(), 1, "SeenSet does not move the message");
        assert!(rows[0].seen, "SeenSet(true) sets seen");
        assert!(!rows[0].flagged, "SeenSet touches the seen bit and NOTHING else");
        assert_eq!(store.placement("acct", &refs[0]).unwrap(), Some(Placement::Archive));
        assert_eq!(c.apply_verb_delta("acct", &refs[0], VerbDelta::SeenSet(false)), ProjectionOutcome::Current);
        assert!(!headers(&path, "acct", MAILBOX_ARCHIVE)[0].seen, "SeenSet(false) clears it");

        // The exactly-one-row rule (`refuse_unprojected`) covers the new arms too: a ref the
        // projection never heard of is Stale, never a silent Current.
        for delta in [
            VerbDelta::Trashed,
            VerbDelta::Untrashed,
            VerbDelta::SpamSet(true),
            VerbDelta::SpamSet(false),
            VerbDelta::SeenSet(true),
        ] {
            assert!(
                matches!(c.apply_verb_delta("acct", "msg-never-ingested", delta), ProjectionOutcome::Stale(_)),
                "{delta:?} on an unknown ref must be Stale"
            );
        }

        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// THE VERB PROJECTION REQUIRES *BOTH* ROWS.
    ///
    /// A placement-moving delta writes two rows, and the old admission test was
    /// `moved + refiled != 0` — so a store carrying only ONE of them (a legacy row written before
    /// the pair was atomic, a half-removed row, a damaged file) passed as `Current` while exactly
    /// half the projection moved. The UI then rendered a message that had left the Inbox in the
    /// placement table but still sat in the Inbox folder view, with nothing marked stale.
    #[test]
    fn t7_e_a_placement_row_without_its_header_row_is_stale_and_changes_neither_row() {
        let (path, mut c) = coordinator("verb-half-projection");
        // ONLY the placement row exists — no header row for this ref.
        let mut p = SqliteMessageStore::open(&path).unwrap();
        p.record_optimistic_placement(
            "acct",
            "msg-orphan",
            &ProviderMessageId("E-orphan".into()),
            Placement::Inbox,
        )
        .unwrap();
        drop(p);

        match c.apply_verb_delta("acct", "msg-orphan", VerbDelta::Archived) {
            ProjectionOutcome::Stale(reason) => {
                assert!(
                    reason.contains("message_header"),
                    "the reason must NAME the row that was absent, or the stale arm is \
                     undiagnosable: {reason}"
                );
            }
            ProjectionOutcome::Current => panic!(
                "only the placement row moved — reporting Current commits a half-updated \
                 projection as the truth"
            ),
        }

        // NEITHER row changed: the transaction rolled back, so the placement row still says Inbox.
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", "msg-orphan").unwrap(),
            Some(Placement::Inbox),
            "a refused projection must roll the placement write back, never leave the half it \
             managed to write"
        );
        let conn = raw(&path);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM message_header WHERE message_ref='msg-orphan';"),
            0,
            "no header row is invented on the way out"
        );

        drop(conn);
        drop(store);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    /// The mirror of the row above: a HEADER row with no placement row. Same rule, other side —
    /// the star delta (one row only) is unaffected and keeps its own single-row admission.
    #[test]
    fn t7_e_a_header_row_without_its_placement_row_is_stale_too() {
        let (path, mut c) = coordinator("verb-half-projection-header");
        let mut h = SqliteMessageHeaderStore::open(&path).unwrap();
        h.record_header("acct", "msg-headeronly", MAILBOX_INBOX, 100, "s@e.com", "S", "subj", false, false)
            .unwrap();
        drop(h);

        match c.apply_verb_delta("acct", "msg-headeronly", VerbDelta::Archived) {
            ProjectionOutcome::Stale(reason) => assert!(
                reason.contains("message_placement"),
                "the reason must name the absent row: {reason}"
            ),
            ProjectionOutcome::Current => {
                panic!("only the header row moved — that is a half-updated projection")
            }
        }
        // The paged read (`headers()`/`folder_first_page`) is placement-joined and
        // so is blind to this deliberately-orphaned header row by design — read the mailbox column
        // RAW to witness the rollback instead.
        assert_eq!(
            raw_header_mailbox(&path, "acct", "msg-headeronly").as_deref(),
            Some(MAILBOX_INBOX),
            "the header row must NOT have moved to Archive — the txn rolled back"
        );
        assert!(
            headers(&path, "acct", MAILBOX_INBOX).is_empty(),
            "the placement-joined page never surfaces this row at all — it has no placement \
             identity to pair it with, paired or not (codex-r16 F3)"
        );
        assert_eq!(headers(&path, "acct", MAILBOX_ARCHIVE).len(), 0);

        // A STAR delta touches exactly one row by design, and it is still admitted on that one.
        assert_eq!(
            c.apply_verb_delta("acct", "msg-headeronly", VerbDelta::StarSet(true)),
            ProjectionOutcome::Current,
            "starring writes the header row alone — the both-rows rule is a PLACEMENT-MOVE rule"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn t7_e_an_unknown_ref_is_stale_not_a_silent_success() {
        let (path, mut c) = coordinator("verb-unknown-ref");
        match c.apply_verb_delta("acct", "msg-never-ingested", VerbDelta::Archived) {
            ProjectionOutcome::Stale(reason) => assert!(
                !reason.is_empty(),
                "a projection that could not be maintained must say why"
            ),
            ProjectionOutcome::Current => {
                panic!("no row exists to project onto — reporting Current would be a lie")
            }
        }
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // (f) ------------------------------------------------------------------------------------
    #[test]
    fn t7_f_a_failed_projection_write_after_a_successful_verb_reports_stale_with_the_real_reason() {
        let (path, mut c) = coordinator("dual-outcome");
        let refs = c.ingest_page("acct", &[summary("E1", 100, "hi")]).unwrap();

        // FAULT INJECTION: the projection UPDATE aborts. The VERB already succeeded (this API is
        // called after it), so this must NOT become an error — it must become the Stale arm.
        let conn = raw(&path);
        conn.execute_batch(
            "CREATE TRIGGER poison_placement_update BEFORE UPDATE ON message_placement
             BEGIN SELECT RAISE(ABORT, 'injected projection write failure'); END;",
        )
        .unwrap();

        match c.apply_verb_delta("acct", &refs[0], VerbDelta::Archived) {
            ProjectionOutcome::Stale(reason) => {
                assert!(!reason.is_empty(), "the stale arm must carry a reason");
                assert!(
                    reason.contains("injected projection write failure"),
                    "the reason must be built from the REAL error, never a generic string: {reason}"
                );
            }
            ProjectionOutcome::Current => panic!("a failed projection write must never report Current"),
        }
        // ...and the failed projection left NO half-applied state: the header must not have moved
        // to Archive while the placement row still says Inbox.
        assert_eq!(
            headers(&path, "acct", MAILBOX_INBOX).len(),
            1,
            "a stale projection is the OLD projection, not a half-written one"
        );
        assert_eq!(headers(&path, "acct", MAILBOX_ARCHIVE).len(), 0);

        drop(conn);
        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // (g) ------------------------------------------------------------------------------------
    #[test]
    fn t7_g_ingest_normalizes_display_strings_and_leaves_the_address_byte_exact() {
        let (path, mut c) = coordinator("normalize");
        // A Cyrillic 'о' (U+043E) in the address: an identity byte string that must round-trip
        // EXACTLY as the provider sent it (`header_normalize`'s from_addr caller contract).
        let hostile_addr = "admin@ph\u{043E}ton.local";
        let row = HeaderSummary {
            provider_id: ProviderMessageId("E-spoof".into()),
            received_at: 100,
            from_addr: hostile_addr.to_string(),
            from_name: "\u{2066}admin".to_string(),
            subject: "invoice\u{202E}fdp.exe".to_string(),
            seen: false,
            flagged: false,
            attachments: AttachmentPresence::default(),
        };
        c.ingest_page("acct", &[row]).unwrap();

        let rows = headers(&path, "acct", MAILBOX_INBOX);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].subject, "invoicefdp.exe", "the RLO must be stripped at ingest");
        assert_eq!(rows[0].from_name, "admin", "the LRI must be stripped at ingest");
        assert_eq!(
            rows[0].from_addr, hostile_addr,
            "from_addr is identity, NOT display — it must survive byte-exact"
        );

        drop(c);
        std::fs::remove_file(&path).ok();
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // the reconcile's two concurrency windows. Both drive a REAL
    // competing writer through the `seam` hooks above (see that module's doc for why the
    // instants are otherwise unreachable), and both assert the injected write LANDED.
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// The raw `(mailbox, received_at, ingest_revision)` triple for one header row — the CAS's
    /// own inputs, read outside every decorated path.
    fn raw_header_row(
        path: &std::path::Path,
        account: &str,
        message_ref: &str,
    ) -> Option<(String, i64, i64)> {
        let conn = raw(path);
        conn.query_row(
            "SELECT mailbox, received_at, ingest_revision FROM message_header
              WHERE account=?1 AND message_ref=?2;",
            rusqlite::params![account, message_ref],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()
    }

    #[test]
    fn a_newer_ingest_re_confirm_is_not_deleted_by_an_older_reconcile() {
        // THE RACE, EXACTLY: coordinator A decides that `E2` is gone from the Inbox (its window
        // no longer carries it). Before A applies that verdict, a NEWER refresh — coordinator B,
        // its own connection — runs `ingest_page` and re-confirms `E2` INTO the Inbox. The
        // pre-fix CAS compared only `mailbox='Inbox'`, which the re-upserted row satisfies
        // (ingest is what put it there) with an unchanged `received_at`, so A's DELETE removed
        // the CURRENT provider evidence: a live message vanishing from the Inbox on the strength
        // of a page that no longer describes it, recoverable only by a later refresh.
        let (path, mut a) = coordinator("r4-f3-newer-ingest-wins");
        let e1 = summary("E1", 200, "kept");
        let e2 = summary("E2", 100, "re-confirmed");
        let refs = a.ingest_page("acct", &[e1.clone(), e2.clone()]).unwrap();
        let ref2 = refs[1].clone();
        let before = raw_header_row(&path, "acct", &ref2).expect("E2 is local");

        // B, at the one instant that matters.
        let seam_path = path.to_path_buf();
        let seam_row = e2.clone();
        seam::arm_between_phases(move || {
            let mut b = ReadCoordinator::open(&seam_path).expect("the newer refresh opens");
            b.ingest_page("acct", std::slice::from_ref(&seam_row))
                .expect("the newer refresh re-confirms E2 into the Inbox");
        });

        // A's window: E1 only. E2 is an absentee by A's evidence.
        let fresh = a
            .refresh_reconcile("acct", &[e1], first_page(false))
            .unwrap();

        let after = raw_header_row(&path, "acct", &ref2);
        assert!(
            after.is_some(),
            "the re-confirmed row must SURVIVE the older reconcile — the newer provider answer \
             wins, and the stale verdict is withdrawn rather than applied"
        );
        let (mailbox, _, revision_after) = after.unwrap();
        assert_eq!(mailbox, MAILBOX_INBOX, "and it stays where ingest put it");

        // ANTI-VACUITY: the injected ingest really ran, and really moved the marker the CAS
        // reads. Without this the survival above could just as well mean the seam never fired.
        assert_eq!(
            revision_after,
            before.2 + 1,
            "the re-confirm must bump `ingest_revision` — that bump IS the discriminator"
        );
        assert_eq!(
            fresh.stale_below, 1,
            "a withdrawn verdict is an UNDECIDED row, and is reported as one rather than \
             silently dropped"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }

    /// CLOSE B — **A DELETE + REINSERT MUST NOT RESURRECT A STALE
    /// RECONCILE VERDICT.**
    ///
    /// The second member of the reconcile-versioning family (gave the CAS a marker;
    /// found the marker RESETTABLE), and the reason the family closed WHOLESALE by making the
    /// marker STORE-MONOTONIC rather than by adding a third comparand. `upsert_header_row`'s
    /// INSERT arm used to write `ingest_revision = 0` literally, so a row that was DELETED and
    /// then RE-INSERTED came back at 0 — and an older reconcile holding
    /// `decided_ingest_revision = 0` matched it exactly. The CAS then deleted a row written
    /// AFTER the verdict that condemned it: precisely the harm closed, in a new costume.
    ///
    /// THE INTERLEAVE, EXACTLY: coordinator A decides `E2` is gone from the Inbox. Between the
    /// verdict and the apply, reconcile-B (an authoritative empty page 1 — the provider says
    /// the Inbox is empty) REMOVES every local row, and a NEWER ingest re-confirms `E2`. A
    /// then applies. Pre-fix the reinserted row's revision is 0 == A's decided value, so A
    /// deletes CURRENT provider evidence; post-fix the reinsert carries a fresh revision
    /// strictly greater than anything ever issued in this store, the compare fails, and the
    /// row SURVIVES.
    #[test]
    fn a_delete_and_reinsert_cannot_resurrect_a_stale_reconcile_verdict() {
        let (path, mut a) = coordinator("r5-delete-reinsert-revision");
        let e1 = summary("E1", 200, "kept");
        let e2 = summary("E2", 100, "removed, then re-ingested");
        let refs = a.ingest_page("acct", &[e1.clone(), e2.clone()]).unwrap();
        let ref2 = refs[1].clone();
        let before = raw_header_row(&path, "acct", &ref2).expect("E2 is local");

        // B, at the one instant that matters: a full removal followed by a fresh re-ingest.
        let seam_path = path.to_path_buf();
        let seam_row = e2.clone();
        let seam_ref = ref2.clone();
        seam::arm_between_phases(move || {
            let mut b = ReadCoordinator::open(&seam_path).expect("the newer refresh opens");
            // An AUTHORITATIVE empty page 1 removes every local Inbox row — including E2.
            b.refresh_reconcile("acct", &[], first_page(true))
                .expect("the empty-page reconcile applies");
            assert!(
                raw_header_row(&seam_path, "acct", &seam_ref).is_none(),
                "the interleave's premise: E2's header row is really GONE before the re-ingest"
            );
            // …and a NEWER page re-confirms the same message into the Inbox.
            b.ingest_page("acct", std::slice::from_ref(&seam_row))
                .expect("the newer refresh re-ingests E2");
        });

        // A's window: E1 only. E2 is an absentee by A's (now stale) evidence.
        let fresh = a.refresh_reconcile("acct", &[e1], first_page(false)).unwrap();

        let after = raw_header_row(&path, "acct", &ref2);
        assert!(
            after.is_some(),
            "the RE-INSERTED row must SURVIVE the older reconcile — a row written after a \
             verdict carries a revision the verdict cannot name, whether or not the row it \
             replaced was deleted first"
        );
        let (mailbox, _, revision_after) = after.unwrap();
        assert_eq!(mailbox, MAILBOX_INBOX, "and it stays where ingest put it");
        assert!(
            revision_after > before.2,
            "the marker is STORE-MONOTONIC: a reinsert must issue a revision strictly greater \
             than the decided one ({}), never reset to 0 — got {revision_after}",
            before.2
        );
        assert_eq!(
            fresh.stale_below, 1,
            "a withdrawn verdict is an UNDECIDED row, and is reported as one"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }

    /// **AN ARCHIVE→UNARCHIVE ROUND TRIP MUST NOT RESURRECT A STALE
    /// RECONCILE VERDICT.**
    ///
    /// The third member of the reconcile-versioning family (gave the CAS a marker; found
    /// it RESETTABLE on delete+reinsert; found it INCOMPLETE — one call site never drew it
    /// at all), one hop past: `refresh_reconcile`'s DELETE compares `ingest_revision` against
    /// the value read at DECISION time. closed the case where the row's revision RESETS (a
    /// delete+reinsert bringing a fresh row back at 0); this is the case where the row's
    /// PLACEMENT round-trips through [`Self::write_verb_delta`] WITHOUT the revision moving AT
    /// ALL — pre-fix that function's `UPDATE message_header SET mailbox = ?3` never touched
    /// `ingest_revision`, so an archive followed by an unarchive restores `mailbox='Inbox'` at
    /// the SAME revision an earlier reconcile already decided against. The CAS then matches a
    /// row the user visibly just acted on (they unarchived it — it belongs in the Inbox right
    /// now) and deletes it.
    ///
    /// THE INTERLEAVE, EXACTLY: coordinator A decides `E2` is gone from the Inbox (absent from
    /// its window). Between the verdict and the apply, coordinator B archives `E2` and then
    /// unarchives it — `mailbox` ends back at `'Inbox'`, matching what A's read phase saw. A
    /// then applies. Pre-fix the round-tripped row's revision is UNCHANGED (still the decided
    /// value), so A's CAS matches and DELETES it; post-fix the archive/unarchive pair each drew
    /// a fresh revision, the compare fails, and the row SURVIVES — counted into `stale_below` as
    /// the undecided row it now is.
    #[test]
    fn an_archive_unarchive_round_trip_cannot_resurrect_a_stale_reconcile_verdict() {
        let (path, mut a) = coordinator("r6-f2-archive-unarchive-revision");
        let e1 = summary("E1", 200, "kept");
        let e2 = summary("E2", 100, "archived, then unarchived");
        let refs = a.ingest_page("acct", &[e1.clone(), e2.clone()]).unwrap();
        let ref2 = refs[1].clone();
        let before = raw_header_row(&path, "acct", &ref2).expect("E2 is local");

        // B, at the one instant that matters: an archive immediately followed by an unarchive,
        // landing E2 back in the Inbox — visibly, by the user's own action — between A's
        // decision and its apply.
        let seam_path = path.to_path_buf();
        let seam_ref = ref2.clone();
        seam::arm_between_phases(move || {
            let mut b = ReadCoordinator::open(&seam_path).expect("the round trip opens");
            assert_eq!(
                b.apply_verb_delta("acct", &seam_ref, VerbDelta::Archived),
                ProjectionOutcome::Current,
                "the archive half of the round trip must apply"
            );
            assert_eq!(
                b.apply_verb_delta("acct", &seam_ref, VerbDelta::Unarchived),
                ProjectionOutcome::Current,
                "the unarchive half of the round trip must apply"
            );
            assert_eq!(
                raw_header_mailbox(&seam_path, "acct", &seam_ref).as_deref(),
                Some(MAILBOX_INBOX),
                "the interleave's premise: E2 is genuinely back in the Inbox, visibly, before A \
                 applies"
            );
        });

        // A's window: E1 only. E2 is an absentee by A's (now stale) evidence.
        let fresh = a.refresh_reconcile("acct", &[e1], first_page(false)).unwrap();

        let after = raw_header_row(&path, "acct", &ref2);
        assert!(
            after.is_some(),
            "the ROUND-TRIPPED row must SURVIVE the older reconcile — the user unarchived it \
             after the decision was made, and EVERY message_header write in write_verb_delta \
             draws a fresh ingest_revision (#24-1b codex-r6 F2), whether it moves mailbox or \
             only flips a flag"
        );
        let (mailbox, _, revision_after) = after.unwrap();
        assert_eq!(mailbox, MAILBOX_INBOX, "and it stays where the user's unarchive put it");
        assert!(
            revision_after > before.2,
            "write_verb_delta must draw a fresh revision on EVERY message_header mutation: the \
             round trip must issue a revision strictly greater than the decided one ({}), never \
             leave it unchanged — got {revision_after}",
            before.2
        );
        assert_eq!(
            fresh.stale_below, 1,
            "a withdrawn verdict is an UNDECIDED row, and is reported as one"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }

    /// **A WITHDRAWN HEADER DELETE MUST WITHDRAW ITS PAIRED PLACEMENT
    /// ARCHIVE TOO.** The header DELETE at the top of the apply-phase pair is revision-guarded
    /// (/); this closes the SAME stale-verdict shape one statement later, on the
    /// placement half of the SAME pair (`read_coordinator.rs`'s apply-phase `for chunk` body:
    /// header DELETE, then `UPDATE message_placement ... SET placement = 'archive'`).
    ///
    /// THE INTERLEAVE: identical premise to the archive/unarchive round-trip test above (a round trip that leaves `mailbox`
    /// back at `'Inbox'` — matching what A's read phase saw — while `ingest_revision` has moved
    /// past the decided value). That test only asserted the HEADER row survived; it never checked
    /// the PLACEMENT row the very next statement in the same loop body touches. The pairing is
    /// `if removed == 0 { ...; continue; }` guarding the `UPDATE message_placement` beneath it —
    /// this test is the missing witness that the guard actually reaches the placement half, not
    /// just the header half: a stale-verdict pair that skips the DELETE must ALSO skip the
    /// UPDATE, or the store lands in the third state neither row's own doc allows (a placement
    /// row saying Archive over a header row still saying Inbox).
    #[test]
    fn a_withdrawn_header_delete_must_not_archive_the_paired_placement_row() {
        let (path, mut a) = coordinator("r7-f1-withdrawn-removal-placement-guard");
        let e1 = summary("E1", 200, "kept");
        let e2 = summary("E2", 100, "round tripped, revision advances past the decided value");
        let refs = a.ingest_page("acct", &[e1.clone(), e2.clone()]).unwrap();
        let ref2 = refs[1].clone();
        let before = raw_header_row(&path, "acct", &ref2).expect("E2 is local");

        // B, at the one instant that matters: the SAME archive/unarchive round trip r6_f2 drives
        // — `mailbox` ends back at `'Inbox'` (matching A's read-phase snapshot) while
        // `ingest_revision` has moved strictly past the value A decided against.
        let seam_path = path.to_path_buf();
        let seam_ref = ref2.clone();
        seam::arm_between_phases(move || {
            let mut b = ReadCoordinator::open(&seam_path).expect("the round trip opens");
            assert_eq!(
                b.apply_verb_delta("acct", &seam_ref, VerbDelta::Archived),
                ProjectionOutcome::Current,
                "the archive half of the round trip must apply"
            );
            assert_eq!(
                b.apply_verb_delta("acct", &seam_ref, VerbDelta::Unarchived),
                ProjectionOutcome::Current,
                "the unarchive half of the round trip must apply"
            );
        });

        // A's window: E1 only. E2 is an absentee by A's (now stale) evidence.
        let fresh = a.refresh_reconcile("acct", &[e1], first_page(false)).unwrap();

        // ANTI-VACUITY: the interleave really advanced the revision past what A decided against,
        // and the header DELETE really was withdrawn (the header row survives, per r6_f2).
        let after_header = raw_header_row(&path, "acct", &ref2);
        assert!(after_header.is_some(), "the round-tripped header row must SURVIVE");
        let (mailbox, _, revision_after) = after_header.unwrap();
        assert_eq!(mailbox, MAILBOX_INBOX, "and it stays where the round trip left it");
        assert!(
            revision_after > before.2,
            "the round trip must have advanced the revision strictly past the decided value \
             ({}) — otherwise the header DELETE's guard was never actually exercised here",
            before.2
        );

        // THE ACTUAL WITNESS: the paired placement row must NOT have been archived. A withdrawn
        // header DELETE (this row changed under the verdict) has no standing to run the
        // placement half of its own pair either — the same reasoning `read_coordinator.rs`'s own
        // doc gives for withdrawing the DELETE applies verbatim to the UPDATE beneath it.
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", &ref2).unwrap(),
            Some(Placement::Inbox),
            "a withdrawn header DELETE must withdraw the paired placement UPDATE too — the row \
             the round trip actually left (Inbox), never overwritten to Archive by a verdict \
             the header half already refused to apply"
        );
        drop(store);

        assert_eq!(
            fresh.stale_below, 1,
            "a withdrawn verdict is an UNDECIDED row, and is reported as one — exactly once, \
             not twice for the same pair"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }

    /// **A PLACEMENT-ONLY WRITER IN THE PHASE GAP MUST WITHDRAW THE
    /// VERDICT: THE CAS GAINS ITS THIRD COMPARE.** The header CAS (`mailbox` + `ingest_revision`,
    /// proves the HEADER row unchanged — and `record_optimistic_placement` /
    /// `correct_placement` never touch the header. Pre-fix, a correction committing between the
    /// verdict and the DELETE (here: provider truth moving the message BACK to Inbox over an
    /// optimistic Archive) left both header compares matching, so the header died and the UPDATE
    /// overwrote the racer's NEWER placement with Archive. Post-fix the decided-time placement
    /// value participates in the compare and the pair is withdrawn instead.
    ///
    /// The anti-vacuity half is the DISCRIMINATOR against the two tests above: the
    /// revision provably does NOT move here, so only the placement compare can be what withdrew
    /// the pair.
    #[test]
    fn a_placement_only_racer_in_the_phase_gap_withdraws_the_verdict() {
        let (path, mut a) = coordinator("r15-f1-placement-only-racer");
        let e1 = summary("E1", 200, "kept");
        let e2 = summary("E2", 100, "externally absent; placement corrected mid-reconcile");
        let refs = a.ingest_page("acct", &[e1.clone(), e2.clone()]).unwrap();
        let ref2 = refs[1].clone();
        let before = raw_header_row(&path, "acct", &ref2).expect("E2 is local");

        // The optimistic belief the reconcile will DECIDE against: a placement-only Archive
        // (a verb's optimism — the header row is untouched, `mailbox` stays 'Inbox').
        let mut store = SqliteMessageStore::open(&path).unwrap();
        let email_id = store
            .resolve_email_id("acct", &ref2)
            .unwrap()
            .expect("E2 carries its provider id");
        store
            .record_optimistic_placement("acct", &ref2, &email_id, Placement::Archive)
            .unwrap();

        // B, at the one instant that matters: provider truth corrects the placement BACK to
        // Inbox — a placement-ONLY write. `mailbox` and `ingest_revision` never move.
        let seam_path = path.to_path_buf();
        let seam_ref = ref2.clone();
        seam::arm_between_phases(move || {
            let mut b = SqliteMessageStore::open(&seam_path).expect("the corrector opens");
            let corrected = b
                .correct_placement("acct", &seam_ref, Placement::Inbox)
                .expect("the correction applies");
            assert!(corrected.changed, "the correction must be a real divergence fix");
        });

        // A's window: E1 only. E2 is an absentee by A's (now stale) evidence.
        let fresh = a.refresh_reconcile("acct", &[e1], first_page(false)).unwrap();

        // ANTI-VACUITY + the discriminator: the header row was NEVER touched — same mailbox,
        // same revision — so the header CAS alone could not have withdrawn this pair.
        let after_header = raw_header_row(&path, "acct", &ref2);
        assert!(
            after_header.is_some(),
            "the header row must SURVIVE — the verdict was stale the moment the placement moved"
        );
        let (mailbox, _, revision_after) = after_header.unwrap();
        assert_eq!(mailbox, MAILBOX_INBOX);
        assert_eq!(
            revision_after, before.2,
            "the racer is placement-ONLY — a moved revision would mean the r4 compare was \
             exercised instead of the r15 one this witness exists to prove"
        );

        // THE ACTUAL WITNESS: the corrector's newer Inbox placement stands — never overwritten
        // to Archive by a verdict decided against the superseded optimistic state.
        assert_eq!(
            store.placement("acct", &ref2).unwrap(),
            Some(Placement::Inbox),
            "a placement-only racer in the phase gap must withdraw the verdict, not be \
             clobbered by it"
        );
        drop(store);

        assert_eq!(
            fresh.stale_below, 1,
            "the withdrawn pair is reported as the one undecided row"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }

    /// **AN IDENTITY REBIND IN THE PHASE GAP MUST WITHDRAW THE
    /// VERDICT: the compare covers the placement row's COMPLETE non-key state.** The
    /// compare took the placement VALUE; a `record_optimistic_placement` rebinding the SAME
    /// ref to a DIFFERENT `email_id` while leaving `placement` unchanged slipped every
    /// predicate — and the reconcile then archived the newly rebound mapping on provider
    /// evidence gathered for the OLD identity. With `email_id` in the compare the set is
    /// {`email_id`, `placement`} — the whole non-key column set, derived from the schema, so
    /// there is no fourth field left to find.
    #[test]
    fn an_identity_rebind_in_the_phase_gap_withdraws_the_verdict() {
        let (path, mut a) = coordinator("r18-f1-identity-rebind-racer");
        let e1 = summary("E1", 200, "kept");
        let e2 = summary("E2", 100, "externally absent; identity rebound mid-reconcile");
        let refs = a.ingest_page("acct", &[e1.clone(), e2.clone()]).unwrap();
        let ref2 = refs[1].clone();
        let before = raw_header_row(&path, "acct", &ref2).expect("E2 is local");

        // B, at the one instant that matters: the SAME ref rebound to a DIFFERENT provider
        // identity, placement value unchanged — the write the value-compare cannot see.
        let seam_path = path.to_path_buf();
        let seam_ref = ref2.clone();
        seam::arm_between_phases(move || {
            let mut b = SqliteMessageStore::open(&seam_path).expect("the rebinder opens");
            b.record_optimistic_placement(
                "acct",
                &seam_ref,
                &ProviderMessageId("E2-rebound".to_string()),
                Placement::Inbox,
            )
            .expect("the rebind applies");
        });

        let fresh = a.refresh_reconcile("acct", &[e1], first_page(false)).unwrap();

        // ANTI-VACUITY + the discriminator: header untouched (same mailbox, same revision)
        // AND the placement VALUE unchanged — neither the nor the compare could have
        // withdrawn this pair; only the identity compare can be what did.
        let after_header = raw_header_row(&path, "acct", &ref2);
        assert!(after_header.is_some(), "the header row must SURVIVE the stale verdict");
        let (mailbox, _, revision_after) = after_header.unwrap();
        assert_eq!(mailbox, MAILBOX_INBOX);
        assert_eq!(revision_after, before.2, "the racer is placement-table-only");

        // THE ACTUAL WITNESS: the rebound mapping keeps its Inbox placement and its NEW
        // identity — never archived on evidence for the old one.
        let store = SqliteMessageStore::open(&path).unwrap();
        assert_eq!(
            store.placement("acct", &ref2).unwrap(),
            Some(Placement::Inbox),
            "a rebound mapping must not be archived on the old identity's evidence"
        );
        assert_eq!(
            store.resolve_email_id("acct", &ref2).unwrap(),
            Some(ProviderMessageId("E2-rebound".to_string())),
            "the rebind itself must have landed — otherwise this witness proved nothing"
        );
        drop(store);

        assert_eq!(
            fresh.stale_below, 1,
            "the withdrawn pair is reported as the one undecided row"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_reconcile_read_phase_decides_on_one_snapshot() {
        // THE INCOHERENT PAIR: phase 1's below-floor COUNT and its in-window materialization
        // used to be separate autocommit reads. A row can be BELOW the floor for the first and
        // ABOVE it for the second — `ingest_page` upserts `received_at` from the provider's own
        // answer, so a re-ingest at a corrected timestamp moves it across the boundary. Pre-fix
        // the reconcile then COUNTED that row as undecided (`stale_below`) AND, in the same
        // breath, decided it an absentee and DELETED it: two statements describing a store state
        // that never existed. Inside one `BEGIN DEFERRED` read transaction the second statement
        // sees what the first saw, and the row is simply below the floor.
        let (path, mut a) = coordinator("r4-f4-one-snapshot");
        let anchored = summary("E-ANCHOR", 100, "anchor");
        let victim = summary("E-VICTIM", 50, "below the floor");
        let refs = a
            .ingest_page("acct", &[anchored.clone(), victim.clone()])
            .unwrap();
        let victim_ref = refs[1].clone();

        // The competing write, at the instant between the COUNT and the materialization: the
        // same message re-ingested at a timestamp ABOVE the window floor.
        let seam_path = path.to_path_buf();
        seam::arm_in_read_phase(move || {
            let mut b = ReadCoordinator::open(&seam_path).expect("the competing writer opens");
            b.ingest_page("acct", &[summary("E-VICTIM", 300, "moved above the floor")])
                .expect("the competing re-ingest lands");
        });

        // A NON-exhausted first page — the arm that has a floor and therefore a COUNT.
        let fresh = a
            .refresh_reconcile(
                "acct",
                &[anchored],
                WindowAnchor::FirstPage {
                    raw_page_was_empty: false,
                    walk_exhausted: false,
                },
            )
            .unwrap();

        let after = raw_header_row(&path, "acct", &victim_ref);
        assert!(
            after.is_some(),
            "the row was COUNTED below the floor, so this phase did not decide it — it must not \
             also have been removed by the very same phase"
        );
        assert_eq!(
            fresh.stale_below, 1,
            "exactly one undecided row, counted exactly once: a phase that saw the row twice, \
             in two different states, would report it twice or remove it"
        );

        // ANTI-VACUITY: the injected re-ingest really committed — the row's timestamp DID move
        // above the floor, just not inside this phase's snapshot.
        assert_eq!(
            after.unwrap().1,
            300,
            "the competing write must be durable — otherwise the snapshot proved nothing"
        );
        drop(a);
        std::fs::remove_file(&path).ok();
    }
}
