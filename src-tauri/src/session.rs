//! The store side of the session: the handles behind the session mutex, and the page absorb.

use std::path::Path;

use aruna::message_header::{HeaderRow, SqliteMessageHeaderStore};
use aruna::message_store::SqliteMessageStore;
use aruna::read_coordinator::{Freshness, ReadCoordinator, WindowAnchor, MAILBOX_INBOX};
use aruna::read_surface::{ContinuationToken, HeaderSummary};
use aruna::{LogError, SqliteIntentLog};

use crate::error::SurfaceError;
use crate::ipc::{FreshnessView, PageCursor, RefreshOutcome, NO_COVERAGE_YET};

/// The store side of the session and nothing else.
///
/// This is the type the session mutex guards. It holds no transport, so no code path can hold
/// this lock and make a provider call; adding a transport handle to this struct would break
/// "the session lock covers store access only".
pub struct PhotonSession {
    pub(crate) coordinator: ReadCoordinator,
    pub(crate) headers: SqliteMessageHeaderStore,
    pub(crate) placements: SqliteMessageStore,
    /// What the last refresh re-checked. `None` until a refresh has run: the UI renders "never
    /// refreshed", never a fabricated all-fresh marker.
    pub(crate) last_freshness: Option<Freshness>,
    /// The store's own intent log, kept open so `session_status` has a live handle to
    /// `SqliteIntentLog::control_epoch`, the same singleton read every internal fence uses
    /// (`crates/aruna/src/lib.rs`). This handle never calls `sever`: the mutation boundary's own
    /// log (`GmailProvider.bus`) is the singleton's only writer.
    pub(crate) log: SqliteIntentLog,
    /// The provider's continuation from the most recent listing call. `None` when the provider
    /// said that was the last page, and until the first refresh has run.
    provider_cursor: Option<ProviderCursor>,
}

/// Where a fetched page sits in the provider's walk. This is the shell's two-state question,
/// kept separate from the coordinator's [`WindowAnchor`].
///
/// A caller knows only whether it asked for page 1 or spent a continuation token. What that
/// means for removal coverage has a fixed answer per arm: page 1 is the only window removal is
/// ever inferred from ([`PhotonSession::absorb_page`]). No command constructs a [`WindowAnchor`]
/// itself, so none can build one whose `raw_page_was_empty`/`walk_exhausted` disagree with the
/// page it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageAnchor {
    /// The provider was asked for page 1 (`continuation: None`).
    FirstPage,
    /// The provider was handed a continuation token.
    Continuation,
}

/// The transport's own two answers about the page it just read: the facts the mapped `rows`
/// slice cannot show and the shell must not re-derive ([`aruna::read_surface::ListedPage`]).
///
/// They travel in one value because two adjacent `bool` parameters read as `(…, false, true)` at
/// a call site, and swapping them would silently turn a conservative refresh into a wipe. The
/// safe value of both fields is `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PageFacts {
    /// Was the provider's own page empty, before this transport filtered anything out of it?
    pub(crate) raw_page_was_empty: bool,
    /// Did the page arrive ordered newest-first, so its `min(received_at)` is a real coverage
    /// floor?
    pub(crate) chronological: bool,
}

impl PageFacts {
    /// A well-ordered page: the ordinary case, for tests that are not about ordering.
    #[cfg(test)]
    pub(crate) fn chronological(raw_page_was_empty: bool) -> Self {
        Self {
            raw_page_was_empty,
            chronological: true,
        }
    }
}

/// A held provider continuation: the token, the account it belongs to, and the page size the
/// walk was started with.
///
/// The token is opaque and belongs to one provider walk, so the account travels with it and is
/// compared before the token is used (v1 is single-account, so this is defense in depth). The
/// page size is remembered because the continuation continues that walk: a token minted by a
/// 50-row page followed by a 200-row fetch is a window whose shape nobody chose, and the
/// reconcile that follows is window-scoped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderCursor {
    account: String,
    pub(crate) token: ContinuationToken,
    pub(crate) page_size: i64,
}

/// What `refresh_more_inbox` answers when no continuation is held: the walk is finished or was
/// never started. Named once so the refusal and its test quote the same sentence.
pub const NO_CONTINUATION_REASON: &str =
    "no provider continuation is held for this account — the last refresh reached the end of the \
     mailbox, or none has run yet. Refresh first; `has_more` on a refresh result says whether \
     there is another page to ask for.";

impl PhotonSession {
    pub(crate) fn open(store_path: &Path) -> Result<Self, String> {
        // The intent log owns the schema; every other handle opens over the file it created.
        let log = SqliteIntentLog::open(store_path)
            .map_err(|e| format!("cannot open the Photon store at {}: {e}", store_path.display()))?;
        Ok(Self {
            coordinator: ReadCoordinator::open(store_path)
                .map_err(|e| format!("cannot open the read coordinator: {e}"))?,
            headers: SqliteMessageHeaderStore::open(store_path)
                .map_err(|e| format!("cannot open the header store: {e}"))?,
            placements: SqliteMessageStore::open(store_path)
                .map_err(|e| format!("cannot open the placement store: {e}"))?,
            last_freshness: None,
            log,
            provider_cursor: None,
        })
    }

    /// Absorb one fetched provider page: ingest it, record the freshness the UI renders, and
    /// remember (or clear) the continuation it came with. A page-1 page also reconciles; a
    /// continuation does not.
    ///
    /// This is the store-side half of both refresh commands, which differ only in whether the page
    /// is a removal window. It is also the seam the tests reach through, since the commands need a
    /// `tauri::State` that has no constructor outside a running app.
    ///
    /// # Removal inference is page-1-window-scoped
    ///
    /// A continuation page is purely additive: it ingests, appends, advances the cursor and
    /// reconciles nothing, because its window covers only its own range. Widening that means
    /// accumulating the walk in the session (tried and dropped: reconciling a composed window never
    /// made the claim sound while the mailbox moves under a multi-minute walk) or using the
    /// provider's change cursor (Gmail `historyId` / JMAP `queryChanges`), which v1 lacks. The cost
    /// is visible staleness below the page-1 window: a row archived externally during the walk
    /// stays on screen until the next page-1 refresh, and the freshness marker says so. Deleting a
    /// row on a window that never looked at it would be worse.
    ///
    /// The cursor is replaced, never merged. A page-1 refresh restarts the walk; a continuation
    /// advances it; `next: None` clears it, since a stale token would offer a "load more" over a
    /// window that no longer exists.
    ///
    /// `facts` are the transport's own answers about the page ([`aruna::read_surface::ListedPage`])
    /// and are passed through unchanged. `rows` is filtered and possibly reordered, so it cannot
    /// distinguish an empty mailbox from a filtered-to-zero page, or a window from a shuffled
    /// slice. An empty page that still offers a continuation is a gap in the walk, not the end of
    /// the mailbox, so `raw_page_was_empty` is combined with `walk_exhausted` (derived from `next`)
    /// and wipes nothing.
    ///
    /// # A non-chronological page ingests but bounds nothing
    ///
    /// The reconcile's coverage floor is `min(received_at)` of the window, and every local row
    /// above it that the window omitted is deleted. That is sound only for a newest-first page, and
    /// Gmail's `messages.list` promises no order, so its transport verifies. An unverified page is
    /// still ingested in full but reconciles against an empty window ("this refresh re-checked
    /// nothing"), the same conservative arm a filtered-to-zero page takes. Nothing is removed, and
    /// the next well-ordered refresh clears the staleness.
    pub(crate) fn absorb_page(
        &mut self,
        account: &str,
        rows: &[HeaderSummary],
        next: Option<ContinuationToken>,
        anchor: PageAnchor,
        page_size: i64,
        facts: PageFacts,
    ) -> Result<RefreshOutcome, SurfaceError> {
        self.coordinator
            .ingest_page(account, rows)
            .map_err(SurfaceError::store)?;
        if anchor == PageAnchor::FirstPage {
            // Page-1-anchored, and page 1 only: coverage is open-ended above, and the
            // authoritative-empty answer is gated on the raw page and on the walk having ended.
            //
            // An out-of-order page reconciles as no coverage (an empty window with both
            // authoritative-empty gates shut), the same as the filtered-to-zero shape, so there is
            // one conservative arm. A raw-empty page keeps its authoritative-empty facts regardless
            // of the ordering claim, since an empty page has no rows to order; otherwise a Gmail
            // inbox that became empty (`chronological=false` always on Gmail) could never reconcile
            // to empty and stale rows would survive.
            let (window, window_anchor): (&[HeaderSummary], WindowAnchor) =
                if facts.chronological || facts.raw_page_was_empty {
                    (
                        rows,
                        WindowAnchor::FirstPage {
                            raw_page_was_empty: facts.raw_page_was_empty,
                            walk_exhausted: next.is_none(),
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
            let freshness = self
                .coordinator
                .refresh_reconcile(account, window, window_anchor)
                .map_err(SurfaceError::store)?;
            self.last_freshness = Some(freshness);
        }
        self.provider_cursor = next.map(|token| ProviderCursor {
            account: account.to_string(),
            token,
            page_size,
        });
        Ok(RefreshOutcome {
            // The coverage claim is the last page-1 refresh's, verbatim: a continuation decided
            // nothing, so it neither widens nor shrinks it. `NO_COVERAGE_YET` is unreachable in
            // practice, since a cursor only exists after a page-1 absorb set this.
            freshness: self
                .last_freshness
                .as_ref()
                .map(FreshnessView::from)
                .unwrap_or(NO_COVERAGE_YET),
            ingested: rows.len(),
            has_more: self.provider_cursor.is_some(),
        })
    }

    /// The held continuation for `account`, or the typed refusal that says there is none.
    ///
    /// A [`SurfaceError::Refused`] rather than a new wire variant: the renderer's signal for
    /// "there is another page" is [`RefreshOutcome::has_more`], so this refusal is defense in
    /// depth against being called anyway, not a state the UI branches on.
    pub(crate) fn continuation_for(&self, account: &str) -> Result<ProviderCursor, SurfaceError> {
        match &self.provider_cursor {
            Some(cursor) if cursor.account == account => Ok(cursor.clone()),
            // Terminal: this is defense in depth against a call the UI's `has_more` should already
            // prevent, and retrying the identical call cannot change the outcome (a new page
            // fetch, not a retry, sets a fresh cursor).
            _ => Err(SurfaceError::Refused {
                reason: NO_CONTINUATION_REASON.to_string(),
                terminal: true,
            }),
        }
    }
}

/// One local keyset page plus a cursor that is only minted when a next page is proven to exist.
///
/// Reading `rows.len() == limit` as "there is more" fires at every exact multiple of `limit`
/// whether or not the store holds another row, since the page length cannot distinguish the two.
/// A fabricated cursor costs a keypress: `loadNextPage` spends it on a genuinely empty local page
/// instead of falling through to the provider fetch.
///
/// So the query asks for one row of lookahead (`limit + 1`). If the `limit + 1`th row came back,
/// a next page exists and the cursor is the `(received_at, message_ref)` of the last row of the
/// `limit`-sized page actually returned (not the lookahead row, which is always dropped).
/// Otherwise `rows.len() <= limit` and the cursor is `None`.
pub(crate) fn local_page_with_lookahead(
    headers: &SqliteMessageHeaderStore,
    account: &str,
    cursor: Option<&PageCursor>,
    limit: i64,
) -> Result<(Vec<HeaderRow>, Option<PageCursor>), LogError> {
    let mut rows = match cursor {
        None => headers.folder_first_page(account, MAILBOX_INBOX, limit + 1),
        Some(c) => {
            headers.folder_next_page(account, MAILBOX_INBOX, c.received_at, &c.message_ref, limit + 1)
        }
    }?;

    let next_cursor = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        let last = &rows[rows.len() - 1];
        Some(PageCursor {
            received_at: last.received_at,
            message_ref: last.message_ref.clone(),
        })
    } else {
        None
    };
    Ok((rows, next_cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use crate::tests::fixtures::{inbox_refs, page_row, session_for};

    // ===========================================================================================
    // THE PROVIDER CURSOR SURVIVES, SO OLDER MAIL CAN BE INGESTED.
    //
    // `refresh_inbox` fetched page 1 and threw the continuation away (`let (rows, _next)`), so a
    // mailbox bigger than one provider page could never ingest past its newest page — refreshing
    // again just re-fetches page 1. Tested at the SYNC SEAM both refresh commands now share
    // ([`PhotonSession::absorb_page`] / [`PhotonSession::continuation_for`]), for the same reason
    // every other witness in this file is: `tauri::State` has no constructor outside a running app.
    // ===========================================================================================

    /// The guarded-path form: a REAL store opened on a guarded path
    /// The file family a session actually creates — is gone once the state and then the guard
    /// drop, siblings included.
    #[test]
    fn h4_a_store_guard_removes_the_store_and_its_siblings_once_it_drops() {
        let path;
        {
            let (store, state, session) = session_for("h4-guard-witness");
            path = store.to_path_buf();
            assert!(path.exists(), "precondition: the session created the store");
            drop(session);
            drop(state);
        }
        assert!(!path.exists(), "the store must be gone once the guard drops: {}", path.display());
        for suffix in ["-wal", "-shm", ".photon-init.lock"] {
            let sibling = PathBuf::from(format!("{}{suffix}", path.display()));
            assert!(!sibling.exists(), "the {suffix} sibling must be gone once the guard drops");
        }
    }

    #[test]
    fn a_page_one_refresh_keeps_the_provider_continuation_and_reports_has_more() {
        let (path, _state, session) = session_for("cursor-armed");
        let mut guard = session.lock().expect("session lock");

        let outcome = guard
            .absorb_page(
                "acct",
                &[page_row("E100", 100), page_row("E090", 90)],
                Some(ContinuationToken("TOK-2".to_string())),
                PageAnchor::FirstPage,
                50,
                PageFacts::chronological(false),
            )
            .expect("a page-1 absorb writes and reconciles");

        assert!(
            outcome.has_more,
            "the provider handed back a continuation — the session must SAY there is more, not \
             silently drop the token"
        );
        let cursor = guard
            .continuation_for("acct")
            .expect("the cursor is held for the account it came from");
        assert_eq!(cursor.token, ContinuationToken("TOK-2".to_string()));
        assert_eq!(
            cursor.page_size, 50,
            "the walk's own page size rides with the token — a continuation continues THAT walk"
        );
        match guard.continuation_for("someone-elses-partition") {
            Err(SurfaceError::Refused { reason, .. }) => assert_eq!(reason, NO_CONTINUATION_REASON),
            other => panic!("a token belongs to ONE account's walk: {other:?}"),
        }

        drop(guard);
        std::fs::remove_file(&path).ok();
    }

    /// A raw-empty page 1 that STILL OFFERS A CONTINUATION is not the
    /// empty inbox, and must wipe nothing.
    ///
    /// "The provider's newest page came back empty" only says the mailbox is empty when that page
    /// was also the WHOLE walk. Both live listing routes can answer an empty page while handing
    /// back a continuation token (Gmail's `messages.list` returns `nextPageToken` alongside an
    /// absent `messages` array; JMAP's `Email/query` answers `ids: []` while `total` still exceeds
    /// the position). That is NO COVERAGE — the rows are further down the walk — and the wipe rule
    /// read it as an answer, deleting the entire local projection.
    #[test]
    fn a_raw_empty_page_one_that_still_offers_a_continuation_wipes_nothing() {
        let (path, _state, session) = session_for("empty-with-continuation");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E100", 100), labeled_row("E090", 90)],
                    None,
                    PageAnchor::FirstPage,
                    50,
                    PageFacts::chronological(false),
                )
                .expect("page 1");
        }
        assert_eq!(inbox_subjects(&session).len(), 2, "two rows are local");

        // The provider's OWN page was empty — and it handed back a token for the next one.
        let outcome = {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[],
                    Some(ContinuationToken("TOK-2".to_string())),
                    PageAnchor::FirstPage,
                    50,
                    PageFacts::chronological(true),
                )
                .expect("an empty page still absorbs")
        };

        assert_eq!(
            inbox_subjects(&session).len(),
            2,
            "an empty page with a continuation pending covers NOTHING — the walk is not finished, \
             so the local projection must stand"
        );
        assert_eq!(
            outcome.freshness.stale_below, 2,
            "and both rows are reported honestly as un-checked"
        );
        assert!(outcome.has_more, "the token is held: the walk continues");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn refresh_more_with_no_cursor_held_is_a_typed_refusal_before_any_round_trip() {
        let (path, _state, session) = session_for("cursor-absent");
        let mut guard = session.lock().expect("session lock");

        // A session that has never refreshed holds nothing.
        match guard.continuation_for("acct") {
            Err(SurfaceError::Refused { reason, .. }) => {
                assert_eq!(reason, NO_CONTINUATION_REASON);
                assert!(reason.contains("Refresh first"), "the refusal says what to do: {reason}");
            }
            other => panic!("no cursor must be a TYPED refusal, never a fetch of page 1: {other:?}"),
        }

        // A refresh whose page was the LAST page clears the door again: `next: None` is the
        // provider saying there is nothing after this, and a stale token would offer a walk that
        // no longer exists.
        let outcome = guard
            .absorb_page("acct", &[page_row("E100", 100)], None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
            .expect("absorb");
        assert!(!outcome.has_more, "no token ⇒ no more");
        assert!(guard.continuation_for("acct").is_err());

        drop(guard);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_continuation_page_appends_older_rows_and_never_removes_the_page_above_it() {
        let (path, _state, session) = session_for("cursor-interior");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[page_row("E100", 100), page_row("E090", 90)],
                    Some(ContinuationToken("TOK-2".to_string())),
                    PageAnchor::FirstPage,
                    2,
                    PageFacts::chronological(false),
                )
                .expect("page 1");
        }
        assert_eq!(inbox_refs(&session).len(), 2, "page 1 ingested");

        let outcome = {
            let mut guard = session.lock().expect("session lock");
            let cursor = guard.continuation_for("acct").expect("the cursor is armed");
            assert_eq!(cursor.token, ContinuationToken("TOK-2".to_string()));
            guard
                .absorb_page(
                    "acct",
                    &[page_row("E080", 80), page_row("E070", 70)],
                    Some(ContinuationToken("TOK-3".to_string())),
                    // THE ANCHOR IS THE SAFETY PROPERTY: a continuation is not a removal window
                    // at all. Under `FirstPage` this same call would treat the two page-1 rows
                    // above it as externally gone and DELETE them.
                    PageAnchor::Continuation,
                    2,
                    PageFacts::chronological(false),
                )
                .expect("page 2")
        };

        assert_eq!(
            inbox_refs(&session).len(),
            4,
            "the continuation page APPENDS: two page-1 rows above it survive an Interior-anchored \
             reconcile, and the two older rows are now local"
        );
        assert!(outcome.has_more, "the provider offered a third page");
        assert_eq!(
            session
                .lock()
                .expect("session lock")
                .continuation_for("acct")
                .expect("armed")
                .token,
            ContinuationToken("TOK-3".to_string()),
            "the stored cursor ADVANCES with the walk — a cursor that stayed on TOK-2 would refetch \
             the same page forever"
        );

        std::fs::remove_file(&path).ok();
    }

    /// The same row shape, but with the provider id written into the SUBJECT so a projection read
    /// can name which rows survived (minted refs are random by design).
    fn labeled_row(id: &str, received_at: i64) -> HeaderSummary {
        let mut row = page_row(id, received_at);
        row.subject = id.to_string();
        row
    }

    fn inbox_subjects(session: &Arc<Mutex<PhotonSession>>) -> Vec<String> {
        session
            .lock()
            .expect("session lock")
            .headers
            .folder_first_page("acct", MAILBOX_INBOX, 100)
            .expect("read the projection")
            .into_iter()
            .map(|r| r.subject)
            .collect()
    }

    /// THE v1 CONTRACT for a continuation: it INGESTS AND
    /// APPENDS, and it removes NOTHING.
    ///
    /// Removal inference is page-1-window-scoped, full stop. A continuation page covers only its
    /// own range, and the only ways to widen that honestly are (a) accumulating the walk in the
    /// session — mid-loop machinery, deleted — or (b) the provider's own change cursor
    /// (Gmail `historyId` / JMAP `queryChanges`), which would be the wholesale close and is
    /// NOT in v1. So a row the tie rule deferred at page 1's floor SURVIVES the
    /// continuation: it is visible-stale by design, and the next page-1 refresh (or the cursor
    /// sync) is what decides it. Staleness the freshness marker reports is the honest answer; a
    /// removal the window never covered is not.
    #[test]
    fn a_continuation_page_ingests_and_appends_and_never_removes_a_local_row() {
        let (path, _state, session) = session_for("walk-contiguous");

        // Page 1: three rows, the OLDEST TWO sharing timestamp 80 — the page break falls inside
        // that timestamp.
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[
                        labeled_row("E100", 100),
                        labeled_row("E080", 80),
                        labeled_row("E080b", 80),
                    ],
                    Some(ContinuationToken("TOK-2".to_string())),
                    PageAnchor::FirstPage,
                    3,
                    PageFacts::chronological(false),
                )
                .expect("page 1");
        }
        assert_eq!(inbox_subjects(&session).len(), 3, "page 1 ingested");

        // A fresh page-1 refresh: E080b was archived externally, so page 1 no longer returns it.
        // It sits exactly ON the floor timestamp, so the tie rule DEFERS it — kept, undecided.
        {
            let mut guard = session.lock().expect("session lock");
            let outcome = guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E100", 100), labeled_row("E080", 80)],
                    Some(ContinuationToken("TOK-2".to_string())),
                    PageAnchor::FirstPage,
                    3,
                    PageFacts::chronological(false),
                )
                .expect("page 1 again");
            assert_eq!(
                outcome.freshness.stale_below, 1,
                "the equal-timestamp absentee is deferred, not removed — that is the r1 F2 rule"
            );
        }
        assert!(
            inbox_subjects(&session).contains(&"E080b".to_string()),
            "the deferred row is still local at this point, by design"
        );

        // The continuation. Its own rows start BELOW the tie — and it decides NOTHING about the
        // deferred row, because its window never covered it.
        let outcome = {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E070", 70)],
                    None,
                    PageAnchor::Continuation,
                    3,
                    PageFacts::chronological(false),
                )
                .expect("page 2")
        };

        let mut after = inbox_subjects(&session);
        after.sort();
        assert_eq!(
            after,
            vec!["E070", "E080", "E080b", "E100"],
            "the continuation APPENDED its own row and removed nothing — the tie-deferred row is \
             visible-stale, not deleted on a window that never looked at it"
        );
        assert_eq!(
            outcome.freshness.stale_below, 1,
            "the coverage claim is still PAGE 1's, verbatim: the continuation widened no window, \
             so it may not shrink the staleness page 1 reported either"
        );
        assert_eq!(
            outcome.freshness.checked_through.as_ref().map(|c| c.received_at),
            Some(80),
            "and `checked_through` stays page 1's floor — a continuation makes no new claim"
        );

        std::fs::remove_file(&path).ok();
    }

    /// At the SHELL boundary: a page the provider did NOT return
    /// newest-first must not drive removals.
    ///
    /// The coordinator's page-1 reconcile takes `min(received_at)` of the window as its coverage
    /// floor and deletes every local row above that floor the window omitted. That is only sound
    /// on a page that IS newest-first, and Gmail's `messages.list` promises no sort order (see
    /// `aruna-gmail`'s own witness). Fed a scrambled page, the floor lands mid-mailbox and the
    /// valid rows between it and the real newest row are deleted — mail on screen, gone, with no
    /// provider event behind it.
    ///
    /// Ordering is a property of ROWS — an EMPTY page has none, so a raw-empty,
    /// walk-exhausted answer keeps its authoritative-empty facts even from the Gmail arm (which
    /// reports `chronological: false` unconditionally). Without this, a Gmail inbox that became
    /// empty could never reconcile to empty and stale local rows survived every refresh.
    #[test]
    fn a_raw_empty_non_chronological_page_one_still_reconciles_the_empty_inbox() {
        let (path, _state, session) = session_for("raw-empty-non-chrono");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E100", 100), labeled_row("E090", 90)],
                    None,
                    PageAnchor::FirstPage,
                    50,
                    PageFacts::chronological(false),
                )
                .expect("seed page");
        }
        assert_eq!(inbox_subjects(&session).len(), 2, "two rows are local");

        // The provider now answers an EMPTY page-1 with NO continuation — the whole inbox was
        // externally emptied. The Gmail arm marks it non-chronological like every Gmail page.
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[],
                    None,
                    PageAnchor::FirstPage,
                    50,
                    PageFacts {
                        raw_page_was_empty: true,
                        chronological: false,
                    },
                )
                .expect("the authoritative empty page");
        }
        assert_eq!(
            inbox_subjects(&session).len(),
            0,
            "a raw-empty exhausted page IS the empty inbox — ordering is irrelevant with no rows"
        );
        drop(session);
        let _ = std::fs::remove_file(&path);
    }

    /// The conservative arm is the SAME one a filtered-to-zero page already takes (the test right
    /// below): the page ingests in full, and the reconcile is handed NO coverage — nothing removed,
    /// every local row reported honestly as un-checked.
    #[test]
    fn an_out_of_order_page_one_ingests_but_removes_nothing() {
        let (path, _state, session) = session_for("non-chronological");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[
                        labeled_row("E100", 100),
                        labeled_row("E090", 90),
                        labeled_row("E080", 80),
                    ],
                    None,
                    PageAnchor::FirstPage,
                    50,
                    PageFacts::chronological(false),
                )
                .expect("page 1");
        }
        assert_eq!(inbox_subjects(&session).len(), 3, "three rows are local");

        // The provider answers page 1 again — this time NOT newest-first, and page-sized at two,
        // so E090 is simply further down the walk. Its `min` is 80: read as a floor, it condemns
        // E090 (90 > 80, absent from the window).
        let outcome = {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E080", 80), labeled_row("E100", 100)],
                    Some(ContinuationToken("TOK-2".to_string())),
                    PageAnchor::FirstPage,
                    2,
                    PageFacts {
                        raw_page_was_empty: false,
                        chronological: false,
                    },
                )
                .expect("an out-of-order page still absorbs")
        };

        let mut subjects = inbox_subjects(&session);
        subjects.sort();
        assert_eq!(
            subjects,
            vec!["E080".to_string(), "E090".to_string(), "E100".to_string()],
            "an out-of-order page bounds no coverage range — it may not delete a local row"
        );
        assert_eq!(
            outcome.ingested, 2,
            "the rows themselves are real mail and are ingested in full"
        );
        assert_eq!(
            outcome.freshness.checked_through, None,
            "…and the coverage claim is honest: this window re-checked nothing"
        );
        assert_eq!(
            outcome.freshness.stale_below, 3,
            "every local row is reported un-checked rather than silently decided"
        );

        std::fs::remove_file(&path).ok();
    }

    /// At the SHELL boundary: the transport's raw-page answer is what the wipe rule
    /// sees, and `rows.is_empty()` is not it. Both arms in one test, because the whole point is
    /// that they differ while the `rows` slice is byte-identical.
    #[test]
    fn a_filtered_to_zero_page_one_keeps_the_local_rows_and_a_raw_empty_one_clears_them() {
        let (path, _state, session) = session_for("raw-vs-filtered");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E100", 100), labeled_row("E090", 90)],
                    None,
                    PageAnchor::FirstPage,
                    50,
                    PageFacts::chronological(false),
                )
                .expect("page 1");
        }
        assert_eq!(inbox_subjects(&session).len(), 2, "two rows are local");

        // The provider returned a page; every row of it was filtered out above this call.
        let outcome = {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page("acct", &[], None, PageAnchor::FirstPage, 50, PageFacts::chronological(false))
                .expect("a filtered-to-zero page still absorbs")
        };
        assert_eq!(
            inbox_subjects(&session).len(),
            2,
            "a filtered-to-zero page decides nothing — the local projection stands"
        );
        assert_eq!(
            outcome.freshness.stale_below, 2,
            "and both rows are reported honestly as un-checked"
        );

        // The provider's own page was empty: that IS the empty inbox.
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page("acct", &[], None, PageAnchor::FirstPage, 50, PageFacts::chronological(true))
                .expect("a raw-empty page absorbs");
        }
        assert!(
            inbox_subjects(&session).is_empty(),
            "a RAW-empty page 1 is the empty inbox and clears every local row"
        );

        std::fs::remove_file(&path).ok();
    }

    /// At the seam that could re-grow the machinery: `absorb_page` holds NO
    /// walk state, so nothing about a continuation depends on how many pages preceded it.
    ///
    /// The deleted shape accumulated every row fetched since the last page-1 refresh and
    /// reconciled the composed window as page-1-anchored. It needed a memory cap, an account
    /// guard, a fold of every page's raw-emptiness, and a conservative fallback for the
    /// past-the-cap case — four mechanisms to make a claim (that the composed window still
    /// reflects the mailbox) that a moving mailbox does not support anyway. This test pins the
    /// property the deletion bought: continuation after continuation, the local projection only
    /// ever GROWS.
    #[test]
    fn continuation_after_continuation_only_ever_grows_the_local_projection() {
        let (path, _state, session) = session_for("walk-additive");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[labeled_row("E100", 100)],
                    Some(ContinuationToken("TOK-2".to_string())),
                    PageAnchor::FirstPage,
                    1,
                    PageFacts::chronological(false),
                )
                .expect("page 1");
        }

        for (i, ts) in [90i64, 80, 70, 60].into_iter().enumerate() {
            let mut guard = session.lock().expect("session lock");
            let outcome = guard
                .absorb_page(
                    "acct",
                    &[labeled_row(&format!("E0{ts}"), ts)],
                    Some(ContinuationToken(format!("TOK-{}", i + 3))),
                    PageAnchor::Continuation,
                    1,
                    PageFacts::chronological(false),
                )
                .expect("continuation");
            assert_eq!(outcome.ingested, 1, "the page reports what IT carried into the store");
            assert_eq!(
                outcome.freshness.checked_through.as_ref().map(|c| c.received_at),
                Some(100),
                "and never revises page 1's coverage claim, however deep the walk goes"
            );
        }

        assert_eq!(
            inbox_subjects(&session).len(),
            5,
            "five pages in, five rows local — a continuation has no way to remove one"
        );

        // An empty continuation, RAW-empty, at the end of the walk: still not a wipe, because a
        // continuation is not a removal window at all.
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page("acct", &[], None, PageAnchor::Continuation, 1, PageFacts::chronological(true))
                .expect("an empty tail page");
        }
        assert_eq!(
            inbox_subjects(&session).len(),
            5,
            "the empty-inbox answer belongs to page 1 alone — an empty TAIL says only that the              walk ran out"
        );

        std::fs::remove_file(&path).ok();
    }

    /// `rows.len() == limit` fabricates a cursor at every EXACT
    /// multiple of `limit`, not just when a next page truly exists.
    ///
    /// The local store holds EXACTLY `limit` rows and nothing more. The earlier arithmetic could
    /// not tell that apart from "there happen to be at least `limit + 1`": it read the returned
    /// page's length alone and minted a cursor whenever that length hit the boundary. Spending that
    /// cursor (`loadNextPage`) would query a next page that comes back EMPTY — a keypress burned on
    /// nothing, instead of falling through to the provider fetch that would have found more mail.
    #[test]
    fn a_local_page_at_exactly_the_limit_mints_no_cursor_but_proves_one_more_row() {
        let (path, _state, session) = session_for("lookahead-cursor");
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[page_row("E100", 100), page_row("E090", 90)],
                    None,
                    PageAnchor::FirstPage,
                    2,
                    PageFacts::chronological(false),
                )
                .expect("seed exactly `limit` (2) local rows");
        }

        {
            let guard = session.lock().expect("session lock");
            let (rows, cursor) = local_page_with_lookahead(&guard.headers, "acct", None, 2)
                .expect("a local read never touches the provider");
            assert_eq!(rows.len(), 2, "every seeded row is still returned");
            assert!(
                cursor.is_none(),
                "the store holds EXACTLY `limit` rows — there is no proven next row, so no cursor \
                 may be minted (the pre-fix RED: this used to be `Some(..)`)"
            );
        }

        // Now the mailbox genuinely holds one more row than the page size: the lookahead row PROVES
        // a next page, and only now is a cursor minted — over the same `limit`, on the LIMIT-sized
        // page actually returned (the lookahead row itself is dropped, not handed to the caller).
        {
            let mut guard = session.lock().expect("session lock");
            guard
                .absorb_page(
                    "acct",
                    &[page_row("E100", 100), page_row("E090", 90), page_row("E080", 80)],
                    None,
                    PageAnchor::Continuation,
                    2,
                    PageFacts::chronological(false),
                )
                .expect("append the proving row without touching the FirstPage removal window");
        }
        {
            let guard = session.lock().expect("session lock");
            let (rows, cursor) = local_page_with_lookahead(&guard.headers, "acct", None, 2)
                .expect("a local read never touches the provider");
            assert_eq!(rows.len(), 2, "the page returned is still exactly `limit` rows");
            assert_eq!(
                rows.last().map(|r| r.received_at),
                Some(90),
                "the lookahead row (received_at 80) is dropped from the returned page"
            );
            match cursor {
                Some(c) => assert_eq!(
                    c,
                    PageCursor { received_at: 90, message_ref: rows[1].message_ref.clone() },
                    "the cursor names the last row of the RETURNED page, not the lookahead row"
                ),
                None => panic!("a genuinely proven next row must mint a cursor"),
            }
        }

        std::fs::remove_file(&path).ok();
    }
}
