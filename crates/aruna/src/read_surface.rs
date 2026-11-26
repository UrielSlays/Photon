//! Shared transport read-surface vocabulary: the types `GmailTransport::list_inbox_page`/
//! `fetch_body` and `JmapTransport::list_inbox_page`/`fetch_body` return, plus the engine-side
//! page-size clamp both traits' `list_inbox_page` share. `pub` because the shell consumes these
//! types directly.
//!
//! Provider-neutral: the only identity field is [`crate::read_model::ProviderMessageId`] (opaque
//! text), never a Gmail/JMAP-native handle, the same confinement `crate::gmail`/`crate::jmap`
//! already enforce on their own connector error codes.
//!
//! Every type here derives `Serialize`/`Deserialize`, since these values cross IPC in the shell
//! and deriving them now avoids retrofitting a wire format onto a type the engine has committed
//! to.

use serde::{Deserialize, Serialize};

use crate::read_model::ProviderMessageId;

/// One inbox row's identity, header fields and state flags: the unit `list_inbox_page` returns,
/// newest first. `provider_id` is the opaque [`ProviderMessageId`], never a Gmail/JMAP-native
/// handle. `seen`/`flagged` are the provider-neutral state flags both providers answer with in
/// the very call that lists (Gmail `labelIds` UNREAD/STARRED; JMAP `keywords` `$seen`/`$flagged`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeaderSummary {
    pub provider_id: ProviderMessageId,
    pub received_at: i64,
    pub from_addr: String,
    pub from_name: String,
    pub subject: String,
    pub seen: bool,
    pub flagged: bool,
    pub attachments: AttachmentPresence,
}

/// An opaque provider-issued page cursor (Gmail `nextPageToken`, JMAP `position`/anchor),
/// round-tripped as text and handed back to the same transport's next `list_inbox_page` call. The
/// engine never parses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuationToken(pub String);

/// One `list_inbox_page` answer: the mapped page, the continuation, and whether the provider's
/// page was empty before this transport filtered it.
///
/// # Why `raw_page_was_empty` cannot be derived
///
/// `rows` is the mapped page, and both transports legitimately drop rows on the way to it: Gmail
/// skips a message whose per-id metadata get no longer says `INBOX`, and JMAP skips an id its
/// `Email/get` half did not answer for or whose `mailboxIds` no longer carries the inbox. So
/// `rows.is_empty()` answers two different questions with one bit: "the mailbox page was empty"
/// and "every row of a nonempty page was filtered out". The read coordinator's window reconcile
/// treats the first as an authoritative empty inbox and deletes every local row
/// (`ReadCoordinator::refresh_reconcile`); doing that on the second would wipe a live projection
/// over a filter. Only the transport saw the provider's own id list, so it reports the fact here.
/// `raw_page_was_empty: false` is always the safe value (a conservative, no-removal reconcile).
///
/// # Why `chronological` exists
///
/// The window reconcile takes `min(received_at)` of the page as its coverage floor and removes
/// every local row above that floor the page omitted, an inference that is sound only if the page
/// is ordered newest-first. JMAP's is, by contract (the query carries an explicit `receivedAt
/// desc` sort). Gmail's `users.messages.list` documents no order, so its transport verifies the
/// mapped page instead of assuming it. A page that fails the check still carries real mail and
/// still ingests, but it is not a window, and reconciling it as one would delete live rows that
/// were merely further down a scrambled walk. `chronological: false` is the safe value: it costs
/// a conservative no-coverage reconcile (nothing removed, honest staleness), which the next
/// well-ordered page clears.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListedPage {
    pub rows: Vec<HeaderSummary>,
    pub next: Option<ContinuationToken>,
    pub raw_page_was_empty: bool,
    pub chronological: bool,
}

/// Attachment presence only: never bytes, never filenames (no attachment bytes cross any
/// boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttachmentPresence {
    pub has_attachments: bool,
    pub count: u32,
}

/// One message's raw body as the transport read it, size-capped at the transport boundary. A
/// genuinely absent textual body is `text: None, html: None`, never fabricated as an empty string.
///
/// Truncation is tracked per representation. `text_truncated`/`html_truncated` name which
/// representation the transport clipped, independently: a single shared flag would report a
/// complete short `text/plain` as truncated because its `text/html` sibling was clipped.
/// `to_body_view` (`crate::body_view`) propagates only the flag of the representation it selected,
/// and its post-conversion cap is ORed in on top.
///
/// This is the transport-to-engine type, not the IPC-facing `BodyView`. Keeping `html` out of the
/// type that crosses IPC is structural: the conversion boundary that drops this field lives above
/// this trait seam.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawBody {
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: AttachmentPresence,
    pub text_truncated: bool,
    pub html_truncated: bool,
}

/// The engine-side hard clamp on a caller-requested `list_inbox_page` page size, `(min, max)`
/// inclusive. A transport never sees a request wider than this, however the caller asked.
pub const PAGE_SIZE_CLAMP: (i64, i64) = (1, 200);

/// Clamp a caller-requested page size into [`PAGE_SIZE_CLAMP`]. This is the one place a
/// `list_inbox_page` caller's requested size is bounded before it reaches a transport.
pub fn clamp_page_size(requested: i64) -> i64 {
    requested.clamp(PAGE_SIZE_CLAMP.0, PAGE_SIZE_CLAMP.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_page_size_floors_a_non_positive_request_at_the_minimum() {
        assert_eq!(clamp_page_size(0), PAGE_SIZE_CLAMP.0);
        assert_eq!(clamp_page_size(0), 1);
    }

    #[test]
    fn clamp_page_size_ceilings_an_oversize_request_at_the_maximum() {
        assert_eq!(clamp_page_size(5000), PAGE_SIZE_CLAMP.1);
        assert_eq!(clamp_page_size(5000), 200);
    }

    #[test]
    fn clamp_page_size_passes_through_an_in_range_request_unchanged() {
        assert_eq!(clamp_page_size(50), 50);
    }
}
