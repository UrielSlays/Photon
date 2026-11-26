//! The engine-side body conversion boundary: raw HTML is dropped here.
//!
//! [`crate::read_surface::RawBody`] is the transport-to-engine type and carries
//! `html: Option<String>`. [`BodyView`](crate::body_view::BodyView) crosses IPC and has no `html`
//! field, so "no raw HTML reaches the renderer" holds structurally (the field does not exist to
//! be populated), not by a convention a later edit could break.
//!
//! The converter is `html2text` (html5ever-backed), version-pinned in `crates/aruna/Cargo.toml`
//! with a RustSec advisory check recorded in the commit that added it. The transport-boundary cap
//! is not sufficient on its own, since a small HTML source can expand under conversion, so the cap
//! is re-applied after conversion here.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde::{Deserialize, Serialize};

use crate::read_surface::{AttachmentPresence, RawBody};

/// The wrap width, in columns, handed to `html2text`'s plain-text renderer. It is a named
/// constant because it is a rendering decision the shell must not influence: a renderer-supplied
/// width would let a hostile webview drive the converter's layout path.
pub const RENDER_WIDTH_COLS: usize = 80;

/// Whether a message has a textual body at all: the third state, so a truly absent body renders
/// as an explicit "no textual body" and never as a blank that lies. An empty
/// [`BodyView::plain_text`] is not how absence is expressed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BodyAvailability {
    /// The message has a textual body, already converted, capped, and HTML-free.
    Text(BodyView),
    /// The message has neither a `text/plain` nor a `text/html` part.
    ///
    /// It still carries attachment presence. Attachment-only mail (the ordinary "here are the
    /// files" message) lands here, and a payload-free variant would drop the one fact the message
    /// has: the reading pane would show "no textual body" over a message whose whole content is
    /// its attachments. Presence is carried on the absence arm so the presence line renders on
    /// both arms from the same field name.
    NoTextualBody { attachments: AttachmentPresence },
}

/// One message's body as it crosses IPC, plain text only.
///
/// There is no `html` field on this type and there must never be one. Tests in
/// `crates/aruna/src/body_view.rs` assert the serialized field set exactly, so a field addition
/// fails a test instead of silently widening the surface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BodyView {
    pub plain_text: String,
    pub truncated: bool,
    pub attachments: AttachmentPresence,
}

/// A conversion that did not produce text. It is payload-free beyond a short static reason:
/// converter internals, and therefore body-derived substrings, must not travel in an error string
/// into a log (logs, traces and error strings are prohibited body sinks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyViewError {
    /// `html2text` returned `Err` (its `Error` enum: `TooNarrow` / `CssParseError` / `Fail` /
    /// `IoError`). The variant is not carried, being converter-internal vocabulary.
    ConversionFailed,
    /// The converter unwound on this input and the unwind was contained here. A parser fed
    /// untrusted remote bytes must not be able to take the process with it.
    ConversionPanicked,
}

impl fmt::Display for BodyViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyViewError::ConversionFailed => f.write_str("html-to-text conversion failed"),
            BodyViewError::ConversionPanicked => f.write_str("html-to-text conversion panicked"),
        }
    }
}

impl std::error::Error for BodyViewError {}

/// Convert a transport-read [`RawBody`] into the IPC-facing [`BodyAvailability`].
///
/// - `text` present: used as-is; any `html` sibling is ignored, never merged.
/// - `text` absent, `html` present: converted through `html2text`'s plain-text path.
/// - both absent: [`BodyAvailability::NoTextualBody`].
/// - The resulting plain text is re-capped at `cap_bytes` on a char boundary. `truncated` is
///   true if we clipped here or if the selected representation was already truncated at the
///   transport. `RawBody::text_truncated`/`html_truncated` are independent, so an unselected
///   sibling's truncation never carries over: when `text` wins, the html sibling's flag is
///   dropped along with its value.
pub fn to_body_view(raw: RawBody, cap_bytes: usize) -> Result<BodyAvailability, BodyViewError> {
    let RawBody { text, html, attachments, text_truncated, html_truncated } = raw;

    let (rendered, truncated_at_transport) = match (text, html) {
        // `text` wins outright. The html sibling, value and truncation flag both, is dropped
        // here unread: there is nowhere for either to go.
        (Some(plain), _) => (plain, text_truncated),
        (None, Some(markup)) => (html_to_plain_text(&markup)?, html_truncated),
        // Truthful absence: not `Text(BodyView { plain_text: String::new(), .. })`, and not
        // presence-free either, since an attachment-only message's whole content is what this
        // carries.
        (None, None) => return Ok(BodyAvailability::NoTextualBody { attachments }),
    };

    let (plain_text, clipped_here) = clip_on_char_boundary(rendered, cap_bytes);

    Ok(BodyAvailability::Text(BodyView {
        plain_text,
        truncated: clipped_here || truncated_at_transport,
        attachments,
    }))
}

/// The one call into `html2text`.
///
/// Its plain-text path is fallible by `Result` (`Config::string_from_read<R: io::Read>(self,
/// input: R, width: usize) -> Result<String, html2text::Error>`, checked against `html2text`
/// 0.17.1), so the ordinary failure is a value and we take it. The `catch_unwind` is a second,
/// independent net: the crate reaches html5ever over bytes from a remote sender, and a library
/// `unwrap` we do not control must not end the process. Both nets land on [`BodyViewError`].
///
/// Limit: `catch_unwind` contains an unwind. It cannot contain a stack overflow or an abort,
/// which are process-level. See the pathological-nesting test for what the converter does with
/// deep input.
///
/// `plain_no_decorate().link_footnotes(true)` is used instead of `config::plain()`, which
/// differs in two agent rules. `plain()` also calls `do_decorate()`, which injects markdown
/// emphasis (`**` around `<b>`/`<strong>`, `*` around `<em>`, backticks around `<code>`) the
/// sender never wrote: synthetic markup in a pane that renders literal text, and forgeable by
/// any sender typing `**` anyway. Footnotes do the opposite: they put the link target in
/// readable text, the one thing a reader needs to judge whether "click here" goes where it
/// claims. So decoration is off and footnotes are on.
fn html_to_plain_text(markup: &str) -> Result<String, BodyViewError> {
    let converted = catch_unwind(AssertUnwindSafe(|| {
        html2text::config::plain_no_decorate()
            .link_footnotes(true)
            .string_from_read(markup.as_bytes(), RENDER_WIDTH_COLS)
    }))
    .map_err(|_| BodyViewError::ConversionPanicked)?;

    converted.map_err(|_| BodyViewError::ConversionFailed)
}

/// Clip to at most `cap_bytes`, never inside a UTF-8 code point. Returns whether it clipped.
fn clip_on_char_boundary(mut s: String, cap_bytes: usize) -> (String, bool) {
    if s.len() <= cap_bytes {
        return (s, false);
    }
    let mut end = cap_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    (s, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presence(has: bool, count: u32) -> AttachmentPresence {
        AttachmentPresence { has_attachments: has, count }
    }

    fn raw(text: Option<&str>, html: Option<&str>, text_truncated: bool) -> RawBody {
        raw_split(text, html, text_truncated, false)
    }

    /// The per-representation constructor — `raw` above stays the convenience form
    /// (only `text`'s flag ever mattered to it) and this one lets a test set `html_truncated`
    /// independently.
    fn raw_split(
        text: Option<&str>,
        html: Option<&str>,
        text_truncated: bool,
        html_truncated: bool,
    ) -> RawBody {
        RawBody {
            text: text.map(str::to_owned),
            html: html.map(str::to_owned),
            attachments: presence(false, 0),
            text_truncated,
            html_truncated,
        }
    }

    fn text_of(av: BodyAvailability) -> BodyView {
        match av {
            BodyAvailability::Text(v) => v,
            BodyAvailability::NoTextualBody { .. } => {
                panic!("expected a textual body, got NoTextualBody")
            }
        }
    }

    /// THE FENCE, asserted at the wire. `BodyView` may serialize EXACTLY these three keys —
    /// no `html`, and nothing else that could carry markup to the renderer.
    #[test]
    fn body_view_serializes_exactly_three_fields_and_never_an_html_key() {
        let view = BodyView {
            plain_text: "hello".to_owned(),
            truncated: false,
            attachments: presence(true, 2),
        };

        let value = serde_json::to_value(&view).expect("BodyView serializes");
        let obj = value.as_object().expect("BodyView is a JSON object");

        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["attachments", "plain_text", "truncated"]);
        assert!(obj.get("html").is_none(), "the RAW-HTML-FENCE broke: BodyView grew an html key");
    }

    #[test]
    fn text_is_preferred_and_the_html_sibling_is_ignored_entirely() {
        let av = to_body_view(raw(Some("the plain part"), Some("<p>the HTML part</p>"), false), 4096)
            .expect("conversion succeeds");
        let view = text_of(av);

        assert_eq!(view.plain_text, "the plain part");
        assert!(!view.plain_text.contains("HTML part"));
        assert!(!view.truncated);
    }

    #[test]
    fn an_html_only_body_converts_to_tag_free_plain_text() {
        let av = to_body_view(raw(None, Some("<p>Hello <b>world</b></p>"), false), 4096)
            .expect("conversion succeeds");
        let view = text_of(av);

        assert!(view.plain_text.contains("Hello"), "got {:?}", view.plain_text);
        assert!(view.plain_text.contains("world"), "got {:?}", view.plain_text);
        assert!(!view.plain_text.contains('<'), "markup leaked: {:?}", view.plain_text);
        assert!(!view.plain_text.contains("<b>"), "markup leaked: {:?}", view.plain_text);
        // No SYNTHETIC markup either: `config::plain()`'s `do_decorate()` would have emitted
        // "Hello **world**". We render the sender's characters, not markdown we invented.
        assert!(!view.plain_text.contains('*'), "synthetic markup: {:?}", view.plain_text);
        assert_eq!(view.plain_text.trim(), "Hello world");
    }

    #[test]
    fn script_and_style_content_never_reaches_the_plain_text() {
        let av = to_body_view(
            raw(
                None,
                Some("<style>.x{background:url(http://evil.example/s)}</style>\
                      <script>evil()</script><p>safe</p>"),
                false,
            ),
            4096,
        )
        .expect("conversion succeeds");
        let view = text_of(av);

        assert!(view.plain_text.contains("safe"), "got {:?}", view.plain_text);
        assert!(!view.plain_text.contains("evil"), "script body leaked: {:?}", view.plain_text);
        assert!(
            !view.plain_text.contains("background"),
            "style body leaked: {:?}",
            view.plain_text
        );
    }

    /// The POST-conversion cap. The input HTML is well under the cap; its CONVERTED output is
    /// not — the transport-boundary cap alone would have let this through whole.
    #[test]
    fn the_cap_re_applies_after_conversion_and_clips_on_a_char_boundary() {
        // 'é' is two bytes; a cap of 5 falls INSIDE the third one, so a naive byte truncate
        // would panic / split a code point.
        let html = format!("<p>{}</p>", "é".repeat(50));
        assert!(html.len() < 4096, "the source must be under the transport cap");

        let av = to_body_view(raw(None, Some(&html), false), 5).expect("conversion succeeds");
        let view = text_of(av);

        assert!(view.truncated, "an over-cap conversion must report truncated");
        assert!(view.plain_text.len() <= 5, "cap exceeded: {} bytes", view.plain_text.len());
        assert_eq!(view.plain_text, "éé", "expected a char-boundary clip at 4 bytes");
        assert_eq!(view.plain_text.len(), 4);
    }

    #[test]
    fn a_transport_truncated_raw_body_stays_truncated_even_far_under_the_cap() {
        let av = to_body_view(raw(Some("short"), None, true), 4096).expect("conversion succeeds");
        let view = text_of(av);

        assert_eq!(view.plain_text, "short");
        assert!(view.plain_text.len() < 4096);
        assert!(view.truncated, "the transport's own truncation must propagate");
    }

    /// TRUNCATION IS PER-REPRESENTATION. `text` is complete (never clipped)
    /// and `html` is present-but-clipped; `text` wins outright per precedence, so the html
    /// sibling — value AND truncation flag — must never reach the selected view. Before this
    /// fold `RawBody` carried ONE shared `truncated` bool set from either representation, so this
    /// exact fixture reported the complete, displayed text as truncated. RED (pre-fix, with the
    /// old shared-bool `RawBody`): `view.truncated == true`. GREEN (this fold):
    /// `view.truncated == false`.
    #[test]
    fn truncation_rides_only_the_selected_representation_not_an_unselected_sibling() {
        let av = to_body_view(raw_split(Some("a complete short text body"), Some("<p>clipped</p>"), false, true), 4096)
            .expect("conversion succeeds");
        let view = text_of(av);

        assert_eq!(view.plain_text, "a complete short text body");
        assert!(
            !view.truncated,
            "the SELECTED text representation was never clipped — an unselected html \
             sibling's own truncation must not ride along"
        );
    }

    /// The converse of the test above, pinned so the fix cannot just always report `false`: when
    /// `text` itself is the one the transport clipped, that must still surface.
    #[test]
    fn truncation_still_surfaces_when_the_selected_representation_was_the_one_clipped() {
        let av = to_body_view(raw_split(Some("a clipped text body"), Some("<p>complete</p>"), true, false), 4096)
            .expect("conversion succeeds");
        let view = text_of(av);

        assert!(
            view.truncated,
            "the SELECTED text representation's own truncation must still propagate"
        );
    }

    #[test]
    fn a_body_with_neither_text_nor_html_is_the_typed_no_textual_body_state() {
        let av = to_body_view(raw(None, None, false), 4096).expect("absence is not an error");
        assert_eq!(
            av,
            BodyAvailability::NoTextualBody {
                attachments: presence(false, 0)
            }
        );
    }

    /// ATTACHMENT-ONLY MAIL. A message with no textual part but three
    /// attachments is the ordinary "here are the files" mail, and the absence arm used to DROP the
    /// presence it was handed: the reading pane could then render "no textual body" over a message
    /// whose entire content was its attachments. The presence rides the absence arm, at the wire.
    #[test]
    fn the_absence_arm_carries_attachment_presence_to_the_renderer() {
        let av = to_body_view(
            RawBody {
                text: None,
                html: None,
                attachments: presence(true, 3),
                text_truncated: false,
                html_truncated: false,
            },
            4096,
        )
        .expect("absence is not an error");

        let wire = serde_json::to_value(&av).expect("BodyAvailability serializes");
        assert_eq!(
            wire["NoTextualBody"]["attachments"]["has_attachments"],
            serde_json::json!(true),
            "the absence arm must carry attachment presence across IPC; got {wire}"
        );
        assert_eq!(
            wire["NoTextualBody"]["attachments"]["count"],
            serde_json::json!(3),
            "the count rides with it; got {wire}"
        );
        // THE EXACT WIRE SHAPE, pinned: the enum carries no serde attributes, so a struct variant
        // serializes externally-tagged as one key over one object. The renderer's `ipc.ts` union
        // must match this byte for byte — it used to be the bare string `"NoTextualBody"`, and a
        // change of that shape is exactly what this assertion exists to surface.
        assert_eq!(
            wire,
            serde_json::json!({
                "NoTextualBody": { "attachments": { "has_attachments": true, "count": 3 } }
            })
        );
    }

    /// The CONTAINMENT witness. Untrusted remote bytes reach this parser; a pathological
    /// document must produce a value or a typed error, and reaching the assertion below is
    /// itself the proof that nothing escaped — an unwind past `to_body_view` fails the test
    /// and an abort/stack-overflow kills the test binary outright.
    ///
    /// MEASURED at 0.17.1, depths 1k/5k/10k: all three return `Ok("deep\n")`. The converter's
    /// tree build is de-recursed (an explicit `pending_stack`, `html2text/src/lib.rs:1402`),
    /// so depth does not ride the machine stack. The contract asserted here is the weaker,
    /// upgrade-durable one — value OR typed error — because the exact outcome is the
    /// converter's business; only "no escape" is ours.
    #[test]
    fn pathological_nesting_yields_a_value_or_a_typed_error_and_never_escapes() {
        let depth = 10_000;
        let mut html = String::with_capacity(depth * 12);
        for _ in 0..depth {
            html.push_str("<div>");
        }
        html.push_str("deep");
        for _ in 0..depth {
            html.push_str("</div>");
        }

        let outcome = to_body_view(raw(None, Some(&html), false), 4096);
        match outcome {
            Ok(av) => assert_eq!(text_of(av).plain_text.trim(), "deep"),
            Err(BodyViewError::ConversionFailed) | Err(BodyViewError::ConversionPanicked) => {}
        }
    }

    /// The COPY-URL residual, named and pinned. `html2text`'s plain decorator brackets link
    /// text and appends a numbered footnote carrying the TARGET URL as literal text. That is
    /// ACCEPTED (design §2: the user can read/copy a link target) — but it is asserted
    /// exactly, so a converter upgrade that changes the shape trips this test instead of
    /// silently changing what the reading pane shows.
    #[test]
    fn a_hyperlink_lands_as_plain_text_with_its_target_as_a_documented_footnote() {
        let av = to_body_view(
            raw(None, Some(r#"<a href="http://evil.example/x">click</a>"#), false),
            4096,
        )
        .expect("conversion succeeds");
        let view = text_of(av);

        assert!(!view.plain_text.contains('<'), "markup leaked: {:?}", view.plain_text);
        assert!(!view.plain_text.contains("href"), "attribute leaked: {:?}", view.plain_text);
        assert_eq!(view.plain_text.trim_end(), "[click][1]\n\n[1]: http://evil.example/x");
    }
}
