//! **Permanent deletion is unconstructible: the SOURCE-SCAN half.**
//!
//! Prior art: Gmail's
//! `users.messages.delete` reference (`DELETE …/users/{userId}/messages/{id}`, "cannot be undone",
//! sole scope `https://mail.google.com/`) and Google's scope page (`gmail.modify` "does not allow
//! immediate, permanent deletion of threads and messages, bypassing the trash").
//!
//! # ⚠ THIS FILE IS A SOURCE-SCAN PIN, NOT A BEHAVIOURAL PROOF
//!
//! It reads `crates/aruna-gmail/src/transport.rs` **as text** and asserts that the delete-route
//! vocabulary does not appear in it. That establishes exactly one thing — that nobody has written
//! a permanent-delete route into this module — and it establishes it by *grep*, which any
//! sufficiently indirect construction (a runtime-assembled string, a new module, a dependency)
//! would walk straight past. It is a REVIEW TRIPWIRE at the cheapest possible price, and it is
//! deliberately labelled as one so no reader mistakes it for a control.
//!
//! # The decomposition, stated at the strength it is true
//!
//! A naive claim would be "permanent deletion is unconstructible", carried by two legs — scope
//! and verb set. Google's own references take a piece out of each:
//!
//!   * `users.drafts.delete`: its authorization scopes include
//!     `https://www.googleapis.com/auth/gmail.modify`, and it "immediately and permanently
//!     deletes the specified draft". So `gmail.modify` DOES authorize an immediate permanent
//!     delete — of a DRAFT. The scope wall is real for MESSAGES and THREADS and false as a
//!     general statement.
//!   * `users.messages.batchDelete` is a **POST**, not an HTTP
//!     `DELETE`. So "the seam has no DELETE verb" is not, on its own, a permanent-delete barrier.
//!
//! What this file and its siblings actually close, stated at the size it is true:
//!
//!   1. **MESSAGES and THREADS — closed by SCOPE.** Google's scope table says `gmail.modify`
//!      "does not allow immediate, permanent deletion of threads and messages, bypassing the
//!      trash", and both `users.messages.delete` and `users.messages.batchDelete` require
//!      `https://mail.google.com/`. The product's exact set is `{gmail.modify}`, and the
//!      full-mailbox scope is refused at the mint AND at admission (`src-tauri/src/lib.rs`'s
//!      `parse_gmail_credential`). This leg does not depend on any grep.
//!   2. **DRAFTS — NOT closed by scope.** For drafts the closure is a ROUTE-AND-BODY statement:
//!      the transport constructs exactly the `{modify, trash, untrash, get, list, attachment}`
//!      routes, with label-only bodies on `modify` and no body on `trash`/`untrash`, and no
//!      drafts route exists to be issued. That is pinned behaviourally by the transport's own
//!      route-shape witnesses — `the_production_modify_url_is_the_compiled_endpoint_route`,
//!      `trash_url_and_untrash_url_are_the_dedicated_endpoints_with_the_field_mask`,
//!      `the_get_message_url_carries_both_composed_parameters`,
//!      `url_metacharacters_in_ids_are_encoded_and_the_route_shape_is_pinned`,
//!      `read_route_metacharacter_ids_keep_the_route_shape_and_both_parameters`,
//!      `the_attachment_fetch_route_resolves_its_own_wire_cap` and
//!      `the_request_body_is_the_connector_built_request_and_only_the_two_label_arrays` — plus
//!      the scan below as a review tripwire over the same source. `trash`/`untrash`
//!      are reversible within Gmail's trash window and are not a permanent-delete route;
//!      `users.messages.delete` and `users.messages.batchDelete` stay unconstructible — the scan
//!      below is unchanged.
//!   3. **The verb set is NOT an independent leg.** The compile-level pin
//!      (`the_http_seam_exposes_exactly_post_json_post_empty_and_get_so_no_delete_verb_exists`,
//!      inside `src/transport.rs` because `HttpClient` is `pub(crate)`) still earns its place:
//!      the seam exposes exactly `post_json`, `post_empty` (the bodiless POST that
//!      `trash`/`untrash` ride) and `get`, and adding ANY further method to it is a compile
//!      break, which is a review moment. It is API hygiene and a tripwire, not a barrier —
//!      `batchDelete` would ride the `post_json` that already exists.

/// The transport's source, embedded at COMPILE time — so the scan cannot read a different tree
/// than the one that was built.
const TRANSPORT_SRC: &str = include_str!("../src/transport.rs");

/// The delete-route vocabulary. Each entry is a literal a permanent-delete implementation would
/// have to write down somewhere, with the reason it is on the list.
const DELETE_VOCABULARY: &[(&str, &str)] = &[
    (
        "batchDelete",
        "users.messages.batchDelete — the bulk permanent-delete route",
    ),
    (
        "\"/delete\"",
        "a `.../delete` route suffix built as a literal path segment",
    ),
    (
        "Method::DELETE",
        "reqwest's DELETE verb, named directly",
    ),
    (
        ".delete(",
        "a client `delete(...)` call — reqwest's per-verb builder",
    ),
    // The drafts collection, as a ROUTE would have to spell it — a quoted path segment or a
    // path literal. Deliberately NOT the bare word `drafts`: the transport already discusses
    // the DRAFT label in prose (`transport.rs`'s §3.3 archivability rows), and a needle that
    // fires on legitimate prose is a tripwire nobody can keep. `users.drafts.delete` is the one
    // permanent delete `gmail.modify` DOES authorize (per Google's
    // reference), so for that collection the route's absence is the whole closure.
    (
        "\"drafts\"",
        "a `drafts` path segment built as a literal — the collection whose delete route \
         gmail.modify authorizes",
    ),
    (
        "/drafts",
        "a `.../drafts/...` route written as a path literal",
    ),
];

#[test]
fn the_transport_source_names_no_permanent_delete_route_source_scan_pin() {
    for (needle, why) in DELETE_VOCABULARY {
        assert!(
            !TRANSPORT_SRC.contains(needle),
            "SOURCE-SCAN PIN (#75 S0 C5(b)): `{needle}` appears in \
             crates/aruna-gmail/src/transport.rs — {why}. Permanent deletion bypasses the trash \
             and cannot be undone. For messages and threads it also requires the full-mailbox \
             scope this product structurally never holds; for DRAFTS it does not — `gmail.modify` \
             authorizes `users.drafts.delete`, so there the route being absent is the whole \
             closure. If any of this is genuinely wanted, it is its own designed slice with its \
             own council round — not a line that lands under a triage PR."
        );
    }
}

/// The pin's own premise, asserted so a refactor that moves the transport out from under
/// `include_str!` cannot silently turn the scan above into a scan of nothing.
#[test]
fn the_source_scan_actually_read_the_transport() {
    assert!(
        TRANSPORT_SRC.len() > 10_000,
        "the embedded transport source is implausibly small ({} bytes) — the scan is pointed at \
         the wrong file and proves nothing",
        TRANSPORT_SRC.len()
    );
    assert!(
        TRANSPORT_SRC.contains("trait HttpClient"),
        "the embedded source must be the transport module that owns the HTTP seam"
    );
    assert!(
        TRANSPORT_SRC.contains("fn post_json")
            && TRANSPORT_SRC.contains("fn post_empty")
            && TRANSPORT_SRC.contains("fn get"),
        "the three verbs the seam DOES expose must be present — their absence means this scan is \
         reading a file that no longer defines the seam"
    );
}
