//! The live HTTP JMAP transport: `HttpJmapTransport` implements `aruna::jmap::JmapTransport` over a
//! hand-rolled `reqwest::blocking` + serde surface (Session discovery, `Mailbox/query|get`,
//! `Email/set`). The wire shape lives here; the wire to taxonomy mapping lives in
//! [`crate::error`] / [`crate::response`]. Provider ids, `description` and `detail` never cross
//! back above the seam, only typed [`aruna::jmap::JmapError`] variants do.

use std::collections::HashSet;
use std::time::Duration;

use serde_json::{json, Value};

use aruna::jmap::{
    classify_jmap_error, AccountId, EmailCurrentState, EmailId, EmailSetRequest, JmapError,
    JmapTransport, MailboxId, MailboxRole, PatchOp, TransportError,
};
use aruna::read_model::{Placement, ProviderMessageId, ProviderPlacement};
use aruna::read_surface::{
    clamp_page_size, AttachmentPresence, ContinuationToken, HeaderSummary, ListedPage, RawBody,
};
use aruna::{ConnectorError, FailureKind};

use crate::error::{map_http_status, map_method_error, map_request_problem};
use crate::response::parse_email_set_response;

/// The two JMAP capability URNs an `Email/set` mailbox move uses (RFC 8620 core + RFC 8621 mail).
const JMAP_CORE: &str = "urn:ietf:params:jmap:core";
const JMAP_MAIL: &str = "urn:ietf:params:jmap:mail";

/// The hard ceiling `fetch_body` applies to each of `RawBody.text`/`.html` independently, at the
/// transport boundary. Same value as the Gmail transport's `aruna_gmail::transport::BODY_FETCH_CAP`
/// (1 MB of decoded text covers ordinary mail while keeping a misbehaving provider from having an
/// unbounded body buffered). Sent to the provider as `maxBodyValueBytes` (RFC 8621 §4.1.4) and
/// re-applied locally on the returned value, since the provider's own truncation is not trusted
/// alone.
pub const BODY_FETCH_CAP: usize = 1_000_000;

/// How many [`BODY_FETCH_CAP`]-sized bodies one body read is sized to bring back: the `textBody`
/// aggregate and the `htmlBody` aggregate (`fetchTextBodyValues` + `fetchHTMLBodyValues`, RFC 8621
/// §4.1.4), each bounded on the wire by the `maxBodyValueBytes` we send. Two, because `RawBody`
/// has two textual members and [`body_parts_text`] caps each across its whole concatenation.
///
/// It is not a count of `bodyValues` entries: `textBody`/`htmlBody` are sequential part lists, so
/// a provider returns one entry per listed part. `maxBodyValueBytes` bounds each entry, not their
/// sum, so a message whose parts sum past [`MAX_RESPONSE_WIRE_BYTES`] is refused on the wire,
/// deterministically and visibly, before [`body_parts_text`]'s aggregate cap can clip it. Raising
/// the ceiling is a wire-posture change needing its own review.
const MAX_BODY_VALUES_PER_FETCH: u64 = 2;

/// The worst-case blow-up of one UTF-8 byte of body text written into a JSON string. RFC 8259 §7
/// requires control characters to be escaped, and the general escape is `\uXXXX`: six bytes out
/// for one in. Ordinary mail is nowhere near this, but a body of control characters is legal
/// content, so the legitimate-envelope bound has to admit it.
const JSON_STRING_ESCAPE_WORST_CASE: u64 = 6;

/// Headroom over the escaped body text for the JSON envelope carrying it: the `methodResponses`
/// framing, the `Email` object's other requested properties and the `bodyValues` structure.
/// Chosen (512 KiB) and generous; an observed envelope around two capped bodies is a few KiB.
const RESPONSE_WIRE_MARGIN_BYTES: u64 = 512 * 1024;

/// The wire ceiling every live response is read under. Without it the client would buffer
/// `resp.text()` whole, and a hostile or broken provider could hand this process a response of
/// any size. Nothing above the client can refuse bytes already allocated, so this is the only
/// defense.
///
/// Sized for the worst legitimate response, the body read (every other route is far smaller):
///
/// ```text
/// MAX_BODY_VALUES_PER_FETCH (2) × BODY_FETCH_CAP (1,000,000) × JSON_STRING_ESCAPE_WORST_CASE (6)
///   + RESPONSE_WIRE_MARGIN_BYTES (512 KiB)  =  12,000,000 + 524,288  =  12,524,288 bytes
/// ```
///
/// It is an expression over the named constants, so a change to [`BODY_FETCH_CAP`] moves the wire
/// bound with it (as in the Gmail sibling's `MAX_BODY_FETCH_WIRE_BYTES`).
///
/// One bound, not a per-route axis: every JMAP method call is a POST to the same `apiUrl`, so the
/// reader cannot tell a body read from a label read, and sizing the other routes tighter would
/// risk refusing legitimate traffic (the failure the Gmail sibling had to correct). Any finite
/// bound closes the memory-exhaustion class; taking the largest legitimate envelope keeps that
/// from creating an unreadable-mail class. Residual: a single in-flight response may occupy up
/// to this many bytes.
const MAX_RESPONSE_WIRE_BYTES: u64 = MAX_BODY_VALUES_PER_FETCH
    * BODY_FETCH_CAP as u64
    * JSON_STRING_ESCAPE_WORST_CASE
    + RESPONSE_WIRE_MARGIN_BYTES;

// JMAP method-call ids are minted per request by `HttpJmapTransport` (a monotonic counter), not
// a constant. RFC 8620 §3.2: the response's third tuple element echoes the id we sent, and we
// verify the echo to reject a misrouted or replayed response. A fixed id could only reject a
// wholly unrelated method; it could not disambiguate two requests of the same method (e.g. the
// inbox and archive `Mailbox/query` in one archive op).

/// What Session discovery (RFC 8620 §2) yields and the transport needs: where to POST method calls
/// (`apiUrl`) and the primary account for the mail capability. Both are provider identifiers held
/// inside [`HttpJmapTransport`], never surfaced above it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The endpoint to POST JMAP requests to.
    pub api_url: String,
    /// The `primaryAccounts[urn:ietf:params:jmap:mail]` account id, if the server advertises a
    /// default mail account. RFC 8620 §2 lets a mail-capable session omit it (e.g.
    /// shared-account-only users); the account actually used comes from the connector's
    /// `AccountResolver`, so this is optional context, never required to connect.
    pub primary_account: Option<String>,
    /// `capabilities[urn:ietf:params:jmap:core].maxObjectsInGet` (RFC 8620 §2), when the server
    /// advertises a usable one: "the maximum number of objects that the client may request in a
    /// single `/get` type method call". A `/get` over it is answered `requestTooLarge` and the
    /// whole request fails, so a small advertised value would make the inbox unlistable at our
    /// default page size. `None` means not advertised (no default in the RFC): the page size
    /// stands as clamped. A non-positive or non-integer value is treated as absent, not as a
    /// ceiling of zero.
    pub max_objects_in_get: Option<i64>,
}

/// Redacted `Debug`: `api_url` and `primary_account` are provider identifiers and must never
/// reach `{:?}` output (logs, `expect_err`).
impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionInfo(<redacted>)")
    }
}

/// Parse a JMAP Session resource body (RFC 8620 §2) into the [`SessionInfo`] the transport needs.
/// Fails closed and id-free: a malformed body, a missing `apiUrl`, or a session that does not
/// advertise the mail capability (`capabilities[urn:ietf:params:jmap:mail]`, the positive "this
/// is a JMAP mail server" signal) is a deterministic failure. The mail `primaryAccounts` entry is
/// optional (the connector's `AccountResolver` chooses the account), so an absent entry is
/// recorded as `None`, not a connect failure, and an account is never guessed.
///
/// Not account-correlated, by RFC: this is the Session resource, not a method response, and has
/// no `accountId` (it is the object that enumerates accounts), so [`correlate_account`] does not
/// apply, as with [`parse_request_problem`]'s request-level scope.
fn parse_session(body: &str) -> Result<SessionInfo, JmapError> {
    // A deterministic, id-free fail-closed error for an unusable session. It reuses the taxonomy's
    // unknown to `serverFail` route so retrying a structurally broken discovery never burns the
    // DLQ budget, and no provider text rides along.
    let fail = || map_method_error("__session_discovery_failed__");
    let value: Value = serde_json::from_str(body).map_err(|_| fail())?;
    // Same wire-level uniqueness check as the method-response parses: `apiUrl` decides where
    // credentialed traffic is POSTed, and `capabilities`/`primaryAccounts` (plus the mail URN
    // inside them) decide the mail-capability gate and the advertised account. A duplicate
    // collapses in `Value` to the last copy, so it must be caught on the raw text.
    wire_member_names_are_unique(body).map_err(|_| fail())?;
    let api_url = value.get("apiUrl").and_then(Value::as_str).ok_or_else(fail)?;
    // Require the server to advertise the mail capability (RFC 8620 §2 `capabilities`). With
    // `primary_account` optional, this is the "is a JMAP mail server" signal; without it
    // Mailbox/query and Email/set cannot work, so fail closed at connect rather than later.
    let capabilities = value.get("capabilities").and_then(Value::as_object);
    let advertises_mail = capabilities.is_some_and(|caps| caps.contains_key(JMAP_MAIL));
    if !advertises_mail {
        return Err(fail());
    }
    // The core capability's `/get` ceiling (RFC 8620 §2), when advertised and usable. Absent,
    // non-integer or non-positive all read as "no ceiling stated"; a server does not get to
    // shrink our page to zero rows by advertising one.
    let max_objects_in_get = capabilities
        .and_then(|caps| caps.get(JMAP_CORE))
        .and_then(Value::as_object)
        .and_then(|core| core.get("maxObjectsInGet"))
        .and_then(Value::as_i64)
        .filter(|n| *n > 0);
    // The mail capability's primary account when advertised, never any other account and never
    // the first we find. Absent is fine (the AccountResolver supplies it).
    let primary_account = value
        .get("primaryAccounts")
        .and_then(Value::as_object)
        .and_then(|m| m.get(JMAP_MAIL))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(SessionInfo {
        api_url: api_url.to_string(),
        primary_account,
        max_objects_in_get,
    })
}

/// The IANA mailbox-role string (RFC 8621 §2 / the role registry) for a [`MailboxRole`].
fn role_str(role: MailboxRole) -> &'static str {
    match role {
        MailboxRole::Inbox => "inbox",
        MailboxRole::Archive => "archive",
    }
}

/// Build a `Mailbox/query` request filtering on the given role (RFC 8621 §2.3: `role` is a valid
/// FilterCondition). The response's `ids` names the mailbox holding that role (at most one,
/// since roles are unique per account).
fn build_mailbox_query_body(account_id: &str, role: MailboxRole, call_id: &str) -> Value {
    json!({
        "using": [JMAP_CORE, JMAP_MAIL],
        "methodCalls": [[
            "Mailbox/query",
            { "accountId": account_id, "filter": { "role": role_str(role) } },
            call_id,
        ]],
    })
}

/// Pull the method response `(name, args, callId)` at `index` out of a JMAP response envelope (RFC
/// 8620 §3.4: `methodResponses` is a list of `[name, args, callId]`). A malformed or short
/// envelope is a deterministic, id-free failure, never a silent success. This is the only
/// envelope walker: single-call parses go through [`first_method_response`] (`index` 0), and the
/// combined-request parse ([`parse_inbox_query_response`] / [`parse_inbox_get_response`]) calls
/// it at indices 0 and 1.
fn nth_method_response(body: &str, index: usize) -> Result<(String, Value, String), JmapError> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| map_method_error("__malformed_response__"))?;
    // The raw-text uniqueness scan runs here, once, so every method-response parse in this crate
    // inherits it. The `Value` above has already collapsed any duplicate member (last key wins),
    // and the members these parses decide on (`accountId`, `state`, `list`, `id`, `ids`, `type`,
    // …) must be checked at the wire level or the decision can be flipped invisibly. It runs
    // after the syntax parse so a body that is not JSON keeps its `__malformed_response__`
    // verdict.
    wire_member_names_are_unique(body)?;
    let entry = value
        .get("methodResponses")
        .and_then(Value::as_array)
        .and_then(|calls| calls.get(index))
        .and_then(Value::as_array)
        .ok_or_else(|| map_method_error("__empty_response__"))?;
    let name = entry
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| map_method_error("__malformed_response__"))?
        .to_string();
    let args = entry.get(1).cloned().unwrap_or(Value::Null);
    // A present callId of the wrong type is malformed, not an empty callId (which would only
    // surface later as a mismatch). An absent one keeps the empty string and fails the caller's
    // correlation.
    let call_id = match entry.get(2) {
        None => String::new(),
        Some(Value::String(id)) => id.clone(),
        Some(_) => return Err(map_method_error("__malformed_response__")),
    };
    Ok((name, args, call_id))
}

/// The first method response, used by every single-method-call request's parse. See
/// [`nth_method_response`].
fn first_method_response(body: &str) -> Result<(String, Value, String), JmapError> {
    nth_method_response(body, 0)
}

/// Parse a `Mailbox/query` response into the role mailbox id, or `Ok(None)` when no mailbox has the
/// role (RFC 8621 §2: roles are optional). A method-level error maps via the taxonomy; a malformed
/// envelope fails closed. Correlates the callId first, then the method name, then the requested
/// account ([`correlate_account`]): mailbox roles are per-account, so a foreign `accountId` here
/// would resolve our role to another account's mailbox id and hand it to the destructive
/// `Email/set`.
fn parse_mailbox_query_response(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
) -> Result<Option<MailboxId>, JmapError> {
    let (name, args, call_id) = first_method_response(body)?;
    // Correlate to our request before interpreting the tuple as an error or a result. A tuple
    // whose callId doesn't echo this request's id is misrouted or replayed and fails closed; a
    // mismatched method-level `error` must not be accepted as our (possibly transient) result
    // and retried.
    if call_id != expected_call_id {
        return Err(map_method_error("__call_id_mismatch__"));
    }
    // A method-level failure replaces the response with `["error", {type}, callId]`.
    if name == "error" {
        let type_str = args.get("type").and_then(Value::as_str).unwrap_or("");
        return Err(map_method_error(type_str));
    }
    // Fail closed on an unexpected method name: a stray `ids` must not be trusted as the role
    // mailbox id (it feeds the subsequent Email/set).
    if name != "Mailbox/query" {
        return Err(map_method_error("__unexpected_method_response__"));
    }
    // Then whose namespace this is: a role query correlated only by callId and method name can
    // still describe another account's mailboxes, and the id it yields feeds the Email/set.
    correlate_account(&args, expected_account_id)?;
    // `ids` lists the mailboxes matching the role filter; roles are unique, so take the first (or
    // `None` when the role is absent). `ids` is `Id[]` and required (RFC 8620 `/query`): absent,
    // not an array, or any member not a string is malformed, never "no role mailbox"; only a
    // well-typed empty array is `None`. `parse_inbox_query_response` reads its `ids` the same way.
    let ids = args
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| map_method_error("__malformed_response__"))?
        .iter()
        .map(|v| v.as_str().ok_or_else(|| map_method_error("__malformed_response__")))
        .collect::<Result<Vec<&str>, _>>()?;
    Ok(ids.first().map(|id| MailboxId(id.to_string())))
}

/// Build the JMAP request body for an `Email/set` from the connector's request data (its public
/// `account_id()` / `typed_updates()`). Every recognized [`PatchOp`] is carried to the wire,
/// mailbox membership (`mailboxIds/<id>`) and keyword (`keywords/<name>`) patches alike: the
/// surgical RFC 8621 PatchObject the connector intends, never a silent drop.
fn build_email_set_body(
    account_id: &str,
    updates: &[(&str, Vec<PatchOp<'_>>)],
    call_id: &str,
) -> Value {
    let mut update = serde_json::Map::new();
    for (email_id, ops) in updates {
        let mut patch = serde_json::Map::new();
        for op in ops {
            match op {
                // RFC 8621 PatchObject: add/set is true, remove/clear is null (a surgical
                // change, not a full replace, which would strip other memberships/keywords).
                PatchOp::Mailbox { mailbox_id, member } => {
                    let value = if *member { json!(true) } else { Value::Null };
                    patch.insert(format!("mailboxIds/{mailbox_id}"), value);
                }
                PatchOp::Keyword { name, set } => {
                    let value = if *set { json!(true) } else { Value::Null };
                    patch.insert(format!("keywords/{name}"), value);
                }
            }
        }
        update.insert((*email_id).to_string(), Value::Object(patch));
    }
    json!({
        "using": [JMAP_CORE, JMAP_MAIL],
        "methodCalls": [["Email/set", { "accountId": account_id, "update": update }, call_id]],
    })
}

/// Build the JMAP `Email/get` request for one message (RFC 8621 §4.1): the read-side truth source
/// for divergence correction and the capture read. `properties` is narrowed by the caller to
/// what it needs (`["mailboxIds"]` for placement, `["mailboxIds","keywords"]` for the capture
/// read) so the response carries no more than the reading requires.
fn build_email_get_body(
    account_id: &str,
    email_id: &str,
    properties: &[&str],
    call_id: &str,
) -> Value {
    json!({
        "using": [JMAP_CORE, JMAP_MAIL],
        "methodCalls": [[
            "Email/get",
            { "accountId": account_id, "ids": [email_id], "properties": properties },
            call_id,
        ]],
    })
}

/// Build a `Mailbox/get` whose only purpose is the namespace's state cursor (RFC 8620 §5.1: every
/// `Foo/get` response carries `state`; RFC 8621 §2 makes it the basis for `Mailbox/changes`).
/// `ids: []` + `properties: []` ask for no records: the freshness basis wants the token, not the
/// mailbox list.
fn build_mailbox_get_state_body(account_id: &str, call_id: &str) -> Value {
    json!({
        "using": [JMAP_CORE, JMAP_MAIL],
        "methodCalls": [[
            "Mailbox/get",
            { "accountId": account_id, "ids": [], "properties": [] },
            call_id,
        ]],
    })
}

/// Correlate a method response's `accountId` against the account the request was made for.
///
/// CallId and method name prove the response answers our call, not whose data it describes.
/// Without this, a misrouted or hostile response echoing our call id and record id but carrying
/// another account's `accountId` would be read as our answer, and a capture parse would journal
/// another account's state under our key. RFC 8620 §5.1 puts `accountId` in every
/// account-scoped response, so an absent or non-string one is nonconforming and fails closed.
///
/// Every account-scoped parse shares this check, so it has one definition and one error token.
/// It runs after the method-name check on purpose: RFC 8620 §3.6.2's `["error", {type}, callId]`
/// tuple carries no `accountId`, so correlating it would turn every method-level error into
/// `__account_id_mismatch__` and erase the taxonomy.
pub(crate) fn correlate_account(args: &Value, expected_account_id: &str) -> Result<(), JmapError> {
    match args.get("accountId").and_then(Value::as_str) {
        Some(id) if id == expected_account_id => Ok(()),
        _ => Err(map_method_error("__account_id_mismatch__")),
    }
}

/// Parse a `Mailbox/get` response into the account's Mailbox state cursor. Correlates the callId
/// first (misrouted/replayed fails closed), then the `Mailbox/get` method name, then the
/// requested account ([`correlate_account`]: a state token belongs to one account's namespace,
/// and a foreign one frozen as basis freshness would have us re-verify our namespace against
/// someone else's clock), then reads `state`. An absent or empty `state` fails closed: an empty
/// token would compare equal to itself forever and turn the freshness evidence into a constant.
fn parse_mailbox_get_state(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
) -> Result<String, JmapError> {
    let (name, args, call_id) = first_method_response(body)?;
    if call_id != expected_call_id {
        return Err(map_method_error("__call_id_mismatch__"));
    }
    if name == "error" {
        let type_str = args.get("type").and_then(Value::as_str).unwrap_or("");
        return Err(map_method_error(type_str));
    }
    if name != "Mailbox/get" {
        return Err(map_method_error("__unexpected_method_response__"));
    }
    correlate_account(&args, expected_account_id)?;
    match args.get("state").and_then(Value::as_str) {
        Some(state) if !state.is_empty() => Ok(state.to_string()),
        _ => Err(map_method_error("__missing_state_cursor__")),
    }
}

/// The RFC 8621 `Email` properties whose value is a `String[Boolean]` set: membership by key
/// presence, values must be `true` (§4.1.1 `mailboxIds`, `keywords`). One list, so the true-only
/// and I-JSON-uniqueness checks below cover every such property and a future set-valued property
/// is one edit.
const BOOLEAN_SET_PROPERTIES: [&str; 2] = ["mailboxIds", "keywords"];

/// Every member name this crate makes a security, correlation, navigation or taxonomy decision
/// on. `serde_json::Value` silently collapses a repeated member to the last one, so any member a
/// parser branches on can have its decision flipped by a duplicate the collapsed `Value` never
/// shows. Declaring the set here, and enforcing it on the raw body (see
/// [`wire_member_names_are_unique`]), closes the class rather than two point cases.
///
/// What each parse reads, and whether a duplicate could flip its decision:
///
/// | member | read by | a duplicate flips | verdict |
/// |---|---|---|---|
/// | `methodResponses` | [`first_method_response`], `response::ResponseEnvelope` | which tuple list is parsed | IN |
/// | `accountId` | [`correlate_account`] | whose namespace the response describes | IN |
/// | `state` | [`parse_mailbox_get_state`] | the basis freshness cursor | IN |
/// | `ids` | [`parse_mailbox_query_response`], [`parse_inbox_query_response`] | the role mailbox id handed to the destructive `Email/set`; the page's id list and its order | IN |
/// | `list` | `parse_email_get_row`, [`parse_inbox_get_response`] | which row set the requested id is searched in | IN |
/// | `id` | `parse_email_get_row`, [`parse_inbox_get_response`] | which row answers for ours | IN |
/// | `type` | the `["error", …]` arms, `map_set_error`, [`parse_request_problem`] | the taxonomy verdict (retry vs dead-letter) | IN |
/// | `updated` | [`crate::response::parse_email_set_response`] | whether a non-idempotent write is confirmed applied | IN |
/// | `notUpdated` | same | whether that write is refuted | IN |
/// | `limit` | [`parse_request_problem`] | the `RequestLimit` subtype (transient vs deterministic) | IN |
/// | `apiUrl` | [`parse_session`] | where credentialed method calls are POSTed | IN |
/// | `capabilities` | [`parse_session`] | the "is a JMAP mail server" gate | IN |
/// | `primaryAccounts` | [`parse_session`] | the advertised default mail account | IN |
/// | `urn:ietf:params:jmap:mail` | [`parse_session`], inside the two above | the same two decisions, at member level | IN |
/// | `urn:ietf:params:jmap:core` | [`parse_session`], inside `capabilities` | which core-capability object the `/get` ceiling is read from | IN |
/// | `maxObjectsInGet` | [`parse_session`], inside the core capability | the effective page size (high earns `requestTooLarge` on every listing, low silently shortens pages) | IN |
/// | `total` | [`parse_inbox_query_response`] | whether `list_inbox_page` reports a [`ContinuationToken`] (low hides the tail of the inbox, high spins the caller on a phantom page) | IN |
/// | `mailboxIds`, `keywords` | [`true_only_member_keys`] | membership/keyword truth; already closed at property and member level by [`BOOLEAN_SET_PROPERTIES`] | covered |
/// | `notFound` | nobody (only in fixtures; "absent" is decided from `list` alone) | nothing | OUT |
/// | `description`, `detail` | nobody (never read: no provider text crosses the seam) | nothing | OUT |
/// | `receivedAt`, `from`, `subject`, `hasAttachment`, `textBody`, `htmlBody`, `bodyValues`, `value`, `isTruncated` | [`header_summary_from_row`], [`body_part_text`] | which of two equally untrusted provider-content copies displays; the row is already gated to the right id and account by `id`/`list`/`accountId`, so a duplicate only picks between two copies of content from the same correlated row | OUT (content, not a gated decision) |
/// | method name, callId | tuple positions 0 and 2 of a JSON array | n/a: arrays have no member names | n/a |
/// | `using`, `methodCalls`, `filter`, `properties`, `update` | request side only; built here, never parsed off a provider body | n/a | OUT |
///
/// A member that joins any parse's decision must be added here.
const DECISION_MEMBERS: [&str; 20] = [
    "methodResponses",
    "accountId",
    "state",
    "ids",
    "list",
    "id",
    "type",
    "updated",
    "notUpdated",
    "limit",
    "apiUrl",
    "capabilities",
    "primaryAccounts",
    "total",
    JMAP_MAIL,
    JMAP_CORE,
    "maxObjectsInGet",
    // These three decide page correlation, whether an omitted query id is accepted, and the
    // chronological coverage floor (`receivedAt` and the reconcile window). A duplicate of any
    // of them is last-one-wins ambiguity on a removal-deciding value, so it fails closed too.
    "position",
    "notFound",
    "receivedAt",
];

/// The scan's fail-closed token for a repeated [`DECISION_MEMBERS`] name. Distinct from
/// `__invalid_mailbox_membership__` (the boolean-set verdict) for the audit trail; both route
/// through `map_method_error`'s deterministic unknown bucket.
const DUPLICATE_DECISION_MEMBER: &str = "__duplicate_decision_member__";

/// Reject a response body whose wire text repeats a member name that some parse decides on. It
/// scans the raw body because every parse pre-deserializes into [`serde_json::Value`], whose
/// map silently keeps the last duplicate key. Two families, one walk:
///
/// 1. **[`BOOLEAN_SET_PROPERTIES`]** (`mailboxIds`, `keywords`): `{"INBOX": false, "INBOX": true}`
///    would reach the RFC 8621 true-only check as just `true`. Checked inside the set's value and
///    on the enclosing object's property names (`{"keywords":{…},"keywords":{}}`).
/// 2. **[`DECISION_MEMBERS`]**: the same collapse on members that decide correlation, navigation
///    and taxonomy (`{"accountId":"ACCT-OTHER", …, "accountId":"OURS"}` would correlate as ours
///    while describing another account).
///
/// JMAP is I-JSON (RFC 8620 §1.1 / RFC 7493 §2.3): member names must be unique, so a repeat is a
/// nonconforming wire object and fails the whole read closed, whatever the order or values. It
/// therefore cannot refuse a well-formed body. Serde's streaming `MapAccess` sees every pair
/// including duplicates, so the scan walks the body wherever such a member appears. Navigation,
/// correlation, the error arm and the true-only check stay on the parsed `Value`.
///
/// Called from every parse entry point that owns a raw body ([`first_method_response`],
/// [`parse_session`], [`parse_request_problem`], [`crate::response::parse_email_set_response`]),
/// so no parse can acquire a second, laxer reading of the same wire object.
pub(crate) fn wire_member_names_are_unique(body: &str) -> Result<(), JmapError> {
    /// Walk any JSON value, recursing into arrays and objects; the value of a
    /// [`BOOLEAN_SET_PROPERTIES`] member is handed to [`UniqueMemberNames`].
    struct Scan;
    /// Like [`Scan`], but the directly visited object must not repeat a member name.
    struct UniqueMemberNames;

    impl<'de> serde::de::DeserializeSeed<'de> for Scan {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
    }
    impl<'de> serde::de::DeserializeSeed<'de> for UniqueMemberNames {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
    }

    /// The scalar arms are shared: a scalar carries no member names, so both visitors accept it
    /// (a non-object `mailboxIds` is refused by the `Value`-side shape check, not here).
    macro_rules! scalar_arms {
        () => {
            fn visit_bool<E>(self, _: bool) -> Result<(), E> {
                Ok(())
            }
            fn visit_i64<E>(self, _: i64) -> Result<(), E> {
                Ok(())
            }
            fn visit_u64<E>(self, _: u64) -> Result<(), E> {
                Ok(())
            }
            fn visit_f64<E>(self, _: f64) -> Result<(), E> {
                Ok(())
            }
            fn visit_str<E>(self, _: &str) -> Result<(), E> {
                Ok(())
            }
            fn visit_unit<E>(self) -> Result<(), E> {
                Ok(())
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                while seq.next_element_seed(Scan)?.is_some() {}
                Ok(())
            }
        };
    }

    impl<'de> serde::de::Visitor<'de> for Scan {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        scalar_arms!();
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            // Uniqueness is checked at both levels of the same nesting: inside a boolean-set
            // value (below), and on the enclosing object's own boolean-set property names
            // (here). A row repeating the property (`"keywords":{…},"keywords":{…}`) collapses
            // in `Value` to the last one like a repeated member, so checking only the inner level
            // would leave the outer bypass open. The same check covers `DECISION_MEMBERS`.
            let mut seen_properties = std::collections::HashSet::new();
            let mut seen_decisions = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if DECISION_MEMBERS.contains(&key.as_str()) && !seen_decisions.insert(key.clone()) {
                    return Err(serde::de::Error::custom(DUPLICATE_DECISION_MEMBER));
                }
                if BOOLEAN_SET_PROPERTIES.contains(&key.as_str()) {
                    if !seen_properties.insert(key) {
                        return Err(serde::de::Error::custom(
                            "duplicate boolean-set property name",
                        ));
                    }
                    map.next_value_seed(UniqueMemberNames)?;
                } else {
                    map.next_value_seed(Scan)?;
                }
            }
            Ok(())
        }
    }

    impl<'de> serde::de::Visitor<'de> for UniqueMemberNames {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a mailboxIds/keywords object with unique member names")
        }
        scalar_arms!();
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut seen = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key) {
                    return Err(serde::de::Error::custom("duplicate boolean-set member name"));
                }
                // Values still recurse: a nonconforming nested object could carry its own
                // `mailboxIds`/`keywords`, and the scan must not go blind inside it.
                map.next_value_seed(Scan)?;
            }
            Ok(())
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(body);
    serde::de::DeserializeSeed::deserialize(Scan, &mut deserializer).map_err(|e| {
        // Which family fired decides only the token (for the audit trail); both land in the same
        // deterministic fail-closed bucket. serde's `Error::custom` Displays the message we
        // minted, so the token round-trips through it.
        if e.to_string().contains(DUPLICATE_DECISION_MEMBER) {
            map_method_error(DUPLICATE_DECISION_MEMBER)
        } else {
            map_method_error("__invalid_mailbox_membership__")
        }
    })
}

/// Read one `String[Boolean]` property off an `Email/get` row (RFC 8621 §4.1.1: `mailboxIds`,
/// `keywords`). Membership is key presence, so any non-`true` value (false, string, null, …) is a
/// nonconforming wire object and fails the whole read closed, never filtered into a subset. An
/// absent or non-object property is malformed too: the caller asked for it, so silence is not
/// "empty".
fn true_only_member_keys(entry: &Value, property: &str) -> Result<Vec<String>, JmapError> {
    debug_assert!(BOOLEAN_SET_PROPERTIES.contains(&property));
    let members = entry
        .get(property)
        .and_then(Value::as_object)
        .ok_or_else(|| map_method_error("__malformed_response__"))?;
    let mut keys = Vec::with_capacity(members.len());
    for (key, value) in members {
        if value != &Value::Bool(true) {
            return Err(map_method_error("__invalid_mailbox_membership__"));
        }
        keys.push(key.clone());
    }
    Ok(keys)
}

/// Parse an `Email/get` response into the requested message's `mailboxIds` membership keys, the
/// read-side placement truth. Navigation, correlation and wire-shape checks all come from
/// `parse_email_get_row` / [`true_only_member_keys`]; this adds nothing, so there is one parse to
/// trust.
fn parse_email_get_mailbox_ids(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
    expected_email_id: &str,
) -> Result<Vec<String>, JmapError> {
    let entry =
        parse_email_get_row(body, expected_call_id, expected_account_id, expected_email_id)?;
    true_only_member_keys(&entry, "mailboxIds")
}

/// Parse an `Email/get` response into the capture read: the message's current true-only
/// `mailboxIds` + `keywords` (`aruna::jmap::EmailCurrentState`). It shares the placement read's
/// parse, so the capture never gets a second, laxer reading of the same wire object.
fn parse_email_get_current_state(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
    expected_email_id: &str,
) -> Result<EmailCurrentState, JmapError> {
    let entry =
        parse_email_get_row(body, expected_call_id, expected_account_id, expected_email_id)?;
    Ok(EmailCurrentState {
        mailbox_ids: true_only_member_keys(&entry, "mailboxIds")?
            .into_iter()
            .collect(),
        keywords: true_only_member_keys(&entry, "keywords")?
            .into_iter()
            .collect(),
    })
}

/// Locate the requested message's `Email/get` row, the one navigation every `Email/get` read
/// shares (see [`parse_email_get_mailbox_ids`] / [`parse_email_get_current_state`]). Correlates
/// the callId first (misrouted/replayed fails closed), then the `Email/get` method name, then
/// finds the `list` entry whose `id` matches `expected_email_id`. It never trusts `list[0]`
/// blindly: a misrouted or malformed response could carry a different email's row, which would
/// feed the wrong placement into reconcile_divergence or the wrong pre-state into the capture. A
/// missing or non-matching entry (the id was `notFound`, or the row is for another email) fails
/// closed, never a silent "nothing is set".
fn parse_email_get_row(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
    expected_email_id: &str,
) -> Result<Value, JmapError> {
    let (name, args, call_id) = first_method_response(body)?;
    if call_id != expected_call_id {
        return Err(map_method_error("__call_id_mismatch__"));
    }
    if name == "error" {
        let type_str = args.get("type").and_then(Value::as_str).unwrap_or("");
        return Err(map_method_error(type_str));
    }
    if name != "Email/get" {
        return Err(map_method_error("__unexpected_method_response__"));
    }
    // Then whose data this is: a row correlated only by call id and email id can still describe
    // another account's message that happens to carry the same id.
    correlate_account(&args, expected_account_id)?;
    let entry = args
        .get("list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e.get("id").and_then(Value::as_str) == Some(expected_email_id))
        .ok_or_else(|| map_method_error("__email_not_found__"))?
        .clone();
    // The raw-text uniqueness scan this read depends on (the `Value` navigated above collapsed
    // any duplicate member, last key wins) is run by `first_method_response` for every
    // method-response parse, so it guards the correlation and navigation above as well as the
    // membership read below. One call site, no second laxer copy.
    Ok(entry)
}

/// Derive the two-state [`Placement`] from a message's `mailboxIds` set. Exactly one of the two
/// known mailboxes must be present: archive-only is Archive, inbox-only is Inbox. Both present is
/// a real divergence (a half-applied archive that never removed Inbox, or an external change)
/// and fails closed so reconcile surfaces it instead of falsely reporting "converged". Neither
/// present also fails closed, never a silent default.
fn placement_from_mailbox_ids(
    mailbox_ids: &[String],
    inbox_id: &str,
    archive_id: &str,
) -> Result<Placement, JmapError> {
    let in_archive = mailbox_ids.iter().any(|m| m == archive_id);
    let in_inbox = mailbox_ids.iter().any(|m| m == inbox_id);
    match (in_archive, in_inbox) {
        (true, false) => Ok(Placement::Archive),
        (false, true) => Ok(Placement::Inbox),
        (true, true) => Err(map_method_error("__ambiguous_placement__")),
        (false, false) => Err(map_method_error("__unexpected_placement__")),
    }
}

/// Map a normalized [`JmapError`] to the connector's id-free [`ConnectorError`], reusing aruna's
/// single transient-vs-deterministic taxonomy home ([`classify_jmap_error`]).
fn jmap_to_connector(e: &JmapError) -> ConnectorError {
    let message = "provider rejected the placement read";
    match classify_jmap_error(e) {
        FailureKind::Transient => ConnectorError::transient(message),
        FailureKind::Deterministic => ConnectorError::deterministic(message),
    }
}

// `list_inbox_page` and `fetch_body`. Both are read-only: no ADR-P010 destructive-write gate, and
// both stay on `HttpClient::post_json` (the read route).

/// Build the one-request `Email/query` plus back-referenced `Email/get` pair the inbox-page read
/// issues (RFC 8620 §3.7). `inMailbox` takes the already-resolved inbox mailbox id as a concrete
/// string, not a nested back-reference: RFC 8620 §3.7 back-references only replace a whole
/// top-level argument (the `"#argname"` form, e.g. `"#ids"` below), never a property nested
/// inside one (`filter.inMailbox`). A nested `"#inMailbox"` is the unratified
/// `draft-degennaro-jmap-refplus` extension, not base RFC 8620/8621, so it is not assumed. Role
/// resolution therefore stays [`JmapTransport::mailbox_id_for_role`]'s own round trip (reused by
/// [`HttpJmapTransport::list_inbox_page`]), and this pair is the one back-reference this crate
/// makes.
fn build_inbox_page_body(
    account_id: &str,
    inbox_mailbox_id: &str,
    position: i64,
    limit: i64,
    call_id_query: &str,
    call_id_get: &str,
) -> Value {
    json!({
        "using": [JMAP_CORE, JMAP_MAIL],
        "methodCalls": [
            [
                "Email/query",
                {
                    "accountId": account_id,
                    "filter": { "inMailbox": inbox_mailbox_id },
                    "sort": [{ "property": "receivedAt", "isAscending": false }],
                    "position": position,
                    "limit": limit,
                    "calculateTotal": true,
                },
                call_id_query,
            ],
            [
                "Email/get",
                {
                    "accountId": account_id,
                    "#ids": {
                        "resultOf": call_id_query,
                        "name": "Email/query",
                        "path": "/ids",
                    },
                    // `mailboxIds` is here for the membership re-check, not the mapping:
                    // `Email/query` and this back-referenced `Email/get` are evaluated in
                    // sequence, and a message archived between them is still in the query's
                    // `ids` and still answered by the get. See `list_inbox_page`'s doc.
                    "properties": ["id", "receivedAt", "header:From:asRaw:all", "subject", "keywords", "hasAttachment", "mailboxIds"],
                },
                call_id_get,
            ],
        ],
    })
}

/// Build the `Email/get` request the on-demand body read issues: `bodyValues` resolved via
/// `fetchTextBodyValues`/`fetchHTMLBodyValues` (RFC 8621 §4.1.4), capped at [`BODY_FETCH_CAP`] on
/// the wire via `maxBodyValueBytes` (and re-capped locally; see that constant).
fn build_email_body_fetch_body(account_id: &str, email_id: &str, call_id: &str) -> Value {
    json!({
        "using": [JMAP_CORE, JMAP_MAIL],
        "methodCalls": [[
            "Email/get",
            {
                "accountId": account_id,
                "ids": [email_id],
                "properties": ["bodyValues", "textBody", "htmlBody", "hasAttachment"],
                "fetchTextBodyValues": true,
                "fetchHTMLBodyValues": true,
                "maxBodyValueBytes": BODY_FETCH_CAP,
            },
            call_id,
        ]],
    })
}

/// Parse the `Email/query` half (response index 0) of the combined response: correlate, then read
/// `ids` (the page, in the provider's returned order, trusted as the sort order we asked for) and
/// `total` (requested via `calculateTotal: true`, the continuation decision; see
/// [`DECISION_MEMBERS`]). A malformed, missing or negative `ids` or `total` fails closed.
///
/// `total` is unsigned on the wire (RFC 8621 §5.5), so a negative value is a malformed response,
/// not a small total. Unchecked, it would flow into the continuation math (`next_position <
/// total`) and could make a page that is not the end of the mailbox read as one (a next_position
/// of 0 against a total of -1 synthesizes an authoritative empty page from a provider bug or a
/// hostile response), the same failure the missing-`total` case already refuses.
fn parse_inbox_query_response(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
    expected_position: i64,
) -> Result<(Vec<String>, i64), JmapError> {
    let (name, args, call_id) = nth_method_response(body, 0)?;
    if call_id != expected_call_id {
        return Err(map_method_error("__call_id_mismatch__"));
    }
    if name == "error" {
        let type_str = args.get("type").and_then(Value::as_str).unwrap_or("");
        return Err(map_method_error(type_str));
    }
    if name != "Email/query" {
        return Err(map_method_error("__unexpected_method_response__"));
    }
    correlate_account(&args, expected_account_id)?;
    // The response's own `position` (RFC 8621 §5.5) is what `list_inbox_page`'s continuation
    // math advances from, not the request-side value. Trusting the request side would let a
    // response that omitted `position`, or answered a different one, mint the next cursor from a
    // number the server never confirmed, skipping pages of mail (a server that started further
    // along) or re-delivering rows the reconcile above this seam would treat as fresh (a server
    // that started earlier). Absent or wrong-typed is malformed; present but different from the
    // request is its own typed inconsistency.
    let response_position = args
        .get("position")
        .and_then(Value::as_i64)
        .ok_or_else(|| map_method_error("__missing_query_position__"))?;
    if response_position != expected_position {
        return Err(map_method_error("__query_position_inconsistent__"));
    }
    let ids = args
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| map_method_error("__malformed_response__"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| map_method_error("__malformed_response__"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let total = args
        .get("total")
        .and_then(Value::as_i64)
        .ok_or_else(|| map_method_error("__missing_query_total__"))?;
    // `total` is unsigned on the wire: a negative value is a malformed shape, and admitting it
    // would let it flow into the continuation math below.
    if total < 0 {
        return Err(map_method_error("__negative_query_total__"));
    }
    Ok((ids, total))
}

/// Parse the `Email/get` half (response index 1) of the combined response into an id to row
/// lookup. [`HttpJmapTransport::list_inbox_page`] walks the query's `ids` order (not the
/// `Email/get` `list` order, which RFC 8621 does not guarantee matches the request) and maps each
/// row through [`header_summary_from_row`].
fn parse_inbox_get_response(
    body: &str,
    expected_call_id: &str,
    expected_account_id: &str,
) -> Result<(std::collections::HashMap<String, Value>, HashSet<String>), JmapError> {
    let (name, args, call_id) = nth_method_response(body, 1)?;
    if call_id != expected_call_id {
        return Err(map_method_error("__call_id_mismatch__"));
    }
    if name == "error" {
        let type_str = args.get("type").and_then(Value::as_str).unwrap_or("");
        return Err(map_method_error(type_str));
    }
    if name != "Email/get" {
        return Err(map_method_error("__unexpected_method_response__"));
    }
    correlate_account(&args, expected_account_id)?;
    let list = args
        .get("list")
        .and_then(Value::as_array)
        .ok_or_else(|| map_method_error("__malformed_response__"))?;
    let mut by_id = std::collections::HashMap::with_capacity(list.len());
    for row in list {
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| map_method_error("__malformed_response__"))?;
        // Two records with one id is an ambiguous answer: last-one-wins would let a malformed or
        // hostile response pick which record the membership and header mapping trusts. Same
        // fail-closed posture as the query-side duplicate-ids refusal.
        if by_id.insert(id.to_string(), row.clone()).is_some() {
            return Err(map_method_error("__duplicate_get_records__"));
        }
    }
    // `notFound` (RFC 8620 §5.1: ids the server was asked for and does not have) makes an id
    // absent from `list` an explained absence rather than a silent drop. The accountability walk
    // in `list_inbox_page` refuses an id in neither `list` nor `notFound`; this parse only
    // collects the set. Some servers omit an empty `notFound`, so an absent key is the empty set;
    // a present but wrong-typed one still fails closed.
    let not_found: HashSet<String> = match args.get("notFound") {
        None => HashSet::new(),
        Some(v) => v
            .as_array()
            .ok_or_else(|| map_method_error("__malformed_response__"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| map_method_error("__malformed_response__"))
            })
            .collect::<Result<HashSet<_>, _>>()?,
    };
    Ok((by_id, not_found))
}

/// Map one `Email/get` row (properties `id`, `receivedAt`, `from`, `subject`, `keywords`,
/// `hasAttachment`) into a [`HeaderSummary`]:
/// - `receivedAt` (RFC 8620 `UTCDate`) becomes `received_at` (epoch milliseconds) via
///   [`parse_jmap_utc_date`]; malformed or missing fails closed, never a guessed timestamp.
/// - `from[0].email`/`.name` become `from_addr`/`from_name`; an absent or empty `from` gives empty
///   strings, never a panic. A `from` of more than one mailbox is an empty name and the emails
///   as a list (the header row reads it as `unsupported`: valid syntax, no single sender
///   attributed, never the first mailbox's domain).
/// - `keywords` `$seen` present means `seen: true` (absent means `false`; the opposite polarity
///   of Gmail's `UNREAD` label); `$flagged` present means `flagged: true`. Reuses
///   [`true_only_member_keys`], the same true-only and I-JSON-uniqueness checks the placement
///   read applies.
/// - `hasAttachment` becomes `AttachmentPresence.has_attachments`; `count` is always `0`, since a
///   bare boolean carries no count and this crate never fabricates one.
fn header_summary_from_row(row: &Value) -> Result<HeaderSummary, JmapError> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| map_method_error("__malformed_response__"))?;
    let received_at_str = row
        .get("receivedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| map_method_error("__malformed_response__"))?;
    let received_at =
        parse_jmap_utc_date(received_at_str).ok_or_else(|| map_method_error("__malformed_received_at__"))?;
    // The raw header, every instance, through the same grammar the Gmail transport runs
    // (`aruna::mailbox::RawFrom`/`parse_from`), not the `from` convenience property. RFC 8621
    // §4.1.2.3's `from` (`header:From:asAddresses`) flattens groups and comments before this code
    // sees them, and §4.1.3 makes a plain property name the last header instance, so a message
    // with two `From:` fields would silently lose the first. `header:From:asRaw:all` answers an
    // array of every instance's raw bytes: `[]` (no header), one element (parsed by our grammar,
    // which understands groups), or more (the §3.6 violation `RawFrom::Multiple`, always
    // `Malformed`, as in the Gmail arm).
    //
    // The property is always requested and `:all` is never `null`, so an absent property, `null`
    // or non-array is malformed, never "no From". Every member must be a string or the whole read
    // fails (`[7, "trusted@…"]` must not read as a trusted singleton). Only a well-typed `[]` is
    // `RawFrom::Absent`.
    let instances = row
        .get("header:From:asRaw:all")
        .and_then(Value::as_array)
        .ok_or_else(|| map_method_error("__malformed_response__"))?
        .iter()
        .map(|v| v.as_str().ok_or_else(|| map_method_error("__malformed_response__")))
        .collect::<Result<Vec<&str>, _>>()?;
    let raw_from = match instances.as_slice() {
        [] => aruna::mailbox::RawFrom::Absent,
        [only] => aruna::mailbox::RawFrom::Single((*only).to_string()),
        many => aruna::mailbox::RawFrom::Multiple(many.len()),
    };
    let parsed_from = aruna::mailbox::parse_from(raw_from);
    // Only the display-name half, which arrives already decoded by the parser's own `phrase()`
    // (per word, provenance-aware: a quoted-string is literal), after the grammar has fixed what
    // is the name half and what is the address half. The address is never decoded (an
    // encoded-word token there stays wire syntax, as in the Gmail arm's decode-name-only order),
    // nor is `subject`, which the server has already decoded (RFC 8621's `Email` object has no
    // encoded `Subject` text to re-decode). `decode_rfc2047` is not called on the name again; a
    // second pass would double-decode.
    let from_name = parsed_from.display_name;
    let from_addr = parsed_from.from_addr;
    // `subject` is `String|null` (RFC 8621) and always requested: `null` is "no subject" (`""`);
    // absent or any other type is malformed, never a default.
    let subject = match row.get("subject") {
        Some(Value::String(subject)) => subject.clone(),
        Some(Value::Null) => String::new(),
        _ => return Err(map_method_error("__malformed_response__")),
    };
    let keywords = true_only_member_keys(row, "keywords")?;
    let seen = keywords.iter().any(|k| k == "$seen");
    let flagged = keywords.iter().any(|k| k == "$flagged");
    let has_attachments = row
        .get("hasAttachment")
        .and_then(Value::as_bool)
        .ok_or_else(|| map_method_error("__malformed_response__"))?;
    Ok(HeaderSummary {
        provider_id: ProviderMessageId(id.to_string()),
        received_at,
        from_addr,
        from_name,
        subject,
        seen,
        flagged,
        attachments: AttachmentPresence {
            has_attachments,
            count: 0,
        },
    })
}

/// Is this `Email/get` row still in `mailbox_id`? The JMAP counterpart of the Gmail arm's `INBOX`
/// re-check (`aruna-gmail`'s `fetch_header_summary`).
///
/// `Email/query` and the back-referenced `Email/get` are evaluated in sequence (RFC 8620 §3.7),
/// not against one snapshot, so a message archived, moved or deleted in that gap is still in the
/// query's `ids` and answered by the get with the inbox gone from its `mailboxIds`. Mapping it
/// anyway would hand the caller a row the provider no longer considers inbox mail, and the
/// window reconcile would write it back into the local Inbox. Membership is re-asserted on the
/// answer we got, and the row is skipped when it fails.
///
/// The read goes through [`true_only_member_keys`], so an absent or nonconforming `mailboxIds`
/// fails the read closed rather than skipping quietly: an `Email` always belongs to at least one
/// mailbox, and a silent skip would be indistinguishable from a genuine archive. (Unlike Gmail,
/// where ProtoJSON legitimately omits an empty `labelIds`, absence here is malformed.)
fn row_is_in_mailbox(row: &Value, mailbox_id: &str) -> Result<bool, JmapError> {
    Ok(true_only_member_keys(row, "mailboxIds")?
        .iter()
        .any(|m| m == mailbox_id))
}

/// Decode a [`ContinuationToken`] into the `Email/query` `position` for the next
/// `list_inbox_page` call. `None` (the first page) is position `0`. A malformed or negative token
/// fails closed rather than guessing a position: the token is opaque to every caller above this
/// transport, so a corrupted one is refused, never silently clamped to a wrong page.
fn parse_continuation_position(token: Option<&ContinuationToken>) -> Result<i64, JmapError> {
    match token {
        None => Ok(0),
        Some(ContinuationToken(s)) => s
            .parse::<i64>()
            .ok()
            .filter(|p| *p >= 0)
            .ok_or_else(|| map_method_error("__malformed_continuation_token__")),
    }
}

/// What joins two sequential `textBody` parts. RFC 8621 §4.1.4 lists them as content to display
/// in order, and a plain-text message's parts are separate blocks (body, `-- ` signature,
/// forwarded section); running them together would fuse the last line of one into the first line
/// of the next. A newline is the minimum that keeps the boundary visible without inventing text.
/// `htmlBody` parts take the empty joiner: any character inserted between two HTML fragments is
/// markup we authored, and the conversion boundary owns what that HTML becomes.
const TEXT_PART_JOINER: &str = "\n";

/// Every listed `textBody`/`htmlBody` part's value, in the provider's order, resolved through
/// `bodyValues` (RFC 8621 §4.1.4 / §4.4.1) and concatenated with `joiner`. `Ok(None)` when the
/// list is absent or empty (a genuinely absent textual body, never fabricated). A part that is
/// listed but cannot be resolved (no `partId`, or no matching `bodyValues` entry despite
/// `fetchTextBodyValues`/`fetchHTMLBodyValues: true`) is a malformed response, never reported as
/// "no textual body".
///
/// All parts are read because these are lists of sequential content, not ranked alternatives:
/// `parts.first()` would silently drop the signature block and every forwarded section. The
/// provider already sent every value, so this does not widen the surface.
///
/// The cap applies to the aggregate. Resolving stops at the first part that would carry the
/// concatenation past `cap` (the prefix that fits is kept, clipped at a char boundary) and
/// `truncated` is `true`, so the caller never receives N times `cap` bytes. A later part's own
/// `isTruncated` counts too.
fn body_parts_text(
    entry: &Value,
    list_property: &str,
    joiner: &str,
    cap: usize,
) -> Result<Option<(String, bool)>, JmapError> {
    // Absent and present-but-wrong-type are different wire facts: collapsing them with
    // `.and_then(Value::as_array)` would read a malformed `"textBody": "oops"` as the "no
    // textual body" absence instead of failing closed. The property is looked up first, then
    // typed.
    let parts = match entry.get(list_property) {
        None => return Ok(None),
        Some(value) => value
            .as_array()
            .ok_or_else(|| map_method_error("__malformed_response__"))?,
    };
    if parts.is_empty() {
        return Ok(None);
    }
    let mut out = String::new();
    let mut truncated = false;
    for (index, part) in parts.iter().enumerate() {
        if out.len() >= cap {
            // The budget is spent and parts remain: stop reading, and say so.
            truncated = true;
            break;
        }
        let part_id = part
            .get("partId")
            .and_then(Value::as_str)
            .ok_or_else(|| map_method_error("__malformed_response__"))?;
        let value_entry = entry
            .get("bodyValues")
            .and_then(Value::as_object)
            .and_then(|m| m.get(part_id))
            .ok_or_else(|| map_method_error("__malformed_response__"))?;
        let value = value_entry
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| map_method_error("__malformed_response__"))?;
        // The same absent vs present-but-wrong-type split as `textBody`/`htmlBody`, one level
        // down. `.and_then(Value::as_bool).unwrap_or(false)` would collapse a genuinely absent
        // `isTruncated` (optional per RFC 8621 §4.1.4, where `false` is the honest default) and a
        // present `"isTruncated": "true"`/`42` into the same `false`, reporting a partial body as
        // complete. Absent still defaults to `false`; present-but-wrong-typed fails closed.
        truncated |= match value_entry.get("isTruncated") {
            None => false,
            Some(v) => v.as_bool().ok_or_else(|| map_method_error("__malformed_response__"))?,
        };
        if index > 0 && !joiner.is_empty() {
            if out.len() + joiner.len() > cap {
                truncated = true;
                break;
            }
            out.push_str(joiner);
        }
        let room = cap - out.len();
        if value.len() > room {
            let mut clipped = false;
            out.push_str(&cap_body_text(value.to_string(), room, &mut clipped));
            truncated = true;
            break;
        }
        out.push_str(value);
    }
    Ok(Some((out, truncated)))
}

/// Clip `s` to at most `cap` bytes, at the nearest `char` boundary at or below `cap`, recording
/// whether clipping happened: the local half of [`BODY_FETCH_CAP`]'s defense in depth (the
/// provider's own `maxBodyValueBytes`/`isTruncated` is the other). Same algorithm as
/// `aruna_gmail::transport::cap_text`; never panics, since `is_char_boundary` is checked before
/// every slice and the search terminates at `0`.
fn cap_body_text(s: String, cap: usize, truncated: &mut bool) -> String {
    if s.len() <= cap {
        return s;
    }
    *truncated = true;
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Parse an RFC 8620 §1.5 `UTCDate`/RFC 3339 timestamp (JMAP `receivedAt`) into epoch
/// milliseconds. Hand-rolled (the workspace keeps transports on their existing dependency set;
/// `aruna-gmail` needs no such parse because Gmail's `internalDate` is already epoch
/// milliseconds). Accepts `Z` or a `±HH:MM` numeric offset and an optional fractional-seconds
/// component (truncated to milliseconds); `None` on any malformed input, never a best-effort
/// guess. The calendar math is Howard Hinnant's `days_from_civil` (proleptic Gregorian,
/// integer-only).
fn parse_jmap_utc_date(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let digit = |i: usize| -> Option<i64> {
        let b = *bytes.get(i)?;
        b.is_ascii_digit().then(|| (b - b'0') as i64)
    };
    let two = |i: usize| -> Option<i64> { Some(digit(i)? * 10 + digit(i + 1)?) };
    let four = |i: usize| -> Option<i64> { Some(digit(i)? * 1000 + digit(i + 1)? * 100 + digit(i + 2)? * 10 + digit(i + 3)?) };
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let year = four(0)?;
    let month = two(5)?;
    let day = two(8)?;
    if !matches!(bytes.get(10), Some(b'T') | Some(b't')) {
        return None;
    }
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return None;
    }
    let hour = two(11)?;
    let minute = two(14)?;
    let second = two(17)?;
    let mut idx = 19usize;
    let mut millis_frac: i64 = 0;
    if bytes.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while bytes.get(idx).is_some_and(u8::is_ascii_digit) {
            idx += 1;
        }
        if idx == start {
            return None;
        }
        let frac = &s[start..idx];
        let mut digits = [0i64; 3];
        for (i, c) in frac.bytes().take(3).enumerate() {
            digits[i] = (c - b'0') as i64;
        }
        millis_frac = digits[0] * 100 + digits[1] * 10 + digits[2];
    }
    let offset_minutes: i64 = match bytes.get(idx) {
        Some(b'Z') | Some(b'z') => {
            idx += 1;
            0
        }
        Some(&sign_byte @ (b'+' | b'-')) => {
            let sign: i64 = if sign_byte == b'-' { -1 } else { 1 };
            idx += 1;
            let oh = two(idx)?;
            idx += 2;
            if bytes.get(idx) != Some(&b':') {
                return None;
            }
            idx += 1;
            let om = two(idx)?;
            idx += 2;
            // Offset bounds: unchecked, `+99:99` would parse into a timestamp about 4 days off.
            // RFC 3339 §4.2's grammar allows 00-23/00-59, but no real zone exceeds ±14:00 (the
            // IANA maximum: +14:00 Line Islands, -12:00 Baker Island), so that is the bound.
            if om > 59 || oh * 60 + om > MAX_OFFSET_MINUTES {
                return None;
            }
            sign * (oh * 60 + om)
        }
        _ => return None,
    };
    if idx != bytes.len() {
        return None;
    }
    // Calendar validation. A flat `1..=31` day check is not enough: `days_from_civil` is pure
    // arithmetic with no notion of an invalid input, so `2024-02-31` would silently normalize
    // forward to 2024-03-02 and a row with an impossible instant would be ingested as real. The
    // day is checked against the length of its own month (leap-aware), and an impossible date
    // fails closed through the caller's `__malformed_received_at__` error.
    if !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let total_seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    Some(total_seconds * 1_000 + millis_frac)
}

/// The largest UTC offset any real zone uses, in minutes (+14:00, IANA's maximum); the bound
/// [`parse_jmap_utc_date`] validates an `±HH:MM` offset against.
const MAX_OFFSET_MINUTES: i64 = 14 * 60;

/// How many days month `m` of year `y` has, proleptic-Gregorian and leap-aware (a leap year is
/// divisible by 4, except centuries not divisible by 400). `m` is assumed already checked to be
/// `1..=12`; anything else answers 0, which fails every day check.
fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil`: proleptic-Gregorian civil date to days since the epoch
/// (1970-01-01), integer-only (public-domain algorithm). `y`/`m`/`d` are assumed already
/// range-checked by the caller.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

// The HTTP seam and the transport. The network is behind a tiny `HttpClient` trait so the
// orchestration (status to taxonomy, body to parsers, the fidelity matrix) is testable with a
// fake; the real `reqwest::blocking` impl is the thin part the live Stalwart test exercises.

/// A completed HTTP exchange: the status and the already-read body. A completed exchange of any
/// status is `Ok` here; status mapping stays in the orchestration, and only a network-level
/// failure (no response) becomes a transport `JmapError` inside the client.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Redacted `Debug`: a real JMAP response body carries provider ids, so only the status is
/// printed and the body is reduced to its byte length.
impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HttpResponse {{ status: {}, body: <{} bytes redacted> }}",
            self.status,
            self.body.len()
        )
    }
}

/// The minimal HTTP surface the transport needs, decoupling JMAP orchestration from the network.
/// The real impl ([`ReqwestClient`]) maps network-level failures (timeout/connect/reset) to a
/// transport `JmapError`; everything above it deals only in `(status, body)`, so the JMAP
/// semantics live in pure, tested code (and an alternative HTTP backend can drop in here).
///
/// The split is by route class, not HTTP verb. Every JMAP method call, read or write, is a POST
/// to the same `apiUrl`, so the verb cannot distinguish a `Mailbox/query` from an `Email/set`.
/// The caller knows, and says so by choosing the method: reads go through
/// [`HttpClient::post_json`], mutations through [`HttpClient::post_json_mutation`]. They are not
/// interchangeable; see the mutation method's contract.
///
/// `post_json_mutation` is required, with no default body: a defaulted delegation to `post_json`
/// is the silent drift this split prevents, and a future HTTP backend must make the redirect
/// decision deliberately.
pub trait HttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, JmapError>;

    /// A read-route method call. May follow same-authority redirects: re-issuing a read is
    /// idempotent by the method's own contract.
    fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, JmapError>;

    /// A mutation-route method call (`Email/set`). Implementations must not follow redirects and
    /// must not re-send the request internally: one send-authorized attempt may produce at most
    /// one potentially effectful wire dispatch, and RFC 9110 §9.2.2 forbids automatically
    /// re-issuing a non-idempotent request whose fate is unknown. A redirect answer is surfaced
    /// as [`aruna::jmap::TransportError::MutationRedirectRefused`], never followed.
    fn post_json_mutation(&self, url: &str, body: &Value) -> Result<HttpResponse, JmapError>;
}

/// Classify a completed HTTP exchange. 2xx proceeds to the JMAP-level body parse (an `Email/set`
/// can still report a per-record failure at HTTP 200). A non-2xx first honors any RFC 8620
/// §3.6.1 request-level problem-details body (e.g. `urn:ietf:params:jmap:error:limit` with
/// `maxConcurrentRequests` is transient, which the bare status would misclassify as a
/// deterministic 4xx) and falls back to the HTTP status only when the body is not a recognizable
/// JMAP problem.
fn ensure_ok(status: u16, body: &str) -> Result<(), JmapError> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    Err(parse_request_problem(body).unwrap_or_else(|| map_http_status(status)))
}

/// Parse an RFC 8620 §3.6.1 request-level problem-details body (a JSON object whose `type` is a
/// `urn:ietf:params:jmap:error:*` URN) into the taxonomy via [`map_request_problem`]; the
/// optional `limit` property decides concurrency-transient vs fixed-shape-deterministic. Returns
/// `None` when the body is not a recognizable JMAP problem, so the caller falls back to the HTTP
/// status. Only the typed `type` (and the `limit` name) is consulted.
///
/// Not account-correlated, by RFC: a §3.6.1 problem is request-level, replacing the whole
/// response envelope because the request never reached method dispatch, so there is no
/// `accountId` to correlate. It yields only a taxonomy verdict, never data attributed to an
/// account, so [`correlate_account`] has nothing to guard.
fn parse_request_problem(body: &str) -> Option<JmapError> {
    let value: Value = serde_json::from_str(body).ok()?;
    // `type` and `limit` are both decision members here (transient vs deterministic), and both
    // collapse last-key-wins in `Value`. A body that repeats either is not a problem-details
    // document we can read: return `None` so the caller falls back to the HTTP status, as for any
    // unrecognizable body, rather than invent a verdict from an ambiguous one.
    wire_member_names_are_unique(body).ok()?;
    let type_str = value.get("type").and_then(Value::as_str)?;
    if !type_str.starts_with("urn:ietf:params:jmap:error:") {
        return None;
    }
    let limit = value.get("limit").and_then(Value::as_str);
    Some(map_request_problem(type_str, limit))
}

/// Refusal to authorize live destructive writes against a non-local / production-looking host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// Only an actual loopback host (literal `localhost` + loopback IPs) may be authorized; a
    /// `.test`/`.localhost` name is not proof of locality (it can resolve off-machine).
    NonLocalHostRefused,
}

/// ADR-P010 default-closed runtime gate: a destructive `Email/set` write is refused unless the
/// gate has been opened for the exact host being written to, and it can only be opened for a
/// local/test host, so a production mailbox can never be written. Reads (Session discovery,
/// `Mailbox/query`) are never gated.
#[derive(Debug, Clone)]
pub struct DestructiveWriteGate {
    authorized_host: Option<String>,
}

impl DestructiveWriteGate {
    /// Default-closed: every destructive write is refused.
    pub fn closed() -> Self {
        Self {
            authorized_host: None,
        }
    }

    /// Authorize destructive writes against one loopback host. Returns `Err` for any non-loopback
    /// host (a `.test`/`.localhost` name is not proof of locality, since it can resolve
    /// off-machine), so only literal `localhost` and loopback IPs qualify. This is the only way to
    /// enable live writes, and it cannot be pointed at a remote mailbox.
    pub fn allow_test_host(host: &str) -> Result<Self, GateError> {
        if is_loopback_host(host) {
            // Store the canonical host so the bind survives bracket-form differences: a gate
            // opened with bare `::1` must still permit a write whose `Url::host_str()` is `[::1]`.
            Ok(Self {
                authorized_host: Some(canonical_host(host).to_string()),
            })
        } else {
            Err(GateError::NonLocalHostRefused)
        }
    }

    /// Whether destructive writes to `host` are authorized (exact match against the opened host,
    /// both canonicalized so `::1` and `[::1]` are the same authority).
    fn permits_host(&self, host: &str) -> bool {
        self.authorized_host.as_deref() == Some(canonical_host(host))
    }
}

/// Canonical host for gate binding, comparison and locality checks. Strips the brackets only
/// around a genuine IPv6 literal (RFC 3986 §3.2.2): `[::1]` becomes `::1`, so an address has one
/// canonical key. A bracketed non-IPv6 string (`[localhost]`, `[evil.test]`, `[127.0.0.1]`,
/// partial or embedded brackets) is left intact and refused by the `IpAddr`/locality checks.
fn canonical_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .filter(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
        .unwrap_or(host)
}

/// Is `host` an actual loopback target? Loopback is proof of locality; a `.test`/`.localhost`
/// name is not, since it can resolve off-machine. This guards both the plaintext-credential check
/// and the destructive-write gate, so only literal `localhost` and loopback IPs (127.0.0.0/8,
/// `::1`) qualify.
fn is_loopback_host(host: &str) -> bool {
    // `canonical_host` strips the brackets `Url::host_str()` adds to an IPv6 literal so the
    // `IpAddr` parse sees the bare address and recognizes `::1` as local.
    host == "localhost"
        || canonical_host(host)
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Refuse to send credentials over plaintext. TLS (`https`) is allowed to any host; plaintext
/// (`http`) only to an actual loopback host (the fixture). A non-local `http` connect would send
/// the bearer token or Basic password on the session-discovery request in cleartext, so it is
/// refused deterministically before any socket.
fn require_tls_or_local(base_url: &str) -> Result<(), JmapError> {
    let url = reqwest::Url::parse(base_url).map_err(|_| map_method_error("__bad_base_url__"))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() == "http" && is_loopback_host(url.host_str().unwrap_or("")) {
        return Ok(());
    }
    Err(map_method_error("__plaintext_credentials_refused__"))
}

/// The host of a URL, if parseable; binds the destructive-write gate to the exact target the
/// `Email/set` would hit (so a server returning an `apiUrl` on a different host is refused).
fn host_of(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Do two URLs share the same scheme, host and port? Bounds redirect-following: a request may
/// only follow a redirect within the authority it was authorized and gated for, never to a new
/// authority (or a scheme downgrade) that the TLS guard and write gate never saw.
fn same_authority(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Rebase an advertised JMAP `apiUrl` onto the authority we actually connected to: keep the
/// server's path and query, take scheme, host and port from `base_url`. Used only by the local
/// test fixture, whose advertised `apiUrl` is built from its configured hostname (e.g.
/// `https://localhost/jmap/`) and is not the reachable test mapping
/// (`http://localhost:18080/jmap/`). Production does not rebase: it requires the advertised
/// `apiUrl` to be the same authority it connected and authenticated to, so a malicious Session
/// cannot retarget credentialed traffic (`authed_method_url`; CWE-346). A genuine
/// cross-authority provider would need an explicit reviewed allowlist.
fn rebase_api_url(advertised: &str, base_url: &str) -> Option<String> {
    let advertised = reqwest::Url::parse(advertised).ok()?;
    let mut rebased = reqwest::Url::parse(base_url).ok()?;
    rebased.set_path(advertised.path());
    rebased.set_query(advertised.query());
    Some(rebased.to_string())
}

/// The live JMAP transport: discovers the Session once (caching `apiUrl` and the mail primary
/// account below the seam), then drives `Mailbox/query` and `Email/set` over HTTP. Generic over
/// the HTTP client so the orchestration is testable with a fake.
///
/// `Debug` is hand-written and redacted: `connection_base` is a provider endpoint/tenant URL that
/// could carry userinfo, so it must never reach `{:?}` / `expect_err` output (as with `Auth` and
/// `SessionInfo`).
pub struct HttpJmapTransport<C = ReqwestClient> {
    client: C,
    session: SessionInfo,
    /// ADR-P010 default-closed runtime gate guarding destructive `Email/set` writes.
    gate: DestructiveWriteGate,
    /// Monotonic source of a distinct method-call id per request, so response correlation can
    /// disambiguate requests of the same method.
    call_seq: std::sync::atomic::AtomicU64,
    /// The authority we connected and authenticated to. Authenticated method calls must stay on
    /// it: a malicious Session must not be able to retarget credentialed traffic to another host
    /// (CWE-346).
    connection_base: reqwest::Url,
}

impl<C: std::fmt::Debug> std::fmt::Debug for HttpJmapTransport<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: `connection_base` is a provider endpoint/tenant URL that can carry userinfo.
        // `session` already redacts its `api_url`.
        f.debug_struct("HttpJmapTransport")
            .field("client", &self.client)
            .field("session", &self.session)
            .field("gate", &self.gate)
            .field("call_seq", &self.call_seq)
            .field("connection_base", &"<redacted>")
            .finish()
    }
}

impl<C: HttpClient> HttpJmapTransport<C> {
    /// Connect: fetch the Session resource from `<base_url>/.well-known/jmap` and cache it. A
    /// non-2xx status or an unusable Session body is a deterministic, id-free failure.
    fn connect_with(client: C, base_url: &str) -> Result<Self, JmapError> {
        // Never send credentials over plaintext to a non-local host; refuse before the
        // session-discovery request is built.
        require_tls_or_local(base_url)?;
        // Remember the authority we connect and authenticate to, so authenticated method calls
        // can be bound to it (CWE-346): the Session `apiUrl` must not retarget credentialed
        // traffic elsewhere.
        let connection_base =
            reqwest::Url::parse(base_url).map_err(|_| map_method_error("__bad_base_url__"))?;
        let url = format!("{}/.well-known/jmap", base_url.trim_end_matches('/'));
        let resp = client.get(&url)?;
        ensure_ok(resp.status, &resp.body)?;
        let session = parse_session(&resp.body)?;
        // The guard must also cover the Session-advertised apiUrl (where the authenticated
        // Mailbox/query and Email/set POST): a Session must not downgrade those to plaintext on
        // a non-local host. The fixture path then rebases it via with_api_base.
        require_tls_or_local(&session.api_url)?;
        // Default-closed: destructive writes are refused until explicitly opened (ADR-P010).
        Ok(Self {
            client,
            session,
            gate: DestructiveWriteGate::closed(),
            call_seq: std::sync::atomic::AtomicU64::new(0),
            connection_base,
        })
    }

    /// The destination for an authenticated method call: the cached Session apiUrl, but only if
    /// it is the same authority we connected and authenticated to. A malicious or compromised
    /// Session must not be able to retarget credentialed `Mailbox/query` and `Email/set` traffic
    /// to a different host (CWE-346). Production never silently rebases; a genuine
    /// cross-authority provider would need an explicit reviewed allowlist. (The loopback
    /// fixture's `with_api_base` rebases onto the same connection authority, so it satisfies
    /// this check.)
    fn authed_method_url(&self) -> Result<&str, JmapError> {
        let api = reqwest::Url::parse(&self.session.api_url)
            .map_err(|_| map_method_error("__bad_api_url__"))?;
        if !same_authority(&self.connection_base, &api) {
            return Err(map_method_error("__api_url_cross_authority__"));
        }
        Ok(&self.session.api_url)
    }

    /// Mint a distinct method-call id for the next request, so a stale or replayed response from
    /// one lookup cannot satisfy another request's correlation check, even for the same method.
    fn next_call_id(&self) -> String {
        format!(
            "c{}",
            self.call_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    /// Enable destructive writes against the gate's authorized host (the ADR-P010 flag). Without
    /// it, `email_set` refuses. The live fixture test opens it for localhost only; a
    /// `DestructiveWriteGate` cannot be built for a production host.
    pub fn with_destructive_writes(mut self, gate: DestructiveWriteGate) -> Self {
        self.gate = gate;
        self
    }

    /// Rebase the cached `apiUrl` onto `base_url`'s authority (fixture-only; see
    /// `rebase_api_url`). Private and loopback-only: only `connect_for_test_fixture` calls it, and
    /// a rebase is adopted only when the new authority is an actual loopback host. That keeps the
    /// "production honors the Session-advertised `apiUrl`" invariant enforceable: the public
    /// surface offers no way to retarget authenticated method calls (which carry the credential)
    /// at a remote host. A no-op if either URL is unparseable or the rebased host is non-loopback.
    fn with_api_base(mut self, base_url: &str) -> Self {
        if let Some(rebased) = rebase_api_url(&self.session.api_url, base_url) {
            // Adopt the rebase only for a loopback authority (the fixture). A non-loopback target,
            // even over TLS, is ignored: the cached, already-validated Session apiUrl stands, so
            // a rebase can never exfiltrate the credential to a remote host. The plaintext guard
            // still applies on top.
            let loopback = host_of(&rebased).is_some_and(|h| is_loopback_host(&h));
            if loopback && require_tls_or_local(&rebased).is_ok() {
                self.session.api_url = rebased;
            }
        }
        self
    }

    /// The cached Session discovery result (below the seam). Test-only inspection hook.
    #[cfg(test)]
    fn session(&self) -> &SessionInfo {
        &self.session
    }
}

impl<C: HttpClient> JmapTransport for HttpJmapTransport<C> {
    fn mailbox_id_for_role(
        &self,
        account: &AccountId,
        role: MailboxRole,
    ) -> Result<Option<MailboxId>, JmapError> {
        // Bind credentialed traffic to the connection authority before the POST.
        let api_url = self.authed_method_url()?;
        let call_id = self.next_call_id();
        let body = build_mailbox_query_body(&account.0, role, &call_id);
        let resp = self.client.post_json(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        parse_mailbox_query_response(&resp.body, &call_id, &account.0)
    }

    fn email_set(&self, request: &EmailSetRequest) -> Result<(), JmapError> {
        // Bind the destructive write to the connection authority first: a malicious Session
        // apiUrl must not retarget the credentialed Email/set to another host (CWE-346).
        let api_url = self.authed_method_url()?;
        // ADR-P010 default-closed gate: refuse the destructive write, before any network call,
        // unless it was explicitly authorized for the exact host we would write to. A malformed
        // api_url host fails closed. The refusal is typed rather than routed through the
        // method-error table: the synthetic `__destructive_writes_disabled__` string would fall
        // into the deterministic `MethodError::Unknown` bucket, making a local pre-socket refusal
        // bit-identical to an unrecognized provider method answer. `apply` runs post-authorization,
        // where those two must classify oppositely (proven-no-wire vs ISSUANCE_UNKNOWN).
        let permitted = host_of(api_url).is_some_and(|host| self.gate.permits_host(&host));
        if !permitted {
            return Err(JmapError::Transport(TransportError::LocalWriteGateRefused));
        }
        // Total dispatch: an unrecognized or empty patch shape fails closed before the network,
        // never a filtered or partial body reported as success (RFC 8620 §5.3: the patch must
        // be consumed exhaustively).
        let updates = request
            .typed_updates()
            .map_err(|_| map_method_error("__unrecognized_patch__"))?;
        // One email per set; `typed_updates()` already rejected empty.
        let email_id = updates
            .first()
            .map(|(id, _)| *id)
            .ok_or_else(|| map_method_error("__empty_email_set__"))?;
        let call_id = self.next_call_id();
        let body = build_email_set_body(request.account_id(), &updates, &call_id);
        // The mutation route (one-wire contract). This is the one call in the crate that can
        // change provider state, so it alone goes through `post_json_mutation`: no
        // redirect-following, no internal re-send. Every other method call is a read and keeps
        // the same-authority redirect chain.
        let resp = self.client.post_json_mutation(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        // An HTTP-200 can still carry a per-record `notUpdated` failure; the response parser
        // routes it through the taxonomy, id-free.
        parse_email_set_response(&resp.body, email_id, &call_id, request.account_id())
    }

    /// The account's RFC 8621 `Mailbox` state cursor, read as a `Mailbox/get` that asks for no
    /// records, only the response's `state` token. Read-only: no ADR-P010 gate; credentialed
    /// traffic is bound to the connection authority like every other method call.
    ///
    /// The result is typed: an `Option<String>` would erase every failure cause to `None`,
    /// laundering a deterministic 401/403 (auth/permission) into the same answer as a transient
    /// timeout. `reverify_role_basis` classifies the typed error through the JMAP taxonomy, so an
    /// auth failure re-verifying a move basis dead-letters instead of retry-looping.
    fn mailbox_state(&self, account: &AccountId) -> Result<String, JmapError> {
        let api_url = self.authed_method_url()?;
        let call_id = self.next_call_id();
        let body = build_mailbox_get_state_body(&account.0, &call_id);
        let resp = self.client.post_json(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        parse_mailbox_get_state(&resp.body, &call_id, &account.0)
    }

    /// The capture read: one `Email/get` for the one id, `properties` narrowed to `mailboxIds` +
    /// `keywords`, parsed with the same true-only and I-JSON-uniqueness checks as the placement
    /// parse (`parse_email_get_current_state`). Read-only: no ADR-P010 gate. Content-free: ids
    /// and keyword names only.
    fn email_current_state(
        &self,
        account: &AccountId,
        email: &EmailId,
    ) -> Result<EmailCurrentState, JmapError> {
        let api_url = self.authed_method_url()?;
        let call_id = self.next_call_id();
        let body = build_email_get_body(
            &account.0,
            &email.0,
            &["mailboxIds", "keywords"],
            &call_id,
        );
        let resp = self.client.post_json(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        parse_email_get_current_state(&resp.body, &call_id, &account.0, &email.0)
    }

    /// The inbox-page read: resolve the inbox mailbox id via the existing
    /// [`JmapTransport::mailbox_id_for_role`] round trip (see `build_inbox_page_body` for why
    /// this stays a separate call), then issue the one combined `Email/query` plus
    /// back-referenced `Email/get` request (RFC 8620 §3.7). Read-only: no ADR-P010 gate; stays on
    /// [`HttpClient::post_json`] both times.
    fn list_inbox_page(
        &self,
        account: &AccountId,
        page_size: i64,
        continuation: Option<&ContinuationToken>,
    ) -> Result<ListedPage, JmapError> {
        // The effective page size: the house clamp, then the server's own `maxObjectsInGet`
        // ceiling on top of it. Both halves of the combined request are bound by this one number
        // (the `Email/query` `limit` decides how many ids the back-referenced `Email/get` is
        // handed), so bounding only the get would still send an over-large get and earn a
        // `requestTooLarge` that fails the whole round trip.
        let limit = match self.session.max_objects_in_get {
            Some(ceiling) => clamp_page_size(page_size).min(ceiling),
            None => clamp_page_size(page_size),
        };
        let position = parse_continuation_position(continuation)?;
        let inbox = self
            .mailbox_id_for_role(account, MailboxRole::Inbox)?
            .ok_or_else(|| map_method_error("__no_inbox_mailbox__"))?;
        let api_url = self.authed_method_url()?;
        let call_id_query = self.next_call_id();
        let call_id_get = self.next_call_id();
        let body = build_inbox_page_body(
            &account.0,
            &inbox.0,
            position,
            limit,
            &call_id_query,
            &call_id_get,
        );
        let resp = self.client.post_json(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        let (ids, total) =
            parse_inbox_query_response(&resp.body, &call_id_query, &account.0, position)?;
        // Consistent-page check, on the untruncated answer, before the hostile-response bound
        // below looks at `limit`. Two ways a server can lie about the walk it just answered:
        //   - a duplicate id inflates `ids.len()`, so `next_position = position + ids.len()`
        //     overcounts how far the walk advanced and the continuation can skip rows;
        //   - `total < position + ids.len()` means the server's own total is smaller than the
        //     page it handed back, so the continuation math (`next_position < total`) can land
        //     on `next = None` ("exhausted") off a page that never proved it was complete.
        //     `walk_exhausted` (the caller above this transport) sweeps the local Inbox on
        //     exactly that signal.
        // Both are checked on the raw `ids` (before the `limit` truncation), since either is the
        // same lie about the server's own walk whether or not `limit` cuts the page first. Fail
        // closed: a typed error, never a page or continuation minted off an untrustworthy answer.
        let unique_ids: HashSet<&str> = ids.iter().map(String::as_str).collect();
        if unique_ids.len() != ids.len() {
            return Err(map_method_error("__duplicate_query_ids__"));
        }
        // The check fires only when returned ids extend beyond the advertised total. A shrink
        // between pages (continuation at position 5, concurrent archives drop total to 3)
        // validly answers `ids: []`: the exhausted-walk shape the continuation math handles
        // (`total <= position` gives `next = None`). Refusing it would wedge the held cursor
        // until a page-1 restart.
        //
        // Checked arithmetic: `position` comes from an opaque continuation token parsed as an
        // unbounded `i64` (`parse_continuation_position`), so a value near `i64::MAX` plus a
        // nonempty page would overflow (a debug build panics, a release build wraps to a
        // negative sum that corrupts every downstream check). A token this crate cannot safely
        // advance from is malformed, so overflow gets the same typed refusal as a malformed
        // token, never a panic or a wrapped cursor.
        let raw_advanced = position
            .checked_add(ids.len() as i64)
            .ok_or_else(|| map_method_error("__malformed_continuation_token__"))?;
        if !ids.is_empty() && total < raw_advanced {
            return Err(map_method_error("__query_total_inconsistent__"));
        }
        // Hostile-response bound (the same shape as the Gmail arm's bound on `messages.list`).
        // `limit` is what we asked for: RFC 8621 §5.5 lets a server return fewer ids than the
        // limit, and nothing makes it return no more. Without this truncation one `Email/query`
        // response decides how many rows the caller ingests. The bound is the already-clamped
        // limit this request carried, applied before the mapping loop and the continuation math,
        // so extra ids are never mapped, never returned, and never skipped over by the next
        // page's position. A page that loses rows anywhere between the provider's raw answer and
        // the mapped summaries (this truncation, a `notFound` skip, a membership-recheck skip) is
        // not a contiguous window: a live row can sit between two survivors, and a monotonicity
        // check over the survivors alone would still bless the page as a coverage floor that
        // condemns it. Lossy means `chronological: false` (ingest everything, remove nothing).
        let raw_ids_len = ids.len();
        let ids = &ids[..ids.len().min(limit.max(0) as usize)];
        let mut lossy = raw_ids_len > ids.len();
        let (rows_by_id, not_found_ids) =
            parse_inbox_get_response(&resp.body, &call_id_get, &account.0)?;
        // Walk the query's `ids` order (not the `Email/get` `list` order, which RFC 8621 does not
        // guarantee matches the request) so the page stays newest-first as sorted.
        //
        // Every id the `Email/query` named must be accounted for: answered here (the `Some(row)`
        // arm) or explicitly reported gone via `notFound` (a legitimate race: deleted between the
        // query and the get within this request). An id in neither is the get half silently
        // dropping a row the query just said exists, and the caller's chronological reconcile
        // would read the omission as "no longer exists" and delete a local row the query's own
        // answer said was still there.
        let mut summaries = Vec::with_capacity(ids.len());
        for id in ids {
            match rows_by_id.get(id) {
                Some(row) => {
                    // The membership re-check, before anything is mapped (see
                    // `row_is_in_mailbox`). The inbox mailbox id we filtered the query by must
                    // still be in the row's `mailboxIds`, or it is no longer inbox mail and the
                    // page comes back one row shorter. It counts toward nothing: not the limit
                    // (the id was already spent), nor the continuation (`position + ids.len()` is
                    // the provider's own walk, and skipping a row here must not make the next
                    // page start early and skip mail).
                    if !row_is_in_mailbox(row, &inbox.0)? {
                        lossy = true;
                        continue;
                    }
                    summaries.push(header_summary_from_row(row)?);
                }
                None if not_found_ids.contains(id) => {
                    // The legitimate race: the `Email/get` half says this id is gone. Skipped, not
                    // a hard failure, and it counts toward nothing, like the membership skip.
                    lossy = true;
                }
                None => return Err(map_method_error("__query_id_unaccounted_for__")),
            }
        }
        // The same checked arithmetic as above, on the bounded `ids` this page consumed: the
        // minted next position must not overflow into a wrapped or negative cursor either.
        // overflow into a wrapped/negative cursor either.
        let next_position = position
            .checked_add(ids.len() as i64)
            .ok_or_else(|| map_method_error("__malformed_continuation_token__"))?;
        // A non-advancing continuation is refused, never re-emitted. The next position is
        // `position + ids.len()`; if the provider answers an empty `ids` while its own `total`
        // still claims more rows past `position` (`next_position < total` with `ids.is_empty()`),
        // the token this page would mint is byte-identical to the one the caller just sent, and a
        // caller that trusts `has_more` would loop forever on the same request with no signal. A
        // non-empty `ids` always advances, so this only fires on the empty-`ids` shape; a
        // genuinely exhausted mailbox (`total <= position`) still yields `next = None`.
        if ids.is_empty() && next_position < total {
            return Err(map_method_error("__non_advancing_continuation__"));
        }
        let next = (next_position < total).then(|| ContinuationToken(next_position.to_string()));
        // The raw answer, reported alongside the mapped one: `summaries` can be empty because the
        // query matched nothing or because the membership re-check and notFound skip dropped
        // every row. The reconcile above this seam does opposite things with those two (the
        // first clears the local Inbox), so the `Email/query` `ids` list, the provider's own
        // answer before any filtering here, reports emptiness.
        //
        // The request asks for a sort (`build_inbox_page_body`), but a scrambled or hostile
        // answer would still carry real mail through the mapping loop, and nothing else checks
        // that it kept the sort. So `received_at` must be non-increasing across `summaries`; a
        // violation fails closed to `false` (the Gmail arm's safe value). The page still ingests
        // but is not trusted as a coverage window, so the reconcile runs its conservative
        // no-removal pass. Monotonicity over the survivors also proves nothing when rows were
        // lost (truncation, notFound, membership skip), since the gap can hide a live row above
        // the floor, so a lossy page is never a coverage window.
        let chronological = !lossy
            && summaries
                .windows(2)
                .all(|pair| pair[0].received_at >= pair[1].received_at);
        Ok(ListedPage {
            rows: summaries,
            next,
            raw_page_was_empty: ids.is_empty(),
            chronological,
        })
    }

    /// The on-demand body read: one `Email/get` for the one id, `bodyValues` resolved via
    /// `fetchTextBodyValues`/`fetchHTMLBodyValues`, capped at [`BODY_FETCH_CAP`] on the wire
    /// (`maxBodyValueBytes`) and locally (`cap_body_text`). Read-only: no ADR-P010 gate. Reuses
    /// `parse_email_get_row`, the same id/account navigation the placement and capture reads use.
    fn fetch_body(&self, account: &AccountId, email: &EmailId) -> Result<RawBody, JmapError> {
        let api_url = self.authed_method_url()?;
        let call_id = self.next_call_id();
        let body = build_email_body_fetch_body(&account.0, &email.0, &call_id);
        let resp = self.client.post_json(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        let entry = parse_email_get_row(&resp.body, &call_id, &account.0, &email.0)?;
        // Truncation is tracked per representation: a shared flag would mark the displayed
        // (selected) representation truncated when only its unselected sibling hit the cap.
        let mut text_truncated = false;
        let mut html_truncated = false;
        // Every listed part, in order, capped across the whole concatenation. The cap is applied
        // inside the resolver, so an over-cap concatenation is never assembled in memory first.
        let text = match body_parts_text(&entry, "textBody", TEXT_PART_JOINER, BODY_FETCH_CAP)? {
            Some((value, part_truncated)) => {
                text_truncated |= part_truncated;
                Some(value)
            }
            None => None,
        };
        let html = match body_parts_text(&entry, "htmlBody", "", BODY_FETCH_CAP)? {
            Some((value, part_truncated)) => {
                html_truncated |= part_truncated;
                Some(value)
            }
            None => None,
        };
        let has_attachments = entry
            .get("hasAttachment")
            .and_then(Value::as_bool)
            .ok_or_else(|| map_method_error("__malformed_response__"))?;
        Ok(RawBody {
            text,
            html,
            attachments: AttachmentPresence {
                has_attachments,
                count: 0,
            },
            text_truncated,
            html_truncated,
        })
    }
}

impl<C: HttpClient> HttpJmapTransport<C> {
    /// Read a message's current `mailboxIds` via `Email/get`, the read-side truth for divergence
    /// correction. Read-only: no ADR-P010 gate. Credentialed traffic is bound to the connection
    /// authority first, like every other method call.
    pub fn email_get_mailbox_ids(
        &self,
        account: &AccountId,
        email_id: &EmailId,
    ) -> Result<Vec<String>, JmapError> {
        let api_url = self.authed_method_url()?;
        let call_id = self.next_call_id();
        let body = build_email_get_body(&account.0, &email_id.0, &["mailboxIds"], &call_id);
        let resp = self.client.post_json(api_url, &body)?;
        ensure_ok(resp.status, &resp.body)?;
        parse_email_get_mailbox_ids(&resp.body, &call_id, &account.0, &email_id.0)
    }
}

/// A [`ProviderPlacement`] over the live JMAP transport: reads a message's real `mailboxIds` and
/// derives the [`Placement`]. Holds the resolved account and inbox/archive mailbox ids
/// (single-account); the `account: &str` arg is the Photon-local handle and is not re-resolved.
pub struct JmapProviderPlacement<'a, C: HttpClient = ReqwestClient> {
    transport: &'a HttpJmapTransport<C>,
    account: AccountId,
    inbox: MailboxId,
    archive: MailboxId,
}

impl<'a, C: HttpClient> JmapProviderPlacement<'a, C> {
    /// Bind the placement reader to a connected transport and the resolved inbox/archive ids.
    pub fn new(
        transport: &'a HttpJmapTransport<C>,
        account: AccountId,
        inbox: MailboxId,
        archive: MailboxId,
    ) -> Self {
        Self {
            transport,
            account,
            inbox,
            archive,
        }
    }
}

impl<C: HttpClient> ProviderPlacement for JmapProviderPlacement<'_, C> {
    fn fetch_placement(
        &self,
        _account: &str,
        id: &ProviderMessageId,
    ) -> Result<Placement, ConnectorError> {
        // The neutral opaque id becomes the JMAP-native EmailId here, at this crate's own
        // boundary; it is the same opaque text either way.
        let email_id = EmailId(id.0.clone());
        let ids = self
            .transport
            .email_get_mailbox_ids(&self.account, &email_id)
            .map_err(|e| jmap_to_connector(&e))?;
        placement_from_mailbox_ids(&ids, &self.inbox.0, &self.archive.0)
            .map_err(|e| jmap_to_connector(&e))
    }
}

impl HttpJmapTransport<ReqwestClient> {
    /// Connect to a live JMAP server: build a bearer-authenticated blocking client and run
    /// Session discovery against `<base_url>/.well-known/jmap`. This is the only public entry
    /// point; the generic `connect_with` is for hermetic tests over a fake client.
    pub fn connect(base_url: &str, token: &str) -> Result<Self, JmapError> {
        Self::connect_with(ReqwestClient::new(Auth::Bearer(token.to_string()))?, base_url)
    }

    /// Connect with HTTP Basic credentials (`Authorization: Basic ...`), as used by the
    /// self-hosted Stalwart fixture (`user@domain:password`).
    pub fn connect_basic(base_url: &str, username: &str, password: &str) -> Result<Self, JmapError> {
        let auth = Auth::Basic {
            username: username.to_string(),
            password: password.to_string(),
        };
        Self::connect_with(ReqwestClient::new(auth)?, base_url)
    }

    /// Connect to a loopback fixture (HTTP Basic) and open the destructive-write gate for the
    /// validated host. Refuses, before any network, if `base_url`'s host is not an actual
    /// loopback host (literal `localhost` + loopback IPs; a `.test`/`.localhost` name is not proof
    /// of locality), so the live integration test cannot be aimed at a real mailbox. The only
    /// built-in write-enabled entry point.
    pub fn connect_for_test_fixture(
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, JmapError> {
        let host = host_of(base_url).ok_or_else(|| map_method_error("__bad_base_url__"))?;
        let gate = DestructiveWriteGate::allow_test_host(&host)
            .map_err(|_| map_method_error("__non_local_fixture_refused__"))?;
        Ok(Self::connect_basic(base_url, username, password)?
            .with_destructive_writes(gate)
            .with_api_base(base_url))
    }
}

// The real reqwest::blocking client: the thin, network-touching part the live Stalwart
// integration test exercises. Everything above it is pure and hermetically tested.

/// How the live client authenticates to the JMAP server (RFC 8620 §8 admits either scheme).
#[derive(Clone)]
enum Auth {
    /// OAuth-style bearer token (`Authorization: Bearer ...`).
    Bearer(String),
    /// HTTP Basic (`Authorization: Basic ...`), the practical scheme for a self-hosted Stalwart
    /// fixture, which accepts `user@domain:password` without an OAuth code exchange.
    Basic { username: String, password: String },
}

/// Hand-written, redacted `Debug`: the token, password and username must never reach `{:?}`
/// output (logs, `expect_err`).
impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Auth::Basic { .. } => f.write_str("Basic(<redacted>)"),
        }
    }
}

/// The redirect policy for the read route: bound to the same authority, chain-capped.
///
/// A cross-authority redirect on an authenticated or gated request would replay credentials to a
/// host that never passed the TLS guard or the destructive-write gate. Same-authority redirects
/// (e.g. `/.well-known/jmap` to `/jmap/session`) are still followed, because re-issuing a read is
/// idempotent by the method's own contract; anything else is stopped and the 3xx surfaces as a
/// deterministic failure.
fn read_route_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        // Cap the chain (reqwest's default is 10) so a same-authority redirect loop fails fast
        // instead of following until the 30s timeout.
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        match attempt.previous().last() {
            Some(prev) if same_authority(prev, attempt.url()) => attempt.follow(),
            _ => attempt.stop(),
        }
    })
}

/// The redirect policy for the mutation route: follow nothing.
///
/// Bounding the authority (the read route's rule) protects the credential but not the selected
/// resource. reqwest replays a cloneable body across 307/308 and strips sensitive headers only
/// when the host changes, so a same-authority redirect would re-POST the authenticated
/// `Email/set` to a server-chosen path: a second credentialed provider touch under one
/// send-authorized attempt, breaching both the one-wire contract and RFC 9110 §9.2.2.
///
/// Returned as a named value, not inlined, so the drift test can assert on the constructed
/// policy rather than on behavior alone.
fn mutation_route_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::none()
}

/// The authenticated `reqwest::blocking` HTTP client backing the live transport.
///
/// Reqwest fixes the redirect policy at client-build time, with no per-request override, so the
/// read/mutation split needs two clients, identical except for that policy.
///
/// `retry::never()` is absent because it is inert in this build, as in the Gmail transport
/// (`aruna-gmail/src/transport.rs`, "The single-dispatch invariant"): reqwest's
/// `is_retryable_error` is gated behind the `http2`/`http3` features (`reqwest-0.13.4/src/retry.rs`),
/// this crate enables neither (`Cargo.toml`: `blocking`, `json`, `rustls`), and `Cargo.lock`
/// carries no `h2` or `h3`. The remaining library-level re-send, hyper-util's
/// `retry_canceled_requests`, is provably pre-write: hyper hands a request back only when its
/// message was never serialized onto the connection.
///
/// Warning: if the `http2` feature is ever enabled here, revisit single-dispatch. reqwest's retry
/// policy becomes live and, unlike hyper's pre-write re-dispatch, is not provably safe.
#[derive(Debug)]
pub struct ReqwestClient {
    /// The read route: session discovery plus `Mailbox/query` / `Mailbox/get` / `Email/get`.
    http: reqwest::blocking::Client,
    /// The mutation route: `Email/set` only. Follows nothing.
    http_mutation: reqwest::blocking::Client,
    auth: Auth,
}

impl ReqwestClient {
    fn new(auth: Auth) -> Result<Self, JmapError> {
        let http = Self::build(read_route_redirect_policy())?;
        let http_mutation = Self::build(mutation_route_redirect_policy())?;
        Ok(Self {
            http,
            http_mutation,
            auth,
        })
    }

    /// The shared client contract; only the redirect policy differs by route class.
    fn build(redirect: reqwest::redirect::Policy) -> Result<reqwest::blocking::Client, JmapError> {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            // Never route a credentialed request through an ambient/system proxy. reqwest's
            // default honors HTTP_PROXY / system proxy settings, which would send an
            // `http://localhost` JMAP request (plaintext, but loopback-approved by
            // require_tls_or_local) through that proxy and expose the `Authorization` header
            // off-host, defeating the loopback assumption (reproduced: a loopback GET egressed
            // to a fake HTTP_PROXY). A loopback request must stay on the host, production
            // credentials travel inside TLS, and explicit proxy support, if ever needed, should
            // be a deliberate config knob rather than an ambient env var.
            .no_proxy()
            .redirect(redirect)
            .build()
            // A client we cannot build is a deterministic local misconfiguration (id-free).
            .map_err(|_| map_method_error("__http_client_build_failed__"))
    }

    /// Apply the configured auth scheme to a request builder.
    fn authed(&self, rb: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        match &self.auth {
            Auth::Bearer(token) => rb.bearer_auth(token),
            Auth::Basic { username, password } => rb.basic_auth(username, Some(password)),
        }
    }
}

/// Does this error's source chain carry a rustls TLS certificate-validation failure? The rustls
/// backend (Cargo.toml: reqwest feature `rustls`) renders expired / self-signed /
/// hostname-mismatch / unknown-issuer failures as `invalid peer certificate: <reason>` on the
/// inner error. reqwest 0.13 exposes no typed `is_tls()`, so this phrase is the available
/// signal.
///
/// Two precautions against a false positive that would wrongly dead-letter a retryable failure:
/// (1) skip the outer reqwest error, whose `Display` embeds the request URL (a host like
/// `https://certificate.invalid/` with a DNS/connect failure must not look like a cert fault);
/// (2) match the specific rustls phrase `invalid peer certificate`, not the bare word, so URL
/// text cannot trip it. If the TLS backend ever changes from rustls, revisit this phrase.
/// Generic over `dyn Error` so it is unit-testable without a live handshake.
fn is_tls_certificate_error(err: &(dyn std::error::Error + 'static)) -> bool {
    // Start at `.source()`: the outer reqwest error's Display carries the URL, while the rustls
    // cert text lives on an inner error, so only the inner chain is a trustworthy signal.
    let mut source = err.source();
    while let Some(e) = source {
        if e.to_string().to_ascii_lowercase().contains("invalid peer certificate") {
            return true;
        }
        source = e.source();
    }
    false
}

/// Map a reqwest error (we never got a usable HTTP response) onto the transport taxonomy. A
/// builder error (a malformed or unsupported URL, e.g. a missing scheme or a Session that
/// advertised a bad `apiUrl`) is a deterministic config/protocol fault: retrying the identical
/// request fails identically, so it must not burn the retry budget. Timeouts map to `Timeout`;
/// every other network-level failure (connect refused, reset, body read) is conservatively a
/// reset, which is transient so a recoverable blip retries. No provider text is carried.
fn map_transport_error(err: &reqwest::Error) -> JmapError {
    if err.is_builder() || err.is_redirect() {
        // A malformed URL or an exhausted/looping redirect chain is a deterministic
        // config/protocol fault: retrying the identical request fails identically.
        return map_method_error("__request_build_failed__");
    }
    if is_tls_certificate_error(err) {
        // A TLS certificate-validation failure (expired / self-signed / hostname-mismatch /
        // unknown issuer) is deterministic: the same URL and credentials fail identically until
        // the server's cert or our trust store changes, so retrying only burns the budget.
        return map_method_error("__tls_certificate_invalid__");
    }
    let kind = if err.is_timeout() {
        TransportError::Timeout
    } else {
        TransportError::ConnectionReset
    };
    JmapError::Transport(kind)
}

/// An advertised body size over [`MAX_RESPONSE_WIRE_BYTES`] is refused here, on the header alone,
/// so the body is never read: the cheap half of the bound. A server that omits `Content-Length`
/// (chunked) or lies about it is caught by [`read_response_bounded`]; the two halves do not
/// substitute for one another.
///
/// The verdict is deterministic (`__oversized_response_body__` maps to `MethodError::Unknown`): a
/// provider naming an impossible size is not having a transient blip, and retrying the identical
/// request only burns the budget for the identical refusal.
fn refuse_oversized_advertised_length(content_length: Option<u64>) -> Result<(), JmapError> {
    if content_length.is_some_and(|len| len > MAX_RESPONSE_WIRE_BYTES) {
        return Err(map_method_error("__oversized_response_body__"));
    }
    Ok(())
}

/// Read at most [`MAX_RESPONSE_WIRE_BYTES`] `+ 1` bytes of a response body, refusing anything over
/// the ceiling. The extra byte distinguishes "exactly MAX" (accepted) from "over MAX" (refused);
/// nothing beyond it is materialized, so a hostile server cannot make this process allocate
/// without limit whatever its headers claimed.
///
/// Generic over `Read` so the bound is tested on the function that enforces it, not only through
/// a socket (`reqwest`'s blocking `Response` is one implementor, a synthetic reader in a test is
/// another).
///
/// The decode stays `from_utf8_lossy`, as `resp.text()` did for the `application/json` (UTF-8,
/// RFC 8259 §8.1) bodies this client speaks: this bounds how much is read, not how a malformed
/// body is classified.
/// malformed body is classified.
fn read_response_bounded<R: std::io::Read>(reader: R) -> Result<String, JmapError> {
    use std::io::Read;

    let mut buf = Vec::new();
    reader
        .take(MAX_RESPONSE_WIRE_BYTES + 1)
        .read_to_end(&mut buf)
        // A body-read I/O failure is the same conservative transient `map_transport_error` gives.
        .map_err(|_| JmapError::Transport(TransportError::ConnectionReset))?;
    if buf.len() as u64 > MAX_RESPONSE_WIRE_BYTES {
        return Err(map_method_error("__oversized_response_body__"));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Consume a completed `reqwest` response into the seam's [`HttpResponse`] under the wire bound.
/// Every route shares this tail, so the ceiling cannot drift between session discovery, the read
/// route and the mutation route. Status mapping stays above the client.
fn consume_response(resp: reqwest::blocking::Response) -> Result<HttpResponse, JmapError> {
    let status = resp.status().as_u16();
    refuse_oversized_advertised_length(resp.content_length())?;
    let body = read_response_bounded(resp)?;
    Ok(HttpResponse { status, body })
}

impl HttpClient for ReqwestClient {
    fn get(&self, url: &str) -> Result<HttpResponse, JmapError> {
        let resp = self
            .authed(self.http.get(url))
            .send()
            .map_err(|e| map_transport_error(&e))?;
        consume_response(resp)
    }

    fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, JmapError> {
        let resp = self
            .authed(self.http.post(url).json(body))
            .send()
            .map_err(|e| map_transport_error(&e))?;
        consume_response(resp)
    }

    fn post_json_mutation(&self, url: &str, body: &Value) -> Result<HttpResponse, JmapError> {
        let resp = self
            .authed(self.http_mutation.post(url).json(body))
            .send()
            .map_err(|e| map_transport_error(&e))?;
        let status = resp.status().as_u16();
        // The redirect arm. With `Policy::none()` reqwest hands the 3xx back as an ordinary
        // response, so the refusal is decided here on the status alone, before the body is
        // consulted. Reading the body first would let a hostile provider pair a 307 with an RFC
        // 8620 §3.6.1 problem-details document (`urn:ietf:params:jmap:error:limit`,
        // `maxConcurrentRequests`) and have `ensure_ok` classify the redirect as transient,
        // retrying the mutation, the duplication this route exists to prevent.
        //
        // Refusing the redirect proves the `Location` is never asked, so this route cannot
        // create a second effect. It does not prove the first one did not happen: RFC 9110
        // §15.4.4's 303 See Other is, after a POST, the canonical "the action completed, GET its
        // result there" answer. So the outcome is ISSUANCE_UNKNOWN / `ACK_AMBIGUOUS`, never
        // `ACK_REFUSED_NO_EFFECT` (see `aruna::jmap::provider_rejection`).
        if (300..400).contains(&status) {
            return Err(JmapError::Transport(TransportError::MutationRedirectRefused));
        }
        consume_response(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (the complement rule) — the JMAP half of the
    /// sender boundary: one mailbox is its address (the header row derives its domain), none is no
    /// sender, and more than one is the comma-joined list it is — a `mailbox-list` of more than
    /// one, valid syntax under RFC 5322 §3.4's `address-list` grammar, so the header row's write
    /// door reads `unsupported` (NOT `malformed`), naming no domain. Was `malformed` before the complement
    /// rule; moved here because the complement rule reclassifies every parsed-but-not-one-mailbox
    /// shape, and this joined text is exactly that shape.
    #[test]
    fn a_from_of_more_than_one_mailbox_is_kept_as_a_list_the_header_row_reads_unsupported() {
        use aruna::mailbox::{sender_facts, SenderStatus};
        // The row now carries `header:From:asRaw:all` — an array of
        // every RAW instance's bytes — never the `from` convenience property's flattened
        // EmailAddress objects.
        let row = |instances: serde_json::Value| {
            serde_json::json!({ "id": "E1", "receivedAt": "2024-01-15T10:30:00Z", "header:From:asRaw:all": instances, "subject": "s", "keywords": {}, "hasAttachment": false })
        };
        let one = header_summary_from_row(&row(serde_json::json!(["A <a@X.example>"]))).unwrap();
        assert_eq!((one.from_name.as_str(), one.from_addr.as_str()), ("A", "a@X.example"));
        assert_eq!(sender_facts(&one.from_addr), (SenderStatus::Ok, Some("x.example".to_string())));
        let none = header_summary_from_row(&row(serde_json::json!([]))).unwrap();
        assert_eq!(sender_facts(&none.from_addr), (SenderStatus::Unavailable, None));
        let two = header_summary_from_row(&row(serde_json::json!(["a@x.example, b@y.example"]))).unwrap();
        assert_eq!((two.from_name.as_str(), two.from_addr.as_str()), ("", "a@x.example, b@y.example"));
        assert_eq!(sender_facts(&two.from_addr), (SenderStatus::Unsupported, None));
    }

    /// A GROUP From, run through the parser's OWN grammar
    /// (which understands `display-name ":" [group-list] ";"`), is `Unsupported` — never `Ok` with
    /// a domain the RFC 6854 §2 server-side flattening happened to leave sitting alone in the
    /// array. Before the fix: the `from` convenience property (RFC 8621 §4.1.2.3) discards
    /// group/comment information server-side, so `[{"email":"ben@example.com"}]` (what a server
    /// answers for `Managing Partners:ben@example.com;`) was indistinguishable from a bare
    /// mailbox and came back `(Ok, "example.com")`.
    #[test]
    fn a_flattened_group_from_is_unsupported_never_ok() {
        use aruna::mailbox::{sender_facts, SenderStatus};
        let row = serde_json::json!({
            "id": "E1", "receivedAt": "2024-01-15T10:30:00Z",
            "header:From:asRaw:all": ["Managing Partners:ben@example.com;"],
            "subject": "s", "keywords": {}, "hasAttachment": false
        });
        let summary = header_summary_from_row(&row).unwrap();
        assert_eq!(sender_facts(&summary.from_addr), (SenderStatus::Unsupported, None));
    }

    /// TWO raw `From:` instances is the §3.6
    /// cardinality violation — `Malformed`, naming no domain — never RFC 8621 §4.1.3's silent
    /// last-instance projection (`(Ok, Some("trusted.example"))` before this change, discarding
    /// `real@evil.example` with no signal it ever existed).
    #[test]
    fn two_raw_from_instances_is_malformed_never_last_instance_wins() {
        use aruna::mailbox::{sender_facts, SenderStatus};
        let row = serde_json::json!({
            "id": "E1", "receivedAt": "2024-01-15T10:30:00Z",
            "header:From:asRaw:all": ["real@evil.example", "billing@trusted.example"],
            "subject": "s", "keywords": {}, "hasAttachment": false
        });
        let summary = header_summary_from_row(&row).unwrap();
        assert_eq!(sender_facts(&summary.from_addr), (SenderStatus::Malformed, None));
    }

    /// The display name is decoded ONCE, inside the parser's own
    /// `phrase()` — a word that decodes to encoded-word SYNTAX stays that syntax. A leftover
    /// `decode_rfc2047` on the transport's side would decode it a second time and show `PayPal`.
    #[test]
    fn a_double_encoded_word_stays_single_decoded() {
        let row = serde_json::json!({
            "id": "E1", "receivedAt": "2024-01-15T10:30:00Z",
            "header:From:asRaw:all": ["=?UTF-8?Q?=3D=3FUTF-8=3FQ=3FPayPal=3F=3D?= <x@evil.example>"],
            "subject": "s", "keywords": {}, "hasAttachment": false
        });
        let summary = header_summary_from_row(&row).unwrap();
        assert_eq!(summary.from_name, "=?UTF-8?Q?PayPal?=");
        assert_eq!(summary.from_addr, "x@evil.example");
    }

    /// The JMAP arm reads the SAME provenance-aware decode as the
    /// Gmail arm — a quoted encoded-word is literal (RFC 2047 §5(3)).
    #[test]
    fn an_encoded_word_inside_a_quoted_string_is_literal() {
        let row = serde_json::json!({
            "id": "E1", "receivedAt": "2024-01-15T10:30:00Z",
            "header:From:asRaw:all": ["\"=?UTF-8?Q?Legal_Hold?=\" <hold@example.com>"],
            "subject": "s", "keywords": {}, "hasAttachment": false
        });
        assert_eq!(header_summary_from_row(&row).unwrap().from_name, "=?UTF-8?Q?Legal_Hold?=");
    }

    // ---- strict typing at the JMAP boundary — a PRESENT value of the
    // wrong type is `__malformed_response__` (the deterministic `MethodError::Unknown` bucket),
    // never a default and never a dropped member ----

    /// One `Email/get` row with `overrides` merged over a well-formed baseline.
    fn r6_j2_row(overrides: serde_json::Value) -> serde_json::Value {
        let mut row = serde_json::json!({
            "id": "E1", "receivedAt": "2024-01-15T10:30:00Z",
            "header:From:asRaw:all": ["A <a@x.example>"],
            "subject": "s", "keywords": {}, "hasAttachment": false
        });
        for (k, v) in overrides.as_object().expect("an object of overrides") {
            row[k] = v.clone();
        }
        row
    }

    fn r6_j2_is_malformed(result: Result<HeaderSummary, JmapError>) {
        match result {
            Err(JmapError::Method(aruna::jmap::MethodError::Unknown)) => {}
            other => panic!("a wrong-typed present value must be __malformed_response__: {other:?}"),
        }
    }

    /// `header:From:asRaw:all` is always requested and `:all` is never null (RFC 8621: an empty
    /// array when there is no such header) — a present `7` is not "no From".
    #[test]
    fn a_wrong_typed_raw_from_property_is_a_malformed_response() {
        r6_j2_is_malformed(header_summary_from_row(&r6_j2_row(serde_json::json!({ "header:From:asRaw:all": 7 }))));
        r6_j2_is_malformed(header_summary_from_row(&r6_j2_row(serde_json::json!({ "header:From:asRaw:all": null }))));
        let mut absent = r6_j2_row(serde_json::json!({}));
        absent.as_object_mut().unwrap().remove("header:From:asRaw:all");
        r6_j2_is_malformed(header_summary_from_row(&absent));
    }

    /// Every array member must be a string: `[7, "trusted@example.com"]` was a trusted SINGLETON
    /// (the `7` filtered away), never the malformed two-instance array it is.
    #[test]
    fn a_wrong_typed_raw_from_member_is_a_malformed_response_never_a_survivor() {
        r6_j2_is_malformed(header_summary_from_row(&r6_j2_row(
            serde_json::json!({ "header:From:asRaw:all": [7, "trusted@example.com"] }),
        )));
    }

    #[test]
    fn a_wrong_typed_subject_is_a_malformed_response() {
        r6_j2_is_malformed(header_summary_from_row(&r6_j2_row(serde_json::json!({ "subject": 7 }))));
        r6_j2_is_malformed(header_summary_from_row(&r6_j2_row(serde_json::json!({ "subject": ["s"] }))));
    }

    /// KEEP-After the fix: RFC 8621 types `subject` as `String|null` — `null` is "no subject", `""`.
    #[test]
    fn a_null_subject_is_empty_not_malformed() {
        let summary = header_summary_from_row(&r6_j2_row(serde_json::json!({ "subject": null }))).unwrap();
        assert_eq!(summary.subject, "");
        let empty_from = header_summary_from_row(&r6_j2_row(serde_json::json!({ "header:From:asRaw:all": [] }))).unwrap();
        assert_eq!(empty_from.from_addr, "", "an empty :all array is no From — Absent, never malformed");
    }

    /// `Mailbox/query.ids` is `Id[]` (RFC 8620 `/query`, required): `[7, "mbx"]` used to read as
    /// "no role mailbox" (only `first()` was typed); an absent `ids` likewise.
    #[test]
    fn a_wrong_typed_mailbox_query_ids_is_malformed_not_no_role_mailbox() {
        for args in [
            r#"{"accountId":"ACCT-1","ids":[7,"mbx"]}"#,
            r#"{"accountId":"ACCT-1","ids":"mbx"}"#,
            r#"{"accountId":"ACCT-1"}"#,
        ] {
            let (_probe, t) = connected(vec![resp(200, &format!(r#"{{"methodResponses":[["Mailbox/query",{args},"c0"]]}}"#))]);
            match t.mailbox_id_for_role(&AccountId("ACCT-1".to_string()), MailboxRole::Inbox) {
                Err(JmapError::Method(aruna::jmap::MethodError::Unknown)) => {}
                other => panic!("{args}: a wrong-typed ids must be __malformed_response__, never no role mailbox: {other:?}"),
            }
        }
        let (_probe, t) = connected(vec![resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":[]},"c0"]]}"#)]);
        assert_eq!(
            t.mailbox_id_for_role(&AccountId("ACCT-1".to_string()), MailboxRole::Inbox).expect("an empty ids is a real answer"),
            None,
            "KEEP-GREEN: an empty ids is no role mailbox"
        );
    }

    /// A present non-string callId is malformed, not an empty-string callId that merely mismatches.
    #[test]
    fn a_wrong_typed_call_id_is_a_malformed_response() {
        assert_eq!(
            first_method_response(r#"{"methodResponses":[["Mailbox/query",{"ids":[]},7]]}"#)
                .expect_err("a non-string callId is malformed"),
            map_method_error("__malformed_response__")
        );
    }
    use aruna::jmap::{classify_jmap_error, RequestError, RequestLimit};
    use aruna::FailureKind;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    // A fake HTTP client: replies with queued responses in order and records each request, so the
    // transport orchestration is exercised over a synthetic wire with zero network (
    // "synthetic wire" satisfies the taxonomy-fidelity matrix hermetically).
    #[derive(Clone, Debug)]
    struct FakeHttp {
        inner: Rc<RefCell<FakeInner>>,
    }
    #[derive(Debug)]
    struct FakeInner {
        queued: VecDeque<HttpResponse>,
        calls: Vec<(String, Option<Value>)>,
        routes: Vec<Route>,
    }
    /// Which ROUTE CLASS a recorded call went out on — the §5.2b read/mutation split, made
    /// observable so a call site that drifts onto the wrong client is caught at once.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Route {
        Get,
        Read,
        Mutation,
    }
    impl FakeHttp {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                inner: Rc::new(RefCell::new(FakeInner {
                    queued: responses.into_iter().collect(),
                    calls: Vec::new(),
                    routes: Vec::new(),
                })),
            }
        }
        fn calls(&self) -> Vec<(String, Option<Value>)> {
            self.inner.borrow().calls.clone()
        }
        fn routes(&self) -> Vec<Route> {
            self.inner.borrow().routes.clone()
        }
        fn pop(
            &self,
            url: &str,
            body: Option<Value>,
            route: Route,
        ) -> Result<HttpResponse, JmapError> {
            let mut inner = self.inner.borrow_mut();
            inner.calls.push((url.to_string(), body));
            inner.routes.push(route);
            Ok(inner
                .queued
                .pop_front()
                .expect("FakeHttp ran out of queued responses"))
        }
    }
    impl HttpClient for FakeHttp {
        fn get(&self, url: &str) -> Result<HttpResponse, JmapError> {
            self.pop(url, None, Route::Get)
        }
        fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, JmapError> {
            self.pop(url, Some(body.clone()), Route::Read)
        }
        fn post_json_mutation(&self, url: &str, body: &Value) -> Result<HttpResponse, JmapError> {
            self.pop(url, Some(body.clone()), Route::Mutation)
        }
    }
    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            body: body.to_string(),
        }
    }
    fn session_body(api_url: &str) -> String {
        format!(
            r#"{{"apiUrl":"{api_url}","capabilities":{{"urn:ietf:params:jmap:core":{{}},"urn:ietf:params:jmap:mail":{{}}}},"primaryAccounts":{{"urn:ietf:params:jmap:mail":"ACCT-1"}}}}"#
        )
    }

    // ---- redirect bounding (a method request may only follow same-authority redirects) ----

    #[test]
    fn same_authority_allows_same_host_path_redirect_but_blocks_cross_authority_and_downgrade() {
        let from = reqwest::Url::parse("http://localhost:18080/.well-known/jmap").unwrap();
        // Same scheme+host+port, different path (e.g. .well-known/jmap -> /jmap/session) — allowed
        assert!(same_authority(
            &from,
            &reqwest::Url::parse("http://localhost:18080/jmap/session").unwrap()
        ));
        // Cross host / cross port / scheme downgrade — all blocked
        assert!(!same_authority(
            &from,
            &reqwest::Url::parse("http://evil.example.com:18080/jmap/").unwrap()
        ));
        assert!(!same_authority(
            &from,
            &reqwest::Url::parse("http://localhost:9999/jmap/").unwrap()
        ));
        assert!(!same_authority(
            &from,
            &reqwest::Url::parse("https://localhost:18080/jmap/").unwrap()
        ));
    }

    // ---- TLS-or-local credential guard (production connects must use TLS) ----

    #[test]
    fn plaintext_connect_is_refused_for_non_local_hosts() {
        // TLS is fine to any host; plaintext http only to local/test (the fixture). A non-local
        // plaintext connect would leak credentials in cleartext — refuse it.
        assert!(require_tls_or_local("https://mail.example.com/").is_ok(), "TLS anywhere is fine");
        assert!(require_tls_or_local("http://localhost:18080").is_ok(), "loopback http (fixture) ok");
        assert!(require_tls_or_local("http://127.0.0.1:8080").is_ok());
        // A `.test` NAME is not loopback — plaintext to it must be refused
        assert!(require_tls_or_local("http://stalwart.test").is_err());
        assert!(
            require_tls_or_local("http://mail.example.com/").is_err(),
            "plaintext to a non-loopback host must be refused"
        );
    }

    // ---- apiUrl rebasing (fixture path; production REQUIRES a same-authority advertised apiUrl) ----

    #[test]
    fn rebase_api_url_keeps_server_path_but_uses_the_connection_authority() {
        // The Stalwart fixture case: advertised https://localhost/jmap/ is unreachable; rebase onto
        // the reachable http://localhost:18080 base, keeping the /jmap/ path.
        assert_eq!(
            rebase_api_url("https://localhost/jmap/", "http://localhost:18080").as_deref(),
            Some("http://localhost:18080/jmap/")
        );
        // Path + query preserved, authority taken from the base
        assert_eq!(
            rebase_api_url("https://adv.example/api/jmap?v=2", "http://127.0.0.1:18080").as_deref(),
            Some("http://127.0.0.1:18080/api/jmap?v=2")
        );
        // Unparseable inputs fail closed (None)
        assert_eq!(rebase_api_url("not a url", "http://localhost:18080"), None);
    }

    // ---- non-2xx classification: a request-level problem-details body beats the bare status ----

    #[test]
    fn non_2xx_with_a_request_limit_problemdetails_is_classified_by_the_taxonomy() {
        // RFC 8620 §3.6.1: a request-level error returns a problem-details body. A maxConcurrentRequests
        // limit is TRANSIENT — classifying it from the bare 400 status would wrongly dead-letter it
        // as a deterministic ClientError.
        let body = r#"{"type":"urn:ietf:params:jmap:error:limit","limit":"maxConcurrentRequests"}"#;
        let err = ensure_ok(400, body).expect_err("400 problemdetails -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Transient);
        assert_eq!(
            err,
            JmapError::Request(RequestError::Limit(RequestLimit::MaxConcurrentRequests))
        );
    }

    #[test]
    fn non_2xx_without_a_jmap_problemdetails_falls_back_to_the_http_status() {
        let err = ensure_ok(400, "Bad Request (not a JMAP body)").expect_err("400 -> Err");
        assert_eq!(err, JmapError::Transport(TransportError::ClientError(400)));
    }

    #[test]
    fn ensure_ok_passes_on_2xx_regardless_of_body() {
        assert!(ensure_ok(200, "").is_ok());
        assert!(ensure_ok(201, "anything").is_ok());
    }

    #[test]
    fn auth_debug_never_prints_the_secret() {
        // The never-print-credentials guarantee must survive `{:?}` (logs, expect_err) — a derived
        // Debug on Auth would leak the bearer token / Basic password.
        let bearer = format!("{:?}", Auth::Bearer("SUPER-SECRET-TOKEN".to_string()));
        assert!(!bearer.contains("SUPER-SECRET-TOKEN"), "bearer token leaked: {bearer}");
        let basic = format!(
            "{:?}",
            Auth::Basic {
                username: "user@example.test".to_string(),
                password: "HUNTER2-SECRET-PW".to_string(),
            }
        );
        assert!(!basic.contains("HUNTER2-SECRET-PW"), "basic password leaked: {basic}");
    }

    #[test]
    fn debug_never_leaks_session_provider_ids_or_response_bodies() {
        // Class closure: NO leaf or composite `Debug` may print provider ids
        // or response bodies — confinement must survive `{:?}` everywhere (logs, expect_err).
        let session = SessionInfo {
            api_url: "http://host/jmap/".to_string(),
            primary_account: Some("PROVIDER-ACCT-LEAK".to_string()),
            max_objects_in_get: None,
        };
        assert!(
            !format!("{session:?}").contains("PROVIDER-ACCT-LEAK"),
            "session id leaked: {session:?}"
        );

        let http_resp = HttpResponse {
            status: 200,
            body: "PROVIDER-BODY-LEAK".to_string(),
        };
        let r_dbg = format!("{http_resp:?}");
        assert!(!r_dbg.contains("PROVIDER-BODY-LEAK"), "response body leaked: {r_dbg}");
        assert!(r_dbg.contains("200"), "status should still show: {r_dbg}");

        // Composite: the transport's derived Debug must inherit the leaf redaction.
        let fake = FakeHttp::new(vec![resp(
            200,
            r#"{"apiUrl":"https://h/jmap/","capabilities":{"urn:ietf:params:jmap:mail":{}},"primaryAccounts":{"urn:ietf:params:jmap:mail":"COMPOSITE-ACCT-LEAK"}}"#,
        )]);
        let t = HttpJmapTransport::connect_with(fake, "https://server.test").expect("connect");
        assert!(
            !format!("{t:?}").contains("COMPOSITE-ACCT-LEAK"),
            "transport leaked session id: {t:?}"
        );
    }

    // ---- the default-closed destructive-write gate (ADR-P010) ----

    #[test]
    fn gate_refuses_to_authorize_a_production_host() {
        assert_eq!(
            DestructiveWriteGate::allow_test_host("mail.google.com").err(),
            Some(GateError::NonLocalHostRefused)
        );
        assert_eq!(
            DestructiveWriteGate::allow_test_host("api.fastmail.com").err(),
            Some(GateError::NonLocalHostRefused)
        );
        // A public IP is not a test host either
        assert!(DestructiveWriteGate::allow_test_host("93.184.216.34").is_err());
    }

    #[test]
    fn gate_authorizes_only_actual_loopback_not_naming_conventions() {
        // Loopback is proof of locality; a `.test`/`.localhost` NAME is not — it can resolve
        // off-machine, which would open the write gate (and plaintext creds) to a remote host.
        for h in ["127.0.0.1", "localhost", "::1", "127.0.0.2"] {
            assert!(DestructiveWriteGate::allow_test_host(h).is_ok(), "{h} is loopback — allowed");
        }
        for h in ["api.test", "stalwart.localhost", "evil.test", "localhost.evil.com"] {
            assert!(
                DestructiveWriteGate::allow_test_host(h).is_err(),
                "{h} is a NAME, not loopback — must be refused"
            );
        }
    }

    #[test]
    fn ipv6_loopback_is_recognized_as_local_brackets_and_all() {
        // `Url::host_str()` brackets IPv6 literals; the locality check must still see `[::1]` as
        // loopback so a documented IPv6 fixture URL works and the write gate opens for it, while a
        // non-loopback IPv6 literal stays non-local.
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("::1"));
        assert!(require_tls_or_local("http://[::1]:18080").is_ok());
        assert!(DestructiveWriteGate::allow_test_host("[::1]").is_ok());
        assert!(!is_loopback_host("[2001:db8::1]"));
    }

    #[test]
    fn gate_binds_ipv6_loopback_regardless_of_bracket_form() {
        // (2026-06-25): `Url::host_str()` yields `[::1]` while a caller may open the
        // gate with bare `::1` — the gate must canonicalize BOTH sides so a write to the bracketed host
        // is permitted, or email_set stays wrongly disabled for an IPv6 fixture.
        let bare = DestructiveWriteGate::allow_test_host("::1").expect("::1 is loopback");
        assert!(bare.permits_host("[::1]"), "bare-opened gate must permit the bracketed host form");
        let bracketed = DestructiveWriteGate::allow_test_host("[::1]").expect("[::1] is loopback");
        assert!(bracketed.permits_host("::1"), "bracket-opened gate must permit the bare host form");
        // A different host is still refused (the gate is exact-host).
        assert!(!bare.permits_host("127.0.0.1"), "a different loopback host must not be permitted");
    }

    #[test]
    fn canonical_host_normalizes_only_genuine_ipv6_literals_and_every_hostile_form_is_fail_closed() {
        // canonical_host is IPv6-bracket
        // NORMALIZATION, not arbitrary bracket-stripping. A genuine IPv6 literal loses its brackets; a
        // bracketed NON-IPv6 string is left intact (and then refused), so nothing is rescued into
        // locality and every hostile form is fail-closed.
        assert_eq!(canonical_host("[::1]"), "::1");
        assert_eq!(canonical_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(canonical_host("::1"), "::1");
        assert_eq!(canonical_host("127.0.0.1"), "127.0.0.1");
        // NON-IPv6 / malformed bracketed strings are NOT unwrapped:
        assert_eq!(canonical_host("[localhost]"), "[localhost]");
        assert_eq!(canonical_host("[evil.test]"), "[evil.test]");
        assert_eq!(canonical_host("[127.0.0.1]"), "[127.0.0.1]"); // IPv4-in-brackets is malformed
        assert_eq!(canonical_host("[::1"), "[::1");
        assert_eq!(canonical_host("::1]"), "::1]");

        // None of the hostile forms read as loopback or open the gate (fail-closed):
        for h in [
            "[localhost]",
            "[evil.test]",
            "[127.0.0.1]",
            "[::1",
            "::1]",
            "[::1]x",
            "::ffff:127.0.0.1", // IPv4-mapped IPv6 is NOT ::1 → not loopback (Rust footgun, safe here)
        ] {
            assert!(!is_loopback_host(h), "{h} must NOT be loopback");
            assert!(
                DestructiveWriteGate::allow_test_host(h).is_err(),
                "{h} must not be able to open the write gate"
            );
        }
        // The genuine loopback forms still qualify.
        assert!(is_loopback_host("[::1]") && is_loopback_host("::1") && is_loopback_host("127.0.0.1"));
    }

    #[test]
    fn transport_debug_redacts_the_connection_base_url() {
        // (2026-06-25): the below-seam provider endpoint + any base-URL userinfo must never
        // leak into Debug / expect_err output (matching the Auth + SessionInfo redaction). The field
        // itself must read `<redacted>`. (We assert on the FIELD, not the whole string: the test-only
        // FakeHttp records request URLs in its own Debug; the real ReqwestClient prints no URLs.)
        let fake = FakeHttp::new(vec![resp(200, &session_body("https://api.test/jmap"))]);
        let t =
            HttpJmapTransport::connect_with(fake, "https://u:s3cr3t-pw@api.test").expect("connect");
        let dbg = format!("{t:?}");
        assert!(
            dbg.contains(r#"connection_base: "<redacted>""#),
            "connection_base must be redacted in Debug: {dbg}"
        );
    }

    #[test]
    fn closed_gate_permits_no_host() {
        assert!(!DestructiveWriteGate::closed().permits_host("127.0.0.1"));
        assert!(!DestructiveWriteGate::closed().permits_host("api.test"));
    }

    #[test]
    fn open_gate_permits_only_its_exact_authorized_host() {
        let gate = DestructiveWriteGate::allow_test_host("127.0.0.1").unwrap();
        assert!(gate.permits_host("127.0.0.1"));
        assert!(!gate.permits_host("localhost"), "a different host string is not covered");
        assert!(!gate.permits_host("evil.test"));
    }

    // ---- connect / Session discovery over HTTP ----

    #[test]
    fn connect_fetches_well_known_session_and_caches_api_url_and_account() {
        let fake = FakeHttp::new(vec![resp(200, &session_body("https://api.test/jmap"))]);
        let probe = fake.clone();
        let t = HttpJmapTransport::connect_with(fake, "https://server.test/").expect("connect");

        assert_eq!(t.session().api_url, "https://api.test/jmap");
        assert_eq!(t.session().primary_account.as_deref(), Some("ACCT-1"));
        // It hit the RFC 8620 well-known discovery path (no double slash).
        assert_eq!(probe.calls()[0].0, "https://server.test/.well-known/jmap");
    }

    #[test]
    fn connect_on_unauthorized_status_fails_deterministic() {
        let fake = FakeHttp::new(vec![resp(401, "unauthorized")]);
        let err = HttpJmapTransport::connect_with(fake, "https://server.test")
            .expect_err("401 → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn connect_on_malformed_session_fails_deterministic() {
        let fake = FakeHttp::new(vec![resp(200, "not a session")]);
        let err = HttpJmapTransport::connect_with(fake, "https://server.test")
            .expect_err("bad session → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- mailbox_id_for_role over HTTP ----

    fn connected(extra: Vec<HttpResponse>) -> (FakeHttp, HttpJmapTransport<FakeHttp>) {
        let mut responses = vec![resp(200, &session_body("https://api.test/jmap"))];
        responses.extend(extra);
        let fake = FakeHttp::new(responses);
        let probe = fake.clone();
        // Connect to the SAME authority the session advertises (api.test) — authenticated method
        // calls are now bound to the connection authority.
        let t = HttpJmapTransport::connect_with(fake, "https://api.test").expect("connect");
        (probe, t)
    }

    #[test]
    fn with_api_base_rebases_subsequent_calls_onto_the_connection_authority() {
        // The session advertises an unreachable apiUrl; after with_api_base, method calls must POST
        // to the rebased URL (connection authority + advertised path), not the advertised host.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://advertised.example/jmap/")),
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"c","ids":[]},"c0"]]}"#),
        ]);
        let probe = fake.clone();
        // The fixture flow: connect to the loopback base, the session advertises an unreachable URL,
        // and with_api_base rebases onto the SAME loopback connection authority (so the same-authority
        // bind still holds ).
        let t = HttpJmapTransport::connect_with(fake, "http://localhost:18080")
            .expect("connect")
            .with_api_base("http://localhost:18080");
        t.mailbox_id_for_role(&AccountId("c".to_string()), MailboxRole::Inbox)
            .expect("query ok");
        assert_eq!(probe.calls()[1].0, "http://localhost:18080/jmap/");
    }

    #[test]
    fn with_api_base_refuses_to_retarget_authenticated_calls_to_a_remote_host() {
        // Bypass-construction: with_api_base is a fixture-only escape
        // hatch and must NOT be usable to point authenticated method calls (which carry the
        // credential) at an arbitrary remote host. A NON-loopback rebase target — even over TLS — is
        // ignored: the cached, Session-advertised apiUrl stands, so the credential never leaves the
        // server the client actually authenticated against.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://api.test/jmap")),
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"c","ids":[]},"c0"]]}"#),
        ]);
        let probe = fake.clone();
        let t = HttpJmapTransport::connect_with(fake, "https://api.test")
            .expect("connect")
            .with_api_base("https://attacker.example"); // remote https — must be refused
        t.mailbox_id_for_role(&AccountId("c".to_string()), MailboxRole::Inbox)
            .expect("query ok");
        // The POST still went to the original advertised (same-authority) apiUrl, never the attacker.
        assert_eq!(probe.calls()[1].0, "https://api.test/jmap");
    }

    #[test]
    fn cross_authority_session_api_url_refuses_credentialed_method_calls() {
        // (CWE-346): a malicious/compromised Session that advertises an
        // apiUrl on a DIFFERENT authority than the one we connected + authenticated to must NOT be
        // able to retarget the credentialed Mailbox/query there. Fail closed BEFORE any authenticated
        // POST — the credential never leaves the connection authority.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://attacker.example/jmap")),
            // A Mailbox/query success IS queued, so a leak would wrongly succeed (a clean failure) rather
            // than panic on an empty queue.
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"a","ids":["MBX-x"]},"c0"]]}"#),
        ]);
        let probe = fake.clone();
        let t = HttpJmapTransport::connect_with(fake, "https://mail.provider.test")
            .expect("connect succeeds; the retarget is refused at method-call time");
        let err = t
            .mailbox_id_for_role(&AccountId("a".to_string()), MailboxRole::Inbox)
            .expect_err("cross-authority apiUrl must fail closed");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        // Only the session-discovery GET hit the wire — the credentialed POST never did.
        assert_eq!(
            probe.calls().len(),
            1,
            "a cross-authority apiUrl must not reach the authenticated POST"
        );
    }

    #[test]
    fn same_authority_session_api_url_is_accepted() {
        // The common, legitimate case: the Session advertises an apiUrl on the SAME authority we
        // connected to (most JMAP providers) — credentialed method calls proceed normally.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://mail.provider.test/jmap")),
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"a","ids":["MBX-arch"]},"c0"]]}"#),
        ]);
        let probe = fake.clone();
        let t =
            HttpJmapTransport::connect_with(fake, "https://mail.provider.test").expect("connect");
        let id = t
            .mailbox_id_for_role(&AccountId("a".to_string()), MailboxRole::Archive)
            .expect("same-authority query ok");
        assert_eq!(id, Some(MailboxId("MBX-arch".to_string())));
        assert_eq!(probe.calls()[1].0, "https://mail.provider.test/jmap");
    }

    #[test]
    fn each_request_uses_a_distinct_call_id_so_a_replayed_same_method_response_fails_closed() {
        // (2026-06-25): the inbox + archive Mailbox/query in one archive op must use
        // DISTINCT call ids. Here the 2nd lookup is answered with a REPLAY of the 1st response (still
        // callId c0); because the 2nd request used c1, the correlation rejects it — fail closed,
        // instead of resolving the archive role to the inbox mailbox and reporting a no-op as success.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://api.test/jmap")),
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"a","ids":["MBX-inbox"]},"c0"]]}"#),
            // A REPLAY of the c0 response, served for the SECOND (c1) request:
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"a","ids":["MBX-inbox"]},"c0"]]}"#),
        ]);
        let t = HttpJmapTransport::connect_with(fake, "https://api.test").expect("connect");
        // 1st lookup correlates (request c0 == response c0).
        assert_eq!(
            t.mailbox_id_for_role(&AccountId("a".to_string()), MailboxRole::Inbox)
                .expect("first lookup ok"),
            Some(MailboxId("MBX-inbox".to_string()))
        );
        // 2nd lookup expects c1; the replayed c0 response fails the correlation → Deterministic.
        let err = t
            .mailbox_id_for_role(&AccountId("a".to_string()), MailboxRole::Archive)
            .expect_err("replayed c0 for the c1 request must fail closed");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_id_for_role_posts_a_role_query_to_the_api_url_and_returns_the_id() {
        let (probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-arch-1"]},"c0"]]}"#,
        )]);
        let id = t
            .mailbox_id_for_role(&AccountId("ACCT-1".to_string()), MailboxRole::Archive)
            .expect("query ok");
        assert_eq!(id, Some(MailboxId("MBX-arch-1".to_string())));
        // The POST went to the *discovered* api_url with a role-filtered Mailbox/query.
        let (url, body) = &probe.calls()[1];
        assert_eq!(url, "https://api.test/jmap");
        assert_eq!(body.as_ref().unwrap()["methodCalls"][0][1]["filter"]["role"], "archive");
    }

    #[test]
    fn mailbox_id_for_role_absent_role_is_ok_none() {
        let (_p, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":[]},"c0"]]}"#,
        )]);
        let id = t
            .mailbox_id_for_role(&AccountId("ACCT-1".to_string()), MailboxRole::Archive)
            .expect("query ok");
        assert_eq!(id, None);
    }

    #[test]
    fn mailbox_id_for_role_refuses_a_response_scoped_to_another_account() {
        // Call-site threading, not just the parser: the transport asked for ACCT-1's inbox and the
        // wire answered with a correlated callId + the right method but ANOTHER account's namespace.
        // A leak here resolves the role to a foreign mailbox id and feeds it straight to Email/set.
        let (_p, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-OTHER","ids":["MBX-foreign"]},"c0"]]}"#,
        )]);
        let err = t
            .mailbox_id_for_role(&AccountId("ACCT-1".to_string()), MailboxRole::Inbox)
            .expect_err("foreign accountId → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_id_for_role_non_2xx_maps_via_transport_taxonomy() {
        let (_p, t) = connected(vec![resp(503, "upstream down")]);
        let err = t
            .mailbox_id_for_role(&AccountId("ACCT-1".to_string()), MailboxRole::Inbox)
            .expect_err("503 → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Transient);
    }

    // ---- email_set, exercised end-to-end through the connector over the synthetic wire ----
    // (EmailSetRequest is built only by the connector, so this is also the realistic path: it
    // proves connector → HttpJmapTransport → wire moves mail, the fidelity matrix maps through, and
    // provider text never leaks — all hermetically, no Docker.)

    use aruna::jmap::{AccountResolver, JmapConnector, MessageRefResolver};
    use aruna::{Action, Command, Connector, ConnectorError, Facet};

    #[derive(Clone, Copy)]
    struct Fixed;
    impl AccountResolver for Fixed {
        fn resolve_account(&self, _: &str) -> Option<AccountId> {
            Some(AccountId("ACCT-1".to_string()))
        }
    }
    impl MessageRefResolver for Fixed {
        fn resolve_message(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<ProviderMessageId>, aruna::LogError> {
            Ok(Some(ProviderMessageId("EML-1".to_string())))
        }
    }
    fn archive_cmd() -> Command {
        Command::new(
            "k1",
            "photon-acct",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".to_string(),
            },
        )
    }
    fn mailbox_ids(id: &str, call_id: &str) -> String {
        format!(
            r#"{{"methodResponses":[["Mailbox/query",{{"accountId":"ACCT-1","ids":["{id}"]}},"{call_id}"]]}}"#
        )
    }

    /// The ADMISSION-FROZEN basis an Archive of `msg-1` carries here: the identity `Fixed`
    /// resolves, plus the role→mailbox pair the `Mailbox/query` fixtures answer with.
    ///
    /// `Connector::apply` CONSUMES this rather than re-resolving,
    /// so a dispatch fixture has to supply the freeze the engine would have taken at admission —
    /// and the two `Mailbox/query` round-trips the dispatch used to spend are gone with the
    /// re-resolution, which is why these queues no longer hold them.
    fn archive_basis() -> aruna::prestate::FrozenBasis {
        aruna::prestate::FrozenBasis {
            native_resource_key: aruna::prestate::native_resource_key(
                aruna::jmap::JMAP_KEY_PROVIDER,
                &["ACCT-1", "EML-1"],
            ),
            touched_atoms: [
                ("membership:MBX-inbox".to_string(), "MBX-inbox".to_string()),
                ("membership:MBX-archive".to_string(), "MBX-archive".to_string()),
            ]
            .into_iter()
            .collect(),
            atom_targets: [
                ("membership:MBX-inbox".to_string(), false),
                ("membership:MBX-archive".to_string(), true),
            ]
            .into_iter()
            .collect(),
            role_bindings: [
                ("inbox".to_string(), "MBX-inbox".to_string()),
                ("archive".to_string(), "MBX-archive".to_string()),
            ]
            .into_iter()
            .collect(),
            freshness: aruna::prestate::Freshness::StateCursor {
                cursor: "s-1".to_string(),
            },
        }
    }

    #[test]
    fn derives_placement_from_mailbox_ids() {
        use aruna::read_model::Placement;
        // Archive id present -> Archive
        let p = placement_from_mailbox_ids(&["ARCHIVE_ID".to_string()], "INBOX_ID", "ARCHIVE_ID")
            .unwrap();
        assert_eq!(p, Placement::Archive);
        // Inbox present -> Inbox
        let p =
            placement_from_mailbox_ids(&["INBOX_ID".to_string()], "INBOX_ID", "ARCHIVE_ID").unwrap();
        assert_eq!(p, Placement::Inbox);
        // Both present -> ambiguous divergence, fail closed (not silently collapsed to Archive):
        // a half-applied archive must surface, not look "converged".
        assert!(placement_from_mailbox_ids(
            &["INBOX_ID".to_string(), "ARCHIVE_ID".to_string()],
            "INBOX_ID",
            "ARCHIVE_ID",
        )
        .is_err());
        // Neither -> error, never a silent default
        assert!(placement_from_mailbox_ids(&["OTHER".to_string()], "INBOX_ID", "ARCHIVE_ID").is_err());
    }

    #[test]
    fn parse_email_get_mailbox_ids_extracts_the_membership_keys() {
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true,"MBX-B":true}}]},"c0"]]}"#;
        let mut ids = parse_email_get_mailbox_ids(body, "c0", "ACCT-1", "E1").unwrap();
        ids.sort();
        assert_eq!(ids, vec!["MBX-A".to_string(), "MBX-B".to_string()]);
    }

    #[test]
    fn parse_email_get_rejects_non_true_mailbox_membership_values() {
        // RFC 8621 §4.1.1: `mailboxIds` is `String[Boolean]` whose values MUST be `true` —
        // membership is expressed by key PRESENCE, and a `false`/non-boolean value is a
        // nonconforming wire object. Today's parse collected KEYS without validating values, so
        // `{"INBOX": false}` read as membership — it must
        // fail the WHOLE read closed, never be filtered into a subset or read as membership.
        let false_value = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":false}}]},"c0"]]}"#;
        assert!(parse_email_get_mailbox_ids(false_value, "c0", "ACCT-1", "E1").is_err());
        let string_value = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":"yes"}}]},"c0"]]}"#;
        assert!(parse_email_get_mailbox_ids(string_value, "c0", "ACCT-1", "E1").is_err());
        // A true member beside a false one fails whole too — no silent filtering.
        let mixed = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true,"MBX-B":false}}]},"c0"]]}"#;
        assert!(parse_email_get_mailbox_ids(mixed, "c0", "ACCT-1", "E1").is_err());
    }

    #[test]
    fn parse_email_get_rejects_duplicate_mailbox_membership_keys() {
        // Regression test for the duplicate-key finding. `first_method_response` pre-deserializes
        // the body into `serde_json::Value`, whose map keeps the LAST duplicate member silently —
        // so `{"MBX-A":false,"MBX-A":true}` reached the RFC 8621 true-only check as just `true`
        // and was ACCEPTED, bypassing the whole-read fail-closed guarantee one duplicate at a
        // time. JMAP is I-JSON (RFC 8620 §1.1 / RFC 7493 §2.3): member names MUST be unique, so a
        // repeated name is a nonconforming wire object and fails the WHOLE read closed — order-
        // independently, value-independently (uniqueness is the contract, not value agreement).
        let last_true = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":false,"MBX-A":true}}]},"c0"]]}"#;
        assert!(
            parse_email_get_mailbox_ids(last_true, "c0", "ACCT-1", "E1").is_err(),
            "a last-key-wins collapse must not smuggle a false membership past the true-only check"
        );
        let last_false = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true,"MBX-A":false}}]},"c0"]]}"#;
        assert!(
            parse_email_get_mailbox_ids(last_false, "c0", "ACCT-1", "E1").is_err(),
            "the reversed order must fail identically"
        );
        let both_true = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true,"MBX-A":true}}]},"c0"]]}"#;
        assert!(
            parse_email_get_mailbox_ids(both_true, "c0", "ACCT-1", "E1").is_err(),
            "agreeing duplicates are still a nonconforming wire object"
        );
        // …and a valid single-key body still parses: the wire-shape discipline must not refuse
        // conforming responses.
        let valid = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true}}]},"c0"]]}"#;
        assert_eq!(
            parse_email_get_mailbox_ids(valid, "c0", "ACCT-1", "E1").unwrap(),
            vec!["MBX-A".to_string()]
        );
    }

    #[test]
    fn parse_email_get_mismatched_call_id_fails_closed() {
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true}}]},"WRONG"]]}"#;
        assert!(parse_email_get_mailbox_ids(body, "c0", "ACCT-1", "E1").is_err());
    }

    #[test]
    fn parse_email_get_not_found_email_fails_closed() {
        // RFC 8621 §4.1: an unknown id lands in `notFound`, the `list` is empty -> no placement.
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[],"notFound":["E1"]},"c0"]]}"#;
        assert!(parse_email_get_mailbox_ids(body, "c0", "ACCT-1", "E1").is_err());
    }

    #[test]
    fn parse_email_get_wrong_email_id_fails_closed() {
        // A misrouted/malformed response carrying a DIFFERENT email's row must NOT be trusted as the
        // requested email's placement — fail closed, never use list[0].
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"OTHER","mailboxIds":{"MBX-A":true}}]},"c0"]]}"#;
        assert!(parse_email_get_mailbox_ids(body, "c0", "ACCT-1", "E1").is_err());
    }

    // ---- capture reads over the live transport ----

    #[test]
    fn mailbox_state_answers_the_provider_state_cursor_from_a_mailbox_get() {
        // Freshness basis: the JMAP Mailbox namespace's freshness evidence is RFC 8621 `Mailbox` `state`.
        // The trait DEFAULT is a TRANSIENT `Err` ("cannot evidence freshness"), which makes
        // `resolve_basis` refuse every role verb — so a live transport that never wires this read
        // refuses archive/unarchive at admission, pre-purpose. The wire read is a `Mailbox/get`
        // whose response `state` IS the cursor.
        let (probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Mailbox/get",{"accountId":"ACCT-1","state":"mbx-state-77","list":[],"notFound":[]},"c0"]]}"#,
        )]);
        assert_eq!(
            t.mailbox_state(&AccountId("ACCT-1".to_string())),
            Ok("mbx-state-77".to_string()),
            "the live transport must answer the provider-issued Mailbox state cursor"
        );
        let (url, body) = &probe.calls()[1];
        assert_eq!(url, "https://api.test/jmap");
        assert_eq!(body.as_ref().unwrap()["methodCalls"][0][0], "Mailbox/get");
        // Ids:[] — the cursor is namespace state; we never pull the mailbox list to read it.
        assert_eq!(
            body.as_ref().unwrap()["methodCalls"][0][1]["ids"],
            serde_json::json!([])
        );
    }

    #[test]
    fn mailbox_state_is_err_when_the_provider_read_fails() {
        // Honest `Err`: a transport that could not TAKE the reading must not be read as fresh —
        // `resolve_basis` refuses the role verb with its named retryable error. The typed error
        // now PRESERVES the cause (a 503 → transient), instead of the old cause-erasing `None`.
        let (_probe, t) = connected(vec![resp(503, "")]);
        let err = t
            .mailbox_state(&AccountId("ACCT-1".to_string()))
            .expect_err("a failed read is an Err, never a fabricated cursor");
        assert_eq!(
            classify_jmap_error(&err),
            aruna::FailureKind::Transient,
            "an HTTP 5xx read failure is transient"
        );
    }

    #[test]
    fn email_current_state_reads_mailbox_ids_and_keywords_from_one_email_get() {
        // The `observe` half of the capture pipeline: ONE Email/get for the one id, properties
        // narrowed to mailboxIds + keywords. The trait DEFAULT refuses, so keyword verbs die at
        // observation and role verbs can never verify their frozen atoms.
        let (probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-inbox":true},"keywords":{"$seen":true,"$flagged":true}}]},"c0"]]}"#,
        )]);
        let state = t
            .email_current_state(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("the live transport must answer the capture read");
        assert_eq!(
            state.mailbox_ids,
            ["MBX-inbox".to_string()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert_eq!(
            state.keywords,
            ["$seen".to_string(), "$flagged".to_string()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
        let (url, body) = &probe.calls()[1];
        assert_eq!(url, "https://api.test/jmap");
        assert_eq!(body.as_ref().unwrap()["methodCalls"][0][0], "Email/get");
        assert_eq!(
            body.as_ref().unwrap()["methodCalls"][0][1]["properties"],
            serde_json::json!(["mailboxIds", "keywords"])
        );
        assert_eq!(
            body.as_ref().unwrap()["methodCalls"][0][1]["ids"],
            serde_json::json!(["E1"])
        );
    }

    // ---- list_inbox_page — Email/query + back-referenced Email/get,
    // ONE combined POST, on top of the EXISTING mailbox_id_for_role round trip ----

    #[test]
    fn list_inbox_page_issues_the_role_lookup_then_one_combined_request_and_maps_every_field() {
        let (probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E2","E1"],"total":2,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":["Alice <a@ex.com>"],"subject":"Hi","keywords":{"$seen":true},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E2","receivedAt":"2024-01-16T09:00:00Z","header:From:asRaw:all":[],"subject":"Yo","keywords":{"$flagged":true},"hasAttachment":true,"mailboxIds":{"MBX-inbox":true,"MBX-other":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);
        let ListedPage { rows: page, next, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect("the live transport must answer the S1 page read");
        // Order follows the QUERY's `ids` (newest-first, E2 then E1) — NOT the Email/get `list`
        // order, which the fixture deliberately returns E1-then-E2 to prove the reordering.
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].provider_id, ProviderMessageId("E2".to_string()));
        assert_eq!(page[0].received_at, 1_705_395_600_000);
        assert_eq!(page[0].from_addr, "", "an absent `from` must be an empty string, never a panic");
        assert_eq!(page[0].from_name, "");
        assert_eq!(page[0].subject, "Yo");
        assert!(!page[0].seen, "absent $seen ⇒ false — the OPPOSITE polarity of Gmail's UNREAD");
        assert!(page[0].flagged);
        assert!(page[0].attachments.has_attachments);
        assert_eq!(page[0].attachments.count, 0, "count is unknowable from hasAttachment alone");

        assert_eq!(page[1].provider_id, ProviderMessageId("E1".to_string()));
        assert_eq!(page[1].received_at, 1_705_314_600_000);
        assert_eq!(page[1].from_addr, "a@ex.com");
        assert_eq!(page[1].from_name, "Alice");
        assert_eq!(page[1].subject, "Hi");
        assert!(page[1].seen);
        assert!(!page[1].flagged);
        assert!(!page[1].attachments.has_attachments);

        // Total (2) == position(0) + returned ids(2) ⇒ no more rows ⇒ no continuation.
        assert_eq!(next, None);

        // Reuses the EXISTING mailbox_id_for_role round trip — never a redundant/duplicated
        // Mailbox/query — then exactly ONE combined POST for Email/query + Email/get.
        assert_eq!(probe.routes(), vec![Route::Get, Route::Read, Route::Read]);
        let calls = probe.calls();
        let combined = &calls[2].1.as_ref().unwrap()["methodCalls"];
        assert_eq!(combined[0][0], "Email/query");
        assert_eq!(combined[0][1]["filter"]["inMailbox"], "MBX-inbox");
        assert_eq!(
            combined[0][1]["sort"],
            serde_json::json!([{"property": "receivedAt", "isAscending": false}])
        );
        assert_eq!(combined[0][1]["position"], 0);
        assert_eq!(combined[0][1]["limit"], 50);
        assert_eq!(combined[0][1]["calculateTotal"], true);
        assert_eq!(combined[1][0], "Email/get");
        assert_eq!(combined[1][1]["#ids"]["resultOf"], combined[0][2]);
        assert_eq!(combined[1][1]["#ids"]["name"], "Email/query");
        assert_eq!(combined[1][1]["#ids"]["path"], "/ids");
        assert_eq!(
            combined[1][1]["properties"],
            serde_json::json!([
                "id",
                "receivedAt",
                "header:From:asRaw:all",
                "subject",
                "keywords",
                "hasAttachment",
                "mailboxIds"
            ]),
            "`mailboxIds` rides along for the membership re-check (codex-r6 F4)"
        );
    }

    /// Regression test: the Inbox membership is RE-CHECKED on the `Email/get` answer,
    /// the mirror of the Gmail arm's own recheck.
    ///
    /// `Email/query` and the back-referenced `Email/get` are evaluated in sequence by the server,
    /// and a message archived or moved between the two is still in the query's `ids` and still
    /// ANSWERED by the get — with the inbox mailbox gone from its `mailboxIds`. Mapping it anyway
    /// handed the caller a row the provider no longer considers inbox mail, and the window
    /// reconcile above wrote it straight back into the local Inbox as a re-checked, current row.
    #[test]
    fn list_inbox_page_skips_a_row_whose_get_answer_no_longer_carries_the_inbox() {
        let (probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E1","E2"],"total":2,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"still in the inbox","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E2","receivedAt":"2024-01-16T09:00:00Z","header:From:asRaw:all":[],"subject":"archived mid-request","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-archive":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);

        let ListedPage { rows: page, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect("the page still maps — one row is skipped, not the whole read");

        assert_eq!(
            page.len(),
            1,
            "the row whose own answer says it is no longer in the inbox must be SKIPPED"
        );
        assert_eq!(page[0].provider_id, ProviderMessageId("E1".to_string()));

        // The decision is only possible because the request ASKS for the property it decides on.
        let calls = probe.calls();
        let combined = &calls[2].1.as_ref().unwrap()["methodCalls"];
        assert_eq!(
            combined[1][1]["properties"],
            serde_json::json!([
                "id",
                "receivedAt",
                "header:From:asRaw:all",
                "subject",
                "keywords",
                "hasAttachment",
                "mailboxIds"
            ]),
            "`mailboxIds` must be requested — a membership recheck over a property we never asked \
             for would fail every row closed"
        );
    }

    /// Regression test: the server's advertised `maxObjectsInGet` is a HARD CEILING on
    /// the page, and this transport ignored it.
    ///
    /// RFC 8620 §2 puts `maxObjectsInGet` in the core capability object: "the maximum number of
    /// objects that the client may request in a single `/get` type method call". Asking for more
    /// is not a soft preference — the server answers `requestTooLarge` and the whole combined
    /// request fails, so a mailbox on a server advertising a small ceiling could not be listed at
    /// all at our 50-row default. The clamp is applied to BOTH halves of the combined request: the
    /// `Email/query` `limit` decides how many ids the back-referenced `Email/get` will be handed,
    /// so bounding only the get would still send an over-large get.
    #[test]
    fn list_inbox_page_respects_the_sessions_max_objects_in_get() {
        let session = r#"{"apiUrl":"https://api.test/jmap","capabilities":{"urn:ietf:params:jmap:core":{"maxObjectsInGet":2},"urn:ietf:params:jmap:mail":{}},"primaryAccounts":{"urn:ietf:params:jmap:mail":"ACCT-1"}}"#;
        let fake = FakeHttp::new(vec![
            resp(200, session),
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[],"total":0,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#),
        ]);
        let probe = fake.clone();
        let t = HttpJmapTransport::connect_with(fake, "https://api.test").expect("connect");

        t.list_inbox_page(&AccountId("ACCT-1".to_string()), 5, None)
            .expect("empty page ok");

        let calls = probe.calls();
        let combined = &calls[2].1.as_ref().unwrap()["methodCalls"];
        assert_eq!(
            combined[0][1]["limit"], 2,
            "the effective page size is min(clamped request, maxObjectsInGet) — asking for 5 \
             against a ceiling of 2 is a `requestTooLarge` the whole request dies on"
        );
    }

    #[test]
    fn list_inbox_page_reclamps_an_out_of_range_page_size_before_the_wire() {
        // A direct trait caller must never be able to hand this transport an unclamped page size
        // (mirrors the Gmail sibling's own re-clamp test).
        for (requested, clamped) in [(0i64, 1i64), (5000i64, 200i64)] {
            let (probe, t) = connected(vec![
                resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
                resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[],"total":0,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#),
            ]);
            t.list_inbox_page(&AccountId("ACCT-1".to_string()), requested, None)
                .expect("empty page ok");
            let calls = probe.calls();
        let combined = &calls[2].1.as_ref().unwrap()["methodCalls"];
            assert_eq!(combined[0][1]["limit"], clamped);
        }
    }

    /// THE PAGE-SIZE BOUND IS ENFORCED ON THE *RESPONSE*, not only on the
    /// request. `limit` is what we ASKED the server for (RFC 8621 §4.4 lets a server return fewer;
    /// nothing makes it return no more). A hostile or broken server answering `Email/query` with
    /// more ids than the limit drove every one of them through `header_summary_from_row` and into
    /// the caller's ingest — one response deciding how much this process writes. Mirrors the Gmail
    /// arm's own hostile-response bound.
    #[test]
    fn list_inbox_page_bounds_an_over_long_id_list_by_the_clamped_limit() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E1","E2","E3","E4","E5"],"total":5,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E2","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E3","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E4","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E5","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);
        let ListedPage { rows: page, next, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 2, None)
            .expect("an over-long id list is BOUNDED, not refused");
        assert_eq!(
            page.len(),
            2,
            "the page the CALLER asked for, never more — one response must not decide the \
             ingest's size"
        );
        assert_eq!(page[0].provider_id, ProviderMessageId("E1".to_string()));
        assert_eq!(page[1].provider_id, ProviderMessageId("E2".to_string()));
        assert_eq!(
            next,
            Some(ContinuationToken("2".to_string())),
            "the continuation resumes at the id we actually consumed (position + 2), never at the \
             oversized count — a next page computed from ids we never returned SKIPS mail"
        );
    }

    #[test]
    fn list_inbox_page_continuation_sets_position_on_the_next_call() {
        // "A second call with the token sets position accordingly."
        let (probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E9"],"total":9,"position":7},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E9","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#),
        ]);
        let token = ContinuationToken("7".to_string());
        t.list_inbox_page(&AccountId("ACCT-1".to_string()), 1, Some(&token))
            .expect("continued page ok");
        let calls = probe.calls();
        let combined = &calls[2].1.as_ref().unwrap()["methodCalls"];
        assert_eq!(combined[0][1]["position"], 7);
    }

    #[test]
    fn list_inbox_page_returns_a_continuation_token_when_more_rows_remain() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":5,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#),
        ]);
        let ListedPage { next, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 1, None)
            .expect("page ok");
        // Position(0) + returned(1) = 1 < total(5) ⇒ more rows remain.
        assert_eq!(next, Some(ContinuationToken("1".to_string())));
    }

    /// Regression test: a DUPLICATE id in the (untruncated) `Email/query` answer must
    /// refuse, never mint a continuation off it. A hostile/broken server that repeats an id makes
    /// `ids.len()` count that id twice: `next_position = position + ids.len()` then overcounts the
    /// walk by every repeat, so the continuation this page mints can SKIP the rows the server never
    /// actually delivered a second copy of. The check runs on the UNTRUNCATED list (before the
    /// hostile-response bound clamps it to `limit`) — a duplicate anywhere in the raw answer is the
    /// same lie about the walk's progress regardless of whether this page's `limit` happens to cut
    /// it off first.
    #[test]
    fn list_inbox_page_refuses_a_duplicate_id_in_the_query_answer() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E1","E1"],"total":2,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect_err("a duplicate id in the query answer must refuse, never mint a page off it");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// Regression test: `total < position + ids.len()` (the UNTRUNCATED count) is an
    /// INCONSISTENT page: the server's own `total` says fewer rows exist past `position` than it
    /// just handed back. Left unchecked this flows straight into the continuation math
    /// (`next_position < total`), and can mint `next = None` off a page the server itself says is
    /// short — the caller reads that as "the walk is exhausted" and `walk_exhausted` sweeps the
    /// local Inbox against a page that never proved it was complete.
    #[test]
    fn list_inbox_page_refuses_a_total_inconsistent_with_the_returned_ids() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                // Position(0) + returned ids(2) = 2 > total(1) — the server's own total is smaller
                // than the page it just answered.
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E1","E2"],"total":1,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E2","receivedAt":"2024-01-16T09:00:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect_err(
                "total < position + ids.len() is an inconsistent page and must refuse, never mint \
                 next=None off it",
            );
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// Regression test: an empty `ids` with `total > position` cannot advance the walk:
    /// `next_position` would equal `position`, so the token this page mints is BYTE-IDENTICAL to the
    /// one the caller just sent, and a caller that trusts `has_more` (a `next` token present) retries
    /// forever on the same request. The fix refuses this shape outright rather than re-emitting the
    /// same token.
    #[test]
    fn list_inbox_page_refuses_a_non_advancing_continuation_rather_than_reissuing_the_same_token() {
        let token = ContinuationToken("3".to_string());
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            // Position=3, ids=[] (no rows answered), yet total=5 > position(3) claims more remain.
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[],"total":5,"position":3},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 1, Some(&token))
            .expect_err(
                "an empty ids answer that cannot advance past `total` must refuse, never re-mint \
                 the same continuation token",
            );
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// The other side of that boundary: an empty `ids` where `total <= position` is a genuinely
    /// EXHAUSTED walk (the mailbox truly has no more rows) — this must still succeed with `next:
    /// None`, never be swept into the same refusal as the non-advancing shape above.
    #[test]
    fn list_inbox_page_an_empty_ids_answer_at_the_end_of_the_walk_is_still_a_valid_exhausted_page() {
        let token = ContinuationToken("5".to_string());
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[],"total":5,"position":5},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#),
        ]);
        let ListedPage { rows, next, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 1, Some(&token))
            .expect("total <= position is a genuinely exhausted walk, not a non-advancing one");
        assert!(rows.is_empty());
        assert_eq!(next, None, "the walk is exhausted — no continuation to reissue");
    }

    #[test]
    fn list_inbox_page_a_mailbox_shrink_below_the_position_is_exhaustion_not_inconsistency() {
        // Continuation at position 5, concurrent archives drop total to 3, server
        // validly answers `ids: []`. The consistency check must not fire on an empty page — the
        // exhaustion math (`total <= position` ⇒ `next: None`) owns this shape.
        let token = ContinuationToken("5".to_string());
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[],"total":3,"position":5},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#),
        ]);
        let ListedPage { rows, next, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 1, Some(&token))
            .expect("a shrink below the position is a valid exhausted walk, never an inconsistency");
        assert!(rows.is_empty());
        assert_eq!(next, None, "the walk finished — the cursor must not stay wedged");
    }

    #[test]
    fn fetch_pages_refuse_a_duplicate_email_get_record() {
        // Two Email/get records with one id is ambiguous — last-one-wins would let a
        // hostile response pick which record the membership check trusts. Fail closed.
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[
                {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"first","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"second","keywords":{},"hasAttachment":false,"mailboxIds":{}}
            ]},"c2"]]}"#),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 5, None)
            .expect_err("an ambiguous duplicate Email/get record must refuse, never last-one-wins");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn list_inbox_page_no_inbox_mailbox_is_a_typed_error_never_a_fabricated_empty_page() {
        let (probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":[]},"c0"]]}"#,
        )]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect_err("an account with no inbox mailbox must refuse, never fabricate an empty page");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        // No combined request was ever issued (fail closed BEFORE the second POST).
        assert_eq!(probe.calls().len(), 2, "session GET + the role lookup only");
    }

    #[test]
    fn list_inbox_page_malformed_or_missing_shapes_are_typed_errors_never_a_panic() {
        const ROLE_OK: &str =
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#;
        for combined in [
            "not json",
            // Total missing despite calculateTotal:true being requested
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#,
            // Total negative — Regression test: JMAP `total` is unsigned on the wire, so
            // a negative value is a malformed shape, not a tiny mailbox; unrefused it flows into
            // the continuation math and can synthesize an authoritative empty page.
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":-1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#,
            // Ids not an array of strings
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[1],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#,
            // HasAttachment missing on a returned row
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#,
            // MailboxIds missing on a returned row: we ASKED for it and an Email always has one,
            // so its absence is a malformed response, never a quiet skip
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false}]},"c2"]]}"#,
            // ReceivedAt malformed
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"not-a-date","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#,
        ] {
            let (_probe, t) = connected(vec![resp(200, ROLE_OK), resp(200, combined)]);
            let err = t
                .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
                .expect_err("a malformed/missing shape must fail closed, never panic");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
    }

    /// Regression test: the RESPONSE'S OWN `position` is required, never assumed from
    /// the request this call sent. RFC 8621 §5.5's `Email/query` response echoes `position`; an
    /// absent one is a malformed shape, not "the server must have used what we asked for".
    #[test]
    fn list_inbox_page_refuses_a_query_response_missing_its_own_position() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect_err("a response with no `position` must refuse, never advance from the request-side value alone");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// Regression test: the RESPONSE'S `position` DIFFERS from the one this request
    /// asked for (0). Silently trusting the request-side `position` for the continuation math
    /// would mint the next page's cursor off a number the server never confirmed it walked from;
    /// this must refuse instead.
    #[test]
    fn list_inbox_page_refuses_a_query_response_position_that_disagrees_with_the_request() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            // Requested position 0; the response claims it actually walked from 1.
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":2,"position":1},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect_err("a response `position` that disagrees with the request must refuse, never be silently accepted");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// Regression test: an id the `Email/query` half named is answered by NEITHER
    /// `Email/get`'s `list` NOR its `notFound`. This is the SILENT-DROP shape, distinct from the
    /// legitimate deletion race `notFound` explains: left unrefused, the chronological reconcile
    /// above this seam would read the unexplained omission as "this id no longer exists" and
    /// delete a local row the query's own answer, moments earlier, said was still there.
    #[test]
    fn list_inbox_page_refuses_a_query_id_answered_by_neither_list_nor_not_found() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[],"notFound":[]},"c2"]]}"#),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect_err("an id in neither `list` nor `notFound` must refuse, never a silent drop");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// The other side of that boundary: an id in `notFound` is the LEGITIMATE deletion race (the same
    /// window `row_is_in_mailbox`'s own doc names) and must still succeed, the row simply skipped.
    #[test]
    fn list_inbox_page_skips_a_query_id_the_get_half_explicitly_reports_not_found() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1","E2"],"total":2,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[
                {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"still there","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
            ],"notFound":["E2"]},"c2"]]}"#),
        ]);
        let ListedPage { rows, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect("an id explicitly reported `notFound` must still succeed — the row is simply skipped");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provider_id, ProviderMessageId("E1".to_string()));
    }

    /// Regression test: a SCRAMBLED (non-monotonic `received_at`) mapped page must
    /// report `chronological: false`, never the unconditional `true` an earlier version declared
    /// off the ASK alone. The page still ingests: both rows are real mail.
    #[test]
    fn list_inbox_page_reports_chronological_false_on_a_scrambled_mapped_page() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                // Query `ids` order is E1 (older) then E2 (newer) — the WRONG order for a
                // `receivedAt desc` sort, so the mapped page's `received_at` values go UP, not
                // down.
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E1","E2"],"total":2,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"older","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E2","receivedAt":"2024-01-16T09:00:00Z","header:From:asRaw:all":[],"subject":"newer","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);
        let ListedPage { rows, chronological, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect("a scrambled page still ingests — the rows are real mail");
        assert_eq!(rows.len(), 2, "both rows are real mail and must still be returned");
        assert!(
            !chronological,
            "a non-monotonic mapped page must report chronological:false, never the ASK alone"
        );
    }

    /// The other side of that boundary: a genuinely `receivedAt desc`-ordered mapped page still
    /// reports `chronological: true` — the verification is not a downgrade to Gmail's
    /// unconditional `false`, only a check that the answer actually kept the contract it was
    /// asked for.
    #[test]
    fn list_inbox_page_reports_chronological_true_on_a_properly_ordered_mapped_page() {
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(
                200,
                r#"{"methodResponses":[
                    ["Email/query",{"accountId":"ACCT-1","ids":["E2","E1"],"total":2,"position":0},"c1"],
                    ["Email/get",{"accountId":"ACCT-1","list":[
                        {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"older","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
                        {"id":"E2","receivedAt":"2024-01-16T09:00:00Z","header:From:asRaw:all":[],"subject":"newer","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
                    ]},"c2"]
                ]}"#,
            ),
        ]);
        let ListedPage { chronological, .. } = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect("page ok");
        assert!(chronological, "a properly newest-first mapped page must still report chronological:true");
    }

    /// Regression test: a continuation token near `i64::MAX` plus a nonempty page
    /// overflows the request-side `position + ids.len()` arithmetic. Before this change, a debug
    /// build PANICS here (`attempt to add with overflow`); the fix turns that into the SAME typed
    /// refusal a malformed continuation token already gets, never a panic or a release-mode wrap
    /// to a negative cursor.
    #[test]
    fn list_inbox_page_refuses_rather_than_overflows_on_a_near_max_continuation_position() {
        let token = ContinuationToken(i64::MAX.to_string());
        let (_probe, t) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, format!(
                r#"{{"methodResponses":[["Email/query",{{"accountId":"ACCT-1","ids":["E1"],"total":{total},"position":{max}}},"c1"],["Email/get",{{"accountId":"ACCT-1","list":[{{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{{}},"hasAttachment":false,"mailboxIds":{{"MBX-inbox":true}}}}]}},"c2"]]}}"#,
                total = i64::MAX,
                max = i64::MAX,
            ).as_str()),
        ]);
        let err = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 1, Some(&token))
            .expect_err("a position + ids.len() overflow must refuse, never panic or wrap to a negative cursor");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- fetch_body — Email/get bodyValues, capped both on the wire
    // and locally ----

    #[test]
    fn fetch_body_prefers_text_and_carries_html_via_bodyvalues() {
        let (probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1",
                "textBody":[{"partId":"1"}],
                "htmlBody":[{"partId":"2"}],
                "bodyValues":{"1":{"value":"Hello text","isTruncated":false},"2":{"value":"<p>Hello html</p>","isTruncated":false}},
                "hasAttachment":true
            }]},"c0"]]}"#,
        )]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("the live transport must answer the S2 body read");
        assert_eq!(raw.text.as_deref(), Some("Hello text"));
        assert_eq!(raw.html.as_deref(), Some("<p>Hello html</p>"));
        assert!(!raw.text_truncated);
        assert!(!raw.html_truncated);
        assert!(raw.attachments.has_attachments);
        assert_eq!(raw.attachments.count, 0);

        let (url, body) = &probe.calls()[1];
        assert_eq!(url, "https://api.test/jmap");
        let call = &body.as_ref().unwrap()["methodCalls"][0];
        assert_eq!(call[0], "Email/get");
        assert_eq!(call[1]["ids"], serde_json::json!(["E1"]));
        assert_eq!(
            call[1]["properties"],
            serde_json::json!(["bodyValues", "textBody", "htmlBody", "hasAttachment"])
        );
        assert_eq!(call[1]["fetchTextBodyValues"], true);
        assert_eq!(call[1]["fetchHTMLBodyValues"], true);
        assert_eq!(call[1]["maxBodyValueBytes"], BODY_FETCH_CAP);
    }

    /// TRUNCATION IS PER-REPRESENTATION AT THE TRANSPORT ITSELF. `textBody`
    /// is complete; `htmlBody` alone is the one the provider flagged `isTruncated`. Before the fix,
    /// both `body_parts_text` outcomes were OR'd into ONE shared `truncated` bool, so this
    /// fixture reported the complete `text` as truncated too.
    #[test]
    fn fetch_body_marks_only_the_actually_clipped_representation_truncated() {
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1",
                "textBody":[{"partId":"1"}],
                "htmlBody":[{"partId":"2"}],
                "bodyValues":{
                    "1":{"value":"complete text","isTruncated":false},
                    "2":{"value":"<p>clipped by the server</p>","isTruncated":true}},
                "hasAttachment":false
            }]},"c0"]]}"#,
        )]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("ok");
        assert_eq!(raw.text.as_deref(), Some("complete text"));
        assert!(
            !raw.text_truncated,
            "the complete textBody must not inherit htmlBody's truncation"
        );
        assert!(
            raw.html_truncated,
            "the provider-truncated htmlBody must say so, independently of text"
        );
    }

    // ---- textBody/htmlBody are SEQUENTIAL part lists (RFC 8621 §4.1.4) ----

    #[test]
    fn fetch_body_concatenates_every_listed_text_part_in_provider_order() {
        // Regression test. RFC 8621 §4.1.4: "textBody: The text/plain parts to display ... in order".
        // Resolving only `parts.first()` silently dropped the signature block, the forwarded
        // section and every other sequential part — the message rendered as a truthful-looking
        // fragment with nothing saying it was a fragment.
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1",
                "textBody":[{"partId":"1"},{"partId":"2"}],
                "htmlBody":[{"partId":"3"},{"partId":"4"}],
                "bodyValues":{
                    "1":{"value":"first part","isTruncated":false},
                    "2":{"value":"-- \nthe signature","isTruncated":false},
                    "3":{"value":"<p>first</p>","isTruncated":false},
                    "4":{"value":"<p>second</p>","isTruncated":false}},
                "hasAttachment":false
            }]},"c0"]]}"#,
        )]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("ok");
        assert_eq!(
            raw.text.as_deref(),
            Some("first part\n-- \nthe signature"),
            "every listed text part, in the provider's order, joined by a newline"
        );
        assert_eq!(
            raw.html.as_deref(),
            Some("<p>first</p><p>second</p>"),
            "html parts concatenate directly — a joiner would be injected markup"
        );
        assert!(!raw.text_truncated, "a complete text concatenation is not truncated");
        assert!(!raw.html_truncated, "a complete html concatenation is not truncated");
    }

    #[test]
    fn fetch_body_enforces_the_cap_across_the_whole_concatenation_not_per_part() {
        // Two parts each UNDER the cap whose SUM exceeds it. Per-part capping would hand back
        // ~2× BODY_FETCH_CAP of text with `truncated: false` — the aggregate is what the cap is
        // about, and the truncation has to be admitted.
        let half = "a".repeat(BODY_FETCH_CAP - 10);
        let body = format!(
            r#"{{"methodResponses":[["Email/get",{{"accountId":"ACCT-1","list":[{{"id":"E1",
                "textBody":[{{"partId":"1"}},{{"partId":"2"}}],
                "bodyValues":{{"1":{{"value":"{half}","isTruncated":false}},"2":{{"value":"{half}","isTruncated":false}}}},
                "hasAttachment":false
            }}]}},"c0"]]}}"#
        );
        let (_probe, t) = connected(vec![resp(200, &body)]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("an oversize concatenation is truncated, not refused");
        let text = raw.text.expect("the clipped prefix still comes back");
        assert!(
            text.len() <= BODY_FETCH_CAP,
            "the AGGREGATE must not exceed the cap: {}",
            text.len()
        );
        assert!(
            raw.text_truncated,
            "hitting the cap mid-concatenation must be admitted, never silently dropped"
        );
        assert!(!raw.html_truncated, "no htmlBody was listed at all");
    }

    #[test]
    fn fetch_body_a_later_parts_provider_truncation_still_surfaces() {
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1",
                "textBody":[{"partId":"1"},{"partId":"2"}],
                "bodyValues":{"1":{"value":"whole","isTruncated":false},"2":{"value":"clipped by the server","isTruncated":true}},
                "hasAttachment":false
            }]},"c0"]]}"#,
        )]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("ok");
        assert!(
            raw.text_truncated,
            "isTruncated on ANY resolved part is the message's truth, not only the first part's"
        );
    }

    #[test]
    fn fetch_body_no_textual_part_anywhere_is_none_never_a_fabricated_empty_string() {
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","hasAttachment":false}]},"c0"]]}"#,
        )]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("an absent textual body is still Ok — never fabricated, never a hard error");
        assert_eq!(raw.text, None);
        assert_eq!(raw.html, None);
        assert!(!raw.text_truncated);
        assert!(!raw.html_truncated);
        assert!(!raw.attachments.has_attachments);
    }

    #[test]
    fn fetch_body_honors_the_providers_is_truncated_flag() {
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1",
                "textBody":[{"partId":"1"}],
                "bodyValues":{"1":{"value":"clipped by the server","isTruncated":true}},
                "hasAttachment":false
            }]},"c0"]]}"#,
        )]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("ok");
        assert!(raw.text_truncated, "the provider's own isTruncated must be honored honestly");
    }

    #[test]
    fn fetch_body_truncates_locally_at_the_cap_on_a_char_boundary_even_if_the_provider_did_not() {
        // Defense-in-depth: [`BODY_FETCH_CAP`] is re-applied AT THE TRANSPORT BOUNDARY regardless
        // of the provider's own `isTruncated` claim (mirrors the Gmail sibling's identical test).
        let ch = '€';
        let count = (BODY_FETCH_CAP / ch.len_utf8()) + 4;
        let big: String = std::iter::repeat_n(ch, count).collect();
        assert!(big.len() > BODY_FETCH_CAP, "the fixture must actually exceed the cap");
        let body = format!(
            r#"{{"methodResponses":[["Email/get",{{"accountId":"ACCT-1","list":[{{"id":"E1","textBody":[{{"partId":"1"}}],"bodyValues":{{"1":{{"value":"{big}","isTruncated":false}}}},"hasAttachment":false}}]}},"c0"]]}}"#
        );
        let (_probe, t) = connected(vec![resp(200, &body)]);
        let raw = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("an oversize value is truncated, not refused");
        assert!(raw.text_truncated);
        let text = raw.text.expect("truncation still returns the clipped prefix");
        assert!(text.len() <= BODY_FETCH_CAP, "clipped length {} must not exceed the cap", text.len());
        assert!(
            text.len() > BODY_FETCH_CAP - ch.len_utf8(),
            "the clip must land at the LAST valid char boundary at-or-below the cap, not earlier"
        );
        assert!(text.chars().all(|c| c == '€'), "every clipped char must be well-formed");
    }

    #[test]
    fn fetch_body_a_listed_part_with_no_resolvable_value_is_a_typed_error() {
        for entry in [
            // TextBody entry with no partId at all
            r#"{"id":"E1","textBody":[{}],"hasAttachment":false}"#,
            // PartId present but no matching bodyValues entry
            r#"{"id":"E1","textBody":[{"partId":"1"}],"bodyValues":{},"hasAttachment":false}"#,
        ] {
            let body = format!(r#"{{"methodResponses":[["Email/get",{{"accountId":"ACCT-1","list":[{entry}]}},"c0"]]}}"#);
            let (_probe, t) = connected(vec![resp(200, &body)]);
            let err = t
                .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                .expect_err("a listed but unresolvable part must never read as \"no textual body\"");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
    }

    /// WRONG-TYPED `textBody`/`htmlBody` IS MALFORMED, NOT ABSENT. The old
    /// read was `entry.get(list_property).and_then(Value::as_array)`, which conflates two
    /// distinct wire facts into one `None`: the property is genuinely absent (`Ok(None)`, a
    /// truthful "no textual body" per design §2) and the property is PRESENT but not the list
    /// shape RFC 8621 §4.1.4 promises. A hostile/malformed server sending `"textBody": "oops"`
    /// used to read as the honest absence case; it must instead fail closed as a typed malformed
    /// response. Before the fix: `Ok(None)`. After the fix: a typed `Err`.
    #[test]
    fn fetch_body_a_present_but_wrong_typed_text_body_is_malformed_not_absent() {
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[
            {"id":"E1","textBody":"oops","hasAttachment":false}
        ]},"c0"]]}"#;
        let (_probe, t) = connected(vec![resp(200, body)]);
        let err = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect_err("a present-but-wrong-typed textBody must never read as absence");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// The `htmlBody` twin of the test above — the same wrong-type/absent conflation lived in
    /// the identical `body_parts_text` call site for `htmlBody`.
    #[test]
    fn fetch_body_a_present_but_wrong_typed_html_body_is_malformed_not_absent() {
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[
            {"id":"E1","htmlBody":42,"hasAttachment":false}
        ]},"c0"]]}"#;
        let (_probe, t) = connected(vec![resp(200, body)]);
        let err = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect_err("a present-but-wrong-typed htmlBody must never read as absence");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    /// A PRESENT-but-non-boolean `isTruncated` is malformed, not `false`. The old
    /// read was `.and_then(Value::as_bool).unwrap_or(false)`, the same absent/wrong-type
    /// conflation the `textBody`/`htmlBody` list properties had: a hostile/malformed
    /// server sending `"isTruncated": "true"` (a JSON string, not the boolean RFC 8621 §4.1.4
    /// promises) used to read as the honest default `false`, so a body the provider itself flagged
    /// as clipped was reported complete. Before the fix: `Ok` with `text_truncated == false`. After the fix:
    /// a typed `Err`.
    #[test]
    fn fetch_body_a_present_but_non_boolean_is_truncated_is_malformed_not_false() {
        let body = r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[
            {"id":"E1","textBody":[{"partId":"1"}],
             "bodyValues":{"1":{"value":"partial","isTruncated":"true"}},
             "hasAttachment":false}
        ]},"c0"]]}"#;
        let (_probe, t) = connected(vec![resp(200, body)]);
        let err = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect_err("a present-but-non-boolean isTruncated must never read as false");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn fetch_body_missing_has_attachment_is_a_typed_error() {
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1"}]},"c0"]]}"#,
        )]);
        let err = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect_err("a requested property missing from the response is malformed, not defaulted");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn fetch_body_malformed_json_is_a_typed_error_never_a_panic() {
        let (_probe, t) = connected(vec![resp(200, "not json")]);
        let err = t
            .fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect_err("malformed -> Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- the one-wire / mutation-boundary invariant holds for the two new reads ----

    #[test]
    fn list_inbox_page_and_fetch_body_never_take_the_mutation_route() {
        let (probe1, t1) = connected(vec![
            resp(200, r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#),
            resp(200, r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":[],"total":0,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[]},"c2"]]}"#),
        ]);
        t1.list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
            .expect("page ok");
        assert_eq!(probe1.routes(), vec![Route::Get, Route::Read, Route::Read]);

        let (probe2, t2) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","hasAttachment":false}]},"c0"]]}"#,
        )]);
        t2.fetch_body(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("body ok");
        assert_eq!(probe2.routes(), vec![Route::Get, Route::Read]);
    }

    // ---- parse_jmap_utc_date: the hand-rolled RFC3339/UTCDate → epoch-milliseconds parse ----

    #[test]
    fn parse_jmap_utc_date_handles_z_offset_fraction_and_the_epoch() {
        assert_eq!(parse_jmap_utc_date("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_jmap_utc_date("2024-01-15T10:30:00Z"), Some(1_705_314_600_000));
        assert_eq!(parse_jmap_utc_date("2024-01-15T10:30:00.500Z"), Some(1_705_314_600_500));
        // A +02:00 offset is 2 hours EARLIER in UTC than the same clock reading at Z.
        assert_eq!(parse_jmap_utc_date("2024-01-15T12:30:00+02:00"), Some(1_705_314_600_000));
        assert_eq!(parse_jmap_utc_date("1969-12-31T23:59:59Z"), Some(-1_000));
    }

    #[test]
    fn parse_jmap_utc_date_rejects_malformed_input_never_a_guess() {
        for bad in [
            "",
            "not a date",
            "2024-01-15",
            "2024-01-15T10:30:00",   // no Z / offset
            "2024-13-01T00:00:00Z",  // month out of range
            "2024-01-15T10:30:00X",  // unrecognized offset marker
        ] {
            assert_eq!(parse_jmap_utc_date(bad), None, "must reject: {bad:?}");
        }
    }

    /// The day was range-checked against a FLAT 1..=31 and the offset was unbounded,
    /// so a nonexistent civil date silently NORMALIZED forward (2024-02-31 → 2024-03-02) and an
    /// impossible offset (`+99:99`) produced a timestamp. A provider row whose date cannot exist
    /// is a malformed row: it fails closed through the same `__malformed_received_at__` typed
    /// parse error every other malformed field already takes.
    #[test]
    fn parse_jmap_utc_date_fails_closed_on_impossible_calendar_days_and_offsets() {
        for bad in [
            "2024-02-31T00:00:00Z", // February never has 31 days — silently became March 2
            "2024-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z", // 2023 is not a leap year
            "1900-02-29T00:00:00Z", // century non-leap (divisible by 100, not by 400)
            "2024-04-31T00:00:00Z", // April has 30
            "2024-06-31T00:00:00Z",
            "2024-09-31T00:00:00Z",
            "2024-11-31T00:00:00Z",
            "2024-01-32T00:00:00Z",
            "2024-01-00T00:00:00Z",
            "2024-01-15T10:30:00+99:99", // impossible offset — both halves out of bounds
            "2024-01-15T10:30:00+15:00", // beyond the RFC 3339 practical ±14:00 bound
            "2024-01-15T10:30:00-14:01", // hours at the bound, minutes past it
            "2024-01-15T10:30:00+00:60", // minutes must be 0..=59
        ] {
            assert_eq!(
                parse_jmap_utc_date(bad),
                None,
                "an impossible instant must fail closed, never normalize: {bad:?}"
            );
        }
    }

    /// The other half: the dates that DO exist still parse — a fail-closed tightening that
    /// also rejected real mail would be a worse bug than the one it fixed.
    #[test]
    fn parse_jmap_utc_date_still_accepts_every_real_boundary_day_and_offset() {
        for good in [
            "2024-02-29T00:00:00Z", // 2024 IS a leap year
            "2000-02-29T00:00:00Z", // divisible by 400 — leap
            "2023-02-28T00:00:00Z",
            "2024-01-31T00:00:00Z",
            "2024-04-30T00:00:00Z",
            "2024-12-31T23:59:60Z", // leap second, already accepted
            "2024-01-15T10:30:00+14:00",
            "2024-01-15T10:30:00-14:00",
            "2024-01-15T10:30:00+00:59",
        ] {
            assert!(
                parse_jmap_utc_date(good).is_some(),
                "a real instant must still parse: {good:?}"
            );
        }
    }

    /// The ROW-level consequence, at the mapping seam: an impossible `receivedAt` takes the same
    /// typed refusal path as every other malformed field in `header_summary_from_row` — it is
    /// never a guessed timestamp on a real row.
    #[test]
    fn a_header_row_with_an_impossible_received_at_fails_closed_like_any_malformed_field() {
        // Every OTHER member is well-formed, so the date is the only thing that can refuse this
        // row — the discriminating half. (The always-requested
        // `header:From:asRaw:all` and `subject` are now REQUIRED — an absent one is itself
        // malformed — so both rows carry them, keeping the date the ONLY discriminator.) The control below proves the same row parses with a
        // real date.
        let bad = serde_json::json!({
            "id": "E1",
            "receivedAt": "2024-02-31T00:00:00Z",
            "header:From:asRaw:all": [],
            "subject": "s",
            "keywords": {"$seen": true},
            "hasAttachment": false,
        });
        header_summary_from_row(&bad)
            .expect_err("an impossible civil date is a malformed row, not a normalized one");

        let good = serde_json::json!({
            "id": "E1",
            "receivedAt": "2024-02-29T00:00:00Z",
            "header:From:asRaw:all": [],
            "subject": "s",
            "keywords": {"$seen": true},
            "hasAttachment": false,
        });
        header_summary_from_row(&good).expect("the identical row with a REAL date still maps");
    }

    #[test]
    fn email_current_state_applies_the_same_true_only_and_duplicate_discipline_to_keywords() {
        // The capture read REUSES the read side's parse discipline (RFC 8621 §4.1.1 / §4.1.1
        // keywords are `String[Boolean]` whose values MUST be `true`; I-JSON member names MUST be
        // unique). A second, laxer parse for keywords would re-open the very bypasses the
        // mailboxIds parse closed — so each nonconforming shape fails the WHOLE read closed.
        for body in [
            // A non-`true` keyword value
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{"$seen":false}}]},"c0"]]}"#,
            // A duplicate keyword member name (the Value map would collapse it, last key wins)
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{"$seen":false,"$seen":true}}]},"c0"]]}"#,
            // A duplicate mailboxIds member name still fails on this read too
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true,"MBX-A":true},"keywords":{}}]},"c0"]]}"#,
            // The requested id is absent (notFound) — never a fabricated empty state
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[],"notFound":["E1"]},"c0"]]}"#,
            // A different email's row must never answer for ours
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"OTHER","mailboxIds":{"MBX-A":true},"keywords":{}}]},"c0"]]}"#,
        ] {
            let (_probe, t) = connected(vec![resp(200, body)]);
            let err = t
                .email_current_state(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                .expect_err("a nonconforming capture read must fail the WHOLE read closed");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
        // …and a conforming body with an EMPTY keyword set still parses: "no keywords set" is a
        // legitimate reading, distinct from "the read could not be taken".
        let (_probe, t) = connected(vec![resp(
            200,
            r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}]},"c0"]]}"#,
        )]);
        let state = t
            .email_current_state(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
            .expect("a conforming body must parse");
        assert!(state.keywords.is_empty());
    }

    #[test]
    fn a_capture_response_for_a_different_account_fails_closed() {
        // Account-identity basis. Correlating on callId + method name proves the response answers OUR CALL; it
        // proves NOTHING about whose mailbox it describes. A misrouted (or hostile) response that
        // echoes our call id and our email id but carries another `accountId` was accepted, and
        // its membership/keyword reading was journaled as pre-state under
        // `jmap:<OUR account>/<id>` — another account's state recorded as ours, and later
        // restored/verified against ours. An ABSENT `accountId` is the same verdict: RFC 8620
        // §5.1 puts it in every method response, so silence is not agreement.
        for args in [
            // A different account
            r#"{"accountId":"ACCT-OTHER","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}]}"#,
            // No accountId at all
            r#"{"list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}]}"#,
            // A non-string accountId is not an account id either
            r#"{"accountId":7,"list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}]}"#,
        ] {
            let body = format!(r#"{{"methodResponses":[["Email/get",{args},"c0"]]}}"#);
            let (_probe, t) = connected(vec![resp(200, &body)]);
            let err = t
                .email_current_state(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                .expect_err("an un-correlated account must fail the capture read closed");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);

            let (_probe, t) = connected(vec![resp(200, &body)]);
            assert!(
                t.email_get_mailbox_ids(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                    .is_err(),
                "the placement read shares the parse and must fail identically"
            );
        }
    }

    #[test]
    fn a_state_cursor_for_a_different_account_fails_closed() {
        // The same class on the OTHER capture parse: a `Mailbox/get` state token belongs to ONE
        // account's namespace. Frozen as basis freshness for our account, a foreign token makes
        // re-verification compare our namespace against someone else's clock. `None` is the
        // honest answer — a reading we could not TRUST is not freshness.
        for args in [
            r#"{"accountId":"ACCT-OTHER","state":"mbx-state-77","list":[],"notFound":[]}"#,
            r#"{"state":"mbx-state-77","list":[],"notFound":[]}"#,
        ] {
            let body = format!(r#"{{"methodResponses":[["Mailbox/get",{args},"c0"]]}}"#);
            let (_probe, t) = connected(vec![resp(200, &body)]);
            assert!(
                t.mailbox_state(&AccountId("ACCT-1".to_string())).is_err(),
                "a state cursor that is not OUR account's is not freshness evidence"
            );
        }
    }

    #[test]
    fn a_repeated_boolean_set_property_name_on_one_row_fails_closed() {
        // I-JSON uniqueness at the ROW level, not just INSIDE a set. The scan caught a repeated
        // member inside a `keywords`/`mailboxIds` object, but a row that repeats the PROPERTY —
        // `"keywords":{...},"keywords":{...}` — collapsed in `serde_json::Value` to the LAST one
        // and was journaled silently. Same RFC 7493 §2.3 verdict, one level up: a nonconforming
        // wire object fails the WHOLE read closed.
        for row in [
            r#"{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{"$seen":true},"keywords":{}}"#,
            r#"{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{},"keywords":{"$seen":true}}"#,
            r#"{"id":"E1","mailboxIds":{"MBX-A":true},"mailboxIds":{"MBX-B":true},"keywords":{}}"#,
        ] {
            let body = format!(
                r#"{{"methodResponses":[["Email/get",{{"accountId":"ACCT-1","list":[{row}]}},"c0"]]}}"#
            );
            let (_probe, t) = connected(vec![resp(200, &body)]);
            let err = t
                .email_current_state(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                .expect_err("a repeated boolean-set property is a nonconforming wire object");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
    }

    #[test]
    fn a_duplicate_account_id_member_cannot_smuggle_a_foreign_account_past_correlation() {
        // Regression test. `correlate_account` reads `accountId` off the ALREADY-COLLAPSED
        // `serde_json::Value`, whose map keeps the LAST duplicate member. A response carrying
        // `{"accountId":"ACCT-OTHER", …, "accountId":"ACCT-1"}` therefore correlated as OURS —
        // and the row it describes (which belongs to ACCT-OTHER, the value the provider/attacker
        // actually meant first) was journaled as our pre-state. The correlation-deciding member
        // must be duplicate-rejected at the RAW level, exactly like the boolean-set scan.
        for args in [
            // Foreign FIRST, expected LAST — the last-key-wins collapse
            r#"{"accountId":"ACCT-OTHER","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}],"accountId":"ACCT-1"}"#,
            // And the reverse order fails identically: uniqueness is the contract, not which
            // copy happens to agree with us
            r#"{"accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}],"accountId":"ACCT-OTHER"}"#,
            // Even two AGREEING copies are a nonconforming I-JSON object
            r#"{"accountId":"ACCT-1","accountId":"ACCT-1","list":[{"id":"E1","mailboxIds":{"MBX-A":true},"keywords":{}}]}"#,
        ] {
            let body = format!(r#"{{"methodResponses":[["Email/get",{args},"c0"]]}}"#);
            let (_probe, t) = connected(vec![resp(200, &body)]);
            let err = t
                .email_current_state(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                .expect_err("a duplicated accountId is an ambiguous correlation — fail closed");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);

            let (_probe, t) = connected(vec![resp(200, &body)]);
            assert!(
                t.email_get_mailbox_ids(&AccountId("ACCT-1".to_string()), &EmailId("E1".to_string()))
                    .is_err(),
                "the placement read shares the parse and must fail identically"
            );
        }
    }

    /// A LOSSY page (a row dropped by the membership re-check here — same for a
    /// notFound skip or the limit truncation) must never be a coverage window, however
    /// monotonic its SURVIVORS look: a live row can sit inside the gap, above the floor,
    /// and a chronological verdict would condemn it.
    #[test]
    fn a_lossy_page_is_never_chronological_even_when_its_survivors_are_ordered() {
        const ROLE_OK: &str =
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#;
        // Three ids; E75 answered but NO LONGER in the inbox (membership skip) — survivors
        // E100, E50 are perfectly ordered, and that must not be enough.
        let combined = r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E100","E75","E50"],"total":3,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[
            {"id":"E100","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}},
            {"id":"E75","receivedAt":"2024-01-10T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-other":true}},
            {"id":"E50","receivedAt":"2024-01-05T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
        ]},"c2"]]}"#;
        let (_probe, t) = connected(vec![resp(200, ROLE_OK), resp(200, combined)]);
        let page = t
            .list_inbox_page(&AccountId("ACCT-1".to_string()), 5, None)
            .expect("the page still ingests — losing coverage authority is not an error");
        assert_eq!(page.rows.len(), 2, "the survivors still arrive");
        assert!(
            !page.chronological,
            "a page that LOST a row is not a coverage window, however ordered its survivors"
        );
    }

    /// `position`, `notFound`, and `receivedAt` now DECIDE (page correlation ·
    /// omitted-id acceptance · the chronological coverage floor). A duplicated copy of any of
    /// them is serde last-one-wins ambiguity on a removal-deciding value — the raw-level
    /// uniqueness scan must refuse it like every other decision member.
    #[test]
    fn a_duplicated_position_not_found_or_received_at_refuses_the_page() {
        const ROLE_OK: &str =
            r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#;
        for combined in [
            // Duplicated position: 0-then-7 — last-wins would re-correlate the page
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0,"position":7},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#,
            // Duplicated notFound: [] then ["E1"] — last-wins would excuse an unexplained omission
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","notFound":[],"notFound":["E1"],"list":[]},"c2"]]}"#,
            // Duplicated receivedAt inside a row — last-wins would move the coverage floor
            r#"{"methodResponses":[["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],["Email/get",{"accountId":"ACCT-1","list":[{"id":"E1","receivedAt":"2024-01-15T10:30:00Z","receivedAt":"2030-01-01T00:00:00Z","header:From:asRaw:all":[],"subject":"","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}]},"c2"]]}"#,
        ] {
            let (_probe, t) = connected(vec![resp(200, ROLE_OK), resp(200, combined)]);
            let err = t
                .list_inbox_page(&AccountId("ACCT-1".to_string()), 5, None)
                .expect_err("a duplicated decision member on the listing wire must refuse");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
    }

    #[test]
    fn a_duplicate_state_member_cannot_freeze_an_ambiguous_cursor() {
        // Regression test. `parse_mailbox_get_state` reads `state` off the collapsed
        // `Value`, so `{"state":"OLD","state":"NEW"}` froze the LAST cursor as basis freshness
        // evidence — a token we cannot attribute to a single reading, silently promoted to the
        // thing later re-verification compares against. `None` is the honest answer.
        for args in [
            r#"{"accountId":"ACCT-1","state":"mbx-state-OLD","list":[],"notFound":[],"state":"mbx-state-77"}"#,
            r#"{"accountId":"ACCT-1","state":"mbx-state-77","list":[],"notFound":[],"state":"mbx-state-OLD"}"#,
            r#"{"accountId":"ACCT-1","state":"mbx-state-77","state":"mbx-state-77","list":[],"notFound":[]}"#,
        ] {
            let body = format!(r#"{{"methodResponses":[["Mailbox/get",{args},"c0"]]}}"#);
            let (_probe, t) = connected(vec![resp(200, &body)]);
            assert!(
                t.mailbox_state(&AccountId("ACCT-1".to_string())).is_err(),
                "an ambiguous state cursor is not freshness evidence"
            );
        }
    }

    #[test]
    fn a_duplicated_decision_member_in_the_session_resource_refuses_the_connect() {
        // The class's THIRD entry point. Session discovery decides where every
        // credentialed method call is POSTed (`apiUrl`) and whether this is a mail server at all
        // (`capabilities`) — both collapse last-key-wins in `Value`, so a Session repeating either
        // hands us a destination/verdict we cannot attribute to one reading. Fail closed.
        for session in [
            // `apiUrl` twice — a benign one first, the one actually used last
            r#"{"apiUrl":"https://localhost/jmap","apiUrl":"https://localhost/other","capabilities":{"urn:ietf:params:jmap:core":{},"urn:ietf:params:jmap:mail":{}},"primaryAccounts":{"urn:ietf:params:jmap:mail":"ACCT-1"}}"#,
            // `capabilities` twice — the mail-capability gate decided by the last copy
            r#"{"apiUrl":"https://localhost/jmap","capabilities":{"urn:ietf:params:jmap:core":{}},"capabilities":{"urn:ietf:params:jmap:mail":{}},"primaryAccounts":{"urn:ietf:params:jmap:mail":"ACCT-1"}}"#,
            // The mail URN repeated INSIDE primaryAccounts — the advertised account decided by the last
            r#"{"apiUrl":"https://localhost/jmap","capabilities":{"urn:ietf:params:jmap:mail":{}},"primaryAccounts":{"urn:ietf:params:jmap:mail":"ACCT-OTHER","urn:ietf:params:jmap:mail":"ACCT-1"}}"#,
        ] {
            let fake = FakeHttp::new(vec![resp(200, session)]);
            let err = HttpJmapTransport::connect_with(fake, "https://localhost")
                .expect_err("an ambiguous Session resource must fail the connect closed");
            assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        }
        // …and the conforming Session still connects.
        let fake = FakeHttp::new(vec![resp(200, &session_body("https://localhost/jmap"))]);
        assert!(HttpJmapTransport::connect_with(fake, "https://localhost").is_ok());
    }

    /// Build a connector over a FakeHttp whose `Email/set` returns `set_body`; queues the archive
    /// call sequence (session, set). Returns the apply result + a probe to inspect the recorded
    /// requests.
    ///
    /// NO MAILBOX QUERIES: the dispatch consumes the frozen role pair from
    /// `archive_basis()` instead of re-resolving it, so the `Email/set` is the FIRST method call
    /// after session discovery — and its call id is `c0`, the first this transport mints.
    fn archive_with_set_result(set_body: &str) -> (FakeHttp, Result<(), ConnectorError>) {
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://localhost/jmap")),
            resp(200, set_body),
        ]);
        let probe = fake.clone();
        // The fake's apiUrl host is `localhost` (an actual loopback host) — open the gate for it so
        // these tests exercise the real write path; the closed-gate refusal is its own test.
        let transport = HttpJmapTransport::connect_with(fake, "https://localhost")
            .expect("connect")
            .with_destructive_writes(DestructiveWriteGate::allow_test_host("localhost").unwrap());
        let conn = JmapConnector::new(transport, Fixed, Fixed);
        let result = conn.apply(&archive_cmd(), &archive_basis());
        (probe, result)
    }

    #[test]
    fn connect_for_test_fixture_refuses_a_production_base_url_before_any_network() {
        // The write-enabled entry point cannot be aimed at prod: a non-local base URL is refused at
        // gate construction, before any socket is opened (so this is hermetic).
        let err =
            HttpJmapTransport::connect_for_test_fixture("https://mail.google.com/", "user", "pass")
                .expect_err("prod base url → refuse");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn connector_archives_over_the_wire_posting_the_surgical_mailbox_move() {
        let (probe, result) =
            archive_with_set_result(r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","updated":{"EML-1":null}},"c0"]]}"#);
        result.expect("archive over the synthetic wire");

        // The 2nd call is the Email/set POST: to the discovered api_url, carrying the surgical
        // patch (add archive = true, remove inbox = null) — not a full mailboxIds replace. SECOND
        // rather than fourth because the dispatch consumes the frozen role pair instead of
        // re-resolving it over two `Mailbox/query` round-trips.
        let (url, body) = &probe.calls()[1];
        assert_eq!(url, "https://localhost/jmap");
        let patch = &body.as_ref().unwrap()["methodCalls"][0][1]["update"]["EML-1"];
        assert_eq!(patch["mailboxIds/MBX-archive"], json!(true));
        assert_eq!(patch["mailboxIds/MBX-inbox"], json!(null));
    }

    #[test]
    fn fidelity_not_found_set_error_is_deterministic() {
        let (_p, result) = archive_with_set_result(
            r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","notUpdated":{"EML-1":{"type":"notFound"}}},"c0"]]}"#,
        );
        assert_eq!(result.expect_err("notFound → Err").kind, FailureKind::Deterministic);
    }

    #[test]
    fn fidelity_rate_limit_set_error_is_transient() {
        let (_p, result) = archive_with_set_result(
            r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","notUpdated":{"EML-1":{"type":"rateLimit"}}},"c0"]]}"#,
        );
        assert_eq!(result.expect_err("rateLimit → Err").kind, FailureKind::Transient);
    }

    #[test]
    fn fidelity_server_fail_method_error_is_deterministic() {
        let (_p, result) =
            archive_with_set_result(r#"{"methodResponses":[["error",{"type":"serverFail"},"c0"]]}"#);
        assert_eq!(result.expect_err("serverFail → Err").kind, FailureKind::Deterministic);
    }

    #[test]
    fn fidelity_server_partial_fail_method_error_is_deterministic() {
        let (_p, result) = archive_with_set_result(
            r#"{"methodResponses":[["error",{"type":"serverPartialFail"},"c0"]]}"#,
        );
        assert_eq!(
            result.expect_err("serverPartialFail → Err").kind,
            FailureKind::Deterministic
        );
    }

    #[test]
    fn provider_description_never_leaks_through_the_surfaced_error() {
        // Confinement by construction over the wire: a SetError.description carrying
        // a provider secret must NEVER reach the surfaced ConnectorError message.
        let (_p, result) = archive_with_set_result(
            r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","notUpdated":{"EML-1":{"type":"notFound","description":"SECRET-PROVIDER-LEAK-xyz"}}},"c0"]]}"#,
        );
        let err = result.expect_err("notFound → Err");
        assert!(
            !err.message.contains("SECRET-PROVIDER-LEAK"),
            "provider description leaked into the surfaced error: {}",
            err.message
        );
    }

    #[test]
    fn email_set_updated_under_a_foreign_account_id_is_not_proven_applied() {
        // The write path's member of the c47776d class, end-to-end. The response echoes our callId
        // and the `Email/set` method name and carries `updated["EML-1"]` — but scoped to ANOTHER
        // account. That is not proof OUR account's message moved, so it must land in the
        // fail-closed / NOT-PROVEN-APPLIED family (Deterministic — never retried, never a silent
        // success), exactly like `__record_not_in_response__` and `__call_id_mismatch__`.
        let (_p, result) = archive_with_set_result(
            r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-OTHER","updated":{"EML-1":null}},"c0"]]}"#,
        );
        let err = result.expect_err("foreign accountId must not confirm the write");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    // ---- the gate, wired into email_set (default-closed; no network write unless opened) ----

    #[test]
    fn closed_gate_refuses_the_email_set_write_with_no_network_call() {
        // Default-closed (ADR-P010): a transport that has NOT had destructive writes
        // explicitly enabled must refuse the Email/set deterministically, without sending it.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://api.test/jmap")),
            // An Email/set success IS queued — so if the gate leaks, the archive wrongly succeeds
            // (a clean failure) instead of panicking on an empty queue.
            resp(200, r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","updated":{"EML-1":null}},"c0"]]}"#),
        ]);
        let probe = fake.clone();
        let transport =
            HttpJmapTransport::connect_with(fake, "https://api.test").expect("connect");
        let conn = JmapConnector::new(transport, Fixed, Fixed);

        let err = conn.apply(&archive_cmd(), &archive_basis()).expect_err("closed gate → refuse");
        assert_eq!(err.kind, FailureKind::Deterministic);
        // Only the session discovery hit the wire — the destructive write never did. (The two
        // `Mailbox/query` calls this used to count are gone: the dispatch consumes the frozen
        // role pair.)
        assert_eq!(
            probe.calls().len(),
            1,
            "a default-closed gate must not let the Email/set reach the network"
        );
    }

    #[test]
    fn the_closed_gates_refusal_is_a_proven_pre_socket_refusal() {
        // Same class as the URL-builder refusal, one more site — and the LAST
        // pre-socket refusal on the mutation route that still claimed nothing. This gate refuses
        // from LOCAL values (the authorized-host map) BEFORE any POST is issued, so non-issuance
        // is not an inference from a failure's NAME, it is a fact about the code path. `apply`
        // runs AFTER the send-authorization boundary, where an untagged refusal settles
        // `ACK_AMBIGUOUS` and parks a human on a question the transport can answer with
        // certainty.
        //
        // The refusal must ALSO be distinguishable from a real provider answer: it used to be
        // spelled `map_method_error("__destructive_writes_disabled__")`, which falls through to
        // the deterministic `MethodError::Unknown` bucket — bit-identical to an unrecognized
        // PROVIDER method error, which is a POST-socket answer and must stay Indeterminate.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://api.test/jmap")),
            resp(200, r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","updated":{"EML-1":null}},"c0"]]}"#),
        ]);
        let transport =
            HttpJmapTransport::connect_with(fake, "https://api.test").expect("connect");
        let conn = JmapConnector::new(transport, Fixed, Fixed);

        let err = conn.apply(&archive_cmd(), &archive_basis()).expect_err("closed gate → refuse");
        assert_eq!(
            err.effect_evidence,
            aruna::EffectEvidence::ProvenNoWire,
            "a refusal taken before the socket PROVES no mutation issued"
        );
        assert_eq!(
            err.kind,
            FailureKind::Deterministic,
            "the retry taxonomy is untouched: a closed gate does not open on retry"
        );
    }

    // ---- the real reqwest path (network-error mapping) ----

    #[test]
    fn reqwest_connect_to_a_dead_port_is_a_transient_transport_error() {
        // Exercises the real reqwest client (no fake). Grab a test-OWNED ephemeral port and close it
        // so the port is reliably refused — never assume a globally-closed port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener); // close it — now the connect must be refused at the network layer
        let err = HttpJmapTransport::connect(&format!("http://127.0.0.1:{port}"), "test-token")
            .expect_err("dead port → Err");
        // A recoverable network refusal must be transient — never a deterministic dead-letter.
        assert_eq!(classify_jmap_error(&err), FailureKind::Transient);
    }

    #[test]
    fn tls_cert_errors_detected_but_certificate_in_a_url_is_not_a_false_positive() {
        // A nested rustls cert failure must be detected (→ Deterministic, no infinite retry); but a
        // RETRYABLE DNS/connect failure whose URL merely CONTAINS "certificate" must NOT be — matching
        // the URL text would wrongly dead-letter a recoverable op.
        use std::error::Error;
        use std::fmt;

        #[derive(Debug)]
        struct Leaf(&'static str);
        impl fmt::Display for Leaf {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        impl Error for Leaf {}

        // Outer = the reqwest-shaped error whose Display embeds the request URL; inner = the cause.
        #[derive(Debug)]
        struct Wrap {
            outer: &'static str,
            inner: Leaf,
        }
        impl fmt::Display for Wrap {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.outer)
            }
        }
        impl Error for Wrap {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(&self.inner)
            }
        }

        // Real rustls cert faults (nested under the URL-bearing outer error) → detected.
        let expired = Wrap {
            outer: "error sending request for url (https://mail.example/)",
            inner: Leaf("invalid peer certificate: Expired"),
        };
        assert!(is_tls_certificate_error(&expired));
        let bad_name = Wrap {
            outer: "error sending request for url (https://mail.example/)",
            inner: Leaf("invalid peer certificate: NotValidForName"),
        };
        assert!(is_tls_certificate_error(&bad_name));

        // FALSE-POSITIVE GUARD: a retryable DNS failure to a host whose name CONTAINS "certificate"
        // must NOT be treated as a cert fault — we skip the URL-bearing outer error + match the full
        // rustls phrase, so the URL can't trip it.
        let dns_to_certificatey_host = Wrap {
            outer: "error sending request for url (https://certificate.invalid/)",
            inner: Leaf("dns error: No such host is known"),
        };
        assert!(!is_tls_certificate_error(&dns_to_certificatey_host));

        // A plain transient reset is not a cert fault.
        let reset = Wrap {
            outer: "error sending request",
            inner: Leaf("connection reset by peer"),
        };
        assert!(!is_tls_certificate_error(&reset));
    }

    #[test]
    fn connect_to_a_non_local_plaintext_url_refuses_before_any_network() {
        // The public connect over plaintext http to a NON-local host would leak the credentials on
        // the session-discovery request — refuse it deterministically, before any socket. Also
        // covers the schemeless case (no scheme => not https, not local-http => refused).
        let err = HttpJmapTransport::connect("http://mail.example.com", "secret-token")
            .expect_err("plaintext non-local connect → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        let schemeless = HttpJmapTransport::connect("localhost:18080", "test-token")
            .expect_err("schemeless url → Err");
        assert_eq!(classify_jmap_error(&schemeless), FailureKind::Deterministic);
    }

    #[test]
    fn connect_rejects_a_session_advertising_a_non_local_plaintext_api_url() {
        // The guard must cover the SESSION-advertised apiUrl too, not just the connect base: a
        // malicious/misconfigured Session that advertises http:// on a non-local host would downgrade
        // the subsequent authed Mailbox/query + Email/set to cleartext.
        let fake = FakeHttp::new(vec![resp(200, &session_body("http://evil.example.com/jmap/"))]);
        let err = HttpJmapTransport::connect_with(fake, "https://server.test")
            .expect_err("plaintext non-local apiUrl → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- Session discovery (RFC 8620 §2) ----

    #[test]
    fn parse_session_reads_api_url_and_the_mail_primary_account() {
        let body = r#"{
            "apiUrl": "https://jmap.example.test/api/",
            "capabilities": { "urn:ietf:params:jmap:core": {}, "urn:ietf:params:jmap:mail": {} },
            "primaryAccounts": { "urn:ietf:params:jmap:mail": "ACCT-mail-7f3a" },
            "accounts": {}
        }"#;
        let session = parse_session(body).expect("well-formed session parses");
        assert_eq!(session.api_url, "https://jmap.example.test/api/");
        assert_eq!(session.primary_account.as_deref(), Some("ACCT-mail-7f3a"));
    }

    #[test]
    fn parse_session_without_a_mail_primary_account_succeeds_with_none() {
        // RFC 8620 §2 lets a mail-capable session omit a default account (e.g. shared-account-only
        // users); the AccountResolver supplies the account, so we record None and do NOT fail closed —
        // while still never guessing another account (don't guess).
        let body = r#"{
            "apiUrl": "https://jmap.example.test/api/",
            "capabilities": { "urn:ietf:params:jmap:core": {}, "urn:ietf:params:jmap:mail": {} },
            "primaryAccounts": { "urn:ietf:params:jmap:submission": "ACCT-sub-1" }
        }"#;
        let session = parse_session(body).expect("absent mail primary account is OK, not a failure");
        assert_eq!(session.api_url, "https://jmap.example.test/api/");
        assert_eq!(session.primary_account, None);
    }

    #[test]
    fn parse_session_without_the_mail_capability_fails_deterministic() {
        // After primary_account became optional, positively require the server to advertise the mail
        // capability (RFC 8620 §2 `capabilities`): a session that is not mail-capable cannot serve
        // Mailbox/query + Email/set, so fail closed at connect rather than later over the wire.
        let body = r#"{
            "apiUrl": "https://jmap.example.test/api/",
            "capabilities": { "urn:ietf:params:jmap:core": {} }
        }"#;
        let err = parse_session(body).expect_err("no mail capability → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn parse_session_malformed_body_fails_deterministic() {
        let err = parse_session("not json").expect_err("malformed → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- Mailbox/query role resolution (RFC 8621 §2.3) ----

    #[test]
    fn mailbox_query_body_filters_by_the_iana_role_string() {
        let body = build_mailbox_query_body("acct-1", MailboxRole::Archive, "c0");
        assert_eq!(body["using"], json!([JMAP_CORE, JMAP_MAIL]));
        let call = &body["methodCalls"][0];
        assert_eq!(call[0], "Mailbox/query");
        assert_eq!(call[2], "c0");
        let args = &call[1];
        assert_eq!(args["accountId"], "acct-1");
        assert_eq!(args["filter"]["role"], "archive");
    }

    #[test]
    fn mailbox_query_response_with_a_match_returns_the_id() {
        let body = r#"{"methodResponses":[["Mailbox/query",{"accountId":"a","ids":["MBX-archive-1"]},"c0"]]}"#;
        let id = parse_mailbox_query_response(body, "c0", "a")
            .expect("parses")
            .expect("a match");
        assert_eq!(id, MailboxId("MBX-archive-1".to_string()));
    }

    #[test]
    fn mailbox_query_response_with_no_match_is_ok_none() {
        // RFC 8621 §2: roles are optional — an empty result is a legitimate "no such role mailbox".
        let body = r#"{"methodResponses":[["Mailbox/query",{"accountId":"a","ids":[]},"c0"]]}"#;
        assert_eq!(parse_mailbox_query_response(body, "c0", "a").expect("parses"), None);
    }

    #[test]
    fn mailbox_query_method_error_maps_via_taxonomy() {
        let body = r#"{"methodResponses":[["error",{"type":"accountNotFound"},"c0"]]}"#;
        let err = parse_mailbox_query_response(body, "c0", "a").expect_err("method error → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_query_malformed_fails_closed_deterministic() {
        let err = parse_mailbox_query_response("not json", "c0", "a").expect_err("malformed → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_query_misrouted_method_name_fails_closed_even_with_ids() {
        // A misrouted/unexpected method name carrying `ids` must NOT be trusted as the role mailbox
        // id (it feeds the subsequent Email/set) — fail closed.
        let body = r#"{"methodResponses":[["Foo/bar",{"ids":["MBX-wrong"]},"c0"]]}"#;
        let err = parse_mailbox_query_response(body, "c0", "a").expect_err("wrong method name → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_query_mismatched_call_id_fails_closed_even_with_ids() {
        // The response callId must echo our request's — a misrouted Mailbox/query under the WRONG
        // callId must not be trusted as the role mailbox id.
        let body = r#"{"methodResponses":[["Mailbox/query",{"ids":["MBX-wrong"]},"WRONG"]]}"#;
        let err = parse_mailbox_query_response(body, "c0", "a").expect_err("callId mismatch → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_query_method_error_under_a_mismatched_call_id_fails_closed_not_retried() {
        // A misrouted/replayed `["error", …]` whose callId is NOT ours must fail closed
        // (Deterministic), never be accepted as our transient result and retried — the callId
        // correlation runs BEFORE the `error` branch.
        let body = r#"{"methodResponses":[["error",{"type":"serverUnavailable"},"WRONG"]]}"#;
        let err = parse_mailbox_query_response(body, "c0", "a").expect_err("misrouted error → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn mailbox_query_response_scoped_to_another_account_fails_closed_even_with_ids() {
        // The c47776d class, at THIS member: the callId echoes and the method name is right, but the
        // response describes ANOTHER account's mailbox namespace. Roles are per-account (RFC 8621
        // §2), so a foreign `accountId` means this `ids` names a mailbox we must never resolve a role
        // to — it would feed the subsequent Email/set a foreign mailbox id. Fail closed.
        let body = r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-OTHER","ids":["MBX-foreign"]},"c0"]]}"#;
        let err = parse_mailbox_query_response(body, "c0", "ACCT-1")
            .expect_err("foreign accountId → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
        // RFC 8620 §5.1 puts `accountId` in every account-scoped method response, so an ABSENT one is
        // nonconforming, not "unspecified" — same fail-closed answer as a mismatch.
        let absent = r#"{"methodResponses":[["Mailbox/query",{"ids":["MBX-foreign"]},"c0"]]}"#;
        let err = parse_mailbox_query_response(absent, "c0", "ACCT-1")
            .expect_err("absent accountId → Err");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- Email/set request body ----

    #[test]
    fn email_set_body_is_a_jmap_request_with_core_mail_using_and_a_patch_object_move() {
        let body = build_email_set_body(
            "acct-1",
            &[(
                "eml-1",
                vec![
                    PatchOp::Mailbox { mailbox_id: "archive-1", member: true },
                    PatchOp::Mailbox { mailbox_id: "inbox-1", member: false },
                ],
            )],
            "c0",
        );

        // A JMAP Request object (RFC 8620 §3.3): the capabilities it uses + the method calls.
        assert_eq!(body["using"], json!([JMAP_CORE, JMAP_MAIL]));

        let call = &body["methodCalls"][0];
        assert_eq!(call[0], "Email/set", "the method name");
        assert_eq!(call[2], "c0", "the client-supplied call id");

        let args = &call[1];
        assert_eq!(args["accountId"], "acct-1");

        // The surgical PatchObject: add to archive (true), remove from inbox (null) — never a
        // full mailboxIds replace, which would strip other labels (RFC 8621).
        let patch = &args["update"]["eml-1"];
        assert_eq!(patch["mailboxIds/archive-1"], json!(true), "add → true");
        assert_eq!(patch["mailboxIds/inbox-1"], json!(null), "remove → null");
    }

    #[test]
    fn email_set_body_carries_keyword_patches() {
        // Pure body-builder test: the keywords/$seen wire shape survives to
        // the JSON body — the regression test for the silent-drop class (the OLD builder only ever
        // emitted mailboxIds/ keys, so a keyword patch became an empty no-op reported as success).
        let typed = vec![("e1", vec![PatchOp::Keyword { name: "$seen", set: true }])];
        let body = build_email_set_body("acct", &typed, "c1");
        assert_eq!(
            body["methodCalls"][0][1]["update"]["e1"]["keywords/$seen"],
            serde_json::json!(true)
        );
        let cleared = vec![("e1", vec![PatchOp::Keyword { name: "$seen", set: false }])];
        let body = build_email_set_body("acct", &cleared, "c1");
        assert_eq!(
            body["methodCalls"][0][1]["update"]["e1"]["keywords/$seen"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn email_set_body_carries_the_flagged_keyword_patch() {
        // The $flagged twin of the $seen test above (star/unstar design 2026-07-26 §5.4): the
        // builder formats keywords/{name} generically, and this pins that the star verb's OWN
        // wire shape survives to the JSON body — set → true, clear → null.
        let typed = vec![("e1", vec![PatchOp::Keyword { name: "$flagged", set: true }])];
        let body = build_email_set_body("acct", &typed, "c1");
        assert_eq!(
            body["methodCalls"][0][1]["update"]["e1"]["keywords/$flagged"],
            serde_json::json!(true)
        );
        let cleared = vec![("e1", vec![PatchOp::Keyword { name: "$flagged", set: false }])];
        let body = build_email_set_body("acct", &cleared, "c1");
        assert_eq!(
            body["methodCalls"][0][1]["update"]["e1"]["keywords/$flagged"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn email_set_body_still_carries_mailbox_patches() {
        let typed = vec![("e1", vec![
            PatchOp::Mailbox { mailbox_id: "inbox", member: false },
            PatchOp::Mailbox { mailbox_id: "arch", member: true },
        ])];
        let body = build_email_set_body("acct", &typed, "c9");
        assert_eq!(body["methodCalls"][0][1]["update"]["e1"]["mailboxIds/inbox"], serde_json::Value::Null);
        assert_eq!(body["methodCalls"][0][1]["update"]["e1"]["mailboxIds/arch"], serde_json::json!(true));
    }

    // ============================================================================================
    // THE ONE-WIRE CONTRACT — the redirect arm (design §5.2b
    // ACK-VERDICT-AND-ONE-WIRE-CONTRACT: `retry::never()`-class configuration does
    // not touch redirects).
    //
    // `FakeHttp` structurally CANNOT prove any of this: it has no connection pool and never hands a
    // real `Location` header to a real client, so a fake-driven redirect assertion passes even with
    // redirect-following fully enabled. These witnesses drive the REAL `ReqwestClient` against a
    // listener this test starts and owns. No external network is touched.
    // ============================================================================================

    /// The server-chosen resource a FOLLOWING client re-POSTs the mutation to. Its appearance in any
    /// recorded request line is the replay, caught red-handed.
    const REDIRECT_VICTIM_PATH: &str = "/jmap/server-chosen-victim";

    /// A loopback JMAP endpoint this test owns. It answers Session discovery and both
    /// `Mailbox/query` role lookups normally, answers the FIRST `Email/set` POST with a
    /// SAME-AUTHORITY redirect, and answers any FURTHER `Email/set` POST with a SUCCESSFUL
    /// `Email/set` reply — so a client that follows both touches the provider twice AND is told the
    /// duplicated credentialed mutation applied at the server-chosen resource.
    struct RedirectingJmap {
        port: u16,
        requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RedirectingJmap {
        /// The first line of every recorded request (`POST /jmap HTTP/1.1`).
        fn request_lines(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("lock")
                .iter()
                .map(|r| r.lines().next().unwrap_or_default().to_string())
                .collect()
        }

        /// How many `Email/set` POSTs actually reached the provider. Counted on the REQUEST BODY,
        /// not on connections: a redirect followed over a REUSED connection is still a second
        /// provider touch, and connection counting would miss it.
        fn email_set_touches(&self) -> usize {
            self.requests
                .lock()
                .expect("lock")
                .iter()
                .filter(|r| r.contains("Email/set"))
                .count()
        }
    }

    /// Read exactly one HTTP request (head + `Content-Length` body) off the stream.
    fn read_one_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
        use std::io::Read;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
            let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
                continue;
            };
            let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
            let expected = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while raw.len() < head_end + expected {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            }
            return Some(String::from_utf8_lossy(&raw).to_string());
        }
    }

    /// Answer one request: role queries and Session discovery normally; the first `Email/set` with
    /// `redirect_status`, later ones with success.
    fn answer_jmap(
        request: &str,
        port: u16,
        redirect_status: u16,
        email_set_seen: &mut usize,
    ) -> String {
        let body = request.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let call: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let method = call["methodCalls"][0][0].as_str().unwrap_or("");
        let call_id = call["methodCalls"][0][2].as_str().unwrap_or("c0").to_string();
        let payload = match method {
            "Mailbox/query" => {
                let role = call["methodCalls"][0][1]["filter"]["role"].as_str().unwrap_or("");
                let id = if role == "inbox" { "MBX-inbox" } else { "MBX-archive" };
                mailbox_ids(id, &call_id)
            }
            "Email/set" => {
                *email_set_seen += 1;
                if *email_set_seen == 1 {
                    return format!(
                        "HTTP/1.1 {redirect_status} Redirect\r\n\
                         Location: {REDIRECT_VICTIM_PATH}\r\n\
                         Content-Length: 0\r\n\r\n"
                    );
                }
                format!(
                    r#"{{"methodResponses":[["Email/set",{{"accountId":"ACCT-1","updated":{{"EML-1":null}}}},"{call_id}"]]}}"#
                )
            }
            // Session discovery is a GET with no JSON body.
            _ => session_body(&format!("http://127.0.0.1:{port}/jmap")),
        };
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        )
    }

    fn spawn_redirecting_jmap(redirect_status: u16) -> RedirectingJmap {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&requests);
        std::thread::spawn(move || {
            let mut email_set_seen = 0usize;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                // Serve every request on this connection: a redirect followed on a REUSED
                // connection must still be recorded.
                while let Some(request) = read_one_http_request(&mut stream) {
                    recorder.lock().expect("lock").push(request.clone());
                    let response = answer_jmap(&request, port, redirect_status, &mut email_set_seen);
                    if stream.write_all(response.as_bytes()).is_err() {
                        break;
                    }
                }
            }
        });
        RedirectingJmap { port, requests }
    }

    /// W-ONE-WIRE-ATTEMPT, redirect arm: a 307/308 answer to an `Email/set` must produce EXACTLY
    /// ONE wire dispatch, and the outcome must be an honest refusal — never a replay.
    fn one_wire_redirect_arm(redirect_status: u16) {
        let server = spawn_redirecting_jmap(redirect_status);
        let transport = HttpJmapTransport::connect_for_test_fixture(
            &format!("http://127.0.0.1:{}", server.port),
            "user@example.test",
            "pw",
        )
        .expect("the loopback fixture connects and opens the destructive-write gate");
        let conn = JmapConnector::new(transport, Fixed, Fixed);

        let result = conn.apply(&archive_cmd(), &archive_basis());

        // Checked BEFORE the verdict: whatever we return, the provider must have been touched by
        // the mutation exactly ONCE. This is the property; the verdict below is its honest report.
        assert_eq!(
            server.email_set_touches(),
            1,
            "one attempt = at most one potentially effectful wire dispatch ({redirect_status}); \
             recorded: {:#?}",
            server.request_lines()
        );
        assert!(
            !server
                .request_lines()
                .iter()
                .any(|line| line.contains(REDIRECT_VICTIM_PATH)),
            "the server-chosen resource must never be requested ({redirect_status}): {:#?}",
            server.request_lines()
        );

        let err = result.expect_err("a redirected mutation is a refusal, never a replay");
        assert_eq!(
            err.kind,
            FailureKind::Deterministic,
            "a provider that redirects a mutation is not having a transient blip"
        );
        assert_eq!(
            err.effect_evidence,
            aruna::EffectEvidence::Indeterminate,
            "codex-CLI r2 P1: a 3xx after a POST is routinely the COMPLETED action's redirect \
             (303 See Other), so it proves NOTHING about effect — the one-wire refusal keeps a \
             SECOND effect from happening and honestly says it cannot speak for the first"
        );
    }

    #[test]
    fn a_real_307_on_a_mutation_produces_exactly_one_wire_touch_and_an_indeterminate_refusal() {
        one_wire_redirect_arm(307);
    }

    #[test]
    fn a_real_308_on_a_mutation_produces_exactly_one_wire_touch_and_an_indeterminate_refusal() {
        one_wire_redirect_arm(308);
    }

    #[test]
    fn a_redirect_answer_on_the_mutation_route_is_refused_on_the_status_before_the_body() {
        // The hostile pairing the status-first ordering exists to defeat: a 3xx whose body is a
        // well-formed RFC 8620 §3.6.1 problem-details document naming a CONCURRENCY limit — the one
        // request-level problem the taxonomy calls TRANSIENT. If the body were consulted first, a
        // redirect would classify retryable and the engine would re-dispatch the mutation.
        let server = spawn_problem_details_redirect();
        let client = ReqwestClient::new(Auth::Bearer("tok".to_string())).expect("client builds");
        let url = format!("http://127.0.0.1:{}/jmap", server.port);
        let body = build_email_set_body("ACCT-1", &[("EML-1", vec![])], "c0");

        let err = client
            .post_json_mutation(&url, &body)
            .expect_err("a redirected mutation is refused");
        assert_eq!(
            err,
            JmapError::Transport(TransportError::MutationRedirectRefused)
        );
        assert_eq!(
            classify_jmap_error(&err),
            FailureKind::Deterministic,
            "the transient problem-details body must not survive the status verdict"
        );
        assert_eq!(server.email_set_touches(), 1, "one dispatch, one answer");
    }

    /// A loopback endpoint that answers EVERY POST with a 307 whose body is a transient-classifying
    /// JMAP problem-details document.
    fn spawn_problem_details_redirect() -> RedirectingJmap {
        use std::io::Write;
        const TRANSIENT_PROBLEM: &str = r#"{"type":"urn:ietf:params:jmap:error:limit","limit":"maxConcurrentRequests"}"#;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                while let Some(request) = read_one_http_request(&mut stream) {
                    recorder.lock().expect("lock").push(request);
                    let response = format!(
                        "HTTP/1.1 307 Temporary Redirect\r\n\
                         Location: {REDIRECT_VICTIM_PATH}\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        TRANSIENT_PROBLEM.len(),
                        TRANSIENT_PROBLEM
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        break;
                    }
                }
            }
        });
        RedirectingJmap { port, requests }
    }

    // ---- the live client's response read is BOUNDED ----

    /// Comfortably over the wire ceiling (pinned to the constant by
    /// [`the_oversized_fixture_really_is_over_the_wire_ceiling`], so the fixture cannot drift).
    const OVER_CEILING_BYTES: usize = 13 * 1024 * 1024;

    /// How the oversized-response listener answers a request.
    #[derive(Clone, Copy)]
    enum Oversized {
        /// Headers advertising a body far over the ceiling, and then NOTHING — the connection is
        /// held open. A client that consults `Content-Length` first returns at once; a client that
        /// reads first waits out its own total timeout. That gap is the witness.
        AdvertiseAndWithhold,
        /// No `Content-Length` at all (EOF-delimited, `Connection: close`) and an actual body far
        /// over the ceiling. The header check CANNOT fire here, so only a limited read refuses it.
        StreamOverCeiling,
    }

    fn spawn_oversized_responder(mode: Oversized) -> RedirectingJmap {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&requests);
        std::thread::spawn(move || {
            // ONE connection, ONE answer: both arms end the exchange (the withholding arm holds the
            // socket open, the streaming arm closes it), so there is never a second request.
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                if let Some(request) = read_one_http_request(&mut stream) {
                    recorder.lock().expect("lock").push(request);
                    let written = match mode {
                        Oversized::AdvertiseAndWithhold => stream.write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {OVER_CEILING_BYTES}\r\n\r\n"
                            )
                            .as_bytes(),
                        ),
                        Oversized::StreamOverCeiling => stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                  Connection: close\r\n\r\n",
                            )
                            .and_then(|()| stream.write_all(&vec![b'x'; OVER_CEILING_BYTES])),
                    };
                    if written.is_ok() && matches!(mode, Oversized::AdvertiseAndWithhold) {
                        // The promised body never comes. Hold the socket so a client that reads
                        // before checking the header waits on US rather than seeing a clean EOF.
                        std::thread::sleep(Duration::from_secs(30));
                    }
                }
            }
        });
        RedirectingJmap { port, requests }
    }

    #[test]
    fn an_over_ceiling_advertised_length_is_refused_before_the_live_client_reads_the_body() {
        // Regression test. `resp.text()` buffers whatever the server sends,
        // with no ceiling and no look at `Content-Length` — a hostile JMAP server could name any
        // size it liked and we would try to hold it.
        //
        // The discriminator is TIME: this server promises 13 MiB and sends nothing, holding the
        // connection open. Consulting the header first returns in milliseconds; reading first
        // blocks until the client's own 30-second total timeout (and then classifies TRANSIENT,
        // i.e. retryable — the wrong verdict as well as the wrong cost).
        let server = spawn_oversized_responder(Oversized::AdvertiseAndWithhold);
        let client = ReqwestClient::new(Auth::Bearer("tok".to_string())).expect("client builds");
        let url = format!("http://127.0.0.1:{}/jmap", server.port);

        let started = std::time::Instant::now();
        let err = client
            .post_json(&url, &json!({"using": [], "methodCalls": []}))
            .expect_err("an over-ceiling Content-Length fails closed");
        let elapsed = started.elapsed();

        assert_eq!(
            classify_jmap_error(&err),
            FailureKind::Deterministic,
            "a server naming an impossible body size is not having a transient blip"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the over-ceiling header must short-circuit BEFORE the body is read; this call took \
             {elapsed:?}, i.e. it waited on a body that never came"
        );
    }

    #[test]
    fn a_body_over_the_ceiling_is_refused_even_when_no_length_is_advertised() {
        // Regression test. EOF-delimited, so the header check cannot fire:
        // the only thing that can refuse this is a LIMITED read. Before the fix the whole 13 MiB
        // was buffered into a `String` and handed up as a successful exchange.
        let server = spawn_oversized_responder(Oversized::StreamOverCeiling);
        let client = ReqwestClient::new(Auth::Bearer("tok".to_string())).expect("client builds");
        let url = format!("http://127.0.0.1:{}/jmap", server.port);

        let err = client
            .post_json(&url, &json!({"using": [], "methodCalls": []}))
            .expect_err("a body over the ceiling is refused, never buffered whole");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn the_oversized_fixture_really_is_over_the_wire_ceiling() {
        // The two live tests above are only witnesses if their fixture actually exceeds the bound.
        assert!(
            OVER_CEILING_BYTES as u64 > MAX_RESPONSE_WIRE_BYTES,
            "fixture {OVER_CEILING_BYTES} must exceed the ceiling {MAX_RESPONSE_WIRE_BYTES}"
        );
    }

    #[test]
    fn the_wire_ceiling_is_derived_from_the_body_cap_for_two_escaped_body_values() {
        // The bound is an EXPRESSION over the named constants: moving BODY_FETCH_CAP moves it.
        // What must hold is that the worst LEGITIMATE body read still fits, with envelope margin.
        let two_escaped_bodies = 2 * BODY_FETCH_CAP as u64 * 6;
        assert!(MAX_RESPONSE_WIRE_BYTES > two_escaped_bodies);
        assert_eq!(
            MAX_RESPONSE_WIRE_BYTES - two_escaped_bodies,
            512 * 1024,
            "the JSON-envelope margin"
        );
    }

    #[test]
    fn the_bounded_read_accepts_exactly_the_ceiling_and_refuses_one_byte_more() {
        // The contract is exact, and it is asserted on the ENFORCING function with synthetic
        // readers — no socket, no provider, and an INFINITE reader for the over-cap arm, which only
        // terminates because the read is limited. That is the property, stated as a test that
        // cannot pass without it.
        use std::io::Read as _;
        let at_ceiling = std::io::repeat(b'x').take(MAX_RESPONSE_WIRE_BYTES);
        let body = read_response_bounded(at_ceiling).expect("exactly MAX is accepted");
        assert_eq!(body.len() as u64, MAX_RESPONSE_WIRE_BYTES);

        let endless = std::io::repeat(b'x');
        let err = read_response_bounded(endless).expect_err("over MAX is refused");
        assert_eq!(
            classify_jmap_error(&err),
            FailureKind::Deterministic,
            "a body that will not stop is not a transient blip"
        );
    }

    #[test]
    fn an_advertised_length_is_refused_only_when_it_exceeds_the_ceiling() {
        assert!(refuse_oversized_advertised_length(None).is_ok(), "chunked: nothing advertised");
        assert!(refuse_oversized_advertised_length(Some(MAX_RESPONSE_WIRE_BYTES)).is_ok());
        let err = refuse_oversized_advertised_length(Some(MAX_RESPONSE_WIRE_BYTES + 1))
            .expect_err("one byte over the ceiling fails closed");
        assert_eq!(classify_jmap_error(&err), FailureKind::Deterministic);
    }

    // ---- the drift tripwires (§5.2b: "an HTTP-client retry/redirect-policy drift tripwire") ----

    #[test]
    fn the_mutation_route_redirect_policy_is_structurally_the_no_redirect_policy() {
        // STRUCTURAL, not behavioral: asserted on the CONSTRUCTED policy value, so this fails the
        // moment someone hands the mutation client a custom/limited policy — even one that would
        // pass every behavioral test we happen to have written. reqwest exposes no way to read the
        // policy back off a BUILT client, so the named constructor is the assertable seam.
        assert_eq!(
            format!("{:?}", mutation_route_redirect_policy()),
            format!("{:?}", reqwest::redirect::Policy::none()),
            "the mutation route must follow NOTHING (§5.2b one-wire contract)"
        );
        // And the two route classes must not have collapsed into one policy.
        assert_ne!(
            format!("{:?}", mutation_route_redirect_policy()),
            format!("{:?}", read_route_redirect_policy()),
            "the read route keeps its same-authority chain; the split is the point"
        );
    }

    #[test]
    fn every_read_stays_on_the_read_route_and_only_email_set_takes_the_mutation_route() {
        // The other half of the tripwire: the POLICY is only worth anything if `Email/set` is the
        // call that uses it. In JMAP every method call is a POST to the same apiUrl, so nothing but
        // this assertion stops a mutation from drifting back onto the redirect-following client.
        let (probe, result) = archive_with_set_result(
            r#"{"methodResponses":[["Email/set",{"accountId":"ACCT-1","updated":{"EML-1":null}},"c0"]]}"#,
        );
        result.expect("archive over the synthetic wire");
        assert_eq!(
            probe.routes(),
            vec![Route::Get, Route::Mutation],
            "session discovery is the GET route; the Email/set is the ONLY mutation-route call. \
             (The two Mailbox/query READS this used to list are gone — the dispatch consumes the \
             frozen role pair, codex-CLI r3 P1-2 — which makes the assertion sharper, not weaker: \
             there is nothing else left on the wire at all.)"
        );

        // The read-only method calls, each on its own, stay on the read route.
        let fake = FakeHttp::new(vec![
            resp(200, &session_body("https://localhost/jmap")),
            resp(
                200,
                r#"{"methodResponses":[["Mailbox/get",{"accountId":"ACCT-1","state":"s1","list":[]},"c0"]]}"#,
            ),
            resp(
                200,
                r#"{"methodResponses":[["Email/get",{"accountId":"ACCT-1","state":"s1","list":[{"id":"EML-1","mailboxIds":{"MBX-inbox":true},"keywords":{}}],"notFound":[]},"c1"]]}"#,
            ),
        ]);
        let probe = fake.clone();
        let transport =
            HttpJmapTransport::connect_with(fake, "https://localhost").expect("connect");
        let account = AccountId("ACCT-1".to_string());
        transport.mailbox_state(&account).expect("state cursor");
        transport
            .email_current_state(&account, &EmailId("EML-1".to_string()))
            .expect("current state");
        assert_eq!(
            probe.routes(),
            vec![Route::Get, Route::Read, Route::Read],
            "no read may take the mutation route: it would lose the same-authority chain for nothing"
        );
    }

    #[test]
    fn the_read_route_still_follows_a_same_authority_redirect() {
        // The split's OTHER side, proven against a real client: read routes KEEP the chain
        // (`transport.rs` read policy). If the no-redirect policy is ever applied wholesale, this
        // fails — the split is not a euphemism for "turn redirects off everywhere".
        let server = spawn_redirecting_read();
        let client = ReqwestClient::new(Auth::Bearer("tok".to_string())).expect("client builds");
        let resp = client
            .get(&format!("http://127.0.0.1:{}/.well-known/jmap", server.port))
            .expect("the read follows the same-authority redirect");
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("apiUrl"), "the followed read landed");
        let lines = server.request_lines();
        assert_eq!(lines.len(), 2, "one redirect, one follow: {lines:#?}");
        assert!(
            lines[1].contains("/jmap/session"),
            "the read reached the redirect target: {lines:#?}"
        );
    }

    /// A loopback endpoint that redirects `/.well-known/jmap` to `/jmap/session` on the SAME
    /// authority and serves the Session resource there — the legitimate discovery hop.
    fn spawn_redirecting_read() -> RedirectingJmap {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                while let Some(request) = read_one_http_request(&mut stream) {
                    let well_known = request.starts_with("GET /.well-known/jmap");
                    recorder.lock().expect("lock").push(request);
                    let response = if well_known {
                        "HTTP/1.1 302 Found\r\nLocation: /jmap/session\r\nContent-Length: 0\r\n\r\n"
                            .to_string()
                    } else {
                        let payload = session_body(&format!("http://127.0.0.1:{port}/jmap"));
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\n\r\n{}",
                            payload.len(),
                            payload
                        )
                    };
                    if stream.write_all(response.as_bytes()).is_err() {
                        break;
                    }
                }
            }
        });
        RedirectingJmap { port, requests }
    }

    #[test]
    fn the_gmail_transport_already_conforms_on_its_mutation_path() {
        // VERIFY + CITE, no change expected. Byte-checked at
        // `crates/aruna-gmail/src/transport.rs` on this HEAD:
        //   :1039  `.redirect(reqwest::redirect::Policy::none())`  — the ONE client that crate
        //          builds, so every request (its mutation path included) follows nothing.
        //   :961-991  the module note that RULED on the other half: `retry::never()` is INERT
        //          without the `http2`/`http3` features and is deliberately absent.
        //   :2702  `a_real_307_produces_exactly_one_request_and_never_replays_the_mutation` — the
        //          real-client loopback witness, the twin of the two above.
        // The difference in SHAPE is intended: Gmail's endpoint is compiled in and it has no
        // discovery hop, so one no-redirect client covers it; JMAP must keep a redirect-following
        // READ route for `/.well-known/jmap` discovery, which is why this crate splits by route.
        // This test exists so the citation cannot rot silently.
        let gmail_transport = include_str!("../../aruna-gmail/src/transport.rs");
        assert!(
            gmail_transport.contains(".redirect(reqwest::redirect::Policy::none())"),
            "aruna-gmail's mutation path must still follow nothing"
        );
        assert!(
            !gmail_transport.contains("redirect::Policy::custom")
                && !gmail_transport.contains("redirect::Policy::limited"),
            "aruna-gmail must not have grown a redirect-FOLLOWING policy"
        );
        assert!(
            !gmail_transport.contains(".retry("),
            "aruna-gmail must not have grown an internal retry policy"
        );
    }
}
