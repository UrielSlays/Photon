//! The live HTTP Gmail transport: `HttpGmailTransport` implements `aruna::gmail::GmailTransport`
//! over a hand-rolled `reqwest::blocking` + serde surface (`users.messages.modify`). The wire shape
//! lives here; the wire to taxonomy mapping lives in [`crate::error`]. Provider ids and response
//! text never cross back above the seam, only typed `aruna::gmail::GmailError` variants do.
//!
//! # Endpoint identity is compiled in
//!
//! Production has no host parameter. [`GMAIL_ENDPOINT`] is the discovery `rootUrl`, and every
//! production URL is built from it locally. There is no allowlist to widen, no base path to
//! normalize, and no parameter through which a typosquat (`gmai1.googleapis.com`), a proxy prefix
//! (`https://gmail.googleapis.com/proxy`), or a userinfo/query/fragment could be passed. **Never
//! widen this to a `*.googleapis.com` suffix match**, and never let `require_tls_or_local`
//! become the sole host constraint: that would reopen the class this design closes.

use aruna::gmail::{
    classify_gmail_error, GmailError, GmailMessageId, GmailModifyRequest, GmailTransport,
    GmailUserId,
};
use aruna::read_model::{Placement, ProviderMessageId, ProviderPlacement};
use aruna::read_surface::{
    clamp_page_size, AttachmentPresence, ContinuationToken, HeaderSummary, ListedPage, RawBody,
};
use aruna::{ConnectorError, FailureKind};
use std::collections::BTreeSet;

/// The single compiled production endpoint: Gmail's discovery `rootUrl`, path exactly `/`.
///
/// The service definition lists this one host. The published mTLS endpoint
/// (`https://gmail.mtls.googleapis.com/`) is unsupported (no client-certificate machinery in
/// this crate), and Private Google Access works by DNS-routing `*.googleapis.com` rather than by
/// changing the application hostname, so pinning the host breaks no documented deployment.
pub const GMAIL_ENDPOINT: &str = "https://gmail.googleapis.com/";

/// The transport's single deterministic, id-free refusal.
///
/// `GmailError` carries no string payload, so a refused host, a rejected identifier or a hostile
/// response body has nowhere to travel out of this crate (ADR-P003/P004).
fn refused() -> GmailError {
    GmailError::Unknown
}

/// The transport's pre-socket refusal: the same deterministic, id-free discipline as
/// [`refused`], plus what `Unknown` cannot carry, positive proof that nothing was dispatched.
///
/// Use it only where no network call can have happened yet: the identifier-validating URL
/// builder, the ADR-P010 destructive-write gate (both run before a socket exists on the mutation
/// route), and one send-stage failure, a rustls certificate-validation failure. A rejected
/// handshake means no request byte was written, and [`is_tls_certificate_error`] proves that
/// positively. Any other post-dispatch stall keeps [`refused`], per `send_stage_verdict`'s
/// fail-closed contract, because the transport cannot prove the request did not land.
fn pre_wire_refused() -> GmailError {
    GmailError::PreWireRefused
}

/// Refusal to authorize live destructive writes against a non-local / production-looking host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// Only an actual loopback host (literal `localhost` + loopback IPs) may be authorized; a
    /// `.test`/`.localhost` name is not proof of locality (it can resolve off-machine).
    NonLocalHostRefused,
}

/// ADR-P010 default-closed runtime gate: a destructive write (`messages.modify`,
/// `messages.trash`, `messages.untrash`) is refused unless the gate has been opened for the exact
/// host being written to, and it can only be opened for a loopback host, so a real mailbox can
/// never be written. Every `modify_labels` / `modify_labels_observed` / `trash_message` /
/// `untrash_message` is a write, so with the gate closed this transport performs no writes (the
/// read routes do not pass this gate).
///
/// This is one of two independent guards keeping the live drill parked (the other is ADR
/// Part III). `allow_test_host("gmail.googleapis.com")` is refused, and a test checks that.
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

    /// Authorize destructive writes against one loopback host. Refuses any non-loopback host (a
    /// `.test`/`.localhost` name is not proof of locality, since it can resolve off-machine), so
    /// only literal `localhost` and loopback IPs qualify. This is the only way to enable live
    /// writes, and it cannot be pointed at a real mailbox.
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
/// partial or embedded brackets) is left intact and is then refused by the `IpAddr`/locality
/// checks downstream.
fn canonical_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .filter(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
        .unwrap_or(host)
}

/// Is `host` an actual loopback target? Loopback is proof of locality; a `.test`/`.localhost`
/// name is not, since it can resolve off-machine. Only literal `localhost` and loopback IPs
/// (127.0.0.0/8, `::1`) qualify.
///
/// The comparison is byte-exact. Obfuscated loopback forms (`127.1`, `2130706433`, `0x7f.1`) are
/// not decoded here; the URL parser normalizes them and the gate is always keyed from the parsed
/// host (`host_of`), so the gate and the URL agree and there is no second address grammar to
/// disagree about. Handed a raw obfuscated string, this returns `false` and the gate stays shut.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || canonical_host(host)
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// The host of a URL, if parseable; binds the destructive-write gate to the exact target a write
/// would hit.
fn host_of(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Refuse to send credentials over plaintext. TLS (`https`) is allowed; plaintext (`http`) only
/// to an actual loopback host.
///
/// This guards the fixture base only. Production never passes through here, and this function
/// must never become the sole host constraint on a production path: `https` to any host satisfies
/// it, which is the JMAP rule whose justification does not transfer to Gmail (JMAP's server is
/// user-chosen; Gmail's is not).
fn require_tls_or_local(base_url: &str) -> Result<(), GmailError> {
    let url = reqwest::Url::parse(base_url).map_err(|_| refused())?;
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() == "http" && is_loopback_host(url.host_str().unwrap_or("")) {
        return Ok(());
    }
    Err(refused())
}

/// Gmail's partial-response narrowing for `messages.modify`. `Message` can carry `snippet`,
/// `payload`, headers and body parts; the applied-state check needs only these two fields, so
/// asking for only these is the data-minimization half of the response bounds. It limits what a
/// well-behaved server sends; a hostile one can ignore it, which is why the byte caps exist and
/// why neither control substitutes for the other.
const PARTIAL_RESPONSE_FIELDS: &str = "fields=id,labelIds";

/// Validate an id that will become a URL path segment, before any URL is built.
///
/// Validate, then construct; the encoder is not the defense. Checked against `url 2.5.8`:
/// `PathSegmentsMut::push` percent-encodes `/`, `?`, `#`, `%` and NUL, but does not encode exact
/// dot segments, it elides them. `userId = ".."` yields `/gmail/v1/users/messages/{id}/modify`
/// (six segments), silently shifting the route onto a different resource. The newtypes
/// `aruna::gmail::GmailUserId` / `GmailMessageId` carry no validation of their own, so this is
/// the only place the class is closed.
///
/// Beyond empty, `.` and `..` the ids stay opaque. Gmail publishes no character grammar for
/// message ids and `userId` is legitimately an email address, so a stricter charset would reject
/// legitimate traffic on an unsourced rule.
fn validate_path_id(id: &str) -> Result<(), GmailError> {
    if id.is_empty() || id == "." || id == ".." {
        // Before any socket: there is not even a URL yet.
        return Err(pre_wire_refused());
    }
    Ok(())
}

/// Validate a fixture base: scheme, host and optional port only.
///
/// Userinfo, a non-root path, a query and a fragment are all refused, because changing a URL's
/// path does not clear its query or fragment. Probed: `path_segments_mut().clear()` on
/// `https://gmail.googleapis.com/prefix?alt=media#frag` yields `…/messages/M/modify?alt=media#frag`,
/// and a surviving `alt=media` can change how a response is handled after the provider has
/// already applied the mutation. An origin has no path to normalize, which also covers the
/// narrower dot/empty-segment rules.
///
/// Production never passes through here; it has no base parameter.
fn parse_origin(base: &str) -> Result<reqwest::Url, GmailError> {
    let url = reqwest::Url::parse(base).map_err(|_| refused())?;
    let is_origin = url.username().is_empty()
        && url.password().is_none()
        && (url.path().is_empty() || url.path() == "/")
        && url.query().is_none()
        && url.fragment().is_none();
    if !is_origin {
        return Err(refused());
    }
    Ok(url)
}

/// Build the `users.messages.modify` URL for one message: the fixed route, on the given base.
///
/// Both ids are validated first (see [`validate_path_id`]), so a refusal happens before any URL
/// exists and therefore before any socket. The route is exactly seven segments, the query is
/// exactly the partial-response narrowing, and the fragment is cleared so nothing carries over
/// from a base.
fn modify_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
) -> Result<reqwest::Url, GmailError> {
    message_action_url(base, user, message, "modify")
}

/// The single builder behind every `users.messages.{id}/{action}` write route (`modify`,
/// `trash`, `untrash`), so the routes cannot drift: both ids are validated first, then exactly
/// seven segments ending in the fixed `action`, then the query is set to exactly the
/// partial-response narrowing, then the fragment is cleared. `action` is `'static`: a compiled
/// literal at every call site, never data.
fn message_action_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
    action: &'static str,
) -> Result<reqwest::Url, GmailError> {
    validate_path_id(&user.0)?;
    validate_path_id(&message.0)?;
    let mut url = base.clone();
    url.path_segments_mut()
        // Cannot-be-a-base: still before any socket.
        .map_err(|_| pre_wire_refused())?
        .clear()
        .extend([
            "gmail", "v1", "users", &user.0, "messages", &message.0, action,
        ]);
    url.set_query(Some(PARTIAL_RESPONSE_FIELDS));
    url.set_fragment(None);
    Ok(url)
}

/// `users.messages.trash` — Gmail's dedicated trash route, on [`message_action_url`].
fn trash_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
) -> Result<reqwest::Url, GmailError> {
    message_action_url(base, user, message, "trash")
}

/// `users.messages.untrash` — the inverse route, on [`message_action_url`].
fn untrash_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
) -> Result<reqwest::Url, GmailError> {
    message_action_url(base, user, message, "untrash")
}

// The HTTP seam and the transport. The network sits behind a tiny `HttpClient` trait so the
// orchestration (URL construction, the gate, status to taxonomy, the applied-state check) is
// testable with a fake; `ReqwestClient` is the thin real part.
//
// A fake cannot grade client configuration: `FakeHttp` has no connection pool and never hands a
// real `Location` header to a real client, so a fake-driven redirect or pooling assertion would
// pass even if `redirect::Policy::none()` were absent. The real-client tests cover that.

/// A completed HTTP exchange: the status, the advertised `Content-Length` (when the server sent
/// one), and the already-read body. A completed exchange of any status is `Ok` here; status
/// mapping stays in the orchestration, and only a network-level failure (no response) becomes a
/// `GmailError` inside the client.
///
/// `pub(crate)`: nothing outside this crate consumes a raw exchange. A write returns across the
/// seam only a typed `aruna::gmail::GmailError`, `Ok(())`, or the label set parsed from the
/// id-correlated 2xx body, never the raw body (ADR-P003/P004).
pub(crate) struct HttpResponse {
    /// The HTTP status.
    pub(crate) status: u16,
    /// The advertised body length, when the server sent one. Checked before the body is read so
    /// an over-cap response can be refused without materializing it.
    pub(crate) content_length: Option<u64>,
    /// The response body, already bounded by the client's read cap.
    pub(crate) body: String,
}

/// Redacted `Debug`: a real `Message` response carries provider ids (and can carry `snippet`,
/// headers and body parts if a server ignores the partial-response narrowing), so only the status
/// is printed and the body is reduced to its byte length.
impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HttpResponse {{ status: {}, content_length: {:?}, body: <{} bytes redacted> }}",
            self.status,
            self.content_length,
            self.body.len()
        )
    }
}

/// A caller-supplied OAuth2 bearer access token. A newtype so the secret has one home and one
/// redacted `Debug`.
///
/// Never persisted, never logged, never placed in a URL. There is no OAuth flow and no refresh in
/// this crate, which is why HTTP 401 stays deterministic here.
///
/// `pub(crate)`, like the client it authenticates.
#[derive(Clone)]
pub(crate) struct BearerToken(String);

impl BearerToken {
    /// Wrap a caller-supplied access token.
    pub(crate) fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The raw token. The only read path, used solely to set the `Authorization` header.
        fn expose(&self) -> &str {
        &self.0
    }
}

/// Redacted `Debug`: the secret must never reach `{:?}` output (logs, `expect_err`).
impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// The minimal HTTP surface this transport needs, decoupling Gmail orchestration from the
/// network. The real impl (`ReqwestClient`) maps network-level failures onto the taxonomy by
/// call-site stage; everything above it deals only in `(status, content_length, body)`.
///
/// `pub(crate)`: a test seam, not a public API; the public way to reach Gmail is
/// [`HttpGmailTransport`].
pub(crate) trait HttpClient {
    /// POST a JSON body and return the completed exchange.
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse, GmailError>;

    /// POST with no body: Gmail's `users.messages.trash` / `untrash` reference says "The request
    /// body must be empty". Same auth header, send-stage split and bounded read as `post_json`,
    /// but no body is serialized and `Content-Length: 0` is declared, since Google's front end
    /// answers a bodiless POST without it with 411 (googleworkspace/cli#182; RFC 9110 §8.6
    /// recommends a `Content-Length` on a bodiless POST).
    fn post_empty(&self, url: &str) -> Result<HttpResponse, GmailError>;

    /// GET and return the completed exchange (the read route). Same dispatch shell as the POST:
    /// auth header, byte caps, strict decode.
    ///
    /// `route` declares which read this is; the bounded read resolves its ceiling from it
    /// ([`wire_body_cap`]), since a body-fetch route may legitimately carry far more than a
    /// label-shaped one and the reader has no URL left to infer that from.
    fn get(&self, url: &str, route: WireRoute) -> Result<HttpResponse, GmailError>;
}

/// The Gmail orchestration, generic over the HTTP client so it is testable with a fake: URL
/// construction, the gate, status mapping and the applied-state check. `pub(crate)` so the `C`
/// parameter and `HttpClient` bound stay out of the public interface; [`HttpGmailTransport`]
/// is the non-generic public wrapper.
///
/// Unlike JMAP there is no session discovery at connect time (Gmail is a fixed REST endpoint),
/// so construction touches no network. `Debug` is redacted: the base is a provider endpoint and,
/// on the fixture path, caller-supplied.
pub(crate) struct GatedTransport<C> {
    client: C,
    /// The origin every request is built on: the compiled endpoint in production, a validated
    /// loopback origin on the fixture path.
    base: reqwest::Url,
    /// ADR-P010 default-closed runtime gate guarding every write (`modify_labels` /
    /// `modify_labels_observed`, and `trash_message` / `untrash_message`).
    gate: DestructiveWriteGate,
}

impl<C: std::fmt::Debug> std::fmt::Debug for GatedTransport<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatedTransport")
            .field("client", &self.client)
            .field("base", &"<redacted>")
            .field("gate", &self.gate)
            .finish()
    }
}

impl<C> GatedTransport<C> {
    /// Production construction over an arbitrary client: the base is the compiled endpoint (there
    /// is no base parameter) and the gate is closed.
    pub(crate) fn production_with(client: C) -> Self {
        Self {
            client,
            base: reqwest::Url::parse(GMAIL_ENDPOINT)
                .expect("the compiled endpoint is a valid URL"),
            gate: DestructiveWriteGate::closed(),
        }
    }

    /// Fixture construction over an arbitrary client: the only path that accepts a base. The
    /// origin is validated (scheme, host and optional port only), plaintext is refused off
    /// loopback, and the gate is opened for that loopback host, all before anything touches the
    /// network.
    pub(crate) fn fixture_with(client: C, origin: &str) -> Result<Self, GmailError> {
        let base = parse_origin(origin)?;
        require_tls_or_local(base.as_str())?;
        let host = base.host_str().ok_or_else(refused)?;
        let gate = DestructiveWriteGate::allow_test_host(host).map_err(|_| refused())?;
        Ok(Self { client, base, gate })
    }

    /// Enable destructive writes against the gate's authorized host (the ADR-P010 flag).
    /// Without it `modify_labels` refuses.
    pub(crate) fn with_destructive_writes(mut self, gate: DestructiveWriteGate) -> Self {
        self.gate = gate;
        self
    }
}

/// The live Gmail transport, the public surface of this crate's network side.
///
/// Non-generic: callers have no client to choose. Everything underneath (`GatedTransport`,
/// `HttpClient`, `ReqwestClient`, `BearerToken`, `HttpResponse`) is `pub(crate)` as API hygiene,
/// not as a boundary (see the crate doc). The constraints on where credentialed traffic may go
/// are the compiled endpoint, the identifier rules and the default-closed
/// [`DestructiveWriteGate`], which run on every call regardless of this type's shape.
///
/// `Debug` is redacted through to the inner transport.
pub struct HttpGmailTransport(GatedTransport<ReqwestClient>);

impl std::fmt::Debug for HttpGmailTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HttpGmailTransport").field(&self.0).finish()
    }
}

// Ambiguous-outcome classification, split by call-site stage.
//
// JMAP's blanket "any transport error is Transient" rule is safe where idempotency is
// established. Here it is not: a server that receives the complete authenticated POST and then
// closes without responding would be classified Transient and the engine would re-dispatch a
// mutation that may already have applied. RFC 9110 §9.2.2 forbids automatically retrying a
// non-idempotent request without knowing it was unprocessed.
//
// Measured reqwest flags cannot decide this alone (`dead port: request=true, connect=true`;
// `full POST then EOF: request=true, connect=false, status=None`; `truncated body:
// request=false, connect=false, decode=true`), but the call site knows its stage. Errors out of
// `send()` go through the provability predicate below; errors while consuming an
// already-obtained `Response` are always deterministic, because headers arrived and the
// provider processed the request.
//
// `Failed` from either stage means "not proven applied", never "no provider effect". Closing
// the gap needs an explicit `Ambiguous` state reconciled through the read path, or a provider
// idempotency proof. Process death after provider application but before reconciliation still
// duplicates.

/// Total request timeout.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Connect (including TLS handshake) timeout. It must be strictly shorter than [`HTTP_TIMEOUT`].
///
/// With only a short total timeout configured, a genuinely pre-dispatch connect failure
/// surfaced as `request=true, timeout=true, connect=false`, so the phase could no longer be
/// proven from the final error and would have to be Deterministic. The connect timeout is a
/// `TimeoutLayer` inside the connector, so its expiry propagates as a connector error and
/// `is_connect()` stays true, which keeps ordinary connection failures classifiable. Without
/// the ordering, "dead port is Transient" would depend on platform and timing.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The send-stage predicate: positive proof, not failure name.
///
/// `Transient` iff the failure is positively proven pre-dispatch, which for this error type means
/// `is_connect()`, its one positive pre-dispatch signal. Everything else, including any stall the
/// type cannot prove pre-dispatch, is Deterministic: fail-closed and visible beats a silent
/// duplicate mutation.
///
/// - **Builder errors are Deterministic**: a local misconfiguration; an identical retry fails
///   identically. Positive proof means proof of reaching the network and failing there, not
///   "some early-looking error".
/// - **Certificate errors are Deterministic**: they persist until the server's cert or our
///   trust store changes. They are also proven pre-wire (see the arm below).
/// - **`is_timeout()` alone is never the discriminator.** It carries no temporal information, so
///   a connect-phase stall and a post-send response-wait stall are indistinguishable through
///   it. It only names which transient variant an already-proven connect failure is.
fn send_stage_verdict(
    is_builder: bool,
    is_certificate: bool,
    is_connect: bool,
    is_timeout: bool,
) -> GmailError {
    // A rustls certificate-validation failure is the one send-stage failure that is provably
    // pre-wire: the handshake is rejected before a single request byte is written, and
    // [`is_tls_certificate_error`] identifies it positively (a dedicated input to this
    // predicate, not an inference from a failure name). Under `refused()` it would inherit
    // `Unknown`'s `Indeterminate`, so a certificate failure after authorization would park the
    // operation for human adjudication over an outcome the transport can prove changed nothing.
    // The retry classification is unchanged (`PreWireRefused` is Deterministic: the cert or the
    // trust store has to change before an identical retry answers differently). Checked first so
    // the flag outranks `is_connect`.
    if is_certificate {
        return pre_wire_refused();
    }
    // The builder arm stays `refused()`: a request that was never constructed is a different
    // claim, and only the certificate case is proven here.
    if is_builder {
        return refused();
    }
    if is_connect {
        // Proven pre-dispatch: nothing was sent, so a retry cannot duplicate anything.
        //
        // `TransportPreDispatch` carries that claim in the type. A plain `Transport` answer
        // would have let the engine's evidence map read it as "never on the wire", justified
        // only by this function's stage split and by nothing in the `GmailTransport` trait, so
        // any foreign impl surfacing a post-body timeout would inherit it.
        return GmailError::TransportPreDispatch(if is_timeout {
            aruna::gmail::GmailTransportError::Timeout
        } else {
            aruna::gmail::GmailTransportError::ConnectionReset
        });
    }
    refused()
}

/// The response-body-read stage: always Deterministic, with no predicate.
///
/// Response headers arrived, so the provider processed the request; the write may have applied,
/// and re-dispatching it would risk the duplicate this section exists to prevent.
fn body_stage_verdict() -> GmailError {
    refused()
}

// The read route's own failure mapping: the write predicate must not govern a safe GET.
//
// The write predicate exists to prevent replaying a non-idempotent mutation POST.
// `users.messages.get` is a GET, a safe method (RFC 9110 §9.2.1), so repeating it cannot
// duplicate anything and RFC 9110 §9.2.2's bar is met by the method itself. Routing the read
// through the write's provability predicate would turn recoverable network failures
// (post-dispatch stall, reset, lost response, mid-body death) into deterministic dead-letters
// for a policy whose justification does not exist on this route.

/// Map a send-stage failure on the read route. No provability predicate: a retry is safe by the
/// method's own contract, so every network failure is transient. Only failures an identical
/// retry would repeat stay deterministic: a builder error (local misconfiguration) and a
/// certificate failure (persists until the cert or trust store changes).
fn map_read_send_error(err: &reqwest::Error) -> GmailError {
    read_send_stage_verdict(
        err.is_builder(),
        is_tls_certificate_error(err),
        err.is_timeout(),
    )
}

/// The read-route send-stage verdict. `is_connect` is not consulted: on the write path it is the
/// one positive pre-dispatch proof, and the read path needs none. `is_timeout` only names which
/// transient variant the failure is.
///
/// It answers the unproven [`GmailError::Transport`], never the write path's
/// `TransportPreDispatch`, since this route never established the stage and must not spell the
/// claim.
fn read_send_stage_verdict(is_builder: bool, is_certificate: bool, is_timeout: bool) -> GmailError {
    if is_builder || is_certificate {
        return refused();
    }
    GmailError::Transport(if is_timeout {
        aruna::gmail::GmailTransportError::Timeout
    } else {
        aruna::gmail::GmailTransportError::ConnectionReset
    })
}

/// The read route's body-read stage: headers arrived and the exchange then broke mid-body. On the
/// write path that is deterministic by stage (the provider processed the mutation). On a safe GET
/// it proves only that the network failed, and re-requesting duplicates nothing: transient.
fn read_body_stage_verdict() -> GmailError {
    GmailError::Transport(aruna::gmail::GmailTransportError::ConnectionReset)
}

/// The verdict for a complete response whose body cannot be consulted: over the byte cap, or not
/// valid UTF-8.
///
/// Fall back to what the status alone determines, the same rule `entries()` applies to
/// unparseable JSON. At 429/5xx the body is never consulted (`map_error_response` returns on the
/// status alone), so an oversized or malformed body must not fail the exchange with a
/// deterministic `Unknown` and downgrade a retryable refusal into a dead-letter.
///
/// The fail-closed rows do not weaken. A 2xx body is the applied-state evidence, so an
/// unreadable one stays a deterministic refusal (retrying an ambiguously applied write is unsafe
/// while provider idempotency is unproven). 403's status family is already the fail-closed
/// `Unknown`. The body-read I/O path (`body_stage_verdict`) is not routed here: an exchange that
/// broke mid-body is an incomplete response, a different stage with its own contract.
fn unconsultable_body_verdict(status: u16) -> GmailError {
    if (200..300).contains(&status) {
        refused()
    } else {
        crate::error::status_family(status)
    }
}

/// Hard ceiling on an error body, enforced before JSON parsing. Error envelopes are small and
/// bounded by their schema, so 64 KiB is generous.
pub const MAX_ERROR_BODY_BYTES: usize = 65_536;

/// Hard ceiling on a success body, enforced before JSON parsing.
///
/// This is a chosen engineering bound, not a derived worst case. Gmail documents a 10,000-label
/// mailbox limit and types `labelIds[]: string`, but neither the REST reference nor the discovery
/// schema gives a label-id `maxLength`, so cardinality alone cannot establish a worst legitimate
/// size. A test built a schema-conforming response of 10,000 unique 128-byte ids at 1,310,023
/// bytes, over this cap. A realistic 10,000-label body of ordinary `Label_N` ids is about
/// 126 KiB, so the cap leaves roughly 8x headroom over observed shapes.
///
/// A schema-conforming success response can still exceed it. Then the write fails closed
/// (deterministic and visible), and the attended drill is where a real distribution gets
/// measured. Raising the constant blindly would trade a visible failure for an unbounded buffer.
pub const MAX_SUCCESS_BODY_BYTES: usize = 1_048_576;

/// The cap that applies to a response of this status. An error envelope and a full `Message` are
/// different shapes with different legitimate sizes, and one cap could not serve both without
/// rejecting legitimate traffic or over-admitting error bodies.
fn body_cap(status: u16) -> usize {
    if (200..300).contains(&status) {
        MAX_SUCCESS_BODY_BYTES
    } else {
        MAX_ERROR_BODY_BYTES
    }
}

/// Which route a response is being read for: the second axis, beside status, that the wire cap
/// depends on.
///
/// It is a parameter of the client seam because by the time a response reaches the bounded read
/// there is no URL left to look at. The body-fetch routes declare themselves at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireRoute {
    /// Every label-shaped route: `messages.list`, `format=minimal` gets, the listing get (a
    /// `format=full` narrowed by [`LISTING_FIELDS_QUERY`]: headers plus a part skeleton, no
    /// `body` member requested), and the `modify` write. Their legitimate 2xx is small, and
    /// [`MAX_SUCCESS_BODY_BYTES`] was sized for that shape.
    ///
    /// Residual: the listing get carries the message's whole header block (a `fields` mask
    /// cannot filter headers by name), so a pathological header chain or a part tree of
    /// thousands of skeleton entries could exceed this cap, in which case the read fails closed,
    /// deterministically and visibly, like any other over-cap response on this route.
    Generic,
    /// The unmasked `format=full` `messages.get`, whose legitimate payload is up to two
    /// base64url-encoded textual parts (`text/plain` and `text/html`). See
    /// [`MAX_BODY_FETCH_WIRE_BYTES`]. What puts a route here is `body.data`, not the
    /// `format=full` spelling.
    ///
    /// Separate from `attachments.get`, whose response carries exactly one representation. See
    /// [`WireRoute::AttachmentFetch`].
    BodyFetch,
    /// `users.messages.attachments.get`: the attachment-fetch edge resolving a textual part too
    /// large to inline. Exactly one representation per response, so it has its own, larger
    /// per-representation cap ([`MAX_ATTACHMENT_FETCH_WIRE_BYTES`]) rather than
    /// [`BodyFetch`]'s two-representation one; see that constant's doc for the arithmetic and
    /// the residual.
    AttachmentFetch,
}

/// The single resolver for how many bytes a response may occupy on the wire, keyed on both axes.
///
/// Status still decides first: an error envelope is small on every route, and the route axis
/// must not widen it, or a hostile server could hand a body-fetch route a 1.4 MB "error" to
/// parse. Only a 2xx on a body-fetch route gets its route-specific ceiling.
///
/// The live `consume_response` tail resolves through this function. Asking `body_cap(status)`
/// regardless of route would refuse a legitimate `format=full` body over 1 MiB on the wire
/// before [`BODY_FETCH_CAP`]'s truncation could apply. The fake test client cannot exercise
/// client configuration, so the resolver is tested directly.
fn wire_body_cap(route: WireRoute, status: u16) -> u64 {
    match (route, (200..300).contains(&status)) {
        (WireRoute::BodyFetch, true) => MAX_BODY_FETCH_WIRE_BYTES,
        (WireRoute::AttachmentFetch, true) => MAX_ATTACHMENT_FETCH_WIRE_BYTES,
        _ => body_cap(status) as u64,
    }
}

/// Enforce the byte ceiling before any JSON parsing, on success and error bodies alike.
///
/// An advertised `Content-Length` over the cap short-circuits so the body is never read; a body
/// that arrives over the cap anyway (chunked, or a lying header) is refused on its length. The
/// contract is exact: `MAX` bytes is accepted, `MAX + 1` is not.
///
/// This is the only defense against a hostile server, which is free to ignore the `fields`
/// narrowing; the two controls do not substitute for one another.
fn enforce_body_cap(
    status: u16,
    content_length: Option<u64>,
    body: &str,
) -> Result<(), GmailError> {
    let cap = body_cap(status);
    if content_length.is_some_and(|len| len > cap as u64) {
        return Err(unconsultable_body_verdict(status));
    }
    if body.len() > cap {
        return Err(unconsultable_body_verdict(status));
    }
    Ok(())
}

/// The applied-state check for `modify`: a 2xx alone does not prove our mutation was applied.
/// Two conjuncts, both required:
///
/// 1. **Identity correlation.** `Message.id` must equal the requested id, otherwise a misrouted
///    response for a different message that happens to carry the expected labels would pass.
///    This is the Gmail form of JMAP's "the intended record must appear in the success
///    response". It is a mis-routing check, not a replay nonce: a resource id carries no
///    freshness.
/// 2. **Label postcondition.** Every requested add is present; no requested remove is present.
///
/// An absent `labelIds` is not a violation: proto3 JSON omits empty repeated fields, so a
/// message left with zero labels legitimately returns none while satisfying conjunct 2 (the case
/// for `set_seen(true)`: remove `UNREAD`, add nothing). Treating it as failure would turn an
/// applied write into a deterministic dead-letter. Where an add was requested, absence is still
/// a violation.
///
/// Anything unparseable, id-mismatched, id-missing or postcondition-contradicted maps to
/// `GmailError::Unknown` (deterministic, no response text), since retrying an ambiguously
/// applied write is unsafe while provider idempotency is unproven. On success it returns the
/// parsed `labelIds`, the observed label set `modify_labels_observed` reports.
fn witness_applied(
    body: &str,
    message: &GmailMessageId,
    request: &GmailModifyRequest,
) -> Result<LabelIds, GmailError> {
    let resource: MessageResource = serde_json::from_str(body).map_err(|_| refused())?;
    // Conjunct 1: identity.
    let id = resource.id.as_deref().ok_or_else(refused)?;
    if id != message.0 {
        return Err(refused());
    }
    // Conjunct 2: the label postcondition.
    let holds = match &resource.label_ids {
        LabelIds::Present(present) => {
            let added = request
                .add_label_ids()
                .iter()
                .all(|add| present.iter().any(|l| l == add));
            let removed = request
                .remove_label_ids()
                .iter()
                .all(|remove| !present.iter().any(|l| l == remove));
            added && removed
        }
        // No `labelIds` field: the message carries no labels at all. Every requested remove is
        // satisfied; a requested add is not.
        LabelIds::Absent => request.add_label_ids().is_empty(),
    };
    if holds {
        Ok(resource.label_ids)
    } else {
        Err(refused())
    }
}

/// The trash/untrash applied-state check, [`witness_applied`]'s discipline on the dedicated
/// routes, which carry no label arrays to echo. The 2xx body is a `Message` resource, parsed and
/// id-correlated by [`parse_minimal_message`] (conjunct 1: a response for a different message, or
/// for no id at all, is never accepted). Conjunct 2 is the effect the route is named for:
/// `TRASH` present after a trash, absent after an untrash. An absent `labelIds` is the provider's
/// empty answer (proto3), so it satisfies an untrash and violates a trash. Every failure is
/// `refused()`: past the dispatch the transport cannot prove the write did not land.
///
/// Returns the observed label set. This checks only `TRASH`; what else the provider changed is
/// reported, not judged, here.
fn witness_trash_state(
    body: &str,
    message: &GmailMessageId,
    expect_trash: bool,
) -> Result<BTreeSet<String>, GmailError> {
    let labels = parse_minimal_message(body, message)?.into_label_set();
    // The id comes from the engine's single label-id home (`aruna::gmail::LabelId`), not a literal.
    if labels.contains(&aruna::gmail::LabelId::trash().0) != expect_trash {
        return Err(refused());
    }
    Ok(labels)
}

/// The 2xx `Message` resource the applied-state check reads, typed rather than probed out of a
/// `serde_json::Value` tree.
///
/// `Value` resolves a duplicate object member silently, last-key-wins, so
/// `{"id":"OTHER","id":"MSG-1",…}` passed the identity conjunct and
/// `{"labelIds":["INBOX"],"labelIds":["IMPORTANT"]}` passed the postcondition, recording an
/// ambiguous 2xx as applied. A serde-derived struct rejects a repeated `id`/`labelIds` outright.
///
/// Unknown members (`snippet`, `payload`, `threadId`, anything a server adds despite the `fields`
/// narrowing) stay ignored: only the two members that can change the verdict are typed, and
/// provider prose is never read.
#[derive(serde::Deserialize)]
struct MessageResource {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "labelIds", default)]
    label_ids: LabelIds,
}

/// `labelIds` distinguishing absent from present, which the remove-only rule rests on. proto3 JSON
/// omits empty repeated fields, so an absent field means "no labels" and satisfies every
/// requested remove. That is distinct from a present but malformed field, which is refused:
/// `Vec<String>` is what deserializes here, so a `null`, a bare string, or an array carrying a
/// non-string all fail rather than degrading into "absent".
#[derive(Default)]
enum LabelIds {
    /// The member is not in the response at all.
    #[default]
    Absent,
    /// The member is present and well-formed.
    Present(Vec<String>),
}

impl<'de> serde::Deserialize<'de> for LabelIds {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<String>::deserialize(deserializer).map(LabelIds::Present)
    }
}

impl LabelIds {
    /// The label set this answer carries. `Absent` projects to the empty set, since ProtoJSON
    /// omits an empty repeated field. The one projection shared by the set-returning routes: the
    /// observe read ([`GatedTransport::message_labels`]) and the observed writes.
    fn into_label_set(self) -> BTreeSet<String> {
        match self {
            LabelIds::Present(labels) => labels.into_iter().collect(),
            LabelIds::Absent => BTreeSet::new(),
        }
    }
}

impl<C: HttpClient> GatedTransport<C> {
    /// The dedicated-route body: the same six steps as [`GatedTransport::modify_labels_observed`],
    /// in the same order, over the same machinery. Ids are validated and the URL built, the
    /// ADR-P010 gate is keyed to that URL's own host, one `post_empty` is sent (`post_json`'s
    /// bodiless sibling, so the live client's send-stage split (`send_stage_verdict`) classifies
    /// a transport failure exactly as for modify), the byte cap applies before any parse, non-2xx
    /// goes to the one normalizer, and a 2xx must still prove itself, through
    /// [`witness_trash_state`] in place of the label-array check.
    fn trash_or_untrash(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        trash: bool,
    ) -> Result<BTreeSet<String>, GmailError> {
        // (1) Validate ids and build the URL, before any network.
        let url = if trash {
            trash_url(&self.base, user, message)?
        } else {
            untrash_url(&self.base, user, message)?
        };
        // (2) ADR-P010 default-closed gate, keyed to the host this write would actually hit,
        // before any network call. Trash and untrash are writes; an unparseable host fails closed.
        let permitted = host_of(url.as_str()).is_some_and(|host| self.gate.permits_host(&host));
        if !permitted {
            // Proven no wire: the same refusal modify's step (2) makes (asserted in
            // `a_closed_gate_refuses_trash_untrash_and_observed_modify_with_zero_wire_calls`).
            return Err(pre_wire_refused());
        }
        // (3) No body. Google's `users.messages.trash` and `users.messages.untrash` references
        // (both last updated 2026-04-15) say "The request body must be empty", so these routes use
        // the bodiless `post_empty` and nothing is serialized, not even `{}`. That no body leaves
        // the real client is tested hermetically; that the live endpoint accepts the request is
        // for the live drill to observe.
        // (4) One dispatch. Redirects are refused at the client (`Policy::none()`), as for modify.
        let response = self.client.post_empty(url.as_str())?;
        // (5) Bounds before parsing, on every path.
        enforce_body_cap(response.status, response.content_length, &response.body)?;
        // (6) Non-2xx goes to the normalizer; 2xx must still prove itself.
        if !(200..300).contains(&response.status) {
            return Err(crate::error::map_error_response(response.status, &response.body));
        }
        witness_trash_state(&response.body, message, trash)
    }
}

impl<C: HttpClient> GmailTransport for GatedTransport<C> {
    /// The thin wrapper over the one route body, [`GatedTransport::modify_labels_observed`], with
    /// the observed label set dropped.
    fn modify_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        request: &GmailModifyRequest,
    ) -> Result<(), GmailError> {
        self.modify_labels_observed(user, message, request).map(|_| ())
    }

    /// `users.messages.modify`, returning the observed label set the applied-state check parsed
    /// and correlated (MarkSpam/UnmarkSpam use this). It is the six-step route body that
    /// `modify_labels` wraps.
    fn modify_labels_observed(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        request: &GmailModifyRequest,
    ) -> Result<BTreeSet<String>, GmailError> {
        // (1) Validate ids and build the URL, before any network: a refusal here happens before
        // a socket exists.
        let url = modify_url(&self.base, user, message)?;
        // (2) ADR-P010 default-closed gate, keyed to the host this write would actually hit,
        // before any network call. An unparseable host fails closed. Every modify_labels is a
        // write, so a closed gate means this transport performs no network operation at all.
        let permitted = host_of(url.as_str()).is_some_and(|host| self.gate.permits_host(&host));
        if !permitted {
            // Proven no wire. This is the ADR-P010 default, so it is the refusal an ordinary
            // build meets: filing it under `Unknown` would make every mutation settle
            // `ACK_AMBIGUOUS` after authorization and park for human adjudication, over a
            // refusal that makes no network call (asserted in
            // `a_closed_gate_refuses_the_write_with_zero_wire_calls`).
            return Err(pre_wire_refused());
        }
        // (3) The body is the connector-built request, read through its public accessors, so only
        // the two label arrays can ever serialize, whatever fields the request type grows later.
        // The transport never invents label ids: the SetFlag(Seen) polarity inversion stays in the
        // connector, and this carries exactly what it built.
        let body = serde_json::json!({
            "addLabelIds": request.add_label_ids(),
            "removeLabelIds": request.remove_label_ids(),
        });
        // (4) One dispatch. Redirects are refused at the client (`Policy::none()`), so a 3xx
        // arrives here as a completed response and is terminal: never followed, never a second
        // POST, never a replayed body.
        let response = self.client.post_json(url.as_str(), &body)?;
        // (5) Bounds before parsing, on every path.
        enforce_body_cap(response.status, response.content_length, &response.body)?;
        // (6) Non-2xx goes to the normalizer; 2xx must still prove itself.
        if !(200..300).contains(&response.status) {
            return Err(crate::error::map_error_response(response.status, &response.body));
        }
        Ok(witness_applied(&response.body, message, request)?.into_label_set())
    }

    /// `users.messages.trash` — see [`GatedTransport::trash_or_untrash`].
    fn trash_message(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        self.trash_or_untrash(user, message, true)
    }

    /// `users.messages.untrash` — see [`GatedTransport::trash_or_untrash`].
    fn untrash_message(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        self.trash_or_untrash(user, message, false)
    }

    /// The live observe half: delegates to [`GatedTransport::get_message_labels`] (the
    /// `users.messages.get?format=minimal&fields=id,labelIds` read) and projects its typed result
    /// onto the atom alphabet `Connector::observe` compares against. The id-echo correlation, the
    /// byte caps and the one 403 classifier are the read side's.
    ///
    /// Read verbs do not pass the destructive-write gate, so this answers on a default-closed
    /// transport; a capture must not require write authority.
    ///
    /// Every refusal propagates verbatim: an observation that cannot be taken is never reported
    /// as "no labels". [`LabelIds::Absent`] is not such a case: ProtoJSON omits empty repeated
    /// fields, so omission is the provider's empty answer, read as [`placement_from_labels`]
    /// reads it.
    fn message_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        Ok(self.get_message_labels(user, message)?.into_label_set())
    }

    /// The live listing: delegates to [`GatedTransport::list_inbox_page_impl`]. A read, so it
    /// does not pass the destructive-write gate, like [`GatedTransport::message_labels`] above.
    fn list_inbox_page(
        &self,
        user: &GmailUserId,
        page_size: i64,
        continuation: Option<&ContinuationToken>,
    ) -> Result<ListedPage, GmailError> {
        self.list_inbox_page_impl(user, page_size, continuation)
    }

    /// The live body read: delegates to [`GatedTransport::fetch_body_impl`]. A read, so it does
    /// not pass the destructive-write gate.
    fn fetch_body(&self, user: &GmailUserId, message: &GmailMessageId) -> Result<RawBody, GmailError> {
        self.fetch_body_impl(user, message)
    }
}

// The single-message placement read: the aruna-gmail half of the generalized read seam, and the
// independent oracle the drills and the future `Ambiguous` discharge consume. Read-only: the route
// carries no write authority and does not pass the destructive-write gate (JMAP precedent:
// `email_get_mailbox_ids`).

/// The scope-compatible representation selector for the read route. An omitted `format` defaults
/// to `full`, which Google prohibits under the recommended `gmail.metadata` scope, so a
/// `fields=`-only GET would fail under its own credential.
const MINIMAL_FORMAT: &str = "format=minimal";

/// Build the `users.messages.get` URL for one message: the fixed route on the given base, with
/// both query parameters explicit and composed: [`MINIMAL_FORMAT`] (scope compatibility) plus
/// the write path's field mask ([`PARTIAL_RESPONSE_FIELDS`]). A `set_query`-style overwrite of an
/// existing mask would delete one of them, so a test asserts the final URL carries both.
///
/// Both ids are validated first (see [`validate_path_id`]), so a refusal happens before any URL
/// exists and therefore before any socket. Same discipline as [`modify_url`].
fn get_message_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
) -> Result<reqwest::Url, GmailError> {
    validate_path_id(&user.0)?;
    validate_path_id(&message.0)?;
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| refused())?
        .clear()
        .extend(["gmail", "v1", "users", &user.0, "messages", &message.0]);
    url.set_query(Some(&format!("{MINIMAL_FORMAT}&{PARTIAL_RESPONSE_FIELDS}")));
    url.set_fragment(None);
    Ok(url)
}

/// The 2xx `messages.get` minimal resource, typed with the same strictness as the applied-state
/// [`MessageResource`] and reusing the shared [`LabelIds`] absent/present type. A literal
/// `labelIds: null` is therefore refused: a deliberate fail-closed deviation from ProtoJSON's
/// null-as-unset, without changing the shared deserializer. Duplicate array members are not
/// rejected (they cannot alter a set-membership verdict). Unknown members stay ignored.
#[derive(serde::Deserialize)]
struct MinimalMessage {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "labelIds", default)]
    label_ids: LabelIds,
}

/// Parse a 2xx read body and correlate it to the requested message. The id-echo check (as in the
/// write path's conjunct 1): a response for a different message must never feed a placement.
/// This is a mis-routing check, not a truth or freshness proof; a structurally valid,
/// correctly correlated response is accepted as provider truth. Anything unparseable, id-missing
/// or id-mismatched fails closed.
fn parse_minimal_message(body: &str, message: &GmailMessageId) -> Result<LabelIds, GmailError> {
    let resource: MinimalMessage = serde_json::from_str(body).map_err(|_| refused())?;
    let id = resource.id.as_deref().ok_or_else(refused)?;
    if id != message.0 {
        return Err(refused());
    }
    Ok(resource.label_ids)
}

/// The Gmail system labels the placement model rejects outright: drafts are not archivable mail
/// (DRAFT is auto-applied; labels cannot be applied to drafts), so there is no placement belief
/// for them. `TRASH`/`SPAM` are in the model and derive [`Placement::Trash`]/[`Placement::Spam`]
/// below, because the triage verbs write those beliefs.
const OUT_OF_MODEL_LABELS: [&str; 1] = ["DRAFT"];

/// Label set to [`Placement`]: a total partition over the post-parse label set, by exact
/// case-sensitive byte equality (a hostile `"inbox"` is not `INBOX` and falls to the else arm),
/// checked in this order:
///
/// - contains `DRAFT` (with anything, including `INBOX`/`TRASH`/`SPAM`): typed out-of-model
///   error, fail closed. Reconcile surfaces it as `ReconcileError::Provider` rather than
///   "correcting" a belief to a lie.
/// - contains `TRASH`: [`Placement::Trash`]; else contains `SPAM`: [`Placement::Spam`]; else
///   contains `INBOX`: [`Placement::Inbox`]. "TRASH over SPAM" is our derivation choice, not a
///   provider claim: a label set can carry both, and one belief has to win for the derivation to
///   stay deterministic. Either label over `INBOX` is the same kind of choice.
/// - everything else (including empty/`Absent`, SENT-only, user-label-only):
///   [`Placement::Archive`], a model-compression else-arm. In Gmail, archived is the absence of
///   `INBOX`. `UNREAD`/`STARRED`/`CATEGORY_*`/user labels are placement-orthogonal.
fn placement_from_labels(label_ids: &LabelIds) -> Result<Placement, GmailError> {
    let labels: &[String] = match label_ids {
        LabelIds::Present(labels) => labels,
        // ProtoJSON omits empty repeated fields, so `Absent` derives like `Present([])` today.
        // The distinction stays typed so flipping `Absent` to an error costs one match arm,
        // pending a live probe.
        LabelIds::Absent => &[],
    };
    if labels
        .iter()
        .any(|l| OUT_OF_MODEL_LABELS.contains(&l.as_str()))
    {
        return Err(refused());
    }
    // The precedence is this list's order (first match wins). The ids come from the engine's
    // single label-id home (`aruna::gmail::LabelId`), not literals, as in `witness_trash_state`.
    for (label, placement) in [
        (aruna::gmail::LabelId::trash(), Placement::Trash),
        (aruna::gmail::LabelId::spam(), Placement::Spam),
        (aruna::gmail::LabelId::inbox(), Placement::Inbox),
    ] {
        if labels.contains(&label.0) {
            return Ok(placement);
        }
    }
    Ok(Placement::Archive)
}

impl<C: HttpClient> GatedTransport<C> {
    /// Read one message's labels via `users.messages.get?format=minimal&fields=id,labelIds`, the
    /// read half of the shell. Read verbs do not pass the destructive-write gate (the route
    /// builder takes no gate token). Otherwise the same dispatch shell as `modify_labels`: the
    /// auth header, `MAX_SUCCESS_BODY_BYTES`/`MAX_ERROR_BODY_BYTES` caps before parsing, and
    /// `map_error_response` reused, so there is one 403 classifier. A 2xx must still correlate
    /// (the id-echo) before its labels are believed.
    fn get_message_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<LabelIds, GmailError> {
        let url = get_message_url(&self.base, user, message)?;
        let response = self.client.get(url.as_str(), WireRoute::Generic)?;
        enforce_body_cap(response.status, response.content_length, &response.body)?;
        if !(200..300).contains(&response.status) {
            return Err(crate::error::map_error_response(response.status, &response.body));
        }
        parse_minimal_message(&response.body, message)
    }
}

// The inbox-page listing and on-demand body read. Sequential per-id gets only, no batch
// endpoint (a latency measurement decides batching later). Both routes are reads and do not pass
// the destructive-write gate, like [`GatedTransport::get_message_labels`] above.

/// One `messages.list` id — only the id is requested; the header content itself comes from the
/// per-id metadata `GET` below.
#[derive(serde::Deserialize)]
struct MessageIdOnly {
    id: String,
}

/// The `users.messages.list` response shape: an (optionally absent, ProtoJSON-omitted-when-empty)
/// `messages` array plus an optional `nextPageToken`.
#[derive(serde::Deserialize, Default)]
struct ListMessagesResponse {
    #[serde(default)]
    messages: Vec<MessageIdOnly>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

/// One RFC 2822 header as Gmail's `payload.headers[]` shape carries it.
#[derive(serde::Deserialize, Clone)]
struct HeaderKv {
    name: String,
    value: String,
}

/// One `payload` (or nested) MIME part, shared by the masked listing read
/// ([`LISTING_FIELDS_QUERY`]: headers plus attachment-presence scan, no `body` requested) and the
/// unmasked `format=full` body read (the same scan, plus `body.data`/`body.attachmentId`). Unknown
/// members stay ignored: only the members that can change a verdict are typed, and `body` being
/// absent on the listing route is simply `None` here rather than a second type.
#[derive(serde::Deserialize, Default, Clone)]
struct MessagePart {
    #[serde(rename = "mimeType", default)]
    mime_type: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    headers: Vec<HeaderKv>,
    #[serde(default)]
    body: Option<PartBody>,
    #[serde(default)]
    parts: Vec<MessagePart>,
}

/// One MIME part's `body` member: inline `data` (base64url, unpadded) or a Gmail-issued
/// `attachmentId` naming a separate `attachments.get` fetch (a textual part can be large enough
/// that Gmail refuses to inline it).
#[derive(serde::Deserialize, Default, Clone)]
struct PartBody {
    #[serde(default)]
    data: Option<String>,
    #[serde(rename = "attachmentId", default)]
    attachment_id: Option<String>,
    /// Gmail serializes a valid zero-length textual leaf as `body: {"size": 0}`, with `data`
    /// omitted and no `attachmentId`. `size` distinguishes that empty part from a positive-size
    /// body with no byte source (malformed, still refused).
    #[serde(default)]
    size: Option<i64>,
}

/// The listing `messages.get` resource: headers, `labelIds`, `internalDate`, and the
/// part-skeleton `payload` the attachment-presence scan reads. No body bytes at this scope,
/// because [`LISTING_FIELDS_QUERY`] never asks for `body`. Reuses the write route's
/// [`LabelIds`] absent/present type.
#[derive(serde::Deserialize, Default)]
struct MessageMetadataResource {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "internalDate", default)]
    internal_date: Option<String>,
    #[serde(rename = "labelIds", default)]
    label_ids: LabelIds,
    #[serde(default)]
    payload: Option<MessagePart>,
}

/// The `format=full` `messages.get` resource: only `id` and `payload` are read (`snippet`,
/// `threadId`, `historyId`, … are not).
#[derive(serde::Deserialize, Default)]
struct FullMessageResource {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    payload: Option<MessagePart>,
}

/// The `users.messages.attachments.get` resource: inline base64url (unpadded) attachment bytes.
#[derive(serde::Deserialize)]
struct AttachmentResource {
    data: Option<String>,
}

/// Case-insensitive header lookup: RFC 2822 header field names are case-insensitive, and Gmail's
/// header echo does not normalize casing.
fn header_value(headers: &[HeaderKv], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.clone())
}

/// Every header named `name`, case-insensitively. Used to count occurrences (RFC 5322 §3.6:
/// `from` occurs at most once), which `header_value`'s `.find` cannot do since it takes the first.
fn header_values<'a, 'b>(headers: &'a [HeaderKv], name: &'b str) -> impl Iterator<Item = &'a str> + use<'a, 'b> {
    headers.iter().filter(move |h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
}

/// The transport's typed RFC 5322 §3.6 cardinality signal for the `From` header, computed before
/// the §3.4 grammar runs (`aruna::mailbox::RawFrom`, `aruna::mailbox::parse_from`).
fn raw_from(headers: &[HeaderKv]) -> aruna::mailbox::RawFrom {
    use aruna::mailbox::RawFrom;
    let mut values = header_values(headers, "From");
    match (values.next(), values.next()) {
        (None, _) => RawFrom::Absent,
        (Some(only), None) => RawFrom::Single(only.to_string()),
        (Some(_), Some(_)) => RawFrom::Multiple(2 + values.count()),
    }
}

/// Split an RFC 5322 `From` into `(display-name half, from_addr)` by the §3.4 `address-list`
/// grammar, never by a delimiter search (a comment is CFWS and may hold angle brackets; a
/// quoted-string is one word). More than one `From` field (§3.6) is `Malformed` before the
/// grammar runs (`raw`, the transport's typed signal).
///
/// - exactly one mailbox: its display-name phrase (not yet RFC 2047-decoded) and canonical
///   addr-spec;
/// - absent: two empty strings;
/// - parsed but not exactly one mailbox (a group, RFC 6854; a longer mailbox-list): an empty
///   name and the raw value with folding whitespace trimmed;
/// - anything else (two angle-addrs, an unterminated bracket, text after the angle-addr, an
///   address with an unshowable codepoint, more than one `From` field): an empty name and the
///   raw value (for more than one field, a marker naming the count).
///
/// The header row's sender status and domain are derived from the returned `from_addr` through
/// the same parser (`aruna::mailbox::sender_facts`).
fn parse_from_header(raw: aruna::mailbox::RawFrom) -> (String, String) {
    let parsed = aruna::mailbox::parse_from(raw);
    (parsed.display_name, parsed.from_addr)
}

/// The bound on MIME-part nesting depth for both the listing attachment-presence scan and the
/// body read's part walk. A generous ceiling (ordinary multipart mail is 1-3 levels deep; RFC
/// 2046 sets no numeric limit, and Gmail publishes none). A response nested past this depth is
/// refused with a typed [`GmailError`], never silently truncated: a walk that quietly drops part
/// of the tree could under-report attachments or miss the real textual part.
const MAX_PART_DEPTH: usize = 8;

/// Is this part an attachment rather than message content?
///
/// Either signal is sufficient:
/// - a non-empty `filename` (Gmail's own marker); or
/// - a `Content-Disposition` header naming `attachment` (RFC 2183 §2.2), which a sender sets when
///   the part is not to be displayed inline. The disposition type is the token before the first
///   `;`, so `attachment; filename*=utf-8''x` counts and `inline` never does.
///
/// Both tree walks (the listing presence scan and the body read's part walk) use this one
/// predicate, so "what counts as an attachment" cannot differ between the routes. For the body
/// walk it is also a skip: a `text/plain` part that is an attachment is attachment bytes that
/// happen to be textual, and selecting the body by MIME type alone would ship them across IPC,
/// violating the no-attachment-bytes contract.
fn part_is_attachment(part: &MessagePart) -> bool {
    if part.filename.as_deref().is_some_and(|f| !f.is_empty()) {
        return true;
    }
    header_value(&part.headers, "Content-Disposition").is_some_and(|v| {
        v.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("attachment")
    })
}

/// Scan a `payload` part tree for attachment presence only (never bytes, never fetched). A part
/// [`part_is_attachment`] recognizes counts, at any depth up to [`MAX_PART_DEPTH`]. Used by the
/// listing route, which needs presence and a count, never content.
fn attachment_presence(payload: Option<&MessagePart>) -> Result<AttachmentPresence, GmailError> {
    let mut count = 0u32;
    if let Some(root) = payload {
        scan_attachment_presence(root, 0, &mut count)?;
    }
    Ok(AttachmentPresence {
        has_attachments: count > 0,
        count,
    })
}

fn scan_attachment_presence(
    part: &MessagePart,
    depth: usize,
    count: &mut u32,
) -> Result<(), GmailError> {
    if depth > MAX_PART_DEPTH {
        return Err(refused());
    }
    if part_is_attachment(part) {
        *count += 1;
    }
    for child in &part.parts {
        scan_attachment_presence(child, depth + 1, count)?;
    }
    Ok(())
}

/// The `charset` parameter of a MIME `Content-Type` header value, lowercased; `None` when the
/// header declares none (RFC 2045 §5.1 parameter, case-insensitive name, value optionally quoted).
///
/// Walks the parameter list rather than substring-scanning the raw header: a bare
/// `value.find("charset")` matches inside `xcharset=…` or any parameter whose name merely contains
/// the word. The header is split on its `;` separators first, and each candidate's name is
/// compared for exact (case-insensitive) equality to `"charset"`. A `charset=` with no value is
/// `None`: an empty declaration is an absent one, not an unknown encoding.
///
/// This is a small parser, not the full RFC 2045 grammar: a `;` inside a quoted parameter value
/// (e.g. `boundary="a;b"`) would be misread as a parameter boundary. That is rare in practice
/// and out of scope; the parameter-name boundary is the case that occurs.
fn charset_from_content_type(value: &str) -> Option<String> {
    for param in value.split(';').skip(1) {
        let mut parts = param.splitn(2, '=');
        let name = parts.next()?.trim();
        let raw_value = match parts.next() {
            Some(v) => v.trim(),
            None => continue,
        };
        if !name.eq_ignore_ascii_case("charset") {
            continue;
        }
        let token = match raw_value.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next().unwrap_or_default(),
            None => raw_value,
        };
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_ascii_lowercase());
        }
    }
    None
}

/// The 0x80–0x9F block of windows-1252, where it differs from ISO-8859-1 (which puts C1 controls
/// there). 27 printable remaps; the five bytes windows-1252 leaves undefined (0x81, 0x8D, 0x8F,
/// 0x90, 0x9D) map to their own code point, matching the WHATWG Encoding index.
const WINDOWS_1252_HIGH: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// Decode one textual part's bytes against its declared charset. Four arms:
///
/// - **absent / `utf-8` / `us-ascii`: strict [`String::from_utf8`].** When the sender declares
///   utf-8, honouring that is the strict path: a part that lies about being utf-8 is malformed
///   and stays a typed refusal rather than being silently rewritten with replacement characters.
///   (us-ascii is a utf-8 subset, so the same check is exact for it.)
/// - **`iso-8859-1` (latin-1): a direct byte to char transcode.** Latin-1 is the first 256
///   Unicode code points, so `char::from(byte)` is the whole conversion.
/// - **`windows-1252`: latin-1 plus the [`WINDOWS_1252_HIGH`] remaps.** It is the superset latin-1
///   is mislabelled as in practice; without the 0x80–0x9F table, smart quotes and dashes (the
///   most common non-ASCII bytes in real mail) decode as invisible C1 controls.
/// - **anything else: [`String::from_utf8_lossy`].** Readable degradation, chosen over refusing
///   (which would leave the user no body for a message that is mostly ASCII) and over adding an
///   encoding crate. Bytes that do not decode become U+FFFD: visibly wrong, never silently
///   wrong, and never a claim that the text is faithful.
///
/// No re-encoding: the caller's cap and truncation apply afterwards, on the resulting `String`.
fn decode_part_bytes(bytes: Vec<u8>, charset: Option<&str>) -> Result<String, GmailError> {
    match charset {
        None | Some("utf-8") | Some("utf8") | Some("us-ascii") | Some("ascii") => {
            String::from_utf8(bytes).map_err(|_| refused())
        }
        Some("iso-8859-1") | Some("iso8859-1") | Some("latin1") | Some("latin-1")
        | Some("iso_8859-1") | Some("l1") => Ok(bytes.into_iter().map(char::from).collect()),
        Some("windows-1252") | Some("cp1252") | Some("cp-1252") | Some("windows1252") => Ok(bytes
            .into_iter()
            .map(|b| match b {
                0x80..=0x9F => WINDOWS_1252_HIGH[(b - 0x80) as usize],
                other => char::from(other),
            })
            .collect()),
        Some(_) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

/// The shared base64 core for both alphabets below. The sextet mapping is the only difference
/// between RFC 4648 §5 base64url and §4 standard base64, so it is the one parameter and every
/// padding and length rule lives in one place.
///
/// # Terminal padding
///
/// At most two `=` at the very end are consumed, and the length congruence is checked
/// (`data.len() + pad` must complete a 4-character group, so `AAAA=` and `AA=` are refused).
/// Interior padding, three or more pads, and pad-only input stay malformed rather than guessed.
///
/// # Non-zero pad bits are accepted (deliberate, tested)
///
/// The tail arms discard the unused bits of a partial final quantum without checking them, and
/// padding is optional, so a 1-byte tail has 32 accepted spellings and a 2-byte tail has 8, all
/// decoding identically (`Zg==` … `Zv==` and `Zg` … `Zv` all decode to `f`). RFC 4648 §3.5
/// requires encoders to zero those bits but says "decoders MAY chose to reject an encoding if
/// the pad bits have not been set to zero", and "the specification referring to this may
/// mandate a specific behaviour". Photon's referring specs do not (RFC 2047 §4.1 defers to RFC
/// 2045's BASE64, RFC 2045 §6.8 only mandates encoder zero-fill, and the Gmail reference calls
/// `body.data` just a base64url string). Refusing would turn a sloppily encoded but legitimate
/// header word into a raw `=?UTF-8?B?…?=` token in the subject line, since [`decode_rfc2047`]
/// fails open.
///
/// RFC 4648 §12 names three abuses of non-significant bits:
///
/// * **Bypassing string equality:** nothing in this repo keys on the encoded text (decode sites
///   drop it, dedupe is on the Gmail message id or local `message_ref`, no digest covers a
///   `data` field). Re-check this before relying on the lenience again: if any consumer keys on
///   the encoded form, the tail arms must reject non-zero pad bits (`group[1] & 0x0F != 0` in
///   the 2-arm, `group[2] & 0x03` in the 3-arm).
/// * **Leaking information:** one path does retain encoded text. When base64 succeeds but the
///   charset conversion fails, `decode_one_encoded_word` returns `None` and the raw fallback
///   preserves the token verbatim (`decode_rfc2047("=?UTF-8?B?/w==?=")` returns itself; both
///   `/w==` and `/x==` decode to the invalid UTF-8 `[255]`), so attacker-chosen pad bits reach
///   the display string and `message_header`. That is the intentional display fallback, not a
///   demonstrated attack, and rejecting non-zero pad bits would not close it since the fail-open
///   path preserves refused tokens too. Revisit if any surface retains or logs the encoded form
///   (for example a raw-message cache).
/// * **Triggering implementation problems:** the tail arms only shift the pad bits off (constant
///   shifts on `u8`, no branch, index or length derived from them), so they cannot reach a panic
///   or an allocation. Out-of-alphabet input is `Err(())` before the arms run.
///
/// The lenience is pinned by `pad_bits_are_currently_ignored_in_both_alphabets_pinning` and
/// every alphabet value by `every_alphabet_value_is_pinned_where_it_is_load_bearing`. These
/// tests cover the dimensions tested (every symbol, the tail boundary, alphabet membership both
/// ways), not every conceivable change to decoding.
fn base64_decode_with_alphabet(input: &str, sextet: fn(u8) -> Result<u8, ()>) -> Result<Vec<u8>, ()> {
    let all = input.as_bytes();
    // Consume at most two trailing pad characters, then require what is left to be pad-free and
    // to complete a 4-character group with them. The second half is load-bearing: without it,
    // `AAAA=` (a complete group plus a pad) and `AA=` (a remainder that pad cannot complete)
    // would decode as if the pad were not there. The pad-free check below is defensive and
    // redundant: `=` is in neither alphabet, so `sextet()` already returns `Err(())` for any `=`
    // still inside the slice. Deleting it diverges on none of 1,320,051 differential inputs. Note
    // that `base64url_decode("AA=A").is_err()` passes because of the alphabet, not because of
    // this check.
    let mut end = all.len();
    let mut pad = 0usize;
    while end > 0 && all[end - 1] == b'=' && pad < 2 {
        end -= 1;
        pad += 1;
    }
    let bytes = &all[..end];
    if bytes.contains(&b'=') {
        return Err(());
    }
    if pad > 0 && !(bytes.len() + pad).is_multiple_of(4) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 3);
    let mut group = [0u8; 4];
    let mut group_len = 0usize;
    for &b in bytes {
        group[group_len] = sextet(b)?;
        group_len += 1;
        if group_len == 4 {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
            out.push((group[2] << 6) | group[3]);
            group_len = 0;
        }
    }
    match group_len {
        0 => {}
        // A single leftover base64 sextet (6 bits) cannot decode to a whole byte: malformed.
        1 => return Err(()),
        2 => out.push((group[0] << 2) | (group[1] >> 4)),
        3 => {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
        }
        _ => unreachable!("group_len is bounded to 0..4 by the loop above"),
    }
    Ok(out)
}

/// Decode RFC 4648 §5 base64url (the URL-and-filename-safe alphabet: `-`/`_` in place of `+`/`/`),
/// padded or unpadded. Hand-rolled to avoid a new dependency: `aruna-gmail/Cargo.toml` carries no
/// `base64` crate (only a transitive copy inside `reqwest`'s dependency tree, which this crate
/// must not reach through). Used for Gmail's `body.data` and attachment `data` fields.
fn base64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn sextet(b: u8) -> Result<u8, ()> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(()),
        }
    }
    base64_decode_with_alphabet(input, sextet)
}

/// The encoded-word decoder lives in `aruna::encoded_word` so that `aruna-jmap`, which depends
/// only on `aruna`, can decode a `From` display-name too. Re-imported under its short name here;
/// `base64_standard_decode` is imported separately inside `mod tests`.
use aruna::encoded_word::decode_rfc2047;

/// The hard ceiling `fetch_body` applies to each of `RawBody.text`/`.html` independently, at the
/// transport boundary, clipped at a `char` boundary so truncation never splits a multi-byte UTF-8
/// sequence. A chosen engineering bound (like [`MAX_SUCCESS_BODY_BYTES`]): 1 MB of decoded text
/// covers ordinary mail while keeping a hostile multi-megabyte body from being buffered without
/// limit.
pub const BODY_FETCH_CAP: usize = 1_000_000;

/// Headroom over the encoded body bytes for the JSON envelope that carries them: the `format=full`
/// resource's part structure, headers, `snippet`, ids and quoting. Chosen (512 KiB) and generous;
/// observed envelopes around two capped bodies are a few KiB of structure.
const BODY_FETCH_WIRE_MARGIN_BYTES: u64 = 512 * 1024;

/// The wire-level ceiling the `format=full` `messages.get` route ([`WireRoute::BodyFetch`])
/// enforces, distinct from [`MAX_SUCCESS_BODY_BYTES`], which was sized for label-only 2xx
/// bodies. Base64 expands input by about 4/3, so [`BODY_FETCH_CAP`] decoded bytes alone need
/// about 1.33M encoded bytes before any JSON overhead. `users.messages.attachments.get` has its
/// own cap ([`MAX_ATTACHMENT_FETCH_WIRE_BYTES`], [`WireRoute::AttachmentFetch`]).
///
/// A ceiling derived from two capped bodies (`2 × BODY_FETCH_CAP × 4/3 +
/// BODY_FETCH_WIRE_MARGIN_BYTES` = 3,190,954) undercounts: it assumes one `text/plain` and one
/// `text/html` leaf, but a `format=full` resource legitimately carries multiple inline leaves
/// (every quoted layer of a repeatedly forwarded message has its own `multipart/alternative`),
/// and all of them are on the wire and counted by [`get_bounded_routed`] before
/// [`walk_body_parts`] selects the first of each. Mail structure bounds the number of leaves by
/// nothing, so no part-count derivation can be sound.
///
/// So the ceiling is a flat 16 MiB (16,777,216 bytes) whole-response memory bound, not a promise
/// about displayed message size; [`BODY_FETCH_CAP`] (1 MB) still clips each selected
/// representation after the walk. It matches the JMAP sibling's flat posture
/// (`aruna_jmap::transport::MAX_RESPONSE_WIRE_BYTES`, 12,524,288 bytes). Residual: a response
/// whose inline leaves sum past 16 MiB is refused outright, deterministically and visibly; any
/// finite bound closes the memory-exhaustion class.
///
/// The live `ReqwestClient::get` path funnels every response through [`consume_response`], which
/// must resolve [`wire_body_cap`] by route rather than ask [`body_cap`] regardless of route, or
/// a legitimate `format=full` response would be refused at the 1,048,576-byte ceiling. The route
/// travels through the client seam ([`WireRoute`]), so live and hermetic paths agree. The fake
/// client cannot exercise this, so the resolver is tested directly
/// (`the_body_fetch_route_resolves_the_wire_cap_not_the_generic_success_cap`).
const MAX_BODY_FETCH_WIRE_BYTES: u64 = 16 * 1024 * 1024;

/// How many decoded bytes a single textual attachment (behind `body.attachmentId`) may arrive as
/// before `fetch_attachment_bytes` gives up on it entirely. This is not [`BODY_FETCH_CAP`]: the
/// final representation is always clipped to [`BODY_FETCH_CAP`] by [`cap_text`], so this constant
/// only decides how much oversize the fetch absorbs and truncates rather than refuses.
///
/// Four times [`BODY_FETCH_CAP`], a chosen ceiling in the same spirit as [`MAX_PART_DEPTH`]
/// (Gmail publishes no per-attachment size contract for this route): enough to absorb an
/// ordinary oversize text attachment while keeping a hostile multi-hundred-megabyte one from
/// being buffered without limit.
const MAX_ATTACHMENT_FETCH_DECODED_BYTES: u64 = 4 * BODY_FETCH_CAP as u64;

/// The wire-level ceiling `fetch_attachment_bytes` enforces ([`WireRoute::AttachmentFetch`]). An
/// oversized but textual attachment truncates rather than errors.
///
/// Sharing [`MAX_BODY_FETCH_WIRE_BYTES`] (sized for the two-part `format=full` route) would make
/// an attachment whose decoded size passed roughly 2.39 MB fail the read, although every other
/// oversized representation here yields a truncated [`BODY_FETCH_CAP`] prefix. `attachments.get`
/// answers exactly one part, so it does not need a cap sized for two.
///
/// It is sized off [`MAX_ATTACHMENT_FETCH_DECODED_BYTES`] (not [`BODY_FETCH_CAP`] itself) so a
/// moderately larger attachment still succeeds, truncated:
///
/// ```text
/// MAX_ATTACHMENT_FETCH_DECODED_BYTES (4,000,000) × 4/3 (base64) + BODY_FETCH_WIRE_MARGIN_BYTES (512 KiB)
///   = 5,333,333 + 524,288 = 5,857,621 bytes
/// ```
///
/// The response is fetched and decoded whole (no partial-JSON read), and the existing
/// [`cap_text`] call in `fetch_body_impl` clips whatever comes back to [`BODY_FETCH_CAP`] and
/// marks the representation truncated, as it does for an oversized inline `body.data`.
///
/// Residual (same posture as [`MAX_SUCCESS_BODY_BYTES`]): an attachment whose encoded size
/// exceeds even this is refused outright, since a fixed wire ceiling cannot promise truncated
/// service to an unboundedly large response without a streamed, partial-JSON read this
/// transport does not implement.
const MAX_ATTACHMENT_FETCH_WIRE_BYTES: u64 =
    (MAX_ATTACHMENT_FETCH_DECODED_BYTES * 4 / 3) + BODY_FETCH_WIRE_MARGIN_BYTES;

/// Clip `s` to at most `cap` bytes, at the nearest `char` boundary at or below `cap`, and record
/// whether clipping happened. Never panics: `is_char_boundary` is checked before every slice, and
/// the search terminates at `0` (always a boundary).
fn cap_text(s: String, cap: usize, truncated: &mut bool) -> String {
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

/// Build the `users.messages.list` URL: `labelIds=INBOX`, the re-clamped `maxResults`, and an
/// optional `pageToken` continuation (the id-only listing call). The clamp is re-applied here
/// (see [`clamp_page_size`]) so a direct trait caller cannot hand this transport an unclamped
/// page size.
fn list_messages_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    page_size: i64,
    continuation: Option<&ContinuationToken>,
) -> Result<reqwest::Url, GmailError> {
    validate_path_id(&user.0)?;
    let clamped = clamp_page_size(page_size);
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| refused())?
        .clear()
        .extend(["gmail", "v1", "users", &user.0, "messages"]);
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("labelIds", "INBOX");
        qp.append_pair("maxResults", &clamped.to_string());
        if let Some(token) = continuation {
            qp.append_pair("pageToken", &token.0);
        }
    }
    url.set_fragment(None);
    Ok(url)
}

/// The listing route's query: `format=full` narrowed by a `fields` partial-response mask.
///
/// Not `format=metadata`: the Gmail REST reference says METADATA "Returns only email message ID,
/// labels, and email headers", so there is no `payload.parts` at any depth,
/// [`attachment_presence`] would scan a part tree that never exists, and every row would answer
/// `has_attachments: false`. Presence that is always false is worse than none: the UI cannot
/// tell "no paperclip" from "we never looked".
///
/// This is not a body read: the mask names every member we consume and `body` is not among them,
/// so Gmail sends the part skeleton (`partId`/`mimeType`/`filename`/`headers`) and no
/// `body.data`. [`part_is_attachment`] decides on `filename` and `Content-Disposition`.
///
/// Residual: the mask spells its nesting explicitly and sees `payload.parts` three levels deep,
/// so an attachment nested below that (a forward inside a forward inside a forward) reads as
/// absent on the listing route. The body route walks the whole tree to [`MAX_PART_DEPTH`];
/// presence is a listing hint, the message read is the truth. The mask also cannot filter
/// `headers` by name (`metadataHeaders` is METADATA-only), so the full header block arrives and
/// [`header_value`] picks `From`/`Subject`; it is bounded by [`MAX_SUCCESS_BODY_BYTES`].
const LISTING_FIELDS_QUERY: &str = "format=full&fields=id,internalDate,labelIds,\
     payload(partId,mimeType,filename,headers,\
     parts(partId,mimeType,filename,headers,\
     parts(partId,mimeType,filename,headers,\
     parts(partId,mimeType,filename,headers))))";

/// Build the per-id listing `users.messages.get` URL: `format=full` under the
/// [`LISTING_FIELDS_QUERY`] mask, a compile-time constant (no caller-supplied bytes reach the
/// query string; the two identifiers are still `validate_path_id`-checked before they reach the
/// path).
fn get_message_metadata_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
) -> Result<reqwest::Url, GmailError> {
    validate_path_id(&user.0)?;
    validate_path_id(&message.0)?;
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| refused())?
        .clear()
        .extend(["gmail", "v1", "users", &user.0, "messages", &message.0]);
    url.set_query(Some(LISTING_FIELDS_QUERY));
    url.set_fragment(None);
    Ok(url)
}

/// Build the `users.messages.get?format=full` URL for the on-demand body read.
fn get_message_full_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
) -> Result<reqwest::Url, GmailError> {
    validate_path_id(&user.0)?;
    validate_path_id(&message.0)?;
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| refused())?
        .clear()
        .extend(["gmail", "v1", "users", &user.0, "messages", &message.0]);
    url.set_query(Some("format=full"));
    url.set_fragment(None);
    Ok(url)
}

/// Build the `users.messages.attachments.get` URL: a textual part whose `body` carries
/// `attachmentId` instead of inline `data` is fetched here, within the same size cap as every
/// other read.
fn get_attachment_url(
    base: &reqwest::Url,
    user: &GmailUserId,
    message: &GmailMessageId,
    attachment_id: &str,
) -> Result<reqwest::Url, GmailError> {
    validate_path_id(&user.0)?;
    validate_path_id(&message.0)?;
    validate_path_id(attachment_id)?;
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| refused())?
        .clear()
        .extend([
            "gmail",
            "v1",
            "users",
            &user.0,
            "messages",
            &message.0,
            "attachments",
            attachment_id,
        ]);
    url.set_fragment(None);
    Ok(url)
}

impl<C: HttpClient> GatedTransport<C> {
    /// One `GET` plus bounds plus status normalization, the shared tail every route below runs, so
    /// the caps and `map_error_response` cannot drift between them.
    fn get_bounded(&self, url: &reqwest::Url) -> Result<String, GmailError> {
        let response = self.client.get(url.as_str(), WireRoute::Generic)?;
        enforce_body_cap(response.status, response.content_length, &response.body)?;
        if !(200..300).contains(&response.status) {
            return Err(crate::error::map_error_response(response.status, &response.body));
        }
        Ok(response.body)
    }

    /// The same shape as [`GatedTransport::get_bounded`], for a route whose ceiling is not the
    /// generic one: the wire-level half of [`MAX_BODY_FETCH_WIRE_BYTES`].
    ///
    /// The route is declared once and used twice: the client seam reads its bounded body under
    /// it, and the check below re-applies the same [`wire_body_cap`] to whatever came back, so a
    /// fake client (or a client that ignored the bound) cannot smuggle an over-cap body past
    /// this check.
    fn get_bounded_routed(
        &self,
        url: &reqwest::Url,
        route: WireRoute,
    ) -> Result<String, GmailError> {
        let response = self.client.get(url.as_str(), route)?;
        let cap = wire_body_cap(route, response.status);
        if response.content_length.is_some_and(|len| len > cap) {
            return Err(unconsultable_body_verdict(response.status));
        }
        if response.body.len() as u64 > cap {
            return Err(unconsultable_body_verdict(response.status));
        }
        if !(200..300).contains(&response.status) {
            return Err(crate::error::map_error_response(response.status, &response.body));
        }
        Ok(response.body)
    }

    /// List one page of Inbox header summaries: an id-only `messages.list`, then a per-id masked
    /// listing `messages.get` ([`LISTING_FIELDS_QUERY`]), sequentially (no batch endpoint), and
    /// never more of them than the caller's clamped page size.
    fn list_inbox_page_impl(
        &self,
        user: &GmailUserId,
        page_size: i64,
        continuation: Option<&ContinuationToken>,
    ) -> Result<ListedPage, GmailError> {
        let url = list_messages_url(&self.base, user, page_size, continuation)?;
        let body = self.get_bounded(&url)?;
        let list: ListMessagesResponse = serde_json::from_str(&body).map_err(|_| refused())?;
        // `maxResults` is what we asked for, not a promise about what comes back: a malformed or
        // hostile `messages.list` reply can list any number of ids, and the fan-out below is one
        // sequential GET per id.
        //
        // An over-limit page is refused, not truncated. This transport hands `next_page_token`
        // back to the caller as the provider's own continuation cursor, so advancing past a page
        // truncated on our end, using a cursor the provider issued for the full page, would
        // silently skip every id between the cut and where the cursor resumes: the dropped ids
        // are never fetched on this page or the next. The caller instead sees a typed error and
        // can retry from the same, unconsumed continuation.
        let clamped = clamp_page_size(page_size) as usize;
        if list.messages.len() > clamped {
            return Err(refused());
        }
        let ids: Vec<&MessageIdOnly> = list.messages.iter().collect();
        let mut summaries = Vec::with_capacity(ids.len());
        for m in ids {
            match self.fetch_header_summary(user, &GmailMessageId(m.id.clone())) {
                // `None` is the membership re-check: the metadata answer says this message is no
                // longer in the Inbox, so it is skipped rather than summarized. It counts toward
                // nothing, neither the page size (the id was already spent) nor the continuation
                // (the provider's own token decides that); the page simply comes back one row
                // shorter, which is what the mailbox now holds.
                Ok(Some(summary)) => summaries.push(summary),
                Ok(None) => {}
                // The deletion counterpart of that skip. `messages.list` and this per-id
                // `messages.get` are two round trips and the mailbox keeps moving between them: a
                // message deleted in that gap is still listed by the first call and answers 404
                // to the second. Aborting the page over it would lose every other row and the
                // continuation, so one deletion could stall the read side. A 404 is the provider
                // stating there is nothing there to summarize: skip it, on the same terms as the
                // archive race (it counts toward nothing).
                Err(GmailError::NotFound) => {}
                // Everything else aborts. A 403/429/5xx is not evidence the message is gone, and
                // mapping the page around it would report a shorter mailbox than the provider
                // holds, which the window reconcile above this seam would then act on.
                Err(e) => return Err(e),
            }
        }
        // A non-advancing continuation is refused, never handed back (the Gmail twin of the JMAP
        // arm's refusal). Two shapes make no progress, and both leave a caller that trusts
        // `has_more` re-issuing one request forever:
        //
        //  - `Some("")`: an empty `pageToken` is no `pageToken` at all, so spending it
        //    re-fetches the page we just read;
        //  - a token byte-identical to the one this request carried: the same request, verbatim.
        //
        // Fail closed with the transport's deterministic typed refusal rather than mint a cursor
        // that cannot advance.
        let next = match list.next_page_token {
            Some(token)
                if token.is_empty() || continuation.is_some_and(|c| c.0 == token) =>
            {
                return Err(refused())
            }
            other => other.map(ContinuationToken),
        };
        // Gmail pages never drive removals. The window reconcile treats `min(received_at)` of a
        // chronological page as its coverage floor and deletes every local row above it that the
        // page did not return. An in-sample monotonicity check cannot gate that: `messages.list`
        // has no sort contract, so a one-row page (or one that happens to be sorted) always
        // passes while proving nothing about inbox mail between the newest row and the floor. So
        // this arm reports `false` unconditionally: Gmail pages ingest (the rows are real mail)
        // but never license a removal, until the reconcile is built on provider-backed sync
        // evidence (the `historyId` close). Mail that left the Inbox via another client stays
        // visible locally as staleness; it leaves only through the user's own verbs here, or via
        // a provider (JMAP) with a contractual `receivedAt desc` sort, whose arm reports `true`.
        let chronological = false;
        // The raw answer, reported alongside the mapped one. `summaries` can be empty because the
        // mailbox is empty or because the membership re-check above dropped every row of a page
        // that had them; the reconcile above this seam does opposite things with those two, and
        // `list.messages` is the only place the difference is still visible. (An over-limit page
        // never reaches this line; it is refused above.)
        Ok(ListedPage {
            rows: summaries,
            next,
            raw_page_was_empty: list.messages.is_empty(),
            chronological,
        })
    }

    /// One masked listing `messages.get` ([`LISTING_FIELDS_QUERY`]) to one [`HeaderSummary`]: the
    /// id-echo correlation (the same mis-routing guard as [`parse_minimal_message`]),
    /// `internalDate` to `received_at`, the `From`/`Subject` header parse, `UNREAD`/`STARRED` to
    /// `seen`/`flagged`, and the attachment-presence scan.
    ///
    /// `None` means the message is no longer in the Inbox. `messages.list(labelIds=INBOX)` and
    /// this per-id `messages.get` are two round trips, and the mailbox keeps moving between them:
    /// a message archived, trashed or moved in that gap is still listed by the first call and
    /// still answered by the second, with `INBOX` gone from its `labelIds`. Mapping it anyway
    /// would hand the caller a row the provider no longer considers inbox mail, and the window
    /// reconcile would write it back into the local Inbox as a current row. So membership is
    /// re-asserted on the answer we actually got: `INBOX` present yields a summary, otherwise
    /// `None`. An absent `labelIds` is not evidence of membership either and takes the same
    /// path. The race cannot be closed (the message may be archived a millisecond after this
    /// response is written), but the window shrinks to the one call, and everything this listing
    /// returns said `INBOX` in its own answer.
    fn fetch_header_summary(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<Option<HeaderSummary>, GmailError> {
        let url = get_message_metadata_url(&self.base, user, message)?;
        let body = self.get_bounded(&url)?;
        let resource: MessageMetadataResource =
            serde_json::from_str(&body).map_err(|_| refused())?;
        let id = resource.id.as_deref().ok_or_else(refused)?;
        if id != message.0 {
            return Err(refused());
        }
        let received_at: i64 = resource
            .internal_date
            .as_deref()
            .ok_or_else(refused)?
            .parse()
            .map_err(|_| refused())?;
        let labels: BTreeSet<&str> = match &resource.label_ids {
            LabelIds::Present(v) => v.iter().map(String::as_str).collect(),
            LabelIds::Absent => BTreeSet::new(),
        };
        // The membership re-check, before anything is mapped (see this function's doc).
        // Byte-exact `INBOX`, the same case-sensitive comparison `placement_from_labels` makes: a
        // hostile `"inbox"` is not `INBOX`.
        if !labels.contains("INBOX") {
            return Ok(None);
        }
        let seen = !labels.contains("UNREAD");
        let flagged = labels.contains("STARRED");
        let headers: &[HeaderKv] = resource.payload.as_ref().map_or(&[], |p| &p.headers);
        // Split first, decode second, and decode only the name half. Decoding the whole raw
        // `From` value first assumes an encoded-word only appears in the display-name, which
        // holds for a compliant sender but is not enforced: a hostile header can put
        // encoded-word syntax where the addr-spec should be (the whole value being
        // `=?UTF-8?Q?trusted=40example.com?=`, with no `<...>`, which `parse_from_header` would
        // read as the decoded address), letting a token mutate address identity. Splitting the
        // raw header first (RFC 5322 §3.4) fixes the name and address halves before any decode;
        // an encoded-word in the address renders verbatim, never expanded.
        //
        // The name half arrives already decoded, per word with its lexical provenance, inside
        // the parser's `phrase()` (a quoted-string is literal; an atom decodes only if it is
        // exactly one LWSP-separated encoded-word), so `decode_rfc2047` is not called on it again
        // (a second pass would double-decode). The Subject is unstructured text and keeps its
        // own `decode_rfc2047` below.
        let (from_name, from_addr) = parse_from_header(raw_from(headers));
        let subject_raw = header_value(headers, "Subject").unwrap_or_default();
        let subject = decode_rfc2047(&subject_raw);
        let attachments = attachment_presence(resource.payload.as_ref())?;
        Ok(Some(HeaderSummary {
            provider_id: ProviderMessageId(message.0.clone()),
            received_at,
            from_addr,
            from_name,
            subject,
            seen,
            flagged,
            attachments,
        }))
    }

    /// Fetch one message's raw body: `format=full`, preferring `text/plain` and carrying
    /// `text/html` when present, resolving any textual part behind an `attachmentId` via the
    /// dedicated attachment fetch, and applying [`BODY_FETCH_CAP`] at this transport boundary.
    fn fetch_body_impl(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<RawBody, GmailError> {
        let url = get_message_full_url(&self.base, user, message)?;
        let body = self.get_bounded_routed(&url, WireRoute::BodyFetch)?;
        let resource: FullMessageResource = serde_json::from_str(&body).map_err(|_| refused())?;
        let id = resource.id.as_deref().ok_or_else(refused)?;
        if id != message.0 {
            return Err(refused());
        }
        let mut text: Option<String> = None;
        let mut html: Option<String> = None;
        let mut attachment_count = 0u32;
        if let Some(payload) = &resource.payload {
            self.walk_body_parts(
                user,
                message,
                payload,
                0,
                &mut text,
                &mut html,
                &mut attachment_count,
            )?;
        }
        // Truncation is tracked per representation: a shared flag would mark the displayed
        // (selected) representation truncated when only its unselected sibling was clipped.
        let mut text_truncated = false;
        let mut html_truncated = false;
        let text = text.map(|t| cap_text(t, BODY_FETCH_CAP, &mut text_truncated));
        let html = html.map(|t| cap_text(t, BODY_FETCH_CAP, &mut html_truncated));
        Ok(RawBody {
            text,
            html,
            attachments: AttachmentPresence {
                has_attachments: attachment_count > 0,
                count: attachment_count,
            },
            text_truncated,
            html_truncated,
        })
    }

    /// Depth-bounded ([`MAX_PART_DEPTH`]) recursive walk of the `format=full` part tree: records
    /// the first non-attachment `text/plain` and `text/html` texts and the running attachment
    /// count ([`part_is_attachment`], any depth). A part nested past the bound is refused rather
    /// than silently truncating the walk (which could under-report attachments or skip the real
    /// textual part).
    ///
    /// Attachment-typed textual parts are skipped, not selected: a `text/plain` part with
    /// `filename: "notes.txt"` is an attachment that happens to be textual, and selecting it
    /// would put attachment bytes on the IPC boundary, which v1 forbids. Skipping never hides
    /// it: the part is counted by the predicate the listing route uses, so a message whose only
    /// textual part is an attachment returns no text and no html (the `NoTextualBody` shape)
    /// with its attachment count, and no wire call is spent on an `attachmentId`.
    ///
    /// The skip covers the whole subtree: an attachment container (an attached `message/rfc822`,
    /// or a `multipart/*` with an attachment disposition) has unmarked `text/plain` children
    /// that would otherwise leak as the body one level down.
    #[allow(clippy::too_many_arguments)]
    fn walk_body_parts(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        part: &MessagePart,
        depth: usize,
        text: &mut Option<String>,
        html: &mut Option<String>,
        attachment_count: &mut u32,
    ) -> Result<(), GmailError> {
        if depth > MAX_PART_DEPTH {
            return Err(refused());
        }
        if part_is_attachment(part) {
            // The subtree, not just the part. An attachment can be a container (an attached
            // `message/rfc822`, or a `multipart/*` bundle with an attachment disposition) and its
            // children carry no attachment marking of their own, because the enclosing part is
            // what makes them attachment content. Descending would select such an unmarked
            // `text/plain` as the body, the same IPC leak the part-level skip closes.
            //
            // The count is delegated to the listing route's own scan over the same subtree, so
            // the container and anything attached inside it are counted exactly as
            // `attachment_presence` counts them: the two routes agree on the number, and sealing
            // the subtree cannot hide an attachment. That scan has the same depth bound, so a
            // nest past it is still refused.
            scan_attachment_presence(part, depth, attachment_count)?;
            return Ok(());
        }
        match part.mime_type.as_deref() {
            Some("text/plain") if text.is_none() => {
                *text = Some(self.resolve_part_text(user, message, part)?);
            }
            Some("text/html") if html.is_none() => {
                *html = Some(self.resolve_part_text(user, message, part)?);
            }
            _ => {}
        }
        for child in &part.parts {
            self.walk_body_parts(
                user,
                message,
                child,
                depth + 1,
                text,
                html,
                attachment_count,
            )?;
        }
        Ok(())
    }

    /// Resolve one textual part's decoded content: inline `body.data` (base64url) when present,
    /// otherwise `body.attachmentId` fetched via `attachments.get`. A part with neither is
    /// malformed and refused.
    ///
    /// An empty `data` beside an `attachmentId` is absent data: Gmail answers such a part as
    /// `{"size":N,"data":"","attachmentId":"…"}` (present and empty, not omitted), and reading
    /// the empty string as content would silently report a blank body for a message that has
    /// one. An empty `data` counts as data only when there is no `attachmentId`, in which case
    /// the part really is empty and no round trip is spent.
    ///
    /// The bytes are decoded against the part's own declared charset
    /// ([`charset_from_content_type`]; see [`decode_part_bytes`]), read once here since it is a
    /// property of the part, not of how Gmail delivered its bytes.
    fn resolve_part_text(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        part: &MessagePart,
    ) -> Result<String, GmailError> {
        let body = part.body.as_ref().ok_or_else(refused)?;
        let charset = header_value(&part.headers, "Content-Type")
            .as_deref()
            .and_then(charset_from_content_type);
        let inline = body
            .data
            .as_deref()
            .filter(|data| !data.is_empty() || body.attachment_id.is_none());
        let bytes = if let Some(data) = inline {
            base64url_decode(data).map_err(|_| refused())?
        } else if let Some(attachment_id) = &body.attachment_id {
            self.fetch_attachment_bytes(user, message, attachment_id)?
        } else if body.size == Some(0) {
            // A valid zero-length textual leaf: `body: {"size": 0}`, `data` omitted, no
            // attachment id. The part is empty: empty text, no refusal.
            Vec::new()
        } else {
            return Err(refused());
        };
        decode_part_bytes(bytes, charset.as_deref())
    }

    /// `users.messages.attachments.get` for a textual part too large to inline. Returns the raw
    /// bytes; the charset decision belongs to the part that named the id, since an
    /// `attachments.get` response carries no `Content-Type` of its own.
    ///
    /// Uses [`WireRoute::AttachmentFetch`], with its own per-representation wire cap
    /// ([`MAX_ATTACHMENT_FETCH_WIRE_BYTES`]) rather than [`WireRoute::BodyFetch`]'s
    /// two-representation one. An attachment within that cap decodes and truncates like every
    /// other oversize source in this file: the caller ([`GatedTransport::fetch_body_impl`]) runs
    /// every returned representation through [`cap_text`], which clips to [`BODY_FETCH_CAP`] and
    /// marks it truncated, so no separate truncation path is needed here.
    fn fetch_attachment_bytes(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        attachment_id: &str,
    ) -> Result<Vec<u8>, GmailError> {
        let url = get_attachment_url(&self.base, user, message, attachment_id)?;
        let body = self.get_bounded_routed(&url, WireRoute::AttachmentFetch)?;
        let resource: AttachmentResource = serde_json::from_str(&body).map_err(|_| refused())?;
        let data = resource.data.ok_or_else(refused)?;
        base64url_decode(&data).map_err(|_| refused())
    }
}

/// Map a normalized [`GmailError`] to the connector's id-free [`ConnectorError`], reusing aruna's
/// transient-vs-deterministic taxonomy ([`classify_gmail_error`]); the counterpart of
/// `aruna-jmap`'s `jmap_to_connector`.
fn gmail_to_connector(e: &GmailError) -> ConnectorError {
    let message = "provider rejected the placement read";
    match classify_gmail_error(e) {
        FailureKind::Transient => ConnectorError::transient(message),
        FailureKind::Deterministic => ConnectorError::deterministic(message),
    }
}

/// The [`ProviderPlacement`] core over the gated transport: `pub(crate)` and generic over the
/// client so the fixture can drive it (the same core/facade split as [`GatedTransport`] /
/// [`HttpGmailTransport`], and the same wrapper shape as `JmapProviderPlacement`).
pub(crate) struct GatedProviderPlacement<'a, C> {
    transport: &'a GatedTransport<C>,
    user: GmailUserId,
}

impl<'a, C> GatedProviderPlacement<'a, C> {
    /// Bind the placement reader to a transport and the resolved Gmail user id.
    pub(crate) fn new(transport: &'a GatedTransport<C>, user: GmailUserId) -> Self {
        Self { transport, user }
    }
}

impl<C: HttpClient> ProviderPlacement for GatedProviderPlacement<'_, C> {
    fn fetch_placement(
        &self,
        _account: &str,
        id: &ProviderMessageId,
    ) -> Result<Placement, ConnectorError> {
        // The neutral opaque id becomes the Gmail-native message id here, at this crate's own
        // boundary; it is the same opaque text either way.
        let message = GmailMessageId(id.0.clone());
        let labels = self
            .transport
            .get_message_labels(&self.user, &message)
            .map_err(|e| gmail_to_connector(&e))?;
        placement_from_labels(&labels).map_err(|e| gmail_to_connector(&e))
    }
}

/// A [`ProviderPlacement`] over the live Gmail transport: reads a message's real labels via the
/// `users.messages.get` read route and derives the [`Placement`]. The public, non-generic facade
/// over the crate-internal gated placement core; callers have no client to choose. The
/// `account: &str` arg is the Photon-local handle and is not re-resolved here (as in
/// `JmapProviderPlacement`).
pub struct GmailProviderPlacement<'a> {
    inner: GatedProviderPlacement<'a, ReqwestClient>,
}

impl<'a> GmailProviderPlacement<'a> {
    /// Bind the placement reader to a connected transport and the resolved Gmail user id.
    pub fn new(transport: &'a HttpGmailTransport, user: GmailUserId) -> Self {
        Self {
            inner: GatedProviderPlacement::new(&transport.0, user),
        }
    }
}

impl ProviderPlacement for GmailProviderPlacement<'_> {
    fn fetch_placement(
        &self,
        account: &str,
        id: &ProviderMessageId,
    ) -> Result<Placement, ConnectorError> {
        self.inner.fetch_placement(account, id)
    }
}

// The real `reqwest::blocking` client: the thin, network-touching part. Everything above it is
// pure and hermetically tested.
//
// # The single-dispatch invariant
//
// Redirects are refused outright, and the only remaining library-level re-send (hyper-util's
// `retry_canceled_requests`) is provably pre-write: `TrySendError::Retryable` is constructed
// only when `err.take_message()` returns `Some`, and hyper's contract says the message is
// unavailable once serialized onto the connection. So hyper hands a request back only when it
// was never written, and an engine attempt can never produce a second dispatch of a request
// that reached Gmail (compliant with RFC 9110 §9.2.2, since the request was unprocessed).
//
// Consequences: default pooling stands (`pool_max_idle_per_host(0)` does disable the pool, but
// no real risk was established, and it cost a TCP+TLS handshake per request), and
// `retry::never()` stays absent because it is inert in this build (`is_retryable_error` is gated
// behind the `http2`/`http3` features, which are not enabled; the lock carries no `h2`).
//
// Warning: if `http2` is ever enabled, revisit single-dispatch: reqwest's retry policy becomes
// live and, unlike hyper's pre-write re-dispatch, is not provably safe. Also, a future
// media/upload verb must not blanket-inherit `Policy::none()` (Drive's 308 resume is a
// legitimate follow); that would be its own reviewed decision.

/// The authenticated `reqwest::blocking` client backing the live transport.
///
/// `pub(crate)`, together with [`BearerToken`] and [`HttpClient`]. Its only caller is
/// [`HttpGmailTransport`], which hands it a url only after the compiled endpoint, the identifier
/// rules and the [`DestructiveWriteGate`] are all satisfied.
#[derive(Debug)]
pub(crate) struct ReqwestClient {
    http: reqwest::blocking::Client,
    token: BearerToken,
}

impl ReqwestClient {
    /// Build the client with this crate's timeout contract.
    pub(crate) fn new(token: BearerToken) -> Result<Self, GmailError> {
        Self::with_timeouts(token, CONNECT_TIMEOUT, HTTP_TIMEOUT)
    }

    /// Build with explicit timeouts. Private: the only caller besides [`ReqwestClient::new`] is
    /// the hermetic connect-stall test, which needs a short connect timeout to stay fast. The
    /// contract requires the ordering (connect strictly shorter than total), not the exact
    /// seconds.
    fn with_timeouts(
        token: BearerToken,
        connect: std::time::Duration,
        total: std::time::Duration,
    ) -> Result<Self, GmailError> {
        debug_assert!(connect < total, "connect timeout must be strictly shorter");
        let http = reqwest::blocking::Client::builder()
            .timeout(total)
            // Distinct from the total timeout on purpose: `connect_timeout` is a `TimeoutLayer`
            // inside the connector, so its expiry propagates as a connector error, `is_connect()`
            // is true, and the send-stage predicate can prove the failure was pre-dispatch. A
            // bare total-timeout expiry cannot.
            .connect_timeout(connect)
            // Never route a credentialed request through an ambient/system proxy: reqwest's
            // default honors HTTP_PROXY, which would send a loopback-approved plaintext request
            // through that proxy and expose the `Authorization` header off-host (reproduced in
            // the JMAP transport). Residual: this also excludes environments where a corporate
            // proxy is mandatory. That is a deliberate security posture, and revisiting it
            // belongs to production enablement.
            .no_proxy()
            // A mutation POST follows nothing. reqwest replays a cloneable body across 307/308
            // and strips sensitive headers only when the host changes, so a same-authority
            // redirect re-POSTs the authenticated mutation to a server-chosen path, and Gmail's
            // whole request identity lives in the path. Bounding the authority (JMAP's rule)
            // protects the credential but not the selected resource.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            // A client we cannot build is a deterministic local misconfiguration (id-free).
            .map_err(|_| refused())?;
        Ok(Self { http, token })
    }
}

/// Does this error's source chain carry a rustls certificate-validation failure?
///
/// The rustls backend renders expired / self-signed / hostname-mismatch / unknown-issuer
/// failures as `invalid peer certificate: <reason>` on the inner error; reqwest exposes no typed
/// `is_tls()`, so this phrase is the available signal.
///
/// Two precautions against a false positive that would wrongly dead-letter a retryable failure:
/// (1) start at `.source()`, skipping the outer error whose `Display` embeds the request URL, so
/// a DNS/connect failure to `https://certificate.invalid/` does not look like a cert fault;
/// (2) match the specific rustls phrase, never the bare word. Residual: this matches on error
/// phrasing, which is brittle across rustls patch versions (equally so in the JMAP transport).
/// The blast radius is bounded: a cert failure is pre-dispatch, so a misclassification retries a
/// failing handshake to RETRY_CAP and then dead-letters.
fn is_tls_certificate_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = err.source();
    while let Some(e) = source {
        if e.to_string()
            .to_ascii_lowercase()
            .contains("invalid peer certificate")
        {
            return true;
        }
        source = e.source();
    }
    false
}

/// Map a send-stage failure (we never got a usable response) through the write predicate.
fn map_send_error(err: &reqwest::Error) -> GmailError {
    send_stage_verdict(
        err.is_builder(),
        is_tls_certificate_error(err),
        err.is_connect(),
        err.is_timeout(),
    )
}

/// Consume a completed `reqwest` response into the seam's bounded [`HttpResponse`]: the one tail
/// shared by the POST (write) and GET (read) dispatches, so the caps and the strict decode cannot
/// drift between routes. The one stage whose verdict legitimately differs by route, a body-read
/// I/O failure (deterministic on the write ([`body_stage_verdict`]), transient on the safe GET
/// ([`read_body_stage_verdict`])), is a parameter.
fn consume_response(
    response: reqwest::blocking::Response,
    body_read_verdict: fn() -> GmailError,
    route: WireRoute,
) -> Result<HttpResponse, GmailError> {
    use std::io::Read;

    let status = response.status().as_u16();
    let content_length = response.content_length();
    // The ceiling is resolved on both axes, status and route. Asking `body_cap` alone would
    // refuse a legitimate `format=full` body at the label-shaped ceiling on every real network
    // call, while the hermetic path believed `MAX_BODY_FETCH_WIRE_BYTES` applied.
    let cap = wire_body_cap(route, status);
    // An over-cap `Content-Length` short-circuits before the body is read at all.
    if content_length.is_some_and(|len| len > cap) {
        return Err(unconsultable_body_verdict(status));
    }
    // Bounded read: never materialize more than `cap + 1` bytes, so a hostile server cannot make
    // us allocate an unbounded buffer even when it lies about (or omits) Content-Length. The
    // extra byte lets the caller distinguish "exactly MAX" from "over MAX".
    let mut buf = Vec::with_capacity(0);
    response
        .take(cap + 1)
        .read_to_end(&mut buf)
        // Body-read stage: the verdict is the route's, deterministic on the write (headers
        // arrived, so the mutation may have applied) and transient on the safe GET.
        .map_err(|_| body_read_verdict())?;
    // Strict, never lossy. `from_utf8_lossy` replaces each invalid byte with U+FFFD before the
    // body is parsed, which would silently repair a malformed response into a well-formed JSON
    // document: hostile bytes inside a field this crate never reads (`message`, `snippet`)
    // vanish, and a body that is not valid UTF-8 (so not valid JSON) becomes classifiable.
    // Measured both ways: a 403 carrying invalid bytes beside `usageLimits/rateLimitExceeded`
    // was repaired into a transient retry, and a 2xx carrying them beside a conforming
    // `id`/`labelIds` was repaired into a passing applied-state check.
    //
    // Invalid UTF-8 is not a classification signal; it is a broken response. Its verdict belongs
    // to the status: where the status alone decides (429/5xx and the other status-determined
    // rows) a complete response keeps that verdict regardless of its body, and only where the
    // body matters (the 2xx applied-state check) does undecodability stay a deterministic
    // refusal. The plumbing must not contradict the taxonomy's status-first precedence.
    let body = String::from_utf8(buf).map_err(|_| unconsultable_body_verdict(status))?;
    Ok(HttpResponse {
        status,
        content_length,
        body,
    })
}

impl HttpClient for ReqwestClient {
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse, GmailError> {
        let response = self
            .http
            .post(url)
            .bearer_auth(self.token.expose())
            .json(body)
            .send()
            .map_err(|e| map_send_error(&e))?;
        // Every write is a label-shaped route: `modify` POSTs label arrays through here,
        // `trash`/`untrash` POST no body through `post_empty`, and each reads a `Message` back.
        // There is no body-fetch POST.
        consume_response(response, body_stage_verdict, WireRoute::Generic)
    }

    fn post_empty(&self, url: &str) -> Result<HttpResponse, GmailError> {
        // `post_json` minus `.json(body)`: no body is serialized and `Content-Length: 0` is
        // declared, since Google's front end answers a bodiless POST without it with 411
        // (googleworkspace/cli#182; RFC 9110 §8.6 recommends a `Content-Length` on a bodiless
        // POST). Gmail's `users.messages.trash` and `users.messages.untrash` references both say
        // "The request body must be empty". Same send-stage mapping (`map_send_error`),
        // body-stage verdict (`body_stage_verdict`) and label-shaped bounded read as `post_json`.
        let response = self
            .http
            .post(url)
            .bearer_auth(self.token.expose())
            .header(reqwest::header::CONTENT_LENGTH, 0)
            .send()
            .map_err(|e| map_send_error(&e))?;
        consume_response(response, body_stage_verdict, WireRoute::Generic)
    }

    fn get(&self, url: &str, route: WireRoute) -> Result<HttpResponse, GmailError> {
        let response = self
            .http
            .get(url)
            .bearer_auth(self.token.expose())
            .send()
            // The read route's own mapping: a GET is safe to repeat, so post-dispatch failures
            // are transient, not the write predicate's "not proven applied" fallback.
            .map_err(|e| map_read_send_error(&e))?;
        consume_response(response, read_body_stage_verdict, route)
    }
}

impl HttpGmailTransport {
    /// Connect to Gmail. Takes no base URL: the endpoint is the compiled constant, so there is
    /// no parameter through which a caller could point credentialed traffic anywhere else. The
    /// gate is closed, so no write can leave this process until it is explicitly opened, and it
    /// can only be opened for a loopback host. No network contact happens here.
    pub fn connect(token: &str) -> Result<Self, GmailError> {
        Ok(Self(GatedTransport::production_with(ReqwestClient::new(
            BearerToken::new(token),
        )?)))
    }

    /// Connect to a loopback fixture and open the destructive-write gate for it. The only
    /// constructor that accepts a base: origin-only, loopback-only, refused before any network.
    /// This exists for hermetic tests; it can never be aimed at a real mailbox.
    pub fn connect_for_test_fixture(origin: &str, token: &str) -> Result<Self, GmailError> {
        Ok(Self(GatedTransport::fixture_with(
            ReqwestClient::new(BearerToken::new(token))?,
            origin,
        )?))
    }

    /// Enable destructive writes against the gate's authorized host (the ADR-P010 flag). Without
    /// it `modify_labels` refuses. A gate can only be opened for a loopback host, so this cannot
    /// name a real mailbox.
    pub fn with_destructive_writes(self, gate: DestructiveWriteGate) -> Self {
        Self(self.0.with_destructive_writes(gate))
    }
}

impl GmailTransport for HttpGmailTransport {
    fn modify_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        request: &GmailModifyRequest,
    ) -> Result<(), GmailError> {
        self.0.modify_labels(user, message, request)
    }

    /// Facade over the gated core, like `modify_labels`.
    fn modify_labels_observed(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        request: &GmailModifyRequest,
    ) -> Result<BTreeSet<String>, GmailError> {
        self.0.modify_labels_observed(user, message, request)
    }

    /// Facade over the gated core, like `modify_labels`.
    fn trash_message(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        self.0.trash_message(user, message)
    }

    /// Facade over the gated core, like `modify_labels`.
    fn untrash_message(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        self.0.untrash_message(user, message)
    }

    /// The live observe half, delegated to the gated core's read (see
    /// `GatedTransport::message_labels`).
    fn message_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        self.0.message_labels(user, message)
    }

    /// The live listing facade, delegating like `message_labels`.
    fn list_inbox_page(
        &self,
        user: &GmailUserId,
        page_size: i64,
        continuation: Option<&ContinuationToken>,
    ) -> Result<ListedPage, GmailError> {
        self.0.list_inbox_page(user, page_size, continuation)
    }

    /// The live body-read facade, delegating like `message_labels`.
    fn fetch_body(&self, user: &GmailUserId, message: &GmailMessageId) -> Result<RawBody, GmailError> {
        self.0.fetch_body(user, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aruna::encoded_word::base64_standard_decode;
    use aruna::gmail::{
        classify_gmail_error, GmailAccountResolver, GmailConnector, GmailMessageId,
        GmailMessageRefResolver, GmailUserId,
    };
    use aruna::{Action, Command, Connector, Facet, FailureKind, LogError, MailFlag};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    // A fake HTTP client: replies with queued responses in order and records every request, so the
    // orchestration is exercised over a synthetic wire with zero network. It grades ORCHESTRATION
    // and TAXONOMY only — never client configuration (see the module comment).
    #[derive(Clone, Debug)]
    struct FakeHttp {
        inner: Rc<RefCell<FakeInner>>,
    }
    #[derive(Debug)]
    struct FakeInner {
        queued: VecDeque<HttpResponse>,
        calls: Vec<(String, serde_json::Value)>,
        /// Which seam method carried each call, index-aligned with `calls`. The body
        /// slot alone cannot tell a bodiless POST from a GET — both record `Null` — so the verb
        /// is logged beside it rather than smuggled into the body as a marker value.
        verbs: Vec<FakeVerb>,
    }
    /// The three `HttpClient` methods, as the fake saw them dispatched.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeVerb {
        PostJson,
        PostEmpty,
        Get,
    }
    impl FakeHttp {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                inner: Rc::new(RefCell::new(FakeInner {
                    queued: responses.into_iter().collect(),
                    calls: Vec::new(),
                    verbs: Vec::new(),
                })),
            }
        }
        fn calls(&self) -> Vec<(String, serde_json::Value)> {
            self.inner.borrow().calls.clone()
        }
        fn verbs(&self) -> Vec<FakeVerb> {
            self.inner.borrow().verbs.clone()
        }
    }
    impl HttpClient for FakeHttp {
        fn post_json(
            &self,
            url: &str,
            body: &serde_json::Value,
        ) -> Result<HttpResponse, GmailError> {
            let mut inner = self.inner.borrow_mut();
            inner.calls.push((url.to_string(), body.clone()));
            inner.verbs.push(FakeVerb::PostJson);
            Ok(inner
                .queued
                .pop_front()
                .expect("FakeHttp ran out of queued responses"))
        }

        fn post_empty(&self, url: &str) -> Result<HttpResponse, GmailError> {
            // No body exists to record: `Null` fills the slot, as for `get`, and the verb log is
            // what tells a bodiless POST from a GET (and from a `post_json`).
            let mut inner = self.inner.borrow_mut();
            inner.calls.push((url.to_string(), serde_json::Value::Null));
            inner.verbs.push(FakeVerb::PostEmpty);
            Ok(inner
                .queued
                .pop_front()
                .expect("FakeHttp ran out of queued responses"))
        }

        fn get(&self, url: &str, _route: WireRoute) -> Result<HttpResponse, GmailError> {
            // The route is IGNORED here on purpose: this fake hands back whatever the test queued,
            // byte for byte, so the route-keyed bounded read it drives in the live client has
            // nothing to act on. That is the same limit the module doc already names — the rig
            // grades orchestration and taxonomy, never client configuration.
            //
            // A GET carries no body; `Null` marks the slot so the shared call recorder still
            // captures the URL (the request-shape witnesses read it).
            let mut inner = self.inner.borrow_mut();
            inner.calls.push((url.to_string(), serde_json::Value::Null));
            inner.verbs.push(FakeVerb::Get);
            Ok(inner
                .queued
                .pop_front()
                .expect("FakeHttp ran out of queued responses"))
        }
    }
    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            content_length: Some(body.len() as u64),
            body: body.to_string(),
        }
    }
    /// Like [`resp`], but the advertised `Content-Length` is the TEST's choice — absent (chunked
    /// transfer) or a lie. `resp` always tells the truth, which let the header short-circuit mask
    /// the `body.len()` check in every cap test: deleting that check left all of them green
    /// (a check that cannot fail).
    fn resp_lying_about_length(status: u16, body: &str, content_length: Option<u64>) -> HttpResponse {
        HttpResponse {
            status,
            content_length,
            body: body.to_string(),
        }
    }

    fn user(id: &str) -> GmailUserId {
        GmailUserId(id.to_string())
    }
    fn message(id: &str) -> GmailMessageId {
        GmailMessageId(id.to_string())
    }
    fn endpoint() -> reqwest::Url {
        reqwest::Url::parse(GMAIL_ENDPOINT).expect("the compiled endpoint parses")
    }

    // ---- the compiled production endpoint (design §3, v6/v7) ----

    #[test]
    fn the_production_endpoint_is_the_compiled_discovery_root_url() {
        // Identity pinned at the byte: scheme, host, path exactly `/`, and nothing else. Anything
        // that drifts here changes where credentialed mutations go.
        assert_eq!(GMAIL_ENDPOINT, "https://gmail.googleapis.com/");
        let url = reqwest::Url::parse(GMAIL_ENDPOINT).expect("the compiled endpoint must parse");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("gmail.googleapis.com"));
        assert_eq!(url.path(), "/");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
        assert_eq!(url.port(), None);
        assert_eq!(url.username(), "");
        assert_eq!(url.password(), None);
    }

    #[test]
    fn the_endpoint_is_matched_by_identity_never_by_suffix() {
        // There is no host parameter in production, so a typosquat cannot be PASSED — this asserts
        // the other half: nothing in this crate would accept these as the endpoint. A
        // `*.googleapis.com` suffix rule would admit every one of them.
        let endpoint = reqwest::Url::parse(GMAIL_ENDPOINT).expect("parse");
        for impostor in [
            "https://gmai1.googleapis.com/",              // typosquat
            "https://gmail.googleapis.com.evil.test/",    // suffix-appended
            "https://evil.test/gmail.googleapis.com/",    // path, not authority
            "https://gmail.mtls.googleapis.com/",         // real, but UNSUPPORTED here
            "https://www.googleapis.com/",                // the legacy alternate
            "https://gmail.googleapis.com.evil.test:443/",
        ] {
            let other = reqwest::Url::parse(impostor).expect("parse");
            assert_ne!(
                other.host_str(),
                endpoint.host_str(),
                "{impostor} must never be taken for the compiled endpoint"
            );
        }
    }

    // ---- the destructive-write gate (the executable half of the live-drill fence) ----

    #[test]
    fn allow_test_host_refuses_the_production_gmail_authority() {
        // The parked-state fence, testable rather than a comment: the live drill cannot be
        // aimed at Gmail by opening this gate, because the gate will not open for it.
        for host in [
            "gmail.googleapis.com",
            "gmail.mtls.googleapis.com",
            "www.googleapis.com",
            "mail.google.com",
        ] {
            assert_eq!(
                DestructiveWriteGate::allow_test_host(host).unwrap_err(),
                GateError::NonLocalHostRefused,
                "{host} must be unauthorizable"
            );
        }
    }

    #[test]
    fn allow_test_host_refuses_public_addresses() {
        for host in [
            "8.8.8.8",
            "203.0.113.10",
            "2001:4860:4860::8888",
            "[2001:4860:4860::8888]",
            "0.0.0.0",
            "169.254.169.254", // cloud metadata — routable, not loopback
        ] {
            assert_eq!(
                DestructiveWriteGate::allow_test_host(host).unwrap_err(),
                GateError::NonLocalHostRefused,
                "{host} is not proof of locality"
            );
        }
    }

    #[test]
    fn allow_test_host_refuses_test_and_localhost_names() {
        // A NAME is not proof of locality — `foo.localhost` / `evil.test` can resolve off-machine.
        for host in [
            "evil.test",
            "fixture.localhost",
            "localhost.evil.com",
            "localhost.",
            "notlocalhost",
        ] {
            assert_eq!(
                DestructiveWriteGate::allow_test_host(host).unwrap_err(),
                GateError::NonLocalHostRefused,
                "{host} is a name, not a loopback address"
            );
        }
    }

    #[test]
    fn allow_test_host_refuses_bracketed_non_ipv6() {
        // Bracket-stripping is IPv6 normalization ONLY. If it were arbitrary, `[localhost]` and
        // `[127.0.0.1]` would sneak past the shape checks a URL parser applies to brackets.
        for host in ["[localhost]", "[127.0.0.1]", "[evil.test]", "[::1", "::1]", "[]"] {
            assert_eq!(
                DestructiveWriteGate::allow_test_host(host).unwrap_err(),
                GateError::NonLocalHostRefused,
                "{host} must not be bracket-stripped into a loopback"
            );
        }
    }

    #[test]
    fn localhost_case_behavior_is_pinned_to_exact_match() {
        // PINNED, not incidental: the literal-name comparison is byte-exact, so `LOCALHOST` is
        // refused. A URL parser lowercases the host before this ever sees it (asserted below), so
        // the strict form costs nothing on the real path and keeps the raw-string API fail-closed.
        assert_eq!(
            DestructiveWriteGate::allow_test_host("LOCALHOST").unwrap_err(),
            GateError::NonLocalHostRefused
        );
        assert_eq!(
            host_of("http://LOCALHOST:8080/").as_deref(),
            Some("localhost"),
            "the URL parser lowercases the host, so the real path is unaffected"
        );
    }

    #[test]
    fn allow_test_host_permits_actual_loopback_and_binds_canonically() {
        for host in ["localhost", "127.0.0.1", "127.0.0.2", "::1", "[::1]"] {
            assert!(
                DestructiveWriteGate::allow_test_host(host).is_ok(),
                "{host} is an actual loopback target"
            );
        }
        // `::1` and `[::1]` are ONE authority: a gate opened with either must permit the other, or
        // a fixture write would be refused purely by bracket form.
        let bare = DestructiveWriteGate::allow_test_host("::1").expect("open");
        assert!(bare.permits_host("[::1]"));
        let bracketed = DestructiveWriteGate::allow_test_host("[::1]").expect("open");
        assert!(bracketed.permits_host("::1"));
        // …and the bind is still EXACT: one loopback host does not authorize another.
        let local = DestructiveWriteGate::allow_test_host("127.0.0.1").expect("open");
        assert!(local.permits_host("127.0.0.1"));
        assert!(!local.permits_host("127.0.0.2"));
        assert!(!local.permits_host("localhost"));
        assert!(!local.permits_host("gmail.googleapis.com"));
    }

    #[test]
    fn a_closed_gate_permits_nothing() {
        let closed = DestructiveWriteGate::closed();
        for host in ["127.0.0.1", "localhost", "::1", "gmail.googleapis.com", ""] {
            assert!(!closed.permits_host(host), "closed gate permitted {host}");
        }
    }

    #[test]
    fn obfuscated_loopback_normalizes_in_the_url_parser_so_the_gate_and_the_url_agree() {
        // The gate is ALWAYS keyed from the parsed host, never from a raw string, so an obfuscated
        // loopback form cannot make the two disagree: whatever the URL parser resolves is exactly
        // what the gate is opened for and later checked against.
        for form in ["127.1", "2130706433", "0x7f.1", "127.0.0.1"] {
            let raw = format!("http://{form}/");
            let host = host_of(&raw).expect("parseable");
            assert!(
                is_loopback_host(&host),
                "{form} parsed to {host}, which must be recognized as loopback"
            );
            let gate = DestructiveWriteGate::allow_test_host(&host).expect("loopback opens");
            assert!(
                gate.permits_host(&host),
                "the gate must permit the very host it was opened from"
            );
        }
        // Handed the raw obfuscated string directly — no URL parser involved — the strict grammar
        // refuses rather than guessing. Fail-closed in the direction that matters.
        for form in ["127.1", "2130706433", "0x7f.1"] {
            assert_eq!(
                DestructiveWriteGate::allow_test_host(form).unwrap_err(),
                GateError::NonLocalHostRefused,
                "{form} is not a canonical address literal"
            );
        }
    }

    // ---- identifier validation + URL construction (design §3) ----

    #[test]
    fn the_production_modify_url_is_the_compiled_endpoint_route() {
        // The ENTIRE final URL string, asserted at the byte. This is an assertion rather than a
        // refusal test on purpose: the typosquat case (gmai1.googleapis.com) is closed BY
        // CONSTRUCTION — there is no parameter to pass it through — so what is left to prove is
        // that the URL we actually build is the one we intend.
        let url = modify_url(&endpoint(), &user("me"), &message("MSG-1")).expect("valid ids");
        assert_eq!(
            url.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/MSG-1/modify?fields=id,labelIds"
        );
        // …and a userId that is legitimately an email address (Gmail documents both forms).
        // MEASURED: `@` is a valid path character (RFC 3986 pchar) and the encoder leaves it as-is.
        // That is harmless — an `@` after the path has begun cannot introduce an authority — but it
        // is asserted rather than assumed, because the whole point of this test is that we know the
        // exact bytes we put on the wire.
        let addressed = modify_url(&endpoint(), &user("person@example.com"), &message("MSG-1"))
            .expect("an address is a legitimate userId");
        assert_eq!(
            addressed.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/person@example.com/messages/MSG-1/modify?fields=id,labelIds"
        );
    }

    #[test]
    fn empty_and_dot_segment_identifiers_are_refused_before_any_url_exists() {
        // Refused for BOTH ids, deterministically, at a point where no URL — and therefore no
        // socket — exists yet.
        for bad in ["", ".", ".."] {
            let by_user = modify_url(&endpoint(), &user(bad), &message("MSG-1"))
                .expect_err("userId must be refused");
            assert_eq!(classify_gmail_error(&by_user), FailureKind::Deterministic);
            let by_message = modify_url(&endpoint(), &user("me"), &message(bad))
                .expect_err("message id must be refused");
            assert_eq!(classify_gmail_error(&by_message), FailureKind::Deterministic);
        }
    }

    #[test]
    fn a_dot_segment_would_shift_the_route_because_the_encoder_elides_it() {
        // The executed evidence the validation rule exists for, re-run here as a live witness: the
        // encoder percent-encodes metacharacters but ELIDES exact dot segments, so relying on it
        // (v1's plan) leaves a route-shifting hole. If this ever starts producing 7 segments, the
        // dependency's behaviour changed and the rationale above needs re-reading — the validation
        // itself stays either way.
        let mut probe = endpoint();
        probe
            .path_segments_mut()
            .expect("base")
            .clear()
            .extend(["gmail", "v1", "users", "..", "messages", "MSG-1", "modify"]);
        assert_eq!(
            probe.path(),
            "/gmail/v1/users/messages/MSG-1/modify",
            "the encoder elides `..` rather than encoding it — six segments, route shifted"
        );
        assert_eq!(
            probe.path_segments().expect("segments").count(),
            6,
            "six segments where the route needs seven"
        );
    }

    #[test]
    fn url_metacharacters_in_ids_are_encoded_and_the_route_shape_is_pinned() {
        // The WHOLE path string plus the exact segment count — a weaker "no query, no fragment"
        // assertion cannot catch a route that shifted by segment elision.
        for hostile in [
            "M/../../evil",
            "M?alt=media",
            "M#frag",
            "M%2f..%2fevil",
            "M\u{0}NUL",
            "M/modify",
        ] {
            let url = modify_url(&endpoint(), &user("me"), &message(hostile))
                .expect("opaque ids are transmitted, not rejected");
            let segments: Vec<&str> = url.path_segments().expect("segments").collect();
            assert_eq!(
                segments.len(),
                7,
                "id {hostile:?} produced {segments:?} — the route shape must be exactly 7 segments"
            );
            assert_eq!(segments[0..3], ["gmail", "v1", "users"]);
            assert_eq!(segments[3], "me");
            assert_eq!(segments[4], "messages");
            assert_eq!(segments[6], "modify");
            assert_eq!(
                url.query(),
                Some("fields=id,labelIds"),
                "the partial-response narrowing must survive exactly, for id {hostile:?}"
            );
            assert_eq!(url.fragment(), None);
            assert_eq!(url.host_str(), Some("gmail.googleapis.com"));
        }
    }

    #[test]
    fn ids_are_otherwise_opaque_no_invented_charset() {
        // Gmail publishes no character grammar for message ids, and `userId` is legitimately an
        // address — so anything that is not a URL-semantic exception is transmitted as given.
        for id in ["18f0a1b2c3d4e5f6", "MSG-1_x", "ü-nicode", "with space", "+=~", "."] {
            let result = modify_url(&endpoint(), &user("me"), &message(id));
            assert_eq!(
                result.is_ok(),
                id != ".",
                "only the three URL-semantic exceptions are refused; {id:?} is otherwise opaque"
            );
        }
    }

    // ---- origin-only fixture bases (design §3, v4) ----

    #[test]
    fn a_fixture_base_must_be_an_origin() {
        for ok in [
            "http://127.0.0.1:18080",
            "http://127.0.0.1:18080/",
            "https://localhost",
            "http://[::1]:18080/",
        ] {
            assert!(parse_origin(ok).is_ok(), "{ok} is an origin");
        }
        for bad in [
            "https://user:pw@gmail.googleapis.com/",  // userinfo
            "https://gmail.googleapis.com/prefix",    // a non-root path
            "https://gmail.googleapis.com/proxy/",    // …including the one that survived v4's rules
            "https://gmail.googleapis.com/?alt=media", // a query
            "https://gmail.googleapis.com/#frag",     // a fragment
            "https://gmail.googleapis.com/prefix?alt=media#frag",
            "not a url",
        ] {
            let err = parse_origin(bad).expect_err("must be refused");
            assert_eq!(
                classify_gmail_error(&err),
                FailureKind::Deterministic,
                "{bad} is not an origin"
            );
        }
    }

    #[test]
    fn changing_a_path_does_not_clear_a_query_or_fragment() {
        // The discriminating probe, executed: this is WHY the rule is origin-only rather than
        // "normalize the path". A host + segment-count assertion passes while the defect is live —
        // only comparing the entire final URL string catches it.
        let mut leaky = reqwest::Url::parse("https://gmail.googleapis.com/prefix?alt=media#frag")
            .expect("parse");
        leaky
            .path_segments_mut()
            .expect("base")
            .clear()
            .extend([
                "gmail", "v1", "users", "me", "messages", "MSG-1", "modify",
            ]);
        assert_eq!(
            leaky.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/MSG-1/modify?alt=media#frag",
            "the query and fragment SURVIVE a path change — hence the origin-only rule"
        );
        // The rule closes it before construction ever happens.
        assert!(parse_origin("https://gmail.googleapis.com/prefix?alt=media#frag").is_err());
    }

    // ---- construction: production takes NO base; the fixture path is loopback + origin only ----

    #[test]
    fn production_construction_uses_the_compiled_endpoint_and_a_closed_gate() {
        let transport = GatedTransport::production_with(FakeHttp::new(vec![]));
        assert_eq!(transport.base.as_str(), GMAIL_ENDPOINT);
        assert!(
            !transport.gate.permits_host("gmail.googleapis.com"),
            "production must be constructed with the gate CLOSED"
        );
        // The whole route, from a transport built with no base parameter at all.
        let url = modify_url(&transport.base, &user("me"), &message("MSG-1")).expect("ids ok");
        assert_eq!(
            url.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/MSG-1/modify?fields=id,labelIds"
        );
    }

    #[test]
    fn the_fixture_constructor_refuses_non_loopback_plaintext_and_non_origin_bases() {
        // Every refusal happens before the client is ever used — asserted, not assumed, by queueing
        // a success response and then proving nothing was sent.
        for bad in [
            "https://gmail.googleapis.com/",         // real authority: the gate cannot open for it
            "https://gmail.googleapis.com/prefix",   // …nor with a path
            "http://mail.example.com",               // plaintext credentials off-loopback
            "http://8.8.8.8:80",                     // public address
            "http://fixture.localhost:18080",        // a NAME is not proof of locality
            "https://user:pw@127.0.0.1:18080/",      // userinfo
            "http://127.0.0.1:18080/?alt=media",     // a query that would survive path construction
            "http://127.0.0.1:18080/#frag",          // a fragment, likewise
            "127.0.0.1:18080",                       // schemeless
        ] {
            let fake = FakeHttp::new(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
            let probe = fake.clone();
            let err = GatedTransport::fixture_with(fake, bad)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"));
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
            assert!(
                probe.calls().is_empty(),
                "{bad} was refused only AFTER touching the wire"
            );
        }
    }

    #[test]
    fn the_fixture_constructor_opens_the_gate_for_a_loopback_origin() {
        for origin in ["http://127.0.0.1:18080", "http://localhost:18080/", "https://[::1]:8443"] {
            let transport = GatedTransport::fixture_with(FakeHttp::new(vec![]), origin)
                .unwrap_or_else(|_| panic!("{origin} is a loopback origin"));
            let host = reqwest::Url::parse(origin)
                .expect("parse")
                .host_str()
                .expect("host")
                .to_string();
            assert!(
                transport.gate.permits_host(&host),
                "{origin} should have opened the gate for {host}"
            );
            assert!(!transport.gate.permits_host("gmail.googleapis.com"));
        }
    }

    #[test]
    fn with_destructive_writes_is_the_only_flag_flip_and_cannot_name_a_real_host() {
        // The ADR-P010 flip takes a gate, and a gate for a production host cannot be constructed —
        // so there is no expressible way to enable a real-mailbox write.
        let transport = GatedTransport::production_with(FakeHttp::new(vec![]))
            .with_destructive_writes(DestructiveWriteGate::allow_test_host("127.0.0.1").expect("ok"));
        assert!(transport.gate.permits_host("127.0.0.1"));
        assert!(!transport.gate.permits_host("gmail.googleapis.com"));
        assert!(DestructiveWriteGate::allow_test_host("gmail.googleapis.com").is_err());
    }

    // ---- redaction (credentials, endpoint, body) ----

    #[test]
    fn debug_redacts_the_bearer_token() {
        let token = BearerToken::new("ya29.SUPER-SECRET-ACCESS-TOKEN");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "BearerToken(<redacted>)");
        assert!(!rendered.contains("ya29"), "the token leaked: {rendered}");
    }

    #[test]
    fn debug_redacts_the_response_body_to_a_byte_count() {
        // A `Message` body carries provider ids — and, if a server ignores the partial-response
        // narrowing, snippets and headers too. Only the status and the byte count are printable.
        let response = resp(200, r#"{"id":"SEEDED-MESSAGE-ID","labelIds":["INBOX","UNREAD"]}"#);
        let rendered = format!("{response:?}");
        assert!(
            rendered.contains("<56 bytes redacted>"),
            "the body must be reduced to a byte count: {rendered}"
        );
        assert!(!rendered.contains("SEEDED-MESSAGE-ID"), "leaked: {rendered}");
        assert!(!rendered.contains("INBOX"), "leaked: {rendered}");
    }

    #[test]
    fn debug_redacts_the_transport_base() {
        let transport =
            GatedTransport::fixture_with(FakeHttp::new(vec![]), "http://127.0.0.1:18080")
                .expect("loopback origin");
        let rendered = format!("{transport:?}");
        assert!(
            rendered.contains("base: \"<redacted>\""),
            "the base must not reach Debug output: {rendered}"
        );
        assert!(!rendered.contains("18080"), "the endpoint leaked: {rendered}");

        // …and the PUBLIC facade redacts through to it — the wrapper is what a caller can hold.
        let public = HttpGmailTransport::connect_for_test_fixture("http://127.0.0.1:18080", "tok")
            .expect("loopback fixture");
        let rendered = format!("{public:?}");
        assert!(
            rendered.contains("base: \"<redacted>\""),
            "the facade must redact the base too: {rendered}"
        );
        assert!(!rendered.contains("18080"), "the endpoint leaked: {rendered}");
    }

    #[test]
    fn no_provider_id_or_secret_appears_in_a_construction_error() {
        // Confinement by construction: the refusal type carries no payload, so there is nowhere for
        // a seeded id, a token, or a hostile base to ride out of this crate.
        let err = GatedTransport::fixture_with(
            FakeHttp::new(vec![]),
            "https://SEEDED-PROVIDER-HOST.example/",
        )
        .expect_err("refused");
        let rendered = format!("{err:?}");
        assert!(!rendered.contains("SEEDED-PROVIDER-HOST"), "leaked: {rendered}");
        assert_eq!(rendered, "Unknown");
    }

    // ============================================================================================
    // `modify_labels` orchestration. The request bodies come from the REAL connector: a capture
    // transport driven through `GmailConnector::apply` is the request factory, so "the body is the
    // connector-built request verbatim" is literal rather than asserted — and no `aruna` edit is
    // needed to reach the type's private constructors.
    // ============================================================================================

    struct Fixed;
    impl GmailAccountResolver for Fixed {
        /// A STABLE account identity, never the credential-relative `me` alias: an account
        /// resolver feeds `resolve_basis`, which refuses to freeze `gmail:me/<id>`.
        /// The alias stays legal on the WIRE — the `modify_url`/`get_message_url` witnesses
        /// below still exercise it there.
        fn resolve_user(&self, _photon_account: &str) -> Option<GmailUserId> {
            Some(user("fixture-user@example.test"))
        }
    }
    impl GmailMessageRefResolver for Fixed {
        fn resolve_message(
            &self,
            _photon_account: &str,
            _message_ref: &str,
        ) -> Result<Option<GmailMessageId>, LogError> {
            Ok(Some(message("MSG-1")))
        }
    }

    /// The connector builds the `GmailModifyRequest`; this captures the very one it built.
    fn connector_request(action: Action) -> GmailModifyRequest {
        struct Capture(Rc<RefCell<Option<GmailModifyRequest>>>);
        impl GmailTransport for Capture {
            fn modify_labels(
                &self,
                _user: &GmailUserId,
                _message: &GmailMessageId,
                request: &GmailModifyRequest,
            ) -> Result<(), GmailError> {
                *self.0.borrow_mut() = Some(request.clone());
                Ok(())
            }
            // The observed twin captures the same request; this fake carries no label set.
            fn modify_labels_observed(
                &self,
                _user: &GmailUserId,
                _message: &GmailMessageId,
                request: &GmailModifyRequest,
            ) -> Result<BTreeSet<String>, GmailError> {
                *self.0.borrow_mut() = Some(request.clone());
                Ok(BTreeSet::new())
            }
            // The dedicated routes build NO modify request, so there is nothing to capture:
            // refuse rather than report a fabricated observed set.
            fn trash_message(
                &self,
                _user: &GmailUserId,
                _message: &GmailMessageId,
            ) -> Result<BTreeSet<String>, GmailError> {
                Err(GmailError::Unknown)
            }
            fn untrash_message(
                &self,
                _user: &GmailUserId,
                _message: &GmailMessageId,
            ) -> Result<BTreeSet<String>, GmailError> {
                Err(GmailError::Unknown)
            }
        }
        let cell = Rc::new(RefCell::new(None));
        let connector = GmailConnector::new(Capture(Rc::clone(&cell)), Fixed, Fixed);
        let command = Command::new("k-capture", "photon-acct", Facet::Mail, action);
        // Freeze first, dispatch second — the engine's own two-step. `apply` CONSUMES the
        // admission-frozen basis and verifies its own resolution against it rather than
        // re-resolving, so a capture fixture supplies the freeze the
        // bus would have taken. `Fixed` answers identically at both moments, so this passes.
        let basis = connector
            .resolve_basis(&command)
            .expect("the admission freeze");
        connector
            .apply(&command, &basis)
            .expect("the connector applies against a capture transport");
        let captured = cell.borrow_mut().take();
        captured.expect("the connector built a request")
    }

    fn archive_request() -> GmailModifyRequest {
        connector_request(Action::Archive {
            message_ref: "msg-1".to_string(),
        })
    }
    fn unarchive_request() -> GmailModifyRequest {
        connector_request(Action::Unarchive {
            message_ref: "msg-1".to_string(),
        })
    }
    /// `set_seen(true)` — remove `UNREAD`, add nothing. The remove-only shape.
    fn set_seen_request(value: bool) -> GmailModifyRequest {
        connector_request(Action::SetFlag {
            message_ref: "msg-1".to_string(),
            flag: MailFlag::Seen,
            value,
        })
    }
    /// `set_starred(value)` — DIRECT polarity: star ⇒ add `STARRED`, unstar ⇒ remove it
    /// (star/unstar design 2026-07-26 §3).
    fn set_starred_request(value: bool) -> GmailModifyRequest {
        connector_request(Action::SetFlag {
            message_ref: "msg-1".to_string(),
            flag: MailFlag::Flagged,
            value,
        })
    }

    /// A fixture transport with the gate OPEN, over a queued fake wire.
    fn fixture(responses: Vec<HttpResponse>) -> (GatedTransport<FakeHttp>, FakeHttp) {
        let fake = FakeHttp::new(responses);
        let probe = fake.clone();
        let transport = GatedTransport::fixture_with(fake, "http://127.0.0.1:18080")
            .expect("loopback origin");
        (transport, probe)
    }

    fn apply(transport: &GatedTransport<FakeHttp>, request: &GmailModifyRequest) -> Result<(), GmailError> {
        transport.modify_labels(&user("me"), &message("MSG-1"), request)
    }

    // ---- the gate, wired into modify_labels ----

    #[test]
    fn a_closed_gate_refuses_the_write_with_zero_wire_calls() {
        // A SUCCESS response is queued on purpose: if the gate leaks, the write wrongly SUCCEEDS
        // (a clean failure) instead of panicking on an empty queue.
        let fake = FakeHttp::new(vec![resp(
            200,
            r#"{"id":"MSG-1","labelIds":["IMPORTANT"]}"#,
        )]);
        let probe = fake.clone();
        let transport = GatedTransport::production_with(fake);

        let err = apply(&transport, &archive_request()).expect_err("closed gate → refuse");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
        assert!(
            probe.calls().is_empty(),
            "a default-closed gate must not let the mutation reach the network"
        );
        // The probe above PROVES no wire call happened, so the evidence the
        // engine settles on must say so. Before the fix this refusal was `GmailError::Unknown` —
        // the same bucket an UNPROVABLE post-dispatch stall lands in — so a build shipping with
        // the default-closed gate parked every mutation in `ACK_AMBIGUOUS` adjudication instead
        // of failing cleanly.
        assert_eq!(
            aruna::gmail::gmail_effect_evidence(&err),
            aruna::EffectEvidence::ProvenNoWire,
            "a refusal decided before a socket exists is PROVEN no-wire, not an unknown"
        );
    }

    #[test]
    fn identifier_refusals_happen_with_zero_wire_calls() {
        for (bad_user, bad_message) in [("", "MSG-1"), (".", "MSG-1"), ("me", ".."), ("me", "")] {
            let (transport, probe) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
            let err = transport
                .modify_labels(&user(bad_user), &message(bad_message), &archive_request())
                .expect_err("invalid identifiers must be refused");
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
            assert!(
                probe.calls().is_empty(),
                "userId={bad_user:?} id={bad_message:?} reached the wire"
            );
            // Same rule: the URL never even got built, so nothing was sent.
            assert_eq!(
                aruna::gmail::gmail_effect_evidence(&err),
                aruna::EffectEvidence::ProvenNoWire,
                "userId={bad_user:?} id={bad_message:?}: refused before a URL existed"
            );
        }
    }

    // ---- the dedicated trash/untrash routes and the observed modify ----

    fn labels(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn trash_url_and_untrash_url_are_the_dedicated_endpoints_with_the_field_mask() {
        let base = endpoint();
        let u = user("me");
        let m = message("18f0abc");
        assert_eq!(
            trash_url(&base, &u, &m).expect("valid ids").as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/18f0abc/trash?fields=id,labelIds"
        );
        assert_eq!(
            untrash_url(&base, &u, &m).expect("valid ids").as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/18f0abc/untrash?fields=id,labelIds"
        );
        // Validate_path_id runs FIRST — an exact dot segment (which the encoder would ELIDE,
        // shifting the route) or an empty id never reaches a URL, and the refusal is pre-wire.
        for (bad_user, bad_message) in [("me", ".."), ("me", "."), ("me", ""), ("..", "18f0abc")] {
            for built in [
                trash_url(&base, &user(bad_user), &message(bad_message)),
                untrash_url(&base, &user(bad_user), &message(bad_message)),
            ] {
                assert_eq!(
                    built.expect_err("an unroutable id must be refused before a URL exists"),
                    GmailError::PreWireRefused,
                    "userId={bad_user:?} id={bad_message:?}"
                );
            }
        }
        // A NON-dot id carrying a slash is not refused — it is ENCODED into ONE segment, so the
        // route cannot shift onto another resource (the same guarantee `modify_url` rests on).
        let hostile = trash_url(&base, &u, &message("../delete")).expect("encoded, not refused");
        assert_eq!(hostile.path(), "/gmail/v1/users/me/messages/..%2Fdelete/trash");
        assert_eq!(hostile.query(), Some("fields=id,labelIds"));
    }

    #[test]
    fn trash_message_posts_once_through_the_gate_and_returns_the_observed_label_set() {
        let (transport, probe) = fixture(vec![resp(
            200,
            r#"{"id":"18f0abc","labelIds":["TRASH","CATEGORY_PROMOTIONS"]}"#,
        )]);
        let observed = transport
            .trash_message(&user("me"), &message("18f0abc"))
            .expect("trash applies");
        assert_eq!(observed, labels(&["TRASH", "CATEGORY_PROMOTIONS"]));
        let calls = probe.calls();
        assert_eq!(calls.len(), 1, "exactly one dispatch");
        assert_eq!(
            calls[0].0,
            "http://127.0.0.1:18080/gmail/v1/users/me/messages/18f0abc/trash?fields=id,labelIds"
        );
        // Google's `users.messages.trash` reference: "The request body must be empty." So the
        // route rides the bodiless seam method — nothing is serialized, not even `{}`.
        assert_eq!(
            probe.verbs(),
            vec![FakeVerb::PostEmpty],
            "trash dispatches through `post_empty` exactly once and through `post_json` never"
        );
    }

    #[test]
    fn untrash_message_posts_once_to_the_untrash_route_and_returns_the_observed_label_set() {
        let (transport, probe) =
            fixture(vec![resp(200, r#"{"id":"18f0abc","labelIds":["INBOX","UNREAD"]}"#)]);
        let observed = transport
            .untrash_message(&user("me"), &message("18f0abc"))
            .expect("untrash applies");
        assert_eq!(observed, labels(&["INBOX", "UNREAD"]));
        let calls = probe.calls();
        assert_eq!(calls.len(), 1, "exactly one dispatch");
        assert_eq!(
            calls[0].0,
            "http://127.0.0.1:18080/gmail/v1/users/me/messages/18f0abc/untrash?fields=id,labelIds"
        );
        // `users.messages.untrash` carries the same sentence: "The request body must be empty."
        assert_eq!(
            probe.verbs(),
            vec![FakeVerb::PostEmpty],
            "untrash dispatches through `post_empty` exactly once and through `post_json` never"
        );

        // Proto3 JSON omits an empty `labelIds`: an untrashed message left with NO labels answers
        // with no member at all, and TRASH is provably absent — absent ≠ violated (the remove-only rule).
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"18f0abc"}"#)]);
        assert_eq!(
            transport
                .untrash_message(&user("me"), &message("18f0abc"))
                .expect("an absent labelIds proves TRASH absent"),
            BTreeSet::new()
        );
        // …while the same absence after a TRASH is a violation: TRASH was not proven present.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"18f0abc"}"#)]);
        assert_eq!(
            transport
                .trash_message(&user("me"), &message("18f0abc"))
                .expect_err("no labelIds cannot witness TRASH present"),
            GmailError::Unknown
        );
    }

    #[test]
    fn trash_witness_refuses_an_id_mismatch_and_a_missing_trash_label() {
        // Every refusal here happens AFTER a dispatch, so it must be the post-wire `Unknown` —
        // never the pre-wire variant (the request may have landed).
        let (t, _) = fixture(vec![resp(200, r#"{"id":"OTHER","labelIds":["TRASH"]}"#)]);
        assert_eq!(
            t.trash_message(&user("me"), &message("18f0abc"))
                .expect_err("a response for another message never feeds a witness"),
            GmailError::Unknown
        );
        let (t, _) = fixture(vec![resp(200, r#"{"labelIds":["TRASH"]}"#)]);
        assert_eq!(
            t.trash_message(&user("me"), &message("18f0abc"))
                .expect_err("an id-less response correlates to nothing"),
            GmailError::Unknown
        );
        let (t, _) = fixture(vec![resp(200, r#"{"id":"18f0abc","labelIds":["INBOX"]}"#)]);
        assert_eq!(
            t.trash_message(&user("me"), &message("18f0abc"))
                .expect_err("2xx must still prove the effect: TRASH present"),
            GmailError::Unknown
        );
        let (t, _) = fixture(vec![resp(200, r#"{"id":"18f0abc","labelIds":["TRASH"]}"#)]);
        assert_eq!(
            t.untrash_message(&user("me"), &message("18f0abc"))
                .expect_err("untrash must prove TRASH absent"),
            GmailError::Unknown
        );
        let (t, _) = fixture(vec![resp(200, r#"{"id":"OTHER","labelIds":["INBOX"]}"#)]);
        assert_eq!(
            t.untrash_message(&user("me"), &message("18f0abc"))
                .expect_err("the id echo binds untrash too"),
            GmailError::Unknown
        );
    }

    #[test]
    fn trash_routes_run_the_same_bounds_and_normalizer_as_modify() {
        // A non-2xx goes to the ONE normalizer, verbatim.
        let (t, _) = fixture(vec![resp(429, r#"{"error":{"code":429}}"#)]);
        assert_eq!(
            t.trash_message(&user("me"), &message("18f0abc"))
                .expect_err("a 429 is not an applied trash"),
            crate::error::map_error_response(429, r#"{"error":{"code":429}}"#)
        );
        // The byte cap runs BEFORE the witness: a body that WOULD witness TRASH is still refused
        // when its advertised length is over the cap.
        let witnessing = r#"{"id":"18f0abc","labelIds":["TRASH"]}"#;
        let (t, _) = fixture(vec![resp_lying_about_length(200, witnessing, Some(u64::MAX))]);
        assert_eq!(
            t.trash_message(&user("me"), &message("18f0abc"))
                .expect_err("over-cap is refused before parsing"),
            enforce_body_cap(200, Some(u64::MAX), witnessing).expect_err("over cap")
        );
    }

    #[test]
    fn a_closed_gate_refuses_trash_untrash_and_observed_modify_with_zero_wire_calls() {
        // SUCCESS responses are queued on purpose (the neighbour's discipline): a leaking gate
        // makes the write wrongly SUCCEED — a clean failure — rather than panic on an empty queue.
        let fake = FakeHttp::new(vec![
            resp(200, r#"{"id":"18f0abc","labelIds":["TRASH"]}"#),
            resp(200, r#"{"id":"18f0abc","labelIds":["INBOX"]}"#),
            resp(200, r#"{"id":"18f0abc","labelIds":["SPAM"]}"#),
        ]);
        let probe = fake.clone();
        let closed = GatedTransport::production_with(fake);
        let u = user("me");
        let m = message("18f0abc");
        let spam = aruna::gmail::GmailModifyRequest::for_test_add(&["SPAM"]);
        let refusals = [
            closed.trash_message(&u, &m).expect_err("closed gate → refuse trash"),
            closed.untrash_message(&u, &m).expect_err("closed gate → refuse untrash"),
            closed
                .modify_labels_observed(&u, &m, &spam)
                .expect_err("closed gate → refuse the observed modify"),
        ];
        for err in &refusals {
            assert_eq!(
                aruna::gmail::gmail_effect_evidence(err),
                aruna::EffectEvidence::ProvenNoWire,
                "a gate refusal is decided before a socket exists"
            );
        }
        assert!(probe.calls().is_empty(), "proven no wire");
    }

    #[test]
    fn modify_labels_observed_returns_the_responses_label_set_and_modify_labels_is_its_thin_wrapper() {
        let body = r#"{"id":"18f0abc","labelIds":["SPAM"]}"#;
        let request = aruna::gmail::GmailModifyRequest::for_test_add(&["SPAM"]);
        let (t, probe) = fixture(vec![resp(200, body)]);
        let observed = t
            .modify_labels_observed(&user("me"), &message("18f0abc"), &request)
            .expect("the observed modify applies");
        assert_eq!(observed, labels(&["SPAM"]));
        let observed_calls = probe.calls();
        assert_eq!(observed_calls.len(), 1, "exactly one dispatch");
        assert_eq!(
            observed_calls[0].1,
            serde_json::json!({"addLabelIds": ["SPAM"], "removeLabelIds": []})
        );
        // ONE route body: `modify_labels` sends the byte-identical exchange.
        let (t, probe) = fixture(vec![resp(200, body)]);
        t.modify_labels(&user("me"), &message("18f0abc"), &request)
            .expect("the wrapper applies");
        assert_eq!(probe.calls(), observed_calls);
        // …and the applied-witness still governs the observed twin: SPAM absent ⇒ refused.
        let (t, _) = fixture(vec![resp(200, r#"{"id":"18f0abc","labelIds":["INBOX"]}"#)]);
        assert_eq!(
            t.modify_labels_observed(&user("me"), &message("18f0abc"), &request)
                .expect_err("the requested add is not present"),
            GmailError::Unknown
        );
    }

    // ---- the request itself ----

    #[test]
    fn the_request_body_is_the_connector_built_request_and_only_the_two_label_arrays() {
        let (transport, probe) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":[]}"#)]);
        apply(&transport, &archive_request()).expect("archive applies");

        let calls = probe.calls();
        assert_eq!(calls.len(), 1, "exactly one dispatch");
        let (url, body) = &calls[0];
        assert_eq!(
            url,
            "http://127.0.0.1:18080/gmail/v1/users/me/messages/MSG-1/modify?fields=id,labelIds"
        );
        let object = body.as_object().expect("a JSON object");
        let keys: Vec<&String> = object.keys().collect();
        assert_eq!(
            keys,
            vec!["addLabelIds", "removeLabelIds"],
            "ONLY the two label arrays may serialize — no Classification-Label field may leak in"
        );
        assert_eq!(body["addLabelIds"], serde_json::json!([]));
        assert_eq!(body["removeLabelIds"], serde_json::json!(["INBOX"]));
    }

    #[test]
    fn the_transport_transmits_the_connectors_polarity_never_its_own() {
        // SetFlag(Seen) inversion lives in the connector (`set_seen`): read ⇒ REMOVE `UNREAD`.
        // The transport must carry exactly that, never invent a label.
        let (transport, probe) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
        apply(&transport, &set_seen_request(true)).expect("set_seen(true) applies");
        let (_, body) = &probe.calls()[0];
        assert_eq!(body["addLabelIds"], serde_json::json!([]));
        assert_eq!(body["removeLabelIds"], serde_json::json!(["UNREAD"]));

        let (transport, probe) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["UNREAD"]}"#)]);
        apply(&transport, &set_seen_request(false)).expect("set_seen(false) applies");
        let (_, body) = &probe.calls()[0];
        assert_eq!(body["addLabelIds"], serde_json::json!(["UNREAD"]));
        assert_eq!(body["removeLabelIds"], serde_json::json!([]));
    }

    #[test]
    fn the_transport_transmits_set_starred_direct_polarity_verbatim() {
        // SetFlag(Flagged) is DIRECT in the connector (`set_starred`): star ⇒ ADD `STARRED`,
        // unstar ⇒ REMOVE it — no inversion, unlike the UNREAD test above. The CAPTURED OUTBOUND
        // arrays are graded, not only the response echo: a request-graded witness can bless an
        // internally-consistent inversion (star/unstar design 2026-07-26 §5.4). Both responses
        // also pass the applied-witness postcondition for the STARRED add/remove.
        let (transport, probe) =
            fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["STARRED"]}"#)]);
        apply(&transport, &set_starred_request(true)).expect("set_starred(true) applies");
        let (_, body) = &probe.calls()[0];
        assert_eq!(body["addLabelIds"], serde_json::json!(["STARRED"]));
        assert_eq!(body["removeLabelIds"], serde_json::json!([]));

        let (transport, probe) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        apply(&transport, &set_starred_request(false)).expect("set_starred(false) applies");
        let (_, body) = &probe.calls()[0];
        assert_eq!(body["addLabelIds"], serde_json::json!([]));
        assert_eq!(body["removeLabelIds"], serde_json::json!(["STARRED"]));
    }

    #[test]
    fn a_contradicted_starred_postcondition_is_deterministic() {
        // The applied-witness on the star verb's own postcondition: a star whose response lacks
        // `STARRED`, or an unstar whose response still carries it, is refused — the named
        // residual (absent `labelIds` on a remove passes vacuously) is inherited, not new.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        let err = apply(&transport, &set_starred_request(true))
            .expect_err("STARRED absent after an add");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);

        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["STARRED"]}"#)]);
        let err = apply(&transport, &set_starred_request(false))
            .expect_err("STARRED still present after a remove");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn a_3xx_is_one_dispatch_and_a_deterministic_failure() {
        // Orchestration-level single dispatch: a 3xx arrives as a COMPLETED response (because the
        // client refuses to follow it) and is terminal. NOTE: `FakeHttp` cannot grade the client's
        // redirect CONFIGURATION at all — it never hands a real `Location` to a real client — so
        // the load-bearing proof is the loopback `ReqwestClient` witness (task 4b).
        let (transport, probe) = fixture(vec![HttpResponse {
            status: 307,
            content_length: Some(0),
            body: String::new(),
        }]);
        let err = apply(&transport, &archive_request()).expect_err("3xx → Err");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
        assert_eq!(probe.calls().len(), 1, "never a second POST, never a replay");
    }

    #[test]
    fn a_non_2xx_is_classified_by_the_normalizer() {
        for (status, body, expected) in [
            (429, "", FailureKind::Transient),
            (503, "", FailureKind::Transient),
            (403, r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions"}]}}"#, FailureKind::Deterministic),
            (403, r#"{"error":{"code":403,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#, FailureKind::Transient),
            (401, "", FailureKind::Deterministic),
            (404, "", FailureKind::Deterministic),
        ] {
            let (transport, _) = fixture(vec![resp(status, body)]);
            let err = apply(&transport, &archive_request()).expect_err("non-2xx → Err");
            assert_eq!(
                classify_gmail_error(&err),
                expected,
                "status {status} classified wrongly"
            );
        }
    }

    // ---- the applied-witness (§3.2) ----

    #[test]
    fn a_2xx_satisfying_both_conjuncts_is_applied() {
        let (transport, _) = fixture(vec![resp(
            200,
            r#"{"id":"MSG-1","labelIds":["IMPORTANT","CATEGORY_PERSONAL"]}"#,
        )]);
        apply(&transport, &archive_request()).expect("INBOX absent ⇒ the archive applied");

        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        apply(&transport, &unarchive_request()).expect("INBOX present ⇒ the unarchive applied");
    }

    #[test]
    fn an_id_mismatched_or_id_missing_2xx_is_deterministic() {
        // Identity FIRST: a response for a DIFFERENT message that happens to carry the expected
        // labels must not pass. HTTP request/response association proves nothing about which
        // resource came back.
        for body in [
            r#"{"id":"OTHER-MESSAGE","labelIds":["IMPORTANT"]}"#,
            r#"{"labelIds":["IMPORTANT"]}"#,
            r#"{"id":null,"labelIds":["IMPORTANT"]}"#,
            r#"{"id":"MSG-1 ","labelIds":["IMPORTANT"]}"#,
            "not json",
            "",
        ] {
            let (transport, _) = fixture(vec![resp(200, body)]);
            let err = apply(&transport, &archive_request())
                .err()
                .unwrap_or_else(|| panic!("body {body:?} must not pass the witness"));
            assert_eq!(
                classify_gmail_error(&err),
                FailureKind::Deterministic,
                "body {body:?}"
            );
        }
    }

    #[test]
    fn a_2xx_with_duplicate_witness_members_never_passes_the_witness() {
        // Regression test. `serde_json::Value`
        // takes the LAST duplicate member silently, so a response naming a DIFFERENT message first
        // and ours second passed conjunct 1, and a response contradicting the postcondition first
        // and satisfying it second passed conjunct 2. Either way an ambiguous 2xx was recorded as
        // APPLIED — the one outcome the witness exists to prevent. A duplicate member is a
        // non-conforming envelope: we cannot say which value the provider meant, so we refuse.
        for body in [
            // Conjunct 1 — identity, both orders.
            r#"{"id":"OTHER-MESSAGE","id":"MSG-1","labelIds":["IMPORTANT"]}"#,
            r#"{"id":"MSG-1","id":"OTHER-MESSAGE","labelIds":["IMPORTANT"]}"#,
            // Conjunct 2 — the label postcondition, both orders (archive removes INBOX).
            r#"{"id":"MSG-1","labelIds":["INBOX"],"labelIds":["IMPORTANT"]}"#,
            r#"{"id":"MSG-1","labelIds":["IMPORTANT"],"labelIds":["INBOX"]}"#,
            // …and a duplicate that a lenient parser would simply not notice.
            r#"{"id":"MSG-1","labelIds":["IMPORTANT"],"labelIds":["IMPORTANT"]}"#,
        ] {
            let (transport, _) = fixture(vec![resp(200, body)]);
            let err = apply(&transport, &archive_request())
                .err()
                .unwrap_or_else(|| panic!("body {body:?} must not pass the witness"));
            assert_eq!(
                classify_gmail_error(&err),
                FailureKind::Deterministic,
                "body {body:?}"
            );
        }
    }

    #[test]
    fn an_absent_labelids_on_a_remove_only_mutation_is_applied_not_violated() {
        // Proto3 JSON omits empty repeated fields, so a message left with zero labels legitimately
        // returns NO `labelIds`. The trigger is set_seen(true) — remove UNREAD, add nothing — this
        // milestone's own verb. Treating "lacks labelIds" as failure would dead-letter a write that
        // genuinely applied.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
        apply(&transport, &set_seen_request(true)).expect("remove-only + absent labelIds ⇒ APPLIED");

        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
        apply(&transport, &archive_request()).expect("archive is remove-only too ⇒ APPLIED");

        // …but an absent field where an ADD was requested is still a violation.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
        let err = apply(&transport, &unarchive_request())
            .expect_err("an add cannot be witnessed by an absent field");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn a_contradicted_postcondition_is_deterministic() {
        // A removed label still present, or an added label absent from a field that IS present.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        let err = apply(&transport, &archive_request()).expect_err("INBOX still present");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);

        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["IMPORTANT"]}"#)]);
        let err = apply(&transport, &unarchive_request()).expect_err("INBOX absent after an add");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);

        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":"INBOX"}"#)]);
        let err = apply(&transport, &archive_request()).expect_err("labelIds must be an array");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn no_response_text_or_provider_id_rides_out_on_a_witness_failure() {
        let (transport, _) = fixture(vec![resp(
            200,
            r#"{"id":"SEEDED-OTHER-ID","labelIds":["INBOX"],"snippet":"SEEDED-SNIPPET-TEXT"}"#,
        )]);
        let err = apply(&transport, &archive_request()).expect_err("witness fails");
        let rendered = format!("{err:?}");
        assert!(!rendered.contains("SEEDED-OTHER-ID"), "leaked: {rendered}");
        assert!(!rendered.contains("SEEDED-SNIPPET-TEXT"), "leaked: {rendered}");
    }

    // ---- response bounds: TWO caps, separately derived ----

    /// A success body of EXACTLY `len` bytes that also satisfies the witness.
    fn padded_success(len: usize) -> String {
        let head = r#"{"id":"MSG-1","labelIds":["PAD_"#;
        let tail = r#""]}"#;
        let padding = len - head.len() - tail.len();
        format!("{head}{}{tail}", "x".repeat(padding))
    }

    /// An error body of EXACTLY `len` bytes carrying a typed, classifiable reason.
    fn padded_error(len: usize) -> String {
        let head = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions","message":""#;
        let tail = r#""}]}}"#;
        let padding = len - head.len() - tail.len();
        format!("{head}{}{tail}", "x".repeat(padding))
    }

    #[test]
    fn the_error_body_cap_accepts_max_and_refuses_max_plus_one() {
        let at_cap = padded_error(MAX_ERROR_BODY_BYTES);
        assert_eq!(at_cap.len(), MAX_ERROR_BODY_BYTES);
        let (transport, _) = fixture(vec![resp(403, &at_cap)]);
        let err = apply(&transport, &archive_request()).expect_err("403 → Err");
        assert_eq!(
            err,
            GmailError::Forbidden,
            "a body of exactly MAX is accepted and still classified"
        );

        let over = padded_error(MAX_ERROR_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp(403, &over)]);
        let err = apply(&transport, &archive_request()).expect_err("403 → Err");
        assert_eq!(
            err,
            GmailError::Unknown,
            "MAX+1 fails closed BEFORE parsing — the typed reason inside is never consulted"
        );
    }

    #[test]
    fn the_success_body_cap_accepts_max_and_refuses_max_plus_one() {
        let at_cap = padded_success(MAX_SUCCESS_BODY_BYTES);
        assert_eq!(at_cap.len(), MAX_SUCCESS_BODY_BYTES);
        let (transport, _) = fixture(vec![resp(200, &at_cap)]);
        apply(&transport, &archive_request()).expect("a body of exactly MAX is accepted");

        let over = padded_success(MAX_SUCCESS_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp(200, &over)]);
        let err = apply(&transport, &archive_request()).expect_err("MAX+1 → Err");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    /// THE WIRE CAP MUST BE ROUTE-AWARE, NOT ONLY STATUS-AWARE.
    ///
    /// `consume_response` (the LIVE Reqwest tail) resolves its bounded-read ceiling through
    /// `body_cap(status)`, which knows nothing about routes: on a real network call a legitimate
    /// `format=full` / `attachments.get` body is therefore refused at the generic
    /// `MAX_SUCCESS_BODY_BYTES` before [`MAX_BODY_FETCH_WIRE_BYTES`] — the ceiling those two body-fetch
    /// routes are actually contracted to — can apply. This is the boundary function that picks the
    /// cap; the fake rig cannot witness the live client, but the resolver it and the live path
    /// share can be pinned exactly.
    #[test]
    fn the_body_fetch_route_resolves_the_wire_cap_not_the_generic_success_cap() {
        assert_eq!(
            wire_body_cap(WireRoute::BodyFetch, 200),
            MAX_BODY_FETCH_WIRE_BYTES,
            "a 2xx on an S2 body-fetch route must resolve the body-route wire ceiling"
        );
        assert_eq!(
            wire_body_cap(WireRoute::Generic, 200),
            MAX_SUCCESS_BODY_BYTES as u64,
            "a 2xx on every other route keeps the generic success ceiling"
        );
        for status in [403u16, 429, 500] {
            assert_eq!(
                wire_body_cap(WireRoute::BodyFetch, status),
                MAX_ERROR_BODY_BYTES as u64,
                "an ERROR envelope is small on every route — the route axis must not widen it, or \
                 a hostile server hands the body route a 1.4 MB 'error' to parse"
            );
            assert_eq!(
                wire_body_cap(WireRoute::Generic, status),
                MAX_ERROR_BODY_BYTES as u64
            );
        }
        assert!(
            MAX_BODY_FETCH_WIRE_BYTES > MAX_SUCCESS_BODY_BYTES as u64,
            "the whole point of the route axis is that the body ceiling is the LOOSER one"
        );
    }

    /// `AttachmentFetch` rides its OWN wire cap, DISTINCT from `BodyFetch`'s: the
    /// old shared cap was sized for exactly TWO representations, and the attachment route only
    /// ever carries one, so it needed a cap derived from its own (single-representation) worst
    /// case rather than `BodyFetch`'s.
    ///
    /// Note.** Previously `BodyFetch`'s cap was itself a tight two-part
    /// derivation, so the attachment route's own cap came out LARGER — the two were still directly
    /// comparable, single-representation-derived numbers. `BodyFetch`'s cap is now a flat,
    /// generous WHOLE-RESPONSE ceiling (16 MiB) sized to admit an unbounded
    /// number of unselected inline leaves in the SAME response — a different kind of bound
    /// entirely, no longer commensurable with the attachment route's single-representation one.
    /// Which is numerically larger is no longer a meaningful invariant to assert; what matters is
    /// only that each route resolves its OWN named constant, checked below.
    #[test]
    fn the_attachment_fetch_route_resolves_its_own_wire_cap() {
        assert_eq!(
            wire_body_cap(WireRoute::AttachmentFetch, 200),
            MAX_ATTACHMENT_FETCH_WIRE_BYTES,
            "a 2xx on the attachment-fetch route must resolve its own ceiling"
        );
        assert_eq!(
            wire_body_cap(WireRoute::BodyFetch, 200),
            MAX_BODY_FETCH_WIRE_BYTES,
            "a 2xx on the body-fetch route must resolve its own, DISTINCT ceiling"
        );
        for status in [403u16, 429, 500] {
            assert_eq!(
                wire_body_cap(WireRoute::AttachmentFetch, status),
                MAX_ERROR_BODY_BYTES as u64,
                "an ERROR envelope stays small on the attachment route too — the route axis must \
                 never widen it"
            );
        }
    }

    #[test]
    fn an_oversized_body_with_no_content_length_is_refused_by_the_body_check() {
        // Chunked transfer carries NO Content-Length, so the header short-circuit cannot fire and
        // the `body.len()` check is the only line between an unbounded body and the parser.
        // Regression test: `resp()` always advertised the true length, so the header
        // check masked the body check and deleting the body check kept every cap test green.
        let over = padded_error(MAX_ERROR_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp_lying_about_length(403, &over, None)]);
        let err = apply(&transport, &archive_request()).expect_err("403 → Err");
        assert_eq!(
            err,
            GmailError::Unknown,
            "an over-cap chunked error body fails closed unparsed"
        );

        let over = padded_success(MAX_SUCCESS_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp_lying_about_length(200, &over, None)]);
        let err = apply(&transport, &archive_request()).expect_err("MAX+1 → Err");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn an_underreported_content_length_does_not_smuggle_an_oversized_body() {
        // A header that lies SMALL passes the short-circuit; the body the wire actually delivered
        // must still be refused by the byte-count it violates.
        let over = padded_success(MAX_SUCCESS_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp_lying_about_length(200, &over, Some(1))]);
        let err = apply(&transport, &archive_request()).expect_err("MAX+1 → Err");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn an_unconsultable_body_on_a_status_determined_family_keeps_the_status_verdict() {
        // Regression test. The taxonomy never consults the body at 429/5xx —
        // `map_error_response` returns on the status alone — yet an over-cap body made the
        // PLUMBING fail first with a deterministic `Unknown`, downgrading a retryable refusal
        // into a dead-letter. An unreadable body on a COMPLETE non-2xx response falls back to
        // the status family: the same "honest answer for a body we cannot read" rule `entries()`
        // already applies to unparseable JSON.
        let over = "x".repeat(MAX_ERROR_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp(429, &over)]);
        let err = apply(&transport, &archive_request()).expect_err("429 → Err");
        assert_eq!(err, GmailError::RateLimit);
        assert_eq!(classify_gmail_error(&err), FailureKind::Transient);

        let (transport, _) = fixture(vec![resp(503, &over)]);
        let err = apply(&transport, &archive_request()).expect_err("503 → Err");
        assert_eq!(err, GmailError::Backend(503));
        assert_eq!(classify_gmail_error(&err), FailureKind::Transient);

        // The header check obeys the same rule: a lying-huge Content-Length at a transient
        // status refuses the body, not the status's verdict.
        let (transport, _) = fixture(vec![resp_lying_about_length(
            503,
            "{}",
            Some(MAX_ERROR_BODY_BYTES as u64 + 1),
        )]);
        let err = apply(&transport, &archive_request()).expect_err("503 → Err");
        assert_eq!(err, GmailError::Backend(503));

        // …and the fail-closed rows do NOT weaken: 403's status family IS `Unknown`, and a 2xx
        // still cannot witness an applied write from a body it cannot read.
        let (transport, _) = fixture(vec![resp(403, &over)]);
        assert_eq!(
            apply(&transport, &archive_request()).expect_err("403 → Err"),
            GmailError::Unknown
        );
        let over_success = "x".repeat(MAX_SUCCESS_BODY_BYTES + 1);
        let (transport, _) = fixture(vec![resp(200, &over_success)]);
        let err = apply(&transport, &archive_request()).expect_err("200 → Err");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn the_success_cap_accepts_a_maximum_label_shaped_valid_response() {
        // The failure mode a hostile-oversize test cannot see: a cap that rejects LEGITIMATE
        // traffic. `Message.labelIds` returns EVERY label on the message, and a mailbox may hold
        // 10,000 — measured here rather than assumed.
        let labels: Vec<String> = (0..10_000).map(|n| format!("\"Label_{n}\"")).collect();
        let body = format!(r#"{{"id":"MSG-1","labelIds":[{}]}}"#, labels.join(","));
        assert!(
            body.len() > 120_000,
            "a 10,000-label body should be ~126 KiB, measured {}",
            body.len()
        );
        assert!(
            body.len() < MAX_SUCCESS_BODY_BYTES,
            "a legitimate maximum-cardinality response must fit under the cap, measured {}",
            body.len()
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);
        apply(&transport, &archive_request()).expect("a legitimate 10,000-label response applies");
    }

    #[test]
    fn an_over_cap_content_length_is_refused_on_the_header_alone() {
        // The PURE half of the contract: the advertised length alone is enough to refuse, with an
        // empty body — and a length exactly AT the cap is not refused on the header.
        //
        // NOTE what this test does NOT prove, because it structurally cannot: that the real client
        // short-circuits BEFORE reading. `enforce_body_cap` is pure, and `FakeHttp` hands over a
        // body that is already materialized, so both would stay green if the client read first.
        // That claim is owed a real-client witness, and has one — see
        // `an_over_cap_content_length_short_circuits_before_the_real_client_reads_the_body`.
        for (status, cap) in [(200u16, MAX_SUCCESS_BODY_BYTES), (403, MAX_ERROR_BODY_BYTES)] {
            assert!(enforce_body_cap(status, Some(cap as u64 + 1), "").is_err());
            assert!(enforce_body_cap(status, Some(cap as u64), "").is_ok());
            let (transport, _) = fixture(vec![HttpResponse {
                status,
                content_length: Some(cap as u64 + 1),
                body: String::new(),
            }]);
            let err = apply(&transport, &archive_request()).expect_err("over-cap header → Err");
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
        }
    }

    // ---- ambiguous-outcome classification (§3.1c): the stage split + the send predicate ----

    /// The flag combinations measured against the pinned reqwest, used as fixtures so the
    /// predicate is graded against reality rather than against my model of it.
    /// `(label, is_builder, is_certificate, is_connect, is_timeout)`
    const MEASURED_SEND_FAILURES: &[(&str, bool, bool, bool, bool)] = &[
        // Dead port: request=true, connect=true — proven pre-dispatch.
        ("connect refused (dead port)", false, false, true, false),
        // A connect/TLS-handshake stall with a distinct connect timeout: connect=true, timeout=true.
        ("connect stall (TLS handshake)", false, false, true, true),
        // Full POST then EOF: request=true, connect=false, status=None — the bytes landed.
        ("complete POST then close", false, false, false, false),
        // A total-timeout expiry after dispatch: timeout=true, connect=false — temporally opaque.
        ("response-wait timeout", false, false, false, true),
        ("builder (malformed URL)", true, false, false, false),
        ("TLS certificate invalid", false, true, false, false),
    ];

    #[test]
    fn the_send_stage_is_transient_iff_the_failure_is_proven_pre_dispatch() {
        for (label, builder, certificate, connect, timeout) in MEASURED_SEND_FAILURES {
            let verdict = send_stage_verdict(*builder, *certificate, *connect, *timeout);
            let expected = if *connect && !*builder && !*certificate {
                FailureKind::Transient
            } else {
                FailureKind::Deterministic
            };
            assert_eq!(
                classify_gmail_error(&verdict),
                expected,
                "{label} classified wrongly"
            );
        }
    }

    #[test]
    fn a_post_dispatch_no_response_is_deterministic_not_transient() {
        // Regression test for §3.1c: this is the exact measured shape (request fully sent,
        // connection closed, no status) that v2's blanket transport→Transient mapping called
        // retryable — and retrying it re-dispatches a mutation that may already have applied, on an
        // idempotency property nobody has proven. RFC 9110 §9.2.2 forbids exactly that.
        let verdict = send_stage_verdict(false, false, false, false);
        assert_eq!(classify_gmail_error(&verdict), FailureKind::Deterministic);
        assert_eq!(verdict, GmailError::Unknown);
    }

    #[test]
    fn is_timeout_alone_is_never_the_discriminator() {
        // `is_timeout()` is temporally opaque: it cannot tell a connect-phase stall from a
        // post-send response-wait stall. An implementation that keys on it maps the post-dispatch
        // stall to Transient and fails here.
        let post_dispatch_stall = send_stage_verdict(false, false, false, true);
        assert_eq!(
            classify_gmail_error(&post_dispatch_stall),
            FailureKind::Deterministic,
            "a timeout with no proof of pre-dispatch must not be retried"
        );
        // …while a timeout that IS proven to be in the connect phase stays transient.
        let connect_stall = send_stage_verdict(false, false, true, true);
        assert_eq!(classify_gmail_error(&connect_stall), FailureKind::Transient);
    }

    #[test]
    fn the_connect_arm_spells_its_pre_dispatch_proof_in_the_type() {
        // The engine's evidence map used to read `Transport(_) ⇒
        // ProvenNoWire`, and the only thing making that true was THIS function's stage split —
        // a property of one impl behind the PUBLIC `GmailTransport` seam. The claim moved to a
        // typed variant; this transport's behaviour must be BYTE-IDENTICAL, so the assertion is
        // both halves at once: the proving arm names the proving variant, and the evidence it
        // carries above the seam is exactly what it always was.
        for (timeout, expected) in [
            (true, aruna::gmail::GmailTransportError::Timeout),
            (false, aruna::gmail::GmailTransportError::ConnectionReset),
        ] {
            let verdict = send_stage_verdict(false, false, true, timeout);
            assert_eq!(
                verdict,
                GmailError::TransportPreDispatch(expected),
                "the measured `is_connect()` arm IS the proof, so it spells the proven variant"
            );
            assert_eq!(
                aruna::gmail::gmail_effect_evidence(&verdict),
                aruna::EffectEvidence::ProvenNoWire,
                "…and the evidence above the seam is unchanged"
            );
            assert_eq!(classify_gmail_error(&verdict), FailureKind::Transient);
        }
        // The UNPROVEN spelling is what a route that never established the stage answers — the
        // READ route here, and any foreign impl by default. It claims nothing.
        assert_eq!(
            aruna::gmail::gmail_effect_evidence(&read_send_stage_verdict(false, false, true)),
            aruna::EffectEvidence::Indeterminate,
            "a route with no stage split may not inherit a no-wire proof"
        );
    }

    #[test]
    fn builder_and_certificate_errors_are_deterministic_even_when_flagged_connect() {
        // An earlier version wrongly grouped builder with connect. A local misconfiguration retries identically,
        // and a certificate failure persists until the cert or the trust store changes — so both
        // are deterministic even if the error also carries the connect flag.
        for (builder, certificate) in [(true, false), (false, true), (true, true)] {
            let verdict = send_stage_verdict(builder, certificate, true, true);
            assert_eq!(
                classify_gmail_error(&verdict),
                FailureKind::Deterministic,
                "builder={builder} certificate={certificate}"
            );
        }
    }

    #[test]
    fn a_certificate_failure_is_a_proven_pre_wire_refusal() {
        // A residual named earlier, now closed: the
        // transport has `PreWireRefused` for the refusals it can PROVE reached no socket, and
        // scoped it — at `pre_wire_refused`'s doc — to the URL builder and the ADR-P010 gate,
        // "because past [`client.post_json`] the transport cannot prove the request did not
        // land". A rustls certificate-validation failure is the one send-stage failure where
        // that sentence is FALSE and provably so: the handshake is rejected before a single
        // request byte is written, and `is_tls_certificate_error` already identifies it
        // positively — the predicate has taken it as its own dedicated input since v5.
        //
        // Filed under `Unknown` it inherited `Indeterminate`, so a POST-AUTHORIZATION
        // certificate failure settled `ACK_AMBIGUOUS`/`AwaitingAdjudication` — parked for a
        // human decision — over an outcome the transport can prove made no change.
        let verdict = send_stage_verdict(false, true, false, false);
        assert_eq!(
            verdict,
            GmailError::PreWireRefused,
            "a rejected handshake is a PROVEN pre-wire refusal, not the fail-closed bucket"
        );
        assert_eq!(
            aruna::gmail::gmail_effect_evidence(&verdict),
            aruna::EffectEvidence::ProvenNoWire,
            "…so the post-auth verdict row is FAILED_PRE_SEND/proven-no-wire (a deterministic \
             dead-letter), never the ACK_AMBIGUOUS park"
        );
        // …and the RETRY classification is UNCHANGED — the whole point of the second axis being
        // orthogonal. A cert failure persists until the cert or the trust store changes.
        assert_eq!(
            classify_gmail_error(&verdict),
            FailureKind::Deterministic,
            "the evidence axis must not move the taxonomy"
        );
        // The certificate flag OUTRANKS `is_connect`, exactly as before: a handshake rejection
        // that also carries the connect flag is still the proven-no-wire deterministic refusal,
        // never the retryable `Transport` row.
        assert_eq!(send_stage_verdict(false, true, true, true), GmailError::PreWireRefused);
        // The BUILDER arm is deliberately untouched by this change: it shares the arm's `refused()`
        // and stays `Unknown`/`Indeterminate`. It is a different claim (a request that was never
        // constructed) with no measured fixture behind it here, and only the certificate
        // case is scoped here.
        assert_eq!(send_stage_verdict(true, false, false, false), GmailError::Unknown);
    }

    #[test]
    fn the_body_read_stage_is_always_deterministic() {
        // Headers arrived ⇒ the provider processed the request ⇒ the write may have applied.
        assert_eq!(classify_gmail_error(&body_stage_verdict()), FailureKind::Deterministic);
        assert_eq!(body_stage_verdict(), GmailError::Unknown);
    }

    #[test]
    fn the_read_send_stage_is_transient_unless_builder_or_certificate() {
        // The SAME measured flag fixtures, graded by the READ predicate: a GET is safe to repeat
        // (RFC 9110 §9.2.1), so pre-dispatch proof is not required — every network failure is
        // transient, and only the failures an identical retry provably repeats (builder,
        // certificate) stay deterministic.
        for (label, builder, certificate, _connect, timeout) in MEASURED_SEND_FAILURES {
            let verdict = read_send_stage_verdict(*builder, *certificate, *timeout);
            let expected = if *builder || *certificate {
                FailureKind::Deterministic
            } else {
                FailureKind::Transient
            };
            assert_eq!(
                classify_gmail_error(&verdict),
                expected,
                "{label} classified wrongly on the read route"
            );
        }
        // `is_timeout` names WHICH transient variant — its only role, as on the write path.
        assert_eq!(
            read_send_stage_verdict(false, false, true),
            GmailError::Transport(aruna::gmail::GmailTransportError::Timeout)
        );
        assert_eq!(
            read_send_stage_verdict(false, false, false),
            GmailError::Transport(aruna::gmail::GmailTransportError::ConnectionReset)
        );
        // The read body-read stage: an incomplete exchange on a safe GET is transient.
        assert_eq!(
            classify_gmail_error(&read_body_stage_verdict()),
            FailureKind::Transient
        );
    }

    #[test]
    fn the_connect_timeout_is_strictly_shorter_than_the_total_timeout() {
        // Load-bearing ORDERING, not a tuning preference: without it an ordinary pre-dispatch
        // connect failure surfaces as timeout=true, connect=false — and the phase stops being
        // provable, which turns "dead port → Transient" from a contract into a coin flip.
        assert!(
            CONNECT_TIMEOUT < HTTP_TIMEOUT,
            "connect timeout {CONNECT_TIMEOUT:?} must be strictly shorter than {HTTP_TIMEOUT:?}"
        );
    }

    // ---- the real reqwest client (network-error mapping; no external network) ----

    #[test]
    fn connect_takes_no_base_url_and_starts_with_a_closed_gate() {
        // The production entry point: one argument, the token. There is no endpoint selector, so
        // there is no unreachable second variant to maintain either.
        let transport = HttpGmailTransport::connect("test-token").expect("client builds");
        assert_eq!(transport.0.base.as_str(), GMAIL_ENDPOINT);
        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("the default-closed gate refuses");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn a_dead_ephemeral_port_is_a_transient_transport_error() {
        // Exercises the REAL client. A test-OWNED ephemeral port is bound then closed, so the
        // refusal is reliable — never assume a globally-closed port. This is REFUSAL, not a stall:
        // the stall is a different code path and has its own witness.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let transport =
            HttpGmailTransport::connect_for_test_fixture(&format!("http://127.0.0.1:{port}"), "tok")
                .expect("loopback fixture");
        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("dead port → Err");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Transient,
            "a connection REFUSED is proven pre-dispatch: nothing was sent, so a retry is safe"
        );
    }

    #[test]
    fn a_builder_error_is_deterministic() {
        // A malformed URL fails at request-build time — a local misconfiguration that retries
        // identically. Against a blanket transport→Transient mapping this burns the retry budget
        // five times before dead-lettering anyway.
        let client = ReqwestClient::new(BearerToken::new("tok")).expect("client builds");
        let err = client
            .post_json("not a url", &serde_json::json!({}))
            .expect_err("builder error");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn tls_cert_errors_are_detected_but_a_certificate_in_a_url_is_not_a_false_positive() {
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

        for reason in ["Expired", "NotValidForName", "UnknownIssuer"] {
            let cert_fault = Wrap {
                outer: "error sending request for url (https://gmail.googleapis.com/)",
                inner: Leaf(Box::leak(
                    format!("invalid peer certificate: {reason}").into_boxed_str(),
                )),
            };
            assert!(is_tls_certificate_error(&cert_fault), "{reason}");
        }
        // FALSE-POSITIVE GUARD: a RETRYABLE dns failure whose URL merely contains "certificate"
        // must not be dead-lettered. Matching the outer error's Display would trip on the URL.
        let dns_failure = Wrap {
            outer: "error sending request for url (https://certificate.invalid/)",
            inner: Leaf("dns error: No such host is known"),
        };
        assert!(!is_tls_certificate_error(&dns_failure));
        let reset = Wrap {
            outer: "error sending request",
            inner: Leaf("connection reset by peer"),
        };
        assert!(!is_tls_certificate_error(&reset));
    }

    // ============================================================================================
    // REAL-CLIENT loopback witnesses (task 4b — the proofs `FakeHttp` structurally cannot give).
    //
    // A fake has no connection pool and never hands a real `Location` header to a real client, so
    // every fake-driven redirect or pooling assertion passes EVEN IF `redirect::Policy::none()`
    // were accidentally absent. These four drive the actual `ReqwestClient` against a listener this
    // test starts and owns. No external network is touched.
    //
    // ORDERING NOTE: these tests come after the client they drive. A test that
    // can only fail to COMPILE (because the client it drives does not exist yet) is not a
    // right-reason failure.
    //
    // The non-routable-external-address probe (10.255.255.1:80) is deliberately NOT here: a test
    // measured it blackholing correctly on one machine, but it may be routed — or fail instantly —
    // on another, so it could only ever be an optional extra, never the thing a contract rests on.
    // ============================================================================================

    /// How the loopback listener answers.
    #[derive(Clone, Copy)]
    enum Behavior {
        /// A 307 to a different path on the SAME authority — the exact shape that made reqwest
        /// re-POST an authenticated mutation to a server-chosen resource.
        Redirect307,
        /// Read the COMPLETE request, then close without answering.
        CloseAfterCompleteRequest,
        /// Answer with headers promising more body than is sent, then close.
        TruncatedBody,
        /// Accept the TCP connection and never speak — so a TLS handshake can never complete.
        StallForever,
        /// Write an exact, hand-built response and close. The ONLY way to put bytes on the wire
        /// that a `String`-bodied fake structurally cannot represent — invalid UTF-8 in particular.
        Raw(&'static [u8]),
        /// Write response HEADERS advertising a body far over the cap, then WITHHOLD the body and
        /// hold the connection open. A client that consults `Content-Length` first returns at once;
        /// a client that reads first blocks until its own total timeout. That gap is the witness.
        WithholdBodyAfterHeaders(&'static [u8]),
    }

    /// A listener this test owns. Records every request it receives, so a replayed mutation is
    /// visible even when it arrives on a REUSED connection (counting connections alone would miss
    /// it).
    struct Loopback {
        port: u16,
        requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    fn spawn_loopback(behavior: Behavior) -> Loopback {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                if matches!(behavior, Behavior::StallForever) {
                    // Hold the connection open, silently, until the test drops us.
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    continue;
                }
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                // Serve requests on this connection until the peer goes away, so a redirect
                // followed on a REUSED connection would still be recorded.
                loop {
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let request = loop {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break None,
                            Ok(n) => raw.extend_from_slice(&chunk[..n]),
                        }
                        let Some(head_end) = raw
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|p| p + 4)
                        else {
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
                        break Some(String::from_utf8_lossy(&raw).to_string());
                    };
                    let Some(request) = request else { break };
                    recorder.lock().expect("lock").push(request);
                    let written = match behavior {
                        Behavior::Redirect307 => stream.write_all(
                            b"HTTP/1.1 307 Temporary Redirect\r\n\
                              Location: /gmail/v1/users/me/messages/VICTIM/modify?fields=id,labelIds\r\n\
                              Content-Length: 0\r\n\r\n",
                        ),
                        // Headers promise 4096 bytes; five arrive, then the socket closes.
                        Behavior::TruncatedBody => stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                              Content-Length: 4096\r\n\r\nshort",
                        ),
                        Behavior::Raw(bytes) | Behavior::WithholdBodyAfterHeaders(bytes) => {
                            stream.write_all(bytes)
                        }
                        Behavior::CloseAfterCompleteRequest | Behavior::StallForever => break,
                    };
                    if written.is_err() {
                        break;
                    }
                    if matches!(behavior, Behavior::WithholdBodyAfterHeaders(_)) {
                        // The promised body never comes. Hold the socket so a client that reads
                        // before checking the header waits on us rather than seeing a clean EOF.
                        std::thread::sleep(std::time::Duration::from_secs(30));
                        break;
                    }
                    if matches!(behavior, Behavior::TruncatedBody | Behavior::Raw(_)) {
                        break; // close: mid-body for the truncated case, EOF-delimited for Raw
                    }
                }
            }
        });
        Loopback { port, requests }
    }

    /// A real-client transport pointed at a loopback listener, with SHORT timeouts so a stall
    /// witness stays fast. The ordering (connect strictly shorter than total) is what the contract
    /// requires — not the exact seconds.
    fn real_client_fixture(scheme: &str, port: u16) -> GatedTransport<ReqwestClient> {
        real_client_fixture_with_total(scheme, port, std::time::Duration::from_secs(5))
    }

    /// The same, with an explicit TOTAL timeout — for the one witness whose whole discriminator is
    /// the distance between "returned immediately" and "waited out the total timeout".
    fn real_client_fixture_with_total(
        scheme: &str,
        port: u16,
        total: std::time::Duration,
    ) -> GatedTransport<ReqwestClient> {
        let client = ReqwestClient::with_timeouts(
            BearerToken::new("test-token"),
            std::time::Duration::from_secs(1),
            total,
        )
        .expect("client builds");
        GatedTransport::fixture_with(client, &format!("{scheme}://127.0.0.1:{port}"))
            .expect("loopback origin")
    }

    #[test]
    fn a_real_307_produces_exactly_one_request_and_never_replays_the_mutation() {
        // THE proof `FakeHttp` cannot give: a real client, a real `Location`, and the same-authority
        // 307 that reqwest's default policy replays a cloneable mutation body across — to a
        // SERVER-CHOSEN path, which for Gmail is the entire request identity.
        let server = spawn_loopback(Behavior::Redirect307);
        let transport = real_client_fixture("http", server.port);

        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("a 3xx is terminal");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);

        let requests = server.requests.lock().expect("lock").clone();
        assert_eq!(
            requests.len(),
            1,
            "exactly ONE request may reach the server — got {requests:#?}"
        );
        assert!(
            requests[0].contains("/messages/MSG-1/modify"),
            "the one request must be ours: {}",
            requests[0]
        );
        assert!(
            !requests[0].contains("VICTIM"),
            "the server-chosen path must never be requested"
        );
        assert_eq!(
            requests[0].matches("removeLabelIds").count(),
            1,
            "the mutation body must appear exactly once, never replayed"
        );
    }

    #[test]
    fn a_stalled_tls_handshake_is_transient_via_is_connect() {
        // The DISCRIMINATING ambiguity witness, and it must be a STALL rather than a refusal: the
        // dead-port test hits connection-refused, a different code path. The listener accepts the
        // TCP connection and never speaks, so the TLS handshake can never complete — deterministic
        // on every machine, unlike a non-routable address. The connect timeout fires INSIDE the
        // connector, so the failure is provably pre-dispatch and safe to retry.
        let server = spawn_loopback(Behavior::StallForever);
        let transport = real_client_fixture("https", server.port);

        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("a stalled handshake cannot succeed");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Transient,
            "a stall proven to be in the connect phase sent nothing, so a retry cannot duplicate"
        );
        assert!(
            server.requests.lock().expect("lock").is_empty(),
            "nothing was ever sent"
        );
    }

    #[test]
    fn a_complete_post_followed_by_a_close_is_deterministic() {
        // The request bytes LANDED — the server read the whole POST — and then the connection died.
        // We cannot prove the mutation was not applied, so re-dispatching it would gamble on an
        // idempotency property nobody has proven. This is the exact shape v2's blanket
        // transport→Transient mapping called retryable.
        let server = spawn_loopback(Behavior::CloseAfterCompleteRequest);
        let transport = real_client_fixture("http", server.port);

        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("no response");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Deterministic,
            "NOT PROVEN APPLIED must fail closed, never retry"
        );
        let requests = server.requests.lock().expect("lock").clone();
        assert_eq!(requests.len(), 1, "the complete request did reach the server");
        assert!(requests[0].contains("removeLabelIds"));
    }

    // Both bodies are EOF-delimited (`Connection: close`, no `Content-Length`) so the fixture
    // carries no hand-computed byte arithmetic, and both are hostile in exactly ONE way: two
    // invalid UTF-8 bytes inside a field this crate never reads. Repaired to U+FFFD each becomes
    // well-formed JSON — which is the whole defect.

    /// Lossy-repaired, this is the documented back-off family: a malformed 403 becomes RETRYABLE.
    const HOSTILE_UTF8_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":{\"code\":403,\"errors\":[{\"domain\":\"usageLimits\",\"reason\":\"rateLimitExceeded\",\"message\":\"\xFF\xFE\"}]}}";

    /// Lossy-repaired, this satisfies BOTH witness conjuncts for an archive: a malformed 2xx is
    /// recorded as APPLIED.
    const HOSTILE_UTF8_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"MSG-1\",\"labelIds\":[\"IMPORTANT\"],\"snippet\":\"\xFF\xFE\"}";

    /// Invalid UTF-8 at a status the taxonomy decides WITHOUT the body: still a broken body,
    /// but the status verdict must survive it.
    const HOSTILE_UTF8_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"\xFF\xFE\"}";

    #[test]
    fn invalid_utf8_at_a_status_determined_family_keeps_the_transient_verdict() {
        // Regression test. Strict decoding stays — hostile bytes are never
        // repaired into a classifiable document — but the VERDICT for an undecodable body belongs
        // to the status at rows where the body is never consulted. A complete 503 is
        // Backend/Transient with or without a readable body; only where the body MATTERS (the 2xx
        // applied-witness, 403 refinement) does unreadability remain a fail-closed refusal.
        let server = spawn_loopback(Behavior::Raw(HOSTILE_UTF8_503));
        let transport = real_client_fixture("http", server.port);
        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("503 → Err");
        assert_eq!(err, GmailError::Backend(503));
        assert_eq!(classify_gmail_error(&err), FailureKind::Transient);
    }

    #[test]
    fn invalid_utf8_on_the_wire_is_never_repaired_into_a_classifiable_response() {
        // Regression test. `String::from_utf8_lossy` turns
        // hostile wire bytes into U+FFFD *before* JSON parsing, so a body that is not valid UTF-8
        // — and therefore not a valid JSON document — gets silently repaired into one. Both
        // directions of the resulting lie are dangerous, and both are asserted here: a malformed
        // 403 must not become retryable, and a malformed 2xx must not pass the applied-witness.
        //
        // Invalid UTF-8 is not a classification signal; it is a broken response. At 403 the body
        // exists only to REFINE, and a body we cannot read refines nothing — the status family's
        // fail-closed `Unknown` is the verdict. At 2xx the body IS the applied-witness, so
        // undecodability stays a deterministic refusal (the write may have applied, §3.1c).
        let server = spawn_loopback(Behavior::Raw(HOSTILE_UTF8_403));
        let transport = real_client_fixture("http", server.port);
        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("a body that is not valid UTF-8 cannot be classified");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Deterministic,
            "a malformed 403 must not be repaired into the transient back-off family"
        );
        assert_eq!(err, GmailError::Unknown);

        let server = spawn_loopback(Behavior::Raw(HOSTILE_UTF8_200));
        let transport = real_client_fixture("http", server.port);
        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("a body that is not valid UTF-8 cannot witness anything");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Deterministic,
            "a malformed 2xx must not be repaired into an APPLIED witness"
        );
    }

    /// Headers advertising `MAX_SUCCESS_BODY_BYTES + 1`, and no body ever. The literal is pinned to
    /// the constant by an assertion in the test below, so the fixture cannot drift silently.
    const OVERSIZED_LENGTH_HEADERS: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1048577\r\n\r\n";

    #[test]
    fn an_over_cap_content_length_short_circuits_before_the_real_client_reads_the_body() {
        // REPLACES a `FakeHttp`-driven test that could not fail. A fake hands
        // over a body that is ALREADY materialized, so "the body is never read" was asserted
        // against a harness in which reading costs nothing — the test stayed green whether the real
        // client consulted `Content-Length` first or not. The claim is about the REAL client, so
        // only the real client can witness it.
        //
        // The discriminator is time. This server promises 1 MiB + 1 and then sends nothing,
        // holding the connection open. Consulting the header first returns in milliseconds;
        // reading first blocks until the client's own TOTAL timeout, set here to 20s. The
        // assertion is deliberately loose (5s) — it is not a latency benchmark, it is the gap
        // between "did not read" and "waited out a 20-second timeout".
        assert_eq!(
            MAX_SUCCESS_BODY_BYTES + 1,
            1_048_577,
            "the fixture's advertised Content-Length must stay MAX_SUCCESS_BODY_BYTES + 1"
        );
        let server = spawn_loopback(Behavior::WithholdBodyAfterHeaders(OVERSIZED_LENGTH_HEADERS));
        let transport =
            real_client_fixture_with_total("http", server.port, std::time::Duration::from_secs(20));

        let started = std::time::Instant::now();
        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("an over-cap Content-Length fails closed");
        let elapsed = started.elapsed();

        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the over-cap header must short-circuit BEFORE the body is read; \
             this call took {elapsed:?}, i.e. it waited on a body that never came"
        );
        // The request really did reach the server — the refusal is on the response, not a failure
        // to dispatch, so the timing above is measuring the right thing.
        assert_eq!(server.requests.lock().expect("lock").len(), 1);
    }

    #[test]
    fn the_bearer_request_stays_local_under_an_ambient_proxy_env_var() {
        // `.no_proxy()` had NO regression witness: deleting the call left every
        // test green, because nothing in the suite ever set an ambient proxy. reqwest's DEFAULT is
        // to honor `HTTP_PROXY`, so without that call a loopback-approved plaintext request — the
        // one carrying an `Authorization: Bearer` header — egresses through whatever the
        // environment names. The JMAP transport reproduced exactly that exfiltration; this is its
        // missing witness on the Gmail side.
        //
        // TWO servers, both owned by this test: the real fixture, and a decoy standing in for the
        // proxy. The assertion is not "the request succeeded" — it is WHICH socket the credential
        // arrived on.
        //
        // ISOLATION: the proxy env var is process-global, so this test serializes on its own mutex
        // and restores the previous value. It stays correct even if another test builds a client
        // meanwhile — every client in this crate is `.no_proxy()`, which is the property under
        // test.
        static PROXY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        const PROXY_VARS: [&str; 4] = ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
        const CLEARED_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];

        let fixture_server = spawn_loopback(Behavior::CloseAfterCompleteRequest);
        let decoy_proxy = spawn_loopback(Behavior::CloseAfterCompleteRequest);
        let proxy_url = format!("http://127.0.0.1:{}", decoy_proxy.port);

        let _guard = PROXY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore: Vec<(&str, Option<String>)> = PROXY_VARS
            .iter()
            .chain(CLEARED_VARS.iter())
            .map(|name| (*name, std::env::var(name).ok()))
            .collect();
        for name in PROXY_VARS {
            std::env::set_var(name, &proxy_url);
        }
        // An ambient `NO_PROXY=127.0.0.1` defeats this witness WITHOUT `.no_proxy()`: reqwest
        // bypasses the decoy for loopback on the exclusion list alone, so the test stayed green
        // with the call under test deleted (LOW — the witness was environment-
        // dependent). Clearing the exclusion list makes `.no_proxy()` the only thing keeping the
        // credential local; the restore loop above puts both variables back.
        for name in CLEARED_VARS {
            std::env::remove_var(name);
        }
        // Built AFTER the env is set: reqwest reads the proxy environment at client-build time.
        let transport = real_client_fixture("http", fixture_server.port);
        let outcome = transport.modify_labels(&user("me"), &message("MSG-1"), &archive_request());
        for (name, previous) in restore {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        drop(_guard);

        // The listener closes without answering, so the call fails — deterministically, per §3.1c.
        // That is incidental; the credential's destination is the point.
        assert!(outcome.is_err());
        let leaked = decoy_proxy.requests.lock().expect("lock").clone();
        assert!(
            leaked.is_empty(),
            "the authenticated request egressed through the ambient proxy: {leaked:#?}"
        );
        let local = fixture_server.requests.lock().expect("lock").clone();
        assert_eq!(
            local.len(),
            1,
            "the request must have gone straight to the loopback fixture"
        );
        assert!(
            local[0].contains("/messages/MSG-1/modify"),
            "the recorded request must be ours: {}",
            local[0]
        );
        // A proxied request is an absolute-form request line (`POST http://host/path HTTP/1.1`);
        // a direct one is origin-form. Pinning the form catches a proxy that merely happened to be
        // unreachable rather than unused.
        assert!(
            local[0].starts_with("POST /gmail/v1/"),
            "the request must be origin-form, i.e. never sent to a proxy: {}",
            local[0]
        );
        assert!(
            local[0].contains("authorization: Bearer") || local[0].contains("Authorization: Bearer"),
            "the credential must be the thing that stayed local: {}",
            local[0]
        );
    }

    #[test]
    fn response_headers_followed_by_a_truncated_body_are_deterministic() {
        // Headers arrived ⇒ the provider processed the request ⇒ the write may have applied. The
        // body-read STAGE decides this, without inspecting a single flag.
        let server = spawn_loopback(Behavior::TruncatedBody);
        let transport = real_client_fixture("http", server.port);

        let err = transport
            .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
            .expect_err("a truncated body cannot witness anything");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    // ============================================================================================
    // END-TO-END composition — THE ZERO-EDIT-NEUTRALITY WITNESS.
    //
    // The real `GmailConnector`, the real `CommandBus`, the real `SqliteIntentLog`, and the live
    // `HttpGmailTransport` over a synthetic wire. If this stack composes with `crates/aruna/**`
    // byte-identical, the whole thesis — that the seam already fits a live transport —
    // holds. If it needed one edit there, the thesis was false.
    // ============================================================================================

    const SEEDED_USER: &str = "SEEDED-GMAIL-USER-ID";
    const SEEDED_MESSAGE: &str = "SEEDED-GMAIL-MESSAGE-ID";

    struct Seeded;
    impl GmailAccountResolver for Seeded {
        fn resolve_user(&self, _photon_account: &str) -> Option<GmailUserId> {
            Some(user(SEEDED_USER))
        }
    }
    impl GmailMessageRefResolver for Seeded {
        fn resolve_message(
            &self,
            _photon_account: &str,
            _message_ref: &str,
        ) -> Result<Option<GmailMessageId>, LogError> {
            Ok(Some(message(SEEDED_MESSAGE)))
        }
    }

    /// A temp sqlite store minted by the engine's ONE guard (`aruna::test_temp`):
    /// unique per call, the whole store family removed when it drops (this guard used
    /// to remove the main file only, once, errors swallowed), a leak a loud failure.
    type TempDb = aruna::test_temp::TempFile;

    fn temp_db(tag: &str) -> TempDb {
        aruna::test_temp::TempFile::sqlite(&format!("aruna-gmail-e2e-{tag}"))
    }

    /// `execute()` runs the stage-2 capture pipeline (observe → PREPARE → apply) before it
    /// dispatches, so every one of these e2e scripts now performs a READ before its write.
    /// `GmailTransport::message_labels` IS wired on `GatedTransport` (it delegates to the
    /// `users.messages.get` oracle — see the read-route witnesses above), but [`FakeHttp`]
    /// serves GET and POST from ONE queue: letting the capture read consume slots would rewrite
    /// every script's response ledger and change which exchange each assertion grades. So the
    /// decorator answers the READ hermetically and DELEGATES the write to the real
    /// `GatedTransport` under test — these tests keep grading the MUTATION path end to end,
    /// and the live read is graded by its own tests, one path each with no double cover.
    struct HermeticallyObservable<T> {
        inner: T,
        labels: std::collections::BTreeSet<String>,
    }
    impl<T: GmailTransport> GmailTransport for HermeticallyObservable<T> {
        fn modify_labels(
            &self,
            user: &GmailUserId,
            message: &GmailMessageId,
            request: &GmailModifyRequest,
        ) -> Result<(), GmailError> {
            self.inner.modify_labels(user, message, request)
        }
        // The three write routes DELEGATE, like `modify_labels` — only the read is hermetic.
        fn modify_labels_observed(
            &self,
            user: &GmailUserId,
            message: &GmailMessageId,
            request: &GmailModifyRequest,
        ) -> Result<std::collections::BTreeSet<String>, GmailError> {
            self.inner.modify_labels_observed(user, message, request)
        }
        fn trash_message(
            &self,
            user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<std::collections::BTreeSet<String>, GmailError> {
            self.inner.trash_message(user, message)
        }
        fn untrash_message(
            &self,
            user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<std::collections::BTreeSet<String>, GmailError> {
            self.inner.untrash_message(user, message)
        }
        fn message_labels(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<std::collections::BTreeSet<String>, GmailError> {
            Ok(self.labels.clone())
        }
    }

    #[allow(clippy::type_complexity)]
    fn e2e_bus(
        responses: Vec<HttpResponse>,
        db: &TempDb,
    ) -> aruna::CommandBus<
        aruna::SqliteIntentLog,
        GmailConnector<HermeticallyObservable<GatedTransport<FakeHttp>>, Seeded, Seeded>,
    > {
        let transport = GatedTransport::fixture_with(
            FakeHttp::new(responses),
            "http://127.0.0.1:18080",
        )
        .expect("loopback origin");
        aruna::CommandBus::new(
            aruna::SqliteIntentLog::open(db).expect("open sqlite"),
            GmailConnector::new(
                HermeticallyObservable {
                    inner: transport,
                    labels: ["INBOX".to_string()].into_iter().collect(),
                },
                Seeded,
                Seeded,
            ),
        )
    }

    fn archive_command(key: &str) -> Command {
        Command::new(
            key,
            "photon-acct",
            Facet::Mail,
            Action::Archive {
                message_ref: "msg-1".to_string(),
            },
        )
    }

    #[test]
    fn e2e_an_applied_archive_lands_applied_in_the_durable_log() {
        use aruna::IntentLog;
        let db = temp_db("applied");
        let body = format!(r#"{{"id":"{SEEDED_MESSAGE}","labelIds":["IMPORTANT"]}}"#);
        let mut bus = e2e_bus(vec![resp(200, &body)], &db);

        bus.execute(&archive_command("k-applied")).expect("archive applies");

        assert_eq!(
            bus.log().get("k-applied").expect("read").expect("row").status,
            aruna::IntentStatus::Applied
        );
    }

    #[test]
    fn e2e_a_deterministic_provider_rejection_dead_letters_immediately() {
        use aruna::IntentLog;
        let db = temp_db("deterministic");
        let body = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions"}]}}"#;
        let mut bus = e2e_bus(vec![resp(403, body)], &db);

        let result = bus.execute(&archive_command("k-forbidden"));
        assert!(matches!(result, Err(aruna::ExecuteError::Connector(_))));
        assert_eq!(
            bus.log().get("k-forbidden").expect("read").expect("row").status,
            aruna::IntentStatus::Failed,
            "a deterministic refusal must not burn the retry budget"
        );
    }

    #[test]
    fn e2e_a_persistent_transient_stays_pending_then_dead_letters_at_the_retry_cap() {
        use aruna::IntentLog;
        let db = temp_db("transient");
        // One response per attempt: the initial execute plus RETRY_CAP - 1 recovery sweeps.
        let responses = (0..aruna::RETRY_CAP).map(|_| resp(429, "")).collect();
        let mut bus = e2e_bus(responses, &db);

        assert!(matches!(
            bus.execute(&archive_command("k-throttled")),
            Err(aruna::ExecuteError::Connector(_))
        ));
        assert_eq!(
            bus.log().get("k-throttled").expect("read").expect("row").status,
            aruna::IntentStatus::Pending,
            "one transient failure is retryable, not a dead-letter"
        );

        for _ in 0..(aruna::RETRY_CAP - 1) {
            bus.recover().expect("recovery sweep runs");
        }

        assert_eq!(
            bus.log().get("k-throttled").expect("read").expect("row").status,
            aruna::IntentStatus::Failed,
            "a transient failure retried past RETRY_CAP dead-letters"
        );
    }

    #[test]
    fn e2e_no_provider_id_reaches_a_surfaced_error_or_a_durable_row() {
        use aruna::IntentLog;
        let db = temp_db("confinement");
        // A hostile-shaped 403 carrying provider text AND the seeded ids.
        let body = format!(
            r#"{{"error":{{"code":403,"message":"user {SEEDED_USER} may not modify {SEEDED_MESSAGE}","errors":[{{"domain":"global","reason":"insufficientPermissions","message":"SEEDED-PROVIDER-PROSE"}}]}}}}"#
        );
        let mut db_bus = e2e_bus(vec![resp(403, &body)], &db);

        let err = db_bus
            .execute(&archive_command("k-confinement"))
            .expect_err("403 → Err");
        let surfaced = format!("{err:?}");
        for seed in [SEEDED_USER, SEEDED_MESSAGE, "SEEDED-PROVIDER-PROSE"] {
            assert!(!surfaced.contains(seed), "{seed} leaked into the error: {surfaced}");
        }

        let intent = db_bus.log().get("k-confinement").expect("read").expect("row");
        // NARROWED (design §7a): `intents.frozen_basis` EXISTS to
        // carry provider-native identity — that column is the pre-state capture's whole
        // point. Confinement is a property of the NEUTRAL vocabulary (command, action,
        // envelope, and every surfaced error), which is what the arms below assert; the
        // native ids are asserted to live EXACTLY in the basis and provider PROSE nowhere at
        // all (the basis is built from resolved ids, never from response text).
        let durable = format!("{:?}", intent.command);
        for seed in [SEEDED_USER, SEEDED_MESSAGE, "SEEDED-PROVIDER-PROSE"] {
            assert!(!durable.contains(seed), "{seed} leaked into the durable row: {durable}");
        }
        let basis = intent
            .frozen_basis
            .expect("stage 2 freezes a basis at admission");
        assert_eq!(
            basis.native_resource_key,
            aruna::prestate::native_resource_key(
                aruna::gmail::GMAIL_KEY_PROVIDER,
                &[SEEDED_USER, SEEDED_MESSAGE],
            )
        );
        let basis_text = format!("{basis:?}");
        assert!(
            !basis_text.contains("SEEDED-PROVIDER-PROSE"),
            "provider PROSE must never reach the basis: {basis_text}"
        );
    }

    // ============================================================================================
    // The single-message placement read (design §3, §6 fixture matrix). Every closed
    // class carries a test: delete the check and the test fails.
    // ============================================================================================

    use aruna::read_model::{Placement, ProviderMessageId, ProviderPlacement};

    /// Drive the read route over the open-gate loopback fixture harness (same shape as `apply`).
    fn read(transport: &GatedTransport<FakeHttp>) -> Result<LabelIds, GmailError> {
        transport.get_message_labels(&user("me"), &message("MSG-1"))
    }

    // ---- §6.8: the request-shape witness (both composed parameters + path-id validation) ----

    #[test]
    fn the_get_message_url_carries_both_composed_parameters() {
        // The ENTIRE final URL at the byte: `format=minimal` (an omitted format defaults to
        // `full`, PROHIBITED under the recommended gmail.metadata scope — the route would fail
        // under its own credential) AND the write path's field mask (the
        // same mask). A set_query-style overwrite that drops either is the exact deletion mechanism
        // — this test fails if a builder change drops, overwrites, or omits either.
        let url = get_message_url(&endpoint(), &user("me"), &message("MSG-1")).expect("valid ids");
        assert_eq!(
            url.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/MSG-1?format=minimal&fields=id,labelIds"
        );
        let query = url.query().expect("a query");
        assert!(query.contains("format=minimal"), "the scope-compatibility half: {query}");
        assert!(query.contains("fields=id,labelIds"), "the field-mask half: {query}");
    }

    #[test]
    fn read_route_metacharacter_ids_keep_the_route_shape_and_both_parameters() {
        // The write route's shape discipline, carried: hostile ids may not shift the route or
        // strip either query parameter.
        for hostile in ["M/../../evil", "M?alt=media", "M#frag", "M%2f..%2fevil"] {
            let url = get_message_url(&endpoint(), &user("me"), &message(hostile))
                .expect("opaque ids are transmitted, not rejected");
            let segments: Vec<&str> = url.path_segments().expect("segments").collect();
            assert_eq!(segments.len(), 6, "id {hostile:?} produced {segments:?}");
            assert_eq!(segments[0..3], ["gmail", "v1", "users"]);
            assert_eq!(segments[4], "messages");
            assert_eq!(url.query(), Some("format=minimal&fields=id,labelIds"));
            assert_eq!(url.host_str(), Some("gmail.googleapis.com"));
        }
    }

    #[test]
    fn read_route_path_ids_are_refused_before_any_url_or_socket_exists() {
        // `validate_path_id` on BOTH read-route ids (§3.1): a dot-segment userId or
        // message id is refused pre-URL, with zero wire calls.
        for (bad_user, bad_message) in [("", "MSG-1"), (".", "MSG-1"), ("..", "MSG-1"), ("me", ".."), ("me", "."), ("me", "")] {
            let by_fn = get_message_url(&endpoint(), &user(bad_user), &message(bad_message))
                .expect_err("invalid path ids must be refused");
            assert_eq!(classify_gmail_error(&by_fn), FailureKind::Deterministic);
            let (transport, probe) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
            let err = transport
                .get_message_labels(&user(bad_user), &message(bad_message))
                .err()
                .expect("must be refused");
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
            assert!(
                probe.calls().is_empty(),
                "userId={bad_user:?} id={bad_message:?} reached the wire"
            );
        }
    }

    // ---- §6.1: the id-echo (mis-routing check, not a truth/freshness proof) ----

    #[test]
    fn a_read_answered_with_a_different_message_id_fails_closed() {
        // Before the check existed: a 2xx for the WRONG message must never feed a placement.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"OTHER-MESSAGE","labelIds":["INBOX"]}"#)]);
        let err = read(&transport)
            .err()
            .expect("a wrong-id response must be refused");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    // ---- §6.2: absent labelIds is TYPED Absent, distinct from Present([]) at the type level ----

    #[test]
    fn absent_label_ids_is_typed_absent_distinct_from_empty_and_both_derive_archive() {
        // ProtoJSON omits empty repeated fields, so omission is the normal empty encoding: Absent
        // derives like Present([]) today — but the distinction is TYPED, so a flip-to-error
        // costs one match arm, gated on a live probe (design §3.2).
        let absent = parse_minimal_message(r#"{"id":"MSG-1"}"#, &message("MSG-1"))
            .expect("absent labelIds parses");
        assert!(matches!(absent, LabelIds::Absent), "omission must be TYPED as Absent");
        let empty = parse_minimal_message(r#"{"id":"MSG-1","labelIds":[]}"#, &message("MSG-1"))
            .expect("empty labelIds parses");
        assert!(
            matches!(empty, LabelIds::Present(ref v) if v.is_empty()),
            "a literal [] must be TYPED as Present(vec![])"
        );
        assert_eq!(placement_from_labels(&absent).unwrap(), Placement::Archive);
        assert_eq!(placement_from_labels(&empty).unwrap(), Placement::Archive);
    }

    // ---- the LIVE observe seam — `GmailTransport::message_labels` ----

    #[test]
    fn message_labels_delegates_to_the_live_read_oracle_and_needs_no_write_gate() {
        // The aruna `Connector::observe` half is no longer the trait's DEFAULT = REFUSE on this
        // transport: it delegates to the SHIPPED `users.messages.get` read oracle (the
        // minimal read). The gate is CLOSED here (a production transport) — a READ carries no
        // write authority and must not need it, so a refusal would be a bug.
        let fake = FakeHttp::new(vec![resp(
            200,
            r#"{"id":"MSG-1","labelIds":["INBOX","UNREAD"]}"#,
        )]);
        let probe = fake.clone();
        let transport = GatedTransport::production_with(fake);
        let labels = transport
            .message_labels(&user("me"), &message("MSG-1"))
            .expect("a read must not be gated by the destructive-write gate");
        assert_eq!(
            labels,
            ["INBOX".to_string(), "UNREAD".to_string()]
                .into_iter()
                .collect::<std::collections::BTreeSet<String>>()
        );
        assert_eq!(probe.calls().len(), 1, "exactly one read reached the wire");
    }

    #[test]
    fn message_labels_surfaces_the_read_oracles_refusals_verbatim() {
        // No fabricated "no labels": every failure the read oracle classifies (id-echo
        // mismatch, malformed body, provider status) propagates as a normalized GmailError —
        // an observation that cannot be taken is never reported as an empty label set.
        for (status, body) in [
            (403, r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions"}]}}"#),
            (200, r#"{"id":"OTHER-MESSAGE","labelIds":["INBOX"]}"#),
            (200, "not json"),
        ] {
            let (transport, probe) = fixture(vec![resp(status, body)]);
            let err = transport
                .message_labels(&user("me"), &message("MSG-1"))
                .err()
                .unwrap_or_else(|| panic!("status {status} body {body:?} must not yield labels"));
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
            // NON-VACUITY: the refusal must be the ORACLE's verdict on a real exchange, not
            // the trait's blanket DEFAULT = REFUSE (which never touches the wire).
            assert_eq!(
                probe.calls().len(),
                1,
                "status {status} body {body:?} never reached the read oracle"
            );
        }
    }

    #[test]
    fn message_labels_reports_an_omitted_label_array_as_the_empty_set() {
        // ProtoJSON omits empty repeated fields, so `Absent` is the normal empty encoding —
        // the SAME reading `placement_from_labels` already ships (design §3.2). This is a
        // provider ANSWER of "no labels", not a missing observation, and the typed distinction
        // stays one match arm away if a live probe overturns it.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1"}"#)]);
        assert!(transport
            .message_labels(&user("me"), &message("MSG-1"))
            .expect("an omitted array parses")
            .is_empty());
    }

    // ---- §6.3: malformed bodies fail closed, never a placement; duplicates are NOT rejected ----

    #[test]
    fn malformed_read_bodies_fail_closed_never_a_placement() {
        for body in [
            "not json",
            "",
            r#"{"labelIds":["INBOX"]}"#,          // missing id
            r#"{"id":null,"labelIds":["INBOX"]}"#, // null id
            // A literal `labelIds: null` is REFUSED — the reused LabelIds deserializer
            // hard-errors on null by deliberate construction (the documented fail-closed
            // strictness DEVIATION from ProtoJSON null-as-unset; the shared deserializer is
            // untouched here).
            r#"{"id":"MSG-1","labelIds":null}"#,
            r#"{"id":"MSG-1","labelIds":"INBOX"}"#, // present but not an array
        ] {
            let (transport, _) = fixture(vec![resp(200, body)]);
            let err = read(&transport)
                .err()
                .unwrap_or_else(|| panic!("body {body:?} must not yield labels"));
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic, "body {body:?}");
        }
    }

    #[test]
    fn duplicate_label_array_members_are_not_rejected() {
        // Surplus normalization is deliberately absent — duplicate array members cannot alter a
        // set-membership verdict, so they pass through.
        let doubled = parse_minimal_message(
            r#"{"id":"MSG-1","labelIds":["INBOX","INBOX"]}"#,
            &message("MSG-1"),
        )
        .expect("duplicate members are harmless");
        assert_eq!(placement_from_labels(&doubled).unwrap(), Placement::Inbox);
        let sent_twice = parse_minimal_message(
            r#"{"id":"MSG-1","labelIds":["SENT","SENT"]}"#,
            &message("MSG-1"),
        )
        .expect("duplicate members are harmless");
        assert_eq!(placement_from_labels(&sent_twice).unwrap(), Placement::Archive);
    }

    // ---- §6.4: the derivation table (total partition, honest arms, exact case) ----

    #[test]
    fn out_of_model_label_sets_are_a_typed_error_in_any_combination() {
        // §3.3 row 1: DRAFT — drafts are not archivable mail; the model has no belief for them.
        // ANY combination, regardless of INBOX and of the placement labels TRASH/SPAM,
        // fails closed rather than "correcting" a belief to a lie. (Through M1 this list also
        // carried TRASH/SPAM-only sets; those are now in the model —
        // `placement_derives_trash_over_spam_over_inbox_and_only_draft_is_out_of_model`.)
        for labels in [
            vec!["DRAFT"],
            vec!["DRAFT", "INBOX"],
            vec!["DRAFT", "TRASH"],
            vec!["SPAM", "DRAFT", "INBOX"],
        ] {
            let set = LabelIds::Present(labels.iter().map(|s| s.to_string()).collect());
            let err = placement_from_labels(&set)
                .err()
                .unwrap_or_else(|| panic!("{labels:?} must be out-of-model"));
            assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic, "{labels:?}");
        }
    }

    #[test]
    fn inbox_membership_is_positive_evidence_and_noise_labels_are_orthogonal() {
        for labels in [vec!["INBOX"], vec!["INBOX", "UNREAD", "STARRED", "CATEGORY_PERSONAL"]] {
            let set = LabelIds::Present(labels.iter().map(|s| s.to_string()).collect());
            assert_eq!(placement_from_labels(&set).unwrap(), Placement::Inbox, "{labels:?}");
        }
    }

    #[test]
    fn everything_else_lands_in_the_named_model_compression_arm() {
        // The else-arm IS Gmail's own semantics (archived = the absence of INBOX, labels guide) —
        // but it is an else-arm and documented as such: SENT-only, CHAT-only, user-label-only.
        for labels in [vec!["SENT"], vec!["CHAT"], vec!["Label_23"], vec!["SENT", "UNREAD"]] {
            let set = LabelIds::Present(labels.iter().map(|s| s.to_string()).collect());
            assert_eq!(placement_from_labels(&set).unwrap(), Placement::Archive, "{labels:?}");
        }
    }

    #[test]
    fn label_matching_is_exact_and_case_sensitive() {
        // A hostile lowercase "inbox" is NOT `INBOX` — it falls to the else arm, never Inbox; a
        // lowercase "trash" is NOT `TRASH` — it is placement-orthogonal, never Trash.
        let hostile_inbox = LabelIds::Present(vec!["inbox".to_string()]);
        assert_eq!(placement_from_labels(&hostile_inbox).unwrap(), Placement::Archive);
        let hostile_trash = LabelIds::Present(vec!["trash".to_string()]);
        assert_eq!(placement_from_labels(&hostile_trash).unwrap(), Placement::Archive);
    }

    #[test]
    fn placement_derives_trash_over_spam_over_inbox_and_only_draft_is_out_of_model() {
        let present = |labels: &[&str]| LabelIds::Present(labels.iter().map(|s| s.to_string()).collect());
        assert_eq!(placement_from_labels(&present(&["TRASH", "INBOX"])).unwrap(), Placement::Trash, "TRASH over everything");
        assert_eq!(placement_from_labels(&present(&["SPAM", "INBOX"])).unwrap(), Placement::Spam);
        assert_eq!(
            placement_from_labels(&present(&["TRASH", "SPAM"])).unwrap(),
            Placement::Trash,
            "TRASH over SPAM — a NAMED derivation choice of ours (#75 S1 plan B5), not a provider claim"
        );
        assert_eq!(placement_from_labels(&present(&["INBOX"])).unwrap(), Placement::Inbox);
        assert_eq!(placement_from_labels(&present(&["CATEGORY_PROMOTIONS"])).unwrap(), Placement::Archive);
        assert!(placement_from_labels(&present(&["DRAFT"])).is_err(), "DRAFT stays out of model");
        assert!(placement_from_labels(&present(&["DRAFT", "INBOX"])).is_err());
        assert!(placement_from_labels(&present(&["DRAFT", "TRASH"])).is_err(), "DRAFT dominates every placement label");
        assert_eq!(OUT_OF_MODEL_LABELS, ["DRAFT"]);
    }

    #[test]
    fn every_placement_variant_has_a_label_that_derives_it_generated_from_the_enum() {
        // A label with a Placement is never out-of-model — both directions, from the enum.
        for p in Placement::ALL {
            let label = match p {
                Placement::Inbox => "INBOX",
                Placement::Archive => "CATEGORY_UPDATES",
                Placement::Trash => "TRASH",
                Placement::Spam => "SPAM",
            };
            assert!(!OUT_OF_MODEL_LABELS.contains(&label), "{label} has a placement, so it is in-model");
            assert_eq!(placement_from_labels(&LabelIds::Present(vec![label.to_string()])).unwrap(), p);
        }
    }

    // ---- §6.5: 403 reuse — ONE classifier, not two ----

    #[test]
    fn the_read_route_reuses_the_write_paths_403_disambiguation() {
        let (transport, _) = fixture(vec![resp(
            403,
            r#"{"error":{"code":403,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#,
        )]);
        let err = read(&transport).err().expect("403 → Err");
        assert_eq!(err, GmailError::RateLimit);
        assert_eq!(classify_gmail_error(&err), FailureKind::Transient);

        let (transport, _) = fixture(vec![resp(
            403,
            r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions"}]}}"#,
        )]);
        let err = read(&transport).err().expect("403 → Err");
        assert_eq!(err, GmailError::Forbidden);
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    // ---- the read route carries no write authority (§3.1: reads do not pass the gate) ----

    #[test]
    fn the_read_route_does_not_pass_the_destructive_write_gate() {
        // A production transport's gate is CLOSED — the write refuses with zero wire calls, while
        // the READ on the same transport dispatches: the read route builder takes no gate token,
        // by construction (JMAP precedent: email_get_mailbox_ids).
        let fake = FakeHttp::new(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        let probe = fake.clone();
        let transport = GatedTransport::production_with(fake);
        assert!(
            apply(&transport, &archive_request()).is_err(),
            "the closed gate must refuse the write"
        );
        assert!(probe.calls().is_empty(), "the refused write must not touch the wire");
        let labels = read(&transport).expect("the read passes no gate");
        assert!(matches!(labels, LabelIds::Present(ref v) if v == &["INBOX"]));
        assert_eq!(probe.calls().len(), 1, "the read dispatched");
    }

    // ---- §6.10: high-cardinality VALID response over the cap — the named availability residual ----

    #[test]
    fn a_schema_conforming_read_body_over_the_success_cap_fails_closed_typed() {
        // Gmail permits 10,000 labels and publishes no label-id maxLength: 10,000 unique 128-byte
        // ids ≈ 1.31 MiB > the 1 MiB cap (inherited from the write shell). The ACCEPTED
        // availability residual, made visible for the read oracle too: typed over-cap refusal,
        // never an unbounded buffer.
        let labels: Vec<String> = (0..10_000).map(|n| format!("\"{n:0>128}\"")).collect();
        let body = format!(r#"{{"id":"MSG-1","labelIds":[{}]}}"#, labels.join(","));
        assert!(
            body.len() > MAX_SUCCESS_BODY_BYTES,
            "the fixture must exceed the cap, measured {}",
            body.len()
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);
        let err = read(&transport).err().expect("over-cap → Err");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    // ---- the neutral seam impl (§3.4) ----

    #[test]
    fn gmail_provider_placement_implements_the_neutral_seam_over_the_fixture() {
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        let provider = GatedProviderPlacement::new(&transport, user("me"));
        let placement = provider
            .fetch_placement("photon-acct", &ProviderMessageId("MSG-1".to_string()))
            .expect("a fixture INBOX read derives Inbox");
        assert_eq!(placement, Placement::Inbox);

        // A TRASH read now derives a belief through the same seam.
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["TRASH"]}"#)]);
        let provider = GatedProviderPlacement::new(&transport, user("me"));
        let placement = provider
            .fetch_placement("photon-acct", &ProviderMessageId("MSG-1".to_string()))
            .expect("a fixture TRASH read derives Trash");
        assert_eq!(placement, Placement::Trash);

        // An out-of-model truth surfaces as a normalized deterministic ConnectorError — through
        // the existing classifier, id-free. (DRAFT now; through M1 this was TRASH.)
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["DRAFT"]}"#)]);
        let provider = GatedProviderPlacement::new(&transport, user("me"));
        let err = provider
            .fetch_placement("photon-acct", &ProviderMessageId("MSG-1".to_string()))
            .expect_err("DRAFT is out-of-model");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert!(
            !format!("{err:?}").contains("DRAFT"),
            "no provider label text may ride out through the seam"
        );
    }

    // ---- the REAL client over the loopback fixture ----

    /// A live-shape MINIMAL 200 for `MSG-1`, EOF-delimited like the other raw fixtures.
    const MINIMAL_OK_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"MSG-1\",\"labelIds\":[\"INBOX\"]}";

    #[test]
    fn the_public_placement_reader_reads_over_the_real_client_loopback_fixture() {
        // `connect_for_test_fixture` + the REAL `ReqwestClient` against a listener this test owns
        // — the proof the FakeHttp fixture structurally cannot give for the READ dispatch: the
        // actual GET on the wire carries the composed route (BOTH query parameters), origin-form,
        // authenticated — through the PUBLIC `GmailProviderPlacement` facade.
        let server = spawn_loopback(Behavior::Raw(MINIMAL_OK_200));
        let transport = HttpGmailTransport::connect_for_test_fixture(
            &format!("http://127.0.0.1:{}", server.port),
            "test-token",
        )
        .expect("loopback fixture");
        let provider = GmailProviderPlacement::new(&transport, user("me"));

        let placement = provider
            .fetch_placement("photon-acct", &ProviderMessageId("MSG-1".to_string()))
            .expect("a live-shape INBOX read derives Inbox");
        assert_eq!(placement, Placement::Inbox);

        let requests = server.requests.lock().expect("lock").clone();
        assert_eq!(requests.len(), 1, "exactly one GET dispatched");
        assert!(
            requests[0]
                .starts_with("GET /gmail/v1/users/me/messages/MSG-1?format=minimal&fields=id,labelIds"),
            "the GET must carry the composed route with BOTH parameters: {}",
            requests[0]
        );
        assert!(
            requests[0].contains("Bearer test-token"),
            "the read must be authenticated: {}",
            requests[0]
        );
    }

    /// A live-shape field-masked 200 for a TRASHED `MSG-1` — what the `trash` route reads back.
    const TRASHED_OK_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"MSG-1\",\"labelIds\":[\"TRASH\"]}";

    #[test]
    fn the_real_client_posts_trash_and_untrash_with_no_body_on_the_wire() {
        // What the FakeHttp verb log cannot grade: that the REAL client's `post_empty`
        // puts NO body on the wire. Google's `users.messages.trash` and `users.messages.untrash`
        // references both say "The request body must be empty." The earlier shape serialized `{}`,
        // which arrives here as the two-byte body `{}` (the failure this test was written against).
        for (trash, response, route) in [
            (true, TRASHED_OK_200, "trash"),
            (false, MINIMAL_OK_200, "untrash"),
        ] {
            let server = spawn_loopback(Behavior::Raw(response));
            let transport = real_client_fixture("http", server.port);
            let applied = if trash {
                transport.trash_message(&user("me"), &message("MSG-1"))
            } else {
                transport.untrash_message(&user("me"), &message("MSG-1"))
            };
            applied.unwrap_or_else(|e| panic!("{route} applies over the real client: {e:?}"));

            let requests = server.requests.lock().expect("lock").clone();
            assert_eq!(requests.len(), 1, "{route}: exactly one POST dispatched");
            let request = &requests[0];
            assert!(
                request.starts_with(&format!(
                    "POST /gmail/v1/users/me/messages/MSG-1/{route}?fields=id,labelIds HTTP/1.1\r\n"
                )),
                "{route}: the dedicated route, origin-form: {request}"
            );
            assert!(
                request.contains("Bearer test-token"),
                "{route}: the write must be authenticated: {request}"
            );
            let (head, body) = request
                .split_once("\r\n\r\n")
                .expect("the recorder captured a complete request head");
            assert_eq!(body, "", "{route}: NO body may reach the wire: {request}");
            assert!(
                !head.to_ascii_lowercase().contains("content-type"),
                "{route}: nothing was serialized, so no content type may be declared: {head}"
            );
            // The empty body is DECLARED, not left implicit. Google's
            // front end answers a bodiless POST that carries no length header with 411
            // (googleworkspace/cli#182). The earlier `post_empty` sent none: this assertion's
            // failed on a head of only the request line, `authorization`, `accept` and `host`.
            assert!(
                head.to_ascii_lowercase().contains("content-length: 0"),
                "{route}: a bodiless POST must declare `Content-Length: 0`: {head}"
            );
        }
    }

    // ---- the read route's OWN failure mapping: a GET is safe to repeat (RFC 9110 §9.2.1) ----

    #[test]
    fn a_read_get_answered_by_a_post_dispatch_close_is_transient() {
        // Regression test, at the write route's own measured shape: the
        // complete request LANDED and the connection died without a response. On the WRITE route
        // that is deterministic by design — re-dispatching a mutation that may
        // already have applied is the duplicate §3.1c exists to prevent. A GET carries no mutation:
        // it is SAFE (RFC 9110 §9.2.1), so repeating it can duplicate nothing, and the same wire
        // shape is a recoverable network failure. Reusing the write predicate here dead-lettered
        // every read whose response was lost.
        let server = spawn_loopback(Behavior::CloseAfterCompleteRequest);
        let transport = real_client_fixture("http", server.port);
        let err = transport
            .get_message_labels(&user("me"), &message("MSG-1"))
            .err()
            .expect("no response");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Transient,
            "a lost response on a safe GET must retry, never dead-letter"
        );
        assert_eq!(
            server.requests.lock().expect("lock").len(),
            1,
            "the complete GET did reach the server"
        );
    }

    #[test]
    fn a_read_get_response_wait_timeout_is_transient() {
        // The post-dispatch stall: plaintext, so the TCP connect succeeds instantly (no handshake
        // to stall) and the request dispatches — then the server never answers and the TOTAL
        // timeout fires. `is_timeout=true, is_connect=false`, the exact temporally-opaque shape
        // the write predicate must refuse to retry — and the read route must retry.
        let server = spawn_loopback(Behavior::StallForever);
        let transport =
            real_client_fixture_with_total("http", server.port, std::time::Duration::from_secs(2));
        let err = transport
            .get_message_labels(&user("me"), &message("MSG-1"))
            .err()
            .expect("a stalled response cannot succeed");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Transient,
            "a response-wait timeout on a safe GET must retry, never dead-letter"
        );
    }

    #[test]
    fn a_read_get_that_dies_mid_body_is_transient() {
        // The body-read stage on the read route: headers arrived, the body was promised, and the
        // socket died mid-body. On the write route that stage is deterministic WITHOUT a predicate
        // (the provider processed the mutation). On a safe GET the broken exchange proves only
        // that the NETWORK failed — re-requesting the read duplicates nothing.
        let server = spawn_loopback(Behavior::TruncatedBody);
        let transport = real_client_fixture("http", server.port);
        let err = transport
            .get_message_labels(&user("me"), &message("MSG-1"))
            .err()
            .expect("a truncated body cannot yield labels");
        assert_eq!(
            classify_gmail_error(&err),
            FailureKind::Transient,
            "a mid-body death on a safe GET must retry, never dead-letter"
        );
    }

    #[test]
    fn the_write_posts_deterministic_fallback_is_unchanged_by_the_read_mapping() {
        // THE GUARD: the read route earning its own transient mapping must not move the write
        // route one byte — the SAME wire shapes stay deterministic through `modify_labels`,
        // because there they mean NOT PROVEN APPLIED (§3.1c). A shared mapper
        // that drifted transient-ward for both routes fails here.
        for behavior in [Behavior::CloseAfterCompleteRequest, Behavior::TruncatedBody] {
            let server = spawn_loopback(behavior);
            let transport = real_client_fixture("http", server.port);
            let err = transport
                .modify_labels(&user("me"), &message("MSG-1"), &archive_request())
                .expect_err("the broken exchange fails the write");
            assert_eq!(
                classify_gmail_error(&err),
                FailureKind::Deterministic,
                "the write route's NOT-PROVEN-APPLIED fallback must stay deterministic"
            );
        }
    }

    // ---- the reconcile battery, instantiated over the Gmail impl (fixture) ----

    /// Log + store + a poisoned/seeded projection over one temp DB, with a terminal (Applied)
    /// intent governing `m1` — the aruna reconcile battery's setup, for the fixture (the
    /// live_divergence.rs poisoned-projection pattern without the live transport).
    fn reconcile_setup(
        tag: &str,
        optimistic: Placement,
    ) -> (TempDb, aruna::SqliteIntentLog, aruna::message_store::SqliteMessageStore) {
        use aruna::IntentLog;
        let db = temp_db(tag);
        let mut log = aruna::SqliteIntentLog::open(&db).expect("open log");
        let cmd = Command::new(
            aruna::derive_idempotency_key("acct", &Facet::Mail, "m1-logical"),
            "acct",
            Facet::Mail,
            Action::Archive {
                message_ref: "m1".into(),
            },
        );
        // Admission freezes a native basis. This fixture seeds the
        // governing intent directly to set up a poisoned projection — it never dispatches —
        // so it supplies a well-formed placeholder basis rather than a live resolution.
        log.record(
            &cmd,
            &aruna::prestate::FrozenBasis {
                // Through the ONE encoding authority, like the
                // connector this placeholder stands in for.
                native_resource_key: aruna::prestate::native_resource_key(
                    aruna::gmail::GMAIL_KEY_PROVIDER,
                    &["me", "MSG-1"],
                ),
                touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                    .into_iter()
                    .collect(),
                // Stage 3: the forward target vector `A`, keyed identically to
                // `touched_atoms` (FrozenBasis::validate enforces the equality both ways).
                // Archive's target is "no longer in INBOX".
                atom_targets: [("membership:INBOX".to_string(), false)]
                    .into_iter()
                    .collect(),
                role_bindings: std::collections::BTreeMap::new(),
                freshness: aruna::prestate::Freshness::ImmutableConstants,
            },
        )
        .expect("record");
        log.set_status_forced(&cmd.idempotency_key, aruna::IntentStatus::Applied)
            .expect("applied");
        let mut store = aruna::message_store::SqliteMessageStore::open(&db).expect("open store");
        store
            .record_optimistic_placement(
                "acct",
                "m1",
                &ProviderMessageId("MSG-1".to_string()),
                optimistic,
            )
            .expect("seed projection");
        // The guard FIRST: a tuple pattern's bindings drop right to left, so `(_db, log, store)`
        // closes both handles before the guard deletes. It was LAST — `_db` dropped first, under
        // the open store.
        (db, log, store)
    }

    #[test]
    fn reconcile_through_gmail_corrects_a_poisoned_projection() {
        use aruna::message_store::Corrected;
        // The projection wrongly believes Archive; Gmail fixture truth says INBOX.
        let (_db, log, mut store) = reconcile_setup("gmail-poisoned", Placement::Archive);
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        let provider = GatedProviderPlacement::new(&transport, user("me"));
        let out = aruna::reconcile::reconcile_divergence(&log, &mut store, &provider, "acct", "m1")
            .expect("reconcile through the Gmail impl");
        assert_eq!(out, Corrected { changed: true });
        assert_eq!(store.placement("acct", "m1").unwrap(), Some(Placement::Inbox));
    }

    #[test]
    fn reconcile_through_gmail_converged_is_a_noop() {
        use aruna::message_store::Corrected;
        let (_db, log, mut store) = reconcile_setup("gmail-converged", Placement::Inbox);
        let (transport, _) = fixture(vec![resp(200, r#"{"id":"MSG-1","labelIds":["INBOX"]}"#)]);
        let provider = GatedProviderPlacement::new(&transport, user("me"));
        let out = aruna::reconcile::reconcile_divergence(&log, &mut store, &provider, "acct", "m1")
            .expect("reconcile through the Gmail impl");
        assert_eq!(out, Corrected { changed: false });
    }

    #[test]
    fn reconcile_through_gmail_out_of_model_truth_fails_loud_never_corrects_to_a_lie() {
        // §3.3: a reconcile against a draft message surfaces ReconcileError::Provider — LOUD,
        // rather than "correcting" the belief. The named time-unbounded residual until the
        // substrate gives it a terminal state. (Through M1 an externally-TRASHED message took
        // this arm too; it now has a belief —
        // `reconcile_through_gmail_corrects_an_externally_trashed_or_spammed_belief`.)
        for body in [
            r#"{"id":"MSG-1","labelIds":["DRAFT"]}"#,
            r#"{"id":"MSG-1","labelIds":["DRAFT","INBOX"]}"#,
        ] {
            let (_db, log, mut store) = reconcile_setup("gmail-out-of-model", Placement::Archive);
            let (transport, _) = fixture(vec![resp(200, body)]);
            let provider = GatedProviderPlacement::new(&transport, user("me"));
            let err = aruna::reconcile::reconcile_divergence(&log, &mut store, &provider, "acct", "m1")
                .expect_err("out-of-model truth must fail loud");
            assert!(
                matches!(err, aruna::reconcile::ReconcileError::Provider(_)),
                "expected ReconcileError::Provider, got {err:?}"
            );
            // The belief was NOT clobbered.
            assert_eq!(store.placement("acct", "m1").unwrap(), Some(Placement::Archive));
        }
    }

    #[test]
    fn reconcile_through_gmail_corrects_an_externally_trashed_or_spammed_belief() {
        use aruna::message_store::Corrected;
        // TRASH/SPAM are in model, so a reconcile whose provider read derives one of them
        // CORRECTS the belief (the store round-trips the new durable tokens) instead of failing
        // loud. Scope: `reconcile_divergence`'s own gate still applies — `reconcile_setup` seeds
        // the terminal governing intent it requires.
        for (body, truth) in [
            (r#"{"id":"MSG-1","labelIds":["TRASH"]}"#, Placement::Trash),
            (r#"{"id":"MSG-1","labelIds":["SPAM","CATEGORY_PROMOTIONS"]}"#, Placement::Spam),
        ] {
            let (_db, log, mut store) = reconcile_setup("gmail-s1-in-model", Placement::Archive);
            let (transport, _) = fixture(vec![resp(200, body)]);
            let provider = GatedProviderPlacement::new(&transport, user("me"));
            let out = aruna::reconcile::reconcile_divergence(&log, &mut store, &provider, "acct", "m1")
                .expect("an in-model truth reconciles");
            assert_eq!(out, Corrected { changed: true }, "{truth:?}");
            assert_eq!(store.placement("acct", "m1").unwrap(), Some(truth));
        }
    }

    // ---- plaintext credentials (fixture path only) ----

    #[test]
    fn plaintext_is_permitted_only_to_an_actual_loopback_host() {
        for ok in [
            "http://127.0.0.1:18080",
            "http://localhost:18080/",
            "http://[::1]:18080",
            "https://gmail.googleapis.com/",
            "https://anything.example",
        ] {
            assert!(require_tls_or_local(ok).is_ok(), "{ok} should be allowed");
        }
        for refused_url in [
            "http://mail.example.com",
            "http://8.8.8.8",
            "http://fixture.localhost:18080",
            "http://evil.test",
            "localhost:18080", // schemeless — not https, not local http
            "not a url",
        ] {
            let err = require_tls_or_local(refused_url).expect_err("must refuse");
            assert_eq!(
                classify_gmail_error(&err),
                FailureKind::Deterministic,
                "{refused_url} must be refused deterministically, before any socket"
            );
        }
    }

    // ============================================================================================
    // the inbox-page listing + on-demand body read. Driven over
    // the same open-gate loopback `fixture()` harness the read route above uses (these are READS
    // and never require the destructive-write gate).
    // ============================================================================================

    /// RFC 4648 §4 Table 1 — the STANDARD alphabet in VALUE order, read at rfc-editor.org. Every
    /// base64 spelling built in the tests below is INDEXED out of this table, never hand-computed
    /// from an ASCII range: a wrong symbol then shows up as a wrong character, not as silence.
    const BASE64_STANDARD_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// RFC 4648 §5 Table 2 — the URL-and-filename-safe alphabet. Identical to the table above
    /// except at values 62 and 63, which is the whole of the difference between the two decoders.
    const BASE64URL_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// RFC 4648 §5 base64url (unpadded) ENCODE — the test-side mirror of [`base64url_decode`],
    /// used only to build fixture JSON bodies. A round-trip through both directions is itself
    /// evidence the decoder is not accidentally testing its own bugs.
    fn b64url_encode(input: &str) -> String {
        b64url_encode_bytes(input.as_bytes())
    }

    /// The same encoder over RAW BYTES — fixtures for the charset tests carry byte
    /// sequences that are deliberately not valid UTF-8, so they cannot arrive as a `&str`.
    fn b64url_encode_bytes(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] = BASE64URL_ALPHABET;
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(n & 0x3F) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn base64url_encode_decode_round_trips_including_every_padding_remainder() {
        for sample in ["", "a", "ab", "abc", "hello world", "€ multi-byte €"] {
            let encoded = b64url_encode(sample);
            assert!(!encoded.contains('='), "unpadded: {encoded:?}");
            let decoded = base64url_decode(&encoded).expect("decodes");
            assert_eq!(String::from_utf8(decoded).unwrap(), sample);
        }
    }

    /// The SAME encoder, PADDED to a whole 4-character group — the RFC 4648 §4/§5
    /// canonical form. ⚠ **CORRECTED:** the previous wording claimed the API docs
    /// "show the unpadded shape". They show neither — the Gmail discovery document (rev 20260907)
    /// describes `MessagePartBody.data` as a base64url string and contains ZERO occurrences of
    /// "padding" or "unpadded" across 217,687 bytes. Two sibling sites in this file already
    /// carried that correction; this one was missed. ⚠ **Silence is not licence, though:** RFC
    /// 2047 §5 requires a `B` encoded-word's encoded text to have a length divisible by four, so
    /// header spelling IS constrained even where the Gmail reference is silent — a separate
    /// question from whether a decoder must REJECT non-zero pad bits, which it does not by itself
    /// mandate. The "observed to carry" half was an observation claim with no cited witness and is
    /// withdrawn.
    fn b64url_encode_padded(input: &str) -> String {
        let mut encoded = b64url_encode(input);
        while !encoded.len().is_multiple_of(4) {
            encoded.push('=');
        }
        encoded
    }

    /// Regression test: TERMINAL padding decodes; everything else about the old refusal
    /// stands. A `=`-padded `body.data` is the same bytes in the canonical RFC 4648 spelling, and
    /// refusing it turned an ordinary message into a deterministic body failure the user could do
    /// nothing about.
    #[test]
    fn base64url_decode_accepts_terminal_padding_and_still_refuses_everything_else() {
        for sample in ["", "a", "ab", "abc", "hello world", "€ multi-byte €"] {
            let padded = b64url_encode_padded(sample);
            assert!(padded.len().is_multiple_of(4), "the fixture is canonically padded: {padded:?}");
            let decoded = base64url_decode(&padded)
                .unwrap_or_else(|_| panic!("terminal padding must decode: {padded:?}"));
            assert_eq!(String::from_utf8(decoded).unwrap(), sample);
        }
        // The unpadded shape Gmail documents keeps decoding — this is a WIDENING, not a swap.
        assert_eq!(base64url_decode(&b64url_encode("abc")).unwrap(), b"abc".to_vec());

        // INTERIOR and over-long padding stay refused: those are malformed, not a spelling.
        assert!(base64url_decode("AA=A").is_err(), "interior padding is malformed");
        assert!(base64url_decode("A===").is_err(), "three pad characters is malformed");
        assert!(base64url_decode("====").is_err(), "pad-only is malformed");
        assert!(
            base64url_decode("AAAA=").is_err(),
            "padding a COMPLETE group is a length-congruence violation"
        );
        assert!(
            base64url_decode("AA=").is_err(),
            "one pad after a 2-character remainder does not reach a whole group"
        );
        assert!(base64url_decode("not base64!!").is_err());
        assert!(base64url_decode("A").is_err(), "a single leftover sextet cannot be a byte");
    }

    // ---- the STANDARD alphabet direct test, and §3.5 pinned ----

    /// `base64_standard_decode` had **no direct unit test**: every exercise of it ran
    /// indirectly through [`decode_rfc2047`], so a change to the standard-alphabet arm could only
    /// be caught by a header-decoding assertion several layers up. These are the RFC 4648 §10
    /// test vectors for the standard alphabet, read at rfc-editor.org.
    #[test]
    fn base64_standard_decode_matches_the_rfc_4648_section_10_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            let decoded = base64_standard_decode(encoded)
                .unwrap_or_else(|_| panic!("RFC 4648 §10 vector must decode: {encoded:?}"));
            assert_eq!(
                String::from_utf8(decoded).expect("utf8"),
                plain,
                "vector {encoded:?}"
            );
        }
        // The two alphabets stay DISTINCT: 62/63 are `+`/`/` here, so the url-safe
        // symbols are not merely a different spelling — they are outside this alphabet.
        assert!(
            base64_standard_decode("Zm-=").is_err(),
            "`-` is not in the standard alphabet"
        );
        assert!(
            base64_standard_decode("Zm_=").is_err(),
            "`_` is not in the standard alphabet"
        );
        // …AND THE MIRROR, which was missing.
        // Only the standard direction was asserted, so a mutant that widened the
        // URL-SAFE table to accept `+` and `/` survived all 288 tests. Correct values for the
        // symbols an alphabet PERMITS never prove the symbols it FORBIDS are still refused: that
        // is a separate property and it needs its own witness. All three positions are covered
        // because a symbol can be refused in the tail and admitted mid-group, or the reverse.
        for forbidden in ['+', '/'] {
            assert!(
                base64url_decode(&format!("Zm{forbidden}=")).is_err(),
                "`{forbidden}` is not in the url-safe alphabet (tail position)"
            );
            assert!(
                base64url_decode(&format!("{forbidden}AAA")).is_err(),
                "`{forbidden}` is not in the url-safe alphabet (leading position)"
            );
            assert!(
                base64url_decode(&format!("AA{forbidden}A")).is_err(),
                "`{forbidden}` is not in the url-safe alphabet (interior position)"
            );
        }

        // THE ACTUAL COMPLEMENT. WARNING: the four assertions above are an ENUMERATION, and an
        // enumeration is an EDGE however long the list. The earlier version called itself a
        // "complement" while testing exactly four symbols -- which is the error that a
        // complement test exists to catch. A mutant
        // adding `b'.' => Ok(0)` to either `sextet` would leave every value assertion AND every
        // exclusion assertion above green while malformed input silently decoded.
        //
        // So: sweep the WHOLE ASCII space and require that every byte NOT in the alphabet is
        // refused -- "reject everything EXCEPT the 64 table symbols", as one sweep rather than a
        // list of interesting characters. `=` is skipped because it is PADDING, a separate
        // grammar handled by the pad rules above, not an alphabet member. The interior position
        // is used because it is non-padding: a symbol there contributes all six of its bits, so
        // nothing can hide.
        for (label, alphabet, decode) in [
            (
                "standard",
                BASE64_STANDARD_ALPHABET,
                base64_standard_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
            (
                "url-safe",
                BASE64URL_ALPHABET,
                base64url_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
        ] {
            let mut refused = 0usize;
            for byte in 0u8..128 {
                if alphabet.contains(&byte) || byte == b'=' {
                    continue;
                }
                let spelling = format!("AA{}A", byte as char);
                assert!(
                    decode(&spelling).is_err(),
                    "{label}: byte {byte:#04x} ({:?}) is NOT in this alphabet and must be refused                      at a non-padding position",
                    byte as char
                );
                refused += 1;
            }
            // 128 ASCII bytes - 64 alphabet symbols - 1 pad character.
            assert_eq!(
                refused, 63,
                "{label}: the complement over ASCII is 63 bytes; got {refused}"
            );
        }
        // Non-ASCII is covered by construction rather than by iteration: every byte of a
        // multi-byte UTF-8 sequence is >= 0x80, no alphabet holds such a byte, and `sextet`'s
        // final arm is `_ => Err(())`. One case is asserted so the reasoning carries a witness.
        //
        // WARNING -- the fixture LENGTH is load-bearing, and the first version of this assertion
        // got it wrong. `é` is TWO UTF-8 bytes (0xC3 0xA9), so "AAéA" is FIVE bytes: not a
        // multiple of four, which the single-leftover-sextet rule refuses on its own. That
        // assertion passed no matter what the alphabet did -- it could not fail on the property it
        // names, the same defect as in the interior-`=` guard's comment. "AéA" is
        // FOUR bytes (41 C3 A9 41), a COMPLETE group, so refusal has to come from the alphabet.
        assert!(
            base64_standard_decode("AéA").is_err(),
            "a non-ASCII byte is not in the standard alphabet (4-byte group, so the length rule              cannot be what refuses it)"
        );
        assert!(
            base64url_decode("AéA").is_err(),
            "a non-ASCII byte is not in the url-safe alphabet (4-byte group, so the length rule              cannot be what refuses it)"
        );
    }

    /// ⚠ **PINS CURRENT BEHAVIOUR — this is not an assertion that the behaviour is desirable**.
    ///
    /// RFC 4648 §3.5 requires conforming ENCODERS to zero the unused bits of a partial final
    /// quantum, but says decoders "**MAY** chose to reject an encoding if the pad bits have not
    /// been set to zero". This decoder does not, so one payload tail has several accepted
    /// spellings. That is PERMITTED lenience, not a conformance violation, and refusing instead
    /// would turn a sloppily-encoded-but-legitimate subject line into a raw `=?UTF-8?B?…?=` token
    /// because [`decode_rfc2047`] fails open.
    ///
    /// The lenience is safe only while **nothing keys on the ENCODED text** — traced repo-wide at
    /// `main @ e06b325`: every decode site drops the encoded string, dedupe is on the Gmail
    /// message id or the local `message_ref`, and no digest covers a `data` field. That answers
    /// ONE of the three abuses §12 names for non-significant bits (bypassing string equality);
    /// the other two — leaking information, triggering implementation problems — are discharged
    /// in the docblock on [`base64_decode_with_alphabet`], not here. **The day a consumer keys on
    /// the encoded form this test must be INVERTED to a refusal** — which is the point of pinning
    /// it: the flip becomes a deliberate edit to a failing test instead of a silent accident.
    ///
    /// Both the PADDED and the UNPADDED spelling of every tail are scanned, because no source
    /// settles which one arrives. The Gmail API reference describes `body.data` and attachment
    /// `data` only as a base64url encoded string and says nothing about padding either way, while
    /// `base64url_decode_accepts_terminal_padding_and_still_refuses_everything_else` records that
    /// refusing PADDED `data` turned ordinary messages into deterministic body failures. So the
    /// pin is the union: a change that rejected non-zero pad bits on only one of the two paths
    /// would break real Gmail input while the other path's assertions still passed.
    #[test]
    fn pad_bits_are_currently_ignored_in_both_alphabets_pinning() {
        // ONE scan per alphabet, over the WHOLE 64-symbol table and over BOTH the padded and the
        // unpadded spelling of each tail. Scanning is what makes "all sixteen" / "all four" a
        // MEASUREMENT; the earlier shape asserted `.len()` on a list written three lines above,
        // which passes no matter what the decoder does.
        //
        // The expected byte deliberately restates the tail arm's own formula. What is asserted is
        // what that formula OMITS — any reference to the low bits of the final sextet — not the
        // shift constants, which the RFC 4648 §10 vectors above pin independently.
        for (label, alphabet, decode) in [
            (
                "standard",
                BASE64_STANDARD_ALPHABET,
                base64_standard_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
            (
                "url-safe",
                BASE64URL_ALPHABET,
                base64url_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
        ] {
            let value_of = |symbol: u8| {
                alphabet.iter().position(|&c| c == symbol).expect("symbol is in the table") as u8
            };
            let (z, m) = (value_of(b'Z'), value_of(b'm'));

            // ONE-byte tail `Z?` / `Z?==`: the 2-arm emits `(s0 << 2) | (s1 >> 4)`, so the low
            // FOUR bits of the second sextet never reach the output.
            let mut spellings_of_f = Vec::new();
            for (value, &symbol) in alphabet.iter().enumerate() {
                let expected = vec![(z << 2) | (value as u8 >> 4)];
                for spelling in [format!("Z{}", symbol as char), format!("Z{}==", symbol as char)] {
                    let decoded = decode(&spelling)
                        .unwrap_or_else(|_| panic!("{label} {spelling:?} decodes today"));
                    assert_eq!(
                        decoded, expected,
                        "{label} 1-byte tail {spelling:?}: the 2-arm keeps only the top two bits \
                         of sextet {value}"
                    );
                    if decoded == b"f".to_vec() {
                        spellings_of_f.push(spelling);
                    }
                }
            }
            // Counted from what the DECODER returned, not from the length of a literal. It is a
            // restatement of the scan above rather than an independent pin — the per-symbol
            // assertions already determine it — but it is the number the docblock on
            // [`base64_decode_with_alphabet`] quotes, so witness and claim are checked against
            // each other here instead of by eye.
            assert_eq!(
                spellings_of_f.len(),
                32,
                "{label}: `f` has 32 accepted spellings today (16 symbols, padded and unpadded); \
                 got {spellings_of_f:?}"
            );

            // TWO-byte tail `Zm?` / `Zm?=`: the 3-arm's second byte is `(s1 << 4) | (s2 >> 2)`, so
            // the low TWO bits of the third sextet never reach the output.
            let mut spellings_of_fo = Vec::new();
            for (value, &symbol) in alphabet.iter().enumerate() {
                let expected = vec![(z << 2) | (m >> 4), (m << 4) | (value as u8 >> 2)];
                for spelling in [format!("Zm{}", symbol as char), format!("Zm{}=", symbol as char)]
                {
                    let decoded = decode(&spelling)
                        .unwrap_or_else(|_| panic!("{label} {spelling:?} decodes today"));
                    assert_eq!(
                        decoded, expected,
                        "{label} 2-byte tail {spelling:?}: the 3-arm keeps only the top four bits \
                         of sextet {value}"
                    );
                    if decoded == b"fo".to_vec() {
                        spellings_of_fo.push(spelling);
                    }
                }
            }
            assert_eq!(
                spellings_of_fo.len(),
                8,
                "{label}: `fo` has 8 accepted spellings today (4 symbols, padded and unpadded); \
                 got {spellings_of_fo:?}"
            );
        }

        // The canonical spelling and a non-canonical sibling are INDISTINGUISHABLE after decode —
        // stated as an assertion so the malleability property itself is on the record, not just
        // implied by the rows above.
        assert_eq!(
            base64_standard_decode("Zg==").expect("canonical"),
            base64_standard_decode("Zv==").expect("non-canonical"),
            "canonical and non-canonical pad bits are indistinguishable after decode"
        );

        // THE TAIL AFTER A COMPLETE GROUP — the dimension every scan above misses.
        // Everything above varies
        // the final symbol while holding the decoder's PRECEDING state fixed at empty: the
        // spellings are `Z?` and `Zm?`, standalone tails. So a change that refuses non-zero pad
        // bits ONLY when output already holds a complete group is invisible to all of it — that
        // mutant survived the entire suite. Exhaustive over the symbol dimension is not
        // exhaustive over the state the symbol arrives in.
        for (label, decode) in [
            (
                "standard",
                base64_standard_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
            ("url-safe", base64url_decode as fn(&str) -> Result<Vec<u8>, ()>),
        ] {
            // One-byte tail after one complete group. `Zg`/`Zv` differ only in discarded pad
            // bits, so both spellings must still reach the same bytes WITH a group in front.
            for spelling in ["TWFuZv==", "TWFuZv", "QUJDZv==", "QUJDZv"] {
                let canonical = spelling.replace('v', "g");
                assert_eq!(
                    decode(spelling)
                        .unwrap_or_else(|_| panic!("{label} {spelling:?} decodes today")),
                    decode(&canonical)
                        .unwrap_or_else(|_| panic!("{label} {canonical:?} decodes today")),
                    "{label}: a non-canonical ONE-byte tail behind a complete group is still                      accepted and still indistinguishable ({spelling:?} vs {canonical:?})"
                );
            }
            // Two-byte tail after one complete group — the 3-arm's two discarded bits.
            for spelling in ["TWFuZm9=", "TWFuZm9"] {
                assert_eq!(
                    decode(spelling)
                        .unwrap_or_else(|_| panic!("{label} {spelling:?} decodes today")),
                    b"Manfo".to_vec(),
                    "{label}: a TWO-byte tail behind a complete group decodes today                      ({spelling:?})"
                );
            }
        }
    }

    /// The two symbols that DEFINE each alphabet, pinned where their VALUE is load-bearing. Before this test, every appearance of `+`, `/`, `-` and `_` in this file
    /// was the THIRD sextet of a 2-byte tail (`Zm+=`, `Zm/=`, `Zm-=`, `Zm_=` and their unpadded
    /// twins) — a position whose low TWO bits are pad bits the decoder discards. Values 60, 61,
    /// 62 and 63 share their top four bits, so every one of those assertions passes UNCHANGED if
    /// `+` and `/` are swapped with each other, or if either is mapped to 60 or 61. The
    /// round-trip test does not cover the gap either: none of its six samples encodes to a sextet
    /// of 62 or 63, so `b64url_encode` never emits a `-` or a `_` for it to feed back in.
    ///
    /// A FULL four-character group has no pad bits — all 24 bits reach the output — so there each
    /// symbol's exact value is witnessed. That is what this test uses.
    #[test]
    fn every_alphabet_value_is_pinned_where_it_is_load_bearing() {
        /// RFC 4648 §9's packing of one full group, as a single 24-bit quantity rather than as the
        /// decoder's three byte-shifts — an independent statement of the layout, not a copy of the
        /// code under test.
        fn group_bytes(values: [u8; 4]) -> Vec<u8> {
            let n = ((values[0] as u32) << 18)
                | ((values[1] as u32) << 12)
                | ((values[2] as u32) << 6)
                | (values[3] as u32);
            vec![(n >> 16) as u8, (n >> 8) as u8, n as u8]
        }

        // `A` is value 0 in both tables, so the symbol under test is the only non-zero
        // contribution: the decoded bytes ARE its value, shifted into its position.
        for (label, alphabet, decode) in [
            (
                "standard",
                BASE64_STANDARD_ALPHABET,
                base64_standard_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
            (
                "url-safe",
                BASE64URL_ALPHABET,
                base64url_decode as fn(&str) -> Result<Vec<u8>, ()>,
            ),
        ] {
            for value in 0u8..64 {
                let symbol = alphabet[value as usize] as char;
                for position in 0..4usize {
                    let mut spelling = ['A'; 4];
                    spelling[position] = symbol;
                    let mut values = [0u8; 4];
                    values[position] = value;
                    let encoded: String = spelling.iter().collect();
                    assert_eq!(
                        decode(&encoded)
                            .unwrap_or_else(|_| panic!("a full group decodes: {encoded:?}")),
                        group_bytes(values),
                        "{label} `{symbol}` must carry value {value} at position {position} of a \
                         full group ({encoded:?})"
                    );
                }
            }
        }

        // The two alphabets carry the SAME values at 62/63 in DIFFERENT spellings — RFC 4648 §5's
        // "technically identical except for the 62nd and 63rd character", as an assertion. Note
        // what this one can and cannot do: it fails if 62/63 are swapped in ONE wrapper and PASSES
        // if both are swapped together. The positional loop above is what catches a matched swap.
        assert_eq!(
            base64_standard_decode("+/+/").expect("standard full group"),
            base64url_decode("-_-_").expect("url-safe full group"),
            "`+`/`/` and `-`/`_` are the same values 62/63 in two spellings"
        );

        // The RFC's own worked example (§9): 0x14fb9c03d97e encodes to `FPucA9l+` — a `+` in the
        // last sextet of a full group, taken from the primary source rather than constructed here.
        let rfc_4648_9_bytes = vec![0x14u8, 0xfb, 0x9c, 0x03, 0xd9, 0x7e];
        assert_eq!(
            base64_standard_decode("FPucA9l+").expect("RFC 4648 §9 illustration"),
            rfc_4648_9_bytes,
            "the RFC's own illustration decodes to the bytes it illustrates"
        );
        assert_eq!(
            base64url_decode("FPucA9l-").expect("RFC 4648 §9 illustration, url-safe spelling"),
            rfc_4648_9_bytes,
            "the same bytes, with value 62 spelled `-`"
        );
    }

    // ---- RFC 2047 encoded-word decoding ----

    /// Regression test: a `B`-encoded UTF-8 Subject arrives as MIME wire syntax and must
    /// decode to the sender's actual (Japanese) text, never stay `=?UTF-8?B?...?=` verbatim.
    #[test]
    fn decode_rfc2047_decodes_a_base64_encoded_utf8_word() {
        // "こんにちは" (konnichiwa), standard base64 (NOT base64url — this token would fail to
        // decode at all through base64url_decode, since std base64 can carry `+`/`/`).
        let raw = "=?UTF-8?B?44GT44KT44Gr44Gh44Gv?=";
        assert_eq!(decode_rfc2047(raw), "こんにちは");
    }

    /// Regression test: a `Q`-encoded Latin-1 display name: `_` must decode to a literal
    /// space (never `%20`-style, never left as an underscore), and `=XX` hex escapes decode against
    /// the DECLARED charset (ISO-8859-1), reusing [`decode_part_bytes`]'s own charset policy.
    #[test]
    fn decode_rfc2047_decodes_a_quoted_printable_latin1_word_with_underscores_as_spaces() {
        let raw = "=?ISO-8859-1?Q?Andr=E9_M=FCller?=";
        assert_eq!(decode_rfc2047(raw), "André Müller");
    }

    /// Regression test: two adjacent encoded words, separated only by linear whitespace,
    /// concatenate WITHOUT that whitespace (RFC 2047 §6.2): `"AB"`, never `"A  B"`.
    #[test]
    fn decode_rfc2047_concatenates_adjacent_encoded_words_dropping_the_separating_whitespace() {
        let raw = "=?UTF-8?B?QQ==?=  =?UTF-8?B?Qg==?=";
        assert_eq!(decode_rfc2047(raw), "AB");
    }

    /// The other side of the adjacency rule: whitespace that is NOT sandwiched between two
    /// successfully-decoded words (here: plain text on one side) is left exactly where it was.
    #[test]
    fn decode_rfc2047_keeps_whitespace_that_does_not_separate_two_encoded_words() {
        let raw = "Team =?UTF-8?B?QQ==?=";
        assert_eq!(decode_rfc2047(raw), "Team A");
    }

    /// Regression test: a malformed token (an encoding letter that is neither `B` nor
    /// `Q`) is FAIL-OPEN: the original substring survives verbatim, never an error and never a
    /// dropped header.
    #[test]
    fn decode_rfc2047_leaves_a_malformed_token_verbatim() {
        let raw = "=?UTF-8?X?not-a-real-encoding?=";
        assert_eq!(decode_rfc2047(raw), raw, "an unrecognized encoding letter is not decodable");
    }

    /// The same fail-open contract for a token whose PAYLOAD fails to decode against its own
    /// encoding (invalid base64) — the token stays verbatim rather than losing bytes or panicking.
    #[test]
    fn decode_rfc2047_leaves_a_token_with_undecodable_base64_payload_verbatim() {
        let raw = "=?UTF-8?B?not valid base64!!?=";
        assert_eq!(decode_rfc2047(raw), raw);
    }

    /// Ordinary, unencoded text passes through completely unchanged — the decoder must never touch
    /// a header that carries no encoded-word at all.
    #[test]
    fn decode_rfc2047_is_a_no_op_on_plain_text() {
        assert_eq!(decode_rfc2047("Ordinary Subject Line"), "Ordinary Subject Line");
        assert_eq!(decode_rfc2047(""), "");
    }

    /// Integration test — wired into `fetch_header_summary`: the Subject header
    /// decodes, and the From header's DISPLAY NAME decodes while the ADDRESS itself is left
    /// untouched (encoded-words are only ever valid in the display-name portion of a From header).
    #[test]
    fn list_inbox_page_decodes_rfc2047_encoded_words_in_subject_and_from_display_name() {
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let m1_body = r#"{"id":"M1","internalDate":"1700000000000","labelIds":["INBOX"],
            "payload":{"headers":[
                {"name":"From","value":"=?UTF-8?B?44GT44KT44Gr44Gh44Gv?= <sender@example.com>"},
                {"name":"Subject","value":"=?ISO-8859-1?Q?Andr=E9_M=FCller?="}]}}"#;
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, m1_body)]);

        let ListedPage { rows: page, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a well-formed page must map");

        assert_eq!(page.len(), 1);
        assert_eq!(page[0].from_name, "こんにちは", "the display name must be RFC 2047 decoded");
        assert_eq!(
            page[0].from_addr, "sender@example.com",
            "the address itself is never RFC 2047 decoded"
        );
        assert_eq!(page[0].subject, "André Müller", "the Subject must be RFC 2047 decoded");
    }

    // ---- provenance-aware encoded-word decoding, through the real
    // listing route (the `from_name` this transport publishes) ----

    /// One message whose raw `From` value is `from`, listed through `list_inbox_page`: the
    /// `from_name` the page publishes. The JSON is built by `serde_json`, so a `"` in `from`
    /// reaches the transport as the header byte it is.
    fn r6_w2_from_name(from: &str) -> String {
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let m1_body = serde_json::json!({
            "id": "M1", "internalDate": "1700000000000", "labelIds": ["INBOX"],
            "payload": { "headers": [ { "name": "From", "value": from } ] }
        })
        .to_string();
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, &m1_body)]);
        let ListedPage { rows, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a well-formed page must map");
        assert_eq!(rows.len(), 1);
        rows[0].from_name.clone()
    }

    /// RFC 2047 §5(3): an encoded-word MUST NOT appear within a quoted-string — the quoted form
    /// is literal text, never decoded like the atom form.
    #[test]
    fn an_encoded_word_inside_a_quoted_string_is_literal() {
        assert_eq!(
            r6_w2_from_name("\"=?UTF-8?Q?Legal_Hold?=\" <hold@example.com>"),
            "=?UTF-8?Q?Legal_Hold?="
        );
    }

    /// The construction: a quoted display name carrying an encoded-word that would decode
    /// to a trusted brand stays the literal text the sender quoted.
    #[test]
    fn a_partly_encoded_quoted_name_is_literal() {
        assert_eq!(
            r6_w2_from_name("\"Support =?UTF-8?Q?PayPal?=\" <x@evil.example>"),
            "Support =?UTF-8?Q?PayPal?="
        );
    }

    /// RFC 2047 §2/§5(3): an atom decodes only if it IS exactly one encoded-word, separated from
    /// both neighbours by linear whitespace. Text glued onto a word (the lexer merges atext into
    /// ONE atom), two words glued into one atom, and a word touching a `.` or a quoted-string all
    /// stay literal.
    #[test]
    fn a_glued_atom_is_literal() {
        assert_eq!(r6_w2_from_name("x=?UTF-8?Q?y?= <x@example.com>"), "x=?UTF-8?Q?y?=");
        assert_eq!(
            r6_w2_from_name("=?UTF-8?Q?a?==?UTF-8?Q?b?= <x@example.com>"),
            "=?UTF-8?Q?a?==?UTF-8?Q?b?="
        );
        assert_eq!(
            r6_w2_from_name("=?UTF-8?Q?J?=.=?UTF-8?Q?S?= <x@example.com>"),
            "=?UTF-8?Q?J?=.=?UTF-8?Q?S?="
        );
        assert_eq!(r6_w2_from_name("\"x\"=?UTF-8?Q?y?= <x@example.com>"), "x=?UTF-8?Q?y?=");
    }

    /// A word that decodes to encoded-word SYNTAX is decoded ONCE — the transport must not decode
    /// the already-decoded display name a second time (a leftover call would show `PayPal`).
    #[test]
    fn a_double_encoded_word_stays_single_decoded() {
        assert_eq!(
            r6_w2_from_name("=?UTF-8?Q?=3D=3FUTF-8=3FQ=3FPayPal=3F=3D?= <x@evil.example>"),
            "=?UTF-8?Q?PayPal?="
        );
    }

    /// KEEP-After the fix (§6.2): the space between a plain word and an encoded-word is kept — only
    /// whitespace BETWEEN TWO DECODED words is dropped.
    #[test]
    fn a_plain_word_then_an_encoded_word_keeps_its_space() {
        assert_eq!(r6_w2_from_name("Legal =?UTF-8?Q?Hold?= <hold@example.com>"), "Legal Hold");
        assert_eq!(r6_w2_from_name("=?UTF-8?Q?Legal?= Hold <hold@example.com>"), "Legal Hold");
    }

    /// KEEP-After the fix: an atom that IS one encoded-word decodes, and adjacent decoded words join
    /// without their separating whitespace (§6.2). Non-claim, pinned: a comment between two
    /// encoded-words is CFWS, so they join as if only LWSP separated them.
    #[test]
    fn an_encoded_word_atom_decodes_and_adjacent_ones_join() {
        assert_eq!(r6_w2_from_name("=?UTF-8?Q?Legal_Hold?= <hold@example.com>"), "Legal Hold");
        assert_eq!(r6_w2_from_name("=?UTF-8?Q?a?= =?UTF-8?Q?b?= <x@example.com>"), "ab");
        assert_eq!(r6_w2_from_name("=?UTF-8?Q?a?= (c) =?UTF-8?Q?b?= <x@example.com>"), "ab");
    }

    /// Regression test: before the split-first fix, the WHOLE raw From value was RFC
    /// 2047-decoded before `parse_from_header` ever ran. When the entire From header is one
    /// encoded-word — no `<...>` at all, which is exactly what a hostile/malformed sender can hand
    /// us — decoding first turns the encoded-word's PAYLOAD into what `parse_from_header` then
    /// reads as the address, letting the payload MINT an address that never appeared on the wire.
    /// After the fix, the raw (un-decoded) header is split first: with no `<...>` present the
    /// whole raw token becomes `from_addr` byte-exact, wire text — never expanded.
    #[test]
    fn list_inbox_page_leaves_an_encoded_word_whole_from_value_as_the_raw_token_not_a_decoded_address(
    ) {
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let raw_from = "=?UTF-8?Q?trusted=40example.com?=";
        let m1_body = format!(
            r#"{{"id":"M1","internalDate":"1700000000000","labelIds":["INBOX"],
            "payload":{{"headers":[
                {{"name":"From","value":"{raw_from}"}}]}}}}"#
        );
        // Sanity: the payload DOES decode to something that looks like a real, different address —
        // that is the spoof this test guards against, not a decode failure.
        assert_eq!(decode_rfc2047(raw_from), "trusted@example.com");
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, &m1_body)]);

        let ListedPage { rows: page, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a well-formed page must map");

        assert_eq!(page.len(), 1);
        assert_eq!(
            page[0].from_addr, raw_from,
            "the address half must stay the byte-exact wire text — an encoded-word token in the \
             address position renders verbatim, never decoded into a different address"
        );
        assert_eq!(
            page[0].from_name, "",
            "no `<...>` was present, so parse_from_header's whole-value-is-the-address branch \
             applies and there is no separate name half to decode"
        );
    }

    /// The earlier legit-name fixture (a real `Name <addr>` shape with an encoded-word display
    /// name) must stay green under split-first — the name half is still decoded, exactly as
    /// established.
    #[test]
    fn list_inbox_page_still_decodes_the_name_half_when_a_real_address_follows_it() {
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let m1_body = r#"{"id":"M1","internalDate":"1700000000000","labelIds":["INBOX"],
            "payload":{"headers":[
                {"name":"From","value":"=?UTF-8?B?44GT44KT44Gr44Gh44Gv?= <sender@example.com>"}]}}"#;
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, m1_body)]);

        let ListedPage { rows: page, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a well-formed page must map");

        assert_eq!(page.len(), 1);
        assert_eq!(page[0].from_name, "こんにちは");
        assert_eq!(page[0].from_addr, "sender@example.com");
    }

    // ---- the construction, transport to approval ----

    /// The recipe, byte for byte the one `src/__tests__/plan-review-dom.test.ts` renders:
    /// `phrase` repeated and cut to `n` bytes, a trailing space turned into `.` (so no trim on the
    /// way can shorten it). ASCII only, so bytes = chars.
    fn council_r1_filled(phrase: &str, n: usize) -> String {
        let mut s = String::new();
        while s.len() < n {
            s.push_str(phrase);
        }
        s.truncate(n);
        if s.ends_with(' ') {
            s.pop();
            s.push('.');
        }
        s
    }

    /// The input, reproduced end to
    /// end on the DATA half: a 623-byte sender display (`Name <addr>`) and a 480-byte subject
    /// ending in `KEEP LEGAL HOLD`, answered by a remote `messages.get`, go through the REAL
    /// transport parser (`fetch_header_summary` → `parse_from_header` → `decode_rfc2047`), the
    /// read coordinator's ingest chokepoint (`normalize_display`), the plan mint
    /// (`frozen_plan_member`) and the approval store (`view_commitment` / `validate_evidence`),
    /// and the review view — `digests.presentation_view`, which the shell's `review_view_for`
    /// clones verbatim into `PlanReviewView.presentation` — carries every byte, and the approval
    /// commits them. This half was never the defect ("the frozen fields preserved the
    /// normalized values, and approval accepted their presentation digest"); it pins what the
    /// renderer must then show in full. The renderer half — the same bytes as the cells' whole
    /// text, no truncating CSS reaching them, Approve echoing them — is
    /// `plan-review-dom.test.ts`. The door is `fetch_header_summary`, not
    /// `parse_minimal_message` (ids and labels only): a map correction.
    #[test]
    fn council_r1_s3_p1_the_seats_623_and_480_byte_construction_survives_transport_to_approval_intact() {
        const HOLD: &str = " KEEP LEGAL HOLD";
        let addr = "records-custodian@legal-hold.example";
        let name = council_r1_filled("Compliance Archive Notification Service ", 623 - addr.len() - 3);
        let sender = format!("{name} <{addr}>");
        let subject = format!("{}{HOLD}", council_r1_filled("Re: quarterly retention schedule review ", 480 - HOLD.len()));
        assert_eq!(sender.len(), 623, "the seat's sender display is 623 bytes");
        assert_eq!(subject.len(), 480, "the seat's subject is 480 bytes");
        assert!(subject.ends_with("KEEP LEGAL HOLD"));

        // The remote answer: the list, then the masked metadata get for the one message.
        let list_body = r#"{"messages":[{"id":"CLIP-1"}]}"#;
        let m1_body = serde_json::json!({
            "id": "CLIP-1",
            "internalDate": "1758672000000",
            "labelIds": ["INBOX", "UNREAD"],
            "payload": { "headers": [ { "name": "From", "value": sender }, { "name": "Subject", "value": subject } ] }
        })
        .to_string();
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, &m1_body)]);
        let ListedPage { rows, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("the page maps");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].from_name, name, "the transport parser keeps the whole display name");
        assert_eq!(rows[0].from_addr, addr);
        assert_eq!(rows[0].subject, subject, "the transport parser keeps the whole subject");

        // The durable store: the intent log owns the schema, so it opens first; then the ingest
        // chokepoint writes the header row; then the plan is minted and approved on it.
        // a guarded directory (the ONE guard), bound before the store.
        let dir = aruna::test_temp::TempDir::new("photon-council-r1-clip");
        let path = dir.join("store.sqlite");
        let mut log = aruna::SqliteIntentLog::open(&path).expect("open the store");
        let refs = aruna::read_coordinator::ReadCoordinator::open(&path)
            .expect("open the read coordinator")
            .ingest_page("acct", &rows)
            .expect("ingest");
        let custody = aruna::key_custody::InMemoryCustody::new();
        let root = aruna::key_custody::root_key_verified(&custody, &mut log).expect("root key");
        let spec = aruna::plan::PlanSpec {
            account: "acct".into(),
            provider_principal: "me@e".into(),
            grant_generation: 1,
            verb: aruna::plan::PlanVerb::Trash,
            member_refs: refs.clone(),
            rationale: None,
            ttl_seconds: 3600,
        };
        let minted = aruna::IntentLog::mint_plan(&mut log, &root, spec).expect("mint");
        let plan = aruna::IntentLog::plan(&log, &minted.plan_id)
            .expect("read the plan")
            .expect("stored");
        let view = &plan.digests.presentation_view;
        assert_eq!(view.rows.len(), 1);
        // The row's sender is now TWO frozen fields, name and address,
        // never one composed 623-byte string — together they are still the whole construction.
        assert_eq!(view.rows[0].sender, name, "the review row's sender NAME is the whole name half");
        assert_eq!(view.rows[0].sender_address, format!("<{addr}>"), "the review row's sender ADDRESS is the bracketed address half");
        assert_eq!(format!("{} {}", view.rows[0].sender, view.rows[0].sender_address).len(), sender.len(), "together, still the whole 623 bytes");
        assert_eq!(view.rows[0].subject, subject, "the review row's subject is the whole 480 bytes");
        assert_eq!(view.summary.sender_domains, vec![("legal-hold.example".to_string(), 1)]);
        assert_eq!(&minted.presentation, view, "the minted presentation is the stored review view");

        // The approval commits the SAME bytes: the whole presentation is accepted, and a
        // presentation clipped the way the screen clipped it is not the one approved.
        let mut clipped = view.clone();
        clipped.rows[0].sender = format!("{}\u{2026}", &sender[..40]);
        clipped.rows[0].subject = format!("{}\u{2026}", &subject[..60]);
        assert_eq!(
            aruna::IntentLog::record_approval(&mut log, &root, &minted.plan_id, "operator", aruna::plan::RenderedView::FullList(clipped))
                .unwrap_err(),
            aruna::plan::PlanStoreError::Refused(aruna::plan::PlanRefusal::ViewMismatch),
            "the commitment is over the whole value"
        );
        let evidence = aruna::IntentLog::record_approval(&mut log, &root, &minted.plan_id, "operator", aruna::plan::RenderedView::FullList(view.clone()))
            .expect("the whole presentation approves");
        assert_eq!(evidence.view_digest, plan.digests.presentation);
        drop(log);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- the From header by RFC 5322 §3.4 ----

    /// One masked `messages.get` answering `from` as the whole From header value, through the REAL
    /// listing route (`list_inbox_page` → `fetch_header_summary` → `parse_from_header`).
    fn council_r2_listed_from(from: &str) -> aruna::read_surface::HeaderSummary {
        let list_body = r#"{"messages":[{"id":"S31"}]}"#;
        let m1_body = serde_json::json!({
            "id": "S31",
            "internalDate": "1758672000000",
            "labelIds": ["INBOX"],
            "payload": { "headers": [ { "name": "From", "value": from }, { "name": "Subject", "value": "s" } ] }
        })
        .to_string();
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, &m1_body)]);
        let ListedPage { mut rows, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("the page maps");
        assert_eq!(rows.len(), 1);
        rows.remove(0)
    }

    /// A comment is CFWS (RFC 5322 §3.2.2) and a comment may hold
    /// angle brackets, so the mailbox is the angle-addr OUTSIDE it — never the last `<…>`.
    #[test]
    fn an_angle_addr_inside_a_comment_is_never_the_address() {
        let row = council_r2_listed_from("Notice <real@evil.example> (routing note <billing@trusted.example>)");
        assert_eq!(row.from_addr, "real@evil.example", "the mailbox is the angle-addr outside the comment");
        assert_eq!(row.from_name, "Notice", "the display name is the phrase before it — the comment is not display text");
        assert_eq!(
            aruna::mailbox::sender_facts(&row.from_addr),
            (aruna::mailbox::SenderStatus::Ok, Some("evil.example".to_string())),
            "the header row's write door derives the mailbox's domain from what the transport stored"
        );
    }

    /// Witness (2): a quoted-string is one word of the display name, whatever it spells.
    #[test]
    fn a_quoted_strings_fake_address_is_display_text_never_the_address() {
        let row = council_r2_listed_from("\"<fake@x.example>\" <real@y.example>");
        assert_eq!(row.from_addr, "real@y.example");
        assert_eq!(row.from_name, "<fake@x.example>");
        assert_eq!(aruna::mailbox::sender_facts(&row.from_addr), (aruna::mailbox::SenderStatus::Ok, Some("y.example".to_string())));
    }

    /// Witness (3): an EMPTY From names no mailbox at all.
    #[test]
    fn an_empty_from_names_no_address() {
        let row = council_r2_listed_from("");
        assert_eq!(row.from_addr, "");
        assert_eq!(row.from_name, "");
        assert_eq!(aruna::mailbox::sender_facts(&row.from_addr), (aruna::mailbox::SenderStatus::Unavailable, None), "no addr, no domain: UNAVAILABLE");
    }

    /// Witness (4): a bare addr-spec is the mailbox, with no display name.
    #[test]
    fn a_bare_address_is_the_mailbox_with_an_empty_display() {
        let row = council_r2_listed_from("real@evil.example");
        assert_eq!(row.from_addr, "real@evil.example");
        assert_eq!(row.from_name, "");
        assert_eq!(aruna::mailbox::sender_facts(&row.from_addr), (aruna::mailbox::SenderStatus::Ok, Some("evil.example".to_string())));
    }

    /// Witness (5): a value that is not exactly one mailbox — two angle-addrs outside any comment,
    /// or an unterminated one — keeps its raw text (the row's `from_addr`, the display the plan
    /// freezes) and names no mailbox: no display name is split off it.
    #[test]
    fn a_malformed_from_keeps_its_raw_text_and_names_no_mailbox() {
        for raw in ["<a@x.example> <b@y.example>", "Name <unterminated"] {
            let row = council_r2_listed_from(raw);
            assert_eq!(row.from_addr, raw, "the raw text is kept whole: {raw}");
            assert_eq!(row.from_name, "", "nothing is split off a value that is not one mailbox: {raw}");
            assert_eq!(aruna::mailbox::sender_facts(&row.from_addr), (aruna::mailbox::SenderStatus::Malformed, None), "MALFORMED, no domain: {raw}");
        }
    }

    /// RFC 5322 §3.6 — `from` occurs at most once. Through the REAL
    /// listing route (`list_inbox_page` → `fetch_header_summary` → `raw_from` → `parse_from_header`),
    /// two `From` fields is `Malformed`, never "the first one wins".
    #[test]
    fn two_from_fields_is_malformed_never_first_wins() {
        let list_body = r#"{"messages":[{"id":"D1"}]}"#;
        let m1_body = serde_json::json!({
            "id": "D1",
            "internalDate": "1758672000000",
            "labelIds": ["INBOX"],
            "payload": { "headers": [
                { "name": "From", "value": "PayPal Service <service@paypal.example>" },
                { "name": "From", "value": "Notice <real@evil.example>" },
                { "name": "Subject", "value": "s" }
            ] }
        })
        .to_string();
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, &m1_body)]);
        let ListedPage { rows, .. } = transport.list_inbox_page(&user("me"), 50, None).expect("the page maps");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.from_name, "", "no display name is split off a value that is not one From field");
        assert_eq!(row.from_addr, "2 From header fields");
        assert_eq!(
            aruna::mailbox::sender_facts(&row.from_addr),
            (aruna::mailbox::SenderStatus::Malformed, None),
            "two From fields is Malformed, never the first one's domain"
        );
    }

    /// The construction END TO END: three remote
    /// answers — the comment construction, an EMPTY From and a malformed From — go through the real
    /// transport, the read coordinator's ingest chokepoint, the plan mint and the stored review
    /// view. The summary names the MAILBOX's domain and never a comment's, and an empty or
    /// malformed sender is never a domain entry.
    #[test]
    fn the_construction_end_to_end_names_the_mailbox_domain_and_never_an_empty_or_malformed_one() {
        let list_body = r#"{"messages":[{"id":"C1"},{"id":"C2"},{"id":"C3"}]}"#;
        let get = |id: &str, at: &str, from: &str| {
            serde_json::json!({
                "id": id,
                "internalDate": at,
                "labelIds": ["INBOX"],
                "payload": { "headers": [ { "name": "From", "value": from }, { "name": "Subject", "value": format!("subject {id}") } ] }
            })
            .to_string()
        };
        let c1 = get("C1", "1758672003000", "Notice <real@evil.example> (routing note <billing@trusted.example>)");
        let c2 = get("C2", "1758672002000", "");
        let c3 = get("C3", "1758672001000", "<a@x.example> <b@y.example>");
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, &c1), resp(200, &c2), resp(200, &c3)]);
        let ListedPage { rows, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("the page maps");
        assert_eq!(rows.len(), 3);

        // A guarded directory (the ONE guard), bound before the store.
        let dir = aruna::test_temp::TempDir::new("photon-council-r2-s31");
        let path = dir.join("store.sqlite");
        let mut log = aruna::SqliteIntentLog::open(&path).expect("open the store");
        let refs = aruna::read_coordinator::ReadCoordinator::open(&path)
            .expect("open the read coordinator")
            .ingest_page("acct", &rows)
            .expect("ingest");
        let custody = aruna::key_custody::InMemoryCustody::new();
        let root = aruna::key_custody::root_key_verified(&custody, &mut log).expect("root key");
        let spec = aruna::plan::PlanSpec {
            account: "acct".into(),
            provider_principal: "me@e".into(),
            grant_generation: 1,
            verb: aruna::plan::PlanVerb::Trash,
            member_refs: refs.clone(),
            rationale: None,
            ttl_seconds: 3600,
        };
        let minted = aruna::IntentLog::mint_plan(&mut log, &root, spec).expect("mint");
        let plan = aruna::IntentLog::plan(&log, &minted.plan_id)
            .expect("read the plan")
            .expect("stored");
        let view = &plan.digests.presentation_view;
        assert_eq!(
            view.summary.sender_domains,
            vec![("evil.example".to_string(), 1)],
            "the mailbox's domain, once — never the comment's, never an empty or a malformed sender's"
        );
        assert_eq!(view.summary.sender_domain_unavailable, 1, "the empty From is counted, by why");
        assert_eq!(view.summary.sender_header_malformed, 1, "the malformed From is counted, by why");
        assert_eq!(&minted.presentation, view, "the minted presentation is the stored review view");
        // Each member froze its display text — name and address, SEPARATELY
        // — beside its STRUCTURED sender.
        let frozen: std::collections::BTreeMap<&str, (&str, &str, &aruna::plan::FrozenSender)> = plan
            .members
            .iter()
            .map(|m| (m.display.subject.as_str(), (m.display.sender.as_str(), m.display.sender_address.as_str(), &m.display.sender_parse)))
            .collect();
        assert_eq!(
            frozen["subject C1"],
            (
                "Notice",
                "<real@evil.example>",
                &aruna::plan::FrozenSender::Parsed { addr: "real@evil.example".into(), local: "real".into(), domain: "evil.example".into() }
            ),
            "the comment is gone from the display too — it was never part of the mailbox"
        );
        assert_eq!(frozen["subject C2"], ("", "", &aruna::plan::FrozenSender::Unavailable));
        assert_eq!(
            frozen["subject C3"],
            ("", "<a@x.example> <b@y.example>", &aruna::plan::FrozenSender::Malformed),
            "the raw text is the display"
        );
        // The approval commits this view — the one that names the mailbox's domain.
        let evidence = aruna::IntentLog::record_approval(&mut log, &root, &minted.plan_id, "operator", aruna::plan::RenderedView::FullList(view.clone()))
            .expect("the review view approves");
        assert_eq!(evidence.view_digest, plan.digests.presentation);
        drop(log);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- list_inbox_page ----

    #[test]
    fn list_inbox_page_issues_the_list_then_per_id_metadata_gets_and_maps_every_field() {
        let list_body = r#"{"messages":[{"id":"M1"},{"id":"M2"}],"nextPageToken":"TOK-2"}"#;
        let m1_body = r#"{"id":"M1","internalDate":"1699999999000","labelIds":["INBOX","STARRED"],
            "payload":{"headers":[{"name":"From","value":"Alice <alice@example.com>"},
            {"name":"Subject","value":"Hello"}]}}"#;
        let m2_body = r#"{"id":"M2","internalDate":"1700000000000","labelIds":["INBOX","UNREAD"],
            "payload":{"headers":[{"name":"From","value":"bob@example.com"}]}}"#;
        let (transport, probe) =
            fixture(vec![resp(200, list_body), resp(200, m1_body), resp(200, m2_body)]);

        let ListedPage { rows: page, next, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a well-formed page must map");

        assert_eq!(page.len(), 2);
        assert_eq!(page[0].provider_id, ProviderMessageId("M1".to_string()));
        assert_eq!(page[0].received_at, 1_699_999_999_000, "internalDate ms string -> i64 ms");
        assert_eq!(page[0].from_name, "Alice");
        assert_eq!(page[0].from_addr, "alice@example.com");
        assert_eq!(page[0].subject, "Hello");
        assert!(page[0].seen, "no UNREAD label => seen");
        assert!(page[0].flagged, "STARRED present => flagged");
        assert!(!page[0].attachments.has_attachments);

        assert_eq!(page[1].from_name, "", "bare address form: no name");
        assert_eq!(page[1].from_addr, "bob@example.com");
        assert_eq!(page[1].subject, "", "absent Subject header => empty, never fabricated");
        assert!(!page[1].seen, "UNREAD present => not seen");
        assert!(!page[1].flagged, "STARRED absent => not flagged");

        assert_eq!(next, Some(ContinuationToken("TOK-2".to_string())));

        let calls = probe.calls();
        assert_eq!(calls.len(), 3, "sequential: one list call + one GET per id, never a batch");
        assert!(calls[0].0.contains("/gmail/v1/users/me/messages?"));
        assert!(calls[0].0.contains("labelIds=INBOX"));
        assert!(calls[0].0.contains("maxResults=50"));
        assert!(!calls[0].0.contains("pageToken"), "no token on the first page");
        assert!(calls[1].0.contains("/messages/M1?"));
        // The listing get is `format=full` under the narrowing mask — the header
        // scope is no longer a `metadataHeaders` list, because that parameter belongs to a format
        // that cannot answer attachment presence at all.
        assert!(calls[1].0.contains("format=full"), "url: {}", calls[1].0);
        assert!(calls[1].0.contains("fields=id,internalDate,labelIds,payload("));
        assert!(calls[1].0.contains("parts(partId,mimeType,filename,headers"));
        assert!(!calls[1].0.contains("metadataHeaders"));
        assert!(calls[2].0.contains("/messages/M2?"));
    }

    // ---- the listing route needs the MIME tree for attachment presence ----

    #[test]
    fn list_inbox_page_reports_real_attachment_presence_from_the_part_tree() {
        // Regression test. `format=metadata` returns NO `payload.parts` at all (the Gmail REST reference:
        // METADATA "Returns only email message ID, labels, and email headers"), so
        // `attachment_presence` scanned a part tree that was never on the wire and every listing
        // row answered `has_attachments: false` — a paperclip that could not exist.
        //
        // WHERE THE WITNESS ACTUALLY BITES: the fake hands back whatever the test queued, so it
        // cannot withhold the part tree the real API withholds — the mapping assertion below
        // passed BEFORE the fix too. The discriminating half is the REQUEST shape (the last four
        // assertions): what we ask Gmail for is the thing that was wrong, and it is the only part
        // of this the hermetic rig can grade. The live drill is where the response half is seen.
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let m1_body = r#"{"id":"M1","internalDate":"1000","labelIds":["INBOX"],
            "payload":{"mimeType":"multipart/mixed","headers":[{"name":"Subject","value":"With a file"}],
              "parts":[
                {"partId":"0","mimeType":"text/plain","headers":[]},
                {"partId":"1","mimeType":"application/pdf","filename":"invoice.pdf",
                 "headers":[{"name":"Content-Disposition","value":"attachment; filename=\"invoice.pdf\""}]}
              ]}}"#;
        let (transport, probe) = fixture(vec![resp(200, list_body), resp(200, m1_body)]);

        let ListedPage { rows: page, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a page with an attachment must map");
        assert!(
            page[0].attachments.has_attachments,
            "the listing route must see the real part tree, not a payload that is never sent"
        );
        assert_eq!(page[0].attachments.count, 1);

        // AND NO BODY BYTES ON THE LISTING WIRE. The fields mask names every member we read and
        // deliberately omits `body`, so the response carries the part SKELETON only.
        let url = &probe.calls()[1].0;
        assert!(url.contains("format=full"), "url: {url}");
        assert!(
            url.contains("fields=id,internalDate,labelIds,payload("),
            "the narrowing mask must ride the listing GET: {url}"
        );
        assert!(
            !url.contains("body"),
            "the mask must never request body data on the LISTING route: {url}"
        );
        assert!(
            !url.contains("format=metadata"),
            "format=metadata cannot answer attachment presence: {url}"
        );
    }

    #[test]
    fn list_inbox_page_refuses_an_over_limit_list_response_rather_than_truncating_it() {
        // A malformed or hostile
        // `messages.list` response can list MORE ids than the `maxResults` we asked for. The
        // earlier fix silently took the first `clamped` ids and fetched only those — but this
        // transport hands the provider's own `nextPageToken` straight back as the continuation
        // cursor, and that cursor was minted for the FULL (over-limit) page. Truncating our side
        // while keeping the provider's cursor drops the ids between the cut and wherever the
        // cursor resumes, on THIS page and the next, with no signal to the caller that anything
        // was skipped. So the malformed page is refused outright, never partially served.
        let list_body =
            r#"{"messages":[{"id":"M1"},{"id":"M2"},{"id":"M3"},{"id":"M4"},{"id":"M5"}]}"#;
        let (transport, probe) = fixture(vec![resp(200, list_body)]);

        let err = transport
            .list_inbox_page(&user("me"), 2, None)
            .expect_err("an over-long list response must be refused, never silently truncated");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
        assert_eq!(
            probe.calls().len(),
            1,
            "the refusal happens before any per-id fan-out is spent: {:#?}",
            probe.calls().iter().map(|c| c.0.clone()).collect::<Vec<_>>()
        );
    }

    /// THE INBOX MEMBERSHIP IS RE-CHECKED ON THE METADATA ANSWER.
    ///
    /// `messages.list(labelIds=INBOX)` and the per-id `messages.get` are two round trips with a
    /// real gap between them: a message archived (or trashed) in that gap is still listed by the
    /// first call and still answered by the second — with `INBOX` gone from its `labelIds`. The
    /// summary was mapped anyway, and the caller's reconcile then wrote the row straight back into
    /// the local Inbox, where nothing could remove it until a later refresh happened to catch it.
    #[test]
    fn list_inbox_page_skips_a_message_archived_between_the_list_and_the_metadata_get() {
        let list_body = r#"{"messages":[{"id":"M1"},{"id":"M2"}]}"#;
        let m1_body = r#"{"id":"M1","internalDate":"1000","labelIds":["INBOX","UNREAD"],
            "payload":{"headers":[{"name":"Subject","value":"still here"}]}}"#;
        // M2 was archived in the race window: the metadata answer no longer carries INBOX.
        let m2_body = r#"{"id":"M2","internalDate":"2000","labelIds":["STARRED"],
            "payload":{"headers":[{"name":"Subject","value":"archived mid-page"}]}}"#;
        let (transport, probe) =
            fixture(vec![resp(200, list_body), resp(200, m1_body), resp(200, m2_body)]);

        let ListedPage { rows: page, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a mid-page archive is a SKIP, never a refusal of the whole page");

        assert_eq!(
            page.len(),
            1,
            "a summary whose labelIds no longer contain INBOX must not be returned — reconcile \
             would write it back into the local Inbox: {page:#?}"
        );
        assert_eq!(page[0].provider_id, ProviderMessageId("M1".to_string()));
        assert_eq!(
            probe.calls().len(),
            3,
            "the skip happens on the ANSWER — both gets were already spent"
        );
    }

    #[test]
    fn list_inbox_page_a_metadata_answer_with_no_labels_at_all_is_skipped_too() {
        // `labelIds` absent entirely (the `LabelIds::Absent` arm) is not evidence of membership:
        // the row is skipped for the same reason a present-but-INBOX-free list is.
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let m1_body = r#"{"id":"M1","internalDate":"1000","payload":{"headers":[]}}"#;
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, m1_body)]);
        let ListedPage { rows: page, .. } = transport.list_inbox_page(&user("me"), 50, None).expect("maps");
        assert!(
            page.is_empty(),
            "absent labels prove nothing — INBOX membership must be POSITIVE evidence: {page:#?}"
        );
    }

    #[test]
    fn list_inbox_page_an_empty_inbox_issues_no_per_id_calls() {
        let (transport, probe) = fixture(vec![resp(200, r#"{"messages":[]}"#)]);
        let ListedPage { rows: page, next, .. } = transport.list_inbox_page(&user("me"), 50, None).expect("empty page");
        assert!(page.is_empty());
        assert_eq!(next, None, "absent nextPageToken => no continuation");
        assert_eq!(probe.calls().len(), 1, "an empty inbox issues zero per-id gets");
    }

    #[test]
    fn list_inbox_page_pagination_passes_the_continuation_token_as_pagetoken() {
        let (transport, probe) = fixture(vec![resp(200, r#"{"messages":[]}"#)]);
        let token = ContinuationToken("TOK-1".to_string());
        transport
            .list_inbox_page(&user("me"), 10, Some(&token))
            .expect("a token-bearing page still maps");
        let calls = probe.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("pageToken=TOK-1"), "url: {}", calls[0].0);
    }

    #[test]
    fn list_inbox_page_reclamps_an_out_of_range_page_size_before_the_wire() {
        let (transport, probe) = fixture(vec![resp(200, r#"{"messages":[]}"#)]);
        transport
            .list_inbox_page(&user("me"), 5_000, None)
            .expect("an oversize request is clamped, not rejected");
        assert!(probe.calls()[0].0.contains("maxResults=200"), "url: {}", probe.calls()[0].0);
    }

    #[test]
    fn list_inbox_page_malformed_json_is_a_typed_error_never_a_panic() {
        let (transport, _) = fixture(vec![resp(200, "not json")]);
        let err = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect_err("malformed JSON must be a typed refusal");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn list_inbox_page_a_metadata_response_missing_internal_date_is_a_typed_error() {
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        let m1_body = r#"{"id":"M1","labelIds":["INBOX"]}"#; // no internalDate
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, m1_body)]);
        let err = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect_err("a missing internalDate must refuse, never fabricate a timestamp");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn list_inbox_page_from_header_malformed_yields_empty_name_and_raw_string_as_addr() {
        let list_body = r#"{"messages":[{"id":"M1"}]}"#;
        // `labelIds` carries INBOX because the listing route now re-checks membership on this very
        // answer — this fixture is about the FROM header, not about membership, and
        // its old empty `labelIds` would now (correctly) be skipped as no-longer-inbox mail.
        let m1_body = r#"{"id":"M1","internalDate":"1000","labelIds":["INBOX"],
            "payload":{"headers":[{"name":"From","value":"Name <unterminated"}]}}"#;
        let (transport, _) = fixture(vec![resp(200, list_body), resp(200, m1_body)]);
        let ListedPage { rows: page, .. } = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a malformed From must never panic, and never refuse the whole page");
        assert_eq!(page[0].from_name, "");
        assert_eq!(page[0].from_addr, "Name <unterminated");
    }

    #[test]
    fn list_inbox_page_propagates_the_shared_status_classifier_on_404_and_429() {
        for (status, body) in [
            (404, r#"{"error":{"code":404,"errors":[{"domain":"global","reason":"notFound"}]}}"#),
            (429, r#"{"error":{"code":429,"errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}]}}"#),
        ] {
            let (transport, _) = fixture(vec![resp(status, body)]);
            let err = transport
                .list_inbox_page(&user("me"), 50, None)
                .expect_err("a non-2xx list response must surface the shared classifier");
            match status {
                404 => assert_eq!(err, GmailError::NotFound),
                429 => assert_eq!(err, GmailError::RateLimit),
                _ => unreachable!(),
            }
        }
    }

    // ---- the listing route's page-level contracts ----

    /// One listing fixture: the `messages.list` id array, then one metadata answer per id.
    fn listing_fixture(list_body: &str, metadata: &[&str]) -> GatedTransport<FakeHttp> {
        let mut responses = vec![resp(200, list_body)];
        for body in metadata {
            responses.push(resp(200, body));
        }
        fixture(responses).0
    }

    /// A minimal INBOX metadata answer at `internal_date`.
    fn inbox_metadata(id: &str, internal_date: i64) -> String {
        format!(
            r#"{{"id":"{id}","internalDate":"{internal_date}","labelIds":["INBOX"],
                "payload":{{"headers":[{{"name":"Subject","value":"{id}"}}]}}}}"#
        )
    }

    /// Regression test: a per-page monotonicity check cannot prove
    /// COVERAGE, only within-sample order. `messages.list` carries no sort contract at all, so a
    /// page that merely happens to look sorted (or is a single row) passed that check while
    /// proving nothing about whether other inbox mail sits above its floor: a pass was silence,
    /// not evidence. `chronological` is now `false` UNCONDITIONALLY, on every shape a page can
    /// take — out-of-order, newest-first, and tied — so the coordinator's window reconcile never
    /// treats a Gmail page as a coverage floor until provider-backed sync evidence (design §7's
    /// `historyId` close) replaces this guess. Mail archived elsewhere surfaces as local
    /// staleness rather than a silent deletion; a row leaves the local Inbox only via the user's
    /// own verbs, or a provider (JMAP) that carries a real, contractual `receivedAt desc` sort.
    #[test]
    fn list_inbox_page_never_reports_a_gmail_page_as_chronological() {
        for (label, ids, dates) in [
            ("out-of-order (oldest first)", ["M1", "M2"], [1_000i64, 2_000]),
            ("newest-first", ["M2", "M1"], [2_000, 1_000]),
            ("tied timestamps", ["M1", "M2"], [2_000, 2_000]),
        ] {
            let list_body =
                format!(r#"{{"messages":[{{"id":"{}"}},{{"id":"{}"}}]}}"#, ids[0], ids[1]);
            let m0 = inbox_metadata(ids[0], dates[0]);
            let m1 = inbox_metadata(ids[1], dates[1]);
            let transport = listing_fixture(&list_body, &[&m0, &m1]);

            let page = transport
                .list_inbox_page(&user("me"), 50, None)
                .unwrap_or_else(|e| panic!("{label}: a Gmail page of any order still ingests: {e:?}"));

            assert_eq!(page.rows.len(), 2, "{label}: nothing is dropped — the rows are real mail");
            assert!(
                !page.chronological,
                "{label}: Gmail pages never license removals, regardless of order"
            );
        }
    }

    /// Regression test: a message DELETED between `messages.list` and the per-id
    /// `messages.get` 404s, and that 404 aborted the whole page.
    ///
    /// It is the deletion counterpart of the archive-race skip (`fetch_header_summary`'s
    /// membership re-check): the two calls are separated in time and the mailbox
    /// keeps moving. Losing every OTHER row of the page — and the continuation with it — because
    /// one id no longer exists makes a single deletion able to stall the whole read side.
    #[test]
    fn list_inbox_page_skips_an_id_that_404s_between_the_list_and_the_get() {
        let not_found =
            r#"{"error":{"code":404,"errors":[{"domain":"global","reason":"notFound"}]}}"#;
        let (transport, probe) = fixture(vec![
            resp(200, r#"{"messages":[{"id":"M2"},{"id":"GONE"},{"id":"M1"}]}"#),
            resp(200, &inbox_metadata("M2", 2_000)),
            resp(404, not_found),
            resp(200, &inbox_metadata("M1", 1_000)),
        ]);

        let page = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect("a deleted id must not abort the page");

        let ids: Vec<&str> = page.rows.iter().map(|r| r.provider_id.0.as_str()).collect();
        assert_eq!(ids, vec!["M2", "M1"], "the surviving rows come back");
        assert_eq!(probe.calls().len(), 4, "the walk continued past the 404");
    }

    /// …and the split that keeps the skip honest: any OTHER per-id failure still aborts. A 403 is
    /// not evidence the message is gone, so mapping the page around it would report a shorter
    /// mailbox than the provider holds.
    #[test]
    fn list_inbox_page_still_aborts_on_a_per_id_failure_that_is_not_a_404() {
        let forbidden =
            r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions"}]}}"#;
        let (transport, _) = fixture(vec![
            resp(200, r#"{"messages":[{"id":"M2"},{"id":"M1"}]}"#),
            resp(200, &inbox_metadata("M2", 2_000)),
            resp(403, forbidden),
        ]);
        let err = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect_err("a 403 mid-page is not a deletion — it must surface");
        assert_eq!(err, GmailError::Forbidden);
    }

    /// Regression test (first shape): an EMPTY `nextPageToken` string handed back as
    /// a live cursor.
    ///
    /// `Some("")` is not a continuation: spending it re-issues the SAME request (an empty
    /// `pageToken` is no `pageToken`), so a caller that trusts `has_more` walks page 1 forever. The
    /// JMAP arm already refuses its own non-advancing shape; this is the Gmail
    /// twin, and it fails CLOSED with a deterministic typed error rather than minting the token.
    #[test]
    fn list_inbox_page_refuses_an_empty_next_page_token() {
        let (transport, _) = fixture(vec![resp(200, r#"{"messages":[],"nextPageToken":""}"#)]);
        let err = transport
            .list_inbox_page(&user("me"), 50, None)
            .expect_err("an empty continuation string must never be handed back as a cursor");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    /// Regression test (second shape): a `nextPageToken` BYTE-IDENTICAL to the one
    /// this very request carried. Same infinite walk, one step further along.
    #[test]
    fn list_inbox_page_refuses_a_next_page_token_that_repeats_the_one_we_sent() {
        let (transport, _) = fixture(vec![resp(
            200,
            r#"{"messages":[],"nextPageToken":"TOK-1"}"#,
        )]);
        let token = ContinuationToken("TOK-1".to_string());
        let err = transport
            .list_inbox_page(&user("me"), 50, Some(&token))
            .expect_err("a token that repeats the request's own cursor makes no progress");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    /// The unaffected shape, pinned beside them: a DIFFERENT token is a live cursor and still
    /// rides back out.
    #[test]
    fn list_inbox_page_still_returns_an_advancing_continuation() {
        let (transport, _) = fixture(vec![resp(
            200,
            r#"{"messages":[],"nextPageToken":"TOK-2"}"#,
        )]);
        let token = ContinuationToken("TOK-1".to_string());
        let page = transport
            .list_inbox_page(&user("me"), 50, Some(&token))
            .expect("an advancing token is a normal continuation");
        assert_eq!(page.next, Some(ContinuationToken("TOK-2".to_string())));
    }

    // ---- fetch_body ----

    #[test]
    fn fetch_body_prefers_text_plain_and_carries_text_html_when_both_present() {
        let plain = b64url_encode("hello plain");
        let html = b64url_encode("<p>hello html</p>");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/alternative","parts":[
                {{"mimeType":"text/plain","body":{{"data":"{plain}"}}}},
                {{"mimeType":"text/html","body":{{"data":"{html}"}}}}
            ]}}}}"#
        );
        let (transport, probe) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a well-formed full body must map");

        assert_eq!(raw.text.as_deref(), Some("hello plain"));
        assert_eq!(raw.html.as_deref(), Some("<p>hello html</p>"));
        assert!(!raw.text_truncated);
        assert!(!raw.html_truncated);
        assert!(!raw.attachments.has_attachments);
        assert!(probe.calls()[0].0.contains("format=full"));
    }

    /// TRUNCATION IS PER-REPRESENTATION AT THE TRANSPORT ITSELF, not only at
    /// the `to_body_view` selection above it. `text` is small and complete; `html` alone exceeds
    /// [`BODY_FETCH_CAP`]. Before this change both `cap_text` calls shared one `&mut truncated`, so
    /// this fixture reported the complete `text` as truncated too.
    #[test]
    fn fetch_body_marks_only_the_actually_clipped_representation_truncated() {
        let plain = "hello plain, complete and short";
        let big_html: String = std::iter::repeat_n('a', BODY_FETCH_CAP + 16).collect();
        let plain_encoded = b64url_encode(plain);
        let html_encoded = b64url_encode(&big_html);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/alternative","parts":[
                {{"mimeType":"text/plain","body":{{"data":"{plain_encoded}"}}}},
                {{"mimeType":"text/html","body":{{"data":"{html_encoded}"}}}}
            ]}}}}"#
        );
        let (transport, _probe) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a large html sibling next to a small complete text must still map");

        assert_eq!(raw.text.as_deref(), Some(plain));
        assert!(
            !raw.text_truncated,
            "the small, complete text/plain part was never clipped"
        );
        assert!(
            raw.html_truncated,
            "the oversize text/html part was clipped and must say so, independently of text"
        );
    }

    #[test]
    fn fetch_body_no_textual_part_anywhere_is_none_never_a_fabricated_empty_string() {
        let body = r#"{"id":"M1","payload":{"mimeType":"multipart/mixed","parts":[
            {"mimeType":"image/png","filename":"logo.png","body":{"attachmentId":"ATT-1"}}
        ]}}"#;
        let (transport, _) = fixture(vec![resp(200, body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a message with no textual part is still a valid, mappable body");

        assert_eq!(raw.text, None);
        assert_eq!(raw.html, None);
        assert!(raw.attachments.has_attachments, "the image part still counts as an attachment");
        assert_eq!(raw.attachments.count, 1);
    }

    // ---- a zero-byte textual leaf is honest empty text, not malformed ----

    #[test]
    fn fetch_body_accepts_a_zero_byte_text_part_as_honest_empty_text() {
        // Gmail serializes a valid empty textual leaf as `body: {"size": 0}` — `data` omitted
        // (its default), no attachmentId. Refusing it made the whole message unopenable.
        let body = r#"{"id":"M1","payload":{"mimeType":"text/plain","body":{"size":0}}}"#;
        let (transport, probe) = fixture(vec![resp(200, body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a zero-byte textual leaf is a VALID empty body, never malformed");

        assert_eq!(raw.text, Some(String::new()), "honestly empty, not absent");
        assert_eq!(probe.calls().len(), 1, "no attachment fetch was attempted");
    }

    #[test]
    fn fetch_body_still_refuses_a_positive_size_body_with_no_byte_source() {
        // The inverse fence: size > 0 with neither inline data nor an attachmentId claims bytes
        // it cannot deliver — that stays malformed (refused), exactly as before.
        let body = r#"{"id":"M1","payload":{"mimeType":"text/plain","body":{"size":5}}}"#;
        let (transport, _) = fixture(vec![resp(200, body)]);

        transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("a positive-size body with no source is malformed, not empty");
    }

    // ---- an ATTACHMENT-typed textual part is never the body ----

    #[test]
    fn fetch_body_skips_a_text_plain_attachment_and_selects_the_real_body() {
        // A `text/plain` part carrying a FILENAME is an attachment that happens to be textual
        // (`notes.txt`). Selecting the body by MIME type alone picked it — and because it sits
        // BEFORE the real body part, "first text/plain wins" shipped attachment bytes across IPC,
        // which the v1 no-attachment-bytes contract forbids.
        let attachment = b64url_encode("ATTACHMENT BYTES THAT MUST NOT CROSS IPC");
        let real = b64url_encode("the real body");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/mixed","parts":[
                {{"mimeType":"text/plain","filename":"notes.txt","body":{{"data":"{attachment}"}}}},
                {{"mimeType":"text/plain","body":{{"data":"{real}"}}}}
            ]}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a well-formed full body must map");

        assert_eq!(
            raw.text.as_deref(),
            Some("the real body"),
            "the filename-bearing text/plain part is an ATTACHMENT — the body is the next one"
        );
        assert_eq!(
            raw.attachments.count, 1,
            "the skipped part still COUNTS as an attachment — skipping it must not hide it"
        );
        assert!(raw.attachments.has_attachments);
    }

    #[test]
    fn fetch_body_skips_a_disposition_attachment_textual_part_even_without_a_filename() {
        // Same class, the other witness: no `filename` member at all, but the part's own
        // `Content-Disposition` header says `attachment`.
        let attachment = b64url_encode("ATTACHMENT BYTES THAT MUST NOT CROSS IPC");
        let real = b64url_encode("<p>the real html body</p>");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/mixed","parts":[
                {{"mimeType":"text/html",
                  "headers":[{{"name":"Content-Disposition","value":"attachment; filename*=utf-8''x"}}],
                  "body":{{"data":"{attachment}"}}}},
                {{"mimeType":"text/html","body":{{"data":"{real}"}}}}
            ]}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a well-formed full body must map");

        assert_eq!(raw.html.as_deref(), Some("<p>the real html body</p>"));
        assert_eq!(
            raw.attachments.count, 1,
            "an attachment-disposition part counts even when it names no filename"
        );
    }

    #[test]
    fn fetch_body_a_message_whose_only_textual_part_is_an_attachment_is_no_textual_body() {
        // The NoTextualBody shape (text AND html both `None`) with the attachment still counted —
        // never a body fabricated out of attachment bytes.
        let attachment = b64url_encode("ATTACHMENT BYTES THAT MUST NOT CROSS IPC");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/mixed","parts":[
                {{"mimeType":"text/plain","filename":"transcript.txt","body":{{"data":"{attachment}"}}}}
            ]}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("an attachment-only message is still a mappable body");

        assert_eq!(raw.text, None, "attachment bytes are not a body");
        assert_eq!(raw.html, None);
        assert!(raw.attachments.has_attachments);
        assert_eq!(raw.attachments.count, 1);
    }

    #[test]
    fn fetch_body_never_spends_a_wire_call_resolving_an_attachment_id_of_an_attachment_part() {
        // The strongest form: a textual ATTACHMENT delivered behind an `attachmentId` must
        // not even be FETCHED. A single response is queued, so a leak panics on an empty queue.
        let body = r#"{"id":"M1","payload":{"mimeType":"multipart/mixed","parts":[
            {"mimeType":"text/plain","filename":"big.txt","body":{"attachmentId":"ATT-1"}}
        ]}}"#;
        let (transport, probe) = fixture(vec![resp(200, body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("an attachment-only message is still a mappable body");

        assert_eq!(raw.text, None);
        assert_eq!(
            probe.calls().len(),
            1,
            "only the full-message GET — the attachment's bytes are never fetched: {:?}",
            probe.calls()
        );
    }

    // ---- an attachment part terminates its whole SUBTREE ----

    #[test]
    fn fetch_body_never_descends_into_an_attached_message_subtree() {
        // Regression test: skipping only the attachment PART left its CHILDREN reachable:
        // an attached `message/rfc822` carries its own `text/plain`, and that child bears no
        // `filename` and no attachment disposition of its own — it is unmarked, so the walk
        // selected it as the body. Those are attachment bytes on the IPC boundary by another door.
        let attached = b64url_encode("FORWARDED MESSAGE BODY THAT MUST NOT CROSS IPC");
        let real = b64url_encode("the real body");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/mixed","parts":[
                {{"mimeType":"message/rfc822","filename":"forwarded.eml","parts":[
                    {{"mimeType":"text/plain","body":{{"data":"{attached}"}}}}
                ]}},
                {{"mimeType":"text/plain","body":{{"data":"{real}"}}}}
            ]}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a well-formed full body must map");

        assert_eq!(
            raw.text.as_deref(),
            Some("the real body"),
            "the attached message's own text part is INSIDE an attachment — the body is the \
             message's own text/plain part, not the forwarded one"
        );
        assert_eq!(raw.attachments.count, 1, "the attached message counts, once");
        assert!(raw.attachments.has_attachments);
    }

    #[test]
    fn fetch_body_an_attachment_container_with_only_attached_text_is_no_textual_body() {
        // The same seal, with nothing else in the message: a `multipart/mixed` marked
        // `Content-Disposition: attachment` (an attached bundle) whose children are a text part and
        // an image. NOTHING inside it is body — the honest answer is the NoTextualBody shape — and
        // the count is the LISTING route's count for the same tree (the container plus the nested
        // attachment), so the two routes still agree on how many attachments this message has.
        let attached = b64url_encode("BUNDLED TEXT THAT MUST NOT CROSS IPC");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/mixed","parts":[
                {{"mimeType":"multipart/mixed",
                  "headers":[{{"name":"Content-Disposition","value":"attachment"}}],
                  "parts":[
                    {{"mimeType":"text/plain","body":{{"data":"{attached}"}}}},
                    {{"mimeType":"image/png","filename":"logo.png","body":{{"attachmentId":"ATT-1"}}}}
                  ]}}
            ]}}}}"#
        );
        let (transport, probe) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("an attachment-only message is still a mappable body");

        assert_eq!(raw.text, None, "bytes inside an attachment container are not a body");
        assert_eq!(raw.html, None);
        assert!(raw.attachments.has_attachments);
        assert_eq!(
            raw.attachments.count, 2,
            "the container AND the nested attachment — the same count the listing route's scan \
             reports for this tree"
        );
        assert_eq!(probe.calls().len(), 1, "no part inside the container is ever fetched");
    }

    // ---- the body-route wire bound covers a two-body envelope ----

    #[test]
    fn fetch_body_accepts_a_legitimate_multipart_alternative_with_both_bodies_at_the_cap() {
        // Regression test. `MAX_BODY_FETCH_WIRE_BYTES` was sized for ONE body
        // (BODY_FETCH_CAP * 4/3 + 64 KiB), but a perfectly ordinary `multipart/alternative` carries
        // TEXT AND HTML, each of which the contract allows up to BODY_FETCH_CAP. Contract-compliant
        // mail was therefore refused on the wire and shown to the user as an error.
        let plain = "a".repeat(BODY_FETCH_CAP - 1);
        let markup = "b".repeat(BODY_FETCH_CAP - 1);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/alternative","parts":[
                {{"mimeType":"text/plain","body":{{"data":"{}"}}}},
                {{"mimeType":"text/html","body":{{"data":"{}"}}}}
            ]}}}}"#,
            b64url_encode(&plain),
            b64url_encode(&markup)
        );
        // The fixture is LEGITIMATE by the contract's own numbers — each decoded body is under the
        // per-body cap — and it can only pass a bound sized for TWO bodies.
        assert!(plain.len() <= BODY_FETCH_CAP && markup.len() <= BODY_FETCH_CAP);
        assert!(
            body.len() as u64 > BODY_FETCH_CAP as u64 * 4 / 3 + 65_536,
            "the fixture must exceed the OLD one-body bound, or it witnesses nothing"
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a contract-compliant two-body message must be readable");

        assert_eq!(raw.text.as_deref(), Some(plain.as_str()));
        assert_eq!(raw.html.as_deref(), Some(markup.as_str()));
        assert!(!raw.text_truncated, "text did not reach the per-body cap");
        assert!(!raw.html_truncated, "html did not reach the per-body cap");
    }

    // ---- the wire bound must cover a legitimate MULTI-LEAF forwarded message ----

    #[test]
    fn fetch_body_accepts_a_forwarded_message_with_three_inline_textual_leaves() {
        // Regression test: a `format=full` response is not bounded to ONE text/plain and
        // ONE text/html leaf — every quoted layer of a forwarded-and-forwarded-again message is
        // its own `multipart/alternative` pair, so a perfectly ordinary three-leaf inline shape
        // (two `text/plain` leaves plus one `text/html` leaf, each near BODY_FETCH_CAP) puts more
        // encoded bytes on the wire than the OLD two-body-derived bound (3,190,954) admitted, even
        // though `walk_body_parts` only ever SELECTS the first of each mime type.
        let first_plain = "a".repeat(BODY_FETCH_CAP - 1);
        let quoted_plain = "q".repeat(BODY_FETCH_CAP - 1);
        let markup = "b".repeat(BODY_FETCH_CAP - 1);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"multipart/mixed","parts":[
                {{"mimeType":"multipart/alternative","parts":[
                    {{"mimeType":"text/plain","body":{{"data":"{}"}}}},
                    {{"mimeType":"text/html","body":{{"data":"{}"}}}}
                ]}},
                {{"mimeType":"multipart/alternative","parts":[
                    {{"mimeType":"text/plain","body":{{"data":"{}"}}}}
                ]}}
            ]}}}}"#,
            b64url_encode(&first_plain),
            b64url_encode(&markup),
            b64url_encode(&quoted_plain)
        );
        let old_two_body_bound = 2 * (BODY_FETCH_CAP as u64 * 4 / 3) + 524_288;
        assert!(
            body.len() as u64 > old_two_body_bound,
            "the fixture must exceed the OLD two-body bound ({old_two_body_bound}), or it \
             witnesses nothing: body is {} bytes",
            body.len()
        );
        assert!(
            (body.len() as u64) < MAX_BODY_FETCH_WIRE_BYTES,
            "the fixture must fit under the NEW whole-response ceiling"
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a contract-compliant multi-leaf forwarded message must be readable");

        assert_eq!(
            raw.text.as_deref(),
            Some(first_plain.as_str()),
            "the FIRST text/plain leaf wins — the third, unselected leaf's bytes still had to fit \
             on the wire, but never displace the selection"
        );
        assert_eq!(raw.html.as_deref(), Some(markup.as_str()));
        assert!(!raw.text_truncated);
        assert!(!raw.html_truncated);
    }

    #[test]
    fn the_body_route_wire_bound_is_a_flat_16_mib_whole_response_ceiling() {
        // The bound is NO LONGER derived from a two-part count (a `format=full`
        // response legitimately carries more than two inline textual leaves — every quoted layer
        // of a forwarded-and-forwarded-again message is its own pair — so no part-count expression
        // over `BODY_FETCH_CAP` can be honest). It is a flat, named, generous whole-response
        // ceiling instead.
        assert_eq!(
            MAX_BODY_FETCH_WIRE_BYTES,
            16 * 1024 * 1024,
            "16 MiB, doc-commented as the whole-response memory-exhaustion ceiling"
        );
        let two_encoded_bodies = 2 * (BODY_FETCH_CAP as u64 * 4).div_ceil(3);
        assert!(
            MAX_BODY_FETCH_WIRE_BYTES > two_encoded_bodies,
            "still admits the ordinary text+html shape: bound {MAX_BODY_FETCH_WIRE_BYTES} vs \
             {two_encoded_bodies} encoded bytes"
        );
        // A fact about two compile-time constants — a `const` block, not a runtime assertion
        // (clippy::assertions_on_constants).
        const {
            assert!(
                MAX_BODY_FETCH_WIRE_BYTES > 12_524_288,
                "matches (and exceeds) the JMAP sibling's already-larger flat posture \
                 (aruna_jmap::transport::MAX_RESPONSE_WIRE_BYTES, 12,524,288 bytes)"
            );
        }
    }

    // ---- declared-charset transcoding ----

    #[test]
    fn fetch_body_decodes_an_iso_8859_1_declared_part_instead_of_refusing_it() {
        // `café` in ISO-8859-1: the é is the single byte 0xE9, which is NOT valid UTF-8 — strict
        // `from_utf8` refused the whole body read and the user saw nothing.
        let data = b64url_encode_bytes(&[b'c', b'a', b'f', 0xE9]);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain",
              "headers":[{{"name":"Content-Type","value":"text/plain; charset=ISO-8859-1"}}],
              "body":{{"data":"{data}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a declared latin-1 body decodes, never refuses");
        assert_eq!(raw.text.as_deref(), Some("café"));
    }

    #[test]
    fn fetch_body_decodes_windows_1252_including_the_0x80_0x9f_remaps() {
        // 0x92 is a RIGHT SINGLE QUOTATION MARK in windows-1252 and an undefined C1 control in
        // latin-1 — the byte that proves the 27-entry remap table is applied, not skipped.
        let data = b64url_encode_bytes(&[b'i', b't', 0x92, b's', b' ', 0x80]);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain",
              "headers":[{{"name":"CONTENT-TYPE","value":"text/plain; charset=\"windows-1252\""}}],
              "body":{{"data":"{data}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a declared windows-1252 body decodes");
        assert_eq!(raw.text.as_deref(), Some("it’s €"));
    }

    #[test]
    fn fetch_body_degrades_an_unknown_charset_readably_and_keeps_utf_8_strict() {
        // An unsupported declared charset is LOSSY-decoded (readable degradation), never a refusal
        // and never a silent wrong-bytes claim.
        let data = b64url_encode_bytes(&[b'o', b'k', 0xFF]);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain",
              "headers":[{{"name":"Content-Type","value":"text/plain; charset=shift_jis"}}],
              "body":{{"data":"{data}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);
        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("an unknown charset degrades readably");
        assert_eq!(raw.text.as_deref(), Some("ok\u{FFFD}"));

        // A part that DECLARES utf-8 and is not utf-8 stays a typed refusal: the declaration is
        // the sender's own claim, and honouring it is the strict path (no silent lossy rewrite).
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain",
              "headers":[{{"name":"Content-Type","value":"text/plain; charset=utf-8"}}],
              "body":{{"data":"{data}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);
        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("a lying utf-8 declaration is refused, exactly as before");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn charset_from_content_type_reads_quoted_bare_and_absent_forms() {
        for (header, want) in [
            ("text/plain; charset=ISO-8859-1", Some("iso-8859-1")),
            ("text/plain; charset=\"windows-1252\"", Some("windows-1252")),
            ("text/plain; CHARSET = us-ascii ; format=flowed", Some("us-ascii")),
            ("text/plain;charset=utf-8", Some("utf-8")),
            ("text/plain", None),
            ("text/plain; charset=", None),
        ] {
            assert_eq!(
                charset_from_content_type(header).as_deref(),
                want,
                "header: {header:?}"
            );
        }
    }

    /// Regression test: a SUBSTRING scan for `"charset"` matches inside `xcharset=`
    /// (and any other parameter whose NAME merely happens to contain the word), because the old
    /// implementation searched the whole header value as one string rather than walking its
    /// parameter list. A real `charset=` parameter appearing LATER in the same header must win.
    #[test]
    fn charset_from_content_type_respects_parameter_name_boundaries() {
        for (header, want) in [
            // The exact fixture: `xcharset` is a decoy — its NAME merely contains
            // the substring "charset". The real `charset` parameter, later in the list, must win.
            (
                "text/plain; xcharset=windows-1252; charset=utf-8",
                Some("utf-8"),
            ),
            // The decoy alone (no real charset param at all) must not match either.
            ("text/plain; xcharset=windows-1252", None),
            // A quoted VALUE that happens to contain the word "charset" must not fool the name
            // match either — the parser only looks at parameter NAMES, never scans values.
            (
                "text/plain; boundary=\"has charset inside\"; charset=iso-8859-1",
                Some("iso-8859-1"),
            ),
        ] {
            assert_eq!(
                charset_from_content_type(header).as_deref(),
                want,
                "header: {header:?}"
            );
        }
    }

    /// End-to-end regression test, the exact dispatch fixture: `xcharset=windows-1252`
    /// (a decoy whose NAME merely contains the substring "charset") precedes the real
    /// `charset=utf-8` parameter. Pre-fix the substring scan picked `windows-1252` off the decoy;
    /// the body bytes are valid UTF-8, so decoding them as windows-1252 (a latin-1 superset)
    /// produces mangled non-ASCII output instead of the plain ASCII the fixture actually carries
    /// unchanged either way — the byte-identity assertion below is what actually distinguishes the
    /// two decode paths for a non-ASCII payload.
    #[test]
    fn fetch_body_picks_the_real_charset_param_not_a_name_that_merely_contains_the_word() {
        // 0xE9 is UTF-8-invalid on its own, so decoding it as "windows-1252" (the decoy) would
        // succeed with a WRONG character, while decoding the actual utf-8-encoded "café" bytes
        // under the real `charset=utf-8` parameter must round-trip exactly.
        let data = b64url_encode_bytes("café".as_bytes());
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain",
              "headers":[{{"name":"Content-Type","value":"text/plain; xcharset=windows-1252; charset=utf-8"}}],
              "body":{{"data":"{data}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("the real charset=utf-8 parameter must be honoured");
        assert_eq!(
            raw.text.as_deref(),
            Some("café"),
            "decoding under the decoy's windows-1252 would corrupt the multi-byte é"
        );
    }

    #[test]
    fn fetch_body_resolves_a_textual_part_behind_an_attachment_id_the_attachment_fetch_edge() {
        let text = b64url_encode("large plain text delivered behind an attachment id");
        let full_body =
            r#"{"id":"M1","payload":{"mimeType":"text/plain","body":{"attachmentId":"ATT-1"}}}"#;
        let attachment_body = format!(r#"{{"data":"{text}"}}"#);
        let (transport, probe) =
            fixture(vec![resp(200, full_body), resp(200, &attachment_body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a textual part behind attachmentId must resolve via the dedicated fetch");

        assert_eq!(raw.text.as_deref(), Some("large plain text delivered behind an attachment id"));

        let calls = probe.calls();
        assert_eq!(calls.len(), 2, "the full-message GET, then the attachments.get GET");
        assert!(calls[1].0.contains("/messages/M1/attachments/ATT-1"), "url: {}", calls[1].0);
    }

    /// Regression test: a padded `body.data` is an ordinary
    /// Gmail answer, and the whole body read used to fail deterministically on it.
    #[test]
    fn fetch_body_decodes_a_terminally_padded_body_data_field() {
        let data = b64url_encode_padded("padded body text");
        assert!(data.ends_with('='), "the fixture must actually carry padding: {data:?}");
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain","body":{{"data":"{data}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("a padded base64url body must decode, never refuse the whole message");
        assert_eq!(raw.text.as_deref(), Some("padded body text"));
    }

    /// Regression test: an EMPTY inline `data` beside an `attachmentId` is Gmail saying
    /// "the bytes are not here, fetch them", not "this message is blank". Reading the empty string
    /// as the content produced a silently blank body.
    #[test]
    fn fetch_body_empty_inline_data_beside_an_attachment_id_falls_back_to_the_fetch() {
        let text = b64url_encode("the real text, delivered behind the attachment id");
        let full_body = r#"{"id":"M1","payload":{"mimeType":"text/plain",
            "body":{"data":"","attachmentId":"ATT-1"}}}"#;
        let attachment_body = format!(r#"{{"data":"{text}"}}"#);
        let (transport, probe) = fixture(vec![resp(200, full_body), resp(200, &attachment_body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("the body read must resolve the attachment id");

        assert_eq!(
            raw.text.as_deref(),
            Some("the real text, delivered behind the attachment id"),
            "empty inline data with an attachmentId present is ABSENT data, never a blank body"
        );
        let calls = probe.calls();
        assert_eq!(calls.len(), 2, "the full-message GET, then the attachments.get GET");
        assert!(calls[1].0.contains("/messages/M1/attachments/ATT-1"), "url: {}", calls[1].0);
    }

    /// The other side of that boundary: an empty `data` with NO attachment id is a genuinely empty
    /// part, and stays an empty string — the fallback must not invent a fetch that has no id.
    #[test]
    fn fetch_body_empty_inline_data_with_no_attachment_id_is_an_empty_part() {
        let body = r#"{"id":"M1","payload":{"mimeType":"text/plain","body":{"data":""}}}"#;
        let (transport, probe) = fixture(vec![resp(200, body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("an empty inline part is still a valid body");
        assert_eq!(raw.text.as_deref(), Some(""));
        assert_eq!(probe.calls().len(), 1, "no attachment id ⇒ no second round trip");
    }

    #[test]
    fn fetch_body_a_textual_part_with_neither_data_nor_attachment_id_is_a_typed_error() {
        let body = r#"{"id":"M1","payload":{"mimeType":"text/plain","body":{}}}"#;
        let (transport, _) = fixture(vec![resp(200, body)]);
        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("a textual part with no content source must refuse, never fabricate");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn fetch_body_refuses_multipart_nesting_past_the_depth_bound_loudly() {
        // Build MAX_PART_DEPTH + 2 levels of pure nesting wrapper, so the walk must cross the
        // bound before it ever reaches the innermost textual leaf.
        let mut part = r#"{"mimeType":"text/plain","body":{"data":"AA"}}"#.to_string();
        for _ in 0..(MAX_PART_DEPTH + 2) {
            part = format!(r#"{{"mimeType":"multipart/mixed","parts":[{part}]}}"#);
        }
        let body = format!(r#"{{"id":"M1","payload":{part}}}"#);
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("nesting past the bound must refuse loudly, never silently truncate");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn fetch_body_truncates_at_the_cap_on_a_char_boundary() {
        // A repeated 3-byte UTF-8 character so a naive byte-index cut would split one — proving
        // the clip lands on a real `char` boundary, not merely under the cap.
        let ch = '€';
        let count = (BODY_FETCH_CAP / ch.len_utf8()) + 4;
        let big: String = std::iter::repeat_n(ch, count).collect();
        assert!(big.len() > BODY_FETCH_CAP, "the fixture must actually exceed the cap");
        let encoded = b64url_encode(&big);
        let body = format!(
            r#"{{"id":"M1","payload":{{"mimeType":"text/plain","body":{{"data":"{encoded}"}}}}}}"#
        );
        let (transport, _) = fixture(vec![resp(200, &body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect("an oversize decoded body is truncated, not refused");

        assert!(raw.text_truncated);
        assert!(!raw.html_truncated, "no html part was present to truncate");
        let text = raw.text.expect("truncation still returns the clipped prefix");
        assert!(text.len() <= BODY_FETCH_CAP, "clipped length {} must not exceed the cap", text.len());
        assert!(
            text.len() > BODY_FETCH_CAP - ch.len_utf8(),
            "the clip must land at the LAST valid char boundary at-or-below the cap, not earlier"
        );
        assert!(text.chars().all(|c| c == '€'), "every clipped char must be well-formed");
    }

    /// Regression test: a textual part behind `attachmentId` whose decoded size sits
    /// comfortably above the OLD shared two-representation wire cap (~2.39 MB) used to fail the
    /// whole body read with a deterministic error, instead of the truncated [`BODY_FETCH_CAP`]
    /// prefix every OTHER oversize source in this file already promises (see
    /// [`fetch_body_truncates_at_the_cap_on_a_char_boundary`] for the inline-data sibling of this
    /// exact contract). 2.5 MB decoded needs ~3,333,334 encoded bytes — over the old
    /// `MAX_BODY_FETCH_WIRE_BYTES` (3,190,954) but well inside the new, attachment-specific
    /// `MAX_ATTACHMENT_FETCH_WIRE_BYTES` (5,857,621).
    #[test]
    fn fetch_body_truncates_an_oversized_textual_attachment_instead_of_refusing_it() {
        const DECODED_LEN: usize = 2_500_000;
        // A fact about two compile-time constants — a `const` block, not a runtime assertion
        // (clippy::assertions_on_constants).
        const {
            assert!(DECODED_LEN > BODY_FETCH_CAP, "the fixture must exceed the final truncation cap");
        }
        let big: String = std::iter::repeat_n('a', DECODED_LEN).collect();
        let encoded = b64url_encode(&big);
        // Raised `MAX_BODY_FETCH_WIRE_BYTES` to a flat 16 MiB, so this fixture no
        // longer exceeds the CURRENT `BodyFetch` cap — it never needs to: what this self-check
        // proves is the historical regression, against the shared cap AS IT
        // STOOD then (3,190,954 bytes, two capped bodies + margin, before the routes split). That
        // number is a fixed historical fact now, not the live constant.
        const OLD_SHARED_WIRE_CAP_BEFORE_R10_F2: u64 = 3_190_954;
        assert!(
            encoded.len() as u64 > OLD_SHARED_WIRE_CAP_BEFORE_R10_F2,
            "the fixture must exceed the OLD shared wire cap ({encoded_len} vs {old_cap}) — \
             otherwise this is not the F2 regression at all",
            encoded_len = encoded.len(),
            old_cap = OLD_SHARED_WIRE_CAP_BEFORE_R10_F2,
        );
        assert!(
            encoded.len() as u64 + 64 < MAX_ATTACHMENT_FETCH_WIRE_BYTES,
            "the fixture must still fit the NEW attachment-only wire cap, with margin for the \
             surrounding JSON"
        );
        let full_body =
            r#"{"id":"M1","payload":{"mimeType":"text/plain","body":{"attachmentId":"ATT-1"}}}"#;
        let attachment_body = format!(r#"{{"data":"{encoded}"}}"#);
        let (transport, probe) =
            fixture(vec![resp(200, full_body), resp(200, &attachment_body)]);

        let raw = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect(
                "an oversized textual attachment must be truncated at BODY_FETCH_CAP, never \
                 refused outright",
            );

        assert!(
            raw.text_truncated,
            "the oversized attachment representation must be marked truncated"
        );
        let text = raw.text.expect("truncation still returns the clipped prefix");
        assert_eq!(text.len(), BODY_FETCH_CAP, "an all-ASCII fixture clips exactly at the cap");
        assert!(text.chars().all(|c| c == 'a'), "every clipped char must be well-formed");
        assert_eq!(probe.calls().len(), 2, "the full-message GET, then the attachments.get GET");
    }

    #[test]
    fn fetch_body_malformed_json_is_a_typed_error_never_a_panic() {
        let (transport, _) = fixture(vec![resp(200, "{not valid")]);
        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("malformed JSON must be a typed refusal");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn fetch_body_an_id_mismatched_response_is_refused_the_misrouting_guard() {
        let body = r#"{"id":"SOME-OTHER-MESSAGE","payload":{"mimeType":"text/plain","body":{"data":"QQ"}}}"#;
        let (transport, _) = fixture(vec![resp(200, body)]);
        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("a response for a different message must never feed a body");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    #[test]
    fn fetch_body_propagates_the_shared_status_classifier_on_401_and_403() {
        let (transport, _) = fixture(vec![resp(401, "")]);
        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("401 must surface through the shared classifier");
        assert_eq!(err, GmailError::Unauthorized);

        let body = r#"{"error":{"code":403,"errors":[{"domain":"global","reason":"insufficientPermissions"}]}}"#;
        let (transport, _) = fixture(vec![resp(403, body)]);
        let err = transport
            .fetch_body(&user("me"), &message("M1"))
            .expect_err("403 must surface through the shared classifier");
        assert_eq!(err, GmailError::Forbidden);
    }

    #[test]
    fn fetch_body_and_list_inbox_page_never_pass_through_the_destructive_write_gate() {
        // A CLOSED-gate production transport must still answer these reads — they are not writes.
        let fake = FakeHttp::new(vec![
            resp(200, r#"{"messages":[]}"#),
            resp(200, r#"{"id":"M1","payload":{}}"#),
        ]);
        let transport = GatedTransport::production_with(fake);
        assert!(transport.list_inbox_page(&user("me"), 50, None).is_ok());
        assert!(transport.fetch_body(&user("me"), &message("M1")).is_ok());
    }

    // ---- the public facade forwards both new methods (HttpGmailTransport) ----

    #[test]
    fn http_gmail_transport_forwards_list_inbox_page_and_fetch_body_refusals_identically() {
        // `HttpGmailTransport` cannot be constructed over a `FakeHttp` (it is hard-wired to
        // `ReqwestClient`), so this proves the forwarding shape the same way the crate already
        // proves it elsewhere: identifier refusals happen before any client is consulted, so a
        // production-constructed instance answers identically regardless of the client behind it.
        let transport = HttpGmailTransport::connect("token").expect("construct");
        let err = transport
            .list_inbox_page(&GmailUserId("..".to_string()), 50, None)
            .expect_err("a dot-segment userId must be refused pre-wire");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);

        let err = transport
            .fetch_body(&GmailUserId("me".to_string()), &GmailMessageId("..".to_string()))
            .expect_err("a dot-segment message id must be refused pre-wire");
        assert_eq!(classify_gmail_error(&err), FailureKind::Deterministic);
    }

    // -------------------------------------------------------------------------------------------
    // PERMANENT DELETION IS UNCONSTRUCTIBLE: the HTTP seam's verb set.
    // Gmail's `users.messages.delete` (`DELETE .../users/{userId}/messages/{id}`, "cannot be
    // undone") is the one route that bypasses the trash for a message, and it needs the
    // full-mailbox scope this product never requests. This transport's `HttpClient` exposes
    // exactly THREE methods — two POST shapes (`post_json`, and the bodiless
    // `post_empty` that `trash`/`untrash` ride) and one GET (`get`) — so there is still no verb
    // for THAT route to be issued through.
    //
    // WHAT THIS PIN IS NOT:
    // the verb set is NOT an independent safety leg. Gmail's BULK permanent-delete route is a
    // **POST**, and the draft-deletion route is authorized by `gmail.modify` itself — so "no
    // DELETE verb on the seam" closes neither of those on its own. The load-bearing legs are
    // SCOPE (messages and threads: the exact set `{gmail.modify}` cannot permanently delete
    // them) and ROUTE-AND-BODY (everything else: this transport constructs exactly the
    // `{modify, trash, untrash, get, list, attachment}` routes, with label-only bodies on
    // `modify` and no body at all on `trash`/`untrash` — see
    // `the_production_modify_url_is_the_compiled_endpoint_route`,
    // `trash_url_and_untrash_url_are_the_dedicated_endpoints_with_the_field_mask`,
    // `the_get_message_url_carries_both_composed_parameters`,
    // `the_attachment_fetch_route_resolves_its_own_wire_cap` and
    // `the_request_body_is_the_connector_built_request_and_only_the_two_label_arrays`).
    //
    // The route names those two legs turn on are DELIBERATELY not spelled here: the sibling
    // source scan (`tests/permanent_delete_non_construction.rs`) greps THIS file for exactly
    // that vocabulary, so writing it down — even in a comment explaining why we do not build it
    // — would trip the tripwire. The scan's own module doc carries the full names and citations.
    //
    // THIS IS A COMPILE-LEVEL PIN, and its discriminating power is the compiler's: the struct
    // below implements the trait with those three methods and NOTHING else. Adding a fourth
    // required method to `HttpClient` — `delete`, or any other — makes this file stop compiling
    // (E0046, "not all trait items implemented"), which is a REVIEW MOMENT: a new verb on this
    // seam is a decision someone must make on purpose. `post_empty` took exactly that
    // path — E0046 named all three impls, this pin among them — and it adds a POST shape, not a
    // new HTTP verb. A tripwire and hygiene, deliberately not labelled a
    // control — a statement about the SEAM's surface, never a behavioural proof about a live
    // wire.
    // -------------------------------------------------------------------------------------------
    struct VerbSetPin;

    impl HttpClient for VerbSetPin {
        fn post_json(
            &self,
            _url: &str,
            _body: &serde_json::Value,
        ) -> Result<HttpResponse, GmailError> {
            Err(refused())
        }

        fn post_empty(&self, _url: &str) -> Result<HttpResponse, GmailError> {
            Err(refused())
        }

        fn get(&self, _url: &str, _route: WireRoute) -> Result<HttpResponse, GmailError> {
            Err(refused())
        }
    }

    #[test]
    fn the_http_seam_exposes_exactly_post_json_post_empty_and_get_so_no_delete_verb_exists() {
        // The pin's own liveness: if this ever stops being a full implementation, the file does
        // not compile and the test cannot run at all.
        let pin = VerbSetPin;
        assert!(pin.post_json("https://example.invalid/", &serde_json::json!({})).is_err());
        assert!(pin.post_empty("https://example.invalid/").is_err());
        assert!(pin.get("https://example.invalid/", WireRoute::Generic).is_err());
    }
}
