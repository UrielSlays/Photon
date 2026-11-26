//! Live HTTP Gmail transport for the Photon engine (`aruna`).
//!
//! Implements `aruna::gmail::GmailTransport` against the real Gmail REST API
//! (`users.messages.modify`) over a hand-rolled `reqwest::blocking` + serde surface.
//! Compile-isolated from the engine crate so the HTTP/TLS dependency tree never reaches
//! `aruna` (workspace rule, root `Cargo.toml`). The crate exists to show that the
//! `GmailTransport` seam fits a live transport without any change to `crates/aruna/**`.
//!
//! ```no_run
//! use aruna::gmail::{GmailError, GmailMessageId, GmailTransport, GmailUserId};
//! use aruna_gmail::HttpGmailTransport;
//!
//! // Production connect takes NO base URL — the endpoint is compiled in — and the
//! // destructive-write gate starts CLOSED, so this `modify_labels` is refused
//! // deterministically BEFORE any socket is opened. Opening the gate requires a
//! // loopback host, which `gmail.googleapis.com` can never be.
//! let transport = HttpGmailTransport::connect("ya29.caller-supplied-access-token")?;
//! # let request = unimplemented!("built by aruna's GmailConnector, never by hand");
//! let refused = transport.modify_labels(
//!     &GmailUserId("me".to_string()),
//!     &GmailMessageId("18f0a1b2c3d4e5f6".to_string()),
//!     request,
//! );
//! assert!(refused.is_err());
//! # Ok::<(), GmailError>(())
//! ```
//!
//! # Public surface
//!
//! [`HttpGmailTransport`] is the only public way to reach Gmail from this crate. The HTTP seam
//! underneath it (the bearer-token newtype, the `HttpClient` trait, its completed-exchange type
//! and the `reqwest` implementation) is `pub(crate)`, keeping the API narrow.
//!
//! This is API hygiene, not a security boundary. Reaching those items takes compiling Rust into
//! this binary, and anyone with that power can equally delete the [`DestructiveWriteGate`] or edit
//! [`GMAIL_ENDPOINT`]; code already running on the user's machine is out of scope. The
//! mechanisms face different audiences. The response bounds, the strict body decode, the
//! taxonomy's status-first precedence and the applied-state check face untrusted provider data.
//! The compiled endpoint, `.no_proxy()` and the redirect refusal govern where a credentialed
//! request may egress. The identifier rules and the default-closed gate guard against mistaken
//! first-party callers.
//!
//! # Why not `google-gmail1`
//!
//! `google-gmail1` (the generated `google-apis-rs` client) is deliberately not adopted: (a) it is
//! async on the hyper/yup-oauth2 stack, while the workspace keeps transports on blocking reqwest
//! with a lean tree (the same reason the JMAP crate rejected `jmap-client`); (b) this crate's job
//! is faithful error-body normalization at our taxonomy boundary, and a generated client's error
//! envelope sits between us and the bytes we must classify; (c) the surface is exactly one
//! method. The residual risk is shape drift versus the real API, bounded by pinning to the
//! primary sources (the `users.messages.modify` reference and the Gmail error guide) and by a
//! future attended drill.
//!
//! # Differences from the JMAP transport
//!
//! `aruna-jmap`'s transport is the model for this one, but four of its mechanisms failed
//! probing against Gmail and are rejected here:
//!
//! - **Redirect-following** (JMAP bounds redirects to the same authority). reqwest replays a
//!   cloneable mutation body across 307/308 and strips sensitive headers only when the host
//!   changes, so a same-authority redirect re-POSTs the authenticated mutation to a
//!   server-chosen path, and Gmail's whole request identity lives in the path. This transport
//!   uses `redirect::Policy::none()`; any 3xx is a terminal deterministic failure.
//! - **Per-request call-id correlation.** Gmail REST is one operation per HTTP request, so there
//!   is no call-id protocol. Instead the response `Message.id` is correlated with the request
//!   and the label postcondition is checked. A resource id carries no freshness, so this is a
//!   mis-routing check, not a replay nonce.
//! - **`PathSegmentsMut` as the injection defense.** `push` percent-encodes `/ ? # %` and NUL but
//!   elides exact `.`/`..` segments, shifting the route. Identifiers are validated before any
//!   URL is built.
//! - **Blanket transport-error to Transient.** A failure that is not provably pre-dispatch may
//!   have applied the mutation, and re-dispatching would rely on a provider idempotency
//!   property nobody has proven.
//!
//! Carried over unchanged: the `.no_proxy()` egress refusal, the default-closed
//! `DestructiveWriteGate`, credential/endpoint redaction, and deterministic
//! TLS-certificate/builder classification.
//!
//! # Endpoint identity
//!
//! Production `connect(token)` takes no base URL: the URL is built internally from one compiled
//! endpoint constant (the discovery `rootUrl`, `https://gmail.googleapis.com/`, path exactly `/`).
//! There is nothing to allowlist or normalize, and no parameter through which a typosquat or a
//! proxy prefix could be passed. Only `connect_for_test_fixture(origin, token)` accepts a base,
//! and it is loopback-only and origin-only.
//!
//! mTLS is unsupported. Google publishes a second endpoint, `https://gmail.mtls.googleapis.com/`,
//! which this crate cannot reach because it has no client-certificate machinery. Adding it is a
//! reviewed change, never a widening of the host rule to a `*.googleapis.com` suffix match.
//!
//! # OAuth account mode
//!
//! Auth is a caller-supplied OAuth2 bearer access token. There is no flow, refresh or
//! persistence, so HTTP 401 stays deterministic in this crate. `gmail.modify` is a restricted
//! scope for public OAuth apps; `gmail.modify.restricted` and domain-wide delegation are an
//! administrator path with different authority semantics, and a Workspace admin can restrict or
//! revoke a high-risk scope, producing deterministic authorization/domain-policy failures with a
//! syntactically valid token. Settle which account mode the token comes from before running any
//! attended drill.
//!
//! # Real-provider drill
//!
//! No real-provider write occurs from this crate. Two independent guards apply: ADR Part III
//! (real-provider destructive execution disabled until the validation gate passes) and the
//! pre-state/snapshot exit criterion (pre-state/snapshot must land before any real-provider,
//! Part-III-ungated YELLOW+ write). The transport's [`DestructiveWriteGate`] is default-closed
//! and can only be opened for a loopback host, so `gmail.googleapis.com` cannot be authorized;
//! a test checks that refusal.
//!
//! Runbook for a future operator-attended, env-gated drill (not in this crate yet):
//!
//! 1. Land the pre-state/snapshot capability; confirm the ADR Part III gate is open for the drill account.
//! 2. Establish the account mode and scope (above) and mint a short-lived bearer token out of band.
//! 3. Add an env-gated integration test that makes its own independent `messages.get`
//!    read-backs. The transport's applied-state check must not be the drill's oracle: for
//!    `set_seen(true)` against an already-read message both of its conjuncts pass with no
//!    mutation performed, so it cannot see the difference an idempotency proof must measure.
//! 4. A production-authority gate is its own reviewed change. This crate's loopback test is no
//!    proof of it, and endpoint identity must stay a compiled property.
//!
//! Two further preconditions before any production `RateLimit` classification is exercised: a
//! typed `Retry-After` hint plus a real scheduler/jitter path in the engine (the existence of
//! `backoff_delay()` does not satisfy it), and an explicit `Ambiguous` outcome state reconciled
//! via the read path instead of guessing.
//!
//! # Wording
//!
//! A `Failed` outcome from this transport means "not proven applied", never "no provider
//! effect".

// Wire to taxonomy normalization (pure, hermetic).
pub mod error;
// The live `HttpGmailTransport` (reqwest::blocking) and the pure host/URL/applied-state helpers it uses.
pub mod transport;

pub use error::map_error_response;
// Only the transport facade; `BearerToken`, `HttpClient`, `HttpResponse` and `ReqwestClient`
// are omitted because nothing outside this crate needs them.
pub use transport::{
    DestructiveWriteGate, GateError, GmailProviderPlacement, HttpGmailTransport, GMAIL_ENDPOINT,
    MAX_ERROR_BODY_BYTES, MAX_SUCCESS_BODY_BYTES,
};
