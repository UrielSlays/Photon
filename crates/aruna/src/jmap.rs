//! JMAP provider connector: archive/unarchive over a JMAP-shaped transport.
//!
//! The first real provider connector: it derives the engine's `FailureKind` from JMAP's actual
//! error model (RFC 8620/8621), translates `Action` into an `Email/set` mailbox move, and keeps
//! all provider-native ids (Email, Mailbox, account) below the seam. Tested against an in-memory
//! JMAP-shaped fake with no live network, so ADR-P010's "real destructive execution disabled
//! until the validation gate" holds. Design: `docs/design/2026-06-24-jmap-connector-design.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::prestate::{native_resource_key, Freshness, FrozenBasis, Observation};
use crate::read_model::ProviderMessageId;
use crate::read_surface::{ContinuationToken, ListedPage, RawBody};
use crate::{
    action_message_ref, Action, Command, Connector, ConnectorError, FailureKind, LogError, MailFlag,
    ResolveBasisError,
};

// Error taxonomy: the single home for the transient-vs-deterministic policy (RFC 8620/8621).

/// A normalized JMAP error: the connector's internal error vocabulary, decoupled from any
/// wire/library type so adopting a JMAP client does not ripple into the taxonomy. Every layer
/// JMAP can fail at maps into one variant here, and `classify_jmap_error` is the single home
/// for the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JmapError {
    /// Request-level problem-details (RFC 8620 §3.6.1, `urn:ietf:params:jmap:error:*`).
    Request(RequestError),
    /// Method-level error (RFC 8620 §3.6.2): the whole method call failed.
    Method(MethodError),
    /// Per-record `SetError` (RFC 8620 §5.3 + RFC 8621 mail-specific).
    Set(SetError),
    /// Transport/HTTP/TCP layer, below JMAP semantics.
    Transport(TransportError),
}

/// Request-level problem-details types (RFC 8620 §3.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// A server-defined `limit` was reached (RFC 8620 §3.6.1). Which limit decides the policy: a
    /// concurrency limit lifts on retry; a fixed-shape limit (request too large, too many calls)
    /// fails identically every time.
    Limit(RequestLimit),
    /// The client requested a capability the server does not support.
    UnknownCapability,
    /// The request body was not valid JSON.
    NotJson,
    /// The request was valid JSON but not a valid JMAP Request object.
    NotRequest,
    /// An unrecognized request-level type — fail closed.
    Unknown,
}

/// Which server limit an RFC 8620 request-level `limit` error names. Concurrency limits lift on
/// retry; fixed-shape limits never will, so retrying the identical request only burns the DLQ
/// budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestLimit {
    /// `maxConcurrentRequests` — too many in flight; back off and retry (transient).
    MaxConcurrentRequests,
    /// `maxSizeRequest` — this request body is too large; retrying it unchanged fails again.
    MaxSizeRequest,
    /// `maxCallsInRequest` — too many method calls in this batch; deterministic for the same batch.
    MaxCallsInRequest,
    /// Any other / unrecognized named limit — fail closed.
    Other,
}

/// Method-level error types (RFC 8620 §3.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodError {
    /// Some internal resource was temporarily unavailable; retry may succeed.
    ServerUnavailable,
    /// Too many calls recently; a server rate limit was reached — lifts later.
    RateLimit,
    /// An unexpected error; **no state change, retry is expected to fail again** (RFC 8620).
    ServerFail,
    /// A partial change occurred; the client **MUST resync** to learn the state — not a blind retry.
    ServerPartialFail,
    /// The method arguments were invalid (malformed request — will not self-heal).
    InvalidArguments,
    /// A result reference could not be resolved.
    InvalidResultReference,
    /// The server does not recognize this method.
    UnknownMethod,
    /// The accountId does not correspond to a valid account.
    AccountNotFound,
    /// The account is read-only; this mutation is forbidden.
    AccountReadOnly,
    /// The account does not support this method.
    AccountNotSupportedByMethod,
    /// The action would violate an ACL or permissions policy.
    Forbidden,
    /// `ifInState` did not match (optimistic concurrency): requires refetch/rebase, not retry.
    /// Not emitted today (we do not send `ifInState`).
    StateMismatch,
    /// An unrecognized method-level type. RFC 8620: a client receiving an unknown error type
    /// **MUST treat it the same as `serverFail`**.
    Unknown,
}

/// Per-record `SetError` types (RFC 8620 §5.3 + RFC 8621 mail-specific).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetError {
    /// A server rate limit on creates — lifts later.
    RateLimit,
    /// The id to update/destroy could not be found.
    NotFound,
    /// The mutation would violate an ACL or permissions policy.
    Forbidden,
    /// The PatchObject was not a valid patch.
    InvalidPatch,
    /// The record/patch was invalid per the type spec.
    InvalidProperties,
    /// The change would exceed a server-defined size limit.
    TooLarge,
    /// A singleton record cannot be created/destroyed this way.
    Singleton,
    /// Destroying the record requires explicit confirmation.
    WillDestroy,
    /// A server-defined object count/size quota would be exceeded.
    OverQuota,
    /// RFC 8621: the email would be in more mailboxes than the server allows.
    TooManyMailboxes,
    /// RFC 8621: a per-mailbox count limit would be exceeded.
    MailboxCounts,
    /// An unrecognized SetError type — fail closed.
    Unknown,
}

/// Transport/HTTP/TCP failures, below JMAP semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The request timed out.
    Timeout,
    /// The connection was reset/dropped.
    ConnectionReset,
    /// HTTP 429 Too Many Requests.
    TooManyRequests,
    /// An HTTP 5xx server error.
    ServerError(u16),
    /// HTTP 401/403, an auth failure. Deterministic for now (no refresh path); an OAuth refresh
    /// would reopen 401 as a "refresh-then-retry" third path the binary kind cannot express.
    Unauthorized(u16),
    /// Any other HTTP 4xx client error.
    ClientError(u16),
    /// The provider answered a mutation request with a redirect (3xx) and the transport refused
    /// to follow it (§5.2b one-wire contract).
    ///
    /// It has its own variant rather than `ClientError(307)` so it is reliably deterministic (an
    /// identical re-POST gets the identical `Location`) and the route's outcome stays
    /// distinguishable from a 3xx that reached the generic status mapper.
    ///
    /// It does not prove that no effect happened: 303 See Other (RFC 9110 §15.4.4) is, after a
    /// POST, the canonical "your action completed; GET the result over there" answer, so a 3xx on
    /// a mutation is compatible with the effect having already happened. The evidence is
    /// `Indeterminate` (`aruna::jmap::provider_rejection`) and the post-authorization outcome
    /// is `ACK_AMBIGUOUS`. What the refusal does guarantee is that the named resource is never
    /// asked, so this route can never create a second effect by replaying the body.
    MutationRedirectRefused,
    /// The transport itself refused the mutation locally, before any socket was opened: the
    /// ADR-P010 default-closed destructive-write gate.
    ///
    /// The gate used to spell its refusal `map_method_error("__destructive_writes_disabled__")`,
    /// which falls into the deterministic [`MethodError::Unknown`] bucket, identical to an
    /// unrecognized method error the provider answered with. Those sit on opposite sides of
    /// §5.2b's evidence axis (a provider answer arrived after a POST and is `Indeterminate`; this
    /// is decided locally with no request in flight, `ProvenNoWire`), and one spelling for both
    /// made `apply`'s refusal settle `ACK_AMBIGUOUS` and park a human on a question the transport
    /// could answer with certainty. Deterministic: a closed gate does not open on retry.
    LocalWriteGateRefused,
}

/// Classify a normalized JMAP error into the engine's retry policy (`FailureKind`). The single
/// home for the transient-vs-deterministic taxonomy (mirrors ADR-P013's one-place `classify`).
///
/// Per RFC 8620/8621, `serverFail`, `serverPartialFail` and any unknown method-level type are
/// deterministic (retry is expected to fail again, and an unknown type must be treated as
/// `serverFail`); only genuinely transient classes (serverUnavailable, rateLimit, request
/// `limit`, HTTP 429/5xx, timeouts) are retried.
pub fn classify_jmap_error(error: &JmapError) -> FailureKind {
    use FailureKind::{Deterministic, Transient};
    match error {
        JmapError::Request(e) => match e {
            // Only a concurrency limit lifts on retry; a fixed-shape limit (request too large,
            // too many calls, unknown) fails identically every time, so it dead-letters.
            RequestError::Limit(RequestLimit::MaxConcurrentRequests) => Transient,
            RequestError::Limit(_) => Deterministic,
            RequestError::UnknownCapability
            | RequestError::NotJson
            | RequestError::NotRequest
            | RequestError::Unknown => Deterministic,
        },
        JmapError::Method(e) => match e {
            MethodError::ServerUnavailable | MethodError::RateLimit => Transient,
            MethodError::ServerFail
            | MethodError::ServerPartialFail
            | MethodError::Unknown
            | MethodError::InvalidArguments
            | MethodError::InvalidResultReference
            | MethodError::UnknownMethod
            | MethodError::AccountNotFound
            | MethodError::AccountReadOnly
            | MethodError::AccountNotSupportedByMethod
            | MethodError::Forbidden
            | MethodError::StateMismatch => Deterministic,
        },
        JmapError::Set(e) => match e {
            SetError::RateLimit => Transient,
            SetError::NotFound
            | SetError::Forbidden
            | SetError::InvalidPatch
            | SetError::InvalidProperties
            | SetError::TooLarge
            | SetError::Singleton
            | SetError::WillDestroy
            | SetError::OverQuota
            | SetError::TooManyMailboxes
            | SetError::MailboxCounts
            | SetError::Unknown => Deterministic,
        },
        JmapError::Transport(e) => match e {
            TransportError::Timeout
            | TransportError::ConnectionReset
            | TransportError::TooManyRequests
            | TransportError::ServerError(_) => Transient,
            // A redirected mutation is deterministic: the identical request earns the identical
            // `Location`, and following it is the replay the one-wire contract forbids. A closed
            // local write gate does not open on retry.
            TransportError::Unauthorized(_)
            | TransportError::ClientError(_)
            | TransportError::MutationRedirectRefused
            | TransportError::LocalWriteGateRefused => Deterministic,
        },
    }
}

// Below-seam provider ids (ADR-P003/P004), never surfaced above `Connector::apply`.

/// The provider-native account id (JMAP `accountId`). Stays below the seam: `Command.account` is
/// the Photon-local handle, resolved privately via [`AccountResolver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountId(pub String);
/// A provider-native `Mailbox` id. Below the seam.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MailboxId(pub String);
/// A provider-native `Email` id. Below the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailId(pub String);

/// A standardized mailbox role (RFC 8621 §2 / the IANA registry); inbox and archive are needed.
/// The provider-neutral read-side `Placement` vocabulary lives in [`crate::read_model`]; this
/// role enum is JMAP-native.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxRole {
    Inbox,
    Archive,
}

// Seams: resolvers (fake-seeded in tests) and the JMAP transport.

/// Resolves a Photon-local account string to the provider `accountId`, below the seam.
pub trait AccountResolver {
    fn resolve_account(&self, photon_account: &str) -> Option<AccountId>;
}

/// Resolves a Photon-local `message_ref` to the provider-opaque message id, below the seam. The
/// return is the neutral [`ProviderMessageId`] (the store round-trips text and never inspects
/// it); this connector converts it to its native [`EmailId`] at its own boundary. `Ok(None)` is a
/// genuine absent mapping (deterministic `MessageUnresolved`); `Err` is a store failure
/// (locked/corrupt DB), which the connector maps to a transient error so a retryable store
/// hiccup is never mis-classified as a permanent "message unresolved" dead-letter.
pub trait MessageRefResolver {
    fn resolve_message(
        &self,
        photon_account: &str,
        message_ref: &str,
    ) -> Result<Option<ProviderMessageId>, LogError>;
}

/// One JMAP method-call surface: the only thing a live-network impl replaces (a `reqwest`/
/// `jmap-client`-backed impl drops in behind the validation gate).
pub trait JmapTransport {
    /// Resolve the mailbox id holding `role` (models a `Mailbox/query` role filter). `Ok(None)` =
    /// the account has no mailbox with that role (RFC 8621 §2: roles are optional).
    fn mailbox_id_for_role(
        &self,
        account: &AccountId,
        role: MailboxRole,
    ) -> Result<Option<MailboxId>, JmapError>;

    /// Apply an `Email/set` (the mailbox move). `Err` carries a normalized [`JmapError`].
    fn email_set(&self, request: &EmailSetRequest) -> Result<(), JmapError>;

    /// BASIS-3: the provider-issued state cursor for the Mailbox namespace this transport's role
    /// answers were taken from (RFC 8621 `Mailbox` `state`). An `Err` means the reading could not
    /// be taken, and `resolve_basis` then refuses any role-resolving verb (a notification is a
    /// trigger to synchronize, never itself freshness proof).
    ///
    /// The result is typed, not `Option`: a bare `None` laundered a deterministic provider
    /// failure (401/403) into the same "unavailable, so transient" answer as a timeout, so an
    /// auth failure re-verifying a move basis would retry-loop forever. The typed error
    /// preserves the provider classification for `reverify_role_basis`.
    ///
    /// Defaults to a transient unavailability: a transport that tracks no cursor cannot evidence
    /// freshness, and "cannot evidence" is retryable, never a deterministic dead-letter.
    fn mailbox_state(&self, _account: &AccountId) -> Result<String, JmapError> {
        Err(JmapError::Method(MethodError::ServerUnavailable))
    }

    /// Read one message's current mailbox memberships (true-only) and keywords: the JMAP half of
    /// [`Connector::observe`] (an `Email/get` on `mailboxIds`/`keywords`). Read-only: no
    /// destructive-write gate.
    ///
    /// Defaults to refusing. A transport that has not wired the read answers a method error
    /// rather than a fabricated empty membership/keyword set: an observation that cannot be
    /// taken must never be reported as "nothing is set".
    fn email_current_state(
        &self,
        _account: &AccountId,
        _email: &EmailId,
    ) -> Result<EmailCurrentState, JmapError> {
        Err(JmapError::Method(MethodError::Unknown))
    }

    /// List one page of Inbox header summaries, newest-first (`Email/query` with the inbox-role
    /// filter and `sort receivedAt desc`, back-referenced `Email/get`): the read-ingest surface.
    /// `Ok` carries the page and, when more rows remain, a [`ContinuationToken`] (the JMAP
    /// `position`/anchor), plus [`ListedPage::raw_page_was_empty`], the one fact the mapped page
    /// cannot show (this route filters rows out, so an empty page and a filtered-to-zero page
    /// have the same shape).
    ///
    /// Defaults to refusing, like [`JmapTransport::email_current_state`] above.
    /// [`JmapTransport`] is a `pub` trait, so a new method must be additive for every implementor
    /// including out-of-crate ones. A transport that has not wired listing answers a method
    /// error rather than a fabricated empty inbox: an observation that cannot be taken must
    /// never be reported as "no mail".
    fn list_inbox_page(
        &self,
        _account: &AccountId,
        _page_size: i64,
        _continuation: Option<&ContinuationToken>,
    ) -> Result<ListedPage, JmapError> {
        Err(JmapError::Method(MethodError::Unknown))
    }

    /// Fetch one message's raw body (`Email/get` `bodyValues`), the on-demand body read.
    /// Read-only: no destructive-write gate.
    ///
    /// Defaults to refusing, for the same reason as [`JmapTransport::list_inbox_page`]: a
    /// fabricated empty [`RawBody`] is indistinguishable from a genuinely empty message.
    fn fetch_body(&self, _account: &AccountId, _email: &EmailId) -> Result<RawBody, JmapError> {
        Err(JmapError::Method(MethodError::Unknown))
    }
}

/// One message's observable JMAP state (the `observe` read's payload). Content-free: ids and
/// keyword names only, never a body, subject or header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmailCurrentState {
    /// The mailbox ids the message is currently IN (`mailboxIds` filtered to `true`).
    pub mailbox_ids: BTreeSet<String>,
    /// The keywords currently set on the message (RFC 8621 §4.1.1, e.g. `$seen`).
    pub keywords: BTreeSet<String>,
}

/// One typed, validated operation from an `Email/set` PatchObject key. The only two key families
/// Photon emits; anything else is rejected whole by [`EmailSetRequest::typed_updates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp<'a> {
    /// `mailboxIds/<id>` — membership add (`member: true`) / remove (`false`).
    Mailbox { mailbox_id: &'a str, member: bool },
    /// `keywords/<name>` — keyword set (`set: true`) / clear (`false`).
    Keyword { name: &'a str, set: bool },
}

/// A patch shape [`EmailSetRequest::typed_updates`] refuses. Id-free: no key content is carried
/// (ADR-P003/P004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchDispatchError {
    /// A key outside the `mailboxIds/` / `keywords/` families: reject the whole request (RFC 8620
    /// §5.3: never filter or part-apply).
    UnrecognizedKey,
    /// A record whose patch projects to nothing, or a request with zero records.
    Empty,
}

/// A JMAP `Email/set` request (the supported subset), typed and serde-serializable so the
/// `*/set` shape can be asserted against JSON. `update[emailId]` is an RFC 8620 §5.3
/// `PatchObject` of JSON-Pointer keys (`mailboxIds/<id>`: `true` to add, `null` to remove).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailSetRequest {
    #[serde(rename = "accountId")]
    account_id: String,
    update: BTreeMap<String, BTreeMap<String, Option<bool>>>,
}

/// Escape an operand as an RFC 6901 JSON-Pointer reference token before it becomes a PatchObject
/// path segment: `~` to `~0` first, then `/` to `~1` (the reverse order would double-escape the
/// `~` the first step introduces).
///
/// Hygiene, not a security control. A conformant JMAP provider cannot emit either metacharacter
/// in an id (RFC 8620 §1.2 restricts an Id to the URL-safe base64 alphabet `[A-Za-z0-9_-]`), so
/// on conformant input this is a no-op. It only keeps the emitted JSON Pointer well-formed
/// against a non-conformant provider; a hostile provider already owns the user's mailbox
/// namespace directly, so a crafted id buys it nothing.
fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

impl EmailSetRequest {
    /// Build the surgical move: remove `from`, add `to`, preserving every other mailbox
    /// membership (RFC 8621: emails can live in many mailboxes; a full replace would strip labels).
    fn move_mailbox(account: &AccountId, email: &EmailId, from: &MailboxId, to: &MailboxId) -> Self {
        let mut patch: BTreeMap<String, Option<bool>> = BTreeMap::new();
        patch.insert(format!("mailboxIds/{}", from.0), None);
        patch.insert(format!("mailboxIds/{}", to.0), Some(true));
        let mut update = BTreeMap::new();
        update.insert(email.0.clone(), patch);
        Self {
            account_id: account.0.clone(),
            update,
        }
    }

    /// Build a surgical keyword set/clear: `keywords/<name>` is `true` to set, `null` to clear
    /// (RFC 8620 PatchObject remove-by-null; RFC 8621 §4.1.1 `$seen`).
    fn set_keyword(account: &AccountId, email: &EmailId, keyword: &str, set: bool) -> Self {
        let mut patch: BTreeMap<String, Option<bool>> = BTreeMap::new();
        patch.insert(format!("keywords/{keyword}"), if set { Some(true) } else { None });
        let mut update = BTreeMap::new();
        update.insert(email.0.clone(), patch);
        Self {
            account_id: account.0.clone(),
            update,
        }
    }

    /// Build the restore patch: one path-scoped entry per captured atom, already keyed
    /// (`mailboxIds/<id>` / `keywords/<kw>`) and valued (`Some(true)` to hold, `None` to drop,
    /// RFC 8620 §5.3 remove-by-null) by the caller from the captured pre-state. There is no
    /// direction to encode and no whole-object arm: `"mailboxIds": {...}` would stomp every
    /// membership the action never touched.
    fn restore_patch(
        account: &AccountId,
        email: &EmailId,
        patch: BTreeMap<String, Option<bool>>,
    ) -> Self {
        let mut update = BTreeMap::new();
        update.insert(email.0.clone(), patch);
        Self {
            account_id: account.0.clone(),
            update,
        }
    }

    /// The provider `accountId` this `Email/set` targets. Public so an out-of-crate transport
    /// impl (e.g. `aruna-jmap`) can read the request the connector built.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The total, fail-closed dispatch over the update PatchObject: every key is recognized
    /// (`mailboxIds/`, `keywords/`) or the whole request is rejected. This is the only read-side
    /// accessor; per-prefix filters are banned because a filter that ignores keys it doesn't own
    /// turns a foreign key into a silent no-op reported as success (the patch must be consumed
    /// exhaustively).
    pub fn typed_updates(&self) -> Result<Vec<(&str, Vec<PatchOp<'_>>)>, PatchDispatchError> {
        if self.update.is_empty() {
            return Err(PatchDispatchError::Empty);
        }
        let mut out = Vec::with_capacity(self.update.len());
        for (email_id, patch) in &self.update {
            if patch.is_empty() {
                return Err(PatchDispatchError::Empty);
            }
            let mut ops = Vec::with_capacity(patch.len());
            for (key, value) in patch {
                if let Some(mailbox_id) = key.strip_prefix("mailboxIds/") {
                    ops.push(PatchOp::Mailbox {
                        mailbox_id,
                        member: matches!(value, Some(true)),
                    });
                } else if let Some(name) = key.strip_prefix("keywords/") {
                    ops.push(PatchOp::Keyword {
                        name,
                        set: matches!(value, Some(true)),
                    });
                } else {
                    return Err(PatchDispatchError::UnrecognizedKey);
                }
            }
            out.push((email_id.as_str(), ops));
        }
        Ok(out)
    }
}

// Capability map (ADR-P010) and the structured, id-free error code.

/// The connector's published capability map (ADR-P010). Unsupported verbs fail safe and visibly.
/// This is the connector's own truth, distinct from (not a substitute for) the global "real
/// destructive execution disabled until the validation gate", a property of the live transport.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityMap {
    archive: bool,
    unarchive: bool,
    set_flag_seen: bool,
    set_flag_flagged: bool,
}

impl CapabilityMap {
    /// The YELLOW verb set: archive/unarchive + SetFlag(Seen) + SetFlag(Flagged) (ADR-P010
    /// reversibility order). Everything else is unsupported.
    pub fn m1_verbs() -> Self {
        Self {
            archive: true,
            unarchive: true,
            set_flag_seen: true,
            set_flag_flagged: true,
        }
    }

    /// Explicit per-verb (and per-flag) support (for tests / future verbs).
    pub fn custom(
        archive: bool,
        unarchive: bool,
        set_flag_seen: bool,
        set_flag_flagged: bool,
    ) -> Self {
        Self {
            archive,
            unarchive,
            set_flag_seen,
            set_flag_flagged,
        }
    }

    /// Whether `archive` is supported. Part of the ADR-P010 published capability surface, so an
    /// external caller can preflight without submitting a command.
    pub fn archive(&self) -> bool {
        self.archive
    }

    /// Whether `unarchive` is supported (published surface; see [`CapabilityMap::archive`]).
    pub fn unarchive(&self) -> bool {
        self.unarchive
    }

    /// Whether a given action is supported by this connector: the preflight query an external
    /// caller uses before dispatch instead of discovering an unsupported verb through a
    /// deterministic failure (ADR-P010 "published capability map").
    pub fn supports(&self, action: &Action) -> bool {
        match action {
            Action::Archive { .. } => self.archive,
            Action::Unarchive { .. } => self.unarchive,
            // Per flag, never a wildcard: a future MailFlag must add its own capability row here
            // or compilation fails (ADR-P010).
            Action::SetFlag { flag: MailFlag::Seen, .. } => self.set_flag_seen,
            Action::SetFlag { flag: MailFlag::Flagged, .. } => self.set_flag_flagged,
            // JMAP declares the four triage verbs unsupported: no map publishes them, so `apply`
            // refuses them before the wire with the typed code.
            Action::Trash { .. }
            | Action::Untrash { .. }
            | Action::MarkSpam { .. }
            | Action::UnmarkSpam { .. } => false,
        }
    }
}

/// A structured, id-free connector error code. The `ConnectorError` surfaced above the seam is
/// built from this code's fixed phrase, never from a raw JMAP id, response body or `SetError`
/// description string (ADR-P003/P004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JmapErrorCode {
    UnsupportedCapability,
    AccountUnresolved,
    MessageUnresolved,
    RoleMailboxAbsent,
    ProviderRejected,
    /// Restore: the captured pre-state does not cover every frozen atom, so the patch cannot be
    /// built without inventing a value. Structured, because the atom name it would otherwise
    /// quote carries a provider mailbox id (ADR-P003/P004).
    PreStateIncomplete,
    /// The provider answered a mutation with a redirect and the transport refused to follow it
    /// (§5.2b one-wire contract). Structured, because the `Location` it would otherwise quote is
    /// a provider-chosen URL that must never surface.
    MutationRedirectRefused,
    /// The transport's own default-closed destructive-write gate refused the mutation before any
    /// socket (ADR-P010). Id-free like every other code here: the authorized host it declined to
    /// write to is below-seam configuration.
    LocalWriteGateRefused,
}

impl JmapErrorCode {
    /// A fixed, id-free message, free of provider-native handles.
    fn message(self) -> &'static str {
        match self {
            JmapErrorCode::UnsupportedCapability => {
                "jmap: action not supported by this connector"
            }
            JmapErrorCode::AccountUnresolved => "jmap: account could not be resolved",
            JmapErrorCode::MessageUnresolved => "jmap: message reference could not be resolved",
            JmapErrorCode::RoleMailboxAbsent => "jmap: required role mailbox is absent",
            JmapErrorCode::ProviderRejected => "jmap: provider rejected the mutation",
            JmapErrorCode::PreStateIncomplete => {
                "jmap: captured pre-state does not cover the frozen atoms"
            }
            JmapErrorCode::MutationRedirectRefused => {
                "jmap: provider redirected the mutation; refused without replay"
            }
            JmapErrorCode::LocalWriteGateRefused => {
                "jmap: destructive writes are not enabled for this transport; refused before the \
                 socket"
            }
        }
    }
}

/// Build a deterministic `ConnectorError` from a structured, id-free code. The capability refusal
/// carries its own axis (`ConnectorError::unsupported_capability`), as the Gmail connector's does.
fn deterministic(code: JmapErrorCode) -> ConnectorError {
    let error = ConnectorError::deterministic(code.message());
    match code {
        JmapErrorCode::UnsupportedCapability => error.unsupported_capability(),
        JmapErrorCode::AccountUnresolved
        | JmapErrorCode::MessageUnresolved
        | JmapErrorCode::RoleMailboxAbsent
        | JmapErrorCode::ProviderRejected
        | JmapErrorCode::PreStateIncomplete
        | JmapErrorCode::MutationRedirectRefused
        | JmapErrorCode::LocalWriteGateRefused => error,
    }
}

/// The same code, tagged with the positive proof that no mutation was issued. Every caller is on
/// a mutation path (`apply` / `restore`) and refuses from local values (the capability map, the
/// account/message-ref resolvers, the captured pre-state's coverage, the atom-family dispatch)
/// before any `Email/set` request has been built, let alone sent.
///
/// The tag is required: both mutation paths run after the send-authorization boundary, and the
/// grammar refuses to infer non-issuance from a failure's name there, so without positive
/// evidence these refusals settle `ACK_AMBIGUOUS` and park a human on a question the connector
/// can answer with certainty. The constructor default stays fail-closed `Indeterminate`; the
/// sites are tagged, never the default.
fn refused_pre_wire(code: JmapErrorCode) -> ConnectorError {
    deterministic(code).proven_no_wire()
}

/// The message-ref store read failing on a mutation path: retryable (a store fault lifts), and
/// proven pre-wire for the same reason as [`refused_pre_wire`] (the resolver runs before any
/// request exists). One spelling so the two mutation paths cannot drift.
fn store_read_failed_pre_wire() -> ConnectorError {
    ConnectorError::transient("jmap: message store read failed").proven_no_wire()
}

/// Map a provider `JmapError` to a `ConnectorError`: `kind` from the taxonomy, message from the
/// fixed id-free `ProviderRejected` phrase (the JMAP error's own text and ids are never
/// surfaced).
///
/// **No wire evidence.** No `ConnectorError` here claims [`crate::EffectEvidence::ProvenNoWire`],
/// because `aruna-jmap` has no send-stage split: unlike the Gmail transport, it classifies every
/// network failure with one blanket rule. A post-authorization JMAP transport failure therefore
/// classifies `ACK_AMBIGUOUS` / ISSUANCE_UNKNOWN, since claiming no-wire would authorize a retry
/// that could duplicate a mutation. (`jmap_rejections_never_claim_effect_evidence` is the drift
/// tripwire.)
///
/// **Two families this transport can prove**, neither a wire claim (bytes left the host): the
/// per-record `SetError` and the method-level error family ([`method_error_proves_no_effect`])
/// carry the provider's own statement that the mutation did not change its state, so both are
/// `ProvenRefusedNoEffect`.
///
/// A per-record `SetError` is not a network outcome: RFC 8620 §5.3 defines `notUpdated` as "a
/// map of the record id to a SetError object for each record that failed to be updated", so a
/// 200 carrying our id there is the provider stating that it received the `Email/set`, decided,
/// and did not change this record. That is [`crate::EffectEvidence::ProvenRefusedNoEffect`], the
/// one class where "absence of proof is never proof" does not apply because the proof is
/// present; `Indeterminate` would park a human on a question the provider already answered. The
/// proof is the record's presence in `notUpdated`, not the type token, so the whole family is
/// tagged (`SetError::Unknown` included) and the retry classification is untouched. The axes
/// stay independent: `rateLimit` is refused-no-effect and still retried.
///
/// **The one-wire redirect refusal is not an exception.** A mutation answered with a redirect
/// ([`TransportError::MutationRedirectRefused`]) gets its own id-free code and stays
/// [`crate::EffectEvidence::Indeterminate`]. RFC 9110 §15.4 was once read as proof that the
/// target did not perform the request, but 303 See Other (§15.4.4) is the counterexample (the
/// POST/redirect/GET shape, where the action completed and the redirect points at its result),
/// and no per-provider redirect contract is pinned here to tell the cases apart. The redirect is
/// never followed, so no second effect can come from a replayed body, and the id-free message
/// keeps the provider-chosen `Location` below the seam. Post-authorization it lands
/// `ACK_AMBIGUOUS`, cheaper than a durable "no effect" record a 303 would make false. The kind
/// stays deterministic: an identical re-POST earns an identical `Location`.
fn provider_rejection(error: &JmapError) -> ConnectorError {
    // The one exception to "no effect evidence" above: a `LocalWriteGateRefused` is not a
    // provider answer. The transport's own default-closed gate decided it from a local host map
    // with no request in flight, the same positive proof `refused_pre_wire` attaches to every
    // local refusal inside this connector; it reaches this function only because the gate lives
    // one layer down (`aruna-jmap`). Every other variant here is the provider's own answer,
    // arrived after a POST, and keeps the fail-closed `Indeterminate` default.
    if matches!(
        error,
        JmapError::Transport(TransportError::LocalWriteGateRefused)
    ) {
        return refused_pre_wire(JmapErrorCode::LocalWriteGateRefused);
    }
    // The one-wire refusal answers with its own id-free code (the `Location` it declines to
    // follow is provider-chosen text and never surfaces). No evidence is attached; see above.
    if matches!(
        error,
        JmapError::Transport(TransportError::MutationRedirectRefused)
    ) {
        return ConnectorError::deterministic(JmapErrorCode::MutationRedirectRefused.message());
    }
    let message = JmapErrorCode::ProviderRejected.message();
    let refusal = match classify_jmap_error(error) {
        FailureKind::Transient => ConnectorError::transient(message),
        FailureKind::Deterministic => ConnectorError::deterministic(message),
    };
    // The per-record `SetError` is a positive no-effect proof: `notUpdated[id]` is the provider
    // naming this record as one it did not change, after receiving and deciding the mutation.
    // The tag is added to the taxonomy's verdict, so the retry axis is unchanged.
    if matches!(error, JmapError::Set(_)) {
        return refusal.proven_refused_no_effect();
    }
    // The method-level error carries RFC 8620 §3.6.2's own guarantee: the RFC attaches a
    // normative MUST to the error's position, not to any one type token, so the whole family
    // (minus its two exclusions) is the same proof the per-record `SetError` is. The taxonomy
    // still decides retryability.
    if let JmapError::Method(method) = error {
        if method_error_proves_no_effect(method) {
            return refusal.proven_refused_no_effect();
        }
    }
    refusal
}

/// Does this method-level error carry RFC 8620 §3.6.2's no-state-change guarantee?
///
/// The sentence (RFC 8620 §3.6.2): "With the exception of when the `serverPartialFail` error is
/// returned, the externally visible state of the server MUST NOT have changed if an error is
/// returned at the method level." The guarantee is attached to the position of the answer (a
/// method-level `["error", {type}, callId]` tuple), not to a type vocabulary, so this is a family
/// rather than one token. It lands on the mutation unambiguously: `email_set` sends one method
/// call under one `callId`, and `parse_email_set_response` correlates that id before reading the
/// tuple as an error, so no sibling call could be mistaken for the `Email/set`'s failure.
///
/// Exclusion 1, `serverPartialFail`, is the RFC's own: "Some, but not all, expected changes
/// described by the method occurred. The client MUST resynchronise impacted data."
///
/// Exclusion 2, `Unknown`, is ours. RFC 8620 says an unknown error type "MUST [be treated] the
/// same as the `serverFail` type", so a genuine unrecognized provider type would qualify. But
/// [`MethodError::Unknown`] is also the fail-closed bucket `aruna-jmap`'s `map_method_error`
/// drops every unrecognized token into, and that crate spells its own local verdicts as tokens
/// that fall through it: `__record_not_in_response__` (HTTP 200, a real `Email/set` answer for
/// our callId, our record in neither `updated` nor `notUpdated`), `__malformed_response__`,
/// `__unexpected_method_response__`, `__call_id_mismatch__`, `__empty_response__`,
/// `__unrecognized_patch__`, `__empty_email_set__`. These are cases where the provider told us
/// nothing readable, which is what `Indeterminate` means, and `__record_not_in_response__` is
/// the worst because the mutation may well have applied. If the variant is ever split, the
/// provider half joins this set; the local sentinels never do.
///
/// Residual: a provider that violates its normative obligation can make a transient member
/// (`serverUnavailable`, `rateLimit`) authorize a retry that duplicates. The `SetError` family
/// accepts the same residual; no on-wire check separates a conformant "no" from a lying one.
///
/// The match is exhaustive on purpose: a new method-level variant must decide this question at
/// the compiler's insistence.
fn method_error_proves_no_effect(error: &MethodError) -> bool {
    match error {
        MethodError::ServerFail
        | MethodError::ServerUnavailable
        | MethodError::RateLimit
        | MethodError::InvalidArguments
        | MethodError::InvalidResultReference
        | MethodError::UnknownMethod
        | MethodError::AccountNotFound
        | MethodError::AccountReadOnly
        | MethodError::AccountNotSupportedByMethod
        | MethodError::Forbidden
        | MethodError::StateMismatch => true,
        MethodError::ServerPartialFail | MethodError::Unknown => false,
    }
}

/// Why an admission-time basis freeze was refused: the resolver half of the confinement
/// discipline [`JmapErrorCode`] enforces on the apply half. The [`ResolveBasisError`] handed to
/// the admission path (and from there to `execute()`'s public error) is built from one of these
/// fixed phrases, so a below-seam failure's own text (SQL, an on-disk path, a provider id) has
/// nowhere to travel. Every variant is retryable: admission runs before `record()`, so a refusal
/// means nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JmapBasisRefusal {
    AccountUnresolved,
    /// The message-ref resolver failed (store fault). Its text stays below the seam.
    MessageResolverFailed,
    MessageUnresolved,
    /// No `Mailbox` state cursor: the namespace's freshness is unevidenced (BASIS-3).
    FreshnessUnevidenced,
    RoleLookupFailed,
    RoleAbsent,
    /// The verb is one JMAP declares unsupported (the four triage verbs): no basis is frozen for
    /// a mutation this connector will never express.
    UnsupportedCapability,
}

impl JmapBasisRefusal {
    /// A fixed, id-free message, free of provider-native handles and store text.
    fn message(self) -> &'static str {
        match self {
            JmapBasisRefusal::AccountUnresolved => "jmap: account unresolved (retryable)",
            JmapBasisRefusal::MessageResolverFailed => {
                "jmap: message resolver failure (retryable)"
            }
            JmapBasisRefusal::MessageUnresolved => "jmap: message unresolved (retryable)",
            JmapBasisRefusal::FreshnessUnevidenced => {
                "jmap: no mailbox state cursor — freshness unevidenced (BASIS-3), retryable"
            }
            JmapBasisRefusal::RoleLookupFailed => {
                "jmap: role mailbox lookup failed (retryable)"
            }
            JmapBasisRefusal::RoleAbsent => "jmap: required role mailbox is absent (retryable)",
            JmapBasisRefusal::UnsupportedCapability => {
                "jmap: action not supported by this connector"
            }
        }
    }
}

/// Build the admission refusal from a structured, id-free code. The only way this module
/// constructs a [`ResolveBasisError`], so a future refusal site cannot reopen the leak by
/// interpolating the error it caught.
fn refuse_basis(code: JmapBasisRefusal) -> ResolveBasisError {
    ResolveBasisError(code.message().to_string())
}

// The connector.

/// The provider tag this connector's native resource keys carry: the first component handed to
/// [`crate::prestate::native_resource_key`], the single encoding authority. A tag, not a prefix:
/// it is a component of the injective encoding, so it cannot be absorbed into an account id that
/// starts with the same characters.
pub const JMAP_KEY_PROVIDER: &str = "jmap";

/// The JMAP `act`-verb connector: translates `Action::{Archive,Unarchive}` and the flag verbs
/// into an `Email/set`, classifying provider failures and confining provider ids below the seam.
/// The narrow `Connector::apply` actuator, not the full ADR-P003 `MailSurfaceAdapter`.
pub struct JmapConnector<T, A, M> {
    transport: T,
    accounts: A,
    messages: M,
    capabilities: CapabilityMap,
}

impl<T: JmapTransport, A: AccountResolver, M: MessageRefResolver> JmapConnector<T, A, M> {
    /// The default connector: the published verb set (archive/unarchive + SetFlag(Seen) +
    /// SetFlag(Flagged)).
    pub fn new(transport: T, accounts: A, messages: M) -> Self {
        Self::with_capabilities(transport, accounts, messages, CapabilityMap::m1_verbs())
    }

    /// Construct with an explicit capability map (tests / future verbs).
    pub fn with_capabilities(
        transport: T,
        accounts: A,
        messages: M,
        capabilities: CapabilityMap,
    ) -> Self {
        Self {
            transport,
            accounts,
            messages,
            capabilities,
        }
    }

    /// The connector's published capability map (ADR-P010).
    pub fn capabilities(&self) -> &CapabilityMap {
        &self.capabilities
    }

    /// Resolve a role mailbox for the basis path, mapping both a lookup failure and a genuine
    /// role absence to a named, id-free `ResolveBasisError`: an unresolvable role refuses
    /// admission (retryable), never a partial or invented basis.
    fn require_role(
        &self,
        account: &AccountId,
        role: MailboxRole,
    ) -> Result<MailboxId, ResolveBasisError> {
        self.transport
            .mailbox_id_for_role(account, role)
            .map_err(|_| refuse_basis(JmapBasisRefusal::RoleLookupFailed))?
            .ok_or_else(|| refuse_basis(JmapBasisRefusal::RoleAbsent))
    }

    /// BASIS-6 for the role-resolving verbs (Archive/Unarchive): re-resolve the roles fresh and
    /// refuse unless the freshly resolved ids equal the basis's frozen operands. A no-op for the
    /// keyword verbs, whose atoms are RFC 8621 provider constants (nothing was resolved, so
    /// nothing can rebind).
    ///
    /// Identity gates compare identity (resolved ids vs frozen operands); a cursor gates nothing
    /// by equality, it only evidences the freshness of the resolution that produced the
    /// comparison inputs (BASIS-3). Value-equality against a frozen cursor conflates the two, and
    /// every window in which the namespace legitimately moves (the forward move re-dates it
    /// itself; a deferred child waits behind a predecessor; another client renames a mailbox; a
    /// lost ack forces a re-drive) would become a deterministic rebound that dead-letters a
    /// correct operation. No cursor cannot go stale, so the gate is removed rather than
    /// re-pointed at a fresher one.
    ///
    /// What remains:
    /// - **ids differ**: the role now names a different mailbox, and `apply` would mutate one the
    ///   journal never recorded. Deterministic, since a retry can only ask the same wrong
    ///   question. This is the only deterministic refusal here.
    /// - **the cursor cannot be read**: the fresh resolution is not freshness-evidenced.
    ///   Transient: unavailability is not proof of a rebind, but not permission to proceed
    ///   unverified.
    /// - **the sandwich** (cursor, role lookups, cursor): a coherence check. The reads are
    ///   separate round trips, so a change between them makes the ids a smear across two
    ///   namespace states. Transient, and checked before the id comparison so ids gathered
    ///   across a moving namespace are never promoted into a deterministic dead-letter. Both
    ///   reads are of the current cursor and compared only to each other.
    ///
    /// The one history no longer refused is a true ABA in which both the id set and the role to
    /// id mapping equal current. A stable role permutation (Inbox and Archive swapped, so the id
    /// set {X,Y} is preserved but the direction inverted) is refused by the role-keyed map
    /// compare below; an unordered id set would pass it, and RFC 8621 §2 makes `role`
    /// client-mutable, so it is reachable via data. What a true ABA can still hide is a third
    /// party's content change inside that window (the requalify-to-write TOCTOU residual),
    /// closable only by a provider-side conditional write that neither Gmail nor JMAP offers
    /// for this shape.
    fn reverify_role_basis(
        &self,
        account: &AccountId,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<(), ConnectorError> {
        // Per family, never a wildcard arm: a future verb must name its own re-verification.
        match &command.action {
            Action::SetFlag { .. } => return Ok(()),
            Action::Archive { .. } | Action::Unarchive { .. } => {}
            // Declared unsupported: no basis is ever frozen for these (see `resolve_basis`), so
            // there is no role basis to re-verify; refuse by the typed code.
            Action::Trash { .. }
            | Action::Untrash { .. }
            | Action::MarkSpam { .. }
            | Action::UnmarkSpam { .. } => {
                return Err(refused_pre_wire(JmapErrorCode::UnsupportedCapability));
            }
        }
        // Shape, not value: a role verb's basis must have been frozen with a state cursor
        // (`resolve_basis` refuses otherwise), so anything else means this basis was not frozen
        // for this verb. The cursor's value is not bound: nothing compares to it.
        let Freshness::StateCursor { .. } = &basis.freshness else {
            return Err(ConnectorError::deterministic_basis_rebound());
        };
        // A move basis must carry the frozen role to id mapping (`resolve_basis` populates it
        // for Archive/Unarchive). Empty means the basis was frozen without bindings, so its role
        // direction is unknowable and it cannot be role-verified: refuse it by name rather than
        // fall back to an id-set compare.
        if basis.role_bindings.is_empty() {
            return Err(ConnectorError::deterministic_basis_rebound());
        }
        // The cursor read is written once and taken twice. Both are reads of the current cursor,
        // compared only to each other: freshness evidence for the fresh resolution below, never
        // an identity gate. A read that could not be taken is classified by the provider
        // taxonomy: genuine unavailability is transient (verify-or-refuse, retryable); a
        // deterministic provider/auth failure (401/403) is deterministic, never laundered into a
        // retry loop.
        let read_cursor = || -> Result<String, ConnectorError> {
            self.transport.mailbox_state(account).map_err(|e| match classify_jmap_error(&e) {
                FailureKind::Transient => ConnectorError::transient(
                    "jmap: mailbox state cursor unavailable — the fresh role resolution cannot be \
                     freshness-evidenced (BASIS-3), retryable",
                ),
                FailureKind::Deterministic => ConnectorError::deterministic(
                    "jmap: mailbox state cursor read was DETERMINISTICALLY refused by the provider \
                     (auth/permission) — the fresh role resolution cannot be freshness-evidenced \
                     (BASIS-3), not retryable",
                ),
            })
        };
        let cursor_before = read_cursor()?;
        // The fresh resolution: the roles are resolved again, now, off current Mailbox state,
        // bracketed by the two cursor reads that date it. Built as a role to id map (not an
        // unordered set) so the direction is comparable.
        let mut current: BTreeMap<&str, String> = BTreeMap::new();
        for (role_name, role) in [("inbox", MailboxRole::Inbox), ("archive", MailboxRole::Archive)] {
            let id = self
                .transport
                .mailbox_id_for_role(account, role)
                .map_err(|e| provider_rejection(&e))?
                .ok_or_else(|| deterministic(JmapErrorCode::RoleMailboxAbsent))?;
            current.insert(role_name, id.0);
        }
        // The far slice. Checked before the role comparison on purpose: ids gathered while the
        // namespace was moving are not evidence, so they must never be promoted into the
        // deterministic (dead-lettering) rebound verdict.
        if read_cursor()? != cursor_before {
            return Err(ConnectorError::transient(
                "jmap: the Mailbox namespace moved DURING re-verification (the state cursor \
                 advanced between the pre-read and the role lookups) — the readings are not one \
                 coherent snapshot, retryable",
            ));
        }
        // The identity gate is role-keyed, never an unordered id set. Per role, the freshly
        // resolved id must equal the id admission froze for that role. A stable Inbox/Archive
        // permutation preserves the id set {X,Y} but inverts the mapping, so
        // `current["inbox"]` reads the archive's old id, not `frozen["inbox"]`, and the result is
        // a deterministic rebound, whatever the cursor did in between. Any missing side fails
        // closed.
        for role_name in ["inbox", "archive"] {
            match (basis.role_bindings.get(role_name), current.get(role_name)) {
                (Some(frozen), Some(fresh)) if frozen == fresh => {}
                _ => return Err(ConnectorError::deterministic_basis_rebound()),
            }
        }
        Ok(())
    }
}

impl<T, A, M> Connector for JmapConnector<T, A, M>
where
    T: JmapTransport,
    A: AccountResolver,
    M: MessageRefResolver,
{
    /// BASIS-6 runs here, at the forward dispatch site, as [`Connector::restore`] does. The two
    /// kinds of identity are split by what they are for:
    ///
    /// - the account and email handles route the write, so they are re-resolved (there is no
    ///   other way to address the request) and then verified against the frozen native key; a
    ///   mismatch refuses `deterministic_basis_rebound`, never retargets;
    /// - the role to mailbox pair is an operand of the write, so it is taken from the frozen
    ///   `role_bindings` and never re-resolved. No window is left for a permutation to invert the
    ///   direction.
    ///
    /// The observe-time gate (`reverify_role_basis`) still owns the pre-observe half; the
    /// observe-to-apply window no longer exists.
    fn apply(&self, command: &Command, basis: &FrozenBasis) -> Result<(), ConnectorError> {
        // Every local refusal in this function is proven pre-wire (`refused_pre_wire`): `apply`
        // is called after the send-authorization boundary, and each refuses from local values
        // before any `Email/set` is built. Only the provider's own answers (`provider_rejection`)
        // stay evidence-free.
        //
        // ADR-P010: fail safe and visibly on an unsupported verb (the connector's own capability
        // truth).
        if !self.capabilities.supports(&command.action) {
            return Err(refused_pre_wire(JmapErrorCode::UnsupportedCapability));
        }
        // Every verb targets one message. Resolve the provider-native account and email handles
        // below the seam first (ADR-P003/P004); a miss is a deterministic, id-free failure.
        let message_ref = match &command.action {
            Action::Archive { message_ref }
            | Action::Unarchive { message_ref }
            | Action::SetFlag { message_ref, .. }
            | Action::Trash { message_ref }
            | Action::Untrash { message_ref }
            | Action::MarkSpam { message_ref }
            | Action::UnmarkSpam { message_ref } => message_ref,
        };
        let account = self
            .accounts
            .resolve_account(&command.account)
            .ok_or_else(|| refused_pre_wire(JmapErrorCode::AccountUnresolved))?;
        let email = self
            .messages
            .resolve_message(&command.account, message_ref)
            // A store failure is transient (retryable), never a permanent dead-letter; only a
            // genuine absent mapping is the deterministic MessageUnresolved.
            .map_err(|_| store_read_failed_pre_wire())?
            // The neutral opaque id becomes the JMAP-native EmailId here, at this connector's
            // own boundary; it is the same opaque text either way.
            .map(|id| EmailId(id.0))
            .ok_or_else(|| refused_pre_wire(JmapErrorCode::MessageUnresolved))?;
        // BASIS-6 at the wire, identity half. The two handles above route the request, so they
        // had to be re-resolved and must be re-verified against the identity admission froze,
        // through the single encoding authority so the comparison cannot drift from what was
        // frozen. A mismatch is deterministic (a frozen basis is immutable: an identical retry
        // can only re-ask the same wrong question) and proven no-wire (decided on a local
        // comparison, before any `Email/set` is built). `restore` makes the same check.
        if native_resource_key(JMAP_KEY_PROVIDER, &[&account.0, &email.0])
            != basis.native_resource_key
        {
            return Err(ConnectorError::deterministic_basis_rebound());
        }
        // BASIS-6 at the wire, operand half. The role to mailbox pair is not re-resolved: it is
        // read from the basis frozen at admission, the only place role direction was ever
        // knowable (`resolve_basis`). A permutation landing between observe and apply would
        // otherwise invert the move silently (`Archive` resolving Inbox to the archive's id and
        // vice versa, so the `Email/set` removed the message from Archive and added it to Inbox
        // while the engine recorded `Applied`).
        //
        // A basis with no frozen bindings cannot answer a move verb (a legacy row, or one frozen
        // for a keyword verb): its direction is unknowable, so it refuses by name rather than
        // re-resolving, the same fail-closed answer `reverify_role_basis` gives. The keyword
        // verbs never call this: their atoms are RFC 8621 provider constants and their
        // `role_bindings` are legitimately empty.
        let frozen_role = |role_name: &str| -> Result<MailboxId, ConnectorError> {
            basis
                .role_bindings
                .get(role_name)
                .map(|id| MailboxId(id.clone()))
                .ok_or_else(ConnectorError::deterministic_basis_rebound)
        };
        // Build the surgical Email/set per verb. Archive moves Inbox to Archive; Unarchive is the
        // inverse (the Action carries only a Photon-local message_ref, so the destination comes
        // from mailbox roles). SetFlag needs no mailbox roles, just one keywords/<kw> patch; the
        // MailFlag to keyword mapping lives here and only here (the engine never learns "$seen").
        // Per flag, never a wildcard arm.
        let request = match &command.action {
            Action::Archive { .. } => EmailSetRequest::move_mailbox(
                &account,
                &email,
                &frozen_role("inbox")?,
                &frozen_role("archive")?,
            ),
            Action::Unarchive { .. } => EmailSetRequest::move_mailbox(
                &account,
                &email,
                &frozen_role("archive")?,
                &frozen_role("inbox")?,
            ),
            Action::SetFlag { flag: MailFlag::Seen, value, .. } => {
                EmailSetRequest::set_keyword(&account, &email, "$seen", *value)
            }
            // Flagged is RFC 8621 §10.4.3 `$flagged`: positive on both sides, same generic
            // keyword builder.
            Action::SetFlag { flag: MailFlag::Flagged, value, .. } => {
                EmailSetRequest::set_keyword(&account, &email, "$flagged", *value)
            }
            // Declared unsupported (the published map already refused above; this arm is the
            // same typed refusal, never a request).
            Action::Trash { .. }
            | Action::Untrash { .. }
            | Action::MarkSpam { .. }
            | Action::UnmarkSpam { .. } => {
                return Err(refused_pre_wire(JmapErrorCode::UnsupportedCapability));
            }
        };
        // A provider rejection is classified by the taxonomy and surfaced with an id-free
        // message.
        self.transport
            .email_set(&request)
            .map_err(|e| provider_rejection(&e))
    }

    /// BASIS-2/-3/-4. The native identity is the local durable resolver pair (accountId + Email
    /// id). The atoms split by verb family, and so does their freshness:
    ///
    /// - the move verbs use a pair of role-resolved mailbox ids, which are namespace state, so
    ///   they require the provider's Mailbox state cursor as freshness evidence (BASIS-3). The
    ///   cursor is demanded first so an unevidenced namespace refuses before any role
    ///   resolution is attempted;
    /// - the keyword verbs use RFC 8621 provider constants (`$seen`/`$flagged`): nothing is
    ///   resolved or cached, so their freshness is `ImmutableConstants` and a missing cursor
    ///   does not refuse them.
    ///
    /// Residual: role resolution reaches the transport seam, whose live impl is a
    /// `Mailbox/query` wire call, while BASIS-2 wants admission-path resolution to read local
    /// durable state only. The cursor-first order makes this unreachable for any transport that
    /// cannot evidence freshness locally (the default `mailbox_state` is unavailable); a local
    /// role cache would close it.
    fn resolve_basis(&self, command: &Command) -> Result<FrozenBasis, ResolveBasisError> {
        let account = self
            .accounts
            .resolve_account(&command.account)
            .ok_or_else(|| refuse_basis(JmapBasisRefusal::AccountUnresolved))?;
        let email = self
            .messages
            .resolve_message(&command.account, action_message_ref(&command.action))
            // The store error is dropped, not formatted: `LogError` carries unconstrained text
            // (SQL, paths, provider ids) and this refusal surfaces through `execute()`.
            .map_err(|_| refuse_basis(JmapBasisRefusal::MessageResolverFailed))?
            .map(|id| EmailId(id.0))
            .ok_or_else(|| refuse_basis(JmapBasisRefusal::MessageUnresolved))?;
        // `A`, the forward target per atom, is emitted in the same arms that build the atoms so
        // the two key-sets cannot drift (`FrozenBasis::validate` enforces equality both ways).
        // Archive is a move: the source membership drops and the destination gains, and which
        // frozen id plays which role is knowable only here, at role resolution. After this
        // moment the ids are opaque equals and the direction is unrecoverable, so it is frozen
        // now rather than re-derived at undo time (the rebind BASIS-6 forbids).
        //   Archive:             {membership:<inbox>: false, membership:<archive>: true}
        //   Unarchive:           {membership:<inbox>: true,  membership:<archive>: false}
        //   SetFlag(Seen, v):    {keyword:$seen: v}      (positive polarity on JMAP: the
        //   SetFlag(Flagged, v): {keyword:$flagged: v}    atom is the keyword, not a label)
        // Result: touched atoms to operands, the forward target vector A, the role to id
        // bindings, freshness.
        type ResolvedBasisParts = (
            BTreeMap<String, String>,
            BTreeMap<String, bool>,
            BTreeMap<String, String>,
            Freshness,
        );
        let (touched_atoms, atom_targets, role_bindings, freshness): ResolvedBasisParts =
            match &command.action {
            Action::Archive { .. } | Action::Unarchive { .. } => {
                let cursor = self
                    .transport
                    .mailbox_state(&account)
                    // A state-cursor read that could not be taken refuses admission (retryable);
                    // its typed failure cause stays below the seam. Admission refusals are all
                    // retryable, so the classification is not needed here (it is at re-verify).
                    .map_err(|_| refuse_basis(JmapBasisRefusal::FreshnessUnevidenced))?;
                let inbox = self.require_role(&account, MailboxRole::Inbox)?;
                let archive = self.require_role(&account, MailboxRole::Archive)?;
                // Archive moves inbox → archive; Unarchive is the same pair, reversed.
                let inbox_target = matches!(command.action, Action::Unarchive { .. });
                (
                    [
                        (format!("membership:{}", inbox.0), inbox.0.clone()),
                        (format!("membership:{}", archive.0), archive.0.clone()),
                    ]
                    .into_iter()
                    .collect(),
                    [
                        (format!("membership:{}", inbox.0), inbox_target),
                        (format!("membership:{}", archive.0), !inbox_target),
                    ]
                    .into_iter()
                    .collect(),
                    // The role to id mapping, frozen here, the only place role direction is
                    // knowable. BASIS-6 compares this map, never an unordered id set, so a stable
                    // Inbox/Archive permutation that preserves the id set but inverts the
                    // direction still refuses. Keys are connector-agnostic role names.
                    [
                        ("inbox".to_string(), inbox.0.clone()),
                        ("archive".to_string(), archive.0.clone()),
                    ]
                    .into_iter()
                    .collect(),
                    Freshness::StateCursor { cursor },
                )
            }
            // Per flag, never a wildcard arm: a future MailFlag must name its own keyword.
            // Keyword verbs resolve no role, so `role_bindings` is empty (the role-keyed gate is a
            // no-op for them, as in the per-family split in `reverify_role_basis`).
            Action::SetFlag { flag: MailFlag::Seen, value, .. } => (
                [("keyword:$seen".to_string(), "$seen".to_string())]
                    .into_iter()
                    .collect(),
                [("keyword:$seen".to_string(), *value)].into_iter().collect(),
                BTreeMap::new(),
                Freshness::ImmutableConstants,
            ),
            Action::SetFlag { flag: MailFlag::Flagged, value, .. } => (
                [("keyword:$flagged".to_string(), "$flagged".to_string())]
                    .into_iter()
                    .collect(),
                [("keyword:$flagged".to_string(), *value)]
                    .into_iter()
                    .collect(),
                BTreeMap::new(),
                Freshness::ImmutableConstants,
            ),
            // Declared unsupported: admission refuses by the typed code rather than freezing a
            // basis for a mutation this connector will never express.
            Action::Trash { .. }
            | Action::Untrash { .. }
            | Action::MarkSpam { .. }
            | Action::UnmarkSpam { .. } => {
                return Err(refuse_basis(JmapBasisRefusal::UnsupportedCapability));
            }
        };
        Ok(FrozenBasis {
            native_resource_key: native_resource_key(JMAP_KEY_PROVIDER, &[&account.0, &email.0]),
            touched_atoms,
            atom_targets,
            role_bindings,
            freshness,
        })
    }

    /// The provider read behind "observe": one `Email/get` of `mailboxIds`/`keywords`,
    /// projected onto exactly the frozen atoms. The atom-family dispatch is total and
    /// fail-closed: an atom outside the two families is a deterministic refusal, never a
    /// silently false reading.
    ///
    /// BASIS-6 runs here too, on the role basis (the move verbs), not only on the message
    /// identity the engine checks above the seam: `reverify_role_basis` re-resolves the roles
    /// fresh and compares the resolved ids to the frozen operands before the observation is
    /// taken. Without it, a role rebind between `resolve_basis` and `observe` would be accepted,
    /// and the journal would record a pre-state for different mailboxes than `apply` mutates,
    /// making it a false record for undo.
    ///
    /// Identity gates compare identity (resolved ids vs frozen operands); a cursor gates
    /// nothing by equality, it only evidences the freshness of the resolution that produced the
    /// comparison inputs (any frozen cursor is stale after the forward's own advance, a
    /// deferral, another client, or a lost-ack gap).
    fn observe(
        &self,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<Observation, ConnectorError> {
        let account = self
            .accounts
            .resolve_account(&command.account)
            .ok_or_else(|| deterministic(JmapErrorCode::AccountUnresolved))?;
        self.reverify_role_basis(&account, command, basis)?;
        let email = self
            .messages
            .resolve_message(&command.account, action_message_ref(&command.action))
            .map_err(|_| ConnectorError::transient("jmap: message store read failed"))?
            .map(|id| EmailId(id.0))
            .ok_or_else(|| deterministic(JmapErrorCode::MessageUnresolved))?;
        let current = self
            .transport
            .email_current_state(&account, &email)
            .map_err(|e| provider_rejection(&e))?;
        let mut atoms = BTreeMap::new();
        for (atom, operand) in &basis.touched_atoms {
            let present = if atom.starts_with("membership:") {
                current.mailbox_ids.contains(operand)
            } else if atom.starts_with("keyword:") {
                current.keywords.contains(operand)
            } else {
                return Err(ConnectorError::deterministic(
                    "jmap: frozen basis carries an atom outside the membership/keyword families",
                ));
            };
            atoms.insert(atom.clone(), present);
        }
        Ok(Observation {
            native_resource_key: native_resource_key(JMAP_KEY_PROVIDER, &[&account.0, &email.0]),
            atoms,
            request_id: None,
            // JMAP has no provider label set — honest absence, never an empty set.
            provider_label_vector: None,
        })
    }

    /// Restore: one `Email/set` through the same plumbing `apply` uses, whose PatchObject is
    /// path-scoped entries derived from the captured pre-state `p` over the frozen operands
    /// (`mailboxIds/<id>` / `keywords/<kw>`: `true` to hold, `null` to drop). The atom-family
    /// dispatch is total and fail-closed, as in `observe`.
    ///
    /// Roles are not re-resolved here: the pair ids come from the basis frozen at the parent's
    /// admission, because a role rebind since would make this write land on mailboxes the
    /// journal never observed (BASIS-6). The whole-object `"mailboxIds": {...}` form RFC 8620
    /// §5.3 permits is prohibited on this path: it cannot express a captured `{Inbox, Archive}`
    /// (or `{neither}`) state without stomping memberships the forward action never touched.
    ///
    /// BASIS-6 runs here, at the dispatch site. The roles are frozen, but the account and the
    /// email id are re-resolved to route the write, so the identity those resolvers answer with
    /// must be re-verified against the frozen one before anything reaches the wire; otherwise a
    /// rebind between the observation and this moment would land the captured memberships on a
    /// different Email. The forward `apply` dispatch site makes the same check and reads its
    /// role pair out of `role_bindings`, as this function does.
    fn restore(
        &self,
        command: &Command,
        basis: &FrozenBasis,
        p: &std::collections::BTreeMap<String, bool>,
    ) -> Result<(), ConnectorError> {
        // Capability gate (ADR-P010). Restore writes the inverse of the parent's forward action
        // as a native delta, so it must clear the same published capability `apply` enforces for
        // that inverse verb; otherwise `undo` of an Archive would dispatch the Unarchive
        // direction even when Unarchive is disabled. It reuses the single `supports` check, and a
        // disabled capability is the existing deterministic "unsupported" refusal, so the undo
        // dead-letters deterministically and dispatches nothing.
        //
        // Every local refusal below is proven pre-wire (`refused_pre_wire`): `restore` is called
        // after the undo drive's own send-authorization boundary, so without the tag these would
        // settle `ACK_AMBIGUOUS`, a parked unknown over refusals decided entirely from local
        // values.
        if !self.capabilities.supports(&command.action.inverse()) {
            return Err(refused_pre_wire(JmapErrorCode::UnsupportedCapability));
        }
        let mut patch: BTreeMap<String, Option<bool>> = BTreeMap::new();
        for (atom, operand) in &basis.touched_atoms {
            // A captured `false` is remove-by-NULL, never JSON `false` (RFC 8620 §5.3).
            let value = match p.get(atom) {
                Some(true) => Some(true),
                Some(false) => None,
                None => return Err(refused_pre_wire(JmapErrorCode::PreStateIncomplete)),
            };
            // The operand becomes a JSON-Pointer path segment, so it is RFC 6901-escaped. On
            // conformant provider ids this is a no-op (see `escape_json_pointer_token`);
            // defensive hygiene, not a security control.
            let token = escape_json_pointer_token(operand);
            let key = if atom.starts_with("membership:") {
                format!("mailboxIds/{token}")
            } else if atom.starts_with("keyword:") {
                format!("keywords/{token}")
            } else {
                return Err(ConnectorError::deterministic(
                    "jmap: frozen basis carries an atom outside the membership/keyword families",
                )
                .proven_no_wire());
            };
            patch.insert(key, value);
        }
        let account = self
            .accounts
            .resolve_account(&command.account)
            .ok_or_else(|| refused_pre_wire(JmapErrorCode::AccountUnresolved))?;
        let email = self
            .messages
            .resolve_message(&command.account, action_message_ref(&command.action))
            .map_err(|_| store_read_failed_pre_wire())?
            .map(|id| EmailId(id.0))
            .ok_or_else(|| refused_pre_wire(JmapErrorCode::MessageUnresolved))?;
        // BASIS-6: the binding must still be the frozen one. The key is recomputed as
        // `resolve_basis` and `observe` compute it, through the single encoding authority, and a
        // mismatch is deterministic: a frozen basis is immutable, so an identical retry can only
        // re-ask the same wrong question. The refusal phrase is the engine's shared, id-free one.
        if native_resource_key(JMAP_KEY_PROVIDER, &[&account.0, &email.0])
            != basis.native_resource_key
        {
            return Err(ConnectorError::deterministic_basis_rebound());
        }
        self.transport
            .email_set(&EmailSetRequest::restore_patch(&account, &email, patch))
            .map_err(|e| provider_rejection(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CommandBus, EffectEvidence, ExecuteError, InMemoryIntentLog, IntentLog, IntentStatus,
        RETRY_CAP,
    };
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::rc::Rc;

    // ---- taxonomy ----

    #[test]
    fn server_unavailable_is_transient() {
        assert_eq!(
            classify_jmap_error(&JmapError::Method(MethodError::ServerUnavailable)),
            FailureKind::Transient
        );
    }

    #[test]
    fn method_rate_limit_is_transient() {
        assert_eq!(
            classify_jmap_error(&JmapError::Method(MethodError::RateLimit)),
            FailureKind::Transient
        );
    }

    #[test]
    fn server_fail_is_deterministic_not_transient() {
        assert_eq!(
            classify_jmap_error(&JmapError::Method(MethodError::ServerFail)),
            FailureKind::Deterministic
        );
    }

    #[test]
    fn server_partial_fail_is_deterministic_requires_resync() {
        assert_eq!(
            classify_jmap_error(&JmapError::Method(MethodError::ServerPartialFail)),
            FailureKind::Deterministic
        );
    }

    #[test]
    fn unknown_method_error_is_deterministic_treated_as_server_fail() {
        assert_eq!(
            classify_jmap_error(&JmapError::Method(MethodError::Unknown)),
            FailureKind::Deterministic
        );
    }

    #[test]
    fn forbidden_and_not_found_set_errors_are_deterministic() {
        assert_eq!(
            classify_jmap_error(&JmapError::Set(SetError::Forbidden)),
            FailureKind::Deterministic
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Set(SetError::NotFound)),
            FailureKind::Deterministic
        );
    }

    #[test]
    fn set_rate_limit_is_transient() {
        assert_eq!(
            classify_jmap_error(&JmapError::Set(SetError::RateLimit)),
            FailureKind::Transient
        );
    }

    #[test]
    fn unknown_set_error_fails_closed_deterministic() {
        assert_eq!(
            classify_jmap_error(&JmapError::Set(SetError::Unknown)),
            FailureKind::Deterministic
        );
    }

    #[test]
    fn jmap_rejections_never_claim_effect_evidence() {
        // THE SCOPE-FENCE TRIPWIRE (§5.2b). `aruna-jmap` ships NO connect-stage
        // proof this slice, so no JMAP rejection may claim one: a post-authorization JMAP
        // TRANSPORT failure is ISSUANCE_UNKNOWN, never `FAILED_PRE_SEND`. This test FAILS the
        // day someone attaches evidence here without landing the stage split that earns it.
        //
        // NARROWED TWICE, NEVER WEAKENED (then). First the
        // per-record `SetError` rows moved out of this list, then the method-level family did —
        // both times to a STRONGER assertion, not a lifted one: each moved family now has a
        // witness that pins EVERY member to `ProvenRefusedNoEffect`
        // (`a_per_record_set_error_is_a_proven_refusal_with_no_effect`,
        // `a_method_level_error_is_a_proven_refusal_with_no_effect`) rather than
        // merely forbidding a claim, because the provider's own answer proves it. What this
        // tripwire still guards is the thing that has not changed: the WIRE axis. Every
        // rejection here — the two proven families included, asserted below — refuses to claim
        // `ProvenNoWire`, because bytes did leave the host.
        for error in [
            // The two method-level members that prove NOTHING: the RFC's own named exception,
            // and our overloaded fail-closed bucket (see `method_error_proves_no_effect`).
            JmapError::Method(MethodError::ServerPartialFail),
            JmapError::Method(MethodError::Unknown),
            JmapError::Request(RequestError::NotJson),
            // The 3xx-shaped NEIGHBOURS of the one-wire refusal: a generic 3xx that reached the
            // status mapper (`map_http_status(302)` → `ClientError`) proves nothing, because it did
            // not come from the mutation route's no-redirect policy. Only the typed variant does.
            JmapError::Transport(TransportError::ClientError(302)),
            JmapError::Transport(TransportError::ClientError(307)),
        ] {
            assert_eq!(
                provider_rejection(&error).effect_evidence,
                crate::EffectEvidence::Indeterminate,
                "a JMAP rejection has nothing to prove about the wire: {error:?}"
            );
        }
        for error in [
            JmapError::Method(MethodError::ServerUnavailable),
            JmapError::Method(MethodError::ServerFail),
            JmapError::Set(SetError::Forbidden),
            JmapError::Set(SetError::NotFound),
            JmapError::Request(RequestError::NotJson),
            JmapError::Transport(TransportError::ClientError(302)),
        ] {
            assert_eq!(
                provider_rejection(&error).effect_evidence.wire_evidence(),
                crate::attempt::WireEvidence::Indeterminate,
                "no JMAP rejection may claim the connect stage sent nothing: {error:?}"
            );
        }
    }

    #[test]
    fn a_per_record_set_error_is_a_proven_refusal_with_no_effect() {
        // A 200-with-`notUpdated[id]` is a POSITIVE NO-EFFECT PROOF,
        // not an absence of proof. RFC 8620 §5.3 defines `notUpdated` as "a map of the record
        // id to a SetError object for each record that failed to be updated" — the provider
        // received the `Email/set`, DECIDED, and named THIS record as one it did not change.
        // That is exactly §5.2b's `ACK_REFUSED_NO_EFFECT`: "the provider ANSWERED and
        // definitively refused BEFORE any effect".
        //
        // The blanket `Indeterminate` default therefore lied by omission on this one family:
        // post-authorization it settled `ACK_AMBIGUOUS` and parked a HUMAN on a question the
        // provider had already answered in writing. (`aruna-jmap`'s
        // `not_updated_with_typed_set_error_is_a_deterministic_failure` pins that a real 200 body
        // with `notUpdated[id]` is exactly what lands here.)
        for set_error in [
            SetError::NotFound,
            SetError::Forbidden,
            SetError::InvalidPatch,
            SetError::InvalidProperties,
            SetError::TooLarge,
            SetError::Singleton,
            SetError::WillDestroy,
            SetError::OverQuota,
            SetError::TooManyMailboxes,
            SetError::MailboxCounts,
            // The proof is the record's PRESENCE in `notUpdated`, not the type token — so an
            // unrecognized type is no-effect too, while its retry KIND stays fail-closed.
            SetError::Unknown,
            SetError::RateLimit,
        ] {
            let refusal = provider_rejection(&JmapError::Set(set_error.clone()));
            assert_eq!(
                refusal.effect_evidence,
                crate::EffectEvidence::ProvenRefusedNoEffect,
                "a per-record SetError PROVES the update did not occur: {set_error:?}"
            );
            // The two axes stay INDEPENDENT: the existing per-SetError-type taxonomy still
            // decides retryability, so a rate limit is refused-no-effect AND retryable.
            assert_eq!(
                refusal.kind,
                classify_jmap_error(&JmapError::Set(set_error.clone())),
                "the evidence axis never overrides the retry taxonomy: {set_error:?}"
            );
        }
        assert_eq!(
            provider_rejection(&JmapError::Set(SetError::RateLimit)).kind,
            FailureKind::Transient,
            "…and the transient member of the family is still retried"
        );
    }

    #[test]
    fn a_method_level_error_is_a_proven_refusal_with_no_effect() {
        // RFC 8620 §3.6.2, the sentence that decides this, VERBATIM:
        //
        //   "With the exception of when the 'serverPartialFail' error is returned, the
        //    externally visible state of the server MUST NOT have changed if an error is
        //    returned at the method level."
        //
        // That is a NORMATIVE guarantee attached to the error's POSITION (a method-level
        // `["error", {type}, callId]` tuple), not to any one type token — and `serverFail`
        // restates it for itself ("The method call made no changes to the server's state").
        // So every method-level answer this transport can receive, save the RFC's own named
        // exception, is §5.2b's `ACK_REFUSED_NO_EFFECT`: the provider ANSWERED and definitively
        // refused BEFORE any effect. Parking a human on it was parking them on a question the
        // RFC had already answered.
        //
        // The `Email/set` is a ONE-CALL request (`build_email_set_body` sends a single method
        // call under a single `callId`, and `parse_email_set_response` correlates that id before
        // reading the tuple), so a method-level error in its response can only belong to the
        // mutation itself — there is no sibling call in the batch to confuse it with.
        for method_error in [
            MethodError::ServerFail,
            MethodError::ServerUnavailable,
            MethodError::RateLimit,
            MethodError::InvalidArguments,
            MethodError::InvalidResultReference,
            MethodError::UnknownMethod,
            MethodError::AccountNotFound,
            MethodError::AccountReadOnly,
            MethodError::AccountNotSupportedByMethod,
            MethodError::Forbidden,
            MethodError::StateMismatch,
        ] {
            let refusal = provider_rejection(&JmapError::Method(method_error.clone()));
            assert_eq!(
                refusal.effect_evidence,
                crate::EffectEvidence::ProvenRefusedNoEffect,
                "a method-level error carries RFC 8620 §3.6.2's own MUST-NOT-have-changed \
                 guarantee: {method_error:?}"
            );
            // The two axes stay INDEPENDENT, exactly as they do for the `SetError` family: the
            // evidence answers "did it happen?", the taxonomy answers "is another attempt worth
            // making?". So the transient members are refused-no-effect AND still retried.
            assert_eq!(
                refusal.kind,
                classify_jmap_error(&JmapError::Method(method_error.clone())),
                "the evidence axis never overrides the retry taxonomy: {method_error:?}"
            );
            assert_eq!(
                refusal.effect_evidence.wire_evidence(),
                crate::attempt::WireEvidence::Indeterminate,
                "…and it never claims the WIRE was clean: bytes did leave the host"
            );
        }
        assert_eq!(
            provider_rejection(&JmapError::Method(MethodError::ServerUnavailable)).kind,
            FailureKind::Transient,
            "…and the transient members are still retried"
        );
    }

    #[test]
    fn server_partial_fail_and_the_unknown_bucket_stay_indeterminate() {
        // THE TWO EXCLUSIONS, and neither is an oversight.
        //
        // `serverPartialFail` is the RFC's OWN named exception — it is the one method-level
        // type that says the opposite: "Some, but not all, expected changes described by the
        // method occurred. The client MUST resynchronise impacted data to determine server
        // state." Claiming no-effect over that sentence would be a durable lie.
        //
        // `MethodError::Unknown` is excluded for a reason that is OURS, not the RFC's. RFC 8620
        // does say a client receiving an error type it does not understand "MUST treat it the
        // same as the 'serverFail' type" — but this variant is not only that. It is the
        // fail-closed bucket `map_method_error`'s `_` arm lands EVERY unrecognized token in,
        // and `aruna-jmap` deliberately spells its own LOCAL synthetic verdicts as tokens that
        // fall through it: `__record_not_in_response__` (HTTP 200, a real `Email/set` answer for
        // our callId, and our record in NEITHER `updated` NOR `notUpdated`),
        // `__malformed_response__`, `__unexpected_method_response__`, `__call_id_mismatch__`,
        // `__empty_response__`. Those are not method-level errors at all — they are the cases
        // where the provider told us NOTHING we can read, which is the definition of
        // Indeterminate. Tagging the bucket would attach the RFC's guarantee to answers the RFC
        // never made. If the variant is ever split (a real unknown provider type vs. our own
        // sentinels), the provider half joins the set above; the sentinels never do.
        for method_error in [MethodError::ServerPartialFail, MethodError::Unknown] {
            assert_eq!(
                provider_rejection(&JmapError::Method(method_error.clone()))
                    .effect_evidence,
                crate::EffectEvidence::Indeterminate,
                "this one proves nothing about the effect: {method_error:?}"
            );
        }
    }

    #[test]
    fn a_method_level_server_fail_surfaces_the_refusal_through_apply() {
        // The same proof at the CONNECTOR's own door — the value the engine's verdict boundary
        // actually reads. A fake endpoint answering the post-authorization `Email/set` with a
        // method-level `serverFail`: pre-fix this reached `settle_attempt` as Indeterminate and
        // settled `ACK_AMBIGUOUS`, parking the operation for human adjudication over an answer
        // RFC 8620 §3.6.2 had already made normative.
        let fake = FakeJmap::healthy()
            .with(|s| s.inject = Some(JmapError::Method(MethodError::ServerFail)));
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("serverFail -> error");

        assert_eq!(
            err.effect_evidence,
            crate::EffectEvidence::ProvenRefusedNoEffect,
            "the provider's own method-level error must reach the verdict door as PROOF, or a \
             post-auth dispatch parks a human on a question the RFC answered"
        );
        assert_eq!(
            err.kind,
            FailureKind::Deterministic,
            "…with its retry classification untouched: `serverFail` will fail again"
        );
        assert_eq!(
            err.effect_evidence.wire_evidence(),
            crate::attempt::WireEvidence::Indeterminate,
            "…and it never claims the WIRE was clean: bytes did leave the host"
        );
    }

    #[test]
    fn a_not_updated_dispatch_surfaces_the_refusal_through_apply() {
        // The same proof at the CONNECTOR's own door — the value the engine's verdict boundary
        // actually reads.
        let fake = FakeJmap::healthy().with(|s| s.inject = Some(JmapError::Set(SetError::NotFound)));
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("notUpdated -> error");

        assert_eq!(
            err.effect_evidence,
            crate::EffectEvidence::ProvenRefusedNoEffect,
            "the provider's own `notUpdated` answer must reach the verdict door as PROOF, or \
             a post-auth dispatch parks for adjudication over an answered question"
        );
        assert_eq!(
            err.effect_evidence.wire_evidence(),
            crate::attempt::WireEvidence::Indeterminate,
            "…and it never claims the WIRE was clean: bytes did leave the host"
        );
    }

    #[test]
    fn a_refused_mutation_redirect_is_indeterminate_never_a_proven_refusal() {
        // §5.2b one-wire contract, CORRECTED — 2026-08-08. The claim
        // was `ProvenRefusedNoEffect`, read off RFC 9110 §15.4's "further action needs to be
        // taken". THE COUNTEREXAMPLE THAT KILLS IT: 303 See Other after a POST is the canonical
        // "your action COMPLETED — go GET the result" answer (RFC 9110 §15.4.4, the classic
        // POST/redirect/GET shape), and 302's own deployed practice is the same. A 3xx therefore
        // does NOT prove the effect did not happen; it proves only that the provider answered with
        // a pointer. Not following that pointer keeps us from making a SECOND effect — it says
        // nothing about the first.
        //
        // So the honest evidence is INDETERMINATE, and the honest cost is a post-auth
        // `ACK_AMBIGUOUS` that parks for adjudication. `ProvenNoWire` would be the bigger lie
        // (bytes did leave the host).
        let refusal =
            provider_rejection(&JmapError::Transport(TransportError::MutationRedirectRefused));
        assert_eq!(
            refusal.kind,
            FailureKind::Deterministic,
            "the identical request earns the identical `Location` — a retry is not worth making"
        );
        assert_eq!(
            refusal.effect_evidence,
            crate::EffectEvidence::Indeterminate,
            "a 303-after-POST is a COMPLETED action's redirect; a 3xx proves nothing about effect"
        );
        assert_eq!(
            refusal.effect_evidence.wire_evidence(),
            crate::attempt::WireEvidence::Indeterminate,
            "nothing here may launder into a post-auth `FAILED_PRE_SEND`"
        );
        // Confinement: the provider-chosen `Location` never rides out.
        assert_eq!(
            refusal.message,
            "jmap: provider redirected the mutation; refused without replay"
        );
    }

    #[test]
    fn request_limit_is_transient_only_for_concurrency_else_deterministic() {
        // Only maxConcurrentRequests lifts on retry; a fixed-shape limit (too large /
        // too many calls) and any structural request error are deterministic.
        assert_eq!(
            classify_jmap_error(&JmapError::Request(RequestError::Limit(
                RequestLimit::MaxConcurrentRequests
            ))),
            FailureKind::Transient
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Request(RequestError::Limit(
                RequestLimit::MaxSizeRequest
            ))),
            FailureKind::Deterministic
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Request(RequestError::Limit(
                RequestLimit::MaxCallsInRequest
            ))),
            FailureKind::Deterministic
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Request(RequestError::NotJson)),
            FailureKind::Deterministic
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Request(RequestError::Unknown)),
            FailureKind::Deterministic
        );
    }

    #[test]
    fn transport_timeouts_and_5xx_and_429_are_transient() {
        assert_eq!(
            classify_jmap_error(&JmapError::Transport(TransportError::Timeout)),
            FailureKind::Transient
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Transport(TransportError::ConnectionReset)),
            FailureKind::Transient
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Transport(TransportError::TooManyRequests)),
            FailureKind::Transient
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Transport(TransportError::ServerError(503))),
            FailureKind::Transient
        );
    }

    #[test]
    fn transport_4xx_and_auth_are_deterministic() {
        assert_eq!(
            classify_jmap_error(&JmapError::Transport(TransportError::ClientError(400))),
            FailureKind::Deterministic
        );
        assert_eq!(
            classify_jmap_error(&JmapError::Transport(TransportError::Unauthorized(401))),
            FailureKind::Deterministic
        );
    }

    // ---- the JMAP-shaped fake (one backend implementing all three seams) ----

    // Distinctive seeded ids — used by the confinement test to prove none leak above the seam.
    const SEED_ACCOUNT_ID: &str = "JMAPACCT-PROVIDER-7f3a";
    const SEED_INBOX_ID: &str = "MBX-INBOX-aa11";
    const SEED_ARCHIVE_ID: &str = "MBX-ARCHIVE-bb22";
    const SEED_EMAIL_ID: &str = "EML-PROVIDER-cc33";

    struct FakeState {
        account_id: Option<AccountId>,
        /// When `Some(a)`, this resolver state answers ONLY for the Photon account `a`
        /// (BASIS-4: resolver identity is per-ACCOUNT). `None` = the pre-existing
        /// account-agnostic fake used by the apply-path tests.
        scoped_to: Option<String>,
        /// The provider-issued Mailbox state cursor this fake's role answers were taken
        /// from (BASIS-3). `None` = freshness unevidenced.
        mailbox_state: Option<String>,
        inbox: Option<MailboxId>,
        archive: Option<MailboxId>,
        // message_ref -> provider Email id
        messages: BTreeMap<String, EmailId>,
        // provider Email id -> current mailbox memberships
        memberships: BTreeMap<String, BTreeSet<MailboxId>>,
        // provider Email id -> current keyword set (RFC 8621 §4.1.1, e.g. "$seen")
        keywords: BTreeMap<String, BTreeSet<String>>,
        // when set, email_set returns this error instead of applying
        inject: Option<JmapError>,
        /// Every `Email/set` REQUEST the connector handed the transport, in order — the wire
        /// shape, recorded before the typed dispatch so a prohibited shape is still visible.
        sets: Vec<EmailSetRequest>,
        /// When set, the message-ref RESOLVER fails with this store error instead of answering.
        /// Its text is BELOW the seam (SQL, paths, provider ids) and must never surface.
        resolver_fault: Option<LogError>,
    }

    #[derive(Clone)]
    struct FakeJmap {
        state: Rc<RefCell<FakeState>>,
    }

    impl FakeJmap {
        /// A healthy account: inbox + archive roles present, one email seeded in the inbox.
        fn healthy() -> Self {
            let inbox = MailboxId(SEED_INBOX_ID.to_string());
            let mut memberships = BTreeMap::new();
            let mut start = BTreeSet::new();
            start.insert(inbox.clone());
            memberships.insert(SEED_EMAIL_ID.to_string(), start);
            let mut messages = BTreeMap::new();
            messages.insert("msg-1".to_string(), EmailId(SEED_EMAIL_ID.to_string()));
            Self {
                state: Rc::new(RefCell::new(FakeState {
                    account_id: Some(AccountId(SEED_ACCOUNT_ID.to_string())),
                    scoped_to: None,
                    mailbox_state: Some("s-1".to_string()),
                    inbox: Some(inbox),
                    archive: Some(MailboxId(SEED_ARCHIVE_ID.to_string())),
                    messages,
                    memberships,
                    keywords: BTreeMap::new(),
                    inject: None,
                    sets: Vec::new(),
                    resolver_fault: None,
                })),
            }
        }

        fn with<F: FnOnce(&mut FakeState)>(self, f: F) -> Self {
            f(&mut self.state.borrow_mut());
            self
        }

        fn membership_ids(&self, email: &str) -> BTreeSet<String> {
            self.state
                .borrow()
                .memberships
                .get(email)
                .map(|s| s.iter().map(|m| m.0.clone()).collect())
                .unwrap_or_default()
        }

        /// The `Email/set` requests this transport was handed, in dispatch order.
        fn sets(&self) -> Vec<EmailSetRequest> {
            self.state.borrow().sets.clone()
        }

        fn keywords_of(&self, email: &str) -> BTreeSet<String> {
            self.state
                .borrow()
                .keywords
                .get(email)
                .cloned()
                .unwrap_or_default()
        }
    }

    impl AccountResolver for FakeJmap {
        fn resolve_account(&self, photon_account: &str) -> Option<AccountId> {
            let s = self.state.borrow();
            // BASIS-4: a scoped fake answers only for the account it was seeded for.
            if let Some(scope) = &s.scoped_to {
                if scope != photon_account {
                    return None;
                }
            }
            s.account_id.clone()
        }
    }

    impl MessageRefResolver for FakeJmap {
        fn resolve_message(
            &self,
            _photon_account: &str,
            message_ref: &str,
        ) -> Result<Option<ProviderMessageId>, LogError> {
            let s = self.state.borrow();
            if let Some(fault) = s.resolver_fault.clone() {
                return Err(fault);
            }
            Ok(s.messages
                .get(message_ref)
                .map(|e| ProviderMessageId(e.0.clone())))
        }
    }

    impl JmapTransport for FakeJmap {
        fn mailbox_id_for_role(
            &self,
            _account: &AccountId,
            role: MailboxRole,
        ) -> Result<Option<MailboxId>, JmapError> {
            let s = self.state.borrow();
            Ok(match role {
                MailboxRole::Inbox => s.inbox.clone(),
                MailboxRole::Archive => s.archive.clone(),
            })
        }

        fn mailbox_state(&self, _account: &AccountId) -> Result<String, JmapError> {
            // The fake's `Option<String>` models presence/absence of a cursor; `None` = a
            // transport that cannot evidence freshness, surfaced as the TRANSIENT unavailability
            // (the recut's typed seam — a deterministic-auth read is modeled by `StateReadFails`).
            self.state
                .borrow()
                .mailbox_state
                .clone()
                .ok_or(JmapError::Method(MethodError::ServerUnavailable))
        }

        /// The fake answers the observation read from the SAME membership/keyword state the
        /// `Email/set` path mutates — so an observe taken before a dispatch reports pre-state
        /// and one taken after reports post-state (what §2.2's "never re-capture" turns on).
        fn email_current_state(
            &self,
            _account: &AccountId,
            email: &EmailId,
        ) -> Result<EmailCurrentState, JmapError> {
            let s = self.state.borrow();
            if let Some(err) = s.inject.clone() {
                return Err(err);
            }
            Ok(EmailCurrentState {
                mailbox_ids: s
                    .memberships
                    .get(&email.0)
                    .map(|set| set.iter().map(|m| m.0.clone()).collect())
                    .unwrap_or_default(),
                keywords: s.keywords.get(&email.0).cloned().unwrap_or_default(),
            })
        }

        /// THE MASK THIS FAKE USED TO WEAR. A conforming JMAP server's
        /// `Mailbox` state cursor DATES THE MAILBOX NAMESPACE, and a membership change is a
        /// change to it: RFC 8621 §2 makes a Mailbox's `totalEmails`/`unreadEmails` part of
        /// the object, so moving one Email between two mailboxes mutates BOTH and the
        /// namespace state advances. This fake left `mailbox_state` frozen across every
        /// `Email/set`, so the forward move's OWN cursor advance — the one every live
        /// move-undo has to survive — was unrepresentable here, and the engine's use of a
        /// stale cursor at observation time could not be witnessed.
        ///
        /// The bump is scoped to MAILBOX ops on purpose: a keywords-only patch changes the
        /// Email, not the Mailbox namespace, and the keyword verbs carry
        /// `Freshness::ImmutableConstants` (nothing resolved, nothing to date). Bumping on
        /// those too would model a provider we are not claiming to model.
        fn email_set(&self, request: &EmailSetRequest) -> Result<(), JmapError> {
            let mut s = self.state.borrow_mut();
            s.sets.push(request.clone());
            if let Some(err) = s.inject.clone() {
                return Err(err);
            }
            // TOTAL dispatch: an unrecognized/empty shape is a deterministic method error,
            // never a silent partial apply (mirrors the live transport's fail-closed path).
            let typed = request
                .typed_updates()
                .map_err(|_| JmapError::Set(SetError::InvalidPatch))?;
            let mut touched_the_mailbox_namespace = false;
            for (email_id, ops) in typed {
                for op in ops {
                    match op {
                        PatchOp::Mailbox { mailbox_id, member } => {
                            touched_the_mailbox_namespace = true;
                            let set = s.memberships.entry(email_id.to_string()).or_default();
                            if member {
                                set.insert(MailboxId(mailbox_id.to_string()));
                            } else {
                                set.remove(&MailboxId(mailbox_id.to_string()));
                            }
                        }
                        PatchOp::Keyword { name, set } => {
                            let kws = s.keywords.entry(email_id.to_string()).or_default();
                            if set {
                                kws.insert(name.to_string());
                            } else {
                                kws.remove(name);
                            }
                        }
                    }
                }
            }
            // …and the namespace is re-dated. Only when it evidences freshness at all: a
            // `None` cursor means THIS fake models a transport that cannot date the
            // namespace (the BASIS-3 refusal arms), and inventing one here would erase them.
            if touched_the_mailbox_namespace && s.mailbox_state.is_some() {
                let n = s.sets.len();
                s.mailbox_state = Some(format!("s-after-set-{n}"));
            }
            Ok(())
        }
    }

    // `list_inbox_page`/`fetch_body` DEFAULT = REFUSE ----

    /// A transport implementing ONLY the trait's two required methods (`mailbox_id_for_role`,
    /// `email_set`) — proving, AS A COMPILE FACT, the additive guarantee the design's
    /// TRAIT-DEFAULTS fold promises: adding `list_inbox_page`/`fetch_body` (and, earlier,
    /// `mailbox_state`/`email_current_state`) never forces an edit here. If any new method
    /// lost its default body this struct would stop compiling, which is the whole test.
    struct MinimalJmapTransport;

    impl JmapTransport for MinimalJmapTransport {
        fn mailbox_id_for_role(
            &self,
            _account: &AccountId,
            _role: MailboxRole,
        ) -> Result<Option<MailboxId>, JmapError> {
            Ok(None)
        }

        fn email_set(&self, _request: &EmailSetRequest) -> Result<(), JmapError> {
            Ok(())
        }
    }

    #[test]
    fn an_unwired_transport_refuses_list_inbox_page_loudly() {
        let transport = MinimalJmapTransport;
        let error = transport
            .list_inbox_page(&AccountId(SEED_ACCOUNT_ID.to_string()), 50, None)
            .expect_err("DEFAULT = REFUSE: an unwired transport must not fabricate an empty inbox");
        assert_eq!(error, JmapError::Method(MethodError::Unknown));
    }

    #[test]
    fn an_unwired_transport_refuses_fetch_body_loudly() {
        let transport = MinimalJmapTransport;
        let error = transport
            .fetch_body(
                &AccountId(SEED_ACCOUNT_ID.to_string()),
                &EmailId(SEED_EMAIL_ID.to_string()),
            )
            .expect_err("DEFAULT = REFUSE: an unwired transport must not fabricate an empty body");
        assert_eq!(error, JmapError::Method(MethodError::Unknown));
    }

    fn archive(message_ref: &str) -> Command {
        Command::new(
            "k1",
            "photon-acct",
            crate::Facet::Mail,
            Action::Archive {
                message_ref: message_ref.to_string(),
            },
        )
    }

    /// Dispatch the way the ENGINE does: freeze the basis at admission, then
    /// hand THAT basis to the wire — `apply` consumes it (identity verified, role pair read
    /// straight out of it) and never re-resolves (BASIS-6). The bus's own two-step.
    ///
    /// The arms that break a resolver ON PURPOSE cannot freeze at all; they probe `apply`'s OWN
    /// refusals, which fire on those same resolvers BEFORE the identity comparison, so an
    /// unfreezable command is dispatched against a placeholder and still reaches the door it
    /// names.
    fn dispatch<T: JmapTransport, A: AccountResolver, M: MessageRefResolver>(
        conn: &JmapConnector<T, A, M>,
        command: &Command,
    ) -> Result<(), ConnectorError> {
        let basis = conn.resolve_basis(command).unwrap_or_else(|_| FrozenBasis {
            native_resource_key: native_resource_key(JMAP_KEY_PROVIDER, &["<unfreezable>"]),
            touched_atoms: [("keyword:$seen".to_string(), "$seen".to_string())]
                .into_iter()
                .collect(),
            atom_targets: [("keyword:$seen".to_string(), true)].into_iter().collect(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        });
        conn.apply(command, &basis)
    }

    /// An Archive command for an EXPLICIT Photon account (the BASIS-4 scoping arms).
    fn archive_command(account: &str, message_ref: &str) -> Command {
        Command::new(
            "k1",
            account,
            crate::Facet::Mail,
            Action::Archive {
                message_ref: message_ref.to_string(),
            },
        )
    }

    /// A `SetFlag` command for an EXPLICIT Photon account. The keyword family needs no role
    /// mailboxes and no state cursor, so a fixture can vary ONLY the provider ids under test.
    fn seen_command(account: &str, message_ref: &str) -> Command {
        Command::new(
            "k1",
            account,
            crate::Facet::Mail,
            Action::SetFlag {
                message_ref: message_ref.to_string(),
                flag: MailFlag::Seen,
                value: true,
            },
        )
    }

    /// A healthy fake whose provider account/email ids are set EXACTLY — the arms that probe
    /// what happens when OPAQUE provider ids contain the character a key encoding uses.
    fn fake_with_provider_ids(account_id: &str, email_id: &str) -> FakeJmap {
        FakeJmap::healthy().with(|s| {
            s.account_id = Some(AccountId(account_id.to_string()));
            s.messages = [("msg-1".to_string(), EmailId(email_id.to_string()))]
                .into_iter()
                .collect();
        })
    }

    #[test]
    fn native_keys_of_differently_split_provider_ids_are_never_equal() {
        // Regression test. Joining native-key components with '/'
        // is AMBIGUOUS: provider ids are OPAQUE, so `(account="a/b", email="c")` and
        // `(account="a", email="b/c")` both encoded `jmap:a/b/c`. A resolver rebind between
        // those two pairs then passed BASIS-6's equality check and the engine dispatched
        // against the WRONG message. Never reason from provider id-charset promises — encode
        // injectively, at ONE authority.
        let split_left = fake_with_provider_ids("a/b", "c");
        let split_right = fake_with_provider_ids("a", "b/c");
        let key_of = |f: &FakeJmap| {
            JmapConnector::new(f.clone(), f.clone(), f.clone())
                .resolve_basis(&seen_command("photon-acct", "msg-1"))
                .unwrap()
                .native_resource_key
        };
        assert_ne!(
            key_of(&split_left),
            key_of(&split_right),
            "two DIFFERENT (account, email) pairs must never encode to one native key"
        );
    }

    #[test]
    fn an_observe_rebind_between_ambiguous_id_splits_is_not_equal_to_the_frozen_key() {
        // The observe-side arm of the same class: BASIS-6 verifies the observation's key
        // against the FROZEN key by string equality (`ensure_prepared`). Under the ambiguous
        // encoding a rebind from `(a/b, c)` to `(a, b/c)` produced the SAME string, so the
        // rebind passed and the pre-state journal became a witness for a message the provider
        // never answered for. The keys must differ, so the engine's own equality check refuses.
        let fake = fake_with_provider_ids("a/b", "c");
        let connector = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let command = seen_command("photon-acct", "msg-1");
        let basis = connector.resolve_basis(&command).expect("freeze");
        // REBIND: the resolver now answers with the OTHER split of the same characters.
        fake.clone().with(|s| {
            s.account_id = Some(AccountId("a".to_string()));
            s.messages = [("msg-1".to_string(), EmailId("b/c".to_string()))]
                .into_iter()
                .collect();
        });
        let observation = connector.observe(&command, &basis).expect("observe");
        assert_ne!(
            observation.native_resource_key, basis.native_resource_key,
            "a rebind onto a DIFFERENT provider pair must not re-encode to the frozen key"
        );
    }

    /// A DIFFERENT provider Email the message-ref resolver can rebind ONTO.
    const REBOUND_EMAIL_ID: &str = "EML-PROVIDER-REBOUND-9a1";

    /// A message-ref resolver that REBINDS MID-FLIGHT (the JMAP twin of the Gmail fixture):
    /// the seeded Email for the first `stable` resolutions, a different one after.
    struct RebindingMessageRefs {
        inner: FakeJmap,
        stable: std::cell::Cell<usize>,
        rebound: ProviderMessageId,
    }

    impl MessageRefResolver for RebindingMessageRefs {
        fn resolve_message(
            &self,
            photon_account: &str,
            message_ref: &str,
        ) -> Result<Option<ProviderMessageId>, LogError> {
            match self.stable.get() {
                0 => Ok(Some(self.rebound.clone())),
                n => {
                    self.stable.set(n - 1);
                    self.inner.resolve_message(photon_account, message_ref)
                }
            }
        }
    }

    /// A transport that PERMUTES the two role mailboxes after `stable` role lookups: Inbox
    /// starts answering the archive's id and Archive the inbox's. RFC 8621 §2 makes `role`
    /// client-mutable, so this is reachable via data — and it is the exact history
    /// `reverify_role_basis` refuses BEFORE the observation, leaving the observe→apply window
    /// as the one `apply` had to close by consuming the FROZEN ids.
    struct PermutingRoles {
        inner: FakeJmap,
        stable: std::cell::Cell<usize>,
    }

    impl JmapTransport for PermutingRoles {
        fn mailbox_id_for_role(
            &self,
            account: &AccountId,
            role: MailboxRole,
        ) -> Result<Option<MailboxId>, JmapError> {
            let asked = match self.stable.get() {
                0 => match role {
                    MailboxRole::Inbox => MailboxRole::Archive,
                    MailboxRole::Archive => MailboxRole::Inbox,
                },
                n => {
                    self.stable.set(n - 1);
                    role
                }
            };
            self.inner.mailbox_id_for_role(account, asked)
        }

        fn mailbox_state(&self, account: &AccountId) -> Result<String, JmapError> {
            self.inner.mailbox_state(account)
        }

        fn email_current_state(
            &self,
            account: &AccountId,
            email: &EmailId,
        ) -> Result<EmailCurrentState, JmapError> {
            self.inner.email_current_state(account, email)
        }

        fn email_set(&self, request: &EmailSetRequest) -> Result<(), JmapError> {
            self.inner.email_set(request)
        }
    }

    #[test]
    fn forward_dispatch_never_retargets_the_wire_onto_a_rebound_email() {
        // the identity half ═══ `apply` re-resolves account + Email to
        // ROUTE the write, so the identity those resolvers answer with must be re-verified
        // against the FROZEN one before the wire — the same check `restore` has carried since
        // and named `apply` as the stage-4 deferral for. Rebind at the THIRD resolution:
        // 1 = `resolve_basis`, 2 = `observe`, 3 = `apply`.
        let fake = FakeJmap::healthy();
        fake.clone().with(|s| {
            s.memberships.insert(
                REBOUND_EMAIL_ID.to_string(),
                [MailboxId(SEED_INBOX_ID.to_string())].into_iter().collect(),
            );
        });
        let messages = RebindingMessageRefs {
            inner: fake.clone(),
            stable: std::cell::Cell::new(2),
            rebound: ProviderMessageId(REBOUND_EMAIL_ID.to_string()),
        };
        let connector = JmapConnector::new(fake.clone(), fake.clone(), messages);
        let mut bus = CommandBus::new(InMemoryIntentLog::new(), connector);

        let outcome = bus.execute(&archive("msg-1"));
        match &outcome {
            Err(ExecuteError::Connector(error)) => {
                assert_eq!(error.kind, FailureKind::Deterministic);
                assert_eq!(
                    error.effect_evidence,
                    EffectEvidence::ProvenNoWire,
                    "decided on a LOCAL comparison before any Email/set is built"
                );
            }
            other => panic!("a rebound binding must REFUSE pre-wire, got {other:?}"),
        }
        assert!(
            fake.sets().is_empty(),
            "nothing may reach the wire on a refused dispatch, got {:?}",
            fake.sets()
        );
        assert_eq!(
            fake.membership_ids(REBOUND_EMAIL_ID),
            [SEED_INBOX_ID.to_string()].into_iter().collect::<BTreeSet<_>>(),
            "the REBOUND email is a stranger to this operation and must be untouched"
        );
    }

    #[test]
    fn forward_dispatch_moves_the_frozen_role_pair_not_a_re_resolved_one() {
        // the OPERAND half ═══ The residual `apply` carried by name
        // ("`apply` RE-RESOLVES the roles at dispatch rather than dispatching the
        // admission-frozen directional ids … the observe→apply window is the dispatch stage's to close by
        // carrying the frozen directional ids into dispatch"). This is that stage, and the close is
        // the one `restore` already ships: the pair ids come from the FROZEN basis, never from a
        // re-resolution — so there is no window left in which a permutation can invert them.
        //
        // Role lookups before the wire: `resolve_basis` takes 2 (require_role × 2) and `observe`
        // takes 2 (`reverify_role_basis`), so the permutation is armed at the 5th — `apply`'s.
        let fake = FakeJmap::healthy();
        let transport = PermutingRoles {
            inner: fake.clone(),
            stable: std::cell::Cell::new(4),
        };
        let connector = JmapConnector::new(transport, fake.clone(), fake.clone());
        let mut bus = CommandBus::new(InMemoryIntentLog::new(), connector);

        bus.execute(&archive("msg-1"))
            .expect("a permutation AFTER the verified observation must not defeat the dispatch");
        assert_eq!(
            fake.membership_ids(SEED_EMAIL_ID),
            [SEED_ARCHIVE_ID.to_string()].into_iter().collect::<BTreeSet<_>>(),
            "the Archive must move the FROZEN inbox id -> the FROZEN archive id; a re-resolved \
             pair inverts the direction and silently no-ops the move"
        );
    }

    // ---- the resolver seam (BASIS-2/-3/-4) ----

    #[test]
    fn resolve_basis_freezes_the_pair_and_carries_the_state_cursor() {
        // BASIS-3/-4: role→id resolution is account-scoped and cursor-evidenced.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let basis = c.resolve_basis(&archive_command("photon-acct", "msg-1")).unwrap();
        assert_eq!(
            basis.native_resource_key,
            native_resource_key(JMAP_KEY_PROVIDER, &[SEED_ACCOUNT_ID, SEED_EMAIL_ID])
        );
        assert!(basis
            .touched_atoms
            .contains_key(&format!("membership:{SEED_INBOX_ID}")));
        assert!(basis
            .touched_atoms
            .contains_key(&format!("membership:{SEED_ARCHIVE_ID}")));
        assert_eq!(
            basis.freshness,
            crate::prestate::Freshness::StateCursor {
                cursor: "s-1".into()
            }
        );
    }

    #[test]
    fn jmap_resolve_basis_freezes_the_pair_direction() {
        // §3.1a: Archive is a MOVE — the source membership drops and the destination gains.
        // WHICH frozen mailbox id is source and which is destination is knowable ONLY here,
        // at role resolution; after this moment the ids are opaque equals and the direction
        // is unrecoverable. So the pair direction is frozen into `A` at resolve time.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let basis = c
            .resolve_basis(&archive_command("photon-acct", "msg-1"))
            .unwrap();
        assert_eq!(
            basis.atom_targets.get(&format!("membership:{SEED_INBOX_ID}")),
            Some(&false),
            "archive: source drops"
        );
        assert_eq!(
            basis
                .atom_targets
                .get(&format!("membership:{SEED_ARCHIVE_ID}")),
            Some(&true),
            "archive: destination gains"
        );
        let un = c.resolve_basis(&unarchive("msg-1")).unwrap();
        assert_eq!(
            un.atom_targets.get(&format!("membership:{SEED_INBOX_ID}")),
            Some(&true)
        );
        assert_eq!(
            un.atom_targets
                .get(&format!("membership:{SEED_ARCHIVE_ID}")),
            Some(&false)
        );
        // The keyword family has positive polarity on JMAP (the atom IS `$seen`).
        let seen = c.resolve_basis(&seen_command("photon-acct", "msg-1")).unwrap();
        assert_eq!(seen.atom_targets.get("keyword:$seen"), Some(&true));
    }

    // ---- the restore seam (§3.1/§4.2: the native delta written from the captured P) ----

    #[test]
    fn jmap_restore_refuses_the_inverse_direction_a_disabled_capability_forbids() {
        // Restore writes the INVERSE of the parent's forward action as a
        // native delta (§4.2), so it must clear the SAME published capability gate `apply`
        // makes for that inverse verb — else `undo` of an Archive dispatches the Unarchive
        // direction even when Unarchive is disabled. Archive on, Unarchive OFF ⇒ the restore
        // is refused deterministically and dispatches NOTHING (the undo dead-letters honestly).
        let fake = FakeJmap::healthy();
        let c = JmapConnector::with_capabilities(
            fake.clone(),
            fake.clone(),
            fake.clone(),
            CapabilityMap::custom(true, false, true, true),
        );
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        // P = the captured pre-state (back in the inbox, out of archive) — the Unarchive delta.
        let p: BTreeMap<String, bool> = [
            (format!("membership:{SEED_INBOX_ID}"), true),
            (format!("membership:{SEED_ARCHIVE_ID}"), false),
        ]
        .into_iter()
        .collect();
        let before = fake.sets().len();
        let err = c
            .restore(&cmd, &basis, &p)
            .expect_err("unarchive disabled ⇒ restore of an archive refuses");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert_eq!(fake.sets().len(), before, "a capability refusal dispatches nothing");
    }

    #[test]
    fn jmap_restore_is_path_scoped_and_writes_the_captured_pair() {
        // W-STALE's multi-label arm. The captured pre-state here is the NONCANONICAL one an
        // external client can produce and a whole-object write cannot express without
        // stomping untouched memberships: the message was in BOTH pair mailboxes. The patch
        // must therefore be PATH-SCOPED entries only — one per captured atom, value from P
        // (`true` to hold, `null` to drop) — and must never carry a whole-object
        // `mailboxIds` key, which RFC 8620 §5.3 permits but this path prohibits.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        let inbox_path = format!("mailboxIds/{SEED_INBOX_ID}");
        let archive_path = format!("mailboxIds/{SEED_ARCHIVE_ID}");

        let both: BTreeMap<String, bool> = [
            (format!("membership:{SEED_INBOX_ID}"), true),
            (format!("membership:{SEED_ARCHIVE_ID}"), true),
        ]
        .into_iter()
        .collect();
        c.restore(&cmd, &basis, &both).expect("restore dispatches");
        let request = fake.sets().pop().expect("one Email/set recorded");
        let patch = request
            .update
            .get(SEED_EMAIL_ID)
            .expect("the patch is keyed by the FROZEN email id");
        assert_eq!(
            patch.keys().cloned().collect::<BTreeSet<String>>(),
            [inbox_path.clone(), archive_path.clone()]
                .into_iter()
                .collect::<BTreeSet<String>>(),
            "exactly the captured atoms, path-scoped"
        );
        assert_eq!(patch.get(&inbox_path), Some(&Some(true)));
        assert_eq!(patch.get(&archive_path), Some(&Some(true)));
        assert!(
            !patch.contains_key("mailboxIds"),
            "a whole-object mailboxIds write strands the {{Inbox, Archive}} pre-state"
        );
        assert_eq!(
            fake.membership_ids(SEED_EMAIL_ID),
            [SEED_INBOX_ID.to_string(), SEED_ARCHIVE_ID.to_string()]
                .into_iter()
                .collect::<BTreeSet<String>>(),
            "the provider ends holding BOTH memberships the capture recorded"
        );

        // A captured `false` is the PatchObject removal (`null`), never `false` — RFC 8620
        // §5.3's remove-by-null, the same shape the forward move uses.
        let only_inbox: BTreeMap<String, bool> = [
            (format!("membership:{SEED_INBOX_ID}"), true),
            (format!("membership:{SEED_ARCHIVE_ID}"), false),
        ]
        .into_iter()
        .collect();
        c.restore(&cmd, &basis, &only_inbox).expect("restore dispatches");
        let request = fake.sets().pop().expect("one Email/set recorded");
        let patch = request.update.get(SEED_EMAIL_ID).expect("patch");
        assert_eq!(patch.get(&inbox_path), Some(&Some(true)));
        assert_eq!(patch.get(&archive_path), Some(&None));

        // The keyword family rides the same path grammar (`keywords/<kw>`).
        let seen = seen_command("photon-acct", "msg-1");
        let seen_basis = c.resolve_basis(&seen).unwrap();
        let unseen: BTreeMap<String, bool> = [("keyword:$seen".to_string(), false)]
            .into_iter()
            .collect();
        c.restore(&seen, &seen_basis, &unseen).expect("restore dispatches");
        let request = fake.sets().pop().expect("one Email/set recorded");
        let patch = request.update.get(SEED_EMAIL_ID).expect("patch");
        assert_eq!(patch.get("keywords/$seen"), Some(&None));

        // Delta grain is TOTAL: an atom the capture does not cover is a deterministic
        // refusal — never a guessed value — and nothing is dispatched.
        let before = fake.sets().len();
        let err = c
            .restore(&cmd, &basis, &BTreeMap::new())
            .expect_err("an uncovered atom must refuse");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert_eq!(fake.sets().len(), before, "a refusal dispatches nothing");
    }

    #[test]
    fn restore_escapes_json_pointer_metacharacters_in_mailbox_ids() {
        // DEFENSIVE ROBUSTNESS, NOT A CONTROL. A CONFORMANT provider cannot
        // emit these — RFC 8620 §1.2 restricts an Id to `[A-Za-z0-9_-]` — so this arm exercises
        // a NON-CONFORMANT provider whose operands carry the RFC 6901 metacharacters `/` (→ ~1)
        // and `~` (→ ~0). Unescaped, they forge extra JSON-Pointer path segments; escaped, the
        // PatchObject path is well-formed. (A hostile provider owns the mailbox namespace
        // directly, so a crafted id buys it nothing — theater; this is hygiene.)
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        // Start from a real basis (correct frozen native_resource_key so BASIS-6 passes), then
        // substitute non-conformant operands into the frozen atom set.
        let mut basis = c.resolve_basis(&cmd).unwrap();
        basis.touched_atoms = [
            ("membership:a/b".to_string(), "a/b".to_string()),
            ("membership:x~y".to_string(), "x~y".to_string()),
        ]
        .into_iter()
        .collect();
        basis.atom_targets = [
            ("membership:a/b".to_string(), true),
            ("membership:x~y".to_string(), true),
        ]
        .into_iter()
        .collect();
        let p: BTreeMap<String, bool> = [
            ("membership:a/b".to_string(), true),
            ("membership:x~y".to_string(), true),
        ]
        .into_iter()
        .collect();
        c.restore(&cmd, &basis, &p).expect("restore dispatches");
        let request = fake.sets().pop().expect("one Email/set recorded");
        let patch = request
            .update
            .get(SEED_EMAIL_ID)
            .expect("the patch is keyed by the FROZEN email id");
        assert_eq!(
            patch.keys().cloned().collect::<BTreeSet<String>>(),
            ["mailboxIds/a~1b".to_string(), "mailboxIds/x~0y".to_string()]
                .into_iter()
                .collect::<BTreeSet<String>>(),
            "'/' escapes to ~1 and '~' to ~0 (RFC 6901) — never raw path metacharacters"
        );
        assert!(
            !patch.contains_key("mailboxIds/a/b"),
            "an unescaped '/' forges an extra JSON-Pointer path segment"
        );
    }

    #[test]
    fn jmap_restore_refuses_a_rebound_identity_before_dispatch() {
        // BASIS-6 AT THE RESTORE DISPATCH SITE — the JMAP half of the same
        // class the Gmail connector carries. `restore` deliberately does NOT re-resolve the
        // role mailboxes (the operands come from the frozen basis), but it DOES re-resolve the
        // account and the Email id through the same resolvers `resolve_basis`/`observe` use,
        // and never compared the recomputed native key against the frozen one. A message-ref
        // rebind between the observation and the restore therefore aimed the path-scoped
        // `Email/set` at a DIFFERENT Email — writing the captured memberships onto a message
        // that never had them.
        //
        // BASIS-6: every later step verifies the current binding still matches the frozen
        // basis and REFUSES on mismatch. Deterministic, because the frozen basis is immutable.
        const REBOUND_EMAIL_ID: &str = "EML-PROVIDER-REBOUND-9999";
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        // A total capture over the frozen pair: nothing here is what refuses.
        let p: BTreeMap<String, bool> = [
            (format!("membership:{SEED_INBOX_ID}"), true),
            (format!("membership:{SEED_ARCHIVE_ID}"), false),
        ]
        .into_iter()
        .collect();
        // THE REBIND: the same Photon-local ref now resolves to another provider Email.
        fake.state.borrow_mut().messages.insert(
            "msg-1".to_string(),
            EmailId(REBOUND_EMAIL_ID.to_string()),
        );
        let before = fake.sets().len();

        let err = c
            .restore(&cmd, &basis, &p)
            .expect_err("a rebound identity must refuse BEFORE the Email/set");

        assert_eq!(
            err.kind,
            FailureKind::Deterministic,
            "a frozen basis is immutable — retrying re-asks the same wrong question"
        );
        assert_eq!(
            fake.sets().len(),
            before,
            "NOTHING is dispatched: the refusal precedes the wire"
        );
        assert!(
            fake.membership_ids(REBOUND_EMAIL_ID).is_empty(),
            "the rebound Email was never touched"
        );
        assert_eq!(
            fake.membership_ids(SEED_EMAIL_ID),
            [SEED_INBOX_ID.to_string()].into_iter().collect::<BTreeSet<String>>(),
            "…and the frozen Email is exactly as the observation left it"
        );
        // Confinement by construction: the refusal names no provider handle.
        for id in [REBOUND_EMAIL_ID, SEED_EMAIL_ID, SEED_ACCOUNT_ID] {
            assert!(
                !err.message.contains(id),
                "a provider id rode the rebind refusal: {}",
                err.message
            );
        }
    }

    /// A store failure's own text: a SQLite condition, an on-disk path, and a provider id —
    /// exactly the unconstrained below-seam material an `{e.0}` interpolation would copy out.
    const BELOW_SEAM_FAULT_TEXT: &str =
        "SQLITE_BUSY: UPDATE refs SET email_id='EML-PROVIDER-cc33' (/var/photon/store.sqlite)";

    #[test]
    fn a_resolver_failure_surfaces_a_fixed_id_free_refusal() {
        // The SAME class as gmail.rs: `resolve_basis` runs at ADMISSION and its refusal reaches
        // the caller through execute(). Built from a fixed phrase — never from the store error.
        let fake = FakeJmap::healthy()
            .with(|s| s.resolver_fault = Some(LogError(BELOW_SEAM_FAULT_TEXT.to_string())));
        let mut bus = CommandBus::new(
            crate::InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let err = bus
            .execute(&archive("msg-1"))
            .expect_err("a resolver failure refuses admission");
        let surfaced = format!("{err:?}");
        for leaked in ["SQLITE_BUSY", SEED_EMAIL_ID, "/var/photon/store.sqlite"] {
            assert!(
                !surfaced.contains(leaked),
                "below-seam text {leaked} leaked above the seam: {surfaced}"
            );
        }
        assert!(
            surfaced.contains("message resolver failure"),
            "the FIXED phrase is what surfaces: {surfaced}"
        );
    }

    #[test]
    fn resolve_basis_refuses_without_a_freshness_cursor() {
        // BASIS-3: value equality alone is not freshness; no cursor ⇒ named retryable refusal.
        let fake = FakeJmap::healthy().with(|s| s.mailbox_state = None);
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let err = c
            .resolve_basis(&archive_command("photon-acct", "msg-1"))
            .unwrap_err();
        assert!(err.0.contains("freshness"), "named refusal, got: {}", err.0);
    }

    #[test]
    fn a_role_token_never_crosses_accounts() {
        // BASIS-4 (arm): resolver identity is scoped per ACCOUNT — account B's resolver
        // state cannot answer for account A.
        let fake = FakeJmap::healthy().with(|s| s.scoped_to = Some("acct-b".to_string()));
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        assert!(c.resolve_basis(&archive_command("acct-a", "msg-1")).is_err());
    }

    #[test]
    fn keyword_verbs_resolve_as_provider_constants_without_a_cursor() {
        // The keyword atoms ($seen/$flagged) need NO role resolution — they are
        // provider-constants, so `ImmutableConstants` is their honest freshness and a
        // missing Mailbox cursor does NOT refuse them (only ROLE-resolving verbs require it).
        let fake = FakeJmap::healthy().with(|s| s.mailbox_state = None);
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = Command::new(
            "k-seen",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag {
                message_ref: "msg-1".to_string(),
                flag: MailFlag::Seen,
                value: true,
            },
        );
        let basis = c.resolve_basis(&cmd).unwrap();
        assert!(basis.touched_atoms.contains_key("keyword:$seen"));
        assert_eq!(
            basis.freshness,
            crate::prestate::Freshness::ImmutableConstants
        );
    }

    #[test]
    fn observe_answers_the_frozen_atoms_for_the_frozen_identity() {
        // §2.2 observe: the provider read answers FOR the native identity it read (the
        // BASIS-6 verify input), projected onto exactly the frozen atoms.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        let obs = c.observe(&cmd, &basis).unwrap();
        assert_eq!(obs.native_resource_key, basis.native_resource_key);
        assert_eq!(
            obs.atoms.get(&format!("membership:{SEED_INBOX_ID}")),
            Some(&true),
            "the seeded email is in the inbox"
        );
        assert_eq!(
            obs.atoms.get(&format!("membership:{SEED_ARCHIVE_ID}")),
            Some(&false)
        );
    }

    // ---- BASIS-6 at observation: the frozen ROLE basis is re-verified, never assumed ----

    #[test]
    fn observe_refuses_when_a_role_rebound_between_resolve_and_observe() {
        // BASIS-6: every later step verifies the current binding still matches the frozen basis.
        // Here the account's `archive` role is re-pointed at a DIFFERENT mailbox after admission
        // froze the basis. The EMAIL read still answers for the frozen atoms (the message is
        // untouched), so the engine-level rebind check at lib.rs:2011 cannot see this — yet
        // `apply` re-resolves roles and would move the message into a mailbox `pre_state` never
        // recorded. Observation must refuse.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        // The role rebinds; the cursor moves with it (a real provider would advance state).
        fake.state.borrow_mut().archive = Some(MailboxId("MBX-ARCHIVE-REBOUND".to_string()));
        fake.state.borrow_mut().mailbox_state = Some("s-2".to_string());
        let err = c
            .observe(&cmd, &basis)
            .expect_err("a rebound role must refuse at observation, never be silently accepted");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert!(
            err.message.contains("basis rebound"),
            "the named BASIS-6 refusal, got: {}",
            err.message
        );
    }

    #[test]
    fn observe_accepts_a_moved_cursor_when_every_resolved_id_still_matches() {
        // RECUT by the WHOLESALE close (was
        // `observe_refuses_provider_state_aba_same_ids_moved_cursor`). It asserted the gate that
        // is now GONE: cursor value-equality against the frozen basis. Two failures proved that
        // gate cannot tell a provider-state ABA from the ordinary, legitimate ways the Mailbox
        // namespace moves between admission and observation — the forward move re-dating it
        // itself, a deferral, ANOTHER CLIENT, a lost-ack re-drive — and it refused all
        // of them DETERMINISTICALLY, dead-lettering correct operations.
        //
        // The complement stands in its place: identity gates compare IDENTITY (freshly resolved
        // ids vs frozen operands); a cursor evidences the FRESHNESS of that resolution and gates
        // nothing by equality. Here the roles re-resolve to the very mailboxes admission froze,
        // so the binding HOLDS and the observation is taken.
        //
        // GIVEN UP BY NAME: an A→B→A in this window is no longer refused. What it can still hide
        // is a third party's content change — design §8 residual 2 (requalify-to-write TOCTOU),
        // untouched and still open.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        assert_eq!(
            basis.freshness,
            crate::prestate::Freshness::StateCursor { cursor: "s-1".into() }
        );
        // Ids unchanged; ONLY the state token moved.
        fake.state.borrow_mut().mailbox_state = Some("s-2".to_string());
        let obs = c
            .observe(&cmd, &basis)
            .expect("a moved cursor over UNCHANGED ids is not a rebound — the binding holds");
        assert_eq!(obs.native_resource_key, basis.native_resource_key);
        assert_eq!(
            obs.atoms.get(&format!("membership:{SEED_INBOX_ID}")),
            Some(&true),
            "…and the observation is the real one, taken for the frozen atoms"
        );
    }

    #[test]
    fn reverify_refuses_a_stable_role_permutation() {
        // Regression test (2026-08-08, verified by execution). A stable Inbox↔Archive
        // permutation PRESERVES the id set {inbox_id, archive_id} but INVERTS the role→id mapping.
        // The retired gate compared an UNORDERED id set, so the swap PASSED while the roles
        // genuinely rebound — `apply` would then write the INVERSE direction and the journal's
        // frozen A becomes the inverse of reality (silent wrong answer on both undo halves). The
        // role-keyed map compare refuses it. RFC 8621 §2: `role` is client-mutable, so reachable.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        // The frozen mapping names each role's own mailbox.
        assert_eq!(
            basis.role_bindings.get("inbox").map(String::as_str),
            Some(SEED_INBOX_ID)
        );
        assert_eq!(
            basis.role_bindings.get("archive").map(String::as_str),
            Some(SEED_ARCHIVE_ID)
        );
        // THE SWAP: inbox now resolves to the archive's old id and vice-versa — the id SET is
        // identical, only the direction inverted. The cursor advances (a real permutation is a
        // Mailbox-type state change), but the gate never compares the cursor.
        {
            let mut s = fake.state.borrow_mut();
            s.inbox = Some(MailboxId(SEED_ARCHIVE_ID.to_string()));
            s.archive = Some(MailboxId(SEED_INBOX_ID.to_string()));
            s.mailbox_state = Some("s-permuted".to_string());
        }
        let err = c.observe(&cmd, &basis).expect_err(
            "a stable role permutation preserves the id set but rebinds the roles — must refuse",
        );
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert!(
            err.message.contains("basis rebound"),
            "the named BASIS-6 refusal, got: {}",
            err.message
        );
    }

    #[test]
    fn reverify_accepts_when_the_role_mapping_is_unchanged() {
        // GREEN guard for the role-keyed gate: the ids AND the role→id mapping are both intact,
        // only the cursor moved (the forward move re-dates the namespace itself). The binding
        // holds, so the observation is taken — the recut refuses PERMUTATIONS, not moved cursors.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        fake.state.borrow_mut().mailbox_state = Some("s-moved".to_string());
        let obs = c
            .observe(&cmd, &basis)
            .expect("an unchanged role→id mapping over a moved cursor is not a rebound");
        assert_eq!(obs.native_resource_key, basis.native_resource_key);
    }

    /// A transport whose `mailbox_state` read fails with a configured provider error, while every
    /// other seam delegates to the wrapped healthy fake. Models the error-taxonomy laundering the
    /// recut closes: the retired `Option<String>` seam erased a deterministic 401 to `None`, which
    /// `reverify_role_basis` then read as a transient "unavailable".
    struct StateReadFails {
        inner: FakeJmap,
        error: JmapError,
    }

    impl JmapTransport for StateReadFails {
        fn mailbox_id_for_role(
            &self,
            account: &AccountId,
            role: MailboxRole,
        ) -> Result<Option<MailboxId>, JmapError> {
            self.inner.mailbox_id_for_role(account, role)
        }

        fn mailbox_state(&self, _account: &AccountId) -> Result<String, JmapError> {
            Err(self.error.clone())
        }

        fn email_current_state(
            &self,
            account: &AccountId,
            email: &EmailId,
        ) -> Result<EmailCurrentState, JmapError> {
            self.inner.email_current_state(account, email)
        }

        fn email_set(&self, request: &EmailSetRequest) -> Result<(), JmapError> {
            self.inner.email_set(request)
        }
    }

    #[test]
    fn state_read_401_is_deterministic_not_transient() {
        // The state-read seam now returns a TYPED error, so a
        // DETERMINISTIC 401/403 (auth/permission) re-verifying a move basis dead-letters instead
        // of laundering into a transient retry-loop. Build the basis with a healthy transport (the
        // read succeeds at admission), then re-verify against a transport whose state read fails.
        let fake = FakeJmap::healthy();
        let basis = {
            let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
            c.resolve_basis(&archive_command("photon-acct", "msg-1")).unwrap()
        };
        let cmd = archive_command("photon-acct", "msg-1");
        let c = JmapConnector::new(
            StateReadFails {
                inner: fake.clone(),
                error: JmapError::Transport(TransportError::Unauthorized(401)),
            },
            fake.clone(),
            fake.clone(),
        );
        let err = c
            .observe(&cmd, &basis)
            .expect_err("a deterministic auth failure on the state read must not pass");
        assert_eq!(
            err.kind,
            FailureKind::Deterministic,
            "a 401 on the freshness read is deterministic, never a transient retry-loop: {}",
            err.message
        );
        // Control: a genuine transient (timeout) on the same read stays TRANSIENT — the seam
        // preserves the classification both ways, it does not blanket-deterministic every failure.
        let c_transient = JmapConnector::new(
            StateReadFails {
                inner: fake.clone(),
                error: JmapError::Transport(TransportError::Timeout),
            },
            fake.clone(),
            fake.clone(),
        );
        let err_t = c_transient
            .observe(&cmd, &basis)
            .expect_err("a timeout still refuses (verify-or-refuse)");
        assert_eq!(
            err_t.kind,
            FailureKind::Transient,
            "a timeout on the freshness read is retryable"
        );
    }

    /// A transport that models the provider MOVING DURING re-verification. The role lookups and
    /// the cursor read are separate round-trips, so the namespace can shift between them: on the
    /// FIRST `mailbox_id_for_role` call this fake re-points the Archive role and immediately
    /// restores it (an A→B→A that leaves every id reading back IDENTICAL) while advancing the
    /// provider's Mailbox state cursor — the ONE witness that anything happened. Everything else
    /// delegates to the wrapped fake.
    ///
    /// `armed = false` is the CONTROL: the same wrapper, nothing moving.
    struct RoleLookupMovesTheNamespace {
        inner: FakeJmap,
        armed: std::cell::Cell<bool>,
    }

    impl RoleLookupMovesTheNamespace {
        fn new(inner: FakeJmap, armed: bool) -> Self {
            Self {
                inner,
                armed: std::cell::Cell::new(armed),
            }
        }
    }

    impl JmapTransport for RoleLookupMovesTheNamespace {
        fn mailbox_id_for_role(
            &self,
            account: &AccountId,
            role: MailboxRole,
        ) -> Result<Option<MailboxId>, JmapError> {
            if self.armed.replace(false) {
                // A→B→A: the ids the verification is about to read are unchanged, so an
                // ids-only comparison cannot see this. Only the cursor moved.
                self.inner.state.borrow_mut().mailbox_state = Some("s-2".to_string());
            }
            self.inner.mailbox_id_for_role(account, role)
        }

        fn mailbox_state(&self, account: &AccountId) -> Result<String, JmapError> {
            self.inner.mailbox_state(account)
        }

        fn email_current_state(
            &self,
            account: &AccountId,
            email: &EmailId,
        ) -> Result<EmailCurrentState, JmapError> {
            self.inner.email_current_state(account, email)
        }

        fn email_set(&self, request: &EmailSetRequest) -> Result<(), JmapError> {
            self.inner.email_set(request)
        }
    }

    #[test]
    fn observe_refuses_when_the_namespace_moves_between_the_cursor_read_and_the_role_lookups() {
        // Regression test. `reverify_role_basis` read the cursor ONCE, BEFORE the role
        // lookups — so the two halves of the verification described DIFFERENT moments: the
        // cursor was read from the pre-move namespace and the ids from the post-move one, and
        // the reading was not one snapshot.
        //
        // The SANDWICH closes it: cursor₁ → role lookups → cursor₂, and the two must AGREE.
        // SURVIVES the wholesale close UNCHANGED, because it never was an identity gate:
        // both slices read the CURRENT cursor and are compared only to EACH OTHER. It is the
        // COHERENCE of this reading — the freshness evidence BASIS-3 demands for the fresh role
        // resolution — not a value comparison against anything frozen.
        let fake = FakeJmap::healthy();
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = {
            let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
            c.resolve_basis(&cmd).unwrap()
        };
        assert_eq!(
            basis.freshness,
            crate::prestate::Freshness::StateCursor { cursor: "s-1".into() },
            "precondition: the frozen cursor is the pre-move one"
        );
        let racing = JmapConnector::new(
            RoleLookupMovesTheNamespace::new(fake.clone(), true),
            fake.clone(),
            fake.clone(),
        );
        let err = racing
            .observe(&cmd, &basis)
            .expect_err("a namespace that moved DURING verification must refuse, not be accepted");
        // TRANSIENT, not the deterministic rebound: the two cursor reads disagreeing means the
        // READING was incoherent, which is not proof that the basis rebound — the same
        // verify-or-refuse honesty an unreadable cursor already gets. A retry re-runs the whole
        // sandwich against a settled namespace.
        assert_eq!(err.kind, FailureKind::Transient, "got: {}", err.message);
        assert!(
            err.message.contains("moved DURING"),
            "the refusal must name the mid-verification move, got: {}",
            err.message
        );
    }

    #[test]
    fn observe_accepts_when_the_cursor_holds_still_across_the_role_lookups() {
        // The non-vacuity control for the sandwich: the SAME wrapper, disarmed. Nothing moves
        // between the two cursor reads, so the observation is taken normally — the sandwich must
        // not refuse a quiet provider.
        let fake = FakeJmap::healthy();
        let cmd = archive_command("photon-acct", "msg-1");
        let c = JmapConnector::new(
            RoleLookupMovesTheNamespace::new(fake.clone(), false),
            fake.clone(),
            fake.clone(),
        );
        let basis = c.resolve_basis(&cmd).unwrap();
        let obs = c.observe(&cmd, &basis).expect("an unmoved namespace observes");
        assert_eq!(obs.native_resource_key, basis.native_resource_key);
    }

    #[test]
    fn observe_refuses_retryably_when_the_cursor_cannot_be_read() {
        // Verify-or-refuse, honestly classified: a reading we could not TAKE is not proof of a
        // rebind, so it is TRANSIENT (the intent stays retryable) — never a dead-letter, and
        // never a silent pass.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        fake.state.borrow_mut().mailbox_state = None;
        let err = c
            .observe(&cmd, &basis)
            .expect_err("an unevidenced cursor must refuse, not pass");
        assert_eq!(err.kind, FailureKind::Transient);
    }

    #[test]
    fn observe_accepts_an_unchanged_role_basis() {
        // The non-vacuity companion: nothing moved ⇒ the re-verification passes and the
        // observation is taken normally.
        let fake = FakeJmap::healthy();
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive_command("photon-acct", "msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        let obs = c.observe(&cmd, &basis).expect("an unchanged basis observes");
        assert_eq!(obs.native_resource_key, basis.native_resource_key);
    }

    #[test]
    fn keyword_verbs_observe_without_any_role_reverification() {
        // Keyword verbs ride provider CONSTANTS ($seen/$flagged): nothing was role-resolved, so
        // there is nothing to re-verify and a missing Mailbox cursor must not refuse them —
        // exactly mirroring `resolve_basis`'s per-family split.
        let fake = FakeJmap::healthy().with(|s| s.mailbox_state = None);
        let c = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = Command::new(
            "k-seen",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag {
                message_ref: "msg-1".to_string(),
                flag: MailFlag::Seen,
                value: true,
            },
        );
        let basis = c.resolve_basis(&cmd).unwrap();
        let obs = c.observe(&cmd, &basis).expect("keyword observe needs no cursor");
        assert_eq!(obs.atoms.get("keyword:$seen"), Some(&false));
    }

    fn unarchive(message_ref: &str) -> Command {
        Command::new(
            "k1",
            "photon-acct",
            crate::Facet::Mail,
            Action::Unarchive {
                message_ref: message_ref.to_string(),
            },
        )
    }

    // ---- connector behavior ----

    #[test]
    fn archive_moves_the_email_from_inbox_to_archive() {
        let fake = FakeJmap::healthy();
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        dispatch(&conn, &archive("msg-1")).expect("archive should succeed");

        let ids = fake.membership_ids(SEED_EMAIL_ID);
        assert!(ids.contains(SEED_ARCHIVE_ID), "email should now be in archive");
        assert!(!ids.contains(SEED_INBOX_ID), "email should no longer be in inbox");
    }

    #[test]
    fn connector_resolves_message_refs_via_the_real_store() {
        // The real SqliteMessageStore is a drop-in for the M0 fake at the MessageRefResolver seam:
        // seed it, build a connector with it as the message resolver, and prove an archive moves
        // the email the store resolved.
        use crate::message_store::SqliteMessageStore;
        use crate::read_model::Placement;
        use crate::SqliteIntentLog;

        let path = crate::test_temp::TempFile::sqlite("aruna-store-seam");
        let _log = SqliteIntentLog::open(&path).unwrap();
        let mut store = SqliteMessageStore::open(&path).unwrap();
        store
            .record_optimistic_placement(
                "photon-acct",
                "msg-real",
                &ProviderMessageId(SEED_EMAIL_ID.to_string()),
                Placement::Inbox,
            )
            .unwrap();

        let fake = FakeJmap::healthy();
        let conn = JmapConnector::new(fake.clone(), fake.clone(), store);

        dispatch(&conn, &Command::new(
            "k-seam",
            "photon-acct",
            crate::Facet::Mail,
            Action::Archive {
                message_ref: "msg-real".into(),
            },
        ))
        .expect("archive via the real store should succeed");

        let ids = fake.membership_ids(SEED_EMAIL_ID);
        assert!(ids.contains(SEED_ARCHIVE_ID), "email should now be in archive");
        assert!(!ids.contains(SEED_INBOX_ID), "email should no longer be in inbox");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unarchive_is_the_inverse_move() {
        // Seed the email in archive, then unarchive back to inbox.
        let fake = FakeJmap::healthy().with(|s| {
            let mut set = BTreeSet::new();
            set.insert(MailboxId(SEED_ARCHIVE_ID.to_string()));
            s.memberships.insert(SEED_EMAIL_ID.to_string(), set);
        });
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        dispatch(&conn, &unarchive("msg-1")).expect("unarchive should succeed");

        let ids = fake.membership_ids(SEED_EMAIL_ID);
        assert!(ids.contains(SEED_INBOX_ID), "email should be back in inbox");
        assert!(!ids.contains(SEED_ARCHIVE_ID), "email should no longer be in archive");
    }

    #[test]
    fn set_flag_seen_sets_and_clears_the_seen_keyword() {
        // The JMAP mechanic: SetFlag{Seen,true} → keywords/$seen set; false → cleared.
        // NEUTRALITY HEADLINE (JMAP half): the same neutral action drives a KEYWORD here and a
        // LABEL toggle on Gmail (gmail.rs twin test) — one verb, two native mechanics (ADR-P003).
        let fake = FakeJmap::healthy();
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = Command::new(
            "k-seen",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: true },
        );
        dispatch(&conn, &cmd).expect("set seen");
        assert!(fake.keywords_of(SEED_EMAIL_ID).contains("$seen"));

        let clear = Command::new(
            "k-unseen",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: false },
        );
        dispatch(&conn, &clear).expect("clear seen");
        assert!(!fake.keywords_of(SEED_EMAIL_ID).contains("$seen"));
    }

    #[test]
    fn set_flag_flagged_sets_and_clears_the_flagged_keyword() {
        // The JMAP mechanic: SetFlag{Flagged,true} → keywords/$flagged set; false → cleared
        // (RFC 8621 §10.4.3). Positive on BOTH sides — no inversion anywhere, unlike Seen on
        // Gmail; the gmail.rs STARRED test is this test's twin (star/unstar design 2026-07-26 §3).
        let fake = FakeJmap::healthy();
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let star = Command::new(
            "k-flag",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: true },
        );
        dispatch(&conn, &star).expect("set flagged");
        assert!(fake.keywords_of(SEED_EMAIL_ID).contains("$flagged"));

        let clear = Command::new(
            "k-unflag",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: false },
        );
        dispatch(&conn, &clear).expect("clear flagged");
        assert!(!fake.keywords_of(SEED_EMAIL_ID).contains("$flagged"));
    }

    #[test]
    fn set_flag_capability_is_per_flag_and_published_by_default() {
        let caps = CapabilityMap::m1_verbs();
        assert!(caps.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Seen,
            value: true,
        }));
        // A map without the flag capability fails safe + visibly (ADR-P010).
        let no_flag = CapabilityMap::custom(true, true, false, true);
        assert!(!no_flag.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Seen,
            value: true,
        }));
    }

    #[test]
    fn set_flag_flagged_capability_is_per_flag_and_published_by_default() {
        // The Flagged row is its OWN capability (per-flag, never wholesale): default-published,
        // and refusing it must not disturb Seen (star/unstar design 2026-07-26 §3/§5.2).
        let caps = CapabilityMap::m1_verbs();
        assert!(caps.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Flagged,
            value: true,
        }));
        let no_flagged = CapabilityMap::custom(true, true, true, false);
        assert!(!no_flagged.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Flagged,
            value: true,
        }));
        assert!(no_flagged.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Seen,
            value: true,
        }));
    }

    #[test]
    fn unsupported_action_fails_safe_deterministic() {
        let fake = FakeJmap::healthy();
        let conn = JmapConnector::with_capabilities(
            fake.clone(),
            fake.clone(),
            fake.clone(),
            CapabilityMap::custom(false, true, true, true),
        );

        let err = dispatch(&conn, &archive("msg-1")).expect_err("archive unsupported -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn jmap_refuses_every_triage_verb_pre_wire_with_the_typed_unsupported_code() {
        // JMAP DECLARES the four triage verbs unsupported. No capability
        // row publishes them, admission refuses them by a typed code, and `apply` refuses them
        // deterministically, PROVEN pre-wire, with zero `Email/set` requests reaching the
        // transport. A tracked "JMAP trash/spam" issue is filed at merge.
        let m = || "msg-1".to_string();
        let caps = CapabilityMap::m1_verbs(); // JMAP's own map type in this module
        let verbs = [
            Action::Trash { message_ref: m() },
            Action::Untrash { message_ref: m() },
            Action::MarkSpam { message_ref: m() },
            Action::UnmarkSpam { message_ref: m() },
        ];
        for a in &verbs {
            assert!(!caps.supports(a), "{a:?}");
        }
        for a in verbs {
            // A HEALTHY fake: every resolver would answer, so a refusal is the verb's own.
            let fake = FakeJmap::healthy();
            let connector = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
            let cmd = Command::new("k", "photon-acct", crate::Facet::Mail, a.clone());
            // Admission: the typed refusal — never a basis frozen for a verb JMAP cannot express.
            assert_eq!(
                connector.resolve_basis(&cmd).expect_err("admission must refuse"),
                refuse_basis(JmapBasisRefusal::UnsupportedCapability),
                "{a:?}"
            );
            // Dispatch, handed a VALID basis for the same message (so neither an identity
            // rebind nor a resolver miss can explain the refusal): the published-map refusal.
            let basis = connector.resolve_basis(&archive("msg-1")).expect("archive basis");
            let err = connector.apply(&cmd, &basis).unwrap_err();
            assert_eq!(err.kind, FailureKind::Deterministic, "{a:?}");
            assert_eq!(err.effect_evidence, EffectEvidence::ProvenNoWire, "{a:?}");
            assert_eq!(err.message, JmapErrorCode::UnsupportedCapability.message(), "{a:?}");
            // The observation door refuses the same way: there is no role basis to re-verify
            // for a verb JMAP never freezes (mutation witness: an `Ok` there survived).
            let observe_err = connector.observe(&cmd, &basis).unwrap_err();
            assert_eq!(observe_err.kind, FailureKind::Deterministic, "{a:?}");
            assert_eq!(observe_err.message, JmapErrorCode::UnsupportedCapability.message(), "{a:?}");
            // Undo of such a verb is refused at the SAME published map (its inverse is one of
            // the four too), before any patch is built.
            let restore_err = connector.restore(&cmd, &basis, &BTreeMap::new()).unwrap_err();
            assert_eq!(restore_err.kind, FailureKind::Deterministic, "{a:?}");
            assert_eq!(restore_err.effect_evidence, EffectEvidence::ProvenNoWire, "{a:?}");
            assert!(fake.sets().is_empty(), "zero Email/set requests reached the wire: {a:?}");
        }
    }

    #[test]
    fn account_resolution_miss_is_deterministic() {
        let fake = FakeJmap::healthy().with(|s| s.account_id = None);
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("no account -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn message_resolution_miss_is_deterministic() {
        let fake = FakeJmap::healthy();
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("no-such-ref")).expect_err("unknown message -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn absent_role_mailbox_is_deterministic() {
        // RFC 8621 §2: roles are optional. Archiving needs an archive mailbox — and WHERE that
        // is decided moved with the fold: `apply` no longer resolves roles at all, so an
        // absent role is now caught at the FREEZE (`resolve_basis` → `RoleAbsent`, retryable
        // because admission wrote nothing) and, if a basis somehow reaches the wire without the
        // frozen pair, by `apply`'s own fail-closed arm. Both doors, both refusals.
        let fake = FakeJmap::healthy().with(|s| s.archive = None);
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let refusal = conn
            .resolve_basis(&archive("msg-1"))
            .expect_err("no archive mailbox -> the freeze refuses");
        assert!(
            !refusal.0.contains(SEED_INBOX_ID) && !refusal.0.contains(SEED_ACCOUNT_ID),
            "the admission refusal stays id-free: {}",
            refusal.0
        );

        // …and the dispatch door's own arm: a move basis with NO frozen role bindings cannot say
        // which mailbox plays which role, so it refuses DETERMINISTICALLY rather than falling
        // back to the re-resolution the fold removed.
        let unbound = FrozenBasis {
            native_resource_key: native_resource_key(
                JMAP_KEY_PROVIDER,
                &[SEED_ACCOUNT_ID, SEED_EMAIL_ID],
            ),
            touched_atoms: [(
                format!("membership:{SEED_INBOX_ID}"),
                SEED_INBOX_ID.to_string(),
            )]
            .into_iter()
            .collect(),
            atom_targets: [(format!("membership:{SEED_INBOX_ID}"), false)]
                .into_iter()
                .collect(),
            role_bindings: BTreeMap::new(),
            freshness: Freshness::StateCursor {
                cursor: "s-1".to_string(),
            },
        };
        let err = conn
            .apply(&archive("msg-1"), &unbound)
            .expect_err("a move basis with no frozen role direction -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert!(
            fake.sets().is_empty(),
            "and nothing reached the wire, got {:?}",
            fake.sets()
        );
    }

    #[test]
    fn deterministic_provider_rejection_maps_to_deterministic() {
        let fake = FakeJmap::healthy().with(|s| s.inject = Some(JmapError::Set(SetError::NotFound)));
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("provider NotFound -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn transient_provider_rejection_maps_to_transient() {
        let fake = FakeJmap::healthy()
            .with(|s| s.inject = Some(JmapError::Method(MethodError::ServerUnavailable)));
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("serverUnavailable -> error");
        assert_eq!(err.kind, FailureKind::Transient);
    }

    #[test]
    fn no_provider_ids_leak_into_surfaced_errors() {
        // Force every failure path and assert no seeded provider id appears in the surfaced message.
        let seeds = [SEED_ACCOUNT_ID, SEED_INBOX_ID, SEED_ARCHIVE_ID, SEED_EMAIL_ID];
        let cases = vec![
            FakeJmap::healthy().with(|s| s.inject = Some(JmapError::Set(SetError::NotFound))),
            FakeJmap::healthy()
                .with(|s| s.inject = Some(JmapError::Method(MethodError::ServerUnavailable))),
            FakeJmap::healthy().with(|s| s.archive = None),
        ];
        for fake in cases {
            let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
            // BOTH doors of the dispatch two-step: the FREEZE (where an unresolvable role or
            // account is now decided) and the WIRE. Whichever refuses, its message must
            // be free of every seeded provider id.
            let messages = [
                conn.resolve_basis(&archive("msg-1")).err().map(|e| e.0),
                dispatch(&conn, &archive("msg-1")).err().map(|e| e.message),
            ];
            assert!(
                messages.iter().any(Option::is_some),
                "every case here must refuse at one of the two doors"
            );
            for message in messages.into_iter().flatten() {
                for seed in seeds {
                    assert!(
                        !message.contains(seed),
                        "provider id {seed} leaked into error message: {message}"
                    );
                }
            }
        }
    }

    #[test]
    fn email_set_request_is_a_valid_set_subset() {
        let req = EmailSetRequest::move_mailbox(
            &AccountId(SEED_ACCOUNT_ID.to_string()),
            &EmailId(SEED_EMAIL_ID.to_string()),
            &MailboxId(SEED_INBOX_ID.to_string()),
            &MailboxId(SEED_ARCHIVE_ID.to_string()),
        );
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["accountId"], SEED_ACCOUNT_ID);
        let patch = &json["update"][SEED_EMAIL_ID];
        assert_eq!(patch[format!("mailboxIds/{SEED_ARCHIVE_ID}")], serde_json::json!(true));
        assert_eq!(patch[format!("mailboxIds/{SEED_INBOX_ID}")], serde_json::json!(null));
    }

    // the total typed dispatch (M1 §2: silent-drop closed) ----

    #[test]
    fn typed_updates_carries_mailbox_and_keyword_patches() {
        let req = EmailSetRequest::move_mailbox(
            &AccountId("a1".into()),
            &EmailId("e1".into()),
            &MailboxId("inbox".into()),
            &MailboxId("arch".into()),
        );
        let typed = req.typed_updates().expect("total dispatch");
        assert_eq!(typed.len(), 1);
        let (email, ops) = &typed[0];
        assert_eq!(*email, "e1");
        assert!(ops.contains(&PatchOp::Mailbox { mailbox_id: "inbox", member: false }));
        assert!(ops.contains(&PatchOp::Mailbox { mailbox_id: "arch", member: true }));

        let kw = EmailSetRequest::set_keyword(
            &AccountId("a1".into()),
            &EmailId("e1".into()),
            "$seen",
            true,
        );
        let typed = kw.typed_updates().expect("total dispatch");
        assert_eq!(
            typed[0].1,
            vec![PatchOp::Keyword { name: "$seen", set: true }]
        );
    }

    #[test]
    fn typed_updates_rejects_unknown_and_mixed_and_empty_shapes_whole() {
        // Hand-built foreign shapes (in-module, fields visible): the dispatch must reject the
        // WHOLE request — never filter, never part-apply (RFC 8620 §5.3; class
        // `exhaustive-patch-consumption`; red-witness: the old mailbox_updates() filter silently
        // dropped exactly these).
        let mk = |patch: std::collections::BTreeMap<String, Option<bool>>| {
            let mut update = std::collections::BTreeMap::new();
            update.insert("e1".to_string(), patch);
            EmailSetRequest { account_id: "a1".into(), update }
        };
        // unknown prefix alone
        let mut p = std::collections::BTreeMap::new();
        p.insert("headers/x".to_string(), Some(true));
        assert!(mk(p).typed_updates().is_err());
        // valid mailbox patch MIXED with an unknown key — the multi-prefix partial case
        let mut p = std::collections::BTreeMap::new();
        p.insert("mailboxIds/inbox".to_string(), None);
        p.insert("frobnicate/x".to_string(), Some(true));
        assert!(mk(p).typed_updates().is_err(), "mixed known+unknown must reject WHOLE");
        // valid keyword patch mixed with an unknown key
        let mut p = std::collections::BTreeMap::new();
        p.insert("keywords/$seen".to_string(), Some(true));
        p.insert("bogus".to_string(), None);
        assert!(mk(p).typed_updates().is_err());
        // a record whose projected patch is empty
        assert!(mk(std::collections::BTreeMap::new()).typed_updates().is_err());
        // zero records
        let empty = EmailSetRequest { account_id: "a1".into(), update: std::collections::BTreeMap::new() };
        assert!(empty.typed_updates().is_err());
    }

    #[test]
    fn set_keyword_request_serializes_to_the_keywords_pointer_shape() {
        let req = EmailSetRequest::set_keyword(
            &AccountId("acct".into()),
            &EmailId("e7".into()),
            "$seen",
            false,
        );
        let json = serde_json::to_value(&req).expect("serialize");
        // RFC 8620 PatchObject: clear = null (removes the set member).
        assert_eq!(json["update"]["e7"]["keywords/$seen"], serde_json::Value::Null);
        let set = EmailSetRequest::set_keyword(
            &AccountId("acct".into()),
            &EmailId("e7".into()),
            "$seen",
            true,
        );
        let json = serde_json::to_value(&set).expect("serialize");
        assert_eq!(json["update"]["e7"]["keywords/$seen"], serde_json::json!(true));

        // The $flagged twin (star/unstar design 2026-07-26 §5.4): same pointer shape, same
        // remove-by-null grammar.
        let flagged = EmailSetRequest::set_keyword(
            &AccountId("acct".into()),
            &EmailId("e7".into()),
            "$flagged",
            true,
        );
        let json = serde_json::to_value(&flagged).expect("serialize");
        assert_eq!(json["update"]["e7"]["keywords/$flagged"], serde_json::json!(true));
        let unflagged = EmailSetRequest::set_keyword(
            &AccountId("acct".into()),
            &EmailId("e7".into()),
            "$flagged",
            false,
        );
        let json = serde_json::to_value(&unflagged).expect("serialize");
        assert_eq!(json["update"]["e7"]["keywords/$flagged"], serde_json::Value::Null);
    }

    // ---- end-to-end through the bus (the connector drives the real ADR-P013 lifecycle) ----

    #[test]
    fn bus_executes_archive_through_the_jmap_connector() {
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );

        bus.execute(&archive("msg-1")).expect("execute should succeed");

        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Applied
        );
        assert!(fake.membership_ids(SEED_EMAIL_ID).contains(SEED_ARCHIVE_ID));
    }

    #[test]
    fn bus_dead_letters_a_deterministic_provider_failure() {
        let fake = FakeJmap::healthy().with(|s| s.inject = Some(JmapError::Set(SetError::Forbidden)));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );

        let result = bus.execute(&archive("msg-1"));
        assert!(matches!(result, Err(ExecuteError::Connector(_))));
        // Deterministic failure dead-letters immediately via the PR lifecycle.
        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Failed
        );
    }

    /// A transport that answers the MUTATION — and only the mutation — with the one-wire redirect
    /// refusal. Everything else (the freshness cursor, the role lookups, the observation read)
    /// delegates to a healthy fake, so the failure lands where the defect is about: AFTER the
    /// send-authorization boundary. (`FakeJmap::inject` fires on the observation read too, which
    /// would refuse the dispatch PRE-authorization and prove nothing about post-auth evidence.)
    struct RedirectsTheMutation {
        inner: FakeJmap,
    }

    impl JmapTransport for RedirectsTheMutation {
        fn mailbox_id_for_role(
            &self,
            account: &AccountId,
            role: MailboxRole,
        ) -> Result<Option<MailboxId>, JmapError> {
            self.inner.mailbox_id_for_role(account, role)
        }

        fn mailbox_state(&self, account: &AccountId) -> Result<String, JmapError> {
            self.inner.mailbox_state(account)
        }

        fn email_current_state(
            &self,
            account: &AccountId,
            email: &EmailId,
        ) -> Result<EmailCurrentState, JmapError> {
            self.inner.email_current_state(account, email)
        }

        fn email_set(&self, _request: &EmailSetRequest) -> Result<(), JmapError> {
            Err(JmapError::Transport(TransportError::MutationRedirectRefused))
        }
    }

    #[test]
    fn a_built_in_local_refusal_after_send_authorization_is_proven_no_wire_not_ambiguous() {
        // `Connector::apply` runs AFTER the send-authorization boundary, so
        // the connector's OWN pre-transport refusals — the published capability gate, the account
        // and message-ref resolvers, a local store read failure — used to settle post-auth with
        // the constructor's fail-closed `Indeterminate`. That is `ACK_AMBIGUOUS`: a durable open
        // unknown, parked for a human, over a refusal that provably never built a request, let
        // alone sent one.
        //
        // The honest verdict is `FAILED_PRE_SEND` with the taxonomy's own lifecycle — here a
        // DETERMINISTIC unsupported verb, so it dead-letters immediately.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::with_capabilities(
                fake.clone(),
                fake.clone(),
                fake.clone(),
                // Archive DISABLED; everything the capture pipeline needs still works, so the
                // refusal lands at `apply` — past the claim, past the authorization.
                CapabilityMap::custom(false, true, true, true),
            ),
        );

        let result = bus.execute(&archive("msg-1"));
        assert!(matches!(result, Err(ExecuteError::Connector(_))));
        let kinds: Vec<crate::attempt::FactKind> = bus
            .log()
            .attempt_facts()
            .iter()
            .map(|fact| fact.kind)
            .collect();
        assert!(
            kinds.contains(&crate::attempt::FactKind::SendAuthorized),
            "the premise: this refusal happens POST-authorization; chain was {kinds:?}"
        );
        assert!(
            kinds.contains(&crate::attempt::FactKind::FailedPreSend),
            "a refusal that never built a request is FAILED_PRE_SEND; chain was {kinds:?}"
        );
        assert!(
            !kinds.contains(&crate::attempt::FactKind::AckAmbiguous),
            "no adjudication is owed for a local refusal; chain was {kinds:?}"
        );
        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Failed,
            "the retry taxonomy still decides the lifecycle: a deterministic refusal dead-letters"
        );
    }

    #[test]
    fn a_redirected_mutation_parks_awaiting_adjudication_and_never_terminalizes_refused() {
        // THE ENGINE-LEVEL ARM of the correction. A redirect answered AFTER the
        // send-authorization boundary is ISSUANCE_UNKNOWN: the attempt records `ACK_AMBIGUOUS`
        // and the OPERATION stays open for a human, because no local record can tell a
        // "307, nothing done" from a "303, already done, go look".
        //
        // What this test forbids, by name: `ACK_REFUSED_NO_EFFECT` + a `Failed` dead-letter,
        // which is what shipped — a durable claim of NO EFFECT that the provider never made.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(
                RedirectsTheMutation {
                    inner: fake.clone(),
                },
                fake.clone(),
                fake.clone(),
            ),
        );

        let result = bus.execute(&archive("msg-1"));
        assert!(matches!(result, Err(ExecuteError::Connector(_))));
        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Pending,
            "ISSUANCE_UNKNOWN is neither a completion nor a retry — the operation parks, it is \
             never dead-lettered on a no-effect claim nobody made"
        );
        let kinds: Vec<crate::attempt::FactKind> = bus
            .log()
            .attempt_facts()
            .iter()
            .map(|fact| fact.kind)
            .collect();
        assert!(
            kinds.contains(&crate::attempt::FactKind::AckAmbiguous),
            "a post-auth redirect settles ACK_AMBIGUOUS; chain was {kinds:?}"
        );
        assert!(
            !kinds.contains(&crate::attempt::FactKind::AckRefusedNoEffect),
            "the chain must never record a refusal the provider did not prove; chain was {kinds:?}"
        );
    }

    #[test]
    fn bus_dead_letters_a_transient_provider_failure_at_the_retry_cap() {
        // The taxonomy must drive the PR retry-cap lifecycle, not just the deterministic path: a
        // persistent TRANSIENT JMAP failure stays Pending and is retried, then dead-letters to Failed
        // once the budget is exhausted (TaxonomyLifecycleProofGap).
        let fake = FakeJmap::healthy()
            .with(|s| s.inject = Some(JmapError::Method(MethodError::ServerUnavailable)));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );

        // Initial dispatch = attempt 1: surfaced as a connector error, intent stays Pending.
        assert!(matches!(
            bus.execute(&archive("msg-1")),
            Err(ExecuteError::Connector(_))
        ));
        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Pending,
            "one transient JMAP failure is retryable, not dead-lettered"
        );

        // Each sweep burns another attempt; RETRY_CAP-1 more exhausts the budget.
        for _ in 0..(RETRY_CAP - 1) {
            bus.recover().expect("recovery sweep runs");
        }

        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Failed,
            "a transient JMAP failure retried past RETRY_CAP dead-letters to Failed"
        );
    }

    #[test]
    fn set_flag_applies_through_the_bus_and_lands_applied() {
        // End-to-end: SetFlag → Applied; the durable row round-trips the set_flag:seen:true
        // token through the real SqliteIntentLog (mirrors the module's archive end-to-end test
        // with the action swapped and a re-read assertion added).
        use crate::SqliteIntentLog;
        let path = crate::test_temp::TempFile::sqlite("aruna-jmap-setflag-bus");
        let fake = FakeJmap::healthy();
        let action = Action::SetFlag {
            message_ref: "msg-1".to_string(),
            flag: MailFlag::Seen,
            value: true,
        };
        let cmd = Command::new("k-sf", "photon-acct", crate::Facet::Mail, action.clone());
        {
            let mut bus = CommandBus::new(
                SqliteIntentLog::open(&path).expect("open"),
                JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
            );
            bus.execute(&cmd).expect("execute should succeed");
            assert_eq!(
                bus.log().get("k-sf").unwrap().unwrap().status,
                IntentStatus::Applied
            );
            assert!(fake.keywords_of(SEED_EMAIL_ID).contains("$seen"));
        } // drop → reopen: the durable token must round-trip through the real log
        let log = SqliteIntentLog::open(&path).expect("reopen");
        let stored = log.get("k-sf").unwrap().expect("row survives reopen");
        assert_eq!(
            stored.command.action, action,
            "set_flag:seen:true must round-trip the real SqliteIntentLog"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bus_dead_letters_a_deterministic_provider_failure_for_set_flag() {
        let fake =
            FakeJmap::healthy().with(|s| s.inject = Some(JmapError::Set(SetError::Forbidden)));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let cmd = Command::new(
            "k-sf-det",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: true },
        );
        assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_))));
        assert_eq!(
            bus.log().get("k-sf-det").unwrap().unwrap().status,
            IntentStatus::Failed
        );
    }

    #[test]
    fn bus_dead_letters_a_transient_set_flag_failure_at_the_retry_cap() {
        // Mirrors the archive retry-cap test with the action swapped: a persistent TRANSIENT
        // failure stays Pending (retryable), then dead-letters once the budget is exhausted.
        let fake = FakeJmap::healthy()
            .with(|s| s.inject = Some(JmapError::Method(MethodError::ServerUnavailable)));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let cmd = Command::new(
            "k-sf-tr",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: true },
        );
        assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_))));
        assert_eq!(
            bus.log().get("k-sf-tr").unwrap().unwrap().status,
            IntentStatus::Pending,
            "one transient SetFlag failure is retryable, not dead-lettered"
        );
        for _ in 0..(RETRY_CAP - 1) {
            bus.recover().expect("recovery sweep runs");
        }
        assert_eq!(
            bus.log().get("k-sf-tr").unwrap().unwrap().status,
            IntentStatus::Failed,
            "a transient SetFlag failure retried past RETRY_CAP dead-letters to Failed"
        );
    }

    #[test]
    fn set_flag_flagged_applies_through_the_bus_and_lands_applied() {
        // End-to-end: SetFlag(Flagged) → Applied; the durable row round-trips the
        // set_flag:flagged:true token through the real SqliteIntentLog (mirrors the Seen
        // end-to-end test with the flag swapped; star/unstar design 2026-07-26 §5.2).
        use crate::SqliteIntentLog;
        let path = crate::test_temp::TempFile::sqlite("aruna-jmap-setflagged-bus");
        let fake = FakeJmap::healthy();
        let action = Action::SetFlag {
            message_ref: "msg-1".to_string(),
            flag: MailFlag::Flagged,
            value: true,
        };
        let cmd = Command::new("k-sfl", "photon-acct", crate::Facet::Mail, action.clone());
        {
            let mut bus = CommandBus::new(
                SqliteIntentLog::open(&path).expect("open"),
                JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
            );
            bus.execute(&cmd).expect("execute should succeed");
            assert_eq!(
                bus.log().get("k-sfl").unwrap().unwrap().status,
                IntentStatus::Applied
            );
            assert!(fake.keywords_of(SEED_EMAIL_ID).contains("$flagged"));
        } // drop → reopen: the durable token must round-trip through the real log
        let log = SqliteIntentLog::open(&path).expect("reopen");
        let stored = log.get("k-sfl").unwrap().expect("row survives reopen");
        assert_eq!(
            stored.command.action, action,
            "set_flag:flagged:true must round-trip the real SqliteIntentLog"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bus_dead_letters_a_deterministic_provider_failure_for_set_flag_flagged() {
        let fake =
            FakeJmap::healthy().with(|s| s.inject = Some(JmapError::Set(SetError::Forbidden)));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let cmd = Command::new(
            "k-sfl-det",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: true },
        );
        assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_))));
        assert_eq!(
            bus.log().get("k-sfl-det").unwrap().unwrap().status,
            IntentStatus::Failed
        );
    }

    #[test]
    fn bus_dead_letters_a_transient_set_flag_flagged_failure_at_the_retry_cap() {
        // Mirrors the Seen retry-cap test with the flag swapped: a persistent TRANSIENT failure
        // stays Pending (retryable), then dead-letters once the budget is exhausted.
        let fake = FakeJmap::healthy()
            .with(|s| s.inject = Some(JmapError::Method(MethodError::ServerUnavailable)));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let cmd = Command::new(
            "k-sfl-tr",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: true },
        );
        assert!(matches!(bus.execute(&cmd), Err(ExecuteError::Connector(_))));
        assert_eq!(
            bus.log().get("k-sfl-tr").unwrap().unwrap().status,
            IntentStatus::Pending,
            "one transient SetFlag(Flagged) failure is retryable, not dead-lettered"
        );
        for _ in 0..(RETRY_CAP - 1) {
            bus.recover().expect("recovery sweep runs");
        }
        assert_eq!(
            bus.log().get("k-sfl-tr").unwrap().unwrap().status,
            IntentStatus::Failed,
            "a transient SetFlag(Flagged) failure retried past RETRY_CAP dead-letters to Failed"
        );
    }

    #[test]
    fn capability_map_is_publicly_queryable_for_preflight() {
        // ADR-P010 "published capability map": an external caller can preflight without dispatching
        // (+: CapabilityMapPublicationGap).
        let fake = FakeJmap::healthy();
        let conn = JmapConnector::new(fake.clone(), fake.clone(), fake.clone());
        let caps = conn.capabilities();
        assert!(caps.archive());
        assert!(caps.unarchive());
        assert!(caps.supports(&Action::Archive {
            message_ref: "msg-1".to_string()
        }));
    }

    #[test]
    fn email_set_request_exposes_account_and_typed_updates_for_external_transports() {
        // An out-of-crate transport (aruna-jmap) must read the request the connector built —
        // through the ONE total dispatch, never a per-prefix filter.
        let req = EmailSetRequest::move_mailbox(
            &AccountId("acct-1".to_string()),
            &EmailId("eml-1".to_string()),
            &MailboxId("inbox-1".to_string()),
            &MailboxId("archive-1".to_string()),
        );
        assert_eq!(req.account_id(), "acct-1");
        let updates = req.typed_updates().expect("total dispatch");
        assert_eq!(updates.len(), 1);
        let (email_id, ops) = &updates[0];
        assert_eq!(*email_id, "eml-1");
        // archive-1 added (member: true), inbox-1 removed (member: false)
        assert!(ops.contains(&PatchOp::Mailbox { mailbox_id: "archive-1", member: true }));
        assert!(ops.contains(&PatchOp::Mailbox { mailbox_id: "inbox-1", member: false }));
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn jmap_move_undo_survives_the_forward_moves_own_state_advance() {
        // Regression test. On a CONFORMING JMAP provider the forward move ITSELF
        // re-dates the Mailbox namespace (source and destination counts both change), so by
        // the time the undo is driven the provider's cursor has legitimately advanced past
        // the one the PARENT froze at ITS admission. Observing with the PARENT's basis fed
        // that stale cursor into `reverify_role_basis`, whose cursor₁ ≠ frozen arm is a
        // DETERMINISTIC rebound — so EVERY legitimate live move-undo dead-lettered as a
        // rebind, and the fake masked it by never advancing `mailbox_state` on `Email/set`.
        //
        // BASIS-3 is the split that makes the fix sound: a cursor is FRESHNESS evidence, and
        // freshness legitimately moves; IDENTITY is the OPERANDS, and those are frozen at the
        // parent's admission and verified EQUAL at the child's (the drive's basis-match gate
        // now compares the whole operand map, not just the native key). So the observation
        // rides the CHILD's fresh cursor over identity the engine has proven unchanged.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let cursor_at_admission = fake.state.borrow().mailbox_state.clone();

        bus.execute(&archive("msg-1")).expect("the forward archive applies");

        assert!(fake.membership_ids(SEED_EMAIL_ID).contains(SEED_ARCHIVE_ID));
        assert!(!fake.membership_ids(SEED_EMAIL_ID).contains(SEED_INBOX_ID));
        assert_ne!(
            fake.state.borrow().mailbox_state,
            cursor_at_admission,
            "PRECONDITION: the move itself re-dated the Mailbox namespace (the live shape)"
        );

        bus.undo("k1")
            .expect("the undo requalifies against the CHILD's fresh cursor and restores");

        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Undone,
            "the parent flips at the restore VERIFICATION"
        );
        assert!(
            fake.membership_ids(SEED_EMAIL_ID).contains(SEED_INBOX_ID),
            "the CAPTURED pre-state is back in the inbox"
        );
        assert!(
            !fake.membership_ids(SEED_EMAIL_ID).contains(SEED_ARCHIVE_ID),
            "…and out of archive — the captured `false` written as remove-by-null"
        );
        assert_eq!(fake.sets().len(), 2, "exactly the forward move and the restore");
    }

    #[test]
    fn jmap_move_undo_refuses_when_the_childs_operands_are_not_the_parents() {
        // THE NEGATIVE ARM of the fix above: passing the CHILD's basis to `observe` is only
        // sound because the gate first proved the child resolved the SAME OBJECTS. A role
        // that re-resolved to a DIFFERENT mailbox id between the parent's admission and the
        // child's is a REAL rebound — the native resource key is unchanged (it names account
        // + email, not the roles), so the operand map is the only thing that can see it — and
        // it must still refuse DETERMINISTICALLY, before any wire call.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        bus.execute(&archive("msg-1")).expect("the forward archive applies");
        // "The archive role now names a different mailbox" — a genuine rebind.
        fake.state.borrow_mut().archive = Some(MailboxId("MBX-ARCHIVE-REBOUND-zz99".to_string()));

        let refused = bus.undo("k1");

        assert!(
            matches!(refused, Err(ExecuteError::Connector(_))),
            "a rebound operand refuses deterministically, got: {refused:?}"
        );
        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Applied,
            "…and the parent stays truthfully Applied: the undo did NOT happen"
        );
        assert_eq!(
            fake.sets().len(),
            1,
            "nothing reached the wire beyond the original forward move"
        );
    }

    #[test]
    fn jmap_undo_survives_a_cursor_advanced_by_a_third_party_between_admission_and_drive() {
        // Regression test (the SECOND appearance of the cursor-freshness class).
        // moved the undo's observation from the PARENT's cursor to the CHILD's; shows
        // the child's cursor goes stale the same way. Between the child's admission and its
        // drive the Mailbox namespace legitimately moves for reasons that have NOTHING to do
        // with our roles — a deferral behind a predecessor, ANOTHER CLIENT's change, a
        // lost-ack gap, a transient re-drive. Comparing that cursor by VALUE against the
        // frozen one then refused a LEGITIMATE undo as a deterministic rebound and
        // dead-lettered it.
        //
        // THE CLOSE (BASIS-3 vs BASIS-6, the design's own split): the roles are RE-RESOLVED
        // fresh at observe time and the freshly-resolved ids are compared to the frozen
        // OPERANDS. Ids equal ⇒ the binding holds, whatever the cursor did.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        bus.execute(&archive("msg-1")).expect("the forward archive applies");

        // The undo is ADMITTED — the child freezes the cursor as it stands NOW — but its
        // drive fails TRANSIENTLY at the provider read, so it stays Pending for recovery.
        fake.state.borrow_mut().inject = Some(JmapError::Method(MethodError::ServerUnavailable));
        assert!(
            bus.undo("k1").is_err(),
            "the first drive fails transiently, leaving the admitted child for recovery"
        );
        fake.state.borrow_mut().inject = None;
        let frozen_child_cursor = fake.state.borrow().mailbox_state.clone();

        // A THIRD PARTY re-dates the Mailbox namespace (a mailbox created/renamed elsewhere).
        // NO role rebinds: Inbox and Archive still name the very mailboxes admission froze.
        fake.state.borrow_mut().mailbox_state = Some("s-another-client-42".to_string());
        assert_ne!(
            fake.state.borrow().mailbox_state,
            frozen_child_cursor,
            "PRECONDITION: the child's frozen cursor is now stale"
        );
        assert_eq!(
            fake.state.borrow().inbox,
            Some(MailboxId(SEED_INBOX_ID.to_string())),
            "PRECONDITION: the Inbox role is UNCHANGED — identity held"
        );
        assert_eq!(
            fake.state.borrow().archive,
            Some(MailboxId(SEED_ARCHIVE_ID.to_string())),
            "PRECONDITION: the Archive role is UNCHANGED — identity held"
        );

        bus.recover().expect("the recovery sweep runs");

        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Undone,
            "a stale CURSOR is not a rebound: the undo requalifies and restores"
        );
        assert!(
            fake.membership_ids(SEED_EMAIL_ID).contains(SEED_INBOX_ID),
            "the CAPTURED pre-state is back in the inbox"
        );
        assert!(
            !fake.membership_ids(SEED_EMAIL_ID).contains(SEED_ARCHIVE_ID),
            "…and out of archive"
        );
    }

    #[test]
    fn jmap_deferred_forward_observes_under_an_advanced_cursor() {
        // The FORWARD half of the same exposure (sweep): a forward whose
        // dispatch is deferred — behind a held predecessor, or (here) by one transient
        // provider failure — observes at RECOVERY time under the cursor ADMISSION froze. Any
        // namespace movement in that window is legitimate, and the value-equality gate turned
        // it into a deterministic dead-letter for an action nothing had rebound.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        fake.state.borrow_mut().inject = Some(JmapError::Method(MethodError::ServerUnavailable));
        assert!(
            bus.execute(&archive("msg-1")).is_err(),
            "the first drive fails transiently at the observation — nothing is prepared yet"
        );
        fake.state.borrow_mut().inject = None;

        // Another client re-dates the namespace while our forward waits. Roles untouched.
        fake.state.borrow_mut().mailbox_state = Some("s-another-client-7".to_string());

        bus.recover().expect("the recovery sweep runs");

        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Applied,
            "the deferred forward observes and applies — a moved cursor is not a rebound"
        );
        assert!(
            fake.membership_ids(SEED_EMAIL_ID).contains(SEED_ARCHIVE_ID),
            "the archive actually happened"
        );
    }

    #[test]
    fn no_provider_ids_reach_the_intent_log_row() {
        // Confinement at the log boundary, not just the error path : even with the
        // provider holding distinctive account/mailbox/email ids, a successful archive stores only
        // the Photon-local command in the durable row — no provider-native handle leaks into the SoR.
        //
        // NARROWED by (design §7a + BASIS-4): `intents.frozen_basis` EXISTS to
        // carry provider-native identity — a captured operation that could not name the
        // native resource (and, for the move verbs, the resolved role-mailbox PAIR) it was
        // admitted against would be useless as pre-state. Confinement is therefore a property
        // of the NEUTRAL vocabulary (command, action, envelope, error text), not of that one
        // column. Both halves are asserted below.
        let fake = FakeJmap::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            JmapConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        bus.execute(&archive("msg-1")).expect("archive should succeed");

        let intent = bus.log().get("k1").unwrap().unwrap();
        let command_surface = format!("{:?}", intent.command);
        for seed in [SEED_ACCOUNT_ID, SEED_INBOX_ID, SEED_ARCHIVE_ID, SEED_EMAIL_ID] {
            assert!(
                !command_surface.contains(seed),
                "provider id {seed} leaked into the durable intent-log row: {command_surface}"
            );
        }
        let basis = intent
            .frozen_basis
            .expect("stage 2 freezes a basis at admission");
        assert_eq!(
            basis.native_resource_key,
            native_resource_key(JMAP_KEY_PROVIDER, &[SEED_ACCOUNT_ID, SEED_EMAIL_ID]),
            "the native identity lives in frozen_basis and nowhere else"
        );
    }
}
