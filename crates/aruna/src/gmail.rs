//! Gmail provider connector: archive/unarchive and the triage verbs over Gmail labels.
//!
//! The second real-provider terrain (after JMAP), proving ADR-P003 neutrality: the same
//! `Action::{Archive,Unarchive}` drives a different mechanic. Gmail has no Archive folder;
//! archiving is removing the `INBOX` system label via `users.messages.modify`. The connector
//! drives the eight verbs `CapabilityMap::triage_verbs` publishes over three routes:
//! `users.messages.modify` for every label verb (archive/unarchive on `INBOX`, seen on `UNREAD`,
//! flagged on `STARRED`, spam on `SPAM`), and the dedicated `users.messages.trash` /
//! `users.messages.untrash` for the trash pair. All Gmail-native ids stay below the seam. Tested
//! against an in-memory fake, so ADR-P010's "real destructive execution disabled until the
//! validation gate" holds; the live HTTP impl is the `aruna-gmail` crate. Design:
//! `docs/design/2026-06-27-m1-gmail-connector-design.md`.
//!
//! Scope: message-scoped `Connector::apply` neutrality. `Action::Archive { message_ref }`
//! removes `INBOX` from the resolved single message, not a thread/conversation archive
//! (`threads.modify` is a distinct surface). It does not claim full read-side neutrality.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::prestate::{native_resource_key, Freshness, FrozenBasis, Observation};
use crate::read_surface::{ContinuationToken, ListedPage, RawBody};
use crate::{
    action_message_ref, Action, Command, Connector, ConnectorError, EffectEvidence, EffectWitness,
    FailureKind,
    LogError, MailFlag, ResolveBasisError,
};

// Error taxonomy: the single home for the transient-vs-deterministic policy (Gmail API).

/// A normalized Gmail error: the connector's internal error vocabulary, decoupled from any
/// wire/library type so adopting a Gmail client does not ripple into the taxonomy (mirrors
/// `jmap::JmapError`). Every layer Gmail can fail at maps into one variant here, and
/// `classify_gmail_error` is the single home for the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmailError {
    /// HTTP 429 / 403 `rateLimitExceeded` / `userRateLimitExceeded` — back off and retry.
    RateLimit,
    /// HTTP 5xx / `backendError` — server-side, lifts on retry.
    Backend(u16),
    /// Transport/HTTP/TCP layer, below Gmail semantics, and proving nothing about the wire.
    ///
    /// The payload names what failed (a timeout, a reset), not when. A transport that times out
    /// waiting for a response body has already dispatched the request, and reaches this variant
    /// exactly as a connect-phase stall does. So this is the unproven class and maps to
    /// [`crate::EffectEvidence::Indeterminate`]; a stage split that can prove pre-dispatch says
    /// so through [`GmailError::TransportPreDispatch`].
    Transport(GmailTransportError),
    /// A transport failure the impl proved happened before any request byte was dispatched,
    /// carried as a type rather than inferred from a variant name.
    ///
    /// [`gmail_effect_evidence`] used to map every [`GmailError::Transport`] to `ProvenNoWire`.
    /// That held for the pinned HTTP transport (whose `send_stage_verdict` reaches `Transport`
    /// only from its measured `is_connect()` arm), but [`GmailTransport`] is a public seam and
    /// `GmailTransportError` variants are not contractually connect-stage-only. A foreign impl
    /// surfacing a post-body timeout under `Transport(Timeout)` would inherit a no-wire proof
    /// nobody held, authorizing a retry that can duplicate a mutation. Now only a code path that
    /// has established the pre-dispatch stage can name this variant, as with
    /// [`crate::jmap::TransportError::MutationRedirectRefused`]. This is not a control (a
    /// foreign impl can spell any variant); it makes claiming no-wire deliberate.
    ///
    /// Transient, like its unproven twin: the proof axis never moves the taxonomy.
    TransportPreDispatch(GmailTransportError),
    /// HTTP 403 `insufficientPermissions` / `forbidden` — will not self-heal.
    Forbidden,
    /// HTTP 404 `notFound` — the id is gone.
    NotFound,
    /// HTTP 400 `invalidArgument` / `failedPrecondition` — malformed; an identical retry fails again.
    InvalidArgument,
    /// HTTP 401 unauthorized. Deterministic for now (no refresh path); an OAuth refresh would
    /// reopen 401 as a "refresh-then-retry" third path the binary kind cannot express (as with
    /// JMAP's `Unauthorized`).
    Unauthorized,
    /// Any unrecognized condition — fail closed.
    Unknown,
    /// A local refusal the transport decided before a socket could exist: the default-closed
    /// ADR-P010 destructive-write gate, and an identifier the URL builder rejects.
    ///
    /// It is separate from `Unknown`, where `send_stage_verdict` files an unprovable
    /// post-dispatch stall and which the evidence map must keep `Indeterminate`. Sharing it meant
    /// a build shipping with the gate closed (the default) settled every mutation `ACK_AMBIGUOUS`
    /// and parked it for human adjudication, over a refusal that made no network call. The retry
    /// class is unchanged (deterministic: an identical retry meets the identical closed gate);
    /// the variant adds the second axis, [`crate::EffectEvidence::ProvenNoWire`].
    ///
    /// Carries no payload, like its siblings: a refused host or rejected identifier has nowhere
    /// to travel out of the transport crate (ADR-P003/P004).
    PreWireRefused,
}

/// Transport/HTTP/TCP failures, below Gmail semantics: the "what" axis only.
///
/// It carries no stage: "timed out" and "was reset" are true of a connect-phase failure and a
/// post-dispatch one alike. The stage, which §5.2b's evidence axis is about, is carried by which
/// [`GmailError`] variant wraps this one: [`GmailError::TransportPreDispatch`] when the impl
/// proved it, plain [`GmailError::Transport`] when it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmailTransportError {
    /// The request timed out.
    Timeout,
    /// The connection was reset/dropped.
    ConnectionReset,
}

/// Classify a normalized Gmail error into the engine's retry policy (`FailureKind`). The single
/// home for the transient-vs-deterministic taxonomy (mirrors `jmap::classify_jmap_error`).
/// Transient: rate-limit, 5xx/backend, timeouts/resets. Deterministic (fail-closed default):
/// forbidden, notFound, invalidArgument, 401, and any unknown condition.
///
/// A 403 is ambiguous: `rateLimitExceeded` (`RateLimit`, Transient) and `insufficientPermissions`
/// (`Forbidden`, Deterministic) share the status. The wire to `GmailError` normalization that
/// disambiguates them via the error-body `reason` lives in `aruna-gmail`; this taxonomy classifies
/// the already-normalized variant.
pub fn classify_gmail_error(error: &GmailError) -> FailureKind {
    use FailureKind::{Deterministic, Transient};
    match error {
        GmailError::RateLimit
        | GmailError::Backend(_)
        // Both transport variants share one row: the split is on the evidence axis only, and
        // whether another attempt is worthwhile does not depend on whether the stage was proven.
        | GmailError::Transport(_)
        | GmailError::TransportPreDispatch(_) => Transient,
        GmailError::Forbidden
        | GmailError::NotFound
        | GmailError::InvalidArgument
        | GmailError::Unauthorized
        // A closed gate stays closed and a rejected identifier stays rejected.
        | GmailError::PreWireRefused
        | GmailError::Unknown => Deterministic,
    }
}

// Below-seam provider ids (ADR-P003/P004), never surfaced above `Connector::apply`.

/// The Gmail `userId` (`"me"` or the address). Stays below the seam: `Command.account` is the
/// Photon-local handle, resolved privately via [`GmailAccountResolver`].
///
/// `me` is admissible on the wire but never in a frozen basis (see
/// `GmailUserId::is_credential_relative_alias`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailUserId(pub String);

impl GmailUserId {
    /// Is this user id the reserved, credential-relative alias (`me`)?
    ///
    /// Gmail's `users.*` endpoints accept `me` as "whoever this credential authenticates as": a
    /// pointer, not an identity. That is fine on the wire (the request carries the credential
    /// that resolves it) and fatal in a frozen basis: a key built from `me` re-reads as a
    /// different mailbox once the credential is rebound, while still comparing equal to what
    /// admission froze, defeating the BASIS-6 identity check.
    fn is_credential_relative_alias(&self) -> bool {
        self.0 == RESERVED_ME_ALIAS
    }
}

/// The reserved Gmail `userId` alias that names the credential rather than an account.
const RESERVED_ME_ALIAS: &str = "me";

/// A Gmail message id. Below the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailMessageId(pub String);

/// A Gmail label id. The only one this slice needs is the well-known system label `INBOX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelId(pub String);

impl LabelId {
    /// The Gmail system label `INBOX`: a fixed, locale-independent id (system-label ids are
    /// reserved; only display names localize). Archiving removes it; unarchiving adds it.
    pub fn inbox() -> Self {
        LabelId("INBOX".to_string())
    }

    /// The Gmail system label `UNREAD` (reserved, locale-independent). Gmail models read-state as
    /// the negative: Seen=true removes this label.
    pub fn unread() -> Self {
        LabelId("UNREAD".to_string())
    }

    /// The Gmail system label `STARRED` (reserved, locale-independent, manually applicable).
    /// Gmail models star-state as the positive: Flagged=true adds this label (direct polarity,
    /// unlike UNREAD).
    pub fn starred() -> Self {
        LabelId("STARRED".to_string())
    }

    /// The Gmail system label `TRASH` (reserved). Applied by `users.messages.trash`, removed by
    /// `untrash`; Gmail also strips `INBOX` on trash (a ripple the closure carries).
    pub fn trash() -> Self {
        LabelId("TRASH".to_string())
    }

    /// The Gmail system label `SPAM` (reserved). There is no dedicated route; MarkSpam/UnmarkSpam
    /// use `users.messages.modify` (ADR-P005).
    pub fn spam() -> Self {
        LabelId("SPAM".to_string())
    }
}

// Seams: resolvers (fake-seeded in tests) and the Gmail transport.

/// Resolves a Photon-local account string to the Gmail `userId`, below the seam.
pub trait GmailAccountResolver {
    fn resolve_user(&self, photon_account: &str) -> Option<GmailUserId>;
}

/// Resolves a Photon-local `message_ref` to the Gmail message id, below the seam. `Ok(None)` is a
/// genuine absent mapping (deterministic `MessageUnresolved`); `Err` is a store failure
/// (locked/corrupt DB), which the connector maps to a transient error so a retryable store
/// hiccup is never mis-classified as a permanent dead-letter (mirrors
/// `jmap::MessageRefResolver`).
pub trait GmailMessageRefResolver {
    fn resolve_message(
        &self,
        photon_account: &str,
        message_ref: &str,
    ) -> Result<Option<GmailMessageId>, LogError>;
}

/// A Gmail `messages.modify` request body, typed and serde-serializable so the modify shape can
/// be asserted against JSON. Mirrors `jmap::EmailSetRequest`. Both label arrays are always
/// present (an empty array is valid Gmail) for a stable shape. `batchModify` takes the same
/// arrays plus an `ids` array, so a batch impl can wrap this without a seam change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GmailModifyRequest {
    #[serde(rename = "addLabelIds")]
    add_label_ids: Vec<String>,
    #[serde(rename = "removeLabelIds")]
    remove_label_ids: Vec<String>,
}

impl GmailModifyRequest {
    /// Archive: remove `INBOX`, add nothing.
    fn remove_inbox() -> Self {
        Self {
            add_label_ids: Vec::new(),
            remove_label_ids: vec![LabelId::inbox().0],
        }
    }

    /// Unarchive: add `INBOX`, remove nothing.
    fn add_inbox() -> Self {
        Self {
            add_label_ids: vec![LabelId::inbox().0],
            remove_label_ids: Vec::new(),
        }
    }

    /// SetFlag(Seen): the polarity inversion lives here and only here (the engine never learns
    /// "UNREAD"). value=true (read) removes UNREAD; value=false (unread) adds UNREAD.
    fn set_seen(value: bool) -> Self {
        if value {
            Self {
                add_label_ids: Vec::new(),
                remove_label_ids: vec![LabelId::unread().0],
            }
        } else {
            Self {
                add_label_ids: vec![LabelId::unread().0],
                remove_label_ids: Vec::new(),
            }
        }
    }

    /// SetFlag(Flagged): direct polarity. Where `set_seen` inverts (Gmail stores the negative
    /// `UNREAD`), `STARRED` stores the positive: value=true (star) adds STARRED; value=false
    /// (unstar) removes it.
    fn set_starred(value: bool) -> Self {
        if value {
            Self {
                add_label_ids: vec![LabelId::starred().0],
                remove_label_ids: Vec::new(),
            }
        } else {
            Self {
                add_label_ids: Vec::new(),
                remove_label_ids: vec![LabelId::starred().0],
            }
        }
    }

    /// MarkSpam: add `SPAM`, remove nothing; Gmail strips `INBOX` itself.
    fn add_spam() -> Self {
        Self { add_label_ids: vec![LabelId::spam().0], remove_label_ids: Vec::new() }
    }

    /// UnmarkSpam: remove `SPAM`, add nothing.
    fn remove_spam() -> Self {
        Self { add_label_ids: Vec::new(), remove_label_ids: vec![LabelId::spam().0] }
    }

    /// The restore delta: the arrays come from the captured pre-state, so unlike the verb
    /// constructors above there is no fixed direction to encode. The caller routed each frozen
    /// atom to `add` or `remove` by its captured value.
    fn restore_delta(add_label_ids: Vec<String>, remove_label_ids: Vec<String>) -> Self {
        Self {
            add_label_ids,
            remove_label_ids,
        }
    }

    /// Test seam: an arbitrary add-list request for out-of-crate transport tests
    /// (`aruna-gmail`). Production code must not call it, and nothing enforces that: `aruna` has
    /// no test-seam feature to gate it behind, so it is a plain `#[doc(hidden)] pub fn`, hygiene
    /// only.
    #[doc(hidden)]
    pub fn for_test_add(add: &[&str]) -> Self {
        Self {
            add_label_ids: add.iter().map(|s| s.to_string()).collect(),
            remove_label_ids: Vec::new(),
        }
    }

    /// Test seam: an arbitrary remove-list request, the sibling of
    /// [`GmailModifyRequest::for_test_add`] (`aruna-gmail`'s ripple drill drives UnmarkSpam's
    /// `SPAM` removal with it). Same caveat: hygiene only, not a control.
    #[doc(hidden)]
    pub fn for_test_remove(remove: &[&str]) -> Self {
        Self {
            add_label_ids: Vec::new(),
            remove_label_ids: remove.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Label ids to add. Public so an out-of-crate transport (`aruna-gmail`) can read the request
    /// the connector built.
    pub fn add_label_ids(&self) -> &[String] {
        &self.add_label_ids
    }

    /// Label ids to remove (public; see [`GmailModifyRequest::add_label_ids`]).
    pub fn remove_label_ids(&self) -> &[String] {
        &self.remove_label_ids
    }
}

/// One Gmail method-call surface: the only thing a live network impl replaces (a
/// `reqwest`-backed impl drops in behind the validation gate). Single-message `modify` fits
/// because each `Action` carries one `message_ref`; the body is `batchModify`-compatible.
pub trait GmailTransport {
    /// Apply a label modification to one message (`users.messages.modify`). `Err` carries a
    /// normalized [`GmailError`].
    fn modify_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        request: &GmailModifyRequest,
    ) -> Result<(), GmailError>;

    /// `modify_labels`, but returning the response's observed label set (MarkSpam/UnmarkSpam use
    /// this, since Gmail has no dedicated spam route). On the live transport `modify_labels` is
    /// its thin wrapper: one route body, one applied-state check.
    ///
    /// Required, with no default body, like `trash_message`/`untrash_message` below and unlike the
    /// read methods, which default to refusing. Adding these write methods is a deliberate
    /// compile break for every implementor, out-of-crate ones included.
    fn modify_labels_observed(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        request: &GmailModifyRequest,
    ) -> Result<BTreeSet<String>, GmailError>;

    /// `users.messages.trash`, Gmail's dedicated trash route. Returns the response's observed
    /// label set: the postcondition source and the effect-evidence vector, from one read. A write:
    /// the live transport sends it through the destructive-write gate. Required (see
    /// [`GmailTransport::modify_labels_observed`]).
    fn trash_message(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError>;

    /// `users.messages.untrash`. Same contract as [`GmailTransport::trash_message`].
    fn untrash_message(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError>;

    /// Read one message's current label-id set via the minimal
    /// `users.messages.get?format=minimal&fields=id,labelIds` read. This is the Gmail half of
    /// [`Connector::observe`]: a read, never gated by the destructive-write gate, and the only
    /// provider input to a pre-state journal row.
    ///
    /// Defaults to refusing. A transport that has not wired the read answers `Unknown` (a
    /// deterministic refusal) rather than a fabricated empty label set: an observation that
    /// cannot be taken must never be reported as "no labels".
    fn message_labels(
        &self,
        _user: &GmailUserId,
        _message: &GmailMessageId,
    ) -> Result<BTreeSet<String>, GmailError> {
        Err(GmailError::Unknown)
    }

    /// List one page of Inbox header summaries, newest-first: `users.messages.list(labelIds=INBOX)`
    /// id-only, then a per-id metadata-scope `users.messages.get`. `Ok` carries the page and,
    /// when more rows remain, a [`ContinuationToken`] (the Gmail `nextPageToken`), plus
    /// [`ListedPage::raw_page_was_empty`], the one fact the mapped page cannot show (this route
    /// filters rows out, so an empty page and a filtered-to-zero page have the same shape).
    ///
    /// Defaults to refusing. [`GmailTransport`] is a `pub` trait, so a new method must be additive
    /// for every implementor including out-of-crate ones. A transport that has not wired listing
    /// answers `Unknown` rather than a fabricated empty inbox: an observation that cannot be
    /// taken must never be reported as "no mail".
    fn list_inbox_page(
        &self,
        _user: &GmailUserId,
        _page_size: i64,
        _continuation: Option<&ContinuationToken>,
    ) -> Result<ListedPage, GmailError> {
        Err(GmailError::Unknown)
    }

    /// Fetch one message's raw body (`users.messages.get?format=full`), the on-demand body read.
    /// Read-only: no destructive-write gate.
    ///
    /// Defaults to refusing, for the same reason as [`GmailTransport::list_inbox_page`]: a
    /// fabricated empty [`RawBody`] is indistinguishable from a genuinely empty message.
    fn fetch_body(
        &self,
        _user: &GmailUserId,
        _message: &GmailMessageId,
    ) -> Result<RawBody, GmailError> {
        Err(GmailError::Unknown)
    }
}

// Capability map (ADR-P010) and the structured, id-free error code.

/// The connector's published capability map (ADR-P010). Unsupported verbs fail safe and visibly.
/// Connector-local (not shared with JMAP): ADR-P010 makes capabilities per-provider and per-tier,
/// and Gmail's verb set will diverge.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityMap {
    archive: bool,
    unarchive: bool,
    set_flag_seen: bool,
    set_flag_flagged: bool,
    trash: bool,
    untrash: bool,
    mark_spam: bool,
    unmark_spam: bool,
}

impl CapabilityMap {
    /// The YELLOW verb set: archive/unarchive + SetFlag(Seen) + SetFlag(Flagged) (ADR-P010
    /// reversibility order). Everything else is unsupported, including the four triage verbs,
    /// which only [`CapabilityMap::triage_verbs`] publishes.
    pub fn m1_verbs() -> Self {
        Self {
            archive: true,
            unarchive: true,
            set_flag_seen: true,
            set_flag_flagged: true,
            trash: false,
            untrash: false,
            mark_spam: false,
            unmark_spam: false,
        }
    }

    /// The triage set: `m1_verbs`' YELLOW verbs plus Trash/Untrash/MarkSpam/UnmarkSpam. A
    /// connector built with this map dispatches the four verbs through `apply_witnessed`'s routes;
    /// `GmailConnector::new` still publishes `m1_verbs()`, which refuses them before the wire.
    pub fn triage_verbs() -> Self {
        Self {
            archive: true,
            unarchive: true,
            set_flag_seen: true,
            set_flag_flagged: true,
            trash: true,
            untrash: true,
            mark_spam: true,
            unmark_spam: true,
        }
    }

    /// Explicit per-verb (and per-flag) support (for tests / future verbs).
    #[allow(clippy::too_many_arguments)] // one bool per published row, by design (ADR-P010)
    pub fn custom(
        archive: bool,
        unarchive: bool,
        set_flag_seen: bool,
        set_flag_flagged: bool,
        trash: bool,
        untrash: bool,
        mark_spam: bool,
        unmark_spam: bool,
    ) -> Self {
        Self {
            archive,
            unarchive,
            set_flag_seen,
            set_flag_flagged,
            trash,
            untrash,
            mark_spam,
            unmark_spam,
        }
    }

    /// Whether `archive` is supported (published preflight surface, ADR-P010).
    pub fn archive(&self) -> bool {
        self.archive
    }

    /// Whether `unarchive` is supported (published preflight surface, ADR-P010).
    pub fn unarchive(&self) -> bool {
        self.unarchive
    }

    /// Whether a given action is supported: the preflight query a caller uses before dispatch
    /// instead of discovering an unsupported verb via a deterministic failure (ADR-P010).
    pub fn supports(&self, action: &Action) -> bool {
        match action {
            Action::Archive { .. } => self.archive,
            Action::Unarchive { .. } => self.unarchive,
            // Per flag, never a wildcard: a future MailFlag must add its own capability row here
            // or compilation fails (ADR-P010).
            Action::SetFlag { flag: MailFlag::Seen, .. } => self.set_flag_seen,
            Action::SetFlag { flag: MailFlag::Flagged, .. } => self.set_flag_flagged,
            // One row per verb, never a wildcard (ADR-P010).
            Action::Trash { .. } => self.trash,
            Action::Untrash { .. } => self.untrash,
            Action::MarkSpam { .. } => self.mark_spam,
            Action::UnmarkSpam { .. } => self.unmark_spam,
        }
    }
}

/// A structured, id-free connector error code. The `ConnectorError` surfaced above the seam is
/// built from this code's fixed phrase, never from a raw Gmail id, response body or error string
/// (ADR-P003/P004; mirrors `jmap::JmapErrorCode`). There is no `RoleMailboxAbsent` variant:
/// Gmail has no role mailbox, `INBOX` is a fixed label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmailErrorCode {
    UnsupportedCapability,
    AccountUnresolved,
    MessageUnresolved,
    ProviderRejected,
    /// The provider refused the credential (HTTP 401, [`GmailError::Unauthorized`]: an expired or
    /// revoked access token), not the request.
    CredentialRejected,
    /// Restore: the captured pre-state does not cover every frozen atom, so the delta cannot be
    /// built without inventing a value. Structured, because the atom name it would otherwise
    /// quote is a provider id on some connectors.
    PreStateIncomplete,
}

impl GmailErrorCode {
    /// A fixed, id-free message, free of provider-native handles.
    fn message(self) -> &'static str {
        match self {
            GmailErrorCode::UnsupportedCapability => "gmail: action not supported by this connector",
            GmailErrorCode::AccountUnresolved => "gmail: account could not be resolved",
            GmailErrorCode::MessageUnresolved => "gmail: message reference could not be resolved",
            GmailErrorCode::ProviderRejected => "gmail: provider rejected the mutation",
            GmailErrorCode::CredentialRejected => "gmail: provider rejected the credential",
            GmailErrorCode::PreStateIncomplete => {
                "gmail: captured pre-state does not cover the frozen atoms"
            }
        }
    }
}

/// Build a deterministic `ConnectorError` from a structured, id-free code. The capability refusal
/// carries its own axis (`ConnectorError::unsupported_capability`), so a caller names it by type,
/// never by matching this phrase.
fn deterministic(code: GmailErrorCode) -> ConnectorError {
    let error = ConnectorError::deterministic(code.message());
    match code {
        GmailErrorCode::UnsupportedCapability => error.unsupported_capability(),
        GmailErrorCode::AccountUnresolved
        | GmailErrorCode::MessageUnresolved
        | GmailErrorCode::ProviderRejected
        | GmailErrorCode::CredentialRejected
        | GmailErrorCode::PreStateIncomplete => error,
    }
}

/// The same code, tagged with the positive proof that no mutation was issued (the twin of
/// `jmap::refused_pre_wire`). The mutation paths (`apply` / `restore`) run after the
/// send-authorization boundary, so a refusal decided from local values (the capability map, the
/// resolvers, the captured pre-state's coverage) settles `ACK_AMBIGUOUS` unless it says what it
/// can prove. The constructor default stays fail-closed `Indeterminate`; each site is tagged.
fn refused_pre_wire(code: GmailErrorCode) -> ConnectorError {
    deterministic(code).proven_no_wire()
}

/// The message-ref store read failing on a mutation path: retryable (a store fault lifts) and
/// proven pre-wire, since the resolver runs before any request exists. One spelling, both paths.
fn store_read_failed_pre_wire() -> ConnectorError {
    ConnectorError::transient("gmail: message store read failed").proven_no_wire()
}

/// What a normalized `GmailError` positively proves about the request's effect: the second axis,
/// orthogonal to [`classify_gmail_error`]'s retry policy, from which the attempt grammar's ack
/// verdicts are decided.
///
/// The proof is carried by the type, not the variant's name. This arm used to map
/// `Transport(_)` to `ProvenNoWire`, justified by one implementation (on the mutation route
/// `aruna-gmail` produces `Transport` only from `send_stage_verdict`'s `is_connect()` arm). But
/// [`GmailTransport`] is a public trait and `GmailTransportError` a public enum whose variants
/// say what failed, never when: a foreign impl whose response-body read times out lands on
/// `Transport(Timeout)` and would inherit a no-wire proof it never made, which post-authorization
/// is a durable "no effect" record that authorizes a duplicate mutation. So the mapping keys on
/// [`GmailError::TransportPreDispatch`], a variant only a code path that has established the
/// stage can name, and the HTTP transport populates it from that same `is_connect()` arm. (The
/// read route keeps plain `Transport` for a post-header break; that mapping is inert, because
/// `observe` is only called before the send-authorization boundary, where the grammar derives
/// proven-no-wire from the absence of `SEND_AUTHORIZED`.)
///
/// The definitive-refusal arm is the 4xx status class (§5.2b's own example: "a 4xx validation
/// refusal"). 403/404/400/401 and 429 are answers whose HTTP semantics are "the request was not
/// fulfilled" (RFC 9110 §15.5; RFC 6585 §4 for 429). This proof is orthogonal to retryability: a
/// rate-limit refusal is `ACK_REFUSED_NO_EFFECT` and `Transient`, the retry-eligible pair.
///
/// `Backend`, `Unknown` and the unproven `Transport` prove nothing. §5.2b: "5xx per Gmail's own
/// retry guidance is NOT proof of no-effect", since the server may have applied before failing.
/// `Unknown` is the fail-closed bucket where `send_stage_verdict`'s unprovable post-dispatch
/// stall lands, so it must stay unproven. `PreWireRefused` is the strongest proof: it is
/// produced only where the transport refused before building a request or opening a socket (the
/// destructive-write gate and the identifier-validating URL builder), asserted by
/// `a_closed_gate_refuses_the_write_with_zero_wire_calls` and
/// `identifier_refusals_happen_with_zero_wire_calls`.
pub fn gmail_effect_evidence(error: &GmailError) -> EffectEvidence {
    match error {
        GmailError::TransportPreDispatch(_) | GmailError::PreWireRefused => {
            EffectEvidence::ProvenNoWire
        }
        GmailError::Forbidden
        | GmailError::NotFound
        | GmailError::InvalidArgument
        | GmailError::Unauthorized
        | GmailError::RateLimit => EffectEvidence::ProvenRefusedNoEffect,
        GmailError::Transport(_) | GmailError::Backend(_) | GmailError::Unknown => {
            EffectEvidence::Indeterminate
        }
    }
}

/// Map a provider `GmailError` to a `ConnectorError`: `kind` from the taxonomy, effect evidence
/// from [`gmail_effect_evidence`], message from a fixed id-free phrase (the Gmail error's own
/// text and ids are never surfaced).
///
/// [`GmailError::Unauthorized`] is the connector's auth family: the provider refused the
/// credential (HTTP 401, an expired or revoked access token), not the request. It is tagged
/// [`ConnectorError::credential_rejected`] and named by its own phrase
/// ([`GmailErrorCode::CredentialRejected`]); its retry kind and effect evidence are unchanged.
fn provider_rejection(error: &GmailError) -> ConnectorError {
    let credential = matches!(error, GmailError::Unauthorized);
    let message = if credential {
        GmailErrorCode::CredentialRejected.message()
    } else {
        GmailErrorCode::ProviderRejected.message()
    };
    let rejection = match classify_gmail_error(error) {
        FailureKind::Transient => ConnectorError::transient(message),
        FailureKind::Deterministic => ConnectorError::deterministic(message),
    };
    ConnectorError {
        effect_evidence: gmail_effect_evidence(error),
        credential_rejected: credential,
        ..rejection
    }
}

/// Why an admission-time basis freeze was refused: the resolver half of the confinement
/// discipline [`GmailErrorCode`] enforces on the apply half. The [`ResolveBasisError`] handed to
/// the admission path (and from there to `execute()`'s public error) is built from one of these
/// fixed phrases, so a below-seam failure's own text (SQL, an on-disk path, a provider id) has
/// nowhere to travel. Every variant is retryable: admission runs before `record()`, so a refusal
/// means nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GmailBasisRefusal {
    AccountUnresolved,
    /// The resolver answered with the credential-relative `me` alias, which is not an identity.
    CredentialRelativeAlias,
    /// The message-ref resolver failed (store fault). Its text stays below the seam.
    MessageRefResolverFailed,
    MessageRefUnresolved,
}

impl GmailBasisRefusal {
    /// A fixed, id-free message, free of provider-native handles and store text.
    fn message(self) -> &'static str {
        match self {
            GmailBasisRefusal::AccountUnresolved => {
                "gmail: account unresolved (retryable — seed the resolver)"
            }
            GmailBasisRefusal::CredentialRelativeAlias => {
                "gmail: a stable account identity is required before freezing a basis \
                 (retryable — re-seed the resolver)"
            }
            GmailBasisRefusal::MessageRefResolverFailed => {
                "gmail: message-ref resolver failure (retryable)"
            }
            GmailBasisRefusal::MessageRefUnresolved => {
                "gmail: message ref unresolved (retryable)"
            }
        }
    }
}

/// Build the admission refusal from a structured, id-free code. The only way this module
/// constructs a [`ResolveBasisError`], so a future refusal site cannot reopen the leak by
/// interpolating the error it caught.
fn refuse_basis(code: GmailBasisRefusal) -> ResolveBasisError {
    ResolveBasisError(code.message().to_string())
}

// The connector.

/// The provider tag this connector's native resource keys carry: the first component handed to
/// [`crate::prestate::native_resource_key`], the single encoding authority. A tag, not a prefix:
/// it is a component of the injective encoding, so it cannot be absorbed into a user id that
/// starts with the same characters.
pub const GMAIL_KEY_PROVIDER: &str = "gmail";

/// The Gmail `act`-verb connector: translates each published `Action` verb into its route (a
/// `messages.modify` label delta for archive/unarchive, seen, flagged and spam, or the dedicated
/// `messages.trash` / `messages.untrash`), classifying provider failures and confining provider
/// ids below the seam. The narrow `Connector::apply` actuator, not the full ADR-P003
/// `MailSurfaceAdapter`.
pub struct GmailConnector<T, A, M> {
    transport: T,
    accounts: A,
    messages: M,
    capabilities: CapabilityMap,
}

impl<T: GmailTransport, A: GmailAccountResolver, M: GmailMessageRefResolver> GmailConnector<T, A, M> {
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
}

impl<T, A, M> Connector for GmailConnector<T, A, M>
where
    T: GmailTransport,
    A: GmailAccountResolver,
    M: GmailMessageRefResolver,
{
    /// The one route body; `apply` below is its wrapper with the evidence dropped. Every route
    /// hands back the label set its transport method returned, so the evidence is `Some` on
    /// every success.
    ///
    /// BASIS-6 runs here, at the forward dispatch site, like [`Connector::restore`] below. Gmail
    /// resolves no roles (its atoms are reserved system labels, frozen `ImmutableConstants`), so
    /// the whole identity is the user + message pair the resolvers answer with, re-verified
    /// against the frozen key from the same two resolutions this dispatch already needed.
    fn apply_witnessed(
        &self,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<EffectWitness, ConnectorError> {
        // Every local refusal in this function is proven pre-wire (`refused_pre_wire`): `apply`
        // runs after the send-authorization boundary, and each refuses from local values before
        // the transport is called on any of the three routes. Only the provider's own answers
        // (`provider_rejection`) carry the transport's evidence instead.
        //
        // ADR-P010: fail safe and visibly on an unsupported verb (the connector's own capability
        // truth).
        if !self.capabilities.supports(&command.action) {
            return Err(refused_pre_wire(GmailErrorCode::UnsupportedCapability));
        }
        // Archive removes INBOX; Unarchive adds it. Unlike JMAP there is no from/to role
        // resolution: INBOX is a fixed system label, which is the neutrality divergence. This
        // toggles INBOX on the resolved single message, not a thread/conversation archive.
        //
        // The route each verb takes: the modify route, or one of the two dedicated trash routes.
        enum Route {
            Modify(GmailModifyRequest),
            Trash,
            Untrash,
        }
        let (message_ref, route) = match &command.action {
            Action::Archive { message_ref } => {
                (message_ref, Route::Modify(GmailModifyRequest::remove_inbox()))
            }
            Action::Unarchive { message_ref } => {
                (message_ref, Route::Modify(GmailModifyRequest::add_inbox()))
            }
            // SetFlag(Seen): the same modify seam, on UNREAD with inverted polarity (the
            // inversion lives in set_seen; the engine never learns "UNREAD"). Per flag, never a
            // wildcard arm.
            Action::SetFlag { message_ref, flag: MailFlag::Seen, value } => {
                (message_ref, Route::Modify(GmailModifyRequest::set_seen(*value)))
            }
            // SetFlag(Flagged): the same seam, on STARRED with direct polarity (the direction
            // lives in set_starred).
            Action::SetFlag { message_ref, flag: MailFlag::Flagged, value } => {
                (message_ref, Route::Modify(GmailModifyRequest::set_starred(*value)))
            }
            // The dedicated `users.messages.trash`/`untrash` routes; their returned `Message` is
            // the postcondition source.
            Action::Trash { message_ref } => (message_ref, Route::Trash),
            Action::Untrash { message_ref } => (message_ref, Route::Untrash),
            // Spam has no dedicated route: the SPAM label goes through the modify route.
            Action::MarkSpam { message_ref } => {
                (message_ref, Route::Modify(GmailModifyRequest::add_spam()))
            }
            Action::UnmarkSpam { message_ref } => {
                (message_ref, Route::Modify(GmailModifyRequest::remove_spam()))
            }
        };
        // Resolve provider-native handles below the seam (ADR-P003/P004).
        let user = self
            .accounts
            .resolve_user(&command.account)
            .ok_or_else(|| refused_pre_wire(GmailErrorCode::AccountUnresolved))?;
        let message = self
            .messages
            .resolve_message(&command.account, message_ref)
            // A store failure is transient (retryable), never a permanent dead-letter; only a
            // genuine absent mapping is the deterministic MessageUnresolved (as in jmap.rs).
            .map_err(|_| store_read_failed_pre_wire())?
            .ok_or_else(|| refused_pre_wire(GmailErrorCode::MessageUnresolved))?;
        // BASIS-6 at the wire: the binding must still be the frozen one. The key is recomputed
        // as `resolve_basis` and `observe` compute it, through the single encoding authority, so
        // the comparison cannot drift from what was frozen. A mismatch is deterministic and
        // proven no-wire: it is decided on a local comparison, before the route is handed to the
        // transport. `restore` makes the same check; the two dispatch sites hold one rule.
        if native_resource_key(GMAIL_KEY_PROVIDER, &[&user.0, &message.0])
            != basis.native_resource_key
        {
            return Err(ConnectorError::deterministic_basis_rebound());
        }
        // Dispatch the route; a provider rejection is classified by the taxonomy and surfaced
        // with an id-free message. The label set each route answers with is the effect evidence,
        // handed back verbatim.
        let vector = match route {
            Route::Trash => self.transport.trash_message(&user, &message),
            Route::Untrash => self.transport.untrash_message(&user, &message),
            Route::Modify(request) => {
                self.transport.modify_labels_observed(&user, &message, &request)
            }
        }
        .map_err(|e| provider_rejection(&e))?;
        Ok(EffectWitness {
            provider_label_vector: Some(vector),
        })
    }

    /// The plain dispatch: `apply_witnessed`'s route body with the evidence dropped, so the two
    /// cannot route differently.
    fn apply(&self, command: &Command, basis: &FrozenBasis) -> Result<(), ConnectorError> {
        self.apply_witnessed(command, basis).map(|_| ())
    }

    /// BASIS-2/-3/-4. Gmail's verbs touch only immutable system labels (`INBOX`, `UNREAD`,
    /// `STARRED`: reserved and locale-independent), so the freshness provenance is
    /// `ImmutableConstants`: there is no namespace cursor because there is nothing to cache. The
    /// native identity is the local durable resolver pair (user id + message id); this method
    /// does no provider I/O, because it runs inside the admission path.
    ///
    /// The identity half is refused rather than frozen when the resolver answers with the
    /// credential-relative `me` alias (see `is_credential_relative_alias`).
    fn resolve_basis(&self, command: &Command) -> Result<FrozenBasis, ResolveBasisError> {
        let user = self
            .accounts
            .resolve_user(&command.account)
            .ok_or_else(|| refuse_basis(GmailBasisRefusal::AccountUnresolved))?;
        // BASIS-4/-6: the frozen key must name an account, and `me` names a credential. Freezing
        // the alias would make a key whose account component is `me` survive a credential rebind
        // unchanged, and BASIS-6 would then re-verify against a mailbox the journal never
        // observed and pass. Refuse here, at the freeze, and let the resolver be re-seeded with
        // a stable identity (`users.getProfile` `emailAddress`); the wire is free to keep
        // sending `me`.
        if user.is_credential_relative_alias() {
            return Err(refuse_basis(GmailBasisRefusal::CredentialRelativeAlias));
        }
        let message = self
            .messages
            .resolve_message(&command.account, action_message_ref(&command.action))
            // The store error is dropped, not formatted: `LogError` carries unconstrained text
            // (SQL, paths, provider ids) and this refusal surfaces through `execute()`.
            .map_err(|_| refuse_basis(GmailBasisRefusal::MessageRefResolverFailed))?
            .ok_or_else(|| refuse_basis(GmailBasisRefusal::MessageRefUnresolved))?;
        // `A` = the forward target per atom, frozen at resolve time because re-deriving it at
        // undo time is the rebind BASIS-6 forbids. One authority: [`gmail_atom_targets`]
        // (polarity is absorbed there).
        let atom_targets = gmail_atom_targets(&command.action);
        Ok(FrozenBasis {
            native_resource_key: native_resource_key(GMAIL_KEY_PROVIDER, &[&user.0, &message.0]),
            touched_atoms: touched_atoms(&command.action),
            atom_targets,
            // Gmail's atoms are provider constants (system labels): no role is resolved, so the
            // role to id mapping is empty.
            role_bindings: std::collections::BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        })
    }

    /// The provider read behind "observe": one minimal `messages.get` label-set fetch, projected
    /// onto exactly the frozen atoms. The returned key is the identity the provider answered for
    /// (re-resolved here, provider-scoped like `resolve_basis`), which BASIS-6 verifies the
    /// frozen basis against; engine state is never consulted.
    fn observe(
        &self,
        command: &Command,
        basis: &FrozenBasis,
    ) -> Result<Observation, ConnectorError> {
        let user = self
            .accounts
            .resolve_user(&command.account)
            .ok_or_else(|| deterministic(GmailErrorCode::AccountUnresolved))?;
        let message = self
            .messages
            .resolve_message(&command.account, action_message_ref(&command.action))
            .map_err(|_| ConnectorError::transient("gmail: message store read failed"))?
            .ok_or_else(|| deterministic(GmailErrorCode::MessageUnresolved))?;
        let labels = self
            .transport
            .message_labels(&user, &message)
            .map_err(|e| provider_rejection(&e))?;
        Ok(Observation {
            native_resource_key: native_resource_key(GMAIL_KEY_PROVIDER, &[&user.0, &message.0]),
            // The atom's value is the resolved native operand (the label id it rides on), so
            // presence of that label is the atom's current value, for `label:UNREAD` too, where
            // the neutral flag's polarity is inverted (the atom is the label, not "seen").
            atoms: basis
                .touched_atoms
                .iter()
                .map(|(atom, label)| (atom.clone(), labels.contains(label)))
                .collect(),
            request_id: None,
            // The whole set this read returned: the pre-effect vector, beside the projection.
            provider_label_vector: Some(labels),
        })
    }

    /// Restore: one `users.messages.modify` whose label arrays are built from the captured
    /// pre-state `p` over the frozen operands, using the same modify seam `apply` uses and
    /// routed by resolvers as `apply` routes.
    ///
    /// The verb is not consulted. A direction-derived inverse would add `INBOX` on every undo of
    /// an Archive, including for a message that was never in the inbox: a state change the
    /// action itself never made.
    ///
    /// BASIS-6 runs here, at the dispatch site. Because the resolvers are consulted again to
    /// route the write, the identity they answer with must be re-verified against the frozen one
    /// before anything reaches the wire; a rebind between the observation and this moment would
    /// otherwise land the captured pre-state on a different provider object. The forward `apply`
    /// dispatch site carries the same check.
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
        // Every local refusal below is proven pre-wire (`refused_pre_wire`): `restore` runs after
        // the undo drive's own send-authorization boundary, so an untagged local refusal would
        // park a human on `ACK_AMBIGUOUS` for nothing.
        if !self.capabilities.supports(&command.action.inverse()) {
            return Err(refused_pre_wire(GmailErrorCode::UnsupportedCapability));
        }
        // Delta grain: exactly the frozen atoms, each routed by its captured value. An atom the
        // capture does not cover refuses deterministically; a guessed value would be the blind
        // inverse under another name.
        let mut add: Vec<String> = Vec::new();
        let mut remove: Vec<String> = Vec::new();
        for (atom, operand) in &basis.touched_atoms {
            match p.get(atom) {
                Some(true) => add.push(operand.clone()),
                Some(false) => remove.push(operand.clone()),
                None => return Err(refused_pre_wire(GmailErrorCode::PreStateIncomplete)),
            }
        }
        let user = self
            .accounts
            .resolve_user(&command.account)
            .ok_or_else(|| refused_pre_wire(GmailErrorCode::AccountUnresolved))?;
        let message = self
            .messages
            .resolve_message(&command.account, action_message_ref(&command.action))
            // A store failure is transient; only a genuine absent mapping is deterministic (the
            // same split `apply` makes).
            .map_err(|_| store_read_failed_pre_wire())?
            .ok_or_else(|| refused_pre_wire(GmailErrorCode::MessageUnresolved))?;
        // BASIS-6: the binding must still be the frozen one. The key is recomputed as
        // `resolve_basis` and `observe` compute it, through the single encoding authority, and a
        // mismatch is deterministic: a frozen basis is immutable, so an identical retry can only
        // re-ask the same wrong question. The refusal phrase is the engine's shared, id-free one.
        if native_resource_key(GMAIL_KEY_PROVIDER, &[&user.0, &message.0])
            != basis.native_resource_key
        {
            return Err(ConnectorError::deterministic_basis_rebound());
        }
        self.transport
            .modify_labels(&user, &message, &GmailModifyRequest::restore_delta(add, remove))
            .map_err(|e| provider_rejection(&e))
    }
}

/// `A`, the forward target per atom: the value each touched atom holds after this action
/// applies. Polarity is absorbed here, where the atom's meaning is known: `Seen` is stored
/// negative (the atom is the UNREAD label), so `Seen=true` targets `label:UNREAD=false`, while
/// `Flagged` uses STARRED directly. Per verb, never a wildcard arm. Keys match `touched_atoms`
/// in both directions (`FrozenBasis::validate`).
///
/// The rippled-atom closure lives here: Trash/MarkSpam declare `membership:INBOX -> false`
/// because Gmail strips INBOX as a side effect, and the restore arms declare it too (untrash and
/// not-spam return the message to All Mail, not to the inbox). The INBOX half is a declared
/// hypothesis, undetermined until the live ripple drill runs. The drill asserts that the
/// observed change stays inside {TRASH|SPAM, INBOX} and that the route's INBOX membership equals
/// the declared target; neither has been observed live yet.
pub(crate) fn gmail_atom_targets(action: &Action) -> std::collections::BTreeMap<String, bool> {
    match action {
        Action::Archive { .. } => [("membership:INBOX".to_string(), false)].into_iter().collect(),
        Action::Unarchive { .. } => [("membership:INBOX".to_string(), true)].into_iter().collect(),
        Action::SetFlag { flag: MailFlag::Seen, value, .. } => {
            [("label:UNREAD".to_string(), !*value)].into_iter().collect()
        }
        Action::SetFlag { flag: MailFlag::Flagged, value, .. } => {
            [("label:STARRED".to_string(), *value)].into_iter().collect()
        }
        Action::Trash { .. } => [
            ("label:TRASH".to_string(), true),
            ("membership:INBOX".to_string(), false),
        ]
        .into_iter()
        .collect(),
        Action::Untrash { .. } => [
            ("label:TRASH".to_string(), false),
            ("membership:INBOX".to_string(), false),
        ]
        .into_iter()
        .collect(),
        Action::MarkSpam { .. } => [
            ("label:SPAM".to_string(), true),
            ("membership:INBOX".to_string(), false),
        ]
        .into_iter()
        .collect(),
        Action::UnmarkSpam { .. } => [
            ("label:SPAM".to_string(), false),
            ("membership:INBOX".to_string(), false),
        ]
        .into_iter()
        .collect(),
    }
}

/// The primitive atoms a Gmail verb touches, mapped to the resolved native operand each uses.
/// Gmail has no role mailboxes: every operand is a reserved system label, so this is a pure
/// function of the verb. Per flag, never a wildcard arm: a future `MailFlag` must name its own
/// label or compilation fails.
fn touched_atoms(action: &Action) -> std::collections::BTreeMap<String, String> {
    let atoms: Vec<(String, String)> = match action {
        Action::Archive { .. } | Action::Unarchive { .. } => {
            vec![("membership:INBOX".to_string(), LabelId::inbox().0)]
        }
        Action::SetFlag { flag: MailFlag::Seen, .. } => {
            vec![("label:UNREAD".to_string(), LabelId::unread().0)]
        }
        Action::SetFlag { flag: MailFlag::Flagged, .. } => {
            vec![("label:STARRED".to_string(), LabelId::starred().0)]
        }
        // The rippled-atom closure: the label the verb sends plus the INBOX membership Gmail
        // mutates as a side effect (see `gmail_atom_targets`).
        Action::Trash { .. } | Action::Untrash { .. } => vec![
            ("label:TRASH".to_string(), LabelId::trash().0),
            ("membership:INBOX".to_string(), LabelId::inbox().0),
        ],
        Action::MarkSpam { .. } | Action::UnmarkSpam { .. } => vec![
            ("label:SPAM".to_string(), LabelId::spam().0),
            ("membership:INBOX".to_string(), LabelId::inbox().0),
        ],
    };
    atoms.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandBus, ExecuteError, InMemoryIntentLog, IntentLog, IntentStatus, RETRY_CAP};
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::rc::Rc;

    // ---- taxonomy ----

    #[test]
    fn rate_limit_is_transient() {
        assert_eq!(classify_gmail_error(&GmailError::RateLimit), FailureKind::Transient);
    }

    #[test]
    fn backend_5xx_is_transient() {
        assert_eq!(classify_gmail_error(&GmailError::Backend(503)), FailureKind::Transient);
    }

    #[test]
    fn transport_timeout_and_reset_are_transient() {
        // BOTH spellings — proven-pre-dispatch and unproven. The evidence
        // split must not move the retry taxonomy: the two axes are independent.
        for error in [
            GmailError::Transport(GmailTransportError::Timeout),
            GmailError::Transport(GmailTransportError::ConnectionReset),
            GmailError::TransportPreDispatch(GmailTransportError::Timeout),
            GmailError::TransportPreDispatch(GmailTransportError::ConnectionReset),
        ] {
            assert_eq!(classify_gmail_error(&error), FailureKind::Transient);
        }
    }

    #[test]
    fn forbidden_not_found_invalid_arg_are_deterministic() {
        assert_eq!(classify_gmail_error(&GmailError::Forbidden), FailureKind::Deterministic);
        assert_eq!(classify_gmail_error(&GmailError::NotFound), FailureKind::Deterministic);
        assert_eq!(classify_gmail_error(&GmailError::InvalidArgument), FailureKind::Deterministic);
    }

    #[test]
    fn unauthorized_is_deterministic_in_m0() {
        assert_eq!(classify_gmail_error(&GmailError::Unauthorized), FailureKind::Deterministic);
    }

    #[test]
    fn unknown_fails_closed_deterministic() {
        assert_eq!(classify_gmail_error(&GmailError::Unknown), FailureKind::Deterministic);
    }

    // §5.2b: the SECOND axis — what the failure PROVES about the effect ----

    #[test]
    fn the_connect_stage_proof_is_surfaced_as_proven_no_wire() {
        // The mapping the design asks for: `aruna-gmail`'s existing proven-pre-dispatch class
        // (`send_stage_verdict`'s `is_connect()` arm) becomes the attempt grammar's
        // `ProvenNoWire` — which is what keeps a safely-retryable outage out of ISSUANCE_UNKNOWN.
        //
        // It is keyed on the TYPED variant now, not on "the mutation route
        // only ever produces `Transport` here" — a property of one impl behind a public trait.
        for error in [
            GmailError::TransportPreDispatch(GmailTransportError::Timeout),
            GmailError::TransportPreDispatch(GmailTransportError::ConnectionReset),
        ] {
            assert_eq!(gmail_effect_evidence(&error), EffectEvidence::ProvenNoWire);
            assert_eq!(
                provider_rejection(&error).effect_evidence,
                EffectEvidence::ProvenNoWire,
                "…and it rides the ConnectorError the engine actually settles on"
            );
        }
    }

    /// 401 (`Unauthorized`) — and only 401 — is the connector's AUTH
    /// family: tagged `credential_rejected`, named by its own phrase; its retry kind and effect
    /// evidence are unchanged. Every other answer keeps the untagged `ProviderRejected` phrase.
    #[test]
    fn the_auth_family_alone_is_tagged_credential_rejected_and_named() {
        let auth = provider_rejection(&GmailError::Unauthorized);
        assert!(auth.credential_rejected);
        assert_eq!(auth.message, "gmail: provider rejected the credential");
        assert_eq!(auth.kind, FailureKind::Deterministic);
        assert_eq!(auth.effect_evidence, EffectEvidence::ProvenRefusedNoEffect);
        for error in [
            GmailError::Forbidden,
            GmailError::NotFound,
            GmailError::InvalidArgument,
            GmailError::RateLimit,
            GmailError::Unknown,
            GmailError::PreWireRefused,
            GmailError::Backend(503),
            GmailError::Transport(GmailTransportError::Timeout),
            GmailError::TransportPreDispatch(GmailTransportError::ConnectionReset),
        ] {
            let rejection = provider_rejection(&error);
            assert!(!rejection.credential_rejected, "{error:?}");
            assert_eq!(rejection.message, "gmail: provider rejected the mutation", "{error:?}");
        }
    }

    #[test]
    fn an_answered_refusal_is_proven_refused_and_an_unproven_one_is_not() {
        // POSITIVE PROOF, NOT FAILURE NAME (§5.2b). A status family that carries a DECISION
        // proves rejection before effect; the fail-closed buckets prove nothing — and `Unknown`
        // is exactly where the transport's unprovable post-dispatch stall lands, so deriving a
        // refusal from `FailureKind::Deterministic` alone would record "no effect" for an
        // outcome the connector never claimed.
        for error in [
            GmailError::Forbidden,
            GmailError::NotFound,
            GmailError::InvalidArgument,
            GmailError::Unauthorized,
            // A 4xx too — and the pair that proves the two axes are orthogonal: PROVEN refused
            // (a terminal attribution) and still TRANSIENT (retry-eligible).
            GmailError::RateLimit,
        ] {
            assert_eq!(
                gmail_effect_evidence(&error),
                EffectEvidence::ProvenRefusedNoEffect
            );
        }
        for error in [
            GmailError::Unknown,
            // "5xx per Gmail's own retry guidance is NOT proof of no-effect" (§5.2b, verbatim).
            GmailError::Backend(503),
            // …and the UNPROVEN transport class joins them: "timed out" and
            // "was reset" describe WHAT failed, never WHEN, so on their own they prove nothing.
            GmailError::Transport(GmailTransportError::Timeout),
            GmailError::Transport(GmailTransportError::ConnectionReset),
        ] {
            assert_eq!(gmail_effect_evidence(&error), EffectEvidence::Indeterminate);
        }
        assert_eq!(
            classify_gmail_error(&GmailError::RateLimit),
            FailureKind::Transient,
            "the retry taxonomy is untouched by the evidence axis"
        );
    }

    #[test]
    fn proven_no_wire_projects_into_the_grammars_two_valued_wire_evidence() {
        // The projection the `FAILED_PRE_SEND` payload records: only a no-WIRE proof projects.
        // A proven REFUSAL is proof about the provider's decision, not about the wire, and
        // takes the `ACK_REFUSED_NO_EFFECT` road instead.
        use crate::attempt::WireEvidence;
        assert_eq!(
            EffectEvidence::ProvenNoWire.wire_evidence(),
            WireEvidence::ProvenNoWire
        );
        assert_eq!(
            EffectEvidence::ProvenRefusedNoEffect.wire_evidence(),
            WireEvidence::Indeterminate
        );
        assert_eq!(
            EffectEvidence::Indeterminate.wire_evidence(),
            WireEvidence::Indeterminate
        );
        assert_eq!(
            EffectEvidence::default(),
            EffectEvidence::Indeterminate,
            "absence of proof is never proof"
        );
    }

    // ---- modify request shape (mirrors the JMAP */set subset test) ----

    #[test]
    fn modify_request_is_a_valid_modify_subset() {
        let archive = GmailModifyRequest::remove_inbox();
        let json = serde_json::to_value(&archive).expect("serialize");
        assert_eq!(json["removeLabelIds"], serde_json::json!(["INBOX"]));
        assert_eq!(json["addLabelIds"], serde_json::json!([]));

        let unarchive = GmailModifyRequest::add_inbox();
        let json = serde_json::to_value(&unarchive).expect("serialize");
        assert_eq!(json["addLabelIds"], serde_json::json!(["INBOX"]));
        assert_eq!(json["removeLabelIds"], serde_json::json!([]));
    }

    // ---- the Gmail-shaped fake (one backend implementing all three seams) ----

    // Distinctive seeded ids — used by the confinement tests to prove none leak above the seam.
    const SEED_USER_ID: &str = "GMAILUSER-PROVIDER-7f3a";
    const SEED_MESSAGE_ID: &str = "GMSG-PROVIDER-cc33";
    const INBOX: &str = "INBOX";

    struct FakeState {
        user_id: Option<GmailUserId>,
        // message_ref -> provider message id
        messages: BTreeMap<String, GmailMessageId>,
        // provider message id -> current label set
        labels: BTreeMap<String, BTreeSet<String>>,
        // when set, modify_labels returns this error instead of applying
        inject: Option<GmailError>,
        /// Every modify BODY the connector handed the transport, in order — the wire shape,
        /// recorded before it is applied so a refused shape is still visible.
        modifies: Vec<GmailModifyRequest>,
        /// When set, the message-ref RESOLVER fails with this store error instead of answering.
        /// Its text is BELOW the seam (SQL, paths, provider ids) and must never surface.
        resolver_fault: Option<LogError>,
        /// when set, the three OBSERVED write routes (`modify_labels_observed`,
        /// `trash_message`, `untrash_message`) answer with THIS set instead of the modelled one —
        /// the model is still mutated, only the ANSWER is scripted. `None` = B3's behaviour.
        answer: Option<BTreeSet<String>>,
        /// how many times each dedicated trash route was called.
        trash_calls: usize,
        untrash_calls: usize,
    }

    #[derive(Clone)]
    struct FakeGmail {
        state: Rc<RefCell<FakeState>>,
    }

    impl FakeGmail {
        /// A healthy user with one message seeded in the inbox (carrying the `INBOX` label).
        fn healthy() -> Self {
            let mut labels = BTreeMap::new();
            let mut start = BTreeSet::new();
            start.insert(INBOX.to_string());
            labels.insert(SEED_MESSAGE_ID.to_string(), start);
            let mut messages = BTreeMap::new();
            messages.insert("msg-1".to_string(), GmailMessageId(SEED_MESSAGE_ID.to_string()));
            Self {
                state: Rc::new(RefCell::new(FakeState {
                    user_id: Some(GmailUserId(SEED_USER_ID.to_string())),
                    messages,
                    labels,
                    inject: None,
                    modifies: Vec::new(),
                    resolver_fault: None,
                    answer: None,
                    trash_calls: 0,
                    untrash_calls: 0,
                })),
            }
        }

        /// [`FakeGmail::healthy`], with `labels` QUEUED as the answer every observed
        /// write route returns (see `FakeState::answer`).
        fn new_with_labels(labels: Vec<String>) -> Self {
            Self::healthy().with(|s| s.answer = Some(labels.into_iter().collect()))
        }

        /// Calls to the dedicated `trash_message` route.
        fn trash_calls(&self) -> usize {
            self.state.borrow().trash_calls
        }

        /// Calls to the dedicated `untrash_message` route.
        fn untrash_calls(&self) -> usize {
            self.state.borrow().untrash_calls
        }

        /// Modify bodies handed to the transport (`modify_labels` + `modify_labels_observed`).
        fn modify_calls(&self) -> usize {
            self.state.borrow().modifies.len()
        }

        /// The last modify body handed to the transport, if any.
        fn last_modify_request(&self) -> Option<GmailModifyRequest> {
            self.state.borrow().modifies.last().cloned()
        }

        fn with<F: FnOnce(&mut FakeState)>(self, f: F) -> Self {
            f(&mut self.state.borrow_mut());
            self
        }

        fn labels_of(&self, message: &str) -> BTreeSet<String> {
            self.state
                .borrow()
                .labels
                .get(message)
                .cloned()
                .unwrap_or_default()
        }

        /// The modify bodies this transport was handed, in dispatch order.
        fn modifies(&self) -> Vec<GmailModifyRequest> {
            self.state.borrow().modifies.clone()
        }

        fn add_label(&self, message: &str, label: &str) {
            self.state
                .borrow_mut()
                .labels
                .entry(message.to_string())
                .or_default()
                .insert(label.to_string());
        }
    }

    impl GmailAccountResolver for FakeGmail {
        fn resolve_user(&self, _photon_account: &str) -> Option<GmailUserId> {
            self.state.borrow().user_id.clone()
        }
    }

    impl GmailMessageRefResolver for FakeGmail {
        fn resolve_message(
            &self,
            _photon_account: &str,
            message_ref: &str,
        ) -> Result<Option<GmailMessageId>, LogError> {
            let s = self.state.borrow();
            if let Some(fault) = s.resolver_fault.clone() {
                return Err(fault);
            }
            Ok(s.messages.get(message_ref).cloned())
        }
    }

    impl GmailTransport for FakeGmail {
        fn modify_labels(
            &self,
            _user: &GmailUserId,
            message: &GmailMessageId,
            request: &GmailModifyRequest,
        ) -> Result<(), GmailError> {
            let mut s = self.state.borrow_mut();
            s.modifies.push(request.clone());
            if let Some(err) = s.inject.clone() {
                return Err(err);
            }
            // Gmail modify is set-style idempotent: adding a present label / removing an absent label
            // is a no-op. A set naturally models that (design §3.4).
            let set = s.labels.entry(message.0.clone()).or_default();
            for add in request.add_label_ids() {
                set.insert(add.clone());
            }
            for remove in request.remove_label_ids() {
                set.remove(remove.as_str());
            }
            Ok(())
        }

        /// The fake answers the observation read from the SAME per-message label set the
        /// modify path mutates — so an observe taken before a dispatch reports pre-state and
        /// one taken after reports post-state (what §2.2's "never re-capture" rule turns on).
        fn message_labels(
            &self,
            _user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, GmailError> {
            let s = self.state.borrow();
            if let Some(err) = s.inject.clone() {
                return Err(err);
            }
            Ok(s.labels.get(&message.0).cloned().unwrap_or_default())
        }

        /// the modify, answering with the fake's post-modify label set for that message
        /// (the fake CARRIES a label set, so it reports it rather than an empty one).
        fn modify_labels_observed(
            &self,
            user: &GmailUserId,
            message: &GmailMessageId,
            request: &GmailModifyRequest,
        ) -> Result<BTreeSet<String>, GmailError> {
            self.modify_labels(user, message, request)?;
            let answer = self.state.borrow().answer.clone();
            Ok(answer.unwrap_or_else(|| self.labels_of(&message.0)))
        }

        /// the fake models ONLY the `TRASH` label the route is named for. What else Gmail
        /// changes on trash (the ripple) is never invented here — a fake that produced the
        /// declared ripple would make any ripple check against it tautological.
        fn trash_message(
            &self,
            _user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, GmailError> {
            let mut s = self.state.borrow_mut();
            s.trash_calls += 1;
            if let Some(err) = s.inject.clone() {
                return Err(err);
            }
            let set = s.labels.entry(message.0.clone()).or_default();
            set.insert(LabelId::trash().0);
            let modelled = set.clone();
            Ok(s.answer.clone().unwrap_or(modelled))
        }

        /// the inverse of [`FakeGmail::trash_message`] — removes `TRASH` only.
        fn untrash_message(
            &self,
            _user: &GmailUserId,
            message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, GmailError> {
            let mut s = self.state.borrow_mut();
            s.untrash_calls += 1;
            if let Some(err) = s.inject.clone() {
                return Err(err);
            }
            let set = s.labels.entry(message.0.clone()).or_default();
            set.remove(LabelId::trash().0.as_str());
            let modelled = set.clone();
            Ok(s.answer.clone().unwrap_or(modelled))
        }
    }

    // `list_inbox_page`/`fetch_body` DEFAULT = REFUSE ----

    /// A transport implementing ONLY the trait's REQUIRED methods — `modify_labels`, plus the
    /// three write methods that are required ON PURPOSE (see
    /// [`GmailTransport::modify_labels_observed`]) — proving, AS A COMPILE FACT, the additive
    /// guarantee the design's TRAIT-DEFAULTS fold promises for the READ methods: adding
    /// `list_inbox_page`/`fetch_body` (and, earlier, `message_labels`) never forces an edit here.
    /// If either of those lost its default body this struct would stop compiling, which is the
    /// whole test.
    struct MinimalGmailTransport;

    impl GmailTransport for MinimalGmailTransport {
        fn modify_labels(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
            _request: &GmailModifyRequest,
        ) -> Result<(), GmailError> {
            Ok(())
        }

        /// Carries no label set, so it reports none. Through a connector this yields a witness of
        /// `Some(∅)` — the honest "the route answered no labels", never "no witness". The only
        /// tests using this fake (`an_unwired_transport_refuses_list_inbox_page_loudly`,
        /// `an_unwired_transport_refuses_fetch_body_loudly`) call the transport directly, never
        /// through a connector, and none of them asserts a vector.
        fn modify_labels_observed(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
            _request: &GmailModifyRequest,
        ) -> Result<BTreeSet<String>, GmailError> {
            Ok(BTreeSet::new())
        }

        /// Refuses: an `Ok(∅)` here would claim `TRASH` absent right after a trash.
        fn trash_message(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, GmailError> {
            Err(GmailError::Unknown)
        }

        /// Refuses, for symmetry with `trash_message` — this fake models no mailbox.
        fn untrash_message(
            &self,
            _user: &GmailUserId,
            _message: &GmailMessageId,
        ) -> Result<BTreeSet<String>, GmailError> {
            Err(GmailError::Unknown)
        }
    }

    #[test]
    fn an_unwired_transport_refuses_list_inbox_page_loudly() {
        let transport = MinimalGmailTransport;
        let error = transport
            .list_inbox_page(&GmailUserId(SEED_USER_ID.to_string()), 50, None)
            .expect_err("DEFAULT = REFUSE: an unwired transport must not fabricate an empty inbox");
        assert_eq!(error, GmailError::Unknown);
    }

    #[test]
    fn an_unwired_transport_refuses_fetch_body_loudly() {
        let transport = MinimalGmailTransport;
        let error = transport
            .fetch_body(
                &GmailUserId(SEED_USER_ID.to_string()),
                &GmailMessageId(SEED_MESSAGE_ID.to_string()),
            )
            .expect_err("DEFAULT = REFUSE: an unwired transport must not fabricate an empty body");
        assert_eq!(error, GmailError::Unknown);
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
    /// hand THAT basis to the wire — `apply` consumes it and never re-resolves (BASIS-6). The
    /// bus's own two-step, so a connector test exercises the same sequence production takes.
    ///
    /// The arms that break a resolver ON PURPOSE cannot freeze at all; they are probing `apply`'s
    /// OWN refusals, which fire on those same resolvers BEFORE the identity comparison, so an
    /// unfreezable command is dispatched against a placeholder and still reaches exactly the door
    /// it names.
    fn dispatch<T: GmailTransport, A: GmailAccountResolver, M: GmailMessageRefResolver>(
        conn: &GmailConnector<T, A, M>,
        command: &Command,
    ) -> Result<(), ConnectorError> {
        let basis = conn.resolve_basis(command).unwrap_or_else(|_| FrozenBasis {
            native_resource_key: native_resource_key(GMAIL_KEY_PROVIDER, &["<unfreezable>"]),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            atom_targets: [("membership:INBOX".to_string(), false)]
                .into_iter()
                .collect(),
            role_bindings: std::collections::BTreeMap::new(),
            freshness: Freshness::ImmutableConstants,
        });
        conn.apply(command, &basis)
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

    /// A DIFFERENT provider message the resolver can rebind ONTO — seeded in the inbox, so a
    /// retargeted Archive would really strip a message the operation never named.
    const REBOUND_MESSAGE_ID: &str = "GMSG-PROVIDER-REBOUND-9a1";

    /// A message-ref resolver that REBINDS MID-FLIGHT: the seeded id for the first `stable`
    /// resolutions, a different provider message for every one after. Models exactly what
    /// BASIS-6 exists for — a local durable mapping that moved between the moment identity was
    /// FROZEN and the moment the wire is entered.
    struct RebindingMessageRefs {
        inner: FakeGmail,
        stable: std::cell::Cell<usize>,
        rebound: GmailMessageId,
    }

    impl GmailMessageRefResolver for RebindingMessageRefs {
        fn resolve_message(
            &self,
            photon_account: &str,
            message_ref: &str,
        ) -> Result<Option<GmailMessageId>, LogError> {
            match self.stable.get() {
                0 => Ok(Some(self.rebound.clone())),
                n => {
                    self.stable.set(n - 1);
                    self.inner.resolve_message(photon_account, message_ref)
                }
            }
        }
    }

    #[test]
    fn forward_dispatch_never_retargets_the_wire_onto_a_rebound_message() {
        // BASIS-6, at the FORWARD dispatch site: "dispatch never
        // RE-resolves — a binding change between admission and dispatch REFUSES, it never
        // retargets; the frozen basis is the identity the wire is permitted to touch" (§2.2).
        // `restore` has enforced this at its own dispatch site and NAMED `apply` as the
        // deferral to the dispatch stage. This is that stage.
        //
        // The exposure gate and the `SEND_AUTHORIZED` payload are derived from the
        // ADMISSION-FROZEN basis — so an `apply` that re-resolves puts the wire on ids no gate
        // ever saw. The rebind is scripted at the THIRD resolution: 1 = `resolve_basis`
        // (admission), 2 = `observe` (the §2.2 capture), 3 = `apply` (the wire).
        let fake = FakeGmail::healthy();
        fake.add_label(REBOUND_MESSAGE_ID, INBOX);
        let messages = RebindingMessageRefs {
            inner: fake.clone(),
            stable: std::cell::Cell::new(2),
            rebound: GmailMessageId(REBOUND_MESSAGE_ID.to_string()),
        };
        let connector = GmailConnector::new(fake.clone(), fake.clone(), messages);
        let mut bus = CommandBus::new(InMemoryIntentLog::new(), connector);

        let outcome = bus.execute(&archive("msg-1"));
        match &outcome {
            Err(ExecuteError::Connector(error)) => {
                assert_eq!(
                    error.kind,
                    FailureKind::Deterministic,
                    "a frozen basis is immutable — an identical retry can only re-ask the same \
                     wrong question"
                );
                assert_eq!(
                    error.effect_evidence,
                    EffectEvidence::ProvenNoWire,
                    "the refusal is decided on a LOCAL comparison before any modify is built"
                );
            }
            other => panic!("a rebound binding must REFUSE pre-wire, got {other:?}"),
        }
        assert!(
            fake.modifies().is_empty(),
            "nothing may reach the wire on a refused dispatch, got {:?}",
            fake.modifies()
        );
        assert!(
            fake.labels_of(REBOUND_MESSAGE_ID).contains(INBOX),
            "the REBOUND message is a stranger to this operation and must be untouched"
        );
        assert!(
            fake.labels_of(SEED_MESSAGE_ID).contains(INBOX),
            "…and the frozen message is untouched too: the dispatch refused, it did not retry"
        );
    }

    // ---- the resolver seam (BASIS-2/-3/-4) ----

    #[test]
    fn resolve_basis_freezes_the_native_identity_and_the_constant_label() {
        // BASIS-3/-4: Gmail's M1 verbs touch only IMMUTABLE system labels ("literal
        // constants, nothing to cache"), and the native identity is user-scoped.
        let fake = FakeGmail::healthy();
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let basis = c.resolve_basis(&archive("msg-1")).unwrap();
        assert_eq!(
            basis.native_resource_key,
            native_resource_key(GMAIL_KEY_PROVIDER, &[SEED_USER_ID, SEED_MESSAGE_ID])
        );
        assert!(basis.touched_atoms.contains_key("membership:INBOX"));
        assert_eq!(
            basis.freshness,
            crate::prestate::Freshness::ImmutableConstants
        );
    }

    #[test]
    fn resolve_basis_refuses_the_credential_relative_me_alias() {
        // BASIS-4/-6: `me` is not an identity, it is a POINTER at whoever the credential
        // currently authenticates as. Frozen into `native_resource_key` it re-reads, after a
        // credential rebind, as a DIFFERENT mailbox whose key still encodes `me` — so
        // BASIS-6's identity check passes on a resource the journal never observed. The freeze
        // refuses; the wire may keep saying `me`.
        let fake = FakeGmail::healthy().with(|s| s.user_id = Some(GmailUserId("me".to_string())));
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let err = c.resolve_basis(&archive("msg-1")).unwrap_err();
        assert!(
            err.0.contains("stable account identity"),
            "named refusal, got: {}",
            err.0
        );
    }

    #[test]
    fn the_me_alias_is_refused_before_any_intent_row_exists() {
        // The refusal runs BEFORE `record()` (BASIS-2 admission order), so an alias-seeded
        // resolver never leaves a durable row whose key names `me`.
        let fake = FakeGmail::healthy().with(|s| s.user_id = Some(GmailUserId("me".to_string())));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        bus.execute(&archive("msg-1"))
            .expect_err("the alias is refused at admission");
        assert!(
            bus.log().get("k1").unwrap().is_none(),
            "a refused admission records nothing"
        );
    }

    /// A store failure's own text: a SQLite condition, an on-disk path, and a provider id —
    /// exactly the unconstrained below-seam material a `{e:?}` interpolation would copy out.
    const BELOW_SEAM_FAULT_TEXT: &str =
        "SQLITE_BUSY: UPDATE refs SET gmail_id='GMAILUSER-PROVIDER-7f3a' \
         (/var/photon/store.sqlite)";

    #[test]
    fn a_resolver_failure_surfaces_a_fixed_id_free_refusal() {
        // Confinement is NOT only the apply path: `resolve_basis` runs at ADMISSION and its
        // refusal reaches the caller through execute(). The refusal is BUILT from a fixed
        // phrase, so the store error's text can never ride out with it (ADR-P003/P004).
        let fake = FakeGmail::healthy()
            .with(|s| s.resolver_fault = Some(LogError(BELOW_SEAM_FAULT_TEXT.to_string())));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        let err = bus
            .execute(&archive("msg-1"))
            .expect_err("a resolver failure refuses admission");
        let surfaced = format!("{err:?}");
        for leaked in ["SQLITE_BUSY", SEED_USER_ID, "/var/photon/store.sqlite"] {
            assert!(
                !surfaced.contains(leaked),
                "below-seam text {leaked} leaked above the seam: {surfaced}"
            );
        }
        assert!(
            surfaced.contains("message-ref resolver failure"),
            "the FIXED phrase is what surfaces: {surfaced}"
        );
    }

    #[test]
    fn resolve_basis_refuses_an_unresolved_message_ref_retryably() {
        // BASIS-2: a missing resolver answer REFUSES admission with a NAMED error — never a
        // stale fallback, never a wire call from inside the admission path.
        let fake = FakeGmail::healthy();
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let err = c.resolve_basis(&archive("no-such-ref")).unwrap_err();
        assert!(
            err.0.contains("message ref unresolved"),
            "named refusal, got: {}",
            err.0
        );
    }

    #[test]
    fn set_flag_basis_names_the_polarity_carrying_label() {
        // The seam absorbs polarity: Seen rides UNREAD, Flagged rides STARRED. The frozen
        // atom names the label the operation actually touches (§3.1a).
        let fake = FakeGmail::healthy();
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let seen = Command::new(
            "k-seen",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag {
                message_ref: "msg-1".to_string(),
                flag: MailFlag::Seen,
                value: true,
            },
        );
        assert!(c
            .resolve_basis(&seen)
            .unwrap()
            .touched_atoms
            .contains_key("label:UNREAD"));
        let flagged = Command::new(
            "k-flagged",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag {
                message_ref: "msg-1".to_string(),
                flag: MailFlag::Flagged,
                value: true,
            },
        );
        assert!(c
            .resolve_basis(&flagged)
            .unwrap()
            .touched_atoms
            .contains_key("label:STARRED"));
    }

    /// A `SetFlag` command for the standard fixture message — the polarity arms vary only
    /// the flag and its value.
    fn set_flag_command(flag: MailFlag, value: bool) -> Command {
        Command::new(
            "k-flag",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag {
                message_ref: "msg-1".to_string(),
                flag,
                value,
            },
        )
    }

    #[test]
    fn gmail_resolve_basis_freezes_forward_targets_with_polarity() {
        // §3.2/§4.1 `A`: the value each touched atom holds AFTER the forward action. POLARITY
        // is the connector's to absorb — Seen is stored NEGATIVE (the atom is the UNREAD
        // label), so `Seen=true` targets `label:UNREAD=false`. Frozen HERE, at resolve time:
        // re-deriving it at undo time is the rebind BASIS-6 forbids.
        let fake = FakeGmail::healthy();
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let archived = c.resolve_basis(&archive("msg-1")).unwrap();
        assert_eq!(
            archived.atom_targets.get("membership:INBOX"),
            Some(&false),
            "archive removes INBOX"
        );
        let unarchived = c.resolve_basis(&unarchive("msg-1")).unwrap();
        assert_eq!(
            unarchived.atom_targets.get("membership:INBOX"),
            Some(&true),
            "unarchive adds INBOX"
        );
        let seen = c
            .resolve_basis(&set_flag_command(MailFlag::Seen, true))
            .unwrap();
        assert_eq!(
            seen.atom_targets.get("label:UNREAD"),
            Some(&false),
            "seen=true clears UNREAD"
        );
        let unseen = c
            .resolve_basis(&set_flag_command(MailFlag::Seen, false))
            .unwrap();
        assert_eq!(
            unseen.atom_targets.get("label:UNREAD"),
            Some(&true),
            "seen=false sets UNREAD"
        );
        let flagged = c
            .resolve_basis(&set_flag_command(MailFlag::Flagged, true))
            .unwrap();
        assert_eq!(flagged.atom_targets.get("label:STARRED"), Some(&true));
    }

    // ---- the restore seam (§3.1/§4.2: the native delta written from the captured P) ----

    #[test]
    fn gmail_restore_sends_delta_arrays_from_captured_values_not_action_direction() {
        // Every array entry comes from the CAPTURED value, never from the verb. Both arms
        // below are the ones a direction-derived inverse gets WRONG: the inverse of Archive
        // is "add INBOX", but a message captured NOT in the inbox must be restored to NOT in
        // the inbox — and symmetrically for Unarchive. (.)
        //
        // NAMED LIMIT of the single-atom terrain: a Boolean atom has two values, so `P` is
        // either `A` or `¬A` and the wire form of "restore P" is necessarily the wire form of
        // one of them. These arms discriminate the BLIND INVERSE (`¬A`); the other defect —
        // re-applying the forward result — is not decidable at this seam and is killed one
        // level up, by §4.1's `P == A` no-op kill, which never dispatches at all. The JMAP
        // pair below has a third observed state and so discriminates both.
        let fake = FakeGmail::healthy();
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        // Forward verb ARCHIVE, captured pre-state "was not in INBOX" ⇒ REMOVE, not add.
        let archived = archive("msg-1");
        let basis = c.resolve_basis(&archived).unwrap();
        let p_out: BTreeMap<String, bool> = [("membership:INBOX".to_string(), false)]
            .into_iter()
            .collect();
        c.restore(&archived, &basis, &p_out).expect("restore dispatches");
        let body = fake.modifies().pop().expect("one modify body recorded");
        assert_eq!(body.remove_label_ids(), ["INBOX".to_string()]);
        assert!(
            body.add_label_ids().is_empty(),
            "the inverse of Archive would have ADDED INBOX; P says otherwise"
        );
        assert!(!fake.labels_of(SEED_MESSAGE_ID).contains(INBOX));

        // Forward verb UNARCHIVE, captured pre-state "was in INBOX" ⇒ ADD, not remove.
        let unarchived = unarchive("msg-1");
        let basis = c.resolve_basis(&unarchived).unwrap();
        let p_in: BTreeMap<String, bool> = [("membership:INBOX".to_string(), true)]
            .into_iter()
            .collect();
        c.restore(&unarchived, &basis, &p_in).expect("restore dispatches");
        let body = fake.modifies().pop().expect("one modify body recorded");
        assert_eq!(body.add_label_ids(), ["INBOX".to_string()]);
        assert!(
            body.remove_label_ids().is_empty(),
            "the inverse of Unarchive would have REMOVED INBOX; P says otherwise"
        );
        assert!(fake.labels_of(SEED_MESSAGE_ID).contains(INBOX));

        // Delta grain is TOTAL: an atom the capture does not cover is a deterministic
        // refusal — a restore that guessed the missing value would be the blind inverse
        // wearing a different name. Nothing is dispatched.
        let before = fake.modifies().len();
        let err = c
            .restore(&archived, &basis, &BTreeMap::new())
            .expect_err("an uncovered atom must refuse");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert_eq!(fake.modifies().len(), before, "a refusal dispatches nothing");
    }

    #[test]
    fn gmail_restore_refuses_the_inverse_direction_a_disabled_capability_forbids() {
        // The Gmail mirror of the JMAP arm. Restore writes the INVERSE of
        // the parent's forward action, so it must clear the SAME published capability gate
        // `apply` makes for that inverse verb. Archive on, Unarchive OFF ⇒ restore of an
        // Archive (the Unarchive direction) is refused deterministically and dispatches nothing.
        let fake = FakeGmail::healthy();
        let c = GmailConnector::with_capabilities(
            fake.clone(),
            fake.clone(),
            fake.clone(),
            CapabilityMap::custom(true, false, true, true, false, false, false, false),
        );
        let archived = archive("msg-1");
        let basis = c.resolve_basis(&archived).unwrap();
        // P = the captured pre-state "was in INBOX" ⇒ the ADD-INBOX (Unarchive) delta.
        let p_in: BTreeMap<String, bool> =
            [("membership:INBOX".to_string(), true)].into_iter().collect();
        let before = fake.modifies().len();
        let err = c
            .restore(&archived, &basis, &p_in)
            .expect_err("unarchive disabled ⇒ restore of an archive refuses");
        assert_eq!(err.kind, FailureKind::Deterministic);
        assert_eq!(fake.modifies().len(), before, "a capability refusal dispatches nothing");
    }

    #[test]
    fn gmail_restore_refuses_a_rebound_identity_before_dispatch() {
        // BASIS-6 AT THE RESTORE DISPATCH SITE. `restore` re-resolves the
        // user and the message through the SAME resolvers `resolve_basis` and `observe` use,
        // and — before this fold — never compared the recomputed native key against the one
        // admission FROZE. A resolver rebind between the observation and the restore
        // therefore retargeted the captured-pre-state write onto a DIFFERENT provider object:
        // the undo "succeeded" while writing P onto a message that never carried it, and the
        // message the journal actually witnessed stayed in forward state.
        //
        // BASIS-6 is explicit that every later step verifies the current binding still
        // matches the frozen basis and REFUSES on mismatch; the engine never silently
        // re-resolves onto another object. The refusal is DETERMINISTIC — a frozen basis is
        // immutable, so an identical retry can only ask the same wrong question again.
        const REBOUND_MESSAGE_ID: &str = "GMSG-PROVIDER-REBOUND-9999";
        let fake = FakeGmail::healthy();
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive("msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        // A total capture over the frozen atoms: nothing here is what refuses.
        let p: BTreeMap<String, bool> = [("membership:INBOX".to_string(), true)]
            .into_iter()
            .collect();
        // THE REBIND: the same Photon-local ref now resolves to another provider message.
        fake.state.borrow_mut().messages.insert(
            "msg-1".to_string(),
            GmailMessageId(REBOUND_MESSAGE_ID.to_string()),
        );
        let before = fake.modifies().len();

        let err = c
            .restore(&cmd, &basis, &p)
            .expect_err("a rebound identity must refuse BEFORE the modify");

        assert_eq!(
            err.kind,
            FailureKind::Deterministic,
            "a frozen basis is immutable — retrying re-asks the same wrong question"
        );
        assert_eq!(
            fake.modifies().len(),
            before,
            "NOTHING is dispatched: the refusal precedes the wire"
        );
        assert!(
            fake.labels_of(REBOUND_MESSAGE_ID).is_empty(),
            "the rebound message was never touched"
        );
        assert!(
            fake.labels_of(SEED_MESSAGE_ID).contains(INBOX),
            "…and the frozen message is exactly as the observation left it"
        );
        // Confinement by construction: the refusal names no provider handle.
        for id in [REBOUND_MESSAGE_ID, SEED_MESSAGE_ID, SEED_USER_ID] {
            assert!(
                !err.message.contains(id),
                "a provider id rode the rebind refusal: {}",
                err.message
            );
        }
    }

    #[test]
    fn observe_answers_the_frozen_atoms_for_the_frozen_identity() {
        // §2.2 observe: the minimal `messages.get` label-set oracle (proven read
        // shape), projected onto exactly the frozen atoms, answering for the native id read.
        let fake = FakeGmail::healthy();
        // A label OUTSIDE the frozen atoms, so the full pre-effect vector and the atom projection
        // are different sets.
        fake.add_label(SEED_MESSAGE_ID, "CATEGORY_UPDATES");
        let c = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let cmd = archive("msg-1");
        let basis = c.resolve_basis(&cmd).unwrap();
        let obs = c.observe(&cmd, &basis).unwrap();
        assert_eq!(obs.native_resource_key, basis.native_resource_key);
        assert_eq!(
            obs.atoms.get("membership:INBOX"),
            Some(&true),
            "the seeded message carries INBOX"
        );
        // the observation also carries the FULL label set it read — beside the
        // projection, never folded into it.
        assert_eq!(
            obs.provider_label_vector,
            Some(fake.labels_of(SEED_MESSAGE_ID)),
            "the pre-effect vector is the whole set the read returned"
        );
        assert!(
            !obs.atoms.contains_key("CATEGORY_UPDATES"),
            "a label outside the frozen atoms is not projected into `atoms`"
        );
    }

    // ---- connector behavior (the ADR-P003 neutrality proof) ----

    #[test]
    fn archive_removes_the_inbox_label() {
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        dispatch(&conn, &archive("msg-1")).expect("archive should succeed");

        let labels = fake.labels_of(SEED_MESSAGE_ID);
        assert!(!labels.contains(INBOX), "archive should remove the INBOX label");
    }

    #[test]
    fn unarchive_adds_the_inbox_label() {
        // Seed the message with no INBOX label (already archived), then unarchive.
        let fake = FakeGmail::healthy().with(|s| {
            s.labels.insert(SEED_MESSAGE_ID.to_string(), BTreeSet::new());
        });
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        dispatch(&conn, &unarchive("msg-1")).expect("unarchive should succeed");

        let labels = fake.labels_of(SEED_MESSAGE_ID);
        assert!(labels.contains(INBOX), "unarchive should add the INBOX label");
    }

    #[test]
    fn archive_twice_is_an_idempotent_no_op_success() {
        // Design §3.4: Gmail modify is set-style idempotent — removing an absent label is a no-op
        // success, so a crash-retry / lost-ack re-dispatch is safe. (The live slice must prove the
        // real provider honors this; the fake locks the design intent.)
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        dispatch(&conn, &archive("msg-1")).expect("first archive");
        dispatch(&conn, &archive("msg-1")).expect("second archive is a no-op success");

        assert!(!fake.labels_of(SEED_MESSAGE_ID).contains(INBOX), "INBOX stays removed");
    }

    #[test]
    fn archive_preserves_unrelated_labels() {
        // The toggle is surgical — only INBOX moves. A user label on the same message must survive
        // (3- 2026-07-04, ArchiveSemanticFidelity: prove Archive/Unarchive don't strip
        // other labels; the design's predicate is "remove INBOX from the resolved message" only).
        let fake = FakeGmail::healthy().with(|s| {
            let mut set = BTreeSet::new();
            set.insert(INBOX.to_string());
            set.insert("Label_42".to_string());
            s.labels.insert(SEED_MESSAGE_ID.to_string(), set);
        });
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        dispatch(&conn, &archive("msg-1")).expect("archive should succeed");

        let labels = fake.labels_of(SEED_MESSAGE_ID);
        assert!(!labels.contains(INBOX), "INBOX removed");
        assert!(labels.contains("Label_42"), "unrelated user label must survive the surgical toggle");
    }

    // ---- SetFlag(Seen) — the UNREAD polarity inversion (M1 §2) ----

    #[test]
    fn set_flag_seen_true_removes_unread_and_false_adds_it() {
        // THE POLARITY INVERSION (design §3.3, produce-check Item 3's most-likely-serious
        // footgun): Seen is the neutral positive; Gmail stores the NEGATIVE (UNREAD).
        // read (Seen=true)  ⇒ remove UNREAD;  unread (Seen=false) ⇒ add UNREAD.
        // NEUTRALITY HEADLINE (Gmail half — twin of the jmap.rs keyword test).
        let fake = FakeGmail::healthy();
        fake.add_label(SEED_MESSAGE_ID, "UNREAD"); // seeded unread
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let read = Command::new(
            "k-read",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: true },
        );
        dispatch(&conn, &read).expect("mark read");
        assert!(!fake.labels_of(SEED_MESSAGE_ID).contains("UNREAD"), "read ⇒ UNREAD absent");

        let unread = Command::new(
            "k-unread",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: false },
        );
        dispatch(&conn, &unread).expect("mark unread");
        assert!(fake.labels_of(SEED_MESSAGE_ID).contains("UNREAD"), "unread ⇒ UNREAD present");
    }

    // ---- SetFlag(Flagged) — the STARRED direct polarity (star/unstar) ----

    #[test]
    fn set_flag_flagged_true_adds_starred_and_false_removes_it() {
        // THE DIRECT POLARITY (star/unstar design 2026-07-26 §3/§5.1): unlike Seen/UNREAD there
        // is NO inversion — star (Flagged=true) ⇒ ADD STARRED; unstar (false) ⇒ REMOVE it. The
        // two-sided assert is what catches a copied inversion from the Seen mechanic.
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let star = Command::new(
            "k-star",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: true },
        );
        dispatch(&conn, &star).expect("star");
        assert!(fake.labels_of(SEED_MESSAGE_ID).contains("STARRED"), "star ⇒ STARRED present");

        let unstar = Command::new(
            "k-unstar",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: false },
        );
        dispatch(&conn, &unstar).expect("unstar");
        assert!(!fake.labels_of(SEED_MESSAGE_ID).contains("STARRED"), "unstar ⇒ STARRED absent");
    }

    #[test]
    fn set_flag_flagged_is_idempotent_and_surgical_on_unrelated_labels() {
        let fake = FakeGmail::healthy();
        fake.add_label(SEED_MESSAGE_ID, "IMPORTANT"); // an unrelated label that must survive
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let star = Command::new(
            "k-st1",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Flagged, value: true },
        );
        dispatch(&conn, &star).expect("first");
        dispatch(&conn, &star).expect("idempotent repeat"); // provider-idempotent modify
        assert!(
            fake.labels_of(SEED_MESSAGE_ID).contains("IMPORTANT"),
            "surgical: unrelated labels survive"
        );
        assert!(fake.labels_of(SEED_MESSAGE_ID).contains("STARRED"), "STARRED stays set");
    }

    #[test]
    fn set_flag_is_idempotent_and_surgical_on_unrelated_labels() {
        let fake = FakeGmail::healthy();
        fake.add_label(SEED_MESSAGE_ID, "IMPORTANT"); // an unrelated label that must survive
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let read = Command::new(
            "k-r1",
            "photon-acct",
            crate::Facet::Mail,
            Action::SetFlag { message_ref: "msg-1".into(), flag: MailFlag::Seen, value: true },
        );
        dispatch(&conn, &read).expect("first");
        dispatch(&conn, &read).expect("idempotent repeat"); // provider-idempotent modify
        assert!(
            fake.labels_of(SEED_MESSAGE_ID).contains("IMPORTANT"),
            "surgical: unrelated labels survive"
        );
    }

    #[test]
    fn gmail_set_flag_capability_is_per_flag_and_published_by_default() {
        let caps = CapabilityMap::m1_verbs();
        assert!(caps.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Seen,
            value: true,
        }));
        let no_flag = CapabilityMap::custom(true, true, false, true, false, false, false, false);
        assert!(!no_flag.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Seen,
            value: true,
        }));
    }

    #[test]
    fn gmail_set_flag_flagged_capability_is_per_flag_and_published_by_default() {
        // The Flagged row is its OWN capability (per-flag, never wholesale): default-published,
        // and refusing it must not disturb Seen (star/unstar design 2026-07-26 §3/§5.1).
        let caps = CapabilityMap::m1_verbs();
        assert!(caps.supports(&Action::SetFlag {
            message_ref: "m".into(),
            flag: MailFlag::Flagged,
            value: true,
        }));
        let no_flagged = CapabilityMap::custom(true, true, true, false, false, false, false, false);
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

    // ---- failure classing ----

    #[test]
    fn unsupported_action_fails_safe_deterministic() {
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::with_capabilities(
            fake.clone(),
            fake.clone(),
            fake.clone(),
            CapabilityMap::custom(false, true, true, true, false, false, false, false),
        );

        let err = dispatch(&conn, &archive("msg-1")).expect_err("archive unsupported -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn account_resolution_miss_is_deterministic() {
        let fake = FakeGmail::healthy().with(|s| s.user_id = None);
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("no user -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn message_resolution_miss_is_deterministic() {
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("no-such-ref")).expect_err("unknown message -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn message_store_failure_is_transient_not_a_dead_letter() {
        // A locked/corrupt store must be retryable, never mis-classified as permanent MessageUnresolved
        // (the Option-swallow class carried from M0).
        struct FailingStore;
        impl GmailMessageRefResolver for FailingStore {
            fn resolve_message(
                &self,
                _a: &str,
                _m: &str,
            ) -> Result<Option<GmailMessageId>, LogError> {
                Err(LogError("store locked".to_string()))
            }
        }
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::new(fake.clone(), fake.clone(), FailingStore);

        let err = dispatch(&conn, &archive("msg-1")).expect_err("store failure -> error");
        assert_eq!(
            err.kind,
            FailureKind::Transient,
            "a store failure is retryable, not a dead-letter"
        );
    }

    #[test]
    fn deterministic_provider_rejection_maps_to_deterministic() {
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::NotFound));
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("provider NotFound -> error");
        assert_eq!(err.kind, FailureKind::Deterministic);
    }

    #[test]
    fn transient_provider_rejection_maps_to_transient() {
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::RateLimit));
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());

        let err = dispatch(&conn, &archive("msg-1")).expect_err("rateLimit -> error");
        assert_eq!(err.kind, FailureKind::Transient);
    }

    // ---- confinement (ADR-P003/P004: no provider id above the seam) ----

    #[test]
    fn no_provider_ids_leak_into_surfaced_errors() {
        let seeds = [SEED_USER_ID, SEED_MESSAGE_ID];
        let cases = vec![
            FakeGmail::healthy().with(|s| s.inject = Some(GmailError::NotFound)),
            FakeGmail::healthy().with(|s| s.inject = Some(GmailError::RateLimit)),
        ];
        for fake in cases {
            let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
            let err = dispatch(&conn, &archive("msg-1")).expect_err("should error");
            for seed in seeds {
                assert!(
                    !err.message.contains(seed),
                    "provider id {seed} leaked into error message: {}",
                    err.message
                );
            }
        }
    }

    // ---- end-to-end through the bus (the connector drives the real ADR-P013 lifecycle) ----

    #[test]
    fn bus_executes_archive_through_the_gmail_connector() {
        let fake = FakeGmail::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );

        bus.execute(&archive("msg-1")).expect("execute should succeed");

        assert_eq!(bus.log().get("k1").unwrap().unwrap().status, IntentStatus::Applied);
        assert!(!fake.labels_of(SEED_MESSAGE_ID).contains(INBOX));
    }

    #[test]
    fn bus_dead_letters_a_deterministic_provider_failure() {
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::Forbidden));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );

        let result = bus.execute(&archive("msg-1"));
        assert!(matches!(result, Err(ExecuteError::Connector(_))));
        assert_eq!(bus.log().get("k1").unwrap().unwrap().status, IntentStatus::Failed);
    }

    #[test]
    fn bus_dead_letters_a_transient_provider_failure_at_the_retry_cap() {
        // The taxonomy must drive the retry-cap lifecycle: a persistent TRANSIENT failure stays
        // Pending and is retried, then dead-letters to Failed once the budget is exhausted.
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::RateLimit));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );

        assert!(matches!(
            bus.execute(&archive("msg-1")),
            Err(ExecuteError::Connector(_))
        ));
        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Pending,
            "one transient failure is retryable, not dead-lettered"
        );

        for _ in 0..(RETRY_CAP - 1) {
            bus.recover().expect("recovery sweep runs");
        }

        assert_eq!(
            bus.log().get("k1").unwrap().unwrap().status,
            IntentStatus::Failed,
            "a transient failure retried past RETRY_CAP dead-letters to Failed"
        );
    }

    #[test]
    fn set_flag_applies_through_the_bus_and_lands_applied() {
        // End-to-end: SetFlag → Applied; the durable row round-trips the set_flag:seen:true
        // token through the real SqliteIntentLog (mirrors the module's archive end-to-end test
        // with the action swapped and a re-read assertion added).
        use crate::SqliteIntentLog;
        let path = crate::test_temp::TempFile::sqlite("aruna-gmail-setflag-bus");
        let fake = FakeGmail::healthy();
        fake.add_label(SEED_MESSAGE_ID, "UNREAD"); // seeded unread
        let action = Action::SetFlag {
            message_ref: "msg-1".to_string(),
            flag: MailFlag::Seen,
            value: true,
        };
        let cmd = Command::new("k-sf", "photon-acct", crate::Facet::Mail, action.clone());
        {
            let mut bus = CommandBus::new(
                SqliteIntentLog::open(&path).expect("open"),
                GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
            );
            bus.execute(&cmd).expect("execute should succeed");
            assert_eq!(
                bus.log().get("k-sf").unwrap().unwrap().status,
                IntentStatus::Applied
            );
            assert!(
                !fake.labels_of(SEED_MESSAGE_ID).contains("UNREAD"),
                "read ⇒ UNREAD removed"
            );
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
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::Forbidden));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
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
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::RateLimit));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
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
        // end-to-end test with the flag swapped; star/unstar design 2026-07-26 §5.1).
        use crate::SqliteIntentLog;
        let path = crate::test_temp::TempFile::sqlite("aruna-gmail-setflagged-bus");
        let fake = FakeGmail::healthy();
        let action = Action::SetFlag {
            message_ref: "msg-1".to_string(),
            flag: MailFlag::Flagged,
            value: true,
        };
        let cmd = Command::new("k-sfl", "photon-acct", crate::Facet::Mail, action.clone());
        {
            let mut bus = CommandBus::new(
                SqliteIntentLog::open(&path).expect("open"),
                GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
            );
            bus.execute(&cmd).expect("execute should succeed");
            assert_eq!(
                bus.log().get("k-sfl").unwrap().unwrap().status,
                IntentStatus::Applied
            );
            assert!(
                fake.labels_of(SEED_MESSAGE_ID).contains("STARRED"),
                "star ⇒ STARRED added"
            );
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
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::Forbidden));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
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
        let fake = FakeGmail::healthy().with(|s| s.inject = Some(GmailError::RateLimit));
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
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
        let fake = FakeGmail::healthy();
        let conn = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let caps = conn.capabilities();
        assert!(caps.archive());
        assert!(caps.unarchive());
        assert!(caps.supports(&Action::Archive {
            message_ref: "msg-1".to_string()
        }));
    }

    // TRASH/SPAM labels, spam requests, capability rows, closure ----

    #[test]
    fn labels_and_requests_are_the_system_ids() {
        assert_eq!(LabelId::trash().0, "TRASH");
        assert_eq!(LabelId::spam().0, "SPAM");
        let add = GmailModifyRequest::add_spam();
        assert_eq!(add.add_label_ids(), &["SPAM".to_string()]);
        assert!(add.remove_label_ids().is_empty());
        let rm = GmailModifyRequest::remove_spam();
        assert!(rm.add_label_ids().is_empty());
        assert_eq!(rm.remove_label_ids(), &["SPAM".to_string()]);
    }

    #[test]
    fn capability_rows_are_per_verb_and_the_triage_set_publishes_all_four() {
        let m = || "m".to_string();
        let caps = CapabilityMap::triage_verbs();
        assert!(caps.supports(&Action::Trash { message_ref: m() }));
        assert!(caps.supports(&Action::Untrash { message_ref: m() }));
        assert!(caps.supports(&Action::MarkSpam { message_ref: m() }));
        assert!(caps.supports(&Action::UnmarkSpam { message_ref: m() }));
        assert!(caps.supports(&Action::Archive { message_ref: m() }), "the triage set is a superset of m1_verbs");
        let m1 = CapabilityMap::m1_verbs();
        assert!(!m1.supports(&Action::Trash { message_ref: m() }), "m1_verbs publishes NO triage verb — the arm a stale map ships is refused, never guessed");
        assert!(!m1.supports(&Action::MarkSpam { message_ref: m() }));
        // m1_verbs publishes NONE of the four (mutation witness: one row flipped on
        // survived the two hand-picked asserts above).
        let four = [
            Action::Trash { message_ref: m() },
            Action::Untrash { message_ref: m() },
            Action::MarkSpam { message_ref: m() },
            Action::UnmarkSpam { message_ref: m() },
        ];
        for a in &four {
            assert!(!m1.supports(a), "m1_verbs must not publish {a:?}");
        }
        // PER VERB: a map with exactly ONE triage row on supports exactly that verb (mutation
        // witness: a cross-wired row survived the all-on / all-off maps).
        for (i, only) in four.iter().enumerate() {
            let row = |k: usize| k == i;
            let caps = CapabilityMap::custom(true, true, true, true, row(0), row(1), row(2), row(3));
            for (k, a) in four.iter().enumerate() {
                assert_eq!(caps.supports(a), k == i, "only {only:?} is on; asked {a:?}");
            }
        }
    }

    #[test]
    fn frozen_atoms_are_the_rippled_atom_closure_with_declared_targets() {
        // v2 §4.2 (the architectural rule, its one home): the frozen atom set is the CLOSURE
        // over every atom the provider mutates as a side effect — never only the atom we send.
        use std::collections::BTreeMap;
        let m = || "m".to_string();
        let expect = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        assert_eq!(touched_atoms(&Action::Trash { message_ref: m() }), expect(&[("label:TRASH", "TRASH"), ("membership:INBOX", "INBOX")]));
        assert_eq!(touched_atoms(&Action::Untrash { message_ref: m() }), expect(&[("label:TRASH", "TRASH"), ("membership:INBOX", "INBOX")]));
        assert_eq!(touched_atoms(&Action::MarkSpam { message_ref: m() }), expect(&[("label:SPAM", "SPAM"), ("membership:INBOX", "INBOX")]));
        assert_eq!(touched_atoms(&Action::UnmarkSpam { message_ref: m() }), expect(&[("label:SPAM", "SPAM"), ("membership:INBOX", "INBOX")]));
        // The forward targets (A): Gmail strips INBOX on trash/spam; the restore arms leave INBOX
        // where trash/spam left it (All Mail) — a DECLARED HYPOTHESIS the live ripple drill
        // falsifies or confirms; v3 §2: UNDETERMINED until witnessed.
        let targets = |a: &Action| gmail_atom_targets(a);
        let t = |pairs: &[(&str, bool)]| -> BTreeMap<String, bool> { pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect() };
        assert_eq!(targets(&Action::Trash { message_ref: m() }), t(&[("label:TRASH", true), ("membership:INBOX", false)]));
        assert_eq!(targets(&Action::Untrash { message_ref: m() }), t(&[("label:TRASH", false), ("membership:INBOX", false)]));
        assert_eq!(targets(&Action::MarkSpam { message_ref: m() }), t(&[("label:SPAM", true), ("membership:INBOX", false)]));
        assert_eq!(targets(&Action::UnmarkSpam { message_ref: m() }), t(&[("label:SPAM", false), ("membership:INBOX", false)]));
        // FrozenBasis::validate's law: targets' keys == touched atoms' keys, both directions.
        for a in [Action::Trash { message_ref: m() }, Action::Untrash { message_ref: m() }, Action::MarkSpam { message_ref: m() }, Action::UnmarkSpam { message_ref: m() }] {
            assert!(touched_atoms(&a).keys().eq(gmail_atom_targets(&a).keys()));
        }
    }

    #[test]
    fn no_provider_ids_reach_the_intent_log_row() {
        // Confinement at the log boundary, not just the error path: a successful archive stores only
        // the Photon-local command in the durable row — no Gmail-native handle leaks into the SoR.
        //
        // NARROWED by (design §7a + BASIS-4): `intents.frozen_basis` EXISTS to
        // carry provider-native identity — a captured operation that could not name the
        // native resource it was admitted against would be useless as pre-state. Confinement
        // is therefore a property of the NEUTRAL vocabulary (command, action, envelope, error
        // text), not of that one column. Both halves are asserted: nothing native in the
        // command, and the native identity present EXACTLY where the design put it.
        let fake = FakeGmail::healthy();
        let mut bus = CommandBus::new(
            InMemoryIntentLog::new(),
            GmailConnector::new(fake.clone(), fake.clone(), fake.clone()),
        );
        bus.execute(&archive("msg-1")).expect("archive should succeed");

        let intent = bus.log().get("k1").unwrap().unwrap();
        let command_surface = format!("{:?}", intent.command);
        for seed in [SEED_USER_ID, SEED_MESSAGE_ID] {
            assert!(
                !command_surface.contains(seed),
                "provider id {seed} leaked into the intent-log row: {command_surface}"
            );
        }
        let basis = intent
            .frozen_basis
            .expect("stage 2 freezes a basis at admission");
        assert_eq!(
            basis.native_resource_key,
            native_resource_key(GMAIL_KEY_PROVIDER, &[SEED_USER_ID, SEED_MESSAGE_ID]),
            "the native identity lives in frozen_basis and nowhere else"
        );
    }

    // the evidence claim belongs where the PROOF lives ----

    #[test]
    fn a_foreign_transports_post_body_timeout_never_claims_no_wire() {
        // `GmailTransportError`'s variants describe WHAT failed
        // (a timeout, a reset) and prove NOTHING about WHEN. The blanket
        // `Transport(_) ⇒ ProvenNoWire` mapping was true only of the pinned HTTP transport,
        // whose `send_stage_verdict` reaches this variant exclusively from the `is_connect()`
        // arm — a property of THAT impl, not of the trait. `GmailTransport` is a public seam:
        // a foreign impl that times out waiting for a response body, AFTER the request was
        // dispatched, lands on the same variant and inherits a no-wire proof nobody holds —
        // authorizing a retry that can duplicate a mutation.
        let fake = FakeGmail::healthy()
            .with(|s| s.inject = Some(GmailError::Transport(GmailTransportError::Timeout)));
        let connector = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        let command = archive("msg-1");
        let basis = connector.resolve_basis(&command).expect("basis");

        let error = connector
            .apply(&command, &basis)
            .expect_err("the transport failed");

        assert_eq!(
            error.effect_evidence,
            EffectEvidence::Indeterminate,
            "THE RED: absence of proof is never proof — a transport failure that does not \
             POSITIVELY carry its pre-dispatch stage may not claim `ProvenNoWire`"
        );
        assert_eq!(
            error.kind,
            FailureKind::Transient,
            "…and the retry taxonomy is untouched: the two axes stay independent"
        );
    }

    // `apply_witnessed` — the routes, and the effect witness ----

    #[test]
    fn apply_witnessed_routes_trash_to_the_dedicated_endpoint_and_spam_to_modify_and_returns_the_vector() {
        // The fake's QUEUED answer differs from its modelled label set (the seeded message holds
        // `INBOX`; the answer names `CATEGORY_PROMOTIONS` and no `INBOX`), so equality with the
        // queued set proves the witness is what the ROUTE answered — never a re-read, never a
        // set the connector computed.
        let fake = FakeGmail::new_with_labels(vec!["TRASH".into(), "CATEGORY_PROMOTIONS".into()]);
        let connector = GmailConnector::with_capabilities(
            fake.clone(),
            fake.clone(),
            fake.clone(),
            CapabilityMap::triage_verbs(),
        );
        let cmd = Command::new("k", "acct", crate::Facet::Mail, Action::Trash { message_ref: "msg-1".into() });
        let basis = connector.resolve_basis(&cmd).unwrap();
        let witness = connector.apply_witnessed(&cmd, &basis).unwrap();
        assert_eq!(fake.trash_calls(), 1);
        assert_eq!(fake.modify_calls(), 0);
        let expected: BTreeSet<String> =
            ["TRASH", "CATEGORY_PROMOTIONS"].iter().map(|s| s.to_string()).collect();
        assert_eq!(witness.provider_label_vector.unwrap(), expected);

        let fake = FakeGmail::new_with_labels(vec!["SPAM".into()]);
        let connector = GmailConnector::with_capabilities(
            fake.clone(),
            fake.clone(),
            fake.clone(),
            CapabilityMap::triage_verbs(),
        );
        let cmd = Command::new("k2", "acct", crate::Facet::Mail, Action::MarkSpam { message_ref: "msg-1".into() });
        let basis = connector.resolve_basis(&cmd).unwrap();
        let witness = connector.apply_witnessed(&cmd, &basis).unwrap();
        assert_eq!(fake.trash_calls(), 0);
        assert_eq!(fake.modify_calls(), 1);
        let request = fake.last_modify_request().unwrap();
        assert_eq!(request.add_label_ids(), &["SPAM".to_string()]);
        assert!(
            request.remove_label_ids().is_empty(),
            "MarkSpam sends SPAM only — the INBOX strip is Gmail's ripple"
        );
        let expected: BTreeSet<String> = ["SPAM".to_string()].into_iter().collect();
        assert_eq!(witness.provider_label_vector, Some(expected));
    }

    #[test]
    fn apply_witnessed_routes_untrash_and_unmark_spam_to_their_own_doors_and_every_route_answers() {
        // The two restore-direction verbs the test above does not dispatch, plus one pre- verb:
        // every route is its own door, and every route hands back the transport's answer.
        let run = |action: Action| {
            let fake = FakeGmail::new_with_labels(vec!["ANSWERED".into()]);
            let connector = GmailConnector::with_capabilities(
                fake.clone(),
                fake.clone(),
                fake.clone(),
                CapabilityMap::triage_verbs(),
            );
            let cmd = Command::new("k", "acct", crate::Facet::Mail, action);
            let basis = connector.resolve_basis(&cmd).unwrap();
            let witness = connector.apply_witnessed(&cmd, &basis).unwrap();
            (fake, witness)
        };
        let answered: BTreeSet<String> = ["ANSWERED".to_string()].into_iter().collect();

        // Untrash: the dedicated untrash route — never trash, never a modify.
        let (fake, witness) = run(Action::Untrash { message_ref: "msg-1".into() });
        assert_eq!((fake.untrash_calls(), fake.trash_calls(), fake.modify_calls()), (1, 0, 0));
        assert_eq!(witness.provider_label_vector, Some(answered.clone()));

        // UnmarkSpam: the modify chokepoint, REMOVING SPAM and adding nothing.
        let (fake, witness) = run(Action::UnmarkSpam { message_ref: "msg-1".into() });
        assert_eq!((fake.untrash_calls(), fake.trash_calls(), fake.modify_calls()), (0, 0, 1));
        let request = fake.last_modify_request().unwrap();
        assert!(request.add_label_ids().is_empty());
        assert_eq!(request.remove_label_ids(), &["SPAM".to_string()]);
        assert_eq!(witness.provider_label_vector, Some(answered.clone()));

        // A pre- verb rides the same observed modify body, so it answers a vector too.
        let (fake, witness) = run(Action::Archive { message_ref: "msg-1".into() });
        assert_eq!((fake.untrash_calls(), fake.trash_calls(), fake.modify_calls()), (0, 0, 1));
        assert_eq!(fake.last_modify_request().unwrap(), GmailModifyRequest::remove_inbox());
        assert_eq!(witness.provider_label_vector, Some(answered));
    }

    #[test]
    fn apply_witnessed_refuses_pre_wire_when_the_capability_map_lacks_the_verb() {
        // `m1_verbs` publishes none of the four triage verbs: each is refused from the LOCAL
        // capability map, proven no-wire (the module's pre-wire predicate is the effect-evidence
        // tag `refused_pre_wire` sets), with zero transport calls of any kind.
        for action in [
            Action::Trash { message_ref: "msg-1".into() },
            Action::Untrash { message_ref: "msg-1".into() },
            Action::MarkSpam { message_ref: "msg-1".into() },
            Action::UnmarkSpam { message_ref: "msg-1".into() },
        ] {
            let fake = FakeGmail::new_with_labels(vec![]);
            let connector = GmailConnector::with_capabilities(
                fake.clone(),
                fake.clone(),
                fake.clone(),
                CapabilityMap::m1_verbs(),
            );
            let cmd = Command::new("k", "acct", crate::Facet::Mail, action);
            let basis = connector.resolve_basis(&cmd).unwrap();
            let err = connector.apply_witnessed(&cmd, &basis).unwrap_err();
            assert_eq!(err.effect_evidence, EffectEvidence::ProvenNoWire, "{err:?}");
            assert_eq!(err.kind, FailureKind::Deterministic, "{err:?}");
            // the refusal NAMES itself by type — the caller never
            // matches the phrase.
            assert!(err.unsupported_capability, "the capability refusal carries its own axis: {err:?}");
            assert_eq!(fake.trash_calls() + fake.untrash_calls() + fake.modify_calls(), 0);
        }
    }

    /// `GmailConnector::new` publishes `m1_verbs()` — the shell's connector —
    /// so each triage verb is refused by the capability map with the `unsupported_capability` axis
    /// set; every OTHER refusal leaves it unset (the axis is the capability map's alone).
    #[test]
    fn new_refuses_each_triage_verb_by_the_unsupported_capability_axis_and_nothing_else_sets_it() {
        let fake = FakeGmail::new_with_labels(vec![]);
        let connector = GmailConnector::new(fake.clone(), fake.clone(), fake.clone());
        for action in [
            Action::Trash { message_ref: "msg-1".into() },
            Action::Untrash { message_ref: "msg-1".into() },
            Action::MarkSpam { message_ref: "msg-1".into() },
            Action::UnmarkSpam { message_ref: "msg-1".into() },
        ] {
            let cmd = Command::new("k", "acct", crate::Facet::Mail, action.clone());
            let basis = connector.resolve_basis(&cmd).unwrap();
            let err = connector.apply_witnessed(&cmd, &basis).unwrap_err();
            assert!(err.unsupported_capability, "{action:?}: {err:?}");
        }
        for code in [
            GmailErrorCode::AccountUnresolved,
            GmailErrorCode::MessageUnresolved,
            GmailErrorCode::ProviderRejected,
            GmailErrorCode::CredentialRejected,
            GmailErrorCode::PreStateIncomplete,
        ] {
            assert!(!deterministic(code).unsupported_capability, "{code:?}");
            assert!(!refused_pre_wire(code).unsupported_capability, "{code:?}");
        }
        assert!(deterministic(GmailErrorCode::UnsupportedCapability).unsupported_capability);
    }

    #[test]
    fn the_default_apply_witnessed_is_apply_with_no_vector() {
        // Every non-Gmail connector keeps `apply` and gets `apply_witnessed` for free: a
        // default vector of None, never a fabricated one.
        struct Plain;
        impl Connector for Plain {
            fn apply(&self, _: &Command, _: &crate::prestate::FrozenBasis) -> Result<(), ConnectorError> {
                Ok(())
            }
            fn resolve_basis(&self, _: &Command) -> Result<crate::prestate::FrozenBasis, ResolveBasisError> {
                unreachable!()
            }
            fn observe(
                &self,
                _: &Command,
                _: &crate::prestate::FrozenBasis,
            ) -> Result<crate::prestate::Observation, ConnectorError> {
                unreachable!()
            }
            fn restore(
                &self,
                _: &Command,
                _: &crate::prestate::FrozenBasis,
                _: &std::collections::BTreeMap<String, bool>,
            ) -> Result<(), ConnectorError> {
                unreachable!()
            }
        }
        let basis = crate::prestate::FrozenBasis::for_test_empty();
        let w = Plain
            .apply_witnessed(
                &Command::new("k", "a", crate::Facet::Mail, Action::Archive { message_ref: "m".into() }),
                &basis,
            )
            .unwrap();
        assert_eq!(w, EffectWitness::default());
        assert!(w.provider_label_vector.is_none());
    }

    // The witness through the BUS ----

    #[test]
    fn gmail_through_the_bus_persists_the_route_answer_and_its_ripple_verdict() {
        // bus witnesses ride a double (`WitnessingConnector`, lib.rs) because `FakeGmail` is
        // private to this module. This is the same witness with the REAL connector under the bus:
        // `observe` reads the fake's label set (the PRE vector, journaled), `apply_witnessed`
        // takes the fake's trash route (the POST vector), and the bus persists both.
        let set = |s: &[&str]| -> BTreeSet<String> { s.iter().map(|x| x.to_string()).collect() };
        let run = |fake: &FakeGmail, key: &str| {
            let connector = GmailConnector::with_capabilities(
                fake.clone(),
                fake.clone(),
                fake.clone(),
                CapabilityMap::triage_verbs(),
            );
            // A Trash reaches the bus only as a plan child (a bare RED verb is
            // `PlanRequired`) — one Inbox member, `backups: off`, a ready episode.
            let mut log = crate::tests::s1_twin_seeded(&["msg-1"]);
            let plan = crate::tests::s1_plan_ready(&mut log, &["msg-1".to_string()]);
            let mut bus = crate::tests::s1_plan_bus(log, connector);
            let trash = Command::plan_child(&plan, "msg-1");
            assert_eq!(trash.action, Action::Trash { message_ref: "msg-1".into() }, "the plan's verb over the member ({key})");
            bus.execute(&trash).expect("the Trash applies");
            let pre = bus
                .log()
                .captured_pre_state(&trash.idempotency_key)
                .unwrap()
                .expect("a Trash journals its pre-state")
                .observed_label_vector;
            (pre, bus.log().effect_witness(&trash.idempotency_key).unwrap())
        };

        // (a) The fake's OWN model, no scripted answer: `healthy` seeds `INBOX`, and its trash
        // route adds ONLY `TRASH` (it never invents the ripple) — so pre {INBOX}, post
        // {INBOX, TRASH}: the delta {TRASH} lies inside the declared closure {TRASH, INBOX}.
        let fake = FakeGmail::healthy();
        let (pre, witness) = run(&fake, "k-gmail-bus");
        assert_eq!(fake.trash_calls(), 1, "the dedicated trash route, once");
        assert_eq!(pre, Some(set(&["INBOX"])), "the observe read, journaled as the pre vector");
        assert_eq!(
            witness,
            Some(crate::EffectWitnessRow {
                effect_label_vector: Some(set(&["INBOX", "TRASH"])),
                ripple_verdict: Some(crate::prestate::RippleVerdict::WithinClosure),
            }),
            "the bus persists what the Gmail ROUTE answered, judged against the frozen closure"
        );

        // (b) A scripted answer that ALSO drops IMPORTANT (seeded first, so the observe read
        // carries it): the delta {INBOX, IMPORTANT, TRASH} has IMPORTANT outside the closure, and
        // the log reads back exactly that verdict.
        let fake = FakeGmail::new_with_labels(vec!["TRASH".into()]);
        fake.add_label(SEED_MESSAGE_ID, "IMPORTANT");
        let (pre, witness) = run(&fake, "k-gmail-bus-ripple");
        assert_eq!(pre, Some(set(&["IMPORTANT", "INBOX"])));
        assert_eq!(
            witness,
            Some(crate::EffectWitnessRow {
                effect_label_vector: Some(set(&["TRASH"])),
                ripple_verdict: Some(crate::prestate::RippleVerdict::OutsideClosure {
                    unexpected: set(&["IMPORTANT"]),
                }),
            }),
            "an atom outside the closure is read back from the log as exactly that ripple"
        );
    }
}
