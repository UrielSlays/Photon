//! The refresh exchange and the credential writer.
//!
//! This module holds the exchange (its typed outcome model and the untrusted-text contract),
//! atomic persistence, and the lock primitives. The wave protocol, the credential cell, the
//! pacing floor and the admission ordering live in `credential_cell.rs`; this module owns no
//! state and sets no policy.
//!
//! The entry point for untrusted data is `parse_refresh_response`: the HTTPS body from the token
//! endpoint is attacker-influenced data. Everything the provider can say is bounded (64 KiB),
//! typed, and refused rather than guessed, and every remotely derived string that can reach a
//! reason passes the `Sanitized` contract or the scope-rendering rules before it is rendered.
//!
//! The credential directory's own files (client secret, token file, lock file) belong to the
//! user running Photon. Code already running with that user's privileges is out of scope:
//! validation here is hygiene, not a control against an on-box actor.

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Compiled constants: the things a response is never allowed to move.

/// The token endpoint, compiled in. It is never read from the client file: the file's `token_uri`
/// is only cross-checked against this constant, and a disagreement is refused.
pub(crate) const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// The product's allowed authority, as an exact set, used at the load path (the mint's own
/// main-slot contract, `scripts/gmail_drill_mint.py` `enforce_lane_scope_contract`). Missing or
/// unexpected authority is a refusal, never a widening.
///
/// Why `gmail.modify` and nothing wider: the triage verbs (trash, spam, batch label moves) are
/// writes, which `gmail.readonly` cannot perform. Google's scope reference
/// (`developers.google.com/workspace/gmail/api/auth/scopes`) says `gmail.modify` "does not allow
/// immediate, permanent deletion of threads and messages, bypassing the trash", while
/// `https://mail.google.com/` does. So `gmail.modify` is the widest authority the product can
/// hold while permanent deletion stays impossible by scope; the full-mailbox scope is never
/// requested (the mint refuses to ask for it and the loader refuses to admit it).
///
/// This is not the refresh path's reference. RFC 6749 §6 binds a refresh to the grant originally
/// made ("MUST NOT include any scope not originally granted"), and §5.1 makes an omitted `scope`
/// equal to the grant on record. So [`parse_refresh_response`] compares against the stored
/// [`GrantProvenance::effective_scopes`]; this constant answers a different question ("is this
/// the authority Photon runs under").
pub(crate) const REQUIRED_SCOPES: &[&str] = &["https://www.googleapis.com/auth/gmail.modify"];

/// The bounded body read. The client reads at most `cap + 1` bytes so "exactly the cap" and
/// "over the cap" stay distinguishable; the parser refuses anything larger.
pub(crate) const MAX_REFRESH_BODY_BYTES: usize = 64 * 1024;

/// The credential file the mint script writes and this module rewrites: the only file persisted.
pub(crate) const CREDENTIAL_FILE_NAME: &str = "gmail_readside_main_token.json";

/// The OAuth client file (`installed` entry only; see `scripts/gmail_drill_mint.py`
/// `client_from_config`).
pub(crate) const CLIENT_SECRET_FILE_NAME: &str = "client_secret.json";

/// The lock address. The file is an address, not the lock: the lock is the OS advisory lock,
/// which the kernel releases on process death.
pub(crate) const CREDENTIAL_LOCK_FILE_NAME: &str = "credential.lock";

/// Bounded acquisition: a monotonic 5 s budget polled every [`CREDENTIAL_LOCK_POLL`]. Expiry is
/// a typed [`RefreshLocalError::LockTimeout`] with no write and no hang; the blocking `lock()`
/// call is deliberately not used.
pub(crate) const CREDENTIAL_LOCK_DEADLINE: Duration = Duration::from_secs(5);

/// The poll interval inside [`CREDENTIAL_LOCK_DEADLINE`].
pub(crate) const CREDENTIAL_LOCK_POLL: Duration = Duration::from_millis(100);

/// Total request timeout, mirroring aruna-gmail.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout. It must stay shorter than [`HTTP_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// Secrets and untrusted text

/// A credential secret with one home and a redacted `Debug`, as with `aruna-gmail`'s
/// `BearerToken`. No secret byte may reach a reason, an error, a log or a `{:?}`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretString(String);

impl SecretString {
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The raw secret: the only read path (the request form, the persisted file).
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The untrusted-text contract as a type: remotely derived text that can reach a reason or the UI
/// passes an allowlist `[A-Za-z0-9_-]` and is truncated to 64 chars (the cut marked with `…`).
/// Anything failing the allowlist becomes the literal [`UNRECOGNIZED`] marker, never
/// escaped-and-echoed, and never forgeable (the marker is outside its own alphabet).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Sanitized(String);

/// What a value that failed the allowlist renders as: a literal, never the input. It lives
/// outside its own alphabet (the bare word `unrecognized` passed `code_char`, so a provider could
/// forge the scrub marker); `<` and `>` fail every allowlist here, so only the scrubber can
/// produce this string.
pub(crate) const UNRECOGNIZED: &str = "<unrecognized>";

impl Sanitized {
    /// Apply the contract. Truncation happens first, then the allowlist decides the whole value:
    /// a tail beyond 64 chars cannot smuggle markup in, and a value with anything outside the
    /// allowlist is replaced wholesale rather than partially cleaned.
    pub(crate) fn new(raw: &str) -> Self {
        Self(bounded_render(raw, 64, code_char))
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Sanitized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sanitized({})", self.0)
    }
}

impl std::fmt::Display for Sanitized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The bounded renderer both text contracts resolve through: keep at most `limit` chars, then
/// replace the whole value with [`UNRECOGNIZED`] if anything in it fails `allowed`. One code path
/// keeps the two charsets from drifting into two policies.
fn bounded_render(raw: &str, limit: usize, allowed: fn(char) -> bool) -> String {
    let truncated: String = raw.chars().take(limit).collect();
    if truncated.is_empty() || !truncated.chars().all(allowed) {
        return UNRECOGNIZED.to_string();
    }
    if raw.chars().count() > limit {
        // Truncation is marked: a silent prefix reads as the complete code, a sentence asserting a
        // value the provider never sent. '…' fails every allowlist here, so a provider cannot
        // forge an already-truncated-looking value.
        return format!("{truncated}\u{2026}");
    }
    truncated
}

fn code_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn uri_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/')
}

/// A local (client-file) URI, rendered bounded. Its charset is distinct from [`Sanitized`]: the
/// client file belongs to the user running Photon, so naming its `token_uri` back is not an
/// untrusted-data echo, but it still reaches a UI string and so stays bounded and markup-free.
fn render_local_uri(raw: &str) -> String {
    bounded_render(raw, 96, uri_char)
}

// The scope-rendering rules

/// Photon's own scope constants and the locally authored label each renders as. Remote scope
/// strings are URI-like and fail the [`Sanitized`] allowlist, so `AuthorityMismatch` never echoes
/// them: a scope equal to one of these constants renders as its label, and anything else renders
/// as [`UNRECOGNIZED`] plus a bounded count.
const SCOPE_LABELS: &[(&str, &str)] = &[
    (
        "https://www.googleapis.com/auth/gmail.readonly",
        "read-only mailbox authority",
    ),
    // The operator-facing name for what the product actually does with this scope.
    // "read/compose/send" was true of the OAuth scope and false of Photon: send is off the
    // critical path and triage is the point.
    (
        "https://www.googleapis.com/auth/gmail.modify",
        "read + triage authority",
    ),
    (
        "https://www.googleapis.com/auth/gmail.send",
        "send authority",
    ),
    (
        "https://www.googleapis.com/auth/gmail.labels",
        "label-mutation authority",
    ),
    // The label says what the scope would buy and that we never ask for it. It is the only Gmail
    // scope that can permanently delete (Google's scope reference), so "full mailbox authority"
    // understated the refusal it always earns.
    (
        "https://mail.google.com/",
        "full mailbox incl. permanent delete — never requested",
    ),
];

/// The local label for a scope Photon itself names, or `None` for anything remote-authored.
pub(crate) fn scope_label(scope: &str) -> Option<&'static str> {
    SCOPE_LABELS
        .iter()
        .find(|(uri, _)| *uri == scope)
        .map(|(_, label)| *label)
}

/// Raw remote scope strings, lossless for comparison and render-bound on every surface. `Debug`
/// renders through [`render_scope_set`], the same rules the sentences use, so hostile URI-shaped
/// members are never printed verbatim; the raw members are reachable only by deref.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ScopeSet(BTreeSet<String>);

impl ScopeSet {
    pub(crate) fn new(scopes: BTreeSet<String>) -> Self {
        Self(scopes)
    }
}

impl std::ops::Deref for ScopeSet {
    type Target = BTreeSet<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for ScopeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ScopeSet({})", render_scope_set(&self.0))
    }
}

/// Render a scope set for a human. **Never returns any part of a remote scope string**: a scope
/// Photon itself names renders as its label, and everything else contributes only to a count.
pub(crate) fn render_scope_set(scopes: &BTreeSet<String>) -> String {
    if scopes.is_empty() {
        return "none".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut unknown = 0usize;
    for scope in scopes {
        match scope_label(scope) {
            Some(label) => parts.push(label.to_string()),
            None => unknown += 1,
        }
    }
    if unknown > 0 {
        parts.push(format!(
            "{unknown} {UNRECOGNIZED} scope{}",
            if unknown == 1 { "" } else { "s" }
        ));
    }
    parts.join(", ")
}

// The grant: what authorized this credential

/// The provenance of the grant a credential file was minted under: the record that makes "which
/// authority is Photon running with, and is it still the current one" answerable without a
/// network call.
///
/// - `grant_generation` is which consent. The script mints it monotonically
///   (`scripts/gmail_drill_mint.py` `raise_grant_high_water`) so a superseded credential restored
///   over a current one is detectable. Zero is not a generation: the ratchet reads "nothing
///   minted yet" as 0, so a credential claiming 0 would claim to predate every consent, and it is
///   refused at deserialization.
/// - `provider_principal` is which mailbox, as the mint observed it at `users.getProfile`
///   (`emailAddress`). It replaces the credential-relative `me` alias, which `aruna::gmail`'s
///   `resolve_basis` refuses to freeze into a native resource key (BASIS-4/-6). It is
///   provider-supplied data that becomes a URL path segment, so its shape is validated at load,
///   before any URL exists (see [`principal_shape_violation`]).
/// - `effective_scopes` is what was granted. It is a `BTreeSet` because the comparison is an
///   unordered exact set (never a substring, never missing-only) and because it makes this
///   writer's serialized form deterministic: sorted and deduplicated.
///
/// Both writers emit a sorted, deduplicated set (this one through the `BTreeSet`, the mint
/// through `sorted(set(...))` in `main_token_document`), and ingest still canonicalizes whatever
/// any writer emitted, so `["…modify","…modify"]` deserializes to the same one-member set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(try_from = "GrantWire")]
pub(crate) struct GrantProvenance {
    pub(crate) grant_generation: u64,
    pub(crate) provider_principal: String,
    pub(crate) effective_scopes: BTreeSet<String>,
}

/// The on-the-wire shape of [`GrantProvenance`], separate so the generation rule is enforced at
/// deserialization rather than by every reader remembering to check it.
///
/// This derive is also the duplicate-member check, and it holds only if the caller hands it the
/// document's raw member stream. A `serde_json::Value` is a map: building one keeps the last
/// occurrence of a repeated name, so `from_value` here would admit a grant that states an old
/// `grant_generation` and then the current high-water. Every reader of a grant-bearing document
/// therefore parses typed from the bytes: the credential's `grant` through a `RawValue`
/// (`lib.rs`'s `GmailTokenFile`), the ratchet through [`read_grant_high_water`]'s typed-first
/// `RatchetFile`, the drill's bundle through its own `from_slice`. A `Value` in front of any of
/// them silently voids the check.
#[derive(serde::Deserialize)]
struct GrantWire {
    grant_generation: u64,
    provider_principal: String,
    effective_scopes: BTreeSet<String>,
}

impl TryFrom<GrantWire> for GrantProvenance {
    type Error = String;

    fn try_from(wire: GrantWire) -> Result<Self, Self::Error> {
        if wire.grant_generation == 0 {
            // 0 is the ratchet's "absent" reading (`read_grant_high_water` answers 0 for no
            // file), so a credential asserting generation 0 would predate every consent: it can
            // never be latched or superseded. Refuse the value rather than carry a number whose
            // comparisons are all meaningless.
            return Err("grant_generation must be 1 or greater".to_string());
        }
        Ok(Self {
            grant_generation: wire.grant_generation,
            provider_principal: wire.provider_principal,
            effective_scopes: wire.effective_scopes,
        })
    }
}

/// Why a `provider_principal` cannot be used, named by class. The value itself is
/// provider-supplied and never rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrincipalShape {
    Empty,
    NonAscii,
    Whitespace,
    /// Carries one of `/ ? # %`, the characters that decide where a URL points.
    UrlSignificant,
    /// `.` or `..`: the exact dot segments `url`'s `PathSegmentsMut::push` elides rather than
    /// percent-encodes, which shifts the route onto a different resource.
    /// `crates/aruna-gmail/src/transport.rs`'s `validate_path_id` stays as the second check.
    DotSegment,
    /// The reserved `me` alias, ASCII-case-insensitively. It names a credential, not an account,
    /// and freezing it into a basis is what `aruna::gmail`'s `resolve_basis` refuses (BASIS-4/-6).
    /// Google's path-parameter text says nothing about the alias's case sensitivity, so `ME` is
    /// refused as the same class rather than sent to the wire on an undocumented assumption.
    CredentialRelativeAlias,
    /// A byte outside printable ASCII that is neither non-ASCII nor whitespace: a control byte,
    /// `NUL` and `DEL` included.
    ControlByte,
    /// Not a provider-native mailbox. Google documents Gmail's `userId` as "the user's email
    /// address" (or the `me` alias), so a string that is not one would be a stable but
    /// meaningless basis that fails later at the provider instead of here.
    NotAMailbox,
    /// Over the mailbox bound — see [`MAX_PRINCIPAL_BYTES`].
    TooLong,
}

/// RFC 5321 §4.5.3.1.3: "The maximum total length of a reverse-path or forward-path is 256
/// octets (including the punctuation and element separators)". The angle brackets are two of
/// those octets, so the widest mailbox inside a path is 254, which is the bound used here.
/// (RFC 5321 gives 64 octets for a local part and 255 for a domain; 320 is arithmetic on those
/// that no RFC states as a bound.)
pub(crate) const MAX_PRINCIPAL_BYTES: usize = 254;

/// Validate the provider-supplied principal before any URL exists (OWASP ASVS V5 / CWE-20).
/// `None` means usable. The caller renders [`principal_shape_label`], never the value.
///
/// The same rules apply at both writers, here at the app's load path and, ported verbatim, at the
/// mint before it reserves a generation. A rule only the reader enforces would let the writer
/// ratchet past a credential the reader can never admit, bricking the product and burning the
/// rollback path.
///
/// The clauses, in order:
/// 1. non-empty;
/// 2. at most [`MAX_PRINCIPAL_BYTES`];
/// 3. every byte printable ASCII (`0x21..=0x7E`), classified into `NonAscii` / `Whitespace` /
///    `ControlByte` so the operator gets the specific class;
/// 4. none of `/ ? # %`, the characters that decide where a URL points;
/// 5. not the `.`/`..` dot segments `url`'s encoder elides rather than percent-encodes;
/// 6. not the `me` alias, ASCII-case-insensitively;
/// 7. provider-native mailbox shape: exactly one `@`, a non-empty local part, and a non-empty
///    domain that contains a `.` and neither starts nor ends with one. This is a shape check, not
///    RFC 5321's full grammar: Google documents `userId` as an email address, and
///    re-implementing the grammar would refuse legitimate accounts on a rule we invented.
pub(crate) fn principal_shape_violation(principal: &str) -> Option<PrincipalShape> {
    if principal.is_empty() {
        return Some(PrincipalShape::Empty);
    }
    if principal.len() > MAX_PRINCIPAL_BYTES {
        return Some(PrincipalShape::TooLong);
    }
    // Printable ASCII, byte by byte. The three classes stay apart because they are three
    // operator stories (a non-ASCII address, a pasted-in space, a corrupt byte).
    if let Some(b) = principal.bytes().find(|b| !(0x21..=0x7E).contains(b)) {
        return Some(if b >= 0x80 {
            PrincipalShape::NonAscii
        } else if b.is_ascii_whitespace() {
            PrincipalShape::Whitespace
        } else {
            PrincipalShape::ControlByte
        });
    }
    if principal.bytes().any(|b| matches!(b, b'/' | b'?' | b'#' | b'%')) {
        return Some(PrincipalShape::UrlSignificant);
    }
    if principal == "." || principal == ".." {
        return Some(PrincipalShape::DotSegment);
    }
    if principal.eq_ignore_ascii_case("me") {
        return Some(PrincipalShape::CredentialRelativeAlias);
    }
    let mut parts = principal.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        // Zero `@` (`not-an-email`) or two of them: neither is a mailbox.
        return Some(PrincipalShape::NotAMailbox);
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Some(PrincipalShape::NotAMailbox);
    }
    None
}

/// The operator-facing name for a principal refusal: the class, never the value.
pub(crate) fn principal_shape_label(shape: PrincipalShape) -> &'static str {
    match shape {
        PrincipalShape::Empty => "it is empty",
        PrincipalShape::NonAscii => "it carries a non-ASCII byte",
        PrincipalShape::Whitespace => "it carries whitespace",
        PrincipalShape::UrlSignificant => {
            "it carries a URL-significant character (one of / ? # %)"
        }
        PrincipalShape::DotSegment => "it is a bare dot segment",
        PrincipalShape::CredentialRelativeAlias => {
            "it is the reserved alias that names a credential rather than an account"
        }
        PrincipalShape::ControlByte => "it carries a control byte",
        PrincipalShape::NotAMailbox => {
            "it is not a mailbox address (the provider names accounts by email address)"
        }
        PrincipalShape::TooLong => {
            "it is longer than a mailbox address can be (RFC 5321 §4.5.3.1.3: a 256-octet path, \
             so 254 bytes inside the angle brackets)"
        }
    }
}

/// The grant ratchet: `{"grant_generation": u64}`, one integer, beside the credential it guards.
pub(crate) const GRANT_HIGH_WATER_FILE_NAME: &str = "grant_high_water.json";

/// Which shape the ratchet file failed on. "Could not read it" and "it says zero" are different
/// facts and only one is safe; see [`admit_grant_generation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantHighWaterShape {
    Unreadable(std::io::ErrorKind),
    NotJson,
    NotAnObject,
    GenerationAbsent,
    /// Present but not a non-negative integer (a string, a float, `null`, a negative).
    GenerationNotAnUnsignedInteger,
    /// The object repeats a member name, or carries a member the shared schema has no field for.
    /// A JSON object is a list of name/value pairs on the wire, and the two readers of this
    /// shared file once resolved a repeat differently: CPython's `json` and `serde_json::Value`
    /// both keep the last pair, so `{"grant_generation": -0, "grant_generation": 2}` collapsed to
    /// 2 and the illegal `-0` was discarded with its pair. Both readers now refuse the wire form
    /// instead of resolving it (the mint's `canonical_ratchet_object`; this reader's typed parse).
    DuplicateOrUnknownMember,
}

fn grant_high_water_label(shape: GrantHighWaterShape) -> String {
    match shape {
        GrantHighWaterShape::Unreadable(kind) => format!("it could not be read ({kind:?})"),
        GrantHighWaterShape::NotJson => "it is not valid JSON".to_string(),
        GrantHighWaterShape::NotAnObject => "its top level is not a JSON object".to_string(),
        GrantHighWaterShape::GenerationAbsent => "it declares no grant_generation".to_string(),
        GrantHighWaterShape::GenerationNotAnUnsignedInteger => {
            "its grant_generation is not a non-negative integer".to_string()
        }
        GrantHighWaterShape::DuplicateOrUnknownMember => {
            "it repeats a member name or carries a member the shared schema has no field for"
                .to_string()
        }
    }
}

/// The ratchet's address for a secrets dir.
pub(crate) fn grant_high_water_path(secrets_dir: &Path) -> PathBuf {
    secrets_dir.join(GRANT_HIGH_WATER_FILE_NAME)
}

/// The one member the ratchet's shared schema has (`scripts/gmail_drill_mint.py`'s
/// `GRANT_GENERATION_MEMBER` is its counterpart).
const GRANT_GENERATION_MEMBER: &str = "grant_generation";

/// The ratchet's typed shape, the single accept/refuse authority for [`read_grant_high_water`].
///
/// `deny_unknown_fields` matters twice: it refuses a member the shared schema has no field for,
/// and serde's derive independently refuses a repeated field, which the `serde_json::Value` map
/// could not do because it resolves a repeat last-wins. `u64` closes the rest by type: a
/// negative, a `-0` (an f64 to serde_json), a float, an exponent, a string, a `null` and anything
/// past the u64 ceiling all fail the field and never round to zero.
///
/// Warning: serde issue #2416. Adding a `#[serde(flatten)]` field, or otherwise routing this
/// struct through serde's map-collecting path, disables `deny_unknown_fields` and with it the
/// derive's duplicate-field refusal, with no compile error. The same holds for any future member
/// that must be buffered rather than matched by name. Nothing here prevents that edit; what
/// catches it is the committed differential corpus (`src/ratchet_parity_differential.rs` against
/// `tests/fixtures/ratchet-parity-corpus.json`), which replays the repeated-member and
/// unknown-member bytes through both readers and fails on divergence.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RatchetFile {
    grant_generation: u64,
}

/// The member names of a JSON object in wire order, repeats included.
///
/// It decides nothing ([`RatchetFile`] accepts or refuses). It exists so a refusal can name which
/// shape class it is (a repeat, a member outside the schema, no member at all, a member that is
/// not a `u64`) instead of collapsing four operator-facing facts into one label, and so those
/// classes line up with the mint's (`canonical_ratchet_object`).
struct RatchetMemberNames(Vec<String>);

impl<'de> Deserialize<'de> for RatchetMemberNames {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Names;
        impl<'de> serde::de::Visitor<'de> for Names {
            type Value = Vec<String>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut names = Vec::new();
                // `next_entry` walks the pairs as they appear; nothing collapses them.
                while let Some((name, _)) = map.next_entry::<String, serde::de::IgnoredAny>()? {
                    names.push(name);
                }
                Ok(names)
            }
        }
        deserializer.deserialize_map(Names).map(RatchetMemberNames)
    }
}

/// Read the ratchet. `Ok(None)` is absence, a real state (before the first mint), not a failure.
///
/// Read-only and lock-free by contract: it writes nothing, so it takes no `&CredentialLock`
/// (the lock requirement constrains writes). The read-only callers are:
///
/// * `credential_cell::CredentialCoordinator::grant_still_admitted`: the wave's pre-spend check
///   on the credential it just loaded under the lock, i.e. the refresh path;
/// * the status surface's single read, `GrantOnDisk`, which answers both the expired branch's
///   plausible-usability gate and the live branch's consult from one read of this file.
///
/// There is no admission-exit caller: that gate was reverted (see
/// `CredentialCoordinator::admit`). A retired generation refuses at load / construction, refresh
/// and send admission, and a live read arm is re-validated at the next reconcile or at expiry.
///
/// The command-side callers refuse on a shape error rather than treat an unusable ratchet as
/// absent. The status read suppresses nothing on an unusable ratchet and does not go silent
/// either: `GrantOnDisk::verdict` renders `Cure::Undetermined` with this function's shape label,
/// so the bar never reads `configured: true, cure: none` while the command surface refuses.
pub(crate) fn read_grant_high_water(path: &Path) -> Result<Option<u64>, GrantHighWaterShape> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(GrantHighWaterShape::Unreadable(e.kind())),
    };
    // The typed parse is the one authority. It refuses a repeated field, a member outside the
    // schema, and every spelling that is not a `u64`, including `-0`, which serde_json parses as
    // an f64. Nothing below this line can admit a file it refused; it only decides which shape
    // label the refusal carries.
    if let Ok(file) = serde_json::from_slice::<RatchetFile>(&bytes) {
        return Ok(Some(file.grant_generation));
    }
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Err(GrantHighWaterShape::NotJson);
    };
    if !value.is_object() {
        return Err(GrantHighWaterShape::NotAnObject);
    }
    // The pairs in wire order: `Value`'s map has already collapsed a repeat by the time it is
    // built, so the names are read again from the same bytes rather than from the map.
    let names = serde_json::from_slice::<RatchetMemberNames>(&bytes)
        .map(|n| n.0)
        .map_err(|_| GrantHighWaterShape::NotAnObject)?;
    let mut seen = BTreeSet::new();
    if names.iter().any(|name| !seen.insert(name.as_str()))
        || names.iter().any(|name| name != GRANT_GENERATION_MEMBER)
    {
        return Err(GrantHighWaterShape::DuplicateOrUnknownMember);
    }
    if names.is_empty() {
        return Err(GrantHighWaterShape::GenerationAbsent);
    }
    // Exactly one `grant_generation` member and the typed parse still refused it: the value is not
    // a non-negative integer the u64 field can hold, never zero and never absent.
    Err(GrantHighWaterShape::GenerationNotAnUnsignedInteger)
}

/// Admit a credential's grant generation against the ratchet, and latch. It is called before any
/// transport or connector is constructed, so a retired grant never reaches a socket.
///
/// * `credential < high_water`: [`RefreshLocalError::GrantRetired`] (cure: re-mint). This is the
///   rollback case, a backup/sync/restore agent putting a pre-re-consent credential back.
/// * `credential > high_water`, or the ratchet is absent: raise it, by atomic replace.
/// * `credential == high_water`: nothing to raise, so nothing is written.
/// * the ratchet is unreadable, unparsable, not an object or not a non-negative integer: refuse.
///   Never latch low. Treating an unusable ratchet as absent would let one corrupted byte
///   re-admit every retired generation.
/// * the raise cannot be written: refuse. Failing closed matters because admitting a generation
///   the ratchet does not record would leave the credential it supersedes admissible forever.
///
/// The credential lock linearizes this, and `held` is its proof. Atomic replacement prevents torn
/// bytes but is not a compare-and-swap, so a bare read-compare-replace can be overtaken (two
/// raisers from high-water 9 both returned `Ok` and left the durable ratchet at 10, after which
/// the retired generation 10 was admissible again). The fix is the cross-process credential lock
/// this module owns and the mint also takes (`gmail_drill_mint.py`'s `credential.lock`): every
/// read-compare-replace of the ratchet happens while it is held. The `held: &CredentialLock`
/// parameter enforces that, and the boot path (`build_gmail_provider`) acquires it around
/// `build_gmail_arm` for this reason.
///
/// The proof is also scoped to this directory. A handle has no identity, so the type alone would
/// show that some credential lock is held, not that it guards the directory whose ratchet is
/// about to be read and replaced. The lock records the directory it guards (the lock path's own
/// parent, as spelled; see [`CredentialLock::guards`], a path comparison and nothing more), and
/// an admission proven by another directory's lock refuses and writes nothing. The mint runs the
/// same check over its reservation (`gmail_drill_mint.py`'s `main_token_document`) but normalizes
/// paths first, while this side compares them as spelled. Both refuse a reservation or lock for a
/// different directory, which is the fail-closed property that matters; they differ only in which
/// spellings of one directory each calls equal (the mint accepts a relative path or `..`
/// segment that resolves to the guarded directory; this side does not, and neither resolves a
/// symlink). They are left unaligned because no caller in either program can reach the
/// difference: each derives both halves from a single field.
///
/// A mismatch is a programming error: no untrusted data reaches this parameter, only first-party
/// code passing the wrong handle, so the refusal is hygiene and not a control. Its cure is
/// `Undetermined`, since nothing the operator does repairs a caller.
///
/// The other half of the protocol is at the mint: it reserves the generation (raises the ratchet
/// to N+1 under this same lock) before it writes the credential carrying N+1, so a crash between
/// the two leaves a retired credential and an explicit re-consent instead of two different
/// consents sharing one generation.
///
/// The ratchet is an ordinary file: the user, or code running as them, can delete it and it
/// resets. It is tamper-evident against a restore agent, not a control against the operator's
/// own hands.
pub(crate) fn admit_grant_generation(
    secrets_dir: &Path,
    grant: &GrantProvenance,
    held: &CredentialLock,
) -> Result<(), RefreshLocalError> {
    // The lock is a proof parameter, and the proof is scoped: the type makes "a lock is held"
    // compile-checked, and this question makes it "the lock for this directory". It is asked
    // first, before the ratchet is read or could be raised, so an unproven admission touches
    // nothing.
    if !held.guards(secrets_dir) {
        return Err(RefreshLocalError::AdmissionLockMismatch {
            held: held.guards.clone(),
            secrets_dir: secrets_dir.to_path_buf(),
        });
    }
    let path = grant_high_water_path(secrets_dir);
    let recorded = read_grant_high_water(&path).map_err(|shape| {
        RefreshLocalError::GrantHighWaterUnusable {
            path: path.clone(),
            shape,
        }
    })?;
    let credential_generation = grant.grant_generation;
    if let Some(high_water) = recorded {
        if credential_generation < high_water {
            return Err(RefreshLocalError::GrantRetired {
                path: path.clone(),
                credential_generation,
                high_water,
            });
        }
        if credential_generation == high_water {
            // Max-only means there is nothing to do here, and that is load-bearing: a rewrite
            // would be a write on every admission.
            return Ok(());
        }
    }
    write_grant_high_water(&path, credential_generation)
}

/// Raise the ratchet by atomic replace, with the same `atomic-write-file` discipline (and Unix
/// mode narrowing) as the credential writer, so the two files cannot drift into two durability
/// stories.
///
/// Atomic replace prevents a torn file but is not monotonic: on its own it would write a lower
/// value. Monotonicity comes from its one caller, [`admit_grant_generation`], which reads,
/// compares and replaces while holding the cross-process credential lock. Nothing in this
/// function enforces that; the caller's `held: &CredentialLock` parameter does.
fn write_grant_high_water(path: &Path, generation: u64) -> Result<(), RefreshLocalError> {
    let mut bytes = serde_json::to_vec(&serde_json::json!({ "grant_generation": generation }))
        .expect("a one-field object always serializes");
    bytes.push(b'\n');

    let refuse = |kind: std::io::ErrorKind| RefreshLocalError::GrantHighWaterWriteFailed {
        path: path.to_path_buf(),
        reason: LocalIoReason(kind),
    };

    #[allow(unused_mut)]
    let mut options = atomic_write_file::AtomicWriteFile::options();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        options.preserve_mode(false);
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| refuse(e.kind()))?;
    file.write_all(&bytes).map_err(|e| refuse(e.kind()))?;
    file.commit().map_err(|e| refuse(e.kind()))?;
    Ok(())
}

// The outcome model

/// The named cure a refusal carries onto the wire, serialized `snake_case` (the frontend
/// contract): `re_mint | client_config | admin_policy | retry_later | undetermined`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cure {
    /// Re-mint via `scripts/gmail_drill_mint.py` (a re-auth session in this app).
    ReMint,
    /// The OAuth client / console entry is wrong; only its developer can fix it.
    ClientConfig,
    /// An account or organization policy refused the credential; neither retry nor re-mint cures
    /// it. The name is actor-neutral (org_internal's documented remedy is account switching, not
    /// necessarily an administrator's act), and the refusal reason names the policy.
    AdminPolicy,
    /// Photon retries on the next command, under the pacing floor.
    RetryLater,
    /// Undetermined: the provider refused in a way we do not map.
    Undetermined,
}

/// Which clause of the success contract a response violated. It names the clause, never the
/// content, so a violation is describable without quoting the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContractViolation {
    /// Over [`MAX_REFRESH_BODY_BYTES`].
    BodyTooLarge,
    /// Not a JSON object.
    BodyNotAnObject,
    /// A member name occurs more than once. Refused as ambiguous: RFC 8259 §4 leaves duplicate
    /// names reader-defined (names SHOULD be unique; §8.3 names the interop hazard), so a repeat's
    /// meaning depends on which conformant parser reads it. RFC 6749 §3.2's "MUST NOT be included
    /// more than once" covers the parameters that RFC defines (verified erratum 5708 scopes the
    /// MUST NOT to those). The refusal is the complement: any repeated name, accepting the cost
    /// that a conformant repeated extension member is refused. `serde_json::Value` would
    /// otherwise collapse it last-wins, and the wire order of two `scope` members would decide
    /// admission.
    BodyRepeatsMember,
    /// `access_token` absent, non-string, or blank.
    AccessTokenMissingOrBlank,
    /// `access_token` carries a byte outside visible ASCII. Its one consumer is the
    /// `Authorization: Bearer` header, and reqwest refuses such a value after the credential is
    /// persisted and published live, which would wedge until near expiry.
    AccessTokenNotHeaderSafe,
    /// `access_token` is visible ASCII but outside RFC 6750 §2.1's Bearer credential grammar
    /// (`ya29!…` and `ya29:BAD` were once accepted):
    /// `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/") *"="`. reqwest can
    /// build the header, but the credential is not syntactically a Bearer token. This is a
    /// different fact from header-safety, so it is a different violation.
    AccessTokenNotBearerGrammar,
    /// `expires_in` absent.
    ExpiresInAbsent,
    /// `expires_in` present but not an integer.
    ExpiresInNotAnInteger,
    /// `expires_in` present, integral, and <= 0.
    ExpiresInNonPositive,
    /// `expires_in` integral and positive but `now + expires_in` does not fit i64 (the 2^200
    /// shape), refused by checked arithmetic rather than wrapped into an invented expiry.
    ExpiresInUnrepresentable,
    /// `token_type` absent.
    TokenTypeAbsent,
    /// `token_type` present and not case-insensitively `Bearer`.
    TokenTypeNotBearer,
    /// `refresh_token` present but not a string.
    RefreshTokenNotAString,
    /// `scope` present but malformed per RFC 6749 §3.3's ABNF: empty, whitespace-only, or with an
    /// empty/whitespace member. Malformed is decided before the authority comparison.
    ScopeMalformed,
    /// A status that is neither 200 nor a classifiable denial (a 3xx survives `redirect::none`).
    StatusUnexpected,
}

/// The transient family: retryable under the pacing floor, never latched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransientKind {
    /// The request never produced a response we could read.
    Network,
    /// HTTP 5xx.
    ServerError(u16),
    /// HTTP 429, classified before the generic-4xx rule (RFC 6585 §4).
    RateLimited(u16),
    /// A known transient code at any status (`rate_limit_exceeded` arrives at 403).
    ProviderTransient(Sanitized),
    /// The response broke the typed contract.
    ContractViolation(ContractViolation),
}

/// Did the provider state the granted scope, or omit it?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopeConfirmation {
    /// `scope` was present and exactly equalled the stored grant.
    StatedAndMatched,
    /// `scope` was absent. RFC 6749 §5.1's identical-grant rule makes the omission mean the
    /// original grant, i.e. the stored one: accepted, and the stored grant stands.
    AbsentIdenticalGrant,
}

/// The typed, lossless result of one refresh attempt. The discriminant travels to the credential
/// cell, the surface error and the frontend, so a waiter reproduces the same cure rather than a
/// genericized kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    /// The exchange succeeded and every clause of the success contract held.
    Renewed {
        access_token: SecretString,
        /// RFC 6749 §6 rotation: the replacement when the server sent one, otherwise the original
        /// (`scripts/gmail_drill_mint.py` (`surviving_refresh_token`)).
        refresh_survivor: SecretString,
        expires_at: i64,
        scope_confirmed: ScopeConfirmation,
    },
    /// Terminal. The grant's authority is not this lane's exact set.
    AuthorityMismatch {
        /// Raw scope strings, stored losslessly and never rendered directly: rendering goes
        /// through [`render_scope_set`] on every surface including `Debug` ([`ScopeSet`]).
        missing: ScopeSet,
        unexpected: ScopeSet,
    },
    /// Terminal. `invalid_grant` only. The sentence says reauthorization is required, not that
    /// the refresh token is proven dead, which the provider's response does not establish.
    ReauthRequired { subtype: Option<Sanitized> },
    /// Terminal. The credential file carries no refresh token at all: a local fact, not a
    /// provider verdict, so it has its own variant and sentence. Cure `re_mint`.
    MissingRefreshToken,
    /// Terminal. The app's OAuth client entry is wrong; only its developer can fix it.
    ClientConfig { code: Sanitized },
    /// Terminal. Account/administrator policy, for codes established at this endpoint by named
    /// vendor evidence only.
    ProviderPolicy { code: Sanitized },
    /// Terminal. The provider evidence does not establish that a re-mint cures it, so the
    /// sentence asserts no cure beyond developer/console review.
    InvalidScope,
    /// Undetermined: an unmapped non-429 4xx. Lossless: the sanitized unknown code, or its
    /// explicit absence, travels with the outcome. Retries are command-driven under the floor and
    /// never latched to the file generation.
    UnknownDenied {
        status: u16,
        code: Option<Sanitized>,
    },
    /// Retryable under the pacing floor.
    Transient { kind: TransientKind },
}

impl RefreshOutcome {
    /// The "file carries no refresh token" outcome (the legacy-file case). It is its own variant
    /// rather than `ReauthRequired { subtype: None }` because the two need different sentences.
    pub(crate) fn no_refresh_token() -> Self {
        Self::MissingRefreshToken
    }

    /// The cure discriminant this outcome carries onto the wire.
    ///
    /// `Renewed` owes no cure, but the type has no "none" member, so it answers
    /// [`Cure::Undetermined`]. Callers that put a cure on the wire must use the test-only
    /// `cure_owed` instead of branching after the fact.
    pub(crate) fn cure(&self) -> Cure {
        match self {
            Self::Renewed { .. } => Cure::Undetermined,
            Self::AuthorityMismatch { .. }
            | Self::ReauthRequired { .. }
            | Self::MissingRefreshToken => Cure::ReMint,
            Self::ClientConfig { .. } | Self::InvalidScope => Cure::ClientConfig,
            Self::ProviderPolicy { .. } => Cure::AdminPolicy,
            Self::UnknownDenied { .. } => Cure::Undetermined,
            Self::Transient { .. } => Cure::RetryLater,
        }
    }

    /// The cure, or `None` when none is owed: the form for `SessionStatus.credential_cure`.
    #[cfg(test)]
    pub(crate) fn cure_owed(&self) -> Option<Cure> {
        match self {
            Self::Renewed { .. } => None,
            other => Some(other.cure()),
        }
    }

    /// Does this outcome latch to the file generation?
    ///
    /// A latch released by the token file's generation may hold only outcomes whose cure rewrites
    /// that file, the re-mint family. `ClientConfig` / `ProviderPolicy` / `InvalidScope` are cured
    /// in client_secret.json, the Cloud console or administrator policy, none of which a
    /// token-file digest observes, so a file-keyed latch would replay the stale refusal forever
    /// after the operator applies the cure. They pace under the floor instead (one re-probe per
    /// command outside 30 s), as `UnknownDenied` and `Transient` do.
    pub(crate) fn latches(&self) -> bool {
        matches!(
            self,
            Self::AuthorityMismatch { .. }
                | Self::ReauthRequired { .. }
                | Self::MissingRefreshToken
        )
    }

    /// The one sentence this outcome produces. The construction-time reason and the command-time
    /// refusal both quote it so they cannot drift into two explanations of one fact. It never
    /// asserts a cure the provider's response did not establish.
    pub(crate) fn reason_sentence(&self) -> String {
        match self {
            Self::Renewed { expires_at, .. } => {
                format!("the Gmail credential was renewed; it expires at {expires_at} (unix seconds)")
            }
            Self::AuthorityMismatch {
                missing,
                unexpected,
            } => format!(
                "the provider returned a grant whose authority is not the one on record — \
                 missing: {}; unexpected: {}. Re-mint via scripts/gmail_drill_mint.py to consent \
                 again with the authority Photon runs under.",
                render_scope_set(missing),
                render_scope_set(unexpected)
            ),
            // RFC 6749 folds a grant bound to another client, and Google's session-control case
            // (`invalid_rapt`), under `invalid_grant`, so the response does not establish that the
            // refresh token is dead. What it does establish is that reauthorization is required,
            // and the wording says only that.
            Self::ReauthRequired { subtype } => {
                let named = match subtype {
                    Some(s) => format!("invalid_grant, subtype {s}"),
                    None => "invalid_grant".to_string(),
                };
                format!(
                    "the provider refused the refresh token ({named}); reauthorization is \
                     required — re-mint via scripts/gmail_drill_mint.py, which runs a fresh \
                     consent session."
                )
            }
            Self::MissingRefreshToken => "the Gmail credential file carries no refresh token, so \
                 Photon has nothing to renew it with — re-mint via scripts/gmail_drill_mint.py."
                .to_string(),
            Self::ClientConfig { code } => format!(
                "the provider refused this app's OAuth client configuration ({code}); the \
                 client_secret.json entry and its Google Cloud console client must be corrected — \
                 re-minting the same client cannot cure it."
            ),
            // org_internal names what is restricted without overclaiming who fixes it: the fixing
            // actor (the consenting account's org membership vs the app's audience configuration)
            // is not established by the response.
            Self::ProviderPolicy { code } if code.to_string() == "org_internal" => {
                "the OAuth client is restricted to an organization this grant's account is \
                 not in (org_internal); retrying will not change it — consent with an account \
                 inside that organization, or the app's audience configuration must change."
                    .to_string()
            }
            Self::ProviderPolicy { code } => format!(
                "the provider refused under account or administrator policy ({code}); an \
                 administrator must grant this app access — neither a retry nor a re-mint cures it."
            ),
            Self::InvalidScope => "the provider refused the credential's scope configuration \
                 (invalid_scope); developer/console review is required. What cures it is not \
                 established by the provider's response, so nothing further is asserted."
                .to_string(),
            Self::UnknownDenied { status, code } => {
                let named = match code {
                    Some(c) => format!("error code {c}"),
                    None => "no error code".to_string(),
                };
                format!(
                    "the provider refused with HTTP {status} and {named}; paced — no credential \
                     was renewed and nothing was written. A 4xx proves the endpoint was reached \
                     — if it persists, review the provider response, not the network."
                )
            }
            Self::Transient { kind } => transient_sentence(kind),
        }
    }
}

fn transient_sentence(kind: &TransientKind) -> String {
    let detail = match kind {
        TransientKind::Network => {
            "the token endpoint could not be reached (network failure)".to_string()
        }
        TransientKind::ServerError(status) => {
            format!("the token endpoint returned HTTP {status}")
        }
        TransientKind::RateLimited(status) => {
            format!("the token endpoint rate-limited this app (HTTP {status})")
        }
        TransientKind::ProviderTransient(code) => {
            format!("the token endpoint reported a transient condition ({code})")
        }
        TransientKind::ContractViolation(what) => format!(
            "the token endpoint's response broke the response contract ({})",
            contract_violation_label(*what)
        ),
    };
    format!("{detail}; paced — no credential was renewed and nothing was written.")
}

pub(crate) fn contract_violation_label(what: ContractViolation) -> &'static str {
    match what {
        ContractViolation::BodyTooLarge => "response body over the 64 KiB bound",
        ContractViolation::BodyNotAnObject => "response body is not a JSON object",
        ContractViolation::BodyRepeatsMember => {
            "response body repeats a member name — refused as ambiguous (RFC 8259 §4; RFC 6749 §3.2 for the parameters it defines)"
        }
        ContractViolation::AccessTokenMissingOrBlank => "no usable access_token",
        ContractViolation::AccessTokenNotHeaderSafe => {
            "access_token is not header-safe (a byte outside visible ASCII)"
        }
        ContractViolation::AccessTokenNotBearerGrammar => {
            "access_token is outside the Bearer credential grammar (RFC 6750 b64token)"
        }
        ContractViolation::ExpiresInAbsent => "no expires_in",
        ContractViolation::ExpiresInNotAnInteger => "expires_in is not an integer",
        ContractViolation::ExpiresInNonPositive => "expires_in is not positive",
        ContractViolation::ExpiresInUnrepresentable => {
            "expires_in does not fit a representable expiry"
        }
        ContractViolation::TokenTypeAbsent => "no token_type",
        ContractViolation::TokenTypeNotBearer => "token_type is not Bearer",
        ContractViolation::RefreshTokenNotAString => "refresh_token is not a string",
        ContractViolation::ScopeMalformed => "scope member is malformed per RFC 6749 §3.3",
        ContractViolation::StatusUnexpected => "an unexpected HTTP status",
    }
}

// parse_refresh_response

/// Classify one token-endpoint response. `status` and `body` are wholly attacker-controlled data.
///
/// `body` must already be within [`MAX_REFRESH_BODY_BYTES`]: the client enforces the cap on the
/// wire, and anything larger arriving here is itself a contract violation.
///
/// Classification is by error code plus status, never status alone.
///
/// `stored_scopes` is the stored grant's scope set, the reference for the exact-set authority
/// comparison. RFC 6749 §6 binds a refresh to what was originally granted and §5.1 makes an
/// omitted `scope` equal to that grant, so the reference is the record, never
/// [`REQUIRED_SCOPES`] (which answers the load path's different question).
pub(crate) fn parse_refresh_response(
    status: u16,
    body: &[u8],
    now_unix: i64,
    original_refresh_token: &str,
    stored_scopes: &BTreeSet<String>,
) -> RefreshOutcome {
    // The bound is checked before anything looks at the bytes: a body over the cap is a contract
    // violation in its own right, named as such, never a parse failure we then guess about.
    if body.len() > MAX_REFRESH_BODY_BYTES {
        return violation(ContractViolation::BodyTooLarge);
    }
    if status == 200 {
        parse_success(body, now_unix, original_refresh_token, stored_scopes)
    } else {
        classify_error(status, body)
    }
}

fn violation(what: ContractViolation) -> RefreshOutcome {
    RefreshOutcome::Transient {
        kind: TransientKind::ContractViolation(what),
    }
}

/// RFC 6750 §2.1: `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/") *"="`. The
/// padding `=` may only trail, and the core must be non-empty.
///
/// Applied at the body position this is deliberate strictness beyond RFC 6749 App. A.12's
/// `access-token = 1*VSCHAR` (which would admit `:`/`!`/`,`): house policy, one credential shape
/// from the response to the header. Every real Google token conforms, and the liveness cost of
/// refusing a conformant-but-odd token is a known non-goal.
fn bearer_b64token(t: &str) -> bool {
    let core = t.trim_end_matches('=');
    !core.is_empty()
        && core
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/'))
}

/// The token-shape half of the success contract, shared with the ingress boundary the app owns
/// (a `ya29:BAD` token once passed the mint into a durable credential the refresh path refuses;
/// the loader closes that drift for every writer). The returned violation names the clause, and
/// [`contract_violation_label`] renders it without bytes.
pub(crate) fn access_token_shape_violation(t: &str) -> Option<ContractViolation> {
    if t.chars().any(|c| !matches!(c, '\x21'..='\x7E')) {
        return Some(ContractViolation::AccessTokenNotHeaderSafe);
    }
    if !bearer_b64token(t) {
        return Some(ContractViolation::AccessTokenNotBearerGrammar);
    }
    None
}

/// One strict reader for the token endpoint's response body, used by both `parse_success` and
/// `classify_error`, so every decision derives from one reader per document. A repeated member
/// name is refused as ambiguous (RFC 8259 §4 leaves duplicates reader-defined, §8.3 notes the
/// interop hazard, and RFC 6749 §3.2's MUST NOT covers the parameters that RFC defines, per
/// verified erratum 5708). The rule is the complement, "refuse a body that repeats any member
/// name", not an enumeration of the names this code happens to read; over-refusing a conformant
/// repeated extension member is the accepted cost. Unknown members are still tolerated once each
/// (§5.1's extension rule): the refusal is on repetition, not vocabulary.
///
/// The check covers top-level member names. No decision here reads inside a nested object (every
/// consulted member is a string or a number), so a repeat under an unknown nested member is
/// unconsulted, not laundered. The Python reader (`read_bounded_json`) refuses repeats at every
/// depth, which only differs on content neither side consults.
///
/// `crates/aruna-jmap/src/transport.rs`'s `wire_member_names_are_unique` uses the same mechanism
/// (a serde `DeserializeSeed`/`MapAccess` walk refusing a repeat with a custom-token error). It
/// is crate-private and scopes its refusal by a JMAP name set, where this takes the top-level
/// complement, so the technique is reused rather than the code.
struct UniqueMembers(serde_json::Map<String, Value>);

impl<'de> serde::Deserialize<'de> for UniqueMembers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = UniqueMembers;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object whose member names are unique")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut members = serde_json::Map::new();
                // The key is checked before the value is deserialized. Pulling both with
                // `next_entry` made a repeat whose second value was malformed (`1e999`) fail as a
                // value error and classify as NotAnObject instead of RepeatsMember. The repeated
                // name decides, in both orders.
                while let Some(name) = map.next_key::<String>()? {
                    if members.contains_key(&name) {
                        // The name is a member name, never a value; nothing secret is here.
                        return Err(serde::de::Error::custom("repeated member name"));
                    }
                    let value = map.next_value::<Value>()?;
                    members.insert(name, value);
                }
                Ok(UniqueMembers(members))
            }
        }
        deserializer.deserialize_map(V)
    }
}

/// The body-shape classification, shared by both branches.
enum TokenResponseBody {
    Object(serde_json::Map<String, Value>),
    NotAnObject,
    RepeatsMember,
}

fn token_response_members(body: &[u8]) -> TokenResponseBody {
    match serde_json::from_slice::<UniqueMembers>(body) {
        Ok(UniqueMembers(map)) => TokenResponseBody::Object(map),
        Err(e) if e.is_data() && e.to_string().starts_with("repeated member name") => {
            TokenResponseBody::RepeatsMember
        }
        Err(_) => TokenResponseBody::NotAnObject,
    }
}

fn parse_success(
    body: &[u8],
    now_unix: i64,
    original_refresh_token: &str,
    stored_scopes: &BTreeSet<String>,
) -> RefreshOutcome {
    let map = match token_response_members(body) {
        TokenResponseBody::Object(map) => map,
        TokenResponseBody::RepeatsMember => return violation(ContractViolation::BodyRepeatsMember),
        TokenResponseBody::NotAnObject => return violation(ContractViolation::BodyNotAnObject),
    };

    // 1. access_token: present, a string, non-blank, header-safe (visible ASCII, 0x21-0x7E, which
    // is what reqwest enforces at header construction) and inside the Bearer grammar (RFC 6750
    // §2.1, which makes it syntactically a Bearer token at all). These are two facts and two
    // violations, and either one is a broken contract (transient scrutiny), not a credential.
    let access_token = match map.get("access_token").and_then(Value::as_str) {
        Some(t) if !t.trim().is_empty() => {
            // One shape source for both ingress boundaries: this path and the loader call the
            // same predicate, so they cannot drift apart.
            if let Some(what) = access_token_shape_violation(t) {
                return violation(what);
            }
            SecretString::new(t)
        }
        _ => return violation(ContractViolation::AccessTokenMissingOrBlank),
    };

    // 2. expires_in: attested, never invented, checked.
    let expires_at = match attested_expiry(map.get("expires_in"), now_unix) {
        Ok(at) => at,
        Err(what) => return violation(what),
    };

    // 3. token_type: present and case-insensitively Bearer (RFC 6749 §5.1). Absent and non-Bearer
    // are different facts, so they are different violations.
    match map.get("token_type") {
        None => return violation(ContractViolation::TokenTypeAbsent),
        Some(v) => match v.as_str() {
            Some(t) if t.eq_ignore_ascii_case("Bearer") => {}
            _ => return violation(ContractViolation::TokenTypeNotBearer),
        },
    }

    // 4. refresh_token: optional; the survivor rule.
    let refresh_survivor = match surviving_refresh_token(map.get("refresh_token"), original_refresh_token) {
        Ok(s) => s,
        Err(what) => return violation(what),
    };

    // 5. scope: malformed is decided first, then the exact-set authority comparison.
    let scope_confirmed = match map.get("scope") {
        None => ScopeConfirmation::AbsentIdenticalGrant,
        Some(raw) => {
            let Some(raw) = raw.as_str() else {
                return violation(ContractViolation::ScopeMalformed);
            };
            let granted = match scope_members(raw) {
                Ok(set) => set,
                Err(what) => return violation(what),
            };
            if let Some(mismatch) = authority_mismatch(&granted, stored_scopes) {
                return mismatch;
            }
            ScopeConfirmation::StatedAndMatched
        }
    };

    RefreshOutcome::Renewed {
        access_token,
        refresh_survivor,
        expires_at,
        scope_confirmed,
    }
}

/// `now + expires_in`, attested and checked (`scripts/gmail_drill_mint.py` `attested_expiry`,
/// plus the representability bound for a `2**200` input). A fabricated default would let an
/// already-dead token be called live.
fn attested_expiry(raw: Option<&Value>, now_unix: i64) -> Result<i64, ContractViolation> {
    let Some(raw) = raw else {
        return Err(ContractViolation::ExpiresInAbsent);
    };
    let Value::Number(n) = raw else {
        return Err(ContractViolation::ExpiresInNotAnInteger);
    };
    let lifetime = if let Some(i) = n.as_i64() {
        i
    } else if n.as_u64().is_some() {
        // Integral, positive, and past i64::MAX.
        return Err(ContractViolation::ExpiresInUnrepresentable);
    } else {
        // serde_json parks an integer literal too large for u64/i64 as an f64, which is also where
        // a genuinely fractional value lands, and where a float-spelled representable value lands
        // ("3600.0", "3.6e3"). Fractional or float-spelled-but-representable gives
        // not-an-integer (RFC 6749 App. A.14: `expires-in = 1*DIGIT`); integral past i64 gives
        // unrepresentable.
        let f = n.as_f64().ok_or(ContractViolation::ExpiresInNotAnInteger)?;
        if !f.is_finite() || f.fract() != 0.0 {
            return Err(ContractViolation::ExpiresInNotAnInteger);
        }
        if f <= 0.0 {
            return Err(ContractViolation::ExpiresInNonPositive);
        }
        if f > i64::MAX as f64 {
            // The `2**200` shape: integral, positive, past any representable expiry.
            return Err(ContractViolation::ExpiresInUnrepresentable);
        }
        return Err(ContractViolation::ExpiresInNotAnInteger);
    };
    if lifetime <= 0 {
        return Err(ContractViolation::ExpiresInNonPositive);
    }
    now_unix
        .checked_add(lifetime)
        .ok_or(ContractViolation::ExpiresInUnrepresentable)
}

/// Which refresh token must be persisted (`scripts/gmail_drill_mint.py` `surviving_refresh_token`):
/// the returned replacement when the server sent a non-blank one, otherwise the original.
/// Persisting a rotated-away token would park a dead credential while reporting success.
fn surviving_refresh_token(
    raw: Option<&Value>,
    original: &str,
) -> Result<SecretString, ContractViolation> {
    match raw {
        None => Ok(SecretString::new(original)),
        Some(v) => {
            let Some(replacement) = v.as_str() else {
                return Err(ContractViolation::RefreshTokenNotAString);
            };
            let replacement = SecretString::new(replacement);
            if replacement.is_blank() {
                // A present-but-blank replacement is not a rotation. Keeping the original is what
                // the mint script does, and it is the arm that does not lose a working token.
                return Ok(SecretString::new(original));
            }
            Ok(replacement)
        }
    }
}

/// Split a `scope` value per RFC 6749 §3.3's ABNF (`scope = scope-token *( SP scope-token)`,
/// `scope-token = 1*NQCHAR`). A present-but-empty value, or any empty/whitespace member, is
/// malformed, never an omission (`scripts/gmail_drill_mint.py` `_refuse_malformed_scope`).
/// Substituting the requested set for a malformed value could attest a narrow set while a broader
/// grant's refresh token persists, so it refuses. The separator is the ABNF's single SP, not "any
/// whitespace run": splitting on runs would repair `a b` into two valid members.
fn scope_members(raw: &str) -> Result<BTreeSet<String>, ContractViolation> {
    if raw.trim().is_empty() {
        return Err(ContractViolation::ScopeMalformed);
    }
    let mut set = BTreeSet::new();
    for member in raw.split(' ') {
        // The full NQCHAR alphabet (%x21 / %x23-5B / %x5D-7E), not merely "no whitespace". A
        // quote, backslash, control byte or non-ASCII char is outside the grammar, and a response
        // outside the grammar is a broken contract: it must never be read as evidence about
        // granted authority and converted into a terminal re-mint demand.
        if member.is_empty()
            || member
                .chars()
                .any(|c| !matches!(c, '\x21' | '\x23'..='\x5B' | '\x5D'..='\x7E'))
        {
            return Err(ContractViolation::ScopeMalformed);
        }
        set.insert(member.to_string());
    }
    Ok(set)
}

/// Exact-set comparison against the stored grant: missing or unexpected refuses
/// (`scripts/gmail_drill_mint.py` `enforce_lane_scope_contract` enforces the same at the mint).
/// It is an unordered exact set, never a substring and never missing-only.
///
/// The reference is `stored`, not [`REQUIRED_SCOPES`]: RFC 6749 §6 forbids a refresh from
/// carrying "any scope not originally granted", so the question here is "did the provider answer
/// with the grant we hold?", not "is this the product's set?" (asked once, at load). A stated
/// narrower set therefore refuses this generation (missing) rather than quietly minting a new,
/// smaller grant identity.
fn authority_mismatch(
    granted: &BTreeSet<String>,
    stored: &BTreeSet<String>,
) -> Option<RefreshOutcome> {
    let missing: BTreeSet<String> = stored.difference(granted).cloned().collect();
    let unexpected: BTreeSet<String> = granted.difference(stored).cloned().collect();
    if missing.is_empty() && unexpected.is_empty() {
        return None;
    }
    Some(RefreshOutcome::AuthorityMismatch {
        missing: ScopeSet::new(missing),
        unexpected: ScopeSet::new(unexpected),
    })
}

/// Classify a non-200 response. Order is load-bearing: the known transient codes win at any
/// status, then the mapped code table, then 429 (RFC 6585 §4) before the generic-4xx rule, then
/// 5xx, then the `UnknownDenied` fallback.
///
/// An unparseable non-200 body with a recognized status still classifies by status; the absence
/// of a code is recorded, not guessed around.
///
/// The status-by-code matrix: a terminal OAuth code is believed only at the status(es) its
/// governing document establishes for it. A blanket any-4xx gate believed `invalid_grant` at 418
/// and 403 and latched a false re-mint to the file generation. RFC 6749 §5.2's rule is HTTP 400
/// unless specified otherwise, with one named exception: `invalid_client` MAY arrive at 401. The
/// Google-vocabulary codes ride Google's own error surface, recorded at 400/403 in the design's
/// vendor evidence (the Chromium OAuth fetcher; `rate_limit_exceeded` observed at 403 anchors the
/// family's status range). A recognized code at an unestablished status falls through to
/// `UnknownDenied`, paced and never latched, which is the direction that cannot wrongly latch a
/// terminal cure.
///
/// A code is in the table only if an opened source of one of three kinds establishes both the
/// code and its status(es) for this grant at this endpoint: (a) RFC 6749 §5.2's token-error
/// vocabulary; (b) Google's current Token Endpoint reference
/// (developers.google.com/identity/openid-connect/reference, "Error responses", which covers our
/// endpoint and the refresh parameters); (c) a token-response consumer implementation or a
/// grant-independent client status: the Chromium OAuth token fetcher establishes
/// `admin_policy_enforced`/`restricted_client` as token-response codes, and Google documents
/// `deleted_client`/`disabled_client` as client states with an unconditional
/// only-the-developer-can-fix remedy. Everything else refuses as `UnknownDenied`.
///
/// Demoted, because the Token Endpoint reference is the governing source: `access_denied` (listed
/// there for the device flow only, not our refresh grant) and `access_not_configured` (documented
/// on the sign-in surface only). Deliberately unmapped though documented elsewhere at Google:
/// `policy_enforced`@400, `invalid_user`@400, `invalid_account`@403, since the opened sources do
/// not establish their remedies.
fn code_established_at(code: &str, status: u16) -> bool {
    match code {
        // (a) RFC 6749 §5.2 vocabulary: 400 unless specified otherwise.
        "invalid_grant" | "unauthorized_client" | "unsupported_grant_type" | "invalid_request"
        | "invalid_scope" => status == 400,
        // (a) §5.2's named exception: invalid_client MAY be 401 (with WWW-Authenticate).
        "invalid_client" => status == 400 || status == 401,
        // (c) Grant-independent client states, with a Google-documented remedy.
        "deleted_client" | "disabled_client" => status == 401,
        // (c) Chromium token-fetcher evidence.
        "admin_policy_enforced" => status == 400,
        "restricted_client" => status == 403,
        // (b) The Token Endpoint reference's own error table.
        "org_internal" => status == 403,
        _ => false,
    }
}

fn classify_error(status: u16, body: &[u8]) -> RefreshOutcome {
    // The same reader as the success branch: a repeated member is refused as a contract violation
    // rather than read last-wins, since a repeat could otherwise flip a terminal denial into a
    // transient one or the reverse. An unparsable error body stays what it was: no code, and the
    // status arms classify it.
    let parsed = match token_response_members(body) {
        TokenResponseBody::Object(map) => Some(map),
        TokenResponseBody::RepeatsMember => return violation(ContractViolation::BodyRepeatsMember),
        TokenResponseBody::NotAnObject => None,
    };
    let code = parsed
        .as_ref()
        .and_then(|m| m.get("error"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let subtype = parsed
        .as_ref()
        .and_then(|m| m.get("error_subtype"))
        .and_then(Value::as_str)
        .map(str::to_string);

    match code.as_deref() {
        // The known transient codes, at any status, deliberately status-free: `rate_limit_exceeded`
        // arrives at 403, and Google's OAuth fetcher treats it as retryable, so a status-only
        // classifier would latch a rate limit as a permanent denial. A transient never latches and
        // never asserts a cure medium, so believing it at an odd status costs one paced retry,
        // while gating it could turn a real rate limit into `UnknownDenied` noise.
        Some(c @ ("rate_limit_exceeded" | "internal_failure")) => RefreshOutcome::Transient {
            kind: TransientKind::ProviderTransient(Sanitized::new(c)),
        },
        // `invalid_grant` only. `invalid_scope` has its own terminal arm with an honest sentence,
        // since the provider evidence does not establish that a re-mint cures it.
        //
        // Every terminal arm is gated on `code_established_at`: a terminal code is believed only at
        // the status(es) its governing document establishes. On a 5xx it is noise riding a server
        // fault, on a 429 a rate limit, on a 3xx/2xx not a token response, and on a 4xx outside its
        // established set (418, or 403 with `invalid_grant`) a nonconforming response that must not
        // latch a re-mint/config/policy cure to the file generation. The status arms below then
        // classify honestly.
        Some(c @ "invalid_grant") if code_established_at(c, status) => {
            RefreshOutcome::ReauthRequired {
                subtype: subtype.as_deref().map(Sanitized::new),
            }
        }
        Some(
            c @ ("invalid_client" | "deleted_client" | "disabled_client" | "unauthorized_client"
            | "unsupported_grant_type" | "invalid_request" | "restricted_client"),
        ) if code_established_at(c, status) => RefreshOutcome::ClientConfig {
            code: Sanitized::new(c),
        },
        // Only codes established at this endpoint by named vendor evidence. `org_internal` and
        // `disallowed_useragent` are authorization-endpoint vocabulary and are deliberately not
        // mapped: speculative completeness loses to an honest `UnknownDenied`.
        Some(c @ ("admin_policy_enforced" | "org_internal"))
            if code_established_at(c, status) =>
        {
            RefreshOutcome::ProviderPolicy {
                code: Sanitized::new(c),
            }
        }
        Some(c @ "invalid_scope") if code_established_at(c, status) => RefreshOutcome::InvalidScope,
        // 429 before the generic-4xx rule (RFC 6585 §4); otherwise a rate limit becomes an
        // `UnknownDenied` and the floor is asked to explain a wait it did not choose.
        _ if status == 429 => RefreshOutcome::Transient {
            kind: TransientKind::RateLimited(status),
        },
        _ if (500..600).contains(&status) => RefreshOutcome::Transient {
            kind: TransientKind::ServerError(status),
        },
        _ if (400..500).contains(&status) => RefreshOutcome::UnknownDenied {
            status,
            code: code.as_deref().map(Sanitized::new),
        },
        // A 3xx survives `redirect::Policy::none()`, and a non-200 2xx is not a token response.
        // Neither is a denial, so neither may be classified as one.
        _ => violation(ContractViolation::StatusUnexpected),
    }
}

// The OAuth client configuration

/// Which shape the client file failed on. Reasons name the path and shape, never contents
/// (`scripts/gmail_drill_mint.py` `client_from_config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClientConfigShape {
    Unreadable(std::io::ErrorKind),
    NotJson,
    NotAnObject,
    /// A `web` application client, refused by name: its redirect URIs are registered exactly, so
    /// this flow can only end in `redirect_uri_mismatch`.
    WebClient,
    NoInstalledMember,
    MissingClientId,
    MissingClientSecret,
    TokenUriAbsent,
    /// The file's `token_uri` disagrees with the compiled [`TOKEN_ENDPOINT`]; the reason names both.
    TokenUriMismatch {
        found: String,
    },
}

/// A refusal to load the client file: the path it read and the shape it found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientConfigError {
    pub(crate) path: PathBuf,
    pub(crate) shape: ClientConfigShape,
}

impl ClientConfigError {
    pub(crate) fn reason_sentence(&self) -> String {
        let what = match &self.shape {
            ClientConfigShape::Unreadable(kind) => format!("it could not be read ({kind:?})"),
            ClientConfigShape::NotJson => "it is not valid JSON".to_string(),
            ClientConfigShape::NotAnObject => "its top level is not a JSON object".to_string(),
            ClientConfigShape::WebClient => "it holds a WEB application client; Photon's refresh \
                 exchange requires an 'installed' (Desktop) client"
                .to_string(),
            ClientConfigShape::NoInstalledMember => {
                "it has no 'installed' client member".to_string()
            }
            ClientConfigShape::MissingClientId => {
                "its 'installed' entry has no usable client_id".to_string()
            }
            ClientConfigShape::MissingClientSecret => {
                "its 'installed' entry has no usable client_secret".to_string()
            }
            ClientConfigShape::TokenUriAbsent => {
                "its 'installed' entry declares no token_uri".to_string()
            }
            ClientConfigShape::TokenUriMismatch { found } => format!(
                "its 'installed' entry declares token_uri {found}, which is not Photon's compiled \
                 endpoint {TOKEN_ENDPOINT}"
            ),
        };
        format!(
            "the OAuth client file at {} cannot be used: {what}.",
            self.path.display()
        )
    }
}

/// The OAuth client Photon spends the refresh token with. The secret has one home.
#[derive(Clone)]
pub(crate) struct ClientConfig {
    client_id: String,
    client_secret: SecretString,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("client_id", &"<redacted>")
            .field("client_secret", &self.client_secret)
            .finish()
    }
}

impl ClientConfig {
    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn client_secret(&self) -> &SecretString {
        &self.client_secret
    }

    /// Load `<secrets_dir>/client_secret.json`, `installed` entry only.
    ///
    /// A `web` application client is refused by name, mirroring the mint script
    /// (`scripts/gmail_drill_mint.py` `client_from_config`), and the file's `token_uri` is
    /// cross-checked against the compiled [`TOKEN_ENDPOINT`]: the client file must not be able to
    /// move where Photon spends the refresh token. Reasons name path and shape, never contents.
    ///
    /// An absent `token_uri` also refuses ([`ClientConfigShape::TokenUriAbsent`]). A Google client
    /// file always carries one, so a file without it is not the file this loader thinks it is
    /// reading, and accepting it would make the cross-check optional in exactly the case where it
    /// is cheapest to omit.
    pub(crate) fn load(secrets_dir: &Path) -> Result<Self, RefreshLocalError> {
        let path = secrets_dir.join(CLIENT_SECRET_FILE_NAME);
        let refuse = |shape: ClientConfigShape| {
            RefreshLocalError::ClientConfig(ClientConfigError {
                path: path.clone(),
                shape,
            })
        };
        let bytes = std::fs::read(&path)
            .map_err(|e| refuse(ClientConfigShape::Unreadable(e.kind())))?;
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            return Err(refuse(ClientConfigShape::NotJson));
        };
        let Some(map) = value.as_object() else {
            return Err(refuse(ClientConfigShape::NotAnObject));
        };
        let entry = match map.get("installed") {
            Some(entry) => entry,
            None if map.contains_key("web") => return Err(refuse(ClientConfigShape::WebClient)),
            None => return Err(refuse(ClientConfigShape::NoInstalledMember)),
        };
        match entry.get("token_uri").and_then(Value::as_str) {
            Some(uri) if uri == TOKEN_ENDPOINT => {}
            Some(other) => {
                return Err(refuse(ClientConfigShape::TokenUriMismatch {
                    found: render_local_uri(other),
                }))
            }
            None => return Err(refuse(ClientConfigShape::TokenUriAbsent)),
        }
        let client_id = entry
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| refuse(ClientConfigShape::MissingClientId))?;
        let client_secret = entry
            .get("client_secret")
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| refuse(ClientConfigShape::MissingClientSecret))?;
        Ok(Self {
            client_id: client_id.to_string(),
            client_secret: SecretString::new(client_secret),
        })
    }
}

// Typed local failures: each maps to a transient-class result at the cell

/// The failures that are ours, not the provider's. The wave publishes each as a transient-class
/// result so the cell keeps its old provider and the next admission reconciles, never a silent
/// wedge.
#[derive(Clone, Debug)]
pub(crate) enum RefreshLocalError {
    /// The bounded acquisition expired. Explicit refusal: no write, no hang.
    LockTimeout { path: PathBuf, waited: Duration },
    /// The lock address itself could not be opened or classified. Distinct from a timeout, since
    /// no contention was observed.
    LockUnavailable {
        path: PathBuf,
        reason: LocalIoReason,
    },
    /// The credential could not be written (before any rename; the old file is untouched).
    WriteFailed {
        path: PathBuf,
        reason: LocalIoReason,
    },
    /// The atomic replace failed (the old file is still the one on disk).
    RenameFailed {
        path: PathBuf,
        reason: LocalIoReason,
    },
    /// The credential persisted but the provider arm could not be rebuilt.
    RebuildFailed { reason: String },
    /// The refresh HTTP client could not be built. Pre-wire: nothing was dialled or written.
    /// (This state once borrowed `RebuildFailed`, whose sentence claims "renewed and written",
    /// which is false here.) Construction is retried on the next wave.
    ClientBuild,
    /// The atomic replace's commit failed and "the existing file is unchanged" cannot be claimed
    /// (the sentence states only what was observed). `observed_replaced` means both digests were
    /// read and differ: the renewed bytes are known to be the visible file, durability
    /// unconfirmed. `false` means at least one digest was unreadable, so which side of the replace
    /// the failure stopped on is unknown. Either way the next admission's reconcile adopts
    /// whatever the file is.
    CommitUncertain {
        path: PathBuf,
        observed_replaced: bool,
    },
    /// The OAuth client file cannot be used.
    ClientConfig(ClientConfigError),
    /// The parked credential's grant generation is below the recorded high-water: a later consent
    /// superseded it, and this file is a rollback. Terminal for this file; the cure is a re-mint
    /// (the cure map in `credential_cell` carries that, beside `ClientConfig`'s own carve-out).
    GrantRetired {
        path: PathBuf,
        credential_generation: u64,
        high_water: u64,
    },
    /// The grant ratchet exists but could not be used. Refused explicitly and never treated as
    /// absent: sorting an unusable ratchet low would re-admit every retired grant.
    GrantHighWaterUnusable {
        path: PathBuf,
        shape: GrantHighWaterShape,
    },
    /// The ratchet could not be raised. Fails closed: admitting a generation the ratchet does not
    /// record leaves the credential it supersedes admissible.
    GrantHighWaterWriteFailed {
        path: PathBuf,
        reason: LocalIoReason,
    },
    /// The `held` proof parameter is a lock on a different directory than the one whose ratchet is
    /// being admitted, so the read-compare-replace is not serialized against the writer that
    /// matters. It is refused, typed, rather than silently proceeding.
    ///
    /// This is a programming error, not an adversary. No untrusted data reaches this parameter;
    /// only first-party code passing the wrong handle produces it, so it is hygiene and not a
    /// control. Its cure is `Undetermined`: no act by the operator fixes a caller that handed over
    /// the wrong lock.
    AdmissionLockMismatch {
        /// The directory the held lock guards, or `None` when its address had no parent.
        held: Option<PathBuf>,
        /// The directory whose ratchet the caller asked to admit against.
        secrets_dir: PathBuf,
    },
    /// The credential file's generation digest could not be read: a transient filesystem error,
    /// not absence (`FileGen::Absent`) and not a change. Pre-wire: nothing was dialled or written
    /// and no latch released; the read is retried on the next command.
    FileGenUnreadable { reason: LocalIoReason },
}

/// Why a local I/O step failed, at error-kind granularity. The io error's own `Display` is never
/// carried: we name the path ourselves and the kind is all the operator needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalIoReason(pub(crate) std::io::ErrorKind);

impl std::fmt::Display for LocalIoReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl RefreshLocalError {
    /// The named cure this local failure takes, enumerated variant by variant so a new failure
    /// mode cannot inherit a stale remedy from a wildcard arm.
    ///
    /// Two consumers read it and neither owns a copy: the wave's remembered outcome
    /// (`credential_cell::RememberedOutcome::cure`) and the boot path's `Provider::Unconfigured`
    /// (a boot refusal would otherwise cross the boundary as a sentence with no discriminant, and
    /// the status bar would render `credential_cure: null` for a session whose one cure is a
    /// re-mint).
    pub(crate) fn cure(&self) -> Cure {
        match self {
            // An unreadable or refused client config is the operator's file to fix, not a wait.
            Self::ClientConfig(_) => Cure::ClientConfig,
            // A retired grant is not a wait either: a later consent superseded this credential,
            // and no amount of retrying un-supersedes it. The cure is the consent ceremony (pacing
            // is the timing, the cure is the medium).
            Self::GrantRetired { .. } => Cure::ReMint,
            // Everything else heals by retrying: the next command re-runs the step that failed
            // (the lock re-taken, the write/rename/rebuild re-attempted, the digest re-read, the
            // ratchet re-read or re-raised). An unusable ratchet is `RetryLater` here and
            // `Undetermined` on the status read (`GrantOnDisk::verdict`, on both the live and the
            // expired branch): this answers "what does the operator do about the step that just
            // failed", while that one is "what is the verdict on a published arm whose admission
            // cannot be established". `AdmissionLockMismatch` is a caller-side mistake, and the
            // cure says so: no operator act repairs it.
            Self::AdmissionLockMismatch { .. } => Cure::Undetermined,
            Self::LockTimeout { .. }
            | Self::LockUnavailable { .. }
            | Self::WriteFailed { .. }
            | Self::RenameFailed { .. }
            | Self::RebuildFailed { .. }
            | Self::ClientBuild
            | Self::CommitUncertain { .. }
            | Self::GrantHighWaterUnusable { .. }
            | Self::GrantHighWaterWriteFailed { .. }
            | Self::FileGenUnreadable { .. } => Cure::RetryLater,
        }
    }

    /// The boot call site's sentence.
    ///
    /// Every other sentence in [`RefreshLocalError::reason_sentence`] is written for a call site
    /// where the next command re-attempts the failed step, so "Retry your command" is true there.
    /// Boot runs once and no retry re-enters it, so telling the operator to retry would name a
    /// cure that cannot arrive at the surface they are reading: the status bar keeps reporting an
    /// unconfigured session until something re-reads the credential.
    ///
    /// What does re-read it (measured in the boot lock-timeout test): both credential reads happen
    /// inside the lock, so the post-timeout cell carries no digest and no expiry, and the next
    /// provider command reconciles under the lock and heals. A restart is therefore the cure that
    /// is always available, not the only one, and it is the one an operator staring at a dead
    /// status bar can perform. Only the lock timeout gets this treatment; every other local
    /// failure keeps its one sentence.
    pub(crate) fn boot_reason_sentence(&self) -> String {
        match self {
            Self::LockTimeout { path, waited } => format!(
                "Photon started while another writer (the mint script) held the credential lock \
                 at {} for the whole {} ms budget; nothing was written. Restart Photon once the \
                 mint has finished.",
                path.display(),
                waited.as_millis()
            ),
            other => other.reason_sentence(),
        }
    }

    /// Operator-facing and single-sourced: names the stage and the path, never a secret.
    pub(crate) fn reason_sentence(&self) -> String {
        match self {
            Self::LockTimeout { path, waited } => format!(
                "the credential lock at {} was held by another writer for the whole {} ms budget; \
                 nothing was written. Retry your command — if it persists, a mint script may be \
                 wedged.",
                path.display(),
                waited.as_millis()
            ),
            Self::LockUnavailable { path, reason } => format!(
                "the credential lock at {} could not be opened ({reason}); nothing was written.",
                path.display()
            ),
            Self::WriteFailed { path, reason } => format!(
                "the renewed credential could not be written near {} ({reason}); the existing \
                 credential file is unchanged.",
                path.display()
            ),
            Self::RenameFailed { path, reason } => format!(
                "the renewed credential could not replace {} ({reason}); the existing credential \
                 file is unchanged.",
                path.display()
            ),
            Self::RebuildFailed { reason } => format!(
                "the credential was renewed and written, but the Gmail provider could not be \
                 rebuilt from it ({reason}); the credential on disk is the renewed one and the \
                 provider in memory is still the previous one."
            ),
            // Pre-wire, and the sentence says so: nothing was dialled or written.
            Self::ClientBuild => "the refresh HTTP client could not be built (no TLS backend); \
                 nothing was sent and nothing was written."
                .to_string(),
            // Only observed facts: the replaced arm names the known replacement, and the unknown
            // arm asserts no stage, since `commit()` can fail before or after the rename and an
            // unreadable digest cannot tell which.
            Self::CommitUncertain {
                path,
                observed_replaced: true,
            } => format!(
                "the renewed credential replaced {}, but the write did not complete cleanly \
                 (durability unconfirmed); Photon did not advance the published provider onto it.",
                path.display()
            ),
            Self::CommitUncertain {
                path,
                observed_replaced: false,
            } => format!(
                "the credential write at {} failed and the on-disk state could not be read to \
                 establish which side of the replace it stopped on; Photon did not advance the \
                 published provider onto it.",
                path.display()
            ),
            Self::ClientConfig(e) => e.reason_sentence(),
            // Names which consent is stale and which one superseded it (two integers, no identity,
            // no token bytes) and prescribes the one act that cures it.
            Self::GrantRetired {
                path,
                credential_generation,
                high_water,
            } => format!(
                "the parked Gmail credential was minted under grant {credential_generation}, but \
                 a later consent (grant {high_water}) is recorded at {}; this credential has been \
                 retired and Photon will not use it — re-mint via scripts/gmail_drill_mint.py to \
                 consent again.",
                path.display()
            ),
            Self::GrantHighWaterUnusable { path, shape } => format!(
                "the grant record at {} cannot be used: {}. Photon refuses rather than treat an \
                 unreadable record as an empty one — that would re-admit a retired credential. \
                 Nothing was changed.",
                path.display(),
                grant_high_water_label(*shape)
            ),
            Self::GrantHighWaterWriteFailed { path, reason } => format!(
                "this credential's grant could not be recorded at {} ({reason}), so Photon did \
                 not admit it: a grant it cannot record is one it could not later retire. \
                 Nothing was changed.",
                path.display()
            ),
            // Names the class and the two directories, never a credential value: the whole fact is
            // which directory was proven versus which was admitted.
            Self::AdmissionLockMismatch { held, secrets_dir } => format!(
                "the credential admission for {} was handed a lock guarding {} instead, so the                  grant record could not be read and raised under the lock that serializes it;                  nothing was changed. This is an internal fault, not a state your credential is                  in.",
                secrets_dir.display(),
                match held {
                    Some(d) => d.display().to_string(),
                    None => "no directory".to_string(),
                }
            ),
            // Pre-wire: an unreadable digest is not a change and not a verdict. Nothing was
            // dialled or written, and no latched refusal moved.
            Self::FileGenUnreadable { reason } => format!(
                "the credential file's generation could not be read ({reason}); nothing was \
                 dialled and nothing was changed."
            ),
        }
    }
}

// The exchange client (HTTP discipline, execution topology)

/// The blocking reqwest client that spends the refresh token, built with `aruna-gmail`'s
/// discipline: distinct connect/total timeouts, `.no_proxy()` so a credentialed request is never
/// routed through an ambient proxy, and `redirect::Policy::none()` so a server-chosen redirect
/// can never re-POST the client secret elsewhere.
///
/// It runs inside one `spawn_blocking` closure; blocking reqwest never runs on the async
/// runtime.
#[derive(Clone)]
pub(crate) struct RefreshClient {
    http: reqwest::blocking::Client,
    endpoint: reqwest::Url,
}

impl std::fmt::Debug for RefreshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshClient")
            .field("endpoint", &"<redacted>")
            .finish()
    }
}

/// Why a [`RefreshClient`] could not be constructed. Construction touches no network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientBuildError;

impl RefreshClient {
    /// Production construction: the endpoint is the compiled constant, with no base parameter on
    /// this path at all.
    pub(crate) fn production() -> Result<Self, ClientBuildError> {
        Self::with_endpoint(
            reqwest::Url::parse(TOKEN_ENDPOINT).expect("the compiled endpoint is a valid URL"),
        )
    }

    /// Fixture construction: the only path that accepts a base, test-gated exactly like
    /// `aruna-gmail`'s. Plaintext is refused off loopback before anything touches the network.
    #[cfg(test)]
    pub(crate) fn fixture(origin: &str) -> Result<Self, ClientBuildError> {
        let base = reqwest::Url::parse(origin).map_err(|_| ClientBuildError)?;
        require_tls_or_local(&base)?;
        let endpoint = base.join("/token").map_err(|_| ClientBuildError)?;
        Self::with_endpoint(endpoint)
    }

    fn with_endpoint(endpoint: reqwest::Url) -> Result<Self, ClientBuildError> {
        debug_assert!(CONNECT_TIMEOUT < HTTP_TIMEOUT);
        let http = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ClientBuildError)?;
        Ok(Self { http, endpoint })
    }

    /// One refresh exchange: the RFC 6749 §6 form POST (`client_id`, `client_secret`,
    /// `refresh_token`, `grant_type=refresh_token`). No `scope` parameter is sent, which decides
    /// `invalid_scope`'s meaning in the outcome table.
    ///
    /// The body is read bounded (`cap + 1`) so a hostile server cannot make us allocate.
    pub(crate) fn exchange(
        &self,
        client: &ClientConfig,
        refresh_token: &str,
        now_unix: i64,
        stored_scopes: &BTreeSet<String>,
    ) -> RefreshOutcome {
        let form = [
            ("client_id", client.client_id()),
            ("client_secret", client.client_secret().expose()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ];
        let response = match self
            .http
            .post(self.endpoint.clone())
            .form(&form)
            .send()
        {
            Ok(r) => r,
            Err(_) => {
                return RefreshOutcome::Transient {
                    kind: TransientKind::Network,
                }
            }
        };
        // The expiry base is captured when headers arrive. The caller's `now_unix` predates the
        // lock wait, the config load and the HTTP round trip, and a base taken after the body is
        // consumed would inflate the grant by the transfer time of a slowly streamed body. The
        // provider's `expires_in` lifetime began no later than when it generated the response, so
        // the base is sampled the moment `send()` returns, before the body is read. The caller's
        // clock is only the fallback for a pre-epoch system clock.
        let received_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(now_unix);
        let status = response.status().as_u16();
        let mut buf = Vec::new();
        let cap = MAX_REFRESH_BODY_BYTES as u64;
        if std::io::Read::take(response, cap + 1)
            .read_to_end(&mut buf)
            .is_err()
        {
            return RefreshOutcome::Transient {
                kind: TransientKind::Network,
            };
        }
        parse_refresh_response(status, &buf, received_unix, refresh_token, stored_scopes)
    }
}

/// The fixture-base guard: `https` anywhere, plaintext only to an actual loopback host. It
/// mirrors `transport.rs`, guards the fixture base only, and production never passes through it.
#[cfg(test)]
fn require_tls_or_local(url: &reqwest::Url) -> Result<(), ClientBuildError> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let host = url.host_str().unwrap_or("");
    let is_loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if url.scheme() == "http" && is_loopback {
        return Ok(());
    }
    Err(ClientBuildError)
}

// Atomic persistence

/// The credential file's exact on-disk shape, the mint script's own
/// (`scripts/gmail_drill_mint.py` `main_token_document`), so the two writers cannot produce two
/// formats.
///
/// v2 is `{access_token, refresh_token, expires_at, grant}`. The `grant` object is written back
/// unchanged on every rotation (as with `surviving_refresh_token`): a renewal produces a new
/// access token, never a new grant identity.
///
/// Key order is deterministic because `serde_json`'s object map is a `BTreeMap` here (the
/// `preserve_order` feature is not enabled anywhere in this tree) and `effective_scopes` is a
/// `BTreeSet`, so the array is sorted and deduplicated. There is one trailing newline, like every
/// file we write.
///
/// The rotation therefore preserves the grant typed-identically (canonical key order, set
/// semantics), not byte-identically: a stored grant whose `effective_scopes` array carried a
/// duplicate spelling comes back out as a one-member set in canonical order. The authority is
/// preserved exactly; the source bytes are not.
fn credential_document(
    access_token: &str,
    refresh_survivor: &str,
    expires_at: i64,
    grant: &GrantProvenance,
) -> Vec<u8> {
    let doc = serde_json::json!({
        "access_token": access_token,
        "refresh_token": refresh_survivor,
        "expires_at": expires_at,
        "grant": grant,
    });
    let mut bytes = serde_json::to_vec(&doc).expect("a four-field object always serializes");
    bytes.push(b'\n');
    bytes
}

/// The two-phase credential writer. Splitting `open` from `commit` is what makes atomic
/// persistence testable: a failure between them must leave the existing file byte-identical.
struct CredentialWriter {
    file: atomic_write_file::AtomicWriteFile,
    path: PathBuf,
    /// Exact-convention sibling names (`.{base}.{6 alnum}`) present before this writer created its
    /// temp, or `None` when the pre-write enumeration itself failed, which disables the
    /// commit-failure sweep entirely. An empty-set fallback would revert the sweep to
    /// convention-only and delete an operator's colliding sibling; an unswept temp is a bounded
    /// residual, while a deleted operator file is not. The sweep removes only names outside this
    /// set, because "backup" is itself six alphanumerics and name shape alone cannot tell an
    /// operator's pre-existing `.{base}.backup` from our fresh temp. Presence before the write can:
    /// the whole write runs under the credential lock, so the one new convention-shaped entry is
    /// ours.
    preexisting_temps: Option<std::collections::BTreeSet<std::ffi::OsString>>,
}

/// Every sibling of `path` whose whole name matches the pinned crate temp convention:
/// `.{base}.` plus exactly six ASCII-alphanumeric chars (`RandomName`, atomic-write-file 0.3.1
/// `src/imp/generic.rs` and `src/imp/unix/mod.rs`: two implementations, one convention, a
/// version-pinned observation). A failed enumeration is an `Err`, never an empty set: "could not
/// look" and "nothing there" are different facts.
fn convention_temp_names(
    path: &Path,
) -> Result<std::collections::BTreeSet<std::ffi::OsString>, std::io::Error> {
    let mut names = std::collections::BTreeSet::new();
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return Ok(names);
    };
    let prefix = format!(".{name}.");
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let Some(entry_str) = entry_name.to_str() else {
            continue;
        };
        let Some(suffix) = entry_str.strip_prefix(&prefix) else {
            continue;
        };
        if suffix.len() == 6 && suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
            names.insert(entry_name);
        }
    }
    Ok(names)
}

/// "The existing credential file is unchanged" may be claimed only when both the pre-commit and
/// post-error digests were read and match. If either side is unreadable the claim would be
/// asserted rather than known, and `CommitUncertain` is the honest label (on Unix the rename can
/// become visible and then the directory sync fail, which a both-sides-unreadable `None == None`
/// would mislabel).
fn commit_left_target_unchanged(pre: &Option<FileGen>, post: &Option<FileGen>) -> bool {
    matches!((pre, post), (Some(a), Some(b)) if a == b)
}

impl std::io::Write for CredentialWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl CredentialWriter {
    /// fsync, then the atomic replace. Dropping without calling this discards the temp file and
    /// leaves the visible path exactly as it was.
    fn commit(self) -> Result<(), RefreshLocalError> {
        // The pre-commit digest reads the old visible file (the temp lives at a dotted sibling
        // name), so a post-error re-digest can say which side of the rename the failure hit.
        let pre_gen = FileGen::of(&self.path).ok();
        match self.file.commit() {
            Ok(()) => Ok(()),
            Err(e) => {
                // On a failed commit the crate's writer is already finalized, so its Drop does
                // not discard the named temp sibling, which carries both tokens (one more copy
                // per paced retry). The crate exposes no temp-path accessor (v0.3.1 API:
                // new/read/open/options/as_file/directory/commit/discard; see
                // `convention_temp_names`), so cleanup selects by convention and provenance: only
                // a convention-shaped name that was not present before this writer opened is ours
                // to remove. A prefix-only sweep destroyed an operator's `.{base}.backup`, since
                // "backup" is itself six alphanumerics, so the pre-write snapshot, not the name
                // shape, protects a colliding pre-existing sibling. This is safe because the whole
                // write runs under the cross-process lock, so the one new convention-shaped entry
                // is ours. It is best-effort: a removal failure is not a second error, since the
                // refusal below already surfaces the commit failure. (On Linux the temp may be an
                // unnamed O_TMPFILE and the sweep finds nothing, so there is nothing to clean.)
                // The sweep runs only with a good pre-write snapshot and a good post-error
                // enumeration: either side failing disables it, because deleting is the
                // unrecoverable direction and uncertainty always spares the file.
                if let (Some(preexisting), Ok(current)) =
                    (&self.preexisting_temps, convention_temp_names(&self.path))
                {
                    for name in current {
                        if !preexisting.contains(&name) {
                            if let Some(parent) = self.path.parent() {
                                let _ = std::fs::remove_file(parent.join(name));
                            }
                        }
                    }
                }
                // On Unix, `commit()` can fail after the rename became visible (the
                // parent-directory sync). The renewed bytes are then the file, and calling that
                // `RenameFailed` ("the existing credential file is unchanged") would be false,
                // leaving cell and disk inconsistent until reconcile. Classify by what the disk
                // says, and only by what was actually read: an unreadable digest on either side is
                // `CommitUncertain`, never an asserted "unchanged".
                let post_gen = FileGen::of(&self.path).ok();
                if commit_left_target_unchanged(&pre_gen, &post_gen) {
                    Err(RefreshLocalError::RenameFailed {
                        path: self.path,
                        reason: LocalIoReason(e.kind()),
                    })
                } else {
                    // Only what was observed: replacement is a fact only when both digests were
                    // read and differ; otherwise the stage is unknown.
                    let observed_replaced =
                        matches!((&pre_gen, &post_gen), (Some(a), Some(b)) if a != b);
                    Err(RefreshLocalError::CommitUncertain {
                        path: self.path,
                        observed_replaced,
                    })
                }
            }
        }
    }
}

/// Open the credential writer for `path`: `atomic-write-file` gives a same-directory temp,
/// fsync-before-rename, atomic rename and Unix directory-fd path stability.
///
/// `preserve_mode(false)` plus `mode(0o600)` on Unix is load-bearing: the crate's default copies
/// an existing file's permissions onto the replacement, which would preserve a pre-existing 0644
/// credential forever. Windows has no equivalent knob; the file inherits the directory's ACL,
/// which is stated here and not claimed as a control.
fn open_credential_writer(path: &Path) -> Result<CredentialWriter, RefreshLocalError> {
    // `mut` is used on Unix only, where the mode is configured below; Windows has no such knob.
    #[allow(unused_mut)]
    let mut options = atomic_write_file::AtomicWriteFile::options();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        options.preserve_mode(false);
        options.mode(0o600);
    }
    // Snapshot before the crate creates its temp: the commit-failure sweep may remove only
    // convention-shaped names absent from this set (see `CredentialWriter.preexisting_temps`). A
    // failed enumeration is remembered as `None`, which disables the sweep, rather than as an
    // empty snapshot that would delete a pre-existing colliding sibling.
    let preexisting_temps = convention_temp_names(path).ok();
    let file = options
        .open(path)
        .map_err(|e| RefreshLocalError::WriteFailed {
            path: path.to_path_buf(),
            reason: LocalIoReason(e.kind()),
        })?;
    Ok(CredentialWriter {
        file,
        path: path.to_path_buf(),
        preexisting_temps,
    })
}

/// Persist the renewed credential. Only [`CREDENTIAL_FILE_NAME`] is written; the drill lane's
/// attestation bundle is left alone, and its staleness is a known residual.
///
/// Rename-atomicity guards visibility and torn writes. Post-crash durability is undetermined and
/// unclaimed: the writer's fsync eliminates the durably-renamed-but-unwritten-content file, which
/// is what fsync buys, and nothing more is asserted.
///
/// On success this returns the generation of the bytes it wrote, computed in memory from the
/// exact committed bytes and never from a post-persist disk read. The caller therefore publishes
/// a known generation, and the "renewal with an unknown generation" state (whose healing
/// reconcile erased the floor stamp) cannot arise.
pub(crate) fn persist_credential(
    secrets_dir: &Path,
    access_token: &str,
    refresh_survivor: &str,
    expires_at: i64,
    grant: &GrantProvenance,
) -> Result<FileGen, RefreshLocalError> {
    let path = secrets_dir.join(CREDENTIAL_FILE_NAME);
    let bytes = credential_document(access_token, refresh_survivor, expires_at, grant);
    let written_gen = FileGen::of_bytes(&bytes);
    let mut writer = open_credential_writer(&path)?;
    writer
        .write_all(&bytes)
        .map_err(|e| RefreshLocalError::WriteFailed {
            path: path.clone(),
            reason: LocalIoReason(e.kind()),
        })?;
    writer.commit()?;
    Ok(written_gen)
}

// FileGen, the credential file's generation

/// The credential file's generation: a content digest, not size+mtime, so a same-size,
/// timestamp-restored replacement is still detected. It is SHA-384, per the house posture of
/// strict SHA-384 where we control the format (`scripts/gmail_drill_mint.py` `token_sha384`
/// hashes the same way).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FileGen {
    /// No credential file on disk: a real, comparable generation (boot before the first mint).
    Absent,
    /// Lowercase hex SHA-384 of the file's exact bytes.
    Sha384(String),
}

impl FileGen {
    /// Read `path` and digest it. A file that is not there is [`FileGen::Absent`], not an error:
    /// absence is a generation the admission check must be able to compare, and an `Err` would
    /// force every caller to invent that meaning. Size and mtime may serve a caller as a cheap
    /// pre-filter; the digest decides.
    pub(crate) fn of(path: &Path) -> std::io::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(e) => return Err(e),
        };
        Ok(Self::of_bytes(&bytes))
    }

    /// The generation of bytes already in hand, which a writer computes for the exact bytes it is
    /// committing. `persist` returns this instead of re-reading the disk.
    pub(crate) fn of_bytes(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha384::new();
        hasher.update(bytes);
        Self::Sha384(format!("{:x}", hasher.finalize()))
    }
}

// The lock primitives

/// The lock address for a secrets dir.
pub(crate) fn credential_lock_path(secrets_dir: &Path) -> PathBuf {
    secrets_dir.join(CREDENTIAL_LOCK_FILE_NAME)
}

/// A held cross-process credential lock. The lock file is only an address; the lock is an OS
/// advisory lock (`std::fs::File::try_lock`: flock on Unix, `LockFileEx` on Windows) that the
/// kernel releases on process death, so a crashed holder's leftover file is never a held lock
/// (`crates/aruna/src/store_open.rs`, the same lifecycle).
///
/// The zero-byte lock file is left in place by design: unlinking a lock file while another
/// process holds or waits on it splits the lock across two inodes on Unix.
pub(crate) struct CredentialLock {
    file: std::fs::File,
    /// The secrets directory this lock guards, the lock path's own parent, kept so a holder can be
    /// asked which directory it proves. Stored exactly as the caller spelled it, with no
    /// `canonicalize`: that is a second I/O with its own failure modes (and refuses to answer for
    /// a path that does not exist yet) on a value this type only compares. `None` only for a lock
    /// path with no parent at all (a filesystem root, which is not a lock file); it matches no
    /// directory, which is the fail-closed direction.
    guards: Option<PathBuf>,
}

impl std::fmt::Debug for CredentialLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialLock(held)")
    }
}

impl CredentialLock {
    /// Acquire the lock, bounded. The lock file is opened fresh on every call, never from a
    /// cached handle: flock attaches to the open file description, so re-locking a cached handle
    /// is a no-op conversion, not exclusion.
    ///
    /// Non-blocking attempts every [`CREDENTIAL_LOCK_POLL`] until `deadline` elapses, measured
    /// monotonically from entry; expiry is a typed [`RefreshLocalError::LockTimeout`]. The
    /// blocking `lock()` call is never used, since a hang has no cure a person can act on.
    pub(crate) fn try_acquire(path: &Path, deadline: Duration) -> Result<Self, RefreshLocalError> {
        let file = open_lock_address(path)?;
        let started = std::time::Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Self {
                        file,
                        guards: path.parent().map(Path::to_path_buf),
                    })
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(RefreshLocalError::LockUnavailable {
                        path: path.to_path_buf(),
                        reason: LocalIoReason(e.kind()),
                    })
                }
            }
            // The budget is checked before sleeping, so the total wait is the budget and not the
            // budget plus one poll.
            if started.elapsed() >= deadline {
                return Err(RefreshLocalError::LockTimeout {
                    path: path.to_path_buf(),
                    waited: started.elapsed(),
                });
            }
            std::thread::sleep(CREDENTIAL_LOCK_POLL);
        }
    }
}

impl CredentialLock {
    /// Does this held lock guard `secrets_dir`?
    ///
    /// This is a path comparison and no more: it answers "was this lock taken at
    /// `<secrets_dir>/credential.lock` as that directory was spelled here", not "is this the same
    /// directory on disk". Two spellings of one directory (a symlink, a relative path, a Windows
    /// short name) answer `false` and the admission refuses. That is the fail-closed direction and
    /// not reachable in this app, where every caller derives both the lock path and the
    /// `secrets_dir` argument from the same `SessionConfig` field.
    pub(crate) fn guards(&self, secrets_dir: &Path) -> bool {
        self.guards.as_deref() == Some(secrets_dir)
    }
}

impl Drop for CredentialLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Open the lock address, classifying it first: a FIFO, or a symlink to one, would block the open
/// before the advisory lock is reached (the same two precautions as `store_open.rs`, including
/// the read-only retry so a lock file that became 0444 is still acquirable).
fn open_lock_address(path: &Path) -> Result<std::fs::File, RefreshLocalError> {
    let refuse = |kind: std::io::ErrorKind| RefreshLocalError::LockUnavailable {
        path: path.to_path_buf(),
        reason: LocalIoReason(kind),
    };
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.is_file() {
            return Err(refuse(std::io::ErrorKind::InvalidInput));
        }
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            std::fs::OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|e| refuse(e.kind()))
        }
        Err(e) => Err(refuse(e.kind())),
    }
}

// Tests for this module follow. Each was written to fail against the naive implementation first.

#[cfg(test)]
mod tests {
    use super::*;

    const READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
    const MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
    const NOW: i64 = 1_700_000_000;
    const ORIGINAL: &str = "1//ORIGINAL-refresh-token-secret";

    fn ok_body(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"access_token":"ya29.ACCESS-SECRET","expires_in":3599,"token_type":"Bearer"{extra}}}"#
        )
        .into_bytes()
    }

    /// The default stored grant for the legacy witnesses: the PRODUCT's exact set, which is also
    /// what a conformant credential file carries.
    fn parse(body: &[u8]) -> RefreshOutcome {
        parse_refresh_response(200, body, NOW, ORIGINAL, &stored_scopes(&[MODIFY]))
    }

    fn err(status: u16, body: &str) -> RefreshOutcome {
        parse_refresh_response(status, body.as_bytes(), NOW, ORIGINAL, &stored_scopes(&[MODIFY]))
    }

    /// The one scope that can permanently delete (Google's scope reference) — never requested,
    /// refused at both doors, and here only as the thing the witnesses prove is refused.
    const FULL_MAILBOX: &str = "https://mail.google.com/";

    fn stored_scopes(scopes: &[&str]) -> BTreeSet<String> {
        scopes.iter().map(|s| (*s).to_string()).collect()
    }

    /// A grant record as the credential file carries it.
    fn grant_of(generation: u64, scopes: &[&str]) -> GrantProvenance {
        GrantProvenance {
            grant_generation: generation,
            provider_principal: "owner@example.com".to_string(),
            effective_scopes: stored_scopes(scopes),
        }
    }

    /// [`parse`] against an EXPLICIT stored grant — the reference the exact-set law compares to.
    fn parse_with(body: &[u8], stored: &BTreeSet<String>) -> RefreshOutcome {
        parse_refresh_response(200, body, NOW, ORIGINAL, stored)
    }

    /// The generation recorded in the on-disk ratchet, or `None` when there is no usable one.
    fn hw_of(dir: &Path) -> Option<u64> {
        let raw = std::fs::read(dir.join(GRANT_HIGH_WATER_FILE_NAME)).ok()?;
        serde_json::from_slice::<Value>(&raw)
            .ok()?
            .get("grant_generation")?
            .as_u64()
    }

    /// The cross-process credential lock, acquired for the duration of ONE admission — the
    /// PROOF parameter `admit_grant_generation` requires. Acquiring it inside
    /// the witness (rather than passing a shared handle) is deliberate in the race witness: the
    /// two raiser threads really do contend for the same OS advisory lock.
    fn held(dir: &Path) -> CredentialLock {
        CredentialLock::try_acquire(&credential_lock_path(dir), CREDENTIAL_LOCK_DEADLINE)
            .expect("the witness holds the one credential lock for its admission")
    }

    /// Minted by the engine's ONE guard (`aruna::test_temp`) — unique
    /// per call (it was pid + thread id, cleared only at the START of the next same-named call:
    /// one leaked dir per test per run), the tree removed when the guard drops. Bind it BEFORE
    /// any lock or file handle opened inside it.
    fn tempdir(tag: &str) -> aruna::test_temp::TempDir {
        aruna::test_temp::TempDir::new(&format!("photon-tr-{tag}"))
    }

    // -------------------------------------------------------------------------------------------
    // Expires_in is ATTESTED, never invented, and the arithmetic is CHECKED.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn absent_nonpositive_noninteger_and_unrepresentable_expires_in_all_refuse() {
        let cases: &[(&str, ContractViolation)] = &[
            (
                r#"{"access_token":"a","token_type":"Bearer"}"#,
                ContractViolation::ExpiresInAbsent,
            ),
            (
                r#"{"access_token":"a","token_type":"Bearer","expires_in":0}"#,
                ContractViolation::ExpiresInNonPositive,
            ),
            (
                r#"{"access_token":"a","token_type":"Bearer","expires_in":-1}"#,
                ContractViolation::ExpiresInNonPositive,
            ),
            (
                r#"{"access_token":"a","token_type":"Bearer","expires_in":"3600"}"#,
                ContractViolation::ExpiresInNotAnInteger,
            ),
            (
                r#"{"access_token":"a","token_type":"Bearer","expires_in":3600.5}"#,
                ContractViolation::ExpiresInNotAnInteger,
            ),
            // The 2**200 shape: 2**200 seconds.
            (
                r#"{"access_token":"a","token_type":"Bearer","expires_in":1606938044258990275541962092341162602522202993782792835301376}"#,
                ContractViolation::ExpiresInUnrepresentable,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(
                parse(body.as_bytes()),
                RefreshOutcome::Transient {
                    kind: TransientKind::ContractViolation(*expected)
                },
                "an unusable expires_in must REFUSE, never invent an expiry: {body}"
            );
        }
        // And the checked arithmetic is checked at the TOP of the range too, not only at 2^200.
        let body = format!(
            r#"{{"access_token":"a","token_type":"Bearer","expires_in":{}}}"#,
            i64::MAX
        );
        assert_eq!(
            parse_refresh_response(200, body.as_bytes(), 1, ORIGINAL, &stored_scopes(&[MODIFY])),
            RefreshOutcome::Transient {
                kind: TransientKind::ContractViolation(ContractViolation::ExpiresInUnrepresentable)
            },
            "now + expires_in must be CHECKED, never wrapped"
        );
    }

    // -------------------------------------------------------------------------------------------
    // The RFC 6749 §6 rotation survivor rule, both arms.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn the_rotation_survivor_rule_holds_on_both_arms() {
        let rotated = parse(&ok_body(r#","refresh_token":"1//REPLACEMENT-secret""#));
        let RefreshOutcome::Renewed {
            refresh_survivor, ..
        } = &rotated
        else {
            panic!("a rotated response renews: {rotated:?}");
        };
        assert_eq!(
            refresh_survivor.expose(),
            "1//REPLACEMENT-secret",
            "a RETURNED replacement must be the survivor — persisting the original after a \
             provider rotation parks a DEAD credential while reporting success"
        );

        for absent_arm in [ok_body(""), ok_body(r#","refresh_token":"   ""#)] {
            let kept = parse(&absent_arm);
            let RefreshOutcome::Renewed {
                refresh_survivor, ..
            } = &kept
            else {
                panic!("an unrotated response renews: {kept:?}");
            };
            assert_eq!(
                refresh_survivor.expose(),
                ORIGINAL,
                "an absent or blank replacement keeps the ORIGINAL"
            );
        }
    }

    // -------------------------------------------------------------------------------------------
    // A failure BEFORE the rename leaves the old file byte-identical.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn a_write_that_never_commits_leaves_the_old_credential_byte_identical() {
        let dir = tempdir("w3");
        let path = dir.join(CREDENTIAL_FILE_NAME);
        let old = b"{\"access_token\":\"OLD\",\"refresh_token\":\"OLD-R\",\"expires_at\":1}\n";
        std::fs::write(&path, old).expect("seed the old credential");

        {
            let mut writer = open_credential_writer(&path).expect("the writer opens");
            writer
                .write_all(b"CORRUPT-HALF-WRITTEN-CREDENTIAL")
                .expect("bytes go to the writer");
            // Dropped without commit — the atomic-persistence property is that the visible file never moved.
        }

        assert_eq!(
            std::fs::read(&path).expect("the old credential is still readable"),
            old.to_vec(),
            "a write that fails before the atomic replace must leave the EXISTING credential \
             byte-identical (process-visible; no power-loss claim is made)"
        );
    }

    // -------------------------------------------------------------------------------------------
    // No secret byte reaches any reason, error, or Debug rendering.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn no_secret_bytes_reach_any_reason_or_debug_rendering() {
        let secrets = [
            "ya29.ACCESS-SECRET",
            "1//REPLACEMENT-secret",
            ORIGINAL,
            "CLIENT-SECRET-VALUE",
            "CLIENT-ID-VALUE",
        ];

        let renewed = parse(&ok_body(r#","refresh_token":"1//REPLACEMENT-secret""#));
        let mut rendered = vec![
            renewed.reason_sentence(),
            format!("{renewed:?}"),
            format!("{:?}", renewed.cure()),
        ];

        let dir = tempdir("w5");
        std::fs::write(
            dir.join(CLIENT_SECRET_FILE_NAME),
            r#"{"installed":{"client_id":"CLIENT-ID-VALUE","client_secret":"CLIENT-SECRET-VALUE","token_uri":"https://oauth2.googleapis.com/token"}}"#,
        )
        .expect("seed the client file");
        let client = ClientConfig::load(&dir).expect("the client file loads");
        rendered.push(format!("{client:?}"));
        rendered.push(format!("{:?}", client.client_secret()));

        let local = RefreshLocalError::WriteFailed {
            path: dir.join(CREDENTIAL_FILE_NAME),
            reason: LocalIoReason(std::io::ErrorKind::PermissionDenied),
        };
        rendered.push(local.reason_sentence());
        rendered.push(format!("{local:?}"));

        for text in &rendered {
            for secret in secrets {
                assert!(
                    !text.contains(secret),
                    "a secret reached a rendered string: {text}"
                );
            }
        }
    }

    // -------------------------------------------------------------------------------------------
    // The client config refuses loudly, and nothing is POSTed.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn a_missing_or_web_client_config_refuses_loudly() {
        let dir = tempdir("w9");

        let missing = ClientConfig::load(&dir).expect_err("an absent client file refuses");
        let RefreshLocalError::ClientConfig(e) = &missing else {
            panic!("a client-file failure is a ClientConfig local error: {missing:?}");
        };
        assert!(matches!(e.shape, ClientConfigShape::Unreadable(_)));
        assert!(
            e.reason_sentence().contains(CLIENT_SECRET_FILE_NAME),
            "the reason names the PATH: {}",
            e.reason_sentence()
        );

        std::fs::write(
            dir.join(CLIENT_SECRET_FILE_NAME),
            r#"{"web":{"client_id":"w","client_secret":"s","token_uri":"https://oauth2.googleapis.com/token"}}"#,
        )
        .expect("seed a web client file");
        let web = ClientConfig::load(&dir).expect_err("a WEB client refuses BY NAME");
        let RefreshLocalError::ClientConfig(e) = &web else {
            panic!("expected a ClientConfig local error: {web:?}");
        };
        assert_eq!(
            e.shape,
            ClientConfigShape::WebClient,
            "an `installed` entry is the ONLY accepted client shape \
             (gmail_drill_mint.py `client_from_config`)"
        );

        std::fs::write(
            dir.join(CLIENT_SECRET_FILE_NAME),
            r#"{"installed":{"client_id":"i","client_secret":"s","token_uri":"https://evil.example/token"}}"#,
        )
        .expect("seed a redirected token_uri");
        let moved = ClientConfig::load(&dir).expect_err("a disagreeing token_uri refuses");
        let RefreshLocalError::ClientConfig(e) = &moved else {
            panic!("expected a ClientConfig local error: {moved:?}");
        };
        assert!(
            matches!(e.shape, ClientConfigShape::TokenUriMismatch { .. }),
            "a client file must not be able to move the endpoint: {:?}",
            e.shape
        );
        let sentence = e.reason_sentence();
        assert!(
            sentence.contains("https://evil.example/token") && sentence.contains(TOKEN_ENDPOINT),
            "the refusal names BOTH the file's token_uri and the compiled endpoint: {sentence}"
        );
    }

    // -------------------------------------------------------------------------------------------
    // Token_type.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn a_missing_token_type_refuses() {
        assert_eq!(
            parse(br#"{"access_token":"a","expires_in":3599}"#),
            RefreshOutcome::Transient {
                kind: TransientKind::ContractViolation(ContractViolation::TokenTypeAbsent)
            },
            "RFC 6749 §5.1 makes token_type REQUIRED; an absent one is not a Bearer token"
        );
    }

    #[test]
    fn a_non_bearer_token_type_refuses_and_lowercase_bearer_is_accepted() {
        assert_eq!(
            parse(br#"{"access_token":"a","expires_in":3599,"token_type":"MAC"}"#),
            RefreshOutcome::Transient {
                kind: TransientKind::ContractViolation(ContractViolation::TokenTypeNotBearer)
            },
            "a non-Bearer token_type must refuse (RFC 6749 §7.1)"
        );
        assert!(
            matches!(
                parse(br#"{"access_token":"a","expires_in":3599,"token_type":"bearer"}"#),
                RefreshOutcome::Renewed { .. }
            ),
            "token_type is compared case-INSENSITIVELY (RFC 6749 §5.1)"
        );
    }

    // -------------------------------------------------------------------------------------------
    // The classification table.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn invalid_client_is_a_client_config_outcome_never_a_re_mint() {
        let outcome = err(401, r#"{"error":"invalid_client"}"#);
        assert!(
            matches!(outcome, RefreshOutcome::ClientConfig { .. }),
            "invalid_client is the APP's configuration, not the user's grant: {outcome:?}"
        );
        assert_eq!(outcome.cure(), Cure::ClientConfig);
        assert!(
            !outcome.reason_sentence().contains("re-mint via"),
            "a client-configuration failure must never prescribe a re-mint: {}",
            outcome.reason_sentence()
        );
    }

    #[test]
    fn admin_policy_is_provider_policy_and_an_unmapped_4xx_is_unknown_denied() {
        // Evidence-exact status: admin_policy_enforced is established at 400.
        let policy = err(400, r#"{"error":"admin_policy_enforced"}"#);
        assert!(
            matches!(policy, RefreshOutcome::ProviderPolicy { .. }),
            "admin_policy_enforced is persistent provider policy: {policy:?}"
        );
        assert_eq!(policy.cure(), Cure::AdminPolicy);
        assert!(
            !policy.latches(),
            "a policy refusal PACES, never latches (r4 F5, design §3-S2 amended): its cure is \
             applied in the console — a medium the token-file latch key never observes, so a \
             file-keyed latch would replay the stale refusal after the admin grants access"
        );

        let unknown = err(400, r#"{"error":"some_code_we_do_not_map"}"#);
        let RefreshOutcome::UnknownDenied { status, code } = &unknown else {
            panic!("an unmapped 4xx is honestly UNDETERMINED: {unknown:?}");
        };
        assert_eq!(*status, 400);
        assert_eq!(
            code.as_ref().map(Sanitized::as_str),
            Some("some_code_we_do_not_map"),
            "the unknown code rides the outcome LOSSLESSLY (r3 seat-3 F9)"
        );
        assert_eq!(unknown.cure(), Cure::Undetermined);
        assert!(
            !unknown.latches(),
            "UnknownDenied is NOT latched — it retries command-driven under the floor"
        );

        let bodyless = err(418, "");
        assert_eq!(
            bodyless,
            RefreshOutcome::UnknownDenied {
                status: 418,
                code: None
            },
            "an unparseable 4xx body still classifies BY STATUS, with the absence recorded"
        );
    }

    #[test]
    fn a_403_carrying_rate_limit_exceeded_is_transient() {
        let outcome = err(403, r#"{"error":"rate_limit_exceeded"}"#);
        let RefreshOutcome::Transient {
            kind: TransientKind::ProviderTransient(code),
        } = &outcome
        else {
            panic!("classification is by CODE + status, never status alone: {outcome:?}");
        };
        assert_eq!(code.as_str(), "rate_limit_exceeded");
        assert_eq!(outcome.cure(), Cure::RetryLater);
        assert!(!outcome.latches(), "a rate limit must never latch");

        // The generic 429 arm, classified BEFORE the generic-4xx rule (RFC 6585 §4).
        assert_eq!(
            err(429, r#"{"error":"unmapped_thing"}"#),
            RefreshOutcome::Transient {
                kind: TransientKind::RateLimited(429)
            },
            "429 is transient even when its code is not one we map"
        );
        assert_eq!(
            err(503, ""),
            RefreshOutcome::Transient {
                kind: TransientKind::ServerError(503)
            }
        );
    }

    #[test]
    fn every_error_code_maps_to_its_documented_outcome_and_cure() {
        struct Row {
            status: u16,
            code: &'static str,
            expect: fn(&RefreshOutcome) -> bool,
            cure: Cure,
            latches: bool,
        }
        let table: &[Row] = &[
            Row {
                status: 400,
                code: "invalid_grant",
                expect: |o| matches!(o, RefreshOutcome::ReauthRequired { .. }),
                cure: Cure::ReMint,
                latches: true,
            },
            Row {
                status: 401,
                code: "invalid_client",
                expect: |o| matches!(o, RefreshOutcome::ClientConfig { .. }),
                cure: Cure::ClientConfig,
                latches: false,
            },
            Row {
                status: 400,
                code: "unauthorized_client",
                expect: |o| matches!(o, RefreshOutcome::ClientConfig { .. }),
                cure: Cure::ClientConfig,
                latches: false,
            },
            Row {
                status: 400,
                code: "unsupported_grant_type",
                expect: |o| matches!(o, RefreshOutcome::ClientConfig { .. }),
                cure: Cure::ClientConfig,
                latches: false,
            },
            Row {
                status: 400,
                code: "invalid_request",
                expect: |o| matches!(o, RefreshOutcome::ClientConfig { .. }),
                cure: Cure::ClientConfig,
                latches: false,
            },
            Row {
                status: 403,
                code: "restricted_client",
                expect: |o| matches!(o, RefreshOutcome::ClientConfig { .. }),
                cure: Cure::ClientConfig,
                latches: false,
            },
            Row {
                // Evidence-exact per code: Google establishes this one at 400.
                status: 400,
                code: "admin_policy_enforced",
                expect: |o| matches!(o, RefreshOutcome::ProviderPolicy { .. }),
                cure: Cure::AdminPolicy,
                latches: false,
            },
            Row {
                // Device-Flow-scoped on the Token Endpoint
                // reference — not established for our refresh grant; honest UnknownDenied.
                status: 403,
                code: "access_denied",
                expect: |o| matches!(o, RefreshOutcome::UnknownDenied { .. }),
                cure: Cure::Undetermined,
                latches: false,
            },
            Row {
                status: 400,
                code: "invalid_scope",
                expect: |o| matches!(o, RefreshOutcome::InvalidScope),
                cure: Cure::ClientConfig,
                latches: false,
            },
            Row {
                status: 403,
                code: "rate_limit_exceeded",
                expect: |o| matches!(o, RefreshOutcome::Transient { .. }),
                cure: Cure::RetryLater,
                latches: false,
            },
            Row {
                status: 500,
                code: "internal_failure",
                expect: |o| matches!(o, RefreshOutcome::Transient { .. }),
                cure: Cure::RetryLater,
                latches: false,
            },
            Row {
                status: 400,
                code: "org_internal",
                expect: |o| matches!(o, RefreshOutcome::UnknownDenied { .. }),
                cure: Cure::Undetermined,
                latches: false,
            },
            Row {
                status: 400,
                code: "disallowed_useragent",
                expect: |o| matches!(o, RefreshOutcome::UnknownDenied { .. }),
                cure: Cure::Undetermined,
                latches: false,
            },
        ];

        for row in table {
            let outcome = err(row.status, &format!(r#"{{"error":"{}"}}"#, row.code));
            assert!(
                (row.expect)(&outcome),
                "{} @ {} mapped to the wrong outcome: {outcome:?}",
                row.code,
                row.status
            );
            assert_eq!(
                outcome.cure(),
                row.cure,
                "{} @ {} carries the wrong cure",
                row.code,
                row.status
            );
            assert_eq!(
                outcome.latches(),
                row.latches,
                "{} @ {} latches wrongly",
                row.code,
                row.status
            );
        }

        // invalid_scope's sentence asserts NO cure the provider's response did not establish.
        let scope = err(400, r#"{"error":"invalid_scope"}"#);
        let sentence = scope.reason_sentence();
        assert!(
            !sentence.contains("re-mint") && !sentence.contains("Re-mint"),
            "invalid_scope must not assert a re-mint cure: {sentence}"
        );
        assert!(
            sentence.contains("developer/console review"),
            "invalid_scope names what IS known: {sentence}"
        );
    }

    // -------------------------------------------------------------------------------------------
    // The bounded body.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn a_body_one_byte_over_the_cap_is_refused_bounded() {
        let body = vec![b'x'; MAX_REFRESH_BODY_BYTES + 1];
        assert_eq!(
            parse(&body),
            RefreshOutcome::Transient {
                kind: TransientKind::ContractViolation(ContractViolation::BodyTooLarge)
            },
            "over-cap is refused as a CONTRACT violation, named as such — not as a parse failure"
        );

        // Exactly the cap is not over it: the bound must be a bound, not an off-by-one refusal.
        let mut at_cap =
            br#"{"access_token":"a","expires_in":3599,"token_type":"Bearer","pad":""#.to_vec();
        at_cap.resize(MAX_REFRESH_BODY_BYTES - 2, b'p');
        at_cap.extend_from_slice(br#""}"#);
        assert_eq!(at_cap.len(), MAX_REFRESH_BODY_BYTES);
        assert!(
            matches!(parse(&at_cap), RefreshOutcome::Renewed { .. }),
            "a body of exactly the cap is still a valid response"
        );
    }

    // -------------------------------------------------------------------------------------------
    // Authority and the scope-rendering law.
    //
    // An earlier rule said "a SURPLUS
    // gmail.modify is a mismatch", because the product's exact set WAS `{gmail.readonly}` and
    // modify was send-capable authority on a no-send product. The product's set is now
    // `{gmail.modify}` — the triage verbs need it, and per Google's scope reference
    // gmail.modify "does not allow immediate, permanent deletion of threads and messages,
    // bypassing the trash", so it is the widest authority this product can hold while permanent
    // deletion stays impossible BY SCOPE. The law is unchanged and is what this test pins:
    // EXACT SET — stated-narrower is `missing`, stated-broader is `unexpected`, stated-equal
    // is `StatedAndMatched` — with ONE change of reference: the comparison is against the
    // STORED grant (RFC 6749 §6: a refresh "MUST NOT include any scope not originally
    // granted": an omitted scope IS the original grant), never the compiled constant.
    // The test below is the witness for that reference.
    //
    // Before the fix: `parse_refresh_response` took four arguments and compared against
    // `REQUIRED_SCOPES` — there was no stored set to pass, and the constant was readonly.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn the_exact_set_law_holds_against_the_stored_grant_and_renders_only_local_labels() {
        let stored = stored_scopes(&[MODIFY]);

        // (a) STATED NARROWER — the provider says it granted less than the record holds.
        let narrowed = parse_with(&ok_body(&format!(r#","scope":"{READONLY}""#)), &stored);
        let RefreshOutcome::AuthorityMismatch {
            missing,
            unexpected,
        } = &narrowed
        else {
            panic!("a stated narrower grant is not this lane's authority: {narrowed:?}");
        };
        assert_eq!(missing.len(), 1, "the triage authority is MISSING from the stated grant");
        assert_eq!(unexpected.len(), 1, "and the read-only scope is UNEXPECTED in it");
        assert_eq!(narrowed.cure(), Cure::ReMint);
        assert!(
            narrowed.latches(),
            "an authority mismatch latches to the file generation: its cure rewrites that file"
        );
        let sentence = narrowed.reason_sentence();
        assert!(
            sentence.contains("read + triage authority")
                && sentence.contains("read-only mailbox authority"),
            "both sides render as Photon's OWN labels: {sentence}"
        );
        assert!(
            !sentence.contains("googleapis.com") && !sentence.contains("gmail."),
            "a remote scope URI must never be echoed into a rendered string (W41): {sentence}"
        );

        // (b) STATED BROADER, carrying the one scope that could permanently delete.
        let broadened = parse_with(
            &ok_body(&format!(r#","scope":"{MODIFY} {FULL_MAILBOX}""#)),
            &stored,
        );
        let RefreshOutcome::AuthorityMismatch {
            missing,
            unexpected,
        } = &broadened
        else {
            panic!("EXACT SET, not missing-only: a SURPLUS scope fails this contract: {broadened:?}");
        };
        assert!(missing.is_empty());
        assert_eq!(unexpected.len(), 1);
        assert_eq!(broadened.cure(), Cure::ReMint);
        let sentence = broadened.reason_sentence();
        assert!(
            sentence.contains("full mailbox incl. permanent delete — never requested"),
            "the surplus renders as the label that says what it WOULD have bought: {sentence}"
        );
        assert!(
            !sentence.contains("mail.google.com"),
            "a remote scope URI must never be echoed into a rendered string: {sentence}"
        );

        // (c) STATED AND EQUAL to the stored grant.
        let matched = parse_with(&ok_body(&format!(r#","scope":"{MODIFY}""#)), &stored);
        let RefreshOutcome::Renewed { scope_confirmed, .. } = &matched else {
            panic!("a stated grant equal to the stored one renews: {matched:?}");
        };
        assert_eq!(*scope_confirmed, ScopeConfirmation::StatedAndMatched);
    }

    /// A token
    /// response that REPEATS a member name is refused before any member is read — as ambiguous
    /// (RFC 8259 §4; RFC 6749 §3.2 for the parameters it defines, per its erratum 5708).
    /// Before the fix `serde_json::Value` collapsed the repeat last-wins, so the WIRE ORDER of two `scope`
    /// members decided admission: broad-then-exact ADMITTED (`Renewed`, `StatedAndMatched`) a
    /// token whose stated authority included the full-mailbox scope; exact-then-broad refused a
    /// grant that was fine (`AuthorityMismatch`). Failed before the fix in BOTH orders.
    #[test]
    fn repeated_scope_member_is_refused_in_both_orders() {
        for body in [
            ok_body(&format!(r#","scope":"{FULL_MAILBOX}","scope":"{MODIFY}""#)),
            ok_body(&format!(r#","scope":"{MODIFY}","scope":"{FULL_MAILBOX}""#)),
        ] {
            let text = String::from_utf8(body.clone()).expect("the fixture is UTF-8");
            assert!(
                serde_json::from_str::<Value>(&text).is_ok(),
                "the fixture must be well-formed JSON (serde_json's Value collapses the repeat,                  it does not refuse it), or the witness proves nothing: {text}"
            );
            assert_eq!(
                parse(&body),
                violation(ContractViolation::BodyRepeatsMember),
                "a repeated `scope` must be refused as a contract violation regardless of which                  member comes last — wire order may never decide admission: {text}"
            );
        }
    }

    /// The complement form: the refusal is on REPETITION of ANY name, never an
    /// enumeration of the names we happen to read — `access_token`, `expires_in`, and a member
    /// this door never consults all refuse the same way.
    #[test]
    fn any_repeated_member_name_is_refused_not_only_scope() {
        for body in [
            ok_body(r#","access_token":"ya29.OTHER""#),
            ok_body(r#","expires_in":1"#),
            ok_body(r#","id_token":"x","id_token":"y""#),
        ] {
            let text = String::from_utf8(body.clone()).expect("the fixture is UTF-8");
            assert_eq!(
                parse(&body),
                violation(ContractViolation::BodyRepeatsMember),
                "any repeated member name is refused: {text}"
            );
        }
    }

    /// ONE reader for the token endpoint's response, both branches: an error body that repeats
    /// `error` is the same nonconforming shape (RFC 6749 §3.2 governs the response, not only its success
    /// form), and a repeat that could flip a terminal denial into a transient one is refused as a
    /// contract violation rather than read last-wins.
    #[test]
    fn an_error_body_with_a_repeated_member_is_a_contract_violation() {
        assert_eq!(
            err(400, r#"{"error":"invalid_grant","error":"rate_limit_exceeded"}"#),
            violation(ContractViolation::BodyRepeatsMember),
        );
        assert_eq!(
            err(400, r#"{"error":"rate_limit_exceeded","error":"invalid_grant"}"#),
            violation(ContractViolation::BodyRepeatsMember),
        );
    }

    /// Before the fix, the visitor read the ENTRY
    /// (key + value) before the duplicate check, so a repeat whose SECOND value is malformed
    /// (`1e999` does not fit a `Value` number) failed value-deserialization first and
    /// classified `NotAnObject` — refused either way, but the classification claim ("a repeat
    /// is refused before any member is read") was false. The key is now checked before the
    /// value is touched, so the repeat wins the race in both orders.
    #[test]
    fn a_repeat_with_a_malformed_second_value_is_still_classified_as_a_repeat() {
        // The repeat is DETECTED AT THE KEY, before the second value is deserialized —
        // Both value flavours.
        for body in [
            ok_body(r#","scope":"BROAD","scope":1e999"#),
            ok_body(r#","scope":"BROAD","scope":{"deep":1e999}"#),
        ] {
            let text = String::from_utf8(body.clone()).expect("the fixture is UTF-8");
            assert_eq!(
                parse(&body),
                violation(ContractViolation::BodyRepeatsMember),
                "the repeated NAME decides the classification once the repeat is seen: {text}"
            );
        }
        // Honesty bound, asserted so the claim cannot silently widen: a malformed value that
        // comes BEFORE any repeat is a body error — no repeat has been read yet, and the
        // classification says so. (Refused either way; the claim is about ORDER, not rescue.)
        assert_eq!(
            parse(&ok_body(r#","scope":1e999,"scope":"BROAD""#)),
            violation(ContractViolation::BodyNotAnObject),
        );
    }

    /// RFC 8259 §8.3 (opened at the RFC Editor, r6 sweep): names are compared AFTER unescaping,
    /// code unit by code unit — so an ESCAPED spelling of a name already present (`"scope"`
    /// beside `"scope"`) is the same name and collides in the visitor's `String` key. The
    /// classic way past a textual name comparison; refused here in both orders.
    /// An earlier version of this fixture had lost its backslash-u escape
    /// in a heredoc — both names read literal `"scope"`, duplicating the plain repeated-scope test and proving
    /// nothing about unescaping. The escaped spelling is now ASSEMBLED AT RUNTIME from the
    /// backslash's char code, so no source-level escape exists for any transport (heredoc,
    /// tool argument, copy-paste) to eat — and the first assert makes the fixture
    /// self-witnessing: the body text must carry the escape or the test fails loudly.
    #[test]
    fn an_escaped_duplicate_name_is_the_same_name_and_is_refused() {
        let backslash = char::from(0x5c);
        let escaped_scope = format!("sc{backslash}u006fpe");
        for body in [
            ok_body(&format!(r#","scope":"{FULL_MAILBOX}","{escaped_scope}":"{MODIFY}""#)),
            ok_body(&format!(r#","{escaped_scope}":"{FULL_MAILBOX}","scope":"{MODIFY}""#)),
        ] {
            let text = String::from_utf8(body.clone()).expect("the fixture is UTF-8");
            assert!(
                text.contains(&escaped_scope),
                "the fixture itself must carry the escaped spelling: {text}"
            );
            assert_eq!(
                parse(&body),
                violation(ContractViolation::BodyRepeatsMember),
                "an escaped duplicate is a duplicate: {text}"
            );
        }
    }

    /// The tolerance that stays (declared, RFC 6749 §5.1 extension members): UNKNOWN members are
    /// still admitted — the refusal is on repetition, never on vocabulary.
    #[test]
    fn unknown_members_remain_tolerated_once_each() {
        let body = ok_body(&format!(r#","scope":"{MODIFY}","id_token":"x","refresh_token_expires_in":3600"#));
        assert!(
            matches!(parse(&body), RefreshOutcome::Renewed { .. }),
            "unknown members occurring once are tolerated"
        );
    }

    #[test]
    fn a_present_but_empty_scope_member_is_contract_violating_not_an_authority_mismatch() {
        for body in [
            // present-but-empty · whitespace-only · an empty member between two SPs · a tab, which
            // is not the ABNF's separator and is not an NQCHAR either.
            ok_body(r#","scope":"""#),
            ok_body(r#","scope":"   ""#),
            ok_body(&format!(r#","scope":"{READONLY}  {READONLY}""#)),
            ok_body(&format!(r#","scope":"{READONLY}\t{READONLY}""#)),
        ] {
            let text = String::from_utf8(body.clone()).expect("the fixture is UTF-8");
            assert!(
                serde_json::from_str::<Value>(&text).is_ok(),
                "the fixture must be well-formed JSON, or the witness proves nothing: {text}"
            );
            let outcome = parse(&body);
            assert_eq!(
                outcome,
                RefreshOutcome::Transient {
                    kind: TransientKind::ContractViolation(ContractViolation::ScopeMalformed)
                },
                "a MALFORMED scope member (RFC 6749 §3.3 ABNF) is a contract violation and the \
                 malformed arm wins BEFORE the authority comparison — a malformed provider \
                 response must never send the operator to re-mint: {text}"
            );
            assert_eq!(outcome.cure(), Cure::RetryLater);
        }
    }

    // An access token that cannot become an `Authorization: Bearer` header
    // is a broken CONTRACT, never a credential: accepting it persists and publishes a live
    // cell whose every use fails at header construction, wedged until near expiry.
    #[test]
    fn an_access_token_with_control_bytes_is_a_contract_violation_not_a_credential() {
        for bad in ["abc\ntok", "abc\ttok", "abc tok", "caf\u{e9}tok"] {
            let body = serde_json::to_vec(&serde_json::json!({
                "access_token": bad,
                "expires_in": 3599,
                "token_type": "Bearer",
            }))
            .expect("fixture serializes");
            assert_eq!(
                parse(&body),
                RefreshOutcome::Transient {
                    kind: TransientKind::ContractViolation(
                        ContractViolation::AccessTokenNotHeaderSafe
                    )
                },
                "a non-header-safe access_token must refuse, not publish: {bad:?}"
            );
        }
    }

    // RFC 6749 §5.2 is the reference
    // for the STATUS×CODE MATRIX: a terminal OAuth code is
    // believed only at the status(es) its governing document establishes (HTTP 400
    // unless specified otherwise; `invalid_client` alone MAY arrive at 401). Before the fix,
    // `418 + invalid_grant` installed a generation-latched ReauthRequired (the harness held
    // the false re-mint through the latch with the POST counter at 1) and `403 +
    // invalid_grant` did the same. A recognized code at an unestablished status is the
    // honest, UNLATCHED `UnknownDenied` — refusal-not-guessing, in the direction that cannot
    // wrongly latch a terminal cure.
    #[test]
    fn a_terminal_code_is_believed_only_at_its_established_status() {
        let body = |code: &str| format!(r#"{{"error":"{code}"}}"#);
        // Established rows still classify terminal.
        assert!(matches!(
            err(400, &body("invalid_grant")),
            RefreshOutcome::ReauthRequired { .. }
        ));
        assert!(matches!(
            err(400, &body("invalid_client")),
            RefreshOutcome::ClientConfig { .. }
        ));
        assert!(matches!(
            err(401, &body("invalid_client")),
            RefreshOutcome::ClientConfig { .. }
        ));
        assert!(matches!(
            err(400, &body("admin_policy_enforced")),
            RefreshOutcome::ProviderPolicy { .. }
        ));
        assert!(matches!(err(400, &body("invalid_scope")), RefreshOutcome::InvalidScope));
        // Unestablished rows fall to UnknownDenied and never latch.
        for (status, code) in [
            (418u16, "invalid_grant"),
            (403, "invalid_grant"),
            (401, "invalid_grant"),
            (403, "invalid_client"),
            (418, "invalid_scope"),
            (401, "admin_policy_enforced"),
            (404, "unsupported_grant_type"),
            (451, "restricted_client"),
        ] {
            let outcome = err(status, &body(code));
            assert!(
                matches!(outcome, RefreshOutcome::UnknownDenied { .. }),
                "{code}@{status} must be UnknownDenied, got {outcome:?}"
            );
            assert!(!outcome.latches(), "{code}@{status} must never latch");
        }
    }

    // RFC 6750 §2.1:
    // "header-safe" is weaker than the Bearer credential grammar: b64token =
    // 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/") *"=". Before the fix, `ya29!outside`
    // and `ya29:BAD` were accepted, persistable, publishable — a live credential whose one
    // consumer (`Authorization: Bearer`) cannot be syntactically conforming.
    #[test]
    fn an_access_token_outside_the_bearer_grammar_is_refused() {
        for bad in [
            "ya29!outside-b64token",
            "ya29:BAD",
            "tok\"quote",
            "tok(paren)",
            "mid=equals-not-trailing",
            "=",
            "tok?",
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "access_token": bad,
                "expires_in": 3599,
                "token_type": "Bearer",
            }))
            .expect("fixture serializes");
            assert_eq!(
                parse(&body),
                RefreshOutcome::Transient {
                    kind: TransientKind::ContractViolation(
                        ContractViolation::AccessTokenNotBearerGrammar
                    )
                },
                "an access_token outside RFC 6750 b64token must refuse, not publish: {bad:?}"
            );
        }
        for good in ["ya29.a0AfH6-_~+/suffix==", "simple", "A", "a="] {
            let body = serde_json::to_vec(&serde_json::json!({
                "access_token": good,
                "expires_in": 3599,
                "token_type": "Bearer",
            }))
            .expect("fixture serializes");
            assert!(
                matches!(parse(&body), RefreshOutcome::Renewed { .. }),
                "a conforming b64token must still be accepted: {good:?}"
            );
        }
    }

    // {"expires_in": 3600.0} names a REPRESENTABLE value;
    // its defect is the float SPELLING (RFC 6749 App. A.14: expires-in = 1*DIGIT), and the
    // honest label for that is NOT-AN-INTEGER. The earlier integral-f64 arm returned
    // ExpiresInUnrepresentable — a false sentence the operator's toast then asserted. The
    // genuinely unrepresentable magnitude (the 2^200 shape) keeps its label.
    #[test]
    fn an_integral_float_expires_in_is_not_an_integer_never_unrepresentable() {
        for spelling in ["3600.0", "3.6e3"] {
            let body = format!(
                r#"{{"access_token":"tok","expires_in":{spelling},"token_type":"Bearer"}}"#
            );
            assert_eq!(
                parse(body.as_bytes()),
                RefreshOutcome::Transient {
                    kind: TransientKind::ContractViolation(
                        ContractViolation::ExpiresInNotAnInteger
                    )
                },
                "an integral float spelling is NOT-AN-INTEGER, never UNREPRESENTABLE: {spelling}"
            );
        }
    }

    // The vendor
    // rows are EVIDENCE-EXACT, per code, never a family union: the opened primaries establish
    // admin_policy_enforced@400, access_denied@403, restricted_client@403 individually, and
    // Google documents 401 deleted_client / 401 disabled_client under invalid_client's
    // only-the-developer-can-fix remedy (they used to fall to UnknownDenied → "retry", a cure
    // no retry delivers — falsification sentinel b). Unestablished cross-product rows refuse
    // as UnknownDenied (never latched): refuse-not-guess.
    #[test]
    fn vendor_rows_are_evidence_exact_per_code_never_a_family_union() {
        let body = |code: &str| format!(r#"{{"error":"{code}"}}"#);
        // Established per-code rows classify terminal.
        assert!(matches!(
            err(400, &body("admin_policy_enforced")),
            RefreshOutcome::ProviderPolicy { .. }
        ));
        // The Token Endpoint reference limits access_denied to
        // the DEVICE FLOW — not our refresh grant — so for this classifier it is not
        // established at any status and refuses honestly (superseding an earlier
        // admission, whose evidence was consent-surface scoped).
        assert!(matches!(
            err(403, &body("access_denied")),
            RefreshOutcome::UnknownDenied { .. }
        ));
        assert!(matches!(
            err(403, &body("restricted_client")),
            RefreshOutcome::ClientConfig { .. }
        ));
        assert!(matches!(
            err(401, &body("deleted_client")),
            RefreshOutcome::ClientConfig { .. }
        ));
        assert!(matches!(
            err(401, &body("disabled_client")),
            RefreshOutcome::ClientConfig { .. }
        ));
        // The union's unsupported cross-product rows fall to UnknownDenied.
        for (status, code) in [
            (403u16, "admin_policy_enforced"),
            (400, "access_denied"),
            (400, "restricted_client"),
            (400, "deleted_client"),
            (403, "disabled_client"),
        ] {
            let outcome = err(status, &body(code));
            assert!(
                matches!(outcome, RefreshOutcome::UnknownDenied { .. }),
                "{code}@{status} is not evidenced and must be UnknownDenied, got {outcome:?}"
            );
        }
    }

    // (Google's CURRENT Token Endpoint page, opened at
    // origin, lists org_internal at 403 under refresh errors, defeating the pinned
    // "authorization-endpoint vocabulary" comment; access_not_configured@400
    // carries Google's own contact-the-administrator remedy) — both are admitted at their
    // evidenced status with a policy cure whose sentence does not overclaim the actor; their
    // unevidenced cross-products stay UnknownDenied.
    #[test]
    fn org_internal_and_access_not_configured_are_policy_at_their_evidenced_status() {
        let body = |code: &str| format!(r#"{{"error":"{code}"}}"#);
        let org = err(403, &body("org_internal"));
        assert!(
            matches!(org, RefreshOutcome::ProviderPolicy { .. }),
            "org_internal@403 is on Google's current token-endpoint error list: {org:?}"
        );
        assert!(!org.latches(), "policy paces, never latches");
        let s = org.reason_sentence();
        assert!(
            s.contains("organization") && !s.contains("an administrator must grant"),
            "the org_internal sentence must name the org restriction without overclaiming the \
             fixing actor: {s}"
        );
        // (the Token Endpoint reference is the governing
        // primary): access_not_configured is documented on the SIGN-IN surface only — its
        // token-endpoint applicability for our grant is NOT established, so it refuses as the
        // honest UnknownDenied at every status.
        assert!(matches!(
            err(400, &body("access_not_configured")),
            RefreshOutcome::UnknownDenied { .. }
        ));
        assert!(matches!(err(400, &body("org_internal")), RefreshOutcome::UnknownDenied { .. }));
        assert!(matches!(
            err(403, &body("access_not_configured")),
            RefreshOutcome::UnknownDenied { .. }
        ));
    }

    // The uncertain-commit sentence states only
    // what was OBSERVED: with any digest unreadable nothing about rename/sync stages is known;
    // with both digests read and differing, the replacement IS known but durability is not.
    #[test]
    fn commit_uncertain_sentences_state_only_observed_facts() {
        let unknown = RefreshLocalError::CommitUncertain {
            path: PathBuf::from("x/gmail_readside_main_token.json"),
            observed_replaced: false,
        }
        .reason_sentence();
        assert!(
            !unknown.contains("reached") && !unknown.contains("directory sync"),
            "an unobserved commit failure must not assert a stage: {unknown}"
        );
        assert!(unknown.contains("could not"), "{unknown}");
        let replaced = RefreshLocalError::CommitUncertain {
            path: PathBuf::from("x/gmail_readside_main_token.json"),
            observed_replaced: true,
        }
        .reason_sentence();
        assert!(
            replaced.contains("replaced") && !replaced.contains("directory sync"),
            "an observed replacement names the fact and only the fact: {replaced}"
        );
    }

    // Persist RETURNS the generation of the bytes it WROTE —
    // no post-persist disk read exists to fail, so the Renewed-stamp file_gen=None state
    // cannot arise at all (assert what you WROTE, one step stronger than what you read).
    #[test]
    fn persist_returns_the_generation_of_the_written_bytes() {
        let dir = tempdir("persistgen");
        let written = persist_credential(&dir, "ya29.NEW", "1//SURV", 1_700_003_600, &grant_of(1, &[MODIFY]))
            .expect("persist succeeds");
        let on_disk = FileGen::of(&dir.join(CREDENTIAL_FILE_NAME)).expect("readable");
        assert_eq!(
            written, on_disk,
            "the returned generation IS the on-disk generation, derived without a re-read"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // SWEEP-FAIL-OPEN: the provenance guard must not degrade silently to
    // the shape its own test falsified: a failed sibling enumeration is an ERROR, not an empty
    // set (an empty snapshot would revert the sweep to convention-only and delete an
    // operator's pre-existing `.{base}.backup` after a transient EMFILE/permission blip).
    #[test]
    fn a_failed_sibling_enumeration_is_an_error_not_an_empty_snapshot() {
        // A guarded, never-created parent — absent by construction, owned all the same.
        let parent = aruna::test_temp::TempDir::uncreated("photon-nonexistent-parent");
        let missing = parent.join("gmail_readside_main_token.json");
        assert!(
            convention_temp_names(&missing).is_err(),
            "an unenumerable parent must surface as Err — silently answering 'no siblings' \
             re-arms the exact deletion the pre-write snapshot exists to prevent"
        );
    }

    // A commit
    // failure classifies as "unchanged" (RenameFailed's sentence) ONLY when BOTH digests were
    // READ and MATCH; any unreadable side is CommitUncertain — asserted vs known.
    #[test]
    fn a_commit_failure_with_an_unreadable_digest_is_uncertain_never_unchanged() {
        let g = |t: &str| FileGen::Sha384(format!("{t:0>96}"));
        assert!(commit_left_target_unchanged(&Some(g("a")), &Some(g("a"))));
        assert!(!commit_left_target_unchanged(&Some(g("a")), &Some(g("b"))));
        assert!(
            !commit_left_target_unchanged(&None, &None),
            "both digests unreadable: 'the existing file is unchanged' would be asserted, not known"
        );
        assert!(!commit_left_target_unchanged(&None, &Some(g("a"))));
        assert!(!commit_left_target_unchanged(&Some(g("a")), &None));
    }

    // The scrub marker is UNFORGEABLE and truncation is
    // MARKED. Before the fix, {"error":"unrecognized"} and a hostile code rendered byte-identical
    // sentences (the provider could forge "we scrubbed something here"), and an over-limit
    // clean code rendered as its silent 64-char prefix — a sentence asserting a code the
    // provider never sent.
    #[test]
    fn the_scrub_marker_is_unforgeable_and_truncation_is_marked() {
        // The marker itself fails the allowlist, so no provider byte sequence can RENDER as it.
        assert_eq!(Sanitized::new(UNRECOGNIZED).as_str(), UNRECOGNIZED);
        assert!(
            UNRECOGNIZED.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-'),
            "the marker must live outside its own alphabet or it is forgeable"
        );
        // A clean in-alphabet value renders as itself — DISTINCT from the marker.
        assert_ne!(Sanitized::new("unrecognized").as_str(), UNRECOGNIZED);
        // Truncation is visible: the render is the 64-char prefix plus a marker no allowlist
        // admits, never a silent prefix that reads as the complete code.
        let long = "a".repeat(84);
        let rendered = Sanitized::new(&long).as_str().to_string();
        assert_ne!(rendered, "a".repeat(64), "silent truncation reads as a complete code");
        assert!(
            rendered.starts_with(&"a".repeat(64)) && rendered.ends_with('\u{2026}'),
            "truncation carries the ellipsis marker: {rendered:?}"
        );
    }

    // Latent — every current `{:?}` site is
    // cfg(test): the derived Debug printed RAW remote scope strings verbatim, while the sentence-text
    // contract already establishes Debug as a rendering surface (a witness
    // asymmetry: one test iterated Debug, another checked the sentence only). The raw sets stay
    // lossless for comparisons; every RENDER — sentence and Debug alike — goes through the
    // scope-rendering law.
    #[test]
    fn the_debug_surface_never_carries_a_raw_remote_scope() {
        let hostile = "https://evil.example/<img/src=x/onerror=alert(1)>";
        let body = serde_json::to_vec(&serde_json::json!({
            "access_token": "tok",
            "expires_in": 3599,
            "token_type": "Bearer",
            "scope": format!("{READONLY} {hostile}"),
        }))
        .expect("fixture serializes");
        let outcome = parse(&body);
        assert!(matches!(outcome, RefreshOutcome::AuthorityMismatch { .. }));
        let debug = format!("{outcome:?}");
        assert!(
            !debug.contains("evil.example") && !debug.contains("onerror"),
            "Debug must render through the scope law, never the raw member: {debug}"
        );
        assert!(
            debug.contains(UNRECOGNIZED),
            "the scrubbed count marker rides Debug: {debug}"
        );
    }

    // A FAILED commit strands no secret-bearing temp sibling. The crate's
    // writer is already finalized when commit() fails, so its Drop does not discard the named
    // dotted temp — which carries BOTH tokens, one more copy per paced retry. This completes
    // the two-element failure-artifact set the persist neighborhood derives from the crate's
    // contract: the visible target (classified by re-digest) and the temp sibling
    // (cleaned, here).
    //
    // Windows-deterministic RED: renaming over a READ-ONLY target fails; on platforms where
    // the rename succeeds anyway (POSIX ignores target write-bits for rename), the failure
    // cannot be staged this way and the test returns early — labelled, not claimed.
    #[test]
    fn a_failed_commit_leaves_no_secret_bearing_temp_sibling() {
        let dir = tempdir("commitclean");
        let path = dir.join(CREDENTIAL_FILE_NAME);
        std::fs::write(&path, b"{}").expect("seed");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).expect("chmod");

        let result = persist_credential(&dir, "ya29.SECRET", "1//SECRET", 1_700_003_600, &grant_of(1, &[MODIFY]));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod back");
        }
        #[cfg(windows)]
        {
            let mut restore = std::fs::metadata(&path).expect("meta").permissions();
            // Windows-only: clearing the read-only ATTRIBUTE (clippy's world-writable concern
            // is the unix arm, handled above with an explicit 0600).
            #[allow(clippy::permissions_set_readonly_false)]
            restore.set_readonly(false);
            std::fs::set_permissions(&path, restore).expect("chmod back");
        }

        if result.is_ok() {
            // This platform replaced the read-only target — the failure cannot be staged here.
            return;
        }
        let strays: Vec<String> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != CREDENTIAL_FILE_NAME && !n.ends_with(".lock"))
            .collect();
        assert!(
            strays.is_empty(),
            "a failed commit must not strand secret-bearing temp files: {strays:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Commit-failure cleanup selects by
    // convention AND provenance: the earlier prefix-only sweep deleted
    // `.gmail_readside_main_token.json.backup` — an operator's unrelated artifact — while
    // handling an unrelated write error. And name-shape alone cannot close this: "backup" is
    // itself six alphanumerics, indistinguishable from a crate temp by name — so the sweep's
    // selection is the PRE-WRITE SNAPSHOT (a convention-shaped name that predates the writer
    // is not ours), and every pre-existing sibling here must survive while the writer's own
    // fresh temp is swept. Same Windows-deterministic staging as the sibling test above;
    // early-returns labelled where the platform lets the rename succeed.
    #[test]
    fn a_commit_failure_preserves_near_prefix_siblings_and_sweeps_exact_temps() {
        let dir = tempdir("commitexact");
        let path = dir.join(CREDENTIAL_FILE_NAME);
        std::fs::write(&path, b"{}").expect("seed");
        let backup = dir.join(format!(".{CREDENTIAL_FILE_NAME}.backup")); // 6 alnum — collides!
        let audit = dir.join(format!(".{CREDENTIAL_FILE_NAME}.audit77")); // 7 alnum ≠ convention
        let temp = dir.join(format!(".{CREDENTIAL_FILE_NAME}.uzg4pp")); // convention, PRE-EXISTING
        std::fs::write(&backup, b"operator-backup").expect("stage backup");
        std::fs::write(&audit, b"operator-audit").expect("stage audit");
        std::fs::write(&temp, b"operator-copy-shaped-like-a-temp").expect("stage temp");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).expect("chmod");

        let result = persist_credential(&dir, "ya29.SECRET", "1//SECRET", 1_700_003_600, &grant_of(1, &[MODIFY]));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod back");
        }
        #[cfg(windows)]
        {
            let mut restore = std::fs::metadata(&path).expect("meta").permissions();
            // Windows-only: clearing the read-only ATTRIBUTE (clippy's world-writable concern
            // is the unix arm, handled above with an explicit 0600).
            #[allow(clippy::permissions_set_readonly_false)]
            restore.set_readonly(false);
            std::fs::set_permissions(&path, restore).expect("chmod back");
        }

        if result.is_ok() {
            // This platform replaced the read-only target — the failure cannot be staged here.
            return;
        }
        assert!(
            backup.exists(),
            "a pre-existing sibling must survive even when its suffix collides with the convention"
        );
        assert!(audit.exists(), "a 7-char suffix is not the crate convention and must survive");
        assert!(
            temp.exists(),
            "a convention-shaped name that PREDATES the writer is not ours and must survive"
        );
        // The writer's own fresh temp (random convention name, created during this failed
        // write) is the ONE artifact the sweep owns — nothing beyond the staged set remains.
        let strays: Vec<String> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n != CREDENTIAL_FILE_NAME
                    && !n.ends_with(".lock")
                    && !n.ends_with(".backup")
                    && !n.ends_with(".audit77")
                    && !n.ends_with(".uzg4pp")
            })
            .collect();
        assert!(
            strays.is_empty(),
            "the writer's own failed-commit temp must still be swept: {strays:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The post-rename commit failure NEVER claims the old file survived (
    // Both uncertain arms).
    #[test]
    fn a_commit_uncertain_sentence_never_claims_the_file_is_unchanged() {
        for observed_replaced in [true, false] {
            let s = RefreshLocalError::CommitUncertain {
                path: PathBuf::from("x/gmail_readside_main_token.json"),
                observed_replaced,
            }
            .reason_sentence();
            assert!(!s.contains("unchanged"), "{s}");
        }
    }

    // The pre-wire client-build failure NEVER claims a write or a renewal;
    // the post-persist RebuildFailed sentence (which does claim them, truthfully there) must
    // not be borrowed for a state where nothing was dialled.
    #[test]
    fn a_client_build_failure_sentence_claims_no_dial_and_no_write() {
        let s = RefreshLocalError::ClientBuild.reason_sentence();
        assert!(s.contains("nothing was sent and nothing was written"), "{s}");
        assert!(!s.contains("renewed and written"), "{s}");
        assert!(
            RefreshLocalError::RebuildFailed {
                reason: "x".to_string()
            }
            .reason_sentence()
            .contains("renewed and written"),
            "the post-persist variant keeps its truthful claim — the two states stay distinct"
        );
    }

    // A terminal OAuth code is BELIEVED only on an applicable 4xx. RFC 6749
    // §5.2 defines the error response for the 400-class; a 5xx carrying `invalid_grant` is a
    // server fault (transient), a 429 is a rate limit (transient), and a 3xx / non-200 2xx is
    // not a token response at all (contract violation) — none of them may latch a terminal
    // re-mint/config/policy cure to the file generation. The KNOWN transient codes stay
    // status-blind on purpose (`rate_limit_exceeded` arrives at 403).
    #[test]
    fn a_terminal_code_on_a_non_4xx_status_never_latches() {
        let body = r#"{"error":"invalid_grant"}"#;
        assert_eq!(
            err(500, body),
            RefreshOutcome::Transient {
                kind: TransientKind::ServerError(500)
            },
            "a 5xx carrying invalid_grant is the server's fault, not the grant's"
        );
        assert_eq!(
            err(429, body),
            RefreshOutcome::Transient {
                kind: TransientKind::RateLimited(429)
            },
            "a 429 carrying invalid_grant is a rate limit, not a dead grant"
        );
        assert_eq!(
            err(303, body),
            violation(ContractViolation::StatusUnexpected),
            "a redirect is not a token response, whatever its body claims"
        );
        assert!(
            matches!(err(400, body), RefreshOutcome::ReauthRequired { .. }),
            "the believed form still latches: the same code on its RFC 6749 §5.2 status"
        );
        assert!(
            matches!(
                err(500, r#"{"error":"admin_policy_enforced"}"#),
                RefreshOutcome::Transient { .. }
            ),
            "the policy family is status-gated the same way"
        );
    }

    // The FULL NQCHAR grammar, not just "no whitespace". RFC 6749 §3.3:
    // scope-token = 1*NQCHAR = %x21 / %x23-5B / %x5D-7E — a double quote (%x22), backslash
    // (%x5C), control byte, or non-ASCII char is OUTSIDE the grammar, so the response is a broken
    // CONTRACT (transient scrutiny), never evidence about granted AUTHORITY (which the exact-set
    // comparison would convert into a terminal re-mint demand). The `</div>RE-MINT-NOW` member
    // is all NQCHAR and stays an AuthorityMismatch — the two witnesses partition the space.
    #[test]
    fn a_scope_member_with_a_non_nqchar_byte_is_contract_violating_not_authority_evidence() {
        for bad in ["with\"quote", "back\\slash", "bell\u{7}member", "caf\u{e9}"] {
            assert_eq!(
                scope_members(&format!("{READONLY} {bad}")),
                Err(ContractViolation::ScopeMalformed),
                "a non-NQCHAR byte in a scope member is malformed, not a member: {bad:?}"
            );
        }
        // End-to-end: the malformed arm wins BEFORE the authority comparison.
        // `\"` inside the raw string is the JSON ESCAPE — the parsed member carries a real quote.
        let body = ok_body(&format!(r#","scope":"{READONLY} with\"quote""#));
        let text = String::from_utf8(body.clone()).expect("the fixture is UTF-8");
        assert!(
            serde_json::from_str::<Value>(&text).is_ok(),
            "the fixture must be well-formed JSON, or the witness proves nothing: {text}"
        );
        assert_eq!(
            parse(&body),
            RefreshOutcome::Transient {
                kind: TransientKind::ContractViolation(ContractViolation::ScopeMalformed)
            },
            "a quote-bearing scope member classifies as a contract violation, never a mismatch"
        );
    }

    #[test]
    fn a_hostile_or_very_long_unknown_scope_never_reaches_a_rendered_string() {
        let hostile = "</div>RE-MINT-NOW";
        let very_long = "z".repeat(5_000);
        // The one KNOWN member is the product's own scope (the stored grant is
        // `{gmail.modify}`), so the two hostile members are exactly the two UNKNOWNS.
        let outcome = parse(&ok_body(&format!(
            r#","scope":"{MODIFY} {hostile} {very_long}""#
        )));
        let RefreshOutcome::AuthorityMismatch { unexpected, .. } = &outcome else {
            panic!("two surplus scopes are an authority mismatch: {outcome:?}");
        };
        assert_eq!(unexpected.len(), 2, "the RAW set is stored losslessly");

        let sentence = outcome.reason_sentence();
        assert!(
            !sentence.contains("</div>") && !sentence.contains("zzzz"),
            "no part of a remote scope may reach a rendered string: {sentence}"
        );
        assert!(
            sentence.contains(UNRECOGNIZED) && sentence.contains('2'),
            "unknown scopes render as the literal `unrecognized` plus a bounded COUNT: {sentence}"
        );
        assert!(sentence.len() < 600, "the rendering stays bounded: {sentence}");
    }

    // -------------------------------------------------------------------------------------------
    // The untrusted-text contract and the truthful reauth sentence.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn invalid_grant_with_invalid_rapt_is_reauth_required_with_a_sanitized_subtype() {
        let outcome = err(
            400,
            r#"{"error":"invalid_grant","error_subtype":"invalid_rapt"}"#,
        );
        let RefreshOutcome::ReauthRequired { subtype } = &outcome else {
            panic!("invalid_grant is a REAUTH requirement: {outcome:?}");
        };
        assert_eq!(subtype.as_ref().map(Sanitized::as_str), Some("invalid_rapt"));
        assert_eq!(outcome.cure(), Cure::ReMint);

        let sentence = outcome.reason_sentence();
        assert!(
            sentence.contains("reauthorization is required"),
            "the sentence must say what is KNOWN: {sentence}"
        );
        assert!(
            !sentence.contains("dead") && !sentence.contains("expired"),
            "RFC 6749 folds several causes under invalid_grant — the provider's response does not \
             prove the refresh token is dead: {sentence}"
        );
    }

    #[test]
    fn a_hostile_subtype_is_replaced_by_the_literal_unrecognized() {
        let outcome = err(
            400,
            r#"{"error":"invalid_grant","error_subtype":"</div>RE-MINT NOW"}"#,
        );
        let RefreshOutcome::ReauthRequired { subtype } = &outcome else {
            panic!("expected ReauthRequired: {outcome:?}");
        };
        assert_eq!(
            subtype.as_ref().map(Sanitized::as_str),
            Some(UNRECOGNIZED),
            "text failing the allowlist is REPLACED, never escaped-and-echoed"
        );
        for rendered in [outcome.reason_sentence(), format!("{outcome:?}")] {
            assert!(
                !rendered.contains("</div>") && !rendered.contains("RE-MINT NOW"),
                "the hostile bytes must not survive anywhere: {rendered}"
            );
        }
    }

    #[test]
    fn the_sanitizer_truncates_at_64_chars_and_allowlists_the_rest() {
        assert_eq!(Sanitized::new("invalid_rapt").as_str(), "invalid_rapt");
        assert_eq!(Sanitized::new("a-b_C9").as_str(), "a-b_C9");
        assert_eq!(Sanitized::new("").as_str(), UNRECOGNIZED);
        assert_eq!(Sanitized::new("has space").as_str(), UNRECOGNIZED);
        assert_eq!(Sanitized::new("dot.dot").as_str(), UNRECOGNIZED);
        assert_eq!(Sanitized::new("<script>").as_str(), UNRECOGNIZED);
        // Truncation keeps 64 payload chars and MARKS the cut: the
        // ellipsis is the 65th char, outside every allowlist, so it cannot be forged.
        let long = "a".repeat(200);
        assert_eq!(Sanitized::new(&long).as_str().chars().count(), 65);
        assert_eq!(Sanitized::new(&long).as_str(), format!("{}\u{2026}", "a".repeat(64)));
        // A hostile tail beyond the truncation point cannot smuggle itself in — the payload is
        // the clean 64-char prefix, the cut marked.
        let smuggle = format!("{}<img>", "a".repeat(64));
        assert_eq!(Sanitized::new(&smuggle).as_str(), format!("{}\u{2026}", "a".repeat(64)));
    }

    // -------------------------------------------------------------------------------------------
    // FileGen is a CONTENT digest.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn a_same_size_timestamp_restored_replacement_is_detected_by_digest() {
        let dir = tempdir("w42");
        let path = dir.join(CREDENTIAL_FILE_NAME);

        assert_eq!(
            FileGen::of(&path).expect("an absent file is a generation"),
            FileGen::Absent
        );

        std::fs::write(&path, b"AAAAAAAAAAAAAAAA").expect("seed");
        let before = FileGen::of(&path).expect("digest");
        let stamp = std::fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("mtime");

        // Same LENGTH, and the mtime is put back exactly — the shape size+mtime cannot see.
        std::fs::write(&path, b"BBBBBBBBBBBBBBBB").expect("replace");
        let handle = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("reopen");
        handle.set_modified(stamp).expect("restore the timestamp");
        drop(handle);

        let after = FileGen::of(&path).expect("digest");
        assert_ne!(
            before, after,
            "a same-size, timestamp-restored external replacement must still be DETECTED — which \
             is why the generation is a content digest and not size+mtime"
        );
        assert_eq!(
            std::fs::metadata(&path).expect("meta").modified().expect("mtime"),
            stamp,
            "the test's own premise: the timestamp really was restored"
        );
    }

    // -------------------------------------------------------------------------------------------
    // Unix file mode. (cfg(unix): there is no equivalent on Windows, where the file
    // inherits the directory ACL — stated, not claimed.)
    // -------------------------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn the_written_credential_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir("w24");
        persist_credential(&dir, "ya29.A", "1//R", 1_700_003_600, &grant_of(1, &[MODIFY])).expect("persist");
        let mode = std::fs::metadata(dir.join(CREDENTIAL_FILE_NAME))
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a freshly written credential is owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_an_existing_0644_credential_narrows_it_to_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir("w43");
        let path = dir.join(CREDENTIAL_FILE_NAME);
        std::fs::write(&path, b"{}").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        persist_credential(&dir, "ya29.A", "1//R", 1_700_003_600, &grant_of(1, &[MODIFY])).expect("persist");

        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the writer's DEFAULT preserves an existing file's mode, which would defeat narrowing \
             a pre-existing 0644 credential — preserve_mode(false) + mode(0o600) is what makes the \
             narrowing happen (r3 seat-3 F6)"
        );
    }

    #[test]
    fn only_the_one_credential_file_is_written() {
        let dir = tempdir("onefile");
        persist_credential(&dir, "ya29.A", "1//R", 1_700_003_600, &grant_of(1, &[MODIFY])).expect("persist");
        let names: BTreeSet<String> = std::fs::read_dir(&dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            BTreeSet::from([CREDENTIAL_FILE_NAME.to_string()]),
            "§3-S3: ONLY the main token file is written — no attestation bundle, no leftovers"
        );
        let doc: Value = serde_json::from_slice(
            &std::fs::read(dir.join(CREDENTIAL_FILE_NAME)).expect("read back"),
        )
        .expect("the persisted credential is JSON");
        assert_eq!(
            doc.as_object().expect("object").keys().collect::<Vec<_>>(),
            vec!["access_token", "expires_at", "grant", "refresh_token"],
            "exactly the mint script's v2 four-field shape (#75 S0 C1), in a deterministic order"
        );
        // SCOPE: this witness pins THIS writer's shape. It does not, and did not, establish that
        // both writers emit byte-equal documents — the mint pretty-prints and this writer is
        // compact, and the two also differ on duplicate scope members.
        // What holds across BOTH is a property of the READER, pinned by the loader's own
        // witnesses: whatever either writer emitted deserializes into the same exact set.
        assert_eq!(
            doc["grant"]
                .as_object()
                .expect("the grant is an object")
                .keys()
                .collect::<Vec<_>>(),
            vec!["effective_scopes", "grant_generation", "provider_principal"],
            "and the grant's own members are the three C1 names, deterministically ordered"
        );
    }

    // -------------------------------------------------------------------------------------------
    // The lock is BOUNDED.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn a_lock_held_by_another_handle_times_out_within_its_bound() {
        let dir = tempdir("w28");
        let path = credential_lock_path(&dir);
        assert_eq!(path.file_name().expect("name"), CREDENTIAL_LOCK_FILE_NAME);

        // A SECOND open file description on the same address. flock is per open-file-description,
        // and LockFileEx conflicts across handles, so this really is another writer.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .expect("the holder opens the address");
        holder.lock().expect("the holder takes the lock");

        let budget = Duration::from_millis(400);
        let started = std::time::Instant::now();
        let refused = CredentialLock::try_acquire(&path, budget)
            .expect_err("a held lock must REFUSE, not wait forever");
        let elapsed = started.elapsed();

        let RefreshLocalError::LockTimeout { waited, .. } = &refused else {
            panic!("a contended lock is a typed LockTimeout: {refused:?}");
        };
        assert!(*waited >= budget);
        assert!(
            elapsed < budget + Duration::from_secs(2),
            "acquisition is BOUNDED: waited {elapsed:?} against a {budget:?} budget"
        );
        assert!(
            refused.reason_sentence().contains("held by another writer"),
            "the timeout is LOUD: {}",
            refused.reason_sentence()
        );

        // Released by the holder ⇒ acquirable; and released again on OUR drop.
        holder.unlock().expect("release");
        let held = CredentialLock::try_acquire(&path, budget).expect("an uncontended lock is taken");
        drop(held);
        let again = CredentialLock::try_acquire(&path, budget).expect("the drop released it");
        drop(again);

        assert_eq!(
            CREDENTIAL_LOCK_DEADLINE,
            Duration::from_secs(5),
            "§3-S6's budget is 5 s"
        );
        assert_eq!(CREDENTIAL_LOCK_POLL, Duration::from_millis(100));
    }

    // -------------------------------------------------------------------------------------------
    // The client: the real reqwest path against a loopback fixture.
    // -------------------------------------------------------------------------------------------

    struct Fixture {
        port: u16,
        requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    fn spawn_fixture(status: u16, body: &'static str) -> Fixture {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = std::sync::Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    }
                    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
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
                    break;
                }
                recorder
                    .lock()
                    .expect("lock")
                    .push(String::from_utf8_lossy(&raw).to_string());
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.flush();
            }
        });
        Fixture { port, requests }
    }

    fn fixture_client_config() -> ClientConfig {
        ClientConfig {
            client_id: "CLIENT-ID-VALUE.apps.googleusercontent.com".to_string(),
            client_secret: SecretString::new("CLIENT-SECRET-VALUE"),
        }
    }

    // The expiry stamp is anchored at RESPONSE RECEIPT. The caller's
    // `now_unix` is captured at admission, before the lock wait, the config load, and the HTTP
    // round trip; applying `expires_in` to that stale base overstates the grant's remaining
    // life and can carry a stamp already inside the grace margin past the cell's recheck.
    #[test]
    fn the_expiry_stamp_is_based_on_response_receipt_not_the_callers_stale_clock() {
        let fixture = spawn_fixture(
            200,
            r#"{"access_token":"ya29.NEW","expires_in":3600,"token_type":"Bearer"}"#,
        );
        let client =
            RefreshClient::fixture(&format!("http://127.0.0.1:{}", fixture.port)).expect("client");
        let call_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_secs() as i64;
        // The caller's clock is 100 s STALE — modelling the elapsed admission-to-response time.
        let outcome = client.exchange(&fixture_client_config(), "1//rt", call_unix - 100, &stored_scopes(&[MODIFY]));
        let RefreshOutcome::Renewed { expires_at, .. } = outcome else {
            panic!("the fixture answers a well-formed renewal: {outcome:?}");
        };
        assert!(
            expires_at >= call_unix + 3600,
            "expiry anchored at RESPONSE RECEIPT, never the caller's stale base: got \
             {expires_at}, want >= {}",
            call_unix + 3600
        );
    }

    // The expiry base is anchored at HEADERS-ARRIVAL, not after the body.
    // The provider's `expires_in` lifetime began no later than when it generated the response;
    // sampling the clock after `read_to_end` inflates the persisted remaining life by the
    // body-transfer time (a 70 s grant with a 30 s transfer would read as 70 s left with ~40
    // remaining — past the 60 s margin). Never anchor a provider lifetime later than the
    // first bytes received.
    #[test]
    fn the_expiry_base_is_anchored_at_headers_not_after_a_slow_body() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 4096];
            // Read until the end of the request headers+form (best effort).
            let _ = stream.read(&mut buf);
            let body = r#"{"access_token":"ya29.SLOW","expires_in":3599,"token_type":"Bearer"}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.flush();
            // The body arrives TWO SECONDS after the headers.
            std::thread::sleep(Duration::from_secs(2));
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        });
        let client = RefreshClient::fixture(&format!("http://127.0.0.1:{port}"))
            .expect("a loopback fixture client builds");
        let call_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_secs() as i64;
        let outcome = client.exchange(&fixture_client_config(), "1//rt", call_unix, &stored_scopes(&[MODIFY]));
        let RefreshOutcome::Renewed { expires_at, .. } = outcome else {
            panic!("the slow-body fixture still renews: {outcome:?}");
        };
        assert!(
            expires_at <= call_unix + 3600,
            "the base is the HEADERS clock — a slow body must not inflate the grant: got \
             {expires_at}, want <= {}",
            call_unix + 3600
        );
    }

    #[test]
    fn the_exchange_posts_exactly_the_rfc6749_form_and_parses_the_reply() {
        let fixture = spawn_fixture(
            200,
            r#"{"access_token":"ya29.NEW","expires_in":3599,"token_type":"Bearer"}"#,
        );
        let client = RefreshClient::fixture(&format!("http://127.0.0.1:{}", fixture.port))
            .expect("a loopback fixture client builds");
        let outcome = client.exchange(&fixture_client_config(), ORIGINAL, NOW, &stored_scopes(&[MODIFY]));

        let RefreshOutcome::Renewed {
            access_token,
            expires_at,
            scope_confirmed,
            ..
        } = &outcome
        else {
            panic!("the fixture's 200 renews: {outcome:?}");
        };
        assert_eq!(access_token.expose(), "ya29.NEW");
        // The expiry base is RESPONSE RECEIPT, so this pin brackets the real
        // clock around the exchange instead of the caller's `NOW` fixture value.
        let after_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_secs() as i64;
        assert!(
            (*expires_at - 3599) <= after_unix && *expires_at >= NOW + 3599,
            "expires_in is applied to the receipt clock: got {expires_at}"
        );
        assert_eq!(*scope_confirmed, ScopeConfirmation::AbsentIdenticalGrant);

        let recorded = fixture.requests.lock().expect("lock").join("\n");
        assert!(recorded.starts_with("POST /token "), "{recorded}");
        assert!(recorded.contains("grant_type=refresh_token"));
        assert!(recorded.contains("client_id=CLIENT-ID-VALUE"));
        assert!(
            !recorded.to_ascii_lowercase().contains("scope="),
            "no `scope` parameter is sent — which is what decides invalid_scope's meaning"
        );
    }

    #[test]
    fn a_dead_endpoint_is_a_network_transient_not_a_denial() {
        // A test-OWNED ephemeral port, bound then closed, so the refusal is reliable.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let client = RefreshClient::fixture(&format!("http://127.0.0.1:{port}"))
            .expect("client builds");
        assert_eq!(
            client.exchange(&fixture_client_config(), ORIGINAL, NOW, &stored_scopes(&[MODIFY])),
            RefreshOutcome::Transient {
                kind: TransientKind::Network
            },
            "a network failure is never a provider verdict"
        );
    }

    #[test]
    fn the_fixture_constructor_refuses_plaintext_off_loopback() {
        assert!(RefreshClient::fixture("http://example.com").is_err());
        assert!(RefreshClient::fixture("http://10.0.0.5:8080").is_err());
        assert!(RefreshClient::fixture("http://127.0.0.1:9").is_ok());
        assert!(RefreshClient::fixture("https://oauth2.googleapis.com").is_ok());
    }

    #[test]
    fn the_cure_wire_spellings_are_the_frontend_contract() {
        for (cure, wire) in [
            (Cure::ReMint, "re_mint"),
            (Cure::ClientConfig, "client_config"),
            (Cure::AdminPolicy, "admin_policy"),
            (Cure::RetryLater, "retry_later"),
            (Cure::Undetermined, "undetermined"),
        ] {
            assert_eq!(
                serde_json::to_value(cure).expect("a cure serializes"),
                Value::String(wire.to_string())
            );
        }
    }

    #[test]
    fn the_no_refresh_token_outcome_latches_with_a_re_mint_cure() {
        let outcome = RefreshOutcome::no_refresh_token();
        assert_eq!(outcome.cure(), Cure::ReMint);
        assert_eq!(outcome.cure_owed(), Some(Cure::ReMint));
        assert!(outcome.latches());
        assert!(
            outcome.reason_sentence().contains("no refresh token"),
            "the refusal NAMES the absence: {}",
            outcome.reason_sentence()
        );
    }

    // ===========================================================================================
    // THE GRANT WITNESSES.
    //
    // The credential file now carries the GRANT that authorizes it. Two properties follow, and
    // these are their witnesses: (1) a grant generation below the recorded high-water is RETIRED
    // The rollback a restored backup performs is refused, not admitted; (2) the refresh door
    // compares the provider's stated scope against the STORED grant, never the compiled constant,
    // and rotation writes that grant back unchanged.
    //
    // OUT OF SCOPE, stated so nothing here reads as more than it is: `grant_high_water.json` is an
    // ordinary file in an ordinary directory. The user (or code running as them) deletes it and the ratchet resets.
    // This is tamper-EVIDENT against a restore/sync/backup agent
    // putting an old credential back; it is not tamper-PROOF against the operator's own hands,
    // and it is never labelled a control against them.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // A generation BELOW the high-water is a RETIRED grant.
    //
    // Before the fix: `admit_grant_generation` did not exist, and neither did the ratchet —
    // a pre-re-consent credential restored over a current one was simply the credential.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_generation_below_the_high_water_is_refused_as_a_retired_grant() {
        let dir = tempdir("g4");
        let hw = dir.join(GRANT_HIGH_WATER_FILE_NAME);
        std::fs::write(&hw, b"{\"grant_generation\": 5}\n").expect("seed the ratchet at 5");

        let err = admit_grant_generation(&dir, &grant_of(4, &[MODIFY]), &held(&dir))
            .expect_err("a superseded grant must never be admitted");
        let RefreshLocalError::GrantRetired {
            credential_generation,
            high_water,
            ..
        } = &err
        else {
            panic!("a retired grant is its OWN typed refusal, not a generic local failure: {err:?}");
        };
        assert_eq!((*credential_generation, *high_water), (4, 5));
        let sentence = err.reason_sentence();
        assert!(
            sentence.contains("gmail_drill_mint.py"),
            "the refusal carries the re-mint cure the operator can act on: {sentence}"
        );
        assert_eq!(
            hw_of(&dir),
            Some(5),
            "a REFUSAL never writes the ratchet down to the generation it just rejected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // THE PROOF MUST BE A PROOF OF *THIS* DIRECTORY'S LOCK.
    //
    // `held: &CredentialLock` is the compile-checked proof that the read-compare-replace of the
    // ratchet happens under the cross-process credential lock. But the type carried
    // only a FILE HANDLE, and a handle has no identity: it proved that SOME lock was held, never
    // that it was the lock guarding the directory whose ratchet is about to be raised. The
    // linearization the whole ratchet rests on is per-directory — it is the mint's
    // `<secrets>/credential.lock` — so a proof that does not name a directory is not a proof of
    // it.
    //
    // Stated plainly: this is a PROGRAMMING error, not an adversary. Nothing an attacker
    // sends reaches this parameter; it is reachable only by first-party code passing the wrong
    // handle. The refusal is hygiene made compile-adjacent, its cure is honestly `Undetermined`,
    // and it is never claimed as a control.
    //
    // Before the fix: `admit_grant_generation` returns `Ok` and RAISES `<tmp>/secrets`'s ratchet to
    // 7 while the only lock held is `<tmp>/other`'s.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_lock_on_another_directory_is_not_a_proof_for_this_directorys_admission() {
        let root = tempdir("91-lock-dir");
        let secrets = root.join("secrets");
        let other = root.join("other");
        std::fs::create_dir_all(&secrets).expect("the guarded dir");
        std::fs::create_dir_all(&other).expect("some other dir with its own lock");

        let elsewhere = held(&other);
        let err = admit_grant_generation(&secrets, &grant_of(7, &[MODIFY]), &elsewhere)
            .expect_err("a lock on another directory proves nothing about THIS admission");
        // The typed refusal, its cure and its sentence. (No failing run is claimed for THESE three
        // clauses: the variant did not exist before the fix, so the discriminating check is
        // the `expect_err` above — it returned `Ok()` and raised the ratchet.)
        let RefreshLocalError::AdmissionLockMismatch {
            held: guarded,
            secrets_dir,
        } = &err
        else {
            panic!("an unproven admission is its OWN typed refusal, never a generic one: {err:?}");
        };
        assert_eq!(
            (guarded.as_deref(), secrets_dir.as_path()),
            (Some(other.as_path()), secrets.as_path()),
            "the refusal names WHICH directory was proven and WHICH was admitted"
        );
        assert_eq!(
            err.cure(),
            Cure::Undetermined,
            "a caller that handed over the wrong lock is not something an operator can cure"
        );
        let sentence = err.reason_sentence();
        assert!(
            sentence.contains("nothing was changed"),
            "the sentence states the no-write fact: {sentence}"
        );
        assert!(
            !sentence.contains("gmail_drill_mint.py"),
            "an internal fault must never be dressed as a re-mint demand: {sentence}"
        );
        assert_eq!(
            hw_of(&secrets),
            None,
            "a refused admission writes NOTHING — the ratchet it could not prove is untouched"
        );
        assert!(
            !grant_high_water_path(&secrets).exists(),
            "not even an empty ratchet file is created"
        );

        // And the honest lock IS accepted for the same admission — the check refuses a mismatch,
        // it does not refuse admission.
        drop(elsewhere);
        admit_grant_generation(&secrets, &grant_of(7, &[MODIFY]), &held(&secrets))
            .expect("the lock guarding this very directory is the proof this admission needs");
        assert_eq!(hw_of(&secrets), Some(7));

        let _ = std::fs::remove_dir_all(&root);
    }

    // -------------------------------------------------------------------------------------------
    // The ratchet is raised MAX-ONLY, and an EQUAL generation writes nothing.
    //
    // The shape is the house's, adopted not invented: `attempt.rs`'s `clamped_now` (max-only
    // sticky clock) and `store_open.rs`'s `ingest_revision_seq.high_water = MAX(...)`, plus the
    // the rule "raised MAX-ONLY, never a plain assignment that can
    // write it DOWN". The no-write arm is witnessed at the BYTES: a byte-distinct but
    // semantically EQUAL ratchet parked in the file must survive an equal-generation admission
    // untouched.
    //
    // The parked bytes were an "operator marker" MEMBER originally: the ratchet is now
    // exactly one object with exactly one `grant_generation` member, so an extra member is not a
    // legal ratchet any more and the reader refuses it. The byte-evidence is therefore carried
    // by SPELLING (compact, no trailing newline) instead of by an extra member — a rewrite would
    // restore the writer's own pretty form and the trailing newline asserted just above.
    //
    // Before the fix: no ratchet existed at all.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_high_water_latches_upward_and_an_equal_generation_writes_nothing() {
        let dir = tempdir("g5");
        let hw = dir.join(GRANT_HIGH_WATER_FILE_NAME);

        // ABSENT ratchet: the first admission latches from the credential itself.
        admit_grant_generation(&dir, &grant_of(3, &[MODIFY]), &held(&dir))
            .expect("an absent ratchet is not a refusal — it is the first latch");
        assert_eq!(hw_of(&dir), Some(3));
        let raw = std::fs::read_to_string(&hw).expect("the ratchet is readable");
        assert!(raw.ends_with("}\n"), "one trailing newline, like every file we write: {raw:?}");

        // EQUAL: no write at all. The SPELLING is byte-evidence — a rewrite would replace it.
        let marked = b"{\"grant_generation\":3}";
        assert_ne!(
            raw.as_bytes(),
            marked,
            "the witness's own premise: the parked spelling is not the writer's own"
        );
        std::fs::write(&hw, marked).expect("park a byte-distinct, semantically equal ratchet");
        admit_grant_generation(&dir, &grant_of(3, &[MODIFY]), &held(&dir)).expect("an equal generation admits");
        assert_eq!(
            std::fs::read(&hw).expect("read back"),
            marked.to_vec(),
            "an EQUAL generation must not write: there is nothing to raise"
        );

        // HIGHER: raised.
        admit_grant_generation(&dir, &grant_of(9, &[MODIFY]), &held(&dir)).expect("a higher generation latches");
        assert_eq!(hw_of(&dir), Some(9));

        // MAX-ONLY: a lower generation afterwards refuses and cannot write it down.
        assert!(admit_grant_generation(&dir, &grant_of(8, &[MODIFY]), &held(&dir)).is_err());
        assert_eq!(hw_of(&dir), Some(9), "the raise is MAX-ONLY, never a plain assignment");

        // CROSS-WRITER INTEROP: the mint raises this same ratchet, and it writes
        // it PRETTY (`json.dumps(..., indent=2)` in `raise_grant_high_water`) while this writer
        // writes it compact. Two writers, one file — so the reader must be indent-agnostic, and
        // this is the arm that says so. The bytes below are the mint's exact emitted shape.
        std::fs::write(&hw, "{\n  \"grant_generation\": 12\n}\n").expect("the mint's own shape");
        let err = admit_grant_generation(&dir, &grant_of(11, &[MODIFY]), &held(&dir))
            .expect_err("a mint-written ratchet retires an older generation just the same");
        assert!(matches!(err, RefreshLocalError::GrantRetired { high_water: 12, .. }), "{err:?}");
        admit_grant_generation(&dir, &grant_of(12, &[MODIFY]), &held(&dir)).expect("equal to it admits");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // An UNUSABLE ratchet refuses LOUDLY and never latches low.
    //
    // "Could not read it" and "it says zero" are different facts, and only one of them is safe:
    // treating an unparsable ratchet as absent would let a single corrupted byte re-admit every
    // retired generation. Same law `convention_temp_names` follows (a failed enumeration is an
    // Err, never an empty set) and the same direction `clamped_now` refuses in.
    //
    // Before the fix: no ratchet existed at all.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_unusable_high_water_refuses_and_is_never_replaced_by_a_lower_one() {
        let cases: &[(&[u8], &str)] = &[
            (b"not json at all", "unparsable"),
            (b"[1, 2, 3]", "a JSON array, not an object"),
            (b"7", "a bare JSON number"),
            (b"{}", "no grant_generation member"),
            (b"{\"grant_generation\": -1}", "negative"),
            (b"{\"grant_generation\": \"5\"}", "a string, not an integer"),
            (b"{\"grant_generation\": 5.5}", "fractional"),
            (b"{\"grant_generation\": null}", "null"),
        ];
        for (bytes, why) in cases {
            let dir = tempdir("g6");
            let hw = dir.join(GRANT_HIGH_WATER_FILE_NAME);
            std::fs::write(&hw, bytes).expect("seed an unusable ratchet");

            let err = admit_grant_generation(&dir, &grant_of(1, &[MODIFY]), &held(&dir))
                .expect_err("an unusable ratchet refuses; it never reads as absent");
            assert!(
                matches!(err, RefreshLocalError::GrantHighWaterUnusable { .. }),
                "the refusal names the RATCHET as the thing that failed ({why}): {err:?}"
            );
            assert!(
                !err.reason_sentence().is_empty()
                    && err.reason_sentence().contains(GRANT_HIGH_WATER_FILE_NAME),
                "the sentence names the file ({why}): {}",
                err.reason_sentence()
            );
            assert_eq!(
                std::fs::read(&hw).expect("read back"),
                bytes.to_vec(),
                "a ratchet that could not be READ is never REPLACED with a lower one ({why})"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // -------------------------------------------------------------------------------------------
    // THE ROLLBACK, end to end: mint gen 1, re-consent to gen 2, restore the gen-1 file.
    //
    // This is the falsification sentinel ("grant provenance has failed if … a restored
    // pre-re-consent credential file is admitted after a re-consent"), executed against real
    // bytes in a real directory through the real writer.
    //
    // Before the fix: `persist_credential` took four arguments and wrote no grant, so there was no
    // generation on the file to roll back and nothing recording that a later one had existed.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_restored_pre_re_consent_credential_is_refused_as_retired_end_to_end() {
        let dir = tempdir("g8");

        // The first consent: generation 1 is written and admitted.
        let gen1 = grant_of(1, &[MODIFY]);
        persist_credential(&dir, "ya29.ONE", "1//R-ONE", 1_700_003_600, &gen1)
            .expect("the generation-1 credential persists");
        admit_grant_generation(&dir, &gen1, &held(&dir)).expect("the first grant admits and latches");
        let snapshot = std::fs::read(dir.join(CREDENTIAL_FILE_NAME))
            .expect("snapshot the generation-1 file — this is what a backup agent keeps");

        // The operator re-consents: generation 2 replaces the file and raises the ratchet.
        let gen2 = grant_of(2, &[MODIFY]);
        persist_credential(&dir, "ya29.TWO", "1//R-TWO", 1_700_007_200, &gen2)
            .expect("the re-consented credential persists");
        admit_grant_generation(&dir, &gen2, &held(&dir)).expect("the re-consented grant admits");
        assert_eq!(hw_of(&dir), Some(2), "the ratchet moved with the consent");

        // A restore/sync/backup agent puts the OLD file back. (The ACTOR here is a sync agent,
        // not the user — this is the real half of the class.)
        std::fs::write(dir.join(CREDENTIAL_FILE_NAME), &snapshot).expect("restore the old file");
        let doc: Value =
            serde_json::from_slice(&snapshot).expect("the restored file is the v2 document");
        let rolled_back: GrantProvenance = serde_json::from_value(doc["grant"].clone())
            .expect("its grant record reads back through the loader's own type");
        assert_eq!(
            rolled_back, gen1,
            "the test's own premise: the restored bytes really are generation 1"
        );

        let err = admit_grant_generation(&dir, &rolled_back, &held(&dir))
            .expect_err("a rolled-back grant is RETIRED, not a credential");
        assert!(
            matches!(err, RefreshLocalError::GrantRetired { .. }),
            "the rollback is refused by the ratchet, with the re-mint cure: {err:?}"
        );
        assert_eq!(hw_of(&dir), Some(2), "and the ratchet still stands at 2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // An ABSENT `scope` inherits the STORED grant (RFC 6749 §5.1: omitted "is treated as
    // equal to the scope of the access token included by the authorization server"), and the
    // rotation writes that grant back TYPED-IDENTICALLY — the survivor rule's shape
    // (`surviving_refresh_token`) applied to authority instead of to refresh material.
    //
    // "TYPED-IDENTICAL (canonical key order, set semantics)", not byte-identical — corrected after
    // review executed the difference: a stored grant carrying a duplicate scope
    // spelling round-trips to a one-member set, and the members come back in canonical order.
    // The AUTHORITY is preserved exactly; the source bytes were never the claim. The assertion
    // below says so by comparing through the TYPE, not through the bytes.
    //
    // Before the fix: `persist_credential` took no grant and wrote a three-field document.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn an_absent_scope_inherits_the_stored_grant_and_persist_writes_it_back_unchanged() {
        let stored = grant_of(7, &[MODIFY]);
        let outcome = parse_with(&ok_body(""), &stored.effective_scopes);
        let RefreshOutcome::Renewed {
            access_token,
            refresh_survivor,
            expires_at,
            scope_confirmed,
        } = &outcome
        else {
            panic!("an omitted scope is not a refusal — it is the identical grant: {outcome:?}");
        };
        assert_eq!(
            *scope_confirmed,
            ScopeConfirmation::AbsentIdenticalGrant,
            "the STORED grant stands; nothing new is minted from silence"
        );

        let dir = tempdir("r2");
        persist_credential(
            &dir,
            access_token.expose(),
            refresh_survivor.expose(),
            *expires_at,
            &stored,
        )
        .expect("the renewed credential persists");

        let raw = std::fs::read_to_string(dir.join(CREDENTIAL_FILE_NAME)).expect("read back");
        assert!(raw.ends_with("}\n"), "one trailing newline: {raw:?}");
        let doc: Value = serde_json::from_str(&raw).expect("the persisted credential is JSON");
        assert_eq!(
            doc["grant"],
            serde_json::to_value(&stored).expect("the grant serializes"),
            "ROTATION PRESERVES THE GRANT, typed-identically (canonical key order, set \
             semantics): a renewal is a new access token, never a new authority"
        );
        let read_back: GrantProvenance = serde_json::from_value(doc["grant"].clone())
            .expect("the written grant reads back through its own type");
        assert_eq!(read_back, stored);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------------------------
    // The comparison reference is the STORED grant, NEVER the compiled constant.
    //
    // Both directions are asserted, because either alone is satisfiable by the wrong
    // implementation: a constant-referencing parser answers the OPPOSITE on both.
    //
    // The stored set here is `{gmail.readonly}` — a grant the PRODUCT refuses at load. That
    // is deliberate: the refresh door's question is RFC 6749 §6's ("no scope not originally
    // granted"), which is about the grant on record, and the load door's question is the
    // product's ("is this the authority Photon runs under"). Two doors, two references, and
    // conflating them is exactly what this witness forbids.
    //
    // Before the fix: there was no stored set — `authority_mismatch` read `REQUIRED_SCOPES`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn the_authority_reference_is_the_stored_grant_never_the_compiled_constant() {
        let stored = stored_scopes(&[READONLY]);

        let restated = parse_with(&ok_body(&format!(r#","scope":"{READONLY}""#)), &stored);
        assert!(
            matches!(
                restated,
                RefreshOutcome::Renewed {
                    scope_confirmed: ScopeConfirmation::StatedAndMatched,
                    ..
                }
            ),
            "a response restating exactly the STORED grant matches, even though that grant is \
             not REQUIRED_SCOPES: {restated:?}"
        );

        let constant_shaped = parse_with(&ok_body(&format!(r#","scope":"{MODIFY}""#)), &stored);
        assert!(
            matches!(constant_shaped, RefreshOutcome::AuthorityMismatch { .. }),
            "and a response stating the CONSTANT's set against that stored grant is a MISMATCH — \
             the provider widened a grant it was never given: {constant_shaped:?}"
        );

        // The constant is still the ONE compiled product set — it is just used at the LOAD
        // door, not here.
        assert_eq!(
            REQUIRED_SCOPES,
            &["https://www.googleapis.com/auth/gmail.modify"],
            "S0 moves the product's exact set to gmail.modify"
        );
    }

    #[test]
    fn a_renewal_owes_no_cure() {
        let renewed = parse(&ok_body(""));
        assert!(!renewed.latches());
        assert_eq!(renewed.cure_owed(), None);
    }



    // -------------------------------------------------------------------------------------------
    // ONE PRINCIPAL LAW, AND IT IS A MAILBOX LAW.
    //
    // Two independent reviewers: one fed the loader
    // `provider_principal = "not-an-email"` and it was ADMITTED — Google defines Gmail `userId`
    // as the user's email address or `me`, so a string that is neither is a stable but MEANINGLESS
    // basis that fails at the provider instead of loudly at admission. It was also shown that
    // `ME`/`Me`/`mE` walk past the exact-match alias clause and reach the wire, with the
    // alias's case-sensitivity UNDOCUMENTED upstream — fail-loud says
    // refuse the class. `\0` and `\x7F` also passed the "ASCII" clause.
    //
    // Review also refuted the BOUND's citation: RFC 5321 gives 64
    // octets for a local-part, 255 for a domain, and §4.5.3.1.3's 256 octets for a whole
    // forward/reverse PATH including the angle brackets. No RFC states 320. The honest bound is
    // 254 = 256 minus `<` and `>`.
    //
    // Before the fix:
    //   `not-an-email` admitted · `ME` admitted · `mE` admitted · `a\0b` admitted ·
    //   `a\x7Fb` admitted · `@x.test` admitted · `a@` admitted · `a@nodot` admitted ·
    //   `a@.x` admitted · the 255-byte address admitted (the bound was 320).
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_provider_principal_must_be_a_mailbox_and_every_refusal_names_its_class() {
        // Exactly 255 bytes: 243 local-part characters + "@example.com" — one past the honest
        // RFC 5321 §4.5.3.1.3 bound, and shaped so TooLong is the ONLY clause it can trip.
        let over_bound = format!("{}@example.com", "a".repeat(255 - "@example.com".len()));
        assert_eq!(over_bound.len(), 255, "the fixture's own premise");

        let cases: &[(&str, PrincipalShape, &str)] = &[
            ("", PrincipalShape::Empty, "empty"),
            (
                "not-an-email",
                PrincipalShape::NotAMailbox,
                "seat 3's EXECUTED input: Google's userId is an email address",
            ),
            ("ME", PrincipalShape::CredentialRelativeAlias, "seat 1 F-3: the alias, upper"),
            ("mE", PrincipalShape::CredentialRelativeAlias, "seat 1 F-3: the alias, mixed"),
            ("me", PrincipalShape::CredentialRelativeAlias, "the alias itself"),
            ("a\u{0}b", PrincipalShape::ControlByte, "NUL is not printable ASCII"),
            ("a\u{7f}b", PrincipalShape::ControlByte, "DEL is not printable ASCII"),
            ("@x.test", PrincipalShape::NotAMailbox, "no local part"),
            ("a@", PrincipalShape::NotAMailbox, "no domain"),
            ("a@nodot", PrincipalShape::NotAMailbox, "a domain with no dot"),
            ("a@.x", PrincipalShape::NotAMailbox, "a domain that starts with a dot"),
            ("a@x.", PrincipalShape::NotAMailbox, "a domain that ends with a dot"),
            ("a@b@c.test", PrincipalShape::NotAMailbox, "two @ separators"),
            (".", PrincipalShape::DotSegment, "the dot segment the encoder elides"),
            ("..", PrincipalShape::DotSegment, "the parent dot segment"),
            ("a b@x.test", PrincipalShape::Whitespace, "whitespace"),
            ("a/b@x.test", PrincipalShape::UrlSignificant, "a path separator"),
            ("a%b@x.test", PrincipalShape::UrlSignificant, "a percent escape"),
            ("\u{f6}wner@x.test", PrincipalShape::NonAscii, "non-ASCII"),
            (over_bound.as_str(), PrincipalShape::TooLong, "255 bytes, one over the bound"),
        ];
        for (principal, expected, why) in cases {
            assert_eq!(
                principal_shape_violation(principal),
                Some(*expected),
                "refused by CLASS ({why})"
            );
            let label = principal_shape_label(*expected);
            assert!(!label.is_empty(), "every class has an operator-facing name ({why})");
        }

        // And the law must not refuse what the mint really writes.
        for usable in ["owner@example.com", "first.last+tag@sub.example.co"] {
            assert_eq!(
                principal_shape_violation(usable),
                None,
                "a real mailbox address is a usable principal: {usable}"
            );
        }
        // The bound is EXACTLY 254 (RFC 5321 §4.5.3.1.3's 256-octet path minus `<` and `>`), and
        // 254 bytes is admitted while 255 is not — an off-by-one here is a silently different law.
        let at_bound = format!("{}@example.com", "a".repeat(254 - "@example.com".len()));
        assert_eq!(at_bound.len(), MAX_PRINCIPAL_BYTES);
        assert_eq!(principal_shape_violation(&at_bound), None, "254 bytes is admitted");
    }

    // ===========================================================================================
    // THE RATCHET'S LINEARIZATION.
    // The wholesale close is a COMPLEMENT: no
    // ratchet write happens outside the ONE cross-process credential lock, and no arm is built
    // from a generation the ratchet has retired.
    // ===========================================================================================

    // -------------------------------------------------------------------------------------------
    // TWO RAISERS UNDER THE LOCK CAN NEVER LEAVE THE LOWER GENERATION.
    //
    // Reproduced: "both 10 and 11 returned Ok,
    // final high-water = 10, generation 10 re-admitted". The same
    // primitive by interposing a raise inside the atomic replace window, and named the class
    // RATCHET-LINEARIZATION / CROSS-PROCESS-MONOTONICITY. Atomic replacement prevents torn
    // bytes; it is not a compare-and-swap. The fix makes the credential lock — the one that
    // already exists and that the mint already takes — the linearization point, and PROVES the
    // caller holds it by taking `&CredentialLock` as a parameter.
    //
    // Before the fix: run against the OLD two-argument `admit_grant_generation` (no lock), the same
    // 200-round coordinated race left the ratchet at 10 and re-admitted the retired generation.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn two_raisers_under_the_credential_lock_can_never_leave_the_lower_generation() {
        for round in 0..40 {
            let dir = tempdir(&format!("f1rk1-{round}"));
            let hw = dir.join(GRANT_HIGH_WATER_FILE_NAME);
            std::fs::write(&hw, b"{\"grant_generation\":9}\n").expect("seed the ratchet at 9");

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
            let spawn = |generation: u64| {
                let dir = dir.to_path_buf();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    admit_grant_generation(&dir, &grant_of(generation, &[MODIFY]), &held(&dir))
                })
            };
            let lower = spawn(10);
            let higher = spawn(11);
            barrier.wait();
            let lower_result = lower.join().expect("the generation-10 raiser");
            let higher_result = higher.join().expect("the generation-11 raiser");

            assert!(
                higher_result.is_ok(),
                "round {round}: the HIGHEST generation is never retired by a lower raiser: \
                 {higher_result:?}"
            );
            assert_eq!(
                hw_of(&dir),
                Some(11),
                "round {round}: two raisers left the ratchet at the LOWER generation — the later \
                 consent was forgotten and the credential it superseded is admissible again \
                 (lower={lower_result:?})"
            );
            let err = admit_grant_generation(&dir, &grant_of(10, &[MODIFY]), &held(&dir))
                .expect_err("the superseded generation stays retired");
            assert!(
                matches!(err, RefreshLocalError::GrantRetired { high_water: 11, .. }),
                "round {round}: {err:?}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // -------------------------------------------------------------------------------------------
    // THE RATCHET IS EXACTLY ONE OBJECT WITH EXACTLY ONE `grant_generation` MEMBER.
    //
    // A JSON object is a LIST of name/value pairs on the
    // wire, and the two readers of this SHARED file resolved a repeated name differently. The
    // mint's per-token `parse_int` hook saw the `-0` and refused; this reader deserialized into
    // `serde_json::Value`, whose object is a map with LAST-WINS semantics — the `-0` pair was
    // discarded and `as_u64` read the surviving 2. Same bytes, two answers, and the
    // "shared schema" assertion was therefore false.
    //
    // The close is by TYPE, not by a lexical hook: the file is parsed through
    // `#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct RatchetFile` — serde's derive
    // refuses a duplicate field, an unknown field, a negative, a float, a string and a null, and
    // THAT parse is the only accept/refuse authority. The member-name scan beside it decides only
    // WHICH shape label the refusal carries, so the labels stay honest and line up with the
    // mint's own classes (repeat · unknown member · absent · not-an-unsigned-integer).
    //
    // Before the fix this test failed:
    // the first row read as `Ok(Some(2))`.
    // -------------------------------------------------------------------------------------------
    #[test]
    fn a_repeated_or_unknown_ratchet_member_refuses_in_both_wire_orders() {
        let dir = tempdir("f3rk5c");
        let hw = dir.join(GRANT_HIGH_WATER_FILE_NAME);
        let read = |bytes: &[u8]| {
            std::fs::write(&hw, bytes).expect("seed the ratchet");
            read_grant_high_water(&hw)
        };

        // THE WIRE FORM refuses — both orders of the executed finding, and the plain rollback.
        for (bytes, why) in [
            (
                &b"{\"grant_generation\":-0,\"grant_generation\":2}"[..],
                "the EXECUTED finding: last-wins discarded the illegal -0 with its pair and read 2",
            ),
            (
                &b"{\"grant_generation\":2,\"grant_generation\":-0}"[..],
                "…and the other wire order",
            ),
            (
                &b"{\"grant_generation\":7,\"grant_generation\":2}"[..],
                "a repeat whose every token is LEGAL is the rollback itself: last-wins reads 2 \
                 over a standing 7",
            ),
            (
                &b"{\"extra\":1,\"extra\":2}"[..],
                "a repeat of ANY name — the rule is about the wire form, not one privileged member",
            ),
            (
                &b"{\"grant_generation\":7,\"extra\":1}"[..],
                "a member the shared schema has no field for",
            ),
            (
                &b"{\"extra\":1}"[..],
                "…and an unknown member is named as such even when grant_generation is missing",
            ),
        ] {
            assert_eq!(
                read(bytes),
                Err(GrantHighWaterShape::DuplicateOrUnknownMember),
                "{why}: {}",
                String::from_utf8_lossy(bytes)
            );
        }

        // The rest of the shape ladder is UNCHANGED by the retype — the labels the operator
        // already reads must not drift because the parse moved.
        assert_eq!(read(b"{\"grant_generation\":7}"), Ok(Some(7)), "the ordinary ratchet");
        assert_eq!(read(b"{\"grant_generation\":0}"), Ok(Some(0)), "zero is a legal reading");
        assert_eq!(
            read(format!("{{\"grant_generation\":{}}}", u64::MAX).as_bytes()),
            Ok(Some(u64::MAX)),
            "the saturated ceiling still reads"
        );
        assert_eq!(read(b"{}"), Err(GrantHighWaterShape::GenerationAbsent), "no member at all");
        for (bytes, why) in [
            (&b"{\"grant_generation\":-0}"[..], "negative zero"),
            (&b"{\"grant_generation\":-1}"[..], "negative"),
            (&b"{\"grant_generation\":5.5}"[..], "fractional"),
            (&b"{\"grant_generation\":1e2}"[..], "exponent"),
            (&b"{\"grant_generation\":\"5\"}"[..], "a string"),
            (&b"{\"grant_generation\":null}"[..], "null"),
            (&b"{\"grant_generation\":18446744073709551616}"[..], "past the u64 ceiling"),
        ] {
            assert_eq!(
                read(bytes),
                Err(GrantHighWaterShape::GenerationNotAnUnsignedInteger),
                "{why}: {}",
                String::from_utf8_lossy(bytes)
            );
        }
        assert_eq!(read(b"[1, 2, 3]"), Err(GrantHighWaterShape::NotAnObject), "an array");
        assert_eq!(read(b"7"), Err(GrantHighWaterShape::NotAnObject), "a bare number");
        assert_eq!(read(b"not json at all"), Err(GrantHighWaterShape::NotJson), "unparsable");
        assert_eq!(
            read("\u{feff}{\"grant_generation\":7}".as_bytes()),
            Err(GrantHighWaterShape::NotJson),
            "a BOM is not a JSON text (RFC 8259)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
