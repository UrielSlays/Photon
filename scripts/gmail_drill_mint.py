#!/usr/bin/env python3
"""Owner-attended OAuth mint helper for the #21 read-side live drills (design v5 §3/§5).

Mints the drill lane's two tokens in ONE sitting and emits the CONTENT-BOUND attestation
bundle beside them, atomically, into the parked secrets dir (default ~/.photon/gmail —
outside every repo). Stdlib-only on purpose: this file is reviewed in-repo and its own
source bytes are digest-pinned into the bundle (`helper_source_sha384`, design v5 N4 —
producer digest, never a self-reported version string). All digests are SHA-384 (issue
#51: the owner-ruled posture — the ONE exception is the RFC 7636-mandated SHA-256 inside
the PKCE S256 challenge, documented at its site).

Slots — the lane's credential contract is ENFORCED HERE, at the credential (codex r6), both
on the REQUESTED sets before consent is asked for and on the EFFECTIVE GRANTED sets before
anything is written; a violation mints nothing and writes nothing:
  main   — the product token, scope EXACTLY gmail.modify (--scope). #75 S0 (design v7 §4)
           moved this slot off gmail.readonly: the triage verbs (trash, spam, archive,
           label) ARE gmail.modify calls, so a read-only credential cannot serve the
           product. Nothing wider is asked for — per Google's scope reference gmail.modify
           "does not allow immediate, permanent deletion of threads and messages, bypassing
           the trash", and the one scope that does (https://mail.google.com/) is refused at
           this door BY PREFIX, by name, at both stages.
  denial — the R3 token, ZERO Gmail authority (--denial-scope, default "openid email";
           gmail.labels is inside the refused family — it authorizes POST label create/edit).

Grant provenance (#75 S0, design v7 §3/§4): every mint stamps the main token file with a
`grant` object — `grant_generation` (one above the persisted high-water in
grant_high_water.json), `provider_principal` (the mint-time getProfile emailAddress) and the
`effective_scopes` actually granted. The token file is written FIRST and the high-water is
raised LAST, both under the credential writer lock: a crash between them leaves a live
credential above a stale high-water, which the app latches upward on the next admission —
the reverse order would retire a working credential. The raise is MAX-ONLY; a corrupt or
unparsable high-water file REFUSES rather than reading as 0.

`same_principal` is derived HERE, in-process, from the two actually-minted identities
(Gmail `users.getProfile` emailAddress for the main slot — gmail.modify authorizes it, per
the getProfile reference — and the OIDC userinfo `email` claim for the denial slot; a
response without that claim REFUSES rather than falling back to the non-comparable opaque
`sub` — PR #50 bot r2 P2).

Identity, AMENDED by #75 S0 (design v7 §4, principal pinning): the #21-era rule was "no
identity value is ever written to the bundle, a file, stdout, or an exception". It now
reads — no identity value is ever written to the ATTESTATION BUNDLE, stdout, or an
exception; the MAIN TOKEN FILE alone carries `grant.provider_principal`, because the app
must pin its wire calls and its plan basis to the account that actually consented instead of
the `me` alias. That file is the same 0600 file that already holds the refresh token — no
new store, no new sink, and the value still never reaches a log line, a rendered string, or
an error message (refusals name the CLASS, never the value).

RFC 6749 §5.1: the token response MAY omit `scope` when the granted set is identical to
the requested set. The omission is recorded as provenance
(`scope_source = rfc6749_identical_request_fallback`), never silently substituted.

NO SECRET may appear in any error message, log line, or exception path: HTTP failures are
reported as status + endpoint LABEL only; response bodies are never embedded in errors.

Self-test: `--self-test` runs the pure-logic witness matrix (design §7 W6) and exits 0/1.
"""

import argparse
import base64
import contextlib
import hashlib
import inspect
import io
import re
import http.server
import json
import os
import secrets as pysecrets
import shutil
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

# The ONE sanctioned platform branch in this slice (design 2026-08-25-74 §3-S8): the
# cross-process writer lock's family differs per OS, so exactly one of these imports
# succeeds and `credential_writer_lock` below branches on which.
try:
    import fcntl  # Unix: the flock family — never lockf (design §3-S6, the r2 lesson).
except ImportError:  # Windows
    fcntl = None
try:
    import msvcrt  # Windows: byte-range locking.
except ImportError:  # Unix
    msvcrt = None

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
# The Gmail authority family, as ONE named pair shared by the request-time and the
# emission-time checks so they cannot drift (codex r6).
GMAIL_SCOPE_FAMILY_PREFIX = "https://www.googleapis.com/auth/gmail"
FULL_MAILBOX_SCOPE_PREFIX = "https://mail.google.com/"
SOURCE_TOKEN_RESPONSE = "token_response"
SOURCE_RFC6749_FALLBACK = "rfc6749_identical_request_fallback"


class MintError(RuntimeError):
    """A mint failure whose message is SAFE by construction: constructors below only ever
    pass endpoint labels and integer statuses — never tokens, bodies, or identities."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Any 30x from an authorized endpoint is TERMINAL (codex r1 P1-1): urllib's default
    handler re-sends the request — Authorization header and all — to the provider-chosen
    Location, which for a bearer-carrying call is credential egress to an arbitrary host.
    Same rationale as the Rust transports' redirect::Policy::none()."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Refuse, always: the Location value is provider-chosen and is deliberately NOT
        # echoed into the error (it could be used to exfiltrate request context). (The RED
        # for this witness — a super()-delegating follow — is banked in
        # council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)
        raise MintError(
            f"redirect refused: HTTP {code} from an authorized endpoint is terminal "
            "(a bearer request never follows a provider-chosen Location)")


def build_authorized_opener():
    """The ONE opener every authorized request goes through (post_form / get_json below).

    codex r3 P1-1: an EXPLICIT EMPTY ProxyHandler — without it, build_opener installs an
    environment ProxyHandler and a set HTTPS_PROXY silently routes the code/refresh
    exchanges and bearer-authenticated identity calls (client secret, authorization code,
    refresh + access tokens) through an ambient proxy. Mirror of the Rust clients'
    `.no_proxy()`: never route a credentialed request through an ambient/system proxy.
    (The RED — ambient defaults picking up HTTPS_PROXY — is banked in
    council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)
    """
    return urllib.request.build_opener(_RefuseRedirects, urllib.request.ProxyHandler({}))


_OPENER = build_authorized_opener()


def inside_a_repo_checkout(path, path_exists=os.path.exists):
    """Walk up from `path` looking for a `.git` entry — a DIR or a FILE (linked worktrees
    use a `.git` file). Injectable probe so the W6 witness stays pure (codex r3 P1-2)."""
    current = os.path.abspath(path)
    while True:
        if path_exists(os.path.join(current, ".git")):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def validate_secrets_dir(secrets_dir, path_exists=os.path.exists, resolve=os.path.realpath):
    """Refuse a secrets dir that is relative or sits inside ANY repository checkout, and
    return the RESOLVED path the helper must write to.

    codex r3 P1-2 opened this; codex r4 FOLD 2 closed it WHOLESALE, the same way the Rust
    evidence dir was closed: RESOLVE FIRST (`os.path.realpath` — symlinks and Windows
    junctions collapsed), run every containment check against the RESOLVED path, and USE the
    resolved path for all writes. No lexical walking on an unresolved path anywhere: a link
    whose own name sits outside a checkout but which resolves inside one previously passed,
    and `atomic_write` then dropped refresh/access tokens into the repo. `resolve` is
    injectable so the W6 matrix can exercise the symlink face purely. (REDs banked in
    council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)
    """
    if not os.path.isabs(secrets_dir):
        raise MintError(
            "--secrets-dir must be an absolute path (a relative dir resolves into the CWD, "
            "typically a checkout)")
    resolved = resolve(secrets_dir)
    if inside_a_repo_checkout(resolved, path_exists=path_exists):
        raise MintError(
            "--secrets-dir resolves inside a repository checkout; tokens must never be "
            "writable into a committable tree")
    return resolved


def client_from_config(data):
    """Select the OAuth client entry from a client-secret file's parsed JSON.

    codex r3 P2-1: ONLY an `installed` (Desktop) client is accepted. A `web` application
    client's redirect URIs are registered EXACTLY, so this flow's random loopback port can
    only end in redirect_uri_mismatch — after the operator already granted consent. Refused
    up front, with the reason. (RED banked in the council log.)"""
    if "installed" in data:
        return data["installed"]["client_id"], data["installed"]["client_secret"]
    if "web" in data:
        raise MintError(
            "client secret file holds a WEB application client; the loopback-PKCE mint "
            "requires an 'installed' (Desktop) client — a web client's registered redirect "
            "URIs cannot match a random loopback port")
    raise MintError("client secret file has no 'installed' client member")


# ---------------------------------------------------------------------------------------
# Pure logic (the W6 semantic-witness surface — everything here is exercised by --self-test)
# ---------------------------------------------------------------------------------------

def require_token_shape(access_token, token_type, endpoint_label):
    """The unified door contract's TOKEN-SHAPE half (design §2 amendment 8, council r2 —
    seat 2 executed `ya29:BAD` through this path to a durable credential the app door
    refuses): the persisted access token must be non-blank, header-safe (visible ASCII),
    and inside the house Bearer-shape grammar; the refresh response's `token_type` must be
    present and case-insensitively Bearer (RFC 6749 §5.1). The grammar mirrors
    token_refresh.rs::bearer_b64token — deliberate strictness beyond RFC 6749 App. A.12,
    a named design §5 non-claim. Loud exit is the refusal posture; reasons name the
    CLAUSE, never the bytes."""
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise MintError(
            f"{endpoint_label} response carried no Bearer `token_type` (RFC 6749 §5.1); "
            "refusing the credential")
    if not isinstance(access_token, str) or not access_token.strip():
        raise MintError(f"{endpoint_label} response carried no usable access_token")
    if any(not (0x21 <= ord(c) <= 0x7E) for c in access_token):
        raise MintError(
            f"{endpoint_label} access_token is not header-safe (a byte outside visible "
            "ASCII); refusing the credential")
    core = access_token.rstrip("=")
    if not core or any(
            not (c.isascii() and c.isalnum()) and c not in "-._~+/" for c in core):
        raise MintError(
            f"{endpoint_label} access_token is outside the Bearer credential grammar "
            "(RFC 6750 b64token shape); refusing the credential")


def strict_scope_members(response_scope):
    """RFC 6749 §3.3, applied WITHOUT normalization (council r2 S3-F3 — the pre-fix
    `.split()` silently repaired doubled spaces, tabs, and newlines, attesting a grammar
    the server never sent): `scope = scope-token *( SP scope-token )` — single-SP
    separation, every member `1*NQCHAR` (%x21 / %x23-5B / %x5D-7E — no `\"`, no `\\`).
    Mirrors token_refresh.rs::scope_members."""
    members = response_scope.split(" ")
    if any(m == "" for m in members):
        raise MintError(
            "token response `scope` is malformed per RFC 6749 §3.3 (empty member — a "
            "doubled, leading, or trailing separator); refusing rather than normalizing")
    for member in members:
        if any(not (0x21 <= ord(c) <= 0x7E) or c in '"\\' for c in member):
            raise MintError(
                "token response `scope` member carries a non-NQCHAR byte (RFC 6749 §3.3); "
                "refusing rather than normalizing")
    return members


# PR #81 bot r2 (two-door parity, the PRESENCE dimension): `dict.get(key)` collapses an
# explicit JSON `null` member into the same None as an OMITTED member, but RFC 6749
# §5.1/§6 license the omission fallbacks for an ABSENT member only — a present `null` is a
# malformed value the app door refuses (`as_str()` fails ⇒ ScopeMalformed /
# RefreshTokenNotAString). Optional-member call sites read `response.get(key, _ABSENT)` so
# the doors can tell the two apart; `None` reaching a door therefore MEANS JSON null.
_ABSENT = object()


def _refuse_malformed_scope(response_scope):
    """A PRESENT-but-empty/whitespace `scope` member is MALFORMED, never an omission
    (codex r12 P2-1): RFC 6749 §3.3's ABNF is `scope = scope-token *( SP scope-token )`,
    `scope-token = 1*NQCHAR` — the empty string is not a valid value. §5.1's
    identical-to-requested fallback licenses an ABSENT member only. Substituting the
    requested set for a malformed value could attest a narrow set while a broader grant's
    refresh token persists — refuse instead.

    W52-py (the two-door-parity set, closed with W51-py): a present NON-STRING value is
    equally malformed — refuse it here, loudly, before strict parsing would crash on it.
    Bot r2: ABSENT is spelled `_ABSENT`; a `None` is an explicit JSON `null` — present,
    malformed, refused (the app door returns ScopeMalformed for the same value)."""
    if response_scope is _ABSENT:
        return
    if not isinstance(response_scope, str):
        raise MintError(
            "token response `scope` is not a string "
            f"({type(response_scope).__name__}); malformed per RFC 6749 §3.3 — refusing "
            "rather than coercing")
    if not response_scope.strip():
        raise MintError(
            "token response carried a present-but-empty scope member (malformed per "
            "RFC 6749 §3.3); refusing rather than substituting the requested set")


def effective_scopes(requested, response_scope):
    """Derive (effective_scope_set, scope_source) from a token response.

    Precedence: a non-empty `scope` member in the token RESPONSE is the authorization
    server's own statement and WINS over the requested set. Only when the response OMITS
    the member does the exact requested set stand in, with the fallback provenance recorded
    (design §3). A present-but-empty value refuses (`_refuse_malformed_scope`).
    Comparison semantics downstream are unordered-exact-set, so a sorted list is emitted.
    """
    _refuse_malformed_scope(response_scope)
    if response_scope is not _ABSENT:
        return sorted(set(strict_scope_members(response_scope))), SOURCE_TOKEN_RESPONSE
    return sorted(set(requested)), SOURCE_RFC6749_FALLBACK


def refresh_effective_scopes(initial_scopes, initial_source, response_scope):
    """Derive the refresh exchange's (effective_scope_set, scope_source).

    RFC 6749 §6 (codex r1 P1-2): a refresh response omitting `scope` grants a scope
    IDENTICAL TO the original access token's — i.e. this sitting's INITIAL EFFECTIVE GRANT,
    never the original authorization REQUEST. A code exchange that NARROWED the grant makes
    the two differ, and falling back to the request would over-claim authority in the
    attestation bundle. The provenance travels with the value it describes: a grant that
    came from the code-exchange response stays `token_response`; an identical-grant chain
    (both responses omitted) stays the RFC fallback. (The RED — request-set fallback — is
    banked in council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)
    """
    _refuse_malformed_scope(response_scope)
    if response_scope is not _ABSENT:
        return sorted(set(strict_scope_members(response_scope))), SOURCE_TOKEN_RESPONSE
    return sorted(set(initial_scopes)), initial_source


def attested_expiry(now_unix, expires_in):
    """The attested `expires_at_*`: now + a PRESENT, positive-integer `expires_in` — or a
    REFUSAL (codex r10 P2-3). Preflight's expired-token refusal and the manifest's
    bank-a-digest-only-when-expired rule both trust this timestamp; a fabricated default
    (the old `.get("expires_in", 3600)`) could call an expired token live or bank a live
    token's digest. The attestation records what the server SAID, never a guess."""
    # STRICT typing (council r2 S3-F3 EXECUTED: the coercing `int()` truncated 3600.5,
    # believed JSON `true` as one second, and admitted 2**200 past i64 — minting a file the
    # Rust consumer refuses). `type(...) is int` excludes bool deliberately; the same law as
    # the Rust door's checked arithmetic (RFC 6749 App. A.14 `1*DIGIT`).
    if type(expires_in) is not int or expires_in <= 0:
        raise MintError(
            "token response carried no usable positive integer `expires_in`; refusing to "
            "invent or coerce an attested expiry (preflight and digest banking trust this "
            "timestamp)")
    expires_at = int(now_unix) + expires_in
    if expires_at >= 2**63:
        raise MintError(
            "token response `expires_in` does not fit a representable attested expiry; "
            "refusing")
    return expires_at


def surviving_refresh_token(initial_refresh, refresh_response_token):
    """Which refresh token must be PERSISTED after the refresh exchange.

    codex r8 FOLD 3: RFC 6749 §6 permits the authorization server to return a REPLACEMENT
    `refresh_token` in the refresh response and to invalidate the old one. Persisting the
    initial token unconditionally meant that after a provider rotation the emitted credential
    file could be DEAD while the helper reported success. Prefer the returned token when
    present; fall back to the original when absent (the common case — Google usually omits it).
    (The RED — the initial token returned unconditionally — is banked in
    council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)

    PR #81 bot r1 P2 (two-door parity, W51-py): a PRESENT but non-string value refuses
    loudly — the app door's RefreshTokenNotAString. The old truthiness test read JSON 0 as
    "no rotation" (silently persisting a token the server may have retired) and crashed on
    .strip() for a truthy non-string. The type name only reaches the error — never the value.
    Bot r2 (the presence dimension): ABSENT is spelled `_ABSENT` by the call site — a `None`
    here is an explicit JSON `null`, a present malformed value, and refuses like any other
    non-string (the app door's map.get sees Some(Null) and refuses it the same way).
    """
    if refresh_response_token is _ABSENT:
        return initial_refresh
    if not isinstance(refresh_response_token, str):
        raise MintError(
            "refresh exchange carried a non-string `refresh_token` "
            f"({type(refresh_response_token).__name__}); refusing the rotation rather than "
            "guessing (parity with the app door's RefreshTokenNotAString)")
    if refresh_response_token.strip():
        return refresh_response_token
    # A present-but-blank replacement is not a rotation; keeping the original is the arm
    # that does not lose a working token (same rule as the app door).
    return initial_refresh


def same_principal(main_identity, denial_identity):
    """True iff the two minted identities are the same non-empty principal.

    Derived from the two identities actually observed at mint time — NEVER operator input
    and never a constant. An empty identity is a mint failure, not a False: silently
    recording False would let R3 skip its same-principal precondition honestly-looking.
    """
    if not main_identity or not denial_identity:
        raise MintError("identity fetch returned an empty principal; cannot attest")
    return main_identity == denial_identity


# The two spellings under which an OIDC email claim is granted at Google: OIDC Core §5.4's
# scope value `email`, and the long-form scope Google normalizes it to in granted-scope
# strings. Either one authorizes the userinfo `email` claim this lane compares principals with.
EMAIL_CLAIM_SCOPES = frozenset(["email", "https://www.googleapis.com/auth/userinfo.email"])


def require_email_claim_scopes(scopes):
    """Refuse a denial-slot scope set that carries no email-bearing scope (PR #50 bot r2 P2).

    The principal comparison is email↔email: Gmail `users.getProfile` emailAddress on the
    main slot vs the OIDC userinfo `email` claim on the denial slot. OIDC Core §5.4 grants
    the `email` claim only under the `email` scope — `openid` alone yields the opaque `sub`,
    a DIFFERENT identifier type whose comparison against an email address records
    `same_principal: false` for the very same account, after which the Rust preflight refuses
    R3 forever while the mint reports success. Enforced BEFORE consent, like the lane-scope
    contract: a set that cannot produce a comparable identity mints nothing.

    (OIDC Core §5.7 makes `sub` the ONLY spec-stable identifier — but the lane contract pins
    the main slot to EXACTLY gmail.modify, so no `sub` is obtainable there; the same-sitting
    email↔email comparison is the one comparable pair this lane can reach, it is never
    persisted as an identifier, and a mismatch fails CLOSED — R3 refused.)
    """
    if not EMAIL_CLAIM_SCOPES.intersection(scopes):
        raise MintError(
            "the denial scope set carries no email-bearing scope (OIDC Core §5.4: the email "
            "claim requires the `email` scope); without it the userinfo identity falls back "
            "to the opaque `sub`, which is not comparable to the main slot's Gmail "
            "emailAddress. Add `email` (or userinfo.email) to --denial-scope. "
            "Minting nothing, writing nothing.")


def denial_identity_from_userinfo(info):
    """The denial slot's principal: the userinfo `email` claim, or a REFUSAL — never `sub`.

    A userinfo response without a non-empty `email` claim (scope narrowed by the server, or
    an account carrying no email) cannot be compared against the main slot's Gmail
    emailAddress; falling back to `sub` compares different identifier types and records an
    honest-looking `same_principal: false` (the PR #50 bot r2 P2 class). Refusing here is the
    granted-stage gate behind `require_email_claim_scopes`'s request-stage check. No identity
    value rides the error (design §3).
    """
    email = info.get("email")
    if not email:
        raise MintError(
            "oidc userinfo returned no email claim; the denial identity cannot be compared "
            "against the main slot's Gmail emailAddress (a `sub` fallback would compare "
            "different identifier types and refuse R3 forever). Re-mint with an "
            "email-bearing --denial-scope.")
    return email


# ---------------------------------------------------------------------------------------
# THE PRINCIPAL LAW (#75 S0, PL1/PL2) — ONE law, TWO doors, TWO languages.
#
# The Rust home is the LAW: `src-tauri/src/token_refresh.rs`'s `principal_shape_violation`
# / `PrincipalShape` / `principal_shape_label`. This is a deliberate PORT, kept in lockstep
# with it — change one, change the other, in the same commit.
#
# WHY the mint needs the loader's law and not a weaker one (code council r1, seat 1 F-1,
# EXECUTED; seat 3 claim 1, EXECUTED): the mint WRITES the credential and the app's loader
# ADMITS it. A mint-side law weaker than the loader's lets a hostile or merely nonconformant
# `users.getProfile` reply — provider-supplied DATA at a declared door — drive the mint to
# publish a credential the loader will ALWAYS refuse, while the ratchet has already moved
# past the last admissible one. The operator's cure (re-mint) reproduces the same principal
# and fails identically, so the only exit left is deleting the ratchet file — the box-owner
# escape hatch becomes the sole recovery. Refusing at the writer's own door keeps the
# previous credential admissible and the failure to one loud sentence.
#
# DIRECTION, if the two ever drift: a mint STRICTER than the loader is safe — everything we
# write stays admissible, and the cost of a drift is a loud mint-time refusal. A mint WEAKER
# than the loader is the F-1 hole itself. Never close a drift by loosening this side.
#
# The classes are a CLOSED SET of sentences. The principal value is provider-supplied and is
# NEVER rendered in a refusal (design §3: name the class, never the identity).
# ---------------------------------------------------------------------------------------

# RFC 5321 §4.5.3.1.3 caps a forward-path at 256 octets INCLUDING the angle brackets, so a
# bare mailbox address fits in 254. (This supersedes the earlier "320-byte RFC 5321 mailbox
# maximum" — 320 is the 64 + 1 + 255 arithmetic of §4.5.3.1.1/§4.5.3.1.2, which no RFC
# states as a bound. Council r1 seats 1 and 2 both opened the RFC and refuted the cite.)
MAX_PRINCIPAL_BYTES = 254

PRINCIPAL_EMPTY = "it is empty"
PRINCIPAL_TOO_LONG = (
    "it is longer than a mailbox address can be (RFC 5321 §4.5.3.1.3 caps a forward-path "
    "at 256 octets, so 254 without the angle brackets)")
PRINCIPAL_NOT_PRINTABLE_ASCII = (
    "it carries a byte outside printable ASCII 0x21-0x7E (a control byte, whitespace, or a "
    "non-ASCII byte)")
PRINCIPAL_URL_SIGNIFICANT = "it carries a URL-significant character (one of / ? # %)"
PRINCIPAL_DOT_SEGMENT = (
    "it is a bare dot segment, which a URL path builder elides rather than encodes")
PRINCIPAL_CREDENTIAL_RELATIVE_ALIAS = (
    "it is the reserved alias that names a credential rather than an account")
PRINCIPAL_NOT_A_MAILBOX = (
    "it is not a provider-native mailbox address (Gmail's userId is the account's email "
    "address: exactly one @, a non-empty local part, and a dotted domain with no leading "
    "or trailing dot)")

PRINCIPAL_SHAPE_CLASSES = (
    PRINCIPAL_EMPTY, PRINCIPAL_TOO_LONG, PRINCIPAL_NOT_PRINTABLE_ASCII,
    PRINCIPAL_URL_SIGNIFICANT, PRINCIPAL_DOT_SEGMENT,
    PRINCIPAL_CREDENTIAL_RELATIVE_ALIAS, PRINCIPAL_NOT_A_MAILBOX,
)


def principal_shape_violation(principal):
    """WHY a `provider_principal` cannot be used, named per CLASS — or `None` if it can.

    Ported from `token_refresh::principal_shape_violation` (the law's Rust home); see the
    block comment above. Returns a member of `PRINCIPAL_SHAPE_CLASSES`, never the value.
    """
    # Measured in BYTES, because the loader's bound is a byte bound and a surrogate or a
    # multi-byte character must not be able to buy extra length by counting as one char.
    raw = principal.encode("utf-8", "surrogatepass")
    if not raw:
        return PRINCIPAL_EMPTY
    if len(raw) > MAX_PRINCIPAL_BYTES:
        return PRINCIPAL_TOO_LONG
    # ONE range covers non-ASCII, every control byte (NUL and DEL included) and every
    # whitespace form — the loader splits these into separate class names; the partition of
    # ACCEPTED bytes is identical, which is the part that has to match.
    if any(byte < 0x21 or byte > 0x7E for byte in raw):
        return PRINCIPAL_NOT_PRINTABLE_ASCII
    # The characters that decide where a URL points. `%` is here because a principal that
    # already carries a percent-escape re-encodes into a different string downstream.
    if any(byte in b"/?#%" for byte in raw):
        return PRINCIPAL_URL_SIGNIFICANT
    if principal == "." or principal == "..":
        return PRINCIPAL_DOT_SEGMENT
    # ASCII-case-INSENSITIVE: Google documents the special value as `me` and documents
    # nothing about its case, so under FAIL-LOUD we refuse the whole class rather than let
    # `ME` reach the wire on an undetermined reading (council r1 seat 1, F-3; the sweep for
    # a case statement came back empty, and a negative result is a pointer, not an answer).
    # The string is ASCII by the time we get here, so `.lower()` is ASCII case folding.
    if principal.lower() == "me":
        return PRINCIPAL_CREDENTIAL_RELATIVE_ALIAS
    # PROVIDER-NATIVE FORM. `not-an-email` passed every check above and was admitted as a
    # principal (council r1 seat 3, claim 1, EXECUTED) — but Gmail's `userId` is the
    # account's email address, so a value that cannot BE one names no account.
    if principal.count("@") != 1:
        return PRINCIPAL_NOT_A_MAILBOX
    local_part, _, domain = principal.partition("@")
    if not local_part or not domain:
        return PRINCIPAL_NOT_A_MAILBOX
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return PRINCIPAL_NOT_A_MAILBOX
    return None


def principal_refusal_sentence(door, violation):
    """The ONE refusal sentence for a principal — built from the DOOR and the CLASS only, so
    the provider-supplied value structurally cannot ride it."""
    return (f"{door}: refusing a provider principal because {violation}. The value itself "
            "is provider-supplied data and is never rendered.")


def require_principal_shape(principal, door):
    """Apply the law at a door, or refuse naming the class."""
    violation = principal_shape_violation(principal)
    if violation is not None:
        raise MintError(principal_refusal_sentence(door, violation))
    return principal


def main_principal_from_profile(profile):
    """The MAIN slot's principal: the Gmail `users.getProfile` `emailAddress`, or a REFUSAL.

    #75 S0 (design v7 §4, principal pinning): this value is PERSISTED into the token file and
    the app then pins its wire calls and its plan basis to it instead of the `me` alias — so
    an absent, empty, whitespace-only or non-string member cannot be shrugged off here. It is
    provider-supplied DATA that becomes a URL path segment downstream (build record §0 Item
    5), and the app's loader re-validates its shape at its own door; the mint's job is to
    refuse to CREATE a credential with no usable principal in it. The value never rides the
    error message (design §3 — refusals name the class, never the identity).
    """
    # The body is provider-supplied: a JSON array or scalar must refuse as a typed MintError,
    # never crash the mint with an AttributeError mid-sitting (the W52-py two-door-parity
    # class — a present non-object value is malformed, not an omission).
    if not isinstance(profile, dict):
        raise MintError(
            f"gmail getProfile returned a non-object body ({type(profile).__name__}); the "
            "credential's provider principal cannot be pinned")
    email = profile.get("emailAddress", _ABSENT)
    if email is _ABSENT or email is None:
        raise MintError(
            "gmail getProfile returned no emailAddress; the credential's provider principal "
            "cannot be pinned (the app must call the API as the consenting account, not the "
            "`me` alias). Minting nothing, writing nothing.")
    if not isinstance(email, str):
        raise MintError(
            "gmail getProfile returned a non-string emailAddress "
            f"({type(email).__name__}); refusing to pin a provider principal to it")
    # PL2: the SAME law the app's loader admits on, at the mint's own door — before a
    # generation is reserved and before any credential exists (see the block comment above
    # `principal_shape_violation`).
    return require_principal_shape(email, "gmail getProfile")


def require_publishable_principal(provider_principal):
    """The credential principal's law, factored out so the PRE-RESERVATION validation pass
    in `run_mint` and `main_token_document`'s own last door are literally the same code.

    `run_mint` must be able to refuse a nonconformant getProfile reply while the ratchet has
    NOT moved (council r1 seat 1, F-1: otherwise the mint writes a credential the loader
    always refuses AND retires the last good one). Now that the document can only be built
    from a reservation — i.e. after the ratchet HAS moved — that validation has to be
    callable on its own, and it has to be the same bytes the builder runs, not a copy.
    """
    if not isinstance(provider_principal, str):
        raise MintError(
            "refusing to write a credential with no usable provider principal "
            f"({type(provider_principal).__name__}); the app pins its wire calls to it")
    # PL2: the loader's own law, at the last door before bytes hit the disk.
    require_principal_shape(provider_principal, "the credential about to be written")
    return provider_principal


def main_token_document(access_token, refresh_token, expires_at, reserved_generation,
                        provider_principal, effective_main_scopes, secrets_dir):
    """The MAIN token file's document — credential file v2 (#75 S0, design v7 §4).

    The ONE constructor: `run_mint` writes what this returns and the M4 witness inspects what
    this returns, so the attested shape and the emitted shape cannot drift. v1's three members
    are unchanged; `grant` is new and carries the provenance the app admits on —
    `grant_generation` (monotonic, ≥ 1, one above the high-water at mint time),
    `provider_principal` (the mint-time getProfile identity) and the `effective_scopes`
    actually granted, SORTED because every comparison downstream is unordered-exact-set.

    #91 (RK2, TYPE-CARRIED): `reserved_generation` is a `ReservedGeneration` — the ONE
    value `reserve_grant_generation` returns — and `secrets_dir` is the ratchet it must
    have been claimed in. A bare `int` REFUSES here, so the credential-first order the
    council executed a rollback against is no longer SPELLABLE: a document cannot exist
    under a generation the ratchet has not already claimed, and the ordering law is carried
    by the types rather than by `run_mint`'s statement order plus a comment.

    Refusals here are the last door before bytes hit the disk; none of them echoes the
    principal, a token, or the generation value.
    """
    grant_generation = require_reserved_generation(reserved_generation, secrets_dir,
                                                   "build a credential")
    # Defence in depth, and deliberately unreachable while `ReservedGeneration` is the only
    # key to this door: `reserve_grant_generation` already refuses a non-positive or an
    # over-u64 generation before it can mint one. Kept so the document's own invariants stay
    # readable AT the document, not only at the reservation.
    if type(grant_generation) is not int or grant_generation < 1:
        raise MintError(
            "refusing to write a credential whose grant_generation is not a positive "
            f"integer ({type(grant_generation).__name__}); generations start at 1")
    # RK5: Python integers are unbounded, the app's `GrantWire.grant_generation` is a u64.
    # A generation the mint can write and the loader cannot deserialize is a credential
    # that refuses forever (council r1 seats 1 F-4 and 2, both EXECUTED).
    if grant_generation > GRANT_GENERATION_MAX:
        raise MintError(
            "refusing to write a credential whose grant_generation is outside the shared "
            f"schema (u64: 1..={GRANT_GENERATION_MAX}); the app's reader cannot represent "
            "it and would refuse the credential forever")
    require_publishable_principal(provider_principal)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "grant": {
            "grant_generation": grant_generation,
            "provider_principal": provider_principal,
            # PL4: a SET on disk — sorted AND deduplicated. The app reads this into a
            # `BTreeSet` whose doc-comment promises "sorted, deduplicated, one shape on
            # disk"; emitting the raw list let a duplicated grant serialize twice and made
            # the two writers disagree about the canonical bytes (council r1 seat 2,
            # EXECUTED). It never widened authority — the exact-set comparison is what
            # governs that — but the promise has to be true at the writer too.
            "effective_scopes": sorted(set(effective_main_scopes)),
        },
    }


def consent_outcome(code, error, deadline_expired):
    """Decide the consent wait loop's next step from what the callback has seen so far.

    codex r2 P2-4: an `error=` callback (RFC 6749 §4.1.2.1 — access_denied etc.) is TERMINAL,
    and so is the overall consent deadline — the loop must never wait forever on a denial or
    a walked-away consent screen. The error value is echoed only when it matches the RFC's
    snake_case token shape; anything else (hostile or garbled) is replaced with a generic
    label so no callback-controlled bytes ride an error message. (The RED — error ignored,
    no deadline — is banked in council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)
    """
    if code:
        return code
    if error == AMBIGUOUS_CALLBACK:
        # NOT "denied by the authorization server" — the ambiguity's author is unknown
        # (a nonconforming server and a local injector look identical at this door).
        raise MintError(
            "the authorization callback was ambiguous (a repeated or conflicting "
            "parameter); refusing to guess which authorization was meant (RFC 6749 §3.1)")
    if error:
        label = error if re.fullmatch(r"[a-z_]{1,64}", error) else "unrecognized_error"
        raise MintError(f"consent denied by the authorization server: {label}")
    if deadline_expired:
        raise MintError("consent timed out (deadline reached before any callback)")
    return None


def carries_gmail_authority(scope):
    """Does this scope grant ANY Gmail mailbox authority? The single predicate behind both
    lane checks (codex r6). `gmail.labels` is deliberately inside the family: it authorizes
    POST label create/edit, i.e. mutation."""
    return (scope.startswith(GMAIL_SCOPE_FAMILY_PREFIX)
            or scope.startswith(FULL_MAILBOX_SCOPE_PREFIX))


def enforce_lane_scope_contract(slot, scopes, stage):
    """Enforce the lane's credential contract on ONE slot's scope set — AT THE CREDENTIAL.

    codex r6: `--scope` / `--denial-scope` went straight to OAuth, so an operator could mint
    AND PERSIST a mutation-capable credential (`gmail.modify`, `gmail.labels`); the Rust
    preflight refused it only at DRILL time, long after the token existed on disk. The lane's
    posture is that authority is minimized AT THE CREDENTIAL, so the contract is enforced
    where the credential is created:

    - **main** must be EXACTLY `{gmail.modify}` — unordered exact set, never a substring.
      (#75 S0, design v7 §4: the product's triage verbs — trash, spam, archive, label — are
      `gmail.modify` calls, so the read-only credential this lane minted through #21 can no
      longer satisfy the product. `gmail.readonly` present IN ADDITION is surplus authority
      and refuses on the same law.)
    - **main** additionally refuses `https://mail.google.com/` BY PREFIX, before the
      exact-set test. The exact-set test already excludes it arithmetically, so this door is
      redundant on the arithmetic and deliberate on the REASON: the full-mailbox family is
      the ONE Gmail scope that authorizes immediate permanent deletion (bypassing the trash),
      `gmail.modify` cannot do it at all, and this product never asks for it. A reader (or a
      future edit widening the set) meets that sentence at the door rather than inferring it
      from set arithmetic.
    - **denial** must carry NO Gmail authority (`carries_gmail_authority` — the same
      predicate both stages use, so they cannot drift).

    Called TWICE per slot: with the REQUESTED set before consent is even asked for (nothing
    is minted), and with the EFFECTIVE GRANTED set before anything is written to disk
    (nothing is persisted). A violation raises `MintError` naming the offending scope and the
    contract. (REDs banked in council-logs/21-readside-BUILD-red-witnesses-2026-07-26.md.)
    """
    scope_set = set(scopes)
    if slot == "main":
        # The full-mailbox door, kept EXPLICIT (see the docstring): exact-set already
        # excludes it, but the refusal a reader needs to see names the family and why.
        full_mailbox = sorted(
            s for s in scope_set if s.startswith(FULL_MAILBOX_SCOPE_PREFIX))
        if full_mailbox:
            raise MintError(
                f"lane contract violation ({stage} main scopes): the full-mailbox scope "
                f"family ({FULL_MAILBOX_SCOPE_PREFIX}) is NEVER REQUESTED by this product — "
                "it is the only Gmail scope that authorizes immediate, permanent deletion "
                "bypassing the trash, which gmail.modify cannot do at all; offending: "
                f"{', '.join(full_mailbox)}. Minting nothing, writing nothing.")
        if scope_set != {MODIFY_SCOPE}:
            offending = sorted(scope_set - {MODIFY_SCOPE}) or ["<empty scope set>"]
            raise MintError(
                f"lane contract violation ({stage} main scopes): the product's credential "
                f"must be EXACTLY {{{MODIFY_SCOPE}}} — the triage verbs need it and nothing "
                "wider is asked for (a gmail.readonly-only grant cannot trash, spam, archive "
                f"or label); offending: {', '.join(offending)}. "
                "Minting nothing, writing nothing.")
        return None
    if slot == "denial":
        offending = sorted(s for s in scope_set if carries_gmail_authority(s))
        if offending:
            raise MintError(
                f"lane contract violation ({stage} denial scopes): the R3 denial credential "
                "must carry ZERO Gmail authority (any "
                f"{GMAIL_SCOPE_FAMILY_PREFIX}* — gmail.labels included, it authorizes POST "
                f"label create/edit — or {FULL_MAILBOX_SCOPE_PREFIX}); offending: "
                f"{', '.join(offending)}. Minting nothing, writing nothing.")
        return None
    raise MintError(f"unknown credential slot: {slot}")


def token_sha384(token):
    """sha384 hex of the EXACT token string that is emitted to the token file — the
    hash-what-you-emit association rule (design §3: the digest proves post-mint
    token/bundle association, nothing more). SHA-384 per the owner-ruled posture (issue
    #51): strict SHA-384 everywhere we control the format, and this format is ours."""
    return hashlib.sha384(token.encode("utf-8")).hexdigest()


def helper_source_sha384(path=None):
    """sha384 hex of this helper's own source bytes (design v5 N4: producer digest;
    SHA-384 per issue #51 — our own format, no external mandate)."""
    with open(path or os.path.abspath(__file__), "rb") as f:
        return hashlib.sha384(f.read()).hexdigest()


def build_bundle(main_token, main_scopes, main_source, minted_at, expires_at_main,
                 helper_sha, denial_token=None, denial_scopes=None, denial_source=None,
                 principal_match=None, expires_at_denial=None, grant_generation=None):
    """Assemble the attestation bundle dict (design §3, exact member set). The token
    digests are computed HERE from the same strings the caller emits, so the bundle can
    never be assembled against tokens other than the ones written (W6: association).

    Per-token expiries (codex r2 P2-1): each slot carries ITS OWN `expires_at_*`, so the
    manifest's bank-a-hash-only-when-expired rule can be honest per token — one merged
    expiry would let a still-live denial token's digest ride an expired main's timestamp.

    `grant_generation` (#75 S0) records WHICH grant these digests belong to, so an
    attestation cannot be read against a later re-consent's credential. The generation is a
    counter, not an identity: the bundle still carries no principal — that value lives only
    in the 0600 token file (the amended #21 identity rule, module docstring)."""
    return {
        "grant_generation": grant_generation,
        "main_token_sha384": token_sha384(main_token),
        "denial_token_sha384": token_sha384(denial_token) if denial_token else None,
        "effective_main_scopes": list(main_scopes),
        "effective_denial_scopes": list(denial_scopes) if denial_scopes is not None else None,
        "scope_source_main": main_source,
        "scope_source_denial": denial_source,
        "same_principal": principal_match,
        "minted_at": minted_at,
        "expires_at_main": expires_at_main,
        "expires_at_denial": expires_at_denial,
        "helper_source_sha384": helper_sha,
    }


def flush_to_device(f):
    """Force an OPEN file's bytes past the OS page cache, before its name is published.

    `f.flush()` first: per CPython's own `os.fsync` documentation, a buffered Python file
    object must be flushed into the OS before an fd-level sync can mean anything. Then the
    strongest call this platform offers — on macOS plain `fsync(2)` is a host-to-drive flush
    only ("the drive itself may not physically write the data to the platters for quite some
    time"), and Apple names `fcntl(fd, F_FULLFSYNC)` as the one that reaches permanent
    storage; everywhere else `os.fsync` (which on Windows is the CRT's `_commit()`).

    Errors PROPAGATE. `crates/aruna/src/store_open.rs:2394-2399` is the in-repo precedent and
    the reason: swallowing a sync error silently downgrades the guarantee while still
    reporting success, which is worse than not claiming it.
    """
    f.flush()
    full_fsync = getattr(fcntl, "F_FULLFSYNC", None) if fcntl is not None else None
    if full_fsync is not None:
        fcntl.fcntl(f.fileno(), full_fsync)
    else:
        os.fsync(f.fileno())


def fsync_directory(directory):
    """POSIX-ONLY: force a directory's own entries to disk. On LINUX that makes a rename or an
    unlink inside it survive a power loss; on macOS this is the weaker plain fsync — Apple
    documents F_FULLFSYNC for files, not directory descriptors (F21-h; `atomic_write`'s
    per-OS table names the residual) — so the entry's survival there is best-effort, not
    guaranteed. A deliberate NO-OP everywhere else.

    fsync(2): "Calling fsync() does not necessarily ensure that the entry in the directory
    containing the file has also reached disk. For that an explicit fsync() on a file
    descriptor for the directory is also needed." SQLite syncs the containing directory for
    exactly this reason (atomiccommit.html §5.2).

    ⛔ THE POSIX GATE IS NOT DECORATION. On Windows `os.open(<directory>)` raises
    PermissionError (witnessed on the owner's own box: win32, python 3.11.9), and
    `os.O_DIRECTORY` does not exist there, so the guard cannot be feature-detected either. An
    unguarded directory fsync would crash the mint at the instant right AFTER the credential
    landed. Same unix scoping, for the same reason, as
    `crates/aruna/src/store_open.rs:2390-2400`.
    """
    if os.name != "posix":
        return
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def atomic_write(path, text):
    """Temp-file + sync + os.replace in the TARGET directory (same filesystem), so a crash
    mid-write can never leave a torn token file or a token/bundle mixed generation.

    ATOMIC IS NOT DURABLE, and this file needs both. `rename(2)` guarantees only that no
    reader ever finds the destination missing; it says nothing about a power loss. Until
    #75 S0 r11 this function issued no sync at all — the `with` block's close pushed the bytes
    into the OS page cache and the rename published a name over them. That is not a cosmetic
    gap: `run_mint` argues its reserve-first ORDER at length (raise the ratchet, THEN publish
    the credential), and without a sync between the two renames that order is PROGRAM order
    only. The OS is free to reorder the writebacks, so a power loss can land the credential
    and lose the raise — which is precisely the duplicated-generation state reserve-first
    exists to make impossible (council r1 seat 3 executed the rollback it enables).

    THE GUARANTEE, said honestly, per OS:
      * PROCESS CRASH (the mint is killed mid-write): none-or-complete EVERYWHERE. That is the
        rename, and it was already true.
      * POWER LOSS on LINUX: none-or-complete. The temp file's bytes are `fsync`ed BEFORE the
        rename, and the parent directory is `fsync`ed after it so the new directory entry
        itself survives (fsync(2): a file's own sync does not cover its directory entry).
      * POWER LOSS on macOS: the temp file's BYTES are forced with F_FULLFSYNC (Apple's
        fsync(2): plain fsync flushes host→drive only; the drive "may not physically write
        the data ... for quite some time"); the parent DIRECTORY gets a plain `fsync`, which
        is the weaker call — Apple documents F_FULLFSYNC for files, not directory descriptors.
        So the credential's bytes are durable and the directory ENTRY publishing them is
        best-effort: a power cut in that window can lose the rename (council r5, seats 1 and
        2, SEARCHED at developer.apple.com). A NAMED RESIDUAL, not "none-or-complete".
      * POWER LOSS on WINDOWS: NOT guaranteed — a NAMED RESIDUAL, not a closed hole. CPython's
        `os.replace` is `MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING)`
        (Modules/posixmodule.c) and does NOT pass `MOVEFILE_WRITE_THROUGH`, the flag Microsoft
        documents as the one that "guarantees that a move performed as a copy and delete
        operation is flushed to disk before the function returns". The temp file's bytes ARE
        committed here, and Windows offers no directory-fsync substitute. Closing it would
        mean a hand-rolled ctypes Win32 rename on the very path that writes the refresh token
        — new platform-specific machinery, with no power-cycled CI to witness it — so it is
        named rather than grown.
      * a drive that acknowledges a flush it never performed is above everyone's ceiling
        (SQLite atomiccommit.html §9.2). No on-box control exists for it.

    Errors PROPAGATE: a failed sync raises out of here (unlinking the temp on the way) instead
    of being folded into a success — see `flush_to_device`.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".mint-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            # INSIDE the `with`: the sync needs a live fd, and INSIDE the `try`, so a failure
            # takes the temp file with it instead of leaving `.mint-*` litter in the dir.
            flush_to_device(f)
        os.replace(tmp, path)
        fsync_directory(directory)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------------------
# Grant provenance (#75 S0 — design v7 §3/§4): the monotonic grant generation and its
# persisted high-water. Shapes ADOPTED from our own shelf rather than invented —
# crates/aruna/src/store_open.rs (`high_water = MAX(...)`), the bridge's per-lineage
# anti-rollback rule (raised MAX-ONLY, never a plain assignment that can write it DOWN), and
# the bridge's persisted ratchet via atomic file replace, with its honest caveat: this is
# NOT a cross-process monotonic transaction. The mint's own writes are serialized by the
# credential writer lock it already holds.
#
# The caveat is load-bearing and the earlier note here was WRONG: an unlocked
# read-compare-replace can walk the ratchet BACKWARDS, not merely lose a raise — council r1
# seat 2 and seat 3 both executed it, and the codex CLI's P1-b named the same primitive.
# Serializing every ratchet write behind the one cross-process credential lock is the app
# side's contract (RK1, `admit_grant_generation`); this file's part of it is that the mint
# reserves and raises only while holding that same lock.
# ---------------------------------------------------------------------------------------

GRANT_HIGH_WATER_FILENAME = "grant_high_water.json"

# RK5: the ratchet file is SHARED with the app, whose schema for it is
# `{"grant_generation": u64}`. Python's int is unbounded, so without this bound the mint can
# write — and read back — a value the app's reader must call unusable, which converts a
# working ratchet into a permanent refusal with no in-band cure (council r1 seats 1 F-4 and
# 2, both EXECUTED; reaching it needs a box owner to seed the file, so this is HYGIENE at
# the T2 ceiling, not a control — it is here because a cross-writer schema divergence is a
# defect whoever can reach it).
GRANT_GENERATION_MAX = 2 ** 64 - 1

# RK5b: the numeric BOUND above is not enough, because the two readers must also agree on
# the SPELLING. Rust's `serde_json` refuses the token `-0` at `as_u64` (it is a negative
# number in serde's model, and u64 has no negative zero); Python's `json.loads` admits the
# same bytes as the integer 0. That is the worst divergence this file can carry: the app
# calls the ratchet unusable while the mint reads it as "nothing minted yet" and hands out a
# generation the app has already retired — the exact rollback the file exists to catch.
# (Council r2 seat 3, EXECUTED.) So the ratchet is parsed through a `parse_int` hook that
# sees the RAW integer token, before Python widens it into a value, and admits only a
# CANONICAL non-negative decimal: ASCII digits only, no sign (`-` or `+`), and no leading
# zero beyond a bare `0`. Floats and exponent spellings never reach this hook — they go to
# `parse_float` and are caught by the `type(...) is int` check at the read door.
_GENERATION_DIGITS = frozenset("0123456789")


class _NonCanonicalGeneration(ValueError):
    """Sentinel raised INSIDE the ratchet's `parse_int` hook and converted to a `MintError`
    at the read door. It subclasses ValueError deliberately so that no caller can mistake a
    lexical refusal for a successful parse; the door catches it BEFORE the generic
    `ValueError` arm, so a non-canonical token is never reported as "unparsable JSON"."""


def canonical_generation_int(token):
    """`json.loads(..., parse_int=...)` hook: `token` is the raw integer text as it appears
    in the file, sign included. Admit it only if it is spelled the one way the app's u64
    reader accepts; otherwise raise the sentinel. The token itself is NEVER carried into the
    refusal — the message names the SHAPE class, never the offending bytes."""
    if (not token
            or any(ch not in _GENERATION_DIGITS for ch in token)
            or (len(token) > 1 and token[0] == "0")):
        raise _NonCanonicalGeneration("non-canonical generation spelling")
    return int(token)


# RK5c: the numeric bound and the lexical spelling are still not enough, because a JSON
# object is a LIST of name/value pairs on the wire and the two readers RESOLVE a repeated
# name differently. CPython's `json` keeps the LAST pair, so
# `{"grant_generation": -0, "grant_generation": 2}` collapses to 2 and the `-0` the lexical
# hook was built to refuse is DISCARDED with its pair; the app's typed reader
# (`deny_unknown_fields`) refuses a repeated field outright. Same bytes, two answers, and
# the divergent one is the mint's — it would hand out a generation over a file the app calls
# unusable. (Council r3 seat 2, EXECUTED.) So the ratchet is parsed through an
# `object_pairs_hook`, which sees the pairs BEFORE the dict collapses them, and the file is
# held to the shape the shared schema actually is: exactly one object, no repeated name
# (ANY name — the rule is about the wire form, not about one privileged member), and no
# member other than `grant_generation`. Neither refusal ever carries the offending bytes.
GRANT_GENERATION_MEMBER = "grant_generation"


class _MalformedRatchetObject(ValueError):
    """Base sentinel for the ratchet's TOP-LEVEL shape refusals, converted to a `MintError`
    at the read door. ValueError-derived on purpose, and caught BEFORE the generic
    `ValueError` arm, so a shape refusal is never reported as "unparsable JSON"."""


class _RepeatedRatchetMember(_MalformedRatchetObject):
    """A name appears more than once in the top-level object."""


class _UnknownRatchetMember(_MalformedRatchetObject):
    """A member the shared schema has no field for, in the top-level object."""


class _RatchetObject:
    """A decoded JSON object that REMEMBERS its wire pairs — repeats included, in wire order.

    RK5d (council r4 seat 1, EXECUTED): CPython calls `object_pairs_hook` for EVERY object it
    decodes, innermost first, so a hook that ENFORCED the ratchet's one-object/one-member law
    judged nested objects as well — `{"grant_generation": {"n": 7}}` refused as "a member
    outside the shared schema" over the INNER object's `n`, when the honest class is the
    VALUE's type (`not-u64`): the document's own members are exactly right. So the hook
    decides nothing now; it only records. The law runs ONCE, on the outermost result, in
    `canonical_ratchet_top_level`, and a nested object (or array) as the value falls to the
    existing type door.

    Deliberately NOT a `dict` subclass: a nested object must reach the type door as something
    `type(...) is int` refuses, and nothing downstream should be able to index it by accident.
    """

    __slots__ = ("pairs",)

    # The name the TYPE-class refusal carries for this marker. A nested JSON object is a
    # `dict` to anyone reading the file; the marker class is our internal business and never
    # appears in an operator-facing sentence.
    json_type_name = "dict"

    def __init__(self, pairs):
        self.pairs = tuple(pairs)


def canonical_ratchet_object(pairs):
    """`json.loads(..., object_pairs_hook=...)` hook. Fires for every object in the document,
    at every depth, so it RECORDS and never refuses (see `_RatchetObject`)."""
    return _RatchetObject(pairs)


def canonical_ratchet_top_level(pairs):
    """The ratchet's shape law, applied to the TOP-LEVEL object's wire pairs only.

    Two passes, because the two refusals are different classes and the REPEAT one must be
    reported even for a name that is also unknown: first refuse any repeated name, then
    refuse any member outside the shared schema. Neither the offending name nor its value is
    carried into the sentinel — the message at the door names the SHAPE class only.
    """
    seen = set()
    for name, _value in pairs:
        if name in seen:
            raise _RepeatedRatchetMember("repeated member name")
        seen.add(name)
    for name, _value in pairs:
        if name != GRANT_GENERATION_MEMBER:
            raise _UnknownRatchetMember("member outside the shared schema")


def ratchet_generation_type_name(value):
    """The type name a `not-u64` refusal carries. `_RatchetObject` is this module's marker for
    a decoded JSON object, so report the JSON-shaped name an operator can act on."""
    if isinstance(value, _RatchetObject):
        return _RatchetObject.json_type_name
    return type(value).__name__


class _NotARatchetObject(ValueError):
    """The document parsed, but its top level is not a JSON object."""


class _AbsentGenerationMember(ValueError):
    """A legal ratchet object that carries no `grant_generation` member at all."""


class _UnusableGeneration(ValueError):
    """`grant_generation` is present but is not a non-negative integer (a bool, a string, a
    float, a null, or a negative). Carries the TYPE NAME only — never the value."""

    def __init__(self, type_name):
        super().__init__("grant_generation is not a non-negative integer")
        self.type_name = type_name


class _GenerationOutsideSchema(ValueError):
    """A non-negative integer the shared u64 schema has no value for."""


class _NotUtf8Ratchet(ValueError):
    """The file's BYTES are not UTF-8, so there is no text to parse.

    RK5e (council r4 seats 2 and 3, EXECUTED): the read door promises that every unusable
    form of this file becomes a `MintError`, and `main()` rests on that promise because it
    catches `MintError` and nothing else. Opening the ratchet in TEXT mode broke it — a stray
    `0xff` raised a raw `UnicodeDecodeError` out of `read()`, before any door could name a
    class. So the door reads bytes and decodes EXPLICITLY, and this is the class it names.
    ValueError-derived like every other sentinel here, and caught FIRST, so a byte-level
    refusal is never reported as "unparsable JSON" (which would be a claim about text that
    does not exist).
    """


def parse_ratchet_document(raw):
    """Parse the ratchet file's BYTES and return the generation, raising ONE of this module's
    sentinel classes for every refusal.

    Split out of `read_grant_high_water` (#75 S0 witness corpus) so that the parity corpus
    emitted by `--emit-ratchet-parity-corpus` is produced by the SAME code the read door
    runs, rather than by a second reader that could drift from it. The door owns the
    MESSAGES (which carry the path); this owns the DECISIONS. Every sentinel subclasses
    ValueError, and the door catches each specific class BEFORE the generic arm, so a shape
    or spelling refusal is never reported as "unparsable JSON".

    BYTES, not text, on purpose: the app's Rust reader takes `&[u8]`, and a corpus of file
    bytes is the only thing the two readers can be held to. The decode is the FIRST door.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _NotUtf8Ratchet("the ratchet's bytes are not UTF-8") from None
    document = json.loads(text, parse_int=canonical_generation_int,
                          object_pairs_hook=canonical_ratchet_object)
    if not isinstance(document, _RatchetObject):
        raise _NotARatchetObject("the ratchet's top level is not a JSON object")
    # The one-object/one-member law, applied HERE — to the outermost object only (RK5d).
    canonical_ratchet_top_level(document.pairs)
    generation = _ABSENT
    for name, value in document.pairs:
        if name == GRANT_GENERATION_MEMBER:
            generation = value
    if generation is _ABSENT:
        raise _AbsentGenerationMember("no grant_generation member")
    # `type(...) is int` excludes bool deliberately (JSON true is not generation 1) and
    # excludes a string spelling — the same strict typing law as `attested_expiry`. A nested
    # object or array as the value lands here too, which is the honest class for it: the
    # document's members are right, its VALUE is not a u64.
    if type(generation) is not int or generation < 0:
        raise _UnusableGeneration(ratchet_generation_type_name(generation))
    if generation > GRANT_GENERATION_MAX:
        raise _GenerationOutsideSchema("outside the shared u64 schema")
    return generation


def read_grant_high_water(secrets_dir):
    """The persisted grant high-water as an int: ABSENT file ⇒ 0 (nothing minted yet);
    anything unreadable, unparsable, non-integer, negative, spelled in a form the app's
    u64 reader refuses (RK5b), or shaped as anything but ONE object carrying exactly one
    `grant_generation` member (RK5c) ⇒ `MintError`, NEVER 0.

    The refusal is the whole point of the file. A corrupt high-water read as 0 would let the
    next mint hand out a generation the app has already retired — i.e. it would silently
    disarm the rollback detector the file exists to be. (Same law as the aruna store's
    non-canonical latch: refuse LOUD rather than sort low.) No credential value can reach
    this file, so the path may ride the error message; the generation never does.
    """
    path = os.path.join(secrets_dir, GRANT_HIGH_WATER_FILENAME)
    # BINARY, not text (RK5e): a text-mode read decodes inside `read()`, where a byte that is
    # not UTF-8 escapes as a raw `UnicodeDecodeError` — past every door below and out of a
    # `main()` that catches `MintError` and nothing else. The decode happens at the FIRST
    # parse door instead, where it has a class.
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return 0
    except OSError:
        raise MintError(
            f"the grant high-water file exists but is not readable: {path}; refusing rather "
            "than reading the ratchet as 0 (a low read re-issues a retired generation)"
        ) from None
    try:
        return parse_ratchet_document(raw)
    except _NotUtf8Ratchet:
        raise MintError(
            f"the grant high-water file is not valid UTF-8: {path}; there is no text to read "
            "a generation out of, and the app's reader refuses the same bytes, so refusing "
            "rather than reading the ratchet as 0"
        ) from None
    except _RepeatedRatchetMember:
        raise MintError(
            "the grant high-water file repeats a member name inside one object at "
            f"{path}; a plain JSON reader keeps the last pair while the app's typed reader "
            "refuses the repeat outright, so the two readers would disagree about what the "
            "ratchet says — refusing rather than reading the ratchet as 0"
        ) from None
    except _UnknownRatchetMember:
        raise MintError(
            "the grant high-water file carries a member the shared schema has no field "
            f"for at {path}; the ratchet is exactly one object with exactly one "
            "`grant_generation` member, and the app's typed reader refuses the extra field, "
            "so refusing rather than reading the ratchet as 0"
        ) from None
    except _NonCanonicalGeneration:
        raise MintError(
            "the grant high-water file spells its generation in a form the shared u64 "
            f"schema has no value for (signed, or zero-padded) at {path}; the app's reader "
            "refuses the same bytes, so refusing rather than reading the ratchet as 0"
        ) from None
    except _NotARatchetObject:
        raise MintError(
            f"the grant high-water file is not a JSON object: {path}; refusing rather than "
            "reading the ratchet as 0") from None
    except _AbsentGenerationMember:
        raise MintError(
            "the grant high-water file carries no `grant_generation` member "
            f"({path}); refusing rather than reading the ratchet as 0") from None
    except _UnusableGeneration as unusable:
        raise MintError(
            "the grant high-water file's `grant_generation` is not a non-negative integer "
            f"({unusable.type_name}) at {path}; refusing rather than reading the "
            "ratchet as 0") from None
    except _GenerationOutsideSchema:
        raise MintError(
            "the grant high-water file's `grant_generation` is outside the shared schema "
            f"(u64: 0..={GRANT_GENERATION_MAX}) at {path}; the app's reader cannot "
            "represent it, so refusing rather than reading the ratchet as usable") from None
    except ValueError:
        raise MintError(
            f"the grant high-water file is not parsable JSON: {path}; refusing rather than "
            "reading the ratchet as 0") from None


def print_grant_high_water(secrets_dir):
    """`--print-high-water`: print the ratchet's standing generation as a BARE integer, read
    ONLY through `read_grant_high_water` above. No network, no client_secret.json, no write.

    #75 S0 r11 (F14), and this is a REVERT, not a feature. The live-drill runbook used to tell
    the operator to export the generation with a hand-rolled
    `python -c "...json.load(open(grant_high_water.json))['grant_generation']"` — making the
    CEREMONY's reader a third, tolerant one. The r11 audit witnessed the consequence: a
    repeated member, an unknown member, a string-typed generation, a `-0`-then-2 last-wins
    pair and a nested extra object are each REFUSED by this module's reader AND by the app's
    typed `RatchetFile`, yet `json.load` hands every one of them back as a plain integer that
    the drill's `parse::<u64>` then accepts. The drill could run to a GREEN closure, and bank
    evidence, under a ratchet the mint refuses to read and the app refuses to admit. The
    ceremony now reads the ratchet through the SAME door everything else does.

    CONTRACT, because a shell interpolates this through `$( )`:
      * stdout is the integer and NOTHING else — no `[mint]` prefix, which would export a
        string `parse::<u64>` rejects.
      * an unusable ratchet RAISES `MintError`; `main` prints the sentence on stderr and exits
        NON-ZERO, so the operator never exports an empty value. (`live_readside.rs` also
        refuses an empty var, so the failure stays loud on both ends.)
      * an ABSENT ratchet prints 0 — this reader's own "nothing minted yet" semantics, carried
        through unchanged rather than re-decided here. The drill then refuses 0 against any
        real bundle. The runbook says this out loud so the operator is not surprised by it.
      * the ratchet holds ONE small counter and no credential value, so no secret can reach
        stdout down this path.

    NAMED RESIDUAL (r11 audit §A.4, accepted, zero grind): the drill's env leg is
    `high_water_raw.trim().parse::<u64>()`, which also accepts `+9`, `009` and surrounding
    whitespace — spellings the file-level strict readers refuse by construction
    (`_NonCanonicalGeneration`). Nothing in the ceremony PRODUCES them now that this mode is
    the producer; the only other author of that env var is the operator, i.e. the box owner,
    who is above the ceiling. Tightening it buys nothing against any actor in the pinned
    adversary model.
    """
    resolved = validate_secrets_dir(os.path.expanduser(secrets_dir))
    print(read_grant_high_water(resolved))
    return 0


def raise_grant_high_water(secrets_dir, generation):
    """Raise the persisted high-water to `generation` — MAX-ONLY — and return the standing
    value. A lower (or equal) generation writes NOTHING: this is never a plain assignment,
    because an assignment is exactly the operation that can walk the ratchet backwards.

    Reads first, so a corrupt high-water refuses here too — a raise must never be the act
    that silently repairs (overwrites) a file whose bytes we could not understand.
    """
    if type(generation) is not int or generation < 1:
        raise MintError(
            "refusing to raise the grant high-water to a non-positive or non-integer "
            f"generation ({type(generation).__name__}); generations start at 1")
    if generation > GRANT_GENERATION_MAX:
        raise MintError(
            "refusing to raise the grant high-water outside the shared schema "
            f"(u64: 1..={GRANT_GENERATION_MAX}); the app's reader cannot represent it")
    standing = read_grant_high_water(secrets_dir)
    if generation <= standing:
        return standing
    atomic_write(os.path.join(secrets_dir, GRANT_HIGH_WATER_FILENAME),
                 json.dumps({GRANT_GENERATION_MEMBER: generation}, indent=2) + "\n")
    return generation


# RK2 TYPE-CARRIED (#91): the reservation used to be a bare `int`, so "reserve, THEN
# publish" lived only in `run_mint`'s statement order and in the comment above it — one
# edit away from the credential-first ordering council r1 seat 3 EXECUTED a rollback
# against. A number carries no evidence that it was ever claimed. `ReservedGeneration` IS
# that evidence: `reserve_grant_generation` is its only constructor (the witness below is
# module-private and is never handed out), it remembers WHICH ratchet it was claimed in,
# and both publisher doors demand one. The ratchet's own reader and raiser
# (`read_grant_high_water` / `raise_grant_high_water`) are untouched — they ARE the ratchet,
# and the door being closed here is the DOCUMENT BUILDER's, not theirs.
_RESERVATION_WITNESS = object()


class ReservedGeneration:
    """A grant generation this mint has ALREADY claimed in the ratchet, plus the ratchet it
    claimed it in. Constructed ONLY by `reserve_grant_generation` — the witness argument is
    a module-private sentinel, so nothing outside this module can fabricate one without
    reaching into the module's privates (which is in-process code-exec, not a door anyone
    can hold).

    Deliberately NOT an `int` subclass: a subclass would be silently accepted by every
    arithmetic and comparison site that used to take the bare value, which is exactly the
    confusion the type exists to end.
    """

    __slots__ = ("generation", "secrets_dir")

    def __init__(self, witness, generation, secrets_dir):
        if witness is not _RESERVATION_WITNESS:
            raise MintError(
                "a ReservedGeneration is minted ONLY by `reserve_grant_generation`, which "
                "raises the ratchet BEFORE the value exists; refusing to fabricate one")
        self.generation = generation
        self.secrets_dir = secrets_dir

    def __repr__(self):
        # The generation never rides a repr or a refusal: both name the CLASS, never the
        # value (the same law MintError holds for principals and tokens).
        return "ReservedGeneration(<claimed>)"


def require_reserved_generation(reserved, secrets_dir, verb):
    """The publishers' shared door: unwrap a `ReservedGeneration` claimed against THIS
    ratchet, or refuse. Neither refusal names the value it was handed."""
    if not isinstance(reserved, ReservedGeneration):
        raise MintError(
            f"refusing to {verb} from a bare grant generation value "
            f"({type(reserved).__name__}): the publisher requires a ReservedGeneration, "
            "the one value `reserve_grant_generation` returns, so a credential can never "
            "be published under a generation the ratchet has not already claimed")
    if os.path.abspath(reserved.secrets_dir) != os.path.abspath(secrets_dir):
        raise MintError(
            f"refusing to {verb} from a ReservedGeneration claimed against a "
            "different secrets directory; a reservation is only meaningful over the "
            "ratchet file it was taken from")
    return reserved.generation


def publishable_credential_bytes(secrets_dir, reserved_generation, document):
    """The LAST door before credential bytes reach the disk (#91): the caller hands back the
    SAME reservation the document was built under, and the document's own `grant_generation`
    must BE it. A document built here and published under some other number would put the
    ratchet and the credential out of step in the one direction that revives a superseded
    authority, so the two are checked against each other where the bytes are produced."""
    generation = require_reserved_generation(reserved_generation, secrets_dir,
                                             "publish a credential")
    grant = document.get("grant") if isinstance(document, dict) else None
    carried = grant.get("grant_generation") if isinstance(grant, dict) else None
    if type(carried) is not int or carried != generation:
        raise MintError(
            "refusing to publish a credential whose grant object does not carry the "
            "generation this mint reserved; the reservation and the bytes must agree")
    return json.dumps(document, indent=2) + "\n"


def reserve_grant_generation(secrets_dir):
    """RESERVE the next grant generation: raise the high-water to N+1 and return N+1.

    RK2 — the mint claims a generation in the ratchet BEFORE any credential carries it.
    Call this while holding the credential writer lock, so the read and the raise cannot
    interleave with another mint. The return value is a `ReservedGeneration`, not an `int`
    (#91): the publishers demand that type, so a credential cannot be built at all until the
    ratchet has claimed its generation.

    WHY reserve-first, stated honestly (this REVERSES the build record's original ordering
    argument, which was wrong): with the credential written first and the ratchet raised
    last, a crash in the gap leaves the high-water at N, so the NEXT consent derives N+1
    again — two DIFFERENT authorities wearing the same generation, after which restoring
    the first credential passes the equality check and revives a superseded authority.
    Council r1 seat 3 executed exactly that ("first consent generation = 1 / re-run consent
    generation = 1 / standing high-water = 1 / restored first credential generation = 1").
    Reserve-first cannot produce it: a crash between the reservation and the write leaves
    the high-water at N+1 above an old gen-N credential, which the app RETIRES — a loud
    re-consent. Spending a generation number is cheap; reusing one is not.
    """
    standing = read_grant_high_water(secrets_dir)
    reserved = standing + 1
    if reserved > GRANT_GENERATION_MAX:
        raise MintError(
            "refusing to reserve a grant generation outside the shared schema "
            f"(u64: 1..={GRANT_GENERATION_MAX}); the ratchet has saturated and the app's "
            "reader cannot represent the next generation. Nothing was written.")
    raised = raise_grant_high_water(secrets_dir, reserved)
    if raised != reserved:
        # MAX-ONLY means a raise to N+1 over a standing N always lands; if it did not, the
        # file moved under us and the generation we were about to publish is not ours.
        raise MintError(
            "the grant high-water did not take the reservation (it stands at or above the "
            "generation we tried to reserve); refusing to publish a credential under a "
            "generation this mint does not own")
    return ReservedGeneration(_RESERVATION_WITNESS, reserved, secrets_dir)


# ---------------------------------------------------------------------------------------
# The ratchet-reader PARITY CORPUS (#75 S0 residual #91). The `grant_high_water.json` file
# has TWO readers — this mint's `read_grant_high_water` and the app's typed Rust reader —
# and the whole point of the file is lost the moment they disagree about one byte-string
# (council r2 seat 3 and r3 seat 2 both executed exactly that class of divergence). Prose
# cannot hold that; a shared FIXTURE can. The corpus below is emitted from THIS reader —
# every verdict is produced by `parse_ratchet_document`, the same code the read door runs —
# and committed at src-tauri/tests/fixtures/ratchet-parity-corpus.json so the Rust side can
# assert its own reader against the identical bytes. M13 regenerates it in memory every
# self-test run and refuses any drift, in either direction.
#
# The witness matrices M9 and M10 exercise live HERE, at module scope, rather than inside
# `self_test`: the corpus must be the SAME byte-strings the self-test asserts on, not a
# retyped copy of them.
# ---------------------------------------------------------------------------------------

# (name, raw integer token, does the reader ACCEPT it) — M9's lexical domain matrix.
RATCHET_LEXICAL_MATRIX = (
    ("negative-zero", "-0", False),        # negative zero: serde_json refuses, json admits 0
    ("negative-one", "-1", False),         # signed
    ("leading-plus", "+1", False),         # JSON rejects the leading plus — MintError, never a crash
    ("zero-padded", "00", False),          # zero-padded
    ("canonical-zero", "0", True),         # the canonical zero
    ("canonical-seven", "7", True),
    ("u64-max", "18446744073709551615", True),
    ("u64-max-plus-one", "18446744073709551616", False),   # M7's numeric bound still holds
    ("exponent", "1e2", False),            # exponent spelling is a float, not a u64 token
)

# CPython `json` EXTENSIONS — RFC 8259 has no such literals and serde_json refuses all three.
RATCHET_JSON_EXTENSION_TOKENS = ("NaN", "Infinity", "-Infinity")

# (name, document, the class the refusal must name; "" = either door, refusal is enough)
RATCHET_REPEAT_MATRIX = (
    ("negative-zero-then-two",
     '{"grant_generation": -0, "grant_generation": 2}', ""),      # the executed finding
    ("two-then-negative-zero",
     '{"grant_generation": 2, "grant_generation": -0}', ""),      # …and the other order
    ("seven-then-two",
     '{"grant_generation": 7, "grant_generation": 2}', "repeat"), # last-wins = ROLLBACK
    ("two-then-seven",
     '{"grant_generation": 2, "grant_generation": 7}', "repeat"), # …and the other order
    ("identical-twins",
     '{"grant_generation": 1, "grant_generation": 1}', "repeat"), # identical twins too
    ("any-name-twice",
     '{"extra": 1, "extra": 2}', "repeat"),                       # a repeat of ANY name
)

# (name, document) — members outside the shared schema.
RATCHET_STOWAWAY_MATRIX = (
    ("trailing", '{"grant_generation": 7, "extra": 1}'),              # trailing stowaway
    ("leading", '{"extra": 1, "grant_generation": 7}'),               # leading stowaway
    ("case-twist", '{"grant_generation": 7, "Grant_Generation": 8}'), # a case-twist is one
    ("no-generation-at-all", '{"extra": 1}'),                         # no generation at all
)

# (name, EXACT file bytes) — the single-document probes M9 and M10 write verbatim.
RATCHET_SINGLE_PROBES = (
    ("m9-negative-zero-echo-probe", '{"grant_generation": -0}\n'),
    ("m10-repeat-echo-probe",
     '{"grant_generation": 424242, "grant_generation": 424243}\n'),
    ("m10-stowaway-echo-probe", '{"grant_generation": 7, "extra": 424242}\n'),
    ("m10-legal-document", '{"grant_generation": 7}\n'),
    ("m10-legal-document-spaced", '  {\n  "grant_generation"  :  7\n}\n'),
    ("m10-array-wrapped", '[{"grant_generation": 7}]\n'),
)

# (name, EXACT file bytes) — the boundary spellings the two readers are most likely to
# disagree on, none of which any witness in this file happens to write. Tight (no space
# after the colon) and newline-free on purpose: the app's reader sees FILE BYTES, and a
# corpus that only ever exercises this script's own pretty-printed spelling would prove
# nothing about the ones an operator, an editor, or another tool can produce.
RATCHET_BOUNDARY_PROBES = (
    ("tight-seven", '{"grant_generation":7}'),
    ("spaced-seven", ' { "grant_generation" : 7 } '),
    ("tight-zero", '{"grant_generation":0}'),
    ("tight-u64-max", '{"grant_generation":18446744073709551615}'),
    ("tight-u64-max-plus-one", '{"grant_generation":18446744073709551616}'),
    ("tight-negative-zero", '{"grant_generation":-0}'),
    ("tight-negative-one", '{"grant_generation":-1}'),
    ("tight-leading-plus", '{"grant_generation":+1}'),
    ("tight-zero-padded", '{"grant_generation":00}'),
    ("tight-exponent", '{"grant_generation":1e2}'),
    ("tight-float", '{"grant_generation":1.0}'),
    ("tight-string-seven", '{"grant_generation":"7"}'),
    ("tight-true", '{"grant_generation":true}'),
    ("tight-null-value", '{"grant_generation":null}'),
    ("tight-nan", '{"grant_generation":NaN}'),
    ("tight-infinity", '{"grant_generation":Infinity}'),
    # A FULLWIDTH DIGIT SEVEN (U+FF17), UTF-8 encoded: it looks like a 7 in an editor and is
    # not one to any JSON reader.
    ("fullwidth-digit-seven", '{"grant_generation":\uff17}'),
    # A UTF-8 BOM in front of an otherwise perfect document — what a Windows editor leaves.
    ("utf8-bom-then-seven", '\ufeff{"grant_generation":7}'),
    ("tight-repeat-seven-eight", '{"grant_generation":7,"grant_generation":8}'),
    ("tight-repeat-negative-zero-then-two",
     '{"grant_generation":-0,"grant_generation":2}'),
    ("tight-repeat-two-then-negative-zero",
     '{"grant_generation":2,"grant_generation":-0}'),
    ("tight-trailing-stowaway", '{"grant_generation":7,"note":1}'),
    ("tight-leading-stowaway", '{"note":1,"grant_generation":7}'),
    ("empty-object", "{}"),
    ("tight-array-wrapped", '[{"grant_generation":7}]'),
    ("bare-number", "7"),
    ("bare-null", "null"),
    ("empty-file", ""),
    ("trailing-second-object", '{"grant_generation":7}{}'),
    # Python's own integer-literal underscore spelling is not JSON.
    ("python-underscore-literal", '{"grant_generation": 1_000}'),
    ("tight-seven-blank-line", '{"grant_generation":7}\n\n'),
    # THE MEMBER NAME IN ESCAPED SPELLING (council r4, corpus completion). A JSON member name
    # is a JSON STRING, so `grant_generation` IS `grant_generation` — to any conforming
    # reader. Both readers must therefore ACCEPT the first and refuse the second as a REPEAT:
    # a reader that compared raw name BYTES would admit the second as one legal member and
    # the other would refuse it, which is exactly the class of divergence this corpus exists
    # to catch.
    ("escaped-member-name", '{"\\u0067rant_generation":42}'),
    ("escaped-duplicate-member",
     '{"grant_generation":9,"\\u0067rant_generation":8}'),
    # A NUL after an otherwise perfect document — valid UTF-8, and not JSON. (A truncated
    # write, or a tool padding a file to a block.)
    ("nul-after-document", '{"grant_generation":7}\x00'),
    # CRLF around the document — what a Windows editor writes. Insignificant whitespace to
    # both readers, and this is the corpus that has to prove it.
    ("crlf-around-document", '\r\n{"grant_generation":7}\r\n'),
)

# (name, EXACT file bytes) — byte-strings that are NOT TEXT. The ratchet file is a FILE, and a
# file is bytes; the app's Rust reader takes `&[u8]` and never decodes separately, so the mint
# has to be able to say something typed about bytes that are not UTF-8 rather than let the
# decoder's own exception escape the read door. (Council r4 seats 2 and 3, EXECUTED.)
RATCHET_NOT_UTF8_PROBES = (
    ("lone-invalid-byte", b"\xff"),
    ("invalid-byte-before-document", b'\xff{"grant_generation":7}'),
    ("invalid-byte-after-document", b'{"grant_generation":7}\xff'),
)

# (name, EXACT file text) — a legal ratchet SHAPE whose one member's VALUE is a nested object or
# an array. The honest class is the VALUE's type (`not-u64`), never a member-shape class: the
# document has exactly one member, spelled once, and it is `grant_generation`. (Council r4 seat 1,
# EXECUTED — the shape hook used to judge every nested object CPython decoded, so the nested
# object's own members were reported as the ratchet's.)
RATCHET_NESTED_VALUE_PROBES = (
    ("nested-object-value", '{"grant_generation":{"n":7}}'),
    ("array-value", '{"grant_generation":[7]}'),
    ("nested-ratchet-value", '{"grant_generation":{"grant_generation":7}}'),
)

RATCHET_PARITY_CORPUS_SCHEMA = "photon.ratchet-parity-corpus.v1"

# Sentinel class -> the corpus label for the refusal it represents. The three numeric-domain
# refusals collapse to ONE label on purpose: `not-u64` is the property the app's reader has
# to agree with (there is no u64 for these bytes), and WHICH of our doors caught it is our
# internal business, pinned separately by M9/M10.
RATCHET_REFUSAL_LABELS = (
    (_NotUtf8Ratchet, "not-utf8"),
    (_RepeatedRatchetMember, "repeated-member"),
    (_UnknownRatchetMember, "unknown-member"),
    (_NonCanonicalGeneration, "not-u64"),
    (_UnusableGeneration, "not-u64"),
    (_GenerationOutsideSchema, "not-u64"),
    (_NotARatchetObject, "not-an-object"),
    (_AbsentGenerationMember, "absent-member"),
)


def ratchet_reader_verdict(raw):
    """What THIS reader does to a ratchet file containing exactly `raw` (bytes), as one
    short string: `accept:<int>` or `refuse:<label>`.

    The ABSENT file is deliberately not expressible here and is not a corpus case: "no file"
    is not a byte-string, it is the one state that legitimately reads as 0, and pinning it
    as a parse outcome would invite a reader to treat an EMPTY file the same way (it does
    not — an empty file is `refuse:not-json`).
    """
    try:
        return "accept:%d" % parse_ratchet_document(raw)
    except ValueError as refusal:
        for sentinel, label in RATCHET_REFUSAL_LABELS:
            if isinstance(refusal, sentinel):
                return "refuse:" + label
        return "refuse:not-json"


def ratchet_parity_cases():
    """The corpus: every ratchet byte-string this file's own M9/M10 witnesses exercise, plus
    the boundary spellings above, each with the verdict THIS reader gives it. Byte-strings
    are deduplicated (two provenances, one case) and the result is sorted by name."""
    cases = []
    seen = {}

    def add(name, document):
        raw = document.encode("utf-8") if isinstance(document, str) else document
        if raw in seen:
            return                    # the same bytes under two provenances: one case
        seen[raw] = name
        cases.append({"name": name,
                      "bytes_b64": base64.b64encode(raw).decode("ascii"),
                      "python": ratchet_reader_verdict(raw)})

    for name, token, _admitted in RATCHET_LEXICAL_MATRIX:
        add("m9-lexical-" + name, '{"grant_generation": %s}\n' % token)
    for token in RATCHET_JSON_EXTENSION_TOKENS:
        add("m9-json-extension-" + token.lower().replace("-", "minus-"),
            '{"grant_generation": %s}\n' % token)
    for name, document, _named_class in RATCHET_REPEAT_MATRIX:
        add("m10-repeat-" + name, document + "\n")
    for name, document in RATCHET_STOWAWAY_MATRIX:
        add("m10-stowaway-" + name, document + "\n")
    for name, document in RATCHET_SINGLE_PROBES:
        add(name, document)
    for name, document in RATCHET_BOUNDARY_PROBES:
        add("boundary-" + name, document)
    for name, probe in RATCHET_NOT_UTF8_PROBES:
        add("m14-" + name, probe)
    for name, document in RATCHET_NESTED_VALUE_PROBES:
        add("m15-" + name, document + "\n")
    cases.sort(key=lambda case: case["name"])
    return cases


def ratchet_parity_corpus_bytes():
    """The corpus fixture's EXACT bytes: ASCII-only JSON, two-space indent, one trailing
    newline, and no platform in it — the file is compared byte-for-byte on every OS, and it
    is read by a Rust test that must see the same bytes we emitted."""
    corpus = {"schema": RATCHET_PARITY_CORPUS_SCHEMA, "cases": ratchet_parity_cases()}
    return (json.dumps(corpus, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def emit_ratchet_parity_corpus(path):
    """Write the corpus fixture. Binary, so no newline translation can put CRLF into a file
    two operating systems have to agree on byte-for-byte."""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "wb") as f:
        f.write(ratchet_parity_corpus_bytes())
    return path


def http_error_for(endpoint_label, status):
    """The ONLY constructor for HTTP-failure errors: endpoint LABEL + status. The response
    body (which can echo request parameters, tokens, or identities) is never consulted."""
    return MintError(f"{endpoint_label} returned HTTP {status}; body withheld (may echo secrets)")


# ---------------------------------------------------------------------------------------
# Cross-process writer lock (design 2026-08-25-74 §3-S6/§3-S8): the app and this script
# both take an OS advisory lock over the SAME kernel lock family with an OVERLAPPING extent
# before either one writes a credential file — closing the last-writer-wins race where a
# concurrent mint can cross Google's 100-refresh-token cap and silently invalidate the very
# token the app is about to persist (§3-S6's hazard sentence: atomic rename cannot fix a lost
# update, only mutual exclusion can). This is the mint script's half of the protocol.
# ---------------------------------------------------------------------------------------

def _acquire_lock_nonblocking(fd):
    """One non-blocking attempt at an EXCLUSIVE lock on a freshly opened `fd`. Raises
    OSError on contention (never blocks) — the caller decides retry vs. give up.

    Unix: `fcntl.flock` — the flock FAMILY, never `lockf`/fcntl record locks (design
    §3-S6: flock and fcntl record locks do not interact on ordinary Linux, and the Rust side
    takes flock, so this side must too).
    Windows: `msvcrt.locking` over a 1-byte range AT OFFSET 0 (seek first) — overlapping the
    Rust side's LockFileEx range, which also starts at byte 0 (design §3-S6).
    """
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)


def _release_lock(fd):
    """Undo `_acquire_lock_nonblocking` on the same `fd`."""
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextlib.contextmanager
def credential_writer_lock(secrets_dir, deadline_s=5.0, timeout_hint=None):
    """Hold the cross-process credential writer lock for the duration of the `with` block
    (design §3-S6). Lock file: `<secrets_dir>/credential.lock` — an ADDRESS, created if
    absent and NEVER deleted (mirrors the store_open lock-file lifecycle: kernel-released on
    process death, never unlinked). A FRESH handle is opened on every call: flock/msvcrt
    locks attach to the open file description, so a cached handle re-locked would be a silent
    no-op conversion, not exclusion.

    Polls every 100 ms until a MONOTONIC deadline (`deadline_s`, default 5.0); on expiry
    raises `MintError` naming the lock path and that another writer holds it — LOUD, no
    write, no hang. The blocking form of the OS call is never used. Released (unlocked and
    closed) on the way out of the `with` block, including when it raises.
    """
    lock_path = os.path.join(secrets_dir, "credential.lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + deadline_s
        while True:
            try:
                _acquire_lock_nonblocking(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    # `timeout_hint` lets a call site whose post-timeout STATE the generic
                    # sentence cannot know (the post-consent mint: tokens already issued,
                    # nothing persisted) append its honest consequence — council r2's A
                    # condition (all three seats).
                    raise MintError(
                        f"could not acquire the credential writer lock at {lock_path} "
                        "within the deadline; another writer holds it"
                        + (f". {timeout_hint}" if timeout_hint else "")) from None
                time.sleep(0.1)
        try:
            yield
        finally:
            _release_lock(fd)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------------------
# Attended network path. The DOOR CONTRACT halves (read_bounded_json, the headers-arrival
# sample) ARE exercised by --self-test (W46-py/W47-py); the live network calls are not.
# ---------------------------------------------------------------------------------------

# The unified door contract's bound (design §2 amendment 2026-08-26): BOTH remote
# token-response doors — the app's parse_refresh_response and this script — refuse a body
# over 64 KiB before parsing it. Mirrors token_refresh.rs::MAX_REFRESH_BODY_BYTES (the
# constant name corrected at council r2, S1-F5 — the class that makes a relay look like a
# witness, second instance; the folder opened the Rust constant this time).
TOKEN_RESPONSE_MAX_BYTES = 64 * 1024


def read_bounded_json(resp, endpoint_label):
    """Read at most TOKEN_RESPONSE_MAX_BYTES from an open response and parse it as JSON.

    Code-council r1 S2-F1 (EXECUTED): the pre-fix unbounded `resp.read()` accepted a
    ~65.6 KiB token response the Rust door refuses as BodyTooLarge — two doors, two
    contracts. This is the shared bound; over-cap refuses LOUDLY (attended script: loud
    exit IS the refusal posture, design §2).
    """
    body = resp.read(TOKEN_RESPONSE_MAX_BYTES + 1)
    if len(body) > TOKEN_RESPONSE_MAX_BYTES:
        raise MintError(
            f"{endpoint_label} response exceeded {TOKEN_RESPONSE_MAX_BYTES // 1024} KiB; "
            "refusing to parse an unbounded body (design §2 unified door contract)")
    # F20 (council r5, EXECUTED at this door by seat 3): a body that REPEATS a member name is
    # refused before any member is read — as AMBIGUOUS (F21-g warrant recut: RFC 8259 §4 leaves
    # duplicate names reader-defined, SHOULD-unique + §8.3 interop; RFC 6749 §3.2's MUST NOT
    # carries the parameters that RFC defines, per its verified erratum 5708). A last-wins
    # `json.loads` let the WIRE ORDER of two `scope` members decide which authority the mint
    # believed the token carried. The hook fires for every object at every depth (RK5d), so
    # this door refuses nested repeats too — strictly more refusing than the Rust door's top-level
    # check, on content neither door consults. Parity corpus: --self-test F20-py.
    def _unique_members(pairs):
        seen = set()
        for name, _ in pairs:
            if name in seen:
                raise MintError(
                    f"{endpoint_label} response repeats a member name; refused as ambiguous "
                    "(RFC 8259 §4; RFC 6749 §3.2 for the parameters it defines)")
            seen.add(name)
        return dict(pairs)
    try:
        parsed = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_members)
    except MintError:
        raise
    # F21 (council r6, seat 1 A EXECUTED): a top-level list/string parsed fine and the caller's
    # `.get` blew up as a raw AttributeError — the Rust door refuses the identical shape as
    # BodyNotAnObject. One door, one sentence, both sides.
    if not isinstance(parsed, dict):
        raise MintError(
            f"{endpoint_label} response body is not a JSON object; refusing to read members "
            "off it")
    return parsed


def post_form(url, params, endpoint_label):
    """POST a form; returns (parsed_json, received_unix).

    received_unix is sampled the moment open() returns — HEADERS-ARRIVAL, before any body
    byte is consumed — per design §2's clock law (code-council r1 S2-F2, EXECUTED: the
    slow-body probe showed the pre-fix post-read anchor stretching a declared 10 s
    lifetime by the body's 1.25 s transfer latency, in the unsafe direction). Callers
    that attest a lifetime MUST anchor to this sample (W47-py pins the wiring).
    """
    data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        # Redirect-REFUSING opener (codex r1 P1-1): a 30x raises before any re-send.
        with _OPENER.open(req, timeout=60) as resp:
            received_unix = time.time()
            return read_bounded_json(resp, endpoint_label), received_unix
    except urllib.error.HTTPError as e:
        raise http_error_for(endpoint_label, e.code) from None
    except urllib.error.URLError:
        raise MintError(f"{endpoint_label} unreachable") from None


def get_json(url, bearer, endpoint_label):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer}"})
    try:
        # Redirect-REFUSING opener (codex r1 P1-1): the bearer never follows a Location.
        # Same bounded read as the token door — one contract for every remote body here.
        with _OPENER.open(req, timeout=60) as resp:
            return read_bounded_json(resp, endpoint_label)
    except urllib.error.HTTPError as e:
        raise http_error_for(endpoint_label, e.code) from None
    except urllib.error.URLError:
        raise MintError(f"{endpoint_label} unreachable") from None


# F21: the one token the callback publishes for an ambiguous authorization response.
AMBIGUOUS_CALLBACK = "ambiguous_authorization_response"


def _callback_outcome_from_query(query):
    """Select the authorization callback's (code, error) from the decoded query mapping —
    or refuse the whole callback as AMBIGUOUS.

    F21 (council r6 — seat 3 run 2 F1, EXECUTED; seat 2's omission lane independently): the
    pre-fix selection took the FIRST of a repeated `code`/`error` (`parse_qs` keeps every
    value; the `[0]` chose) and let `code` ride beside `error` — wire order guessed which
    authorization the mint exchanged. RFC 6749 §3.1 forbids repeating a parameter the RFC
    defines (`code` and `error` are; erratum 5708 scopes the rule to exactly these), and
    Google documents `code`/`error` as ALTERNATIVES — so a repeated `code`, a repeated
    `error`, or the two together is one ambiguous response, refused as a terminal outcome
    (the wait loop ends; nothing is exchanged). The refusal carries no callback bytes and
    blames no actor: a local injector and a nonconforming server are indistinguishable here.
    """
    codes = query.get("code") or []
    errors = query.get("error") or []
    if len(codes) > 1 or len(errors) > 1 or (codes and errors):
        return None, AMBIGUOUS_CALLBACK
    return (codes or [None])[0], (errors or [None])[0]


def callback_outcome_from_raw_query(raw_query):
    """The ONE reader from the callback's RAW query string to (code, error) — blank values
    PRESERVED.

    F22 (codex-CLI r18 P2, driver-EXECUTED red): the default `parse_qs` DROPS a member whose
    value is blank, so `?code=&code=REAL` and `?code=REAL&error=` reached the ambiguity
    check as one clean `code` and were exchanged — the F21-a refusal bypassed by the parse
    config upstream of it. `keep_blank_values=True` hands the check every member the wire
    carried. A SINGLE blank `code=` now selects `""` (falsy — the wait loop keeps waiting,
    exactly the pre-F22 behaviour for that shape; an attended script, loud on timeout).
    """
    return _callback_outcome_from_query(
        urllib.parse.parse_qs(raw_query, keep_blank_values=True))


def callback_ack_text(code, error):
    """The browser page for one callback outcome — three STATIC literals, chosen by outcome.

    F24-c (council r7 — seats 2 and 3 EXECUTED this independently over real HTTP; the driver
    reproduced it): the page used to say "Consent received" unconditionally — on a denial,
    on an ambiguous callback, and on a still-pending blank — asserting success in states
    that are failure or waiting. The page is a MIRROR of what the callback established,
    nothing more: Google's own loopback guidance is a close-and-return page, and every
    literal below is static — no callback byte ever reaches the browser.
    """
    if code:
        return b"Consent received. You may close this window."
    if error is not None:
        return (b"Consent was NOT completed: the authorization response was refused or "
                b"denied. You may close this window; the terminal names the reason.")
    return (b"No complete authorization response was received. Photon is still waiting "
            b"for consent - check the terminal.")


class _CodeCatcher(http.server.BaseHTTPRequestHandler):
    code = None
    error = None

    def do_GET(self):  # noqa: N802 (http.server contract)
        # RFC 6749 §4.1.2.1: a denial arrives as error= (access_denied etc.) — captured so
        # the wait loop can terminate cleanly instead of spinning (codex r2 P2-4). The parse
        # itself lives in the shared raw-query reader (F22) so the self-test witnesses
        # exercise the handler's exact parse config, blank members included.
        _CodeCatcher.code, _CodeCatcher.error = callback_outcome_from_raw_query(
            urllib.parse.urlparse(self.path).query)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        # F24-c: the page mirrors the OUTCOME (static literals only, chosen by the same
        # (code, error) the wait loop consumes — one derivation, two consumers).
        self.wfile.write(callback_ack_text(_CodeCatcher.code, _CodeCatcher.error))

    def log_message(self, *_args):  # silence: request lines carry the auth code
        pass


def consent_and_exchange(client_id, client_secret, scope_list, slot):
    """PKCE loopback consent -> code exchange -> refresh->access exchange.

    Returns (access_token, refresh_token, expires_at_unix, effective_scopes, scope_source).
    The refresh->access exchange is deliberate: it proves the refresh token works at mint
    time and the drill runs on the refreshed access token's expiry, not the consent one's.

    The lane contract is enforced on the INITIAL effective grant, immediately after the code
    exchange and BEFORE the refresh exchange (codex r11 P2-2): a refresh token's authority is
    the AUTHORIZATION's grant, not any one access-token response's `scope` string — so a
    broader-than-requested code-exchange grant (e.g. a prior incremental grant folded in by
    the server) followed by a narrower refresh-response `scope` would pass the final granted
    check while a mutation-capable refresh credential got persisted. Refusing here means a
    violating grant never even reaches the refresh exchange, and nothing is ever written
    (all persistence happens after every check in run_mint).
    """
    verifier = base64.urlsafe_b64encode(pysecrets.token_bytes(32)).rstrip(b"=").decode()
    # SHA-256 here is EXTERNALLY MANDATED: RFC 7636 §4.2 defines the S256 code-challenge
    # method as BASE64URL(SHA256(verifier)) — a documented exception to the SHA-384 posture
    # (fips-crypto-inventory partition rule), not drift. Do not "convert" this site.
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    _CodeCatcher.code = None
    _CodeCatcher.error = None
    server = http.server.HTTPServer(("127.0.0.1", 0), _CodeCatcher)
    redirect = f"http://127.0.0.1:{server.server_address[1]}/"
    auth = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": client_id, "redirect_uri": redirect, "response_type": "code",
        "scope": " ".join(scope_list), "code_challenge": challenge,
        "code_challenge_method": "S256", "access_type": "offline", "prompt": "consent",
    })
    print(f"[mint] open this URL and grant consent for scopes: {' '.join(scope_list)}")
    print(f"[mint] {auth}")
    webbrowser.open(auth)
    # Bounded wait (codex r2 P2-4): short per-poll timeout inside an OVERALL deadline; an
    # error= callback or the deadline raises MintError via consent_outcome — never an
    # unbounded spin on a denied or abandoned consent screen.
    # MONOTONIC deadline (codex #74 r4 audit C1-m): the wall clock can step under NTP and cut
    # short or stretch an attended consent window; the lock's own deadline already uses
    # time.monotonic() — one discipline for the whole file.
    deadline = time.monotonic() + 300
    server.timeout = 5
    try:
        while consent_outcome(
            _CodeCatcher.code, _CodeCatcher.error, time.monotonic() > deadline
        ) is None:
            server.handle_request()
    finally:
        server.server_close()

    # The code exchange's headers-arrival sample is unused: no lifetime is attested from
    # this response (the drill runs on the REFRESH exchange's expiry, below).
    initial, _initial_received_unix = post_form(TOKEN_URL, {
        "client_id": client_id, "client_secret": client_secret,
        "code": _CodeCatcher.code, "code_verifier": verifier,
        "grant_type": "authorization_code", "redirect_uri": redirect,
    }, "token endpoint (code exchange)")
    refresh_token = initial.get("refresh_token")
    if not refresh_token:
        raise MintError("code exchange returned no refresh_token (re-run with prompt=consent)")
    # The sitting's INITIAL EFFECTIVE GRANT: what the code exchange actually granted (may be
    # narrower than requested) — the only legitimate fallback for the refresh step below.
    initial_scopes, initial_source = effective_scopes(scope_list, initial.get("scope", _ABSENT))
    # codex r11 P2-2: the refresh token inherits THIS grant — enforce the contract on it now,
    # before the refresh exchange can report a narrower scope past the final check.
    enforce_lane_scope_contract(slot, initial_scopes, "granted-initial (code exchange)")

    refreshed, refreshed_received_unix = post_form(TOKEN_URL, {
        "client_id": client_id, "client_secret": client_secret,
        "refresh_token": refresh_token, "grant_type": "refresh_token",
    }, "token endpoint (refresh exchange)")
    access = refreshed.get("access_token")
    if not access:
        raise MintError("refresh exchange returned no access_token")
    # The unified door contract's token-shape half (design §2 amendment 8): the credential
    # this response mints is validated to the SAME shape the app's door and loader enforce.
    require_token_shape(access, refreshed.get("token_type"),
                        "token endpoint (refresh exchange)")
    scopes, source = refresh_effective_scopes(
        initial_scopes, initial_source, refreshed.get("scope", _ABSENT))
    # RFC 6749 §6 rotation (codex r8 FOLD 3): persist the REPLACEMENT when the server sent one,
    # otherwise the original. Persisting a rotated-away token would emit a dead credential.
    surviving_refresh = surviving_refresh_token(
        refresh_token, refreshed.get("refresh_token", _ABSENT))
    if surviving_refresh != refresh_token:
        print("[mint] the authorization server ROTATED the refresh token; persisting the "
              "replacement (RFC 6749 §6)")
    # Attested, never invented (codex r10 P2-3): an absent/invalid expires_in refuses.
    # Anchored at HEADERS-ARRIVAL (design §2 clock law; code-council r1 S2-F2): the sample
    # post_form took when the response line landed — body-transfer latency must never
    # extend the credential's apparent life.
    expires_at = attested_expiry(refreshed_received_unix, refreshed.get("expires_in"))
    return access, surviving_refresh, expires_at, scopes, source


def load_client(secrets_dir, filename):
    path = os.path.join(secrets_dir, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        raise MintError(f"client secret file not readable: {path}") from None
    return client_from_config(data)


def run_mint(args):
    # Containment first (codex r3 P1-2): refuse a relative or repo-contained secrets dir
    # BEFORE any OAuth begins — tokens must never be writable into a worktree.
    secrets_dir = validate_secrets_dir(os.path.expanduser(args.secrets_dir))
    client_id, client_secret = load_client(secrets_dir, args.client_secret)
    helper_sha = helper_source_sha384()
    # (`minted_at` is sampled AFTER the exchanges, just before build_bundle — codex #74 r4
    # audit C1-l: up to two attended consent sessions sit between here and the bundle write,
    # and a stamp taken now would understate the credential's mint time by whole minutes.)

    # LANE CONTRACT, request time (codex r6): validate BOTH slots' REQUESTED sets before a
    # single consent is asked for — a violation mints nothing at all, rather than leaving a
    # mutation-capable credential on disk for the Rust preflight to refuse hours later.
    main_scope_list = args.scope.split()
    enforce_lane_scope_contract("main", main_scope_list, "requested")
    denial_scope_list = None if args.main_only else args.denial_scope.split()
    if denial_scope_list is not None:
        enforce_lane_scope_contract("denial", denial_scope_list, "requested")
        # PR #50 bot r2 P2: the identity comparison is email↔email, so the denial request
        # must be able to yield an email claim at all — refused before any consent is asked.
        require_email_claim_scopes(denial_scope_list)

    main_access, main_refresh, main_exp, main_scopes, main_source = \
        consent_and_exchange(client_id, client_secret, main_scope_list, "main")
    # …and on the EFFECTIVE GRANTED set, before anything is written: the authorization server
    # may grant something other than what was asked for.
    enforce_lane_scope_contract("main", main_scopes, "granted")
    # Identity for the MAIN slot via Gmail getProfile (authorized by gmail.modify, per the
    # getProfile reference). #75 S0: this is no longer held in-process only — it is PERSISTED
    # as the credential's `provider_principal`, so an unusable value REFUSES here rather than
    # travelling as a None into a token file (design v7 §4; build record §0 Item 5).
    main_identity = main_principal_from_profile(
        get_json(PROFILE_URL, main_access, "gmail getProfile"))

    denial_access = denial_refresh = None
    denial_scopes = denial_source = principal_match = None
    denial_exp = None
    if denial_scope_list is not None:
        denial_access, denial_refresh, denial_exp, denial_scopes, denial_source = \
            consent_and_exchange(client_id, client_secret, denial_scope_list, "denial")
        enforce_lane_scope_contract("denial", denial_scopes, "granted")
        info = get_json(USERINFO_URL, denial_access, "oidc userinfo")
        # Granted-stage gate (PR #50 bot r2 P2): the email claim itself, or a refusal —
        # never the opaque `sub`, which is not comparable to Gmail's emailAddress.
        denial_identity = denial_identity_from_userinfo(info)
        principal_match = same_principal(main_identity, denial_identity)

    minted_at = int(time.time())

    # ONE lock acquisition around the whole write set (design §3-S6) — CLAIM STATED EXACTLY
    # (council r2 S3-F4): the lock serializes OBSERVATION during the attempt (no reader sees
    # a half-written set while we hold it), and each file lands atomically; it is NOT a
    # transactional commit — a mid-set failure releases the lock on a durable mixed
    # generation, which the app-side preflight then REFUSES loudly as exactly that. Per-file
    # atomicity + loud mixed-generation refusal is the whole guarantee (design §5 non-claim).
    #
    # THE LOCK'S SPAN, stated honestly (codex #74 r4 F1; design §3-S6 amended, dated; the
    # guarantee WEAKENED to the honest bound 2026-08-26 — code-council r1 S2-F5/S3-F4): the
    # PROVIDER-SIDE mutations above (consent + exchanges — the acts that can cross Google's
    # 100-refresh-token cap) cannot sit inside a cross-process file lock, because an attended
    # consent runs up to 300 s while the app's own lock hold is bounded at seconds — the two
    # spans are mutually unsatisfiable. The lost-update close is an ENGINEERING MARGIN, not a
    # mechanical invariant: the deadline below (60 s) dominates the app wave's NETWORK-bounded
    # hold (5 s acquire + 30 s HTTP), but the wave's local tail (fsync/rename, provider
    # rebuild, digest reads, publication) carries no aggregate deadline, so the inequality is
    # expected, not proven. Within the margin the newest mint wins the disk and the app's next
    # admission reconciles to it (W22/W45). If a wave persisted a cap-invalidated token
    # between our exchanges and this write, it is overwritten seconds later; commands in that
    # window refuse transient and self-heal. On deadline expiry the failure is LOUD
    # (MintError) with the minted credential UNPERSISTED — the tokens exist at Google, a
    # re-run re-mints, and the abandoned mint may have consumed a refresh-token slot
    # (design residual §6-16; the mechanical bound is on council r2's agenda).
    with credential_writer_lock(
            secrets_dir, deadline_s=60.0,
            # TIMEOUT-MESSAGE HONESTY (council r2 question A's one condition, ruled 3/3):
            # at THIS call site a timeout means the consent already succeeded provider-side.
            timeout_hint=(
                "The freshly minted credential EXISTS at Google but was NOT persisted, and "
                "the mint may have consumed one of the ~100 live refresh-token slots for "
                "this client. Wait for the competing writer to finish, then re-run — do "
                "not re-consent in a loop.")):
        # GRANT PROVENANCE (#75 S0, design v7 §3/§4) — VALIDATE, RESERVE, THEN PUBLISH.
        #
        # (a) VALIDATE the write set's provider-supplied half while the ratchet has NOT
        #     moved: `require_publishable_principal` is the SAME code the document builder
        #     runs at its own last door (PL2), called here so a hostile or merely
        #     nonconformant getProfile reply refuses with the ratchet untouched and the
        #     previous credential still admissible (council r1 seat 1, F-1: without this,
        #     the mint writes a credential the loader always refuses AND retires the last
        #     good one, leaving the box-owner ratchet reset as the only exit). #91 moved
        #     this call OUT of the document builder's shadow: the document can no longer be
        #     built before the reservation exists, so F-1's pre-ratchet validation has to be
        #     its own step — the same bytes, run earlier, never a second copy of the law.
        # (b) RESERVE the generation — raise the high-water to N+1 under this lock. The
        #     result is a `ReservedGeneration`, and it is the only thing the publishers in
        #     (c) accept.
        # (c) BUILD the credential under that reservation and PUBLISH it, then the
        #     attestation bundle. The u64 generation bound (RK5) is enforced at (b), where
        #     the generation is minted, rather than at the document.
        #
        # ORDER, and it is load-bearing. THIS REVERSES the ordering this file shipped with,
        # and the old argument ("the credential lands FIRST, the ratchet is raised LAST, so
        # a crash cannot retire a working credential") was WRONG: council r1 seat 3
        # EXECUTED the hole it leaves. With the credential first, a crash before the raise
        # leaves the high-water at N, the next consent derives N+1 again, and two DIFFERENT
        # consents carry the same generation — after which restoring the first credential
        # passes the equality check and revives a superseded authority. Reserve-first
        # cannot do that: a crash between (b) and (c) leaves the high-water at N+1 above
        # the old gen-N credential, which the app RETIRES — one loud re-consent, never a
        # duplicated generation. The gap's cost is a spent generation number and a
        # re-consent; the old gap's cost was a reusable authority identity.
        #
        # The read is UNDER THIS LOCK, so two mints cannot both derive N+1 from the same
        # standing high-water. An absent high-water reads as 0 ⇒ this is generation 1; a
        # corrupt one REFUSES here, before anything is written.
        expected_generation = read_grant_high_water(secrets_dir) + 1
        require_publishable_principal(main_identity)
        reserved_generation = reserve_grant_generation(secrets_dir)
        grant_generation = reserved_generation.generation
        if grant_generation != expected_generation:
            # We hold the writer lock, so nothing legitimate moves the ratchet between the
            # read above and the reservation. Refuse rather than publish under a generation
            # we did not reserve — nothing has been written yet.
            raise MintError(
                "the grant high-water moved between validation and reservation while this "
                "mint held the credential writer lock; refusing to publish. The minted "
                "credential was NOT persisted — re-run the mint.")
        main_token = main_token_document(main_access, main_refresh, main_exp,
                                         reserved_generation, main_identity, main_scopes,
                                         secrets_dir)
        bundle = build_bundle(main_access, main_scopes, main_source, minted_at, main_exp,
                              helper_sha, denial_token=denial_access,
                              denial_scopes=denial_scopes, denial_source=denial_source,
                              principal_match=principal_match, expires_at_denial=denial_exp,
                              grant_generation=grant_generation)
        atomic_write(
            os.path.join(secrets_dir, "gmail_readside_main_token.json"),
            publishable_credential_bytes(secrets_dir, reserved_generation, main_token))
        denial_token_path = os.path.join(secrets_dir, "gmail_readside_denial_token.json")
        if denial_access is not None:
            atomic_write(denial_token_path, json.dumps(
                {"access_token": denial_access, "refresh_token": denial_refresh,
                 "expires_at": denial_exp}, indent=2) + "\n")
        elif os.path.exists(denial_token_path):
            # codex r17 P2: a --main-only mint leaves an EARLIER full mint's denial token
            # beside a bundle that attests no denial slot — the runbook's export step would
            # then feed preflight a mixed generation and hard-refuse the run. Remove the
            # stale artifact so the secrets dir always holds ONE coherent generation.
            os.remove(denial_token_path)
            print("[mint] removed the stale denial token from a prior full mint (--main-only "
                  "attests no denial slot; a leftover file would preflight-refuse as a mixed "
                  "generation)")
        # NAMED RESIDUAL (r11 audit A29/D4, accepted): the drill's `AttestationBundle` and
        # the app's `GrantWire` carry no `deny_unknown_fields`, so an unknown member inside
        # either is ignored rather than refused (the ratchet's `RatchetFile` does refuse one).
        # It cannot change WHICH generation is admitted, a repeated member is refused by the
        # serde derive, and this mint is the ONLY writer of both files — while adding the
        # attribute would break forward-compat with a later mint that adds a member.
        atomic_write(os.path.join(secrets_dir, "gmail_readside_attestation.json"),
                     json.dumps(bundle, indent=2) + "\n")
        # B5 (r11 audit): every `atomic_write` above already forces this directory on POSIX,
        # but the `--main-only` `os.remove` a few lines up does not — an unlink is a
        # directory-entry change exactly like a rename, and a power loss could resurrect the
        # stale denial token beside a bundle that attests no denial slot. ONE directory fsync
        # at the end of the write block covers it. POSIX-only, for the reason
        # `fsync_directory` states at its own site.
        fsync_directory(secrets_dir)
    print(f"[mint] wrote token file(s) + attestation bundle into {secrets_dir}")
    print(f"[mint] grant generation {grant_generation} (reserved in the high-water BEFORE "
          "the credential was written; an older credential file restored over this one is "
          "REFUSED as retired). Both writes are durable on Linux (the bytes are synced "
          "before each rename and the directory after it); on macOS the bytes are forced "
          "(F_FULLFSYNC) but the directory entry gets only a plain fsync, so a power loss "
          "in the rename window can lose the publish — a NAMED residual; on Windows they "
          "are process-crash-safe only — CPython's os.replace passes no "
          "MOVEFILE_WRITE_THROUGH, so a power loss inside the rename window is a NAMED "
          "residual, not a closed hole.")
    print(f"[mint] helper_source_sha384={helper_sha}")
    print("[mint] export PHOTON_GMAIL_ACCESS_TOKEN / PHOTON_GMAIL_403_TOKEN from the "
          "token files' access_token members; PHOTON_GMAIL_ATTESTATION points at the bundle.")
    # #75 S0 F13: the drill's contract is ENV-ONLY — it never opens this dir — so the ratchet's
    # current generation has to be exported the same way the access token is. Without it the
    # drill's preflight cannot bind the bundle to the grant, and an older token restored beside
    # ITS OWN bundle still agrees on sha384. A generation is a counter, never an identity: this
    # line prints a small integer, never a token byte.
    print(f"[mint] export PHOTON_GMAIL_GRANT_HIGH_WATER={grant_generation} (the drill's "
          "preflight refuses a bundle whose grant_generation is not this number)")
    return 0


# ---------------------------------------------------------------------------------------
# --self-test: the W6 semantic-witness matrix (design §7), pure logic only, no network
# ---------------------------------------------------------------------------------------

def self_test():
    failures = []
    # #91: publishing a credential now requires a `ReservedGeneration`, and the ONLY way to
    # get one is `reserve_grant_generation`. The witnesses below therefore publish through
    # exactly the door `run_mint` does — they take REAL reservations over throwaway
    # ratchets. `reserved_for(n)` seeds the ratchet at n-1 and reserves, so a witness can
    # name the generation it wants without a second constructor existing anywhere.
    reservation_dirs = []

    def reserved_for(generation):
        d = tempfile.mkdtemp()
        reservation_dirs.append(d)
        if generation > 1:
            raise_grant_high_water(d, generation - 1)
        return d, reserve_grant_generation(d)

    def check(name, condition):
        (print(f"  ok   {name}") if condition else failures.append(name))
        if not condition:
            print(f"  FAIL {name}")

    # W6.1 scope precedence: a non-empty response scope WINS over the requested set.
    scopes, source = effective_scopes(["a", "b"], "b c")
    check("response-scope wins over requested", scopes == ["b", "c"])
    check("response-scope provenance recorded", source == SOURCE_TOKEN_RESPONSE)

    # W6.2 RFC 6749 §5.1 omission: exact requested set + fallback provenance — for an ABSENT
    # member ONLY. A present-but-empty/whitespace `scope` is MALFORMED (§3.3 ABNF:
    # scope-token = 1*NQCHAR — the empty string is not a valid scope value) and REFUSES
    # (codex r12 P2-1): substituting the requested set for a malformed value could attest a
    # narrow set while a broader grant's refresh token persists. (This supersedes the earlier
    # empty-equals-omitted reading, which W6.2 previously blessed.)
    scopes, source = effective_scopes(["b", "a", "a"], _ABSENT)
    check("omission fallback set (absent member)", scopes == ["a", "b"])
    check("omission fallback provenance (absent member)", source == SOURCE_RFC6749_FALLBACK)
    for malformed in ("", "   "):
        try:
            effective_scopes(["a"], malformed)
            check(f"present-but-empty response scope refuses ({malformed!r})", False)
        except MintError as e:
            check(f"present-but-empty response scope refuses ({malformed!r})",
                  "scope" in str(e))
        try:
            refresh_effective_scopes(["a"], SOURCE_TOKEN_RESPONSE, malformed)
            check(f"present-but-empty refresh scope refuses ({malformed!r})", False)
        except MintError:
            check(f"present-but-empty refresh scope refuses ({malformed!r})", True)

    # W6.7 redirect refusal (codex r1 P1-1): a 30x on an authorized request must raise —
    # never return a follow-up Request aimed at the provider-chosen Location — and the one
    # opener every authorized request uses must carry the refusing handler.
    redirect_probe = urllib.request.Request(
        "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    try:
        _RefuseRedirects().redirect_request(
            redirect_probe, None, 302, "Found", {}, "https://attacker.example/")
        check("authorized-endpoint redirect refused", False)
    except MintError:
        check("authorized-endpoint redirect refused", True)
    check("opener carries the refusing handler",
          any(isinstance(h, _RefuseRedirects) for h in _OPENER.handlers))

    # W6.8 refresh fallback = the INITIAL EFFECTIVE GRANT (codex r1 P1-2): when the code
    # exchange NARROWED the grant and the refresh response omits `scope`, the fallback set is
    # what the exchange actually granted — never the original authorization request — and the
    # provenance travels with the value it describes.
    init_scopes, init_source = effective_scopes(["a", "b"], "a")  # narrowed grant
    scopes, source = refresh_effective_scopes(init_scopes, init_source, _ABSENT)
    check("narrowed-grant refresh fallback set", scopes == ["a"])
    check("narrowed-grant refresh fallback provenance", source == SOURCE_TOKEN_RESPONSE)
    scopes, source = refresh_effective_scopes(init_scopes, init_source, "b")
    check("refresh response scope still wins", scopes == ["b"])
    check("refresh response provenance", source == SOURCE_TOKEN_RESPONSE)
    ident_scopes, ident_source = effective_scopes(["a", "b"], _ABSENT)  # identical grant chain
    scopes, source = refresh_effective_scopes(ident_scopes, ident_source, _ABSENT)
    check("identical-grant chain fallback set", scopes == ["a", "b"])
    check("identical-grant chain fallback provenance", source == SOURCE_RFC6749_FALLBACK)

    # W6.9 consent loop terminal states (codex r2 P2-4): an error= callback is terminal, the
    # overall deadline is terminal, a healthy empty poll keeps waiting, a code wins.
    check("consent code wins", consent_outcome("authcode-x", None, False) == "authcode-x")
    try:
        consent_outcome(None, "access_denied", False)
        check("consent error callback is terminal", False)
    except MintError as e:
        check("consent error callback is terminal", "access_denied" in str(e))
    try:
        consent_outcome(None, None, True)
        check("consent deadline is terminal", False)
    except MintError:
        check("consent deadline is terminal", True)
    check("consent keeps waiting only while healthy",
          consent_outcome(None, None, False) is None)
    # A hostile/garbled error value is never echoed into the failure message.
    try:
        consent_outcome(None, "ya29.SECRET style_Weird//Value", False)
        check("consent error value sanitized", False)
    except MintError as e:
        check("consent error value sanitized", "ya29.SECRET" not in str(e))

    # W6.11 no ambient proxy (codex r3 P1-1): with HTTPS_PROXY set, the authorized opener
    # must carry NO environment-derived proxy route — mirror of the Rust clients' .no_proxy().
    saved_proxy = os.environ.get("HTTPS_PROXY")
    os.environ["HTTPS_PROXY"] = "http://ambient-proxy.example:8080"
    try:
        opener = build_authorized_opener()
        leaky = [h for h in opener.handlers
                 if isinstance(h, urllib.request.ProxyHandler) and h.proxies]
        check("authorized opener ignores ambient proxies", not leaky)
    finally:
        if saved_proxy is None:
            os.environ.pop("HTTPS_PROXY", None)
        else:
            os.environ["HTTPS_PROXY"] = saved_proxy

    # W6.12 secrets containment (codex r3 P1-2): a relative --secrets-dir refuses; a dir
    # inside ANY repository checkout (injected .git probe — pure) refuses; an outside dir
    # passes. Tokens must never be writable into a committable tree.
    try:
        validate_secrets_dir(os.path.join("relative", "secrets"))
        check("relative secrets dir refused", False)
    except MintError:
        check("relative secrets dir refused", True)
    fake_git = os.path.abspath(os.path.join(os.sep, "repo", ".git"))
    check("repo-contained secrets dir detected",
          inside_a_repo_checkout(
              os.path.join(os.sep, "repo", "sub", "secrets"),
              path_exists=lambda p, g=fake_git: os.path.abspath(p) == g) is True)
    check("outside-repo secrets dir accepted",
          inside_a_repo_checkout(
              os.path.join(os.sep, "elsewhere", "secrets"),
              path_exists=lambda p: False) is False)
    try:
        validate_secrets_dir(
            os.path.join(os.sep, "repo", "sub", "secrets"),
            path_exists=lambda p, g=fake_git: os.path.abspath(p) == g)
        check("repo-contained secrets dir refused", False)
    except MintError:
        check("repo-contained secrets dir refused", True)

    # W6.14 containment on the RESOLVED path (codex r4 FOLD 2 — 2nd appearance of the
    # containment class, now Python-side; same wholesale close already ratified for the Rust
    # evidence dir): a symlink/junction whose own name sits outside a checkout but which
    # RESOLVES inside one must refuse, and the resolved path is what the helper writes to.
    outside_name = os.path.join(os.sep, "elsewhere", "link-to-secrets")
    resolved_inside = os.path.join(os.sep, "repo", "sub", "secrets")
    symlinky = lambda p, t=resolved_inside, s=outside_name: t if os.path.abspath(p) == os.path.abspath(s) else os.path.abspath(p)  # noqa: E731
    git_probe = lambda p, g=fake_git: os.path.abspath(p) == g  # noqa: E731
    try:
        validate_secrets_dir(outside_name, path_exists=git_probe, resolve=symlinky)
        check("symlink resolving into a checkout refused", False)
    except MintError:
        check("symlink resolving into a checkout refused", True)
    check("validated secrets dir is the RESOLVED path",
          validate_secrets_dir(
              outside_name,
              path_exists=lambda p: False,
              resolve=symlinky) == resolved_inside)

    # W6.13 web clients refused (codex r3 P2-1): the loopback-PKCE flow cannot satisfy a web
    # client's fixed registered redirect URIs — refuse BEFORE consent, with a reason.
    check("installed client accepted",
          client_from_config({"installed": {"client_id": "i", "client_secret": "s"}})
          == ("i", "s"))
    try:
        client_from_config({"web": {"client_id": "w", "client_secret": "s"}})
        check("web client refused", False)
    except MintError as e:
        check("web client refused", "installed" in str(e).lower() or "web" in str(e).lower())
    try:
        client_from_config({})
        check("empty client config refused", False)
    except MintError:
        check("empty client config refused", True)

    # W6.15 the lane's credential contract, enforced AT THE CREDENTIAL (codex r6): authority
    # minimization must bite where the token is CREATED, not only at drill time — a refused
    # mint never puts a mutation-capable credential on disk in the first place.
    MODIFY = MODIFY_SCOPE  # #75 S0: the module constant, so this block cannot drift from it
    LABELS = "https://www.googleapis.com/auth/gmail.labels"

    # (a) The legitimate DEFAULTS still pass — at request time and at granted time, both
    # slots.
    # ⚖ RECUT at #75 S0: the main default is `gmail.modify`, not `gmail.readonly`. The
    # earlier reading of this witness ("the owner's already-minted tokens used exactly these;
    # this fold must not invalidate them") no longer holds and is NOT quietly preserved: S0
    # deliberately RETIRES the #21-era read-only credential — the owner re-mints once, under
    # the attended ceremony, and every command refuses with the re-mint cure until he does
    # (build record §0 Item 3, residual R-S0-5). M1 above pins the refusal of the old set.
    for stage in ("requested", "granted"):
        for slot, scopes in (("main", [MODIFY_SCOPE]),
                             ("denial", ["openid", "email"])):
            try:
                enforce_lane_scope_contract(slot, scopes, stage)
                check(f"default {slot} scopes accepted ({stage})", True)
            except MintError as e:
                check(f"default {slot} scopes accepted ({stage})", False)
                print(f"       unexpected refusal: {e}")

    # (a2) …and the ACTUAL argparse defaults, read off the parser itself, pass both stages.
    # This is the regression guard on the SHIPPED defaults: if a future edit changed a
    # default to something the contract refuses, every attended mint would fail at the door
    # (post-#75-S0 reading — the guard is over the defaults themselves, no longer over a
    # promise to keep the owner's #21-era credential valid; S0 retires it by design).
    defaults = {a.dest: a.default for a in build_arg_parser()._actions}  # noqa: SLF001
    for stage in ("requested", "granted"):
        try:
            enforce_lane_scope_contract("main", defaults["scope"].split(), stage)
            enforce_lane_scope_contract("denial", defaults["denial_scope"].split(), stage)
            check(f"argparse defaults satisfy the lane contract ({stage})", True)
        except MintError as e:
            check(f"argparse defaults satisfy the lane contract ({stage})", False)
            print(f"       unexpected refusal: {e}")

    # (b) ⚖ RECUT at #75 S0 (this witness's polarity INVERTS with the lane's authority):
    # gmail.modify IS the contracted main set now, so the pre-consent refusal this line
    # pins is the OTHER side — a `--scope gmail.readonly` (the #21 set) is refused before
    # consent, because a read-only credential cannot serve a triage verb and would mint a
    # file the app door refuses. The old assertion is not deleted, it moved: M1 carries it.
    try:
        enforce_lane_scope_contract("main", [READONLY_SCOPE], "requested")
        check("gmail.readonly as --scope refused pre-consent", False)
    except MintError as e:
        check("gmail.readonly as --scope refused pre-consent",
              "modify" in str(e) and "readonly" in str(e))

    # (c) gmail.labels as --denial-scope refused PRE-CONSENT (mutation-bearing: POST label
    # create/edit).
    try:
        enforce_lane_scope_contract("denial", ["openid", LABELS], "requested")
        check("gmail.labels as --denial-scope refused pre-consent", False)
    except MintError as e:
        check("gmail.labels as --denial-scope refused pre-consent", "labels" in str(e))

    # (d) A GRANTED set that comes back broader than requested is refused PRE-WRITE — the
    # authorization server, not the operator, is the source of this violation.
    try:
        enforce_lane_scope_contract("main", [READONLY_SCOPE, MODIFY], "granted")
        check("broader granted main set refused pre-write", False)
    except MintError as e:
        check("broader granted main set refused pre-write", "granted" in str(e))
    try:
        enforce_lane_scope_contract("denial", ["openid", READONLY_SCOPE], "granted")
        check("granted denial set carrying a Gmail scope refused pre-write", False)
    except MintError:
        check("granted denial set carrying a Gmail scope refused pre-write", True)

    # (e) The full-mailbox scope is caught too, and an EMPTY main set is not "exactly
    # {readonly}".
    try:
        enforce_lane_scope_contract("denial", ["https://mail.google.com/"], "requested")
        check("mail.google.com refused for the denial slot", False)
    except MintError:
        check("mail.google.com refused for the denial slot", True)
    try:
        enforce_lane_scope_contract("main", [], "requested")
        check("empty main scope set refused", False)
    except MintError:
        check("empty main scope set refused", True)

    # W6.20 the lane contract bites on the INITIAL grant too (codex r11 P2-2): the refresh
    # token inherits the AUTHORIZATION's grant, so a broad code-exchange grant must refuse at
    # the granted-initial stage regardless of what a later refresh response reports. (The
    # composition — enforcement placed BEFORE the refresh exchange in consent_and_exchange —
    # is part of the reviewed network path; these witnesses pin the check itself at the stage.)
    try:
        enforce_lane_scope_contract(
            "main", [READONLY_SCOPE, MODIFY], "granted-initial (code exchange)")
        check("broad initial main grant refused pre-refresh", False)
    except MintError as e:
        check("broad initial main grant refused pre-refresh", "granted-initial" in str(e))
    try:
        enforce_lane_scope_contract(
            "denial", ["openid", "email", READONLY_SCOPE], "granted-initial (code exchange)")
        check("Gmail scope in initial denial grant refused pre-refresh", False)
    except MintError as e:
        check("Gmail scope in initial denial grant refused pre-refresh",
              "granted-initial" in str(e))

    # W6.19 attested expiry is NEVER invented (codex r10 P2-3): preflight expiry refusal and
    # the manifest's bank-a-digest-only-when-expired rule both trust `expires_at_*`, so a
    # response omitting `expires_in` must REFUSE — a fabricated 3600s default could call an
    # expired token live, or bank a digest while the token still lives.
    check("attested expiry = now + expires_in", attested_expiry(1000, 3599) == 4599)
    # ⚖ RECUT at council r2 (S3-F3): the old pin blessed exactly the coercion the seat
    # executed — a string spelling is NOT an integer, and both doors now refuse it alike.
    for bad in (None, 0, -5, "", "soon", "3599"):
        try:
            attested_expiry(1000, bad)
            check(f"missing/invalid expires_in refuses ({bad!r})", False)
        except MintError as e:
            check(f"missing/invalid expires_in refuses ({bad!r})", "expires_in" in str(e))

    # W6.16 refresh-token ROTATION (codex r8 FOLD 3): RFC 6749 §6 lets the refresh response
    # carry a REPLACEMENT refresh_token and invalidate the old one. Persist the replacement
    # when present; fall back to the original when absent.
    check("rotated refresh token is persisted",
          surviving_refresh_token("initial-rt", "rotated-rt") == "rotated-rt")
    # PR #81 bot r2: ABSENT is spelled `_ABSENT` at the doors now — `None` means an explicit
    # JSON `null`, which is a present malformed value and refuses (W51 covers it below).
    check("absent rotation keeps the original",
          surviving_refresh_token("initial-rt", _ABSENT) == "initial-rt")
    check("empty rotation value keeps the original",
          surviving_refresh_token("initial-rt", "") == "initial-rt")
    check("whitespace rotation value keeps the original",
          surviving_refresh_token("initial-rt", "   ") == "initial-rt")

    # W51-py two-door parity on the ROTATION value (PR #81 bot r1 P2): the app door refuses a
    # present-but-non-string `refresh_token` (token_refresh.rs RefreshTokenNotAString); the
    # mint door must match — a falsy non-string (JSON 0/false) must not read as "no rotation"
    # and silently persist the original, and a truthy one must not crash on .strip(). Absent
    # and blank-string values stay "keep the original" (not a rotation), same as the app door.
    for bad_rotation in (None, 0, False, 5, {"t": 1}, ["x"]):
        try:
            surviving_refresh_token("initial-rt", bad_rotation)
            check(f"W51-py non-string rotation refuses ({type(bad_rotation).__name__})", False)
        except MintError as e:
            check(f"W51-py non-string rotation refuses ({type(bad_rotation).__name__})",
                  "refresh_token" in str(e))

    # W52-py the same set, same shape, on `scope` (the two-door-parity family's last
    # uncovered response field): a present non-string `scope` must refuse loudly as
    # malformed, never crash strict parsing (`.strip()`/`.split()` AttributeError) nor be
    # coerced. Both derivation doors route through _refuse_malformed_scope.
    for bad_scope in (None, 0, {"s": 1}):
        for door_label, door in (
            ("effective_scopes", lambda v: effective_scopes([READONLY_SCOPE], v)),
            ("refresh_effective_scopes",
             lambda v: refresh_effective_scopes([READONLY_SCOPE], SOURCE_TOKEN_RESPONSE, v)),
        ):
            try:
                door(bad_scope)
                check(f"W52-py non-string scope refuses ({door_label}, "
                      f"{type(bad_scope).__name__})", False)
            except MintError as e:
                check(f"W52-py non-string scope refuses ({door_label}, "
                      f"{type(bad_scope).__name__})", "scope" in str(e))

    # W6.17 email-claim requirement on the denial slot (PR #50 bot r2 P2): the denial flow's
    # identity comparison is email↔email (Gmail getProfile emailAddress vs OIDC userinfo
    # email), so the REQUESTED denial scope set must carry an email-bearing scope — either
    # OIDC Core §5.4's `email` or Google's long form — and a set without one refuses BEFORE
    # consent. `openid` alone yields only the opaque `sub`, which is not comparable to an
    # email address.
    for ok_scopes in (["openid", "email"],
                      ["openid", "https://www.googleapis.com/auth/userinfo.email"]):
        try:
            require_email_claim_scopes(ok_scopes)
            check(f"email-bearing denial scopes accepted ({ok_scopes[1]})", True)
        except MintError:
            check(f"email-bearing denial scopes accepted ({ok_scopes[1]})", False)
    for bad_scopes in (["openid"], []):
        try:
            require_email_claim_scopes(bad_scopes)
            check(f"denial scopes without an email claim refused ({bad_scopes!r})", False)
        except MintError as e:
            check(f"denial scopes without an email claim refused ({bad_scopes!r})",
                  "email" in str(e))

    # W6.18 identity derivation refuses the sub fallback (the bot's exact class): a userinfo
    # response with no email claim must REFUSE — never silently fall back to the opaque OIDC
    # `sub`, which records same_principal=false against a Gmail emailAddress and bricks R3
    # while the mint reports success. And no identity value ever rides the error.
    check("userinfo email claim is the denial identity",
          denial_identity_from_userinfo({"email": "drill@example.test", "sub": "10769150"})
          == "drill@example.test")
    for no_email in ({"sub": "10769150-SENTINEL"}, {"email": "", "sub": "10769150-SENTINEL"}):
        try:
            denial_identity_from_userinfo(no_email)
            check(f"userinfo without an email claim refuses ({sorted(no_email)!r})", False)
        except MintError as e:
            check(f"userinfo without an email claim refuses ({sorted(no_email)!r})",
                  "email" in str(e) and "SENTINEL" not in str(e))

    # W6.3 same_principal from two minted-identity fixtures — true / false / empty-refuses.
    check("same principal true", same_principal("drill@example.test", "drill@example.test") is True)
    check("same principal false", same_principal("drill@example.test", "other@example.test") is False)
    try:
        same_principal("drill@example.test", "")
        check("empty identity refuses", False)
    except MintError:
        check("empty identity refuses", True)

    # W6.4 hash-what-you-emit association: the bundle digest IS the digest of the emitted
    # token string, for both slots — SHA-384 (issue #51: the owner-ruled posture is strict
    # SHA-384 everywhere we control the format, and every format in this lane is ours).
    bundle = build_bundle("tok-main", ["s"], SOURCE_TOKEN_RESPONSE, 1, 2, "deadbeef",
                          denial_token="tok-denial", denial_scopes=["openid"],
                          denial_source=SOURCE_TOKEN_RESPONSE, principal_match=True,
                          expires_at_denial=3)
    check("main token digest association (sha384)",
          bundle.get("main_token_sha384") == hashlib.sha384(b"tok-main").hexdigest())
    check("denial token digest association (sha384)",
          bundle.get("denial_token_sha384") == hashlib.sha384(b"tok-denial").hexdigest())
    check("helper source digest field is sha384-named",
          bundle.get("helper_source_sha384") == "deadbeef" and "helper_source_sha256" not in bundle)
    # W6.10 per-token expiries (codex r2 P2-1): the bundle records expires_at_main and
    # expires_at_denial — never one merged expires_at that hides a live denial token behind an
    # expired main (or vice versa) in the manifest's bank-on-expiry rule.
    check("per-token expiry: expires_at_main member present", "expires_at_main" in bundle)
    check("per-token expiry: no merged expires_at member", "expires_at" not in bundle)
    check("per-token expiry: denial slot carries its own", bundle.get("expires_at_denial") == 3)
    main_only = build_bundle("tok-main", ["s"], SOURCE_TOKEN_RESPONSE, 1, 2, "deadbeef")
    check("main-only mint leaves denial fields null",
          main_only.get("denial_token_sha384") is None
          and main_only["effective_denial_scopes"] is None
          and main_only["scope_source_denial"] is None
          and main_only["same_principal"] is None
          and main_only["expires_at_denial"] is None)

    # W6.5 atomic emission: content lands whole and no temp file survives.
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "bundle.json")
        atomic_write(target, "{\"k\":1}\n")
        with open(target, "r", encoding="utf-8") as f:
            check("atomic write content", f.read() == "{\"k\":1}\n")
        check("atomic write leaves no temp file", os.listdir(d) == ["bundle.json"])

    # W37 mint script solo path (design §3-S6): an empty temp dir with no lock file and no
    # contention — the lock acquires, writes proceed, and the lock file exists afterwards and
    # is NOT deleted (it is an ADDRESS, never removed). This is the drill lane's normal case.
    with tempfile.TemporaryDirectory() as d:
        lock_path = os.path.join(d, "credential.lock")
        check("W37 lock file absent before first acquisition", not os.path.exists(lock_path))
        wrote = []
        with credential_writer_lock(d, deadline_s=5.0):
            wrote.append(1)
        check("W37 solo acquisition lets the write set proceed", wrote == [1])
        check("W37 lock file exists after release (an ADDRESS, never deleted)",
              os.path.exists(lock_path))

    # W28-py bounded wait (design §3-S6): a second, FRESH handle holding the same lock
    # conflicts with acquisition (flock is per open-file-description on Unix; msvcrt.locking
    # conflicts across handles on Windows) — the context manager gives up at its deadline with
    # a LOUD typed refusal, never a hang, and performs NO write. Release + re-acquire succeeds.
    with tempfile.TemporaryDirectory() as d:
        lock_path = os.path.join(d, "credential.lock")
        held_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _acquire_lock_nonblocking(held_fd)
            start = time.monotonic()
            wrote = []
            try:
                with credential_writer_lock(d, deadline_s=0.5):
                    wrote.append(1)
                check("W28-py contended lock raises MintError", False)
            except MintError as e:
                elapsed = time.monotonic() - start
                check("W28-py contended lock raises within ~1s", elapsed < 1.5)
                check("W28-py contended lock error names the lock path", lock_path in str(e))
                check("W28-py contended lock performs no write", wrote == [])
        finally:
            _release_lock(held_fd)
            os.close(held_fd)
        wrote2 = []
        with credential_writer_lock(d, deadline_s=5.0):
            wrote2.append(1)
        check("W28-py release then re-acquire succeeds", wrote2 == [1])

    # W6.6 no secret in any error path: the HTTP-failure constructor cannot embed a body,
    # and the empty-identity refusal carries no identity value.
    sentinel = "SENTINEL-ya29.SECRET-TOKEN-BYTES"
    err = http_error_for("token endpoint (code exchange)", 400)
    check("http error carries no body", sentinel not in str(err) and "400" in str(err))
    try:
        same_principal(sentinel + "@example.test", "")
    except MintError as e:
        check("identity error carries no identity", sentinel not in str(e))

    # W46-py the unified door contract, mint side (design §2 amendment 2026-08-26, code-council
    # r1 S2-F1 EXECUTED): the token-response door is BOUNDED — a body over 64 KiB refuses
    # loudly BEFORE parsing (the Rust door refuses the same shape as BodyTooLarge; S2's
    # differential probe showed this path accepting 65.6 KiB pre-fix).
    class _FakeResp:
        def __init__(self, body):
            self._body = body

        def read(self, n=-1):
            return self._body if n is None or n < 0 else self._body[:n]

    over = b'{"pad":"' + b"a" * TOKEN_RESPONSE_MAX_BYTES + b'"}'
    try:
        read_bounded_json(_FakeResp(over), "test endpoint")
        check("W46-py over-cap token response refuses before parse", False)
    except MintError as e:
        check("W46-py over-cap token response refuses before parse",
              "KiB" in str(e) and "test endpoint" in str(e))
    check("W46-py in-cap token response parses",
          read_bounded_json(_FakeResp(b'{"ok": true}'), "test endpoint") == {"ok": True})

    # F20-py (council r5, EXECUTED at this door by seat 3): a body that REPEATS a member name is
    # refused before any member is read — as ambiguous (RFC 8259 §4; RFC 6749 §3.2 for the
    # parameters it defines, per erratum 5708). Pre-fix `json.loads` kept the LAST
    # `scope`, so the wire order of two members decided which authority the mint believed the
    # token carried. Parity with the Rust door's BodyRepeatsMember; both orders RED pre-fix.
    modify = "https://www.googleapis.com/auth/gmail.modify"
    for dup in (
        ('{"scope":"https://mail.google.com/","scope":"%s"}' % modify).encode(),
        ('{"scope":"%s","scope":"https://mail.google.com/"}' % modify).encode(),
        b'{"access_token":"a","access_token":"b"}',
        b'{"error":"invalid_grant","error":"rate_limit_exceeded"}',
    ):
        try:
            read_bounded_json(_FakeResp(dup), "test endpoint")
            check("F20-py repeated member name refuses before any member is read", False)
        except MintError as e:
            check("F20-py repeated member name refuses before any member is read",
                  "repeats" in str(e) and "test endpoint" in str(e)
                  and "mail.google.com" not in str(e))
    check("F20-py unknown members occurring once are tolerated",
          read_bounded_json(_FakeResp(b'{"ok": true, "id_token": "x"}'), "test endpoint")
          == {"ok": True, "id_token": "x"})

    # F21-py-a (council r6 — seat 3 run 2 F1, EXECUTED at a real HTTP server; seat 2's omission
    # lane found the same site): the consent callback picked the FIRST repeated `code`/`error`
    # (parse_qs preserves every value; the `[0]` chose) and let `code` win over a co-present
    # `error`. RFC 6749 §3.1 forbids a repeated parameter the RFC defines, and Google documents
    # `code`/`error` as alternatives — an ambiguous callback is REFUSED, never guessed through.
    import urllib.parse as _up
    for qs, why in (
        ("code=REAL&code=FAKE", "a repeated code"),
        ("code=FAKE&code=REAL", "a repeated code (reversed)"),
        ("c%6fde=REAL&code=FAKE", "a percent-escaped duplicate code"),
        ("error=access_denied&error=server_error", "a repeated error"),
        ("code=GOOD&error=access_denied", "code and error together"),
    ):
        got = callback_outcome_from_raw_query(qs)
        check("F21-py-a ambiguous callback (%s) refuses instead of guessing" % why,
              got == (None, AMBIGUOUS_CALLBACK))
    check("F21-py-a a clean single code still lands",
          callback_outcome_from_raw_query("code=ONLY") == ("ONLY", None))
    check("F21-py-a a clean single error still lands",
          callback_outcome_from_raw_query("error=access_denied")
          == (None, "access_denied"))

    # F22-py (codex-CLI r18 P2, driver-EXECUTED red on the pre-fix bytes: all three shapes
    # returned a clean code/error): the default `parse_qs` DROPS blank-valued members, so a
    # blank duplicate or a blank co-present member evaded the F21-a ambiguity check entirely.
    # The witnesses run the RAW-QUERY reader — the handler's exact parse config — so a parse
    # regression, not only a helper regression, goes RED here.
    for qs, why in (
        ("code=&code=REAL", "a blank duplicate code"),
        ("code=REAL&error=", "code with a blank co-present error"),
        ("error=&error=access_denied", "a blank duplicate error"),
    ):
        check("F22-py blank members still count for ambiguity (%s)" % why,
              callback_outcome_from_raw_query(qs) == (None, AMBIGUOUS_CALLBACK))
    check("F22-py a single blank code stays not-arrived (falsy), the pre-F22 behaviour",
          callback_outcome_from_raw_query("code=") == ("", None))

    # F24-c-py (council r7 — seats 2 and 3 both EXECUTED the false page over real HTTP;
    # driver-reproduced): the browser page mirrors the callback OUTCOME — success text ONLY
    # for a clean nonblank code; a refusal/denial page for error-bearing and ambiguous
    # callbacks; a still-waiting page for blank/absent. Three static literals, no callback
    # bytes ever formatted in.
    ok_page = callback_ack_text("REAL", None)
    check("F24-c-py a clean code gets the success page", b"Consent received" in ok_page)
    for c, e, why in (
        (None, "access_denied", "a denial"),
        (None, AMBIGUOUS_CALLBACK, "an ambiguous callback"),
    ):
        page = callback_ack_text(c, e)
        check("F24-c-py %s does NOT get the success page" % why,
              b"Consent received" not in page and b"NOT completed" in page)
        check("F24-c-py %s page carries no callback bytes" % why,
              b"access_denied" not in page)
    waiting = callback_ack_text("", None)
    check("F24-c-py a blank code gets the still-waiting page",
          b"Consent received" not in waiting and b"still waiting" in waiting)
    check("F24-c-py the absent shape matches the blank one (both keep waiting)",
          callback_ack_text(None, None) == waiting)
    try:
        consent_outcome(None, AMBIGUOUS_CALLBACK, False)
        check("F21-py-a the ambiguous token is terminal and names no actor", False)
    except MintError as e:
        check("F21-py-a the ambiguous token is terminal and names no actor",
              "ambiguous" in str(e) and "authorization server" not in str(e))

    # F21-py-c (council r6 — seat 1 A, EXECUTED): a top-level non-object slipped past the door
    # (`json.loads` happily returns a list/str) and the caller's `.get` then raised a raw
    # AttributeError — the Rust door refuses the same shape as BodyNotAnObject. Parity: refuse
    # it AT the door, with the door's own sentence.
    for nonobj in (b'["repeated member name"]', b'"a bare string"', b'42'):
        try:
            read_bounded_json(_FakeResp(nonobj), "test endpoint")
            check("F21-py-c a top-level non-object refuses at the door", False)
        except MintError as e:
            check("F21-py-c a top-level non-object refuses at the door",
                  "not a JSON object" in str(e) and "test endpoint" in str(e))

    # W47-py the clock law, mint side (design §2 clock-law amendment, code-council r1 S2-F2
    # EXECUTED — the slow-body loopback probe: a post-body-read anchor stretched a 10 s
    # declared lifetime to 11.06 s of apparent life): the refresh exchange's expiry is
    # anchored to the HEADERS-ARRIVAL sample post_form returns, never a post-read clock.
    src = inspect.getsource(consent_and_exchange)
    check("W47-py expiry anchored to the headers-arrival sample",
          "attested_expiry(refreshed_received_unix" in src)
    check("W47-py no post-read wall sample feeds attested_expiry",
          "attested_expiry(time.time()" not in src)
    check("W47-py post_form samples at headers-arrival (before the body read)",
          "received_unix = time.time()" in inspect.getsource(post_form))

    # W48-py the unified door contract's TOKEN-SHAPE half (design §2 amendment 8; council r2
    # S2-F1 EXECUTED ya29:BAD through this path to a durable rc=0 credential pre-fix): the
    # refresh response's token must be Bearer-typed (RFC 6749 §5.1), header-safe, and inside
    # the house Bearer-shape grammar — the same predicate set as the Rust door and the loader.
    for bad_tok in ["ya29:BAD", "ya29!x", "mid=eq-not-trailing", "café"]:
        try:
            require_token_shape(bad_tok, "Bearer", "test endpoint")
            check(f"W48-py non-conforming token refuses ({bad_tok!r})", False)
        except MintError as e:
            check(f"W48-py non-conforming token refuses ({bad_tok!r})", bad_tok not in str(e))
    try:
        require_token_shape("ya29.ok", None, "test endpoint")
        check("W48-py missing token_type refuses", False)
    except MintError:
        check("W48-py missing token_type refuses", True)
    require_token_shape("ya29.a0-_~+/ok==", "bearer", "test endpoint")
    check("W48-py conforming token with case-insensitive Bearer passes", True)
    check("W48-py the refresh exchange enforces the shape",
          "require_token_shape(" in inspect.getsource(consent_and_exchange))

    # W49-py STRICT scope grammar (council r2 S3-F3 EXECUTED: the pre-fix `.split()` silently
    # repaired doubled spaces, tabs, and newlines — a normalizing reader attests a grammar the
    # server never sent): single-SP separation, every member 1*NQCHAR, no normalization.
    for malformed in ["a  b", "a\tb", "a\nb", " a", "a "]:
        try:
            strict_scope_members(malformed)
            check(f"W49-py malformed scope separation refuses ({malformed!r})", False)
        except MintError:
            check(f"W49-py malformed scope separation refuses ({malformed!r})", True)
    try:
        strict_scope_members('a"b')
        check("W49-py non-NQCHAR scope byte refuses", False)
    except MintError:
        check("W49-py non-NQCHAR scope byte refuses", True)
    check("W49-py a conforming scope splits exactly",
          strict_scope_members("a b c") == ["a", "b", "c"])
    check("W49-py effective_scopes rides the strict splitter",
          "strict_scope_members" in inspect.getsource(effective_scopes)
          and "strict_scope_members" in inspect.getsource(refresh_effective_scopes))

    # W50-py STRICT expiry typing (council r2 S3-F3 EXECUTED: the pre-fix `int()` truncated
    # 3600.5, believed JSON `true` as one second, and admitted 2**200 past i64): the lifetime
    # is an INTEGER (bool is not one), positive, and the attested expiry fits i64 — the same
    # law as the Rust door's checked arithmetic.
    for bad_exp in (3600.5, True, "3600"):
        try:
            attested_expiry(1_700_000_000, bad_exp)
            check(f"W50-py non-integer expires_in refuses ({bad_exp!r})", False)
        except MintError:
            check(f"W50-py non-integer expires_in refuses ({bad_exp!r})", True)
    try:
        attested_expiry(1_700_000_000, 2**200)
        check("W50-py past-i64 lifetime refuses", False)
    except MintError as e:
        check("W50-py past-i64 lifetime refuses", "representable" in str(e))
    check("W50-py an integer lifetime still attests",
          attested_expiry(1_700_000_000, 3599) == 1_700_003_599)

    # -----------------------------------------------------------------------------------
    # #75 S0 (BUILD RECORD contract C6) — the lane's main slot moves from read-only to the
    # product's write authority. M1-M4 are this slice's witnesses.
    # -----------------------------------------------------------------------------------

    # M1 the MAIN contract is EXACTLY {gmail.modify}: the product's triage verbs (trash,
    # spam, archive, label) are gmail.modify calls, so a readonly-only credential can no
    # longer satisfy the lane — and a credential carrying readonly IN ADDITION is surplus
    # authority, refused by the same unordered-exact-set law that already governed this slot.
    for stage in ("requested", "granted", "granted-initial (code exchange)"):
        try:
            enforce_lane_scope_contract("main", [MODIFY_SCOPE], stage)
            check(f"M1 main contract accepts exactly {{gmail.modify}} ({stage})", True)
        except MintError as e:
            check(f"M1 main contract accepts exactly {{gmail.modify}} ({stage})", False)
            print(f"       unexpected refusal: {e}")
    try:
        enforce_lane_scope_contract("main", [READONLY_SCOPE], "requested")
        check("M1 readonly-only main set refused (no write authority)", False)
    except MintError as e:
        check("M1 readonly-only main set refused (no write authority)",
              "readonly" in str(e) and "modify" in str(e))
    try:
        enforce_lane_scope_contract("main", [MODIFY_SCOPE, READONLY_SCOPE], "granted")
        check("M1 modify+readonly main set refused (surplus authority)", False)
    except MintError as e:
        check("M1 modify+readonly main set refused (surplus authority)",
              "readonly" in str(e) and "granted" in str(e))

    # M2 the FULL-MAILBOX scope stays refused BY PREFIX for the main slot, explicitly and by
    # name. The exact-set test in M1 already excludes it arithmetically; this witness pins the
    # DEDICATED prefix refusal, because the reason a reader needs is not "not in the set" but
    # "this family is the only one that authorizes immediate permanent deletion, and this
    # product never asks for it" (Gmail API scope reference).
    for stage in ("requested", "granted"):
        for full in (FULL_MAILBOX_SCOPE_PREFIX, FULL_MAILBOX_SCOPE_PREFIX + "extra"):
            try:
                enforce_lane_scope_contract("main", [MODIFY_SCOPE, full], stage)
                check(f"M2 full-mailbox scope refused for main ({stage}, {full})", False)
            except MintError as e:
                check(f"M2 full-mailbox scope refused for main ({stage}, {full})",
                      FULL_MAILBOX_SCOPE_PREFIX in str(e)
                      and "permanent" in str(e).lower()
                      and "never requested" in str(e).lower())

    # M3 the GRANT HIGH-WATER is a MAX-ONLY ratchet that never reads low (design v7 §3;
    # shape adopted from crates/aruna/src/store_open.rs's `high_water = MAX(...)` and the
    # bridge's per-lineage anti-rollback rule — "raised MAX-ONLY, never a plain assignment
    # that can write it DOWN"). An ABSENT file is generation 0 (nothing minted yet); an
    # unreadable one REFUSES — reading a corrupt file as 0 would re-issue a generation the
    # app has already retired, which is precisely the rollback this file exists to catch.
    with tempfile.TemporaryDirectory() as d:
        hw_path = os.path.join(d, "grant_high_water.json")
        check("M3 absent high-water reads as generation 0",
              read_grant_high_water(d) == 0)
        check("M3 reading an absent high-water creates no file", not os.path.exists(hw_path))
        check("M3 first raise returns the new generation", raise_grant_high_water(d, 3) == 3)
        with open(hw_path, "r", encoding="utf-8") as f:
            raised_bytes = f.read()
        check("M3 raised high-water is on disk as {\"grant_generation\": 3}",
              json.loads(raised_bytes) == {"grant_generation": 3})
        check("M3 raise to a LOWER generation returns the standing high-water",
              raise_grant_high_water(d, 2) == 3)
        with open(hw_path, "r", encoding="utf-8") as f:
            check("M3 a lower raise did not rewrite the file (byte-identical)",
                  f.read() == raised_bytes)
        check("M3 the standing high-water still reads 3", read_grant_high_water(d) == 3)
        check("M3 an EQUAL raise is a no-op", raise_grant_high_water(d, 3) == 3)
        check("M3 raise to a HIGHER generation moves the ratchet",
              raise_grant_high_water(d, 4) == 4 and read_grant_high_water(d) == 4)
    for corrupt in ("", "   ", "not json", "[]", "3", "null",
                    '{"grant_generation": "4"}', '{"grant_generation": -1}',
                    '{"grant_generation": 1.5}', '{"grant_generation": true}',
                    '{"grant_generation": null}', '{"generation": 4}', "{}"):
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, "grant_high_water.json"), corrupt)
            try:
                got = read_grant_high_water(d)
                check(f"M3 corrupt high-water refuses ({corrupt!r})", False)
                print(f"       read it as: {got!r}")
            except MintError as e:
                check(f"M3 corrupt high-water refuses ({corrupt!r})",
                      "high-water" in str(e))
            # …and a corrupt file is never SILENTLY overwritten by the next raise either:
            # the raise reads first, so it refuses on the same bytes.
            try:
                raise_grant_high_water(d, 9)
                check(f"M3 raising over a corrupt high-water refuses ({corrupt!r})", False)
            except MintError:
                check(f"M3 raising over a corrupt high-water refuses ({corrupt!r})", True)

    # M4 the MAIN TOKEN DOCUMENT carries the grant object (credential file v2, design v7 §4).
    # The witness builds the document through the SAME function the writer calls, so the
    # attested shape and the emitted shape cannot drift (the W47-py discipline: pin the
    # wiring, not a copy of it).
    dir7, res7 = reserved_for(7)
    dir1, res1 = reserved_for(1)
    doc = main_token_document("ya29.a0-tok", "1//rt-value", 1_700_003_599, res7,
                              "drill@example.test", [MODIFY_SCOPE], dir7)
    check("M4 token document member set",
          sorted(doc) == ["access_token", "expires_at", "grant", "refresh_token"])
    check("M4 token document keeps the v1 members verbatim",
          doc["access_token"] == "ya29.a0-tok" and doc["refresh_token"] == "1//rt-value"
          and doc["expires_at"] == 1_700_003_599)
    check("M4 grant object member set",
          sorted(doc["grant"]) == ["effective_scopes", "grant_generation",
                                   "provider_principal"])
    check("M4 grant carries the generation, the principal and the granted set",
          doc["grant"]["grant_generation"] == 7
          and doc["grant"]["provider_principal"] == "drill@example.test"
          and doc["grant"]["effective_scopes"] == [MODIFY_SCOPE])
    check("M4 effective_scopes are SORTED (the comparison downstream is unordered-exact)",
          main_token_document("t", "r", 1, res1, "p@example.test",
                              ["b", "a"], dir1)["grant"]["effective_scopes"] == ["a", "b"])
    # The principal is provider-supplied DATA that becomes a URL path segment downstream
    # (build record §0 Item 5), so an absent/empty/non-string emailAddress refuses HERE, at
    # the mint, before a token file exists — and the refusal never echoes the value.
    ident_sentinel = "SENTINEL-principal@example.test"
    check("M4 getProfile emailAddress is the main principal",
          main_principal_from_profile({"emailAddress": ident_sentinel, "messagesTotal": 4})
          == ident_sentinel)
    for bad_profile in ({}, {"emailAddress": ""}, {"emailAddress": "   "},
                        {"emailAddress": None}, {"emailAddress": 7},
                        {"emailAddress": [ident_sentinel]}):
        try:
            main_principal_from_profile(bad_profile)
            check(f"M4 unusable getProfile emailAddress refuses ({bad_profile!r})", False)
        except MintError as e:
            check(f"M4 unusable getProfile emailAddress refuses ({bad_profile!r})",
                  "principal" in str(e).lower() and ident_sentinel not in str(e))
    for non_object in ([{"emailAddress": ident_sentinel}], "drill@example.test", None, 7):
        try:
            main_principal_from_profile(non_object)
            check(f"M4 non-object getProfile body refuses ({type(non_object).__name__})",
                  False)
        except MintError as e:
            check(f"M4 non-object getProfile body refuses ({type(non_object).__name__})",
                  "principal" in str(e).lower() and ident_sentinel not in str(e))
    for bad_principal in (None, "", "   ", 7, ["x"]):
        try:
            main_token_document("t", "r", 1, res1, bad_principal, [MODIFY_SCOPE], dir1)
            check(f"M4 token document refuses an unusable principal ({bad_principal!r})",
                  False)
        except MintError as e:
            check(f"M4 token document refuses an unusable principal ({bad_principal!r})",
                  "principal" in str(e).lower())
    # …and a BARE generation of any spelling is refused BY TYPE now (#91, M12): the
    # publisher takes a `ReservedGeneration` or nothing.
    for bad_generation in (0, -1, "1", True, 1.0, None):
        try:
            main_token_document("t", "r", 1, bad_generation, "p@example.test",
                                [MODIFY_SCOPE], dir1)
            check(f"M4 token document refuses generation {bad_generation!r}", False)
        except MintError as e:
            check(f"M4 token document refuses generation {bad_generation!r}",
                  "generation" in str(e))
    # The bundle gains the generation too (and STILL carries no identity — the amended #21
    # rule: only the token file holds the principal).
    gen_bundle = build_bundle("tok-main", [MODIFY_SCOPE], SOURCE_TOKEN_RESPONSE, 1, 2,
                              "deadbeef", grant_generation=5)
    check("M4 attestation bundle records the grant generation",
          gen_bundle.get("grant_generation") == 5)
    check("M4 attestation bundle still carries no principal member",
          not any("principal" in k for k in gen_bundle if k != "same_principal"))
    # …and the WIRING, pinned at the writer: run_mint mints generation = high-water + 1,
    # builds the file through main_token_document, hands the generation to the bundle, and
    # raises the high-water LAST — after the token file is on disk. A crash between the two
    # leaves a live credential ABOVE a stale high-water (the app latches up on the next
    # admission); the reverse order would retire a working credential on that same crash.
    mint_src = inspect.getsource(run_mint)
    check("M4 run_mint mints generation = high-water + 1",
          "read_grant_high_water(secrets_dir) + 1" in mint_src)
    check("M4 run_mint writes the token file through main_token_document",
          "main_token_document(" in mint_src)
    check("M4 run_mint hands the generation to the attestation bundle",
          "grant_generation=grant_generation" in mint_src)
    check("M4 run_mint no longer raises the high-water after publishing the credential",
          "raise_grant_high_water(" not in mint_src)
    lock_at = mint_src.index("with credential_writer_lock(")
    reserve_at = mint_src.find("reserve_grant_generation(secrets_dir)")
    check("M4 both the generation read and the RESERVATION sit inside the writer lock",
          mint_src.index("read_grant_high_water(secrets_dir) + 1") > lock_at
          and reserve_at > lock_at)

    # M5 THE SEAT-3 CRASH SEQUENCE, run against the same writer functions `run_mint` calls
    # (code council r1, seat 3, claim 6 — EXECUTED against the credential-first ordering:
    # "two distinct consent operations received generation 1; restoring the first credential
    # then passed the equality check against high-water 1"). RESERVE-FIRST closes it: the
    # generation is claimed in the ratchet BEFORE any credential carries it, so a crash in
    # the gap spends a generation number rather than duplicating one.
    with tempfile.TemporaryDirectory() as d:
        token_path = os.path.join(d, "gmail_readside_main_token.json")
        # Consent A reserves its generation…
        gen_a = reserve_grant_generation(d)
        check("M5 the first consent reserves generation 1", gen_a.generation == 1)
        check("M5 the reservation is DURABLE before any credential carries it",
              read_grant_high_water(d) == 1 and not os.path.exists(token_path))
        # …then the process dies here, before the credential is published. ---- crash ----
        # A DISTINCT consent B now re-runs the mint's allocation.
        gen_b = reserve_grant_generation(d)
        check("M5 a distinct consent after the crash never re-issues the generation",
              gen_b.generation == 2 and gen_b.generation != gen_a.generation)
        credential_b = main_token_document("ya29.B", "1//B", 1_700_003_599, gen_b,
                                           "b@example.test", [MODIFY_SCOPE], d)
        atomic_write(token_path, json.dumps(credential_b, indent=2) + "\n")
        standing = read_grant_high_water(d)
        check("M5 the published credential and the standing high-water agree",
              standing == credential_b["grant"]["grant_generation"] == 2)
        # Restoring consent A's credential (had it been written) now compares BELOW the
        # standing high-water — the app RETIRES it instead of admitting a second authority
        # wearing the same generation.
        restored_a = main_token_document("ya29.A", "1//A", 1_700_003_599, gen_a,
                                         "a@example.test", [MODIFY_SCOPE], d)
        check("M5 a restored earlier-generation credential compares BELOW the high-water",
              restored_a["grant"]["grant_generation"] < standing)
        # And the crash-gap's OWN cost is the honest one: hw = N+1 above a gen-N credential
        # on disk is a RETIRED credential — loud re-consent, never a duplicate.
        atomic_write(token_path, json.dumps(restored_a, indent=2) + "\n")
        check("M5 a crash between the reservation and the write leaves a RETIRED credential",
              json.loads(open(token_path, encoding="utf-8").read())["grant"]
              ["grant_generation"] < read_grant_high_water(d))
    # The reservation inherits the read door's fail-loud law: it never repairs a ratchet
    # whose bytes we could not understand, and it never hands out a generation over one.
    for corrupt in ("not json", '{"grant_generation": "4"}', '{"grant_generation": -1}'):
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, "grant_high_water.json"), corrupt)
            try:
                reserve_grant_generation(d)
                check(f"M5 reserving over a corrupt high-water refuses ({corrupt!r})", False)
            except MintError:
                check(f"M5 reserving over a corrupt high-water refuses ({corrupt!r})", True)

    # M5b THE ORDER PIN, reversed (RK2). The reservation PRECEDES the token write; the
    # credential is never published under a generation the ratchet has not already claimed.
    # #91: this pin is no longer the only thing holding that order. The reservation is a
    # `ReservedGeneration` and both publishers refuse anything else, so the order is
    # TYPE-CARRIED as well as source-pinned — an edit that moved the write above the
    # reservation would not merely fail this check, it would not run at all (M12).
    check("M5b the reservation precedes the credential write",
          reserve_at >= 0
          and reserve_at < mint_src.index("gmail_readside_main_token.json"))

    # M6 ONE PRINCIPAL LAW, applied at BOTH of the mint's doors (PL2). The corpus is the
    # one three council seats executed against the pre-fold mint, which ACCEPTED every
    # member of it and then ratcheted past the last admissible credential (seat 1 F-1,
    # seat 3 claim 1's `not-an-email`).
    principal_corpus = (
        "me", "ME", "Me", ".", "..", "a/b", "a?b", "a#b", "a%b", "a\tb", "a b",
        "\u00fcser@x.test", "x" * 400, "a\x00b", "a\x7fb",
        "not-an-email", "a@", "@x", "a@nodot", "a@@b.test", "a@.b.test", "a@b.test.",
    )
    for hostile in principal_corpus:
        label = repr(hostile[:20])
        violation = principal_shape_violation(hostile)
        check(f"M6 the law names a CLOSED-SET class for it ({label})",
              violation in PRINCIPAL_SHAPE_CLASSES)
        for door, call in (
                ("gmail getProfile",
                 lambda: main_principal_from_profile({"emailAddress": hostile})),
                ("the credential about to be written",
                 lambda: main_token_document("t", "r", 1, res1, hostile, [MODIFY_SCOPE],
                                             dir1))):
            try:
                call()
                check(f"M6 refused at {door} ({label})", False)
            except MintError as e:
                # EQUALITY, not containment: the sentence is built from the DOOR and the
                # CLASS only, so asserting the whole string pins that the provider-supplied
                # value structurally cannot ride the refusal.
                check(f"M6 refused at {door} ({label})",
                      str(e) == principal_refusal_sentence(door, violation)
                      and "principal" in str(e).lower())
    # …and the no-echo property, said out loud on two values distinctive enough that a
    # substring collision with the class sentences is not possible.
    for distinctive in ("SENTINEL-echo/probe@x.test", "z" * 400):
        for call in (lambda: main_principal_from_profile({"emailAddress": distinctive}),
                     lambda: main_token_document("t", "r", 1, res1, distinctive,
                                                 [MODIFY_SCOPE], dir1)):
            try:
                call()
                check(f"M6 the refusal never echoes the value ({distinctive[:12]!r})", False)
            except MintError as e:
                check(f"M6 the refusal never echoes the value ({distinctive[:12]!r})",
                      distinctive not in str(e))
    # The byte bound is a BYTE bound: 254 ASCII bytes of local part still fit, 255 do not,
    # and a multi-byte character cannot buy length by counting as one char.
    check("M6 a 254-byte mailbox address is accepted",
          principal_shape_violation("a" * (254 - len("@example.com")) + "@example.com")
          is None)
    check("M6 a 255-byte mailbox address is refused as too long",
          principal_shape_violation("a" * (255 - len("@example.com")) + "@example.com")
          == PRINCIPAL_TOO_LONG)
    check("M6 a provider-native mailbox address is ACCEPTED at both doors",
          main_principal_from_profile({"emailAddress": "owner@example.com"})
          == "owner@example.com"
          and main_token_document("t", "r", 1, res1, "owner@example.com",
                                  [MODIFY_SCOPE], dir1)["grant"]["provider_principal"]
          == "owner@example.com")

    # M7 NUMERIC DOMAIN PARITY (RK5): the ratchet file is SHARED with the app, whose schema
    # is `{"grant_generation": u64}`. A value the Python writer accepts and the Rust reader
    # cannot represent is a state the app must call unusable — refuse it at our own door.
    over_u64 = 2 ** 64                     # u64::MAX + 1 = 18446744073709551616
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     '{"grant_generation": %d}\n' % over_u64)
        try:
            got = read_grant_high_water(d)
            check("M7 an over-u64 standing high-water refuses at the read door", False)
            print(f"       read it as: {got!r}")
        except MintError as e:
            check("M7 an over-u64 standing high-water refuses at the read door",
                  "u64" in str(e) and "high-water" in str(e))
        try:
            raise_grant_high_water(d, 5)
            check("M7 raising over an over-u64 high-water refuses", False)
        except MintError:
            check("M7 raising over an over-u64 high-water refuses", True)
    with tempfile.TemporaryDirectory() as d:
        try:
            raise_grant_high_water(d, over_u64)
            check("M7 raising TO an over-u64 generation refuses", False)
        except MintError as e:
            check("M7 raising TO an over-u64 generation refuses", "u64" in str(e))
        check("M7 the refused raise wrote no ratchet file",
              not os.path.exists(os.path.join(d, "grant_high_water.json")))
        check("M7 u64::MAX itself is still a legal high-water",
              raise_grant_high_water(d, over_u64 - 1) == over_u64 - 1
              and read_grant_high_water(d) == over_u64 - 1)
        try:
            reserve_grant_generation(d)
            check("M7 reserving PAST u64::MAX refuses (saturation is loud)", False)
        except MintError as e:
            check("M7 reserving PAST u64::MAX refuses (saturation is loud)",
                  "u64" in str(e))
    # #91 moved the document's u64 door: the bound is now enforced where the generation is
    # MINTED (the reservation above — "M7 reserving PAST u64::MAX refuses"), and an over-u64
    # bare integer cannot even reach the document, because a bare integer is not a
    # reservation. Both doors still refuse the same bytes; the witness names which one.
    try:
        main_token_document("t", "r", 1, over_u64, "owner@example.com", [MODIFY_SCOPE],
                            dir1)
        check("M7 the token document refuses an over-u64 generation", False)
    except MintError as e:
        check("M7 the token document refuses an over-u64 generation",
              "ReservedGeneration" in str(e))
    dir_max, res_max = reserved_for(over_u64 - 1)
    check("M7 u64::MAX is still reservable and writable into a credential",
          res_max.generation == over_u64 - 1
          and main_token_document("t", "r", 1, res_max, "owner@example.com",
                                  [MODIFY_SCOPE],
                                  dir_max)["grant"]["grant_generation"] == over_u64 - 1)

    # M8 CANONICAL SCOPE SET (PL4): the credential's `effective_scopes` is a SET on disk —
    # sorted AND deduplicated — because the app's reader is a `BTreeSet` and the comment at
    # its door promises "one shape on disk". A duplicated member does not widen authority,
    # but it makes the two writers disagree about the canonical bytes.
    dup_doc = main_token_document("t", "r", 1, res1, "owner@example.com",
                                  [MODIFY_SCOPE, MODIFY_SCOPE], dir1)
    check("M8 a duplicated granted scope serializes ONCE",
          dup_doc["grant"]["effective_scopes"] == [MODIFY_SCOPE])
    check("M8 the canonical set is sorted and deduplicated",
          main_token_document("t", "r", 1, res1, "owner@example.com",
                              ["b", "a", "b", "a"], dir1)["grant"]["effective_scopes"]
          == ["a", "b"])

    # M9 LEXICAL DOMAIN PARITY (RK5b): the ratchet file is SHARED with the app, and the two
    # readers must agree on the SPELLING of the generation, not merely on its value. Rust's
    # `serde_json` `as_u64` REFUSES the token `-0`; Python's `json.loads` admits it as the
    # integer 0 (council r2 seat 3, EXECUTED). That divergence is the worst possible one for
    # this file: the app calls the ratchet unusable while the mint reads it as "nothing
    # minted yet" and re-issues a generation the app has already retired. So the mint parses
    # the ratchet through a hook that sees the RAW integer token and admits only a canonical
    # non-negative decimal — no sign, no zero padding.
    # The matrix itself lives at module scope (RATCHET_LEXICAL_MATRIX) because the parity
    # corpus emits from the SAME byte-strings — a retyped copy is a corpus that can drift
    # away from the witness that justifies it.
    for _case_name, token, admitted in RATCHET_LEXICAL_MATRIX:
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, "grant_high_water.json"),
                         '{"grant_generation": %s}\n' % token)
            verb = "ACCEPTS" if admitted else "refuses"
            label = f"M9 ratchet generation token {token!r} {verb}"
            try:
                got = read_grant_high_water(d)
                check(label, admitted and got == int(token))
                if not admitted:
                    print(f"       read it as: {got!r}")
            except MintError as e:
                check(label, (not admitted) and "high-water" in str(e))
            except Exception as e:  # a refusal is a MintError, never a raw crash at the door
                check(label, False)
                print(f"       raised {type(e).__name__}: {e}")
            if not admitted:
                try:
                    raise_grant_high_water(d, 9)
                    check(f"M9 raising over the token {token!r} refuses too", False)
                except MintError:
                    check(f"M9 raising over the token {token!r} refuses too", True)
    # …and the refusal names the SHAPE, never the offending bytes (MintError's safety law).
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     RATCHET_SINGLE_PROBES[0][1])
        try:
            read_grant_high_water(d)
            check("M9 the -0 refusal does not echo the offending token", False)
        except MintError as e:
            check("M9 the -0 refusal does not echo the offending token", "-0" not in str(e))

    # M9 addendum — WHICH DOOR: `NaN`, `Infinity` and `-Infinity` are CPython `json`
    # EXTENSIONS (RFC 8259 has no such literals, and the app's `serde_json` refuses all
    # three). They never reach the `parse_int` lexical hook above — CPython routes them to
    # `parse_constant`, which hands back a `float`. So the door that refuses them is the
    # `type(generation) is not int` check at the READ door, not the lexical hook, and the
    # witness pins that door by name: the refusal sentence must be the type one.
    for extension in RATCHET_JSON_EXTENSION_TOKENS:
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, "grant_high_water.json"),
                         '{"grant_generation": %s}\n' % extension)
            try:
                got = read_grant_high_water(d)
                check(f"M9 the CPython json extension {extension!r} refuses", False)
                print(f"       read it as: {got!r}")
            except MintError as e:
                check(f"M9 the CPython json extension {extension!r} refuses",
                      "high-water" in str(e))
                check(f"M9 {extension!r} refuses at the `type(...) is int` door, not the "
                      "lexical hook",
                      "not a non-negative integer" in str(e) and "float" in str(e))

    # M10 THE RATCHET IS ONE OBJECT WITH ONE MEMBER (RK5c). A JSON object is a LIST of
    # name/value pairs on the wire, and the two readers of this SHARED file resolve a
    # repeated name differently: CPython's `json` keeps the LAST pair, so
    # `{"grant_generation": -0, "grant_generation": 2}` reads as 2 — the per-token
    # `parse_int` hook saw `-0`, refused the losing pair, and that refusal was DISCARDED
    # with it — while the app's typed reader (`deny_unknown_fields`) refuses a duplicate
    # field outright. Same bytes, two answers, and the divergent answer is the MINT's: it
    # would hand out a generation over a file the app calls unusable, which is the very
    # rollback this file exists to catch. (Council r3 seat 2, EXECUTED.) So the ratchet is
    # parsed through an `object_pairs_hook` that sees the pairs BEFORE the dict collapses
    # them, and holds the shape by CONTRACT, not by luck: exactly one object, no repeated
    # name (ANY name, not only `grant_generation`), and no member but `grant_generation`.
    # WHICH DOOR, stated honestly: CPython scans tokens as it goes, so the per-token
    # `parse_int` hook fires BEFORE the object's pairs are assembled and handed to
    # `object_pairs_hook`. A repeat whose losing pair is ALSO lexically illegal — the
    # executed `{"grant_generation": -0, "grant_generation": 2}` — therefore refuses at the
    # LEXICAL door and names the SPELLING class. Both doors refuse, which is the whole
    # contract; so the witness pins the SHAPE class only where every token is legal, and
    # tests OUR rule rather than CPython's scanner order. The `7, 2` row is the harm in one
    # line: every token legal, last-wins reads 2 over a standing 7 — a rollback — while the
    # app's typed reader refuses the same bytes.
    for _case_name, document_bytes, named_class in RATCHET_REPEAT_MATRIX:
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, "grant_high_water.json"), document_bytes + "\n")
            label = f"M10 a repeated member name refuses ({document_bytes})"
            try:
                got = read_grant_high_water(d)
                check(label, False)
                print(f"       read it as: {got!r}")
            except MintError as e:
                check(label, "high-water" in str(e) and named_class in str(e))
            except Exception as e:   # a refusal is a MintError, never a raw crash
                check(label, False)
                print(f"       raised {type(e).__name__}: {e}")
            try:
                raise_grant_high_water(d, 9)
                check(f"M10 raising over a repeated member refuses too ({document_bytes})",
                      False)
            except MintError:
                check(f"M10 raising over a repeated member refuses too ({document_bytes})",
                      True)

    for _case_name, document_bytes in RATCHET_STOWAWAY_MATRIX:
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, "grant_high_water.json"), document_bytes + "\n")
            label = f"M10 a member outside the shared schema refuses ({document_bytes})"
            try:
                got = read_grant_high_water(d)
                check(label, False)
                print(f"       read it as: {got!r}")
            except MintError as e:
                check(label, "high-water" in str(e) and "member" in str(e))
            except Exception as e:
                check(label, False)
                print(f"       raised {type(e).__name__}: {e}")

    # The refusal names the CLASS and never echoes the member's value (MintError's safety
    # law — the same one M9's `-0` check pins for the lexical door).
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     RATCHET_SINGLE_PROBES[1][1])
        try:
            read_grant_high_water(d)
            check("M10 the repeat refusal does not echo either offending value", False)
        except MintError as e:
            check("M10 the repeat refusal does not echo either offending value",
                  "424242" not in str(e) and "424243" not in str(e))
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     RATCHET_SINGLE_PROBES[2][1])
        try:
            read_grant_high_water(d)
            check("M10 the stowaway refusal does not echo the stowaway's value", False)
        except MintError as e:
            check("M10 the stowaway refusal does not echo the stowaway's value",
                  "424242" not in str(e))

    # …and the one legal shape still reads, so the contract refuses SHAPES, not the file.
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     RATCHET_SINGLE_PROBES[3][1])
        check("M10 the one legal shape still reads", read_grant_high_water(d) == 7)
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     RATCHET_SINGLE_PROBES[4][1])
        check("M10 insignificant whitespace is still the legal shape",
              read_grant_high_water(d) == 7)
    with tempfile.TemporaryDirectory() as d:
        atomic_write(os.path.join(d, "grant_high_water.json"),
                     RATCHET_SINGLE_PROBES[5][1])
        try:
            got = read_grant_high_water(d)
            check("M10 a legal object wrapped in an ARRAY is still not the top level", False)
            print(f"       read it as: {got!r}")
        except MintError as e:
            check("M10 a legal object wrapped in an ARRAY is still not the top level",
                  "high-water" in str(e))

    # M12 RESERVE-BEFORE-PUBLISH, TYPE-CARRIED (#91, mint half). RK2's ordering law used to
    # live only in `run_mint`'s statement order: `reserve_grant_generation` handed back a
    # bare `int`, and every publisher accepted any `int`, so the credential-first order the
    # council executed against was still SPELLABLE — one edit away, with nothing but a
    # comment holding the line. The reservation is now a VALUE with a type: only
    # `reserve_grant_generation` can construct a `ReservedGeneration`, and the publishers
    # refuse anything else. The order is therefore carried by the types, not by prose.
    # (The ratchet's readers/raisers are deliberately untouched — `read_grant_high_water`
    # and `raise_grant_high_water` ARE the ratchet; the DOOR is the document builder.)
    with tempfile.TemporaryDirectory() as d_pub, tempfile.TemporaryDirectory() as d_other:

        def refuses(label, call, must_name):
            """A publisher refusal is a MintError naming a CLASS — never a raw crash."""
            try:
                call()
                check(label, False)
            except MintError as e:
                check(label, must_name in str(e))
                if must_name not in str(e):
                    print(f"       said: {e}")
            except Exception as e:
                check(label, False)
                print(f"       raised {type(e).__name__}: {e}")

        reserved = reserve_grant_generation(d_pub)
        foreign = reserve_grant_generation(d_other)
        check("M12 reserve_grant_generation hands back a ReservedGeneration, never a bare int",
              type(reserved).__name__ == "ReservedGeneration")
        check("M12 the reservation carries the generation it claimed in the ratchet",
              getattr(reserved, "generation", None) == 1
              and read_grant_high_water(d_pub) == 1)
        check("M12 the reservation remembers the ratchet it was taken from",
              getattr(reserved, "secrets_dir", None) == d_pub)
        # THE DOOR: a bare integer is not a reservation. Every spelling refuses, and the
        # refusal names the CLASS the publisher requires, never the value it was handed.
        for bare in (1, 7, 424242, 0, -1, True, "1", 1.0, None):
            refuses(f"M12 the document builder refuses the bare generation {bare!r}",
                    lambda bare=bare: main_token_document(
                        "t", "r", 1, bare, "p@example.test", [MODIFY_SCOPE], d_pub),
                    "ReservedGeneration")
        try:
            main_token_document("t", "r", 1, 424242, "p@example.test", [MODIFY_SCOPE], d_pub)
            check("M12 the bare-generation refusal never echoes the value", False)
        except MintError as e:
            check("M12 the bare-generation refusal never echoes the value",
                  "424242" not in str(e))
        except Exception as e:
            check("M12 the bare-generation refusal never echoes the value", False)
            print(f"       raised {type(e).__name__}: {e}")
        # …and a REAL reservation taken over a DIFFERENT ratchet is not a reservation over
        # this one: a reservation is only meaningful against the file it was claimed in.
        refuses("M12 the document builder refuses a reservation taken over another "
                "secrets dir",
                lambda: main_token_document("t", "r", 1, foreign, "p@example.test",
                                            [MODIFY_SCOPE], d_pub),
                "different secrets directory")
        refuses("M12 the credential-write path refuses a bare generation too",
                lambda: publishable_credential_bytes(d_pub, 1, {}),
                "ReservedGeneration")
        refuses("M12 the credential-write path refuses a foreign reservation too",
                lambda: publishable_credential_bytes(d_pub, foreign, {}),
                "different secrets directory")
        # The genuine reservation publishes, and the bytes carry the generation it claimed.
        built = None
        try:
            built = main_token_document("ya29.pub", "1//pub", 1_700_003_599, reserved,
                                        "drill@example.test", [MODIFY_SCOPE], d_pub)
        except Exception as e:
            print(f"       raised {type(e).__name__}: {e}")
        check("M12 a genuine reservation builds the credential under its own generation",
              isinstance(built, dict)
              and built["grant"]["grant_generation"] == 1
              and built["grant"]["provider_principal"] == "drill@example.test")
        written = None
        try:
            written = publishable_credential_bytes(d_pub, reserved, built)
        except Exception as e:
            print(f"       raised {type(e).__name__}: {e}")
        check("M12 the credential-write path emits the document it was handed",
              isinstance(written, str) and written.endswith("\n")
              and json.loads(written) == built)
        # A document whose generation is NOT the reserved one never reaches the disk.
        refuses("M12 the credential-write path refuses a document under another generation",
                lambda: publishable_credential_bytes(
                    d_pub, reserved,
                    {"grant": {"grant_generation": 9}}),
                "generation this mint reserved")

    # …and the WIRING, pinned at the writer: the reservation is taken BEFORE the document
    # exists, and the principal law runs BEFORE the ratchet moves (council r1 seat 1 F-1 —
    # a nonconformant getProfile reply must refuse with the ratchet untouched).
    validate_at = mint_src.find("require_publishable_principal(main_identity)")
    build_at = mint_src.find("main_token_document(")
    check("M12 run_mint reserves BEFORE it builds the credential document",
          reserve_at >= 0 and build_at >= 0 and reserve_at < build_at)
    check("M12 run_mint validates the principal BEFORE the ratchet moves (F-1)",
          validate_at >= 0 and validate_at < reserve_at)
    check("M12 run_mint publishes through the credential-write door",
          "publishable_credential_bytes(" in mint_src)

    # M13 THE PARITY CORPUS IS A COMMITTED FIXTURE, AND IT IS THIS READER'S ANSWER SHEET.
    # The ratchet file has two readers and one meaning; the divergences council r2 seat 3
    # and r3 seat 2 executed were both "same bytes, two answers". A corpus is how that stops
    # being an argument: the byte-strings and OUR verdict for each are committed where the
    # app's Rust test can read them, so a drift on either side is a failing test rather than
    # a discovery months later over a real credential. Regenerated in memory here and
    # compared BYTE-FOR-BYTE with the committed file, so the fixture can never quietly fall
    # behind the reader (and the reader can never quietly move without the fixture).
    corpus_fixture = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "src-tauri", "tests", "fixtures", "ratchet-parity-corpus.json"))
    generated = ratchet_parity_corpus_bytes()
    if os.path.exists(corpus_fixture):
        check("M13 the ratchet-parity corpus fixture is COMMITTED", True)
        with open(corpus_fixture, "rb") as f:
            committed = f.read()
        check("M13 the corpus regenerates byte-identical to the committed fixture",
              committed == generated)
        if committed != generated:
            print(f"       committed {len(committed)} bytes, regenerated {len(generated)}")
            # NAME THE LIKELY CAUSE, because on Windows it is almost never a real drift:
            # the fixture is LF and this repo runs with core.autocrlf, so a checkout can
            # rewrite it to CRLF. The corpus is a file TWO languages read byte-for-byte, so
            # the fix is a .gitattributes rule marking it binary — not a looser comparison
            # here, and not a re-emit that would only be rewritten again on the next
            # checkout.
            if committed.replace(b"\r\n", b"\n") == generated:
                print("       the ONLY difference is CRLF: git translated the committed "
                      "fixture's line endings on checkout. Fix the repo, not the corpus — "
                      "add to .gitattributes:")
                print("       src-tauri/tests/fixtures/ratchet-parity-corpus.json -text")
            print("       regenerate: python scripts/gmail_drill_mint.py "
                  "--emit-ratchet-parity-corpus "
                  "src-tauri/tests/fixtures/ratchet-parity-corpus.json")
    else:
        # LOUD, not skipped: a missing fixture is the corpus not existing at all.
        check("M13 the ratchet-parity corpus fixture is COMMITTED", False)
        check("M13 the corpus regenerates byte-identical to the committed fixture", False)
        print(f"       missing: {corpus_fixture}")
        print("       regenerate: python scripts/gmail_drill_mint.py "
              "--emit-ratchet-parity-corpus "
              "src-tauri/tests/fixtures/ratchet-parity-corpus.json")
    corpus = json.loads(generated.decode("ascii"))
    check("M13 the corpus declares the shared schema name",
          corpus["schema"] == "photon.ratchet-parity-corpus.v1")
    case_names = [case["name"] for case in corpus["cases"]]
    check("M13 case names are unique and sorted",
          case_names == sorted(case_names) and len(set(case_names)) == len(case_names))
    check("M13 every case carries bytes and a verdict",
          all(set(case) == {"name", "bytes_b64", "python"} for case in corpus["cases"]))
    # The corpus is not a copy of the reader's opinion — it is REPLAYED through the real
    # read door, on real files, and must agree. (The door reports a MintError, not a label;
    # the label is this module's classification of which sentinel fired, pinned by M9/M10.)
    verdict_drift = []
    for case in corpus["cases"]:
        raw = base64.b64decode(case["bytes_b64"])
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, GRANT_HIGH_WATER_FILENAME), "wb") as f:
                f.write(raw)
            try:
                door = "accept:%d" % read_grant_high_water(d)
            except MintError:
                door = "refuse"
            except Exception as raw_crash:      # a refusal is a MintError, never a crash
                door = "crash:%s" % type(raw_crash).__name__
        recorded = case["python"]
        if not (door == recorded
                or (door == "refuse" and recorded.startswith("refuse:"))):
            verdict_drift.append((case["name"], recorded, door))
    check("M13 every recorded verdict is what the real read door does to those exact bytes",
          not verdict_drift)
    for name, recorded, door in verdict_drift:
        print(f"       {name}: corpus says {recorded}, the door said {door}")
    labels = sorted({case["python"].split(":", 1)[1] for case in corpus["cases"]
                     if case["python"].startswith("refuse:")})
    # The expected label set is DERIVED from the reader's own table (plus the one fallback label
    # `ratchet_reader_verdict` emits for a refusal no sentinel names) — never a second
    # hand-maintained list checked against the first (the fips partition-rule shape: a label the
    # reader gains that the corpus never exercises goes RED here, instead of hiding behind a list
    # nobody updated). Probe: add a `(_X, "new-label")` row to RATCHET_REFUSAL_LABELS and this
    # check fails naming the label the corpus lacks.
    reader_labels = sorted({label for _sentinel, label in RATCHET_REFUSAL_LABELS} | {"not-json"})
    check("M13 the corpus exercises every refusal label the reader can produce "
          "(expected set derived from RATCHET_REFUSAL_LABELS: %s; corpus has: %s)"
          % (reader_labels, labels),
          labels == reader_labels)
    check("M13 the corpus carries accepted cases too (it refuses SHAPES, not the file)",
          sum(1 for case in corpus["cases"]
              if case["python"].startswith("accept:")) >= 6)
    # The ABSENT file is NOT a case: "no file" is not a byte-string, and it is the one state
    # that legitimately reads as 0. An EMPTY file is a different thing entirely and IS a
    # case — the two must never be conflated by either reader.
    with tempfile.TemporaryDirectory() as d:
        check("M13 an ABSENT ratchet still reads as 0 and is deliberately not a corpus case",
              read_grant_high_water(d) == 0
              and all(base64.b64decode(case["bytes_b64"]) != b"" or
                      case["python"] == "refuse:not-json" for case in corpus["cases"]))

    # M14 THE RATCHET FILE IS BYTES, AND NOT EVERY BYTE-STRING IS TEXT (council r4 seats 2 and
    # 3, EXECUTED). The read door promised that EVERY unusable form of this file becomes a
    # `MintError` — that promise is what `main()` rests on, since it catches `MintError` and
    # nothing else. Opening the ratchet in TEXT mode broke it: a file holding a byte that is not
    # UTF-8 raised a raw `UnicodeDecodeError` out of `f.read()`, before any of the doors below
    # could name a class, and a raw traceback out of a credential tool is not a refusal. So the
    # door reads BYTES and decodes EXPLICITLY, and a decode failure is its own typed class,
    # ordered where it belongs: unreadable -> not-utf8 -> not-json -> the shape ladder.
    for _case_name, probe in RATCHET_NOT_UTF8_PROBES:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, GRANT_HIGH_WATER_FILENAME), "wb") as f:
                f.write(probe)
            label = f"M14 a ratchet that is not UTF-8 refuses as its own class ({_case_name})"
            try:
                got = read_grant_high_water(d)
                check(label, False)
                print(f"       read it as: {got!r}")
            except MintError as e:
                check(label, "high-water" in str(e) and "UTF-8" in str(e))
                # The refusal names the CLASS and carries no file content (MintError's safety
                # law): not the offending byte, not the document that surrounds it.
                check(f"M14 the not-utf8 refusal carries no file content ({_case_name})",
                      "grant_generation" not in str(e) and repr(probe) not in str(e))
            except Exception as e:   # a refusal is a MintError, never a raw crash at the door
                check(label, False)
                print(f"       raised {type(e).__name__}: {e}")
            try:
                raise_grant_high_water(d, 9)
                check(f"M14 raising over a non-UTF-8 ratchet refuses too ({_case_name})", False)
            except MintError:
                check(f"M14 raising over a non-UTF-8 ratchet refuses too ({_case_name})", True)
            except Exception as e:
                check(f"M14 raising over a non-UTF-8 ratchet refuses too ({_case_name})", False)
                print(f"       raised {type(e).__name__}: {e}")
            check(f"M14 the corpus helper gives the same class as the live door ({_case_name})",
                  ratchet_reader_verdict(probe) == "refuse:not-utf8")

    # M15 THE SHAPE LAW IS THE TOP LEVEL'S, NOT EVERY OBJECT'S (council r4 seat 1, EXECUTED).
    # CPython calls `object_pairs_hook` for EVERY object it decodes, innermost first — so a hook
    # that enforces "exactly one member, named grant_generation" judged the NESTED object too,
    # and `{"grant_generation": {"n": 7}}` refused as "a member outside the shared schema" over
    # the inner `n`. That is a lie about a document whose members are exactly right: the fault is
    # the VALUE's TYPE. The hook now only RECORDS each object's wire pairs; the shape law runs
    # once, on the outermost result, and a nested object or array as the value falls to the
    # existing type door as `not-u64`.
    for _case_name, document_bytes in RATCHET_NESTED_VALUE_PROBES:
        with tempfile.TemporaryDirectory() as d:
            atomic_write(os.path.join(d, GRANT_HIGH_WATER_FILENAME), document_bytes + "\n")
            label = ("M15 a nested value refuses as the VALUE's type, never a member-shape "
                     f"class ({_case_name})")
            try:
                got = read_grant_high_water(d)
                check(label, False)
                print(f"       read it as: {got!r}")
            except MintError as e:
                sentence = str(e)
                agreed = ("not a non-negative integer" in sentence
                          and "repeats a member name" not in sentence
                          and "member the shared schema has no field for" not in sentence)
                check(label, agreed)
                if not agreed:
                    print(f"       it said: {sentence}")
            except Exception as e:
                check(label, False)
                print(f"       raised {type(e).__name__}: {e}")
            check(f"M15 the corpus helper agrees it is the not-u64 class ({_case_name})",
                  ratchet_reader_verdict((document_bytes + "\n").encode("utf-8"))
                  == "refuse:not-u64")

    # -------------------------------------------------------------------------------------
    # F14 (#75 S0 r11) — THE CEREMONY'S DURABILITY, AND ITS THIRD READER.
    # -------------------------------------------------------------------------------------
    # F14-A `atomic_write` must be DURABLE, not merely ATOMIC. The r11 ceremony-flow audit
    # found no `os.fsync` anywhere in this file: the `with` block's close pushes the bytes into
    # the OS page cache and `os.replace` publishes the name, but nothing forces the device, so
    # the reserve-first ordering `run_mint` argues at length has no DISK-order relationship
    # behind it — a power loss can land the credential and LOSE the ratchet raise, which is
    # precisely the state reserve-first exists to make impossible (council r1 seat 3 executed
    # the rollback that state enables). The witness records CALL ORDER: the file's bytes are
    # forced before its name is published, and on POSIX the parent directory is forced AFTER
    # the replace — a rename (and the `--main-only` unlink) is a directory-entry change, and
    # fsync(2) says "Calling fsync() does not necessarily ensure that the entry in the
    # directory containing the file has also reached disk". On WINDOWS the directory leg must
    # be ABSENT: `os.open(<dir>)` raises PermissionError there (witnessed on the owner's box),
    # so an unguarded directory fsync would brick the mint at the moment right after the
    # credential lands.
    # `fcntl` is the module-level binding this file already imports for the writer lock
    # (None on Windows) — patching THAT is what proves `flush_to_device`'s macOS arm, rather
    # than a second handle onto the same module.
    _fcntl_probe = fcntl
    _full_fsync_op = getattr(_fcntl_probe, "F_FULLFSYNC", None) if _fcntl_probe else None
    _durability_dir = tempfile.mkdtemp()
    reservation_dirs.append(_durability_dir)
    _durability_calls = []
    _real_fsync, _real_replace, _real_os_open = os.fsync, os.replace, os.open
    _real_fcntl = _fcntl_probe.fcntl if _fcntl_probe is not None else None

    def _recording_fsync(fd):
        _durability_calls.append(("fsync", fd))
        return _real_fsync(fd)

    def _recording_replace(src, dst):
        _durability_calls.append(("replace", dst))
        return _real_replace(src, dst)

    def _recording_os_open(path, flags, *rest, **kwargs):
        # Only DIRECTORY opens are interesting; mkstemp's own file open runs through here too.
        if os.path.isdir(path):
            _durability_calls.append(("open-dir", os.path.abspath(path)))
        return _real_os_open(path, flags, *rest, **kwargs)

    def _recording_fcntl(fd, op, *rest):
        if _full_fsync_op is not None and op == _full_fsync_op:
            _durability_calls.append(("fullfsync", fd))
        return _real_fcntl(fd, op, *rest)

    os.fsync, os.replace, os.open = _recording_fsync, _recording_replace, _recording_os_open
    if _fcntl_probe is not None:
        _fcntl_probe.fcntl = _recording_fcntl
    try:
        atomic_write(os.path.join(_durability_dir, "durability-witness.json"), "{}\n")
    finally:
        os.fsync, os.replace, os.open = _real_fsync, _real_replace, _real_os_open
        if _fcntl_probe is not None:
            _fcntl_probe.fcntl = _real_fcntl

    _kinds = [_kind for _kind, _ in _durability_calls]
    _replace_at = _kinds.index("replace") if "replace" in _kinds else -1
    check("F14-A atomic_write publishes the name through os.replace", _replace_at >= 0)
    check("F14-A the bytes are forced to the device BEFORE the name is published",
          _replace_at > 0
          and any(_kind in ("fsync", "fullfsync") for _kind in _kinds[:_replace_at]))
    _after_replace = _durability_calls[_replace_at + 1:] if _replace_at >= 0 else []
    if os.name == "posix":
        check("F14-A POSIX: the parent directory is opened AFTER the replace",
              os.path.abspath(_durability_dir)
              in [_p for _kind, _p in _after_replace if _kind == "open-dir"])
        check("F14-A POSIX: a directory fsync follows the replace",
              any(_kind == "fsync" for _kind, _ in _after_replace))
    else:
        # The over-closing guard, asserted as an ABSENCE: on this platform `os.open` over a
        # directory raises PermissionError, so "no directory open at all" is the only shape
        # that does not turn a durability close into a crash on the owner's own box.
        check("F14-A non-POSIX: NO directory open (os.open over a dir raises PermissionError)",
              not any(_kind == "open-dir" for _kind, _ in _durability_calls))

    # F14-B THE CEREMONY'S THIRD READER. The runbook told the operator to export the ratchet's
    # generation with a hand-rolled `json.load(...)['grant_generation']`. The audit witnessed
    # five ratchet shapes that BOTH strict readers refuse (a repeated member, an unknown
    # member, a string-typed generation, a `-0`-then-2 last-wins pair, a nested extra object)
    # read by that line as a plain integer which the drill's `parse::<u64>` then ACCEPTS — the
    # drill could bank a green closure under a ratchet the mint refuses to read and the app
    # refuses to admit. The close is a REVERT of that self-authored tolerant reader onto the
    # chokepoint that already exists: `--print-high-water` prints exactly what
    # `read_grant_high_water` returns and nothing else, so the ceremony's third reader IS the
    # strict reader.
    for _case_name, _raw in (
            ("duplicate member", b'{"grant_generation": 1, "grant_generation": 9}\n'),
            ("unknown member", b'{"grant_generation": 9, "note": "hand-edited"}\n')):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, GRANT_HIGH_WATER_FILENAME), "wb") as f:
                f.write(_raw)
            _label = ("F14-B --print-high-water REFUSES a ratchet the strict reader refuses "
                      f"({_case_name})")
            _out = io.StringIO()
            try:
                with contextlib.redirect_stdout(_out):
                    print_grant_high_water(d)
                check(_label, False)
                print(f"       it printed: {_out.getvalue()!r}")
            except MintError as e:
                check(_label, "high-water" in str(e))
                check(f"F14-B the refusal prints NOTHING on stdout ({_case_name})",
                      _out.getvalue() == "")
            except Exception as e:
                check(_label, False)
                print(f"       raised {type(e).__name__}: {e}")
            # ...and the MODE's exit status is what the operator's `$( )` actually sees.
            _out, _err, _saved_argv = io.StringIO(), io.StringIO(), sys.argv
            sys.argv = ["gmail_drill_mint.py", "--print-high-water", "--secrets-dir", d]
            try:
                with contextlib.redirect_stdout(_out), contextlib.redirect_stderr(_err):
                    _rc = main()
            finally:
                sys.argv = _saved_argv
            check(f"F14-B the refusal exits NON-ZERO ({_case_name})", _rc != 0)
            check(f"F14-B the refusal goes to stderr, stdout stays empty ({_case_name})",
                  _out.getvalue() == "" and "high-water" in _err.getvalue())

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, GRANT_HIGH_WATER_FILENAME), "wb") as f:
            f.write(b'{"grant_generation": 9}\n')
        _out = io.StringIO()
        with contextlib.redirect_stdout(_out):
            _rc = print_grant_high_water(d)
        # A BARE integer, no `[mint]` prefix: the runbook interpolates this through `$( )`, and
        # a prefix would export a string the drill's `parse::<u64>` refuses — a confusing
        # refusal in place of a working export.
        check("F14-B a legal ratchet prints the BARE integer and nothing else",
              _out.getvalue() == "9\n")
        check("F14-B a legal ratchet exits 0", _rc == 0)

    with tempfile.TemporaryDirectory() as d:
        _out = io.StringIO()
        with contextlib.redirect_stdout(_out):
            print_grant_high_water(d)
        # The reader's OWN semantics, carried through unchanged: an absent ratchet is 0,
        # "nothing minted yet". The drill then refuses 0 against any real bundle, which is the
        # loud outcome. Said out loud in the runbook so the operator is not surprised by it.
        check("F14-B an absent ratchet prints 0 (the reader's own semantics)",
              _out.getvalue() == "0\n")

    for _reservation_dir in reservation_dirs:
        shutil.rmtree(_reservation_dir, ignore_errors=True)

    if failures:
        print(f"self-test: FAILED ({len(failures)} failing): {failures}")
        return 1
    print("self-test: OK")
    return 0


def build_arg_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--secrets-dir", default=os.path.join("~", ".photon", "gmail"))
    parser.add_argument("--client-secret", default="client_secret.json")
    parser.add_argument("--scope", default=MODIFY_SCOPE,
                        help="main-slot scope set (space-delimited). LANE-CONTRACTED: must "
                             "be exactly gmail.modify — the authority the product's triage "
                             "verbs need. Anything narrower (gmail.readonly alone), anything "
                             "wider, or the full-mailbox scope https://mail.google.com/ is "
                             "refused before consent and nothing is minted.")
    parser.add_argument("--denial-scope", default="openid email",
                        help="denial-slot scope set (space-delimited). LANE-CONTRACTED: must "
                             "carry NO Gmail authority (gmail.labels included — it "
                             "authorizes POST label create/edit).")
    parser.add_argument("--main-only", action="store_true",
                        help="mint the main slot only; denial fields stay null")
    parser.add_argument("--self-test", action="store_true",
                        help="run the W6 pure-logic witness matrix and exit")
    parser.add_argument("--print-high-water", action="store_true",
                        help="print the ratchet's standing grant generation as a BARE "
                             "integer and exit. No network, no client secret, no write. The "
                             "live-drill runbook interpolates this into "
                             "PHOTON_GMAIL_GRANT_HIGH_WATER so the ceremony reads the "
                             "ratchet through this module's STRICT reader instead of a "
                             "hand-rolled json.load that admits shapes both strict readers "
                             "refuse. An unusable ratchet exits non-zero with the reason on "
                             "stderr; an absent one prints 0 (nothing minted yet).")
    parser.add_argument("--emit-ratchet-parity-corpus", metavar="PATH",
                        help="write the ratchet-reader parity corpus (the byte-strings this "
                             "reader is pinned on, each with its verdict) to PATH and exit. "
                             "The committed copy lives at "
                             "src-tauri/tests/fixtures/ratchet-parity-corpus.json and the "
                             "self-test refuses any drift from it.")
    return parser


def main():
    args = build_arg_parser().parse_args()
    if args.self_test:
        return self_test()
    if args.emit_ratchet_parity_corpus:
        written = emit_ratchet_parity_corpus(args.emit_ratchet_parity_corpus)
        corpus = ratchet_parity_cases()
        print(f"[mint] wrote {len(corpus)} ratchet-parity cases to {written}")
        return 0
    if args.print_high_water:
        # Its own arm, not `run_mint`'s: this mode must never require a client secret and
        # must never reach the network. The refusal sentence goes to STDERR so that stdout
        # stays exactly the integer the runbook's `$( )` captures — or nothing at all.
        try:
            return print_grant_high_water(args.secrets_dir)
        except MintError as e:
            print(f"[mint] ERROR: {e}", file=sys.stderr)
            return 1
    try:
        return run_mint(args)
    except MintError as e:
        print(f"[mint] ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
