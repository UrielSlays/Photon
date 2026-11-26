# Photon — Gate 0 code-reading findings

**Date:** 2026-06-21 · **Status:** Gate 0 DONE. Verified the load-bearing claims against
current source (not trained memory). Conclusion: **architecture confirmed buildable; proceed to M0.**

## Gap (a) — Is a single mutation boundary real in code, or leaked into features? → REAL (confirmed)
**aerc** (verified `worker/types/messages.go`): every mailbox mutation is a typed `WorkerMessage` —
`DeleteMessages`, `MoveMessages`, `CopyMessages`, `FlagMessages`, `AnsweredMessages`, `AppendMessage` —
routed through one worker command bus between the UI and the backends (IMAP/JMAP/maildir). The UI does
**not** call backends directly. So the "single mutation boundary" we designed is a proven real-world
pattern, not theory. **Adopt:** every mutation = a typed command object through the bus; backends implement
`apply(command)`; UI never touches a connector. (This is also where our `ActionEnvelope` shape rides — D6.1.)

## Gap (b) — Canonical local identity under mutable/duplicated provider ids → pattern confirmed
Already byte-grounded in the deep-research (RFC 9051 IMAP UID+UIDVALIDITY can reset; RFC 8620 JMAP ids are
server-assigned + immutable + unique only within (account,type)). The cross-system pattern: **a stable
app-owned local id in the SoR, with provider-native handles confined below the seam via an id-map table**
(IMAP UID+UIDVALIDITY / Gmail/Graph id / JMAP id / CalDAV-CardDAV URL+ETag). Matches our merged model's
`Item(account, facet, id)` + below-seam id-map. **Thunderbird-Android** confirms the shape at the client
level (local DB as system-of-record; modular `backend/core/mail/legacy`); its exact message-key schema
lives in its `docs/engineering` ADRs — read those during M0 if we want a concrete reference implementation.

## pimalaya MIME boundary — GO / NO-GO → **GO** (clean, I/O-free, MIT)
Verified on lib.rs:
- **`mml-lib`** = pure MIME compose/parse (MML↔MIME), **no network/transport deps** (async runtime
  optional, not a transport). License **MIT** — *avoid the optional gpgme/PGP feature* which pulls LGPL-2.1.
- Its MIME workhorses are **`mail-builder` + `mail-parser`** (stalwartlabs' pure-Rust MIME crates,
  MIT/Apache, I/O-free) — we can **lift those directly** for the Rust MIME seam, or use `mml-lib` on top.
- **`email-lib`** = the *network* layer (bundles IMAP via `imap-client`, SMTP via `mail-send`, maildir) and
  depends on mml-lib for MIME. **We do NOT take email-lib** — we have our own connector seam; we take only
  the I/O-free MIME crates.
- **Net:** the Rust MIME hot-core (D2) has a clean MIT/Apache, network-free foundation. Recommended:
  start with `mail-parser`/`mail-builder` directly (smallest, purest); reach for `mml-lib` only if we want
  the higher-level MML compose ergonomics.

## Bottom line
The two gaps the deep-research couldn't close are closed: the single mutation boundary is real in code, and
canonical-identity-below-the-seam is the confirmed pattern. The one build-critical dependency (a clean Rust
MIME engine) is GO on MIT/Apache, I/O-free crates. **No blockers to M0.** The only thing M0 needs that we
don't have yet is the new repo.
