# M1 — Gmail connector, first slice (archive/unarchive over labels) · DESIGN

**Date:** 2026-06-27 · **Status:** Implemented
**Milestone:** M1 (milestone plan §4 — "Gmail API connector + send/outbox pipeline"), **first slice only.**
**Mirrors:** the M0 JMAP connector (`crates/aruna/src/jmap.rs`, design `docs/design/2026-06-24-jmap-connector-design.md`) — same seam, same discipline, different provider terrain.

---

## 1. Why this slice exists (the thesis it proves)

M1's whole point is **ADR-P003 neutrality**: the *same* contract drives a completely different provider terrain with no change to the engine. M0 proved the engine + the JMAP terrain (mailbox moves). This slice proves the **second** terrain — Gmail — where the mechanic is fundamentally different:

> **JMAP archives by moving a message between mailboxes (Inbox → Archive). Gmail has no Archive folder — archiving is removing the `INBOX` system label.** The native primitive is `users.messages.modify` / `users.messages.batchModify` with `addLabelIds` / `removeLabelIds`.

If the *identical* `Action::Archive` that drove a JMAP mailbox-move now drives a Gmail label-mutation through the same `CommandBus` / ADR-P013 lifecycle, with **zero engine change**, the contract has admitted a second, mechanically-disjoint provider for the canonical YELLOW verb-pair without engine accommodation.

**Scope of the claim (narrowed by review, which found one overclaim class: `ProviderSemanticBoundaryOverclaim`, existential-vs-universal, `ArchiveSemanticFidelity`).** This slice proves **`Connector::apply` actuator neutrality for one message-scoped archive/unarchive verb-pair** — an *existential* instance, not the *universal* ADR-P003 claim. It does **NOT** establish: (a) full ADR-P003 `MailSurfaceAdapter` / read-side neutrality; (b) verbs beyond this pair; (c) the 401 refresh-then-retry third `FailureKind` (the binary kind cannot express it — a known future engine-growth point, named identically in JMAP); (d) Gmail UI / *thread*-level archive semantics (see §3.2). Neutrality for *this verb-pair* is demonstrated; the universal contract claim is not yet earned.

## 2. Scope fence (load-bearing — read before building)

- **YELLOW only.** `Action::{Archive, Unarchive}` reused **unchanged**. No new `Action` variant, no engine/`classify`/truth-table touch. (A generic `Label{add,remove}` verb is a deliberate follow-on slice; out of scope here.)
- **Fake-first, live deferred.** Built behind a Gmail-shaped in-memory fake. The live HTTP impl lives in a sibling crate (`aruna-gmail`, mirroring `aruna-jmap`) and is a **later slice gated by ADR Part III** — real-provider destructive execution stays disabled by construction. **No network in this slice.**
- **§4-vs-Part-III correction:** master-plan §4's M1 DoD says "trash/send on a live Gmail account." ADR **Part III** disables real-provider RED (trash) + BLACK (send) until the validation gate passes. Authority ladder → **Part III wins**; this slice is the un-gated YELLOW path. (Tracked doc fix: amend §4's M1 DoD.)
- **Governance envelope stays RESERVED.** No `ActionEnvelope` hardening — upstream-blocked on the governance module ("no fire drill"). `authority_grant` is NOT added here (it lives in the engine, not the connector).

## 3. Architecture (mirror the JMAP seam exactly)

A new module `crates/aruna/src/gmail.rs`, structurally parallel to `jmap.rs`:

```
GmailConnector<T, A, M>  impl Connector              // the act-verb actuator (Connector::apply)
  ├─ T: GmailTransport          // the ONLY thing the live-HTTP slice replaces
  ├─ A: GmailAccountResolver    // photon account -> Gmail userId (below seam)
  ├─ M: GmailMessageRefResolver // photon message_ref -> Gmail message id (below seam)
  └─ CapabilityMap              // ADR-P010 published surface (archive/unarchive)
```

**The genuinely SHARED neutral seam is `Connector` + `Command` + `ConnectorError` + `FailureKind` + `LogError`** (defined in `crate::` / `lib.rs`) — that boundary (`Connector::apply`) is what M0 proved and is what neutrality rests on; do NOT fork it. The **resolvers and transport are connector-local**, not shared: `jmap.rs`'s `AccountResolver`/`MessageRefResolver` are JMAP-typed (they return the JMAP `EmailId`/`AccountId` and live in `jmap.rs`), so Gmail defines its own parallel resolver traits returning Gmail-native ids. (This matches how `jmap.rs` is actually structured — only `Connector` crosses connectors; the resolvers are per-provider. If a third connector later wants a shared resolver, generalize then, not speculatively now — YAGNI.)

### 3.1 Provider-native ids below the seam (ADR-P003/P004)
New Gmail-local below-seam newtypes, never surfaced above `apply`:
- `GmailUserId(String)` — the Gmail `userId` (`"me"` or the address). `GmailAccountResolver` resolves the Photon-local account to this.
- `GmailMessageId(String)` — the Gmail message id. `GmailMessageRefResolver::resolve_message` returns it as `Result<Option<GmailMessageId>, LogError>` (mirroring JMAP's contract: `Ok(None)` = genuine absent mapping → deterministic; `Err` = store failure → transient).
- `LabelId(String)` — a Gmail label id. The only one this slice needs is the system label **`INBOX`** (a fixed, well-known id, not user-defined).

### 3.2 The Gmail mechanic (the neutrality divergence)
- `Action::Archive { message_ref }` → **remove** the `INBOX` label from the resolved message.
- `Action::Unarchive { message_ref }` → **add** the `INBOX` label to the resolved message.

No `MailboxRole` / `Placement` mailbox-move model (that was JMAP's terrain). Gmail's terrain is a label toggle on the single well-known `INBOX` label. This *is* the proof.

**Predicate fence — message-scoped, NOT thread/conversation.** `Action::Archive { message_ref }` means exactly "remove `INBOX` from the **resolved single message**." Gmail labels live on *messages*; a *thread*'s label list is the union over its messages, `threads.modify` is a distinct API surface, and a message added to a thread later does not inherit a prior thread-label operation. So archiving one message in a multi-message thread does **not** equal Gmail-UI conversation-archive, and this slice does **not** claim it does. Thread-vs-message archive UX, and special system-label states (`SPAM`/`TRASH`/`DRAFT`), are an explicit later read/UX decision — not an implied-solved property here. **A test asserts the toggle is surgical** (unrelated labels survive Archive/Unarchive — §5).

### 3.3 The transport seam
```rust
pub trait GmailTransport {
    /// Apply a label modification to one message (maps to users.messages.modify).
    /// `add` / `remove` are label ids. Err carries a normalized GmailError.
    fn modify_labels(
        &self,
        user: &GmailUserId,
        message: &GmailMessageId,
        add: &[LabelId],
        remove: &[LabelId],
    ) -> Result<(), GmailError>;
}
```
Single-message `modify` is the right call for this slice (each `Action` carries exactly one `message_ref`). The signature is `add`/`remove` slices so the live impl can back it with `batchModify` later without a seam change.

### 3.4 Provider idempotency (expected — live-slice proof obligation, reinforces ADR-P013)
Gmail `modify`/`batchModify` are **expected to be idempotent at the provider** — set-style label mutation: adding a label already present, or removing one that's absent, should be a no-op with no error. A crash-retry / lost-ack re-dispatch of an archive would then be provider-safe, reinforcing the engine's idempotency contract. **Caveat:** no *official* Google document was found that explicitly guarantees add-present/remove-absent = no-op success. So this is a **proof obligation on the live `aruna-gmail` slice** — assert the add-present/remove-absent no-error behavior over the wire, or normalize it — **not a settled provider guarantee.** The fake models it as a set (§5 archive-twice test) to lock the *design intent*; the fake cannot prove the real provider's behavior.

## 4. Error taxonomy (`classify_gmail_error -> FailureKind`)

The single home for Gmail's transient-vs-deterministic policy, mirroring `classify_jmap_error`. A normalized, wire-decoupled `GmailError` enum (so adopting a Gmail client at the live slice doesn't ripple), every layer mapping to exactly one variant:

| Gmail condition | Variant | `FailureKind` | Rationale |
|---|---|---|---|
| HTTP 429 / 403 `rateLimitExceeded` / `userRateLimitExceeded` | `RateLimit` | **Transient** | back off + retry |
| HTTP 5xx / `backendError` | `Backend(u16)` | **Transient** | server-side, lifts |
| timeout / connection reset | `Transport(..)` | **Transient** | below-semantics |
| 403 `insufficientPermissions` / `forbidden` | `Forbidden` | **Deterministic** | won't self-heal |
| 404 `notFound` | `NotFound` | **Deterministic** | id gone |
| 400 `invalidArgument` / `failedPrecondition` | `InvalidArgument` | **Deterministic** | malformed; identical retry fails |
| 401 unauthorized | `Unauthorized` | **Deterministic** (M0) | no refresh path in this slice; the OAuth slice reopens 401 as refresh-then-retry — named, like JMAP's note |
| any unrecognized | `Unknown` | **Deterministic** | fail closed |

Provider error text/ids are **never** surfaced — an id-free `GmailErrorCode` (fixed phrases, mirroring `JmapErrorCode`) builds the `ConnectorError`. Confinement by construction.

**Carry-forward residual — untested-by-construction.** HTTP **403 is ambiguous**: `rateLimitExceeded`/`userRateLimitExceeded` (→ `RateLimit`, **Transient**) and `insufficientPermissions`/`forbidden` (→ `Forbidden`, **Deterministic**) share the status code — distinguishing them needs the Gmail error-body `reason`/`domain`, parsed in the **wire→`GmailError` normalization layer this fake-first slice does not build**. The fake injects a `GmailError` *variant* directly, so the design's own named worst-mode (a transient 403 misclassified deterministic → a recoverable archive permanently dead-lettered) is **untested until the live `aruna-gmail` slice**, which owns that normalization and its RED tests. Named here so the live slice re-discharges it — not a silent gap.

## 5. Testing (TDD — RED→GREEN, mirror the jmap test suite)

A Gmail-shaped fake (one backend implementing `GmailTransport` + the resolvers, seeded with distinctive provider ids for the leak test). Tests, each written RED first:

- **Behavior:** archive removes `INBOX`; unarchive adds `INBOX`; archive-then-archive is an idempotent no-op success (the research-confirmed property).
- **Capability:** unsupported action fails safe + deterministic; capability map publicly queryable for preflight (ADR-P010).
- **Resolution misses:** account-unresolved → deterministic; message-unresolved (genuine absent) → deterministic; message-store **failure** → **transient** (the Option-swallow class fix carried from M0 — a locked/corrupt store is retryable, never a permanent dead-letter).
- **Taxonomy:** each row of §4 (rate-limit/backend/5xx transient; forbidden/notFound/invalidArgument/401/unknown deterministic).
- **Confinement:** no seeded provider id leaks into a surfaced error message; no provider id reaches the durable intent-log row.
- **End-to-end through the bus:** `bus.execute(archive)` → `Applied`, label removed; deterministic provider rejection → `Failed` (dead-letter); persistent transient rejection stays `Pending`, retried, dead-letters at `RETRY_CAP`.
- **Shape:** the modify request serializes to the documented `{addLabelIds, removeLabelIds}` subset (a JSON-shape conformance check, mirroring the `*/set` subset test).

**Gates:** `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings` + `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` all green (note the quoted RUSTDOCFLAGS footgun).

## 6. Out of scope (named, so a future session doesn't assume otherwise)
Live HTTP / `aruna-gmail` (Part III gated) · OAuth onboarding + token refresh · `history.list` delta sync + `historyId` cursor + `watch`/Pub/Sub push · `batchModify` multi-message batching · generic `Label{add,remove}` verb · move/trash/send (RED/BLACK — validation gate) · role-normalized collections beyond `INBOX`.

**Read-side placement / projection / divergence-correction for Gmail is OUT of scope.** This slice is the act-verb `Connector::apply` actuator ONLY — it builds no read model. The M0 read-side is JMAP-typed by construction: `Placement`/`ProviderPlacement` live *inside* `jmap.rs` (`jmap.rs:232`/`:282`) and `reconcile.rs`/`message_store.rs` consume them as a **two-mailbox** model that does not fit Gmail (where "archived" is the *absence* of the `INBOX` label, not membership in an Archive mailbox). A future "M0-parity for Gmail" session must **not** generalize the JMAP-coupled `Placement` mid-M1 — that is engine-adjacent ripple the scope fence exists to prevent; read-side generalization is its own later slice.

## 7. References
- `crates/aruna/src/jmap.rs` (the M0 connector this mirrors) + `crates/aruna/src/lib.rs` (`Connector`, `Command`, ADR-P013 lifecycle).
- ADR-P003 (MailSurfaceAdapter boundary), ADR-P004 (durable nouns / id confinement), ADR-P010 (capability gates), ADR-P013 (idempotency-decision gate), Part III (validation gate) — `docs/adr/`.
- Gmail API (research 2026-06-27): [`users.messages.modify`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify), [`batchModify`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/batchModify) (idempotent), [`history.list`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list) (later slice).

---

## Pre-review evidence (produce-phase check — discharged 2026-07-04)

> **Class:** design/spec for an **internal code change** — fake-first, **no network, no live credentials, no data movement** in-slice (§2 scope fence). Per the check's proportionality rule the security/data items are discharged as *deferred-by-construction*, not skipped: the connector is the seam that will **later** cross a real trust boundary, so Item 5 is discharged explicitly to prove the boundary is fenced out of this slice, not overlooked. Items **0** and **7** are always live. **This is a "understood," not an "approved"** — the closing doubt feeds Item 7.

**Item 0 — Requirement anchor.** *Claim:* this slice satisfies the M1 milestone's first, lowest-reversibility rung — YELLOW archive on Gmail — proving ADR-P003 contract-neutrality against a second provider terrain. *Source:* the milestone plan (M1 = "Gmail API connector"); `ADR-P010` at `docs/adr/:122` names *"archive on Gmail API is the canonical first write"* as the first YELLOW verb. *Falsification sentinel:* I'd know it failed if driving `Action::Archive` through Gmail required **any** edit to `crate::Command` / `classify` / the ADR-P013 truth-table in `lib.rs` — neutrality is only proven if the engine is untouched. *Cheapest alternative not taken:* a generic `Label{add,remove}` verb — rejected because reusing the *identical* `Archive`/`Unarchive` that drove JMAP is the stronger neutrality proof (a new verb would prove new plumbing, not neutrality). *Out-of-scope boundary:* no live HTTP, no OAuth, no send/trash (§6).

**Item 1 — Regulation / data movement.** *None declared.* (a) *Reason:* no PII, no regulated data, no persistence of message content — the fake is in-memory and seeded with synthetic ids; the durable intent-log stores Photon nouns only, never provider content (ADR-P004). (b) *Checked, reviewer-verifiable:* the slice adds no store/sink/log/export; the only durable write is the existing intent-log row, and Item 5's confinement test asserts no provider id reaches it. (c) *Reproducible search:* grep the slice for network/file/env sinks (`reqwest|std::fs|std::net|env::var`) → must be empty (no live transport in-slice). (d) *Counterfactual:* regulation would apply if this slice touched a **live** mailbox (real user content, GDPR/CCPA data-subject scope) — it does not, because the live path is Part-III-gated (`ADR:206`) and built in a later slice.

**Item 2 — Prior art (two channels).** *External:* Gmail REST `users.messages.modify` / `batchModify` (cited §7), status **confirmed current** (v1, live Google Workspace API, 2026-06-27); the archive-by-removing-`INBOX`-label mechanic and the provider-idempotency property (add-present/remove-absent = no-op) are from the official reference, adopted directly (§3.4). *Internal:* the M0 JMAP connector `crates/aruna/src/jmap.rs` is the mirror-of-record — `classify_jmap_error` (:155), the `AccountResolver`/`MessageRefResolver` traits (:261/:270), `JmapTransport` seam (:288), `CapabilityMap` (:361), `JmapErrorCode` id-confinement (:406). *Adopt or name the gap:* adopted wholesale; the one **deliberate divergence** is the mechanic itself (label-toggle vs mailbox-move, §3.2) — that divergence *is* the neutrality proof, not a gap. *Counter-evidence (what would have failed if I were wrong):* I checked that the shared seam is **only** `Connector`/`Command`/`ConnectorError`/`FailureKind`/`LogError` (`lib.rs:920/854/866`) and that the JMAP resolvers are provider-typed and connector-local — so a claim of "reuse the JMAP resolvers" would have failed; Gmail must define its own (§3, confirmed against `jmap.rs:261-288`).

**Item 3 — Footguns (by class).** *Concurrency:* none new — the engine serializes via `execute(&mut self)`; the connector `apply` is a pure actuator. *Partial-write / failure:* the highest-impact plausible mode is **mis-classifying a transient failure as deterministic**, which would dead-letter a recoverable archive permanently; structurally avoided by routing every layer through the single `classify_gmail_error` home (§4) with the *store-failure→transient* rule (§5) — the Option-swallow class M0 already paid for. *Most-likely mode:* a resolver returning `Ok(None)` (genuine absent id) conflated with `Err` (store failure); §3.1 pins the contract (`Ok(None)`=deterministic, `Err`=transient) mirroring JMAP, and §5 tests both. *Scale/operability:* N/A in-slice — single-message `modify`, no batching, no unbounded growth (batching deferred §6). *Technique-specific, not generic:* Gmail's `modify` idempotency (§3.4) means a crash-retry is provider-safe — the footgun would be *assuming* it isn't and adding a non-idempotent guard; avoided by the explicit idempotency test.

**Item 4 — Abuse / misuse.** *Not live in-slice (no external actor surface).* The connector has no live network or credential path; an actor cannot reach a real provider through it. *Counterfactual:* the abuse case (an authorized agent bulk-archiving to hide mail) becomes live only when the real transport + governance envelope land — that's an engine/`ActionEnvelope`-tier concern (reserved, "no fire drill", §2), not this connector's, and seams with Item 5 there, not here.

**Item 5 — Trust boundary (security-first).** *Boundary declared: NONE crossed in this slice — by construction.* (a) *Reason:* no network reachability, no credential, no identity, no external communication — the transport is an in-memory fake (§2, §5); the live `aruna-gmail` HTTP impl and OAuth are a **separate later slice gated by ADR Part III** (`ADR:206-218`: "real-provider destructive execution disabled until the gate passes"). (b) *Checked:* the `GmailTransport` trait (§3.3) is the *only* seam the live slice replaces; nothing in this slice constructs an HTTP client or reads a secret. (c) *Reproducible search:* the network/secret grep in Item 1(c). (d) *Counterfactual — the boundary this slice PREPARES:* provider-id confinement (ADR-P003/P004) — a Gmail message id / label id leaking above `apply` into a surfaced error or a durable log row **is** a boundary violation (it makes a provider handle durable identity). This IS crossed by the *code*, so it's tested: §5 confinement tests assert (i) no seeded provider id in any surfaced `ConnectorError` message, (ii) no provider id in the durable intent-log row — enforced structurally by the id-free `GmailErrorCode` (§4, mirroring `JmapErrorCode` at `jmap.rs:406`). *Named control:* OWASP ASVS V5 (output-encoding/confinement) + the project's ADR-P003 no-leak law. *Residual:* the real credential-destination-binding trust boundary (the JMAP live slice's `authed_method_url` / cross-authority class) does **not** exist here and must be re-discharged when `aruna-gmail` HTTP lands.

**Item 6 — Blast radius / gate-fit (four axes).** *6a Scope/slice:* one PR — a new `crates/aruna/src/gmail.rs` module + its fake + tests; zero engine edit, so no migration and no security-control-split. Invariant after the slice: the engine is byte-identical; only a new connector module is added. *6b Reversibility:* fully reversible — new module, no schema change, no data migration, no side-effects (in-memory fake). Rollback = revert the commit. *6c Surface/consumers:* adds a new public module surface (`GmailConnector`, `GmailTransport`, resolver traits); it does **not** change the shared `Connector`/`Command` seam, so no existing consumer contract shifts (verified: shared seam is `lib.rs:920` untouched). *6d Exposure:* if wrong/exploited in-slice — bounded to the fake; no real user, no real data, nothing reaches a provider (Part-III fence).

**Item 7 — Assumptions & open unknowns (NON-dischargeable — carried forward).**
1. **`INBOX` is a stable, well-known system label id** across all Gmail accounts (§3.1). **RESOLVED:** Gmail **system label IDs** (`INBOX`/`TRASH`/`SPAM`/`UNREAD`/…) are reserved and **locale-independent** — only user-label *names* (and system-label *display* names) localize, never the IDs. So no preflight `labels.list` is warranted in the fake slice; at most a cheap defensive assertion in the live slice. Unknown closed.
2. **Reusing `Action::{Archive,Unarchive}` unchanged is the right neutrality proof** vs. a generic `Label` verb (§2) — assumed; if review judges a generic verb is the truer M1 target, this re-scopes.
3. **The §4-vs-Part-III doc correction** (amend the master plan's "on a live Gmail account" to name the YELLOW/fake-first staging) is a **tracked doc fix, not yet applied** — assumption: Part III wins the authority ladder.
4. **What in here could still be the wrong call?** — The whole slice's value rests on "zero engine touch." If implementation reveals the label-toggle needs *any* engine accommodation, the neutrality thesis weakens and the slice should stop and re-review rather than bend the engine.

**Item 8 — Verification pointer.** The §5 TDD matrix (RED-first) is the evidence-it-works pointer: behavior (archive removes `INBOX` / unarchive adds it / idempotent no-op), taxonomy (every §4 row), confinement (no leak to error or log), resolution-miss classing, and end-to-end through the bus to `Applied`/`Failed`/`Pending`. Failure signal that blocks: any confinement or transient-classification test RED blocks the merge. Gates: `cargo test --workspace` + `clippy -D warnings` + `RUSTDOCFLAGS="-D warnings" cargo doc` (§5). This points at the loop's existing test gate — it is not a second gate.

> **Open doubt (not a clearance):** the design is a faithful mirror of a shipped connector, so the *mechanical* risk is low — but the load-bearing question is whether "reuse `Archive` unchanged over a label-toggle" is genuinely the strongest proof of ADR-P003 neutrality, or whether it proves something narrower than M1 intends. Attack that framing first.
