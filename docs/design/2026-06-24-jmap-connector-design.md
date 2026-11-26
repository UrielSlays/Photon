# Design — the JMAP provider connector (M0 provider slice, ADR-P010-gated)

**Date:** 2026-06-24 · **Status:** Implemented
**Slice:** `engine: JMAP archive/unarchive connector (behind the ADR-P010 gate, against a JMAP-shaped fake)`.
**Scope discipline:** the *first real provider connector* — protocol-faithful **archive / unarchive** translation (RFC 8620/8621), the **error-policy taxonomy** that the dead-letter slice explicitly deferred to "the real connector," provider-id confinement (ADR-P003/P004), and the per-connector capability map (ADR-P010) — **proven against a JMAP-shaped in-memory fake, NOT a live mailbox.** The live HTTP transport, OAuth/credential onboarding, and any real-provider destructive write stay deferred to a later slice that runs *after* the adversarial safety suite (build-order step 8) and through ADR-P010's validation gate (build-order step 9). This slice does not cross the gate; it builds the contract the gate will guard.

## Why this slice, why now (grounded at the byte)
- the milestone plan §M0: the engine spine landed against a **mock** connector; **"Remaining for M0: the real JMAP connector + end-to-end against a JMAP test account."** M0 = JMAP (Fastmail dev account **or a JMAP-shaped fake** — NOT Gmail; build-rule 6). The DoD names `*/set` shape-conformance (RFC 8620 `/set`), crash-recovery, divergence-correction, provider-id confinement.
- `ADR-P013` deferred-items block names the **error-policy taxonomy** ("which concrete provider errors are deterministic vs transient") as **"the connector's, deferred — documented, no parked red test"** (`2026-06-23-failed-dead-letter-design.md`). This slice is its home. It also unblocks (a) the 409 concurrency guard's prerequisite (real I/O) downstream.
- `ADR-P010`: each connector **publishes an explicit capability map**; unsupported ops **fail safe and visibly**; write verbs enabled per-provider/per-tier in reversibility order (YELLOW archive first); **real-provider destructive execution stays globally disabled until the validation gate passes.** This slice builds the capability map + the archive verb; it does **not** enable a live write.
- `ADR-P003/P004` (provider-id confinement): **no adapter-native handle** (JMAP Email id, Mailbox id, **accountId**) ever becomes durable identity, authority, or audit vocabulary above the connector boundary. The connector mints/maps Photon-local nouns privately.

## What exists before this slice (the seam with only mock impls)
`crates/aruna/src/lib.rs`:
- `pub trait Connector { fn apply(&self, command: &Command) -> Result<(), ConnectorError>; }` — the below-the-seam actuator (doc comment names "mock, IMAP, JMAP…"). **Synchronous.** No capability method yet (this slice adds one on `JmapConnector`, not the trait).
- `Command { idempotency_key, account, facet: Facet::Mail, action: Action::{Archive|Unarchive}{ message_ref: String }, envelope, compensates }`. `account` and `message_ref` are **Photon-local opaque Strings** — the engine treats them opaquely; `Action` carries only `message_ref` (no target mailbox).
- `ConnectorError { message: String, kind: FailureKind::{Transient|Deterministic} }`. **`message` is a `pub String` that crosses the seam** and the engine may log it — so confinement must cover error text. The dead-letter lifecycle already consumes `kind`: deterministic → dead-letter immediately; transient → retry budget (`RETRY_CAP=5`) then dead-letter.
- Mock connectors only — none classify real provider errors. This slice writes the first connector that *derives* `kind` from a real protocol's error model.

## The design

### 1. A transport seam *inside* the connector — protocol real now, network deferred cleanly
`Connector::apply` is synchronous; JMAP is async HTTP. Rather than drag tokio/reqwest into the engine crate, introduce one trait *below* `JmapConnector`:

```rust
/// One JMAP method-call round-trip. The ONLY thing the live-network slice replaces.
pub trait JmapTransport {
    fn request(&self, req: &JmapRequest) -> Result<JmapResponse, TransportError>;
}
```

- `JmapConnector<T: JmapTransport>` implements `Connector`. It owns **all** protocol logic: build the `Email/set` request, parse the response, derive `FailureKind`, resolve mailbox roles + account, confine provider ids.
- This slice ships **only** `FakeJmapTransport` — an in-memory JMAP-shaped server (mailboxes with `role`s, emails with `mailboxIds`, an account) — the master-plan-blessed "JMAP-shaped fake." The **live** `ReqwestJmapTransport` drops in behind the *same* trait in the later slice, gated by the validation gate + adversarial suite.
- **Gate-respecting cut:** ADR-P010's "real-provider destructive execution remains globally disabled until the gate passes" is honored *by construction* — there is no real transport in this slice to disable. **NB:** `JmapConnector` is the narrow `act`-verb `Connector::apply`, **not** the full ADR-P003 `MailSurfaceAdapter` (5 methods incl. perceive/attach) — reads are deferred.

### 2. Protocol translation — `Action` → JMAP `Email/set` (RFC 8621)
Archive is a **move between mailboxes** via the `mailboxIds` set property (RFC 8621 §4.1; an Email MUST belong to ≥1 Mailbox at all times). Using RFC 8620 §5.3 `PatchObject` (JSON-Pointer) for a **surgical** move that preserves other mailbox memberships / labels (JMAP emails can live in many mailboxes — full-replace `{archiveId:true}` would strip labels; the surgical patch is correct and idempotent under at-least-once retry):
- `Action::Archive { message_ref }` → `Email/set { accountId, update: { <emailId>: { "mailboxIds/<inboxId>": null, "mailboxIds/<archiveId>": true } } }`
- `Action::Unarchive { message_ref }` → the exact inverse — matches `Action::inverse()`'s symmetry (undo/compensation stays a clean mirror; inherited fence).

`<accountId>`, `<inboxId>`, `<archiveId>`, `<emailId>` are all resolved **below the seam** (see §4/§5) — never hard-coded, never surfaced.

### 3. The error-policy taxonomy (the heart of the slice — checked against RFC 8620/8621)
JMAP surfaces failure at four layers; one pure function `classify_jmap_error(&JmapError) -> FailureKind` owns the whole table (the single-home discipline ADR-P013 used for `classify`). **`classify_jmap_error` takes an internal, normalized error enum — NOT the wire types** — so adopting a JMAP client library later does not ripple into the taxonomy.

| Layer | Type | → FailureKind | Rationale (RFC byte) |
|---|---|---|---|
| **Request-level** (RFC 8620 §3.6.1, `urn:ietf:params:jmap:error:*`) | `limit` | `Transient` | a server limit (e.g. concurrency) that lifts |
| **Request-level** | `unknownCapability`, `notJSON`, `notRequest` | `Deterministic` | the request is structurally wrong |
| **Method-level** (RFC 8620 §3.6.2) | `serverUnavailable`, `rateLimit` | `Transient` | server explicitly says "later may succeed" |
| **Method-level** | **`serverFail`** | **`Deterministic`** | RFC: no state change, **"expected to fail again"**; admin action likely |
| **Method-level** | **`serverPartialFail`** | **`Deterministic`** (resync-required) | RFC: partial change, client **MUST resync** — blind retry is wrong *(resync reason tracked, deferred to evidence stream)* |
| **Method-level** | **unknown / unrecognized type** | **`Deterministic`** | RFC 8620: client **MUST treat an unknown error type as `serverFail`** *(the RFC MUST is dispositive)* |
| **Method-level** | `invalidArguments`, `invalidResultReference`, `unknownMethod`, `accountNotFound`, `accountReadOnly`, `accountNotSupportedByMethod`, `forbidden` | `Deterministic` | request/account structurally wrong |
| **Method-level** | `stateMismatch` (only if `ifInState` is ever used — not in M0) | `Deterministic` (refetch/rebase) | RFC: requires re-fetch, not generic retry — named so the optimistic-concurrency slice reopens it |
| **SetError** (RFC 8620 §5.3 + RFC 8621) | `rateLimit` | `Transient` | rate limit lifts |
| **SetError** | `notFound`, `forbidden`, `invalidPatch`, `invalidProperties`, `tooLarge`, `singleton`, `willDestroy`, `overQuota`, RFC 8621 `tooManyMailboxes`/`mailboxCounts` | `Deterministic` | the specific mutation is invalid/forbidden (overQuota: judgment, but a move-not-grow op makes it operator-worthy — Q2) |
| **SetError** | unknown / unrecognized type | `Deterministic` (fail-closed) | no RFC retry warrant → fail closed |
| **Transport** (HTTP/TCP) | timeout, conn reset, 429, 500/502/503/504 | `Transient` | textbook backoff-and-retry |
| **Transport** (HTTP) | 400, 404, 422 | `Deterministic` | shape/target wrong, no self-heal |
| **Transport** (HTTP) | **401/403** | `Deterministic` *(conditional)* | M0 has no auth-refresh path so it collapses to deterministic; **named conditional-on-no-auth-refresh** — the OAuth slice reopens 401 as a third "refresh-then-retry" path the binary kind can't yet express |

The binary `{Transient, Deterministic}` is the seam's vocabulary today; the 401-refresh and serverPartialFail-resync cases are **named** as future third paths, not silently collapsed.

### 4. Provider-id confinement (ADR-P003/P004) — airtight **by construction**, not by scrubbing
- **Three provider id classes stay below the seam:** JMAP `Email` ids, `Mailbox` ids, **and `accountId`**. `Command.account` is Photon-local; a private **account resolver** maps it to the JMAP `accountId` below the seam — `accountId` never appears above it.
- **Confinement by construction:** `ConnectorError` is built from a **structured, id-free error code** (a new connector-side error enum) as the *primary* signal; the public `message` is a sanitized, id-free string. The connector **never** formats a raw JMAP response / `Debug` output into `message`. String-scrubbing + an asserted test are **belt-and-suspenders**, not the primary defense. RFC note: SetError `description` is a debug string, not for end users — never surface it raw.
- Confinement tests seed **account + mailbox + email** ids and assert none appear in any surfaced `ConnectorError`, `Command`, or intent-log row.

### 5. Resolution seams + absent-target completeness (the load-bearing RFC gap)
RFC 8621 §2 is explicit: **an account is not required to have Mailboxes with any particular role.** So every below-seam resolution can come up empty, and each MUST be defined:
- **account resolver** (Photon account → JMAP `accountId`): a miss → `Deterministic`, id-free.
- **role→id** (archive / inbox): a missing role mailbox → `Deterministic`, id-free.
- **message_ref→Email-id** (the `MessageRefResolver` seam; fake-seeded in M0, the read-side message store plugs in later): a miss → `Deterministic`, id-free.

The fake + acceptance suite **exercise** the absent-account, absent-role, and resolver-miss cases — archive against a role-less or unknown-message account is defined behavior, not a panic.

### 6. `*/set` shape-conformance (M0 DoD) — narrowed back-reference claim
The emitted `Email/set` request is a clean **subset** of the JMAP `/set` shape (single-account, single-update, idempotent). A conformance test asserts it is a valid `/set` subset so batch attaches later without a transplant. **Back-reference wording narrowed:** JMAP result references substitute whole **argument values**, not computed **object-key fragments** inside a `PatchObject` — so a `Mailbox/query → Email/set` result-ref cannot supply the dynamic `mailboxIds/<id>` patch *key*. The request is **not** claimed "back-reference-ready" for the patch keys; full back-ref batching is **structure/defer** (Q7) and belongs to the later send/batch increment.

### 7. Capability map (ADR-P010)
`JmapConnector::capabilities() -> &CapabilityMap` declares per-verb support (`archive`/`unarchive` = true; `label`/`trash`/`send`/… = false). `apply()` self-checks the map first and returns a **Deterministic** error for an unsupported verb — "fail safe and visibly." The connector self-check is **necessary, not sufficient**, and is kept **distinct** from the *global* "real destructive execution disabled until the validation gate" (a property of the live transport, not built here) — defense-in-depth layers, not substitutes. No bus-level enforcement is claimed until the trait/API grows that surface.

## Dependency posture
Add `serde` + `serde_json` and model `Email/set` request/response as **typed minimal structs** — **not** hand-rolled JSON strings. Keep the engine crate otherwise lean (no tokio/HTTP in this slice). `stalwartlabs/jmap-client` is **v0.4.x (async *and* blocking)** — the earlier "0.3.2 async-first" was stale; re-evaluate adopting it (as an adapter behind `JmapTransport`) at the **live-transport slice**, where async HTTP already arrives. Hand-roll the narrow M0 subset now on scope-discipline grounds (proving the contract + fake), not on stale-library grounds.

## Resolved design questions
- **Q1** transport-seam-now / fake-only — **YES**: gate-respecting, engine stays sync + light.
- **Q2** overQuota → **Deterministic**: operator-worthy for a move op; low cost if wrong (operator re-drive).
- **Q3** unknown error — **RESOLVED to Deterministic** for method-level (RFC 8620 MUST = `serverFail`); transient-with-cap reserved for genuinely-transient classes only.
- **Q4** surgical JSON-Pointer patch — **YES**.
- **Q5** `MessageRefResolver` seam — **YES** + account resolver + defined miss behavior (§5).
- **Q6** dependency posture — **typed minimal serde** now; defer jmap-client to the live-transport slice.
- **Q7** back-reference batching — **structure/defer**; narrow the wording (§6).
- **Q8** capability gate — **connector self-check** (kept distinct from the global gate).
- **Q9** error confinement — **structured id-free code by construction** + sanitized message (not scrub-only).

## Fences (do NOT cross in this slice)
- **No live network / real HTTP transport** → no real-provider destructive write (ADR-P010 global disable honored by construction). Live transport = a later slice, after the adversarial suite (build-order 8) + through the validation gate (build-order 9).
- **No async runtime in the engine crate.** `JmapTransport` is synchronous.
- **No read side / message store, no OAuth / credential storage.** `MessageRefResolver` + account resolver are fake-seeded; onboarding + keyring/DPAPI deferred.
- **No new `ActionEnvelope` behavior** (stays reserved); **inverse-is-a-clean-mirror** unchanged.
- **Error-policy taxonomy is IN scope** — but only for archive/unarchive; other verbs are `false` in the capability map.

## Acceptance / proof (planned, TDD red→green against `FakeJmapTransport`)
- `archive` emits the correct surgical `Email/set` patch; the fake reflects inbox→archive; `unarchive` is the exact inverse.
- `classify_jmap_error` table (corrected): `serverFail`/`serverPartialFail`/unknown-method/`notFound`/`forbidden`/`invalidPatch`/`invalidProperties`/`overQuota`/`tooManyMailboxes`/HTTP-4xx → Deterministic; `serverUnavailable`/`rateLimit`/`limit`/HTTP-429/HTTP-5xx/timeout → Transient.
- **Resolution completeness:** absent-account, absent-role-mailbox, and message_ref-miss each → Deterministic + id-free, exercised in the fake.
- **Confinement:** no seeded account/mailbox/email id appears in any surfaced `ConnectorError`/`Command`/intent-log row; error built from a structured id-free code.
- **Capability map:** an unsupported verb fails safe + visibly (Deterministic).
- **`*/set` conformance:** emitted request is a valid `/set` subset.
- **End-to-end through the bus:** `CommandBus::new(log, JmapConnector::new(fake, resolvers))` archives a message; a fake-injected **deterministic** failure dead-letters via the dead-letter lifecycle; a **transient** failure charges the retry budget then dead-letters at the cap — proving the taxonomy drives the existing lifecycle.
- `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo doc -D warnings` all clean.

## Review fixes (design stage)
Design review confirmed the slice stays **behind the ADR-P010 gate by construction** and the architecture cut is sound; the fixes harden a sound design. Classes of fix, applied above:
- **(A) JMAP error taxonomy correctness**: `serverFail`/`serverPartialFail`/unknown-method are **not** transient (RFC 8620); added request-level problem-details, `stateMismatch`, `limit`, RFC 8621 mail SetErrors (`tooManyMailboxes`); 401 named conditional-on-no-auth-refresh. **Resolved on the RFC text:** unknown-method → Deterministic (RFC 8620 MUST-treat-as-`serverFail`); a transient-cap heuristic is superseded by the explicit RFC clause.
- **(B) Confinement by construction**: structured id-free error code as primary, sanitized message, never raw `Debug`/JMAP-response text; `Command.account` stays Photon-local via a private account resolver; tests seed account+mailbox+email ids.
- **(C) Resolution completeness**: absent account/role/message resolutions → Deterministic id-free, exercised in the fake.
- **(D) Dependency/version freshness + posture**: jmap-client is v0.4.x async+blocking (not 0.3.2); use **typed minimal serde**, not hand-rolled JSON strings; defer the library to the live-transport slice.
- **(E) Back-reference overclaim**: result refs substitute argument values, not patch-key fragments — narrow §6, Q7 = structure/defer.
- **(F) Capability map wording**: publish on `JmapConnector`, self-check distinct from the global destructive-disable gate, no bus-level overclaim.
- Forward-compat: `classify_jmap_error` consumes an internal normalized error enum, decoupled from wire types.

## Review fixes (code stage) — the built slice
Code review confirmed the taxonomy is RFC-mandated, confinement is airtight by two independent guarantees, and the gate is airtight. Changes:
- **Capability publication**: `CapabilityMap::supports` + `archive()`/`unarchive()` are now `pub` — the ADR-P010 map is preflight-queryable, not opaque.
- **Transient-lifecycle proof**: new e2e bus test — a persistent transient JMAP failure stays `Pending`, is retried, and dead-letters to `Failed` at `RETRY_CAP` (the taxonomy drives the dead-letter lifecycle, not just the deterministic path).
- **`limit` taxonomy split**: RFC 8620 `limit` is no longer all-Transient — only `maxConcurrentRequests` lifts on retry; `maxSizeRequest`/`maxCallsInRequest`/unknown are fixed-shape → Deterministic (a `RequestLimit` enum).
- **Log-boundary confinement test**: a successful archive against a provider holding distinctive ids stores only the Photon-local command in the durable row — confinement proven at the SoR, not just the error path.
- **Tracked-forward (named, not built):** Photon-local newtypes at the `Command` boundary (engine-wide type-safety hardening; `Command.account`/`message_ref` are already Photon-local by contract, so this is defense-in-depth for a later slice).
- Final local state: **79 tests / 0 ignored, clippy + `cargo doc -D warnings` clean.**

## References
- RFC 8620 (JMAP core: `/set`, `PatchObject` §5.3, request/method/SetError types §3.6/§5.3) — https://www.rfc-editor.org/rfc/rfc8620.html
- RFC 8621 (JMAP for Mail: `Email/set`, `mailboxIds`, Mailbox `role`, mail SetErrors) — https://www.rfc-editor.org/rfc/rfc8621.html
- IANA JMAP registry / IMAP Mailbox Name Attributes (mailbox `role`s) — https://www.iana.org/assignments/jmap/jmap.xhtml · https://www.iana.org/assignments/imap-mailbox-name-attributes/
- `stalwartlabs/jmap-client` (Rust JMAP client, v0.4.x, async+blocking, Apache-2.0/MIT) — https://github.com/stalwartlabs/jmap-client
- DLQ / backoff norms (transient→retry-with-cap+jitter; deterministic→immediate DLQ): AWS SQS DLQ — https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html · AWS timeouts/retries/backoff-with-jitter — https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/ · Google Pub/Sub dead-letter — https://docs.cloud.google.com/pubsub/docs/dead-letter-topics
- Photon: the milestone plan §M0; `docs/adr/` ADR-P003/P004, ADR-P010, ADR-P013; dead-letter design `docs/design/2026-06-23-failed-dead-letter-design.md`.
