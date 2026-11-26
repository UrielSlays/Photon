# Design — the live JMAP transport (M0 DoD: end-to-end over the wire)

**Date:** 2026-06-24 · **Status:** Implemented. The "Review fixes" section is the binding build contract.
**Slice:** `feat/m0-jmap-live-transport` off `main` @ `e3cf44c`. PR title (planned): `engine(jmap): live HTTP JmapTransport against a self-hosted JMAP server (M0 over-the-wire proof)`.
**Scope discipline:** swap the in-memory `FakeJmapTransport` for a **real HTTP `JmapTransport`** that speaks JMAP to a **self-hosted Stalwart** server, proving `Action::{Archive,Unarchive}` end-to-end **over the wire**. The connector, taxonomy, confinement, and capability map (see `2026-06-24-jmap-connector-design.md`) are unchanged — this slice only fills the one seam built for it. **This is a test-server proof, NOT enabling real-user-mailbox writes** — ADR-P010 Part III keeps real-provider destructive execution gated behind the adversarial suite (build-order step 8 → step 9); this slice does not cross that gate.

## Why this slice, why now (grounded at the byte)
- the milestone plan §M0 DoD: **"works end-to-end against a JMAP test account."** The connector design proved it against a *fake*; this is the *over-the-wire* proof the DoD requires.
- The connector's `JmapTransport` trait (`crates/aruna/src/jmap.rs`) was built as the single seam the live slice replaces — its doc comment literally names "a `reqwest`/`jmap-client`-backed impl drops in here behind the validation gate."
- Provider reality (verified 2026-06-24): JMAP is spoken by **Fastmail** + self-hosted **Stalwart / Apache James / Cyrus**; **Gmail/Outlook do NOT speak JMAP** (they get Gmail-API / Graph connectors in M1/M2). With no Fastmail account available, the test target is a **self-hosted Stalwart** server — the reference self-hosted JMAP stack (full RFC 8621), local, disposable, no paid account, no real user data.

## What exists before this slice
`crates/aruna/src/jmap.rs` (from the connector slice):
- `pub trait JmapTransport { fn mailbox_id_for_role(&self, &AccountId, MailboxRole) -> Result<Option<MailboxId>, JmapError>; fn email_set(&self, &EmailSetRequest) -> Result<(), JmapError>; }` — **synchronous**.
- `JmapConnector<T, A, M>` implements `Connector` over that trait + the `AccountResolver`/`MessageRefResolver` seams.
- `classify_jmap_error(&JmapError) -> FailureKind` — the RFC 8620/8621 taxonomy (the policy is done; this slice only needs to *produce* the right `JmapError` variants from real wire failures).
- `FakeJmapTransport` (test-only) — the in-memory server we are replacing for the live path.
- The engine crate is deliberately lean: `rusqlite` + `serde`/`serde_json` only, **"no async runtime"** (Cargo.toml comment + ADR/master-plan build-rule).

## The design

### 1. Dependency isolation — keep `aruna` lean and sync (the load-bearing decision)
A real JMAP client (`jmap-client` blocking → `reqwest` blocking → a TLS stack) is a heavy dependency the engine crate must not carry; `aruna` is the sync system-of-record and explicitly has "no async runtime." **Proposal: a separate workspace crate** (e.g. `crates/aruna-jmap`) that depends on `aruna` (for the `JmapTransport` trait + `JmapError` types) and on `jmap-client`, exposing `HttpJmapTransport`. The engine crate never compiles HTTP/TLS; the boundary is a hard one. (Alternative: a `jmap-live` cargo *feature* on `aruna` — lighter to set up, but it leaks the HTTP dep tree into the engine crate's feature matrix and risks accidental default-on. See Q1.)

### 2. The client + the sync↔async bridge
Use **`stalwartlabs/jmap-client` with the `blocking` feature** (v0.4.x, Apache-2.0/MIT). The `blocking` API is the bridge: synchronous calls satisfy our sync `JmapTransport` with **no tokio in `aruna`** and no hand-rolled runtime. (This is exactly the library the connector slice deferred "to the live-transport slice".) Alternative: hand-rolled `reqwest::blocking` + serde structs (more control over error granularity — see Q5 — but re-implements a maintained RFC-complete client). See Q2.

### 3. `HttpJmapTransport` — the two seam methods over the wire
- **Session discovery:** on construct/connect, fetch the JMAP **Session resource** (`.well-known/jmap`) → the `apiUrl` + the primary `accountId`. Cache it.
- **`mailbox_id_for_role`:** `Mailbox/query`/`Mailbox/get` filtering on `role` (`inbox`/`archive`) → the mailbox id (or `Ok(None)` if the account has no such role mailbox — RFC 8621 §2, already handled by the connector).
- **`email_set`:** issue the `Email/set` `update` with the surgical `mailboxIds/<id>` PatchObject the connector already builds; map the result (`updated` vs `notUpdated[id] = SetError`) to `Ok(())` / `Err(JmapError::Set(..))`.
- **Provider-id confinement holds:** real JMAP `accountId`/`Mailbox`/`Email` ids live entirely inside `HttpJmapTransport` (below the seam); nothing changes above it.

### 4. Error mapping fidelity (a real risk — flag for review)
Our `JmapError` taxonomy is fine-grained (request/method/SetError/transport layers, specific types). `jmap-client` may **collapse** failures into a coarser error enum; if so, the live transport can only produce the granularity the library exposes, and some taxonomy distinctions (e.g. `serverFail` vs `serverPartialFail`, specific SetError types) could be lossy at the boundary. **Plan:** map what the library exposes faithfully; where it collapses, map conservatively (unknown/ambiguous → the fail-closed/deterministic side per the taxonomy's own unknown-handling), and **document any lossy edge**. If the library is too coarse, that is the argument for hand-rolled reqwest (Q2/Q5).

### 5. Auth + secrets
JMAP auth = **bearer token** (preferred) or basic. For the M0 Stalwart proof, credentials come from **environment variables** (`PHOTON_JMAP_URL`, `PHOTON_JMAP_TOKEN`/user+pass) — **never** committed, **never** logged, **never** in SQLite. Real **keyring/DPAPI** credential storage (ADR-P010) is **deferred to the OAuth/onboarding slice**; this slice uses env-only test creds against a disposable server.

### 6. Test strategy — hermetic suite stays green; live tests are opt-in
The 79 existing tests are hermetic (in-memory fake) and **must stay green with no server running**. The live test must NOT run in a plain `cargo test`:
- **Gate the live integration test** behind an env var (skip-if-unset, e.g. `PHOTON_JMAP_IT=1` + the URL/creds) so default/CI runs stay hermetic.
- **The live test:** stand up Stalwart (Docker), seed a test account + one message in the Inbox, run `JmapConnector::new(HttpJmapTransport, …).apply(archive)` → assert via a fresh `Mailbox`/`Email` query that the message moved Inbox→Archive; then `unarchive` → assert it moved back. Round-trips the real protocol.
- **Stalwart fixture:** a documented `docker compose` + a small seed script (account + message) checked in under the crate's `tests/` or `docs/`, plus a runbook so anyone can reproduce. **Feasibility check before build: confirm Docker is available in this environment**; if not, fall back to the Stalwart native binary or note the blocker.

### 7. ADR-P010 gate honesty (reaffirmed)
This slice proves the **wire protocol against a disposable test server**. It does **not** enable real-user-mailbox destructive execution — that stays behind the Part III validation gate (adversarial suite green + recovery/kill-mid-batch/injection drills + dogfood mileage; build-order step 8 → step 9). The capability map + the global gate remain as-is; we are filling the transport, not opening the door.

## Slice boundary (keep the PR doable — canon: slice small)
**This slice (Slice 1):** the live `HttpJmapTransport` + archive/unarchive **over the wire** against local Stalwart, opt-in integration test + Stalwart runbook, dependency-isolated. The "it moves real mail over the wire" proof.
**Deferred to a follow-on (Slice 2):** the remaining M0 DoD **drills** — crash-recovery (kill mid-flight → restart → reconcile against the live server), divergence-correction (a wrong optimistic projection corrected by provider truth), ambiguous-outcome/duplicate-submit (lost-ack idempotent recovery), and the floor perf gates. These exercise engine+connector+server together and deserve their own focused slice. (The read-side message store that backs a *real* `MessageRefResolver` is also still its own slice; Slice 1 may seed the resolver from the live server's own ids for the test.)

## Open questions
1. **Crate isolation vs feature gate** — separate `crates/aruna-jmap` (hard boundary; engine never compiles HTTP) vs a `jmap-live` feature on `aruna`? *(rec: separate crate.)*
2. **`jmap-client` (blocking) vs hand-rolled `reqwest::blocking`** — adopt the maintained RFC-complete client, or hand-roll for error-granularity control? *(rec: jmap-client blocking; revisit only if Q5 shows it's too coarse.)*
3. **Slice boundary** — is "live transport + archive/unarchive over the wire" the right Slice-1 cut, with the DoD drills as Slice 2? *(rec: yes.)*
4. **Live-test gating** — env-var opt-in integration test + hermetic default suite; Stalwart via committed docker-compose + seed script? *(rec: yes.)*
5. **Error-mapping fidelity** — is `jmap-client`'s error surface granular enough to honor the `JmapError` taxonomy, or do we lose distinctions (→ argues for hand-rolled)? **
6. **Session/account model** — `HttpJmapTransport` owns Session discovery (apiUrl + primary accountId); `AccountResolver` maps the Photon account → that JMAP account; single-account for M0? *(rec: yes.)*
7. **Auth/secrets** — env-only test creds now, keyring/DPAPI deferred to onboarding? *(rec: yes.)*
8. **Feasibility** — can we run Stalwart (Docker) in this environment as the test fixture, and is committing a docker-compose fixture the right reproducibility story? *(verify before build.)*

## Fences (do NOT cross in this slice)
- **No real-user-mailbox enablement** — test server only; the Part III gate stays shut.
- **No async runtime / HTTP deps in `aruna`** — isolated to the new crate/feature; the engine stays sync + lean.
- **No keyring/DPAPI, no OAuth onboarding** — env-only test creds; deferred.
- **No read-side message store** — Slice 1 seeds resolver ids from the live server for the test; the store is its own slice.
- **No DoD drills** — crash-recovery/divergence/perf are Slice 2.
- **Connector logic unchanged** — taxonomy, confinement, capability map, the patch builder all stay as built in the connector slice.

## Acceptance / proof (planned)
- Hermetic suite: still **79 passing, 0 ignored** with no server (live test skipped when env unset).
- Live (env-gated, against local Stalwart): archive moves a seeded Inbox message to Archive over the wire; unarchive is the inverse; both verified by a fresh query.
- Error mapping: at least one real failure (e.g. archive a non-existent email id → `notFound` SetError → `Deterministic`) asserted over the wire.
- Confinement preserved: no real JMAP id surfaces above the seam.
- `cargo test` / `cargo clippy --all-targets -D warnings` / `cargo doc -D warnings` clean across the workspace; the new crate too.
- A reproducible **Stalwart runbook** (docker-compose + seed) committed so CI and reviewers can rerun.

## Review fixes (the binding build contract)
Design review checked the live `jmap-client` source. No misread of the seam/taxonomy/ADR-P010/lean-sync posture was found. Binding fixes for the build:

- **(A) Error-mapping fidelity contract.** `jmap-client` is adopted **only on the typed/raw response path.** The adapter MUST NOT use the convenience helpers (`SetResponse::updated()` / unwrap-style) that collapse `notUpdated[id]` into a stringified crate error via `to_string_error()` — those destroy the taxonomy. Map the raw typed `ProblemDetails` / `MethodErrorType` / `SetErrorType` → our `JmapError` variants. **If the raw typed `notUpdated[id]` cannot be reached with type intact, hand-roll `reqwest::blocking`** for the tiny M0 surface (Session, Mailbox/query|get, Email/set) instead. Acceptance gains a **taxonomy-fidelity test matrix**: at least `notFound`, `rateLimit`, `serverFail`, `serverPartialFail` mapped correctly (live fixture or synthetic wire).
- **(B) Unknown-extension handling.** `MethodErrorType`/`SetErrorType` may lack an `Other(String)` fallback. Unknown/extension method+set error types MUST route to Photon's deterministic `Unknown` buckets (RFC: unknown → treat as `serverFail`) **with zero provider text/id leakage** — synthetic-wire tests required. If the library can't represent unknowns without leaking, that is a further hand-roll trigger.
- **(C) Dependency isolation = a separate `crates/aruna-jmap` crate.** A feature gate is rejected: Cargo feature unification is additive across the workspace, so a `jmap-live` feature could compile reqwest/TLS/tokio into `aruna` and break "no async runtime." Only a separate crate makes the lean/sync invariant compile-enforced.
- **(D) ADR-P010 gate — two complementary layers.** (i) **Default-closed runtime gate by construction**: destructive execution refuses any non-validated provider unless an explicit gate flag is flipped; the live test flips it ONLY for the disposable localhost fixture — so "globally disabled until the gate passes" stays a guarantee now that a real write path exists (this is the wiring the connector slice deferred to this slice). (ii) **Operational guardrails**: strict naming ("test-server / self-hosted fixture transport"), live tests opt-in / default suite hermetic, a **local/test-server URL+account allowlist** (no production-looking host without a separate explicit override), env creds for **disposable fixture accounts only** (never Fastmail/prod), and **never print env credential values**.
- **(E) Confinement scope extended.** The by-construction promise covers not just ids but **raw `ProblemDetails.detail`, `SetError.description`, and any `Display`/`Debug` output** — none may cross into `ConnectorError.message`, the command surface, the intent log, test-failure messages, or normal logs. Mapping is structured + id-free before it leaves `HttpJmapTransport`.
- **(F) M0 DoD wording.** State precisely: Slice 1 satisfies the *"JMAP test account, over the wire"* PART of the M0 DoD; crash-recovery, divergence-correction, ambiguous-outcome/duplicate-submit, and the floor perf gates remain **Slice 2** (also M0). "DoD met" after Slice 1 must not obscure the owed resilience proofs.
- **(G) Minor.** Pin the Stalwart Docker image to a fixed tag (never `:latest`) for a reproducible fixture. Absent/multiple primary account in Session discovery → fail **deterministic + id-free**, never silently pick the wrong one. Docker preflight + fallback note before code (all).

**Open-question resolutions (converged):** Q1 separate crate; Q2/Q5 `jmap-client` typed-path-or-hand-roll (fidelity is the deciding test); Q3 slice boundary good (with the F wording fix); Q4 env-gated live + committed pinned fixture; Q6 single-account M0 with deterministic absent/multi handling; Q7 env-only disposable creds, keyring/DPAPI deferred; Q8 Docker feasibility confirmed (verified locally: Docker 29.5.3 + compose v5.1.4; map Stalwart off the searxng-held :8080 → a free host port).

## References
- RFC 8620 / RFC 8621 (JMAP core + mail) — https://www.rfc-editor.org/rfc/rfc8620.html · https://www.rfc-editor.org/rfc/rfc8621.html
- `stalwartlabs/jmap-client` (Rust, `blocking` feature, v0.4.x) — https://github.com/stalwartlabs/jmap-client · https://docs.rs/jmap-client
- Stalwart mail server (self-hosted JMAP, Docker) — https://stalw.art/docs/install/platform/docker/ · https://github.com/stalwartlabs/stalwart
- Photon: the M0 milestone definition of done and build rules; `docs/adr/` ADR-P003/P004 (confinement), ADR-P010 (capability gates + Part III validation gate); connector design `docs/design/2026-06-24-jmap-connector-design.md` + `crates/aruna/src/jmap.rs`.
