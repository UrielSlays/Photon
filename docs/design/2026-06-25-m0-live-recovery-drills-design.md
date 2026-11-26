# Design — M0 live-transport recovery & idempotency drills (Slice 2a)

**Date:** 2026-06-25 · **Status:** Implemented
**Slice:** `feat/m0-live-recovery-drills` off `main` @ `983911f`. PR title (planned): `engine(jmap): prove crash-recovery + ambiguous-outcome/lost-ack end-to-end over live JMAP (M0 DoD §1, §3, §4)`.
**Scope discipline:** prove, end-to-end against a real Stalwart JMAP server, the M0 DoD property classes that need **only the engine + the live transport** — crash-recovery (DoD §1) and ambiguous-outcome / lost-ack (DoD §3). No new production subsystem; no read-side projection; no UI. This is a **proving slice**: it adds drills (and the minimal test-only fault seam they need), not product surface.

**Already done, not in this slice:** DoD §4 (`*/set` shape-conformance) is already proven on `main` by `email_set_request_is_a_valid_set_subset` (`crates/aruna/src/jmap.rs:885`) — it serializes the connector's `EmailSetRequest` and asserts the `{accountId, update: {<id>: {"mailboxIds/<archive>": true, "mailboxIds/<inbox>": null}}}` subset shape. We **cite** it as the §4 evidence; we do **not** re-implement it (an earlier draft proposed folding a §4 check in — the bytes show it exists, so YAGNI).

## Why this slice, why now (grounded at the byte)
- the milestone plan — the M0 DoD demands the slice "proves the properties that justify the milestone, not just the happy path": **crash-recovery** ("kill mid-flight → restart → reconcile"), **ambiguous-outcome / duplicate-submit** ("provider effect succeeds but the ack is lost before reconcile → at-least-once dispatch + idempotent recovery"), and **`*/set` shape-conformance**.
- The earlier live JMAP test (`tests/live_jmap.rs`) proved the *happy path* over the wire (archive/unarchive + `notFound` fidelity vs Stalwart v0.16.10). It did **not** prove recovery under a crash, nor idempotent re-dispatch after a lost ack. Those are the unproven DoD classes this slice closes.
- The machinery already exists and is currently proven **only against the mock**: `CommandBus::recover()` (`crates/aruna/src/lib.rs:1248`) with a tested crash-recovery sweep, and `SqliteIntentLog::open(path)` (`lib.rs:310`) which already round-trips across reopen (`lib.rs:1494` `sqlite_intent_log_persists_an_intent_across_reopen`). This slice exercises that same machinery against **real provider I/O**, which is the DoD's whole point.

## What exists before this slice
- `crates/aruna/src/lib.rs`: `SqliteIntentLog` (file-backed, survives reopen), `CommandBus<L: IntentLog, C: Connector>` with `execute()` / `undo()` / `recover()`, the ADR-P013 idempotency-decision gate (`classify` → `Decision`), the dead-letter lifecycle.
- `crates/aruna/src/jmap.rs`: `JmapConnector<T, A, M>` over the `JmapTransport` + `AccountResolver` + `MessageRefResolver` seams.
- `crates/aruna-jmap/src/transport.rs`: `HttpJmapTransport` (real `reqwest::blocking` behind an `HttpClient` seam), the ADR-P010 default-closed `DestructiveWriteGate`, Stalwart fixture under `crates/aruna-jmap/tests/fixtures/stalwart/`, and `tests/live_jmap.rs` (env-gated `PHOTON_JMAP_IT=1`).
- 148 hermetic tests green on `main` (80 `aruna` + 66 `aruna-jmap` + 2 live) + clippy + `cargo doc -D warnings`.

## The properties under test (the standards basis)
- **The connector emits a surgical JMAP `Email/set` PatchObject, and each op is idempotent (RFC 8620 §5.3 PatchObject / RFC 8621 §4.6 `Email/set`).** The connector's `EmailSetRequest::move_mailbox` builds `update: {<emailId>: {"mailboxIds/<from>": null, "mailboxIds/<to>": true}}` (`crates/aruna/src/jmap.rs:262-274`) — a partial patch, **not** an absolute `mailboxIds` replace. It is idempotent because **each pointer op is individually idempotent**: `"mailboxIds/<to>": true` on a message already in `<to>` is a no-op; `"mailboxIds/<from>": null` on a message already absent from `<from>` is a no-op. So re-applying the same move patch to an already-moved message changes nothing. *(Confirmed against the byte at jmap.rs:262-274; RFC 8620 PatchObject semantics.)*
- **The engine's idempotency-key contract (ADR-P013)** makes `recover()` re-dispatch the **same logical command** → the connector rebuilds the **same** move patch → idempotent no-op on retry. The drill proves this empirically against the real server, not just the fake.
- **Crash-injection canon** (web, 2026-06-25): inject crashes between "do work" and "save record"; validate the post-recovery state against provider truth. Our two injection points (before the provider effect; after the effect, before the status write) are exactly the canonical boundaries.

## The design

### 1. The crash model — drop-and-reopen at the persistence boundary (the honest sim)
A "crash" is simulated by destroying all in-memory engine state and rebuilding **only** from the durable SQLite file:
1. Build the real stack: `SqliteIntentLog::open(<tempfile>)` + `HttpJmapTransport` → `JmapConnector` against the Stalwart fixture.
2. Drive a mutation to (or past) the chosen injection point.
3. **Drop the `CommandBus`** (process-death analog — the only surviving state is the SQLite file).
4. **Reopen** `SqliteIntentLog::open(same path)`, rebuild a fresh `CommandBus` over a fresh `HttpJmapTransport`, call **`recover()`**.
5. Assert the **provider truth** (a fresh JMAP `Email/get`/`Mailbox/query` read) **and** the durable intent status.

This is honest because nothing carries over a real process boundary except the file — no struct fields, no caches.

### 2. Drill D1 — crash *before* the provider effect (DoD §1: crash-recovery)
Injection: die after the durable `Pending` record is written, before `Email/set` reaches Stalwart.
- Expected after `recover()`: the intent is re-dispatched, the message moves **exactly once** on the provider, the intent reaches a terminal `Applied` status.
- Assert: `Email/get` shows the message in Archive (moved once, not zero/twice); intent status terminal.

### 3. Drill D2 — lost ack / ambiguous outcome (DoD §3: at-least-once + idempotent recovery)
Injection: `Email/set` **succeeds on Stalwart** but the ack is lost before the status write, leaving the intent `Pending`.
- Expected after `recover()`: re-dispatch hits the **idempotent** `Email/set` (same absolute `mailboxIds` target = no-op success on the provider); the message stays correctly moved (not double-applied, not corrupted); the intent reaches terminal `Applied`.
- Assert: `Email/get` shows the message in Archive exactly as intended; intent status terminal; no second distinct provider mutation occurred.

### 4. Fault injection — a test-only `Connector`/transport decorator (the only new "machinery")
To manufacture the D1/D2 states we need to interrupt at a precise point. **Decision: test-only.** A decorator lives in the integration-test layer (under `crates/aruna-jmap/tests/`), wrapping the real transport:
- **D1 fault:** return a simulated-crash error/panic **before** forwarding the POST → provider never sees it.
- **D2 fault:** forward the POST to the real transport, observe its **success**, then **drop the ack** (return a simulated-crash error) → engine leaves the intent `Pending`.
Production code carries **no** fault hooks (clean seam / YAGNI). The decorator implements the same `JmapTransport`/`Connector` trait the engine already consumes, so no production signature changes.

### 5. One `#[test]` fn, sequential phases — the shared-seed / parallel-tests rule
Rust integration tests in one binary **run in parallel by default**, and the Stalwart fixture seeds **one** message. Two independent `#[test]` fns both mutating that seed would race. So D1 and D2 are **sequential phases inside a single `#[test]` fn** (`live_recovery_drills`), chaining state cleanly: D1 drives `Archive` (inbox→archive) and leaves the message in Archive; D2 then drives `Unarchive` (archive→inbox) and leaves it back in Inbox — so the fixture is **re-runnable** (ends exactly as seeded). Each phase discovers the live ids out-of-band (the `Probe`), faults, drops+reopens, recovers, and asserts provider truth.

### 6. Test strategy — hermetic stays green; drills are opt-in
- The D1/D2 live drills are **env-gated** (`PHOTON_JMAP_IT=1` + the Stalwart fixture URL/creds), exactly like the existing live test. A plain `cargo test --workspace` with no server **stays green** (the 148 hermetic tests are untouched).
- Shared test scaffolding (`Probe`, `live_env`, `FixedAccount`/`FixedMessage`, `cmd`, a unique-temp-sqlite-path helper) is factored into `crates/aruna-jmap/tests/common/mod.rs` (the idiomatic Rust integration-test sharing module) so the new `live_recovery.rs` and the existing `live_jmap.rs` both consume it instead of duplicating ~80 lines (DRY).
- Reuse the pinned `stalwartlabs/stalwart:v0.16.10` fixture + `setup.sh` already checked in. No new infra.

## Claims to attack (construct the bypass)
1. **"Drop-and-reopen is a faithful crash sim."** Bypass to find: any engine state that survives a real crash but is NOT in the SQLite file (in-memory caches, a connector-side dedup map, session state) and would make the drill pass where a real crash fails. Name it.
2. **"D2 proves idempotency."** The connector emits a *PatchObject* (`mailboxIds/<from>=null, mailboxIds/<to>=true`), not an absolute set. Bypass to find: a provider state where re-applying that exact patch is NOT a no-op (e.g. the message was concurrently moved so `<from>` is re-added then the patch removes it — a divergence the drill doesn't model), or a path where `recover()` re-dispatch rebuilds a *different* patch than the original command. For M0 (no concurrent external mutation in the drill) the patch ops are each idempotent; name any interleaving that breaks that.
3. **"Exactly-once effect."** Bypass: an interleaving where the ack is lost AND a concurrent/second `recover()` runs → two in-flight re-dispatches. M0 serializes via `execute(&mut self)`, but name whether the drill's assertions would catch a double-apply if that serialization were absent.
4. **"The fault decorator doesn't change what's under test."** Bypass: does wrapping the transport alter timing/ordering/error-classification such that the drill proves the decorator's behavior, not the engine's?

## Non-claims (explicit non-goals)
- **Divergence-correction (DoD §2)** — needs a read-side optimistic projection that can hold a *wrong* state. No projection exists. → **Slice 2b**, its own design.
- **Floor perf gates (DoD §5)** — header search <1s @1M, folder switch <100ms, Tauri idle RAM — need a read-side store + UI surface that don't exist. → deferred (M4-era).
- **Send / outbox pipeline**, real-user-mailbox writes (ADR-P010 keeps those gated), OAuth/keyring credential storage.

## Re-review trigger
Re-review if: the crash model changes from drop-and-reopen to in-process fault injection of the engine itself; the fault decorator moves from test-only into production code; or the connector's `Email/set` payload construction changes from absolute-set to delta semantics (would break the idempotency claim).

## Testing summary
- No new hermetic test (DoD §4 already covered at `jmap.rs:885`); the 148 hermetic tests stay green and untouched.
- New env-gated live drills in `tests/live_recovery.rs` (one `#[test] fn live_recovery_drills` with sequential D1→D2 phases), each asserting provider truth + durable status, behind `PHOTON_JMAP_IT=1`; shared scaffolding factored into `tests/common/mod.rs`.
- Gates to green before PR: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`, then the live drills under the fixture; then review.
