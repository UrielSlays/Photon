# Design — `Failed` dead-letter lifecycle (ADR-P013 deferred item *b*)

**Date:** 2026-06-23 · **Status:** Implemented
**Slice:** `engine: Failed dead-letter lifecycle`.
**Scope discipline:** the *mechanism* only — `Failed` as the terminal dead-letter state for *deterministic* failures, the retry cap, the backoff *structure*, and the inspect surface. The error-**policy taxonomy** (which concrete provider errors are deterministic vs transient) STAYS deferred to the real connector — documented, **no parked red test** (suite stays green). Items (*a*) 409-concurrency-guard and (*d*) evidence-markers remain **BLOCKED** (see ADR-P013); not touched here. Item (*c*) undo tail-ordering shipped in the undo-tail-ordering slice (`2026-06-23-undo-tail-ordering-design.md`) — (*b*) was queued behind it and is now unblocked.

## What existed before this slice (the consumer with no producer)
`ExecuteError::Failed`, `Terminal::Failed`, `IntentStatus::Failed`, and the truth-table branch `TerminalReplay(Failed) -> Err::Failed` were all already present (`crates/aruna/src/lib.rs`), but **`Failed` was unreachable by any M0 code path** — every connector error was treated as transient and left the intent `Pending` (the `recover()` comment said as much: *"A retry cap / dead-letter is deferred Failed-lifecycle work (provider slice)"*). The reserved-replay test `execute_replays_a_failed_intent_as_an_error_never_ok` had to **seed a `failed` row by raw SQL** to exercise the branch. This slice builds the **producer**.

## The design — classify the failure, then cap the retries

### 1. Deterministic vs transient at the seam (`FailureKind`)
`ConnectorError` is now `{ message: String, kind: FailureKind }` where `FailureKind = Transient | Deterministic`, with constructors `ConnectorError::transient(msg)` / `::deterministic(msg)`. A connector that does not classify is treated `Transient` (the M0 default — existing fail-then-retry behavior unchanged). The **policy** — which real errors map to which kind (404/permission = deterministic; 429/503/timeout = transient) — is the connector's taxonomy and is **deferred**; the mock `DeterministicFailConnector` declares the kind directly. (Ripple was bounded: 4 construction sites, all transient; nothing reads the inner field.)

### 2. Deterministic failure -> `Failed` immediately
In `execute()` and `recover()`, a deterministic connector failure dead-letters the intent to terminal `Failed` at once (it will never succeed on retry), instead of looping forever. The connector rejection is still surfaced (`Err::Connector` on the first dispatch; an identical replay then returns `Err::Failed` via the truth table) — never a silent `Ok`.

### 3. Transient failure -> retry cap (durable `attempts` counter)
A durable per-intent `attempts: u32` counter (new SQLite column, **schema v3**, `DEFAULT 0`, **no data migration** — same precedent as the undo-tail-ordering slice: M0 is pre-release with zero persisted DBs, so a fresh DB is created at the current `SCHEMA_VERSION`). The cap is enforced in ONE place — `charge_transient_attempt()`, shared by `execute()` (the initial dispatch = attempt 1) and `recover()` (each sweep): increment the counter; once it reaches `RETRY_CAP` (5) dead-letter to `Failed` (retry-budget exhaustion — *a transient error that recurs forever is effectively permanent*, the canonical DLQ rule).

### 4. Backoff *structure* (`backoff_delay`)
`backoff_delay(attempts) -> Duration` = `BACKOFF_BASE * 2^(n-1)`, saturating, capped at `BACKOFF_CAP` (60s). Pure + deterministic — the schedule the future recovery scheduler will consult to decide *when* a `Pending` intent is next eligible. There is no clock wired in M0 (recover() is invoked externally), so only the schedule's *shape* is defined + tested. Full jitter (research: non-negotiable against thundering-herd) is added when the clock + RNG are wired.

### 5. Inspect / replay
`dead_letters() -> Vec<Intent>` (new `IntentLog` method): every terminal `Failed` intent ordered by `seq` — the operator's DLQ window. SQLite impl parses-then-filters in Rust (fail-closed, same discipline as `unreconciled()` — never SQL-filter by status). **Replay** semantics: the *idempotent* replay (an identical retry of a `Failed` key returns `Err::Failed`, no re-dispatch) is the already-wired truth-table behavior; a *deliberate operator re-drive* is an operator action (submit a fresh logical command) — append-don't-erase forbids resurrecting a terminal row, so this is **not** a new engine `replay()` API in M0.

## Open questions for the depth-check (decisions I made on the merits — pressure-test them)
1. **Barrier interaction (the load-bearing one).** When an intent dead-letters mid-`recover()`, I **release** the per-resource ordering barrier (a terminal/resolved-as-failed intent is not an in-flight predecessor), so a later same-resource intent proceeds independently. Alternative: cascade-block/cascade-dead-letter dependents. I chose release as the minimal mechanism and fenced cross-intent dependency as deferred saga work (ADR-P013 (*c*) scope fence). **Is release correct, or does a dead-lettered predecessor have to block/fail its dependents?**
2. **Attempt counting + cap value.** Initial `execute()` counts as attempt 1; `RETRY_CAP = 5` is *total* dispatch attempts before dead-letter. Right counting? Right default (research says 3–5)?
3. **First-deterministic-failure return.** First deterministic dispatch returns `Err::Connector(err)` (the truthful rejection); the *replay* returns `Err::Failed`. Acceptable, or should the first deterministic failure already return `Err::Failed`?
4. **Backoff as a pure fn now.** Is shipping `backoff_delay` (pure, tested, unused internally — `pub` so no dead-code) the right "structure," or is it speculative machinery to defer entirely until the scheduler exists? (the undo-tail-ordering slice's lesson: premature machinery breeds an edge-tail.)
5. **Replay surface.** Is "idempotent truth-table replay + operator re-drive deferred" a sufficient reading of (*b*)'s "inspect/replay", or does (*b*) intend an explicit engine `replay()`?
6. **`RecoverReport.failed`** does not distinguish a dead-lettered intent from a still-retrying one. Add a distinct signal?

## Fences (do NOT cross in this slice)
- **Error-policy taxonomy stays deferred.** No mapping of concrete provider errors to `FailureKind` here, and **no parked red test** for the gap — documented only; the suite stays green.
- **No clock / scheduler.** Backoff timing is a *schedule shape*, not a runtime; jitter + eligibility-gating land with the scheduler.
- **No data migration** for the new column (decision B — zero persisted population).
- **Inverse-is-a-clean-mirror** assumption unchanged (inherited fence from the undo-tail-ordering slice).

## Acceptance / proof
- `cargo test --manifest-path crates/aruna/Cargo.toml` = **47 passed / 0 failed / 0 ignored** (6 new: deterministic dead-letter, retry-cap exhaustion, deterministic-recovery dead-letter (Pending), deterministic-recovery dead-letter (Undoing), backoff schedule, dead-letter inspect).
- `cargo clippy --manifest-path crates/aruna/Cargo.toml --all-targets -- -D warnings` = clean.
- The reserved `TerminalReplay(Failed)` branch now has a real producer; the previously transient-stays-`Pending` test still passes (the `FailureKind` split is honored both ways).

## Review fixes
All five open design questions were judged **sound** (barrier-release correct for M0; RETRY_CAP=5 / initial=attempt-1 canonical — Google Pub/Sub default is 5; first `Err::Connector` then replay `Err::Failed` correct; `backoff_delay` kept as structure with the jitter-coupling rule attached; replay surface sufficient for M0). Fixes:
- **`RecoverFailureKindParity` / `RecoveryFailureKindClassification` (BLOCKING).** `recover()` collapsed every connector rejection into the transient retry-budget path, so a *deterministic* failure during recovery burned budget instead of dead-lettering — contradicting this doc + ADR-P013(b). **Fix:** centralized the failure decision into one `reconcile_connector_failure(key, &error)` shared by `execute()` and `recover()` so the two paths cannot drift; deterministic → dead-letter immediately, transient → charge the budget. Covers **both** the `Pending` and `Undoing` recovery paths, each with a new test.
- **Jitter-coupling rule:** `backoff_delay`'s doc now states it MUST NOT be wired into a real retry path without full jitter in the same change.
- **Replay disambiguation:** stated explicitly — (b)'s "replay" = the idempotent truth-table replay (shipped) + `dead_letters()` inspect (shipped); a deliberate operator re-drive is a *fresh command* (append-don't-erase), **not** an engine `replay()` API, and is deferred.
- **Doc-freshness nit:** stale head SHA reference corrected (above).

## Review fixes (second pass)
- **[P2] Fresh undo budget.** The durable `attempts` counter was shared between the forward-apply phase and a later undo, so an intent that only reached `Applied` after transient apply-retries could have its undo's inverse dead-lettered far short of the cap. **Fix:** a fresh undo (`Applied → Undoing`) resets the counter (`reset_attempts`), giving the inverse its own retry budget; an `Undoing`-retry keeps its count. New test `a_fresh_undo_gets_a_clean_retry_budget_not_the_apply_phase_count`. (Both findings sit at the dead-letter × undo boundary.)
- **[P1] Compensation-DLQ truthfulness.** Review caught an interaction: the new `reconcile_connector_failure` could dead-letter a *deferred-undo compensation* (`compensates.is_some()`) whose original was already marked `Undone`, leaving the log lying (original Undone, inverse never applied). **Fix:** the dead-letter lifecycle applies to FORWARD intents only — a compensation in `recover()` is exempt and stays transient-retryable, so the inverse keeps being pursued. A permanently-failing inverse is deferred saga work (consistent with the existing ADR-P013 (c) inverse-fence). New test: `recover_does_not_dead_letter_a_deferred_undo_compensation`. **48 tests / 0 ignored, clippy clean.**

## Review fixes (structural pass) — `RetryBudgetTerminalizationInvariant`
Review found 3 rounds / 4 findings all at one boundary (dead-letter/retry-cap × undo/inverse), so the **class** was re-examined as a whole. The open question was whether an atomic single-write was required; the resolution is **atomic-write-primary + recovery-backstop**, citing AWS SQS `maxReceiveCount` / Pub/Sub max-delivery / Azure `MaxDeliveryCountExceeded` (DLQ systems move the message out *at the threshold*, not leave it live hoping a sweeper notices). Resolved shape:
- **(A) one reconciliation boundary.** All dispatch-failure arms — `execute()`, `recover()`, and now `undo()`'s fast-path inverse failure (reconciled against the **original** key) — route through the single `reconcile_connector_failure`. The direct undo path no longer bypasses the cap/dead-letter.
- **Atomic terminalization (primary).** `charge_transient_attempt` is now ONE durable write that increments `attempts` and conditionally sets `Failed` (SQLite `CASE`), so no dispatcher can observe an over-budget non-terminal row. (Replaced the two-write `increment_attempts`.)
- **(B) recover-time backstop.** `recover()` dead-letters any non-compensation row with `attempts ≥ RETRY_CAP` *before* dispatching — defense-in-depth for legacy/corrupt rows.
- Tests: undo-direct deterministic→Failed, undo-direct transient→cap→Failed, recover over-budget pre-dispatch self-heal; the recover-deterministic-undo test updated for the new uniform behavior. **52 tests / 0 ignored, clippy clean.**
- **Tracked:** a dead-lettered *undo* lands the original in `Failed` while its forward effect is still applied at the provider — indistinguishable from a failed-*forward* without reason-metadata (the deferred observability gap below).
- **Follow-on [P2]:** once the inverse path dead-letters, a later `undo()` of a `Failed` row hit the `_ => Ok(())` guard and returned a silent successful no-op (return-signal lie). **Fix:** `undo()` now surfaces `Err::Failed` for a dead-lettered row, uniform with `execute()`'s `Failed → Err::Failed` contract — never `Ok` for a not-succeeded operation. (Distinguishing failed-undo from failed-forward still needs the deferred reason-metadata; both honestly return `Err::Failed`.) **53 tests / 0 ignored, clippy clean.**

## Deferred / tracked (named, not lurking in this diff)
- **Error-policy taxonomy** (which concrete provider errors are deterministic vs transient) — the connector's, deferred; no parked red test.
- **Dead-letter reason-metadata**: `dead_letters()` lists *which* intents dead-lettered (status + attempts) but not *why* (the `ConnectorError` message/kind is not persisted on the row). Deferred with the evidence/observability work (ADR-P013 (d) evidence markers, BLOCKED on ADR-P008). Tracked.
- **Operator re-drive**, **(a) 409 concurrency guard**, **(d) evidence markers** — all behind named gates.

## References
Dead-letter queue / poison-message handling (transient -> retry-with-cap; deterministic -> immediate DLQ; retry-budget exhaustion -> effectively permanent); exponential backoff with full jitter (capped); Temporal durable-execution (failures surfaced in history, inspect/replay) as the contrast to a separate DLQ; append-don't-erase / dead-letter-as-terminal-class; Stripe / brandur.org idempotency-keys; ADR-P013 (`docs/adr/`, item *b*).
