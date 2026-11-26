# Design — Tail-ordered undo intents (ADR-P013 deferred item *c*)

**Date:** 2026-06-23 · **Status:** Implemented
**Slice:** `engine: tail-ordered undo intents`.
**Scope discipline:** one class only — undo ordering. NOT bundled with dead-letter (*b*, see `2026-06-23-failed-dead-letter-design.md`), NOT the 409 guard (*a*) or evidence markers (*d*) (both **BLOCKED**, see ADR-P013). Review chose this as the first slice.

## The bug (real, parked in `main` today)
`undo()` (`crates/aruna/src/lib.rs:781`) dispatches the inverse **immediately** and only `recover()` carries a per-resource ordering barrier. So an undo can be re-defeated by a *pending same-resource* intent that `recover()` re-applies **after** the undo. Encoded by the `#[ignore]`d failing test `undo_is_not_defeated_by_a_later_pending_same_resource_intent` (`lib.rs:1839`):

- `k1` Archive(msg-1) → Applied.
- `k2` Archive(msg-1) → recorded, left **Pending** by a transient connector failure (same resource as k1).
- `undo(k1)` → dispatches Unarchive(msg-1) inline, marks k1 Undone.
- `recover()` → re-applies the Pending `k2` (Archive) **after** the undo → msg-1 ends **archived**, undo defeated.
- **Correct:** msg-1 must end **UNARCHIVED** — the user's undo is the latest intent on the resource and must sequence last.

This is the textbook saga "null-compensation / hanging-action" anomaly: a compensating action must be ordered relative to the forward work, not raced against it (web check: MS compensating-transaction guidance; RFC 8620 §3.3 — JMAP method calls are processed in order, reinforcing that local ordered-mutation sequencing is the engine's job, not the connector's).

## The design — undo as its own tail-ordered compensating intent (hybrid)
The engine already has every primitive needed: `record()` assigns a **monotonic tail `seq`**; `unreconciled()` returns Pending/Undoing **ordered by `seq`**; `recover()` dispatches in `seq` order with a per-resource barrier. The fix routes undo through that ordering instead of bypassing it.

`undo(key)`:
1. Load the intent; must be `Applied` (fresh undo) or `Undoing` (retry) — else no-op `Ok` (unchanged guard).
2. **Detect a same-resource blocker**: any *other* non-terminal (Pending/Undoing) intent on the same `(account, message_ref)` resource, via `unreconciled()`.
3. **No blocker (the common case): inline path, unchanged.** Mark original `Undoing` (write-ahead) → `dispatch_inverse` → `Undone`. Preserves the synchronous-undo contract and all existing undo/undo-recovery tests.
4. **Blocker exists: defer as a compensating intent.** `record()` a new forward intent `{key}:undo` carrying the inverse action (and the originating envelope) — it gets a **tail `seq`** (after the blocker) and stays Pending. Mark the original `Undone` (the durable compensating record is the write-ahead commit point — recovery is owned by the compensating intent). Do **not** dispatch now. `recover()` then applies the compensation in `seq` order, **after** the blocker → the undo wins.

`recover()` needs **no change**: the compensating intent is just another Pending forward intent it already dispatches in `seq` order, and the existing per-resource barrier correctly makes it wait if the blocker re-fails.

### Why hybrid (inline + deferred), not always-defer
Always recording a compensating intent would make *every* undo asynchronous (a `recover()` round-trip) and rewrite the synchronous-undo contract + three passing recovery tests — a scope this slice keeps tight. The hybrid keeps the common case synchronous and only pays the ordering cost when a same-resource conflict actually exists. (If full uniformity is preferred, that becomes a follow-up, not this slice.)

## Fences
- **Do not deepen the `inverse()`-is-a-clean-mirror assumption.** Compensation is derived exactly as today (`Action::inverse()` at `lib.rs:32`, `dispatch_inverse` at `lib.rs:813`) — no new code leans harder on "every Action has a total inverse." The real connector will meet irreversible/lossy actions (permanent-delete, send, lossy trash→restore); making compensation-derivation pluggable ("no compensation / forward-recovery only") is **future work**, explicitly out of scope here.
- **No new `#[ignore]`d / red tests.** This slice un-ignores the existing failing test and leaves the suite fully green.

## Acceptance
- `undo_is_not_defeated_by_a_later_pending_same_resource_intent` un-`#[ignore]`d and **green**.
- All existing 32 tests stay green; `cargo clippy --all-targets -- -D warnings` clean.
- First commit carries the doc-sync: ADR `:3` + master-plan `:3` status bumps, and marks ADR-P013 deferred items (*a*) 409-guard and (*d*) evidence-markers as **BLOCKED with named unblock-gates** (not merely "deferred").

## Review fixes — slice generalized to the `TailOrderedMutationInvariant`
Code review concluded the bug is one invariant, not an undo special case. The slice is renamed **"tail-ordered same-resource mutations."** Changes:
- **`ExecuteOvertakesPendingResource` (P1):** `execute()` now defers behind a pending same-resource predecessor too — recorded `Pending`, returns `Err::InProgress` (recovery owns it; never a false `Ok`, consistent with the ADR-P013 return-signal contract). `execute()` and `undo()` share the one guard `has_pending_same_resource_predecessor()`. Without it, a *deferred undo* could wrongly defeat a *later* execute.
- **`CompensationLinkageAtomicity` (P1) + `CompensationLinkIdentity` (P2):** the `record(compensation)` + flip-original-`Undone` pair is a non-atomic dual write, and inferring the original from the `:undo` key suffix is ambiguous (a user key could collide). **Structural fix:** the compensation carries an **explicit `compensates: Option<String>` link** (new `Command` field + nullable SQLite column; `SCHEMA_VERSION` 1→2). `recover()` heals the linked original to `Undone` **before** terminalizing the compensation (heal-first keeps it retryable across a crash), and **only** via that explicit link — never a key guess — so no user key can corrupt an unrelated intent.
- **`Undoing`-retry ordering (P1):** the tail-defer applies only to a **fresh (`Applied`)** undo. An `Undoing` retry already holds its original `seq` slot; it returns `InProgress` and `recover()` finishes it in place (the per-resource barrier preserving order) rather than minting a new tail compensation that would jump past a later action.
- **`TestCommentDrift`:** the un-ignored test's comments now describe the deferral, not the old inline dispatch.
- **Reserved assumption (named, not fixed):** resource identity is `(account, single message_ref)` — a future folder-scoped/bulk action needs a broader resource key. Sits beside the inverse-fence.
- Tests added: execute-defers-behind-predecessor, deferred-undo crash self-heal, unlinked-`:undo`-key non-corruption, `Undoing`-retry-no-tail-compensation. Suite **37 passed / 0 ignored**, clippy `-D warnings` clean.

## Final decision — slice right-sized
Further review flagged, in turn: a missing schema migration (added a v1→v2 `ALTER`); the link field being `pub` (→ `pub(crate)`) plus migration crash-idempotency; the compensation key sharing the user keyspace (→ reserved `\u{1}undo:` namespace, `record()` rejects non-compensation use) plus a column-driven migration; and that the reserved-key change moved the **connector** idempotency key, so an in-flight `Undoing` row from a *v1* database could double-apply on a real provider.

**Review of the final code concluded:** the core `TailOrderedMutationInvariant` is sound (no real defect), but the **v1→v2 migration served a zero population** (M0 is pre-release; no persisted database exists) and was the root of the whole chain of migration findings. **Resolution: drop the migration.** `migrate()` + `column_exists()` removed; `compensates` stays folded into the fresh `CREATE TABLE` (schema is just v2); the two migration tests removed. This dissolves the last finding outright (no migration path → no cross-version key mismatch).

**Deferred design note:** decouple the **connector dispatch key** from the **durable log key** so a key-format change can't move the provider's dedup key — i.e. version the idempotency-key namespace alongside the schema/API version. (Deferred rather than built against zero data.) Recorded in `SqliteIntentLog::open`.

Final suite after B: **40 passed / 0 ignored**, clippy `-D warnings` clean.

## References
Saga compensation (forward-recovery, tail-ordered, idempotent); MS "compensating transaction" guidance; RFC 8620 §3.3 (ordered method calls) + RFC 8621 `EmailSubmission/set` `undoStatus`; Stripe / brandur.org idempotency-keys; ADR-P013 (`docs/adr/`).
