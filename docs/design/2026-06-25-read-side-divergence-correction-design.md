# Design — M0 read-side projection + divergence-correction (Slice 2b)

**Date:** 2026-06-25 · **Status:** Implemented
**Slice:** `feat/m0-read-side-divergence` off `main` @ `6ee4036`. PR title (planned): `engine(jmap): real read-side projection + prove divergence-correction (M0 DoD §2)`.
**Scope discipline:** stand up the **smallest real read-side optimistic projection** that closes M0 DoD §2 — "a *wrong* optimistic projection corrected by provider truth, not happy-path reconcile." Replace the fake `MessageRefResolver` with a durable store that holds the optimistic mailbox placement, add a correction path that overwrites a diverged row from provider truth, and prove §2 with a **non-vacuous** drill (hermetic + live). **No** JMAP state-string / `Email/changes` cursor; **no** `Email/query` bulk population; **no** UI. Those are named M1 work (the milestone plan) and would be the same "self-inflicted machinery → edge-tail" trap the undo-tail-ordering slice warned about.

## Why this slice, why now (grounded at the byte)
- the milestone plan — the M0 DoD demands **"Divergence-correction: a *wrong* optimistic projection corrected by provider truth, not happy-path reconcile (Q3b)."** This is the one DoD property class still unproven: §1 (crash-recovery) and §3 (lost-ack/idempotent) landed in Slice 2a; §4 (`*/set` shape) is proven on `main`; §5 (floor perf) is later.
- `crates/aruna/src/jmap.rs:237-241` — `MessageRefResolver` is today a trait, **fake-seeded** in M0 (`FakeJmap` impl at `jmap.rs:703-706`), whose doc-comment already names the plan: *"Fake-seeded in M0; the read-side message store plugs into this same seam later."* This slice IS that store.
- Divergence-correction needs a real read model that **can hold a wrong state** to begin with. A fake resolver that just returns a hard-coded id cannot diverge; only a durable, mutable projection can. So §2 forces the read-side store into existence — which is why the master plan pairs them.

## What exists before this slice
- `crates/aruna/src/lib.rs`: `SqliteIntentLog::open(path)` (file-backed, survives reopen — `lib.rs:310`), the `IntentStatus` FSM (`lib.rs:107`: terminal = `Applied`/`Undone`/`Failed`; in-flight = `Pending`/`Undoing`/`EvidenceSnapshotWritten`), `IntentLog::get` (`lib.rs:172`), the ADR-P013 idempotency-decision gate, the dead-letter lifecycle.
- `crates/aruna/src/jmap.rs`: `JmapConnector<T, A, M>` over `JmapTransport` + `AccountResolver` + `MessageRefResolver`; `Action::{Archive,Unarchive}{message_ref}` (`lib.rs:26-29`); the surgical `Email/set` PatchObject move.
- `crates/aruna-jmap/src/transport.rs`: `HttpJmapTransport` (real `reqwest::blocking` behind the `HttpClient` seam), the ADR-P010 default-closed `DestructiveWriteGate`, the Stalwart fixture, env-gated live tests.
- 149 hermetic+live tests green on `main` + clippy + `cargo doc -D warnings`.

## The standards basis (the produce-phase web check, 2026-06-25)
- **Canonical optimistic-projection pattern.** The web-confirmed offline-first pattern: optimistically apply a mutation to the local read model, then on server ack discard the pending snapshot, on conflict revert and **apply the authoritative server state in its place**. Our M0 form is the simplest correct instance: provider-wins overwrite, with the **durable intent log already serving as the rollback record** (no separate rollback stack needed).
- **JMAP's own reconcile guidance** ([jmap.io/client](https://jmap.io/client/)): a client updates `mailboxIds` locally, then on resync *undoes the preemptive change and applies the real server change* — "ideally the end result will be the same." Provider `mailboxIds` (RFC 8621 §4 `Email/get`, a default-fast property) is the truth source for placement.
- **The footgun the search surfaced (load-bearing correctness rule):** provider-wins must **not** clobber a still-in-flight optimistic projection. If the governing intent is non-terminal (`Pending`/`Undoing`/`EvidenceSnapshotWritten`), the optimistic placement is *unconfirmed*, not *wrong* — overwriting it would erase a legitimate pending mutation. **Correction fires only against rows whose governing intent is terminal.** This binds §2 to the existing `IntentStatus` FSM rather than inventing a parallel notion of "settled."

## The design

### 1. The projection store — one database, one transaction (Q2: shares the intent-log DB)
A new durable table in the **same** SQLite database **file** as the intent log. **Correction:** in this slice the store uses a *separate connection*, so the optimistic write and the intent record are **separate autocommit transactions, NOT one atomic boundary** — same file ≠ same transaction. That window is **inert in M0** (no production path pairs the two writes; the optimistic-apply pipeline is unwired; the projection is a rebuildable CQRS read-model whose worst case is a missing/stale row that self-heals from provider truth). The **atomic co-commit is owed** when the optimistic-apply pipeline is wired into `execute()` — tracked as a follow-up issue. The "divergence" we then correct is purely projection-vs-**provider**, never projection-vs-log (single-axis).

```
CREATE TABLE IF NOT EXISTS message_placement (
    account     TEXT NOT NULL,
    message_ref TEXT NOT NULL,
    email_id    TEXT NOT NULL,   -- provider EmailId (what MessageRefResolver returns today)
    placement   TEXT NOT NULL,   -- optimistic belief: 'inbox' | 'archive'
    PRIMARY KEY (account, message_ref)
);
```

`Placement` is a closed enum (`Inbox | Archive`) — the only two states `Action::Archive`/`Unarchive` can produce in M0. (Wider mailbox membership is deliberately out of scope; the enum is the YAGNI-correct shape and a later slice widens it behind the same store API.)

### 2. `SqliteMessageStore` — the real source behind the existing seam
A new struct in `aruna` (HTTP-free, like the rest of the engine) that:
- **implements `MessageRefResolver`** by reading `email_id` from `message_placement` — this is the drop-in that retires the fake;
- adds `placement(account, message_ref) -> Option<Placement>` (read the optimistic belief);
- adds `record_optimistic_placement(account, message_ref, email_id, placement)` (the optimistic-apply write; callable inside the intent-record transaction);
- adds `correct_placement(account, message_ref, provider: Placement) -> Corrected` where `Corrected { changed: bool }` is the **non-vacuity witness** — `changed=true` iff the stored row actually differed from provider truth and was overwritten.

### 3. The provider-truth seam — `ProviderPlacement` (keeps `aruna` HTTP-free)
Correction needs to read the provider's current placement. Mirroring the `MessageRefResolver` seam pattern, a new trait in `aruna`:

```rust
pub trait ProviderPlacement {
    fn fetch_placement(&self, account: &str, email_id: &EmailId)
        -> Result<Placement, ConnectorError>;
}
```

- **In `aruna`:** unit tests use a fake impl that returns a scripted placement (so a *wrong* projection can be manufactured).
- **In `aruna-jmap`:** a real impl issues a JMAP `Email/get` for `mailboxIds` and derives `Placement` (in Archive iff `mailboxIds` contains the Archive id and not Inbox). HTTP/JMAP stays isolated to `aruna-jmap`, per the live-transport slice's standing decision.

### 4. `reconcile_divergence` — the correction path (the §2 engine logic)
A function on the engine (`aruna`) that, for a given `(account, message_ref)`:
1. Look up the governing intent via `IntentLog::get`. **If non-terminal → SKIP** (the footgun rule: an in-flight optimistic placement is unconfirmed, not wrong).
2. Resolve the `email_id` from the store; `fetch_placement` from the `ProviderPlacement` seam.
3. `correct_placement(.., provider)` — overwrite iff diverged. Return whether a correction occurred.

Provider wins, unconditionally, for terminal intents (M0 has no client-side conflict resolution — provider is the source of truth). A `fetch_placement` transport error is surfaced, not swallowed (fail-loud; no silent "assume converged").

### 5. The §2 proof — non-vacuous divergence-correction drills
**Hermetic (in `aruna`, fake `ProviderPlacement`):**
- **D-diverge (the property):** seed the store with `message X → Archive` under a **terminal `Applied`** intent; script the provider truth to `Inbox`. Run `reconcile_divergence`. Assert the row **flips to `Inbox`** *and* the returned witness is `changed=true`. This is non-vacuous: the projection genuinely started wrong and genuinely converged (the `CountingForward`-style witness lesson from Slice 2a).
- **D-agree (negative control):** projection already equals provider truth → correction is a **no-op**, witness `changed=false`, no spurious write.
- **D-inflight (the footgun guard):** a diverged projection whose governing intent is `Pending` is **NOT** corrected (skipped) — proving we never clobber an unconfirmed optimistic mutation.

**Live (in `aruna-jmap`, real `Email/get` vs Stalwart v0.16.10, env-gated `PHOTON_JMAP_IT=1`):**
- Move a real message to Archive on the provider, then **poison** the local projection to claim `Inbox` (manufacture divergence against real provider truth). Run `reconcile_divergence` with the real JMAP `ProviderPlacement`. Assert the projection converges to the real provider placement (`Archive`) and the witness fired. (CI must execute the live lane — this applies here too.)

## What this slice deliberately does NOT do (YAGNI, named to prevent scope creep)
- **No JMAP state-string / `Email/changes` cursor or incremental delta sync** — M1 (the milestone plan).
- **No `Email/query` bulk population** — the store is seeded by the optimistic-apply path and corrected point-wise; bulk initial sync is later.
- **No client-side conflict resolution / merge** — provider-wins is the M0 rule.
- **No new mailbox states beyond `Inbox`/`Archive`** — matches the M0 action set.
- **No UI / surface** — the projection is engine-internal (the truthful-view UI is a later bolt-on, `project-ui-vision-kill-switch`).

## Risks / edges (to pressure-test)
- **Atomicity of the optimistic write with the intent record.** The store write must join the *same* transaction as `record()` or a crash splits them. Design: expose the optimistic write so the bus can call it inside the existing record transaction (or document the ordering if a single transaction across both tables needs a small `CommandBus` change). Confirm the transaction boundary is real, not assumed.
- **Terminal-gate correctness.** The skip-if-non-terminal rule depends on reading the governing intent for a `message_ref`. The intent is keyed by idempotency key, not `message_ref` — the design must define the lookup (most-recent terminal intent for that `message_ref`, ordered by `seq`). Check that this mapping is unambiguous.
- **Placement derivation from `mailboxIds`.** Deriving `Inbox`/`Archive` from the raw `mailboxIds` set must handle the message being in neither / both gracefully (fail-loud, not a silent default).
- **Provider error during correction** must not corrupt or silently "converge" the projection.
```
