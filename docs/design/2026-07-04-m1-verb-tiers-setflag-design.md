# M1 — §2: verb tiers + the first state-toggle verb (`SetFlag`, seeded with `Seen`) · DESIGN

**Date:** 2026-07-04 · **Status:** Implemented. Build against §2's change-B list and §5's test matrix.
**Milestone:** M1 (milestone plan §4), second slice. Builds on §1 (Gmail connector).
**Grounded in:** `docs/research/2026-07-04-mail-action-taxonomy.md` (25/25 primary-sourced claims verified).

---

## 1. Why this slice exists (two coupled theses)

§1 proved neutrality for a **location** verb (`Archive` — a mechanic that *diverges* per provider: Gmail label-removal vs JMAP mailbox-move). The taxonomy research (committed) shows mail verbs split into two classes, and §2 proves the **other** one:

> **State-toggle verbs** are modeled as reversible keyword/flag/property toggles. **The four-surface clean mapping is grounded for READ (this slice's `Seen`)**: JMAP `$seen` keyword ↔ IMAP `\Seen` flag ↔ Gmail `UNREAD` label ↔ Graph `isRead`. (RFC 8621 §4.1.1; RFC 9051 §2.3.2; research findings 1, 4.) *[Scoped: flag/answered/draft do NOT share the full four-surface mapping — Graph `flag` is a structured `followupFlag`, answered lacks Gmail/Graph mechanics, draft is not toggleable on Gmail. Every flag after `Seen` needs its own per-flag grounding + tier row (§2, §3.2).]*

So the *same* neutral verb `mark read/unread` drives **two different native mechanics**: Gmail toggles a **label**, JMAP sets a **keyword**. That is ADR-P003 neutrality demonstrated on the clean-mapping class — a sharper proof than §1 because the divergence is in the *mechanism kind* (label vs keyword), not just the target.

**Second thesis (foundational):** ADR build-order **step 2** wants a mandatory **tier** on every action (ADR-P005). This slice lands the **un-gated** half of that — a static `RiskTier` classification — so `mark read/unread`, and every verb after it, is *born risk-tiered*. (The runtime governance tier — `ActionEnvelope.tier`, the ISOLATION/AUTHORITY axis — stays reserved; see §4.)

## 2. Scope fence (read before building) — **RESTRUCTURED after review: TWO changes, doc first**

**Change A (doc-only, lands FIRST): the ADR-P005 amendment**, corrected after review:
- **`trash` STAYS RED**. Add the retention/recoverability facts as RED rationale. **Independent ground:** recoverability is target-state-dependent (a trashed draft is unrecoverable per official Gmail guidance) — generic trash stays conservative; **`discard-draft` is a separate verb**, not trash.
- Add the ~8 missing verbs (mute, snooze, follow, mark-answered, mark-spam, mark-important, empty-trash, save/discard-draft); footnote `archive` as mechanic-divergent; note one-way keywords (`$MDNSent`/`$Forwarded`) are not plain YELLOW toggles. Mark un-grounded verbs (unsubscribe/filters/spam/block) as **needing a follow-up grounding pass before they are tiered** (tracked).
- Name the **engine-wide blind-compensation class** (see §3.1b) in the amendment: YELLOW means *clean metadata toggle*, NOT pre-state-faithful undo — undo is a compensating inverse until the ADR-P007 snapshot/pre-state substrate lands.

**change B (code-PR, builds against the settled taxonomy):** four coupled parts, one change:
1. **`RiskTier` enum + `Action::risk_tier()`** — a static, exhaustive, **per-flag** verb→risk-tier classification. Un-gated (see §4). *(Renamed from `Tier`/`tier()` — `tier-namespace-disambiguation`: the reserved `ActionEnvelope.tier` is the ISOLATION/AUTHORITY axis; the P005 color is the RISK axis; a shared bare name makes `envelope.tier = Some(action.tier().into())` a one-line future footgun that compiles.)*
2. **`SetFlag { message_ref, flag: MailFlag, value: bool }` Action variant**, `MailFlag` **seeded with only `Seen`** — the general shape, proven with one flag. `inverse()` = `SetFlag { flag, value: !value }` (**a compensating inverse, NOT byte-faithful undo** — §3.1b); `risk_tier()` = YELLOW **for `Seen` specifically** (per-flag match, no `SetFlag{..} => Yellow` wholesale arm).
3. **Gmail connector mapping** — `SetFlag{Seen, value}` → toggle the `UNREAD` label (the **inversion**: `Seen=true` ⇒ remove `UNREAD`; `Seen=false` ⇒ add `UNREAD`) — **plus CapabilityMap publication of the new flag capability**.
4. **JMAP connector mapping** — `SetFlag{Seen, value}` → set the `$seen` keyword via an `Email/set` `keywords/$seen` patch, through the **ONE total `Result`-returning normalization/dispatch path of §3.4** (NOT a per-prefix accessor — a `keyword_updates()` sibling filter would recreate the rejected silent-partial design), including the **live `aruna-jmap` transport** carrying-or-failing-closed in this slice.

**Out of scope:** other flags (`MailFlag` stays a **closed enum restricted to reversible metadata flags**; Flagged/Answered later, each with its own grounded per-flag tier — payload-level risk must not inherit Seen's tier); the runtime tier **gate behavior** / `ActionEnvelope.tier` activation (governance-blocked, "no fire drill"); tiering the un-grounded verbs (follow-up); pre-state/snapshot-faithful undo (ADR-P007 substrate — tracked obligation, §3.1b); the read side.

## 3. Architecture

### 3.1 The neutral verb (engine — `crates/aruna/src/lib.rs`)
```rust
pub enum MailFlag { Seen }              // seeded with one; extensible (Flagged, Answered, … later)

pub enum Action {
    Archive   { message_ref: String },
    Unarchive { message_ref: String },
    SetFlag   { message_ref: String, flag: MailFlag, value: bool },   // NEW
}
```
- `Action::inverse()` gains: `SetFlag { message_ref, flag, value } => SetFlag { message_ref, flag, value: !*value }`.
- **`Seen` is the neutral POSITIVE** ("message has been read"). Each connector bridges to its native representation — Gmail stores the *negative* (`UNREAD`), JMAP the *positive* (`$seen`). The seam absorbs the provider's polarity; the engine never learns "UNREAD."

### 3.1b Undo is a COMPENSATING INVERSE, not byte-faithful restoration
`inverse()` cannot reconstruct pre-state: a message already read + `SetFlag{Seen,true}` (idempotent no-op) + undo ⇒ `SetFlag{Seen,false}` marks unread a message the action never changed. **This class — `PrestateBlindCompensation` — is ENGINE-WIDE, not SetFlag-specific:** `Archive.inverse()=Unarchive` has the identical property today (undo of a no-op archive on a not-in-INBOX message *adds* INBOX). M0 shipped that semantic with ADR-P007's snapshot/pre-state machinery explicitly reserved to a later build-order step; both immediate and deferred compensation call `Action::inverse()` (`lib.rs:1370`) and snapshots remain `None`. **This slice therefore (a) makes NO "true undo" claim anywhere — undo of `SetFlag` (and of Archive/Unarchive, already shipped) is a best-effort compensating inverse until pre-state/snapshot lands; (b) names the class in the ADR-P005 amendment (change A) so YELLOW is defined as *clean metadata toggle*, not *pre-state-faithful undo*; (c) the class is a tracked engine-wide obligation with this exit criterion — pre-state/snapshot restoration lands before any **real-provider (live, Part-III-ungated)** YELLOW+ write or any restores-prior-state claim (capture pre-state at apply time or activate the snapshot path — that slice's design call, not this one's).** Building pre-state capture inside this verb PR would smuggle the snapshot substrate in through a slice that doesn't own it.

**Contract-closure additions:** (i) change A re-words the ENGINE's own undo contract — `lib.rs:37` ("reversing action") and `:1228` — to "blind counter-action successfully applied," never "prior state restored," and adds an implementation-status cross-reference at ADR-P007 itself (P005 is the wrong home for explaining P007's unbuilt contract). (ii) Terminology fence: this section's "compensating inverse" names the MACHINERY GAP (uniform across all YELLOW+ verbs until pre-state capture is built); P005-RED's "compensatable" names the INTRINSIC reversibility class (what separates RED from YELLOW). Same root word, two meanings — the amendment keeps them visibly distinct so "YELLOW undo is compensating" is never read as "YELLOW = RED."

### 3.1a Durable encoding (the real ripple — surfaced by the produce-phase check)
The intent-log serializes an action via `action_to_parts(&Action) -> (kind: &str, message_ref: String)` and reconstructs it via `action_from_parts(kind, message_ref)` (`lib.rs:565-585`), into the fixed schema `(action_kind TEXT, message_ref TEXT)`. Archive/Unarchive carry **only** a `message_ref`; `SetFlag` carries **`flag`+`value` too**. **Decision: encode the extra state into the existing `action_kind` token — `"set_flag:seen:true"` / `"set_flag:seen:false"` — NO DDL migration, WITH these constraints:**
- **A documented, VERSIONED token grammar**: the grammar is `<verb>` or `<verb>:<param>:<param>` where `:` is the reserved delimiter and **params are drawn from closed enums whose serializations can never contain `:`** (`seen`, `true`/`false`). An extensibility note is part of the contract: a future parameterized verb whose param can carry `:` or arbitrary text (snooze-until-timestamp, move-to-folder-id) **must NOT extend this grammar ad hoc** — it takes an escaped/length-prefixed grammar revision or a typed column, with a migration. No provider keyword is ever stuffed into the token.
- **Exact, fail-closed parsing**: exact-token match, no loose prefixes; unknown flag/value ⇒ `LogError`, never a default (mirrors `Placement::from_token`). Round-trip tests cover both values.
- **`SCHEMA_VERSION` bump even without DDL**: the decodable token family changes the durable grammar; older binaries must refuse the database rather than open a format they cannot parse (`lib.rs:351`, `PRAGMA user_version`).

`action_to_parts` builds the composite token; `action_from_parts` splits it; `action_message_ref` adds `SetFlag` to its `|` arm (it has a `message_ref`). **`classify` is unaffected** — it keys same-resource detection on `message_ref` only (`lib.rs:1345/1350`), so a `SetFlag` and an `Archive` on one message are treated same-resource → conservatively tail-ordered. This is safe: read-state and location **commute**, so any order yields the same final state; over-serialization only removes concurrency (out of scope). **Consumer-contract note:** `action_kind` values are durable — the `set_flag:seen:*` token format is a **frozen on-disk contract** (like `Placement::as_str`); changing it later needs a migration.

### 3.2 The risk-tier taxonomy (engine) — renamed `RiskTier`
```rust
pub enum RiskTier { Green, Yellow, Red, Black }   // ADR-P005 color RISK tiers (never bare `Tier`)

impl Action {
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            Action::Archive { .. } | Action::Unarchive { .. } => RiskTier::Yellow, // reversible metadata
            // PER-FLAG, never a wholesale `SetFlag{..}` arm: payload-level risk must not
            // inherit Seen's tier (a future one-way/spam-training flag gets its own row).
            Action::SetFlag { flag: MailFlag::Seen, .. } => RiskTier::Yellow,
        }
    }
}
```
Static, exhaustive, pure. It is verb **metadata**, not the governance runtime field (§4). **Naming is load-bearing:** the reserved `ActionEnvelope.tier` is the ISOLATION/AUTHORITY axis (its test value is `"isolated"`, `lib.rs:1814`, and a persist path to it already exists at `lib.rs:683`); the P005 color is the RISK axis. **The rename is MITIGATION, not structural impossibility:** `envelope.tier` remains `Option<String>` and a maintainer can still format a `RiskTier` into it — the distinct name+type kills the *accidental* one-liner, and a **no-flow guard test** backs it: `risk_tier()` never populates, validates, authorizes from, or gates on `ActionEnvelope.tier`. A future `#[deny]`-style CI guard can assert every `Action` variant (and every `MailFlag`) has a risk tier by exhaustive match.

### 3.3 Gmail mapping (`crates/aruna/src/gmail.rs`)
`SetFlag{Seen, value}` reuses the existing `GmailModifyRequest`/`modify_labels` seam — it's a label toggle like archive, just on `UNREAD` with inverted polarity:
- `value=true` (read) → `removeLabelIds:["UNREAD"]`
- `value=false` (unread) → `addLabelIds:["UNREAD"]`

`LabelId::unread()` ("UNREAD", a reserved locale-independent system-label id — research finding 4). Confinement and error taxonomy reuse §1's machinery unchanged. **The CapabilityMap does NOT reuse unchanged: both connectors' maps today publish only archive/unarchive — each must publish the new flag capability (e.g. `set_flag_seen`) so preflight stays complete per ADR-P010.** **The invariant is PER-FLAG, not per-variant:** `SetFlag` is parameterized by `MailFlag`, so `supports()` matches `MailFlag::Seen` explicitly — never an `Action::SetFlag { .. }` wildcard — and the conformance test FAILS when a new `MailFlag` is added without a capability row. The test targets each connector's **default published map**, not a hand-built one.

### 3.4 JMAP mapping (`crates/aruna/src/jmap.rs` + `crates/aruna-jmap`) — the new mechanic, silent-drop closed
JMAP sets the `$seen` keyword via `Email/set` — the SAME `PatchObject` mechanism as the mailbox move, different pointer keys (`keywords/$seen` instead of `mailboxIds/<id>`). **The sharpest review finding:** the request *type* is generic, but the sole read-side accessor `mailbox_updates()` does `strip_prefix("mailboxIds/")` + `filter_map` (`jmap.rs:332-345`) — it **silently discards** every non-`mailboxIds/` key, and the live `aruna-jmap` transport consumes ONLY that accessor (`transport.rs:625-632`). Unfixed, a `SetFlag` over real HTTP is an empty `Email/set` that **reports success while doing nothing** — worse than a loud failure. The fix (`seam-extension-completeness`):
- Add `EmailSetRequest::set_keyword(account, email, keyword, value)` building a `keywords/$seen` → `Some(true)`/`None` patch (RFC 8620 PatchObject remove-by-null).
- **ONE total normalization/dispatch path, NOT per-prefix accessors.** A `keyword_updates()` sibling filter would repeat the defect (two projections that each ignore keys they don't own; the live transport's `__empty_email_set__` guard is an *emptiness* check, not an *exhaustiveness* check — a multi-prefix partial drop passes it). Instead the request exposes one total dispatch returning `Result`, which REJECTS: an unknown pointer prefix · a valid mailbox patch mixed with an unknown patch · a valid keyword patch mixed with an unknown patch · a record whose projected patch becomes empty · a multi-record request where one record is recognized and another is not. Pre-network whole-request validation is load-bearing (RFC 8620 §5.3: invalid PatchObjects rejected; per-object atomicity means a partial batch can otherwise escape).
- **BOTH consumers ride that path in this slice:** the fake applies `keywords/` patches to a per-email keyword set (mirrors `mailboxIds/` → memberships); the **live transport body-builder carries every recognized patch — or fails closed** (no silent no-op or silent-partial path survives). A **pure body-builder test** asserts the `keywords/$seen` wire shape.
- The JMAP connector's `apply` gains the `SetFlag` arm → build a keyword-set request → `email_set`.

### 3.5 Both connectors must match the new variant
`Action` is exhaustively matched in both `jmap.rs::apply` and `gmail.rs::apply` — adding `SetFlag` **forces** both to handle it (won't compile otherwise). That compile-time forcing is the neutrality guarantee: a new verb cannot land half-connected. (This is why we wire both now, not Gmail-only.)

## 4. The governance question — **separation HOLDS, part 2 ships (renamed)**
`ActionEnvelope.tier: Option<String>` (`lib.rs:70`) is **reserved** — the runtime, governance-authorized tier recorded per action-instance, frozen until the governance module lands. **This slice does NOT touch it.** Attempting the bypass confirmed the separation: no envelope write exists (`Command::new` defaults the whole envelope, `lib.rs:98-106`; envelope all-`None` at `:1760`); the enum materializes the already-P005-normative color vocabulary; and — the decisive byte — the reserved field is a different SEMANTIC AXIS (isolation/authority, test value `"isolated"` at `:1814`), not the risk color. External prior art concurs (MCP tool annotations are untrusted *hints* with enforcement in the authorization layer; OAuth mail scopes are coarse credential classes, not per-action risk). **Guards:** the classification is named `RiskTier`/`risk_tier()` (never bare `tier` — §3.2) — a MITIGATION, not impossibility (the reserved field stays `Option<String>`, so a deliberate conversion still compiles; the distinct name+type kills the accidental one-liner and the §5 no-flow guard test backs it); any envelope population, validation, or authorization derived from `risk_tier()` remains a freeze-crossing and is out of scope until the governance module lands.

## 5. Testing (TDD, mirror §1 + the new surfaces; ★ marks additions from review)
- **RiskTier:** `Archive/Unarchive/SetFlag{Seen}` each classify to the expected `RiskTier` (exhaustive); a `risk_tier()`-of-every-variant test that fails if a new variant **or new `MailFlag`** is added un-tiered (★ per-flag exhaustiveness).
- **Gmail behavior:** `SetFlag{Seen,true}` removes `UNREAD`; `SetFlag{Seen,false}` adds `UNREAD`; idempotent no-op repeat; surgical (unrelated labels survive); confinement (no leak); the inversion is correct (read ⇒ UNREAD absent).
- **JMAP behavior:** `SetFlag{Seen,true}` sets `$seen`; `{Seen,false}` clears it (PatchObject `null` removal); `Email/set` serializes to the `keywords/$seen` subset (shape test); confinement. ★ **Silent-drop closure (red-first on the pre-fix bytes):** a keyword request routed through the OLD `mailbox_updates()`-only path yields an empty patch — the probe that is RED before the dispatch fix and GREEN after (the §7 red-witness for the `seam-extension-completeness` class). ★ **Exhaustiveness, not just emptiness:** a **multi-prefix / partial** case — one recognized prefix mixed with one unrecognized — must be REJECTED whole, red-witnessed against the old per-prefix+emptiness path which silently part-applies it. ★ **Live-transport body-builder test:** the pure builder emits the `keywords/$seen` wire shape; an unrecognized patch shape fails closed, never an empty- or partial-success.
- ★ **Durable token grammar:** round-trip both values; unknown flag/value ⇒ `LogError` (fail-closed, red-witness vs a silent default); exact-match (a loose-prefix impostor token is rejected); `SCHEMA_VERSION` bumped — and the direction stated precisely: **an OLDER BINARY refuses a DB stamped with the newer token grammar**; the new binary accepts-and-raises an older DB (it does NOT refuse it). ★ Leaf: a version-binding test (decodable token family ⇔ stamped version).
- ★ **CapabilityMap completeness (per-flag):** both connectors' DEFAULT published maps carry the flag capability; `supports()` matches `MailFlag::Seen` with no `SetFlag{..}` wildcard; adding a `MailFlag` without a capability row fails the test.
- ★ **RiskTier no-flow guard:** `risk_tier()` never populates/validates/authorizes/gates `ActionEnvelope.tier`.
- **inverse:** `SetFlag{flag,value}.inverse() == SetFlag{flag,!value}` (both connectors honor it end-to-end) — asserted as the COMPENSATING inverse (§3.1b); no test claims pre-state restoration.
- **End-to-end through the bus** (both connectors): `SetFlag` → `Applied`, keyword/label set; deterministic reject → `Failed`; transient → `Pending`→RETRY_CAP→`Failed`.
- **Neutrality proof (the headline test):** the SAME `Action::SetFlag{Seen,true}` drives a label-removal on the Gmail fake AND a keyword-set on the JMAP fake — one verb, two mechanics.
- **Gates:** `cargo test --workspace` + `clippy -D warnings` + `RUSTDOCFLAGS="-D warnings" cargo doc` green.

## 6. Key decisions — **all ruled**
1. **Generalized `SetFlag`** — APPROVED 3/3, with constraints: `MailFlag` stays a closed enum restricted to reversible metadata flags; per-flag tiering; "next flag = one line" is retracted (each new flag needs its own grounded tier row).
2. **Both connectors** — APPROVED 3/3, conditional on the §3.4 `seam-extension-completeness` fix (the silent-drop made "fake-only JMAP" unsound anyway).
3. **Static classification vs the reserved envelope** — SEPARATION HOLDS 3/3 (§4); ships renamed `RiskTier`/`risk_tier()`.
4. **Slice size** — SPLIT: change A = corrected ADR-P005 amendment (doc), change B = the code cluster.
5. **Trash tier (C5)** — REVERSED: trash STAYS RED (P005's RED is *defined* as compensatable-reversible; P007 concurs; recoverability is target-state-dependent — trashed drafts unrecoverable); `discard-draft` separates; the research doc's claim is corrected to a tier-definition clarification.
6. **Undo semantics** — the `PrestateBlindCompensation` class is handled as claim-scoping + engine-wide naming + a tracked ADR-P007 obligation (§3.1b); pre-state capture is NOT built in this slice.

## 7. References
- `docs/research/2026-07-04-mail-action-taxonomy.md` (the grounding).
- §1: `docs/design/2026-06-27-m1-gmail-connector-design.md`; `crates/aruna/src/gmail.rs`, `jmap.rs`, `lib.rs`.
- ADR-P003 (neutrality), P004 (durable nouns), **P005 (color tiers — amended by this slice)**, P006 (envelope — reserved), P010 (capabilities) — `docs/adr/`.
- RFC 8621 §4.1.1 (JMAP keywords / `$seen`), RFC 9051 §2.3.2 (IMAP `\Seen`), Gmail `UNREAD` system label.

---

## Pre-review evidence (produce-phase check — discharged 2026-07-04)

> **Class:** design/spec for an **internal code change** — engine + two connectors, **fake-first, no network, no data movement, no live trust boundary** in-slice. The one genuine trust-boundary item is *governance-internal* (does static `Tier` touch the reserved envelope? — Item 5). Items 0 & 7 always live. This leaves a doubt, not a clearance.

**Item 0 — Requirement anchor.** *Claim:* §2 satisfies M1 verb-breadth + ADR build-order step 2 (the un-gated tier half), proving state-toggle-verb neutrality and landing the tier foundation. *Source:* the milestone plan (M1); ADR build-order step 2 (`docs/adr/:193`); ADR-P005 tier table lists `mark read/unread` as YELLOW (`:63`). *Falsification sentinel:* I'd know it failed if the same `Action::SetFlag{Seen,true}` did NOT drive *two different native mechanics* (Gmail `UNREAD`-label removal vs JMAP `$seen`-keyword set) — if it needed a provider concept above the seam, or forced a second `Action`-shaped change per provider, neutrality is unproven. *Cheapest alternative not taken:* a specific `MarkRead`/`MarkUnread` pair (§6.1) — rejected because the research proved state-toggles are a coherent class, so the generalized `SetFlag` is the honest shape at ~equal cost. *Out-of-scope boundary:* only `Seen` is wired; other flags, the runtime tier gate, and un-grounded verbs are deferred (§2).

**Item 1 — Data movement.** *None declared.* (a) *Reason:* fake-first, in-memory; no PII, no new store/sink/log/export. The only durable write is the existing intent-log row — and §3.1a keeps `SetFlag` inside the *existing* `(action_kind, message_ref)` schema (no new column, no migration). (b) *Checked:* `grep` the slice for `reqwest|std::net|std::fs|env::var` → empty (no live transport in-slice). (c) *Search:* the network/secret grep in the §3.5 build. (d) *Counterfactual:* data-lifecycle concerns apply only when the live `aruna-gmail`/`aruna-jmap` transports carry real mail — deferred, Part-III-gated.

**Item 2 — Prior art (two channels).** *External:* the committed research (`docs/research/2026-07-04-mail-action-taxonomy.md`) — RFC 8621 §4.1.1 (`$seen` keyword, **status: PROPOSED STANDARD, current**), RFC 9051 §2.3.2 (IMAP `\Seen`), Gmail `UNREAD` system label — **25/25 claims verified**. Adopted: the state-toggle-vs-location split, the `$`↔`\`↔label mapping, and the `trash`-is-reversible correction. *Internal:* the §1 `gmail.rs`/`jmap.rs` connectors + ADR-P003/P004/P005/P010; `EmailSetRequest` is already a generic `PatchObject` map (`jmap.rs:307` `update: BTreeMap<String, BTreeMap<String, Option<bool>>>`) so `keywords/$seen` reuses it with **zero seam change** — byte-verified. *Counter-evidence (what would have failed if I were wrong):* I checked `action_to_parts`/`action_from_parts` (`lib.rs:565-585`) — they carry **only** `(kind, message_ref)`, so a naive "just add a match arm" claim would have **failed** to persist `SetFlag`'s `flag`+`value`; §3.1a addresses it. And I checked `classify` keys on `message_ref` (`lib.rs:1345`) not the action variant, so it needs no change.

**Item 3 — Footguns (by class).** *Most-likely serious:* the **`Seen`↔`UNREAD` polarity inversion** — Gmail models the negative, so `SetFlag{Seen,true}`=read must REMOVE `UNREAD` (getting it backwards silently marks messages the wrong read-state). Structurally contained: the inversion lives in one place (the Gmail `apply` arm) with an explicit read⇒UNREAD-absent test (§5). *Highest-impact:* a **durable-encoding drift** — if `action_to_parts`/`from_parts` disagree on the `set_flag:seen:<value>` token, a stored row round-trips to the wrong verb; contained by a round-trip test + fail-closed parse (unknown flag/value → `LogError`, never a default — mirrors `Placement::from_token`, `jmap.rs:247`). *Partial-write/exhaustive-match:* every `match` on `Action` is exhaustive (no wildcard — verified `lib.rs:566/574/580`, both connector `apply`s), so the compiler forces the `SetFlag` arm everywhere; a new verb cannot land half-connected. *Not applicable:* concurrency (engine serializes via `execute(&mut self)`), N+1/scale (single-message).

**Item 4 — Abuse / misuse.** *Not live in-slice* (fake, no external actor surface). The abuse case (an agent bulk-marking mail read to hide it) becomes live only with the real transport + the governance envelope — an `ActionEnvelope`-tier concern (reserved), not this connector's; seams with Item 5 there.

**Item 5 — Trust boundary (security-first).** *The one live boundary is governance-internal:* **does introducing a static `Tier` enum + `Action::tier()` harden the reserved `ActionEnvelope.tier`?** (a) *Argued NO:* `ActionEnvelope.tier: Option<String>` (`lib.rs:70`) is the *runtime, governance-authorized* tier recorded per action-instance — frozen until the governance module lands. `Action::tier()` is a *static classification* (this verb IS yellow), pure and derivable, with **no envelope write, no gate behavior, no epoch/authority** — it is the ADR-P005 *label*, not the ADR-P006 *runtime field* (the ADR keeps them distinct: `:82` "classification drives the tier, not vice versa"). (b) *Checked:* the design writes nothing to `ActionEnvelope` and adds no gate/prompt. (c) *Reproducible:* `grep` the diff for `envelope`/`tier =` writes → must be empty. (d) *Counterfactual — the boundary this PREPARES:* provider-id confinement (ADR-P003/P004) — reused unchanged from §1 (id-free error codes; no provider handle above `apply` or in the log row). *Named control:* ADR-P003 no-leak law. *Residual:* if review rules that any `Tier` surface is envelope-hardening, part 2 drops (ship the verb un-tiered, tracked) — flagged §4/§6.3.

**Item 6 — Blast radius / gate-fit (four axes).** *6a Scope:* five coupled parts, one change — the ADR-P005 amendment (doc), `Tier`+`tier()` (engine), `SetFlag`+`inverse`+encoding (engine), Gmail arm, JMAP arm. Invariant after: the neutral seam (`Connector::apply`) is unchanged; `Action` grows one variant handled by every matcher. *(Decision §6.4: one change, or does the ADR amendment split first?)* *6b Reversibility:* fully reversible pre-merge (revert). The one durable commitment is the `set_flag:seen:*` on-disk token (§3.1a) — frozen contract once shipped, like `Placement::as_str`. *6c Surface/consumers:* **`Action` is a load-bearing frozen surface** — the neutral contract every connector + the durable serializer match on. Adding `SetFlag` is a consumer-contract change; all in-tree matchers are updated and the compiler enforces completeness. External connectors (future) must handle the new variant — that IS the neutrality contract. *6d Exposure:* if wrong in-slice — bounded to the fakes; no real user/data/network.

**Item 7 — Assumptions & open unknowns (NON-dischargeable — carried forward).**
1. **`Seen`↔`UNREAD` polarity** is correctly inverted in the Gmail arm — assumed; a backwards mapping is a silent wrong-state bug (tested, but the semantics assumption is load-bearing).
2. **The generalized `SetFlag` beats a specific pair** (§6.1) — assumed from the research; if review judges a one-variant `MailFlag` enum over-shape, fold to `MarkRead`/`MarkUnread`.
3. **Static `Tier` is not envelope-hardening** (§4/Item 5) — the "no fire drill" call; the ruling governs whether part 2 ships.
4. **Wiring both connectors now** (§6.2) is worth the slice size vs. deferring JMAP — assumed, because label-vs-keyword IS the proof.
5. **What could still be the wrong call?** — Bundling five parts (incl. a normative ADR amendment) in one change may be too big; the honest split is ADR-P005-fix-first as a doc change, then the code. If review strains on scope, split rather than push a mega-change.

**Item 8 — Verification pointer.** The §5 TDD matrix (RED-first): tier classification (+ the exhaustive-tier guard test), Gmail `UNREAD` inversion, JMAP `$seen` keyword set + `keywords/$seen` shape, the durable round-trip, `inverse` symmetry, end-to-end through the bus both connectors, and the headline **one-verb-two-mechanics** neutrality test. Failure signal that blocks: any inversion/round-trip/confinement test RED. Gates: `cargo test --workspace` + `clippy -D warnings` + `RUSTDOCFLAGS="-D warnings" cargo doc`.

> **Open doubt:** the design is byte-grounded and the durable-encoding ripple is now surfaced + solved migration-free — but the load-bearing calls are (a) whether static `Tier` respects the "no fire drill" envelope freeze, and (b) whether five coupled parts (one of them a normative ADR change) belong in one change or want splitting. Attack those two first.
>
> **Resolution note.** The pre-review evidence above is the first-draft discharge, kept as a record; where it conflicts with the review fixes, the fixes govern (§2/§3.1b/§3.2/§3.4/§4/§6). Both doubts were answered: (a) separation HOLDS, ships renamed `RiskTier`; (b) SPLIT — doc change first. First-draft claims corrected by review: "capability map reuses §1 unchanged" (false — it must grow, §3.3); "zero seam change — byte-verified" (true for the request type, false for the accessor read side, §3.4); the trash re-tier premise (reversed, §6.5); any implication that `inverse()` is faithful undo (scoped, §3.1b).
