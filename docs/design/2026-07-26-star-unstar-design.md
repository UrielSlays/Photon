# Design — Star/unstar: `MailFlag::Flagged` through both connectors (v2, 2026-07-26)

**Status:** Implemented (v2, revised after review).

**Slice:** the next un-gated M1 verb (board dependency order). A PATTERN-MIRROR slice: the second
member of the per-flag family (M1 §2 lineage). The
established pattern decisions are NOT re-opened; this doc specifies the deltas and — per review —
writes `Flagged`'s OWN grounding rather than inheriting `Seen`'s.

**Adversary model (pinned):** unchanged — provider responses on the write path are the
untrusted DATA surface, owned by the existing transport witnesses/classifiers; no new parse, no
new route, no new wire shape. Code already running on the user's machine with the user's
privileges is out of scope. Nothing claims an on-box wall.

## 1. Scope / non-goals

**In scope:** `MailFlag::Flagged` + every forced row (§3), the v7 stamp (§4), the mirrored +
generative test battery (§5), and a tracked obligation for the `$flagged`
rights/side-effect question (§2b).

**Non-goals (fences):** no Graph connector / `followupFlag` mapping · no `answered`/`draft` ·
no engine changes · no read-side/placement change (`STARRED` is placement-orthogonal **in the
current Photon projection** — `placement_from_mailbox_ids` consults only the resolved
inbox/archive ids, so even JMAP's possible `\Flagged` SPECIAL-USE membership cannot perturb it;
that is a statement about OUR projection, not a universal claim) · **no per-flag ACL
preflight/dynamic-rights machinery** (review ruled this out of scope: it is a full
capability-negotiation design needing live servers; the connector already maps ACL rejections to
typed deterministic errors — record the §2b obligation, ship the verb) · no live-Gmail drill
(a separate lane) · undo stays the blind compensating inverse (pre-state restoration is a separate obligation; see §2's per-flag note) ·
**parked named futures** (each would move interface and is deliberately NOT taken at the
family's SECOND member; revisit before the THIRD): bijective token table generating both
`action_to_parts`/`action_from_parts` (strum-style; kills the write/read asymmetry class
structurally) · two-integer version scheme (`min_reader_version` split) · reshaping
`CapabilityMap::custom` off positional bools.

## 2. The grounding (per-flag, as `lib.rs:30-32` demands — NOT inherited from Seen)

- **Mechanic grounding:** taxonomy `2026-07-04-mail-action-taxonomy.md:12`: star maps cleanly on
  JMAP `$flagged` · IMAP `\Flagged` · Gmail `STARRED` (manually-applicable system label; Graph
  = the parked caveat). Gmail `messages.modify` takes literal add/remove label arrays ⇒ DIRECT
  polarity.
- **Tier: YELLOW — same tier as Seen, DIFFERENT rationale:** a clean unbounded
  metadata toggle (P005), BUT what the blind compensating inverse can destroy differs: `Seen` is
  largely system-generated read-state (un-reading is an annoyance); **`Flagged` is user-authored
  curation** — for many users the starred set IS a to-do queue, so a blind inverse can destroy
  deliberate curation. Still YELLOW (metadata, reversible-in-kind, no content risk), and this
  paragraph is the honest per-flag record the pre-state obligation inherits. **Gmail
  "superstars" open question (named, no claim either way):** star VARIANTS (colors/symbols) are
  not representable in the boolean `STARRED` label; whether unstar→undo round-trips a
  non-default variant is UNVERIFIED pending a live drill — no faithful-restore claim is made.

### 2b. The `$flagged` authorization/side-effect obligation

RFC 8621 §2: `$seen` is the EXCEPTION keyword (right `maySetSeen`, IMAP ACL `s`); **every other
keyword incl. `$flagged` requires `maySetKeywords`** (IMAP ACL `w`), and the right must hold on
**all mailboxes containing the email** — a delegated principal holding `s` but not `w` marks
read successfully and FAILS to star. Additionally `$flagged` is
registered **Automatic** (setting it may make the message appear in a `\Flagged` SPECIAL-USE
mailbox) where `$seen` is advisory; and on shared stores it discloses urgency/attention
curation — a different privacy content than read-receipts. The existing `$seen` obligation does NOT
cover this. **A new tracked obligation** records: `maySetKeywords` disclosure + all-mailbox
evaluation + SPECIAL-USE side effect + shared-curation disclosure, gated with the same Part-III
live-validation lane as the `$seen` residuals. `tooManyKeywords` (RFC 8621 set error) is named as
inherited observability debt: today it falls to `SetError::Unknown` ⇒ deterministic fail-closed
— safe, unmodeled, noted on the same obligation.

## 3. The deltas (exhaustive; compiler-forced WHERE ENUM MATCHING APPLIES)

**Compiler-forced:**

| Chokepoint | Delta |
|---|---|
| `MailFlag` (`lib.rs:34`) | + `Flagged` ("message is starred/flagged"; positive on BOTH providers — no polarity inversion, unlike Seen/UNREAD) |
| `risk_tier()` (`lib.rs:90`) | + `SetFlag { flag: MailFlag::Flagged, .. } => RiskTier::Yellow` (§2's own grounding) |
| `action_to_parts` (`lib.rs:616`) | + `set_flag:flagged:true/false` |
| Gmail capability dispatch (`gmail.rs:253`) + map (`:217`) | + `set_flag_flagged` row, default-published; `custom()` widens to 4 args (call sites are all `#[cfg(test)]` — verified; the reshape is a parked future) |
| Gmail mechanic (`gmail.rs:358`) | + `LabelId::starred()` (`"STARRED"`) + `GmailModifyRequest::set_starred(value)`: true ⇒ add, false ⇒ remove — doc comment SAYS direct where Seen's says inverted |
| JMAP capability dispatch (`jmap.rs:423`) + map (`:385`) | + `set_flag_flagged` row, default-published |
| JMAP mechanic (`jmap.rs:563`) | + `SetFlag{Flagged,v}` ⇒ the existing private keyword builder **`EmailSetRequest::set_keyword("$flagged", v)`** (`jmap.rs:320` — v2 symbol correction) |

**NOT compiler-forced — the test/doc inventory the build MUST also touch:**

| Site | Forced edit |
|---|---|
| `action_from_parts` (`lib.rs:634-649`) | + `flagged` parse arms — string match with catch-all; **the write/read asymmetry closes via §5.0's generative round-trip witness**, not by trusting the compiler |
| Anti-sentinel `lib.rs:~3626-3637` | `unknown_or_inexact_set_flag_tokens_fail_closed` pins `set_flag:flagged:true` as must-fail — REPLACE that token with a still-unknown flag (e.g. `set_flag:answered:true`); it otherwise goes red on the faithful build and stays green on a half-build |
| `lib.rs:1730` + test name `:1696` | the ONE hard-coded stamp literal `assert_eq!(v, 6, …)` → 7 + rename (`…version_is_7`); `:2295`/`:2337` use the constant and survive |
| Test-only exhaustive matches `lib.rs:3027-3045`, `3103-3118` | + `Flagged` arms |
| Stale doc comments `lib.rs:40` · `gmail.rs:221,317` · `jmap.rs:389,491` | "archive/unarchive + SetFlag(Seen)" → include Flagged |
| Live transports | NO new routes (verified: `witness_applied` iterates request labels with no allowlist; the JMAP body-builder formats `keywords/{name}` generically) |

## 4. SCHEMA_VERSION 7, no DDL

The un-bumped alternative was reproduced live: a v6 binary reads a
`set_flag:flagged:true` row ⇒ row-level `LogError`; stamped 7 ⇒ refused at open. Bump.
**Honesty notes:** (a) the raise-only stamp fires AT OPEN — install v7, open once,
star nothing: the DB is v7 and a reverted v6 binary refuses it; **the slice is code-reversible
but NOT DB-reversible for any opened database** (manual `PRAGMA user_version` surgery is the
rollback; the deliberate, named price of open-time honesty). (b) The guard is
**SqliteIntentLog-constructor-scoped**: `SqliteMessageStore::open`/`SqliteMessageHeaderStore::
open` open the same file bare (pre-existing, inherited, named — not widened here).

## 5. Test plan (mirror + additions from review)

0. **Generative round-trip sentinel (new):** for EVERY `MailFlag` variant,
   `action_to_parts` ⇄ `action_from_parts` round-trips both values — a positive sentinel that
   grows itself; plus perturbation negatives derived from valid tokens (casing/truncation/
   suffix), replacing hand-pinned future-token negatives (the anti-sentinel class).
1. Gmail: `set_flag_flagged_true_adds_starred_and_false_removes_it` (DIRECT polarity — the
   two-sided assert catches a copied inversion) · surgical/idempotent on unrelated labels ·
   per-flag capability row incl. `custom` refusal · bus end-to-end Applied +
   `set_flag:flagged:true` durable round-trip · dead-letter deterministic + transient-at-cap.
2. JMAP: `$flagged` set/clear via `set_keyword` · capability row · bus end-to-end + durable
   round-trip · dead-letters.
3. Engine: risk_tier Yellow · `inverse()` flips value · v7 guard tests (incl. the `:1730`/
   `:1696` edits) · the §3 inventory edits land.
4. Live transports: JMAP body-builder emits `keywords/$flagged` · Gmail fixture asserts the
   **captured outbound JSON arrays** (Seen precedent `aruna-gmail/transport.rs:1890-1904`), not
   only the response echo — plus the applied-witness postcondition. **Named residual:** unstar against a
   response with absent `labelIds` passes the remove-check vacuously (the earlier read-side witness
   family, inherited, not new).

## Pre-review evidence (internal-code-change class — items 0,2,3,6,7 live; **item 4 is LIVE-BUT-GATED**, items 1/5 not-live: no new data class at the transport boundary, no new trust boundary — but see 2b's named disclosure residuals)

**0. Anchor:** board next-action; `lib.rs:30-32`'s per-flag contract — §2 IS the per-flag
grounding, written not inherited. **Sentinel (v2, honest):** the six enum sites are
compiler-witnessed; the non-forced inventory (§3 second table) is witnessed by §5.0 + the listed
test edits; the slice fails if any of those stays untouched. **Cheapest alternative not taken:**
wildcard arms (forbidden by the established rule). **2. Prior art:** INTERNAL: the Seen
implementation read at the byte; EXTERNAL:
RFC 8621 §2 rights + §10.4.3 `$flagged` registration + Gmail labels/modify references — each
verified at the primary source, including the taxonomy and labels-guide rows. **3. Footguns:** polarity copy-paste (→ §5.1 two-sided witness) · write/read token
asymmetry (→ §5.0) · anti-sentinel class (→ §3 inventory + §5.0's generative negatives) ·
hard-coded version literal (→ §3 inventory). **4. Abuse (live-but-gated):** bulk starring
mutates shared urgency/workflow signals visible to co-owners on shared stores — DEFERRED
explicitly with the Part-III gate (not "irrelevant"); the §2b obligation carries it. **6. Blast
radius:** one change; **code-reversible, NOT DB-reversible once opened** (§4, named); consumers:
workspace-internal; `custom()` arity is a signature break whose call sites are all test-mods
(verified). **7. Assumptions:** A1 (replaced in review): per-flag rights are DISTINCT — Seen →
`maySetSeen`, Flagged → `maySetKeywords`, all-mailbox evaluation; the §2b obligation is the tracked
close. A2: §4's bump ruling — confirmed by an executed check, no longer an open assumption. **8.
Verification:** §5 + workspace gates; failure signal = any §5 red staying red or a §3-inventory
site left untouched.

---

## v2 change log: A1 replaced with §2b + a new tracked obligation · per-flag YELLOW rationale
written (§2) · superstars open question named · §3 split into forced/not-forced with the
executed probe's six sites + the full test/doc inventory · symbol corrected to `set_keyword` ·
§4 reversibility + guard-scope honesty · §5.0 generative sentinel replaces hand-pinned
negatives · outbound-JSON assertion added · Item 4 re-scoped live-but-gated · parked futures
named in §1. No mechanism was added.
