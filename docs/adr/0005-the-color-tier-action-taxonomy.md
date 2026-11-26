# ADR-P005: The color-tier action taxonomy

**Status:** Accepted


> **Revised after review.** The verb table is grounded in the cited taxonomy research
> (`docs/research/2026-07-04-mail-action-taxonomy.md` — RFC 8620/8621/9051/5788/9979/6851, Gmail/Graph API
> docs). Changes: state-toggle verbs added to YELLOW; `trash` re-confirmed RED with its rationale written
> down (a proposed re-tier to YELLOW was rejected — RED is *defined* as the compensatable class, of which
> trash is the textbook case); `discard draft` and `empty trash` separated from generic trash as
> irreversible; one-way keywords noted; un-grounded verbs explicitly marked; the reversibility-versus-undo
> distinction fenced.
>
> **Approval mode.** The RED row's "per-action explicit approval" is per-DECISION under a configurable
> approval mode. Default (full-list) mode preserves the cell as written: the approver inspects every member
> row and one positive decision covers exactly the N inspected members, each individually digest-bound into
> the approved commitment. Aggregate mode (summary plus a random spot-check sample of k members) authorizes
> the same frozen, enumerated member set with one positive decision made against the bulk-triage design's
> mode-scoped view commitment. What aggregate approval authorizes is the full committed member set (every
> member digest-bound, identity-checked per child at send admission); what it attests is comprehension of
> the summary and sample only, and the journal records exactly that ("approved by summary + sample of k",
> never "N approvals"). Per-member send-admission binding, snapshot, and logging are unchanged in both
> modes; the knob is a logged configuration act.
>
> **Gmail spam arms.** mark-spam joins the RED row for the Gmail surface: SPAM-label add via the generic
> `users.messages.modify` operation (Gmail's dedicated Trash/Untrash routes have no spam sibling), undo =
> UnmarkSpam, recovery bounded by the Spam folder's provider-managed retention — compensatable-with-effort,
> the RED definition, with P007's heavier content-snapshot scope applying. The reverse arm, not-spam /
> UnmarkSpam = SPAM-label removal via the same operation, is YELLOW: a clean, unbounded,
> provider-supported toggle-back. Footnote 4's cross-provider grounding pass remains owed for every other
> surface; this entry grounds the Gmail arms only.
>
> **Gmail untrash.** untrash joins the YELLOW row for the Gmail surface — the reverse arm of `trash` (RED,
> footnote 3), via Gmail's dedicated `users.messages.untrash` route: a clean, provider-supported
> toggle-back within the provider's Trash window (footnote 3), with none of RED's bounded-recovery
> character. The tier lives in `Action::risk_tier` (`crates/aruna/src/lib.rs`);
> `RiskTier::requires_plan()` is true for RED and BLACK only, so an Untrash command is not refused for
> lacking a plan, and a plan link on it is refused `NotARedVerb` (witnessed by
> `s1_tiers_are_the_adr_p005_rows_and_only_red_requires_a_plan` and
> `s1_a_red_verb_without_a_plan_child_is_refused_pre_durable_and_a_yellow_verb_with_one_is_refused_too`).
>
> **Residual, for both reverse arms (Untrash and UnmarkSpam):** a restore reverses the verb's own closure
> only; a block rule or filter created independently of the verb (by the user or another client) sits
> outside that closure, and the restore leaves it in force. The YELLOW placement of both arms rests on
> Photon's own action set: no `Action` variant (`crates/aruna/src/lib.rs`) creates a block rule or filter,
> so within that set the toggle is clean. This entry grounds the Gmail arm only; untrash on every other
> surface carries no tier row until its own grounding pass.

**Decision.** Every action Photon can take — via UI, planner, or agent API — carries a mandatory tier label:

| Tier | Meaning | Mail verbs (current mapping) | Gate behavior |
| --- | --- | --- | --- |
| **GREEN** | Read-only, no mailbox mutation | metadata scan, search, folder list, single-message on-demand body preview | No prompt. Logged. |
| **YELLOW** | Reversible mutation — a clean, unbounded, provider-supported toggle/relocation | archive¹, label/unlabel, move between folders¹, mark read/unread, star/unstar, snooze¹, unmark spam (GMAIL ARM ONLY — see the revision note above; SPAM-label removal via `users.messages.modify`)⁴, untrash (GMAIL ARM ONLY — see the revision note above; dedicated `users.messages.untrash` route)³ | Batch-approvable in review queue. Snapshot before execution². Logged. |
| **RED** | Socially reversible / **compensatable** — recovery exists but is time-bounded, effortful, or socially mediated | move to trash³, mark spam (GMAIL ARM ONLY — see the revision note above; SPAM-label add via `users.messages.modify`)⁴, unsubscribe execution⁴, block sender⁴, filter/rule creation⁴ | Per-DECISION explicit approval under the configured approval mode (see the revision note above — full-list default: one decision covers exactly the N inspected members; aggregate: one decision against the mode-scoped commitment authorizes the full committed set, journaled as "summary + sample of k"). Snapshot². Logged with rationale. |
| **BLACK** | Irreversible or outbound | send, reply, forward, permanent delete, **empty trash**, **discard draft**⁵, filter/rule deletion⁴, account credential mutation | **Hard stop.** Always prompts for explicit positive human authorization, on every invocation. Never batch-approved. Maps to the irreversible class of ADR-P006's transaction model: the agent MUST NOT autonomously cross the pivot. |

¹ **Mechanic-divergent location verbs:** the *verb* is neutral but the *native mechanic* diverges per provider — archive is Gmail `INBOX`-label removal vs JMAP/Graph mailbox-move vs IMAP COPY/MOVE; snooze is a reversible move into the `Snoozed` role mailbox (RFC 9979 — which registers the mailbox attribute/role and expected storage semantics but expressly does NOT define the snooze/unsnooze mechanism itself; the mechanism verb rests on a still-open IETF draft). No clean cross-provider mechanic mapping; the connector seam absorbs the divergence (ADR-P003). State-toggle verbs map cleanly where grounded: **read** across all four surfaces (JMAP `$seen` ↔ IMAP `\Seen` ↔ Gmail `UNREAD` ↔ Graph `isRead`); **star/unstar** on JMAP/IMAP/Gmail (`$flagged`/`\Flagged`/`STARRED`) — Graph's `message.flag` is a structured `followupFlag`, so a future Graph star arm needs a preservation/mapping decision, not a naive Boolean toggle.

² **"Snapshot before execution" is the ADR-P007 normative contract, built in part.** Originally, undo of a YELLOW+ action was a **blind compensating inverse** — it applied the counter-action without knowing pre-state, so undoing an idempotent no-op manufactured a change the original action never made (the engine-wide `PrestateBlindCompensation` class). The engine now captures pre-state and restores it from the capture; the restore path is proven against hermetic transports only, so pre-state restoration against a live provider is still required before any **real-provider (live, Part-III-ungated)** YELLOW+ write or any restores-prior-state claim. **Terminology fence:** "compensating inverse" names the *machinery gap*; RED's "compensatable" names the *intrinsic reversibility class* that separates RED from YELLOW. YELLOW's "reversible" means the toggle mechanics are clean and unbounded — a claim about the VERB, never about the engine's undo machinery.

³ **Trash is RED, not YELLOW — held on review, rationale recorded:** recovery is real but *bounded and degraded* — Gmail `untrash` inside a ~30-day window, IMAP `\Deleted` before `EXPUNGE`, JMAP re-add-to-mailbox — and the message leaves the mailbox's normal reach (which is why P007 assigns trash the heavier full-RFC-822 snapshot scope). That is compensatable-with-effort, the definition of RED; YELLOW's clean unbounded toggle it is not. Recoverability is also **target-state-dependent**: a trashed *draft* is unrecoverable (official Gmail guidance), so the generic verb cannot assume YELLOW-grade recovery from the verb name alone — `discard draft` is its own BLACK-tier verb⁵, never folded into generic trash. Its reverse arm, `untrash`, is YELLOW on the Gmail surface (see the revision note above).

⁴ **Un- or partially-grounded verbs — tier provisional pending a dedicated grounding pass (tracked):** unsubscribe (RFC 8058 one-click), block/unblock sender, filter/rule create+delete (Sieve / RFC 9661 / Graph messageRules), mark-spam/not-spam (provider-dependent: reversible label vs filter-training + report-sending — **the GMAIL arms are grounded per the revision note above: mark-spam RED, not-spam/UnmarkSpam YELLOW; every other arm stays off the table until its own grounding pass**), mark-important — their current rows are held from the original sketch, not primary-source-verified. **Also parked here: mark-answered** (keyword grounded on JMAP/IMAP only; no verified Gmail/Graph mechanic — capability-limited support is not cross-provider mapping), **save-draft** (a content-bearing create/REPLACE, not a toggle — Gmail draft update replaces the contained message, JMAP's draft-update destroys the old Email; its natural inverse is the BLACK `discard draft` or a pre-state restore, i.e. the pre-state gap — so it fails YELLOW's own definition), **mute and follow/watch** (RFC 9979: `$muted`/`$followed` drive ONGOING automatic behavior — mute can archive/trash/mark-read future replies, follow can bypass filtering and trigger notifications — rule-like consequences, not effect-complete toggles, with an RFC-noted thread-hiding abuse concern; they need a consequence-based ruling like filter-creation, not a toggle tier). All stay OFF the tier table until grounded. Do not treat any of these placements as settled, and do not add new verbs from this set without the grounding pass. (`discard draft`⁵ IS grounded — official Gmail guidance — and stays BLACK.)

⁵ **Draft delete is irreversible** (cannot be recovered from Trash — official Gmail guidance), hence BLACK despite "just a draft" intuition; the taxonomy follows the reversibility fact, not the social feel.

**One-way keywords (noted, unplaced):** `$MDNSent` / `$Forwarded` are set-once ("SHOULD NOT be cleared", RFC 5788) — reversible-in-storage but semantically one-way, so they are NOT plain YELLOW toggles; any future verb built on them needs its own tier ruling (open sub-tier question, carried in the research doc).

Tier labels are part of each tool's published schema in the agent API — an agent knows the tier *before* calling. A user MAY configure bypass for YELLOW/RED gates or grant full access; that is a legitimate, logged choice. BLACK prompting cannot be disabled in latch mode. (Under control-plane governance, BLACK policy belongs to the control plane.)

**In code:** the static classification is `RiskTier` / `Action::risk_tier()` — deliberately NOT named bare `Tier`, because the reserved `ActionEnvelope.tier` (ADR-P006) is the *isolation/authority* axis, a different dimension from this *risk* color. Classification is per-verb AND per-parameter where a verb is parameterized (a `SetFlag` tier is the tier of its specific flag, never a wholesale variant tier). `risk_tier()` is pure metadata: it never populates, validates, authorizes from, or gates on `ActionEnvelope.tier` (the governance runtime remains reserved).

**Why.** This is the human-behavior actuary's sensor grid. The tier system is not primarily a *prevention* mechanism — users who want to hand their agent the keys will do so, and that's their right. It is a *measurement* mechanism: every prompt is a labeling event (approved → outcome fine = calibrated gate; bypassed → incident = enforcement gap; prompted constantly → bypassed always → no incident = miscalibrated friction). Over time this is the dataset nobody has: what humans actually tolerate, where they actually get burned, which action classes actually produce incidents. Static permission models guess; Photon measures.

**Rejected.** Binary safe/unsafe classification (loses the friction-calibration signal); tier assignment by the agent (the surface owns the taxonomy, callers don't get to self-classify); making BLACK bypassable in latch mode (one non-negotiable keeps the floor honest).
