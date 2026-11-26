# Photon — Account / Facet structural model (research-validated)

**Date:** 2026-06-20, refined 2026-06-21 · **Status:** STRUCTURAL MODEL **VALIDATED +
REFINED** by 2 independent research runs and a structural review. The *structure* is settled enough
to build against. The *language/core* decision (TS vs Rust for the engine) remains **OPEN** (see end).

## The merged durable model (7 layers + CapabilitySet)
Both research runs independently said "account/facet is right, but add a layer above account" — from two
angles. The union (neither alone is complete):

```
Realm  →  Grant/Credential  →  Account  →  Identity  →  Facet  →  Collection(role)  →  Item(account,facet,id)
```
- **Realm** — operational only: auth/discovery, quota, throttling rules, notification-lease renewal,
  provider-wide repair policy. (Graph throttles per-mailbox but quota/lease are provider-wide; Gmail quota
  is per-project *and* per-user.) **NOT an authority/isolation boundary.** (Report 2's catch.)
- **Grant/Credential** — one OAuth token / credential. **1 : many accounts** (shared/delegated mailboxes,
  JMAP multi-account sessions, Nylas grants). Separate from Account. (Report 1's catch; corrects the
  original "account = credential" collapse.)
- **Account** — the data container, **AND the authority / epoch / seizure / evidence boundary.** ★ Put
  governance at the Account, *not* the Realm (Realm is too coarse — would freeze every account under a
  provider; below-account loses atomic per-login seizure). Account = JMAP's own isolation unit = the
  governance unit.
- **Identity** — send-as / aliases. An **AXIS under Account, NOT a facet** (review caught
  Report 2 conflating send-identity, an outbox attribute, with syncable data facets).
- **Facet** — `mail | calendar | contacts` capability. Each facet owns its **cursor/state token,
  capability map, local projection schema, mutation queue, invalidation+rebuild policy, notification
  policy, conflict/ack semantics.**
- **Collection(role)** — `MailboxId/FolderId/LabelId · CalendarId · AddressBookId`, carrying a **role enum**
  (inbox/sent/drafts/trash/archive/junk + calendar/contacts defaults) normalized **above** the seam —
  kills Gmail label-as-folder duplication + i18n folder drift in one place. (Report 1's catch.)
- **Item** — durable ref is **always `(account, facet, id)`**; provider-native ids (IMAP UID+UIDVALIDITY,
  Gmail/Graph ids, CalDAV/CardDAV URL+ETag) stay **below the connector seam**; an **id-map table** below
  the seam maps stable-local-id ↔ (provider handle, validity epoch) so local ids survive UIDVALIDITY
  resets + account migration.
- **CapabilitySet** per `(account, facet)`; unsupported ops fail safe + visible.

## The architecture this sits in (both runs converged)
**Store-first system-of-record** (SQLite: canonical metadata + durable intent-log/outbox + pre-mutation
history) · **one serialized mutation boundary** shaped like **JMAP `*/set`** (batched, ordered, idempotent,
back-referenced; `EmailSubmission/set`+`onSuccessUpdateEmail` = atomic send-and-file; `undoStatus` = server
cancel) — *the internal command model even for non-JMAP providers* · **optimistic-apply-then-reconcile**
with provider-specific invalidation/rebuild · provider ids below the seam · build order JMAP → Gmail API
(not IMAP — label dedup) → Graph → IMAP4rev2 + CalDAV/CardDAV floor.

## ★ Two load-bearing design rules (so governance attaches later WITHOUT a spine transplant)
Keep the governance out of the *build* now — but design the *shape* so it bolts on:
1. **The command bus / durable intent record carries the `ActionEnvelope` SHAPE from line one** —
   reserve `principal / epoch / evidence-ref / tier` fields in the schema even while unused. The command
   bus IS the governance chokepoint (it already = ~80% of ADR-P006/P007/P008/P005); building it to carry
   only an idempotency key forces a retrofit = the spine transplant the ADR forbids.
2. **Evidence/snapshot gate sits between optimistic-apply and provider-submit.** Fail-closed gates the
   **provider dispatch**, NOT the optimistic local projection (local apply = a *pending* UI prediction in
   the FSM, not "the effect" in audit terms). Snapshot is captured at that PRE-COMMIT point, and
   **pre-state capture is sized per (facet, action)** — cheap for label/move (re-apply old labels), heavy
   for trash/delete (full RFC-822 source per P007) and calendar/contacts (full prior object). The outbox
   FSM needs an explicit `evidence-and-snapshot-written` state between apply and submit.

## Still OPEN (not closed by the research)
- **Language/core:** core-rewrite/shell-evolve is PROVEN; **TS-shell + Rust-hot-core-seam (MIME via
  pimalaya) + Tauri is a strong DEFAULT, not settled** — Report 1's TS landing partly rode the
  brief-supplied TS-code-sharing prior; drop that given and Rust-core is competitive. Hot-core/shell
  doctrine resolves most of it (command bus = I/O-bound = TS shell; MIME/index = native seam); a 1-week
  Rust-core spike on the vertical slice would settle it on merits if desired.
- **Server-authoritative premise:** both runs reject full local-first/CRDT for canonical mail truth —
  almost certainly right, but worth a *conscious* yes for a possibly-offline agent surface, not inherited
  (both runs share the same brief + sources, so convergence is slightly less independent than it looks).

## Provenance
Structural review (2026-06-20, byte-grounded in JMAP RFC 8620/8621/9610, JSCalendar 8984,
IMAP4rev2 9051, CalDAV 4791, CardDAV 6352) → confirmed account/facet. 2 independent deep-research runs
(2026-06-20/21: "Principal-Architect Survey" + "Decision-Oriented Research") → converged on store-first +
JMAP-set command bus + the layer-above-account refinement. Review of those runs → the
merged 7-layer model, the governance-at-Account rule, Identity-as-axis, and the two load-bearing design
rules above. Supersedes the original flat 2-axis capture.
