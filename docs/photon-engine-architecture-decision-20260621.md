# Photon — Engine Architecture Decision Record (v1)

**Date:** 2026-06-21 · **Status:** Decided. Grounded in 2 research runs and a structural review. Points at, does not restate, the evidence: see
`account-facet-model-20260620.md`.

## Decision driver
**Fast + runs on almost anything — especially low-end hardware.** Footprint and performance on
weak hardware is the binding constraint. The current codebase is **fully scrappable** (it was built for a
different project); we are not bound to any existing language/framework choice. "It's an open field."

## Decisions

### D1 — Shell: **Tauri** (Rust core + the OS's installed WebView). NOT Electron, NOT fully-native.
- Electron bundles Chromium → 150–300MB RAM, heavy installer — fails the low-end-hardware constraint.
- Fully-native per-OS → best footprint but ~3× build cost; overkill for team size.
- **Tauri** = Rust core + OS WebView2 (already on every Win10/11 box) → ~30–50MB RAM, tiny installer,
  native-speed Rust hot paths. Same web-in-native-WebView pattern "New Outlook" uses (Apple Mail = native;
  classic Outlook = Win32; New Outlook = Edge WebView2). Best fit for "runs on almost anything."

### D2 — Language: web/TS UI in the WebView + **native Rust for hot-cores**. Open field, perf-driven.
- The UI/shell is web (TS) running inside Tauri's **OS** WebView (light — not a bundled engine).
- Genuine hot-cores go **native Rust** (Tauri's core is Rust anyway): **MIME parsing at volume** first;
  **metadata indexing** only if benchmarks force it. The I/O-bound command bus / sync orchestration is
  shell (TS or Rust — decide at the spike; not load-bearing).
- Frontend framework: React (keep) **or** a lighter one (Solid/Svelte) — decided at the spike by low-end
  list-scroll perf. Not load-bearing now.
- *Not* settled by ecosystem-fashion; settled by footprint/perf on weak hardware. (This supersedes v5's
  "TS-because-ecosystem" default — don't keep TS just for code-sharing.)

### D3 — Build shape: **core-rewrite / shell-evolve (strangler-fig).**
- **Scrap:** the Python/FastAPI mutation+connector layer (read-only today; lowest sunk cost; built for a
  different project).
- **Keep-or-swap (not load-bearing):** the React UI and the SQLite *schema concept* (the domain model is
  worth salvaging even if the access layer is rewritten).
- **Build new:** the store-first core (below).

### D4 — Core architecture (both research runs converged):
Store-first **SQLite system-of-record** (canonical metadata + durable **intent-log/outbox FSM** +
pre-mutation history) · **one serialized mutation boundary** shaped like **JMAP `*/set`** (batched,
ordered, idempotent, back-referenced; `EmailSubmission/set`+`onSuccessUpdateEmail` = atomic send-and-file;
`undoStatus` = server cancel) — the internal command model **even for non-JMAP providers** ·
**optimistic-apply-then-reconcile** with provider-specific invalidation/rebuild · provider ids **below the
connector seam** · UI never calls a connector.

### D5 — Data model: the merged 7-layer account model.
`Realm → Grant/Credential → Account → Identity → Facet → Collection(role) → Item(account,facet,id)` +
CapabilitySet per (account,facet). **Governance/epoch/seizure boundary = the Account** (not the Realm).
Full detail: `account-facet-model-20260620.md`.

### D6 — Two load-bearing design rules (governance attaches later WITHOUT a spine transplant):
1. The command bus / durable intent record **carries the `ActionEnvelope` shape from line one**
   (reserve principal/epoch/evidence-ref/tier fields), even though governance isn't built now.
2. **Evidence/snapshot gate between optimistic-apply and provider-submit** — fail-closed gates the
   *provider dispatch*, not the optimistic local projection; snapshot at PRE-COMMIT; pre-state sized per
   (facet, action) (cheap for label/move, heavy for trash/delete + calendar/contacts).

### D7 — Provider build order: JMAP-first (test vs self-hosted **Stalwart** / Fastmail) → **Gmail API**
(not IMAP — label-as-folder dedup) → **Microsoft Graph** (budget 429/throttling) → **IMAP4rev2 +
CalDAV/CardDAV** as the universal floor. Calendar/contacts via JSCalendar (RFC 8984) + CalDAV/CardDAV
(JMAP Calendars still a draft).

### D8 — Vertical slice that proves the architecture (the first build):
One account, mail facet, JMAP **or** Gmail API → command bus → SQLite intent log → optimistic apply →
reconcile → **undo** of label/move/archive, plus an outbox **send** with client-side undo window.
Floor-check gates: header search <1s @1M, folder switch <100ms, idle RAM in the Tauri ~30–50MB class.

## Still open (settle at the spike / consciously, not load-bearing now)
- Exact frontend framework (React vs Solid/Svelte) — low-end list-scroll perf decides.
- Command-bus language (TS vs Rust) — decide once the slice exists; the seam makes it cheap to move.
- The server-authoritative premise (reject full local-first/CRDT) — almost certainly right; confirm
  consciously for an offline-capable agent surface rather than inheriting it.

## Next action
Hands-on **code-reading pass** on the pinned commits — aerc (`0.20.1`/`2ecb877`), Thunderbird-Android
(`THUNDERBIRD_16_1`/`9dfc10b`), Mailspring (`1.19.0`/`29769fa`), Stalwart (`v0.16.9`/`3a87174`,
docs-only/AGPL), pimalaya (`oauth-v2.0.0`/`48e4596`) — to close the two gaps the research can't: (a) is the
single mutation boundary real in code or leaked into features, (b) how is canonical local identity modeled
under mutable/duplicated provider ids — and **verify pimalaya's MIT per-crate before lifting.** This is a code-reading
job, not another deep-research run. (Stalwart-for-testing doesn't trip AGPL — internal use, not
distribution — but flag for counsel before anything bundles/depends on it, since the product is commercial.)
