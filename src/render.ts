// The ONLY DOM-writing module ("textContent-equivalent sinks
// ONLY"; sink-fenced by `src/__tests__/sinkfence.test.ts`).
//
// No other file under `src/` may call `document.createElement` or assign `.textContent`. Every
// message-derived string (from_name, from_addr, subject, body text) reaches the DOM through
// `.textContent` — never `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`, and
// never a `title`/tooltip/notification sink.
//
// `from_name` AND `from_addr` each render inside their OWN `<bdi>` element (CSS `unicode-bidi:
// isolate` complements it in `styles.css`, targeting `bdi` generically) — the bidi isolate that
// stops a hostile RTL-override byte sequence in either field from visually swallowing/reordering
// what follows it (the spoof residual). Ingest preserves `from_addr` byte-for-
// byte (identity) exactly like `from_name`, so it gets the same isolation — display-
// side only, the underlying bytes are never touched.

import {
  elementScroll,
  observeElementOffset,
  observeElementRect,
  Virtualizer,
} from "@tanstack/virtual-core";
import type { InboxRow, LaneView, PlanReviewView, PlanRowView, RenderedViewWire, SessionStatus } from "./ipc";
import type { AppState, PlanReviewState, ReadingPaneState, Toast } from "./state";
import { cureCopyFor, formatReceivedAt, freshnessFooterText, rowVisualState } from "./state";

export const ROW_HEIGHT_PX = 56;

export interface RenderRoots {
  listScroll: HTMLElement;
  listInner: HTMLElement;
  readingPane: HTMLElement;
  statusBar: HTMLElement;
  toastRegion: HTMLElement;
  bannerRegion: HTMLElement;
  freshnessFooter: HTMLElement;
  /// The plan review's root.
  planReview: HTMLElement;
}

/// Reads the app skeleton's fixed IDs (`index.html`). Throws loudly on a missing root rather
/// than rendering into `null` silently.
export function queryRoots(doc: Document): RenderRoots {
  const get = (id: string): HTMLElement => {
    const el = doc.getElementById(id);
    if (!el) {
      throw new Error(`photon: missing required root #${id}`);
    }
    return el;
  };
  return {
    listScroll: get("list-scroll"),
    listInner: get("list-inner"),
    readingPane: get("reading-pane"),
    statusBar: get("status-bar"),
    toastRegion: get("toast-region"),
    bannerRegion: get("banner-region"),
    freshnessFooter: get("freshness-footer"),
    planReview: get("plan-review"),
  };
}

function clear(el: HTMLElement): void {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

// ===============================================================================================
// The virtualizer (@tanstack/virtual-core, element-scroll, fixed row height)
// ===============================================================================================

/// `@tanstack/virtual-core`'s `Virtualizer` does nothing on construction or a bare `setOptions`
/// call — there is no framework adapter here (React/Vue/Solid each call the same
/// two lifecycle methods from a mount effect), so this function IS the mount effect:
///   - `_didMount()` is called ONCE, here, right after construction. Its return value is the
///     unmount cleanup (`() => => void` — see `node_modules/@tanstack/virtual-core/dist/esm/
///     index.d.ts`); this app is a single long-lived page that never tears down its list, so
///     there is nothing to hand the cleanup to, but the mount call itself must still happen —
///     skipping it left `scrollElement` permanently `null` and no resize/scroll observer ever
///     attached, so `getVirtualItems()` always returned nothing.
///   - `onChange` is passed through so the virtualizer's own internal `notify()` (fired after a
///     scroll/resize-driven remeasure inside `_willUpdate()`) repaints without a caller having to
///     poll it.
export function createVirtualizer(
  count: number,
  scrollElement: HTMLElement,
  onChange: () => void,
): Virtualizer<HTMLElement, HTMLDivElement> {
  const virtualizer = new Virtualizer<HTMLElement, HTMLDivElement>({
    count,
    getScrollElement: () => scrollElement,
    estimateSize: () => ROW_HEIGHT_PX,
    overscan: 8,
    scrollToFn: elementScroll,
    observeElementRect,
    observeElementOffset,
    onChange,
  });
  virtualizer._didMount();
  return virtualizer;
}

// ===============================================================================================
// One row
// ===============================================================================================

/// Builds one row element. `from_name` and `from_addr` are set via two SEPARATE `.textContent`
/// assignments on two separate elements — never concatenated into one string first (source-scan
/// contract in `render-contract.test.ts`).
export function buildRowElement(row: InboxRow, selected: boolean, focused: boolean): HTMLElement {
  const el = document.createElement("div");
  el.className = "row";
  el.dataset.messageRef = row.message_ref;

  const visual = rowVisualState(row);
  if (visual.unread) {
    el.classList.add("unread");
  }
  if (selected) {
    el.classList.add("selected");
  }
  if (focused) {
    el.classList.add("focused");
  }

  const dot = document.createElement("span");
  dot.className = "unread-dot";
  el.appendChild(dot);

  const star = document.createElement("span");
  star.className = "star";
  star.textContent = visual.starred ? "★" : "☆";
  el.appendChild(star);

  const identity = document.createElement("span");
  identity.className = "identity";

  // <bdi> — the bidi isolate around the untrusted display name.
  const nameIsolate = document.createElement("bdi");
  nameIsolate.className = "from-name";
  nameIsolate.textContent = row.from_name; // SEPARATE assignment #1
  identity.appendChild(nameIsolate);

  const addr = document.createElement("span");
  addr.className = "from-addr";

  // <bdi>: from_addr is preserved byte-for-byte (identity), so it needs the SAME
  // bidi isolation the name gets above.
  const addrIsolate = document.createElement("bdi");
  addrIsolate.textContent = row.from_addr; // SEPARATE assignment #2
  addr.appendChild(addrIsolate);
  identity.appendChild(addr);

  el.appendChild(identity);

  const subject = document.createElement("span");
  subject.className = "subject";
  subject.textContent = row.subject;
  el.appendChild(subject);

  const date = document.createElement("span");
  date.className = "date";
  date.textContent = formatReceivedAt(row.received_at);
  el.appendChild(date);

  return el;
}

/// Renders the currently-visible virtual window into `roots.listInner`, sized to the
/// virtualizer's total measured height so native scrolling stays correct.
export function renderList(
  roots: RenderRoots,
  virtualizer: Virtualizer<HTMLElement, HTMLDivElement>,
  rows: InboxRow[],
  selected: ReadonlySet<string>,
  focusIndex: number,
): void {
  // `_willUpdate()` is what actually attaches `scrollElement` and its rect/offset observers (the
  // FIRST time it runs) and remeasures on every subsequent call — `getVirtualItems()` reads off
  // measurements it produces, so it must run on every paint, before `getVirtualItems()` below
  virtualizer._willUpdate();
  clear(roots.listInner);
  roots.listInner.style.position = "relative";
  roots.listInner.style.height = `${virtualizer.getTotalSize()}px`;

  for (const item of virtualizer.getVirtualItems()) {
    const row = rows[item.index];
    if (!row) {
      continue;
    }
    const el = buildRowElement(row, selected.has(row.message_ref), item.index === focusIndex);
    el.style.position = "absolute";
    el.style.top = "0";
    el.style.left = "0";
    el.style.width = "100%";
    el.style.height = `${item.size}px`;
    el.style.transform = `translateY(${item.start}px)`;
    roots.listInner.appendChild(el);
  }
}

// ===============================================================================================
// Freshness footer (RECONCILE)
// ===============================================================================================

export function renderFreshnessFooter(
  roots: RenderRoots,
  freshness: AppState["freshness"],
  hasRows: boolean,
  hasMore: boolean,
): void {
  clear(roots.freshnessFooter);
  const text = freshnessFooterText(freshness, hasRows, hasMore);
  if (!text) {
    return;
  }
  const line = document.createElement("p");
  line.className = "freshness-line";
  line.textContent = text;
  roots.freshnessFooter.appendChild(line);
}

// ===============================================================================================
// Reading pane
// ===============================================================================================

export function renderReadingPane(
  roots: RenderRoots,
  paneState: ReadingPaneState,
  onCopyFailed: () => void,
): void {
  clear(roots.readingPane);

  if (paneState.status === "empty") {
    const empty = document.createElement("p");
    empty.className = "reading-pane-empty";
    empty.textContent = "Select a message and press Enter to read it.";
    roots.readingPane.appendChild(empty);
    return;
  }

  // Opening a new message clears the previous one's content immediately — these two
  // arms render explicit "loading"/"error" states KEYED to `paneState.ref`, never leaving the
  // prior message's body on screen while a new fetch is in flight or after it fails.
  if (paneState.status === "loading") {
    const loading = document.createElement("p");
    loading.className = "reading-pane-loading";
    loading.textContent = "Loading…";
    roots.readingPane.appendChild(loading);
    return;
  }

  if (paneState.status === "error") {
    const error = document.createElement("p");
    error.className = "reading-pane-error";
    error.textContent = `Could not load this message — ${paneState.reason}`;
    roots.readingPane.appendChild(error);
    return;
  }

  const pane = paneState.text;

  if (pane.noBodyLine) {
    const noBody = document.createElement("p");
    noBody.className = "reading-pane-no-body";
    noBody.textContent = pane.noBodyLine;
    roots.readingPane.appendChild(noBody);
    // `NoTextualBody` still carries attachment presence (attachment-only mail) —
    // a bare early `return` here dropped that line on the one arm that most needed it.
    if (pane.attachmentLine) {
      const attachments = document.createElement("p");
      attachments.className = "reading-pane-attachments";
      attachments.textContent = pane.attachmentLine;
      roots.readingPane.appendChild(attachments);
    }
    return;
  }

  const body = document.createElement("pre");
  body.className = "reading-pane-body";
  body.textContent = pane.bodyText ?? "";
  roots.readingPane.appendChild(body);

  if (pane.truncatedMarker) {
    const truncated = document.createElement("p");
    truncated.className = "reading-pane-truncated";
    truncated.textContent = "(truncated)";
    roots.readingPane.appendChild(truncated);
  }

  if (pane.attachmentLine) {
    const attachments = document.createElement("p");
    attachments.className = "reading-pane-attachments";
    attachments.textContent = pane.attachmentLine;
    roots.readingPane.appendChild(attachments);
  }

  // Copy-only URL affordance ("URLs in bodies are not clickable (copy
  // only)... the copy path is named as carrying attacker-chosen bytes, residual"). No `href` is
  // ever assigned anywhere in this codebase (render-contract.test.ts).
  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.className = "copy-body-button";
  copyButton.textContent = "Copy body";
  // `navigator.clipboard` may not exist at all (no secure context — file://, a
  // non-HTTPS webview) and, even when it does, `writeText` may reject (permission denied, no
  // system clipboard). A bare `void`-ed promise swallowed both, so a copy failure was silent —
  // feature-detect the API first, then catch a rejection, either way routing through the same
  // toast action path every other verb outcome renders through.
  copyButton.addEventListener("click", () => {
    const clipboard = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
    if (!clipboard) {
      onCopyFailed();
      return;
    }
    clipboard.writeText(pane.bodyText ?? "").catch(() => {
      onCopyFailed();
    });
  });
  roots.readingPane.appendChild(copyButton);
}

// ===============================================================================================
// Status bar (session_status)
// ===============================================================================================

export function renderStatusBar(roots: RenderRoots, status: SessionStatus | null): void {
  clear(roots.statusBar);
  if (!status) {
    const loading = document.createElement("span");
    loading.className = "status-loading";
    loading.textContent = "loading session…";
    roots.statusBar.appendChild(loading);
    return;
  }

  const provider = document.createElement("span");
  provider.className = "status-provider";
  provider.textContent = status.provider_kind;
  roots.statusBar.appendChild(provider);

  const account = document.createElement("span");
  account.className = "status-account";
  account.textContent = status.account;
  roots.statusBar.appendChild(account);

  // `store_reason`/`provider_reason` ride the wire (session_status_view, lib.rs)
  // but used to go unread here — the status bar named ONLY the generic "not configured" label,
  // never WHY (a missing store file vs. an unreachable/expired provider read very differently to
  // the person staring at this line). Both reasons are independent facts (either, both, or
  // neither can be set) and are appended, joined, whenever present.
  const configured = document.createElement("span");
  configured.className = status.configured ? "status-configured" : "status-unconfigured";
  const configuredReasons = [status.store_reason, status.provider_reason].filter((r): r is string => r !== null);
  configured.textContent = status.configured
    ? "configured"
    : `not configured${configuredReasons.length > 0 ? ` (${configuredReasons.join("; ")})` : ""}`;
  roots.statusBar.appendChild(configured);

  // Same gap, `epoch_reason` — an unknown epoch used to render as bare "epoch
  // unknown" with no hint whether that is the store's own reason or something else entirely.
  const epoch = document.createElement("span");
  epoch.className = "status-epoch";
  epoch.textContent =
    status.epoch !== null
      ? `epoch ${status.epoch}`
      : `epoch unknown${status.epoch_reason !== null ? ` (${status.epoch_reason})` : ""}`;
  roots.statusBar.appendChild(epoch);

  if (status.credential_expires_at !== null) {
    const expires = document.createElement("span");
    expires.className = "status-credential-expiry";
    expires.textContent = `credential expires ${new Date(status.credential_expires_at * 1000).toLocaleString()}`;
    roots.statusBar.appendChild(expires);
  }

  // `credential_expired: true` is its OWN axis,
  // distinct from `mutations_live` — a dead OR expired-but-refreshable credential means every
  // provider READ now refuses too, not just writes. The notice text is NO LONGER a hard-coded
  // re-mint prompt: it branches on `status.credential_cure` through the SAME single-sourced
  // copy `toastForRefusal` reads (state.ts), so the status bar and the toast can never say
  // different things about the same cure. `credential_cure` should never be `null` while
  // `credential_expired` is `true` — that combination is a CONTRACT VIOLATION on the wire, not a
  // state this UI silently papers over; the fallback inside `cureCopyFor` NAMES the violation via
  // the honest "unrecognized reason" sentence rather than defaulting to a false re-mint demand.
  // Its own notice, its own class, so it never collapses into the mutations-fenced line below.
  //
  // The notice is no longer gated on the EXPIRY axis alone. A boot-time credential refusal is
  // `configured: false` with `credential_expired: false` — there is no arm, and often no expiry
  // stamp at all — and it now carries a cure; gated on `credential_expired` only, that cure
  // rendered nowhere and the operator read the raw refusal sentence trailing the "not configured"
  // line instead of the cure copy. The CLASS still tells the truth about which state this is: an
  // expiry is labelled an expiry, a cure with no expiry behind it is not.
  if (status.credential_expired || status.credential_cure !== null) {
    const cure = document.createElement("span");
    cure.className = status.credential_expired ? "status-credential-expired" : "status-credential-cure";
    // The lookup — BOTH hedges (a NULL discriminant, and a non-null one this
    // build's map has no row for, either of which would otherwise paint the literal word
    // "undefined") AND the choice of map — is `state.ts`'s `cureCopyFor`. A cure published by the
    // LOCAL boot stage (a file read, the boot lock, the grant ratchet) is not the provider's
    // answer, and this line held the refresh-stage map for both. The stage is now read
    // off `provider_reason`, not `configured` — a store that would not open makes `configured`
    // false over an ARMED credential whose cure came from a refresh attempt. Nothing about the
    // copy is decided here: this surface appends what the one selector returns, which is what
    // keeps it and the toast from ever saying two different things about one cure.
    cure.textContent = cureCopyFor(status);
    roots.statusBar.appendChild(cure);
  }

  // `mutations_live: false` means every write verb will refuse — a visible,
  // non-modal notice (NOT the BLACK banner: that is reserved for the kill-switch/severed state;
  // this is a build-arm fact, always true on the fence-gated production Gmail arm) carrying the
  // same reason the verbs themselves refuse with.
  if (!status.mutations_live) {
    const notice = document.createElement("span");
    notice.className = "status-mutations-fenced";
    notice.textContent = status.mutations_reason ?? "writes are not available in this build";
    roots.statusBar.appendChild(notice);
  }
}

// ===============================================================================================
// Toast (every verb outcome, undo affordance, stale line, typed refusal text)
// ===============================================================================================

export function renderToast(
  roots: RenderRoots,
  toast: Toast | null,
  // The bypass-lane retry handle is STATE-derived, read on
  // every paint off `state.pendingBypassPlan` — never a field the toast constructor carries (the
  // OLD `toast.retryPlanId`), so a refused Retry's replacement toast (any other refusal's, too)
  // never drops the control it has nothing to do with.
  pendingBypassRetryPlanId: string | null,
  onUndo: (keys: string[]) => void,
  onRetryPlan: (planId: string) => void = () => {},
): void {
  clear(roots.toastRegion);
  if (!toast) {
    return;
  }

  const box = document.createElement("div");
  box.className = "toast";
  if (toast.refusalKind) {
    box.classList.add(`toast-refusal-${toast.refusalKind}`);
  }

  const message = document.createElement("p");
  message.className = "toast-message";
  message.textContent = toast.message;
  box.appendChild(message);

  // A plan toast's extra lines — the refused member, each diverged atom — one per line.
  for (const line of toast.detail ?? []) {
    const detail = document.createElement("p");
    detail.className = "toast-detail";
    detail.textContent = line;
    box.appendChild(detail);
  }

  if (toast.staleReason) {
    const stale = document.createElement("p");
    stale.className = "toast-stale-line";
    // Kept byte-identical to `STALE_ROW_LINE` in `state.ts` — the old wording
    // ("refresh to confirm") promised an outcome for a door that can refuse.
    stale.textContent = "row not re-checked — the row shown is from before the write";
    box.appendChild(stale);
  }

  if (toast.undoKeys.length > 0) {
    const undoButton = document.createElement("button");
    undoButton.type = "button";
    undoButton.className = "toast-undo-button";
    undoButton.textContent = "Undo";
    undoButton.addEventListener("click", () => onUndo(toast.undoKeys));
    box.appendChild(undoButton);
  }

  // An incomplete bypass-lane plan's
  // retry handle — `plan_apply` on the SAME plan (the toast's detail names it, when this IS that
  // outcome's own toast); no mint, no screen, no approval. State-derived: rendered whatever
  // toast is showing, not only the one `plan_applied` itself produced.
  if (pendingBypassRetryPlanId !== null) {
    const retryButton = document.createElement("button");
    retryButton.type = "button";
    retryButton.className = "toast-retry-button";
    retryButton.textContent = "Retry";
    retryButton.addEventListener("click", () => onRetryPlan(pendingBypassRetryPlanId));
    box.appendChild(retryButton);
  }

  roots.toastRegion.appendChild(box);
}

// ===============================================================================================
// BLACK banner (kill-switch honesty: status-only, no actuator)
// ===============================================================================================

const BLACK_BANNER_TEXT =
  "Control seized (severed) — this session's write verbs are refused. This is a status display; " +
  "there is no control here to release it.";

export function renderBanner(roots: RenderRoots, severed: boolean): void {
  clear(roots.bannerRegion);
  if (!severed) {
    return;
  }
  const banner = document.createElement("div");
  banner.className = "black-banner";
  banner.textContent = BLACK_BANNER_TEXT;
  roots.bannerRegion.appendChild(banner);
}

// ===============================================================================================
// #75 S1 — the plan review (the plan HEADER, the coverage line and the verb-specific
// warning, the summary, and the per-member rows — or, on the aggregate lane, the derived sample —
// all from the canonical payload the engine answered; approval is a positive decision)
// ===============================================================================================

/// What the approve control hands back: EXACTLY the objects this screen renders from — the
/// canonical presentation on the full-list and bypassed lanes; the header, summary and derived
/// sample on the aggregate lane. Built from the review payload itself, never re-read from the
/// DOM; the engine recomputes the view commitment over it (`plan_approve`). `null` when an
/// aggregate review carries no sample — there is then nothing an approval could stand on.
export function renderedViewFor(review: PlanReviewView): RenderedViewWire | null {
  if (review.lane === "aggregate") {
    if (review.sample_k === null || review.sample_rows === null) {
      return null;
    }
    return {
      mode: "aggregate",
      header: review.presentation.header,
      summary: review.presentation.summary,
      sample_k: review.sample_k,
      sample_rows: review.sample_rows,
    };
  }
  return { mode: "full_list", presentation: review.presentation };
}

/// The approval-screen mode the plan froze (the knob's two modes, on screen).
const PLAN_LANE_LINE: Record<LaneView, string> = {
  per_member: "full list — every member is shown below",
  aggregate: "summary + a spot-check sample — not every member is shown",
  bypassed: "RED bypass is on — this plan was frozen for the bypass lane",
};

function textElement(tag: string, className: string, text: string): HTMLElement {
  const el = document.createElement(tag);
  el.className = className;
  el.textContent = text;
  return el;
}

/// The address isolate is split in two
/// (STRUCTURED-SENDER / NO-REPARSE): local-part and domain —
/// giving the domain its OWN isolate so a bidi-hostile local part's internal reordering (UTS #39
/// §3.3 "Other Issues") can never visually touch it (failing case: `PayPal <"א x@paypal.example ב"
/// @evil.example>` rendered with the visual tail reading `x@paypal.example`, the fake text sitting
/// where `evil.example` belongs, because both halves shared one isolate).
///
/// An earlier split ran a delimiter search (`lastIndexOf("@")`) over the composed `sender_address`
/// text — WRONG for a domain-LITERAL, whose own dtext may carry a further `@`
/// (`obs-dtext`/`dtext` do not exclude it): for `a@[x@trusted.example]`, `lastIndexOf` finds the
/// literal's INNER `@`, splitting the domain literal itself in two (a failing case).
/// An addr-spec's local-part (outside a quoted-string) cannot contain an unescaped `@`, so the
/// true boundary can never sit inside a domain literal — but TypeScript has no grammar here to
/// know that. This module now derives NOTHING address-shaped: `row.sender_local` and
/// `row.sender_domain` are the engine's own RFC 5322 grammar tokens (`crate::mailbox`), placed
/// directly into their isolates, with the `<`, `@`, `>` decoration as literal text nodes OUTSIDE
/// both (so the composed reading is still `<local@domain>`, but no split ever runs here).

/// A non-"ok" sender's status, in the SAME wording the
/// plan summary already uses for its per-reason counts — shown as its own atom, OUTSIDE both
/// address isolates, never synthesized text sitting inside one of them (the OLD rule put
/// "N From header fields" — `sender_address`'s multi-instance text — directly in the address
/// `<bdi>`, indistinguishable from a real address).
const PLAN_ROW_SENDER_STATUS_LABEL: Record<string, string> = {
  unavailable: "sender domain unavailable",
  malformed: "malformed sender header — normalized text shown",
  unsupported: "valid sender syntax not attributed (group or multiple mailboxes)",
};

/// One canonical row. The sender's name and address are each untrusted display text, and
/// each gets its OWN `<bdi>` isolation, SEPARATELY — exactly the
/// same isolation the inbox row gives `from_name`/`from_addr` (`buildRowElement` above), not a
/// composed `"{name} <{addr}>"` string in one shared isolate. The OLD single-isolate rendering let
/// a bidi-hostile display name visually reorder a fake address into the trailing, address-looking
/// position — a probe (`"א <billing@paypal.example> ב" <real@evil.example>` rendered with
/// the REAL address pushed out of its own trailing spot).
function buildPlanRow(row: PlanRowView): HTMLElement {
  const el = document.createElement("div");
  el.className = "plan-row";
  el.setAttribute("data-ref", row.message_ref);

  const identity = document.createElement("span");
  identity.className = "plan-row-identity";

  const nameIsolate = document.createElement("bdi");
  nameIsolate.className = "plan-row-sender-name";
  nameIsolate.textContent = row.sender; // SEPARATE assignment #1
  identity.appendChild(nameIsolate);

  const addr = document.createElement("span");
  addr.className = "plan-row-sender-address";
  const localIsolate = document.createElement("bdi");
  localIsolate.className = "plan-row-sender-address-local";
  const domainIsolate = document.createElement("bdi");
  domainIsolate.className = "plan-row-sender-address-domain";
  if (row.sender_status === "ok") {
    // The engine's OWN local-part/domain tokens go straight into their
    // isolates — never re-derived here (see the module doc above `buildPlanRow`) — with the
    // `<`/`@`/`>` decoration as plain text nodes OUTSIDE both isolates, so the composed reading is
    // still `<local@domain>`.
    addr.appendChild(document.createTextNode("<"));
    localIsolate.textContent = row.sender_local; // SEPARATE assignment #2
    addr.appendChild(localIsolate);
    addr.appendChild(document.createTextNode("@"));
    domainIsolate.textContent = row.sender_domain; // SEPARATE assignment #3
    addr.appendChild(domainIsolate);
    addr.appendChild(document.createTextNode(">"));
  } else {
    // A non-"ok" `sender_address` is not an address at
    // all (it is a synthesized sentence, e.g. "N From header fields", or the malformed raw text)
    // The isolates (and the decoration) stay EMPTY and the status atom below carries the
    // information instead, so nothing address-shaped ever holds non-address text.
    addr.appendChild(localIsolate);
    addr.appendChild(domainIsolate);
  }
  identity.appendChild(addr);

  if (row.sender_status !== "ok") {
    // The raw `sender_address` text is NOT an address for a non-"ok"
    // row (it is the engine's own synthesized sentence, or the malformed raw header, kept for
    // losslessness) — it rides in the STATUS atom's own isolate, never the address isolates.
    const status = document.createElement("span");
    status.className = "plan-row-sender-status";
    status.appendChild(document.createTextNode(`${PLAN_ROW_SENDER_STATUS_LABEL[row.sender_status] ?? row.sender_status}: `));
    const rawIsolate = document.createElement("bdi");
    rawIsolate.className = "plan-row-sender-status-raw";
    rawIsolate.textContent = row.sender_address;
    status.appendChild(rawIsolate);
    identity.appendChild(status);
  }

  el.appendChild(identity);
  el.appendChild(textElement("span", "plan-row-subject", row.subject));
  el.appendChild(textElement("span", "plan-row-date", row.date));
  el.appendChild(textElement("span", "plan-row-size", row.size === null ? "size unavailable" : `${row.size} bytes`));
  return el;
}

export function renderPlanReview(
  roots: RenderRoots,
  state: PlanReviewState | null,
  onApprove: (rendered: RenderedViewWire) => void,
  onCancel: () => void,
  onApply: () => void,
): void {
  // Focus moves INTO the review when it opens, and a re-render of an open
  // review keeps it inside — both read before the clear below removes the old panel.
  const opening = roots.planReview.firstChild === null;
  const focusInside = roots.planReview.contains(document.activeElement);
  clear(roots.planReview);
  if (!state) {
    return;
  }
  const { review, busy } = state;
  const { header, summary } = review.presentation;
  const panel = document.createElement("div");
  panel.className = "plan-review-panel";
  // Focusable, not tabbable: the panel itself takes the focus on open — never the approve control,
  // so an Enter on open can never approve a RED plan.
  panel.tabIndex = -1;

  panel.appendChild(
    textElement("h2", "plan-header", `${header.verb} · ${header.tier.toUpperCase()} · ${header.count} messages · account ${header.account}`),
  );
  panel.appendChild(textElement("p", "plan-lane", PLAN_LANE_LINE[review.lane] ?? review.lane));
  panel.appendChild(textElement("p", "plan-coverage", `backups: ${header.backup_coverage ? "on" : "off"}`));
  if (header.warning !== null) {
    panel.appendChild(textElement("p", "plan-warning", header.warning));
  }

  const summaryBlock = document.createElement("div");
  summaryBlock.className = "plan-summary";
  summaryBlock.appendChild(
    textElement("p", "plan-summary-count", `${summary.count} messages from ${summary.sender_domains.length} sender domains`),
  );
  const domains = document.createElement("ul");
  domains.className = "plan-summary-domains";
  for (const [domain, count] of summary.sender_domains) {
    const item = document.createElement("li");
    item.className = "plan-summary-domain";
    const name = document.createElement("bdi");
    name.textContent = domain;
    item.appendChild(name);
    item.appendChild(textElement("span", "plan-summary-domain-count", ` · ${count}`));
    domains.appendChild(item);
  }
  summaryBlock.appendChild(domains);
  // The complement rule: a sender the engine could
  // not parse is never a domain entry — the summary SAYS how many it cannot name a domain for, by
  // why, each on its own line. `malformed` and `unsupported` are NOT the same claim: `malformed`
  // means the header does not parse under the grammar at all; `unsupported` means it parses fine
  // (a group, or a mailbox-list of more than one) but is not one sender Photon attributes. Where
  // the fallback text shown is the displayed sender, it is the NORMALIZED text (the ingest
  // chokepoint's `header_normalize::normalize_display`), never the raw wire bytes.
  const members = (n: number) => `${n} member${n === 1 ? "" : "s"}`;
  if (summary.sender_domain_unavailable > 0) {
    summaryBlock.appendChild(
      textElement("p", "plan-summary-unavailable", `sender domain unavailable for ${members(summary.sender_domain_unavailable)}`),
    );
  }
  if (summary.sender_header_malformed > 0) {
    summaryBlock.appendChild(
      textElement("p", "plan-summary-malformed", `malformed sender header for ${members(summary.sender_header_malformed)} — normalized text shown`),
    );
  }
  if (summary.sender_header_unsupported > 0) {
    summaryBlock.appendChild(
      textElement(
        "p",
        "plan-summary-unsupported",
        `valid sender syntax Photon does not attribute (group or multiple mailboxes) for ${members(summary.sender_header_unsupported)} — no sender address`,
      ),
    );
  }
  summaryBlock.appendChild(textElement("p", "plan-summary-dates", `${summary.date_min} – ${summary.date_max}`));
  summaryBlock.appendChild(
    textElement("p", "plan-summary-size", summary.total_size === null ? "size unavailable" : `${summary.total_size} bytes`),
  );
  panel.appendChild(summaryBlock);

  // The rows the screen SHOWS are the rows the echo carries: the aggregate lane shows only the
  // derived sample, in the order the engine derived it; every other lane shows every member in
  // the payload's canonical order.
  const echo = renderedViewFor(review);
  let shown: PlanRowView[] = review.presentation.rows;
  if (review.lane === "aggregate") {
    shown = review.sample_rows ?? [];
    panel.appendChild(
      textElement(
        "p",
        "plan-sample-caption",
        review.sample_k === null ? "the review carries no sample — it cannot be approved" : `sample of ${review.sample_k} (derived by the engine, in its order)`,
      ),
    );
  }
  const list = document.createElement("div");
  list.className = "plan-rows";
  for (const row of shown) {
    list.appendChild(buildPlanRow(row));
  }
  panel.appendChild(list);
  panel.appendChild(textElement("p", "plan-expires", `approval window ends ${review.expires_at}`));

  const controls = document.createElement("div");
  controls.className = "plan-controls";
  if (review.approved && !review.terminal) {
    // APPROVED and not terminal — the approval is write-once, so the control
    // is Apply: it runs the plan again (a run that stopped, or an approval never applied) and
    // sends no second approval.
    const apply = document.createElement("button");
    apply.type = "button";
    apply.className = "plan-apply";
    apply.textContent = `Apply ${header.count} — ${header.verb}`;
    apply.disabled = busy;
    apply.addEventListener("click", () => onApply());
    controls.appendChild(apply);
  } else {
    const approve = document.createElement("button");
    approve.type = "button";
    approve.className = "plan-approve";
    approve.textContent = `Approve ${header.count} — ${header.verb}`;
    approve.disabled = busy || review.approved || echo === null;
    approve.addEventListener("click", () => {
      if (echo !== null) {
        onApprove(echo);
      }
    });
    controls.appendChild(approve);
  }
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "plan-cancel";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => onCancel());
  controls.appendChild(cancel);
  panel.appendChild(controls);

  roots.planReview.appendChild(panel);
  if (opening || focusInside) {
    panel.focus();
  }
}

// ===============================================================================================
// The one entry point main.ts calls after every dispatch
// ===============================================================================================

export function renderAll(
  roots: RenderRoots,
  virtualizer: Virtualizer<HTMLElement, HTMLDivElement>,
  state: AppState,
  onUndo: (keys: string[]) => void,
  onCopyFailed: () => void,
  onPlanApprove: (rendered: RenderedViewWire) => void,
  onPlanCancel: () => void,
  onPlanApply: () => void,
  onPlanRetry: (planId: string) => void,
): void {
  renderStatusBar(roots, state.status);
  renderList(roots, virtualizer, state.rows, state.selected, state.focusIndex);
  renderFreshnessFooter(roots, state.freshness, state.rows.length > 0, state.hasMore);
  renderReadingPane(roots, state.readingPane, onCopyFailed);
  renderToast(roots, state.toast, state.pendingBypassPlan?.planId ?? null, onUndo, onPlanRetry);
  renderBanner(roots, state.severed);
  renderPlanReview(roots, state.planReview, onPlanApprove, onPlanCancel, onPlanApply);
}
