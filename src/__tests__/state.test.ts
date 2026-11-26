// The reducer's pure-logic contracts.
import { describe, expect, it } from "vitest";
import type { PerMessageAttempt, PlanUndoStep } from "../state";
import {
  acceptBody,
  bodyRequestFor,
  clampFocus,
  COPY_FAILED_MESSAGE,
  CURE_COPY,
  cureCopyFor,
  deriveBatchOutcome,
  fenceToast,
  formatReceivedAt,
  freshnessFooterText,
  initialState,
  isAtPageBoundary,
  isSeveredSignal,
  loadMoreAction,
  opensReviewScreen,
  PLAN_REFUSAL_COPY,
  planRefusalMessage,
  selectionTargets,
  toastForPlanApply,
  toastForPlanBypass,
  toastForPlanUndo,
  readingPaneTextFor,
  reduce,
  rejectBody,
  rowVisualState,
  shouldLoadMoreOnMoveDown,
  shouldRefreshStatus,
  starVerbLabel,
  toastForBatch,
  restorationLine,
  toastForRefusal,
  toastForUndo,
  toastForVerb,
  toggleSelect,
  unconsumedUndoKeys,
  UNCONFIGURED_CURE_COPY,
  undoKeysForBatch,
  verbsAllowed,
  windowReloadDepth,
  clearSupersededPacingToast,
  reopensReviewAfterRun,
  isTerminalRefusal,
  UNDO_STILL_AVAILABLE_MESSAGE,
} from "../state";
import * as fs from "node:fs";
import * as path from "node:path";

// The shell's production modules: src-tauri/src/lib.rs plus the modules split out of it.
const SHELL_MODULES = ["lib.rs", "error.rs", "single_flight.rs", "credential.rs", "session.rs", "provider.rs", "state.rs", "status.rs", "ipc.rs", "plumbing.rs", "verbs.rs", "plan.rs"];
const readRepo = (...p: string[]) => fs.readFileSync(path.resolve(__dirname, "..", "..", ...p), "utf8").split(String.fromCharCode(13)).join("");
/** Each shell module with its `#[cfg(test)] mod tests` block cut off, joined. */
function shellProduction(): string {
  const NL = String.fromCharCode(10);
  const marker = NL + "#[cfg(test)]" + NL + "mod tests {";
  return SHELL_MODULES.map((f) => {
    const source = readRepo("src-tauri", "src", f);
    const at = source.indexOf(marker);
    return at >= 0 ? source.slice(0, at) : source;
  }).join(NL);
}
import { SEVERED_REFUSED_REASON, SEVERED_UNDO_PRESENTATION } from "../ipc";
import type { PlanApplyOutcome, PlanReviewView } from "../ipc";
import type { Cure, InboxRow, RestorationView, SessionStatus, SurfaceError, UndoPresentationView } from "../ipc";

function makeStatus(overrides: Partial<SessionStatus> = {}): SessionStatus {
  return {
    provider_kind: "gmail",
    account: "a@example.com",
    store_path: "/tmp/store",
    configured: true,
    store_reason: null,
    provider_reason: null,
    credential_expires_at: null,
    credential_expired: false,
    credential_cure: null,
    epoch: 1,
    epoch_reason: null,
    mutations_live: true,
    mutations_reason: null,
    ...overrides,
  };
}

function makeRow(messageRef: string): InboxRow {
  return {
    message_ref: messageRef,
    received_at: 1754745600000,
    from_addr: "a@example.com",
    from_name: "A",
    subject: "subject",
    seen: true,
    flagged: false,
  };
}

describe("clampFocus — selection move clamps at both ends", () => {
  it("does not go below index 0", () => {
    expect(clampFocus(0, -1, 10)).toBe(0);
    expect(clampFocus(2, -5, 10)).toBe(0);
  });

  it("does not exceed the last row", () => {
    expect(clampFocus(8, 5, 10)).toBe(9);
    expect(clampFocus(9, 1, 10)).toBe(9);
  });

  it("moves freely inside the range", () => {
    expect(clampFocus(3, 1, 10)).toBe(4);
    expect(clampFocus(3, -1, 10)).toBe(2);
  });

  it("collapses to 0 for an empty list", () => {
    expect(clampFocus(5, 1, 0)).toBe(0);
  });
});

describe("toggleSelect — pure Set toggling", () => {
  it("adds an unselected ref and removes a selected one, without mutating the input", () => {
    const original = new Set(["a"]);
    const added = toggleSelect(original, "b");
    expect(added).toEqual(new Set(["a", "b"]));
    expect(original).toEqual(new Set(["a"])); // input untouched

    const removed = toggleSelect(added, "a");
    expect(removed).toEqual(new Set(["b"]));
  });
});

describe("deriveBatchOutcome — batch archive tri-state bookkeeping", () => {
  it("5 rows, failing at #3, yields 2 succeeded / 1 failed / 2 not-attempted (fail-stop)", () => {
    const refs = ["m1", "m2", "m3", "m4", "m5"];
    const results: PerMessageAttempt[] = [
      { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
      { message_ref: "m2", ok: true, undo_key: "u2", projection: { state: "current" } },
      { message_ref: "m3", ok: false, reason: "provider refused" },
      // m4 and m5 were never attempted — fail-stop.
    ];

    const outcome = deriveBatchOutcome(refs, results);

    expect(outcome.succeeded).toEqual([
      { message_ref: "m1", undo_key: "u1", projection: { state: "current" } },
      { message_ref: "m2", undo_key: "u2", projection: { state: "current" } },
    ]);
    expect(outcome.failed).toEqual({ message_ref: "m3", reason: "provider refused" });
    expect(outcome.notAttempted).toEqual(["m4", "m5"]);
  });

  it("all succeed ⇒ nothing failed and nothing left not-attempted", () => {
    const refs = ["m1", "m2"];
    const results: PerMessageAttempt[] = [
      { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
      { message_ref: "m2", ok: true, undo_key: "u2", projection: { state: "current" } },
    ];
    const outcome = deriveBatchOutcome(refs, results);
    expect(outcome.succeeded).toHaveLength(2);
    expect(outcome.failed).toBeNull();
    expect(outcome.notAttempted).toEqual([]);
  });

  it("fails on the very first message ⇒ 0 succeeded, 1 failed, the rest not-attempted", () => {
    const refs = ["m1", "m2", "m3"];
    const results: PerMessageAttempt[] = [{ message_ref: "m1", ok: false, reason: "busy" }];
    const outcome = deriveBatchOutcome(refs, results);
    expect(outcome.succeeded).toEqual([]);
    expect(outcome.failed).toEqual({ message_ref: "m1", reason: "busy" });
    expect(outcome.notAttempted).toEqual(["m2", "m3"]);
  });
});

describe("batch outcome carries projection-stale through to the toast", () => {
  it("a batch where attempt #2 succeeds with a Stale projection ⇒ the toast payload carries the stale marker", () => {
    const refs = ["m1", "m2"];
    const results: PerMessageAttempt[] = [
      { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
      {
        message_ref: "m2",
        ok: true,
        undo_key: "u2",
        projection: { state: "stale", reason: "refresh_reconcile has not run since this write" },
      },
    ];
    const outcome = deriveBatchOutcome(refs, results);
    const toast = toastForBatch("archive", outcome);

    expect(toast.staleReason).not.toBeNull();
  });

  it("no succeeded attempt is Stale ⇒ the toast carries no stale marker", () => {
    const refs = ["m1", "m2"];
    const results: PerMessageAttempt[] = [
      { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
      { message_ref: "m2", ok: true, undo_key: "u2", projection: { state: "current" } },
    ];
    const outcome = deriveBatchOutcome(refs, results);
    const toast = toastForBatch("archive", outcome);

    expect(toast.staleReason).toBeNull();
  });
});

describe("undoKeysForBatch — the toast carries succeeded keys in REVERSE order", () => {
  it("reverses the succeeded list (last-applied-first undo)", () => {
    const outcome = deriveBatchOutcome(
      ["m1", "m2", "m3"],
      [
        { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
        { message_ref: "m2", ok: true, undo_key: "u2", projection: { state: "current" } },
        { message_ref: "m3", ok: true, undo_key: "u3", projection: { state: "current" } },
      ],
    );
    expect(undoKeysForBatch(outcome)).toEqual(["u3", "u2", "u1"]);
  });
});

describe("freshnessFooterText — derived from Freshness.stale_below", () => {
  it("renders nothing when stale_below is 0", () => {
    expect(freshnessFooterText({ checked_through: null, stale_below: 0 })).toBeNull();
  });

  it("renders nothing when freshness itself is absent (never refreshed)", () => {
    expect(freshnessFooterText(null)).toBeNull();
    expect(freshnessFooterText(undefined)).toBeNull();
  });

  it("renders the count when rows below the window were not re-checked", () => {
    expect(freshnessFooterText({ checked_through: null, stale_below: 12 })).toBe(
      "12 older messages not re-checked",
    );
  });
});

// ===================================================================================================
// A fresh store's page-1 reconcile lands `stale_below: 0` (nothing BELOW the
// window is stale yet) even when the provider still holds more messages (`has_more: true`) — the
// two facts are orthogonal, and `hasMore: true` must render its own line regardless of
// `stale_below`.
// ===================================================================================================
describe("freshnessFooterText — has_more provider continuation footer", () => {
  it("renders the load-more line when hasMore is true even though stale_below is 0", () => {
    expect(freshnessFooterText({ checked_through: null, stale_below: 0 }, true, true)).toBe(
      "more messages on the provider — press j at the bottom to load more",
    );
  });

  it("does not render the load-more line when hasMore is false", () => {
    expect(freshnessFooterText({ checked_through: null, stale_below: 0 }, true, false)).toBeNull();
  });

  it("combines the load-more line with a nonzero stale_below line", () => {
    expect(freshnessFooterText({ checked_through: null, stale_below: 12 }, true, true)).toBe(
      "12 older messages not re-checked · more messages on the provider — press j at the bottom to load more",
    );
  });

  it("combines the load-more line with the never-refreshed-this-session line", () => {
    expect(freshnessFooterText(null, true, true)).toBe(
      "not yet refreshed this session — press r · more messages on the provider — press j at the bottom to load more",
    );
  });
});

describe("isSeveredSignal — the typed-tag match, never substring", () => {
  it("matches the exact SurfaceError::Refused{reason:\"Severed\"} shape", () => {
    expect(isSeveredSignal({ kind: "refused", reason: SEVERED_REFUSED_REASON, terminal: true })).toBe(true);
  });

  it("does NOT match a refusal whose reason merely CONTAINS the exact tag as a substring", () => {
    // Case-exact substring of `SEVERED_REFUSED_REASON` ("Severed") embedded in a longer, still
    // plausible engine reason — a substring-based matcher would wrongly latch on this.
    expect(
      isSeveredSignal({ kind: "refused", reason: "operation Severed unexpectedly mid-batch", terminal: true }),
    ).toBe(false);
    // Case-INSENSITIVE containment must not match either.
    expect(isSeveredSignal({ kind: "refused", reason: "the mailbox was severed from IMAP", terminal: true })).toBe(
      false,
    );
  });

  it("matches the exact applied_undo_severed wire string but not a substring container of it", () => {
    expect(isSeveredSignal(SEVERED_UNDO_PRESENTATION)).toBe(true);
    expect(isSeveredSignal("applied_undo_severed")).toBe(true);
    expect(
      isSeveredSignal("prefix_applied_undo_severed_suffix" as UndoPresentationView),
    ).toBe(false);
  });

  it("does not match other UndoPresentationView strings", () => {
    expect(isSeveredSignal("applied_undo_failed")).toBe(false);
    expect(isSeveredSignal("undone")).toBe(false);
  });

  it("is false for null/undefined and for other refusal kinds", () => {
    expect(isSeveredSignal(null)).toBe(false);
    expect(isSeveredSignal(undefined)).toBe(false);
    expect(isSeveredSignal({ kind: "busy", operation: "refresh_inbox" })).toBe(false);
  });
});

describe("reducer — the severed flag LATCHES (never un-lights within a session)", () => {
  it("latches true on a Severed-tagged refusal and stays true through later non-severed actions", () => {
    let state = initialState();
    expect(state.severed).toBe(false);

    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "refused", reason: SEVERED_REFUSED_REASON, terminal: true },
    });
    expect(state.severed).toBe(true);

    // A later, unrelated, perfectly-successful toast must not clear it.
    state = reduce(state, {
      type: "verb_toast",
      undoKey: "u1",
      verbLabel: "archive",
      projection: { state: "current" },
    });
    expect(state.severed).toBe(true);
  });

  it("latches from an undo_toast carrying the severed presentation string", () => {
    let state = initialState();
    state = reduce(state, {
      type: "undo_toast",
      presentation: SEVERED_UNDO_PRESENTATION,
      projection: { state: "current" },
    });
    expect(state.severed).toBe(true);
  });

  it("does not latch on an ordinary refusal", () => {
    let state = initialState();
    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "busy", operation: "refresh_inbox" },
    });
    expect(state.severed).toBe(false);
  });
});

// ===================================================================================================
// A typed refusal arriving while an applied-verb toast still holds UNCONSUMED undo
// keys used to REPLACE that toast wholesale (`toastForRefusal` always answers `undoKeys: []`),
// which made the previous action's undo keys irretrievable even though nothing had consumed them.
// The fix: `refusal_toast` PRESERVES the previous toast's unconsumed `undoKeys`, merged onto the
// refusal toast and rendered with an "undo still available" line.
// ===================================================================================================
describe("refusal_toast preserves a live toast's unconsumed undo keys", () => {
  it("THE DEFECT, pinned: an applied-verb toast's undo keys survive a refusal that follows it", () => {
    let state = initialState();
    state = reduce(state, {
      type: "verb_toast",
      verbLabel: "archive",
      undoKey: "u1",
      projection: { state: "current" },
    });
    expect(state.toast?.undoKeys).toEqual(["u1"]);

    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "busy", operation: "refresh_inbox" },
    });

    expect(state.toast?.undoKeys).toEqual(["u1"]);
    expect(state.toast?.message).toContain("undo still available");
  });

  it("a batch toast's undo keys are likewise preserved onto the refusal that follows", () => {
    let state = initialState();
    const results: PerMessageAttempt[] = [
      { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
      { message_ref: "m2", ok: true, undo_key: "u2", projection: { state: "current" } },
    ];
    state = reduce(state, { type: "batch_toast", verbLabel: "archive", refs: ["m1", "m2"], results });
    expect(state.toast?.undoKeys).toEqual(["u2", "u1"]);

    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "too_soon", operation: "refresh_inbox", retry_after_ms: 400 },
    });
    expect(state.toast?.undoKeys).toEqual(["u2", "u1"]);
  });

  it("a refusal with NO live undo keys to preserve renders the ordinary refusal message, unqualified", () => {
    let state = initialState();
    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "busy", operation: "refresh_inbox" },
    });
    expect(state.toast?.undoKeys).toEqual([]);
    expect(state.toast?.message).not.toContain("undo still available");
  });

  it("keys already CONSUMED by an undo_toast are not resurrected by a later refusal", () => {
    let state = initialState();
    state = reduce(state, {
      type: "verb_toast",
      verbLabel: "archive",
      undoKey: "u1",
      projection: { state: "current" },
    });
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
    });
    expect(state.toast?.undoKeys).toEqual([]);

    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "busy", operation: "refresh_inbox" },
    });
    expect(state.toast?.undoKeys).toEqual([]);
  });
});

// ===================================================================================================
// A BATCH undo is walked one key at a time, and the FIRST success replaced the batch
// toast with an undo toast carrying `undoKeys: []`. Every key the walk had not consumed yet became
// irretrievable at that instant, so a throw on key 2 of 5 left keys 2..5 with no affordance at all —
// the exact class already closed for refusals, re-opened by the undo path's own toast.
//
// The fix: each intermediate `undo_toast` carries the UNCONSUMED SUFFIX, so the toast always holds
// exactly the keys that have not been spent — and a refusal landing mid-walk preserves that suffix
// through the merge shape already in place.
// ===================================================================================================
describe("undo_toast keeps the batch's unconsumed undo keys", () => {
  it("unconsumedUndoKeys is the suffix after N consumed keys", () => {
    expect(unconsumedUndoKeys(["u3", "u2", "u1"], 0)).toEqual(["u3", "u2", "u1"]);
    expect(unconsumedUndoKeys(["u3", "u2", "u1"], 1)).toEqual(["u2", "u1"]);
    expect(unconsumedUndoKeys(["u3", "u2", "u1"], 3)).toEqual([]);
  });

  it("THE DEFECT, pinned: one success into a 3-key batch, the other two keys are still offered", () => {
    let state = initialState();
    const results: PerMessageAttempt[] = [
      { message_ref: "m1", ok: true, undo_key: "u1", projection: { state: "current" } },
      { message_ref: "m2", ok: true, undo_key: "u2", projection: { state: "current" } },
      { message_ref: "m3", ok: true, undo_key: "u3", projection: { state: "current" } },
    ];
    state = reduce(state, {
      type: "batch_toast",
      verbLabel: "archive",
      refs: ["m1", "m2", "m3"],
      results,
    });
    const keys = state.toast?.undoKeys ?? [];
    expect(keys).toEqual(["u3", "u2", "u1"]);

    // The walk consumes `u3` and reports it — carrying what it has NOT consumed.
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
      remainingKeys: unconsumedUndoKeys(keys, 1),
    });
    expect(state.toast?.undoKeys).toEqual(["u2", "u1"]);

    // …and the throw that stops the walk preserves them (the merge shape).
    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "busy", operation: "undo" },
    });
    expect(state.toast?.undoKeys).toEqual(["u2", "u1"]);
    expect(state.toast?.message).toContain("undo still available");
  });

  it("the LAST key of a batch leaves no suffix — the toast holds nothing to undo", () => {
    let state = initialState();
    state = reduce(state, {
      type: "verb_toast",
      verbLabel: "archive",
      undoKey: "u1",
      projection: { state: "current" },
    });
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
      remainingKeys: unconsumedUndoKeys(["u1"], 1),
    });
    expect(state.toast?.undoKeys).toEqual([]);
  });

  it("an undo_toast dispatched with no remaining-keys field still consumes everything (the single-verb path)", () => {
    let state = initialState();
    state = reduce(state, {
      type: "verb_toast",
      verbLabel: "archive",
      undoKey: "u1",
      projection: { state: "current" },
    });
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
    });
    expect(state.toast?.undoKeys).toEqual([]);
  });
});

// ===================================================================================================
// The clipboard-failure toast is the OTHER toast that replaced a keyed one wholesale.
// `copy_failed_toast` answers `undoKeys: []`, so pressing "copy body" after an archive threw the
// archive's undo key away over an event that has nothing to do with the verb. Same merge shape as
// `refusal_toast` — one helper, both sites.
// ===================================================================================================
describe("copy_failed_toast preserves a live toast's unconsumed undo keys", () => {
  it("THE DEFECT, pinned: a copy failure after an archive keeps the archive's undo key", () => {
    let state = initialState();
    state = reduce(state, {
      type: "verb_toast",
      verbLabel: "archive",
      undoKey: "u1",
      projection: { state: "current" },
    });
    state = reduce(state, { type: "copy_failed_toast" });
    expect(state.toast?.undoKeys).toEqual(["u1"]);
    expect(state.toast?.message).toContain("undo still available");
  });

  it("a copy failure with nothing live renders the ordinary, unqualified message", () => {
    let state = initialState();
    state = reduce(state, { type: "copy_failed_toast" });
    expect(state.toast?.undoKeys).toEqual([]);
    expect(state.toast?.message).toBe(COPY_FAILED_MESSAGE);
  });

  it("does not latch severed and does not resurrect consumed keys", () => {
    let state = initialState();
    state = reduce(state, {
      type: "verb_toast",
      verbLabel: "archive",
      undoKey: "u1",
      projection: { state: "current" },
    });
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
    });
    state = reduce(state, { type: "copy_failed_toast" });
    expect(state.toast?.undoKeys).toEqual([]);
    expect(state.severed).toBe(false);
  });
});

describe("readingPaneTextFor — NoTextualBody now carries attachments", () => {
  it("attachment-only mail (NoTextualBody with attachments) still renders the presence line", () => {
    const pane = readingPaneTextFor({
      NoTextualBody: { attachments: { has_attachments: true, count: 3 } },
    });
    expect(pane.noBodyLine).not.toBeNull();
    expect(pane.attachmentLine).toBe("3 attachments — attachment opening is not available in v1");
  });

  it("NoTextualBody with no attachments renders no attachment line", () => {
    const pane = readingPaneTextFor({
      NoTextualBody: { attachments: { has_attachments: false, count: 0 } },
    });
    expect(pane.attachmentLine).toBeNull();
  });

  it("the Text arm is unaffected by the shape change", () => {
    const pane = readingPaneTextFor({
      Text: { plain_text: "hi", truncated: false, attachments: { has_attachments: true, count: 1 } },
    });
    expect(pane.noBodyLine).toBeNull();
    expect(pane.attachmentLine).toBe("1 attachments — attachment opening is not available in v1");
  });

  // JMAP reports `{has_attachments: true, count: 0}` when presence is known but the
  // count itself is NOT (the transport doc names this) — a literal "0 attachments" line
  // contradicts the "attachments present" fact sitting right next to it. This must render a
  // count-FREE presence line instead, on both the NoTextualBody and Text arms.
  it("has_attachments true with count 0 (count unknowable) renders a count-free presence line, not '0 attachments'", () => {
    const noBodyPane = readingPaneTextFor({
      NoTextualBody: { attachments: { has_attachments: true, count: 0 } },
    });
    expect(noBodyPane.attachmentLine).toBe("attachments present — attachment opening is not available in v1");
    expect(noBodyPane.attachmentLine).not.toContain("0 attachments");

    const textPane = readingPaneTextFor({
      Text: { plain_text: "hi", truncated: false, attachments: { has_attachments: true, count: 0 } },
    });
    expect(textPane.attachmentLine).toBe("attachments present — attachment opening is not available in v1");
    expect(textPane.attachmentLine).not.toContain("0 attachments");
  });
});

describe("formatReceivedAt — received_at is epoch MILLISECONDS, not seconds", () => {
  it("renders a 2025-ish year for a real epoch-ms timestamp, not a five-digit year", () => {
    // 2025-08-09T12:00:00Z in epoch MILLISECONDS.
    const rendered = formatReceivedAt(1754745600000);
    expect(rendered).toContain("2025");
    expect(rendered).not.toMatch(/\b\d{5,}\b/); // no five-digit year (the *1000-on-ms bug)
  });
});

describe("rowVisualState — unread/star row-state mapping from {seen, flagged}", () => {
  it("seen=false renders unread; seen=true does not", () => {
    expect(rowVisualState({ seen: false, flagged: false }).unread).toBe(true);
    expect(rowVisualState({ seen: true, flagged: false }).unread).toBe(false);
  });

  it("flagged maps directly to starred", () => {
    expect(rowVisualState({ seen: true, flagged: true }).starred).toBe(true);
    expect(rowVisualState({ seen: true, flagged: false }).starred).toBe(false);
  });
});

// ===================================================================================================
// A stale body response must not overwrite a newer one (the focus moved before the
// slower fetch landed). A generation counter: `bodyRequestFor` bumps it and hands back the token
// this specific request must present to land; `acceptBody` only applies a response whose token
// still matches state's CURRENT generation.
// ===================================================================================================
describe("bodyRequestFor / acceptBody — a request-generation counter guards the reading pane", () => {
  it("a response whose token still matches the current generation lands", () => {
    let state = initialState();
    const { state: requested, token } = bodyRequestFor(state, "m1");
    state = requested;

    // Immediately after the request (before the response lands), the pane is an explicit
    // loading state keyed to "m1" — never the previous (here: empty) content re-rendered.
    expect(state.readingPane).toEqual({ status: "loading", ref: "m1" });

    state = acceptBody(state, token, "m1", {
      Text: { plain_text: "hello", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });

    expect(state.readingPaneRef).toBe("m1");
    expect(state.readingPane.status).toBe("loaded");
    expect(state.readingPane.status === "loaded" && state.readingPane.text.bodyText).toBe("hello");
  });

  it("message A's slow response lands AFTER B was opened — it is ignored, not overwriting B's pane", () => {
    let state = initialState();

    // A is opened first (token 1)...
    const afterA = bodyRequestFor(state, "mA");
    state = afterA.state;
    const tokenA = afterA.token;

    // ...then B is opened before A's fetch resolves (token 2, supersedes A).
    const afterB = bodyRequestFor(state, "mB");
    state = afterB.state;
    const tokenB = afterB.token;

    // B's fetch resolves first.
    state = acceptBody(state, tokenB, "mB", {
      Text: { plain_text: "B body", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });
    expect(state.readingPaneRef).toBe("mB");

    // A's slow fetch finally lands — its token is stale, so it must NOT overwrite B's pane.
    state = acceptBody(state, tokenA, "mA", {
      Text: { plain_text: "A body", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });

    expect(state.readingPaneRef).toBe("mB");
    expect(state.readingPane.status).toBe("loaded");
    expect(state.readingPane.status === "loaded" && state.readingPane.text.bodyText).toBe("B body");
  });
});

// ===================================================================================================
// Opening B must never keep rendering A's stale content — neither while B's fetch is
// in flight, nor after B's fetch fails. `reading_pane_requested` clears straight to a loading
// state keyed to the new ref; a failed response (`reading_pane_failed` / `rejectBody`) moves to an
// explicit error state, still keyed to the ref it belongs to — never A's leftover text.
// ===================================================================================================
describe("reading pane loading/error states are keyed to the focused ref, never a stale ref's text", () => {
  it("A's body lands, then B is opened (request only) ⇒ loading-for-B, not A's text", () => {
    let state = initialState();

    const afterA = bodyRequestFor(state, "A");
    state = afterA.state;
    state = acceptBody(state, afterA.token, "A", {
      Text: { plain_text: "A text", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });
    expect(state.readingPane).toEqual({
      status: "loaded",
      ref: "A",
      text: expect.objectContaining({ bodyText: "A text" }),
    });

    // B is opened — request only, no response has landed yet.
    const afterB = bodyRequestFor(state, "B");
    state = afterB.state;

    expect(state.readingPane).toEqual({ status: "loading", ref: "B" });
    expect(state.readingPane).not.toMatchObject({ ref: "A" });
  });

  it("B's fetch fails ⇒ an explicit error state keyed to B, still not A's text", () => {
    let state = initialState();

    const afterA = bodyRequestFor(state, "A");
    state = afterA.state;
    state = acceptBody(state, afterA.token, "A", {
      Text: { plain_text: "A text", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });

    const afterB = bodyRequestFor(state, "B");
    state = afterB.state;
    state = rejectBody(state, afterB.token, "B", "the provider refused");

    expect(state.readingPane).toEqual({ status: "error", ref: "B", reason: "the provider refused" });
  });

  it("a stale (superseded) failure is dropped, same generation guard as acceptBody", () => {
    let state = initialState();

    const afterA = bodyRequestFor(state, "A");
    state = afterA.state;
    const tokenA = afterA.token;

    const afterB = bodyRequestFor(state, "B");
    state = afterB.state;
    state = acceptBody(state, afterB.token, "B", {
      Text: { plain_text: "B text", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });

    // A's fetch fails AFTER B already landed — A's token is stale, must not clobber B's pane.
    state = rejectBody(state, tokenA, "A", "A failed late");

    expect(state.readingPane).toEqual({
      status: "loaded",
      ref: "B",
      text: expect.objectContaining({ bodyText: "B text" }),
    });
  });

  it("reduce() wires the same contract through reading_pane_requested/response/failed actions", () => {
    let state = initialState();
    state = reduce(state, { type: "reading_pane_requested", messageRef: "A" });
    const tokenA = state.bodyRequestGeneration;
    state = reduce(state, {
      type: "reading_pane_response",
      token: tokenA,
      messageRef: "A",
      body: { Text: { plain_text: "A text", truncated: false, attachments: { has_attachments: false, count: 0 } } },
    });

    state = reduce(state, { type: "reading_pane_requested", messageRef: "B" });
    expect(state.readingPane).toEqual({ status: "loading", ref: "B" });

    const tokenB = state.bodyRequestGeneration;
    state = reduce(state, {
      type: "reading_pane_failed",
      token: tokenB,
      messageRef: "B",
      reason: "network refused",
    });
    expect(state.readingPane).toEqual({ status: "error", ref: "B", reason: "network refused" });
  });
});

// ===================================================================================================
// `page_loaded` must prune `selected` down to refs that still exist in the new page —
// a stale selected ref (dropped off the page) used to linger, making `e` (batch archive) a silent
// no-op against a ref the new page can no longer resolve.
// ===================================================================================================
describe("page_loaded — prunes selections that no longer exist in the incoming rows", () => {
  it("select two refs, page_loaded with only one of them present ⇒ selected == the survivor", () => {
    let state = initialState();
    state = { ...state, selected: new Set(["keep", "drop"]) };

    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("keep")],
      nextCursor: null,
      freshness: null,
    });

    expect(state.selected).toEqual(new Set(["keep"]));
  });

  it("a selected ref that is still present survives untouched across a page replace", () => {
    let state = initialState();
    state = { ...state, selected: new Set(["m1", "m2"]) };

    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2"), makeRow("m3")],
      nextCursor: null,
      freshness: null,
    });

    expect(state.selected).toEqual(new Set(["m1", "m2"]));
  });
});

// ===================================================================================================
// `last_freshness: None` with rows already present (e.g. persisted rows after a
// restart, never refreshed this session) must not render an unqualified, unfooted list.
// ===================================================================================================
describe("freshnessFooterText — never-refreshed-this-session footer", () => {
  it("freshness is null/undefined but rows are present ⇒ a distinct 'not yet refreshed' footer", () => {
    expect(freshnessFooterText(null, true)).toBe("not yet refreshed this session — press r");
    expect(freshnessFooterText(undefined, true)).toBe("not yet refreshed this session — press r");
  });

  it("freshness is null and there are no rows ⇒ still nothing to say", () => {
    expect(freshnessFooterText(null, false)).toBeNull();
  });

  it("a real freshness view still takes precedence over the never-refreshed line", () => {
    expect(freshnessFooterText({ checked_through: null, stale_below: 0 }, true)).toBeNull();
    expect(freshnessFooterText({ checked_through: null, stale_below: 12 }, true)).toBe(
      "12 older messages not re-checked",
    );
  });
});

// ===================================================================================================
// The pacing refusals — TooSoon / ProviderBackoff —
// carry a typed retry_after_ms and must render a caller-facing, second-granular toast.
// ===================================================================================================
describe("toastForRefusal — pacing refusal toasts", () => {
  it("too_soon ⇒ 'refreshed moments ago — try again in Ns' (rounded UP to whole seconds)", () => {
    const toast = toastForRefusal({ kind: "too_soon", operation: "refresh_inbox", retry_after_ms: 2500 });
    expect(toast.message).toBe("refreshed moments ago — try again in 3s");
    expect(toast.refusalKind).toBe("too_soon");
  });

  it("provider_backoff ⇒ 'the provider asked us to back off — retrying is blocked for Ns'", () => {
    const toast = toastForRefusal({
      kind: "provider_backoff",
      operation: "message_body",
      retry_after_ms: 61000,
    });
    expect(toast.message).toBe("the provider asked us to back off — retrying is blocked for 61s");
    expect(toast.refusalKind).toBe("provider_backoff");
  });
});

// ===================================================================================================
// `SurfaceError`'s `credential_expired` variant gains `cure: Cure` — the frontend
// branches on it via the single-sourced `CURE_COPY` map, never a hard-coded re-mint prompt (the
// old shape assumed re-mint was the ONLY cure; it is one of five).
// ===================================================================================================
describe("toastForRefusal — credential_expired branches on cure", () => {
  it("re_mint ⇒ CURE_COPY.re_mint AND the engine's own reason", () => {
    const toast = toastForRefusal({
      kind: "credential_expired",
      expires_at: 42,
      cure: "re_mint",
      reason: "the Gmail credential expired at 42",
    });
    expect(toast.message).toBe(`${CURE_COPY.re_mint}: the Gmail credential expired at 42`);
    expect(toast.message).toContain("re-mint");
    expect(toast.refusalKind).toBe("credential_expired");
  });

  it.each<[Cure, string]>([
    ["re_mint", "the Gmail credential needs a re-mint (see the runbook)"],
    ["client_config", "the OAuth client or its scope configuration was refused — developer review of the OAuth client (client_secret.json / console) is required"],
    // CURE-ACTOR-HONESTY: actor-neutral — org_internal's documented remedy is
    // account/organization scoped, not necessarily an administrator's act.
    ["admin_policy", "an account or organization policy refused the credential"],
    // Relit on the state-only wording. The literals stay spelled out here ON
    // PURPOSE — a table that only compares the map to itself would pass on any wording at all.
    // "— the reason beside it names the condition" was FALSE
    // on the status bar for an armed cell (both reasons null ⇒ nothing renders beside it); the
    // row is now the bare state-only fact, true on both surfaces.
    ["retry_later", "the credential is retryable as it stands"],
    ["undetermined", "the provider refused for an unrecognized reason — the credential has not been renewed"],
  ])("the five-cure table: %s ⇒ its own sentence, single-sourced from CURE_COPY", (cure, expected) => {
    expect(CURE_COPY[cure]).toBe(expected);
    const toast = toastForRefusal({
      kind: "credential_expired",
      expires_at: 42,
      cure,
      reason: "engine reason",
    });
    expect(toast.message).toBe(`${expected}: engine reason`);
  });

  // A transient refusal (retry_later) must never contain the word "re-mint" — conflating a
  // paced retry with a re-mint demand sends the operator on a needless off-app errand.
  it("retry_later toast contains no 're-mint'", () => {
    const toast = toastForRefusal({
      kind: "credential_expired",
      expires_at: 42,
      cure: "retry_later",
      reason: "renewal deferred by the pacing floor",
    });
    expect(toast.message.toLowerCase()).not.toContain("re-mint");
  });

  it("undetermined toast also contains no 're-mint'", () => {
    const toast = toastForRefusal({
      kind: "credential_expired",
      expires_at: 42,
      cure: "undetermined",
      reason: "unrecognized provider code",
    });
    expect(toast.message.toLowerCase()).not.toContain("re-mint");
  });
});

// ===================================================================================================
// `session_unconfigured` gains `cure: Cure | null`, the SAME discriminant
// `credential_expired` already carries. A boot-time credential refusal (a pre-grant credential with no
// grant record, a read-only grant, an unusable principal, a retired generation) reached this toast
// as a bare sentence, so the operator read a path and a paragraph where the `credential_expired`
// arm would have opened with "the Gmail credential needs a re-mint". The cure is read through the
// SAME single-sourced `CURE_COPY` map — never a literal — and `null` keeps the old bare-reason
// shape, because a store-unavailable or resolver refusal owes no credential cure.
// ===================================================================================================
describe("toastForRefusal — session_unconfigured branches on cure when it carries one", () => {
  it("a re_mint cure opens with CURE_COPY.re_mint and keeps the engine's own reason", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "the parked credential carries no grant provenance",
      cure: "re_mint",
    });
    expect(toast.message).toBe(
      `${CURE_COPY.re_mint}: the parked credential carries no grant provenance`,
    );
    expect(toast.refusalKind).toBe("session_unconfigured");
  });

  it("cure: null keeps the bare reason — a store/resolver refusal owes no credential cure", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "no HOME could be resolved",
      cure: null,
    });
    expect(toast.message).toBe("no HOME could be resolved");
  });

  // Again, on this arm: the four non-remint cures must never paint a re-mint demand.
  //
  // The map is `UNCONFIGURED_CURE_COPY` — the SAME five cures said for the boot
  // stage. Three rows are the same strings by reference (see that map's doc); the two the finding
  // named are spelled out here as literals ON PURPOSE, because the copy IS the fix and a table
  // that only compares the map to itself would pass on any wording at all.
  it.each<[Cure, string]>([
    ["re_mint", CURE_COPY.re_mint],
    ["client_config", CURE_COPY.client_config],
    ["admin_policy", CURE_COPY.admin_policy],
    // Relit on the state-only wording; `undetermined` was already state-only and
    // is unchanged.
    // "Photon refused to READ its local state" was false for
    // `GrantHighWaterWriteFailed` (the failed op is the RECORDING); actor- and verb-neutral now.
    ["retry_later", "the credential could not be checked — a local state operation was refused; the reason names what refused"],
    ["undetermined", "the credential state could not be established — the refusal reason names what refused"],
  ])("the five-cure table on this arm too: %s ⇒ its own single-sourced sentence", (cure, expected) => {
    expect(UNCONFIGURED_CURE_COPY[cure]).toBe(expected);
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "boot reason",
      cure,
    });
    expect(toast.message).toBe(`${expected}: boot reason`);
    if (cure !== "re_mint") {
      expect(toast.message.toLowerCase()).not.toContain("re-mint");
    }
  });

  // ---------------------------------------------------------------------------------------------
  // THE SAME HEDGE THE STATUS BAR ALREADY CARRIES.
  //
  // `render.ts` renders `CURE_COPY[status.credential_cure ?? "undetermined"]`; this toast indexed
  // `CURE_COPY[error.cure]` bare. The wire union is CLOSED today, so the two agree today — but
  // they are two renderings of one discriminant and only one of them survives a cure the map has
  // no row for. An unmapped index in TypeScript is `undefined`, and the template literal paints
  // it: the operator reads a toast that opens with the word "undefined".
  //
  // The cast is the point of the witness: it stands in for exactly the state a widened wire
  // union, or a build where the frontend is older than the backend, would produce.
  //
  // Before the fix (this exact case, against the pre-fix bytes):
  //   AssertionError: expected 'undefined: boot reason' to be
  //   'the provider refused for an unrecognized reason — Photon will retry on your next
  //   command: boot reason'
  // ---------------------------------------------------------------------------------------------
  it("a cure the map has no row for renders the undetermined copy, never the word undefined", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "boot reason",
      // Deliberately outside the wire union: the shape a widened backend, or a frontend older
      // than the backend it is talking to, would actually deliver.
      cure: "a_cure_this_build_has_never_heard_of" as Cure,
    });
    expect(toast.message).toBe(`${UNCONFIGURED_CURE_COPY.undetermined}: boot reason`);
    expect(toast.message).not.toContain("undefined");
  });

  // The `null` arm is NOT the same case and must keep its own answer: an unopenable store or an
  // unresolved path owes no credential cure at all, and `?? "undetermined"` must never turn that
  // honest silence into a provider-refusal sentence.
  it("cure: null still keeps the bare reason — the fallback is for UNKNOWN, not for ABSENT", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "no HOME could be resolved",
      cure: null,
    });
    expect(toast.message).toBe("no HOME could be resolved");
    expect(toast.message).not.toContain(UNCONFIGURED_CURE_COPY.undetermined);
  });
});

// ===================================================================================================
// THE UNCONFIGURED SURFACE SPEAKS ABOUT THE LOCAL BOOT,
// NOT ABOUT THE PROVIDER.
//
// `session_unconfigured` fronts a different STAGE and a different ACTOR from `credential_expired`:
// its refusals come from the local filesystem before any arm exists (a `PermissionDenied` read ⇒
// `undetermined`; a boot-lock timeout or an unusable grant ratchet ⇒ `retry_later`), and its next
// step is a RECONCILE, not a renewal. Reusing the refresh-stage `CURE_COPY` prefixed the operator's
// own file-access failure with "the provider refused for an unrecognized reason" and promised a
// "renewal" for a state with nothing to renew — the prefix contradicting the reason printed two
// words later. The fix is a SECOND single-sourced map, `UNCONFIGURED_CURE_COPY`, never a literal.
//
// Before the fix these exact cases failed.
// ===================================================================================================
describe("toastForRefusal — stage-/actor-neutral copy on the unconfigured surface", () => {
  it("an undetermined BOOT failure does not blame the provider, and keeps the engine's own reason", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "the credential file could not be read (permission denied)",
      cure: "undetermined",
    });
    expect(toast.message.toLowerCase()).not.toContain("provider refused");
    expect(toast.message).toContain("the credential file could not be read (permission denied)");
  });

  it("a retry_later BOOT failure names a local check, never a RENEWAL — there is nothing to renew", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "the grant ratchet could not be read",
      cure: "retry_later",
    });
    expect(toast.message.toLowerCase()).not.toContain("renew");
    expect(toast.message).toContain("the grant ratchet could not be read");
  });

  it("the re-mint sentence is the SAME on both surfaces — one act cures it, whichever stage found it", () => {
    const toast = toastForRefusal({
      kind: "session_unconfigured",
      reason: "the parked credential carries no grant provenance",
      cure: "re_mint",
    });
    expect(toast.message).toBe(
      `${CURE_COPY.re_mint}: the parked credential carries no grant provenance`,
    );
  });

  it("the LIVE surface is untouched: a credential_expired refusal still speaks the refresh-stage copy", () => {
    const toast = toastForRefusal({
      kind: "credential_expired",
      expires_at: 42,
      cure: "undetermined",
      reason: "unrecognized provider code",
    });
    expect(toast.message).toBe(`${CURE_COPY.undetermined}: unrecognized provider code`);
  });
});

// ===================================================================================================
// `cureCopyFor`: the status bar's copy, chosen by STAGE, with both of the
// toast's hedges. This is the behavioural home of the two fallbacks `render-contract.test.ts` used
// to pin as source text: a status object can be fed a null discriminant and an unmapped one
// directly here, which is a stronger witness than a regex over the call site.
// ===================================================================================================
describe("cureCopyFor — the status bar's copy, chosen by stage", () => {
  // An UNCONFIGURED status carries the REASON that made it unconfigured — that is
  // what `session_status_view` publishes, and it is also the discriminant `cureCopyFor`
  // reads. The `configured: false` fixtures below therefore carry a `provider_reason`; the shape
  // they used to have (`configured: false`, `provider_reason: null`) is the STORE-failed one, and
  // it has its own describe block right after this one.
  const UNARMED = "no Gmail credential at ~/.photon/gmail/gmail_readside_main_token.json";

  it("a CONFIGURED session reads the refresh-stage map: its cure came from a provider answer", () => {
    expect(cureCopyFor(makeStatus({ configured: true, credential_expired: true, credential_cure: "undetermined" })))
      .toBe(CURE_COPY.undetermined);
  });

  it("an UNCONFIGURED session reads the boot-stage map: no arm was built, so nothing was refused by a provider", () => {
    const copy = cureCopyFor(
      makeStatus({ configured: false, provider_reason: UNARMED, credential_cure: "undetermined" }),
    );
    expect(copy).toBe(UNCONFIGURED_CURE_COPY.undetermined);
    expect(copy.toLowerCase()).not.toContain("provider refused");
  });

  it("an UNCONFIGURED retry_later names a local check, never a renewal", () => {
    const copy = cureCopyFor(
      makeStatus({ configured: false, provider_reason: UNARMED, credential_cure: "retry_later" }),
    );
    expect(copy).toBe(UNCONFIGURED_CURE_COPY.retry_later);
    expect(copy.toLowerCase()).not.toContain("renew");
  });

  it("a re-mint demand reads the same on both stages — one act cures it", () => {
    expect(cureCopyFor(makeStatus({ configured: false, provider_reason: UNARMED, credential_cure: "re_mint" })))
      .toBe(CURE_COPY.re_mint);
    expect(cureCopyFor(makeStatus({ configured: true, credential_expired: true, credential_cure: "re_mint" })))
      .toBe(CURE_COPY.re_mint);
  });

  // The two hedges, kept together with the lookup they belong to: a NULL discriminant
  // while expired (a wire contract violation — named, never painted as a false re-mint demand)
  // and a NON-null discriminant this build's map has no row for (a frontend older than the
  // backend it talks to). Neither may ever render the literal word "undefined", and neither may
  // borrow the OTHER stage's sentence.
  it("a null cure falls back to the SELECTED map's undetermined row, never a re-mint demand", () => {
    expect(cureCopyFor(makeStatus({ configured: true, credential_expired: true, credential_cure: null })))
      .toBe(CURE_COPY.undetermined);
    expect(cureCopyFor(makeStatus({ configured: false, provider_reason: UNARMED, credential_cure: null })))
      .toBe(UNCONFIGURED_CURE_COPY.undetermined);
  });

  it("a cure the map has no row for falls back to the SELECTED map, never the word undefined", () => {
    const unknown = "a_cure_this_build_has_never_heard_of" as Cure;
    expect(cureCopyFor(makeStatus({ configured: true, credential_expired: true, credential_cure: unknown })))
      .toBe(CURE_COPY.undetermined);
    const boot = cureCopyFor(
      makeStatus({ configured: false, provider_reason: UNARMED, credential_cure: unknown }),
    );
    expect(boot).toBe(UNCONFIGURED_CURE_COPY.undetermined);
    expect(boot).not.toContain("undefined");
  });
});

// ===================================================================================================
// The stage is the CREDENTIAL's, not the SESSION's.
//
// `configured` is `store_unavailable.is_none() && provider_reason.is_none()` (lib.rs
// `session_status_view`), so it is `false` for TWO different facts: the credential cell published
// no arm, and the STORE would not open. In the second, the credential cell is armed and its
// `credential_cure` is the REFRESH stage's stamp — a provider answer — and the boot-stage map
// re-labels it as a local boot issue (`UNCONFIGURED_CURE_COPY.retry_later`, a LOCAL check that
// could not happen) for a renewal that really was attempted and really was refused.
//
// The discriminator is `provider_reason`, and it is already on the wire: `session_status_view`
// sets it exactly when the cell published no arm (`unconfigured_verdict`) or the grant ratchet
// spoke (`LiveGrantVerdict::Retired`/`Undetermined`) — every source of a BOOT-stage cure — and
// leaves it `null` for an armed cell, whose only cure source is `CredentialCell::status_cure`.
// ===================================================================================================
describe("cureCopyFor — the stage is the credential's, not the session's", () => {
  // The store-failed shape: `configured: false` with NO provider reason, an armed credential
  // whose stamp has passed, and a cure that came from a refresh attempt.
  function storeFailed(cure: Cure | null): SessionStatus {
    return makeStatus({
      configured: false,
      store_reason: "the store could not be opened (PermissionDenied)",
      provider_reason: null,
      credential_expires_at: 1_000,
      credential_expired: true,
      credential_cure: cure,
    });
  }

  it("a store failure over an ARMED, expired credential keeps the refresh-stage copy", () => {
    expect(cureCopyFor(storeFailed("retry_later"))).toBe(CURE_COPY.retry_later);
    expect(cureCopyFor(storeFailed("undetermined"))).toBe(CURE_COPY.undetermined);
  });

  it("and the boot-stage sentences never speak for a credential the provider answered about", () => {
    expect(cureCopyFor(storeFailed("retry_later"))).not.toBe(UNCONFIGURED_CURE_COPY.retry_later);
    expect(cureCopyFor(storeFailed("undetermined"))).not.toBe(UNCONFIGURED_CURE_COPY.undetermined);
  });

  it("a re-mint reads the same on either stage — one act cures it", () => {
    expect(cureCopyFor(storeFailed("re_mint"))).toBe(CURE_COPY.re_mint);
  });

  it("both hedges follow the SELECTED map on the store-failed shape too", () => {
    expect(cureCopyFor(storeFailed(null))).toBe(CURE_COPY.undetermined);
    const unknown = "a_cure_this_build_has_never_heard_of" as Cure;
    expect(cureCopyFor(storeFailed(unknown))).toBe(CURE_COPY.undetermined);
  });

  it("a cell that published NO ARM still reads the boot-stage map — provider_reason says so", () => {
    const unarmed = makeStatus({
      configured: false,
      provider_reason: "no Gmail credential at ~/.photon/gmail/…",
      credential_cure: "retry_later",
    });
    expect(cureCopyFor(unarmed)).toBe(UNCONFIGURED_CURE_COPY.retry_later);
  });

  it("a RETIRED grant on an armed cell is a boot-stage fact too: the ratchet is local", () => {
    const retired = makeStatus({
      configured: false,
      provider_reason: "the consent this credential was minted under has been retired",
      credential_expires_at: 1_000,
      credential_expired: true,
      credential_cure: "undetermined",
    });
    expect(cureCopyFor(retired)).toBe(UNCONFIGURED_CURE_COPY.undetermined);
  });
});

// ===================================================================================================
// A census is a flashlight, not a fence) — THE CURE SENTENCES
// ARE PINNED TO THEIR EXACT WORDING.
//
// RESIDUAL, NAMED: Label honesty (no sentence predicts a door, asserts a refresh history, or
// over-claims) is enforced at these sites by exact-literal pins reviewed by a human, not by any
// predicate or census; a NEW false claim is not automatically caught (the word-list
// fences were harvested and deleted).
//
// WHAT WAS HERE, AND WHY IT IS GONE: an earlier version added `PREDICTS_A_DOOR = /next command|will be retried|
// re-check/` and another added `ASSERTS_A_HISTORY = /recorded|attempt|previous|last time|again/i`, run
// as `not.toMatch` over both `Record<Cure, string>` maps and over every rendered toast. Those
// word-lists are a CENSUS over an unbounded space (English phrasings of a prediction or a claimed
// history). They did their job — they found the original instances — but as permanent fences
// they owe a coverage claim that is falsifiable forever: "no future sentence predicts a door" is
// not something a seven-word regex can hold, and a green run reads as a guarantee it never gave.
//
// WHAT REPLACES THEM: every instance the censuses found is pinned to its EXACT sentence. The
// five-cure tables above already pin both maps row by row (`toastForRefusal — credential_expired
// branches on cure` and `— session_unconfigured branches on cure when it carries one`); the cases
// below pin the three reachable render paths the findings actually named — the STORE-failed
// `retry_later`, the BOOT-stage `retry_later`, the BOOT-IN-GRACE `retry_later`
// — plus the delivered message on both toast surfaces, for all five cures, as full
// exact literals. A wording change goes RED at the byte; a NEW false claim goes to review.
//
// THE FINDINGS THE PINS CARRY (kept because the reasoning is why the wording is what it is):
// `CURE_COPY.retry_later` said "renewal will be retried on your next command". A
//   `configured: false` session whose `store_unavailable` is set reads THIS map, and
//   in that shape NOTHING retries: every provider-read stops at `state.session()?` before
//   `admit_provider`, and `self.session` is written once at construction with no `&mut self`
//   anywhere to reopen it. `UNCONFIGURED_CURE_COPY.retry_later` said "Photon will re-check the
//   credential on your next command" — false at the ACTING doors (`run_verb`, `undo`,
//   `undo_presentation` reach the arm through `PhotonState::gmail`, which never calls
//   `CredentialCoordinator::admit`; their admission is separate).
// "the reason RECORDED is a transient one" asserted a record that does not exist at
//   boot inside the expiry grace window: `CredentialCell::status_cure` yields `retry_later` before
//   any refresh has run, `last_result` is `None`, and it is not on the wire.
// ===================================================================================================
describe("the cure sentences are pinned to their exact wording (label honesty is a review property — no predicate fences it)", () => {
  // RED at b9b4541: this copy read "…renewal will be retried on your next command" — the store is
  // unopenable, so nothing will be retried on any command.
  it("a store that will not open, over an armed expired credential, reads the exact state-only sentence", () => {
    const copy = cureCopyFor(
      makeStatus({
        configured: false,
        store_reason: "the store could not be opened (PermissionDenied)",
        provider_reason: null,
        credential_expires_at: 1_000,
        credential_expired: true,
        credential_cure: "retry_later",
      }),
    );
    expect(copy).toBe("the credential is retryable as it stands");
    expect(copy).toBe(CURE_COPY.retry_later);
  });

  // The same shape on the OTHER map: a cell that published no arm.
  it("the boot-stage retry_later reads the exact local-refusal sentence", () => {
    const copy = cureCopyFor(
      makeStatus({
        configured: false,
        provider_reason: "no Gmail credential at ~/.photon/gmail/…",
        credential_cure: "retry_later",
      }),
    );
    expect(copy).toBe(
      "the credential could not be checked — a local state operation was refused; the reason names what refused",
    );
    expect(copy).toBe(UNCONFIGURED_CURE_COPY.retry_later);
  });

  // At boot inside the expiry grace window `status_cure` yields `retry_later` before
  // ANY refresh has run, so the sentence may not name a record. Pinned as the exact byte.
  it("the boot-in-grace retry_later notice (no refresh has run) reads the exact sentence, which names no record", () => {
    const copy = cureCopyFor(
      makeStatus({ configured: true, provider_reason: null, credential_expired: true, credential_cure: "retry_later" }),
    );
    expect(copy).toBe("the credential is retryable as it stands");
  });

  // Every reachable render path, not just the two maps read directly: both surfaces that speak a
  // cure (the toast and the status bar's notice) are driven from the same maps. The DELIVERED
  // string is pinned whole, per cure, per surface — literals, never a predicate.
  it.each<[Cure, string, string]>([
    [
      "re_mint",
      "the Gmail credential needs a re-mint (see the runbook): engine reason",
      "the Gmail credential needs a re-mint (see the runbook): boot reason",
    ],
    [
      "client_config",
      "the OAuth client or its scope configuration was refused — developer review of the OAuth client (client_secret.json / console) is required: engine reason",
      "the OAuth client or its scope configuration was refused — developer review of the OAuth client (client_secret.json / console) is required: boot reason",
    ],
    [
      "admin_policy",
      "an account or organization policy refused the credential: engine reason",
      "an account or organization policy refused the credential: boot reason",
    ],
    [
      "retry_later",
      "the credential is retryable as it stands: engine reason",
      "the credential could not be checked — a local state operation was refused; the reason names what refused: boot reason",
    ],
    [
      "undetermined",
      "the provider refused for an unrecognized reason — the credential has not been renewed: engine reason",
      "the credential state could not be established — the refusal reason names what refused: boot reason",
    ],
  ])(
    "the %s toast delivers its exact sentence on both surfaces",
    (cure, expiredMessage, unconfiguredMessage) => {
      const expired = toastForRefusal({
        kind: "credential_expired",
        expires_at: 42,
        cure,
        reason: "engine reason",
      });
      const unconfigured = toastForRefusal({
        kind: "session_unconfigured",
        reason: "boot reason",
        cure,
      });
      expect(expired.message).toBe(expiredMessage);
      expect(unconfigured.message).toBe(unconfiguredMessage);
    },
  );
});
// ===================================================================================================
// Rows beyond page 1 were unreachable: `next_cursor` was stored but nothing ever
// consumed it. `page_appended` appends the next local page, deduping by ref and preserving sort
// order; `isAtPageBoundary` is the pure predicate that tells the caller when to fetch it (focus at
// the last loaded row, a cursor present).
// ===================================================================================================
describe("page_appended — cursor-driven incremental loading", () => {
  it("appends new rows after the existing ones, keeping sort order, and adopts the new cursor", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: { received_at: 100, message_ref: "m2" },
      freshness: null,
    });
    state = reduce(state, {
      type: "page_appended",
      rows: [makeRow("m3"), makeRow("m4")],
      nextCursor: { received_at: 50, message_ref: "m4" },
      generation: state.listGeneration,
    });
    expect(state.rows.map((r) => r.message_ref)).toEqual(["m1", "m2", "m3", "m4"]);
    expect(state.nextCursor).toEqual({ received_at: 50, message_ref: "m4" });
  });

  it("dedupes by ref — a row already present in the loaded rows is not appended twice", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: { received_at: 100, message_ref: "m2" },
      freshness: null,
    });
    state = reduce(state, {
      type: "page_appended",
      rows: [makeRow("m2"), makeRow("m3")], // m2 is already present in `rows`
      nextCursor: null,
      generation: state.listGeneration,
    });
    expect(state.rows.map((r) => r.message_ref)).toEqual(["m1", "m2", "m3"]);
  });

  it("preserves selection AND focus across an append", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: { received_at: 100, message_ref: "m2" },
      freshness: null,
    });
    state = { ...state, selected: new Set(["m1"]), focusIndex: 1 };
    state = reduce(state, {
      type: "page_appended",
      rows: [makeRow("m3")],
      nextCursor: null,
      generation: state.listGeneration,
    });
    expect(state.selected).toEqual(new Set(["m1"]));
    expect(state.focusIndex).toBe(1);
  });
});

// ===================================================================================================
// A STALE-GENERATION page_appended IS DROPPED, NOT LANDED.
//
// A `j`-triggered local-page fetch (`loadNextPage`'s `inboxPage` branch) can still be in flight
// when an `r`-triggered reload (`page_loaded`) replaces the whole window out from under it. Landing
// the late `page_appended` response then appends a PRE-RELOAD page onto the POST-RELOAD list — rows
// the reload legitimately dropped reappear, and `nextCursor` regresses to the stale page's cursor.
// `listGeneration` is bumped ONLY by `page_loaded`; `loadNextPage` captures it before issuing the
// fetch and stamps it onto the dispatch, and the reducer drops an append whose stamp no longer
// matches — same shape as `bodyRequestGeneration`'s guard on `acceptBody`/`rejectBody`.
// ===================================================================================================
describe("page_appended is dropped when a reload has superseded it", () => {
  it("a page_loaded reload BUMPS listGeneration", () => {
    const state = initialState();
    expect(state.listGeneration).toBe(0);
    const reloaded = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1")],
      nextCursor: null,
      freshness: null,
    });
    expect(reloaded.listGeneration).toBe(1);
  });

  it("a STALE-generation page_appended (captured before an intervening reload) is ignored outright", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: { received_at: 100, message_ref: "m2" },
      freshness: null,
    });
    // The `j` fetch reads the generation here, BEFORE the reload below lands.
    const staleGeneration = state.listGeneration;

    // An `r` reload lands first and REPLACES the window — a different set of rows entirely (m2 was
    // archived externally in between; a brand-new m9 is now the newest row) and bumps the
    // generation.
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m9"), makeRow("m1")],
      nextCursor: null,
      freshness: null,
    });
    expect(state.listGeneration).not.toBe(staleGeneration);

    // The `j` fetch's response now arrives, stamped with the generation it captured before the
    // reload — a page continuing off the OLD (pre-reload) cursor, carrying a row (m3) the reload
    // never even fetched.
    const beforeAppend = state;
    state = reduce(state, {
      type: "page_appended",
      rows: [makeRow("m3")],
      nextCursor: { received_at: 10, message_ref: "m3" },
      generation: staleGeneration,
    });

    expect(state).toEqual(beforeAppend);
    expect(state.rows.map((r) => r.message_ref)).toEqual(["m9", "m1"]);
    expect(state.nextCursor).toBeNull();
  });

  it("a CURRENT-generation page_appended applies normally", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: { received_at: 100, message_ref: "m2" },
      freshness: null,
    });
    const currentGeneration = state.listGeneration;

    state = reduce(state, {
      type: "page_appended",
      rows: [makeRow("m3")],
      nextCursor: { received_at: 10, message_ref: "m3" },
      generation: currentGeneration,
    });

    expect(state.rows.map((r) => r.message_ref)).toEqual(["m1", "m2", "m3"]);
    expect(state.nextCursor).toEqual({ received_at: 10, message_ref: "m3" });
  });
});

describe("isAtPageBoundary — the bottom-of-list load-more condition", () => {
  it("true when focus is at the last row AND a next cursor is present", () => {
    expect(isAtPageBoundary(2, 3, { received_at: 1, message_ref: "m" })).toBe(true);
  });

  it("false when focus is not at the last row, even with a cursor present", () => {
    expect(isAtPageBoundary(1, 3, { received_at: 1, message_ref: "m" })).toBe(false);
  });

  it("false at the last row when there is no next cursor", () => {
    expect(isAtPageBoundary(2, 3, null)).toBe(false);
  });

  it("false for an empty list", () => {
    expect(isAtPageBoundary(0, 0, { received_at: 1, message_ref: "m" })).toBe(false);
  });
});

// ===================================================================================================
// Opening the SAME ref twice while it is already loading used to bump the
// generation a second time; the backend refused the duplicate as Busy and the first (successful)
// response was discarded as stale, so the pane ended up empty. A reopen of the SAME ref while its
// pane state is loading must be a no-op: same state object back, same generation.
// ===================================================================================================
describe("bodyRequestFor — a reopen of the SAME ref while it is loading is a no-op", () => {
  it("returns the state unchanged (same generation) when the ref matches the in-flight loading ref", () => {
    let state = initialState();
    const first = bodyRequestFor(state, "m1");
    state = first.state;
    expect(state.readingPane).toEqual({ status: "loading", ref: "m1" });

    const second = bodyRequestFor(state, "m1");
    expect(second.state).toBe(state); // same object — untouched
    expect(second.token).toBe(first.token); // generation NOT bumped
  });

  it("a DIFFERENT ref while one is loading still bumps the generation as before", () => {
    let state = initialState();
    const first = bodyRequestFor(state, "m1");
    state = first.state;
    const second = bodyRequestFor(state, "m2");
    expect(second.token).toBe(first.token + 1);
    expect(second.state.readingPane).toEqual({ status: "loading", ref: "m2" });
  });

  it("re-requesting the same ref once it is no longer loading (e.g. loaded) bumps the generation again", () => {
    let state = initialState();
    const first = bodyRequestFor(state, "m1");
    state = acceptBody(first.state, first.token, "m1", {
      Text: { plain_text: "hi", truncated: false, attachments: { has_attachments: false, count: 0 } },
    });
    const second = bodyRequestFor(state, "m1");
    expect(second.token).toBe(first.token + 1);
  });
});

// ===================================================================================================
// Mutation shortcuts must respect the fence: `session_status` reports
// `mutations_live: false` on the production Gmail arm, but `s`/`e` used to still dispatch the write
// commands anyway (guaranteed-fail engine work). `verbsAllowed` is the pure guard a handler consults
// BEFORE issuing any IPC call; `fenceToast` is the toast it renders instead, carrying the engine's
// own `mutations_reason`.
// ===================================================================================================
describe("verbsAllowed — the fence a write-verb handler consults before dispatching", () => {
  it("false when the last-known status has mutations_live: false", () => {
    expect(verbsAllowed(makeStatus({ mutations_live: false }))).toBe(false);
  });

  it("true when mutations_live is true", () => {
    expect(verbsAllowed(makeStatus({ mutations_live: true }))).toBe(true);
  });

  it("true (never blocks) when status has not loaded yet — nothing to fence on", () => {
    expect(verbsAllowed(null)).toBe(true);
  });
});

describe("fenceToast — the toast a fenced write-verb short-circuit renders", () => {
  it("carries the status's own mutations_reason, never a dispatch's worth of undo keys", () => {
    const toast = fenceToast("writes are fenced off in this build");
    expect(toast.message).toBe("writes are fenced off in this build");
    expect(toast.undoKeys).toEqual([]);
  });

  it("falls back to a stated default when mutations_reason is null", () => {
    const toast = fenceToast(null);
    expect(toast.message).toBe("writes are not available in this build");
  });
});

// ===================================================================================================
// The star-toggle toast used to hardcode `verbLabel: "star"` regardless of
// direction, so an UNSTAR (target === false) rendered "star applied" through `toastForVerb`'s
// `${verbLabel} applied` idiom — the opposite of what happened. `starVerbLabel` derives the label
// from the boolean the caller is about to send, so the toast always names the actual direction.
// ===================================================================================================
describe("starVerbLabel — the star-toggle toast label is derived from the target value", () => {
  it("names 'star' when the target value is true (applying the star)", () => {
    expect(starVerbLabel(true)).toBe("star");
  });

  it("names 'unstar' when the target value is false (removing the star)", () => {
    expect(starVerbLabel(false)).toBe("unstar");
  });

  it("feeds toastForVerb's existing idiom so an unstar never reads as a star", () => {
    const applied = toastForVerb(starVerbLabel(true), "undo-1", { state: "current" });
    const removed = toastForVerb(starVerbLabel(false), "undo-1", { state: "current" });
    expect(applied.message).toBe("star applied");
    expect(removed.message).toBe("unstar applied");
  });
});

// ===================================================================================================
// An expiry refusal must trigger a status re-read so the status bar stops being
// stale. `shouldRefreshStatus` is the pure predicate naming which refusal kinds warrant it;
// `status_updated` is the reducer action that lands the re-read's result.
// ===================================================================================================
describe("shouldRefreshStatus — which refusal kinds warrant a status re-read", () => {
  it("true for credential_expired and session_unconfigured", () => {
    expect(shouldRefreshStatus("credential_expired")).toBe(true);
    expect(shouldRefreshStatus("session_unconfigured")).toBe(true);
  });

  it("false for busy, too_soon, provider_backoff, refused, store, internal", () => {
    expect(shouldRefreshStatus("busy")).toBe(false);
    expect(shouldRefreshStatus("too_soon")).toBe(false);
    expect(shouldRefreshStatus("provider_backoff")).toBe(false);
    expect(shouldRefreshStatus("refused")).toBe(false);
    expect(shouldRefreshStatus("store")).toBe(false);
    expect(shouldRefreshStatus("internal")).toBe(false);
  });

  // The cure-carrying credential_expired variant is still, semantically, an expiry —
  // shouldRefreshStatus's predicate is on `SurfaceError["kind"]`, unaffected by the new `cure`
  // field it carries, so this stays true unmodified regardless of WHICH cure the refusal names.
  it("still true for credential_expired regardless of which cure it carries — unchanged semantics", () => {
    const cures: Cure[] = ["re_mint", "client_config", "admin_policy", "retry_later", "undetermined"];
    for (const cure of cures) {
      expect(shouldRefreshStatus("credential_expired")).toBe(true);
      void cure; // the predicate takes only `kind`; the loop documents that cure never influences it
    }
  });
});

// ===================================================================================================
// `configured` is REDEFINED: it now means "store and provider arm are
// constructible," independent of whether the credential is currently live. An expired-but-
// refreshable credential (no refresh attempted yet) is `configured: true` + `credential_expired:
// true` + `credential_cure: "retry_later"`; a latched-dead credential is the same shape with cure
// `re_mint`. Neither carries `configured: false` — that stays reserved for a store/arm that could
// not be built at all. These are reducer-level pins on the SHAPE state.ts carries through
// unmodified (the reducer does not interpret `configured`; the render layer does).
// ===================================================================================================
describe("SessionStatus — the redefined configured contract", () => {
  it("an expired-but-refreshable credential is configured:true, credential_expired:true, cure:retry_later", () => {
    const status = makeStatus({ configured: true, credential_expired: true, credential_cure: "retry_later" });
    expect(status.configured).toBe(true);
    expect(status.credential_expired).toBe(true);
    expect(status.credential_cure).toBe("retry_later");
  });

  it("a latched-dead credential is configured:true, credential_expired:true, cure:re_mint (never configured:false)", () => {
    const status = makeStatus({ configured: true, credential_expired: true, credential_cure: "re_mint" });
    expect(status.configured).toBe(true);
    expect(status.credential_cure).toBe("re_mint");
  });

  it("a live credential carries credential_cure: null", () => {
    const status = makeStatus({ configured: true, credential_expired: false, credential_cure: null });
    expect(status.credential_cure).toBeNull();
  });

  it("reduce() carries status.credential_cure through status_loaded/status_updated unmodified", () => {
    let state = initialState();
    state = reduce(state, {
      type: "status_loaded",
      status: makeStatus({ configured: true, credential_expired: true, credential_cure: "retry_later" }),
    });
    expect(state.status?.credential_cure).toBe("retry_later");

    state = reduce(state, { type: "status_read_requested" });
    state = reduce(state, {
      type: "status_updated",
      token: state.statusRequestGeneration,
      status: makeStatus({ configured: true, credential_expired: true, credential_cure: "re_mint" }),
    });
    expect(state.status?.credential_cure).toBe("re_mint");
  });
});

describe("reduce() — status_updated replaces the status", () => {
  it("replaces state.status with the freshly re-read status", () => {
    let state = initialState();
    state = reduce(state, { type: "status_loaded", status: makeStatus({ configured: false }) });
    expect(state.status?.configured).toBe(false);

    state = reduce(state, { type: "status_read_requested" });
    state = reduce(state, {
      type: "status_updated",
      token: state.statusRequestGeneration,
      status: makeStatus({ configured: true }),
    });
    expect(state.status?.configured).toBe(true);
  });

  it("does not itself touch the severed latch", () => {
    let state = initialState();
    state = { ...state, severed: true };
    state = reduce(state, { type: "status_read_requested" });
    state = reduce(state, {
      type: "status_updated",
      token: state.statusRequestGeneration,
      status: makeStatus(),
    });
    expect(state.severed).toBe(true);
  });
});

// ===================================================================================================
// Overlapping commands each fire `refreshStatus()` in their `finally`, and
// those independent `session_status` reads can complete OUT OF ORDER: an older expired-cell
// snapshot must not repaint over the newer live one. `status_read_requested` bumps the request
// generation at issue time; `status_updated` presents the token its read captured, and the reducer
// drops a response a newer read has since superseded (same request-generation shape as
// `bodyRequestGeneration` / `listGeneration`).
// ===================================================================================================
describe("reduce() — status_updated drops a superseded response", () => {
  it("an older read's late response cannot overwrite the newer read's already-landed status", () => {
    let state = initialState();
    // Read A issued, then read B issued — B is now the live request.
    state = reduce(state, { type: "status_read_requested" });
    const tokenA = state.statusRequestGeneration;
    state = reduce(state, { type: "status_read_requested" });
    const tokenB = state.statusRequestGeneration;
    // B's (newer) response lands first…
    state = reduce(state, {
      type: "status_updated",
      token: tokenB,
      status: makeStatus({ configured: true, credential_expired: false }),
    });
    expect(state.status?.credential_expired).toBe(false);
    // …then A's stale expired-cell snapshot arrives late: dropped, B's status stays painted.
    state = reduce(state, {
      type: "status_updated",
      token: tokenA,
      status: makeStatus({ configured: true, credential_expired: true, credential_cure: "re_mint" }),
    });
    expect(state.status?.credential_expired).toBe(false);
    expect(state.status?.credential_cure).toBeNull();
  });

  it("the live request's own response still lands", () => {
    let state = initialState();
    state = reduce(state, { type: "status_read_requested" });
    state = reduce(state, {
      type: "status_updated",
      token: state.statusRequestGeneration,
      status: makeStatus({ configured: true }),
    });
    expect(state.status?.configured).toBe(true);
  });

  it("status_read_requested bumps the generation monotonically and touches nothing else", () => {
    let state = initialState();
    expect(state.statusRequestGeneration).toBe(0);
    state = reduce(state, { type: "status_read_requested" });
    state = reduce(state, { type: "status_read_requested" });
    expect(state.statusRequestGeneration).toBe(2);
    expect(state.status).toBeNull();
  });
});

// ===================================================================================================
// `refresh_inbox` now answers `RefreshOutcome` (the freshness shape PLUS
// `has_more`), and a new `refresh_more_inbox` door continues the provider walk. `refresh_completed`
// is the reducer action that lands either door's result, storing `has_more` on `AppState`;
// `loadMoreAction` is the pure decision a caller consults to pick "page locally", "ask the provider
// for more", or "nothing to load".
// ===================================================================================================
describe("reduce() — refresh_completed stores has_more", () => {
  it("stores has_more: true off a refresh outcome", () => {
    let state = initialState();
    state = reduce(state, {
      type: "refresh_completed",
      freshness: { checked_through: null, stale_below: 0 },
      hasMore: true,
    });
    expect(state.hasMore).toBe(true);
  });

  it("stores has_more: false off a refresh outcome, and also updates freshness", () => {
    let state = initialState();
    state = reduce(state, {
      type: "refresh_completed",
      freshness: { checked_through: { received_at: 5, message_ref: "m5" }, stale_below: 2 },
      hasMore: false,
    });
    expect(state.hasMore).toBe(false);
    expect(state.freshness).toEqual({ checked_through: { received_at: 5, message_ref: "m5" }, stale_below: 2 });
  });

  it("a TooSoon refusal (rendered via refusal_toast, never refresh_completed) does not reset a previously-true has_more", () => {
    let state = initialState();
    state = reduce(state, {
      type: "refresh_completed",
      freshness: { checked_through: null, stale_below: 0 },
      hasMore: true,
    });
    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "too_soon", operation: "refresh_inbox", retry_after_ms: 1000 },
    });
    expect(state.hasMore).toBe(true);
  });
});

describe("reduce() — a zero-success batch preserves the prior undo offer", () => {
  it("a batch failing on its FIRST message keeps the previous toast's unconsumed keys", () => {
    let state = initialState();
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
      remainingKeys: ["u-prior"],
    });
    expect(state.toast?.undoKeys).toEqual(["u-prior"]);
    state = reduce(state, {
      type: "batch_toast",
      verbLabel: "archive",
      refs: ["m1", "m2"],
      results: [{ message_ref: "m1", ok: false, reason: "busy" }],
    });
    expect(state.toast?.undoKeys).toEqual(["u-prior"]);
  });

  it("a batch WITH successes replaces the offer with its own keys (unchanged behavior)", () => {
    let state = initialState();
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
      remainingKeys: ["u-prior"],
    });
    state = reduce(state, {
      type: "batch_toast",
      verbLabel: "archive",
      refs: ["m1"],
      results: [{ message_ref: "m1", ok: true, undo_key: "u-new", projection: { state: "current" } }],
    });
    expect(state.toast?.undoKeys).toEqual(["u-new"]);
  });
});

describe("reduce() — refresh_completed clears superseded pacing toasts", () => {
  const FRESHNESS = { checked_through: null, stale_below: 0 };

  it("a keyless busy toast is cleared when a refresh completes", () => {
    let state = initialState();
    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "busy", operation: "refresh_inbox" },
    });
    expect(state.toast?.refusalKind).toBe("busy");
    state = reduce(state, { type: "refresh_completed", freshness: FRESHNESS, hasMore: false });
    expect(state.toast).toBeNull();
  });

  it("a pacing toast carrying undo keys degrades to the undo-still-available toast, keys intact", () => {
    let state = initialState();
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
      remainingKeys: ["u1"],
    });
    state = reduce(state, {
      type: "refusal_toast",
      error: { kind: "too_soon", operation: "refresh_inbox", retry_after_ms: 1000 },
    });
    expect(state.toast?.undoKeys).toEqual(["u1"]);
    state = reduce(state, { type: "refresh_completed", freshness: FRESHNESS, hasMore: false });
    expect(state.toast?.undoKeys).toEqual(["u1"]);
    expect(state.toast?.refusalKind).toBeNull();
  });

  it("a NON-pacing toast survives a refresh completion untouched", () => {
    let state = initialState();
    state = reduce(state, {
      type: "undo_toast",
      presentation: "undone",
      projection: { state: "current" },
      remainingKeys: ["u1"],
    });
    const before = state.toast;
    state = reduce(state, { type: "refresh_completed", freshness: FRESHNESS, hasMore: false });
    expect(state.toast).toBe(before);
  });
});

describe("loadMoreAction — the load-more decision", () => {
  function makeRowFor(ref: string): InboxRow {
    return {
      message_ref: ref,
      received_at: 1,
      from_addr: "a@example.com",
      from_name: "A",
      subject: "s",
      seen: true,
      flagged: false,
    };
  }

  it("local-page when next_cursor is present", () => {
    let state = initialState();
    state = { ...state, rows: [makeRowFor("m1")], nextCursor: { received_at: 1, message_ref: "m1" } };
    expect(loadMoreAction(state)).toBe("local-page");
  });

  it("provider-fetch when the local cursor is exhausted (null) but has_more is true", () => {
    let state = initialState();
    state = { ...state, rows: [makeRowFor("m1")], nextCursor: null, hasMore: true };
    expect(loadMoreAction(state)).toBe("provider-fetch");
  });

  it("none when the local cursor is exhausted and has_more is false", () => {
    let state = initialState();
    state = { ...state, rows: [makeRowFor("m1")], nextCursor: null, hasMore: false };
    expect(loadMoreAction(state)).toBe("none");
  });

  it("next_cursor present takes precedence over has_more", () => {
    let state = initialState();
    state = {
      ...state,
      rows: [makeRowFor("m1")],
      nextCursor: { received_at: 1, message_ref: "m1" },
      hasMore: true,
    };
    expect(loadMoreAction(state)).toBe("local-page");
  });
});

// ===================================================================================================
// AN EMPTY LIST MUST STILL REACH LOAD-MORE. `loadMoreAction` never looked at
// `rows.length` at all, so it already answered "provider-fetch" for an empty list with `hasMore:
// true` — but `main.ts`'s `move_down` handler gated the call behind `rows.length > 0 &&
// focusIndex === rows.length - 1` ("at the last row"), which an EMPTY list can never satisfy: there
// is no "last row" to be at. `shouldLoadMoreOnMoveDown` is the caller's full contract — the pure
// decision `j` consults — so the empty-list case is reachable at the state layer, not just inside
// `loadMoreAction`'s own cursor/has_more math.
// ===================================================================================================
describe("shouldLoadMoreOnMoveDown — the j-key load-more trigger, empty list included", () => {
  function makeRowFor(ref: string): InboxRow {
    return {
      message_ref: ref,
      received_at: 1,
      from_addr: "a@example.com",
      from_name: "A",
      subject: "s",
      seen: true,
      flagged: false,
    };
  }

  it("an EMPTY list with has_more true must reach provider-fetch — a regression case", () => {
    let state = initialState();
    state = { ...state, rows: [], nextCursor: null, hasMore: true, focusIndex: 0 };
    expect(shouldLoadMoreOnMoveDown(state)).toBe(true);
  });

  it("an EMPTY list with nothing more to load never fires", () => {
    let state = initialState();
    state = { ...state, rows: [], nextCursor: null, hasMore: false, focusIndex: 0 };
    expect(shouldLoadMoreOnMoveDown(state)).toBe(false);
  });

  it("a non-empty list still requires focus at the LAST loaded row", () => {
    let state = initialState();
    state = {
      ...state,
      rows: [makeRowFor("m1"), makeRowFor("m2")],
      nextCursor: null,
      hasMore: true,
      focusIndex: 0,
    };
    expect(shouldLoadMoreOnMoveDown(state)).toBe(false);
  });

  it("a non-empty list at the last row with more to load fires — unchanged from before", () => {
    let state = initialState();
    state = {
      ...state,
      rows: [makeRowFor("m1"), makeRowFor("m2")],
      nextCursor: null,
      hasMore: true,
      focusIndex: 1,
    };
    expect(shouldLoadMoreOnMoveDown(state)).toBe(true);
  });

  it("a non-empty list at the last row with nothing more to load never fires", () => {
    let state = initialState();
    state = {
      ...state,
      rows: [makeRowFor("m1")],
      nextCursor: null,
      hasMore: false,
      focusIndex: 0,
    };
    expect(shouldLoadMoreOnMoveDown(state)).toBe(false);
  });
});

// ===================================================================================================
// AFTER A PROVIDER CONTINUATION, THE LOADED WINDOW IS RE-READ, NOT
// APPENDED TO.
//
// `refresh_more_inbox` is purely additive in the store (it removes nothing), but
// ingest UPSERTS. A row the continuation returned that is already on screen comes back with the
// provider's CURRENT headers — read/unread, starred, a corrected subject. Appending the tail cannot
// land those: `page_appended` dedupes by ref and keeps the copy already displayed. The first test
// below is that defect, pinned; the second is the shape `loadNextPage` now ships.
// ===================================================================================================
describe("post-continuation window reload", () => {
  function rowWith(ref: string, subject: string, seen: boolean): InboxRow {
    return { ...makeRow(ref), subject, seen };
  }

  it("THE DEFECT: page_appended dedupes by ref, so a re-returned row's UPDATED headers are dropped", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [rowWith("m1", "old subject", false), rowWith("m2", "two", false)],
      nextCursor: null,
      freshness: null,
    });

    // The continuation re-returned m1 — now read, now re-titled — plus a new tail row.
    state = reduce(state, {
      type: "page_appended",
      rows: [rowWith("m1", "NEW subject", true), rowWith("m3", "three", false)],
      nextCursor: null,
      generation: state.listGeneration,
    });

    expect(state.rows.map((r) => r.subject)).toEqual(["old subject", "two", "three"]);
    expect(state.rows[0].seen).toBe(false);
  });

  it("THE SHIPPED SHAPE: a whole-window page_loaded lands the update and preserves focus + selection", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [rowWith("m1", "old subject", false), rowWith("m2", "two", false), rowWith("m3", "three", false)],
      nextCursor: null,
      freshness: null,
    });
    state = { ...state, focusIndex: 2, selected: new Set(["m1", "m3", "gone"]) };

    // The re-page walks from the top: the same rows in the same order, with current headers, plus
    // the row the continuation made reachable.
    state = reduce(state, {
      type: "page_loaded",
      rows: [
        rowWith("m1", "NEW subject", true),
        rowWith("m2", "two", false),
        rowWith("m3", "three", false),
        rowWith("m4", "four", false),
      ],
      nextCursor: null,
      freshness: null,
    });

    expect(state.rows.map((r) => r.subject)).toEqual(["NEW subject", "two", "three", "four"]);
    expect(state.rows[0].seen).toBe(true);
    expect(state.focusIndex).toBe(2);
    expect(state.rows[state.focusIndex].message_ref).toBe("m3");
    expect(state.selected).toEqual(new Set(["m1", "m3"]));
  });

  it("windowReloadDepth covers everything already loaded PLUS the page the continuation added", () => {
    expect(windowReloadDepth(0, 50)).toBe(50);
    expect(windowReloadDepth(150, 50)).toBe(200);
  });
});

// ===================================================================================================
// `page_loaded` used to clamp the NUMERIC focus index against the incoming rows'
// length, which re-lands focus on whatever row now happens to sit at that old index. The instant a
// reload inserts a row ABOVE the focused one (new mail arrived, or an earlier row's position
// shifted), that is the WRONG row. Focus must follow the previously-focused message's IDENTITY
// (its ref) into the new rows first, and only fall back to the clamped index when that ref is
// genuinely gone.
// ===================================================================================================
describe("page_loaded resolves focus by message identity, not numeric index", () => {
  it("THE DEFECT, pinned: a row inserted above the focused one shifts the numeric index onto the wrong row", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2"), makeRow("m3")],
      nextCursor: null,
      freshness: null,
    });
    state = { ...state, focusIndex: 2 }; // focused m3

    // Reload: a new message ("m0") landed above everything else.
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m0"), makeRow("m1"), makeRow("m2"), makeRow("m3")],
      nextCursor: null,
      freshness: null,
    });

    // A bare clamped index re-lands on whatever sits at index 2 now — m2, not m3.
    expect(state.focusIndex).toBe(3);
    expect(state.rows[state.focusIndex].message_ref).toBe("m3");
  });

  it("a row inserted in the MIDDLE, above focus, still resolves to the focused ref's new index", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2"), makeRow("m3")],
      nextCursor: null,
      freshness: null,
    });
    state = { ...state, focusIndex: 2 }; // focused m3

    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("mNew"), makeRow("m2"), makeRow("m3")],
      nextCursor: null,
      freshness: null,
    });

    expect(state.focusIndex).toBe(3);
    expect(state.rows[state.focusIndex].message_ref).toBe("m3");
  });

  it("falls back to the clamped numeric index when the focused ref is genuinely gone", () => {
    let state = initialState();
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2"), makeRow("m3")],
      nextCursor: null,
      freshness: null,
    });
    state = { ...state, focusIndex: 2 }; // focused m3

    // m3 is gone entirely (archived elsewhere) — only m1/m2 remain.
    state = reduce(state, {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: null,
      freshness: null,
    });

    expect(state.focusIndex).toBe(clampFocus(2, 0, 2));
  });

  it("an empty starting focus (index 0 on a fresh store) still resolves correctly on first load", () => {
    const state = reduce(initialState(), {
      type: "page_loaded",
      rows: [makeRow("m1"), makeRow("m2")],
      nextCursor: null,
      freshness: null,
    });
    expect(state.focusIndex).toBe(0);
  });
});

// ===================================================================================================
// The plan-review state: its actions, the apply report in the BatchOutcome
// vocabulary (succeeded / failed / not attempted → applied / refused / not attempted), and the
// refusal copy keyed by the ENGINE's token.
// ===================================================================================================
describe("the plan review state", () => {
  const review: PlanReviewView = {
    plan_id: "p",
    lane: "per_member",
    presentation: {
      header: { account: "a", verb: "trash", tier: "red", count: 1, backup_coverage: false, warning: "snapshot recovery is OFF" },
      summary: { count: 1, sender_domains: [["x.com", 1]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "d", date_max: "d", total_size: null },
      rows: [{ message_ref: "m1", sender: "n@x.com", sender_address: "", sender_local: "", sender_domain: "", sender_status: "ok", subject: "s", date: "d", size: null }],
    },
    sample_k: null,
    sample_rows: null,
    expires_at: "e",
    approved: false,
    terminal: false,
    bypass_notice: null,
  };
  const outcome = (members: PlanApplyOutcome["members"], projection: PlanApplyOutcome["projection"] = { state: "current" }): PlanApplyOutcome => ({
    plan_id: "p",
    preflight: { outcome: "ready" },
    members,
    completion: "completed",
    projection,
    skipped: [],
    held: [],
    undo_keys: [],
    bypass_notice: null,
    stopped: null,
  });

  it("plan_minted opens the review with the canonical payload; plan_review_closed clears it; plan_applied reports per member and clears it", () => {
    let s = reduce(initialState(), { type: "plan_minted", review });
    expect(s.planReview?.review.plan_id).toBe("p");
    s = reduce(s, { type: "plan_review_closed" });
    expect(s.planReview).toBeNull();
    const minted = reduce(initialState(), { type: "plan_minted", review });
    s = reduce(minted, { type: "plan_applied", outcome: { plan_id: "p", preflight: { outcome: "ready" }, members: [["m1", { state: "applied" }]], completion: "completed", projection: { state: "stale", reason: "r" }, skipped: [], held: [], undo_keys: [], bypass_notice: null, stopped: null }, generation: minted.planGeneration });
    expect(s.planReview).toBeNull();
    expect(s.toast?.message).toContain("1 applied");
  });

  it("a plan refusal renders the engine's token through PLAN_REFUSAL_COPY, never raw prose, and the diff atoms verbatim", () => {
    const s = reduce(initialState(), { type: "plan_refusal_toast", refusal: { kind: "plan_refused", reason: "state_diverged", member_ref: "m1", diff: [{ atom: "membership:INBOX", expected: true, observed: false }] } });
    expect(s.toast?.message).toBe(PLAN_REFUSAL_COPY.state_diverged);
    expect(s.toast?.refusalKind).toBe("plan_refused");
    expect(s.toast?.detail).toEqual(["member m1", "membership:INBOX: expected true, observed false"]);
  });

  it("plan_minted opens the review NOT busy, holding the payload object it was handed", () => {
    const s = reduce(initialState(), { type: "plan_minted", review });
    expect(s.planReview).toEqual({ review, busy: false });
    expect(s.planReview?.review).toBe(review);
    expect(initialState().planReview).toBeNull();
  });

  it("plan_busy flips only the open review's busy flag, and does nothing with no review open", () => {
    const open = reduce(initialState(), { type: "plan_minted", review });
    expect(reduce(open, { type: "plan_busy", planId: "p", busy: true }).planReview).toEqual({ review, busy: true });
    expect(reduce(reduce(open, { type: "plan_busy", planId: "p", busy: true }), { type: "plan_busy", planId: "p", busy: false }).planReview?.busy).toBe(false);
    expect(reduce(initialState(), { type: "plan_busy", planId: "p", busy: true }).planReview).toBeNull();
  });

  it("plan_applied's toast counts applied / refused / not attempted from the members, and names the rest", () => {
    const toast = toastForPlanApply(
      outcome([
        ["m1", { state: "applied" }],
        ["m2", { state: "refused", reason: "snapshot_absent", diff: [] }],
        ["m3", { state: "not_minted" }],
        ["m4", { state: "not_minted" }],
        ["m5", { state: "in_flight" }],
        ["m6", { state: "terminal", status: "failed" }],
      ]),
    );
    expect(toast.message).toBe("1 applied, 1 refused, 2 not attempted, 1 in flight, 1 failed");
    expect(toast.detail).toEqual([`m2: ${PLAN_REFUSAL_COPY.snapshot_absent}`]);
    expect(toast.staleReason).toBeNull();
    expect(toast.undoKeys).toEqual([]);
    expect(toast.refusalKind).toBeNull();
  });

  it("a stale projection rides the plan toast exactly as it rides a verb toast", () => {
    const toast = toastForPlanApply(outcome([["m1", { state: "applied" }]], { state: "stale", reason: "the write failed" }));
    expect(toast.staleReason).toBe("the write failed");
    expect(toast.message).toBe("1 applied, 0 refused, 0 not attempted, row not re-checked — the row shown is from before the write");
  });

  it("a refused preflight says the plan did not run and names each diverged atom", () => {
    const toast = toastForPlanApply({
      plan_id: "p",
      preflight: { outcome: "refused", diverged: [["m1", [{ atom: "membership:INBOX", expected: true, observed: false }]]] },
      members: [["m1", { state: "not_minted" }], ["m2", { state: "not_minted" }]],
      completion: "invalidated",
      projection: { state: "current" },
      skipped: [],
      held: [],
      undo_keys: [],
      bypass_notice: null,
      stopped: null,
    });
    expect(toast.message).toBe("plan not run: 1 of 2 members changed since approval — nothing was touched; re-plan from the current state");
    expect(toast.detail).toEqual(["m1 — membership:INBOX: expected true, observed false"]);
  });

  it("a plan toast lands over a keyed toast without destroying its undo offer", () => {
    const keyed = reduce(initialState(), { type: "verb_toast", verbLabel: "archive", undoKey: "k1", projection: { state: "current" } });
    const refused = reduce(keyed, { type: "plan_refusal_toast", refusal: { kind: "plan_child_refused", reason: "not_ready" } });
    expect(refused.toast?.undoKeys).toEqual(["k1"]);
    const applied = reduce(keyed, { type: "plan_applied", outcome: outcome([["m1", { state: "applied" }]]), generation: keyed.planGeneration });
    expect(applied.toast?.undoKeys).toEqual(["k1"]);
  });

  it("PLAN_REFUSAL_COPY: an unknown token renders AS the token — never a blank, never an inherited property", () => {
    expect(planRefusalMessage({ kind: "plan_refused", reason: "a_token_this_build_has_no_copy_for", member_ref: null, diff: [] })).toBe("a_token_this_build_has_no_copy_for");
    expect(planRefusalMessage({ kind: "plan_child_refused", reason: "constructor" })).toBe("constructor");
    expect(planRefusalMessage({ kind: "plan_required" })).toBe(PLAN_REFUSAL_COPY.plan_required);
    expect(planRefusalMessage({ kind: "plan_child_refused", reason: "not_ready" })).toBe(PLAN_REFUSAL_COPY.not_ready);
    for (const [token, copy] of Object.entries(PLAN_REFUSAL_COPY)) {
      expect(copy.trim().length, token).toBeGreaterThan(0);
    }
  });

  it("toastForRefusal reads the SAME copy for the three plan kinds (one map, both toasts)", () => {
    expect(toastForRefusal({ kind: "plan_child_refused", reason: "expired" }).message).toBe(PLAN_REFUSAL_COPY.expired);
    expect(toastForRefusal({ kind: "plan_required" }).message).toBe(PLAN_REFUSAL_COPY.plan_required);
  });

  // EVERY token the shell can put in a plan refusal's `reason` has its own sentence.
  // The shell's tokens live in ONE closed table — `closed_wire_tokens!`'s
  // `PlanWireToken` in `src-tauri/src/lib.rs` — and the engine's send-fence tokens in
  // `PlanSendRefusal::TOKENS` (`crates/aruna/src/plan.rs`); this test reads both. An inline token
  // cannot hide from it: the next test refuses any string literal inside a plan-refusal
  // construction anywhere in the shell's production source.
  it("PLAN_REFUSAL_COPY covers every token the Rust side emits (one closed table + the engine's TOKENS)", () => {
    const NL = String.fromCharCode(10);
    const read = (...p: string[]) => fs.readFileSync(path.resolve(__dirname, ...p), "utf8").split(String.fromCharCode(13)).join("");
    const lib = SHELL_MODULES.map((f) => read("..", "..", "src-tauri", "src", f)).join(NL);
    const plan = read("..", "..", "crates", "aruna", "src", "plan.rs");
    const body = (source: string, head: string, end: string) => {
      const at = source.indexOf(head);
      expect(at, head).toBeGreaterThanOrEqual(0);
      return source.slice(at, source.indexOf(end, at));
    };
    const code = (text: string) => text.split(NL).filter((l) => !l.trim().startsWith("//")).join(NL);
    const literals = (text: string) => [...code(text).matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
    const table = literals(body(lib, "enum PlanWireToken {", NL + "}" + NL));
    expect(table.length).toBeGreaterThanOrEqual(37);
    expect(new Set(table).size, "each token is spelled once").toBe(table.length);
    const emitted = new Set<string>([...table, ...literals(body(plan, "pub const TOKENS: [&'static str; 15]", "];")), "plan_required"]);
    const missing = [...emitted].filter((t) => !Object.prototype.hasOwnProperty.call(PLAN_REFUSAL_COPY, t));
    expect(missing).toEqual([]);
  });

  it("no plan refusal in the shell's production source is built from an inline string literal", () => {
    const NL = String.fromCharCode(10);
    const production = shellProduction();
    expect(production.length).toBeGreaterThan(10_000);
    const offenders: string[] = [];
    for (const head of ["PlanChildRefused {", "PlanRefused {"]) {
      let at = production.indexOf(head);
      while (at >= 0) {
        const construction = production.slice(at, production.indexOf("}", at));
        if (/reason:\s*"/.test(construction)) {
          offenders.push(construction.split(NL).join(" "));
        }
        at = production.indexOf(head, at + head.length);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("selectionTargets: the selected set in row order, else the focused row, else nothing", () => {
    const row = (ref: string) => ({ message_ref: ref, received_at: 0, from_addr: "", from_name: "", subject: "", seen: false, flagged: false });
    const base = { ...initialState(), rows: [row("a"), row("b"), row("c")], focusIndex: 1 };
    expect(selectionTargets(base)).toEqual(["b"]);
    expect(selectionTargets({ ...base, selected: new Set(["c", "a"]) })).toEqual(["a", "c"]);
    expect(selectionTargets({ ...initialState() })).toEqual([]);
  });

});

// The undo presentation reads the effect witness. `VerbOutcome` /
// `UndoOutcome` carry the engine's restoration verdict as a TAGGED value (`verdict`); the verb toast
// and the undo toast compose its UNDETERMINED line verbatim beside the offer, and a within-closure
// outcome renders exactly today's toast.
describe("the restoration verdict beside the undo offer", () => {
  const CURRENT = { state: "current" } as const;
  const OUTSIDE: RestorationView = { verdict: "outside_closure", system_labels: ["IMPORTANT"], user_label_count: 0 };
  const NO_PRE: RestorationView = { verdict: "no_pre_effect_vector" };
  const NO_WITNESS: RestorationView = { verdict: "no_effect_witness" };
  const WITHIN: RestorationView = { verdict: "within_closure" };
  const LINES: [RestorationView, string][] = [
    [OUTSIDE, "restoration UNDETERMINED (labels outside the declared closure changed: IMPORTANT)"],
    [NO_PRE, "restoration UNDETERMINED (no pre-effect vector)"],
    [NO_WITNESS, "restoration UNDETERMINED (no effect witness)"],
  ];

  it("restorationLine composes the three UNDETERMINED lines verbatim; within_closure and no verdict compose none", () => {
    for (const [verdict, line] of LINES) {
      expect(restorationLine(verdict)).toBe(line);
    }
    expect(restorationLine(WITHIN)).toBeNull();
    expect(restorationLine(null)).toBeNull();
    expect(restorationLine({ verdict: "unreadable" })).toBe("restoration UNDETERMINED (the effect witness could not be read)");
  });

  it("user labels are COUNTED, never named (the ripple drill's banking rule); system labels are named", () => {
    expect(restorationLine({ verdict: "outside_closure", system_labels: ["IMPORTANT", "STARRED"], user_label_count: 2 })).toBe(
      "restoration UNDETERMINED (labels outside the declared closure changed: IMPORTANT, STARRED, 2 user labels)",
    );
    expect(restorationLine({ verdict: "outside_closure", system_labels: [], user_label_count: 1 })).toBe(
      "restoration UNDETERMINED (labels outside the declared closure changed: 1 user label)",
    );
  });

  it("the verb toast renders each UNDETERMINED line beside the offer, through the detail sink", () => {
    for (const [verdict, line] of LINES) {
      const toast = toastForVerb("archive", "k1", CURRENT, verdict);
      expect(toast.message).toBe("archive applied");
      expect(toast.undoKeys).toEqual(["k1"]);
      expect(toast.detail).toEqual([line]);
    }
    const s = reduce(initialState(), { type: "verb_toast", verbLabel: "star", undoKey: "k2", projection: CURRENT, restoration: NO_WITNESS });
    expect(s.toast?.detail).toEqual(["restoration UNDETERMINED (no effect witness)"]);
  });

  it("the undo toast renders each UNDETERMINED line", () => {
    for (const [verdict, line] of LINES) {
      const toast = toastForUndo("undone", CURRENT, [], verdict);
      expect(toast.message).toBe("undo: undone");
      expect(toast.detail).toEqual([line]);
    }
    const s = reduce(initialState(), { type: "undo_toast", presentation: "undone", projection: CURRENT, restoration: OUTSIDE });
    expect(s.toast?.detail).toEqual(["restoration UNDETERMINED (labels outside the declared closure changed: IMPORTANT)"]);
  });

  it("a within-closure outcome renders the verb and undo toasts byte for byte as today", () => {
    expect(toastForVerb("archive", "k1", CURRENT, WITHIN)).toStrictEqual({ message: "archive applied", undoKeys: ["k1"], staleReason: null, refusalKind: null });
    expect(toastForVerb("archive", "k1", CURRENT, WITHIN)).toStrictEqual(toastForVerb("archive", "k1", CURRENT));
    expect(toastForUndo("undone", CURRENT, ["k0"], WITHIN)).toStrictEqual({ message: "undo: undone", undoKeys: ["k0"], staleReason: null, refusalKind: null });
    expect(toastForUndo("undone", CURRENT, ["k0"], WITHIN)).toStrictEqual(toastForUndo("undone", CURRENT, ["k0"]));
    const viaReducer = reduce(initialState(), { type: "verb_toast", verbLabel: "archive", undoKey: "k1", projection: CURRENT, restoration: WITHIN });
    expect(viaReducer.toast).toStrictEqual({ message: "archive applied", undoKeys: ["k1"], staleReason: null, refusalKind: null });
  });

  it("the batch verb toast names each succeeded message's UNDETERMINED line; a within-closure batch is today's toast", () => {
    const ok = (ref: string, restoration: RestorationView): PerMessageAttempt => ({ message_ref: ref, ok: true, undo_key: `u-${ref}`, projection: CURRENT, restoration });
    const toast = toastForBatch("archive", deriveBatchOutcome(["a", "b"], [ok("a", WITHIN), ok("b", NO_WITNESS)]));
    expect(toast.detail).toEqual(["b: restoration UNDETERMINED (no effect witness)"]);
    const clean = toastForBatch("archive", deriveBatchOutcome(["a"], [ok("a", WITHIN)]));
    expect(clean).toStrictEqual({ message: "archive: 1 succeeded, 0 failed, 0 not attempted", undoKeys: ["u-a"], staleReason: null, refusalKind: null });
  });

  it("the three UNDETERMINED sentences are the engine's own bytes (`RestorationVerdict::undetermined_line`)", () => {
    const engineDir = path.resolve(__dirname, "..", "..", "crates", "aruna", "src");
    const engine = fs.readdirSync(engineDir).filter((f) => f.endsWith(".rs")).map((f) => fs.readFileSync(path.join(engineDir, f), "utf8")).join("\n");
    for (const fragment of ['"restoration UNDETERMINED ({cause})"', '"labels outside the declared closure changed: {}"', '"no pre-effect vector"', '"no effect witness"', '"{user} user label{}"']) {
      expect(engine, fragment).toContain(fragment);
    }
  });
});

// The bypass lane skips the screen and shows its notice; the apply outcome
// names skipped and held members; the undo route walks a plan's APPLIED children last first.
describe("bypass lane, settled/held members, the plan undo route", () => {
  const NOTICE = "snapshot recovery is OFF: the verb's own warning, verbatim";
  const base: PlanReviewView = {
    plan_id: "p",
    lane: "per_member",
    presentation: {
      header: { account: "a", verb: "trash", tier: "red", count: 2, backup_coverage: false, warning: "w" },
      summary: { count: 2, sender_domains: [["x.com", 2]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "d", date_max: "d", total_size: null },
      rows: [],
    },
    sample_k: null,
    sample_rows: null,
    expires_at: "e",
    approved: false,
    terminal: false,
    bypass_notice: null,
  };
  const bypassed: PlanReviewView = { ...base, lane: "bypassed", bypass_notice: NOTICE };
  const applied = (over: Partial<PlanApplyOutcome> = {}): PlanApplyOutcome => ({
    plan_id: "p",
    preflight: { outcome: "ready" },
    members: [["m1", { state: "applied" }], ["m2", { state: "refused", reason: "state_diverged", diff: [] }], ["m3", { state: "applied" }]],
    completion: "completed",
    projection: { state: "current" },
    skipped: [],
    held: [],
    undo_keys: [
      { member_ref: "m3", undo_key: "k3", restoration: { verdict: "within_closure" } },
      { member_ref: "m1", undo_key: "k1", restoration: { verdict: "within_closure" } },
    ],
    bypass_notice: null,
    stopped: null,
    ...over,
  });

  it("a bypassed review never opens the screen; every other lane does", () => {
    expect(opensReviewScreen(bypassed)).toBe(false);
    expect(opensReviewScreen({ ...bypassed, bypass_notice: null })).toBe(false);
    expect(opensReviewScreen(base)).toBe(true);
    expect(opensReviewScreen({ ...base, lane: "aggregate" })).toBe(true);
    const s = reduce(initialState(), { type: "plan_minted", review: bypassed });
    expect(s.planReview).toBeNull();
    expect(reduce(initialState(), { type: "plan_minted", review: base }).planReview).toEqual({ review: base, busy: false });
  });

  it("the bypass notice is a NON-BLOCKING toast line before the apply, exactly when the plan carries one", () => {
    const s = reduce(initialState(), { type: "plan_minted", review: bypassed });
    expect(s.toast?.message).toBe("RED bypass is on — trash of 2 messages runs with no approval screen");
    expect(s.toast?.detail).toEqual([NOTICE]);
    expect(s.toast?.undoKeys).toEqual([]);
    expect(toastForPlanBypass(bypassed).detail).toEqual([NOTICE]);
    // The bypass lane with backups on froze no notice: the line says so by being absent.
    expect(toastForPlanBypass({ ...bypassed, bypass_notice: null })).toStrictEqual({
      message: "RED bypass is on — trash of 2 messages runs with no approval screen",
      undoKeys: [],
      staleReason: null,
      refusalKind: null,
    });
  });

  it("the outcome toast repeats the notice; a non-bypass plan never shows one", () => {
    expect(toastForPlanApply(applied({ bypass_notice: NOTICE })).detail).toContain(NOTICE);
    const plain = toastForPlanApply(applied());
    expect(plain.detail).not.toContain(NOTICE);
    expect(plain.detail).toEqual([`m2: ${PLAN_REFUSAL_COPY.state_diverged}`]);
  });

  it("the apply toast names every skipped (already settled) and every held (re-driven) member", () => {
    const toast = toastForPlanApply(applied({ skipped: ["m2", "m3"], held: ["m1"] }));
    expect(toast.message).toBe("2 applied, 1 refused, 0 not attempted, 2 skipped (already settled), 1 held (re-driven through recovery)");
    expect(toast.detail).toEqual([
      `m2: ${PLAN_REFUSAL_COPY.state_diverged}`,
      "m2: skipped — already settled",
      "m3: skipped — already settled",
      "m1: held — re-driven through recovery",
    ]);
  });

  it("the apply toast offers the APPLIED children's undo keys in the order the engine gave them (last first), each labelled with its member", () => {
    const toast = toastForPlanApply(applied());
    expect(toast.undoKeys).toEqual(["k3", "k1"]);
    expect(toast.undoLabels).toEqual({ k3: "m3", k1: "m1" });
    // A plan whose children all refused offers nothing to undo.
    const none = toastForPlanApply(applied({ members: [["m2", { state: "refused", reason: "state_diverged", diff: [] }]], undo_keys: [] }));
    expect(none.undoKeys).toEqual([]);
    expect(none.undoLabels).toBeUndefined();
  });

  it("a plan toast WITH its own undo keys replaces the previous offer; one without keeps it", () => {
    const keyed = reduce(initialState(), { type: "verb_toast", verbLabel: "archive", undoKey: "k0", projection: { state: "current" } });
    expect(reduce(keyed, { type: "plan_applied", outcome: applied(), generation: keyed.planGeneration }).toast?.undoKeys).toEqual(["k3", "k1"]);
    expect(reduce(keyed, { type: "plan_applied", outcome: applied({ undo_keys: [] }), generation: keyed.planGeneration }).toast?.undoKeys).toEqual(["k0"]);
  });

  it("the plan undo toast lists each member's verdict (and its restoration line) and keeps the unspent keys labelled", () => {
    const steps: PlanUndoStep[] = [
      { member: "m3", presentation: "undone", projection: { state: "current" }, restoration: { verdict: "within_closure" } },
      { member: "m1", presentation: "undone", projection: { state: "current" }, restoration: { verdict: "no_effect_witness" } },
    ];
    const done = toastForPlanUndo(steps, [], { k3: "m3", k1: "m1" });
    expect(done.message).toBe("plan undo: 2 of 2 members undone");
    expect(done.detail).toEqual(["m3: undone", "m1: undone", "m1: restoration UNDETERMINED (no effect witness)"]);
    expect(done.undoKeys).toEqual([]);
    const midway = toastForPlanUndo(steps.slice(0, 1), ["k1"], { k3: "m3", k1: "m1" });
    expect(midway.message).toBe("plan undo: 1 of 1 members undone");
    expect(midway.undoKeys).toEqual(["k1"]);
    expect(midway.undoLabels).toEqual({ k1: "m1" });
    const s = reduce(initialState(), { type: "plan_undo_toast", steps, remainingKeys: [], labels: { k3: "m3", k1: "m1" } });
    expect(s.toast?.detail).toEqual(done.detail);
  });

  it("the plan apply toast carries each applied member's restoration line BESIDE its undo offer", () => {
    const toast = toastForPlanApply(
      applied({
        undo_keys: [
          { member_ref: "m3", undo_key: "k3", restoration: { verdict: "within_closure" } },
          { member_ref: "m1", undo_key: "k1", restoration: { verdict: "outside_closure", system_labels: ["IMPORTANT"], user_label_count: 2 } },
        ],
      }),
    );
    expect(toast.undoKeys).toEqual(["k3", "k1"]);
    expect(toast.undoLabels).toEqual({ k3: "m3", k1: "m1" });
    expect(toast.detail).toEqual([
      "m1: restoration UNDETERMINED (labels outside the declared closure changed: IMPORTANT, 2 user labels)",
      `m2: ${PLAN_REFUSAL_COPY.state_diverged}`,
    ]);
    // Every UNDETERMINED arm composes its line beside the offer; within_closure (or none) adds none.
    const one = (restoration: RestorationView | null) =>
      toastForPlanApply(applied({ members: [["m1", { state: "applied" }]], undo_keys: [{ member_ref: "m1", undo_key: "k1", restoration }] })).detail;
    expect(one({ verdict: "no_effect_witness" })).toEqual(["m1: restoration UNDETERMINED (no effect witness)"]);
    expect(one({ verdict: "no_pre_effect_vector" })).toEqual(["m1: restoration UNDETERMINED (no pre-effect vector)"]);
    expect(one({ verdict: "unreadable" })).toEqual(["m1: restoration UNDETERMINED (the effect witness could not be read)"]);
    expect(one({ verdict: "within_closure" })).toEqual([]);
    expect(one(null)).toEqual([]);
  });

  it("a run that STOPPED still reports what applied, offers its undo keys, and names why it stopped", () => {
    const stopped = applied({
      members: [["m1", { state: "applied" }], ["m2", { state: "not_minted" }], ["m3", { state: "not_minted" }]],
      completion: "incomplete",
      undo_keys: [{ member_ref: "m1", undo_key: "k1", restoration: { verdict: "within_closure" } }],
      stopped: { kind: "refused", reason: "admission refused: test: the message no longer resolves", terminal: false },
    });
    const toast = toastForPlanApply(stopped);
    expect(toast.message).toBe("run stopped — 1 applied, 0 refused, 2 not attempted");
    expect(toast.detail).toEqual(["why it stopped: admission refused: test: the message no longer resolves"]);
    expect(toast.undoKeys).toEqual(["k1"]);
    expect(toast.undoLabels).toEqual({ k1: "m1" });
    // A stop BEFORE the preflight decided (preflight null) is still a stop, not a refused preflight.
    const early = toastForPlanApply(
      applied({
        preflight: null,
        members: [["m1", { state: "not_minted" }]],
        completion: "incomplete",
        undo_keys: [],
        stopped: { kind: "plan_child_refused", reason: "episode_not_active" },
      }),
    );
    expect(early.message).toBe("run stopped — 0 applied, 0 refused, 1 not attempted");
    expect(early.detail).toEqual([`why it stopped: ${PLAN_REFUSAL_COPY.episode_not_active}`]);
    // Through the reducer: the stopped outcome is the new outstanding undo offer.
    const s = reduce(initialState(), { type: "plan_applied", outcome: stopped , generation: 0 });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.message).toBe("run stopped — 1 applied, 0 refused, 2 not attempted");
  });

  it("a refusal landing mid-walk keeps the unspent keys AND their member labels", () => {
    const planToast = reduce(initialState(), { type: "plan_applied", outcome: applied() , generation: 0 });
    const refused = reduce(planToast, { type: "refusal_toast", error: { kind: "refused", reason: "nope", terminal: true } });
    expect(refused.toast?.undoKeys).toEqual(["k3", "k1"]);
    expect(refused.toast?.undoLabels).toEqual({ k3: "m3", k1: "m1" });
  });
});

// A plan whose run left it INCOMPLETE (a member still in flight, the
// run went to its end with `stopped: null`) re-opens its review, so the approved, still-active plan
// offers Apply — reopen on the COMPLETION, not only on a stop. `incomplete` is the one completion
// token of an episode that is still active with work outstanding (`src-tauri/src/lib.rs`
// `completion_token`); every other token names an episode that ended.
describe("an incomplete plan re-opens its review", () => {
  const incomplete: PlanApplyOutcome = {
    plan_id: "p-inc",
    preflight: { outcome: "ready" },
    members: [["m1", { state: "in_flight" }]],
    completion: "incomplete",
    projection: { state: "stale", reason: "a plan member is still in flight" },
    skipped: [],
    held: [],
    undo_keys: [],
    bypass_notice: null,
    stopped: null,
  };

  it("incomplete with no stop ⇒ reopen; any stop ⇒ reopen; an ended episode ⇒ no reopen", () => {
    expect(reopensReviewAfterRun(incomplete)).toBe(true);
    expect(reopensReviewAfterRun({ ...incomplete, stopped: { kind: "refused", reason: "x", terminal: true } })).toBe(true);
    for (const completion of ["completed", "invalidated:expired", "cancelled", "invalidated", "no_episode"]) {
      expect(reopensReviewAfterRun({ ...incomplete, completion }), completion).toBe(false);
    }
  });

  it("the reducer half: the run's toast closes the review; the re-read review (approved, not terminal) is open and not busy — its control is Apply", () => {
    const view: PlanReviewView = {
      plan_id: "p-inc",
      lane: "per_member",
      presentation: {
        header: { account: "acct", verb: "trash", tier: "red", count: 1, backup_coverage: true, warning: null },
        summary: { count: 1, sender_domains: [["x.com", 1]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "d", date_max: "d", total_size: null },
        rows: [{ message_ref: "m1", sender: "a@x.com", sender_address: "", sender_local: "", sender_domain: "", sender_status: "ok", subject: "s", date: "d", size: null }],
      },
      sample_k: null,
      sample_rows: null,
      expires_at: "e",
      approved: false,
      terminal: false,
      bypass_notice: null,
    };
    let s = reduce(initialState(), { type: "plan_minted", review: view });
    s = reduce(s, { type: "plan_applied", outcome: incomplete, generation: s.planGeneration });
    expect(s.planReview).toBeNull();
    expect(reopensReviewAfterRun(incomplete)).toBe(true);
    s = reduce(s, { type: "plan_minted", review: { ...view, approved: true, terminal: false } });
    expect(s.planReview?.busy).toBe(false);
    expect(s.planReview?.review.approved && !s.planReview.review.terminal).toBe(true);
  });
});

// An undo offer carried onto a later toast (an unrelated refusal, a
// clipboard failure, a pacing refusal cleared by a completed refresh) carries its RESTORATION line
// with it — undo must never stay available without its qualification. The lines ride keyed by undo
// key (`Toast.undoRestoration`), beside the member labels, so a partly spent offer keeps exactly the
// lines of the keys it still holds.
describe("a carried undo offer keeps its restoration line", () => {
  const CURRENT = { state: "current" } as const;
  const NO_WITNESS: RestorationView = { verdict: "no_effect_witness" };
  const WITHIN: RestorationView = { verdict: "within_closure" };
  const LINE = "restoration UNDETERMINED (no effect witness)";
  const undetermined = () =>
    reduce(initialState(), { type: "verb_toast", verbLabel: "archive", undoKey: "k1", projection: CURRENT, restoration: NO_WITNESS });

  it("an UNDETERMINED verb toast, then an unrelated refusal: the merged toast has the undo key AND the restoration line; a clipboard failure on top carries it once more", () => {
    let s = undetermined();
    expect(s.toast?.detail).toEqual([LINE]);
    s = reduce(s, { type: "refusal_toast", error: { kind: "internal", reason: "boom" } });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail ?? []).toContain(LINE);
    s = reduce(s, { type: "copy_failed_toast" });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail).toEqual([LINE]);
  });

  it("the same through clearSupersededPacingToast: a pacing refusal carrying the offer, cleared by a completed refresh, keeps the key and the line", () => {
    let s = undetermined();
    s = reduce(s, { type: "refusal_toast", error: { kind: "too_soon", operation: "refresh_inbox", retry_after_ms: 1000 } });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail ?? []).toContain(LINE);
    const direct = clearSupersededPacingToast(s.toast);
    expect(direct?.message).toBe(UNDO_STILL_AVAILABLE_MESSAGE);
    expect(direct?.undoKeys).toEqual(["k1"]);
    expect(direct?.detail).toEqual([LINE]);
    s = reduce(s, { type: "refresh_completed", freshness: { checked_through: null, stale_below: 0 }, hasMore: false });
    expect(s.toast?.message).toBe(UNDO_STILL_AVAILABLE_MESSAGE);
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail).toEqual([LINE]);
  });

  it("a plan apply's per-member lines and a batch's per-message lines ride with THEIR keys through a refusal (labels too)", () => {
    const applied: PlanApplyOutcome = {
      plan_id: "p",
      preflight: { outcome: "ready" },
      members: [["m1", { state: "applied" }], ["m2", { state: "applied" }]],
      completion: "completed",
      projection: CURRENT,
      skipped: [],
      held: [],
      undo_keys: [
        { member_ref: "m2", undo_key: "k2", restoration: NO_WITNESS },
        { member_ref: "m1", undo_key: "k1", restoration: WITHIN },
      ],
      bypass_notice: null,
      stopped: null,
    };
    let s = reduce(initialState(), { type: "plan_applied", outcome: applied , generation: 0 });
    s = reduce(s, { type: "refusal_toast", error: { kind: "refused", reason: "nope", terminal: true } });
    expect(s.toast?.undoKeys).toEqual(["k2", "k1"]);
    expect(s.toast?.undoLabels).toEqual({ k2: "m2", k1: "m1" });
    expect(s.toast?.detail).toEqual([`m2: ${LINE}`]);
    const ok = (ref: string, restoration: RestorationView): PerMessageAttempt => ({ message_ref: ref, ok: true, undo_key: `u-${ref}`, projection: CURRENT, restoration });
    let b = reduce(initialState(), { type: "batch_toast", verbLabel: "archive", refs: ["a", "b"], results: [ok("a", NO_WITNESS), ok("b", WITHIN)] });
    b = reduce(b, { type: "copy_failed_toast" });
    expect(b.toast?.undoKeys).toEqual(["u-b", "u-a"]);
    expect(b.toast?.detail).toEqual([`a: ${LINE}`]);
  });

  it("NEIGHBOUR (the undo walk carries the unspent suffix too): the keys a walk has not spent keep their lines, and a refusal that stops the walk keeps them", () => {
    const owed = { k2: `m2: ${LINE}`, k1: `m1: ${LINE}` };
    const labels = { k2: "m2", k1: "m1" };
    const step: PlanUndoStep = { member: "m2", presentation: "undone", projection: CURRENT, restoration: null };
    let s = reduce(initialState(), { type: "plan_undo_toast", steps: [step], remainingKeys: ["k1"], labels, undoRestoration: owed });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail ?? []).toContain(`m1: ${LINE}`);
    expect(s.toast?.detail).not.toContain(`m2: ${LINE}`);
    s = reduce(s, { type: "refusal_toast", error: { kind: "internal", reason: "undo door down" } });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail ?? []).toContain(`m1: ${LINE}`);
    // The batch walk's single-undo toast too.
    let u = reduce(initialState(), { type: "undo_toast", presentation: "undone", projection: CURRENT, remainingKeys: ["u-a"], undoRestoration: { "u-a": `a: ${LINE}`, "u-b": `b: ${LINE}` } });
    expect(u.toast?.detail).toEqual([`a: ${LINE}`]);
    u = reduce(u, { type: "copy_failed_toast" });
    expect(u.toast?.undoKeys).toEqual(["u-a"]);
    expect(u.toast?.detail).toEqual([`a: ${LINE}`]);
  });
});

// The renderer halves of: the connector's
// refusal by name, a witness write that failed after settlement (named beside the offer)
// and an incomplete bypass-lane plan keeping its retry handle.
describe("the renderer halves of the capability, witness-write and bypass-retry refusals", () => {
  const CURRENT = { state: "current" } as const;
  const WITNESS_NOT_RECORDED = "effect witness not recorded — restoration UNDETERMINED (no effect witness)";

  it("`unsupported_capability` is its own sentence — this verb is not enabled on this build — with no cure invented", () => {
    const toast = toastForRefusal({ kind: "unsupported_capability" } as unknown as Parameters<typeof toastForRefusal>[0]);
    expect(toast.message).toBe("this verb is not enabled on this build");
    expect(toast.refusalKind).toBe("unsupported_capability");
  });

  // Same class as `unsupported_capability` just above, closed at
  // The credential rejection mid-run is its OWN fixed sentence, carrying nothing of
  // the connector's own message — never a `credential_rejected: ` string prefix a caller had to
  // parse out of `refused` (the pre-fix shape).
  it("`credential_rejected` is its own sentence, carrying no connector message and no cure", () => {
    const toast = toastForRefusal({ kind: "credential_rejected" } as unknown as Parameters<typeof toastForRefusal>[0]);
    expect(toast.message).toBe("the credential was rejected — check the app's credential and try again");
    expect(toast.refusalKind).toBe("credential_rejected");
  });

  it("a witness write that failed after settlement is NAMED beside the undo offer, which stays", () => {
    const failed = { verdict: "witness_write_failed" } as unknown as RestorationView;
    expect(restorationLine(failed)).toBe(WITNESS_NOT_RECORDED);
    const s = reduce(initialState(), { type: "verb_toast", verbLabel: "archive", undoKey: "k1", projection: CURRENT, restoration: failed });
    expect(s.toast?.undoKeys).toEqual(["k1"]);
    expect(s.toast?.detail).toEqual([WITNESS_NOT_RECORDED]);
  });

  const incomplete: PlanApplyOutcome = {
    plan_id: "p-bypass",
    preflight: { outcome: "ready" },
    members: [["m0", { state: "applied" }], ["m1", { state: "in_flight" }]],
    completion: "incomplete",
    projection: { state: "stale", reason: "a plan member is still in flight; its row was not updated" },
    skipped: [],
    held: [],
    undo_keys: [{ member_ref: "m0", undo_key: "k0", restoration: { verdict: "within_closure" } }],
    bypass_notice: null,
    stopped: null,
  };

  it("an INCOMPLETE bypass-lane run keeps a retry handle on the SAME plan — STATE-derived (`pendingBypassPlan`), never a field on the toast; a complete one, and a screen-lane one, keep none", () => {
    const action = { type: "plan_applied", outcome: incomplete, bypass: { verb: "trash", retried: false }, generation: 0 } as unknown as Parameters<typeof reduce>[1];
    const s = reduce(initialState(), action);
    expect(s.pendingBypassPlan?.planId).toBe("p-bypass");
    // The toast itself carries no such field any more — `retryPlanId` is gone entirely.
    expect((s.toast as unknown as { retryPlanId?: string }).retryPlanId).toBeUndefined();
    expect(s.toast?.detail).toContain("plan p-bypass is incomplete — Retry re-applies this same plan; no new plan is minted");
    expect(s.toast?.undoKeys).toEqual(["k0"]);
    const done = reduce(initialState(), { ...action, outcome: { ...incomplete, members: [["m0", { state: "applied" }], ["m1", { state: "applied" }]], completion: "completed" } } as typeof action);
    expect(done.pendingBypassPlan).toBeNull();
    const screen = reduce(initialState(), { type: "plan_applied", outcome: incomplete, generation: 0 });
    expect(screen.pendingBypassPlan).toBeNull();
  });

  // GENERATED over the
  // outcome TYPE — every `stopped` value reachable per audit A3 × members-terminal
  // {all, some, none} × completion token
  // {completed, incomplete, invalidated:expired, cancelled, no_episode} × lane {screen, bypass}.
  // The RULE is written ONCE, here, never a hand-listed table of expected answers:
  //   COMPLETE ⇔ completion is a terminal token (anything but "incomplete") OR every member is
  //               already terminal (applied/refused/terminal — never not_minted/in_flight).
  //   REOPENS (screen lane's Apply, `reopensReviewAfterRun`) ⇔ NOT complete — `stopped` is not
  //   consulted here: a re-read of an incomplete plan's review screen is harmless.
  //   HANDLE SET (bypass lane's Retry, `pendingBypassPlan`) ⇔ NOT complete AND (`stopped` is
  //   `null` OR `isTerminalRefusal(stopped)` is `false`) — class A3's fix for the shape class A2
  //   left standing: a TERMINAL `stopped` (`unsupported_capability`, `plan_child_refused`,
  //   `refused{terminal:true}`, …) on an otherwise-incomplete run (some, not all, members
  //   terminal) installs a Retry that would only meet the identical wall again, so the handle is
  //   NOT set for it — a bypass lane has no screen to fall back to, so this is the only door.
  const STOPPED_VALUES: Record<string, SurfaceError | null> = {
    none: null,
    store: { kind: "store", reason: "locked" },
    refused_terminal: { kind: "refused", reason: "conflict", terminal: true },
    refused_transient: { kind: "refused", reason: "in flight", terminal: false },
    plan_child_refused: { kind: "plan_child_refused", reason: "expired" },
    unsupported_capability: { kind: "unsupported_capability" },
    credential_rejected: { kind: "credential_rejected" },
  };
  const MEMBERS_SHAPES: Record<string, PlanApplyOutcome["members"]> = {
    all: [["m0", { state: "applied" }], ["m1", { state: "terminal", status: "failed" }]],
    some: [["m0", { state: "applied" }], ["m1", { state: "in_flight" }]],
    none: [["m0", { state: "not_minted" }], ["m1", { state: "in_flight" }]],
  };
  const COMPLETION_TOKENS = ["completed", "incomplete", "invalidated:expired", "cancelled", "no_episode"];
  const LANES = ["screen", "bypass"] as const;

  function ruleComplete(completion: string, members: PlanApplyOutcome["members"]): boolean {
    return completion !== "incomplete" || members.every(([, v]) => v.state !== "not_minted" && v.state !== "in_flight");
  }

  it("GENERATED: lanes × stopped × members-terminal × completion — screen reopen follows completion alone; the bypass Retry handle ALSO clears for a terminal stopped", () => {
    let cells = 0;
    for (const [stoppedName, stopped] of Object.entries(STOPPED_VALUES)) {
      for (const [membersName, members] of Object.entries(MEMBERS_SHAPES)) {
        for (const completion of COMPLETION_TOKENS) {
          for (const lane of LANES) {
            cells += 1;
            const outcome: PlanApplyOutcome = {
              plan_id: "p-gen",
              preflight: completion === "incomplete" ? { outcome: "ready" } : null,
              members,
              completion,
              projection: { state: "current" },
              skipped: [],
              held: [],
              undo_keys: [],
              bypass_notice: null,
              stopped,
            };
            const complete = ruleComplete(completion, members);
            const label = `stopped=${stoppedName} members=${membersName} completion=${completion} lane=${lane}`;
            expect(reopensReviewAfterRun(outcome), label).toBe(!complete);
            const action = { type: "plan_applied", outcome, bypass: lane === "bypass" ? { verb: "trash", retried: false } : undefined, generation: 0 } as unknown as Parameters<typeof reduce>[1];
            const s = reduce(initialState(), action);
            if (lane === "screen") {
              expect(s.pendingBypassPlan, `${label}: screen lane never sets a Retry handle`).toBeNull();
            } else {
              // Handle set iff NOT complete AND stopped is null or non-terminal.
              const expectSet = !complete && (stopped === null || !isTerminalRefusal(stopped));
              expect(s.pendingBypassPlan !== null, label).toBe(expectSet);
            }
          }
        }
      }
    }
    expect(cells).toBe(Object.keys(STOPPED_VALUES).length * 3 * COMPLETION_TOKENS.length * 2);
  });

  // The two named cells the follow-up's own RED
  // proof names directly, beside the generated table above (the same `incomplete`/"some" shape:
  // m0 applied, m1 in_flight).
  it("a TERMINAL stopped on an incomplete bypass run sets NO retry handle; a TRANSIENT one still does", () => {
    const terminalStop = reduce(initialState(), {
      type: "plan_applied",
      outcome: { ...incomplete, stopped: { kind: "unsupported_capability" } },
      bypass: { verb: "trash", retried: false },
      generation: 0,
    } as unknown as Parameters<typeof reduce>[1]);
    expect(terminalStop.pendingBypassPlan, "unsupported_capability is terminal — retrying meets the same wall").toBeNull();

    const transientStop = reduce(initialState(), {
      type: "plan_applied",
      outcome: { ...incomplete, stopped: { kind: "credential_rejected" } },
      bypass: { verb: "trash", retried: false },
      generation: 0,
    } as unknown as Parameters<typeof reduce>[1]);
    expect(transientStop.pendingBypassPlan?.planId, "credential_rejected is transient — the handle stays").toBe("p-bypass");
  });

  // Drift check: the "a run did not complete and the operator has no
  // way to continue" class (the Apply control, the bypass Retry handle). A refused Retry attempt
  // (the toast that answers it is an
  // ORDINARY refusal, replaced wholesale, same as any other) and an unrelated refresh completing —
  // neither may drop the affordance; it clears ONLY on a terminal `plan_applied` read for the SAME plan id.
  // This targeted survival check stays hand-written (not generated): it exercises SEQUENCES of actions,
  // which is a different shape than the single-outcome cells the generator above covers.
  it("the Retry handle survives a refused retry attempt and an unrelated refresh completing", () => {
    const bypass = reduce(initialState(), { type: "plan_applied", outcome: incomplete, bypass: { verb: "trash", retried: false } , generation: 0 });
    expect(bypass.pendingBypassPlan?.planId).toBe("p-bypass");
    const refusedRetry = reduce(bypass, { type: "plan_refusal_toast", refusal: { kind: "refused", reason: "retry failed" } } as unknown as Parameters<typeof reduce>[1]);
    expect(refusedRetry.pendingBypassPlan?.planId, "after a refused retry").toBe("p-bypass");
    const refreshed = reduce(bypass, { type: "refresh_completed", freshness: null, hasMore: false } as unknown as Parameters<typeof reduce>[1]);
    expect(refreshed.pendingBypassPlan?.planId, "after an unrelated refresh").toBe("p-bypass");
  });

  // The cell the OLD three-ending table never
  // constructed — `stopped !== null` PAIRED WITH a durably-terminal `completion`. A credential
  // rejection on the LAST member can leave every child terminal while still setting `stopped`; the
  // OLD `reopensReviewAfterRun` (`stopped !== null || …`) called that incomplete anyway, installing
  // a bypass-lane Retry handle that could never succeed (its `plan_apply` would just meet the same
  // wall again) and — on the screen lane — re-reading a review whose Apply control the engine's own
  // `terminal` field already refuses.
  it("a run-ending stop on the LAST member, every child terminal, is COMPLETE — no Retry handle, no reopen", () => {
    const allTerminalButStopped: PlanApplyOutcome = {
      plan_id: "p-r4-4",
      preflight: { outcome: "ready" },
      members: [["m0", { state: "applied" }], ["m1", { state: "terminal", status: "failed" }]],
      completion: "completed",
      projection: { state: "current" },
      skipped: [],
      held: [],
      undo_keys: [{ member_ref: "m0", undo_key: "k0", restoration: { verdict: "within_closure" } }],
      bypass_notice: null,
      stopped: { kind: "credential_rejected" },
    };
    expect(reopensReviewAfterRun(allTerminalButStopped)).toBe(false);
    const bypass = reduce(initialState(), {
      type: "plan_applied",
      outcome: allTerminalButStopped,
      bypass: { verb: "trash", retried: false },
      generation: 0,
    });
    expect(bypass.pendingBypassPlan, "a durably-complete run never installs a Retry handle").toBeNull();
    const screen = reduce(initialState(), { type: "plan_applied", outcome: allTerminalButStopped, generation: 0 });
    expect(screen.pendingBypassPlan).toBeNull();
  });

  // `isTerminalRefusal` is a `Record` over the CLOSED
  // `SurfaceError["kind"]` union (minus `refused`, handled separately below), so `tsc` itself is
  // the derived witness for exhaustiveness (a new kind added to `src/ipc.ts` without a
  // classification here is a compile error). This asserts A3's table verbatim for the five kinds
  // reachable as `stopped`.
  const busy: SurfaceError = { kind: "busy", operation: "refresh_inbox" };
  const tooSoon: SurfaceError = { kind: "too_soon", operation: "refresh_inbox", retry_after_ms: 1 };
  const backoff: SurfaceError = { kind: "provider_backoff", operation: "refresh_inbox", retry_after_ms: 1 };
  const credRejected: SurfaceError = { kind: "credential_rejected" };
  const store: SurfaceError = { kind: "store", reason: "locked" };
  const childRefused: SurfaceError = { kind: "plan_child_refused", reason: "not_ready" };
  const unsupported: SurfaceError = { kind: "unsupported_capability" };
  const planRefused: SurfaceError = { kind: "plan_refused", reason: "state_diverged", member_ref: null, diff: [] };
  const planRequired: SurfaceError = { kind: "plan_required" };
  it("isTerminalRefusal: A3's table for every kind reachable as PlanApplyOutcome.stopped", () => {
    for (const error of [busy, tooSoon, backoff, credRejected, store]) {
      expect(isTerminalRefusal(error), error.kind).toBe(false);
    }
    for (const error of [childRefused, unsupported, planRefused, planRequired]) {
      expect(isTerminalRefusal(error), error.kind).toBe(true);
    }
  });

  // RED before the wire split — the interim default
  // classified EVERY `refused` value terminal, regardless of its cause. Now `refused` reads its
  // OWN `terminal` field, set in the engine's one classifier from the `ExecuteError` variant.
  it("isTerminalRefusal: refused reads its OWN terminal field, never a kind-wide default", () => {
    const transientRefused: SurfaceError = { kind: "refused", reason: "in flight", terminal: false };
    const terminalRefused: SurfaceError = { kind: "refused", reason: "conflict", terminal: true };
    expect(isTerminalRefusal(transientRefused)).toBe(false);
    expect(isTerminalRefusal(terminalRefused)).toBe(true);
  });
});

// After a provider effect, a bookkeeping failure is a labelled field of
// the outcome, never a replacement of it. The renderer's half: a run whose post-run settle failed
// answers the completion `undetermined` (never a guessed one), and an undo whose read-back failed
// answers the presentation `unreadable_after_undo`.
describe("a degraded outcome is rendered as degraded, never as settled", () => {
  const undetermined: PlanApplyOutcome = {
    plan_id: "p-und",
    preflight: { outcome: "ready" },
    members: [
      ["m1", { state: "applied" }],
      ["m2", { state: "not_minted" }],
    ],
    completion: "undetermined",
    projection: { state: "current" },
    skipped: [],
    held: [],
    undo_keys: [],
    bypass_notice: null,
    stopped: { kind: "store", reason: "complete_episode_if_done: plan read: no such table: triage_plan" },
  };

  it("r6_e3_an_undetermined_completion_reopens_the_review_unless_every_member_is_settled", () => {
    expect(reopensReviewAfterRun(undetermined), "a member not settled, completion unread ⇒ reopen").toBe(true);
    expect(reopensReviewAfterRun({ ...undetermined, members: [] }), "no member known at all ⇒ reopen").toBe(true);
    expect(
      reopensReviewAfterRun({ ...undetermined, members: [["m1", { state: "applied" }]] }),
      "every last-known member settled ⇒ the plan is done",
    ).toBe(false);
  });

  it("r6_e3_the_undo_toast_names_an_unreadable_presentation", () => {
    const stale = { state: "stale", reason: "x" } as const;
    const toast = toastForUndo("unreadable_after_undo", stale, [], { verdict: "unreadable" });
    expect(toast.message).toContain("unreadable_after_undo");
    expect(toast.detail).toContain("the undo ran, but its result could not be read back — refresh to confirm");
  });
});

// A REQUEST GENERATION on the review. A run's late outcome (and its late
// reopen) belongs to the review that was open when the run began; a fresh mint since then owns the
// screen. The generation lives in state INDEPENDENTLY of `planReview` (`planGeneration`), because
// `runPlan` dispatches `plan_applied(A)` — which clears A — and THEN re-opens A: a gate on "the
// active review" would starve that legitimate reopen.
describe("a late plan result never clobbers a newer review", () => {
  const reviewFor = (planId: string, approved = false): PlanReviewView => ({
    plan_id: planId,
    lane: "per_member",
    presentation: {
      header: { account: "acct", verb: "trash", tier: "red", count: 1, backup_coverage: true, warning: null },
      summary: { count: 1, sender_domains: [["x.com", 1]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "d", date_max: "d", total_size: null },
      rows: [{ message_ref: "m1", sender: "a@x.com", sender_address: "", sender_local: "", sender_domain: "", sender_status: "ok", subject: "s", date: "d", size: null }],
    },
    sample_k: null,
    sample_rows: null,
    expires_at: "e",
    approved,
    terminal: false,
    bypass_notice: null,
  });
  const incompleteOutcome = (planId: string): PlanApplyOutcome => ({
    plan_id: planId,
    preflight: { outcome: "ready" },
    members: [["m1", { state: "in_flight" }]],
    completion: "incomplete",
    projection: { state: "stale", reason: "a plan member is still in flight" },
    skipped: [],
    held: [],
    undo_keys: [],
    bypass_notice: null,
    stopped: null,
  });

  /// Review A open and APPLYING (busy), its run's generation captured; then Escape and a fresh
  /// mint of review B while A's run is still in flight.
  function aRunningThenBMinted() {
    let s = reduce(initialState(), { type: "plan_minted", review: reviewFor("A", true) });
    s = reduce(s, { type: "plan_busy", planId: "A", busy: true });
    const generationOfA = s.planGeneration;
    s = reduce(s, { type: "plan_review_closed" });
    s = reduce(s, { type: "plan_minted", review: reviewFor("B") });
    return { s, generationOfA };
  }

  it("r6_a_stale_plan_applied_never_clears_a_newer_review", () => {
    const { s, generationOfA } = aRunningThenBMinted();
    const after = reduce(s, { type: "plan_applied", outcome: incompleteOutcome("A"), generation: generationOfA });
    expect(after.planReview?.review.plan_id, "B's review stays open").toBe("B");
    expect(after.toast?.message, "the toast half stays ungated — A's outcome is still reported").toBeDefined();
  });

  it("r6_a_stale_reopen_never_replaces_a_newer_review", () => {
    const { s, generationOfA } = aRunningThenBMinted();
    const after = reduce(s, { type: "plan_minted", review: reviewFor("A", true), generation: generationOfA });
    expect(after.planReview?.review.plan_id, "A's late reopen never replaces B").toBe("B");
  });

  it("r6_a_stale_plan_busy_never_touches_a_newer_review", () => {
    const { s } = aRunningThenBMinted();
    const after = reduce(s, { type: "plan_busy", planId: "A", busy: true });
    expect(after.planReview?.busy, "A's busy flag never lands on B").toBe(false);
  });

  it("r6_a_fresh_mint_still_replaces (KEEP-GREEN)", () => {
    let s = reduce(initialState(), { type: "plan_minted", review: reviewFor("A") });
    s = reduce(s, { type: "plan_minted", review: reviewFor("B") });
    expect(s.planReview?.review.plan_id).toBe("B");
  });

  it("r6_an_incomplete_run_still_reopens_its_own_review (KEEP-GREEN — the starvation guard)", () => {
    let s = reduce(initialState(), { type: "plan_minted", review: reviewFor("A", true) });
    s = reduce(s, { type: "plan_busy", planId: "A", busy: true });
    const generation = s.planGeneration;
    s = reduce(s, { type: "plan_applied", outcome: incompleteOutcome("A"), generation });
    expect(s.planReview, "the run's outcome closes its own review").toBeNull();
    s = reduce(s, { type: "plan_minted", review: reviewFor("A", true), generation });
    expect(s.planReview?.review.plan_id, "…and its reopen re-installs it").toBe("A");
    expect(s.planReview?.busy).toBe(false);
    // The closed-then-reopened case, named: Escape on A while its run is pending and NO new mint —
    // A's incomplete outcome still reopens A (the pin does the same).
    let t = reduce(initialState(), { type: "plan_minted", review: reviewFor("A", true) });
    const g = t.planGeneration;
    t = reduce(t, { type: "plan_review_closed" });
    t = reduce(t, { type: "plan_applied", outcome: incompleteOutcome("A"), generation: g });
    t = reduce(t, { type: "plan_minted", review: reviewFor("A", true), generation: g });
    expect(t.planReview?.review.plan_id).toBe("A");
  });

  it("r6_a_bypass_outcome_installs_its_retry_handle_while_no_review_is_open (KEEP-GREEN)", () => {
    const s = reduce(initialState(), {
      type: "plan_applied",
      outcome: incompleteOutcome("P-bypass"),
      bypass: { verb: "trash", retried: false },
      generation: initialState().planGeneration,
    });
    expect(s.planReview).toBeNull();
    expect(s.pendingBypassPlan?.planId).toBe("P-bypass");
  });
});
