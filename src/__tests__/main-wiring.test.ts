// @vitest-environment jsdom
//
// Main.ts's wiring. main.ts runs `main()` at import, so this file
// builds the app skeleton's roots (the ids `index.html` carries), replaces ONLY the Tauri bridge
// (`@tauri-apps/api/core`'s `invoke`) with a scripted double, imports main.ts once, and drives it
// with real keydown events and real clicks. Every assertion is on the COMMAND the real `ipc.ts`
// wrappers handed the bridge, and on the real DOM `render.ts` painted — nothing in main.ts, state.ts,
// render.ts or ipc.ts is mocked.
//
// What it pins:
// A SINGLE-message `#` / `!` goes through the `trash` / `mark_spam`
//   door (the single-message RED door that mints a one-member plan); a multi-message selection goes
//   through `plan_mint`.
// Escape closes an open review even while one of the review's own buttons has focus, and focus
//   moves into the review when it opens.
// A run that STOPPED answers its outcome; the review is re-read and, approved and not
//   terminal, offers Apply — which re-runs the plan without a second approval.
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { InboxRow, PlanApplyOutcome, PlanReviewView, SessionStatus } from "../ipc";

type Args = Record<string, unknown> | undefined;

const bridge = vi.hoisted(() => ({
  calls: [] as [string, Record<string, unknown> | undefined][],
  script: {} as Record<string, (args: Record<string, unknown> | undefined) => unknown>,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (command: string, args?: Record<string, unknown>) => {
    bridge.calls.push([command, args]);
    const answer = bridge.script[command];
    if (!answer) {
      throw { kind: "internal", reason: `unscripted command ${command}` };
    }
    return answer(args);
  },
}));

const STATUS: SessionStatus = {
  provider_kind: "gmail",
  account: "acct",
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
};

const row = (ref: string, receivedAt: number): InboxRow => ({
  message_ref: ref,
  received_at: receivedAt,
  from_addr: `${ref}@x.com`,
  from_name: ref,
  subject: `subject ${ref}`,
  seen: false,
  flagged: false,
});
const ROWS = [row("r0", 3_000), row("r1", 2_000), row("r2", 1_000)];

function review(planId: string, refs: string[], verb: string, over: Partial<PlanReviewView> = {}): PlanReviewView {
  return {
    plan_id: planId,
    lane: "per_member",
    presentation: {
      header: { account: "acct", verb, tier: "red", count: refs.length, backup_coverage: true, warning: null },
      summary: { count: refs.length, sender_domains: [["x.com", refs.length]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "d", date_max: "d", total_size: null },
      rows: refs.map((ref) => ({ message_ref: ref, sender: `${ref}@x.com`, sender_address: "", sender_local: "", sender_domain: "", sender_status: "ok", subject: `subject ${ref}`, date: "d", size: null })),
    },
    sample_k: null,
    sample_rows: null,
    expires_at: "e",
    approved: false,
    terminal: false,
    bypass_notice: null,
    ...over,
  };
}

const commands = () => bridge.calls.map(([command]) => command);
const argsOf = (command: string): Args[] => bridge.calls.filter(([c]) => c === command).map(([, a]) => a);
const reviewRoot = () => document.getElementById("plan-review") as HTMLElement;
const toastText = () => document.getElementById("toast-region")?.textContent ?? "";

async function settle(): Promise<void> {
  for (let i = 0; i < 30; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function press(key: string, target: EventTarget = document.body): void {
  target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
}

beforeAll(async () => {
  for (const id of ["banner-region", "status-bar", "list-scroll", "reading-pane", "freshness-footer", "plan-review", "toast-region"]) {
    const el = document.createElement(id === "list-scroll" || id === "plan-review" ? "section" : "div");
    el.id = id;
    document.body.appendChild(el);
  }
  const inner = document.createElement("div");
  inner.id = "list-inner";
  (document.getElementById("list-scroll") as HTMLElement).appendChild(inner);
  bridge.script.session_status = () => STATUS;
  bridge.script.inbox_page = () => ({ rows: ROWS, next_cursor: null, freshness: null });
  await import("../main");
  await settle();
});

describe("main.ts's wiring, executed against the real modules", () => {
  it("boots: the status and the first page are read through the bridge", () => {
    expect(commands()).toEqual(["session_status", "inbox_page"]);
  });

  it("a single-message # goes through the trash door (a one-member plan), never plan_mint; focus moves into the review and Escape closes it with the approve button focused", async () => {
    bridge.calls.length = 0;
    bridge.script.trash = (args) => review("p-single-trash", [String(args?.messageRef)], "trash");
    press("#");
    await settle();
    expect(argsOf("trash")).toEqual([{ account: "acct", messageRef: "r0" }]);
    expect(commands()).not.toContain("plan_mint");
    expect(reviewRoot().querySelector(".plan-review-panel")).not.toBeNull();
    // The review took the keyboard when it opened.
    expect(reviewRoot().contains(document.activeElement)).toBe(true);
    // Escape with a review BUTTON focused still closes the review.
    const approve = reviewRoot().querySelector(".plan-approve") as HTMLButtonElement;
    approve.focus();
    expect(document.activeElement).toBe(approve);
    press("Escape", approve);
    await settle();
    expect(reviewRoot().childNodes.length).toBe(0);
  });

  it("a single-message ! goes through the mark_spam door", async () => {
    bridge.calls.length = 0;
    bridge.script.mark_spam = (args) => review("p-single-spam", [String(args?.messageRef)], "mark_spam");
    press("!");
    await settle();
    expect(argsOf("mark_spam")).toEqual([{ account: "acct", messageRef: "r0" }]);
    expect(commands()).not.toContain("plan_mint");
    const cancel = reviewRoot().querySelector(".plan-cancel") as HTMLButtonElement;
    cancel.focus();
    press("Escape", cancel);
    await settle();
    expect(reviewRoot().childNodes.length).toBe(0);
  });

  it("a multi-message selection goes through plan_mint, for # and for !", async () => {
    press("x"); // select r0
    press("j");
    press("x"); // select r1
    await settle();
    for (const [key, verb] of [["#", "trash"], ["!", "mark_spam"]] as const) {
      bridge.calls.length = 0;
      bridge.script.plan_mint = (args) => review(`p-multi-${verb}`, args?.memberRefs as string[], verb);
      press(key);
      await settle();
      expect(argsOf("plan_mint")).toEqual([{ account: "acct", verb, memberRefs: ["r0", "r1"], rationale: null }]);
      expect(commands()).not.toContain("trash");
      expect(commands()).not.toContain("mark_spam");
      press("Escape");
      await settle();
      expect(reviewRoot().childNodes.length).toBe(0);
    }
    // Back to no selection, focus on r0.
    press("x"); // deselect r1
    press("k");
    press("x"); // deselect r0
    await settle();
  });

  it("a stopped run answers its outcome; the review is re-read and offers Apply, which re-runs the plan with no second approval", async () => {
    bridge.calls.length = 0;
    const planId = "p-stopped";
    let applies = 0;
    bridge.script.trash = (args) => review(planId, [String(args?.messageRef)], "trash");
    bridge.script.plan_approve = () => ({ plan_id: planId, comprehension: "per_member", approver: "operator" });
    const stopped: PlanApplyOutcome = {
      plan_id: planId,
      preflight: null,
      members: [["r0", { state: "not_minted" }]],
      completion: "incomplete",
      projection: { state: "current" },
      skipped: [],
      held: [],
      undo_keys: [],
      bypass_notice: null,
      stopped: { kind: "refused", reason: "the provider rejected this session's credential", terminal: false },
    };
    const completed: PlanApplyOutcome = {
      ...stopped,
      preflight: { outcome: "ready" },
      members: [["r0", { state: "applied" }]],
      completion: "completed",
      undo_keys: [{ member_ref: "r0", undo_key: "k0", restoration: { verdict: "within_closure" } }],
      stopped: null,
    };
    bridge.script.plan_apply = () => {
      applies += 1;
      return applies === 1 ? stopped : completed;
    };
    bridge.script.plan_review = () => review(planId, ["r0"], "trash", { approved: true, terminal: false });
    press("#");
    await settle();
    (reviewRoot().querySelector(".plan-approve") as HTMLButtonElement).click();
    await settle();
    expect(commands().filter((c) => c === "plan_approve")).toHaveLength(1);
    expect(applies).toBe(1);
    expect(toastText()).toContain("run stopped");
    const apply = reviewRoot().querySelector(".plan-apply") as HTMLButtonElement | null;
    expect(apply?.textContent).toBe("Apply 1 — trash");
    expect(apply?.disabled).toBe(false);
    apply?.click();
    await settle();
    expect(applies).toBe(2);
    expect(commands().filter((c) => c === "plan_approve")).toHaveLength(1);
    expect(reviewRoot().childNodes.length).toBe(0);
    expect(toastText()).toContain("1 applied");
  });

  it("a run that did NOT stop but left the plan INCOMPLETE (a member still in flight) re-reads the review, which offers an enabled Apply; a run that ended the episode does not", async () => {
    bridge.calls.length = 0;
    const planId = "p-incomplete";
    let applies = 0;
    bridge.script.trash = (args) => review(planId, [String(args?.messageRef)], "trash");
    bridge.script.plan_approve = () => ({ plan_id: planId, comprehension: "per_member", approver: "operator" });
    // Reproduction: a transient member failure left the member's child in flight, the run
    // went on to its end (`stopped: null`), and the episode is still active — `incomplete`.
    const incomplete: PlanApplyOutcome = {
      plan_id: planId,
      preflight: { outcome: "ready" },
      members: [["r0", { state: "in_flight" }]],
      completion: "incomplete",
      projection: { state: "stale", reason: "a plan member is still in flight" },
      skipped: [],
      held: [],
      undo_keys: [],
      bypass_notice: null,
      stopped: null,
    };
    bridge.script.plan_apply = () => {
      applies += 1;
      return applies === 1 ? incomplete : { ...incomplete, completion: "invalidated:expired" };
    };
    bridge.script.plan_review = () => review(planId, ["r0"], "trash", { approved: true, terminal: false });
    press("#");
    await settle();
    (reviewRoot().querySelector(".plan-approve") as HTMLButtonElement).click();
    await settle();
    expect(applies).toBe(1);
    expect(commands()).toContain("plan_review");
    const apply = reviewRoot().querySelector(".plan-apply") as HTMLButtonElement | null;
    expect(apply?.textContent).toBe("Apply 1 — trash");
    expect(apply?.disabled).toBe(false);
    // Apply re-runs the plan with no second approval; this run ends the episode (expired), so
    // nothing re-opens.
    bridge.calls.length = 0;
    apply?.click();
    await settle();
    expect(applies).toBe(2);
    expect(commands()).not.toContain("plan_approve");
    expect(commands()).not.toContain("plan_review");
    expect(reviewRoot().childNodes.length).toBe(0);
  });

  it("an undo walk that stops part-way keeps each unspent key's restoration line beside the offer it still holds", async () => {
    bridge.calls.length = 0;
    const planId = "p-undo-walk";
    const LINE = "restoration UNDETERMINED (no effect witness)";
    bridge.script.trash = (args) => review(planId, [String(args?.messageRef)], "trash");
    bridge.script.plan_approve = () => ({ plan_id: planId, comprehension: "per_member", approver: "operator" });
    bridge.script.plan_apply = (): PlanApplyOutcome => ({
      plan_id: planId,
      preflight: { outcome: "ready" },
      members: [["m0", { state: "applied" }], ["m1", { state: "applied" }]],
      completion: "completed",
      projection: { state: "current" },
      skipped: [],
      held: [],
      undo_keys: [
        { member_ref: "m1", undo_key: "k1", restoration: { verdict: "no_effect_witness" } },
        { member_ref: "m0", undo_key: "k0", restoration: { verdict: "no_effect_witness" } },
      ],
      bypass_notice: null,
      stopped: null,
    });
    let undos = 0;
    bridge.script.undo = () => {
      undos += 1;
      if (undos === 1) {
        return { undone: true, presentation: "undone", projection: { state: "current" }, restoration: null };
      }
      throw { kind: "internal", reason: "undo door down" };
    };
    press("#");
    await settle();
    (reviewRoot().querySelector(".plan-approve") as HTMLButtonElement).click();
    await settle();
    expect(toastText()).toContain(`m0: ${LINE}`);
    expect(toastText()).toContain(`m1: ${LINE}`);
    (document.querySelector(".toast-undo-button") as HTMLButtonElement).click();
    await settle();
    expect(undos).toBe(2);
    // k1 was undone; k0's undo threw — k0 is still on offer, WITH its restoration line.
    expect(document.querySelector(".toast-undo-button")).not.toBeNull();
    expect(toastText()).toContain(`m0: ${LINE}`);
  });

  // A bypass-lane plan has no screen, so a
  // run that leaves it INCOMPLETE (a transient failure at member 2 left its child in flight) must keep
  // a retry handle — the toast names the plan and offers Retry, which calls `plan_apply` on the SAME
  // plan: no new mint, no screen, no approval. And while it is pending, `#` on the same selection
  // re-applies THAT plan and says so.
  const bypassIncomplete = (planId: string): PlanApplyOutcome => ({
    plan_id: planId,
    preflight: { outcome: "ready" },
    members: [["r0", { state: "applied" }], ["r1", { state: "in_flight" }]],
    completion: "incomplete",
    projection: { state: "stale", reason: "a plan member is still in flight; its row was not updated" },
    skipped: [],
    held: [],
    undo_keys: [{ member_ref: "r0", undo_key: "k0", restoration: { verdict: "within_closure" } }],
    bypass_notice: null,
    stopped: null,
  });
  const bypassCompleted = (planId: string): PlanApplyOutcome => ({
    ...bypassIncomplete(planId),
    members: [["r0", { state: "applied" }], ["r1", { state: "applied" }]],
    completion: "completed",
    projection: { state: "current" },
    skipped: ["r0"],
    held: ["r1"],
    undo_keys: [
      { member_ref: "r1", undo_key: "k1", restoration: { verdict: "within_closure" } },
      { member_ref: "r0", undo_key: "k0", restoration: { verdict: "within_closure" } },
    ],
  });

  it("an INCOMPLETE bypass-lane plan keeps a retry handle — Retry calls plan_apply on the SAME plan (no mint, no screen, no approval) and member 2 applies under it", async () => {
    const planId = "p-bypass-retry";
    let applies = 0;
    bridge.script.plan_mint = (args) => review(planId, args?.memberRefs as string[], "trash", { lane: "bypassed" });
    bridge.script.plan_apply = (args) => {
      applies += 1;
      expect(args).toEqual({ planId });
      return applies === 1 ? bypassIncomplete(planId) : bypassCompleted(planId);
    };
    press("x"); // select r0
    press("j");
    press("x"); // select r1
    await settle();
    bridge.calls.length = 0;
    press("#");
    await settle();
    expect(argsOf("plan_mint")).toHaveLength(1);
    expect(applies).toBe(1);
    expect(reviewRoot().childNodes.length).toBe(0);
    expect(toastText()).toContain(`plan ${planId} is incomplete`);
    const retry = document.querySelector(".toast-retry-button") as HTMLButtonElement | null;
    expect(retry?.textContent).toBe("Retry");
    // The handle names the PLAN, not the selection: moving the selection off the plan's members
    // does not change what Retry runs.
    press("x"); // deselect r1 (focus is on r1)
    await settle();
    bridge.calls.length = 0;
    (document.querySelector(".toast-retry-button") as HTMLButtonElement).click();
    await settle();
    expect(applies).toBe(2);
    expect(argsOf("plan_apply")).toEqual([{ planId }]);
    expect(commands()).not.toContain("plan_mint");
    expect(commands()).not.toContain("plan_approve");
    expect(commands()).not.toContain("plan_review");
    expect(toastText()).toContain("2 applied");
    expect(document.querySelector(".toast-retry-button")).toBeNull();
    press("x"); // re-select r1 — the next test starts from r0 + r1 selected
    await settle();
  });

  it("while an incomplete bypass plan is pending, # on the SAME selection re-applies that plan — no new mint — and the toast says so", async () => {
    const planId = "p-bypass-rekey";
    let applies = 0;
    bridge.script.plan_mint = (args) => review(planId, args?.memberRefs as string[], "trash", { lane: "bypassed" });
    bridge.script.plan_apply = () => {
      applies += 1;
      return applies === 1 ? bypassIncomplete(planId) : bypassCompleted(planId);
    };
    bridge.calls.length = 0;
    press("#"); // the selection is still r0 + r1
    await settle();
    expect(argsOf("plan_mint")).toHaveLength(1);
    expect(applies).toBe(1);
    bridge.calls.length = 0;
    press("#");
    await settle();
    expect(commands()).not.toContain("plan_mint");
    expect(argsOf("plan_apply")).toEqual([{ planId }]);
    expect(applies).toBe(2);
    expect(toastText()).toContain(`re-applied the incomplete plan ${planId} — no new plan was minted`);
    // Back to no selection.
    press("x"); // deselect r1
    press("k");
    press("x"); // deselect r0
    await settle();
  });

  // The stuck-Retry catch path. A BARE refusal
  // thrown by `plan_apply` on a bypass-lane Retry never reaches the `plan_applied` reducer case —
  // the only OTHER place `pendingBypassPlan` is cleared — so the OLD code left the handle installed
  // forever: every subsequent `#`/`!` on the same selection, and every subsequent Retry click, kept
  // re-applying the same dead plan. A TERMINAL refusal (`plan_child_refused: expired`, the exact
  // shape `start_episode` answers for an expired plan) must clear it; a TRANSIENT one must not.
  it("a TERMINAL bare refusal on Retry (an expired plan) clears the handle; a TRANSIENT one keeps it", async () => {
    const planId = "p-bypass-expired";
    let applies = 0;
    bridge.script.plan_mint = (args) => review(planId, args?.memberRefs as string[], "trash", { lane: "bypassed" });
    bridge.script.plan_apply = () => {
      applies += 1;
      if (applies === 1) return bypassIncomplete(planId);
      // The plan expired between the first (incomplete) run and this Retry — `start_episode`
      // refuses `expired`, a bare `plan_child_refused` thrown straight out of `plan_apply`, never
      // a `PlanApplyOutcome`.
      throw { kind: "plan_child_refused", reason: "expired" };
    };
    press("x"); // select r0
    press("j");
    press("x"); // select r1
    await settle();
    bridge.calls.length = 0;
    press("#");
    await settle();
    expect(applies).toBe(1);
    expect(document.querySelector(".toast-retry-button")).not.toBeNull();
    bridge.calls.length = 0;
    (document.querySelector(".toast-retry-button") as HTMLButtonElement).click();
    await settle();
    expect(applies).toBe(2);
    expect(
      document.querySelector(".toast-retry-button"),
      "a TERMINAL refusal (plan_child_refused) must clear the stuck handle"
    ).toBeNull();
    // A fresh `#` on the same selection now mints a NEW plan — the dead one is never re-applied.
    bridge.calls.length = 0;
    bridge.script.plan_mint = (args) => review("p-bypass-expired-2", args?.memberRefs as string[], "trash", { lane: "bypassed" });
    bridge.script.plan_apply = () => {
      applies += 1;
      return bypassCompleted("p-bypass-expired-2");
    };
    press("x"); // deselect r1
    press("k");
    press("x"); // deselect r0
    press("x"); // r0
    press("j");
    press("x"); // r1
    await settle();
    bridge.calls.length = 0;
    press("#");
    await settle();
    expect(argsOf("plan_mint")).toHaveLength(1);
    press("x");
    press("k");
    press("x");
    await settle();
  });

  it("a TRANSIENT bare refusal on Retry (a store fault) keeps the handle", async () => {
    const planId = "p-bypass-store-fault";
    let applies = 0;
    bridge.script.plan_mint = (args) => review(planId, args?.memberRefs as string[], "trash", { lane: "bypassed" });
    bridge.script.plan_apply = () => {
      applies += 1;
      if (applies === 1) return bypassIncomplete(planId);
      throw { kind: "store", reason: "database is locked" };
    };
    press("x"); // select r0
    press("j");
    press("x"); // select r1
    await settle();
    bridge.calls.length = 0;
    press("#");
    await settle();
    expect(applies).toBe(1);
    expect(document.querySelector(".toast-retry-button")).not.toBeNull();
    bridge.calls.length = 0;
    (document.querySelector(".toast-retry-button") as HTMLButtonElement).click();
    await settle();
    expect(applies).toBe(2);
    expect(
      document.querySelector(".toast-retry-button"),
      "a TRANSIENT refusal (store) must NOT clear the handle — the same plan may still apply"
    ).not.toBeNull();
    // Clean up: a successful retry clears it for the next test.
    bridge.script.plan_apply = () => {
      applies += 1;
      return bypassCompleted(planId);
    };
    (document.querySelector(".toast-retry-button") as HTMLButtonElement).click();
    await settle();
    press("x");
    press("k");
    press("x");
    await settle();
  });

  // The `refused` kind's OWN `terminal` field now
  // decides — never a kind-wide default. RED (before the wire split, the interim default
  // classified EVERY `refused` value terminal, so a TRANSIENT one — e.g. the engine's own
  // `InProgress` mapping — WRONGLY cleared a still-good retry handle).
  it("a TRANSIENT refused (InProgress) keeps the handle; a TERMINAL one (Conflict) clears it", async () => {
    const planId = "p-bypass-refused-transient";
    let applies = 0;
    bridge.script.plan_mint = (args) => review(planId, args?.memberRefs as string[], "trash", { lane: "bypassed" });
    bridge.script.plan_apply = () => {
      applies += 1;
      if (applies === 1) return bypassIncomplete(planId);
      // The engine's own ExecuteError::InProgress mapping: `{kind:"refused", terminal:false}`.
      throw { kind: "refused", reason: "this operation is still in flight — recovery owns it; retry later", terminal: false };
    };
    press("x"); // select r0
    press("j");
    press("x"); // select r1
    await settle();
    bridge.calls.length = 0;
    press("#");
    await settle();
    expect(applies).toBe(1);
    expect(document.querySelector(".toast-retry-button")).not.toBeNull();
    bridge.calls.length = 0;
    (document.querySelector(".toast-retry-button") as HTMLButtonElement).click();
    await settle();
    expect(applies).toBe(2);
    expect(
      document.querySelector(".toast-retry-button"),
      "a TRANSIENT refused (terminal: false) must NOT clear the handle"
    ).not.toBeNull();

    // Now a TERMINAL refused (the engine's own ExecuteError::Conflict mapping).
    bridge.script.plan_apply = () => {
      applies += 1;
      throw { kind: "refused", reason: "a different command already exists under this idempotency key", terminal: true };
    };
    bridge.calls.length = 0;
    (document.querySelector(".toast-retry-button") as HTMLButtonElement).click();
    await settle();
    expect(applies).toBe(3);
    expect(
      document.querySelector(".toast-retry-button"),
      "a TERMINAL refused (terminal: true) must clear the handle"
    ).toBeNull();

    // Back to no selection for the next test.
    press("x");
    press("k");
    press("x");
    await settle();
  });
});
