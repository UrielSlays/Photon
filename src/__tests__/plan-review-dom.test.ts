// @vitest-environment jsdom
//
// The plan-review screen and the toast sink, EXECUTED against a real HTML DOM
// (jsdom, a devDependency since). Until that fold this block ran against
// an in-file DOM double inside `render-contract.test.ts`; the double had no HTML parser (its
// `querySelector("img")` check could never fail), accepted class tokens a real `classList` refuses,
// and had no focus model. jsdom serves every test the double served, so the double is gone.
//
// The sink rule itself stays witnessed by `sinkfence.test.ts` (a source scan for innerHTML /
// outerHTML / insertAdjacentHTML / document.write); this file adds the EXECUTED half: eight hostile
// strings through every sink the review and its toasts write, on a DOM that would parse markup if a
// sink let it through.
import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import type { PlanReviewView, PlanRowView, RenderedViewWire, RestorationView } from "../ipc";
import type { RenderRoots } from "../render";
import { renderPlanReview, renderToast } from "../render";
import { initialState, reduce, toastForPlanRefusal, toastForUndo, toastForVerb } from "../state";

const noop = () => {};

function makeRoots(): { roots: RenderRoots; planReview: HTMLElement; toastRegion: HTMLElement } {
  const planReview = document.createElement("section");
  const toastRegion = document.createElement("div");
  document.body.appendChild(planReview);
  document.body.appendChild(toastRegion);
  return { roots: { planReview, toastRegion } as unknown as RenderRoots, planReview, toastRegion };
}

afterEach(() => {
  while (document.body.firstChild) {
    document.body.removeChild(document.body.firstChild);
  }
});

const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((el) => el.textContent);

const HOSTILE_SUBJECT = "<img src=x onerror=1>";
const REVIEW_FIXTURE: PlanReviewView = {
  plan_id: "p1",
  lane: "per_member",
  presentation: {
    header: { account: "gmail:me", verb: "trash", tier: "red", count: 2, backup_coverage: false, warning: "snapshot recovery is OFF: the warning, verbatim" },
    summary: { count: 2, sender_domains: [["x.com", 2]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "2026-09-01T00:00:00Z", date_max: "2026-09-02T00:00:00Z", total_size: null },
    rows: [
      { message_ref: "a", sender: "Ann", sender_address: "<ann@x.com>", sender_status: "ok", sender_local: "ann", sender_domain: "x.com", subject: "first subject", date: "2026-09-01T00:00:00Z", size: null },
      { message_ref: "b", sender: "Bob", sender_address: "<bob@x.com>", sender_status: "ok", sender_local: "bob", sender_domain: "x.com", subject: HOSTILE_SUBJECT, date: "2026-09-02T00:00:00Z", size: 2048 },
    ],
  },
  sample_k: null,
  sample_rows: null,
  expires_at: "2026-09-25T00:00:00Z",
  approved: false,
  terminal: false,
  bypass_notice: null,
};
const AGGREGATE_FIXTURE: PlanReviewView = {
  ...REVIEW_FIXTURE,
  plan_id: "p2",
  lane: "aggregate",
  sample_k: 1,
  sample_rows: [REVIEW_FIXTURE.presentation.rows[1]],
};

describe("renderPlanReview, executed on a real DOM", () => {
  it("renderPlanReview writes ONLY the canonical payload through textContent, in canonical row order, with the header, the coverage line and the verb warning", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    const text = planReview.textContent ?? "";
    expect(text).toContain("trash"); // header verb
    expect(text).toContain("RED"); // tier
    expect(text).toContain("2 messages"); // count
    expect(text).toContain("snapshot recovery is OFF"); // the §4.7 warning, verbatim from the payload
    expect(planReview.querySelectorAll(".plan-row").length).toBe(2);
    expect([...planReview.querySelectorAll(".plan-row")].map((r) => r.getAttribute("data-ref"))).toEqual(["a", "b"]);
    // A hostile subject renders as TEXT (the sink rule): a real parser would have made an <img>.
    expect(planReview.querySelector("img")).toBeNull();
    expect(text).toContain(HOSTILE_SUBJECT);
  });

  it("the approve control hands back EXACTLY the payload that was rendered", () => {
    const { roots, planReview } = makeRoots();
    let echoed: RenderedViewWire | null = null;
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, (rendered) => { echoed = rendered; }, noop, noop);
    (planReview.querySelector(".plan-approve") as HTMLButtonElement).click();
    expect(echoed).toEqual({ mode: "full_list", presentation: REVIEW_FIXTURE.presentation });
    // The SAME object that was rendered — never a copy re-assembled from the screen.
    expect((echoed as unknown as { presentation: unknown }).presentation).toBe(REVIEW_FIXTURE.presentation);
  });

  it("the header line names verb · TIER · count · account; the coverage line and the warning each get their own line", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    expect(texts(planReview, ".plan-header")).toEqual(["trash · RED · 2 messages · account gmail:me"]);
    expect(texts(planReview, ".plan-coverage")).toEqual(["backups: off"]);
    expect(texts(planReview, ".plan-warning")).toEqual([REVIEW_FIXTURE.presentation.header.warning]);
    expect(texts(planReview, ".plan-lane")).toEqual(["full list — every member is shown below"]);
  });

  it("covered backups: the coverage line says on and there is no warning line", () => {
    const { roots, planReview } = makeRoots();
    const covered: PlanReviewView = { ...REVIEW_FIXTURE, presentation: { ...REVIEW_FIXTURE.presentation, header: { ...REVIEW_FIXTURE.presentation.header, backup_coverage: true, warning: null } } };
    renderPlanReview(roots, { review: covered, busy: false }, noop, noop, noop);
    expect(texts(planReview, ".plan-coverage")).toEqual(["backups: on"]);
    expect(planReview.querySelectorAll(".plan-warning").length).toBe(0);
  });

  it("the summary block: the count, each (domain, n), the date range, and the size — or its honest absence", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    expect(texts(planReview, ".plan-summary-count")).toEqual(["2 messages from 1 sender domains"]);
    expect(texts(planReview, ".plan-summary-domain")).toEqual(["x.com · 2"]);
    expect(texts(planReview, ".plan-summary-dates")).toEqual(["2026-09-01T00:00:00Z – 2026-09-02T00:00:00Z"]);
    expect(texts(planReview, ".plan-summary-size")).toEqual(["size unavailable"]);
  });

  // The complement rule: a sender the
  // engine could not parse is never a domain entry (a `"" · 1` entry was once shown); the summary SAYS how
  // many members it cannot name a domain for, each on its own line — and says nothing when there
  // are none. `malformed` and `unsupported` are DISTINCT lines with distinct wording
  // `malformed` shows "normalized text shown" (never "raw text shown" — the displayed
  // fallback IS normalized), `unsupported` says the syntax is valid and no address is attributed.
  // Both lanes.
  it("an unavailable, malformed or unsupported sender is its own line, never a domain entry — both lanes", () => {
    const summary = { count: 4, sender_domains: [["evil.example", 1]] as [string, number][], sender_domain_unavailable: 1, sender_header_malformed: 2, sender_header_unsupported: 3, date_min: "d", date_max: "d", total_size: null };
    for (const fixture of [REVIEW_FIXTURE, AGGREGATE_FIXTURE]) {
      const { roots, planReview } = makeRoots();
      const review = { ...fixture, presentation: { ...fixture.presentation, summary } } as PlanReviewView;
      renderPlanReview(roots, { review, busy: false }, noop, noop, noop);
      expect(texts(planReview, ".plan-summary-domain"), fixture.lane).toEqual(["evil.example · 1"]);
      expect(texts(planReview, ".plan-summary-unavailable"), fixture.lane).toEqual(["sender domain unavailable for 1 member"]);
      expect(texts(planReview, ".plan-summary-malformed"), fixture.lane).toEqual(["malformed sender header for 2 members — normalized text shown"]);
      expect(texts(planReview, ".plan-summary-unsupported"), fixture.lane).toEqual([
        "valid sender syntax Photon does not attribute (group or multiple mailboxes) for 3 members — no sender address",
      ]);
      planReview.remove();
    }
    const { roots, planReview } = makeRoots();
    const clean = {
      ...REVIEW_FIXTURE,
      presentation: {
        ...REVIEW_FIXTURE.presentation,
        summary: { ...summary, sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0 },
      },
    } as PlanReviewView;
    renderPlanReview(roots, { review: clean, busy: false }, noop, noop, noop);
    expect(planReview.querySelectorAll(".plan-summary-unavailable, .plan-summary-malformed, .plan-summary-unsupported").length).toBe(0);
  });

  // The sender NAME and ADDRESS are two SEPARATE bidi-isolated cells now
  // (never one composed "Name <addr>" string in one isolate). Earlier,
  // the ADDRESS half is itself split into TWO isolates
  // (local part, domain) — the engine's own `sender_local`/`sender_domain` grammar tokens, never a
  // runtime split of the composed text — the parent `.plan-row-sender-address` span's OWN
  // textContent still reads the whole `<local@domain>` address (the `<`/`@`/`>` decoration are its
  // own literal text nodes), but it now holds 2 `<bdi>` children per row, not 1.
  it("each row: the sender name and address (each bidi-isolated — address split local/domain), the subject, the date and the size, as the payload spells them", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    expect(texts(planReview, ".plan-row-sender-name")).toEqual(["Ann", "Bob"]);
    expect(texts(planReview, ".plan-row-sender-address")).toEqual(["<ann@x.com>", "<bob@x.com>"]);
    expect([...planReview.querySelectorAll(".plan-row-sender-name")].map((el) => el.tagName)).toEqual(["BDI", "BDI"]);
    expect([...planReview.querySelectorAll(".plan-row-sender-address bdi")].map((el) => el.tagName)).toEqual(["BDI", "BDI", "BDI", "BDI"]);
    expect(texts(planReview, ".plan-row-sender-address-local")).toEqual(["ann", "bob"]);
    expect(texts(planReview, ".plan-row-sender-address-domain")).toEqual(["x.com", "x.com"]);
    expect(texts(planReview, ".plan-row-subject")).toEqual(["first subject", HOSTILE_SUBJECT]);
    expect(texts(planReview, ".plan-row-date")).toEqual(["2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"]);
    expect(texts(planReview, ".plan-row-size")).toEqual(["size unavailable", "2048 bytes"]);
    expect(texts(planReview, ".plan-expires")).toEqual(["approval window ends 2026-09-25T00:00:00Z"]);
  });

  // Previously the whole address (including
  // the RTL-hostile quoted local part) shared ONE isolate, and the browser's own bidi reordering
  // (UAX #9) inside that shared isolate visually swapped which text sat in the trailing,
  // domain-looking position. Giving the DOMAIN its own isolate means its text node is never inside
  // the same isolate as the hostile local part, so it can never be reordered by it: the domain
  // isolate's rendered (post-bidi-reorder) text is asserted, not just its DOM source order, to
  // prove the visual claim, not just the markup claim. The boundary is
  // now the engine's own grammar tokens (`sender_local`/`sender_domain`), never a runtime split —
  // a quoted local part's OWN embedded `@` is content the grammar already resolved.
  it("a bidi-hostile quoted local part cannot visually displace the domain — the domain gets its OWN isolate", () => {
    const hostileAddress = '<"א x@paypal.example ב"@evil.example>';
    const review: PlanReviewView = {
      ...REVIEW_FIXTURE,
      presentation: {
        ...REVIEW_FIXTURE.presentation,
        rows: [
          {
            message_ref: "hostile",
            sender: "PayPal",
            sender_address: hostileAddress,
            sender_status: "ok",
            sender_local: '"א x@paypal.example ב"',
            sender_domain: "evil.example",
            subject: "s",
            date: "d",
            size: null,
          },
        ],
      },
    };
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review, busy: false }, noop, noop, noop);
    const local = planReview.querySelector(".plan-row-sender-address-local");
    const domain = planReview.querySelector(".plan-row-sender-address-domain");
    expect(local?.tagName).toBe("BDI");
    expect(domain?.tagName).toBe("BDI");
    // The engine's own local-part token (the quoted string, embedded `@` and all, is CONTENT the
    // grammar already resolved) versus its own domain token — never a runtime split.
    expect(local?.textContent).toBe('"א x@paypal.example ב"');
    expect(domain?.textContent).toBe("evil.example");
    // The two isolates are SEPARATE DOM nodes — the domain's rendered text can never include any
    // byte from the local part's hostile content, regardless of how the browser bidi-reorders
    // GLYPHS on screen within the local isolate.
    expect(domain?.textContent).not.toContain("paypal.example");
  });

  // RED, a non-"ok" sender's status
  // text (e.g. a raw "N From header fields" marker) sat INSIDE the address isolate, where a
  // reader could mistake it for part of a real address. It now renders as its own atom, OUTSIDE
  // both address isolates.
  it("a non-ok sender's status renders as its own atom outside the address isolates", () => {
    const review: PlanReviewView = {
      ...REVIEW_FIXTURE,
      presentation: {
        ...REVIEW_FIXTURE.presentation,
        rows: [
          { message_ref: "two-from", sender: "", sender_address: "2 From header fields", sender_status: "malformed", sender_local: "", sender_domain: "", subject: "s", date: "d", size: null },
        ],
      },
    };
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review, busy: false }, noop, noop, noop);
    const status = planReview.querySelector(".plan-row-sender-status");
    expect(status).not.toBeNull();
    expect(status?.tagName).not.toBe("BDI");
    expect(status?.textContent).toBe("malformed sender header — normalized text shown: 2 From header fields");
    expect(status?.querySelector("bdi")?.textContent).toBe("2 From header fields");
    // The synthesized text never rides inside either ADDRESS isolate — both stay empty.
    expect(planReview.querySelector(".plan-row-sender-address-local")?.textContent).toBe("");
    expect(planReview.querySelector(".plan-row-sender-address-domain")?.textContent).toBe("");
  });

  it("an ok sender's row renders no status atom at all", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    expect(planReview.querySelector(".plan-row-sender-status")).toBeNull();
  });

  it("the approve control is labelled with the count and verb, and is disabled while busy, and once approved on a TERMINAL plan", () => {
    for (const [busy, approved, terminal, disabled] of [
      [false, false, false, false],
      [true, false, false, true],
      [false, true, true, true],
    ] as const) {
      const { roots, planReview } = makeRoots();
      let clicks = 0;
      renderPlanReview(roots, { review: { ...REVIEW_FIXTURE, approved, terminal }, busy }, () => { clicks += 1; }, noop, noop);
      const approve = planReview.querySelector(".plan-approve") as HTMLButtonElement;
      expect(approve.textContent).toBe("Approve 2 — trash");
      expect(approve.disabled).toBe(disabled);
      approve.click();
      expect(clicks).toBe(disabled ? 0 : 1);
      expect(planReview.querySelector(".plan-apply")).toBeNull();
    }
  });

  it("the cancel control calls onCancel and nothing else", () => {
    const { roots, planReview } = makeRoots();
    let cancelled = 0;
    let approved = 0;
    let applied = 0;
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, () => { approved += 1; }, () => { cancelled += 1; }, () => { applied += 1; });
    (planReview.querySelector(".plan-cancel") as HTMLButtonElement).click();
    expect([cancelled, approved, applied]).toEqual([1, 0, 0]);
  });

  it("no review: the root is emptied (a closed review leaves nothing behind)", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    renderPlanReview(roots, null, noop, noop, noop);
    expect(planReview.childNodes.length).toBe(0);
  });

  it("the aggregate lane shows the summary and the DERIVED sample only, and echoes those same objects", () => {
    const { roots, planReview } = makeRoots();
    let echoed: RenderedViewWire | null = null;
    renderPlanReview(roots, { review: AGGREGATE_FIXTURE, busy: false }, (rendered) => { echoed = rendered; }, noop, noop);
    expect(texts(planReview, ".plan-sample-caption")).toEqual(["sample of 1 (derived by the engine, in its order)"]);
    expect([...planReview.querySelectorAll(".plan-row")].map((r) => r.getAttribute("data-ref"))).toEqual(["b"]);
    expect(texts(planReview, ".plan-lane")).toEqual(["summary + a spot-check sample — not every member is shown"]);
    (planReview.querySelector(".plan-approve") as HTMLButtonElement).click();
    const echo = echoed as unknown as { mode: string; header: unknown; summary: unknown; sample_k: number; sample_rows: unknown };
    expect(echo.mode).toBe("aggregate");
    expect(echo.header).toBe(AGGREGATE_FIXTURE.presentation.header);
    expect(echo.summary).toBe(AGGREGATE_FIXTURE.presentation.summary);
    expect(echo.sample_k).toBe(1);
    expect(echo.sample_rows).toBe(AGGREGATE_FIXTURE.sample_rows);
  });

  it("an aggregate review with no sample cannot be approved (nothing to echo)", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: { ...AGGREGATE_FIXTURE, sample_rows: null, sample_k: null }, busy: false }, noop, noop, noop);
    expect((planReview.querySelector(".plan-approve") as HTMLButtonElement).disabled).toBe(true);
  });

  it("a plan toast's detail lines render one per line, through textContent, after the message", () => {
    const { roots, toastRegion } = makeRoots();
    renderToast(roots, { message: "m", undoKeys: [], staleReason: null, refusalKind: "plan_refused", detail: ["member a", "membership:INBOX: expected true, observed false"] }, null, noop);
    expect(texts(toastRegion, ".toast-detail")).toEqual(["member a", "membership:INBOX: expected true, observed false"]);
    expect(texts(toastRegion, ".toast-message")).toEqual(["m"]);
  });

  it("a verb or undo toast's restoration line renders through the same textContent sink, after the message", () => {
    const { roots, toastRegion } = makeRoots();
    renderToast(roots, toastForVerb("archive", "k1", { state: "current" }, { verdict: "no_effect_witness" }), null, noop);
    expect(texts(toastRegion, ".toast-message")).toEqual(["archive applied"]);
    expect(texts(toastRegion, ".toast-detail")).toEqual(["restoration UNDETERMINED (no effect witness)"]);
    renderToast(roots, toastForUndo("undone", { state: "current" }, [], { verdict: "within_closure" }), null, noop);
    expect(texts(toastRegion, ".toast-message")).toEqual(["undo: undone"]);
    expect(toastRegion.querySelectorAll(".toast-detail").length).toBe(0);
  });

  // The bypass-lane Retry control is STATE-derived — read
  // off `pendingBypassRetryPlanId` on every paint, never off `toast.retryPlanId` (removed
  // entirely). A FAILED Retry attempt answers with an ORDINARY
  // refusal toast (wholesale-replaced, same as any other refusal) — the control must survive it
  // regardless of which toast object is on screen, because it is not a property of that toast.
  it("the bypass-lane Retry control survives a refused-retry's replacement toast — it is state-derived, never carried on the toast itself", () => {
    const { roots, toastRegion } = makeRoots();
    // The plan's own toast (an ordinary applied-outcome toast) — the control renders.
    renderToast(roots, { message: "plan p-bypass applied", undoKeys: [], staleReason: null, refusalKind: null }, "p-bypass", noop, noop);
    expect(toastRegion.querySelectorAll(".toast-retry-button").length).toBe(1);
    // A Retry click failed: the REPLACEMENT toast is an ordinary refusal, unrelated to the plan —
    // the SAME `pendingBypassRetryPlanId` is passed on this and every later paint (it comes from
    // state, not from this toast), so the control is still there.
    renderToast(roots, { message: "refused", undoKeys: [], staleReason: null, refusalKind: "refused" }, "p-bypass", noop, noop);
    expect(toastRegion.querySelectorAll(".toast-retry-button").length).toBe(1);
    // Once the plan is terminal, the caller stops passing a plan id (state cleared it) — no control.
    renderToast(roots, { message: "refused", undoKeys: [], staleReason: null, refusalKind: "refused" }, null, noop, noop);
    expect(toastRegion.querySelectorAll(".toast-retry-button").length).toBe(0);
  });
});

// A plan that is APPROVED and whose run is not TERMINAL (the run stopped
// before every member was attempted, or it was approved and never applied) offers an enabled
// "Apply" in place of the approve control, which stays write-once. Apply re-runs the plan; it never
// sends a second approval.
describe("an approved, non-terminal plan offers Apply", () => {
  it("approved and not terminal: the control reads Apply, is enabled, and calls onApply only", () => {
    const { roots, planReview } = makeRoots();
    let approves = 0;
    let applies = 0;
    renderPlanReview(roots, { review: { ...REVIEW_FIXTURE, approved: true, terminal: false }, busy: false }, () => { approves += 1; }, noop, () => { applies += 1; });
    const apply = planReview.querySelector(".plan-apply") as HTMLButtonElement | null;
    expect(apply?.textContent).toBe("Apply 2 — trash");
    expect(apply?.disabled).toBe(false);
    apply?.click();
    expect([approves, applies]).toEqual([0, 1]);
    expect(planReview.querySelector(".plan-approve")).toBeNull();
  });

  it("Apply is disabled while a run is in flight", () => {
    const { roots, planReview } = makeRoots();
    let applies = 0;
    renderPlanReview(roots, { review: { ...REVIEW_FIXTURE, approved: true, terminal: false }, busy: true }, noop, noop, () => { applies += 1; });
    const apply = planReview.querySelector(".plan-apply") as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    apply.click();
    expect(applies).toBe(0);
  });
});

// Focus moves INTO the review when it opens, so the keyboard lands on the
// screen that owns it; a re-render of an open review keeps focus inside it.
describe("focus moves into the review when it opens", () => {
  it("opening the review focuses its panel; a re-render with focus inside keeps it inside", () => {
    const { roots, planReview } = makeRoots();
    expect(planReview.contains(document.activeElement)).toBe(false);
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    expect(planReview.contains(document.activeElement)).toBe(true);
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: true }, noop, noop, noop);
    expect(planReview.contains(document.activeElement)).toBe(true);
  });

  it("the approve control is never the default focus (Enter on open must not approve a RED plan)", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: REVIEW_FIXTURE, busy: false }, noop, noop, noop);
    expect(document.activeElement).not.toBe(planReview.querySelector(".plan-approve"));
  });
});

// Eight hostile strings through every sink the plan
// review and its toasts write, on a DOM with a real HTML parser. None may create an element, each
// must round-trip as text exactly, and the only attributes the panel carries are `class`, `type`,
// `data-ref` and the panel's own `tabindex`.
const HOSTILE = [
  '<img src=x onerror="globalThis.__pwned=1">',
  "&" + "lt;script&" + "gt;alert(1)&" + "lt;/script&" + "gt;",
  String.fromCharCode(0x202e) + "moc.lapyap" + String.fromCharCode(0x202c) + " evil",
  "pay" + String.fromCharCode(0x200b) + "pal",
  "javascript:alert(1)",
  '"><svg onload="globalThis.__pwned=2">',
  '</bdi><img src=x onerror="globalThis.__pwned=3">',
  "x".repeat(10 * 1024),
];

function hostileReview(h: string): PlanReviewView {
  return {
    plan_id: h,
    lane: "per_member",
    presentation: {
      header: { account: h, verb: h, tier: h, count: 1, backup_coverage: false, warning: h },
      summary: { count: 1, sender_domains: [[h, 1]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: h, date_max: h, total_size: null },
      rows: [{ message_ref: h, sender: h, sender_address: h, sender_status: "ok", sender_local: h, sender_domain: h, subject: h, date: h, size: null }],
    },
    sample_k: null,
    sample_rows: null,
    expires_at: h,
    approved: false,
    terminal: false,
    bypass_notice: h,
  };
}

describe("Residual 5 — every untrusted string through the textContent sinks, on a real DOM", () => {
  it("the eight hostile strings are eight distinct strings (the probe is not vacuous)", () => {
    expect(new Set(HOSTILE).size).toBe(8);
    expect(HOSTILE[2].charCodeAt(0)).toBe(0x202e);
    expect(HOSTILE[3].charCodeAt(3)).toBe(0x200b);
  });

  it.each(HOSTILE.map((h, i) => [i, h]))("hostile #%i renders as text only, in every plan sink", (_i, h) => {
    const hostile = h as string;
    const { roots, planReview, toastRegion } = makeRoots();
    renderPlanReview(roots, { review: hostileReview(hostile), busy: false }, noop, noop, noop);
    expect(planReview.querySelectorAll("img,svg,script,a,iframe").length).toBe(0);
    expect(planReview.querySelector(".plan-row-sender-name")?.textContent).toBe(hostile);
    expect(planReview.querySelector(".plan-row-sender-name")?.tagName).toBe("BDI");
    expect(planReview.querySelector(".plan-row-sender-address bdi")?.textContent).toBe(hostile);
    expect(planReview.querySelector(".plan-row-sender-address bdi")?.tagName).toBe("BDI");
    expect(planReview.querySelector(".plan-row-subject")?.textContent).toBe(hostile);
    expect(planReview.querySelector(".plan-warning")?.textContent).toBe(hostile);
    expect(planReview.querySelector(".plan-summary-domain bdi")?.textContent).toBe(hostile);
    expect(planReview.querySelector(".plan-row")?.getAttribute("data-ref")).toBe(hostile);
    const attributes = new Set<string>();
    planReview.querySelectorAll("*").forEach((el) => el.getAttributeNames().forEach((a) => attributes.add(a)));
    for (const a of attributes) {
      expect(["class", "type", "data-ref", "tabindex"], a).toContain(a);
    }
    // The toast sinks: the bypass notice, the refusal copy + member + diff atom, the restoration line.
    renderToast(roots, reduce(initialState(), { type: "plan_minted", review: { ...hostileReview(hostile), lane: "bypassed" } }).toast, null, noop);
    expect(toastRegion.querySelectorAll("img,svg,script,a,iframe").length).toBe(0);
    expect(texts(toastRegion, ".toast-detail")).toEqual([hostile]);
    renderToast(roots, toastForPlanRefusal({ kind: "plan_refused", reason: hostile, member_ref: hostile, diff: [{ atom: hostile, expected: true, observed: null }] }), null, noop);
    expect(toastRegion.querySelectorAll("img,svg,script,a,iframe").length).toBe(0);
    expect(toastRegion.querySelector(".toast-message")?.textContent).toBe(hostile);
    expect(texts(toastRegion, ".toast-detail")).toEqual([`member ${hostile}`, `${hostile}: expected true, observed not captured`]);
    const outside: RestorationView = { verdict: "outside_closure", system_labels: [hostile], user_label_count: 2 };
    renderToast(roots, toastForVerb("trash", "k", { state: "current" }, outside), null, noop);
    expect(toastRegion.querySelectorAll("img,svg,script,a,iframe").length).toBe(0);
    expect(texts(toastRegion, ".toast-detail")).toEqual([`restoration UNDETERMINED (labels outside the declared closure changed: ${hostile}, 2 user labels)`]);
    expect((globalThis as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

// ===============================================================================================
// THE APPROVAL FIELDS ARE LOSSLESS.
// A 623-byte sender display and a 480-byte subject ending in `KEEP LEGAL HOLD` were fed through
// the real transport parser, the read coordinator, the mint and the approval store, then rendered
// the emitted presentation with the production `render.ts` + `styles.css` in Chromium at 1280x900:
// the sender cell showed 278 of 3,876 px and the subject cell 417 of 2,980 px (hidden overflow,
// nowrap, ellipsis) while Approve echoed — and the engine committed — the whole value. The design
// asks for an "inspectable exact member list", and an approval stands on the rendered information.
//
// Two witnesses. (1) THE STYLESHEET WITNESS: no rule of `styles.css` that reaches an element the
// review renders carries a truncating property, and every text the review renders is reached by a
// wrap rule. "Reaches" is decided twice and the two are unioned: by the real selector engine
// (`Element.matches` on the rendered review, dynamic pseudo-classes and pseudo-elements stripped, so
// a `:hover` rule counts), and by the selectors `render.ts` ASSIGNS — classes and tags read from its
// plan-review section, never a hand list — against each selector's last compound. The derived set is
// checked EQUAL to what the review renders, so a narrowed list fails. (2) THE LONG-VALUE CONSTRUCTION on
// a real DOM with the production stylesheet loaded: the whole 623 / 480 bytes are the cells' text,
// no computed truncation reaches either cell, and Approve echoes the same bytes. The engine half of
// the construction (the transport parser → the read coordinator → the mint → the approval) is
// `crates/aruna-gmail/src/transport.rs`.
//
// NOT CLAIMED: a LAYOUT witness. jsdom lays nothing out and the repo has no headless browser, so no
// test here measures a pixel; the stylesheet witness covers the properties that truncate.
// ===============================================================================================

const SRC_DIR = path.resolve(__dirname, "..");
const readSource = (...segments: string[]) =>
  fs.readFileSync(path.resolve(SRC_DIR, ...segments), "utf8").split(String.fromCharCode(13)).join("");

/// The plan-review section of `render.ts`, banner to banner.
function planReviewSection(): string {
  const source = readSource("render.ts");
  const start = source.indexOf("// #75 S1 — the plan review");
  const end = source.indexOf("// The one entry point main.ts calls");
  if (start < 0 || end <= start) {
    throw new Error("render.ts: the plan-review section's banners moved — re-anchor this witness");
  }
  return source.slice(start, end);
}

const stringLiteral = (text: string): string | null => /^"([^"]*)"$/.exec(text.trim())?.[1] ?? null;

/// The classes and tags the plan-review section ASSIGNS, read from its source. A shape this reader
/// cannot resolve — a class assigned from an expression, a `textElement` call whose tag or class is
/// not a literal, a `createElement` of anything but a literal or `textElement`'s own parameter —
/// fails the witness; it is never skipped.
function derivedSelectors(): { classes: Set<string>; tags: Set<string> } {
  const section = planReviewSection();
  const classes = new Set<string>();
  const tags = new Set<string>();
  const addClasses = (value: string) => value.split(" ").filter(Boolean).forEach((c) => classes.add(c));
  for (const m of section.matchAll(/\.className\s*=\s*([^;]+);/g)) {
    const literal = stringLiteral(m[1]);
    if (literal !== null) {
      addClasses(literal);
    } else if (m[1].trim() !== "className") {
      // `className` is `textElement`'s own parameter: every CALL of it is read below.
      throw new Error(`render.ts assigns a class this witness cannot read: ${m[0]}`);
    }
  }
  for (const m of section.matchAll(/classList\.add\(([^)]*)\)/g)) {
    for (const arg of m[1].split(",")) {
      const literal = stringLiteral(arg);
      if (literal === null) {
        throw new Error(`render.ts adds a class this witness cannot read: ${m[0]}`);
      }
      addClasses(literal);
    }
  }
  for (const m of section.matchAll(/textElement\(\s*([^,]+),\s*([^,]+),/g)) {
    if (section.slice(Math.max(0, (m.index ?? 0) - 9), m.index).endsWith("function ")) {
      continue; // the definition, not a call
    }
    const tag = stringLiteral(m[1]);
    const cls = stringLiteral(m[2]);
    if (tag === null || cls === null) {
      throw new Error(`render.ts calls textElement with a tag or class this witness cannot read: ${m[0]}`);
    }
    tags.add(tag);
    addClasses(cls);
  }
  for (const m of section.matchAll(/createElement\(([^)]*)\)/g)) {
    const literal = stringLiteral(m[1]);
    if (literal !== null) {
      tags.add(literal);
    } else if (m[1].trim() !== "tag") {
      throw new Error(`render.ts creates an element this witness cannot read: ${m[0]}`);
    }
  }
  return { classes, tags };
}

/// The review root's class, as `index.html` gives it (the review renders INTO that root).
function reviewRootClass(): string {
  const html = new DOMParser().parseFromString(readSource("..", "index.html"), "text/html");
  const root = html.getElementById("plan-review");
  if (root === null) {
    throw new Error("index.html has no #plan-review root");
  }
  return root.className;
}

/// Every state the review renders in: the full list with its warning and domains (Approve), the
/// same approved and not terminal (Apply), the aggregate lane with its sample, and without one.
const UNPARSED_SUMMARY = { ...REVIEW_FIXTURE.presentation.summary, sender_domain_unavailable: 1, sender_header_malformed: 1, sender_header_unsupported: 1 };
const REVIEW_STATES: PlanReviewView[] = [
  REVIEW_FIXTURE,
  { ...REVIEW_FIXTURE, approved: true, terminal: false },
  AGGREGATE_FIXTURE,
  { ...AGGREGATE_FIXTURE, sample_k: null, sample_rows: null },
  // The two lines a summary with unparsed senders renders.
  { ...REVIEW_FIXTURE, presentation: { ...REVIEW_FIXTURE.presentation, summary: UNPARSED_SUMMARY } },
  // A non-"ok" row renders its OWN status atom.
  {
    ...REVIEW_FIXTURE,
    presentation: {
      ...REVIEW_FIXTURE.presentation,
      rows: [{ ...REVIEW_FIXTURE.presentation.rows[0], sender_status: "unsupported" }, REVIEW_FIXTURE.presentation.rows[1]],
    },
  },
];

/// Render every review state into a root that carries `index.html`'s class; answers every element
/// the review rendered (the roots included) and the tags and classes of the review's own elements.
function renderEveryState(): { elements: Element[]; classes: Set<string>; tags: Set<string> } {
  const rootClass = reviewRootClass();
  const elements: Element[] = [];
  const classes = new Set<string>();
  const tags = new Set<string>();
  for (const review of REVIEW_STATES) {
    const { roots, planReview } = makeRoots();
    planReview.className = rootClass;
    renderPlanReview(roots, { review, busy: false }, noop, noop, noop);
    elements.push(planReview);
    planReview.querySelectorAll("*").forEach((el) => {
      elements.push(el);
      tags.add(el.tagName.toLowerCase());
      el.classList.forEach((c) => classes.add(c));
    });
  }
  return { elements, classes, tags };
}

interface StyleRuleText {
  selectors: string[];
  declarations: [string, string][];
}

/// Every style rule of `styles.css`, parsed by the DOM's own CSS parser; grouping rules (`@media`,
/// `@supports`) are walked; any other rule kind but `@font-face` / `@keyframes` fails the witness
/// (an `@import` would bring rules this witness never read).
function stylesheetRules(): StyleRuleText[] {
  const style = document.createElement("style");
  style.textContent = readSource("styles.css");
  document.head.appendChild(style);
  try {
    const out: StyleRuleText[] = [];
    const walk = (rules: CSSRuleList) => {
      for (const rule of Array.from(rules)) {
        if (rule.type === 1) {
          const styleRule = rule as CSSStyleRule;
          const declarations: [string, string][] = [];
          for (let i = 0; i < styleRule.style.length; i += 1) {
            const property = styleRule.style[i];
            declarations.push([property, styleRule.style.getPropertyValue(property)]);
          }
          out.push({ selectors: styleRule.selectorText.split(",").map((s) => s.trim()), declarations });
        } else if (rule.type === 4 || rule.type === 12) {
          walk((rule as CSSGroupingRule).cssRules);
        } else if (rule.type !== 5 && rule.type !== 7) {
          throw new Error(`styles.css holds a rule this witness cannot read: ${rule.cssText}`);
        }
      }
    };
    walk((style.sheet as CSSStyleSheet).cssRules);
    return out;
  } finally {
    style.remove();
  }
}

const DYNAMIC_PSEUDO = /::?(?:hover|focus-visible|focus-within|focus|active|visited|link|target|before|after|first-line|first-letter|placeholder|selection|marker)\b/g;

function reachesByEngine(selector: string, el: Element): boolean {
  const stripped = selector.replace(DYNAMIC_PSEUDO, "").trim();
  try {
    return el.matches(stripped === "" ? "*" : stripped);
  } catch {
    return true; // a selector the engine cannot read is counted as reaching
  }
}

function reachesByDerivedSet(selector: string, classes: Set<string>, tags: Set<string>): boolean {
  const compounds = selector.replace(DYNAMIC_PSEUDO, "").trim().split(/\s*[>+~]\s*|\s+/).filter(Boolean);
  const last = compounds[compounds.length - 1] ?? "*";
  const type = /^([a-zA-Z][\w-]*|\*)/.exec(last)?.[1];
  const wanted = [...last.matchAll(/\.([\w-]+)/g)].map((m) => m[1]);
  return (type === undefined || type === "*" || tags.has(type.toLowerCase())) && wanted.every((c) => classes.has(c));
}

/// The truncating family: a clipped overflow, an ellipsis (or any non-`clip` overflow marker), a
/// no-wrap white-space or text-wrap, a line clamp.
function truncates(property: string, value: string): boolean {
  const v = value.trim().toLowerCase();
  const tokens = v.split(/\s+/);
  switch (property) {
    case "text-overflow":
      return v !== "clip";
    case "overflow":
    case "overflow-x":
    case "overflow-y":
    case "overflow-inline":
    case "overflow-block":
      return tokens.includes("hidden") || tokens.includes("clip");
    case "white-space":
      return v === "nowrap" || v === "pre";
    case "text-wrap":
    case "text-wrap-mode":
      return tokens.includes("nowrap");
    case "line-clamp":
    case "-webkit-line-clamp":
      return v !== "none";
    default:
      return false;
  }
}

const WRAPPING_WHITE_SPACE = ["pre-wrap", "break-spaces", "normal", "pre-line"];

describe("the approval fields are rendered losslessly", () => {
  it("the stylesheet witness's selector set is DERIVED from render.ts and equals what the review renders", () => {
    const derived = derivedSelectors();
    const rendered = renderEveryState();
    expect([...derived.classes].sort()).toEqual([...rendered.classes].sort());
    expect([...derived.tags].sort()).toEqual([...rendered.tags].sort());
    // Not vacuous: the cells named here are in it (the sender cell
    // split into its own name and address classes).
    for (const cls of ["plan-row-sender-name", "plan-row-sender-address", "plan-row-subject", "plan-warning", "plan-summary-domain"]) {
      expect(derived.classes, cls).toContain(cls);
    }
    expect(derived.tags).toContain("bdi");
  });

  it("no rule of styles.css that reaches an element the review renders carries a truncating property", () => {
    const { classes, tags } = derivedSelectors();
    const rendered = renderEveryState();
    classes.add(reviewRootClass());
    const rules = stylesheetRules();
    const violations: string[] = [];
    let reaching = 0;
    for (const rule of rules) {
      for (const selector of rule.selectors) {
        const reaches = reachesByDerivedSet(selector, classes, tags) || rendered.elements.some((el) => reachesByEngine(selector, el));
        if (!reaches) {
          continue;
        }
        reaching += 1;
        for (const [property, value] of rule.declarations) {
          if (truncates(property, value)) {
            violations.push(`${selector} { ${property}: ${value} }`);
          }
        }
      }
    }
    expect(reaching).toBeGreaterThan(0);
    expect(violations).toEqual([]);
  });

  it("every text the review renders is reached by a wrap rule (break anywhere, white-space that wraps)", () => {
    const rendered = renderEveryState();
    const rules = stylesheetRules();
    const unwrapped: string[] = [];
    for (const el of rendered.elements) {
      const ownText = Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent ?? "").trim() !== "");
      if (!ownText) {
        continue;
      }
      const declared = rules
        .filter((rule) => rule.selectors.some((selector) => reachesByEngine(selector, el)))
        .flatMap((rule) => rule.declarations);
      const breaks = declared.some(([p, v]) => (p === "overflow-wrap" && v.trim() === "anywhere") || (p === "word-break" && v.trim() === "break-all"));
      const wraps = declared.some(([p, v]) => p === "white-space" && WRAPPING_WHITE_SPACE.includes(v.trim()));
      if (!breaks || !wraps) {
        unwrapped.push(`${el.tagName.toLowerCase()}.${Array.from(el.classList).join(".")}`);
      }
    }
    expect(unwrapped).toEqual([]);
  });

  // The long-value construction. ASCII, so bytes = UTF-16 units; the byte counts are asserted anyway.
  const HOLD = " KEEP LEGAL HOLD";
  const filled = (phrase: string, n: number): string => {
    let s = "";
    while (s.length < n) {
      s += phrase;
    }
    s = s.slice(0, n);
    return s.endsWith(" ") ? `${s.slice(0, -1)}.` : s;
  };
  const CLIP_ADDR = "records-custodian@legal-hold.example";
  // The name half and the address half are frozen (and rendered)
  // SEPARATELY now — CLIP_SENDER stays the combined reference string for the byte-count checks.
  const CLIP_NAME = filled("Compliance Archive Notification Service ", 623 - CLIP_ADDR.length - 3);
  const CLIP_SENDER_ADDRESS = `<${CLIP_ADDR}>`;
  const CLIP_SENDER = `${CLIP_NAME} ${CLIP_SENDER_ADDRESS}`;
  const CLIP_SUBJECT = `${filled("Re: quarterly retention schedule review ", 480 - HOLD.length)}${HOLD}`;
  const CLIP_ROW: PlanRowView = { message_ref: "clip", sender: CLIP_NAME, sender_address: CLIP_SENDER_ADDRESS, sender_status: "ok", sender_local: "records-custodian", sender_domain: "legal-hold.example", subject: CLIP_SUBJECT, date: "2026-09-24T00:00:00Z", size: 4096 };
  const utf8Bytes = (s: string) => new TextEncoder().encode(s).length;

  function withProductionStylesheet(body: () => void): void {
    const style = document.createElement("style");
    style.textContent = readSource("styles.css");
    document.head.appendChild(style);
    try {
      body();
    } finally {
      style.remove();
    }
  }

  function expectLossless(cell: Element | null, expected: string): void {
    expect(cell?.textContent).toBe(expected);
    const computed = getComputedStyle(cell as Element);
    expect(computed.getPropertyValue("text-overflow"), "text-overflow").not.toBe("ellipsis");
    expect(["hidden", "clip"], "overflow").not.toContain(computed.getPropertyValue("overflow"));
    expect(["nowrap", "pre"], "white-space").not.toContain(computed.getPropertyValue("white-space"));
    expect(computed.getPropertyValue("overflow-wrap"), "overflow-wrap").toBe("anywhere");
  }

  it("the 623-byte sender and 480-byte subject (ending KEEP LEGAL HOLD) are the cells' whole text, untruncated, and Approve echoes the same bytes — full list", () => {
    expect(utf8Bytes(CLIP_SENDER)).toBe(623);
    expect(utf8Bytes(CLIP_SUBJECT)).toBe(480);
    expect(CLIP_SUBJECT.endsWith("KEEP LEGAL HOLD")).toBe(true);
    const review: PlanReviewView = {
      ...REVIEW_FIXTURE,
      presentation: { ...REVIEW_FIXTURE.presentation, rows: [CLIP_ROW, REVIEW_FIXTURE.presentation.rows[0]] },
    };
    withProductionStylesheet(() => {
      const { roots, planReview } = makeRoots();
      planReview.className = reviewRootClass();
      let echoed: RenderedViewWire | null = null;
      renderPlanReview(roots, { review, busy: false }, (rendered) => { echoed = rendered; }, noop, noop);
      const row = planReview.querySelector('.plan-row[data-ref="clip"]');
      expectLossless(row?.querySelector(".plan-row-sender-name") ?? null, CLIP_NAME);
      // The address now splits across TWO <bdi> isolates (local,
      // domain) at the last `@` — the PARENT span's textContent still concatenates back to the
      // whole address, which is what "lossless" means here.
      expectLossless(row?.querySelector(".plan-row-sender-address") ?? null, CLIP_SENDER_ADDRESS);
      expectLossless(row?.querySelector(".plan-row-subject") ?? null, CLIP_SUBJECT);
      (planReview.querySelector(".plan-approve") as HTMLButtonElement).click();
      const echo = echoed as unknown as { mode: string; presentation: PlanReviewView["presentation"] };
      expect(echo.mode).toBe("full_list");
      expect(echo.presentation).toBe(review.presentation);
      expect(echo.presentation.rows[0].sender).toBe(CLIP_NAME);
      expect(echo.presentation.rows[0].sender_address).toBe(CLIP_SENDER_ADDRESS);
      expect(echo.presentation.rows[0].subject).toBe(CLIP_SUBJECT);
    });
  });

  it("the same construction on the aggregate lane's sample row — untruncated, and echoed byte for byte", () => {
    const review: PlanReviewView = { ...AGGREGATE_FIXTURE, sample_k: 1, sample_rows: [CLIP_ROW] };
    withProductionStylesheet(() => {
      const { roots, planReview } = makeRoots();
      planReview.className = reviewRootClass();
      let echoed: RenderedViewWire | null = null;
      renderPlanReview(roots, { review, busy: false }, (rendered) => { echoed = rendered; }, noop, noop);
      expectLossless(planReview.querySelector(".plan-row-sender-name"), CLIP_NAME);
      // See the note above — check the PARENT span, not one isolate.
      expectLossless(planReview.querySelector(".plan-row-sender-address"), CLIP_SENDER_ADDRESS);
      expectLossless(planReview.querySelector(".plan-row-subject"), CLIP_SUBJECT);
      (planReview.querySelector(".plan-approve") as HTMLButtonElement).click();
      const echo = echoed as unknown as { mode: string; sample_rows: PlanRowView[] };
      expect(echo.mode).toBe("aggregate");
      expect(echo.sample_rows).toBe(review.sample_rows);
      expect(echo.sample_rows[0].sender).toBe(CLIP_NAME);
      expect(echo.sample_rows[0].sender_address).toBe(CLIP_SENDER_ADDRESS);
      expect(echo.sample_rows[0].subject).toBe(CLIP_SUBJECT);
    });
  });
});
