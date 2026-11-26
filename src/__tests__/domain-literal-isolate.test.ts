// @vitest-environment jsdom
//
// Witness: for `a@[x@trusted.example]` the local isolate text is exactly `a` and the domain
// isolate exactly `[x@trusted.example]` (a delimiter search over the composed address would read
// local `a@[x@` / domain `trusted.example]`).
//
// This test goes through the exported plan-row builder `renderPlanReview` exactly the way
// `src/__tests__/plan-review-dom.test.ts` does (same fixture shape, same
// `.plan-row-sender-address-local` / `-domain` selectors), since the address split itself is not
// exported.
import { afterEach, describe, expect, it } from "vitest";
import type { PlanReviewView } from "../ipc";
import type { RenderRoots } from "../render";
import { renderPlanReview } from "../render";

const noop = () => {};

function makeRoots(): { roots: RenderRoots; planReview: HTMLElement } {
  const planReview = document.createElement("section");
  const toastRegion = document.createElement("div");
  document.body.appendChild(planReview);
  document.body.appendChild(toastRegion);
  return { roots: { planReview, toastRegion } as unknown as RenderRoots, planReview };
}

afterEach(() => {
  while (document.body.firstChild) {
    document.body.removeChild(document.body.firstChild);
  }
});

// The address's domain is itself a domain LITERAL carrying its own `@` —
// `a@[x@trusted.example]`. A `lastIndexOf("@")` split would find the literal's INNER `@`, not the
// boundary between the local-part and the domain. So there is no split at all:
// `sender_local`/`sender_domain` are the engine's own RFC 5322 grammar tokens, placed directly
// into their isolates.
function reviewWithParsedSender(local: string, domain: string, address: string): PlanReviewView {
  return {
    plan_id: "p1",
    lane: "per_member",
    presentation: {
      header: { account: "gmail:me", verb: "trash", tier: "red", count: 1, backup_coverage: false, warning: null },
      summary: { count: 1, sender_domains: [["x", 1]], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "2026-09-01T00:00:00Z", date_max: "2026-09-01T00:00:00Z", total_size: null },
      rows: [
        {
          message_ref: "a",
          sender: "A",
          sender_address: address,
          sender_status: "ok",
          sender_local: local,
          sender_domain: domain,
          subject: "s",
          date: "2026-09-01T00:00:00Z",
          size: null,
        },
      ],
    },
    sample_k: null,
    sample_rows: null,
    expires_at: "2026-09-25T00:00:00Z",
    approved: false,
    terminal: false,
    bypass_notice: null,
  };
}

describe("the domain isolate holds the parser's domain for a domain literal with an @", () => {
  it("keeps a bracketed domain literal whole even when the literal itself carries an @", () => {
    const { roots, planReview } = makeRoots();
    renderPlanReview(roots, { review: reviewWithParsedSender("a", "[x@trusted.example]", "a@[x@trusted.example]"), busy: false }, noop, noop, noop);
    const local = planReview.querySelector(".plan-row-sender-address-local")?.textContent;
    const domain = planReview.querySelector(".plan-row-sender-address-domain")?.textContent;
    // A split over the composed text would give local "a@[x@", domain "trusted.example]" — the
    // literal's OWN inner `@` would win. The engine's own tokens go straight into their isolates,
    // never re-split.
    expect(local).toBe("a");
    expect(domain).toBe("[x@trusted.example]");
  });
});
