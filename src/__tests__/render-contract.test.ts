// Source-scan contracts for render.ts (bidi isolation, address-beside-
// name as separate sinks, no linkification). Reads source as TEXT — see sinkfence.test.ts's
// module doc for why (`node` env, no `document`). The plan-review screen is EXECUTED on a
// real DOM in `plan-review-dom.test.ts` (jsdom — the in-file DOM
// double that used to live here is gone), and main.ts's wiring in `main-wiring.test.ts`.
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

const SRC_DIR = path.resolve(__dirname, "..");
const RENDER_TS = fs.readFileSync(path.join(SRC_DIR, "render.ts"), "utf8");
const MAIN_TS = fs.readFileSync(path.join(SRC_DIR, "main.ts"), "utf8");

/// Excludes `__tests__`: this suite's own fixtures/regex literals legitimately contain the
/// forbidden substrings as DATA (e.g. the string `"<a "` a few lines below, used to assert its
/// absence elsewhere) — scanning the test files themselves would be witnessing the test, not the
/// product. `sinkfence.test.ts` draws the same line for the same reason.
function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__") {
        continue;
      }
      out.push(...listTsFiles(full));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".ts")) {
      out.push(full);
    }
  }
  return out;
}

describe("<bdi> bidi isolate", () => {
  it("render.ts creates a <bdi> element around the untrusted display name", () => {
    expect(RENDER_TS).toContain("<bdi");
    expect(RENDER_TS).toContain('document.createElement("bdi")');
  });

  // From_addr is preserved byte-for-byte on ingest (identity), so it needs the SAME
  // display-side bidi isolation the name already gets — a hostile RTL-override BYTE sequence in
  // the address can otherwise visually swallow/reorder what follows it. Two SEPARATE
  // `document.createElement("bdi")` call sites, each immediately followed (within its own small
  // window) by a `.textContent = row.from_*` assignment — one for the name, one for the addr.
  it("render.ts wraps BOTH from_name and from_addr in their own <bdi> element", () => {
    const bdiCreations = RENDER_TS.match(/document\.createElement\("bdi"\)/g) ?? [];
    expect(bdiCreations.length).toBeGreaterThanOrEqual(2);

    expect(RENDER_TS).toMatch(/document\.createElement\("bdi"\)[\s\S]{0,200}?\.textContent\s*=\s*row\.from_name/);
    expect(RENDER_TS).toMatch(/document\.createElement\("bdi"\)[\s\S]{0,200}?\.textContent\s*=\s*row\.from_addr/);
  });
});

describe("from_name and from_addr render via SEPARATE textContent assignments", () => {
  it("two distinct .textContent = row.from_* statements exist, on different elements", () => {
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*row\.from_name/);
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*row\.from_addr/);

    // Not the SAME assignment target and not concatenated into one string first.
    expect(RENDER_TS).not.toMatch(/row\.from_name\s*\+\s*row\.from_addr/);
    expect(RENDER_TS).not.toMatch(/row\.from_addr\s*\+\s*row\.from_name/);
    expect(RENDER_TS).not.toMatch(/`.*\$\{row\.from_name\}.*\$\{row\.from_addr\}.*`/);
  });
});

// Superseded
// (STRUCTURED-SENDER / NO-REPARSE): the plan row's sender name and address, isolated —
// and the ADDRESS half is itself split into TWO isolates (local part, domain), so a bidi-hostile
// local part cannot reorder text into the domain's own isolate (a probe: a
// quoted-string local part carrying RTL override characters rendered with the visual tail reading
// the wrong host). A delimiter search was replaced (`splitAddressAtLastAt`, wrong for
// a domain-literal carrying its own `@`) by the engine's own grammar tokens
// (`row.sender_local` / `row.sender_domain`) placed directly into their isolates — this module
// derives NOTHING address-shaped any more. Source-scanned for the same reason
// `render-contract.test.ts`'s module doc gives: no live `document` in this vitest env.
describe("<bdi> bidi isolate — the plan row's sender NAME, ADDRESS-LOCAL and ADDRESS-DOMAIN", () => {
  it("render.ts wraps row.sender in its own <bdi>, and places row.sender_local / row.sender_domain in TWO more <bdi> isolates — never re-deriving the split itself", () => {
    const bdiCreations = RENDER_TS.match(/document\.createElement\("bdi"\)/g) ?? [];
    expect(bdiCreations.length).toBeGreaterThanOrEqual(5); // inbox row's 2 + plan row's 3 (name, address-local, address-domain)

    expect(RENDER_TS).toMatch(/document\.createElement\("bdi"\)[\s\S]{0,200}?\.textContent\s*=\s*row\.sender;/);
    // The engine's own tokens go straight into their isolates — never
    // a delimiter search over the composed `sender_address` (that OLD, `splitAddressAtLastAt`
    // shape is GONE, along with the function itself: it split a domain-literal's own `@` in two).
    expect(RENDER_TS).toMatch(/localIsolate\.textContent\s*=\s*row\.sender_local;/);
    expect(RENDER_TS).toMatch(/domainIsolate\.textContent\s*=\s*row\.sender_domain;/);
    expect(RENDER_TS).not.toMatch(/splitAddressAtLastAt/);
    // Neither ADDRESS isolate is ever assigned `row.sender_address` directly (that would be the
    // OLD, un-split, class I RED shape) — a DIFFERENT isolate (the status atom's raw text, class
    // S) is allowed to hold it verbatim, so the check is scoped to `localIsolate`/`domainIsolate`.
    expect(RENDER_TS).not.toMatch(/localIsolate\.textContent\s*=\s*row\.sender_address;/);
    expect(RENDER_TS).not.toMatch(/domainIsolate\.textContent\s*=\s*row\.sender_address;/);
  });

  it("row.sender and the structured row.sender_local / row.sender_domain render via SEPARATE textContent assignments, never composed into one string first", () => {
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*row\.sender;/);
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*row\.sender_local;/);
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*row\.sender_domain;/);
    expect(RENDER_TS).not.toMatch(/row\.sender\s*\+\s*row\.sender_address/);
    expect(RENDER_TS).not.toMatch(/row\.sender_address\s*\+\s*row\.sender/);
    expect(RENDER_TS).not.toMatch(/`.*\$\{row\.sender\}.*\$\{row\.sender_address\}.*`/);
    // The `<`/`@`/`>` decoration is plain text nodes, never string
    // concatenation with either structured field.
    expect(RENDER_TS).not.toMatch(/row\.sender_local\s*\+/);
    expect(RENDER_TS).not.toMatch(/row\.sender_domain\s*\+/);
  });

  // The EXECUTABLE proof of the split rule itself (real DOM, real function call, not a regex
  // scan) lives in `plan-review-dom.test.ts` (jsdom) beside this file's source-shape checks.

  // A non-"ok" sender's status renders OUTSIDE both
  // address isolates, as its own atom — never synthesized text (e.g. "2 From header fields")
  // sitting INSIDE an isolate, indistinguishable from a real address.
  it("a non-ok row.sender_status renders as its own atom, never inside an address <bdi>", () => {
    expect(RENDER_TS).toMatch(/row\.sender_status\s*!==\s*"ok"/);
    expect(RENDER_TS).toMatch(/plan-row-sender-status/);
    // The status text is appended to `identity` (the row's own container), never assigned as the
    // textContent of either address isolate.
    expect(RENDER_TS).not.toMatch(/domainIsolate\.textContent[\s\S]{0,80}row\.sender_status/);
    expect(RENDER_TS).not.toMatch(/localIsolate\.textContent[\s\S]{0,80}row\.sender_status/);
  });
});

describe("the virtualizer lifecycle is actually driven", () => {
  // `@tanstack/virtual-core`'s Virtualizer does nothing on construction/`setOptions` alone:
  // `_willUpdate()` is what attaches the scroll element and its rect/offset observers, and
  // `_didMount()` is what returns the unmount cleanup — see
  // `node_modules/@tanstack/virtual-core/dist/esm/index.d.ts` and `src/index.ts`'s
  // `_willUpdate`/`cleanup`/`_didMount` bodies. A construction that never calls either is
  // permanently inert: `getVirtualItems()` always returns nothing because `scrollElement` never
  // gets set and no scroll/resize observer is ever attached.
  it("createVirtualizer's construction passes an onChange handler", () => {
    expect(RENDER_TS).toMatch(/new Virtualizer<[^>]*>\(\{[\s\S]*?onChange[\s\S]*?\}\)/);
  });

  it("render.ts calls _didMount() (once, at mount time)", () => {
    expect(RENDER_TS).toMatch(/\._didMount\(\)/);
  });

  it("render.ts calls _willUpdate() before every paint that reads getVirtualItems()", () => {
    expect(RENDER_TS).toMatch(/\._willUpdate\(\)/);
  });
});

describe("the no-body reading-pane arm still renders the attachment line", () => {
  it("the pane.noBodyLine block checks pane.attachmentLine before its early return", () => {
    // `NoTextualBody` now carries attachment presence (attachment-only mail) — a bare early
    // `return` right after the no-body paragraph dropped that line on the one arm that most
    // needed it. Captures the `if (pane.noBodyLine) {... }` block body (up to its OWN 2-space-
    // indented closing brace, distinguishing it from the nested `if (pane.attachmentLine)`'s
    // 4-space-indented one) and asserts the attachment check lives inside it.
    const match = RENDER_TS.match(/if \(pane\.noBodyLine\) \{([\s\S]*?)\r?\n {2}\}\r?\n/);
    expect(match).not.toBeNull();
    expect(match?.[1]).toContain("pane.attachmentLine");
  });
});

describe("the status bar surfaces a fenced-mutations notice", () => {
  it("renderStatusBar branches on status.mutations_live and renders status.mutations_reason", () => {
    expect(RENDER_TS).toMatch(/status\.mutations_live/);
    expect(RENDER_TS).toMatch(/status\.mutations_reason/);
  });
});

describe("the status bar surfaces a credential-expired notice, distinct from the mutations-fenced notice", () => {
  it("renderStatusBar branches on status.credential_expired", () => {
    expect(RENDER_TS).toMatch(/status\.credential_expired/);
  });

  it("the expired notice uses its OWN class name, never folded into the mutations-fenced one", () => {
    expect(RENDER_TS).toContain("status-credential-expired");
    expect(RENDER_TS).toContain("status-mutations-fenced");
    expect(RENDER_TS).not.toMatch(/status-credential-expired[^"']*status-mutations-fenced/);
  });
});

// ===================================================================================================
// The credential-expired notice branches on `credential_cure` through the SAME
// single-sourced `CURE_COPY` map `state.ts` exports (W39a/W39b: a transient/paced cure must never
// paint the re-mint demand). Source-scanned like every other contract in this file (this suite's
// module doc: the vitest environment is `node`, no live `document`, so `render.ts` is read as text
// rather than executed — see `sinkfence.test.ts`'s module doc for the same reasoning).
// ===================================================================================================
describe("the credential-expired notice branches on credential_cure via CURE_COPY, never a hard-coded re-mint string", () => {
  it("renderStatusBar reads status.credential_cure", () => {
    expect(RENDER_TS).toMatch(/status\.credential_cure/);
  });

  // The lookup itself moved into `state.ts`'s `cureCopyFor` — a status carries the
  // STAGE (`configured`) as well as the cure, and the map is chosen from it — so what is pinned
  // here is that render.ts still holds no copy and no branch of its own, only the delegation.
  it("the notice text is sourced from state.ts's single-sourced selector, not a literal re-mint sentence", () => {
    expect(RENDER_TS).toMatch(/cureCopyFor\(status\)/);
    expect(RENDER_TS).not.toMatch(/CURE_COPY\[/);
    // The old defect hard-coded this exact sentence regardless of cure — asserting its
    // absence is the witness that the fix actually replaced the unconditional prompt rather
    // than adding a branch alongside it.
    expect(RENDER_TS).not.toContain("the Gmail credential has expired — re-mint it (see the runbook)");
  });

  // The FALLBACK moved with the lookup: it is asserted on behaviour, not on text,
  // in `state.test.ts` ("cureCopyFor — …"), where a null and an unmapped discriminant can be fed
  // in directly. What render.ts still owes is the NAMING of the null case as a contract
  // violation, because that judgement is about this notice.
  it("names the null-cure-while-expired combination as a contract violation in a comment, and delegates the fallback", () => {
    expect(RENDER_TS).toMatch(/contract violation/i);
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*cureCopyFor\(status\)/);
  });

  // Second site (the toast was fixed first; this is
  // the SAME class at the status bar — closed together, not left for later):
  // the `?? "undetermined"` hedges the NULL case only. A NON-null discriminant the map has no row
  // for (the wire union is closed today; a future variant added on the Rust side before the map
  // learns it is the reachable shape) would index to `undefined` and render the literal word
  // "undefined" in the status bar. BOTH hedges are inside `cureCopyFor` — one
  // copy for the status bar and the toast — and both are witnessed on BEHAVIOUR in state.test.ts
  // ("cureCopyFor — the status bar's copy, chosen by stage"). All this file can honestly say is
  // that render.ts does not re-implement them.
  it("the status bar does not carry its own fallback — the hedges live with the lookup", () => {
    expect(RENDER_TS).not.toMatch(/\?\?\s*CURE_COPY\./);
    expect(RENDER_TS).not.toMatch(/credential_cure\s*\?\?\s*"undetermined"/);
  });
});

describe("reason/cure text reaches the credential-expired notice via textContent, never HTML injection", () => {
  it("the credential-cure notice is assigned via .textContent, never built as an HTML string", () => {
    // Anchors on the credential-expired block specifically: a `.textContent =` assignment whose
    // right-hand side is the CURE_COPY lookup, immediately followed (within the block) by
    // appendChild — never a `.innerHTML =` or template-built markup string. sinkfence.test.ts
    // already proves render.ts contains NO innerHTML/outerHTML/insertAdjacentHTML/document.write
    // anywhere (a repo-wide fence); this test additionally pins that THIS specific notice's text
    // is a direct assignment off CURE_COPY, not a concatenation that could smuggle markup through
    // template interpolation into a sink this suite cannot see (no live DOM in this vitest env —
    // see the module doc above).
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*cureCopyFor\(status\)/);
    // The repo-wide "no forbidden sink anywhere" guarantee (innerHTML/outerHTML/
    // insertAdjacentHTML/document.write, comments stripped) is sinkfence.test.ts's job — asserted
    // there, not re-asserted here with a naive substring match (render.ts's own module doc
    // legitimately NAMES "innerHTML" in prose to document the prohibition, which a blanket
    // substring check would misfire on).
  });
});

// ===================================================================================================
// The status bar's cure notice is no longer gated on `credential_expired` ALONE. A boot-time
// credential refusal is `configured: false` with `credential_expired: false` (there is no arm and
// often no expiry stamp at all) and now carries a cure; gated on the expiry axis only, that cure
// rendered nowhere and the operator read the raw refusal sentence appended to the "not configured"
// line instead of the single-sourced cure copy.
//
// Source-scanned like every other contract in this file (see the module doc).
// ===================================================================================================
describe("the cure notice renders for an UNCONFIGURED-with-cure status, not only an expired one", () => {
  it("the notice condition reads status.credential_cure, not status.credential_expired alone", () => {
    expect(RENDER_TS).toMatch(
      /if\s*\(\s*status\.credential_expired\s*\|\|\s*status\.credential_cure\s*!==\s*null\s*\)/,
    );
  });

  it("the notice still reads its text from the single-sourced selector in state.ts", () => {
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*cureCopyFor\(status\)/);
  });

  it("an unconfigured-with-cure notice is NOT labelled as an expiry", () => {
    // The class name is the one thing that would lie if the expired span were reused verbatim for
    // a boot refusal that never had a live credential to expire.
    expect(RENDER_TS).toMatch(/status\.credential_expired\s*\?\s*"status-credential-expired"\s*:\s*"status-credential-cure"/);
  });
});

// ===================================================================================================
// The cure notice reads the map for the STAGE the status
// describes: a `configured: false` session's cure came from the LOCAL boot (a file read, the boot
// lock, the grant ratchet), not from a provider refusal, and the refresh-stage sentences lied about
// both the actor and the next step. The selection is single-sourced in `state.ts`
// (`cureCopyFor` over `CURE_COPY` / `UNCONFIGURED_CURE_COPY`) so this notice and the toast cannot
// drift; render.ts holds NO copy of its own and no branch of its own.
//
// Source-scanned like every other contract in this file (see the module doc).
// ===================================================================================================
describe("the cure notice reads the stage-appropriate map through the single-sourced selector", () => {
  it("the notice text is the single-sourced selector applied to the whole status, never a map indexed here", () => {
    expect(RENDER_TS).toMatch(/\.textContent\s*=\s*cureCopyFor\(status\)/);
  });

  it("render.ts imports the selector from state.ts and holds no cure copy of its own", () => {
    expect(RENDER_TS).toMatch(/import\s*\{[^}]*cureCopyFor[^}]*\}\s*from\s*"\.\/state"/);
    expect(RENDER_TS).not.toContain("the provider refused for an unrecognized reason");
    expect(RENDER_TS).not.toContain("needs a re-mint");
  });
});

describe("the status bar surfaces the WHY behind not-configured / unknown-epoch", () => {
  it("renderStatusBar references status.store_reason, status.provider_reason, and status.epoch_reason", () => {
    expect(RENDER_TS).toMatch(/status\.store_reason/);
    expect(RENDER_TS).toMatch(/status\.provider_reason/);
    expect(RENDER_TS).toMatch(/status\.epoch_reason/);
  });
});

// ===================================================================================================
// The redefined `configured` contract: the "configured" pill still keys off
// `status.configured` alone (never re-derived from `credential_expired`/`credential_cure`) — an
// expired-but-refreshable OR latched-dead credential is STILL `configured: true` and must still
// render the "configured" pill, with the credential-cure notice rendering ALONGSIDE it as its own
// independent span (per the "own class, own notice" rule above), never folded into or
// replacing the "not configured" line.
// ===================================================================================================
describe("the redefined configured contract — the configured pill stays keyed on status.configured alone", () => {
  it("the configured/unconfigured branch reads status.configured and nothing else (no credential_expired/credential_cure re-derivation)", () => {
    const match = RENDER_TS.match(/configured\.className\s*=\s*([^;]+);/);
    expect(match).not.toBeNull();
    expect(match?.[1]).toMatch(/status\.configured/);
    expect(match?.[1]).not.toMatch(/credential_expired/);
    expect(match?.[1]).not.toMatch(/credential_cure/);
  });
});

describe("clipboard copy failures are visible, not swallowed", () => {
  it("feature-detects navigator.clipboard (a guarded absence check) before calling it", () => {
    // The old defect called `navigator.clipboard.writeText` unconditionally — `navigator.clipboard`
    // is undefined outside a secure context, which throws on the `.writeText` property access
    // itself, before any promise/catch is ever reached. A guard that can answer "absent" (an
    // `if`/ternary testing clipboard's presence) must exist, not just a bare reference.
    expect(RENDER_TS).toMatch(/if\s*\(\s*!clipboard\s*\)|clipboard\s*\?\s*:|clipboard\s*===\s*undefined/);
  });

  it("catches a writeText rejection rather than a bare void-ed promise", () => {
    // The old defect was `void navigator.clipboard.writeText(...)` — no catch, no detect. The fix
    // must chain a `.catch(` off the `writeText(` call.
    expect(RENDER_TS).toMatch(/\.writeText\([^)]*\)\s*\.catch\(/);
  });

  it("a clipboard failure routes through onCopyFailed, not a swallowed rejection", () => {
    expect(RENDER_TS).toContain("onCopyFailed");
  });
});

describe("no clickable URLs — no href assignment anywhere in src/", () => {
  const files = listTsFiles(SRC_DIR);

  for (const file of files) {
    const rel = path.relative(SRC_DIR, file);
    it(`${rel} assigns no .href / href attribute (copy-only URLs, design §4 R1)`, () => {
      const source = fs.readFileSync(file, "utf8");
      expect(source).not.toMatch(/\.href\s*=/);
      expect(source).not.toMatch(/setAttribute\(\s*["']href["']/);
      expect(source.toLowerCase()).not.toContain("<a ");
      expect(source).not.toMatch(/createElement\(\s*["']a["']\s*\)/);
    });
  }
});

// The SUCCESS half of the status re-read. `admit_provider` renews the
// credential transparently inside every provider-READ command, so the success path is exactly
// where the status bar's credential facts (`credential_expired` / `credential_cure` /
// `credential_expires_at`) go stale — a session that boots expired would otherwise wear the
// dead-credential banner forever while every command succeeds. The refusal half already has a
// chokepoint (`reportRefusal`); this pins the success half at each of the three provider-READ
// call sites, enumerated from the ipc surface (refreshInbox · refreshMoreInbox · messageBody).
describe("every successful provider-READ command re-reads sessionStatus", () => {
  const readCommands = ["refreshInbox", "refreshMoreInbox", "messageBody"] as const;
  it.each(readCommands.map((c) => [c] as const))(
    "the command block around `await %s(...)` re-reads status in a finally (success AND failure)",
    (command) => {
      // A renewal can succeed and the SAME command then fail downstream
      // (provider backoff, store) — a success-arm-only re-read leaves the stale banner up, and
      // `reportRefusal` re-reads only for expiry-class refusals. The `finally` form covers both
      // arms by construction. Bounded window: from the awaited call to a `finally` block that
      // awaits refreshStatus().
      const window = new RegExp(
        String.raw`await ${command}\([\s\S]{0,1600}?finally\s*\{[\s\S]{0,400}?await refreshStatus\(\);`,
        "g",
      );
      expect(
        MAIN_TS.match(window),
        `main.ts re-reads sessionStatus in a finally around ${command}`,
      ).not.toBeNull();
    },
  );
});

// Main.ts's wiring, read as TEXT (main.ts needs a live document and IPC to execute):
// each new key verb reaches its own handler, the approve control approves exactly what was
// rendered BEFORE it applies, Escape closes an open review, and the three plan refusals take
// their own toast. Whitespace is folded to single spaces first (no escape sequences are used).
describe("main.ts routes each new key verb and the approve control to its own handler", () => {
  const folded = MAIN_TS.split(String.fromCharCode(13))
    .join("")
    .split(String.fromCharCode(10))
    .map((line) => line.trim())
    .join(" ");

  it("# mints a trash plan, ! mints a mark_spam plan, Shift+I marks read", () => {
    expect(folded).toContain('case "trash": void mintPlanForSelection("trash"); break;');
    expect(folded).toContain('case "spam": void mintPlanForSelection("mark_spam"); break;');
    expect(folded).toContain('case "mark_read": void markReadSelection(); break;');
    expect(folded).toContain("const review = await mintRedPlan(account, verb, targets);");
    expect(folded).toContain("const outcome = await setSeen(account, messageRef, true);");
  });

  // DERIVED, not a hand list: the KeyVerb union is read from keys.ts and
  // every member must have its own `case` in main.ts's switch, which ends in an exhaustive
  // `assertNever` default (so a new KeyVerb with no case also fails `tsc`, `npm run build`).
  it("every KeyVerb keys.ts declares has its own case in main.ts's key switch, and the switch is exhaustive", () => {
    const keysTs = fs.readFileSync(path.join(SRC_DIR, "keys.ts"), "utf8");
    const head = "export type KeyVerb =";
    const union = keysTs.slice(keysTs.indexOf(head) + head.length, keysTs.indexOf(";", keysTs.indexOf(head)));
    const verbs = [...union.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
    expect(verbs.length).toBeGreaterThanOrEqual(11);
    const cases = [...folded.matchAll(/case "([a-z_]+)":/g)].map((m) => m[1]);
    for (const verb of verbs) {
      expect(cases, `main.ts has a case for the KeyVerb "${verb}"`).toContain(verb);
    }
    expect(folded).toContain("default: assertNever(verb);");
  });

  // The ONE wrapper discovery the route witness below reads —
  // SYNTAX-COMPLETE: any identifier an `export function` can declare (`[A-Za-z_$][A-Za-z0-9_$]*`,
  // generic or not), so an underscore-named wrapper (`probe_route`) cannot slip past the witness the
  // way it did past `[A-Za-z]+`.
  const IDENT = "[A-Za-z_$][A-Za-z0-9_$]*";
  const exportedFunctions = (ts: string): string[] =>
    [...ts.matchAll(new RegExp(`export (?:async )?function (${IDENT})[ ]*[<(]`, "g"))].map((m) => m[1]);

  it("the wrapper discovery finds every identifier an export can declare — an underscore-named wrapper included", () => {
    const probe = ["export function probeRoute(): void {}", "export function probe_route(): void {}", "export function $probe(): void {}"].join(" ");
    expect(exportedFunctions(probe)).toEqual(["probeRoute", "probe_route", "$probe"]);
  });

  // Every ipc.ts wrapper has a caller in main.ts, or is classified here with
  // the reason it has none. Derived from ipc.ts.
  it("every ipc.ts command wrapper is called from main.ts or classified as having no renderer route", () => {
    const ipcTs = fs.readFileSync(path.join(SRC_DIR, "ipc.ts"), "utf8");
    const wrappers = exportedFunctions(ipcTs);
    expect(wrappers.length).toBeGreaterThanOrEqual(20);
    const CLASSIFIED_NO_RENDERER_ROUTE: Record<string, string> = {
      unarchive: "v1: an archive is undone through `undo` (the captured pre-state), never through unarchive",
      undoPresentation: "Part E residual 7: the E7 read door has no renderer caller yet",
      untrash: "v7 L465-473: a plan member's undo is the `undo` route, not a standalone key",
      unmarkSpam: "v7 L465-473: a plan member's undo is the `undo` route, not a standalone key",
      setKnob: "Part E residual 9: no settings surface in S1",
    };
    // An aliased import (`undo as undoIpc`) is called under its alias.
    const importClause = folded.slice(folded.indexOf("import {"), folded.indexOf('} from "./ipc";'));
    const alias = new Map(
      [...importClause.matchAll(new RegExp(`(${IDENT}) as (${IDENT})`, "g"))].map((m) => [m[2], m[1]] as [string, string]),
    );
    const called = new Set([...folded.matchAll(/([A-Za-z_$][A-Za-z0-9_$]*)\(/g)].map((m) => alias.get(m[1]) ?? m[1]));
    const uncalled = wrappers.filter((w) => !called.has(w));
    expect(uncalled.sort()).toEqual(Object.keys(CLASSIFIED_NO_RENDERER_ROUTE).sort());
  });

  it("a bypassed plan opens no screen — the mint's review goes to the reducer (which shows the notice) and straight to the apply door; no approval is sent from the renderer", () => {
    const mint = folded.indexOf("const review = await mintRedPlan(account, verb, targets);");
    const minted = folded.indexOf('store.dispatch({ type: "plan_minted", review });', mint);
    const bypass = folded.indexOf("if (!opensReviewScreen(review)) { await applyBypassedPlan(review.plan_id, verb, false); }", minted);
    expect(mint).toBeGreaterThan(0);
    expect(minted).toBeGreaterThan(mint);
    expect(bypass).toBeGreaterThan(minted);
    const body = folded.slice(folded.indexOf("async function applyBypassedPlan("), folded.indexOf("async function markReadSelection("));
    // The run itself is `runPlan` (shared with the screen lanes); the bypass
    // lane re-opens nothing after it — it has no screen. It hands the reducer
    // its verb, so an incomplete run keeps its retry handle on the toast.
    expect(body).toContain("await runPlan(planId, false, { verb, retried });");
    expect(body).toContain("if (!verbsAllowed(status))");
    expect(body).not.toContain("planApprove");
    const run = folded.slice(folded.indexOf("async function runPlan("), folded.indexOf("async function reopenReview("));
    expect(run).toContain("const outcome = await planApply(planId);");
    // The run stamps the `planGeneration` it captured before awaiting.
    expect(run).toContain("const generation = store.getState().planGeneration;");
    expect(run).toContain('store.dispatch({ type: "plan_applied", outcome, bypass, generation });');
    expect(run).not.toContain("planApprove");
  });

  it("the undo walk over a plan's labelled keys dispatches one per-member plan undo toast, in key order", () => {
    const walk = folded.slice(folded.indexOf("async function handleUndoBatch("), folded.indexOf("function handleCopyFailed("));
    expect(walk).toContain("const labels = store.getState().toast?.undoLabels ?? null;");
    expect(walk).toContain("for (let i = 0; i < keys.length; i += 1) {");
    expect(walk).toContain("const outcome = await undoIpc(keys[i]);");
    // The offer's restoration lines ride the walk beside its labels.
    expect(walk).toContain("const undoRestoration = store.getState().toast?.undoRestoration;");
    expect(walk).toContain('store.dispatch({ type: "plan_undo_toast", steps: [...steps], remainingKeys: unconsumedUndoKeys(keys, i + 1), labels, undoRestoration });');
    expect(walk).toContain("remainingKeys: unconsumedUndoKeys(keys, i + 1), undoRestoration, });");
  });

  it("the approve control approves what was rendered, then applies; Escape closes; plan refusals take their own toast", () => {
    const approve = folded.indexOf('await planApprove(planId, rendered, "operator");');
    // Searched FROM the approval: what this pins is the screen lanes' order — approve, then run
    // the plan (`runPlan`, which re-opens the review after a stop).
    const apply = folded.indexOf("await runPlan(planId, true);", approve);
    expect(approve).toBeGreaterThan(0);
    expect(apply).toBeGreaterThan(approve);
    expect(folded).toContain('if (event.key === "Escape") { event.preventDefault(); handlePlanCancel(); }');
    expect(folded).toContain('if (isPlanRefusal(e)) { store.dispatch({ type: "plan_refusal_toast", refusal: e }); return; }');
  });
});

describe("renderAll paints the plan review and the root exists", () => {
  it("renderAll calls renderPlanReview with the state's review; queryRoots reads #plan-review; index.html carries it", () => {
    expect(RENDER_TS).toMatch(/renderPlanReview\(roots, state\.planReview, onPlanApprove, onPlanCancel, onPlanApply\)/);
    expect(RENDER_TS).toContain('planReview: get("plan-review")');
    const html = fs.readFileSync(path.resolve(SRC_DIR, "..", "index.html"), "utf8");
    expect(html).toContain('id="plan-review"');
  });
});
