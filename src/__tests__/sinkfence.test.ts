// THE SINK FENCE ("textContent-equivalent sinks ONLY").
//
// Reads every non-test `.ts` file under `src/` as TEXT (never imports/executes them — `node`
// env has no `document`) and asserts, by TOKEN, that no forbidden DOM sink appears anywhere,
// and that `render.ts` is the only module writing `document.createElement`/`.textContent`.
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

const SRC_DIR = path.resolve(__dirname, "..");

function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__") {
        continue;
      }
      out.push(...listSourceFiles(full));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".ts")) {
      out.push(full);
    }
  }
  return out;
}

/// Strips `//` line comments and `/*... */` block comments from TypeScript source, respecting
/// single/double/template-literal string boundaries so a `//` or `/*` INSIDE a string literal is
/// never mistaken for the start of a comment (and so a forbidden token quoted inside a string —
/// which is not a real sink call — does not itself need special-casing beyond this).
function stripComments(source: string): string {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    const next = source[i + 1];

    if (c === "/" && next === "/") {
      while (i < n && source[i] !== "\n") {
        i++;
      }
      continue;
    }
    if (c === "/" && next === "*") {
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        i++;
      }
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n && source[i] !== quote) {
        if (source[i] === "\\" && i + 1 < n) {
          out += source[i] + source[i + 1];
          i += 2;
          continue;
        }
        out += source[i];
        i++;
      }
      if (i < n) {
        out += source[i];
        i++;
      }
      continue;
    }

    out += c;
    i++;
  }
  return out;
}

const FORBIDDEN_SINKS = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"];

describe("the sink fence — zero forbidden DOM sinks anywhere under src/", () => {
  const files = listSourceFiles(SRC_DIR);

  it("found at least the expected non-test source files (sanity: the scan is not vacuous)", () => {
    expect(files.length).toBeGreaterThanOrEqual(5);
    expect(files.some((f) => f.endsWith("render.ts"))).toBe(true);
  });

  for (const file of files) {
    const rel = path.relative(SRC_DIR, file);
    it(`${rel} contains none of ${FORBIDDEN_SINKS.join(", ")} (comments stripped)`, () => {
      const stripped = stripComments(fs.readFileSync(file, "utf8"));
      for (const sink of FORBIDDEN_SINKS) {
        expect(stripped.includes(sink)).toBe(false);
      }
    });
  }
});

describe("module discipline — render.ts is the only DOM writer", () => {
  const files = listSourceFiles(SRC_DIR);

  it("no file other than render.ts calls document.createElement or assigns .textContent", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const rel = path.relative(SRC_DIR, file);
      if (rel === "render.ts") {
        continue;
      }
      const stripped = stripComments(fs.readFileSync(file, "utf8"));
      if (stripped.includes("document.createElement") || stripped.includes(".textContent")) {
        offenders.push(rel);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("render.ts itself DOES use document.createElement and .textContent (the fence has a purpose)", () => {
    const renderSource = stripComments(fs.readFileSync(path.join(SRC_DIR, "render.ts"), "utf8"));
    expect(renderSource.includes("document.createElement")).toBe(true);
    expect(renderSource.includes(".textContent")).toBe(true);
  });
});
