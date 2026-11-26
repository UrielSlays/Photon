// The wire mirror, byte for byte. Two witnesses:
//
// 1. TYPED LITERALS: every tag value of every tagged wire type the triage doors answer, spelled as
//    the Rust `#[serde]` attributes emit it and assigned to the `ipc.ts` type — a misspelled tag
//    or a renamed field in the mirror fails `tsc` (`npm run build` type-checks `src/`, tests
//    included; vitest itself strips types).
// 2. THE MIRROR SCAN: `src-tauri/src/lib.rs` and `src/ipc.ts` are read as TEXT (the `node`
//    environment's rule — see `sinkfence.test.ts`) and, for every wire type, the Rust side's
//    tag values / variant field names / struct field names are compared with the TS side's —
//    tsc cannot see the Rust bytes, and the mirror is only as good as its agreement with them.
//    The scan's command list and type list are DERIVED
//    from the Rust source (every `#[tauri::command]`, and every type those commands reach), never
//    a hand list — see the section's own header below.
//    The parser uses no escape sequences (line breaks and carriage returns are assembled from
//    char codes): escapes have died in transport on this lane before.
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import type {
  KnobActWire,
  LaneView,
  MemberStateView,
  PlanApplyOutcome,
  PlanApproveOutcome,
  PlanReviewView,
  PreflightView,
  RenderedViewWire,
  RestorationView,
  SurfaceError,
  UndoPresentationReadView,
  VerbOutcome,
} from "../ipc";

const NL = String.fromCharCode(10);
const CR = String.fromCharCode(13);

function readText(...segments: string[]): string {
  return fs.readFileSync(path.resolve(__dirname, ...segments), "utf8").split(CR).join("");
}

const LIB_RS = readText("..", "..", "src-tauri", "src", "lib.rs");
const IPC_TS = readText("..", "ipc.ts");

const HEADER = { account: "a", verb: "trash", tier: "red", count: 0, backup_coverage: false, warning: "w" };
const SUMMARY = { count: 0, sender_domains: [["x.com", 1]] as [string, number][], sender_domain_unavailable: 0, sender_header_malformed: 0, sender_header_unsupported: 0, date_min: "", date_max: "", total_size: null };

describe("triage wire shapes mirror src-tauri/src/lib.rs", () => {
  it("plan refusals are tagged objects with the engine's tokens", () => {
    const e: SurfaceError = { kind: "plan_refused", reason: "state_diverged", member_ref: "m1", diff: [{ atom: "membership:INBOX", expected: true, observed: false }] };
    expect(e.kind).toBe("plan_refused");
    const r: SurfaceError = { kind: "plan_required" };
    expect(r.kind).toBe("plan_required");
    const c: SurfaceError = { kind: "plan_child_refused", reason: "not_ready" };
    expect(c.kind).toBe("plan_child_refused");
    const whole: SurfaceError = { kind: "plan_refused", reason: "evidence_invalid", member_ref: null, diff: [] };
    expect(whole.kind).toBe("plan_refused");
    // The connector's capability refusal, by name, carrying nothing else.
    const unsupported: SurfaceError = { kind: "unsupported_capability" };
    expect(unsupported.kind).toBe("unsupported_capability");
    // The mid-run credential rejection, by name, carrying nothing
    // else — same shape as `unsupported_capability` just above.
    const credentialRejected: SurfaceError = { kind: "credential_rejected" };
    expect(credentialRejected.kind).toBe("credential_rejected");
  });
  it("the rendered-view echo is mode-tagged exactly as Rust's #[serde(tag = \"mode\")]", () => {
    const v: RenderedViewWire = { mode: "full_list", presentation: { header: HEADER, summary: SUMMARY, rows: [] } };
    expect(v.mode).toBe("full_list");
    const a: RenderedViewWire = { mode: "aggregate", header: HEADER, summary: SUMMARY, sample_k: 1, sample_rows: [{ message_ref: "m", sender: "s", sender_address: "", sender_local: "", sender_domain: "", sender_status: "ok", subject: "t", date: "d", size: null }] };
    expect(a.mode).toBe("aggregate");
  });
  it("member states are state-tagged", () => {
    const s: MemberStateView = { state: "refused", reason: "snapshot_absent", diff: [] };
    expect(s.state).toBe("refused");
    const all: MemberStateView[] = [{ state: "not_minted" }, { state: "in_flight" }, { state: "applied" }, { state: "terminal", status: "failed" }];
    expect(all.map((m) => m.state)).toEqual(["not_minted", "in_flight", "applied", "terminal"]);
  });
  it("the preflight is outcome-tagged; the apply outcome carries [member, state] pairs", () => {
    const p: PreflightView[] = [{ outcome: "ready" }, { outcome: "raced" }, { outcome: "refused", diverged: [["m1", [{ atom: "membership:INBOX", expected: true, observed: null }]]] }];
    expect(p.map((x) => x.outcome)).toEqual(["ready", "raced", "refused"]);
    const o: PlanApplyOutcome = { plan_id: "p", preflight: { outcome: "ready" }, members: [["m1", { state: "applied" }]], completion: "completed", projection: { state: "current" }, skipped: [], held: [], undo_keys: [{ member_ref: "m1", undo_key: "k1", restoration: { verdict: "within_closure" } }], bypass_notice: null, stopped: null };
    expect(o.members[0][1].state).toBe("applied");
    expect(o.undo_keys[0]).toEqual({ member_ref: "m1", undo_key: "k1", restoration: { verdict: "within_closure" } });
    // A run that stopped carries the refusal that stopped it, and a stop before
    // the preflight decided carries no preflight.
    const stopped: PlanApplyOutcome = { ...o, preflight: null, stopped: { kind: "plan_child_refused", reason: "episode_not_active" } };
    expect(stopped.stopped?.kind).toBe("plan_child_refused");
  });
  it("the review, the approval and the knob act are the Rust shapes", () => {
    const lanes: LaneView[] = ["per_member", "aggregate", "bypassed"];
    const review: PlanReviewView = { plan_id: "p", lane: lanes[1], presentation: { header: HEADER, summary: SUMMARY, rows: [] }, sample_k: 2, sample_rows: [], expires_at: "e", approved: false, terminal: false, bypass_notice: null };
    expect(review.lane).toBe("aggregate");
    const approved: PlanApproveOutcome = { plan_id: "p", comprehension: "per_member", approver: "operator" };
    expect(approved.approver).toBe("operator");
    const knobs: KnobActWire[] = [{ kind: "backups", on: false }, { kind: "red_bypass", on: true }, { kind: "approval_mode", mode: "summary_sample", configured_k: 4 }];
    expect(knobs.map((k) => k.kind)).toEqual(["backups", "red_bypass", "approval_mode"]);
  });
  it("the restoration verdict is verdict-tagged and rides beside the bare-string presentation", () => {
    const all: RestorationView[] = [
      { verdict: "within_closure" },
      { verdict: "outside_closure", system_labels: ["IMPORTANT"], user_label_count: 1 },
      { verdict: "no_pre_effect_vector" },
      { verdict: "no_effect_witness" },
      { verdict: "unreadable" },
      { verdict: "witness_write_failed" },
    ];
    expect(all.map((r) => r.verdict)).toEqual(["within_closure", "outside_closure", "no_pre_effect_vector", "no_effect_witness", "unreadable", "witness_write_failed"]);
    const verb: VerbOutcome = { applied: true, undo_key: "k", projection: { state: "current" }, restoration: all[3] };
    expect(verb.restoration?.verdict).toBe("no_effect_witness");
    const read: UndoPresentationReadView = { presentation: "applied_undo_severed", restoration: null };
    expect(read.presentation).toBe("applied_undo_severed");
  });
});

// ===============================================================================================
// THE MIRROR SCAN — DERIVED
//
// Nothing below is a hand list. The COMMAND list is every `#[tauri::command]` function in the
// shell's production source; the TYPE list is the closure of every named type those commands take
// or answer (their arguments, their `Ok` type, `SurfaceError`), followed field by field through the
// Rust definitions — `src-tauri/src/lib.rs`, plus the two other files a wire type is defined in
// (`src-tauri/src/token_refresh.rs` for `Cure`; `crates/aruna/src/body_view.rs` and
// `crates/aruna/src/read_surface.rs` for the body and its attachment presence).
// A command, a variant, a field or a type added on the Rust side alone therefore fails here: a
// command with no `ipc.ts` wrapper, a variant or field `ipc.ts` does not spell, a type `ipc.ts`
// does not declare. Serde's representation is read off each definition's attributes (internally
// tagged, bare-string unit enum, externally tagged, `flatten`), never assumed per type.
// ===============================================================================================

/// Both sources with their comment LINES removed first: a doc comment may quote a shape (braces,
/// semicolons, a tag value) that is not the shape.
function codeOnly(source: string): string {
  return source
    .split(NL)
    .filter((l) => !l.trim().startsWith("//"))
    .join(NL);
}

const TESTS_START = NL + "#[cfg(test)]" + NL + "mod tests {";
function production(source: string): string {
  const at = source.indexOf(TESTS_START);
  return codeOnly(at >= 0 ? source.slice(0, at) : source);
}
const LIB_PRODUCTION = production(LIB_RS);
// lib.rs plus the shell modules split out of it.
const SHELL_MODULES = ["lib.rs", "error.rs", "single_flight.rs", "credential.rs", "session.rs", "provider.rs", "state.rs", "status.rs", "ipc.rs", "plumbing.rs", "verbs.rs", "plan.rs"];
const RUST_SOURCES: [string, string][] = [
  ...SHELL_MODULES.map((f): [string, string] => [`src-tauri/src/${f}`, production(readText("..", "..", "src-tauri", "src", f))]),
  ["src-tauri/src/token_refresh.rs", codeOnly(readText("..", "..", "src-tauri", "src", "token_refresh.rs"))],
  ["crates/aruna/src/body_view.rs", codeOnly(readText("..", "..", "crates", "aruna", "src", "body_view.rs"))],
  ["crates/aruna/src/read_surface.rs", codeOnly(readText("..", "..", "crates", "aruna", "src", "read_surface.rs"))],
];
const IPC_CODE = codeOnly(IPC_TS);

function snake(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function camel(name: string): string {
  return name.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

/// Split on `sep` at nesting depth 0 of `<>`, `()`, `[]` and `{}`.
function splitTop(text: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if ("<([{".includes(ch)) depth += 1;
    if (">)]}".includes(ch)) depth -= 1;
    if (ch === sep && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

/// The text between the `{` that ends `head` and its matching `}`.
function blockAfter(source: string, head: string): string {
  const found = source.indexOf(head);
  if (found < 0) throw new Error(`not found: ${head}`);
  let at = found + head.length;
  const start = at;
  let depth = 1;
  while (depth > 0) {
    const ch = source[at];
    if (ch === "{") depth += 1;
    if (ch === "}") depth -= 1;
    at += 1;
  }
  return source.slice(start, at - 1);
}

/// The attribute lines directly above the line `head` starts.
function attributesAbove(source: string, head: string): string {
  const found = source.indexOf(head);
  const lines = source.slice(0, found).split(NL);
  const attributes: string[] = [];
  while (lines.length > 0 && lines[lines.length - 1].trim().startsWith("#[")) {
    attributes.unshift((lines.pop() ?? "").trim());
  }
  return attributes.join(" ");
}

/// The body on one line (attributes KEPT: a field's `#[serde(flatten)]` is part of its shape).
function oneLine(body: string): string {
  return body
    .split(NL)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join(" ");
}

/// `#[a] #[b] rest` → [["#[a]", "#[b]"], "rest"].
function stripAttributes(part: string): [string[], string] {
  const attributes: string[] = [];
  let rest = part.trim();
  while (rest.startsWith("#[")) {
    let depth = 0;
    let at = 1;
    for (; at < rest.length; at += 1) {
      if (rest[at] === "[") depth += 1;
      if (rest[at] === "]") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    attributes.push(rest.slice(0, at + 1));
    rest = rest.slice(at + 1).trim();
  }
  return [attributes, rest];
}

const RUST_NON_WIRE = new Set(["Result", "Option", "Vec", "String", "Box", "BTreeMap", "BTreeSet", "HashMap", "Self"]);
const TS_NON_WIRE = new Set(["Promise", "Record", "Array", "Readonly"]);

/// The named (wire) types a type expression mentions.
function namedTypes(expression: string, skip: Set<string>): string[] {
  return [...new Set([...expression.matchAll(/\b([A-Z][A-Za-z0-9]*)\b/g)].map((m) => m[1]))].filter((n) => !skip.has(n)).sort();
}

interface RustField {
  name: string;
  type: string;
  flatten: boolean;
}

type RustShape =
  | { kind: "struct"; fields: RustField[] }
  | { kind: "enum"; tag: string | null; snakeCase: boolean; variants: { name: string; fields: RustField[] | null; tuple: string | null }[] };

function rustFields(text: string): RustField[] {
  return splitTop(text, ",").map((part) => {
    const [attributes, rest] = stripAttributes(part);
    const field = rest.startsWith("pub ") ? rest.slice(4) : rest;
    const colon = field.indexOf(":");
    return {
      name: field.slice(0, colon).trim(),
      type: field.slice(colon + 1).trim(),
      flatten: attributes.some((a) => a.includes("flatten")),
    };
  });
}

/// A wire type's Rust definition, from whichever source file declares it.
function rustShape(name: string): { file: string; shape: RustShape } {
  for (const [file, source] of RUST_SOURCES) {
    for (const keyword of ["struct", "enum"] as const) {
      const head = NL + `pub ${keyword} ${name} {`;
      if (!source.includes(head)) continue;
      const serde = attributesAbove(source, head);
      const body = oneLine(blockAfter(source, head));
      if (keyword === "struct") {
        return { file, shape: { kind: "struct", fields: rustFields(body) } };
      }
      const tagAt = serde.indexOf('tag = "');
      const tag = tagAt < 0 ? null : serde.slice(tagAt + 7, serde.indexOf('"', tagAt + 7));
      const variants = splitTop(body, ",").map((part) => {
        const [, rest] = stripAttributes(part);
        let end = 0;
        while (end < rest.length && /[A-Za-z0-9_]/.test(rest[end])) end += 1;
        const variantName = rest.slice(0, end);
        const tail = rest.slice(end).trim();
        if (tail === "") return { name: variantName, fields: null, tuple: null };
        if (tail.startsWith("(")) return { name: variantName, fields: null, tuple: tail.slice(1, -1) };
        return { name: variantName, fields: rustFields(tail.slice(1, -1)), tuple: null };
      });
      return { file, shape: { kind: "enum", tag, snakeCase: serde.includes('rename_all = "snake_case"'), variants } };
    }
  }
  throw new Error(`the wire type ${name} has no Rust definition in ${RUST_SOURCES.map(([f]) => f).join(", ")}`);
}

/// Every `#[tauri::command]` in the production source: name, arguments (the managed state
/// excluded, `[name, type]`), and the `Ok` type.
function rustCommands(): { name: string; args: [string, string][]; ok: string }[] {
  const out: { name: string; args: [string, string][]; ok: string }[] = [];
  const attribute = "#[tauri::command]";
  let at = LIB_PRODUCTION.indexOf(attribute);
  while (at >= 0) {
    const fnAt = LIB_PRODUCTION.indexOf("fn ", at);
    const open = LIB_PRODUCTION.indexOf("(", fnAt);
    const name = LIB_PRODUCTION.slice(fnAt + 3, open).trim();
    let depth = 1;
    let cursor = open + 1;
    while (depth > 0) {
      if ("(<[".includes(LIB_PRODUCTION[cursor])) depth += 1;
      if (")>]".includes(LIB_PRODUCTION[cursor])) depth -= 1;
      cursor += 1;
    }
    const args = splitTop(LIB_PRODUCTION.slice(open + 1, cursor - 1), ",")
      .map((p) => [p.slice(0, p.indexOf(":")).trim(), p.slice(p.indexOf(":") + 1).trim()] as [string, string])
      .filter(([argName]) => argName !== "state");
    const signatureTail = LIB_PRODUCTION.slice(cursor, LIB_PRODUCTION.indexOf("{", cursor));
    const result = signatureTail.slice(signatureTail.indexOf("Result<") + "Result<".length, signatureTail.lastIndexOf(">"));
    const ok = splitTop(result, ",")[0];
    out.push({ name, args, ok });
    at = LIB_PRODUCTION.indexOf(attribute, cursor);
  }
  return out;
}

/// The wire types reachable from the commands, followed through every field.
function wireClosure(): string[] {
  const pending = ["SurfaceError"];
  for (const command of rustCommands()) {
    pending.push(...namedTypes(command.ok, RUST_NON_WIRE));
    for (const [, type] of command.args) pending.push(...namedTypes(type, RUST_NON_WIRE));
  }
  const seen = new Set<string>();
  while (pending.length > 0) {
    const name = pending.pop() as string;
    if (seen.has(name)) continue;
    seen.add(name);
    const { shape } = rustShape(name);
    const fields = shape.kind === "struct" ? shape.fields : shape.variants.flatMap((v) => v.fields ?? []);
    for (const field of fields) pending.push(...namedTypes(field.type, RUST_NON_WIRE));
    if (shape.kind === "enum") {
      for (const v of shape.variants) if (v.tuple) pending.push(...namedTypes(v.tuple, RUST_NON_WIRE));
    }
  }
  return [...seen].sort();
}

/// A TS alias's right-hand side, up to its `;` at depth 0.
function tsAlias(name: string): string {
  const head = `export type ${name} =`;
  const start = IPC_CODE.indexOf(head);
  if (start < 0) throw new Error(`ts type ${name}`);
  let at = start + head.length;
  let depth = 0;
  while (!(IPC_CODE[at] === ";" && depth === 0)) {
    if ("<([{".includes(IPC_CODE[at])) depth += 1;
    if (">)]}".includes(IPC_CODE[at])) depth -= 1;
    at += 1;
  }
  return IPC_CODE.slice(start + head.length, at).trim();
}

function unquote(value: string): string {
  const v = value.trim();
  if (!(v.startsWith('"') && v.endsWith('"'))) throw new Error(`not a string literal: ${value}`);
  return v.slice(1, -1);
}

/// `{ a: T; b?: U }` → [[a, T], [b, U]].
function tsObjectFields(text: string): [string, string][] {
  const inner = text.trim();
  if (!(inner.startsWith("{") && inner.endsWith("}"))) throw new Error(`not an object type: ${text}`);
  return splitTop(oneLine(inner.slice(1, -1)), ";").map((f) => [f.slice(0, f.indexOf(":")).trim().replace("?", ""), f.slice(f.indexOf(":") + 1).trim()]);
}

function tsInterfaceFields(name: string): [string, string][] {
  const head = `export interface ${name} {`;
  if (!IPC_CODE.includes(head)) throw new Error(`ts interface ${name}`);
  return tsObjectFields(`{${blockAfter(IPC_CODE, head)}}`);
}

/// Rust field set ≡ TS field set, and each field names the same wire types on both sides.
function expectSameFields(where: string, rust: RustField[], ts: [string, string][]): void {
  expect(ts.map(([n]) => n).sort(), `${where}: field names`).toEqual(rust.map((f) => f.name).sort());
  for (const field of rust) {
    const tsType = ts.find(([n]) => n === field.name)?.[1] ?? "";
    expect(namedTypes(tsType, TS_NON_WIRE), `${where}.${field.name}: the wire types it names`).toEqual(namedTypes(field.type, RUST_NON_WIRE));
  }
}

/// One wire type: its Rust shape against its `ipc.ts` declaration, by serde representation.
function expectMirrored(name: string): void {
  const { shape } = rustShape(name);
  if (shape.kind === "struct") {
    const flattened = shape.fields.filter((f) => f.flatten);
    if (flattened.length === 0) {
      expectSameFields(name, shape.fields, tsInterfaceFields(name));
      return;
    }
    // `#[serde(flatten)]`: the TS side is `Flattened & { the rest }`.
    const [base, rest] = splitTop(tsAlias(name), "&");
    expect(flattened.map((f) => f.type), `${name}: the flattened type`).toEqual([base.trim()]);
    expectSameFields(name, shape.fields.filter((f) => !f.flatten), tsObjectFields(rest));
    return;
  }
  const members = splitTop(tsAlias(name), "|");
  const value = (variant: string) => (shape.snakeCase ? snake(variant) : variant);
  if (shape.tag !== null) {
    // Internally tagged: `{ tag: "value";...fields }`.
    const tag = shape.tag;
    const ts = new Map(
      members.map((m) => {
        const fields = tsObjectFields(m);
        const tagField = fields.find(([n]) => n === tag);
        if (!tagField) throw new Error(`${name} member without "${tag}": ${m}`);
        return [unquote(tagField[1]), fields.filter(([n]) => n !== tag)] as [string, [string, string][]];
      }),
    );
    expect([...ts.keys()].sort(), `${name}: the ${tag} values`).toEqual(shape.variants.map((v) => value(v.name)).sort());
    for (const v of shape.variants) {
      if (v.tuple !== null) throw new Error(`${name}::${v.name}: an internally tagged tuple variant has no mirror rule`);
      expectSameFields(`${name}.${value(v.name)}`, v.fields ?? [], ts.get(value(v.name)) ?? []);
    }
    return;
  }
  if (shape.variants.every((v) => v.fields === null && v.tuple === null)) {
    // All-unit, untagged: a bare string per variant.
    expect(members.map(unquote).sort(), `${name}: the bare strings`).toEqual(shape.variants.map((v) => value(v.name)).sort());
    return;
  }
  // Externally tagged (no serde attributes): `{ Variant: payload }`.
  const ts = new Map(
    members.map((m) => {
      const [[key, payload]] = tsObjectFields(m);
      return [key, payload] as [string, string];
    }),
  );
  expect([...ts.keys()].sort(), `${name}: the external tags`).toEqual(shape.variants.map((v) => value(v.name)).sort());
  for (const v of shape.variants) {
    const payload = ts.get(value(v.name)) ?? "";
    if (v.tuple !== null) {
      expect(namedTypes(payload, TS_NON_WIRE), `${name}.${v.name}`).toEqual(namedTypes(v.tuple, RUST_NON_WIRE));
    } else {
      expectSameFields(`${name}.${v.name}`, v.fields ?? [], tsObjectFields(payload));
    }
  }
}

/// The `ipc.ts` wrapper for a command: the keys it hands `invoke` and the type its Promise carries.
function tsWrapper(command: string): { keys: string[]; returns: string } {
  const head = `invoke("${command}"`;
  const found = IPC_CODE.indexOf(head);
  if (found < 0) throw new Error(`no ipc.ts wrapper invokes ${command}`);
  const fnAt = IPC_CODE.lastIndexOf("export function ", found);
  const signature = IPC_CODE.slice(fnAt, IPC_CODE.indexOf("{" + NL, fnAt));
  const returns = signature.slice(signature.indexOf("Promise<") + "Promise<".length, signature.lastIndexOf(">"));
  const after = IPC_CODE.slice(found + head.length).trimStart();
  const keys = after.startsWith(")") ? [] : splitTop(after.slice(after.indexOf("{") + 1, after.indexOf("}")), ",");
  return { keys, returns };
}

describe("the mirror scan — DERIVED from the Rust commands and the types they reach", () => {
  const commands = rustCommands();
  const closure = wireClosure();

  it("the scan reads real shapes (it is not vacuous): every registered door, and the types they reach", () => {
    const registered = LIB_PRODUCTION.slice(LIB_PRODUCTION.indexOf("generate_handler!["));
    const handlerList = registered.slice("generate_handler![".length, registered.indexOf("]"));
    expect(commands.map((c) => c.name).sort()).toEqual(splitTop(handlerList, ",").sort());
    expect(commands.length).toBeGreaterThanOrEqual(20);
    expect(closure).toContain("PlanApplyOutcome");
    expect(closure).toContain("UndoPresentationView");
    expect(closure).toContain("BodyAvailability");
    expect(closure).toContain("Cure");
    expect(closure.length).toBeGreaterThanOrEqual(30);
  });

  it.each(rustCommands().map((c) => [c.name]))("the %s wrapper passes exactly the command's own arguments, camelCased, and answers its Ok type", (name) => {
    const command = commands.find((c) => c.name === name);
    const wrapper = tsWrapper(name);
    expect(wrapper.keys.sort(), `${name}: invoke keys`).toEqual((command?.args ?? []).map(([arg]) => camel(arg)).sort());
    expect(namedTypes(wrapper.returns, TS_NON_WIRE), `${name}: the answer type`).toEqual(namedTypes(command?.ok ?? "", RUST_NON_WIRE));
  });

  it.each(wireClosure().map((n) => [n]))("%s: ipc.ts mirrors its Rust definition — representation, variants, fields and the wire types each field names", (name) => {
    expectMirrored(name);
  });
});
