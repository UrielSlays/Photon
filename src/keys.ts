// The keymap. Keyboard-first: j/k move, Enter read, e archive, s star,
// u/z undo, r refresh; `#` trash, `!` spam, Shift+I mark read.
//
// Pure mapping from a `KeyboardEvent`'s `.key` to a named verb — no DOM writes here, and no IPC
// calls: `main.ts` owns wiring the resulting verb to `ipc.ts` + `state.ts`.

export type KeyVerb =
  | "move_down"
  | "move_up"
  | "open"
  | "archive"
  | "toggle_star"
  | "toggle_select"
  | "undo"
  | "refresh"
  | "trash"
  | "spam"
  | "mark_read";

const KEYMAP: Record<string, KeyVerb> = {
  j: "move_down",
  k: "move_up",
  Enter: "open",
  e: "archive",
  s: "toggle_star",
  x: "toggle_select",
  u: "undo",
  z: "undo",
  r: "refresh",
  // Atlas `04-SURFACE-PATTERN-LIBRARY.md:45,47`: Gmail's own public shortcuts, LIFTed.
  // These three are VALUE-keyed: `event.key` carries the produced VALUE (`#` for Shift+3, `!` for
  // Shift+1, `I` for Shift+i on a US layout), so the map needs no shift flag, and whichever keys
  // a layout uses to produce `#`, `!` or `I` reach these verbs — including AltGr on FR / ES / IT
  // Windows layouts and Option on a Mac (`verbForKey`). The unshifted `3`,
  // `1` and `i` stay unmapped. Value-keyed also means CapsLock plus a bare `i` yields `I` and
  // marks read — stated here, not "fixed": the value is what the keymap reads.
  "#": "trash",
  "!": "spam",
  I: "mark_read",
};

/// The three VALUE-keyed entries — the only ones a layout may produce with AltGr or Option.
const VALUE_KEYS = new Set(["#", "!", "I"]);

/// What `verbForKey` reads off an event: the value, the modifiers, and (optionally) the modifier
/// state — `getModifierState("AltGraph")` is how a browser says AltGr produced the value.
export type KeyEventLike = Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "altKey"> & {
  getModifierState?: (key: string) => boolean;
};

/// Returns the verb for a keypress, or `null` for anything not in the keymap.
///
/// The LETTER shortcuts (and `Enter`) claim bare keys only: any modifier leaves them to the
/// browser/OS. The three VALUE-keyed entries (`#`, `!`, `I`) count however the layout produced the
/// value: a Mac's Option (alt set, e.g. UK Mac Option+3 = `#`) and AltGr
/// (Windows reports ctrl+alt, with `getModifierState("AltGraph")` true) are how some layouts TYPE
/// these values, so they do not refuse them. Meta, and ctrl without AltGraph, stay the OS's.
export function verbForKey(event: KeyEventLike): KeyVerb | null {
  const verb = KEYMAP[event.key] ?? null;
  if (verb === null) {
    return null;
  }
  if (!VALUE_KEYS.has(event.key)) {
    return event.ctrlKey || event.metaKey || event.altKey ? null : verb;
  }
  if (event.metaKey) {
    return null;
  }
  if (event.ctrlKey && event.getModifierState?.("AltGraph") !== true) {
    return null;
  }
  return verb;
}

/// The exhaustive-switch guard: `main.ts`'s key switch ends in
/// `default: assertNever(verb);`, so a `KeyVerb` added here with no `case` there fails `tsc`.
export function assertNever(value: never): never {
  throw new Error(`unhandled key verb: ${String(value)}`);
}

// ===================================================================================================
// Global shortcuts must not fire from a focused interactive/editable control. Enter
// on a focused "Copy body"/"Undo" button used to ALSO trigger the global `open` handler, because
// the keydown listener never looked at `event.target`. `isInteractiveTarget` is the pure predicate
// the listener guards on before consulting the keymap at all; it takes a minimal, node-testable
// shape (never the real `Element` type) so it can be unit-tested against a plain mock object with
// no DOM.
// ===================================================================================================

/// The minimal shape `isInteractiveTarget` reads off an event target — deliberately NOT `Element`,
/// so a plain `{ tagName: "BUTTON" }` mock exercises the same code path a real `HTMLElement` does.
export interface InteractiveTargetLike {
  tagName?: string;
  isContentEditable?: boolean;
  getAttribute?: (name: string) => string | null;
}

const INTERACTIVE_TAGS = new Set(["BUTTON", "A", "INPUT", "TEXTAREA", "SELECT"]);

/// True when `target` is a control the browser already treats as interactive/editable (a button,
/// link, form control) OR is `contenteditable` (checked via BOTH the live `isContentEditable`
/// property and a `getAttribute("contenteditable")` fallback, since a mock/test shape may only
/// carry one of the two). Anything else (a `div`, `span`, the document body) is not interactive.
export function isInteractiveTarget(target: InteractiveTargetLike | null | undefined): boolean {
  if (!target) {
    return false;
  }
  const tag = target.tagName?.toUpperCase();
  if (tag && INTERACTIVE_TAGS.has(tag)) {
    return true;
  }
  if (target.isContentEditable) {
    return true;
  }
  const editable = target.getAttribute?.("contenteditable");
  return editable === "true" || editable === "";
}
