// Global shortcuts must not fire from a focused interactive/editable control
// (e.g. Enter on a focused "Copy body"/"Undo" button also triggering the global `open` handler).
// `isInteractiveTarget` is the pure predicate `main.ts`'s keydown handler guards on; it is
// node-testable against a plain mock element shape (tagName + optional getAttribute/
// isContentEditable) — no real DOM required.
import { describe, expect, it } from "vitest";
import { isInteractiveTarget, verbForKey } from "../keys";

describe("isInteractiveTarget — the global-shortcut guard", () => {
  it("a button element IS interactive", () => {
    expect(isInteractiveTarget({ tagName: "BUTTON" })).toBe(true);
  });

  it("a plain div is NOT interactive", () => {
    expect(isInteractiveTarget({ tagName: "DIV" })).toBe(false);
  });

  it("a contenteditable div IS interactive (attribute-based check)", () => {
    expect(
      isInteractiveTarget({
        tagName: "DIV",
        getAttribute: (name: string) => (name === "contenteditable" ? "true" : null),
      }),
    ).toBe(true);
  });

  it("an anchor, input, textarea, and select are all interactive", () => {
    expect(isInteractiveTarget({ tagName: "A" })).toBe(true);
    expect(isInteractiveTarget({ tagName: "INPUT" })).toBe(true);
    expect(isInteractiveTarget({ tagName: "TEXTAREA" })).toBe(true);
    expect(isInteractiveTarget({ tagName: "SELECT" })).toBe(true);
  });

  it("tag matching is case-insensitive (a real Element.tagName is always upper-case, but the check does not assume it)", () => {
    expect(isInteractiveTarget({ tagName: "button" })).toBe(true);
  });

  it("a live DOM isContentEditable=true property is interactive even with no getAttribute", () => {
    expect(isInteractiveTarget({ tagName: "DIV", isContentEditable: true })).toBe(true);
  });

  it("null/undefined target is not interactive", () => {
    expect(isInteractiveTarget(null)).toBe(false);
    expect(isInteractiveTarget(undefined)).toBe(false);
  });
});

describe("the Gmail-familiar RED/read keys", () => {
  const bare = (key: string) => ({ key, ctrlKey: false, metaKey: false, altKey: false });

  it("Gmail-familiar keys map by KEY VALUE — # trash, ! spam, I (Shift+i) mark read; shifted letters are the value the event carries", () => {
    expect(verbForKey({ key: "#", ctrlKey: false, metaKey: false, altKey: false })).toBe("trash");
    expect(verbForKey({ key: "!", ctrlKey: false, metaKey: false, altKey: false })).toBe("spam");
    expect(verbForKey({ key: "I", ctrlKey: false, metaKey: false, altKey: false })).toBe("mark_read");
    expect(verbForKey({ key: "i", ctrlKey: false, metaKey: false, altKey: false })).toBeNull();
    expect(verbForKey({ key: "#", ctrlKey: true, metaKey: false, altKey: false })).toBeNull();
  });

  it("ctrl (without AltGraph) and meta leave each of the three keys to the OS", () => {
    for (const key of ["#", "!", "I"]) {
      expect(verbForKey({ ...bare(key), ctrlKey: true })).toBeNull();
      expect(verbForKey({ ...bare(key), metaKey: true })).toBeNull();
      expect(verbForKey({ ...bare(key), ctrlKey: true, altKey: true })).toBeNull(); // Ctrl+Alt, no AltGraph
      expect(verbForKey({ ...bare(key), ctrlKey: true, altKey: true, getModifierState: () => false })).toBeNull();
      expect(verbForKey({ ...bare(key), metaKey: true, altKey: true, getModifierState: (m: string) => m === "AltGraph" })).toBeNull();
    }
  });

  it("the unshifted neighbours of the three keys stay unmapped (3, 1, i)", () => {
    expect(verbForKey(bare("3"))).toBeNull();
    expect(verbForKey(bare("1"))).toBeNull();
    expect(verbForKey(bare("i"))).toBeNull();
  });
});

// The three keys are VALUE-keyed, so the value counts however the layout
// produced it: AltGr on FR / ES / IT Windows layouts (the browser reports ctrl+alt, with
// `getModifierState("AltGraph")` true) and Option on a Mac (UK Mac: Option+3 is `#`, alt set).
describe("an AltGr- or Option-produced value is still its key", () => {
  const bare = (key: string) => ({ key, ctrlKey: false, metaKey: false, altKey: false });
  const altGraph = (key: string) => ({ ...bare(key), ctrlKey: true, altKey: true, getModifierState: (m: string) => m === "AltGraph" });
  const option = (key: string) => ({ ...bare(key), altKey: true });

  it.each([["#", "trash"], ["!", "spam"], ["I", "mark_read"]] as const)("AltGraph-produced %s is %s (Windows reports ctrl+alt with AltGraph set)", (key, verb) => {
    expect(verbForKey(altGraph(key))).toBe(verb);
  });

  it.each([["#", "trash"], ["!", "spam"], ["I", "mark_read"]] as const)("Option-produced %s is %s (a Mac layout sets alt only)", (key, verb) => {
    expect(verbForKey(option(key))).toBe(verb);
  });

  it("the letter shortcuts keep the strict rule: any modifier, AltGraph included, leaves them to the OS", () => {
    for (const key of ["j", "k", "e", "s", "x", "u", "z", "r", "Enter"]) {
      expect(verbForKey(bare(key)), key).not.toBeNull();
      expect(verbForKey(option(key)), key).toBeNull();
      expect(verbForKey(altGraph(key)), key).toBeNull();
    }
  });

  it("stated, not fixed: the map is value-keyed, so CapsLock plus a bare i yields I and marks read", () => {
    expect(verbForKey({ ...bare("I"), getModifierState: (m: string) => m === "CapsLock" })).toBe("mark_read");
  });
});
