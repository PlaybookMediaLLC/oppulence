import assert from "node:assert/strict";
import test from "node:test";

import { sanitizeDisplayText } from "../apps/renderer/src/lib/sanitize-display.ts";

test("escapes Unicode Tag characters (U+E0000-U+E007F) and flags hidden content", () => {
  const tagPayload = `ls \u{E0069}\u{E0064}`;
  const result = sanitizeDisplayText(tagPayload);
  assert.equal(result.hasHiddenChars, true);
  assert.ok(result.text.includes("[U+E0069]"));
  assert.ok(result.text.includes("[U+E0064]"));
});

test("escapes CR, bidi overrides, invisible operators, Hangul/Braille blanks, and variation selectors", () => {
  const spoofingChars = [
    "\r",
    "\u034F",
    "\u115F",
    "\u1160",
    "\u180E",
    "\u2028",
    "\u202E",
    "\u2061",
    "\u2066",
    "\u2800",
    "\u3164",
    "\uFE0F",
    "\uFEFF",
    "\uFFA0",
    "\u{E0100}",
  ];
  for (const ch of spoofingChars) {
    const res = sanitizeDisplayText(`safe${ch}text`);
    assert.equal(
      res.hasHiddenChars,
      true,
      `expected hidden char detected for code point U+${ch.codePointAt(0)?.toString(16)}`,
    );
    assert.ok(res.text.includes("[U+"));
  }
});

test("leaves ordinary printable ASCII and newlines unflagged", () => {
  const clean = sanitizeDisplayText("ls -la knowledge/note.md\necho ok");
  assert.equal(clean.hasHiddenChars, false);
  assert.equal(clean.text, "ls -la knowledge/note.md\necho ok");
});
