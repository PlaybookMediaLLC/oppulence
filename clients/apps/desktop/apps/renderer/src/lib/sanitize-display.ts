// Escape invisible Unicode bidirectional overrides, zero-width & Format (Cf)
// characters, Tag characters, variation selectors, Hangul/Braille fillers,
// line/paragraph separators, and non-printable control characters so untrusted
// tool arguments cannot visually spoof commands, file paths, or MCP configs.
const UNICODE_FORMAT_CHAR_RE = /^\p{Cf}$/u;

function isHiddenOrBidiChar(ch: string, cp: number): boolean {
  if (
    (cp >= 0x0000 && cp <= 0x0008) ||
    (cp >= 0x000b && cp <= 0x001f) ||
    (cp >= 0x007f && cp <= 0x009f) ||
    cp === 0x00ad ||
    cp === 0x034f ||
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x17b4 ||
    cp === 0x17b5 ||
    cp === 0x180e ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x2800 ||
    cp === 0x3164 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    cp === 0xffa0 ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef)
  ) {
    return true;
  }
  return UNICODE_FORMAT_CHAR_RE.test(ch);
}

export type SanitizedDisplay = {
  readonly text: string;
  readonly hasHiddenChars: boolean;
};

export function sanitizeDisplayText(input: string): SanitizedDisplay {
  let hasHiddenChars = false;
  let text = "";
  for (const ch of input) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && isHiddenOrBidiChar(ch, cp)) {
      hasHiddenChars = true;
      const hex = cp.toString(16).toUpperCase().padStart(4, "0");
      text += `[U+${hex}]`;
    } else {
      text += ch;
    }
  }
  return { text, hasHiddenChars };
}
