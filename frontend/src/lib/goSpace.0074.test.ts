import { describe, expect, it } from "vitest";
// Feature 0074 (T1) — one trim, the same set in every runtime: Go's
// unicode.IsSpace. String.prototype.trim() differs from it in both
// directions (it strips U+FEFF, which Go keeps, and keeps U+0085, which Go
// strips), so a provenance that Go calls LLM-family must not be judged by it.
import { GO_SPACE, trimGoSpace } from "./goSpace";
import { isLLMTier, spansBothTiers } from "./provenance";

// The code points unicode.IsSpace reports true for, enumerated from Go.
const GO_IS_SPACE = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001,
  0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
];

describe("trimGoSpace matches Go strings.TrimSpace (0074 T1)", () => {
  it("the set is exactly Go's unicode.IsSpace", () => {
    expect(
      [...GO_SPACE].map((c) => c.codePointAt(0)).sort((a, b) => a! - b!),
    ).toEqual(GO_IS_SPACE);
  });

  it.each(
    GO_IS_SPACE.map(
      (cp) =>
        [cp.toString(16).padStart(4, "0"), String.fromCodePoint(cp)] as const,
    ),
  )("strips U+%s from both ends", (_hex, ch) => {
    expect(trimGoSpace(`${ch}${ch}llm${ch}`)).toBe("llm");
  });

  it.each([
    ["feff", "\ufeff"],
    ["001c", "\x1c"],
    ["001d", "\x1d"],
    ["001e", "\x1e"],
    ["001f", "\x1f"],
    ["200b", "\u200b"],
  ])("keeps U+%s, which Go does not call whitespace", (_hex, ch) => {
    expect(trimGoSpace(`${ch}llm${ch}`)).toBe(`${ch}llm${ch}`);
  });

  it("keeps interior whitespace and handles blank input", () => {
    expect(trimGoSpace(" a b ")).toBe("a b");
    expect(trimGoSpace("\u0085\u3000")).toBe("");
    expect(trimGoSpace("")).toBe("");
  });
});

describe("the provenance family rule trims with Go's set (0074 T1)", () => {
  it.each([
    [
      "NEL-wrapped llm is LLM (trim() would keep U+0085)",
      "\u0085llm\u0085",
      true,
    ],
    ["BOM-prefixed llm is not LLM (trim() would strip U+FEFF)", "\ufeffllm", false],
    ["unit-separator-prefixed llm is not LLM", "\x1fllm", false],
    ["ideographic-space-wrapped llm is LLM", "\u3000llm\u3000", true],
  ])("%s", (_name, tier, want) => {
    expect(isLLMTier(tier)).toBe(want);
    expect(spansBothTiers({ provenance_origins: ["skill", tier] })).toBe(want);
  });
});
