import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { isLLMTier } from "./provenance";
// Feature 0074 contract T1: the LLM-family rule is pinned for Go, the agents
// and the MCP server by ONE fixture,
// backend/internal/handler/testdata/llm_provenance_family_0074.json. The UI
// reads the same file instead of a hand-copied list, so a spelling (exotic
// whitespace, U+FEFF, the U+001C-U+001F separators) cannot be LLM-family on
// one surface and deterministic on another.

const FIXTURE = resolve(__dirname, "../../../backend/internal/handler/testdata/llm_provenance_family_0074.json");
const CASES = JSON.parse(readFileSync(FIXTURE, "utf8")) as { provenance: string; is_llm: boolean }[];

describe("isLLMTier follows the shared LLM-family fixture (0074 T1)", () => {
  it("the fixture is not empty", () => {
    expect(CASES.length).toBeGreaterThan(0);
  });
  it.each(CASES.map((c) => [JSON.stringify(c.provenance), c] as const))("%s", (_, c) => {
    expect(isLLMTier(c.provenance)).toBe(c.is_llm);
  });
});
