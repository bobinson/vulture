import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
// Feature 0074 — the TS copy of the ONE LLM-family rule, pinned against the
// fixture Go (isLLMProvenance) and Python (is_llm_provenance) are pinned
// against. The fixture's distinguishing rows (skill_llm, semgrep-llm: contain
// "llm" but do not start with it; llmfoo: starts with it without a separator)
// are what catch a prefix rule drifting into a substring or exact rule.
import { isLLMTier, originsRecorded, spansBothTiers } from "./provenance";
import type { Finding } from "./types";

const TESTDATA = resolve(__dirname, "../../../backend/internal/handler/testdata");
const FAMILY = JSON.parse(readFileSync(resolve(TESTDATA, "llm_provenance_family_0074.json"), "utf8")) as {
  provenance: string;
  is_llm: boolean;
}[];

describe("isLLMTier matches the shared family fixture (0074 #7)", () => {
  it("the fixture carries the prefix-vs-substring rows", () => {
    const values = FAMILY.map((c) => c.provenance);
    expect(values).toEqual(expect.arrayContaining(["skill_llm", "semgrep-llm", "llmfoo"]));
  });

  it.each(FAMILY.map((c) => [JSON.stringify(c.provenance), c.provenance, c.is_llm] as const))(
    "provenance %s -> is_llm %s",
    (_name, provenance, isLLM) => {
      expect(isLLMTier(provenance)).toBe(isLLM);
    },
  );

  it.each(FAMILY.map((c) => [JSON.stringify(c.provenance), c.provenance, c.is_llm] as const))(
    "origin %s beside a deterministic origin spans both families iff it is LLM",
    (_name, provenance, isLLM) => {
      // A blank value is no tier at all, so it can never complete a pair.
      expect(spansBothTiers({ provenance_origins: ["signature", provenance] })).toBe(isLLM);
    },
  );
});

describe("grouping provenances are not tiers (0074 #11, C11)", () => {
  it.each([
    [["llm", "catalog_rollup"], false],
    [[" CATALOG_ROLLUP ", "llm_l5_verified"], false],
    [["catalog_rollup", "skill"], false],
    [["catalog_rollup", "skill", "llm"], true],
  ])("origins %j -> both %s", (origins, both) => {
    expect(spansBothTiers({ provenance_origins: origins })).toBe(both);
  });
});

describe("originsRecorded (0074 #35)", () => {
  const row = (validation?: Record<string, unknown>) => ({ validation }) as unknown as Finding;

  it("an explicit API flag wins over detection", () => {
    expect(originsRecorded([row({ provenance_origins: ["skill"] })], false)).toBe(false);
    expect(originsRecorded([], true)).toBe(true);
  });

  it.each([
    ["no findings", [], false],
    ["no validation", [row()], false],
    ["origins absent", [row({ checks: [] })], false],
    ["origins malformed (still recorded, as the backend decides)", [row({ provenance_origins: "skill,llm" })], true],
    ["origins null (the key is there)", [row({ provenance_origins: null })], true],
    ["one row records origins", [row(), row({ provenance_origins: ["llm"] })], true],
  ])("without the flag, detects from the rows: %s", (_name, rows, want) => {
    expect(originsRecorded(rows as Finding[], undefined)).toBe(want);
  });
});
