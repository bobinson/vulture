import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
// Feature 0074 (RED), AC39 cross-surface parity, AC10.
//
// The findings API (GET /api/audits/{id}?provenance=) and the MCP tool
// vulture_get_findings(provenance=) are pinned against ONE shared fixture,
// backend/internal/handler/testdata/provenance_filter_cases_0074.json. This
// test runs the UI filter over that same file, so `llm_family`, `both`, the
// exact values and an unknown value select the same rows on all three
// surfaces. The fixture includes the edge cases where surfaces could disagree
// (empty or blank tiers, an LLM-only pair, origins as a string, an object,
// null, absent, non-string entries, mixed case). Its `_comment` states the
// family rule.
import { useFindings } from "../useFindings";
import type { Finding } from "@/lib/types";

const FIXTURE = resolve(__dirname, "../../../../backend/internal/handler/testdata/provenance_filter_cases_0074.json");
const CASES = JSON.parse(readFileSync(FIXTURE, "utf8")) as {
  findings: Finding[];
  expect: Record<string, string[]>;
};

type Row = Finding & { fingerprint?: string };
const fingerprints = (fs: Finding[]) => (fs as Row[]).map((f) => f.fingerprint ?? "").sort();

function filtered(value: string) {
  const { result } = renderHook(() => useFindings(CASES.findings));
  act(() => result.current.setFilterProvenance(value));
  return result.current.filteredFindings;
}

describe("provenance filter parity with the API and MCP (0074 AC39)", () => {
  it.each(Object.keys(CASES.expect))("provenance=%s selects the shared fixture's rows", (value) => {
    expect(fingerprints(filtered(value))).toEqual([...CASES.expect[value]].sort());
  });
});

describe("provenance filter keeps each row's validation (0074 AC10)", () => {
  it.each(Object.keys(CASES.expect))("provenance=%s returns the input rows themselves", (value) => {
    const rows = filtered(value);
    expect(rows).toHaveLength(CASES.expect[value].length);
    for (const f of rows) expect(CASES.findings).toContain(f);
  });
});
