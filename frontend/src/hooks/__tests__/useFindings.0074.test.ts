import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
// Feature 0074 (RED) — tier-family values in the provenance filter (plan §5.6,
// P2a T2.1/T2.2, P2b T2.5; AC10, AC39).
//
// Contract (extends the 0058 exact-match filter, which stays as it is):
//   setFilterProvenance("llm_family") keeps exactly the rows whose
//     finding.provenance is "llm" or "llm_l5_verified".
//   setFilterProvenance("both") keeps exactly the rows whose
//     validation.provenance_origins names a deterministic tier AND an LLM tier.
//     The split is O1's: a provenance starting with "llm" is the LLM family,
//     any other non-empty provenance (skill, signature, semgrep) is not.
//   Neither value reads, writes or reorders validation_status /
//   validation_confidence / validation (AC10, AC11), and both are one
//   constant-time test per row (O(1) per row, linear overall).
import { useFindings } from "../useFindings";
import type { Finding } from "@/lib/types";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "medium",
    category: "security",
    title: "Test finding",
    description: "A test finding",
    file_path: "/src/main.ts",
    recommendation: "Fix it",
    ...overrides,
  };
}

function row(title: string, provenance: string | undefined, origins?: unknown): Finding {
  const validation = origins === undefined ? undefined : { provenance_origins: origins };
  return makeFinding({ title, provenance, validation });
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.values(value as Record<string, unknown>).forEach(deepFreeze);
  return Object.freeze(value);
}

const ROWS: Finding[] = deepFreeze([
  row("skill only", "skill", ["skill"]),
  row("llm only", "llm", ["llm"]),
  row("l5 only", "llm_l5_verified", ["llm_l5_verified"]),
  row("skill won merge", "skill", ["skill", "llm"]),
  row("llm won merge", "llm", ["llm", "skill"]),
  row("l5 merged with signature", "llm_l5_verified", ["signature", "llm_l5_verified"]),
  row("semgrep merged with llm", "semgrep", ["semgrep", "llm"]),
  row("same-agent llm pair", "llm", ["llm", "llm_l5_verified"]),
  row("two deterministic tiers", "skill", ["skill", "signature"]),
  row("llm, no origins recorded", "llm"),
  row("untagged legacy row", undefined),
  row("empty tier is not a tier", "llm", ["", "llm"]),
  row("origins malformed (string)", "skill", "skill,llm"),
  row("origins malformed (null)", "llm", null),
]);

const titles = (fs: Finding[]) => fs.map((f) => f.title).sort();

function filtered(findings: Finding[], value: string) {
  const { result } = renderHook(() => useFindings(findings));
  act(() => result.current.setFilterProvenance(value));
  return result.current;
}

describe("useFindings llm_family filter (0074 AC39, T2.1)", () => {
  it("keeps exactly the llm and llm_l5_verified rows", () => {
    const r = filtered(ROWS, "llm_family");
    expect(r.filterProvenance).toBe("llm_family");
    expect(titles(r.filteredFindings)).toEqual(
      titles(ROWS.filter((f) => f.provenance === "llm" || f.provenance === "llm_l5_verified")),
    );
    expect(r.totalFiltered).toBe(8);
  });

  it("excludes untagged and deterministic rows even when their origins include an LLM tier", () => {
    const r = filtered(ROWS, "llm_family");
    const kept = new Set(titles(r.filteredFindings));
    expect(kept.size).toBe(8);
    expect(kept.has("untagged legacy row")).toBe(false);
    expect(kept.has("skill won merge")).toBe(false);
    expect(kept.has("semgrep merged with llm")).toBe(false);
  });

  it("composes with the severity filter and the hide-false-positives toggle", () => {
    const rows = deepFreeze([
      makeFinding({ title: "llm crit", provenance: "llm", severity: "critical" }),
      makeFinding({ title: "l5 crit fp", provenance: "llm_l5_verified", severity: "critical", validation_status: "likely_fp" }),
      makeFinding({ title: "l5 high", provenance: "llm_l5_verified", severity: "high" }),
      makeFinding({ title: "skill crit", provenance: "skill", severity: "critical" }),
    ]);
    const { result } = renderHook(() => useFindings(rows));
    act(() => {
      result.current.setFilterProvenance("llm_family");
      result.current.setFilterSeverity("critical");
    });
    expect(titles(result.current.filteredFindings)).toEqual(["l5 crit fp", "llm crit"]);
    act(() => result.current.setHideFalsePositives(true));
    expect(titles(result.current.filteredFindings)).toEqual(["llm crit"]);
  });

  it("regression pin (0058): the exact 'llm' value still excludes llm_l5_verified", () => {
    const r = filtered(ROWS, "llm");
    expect(r.filteredFindings.every((f) => f.provenance === "llm")).toBe(true);
    expect(r.totalFiltered).toBe(6);
  });
});

describe("useFindings both filter (0074 AC39, T2.5)", () => {
  it("keeps exactly the rows whose provenance_origins spans a deterministic and an LLM tier", () => {
    const r = filtered(ROWS, "both");
    expect(r.filterProvenance).toBe("both");
    expect(titles(r.filteredFindings)).toEqual(
      ["l5 merged with signature", "llm won merge", "semgrep merged with llm", "skill won merge"].sort(),
    );
  });

  it("is decided by provenance_origins, not by the winning row's provenance", () => {
    const r = filtered(ROWS, "both");
    const kept = new Set(titles(r.filteredFindings));
    // Winner is deterministic in one, LLM in the other: both are in.
    expect(kept.has("skill won merge")).toBe(true);
    expect(kept.has("llm won merge")).toBe(true);
    // Two tiers of one family are not "both".
    expect(kept.has("same-agent llm pair")).toBe(false);
    expect(kept.has("two deterministic tiers")).toBe(false);
  });

  it("treats missing, empty or malformed origins as not-both without throwing", () => {
    const r = filtered(ROWS, "both");
    const kept = new Set(titles(r.filteredFindings));
    expect(kept.size).toBe(4);
    for (const t of [
      "llm, no origins recorded",
      "untagged legacy row",
      "empty tier is not a tier",
      "origins malformed (string)",
      "origins malformed (null)",
    ]) {
      expect(kept.has(t), t).toBe(false);
    }
  });
});

describe("tier-family filters never touch the validation axis (0074 AC10, AC11)", () => {
  const VALIDATED: Finding[] = deepFreeze([
    makeFinding({ title: "a", provenance: "llm", validation_status: "suspicious", validation_confidence: 0.41,
      validation: { provenance_origins: ["llm", "skill"], checks: [{ id: "anchor", result: "exact", weight: 0 }] } }),
    makeFinding({ title: "b", provenance: "llm_l5_verified", validation_status: "likely_fp", validation_confidence: 0.1,
      validation: { provenance_origins: ["llm_l5_verified"] } }),
    makeFinding({ title: "c", provenance: "skill", validation_status: "high_confidence", validation_confidence: 0.9,
      validation: { provenance_origins: ["skill", "llm"] } }),
  ]);

  it.each(["llm_family", "both"])("returns the input rows themselves, unmodified, under %s", (value) => {
    const before = JSON.stringify(VALIDATED);
    const r = filtered(VALIDATED, value);
    expect(r.totalFiltered).toBeGreaterThan(0);
    for (const f of r.filteredFindings) {
      expect(VALIDATED).toContain(f); // identity: no clone, no relabel
    }
    expect(JSON.stringify(VALIDATED)).toBe(before);
  });

  it.each(["llm_family", "both"])("leaves the per-audit validation counts unchanged under %s", (value) => {
    const { result } = renderHook(() => useFindings(VALIDATED));
    const counts = result.current.validationCounts;
    const fpCount = result.current.falsePositiveCount;
    const suspicious = result.current.suspiciousCount;
    act(() => result.current.setFilterProvenance(value));
    expect(result.current.totalFiltered).toBeGreaterThan(0);
    expect(result.current.validationCounts).toEqual(counts);
    expect(result.current.falsePositiveCount).toBe(fpCount);
    expect(result.current.suspiciousCount).toBe(suspicious);
  });
});

// O(1) per row: every row is tested in constant work, so the number of reads of
// the fields the predicates consult grows linearly with the audit, never with
// N x something. Counted with getters, so the assertion is deterministic.
function countingRows(n: number, counter: { reads: number }): Finding[] {
  const tiers = ["skill", "llm", "llm_l5_verified"];
  return Array.from({ length: n }, (_, i) => {
    const provenance = tiers[i % 3];
    const validation = { provenance_origins: i % 2 ? [provenance, "skill"] : [provenance] };
    const f = makeFinding({ title: `r${i}` });
    Object.defineProperty(f, "provenance", { enumerable: true, get: () => (counter.reads++, provenance) });
    Object.defineProperty(f, "validation", { enumerable: true, get: () => (counter.reads++, validation) });
    return f;
  });
}

function readsToFilter(n: number, value: string): { reads: number; total: number } {
  const counter = { reads: 0 };
  const rows = countingRows(n, counter);
  const { result } = renderHook(() => useFindings(rows));
  counter.reads = 0;
  act(() => result.current.setFilterProvenance(value));
  return { reads: counter.reads, total: result.current.totalFiltered };
}

describe("tier-family filters scale linearly (0074, O(1) per row)", () => {
  it.each([
    ["llm_family", (n: number) => n - Math.ceil(n / 3)],
    ["both", (n: number) => Math.floor(n / 2) - Math.floor((Math.floor(n / 2) + 1) / 3)],
  ] as const)("%s reads a constant number of fields per row", (value, expected) => {
    const small = readsToFilter(1_000, value);
    const large = readsToFilter(10_000, value);
    expect(small.total).toBe(expected(1_000));
    expect(large.total).toBe(expected(10_000));
    expect(large.reads).toBeLessThanOrEqual(4 * 10_000);
    expect(large.reads / Math.max(1, small.reads)).toBeLessThanOrEqual(10.5);
  });
});
