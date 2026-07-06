import { describe, expect, it } from "vitest";
import { renderHook, act } from "@testing-library/react";
// Feature 0058 (RED) — findings filtering by provenance (LLD R6).
// Contract (mirrors the existing filterAgent mechanics):
//   useFindings gains
//     filterProvenance: string            // defaults to "all"
//     setFilterProvenance: (p: string) => void   // resets page to 0
//   Applying a provenance value keeps only findings whose
//   finding.provenance strictly equals that value; "all" resets.
//   The Finding type (src/lib/types.ts) gains `provenance?: string`.
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

const FINDINGS: Finding[] = [
  makeFinding({ title: "Tainted SQL Sink", severity: "critical", provenance: "semgrep" }),
  makeFinding({ title: "Command Injection Flow", severity: "high", provenance: "semgrep" }),
  makeFinding({ title: "Skill Finding", severity: "high", provenance: "skill" }),
  makeFinding({ title: "Untagged Finding", severity: "low" }),
];

describe("useFindings provenance filter (0058)", () => {
  it("defaults filterProvenance to 'all' showing every finding", () => {
    const { result } = renderHook(() => useFindings(FINDINGS));
    expect(result.current.filterProvenance).toBe("all");
    expect(result.current.totalFiltered).toBe(4);
  });

  it("filters visible findings to provenance === 'semgrep'", () => {
    const { result } = renderHook(() => useFindings(FINDINGS));
    act(() => result.current.setFilterProvenance("semgrep"));
    expect(result.current.filterProvenance).toBe("semgrep");
    expect(result.current.totalFiltered).toBe(2);
    expect(result.current.findings.every((f) => f.provenance === "semgrep")).toBe(true);
  });

  it("filters generically by any provenance value, excluding untagged findings", () => {
    const { result } = renderHook(() => useFindings(FINDINGS));
    act(() => result.current.setFilterProvenance("skill"));
    expect(result.current.totalFiltered).toBe(1);
    expect(result.current.findings[0].title).toBe("Skill Finding");
  });

  it("resets to all findings when set back to 'all'", () => {
    const { result } = renderHook(() => useFindings(FINDINGS));
    act(() => result.current.setFilterProvenance("semgrep"));
    expect(result.current.totalFiltered).toBe(2);
    act(() => result.current.setFilterProvenance("all"));
    expect(result.current.totalFiltered).toBe(4);
  });

  it("composes with the severity filter", () => {
    const { result } = renderHook(() => useFindings(FINDINGS));
    act(() => {
      result.current.setFilterProvenance("semgrep");
      result.current.setFilterSeverity("critical");
    });
    expect(result.current.totalFiltered).toBe(1);
    expect(result.current.findings[0].title).toBe("Tainted SQL Sink");
  });

  it("resets page to 0 when the provenance filter changes", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}`, provenance: "semgrep" }),
    );
    const { result } = renderHook(() => useFindings(many));
    act(() => result.current.setPage(1));
    expect(result.current.page).toBe(1);
    act(() => result.current.setFilterProvenance("semgrep"));
    expect(result.current.page).toBe(0);
  });
});
