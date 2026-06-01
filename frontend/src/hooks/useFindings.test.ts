import { describe, expect, it } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useFindings } from "./useFindings";
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

const SAMPLE_FINDINGS: Finding[] = [
  makeFinding({ severity: "critical", category: "auth", title: "SQL Injection", file_path: "/src/db.ts" }),
  makeFinding({ severity: "high", category: "crypto", title: "Weak Hash", file_path: "/src/hash.ts" }),
  makeFinding({ severity: "medium", category: "config", title: "Debug Mode", file_path: "/src/app.ts" }),
  makeFinding({ severity: "low", category: "auth", title: "Verbose Error", file_path: "/src/error.ts" }),
  makeFinding({ severity: "info", category: "docs", title: "Missing Docs", file_path: "/src/api.ts" }),
  makeFinding({ severity: "critical", category: "injection", title: "XSS", file_path: "/src/render.ts", agent_id: "owasp" }),
  makeFinding({ severity: "high", category: "retry", title: "No Retry", file_path: "/src/client.ts", agent_id: "chaos" }),
];

describe("useFindings", () => {
  it("returns first page of findings sorted by severity ascending by default", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    expect(result.current.sortField).toBe("severity");
    expect(result.current.sortDirection).toBe("asc");
    // Critical items first
    expect(result.current.findings[0].severity).toBe("critical");
    expect(result.current.findings[1].severity).toBe("critical");
  });

  it("reports totalFiltered count matching all findings when no filter", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    expect(result.current.totalFiltered).toBe(7);
  });

  it("filters by severity", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => result.current.setFilterSeverity("critical"));
    expect(result.current.totalFiltered).toBe(2);
    expect(result.current.findings.every((f) => f.severity === "critical")).toBe(true);
  });

  it("filters by agent", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => result.current.setFilterAgent("owasp"));
    expect(result.current.totalFiltered).toBe(1);
    expect(result.current.findings[0].title).toBe("XSS");
  });

  it("combines severity and agent filters", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => {
      result.current.setFilterSeverity("high");
      result.current.setFilterAgent("chaos");
    });
    expect(result.current.totalFiltered).toBe(1);
    expect(result.current.findings[0].title).toBe("No Retry");
  });

  it("resets to all when filter set back to 'all'", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => result.current.setFilterSeverity("critical"));
    expect(result.current.totalFiltered).toBe(2);
    act(() => result.current.setFilterSeverity("all"));
    expect(result.current.totalFiltered).toBe(7);
  });

  it("sorts by category ascending", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => result.current.toggleSort("category"));
    expect(result.current.sortField).toBe("category");
    expect(result.current.sortDirection).toBe("asc");
    const categories = result.current.findings.map((f) => f.category);
    const sorted = [...categories].sort((a, b) => a.localeCompare(b));
    expect(categories).toEqual(sorted);
  });

  it("toggles sort direction on same field", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => result.current.toggleSort("title"));
    expect(result.current.sortDirection).toBe("asc");
    act(() => result.current.toggleSort("title"));
    expect(result.current.sortDirection).toBe("desc");
  });

  it("sorts by file path", () => {
    const { result } = renderHook(() => useFindings(SAMPLE_FINDINGS));
    act(() => result.current.toggleSort("file"));
    const paths = result.current.findings.map((f) => f.file_path);
    const sorted = [...paths].sort((a, b) => a.localeCompare(b));
    expect(paths).toEqual(sorted);
  });

  it("resets page to 0 when filter changes", () => {
    // Generate 30 findings to have multiple pages
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}`, severity: i < 15 ? "critical" : "low" }),
    );
    const { result } = renderHook(() => useFindings(many));
    act(() => result.current.setPage(1));
    expect(result.current.page).toBe(1);
    act(() => result.current.setFilterSeverity("critical"));
    expect(result.current.page).toBe(0);
  });

  it("paginates at 25 items per page", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}` }),
    );
    const { result } = renderHook(() => useFindings(many));
    expect(result.current.findings.length).toBe(25);
    expect(result.current.totalPages).toBe(2);
    act(() => result.current.setPage(1));
    expect(result.current.findings.length).toBe(5);
  });

  it("clamps page to last valid page", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}` }),
    );
    const { result } = renderHook(() => useFindings(many));
    act(() => result.current.setPage(99));
    expect(result.current.page).toBe(1);
  });

  it("handles empty findings array", () => {
    const { result } = renderHook(() => useFindings([]));
    expect(result.current.findings).toEqual([]);
    expect(result.current.totalFiltered).toBe(0);
    expect(result.current.totalPages).toBe(1);
    expect(result.current.page).toBe(0);
  });

  it("resets page when toggling sort", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}` }),
    );
    const { result } = renderHook(() => useFindings(many));
    act(() => result.current.setPage(1));
    act(() => result.current.toggleSort("title"));
    expect(result.current.page).toBe(0);
  });

  it("resets page when agent filter changes", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}` }),
    );
    const { result } = renderHook(() => useFindings(many));
    act(() => result.current.setPage(1));
    act(() => result.current.setFilterAgent("chaos"));
    expect(result.current.page).toBe(0);
  });

  // --- 0045/0036 follow-up: hide false positives ---
  // Two FP signals: validation_status === "likely_fp" (automatic L1-L5
  // verdict) and lineage current_status === "false_positive" (manual
  // triage, passed in as a Set of fingerprints). The toggle defaults
  // OFF (show everything); turning it on drops both.

  const FP_FINDINGS: Finding[] = [
    makeFinding({ title: "Real Critical", severity: "critical", validation_status: "high_confidence" }),
    makeFinding({ title: "Auto FP", severity: "medium", validation_status: "likely_fp" }),
    makeFinding({ title: "Suspicious", severity: "high", validation_status: "suspicious" }),
    makeFinding({ title: "Triaged FP", severity: "low", fingerprint: "fp-triaged", validation_status: "high_confidence" }),
  ];
  const TRIAGED = new Set<string>(["fp-triaged"]);

  it("defaults hideFalsePositives to false (shows everything)", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    expect(result.current.hideFalsePositives).toBe(false);
    expect(result.current.totalFiltered).toBe(4);
  });

  it("hides likely_fp findings when toggled on", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    act(() => result.current.setHideFalsePositives(true));
    const titles = result.current.findings.map((f) => f.title);
    expect(titles).not.toContain("Auto FP");
  });

  it("hides lineage false_positive findings (by fingerprint) when toggled on", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    act(() => result.current.setHideFalsePositives(true));
    const titles = result.current.findings.map((f) => f.title);
    expect(titles).not.toContain("Triaged FP");
  });

  it("keeps non-FP findings when toggled on", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    act(() => result.current.setHideFalsePositives(true));
    const titles = result.current.findings.map((f) => f.title);
    expect(titles).toContain("Real Critical");
    expect(titles).toContain("Suspicious");
    expect(result.current.totalFiltered).toBe(2);
  });

  it("reports falsePositiveCount as the union of both FP signals", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    // 1 likely_fp + 1 triaged = 2, independent of toggle state.
    expect(result.current.falsePositiveCount).toBe(2);
  });

  it("composes the FP filter with the severity filter", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    act(() => {
      result.current.setHideFalsePositives(true);
      result.current.setFilterSeverity("low");
    });
    // "Triaged FP" is the only low-severity finding and it's an FP →
    // hidden → zero results.
    expect(result.current.totalFiltered).toBe(0);
  });

  it("resets page to 0 when the FP toggle changes", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeFinding({ title: `F${i}` }),
    );
    const { result } = renderHook(() => useFindings(many));
    act(() => result.current.setPage(1));
    act(() => result.current.setHideFalsePositives(true));
    expect(result.current.page).toBe(0);
  });

  it("reports validationCounts over the full audit (filter-independent)", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS, TRIAGED));
    // 2 high_confidence (Real Critical + Triaged FP), 1 suspicious, 1 likely_fp
    expect(result.current.validationCounts).toEqual({
      highConfidence: 2,
      suspicious: 1,
      likelyFp: 1,
    });
    // counts stay stable even with an active severity filter
    act(() => result.current.setFilterSeverity("critical"));
    expect(result.current.validationCounts.suspicious).toBe(1);
  });

  it("treats a missing fingerprint set as no lineage FPs", () => {
    const { result } = renderHook(() => useFindings(FP_FINDINGS));
    act(() => result.current.setHideFalsePositives(true));
    // Only the likely_fp drops; the triaged one has no set to match.
    expect(result.current.totalFiltered).toBe(3);
    expect(result.current.falsePositiveCount).toBe(1);
  });
});
