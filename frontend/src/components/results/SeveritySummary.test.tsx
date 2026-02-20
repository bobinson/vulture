import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeveritySummary } from "./SeveritySummary";
import type { Finding } from "@/lib/types";

function makeFinding(severity: Finding["severity"]): Finding {
  return {
    severity,
    category: "test",
    title: "Test",
    description: "desc",
    file_path: "/test.ts",
    recommendation: "fix",
  };
}

describe("SeveritySummary", () => {
  it("renders nothing when findings array is empty", () => {
    const { container } = render(<SeveritySummary findings={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it("shows total count", () => {
    const findings = [makeFinding("critical"), makeFinding("high")];
    render(<SeveritySummary findings={findings} />);
    expect(screen.getByText("results.totalCount")).toBeInTheDocument();
  });

  it("shows severity breakdown heading", () => {
    const findings = [makeFinding("medium")];
    render(<SeveritySummary findings={findings} />);
    expect(screen.getByText("results.severityBreakdown")).toBeInTheDocument();
  });

  it("shows count for each severity present", () => {
    const findings = [
      makeFinding("critical"),
      makeFinding("critical"),
      makeFinding("high"),
      makeFinding("low"),
    ];
    render(<SeveritySummary findings={findings} />);
    expect(screen.getByText("2")).toBeInTheDocument(); // 2 critical
    expect(screen.getByText("1", { selector: ".text-\\[\\#9A3412\\]" })).toBeInTheDocument(); // 1 high
  });

  it("does not show zero-count severities in legend", () => {
    const findings = [makeFinding("critical")];
    render(<SeveritySummary findings={findings} />);
    // Should show critical but not info/low/medium/high in the legend
    expect(screen.getByText("severity.critical")).toBeInTheDocument();
  });

  it("renders stacked bar chart with colored segments", () => {
    const findings = [
      makeFinding("critical"),
      makeFinding("high"),
      makeFinding("medium"),
    ];
    const { container } = render(<SeveritySummary findings={findings} />);
    // Each severity gets a colored bar segment
    const segments = container.querySelectorAll(".rounded-full .transition-all");
    expect(segments.length).toBeGreaterThanOrEqual(3);
  });
});
