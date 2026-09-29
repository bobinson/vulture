import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuditComparisonView } from "./AuditComparisonView.tsx";
import type { AuditComparison } from "@/lib/types.ts";

/**
 * Feature 0096: when the previous audit carried pre-0096 OWASP copy rows and
 * the current one labels those findings instead, the backend leaves the copies
 * out of the diff and says how many (`excluded_legacy_copies`). The view says
 * so in one line, so "-N fixed" is not read as N fixes that never happened.
 */

const base: AuditComparison = {
  has_previous: true,
  current_findings_count: 3,
  new_count: 0,
  fixed_count: 0,
  persistent_count: 3,
  changed_count: 0,
  regression_count: 0,
};

describe("AuditComparisonView excluded legacy copies (0096)", () => {
  it("notes how many legacy OWASP copy rows were left out of the comparison", () => {
    render(<AuditComparisonView comparison={{ ...base, excluded_legacy_copies: 4 }} />);
    const note = screen.getByTestId("comparison-excluded-legacy");
    expect(note).toHaveTextContent("comparison.excludedLegacyCopies");
  });

  it.each([
    ["absent", undefined],
    ["zero", 0],
  ])("shows no note when the count is %s", (_name, n) => {
    render(<AuditComparisonView comparison={{ ...base, excluded_legacy_copies: n }} />);
    expect(screen.queryByTestId("comparison-excluded-legacy")).toBeNull();
  });
});
