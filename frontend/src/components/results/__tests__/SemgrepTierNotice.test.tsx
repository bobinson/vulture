import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// Feature 0058 (RED) — "Semgrep tier not active" notice (LLD R9).
// Contract:
//   src/components/results/SemgrepTierNotice.tsx exports
//   `SemgrepTierNotice` with props { lines: Array<{ text: string }> }
//   (wired from the audit stream lines in AuditResults).
//   - When any line's text contains the phrase "Semgrep tier not
//     active" (the R9 orchestrator notice), it renders an
//     informational banner whose root carries
//     data-testid="semgrep-tier-notice" and whose copy comes from the
//     i18n key results.semgrepTierNotice (the test i18n mock returns
//     the raw key).
//   - Otherwise it renders NOTHING.
import { SemgrepTierNotice } from "../SemgrepTierNotice";
import type { StreamLine } from "@/lib/types";

function line(text: string): StreamLine {
  return { id: `l-${text}`, text, type: "info", timestamp: new Date() };
}

describe("SemgrepTierNotice", () => {
  it("renders the banner when the stream contains the R9 notice", () => {
    render(
      <SemgrepTierNotice
        lines={[
          line("Agent started: cwe"),
          line("Semgrep tier not active — running skills + signatures only"),
        ]}
      />,
    );
    const notice = screen.getByTestId("semgrep-tier-notice");
    expect(notice).toBeInTheDocument();
    expect(notice.textContent).toContain("results.semgrepTierNotice");
  });

  it("renders nothing when no line mentions the semgrep tier", () => {
    const { container } = render(
      <SemgrepTierNotice lines={[line("Agent started: cwe"), line("Audit completed")]} />,
    );
    expect(container.firstChild).toBeNull();
    expect(screen.queryByTestId("semgrep-tier-notice")).toBeNull();
  });

  it("renders nothing for an empty stream", () => {
    const { container } = render(<SemgrepTierNotice lines={[]} />);
    expect(container.firstChild).toBeNull();
  });
});
