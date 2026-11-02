import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// Feature 0058 (R9) — "Opengrep tier not active" notice; the engine is
// Opengrep since 0102.
// Contract:
//   src/components/results/OpengrepTierNotice.tsx exports
//   `OpengrepTierNotice` with props { lines: Array<{ text: string }> }
//   (wired from the audit stream lines in AuditResults).
//   - When any line's text contains the phrase "opengrep tier not
//     active" (the R9 orchestrator notice, any case), it renders an
//     informational banner whose root carries
//     data-testid="opengrep-tier-notice" and whose copy comes from the
//     i18n key results.opengrepTierNotice (the test i18n mock returns
//     the raw key).
//   - Otherwise it renders NOTHING, including for the retired plugin's
//     notice in an older audit.
import { OpengrepTierNotice } from "../OpengrepTierNotice";
import type { StreamLine } from "@/lib/types";

function line(text: string): StreamLine {
  return { id: `l-${text}`, text, type: "info", timestamp: new Date() };
}

describe("OpengrepTierNotice", () => {
  it("renders the banner when the stream contains the R9 notice", () => {
    render(
      <OpengrepTierNotice
        lines={[
          line("Agent started: cwe"),
          line("Opengrep tier not active — running skills + signatures only"),
        ]}
      />,
    );
    const notice = screen.getByTestId("opengrep-tier-notice");
    expect(notice).toBeInTheDocument();
    expect(notice.textContent).toContain("results.opengrepTierNotice");
  });

  it("renders the banner for the backend's lowercase notice", () => {
    render(
      <OpengrepTierNotice
        lines={[line("opengrep tier not active (agent unavailable); continuing with the remaining agents")]}
      />,
    );
    expect(screen.getByTestId("opengrep-tier-notice").textContent).toContain("results.opengrepTierNotice");
  });

  it("renders nothing for another agent's notice", () => {
    const { container } = render(
      <OpengrepTierNotice
        lines={[
          line("semgrep tier not active (agent unavailable); continuing with the remaining agents"),
          line("owasp tier not active (agent unavailable); continuing with the remaining agents"),
        ]}
      />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when no line mentions the opengrep tier", () => {
    const { container } = render(
      <OpengrepTierNotice lines={[line("Agent started: cwe"), line("Audit completed")]} />,
    );
    expect(container.firstChild).toBeNull();
    expect(screen.queryByTestId("opengrep-tier-notice")).toBeNull();
  });

  it("renders nothing for an empty stream", () => {
    const { container } = render(<OpengrepTierNotice lines={[]} />);
    expect(container.firstChild).toBeNull();
  });
});
