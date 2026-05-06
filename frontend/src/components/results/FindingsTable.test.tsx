import { describe, expect, it } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { FindingsTable } from "./FindingsTable";
import type { Finding } from "@/lib/types";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "high",
    category: "injection",
    title: "SQL Injection",
    description: "User input not sanitized",
    file_path: "/src/db.ts",
    recommendation: "Use parameterized queries",
    ...overrides,
  };
}

describe("FindingsTable", () => {
  it("shows no findings message when empty", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText("results.noFindings")).toBeInTheDocument();
  });

  it("renders findings table with rows", () => {
    const findings = [makeFinding(), makeFinding({ title: "XSS", severity: "medium" })];
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("XSS")).toBeInTheDocument();
  });

  it("renders severity badge for each finding", () => {
    render(<FindingsTable findings={[makeFinding({ severity: "critical" })]} />);
    // Both filter button and badge have this text, so use getAllByText
    const elements = screen.getAllByText("severity.critical");
    expect(elements.length).toBeGreaterThanOrEqual(2); // filter + badge
  });

  it("renders category badges", () => {
    render(<FindingsTable findings={[makeFinding({ category: "A03-injection" })]} />);
    expect(screen.getByText("A03-injection")).toBeInTheDocument();
  });

  it("shows file name from path", () => {
    render(<FindingsTable findings={[makeFinding({ file_path: "/very/deep/path/db.ts", line_start: 42 })]} />);
    // Path "/very/deep/path/db.ts" is shortened to last 3 segments: "deep/path/db.ts"
    expect(screen.getByText("deep/path/db.ts:42")).toBeInTheDocument();
  });

  it("renders filter buttons for severities", () => {
    render(<FindingsTable findings={[makeFinding()]} />);
    expect(screen.getByText("results.all")).toBeInTheDocument();
    // severity filter buttons exist (may also appear in badges)
    expect(screen.getAllByText("severity.critical").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("severity.high").length).toBeGreaterThanOrEqual(1);
  });

  it("toggles expanded row on click", () => {
    render(<FindingsTable findings={[makeFinding()]} />);
    // Click to expand
    fireEvent.click(screen.getByText("SQL Injection"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();
    expect(screen.getByText("Use parameterized queries")).toBeInTheDocument();
  });

  it("collapses expanded row on second click", () => {
    render(<FindingsTable findings={[makeFinding()]} />);
    fireEvent.click(screen.getByText("SQL Injection"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();
    // Click again to collapse
    fireEvent.click(screen.getByText("SQL Injection"));
    expect(screen.queryByText("Use parameterized queries")).toBeNull();
  });

  it("renders column headers", () => {
    render(<FindingsTable findings={[makeFinding()]} />);
    expect(screen.getByText(/results.severity/)).toBeInTheDocument();
    expect(screen.getByText(/results.category/)).toBeInTheDocument();
    expect(screen.getByText(/results.description/)).toBeInTheDocument();
    expect(screen.getByText(/results.file/)).toBeInTheDocument();
  });

  it("shows findings count", () => {
    render(<FindingsTable findings={[makeFinding(), makeFinding({ title: "XSS" })]} />);
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("filters by agent type via useFindings (no local agentFiltered memo)", () => {
    const findings = [
      makeFinding({ title: "Injection", agent_type: "owasp" }),
      makeFinding({ title: "No Retry", agent_type: "chaos" }),
      makeFinding({ title: "Weak Crypto", agent_type: "owasp" }),
    ];
    render(<FindingsTable findings={findings} />);
    // All 3 findings visible initially
    expect(screen.getByText("Injection")).toBeInTheDocument();
    expect(screen.getByText("No Retry")).toBeInTheDocument();
    expect(screen.getByText("Weak Crypto")).toBeInTheDocument();

    // Click CHAOS agent filter button (filter buttons are <button> elements)
    const chaosButtons = screen.getAllByText("CHAOS");
    const filterButton = chaosButtons.find((el) => el.tagName === "BUTTON");
    fireEvent.click(filterButton!);
    // Only chaos findings should be visible
    expect(screen.getByText("No Retry")).toBeInTheDocument();
    expect(screen.queryByText("Injection")).toBeNull();
    expect(screen.queryByText("Weak Crypto")).toBeNull();
  });

  it("agent filter count reflects filtered results", () => {
    const findings = [
      makeFinding({ title: "A", agent_type: "owasp" }),
      makeFinding({ title: "B", agent_type: "owasp" }),
      makeFinding({ title: "C", agent_type: "chaos" }),
    ];
    render(<FindingsTable findings={findings} />);
    // Click OWASP filter button (filter buttons are <button> elements)
    const owaspButtons = screen.getAllByText("OWASP");
    const filterButton = owaspButtons.find((el) => el.tagName === "BUTTON");
    fireEvent.click(filterButton!);
    // Count badge should show 2 (the owasp findings)
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  // Regression: production audit ec01e021... had 320 findings sharing 62
  // duplicate fingerprints (the formula intentionally collides on
  // title+file+category+agent_type to track lineage across audits).
  // FindingsTable was using fingerprint as the React key first, which
  // caused React to coalesce same-fingerprint rows during reconciliation
  // — clicking the agent filter then rendered the wrong rows because
  // React's diff matched up rows by their (collided) keys, not by data.
  // The fix: use `id` first (always unique per finding row), fingerprint
  // only as a fallback with row-index disambiguation.
  it("filters correctly when findings share fingerprints (regression)", () => {
    // Three OWASP findings on different lines of the same file. The
    // backend generates the same fingerprint for all of them because
    // (title, file, category, agent_type) are identical.
    const sharedFp = "fp-collision-owasp-A02";
    const findings: Finding[] = [
      {
        id: "id-1",
        fingerprint: sharedFp,
        agent_type: "owasp",
        severity: "high",
        category: "A02-crypto-failure",
        title: "Weak cryptographic algorithm",
        description: "MD5 used at line 10",
        file_path: "/src/web/auth.go",
        line_start: 10,
        recommendation: "Use SHA-256",
      },
      {
        id: "id-2",
        fingerprint: sharedFp,
        agent_type: "owasp",
        severity: "high",
        category: "A02-crypto-failure",
        title: "Weak cryptographic algorithm",
        description: "MD5 used at line 50",
        file_path: "/src/web/auth.go",
        line_start: 50,
        recommendation: "Use SHA-256",
      },
      {
        id: "id-3",
        fingerprint: sharedFp,
        agent_type: "owasp",
        severity: "high",
        category: "A02-crypto-failure",
        title: "Weak cryptographic algorithm",
        description: "MD5 used at line 90",
        file_path: "/src/web/auth.go",
        line_start: 90,
        recommendation: "Use SHA-256",
      },
      {
        id: "id-4",
        fingerprint: "fp-cwe-1",
        agent_type: "cwe",
        severity: "medium",
        category: "CWE-89",
        title: "SQL injection",
        description: "Tainted query",
        file_path: "/src/db.go",
        line_start: 5,
        recommendation: "Parameterize",
      },
    ];
    render(<FindingsTable findings={findings} />);

    // Click the OWASP filter — should keep all three OWASP rows even
    // though they share a fingerprint.
    const owaspButtons = screen.getAllByText("OWASP");
    const filterButton = owaspButtons.find((el) => el.tagName === "BUTTON");
    fireEvent.click(filterButton!);

    // All three line numbers must be present (10, 50, 90). The bug
    // collapsed them to a single row.
    expect(screen.getByText("src/web/auth.go:10")).toBeInTheDocument();
    expect(screen.getByText("src/web/auth.go:50")).toBeInTheDocument();
    expect(screen.getByText("src/web/auth.go:90")).toBeInTheDocument();
    // CWE finding should be filtered out.
    expect(screen.queryByText("SQL injection")).toBeNull();
    // Filter count reflects the 3 OWASP rows.
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  // Companion to the above: with no agent filter applied, all rows
  // (even fingerprint-colliding ones) must appear. shortPath needs
  // ≥3 path segments to actually shorten — using "/src/lib/f.go" so
  // the DOM text matches "src/lib/f.go:N".
  it("renders every fingerprint-colliding row in the unfiltered view", () => {
    const sharedFp = "fp-shared";
    const findings: Finding[] = [
      { id: "a", fingerprint: sharedFp, severity: "high", category: "x", title: "T", description: "d1", file_path: "/src/lib/f.go", line_start: 1, recommendation: "r" },
      { id: "b", fingerprint: sharedFp, severity: "high", category: "x", title: "T", description: "d2", file_path: "/src/lib/f.go", line_start: 2, recommendation: "r" },
      { id: "c", fingerprint: sharedFp, severity: "high", category: "x", title: "T", description: "d3", file_path: "/src/lib/f.go", line_start: 3, recommendation: "r" },
    ];
    render(<FindingsTable findings={findings} />);
    // Three distinct line numbers must render — bug collapsed them
    // into a single row by colliding React keys on shared fingerprint.
    expect(screen.getByText("src/lib/f.go:1")).toBeInTheDocument();
    expect(screen.getByText("src/lib/f.go:2")).toBeInTheDocument();
    expect(screen.getByText("src/lib/f.go:3")).toBeInTheDocument();
  });
});
