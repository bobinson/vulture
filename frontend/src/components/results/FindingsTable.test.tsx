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
    expect(screen.getByText("db.ts:42")).toBeInTheDocument();
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
});
