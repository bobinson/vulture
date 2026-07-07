import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { OwaspCoverage } from "./OwaspCoverage.tsx";
import type { OwaspCoverageManifest } from "@/lib/types.ts";

// NOTE: react-i18next is mocked in src/test/setup.ts, so t(key) returns the
// key. Assertions therefore target literal DATA (edition, names, counts) and
// the label KEYS — matching the convention in TokenSavings.test.tsx.

const manifest: OwaspCoverageManifest = {
  edition: "2021",
  cwe_stage_status: "completed",
  categories: [
    { id: "A03", name: "Injection", mapped_count: 33, found_cwes: ["CWE-89"], found_count: 1, status: "found", source_url: "https://owasp.org/a03" },
    { id: "A01", name: "Broken Access Control", mapped_count: 34, found_cwes: [], found_count: 0, status: "clean-or-undetected", source_url: "https://owasp.org/a01" },
  ],
};

describe("OwaspCoverage", () => {
  it("renders every category, including those with no findings", () => {
    render(<OwaspCoverage manifest={manifest} />);
    expect(screen.getByText(/A03 Injection/)).toBeInTheDocument();
    expect(screen.getByText(/A01 Broken Access Control/)).toBeInTheDocument();
    expect(screen.getByText("1 / 33")).toBeInTheDocument();
    expect(screen.getByText("0 / 34")).toBeInTheDocument();
  });

  it("shows the edition and the coverage label", () => {
    render(<OwaspCoverage manifest={manifest} />);
    expect(screen.getByText("2021")).toBeInTheDocument();
    expect(screen.getByText("results.owaspCoverage")).toBeInTheDocument();
  });

  it("flags a non-completed CWE stage with the status value", () => {
    render(<OwaspCoverage manifest={{ ...manifest, cwe_stage_status: "failed" }} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/failed/);
  });

  it("does not show a warning when the CWE stage completed", () => {
    render(<OwaspCoverage manifest={manifest} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("links each category to its OWASP source page", () => {
    render(<OwaspCoverage manifest={manifest} />);
    const link = screen.getByText(/A03 Injection/).closest("a");
    expect(link).toHaveAttribute("href", "https://owasp.org/a03");
  });
});
