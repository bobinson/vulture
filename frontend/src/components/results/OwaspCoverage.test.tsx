import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

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

  describe("categories the audit did not select (0096)", () => {
    // The backend marks each category outside an audit's `categories` subset
    // with `selected: false`; it found nothing there by choice, not because
    // the category is clean.
    const subset: OwaspCoverageManifest = {
      edition: "2025",
      cwe_stage_status: "completed",
      categories: [
        { id: "A05", name: "Injection", mapped_count: 37, found_cwes: [], found_count: 0, status: "clean-or-undetected", source_url: "https://owasp.org/a05", selected: false },
        { id: "A07", name: "Authentication Failures", mapped_count: 36, found_cwes: ["CWE-798"], found_count: 1, status: "found", source_url: "https://owasp.org/a07" },
        { id: "A01", name: "Broken Access Control", mapped_count: 40, found_cwes: [], found_count: 0, status: "clean-or-undetected", source_url: "https://owasp.org/a01" },
      ],
    };

    it("says an unselected category was not selected instead of showing it clean", () => {
      render(<OwaspCoverage manifest={subset} />);
      const a05 = screen.getByText(/A05 Injection/).closest("li");
      expect(a05).toHaveTextContent("results.owaspNotSelected");
      expect(a05).not.toHaveTextContent("0 / 37");
      // A selected category with nothing found still reads as a checked zero.
      expect(screen.getByText("0 / 40")).toBeInTheDocument();
      expect(screen.getByText("1 / 36")).toBeInTheDocument();
    });

    it("counts only the selected categories in the header", () => {
      render(<OwaspCoverage manifest={subset} />);
      expect(screen.getByText("1/2")).toBeInTheDocument();
      expect(screen.queryByText("1/3")).toBeNull();
    });

    it("never makes an unselected category a filter button", () => {
      render(
        <OwaspCoverage manifest={subset} selectableIds={new Set(["A05", "A07"])} onSelectCategory={vi.fn()} />,
      );
      expect(screen.queryByTestId("owasp-coverage-category-A05")).toBeNull();
      expect(screen.getByTestId("owasp-coverage-category-A07")).toBeInTheDocument();
    });
  });

  describe("category filter buttons (0096)", () => {
    it("makes a category a filter button only when findings carry it", () => {
      const onSelect = vi.fn();
      render(
        <OwaspCoverage manifest={manifest} selectableIds={new Set(["A03"])} onSelectCategory={onSelect} />,
      );
      const a03 = screen.getByTestId("owasp-coverage-category-A03");
      expect(a03.tagName).toBe("BUTTON");
      expect(a03).toHaveAttribute("aria-pressed", "false");
      expect(screen.queryByTestId("owasp-coverage-category-A01")).toBeNull();
      // The OWASP source page stays one click away.
      expect(screen.getAllByRole("link").map((a) => a.getAttribute("href"))).toContain("https://owasp.org/a03");
      fireEvent.click(a03);
      expect(onSelect).toHaveBeenCalledWith("A03");
    });

    it("marks the selected category and toggles it off on a second click", () => {
      const onSelect = vi.fn();
      render(
        <OwaspCoverage
          manifest={manifest}
          selectableIds={new Set(["A03"])}
          selectedCategory="A03"
          onSelectCategory={onSelect}
        />,
      );
      const a03 = screen.getByTestId("owasp-coverage-category-A03");
      expect(a03).toHaveAttribute("aria-pressed", "true");
      fireEvent.click(a03);
      expect(onSelect).toHaveBeenCalledWith("all");
    });
  });
});
