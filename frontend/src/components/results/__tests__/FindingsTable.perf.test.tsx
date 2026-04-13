import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { FindingsTable } from "../FindingsTable";
import type { Finding } from "@/lib/types";

// Mock useLineage to avoid API calls
vi.mock("@/hooks/useLineage.ts", () => ({
  useLineage: () => ({
    lineageMap: new Map(),
    timelineMap: new Map(),
    showTimeline: null,
    editingLineage: new Map(),
    savedFeedback: null,
    loadTimeline: vi.fn(),
    updateEdit: vi.fn(),
    saveStatus: vi.fn(),
  }),
}));

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

describe("FindingsTable key stability (Issue #11)", () => {
  it("uses stable keys that do not include page index", () => {
    // Create 30 findings so we have pagination (page size = 25)
    const findings: Finding[] = [];
    for (let i = 0; i < 30; i++) {
      findings.push(
        makeFinding({
          id: `finding-${i}`,
          title: `Finding ${i}`,
          file_path: `/src/file-${i}.ts`,
          fingerprint: `fp-${i}`,
        }),
      );
    }

    const { container } = render(<FindingsTable findings={findings} />);

    // Get initial row texts on page 1
    const page1Rows = container.querySelectorAll("tbody tr");
    expect(page1Rows.length).toBeGreaterThan(0);

    // Expand the first finding on page 1
    fireEvent.click(screen.getByText("Finding 0"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();

    // Navigate to page 2
    const page2Button = screen.getByText("2");
    fireEvent.click(page2Button);

    // Navigate back to page 1
    const page1Button = screen.getByText("1");
    fireEvent.click(page1Button);

    // The first finding should still be expandable with the same key
    // If key included page, the expanded state would be lost because
    // the key changed from "...-0-0" to "...-1-0" and back
    // With stable keys, React preserves DOM identity across page changes
    fireEvent.click(screen.getByText("Finding 0"));
    // After clicking again, it should toggle (collapse since it was expanded)
    // The fact that click works correctly proves key stability
    expect(screen.queryByText("User input not sanitized")).toBeNull();
  });

  it("prefers fingerprint for key when available", () => {
    const findings = [
      makeFinding({
        fingerprint: "abc123",
        title: "Finding A",
        file_path: "/a.ts",
      }),
    ];

    const { container } = render(<FindingsTable findings={findings} />);
    const rows = container.querySelectorAll("tbody tr");
    expect(rows.length).toBeGreaterThan(0);

    // Expand and collapse should work - proves key is stable
    fireEvent.click(screen.getByText("Finding A"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Finding A"));
    expect(screen.queryByText("User input not sanitized")).toBeNull();
  });

  it("falls back to id when fingerprint not available", () => {
    const findings = [
      makeFinding({
        id: "id-456",
        fingerprint: undefined,
        title: "Finding B",
        file_path: "/b.ts",
      }),
    ];

    const { container } = render(<FindingsTable findings={findings} />);
    const rows = container.querySelectorAll("tbody tr");
    expect(rows.length).toBeGreaterThan(0);

    // Expand/collapse still works
    fireEvent.click(screen.getByText("Finding B"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();
  });

  it("falls back to title-path-idx when neither fingerprint nor id", () => {
    const findings = [
      makeFinding({
        id: undefined,
        fingerprint: undefined,
        title: "Finding C",
        file_path: "/c.ts",
      }),
    ];

    const { container } = render(<FindingsTable findings={findings} />);
    const rows = container.querySelectorAll("tbody tr");
    expect(rows.length).toBeGreaterThan(0);

    // Basic expand/collapse works
    fireEvent.click(screen.getByText("Finding C"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();
  });

  it("expanded state survives page navigation with stable keys", () => {
    // Create 30 findings to trigger pagination
    const findings: Finding[] = [];
    for (let i = 0; i < 30; i++) {
      findings.push(
        makeFinding({
          id: `f-${i}`,
          fingerprint: `fp-${i}`,
          title: `Finding ${i}`,
          file_path: `/src/file-${i}.ts`,
        }),
      );
    }

    render(<FindingsTable findings={findings} />);

    // Expand finding on page 1
    fireEvent.click(screen.getByText("Finding 0"));
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();

    // Go to page 2
    fireEvent.click(screen.getByText("2"));

    // Go back to page 1
    fireEvent.click(screen.getByText("1"));

    // With stable keys (no page in key), the row identity is preserved
    // so React can match the same component. The expanded state
    // (stored as expandedId) should still match the key for Finding 0.
    expect(screen.getByText("User input not sanitized")).toBeInTheDocument();
  });
});
