import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";

// Same convention as Header.test.tsx / Sidebar.test.tsx — stub the router so
// the component can render links without a surrounding <BrowserRouter>.
vi.mock("react-router", () => ({
  Link: ({ to, children, ...rest }: { to: string; children: ReactNode }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
}));

import { AggregateTable } from "./AggregateTable";
import type { AggregateRow } from "@/lib/types";

// Feature 0091 P5 (RED) — the unique-findings table of the aggregate report
// (LLD §10.1 row contract, §10.2 "every finding ever reported for the target
// is present"). Computed from finding_lineage alone: there is no Finding here,
// only a lineage row.

function makeRow(overrides: Partial<AggregateRow> = {}): AggregateRow {
  return {
    lineage_id: "l-92190",
    ref: "VLT-92190",
    severity: "critical",
    category: "CWE-506",
    title: "VS Code task runs on folderOpen",
    rel_path: ".vscode/tasks.json",
    line_start: 7,
    tier: "llm",
    seen_count: 2,
    scan_count: 5,
    status: "open",
    first_seen_at: "2026-09-09T10:03:00Z",
    last_seen_at: "2026-09-09T10:39:00Z",
    last_event: "confirmed_by_evidence",
    ...overrides,
  };
}

// Renders one row in isolation and returns the status chip's class string, so
// two statuses can be compared without two trees being mounted at once.
function statusClass(status: AggregateRow["status"]): string {
  const { container, unmount } = render(
    <AggregateTable rows={[makeRow({ lineage_id: `l-${status}`, status })]} />,
  );
  const chip = container.querySelector(`[data-testid="lineage-status-${status}"]`);
  expect(chip, `no status chip rendered for ${status}`).not.toBeNull();
  const cls = chip!.className;
  unmount();
  return cls;
}

describe("AggregateTable", () => {
  it("renders one row per lineage row", () => {
    render(
      <AggregateTable
        rows={[makeRow(), makeRow({ lineage_id: "l-90001", ref: "VLT-90001", title: "Hardcoded credential" })]}
      />,
    );
    expect(screen.getAllByTestId("aggregate-row")).toHaveLength(2);
  });

  it("shows the ref, severity, category and rel_path:line of each row", () => {
    render(<AggregateTable rows={[makeRow()]} />);
    const row = screen.getByTestId("aggregate-row");
    expect(within(row).getByText("VLT-92190")).toBeInTheDocument();
    expect(within(row).getByText("severity.critical")).toBeInTheDocument();
    expect(within(row).getByText("CWE-506")).toBeInTheDocument();
    expect(within(row).getByText(/\.vscode\/tasks\.json:7/)).toBeInTheDocument();
  });

  it("links each row to its lineage detail", () => {
    render(<AggregateTable rows={[makeRow()]} />);
    const link = within(screen.getByTestId("aggregate-row")).getByTestId("aggregate-row-link");
    expect(link).toHaveAttribute("href", "/lineage/l-92190");
  });

  // ---- seen-count bar -----------------------------------------------------

  it("renders the seen-count bar as k of N", () => {
    render(<AggregateTable rows={[makeRow({ seen_count: 2, scan_count: 5 })]} />);
    const bar = screen.getByTestId("seen-bar");
    expect(bar).toHaveAttribute("role", "progressbar");
    expect(bar).toHaveAttribute("aria-valuenow", "2");
    expect(bar).toHaveAttribute("aria-valuemin", "0");
    expect(bar).toHaveAttribute("aria-valuemax", "5");
    expect(screen.getByTestId("seen-count-label")).toHaveTextContent("2/5");
  });

  it("renders a full seen-count bar when the finding was in every scan", () => {
    render(<AggregateTable rows={[makeRow({ seen_count: 5, scan_count: 5 })]} />);
    expect(screen.getByTestId("seen-bar")).toHaveAttribute("aria-valuenow", "5");
    expect(screen.getByTestId("seen-count-label")).toHaveTextContent("5/5");
  });

  it("does not divide by zero when the target has no recorded scans", () => {
    render(<AggregateTable rows={[makeRow({ seen_count: 0, scan_count: 0 })]} />);
    const bar = screen.getByTestId("seen-bar");
    expect(bar).toHaveAttribute("aria-valuemax", "0");
    expect(screen.getByTestId("seen-count-label")).toHaveTextContent("0/0");
  });

  // ---- status chips -------------------------------------------------------

  it.each([
    "open",
    "unconfirmed",
    "regression",
    "fixed",
    "resolved",
    "false_positive",
  ] as const)("renders a status chip for %s", (status) => {
    render(<AggregateTable rows={[makeRow({ status })]} />);
    const chip = screen.getByTestId(`lineage-status-${status}`);
    expect(chip).toBeInTheDocument();
    expect(chip).toHaveTextContent(`lineage.status_${status}`);
  });

  it("gives unconfirmed its own chip styling, distinct from every other status", () => {
    const unconfirmed = statusClass("unconfirmed");
    for (const other of ["open", "regression", "fixed", "resolved", "false_positive"] as const) {
      expect(unconfirmed, `unconfirmed must not look like ${other}`).not.toBe(statusClass(other));
    }
  });

  it("separates the closed statuses from the active ones visually", () => {
    expect(statusClass("fixed")).not.toBe(statusClass("open"));
    expect(statusClass("regression")).not.toBe(statusClass("open"));
    expect(statusClass("false_positive")).not.toBe(statusClass("open"));
  });

  // ---- tier chip ----------------------------------------------------------

  it("renders the llm tier chip", () => {
    render(<AggregateTable rows={[makeRow({ tier: "llm" })]} />);
    const chip = screen.getByTestId("tier-chip");
    expect(chip).toHaveAttribute("data-tier", "llm");
    expect(chip).toHaveTextContent("aggregate.tier_llm");
  });

  it("renders the det tier chip", () => {
    render(<AggregateTable rows={[makeRow({ tier: "det" })]} />);
    const chip = screen.getByTestId("tier-chip");
    expect(chip).toHaveAttribute("data-tier", "det");
    expect(chip).toHaveTextContent("aggregate.tier_det");
  });

  // ---- empty state --------------------------------------------------------

  it("shows the empty state and no rows when there is nothing to report", () => {
    render(<AggregateTable rows={[]} />);
    expect(screen.getByTestId("aggregate-empty")).toHaveTextContent("aggregate.noFindings");
    expect(screen.queryAllByTestId("aggregate-row")).toHaveLength(0);
  });

  // ---- layout resilience --------------------------------------------------

  it("keeps a very long title inside its own container instead of widening the table", () => {
    const longTitle =
      "Unrestricted execution of a workspace-supplied build task that shells out to npm install " +
      "and npm start the moment the folder is opened in the editor, with no user confirmation " +
      "and no allowlist, across every workspace the developer opens on this machine";
    render(<AggregateTable rows={[makeRow({ title: longTitle })]} />);

    // The whole title is present — it is not silently dropped.
    const title = screen.getByTestId("aggregate-title");
    expect(title).toHaveTextContent(longTitle);

    // …and it either wraps or clips inside its own cell.
    expect(title.className).toMatch(/break-words|break-all|truncate|line-clamp|whitespace-normal/);

    // The table itself scrolls in its own container rather than the page body.
    expect(screen.getByTestId("aggregate-table-scroll").className).toMatch(/overflow-x-auto/);
  });
});
