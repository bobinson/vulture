import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";

vi.mock("react-router", () => ({
  Link: ({ to, children, ...rest }: { to: string; children: ReactNode }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
}));

import { ScanHistoryRail } from "./ScanHistoryRail";
import type { TargetScan } from "@/lib/types";

// Feature 0091 P5 (RED) — LLD §10.2: "the per-scan results page gains the
// scan-history rail (every scan of the target, whatever path form)". The rail
// is keyed by target, so a sub-path scan and a root scan of the same project
// sit on the same rail and the sub-path is what tells them apart.

const NEWEST: TargetScan = {
  audit_id: "2281d2a2",
  created_at: "2026-09-09T10:37:00Z",
  sub_path: ".vscode",
  git_branch: "main",
  det_count: 16,
  llm_count: 5,
  types: ["cwe"],
};

const MIDDLE: TargetScan = {
  audit_id: "b94cfa15",
  created_at: "2026-09-09T09:48:00Z",
  sub_path: ".vscode",
  git_branch: "main",
  det_count: 0,
  llm_count: 1,
  types: ["cwe"],
};

const OLDEST: TargetScan = {
  audit_id: "7ec46f63",
  created_at: "2026-09-08T20:00:00Z",
  sub_path: "",
  git_branch: "feature/x",
  det_count: 12,
  llm_count: 0,
  types: ["cwe", "owasp"],
};

function entryIds(): string[] {
  return screen
    .getAllByTestId("rail-entry")
    .map((el) => el.getAttribute("data-audit-id") ?? "");
}

/** The rail entry for one audit, addressed the same way the E2E addresses it. */
function entry(auditId: string): HTMLElement {
  const el = screen
    .getAllByTestId("rail-entry")
    .find((e) => e.getAttribute("data-audit-id") === auditId);
  expect(el, `no rail entry for ${auditId}`).toBeDefined();
  return el as HTMLElement;
}

describe("ScanHistoryRail", () => {
  it("renders one entry per scan of the target", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={NEWEST.audit_id} />);
    expect(screen.getAllByTestId("rail-entry")).toHaveLength(3);
  });

  it("orders entries newest first", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={NEWEST.audit_id} />);
    expect(entryIds()).toEqual(["2281d2a2", "b94cfa15", "7ec46f63"]);
  });

  it("orders newest first even when the server order is not sorted", () => {
    render(<ScanHistoryRail scans={[OLDEST, NEWEST, MIDDLE]} currentAuditId={NEWEST.audit_id} />);
    expect(entryIds()).toEqual(["2281d2a2", "b94cfa15", "7ec46f63"]);
  });

  it("marks the current scan and only the current scan", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={MIDDLE.audit_id} />);
    const marked = screen
      .getAllByTestId("rail-entry")
      .filter((el) => el.getAttribute("data-current") === "true");
    expect(marked).toHaveLength(1);
    expect(marked[0]).toHaveAttribute("data-audit-id", "b94cfa15");
  });

  it("marks nothing when the current scan is not one of the target's scans", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId="not-in-list" />);
    const marked = screen
      .getAllByTestId("rail-entry")
      .filter((el) => el.getAttribute("data-current") === "true");
    expect(marked).toHaveLength(0);
  });

  it("shows the sub-path when the scan was scoped to one", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={NEWEST.audit_id} />);
    expect(within(entry("2281d2a2")).getByTestId("rail-subpath")).toHaveTextContent(".vscode");
  });

  it("shows no sub-path element for a root scan", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={NEWEST.audit_id} />);
    expect(within(entry("7ec46f63")).queryByTestId("rail-subpath")).toBeNull();
  });

  it("shows the det and llm counts of each scan", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={NEWEST.audit_id} />);
    const newest = entry("2281d2a2");
    expect(within(newest).getByTestId("rail-det-count")).toHaveTextContent("16");
    expect(within(newest).getByTestId("rail-llm-count")).toHaveTextContent("5");

    // Zero is a real count, not an absent one: a scan with no LLM tier must
    // still say so rather than render nothing.
    const oldest = entry("7ec46f63");
    expect(within(oldest).getByTestId("rail-det-count")).toHaveTextContent("12");
    expect(within(oldest).getByTestId("rail-llm-count")).toHaveTextContent("0");
  });

  it("links each entry to its per-scan results page", () => {
    render(<ScanHistoryRail scans={[NEWEST, MIDDLE, OLDEST]} currentAuditId={NEWEST.audit_id} />);
    expect(within(entry("7ec46f63")).getByTestId("rail-entry-link")).toHaveAttribute(
      "href",
      "/audit/7ec46f63",
    );
  });

  it("renders nothing when the target has no scans", () => {
    const { container } = render(<ScanHistoryRail scans={[]} currentAuditId={NEWEST.audit_id} />);
    expect(container.querySelectorAll("[data-testid='rail-entry']")).toHaveLength(0);
  });
});
