import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Finding } from "@/lib/types.ts";
import { AuditResults } from "./AuditResults";

/**
 * Feature 0096 (R15): during a live run the rows the page shows come from the
 * stream, and the OWASP agent's streamed mapping labels them before anything
 * is persisted. At terminal status the persisted rows, with the labels the
 * backend stored, replace them.
 */

vi.mock("react-router", () => ({
  useParams: () => ({ id: "audit-live" }),
}));
vi.mock("@/hooks/useAudit.ts", () => ({ useAudit: vi.fn() }));
vi.mock("@/hooks/useAgentStream.ts", () => ({ useAgentStream: vi.fn() }));
vi.mock("@/components/results/AgentStream.tsx", () => ({ AgentStream: () => <div /> }));
vi.mock("@/components/results/AuditTimeline.tsx", () => ({ AuditTimeline: () => <div /> }));
vi.mock("@/components/results/SeveritySummary.tsx", () => ({ SeveritySummary: () => <div /> }));
vi.mock("@/components/results/FindingsTable.tsx", () => ({
  FindingsTable: ({ findings }: { findings: Finding[] }) => (
    <ul data-testid="findings-table">
      {findings.map((f) => (
        <li key={f.title} data-testid="row" data-title={f.title}>
          {(f.compliance_labels ?? []).map((l) => `${l.edition}/${l.category_id}`).join(",")}
        </li>
      ))}
    </ul>
  ),
}));

import { useAudit } from "@/hooks/useAudit.ts";
import { useAgentStream } from "@/hooks/useAgentStream.ts";

const mockUseAudit = vi.mocked(useAudit);
const mockUseAgentStream = vi.mocked(useAgentStream);

const row = (over: Partial<Finding>): Finding => ({
  agent_type: "cwe",
  severity: "high",
  category: "CWE-798",
  title: "t",
  description: "",
  recommendation: "",
  file_path: "src/a.ts",
  ...over,
});

const LIVE = [
  row({ title: "Live credential", category: "CWE-798" }),
  row({ title: "Live regex", category: "CWE-1333", severity: "medium" }),
];

const MAPPING = {
  version: 1 as const,
  framework: "owasp",
  edition: "2025",
  selected: [],
  table: { "CWE-798": [{ id: "A07", name: "Authentication Failures" }] },
};

function audit(status: string, findings: Finding[]) {
  return {
    audit: { id: "audit-live", source_id: "s", types: ["cwe", "owasp"], status, created_at: "2026-09-29T00:00:00Z", findings, scores: {} } as never,
    loading: false,
    error: null,
    createAudit: vi.fn(),
    fetchAudit: vi.fn(),
  };
}

function stream(liveFindings: Finding[], owaspMapping: typeof MAPPING | null) {
  return {
    lines: [{ id: "l1", text: "x", type: "info" as const, timestamp: new Date() }],
    steps: [],
    connected: true,
    done: false,
    tokenSavings: null,
    dedupStats: null,
    validationUpdates: {},
    owaspCoverage: null,
    owaspMapping,
    liveFindings,
  };
}

const labelsOf = (title: string) =>
  screen.getAllByTestId("row").find((el) => el.dataset.title === title)?.textContent;

describe("AuditResults — live OWASP labels (0096 R15)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows the streamed rows of a running audit whose record holds none", () => {
    mockUseAudit.mockReturnValue(audit("running", []));
    mockUseAgentStream.mockReturnValue(stream(LIVE, null) as never);
    render(<AuditResults />);
    expect(screen.getAllByTestId("row")).toHaveLength(2);
    expect(labelsOf("Live credential")).toBe("");
  });

  it("labels the streamed rows from the OWASP agent's streamed mapping before persistence", () => {
    mockUseAudit.mockReturnValue(audit("running", []));
    mockUseAgentStream.mockReturnValue(stream(LIVE, MAPPING) as never);
    render(<AuditResults />);
    expect(labelsOf("Live credential")).toBe("2025/A07");
    expect(labelsOf("Live regex")).toBe("");
  });

  it("at terminal status shows the persisted rows and their stored labels, not the live ones", () => {
    const persisted = [
      row({
        title: "Stored credential",
        compliance_labels: [
          { framework: "owasp", edition: "2021", category_id: "A07", category_name: "Identification", cwe: "CWE-798" },
        ],
      }),
    ];
    mockUseAudit.mockReturnValue(audit("completed", persisted));
    mockUseAgentStream.mockReturnValue(stream(LIVE, MAPPING) as never);
    render(<AuditResults />);
    expect(screen.getAllByTestId("row")).toHaveLength(1);
    expect(labelsOf("Stored credential")).toBe("2021/A07");
  });
});
