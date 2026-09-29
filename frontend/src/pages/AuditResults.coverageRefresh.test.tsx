import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { Finding, OwaspCoverageManifest } from "@/lib/types.ts";
import { AuditResults } from "./AuditResults";

/**
 * 0096 follow-up: the backend serves an audit's OWASP coverage with triaged
 * false positives left out, computed when the audit is READ. A triage saved in
 * the findings table therefore changes the coverage only on the next read, so
 * the page re-fetches the audit once a save lands — the card updates without
 * a page reload.
 */

vi.mock("react-router", () => ({
  useParams: () => ({ id: "audit-cov" }),
}));
vi.mock("@/hooks/useAudit.ts", () => ({ useAudit: vi.fn() }));
vi.mock("@/hooks/useAgentStream.ts", () => ({ useAgentStream: vi.fn() }));
vi.mock("@/hooks/useAuditComparison.ts", () => ({ useAuditComparison: () => null }));
vi.mock("@/hooks/useAuditHistory.ts", () => ({ useAuditHistory: () => ({ scans: [], audits: [] }) }));
vi.mock("@/components/results/AgentStream.tsx", () => ({ AgentStream: () => <div /> }));
vi.mock("@/components/results/SeveritySummary.tsx", () => ({ SeveritySummary: () => <div /> }));
vi.mock("@/components/results/FindingsTable.tsx", () => ({
  FindingsTable: ({ onLineageSaved }: { onLineageSaved?: () => void }) => (
    <div data-testid="findings-table">
      {onLineageSaved && (
        <button type="button" data-testid="simulate-save" onClick={() => onLineageSaved()}>
          save
        </button>
      )}
    </div>
  ),
}));

import { useAudit } from "@/hooks/useAudit.ts";
import { useAgentStream } from "@/hooks/useAgentStream.ts";

const mockUseAudit = vi.mocked(useAudit);
const mockUseAgentStream = vi.mocked(useAgentStream);

const FINDING: Finding = {
  agent_type: "cwe",
  severity: "high",
  category: "CWE-798",
  title: "Hardcoded credential",
  description: "",
  recommendation: "",
  file_path: "src/a.ts",
};

const COVERAGE: OwaspCoverageManifest = {
  edition: "2025",
  cwe_stage_status: "completed",
  categories: [
    { id: "A07", name: "Authentication Failures", mapped_count: 36, found_cwes: ["CWE-798"], found_count: 1, status: "found", source_url: "https://owasp.org/a07", false_positive_count: 0 },
  ],
};

function useAuditResult(owaspCoverage: OwaspCoverageManifest | undefined, fetchAudit = vi.fn()) {
  return {
    audit: {
      id: "audit-cov", source_id: "s", types: ["cwe", "owasp"], status: "completed",
      created_at: "2026-09-29T00:00:00Z", completed_at: "2026-09-29T00:01:00Z",
      findings: [FINDING], scores: {}, owasp_coverage: owaspCoverage,
    } as never,
    loading: false,
    error: null,
    createAudit: vi.fn(),
    fetchAudit,
  };
}

const STREAM = {
  lines: [], steps: [], connected: false, done: true, tokenSavings: null, dedupStats: null,
  validationUpdates: {}, owaspCoverage: null, owaspMapping: null, liveFindings: [],
};

describe("AuditResults — coverage refresh after triage (0096 follow-up)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAgentStream.mockReturnValue(STREAM as never);
  });

  it("re-fetches the audit when a finding's status is saved", () => {
    const fetchAudit = vi.fn().mockResolvedValue(null);
    mockUseAudit.mockReturnValue(useAuditResult(COVERAGE, fetchAudit));
    render(<AuditResults />);

    expect(fetchAudit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId("simulate-save"));
    expect(fetchAudit).toHaveBeenCalledTimes(1);
    expect(fetchAudit).toHaveBeenCalledWith("audit-cov");
  });

  it("does not re-fetch an audit that has no coverage card to update", () => {
    mockUseAudit.mockReturnValue(useAuditResult(undefined));
    render(<AuditResults />);
    expect(screen.getByTestId("findings-table")).toBeInTheDocument();
    expect(screen.queryByTestId("simulate-save")).toBeNull();
  });
});
