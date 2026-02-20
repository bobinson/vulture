import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { AuditResults } from "./AuditResults";

vi.mock("react-router-dom", () => ({
  useParams: () => ({ id: "audit-123" }),
}));

vi.mock("@/hooks/useAudit.ts", () => ({
  useAudit: vi.fn(),
}));

vi.mock("@/hooks/useAgentStream.ts", () => ({
  useAgentStream: vi.fn(),
}));

vi.mock("@/components/results/AgentStream.tsx", () => ({
  AgentStream: ({ lines, connected, done }: { lines: unknown[]; connected: boolean; done: boolean }) => (
    <div data-testid="agent-stream">
      <span data-testid="line-count">{lines.length}</span>
      <span data-testid="connected">{String(connected)}</span>
      <span data-testid="done">{String(done)}</span>
    </div>
  ),
}));

vi.mock("@/components/results/AuditTimeline.tsx", () => ({
  AuditTimeline: ({ steps }: { steps: unknown[] }) => (
    <div data-testid="audit-timeline">{steps.length} steps</div>
  ),
}));

vi.mock("@/components/results/FindingsTable.tsx", () => ({
  FindingsTable: ({ findings }: { findings: unknown[] }) => (
    <div data-testid="findings-table">{findings.length} findings</div>
  ),
}));

vi.mock("@/components/results/ScoreCard.tsx", () => ({
  ScoreCard: ({ label, score }: { label: string; score: number }) => (
    <div data-testid="score-card">{label}: {score}</div>
  ),
}));

vi.mock("@/components/results/SeveritySummary.tsx", () => ({
  SeveritySummary: () => <div data-testid="severity-summary">Severity</div>,
}));

vi.mock("@/components/results/TokenSavings.tsx", () => ({
  TokenSavings: () => <div data-testid="token-savings">Token Savings</div>,
}));

import { useAudit } from "@/hooks/useAudit.ts";
import { useAgentStream } from "@/hooks/useAgentStream.ts";

const mockUseAudit = vi.mocked(useAudit);
const mockUseAgentStream = vi.mocked(useAgentStream);

describe("AuditResults", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAudit.mockReturnValue({
      audit: null,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    mockUseAgentStream.mockReturnValue({
      lines: [],
      steps: [],
      connected: false,
      done: false,
      tokenSavings: null,
    });
  });

  it("renders running layout when audit is pending", () => {
    render(<AuditResults />);
    expect(screen.getByText("common.pending")).toBeInTheDocument();
  });

  it("renders audit ID", () => {
    render(<AuditResults />);
    expect(screen.getByText("audit-123")).toBeInTheDocument();
  });

  it("renders agent stream", () => {
    render(<AuditResults />);
    expect(screen.getByTestId("agent-stream")).toBeInTheDocument();
  });

  it("renders timeline", () => {
    render(<AuditResults />);
    expect(screen.getByTestId("audit-timeline")).toBeInTheDocument();
  });

  it("shows completed layout with status badge", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        completed_at: "2026-01-15T10:05:00Z",
        findings: [],
        scores: {},
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByText("common.completed")).toBeInTheDocument();
  });

  it("renders findings table when audit has findings", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [{ title: "SQL Injection", severity: "critical" }],
        scores: {},
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByTestId("findings-table")).toBeInTheDocument();
  });

  it("shows no findings message when completed with no findings", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [],
        scores: {},
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByText("results.noFindings")).toBeInTheDocument();
  });

  it("renders score cards when scores available", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [],
        scores: { owasp: 85 },
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByTestId("score-card")).toBeInTheDocument();
  });

  it("renders severity summary when findings exist", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [{ title: "XSS", severity: "high" }],
        scores: {},
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByTestId("severity-summary")).toBeInTheDocument();
  });

  it("shows show output toggle for completed audits", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [],
        scores: {},
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByText("results.showOutput")).toBeInTheDocument();
  });

  it("toggles agent output visibility", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [],
        scores: {},
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    fireEvent.click(screen.getByText("results.showOutput"));
    expect(screen.getByText("results.hideOutput")).toBeInTheDocument();
    expect(screen.getByTestId("agent-stream")).toBeInTheDocument();
  });

  it("renders token savings when available", () => {
    mockUseAgentStream.mockReturnValue({
      lines: [{ id: "l1", text: "test", type: "info", timestamp: new Date() }],
      steps: [],
      connected: true,
      done: false,
      tokenSavings: {
        context_tokens: 50,
        raw_tokens: 150,
        tokens_saved: 100,
        savings_pct: 67,
        prior_findings_used: 5,
        duplicates_removed: 3,
      },
    });
    render(<AuditResults />);
    expect(screen.getByTestId("token-savings")).toBeInTheDocument();
  });

  it("shows source path when available", () => {
    mockUseAudit.mockReturnValue({
      audit: {
        id: "audit-123",
        source_id: "src-1",
        types: ["owasp"],
        status: "completed",
        created_at: "2026-01-15T10:00:00Z",
        findings: [],
        scores: {},
        source_path: "/home/user/project",
      } as never,
      loading: false,
      error: null,
      createAudit: vi.fn(),
      fetchAudit: vi.fn(),
    });
    render(<AuditResults />);
    expect(screen.getByText("/home/user/project")).toBeInTheDocument();
  });
});
