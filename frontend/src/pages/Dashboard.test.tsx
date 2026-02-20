import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Dashboard } from "./Dashboard";

vi.mock("react-router-dom", () => ({
  Link: ({ to, children, ...rest }: { to: string; children: React.ReactNode }) => (
    <a href={to} {...rest}>{children}</a>
  ),
  useNavigate: () => vi.fn(),
}));

vi.mock("@/lib/api.ts", () => ({
  api: {
    getStats: vi.fn(),
    listAudits: vi.fn(),
  },
}));

import { api } from "@/lib/api.ts";
const mockGetStats = vi.mocked(api.getStats);
const mockListAudits = vi.mocked(api.listAudits);

const makeAudit = (overrides = {}) => ({
  id: "audit-001",
  source_id: "src-1",
  types: ["owasp"],
  status: "completed",
  created_at: "2026-01-15T10:00:00Z",
  findings_count: 3,
  source_path: "/home/user/project",
  ...overrides,
});

describe("Dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetStats.mockResolvedValue({
      audits_run: 12,
      total_findings: 48,
      critical_issues: 5,
      average_score: 72,
    } as never);
    mockListAudits.mockResolvedValue([makeAudit()] as never);
  });

  it("shows loading spinner initially", () => {
    mockGetStats.mockReturnValue(new Promise(() => {}) as never);
    mockListAudits.mockReturnValue(new Promise(() => {}) as never);
    const { container } = render(<Dashboard />);
    expect(container.querySelector(".animate-spin")).not.toBeNull();
  });

  it("renders subtitle after loading", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("dashboard.subtitle")).toBeInTheDocument();
    });
  });

  it("renders stat cards with values", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("12")).toBeInTheDocument();
      expect(screen.getByText("48")).toBeInTheDocument();
      expect(screen.getByText("5")).toBeInTheDocument();
      expect(screen.getByText("72%")).toBeInTheDocument();
    });
  });

  it("shows new audit button", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("dashboard.newAudit")).toBeInTheDocument();
    });
  });

  it("renders audit rows with type labels", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      // "Owasp" appears in both type filter button and audit row
      expect(screen.getAllByText("Owasp").length).toBeGreaterThanOrEqual(2);
    });
  });

  it("renders findings count badge", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("3")).toBeInTheDocument();
    });
  });

  it("renders source folder name", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("project")).toBeInTheDocument();
    });
  });

  it("shows no audits message when empty", async () => {
    mockListAudits.mockResolvedValue([] as never);
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("dashboard.noAudits")).toBeInTheDocument();
    });
  });

  it("shows error state when fetch fails", async () => {
    mockListAudits.mockRejectedValue(new Error("fail"));
    mockGetStats.mockRejectedValue(new Error("fail"));
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText("errors.fetchFailed")).toBeInTheDocument();
    });
  });

  it("renders status filter buttons", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getAllByText("results.all").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("common.completed")).toBeInTheDocument();
      expect(screen.getByText("common.running")).toBeInTheDocument();
    });
  });

  it("filters audits by status", async () => {
    mockListAudits.mockResolvedValue([
      makeAudit({ id: "a1", status: "completed" }),
      makeAudit({ id: "a2", status: "running", types: ["chaos"] }),
    ] as never);
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getAllByText("Owasp").length).toBeGreaterThanOrEqual(2);
    });
    fireEvent.click(screen.getByText("common.running"));
    // After filtering to running, Owasp audit row disappears (only filter button remains)
    expect(screen.getAllByText("Owasp").length).toBe(1); // just filter button
    expect(screen.getAllByText("Chaos").length).toBeGreaterThanOrEqual(2); // filter + row
  });

  it("filters audits by search text", async () => {
    mockListAudits.mockResolvedValue([
      makeAudit({ id: "abc-123" }),
      makeAudit({ id: "xyz-789", types: ["soc2"] }),
    ] as never);
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getAllByText("Owasp").length).toBeGreaterThanOrEqual(2);
    });
    fireEvent.change(screen.getByPlaceholderText("dashboard.searchPlaceholder"), {
      target: { value: "xyz" },
    });
    // After search, Owasp audit row gone (only filter button remains)
    expect(screen.getAllByText("Owasp").length).toBe(1);
    expect(screen.getAllByText("Soc2").length).toBeGreaterThanOrEqual(2);
  });

  it("shows load more button when more than 10 audits", async () => {
    const audits = Array.from({ length: 15 }, (_, i) =>
      makeAudit({ id: `audit-${i}` }),
    );
    mockListAudits.mockResolvedValue(audits as never);
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/dashboard.loadMore/)).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText(/dashboard.loadMore/));
  });

  it("shows no matches message when filter has no results", async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getAllByText("Owasp").length).toBeGreaterThanOrEqual(2);
    });
    fireEvent.change(screen.getByPlaceholderText("dashboard.searchPlaceholder"), {
      target: { value: "nonexistent" },
    });
    expect(screen.getByText("dashboard.noMatches")).toBeInTheDocument();
  });
});
