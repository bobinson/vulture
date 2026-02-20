import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AuditTypeSelector } from "./AuditTypeSelector";

const MOCK_AGENTS = [
  { id: "chaos", name: "Chaos Engineering", type: "chaos", description: "Resilience patterns" },
  { id: "owasp", name: "OWASP Security", type: "owasp", description: "Security analysis" },
  { id: "soc2", name: "SOC2 Compliance", type: "soc2", description: "Compliance checks" },
];

vi.mock("@/lib/api.ts", () => ({
  api: {
    getAgents: vi.fn(),
  },
}));

import { api } from "@/lib/api.ts";
const mockGetAgents = vi.mocked(api.getAgents);

beforeEach(() => {
  mockGetAgents.mockReset();
});

describe("AuditTypeSelector", () => {
  it("shows loading state initially", () => {
    mockGetAgents.mockReturnValue(new Promise(() => {})); // never resolves
    render(<AuditTypeSelector selected={[]} onSelectionChange={vi.fn()} />);
    expect(screen.getByText("common.loading")).toBeInTheDocument();
  });

  it("renders agent cards after loading", async () => {
    mockGetAgents.mockResolvedValue(MOCK_AGENTS);
    render(<AuditTypeSelector selected={[]} onSelectionChange={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText("Chaos Engineering")).toBeInTheDocument();
    });
    expect(screen.getByText("OWASP Security")).toBeInTheDocument();
    expect(screen.getByText("SOC2 Compliance")).toBeInTheDocument();
  });

  it("shows no agents message when API returns empty", async () => {
    mockGetAgents.mockResolvedValue([]);
    render(<AuditTypeSelector selected={[]} onSelectionChange={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText("audit.noAgents")).toBeInTheDocument();
    });
  });

  it("shows no agents message on API error", async () => {
    mockGetAgents.mockRejectedValue(new Error("Network error"));
    render(<AuditTypeSelector selected={[]} onSelectionChange={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText("audit.noAgents")).toBeInTheDocument();
    });
  });

  it("calls onSelectionChange with added id when unselected agent clicked", async () => {
    mockGetAgents.mockResolvedValue(MOCK_AGENTS);
    const onChange = vi.fn();
    render(<AuditTypeSelector selected={["chaos"]} onSelectionChange={onChange} />);

    await waitFor(() => {
      expect(screen.getByTestId("agent-checkbox-owasp")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId("agent-checkbox-owasp"));
    expect(onChange).toHaveBeenCalledWith(["chaos", "owasp"]);
  });

  it("calls onSelectionChange with removed id when selected agent clicked", async () => {
    mockGetAgents.mockResolvedValue(MOCK_AGENTS);
    const onChange = vi.fn();
    render(<AuditTypeSelector selected={["chaos", "owasp"]} onSelectionChange={onChange} />);

    await waitFor(() => {
      expect(screen.getByTestId("agent-checkbox-chaos")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId("agent-checkbox-chaos"));
    expect(onChange).toHaveBeenCalledWith(["owasp"]);
  });

  it("renders heading and description", async () => {
    mockGetAgents.mockResolvedValue(MOCK_AGENTS);
    render(<AuditTypeSelector selected={[]} onSelectionChange={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText("audit.auditTypes")).toBeInTheDocument();
    });
    expect(screen.getByText("audit.auditTypesDesc")).toBeInTheDocument();
  });

  it("uses i18n description keys for known agents", async () => {
    mockGetAgents.mockResolvedValue(MOCK_AGENTS);
    render(<AuditTypeSelector selected={[]} onSelectionChange={vi.fn()} />);

    await waitFor(() => {
      // Mock t() returns the key itself, so we should see the i18n keys
      expect(screen.getByText("audit.chaosDesc")).toBeInTheDocument();
      expect(screen.getByText("audit.owaspDesc")).toBeInTheDocument();
      expect(screen.getByText("audit.soc2Desc")).toBeInTheDocument();
    });
  });
});
