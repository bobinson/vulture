import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AuditNew } from "./AuditNew";

vi.mock("react-router-dom", () => ({
  useNavigate: () => vi.fn(),
}));

vi.mock("@/hooks/useSource.ts", () => ({
  useSource: () => ({
    submitSource: vi.fn().mockResolvedValue({ id: "src-1", type: "local", path: "/test" }),
    loading: false,
    error: null,
  }),
  validateGitUrl: (url: string) => {
    if (!url.trim()) return "URL is required";
    if (!/^https?:\/\/.+\.git$|^git@.+:.+\.git$/.test(url)) return "Invalid Git URL";
    return null;
  },
  validateLocalPath: (path: string) => {
    if (!path.trim()) return "Path is required";
    if (!path.startsWith("/")) return "Must be absolute";
    return null;
  },
}));

vi.mock("@/hooks/useAudit.ts", () => ({
  useAudit: () => ({
    createAudit: vi.fn().mockResolvedValue({ id: "audit-1" }),
    audit: null,
    loading: false,
    error: null,
    fetchAudit: vi.fn(),
  }),
}));

vi.mock("@/lib/api.ts", () => ({
  api: {
    checkCache: vi.fn().mockResolvedValue({ cached: false }),
  },
}));

vi.mock("@/components/audit/SourceInput.tsx", () => ({
  SourceInput: ({ value, onChange, sourceType, onTypeChange, error }: {
    value: string; onChange: (v: string) => void; sourceType: string;
    onTypeChange: (t: "git" | "local") => void; error: string | null;
  }) => (
    <div data-testid="source-input">
      <input
        data-testid="source-value"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        data-testid="switch-type"
        onClick={() => onTypeChange(sourceType === "local" ? "git" : "local")}
      >
        {sourceType}
      </button>
      {error && <span data-testid="source-error">{error}</span>}
    </div>
  ),
}));

vi.mock("@/components/audit/AuditTypeSelector.tsx", () => ({
  AuditTypeSelector: ({ selected, onSelectionChange }: {
    selected: string[]; onSelectionChange: (s: string[]) => void;
  }) => (
    <div data-testid="audit-type-selector">
      <button
        data-testid="select-owasp"
        onClick={() => onSelectionChange([...selected, "owasp"])}
      >
        select owasp
      </button>
      <span data-testid="selected-count">{selected.length}</span>
    </div>
  ),
}));

describe("AuditNew", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders subtitle", () => {
    render(<AuditNew />);
    expect(screen.getByText("audit.subtitle")).toBeInTheDocument();
  });

  it("renders source input", () => {
    render(<AuditNew />);
    expect(screen.getByTestId("source-input")).toBeInTheDocument();
  });

  it("renders audit type selector", () => {
    render(<AuditNew />);
    expect(screen.getByTestId("audit-type-selector")).toBeInTheDocument();
  });

  it("renders submit button", () => {
    render(<AuditNew />);
    expect(screen.getByTestId("audit-submit-button")).toBeInTheDocument();
  });

  it("submit button shows start audit text", () => {
    render(<AuditNew />);
    expect(screen.getByText("audit.startAudit")).toBeInTheDocument();
  });

  it("shows error when no agents selected and empty path", async () => {
    render(<AuditNew />);
    fireEvent.click(screen.getByTestId("audit-submit-button"));
    await waitFor(() => {
      expect(screen.getByTestId("source-error")).toBeInTheDocument();
    });
  });

  it("shows error when agents selected but empty path", async () => {
    render(<AuditNew />);
    fireEvent.click(screen.getByTestId("select-owasp"));
    fireEvent.click(screen.getByTestId("audit-submit-button"));
    await waitFor(() => {
      expect(screen.getByTestId("source-error")).toBeInTheDocument();
    });
  });

  it("updates selected count when agent selected", () => {
    render(<AuditNew />);
    expect(screen.getByTestId("selected-count").textContent).toBe("0");
    fireEvent.click(screen.getByTestId("select-owasp"));
    expect(screen.getByTestId("selected-count").textContent).toBe("1");
  });

  it("can switch source type", () => {
    render(<AuditNew />);
    expect(screen.getByTestId("switch-type").textContent).toBe("local");
    fireEvent.click(screen.getByTestId("switch-type"));
    expect(screen.getByTestId("switch-type").textContent).toBe("git");
  });
});
