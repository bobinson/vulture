import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Memories } from "./Memories";

vi.mock("@/lib/api.ts", () => ({
  api: {
    searchMemories: vi.fn(),
    getMemoryWithEdges: vi.fn(),
    updateRemediation: vi.fn(),
  },
}));

import { api } from "@/lib/api.ts";
const mockSearchMemories = vi.mocked(api.searchMemories);
const mockGetMemoryWithEdges = vi.mocked(api.getMemoryWithEdges);

const makeMemory = (overrides = {}) => ({
  id: "mem-1",
  audit_id: "a-1",
  agent_type: "owasp",
  codebase_path: "/project",
  finding_type: "vulnerability",
  title: "SQL Injection",
  content: "Input not sanitized",
  severity: "critical",
  compliance_ref: "",
  category: "A03-injection",
  keywords: ["sql", "injection"],
  tags: [],
  file_paths: ["/src/db.ts"],
  remediation_status: "open",
  remediation_notes: "",
  created_at: "2026-01-15T10:00:00Z",
  similarity: 0.95,
  ...overrides,
});

describe("Memories", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchMemories.mockResolvedValue([makeMemory()] as never);
    mockGetMemoryWithEdges.mockResolvedValue({ memory: makeMemory(), edges: [] } as never);
  });

  it("renders subtitle", () => {
    render(<Memories />);
    expect(screen.getByText("memories.subtitle")).toBeInTheDocument();
  });

  it("renders search input", () => {
    render(<Memories />);
    expect(screen.getByPlaceholderText("memories.searchPlaceholder")).toBeInTheDocument();
  });

  it("renders search button", () => {
    render(<Memories />);
    expect(screen.getByText("memories.search")).toBeInTheDocument();
  });

  it("loads recent memories on mount", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(mockSearchMemories).toHaveBeenCalledWith("", 20);
    });
  });

  it("renders memory cards after loading", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    });
  });

  it("renders severity badge", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("severity.critical")).toBeInTheDocument();
    });
  });

  it("renders agent label", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("OWASP")).toBeInTheDocument();
    });
  });

  it("renders remediation status badge", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getAllByText("memories.status_open").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("shows no results when empty", async () => {
    mockSearchMemories.mockResolvedValue([] as never);
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("memories.noResults")).toBeInTheDocument();
    });
  });

  it("searches on button click", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    });
    fireEvent.change(screen.getByPlaceholderText("memories.searchPlaceholder"), {
      target: { value: "xss" },
    });
    fireEvent.click(screen.getByText("memories.search"));
    expect(mockSearchMemories).toHaveBeenCalledWith("xss", 30);
  });

  it("searches on Enter key", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    });
    const input = screen.getByPlaceholderText("memories.searchPlaceholder");
    fireEvent.change(input, { target: { value: "query" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(mockSearchMemories).toHaveBeenCalledWith("query", 30);
  });

  it("opens detail panel when memory clicked", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("SQL Injection"));
    await waitFor(() => {
      expect(screen.getByText("Input not sanitized")).toBeInTheDocument();
    });
  });

  it("shows similarity bar when present", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("95%")).toBeInTheDocument();
    });
  });

  it("renders file path in memory card", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("/src/db.ts")).toBeInTheDocument();
    });
  });

  it("shows change status button in detail panel", async () => {
    render(<Memories />);
    await waitFor(() => {
      expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("SQL Injection"));
    await waitFor(() => {
      expect(screen.getByText("memories.changeStatus")).toBeInTheDocument();
    });
  });
});
