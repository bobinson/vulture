import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { FolderBrowser } from "./FolderBrowser";

vi.mock("@/lib/api.ts", () => ({
  api: {
    browseFilesystem: vi.fn(),
  },
}));

import { api } from "@/lib/api.ts";
const mockBrowse = vi.mocked(api.browseFilesystem);

// Mock HTMLDialogElement methods
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = vi.fn();
  HTMLDialogElement.prototype.close = vi.fn();
});

describe("FolderBrowser", () => {
  const mockOnClose = vi.fn();
  const mockOnSelect = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    mockBrowse.mockResolvedValue({
      path: "/home",
      parent: "/",
      entries: [
        { name: "projects", path: "/home/projects", is_dir: true },
        { name: "readme.md", path: "/home/readme.md", is_dir: false },
      ],
    } as never);
  });

  it("returns null when not open", () => {
    const { container } = render(
      <FolderBrowser open={false} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("renders dialog when open", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("browse.title")).toBeInTheDocument();
    });
  });

  it("renders directory entries", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("projects")).toBeInTheDocument();
      expect(screen.getByText("readme.md")).toBeInTheDocument();
    });
  });

  it("shows current path", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText(/browse.selected/)).toBeInTheDocument();
    });
  });

  it("renders select folder button", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("browse.selectFolder")).toBeInTheDocument();
    });
  });

  it("renders cancel button", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("common.cancel")).toBeInTheDocument();
    });
  });

  it("calls onClose when cancel clicked", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("common.cancel")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("common.cancel"));
    expect(mockOnClose).toHaveBeenCalled();
  });

  it("calls onSelect and onClose when select clicked", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("browse.selectFolder")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("browse.selectFolder"));
    expect(mockOnSelect).toHaveBeenCalledWith("/home");
    expect(mockOnClose).toHaveBeenCalled();
  });

  it("navigates into directories on click", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("projects")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText("projects"));
    expect(mockBrowse).toHaveBeenCalledWith("/home/projects");
  });

  it("shows .. for going up", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("..")).toBeInTheDocument();
    });
  });

  it("shows error state on browse failure", async () => {
    mockBrowse.mockRejectedValue(new Error("fail"));
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    await waitFor(() => {
      expect(screen.getByText("browse.loadError")).toBeInTheDocument();
    });
  });

  it("shows loading spinner while browsing", () => {
    mockBrowse.mockReturnValue(new Promise(() => {}) as never);
    const { container } = render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} />,
    );
    expect(container.querySelector(".animate-spin")).not.toBeNull();
  });

  it("uses initialPath", async () => {
    render(
      <FolderBrowser open={true} onClose={mockOnClose} onSelect={mockOnSelect} initialPath="/usr/local" />,
    );
    await waitFor(() => {
      expect(mockBrowse).toHaveBeenCalledWith("/usr/local");
    });
  });
});
