import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SourceInput } from "./SourceInput";

// Mock FolderBrowser since it depends on API calls
vi.mock("./FolderBrowser.tsx", () => ({
  FolderBrowser: ({ open }: { open: boolean }) =>
    open ? <div data-testid="folder-browser">Browser Open</div> : null,
}));

describe("SourceInput", () => {
  const defaultProps = {
    sourceType: "local" as const,
    onTypeChange: vi.fn(),
    value: "",
    onChange: vi.fn(),
  };

  it("renders source type toggle buttons", () => {
    render(<SourceInput {...defaultProps} />);
    expect(screen.getByTestId("source-type-git")).toBeInTheDocument();
    expect(screen.getByTestId("source-type-local")).toBeInTheDocument();
  });

  it("renders input field", () => {
    render(<SourceInput {...defaultProps} />);
    expect(screen.getByTestId("source-url-input")).toBeInTheDocument();
  });

  it("shows browse button for local source type", () => {
    render(<SourceInput {...defaultProps} sourceType="local" />);
    expect(screen.getByTestId("browse-folder-btn")).toBeInTheDocument();
  });

  it("hides browse button for git source type", () => {
    render(<SourceInput {...defaultProps} sourceType="git" />);
    expect(screen.queryByTestId("browse-folder-btn")).toBeNull();
  });

  it("calls onTypeChange when git button clicked", () => {
    const onTypeChange = vi.fn();
    render(<SourceInput {...defaultProps} onTypeChange={onTypeChange} />);
    fireEvent.click(screen.getByTestId("source-type-git"));
    expect(onTypeChange).toHaveBeenCalledWith("git");
  });

  it("calls onTypeChange when local button clicked", () => {
    const onTypeChange = vi.fn();
    render(<SourceInput {...defaultProps} onTypeChange={onTypeChange} />);
    fireEvent.click(screen.getByTestId("source-type-local"));
    expect(onTypeChange).toHaveBeenCalledWith("local");
  });

  it("calls onChange when input value changes", () => {
    const onChange = vi.fn();
    render(<SourceInput {...defaultProps} onChange={onChange} />);
    fireEvent.change(screen.getByTestId("source-url-input"), {
      target: { value: "/home/user/project" },
    });
    expect(onChange).toHaveBeenCalledWith("/home/user/project");
  });

  it("displays error message when error prop is set", () => {
    render(<SourceInput {...defaultProps} error="Path not found" />);
    expect(screen.getByTestId("source-error")).toHaveTextContent("Path not found");
  });

  it("does not show error when error is null", () => {
    render(<SourceInput {...defaultProps} error={null} />);
    expect(screen.queryByTestId("source-error")).toBeNull();
  });

  it("shows hint when local type and value is empty", () => {
    render(<SourceInput {...defaultProps} sourceType="local" value="" />);
    expect(screen.getByText("browse.hint")).toBeInTheDocument();
  });

  it("hides hint when value is set", () => {
    render(<SourceInput {...defaultProps} sourceType="local" value="/home" />);
    expect(screen.queryByText("browse.hint")).toBeNull();
  });

  it("opens folder browser when browse button clicked", () => {
    render(<SourceInput {...defaultProps} sourceType="local" />);
    expect(screen.queryByTestId("folder-browser")).toBeNull();
    fireEvent.click(screen.getByTestId("browse-folder-btn"));
    expect(screen.getByTestId("folder-browser")).toBeInTheDocument();
  });

  it("renders with pre-filled value", () => {
    render(<SourceInput {...defaultProps} value="/home/user/project" />);
    expect(screen.getByTestId("source-url-input")).toHaveValue("/home/user/project");
  });
});
