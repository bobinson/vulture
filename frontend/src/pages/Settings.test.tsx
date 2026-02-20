import { describe, expect, it, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Settings } from "./Settings";

describe("Settings", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("renders language section", () => {
    render(<Settings />);
    expect(screen.getByText("settings.language")).toBeInTheDocument();
    expect(screen.getByText("English")).toBeInTheDocument();
    expect(screen.getByText("Español")).toBeInTheDocument();
  });

  it("renders model config section", () => {
    render(<Settings />);
    expect(screen.getByText("settings.modelConfig")).toBeInTheDocument();
    expect(screen.getByText("settings.llmModel")).toBeInTheDocument();
    expect(screen.getByText("settings.apiKey")).toBeInTheDocument();
  });

  it("shows model options in select", () => {
    render(<Settings />);
    const options = screen.getAllByRole("option");
    expect(options.length).toBe(3);
    expect(options[0].textContent).toBe("GPT-4o");
    expect(options[1].textContent).toBe("Claude Sonnet");
    expect(options[2].textContent).toBe("Gemini Pro");
  });

  it("saves settings to localStorage on save", () => {
    render(<Settings />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "claude-sonnet" } });
    fireEvent.click(screen.getByText("settings.save"));
    const stored = JSON.parse(localStorage.getItem("vulture_settings") ?? "{}");
    expect(stored.model).toBe("claude-sonnet");
  });

  it("shows saved confirmation after save", () => {
    render(<Settings />);
    expect(screen.queryByText("settings.saved")).toBeNull();
    fireEvent.click(screen.getByText("settings.save"));
    expect(screen.getByText("settings.saved")).toBeInTheDocument();
  });

  it("loads persisted settings on mount", () => {
    localStorage.setItem(
      "vulture_settings",
      JSON.stringify({ model: "gemini-pro", apiKey: "sk-test" }),
    );
    render(<Settings />);
    const select = screen.getByRole("combobox") as HTMLSelectElement;
    expect(select.value).toBe("gemini-pro");
  });

  it("renders language buttons", () => {
    render(<Settings />);
    expect(screen.getByText("English")).toBeInTheDocument();
    expect(screen.getByText("Español")).toBeInTheDocument();
  });

  it("renders save button", () => {
    render(<Settings />);
    expect(screen.getByText("settings.save")).toBeInTheDocument();
  });

  it("renders description text", () => {
    render(<Settings />);
    expect(screen.getByText("settings.languageDesc")).toBeInTheDocument();
    expect(screen.getByText("settings.modelConfigDesc")).toBeInTheDocument();
  });
});
