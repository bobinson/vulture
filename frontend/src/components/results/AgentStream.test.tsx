import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AgentStream } from "./AgentStream";
import type { StreamLine } from "@/lib/types";

function makeLine(overrides: Partial<StreamLine> = {}): StreamLine {
  return {
    id: "l-1",
    text: "Scanning files...",
    type: "info",
    timestamp: new Date("2026-01-15T10:30:00"),
    ...overrides,
  };
}

describe("AgentStream", () => {
  it("renders terminal container", () => {
    render(<AgentStream lines={[]} connected={false} done={false} />);
    expect(screen.getByTestId("agent-stream")).toBeInTheDocument();
  });

  it("shows waiting message when no lines", () => {
    render(<AgentStream lines={[]} connected={false} done={false} />);
    expect(screen.getByText("results.waitingAgents")).toBeInTheDocument();
  });

  it("renders lines when provided", () => {
    const lines = [makeLine({ id: "l-1", text: "Step 1" }), makeLine({ id: "l-2", text: "Step 2" })];
    render(<AgentStream lines={lines} connected={true} done={false} />);
    expect(screen.getByText("Step 1")).toBeInTheDocument();
    expect(screen.getByText("Step 2")).toBeInTheDocument();
  });

  it("shows connected status when connected", () => {
    render(<AgentStream lines={[makeLine()]} connected={true} done={false} />);
    expect(screen.getByText("results.connected")).toBeInTheDocument();
  });

  it("shows connecting status when not connected", () => {
    render(<AgentStream lines={[makeLine()]} connected={false} done={false} />);
    expect(screen.getByText("results.connecting")).toBeInTheDocument();
  });

  it("shows stream complete when done", () => {
    render(<AgentStream lines={[makeLine()]} connected={false} done={true} />);
    expect(screen.getByText("results.streamComplete")).toBeInTheDocument();
  });

  it("renders terminal header text", () => {
    render(<AgentStream lines={[]} connected={false} done={false} />);
    expect(screen.getByText("results.terminal")).toBeInTheDocument();
  });

  it("applies bold to finding lines", () => {
    const lines = [makeLine({ type: "finding", text: "[CRITICAL] SQL Injection" })];
    render(<AgentStream lines={lines} connected={true} done={false} />);
    const el = screen.getByText("[CRITICAL] SQL Injection");
    expect(el.classList.contains("font-medium")).toBe(true);
  });

  it("applies bold to step lines", () => {
    const lines = [makeLine({ type: "step", text: "Agent started: chaos" })];
    render(<AgentStream lines={lines} connected={true} done={false} />);
    const el = screen.getByText("Agent started: chaos");
    expect(el.classList.contains("font-semibold")).toBe(true);
  });
});
