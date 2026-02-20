import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuditTimeline } from "./AuditTimeline";
import type { AgentStep } from "@/lib/types";

function makeStep(overrides: Partial<AgentStep> = {}): AgentStep {
  return {
    agent_id: "chaos",
    label: "chaos",
    status: "running",
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe("AuditTimeline", () => {
  it("shows waiting message when no steps", () => {
    render(<AuditTimeline steps={[]} />);
    expect(screen.getByText("results.waitingAgents")).toBeInTheDocument();
  });

  it("renders timeline heading with steps", () => {
    render(<AuditTimeline steps={[makeStep()]} />);
    expect(screen.getByText("results.timeline")).toBeInTheDocument();
  });

  it("renders agent labels", () => {
    const steps = [
      makeStep({ agent_id: "chaos" }),
      makeStep({ agent_id: "owasp" }),
    ];
    render(<AuditTimeline steps={steps} />);
    // agentLabel fallback capitalizes when mock t() returns the key
    expect(screen.getByText("Chaos")).toBeInTheDocument();
    expect(screen.getByText("Owasp")).toBeInTheDocument();
  });

  it("shows status for each step", () => {
    const steps = [
      makeStep({ agent_id: "chaos", status: "complete" }),
      makeStep({ agent_id: "owasp", status: "running" }),
    ];
    render(<AuditTimeline steps={steps} />);
    expect(screen.getByText("common.complete")).toBeInTheDocument();
    expect(screen.getByText("common.running")).toBeInTheDocument();
  });

  it("renders checkmark SVG for complete status", () => {
    const { container } = render(<AuditTimeline steps={[makeStep({ status: "complete" })]} />);
    const svgs = container.querySelectorAll("svg.text-success");
    expect(svgs.length).toBeGreaterThanOrEqual(1);
  });

  it("renders X SVG for failed status", () => {
    const { container } = render(<AuditTimeline steps={[makeStep({ status: "failed" })]} />);
    const svgs = container.querySelectorAll("svg.text-danger");
    expect(svgs.length).toBeGreaterThanOrEqual(1);
  });
});
