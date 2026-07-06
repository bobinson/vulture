import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// Feature 0058 (RED) — shared, reusable Chip pill component.
// Contract:
//   src/components/shared/Chip.tsx exports `Chip` with props:
//     {
//       label: string;
//       tone?: "neutral" | "info" | "success" | "warning" | "danger";
//       title?: string;
//       onClick?: () => void;
//       active?: boolean;
//       testId?: string;   // data-testid override, defaults to "chip"
//     }
//   - Renders a compact pill showing `label`.
//   - Root element carries data-testid (default "chip") and
//     data-tone (default "neutral").
//   - `title` is passed through as the HTML title attribute.
//   - Without onClick: NOT interactive (no button role).
//   - With onClick: exposed as role="button", keyboard-focusable
//     (tabIndex === 0), click invokes onClick exactly once, and
//     aria-pressed reflects `active`.
//   - `active` sets data-active="true" for styling hooks.
import { Chip } from "../Chip";

describe("Chip (shared)", () => {
  it("renders the label text", () => {
    render(<Chip label="semgrep" />);
    expect(screen.getByText("semgrep")).toBeInTheDocument();
  });

  it("carries the default data-testid 'chip'", () => {
    render(<Chip label="semgrep" />);
    expect(screen.getByTestId("chip")).toBeInTheDocument();
  });

  it("allows overriding the data-testid via testId prop", () => {
    render(<Chip label="semgrep" testId="provenance-chip" />);
    expect(screen.getByTestId("provenance-chip")).toBeInTheDocument();
  });

  it("defaults tone to neutral via data-tone", () => {
    render(<Chip label="x" />);
    expect(screen.getByTestId("chip").getAttribute("data-tone")).toBe("neutral");
  });

  it("exposes an explicit tone via data-tone", () => {
    render(<Chip label="x" tone="info" />);
    expect(screen.getByTestId("chip").getAttribute("data-tone")).toBe("info");
  });

  it("passes title through as the HTML title attribute", () => {
    render(<Chip label="x" title="Detected by the Semgrep taint tier" />);
    expect(screen.getByTestId("chip").getAttribute("title")).toBe(
      "Detected by the Semgrep taint tier",
    );
  });

  it("is not interactive without onClick", () => {
    render(<Chip label="x" />);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("is a keyboard-focusable button when onClick is given and fires once per click", () => {
    const onClick = vi.fn();
    render(<Chip label="x" onClick={onClick} />);
    const btn = screen.getByRole("button");
    expect(btn.tabIndex).toBe(0);
    fireEvent.click(btn);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("reflects active state via data-active and aria-pressed", () => {
    render(<Chip label="x" onClick={() => {}} active />);
    const btn = screen.getByRole("button");
    expect(btn.getAttribute("data-active")).toBe("true");
    expect(btn.getAttribute("aria-pressed")).toBe("true");
  });

  it("reports aria-pressed=false when clickable but not active", () => {
    render(<Chip label="x" onClick={() => {}} />);
    expect(screen.getByRole("button").getAttribute("aria-pressed")).toBe("false");
  });
});
