import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// Feature 0058 (RED) — provenance chip on findings (LLD R6).
// Contract:
//   src/components/results/ProvenanceChip.tsx exports `ProvenanceChip`
//   with props { provenance?: string } (wired from finding.provenance).
//   - Non-empty provenance (e.g. "semgrep") → renders a chip (thin
//     wrapper over the shared Chip) whose root carries
//     data-testid="provenance-chip" and shows the provenance value.
//   - Empty string or undefined provenance → renders NOTHING.
import { ProvenanceChip } from "../ProvenanceChip";

describe("ProvenanceChip", () => {
  it("renders a chip labeled with the provenance value", () => {
    render(<ProvenanceChip provenance="semgrep" />);
    const chip = screen.getByTestId("provenance-chip");
    expect(chip).toBeInTheDocument();
    expect(chip.textContent).toContain("semgrep");
  });

  it("renders any provenance tier generically (not semgrep-hardcoded)", () => {
    render(<ProvenanceChip provenance="signature" />);
    expect(screen.getByTestId("provenance-chip").textContent).toContain("signature");
  });

  it("renders nothing when provenance is undefined", () => {
    const { container } = render(<ProvenanceChip />);
    expect(container.firstChild).toBeNull();
    expect(screen.queryByTestId("provenance-chip")).toBeNull();
  });

  it("renders nothing when provenance is an empty string", () => {
    const { container } = render(<ProvenanceChip provenance="" />);
    expect(container.firstChild).toBeNull();
  });
});
