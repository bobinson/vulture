import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
// Feature 0074 (RED) — shared ChipGroup: a legend followed by shared Chips
// (design: frontend/designs/0074-provenance-family.html, `.v-chipgroup`).
// One component serves the provenance filter (interactive) and the finding's
// anchor result (read-only), so the two cannot drift apart in look or markup.
//
// Contract:
//   src/components/shared/ChipGroup.tsx exports `ChipGroup` with props:
//     {
//       legend: string;                 // shown as "<legend>:"; also the group's accessible name
//       items: ReadonlyArray<{ value: string; label: string; tone?: ChipTone; title?: string; testId?: string }>;
//       value?: string;                 // the active item (interactive mode)
//       onChange?: (value: string) => void;   // present => interactive buttons; absent => read-only
//       testId: string;                 // root data-testid; item default `${testId}-${value}`
//     }
//   - root: role="group", aria-label=legend, data-testid=testId
//   - interactive: one Chip button per item, aria-pressed = (item.value === value),
//     a click calls onChange(item.value) exactly once
//   - read-only: no button, no other control; each item keeps its tone
import { ChipGroup } from "../ChipGroup";

const ITEMS = [
  { value: "all", label: "All" },
  { value: "llm_family", label: "LLM (all)" },
  { value: "both", label: "Both tiers" },
  { value: "skill", label: "skill" },
] as const;

describe("ChipGroup (shared, 0074)", () => {
  it("exposes a named group with the legend and one chip per item", () => {
    render(<ChipGroup legend="Provenance" items={ITEMS} value="all" onChange={() => {}} testId="provenance-filter" />);
    const group = screen.getByRole("group", { name: "Provenance" });
    expect(group).toHaveAttribute("data-testid", "provenance-filter");
    expect(within(group).getByText("Provenance:")).toBeInTheDocument();
    expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual([
      "All", "LLM (all)", "Both tiers", "skill",
    ]);
  });

  it("marks only the active item pressed and derives item test ids from the root", () => {
    render(<ChipGroup legend="Provenance" items={ITEMS} value="llm_family" onChange={() => {}} testId="provenance-filter" />);
    expect(screen.getByTestId("provenance-filter-llm_family")).toHaveAttribute("aria-pressed", "true");
    for (const v of ["all", "both", "skill"]) {
      expect(screen.getByTestId(`provenance-filter-${v}`)).toHaveAttribute("aria-pressed", "false");
    }
  });

  it("reports a click as onChange(value), once", () => {
    const onChange = vi.fn();
    render(<ChipGroup legend="Provenance" items={ITEMS} value="all" onChange={onChange} testId="provenance-filter" />);
    fireEvent.click(screen.getByTestId("provenance-filter-both"));
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith("both");
  });

  it("is read-only without onChange: no control, tones and item test ids kept", () => {
    const { container } = render(
      <ChipGroup
        legend="Anchor"
        testId="anchor-result"
        items={[
          { value: "reanchored", label: "Re-anchored", tone: "info", testId: "anchor-status" },
          { value: "past_eof", label: "Past end of file", tone: "warning", testId: "anchor-range" },
        ]}
      />,
    );
    expect(screen.getByRole("group", { name: "Anchor" })).toBeInTheDocument();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(container.querySelectorAll("input, select, textarea, a[href]")).toHaveLength(0);
    expect(screen.getByTestId("anchor-status")).toHaveTextContent("Re-anchored");
    expect(screen.getByTestId("anchor-status")).toHaveAttribute("data-tone", "info");
    expect(screen.getByTestId("anchor-range")).toHaveAttribute("data-tone", "warning");
  });
});
