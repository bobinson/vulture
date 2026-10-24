import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
// Feature 0074 fix round — the findings table with real detection tiers.
//   #46: the provenance filter renders the two tier-family values beside the
//        exact tiers, and they select rows.
//   #35: "Both tiers" on an audit whose findings record no provenance_origins
//        says "not recorded" instead of reading as "never corroborated".
//   #43e: the agent filter is the shared ChipGroup (role=group, pressed state).
// The global test setup stubs `t` to echo the key.
import { FindingsTable } from "./FindingsTable";
import type { Finding } from "@/lib/types";

function row(title: string, overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "high",
    category: "CWE-89",
    title,
    description: `${title} description`,
    file_path: `/src/${title.replace(/\W+/g, "_")}.go`,
    recommendation: "fix",
    agent_type: "cwe",
    ...overrides,
  };
}

const origins = (...tiers: string[]) => ({ provenance_origins: tiers });

const TIERED: Finding[] = [
  row("Skill only", { provenance: "skill", validation: origins("skill") }),
  row("LLM only", { provenance: "llm", validation: origins("llm") }),
  row("L5 verified", { provenance: "llm_l5_verified", validation: origins("llm_l5_verified") }),
  row("Corroborated", { provenance: "skill", validation: origins("skill", "llm") }),
  row("Rollup over one LLM leaf", { provenance: "catalog_rollup", validation: origins("catalog_rollup", "llm") }),
];

const titles = () => new Set(screen.getAllByRole("row").slice(1).map((r) => r.textContent ?? ""));
const shown = (title: string) => [...titles()].some((text) => text.includes(title));

describe("FindingsTable provenance filter with real tiers (0074 #46)", () => {
  it("offers All, the two family values, then every exact tier", () => {
    render(<FindingsTable findings={TIERED} />);
    const group = screen.getByRole("group", { name: "results.provenance" });
    const labels = within(group).getAllByRole("button").map((b) => b.textContent);
    expect(labels).toEqual([
      "results.all",
      "results.provenanceFamily.llm_family",
      "results.provenanceFamily.both",
      "catalog_rollup", "llm", "llm_l5_verified", "skill",
    ]);
    expect(within(group).getByTestId("provenance-filter-all")).toHaveAttribute("aria-pressed", "true");
  });

  it("llm_family keeps every LLM-tier row and only those", () => {
    render(<FindingsTable findings={TIERED} />);
    fireEvent.click(screen.getByTestId("provenance-filter-llm_family"));
    expect(screen.getByTestId("provenance-filter-llm_family")).toHaveAttribute("aria-pressed", "true");
    expect(shown("LLM only")).toBe(true);
    expect(shown("L5 verified")).toBe(true);
    expect(shown("Skill only")).toBe(false);
    expect(shown("Corroborated")).toBe(false);
    expect(shown("Rollup over one LLM leaf")).toBe(false);
  });

  it("both keeps rows whose origins span both families; a rollup is a grouping, not a tier (C11)", () => {
    render(<FindingsTable findings={TIERED} />);
    fireEvent.click(screen.getByTestId("provenance-filter-both"));
    expect(shown("Corroborated")).toBe(true);
    for (const title of ["Skill only", "LLM only", "L5 verified", "Rollup over one LLM leaf"]) {
      expect(shown(title), title).toBe(false);
    }
    expect(screen.queryByTestId("provenance-both-not-recorded")).toBeNull();
  });
});

describe("FindingsTable qualifies an empty Both tiers result (0074 #35)", () => {
  const LEGACY: Finding[] = [
    row("Old skill row", { provenance: "skill" }),
    row("Old LLM row", { provenance: "llm" }),
  ];

  it("says the origins were not recorded when no finding carries them", () => {
    render(<FindingsTable findings={LEGACY} />);
    expect(screen.queryByTestId("provenance-both-not-recorded")).toBeNull();
    fireEvent.click(screen.getByTestId("provenance-filter-both"));
    expect(screen.getByTestId("provenance-both-not-recorded")).toHaveTextContent(
      "results.provenanceFamily.bothNotRecorded",
    );
  });

  it("stays silent on other filter values", () => {
    render(<FindingsTable findings={LEGACY} />);
    fireEvent.click(screen.getByTestId("provenance-filter-llm_family"));
    expect(screen.queryByTestId("provenance-both-not-recorded")).toBeNull();
  });

  it("the API's origins_recorded flag wins over detection", () => {
    const { unmount } = render(<FindingsTable findings={LEGACY} originsRecorded />);
    fireEvent.click(screen.getByTestId("provenance-filter-both"));
    expect(screen.queryByTestId("provenance-both-not-recorded")).toBeNull();
    unmount();
    render(<FindingsTable findings={TIERED} originsRecorded={false} />);
    fireEvent.click(screen.getByTestId("provenance-filter-both"));
    expect(screen.getByTestId("provenance-both-not-recorded")).toBeInTheDocument();
  });
});

describe("FindingsTable agent filter is the shared ChipGroup (0074 #43e)", () => {
  const AGENTS: Finding[] = [
    row("Injection", { agent_type: "cwe" }),
    row("No retry", { agent_type: "chaos" }),
  ];

  it("renders a labelled group of pressed-state buttons that filter rows", () => {
    render(<FindingsTable findings={AGENTS} />);
    const group = screen.getByRole("group", { name: "results.agent" });
    expect(group).toHaveAttribute("data-testid", "agent-filter");
    const chaos = within(group).getByRole("button", { name: "CHAOS" });
    expect(chaos).toHaveAttribute("aria-pressed", "false");
    expect(within(group).getByRole("button", { name: "results.all" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(chaos);
    expect(chaos).toHaveAttribute("aria-pressed", "true");
    expect(shown("No retry")).toBe(true);
    expect(shown("Injection")).toBe(false);
  });
});
