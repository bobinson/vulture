import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// Feature 0074 (RED) — read-only anchor result in the finding detail (plan
// §5.6 item 2, P2a T2.2; O3 = C). Design: frontend/designs/0074-provenance-family.html S4.
//
// Contract:
//   src/components/shared/AnchorResult.tsx exports `AnchorResult`:
//     props { validation?: Record<string, unknown>,    // Finding["validation"]
//             lineStart?: number }                     // Finding["line_start"]
//   It reads ONLY validation.checks[id === "anchor"]:
//     result                     -> status chip  (data-testid "anchor-status"),
//                                   label t("results.anchor.status.<result>")
//     extras.claimed_line_range  -> range chip   (data-testid "anchor-range"),
//                                   label t("results.anchor.range.<range>");
//                                   one of in_file | past_eof | no_line, else omitted
//     extras.claimed_line (+ extras.delta)
//                                -> line chip    (data-testid "anchor-line"),
//                                   "L<claimed>", or "L<claimed> → L<lineStart>" only when the
//                                   persisted line_start differs from claimed_line (0074 #19:
//                                   a delta alone is not a move; REANCHOR=false and
//                                   VERIFY=observe stamp a delta without moving the line)
//   rendered through the shared ChipGroup (root data-testid "anchor-result",
//   legend t("results.anchor.title")). No anchor check -> renders nothing.
//   Tones: exact success; reanchored info; ambiguous/near_miss/found_elsewhere
//   warning; absent danger; unquoted/unreadable/oversize neutral;
//   range past_eof warning, in_file/no_line neutral.
//   Read-only: it renders no control and never mutates its input.
// The global test setup stubs `t` to echo the key.
import { AnchorResult } from "../AnchorResult";
import { ANCHOR_VOCABULARY } from "@/test/anchorVocabulary";

const STATUS_TONE_CASES: Record<string, string> = {
  exact: "success", reanchored: "info",
  ambiguous: "warning", near_miss: "warning", found_elsewhere: "warning",
  absent: "danger",
  unquoted: "neutral", unreadable: "neutral", oversize: "neutral",
};

function anchorValidation(result: string, extras: Record<string, unknown> = {}) {
  return Object.freeze({
    provenance_origins: ["llm"],
    checks: Object.freeze([
      Object.freeze({ id: "path", result: "ok", weight: 0 }),
      Object.freeze({ id: "anchor", result, weight: 0, reason: `evidence quote: ${result}`, extras: Object.freeze(extras) }),
    ]),
  });
}

describe("AnchorResult (shared, 0074)", () => {
  it("renders the quote verdict, the claimed line range and the moved line side by side", () => {
    render(<AnchorResult lineStart={40} validation={anchorValidation("reanchored", {
      claimed_line: 60, delta: -20, candidates: 1, claimed_line_range: "past_eof",
    })} />);
    expect(screen.getByRole("group", { name: "results.anchor.title" })).toHaveAttribute("data-testid", "anchor-result");
    expect(screen.getByTestId("anchor-status")).toHaveTextContent("results.anchor.status.reanchored");
    expect(screen.getByTestId("anchor-status")).toHaveAttribute("data-tone", "info");
    expect(screen.getByTestId("anchor-range")).toHaveTextContent("results.anchor.range.past_eof");
    expect(screen.getByTestId("anchor-range")).toHaveAttribute("data-tone", "warning");
    expect(screen.getByTestId("anchor-line")).toHaveTextContent("L60 → L40");
  });

  it("shows only the claimed line when the verifier did not move it", () => {
    render(<AnchorResult validation={anchorValidation("exact", { claimed_line: 12, delta: 0, claimed_line_range: "in_file" })} />);
    expect(screen.getByTestId("anchor-line")).toHaveTextContent(/^L12$/);
    expect(screen.getByTestId("anchor-status")).toHaveAttribute("data-tone", "success");
    expect(screen.getByTestId("anchor-range")).toHaveAttribute("data-tone", "neutral");
  });

  it.each([
    ["the line was not moved (REANCHOR=false / VERIFY=observe)", 60, /^L60$/],
    ["the row has no line_start", undefined, /^L60$/],
    ["line_start is not a finite number", Number.NaN, /^L60$/],
    ["the line was moved", 40, /^L60 → L40$/],
    ["the line was moved further than the delta says", 35, /^L60 → L35$/],
  ])("shows the arrow only when the persisted line differs from the claimed one: %s (0074 #19)", (_name, lineStart, label) => {
    render(<AnchorResult lineStart={lineStart} validation={anchorValidation("reanchored", {
      claimed_line: 60, delta: -20, claimed_line_range: "in_file",
    })} />);
    expect(screen.getByTestId("anchor-line")).toHaveTextContent(label);
  });

  it("the tone table below covers the agent's whole status vocabulary (0074 #20)", () => {
    expect(Object.keys(STATUS_TONE_CASES).sort()).toEqual([...ANCHOR_VOCABULARY.statuses].sort());
  });

  it.each(Object.entries(STATUS_TONE_CASES))("gives status %s the %s tone", (status, tone) => {
    render(<AnchorResult validation={anchorValidation(status, { claimed_line_range: "no_line" })} />);
    expect(screen.getByTestId("anchor-status")).toHaveAttribute("data-tone", tone);
    expect(screen.getByTestId("anchor-range")).toHaveTextContent("results.anchor.range.no_line");
  });

  it("records the range independently of the verdict: absent and past end of file both show (O3 = C)", () => {
    render(<AnchorResult validation={anchorValidation("absent", { claimed_line: 900, claimed_line_range: "past_eof" })} />);
    expect(screen.getByTestId("anchor-status")).toHaveTextContent("results.anchor.status.absent");
    expect(screen.getByTestId("anchor-range")).toHaveTextContent("results.anchor.range.past_eof");
  });

  it("omits a range it does not know (pre-0074 row, or a newer token) instead of inventing one", () => {
    const { rerender } = render(<AnchorResult validation={anchorValidation("unquoted")} />);
    expect(screen.getByTestId("anchor-status")).toBeInTheDocument();
    expect(screen.queryByTestId("anchor-range")).toBeNull();
    expect(screen.queryByTestId("anchor-line")).toBeNull();
    rerender(<AnchorResult validation={anchorValidation("unquoted", { claimed_line_range: "sideways" })} />);
    expect(screen.queryByTestId("anchor-range")).toBeNull();
  });

  it("reads the LAST anchor check when there are several, as every reader does (0074 #20)", () => {
    const id = ANCHOR_VOCABULARY.check_id;
    expect(ANCHOR_VOCABULARY.duplicate_rule).toBe("last");
    const validation = {
      checks: [
        { id, result: "exact", weight: 0, extras: { claimed_line: 5, claimed_line_range: "in_file" } },
        { id: "path", result: "ok", weight: 0 },
        { id, result: "absent", weight: 0, extras: { claimed_line: 9, claimed_line_range: "past_eof" } },
      ],
    };
    render(<AnchorResult validation={validation} />);
    expect(screen.getByTestId("anchor-status")).toHaveTextContent("results.anchor.status.absent");
    expect(screen.getByTestId("anchor-range")).toHaveTextContent("results.anchor.range.past_eof");
    expect(screen.getByTestId("anchor-line")).toHaveTextContent(/^L9$/);
  });

  it("is read-only: no button or other control", () => {
    const { container } = render(<AnchorResult validation={anchorValidation("reanchored", {
      claimed_line: 60, delta: -20, claimed_line_range: "past_eof",
    })} />);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(container.querySelectorAll("input, select, textarea, a[href]")).toHaveLength(0);
  });

  it.each([
    ["no validation", undefined],
    ["no checks", { provenance_origins: ["skill"] }],
    ["no anchor check (deterministic row)", { checks: [{ id: "path", result: "ok", weight: 0 }] }],
    ["checks is not an array", { checks: "anchor" }],
    ["checks holds junk", { checks: [null, 7, "anchor", { id: "anchor" }] }],
  ])("renders nothing, and does not throw, for %s", (_name, validation) => {
    const { container } = render(<AnchorResult validation={validation as Record<string, unknown> | undefined} />);
    expect(container).toBeEmptyDOMElement();
  });
});
