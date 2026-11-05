import { describe, expect, it } from "vitest";
// Feature 0074 #20 — the UI's anchor vocabulary is pinned to the one the agent
// exports (agents/shared/tests/contract/anchor_vocabulary_0074.json, itself
// pinned to agents/shared/shared/anchor.py), instead of redeclared literals.
import { ANCHOR_CHECK_ID, ANCHOR_RANGE_TONES, ANCHOR_STATUS_TONES } from "./anchor";
import { ANCHOR_VOCABULARY } from "@/test/anchorVocabulary";


describe("anchor vocabulary matches the agent's export (0074 #20)", () => {
  it("names the same check id", () => {
    expect(ANCHOR_CHECK_ID).toBe(ANCHOR_VOCABULARY.check_id);
  });

  it("tones only statuses the agent can write", () => {
    expect(ANCHOR_VOCABULARY.statuses).toEqual(expect.arrayContaining(Object.keys(ANCHOR_STATUS_TONES)));
  });

  it("tones every claimed-line range and no other", () => {
    expect(Object.keys(ANCHOR_RANGE_TONES).sort()).toEqual([...ANCHOR_VOCABULARY.claimed_line_ranges].sort());
  });

  it("the duplicate-check rule is last-wins, which AnchorResult follows", () => {
    expect(ANCHOR_VOCABULARY.duplicate_rule).toBe("last");
  });
});
