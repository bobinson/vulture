import { describe, expect, it } from "vitest";
// Feature 0074 (RED) — en copy for the tier-family filter values and the
// anchor result (plan §5.6, T2.2, AC39). That every locale defines every 0074
// key is enforced by the REQUIRED_0074_KEYS slot in ../i18n_parity.test.ts;
// this file pins only the English copy drawn in
// designs/0074-provenance-family.html.
import en from "../locales/en.json";

describe("i18n tier-family and anchor keys (0074)", () => {
  it("en carries the designed copy", () => {
    expect(en).toHaveProperty("results.provenanceFamily.llm_family", "LLM (all)");
    expect(en).toHaveProperty("results.provenanceFamily.both", "Both tiers");
    expect(en).toHaveProperty(
      "results.provenanceFamily.bothNotRecorded",
      "Tier origins were not recorded for this audit, so no row can show as reported by both tiers.",
    );
    expect(en).toHaveProperty("results.anchor.title", "Anchor");
    expect(en).toHaveProperty("results.anchor.status.reanchored", "Re-anchored");
    expect(en).toHaveProperty("results.anchor.range.past_eof", "Past end of file");
  });
});
