import { describe, expect, it } from "vitest";
// Feature 0074 (RED) — i18n for the tier-family filter values and the anchor
// result (plan §5.6: "i18n keys go in all six locales"; T2.2, AC39).
// Contract: every locale defines non-empty strings at
//   results.provenanceFamily.{llm_family, both}
//   results.anchor.title
//   results.anchor.status.{the nine 0076 statuses}
//   results.anchor.range.{in_file, past_eof, no_line}
// and en carries the copy drawn in designs/0074-provenance-family.html.
import de from "../locales/de.json";
import en from "../locales/en.json";
import es from "../locales/es.json";
import fr from "../locales/fr.json";
import ja from "../locales/ja.json";
import pt from "../locales/pt.json";

const LOCALES: Record<string, unknown> = { de, en, es, fr, ja, pt };

const STATUSES = [
  "exact", "reanchored", "ambiguous", "near_miss", "found_elsewhere",
  "absent", "unquoted", "unreadable", "oversize",
];
const RANGES = ["in_file", "past_eof", "no_line"];

const REQUIRED = [
  "results.provenanceFamily.llm_family",
  "results.provenanceFamily.both",
  "results.anchor.title",
  ...STATUSES.map((s) => `results.anchor.status.${s}`),
  ...RANGES.map((r) => `results.anchor.range.${r}`),
];

function lookup(tree: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>(
    (node, key) => (node && typeof node === "object" ? (node as Record<string, unknown>)[key] : undefined),
    tree,
  );
}

describe("i18n tier-family and anchor keys (0074)", () => {
  it.each(Object.keys(LOCALES))("%s.json defines every 0074 key as a non-empty string", (name) => {
    const missing = REQUIRED.filter((key) => {
      const value = lookup(LOCALES[name], key);
      return typeof value !== "string" || value.trim() === "";
    });
    expect(missing, `${name}.json is missing: ${missing.join(", ")}`).toEqual([]);
  });

  it("en carries the designed copy", () => {
    expect(lookup(en, "results.provenanceFamily.llm_family")).toBe("LLM (all)");
    expect(lookup(en, "results.provenanceFamily.both")).toBe("Both tiers");
    expect(lookup(en, "results.anchor.title")).toBe("Anchor");
    expect(lookup(en, "results.anchor.status.reanchored")).toBe("Re-anchored");
    expect(lookup(en, "results.anchor.range.past_eof")).toBe("Past end of file");
  });
});
