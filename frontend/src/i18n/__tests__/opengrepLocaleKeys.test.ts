import { describe, expect, it } from "vitest";
// Feature 0058 — i18n keys for the plugin augmentation UI (Opengrep since 0102).
// Contract: every locale file gains (non-empty string values):
//   results.provenance         — label for the provenance filter/chip
//   results.opengrepTierNotice — copy for the R9 "tier not active" banner
import de from "../locales/de.json";
import en from "../locales/en.json";
import es from "../locales/es.json";
import fr from "../locales/fr.json";
import ja from "../locales/ja.json";
import pt from "../locales/pt.json";

const LOCALES: Record<string, { results: Record<string, unknown> }> = {
  de,
  en,
  es,
  fr,
  ja,
  pt,
};

const REQUIRED_KEYS = ["provenance", "opengrepTierNotice"] as const;

describe("i18n plugin augmentation keys (0058)", () => {
  it("all 6 locales define results.provenance and results.opengrepTierNotice", () => {
    for (const [name, locale] of Object.entries(LOCALES)) {
      for (const key of REQUIRED_KEYS) {
        const value = locale.results[key];
        expect(typeof value, `${name}.json results.${key} must be a string`).toBe("string");
        expect(
          (value as string).trim().length,
          `${name}.json results.${key} must be non-empty`,
        ).toBeGreaterThan(0);
      }
    }
  });

  it("no locale keeps the retired results.semgrepTierNotice key", () => {
    for (const [name, locale] of Object.entries(LOCALES)) {
      expect(locale.results, `${name}.json`).not.toHaveProperty("semgrepTierNotice");
    }
  });
});
