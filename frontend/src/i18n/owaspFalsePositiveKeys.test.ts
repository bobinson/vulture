import { describe, expect, it } from "vitest";
import de from "./locales/de.json";
import en from "./locales/en.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";
import ja from "./locales/ja.json";
import pt from "./locales/pt.json";

/**
 * 0096 follow-up: the OWASP coverage card notes how many of a category's
 * findings were triaged false positive. Parity alone cannot catch a key that
 * is missing from every locale including en, so the note's plural forms are
 * named here, and each must interpolate the count.
 */

type Json = Record<string, unknown>;

const LOCALES: Record<string, Json> = { en, es, de, fr, ja, pt };
const KEYS = ["results.owaspFalsePositiveNote_one", "results.owaspFalsePositiveNote_other"] as const;

const lookup = (json: Json, key: string) =>
  key.split(".").reduce<unknown>((acc, part) => (acc as Json)?.[part], json);

describe("i18n OWASP false-positive note (0096 follow-up)", () => {
  it.each(Object.keys(LOCALES))("%s defines both plural forms with {{count}}", (name) => {
    for (const key of KEYS) {
      const value = lookup(LOCALES[name], key);
      expect(typeof value, `${name}.json is missing ${key}`).toBe("string");
      expect(value as string, `${name}.json ${key} does not interpolate the count`).toContain("{{count}}");
    }
  });
});
