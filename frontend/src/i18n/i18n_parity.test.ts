import { describe, expect, it } from "vitest";
import de from "./locales/de.json";
import en from "./locales/en.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";
import ja from "./locales/ja.json";
import pt from "./locales/pt.json";

/**
 * Feature 0091 P5 (RED) — locale parity.
 *
 * The project rule is "i18n keys in ALL SIX locales", but nothing enforced it:
 * `i18n/index.test.ts` covers lazy loading and `__tests__/semgrepLocaleKeys.test.ts`
 * covers exactly two keys of one feature. A key added to `en.json` alone renders
 * as English (or as the raw key) for every other language, silently.
 *
 * This test is the general guard: the key SETS of the six locales must be equal.
 * It is deliberately bidirectional — a key that survives only in a translation
 * is dead weight that outlives the English string it was translated from.
 */

type Json = Record<string, unknown>;

const LOCALES: Record<string, Json> = { en, es, de, fr, ja, pt };
const OTHERS = ["es", "de", "fr", "ja", "pt"] as const;

/** Dotted leaf paths. A branch/leaf mismatch shows up as two differing paths. */
function flatten(node: unknown, prefix = ""): string[] {
  if (node === null || typeof node !== "object" || Array.isArray(node)) {
    return prefix ? [prefix] : [];
  }
  return Object.entries(node as Json).flatMap(([key, value]) =>
    flatten(value, prefix ? `${prefix}.${key}` : key),
  );
}

const KEYS: Record<string, Set<string>> = Object.fromEntries(
  Object.entries(LOCALES).map(([name, json]) => [name, new Set(flatten(json))]),
);

function missingFrom(locale: string): string[] {
  return [...KEYS.en].filter((k) => !KEYS[locale].has(k)).sort();
}

function extraIn(locale: string): string[] {
  return [...KEYS[locale]].filter((k) => !KEYS.en.has(k)).sort();
}

describe("i18n locale parity", () => {
  it.each(OTHERS)("%s defines every key that en defines", (locale) => {
    const missing = missingFrom(locale);
    expect(missing, `${locale}.json is missing ${missing.length} key(s): ${missing.join(", ")}`)
      .toEqual([]);
  });

  it.each(OTHERS)("%s defines no key that en does not define", (locale) => {
    const extra = extraIn(locale);
    expect(extra, `${locale}.json has ${extra.length} orphan key(s): ${extra.join(", ")}`)
      .toEqual([]);
  });

  it("every locale has the same key count as en", () => {
    const counts = Object.fromEntries(
      Object.entries(KEYS).map(([name, set]) => [name, set.size]),
    );
    for (const locale of OTHERS) {
      expect(counts[locale], `${locale} has ${counts[locale]} keys, en has ${counts.en}`)
        .toBe(counts.en);
    }
  });

  it("no locale carries an empty string for a key en fills in", () => {
    const empties: string[] = [];
    for (const [name, json] of Object.entries(LOCALES)) {
      for (const key of flatten(json)) {
        const value = key.split(".").reduce<unknown>((acc, part) => (acc as Json)?.[part], json);
        if (typeof value === "string" && value.trim() === "") empties.push(`${name}:${key}`);
      }
    }
    expect(empties, `empty translations: ${empties.join(", ")}`).toEqual([]);
  });
});

/**
 * The 0091 surface specifically. Parity alone cannot catch a key that is
 * missing from every locale including en, so the new aggregate/lineage strings
 * are named here. Statuses and events follow the existing `status_<value>` /
 * `event_<value>` convention and mirror `model.ActiveLineageStatuses()` and the
 * lineage event vocabulary shipped in P0–P3.
 */
const REQUIRED_0091_KEYS = [
  // Aggregate report
  "aggregate.noFindings",
  "aggregate.activeOnly",
  "aggregate.showAll",
  "aggregate.tier_det",
  "aggregate.tier_llm",
  // New lineage status
  "lineage.status_unconfirmed",
  // New lineage events
  "lineage.event_confirmed_by_evidence",
  "lineage.event_evidence_gone",
  "lineage.event_unconfirmable",
  "lineage.event_out_of_scope",
  "lineage.event_scope_unknown",
  "lineage.event_absent_in_result",
  "lineage.event_skipped_degraded",
  "lineage.event_memory_synced",
  "lineage.event_merged",
] as const;

describe("i18n 0091 aggregate + lineage keys", () => {
  it.each(Object.keys(LOCALES))("%s defines every 0091 key with a non-empty string", (name) => {
    const json = LOCALES[name];
    for (const key of REQUIRED_0091_KEYS) {
      const value = key.split(".").reduce<unknown>((acc, part) => (acc as Json)?.[part], json);
      expect(typeof value, `${name}.json is missing ${key}`).toBe("string");
      expect((value as string).trim().length, `${name}.json has an empty ${key}`).toBeGreaterThan(0);
    }
  });
});
