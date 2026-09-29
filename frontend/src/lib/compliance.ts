import { SEVERITY_ORDER } from "./constants.ts";
import type { ComplianceLabel, Finding, LabelEdition } from "./types.ts";

/**
 * Feature 0096: OWASP Top 10 as LABELS over CWE-categorised findings.
 *
 * The OWASP agent answers with its edition's CWE -> category table instead of
 * re-emitting each CWE finding as a second row. The backend applies that table
 * to the final finding set and persists `compliance_labels`; the helpers here
 * read those labels, and apply the same table to a live run's in-memory rows
 * so chips appear before persistence. The rule mirrors the backend's: a pure
 * function of (category, table, selected), never of ids.
 */

export const OWASP = "owasp";

/** The ten category ids every OWASP Top 10 edition uses. */
export const OWASP_CATEGORY_IDS: readonly string[] = Array.from(
  { length: 10 },
  (_, i) => `A${String(i + 1).padStart(2, "0")}`,
);

export interface MappingCategory {
  id: string;
  name: string;
}

/** The `mapping` object of an OWASP agent result (mapping result v1). */
export interface ComplianceMapping {
  version: 1;
  framework: string;
  edition: string;
  /** The effective `categories` filter; empty = all. */
  selected: string[];
  table: Record<string, MappingCategory[]>;
}

const CWE_CATEGORY = /^CWE-\d+$/;
const TABLE_KEY = /^CWE-\d{1,5}$/;
const CATEGORY_ID = /^A\d{2}$/;
const EDITION = /^\d{4}$/;
const MAX_TABLE_KEYS = 2000;
/** Longest category name, in Unicode code points (the backend's rune count). */
const MAX_NAME = 120;
/** Most entries `selected` may hold; the backend rejects a longer list. */
const MAX_SELECTED = 100;
const ZERO_PADDED_CWE = /^CWE-0+(?=\d)/;

/**
 * A finding's CWE category as the table keys it: `CWE-089` -> `CWE-89`. The
 * backend canonicalises a zero-padded id the same way before its lookup, so
 * a padded category is labelled rather than silently left out.
 */
export function canonicalCwe(category: string): string {
  return category.replace(ZERO_PADDED_CWE, "CWE-");
}

/** Length in code points, as Go's utf8.RuneCountInString counts it. */
function codePointLength(s: string): number {
  return Array.from(s).length;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isMappingCategory(v: unknown): v is MappingCategory {
  return (
    isRecord(v) &&
    typeof v.id === "string" &&
    CATEGORY_ID.test(v.id) &&
    typeof v.name === "string" &&
    !v.name.includes("\u0000") &&
    codePointLength(v.name) <= MAX_NAME
  );
}

/** The categories with duplicate ids folded, first occurrence kept. */
function foldCategories(cats: MappingCategory[]): MappingCategory[] {
  const seen = new Set<string>();
  const out: MappingCategory[] = [];
  for (const { id, name } of cats) {
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name });
  }
  return out;
}

function parseTable(raw: unknown): Record<string, MappingCategory[]> | null {
  if (!isRecord(raw)) return null;
  const entries = Object.entries(raw);
  if (entries.length > MAX_TABLE_KEYS) return null;
  const table: Record<string, MappingCategory[]> = {};
  for (const [cwe, cats] of entries) {
    if (!TABLE_KEY.test(cwe) || !Array.isArray(cats) || !cats.every(isMappingCategory)) return null;
    // Keyed canonically, as the backend keys its table, so a finding's
    // canonical category finds a padded key; colliding keys merge, folded.
    const key = canonicalCwe(cwe);
    table[key] = foldCategories([...(table[key] ?? []), ...cats]);
  }
  return table;
}

function parseSelected(raw: unknown): string[] | null {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw) || raw.length > MAX_SELECTED) return null;
  return raw.every((id) => typeof id === "string" && CATEGORY_ID.test(id)) ? [...raw] : null;
}

/**
 * Validate a mapping from an OWASP result snapshot, all or nothing. Anything
 * malformed yields null, so the page shows no labels rather than wrong ones.
 *
 * The rules are the backend validator's (handler/compliance_mapping.go):
 * version 1, framework "owasp", a four-digit edition; `selected` absent/null
 * (= all) or at most 100 ids matching A\d{2}; a table object of at most 2,000
 * keys matching CWE-\d{1,5}, each an array of categories with an A\d{2} id and
 * a name of at most 120 code points containing no NUL, duplicate ids per CWE
 * folded (first kept), keys and finding categories compared as canonical CWE
 * ids (no leading zeros). Two differences are deliberate and safe in this
 * direction: JSON.parse has already replaced any invalid UTF-8 (which the
 * backend rejects), and a table that is absent or null is rejected here as a
 * non-object, as the backend rejects it as missing.
 */
export function parseComplianceMapping(raw: unknown): ComplianceMapping | null {
  if (!isRecord(raw) || raw.version !== 1 || raw.framework !== OWASP) return null;
  if (typeof raw.edition !== "string" || !EDITION.test(raw.edition)) return null;
  const table = parseTable(raw.table);
  const selected = parseSelected(raw.selected);
  if (!table || !selected) return null;
  return { version: 1, framework: OWASP, edition: raw.edition, selected, table };
}

function labelsFor(f: Finding, m: ComplianceMapping): ComplianceLabel[] {
  if (f.agent_type === OWASP || !CWE_CATEGORY.test(f.category)) return [];
  const cwe = canonicalCwe(f.category);
  const cats = m.table[cwe] ?? [];
  const wanted = m.selected.length > 0 ? cats.filter((c) => m.selected.includes(c.id)) : cats;
  return wanted.map((c) => ({
    framework: m.framework,
    edition: m.edition,
    category_id: c.id,
    category_name: c.name,
    cwe,
  }));
}

/**
 * Apply a mapping to findings: each CWE-categorised finding (from any scan
 * agent, never an OWASP copy row) has its (framework, edition) labels replaced
 * by the table's categories for its CWE; other frameworks' labels are kept.
 * A finding that ends with no label keeps no `compliance_labels` at all, and
 * an untouched finding is returned as the same object.
 */
export function applyComplianceMapping(findings: Finding[], m: ComplianceMapping): Finding[] {
  return findings.map((f) => {
    const add = labelsFor(f, m);
    const existing = f.compliance_labels ?? [];
    const kept = existing.filter((l) => l.framework !== m.framework || l.edition !== m.edition);
    if (add.length === 0 && kept.length === existing.length) return f;
    const labels = [...kept, ...add];
    return { ...f, compliance_labels: labels.length > 0 ? labels : undefined };
  });
}

/** The finding's OWASP labels (any edition). */
export function owaspLabels(f: Finding): ComplianceLabel[] {
  return (f.compliance_labels ?? []).filter((l) => l.framework === OWASP);
}

export function hasOwaspCategory(f: Finding, id: string): boolean {
  return owaspLabels(f).some((l) => l.category_id === id);
}

export interface OwaspCategoryOption {
  id: string;
  name: string;
  edition: string;
}

/** The OWASP categories present among the findings, once each, by id. */
export function owaspCategoryOptions(findings: Finding[]): OwaspCategoryOption[] {
  const byId = new Map<string, OwaspCategoryOption>();
  for (const f of findings) {
    for (const l of owaspLabels(f)) {
      if (!byId.has(l.category_id)) {
        byId.set(l.category_id, { id: l.category_id, name: l.category_name, edition: l.edition });
      }
    }
  }
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export interface OwaspCategoryGroup extends OwaspCategoryOption {
  findings: Finding[];
}

const severityRank = (f: Finding) => SEVERITY_ORDER[f.severity] ?? 4;

/** Labelled findings grouped by (edition, category): newest edition first, then id; worst severity first. */
export function groupByOwaspCategory(findings: Finding[]): OwaspCategoryGroup[] {
  const groups = new Map<string, OwaspCategoryGroup>();
  for (const f of findings) {
    for (const l of owaspLabels(f)) {
      const key = `${l.edition}/${l.category_id}`;
      const g = groups.get(key) ?? { id: l.category_id, name: l.category_name, edition: l.edition, findings: [] };
      g.findings.push(f);
      groups.set(key, g);
    }
  }
  const out = [...groups.values()];
  for (const g of out) g.findings.sort((a, b) => severityRank(a) - severityRank(b));
  return out.sort((a, b) => b.edition.localeCompare(a.edition) || a.id.localeCompare(b.id));
}

export interface LineageOwaspLabel {
  edition: string;
  id: string;
}

/** A lineage row's `compliance_labels` map flattened to its OWASP labels, newest edition first. */
export function lineageOwaspLabels(labels: Record<string, string[]> | undefined): LineageOwaspLabel[] {
  const prefix = `${OWASP}:`;
  return Object.entries(labels ?? {})
    .filter(([key]) => key.startsWith(prefix))
    .flatMap(([key, ids]) => ids.map((id) => ({ edition: key.slice(prefix.length), id })))
    .sort((a, b) => b.edition.localeCompare(a.edition) || a.id.localeCompare(b.id));
}

/** The OWASP editions of a `label_editions` list, newest first, once each; absent = none. */
export function owaspEditionsOf(labelEditions: readonly LabelEdition[] | undefined): string[] {
  const out = new Set<string>();
  for (const le of labelEditions ?? []) {
    if (le.framework === OWASP && isOwaspEdition(le.edition)) out.add(le.edition);
  }
  return [...out].sort((a, b) => b.localeCompare(a));
}

/** The category ids one OWASP edition of a `label_editions` list carries, sorted, once each. */
export function owaspCategoriesOf(labelEditions: readonly LabelEdition[] | undefined, edition: string): string[] {
  const out = new Set<string>();
  for (const le of labelEditions ?? []) {
    if (le.framework !== OWASP || le.edition !== edition) continue;
    for (const id of le.categories ?? []) {
      if (CATEGORY_ID.test(id)) out.add(id);
    }
  }
  return [...out].sort();
}

export function isOwaspEdition(v: string | null | undefined): v is string {
  return typeof v === "string" && EDITION.test(v);
}
