import type { Finding } from "@/lib/types.ts";

// Feature 0074 — detection-tier families for the provenance filter.
//
// ONE family rule, shared with the backend (Go isLLMProvenance) and the agents
// (Python _is_deterministic): a tier, trimmed and lower-cased, that starts with
// "llm" is the LLM family; any other non-empty tier is the deterministic
// family. Only a string is a tier. A GROUPING provenance (catalog_rollup)
// names the rollup that grouped the leaves, not a tier that detected anything,
// so as an origin it is neither family (C11: Go, MCP and this file agree).
//
// The filter VALUE is exact and case-sensitive: "llm_family" and "both" are the
// two family values; every other value matches finding.provenance literally
// (the 0058 behaviour). Each predicate reads one field of the row, so filtering
// is constant work per row.

export const PROVENANCE_LLM_FAMILY = "llm_family";
export const PROVENANCE_BOTH = "both";

const DETERMINISTIC = 1;
const LLM = 2;
const BOTH_FAMILIES = DETERMINISTIC | LLM;

function normalizeTier(tier: unknown): string {
  return typeof tier === "string" ? tier.trim().toLowerCase() : "";
}

const GROUPING_PROVENANCES: ReadonlySet<string> = new Set(["catalog_rollup"]);

function tierFamily(tier: unknown): number {
  const t = normalizeTier(tier);
  if (!t || GROUPING_PROVENANCES.has(t)) return 0;
  return t.startsWith("llm") ? LLM : DETERMINISTIC;
}

/** True when `tier` is the LLM family (trimmed, lower-cased, starts with "llm"). */
export function isLLMTier(tier: unknown): boolean {
  return tierFamily(tier) === LLM;
}

function originsOf(validation: unknown): unknown[] | undefined {
  const origins = (validation as { provenance_origins?: unknown } | null | undefined)?.provenance_origins;
  return Array.isArray(origins) ? origins : undefined;
}

/** True when validation.provenance_origins names a deterministic AND an LLM tier. */
export function spansBothTiers(validation: unknown): boolean {
  const origins = originsOf(validation);
  if (!origins) return false;
  let seen = 0;
  for (const origin of origins) seen |= tierFamily(origin);
  return seen === BOTH_FAMILIES;
}

/**
 * Whether the audit's findings record provenance_origins at all, so an empty
 * "both" result can say "not recorded" (an audit that predates the record)
 * rather than "never corroborated". The API's `origins_recorded` flag wins
 * when the backend sends it; otherwise any row whose validation carries the
 * provenance_origins key (whatever its value, as the backend decides) proves
 * the record exists.
 */
export function originsRecorded(findings: readonly Finding[], flag: boolean | undefined): boolean {
  return flag ?? findings.some(recordsOrigins);
}

// The key's presence, whatever its value: the backend's markOriginsRecorded rule.
function recordsOrigins(f: Finding): boolean {
  const v = f.validation;
  return typeof v === "object" && v !== null && "provenance_origins" in v;
}

type FindingPredicate = (f: Finding) => boolean;

const FAMILY_FILTERS: ReadonlyMap<string, FindingPredicate> = new Map([
  [PROVENANCE_LLM_FAMILY, (f: Finding) => isLLMTier(f.provenance)],
  [PROVENANCE_BOTH, (f: Finding) => spansBothTiers(f.validation)],
]);

/** The row predicate for a provenance filter value ("all" is handled by the caller). */
export function provenanceMatcher(value: string): FindingPredicate {
  return FAMILY_FILTERS.get(value) ?? ((f: Finding) => f.provenance === value);
}
