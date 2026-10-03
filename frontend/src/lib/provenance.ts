import type { Finding } from "@/lib/types.ts";

// Feature 0074 — detection-tier families for the provenance filter.
//
// ONE family rule, shared with the backend (Go isLLMProvenance) and the agents
// (Python _is_deterministic): a tier, trimmed and lower-cased, that starts with
// "llm" is the LLM family; any other non-empty tier is the deterministic
// family. Only a string is a tier.
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

function tierFamily(tier: unknown): number {
  const t = normalizeTier(tier);
  if (!t) return 0;
  return t.startsWith("llm") ? LLM : DETERMINISTIC;
}

/** True when `tier` is the LLM family (trimmed, lower-cased, starts with "llm"). */
export function isLLMTier(tier: unknown): boolean {
  return tierFamily(tier) === LLM;
}

/** True when validation.provenance_origins names a deterministic AND an LLM tier. */
export function spansBothTiers(validation: unknown): boolean {
  const origins = (validation as { provenance_origins?: unknown } | null | undefined)?.provenance_origins;
  if (!Array.isArray(origins)) return false;
  let seen = 0;
  for (const origin of origins) seen |= tierFamily(origin);
  return seen === BOTH_FAMILIES;
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
