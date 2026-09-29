import type { Severity } from "./types.ts";

/** Map LLM severity abbreviations/variants to canonical form. */
const SEVERITY_ALIASES: Record<string, Severity> = {
  c: "critical", crit: "critical", critical: "critical",
  h: "high", high: "high",
  m: "medium", med: "medium", medium: "medium",
  l: "low", low: "low",
  i: "info", info: "info", informational: "info",
};

/** Normalize a finding severity from agent/LLM output; anything unknown reads as info. */
export function normalizeSeverity(raw: string): Severity {
  return SEVERITY_ALIASES[raw.toLowerCase().trim()] ?? "info";
}
