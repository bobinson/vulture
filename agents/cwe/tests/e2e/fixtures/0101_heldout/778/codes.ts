// Feature 0101 held-out (LLD 4.6), CWE-778 Concept B at the idiom level.
// An object checked with `satisfies` NAMES outcome codes; a ternary picking one is
// the decision. Every identifier is invented.
// HELD-OUT-TOKENS: satisfies

export const Denials = {
  Unauthorized: 401, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
  Forbidden: 403, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
} satisfies Record<string, number>;

export const Labels = { Forbidden: 'not allowed' } satisfies Record<string, string>; // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)

export function statusFor(pass: Pass): number {
  return pass.active ? 200 : Denials.Forbidden; // EXPECT: finding check=cwe.insufficient_logging.auth_decision
}
