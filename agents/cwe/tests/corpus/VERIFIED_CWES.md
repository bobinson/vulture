# CWE agent — verified coverage attestation

<!-- GENERATED FILE — do NOT edit by hand. Regenerate via the venv: agents/.venv/bin/python agents/cwe/tests/corpus/report_coverage.py --write -->

**N = 10** corpus-VERIFIED CWE types. N is the count of VERIFIED rows the deterministic gate produced (skills + signatures, NO LLM); it is computed, never asserted as a literal.

This document is the honest, four-bucket picture of what the CWE agent detects — in BOTH directions (no overclaim, no underclaim). It is regenerated from the corpus gate and committed; a stale copy fails CI.

## VERIFIED — corpus-gated (N = 10)

Each of these CWE types passed the per-CWE promotion gate on the labeled corpus: recall 1.0, false-positive rate 0.0, over independent positive and clean fixtures. These — and ONLY these — are counted in N.

| CWE | band | pos | clean | recall | fp |
| --- | ---- | --: | ----: | -----: | -: |
| CWE-78 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-89 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-90 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-91 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-117 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-548 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-798 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-917 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-943 | VERIFIED | 6 | 6 | 1.000 | 0.000 |
| CWE-1333 | VERIFIED | 6 | 6 | 1.000 | 0.000 |

## DETECTED — below the gate

A CWE here FIRES on at least one positive fixture but misses the strict bar (recall < 1.0, a clean-twin false positive, or too few fixtures). It is MEASURED but NOT counted in N.

(none)

## DECLARED-ONLY — detectable, not corpus-gated

The agent's dedicated skills emit 73 distinct CWE-id `category` literals and 7 trusted-signature CWE-ids are declared. The CWE-ids below are declared/detectable but are NOT (yet) corpus-VERIFIED, so they are NOT counted in N. The 846-entry CWE v4.19.1 catalog is metadata/context (names, consequences, rollup parents); its keyword-matching path fires ~0 findings on real code and is not counted.

CWE-20, CWE-22, CWE-79, CWE-94, CWE-113, CWE-120, CWE-125, CWE-134, CWE-190, CWE-200, CWE-209, CWE-248, CWE-252, CWE-269, CWE-287, CWE-306, CWE-312, CWE-319, CWE-321, CWE-326, CWE-327, CWE-328, CWE-330, CWE-352, CWE-367, CWE-369, CWE-384, CWE-390, CWE-400, CWE-401, CWE-404, CWE-415, CWE-416, CWE-434, CWE-457, CWE-467, CWE-476, CWE-494, CWE-502, CWE-506, CWE-521, CWE-532, CWE-562, CWE-601, CWE-611, CWE-614, CWE-639, CWE-662, CWE-668, CWE-681, CWE-704, CWE-732, CWE-754, CWE-755, CWE-770, CWE-778, CWE-787, CWE-824, CWE-829, CWE-833, CWE-838, CWE-862, CWE-863, CWE-918, CWE-937, CWE-1004, CWE-1104, CWE-1188, CWE-1295, CWE-1321

## LLM-ASSISTED — non-deterministic

The LLM tier is generate-then-verify and non-deterministic; it adds **0** to N. LLM findings carry provenance `llm`, or `llm_l5_verified` once an L5 judge confirms them — but they are never corpus-gated and never enter the VERIFIED count.

## Caveats

- recall / fp are FILE-level (the manifest `line` field is diagnostic only).
- the per-CWE pos/clean counts are two independently-authored 3+3 tranches of the SAME vuln family (e.g. `sig_a` + `signatures_a`), not 6 distinct attack shapes; the paired fixtures are genuinely distinct code (different sinks/languages), verified non-duplicate.

