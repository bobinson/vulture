# Feature 0060 — Rollback Plan

| | |
|---|---|
| **Feature** | 0060_cwe676_language_aware |
| **Status** | DRAFT (no code shipped — this plan governs post-merge rollback) |

## Rollback tiers (fastest → most complete)

### Tier 1 — Runtime kill switch (no deploy, no revert)
Set the escape hatch and restart the CWE agent:
```
VULTURE_CWE_DISABLE_LANGUAGE_AWARE_DANGEROUS_FN=true
```
Effect: `check_dangerous_function` falls back to the legacy single-regex matcher (pre-0060 behaviour). Ships for **one release** (R13). Use if the language-aware matcher misbehaves in production (unexpected FN/FP) but you don't want to roll back the binary.

- **Cost:** re-introduces the known idattestor FPs (`regex.exec`, `multi.exec`). Acceptable as a short-term stop-gap.
- **Verification:** re-run a scan over `idattestor`; confirm CWE-676 rows reappear (proves fallback active) — then decide Tier 2/3.

### Tier 2 — Revert Phase 2 only (keep the FP fix, drop the gate)
Revert the corpus+gate commit (P2a–P2c):
```
git revert <corpus_gate_commit>
```
Then regenerate the golden so CI is green again:
```
agents/.venv/bin/python agents/cwe/tests/corpus/report_coverage.py --write
```
Effect: CWE-676/242 leave the VERIFIED set (N 12 → 10); the language-aware matcher (Phase 1) stays. Use if the gate is flaky/over-strict but the matcher itself is good.

- **Note:** because N is computed, the golden MUST be regenerated in the revert commit or `test_report_coverage_golden.py` (0057 T22) fails.

### Tier 3 — Full revert (matcher + corpus + language-map)
Revert both commits (Phase 1 + Phase 2), including the `_LANGUAGE_BY_EXT` additions (R6):
```
git revert <corpus_gate_commit> <matcher_commit>
agents/.venv/bin/python agents/cwe/tests/corpus/report_coverage.py --write   # restore N=10 golden
```
Effect: complete return to pre-0060 state. `dangerous_function_check.py`, `shared/validate/language.py`, `gates.yaml`, `manifest.d/`, `VERIFIED_CWES.md` all restored.

- **Caution:** the `_LANGUAGE_BY_EXT` additions may be depended on by other code once merged — check `git grep` for new callers of the added extensions before reverting P1d in isolation.

## Blast-radius assessment
- **Isolated to the CWE agent.** No backend/Go, frontend, DB, or other agent is touched. `shared/validate/language.py` is shared, but the change is **purely additive** (new extension entries) — reverting removes entries, cannot break existing mappings.
- **No schema/migration changes** → no DB rollback.
- **Attestation (`VERIFIED_CWES.md`)** is the only cross-cutting artifact; every tier above restores it via the documented `--write` command.

## Pre-revert checklist
1. Capture the current N and VERIFIED set (`report_coverage.py --check`) for the record.
2. Choose the lowest tier that resolves the incident (prefer Tier 1).
3. After any Tier 2/3 revert, run `make cwe-corpus` (after `make install`) + the full `agents/cwe` + `agents/shared` suites to confirm green.
4. Re-run an `idattestor` scan to confirm the expected FP posture for the chosen tier.
