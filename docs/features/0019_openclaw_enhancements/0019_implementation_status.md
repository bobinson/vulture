# 0019 Reference Implementation-Inspired Enhancements — Implementation Status

## Status: COMPLETE

All 7 enhancements implemented and verified.

| # | Enhancement | Status | Files Changed |
|---|-------------|--------|---------------|
| 1 | Evidence/code snippet | DONE | 27 skill files, `finding.py`, `finding.go`, `snippet.py` (new) |
| 2 | Score normalization in MMR | DONE | `memory_client.py` |
| 3 | Exponential temporal decay | DONE | `memory_client.py`, `test_memory_client.py` |
| 4 | Two-tier source rules | DONE | 5 CWE skills, `snippet.py` |
| 5 | Candidate amplification 4x | DONE | `memory_client.py` |
| 6 | Token caching in MMR | DONE | `memory_client.py` |
| 7 | requiresContext for prove | DONE | `finding.py`, `finding.go`, 2 prove strategies, 3 CWE skills |

## Key Changes

### New Files
- `agents/shared/shared/tools/snippet.py` — `extract_snippet()` and `check_context()` helpers
- `agents/shared/tests/unit/test_snippet.py` — Unit tests for snippet helpers

### Modified Files (Infrastructure)
- `agents/shared/shared/tools/memory_client.py` — Exponential decay, per-iteration MMR normalization, token caching, 4x amplification
- `agents/shared/shared/models/finding.py` — `code_snippet`, `verification_hints`, `requires_context` fields
- `backend/internal/model/finding.go` — Matching Go struct fields
- `agents/shared/tests/unit/test_memory_client.py` — Updated staleness tests for exponential decay

### Modified Files (Skills — code_snippet)
All 27 skill files across CWE, OWASP, SOC2, and Chaos agents now attach `code_snippet`.

### Modified Files (Two-tier context)
- `agents/cwe/cwe_agent/skills/auth_check.py` — Credential context corroboration
- `agents/cwe/cwe_agent/skills/access_control_check.py` — Route/handler context
- `agents/cwe/cwe_agent/skills/crypto_check.py` — Security/crypto context
- `agents/cwe/cwe_agent/skills/configuration_check.py` — Production/deploy context
- `agents/cwe/cwe_agent/skills/info_exposure_check.py` — Database/persist context

### Modified Files (Prove)
- `agents/prove/prove_agent/strategies/cwe.py` — Code/hints in plan prompt
- `agents/prove/prove_agent/strategies/owasp.py` — Code/hints in plan prompt
