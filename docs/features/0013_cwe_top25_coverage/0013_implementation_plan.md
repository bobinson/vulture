# 0013 - CWE Top 25 Full Coverage

## Problem

The CWE agent had two critical issues:

1. **Dead code**: 8 CWE patterns defined but never wired into analysis pipeline (CWE-476, CWE-770, CWE-200, CWE-754, CWE-833, plus Go-specific helpers for CWE-362)
2. **Missing coverage**: 5 CWEs from the 2024 CWE Top 25 were entirely absent (CWE-352, CWE-416, CWE-502, CWE-918, CWE-190)

## Solution

### Wire Dead Code (4 files)

- `resource_check.py`: Add `_check_null_deref()` (CWE-476) and `_check_unbounded_alloc()` (CWE-770)
- `info_exposure_check.py`: Add `_check_sensitive_response()` (CWE-200)
- `error_handling_check.py`: Add `_check_io_without_check()` (CWE-754)
- `concurrency_check.py`: Add `_check_deadlock()` (CWE-833)

### Add Missing Top 25 (3 files)

- `injection_check.py`: CWE-918 (SSRF) - detects user-controlled URLs in server requests
- `buffer_check.py`: CWE-416 (Use After Free) + CWE-190 (Integer Overflow)
- `input_validation_check.py`: CWE-352 (CSRF) + CWE-502 (Deserialization)

### Tests

- 11 new E2E tests in `test_cwe_audit.py`
- 30+ new unit tests in `test_skills.py` covering pattern detection, skill-level detection, and false positive exclusion

## Affected Files

| File | Changes |
|------|---------|
| `agents/cwe/cwe_agent/skills/resource_check.py` | Wire CWE-476, CWE-770 |
| `agents/cwe/cwe_agent/skills/info_exposure_check.py` | Wire CWE-200 |
| `agents/cwe/cwe_agent/skills/error_handling_check.py` | Wire CWE-754 |
| `agents/cwe/cwe_agent/skills/concurrency_check.py` | Wire CWE-833 |
| `agents/cwe/cwe_agent/skills/injection_check.py` | Add CWE-918 |
| `agents/cwe/cwe_agent/skills/buffer_check.py` | Add CWE-416, CWE-190 |
| `agents/cwe/cwe_agent/skills/input_validation_check.py` | Add CWE-352, CWE-502 |
| `agents/cwe/cwe_agent/agent.py` | Update INSTRUCTIONS |
| `agents/cwe/cwe_agent/config.py` | Update description |
| `agents/cwe/cwe_agent/skills/SKILLS.md` | Document all new CWEs |
| `agents/cwe/tests/e2e/test_cwe_audit.py` | 11 new E2E tests |
| `agents/cwe/tests/unit/test_skills.py` | 30+ new unit tests |
