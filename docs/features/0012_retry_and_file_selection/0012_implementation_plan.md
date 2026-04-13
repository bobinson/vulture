# 0012 — Skill Retries with Jitter + Smarter LLM File Selection

## Overview

Two improvements to Vulture's audit agents:

1. **Skill retries with ±50% jitter** — Transient OS errors (file locks, permissions, busy devices) are retried once with exponential backoff and jitter. LLM retry jitter also widened from ±25% to ±50% to prevent thundering herd.

2. **Smarter file selection for LLM phase** — `_build_source_context` now prioritizes files by: (1) files where skills found issues, (2) entry points/config files, (3) remaining files sorted by size ascending.

## Files Modified

| File | Changes |
|------|---------|
| `agents/shared/shared/llm/errors.py` | Jitter 0.25→0.5; added `retry_skill()`, `_is_transient_skill_error()` |
| `agents/shared/shared/audit_runner.py` | Wrapped `pool.submit` with `retry_skill`; refactored `_build_source_context` with tiered file prioritization; extracted `_prioritize_files()` and `_pack_files()` |
| `agents/shared/shared/tools/file_scanner.py` | Added `is_entry_or_config()` helper |
| `agents/shared/tests/e2e/test_audit_runner.py` | Added `TestSkillRetryBehavior` (3 E2E tests) |
| `agents/shared/tests/unit/test_audit_runner.py` | Added tests for `_prioritize_files`, `_pack_files`, `_build_source_context` with findings, `is_entry_or_config` |
| `agents/shared/tests/unit/test_llm_modules.py` | Added `TestIsTransientSkillError` (6 tests), `TestRetrySkill` (5 tests) |

## Design Decisions

- `retry_skill` uses `max_attempts=2` (1 retry) to avoid masking persistent issues
- Only OS-level transient errors are retried (PermissionError, TimeoutError, EAGAIN, EBUSY, ENOLCK)
- Non-transient errors (ValueError, RuntimeError, etc.) are raised immediately
- File prioritization is purely additive — the `skill_findings` parameter is optional and defaults to None
