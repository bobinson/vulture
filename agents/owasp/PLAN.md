# OWASP Agent Fix Plan

## Scope: 3 Tracks

### Track A — Pipeline Robustness (audit_runner.py)
**Problem**: `future.result()` has no try-except — one failing skill crashes the entire audit. LLM errors are silently swallowed.
**Fix**:
1. Wrap `future.result()` in try-except in `run_skill_audit()` (line 277) and `run_combined_audit()` (line 362)
2. On skill exception: emit error text_message, continue processing remaining skills
3. In `_collect_llm_findings_async()`: capture exception message and return it so caller can emit it

### Track B — Fix Existing 5 Skills
**B1. auth_check.py**: Wire dead MISSING_AUTH_PATTERNS + AUTH_DECORATOR_PATTERNS
- Add `_check_missing_auth(file_path, content, findings)` that:
  - Finds lines matching MISSING_AUTH_PATTERNS (POST routes, create/update/delete functions)
  - Checks if any AUTH_DECORATOR_PATTERNS exist within 5 lines above the match
  - If no decorator found: emit high severity finding
- Keep existing weak auth pattern checks unchanged

**B2. security_misconfig.py**: Wire dead CORS_PATTERNS
- Add `_check_cors(file_path, line, line_num, findings, *, is_test)` that:
  - Tests all 3 CORS_PATTERNS
  - Severity: "high" (wildcard CORS is a real security issue)
  - Skip test files (same as debug/exposed)
- Call from `_analyze_file()` alongside existing checks

**B3-B5. injection_check, crypto_check, access_control**: No code changes needed — just add test coverage for untested patterns.

### Track C — 5 New Skills (Complete OWASP Top 10)

**C1. insecure_design.py (A04)**
Patterns: missing rate limiting on auth endpoints, no input length validation
- `RATE_LIMIT_PATTERNS`: `@rate_limit|@throttle|@ratelimit|RateLimiter|rate_limit`
- `AUTH_ENDPOINT_PATTERNS`: `login|signin|register|signup|reset.?password|forgot.?password`
- Logic: find auth endpoints without rate limiting in same file → medium severity

**C2. vulnerable_components.py (A06)**
Use existing `shared.tools.dependency_checker.check_dependencies()` to parse manifests.
Known-bad list (static, extensible):
- `pyyaml<6.0`, `requests<2.31.0`, `django<4.2`, `flask<2.3`, `lodash<4.17.21`, `express<4.18`
- Parse version strings, compare against known-bad thresholds
- Severity: high for known-vulnerable, medium for unpinned

**C3. data_integrity.py (A08)**
Patterns: unsafe deserialization
- `pickle\.loads?\(`, `marshal\.loads?\(`, `shelve\.open\(`
- `yaml\.load\(` (without `Loader=SafeLoader`)
- `jsonpickle\.decode`, `dill\.loads?\(`
- Severity: critical (deserialization = RCE)

**C4. logging_check.py (A09)**
Patterns: sensitive data in log statements
- `log.*password|log.*secret|log.*token|log.*api.?key|log.*credential` (case-insensitive)
- `print\(.*password|print\(.*secret|print\(.*token`
- Also: auth endpoints without any logging
- Severity: high (sensitive data exposure), medium (missing audit trail)

**C5. ssrf_check.py (A10)**
Patterns: unvalidated URL fetches
- `requests\.(get|post|put|delete|head)\(\s*[a-zA-Z_]` (variable, not string literal)
- `urllib\.request\.urlopen\(\s*[a-zA-Z_]`
- `http\.(Get|Post)\(\s*[a-zA-Z_]` (Go)
- `fetch\(\s*[a-zA-Z_]` (JS — but skip if URL is from known-safe source)
- Severity: high

### Config Updates
- `config.py`: Add 5 new categories to ALL_CATEGORIES and CONFIG_SCHEMA
- `skills/__init__.py`: Add 5 new skills to SKILL_MAP and SKILL_TOOLS
- `SKILLS.md`: Document all 10 skills

### DRY
- All skills follow identical structure: scan → skip generated → analyze → check patterns
- Shared helpers: is_generated_file, is_test_file, read_file_safe, scan_code_files
- Severity reduction in test files: same `"low" if is_test else "high"` pattern

### Complexity < 5
Every function:
- check_X(): iterate files + skip → CC 2
- _analyze_file(): read + iterate lines + call checks → CC 2-3
- _check_Y(): iterate patterns + match + append → CC 2-3

### Optimization
- Pre-compiled regex at module load time (re.compile)
- Early return after first pattern match per line (avoids redundant checks)
- Single file read per analyze call (read once, split once)
- `any()` for boolean short-circuit (auth decorator presence)
- set() for O(1) lookups in dedup

### Test Strategy (TESTS FIRST)
For each skill: create test files with known vulnerabilities, verify findings match expected output.
For pipeline: use stub skills that raise exceptions, verify partial results returned.
All tests in: `tests/unit/test_skills.py` (existing, extend) and `tests/e2e/test_owasp_audit.py` (existing, extend)
