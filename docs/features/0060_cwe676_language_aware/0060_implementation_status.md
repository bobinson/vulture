# Feature 0060 — Implementation Status

| | |
|---|---|
| **Feature** | 0060_cwe676_language_aware |
| **Status** | 🟢 **COMPLETE & GREEN — Phases 1+2+3, all deferred P1 items, and the end-to-end audit (#1–#6) done.** N = 10 → **12**. Uncommitted; awaiting commit decision + a CHANGELOG note for the CWE-676→CWE-78/94 category shift. |
| **Last updated** | 2026-07-02 |
| **Branch** | `feature/0057-cwe-agent-hardening` (working tree — 0060 uncommitted) |
| **Suites** | agents/cwe **632 passed / 1 skip** · agents/shared **977 passed** · ruff clean · idattestor VLT-1037/1038/1039/1043 shapes → **0** findings; `os.system` → exactly `[CWE-78]` (double-report gone) — verified live |

> Per CLAUDE.md, E2E/business-logic tests (T1–T15) are written **before** implementation. Nothing below is "done" until its tests pass AND the existing `agents/cwe` + `agents/shared` suites still pass.

## Checkpoints

### Phase 0 — Design & review ✅
| # | Item | Status |
|---|------|--------|
| 0.1 | Root cause reproduced (live regex matches `.exec()` method calls) | ✅ GREEN-1 confirmed |
| 0.2 | Fix verified (receiver-boundary kills FPs, preserves bare TPs) | ✅ GREEN-1 confirmed |
| 0.3 | Skill-CWE gate-eligibility confirmed (`SKILL_MAP.values()` loop) | ✅ GREEN-2 confirmed |
| 0.4 | RED/GREEN adversarial review (3 RED + 2 GREEN) folded into LLD | ✅ Done |
| 0.5 | Feature docs created (plan/status/rollback) | ✅ This commit |

### Phase 1 — Language-aware matcher ✅
| # | Item | Tests | Status |
|---|------|-------|--------|
| 1a | `_SINKS_BY_LANG` registry (c/cpp/go/rust; memory-unsafe library fns only) + language-scoped scan via `detect_language` | test_dangerous_function_check (18) | ✅ |
| 1b | Injection gains cross-lang OS-command sinks (Java `Runtime.exec`/`ProcessBuilder`, PHP `shell_exec`/`passthru`/`proc_open` → CWE-78) | test_injection_command_langs (7) | ✅ |
| 1c | Reworked existing tests to moved-ownership contract (os.system/Runtime.exec → not owned by dangerous_function; `_classify_match`/`_STRING_FN` refs updated in test_audit_fixes_batch) | — | ✅ |
| 1d | Extend `_LANGUAGE_BY_EXT` + `CODE_EXTENSIONS` (`.cjs/.mts/.cts/.pyw/.phtml/.erb/.m/.mm`) | test_language (+8), test_objc_strcpy | ✅ |
| 1e | Kill switch `VULTURE_CWE_DISABLE_DANGEROUS_FN` (renamed from the `_LANGUAGE_AWARE_` draft name; disables the skill, reuses shared `env_truthy`) | test_disable_kill_switch | ✅ |
| 1f | Def-line skip for retained sinks (`fn transmute(...)` etc.) via per-match `_DEF_BEFORE` (not a line skip — single-line funcs that *call* a sink still fire) | test_rust_fn_named_transmute_definition_not_flagged | ✅ |
| 1g | Objective-C (`.m`/`.mm`) → C sink set (`objc` key in `_SINKS_BY_LANG`) | test_objc_strcpy_flagged_676 | ✅ |

**Deferred item now landed (2026-07-02):** all Phase-1 deferrals (1d extension map, 1e kill switch, 1f def-skip, bare PHP/Ruby `system` — language-scoped in the injection skill, resolving the CWE-94 token collision) are implemented. `.m` maps to `objc` (MATLAB `.m` ambiguity accepted — low FP risk).

### Phase 2 — Corpus + gate ✅
| # | Item | Tests | Status |
|---|------|-------|--------|
| 2a | 18 first-party single-target fixtures under `fixtures/dangerous_functions/` (CWE-676: 6 pos [C/Go/Rust] + 6 clean [strncpy, comment, **idattestor regex.exec + multi.exec .ts shapes**, safe Go/Rust]; CWE-242: 3 pos + 3 clean [fgets, comment, `widgets()` boundary]) | corpus gate | ✅ 676 recall 1.0/fp 0.0; 242 recall 1.0/fp 0.0 |
| 2b | `manifest.d/dangerous_functions.yaml` (auto-globbed) | — | ✅ |
| 2c | **No `gates.yaml` edit needed** (strict defaults apply); regenerated `VERIFIED_CWES.md` → N 10→**12** | test_report_coverage_golden (25) | ✅ |

### Phase 3 — Docs ✅
| 3a | `skills/SKILLS.md` `dangerous_function_check` rewritten (language-scoped sinks, boundary rules, recall-over-corpus wording, kill switch) + injection CWE-78 entry updated (cross-lang sinks) | — | ✅ |
| 3b | `CLAUDE.md` env-var table row for `VULTURE_CWE_DISABLE_DANGEROUS_FN` | — | ✅ |

## Decision log
- **2026-07-01 (a)** — LLD drafted from idattestor triage + RED/GREEN review. Two blockers surfaced: (1) CWE-78↔676 pre-existing double-report; (2) `VERIFIED_CWES.md` golden chicken-and-egg — resolved by atomic regen (R9).
- **2026-07-01 (b) — DESIGN PIVOT (maintainer):** OD-1 = **Option 1 "Pure CWE-676 + move exec to injection"**; OD-3 = **Go + Rust in scope**. Code read revealed the injection skill already owns eval/exec/command WITH the receiver-boundary fix (`injection_check.py:67-72,120-128`). So: `dangerous_function` narrows to memory-unsafe **library** functions (C/C++ string-handling + `gets`→242, Go `unsafe.*`, Rust `transmute`/`get_unchecked`/raw-ptr), drops eval/exec/os.system/os.popen; `injection` gains Java/PHP/Ruby OS-command-exec (CWE-78). **Two skills touched.** Existing 2 dangerous_function unit tests reworked to reflect moved ownership (maintainer-approved contract change). See plan §DECISION block.

## Audit (end-to-end) — 2026-07-02
Self-audit + independent reviewer pass. 13 findings enumerated; **#1–#6 fixed** (TDD for the two correctness bugs), rest accepted/noted.
- **#1 [HIGH, FP]** Ruby/PHP `def system(...)` definition FP'd as CWE-78 → added `_CMD_DEF_BEFORE` def-guard in `_check_command`. Verified: `def system` → no CWE-78.
- **#2 [MED, FN]** `SAFE_STATIC_CALL` substring-matched `shell_exec("x")`/`Runtime….exec("x")` and silently suppressed them → anchored to bare `(?<![\w.>])(?:exec|eval)\(`. Verified: static `shell_exec` → CWE-78.
- **#3 [MED, perf]** `detect_language` was per-line in `_check_command` → hoisted to once-per-file in `_analyze_file`, threaded as `lang`.
- **#4 [LOW, coverage]** added Go `unsafe.Slice/SliceData/Add/String/StringData` to `_GO_UNSAFE`.
- **#5 [LOW, DRY]** centralized `env_truthy` into `shared/shared/env.py`; removed the 3 duplicate `_env_truthy` defs (dangerous_function/catalog_detector/agent.py) + now-unused `os` imports.
- **#6 [LOW, robustness]** CWE-242 corpus 3+3 → **4+4** (gate margin).
- **Accepted/noted:** C-style def-skip gap, `.m`/MATLAB ambiguity, `.get_unchecked` any-receiver, ProcessBuilder severity, pre-existing string-literal FP, dead `sub` keyword, CWE-676 category-shift (changelog note).
- Re-audit: idattestor VLT-1037/1038/1039/1043 → 0 findings; `os.system` → exactly `[CWE-78]` (double-report gone). Suites: cwe **632 passed/1 skip**, shared **977 passed**, ruff clean, golden regenerated (CWE-242 4/4).

## Verified-coverage impact (actual)
- N: **10 → 12** — CWE-676 (6 pos / 6 clean) and CWE-242 (4 pos / 4 clean) now **VERIFIED** (recall 1.0 / fp 0.0), computed by the gate, not asserted.
- `VERIFIED_CWES.md` regenerated and committed with the fixtures — both CWEs moved DECLARED-ONLY → VERIFIED; golden staleness test green.

## Files changed (uncommitted)
- **Skills**: `dangerous_function_check.py` (rewritten), `injection_check.py` (CWE-78 cross-lang sinks + PHP/Ruby `system` + audit #1/#2/#3), `catalog_detector.py` + `agent.py` (env_truthy centralization).
- **Shared**: new `shared/env.py`; `validate/language.py` (+8 extensions); `tools/file_scanner.py` (`CODE_EXTENSIONS` +8).
- **Tests**: `test_dangerous_function_check.py`, `test_injection_command_langs.py` (new), `test_audit_fixes_batch.py` (reworked), `test_language.py`.
- **Corpus**: 20 fixtures under `fixtures/dangerous_functions/` + `manifest.d/dangerous_functions.yaml` + regenerated `VERIFIED_CWES.md`.
- **Docs**: `docs/features/0060_*`, `skills/SKILLS.md`, `CLAUDE.md`.

## Open decisions — RESOLVED
- **OD-1** (command-exec ownership) → Option 1: pure CWE-676, exec ceded to injection. ✅
- **OD-3** (Go/Rust in scope) → yes, as memory-unsafe primitives. ✅
- OD-2 (`unknown` policy → no sinks; injection covers exec cross-file), OD-4 (skill home), OD-5 (kill switch = one-release) → decided per plan.

## Remaining (non-blocking, awaiting maintainer)
- **Commit** the work (branch off `main` — currently on `feature/0057-cwe-agent-hardening`).
- **CHANGELOG note**: shell/code-exec findings shift CWE-676 → CWE-78/CWE-94 (`dangerous_function` is now a no-op for Python/JS/Java/etc.); downstream consumers keying on CWE-676 for shell-exec should be told.
