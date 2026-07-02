# Feature 0060 — Language-Aware Dangerous-Function Detection (CWE-676 / CWE-242) + Corpus Gate

| | |
|---|---|
| **Feature** | 0060_cwe676_language_aware |
| **Status** | 🟡 DRAFT — submitted for review (no code written) |
| **Date** | 2026-07-01 |
| **Author** | bobinson |
| **Depends on** | 0057 (corpus harness + `gates.yaml` + `VERIFIED_CWES.md` attestation + `_DEDICATED_SKILL_CWES`) |
| **Source** | idattestor audit triage (VLT-1037/1038/1039/1043 — 8 of 17 "critical" rows were CWE-676 FPs) + a RED/GREEN adversarial design review (3 RED + 2 GREEN agents) |

> **Review provenance.** This LLD was hardened by an adversarial pass: RED-1 (false-negatives), RED-2 (false-positives / regex correctness), RED-3 (architecture / process), GREEN-1 (core-fix verification — ran the real regexes), GREEN-2 (corpus/architecture-fit verification). Their confirmed findings are folded into the requirements below; the two genuine trade-offs they surfaced are in §11 Open decisions.

> **DECISION — 2026-07-01 (maintainer): Option 1 "Pure CWE-676 + move exec to injection" adopted.**
> A code read during planning found the **injection skill already owns execution sinks _and already has the receiver-boundary fix_**: `injection_check.py:121-122` (`(?<![\w.\]\)])eval|exec\s*\(`, comment cites `myRegex.exec(input)`), `:120-128` (`new Function`, `globalThis.eval`, `setTimeout("…")` → CWE-94), `:67-72` (`os.system`, `os.popen`, `subprocess(shell=True)`, narrow Go `exec.Command("sh",…)` → CWE-78). The idattestor FPs + double-reports trace to `dangerous_function` **redundantly** matching `eval`/`exec`/`os.system` that injection handles correctly. So this feature is now:
> - **676 (`dangerous_function`) is narrowed to memory-unsafe *library* functions only** — C/C++ string-handling (`strcpy`/`strcat`/`sprintf`/`vsprintf`/`scanf`/`sscanf`/`strdup`/`strndup`/`vfprintf`/`vprintf`/`tmpnam`/`tempnam`/`mktemp`/`alloca`/`getwd` → 676; `gets` → 242), **Go** `unsafe.Pointer`/`unsafe.Sizeof`/`uintptr(` conversions (676), **Rust** `std::mem::transmute`/`mem::transmute`/`.get_unchecked(`/`.get_unchecked_mut(`/`ptr::read`/`ptr::write` (676) — each **language-scoped**. Rust bare `unsafe {` blocks are OUT (too noisy; only the specific dangerous ops).
> - **676 DROPS** `eval`, `exec`, `os.system`, `os.popen` (cede to injection — removes the FPs *and* both double-reports).
> - **injection GAINS** cross-language OS-command-exec (CWE-78, `check_id=cwe.injection.command`): Java `Runtime.getRuntime().exec(`/`ProcessBuilder(`, PHP `system(`/`exec(`/`shell_exec(`/`passthru(`/`proc_open(`/backticks, Ruby `system(`/`exec(`/`%x{}`/backticks — so nothing is lost when 676 sheds them. New patterns reuse injection's boundary + safe-validation guard, and must not regress CWE-78's existing `fp_rate=0.0` gate.
> - **Two skills touched** (`dangerous_function` narrowed, `injection` extended). OD-3: **Go + Rust in scope** (as memory-unsafe primitives above; their exec stays injection's domain).
> Everywhere below that says "676 owns exec sinks / build a multi-language exec registry in 676," read the narrowed design above. §11 open decisions OD-1/OD-3 are now **RESOLVED**.

---

## 1. Problem (grounded)

`agents/cwe/cwe_agent/skills/dangerous_function_check.py:52-57` matches dangerous-function tokens **language-agnostically**:

```python
_EXEC_FN = re.compile(r"\b(system|popen|eval|exec)\s*\(" | ...)   # (real source is a multiline alternation)
```

`\bexec\s*\(` matches `.exec(` **method calls** because `\b` sits between `.` and `exec`. **GREEN-1 reproduced this**: the live regex matches `regex.exec(didUri)`, `await multi.exec()`, `cleanup.exec()` (all FPs) as well as the true positives `os.system(cmd)`, `system(cmd)`, `Runtime.getRuntime().exec(cmd)`, `eval(x)`.

Real impact: in the idattestor audit, **8 of 17 "critical" rows were CWE-676 FPs from this one matcher** (VLT-1037 `passwordlessTokenStore.ts` Redis `multi.exec()`; VLT-1038 `didService.ts` `RegExp.exec()`; VLT-1039 `RedisAdapter.ts` ×5 Redis `.exec()`; VLT-1043 `didCreationWorker.ts` `RegExp.exec()`).

Per the 0057 trace these FPs are **uncorrectable downstream**: findings carry `check_id` → `validate/llm_judge.py:_is_l5_exempt` neutralizes any L5 demotion (`deterministic_authoritative`), and the validate phase is length-preserving. **Only a matcher fix removes them.** CWE-676 + CWE-242 are also **ungated** (absent from all `manifest.d` fragments, not counted in N=10); the 0057 plan *deferred* dataflow-class dangerous-function work to a future AST/taint tier that maps to feature 0058 (draft; additive — it will not fix this skill).

## 2. Goal

1. **Language-aware detection** — apply only the sink set relevant to the file's `detect_language()` result, and **never** match a receiver-qualified method call (`.exec()`, `->exec()`, `::exec()`, `?.exec()`) as a bare dangerous builtin.
2. **Corpus-gate CWE-676 + CWE-242** under the 0057 gate (`recall=1.0, fp_rate=0.0`) with clean-twin fixtures encoding the exact idattestor FP shapes, so the fix is CI-enforced and the two CWEs are counted in N.

**Non-goal for v1:** expanding the sink set into new command-execution APIs (that overlaps the injection skill — see §11 OD-1). This feature makes the *existing* sink set language-aware and correct, then gates it.

## 3. Requirements

| ID | Requirement |
|----|-------------|
| **R1** | Detection is scoped by `detect_language(file_path)` (reuse `shared/validate/language.py`; **GREEN-2** confirmed it is an in-convention cross-package import and works on the corpus runner's neutral `f.<ext>` copies). |
| **R2** | The receiver-boundary rule applies to **every** bare sink (`system`, `popen`, `eval`, `exec`, `gets`, string-handling names), not only `exec` (**RED-2 C2**). It must reject a receiver even across whitespace — `a . exec(`, `a -> exec(`, `a :: exec(` must NOT fire (**RED-2 C1**; a single-char lookbehind is insufficient — use an explicit receiver-reject guard since Python `re` forbids variable-width lookbehind). It must still fire on indirect/optional forms `eval?.(x)` and `(0,eval)(x)` (**RED-1 H10**). |
| **R3** | **Qualified** sinks that must survive as positives are matched by explicit receiver+method regexes, distinct from the bare-suppression rule: `os.system`, `os.popen`, `Runtime.getRuntime().exec`. These collide with R2's `.exec`/`.system` suppression on the same token, so they are matched by their own branch (**RED-3 #3 / GREEN-1** — dropping them regresses `test_fires_on_python_os_system` + `test_fires_on_java_runtime_exec`). Do NOT *add* new command-exec sinks (see OD-1). |
| **R4** | The per-language spec is **data, not code** — a declarative compiled-regex registry (`LANG_SINKS: dict[str, tuple[SinkSpec, ...]]`), one generic matcher. Each concern (registry lookup / bare-match / qualified-match / severity / suppression / comment-skip) is its own function so radon/gocyclo stay < ~10 (**RED-3 #7**). |
| **R5** | Preserve still-correct behaviour AND add two new suppressions: (a) safe-context suppression (bounded/safe alt in prior window), (b) const-string severity downgrade — **with the same receiver boundary applied to `_CONST_STRING_ARG`** (**RED-2 M1 / GREEN-1**), (c) comment-line skip, (d) generated/test-file skip, (e) **NEW: skip definition/declaration lines** (`def system(`, `function eval(`, `void system() {`, `interface { exec(): void }`, method decl `exec() {`) (**RED-2 H1**). |
| **R6** | Extend `_LANGUAGE_BY_EXT` in `shared/validate/language.py` **as part of this feature** to close silent coverage cliffs: `.cjs`→js, `.mts`/`.cts`→ts, `.pyw`→python, `.phtml`→php, `.erb`→ruby, `.m`/`.mm`→objc(treat as c for string sinks) (**RED-1 H1/H2/H9**). `unknown`-language files retain a **scripting safety-net** set (bare `eval`/`exec`/`system` + C string-handling), NOT a C-only set, so an unlisted extension does not lose exec-sink coverage entirely (**RED-1 cross-cutting; overrides the naive "C-only universal" idea**). |
| **R7** | Unchanged dedup contract: findings keep `check_id = cwe.dangerous_function.cwe_<id>` (the `(check_id, file_path)` dedup key). CWE-676/242 are **already** in `_DEDICATED_SKILL_CWES` (`catalog_detector.py:88` + auto-discovery) — this feature must **not remove** them (**GREEN-2 Claim 4**: "preserve," not "add"). |
| **R8** | **Corpus**: ≥6 positive + ≥6 clean per gated CWE (676, 242), spanning ≥ C, Python, Java, JS/TS. Fixtures are **minimal, single-target files, file-level scored** — each 676/242 clean twin must contain ZERO tokens the 676/242 matcher fires on (**RED-3 #4 / GREEN-2 Claim 2**). Clean twins MUST include: JS `regex.exec()`, ioredis `multi.exec()`, a spaced receiver `a -> exec()`, a `.eval()`/`.system()`/`.popen()` method call, a *definition* line `def system(...)`/`void system(){}`/`interface{exec():void}`, a docstring mentioning `system(cmd)`, `subprocess.run([...])` safe list-form, a `.h` C++-method header, a var named `system`/`exec`, a commented dangerous call, a safe-context `strncpy`. First-party Apache-2.0 (0057 R14). |
| **R9** | **Gate + attestation (atomic)**: add CWE-676 + CWE-242 to `gates.yaml` at the strict default (`min_recall=1.0, max_fp_rate=0.0, min_fixtures=3`), **and in the same commit** regenerate `VERIFIED_CWES.md` via `agents/.venv/bin/python agents/cwe/tests/corpus/report_coverage.py --write`. The byte-exact golden test (`test_report_coverage_golden.py`, 0057 T22) **will fail mid-PR** until the golden is regenerated — this is a required ordered step, not a doc chore (**RED-3 #2 / GREEN-2 Claim 3**). N grows 10 → 12 (computed, never hand-typed). |
| **R10** | No regression: the existing 9 `test_dangerous_function_check.py` cases are the **frozen contract** — extended only, never weakened (CLAUDE.md invariant). In particular `test_fires_on_java_runtime_exec` pins `Runtime.getRuntime().exec` as a *qualified* positive that R2's receiver-boundary must NOT suppress. |
| **R11** | Complexity within target (< ~10 paths/fn). |
| **R12** | Perf/ReDoS: ext-indexed dispatch (a file runs only its language's specs); line-length caps preserved; all regexes bounded. Detection stays single-line; multi-line calls (e.g. Java builder-chain wrap `Runtime.getRuntime()\n.exec(cmd)`) are a **documented known FN class** with a corpus positive to track it (**RED-1 H4**), not fixed in v1 (that is the 0058 taint tier's job). |
| **R13** | Escape hatch `VULTURE_CWE_DISABLE_LANGUAGE_AWARE_DANGEROUS_FN=true` (matches the `VULTURE_CWE_DISABLE_*` convention; reuse `catalog_detector._env_truthy`) → fall back to the legacy matcher for one release. Document it in CLAUDE.md's env-var table (**RED-3 #5**). |

## 4. Architecture

```
per file:  lang = detect_language(path)                          # R1 (extended ext map, R6)
  specs = LANG_SINKS.get(lang, LANG_SINKS["_scripting_safety_net"])   # R6
  per line:
    if comment_line or definition_line:  skip                    # R5c/R5e
    m = generic_match(line, specs):
        • bare-sink regex + receiver-reject guard (all sinks)     # R2
        • qualified-sink regexes (os.system, Runtime….exec)      # R3
    if m and not safe_context(prior_window):                     # R5a
        sev = severity(m, const_string_arg w/ receiver boundary) # R5b
        emit _build_finding(check_id=cwe.dangerous_function.cwe_<id>)  # R7 unchanged
Corpus:  manifest.d/dangerous_functions.yaml  (≥6 pos + ≥6 clean per CWE, single-target)  # R8
Gate:    gates.yaml += CWE-676, CWE-242  →  report_coverage.py --write  →  N 10→12       # R9
```

**Verified load-bearing facts** (GREEN-1/GREEN-2): `corpus_runner.py:146` runs `for fn in SKILL_MAP.values()` → skill-emitted CWEs are gate-eligible (CWE-78/89 precedent); `dangerous_function` is in `SKILL_MAP` (`skills/__init__.py:76`); scoring is file-level, target-CWE-scoped (`corpus_runner.py:206-218`) → a clean twin is a 676 FP iff `CWE-676` fires anywhere in it.

**Receiver-reject guard** (RED-2 C1/C2): because Python `re` forbids variable-width lookbehind, whitespace-separated receivers are caught with an explicit reject pass, e.g. fire the bare sink only if the line does NOT match `[\w)\]]\s*(?:\.|->|::|\?\.)\s*(?:system|popen|eval|exec)\s*\(` at that position. Final form to be pinned in tests before implementation.

## 5. Work items (test-first, per CLAUDE.md)

### Phase 1 — Language-aware matcher (the FP fix; independently shippable)
| Item | What | Where | Effort |
|---|---|---|---|
| P1a | `SinkSpec` + `LANG_SINKS` registry (data) incl. `_scripting_safety_net` for unknown | new `skills/dangerous_fn/registry.py` | M |
| P1b | Generic matcher: bare + receiver-reject guard (R2) + qualified branch (R3); each concern its own fn (R4/R11) | `skills/dangerous_fn/matcher.py` | M |
| P1c | Rewire `dangerous_function_check.py` to route by `detect_language`; keep safe-context / severity(+receiver-boundary const-string) / comment-skip; add definition-line skip (R5) | `dangerous_function_check.py` | M |
| P1d | Extend `_LANGUAGE_BY_EXT` (R6) | `shared/validate/language.py` | S |
| P1e | Escape hatch `VULTURE_CWE_DISABLE_LANGUAGE_AWARE_DANGEROUS_FN` via `_env_truthy` (R13) | `dangerous_function_check.py` | S |
| — | Tests T1–T12 written FIRST | `tests/unit/` | — |

### Phase 2 — Corpus + gate (makes the fix permanent + grows N)
| Item | What | Where | Effort |
|---|---|---|---|
| P2a | First-party Apache-2.0 fixtures (≥6 pos + ≥6 clean per CWE, ≥4 langs, single-target) | `tests/corpus/fixtures/firstparty/...` | M |
| P2b | `manifest.d/dangerous_functions.yaml` (positive/negative entries) | `tests/corpus/manifest.d/` | S |
| P2c | `gates.yaml` += CWE-676, CWE-242; **regenerate + commit** `VERIFIED_CWES.md` (same commit, R9) | `tests/corpus/` | S |
| — | Tests T13–T15 | | — |

### Phase 3 — Docs
| P3a | Update CWE agent `SKILLS.md` (language-aware behaviour; recall-over-corpus wording, NOT "complete sink coverage" — **RED-1 H6/H7**) + CLAUDE.md env-var row | | S |

## 6. Test plan (test-first, Tn)

- **T1** JS/TS `const m = regex.exec(x)` → **no** CWE-676 (VLT-1038). *(GREEN-1: fails on current code → valid RED.)*
- **T2** `await multi.exec()` / `cleanup.exec()` in `.ts` → none (VLT-1037/1039/1043; one test subsumes all three IDs).
- **T3** Python bare `exec(user_code)` → CWE-676 critical (TP preserved).
- **T4** C `strcpy(dst,src)` fires; a `.js` line with `strcpy(` does NOT (language narrowing — an *intentional* new contract, no existing test locks `.js strcpy` as positive).
- **T5** Java `Runtime.getRuntime().exec(cmd)` fires (R3 qualified); `foo.exec(x)` in `.java` does not (R2).
- **T6** Safe-context suppression + const-string downgrade preserved; downgrade triggers on **bare** `system("ls")` and does NOT resurrect a method-call FP (**GREEN-1**).
- **T7** Definition lines `def system(...)` / `void system(){}` / `interface{exec():void}` → no finding (**RED-2 H1**).
- **T8** Spaced receiver `a -> exec()`, `a . exec()`, `a :: exec()` → no finding (**RED-2 C1**); `.eval()`/`.system()`/`.popen()` → none (**RED-2 C2**).
- **T9** Indirect/optional `eval?.(x)`, `(0,eval)(x)` → CWE-676 (**RED-1 H10**).
- **T10** Extension coverage: `.cjs`/`.mts`/`.pyw`/`.phtml`/`.m` resolve to the right language and fire on their bare sinks (**RED-1 H1/H2/H9**); `unknown` extension still fires on bare `eval`/`exec`/`system` (safety net, R6).
- **T11** `subprocess.run([...])` safe list-form → no finding; a docstring/triple-quoted line mentioning `system(cmd)` → no finding (**RED-2 H2/H3**).
- **T12** Escape hatch on → legacy behaviour (R13).
- **T13** CWE-676 passes the corpus gate (recall 1.0, fp 0.0). **T14** CWE-242 passes. **T15** `VERIFIED_CWES.md` regenerated, not stale; N reconciles to 12 (0057 T22 analogue).
- **Regression:** full `agents/cwe` + `agents/shared` suites green; the 9 existing dangerous-function tests unchanged (R10).

## 7. Rollout & rollback
Phase 1 is independently shippable and removes the FPs immediately (`candidate`-equivalent: skill findings already deterministic). Phase 2 corpus-gates it. Gate each phase. Rollback: `VULTURE_CWE_DISABLE_LANGUAGE_AWARE_DANGEROUS_FN=true` (one-release hatch); full revert = the two commits (matcher, corpus+golden). See `0060_rollback_plan.md`.

## 8. Risks & mitigations
| # | Risk | Mitigation |
|---|---|---|
| 1 | Over-narrowing FN (aliased imports `from os import system as s`, dynamic dispatch) | keep bare scripting sinks; aliasing is 0058 taint scope; corpus positives lock the must-catch set (incl. `from os import system; system(x)`) |
| 2 | `detect_language` cliffs (it is a *hint* tool by design) | extend `_LANGUAGE_BY_EXT` (R6); `unknown` → scripting safety-net set, not C-only |
| 3 | New FPs: definitions / docstrings / `subprocess.run([...])` | R5e def-skip; docstring FP a documented limitation + clean twin; qualified python requires `shell=True` (NOT added in v1 — OD-1) |
| 4 | `fp_rate=0.0` fails on a self-inflicted clean-twin | single-target minimal fixtures, file-level scored (R8) |
| 5 | Golden `VERIFIED_CWES.md` chicken-and-egg | regen + commit atomically (R9) |
| 6 | Complexity outlier | concern-per-function (R4/R11) |
| 7 | Stale local `agents/.venv` (points at a `vulture-gh` sibling predating `validate/`) | `make install` before `make cwe-corpus` — **build note, not an LLD defect** (GREEN-2 Claim 5) |
| 8 | 0058 Semgrep future double-report on 676 | handled at the Go L3 layer (0058 R5), not a 0060 blocker (RED-3 #6) |

## 9. Scope-lock — OUT
- **CWE-532** log-substring FP (the `token`/`password` matcher) — same *class* of fix; sibling follow-up, NOT this feature (user asked for 676).
- **New command-exec sinks** (subprocess `shell=True`, `child_process.exec`, `exec.Command`) — overlaps injection skill CWE-78; see OD-1.
- **AST/dataflow/taint / multi-line / aliasing** — feature 0058.
- **Migrating other skills** to the language-aware primitive — the registry is designed reusable; adoption is a follow-up.

## 10. Complexity / DRY notes
Registry-as-data + one generic matcher (R4) is lower-complexity than a per-language `if` cascade. Reuses `shared/validate/language.py` (no new language detector), `catalog_detector._env_truthy`, `shared.tools.snippet.extract_snippet`, existing `COMMENT_INDICATORS` / `is_test_file` / `is_generated_file`.

## 11. Open decisions — for maintainer review
1. **[BLOCKER] CWE-78 ↔ CWE-676 double-report on command-exec sinks.** RED-3 confirmed `os.system(cmd)` is *already* reported twice today — `injection` emits CWE-78, `dangerous_function` emits CWE-676, different `check_id`s → the `(check_id, file_path)` dedup never collapses them. This LLD **avoids amplifying it** by NOT adding new command-exec sinks (§9), but the pre-existing overlap remains. Options: (a) **cede command-exec to the injection skill** (676 keeps only string-handling + `eval`/`exec` code-eval) — cleanest, but changes what `check_dangerous_function` emits for `os.system`/`Runtime.exec` and would require reworking (not weakening) 2 existing unit tests → needs maintainer sign-off under the E2E-test invariant; (b) add a **same-line cross-skill dedup** (keep the more-specific CWE-78); (c) **defer** as a separate finding. *Recommend (c) for 0060 + open a sibling issue; do not let it block the FP fix.*
2. **`unknown`-language policy** — recommend the scripting safety-net set (R6) over C-only, to avoid coverage cliffs. Confirm.
3. **Language coverage in v1** — C/C++, Python, Java, JS/TS, PHP, Ruby. Include Go? (Go's exec is `exec.Command` — qualified, overlaps injection CWE-78; recommend OUT of 676, cede to injection.)
4. **Skill vs signature-tier home** — GREEN-2 confirmed the *skill* home is gate-eligible and sound; recommend keep as skill (surgical, no migration). Confirm.
5. **Escape-hatch retention** — one release then remove, or keep permanently.

## 12. Acceptance criteria
- ☐ T1–T15 green; existing `agents/cwe` + `agents/shared` suites green; `ruff` clean.
- ☐ The idattestor FP shapes (`regex.exec`, `multi.exec`, `cleanup.exec`) → **0** CWE-676 findings; C `strcpy`, Python `exec()`, Java `Runtime.getRuntime().exec` still fire.
- ☐ CWE-676 + CWE-242 corpus-gated (recall 1.0, fp 0.0); `VERIFIED_CWES.md` regenerated in-commit; N = 12 (computed).
- ☐ No new double-report introduced; `check_id` frozen; OD-1 resolved or explicitly deferred.
- ☐ Complexity within target; escape-hatch rollback verified.
