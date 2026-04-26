# 0038 — Implementation Status

**Branch**: tbd (recommend `feat/0038-scan-xxe-git-hardening`)
**Status**: PLANNED
**Owner**: tbd
**Started**: not started
**Target Phase 1**: ~1 day for one developer
**Target Phase 2**: ~1-2 days for one developer
**Total**: ~2-3 days

## Phase summary

| Phase | Status | E2E green | Notes |
|---|---|---|---|
| Phase 1 — XML entity-injection remediation (defusedxml) | PLANNED | — | 14 attack (1 primary TDD + 6 effective TDD + 8 defense-in-depth) + 5 benign + 3 sitemap integration tests |
| Phase 2 — Git clone + command hardening | PLANNED | — | 5 flag-presence + 4 hook-blocking + 3 Python tests; `core.fsmonitor` RCE proven exploitable in current code |

## Detailed task list

### Phase 1 — XML entity-injection remediation (establishes shared `safe_input/` package)

#### 1.1 Establish `safe_input` package + add defusedxml to shared
- [ ] 1.1.t1 — Create `agents/shared/shared/safe_input/__init__.py` with initial skeleton
- [ ] 1.1.t2 — Create `agents/shared/shared/safe_input/README.md` per Appendix A template
- [ ] 1.1.t3 — Add `"defusedxml>=0.7.1"` to **`agents/shared/pyproject.toml`** (transitive to all agents)
- [ ] 1.1.t4 — `pip install -e .` in `agents/shared/` and `agents/discover/`
- [ ] 1.1.t5 — Smoke imports verified
- [ ] 1.1.t6 — Package skeleton imports cleanly

#### 1.2 Implement `safe_input/xml.py` (canonical home of safe XML parsing)
- [ ] 1.2.t1 — Create `agents/shared/shared/safe_input/xml.py` with `safe_xml_parse`
- [ ] 1.2.t2 — Update `safe_input/__init__.py` to re-export `safe_xml_parse`
- [ ] 1.2.t3 — Edit `_shared.py`: delete local definition; import from shared
- [ ] 1.2.t4 — `ruff check agents/shared/ agents/discover/` passes
- [ ] 1.2.t5 — Smoke import test (both shared and discover paths)
- [ ] 1.2.t6 — Run discover unit suite, no regressions

#### 1.3 Refactor `_parse_sitemap_xml` in `crawl.py` to import safe parser
- [ ] 1.3.t1 — Replace `from xml.etree import ElementTree` with `from shared.safe_input.xml import safe_xml_parse`
- [ ] 1.3.t2 — Replace function body to call `safe_xml_parse`
- [ ] 1.3.t3 — **Delete `# noqa: S314` suppression**
- [ ] 1.3.t4 — Verify `_MAX_SITEMAP_SIZE = 5_000_000` unchanged
- [ ] 1.3.t5 — `ruff check` passes
- [ ] 1.3.t6 — Run existing unit tests, no regressions

#### 1.4 Test corpus (lives in shared/safe_input tests)
- [ ] 1.4.t1 — Create `agents/shared/tests/unit/safe_input/__init__.py` (empty marker)
- [ ] 1.4.t2 — Create `agents/shared/tests/unit/safe_input/test_xml.py` with **14 attack samples** (1 primary + 13 supporting) + 5 benign tests **verbatim**
- [ ] 1.4.t2b — Create `agents/discover/tests/unit/test_crawl_sitemap_xxe.py` with 3 sitemap integration tests
- [ ] 1.4.t3 — Run new tests (shared + discover paths), ALL must pass after fix
- [ ] 1.4.t4 — Run full discover unit suite, no regressions
- [ ] 1.4.t5 — **MANDATORY** TDD red-baseline: revert fix, run 6 effective TDD tests, confirm ≥5 fail. Restore.
- [ ] 1.4.t6 — Run 8 defense-in-depth tests against unfixed code; confirm pass (documents expat baseline).

#### 1.5 Unified CI lint (covers Phase 1 XML + Phase 2 git + future safe_input modules)
- [ ] 1.5.t1 — Add `lint-no-direct-unsafe-input` Make target with all 6 dangerous-API sections (XML, yaml, pickle, shell, Python git, Go git)
- [ ] 1.5.t2 — Wire into CI workflow
- [ ] 1.5.t3 — Run lint, must pass (0 violations)
- [ ] 1.5.t4 — Negative test (Phase 1): temp-add `from xml.etree.ElementTree import fromstring`, verify lint catches it, revert
- [ ] 1.5.t5 — Negative test (Phase 2): temp-add `subprocess.run(["git", "log"])`, verify lint catches it, revert
- [ ] 1.5.t6 — Document the lint surface in `safe_input/README.md`

#### 1.6 Phase 1 acceptance
- [ ] `defusedxml>=0.7.1` in **agents/shared/pyproject.toml** (not discover)
- [ ] `agents/shared/shared/safe_input/{__init__,xml,README}` exist
- [ ] `_shared.py` deletes local `safe_xml_parse` and re-imports from shared
- [ ] `crawl.py` calls `safe_xml_parse`, `# noqa: S314` deleted
- [ ] All 14+5+3 = 22 new tests passing after fix
- [ ] Pre-fix: ≥5 of the 6 effective TDD tests fail; 8 defense-in-depth tests pass
- [ ] No regressions in existing tests
- [ ] `make lint-no-direct-unsafe-input` green
- [ ] PR description includes empirical proof transcript reference

---

### Phase 2 — Git clone + command hardening

#### 2.1 Hardening constants
- [ ] 2.1.t1 — Create `backend/pkg/gitutil/hardening.go` with `gitHardeningArgs()` and `gitCloneArgs()`
- [ ] 2.1.t2 — `go vet ./pkg/gitutil/`
- [ ] 2.1.t3 — Existing tests pass

#### 2.2 Apply to clone.go
- [ ] 2.2.t1 — Modify `Clone` to prepend hardening flags before `"clone"`
- [ ] 2.2.t2 — Existing `clone_test.go` passes
- [ ] 2.2.t3 — Manual command-line shape verification (covered by 2.5.t1)

#### 2.3 Apply to info.go
- [ ] 2.3.t1 — `isGitRepo` prepends `gitHardeningArgs()`
- [ ] 2.3.t2 — `gitCmd` prepends `gitHardeningArgs()`
- [ ] 2.3.t3 — Existing `info_test.go` passes

#### 2.4a Implement Python `safe_input/git.py` (canonical home)
- [ ] 2.4a.t1 — Create `agents/shared/shared/safe_input/git.py` with `GIT_HARDENING_ARGS`, `GIT_CLONE_ARGS`, `build_git_command()`
- [ ] 2.4a.t2 — Update `safe_input/__init__.py` to re-export the three git helpers
- [ ] 2.4a.t3 — Smoke import test for `build_git_command`

#### 2.4 Refactor git_history.py to use safe_input.git
- [ ] 2.4.t1 — Add `from shared.safe_input.git import build_git_command`
- [ ] 2.4.t2 — Replace manual cmd construction with `build_git_command(str(root), *args)`. No local `_GIT_HARDENING_ARGS` constant remains in `git_history.py`
- [ ] 2.4.t3 — Existing tests pass

#### 2.5 Test corpus
- [ ] 2.5.t1 — Create `backend/pkg/gitutil/hardening_test.go` with 5 flag-presence tests
- [ ] 2.5.t2 — Create `backend/pkg/gitutil/clone_security_test.go` with 4 hook-blocking tests
- [ ] 2.5.t3 — Create `agents/shared/tests/unit/safe_input/test_git.py` with 6 Python tests (under safe_input/ dir created in 1.4.t1)
- [ ] 2.5.t4 — `cd backend && go test ./pkg/gitutil/ -count=1 -v` ALL pass
- [ ] 2.5.t5 — `python3 -m pytest agents/shared/tests/unit/safe_input/test_git.py -v` ALL pass
- [ ] 2.5.t6 — TDD verification: temporarily remove one hardening flag, confirm a clearly-named test fails, restore

#### 2.6 CI lint (covered by unified §1.5 rule)
- [ ] 2.6.t1 — Verify §1.5 rule already includes git sections 5+6 (no separate Make target)
- [ ] 2.6.t2 — `make lint-no-direct-unsafe-input` passes after Phase 2
- [ ] 2.6.t3 — Negative test: change `clone.go` to drop `gitHardeningArgs()`; verify lint catches it; restore

#### 2.7 Phase 2 acceptance
- [ ] `backend/pkg/gitutil/hardening.go` exists with both args functions
- [ ] `agents/shared/shared/safe_input/git.py` exists
- [ ] `safe_input/__init__.py` re-exports git helpers
- [ ] `git_history.py` uses `build_git_command`; no local hardening constant
- [ ] All 5+4+6 = 15 new tests pass
- [ ] No regressions in existing gitutil tests
- [ ] `make lint-no-direct-unsafe-input` green (single rule covers Go + Python)
- [ ] TDD calibration verified

---

## Cross-cutting

- [ ] CC.1 — Each task committed separately (TDD discipline)
- [ ] CC.2 — Performance regression measured: < 5% overhead on parsing benchmarks
- [ ] CC.3 — Backwards compat: API signatures unchanged, no caller breaks
- [ ] CC.4 — PR description explicitly scopes to #1, #2, #3, #8, #9 (not #4, #5)
- [ ] CC.5 — Rollback procedure documented in 0038_rollback_plan.md
- [ ] CC.6 — Test corpus expansion convention documented

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-04-26 | Use defusedxml as the safe XML parser (MIT license, drop-in API). | spec |
| 2026-04-26 | Hardening flags applied to ALL git invocations (default-on, no opt-out) — clone, info.go gitCmd/isGitRepo, Python git_history.py git_log. | spec |
| 2026-04-26 | `safe.directory=*` accepted: Vulture clones+operates as same UID; ownership-bypass is intentional and documented. | spec |
| 2026-04-26 | `core.symlinks=false` accepted: trades symlink-as-symlink for symlink-as-text-file content; verify scan agents don't break. | spec |
| 2026-04-26 | `protocol.allow=user` + `protocol.file.allow=never` + `protocol.ext.allow=never` chosen for explicit blocking. | spec |
| 2026-04-26 | **Audit severity recalibration**: findings #1+#2 reframed from "CRITICAL XXE" to "HIGH XML entity-injection". Empirical reproduction showed Python 3.12+expat 2.7.3 already block classic file-disclosure XXE; the actually-exploitable surface is DOCTYPE-driven internal-entity smuggling. Fix scope unchanged (defusedxml closes both classes); only framing changed. | empirical |
| 2026-04-26 | **Phase 2 RCE confirmed**: `core.fsmonitor` arbitrary command execution proven against current `gitCmd`/`isGitRepo` pattern. Hardening flags block it. Severity stays HIGH. | empirical |
| 2026-04-26 | Test corpus reorganised into 1 primary TDD test (entity smuggling) + 6 effective TDD tests + 8 defense-in-depth tests, each labelled with its calibration status against current code. | spec |
| 2026-04-26 | **Establish `agents/shared/shared/safe_input/` as the shared safe-input boundary library**. `safe_xml_parse` (Phase 1) and `build_git_command` (Phase 2) live here; future safe wrappers (yaml, json, archive, base64, path, subprocess) follow the same pattern in feature 0039. defusedxml is a transitive dep via `agents/shared/pyproject.toml`, available to all agents. | user-confirmed |
| 2026-04-26 | Single unified `lint-no-direct-unsafe-input` Make target replaces per-phase lint rules. Grows by category as new safe wrappers are added; no architectural change needed for future expansions. | user-confirmed |
| TBD | Network-dependent regression test policy (skip-or-mock) | |
| TBD | When to fix #4 (SSH host-key) and #5 (token-in-URL) — separate features | |

## Out of scope (explicitly tracked)

- **Finding #4** (SSH `StrictHostKeyChecking=no`): needs design — TOFU vs pinned hosts.
- **Finding #5** (token in URL): needs refactor to `GIT_ASKPASS` or credential helper.
- **Finding #6** (misleading hardening comment in crawl.py): naturally fixed when we delete the `# noqa: S314` line in 1.3.t3.
- **Finding #7** (clone resource limits): separate feature.
- **Finding #10** (vulture-self-scan CI): separate feature.
- **Finding #11** (devdep supply chain): out of project scope.
- **Finding #12** (`isValidPythonModule` regression test): not regressing; revisit if module name ever becomes user-controlled.
