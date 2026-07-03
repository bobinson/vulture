# 0056 Release-Hardening — adversarial audit

End-to-end adversarial review of the **0056 release & supply-chain hardening**
design across four axes: **reliability, security, long-term maintenance,
documentation**. 0056 is **PLANNED (no code yet)**, so these are *design-stage*
findings — each ❌ below is a **build acceptance criterion**: the implementation
must satisfy it before the component ships. Re-run this audit when 0056 lands.

Source design: [`../features/0056_release_hardening/0056_implementation_plan.md`](../features/0056_release_hardening/0056_implementation_plan.md).

## Verdict

**AMBER — direction sound, 9 must-fixes before build.** The C1 + C4 safety core
closes the real hole (lockfile drift merging with no CI gate), and the prior §0
re-scope (dispatch-only C2/C5, disable Dependabot pip updates) is the right call
for a solo-maintainer repo. But the fresh sweep found that several §0
*resolutions are under-specified or wrong*, two C-component mechanisms **don't
work as written**, and the re-scope is only half-applied to the LLD prose.

| Axis | Verdict | Headline |
|------|---------|----------|
| Reliability | 🟠 AMBER | `gen-lockfile.sh` still silently drops the Darwin split (reproduced); `--exclude-newer` date source undefined |
| Security | 🟠 AMBER | default `GITHUB_TOKEN` **cannot** read Dependabot alerts; C1 base-ref read mechanics broken |
| Long-term maintenance | 🟠 AMBER | C1 location self-contradicts; C6 duplicates an existing test suite; uv single-source incomplete |
| Documentation | 🟠 AMBER | §0 re-scope not folded into §5/§6/§7; C3 scope stated three ways; one runbook link missing |

## Must-fix before build

| # | Axis | Defect | Fix (acceptance criterion) |
|---|------|--------|----------------------------|
| **M1** | rel/sec | **`gen-lockfile.sh` fails OPEN on the Darwin split.** `[ -f "$CONSTRAINTS" ] && …` silently skips the constraint if the file is absent; `--universal` then **succeeds** and emits `cryptography==49.0.0` (no Intel-mac wheel) — re-breaking darwin/amd64. *Reproduced.* §0's resolution ("fail closed if `--universal` can't resolve") is wrong — universal resolves fine. | **Require** `lockfile-constraints.txt` (`[ -f … ] \|\| exit 1`); fail closed on universal→host fallback; assert the `cryptography==… ; sys_platform == 'darwin'` line is present **in single-quote form** (uv's output), not the constraint's double-quote form. |
| **M2** | security | **Default `GITHUB_TOKEN` cannot read `/dependabot/alerts`** (`security-events: read` = code-scanning only; 403 even at `write-all`). C5's stated permission is wrong; C4's `gh api` works only with a PAT/App-authed `gh`. | C5 requires a `DEPENDABOT_ALERTS_TOKEN` (PAT/App) — weigh that secret's blast radius in a digest workflow; C4 documents the PAT requirement and treats a 403 as a loud warn (not "network down"). Fix plan §5/§9 + status. |
| **M3** | security | **C1 base-ref read is broken as written.** `origin/${{ github.base_ref }}` is absent after a default `pull_request` checkout (depth-1 of the merge ref). | `setup-pinned-uv` must `git fetch --depth=1 origin "$GITHUB_BASE_REF"` then read `FETCH_HEAD:scripts/uv-version.sh` (or `fetch-depth: 0`); pin to literal `main`, not attacker-chosen `base_ref`; validate `^[0-9]+\.[0-9]+\.[0-9]+$` **before** passing to `setup-uv`. |
| **M4** | maint/doc | **C1 location self-contradicts.** §5 says a new `.github/workflows/lockfile.yml`; §12/§13 say a job in `ci.yml` (which has no `on.paths` filter, so it can't get C1's path-scoping without the job-level `if` §0 rejected). | Choose the **separate `lockfile.yml`** (the whole point of the `on.paths` argument); fix §12/§13/status to match; add the `lockfile.yml` + `setup-pinned-uv/action.yml` + `uv-version.sh` rows to §13. |
| **M5** | rel/sec | **`--exclude-newer` has no date source.** No lock-date exists in the repo (`--no-header` strips uv's timestamp) and `check-lockfile.sh` passes no args. As written, the determinism fix is unimplementable → C1 re-resolves live PyPI and flaps red on unrelated PRs (training maintainers to bypass it). | Commit a date source (e.g. `scripts/lock-date.txt` or a var in `gen-lockfile.sh`) that the generator reads and passes to `uv … --exclude-newer`; bump only on intentional relock. |
| **M6** | maint | **C6 duplicates an existing test suite.** `scripts/tests/test_lockfile_platform_split.sh` (6 tests) already asserts the split line, the constraint pin, and `--constraint` wiring. | **Cut C6 as a component.** Its only novel value (fail-closed on the universal→host fallback) folds into M1's `gen-lockfile.sh` hardening; the split-presence assertion is already owned by the existing test, which C1 runs in CI. |
| **M7** | doc/maint | **§0 re-scope not folded into the LLD body.** §6 ("Weekly…"), §7 ("land the relock **cron**"; "C2 + C3 **together**… defers to it"), and §5 C2/C5 still assert cron — *outside* the §5 supersede-flag — contradicting §0/status (dispatch-only; C3 **disables** pip updates). **C3 scope is stated three ways** (§5 "security may touch", §0 "disable both", §16 "security-only"). | Rewrite §5 C2/C5/C6 + §6 + §7 + §16 to the post-review scope and delete the dual-truth convention; collapse C3 to one decision (disable pip version+security). |
| **M8** | maint/doc | **uv single-source claim is incomplete.** `uv-version.sh` collapses the shell/workflow copies, but the two `0.11.21` literals in `release_process.md` (L31, L131) are Markdown prose — not sourceable. | The runbook must **drop the version number** ("uv pinned in `gen-lockfile.sh`"), not re-cite it; the "forbid the literal in docs" test enforces it. |
| **M9** | security | **Waiver grammar drops GHSA/PYSEC.** The existing parser `awk '/^CVE-/'` (release.yml) silently ignores non-CVE IDs; pip-audit + Dependabot alerts are frequently GHSA/PYSEC-only → a legitimately-waived advisory **false-blocks** C4. | C4's parser (and the release.yml step) must accept `^(CVE\|GHSA\|PYSEC\|OSV)-`; update the `.pip-audit-ignore` grammar doc in lockstep. |

## Should-fix (lower severity)

| Axis | Item | Action |
|------|------|--------|
| sec/maint | CODEOWNERS — `dependabot.yml` + new files (`security-preflight.sh`, `uv-version.sh`, `setup-pinned-uv/`, the new workflows) aren't in the SECURITY-routing block. Note: the `* @bobinson` wildcard *does* own them, so §0's "does not cover" is **overstated** — it's cosmetic while there's one owner, real once a team exists. | Add explicit SECURITY-block entries (matches the existing convention); soften §0's wording to "not in the security-routing block". |
| doc | `native_installation.md` doesn't link `release_process.md` (the runbook links out to it but not back). | Add a "Releasing" see-also link. |
| doc | Status doc says "9 suites" (actually 10); runbook's shellcheck line omits `scripts/lib/*.sh`. | Correct both (or drop the count). |
| maint/doc | 0055 plan §"Release Process" §3.2/§3.4 describe a CI lockfile + pip-audit gate (as `release.yml` `lint` deltas) that **overlaps** 0056 C1/C4 — blurry ownership boundary. | One line in 0056 §3/§13 stating C1 relocates that delta to a separate `lockfile.yml`. |
| maint/doc | No single authority tracks the "on-ship, edit these doc lines" obligations (drop `release_process.md` "planned (0056)" caveats; remove the uv literals; add the gate-misfire runbook). | Designate `0056_implementation_status.md` as the tracker with explicit line-item rows; the forbid-literal/count-parity tests are the *enforcement*. |

## Confirmed solid (do not re-litigate)

- **`check-lockfile.sh` fails CLOSED** when `gen-lockfile.sh` errors (`set -e` + EXIT-trap restore) — the earlier "fails open" claim was **rejected** by three independent passes. ✅
- **C1 fork-PR safety**: `pull_request` (not `_target`) + `permissions: contents: read` + no secrets + base-ref *content* trust + exact-semver regex is the correct, exfil-safe shape (given M3's fetch fix). ✅
- **Dispatch-only C2/C5** removes the dead-cron common-mode blind spot (both crons would otherwise die together — GitHub disables schedules after 60 d inactivity — silencing the staleness detector). ✅
- **C3 disabling Dependabot pip updates** kills the C2/C3 split-brain (two owners of one lockfile). ✅
- **No `id-token`/signing scope** added by any new workflow; the 0055 cosign+Rekor trust chain is untouched; rollback is purely additive. ✅
- **Convention fit**: `run_gate` extension, `lib.sh`-based static tests, SHA-pinned actions + a `github-actions` Dependabot updater to maintain them. ✅

## How to use this audit

1. **Before building a component**, treat its ❌ rows as acceptance criteria (write the test first — see the LLD §12 TDD plan).
2. **C1 is the keystone** — M1, M3, M4, M5 all gate it; build them together.
3. **Re-run the four-axis review** against the *implemented* code (not just the design) before flipping C1 from advisory to enforcing.
4. **The fix for M1–M9 is to revise the LLD first** (fold §0, resolve C1 location, re-spec the token + base-ref + date-source), then implement test-first. Until then, 0056 is **not ready to build**.
