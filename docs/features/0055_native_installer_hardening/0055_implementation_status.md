# 0055 — Native Installer Hardening + Honesty · Implementation Status

**Status**: IMPLEMENTED — Tier A + C + hardening pass + **B1 (lockfile)** + **Tier
B-lite (system-Python install)** + **cross-distro Docker e2e**. Tier B (bundled PBS)
and the `vulture.sh release` preflight remain designed-only (see plan).
**Last updated**: 2026-06-14

## v0.0.3 install-mode UX fixes (auto-detect + audit #1–#8)

Post-implementation audit (2026-06-14) of the install-mode UX surfaced eight
issues, fixed in this pass. Headline change: the system-Python path is now the
**auto-detect default**, not an opt-in.

| # | Fix | Status |
|---|---|---|
| auto | `install_python_deps`: `VULTURE_USE_SYSTEM_PYTHON` is now TRI-STATE — unset=AUTO (use a present ≥3.12 system Python when a hashed lockfile ships), `1`=REQUIRE (loud-fail), `0`=DISABLE (force CLI-only). AUTO sub-cases: no-lockfile / no-Python / hashless-lockfile all degrade to CLI-only (warn, never abort); `--require-hashes` + `>=3.12` gate enforced on every venv install. | ✅ |
| #1/#2/#7/#8 | New `localdev.UIPort(mode, cfg)` helper (install → `BackendPort`; dev → `FrontendPort`) + unit test; the backend serves both API and embedded SPA in install mode (no separate UI port). | ✅ |
| #1 | `start.go` prints the UI URL via `UIPort(...)` (was the phantom 23000). | ✅ |
| #2 | `main.go runScan` "View results" URL uses `UIPort(mode,lcfg)` → `…/audit/<id>`. | ✅ |
| #7 | `main.go runStatus`: in install mode no separate "frontend" row at `FrontendPort` (nothing listens there); the backend row serves the UI. | ✅ |
| #8 | `launcher.go printBanner`: install mode prints "INSTALL MODE", UI line at the backend port, no separate Frontend line, Agents line only when agents are actually started. | ✅ |
| #3 | `runScan` agent-health guard: probes each `cfg.Agents` `/health` (~1s); if zero reachable, prints a loud, actionable warning (no findings; install Python 3.12+ or use Docker), then CONTINUES (warn, not refuse, so remote/centralized submissions still work). | ✅ |
| #5 | `doctor.go checkPython`: install-mode missing `PythonBin` path now returns WARN (not hard FAIL) per plan line 544 — CLI-only is a documented-valid state; fix string updated; test updated. | ✅ |
| #4/#6 | `cli_only_note()` rewritten to be honest — removed the false "CLI + skills still work"; states agent/LLM scanning needs a local Python ≥3.12 (auto-detected; install + re-run, or set `=1`) OR Docker, and that the CLI + web UI are installed and work. Quickstart + post-install summary made conditional on an `AGENTS_INSTALLED` state flag; `launcher.go:228-230` log corrected to "backend + embedded SPA only (no agent runtime…)". | ✅ |
| SPA (Plan A) | `build-release.sh` now embeds the real `frontend/dist` into the `//go:embed` source (`backend/internal/assets/frontend/`) BEFORE `go build` — reordered to frontend→embed→build with a placeholder-restore trap, plus a post-build guard that fails the release if the binary still embeds the placeholder. Prior releases ran `go build` first and shipped the placeholder → Mode-E rendered "Frontend assets not bundled". The unused, never-served `runtime/frontend/` tarball copy is dropped. | ✅ |
| SPA e2e (Plan A) | New `scripts/tests/docker/ui-smoke.sh <distro> <real-tarball>` + `run-ui-matrix.sh`: installs a REAL release tarball in ubuntu:24.04 / fedora:41, runs `vulture start --foreground`, and asserts the embedded SPA loads (real app, not the placeholder) at `/` and `/audit/<id>` (SPA fallback). Unlike `runner.sh` (stub binary, install.sh mechanics) this runs the real Go binary. Verified live: ubuntu ✅ (fedora via the dynamic-workflow e2e run). | ✅ |

## Implemented since 2026-06-05 (B1, Tier B-lite, cross-distro e2e)

| # | Task | Status |
|---|---|---|
| B1 | Hashed lockfile generator + freshness gate | ✅ `scripts/gen-lockfile.sh` (uv pip compile --universal --generate-hashes; third-party only, vulture-* excluded) → `agents/requirements-frozen.txt` (77 pkgs / 2090 hashes); `scripts/check-lockfile.sh` (deterministic re-derive + diff); `make freeze-deps` / `make check-lockfile` |
| B-lite | System-Python install path in `install.sh` | ✅ TDD; `install_python_deps` precedence bundled-PBS > opt-in `VULTURE_USE_SYSTEM_PYTHON` > CLI-only; detect ≥3.12, `--copies` venv at `runtime/python` with `python3.12` alias, `pip --require-hashes --only-binary :all:`; fail-closed on missing/hashless lock, no interpreter, bad version. 31/31 unit tests |
| bugfix | `cleanup` EXIT trap returned non-zero → successful **offline** install exited 1 | ✅ fixed (`return 0`) + unit-locked; **found by the cross-distro e2e** |
| E2E | Fresh-Docker install matrix (Ubuntu 24.04 + Fedora 41, with/without Python) | ✅ `scripts/tests/docker/` (Dockerfiles, offline fixtures, runner, run-one/run-matrix); **9/9 scenarios pass** on real Docker; gated in CI via `.github/workflows/test-install-docker.yml` |

**Not yet built (designed-only):** Tier B (bundle python-build-standalone via the
signed vendor pipeline — needs the release-signing flow, not sandbox-runnable) and
the `scripts/vulture.sh release` preflight + `release.yml` hardening deltas.

Tier B-lite covers the **dependency install** half of "run agents with an existing
Python": after the 2026-06-09 audit fix, releases now ship the hashed lockfile and
`VULTURE_USE_SYSTEM_PYTHON=1` builds the venv + installs with `--require-hashes`.
Native agent **execution** is NOT yet end-to-end — and the gap is bigger than the
env: the whole install-mode `vulture start` is unwired. `runStart → runLocalStart →
findProjectRoot() (= CWD) → Launcher.Start()`, and the Launcher never branches on
mode — `startBackend` `go build`s from `CWD/backend`, `startFrontend` runs vite from
`CWD/frontend`, and `startAgents`/`installAgentDeps` use `CWD/agents` + the detected
host python (never `AgentsRoot`/`PythonBin`/`BuildAgentEnv`). So `vulture start` fails
on a native install. (The agent **packaging** is fine — the nested
`runtime/agents/<a>/<pkg>` layout matches the launcher's `<root>/shared:<agentDir>`
PYTHONPATH; no repackaging is needed.) See Deferred below.

## Checklist

| # | Task | Status |
|---|---|---|
| A1 | Fix `install.sh` cosign verify-blob command | ✅ |
| A2 | Make `install_python_deps` honest + fail-closed | ✅ |
| A3 | Clean up `.filelist` on all platforms | ✅ |
| A4 | Widen system-dir blacklist (validate_home + extract_atomic) | ✅ |
| C1 | README: honest Mode-E framing (CLI works; agents need Docker) | ✅ |
| C2 | Reconcile 0044 status doc (PLANNED → PARTIAL) | ✅ |
| C3 | native_installation.md: current-limitations note | ✅ |
| T  | `sh -n` + branch tests | ✅ 11/11 (`scripts/tests/test_install_sh.sh`); `sh -n` clean; shellcheck unavailable locally — now gated in CI (`lint-installer`) |

## Hardening pass (review-driven, 2026-06-05)

A correctness/security/reliability review of the Tier-A code surfaced
eight further issues; all fixed in the same feature:

| Ref | Sev | Fix |
|---|---|---|
| H1 | High (security) | `install_python_deps`: emit `--trusted-host` **only** for an explicit `http://` mirror (with a warning); never for `https://`, where it would disable TLS verification on the channel that pulls executable code |
| H2 | High (reliability) | Atomic swap now keeps the old install (`OLD_HOME`) until `commit_install()` runs after deps/perms/symlink succeed; an EXIT trap (`cleanup`) rolls back on any abort. Previously the old version was deleted inside `extract_atomic`, before `pip` — a failed install left no rollback point |
| H3 | Med (correctness) | Hashless detection switched from `^name==` to a line-based check (`^[[:space:]]*[A-Za-z0-9]` + no `--hash=` anywhere), so extras / URLs / VCS pins can't slip past the fail-closed guard into an opaque `pip --require-hashes` error |
| H4 | Med (correctness) | Dropped `/root/*` from the blacklist (kept `/root` exact) so a root/container install under the default `~/.vulture` (= `/root/.vulture`) is no longer wrongly rejected |
| H5 | Med (DRY) | Extracted `resolve_path` + `reject_if_system_dir` helpers; `validate_home` and `extract_atomic` now share one blacklist definition instead of two copies |
| H6 | Low (reliability) | All downloads go through a `fetch` helper with `--retry 3 --retry-delay 2 --retry-connrefused --max-time 300`; the releases-API call gets `--retry`/`--max-time` too |
| H7 | Low (hygiene) | Download temp dir renamed `TMPDIR`→`DL_TMP` (no longer clobbers the standard env var) and is removed by the EXIT trap |
| H8 | Low (completeness) | Added a `lint-installer` CI job (`shellcheck install.sh scripts/*.sh` + the branch tests) so the installer is linted on every PR, not only at release-tag time |

## Deferred (Tier B — DEFERRED / demand-gated)

Tier B (embedded Python agent runtime so native installs run agent scans
without Docker) is **fully designed but not scheduled**. The complete
LLD — trigger, current scaffolding vs. missing wiring, install strategy
(build-time pre-install vs. install-time pip), security, size, risks,
test plan, effort — lives in `0055_implementation_plan.md`
§"Tier B (DEFERRED) — embedded Python agent runtime". Summary of the
remaining work:

- ~~Generate a **hashed** `requirements-frozen.txt`~~ — DONE
  (`scripts/gen-lockfile.sh`); as of 2026-06-09 `build-release.sh` also
  **ships** it into the tarball (was a 0-byte stub before — see AU1).
- Bundle PBS: wire `release.yml` to fetch+verify the already-built
  `vendor-pbs-*` asset and extract it into `runtime/python/`. The
  `vendor-pbs.yml` workflow exists but **nothing consumes it**;
  `build-release.sh` only writes a `PBS_NOT_BUNDLED` marker.
- ~~Implement **install-mode `local_start`**~~ — IMPLEMENTED (#10, commit
  range on feature/004-tweaks). `Start()` branches to `startInstallMode`:
  (a) backend via the installed binary's `serve` (no `go build`; serves the
  embedded SPA); (b) agents from `AgentsRoot(install)`=`$VULTURE_HOME/runtime/agents`
  with the venv `PythonBin(install)` via `agentRuntime()`; (c) no vite;
  (d) no `installAgentDeps` (`CheckInstallPrereqs` is soft on a missing venv).
  Two follow-on gaps the e2e surfaced were also fixed: the offline-install SHA
  fallback to the aggregate `SHA256SUMS`, and `DefaultConfig` using
  `DataDir(ModeInstall)`=`$VULTURE_HOME/data` so the backend's DB migrates in
  place. **Verified:** venv deps install (`--require-hashes`), install-mode
  backend serves, and `chaos_agent`/`shared` resolve from the shipped
  `runtime/agents` via the launcher PYTHONPATH (find_spec). **Verified live
  (2026-06-09, clean-port run):** a real `VULTURE_USE_SYSTEM_PYTHON` install +
  `vulture start` bound **all 10 agents** (custom ports 38001-38010, each
  `/health` 200) + the backend (38080, SQLite routes up). The earlier
  28001-28010 failure was a pre-existing install owning those ports, not a #10
  bug. (A full LLM scan-with-findings is an optional remaining confirmation.)
- **PBS bundling** for installs WITHOUT system Python (the no-`VULTURE_USE_SYSTEM_PYTHON`
  case) remains deferred — see the Bundle-PBS item above.
- Make `smoke-install.sh` run a real `vulture scan`.

**Build it only when the Trigger in the LLD is met** (real demand for
Docker-less agent scanning). When built, it graduates to its own feature
(suggested `0056_native_agent_runtime`). Until then, Mode E installs the
CLI + embedded SPA; agent-based scanning requires Docker (Mode A/B), and
even with Tier B an external LLM endpoint is still required.

## Post-release audit fixes (2026-06-09)

A post-v0.0.1 end-to-end audit of the native-runtime shipping chain found
several pieces that were generated/designed but not actually delivered:

| Ref | Sev | Fix |
|---|---|---|
| AU1 | Blocker | `build-release.sh` globbed nonexistent `agents/*/requirements.txt` → shipped a **0-byte** lockfile. Now copies the committed hashed `agents/requirements-frozen.txt` (2090 hashes); empty CLI-only marker only if it's absent/unhashed. Tier B-lite's dep install now works from a real release. |
| AU2 | Major | `release.yml` `pip-audit -r agents/requirements.txt` targeted a nonexistent file (silent no-op) → repointed at `agents/requirements-frozen.txt`. |
| AU3 | Major | `FALLBACK_TAG=v0.0.0` (never released) made the API-down path 404 → bumped to `v0.0.1`; `check-fallback-tag.sh` now rejects `v0.0.0` and enforces the "≤1 minor behind" rule its header promised. |
| AU4 | Major | `verify_signature` silently downgraded to SHA-only when cosign was present but the sig/cert was missing → now fail-closed unless `VULTURE_ALLOW_UNSIGNED=true` (the no-cosign `curl\|sh` path is unchanged). |
| AU5 | Major | Misleading "In CI this is generated…/fetches PBS…" comments in `build-release.sh` (CI ran the same stub path) → corrected to the deferred reality. |
| AU6 | Major | Tests didn't catch the shipping gap (docs-honesty checked only wording; the docker e2e used a hand-injected fixture). Added `test_docs_honesty.sh` **C5** asserting `build-release.sh` ships the hashed lockfile + the committed file is hashed. |

**Still deferred** (Tier B native runtime, see Deferred section): PBS bundling
and the install-mode launcher/packaging wiring so agents execute natively.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-06-05 | `install_python_deps` fails closed on a hashless non-empty frozen file rather than silently installing without `--require-hashes` | a supply-chain-sensitive installer must not weaken hash enforcement silently |
| 2026-06-05 | CLI-only build is a valid, successful install (no pip) — not an error | the Go CLI + skills are usable without the Python agent runtime; only LLM/agent scanning needs Docker today |
| 2026-06-05 | Tier B deferred, not blocking v0.1.0 | bundling a Python runtime + a dependency lockfile is real work; honesty (Tier C) unblocks launch now |
