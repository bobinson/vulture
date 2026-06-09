# 0055 — Native Installer Hardening + Honesty · Implementation Status

**Status**: IMPLEMENTED — Tier A + C + hardening pass + **B1 (lockfile)** + **Tier
B-lite (system-Python install)** + **cross-distro Docker e2e**. Tier B (bundled PBS)
and the `vulture.sh release` preflight remain designed-only (see plan).
**Last updated**: 2026-06-09

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
- Implement **install-mode `local_start`** (the launcher is currently dev-only;
  a Go change is required — the plan's "no Go change" claim applies only to the
  dependency *install*, see plan §3 correction). Install mode must:
  (a) run the backend via the installed binary's `serve` (no `go build`),
  serving the static SPA shipped at `runtime/frontend`;
  (b) start agents from `AgentsRoot(install)` = `$VULTURE_HOME/runtime/agents`
  with the venv `PythonBin(install)` (nested packaging is already correct —
  no repackaging, and do NOT route through `BuildAgentEnv`, whose single-dir
  PYTHONPATH would require flat packaging);
  (c) skip the vite frontend dev server (SPA is static);
  (d) skip `installAgentDeps` (the venv is pre-provisioned with `--require-hashes`).
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
