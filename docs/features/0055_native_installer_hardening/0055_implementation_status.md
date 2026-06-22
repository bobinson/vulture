# 0055 — Native Installer Hardening + Honesty · Implementation Status

**Status**: IMPLEMENTED & SHIPPING — Tier A + C + hardening pass + **B1 (lockfile)**
+ **Tier B-lite (system-Python install)** + **Tier B PBS bundling (linux/amd64)** +
**cross-distro Docker e2e**. **Verified shipping in v0.0.8**: the public
linux/amd64 release tarball bundles a SHA-pinned CPython **3.12.13**
python-build-standalone runtime with the agent deps pre-installed, so
`curl … | sh` → `vulture start` runs the Python agents OFFLINE with no system
Python and no Docker (confirmed by tarball inspection + a fresh clean-host e2e —
see "v0.0.8 release" below). **Deferred as of v0.0.8 — now IMPLEMENTED on branch
`feature/0055-pending-items` (pending merge + release):** the cosign-signed vendor
pipeline (`vendor-pbs.yml` → `release.yml`), darwin + arm64 PBS bundling, and the
`vulture.sh release` preflight (see "Pending-items branch" below).
**Last updated**: 2026-06-22 (pending-items branch: the deferred tail, TDD + reviewed + docker-gated)

## Pending-items branch — the deferred tail (2026-06-22)

The five remaining 0055 pending items were implemented test-first on branch
`feature/0055-pending-items` (RED → /simplify → GREEN → /simplify → adversarial
review → Docker e2e gate). **Not yet merged or released.**

| # | Item | What landed | Verified |
|---|---|---|---|
| 1 | darwin + arm64 PBS bundling | `build-release.sh` derives the PBS triple per `(os,arch)` for all 4 platforms (no more linux/amd64-only guard); real SHA pins for the 3 missing triples in `pbs-shas-20260610.txt`; `release.yml` sets `VULTURE_BUNDLE_PBS=1` for every matrix entry | `test_pbs_multiplatform.sh`; build-side unit-tested + reviewed. **Cross-platform RUN still verified on the macOS/arm CI runners** (not reproducible in a linux sandbox) |
| 2 | cosign-signed PBS vendor pipeline | `vendor-pbs.yml` cosign-signs the vendored `SHA256SUMS` + keys the pin lookup on the full asset filename (was a release-blocking bare-triple mismatch); `release.yml` fetches + cosign-verifies the vendored PBS and passes it to `build-release.sh` via `VULTURE_PBS_TARBALL` (direct indygreg fetch kept as local fallback) | `test_pbs_vendor_wiring.sh` (incl. a pin-resolves assertion). **End-to-end still verified on GitHub Actions** (CI-only) |
| 3 | smoke-install real scan | `smoke-install.sh` runs a real `vulture scan` and, on a bundled tarball, REQUIRES agents up + asserts findings>0 (lean tarballs tolerate 0); `is_bundled` marker-gated so a slow/broken bundled release can't masquerade as lean | `test_smoke_scan.sh` + **Docker gate**: bundled scan → `completed`, 17 findings |
| 4 | `vulture.sh release` preflight | new `release-preflight.sh` runs 5 pre-tag gates (clean-tree first/fail-fast, lockfile, fallback-tag, shellcheck, branch tests) delegated from a POSIX-converted `vulture.sh` | `test_release_preflight.sh` |
| 5 | build-artifact CI guards | `test_release_artifacts.sh` re-creates the removed C5/C6/C7 checks (hashed lockfile shipped, plugin manifests staged, PBS opt-in); all new tests wired into the `lint-installer` CI job | green in CI + locally |

Adversarial review (10 lenses) caught + fixed two real blockers (the #2 pin-key
mismatch that would abort every release; a regex bug in a `sha256_verify_in_sums`
helper). Shared `scripts/tests/lib.sh` harness; `scripts/lib/hash.sh` gained a
portable `sha256_verify_in_sums`. Docker e2e gate (Ubuntu 24.04 + Fedora 41):
install matrix, bundled-PBS agents-run-offline, UI loads, plugin activation, and
the real-scan smoke — all green.

## v0.0.8 release — verified shipping + follow-ups (2026-06-21)

End-to-end verification of the **public** installer against the v0.0.8 release
(`curl -fsSL …/main/install.sh | sh`), plus the LLM/UX follow-ups that landed on
`main` since the 2026-06-17 update. **Everything below is on `main` and in v0.0.8.**

**Tier B PBS bundling — VERIFIED LIVE (not just an opt-in build).** `release.yml`
sets `VULTURE_BUNDLE_PBS=1` for the linux/amd64 matrix entry. The published
`vulture-v0.0.8-linux-amd64.tar.gz` (≈179 MB) was inspected and ships
`runtime/python/{bin/python3.12, lib/python3.12/…}` (CPython 3.12.13 PBS, 19,849
entries) with the agent deps pre-installed and **no `PBS_NOT_BUNDLED` marker**. A
fresh clean-host install ran **all 10 agents** on the bundled interpreter offline;
`vulture scan` completed with **2464 findings persisted** (API-cross-checked);
`doctor` was all-OK; the embedded SPA **auto-logged-in** with **0 console errors**.
arm64/darwin still ship lean (no committed PBS pin → system-Python or CLI-only).

| Area | Fix (all on `main`, shipped in v0.0.8) | Status |
|---|---|---|
| version string | `main.go` declares `var Version`, printed by `vulture version`; the release ldflag `-X main.Version=<tag>` now takes effect (was a hardcoded `vulture v0.1.0` no-op). v0.0.8 reports `vulture v0.0.8`. | ✅ |
| native Gemini | `GEMINI_API_KEY` added to the `config/.env` provider allow-list (`dotenv.go`); was silently dropped — now forwarded to the agents like the other provider keys. | ✅ |
| doctor LLM check | New `checkLLMConfig`/`llmStatus`: resolves the provider from `VULTURE_LLM_MODEL`, reports it, and **WARNs (never FAILs)** if the matching key is missing. | ✅ |
| PATH shadow | `install.sh link_binary` warns when a stale `vulture` earlier on PATH (e.g. an old `/usr/local/bin/vulture`) would shadow the freshly-installed one. | ✅ |
| persistence (#2) | `sqlite_repo.SaveFindings` chunks multi-row INSERTs under the SQLite 32766-param limit + `ON CONFLICT DO NOTHING`; previously dropped the whole batch on a native install (0 findings persisted). | ✅ |
| hermetic agents (#1) | launcher adds `PYTHONNOUSERSITE=1` to the agent env so agents don't pick up a host `~/.local` site-packages and crash. | ✅ |
| CLI scan (#3) | `vulture scan` probes the local daemon by port, triggers the run via the SSE stream, and prints a `Status / findings / by agent` summary. | ✅ |
| CSP fonts (#4) | static CSP allows `fonts.googleapis.com` / `fonts.gstatic.com` — no console error. | ✅ |
| auto-login (#5) | SPA uses runtime local-session detection (not a build-time flag) → native installs auto-login; a centralized (Mode B) server still requires sign-in. | ✅ |
| dev password (#6) | `install.sh` pins + prints `VULTURE_LOCAL_DEV_PASSWORD` on a fresh `.env` (was a random password discarded to `/dev/null`). | ✅ |

**Docs-honesty tests removed.** `scripts/tests/test_docs_honesty.sh` was deleted
(commits 72c8c25 / 9699365) and its `lint-installer` CI step removed. The C1/C2/C3
(docs-prose) and C5/C6 (build-artifact) guards referenced elsewhere in THIS doc no
longer exist — **treat those C-guard citations below as historical.** The
build-artifact coverage they provided (C5 hashed-lockfile-shipped, C6 plugin
manifests, C7 PBS opt-in) is no longer automated; reviving it as a focused
`test_release_artifacts.sh` (no docs-prose grepping) is a suggested follow-up.

**`native_installation.md` rewritten** (correctness + crispness pass): the `doctor`
check list now matches the real checks (incl. the LLM check), the install tree
matches disk (no phantom `runtime/frontend/`), version examples use `v0.0.8`, and a
"start with an LLM" matrix (OpenAI/Claude/Gemini/Ollama/OpenAI-compatible) was added.

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
| dotenv (plugins ckpt 1) | Safe install-mode `config/.env` loader: `localdev.LoadInstallEnv()` PARSES `KEY=VALUE` (never `source` — no code execution) and injects forwardable keys (`VULTURE_*` + provider keys `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/`OPENAI_BASE_URL`/`OLLAMA_*`; **excludes** `PATH`/`HOME`/`PYTHONPATH`/`LD_PRELOAD`). Explicit env wins over the file; called at the top of `startInstallMode` so backend + agents inherit it. Also fixes the standing "`VULTURE_USE_LLM`/`OPENAI_*`/`VULTURE_EMBEDDING_*` not loaded in install mode" gap. First checkpoint of the `VULTURE_PLUGINS` activation LLD. 6 unit tests incl. a command-substitution-not-executed security assertion. | ✅ |
| VULTURE_PLUGINS (plugins ckpt 2) | Activation overlay in `pluginregistry.Build()`: when `VULTURE_PLUGINS` is set it is the **authoritative** allow-list for EXTERNAL plugins — `all` (enable all external), `""`/`none` (disable all external), or `a,b,c` (exactly those). **In-tree built-in agents are never touched** (load-bearing safety: `VULTURE_PLUGINS=semgrep` must not switch off chaos/owasp/…). Unknown names warned + skipped, never fatal. Runtime-only — applied AFTER `SaveState`, so it never rewrites `state.toml`. 7 unit tests incl. the in-tree-not-disabled invariant + no-mutation. Still inert until ckpt 3 ships manifests + sets `VULTURE_BUILTIN_PLUGINS_DIR` for native installs. | ✅ |
| discovery (plugins ckpt 3) | `build-release.sh` stages plugin **manifests** into `runtime/plugins/<name>/` (`plugin.toml` + `rules/*.json`) — discovery metadata only, **not** container images (pull at runtime, like PBS). Install-mode launcher `ensureBuiltinPluginsDir()` defaults `VULTURE_BUILTIN_PLUGINS_DIR=$VULTURE_HOME/runtime/plugins` when unset + present (inherited by the serve child via `os.Environ()`). Verified: a real tarball ships `runtime/plugins/semgrep/{plugin.toml,rules}` (no image). Supervisor degrades gracefully when Docker is absent (`docker ps` err → log + `return nil`, no crash). 3 launcher unit tests + docs-honesty **C6** guard. **Now `VULTURE_PLUGINS` is live on native installs** (discovery + activation wired end-to-end; running container plugins still needs Docker). | ✅ |
| activation UX (plugins ckpts 4-6) | **ckpt 4** `vulture.sh --plugins all\|none\|<list>` → exports `VULTURE_PLUGINS` (existing value untouched when flag absent) + dev defaults `VULTURE_BUILTIN_PLUGINS_DIR=$PROJECT_ROOT/plugins`. **ckpt 5** `install.sh` seeds `VULTURE_PLUGINS=` (empty = quiet/safe default: external plugins off until opted in) + fixed the stale `VULTURE_PORT=23000`→`28080` (dormant until ckpt 1 made `.env` loadable) + summary note. **ckpt 6** `doctor` `checkPluginsReachable()` builds the registry, probes enabled non-in-tree plugins' `/health`, **WARN never FAIL** (CLI/Docker-less is valid); 3 unit tests. | ✅ |
| activation e2e | New `scripts/tests/docker/plugin-smoke.sh`: real-tarball install in ubuntu:24.04, then via real `vulture start` — CASE A (empty `VULTURE_PLUGINS=`) → semgrep ABSENT from `/api/agents`; CASE B (`VULTURE_PLUGINS=semgrep`) → semgrep PRESENT (`{"id":"semgrep","status":"unhealthy"}` — graceful: no docker-in-docker; asserts presence, not health). Proves discovery → allow-list → /api/agents end-to-end. Plus `ui-smoke` ubuntu+fedora green (embedded SPA loads). | ✅ |
| SPA e2e (Plan A) | New `scripts/tests/docker/ui-smoke.sh <distro> <real-tarball>` + `run-ui-matrix.sh`: installs a REAL release tarball in ubuntu:24.04 / fedora:41, runs `vulture start --foreground`, and asserts the embedded SPA loads (real app, not the placeholder) at `/` and `/audit/<id>` (SPA fallback). Unlike `runner.sh` (stub binary, install.sh mechanics) this runs the real Go binary. Verified live: ubuntu ✅ (fedora via the dynamic-workflow e2e run). | ✅ |

## Implemented since 2026-06-05 (B1, Tier B-lite, cross-distro e2e)

| # | Task | Status |
|---|---|---|
| B1 | Hashed lockfile generator + freshness gate | ✅ `scripts/gen-lockfile.sh` (uv pip compile --universal --generate-hashes; third-party only, vulture-* excluded) → `agents/requirements-frozen.txt` (77 pkgs / 2090 hashes); `scripts/check-lockfile.sh` (deterministic re-derive + diff); `make freeze-deps` / `make check-lockfile` |
| B-lite | System-Python install path in `install.sh` | ✅ TDD; `install_python_deps` precedence bundled-PBS > opt-in `VULTURE_USE_SYSTEM_PYTHON` > CLI-only; detect ≥3.12, `--copies` venv at `runtime/python` with `python3.12` alias, `pip --require-hashes --only-binary :all:`; fail-closed on missing/hashless lock, no interpreter, bad version. 31/31 unit tests |
| bugfix | `cleanup` EXIT trap returned non-zero → successful **offline** install exited 1 | ✅ fixed (`return 0`) + unit-locked; **found by the cross-distro e2e** |
| E2E | Fresh-Docker install matrix (Ubuntu 24.04 + Fedora 41, with/without Python) | ✅ `scripts/tests/docker/` (Dockerfiles, offline fixtures, runner, run-one/run-matrix); **9/9 scenarios pass** on real Docker; gated in CI via `.github/workflows/test-install-docker.yml` |

**Tier B PBS bundling — IMPLEMENTED (linux/amd64, opt-in):** `build-release.sh`,
when `VULTURE_BUNDLE_PBS=1`, resolves a real recent CPython **3.12.x**
`install_only` python-build-standalone tag for `x86_64-unknown-linux-gnu`,
downloads + **SHA-256-verifies** it (fail-closed) against the release's published
`SHA256SUMS`, extracts/flattens it to `runtime/python/bin/python3.12`, then
pre-installs the hashed `requirements-frozen.txt` with `--require-hashes
--only-binary :all:`. So a bundled tarball runs the Python agents OFFLINE with no
system Python and no Docker. `install.sh`'s `_install_python_deps_bundled` skips
pip when the bundled interpreter can already `import uvicorn`. Flag UNSET → lean
default (only the `PBS_NOT_BUNDLED` marker). **`release.yml` wires it:** the
`build tarball` step sets `VULTURE_BUNDLE_PBS=1` **only for linux/amd64**
(`${{ matrix.os=='linux' && matrix.arch=='amd64' && '1' || '' }}`) — the platform
with a committed PBS SHA pin; every other matrix entry stays lean (and
build-release gracefully skips bundling even if the flag were set, verified on
linux/arm64). Implications: the linux/amd64 release asset grows to ~180 MB and the
SBOM/Trivy steps now also scan the bundled Python deps (stricter CVE gate). E2E:
`scripts/tests/docker/pbs-bundle-smoke.sh` (bare ubuntu/fedora, no python3) —
**GREEN on both distros** (bundled `python3.12` present, agents healthy on it
offline, `doctor` OK). The e2e caught + drove two fixes: (1) **hermetic build** —
the build-time pip needs `PYTHONNOUSERSITE=1 PYTHONPATH=''`, else it sees the
build host's `~/.local` site-packages, marks ~19 deps "already satisfied", and
ships an incomplete runtime (`annotated_doc` missing → fastapi import fails on the
target); (2) **`NewSQLiteRepo` now chmods `vulture.db` (+ WAL/SHM) to 0600** — it
holds audit findings and `doctor` flags it — surfaced once `doctor` ran post-`start`.

**Still deferred (designed-only):** the **cosign-signed vendor pipeline**
(`vendor-pbs.yml` → `release.yml`; the build-time direct fetch above is the
sandbox-runnable equivalent), **darwin/arm64** bundling, and the
`scripts/vulture.sh release` preflight + `release.yml` hardening deltas.

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

## Tier B (PARTIALLY IMPLEMENTED) — embedded Python agent runtime

Tier B (embedded Python agent runtime so native installs run agent scans
without Docker) is **IMPLEMENTED for linux/amd64** as an opt-in build; the
cosign-signed vendor pipeline and darwin/arm64 remain deferred. The complete
LLD — trigger, scaffolding, install strategy (build-time pre-install vs.
install-time pip), security, size, risks, test plan, effort — lives in
`0055_implementation_plan.md` §"Tier B (PARTIALLY IMPLEMENTED) — embedded
Python agent runtime". Status of the pieces:

- ~~Generate a **hashed** `requirements-frozen.txt`~~ — DONE
  (`scripts/gen-lockfile.sh`); as of 2026-06-09 `build-release.sh` also
  **ships** it into the tarball (was a 0-byte stub before — see AU1).
- ~~Bundle PBS into the release tarball~~ — **DONE (linux/amd64, opt-in
  `VULTURE_BUNDLE_PBS=1`)**: `build-release.sh` fetches the upstream indygreg
  CPython 3.12.x `install_only` PBS tarball directly, **SHA-256-verifies** it
  (fail-closed) against the release's published `SHA256SUMS`, extracts it into
  `runtime/python/`, and pre-installs the hashed deps so it installs OFFLINE.
  No `release.yml` change is needed for this path. **DEFERRED:** wiring the
  cosign-signed `vendor-pbs.yml` artifact into `release.yml` (the
  `vendor-pbs.yml` workflow exists but nothing consumes it), and darwin/arm64.
  Flag unset → `build-release.sh` writes only the `PBS_NOT_BUNDLED` marker.
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
  case) is now **DONE for linux/amd64** via the opt-in build above — a bundled
  release runs agents with no system Python; darwin/arm64 + the cosign vendor flow
  remain deferred (see the Bundle-PBS item above).
- Make `smoke-install.sh` run a real `vulture scan`.

**Tier B is now shipping for linux/amd64** (opt-in `VULTURE_BUNDLE_PBS=1`):
a bundled release installs the CLI + embedded SPA and runs the Python agents
with no system Python and no Docker — the skill-based audit phase runs fully
locally. The remaining deferred pieces (cosign vendor pipeline, darwin/arm64,
real `vulture scan` in `smoke-install.sh`) would graduate to their own feature
(suggested `0056_native_agent_runtime`). On a non-bundled (lean) release, Mode E
installs the CLI + embedded SPA and agent-based scanning needs a system Python
(`VULTURE_USE_SYSTEM_PYTHON=1`) or Docker (Mode A/B). **Regardless of how Python
is provided, the deeper LLM analysis phase still requires an external endpoint and
key** (`VULTURE_USE_LLM=true` + `OPENAI_API_KEY` / `OPENAI_BASE_URL`).

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

**Resolved since this audit** (see Tier B section): PBS bundling now ships for
linux/amd64 (opt-in `VULTURE_BUNDLE_PBS=1`, build-time fetch+SHA-verify+pre-install)
and the install-mode launcher/packaging wiring (#10) lands so agents execute
natively. **Still deferred:** the cosign-signed vendor pipeline and darwin/arm64.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-06-05 | `install_python_deps` fails closed on a hashless non-empty frozen file rather than silently installing without `--require-hashes` | a supply-chain-sensitive installer must not weaken hash enforcement silently |
| 2026-06-05 | CLI-only build is a valid, successful install (no pip) — not an error | the Go CLI + skills are usable without the Python agent runtime; only LLM/agent scanning needs Docker today |
| 2026-06-05 | Tier B deferred, not blocking v0.1.0 | bundling a Python runtime + a dependency lockfile is real work; honesty (Tier C) unblocks launch now |
