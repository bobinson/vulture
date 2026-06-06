# 0055 — Native Installer Hardening + Honesty (LLD + plan)

**Author**: bobinson
**Status**: IMPLEMENTED (Tier A + C + hardening pass; Tier B deferred)
**Created**: 2026-06-05
**Depends on**: 0044 (native installer scripts), 0036 (release hardening)
**Scope**: Tier A (fix `install.sh` correctness bugs) + Tier C (make
Mode-E claims honest). Tier B (bundle a Python agent runtime so Mode E
is fully functional) is explicitly **deferred** — see Non-goals.

## Problem

A pre-publication audit of `install.sh` + the release pipeline found
that the `curl … | sh` native installer (feature 0044, "Mode E")
installs the Go CLI but **does not deliver a working product**, and the
script has correctness bugs:

1. **Broken cosign verification (`install.sh` verify_signature).** The
   `cosign verify-blob` invocation has a stray positional argument
   (`${SHASUM_FILE%/*}/SHA256SUMS.pem`) and a `2>/dev/null` redirect
   wedged mid-command. `verify-blob` takes exactly one positional (the
   blob); the extra positional makes it fail whenever a signature is
   present and cosign is installed — i.e., the strongest supply-chain
   check is broken.

2. **The Python-deps step can't work as designed.**
   `install_python_deps` runs `pip install --require-hashes -r
   requirements-frozen.txt`, but:
   - `build-release.sh` builds that file by aggregating
     `agents/*/requirements.txt`, which **do not exist** → the file is
     empty.
   - `release.yml` only runs `build-release.sh`; it does **not** run
     `pip-compile --generate-hashes` (the build-release comment claiming
     it does is false) and **does not bundle python-build-standalone**.
   - So `runtime/python/bin/pip` is absent → the step is skipped → the
     Python agents get no dependencies and there is no bundled
     interpreter. Agent-based scanning therefore cannot run from a
     native install. (`--require-hashes` would also hard-fail on a
     non-empty hashless file.)

3. **`smoke-install.sh` gives false confidence.** The CI install gate
   checks `vulture version` + `doctor` but never runs a `vulture scan`,
   so it passes green even though the agent runtime is absent.

4. **README Mode E overclaims.** It advertises "One-shot installer in
   the style of nuclei: per-platform tarball + **bundled Python** +
   SQLite" — implying a fully-working audit experience that the
   pipeline does not yet deliver. Same honesty class as the
   ISO-26262 / 100%-coverage claims corrected in the release-honesty
   pass.

5. **0044 status drift.** `0044_implementation_status.md` says
   `Status: PLANNED / no implementation`, yet the scripts
   (`install.sh`, `build-release.sh`, `release.yml`, `smoke-install.sh`)
   are committed. The doc contradicts the tree.

6. **Minor script issues.** `.filelist` is left in `$VULTURE_HOME` on
   Linux (cleaned only in the darwin-only `strip_quarantine`); the
   system-dir blacklist in `validate_home`/`extract_atomic` misses
   `/var/*`, `/bin`, `/sbin`, `/lib`, `/boot`, `/root`, `/sys`, `/proc`,
   `/dev`.

## Goal

Make the native installer **correct** (no broken verification, no
opaque failures, clean teardown) and make its **claims honest** (the CLI
installs and runs; agent-based scanning currently requires Docker
Mode A/B). Leave a clear, signposted path to full Mode-E functionality
(Tier B) without blocking the v0.1.0 launch on it.

## Non-goals (Tier B — deferred to a follow-up feature)

- **Bundling a Python runtime** (python-build-standalone via a
  `vendor-pbs` release + a `release.yml` fetch step).
- **Generating a real hashed `requirements-frozen.txt`** (a
  `pip-compile --generate-hashes` / `uv pip compile` lockfile from the
  agents' resolved deps; the agents currently have no lockfile at all).
- **Making `smoke-install.sh` run a real audit.**

These are real work (a Python runtime bundle + a dependency lockfile)
and are tracked as the Tier-B follow-up. Until they land, Mode E is
"CLI + skills-capable binary; agents need Docker."

**Tier B is documented in full below** (§"Tier B (DEFERRED) — embedded
Python agent runtime") so the design exists on paper and can be picked
up directly if demand materialises — but it is **not scheduled**. Build
it only when the trigger in that section is met.

A lighter **"bring-your-own-Python"** variant — detect an existing host
Python ≥ 3.12 and build an isolated venv at the daemon-expected runtime
path, on explicit opt-in — is designed in full in §"Tier B-lite — Use
an Existing System Python" (also **PROPOSED / awaiting review**; see its
§"Open Decisions for the Reviewer").

## Design

### Tier A — `install.sh` correctness

**A1 — fix `verify_signature` cosign command.** Resolve the signature
PEM path once, then call `verify-blob` with a single positional (the
blob) and proper flags. Drop the stray positional + mid-line redirect:

```sh
PEM="${SHASUM_FILE%/*}/SHA256SUMS.pem"
[ -s "$PEM" ] || { warn "no certificate published; SHA-only verification"; return; }
cosign verify-blob \
    --certificate-identity-regexp "^https://github.com/${REPO_OWNER}/${REPO_NAME}/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate "$PEM" \
    --signature "$SIG_FILE" \
    "$SHASUM_FILE" \
    || err "cosign verification failed"
```

(`--rekor-url` is the default for keyless verify; keeping or dropping it
is fine. The key fix is one positional + a real `--certificate`.)

**A2 — make `install_python_deps` honest + fail-closed.** Distinguish
the three real states instead of skipping/erroring opaquely:
- bundled pip absent (no `runtime/python/bin/pip`) → this is the
  current CLI-only build; print a clear, actionable message: *"agent
  runtime not bundled in this build — `vulture scan` with LLM/agents
  requires Docker mode (Mode A/B); the CLI + skills still work."* and
  return success (the install is still valid).
- frozen file missing or empty → same CLI-only message.
- frozen file present **with** `--hash=` lines → install with
  `--require-hashes` (the secure path, used once Tier B ships).
- frozen file present **without** hashes → refuse (`err`) with a clear
  message rather than silently dropping hash enforcement; an unhashed
  dependency install in a supply-chain-sensitive installer must
  fail-closed, not weaken to hashless.

**A3 — clean up `.filelist` on all platforms.** Move the
`rm -f "$VULTURE_HOME/.filelist"` out of the darwin-only
`strip_quarantine` so the temp filelist is removed on Linux too (do it
unconditionally after `strip_quarantine`, or in `extract_atomic` once
the quarantine strip has consumed it).

**A4 — widen the system-dir blacklist.** In both `validate_home` and
`extract_atomic`, extend the rejected-prefix set to:
`/ /bin /sbin /lib /lib64 /boot /sys /proc /dev /root /etc /usr /var`
and their `/*` children. Keep the existing ownership check as a second
layer.

### Hardening pass (review-driven)

A post-implementation review (correctness / security / reliability /
DRY / chaos / test coverage) of the Tier-A code added eight fixes —
full table in `0055_implementation_status.md` §"Hardening pass". The
design-level points:

- **TLS not silently disabled (H1).** `--trusted-host` (which turns off
  certificate validation for a host) is now gated behind an explicit
  `http://` `VULTURE_PIP_INDEX_URL` and warned about; `https://` (the
  default) never receives it. Hash enforcement protecting *what* we
  install must not sit behind a transport we've told pip not to verify.
- **Crash-consistent upgrade (H2).** The previous install is retained as
  `OLD_HOME` through the whole `main()` and deleted only by
  `commit_install()` after deps/perms/symlink succeed. An EXIT trap
  (`cleanup`) restores it on any earlier abort. The swap is now a real
  commit point, not "delete-old-then-hope-pip-works".
- **Robust fail-closed detection (H3).** Hashless-manifest detection is
  line-based (any requirement line + no `--hash=`), covering extras,
  URLs and VCS pins a `name==` regex missed.
- **Blacklist carve-out (H4).** `/root` stays rejected as an exact
  target but `/root/*` does not — the default `~/.vulture` for a root /
  container user is legitimate.
- **One blacklist (H5).** `resolve_path` + `reject_if_system_dir`
  helpers replace the two copy-pasted case statements.
- **Network resilience (H6/H7).** A `fetch` helper adds bounded retries
  + a timeout to every download; the temp dir is trap-cleaned and no
  longer clobbers `$TMPDIR`.
- **CI gate (H8).** `lint-installer` runs `shellcheck` + the branch
  tests on every PR, not only at release-tag time.

### Tier C — honest Mode-E claims

**C1 — README.** Reword the Mode-E row + the "Native install" section
to state plainly: the installer sets up the `vulture` CLI (scan/start/
stop/doctor) and the embedded SPA; **agent-based (multi-framework /
LLM) scanning currently requires Docker (Mode A or B)**; full
self-contained agents are a planned follow-up (link 0055/Tier B). Drop
the bare "bundled Python" claim (it isn't, yet).

**C2 — 0044 status doc.** Reconcile with reality: the installer
*scripts* are implemented and shipped; the agent-runtime bundle
(PBS + lockfile) is deferred to the Tier-B follow-up. Change the header
from "PLANNED / no implementation" to "PARTIAL — scripts implemented;
agent-runtime bundle deferred (see 0055)".

**C3 — `docs/guides/native_installation.md`.** Add a short "Current
limitations" note mirroring C1 so the guide doesn't promise a
full-agent experience.

## Files touched

- `install.sh` — A1, A2, A3, A4 + hardening H1–H7
- `.github/workflows/ci.yml` — H8 (`lint-installer` job)
- `scripts/tests/test_install_sh.sh` — branch tests (11 cases)
- `README.md` — C1
- `docs/features/0044_native_installer/0044_implementation_status.md` — C2
- `docs/guides/native_installation.md` — C3
- `docs/features/0055_native_installer_hardening/*` — this LLD + status + rollback

No Go/Python source changes; no migration; no dependency changes.

## Test plan

- `sh -n install.sh` (syntax) + `shellcheck install.sh` (the script is
  documented POSIX-sh / shellcheck-clean — keep it so).
- Unit-style: source the functions and exercise `verify_signature`
  branch logic with a stubbed `cosign` on PATH (present-sig vs no-sig vs
  cosign-absent) and `install_python_deps` with: no pip, empty frozen,
  hashless frozen (must `err`), hashed frozen (must invoke pip with
  `--require-hashes`). A small `scripts/tests/test_install_sh.sh`
  harness using `VULTURE_HOME` in a tmpdir + PATH shims.
- Confirm `.filelist` is absent after `strip_quarantine` on Linux (A3).
- `reject_if_system_dir` rejects each blacklisted dir AND allows
  `/root/.vulture` + normal homes (A4 / H4).
- `install_python_deps`: hashed+https → `--require-hashes` with NO
  `--trusted-host` (H1); explicit `http://` → `--trusted-host`; hashless
  with extras → fail closed (H3).
- `commit_install` deletes `OLD_HOME` + marks committed; `cleanup`
  restores `OLD_HOME` on an uncommitted abort (H2).
- All 11 cases run in CI via `lint-installer` (H8).
- Docs: grep that README/guide no longer claim "bundled Python" as a
  shipped fact and that the Docker-for-agents caveat is present.

## Rollback

Pure script + docs change, no state. `git revert <0055 sha>` restores
the prior `install.sh` and docs. No release artifacts or DB affected.
See `0055_rollback_plan.md`.

---

# Tier B (DEFERRED) — embedded Python agent runtime

> **Status: DEFERRED / NOT SCHEDULED — demand-gated.**
> This section is a complete design kept on paper so Tier B can be
> picked up directly *if* users ask for native agent scanning without
> Docker. It is intentionally **not** part of the 0055 implementation
> and ships nothing. Do not start it until the **Trigger** below is met.
> When it is built it should graduate to its own feature folder
> (suggested: `0056_native_agent_runtime`) with its own status +
> rollback docs; this section is the seed LLD for that feature.

## Trigger (when to build this)

Build Tier B only when **at least one** of these is true:

1. **External demand.** ≥N (suggest 3) independent users/issues request
   running the agent pipeline natively (no Docker) — e.g. air-gapped
   laptops, Docker-restricted corporate fleets, CI runners without a
   container runtime.
2. **A committed Mode-E SLA.** A deployment commits to "single-binary,
   no Docker" as a *supported* path rather than a convenience.
3. **Docker becomes a hard blocker** for a target segment we choose to
   support (e.g. Windows-via-WSL users who can't run our compose).

Until then, the honest Mode-E framing (Tier C) is the answer: the CLI +
UI install natively; **agent/LLM scanning uses Docker (Mode A/B)**. This
trigger exists so we don't carry the (non-trivial) maintenance cost of a
bundled interpreter + a hashed lockfile for a path nobody is using.

## Why it's deferred, not abandoned

Bundling a Python runtime is real, ongoing cost: a per-platform
interpreter to track for CVEs, a transitive-dependency lockfile to
regenerate on every agent-dep bump, a ~10× larger release artifact to
sign/scan/host, and a second end-to-end install path to test. That cost
is only justified by real demand. The design is cheap to *write* now
(while context is fresh) and expensive to *carry* — so we write it and
gate the carry.

## Current state (what already exists vs. what's missing)

Tier B is mostly **"finish the wiring,"** not greenfield. The 0044 work
left deliberate scaffolding:

| Piece | State today | Tier B work |
|---|---|---|
| `vendor-pbs.yml` (re-host python-build-standalone as our own signed release; dual-control, `release` env approval, main-branch only, 4-platform matrix, SHA-pinned via `scripts/pbs-shas.txt`) | **Exists & complete** | Run it once per supported Python bump; keep `pbs-shas.txt` current |
| `install.sh` → `install_python_deps` (PBS-present + hashed-lockfile path, fail-closed on hashless, conditional `--trusted-host`) | **Done** (Tier A + hardening) | None — it already consumes the artifacts correctly |
| `build-release.sh` → copy agents source to `runtime/agents/` | **Done** | None |
| `build-release.sh` → `requirements-frozen.txt` | **Stub** — aggregates `agents/*/requirements.txt`, which **do not exist** (agents use `pyproject.toml`), so the file is empty | Generate a **real hashed lockfile** from the pyprojects (B1) |
| `build-release.sh` → PBS fetch | **Stub** — writes a `PBS_NOT_BUNDLED` note, makes an empty `runtime/python/bin/` | Fetch + verify + extract the vendored PBS in CI (B2) |
| `release.yml` | Does **not** fetch PBS or compile a lockfile | Add the two wiring steps (B2) |
| `smoke-install.sh` | Checks `version` + `doctor` only | Run a real `vulture scan` (B4) |

Net: the supply-chain-sensitive parts (PBS re-hosting, hash enforcement)
are built; Tier B is the lockfile + the CI glue + a real smoke test.

## Goal

A native install whose `vulture scan` runs the **full agent pipeline**
(no Docker), using a bundled, CVE-trackable Python and a **hash-pinned**
dependency set — with the same supply-chain guarantees as the Go binary
(re-hosted, checksummed, cosign-signed; no install-time reach to PyPI or
to indygreg).

## Design

### B1 — Hashed dependency lockfile (shared prerequisite)

> **Now load-bearing.** B1 is the single unit of supply-chain trust for agent dependencies and is a **hard prerequisite for BOTH** the bundled runtime (Tier B) **and** the system-Python path (Tier B-lite). Until B1 ships a hash-pinned `requirements-frozen.txt`, both agent-install paths fail closed. **Sequence B1 first.**

**What goes in the lockfile (and what does not).** The agents form a *star*: each of the 10 agent packages (`vulture-{asvs,chaos,cwe,discover,do178c,owasp,prove,soc2,ssdf,xss}-agent`) declares exactly one dependency — first-party `vulture-shared` — and `vulture-shared` carries the only real third-party deps:
`fastapi`, `uvicorn[standard]`, `pydantic`, `openai-agents`, `litellm`, `sse-starlette`, `httpx`, `tiktoken`, `pathspec` (all `>=` ranges; `requires-python >=3.12`; hatchling backend).

The 11 first-party `vulture-*` packages are **never pip-installed** in install mode — the launcher puts them on `PYTHONPATH=$VULTURE_HOME/runtime/agents` and imports them directly (`env.go`). Therefore **the lockfile contains only the third-party transitive closure**, and the compile must **exclude** all 11 first-party names (they are unpublished and would fail to resolve from any index). The generator aggregates `[project.dependencies]` across *all* agent pyprojects and strips `vulture-*` entries, so if a future agent adds a third-party dep beyond `vulture-shared`'s, it flows into the lockfile automatically.

**Tool & cross-platform strategy.** Use `uv pip compile` (fast, deterministic, `--generate-hashes`, `--universal`); pip-tools `pip-compile --generate-hashes` is the documented fallback. Pin the `uv` version. The closure has several native wheels — `pydantic-core` (Rust), `tiktoken` (Rust), and via `uvicorn[standard]`: `uvloop`/`httptools`/`websockets`/`watchfiles`; `litellm` also pulls a large sub-tree. Strategy: produce **one universal lockfile** (`--universal`) that lists **every target-platform wheel hash per package**, so a single `requirements-frozen.txt` validates on all four supported targets (linux amd64/arm64, darwin amd64/arm64). Fall back to per-`(os,arch)` lockfiles (`requirements-frozen-<os>-<arch>.txt`, selected by `install.sh`) only if `--universal` cannot satisfy a package. Resolve targeting the floor interpreter (`--python-version 3.12`); the native wheels in scope ship `cp312-abi3`/pure-`py3` wheels usable on 3.13/3.14 hosts, which is what lets one 3.12 resolution serve newer minors — re-checked on every dep bump.

**Generator — `scripts/gen-lockfile.sh` (a.k.a. `make freeze-deps`):**
```sh
# 1. Collect every third-party requirement across all agent pyprojects,
#    dropping first-party 'vulture-*' deps (PYTHONPATH-loaded, never pip-installed).
python3 - <<'PY' > build/agent-deps.in
import glob, tomllib
specs = {}
for f in glob.glob("agents/*/pyproject.toml"):
    for dep in tomllib.load(open(f, "rb"))["project"].get("dependencies", []):
        name = dep.replace("[", " ").split()[0]
        name = name.split(">")[0].split("=")[0].split("<")[0].split("~")[0].strip()
        if not name.startswith("vulture-"):
            specs[dep] = None            # de-dup, preserve the spec
print("\n".join(specs))
PY
# 2. Resolve to a universal, fully hash-pinned lockfile targeting the 3.12 floor.
uv pip compile build/agent-deps.in \
    --universal --generate-hashes --python-version 3.12 \
    --emit-index-url --no-header -o agents/requirements-frozen.txt
# 3. Prepend a "GENERATED by scripts/gen-lockfile.sh — do not edit by hand" banner.
```
Feeding a derived `agent-deps.in` (rather than the pyprojects directly) sidesteps first-party resolution entirely — the `vulture-*` packages never enter the resolver's input.

**Maintainer workflow (invoke & maintain).** The lockfile is **never hand-edited** (it carries a "GENERATED — do not edit" banner); the *source of truth* is the agents' `pyproject.toml` ranges. A pinned `uv` version (bootstrapped by the script, or `pipx install uv==<pinned>`) is what makes two maintainers — and CI — produce byte-identical output; generation needs Python 3.12 + network to PyPI. The lifecycle:

- **Add / bump a dependency.** Edit the range in the owning `pyproject.toml` (almost always `agents/shared/pyproject.toml`), then regenerate, review, and commit *both* files in the **same PR**:
  ```sh
  make freeze-deps                                   # = scripts/gen-lockfile.sh
  git add agents/*/pyproject.toml agents/requirements-frozen.txt
  git diff --cached agents/requirements-frozen.txt   # eyeball new pins + hashes
  ```
- **Refresh to latest in-range (no range change).** `make freeze-deps UPGRADE=1` (→ `uv pip compile --upgrade`) for everything, or `make freeze-deps UPGRADE_PKG=pydantic` (→ `--upgrade-package`) for one. Review + commit as above.
- **Forgot to re-lock?** You can't merge it: CI's `check-lockfile.sh` recompiles and diffs, failing with *"lockfile stale — run `make freeze-deps` and commit."* The gate enforces freshness, not maintainer vigilance.
- **Security bumps.** Dependabot/renovate open the `pyproject` bump as a PR; a renovate `postUpgradeTasks` hook (or a scheduled "relock" CI job that runs `gen-lockfile.sh --upgrade` and opens a PR) regenerates the lockfile so the bot's PR already carries a matching lock. *Plain* Dependabot cannot regenerate a custom hashed lockfile by itself — wiring that hook is an open item below.
- **Verify before pushing.** Run `scripts/check-lockfile.sh` locally (the exact script CI runs) to confirm determinism; optionally `pip install --require-hashes -r agents/requirements-frozen.txt` into a scratch 3.12 venv to smoke-test resolvability.

```make
freeze-deps:   ## regenerate the hashed agent lockfile (UPGRADE=1 / UPGRADE_PKG=<name> optional)
	UPGRADE="$(UPGRADE)" UPGRADE_PKG="$(UPGRADE_PKG)" scripts/gen-lockfile.sh
```

**Where it lives & how it's consumed.** Commit the result at `agents/requirements-frozen.txt` — reviewable in PRs, diffable, and re-derivable by reproducible-build verification. `build-release.sh` copies the committed file into `runtime/agents/requirements-frozen.txt`, replacing today's empty stub. Both install paths then run `pip install --require-hashes -r requirements-frozen.txt`: Tier B into the bundled PBS interpreter; Tier B-lite into the system-Python venv (with `--only-binary :all:`). `install_python_deps` already **fails closed** when the shipped lockfile lacks `--hash=` lines, so a B1 regression cannot silently weaken to a hashless install.

**Freshness & CVE gates (CI).** Add `scripts/check-lockfile.sh` (mirrors `check-fallback-tag.sh`): re-run the compile in a clean env and `diff` against the committed lockfile — fail the build if a `pyproject` dep bump wasn't re-locked. Run `pip-audit`/`trivy` against the *locked* set and gate releases on HIGH/CRITICAL. Track the lockfile with Dependabot/renovate so bumps arrive as reviewable PRs that re-trigger the freshness gate.

**Reproducibility.** `verify-release.sh` re-runs `gen-lockfile.sh` and diffs; a match proves the lockfile is mechanically derived from the pyprojects, not hand-edited.

**Test (TDD).** B1 is mostly tooling, but it has assertable contracts: (a) the generator's output is non-empty and **every** requirement line carries `--hash=sha256:`; (b) **no** first-party `vulture-*` name appears in the lockfile; (c) `check-lockfile.sh` is green immediately after generation and red after an un-relocked dep bump; (d) `pip install --require-hashes` into a throwaway 3.12 venv succeeds **offline** against a local wheelhouse. (a)–(c) are fast unit checks; (d) is the hermetic e2e shared with Tier B-lite docker scenario 2.

**Files touched (B1).** `scripts/gen-lockfile.sh`, `scripts/check-lockfile.sh`, `agents/requirements-frozen.txt` (committed, generated), `scripts/build-release.sh` (copy the real lockfile; drop the empty stub), `.github/workflows/ci.yml` (lockfile-freshness + pip-audit job), `Makefile` (`freeze-deps` target).

**Open decisions (B1).** Universal single lockfile vs per-`(os,arch)`; `uv` vs `pip-tools`; whether to also hash-pin PEP 517 build backends (only needed if a dep is sdist-only — avoided by `--only-binary :all:` on the Tier B-lite path); how far to rely on `abi3` wheels for 3.13/3.14 vs re-compiling per minor; **how the dependency bot regenerates the lockfile** (renovate `postUpgradeTasks` running `gen-lockfile.sh` vs a scheduled relock-and-PR CI job vs maintainer-only manual relock); and **which `uv` version to pin** for reproducible generation across maintainers + CI.

### B2 — bundle PBS + wire `release.yml`

Two CI steps in the `build-tarball` matrix job, before
`build-release.sh` tars the stage:

1. **Fetch + verify PBS** from our own `vendor-pbs-<tag>` release (never
   indygreg directly): download
   `cpython-3.12.x+<pbs>-${OS}-${ARCH}-install_only.tar.gz`, verify its
   SHA against `scripts/pbs-shas.txt` (fail the build on mismatch),
   extract into `runtime/python/`. `vendor-pbs.yml` already produces and
   signs these assets.
2. **Compile the lockfile** (B1) into `runtime/agents/`.

`build-release.sh` gains a CI mode (e.g. `VULTURE_BUNDLE_PBS=1`) that
replaces the two stubs with the real fetch/compile; local builds keep
the `PBS_NOT_BUNDLED` note + empty lockfile (→ CLI-only, the current
honest default).

### B3 — dependency install strategy (decision required)

Two options for getting the deps into the bundled interpreter:

- **(a) Install at install time** — ship PBS + the hashed lockfile; let
  `install.sh` run `pip install --require-hashes` into the bundled
  python. *This is what `install_python_deps` does today.* Pros: smaller
  tarball (wheels not bundled), already implemented. **Cons: needs
  network (PyPI/our mirror) at install time** — breaks air-gapped, the
  very case driving Tier B; and `--require-hashes` reaches PyPI unless
  `VULTURE_PIP_INDEX_URL` points at a self-hosted mirror.
- **(b) Pre-install at build time** — `pip install --require-hashes`
  into `runtime/python/` during the CI build, then tar the populated
  site-packages. Pros: **zero install-time network**, fully offline,
  faster install, exact bytes signed. Cons: ~2–3× larger tarball;
  site-packages must be relocatable (PBS is; avoid absolute shebangs —
  invoke as `python -m`).

**Recommendation: (b) pre-install at build time** — it matches the
air-gapped driver and gives a single signed artifact with no
install-time PyPI dependency. `install_python_deps` then becomes a
verify-only step (confirm the bundled venv imports), and the build does
the `--require-hashes` install. (a) remains a fallback for a "thin
tarball + corporate mirror" deployment if one asks for it.

### B4 — make `smoke-install.sh` prove it

After install, run an actual scan against a tiny fixture repo and assert
findings/exit code — so the install gate can't go green with a
non-functional agent runtime (the false-confidence gap from the
Problem). Run it in the `release.yml` matrix on at least linux-amd64 +
one arm + one darwin.

### B5 — `install.sh` (mostly already done)

`install_python_deps` already distinguishes CLI-only / hashed / hashless
and installs with `--require-hashes`. Under strategy (b) it shifts to a
**verify-only** check (the bundled venv already has deps); under (a) it
is unchanged. `vulture doctor`'s "Python runtime health" + "pip
integrity of bundled wheels" checks already exist for this path.

## Packaging / platform matrix

Same four targets as the Go build and `vendor-pbs.yml`
(linux amd64/arm64, darwin amd64/arm64). Each tarball carries its own
matching PBS. **Windows stays out of scope** (consistent with 0044 — no
Mode E on Windows in v1).

## Security considerations

- **Provenance**: PBS comes only from our re-hosted, dual-controlled
  `vendor-pbs-*` release, SHA-pinned in `scripts/pbs-shas.txt`; never a
  live fetch from indygreg at build or install time (0044 S9).
- **Hash enforcement**: the lockfile must carry `--hash=` for every
  requirement; `install_python_deps` fails closed otherwise (Tier A).
- **Signing/scanning**: the fat tarball flows through the existing
  release pipeline — syft SBOM, trivy CVE scan, `SHA256SUMS`, cosign
  keyless signature. The bundled interpreter + wheels are inside the
  signed blob.
- **CVE surface**: bundling Python + wheels means we now own their CVE
  lifecycle for Mode E. Add the bundled Python minor + the lockfile to
  the same `pip-audit`/`trivy`/Dependabot watch already in CI, and
  document a "bump PBS / recompile lockfile on advisory" runbook.
- **No `--trusted-host` weakening**: strategy (b) removes install-time
  pip entirely; strategy (a) keeps the Tier-A rule (TLS-off only for an
  explicit `http://` mirror).

## Size & performance impact

- PBS `install_only` ≈ 25–45 MB compressed per platform; agent wheels
  add roughly another 15–40 MB depending on native deps. A Mode-E
  tarball grows from a few MB (CLI-only) to ~**60–120 MB**. Note this in
  the README so the download size isn't a surprise.
- Strategy (b) makes install **faster** (no pip resolve/download) at the
  cost of tarball size; (a) is the reverse.

## Alternatives considered (and why not)

| Alternative | Verdict |
|---|---|
| **Use the host's system Python** | Rejected — version/dep drift, no hash guarantees, pollutes user env; the whole point is a self-contained, pinned runtime. |
| **Docker-only (status quo)** | The current answer. Tier B exists *only* to serve users who can't/won't use Docker. |
| **`pex` / `shiv` / zipapp** | Still needs a host interpreter; doesn't solve "no Python on the box." |
| **Static musl CPython** | More fragile wheel compatibility than PBS; PBS is the de-facto standard (uv/rye use it) and we already re-host it. |
| **Rewrite agents in Go** | Out of scope; the agent ecosystem (LLM SDKs, framework libs) is Python. |

## Risks & mitigations

- **Lockfile rot / cross-platform resolution drift** → CI recompiles +
  `pip-audit` on every agent-dep change; split per-platform lockfiles if
  `--universal` can't resolve.
- **PBS relocatability bugs** (absolute paths/shebangs) → invoke via
  `runtime/python/bin/python3.12 -m <module>`, never rely on baked
  shebangs; covered by the B4 smoke scan.
- **Artifact bloat slows releases / hits asset limits** → acceptable at
  4 platforms; revisit only if targets expand.
- **Still need an LLM endpoint.** Bundling Python makes agents
  *runnable*, but the pipeline is LLM-driven — it still needs a
  configured endpoint + key (NVIDIA/OpenAI/local LM Studio/Ollama, via
  `OPENAI_BASE_URL` / `VULTURE_LLM_MODEL`). Tier B does **not** remove
  that external dependency; the docs must keep saying so.

## Test plan (when built)

- Reproducible-build check (`verify-release.sh`) re-derives the lockfile
  + tarball SHA deterministically.
- `smoke-install.sh` runs a real `vulture scan` on a fixture repo across
  the platform matrix (B4).
- `install_python_deps` branch tests extended for the chosen strategy
  (verify-only vs install-time) — reuse `scripts/tests/test_install_sh.sh`.
- `pip-audit` / `trivy` gate the bundled wheels + interpreter.
- Air-gapped install test (strategy b): install with no network, then
  scan.

## Rough effort

≈ 1–2 focused days: B1 lockfile (~½ day incl. cross-platform wheel
hashing), B2 release.yml wiring + build-release.sh CI mode (~½ day), B4
smoke scan (~½ day), docs/runbook + CVE-watch wiring (~½ day). Low risk
to the *existing* product — Tier B only adds artifacts/steps; the
CLI-only path and Modes A/B are untouched. The deferral cost is purely
the ongoing CVE/lockfile maintenance, which is exactly what the Trigger
gates.

---

# Tier B-lite — Use an Existing System Python

## 1. Status

> **STATUS: DEFERRED / PROPOSED — awaiting review.** No code in this section is implemented. The env-flag names, the unit-test seam, and the `install_python_deps` extension point named below are the *contract* a future implementation must honor, not existing behavior.

**Relationship to Tier B.** Tier B ships a hermetic, pinned, hash/cosign-verified Python-Build-Standalone (PBS) interpreter inside the release tarball at `$VULTURE_HOME/runtime/python`. **Tier B-lite is the lighter "bring-your-own-Python" variant**: when no PBS interpreter is bundled, the installer can — *only on explicit opt-in* — locate a host Python ≥ 3.12 and materialize a venv at the **same** runtime path the daemon already expects. It is strictly a fallback below Tier B and strictly above the existing CLI-only path.

**Dependency verification is identical to Tier B.** Tier B-lite installs the **same shipped hashed `requirements-frozen.txt`** with `pip install --require-hashes` into the system-Python venv. Hashes live in the lockfile, not in the interpreter, so `--require-hashes` works regardless of which Python runs it. **The only thing relaxed vs Tier B is the interpreter's provenance** — it is the operator's host Python, not our pinned, cosign-verified PBS. Dependencies stay pinned + hash-verified on both paths.

**Hard prerequisite: the B1 hashed lockfile.** This is the decisive revision from the first draft. Tier B-lite **requires** the shipped `requirements-frozen.txt` to carry `--hash=` lines — i.e. it depends on Tier B's item **B1** (generate a hashed lockfile from the agents' `pyproject.toml`s via `pip-compile --generate-hashes` / `uv pip compile`, committed and staged into the tarball by `build-release.sh`). **Tier B-lite cannot ship before B1.** If the lockfile is absent or hashless, the system-Python path **fails closed** exactly like the bundled path — there is no "install unhashed from PyPI ranges" mode. Rationale below.

### Why an unhashed escape hatch was rejected

An earlier draft proposed a `VULTURE_ALLOW_UNHASHED_DEPS` opt-out that would resolve the agents' `pyproject` version *ranges* live from PyPI when no lockfile was present. **It has been removed.** Hash verification is a property of the *requirements file*, not the interpreter — `--require-hashes` works on any Python — so "use my system Python" never actually required dropping hashes. The draft coupled them only because no lockfile existed yet (B1 undone). Generating hashes locally from the live download is circular (you would hash whatever PyPI served, including a tampered artifact) and yields no tamper-evidence. The correct design is therefore: **do B1, require the lockfile, and verify hashes on every path.** A "trust-me" unhashed mode is not offered. An operator on a private network may still point `VULTURE_PIP_INDEX_URL` at a controlled mirror, but the installer will still demand a hashed lockfile to verify against.

## 2. Trigger / Scope

**Build it when:** B1 (the hashed lockfile) has landed **and** a deployment wants to run agents on a machine that already has Python 3.12+ without downloading/bundling a ~40 MB PBS interpreter (smaller download, re-use of an existing interpreter, or a platform with no PBS artifact). It is the executable answer to "I already have Python 3.12 — use it, but don't weaken anything."

**Explicitly out of scope / what it does NOT do:**
- It does **not** provide an LLM. Agents still require a configured endpoint (OpenAI/Anthropic/Gemini/Ollama keys + model config), exactly as Tier A/B.
- It does **not** relax dependency verification. It installs the **same hashed lockfile with `--require-hashes`** as Tier B; a missing/hashless lockfile is fail-closed.
- It does **not** verify or sandbox the **interpreter**. The host Python binary, its stdlib, and any `sitecustomize.py` are trusted as-is — this is the one provenance relaxation vs PBS and the only residual the opt-in accepts (see §5).
- It does **not** change the Go daemon contract. No edits to `mode.go`/`launcher.go`/`doctor.go` are required for the happy path (one optional doctor tolerance noted in §4/§7).
- It is **off by default.** With no opt-in flag, installer behavior is byte-for-byte unchanged.

## 3. Current-State Recap

From the runtime investigation (all paths in `/home/user/src/vulture-gh`):

- **Daemon's expected install-mode interpreter is hardcoded** at `$VULTURE_HOME/runtime/python/bin/python3.12` — `backend/internal/localdev/mode.go:86-91` (`PythonBin()`), with `$VULTURE_HOME` defaulting to `$HOME/.vulture` (`mode.go:28-37`).
- **`vulture doctor` literally `os.Stat`s that path** — `backend/cmd/vulture/doctor.go:59-77` (`checkPython()`): dev mode is skipped; install mode probes `PythonBin(mode)` and returns WARN/exit 2 if absent.
- **The agent launcher runs `<python> -m uvicorn <module> --host 0.0.0.0 --port <port>`** under a *restricted* `PATH = $VULTURE_HOME/runtime/python/bin:/usr/bin:/bin` and `PYTHONPATH = $VULTURE_HOME/runtime/agents`, scrubbing `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`PYTHONUSERBASE` — `backend/internal/localdev/launcher.go:316-319`, `env.go:38-86` (`BuildAgentEnv()`). Console scripts (`uvicorn`) and the interpreter must therefore live under `runtime/python/bin`.
- **The installer extension point is `install_python_deps()`** — `install.sh` (the function near the `runtime/python/bin/pip` + `requirements-frozen.txt` logic). Today it is a 3-state machine keyed on (a) an executable `$VULTURE_HOME/runtime/python/bin/pip` and (b) a non-empty `$VULTURE_HOME/runtime/agents/requirements-frozen.txt`:
  - State 1 — pip absent **or** reqs empty → `cli_only_note()`; `return 0`.
  - State 2 — pip+reqs present but **no `--hash=` lines** → `err(...)` fail-closed (no override).
  - State 3 — pip+reqs present **with hashes** → `pip install --require-hashes --no-cache-dir --no-build-isolation --index-url <idx> [--trusted-host <host>] -r <reqs>`.
- Agent packages (1 `vulture-shared` + 10 agents) all declare `requires-python = ">=3.12"`. Native wheels needed: **pydantic-core (Rust)**, plus `tiktoken`, `uvloop` (via `uvicorn[standard]`), `websockets`. No vendored deps; full transitive closure comes from PyPI — which is exactly why a generated, hash-pinned lockfile (B1) is the unit of trust.
- A venv created by a 3.12 interpreter yields exactly `bin/python3.12`, `bin/python3`, `bin/python`, and `bin/pip` — i.e. **the precise layout `PythonBin()` and `doctor` already expect.** This is the load-bearing observation that makes a zero-Go-change integration possible.

**Precise extension point:** a new opt-in branch slots into `install_python_deps()` *after* the bundled-PBS handling and *before* the default CLI-only `return 0`, so the bundled path is unaffected and the default fall-through is preserved when the flag is unset.

## 4. Design

### 4.1 Core decision

**Do not change the Go contract.** Instead of teaching Go a new interpreter location, the installer materializes a venv whose layout *is* what Go already expects: `python3.12` + `pip` under `$VULTURE_HOME/runtime/python/bin`. Doctor's `os.Stat` passes, the launcher's restricted `PATH` finds the interpreter and `uvicorn`, and no Go edit is required for the happy path.

### 4.2 Fallback order (precedence)

```
install_python_deps():
  1. BUNDLED PBS present  ($VULTURE_HOME/runtime/python/bin/pip is -x)
       -> existing State 2/3 logic, UNTOUCHED. Strict --require-hashes.   (Tier B)
  2. else if VULTURE_USE_SYSTEM_PYTHON truthy
       -> NEW: REQUIRE a shipped HASHED requirements-frozen.txt; detect a
          system Python >=3.12; build a venv at runtime/python; install the
          lockfile with --require-hashes. Missing/hashless lockfile, no
          interpreter, unsupported version, or any install failure -> err
          (fail-closed; never a silent drop to CLI-only).                 (Tier B-lite)
  3. else
       -> existing State 1: cli_only_note(); return 0.   (DEFAULT, unchanged)
```

Dependency verification is **identical** in branches 1 and 2 (same hashed lockfile, same `--require-hashes`). The only difference between them is the interpreter's provenance. A real bundled interpreter is the most reproducible, so it always wins; CLI-only remains the safe default.

### 4.3 Env-flag contract

A single new opt-in flag (plus two advanced knobs). **`VULTURE_ALLOW_UNHASHED_DEPS` from the first draft is removed** — there is no unhashed path to gate.

| Flag | Meaning | Default |
|---|---|---|
| `VULTURE_USE_SYSTEM_PYTHON` (`1`\|`true`) | Opt in: when no bundled PBS pip exists, locate a host Python ≥ 3.12 and build a venv at `$VULTURE_HOME/runtime/python`, then install the shipped **hashed** lockfile with `--require-hashes`. | unset → bundled PBS, else CLI-only |
| `VULTURE_PYTHON` (optional) | Explicit interpreter path/name to use instead of PATH auto-detection (e.g. `/opt/py/bin/python3.13` or `python3.12`). Honored only when `VULTURE_USE_SYSTEM_PYTHON` is truthy. | unset → auto-detect |
| `VULTURE_PY_MIN_MINOR` (advanced) | Minimum acceptable 3.x minor. Major always pinned to 3. Lets a future bump to 3.13-only be a one-line change. | `12` |

> **Naming is an open decision (see §11).** Investigation inputs also proposed `VULTURE_SYSTEM_PYTHON` (≈ `VULTURE_PYTHON`). This LLD adopts `VULTURE_USE_SYSTEM_PYTHON` / `VULTURE_PYTHON` as canonical; the implementation must commit to one set and document it in the `install.sh` env header.

**Truth table (single opt-in flag; hashes always required):**

| `USE_SYSTEM_PYTHON` | Bundled PBS? | Lockfile | Result |
|---|---|---|---|
| unset | yes | hashed | Bundled hashed install (unchanged). |
| unset | yes | hashless | **FAIL-CLOSED** `err` (unchanged). |
| unset | no/empty | — | CLI-only, `return 0` (unchanged). |
| **true** | no | **hashed** | Detect Python ≥3.12 → venv → `--require-hashes` install. **Deps hash-verified.** |
| **true** | no | hashless/absent | **FAIL-CLOSED** `err` — no lockfile to verify against (do B1 / use a bundled release). |
| **true** | yes | (any) | Bundled wins (precedence); the system-Python branch is not taken. |
| unset | no | hashed | CLI-only — the flag is required to act on the lockfile. |

### 4.4 Detection + version gate

Ask the interpreter itself (`sys.version_info`) — never parse `--version` text (locale/pyenv-shim risk). Major pinned to 3; minor ≥ `VULTURE_PY_MIN_MINOR`. Newer minors (3.13/3.14) are accepted because agents are `>=3.12`.

```sh
# Echoes an absolute interpreter path, or returns non-zero.
detect_system_python() {
    _min="${VULTURE_PY_MIN_MINOR:-12}"
    if [ -n "${VULTURE_PYTHON:-}" ]; then
        _cands="$VULTURE_PYTHON"
    else
        _cands="python3.14 python3.13 python3.12 python3"   # newest-first; python3 last
    fi
    for _c in $_cands; do
        _bin=$(command -v "$_c" 2>/dev/null) || continue
        [ -x "$_bin" ] || continue
        if py_version_ok "$_bin" "$_min"; then printf '%s\n' "$_bin"; return 0; fi
    done
    return 1
}

py_version_ok() {  # <interp> <min_minor> ; true iff CPython 3.<minor>+ with minor>=min
    "$1" - "$2" <<'PY' >/dev/null 2>&1
import sys
need = int(sys.argv[1]); v = sys.version_info
sys.exit(0 if (v.major == 3 and v.minor >= need) else 1)
PY
}
```

### 4.5 venv layout at the daemon-expected path

The venv is built at `$VULTURE_HOME/runtime/python`. A 3.13/3.14 host yields `bin/python3.13`, **not** `python3.12`, so after creation we guarantee a `python3.12` **name** exists via a symlink to the venv's own `python3`. This keeps `PythonBin()`/doctor satisfied for any supported minor without a Go change.

**`--copies`, not symlinked base interpreter.** A symlinked venv shares the host binary; an `apt` minor bump, pyenv GC, or Homebrew cleanup then breaks it at runtime — and because the launcher runs under a *restricted PATH* it cannot fall back, while doctor's `os.Stat` only checks existence (a broken symlink venv would pass doctor yet fail to launch). `python -m venv --copies` makes the runtime self-contained and upgrade-stable (a few MB), matching PBS hermeticity. The single intentional symlink is the intra-venv `python3.12` name alias, which points *inside* the venv and is therefore also upgrade-stable.

```sh
create_system_venv() {  # <interp>
    _interp="$1"; _root="$VULTURE_HOME/runtime/python"; _bin="$_root/bin"

    # Idempotent: reuse a working venv; rebuild only if broken/partial.
    if [ -x "$_bin/python3.12" ] && "$_bin/python3.12" -c 'import sys' 2>/dev/null; then
        log "reusing existing runtime venv at $_root"
    else
        [ -e "$_root" ] && rm -rf "$_root"
        if ! "$_interp" -c 'import venv, ensurepip' 2>/dev/null; then
            err "system Python at $_interp lacks 'venv'/'ensurepip' (e.g. apt-get install python3-venv), or unset VULTURE_USE_SYSTEM_PYTHON for CLI-only."
        fi
        log "creating runtime venv (system Python: $_interp) at $_root"
        "$_interp" -m venv --copies "$_root" || err "venv creation failed at $_root"
    fi

    # Guarantee Go-expected name on 3.13/3.14 hosts.
    [ -e "$_bin/python3.12" ] || ln -s python3 "$_bin/python3.12" \
        || err "could not create python3.12 alias in venv"

    "$_bin/python3.12" -c 'import sys; assert sys.version_info[:2] >= (3,12)' \
        || err "runtime venv interpreter failed version self-check"
}
```

### 4.6 Dependency install — always hash-verified

Venv built **without** `--system-site-packages` (no host-package leak by construction). `PYTHONNOUSERSITE=1` and `--no-cache-dir` for the install; pip upgraded **inside the venv only**. Installation is **always `--require-hashes`** against the shipped lockfile; there is no unhashed branch. The bundled path's `--no-build-isolation` is **dropped here** — on a non-3.12 host a source build may be triggered and isolation must be ON so pip can fetch a build backend. Prefer `--only-binary :all:` so only wheels are used: it avoids sdist build-time code execution (T3) **and** keeps `--require-hashes` simple (no unhashed transient build deps); a platform with no wheel then fails clearly rather than silently building.

```sh
install_deps_system_venv() {
    _pip="$VULTURE_HOME/runtime/python/bin/pip"
    _py="$VULTURE_HOME/runtime/python/bin/python3.12"
    _reqs="$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
    _index="${VULTURE_PIP_INDEX_URL:-https://pypi.org/simple}"

    # Fail closed: Tier B-lite REQUIRES a hashed lockfile (B1), same rule as the
    # bundled path. There is no unhashed mode.
    reqs_have_hashes "$_reqs" || err \
        "requirements-frozen.txt has no --hash= lines; refusing system-Python install (fail-closed). This build ships no hashed lockfile (Tier B item B1); use a bundled-runtime release."

    PYTHONNOUSERSITE=1 "$_py" -m pip install --disable-pip-version-check \
        --no-cache-dir --upgrade pip >/dev/null 2>&1 || true

    set -- --require-hashes --only-binary :all: --no-cache-dir \
           --disable-pip-version-check --index-url "$_index"
    case "$_index" in   # http:// mirror -> scope --trusted-host (existing TLS gate; never relaxed otherwise)
        http://*) _h=$(printf '%s' "$_index" | sed -e 's,^http://,,' -e 's,/.*$,,')
                  warn "VULTURE_PIP_INDEX_URL is http:// ($_index); disabling TLS verification for $_h"
                  set -- "$@" --trusted-host "$_h" ;;
    esac

    log "installing agent deps (hash-pinned) into runtime venv (system Python)"
    PYTHONNOUSERSITE=1 "$_pip" install "$@" -r "$_reqs" \
        || err "pip install (hash-pinned) failed in runtime venv"

    # Prove the runtime can launch an agent before first `vulture up`.
    PYTHONNOUSERSITE=1 "$_py" - <<'PY' || err "runtime venv import self-check failed (uvicorn/fastapi/pydantic)"
import importlib
for m in ("uvicorn", "fastapi", "pydantic", "pydantic_core"):
    importlib.import_module(m)
PY
}

reqs_have_hashes() { grep -q -- '--hash=' "$1" 2>/dev/null; }
```

### 4.7 Integration point in `install_python_deps`

```sh
install_python_deps() {
    PIP="$VULTURE_HOME/runtime/python/bin/pip"
    REQS="$VULTURE_HOME/runtime/agents/requirements-frozen.txt"

    # State 2/3: bundled PBS present -> existing strict hash-pinned logic (UNCHANGED).
    if [ -x "$PIP" ]; then
        # ... existing fail-closed + --require-hashes install ...
        return 0
    fi

    # NEW: opt-in system Python (only when no bundled interpreter).
    if [ "${VULTURE_USE_SYSTEM_PYTHON:-}" = "1" ] || [ "${VULTURE_USE_SYSTEM_PYTHON:-}" = "true" ]; then
        [ -s "$REQS" ] || err "VULTURE_USE_SYSTEM_PYTHON set but $REQS is missing/empty; this build ships no hashed lockfile (Tier B item B1)."
        _sys_py=$(detect_system_python) \
            || err "VULTURE_USE_SYSTEM_PYTHON set but no Python >= 3.${VULTURE_PY_MIN_MINOR:-12} found (set VULTURE_PYTHON to point at one)."
        log "using system Python: $_sys_py"
        create_system_venv "$_sys_py"
        install_deps_system_venv     # enforces --require-hashes / fail-closed
        return 0
    fi

    # State 1 (DEFAULT, unchanged): no bundled interp, no opt-in -> CLI-only.
    cli_only_note
    return 0
}
```

### 4.8 Idempotency / upgrade

- **Re-run:** `create_system_venv` reuses a venv that passes `python3.12 -c 'import sys'`; otherwise it `rm -rf`'s the stale/partial dir and rebuilds. `pip install -r` is itself idempotent.
- **Upgrade:** a new tarball overwrites `runtime/agents` (sources + new hashed frozen manifest) but the venv at `runtime/python` is reused; `install_deps_system_venv` re-runs `--require-hashes` against the new lockfile, so dependency changes are picked up without rebuilding the interpreter. A minimum-Python bump still satisfies the reused venv's `>=3.12` self-check.
- **Host interpreter removed/upgraded after install:** `--copies` keeps the venv working (the core justification for `--copies`).

## 5. Security & Fail-Closed

With the unhashed path removed, the **dependency supply chain is fully preserved** on the system-Python path: deps are pinned + hash-verified by the same lockfile and `--require-hashes` as the bundled path. The opt-in converts exactly **one** guarantee from enforced to operator-accepted: the **interpreter's provenance** (host Python instead of pinned/cosign-verified PBS). We retain dependency hash verification, transport security, write confinement, version sanity, and full-removal uninstall. We cannot defend the interpreter binary, the system stdlib's `sitecustomize`, or any sdist build-time code execution (mitigated by `--only-binary :all:`); these are the stated residuals and are surfaced in the install message.

### 5.1 What stays fail-closed (non-negotiable)

1. **Hashless/absent lockfile refuses on BOTH paths** — bundled *and* system-Python. No flag rescues it; the system-Python branch errs identically to the bundled one.
2. **Hashes required everywhere** — `--require-hashes` is used on the bundled and system-Python paths alike. There is no mode that installs without hashes.
3. **No silent fallback** — unresolved interpreter, unsupported version, or venv/pip failure → `err`, never a quiet drop to CLI-only or bundled.
4. **TLS to the index stays mandatory** — `--trusted-host` is gated solely on an explicit `http://` `VULTURE_PIP_INDEX_URL`; nothing about the system-Python path relaxes index TLS.

### 5.2 venv isolation guarantees

- Build a dedicated venv; **never** install into the system interpreter; only ever invoke `$VULTURE_HOME/runtime/python/bin/pip`.
- **No** `pip install --user` / global pip; `PYTHONNOUSERSITE=1` so `~/.local` cannot leak in.
- **No** `--system-site-packages`; the agent runtime resolves only what we installed under `$VULTURE_HOME`.
- `vulture uninstall --yes` (`rm -rf "$VULTURE_HOME"`) reclaims 100% of installed libs. Test invariant: after uninstall, the *system* interpreter's importable packages are unchanged (we never touched it).
- Residual: the venv shares the host interpreter binary + stdlib by reference (copied with `--copies`); the interpreter itself is not sandboxed.

### 5.3 Threat-model table

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Dependency version drift / yanked / back-doored release | **`--require-hashes` against the shipped B1 lockfile — same as bundled.** Pinned `--index-url`. | **None beyond Tier B** — resolution is hash-pinned identically to the bundled path. |
| T2 | Unhashed-artifact tampering / wheel MITM | **Mandatory hashes** reject any artifact whose bytes don't match the lockfile; index TLS mandatory. | **None beyond Tier B** — a tampered wheel fails the hash check. |
| T3 | Build-from-source executes attacker code at install (`setup.py`/PEP517) | `--only-binary :all:` (wheels only); unprivileged install user, never root. | A platform with no wheel fails clearly (no silent build); no sdist code runs. |
| T4 | Malicious/hijacked system interpreter (shim, PATH poison) | Resolve via `command -v`; log absolute resolved path + version; refuse non-`>=3.12`; never search CWD. | Cannot attest the binary; the operator's machine and choice — the one accepted relaxation. |
| T5 | `sitecustomize`/`usercustomize`/`PYTHONSTARTUP` injection at runtime | venv without system-site; `PYTHONNOUSERSITE=1`; launcher scrubs `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`PYTHONUSERBASE` + restricts PATH. | `sitecustomize.py` inside the *system stdlib dir* still inherited; not removable without owning the interpreter. |
| T6 | Version skew (3.13/3.14 behavior change, or 3.9 unsupported) | Hard `>=3.12` gate (`err` on <3.12); >3.12 proceeds with a "tested on 3.12" warning. | Newer-minor runtime incompatibilities not caught at install. |
| T7 | Native-wheel ABI mismatch (pydantic-core/uvloop/tiktoken vs libc/arch) | pip selects the right wheel; `--only-binary` + hard `err` on no-wheel, no partial state. | musl/uncommon-arch may have no wheel → hard fail (operator must use bundled/Docker). |
| T8 | Stale/orphaned venv across reinstall or in-place interpreter upgrade | `--copies` self-contained; reinstall rebuilds; idempotent reuse-or-rebuild; venv self-check. | In-place host upgrade may require a reinstall — degraded, not a security exposure. |
| T9 | Privilege / write-path confinement | venv + libs only under `$VULTURE_HOME`; reject HOME = system dir; HOME perms 700. | None notable. |

The decisive change from the first draft: **T1 and T2 are now fully mitigated** (required hashes), so the system-Python path is no weaker than bundled *for dependencies*. The accepted residual is confined to the interpreter (T4/T5) and platform wheel availability (T7).

### 5.4 Required messages (exact strings)

Using existing `log()` / `warn()` (stderr, `warning:`) / `err()` (stderr, `error:`, exit 1).

**A — system Python selected; one-line provenance notice (info):**
```
log: using system Python at <resolved-abspath> (Python <X.Y>) — agent DEPENDENCIES are
log: hash-verified against requirements-frozen.txt; the INTERPRETER is operator-provided
log: and not cosign/PBS-verified. Use a bundled-runtime release for a fully verified stack.
```

**B — unsupported interpreter version (refuse):**
```
error: system Python is <X.Y> at <resolved-abspath>; Vulture agents require >=3.12.
error: install a Python >=3.12 and re-run, or use the bundled-runtime release.
```

**C — system-Python opt-in but no hashed lockfile in this build (refuse):**
```
error: VULTURE_USE_SYSTEM_PYTHON is set but requirements-frozen.txt has no --hash= lines.
error: Tier B-lite installs ONLY a hash-pinned lockfile (Tier B item B1); this build ships
error: none. Use a bundled-runtime release, or build a tarball with a --generate-hashes lock.
```

**D — present-but-hashless BUNDLED lock (unchanged):**
```
error: requirements-frozen.txt has no --hash= lines; refusing hashless install (fail-closed).
```

**E — `http://` mirror (compose with the existing TLS gate; do not relax):**
```
warning: VULTURE_PIP_INDEX_URL is http:// (<index>); disabling TLS verification for <host>.
warning: dependency hashes still verify artifact integrity, but the transport is unauthenticated.
```

## 6. Fresh-Docker Test Matrix

Anchored on verified install.sh behavior: offline path reads `${TARBALL%.tar.gz}.SHA256SUMS` + `.sig` at the same stem; `VULTURE_ALLOW_UNSIGNED=true` + empty `.sig` accepted; deps key off pip + `requirements-frozen.txt`. `VULTURE_USE_SYSTEM_PYTHON` **does not exist yet** — scenarios 2, 4 and 7 encode the feature's acceptance contract and are *expected-red* until it lands.

| # | Name | Base image | Setup / fixture | Env to install.sh | Expected outcome |
|---|---|---|---|---|---|
| 1 | `no-python-cli-only` | `ubuntu:24.04` purged of `python3*` (or `debian:12-slim`) | CLI-only tarball: empty `runtime/python/bin/`, `PBS_NOT_BUNDLED`, **empty** frozen manifest | offline tarball, `ALLOW_UNSIGNED`, `NO_UPDATE_CHECK`, `VULTURE_HOME` | rc 0; `bin/vulture` + `VERSION` present; no `runtime/python/bin/python3*`; no `pyvenv.cfg`; stdout has `agent runtime not bundled`; `doctor` rc ∈ {0,2}; `uninstall --yes` leaves no residue. **Green today.** |
| 2 | `py312-optin-hashed` | `python:3.12-slim` | Agents source + **hashed** frozen lockfile (a small real `--hash=` fixture, or a local wheelhouse — see §6.1) | + `VULTURE_USE_SYSTEM_PYTHON=1` | rc 0; venv at `runtime/python` (`bin/python3.12` + `pyvenv.cfg`); pip invoked **with `--require-hashes`**; `runtime/python/bin/python3.12 -c "import fastapi,pydantic,uvicorn"` rc 0; `doctor` rc 0. **Expected-red until flag lands.** |
| 3 | `py312-no-optin-default` | `python:3.12-slim` | Same CLI-only tarball as #1 | offline tarball only (NO opt-in) | Default unchanged though 3.12 present: rc 0, `agent runtime not bundled`, **no** venv. Proves opt-in is required. **Green today.** |
| 4 | `py39-optin-refuse` | `python:3.9-slim` | Agents source + hashed lockfile (as #2) | + `VULTURE_USE_SYSTEM_PYTHON=1` | rc **non-zero** naming `>=3.12`; **no** `pyvenv.cfg`, no partial `site-packages`; idempotent after refusal. **Expected-red until flag lands.** |
| 5 | `offline-no-network` | `python:3.12-slim`, run `--network none` | CLI-only tarball; companions mounted read-only | as #1 | rc 0 with **zero** egress; same binary/VERSION/uninstall assertions as #1. **Green today.** |
| 6 | `hashless-failclosed-bundled` (security) | `python:3.12-slim` | Tarball with **executable** stub `runtime/python/bin/pip` + non-empty **hashless** manifest | as #1 (no opt-in) | rc **non-zero**; stderr has `refusing hashless install (fail-closed)`; no deps installed. **Green today.** |
| 7 | `py312-optin-no-lockfile-failclosed` (security) | `python:3.12-slim` | Agents source + **empty/hashless** frozen manifest (no bundled pip) | + `VULTURE_USE_SYSTEM_PYTHON=1` | rc **non-zero**; stderr has the no-hashed-lockfile refusal (msg C); **no** venv deps installed. Encodes the "no unhashed escape hatch" rule. **Expected-red until flag lands.** |

### 6.1 Offline-tarball fabrication recipe

No real release / cosign / Go binary needed. A POSIX-sh `vulture` stub satisfies `version`/`doctor`/`uninstall` (doctor returns 2 unless `runtime/python/bin/python3.12` exists, mimicking real doctor). Variants:

- **A — CLI-only** (#1, #3, #5): stub `bin/vulture`, `VERSION`, `runtime/python/PBS_NOT_BUNDLED`, empty `runtime/python/bin/`, **empty** `requirements-frozen.txt`.
- **B — agents + hashed lock** (#2, #4): same + real `runtime/agents/shared/...` + a **hashed** `requirements-frozen.txt`. Because scenario 2 actually runs `pip --require-hashes`, the fixture lockfile must carry **real** hashes for whatever it installs. Two hermetic options: (i) a *tiny* real lockfile of a couple of pure-Python wheels pinned with real `--hash=` (generated once via `pip-compile --generate-hashes`, committed as a fixture), or (ii) a local PEP 503 wheelhouse + `--index-url file://…` so the e2e never touches PyPI. Pick (ii) for the full agent set; (i) suffices to prove the `--require-hashes` argv + venv path.
- **C — bundled-pip hashless** (#6) and **agents hashless** (#7): non-empty **hashless** manifest to force the respective fail-closed branches (no real hashes needed — install must refuse before downloading).

Fabricator `build-fixture-tarball.sh <variant> <out.tar.gz>` stages the tree, then produces a reproducible tarball matching `build-release.sh` flags and the companion files at the same stem:

```sh
( cd "$STAGE" && tar --sort=name --mtime='2020-01-01 00:00:00Z' \
    --owner=0 --group=0 --numeric-owner -cf - . | gzip -9n > "$OUT" )
BASE="${OUT%.tar.gz}"
sha256sum "$OUT" | awk -v n="$(basename "$OUT")" '{print $1"  "n}' > "$BASE.SHA256SUMS"
: > "$BASE.sig"     # empty sig accepted with VULTURE_ALLOW_UNSIGNED=true
```

### 6.2 Runner layout

```
scripts/tests/docker/
├── Dockerfile                  # single parametrized image: ARG BASE_IMAGE, ARG PURGE_PY
├── vulture-stub.sh             # stub binary baked into fixtures
├── build-fixture-tarball.sh    # fabricator (cli-only|agents-hashed|agents-hashless|bundled-hashless)
├── wheelhouse/                 # optional local wheels for the hermetic hashed scenario (2)
├── runner.sh                   # in-container: runs install.sh + per-scenario asserts
└── run-matrix.sh / run-one.sh  # host driver (builds fixtures + images, runs scenarios)
```

`runner.sh` reads `$SCENARIO`, exports the offline env (and, for 2/4/7, `VULTURE_USE_SYSTEM_PYTHON=1`), runs `sh /repo/install.sh`, captures `$?`, and per-scenario asserts: rc, `bin/vulture` + `VERSION`, presence/absence of `runtime/python/pyvenv.cfg`, the `--require-hashes` argv (scenario 2, via a pip wrapper log), venv import probe, `doctor` rc, refusal message (4/7), and `uninstall` residue. Companions bind-mount to `/fix/vt.SHA256SUMS` + `/fix/vt.sig` so they line up with `${TARBALL%.tar.gz}` = `/fix/vt`.

### 6.3 CI integration

Add an `install-docker-matrix` job to `.github/workflows/ci.yml` (gated after the installer-lint job), `strategy.fail-fast: false`, one matrix entry per scenario. Scenarios 1/3/5/6 are **required now**; 2/4/7 carry `continue-on-error: true` (expected-red) until `VULTURE_USE_SYSTEM_PYTHON` ships (which itself is gated on B1), then flip to required.

## 7. TDD Plan

Feature contract: when `VULTURE_USE_SYSTEM_PYTHON=true`, no bundled pip exists, **and a hashed lockfile is present**, resolve a system Python ≥ 3.12 (`VULTURE_PYTHON` first, then PATH), build a venv at `$VULTURE_HOME/runtime/python`, and install the lockfile with `--require-hashes` — preserving fail-closed/TLS/default-off/idempotent properties. A missing/hashless lockfile fails closed. Extend `scripts/tests/test_install_sh.sh` (reusing its `VULTURE_INSTALL_SOURCE_ONLY=1` seam, `run_in_install`, `setup_home`, `make_pip`, `SHIMBIN`, argv-log, `SEAM_OK` guard) for fast unit tests; use the §6 docker matrix for real e2e.

### 7.1 RED unit tests (append to `scripts/tests/test_install_sh.sh`)

Add a `make_python` shim (honors `FAKE_PYVER` + `VULTURE_PYTHON`; on `-m venv DIR` creates `DIR/bin/pip` as an argv recorder writing `VENV_PIP_LOG`) so detection, gating, venv-path, and pip argv are observable with zero network.

| # | Test | Asserts | RED reason |
|---|---|---|---|
| U1 | `default-off-no-flag` | Flag unset, no bundled pip → CLI-only `return 0`; `python`/`venv` shims never invoked. | Guards GREEN (regression lock). |
| U2 | `detects-and-uses-system-python` | Flag on, **hashed** manifest, 3.12 shim → resolves python, creates venv, runs venv-pip (log non-empty). | Flag ignored today; early CLI-only return. |
| U3 | `venv-at-expected-runtime-path` | venv at exactly `$VULTURE_HOME/runtime/python`; pip lives under it. | No venv code exists. |
| U4 | `version-gate-rejects-3.11` | `FAKE_PYVER=3.11` → `err` naming 3.12; no venv, no pip. | No gate. |
| U5 | `version-gate-accepts-3.12-and-3.13` | 3.12 then 3.13 both proceed (`>=`, not `==`). | No gate. |
| U6 | `explicit-interpreter-path` | `VULTURE_PYTHON=<shim>` honored over PATH. | Var unrecognized. |
| U7 | `no-python-found-errs` | Flag on, none on PATH, no `VULTURE_PYTHON` → `err`; no venv/pip. | Falls through silently. |
| U8 | `fail-closed-no-lockfile` | Flag on, **hashless/empty** manifest → `err` (msg C); venv-pip NOT invoked. **This is the "no unhashed escape hatch" lock.** | System branch absent. |
| U9 | `require-hashes-always` | Flag on, **hashed** manifest, https → venv-pip argv contains `--require-hashes` and `--only-binary :all:`, no `--trusted-host`. | Path absent. |
| U10 | `http-index-trusted-host` | `http://mirror:8080/simple` + hashed lock → argv has `--trusted-host mirror`, still `--require-hashes`. | Path absent. |
| U11 | `idempotent-rerun` | Two installs into same HOME both rc 0; valid venv after second; no abort on existing venv. | No venv code; naive `venv` on existing dir fails. |
| U12 | `bundled-python-wins-over-flag` | Bundled pip present AND flag set → bundled path used, no fresh venv. | Precedence undefined today. |

(The first draft's `fail-closed-unhashed` + `fail-closed-opt-out` pair collapses into a single U8: with the escape hatch gone, a hashless lockfile simply refuses.)

### 7.2 RED docker e2e

E1 `no-python` (flag on, hashless → fast `err`, no venv); E2 `python312-hashed` (venv at runtime path, `--require-hashes` install, `doctor` 0, probe import OK); E3 `python39` (gate rejects, no venv); E4 `offline --network none`; E5 `python312-rerun` (idempotent); E6 `python312-no-lockfile` (msg C fail-closed). All red until install.sh implements the feature.

### 7.3 RED-agent brief

**Goal:** add failing tests only; do not implement. **MUST:** append U1–U12 to `scripts/tests/test_install_sh.sh` following existing conventions (`pass`/`fail`, `SEAM_OK`, `run_in_install`, sandboxed `SHIMBIN`, per-test argv logs, final count + non-zero exit); add the `make_python` shim near `make_pip`; create the docker scaffolding (`Dockerfile`, `runner.sh`, `build-fixture-tarball.sh`, wheelhouse-or-tiny-hashed fixture, CI workflow) with a **hashed** and a **hashless** manifest variant and no bundled interpreter; document the contract env-var names (`VULTURE_USE_SYSTEM_PYTHON`, `VULTURE_PYTHON`) in comments; run the harness and capture RED output proving each fails for the stated reason. **MUST NOT:** touch `install.sh` or any Go; weaken assertions to pass; add a real interpreter to the unit layer (shims only). **Return:** absolute file paths + captured RED output.

### 7.4 GREEN-agent brief

**Goal:** make the whole suite pass with minimal change. **MUST:** edit `install_python_deps()` to add the system-Python branch preserving precedence (bundled wins → opt-in system → CLI-only), the `>=3.12` gate, venv at `$VULTURE_HOME/runtime/python` with the `python3.12` alias + `--copies`, **`--require-hashes` + `--only-binary :all:`** install, the **hashless/absent-lockfile fail-closed refusal (msg C)**, TLS reuse, and idempotency; keep it POSIX-sh + shellcheck-clean; document the new vars in the `install.sh` env header; make the *minimal* `doctor.go`/`mode.go` change only if E2's `doctor` rc-0 assertion requires it. **MUST NOT:** edit any test/fixture/shim to force a pass; introduce any unhashed install path; change existing safety behaviors (bundled flow, hashless fail-closed, http-only `--trusted-host` gate, the `VULTURE_INSTALL_SOURCE_ONLY` seam, `main()` sequence); add a second seam. **Return:** diff summary (absolute paths + load-bearing branch logic) + full green output for both layers.

## 8. Files Touched

- `/home/user/src/vulture-gh/install.sh` — new `detect_system_python`, `py_version_ok`, `create_system_venv`, `install_deps_system_venv`, `reqs_have_hashes` helpers; new opt-in branch in `install_python_deps()`; env-var doc header.
- `/home/user/src/vulture-gh/scripts/tests/test_install_sh.sh` — U1–U12 + `make_python` shim.
- `/home/user/src/vulture-gh/scripts/tests/docker/` — `Dockerfile`, `vulture-stub.sh`, `build-fixture-tarball.sh`, wheelhouse-or-hashed-fixture, `runner.sh`, `run-matrix.sh`/`run-one.sh`.
- `/home/user/src/vulture-gh/.github/workflows/ci.yml` (or new `test-install-docker.yml`) — `install-docker-matrix` job.
- *Conditionally* `backend/cmd/vulture/doctor.go` and/or `backend/internal/localdev/mode.go` — only if an e2e `doctor` assertion forces a tolerance change (kept minimal).
- **Prerequisite (not in this feature):** Tier B item **B1** — a hashed `requirements-frozen.txt` generated from the agents' `pyproject.toml`s and staged by `build-release.sh`. Tier B-lite is blocked on B1.

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Operator assumes "system Python" = weaker deps | It isn't — deps are hash-verified identically to bundled. The one-line provenance notice (msg A) states exactly what is and isn't verified (deps yes, interpreter no). |
| Tier B-lite shipped before B1 → nothing to hash-verify | Hard prerequisite + fail-closed refusal (msg C, U8, scenario 7): without a hashed lockfile the path refuses, so a premature ship degrades to "refuse", never "unhashed install". |
| `python3.12` alias on a 3.13 host hides a real version mismatch | venv self-check asserts `>=3.12`; import self-check proves runnable; doctor still stats the path. |
| Broken venv passes doctor's existence-only stat | `--copies` self-contained venv + import self-check at install time; idempotent rebuild on next run. |
| Missing wheel for a native dep on an exotic platform | `--only-binary :all:` → hard `err` (no silent sdist build); operator falls back to bundled/Docker. |
| Debian/Ubuntu split `python3-venv` not installed | Pre-check `import venv, ensurepip`; `err` names the apt package. |
| Hermetic hashed e2e (scenario 2) is heavy | Use a local wheelhouse + `--index-url file://` (no PyPI), or a tiny real hashed fixture to prove argv/path. |
| Expected-red CI scenarios masking unrelated breakage | `continue-on-error` scoped to scenarios 2/4/7 only; flip to required immediately on landing. |

## 10. Rollback

- **Feature is off by default**, so rollback is to ship without the branch or to leave the flag unset — installer behavior is byte-for-byte the current CLI-only/bundled flow.
- **Code rollback:** revert the `install_python_deps` branch + helpers and the doc-header edit; the test additions can stay as expected-red. No Go change ships unless E2 forced one; if it did, revert that minimal tolerance too.
- **Operator-side rollback after a system-Python install:** `vulture uninstall --yes` removes `$VULTURE_HOME` (including the venv) entirely; the host interpreter and its site-packages are untouched. Re-installing a bundled release transparently supersedes the venv (bundled pip wins per §4.2).

## 11. Open Decisions for the Reviewer

- **Flag names.** Adopt `VULTURE_USE_SYSTEM_PYTHON` / `VULTURE_PYTHON` (this LLD) or the investigation alias `VULTURE_SYSTEM_PYTHON`? One set must be canonical and documented in the `install.sh` env header.
- **venv interpreter strategy.** `--copies` (upgrade-stable, +few MB, recommended) vs symlinked base (smaller, fragile under host upgrades). Confirm `--copies`.
- **`python3.12` name alias.** Acceptable to alias `python3.12 → python3` inside the venv on 3.13/3.14 hosts, or should the daemon/`PythonBin()` instead learn to glob `python3.*`? (Latter is a Go change; former is zero-Go.)
- **Version ceiling.** Accept any `>=3.12` (3.13/3.14 with a warning), or pin an upper bound until each minor is tested?
- **`--only-binary :all:`.** Confirm wheels-only (rejects no-wheel platforms cleanly, blocks sdist code execution, keeps `--require-hashes` simple) vs allowing hashed sdists.
- **Docker base images.** Confirm `ubuntu:24.04`/`debian:12-slim` (no-python), `python:3.12-slim`, `python:3.9-slim`; and the hermetic-hashed approach for scenario 2 (local wheelhouse vs tiny real fixture).
- **Doctor tolerance.** Should `doctor` additionally verify the recorded interpreter still *resolves/runs* (not just `os.Stat`), given T8? If yes, that is a small intentional Go change beyond the happy path.
- **Sequencing.** Confirm B1 (hashed lockfile) is scheduled **before** Tier B-lite, since the latter is fail-closed without it.

> **RESOLVED (was open decision #1):** *Is an unhashed BYO install allowed?* **No.** The hashed lockfile is the required path; there is no `VULTURE_ALLOW_UNHASHED_DEPS` escape hatch. Hash verification is interpreter-independent, so "use my Python" keeps full dependency verification. See §1 "Why an unhashed escape hatch was rejected".

## 12. Review Checklist

- [ ] Default-off confirmed: with no flag, install behavior is byte-for-byte unchanged (U1, scenario 3).
- [ ] Precedence is bundled PBS > opt-in system Python > CLI-only; bundled wins even with the flag set (U12).
- [ ] **Hashes required on the system-Python path**: pip argv has `--require-hashes` (+ `--only-binary :all:`) for a hashed lockfile (U9, scenario 2).
- [ ] **No unhashed path exists**: a hashless/absent lockfile with the flag set refuses (msg C, U8, scenario 7); bundled-hashless still refuses (msg D, scenario 6).
- [ ] TLS gate unchanged: `--trusted-host` only on explicit `http://` index; hashes still verify integrity (U10, msg E).
- [ ] venv at exactly `$VULTURE_HOME/runtime/python`; `python3.12` resolvable; `--copies` used; no `--system-site-packages`; `PYTHONNOUSERSITE=1` (U3, §5.2).
- [ ] Version gate rejects <3.12 cleanly with no half-install; accepts ≥3.12 (U4, U5, scenario 4).
- [ ] Idempotent re-run and tarball-upgrade reuse the venv and pick up the new lockfile (U11).
- [ ] `vulture uninstall --yes` removes the venv; system interpreter/site-packages untouched.
- [ ] No Go change ships unless an e2e doctor assertion requires it, and any such change is minimal.
- [ ] Flag names signed off and documented in the `install.sh` env header.
- [ ] **B1 (hashed lockfile) sequenced before Tier B-lite**; expected-red CI scenarios (2, 4, 7) tracked for flip-to-required on landing.

---

# Release Process — `scripts/vulture.sh release` + GitHub Actions

> **STATUS: PROPOSED — awaiting review.** Design only; no code implemented. Several `release.yml` "deltas" below are *fixes to pre-existing gaps* in the current workflow (confirmed by review against the live file).

## 1. Core principle — split by trust domain, not by convenience

Release prerequisites fall into two classes that must stay in **different hands and different times**:

| Class | Examples | Producer | When | Property |
|---|---|---|---|---|
| **Inputs** (decide *what* ships) | hashed lockfile (B1), `FALLBACK_TAG`, version | a **maintainer**, in a reviewed PR (`make freeze-deps`) | *before* the tag | human-reviewed, committed, reproducible |
| **Outputs** (derived from inputs) | per-platform tarballs, `SHA256SUMS`, SBOM, cosign sig | **GitHub Actions** (`release.yml`) | *at* tag time | built in an isolated hosted runner |

The lockfile is an **input** → generated + reviewed + committed *before* release, never produced during it. Decisive constraint: **cosign keyless signing requires the Actions OIDC identity** (`https://github.com/${OWNER}/${REPO}/.github/workflows/release.yml@…`, issuer `token.actions.githubusercontent.com`) that `install.sh` pins via `--certificate-identity-regexp`. That signature **cannot** be reproduced on a maintainer laptop, so the *authoritative* release is necessarily a GitHub Actions responsibility. `vulture.sh release` is a **local preflight + tag-cut**, not the artifact authority.

## 2. `scripts/vulture.sh release [--check] vX.Y.Z` — local preflight + cut

A new `release)` case in the existing `case "$COMMAND"` dispatch. It is a **gate, not a generator**: it verifies every input is met-and-committed, then cuts the tag that triggers `release.yml`. It MUST NOT generate or bake the lockfile into anything.

Conventions: `vulture.sh` already runs `set -euo pipefail` and uses `[[ ]]` tests; this feature adds small `die()`/`log()` helpers (the script currently only has `usage()`). **DRY:** every gate is a *standalone script* (`check-lockfile.sh`, `check-fallback-tag.sh`, `release-version-check.sh`, `verify-no-secrets-in-logs.sh`) invoked by **both** the CI `lint` job (canonical, exhaustive) and this preflight (a curated subset) — no check is inlined into either caller, so they cannot drift.

**Gate sequence (fail-closed; aborts before tagging on any failure):**
1. Tag format is `vX.Y.Z`; refuse otherwise (don't push a malformed tag that all later gates would still accept).
2. Working tree clean; `HEAD` on `main` (not detached); local in sync with `origin/main`; `origin` is the expected repo (don't tag a fork).
3. Tag does not already exist locally or on `origin`. *(This `git ls-remote` check is advisory — there is a TOCTOU window before `git push`; the definitive guard against a moved/duplicate tag is GitHub **tag protection**, §5.)*
4. `scripts/check-fallback-tag.sh vX.Y.Z` — verifies the `FALLBACK_TAG` in `install.sh` is **not newer** than the tag being cut (warns if equal). **Known gap:** despite its docstring, the script does **not** currently enforce the H2 *"≥ latest−1"* floor — a fallback many versions behind still passes. Strengthening it to compare against the *previous published tag* (so a CVE yank actually forces a bump) is a required fix tracked in Open decisions; it also shares the `sort -V` portability issue fixed in `install.sh` (use a pure-awk compare).
5. `scripts/check-lockfile.sh` — B1 freshness (re-compile + diff; on failure: "run `make freeze-deps` and commit").
6. `scripts/release-version-check.sh vX.Y.Z` — `./VERSION` ↔ `FALLBACK_TAG` ↔ requested tag agree.
7. CI-mirroring gates so a bad tag fails *locally* first: `shellcheck install.sh scripts/*.sh scripts/tests/*.sh`, `sh scripts/tests/test_install_sh.sh`, backend `go test ./...`, agent `pytest`, `verify-no-secrets-in-logs.sh`. (Heavy suites may be sampled locally; CI remains authoritative — see Open decisions.)
8. *(Tier B only)* assert vendored `vendor-pbs-*` assets + `scripts/pbs-shas.txt` cover all four platforms for this release.
9. `--check` ⇒ stop (dry-run, exit 0). Otherwise: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z` → triggers `release.yml`.

**Acceptable shortcut (solo maintainer):** step 5 *may* run `make freeze-deps` itself and **halt if it produced a diff** ("lockfile was stale — commit it, then re-run"). That is verify-by-regenerate, never generate-and-ship; it must never tag with an uncommitted lock.

```sh
# vulture.sh is already `set -euo pipefail`; this feature adds die()/log().
release)
    CHECK=0
    [[ "${1:-}" == "--check" ]] && { CHECK=1; shift; }
    TAG="${1:?usage: vulture.sh release [--check] vX.Y.Z}"
    [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "tag must match vX.Y.Z (got: $TAG)"
    [[ -z "$(git status --porcelain)" ]]               || die "working tree not clean"
    [[ "$(git rev-parse --abbrev-ref HEAD)" == main ]] || die "not on main"
    git fetch -q origin
    [[ "$(git rev-parse @)" == "$(git rev-parse '@{u}')" ]] || die "main not in sync with origin"
    git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists locally"
    git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1 && die "tag $TAG exists on origin"  # advisory (TOCTOU) — see §5 tag protection
    scripts/check-fallback-tag.sh "$TAG"
    scripts/check-lockfile.sh                          # B1 freshness gate
    scripts/release-version-check.sh "$TAG"            # VERSION <-> FALLBACK_TAG <-> tag
    shellcheck install.sh scripts/*.sh scripts/tests/*.sh
    sh scripts/tests/test_install_sh.sh
    ( cd backend && go test ./... )
    command -v pytest >/dev/null || die "pytest not found — prepare the agent dev env first; CI is authoritative"
    ( cd agents && python -m pytest -q )
    scripts/verify-no-secrets-in-logs.sh "$HOME/.vulture-smoke"   # exits 0 when no smoke dir; GATES on a real leak (no '|| true')
    [[ "$CHECK" == 1 ]] && { log "preflight OK (dry-run); not tagging"; exit 0; }
    git tag -a "$TAG" -m "$TAG"
    git push origin "$TAG"                             # fires release.yml
    log "pushed $TAG — release.yml builds, signs, and publishes a DRAFT for human review"
    ;;
```

## 3. GitHub Actions (`release.yml`) — authoritative build + sign

**Runner trust.** The matrix uses `ubuntu-latest`, `ubuntu-22.04-arm`, `macos-13`, `macos-14`. All must be **GitHub-Actions-hosted** (not self-hosted) so the cosign OIDC issuer is `token.actions.githubusercontent.com` and the certificate identity matches `install.sh`'s `--certificate-identity-regexp`. A self-hosted runner under one of those labels would silently break signature verification for clients.

### 3.1 What the current workflow already does well (keep)
- **Actions pinned by full commit SHA.**
- **`fail-fast: false`** matrix + a separate `release` job that **gathers all `dist-*` artifacts and publishes once** (`needs: build-binary` → a failed leg blocks publish) → no partial multi-platform release.
- **Draft release** → a human reviews SBOM/vulns/signature before it goes public.
- **cosign keyless** signing of each tarball and of `SHA256SUMS`; SBOM (syft); a Trivy CVE scan that gates via `--exit-code 1`. *(Caveat: Trivy is installed unpinned — `releases/latest` on Linux, `brew` on macOS — so the gate runs against a floating scanner version on every leg; delta 6 pins it.)*

### 3.2 Required deltas (this feature)
1. **Add the B1 freshness gate** to the `lint` job: `scripts/check-lockfile.sh` beside `check-fallback-tag.sh`; extend the shellcheck glob to `scripts/tests/*.sh`.
2. **[Blocked on B1]** Once B1 ships the committed `agents/requirements-frozen.txt`, `build-release.sh` copies it into `runtime/agents/` (never generates it). **Until B1 lands this delta is NOT implemented** — the `cp` would fail; the current empty-stub behavior stands and the installer stays CLI-only/fail-closed. Do not land delta 2 before B1.

### 3.3 Required hardening (fixes pre-existing gaps confirmed by review)
3. **Least-privilege permissions.** Currently `id-token|contents|attestations: write` is granted **workflow-wide**, so `lint`/`build-frontend` get write tokens they never use. Set default `permissions: contents: read`; elevate per job: `build-binary` → `id-token: write` (signs each tarball); `release` → `contents: write` + `id-token: write` (publish + sign `SHA256SUMS`). `lint`/`build-frontend` stay read-only. (`upload-artifact` needs no `contents` write — it uses the artifacts API.)
4. **`pip-audit` must gate and target the real lockfile. [depends on B1]** Today it runs `pip-audit -r agents/requirements.txt … || true`: the `|| true` makes it **non-gating**, and **`agents/requirements.txt` does not exist** (confirmed) so it audits nothing. Fix: audit the hashed `requirements-frozen.txt` and **drop `|| true`**. The lockfile is a B1 prerequisite; when it is absent the step is a **hard failure** (never re-add `|| true`). Honor `.pip-audit-ignore` (90-day expiry).
5. **`verify-no-secrets-in-logs` must run and gate.** Today it is `if: env.VULTURE_HOME != ''` (never set at workflow scope → **always skipped**) + `continue-on-error: true`. Fix: pass the smoke-install `VULTURE_HOME` explicitly and remove `continue-on-error`.
6. **Pin + verify Trivy** on every leg (drop `releases/latest` and bare `brew`): a version-pinned + checksum-verified install, or the pinned-SHA `aquasecurity/trivy-action`.
7. **`concurrency`**: `group: release-${{ github.ref }}`, `cancel-in-progress: false` (serialize re-pushes; never abort an in-flight publish).
8. **`timeout-minutes`** on every job (e.g. 20–30) so a hung runner fails fast.
9. **Idempotent publish — without clobbering signatures.** `gh release create` fails if the release exists (re-run after a transient failure). Because the release is a **draft** (not yet trusted) and a re-run produces *different* per-leg cosign certs, do **not** `--clobber` individual signed assets into an existing draft (that mixes artifacts/signatures from two runs and breaks immutability). Instead, on re-run **replace the draft wholesale**:
   ```sh
   if gh release view "$TAG" --json isDraft -q .isDraft 2>/dev/null | grep -qx true; then
       gh release delete "$TAG" --yes --cleanup-tag=false   # draft only; NEVER a published release
   fi
   gh release create "$TAG" --draft --title "$TAG" --notes "…" dist/*
   ```
10. **Clean up a dangling draft on failure.** If the `release` job fails after creating the draft but before all assets upload, add an `if: failure()` step: `gh release delete "${GITHUB_REF_NAME}" --yes --cleanup-tag=false 2>/dev/null || true`. *(The `|| true` here is acceptable — this is best-effort cleanup, not a security gate.)*
11. **Script-injection hygiene.** Keep passing refs via env (`$GITHUB_REF_NAME`) and quoting; never interpolate `${{ github.event.* }}` into `run:`. Matrix values are literals (safe); `on: push: tags: v*` limits exposure.

## 4. Chaos engineering / failure modes

| Failure | Behavior / mitigation |
|---|---|
| One platform leg fails | `release` `needs: build-binary` (all legs) → **no partial publish**; re-run after fix. |
| `release` job fails mid-publish | Idempotent wholesale-replace of the draft on re-run (delta 9) + `if: failure()` draft cleanup (delta 10) → no dangling/partial draft. |
| PyPI / download flake during build | bounded retries on downloads; a `--require-hashes` install failure **fails the build** (never ship a partial runtime). |
| Re-run for an existing tag | `concurrency` (delta 7) serializes; idempotent publish (delta 9). |
| **Tag moved / re-pushed to a different commit** | GitHub **tag protection / immutable `v*` tags** so a published version can't be re-pointed at different bytes; `vulture.sh release` also refuses to re-tag (§2.3, advisory). |
| Vendored PBS asset missing (Tier B) | build verifies SHA against `pbs-shas.txt` → fail fast, no upstream fallback. |
| Bad release after publish | Draft-first review is the primary guard. To yank a *published* bad release: delete the Release + tag and ship a fixed **higher** version — never reuse a version. `install.sh`'s downgrade guard (H2) means clients won't auto-accept an older replacement, so recovery is **roll-forward** to vX.Y.(Z+1). |
| Hosted-runner trust | GitHub-hosted runners only (the matrix is); never self-hosted for signing (§3 runner trust). |
| Reproducibility | `build-release.sh` already tars with `--sort=name --mtime=… --numeric-owner`; `verify-release.sh` re-derives + diffs. |

## 5. GitHub Actions best-practices checklist

- [ ] All actions pinned by full commit SHA. *(current: yes)*
- [ ] `permissions:` default `contents: read`; write elevated **per job**. *(current: no — workflow-wide write)*
- [ ] `id-token: write` only on signing jobs (`build-binary`, `release`). *(current: workflow-wide)*
- [ ] `concurrency` with `cancel-in-progress: false`. *(current: missing)*
- [ ] `timeout-minutes` on every job. *(current: missing)*
- [ ] Third-party CLIs (trivy/syft/cosign) pinned + verified. *(current: trivy floating both legs)*
- [ ] No untrusted `${{ … }}` in `run:`; refs via env + quoted. *(current: ok)*
- [ ] Security gates fail-closed — no `|| true` / dead `if:` on CVE/secret/audit steps. *(current: pip-audit + secrets check are no-ops)*
- [ ] CVE + dependency audit run against the **hashed lockfile**, not a stale/absent file. *(current: targets nonexistent agents/requirements.txt)*
- [ ] Draft release + human publish; cosign keyless; SBOM attached. *(current: yes)*
- [ ] Idempotent re-run that does **not** clobber signed assets. *(current: non-idempotent)*
- [ ] Tag protection / immutable `v*` tags enabled (repo setting).
- [ ] Runner labels confirmed GitHub-Actions-hosted (OIDC identity). *(current: yes, but assert it)*
- [ ] (Phase 2) `actions/attest-build-provenance` for SLSA provenance — **note:** delta 3 removes the workflow-wide `attestations: write`, so the provenance step must add `attestations: write` to the `build-binary` job's per-job permissions.

## 6. Anti-patterns (do NOT)

- `vulture.sh release` (or any local/CI step) **generating** the lockfile and shipping it without a reviewed commit.
- CI running `gen-lockfile.sh` at release and baking the result into the tarball.
- Signing with cosign **locally** (breaks the OIDC identity `install.sh` trusts).
- `|| true` / `continue-on-error: true` / dead `if:` on a *security* gate (CVE, secret-scan, audit). *(Best-effort cleanup steps like delta 10 are not security gates and may use `|| true`.)*
- Workflow-wide `*: write` permissions.
- Floating tool installs (`releases/latest`, bare `brew`) in the builder.
- `--clobber`-ing signed assets into an existing release, or moving/re-pushing an existing tag.

## 7. Open decisions for the reviewer

- **Publish approval.** Gate the `release` job behind a `release` GitHub **Environment** with required reviewers (mirrors `vendor-pbs.yml`)? Adds friction; strengthens dual-control.
- **Tag protection.** Enable immutable/protected `v*` tags (repo setting)?
- **`check-fallback-tag.sh` floor.** Strengthen it to actually enforce *"≥ latest−1"* against the previous published tag (it currently does not), and replace its `sort -V` with the portable awk compare used in `install.sh`.
- **Preflight depth.** How much of the heavy suite runs in `vulture.sh release` (fast subset) vs left authoritative to CI, and which Python env the agent tests assume.
- **Provenance now or later.** Wire `attest-build-provenance` in this feature or keep it the Phase-2 hook (then it needs per-job `attestations: write`).
- **Trivy pinning mechanism.** Pinned-SHA `trivy-action` vs version-pinned + checksum-verified `curl`/`brew`.

## 8. Files touched

- `scripts/vulture.sh` — new `release)` subcommand + `die()`/`log()` helpers.
- `scripts/check-lockfile.sh` — B1 freshness gate (shared by CI `lint` + preflight).
- `scripts/release-version-check.sh` — new helper. Contract: reads `./VERSION` (must equal `<tag>`, including the `v` prefix); reads `FALLBACK_TAG=` from `install.sh` (must be semver ≤ `<tag>`); exits 1 with a diff-style message on any mismatch.
- `.github/workflows/release.yml` — deltas §3.2 (item 1 now; item 2 after B1) + hardening §3.3.
- `scripts/build-release.sh` — copy the committed lockfile (B1; delta 2).
- `scripts/check-fallback-tag.sh` — strengthen the floor + portable version compare (Open decisions).
- docs — this section.

## 9. Sequencing

`make freeze-deps`/B1 (committed lockfile) **must precede** delta 2 + delta 4 (both consume it) and Tier B / Tier B-lite. The `vulture.sh release` preflight, the permission/concurrency/timeout/idempotency/secret-gate hardening (§3.3 except 4), and the runner-trust assertions are **independent of B1** and can land first.
