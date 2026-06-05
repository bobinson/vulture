# 0055 — Native Installer Hardening + Honesty (LLD + plan)

**Author**: tbd
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

### B1 — real hashed lockfile from the agents' `pyproject.toml`s

The agents are 11 editable packages (`shared`, `asvs`,
`chaos_engineering`, `cwe`, `discover`, `do178c`, `owasp`, `prove`,
`soc2`, `ssdf`, `xss`) installed in CI via `pip install -e`. Tier B
compiles their resolved transitive closure into one
`requirements-frozen.txt` **with hashes**:

- Use `uv pip compile` (fast, deterministic) or `pip-compile
  --generate-hashes` over the union of the pyprojects' dependencies
  (`uv pip compile pyproject1 pyproject2 … --generate-hashes -o
  requirements-frozen.txt`), pinning to the bundled Python's minor
  version (3.12).
- **Platform-specific wheels** (e.g. `pydantic-core`, any native
  extension): list **all** target-platform wheel hashes per package so a
  single lockfile validates on all four platforms, OR emit per-platform
  lockfiles (`requirements-frozen-${OS}-${ARCH}.txt`) if cross-platform
  resolution diverges. Decision at build time: start with one
  all-platform lockfile; split only if `uv pip compile --universal`
  can't satisfy a package.
- The lockfile is committed (or generated in CI and attached as a build
  artifact) so reproducible-build verification (`verify-release.sh`) can
  re-derive it. `install_python_deps` already **fails closed** if the
  shipped lockfile lacks `--hash=` lines, so a regression here can't
  silently weaken to a hashless install.

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
