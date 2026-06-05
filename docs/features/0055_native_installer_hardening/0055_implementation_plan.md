# 0055 — Native Installer Hardening + Honesty (LLD + plan)

**Author**: tbd
**Status**: PLAN
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

- `install.sh` — A1, A2, A3, A4
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
- Confirm `.filelist` is absent after a simulated extract on Linux.
- `validate_home` rejects each newly-blacklisted dir.
- Docs: grep that README/guide no longer claim "bundled Python" as a
  shipped fact and that the Docker-for-agents caveat is present.

## Rollback

Pure script + docs change, no state. `git revert <0055 sha>` restores
the prior `install.sh` and docs. No release artifacts or DB affected.
See `0055_rollback_plan.md`.
