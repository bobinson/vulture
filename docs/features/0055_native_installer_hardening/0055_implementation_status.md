# 0055 — Native Installer Hardening + Honesty · Implementation Status

**Status**: IMPLEMENTED (Tier A + C + hardening pass); Tier B deferred
**Last updated**: 2026-06-05

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

- Generate a **hashed** `requirements-frozen.txt` from the agents'
  `pyproject.toml`s (`uv pip compile --generate-hashes`).
- Wire `release.yml` to fetch+verify the already-built `vendor-pbs-*`
  PBS asset and compile the lockfile (`build-release.sh` has stubs;
  `install_python_deps` already consumes the result).
- Make `smoke-install.sh` run a real `vulture scan`.

**Build it only when the Trigger in the LLD is met** (real demand for
Docker-less agent scanning). When built, it graduates to its own feature
(suggested `0056_native_agent_runtime`). Until then, Mode E installs the
CLI + embedded SPA; agent-based scanning requires Docker (Mode A/B), and
even with Tier B an external LLM endpoint is still required.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-06-05 | `install_python_deps` fails closed on a hashless non-empty frozen file rather than silently installing without `--require-hashes` | a supply-chain-sensitive installer must not weaken hash enforcement silently |
| 2026-06-05 | CLI-only build is a valid, successful install (no pip) — not an error | the Go CLI + skills are usable without the Python agent runtime; only LLM/agent scanning needs Docker today |
| 2026-06-05 | Tier B deferred, not blocking v0.1.0 | bundling a Python runtime + a dependency lockfile is real work; honesty (Tier C) unblocks launch now |
