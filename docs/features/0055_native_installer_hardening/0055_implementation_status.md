# 0055 — Native Installer Hardening + Honesty · Implementation Status

**Status**: IMPLEMENTED (Tier A + C); Tier B deferred
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
| T  | `sh -n` + branch tests for verify_signature/install_python_deps | ✅ 5/5 (`scripts/tests/test_install_sh.sh`); shellcheck unavailable in env, `sh -n` clean |

## Deferred (Tier B — separate follow-up feature)

- Bundle python-build-standalone (vendor-pbs release + release.yml fetch).
- Generate a hashed `requirements-frozen.txt` lockfile from agent deps.
- Make `smoke-install.sh` run a real `vulture scan`.

Until Tier B lands, Mode E installs the CLI + embedded SPA; agent-based
scanning requires Docker (Mode A/B).

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-06-05 | `install_python_deps` fails closed on a hashless non-empty frozen file rather than silently installing without `--require-hashes` | a supply-chain-sensitive installer must not weaken hash enforcement silently |
| 2026-06-05 | CLI-only build is a valid, successful install (no pip) — not an error | the Go CLI + skills are usable without the Python agent runtime; only LLM/agent scanning needs Docker today |
| 2026-06-05 | Tier B deferred, not blocking v0.1.0 | bundling a Python runtime + a dependency lockfile is real work; honesty (Tier C) unblocks launch now |
