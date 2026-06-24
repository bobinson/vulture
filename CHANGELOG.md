# Changelog

All notable changes to Vulture will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Security fixes** are recorded under a `### Security` heading naming the advisory
identifier (CVE / GHSA / PYSEC), the affected versions, and the remediation, and
are surfaced in the corresponding GitHub release notes — so every release that
fixes a vulnerability discloses it (OpenSSF Best Practices passing criterion).

## [Unreleased]

### Known limitations

- **Finding triage labels (thumbs FP/TP) are not yet functional.** The
  `audit_memories` table lacks the `fingerprint` column the label
  endpoint and the L4 memory-prior validation layer query, so labelling
  a finding logs a non-fatal error and the L4 layer is skipped. Audits,
  scanning, and all other validation layers are unaffected. Tracked for
  a follow-up release.

### Added

- **Feature 0044 — Native installer (Mode E):** `curl … install.sh | sh`
  produces a Docker-less single-user install under `~/.vulture/`. Ships
  a bundled python-build-standalone, SQLite-backed daemon, and the SPA
  served as embedded assets straight from the Go binary. Includes new
  `vulture {start, stop, status, logs, doctor, uninstall}` subcommands,
  cosign-signed release tarballs with SBOM + Trivy CVE gate, and a
  19-item security-invariant spec. See
  [docs/features/0044_native_installer](docs/features/0044_native_installer/).
- **Repo-hygiene & security primitives:** CODEOWNERS enforcement on
  security-critical paths; `.trivyignore` / `.pip-audit-ignore`
  90-day-expiry allowlist; install.sh re-validates `VULTURE_HOME` before
  extract (TOCTOU mitigation); subprocess env scrubber drops
  `LD_PRELOAD` / `PYTHONPATH` / `DYLD_INSERT_LIBRARIES` from agent env;
  field-name allow-list logger redactor; append-only audit log for
  security events; LLM endpoint URL validator rejects cleartext non-loopback.
- **CWE detector simplifications:** PATH_TRAVERSAL_PATTERNS collapsed
  from 9 regexes to 2 (hot-path win); 104 dual-contract lock-in tests
  added to guard against false-negative blunders.

### Changed

- **Removed a hardcoded admin backdoor password** that shipped in early
  commits (rejected by hash at startup; the literal was purged from git
  history in the 0036 Phase 4 release scrub). The seeded local
  dev user (`admin@vulture.local`) now uses
  `$VULTURE_LOCAL_DEV_PASSWORD` if set, or a CSPRNG-generated 16-byte
  hex password logged once at backend startup. The `/api/auth/local-session`
  endpoint uses a new password-less `IssueLocalAdminToken` helper.
- Unified all repo-URL references to `github.com/bobinson/vulture`.
- **Native install (Mode E) now auto-detects a system Python for agents.**
  `VULTURE_USE_SYSTEM_PYTHON` became a tri-state: **unset = AUTO** (the new
  default — when a hashed agent lockfile ships and a host Python ≥ 3.12 is
  present, the installer provisions the agent venv automatically so agents +
  skills run via `vulture start` out of the box); `1` = REQUIRE (loud-fail if
  either is absent); `0` = DISABLE (force CLI-only). `--require-hashes`
  dependency verification and the `>=3.12` gate stay enforced on every install
  path; a hashless lockfile under AUTO warns and degrades to CLI-only rather
  than aborting. See
  [docs/features/0055_native_installer_hardening](docs/features/0055_native_installer_hardening/).
- **Honest install messaging.** Rewrote the CLI-only note (removed the false
  "CLI + skills still work" — skills run inside the agents): it now states that
  agent/LLM scanning needs a local Python ≥ 3.12 or Docker, while the CLI and
  web UI are installed and work. The post-install summary and quickstart adapt
  to whether agents were actually installed.

### Fixed

- **Install-mode UI/URL reporting.** Added a `localdev.UIPort` helper so the
  CLI reports the correct UI address — in install mode the backend serves both
  the API and the embedded SPA on one port (the phantom `23000` is gone).
  `vulture start`, `vulture scan` ("View results"), `vulture status`, and the
  launcher banner now print the backend port as the UI, with no bogus separate
  "frontend" row/line in install mode and an Agents line only when agents are
  actually started.
- **`vulture scan` agent-health guard.** Before relying on results, `scan` now
  probes each configured agent `/health`; if none are reachable it prints a
  loud, actionable warning (the scan will produce no findings — install Python
  3.12+ and reinstall, or use Docker) and continues, so submissions to a
  remote/centralized server still work.
- **`vulture doctor`.** In install mode a missing bundled-Python path is now a
  WARN (exit 2), not a hard FAIL — a CLI-only install is a documented-valid
  state; the fix hint points to installing Python 3.12+ or using Docker.

### Planned

- Mode-B (centralized server) hardening pass — see
  [docs/features/0036_public_release_hardening](docs/features/0036_public_release_hardening/)
  Phase 3 (or follow-up feature 0037).
- Frontend agent auto-discovery: replace hardcoded UI lists in
  `frontend/src/components/results/FindingsTable.tsx` with config
  derived from `GET /api/agents`.
- Continuous-integration gates: `actionlint`, `govulncheck`,
  `pip-audit`, `npm audit`.
- SBOM publication as a GitHub release artifact (gating released in
  feature 0044's `release.yml`; pending first tag-push to validate).

## [0.1.0] - 2026-06-05

> Date and tag pinned at release time. See feature 0036 Phase 4.

### Added

- Initial public release.
- Go backend (orchestrator, JWT/API-key auth, PostgreSQL/SQLite
  persistence, Server-Sent Events streaming).
- Ten Python audit agents:
  - `chaos_engineering` — retry, circuit-breaker, timeout, fallback,
    blast-radius patterns.
  - `owasp` — OWASP Top 10 (injection, auth, crypto, misconfig,
    access control, etc.).
  - `soc2` — SOC 2 CC6/CC7/CC8 clauses, configurable per-clause.
  - `cwe` — full CWE 4.19.1 catalog (1,400+ weakness types) with
    taxonomic rollup and `path_equivalence` skill.
  - `prove` — formal provenance/finding verification.
  - `xss` — cross-site scripting scanner.
  - `ssdf` — NIST SP 800-218 SSDF v1.1 practice groups.
  - `discover` — endpoint discovery and attack-surface mapping.
  - `do178c` — DO-178C avionics safety checks.
  - `asvs` — OWASP ASVS v5.0.0 (345 requirements across 17 chapters
    and 3 verification levels).
- React SPA frontend (Vite + Tailwind v4) with native EventSource
  SSE streaming and i18n support for `en`, `es`, `de`, `fr`, `ja`,
  `pt`.
- CLI binary (`vulture scan / login / list / watch`) for headless
  audit execution.
- Memory system with cross-audit intelligence via pgvector
  embeddings (OpenAI `text-embedding-3-small` or Ollama
  `nomic-embed-text`).
- Four documented deployment modes:
  - Mode A — developer laptop (`make docker-up`).
  - Mode B — centralized server.
  - Mode C — read-only viewer.
  - Mode D — CI client.
- Two-phase audit pipeline: deterministic skill-based pattern
  matching across the entire codebase, followed by optional
  LLM-driven deep analysis with automatic deduplication against
  prior findings.
- Configurable LLM provider via LiteLLM (OpenAI, Anthropic, Gemini,
  local models via Ollama / LM Studio / vLLM).

### Documented

- Apache-2.0 license throughout (repository, all 10 agent
  pyproject.toml manifests, frontend package.json).
- `NOTICE`, `THIRD_PARTY_LICENSES.md`, and per-data-directory
  `LICENSE.md` files for redistributed third-party content
  (MITRE CWE, OWASP ASVS, NIST SSDF).
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, PR
  template, bug-report and feature-request issue templates,
  security-advisory contact link.

[Unreleased]: https://github.com/bobinson/vulture/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bobinson/vulture/releases/tag/v0.1.0
