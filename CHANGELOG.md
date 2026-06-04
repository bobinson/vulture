# Changelog

All notable changes to Vulture will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
