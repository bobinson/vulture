# 0036 — Public Open-Source Release Hardening

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Follow CLAUDE.md §Development Workflow (MANDATORY) — E2E tests first, one change at a time. **Phases 1–2 are safe and reversible. Phase 3 (Mode-B hardening) is optional for v0.1. Phase 4 rewrites git history and is one-way — execute only after explicit user confirmation and a verified backup tag.**

## Goal

Bring the Vulture repository to "credible v0.1 OSS release" quality: scrub history of secrets and binaries, attribute redistributed third-party data correctly, fix license-metadata inconsistencies, sync drifted documentation to current code, remove personal/internal references, and tag a `v0.1.0` release pushed to a fresh public remote.

A separate, optional **Phase 3** hardens the centralized-server (Mode B) deployment path against the eight code-security findings surfaced by the audit. Phase 3 may be deferred to a v0.2 feature; if deferred, the v0.1 README must declare "Mode A only" and call out Mode B as not-yet-hardened.

## Background — what triggered this feature

A six-dimension audit (secrets, PII, license, docs, hygiene, code-security) ran on `feat/0031-central-server` at commit `b8ce4b3` on 2026-04-25 and surfaced:

- **2 historical secrets** in commits `5f7d28e` and `f293057` (`REDACTED-PG-PW` postgres password, `REDACTED-JWT-DEFAULT` JWT default).
- **~93 MB** of tracked binaries + vendored MITRE/OWASP data inflating clones.
- **2 third-party-data attribution gaps** (MITRE CWE Terms of Use, OWASP ASVS CC BY-SA 4.0).
- **1 internal-customer reference** ("FutureID" in `CLAUDE.md:167`) plus 3 internal-incident anecdotes.
- **8 code-security defaults** that make Mode B unsafe on first `docker compose up`.
- **Documentation drift**: README enumerates 6 audit frameworks when the codebase ships 10; one wrong API path (`/api/audits/cached` vs real `/api/audits/cache`); inconsistent repo slug (`vulture-project/vulture` vs `vulture/vulture`).
- **License metadata mismatch**: `mcp/pyproject.toml` declares MIT while repo LICENSE is Apache-2.0.

What is **already clean**: LICENSE file present and consistent (Apache-2.0); all dependencies are permissive (no GPL/AGPL/SSPL); committer identity already sanitized to `b@example.com / B`; `.env`/`config.ini`/`.claude/mcp.json` confirmed never-committed; current HEAD's JWT secret correctly fail-closes when env unset; SECURITY.md/CONTRIBUTING.md/CODE_OF_CONDUCT.md/PR template/issue templates all present.

## Architecture

```
                                Phase 1 (safe, reversible)
                                ──────────────────────────
                          ┌─ License attribution
                          ├─ License-metadata reconciliation
                          ├─ Documentation drift fixes
                          ├─ Missing standard files
                          └─ Personal/internal scrub
                                       │
                                       ▼
                                Phase 2 (safe, reversible)
                                ──────────────────────────
                          ┌─ Untrack binaries + bloat
                          └─ Tighten .gitignore
                                       │
                                       ▼
                          Phase 3 — OPTIONAL (defer to v0.2 if time-pressed)
                          ────────────────────────────────────────────────
                          ┌─ E2E security tests (write first, must fail)
                          ├─ Local-mode binding gate
                          ├─ Wildcard-CORS fix
                          ├─ Webhook SSRF guard
                          ├─ Filesystem-browse confinement
                          ├─ Agent-token mandatory in non-local mode
                          ├─ JWT min-length validation
                          ├─ Pin GitHub Actions to SHAs
                          └─ All security tests pass
                                       │
                                       ▼
                                Phase 4 (DESTRUCTIVE, one-way)
                                ──────────────────────────────
                          ┌─ Backup tag + bare-clone
                          ├─ git filter-repo (paths + replace-text)
                          ├─ git gc --aggressive --prune=now
                          ├─ Verify clean state
                          ├─ Tag v0.1.0
                          └─ Push to fresh public remote (not existing)
```

## Tech Stack

- `git filter-repo` (https://github.com/newren/git-filter-repo) — required for Phase 4. Install via package manager (`apt install git-filter-repo`) or `pip install git-filter-repo`.
- Existing Go test harness (`go test ./...`) for Phase 3 backend security tests.
- Existing Python test harness (`pytest`) for any agent-side hardening tests.
- Existing `pre-commit`/`golangci-lint`/`ruff` config for style enforcement.
- No new runtime dependencies.

## Baseline (measured 2026-04-25)

| Metric | Current | Target post-feature |
|---|---:|---:|
| Tracked file count | 755 | ~745 (drop binaries + duplicate MITRE XML + .claude/settings.json + story.md) |
| Tracked content size | **90.18 MB** | **< 2 MB** |
| `.git` directory size | **113 MB** (1,682 loose objects, 0 packs) | **< 10 MB** |
| Largest tracked blob | `cwe_latest.pdf` 37.6 MB | `agents/cwe/cwe_agent/data/cwe_catalog.json` ~2.2 MB (preserved — generated derivative the agent consumes at startup). Upstream PDF/XML/XSD replaced by `*.md` pointer files. |
| Tracked ELF binaries | `backend/vulture` 17 MB | 0 |
| Total commits all branches | 23 | 23 (rewritten: same count, new SHAs) |
| Historical secrets | 2 (`REDACTED-PG-PW`, JWT default) in 2 commits | 0 (scrubbed via `--replace-text`) |
| Third-party data attribution | None | NOTICE + THIRD_PARTY_LICENSES.md + per-data LICENSE.md + README §Attributions |
| `pyproject.toml` files declaring license | 1 of 11 (and that one wrong: `mcp/` says MIT) | 11 of 11 declaring `Apache-2.0` |
| `frontend/package.json` license/repo/author | Missing all three | All present |
| README agents enumerated | 6 | 10 (chaos, owasp, soc2, cwe, prove, xss, ssdf, discover, do178c, asvs) |
| API path drift | `/api/audits/cached` documented, `/api/audits/cache` actual | Both match (use actual) |
| Repo-slug consistency | `vulture-project/vulture` (README) vs `vulture/vulture` (issue config.yml:4) | Single canonical slug everywhere |
| `CHANGELOG.md` | Absent | Present, Keep-a-Changelog format, seeded with v0.1.0 |
| Versioning scheme | None | Semver. `v0.1.0` git tag |
| Mode B default `docker compose up` safe? | No (admin seed + wildcard CORS + SSRF + filesystem browse) | Yes (Phase 3) — or README declares "Mode A only" if Phase 3 deferred |

## Audit cross-reference — finding ID → task

Every finding from the 2026-04-25 audit maps to a task below. Use this table during implementation to ensure no finding is dropped.

| Finding | Severity | Task |
|---|---|---|
| Historical secret `REDACTED-PG-PW` in `5f7d28e`, `f293057` | CRITICAL | T17 (filter-repo `--replace-text`) |
| Historical secret `REDACTED-JWT-DEFAULT` | CRITICAL | T17 (filter-repo `--replace-text`) |
| `backend/vulture` 17 MB ELF tracked | CRITICAL | T6 (untrack), T17 (filter-repo `--invert-paths`) |
| `cli/vulture` 8.97 MB in history | CRITICAL | T17 (filter-repo `--invert-paths`) |
| `docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf` 37 MB | CRITICAL | T6, T17 |
| `cwec_v4.19.1.xml` 16 MB ×2 (duplicate at `docs/features/0010_cwe_audit/`) | CRITICAL | T6, T17 |
| `frontend/playwright-report/index.html` 557 KB | CRITICAL | T6, T17 |
| `.claude/settings.json` (empty, tracked despite gitignore) | CRITICAL | T6, T17 |
| MITRE CWE redistributed without attribution | CRITICAL | T1 (NOTICE + THIRD_PARTY_LICENSES + README §Attributions) |
| OWASP ASVS redistributed without CC BY-SA attribution | CRITICAL | T1 |
| `mcp/pyproject.toml:11` declares MIT vs repo Apache-2.0 | MEDIUM | T2 |
| 10 `pyproject.toml` files missing `license` field | MEDIUM | T2 |
| `frontend/package.json` missing `license`/`repository`/`author` | MEDIUM | T2 |
| "FutureID" reference at `CLAUDE.md:167` | HIGH | T5 |
| Three "Prior incidents:" paragraphs in CLAUDE.md (152-157, 161-167, 184-188) | HIGH | T5 |
| `story.md` (typo-laden brief) tracked at repo root | HIGH | T5 |
| `agents/owasp/PLAN.md` leftover internal planning | MEDIUM | T5 |
| `/home/user/src/vulture/...` absolute paths in `docs/features/0033/0034/0035` | MEDIUM | T5 |
| `agents/prove/CLAUDE.md` tracked (AI-tool-specific) | LOW | T5 |
| README enumerates 6 frameworks; codebase ships 10 | HIGH | T3 |
| API table says `/api/audits/cached`; actual `/api/audits/cache` | HIGH | T3 |
| Repo-slug inconsistency `vulture-project/vulture` vs `vulture/vulture` | MEDIUM | T3 |
| README env-var table missing `VULTURE_AGENT_DO178C_URL`, `VULTURE_AGENT_ASVS_URL` | HIGH | T3 |
| `Makefile build-agents` omits do178c, asvs | HIGH | T3 |
| README "frontend auto-discovers agents" claim contradicted by hardcoded UI lists | MEDIUM | T3 |
| CLAUDE.md self-contradicts: complexity "< 5" vs "10 paths" | MEDIUM | T3 |
| Bug-report issue template missing 6 of 10 agents | LOW | T3 |
| Missing `CHANGELOG.md` | HIGH | T4 |
| No semver / no `VERSION` file / no release tag | HIGH | T4, T20 |
| Missing security-report issue template | HIGH | T4 |
| Missing CODEOWNERS, AUTHORS | MEDIUM | T4 |
| `security@vulture.dev`, `conduct@vulture.dev` — domain ownership unverified | HIGH | T16 (verify) |
| C1: `REDACTED-DEV-PW` admin seed always-on | CRITICAL (Mode B) | T7 (test) + T8 (fix) |
| C2: SQLite vs Postgres role default mismatch | CRITICAL (Mode B) | T9 (test) + T10 (fix) |
| C3: Wildcard CORS | CRITICAL (Mode B) | T7 (test) + T8 (fix) |
| H1: Webhook SSRF | HIGH (Mode B) | T11 (test) + T12 (fix) |
| H2/H3: Filesystem browse exposes host | HIGH (Mode B) | T13 (test) + T14 (fix) |
| H7: Substring-match auto-login (paired with C1) | HIGH (Mode B) | T7 (test) + T8 (fix) |
| H8: Agent-to-agent token optional | HIGH (Mode B) | T11 (test) + T12 (fix) |
| H9: Local mode silent fall-through on non-loopback | HIGH (Mode B) | T7 (test) + T8 (fix) |
| H10: GitHub Actions pinned by tag, not SHA | HIGH (Mode B) | T15 (pin SHAs) |
| M9: JWT secret min-length not enforced | MEDIUM (Mode B) | T15 |
| M14: SQLite `api_keys` table not in versioned migration | MEDIUM | T15 |
| M15: git token via URL leaks via `/proc/<pid>/cmdline` | MEDIUM (Mode B) | T15 |
| L1–L12: deprecated headers, missing CSP, etc. | LOW | T15 |
| `backend-bin` (untracked stale 17 MB) | LOW | T6 (`rm` from working tree) |
| `.gitignore` missing `.aider*`, `.cursor/`, `*.tsbuildinfo`, etc. | LOW | T6 |

---

# Phase 1 — Documentation, attribution, metadata (safe, reversible)

These tasks change only files; no behavior changes; reversible by `git revert`. Order is independent — execute serially for clean diffs.

## Task 1: Third-party data attribution

**Why:** MITRE CWE Terms of Use require visible copyright/attribution; OWASP ASVS CC BY-SA 4.0 requires attribution + license link + change indication + same-license redistribution of derivatives. Both currently violated.

**Files:**
- Create: `/home/user/src/vulture/NOTICE`
- Create: `/home/user/src/vulture/THIRD_PARTY_LICENSES.md`
- Create: `/home/user/src/vulture/agents/cwe/cwe_agent/data/LICENSE.md`
- Create: `/home/user/src/vulture/agents/asvs/asvs_agent/data/LICENSE.md`
- Modify: `/home/user/src/vulture/README.md` — add `## Attributions` section before `## License`

- [ ] **Step 1: Create top-level `NOTICE` file**

```
Vulture
Copyright 2026 Vulture maintainers

This product includes software developed by Vulture contributors,
licensed under the Apache License, Version 2.0 (see LICENSE).

This product redistributes the following third-party content:

  - MITRE CWE™ (Common Weakness Enumeration)
    Copyright (c) 2006-2025, The MITRE Corporation. All rights reserved.
    Source: https://cwe.mitre.org/
    Terms of Use: https://cwe.mitre.org/about/termsofuse.html
    Distributed in: agents/cwe/cwe_agent/data/cwe_catalog.json

  - OWASP Application Security Verification Standard (ASVS) v5.0.0
    Copyright (c) The OWASP Foundation, contributors.
    Licensed under Creative Commons Attribution-ShareAlike 4.0
    International (CC BY-SA 4.0).
    License: https://creativecommons.org/licenses/by-sa/4.0/
    Source: https://github.com/OWASP/ASVS
    Distributed in: agents/asvs/asvs_agent/data/asvs_*.json
    Modifications: transformed to lookup JSON; CWE crosswalk and
    detectability classification added (see THIRD_PARTY_LICENSES.md).

  - NIST SP 800-218 Secure Software Development Framework (SSDF)
    Public domain (NIST publication).
    Source: https://csrc.nist.gov/Projects/ssdf
    Distributed in: agents/ssdf/ssdf_agent/practice_groups/
```

- [ ] **Step 2: Create `THIRD_PARTY_LICENSES.md`**

Document, for each redistributed body of work: (a) source URL, (b) upstream version, (c) upstream license + link, (d) summary of modifications, (e) where it lives in this repo. Sections: MITRE CWE, OWASP ASVS, NIST SSDF, and a "Runtime dependencies" pointer (`go.mod`/`pyproject.toml`/`package.json`).

- [ ] **Step 3: Create `agents/cwe/cwe_agent/data/LICENSE.md`**

Per-directory license marker for the CWE-derived JSON. State: original source MITRE CWE 4.19.1; license MITRE TOU; modifications: extracted to lookup JSON (line-for-line attribution preserved in field names); pointer to top-level NOTICE.

- [ ] **Step 4: Create `agents/asvs/asvs_agent/data/LICENSE.md`**

Per-directory license marker for the ASVS-derived JSON. **CRITICAL:** state CC BY-SA 4.0 explicitly and that the data files in this directory inherit CC BY-SA 4.0 (the rest of the repo is Apache-2.0; the ASVS-derived data files are dual-source: derivatives of CC BY-SA 4.0 content). List the four files and the modifications.

- [ ] **Step 5: Add `## Attributions` section to README**

```markdown
## Attributions

Vulture redistributes the following third-party content. Full
notices are in [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

- **MITRE CWE™** — Copyright © MITRE Corporation, distributed under
  the [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
- **OWASP ASVS v5.0.0** — Copyright © OWASP Foundation, distributed
  under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
- **NIST SSDF (SP 800-218)** — public domain.
```

Insert before the existing `## License` section.

- [ ] **Step 6: Verify**

Run: `grep -E '^(Vulture|MITRE|OWASP|NIST)' NOTICE && grep -c 'CC BY-SA' THIRD_PARTY_LICENSES.md`
Expected: both files present with expected anchors.

- [ ] **Step 7: Commit**

```bash
git add NOTICE THIRD_PARTY_LICENSES.md \
  agents/cwe/cwe_agent/data/LICENSE.md \
  agents/asvs/asvs_agent/data/LICENSE.md \
  README.md
git commit -m "docs(license): add NOTICE + per-source attribution for MITRE CWE and OWASP ASVS

Resolves MITRE TOU and CC BY-SA 4.0 attribution obligations
surfaced by the 2026-04-25 release-readiness audit (feature 0036)."
```

---

## Task 2: License-metadata reconciliation

**Why:** `mcp/pyproject.toml` declares MIT while the repo LICENSE is Apache-2.0. Ten other `pyproject.toml` files declare no license at all. `frontend/package.json` is missing `license`, `repository`, and `author`. License scanners flag this as multi-licensed/inconsistent.

**Files (modify, exact paths):**
- `/home/user/src/vulture/mcp/pyproject.toml` (line 11: `license = "MIT"` → `license = "Apache-2.0"`)
- `/home/user/src/vulture/agents/shared/pyproject.toml`
- `/home/user/src/vulture/agents/owasp/pyproject.toml`
- `/home/user/src/vulture/agents/chaos_engineering/pyproject.toml`
- `/home/user/src/vulture/agents/soc2/pyproject.toml`
- `/home/user/src/vulture/agents/cwe/pyproject.toml`
- `/home/user/src/vulture/agents/prove/pyproject.toml`
- `/home/user/src/vulture/agents/xss/pyproject.toml`
- `/home/user/src/vulture/agents/ssdf/pyproject.toml`
- `/home/user/src/vulture/agents/discover/pyproject.toml`
- `/home/user/src/vulture/agents/do178c/pyproject.toml`
- `/home/user/src/vulture/agents/asvs/pyproject.toml`
- `/home/user/src/vulture/frontend/package.json`

- [ ] **Step 1: Fix `mcp/pyproject.toml` MIT→Apache-2.0**

Edit line 11: `license = "MIT"` → `license = "Apache-2.0"`

- [ ] **Step 2: Add `license = "Apache-2.0"` field to all 11 agent `pyproject.toml` files**

Under `[project]` section, after `version`, add:
```toml
license = "Apache-2.0"
```

PEP 639 form is preferred (`license = "Apache-2.0"` as an SPDX expression). If the existing pyproject.toml uses the older table form (`license = { file = "LICENSE" }`), keep style consistent within the file.

- [ ] **Step 3: Update `frontend/package.json`**

Add three top-level fields next to `"private": true`:
```json
"license": "Apache-2.0",
"repository": {
  "type": "git",
  "url": "https://github.com/<canonical-org>/vulture.git",
  "directory": "frontend"
},
"author": "Vulture maintainers"
```
Use the canonical org slug decided in Task 3 Step 1.

- [ ] **Step 4: Verify**

```bash
grep -l '^license' /home/user/src/vulture/agents/*/pyproject.toml \
  /home/user/src/vulture/mcp/pyproject.toml | wc -l
```
Expected: `12` (11 agents + mcp).

```bash
python -c 'import json; d=json.load(open("/home/user/src/vulture/frontend/package.json")); \
  assert d["license"]=="Apache-2.0"; print("ok")'
```
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add mcp/pyproject.toml agents/*/pyproject.toml frontend/package.json
git commit -m "chore(license): declare Apache-2.0 in all package manifests

Reconciles mcp/pyproject.toml (was MIT) and adds license field to
10 agent pyproject.toml files and frontend/package.json. Closes
metadata mismatch flagged in 2026-04-25 audit."
```

---

## Task 3: Documentation drift sync

**Why:** README enumerates 6 audit frameworks but codebase ships 10. API table has wrong path. Repo slug inconsistent. CLAUDE.md self-contradicts on complexity threshold.

**Files (modify):**
- `/home/user/src/vulture/README.md`
- `/home/user/src/vulture/CLAUDE.md`
- `/home/user/src/vulture/.github/ISSUE_TEMPLATE/config.yml`
- `/home/user/src/vulture/.github/ISSUE_TEMPLATE/bug_report.md`
- `/home/user/src/vulture/Makefile`

- [ ] **Step 1: Decide canonical repo slug**

User-decision required. Options:
  - `vulture-project/vulture` (matches README badge)
  - `vulture/vulture` (matches issue config.yml)
  - other (e.g., `<maintainer-handle>/vulture`)

Pin the answer here:

> **Canonical slug:** `___________________` (fill in before proceeding)

Update everywhere it appears:
```bash
grep -rn "vulture-project/vulture\|vulture/vulture\|github.com/.*\?/vulture" \
  README.md CLAUDE.md .github/ docs/ Makefile 2>/dev/null | grep -v node_modules
```
Replace each hit with the canonical slug.

- [ ] **Step 2: Sync README §Features and architecture diagram to 10 agents**

Current README (lines 11-21) lists 6 frameworks. Replace with the actual list of agents shipped (verify against `backend/pkg/agentregistry/registry.go::AllAgents`):

  1. Chaos Engineering
  2. OWASP Top 10
  3. SOC 2 (CC6/CC7/CC8)
  4. CWE (full v4.19.1 catalog)
  5. NIST SSDF (SP 800-218)
  6. Cross-Site Scripting (XSS)
  7. Provenance / Supply-chain (Prove)
  8. Discoverability (Discover)
  9. DO-178C (avionics)
  10. OWASP ASVS v5.0.0

Update the ASCII architecture diagram (README:~line 22-40) to reflect 10 agents, OR collapse to "10 framework-specific agents" with a footnote.

- [ ] **Step 3: Fix README §Environment Variables agent URL table**

Add `VULTURE_AGENT_DO178C_URL` and `VULTURE_AGENT_ASVS_URL` (the env keys are auto-generated by `agentregistry.EnvURLKey()` and verifiable against `docker-compose.yml:73-74`).

- [ ] **Step 4: Fix API path drift**

In README §Key APIs and CLAUDE.md §Key APIs:
- `/api/audits/cached` → `/api/audits/cache` (verify against `backend/internal/server/server.go:190,267`)
- Add the missing rows for `/api/api-keys`, `/api/lineage`, `/api/memories`, `/api/webhooks` (audit `server.go` for the canonical list).

- [ ] **Step 5: Add §Deployment Modes section to README**

Reuse the table from CLAUDE.md §Deployment Modes (Mode A/B/C/D) verbatim and link to:
- `docs/guides/central_server_deployment.md`
- `docs/guides/neon_deployment.md`
- `docs/guides/ci_integration.md`

If Phase 3 is being deferred to v0.2, add an inline note in the Mode B row: *"⚠️ Mode B is not hardened in v0.1.0 — see [feature 0036 Phase 3](docs/features/0036_public_release_hardening/0036_implementation_plan.md#phase-3) for the planned hardening."*

- [ ] **Step 6: Fix CLAUDE.md complexity contradiction**

Lines 197 and 204 disagree (`< 5` heading vs `< 10` body). Pick `< 10` (matches `Makefile complexity` target and existing `gocyclo` config) and remove the `< 5` claim.

- [ ] **Step 7: Update bug-report issue template agent dropdown**

`/home/user/src/vulture/.github/ISSUE_TEMPLATE/bug_report.md` lines 30-39 list 4 agents; expand to all 10.

- [ ] **Step 8: Fix `Makefile build-agents` to install all 11 packages**

Current target installs: `shared, chaos_engineering, owasp, soc2, cwe, prove, xss, ssdf, discover` (9 packages). Add: `do178c`, `asvs`. Verify by running `make build-agents` after the edit and confirming no `pip install -e` errors.

- [ ] **Step 9: Resolve "frontend auto-discovers agents" misleading claim**

README line 219 says "frontend auto-discovers via `GET /api/agents` — no frontend changes needed". Recent commit `4ca605c` adds hardcoded UI lists for do178c + asvs in `frontend/src/components/results/FindingsTable.tsx` and `frontend/src/pages/Dashboard.tsx`. Either (a) make the discovery claim accurate (preferred — remove hardcoded lists, derive from `GET /api/agents`), or (b) update README to reflect "frontend auto-discovers via `GET /api/agents` for runtime catalog; UI labels and styling are configured per-agent in `frontend/src/components/results/FindingsTable.tsx`." Pick (b) for v0.1; track (a) as a follow-up.

- [ ] **Step 10: Verify each documented claim with a grep**

```bash
# Agent count claims
grep -c -E '^[0-9]+\.' README.md  # in §Features section after edit
# API path
grep -n '/api/audits/cache' backend/internal/server/server.go README.md CLAUDE.md
# Slug
grep -rn 'github.com/.*\?/vulture' README.md CLAUDE.md .github/ | sort -u
# Build-agents target
grep -A 20 '^build-agents:' Makefile
```
Each command should produce the expected hits.

- [ ] **Step 11: Commit**

```bash
git add README.md CLAUDE.md .github/ISSUE_TEMPLATE/config.yml \
  .github/ISSUE_TEMPLATE/bug_report.md Makefile
git commit -m "docs: sync README and CLAUDE.md with 10-agent codebase

- Enumerate all 10 audit agents (was 6)
- Fix API path /api/audits/cached -> /api/audits/cache
- Pin canonical repo slug across README, issue templates
- Add deployment-modes section linking guides
- Resolve complexity-threshold contradiction in CLAUDE.md (< 10)
- Add do178c, asvs to Makefile build-agents target

Closes documentation-drift findings from 2026-04-25 audit."
```

---

## Task 4: Missing standard files

**Why:** OSS users expect a CHANGELOG, a versioning scheme, and a security-issue template that redirects to SECURITY.md. None present today.

**Files (create):**
- `/home/user/src/vulture/CHANGELOG.md`
- `/home/user/src/vulture/.github/ISSUE_TEMPLATE/security_report.md` (or update `config.yml` `contact_links`)
- `/home/user/src/vulture/AUTHORS.md` (optional but recommended)
- `/home/user/src/vulture/.github/CODEOWNERS` (optional)

- [ ] **Step 1: Create `CHANGELOG.md` in Keep-a-Changelog format**

```markdown
# Changelog

All notable changes to Vulture will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - <YYYY-MM-DD: fill in at release tag time>

### Added
- Initial public release.
- Go backend (orchestrator, JWT/API-key auth, PostgreSQL/SQLite persistence).
- 10 Python audit agents: chaos_engineering, owasp, soc2, cwe, prove, xss,
  ssdf, discover, do178c, asvs.
- React SPA frontend with SSE streaming, multi-language UI (en/es/de/fr/ja/pt).
- CLI binary (vulture scan / login / list / watch).
- Memory system with pgvector cross-audit intelligence.
- Four documented deployment modes (dev-local, central server,
  read-only viewer, CI client).

[Unreleased]: https://github.com/<canonical-slug>/vulture/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/<canonical-slug>/vulture/releases/tag/v0.1.0
```

- [ ] **Step 2: Create security-report contact link in `.github/ISSUE_TEMPLATE/config.yml`**

Prefer the `contact_links` form (renders as a button on "New Issue", does not create an issue):

```yaml
blank_issues_enabled: true
contact_links:
  - name: 🔒 Report a security vulnerability
    url: https://github.com/<canonical-slug>/vulture/security/advisories/new
    about: |
      Do NOT open a public issue for security vulnerabilities.
      Use GitHub Security Advisories or email the address in SECURITY.md.
```

- [ ] **Step 3: Optional — `AUTHORS.md`**

Single line: `Vulture contributors. See `git log` for full history.` Or list named maintainers if any.

- [ ] **Step 4: Optional — `.github/CODEOWNERS`**

Even a one-liner improves review routing:
```
* @<maintainer-handle>
```

- [ ] **Step 5: Verify**

```bash
ls /home/user/src/vulture/CHANGELOG.md \
   /home/user/src/vulture/.github/ISSUE_TEMPLATE/config.yml
```

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md .github/ISSUE_TEMPLATE/config.yml \
  AUTHORS.md .github/CODEOWNERS  # last two if added
git commit -m "docs: add CHANGELOG, security-report contact link, AUTHORS

Adopts Keep-a-Changelog + semver; redirects security disclosures
to GitHub Security Advisories per SECURITY.md."
```

---

## Task 5: Personal/internal references scrub

**Why:** "FutureID" is a real product/customer name. Three "Prior incidents:" paragraphs in CLAUDE.md read as private session post-mortems. `story.md` is a typo-laden brainstorm not appropriate for a public repo. Hardcoded `/home/user/src/vulture/...` paths in feature docs look like author-machine artifacts.

**Files (modify or delete):**
- Modify: `/home/user/src/vulture/CLAUDE.md`
- Delete: `/home/user/src/vulture/story.md`
- Delete: `/home/user/src/vulture/agents/owasp/PLAN.md`
- Modify: `/home/user/src/vulture/docs/features/0033_finding_reference_numbers/0033_implementation_plan.md`
- Modify: `/home/user/src/vulture/docs/features/0034_phase1_cwe_expansion/0034_implementation_plan.md`
- Modify: `/home/user/src/vulture/docs/features/0034_phase1_cwe_expansion/0034_rollback_plan.md`
- Modify: `/home/user/src/vulture/docs/features/0035_asvs_agent/0035_implementation_plan.md`
- Modify: `/home/user/src/vulture/docs/guides/neon_deployment.md` (line 72)

- [ ] **Step 1: Strip "FutureID" reference from CLAUDE.md**

`CLAUDE.md:167` currently reads: *"FutureID deployment required debugging Redis binding, OIDC config, key derivation, and referral permissions sequentially because the infrastructure topology wasn't enumerated first."*

Replace with: *"A prior multi-service deployment required debugging service binding, OIDC config, key derivation, and permissions sequentially because the infrastructure topology wasn't enumerated first."*

- [ ] **Step 2: Strip the three "Prior incidents:" paragraphs in CLAUDE.md**

These are private session post-mortems and don't help an external contributor:
- Lines ~152-157 (Audits section, "A 53-issue performance audit missed a PostgreSQL N+1 query…")
- Lines ~161-167 (Debugging section — including the FutureID reference from Step 1; this whole sub-paragraph can go)
- Lines ~184-188 (Complex Tasks, "An Isabelle/HOL verification session grew from…")

Replace each with a generalized one-liner that preserves the *rule* without the incident anecdote. Example for the Audits section: *"Multi-implementation features (Postgres + SQLite + memory repos) require checking ALL implementations in the enumeration phase."* — drop the count and the specific incident framing.

- [ ] **Step 3: Delete `story.md`**

```bash
git rm /home/user/src/vulture/story.md
```

It is the original AI-generated brief with typos ("pricniples", "compleixy", "saftey") and zero canonical content not already in README.md / docs/architecture/. If preservation is desired for historical interest, move to `docs/history/initial_brief.md` first and clean up the typos:

```bash
mkdir -p docs/history
git mv story.md docs/history/initial_brief.md
# then edit to fix typos, OR delete if not needed
```

Pin the choice here:

> **story.md disposition:** `delete | move-to-history` (fill in before proceeding)

- [ ] **Step 4: Delete `agents/owasp/PLAN.md`**

```bash
git rm /home/user/src/vulture/agents/owasp/PLAN.md
```

If the planning content is still useful, first move under `docs/features/` with a 4-digit prefix per CLAUDE.md §Planning convention.

- [ ] **Step 5: Replace `/home/user/src/vulture/...` absolute paths in feature docs**

Files affected (per audit):
- `docs/features/0033_finding_reference_numbers/0033_implementation_plan.md` — lines 147, 208, 226, 264, 286, 287, 288, 294
- `docs/features/0034_phase1_cwe_expansion/0034_implementation_plan.md` — lines 126, 242, 252, 260, 542, 796, 872, 922, 928, 1036, 1055
- `docs/features/0034_phase1_cwe_expansion/0034_rollback_plan.md` — lines 47, 61, 87
- `docs/features/0035_asvs_agent/0035_implementation_plan.md` — lines 144, 146, 147, 306, 347, 443, 684, 715, 724, 777, 810
- `docs/guides/neon_deployment.md` — line 72

Mechanical replace:

```bash
cd /home/user/src/vulture
git grep -l '/home/user/src/vulture' docs/ \
  | xargs sed -i 's|/home/user/src/vulture/|<vulture-repo-root>/|g; s|/home/user/src/vulture\b|<vulture-repo-root>|g'
```

Then spot-check 2-3 modified files to ensure the sed didn't over-match.

- [ ] **Step 6: Verify**

```bash
git grep -E 'FutureID|/home/user/src/vulture'  # should produce zero hits
git grep -l 'Prior incident'  CLAUDE.md  # should produce zero hits
ls story.md agents/owasp/PLAN.md 2>&1 | grep -c 'No such'  # should be 2
```

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md docs/
git rm story.md agents/owasp/PLAN.md
git commit -m "docs: scrub personal and internal references for public release

- Remove FutureID customer reference and three Prior-incidents
  paragraphs from CLAUDE.md
- Delete story.md (original brief, superseded by README/docs)
- Delete agents/owasp/PLAN.md (leftover internal planning)
- Replace absolute author-machine paths in feature docs and guides
  with <vulture-repo-root> placeholder

Closes personal/internal-reference findings from 2026-04-25 audit."
```

---

# Phase 2 — Working tree cleanup (safe, reversible)

## Task 6: Untrack binaries and bloat; tighten .gitignore

**Why:** Tracked binaries and vendored MITRE PDF/XML inflate clones. `.gitignore` already covers the binaries' future state, but never untracked the existing blobs. This task makes HEAD clean; Phase 4 will purge the historic blobs.

**Files (untrack):**
- `/home/user/src/vulture/backend/vulture` (17 MB ELF — currently `M backend/vulture` in git status)
- `/home/user/src/vulture/cli/vulture` (currently `D` in working tree, ensure removal is committed)
- `/home/user/src/vulture/docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf` (37 MB)
- `/home/user/src/vulture/docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml` (16 MB)
- `/home/user/src/vulture/docs/features/0010_cwe_audit/cwec_v4.19.1.xml` (16 MB duplicate)
- `/home/user/src/vulture/docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd` (96 KB)
- `/home/user/src/vulture/frontend/playwright-report/index.html` (557 KB)
- `/home/user/src/vulture/.claude/settings.json` (0 bytes, tracked despite `.claude/` gitignore)

**Files (delete from working tree, untracked stale):**
- `/home/user/src/vulture/backend-bin` (17 MB stale ELF, untracked but sits in repo root)

**Files (modify):**
- `/home/user/src/vulture/.gitignore`

- [ ] **Step 1: Replace each external binary artifact (XML/PDF/XSD) with a sibling Markdown pointer file**

**Pinned decision:** drop every tracked external binary and replace it with a tiny `*.md` pointer file in the same directory. The pointer file documents (a) what the artifact is, (b) the upstream URL, (c) the upstream version, (d) a SHA-256 checksum (computed once, recorded), and (e) how to fetch a local copy. Generated JSON files derived from these artifacts (the `cwe_catalog.json` and the ASVS `asvs_*.json` family) are **preserved as tracked files** — they are first-party-derived data, not the upstream binary.

The tradeoff: clones drop ~70 MB of upstream binary content while keeping the agents fully functional from the committed JSON. Anyone who needs to regenerate the JSON from upstream follows the pointer file.

**Pointer files to create** (one per dropped external artifact):

| Pointer file (create) | Replaces (drop) | Upstream URL |
|---|---|---|
| `docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml.md` | `cwec_v4.19.1.xml` (16 MB) | `https://cwe.mitre.org/data/xml/cwec_v4.19.1.xml.zip` |
| `docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf.md` | `cwe_latest.pdf` (37 MB) | `https://cwe.mitre.org/data/pdf/cwec_v4.19.1.pdf` |
| `docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd.md` | `cwe_schema_latest.xsd` | `https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd` |
| `docs/features/0010_cwe_audit/cwec_v4.19.1.xml.md` | `cwec_v4.19.1.xml` (duplicate) | (same as row 1) |

**Files preserved as tracked** (do NOT untrack these — they are generated, first-party derivatives, ship with the repo so the agents work without network access on first run):

- `agents/cwe/cwe_agent/data/cwe_catalog.json` (~2.2 MB derivative of MITRE CWE)
- `agents/asvs/asvs_agent/data/asvs_source.json` and the three derivatives (`asvs_catalog.json`, `asvs_cwe_crosswalk.json`, `asvs_detectability.json`)

Pointer-file template (use for all four):

```markdown
# MITRE CWE™ 4.19.1 — XML catalog (external resource)

This file replaces `cwec_v4.19.1.xml`, which was previously tracked
in this repository (~16 MB). The XML is *not* shipped here; download
it from MITRE if you need the raw upstream catalog.

## Source

- **Upstream URL:** https://cwe.mitre.org/data/xml/cwec_v4.19.1.xml.zip
- **Version:** CWE 4.19.1
- **License:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html)
- **Copyright:** © 2006-2025 The MITRE Corporation. All rights reserved.
- **SHA-256 (uncompressed XML):** `<run sha256sum locally and paste here>`

## How to fetch

```bash
curl -fsSL https://cwe.mitre.org/data/xml/cwec_v4.19.1.xml.zip -o /tmp/cwec.zip
unzip /tmp/cwec.zip -d /tmp/cwec
sha256sum /tmp/cwec/cwec_v4.19.1.xml  # verify against the SHA-256 above
```

## What ships in this repo instead

The CWE catalog used at runtime by the `agent-cwe` service is the
generated derivative `agents/cwe/cwe_agent/data/cwe_catalog.json`,
which is committed and is the canonical input format for the agent.
You only need this raw upstream XML if you want to regenerate the
JSON or audit the transformation.

## Why this is a pointer instead of the full file

The raw XML is ~16 MB and the corresponding PDF is ~37 MB — together
they accounted for the bulk of the repository's tracked size. They
are upstream content that can be re-downloaded any time; vendoring
them inflated clones for everyone without benefit. See
[NOTICE](../../../NOTICE) and [THIRD_PARTY_LICENSES.md](../../../THIRD_PARTY_LICENSES.md)
for the full attribution.
```

Customize the template per row:
- The `cwe_latest.pdf.md` pointer references the PDF and notes "this is the human-readable form of the same data already shipped as `cwe_catalog.json`".
- The `cwe_schema_latest.xsd.md` pointer references the XSD and notes "needed only if you regenerate the JSON or validate raw upstream XML".
- The `docs/features/0010_cwe_audit/cwec_v4.19.1.xml.md` pointer notes "this directory previously held a duplicate copy of the same MITRE XML; it is not used at runtime — see `docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml.md` for the canonical pointer".

Compute the SHA-256 once locally before authoring the pointer files:

```bash
# After fetching the upstream XML and PDF locally one time:
sha256sum /tmp/cwec/cwec_v4.19.1.xml  # paste into XML pointer
sha256sum /tmp/cwec/cwec_v4.19.1.pdf  # paste into PDF pointer
sha256sum /tmp/cwec/cwe_schema_latest.xsd  # paste into XSD pointer
```

- [ ] **Step 2: Author the four `*.md` pointer files** (using the template + SHA-256 values from Step 1) and `git add` them.

```bash
git add \
  docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml.md \
  docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf.md \
  docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd.md \
  docs/features/0010_cwe_audit/cwec_v4.19.1.xml.md
```

- [ ] **Step 3: `git rm --cached` each tracked-bloat path** (binaries + the upstream artifacts now replaced by pointer files)

```bash
cd /home/user/src/vulture
git rm --cached \
  backend/vulture \
  docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf \
  docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml \
  docs/features/0010_cwe_audit/cwec_v4.19.1.xml \
  docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd \
  frontend/playwright-report/index.html \
  .claude/settings.json
```

For `cli/vulture`: ensure the existing deletion is staged and committed.

**Do NOT untrack** these generated-derivative JSON files — they are first-party, ship with the repo, and are required by the agents at startup:
- `agents/cwe/cwe_agent/data/cwe_catalog.json`
- `agents/asvs/asvs_agent/data/asvs_source.json`
- `agents/asvs/asvs_agent/data/asvs_catalog.json`
- `agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json`
- `agents/asvs/asvs_agent/data/asvs_detectability.json`

- [ ] **Step 4: Tighten `.gitignore`**

Append:
```gitignore
# Build binaries (catch-all by basename)
**/vulture
!**/vulture/  # but allow directories named vulture/ (the source tree)
backend-bin

# External upstream artifacts — replaced by sibling *.md pointer files.
# Anyone who needs the raw upstream binary fetches it via the pointer.
docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf
docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml
docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd
docs/features/0010_cwe_audit/cwec_v4.19.1.xml

# Test reports
frontend/playwright-report/

# Editor / AI tooling
.aider*
.cursor/
.zed/
.fleet/
*.tsbuildinfo
.eslintcache
.turbo/

# Merge-conflict and runtime debris
*.bak
*.orig
*.rej
*.tmp
*.log

# Explicit allowlists
!.env.example
!config.ini.example
# The .md pointer files MUST stay tracked even though the binaries
# they describe are gitignored above. .md files are not matched by
# the *.pdf / *.xml / *.xsd patterns, so no negation is needed —
# this comment is a reminder, not a rule.
```

Verify the `**/vulture` rule does not accidentally ignore the source tree by running:

```bash
git check-ignore -v cli/main.go  # should NOT be ignored
git check-ignore -v backend/internal/handler/audit_handler.go  # should NOT be ignored
git check-ignore -v backend/vulture  # SHOULD be ignored
git check-ignore -v cli/vulture  # SHOULD be ignored
```

If `**/vulture` matches directories incorrectly, switch to two explicit rules:
```gitignore
backend/vulture
cli/vulture
```

- [ ] **Step 5: Delete stale local-only binaries from working tree**

```bash
rm /home/user/src/vulture/backend-bin
# verify the working tree no longer has stale ELFs
find /home/user/src/vulture -maxdepth 3 -type f -name 'vulture' -exec file {} \; \
  | grep -i 'ELF\|executable'
```

- [ ] **Step 6: Verify HEAD-tracked size dropped and pointer files render**

```bash
cd /home/user/src/vulture
git ls-files -z | xargs -0 du -bc | tail -1
```
Expected: dramatically smaller than the pre-task ~90 MB. Note: `.git/` size won't change until Phase 4.

Verify the pointer files are tracked and the upstream binaries are not:

```bash
git ls-files | grep -E 'cwec_v4.19.1|cwe_latest|cwe_schema_latest'
```
Expected: only the four `*.md` pointer files appear; no `.xml`/`.pdf`/`.xsd`.

- [ ] **Step 7: Commit**

```bash
git add .gitignore \
  docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml.md \
  docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf.md \
  docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd.md \
  docs/features/0010_cwe_audit/cwec_v4.19.1.xml.md
git commit -m "chore(repo): untrack binaries; pointer-replace MITRE upstream artifacts

- Untrack backend/vulture (17M ELF) and cli/vulture from HEAD
- Replace 3 tracked upstream MITRE artifacts (PDF 37M, XML 16M,
  schema) and the duplicate-XML copy with sibling *.md pointer
  files documenting the upstream URL, version, license, and
  SHA-256 checksum
- Preserve the generated cwe_catalog.json and asvs_*.json — the
  agents consume those at runtime; only raw upstream binaries
  are externalized
- Untrack frontend/playwright-report/index.html and empty
  .claude/settings.json
- Tighten .gitignore to prevent re-introduction; add explicit
  negations for .env.example and config.ini.example
- Delete stale untracked backend-bin from working tree

HEAD-tracked size drops from ~90M to ~2M. Historic blobs are
still present and will be evicted in Phase 4 (filter-repo).
Closes hygiene findings from 2026-04-25 audit."
```

---

# Phase 3 — Mode B code-security hardening (OPTIONAL — defer to v0.2 if time-pressed)

> **Decision required before starting Phase 3:**
>
> If shipping v0.1 with Mode B safe-by-default, complete this phase.
>
> If shipping v0.1 as "Mode A only", **skip to Phase 4** and ensure README §Deployment Modes (added in Task 3 Step 5) declares Mode B as not-hardened with a link to a follow-up feature `0037_mode_b_hardening`.
>
> **Choice:** `complete-phase-3 | defer-to-v0.2` (fill in before proceeding)

The eight critical/high code-security findings (C1–C3, H1, H2/H3, H7, H8, H9) are clustered into 4 implementation tasks (T7-T14). Each task is structured as **TDD**: write the failing test first, run to confirm fail, implement the fix, run to confirm pass, commit. Per CLAUDE.md §Code Quality Rules, the tests are E2E business-logic tests and **must not** be modified later to make code pass.

## Task 7: Auth/CORS/local-mode E2E tests (RED)

**Why:** C1, C3, H7, H9 all relate to the local-mode admin seed and auth-bypass surface. Test first.

**Files (create):**
- `/home/user/src/vulture/backend/test/e2e/security_local_mode_test.go`

- [ ] **Step 1: Write failing E2E tests**

```go
// /home/user/src/vulture/backend/test/e2e/security_local_mode_test.go
package e2e

import (
  "net/http"
  "net/http/httptest"
  "strings"
  "testing"
)

func TestLocalModeRefusesNonLoopbackBind(t *testing.T) {
  // ARRANGE: server configured with VULTURE_LOCAL_MODE=true and
  //          ListenAddr=0.0.0.0:8080 (non-loopback)
  // EXPECT:  server startup returns error containing "local mode"
  //          and "loopback" (or equivalent: refuses to bind 0.0.0.0).
  t.Skip("RED: implementation pending in T8")
}

func TestLocalModeAdminSeedOnlyInLocalMode(t *testing.T) {
  // ARRANGE: server with VULTURE_LOCAL_MODE=false, no users in DB.
  // ACT:     POST /api/auth/login with {email: admin@vulture.local, password: REDACTED-DEV-PW}
  // EXPECT:  HTTP 401 Unauthorized — admin seed must NOT exist when local mode off.
  t.Skip("RED: implementation pending in T8")
}

func TestCORSNoWildcardWithCredentials(t *testing.T) {
  // ARRANGE: server with default config.
  // ACT:     OPTIONS /api/audits with Origin: https://attacker.example, no allowlist.
  // EXPECT:  response either omits Access-Control-Allow-Origin or returns 403.
  //          Specifically MUST NOT return Access-Control-Allow-Origin: * with
  //          Access-Control-Allow-Credentials: true.
  t.Skip("RED: implementation pending in T8")
}

func TestLocalSessionLoginRequiresHostMatch(t *testing.T) {
  // ARRANGE: server with VULTURE_LOCAL_MODE=true bound to 127.0.0.1.
  // ACT:     GET /api/auth/local-session with Host: evil.example
  // EXPECT:  HTTP 403; substring-match in current code allows
  //          arbitrary Host containing 'localhost' — must be exact match.
  t.Skip("RED: implementation pending in T8")
}
```

- [ ] **Step 2: Run tests — confirm they FAIL (or at minimum show t.Skip is the only thing keeping them green)**

```bash
cd /home/user/src/vulture/backend
go test ./test/e2e/... -run 'TestLocalMode|TestCORS|TestLocalSession' -v
```
Expected: 4 tests skipped (RED — gate for T8).

- [ ] **Step 3: Replace `t.Skip(...)` with actual ARRANGE/ACT/ASSERT bodies**

For each test, write the real body using `httptest.NewServer` + the existing test helpers in `backend/test/e2e/`. The tests must **fail** against current code (proving the vulnerability exists).

- [ ] **Step 4: Run again — confirm 4 tests FAIL with informative messages**

```bash
go test ./test/e2e/... -run 'TestLocalMode|TestCORS|TestLocalSession' -v
```
Expected: each test fails with a message naming the missing protection.

- [ ] **Step 5: Commit RED**

```bash
git add backend/test/e2e/security_local_mode_test.go
git commit -m "test(e2e): RED — auth/CORS/local-mode security tests

Adds 4 failing E2E tests for findings C1, C3, H7, H9 from the
2026-04-25 audit. Implementation lands in T8."
```

## Task 8: Auth/CORS/local-mode fixes (GREEN)

**Files (modify):**
- `/home/user/src/vulture/backend/internal/server/server.go` (`localDevPassword`, `seedLocalUser`, ListenAddr validation)
- `/home/user/src/vulture/backend/internal/server/middleware.go` (CORS allowlist)
- `/home/user/src/vulture/backend/internal/handler/auth_handler.go` (local-session host check)
- `/home/user/src/vulture/backend/internal/config/config.go` (CORS allowlist env: `VULTURE_CORS_ALLOWED_ORIGINS`)

- [ ] **Step 1: Gate the admin seed to local mode only**

In `backend/internal/server/server.go::seedLocalUser` (or wherever `localDevPassword = "REDACTED-DEV-PW"` is consumed), wrap the call site:

```go
if cfg.LocalMode {
  seedLocalUser(...)
}
```

Verify no other call path can seed `admin@vulture.local`.

- [ ] **Step 2: Refuse non-loopback bind in local mode**

In server startup, after parsing `ListenAddr`:

```go
if cfg.LocalMode && !isLoopbackBind(cfg.ListenAddr) {
  return fmt.Errorf("VULTURE_LOCAL_MODE is enabled but listen address %q is not loopback (127.0.0.1, ::1, or localhost) — refusing to start", cfg.ListenAddr)
}
```

Define `isLoopbackBind(addr string) bool` to parse host:port and accept only `127.0.0.1`, `::1`, `localhost`, or empty (means default loopback).

- [ ] **Step 3: Replace wildcard CORS with explicit allowlist**

In `middleware.go`, drive `Access-Control-Allow-Origin` from `cfg.CORSAllowedOrigins` (a `[]string` populated from `VULTURE_CORS_ALLOWED_ORIGINS`, comma-separated). On no match, omit the header entirely. Default value: empty (no cross-origin allowed). When the request Origin matches an allowlist entry, echo it back; never use `*` together with `Access-Control-Allow-Credentials: true`.

- [ ] **Step 4: Replace substring-match with exact-equality on local-session Host**

In `auth_handler.go::LocalSession`, change `strings.Contains(host, "localhost")` (or equivalent substring check) to:

```go
host, _, _ := net.SplitHostPort(r.Host)
if host == "" {
  host = r.Host
}
if host != "localhost" && host != "127.0.0.1" && host != "::1" {
  http.Error(w, "local session requires loopback host", http.StatusForbidden)
  return
}
```

- [ ] **Step 5: Run T7 tests — confirm they PASS**

```bash
go test ./test/e2e/... -run 'TestLocalMode|TestCORS|TestLocalSession' -v
```
Expected: 4/4 PASS.

- [ ] **Step 6: Run full backend test suite — confirm no regressions**

```bash
cd /home/user/src/vulture/backend
go test ./...
```
Expected: all green.

- [ ] **Step 7: Commit GREEN**

```bash
git add backend/internal/server/server.go \
  backend/internal/server/middleware.go \
  backend/internal/handler/auth_handler.go \
  backend/internal/config/config.go
git commit -m "fix(security): gate admin seed + loopback bind + CORS allowlist + Host equality

- C1: REDACTED-DEV-PW admin seed only created when VULTURE_LOCAL_MODE=true
- C3: CORS driven by VULTURE_CORS_ALLOWED_ORIGINS allowlist; no
      wildcard with credentials
- H7: local-session login requires Host \\\\in {localhost, 127.0.0.1, ::1}
      via exact equality (was substring match)
- H9: VULTURE_LOCAL_MODE=true refuses to bind on non-loopback addresses
      with a clear error message at startup

Tests in T7 now PASS. Closes Mode-B critical findings C1/C3/H7/H9."
```

## Task 9: SQLite default-role mismatch — RED

**Files (create):**
- `/home/user/src/vulture/backend/internal/repository/role_default_test.go`

- [ ] **Step 1: Write failing test**

```go
// Verify both Postgres and SQLite stores create new users with role="user"
// (not "admin"). Audit found that one of the two backends defaulted to "admin"
// at user creation; this test pins the contract.
func TestUserDefaultRoleIsNotAdmin(t *testing.T) {
  for _, backend := range []string{"postgres", "sqlite"} {
    t.Run(backend, func(t *testing.T) {
      repo := newRepoForTest(t, backend)
      u, err := repo.CreateUser(ctx, "test@example.com", "hash")
      if err != nil { t.Fatal(err) }
      if u.Role == "admin" {
        t.Fatalf("backend %q created user with role=admin (must default to 'user' or empty)", backend)
      }
    })
  }
}
```

- [ ] **Step 2: Run — confirm SQLite case fails (or both, depending on which had the bug)**

```bash
go test ./internal/repository/ -run TestUserDefaultRoleIsNotAdmin -v
```

- [ ] **Step 3: Commit RED**

```bash
git add backend/internal/repository/role_default_test.go
git commit -m "test: RED — pin user-default-role contract for both backends"
```

## Task 10: SQLite default-role fix — GREEN

**Files (modify):**
- `/home/user/src/vulture/backend/internal/repository/sqlite_repo.go` (CreateUser default)
- `/home/user/src/vulture/backend/migrations/sqlite/<NNN>_user_role_default.sql` OR inline schema fix

- [ ] **Step 1: Identify which backend has the wrong default**

```bash
grep -n 'role' backend/internal/repository/postgres_repo.go backend/internal/repository/sqlite_repo.go
grep -n 'role' backend/migrations/*.sql
```

- [ ] **Step 2: Fix the default at the wrong backend**

Either change the inline `INSERT INTO users (...) VALUES (..., 'admin', ...)` to `'user'`, or change a `CREATE TABLE users (... role TEXT NOT NULL DEFAULT 'admin' ...)` to `DEFAULT 'user'` plus add a migration that ALTERs existing rows.

Add a CHECK constraint to both backends:
```sql
CHECK (role IN ('user', 'admin'))
```

- [ ] **Step 3: Run T9 test — confirm PASS**

```bash
go test ./internal/repository/ -run TestUserDefaultRoleIsNotAdmin -v
```
Expected: both backends PASS.

- [ ] **Step 4: Commit GREEN**

```bash
git add backend/internal/repository/ backend/migrations/
git commit -m "fix(security): default new users to role='user' in both backends

Closes C2 from 2026-04-25 audit. Adds CHECK constraint pinning
role to the {user, admin} set."
```

## Task 11: Webhook SSRF + agent-token tests — RED

**Files (create):**
- `/home/user/src/vulture/backend/internal/handler/webhook_handler_test.go` (extend existing)
- `/home/user/src/vulture/backend/test/e2e/agent_token_required_test.go`

- [ ] **Step 1: Write failing webhook SSRF test**

Test cases the implementation must reject:
- `http://127.0.0.1/...`, `http://[::1]/...`, `http://localhost/...`
- RFC1918: `http://10.0.0.1/`, `http://192.168.1.1/`, `http://172.16.0.1/`
- Link-local: `http://169.254.169.254/` (AWS metadata)
- File scheme: `file:///etc/passwd`
- Non-HTTPS in non-local mode (policy choice)
- DNS rebinding: validate post-resolution IP, not just the hostname string

```go
func TestWebhookURLRejectsInternalAndFileSchemes(t *testing.T) {
  bad := []string{
    "http://127.0.0.1/x", "http://[::1]/x", "http://localhost/x",
    "http://10.0.0.1/x", "http://192.168.1.1/x", "http://172.16.0.1/x",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "gopher://internal.example/",
  }
  for _, u := range bad {
    t.Run(u, func(t *testing.T) {
      err := validateWebhookURL(u)
      if err == nil {
        t.Fatalf("expected validateWebhookURL(%q) to reject; got nil", u)
      }
    })
  }
}
```

- [ ] **Step 2: Write failing agent-token test**

```go
func TestAgentEndpointsRequireTokenInNonLocalMode(t *testing.T) {
  // ARRANGE: backend in non-local mode; no Authorization header.
  // ACT:     direct HTTP to agent service /audit endpoint.
  // EXPECT:  401 Unauthorized.
  //
  // Also: with VULTURE_AGENT_TOKEN set, requests with the wrong
  // token return 401, with the right token return 200.
}
```

- [ ] **Step 3: Confirm both fail**

- [ ] **Step 4: Commit RED**

## Task 12: Webhook SSRF + agent-token fixes — GREEN

**Files (modify):**
- `/home/user/src/vulture/backend/internal/handler/webhook_handler.go` (add `validateWebhookURL`)
- `/home/user/src/vulture/agents/shared/shared/transport/sse_app.py` (FastAPI auth dependency)
- `/home/user/src/vulture/backend/internal/config/config.go` (`VULTURE_AGENT_TOKEN` config)
- `/home/user/src/vulture/docker-compose.yml` (pass `VULTURE_AGENT_TOKEN` to backend + agents)

- [ ] **Step 1: Implement `validateWebhookURL`**

```go
func validateWebhookURL(raw string) error {
  u, err := url.Parse(raw)
  if err != nil { return err }
  if u.Scheme != "http" && u.Scheme != "https" {
    return fmt.Errorf("scheme %q not allowed", u.Scheme)
  }
  host := u.Hostname()
  ips, err := net.LookupIP(host)
  if err != nil { return fmt.Errorf("dns: %w", err) }
  for _, ip := range ips {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
       ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
      return fmt.Errorf("host %q resolves to non-public IP %s", host, ip)
    }
  }
  return nil
}
```

Mind: this still has a TOCTOU window (resolve here, used later by `http.Get`). For a stronger fix, use a `*http.Transport` with a custom `DialContext` that re-checks the resolved IP at dial time. For v0.1, the LookupIP gate is acceptable; document the TOCTOU residual in a comment.

- [ ] **Step 2: Add `VULTURE_AGENT_TOKEN` to config + agent FastAPI dependency**

In Python `agents/shared/shared/transport/sse_app.py`, add a FastAPI dependency that reads `VULTURE_AGENT_TOKEN` env at startup; if set, every endpoint requires `Authorization: Bearer <token>`. If unset and `VULTURE_LOCAL_MODE` is unset, refuse to start with: *"VULTURE_AGENT_TOKEN is required when not in local mode"*.

In Go, the backend's outbound calls to agents must include the token from `cfg.AgentToken`.

- [ ] **Step 3: Wire `VULTURE_AGENT_TOKEN` in `docker-compose.yml`**

Add the env var to the backend service (passed to outbound calls) and to every `agent-*` service block (consumed by the FastAPI dependency).

- [ ] **Step 4: Run RED tests — confirm GREEN**

- [ ] **Step 5: Commit GREEN**

## Task 13: Filesystem-browse confinement — RED

**Files (create):**
- `/home/user/src/vulture/backend/internal/handler/filesystem_handler_test.go`

- [ ] **Step 1: Write failing test**

Validate that:
- Path traversal `..` segments reject with 400.
- Absolute paths outside `cfg.SourceRoot` reject with 403.
- Symlinks pointing outside `cfg.SourceRoot` reject with 403.
- Hidden files (`.git/`, `.env`) reject by default.
- Maximum recursion depth and result count enforced.

## Task 14: Filesystem-browse confinement — GREEN

**Files (modify):**
- `/home/user/src/vulture/backend/internal/handler/filesystem_handler.go`
- `/home/user/src/vulture/backend/internal/service/source_service.go`

- [ ] **Step 1: Add path canonicalization with `filepath.EvalSymlinks` + prefix check**

```go
canon, err := filepath.EvalSymlinks(filepath.Join(cfg.SourceRoot, requested))
if err != nil { return nil, http.StatusBadRequest }
abs, err := filepath.Abs(canon)
if err != nil { return nil, http.StatusBadRequest }
if !strings.HasPrefix(abs, filepath.Clean(cfg.SourceRoot)+string(os.PathSeparator)) &&
   abs != filepath.Clean(cfg.SourceRoot) {
  return nil, http.StatusForbidden
}
```

- [ ] **Step 2: Add hidden-file allowlist + max-depth + max-entries caps**

- [ ] **Step 3: Run T13 tests — confirm GREEN**

- [ ] **Step 4: Commit GREEN**

## Task 15: Misc Mode-B hardening (M9, M14, M15, L1–L12)

Lower-priority items batched together. Each is a single small edit.

**Files (modify):**
- `/home/user/src/vulture/backend/internal/config/config.go` (M9: enforce `len(JWTSecret) >= 32`; refuse to start otherwise)
- `/home/user/src/vulture/backend/migrations/sqlite/NNN_api_keys.sql` (M14: extract SQLite api_keys table from inline `migrateAddColumns` into a versioned migration)
- `/home/user/src/vulture/backend/pkg/gitutil/clone.go` (M15: pass git creds via `GIT_ASKPASS` script or `http.extraHeader`, not via URL embedding)
- `/home/user/src/vulture/backend/internal/server/middleware.go` (L2 deprecated `X-XSS-Protection` removal; L3 add minimal CSP `default-src 'self'`; L1 conditional HSTS only on TLS connections; L4 fix the misleading "ISO 26262" comment to "OWASP secure-headers")
- `/home/user/src/vulture/.github/workflows/ci.yml` (H10: pin all `uses: actions/...@v*` and third-party actions to commit SHAs; add a comment with the human-readable tag)

For each: write a small E2E test if behavior-visible (M9 startup refusal, M14 schema match), or rely on existing handler tests (middleware) / static check (CI workflow `actionlint`).

Acceptance criteria: `golangci-lint run` clean; backend tests green; CI workflow lint clean (`actionlint .github/workflows/ci.yml`).

Commit message:
```
fix(security): JWT min length, SQLite migration, git creds, CSP, action SHAs

Closes M9, M14, M15, L1, L2, L3, L4, H10 from 2026-04-25 audit.
```

## Task 16: Verify SECURITY.md / CODE_OF_CONDUCT.md contact addresses

**Why:** `security@vulture.dev` and `conduct@vulture.dev` are placeholders. If `vulture.dev` is unregistered, an attacker could squat the domain and intercept disclosures.

- [ ] **Step 1: User-decision required**

Choose one:
  - **(a) Register `vulture.dev` and provision the two mailboxes.** Cost ≈ $15/yr + a forwarding rule on the maintainer's mail server. Update SECURITY.md / CODE_OF_CONDUCT.md to mention "responses within 48 hours of receipt".
  - **(b) Replace both addresses with GitHub-native flows.** SECURITY.md → `https://github.com/<canonical-slug>/vulture/security/advisories/new`. CODE_OF_CONDUCT.md → an inbox the maintainer already controls (e.g., `<maintainer-handle>+conduct@<personal-domain>`) **or** a private GitHub Discussions Code-of-Conduct category.
  - **(c) Replace with a `security@<personal-domain>` already controlled.**

> **Choice:** `a | b | c` (fill in before proceeding)

- [ ] **Step 2: Apply the chosen change in SECURITY.md and CODE_OF_CONDUCT.md**

- [ ] **Step 3: Test the channel**

Send a test email or open a test draft advisory; confirm receipt.

- [ ] **Step 4: Commit**

```bash
git add SECURITY.md CODE_OF_CONDUCT.md
git commit -m "docs: pin security and conduct contact channels

Replaces vulture.dev placeholder addresses with [chosen channel].
Verified deliverable on 2026-MM-DD."
```

---

# Phase 4 — History rewrite + release (DESTRUCTIVE, one-way)

> **Pre-flight checklist before starting Phase 4:**
> - [ ] Phases 1, 2, and (if chosen) 3 are merged to `main` or to a clean integration branch.
> - [ ] Working tree is clean (`git status` empty).
> - [ ] All tests green (`make test`).
> - [ ] `git filter-repo` is installed (`git filter-repo --version`).
> - [ ] User has explicitly confirmed: *"Yes, rewrite history."*
> - [ ] A backup tag exists: `git tag pre-filter-repo-backup`.
> - [ ] A bare clone of the current state exists at `<safe-location>/vulture-pre-filter-repo.git`.
> - [ ] **No collaborators have outstanding branches.** Phase 4 invalidates every existing SHA.

## Task 17: Bare-clone backup + filter-repo

**Files (none modified directly; the rewrite touches the entire `.git/` store).**

- [ ] **Step 1: Backup**

```bash
cd /home/user/src/
git clone --mirror /home/user/src/vulture vulture-pre-filter-repo.git
cd vulture
git tag pre-filter-repo-backup
git tag --list | grep pre-filter-repo-backup  # verify
```

- [ ] **Step 2: Run `git filter-repo` — drop bloat blobs**

```bash
cd /home/user/src/vulture
git filter-repo \
  --invert-paths \
  --path backend/vulture \
  --path cli/vulture \
  --path docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf \
  --path docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml \
  --path docs/features/0014_cwe_version_4.19.1/cwe_schema_latest.xsd \
  --path docs/features/0010_cwe_audit/cwec_v4.19.1.xml \
  --path frontend/playwright-report/index.html \
  --path .claude/settings.json \
  --path story.md \
  --path agents/owasp/PLAN.md \
  --force
```

The `--force` flag is needed because `filter-repo` insists the working tree look like a freshly cloned mirror; we have a working repo. **`filter-repo` will remove the `origin` remote** as a safety measure — that's expected. We will set a *fresh* remote in T20.

- [ ] **Step 3: Run `git filter-repo --replace-text` to scrub historical secrets**

Create `/tmp/vulture-secret-replacements.txt`:
```
REDACTED-PG-PW==>***REMOVED***
REDACTED-JWT-DEFAULT==>***REMOVED***
```

```bash
git filter-repo --replace-text /tmp/vulture-secret-replacements.txt --force
```

- [ ] **Step 4: Repack the .git store**

```bash
git reflog expire --expire=now --all
git gc --aggressive --prune=now
```

- [ ] **Step 5: Verify size and content**

```bash
du -sh .git/  # expected: < 10 MB
git ls-files | wc -l  # expected: ~745
git rev-list --all --objects | git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize) %(rest)' \
  | awk '$2=="blob" && $3>500000' | sort -k3 -n -r  # expected: empty or only legit large blobs (e.g., asvs catalog)
git log --all -p | grep -c 'REDACTED-PG-PW' || true  # expected: 0
git log --all -p | grep -c 'REDACTED-JWT-DEFAULT' || true  # expected: 0
```

- [ ] **Step 6: Run smoke tests against rewritten tree**

```bash
make test  # backend + agents + frontend unit tests
make build  # ensure binaries rebuild from rewritten source
```

If anything fails: **STOP and restore from `pre-filter-repo-backup` tag or the bare clone**. Do not push.

- [ ] **Step 7: Commit boundary**

`filter-repo` already created new commits with new SHAs. No further commit needed; HEAD is the rewritten tip.

## Task 18: Final pre-publish verification

- [ ] **Step 1: Run the full audit's grep/check sweep one more time**

```bash
# Personal/internal references
git grep -E 'FutureID|/home/user/src/vulture' && echo "FAIL" || echo "ok"
# Historical secrets
git log --all -p | grep -E 'REDACTED-PG-PW|REDACTED-JWT-DEFAULT' && echo "FAIL" || echo "ok"
# Tracked binaries
git ls-files | xargs -I{} file '{}' 2>/dev/null | grep -E 'ELF|Mach-O|PE32 executable' && echo "FAIL" || echo "ok"
# Repo size
du -sh .git/ | awk '{print $1}'  # expected single-digit MB
git ls-files -z | xargs -0 du -bc | tail -1 | awk '{print $1}'  # expected < 5 MB
```

All four checks must print `ok` (or empty) and the size must be in the expected range.

- [ ] **Step 2: Re-run the test suite**

```bash
make test && make e2e
```

- [ ] **Step 3: Re-read README, CHANGELOG, NOTICE, THIRD_PARTY_LICENSES.md, SECURITY.md, CODE_OF_CONDUCT.md once end-to-end**

Catch typos, dead links, and stale claims with a human read. Fix any that surface (commit normally — these are post-rewrite commits, fine).

## Task 19: Tag v0.1.0 + finalize CHANGELOG

- [ ] **Step 1: Replace the `<YYYY-MM-DD>` placeholder in CHANGELOG.md with today's date**

- [ ] **Step 2: Commit the CHANGELOG date change**

```bash
git add CHANGELOG.md
git commit -m "release: prepare v0.1.0"
```

- [ ] **Step 3: Tag**

```bash
git tag -a v0.1.0 -m "Vulture v0.1.0 — initial public release

See CHANGELOG.md for full notes. This release ships:
- Mode A (developer-laptop) is the supported deployment target
- Modes B/C/D are documented but [hardened in v0.2 / hardened today,
  pick the right line based on Phase-3 outcome]"
git tag -v v0.1.0  # if signing keys are configured; else `git show v0.1.0`
```

## Task 20: Push to fresh public remote

> **CRITICAL:** Do NOT `git push --force` to the existing remote. The
> existing `origin` (if any collaborator has it) becomes invalid because
> every SHA changed. Push to a *fresh* remote and treat the old one as
> archived/abandoned.

- [ ] **Step 1: Create the public GitHub repository**

Via GitHub web UI: create `<canonical-slug>/vulture` (the slug pinned in T3 Step 1). Empty repo, no auto-generated README/LICENSE/gitignore — we already ship our own.

- [ ] **Step 2: Set the new remote and push**

```bash
cd /home/user/src/vulture
git remote remove origin 2>/dev/null || true  # filter-repo already removed it; just in case
git remote add origin git@github.com:<canonical-slug>/vulture.git
git push -u origin main
git push origin v0.1.0
```

- [ ] **Step 3: Verify on GitHub**

Open the repo URL in a browser and check:
- README renders correctly (badges, attributions section, deployment-modes table)
- Issue template surfaces both forms (bug report, feature request) AND the contact-link button (security report)
- Tag `v0.1.0` is visible under Releases (consider clicking "Draft a new release" with the CHANGELOG entry to formalize)
- `.github/workflows/ci.yml` runs and passes on the first push (or shows expected failures fixed in a follow-up)
- Repo size displayed at the top is small (< 10 MB)
- `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.md`, `CHANGELOG.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md` all visible at root.

- [ ] **Step 4: Mark the local backup as keepable, the bare clone as archived**

```bash
# Don't delete pre-filter-repo-backup tag for at least 30 days post-release.
# Keep /home/user/src/vulture-pre-filter-repo.git/ archived offline (or in a
# private S3 bucket) until you are confident no rollback is needed.
echo "DO NOT DELETE — pre-public-release backup, retain until $(date -d '+30 days' +%Y-%m-%d)" \
  > /home/user/src/vulture-pre-filter-repo.git/RETENTION.txt
```

---

## Self-review (against the spec)

This plan covers each finding from the 2026-04-25 audit (cross-referenced in the table at the top). Phase 1 closes documentation/attribution/personal items without behavior change. Phase 2 makes HEAD clean. Phase 3 (optional) closes Mode B's eight code-security findings via TDD. Phase 4 rewrites history once and pushes to a fresh remote.

Spec gaps re-checked: `frontend/playwright-report/index.html` (Phase 2 T6 + Phase 4 T17); `.claude/settings.json` (Phase 2 T6 + Phase 4 T17); `backend-bin` untracked (Phase 2 T6 working-tree delete); `agents/prove/CLAUDE.md` LOW finding (acceptable to leave; not in this plan; flag if future audit demands).

Out of scope: rewriting the frontend agent-discovery to remove hardcoded UI lists (deferred per T3 Step 9 to a follow-up feature). Adding `actionlint` and `govulncheck` to CI as gates (recommended follow-up; not blocking v0.1).

## Execution handoff

Two execution options after this plan is committed:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task (T1, T2, T3, …), review between tasks, fast iteration, cleaner blame history. Phase 4 still runs interactively for safety.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. Faster for trivial tasks, slower for tasks that need test cycles.

Which approach? — answer in the next turn before starting implementation.
