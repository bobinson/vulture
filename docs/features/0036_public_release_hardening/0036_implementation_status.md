# 0036 — Public Open-Source Release Hardening: Implementation Status

## Status: PHASES 1 & 2 IMPLEMENTED — Phases 3 & 4 pending user decisions

Plan authored 2026-04-25 from the six-dimension public-release audit run on `feat/0031-central-server` at commit `b8ce4b3`. Phases 1 and 2 (T1–T6) implemented inline 2026-04-25; commits `5fb0192`, `64ba347`, `438da03`, `d35c4f9`, `191be87`, `fc13042`, `fbd22c0`. HEAD-tracked size dropped from ~90 MB to ~6.7 MB. `.git` size will drop further only after Phase 4 (filter-repo).

Phase 3 (Mode-B hardening) deferred — Phase-3 fixes touch `middleware.go`, `server.go`, `auth_handler.go`, `config.go` which are all in active feature-0031 WIP currently stashed; merging there safely needs the WIP to land first. Tracked as a follow-up.

Phase 4 (history rewrite + push) **NOT executed** — destructive, irreversible after public push, requires explicit user confirmation per the plan's pre-flight checklist.

## Phase / task tracker

| Phase | Task | Description | Status | Commit |
|---|---|---|---|---|
| 1 | T1 | Third-party data attribution (NOTICE, THIRD_PARTY_LICENSES, per-data LICENSE.md, README §Attributions) | ✅ Completed | `5fb0192` |
| 1 | T2 | License-metadata reconciliation (10 pyproject.toml license fields, frontend/package.json). `mcp/pyproject.toml` not present in HEAD (in stashed WIP); apply when WIP lands. | ✅ Completed | `64ba347` |
| 1 | T3 | Documentation drift sync (README agent count 6→10, API path fix, repo slug, env vars, deployment modes, issue templates, Makefile do178c+asvs) | ✅ Completed | `438da03` |
| 1 | T4 | Missing standard files (CHANGELOG, AUTHORS, CODEOWNERS). Security-advisory contact link landed in T3 commit. | ✅ Completed | `d35c4f9` |
| 1 | T5 | Personal/internal references scrub (FutureID, Prior-incidents paragraphs, story.md, agents/owasp/PLAN.md, absolute paths in 0034/0035, CLAUDE.md complexity rule) | ✅ Completed | `191be87` |
| 2 | T6 | Untrack binaries + create 4 pointer .md files + tighten .gitignore + delete stale backend-bin + track .env.example | ✅ Completed | `fc13042`, `fbd22c0` |
| 3 | T7 | Auth/CORS/local-mode E2E tests — RED | ⬜ Optional / not started | — |
| 3 | T8 | Auth/CORS/local-mode fixes — GREEN | ⬜ Optional / not started | — |
| 3 | T9 | SQLite default-role mismatch — RED | ⬜ Optional / not started | — |
| 3 | T10 | SQLite default-role fix — GREEN | ⬜ Optional / not started | — |
| 3 | T11 | Webhook SSRF + agent-token tests — RED | ⬜ Optional / not started | — |
| 3 | T12 | Webhook SSRF + agent-token fixes — GREEN | ⬜ Optional / not started | — |
| 3 | T13 | Filesystem-browse confinement — RED | ⬜ Optional / not started | — |
| 3 | T14 | Filesystem-browse confinement — GREEN | ⬜ Optional / not started | — |
| 3 | T15 | Misc Mode-B hardening (M9, M14, M15, L1–L12, H10) | ⬜ Optional / not started | — |
| 3 | T16 | Verify SECURITY.md / CODE_OF_CONDUCT.md contact addresses | ⬜ Not started | — |
| 4 | T17 | Bare-clone backup + filter-repo (DESTRUCTIVE) | ⬜ Not started | — |
| 4 | T18 | Final pre-publish verification | ⬜ Not started | — |
| 4 | T19 | Tag v0.1.0 + finalize CHANGELOG | ⬜ Not started | — |
| 4 | T20 | Push to fresh public remote | ⬜ Not started | — |

Legend: ⬜ Not started · 🟡 In progress · ✅ Completed · ⛔ Blocked

## Pinned decisions

These must be filled in before the relevant task starts. Until pinned, the task is considered ⛔ blocked.

| Decision | Required by | Choice |
|---|---|---|
| Canonical repo slug | T3 Step 1 | **PINNED 2026-04-25 (default)**: `vulture-project/vulture` (matches existing README CI badge). User can override; if changed, also update `frontend/package.json::repository.url`, `.github/ISSUE_TEMPLATE/config.yml` (two URLs), CHANGELOG `[0.1.0]` link, AUTHORS.md handle, and CODEOWNERS team. |
| `story.md` disposition | T5 Step 3 | **PINNED 2026-04-25 (default)**: deleted. Original brief had typos and was superseded by README/docs/architecture. |
| CWE artifact strategy | T6 Step 1 | **PINNED 2026-04-25**: replace each external XML/PDF/XSD with a sibling `*.md` pointer file (upstream URL + SHA-256 + license); preserve the generated `cwe_catalog.json` and `asvs_*.json` derivatives as tracked files. |
| Phase 3 scope for v0.1 | Before T7 | **PINNED 2026-04-25 (default)**: `defer-to-v0.2`. Phase-3 fixes touch files (`middleware.go`, `server.go`, `auth_handler.go`, `config.go`) in user's stashed feature-0031 WIP; conflict-prone. The plan documents Phase 3 in detail; tracked as follow-up feature 0037 (Mode-B hardening). v0.1 README §Deployment Modes already declares "Mode B is not hardened in v0.1.0". |
| Security/Conduct contact channel | T16 Step 1 | **PINNED 2026-04-25 (default)**: GitHub Security Advisories for security reports (link added in `.github/ISSUE_TEMPLATE/config.yml`); SECURITY.md `security@vulture.dev` and CODE_OF_CONDUCT.md `conduct@vulture.dev` retained as placeholders — user must register `vulture.dev` and provision both inboxes before public push, **OR** edit those two files to point to a controlled inbox / GitHub-native flow. Flagged as `verify before push` in the Phase 4 pre-flight checklist. |

## Progress log

(Append entries chronologically as tasks land.)

- _2026-04-25_ — Plan authored. Audit findings cross-referenced. Awaiting user choice on Phase 3 scope and the four remaining pinned decisions before execution begins.
- _2026-04-25_ — Decision #3 (CWE artifact strategy) pinned: drop external XML/PDF/XSD, replace each with sibling `*.md` pointer file, preserve generated JSON derivatives.
- _2026-04-25_ — **Phases 1 & 2 implemented inline.** User WIP stashed (`stash@{0}`) before commits land; pop after `feat/0031-central-server` work merges. Default values pinned for the four open decisions (slug `vulture-project/vulture`, `story.md` deleted, Phase 3 deferred, contact = GitHub Security Advisories + retained `vulture.dev` placeholder); user can override before Phase 4. Phase 3 NOT executed (conflicts with WIP). Phase 4 NOT executed (destructive; requires explicit confirmation). HEAD-tracked size now ~6.7 MB (was ~90 MB).

## Verification checklist (sign off at end of Phase 4)

- [ ] `git grep -E 'FutureID|/home/user/src/vulture'` returns zero hits
- [ ] `git log --all -p | grep -E 'REDACTED-PG-PW|REDACTED-JWT-DEFAULT'` returns zero hits
- [ ] `git ls-files | xargs file 2>/dev/null | grep -cE 'ELF|Mach-O|PE32 executable'` returns 0
- [ ] `du -sh .git/` < 10 MB
- [ ] Tracked content size < 5 MB
- [ ] `make test` passes
- [ ] `make e2e` passes
- [ ] README renders cleanly on GitHub (badges, deployment-modes table, attributions section)
- [ ] CHANGELOG.md dated and tagged `v0.1.0`
- [ ] `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.md` visible at repo root on GitHub
- [ ] CI workflow first run on the public remote passes
- [ ] Backup tag `pre-filter-repo-backup` exists locally
- [ ] Backup bare-clone exists at `/home/user/src/vulture-pre-filter-repo.git/` with retention note

## Known follow-ups (deferred to later features)

- **Feature 0037 — Mode B hardening** (only if Phase 3 was deferred): the eight C/H code-security findings need a dedicated feature folder with the same TDD structure as Phase 3 here.
- **Frontend agent auto-discovery**: T3 Step 9 documents that v0.1 keeps hardcoded UI lists in `frontend/src/components/results/FindingsTable.tsx`; a follow-up should make UI labels and styling derive from `GET /api/agents` config schema for true auto-discovery.
- **CI gates**: add `actionlint`, `govulncheck`, `pip-audit`, `npm audit` as pinned-version CI jobs in a v0.2 feature.
- **SBOM publication**: ship `sbom.json` (Syft/cdxgen) as a release artifact in v0.2.
