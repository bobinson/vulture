# 0036 — Public Open-Source Release Hardening: Implementation Status

## Status: NOT STARTED

Plan authored 2026-04-25 from the six-dimension public-release audit run on `feat/0031-central-server` at commit `b8ce4b3`. No tasks have been executed yet.

## Phase / task tracker

| Phase | Task | Description | Status | Commit |
|---|---|---|---|---|
| 1 | T1 | Third-party data attribution (NOTICE, THIRD_PARTY_LICENSES, per-data LICENSE.md, README §Attributions) | ⬜ Not started | — |
| 1 | T2 | License-metadata reconciliation (mcp/pyproject MIT→Apache, 11 pyproject.toml license fields, frontend/package.json) | ⬜ Not started | — |
| 1 | T3 | Documentation drift sync (README agent count 6→10, API path fix, repo slug, env vars, deployment modes, CLAUDE.md complexity) | ⬜ Not started | — |
| 1 | T4 | Missing standard files (CHANGELOG, security-report contact link, AUTHORS, CODEOWNERS) | ⬜ Not started | — |
| 1 | T5 | Personal/internal references scrub (FutureID, Prior-incidents paragraphs, story.md, agents/owasp/PLAN.md, absolute paths) | ⬜ Not started | — |
| 2 | T6 | Untrack binaries + bloat; tighten .gitignore | ⬜ Not started | — |
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
| Canonical repo slug | T3 Step 1 | _____ (e.g., `vulture-project/vulture`) |
| `story.md` disposition | T5 Step 3 | _____ (`delete` \| `move-to-history`) |
| CWE artifact strategy | T6 Step 1 | **PINNED 2026-04-25**: replace each external XML/PDF/XSD with a sibling `*.md` pointer file (upstream URL + SHA-256 + license); preserve the generated `cwe_catalog.json` and `asvs_*.json` derivatives as tracked files. |
| Phase 3 scope for v0.1 | Before T7 | _____ (`complete-phase-3` \| `defer-to-v0.2`) |
| Security/Conduct contact channel | T16 Step 1 | _____ (`a` \| `b` \| `c`) |

## Progress log

(Append entries chronologically as tasks land.)

- _2026-04-25_ — Plan authored. Audit findings cross-referenced. Awaiting user choice on Phase 3 scope and the four remaining pinned decisions before execution begins.
- _2026-04-25_ — Decision #3 (CWE artifact strategy) pinned: drop external XML/PDF/XSD, replace each with sibling `*.md` pointer file, preserve generated JSON derivatives.

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
