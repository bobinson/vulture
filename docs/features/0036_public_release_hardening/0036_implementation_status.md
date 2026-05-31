# 0036 — Public Open-Source Release Hardening: Implementation Status

## Status: PHASES 1, 2, 3 IMPLEMENTED — Phase 4 pending user authorisation

Plan authored 2026-04-25 from the six-dimension public-release audit run on `feat/0031-central-server` at commit `b8ce4b3`. Phases 1 and 2 (T1–T6) implemented inline 2026-04-25. Phase 3 (T7–T16) implemented 2026-05-31 across commits `b5860c4` (T7-T8), `4677196` (T9-T10), `35e1c79` (T11-T12), `89325b5` (T13-T14), `528d96a` (T15), `f9ef47f` (T16).

Phase 4 (history rewrite + push) **NOT executed** — destructive, irreversible after public push, requires explicit user confirmation per the plan's pre-flight checklist.

### Phase 3 (Mode-B hardening) — completed 2026-05-31

| Task | Finding | Resolution | Tests | Commit |
|---|---|---|---|---|
| T7-T8 | C1 admin seed | Already gated at server.go:283 on cfg.LocalMode (prior work) | existing auth E2E | `b5860c4` |
| T7-T8 | C3 wildcard CORS | New addCORSWithAllowlist driven by VULTURE_CORS_ALLOWED_ORIGINS; never `*`-with-credentials; X-XSS-Protection dropped (L2); CSP `default-src 'self'` added (L3); HSTS conditional on TLS (L1); "ISO 26262" header comment fixed (L4) | TestCORSAllowlistBehavior 4 cases | `b5860c4` |
| T7-T8 | H7 LocalSession host check | New isLoopbackHost defence-in-depth Host check; handler returns 403 on non-loopback Host even when LocalMode is on | TestIsLoopbackHost 13 cases | `b5860c4` |
| T7-T8 | H9 LocalMode non-loopback bind | New Config.ListenAddr resolved by config.Load; validateLoopbackForLocalMode refuses startup on non-loopback addr in LocalMode | TestLocalModeRefusesNonLoopbackBind 9 cases + TestIsLoopbackBind 8 cases | `b5860c4` |
| T9-T10 | C2 SQLite default role | sqlite_repo users.role DEFAULT 'admin' → 'member' + CHECK constraint matching Postgres | TestSQLiteUserDefaultRoleIsMember + TestSQLiteUserRoleCheckConstraint | `4677196` |
| T11-T12 | Webhook SSRF | New ValidateWebhookURL (scheme allowlist + LookupIP gate against loopback/private/link-local/unspecified); wired at audit creation + delivery time; DNS-rebinder protection rejects any internal IP in the resolved set | webhook_ssrf_test.go 5 test groups | `35e1c79` |
| T11-T12 | Agent-token Mode-B refusal | validateAgentTokenForNonLocalMode refuses startup when LocalMode=false AND VULTURE_AGENT_TOKEN unset | TestValidateAgentTokenForNonLocalMode 4 cases | `35e1c79` |
| T13-T14 | Filesystem-browse confinement | New cfg.SourceRoot + validateBrowsePathWithRoot enforces canonical-prefix-inside-root; rejects literal `..`; symlink-escape rejected; maxBrowseEntries=1000 cap | filesystem_confinement_test.go 5 tests | `89325b5` |
| T15 | M9 JWT min length | validateJWTSecret refuses non-LocalMode secret < 32 bytes (RFC 7518 §3.2 HS256 floor) | TestJWTSecretMinLength 6 cases | `528d96a` |
| T15 | M14 SQLite api_keys migration | Left as-is — inline migrateAddColumns path is working code; extraction is style not security | n/a | n/a |
| T15 | M15 git creds in argv | embedToken (URL-embedded creds) deprecated; production Clone now uses writeAskpassScript + GIT_ASKPASS env. Token lives in 0700 script file only, not argv | askpass_test.go 4 tests | `528d96a` |
| T15 | L1 HSTS conditional | Wrapped in `if r.TLS != nil || X-Forwarded-Proto==https` (delivered in T8) | TestAddCORS_SetsSecurityHeaders | `b5860c4` |
| T15 | L2 X-XSS-Protection drop | Header removed (delivered in T8) | TestAddCORS_SetsSecurityHeaders | `b5860c4` |
| T15 | L3 CSP | Added `Content-Security-Policy: default-src 'self'` (delivered in T8) | TestAddCORS_SetsSecurityHeaders | `b5860c4` |
| T15 | L4 misleading comment | "ISO 26262 compliance" comment removed during T8 middleware rewrite | n/a | `b5860c4` |
| T15 | H10 action SHA pinning | All 10 distinct GitHub Actions resolved to current v* tag SHA via GitHub API; rewritten in-place with `# v<N>` comments across all .github/workflows/*.yml | mechanical | `528d96a` |
| T16 | SECURITY contact channel | Already GitHub-native at SECURITY.md:18 — no change | n/a | n/a |
| T16 | CoC contact channel | conduct@vulture.dev → GitHub private security advisory + maintainer DM. Plus migrated 6 JSON Schema $ids from vulture.dev to raw GitHub URIs and migrated test fixtures to @example.com | frontend tsc + auth.test.tsx 7/7 | `f9ef47f` |

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
