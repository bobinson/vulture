# 0041 — Implementation Status

**Branch**: tbd (recommend `feat/0041-mode-b-ci-smoke`)
**Status**: SHIPPED (v1.0 phases — local smoke green)
**Owner**: tbd
**Started**: 2026-04-28
**v1.0 ship date**: 2026-05-02
**Target v1.0** (Phases 1+2+4): ~0.5 day — **DONE**
**Target v1.1** (Phase 3): +0.25 day after stability window

## Phase summary

| Phase | Status | E2E green | v1.x | Notes |
|---|---|---|---|---|
| 1 — `scripts/mode-b-smoke.sh` runnable locally | **SHIPPED** | ✓ | v1.0 | Local smoke `bash scripts/mode-b-smoke.sh` exits 0; all 11 steps green |
| 2 — GitHub Actions workflow `mode-b-e2e.yml` | **SHIPPED** | TBD (waiting first CI run) | v1.0 | `continue-on-error: true` per plan |
| 3 — Multi-agent audit (chaos + owasp + cwe) | PLANNED | — | v1.1 | Adds a second job after stability window |
| 4 — Sub-fix: promote-to-admin step in deployment guide | **SHIPPED** | ✓ | v1.0 | `central_server_deployment.md` Step 8 now includes `psql UPDATE users SET role='admin'` |

## Bugs uncovered by the smoke (filed as follow-ups)

| # | Severity | Bug | Workaround in smoke | Real fix |
|---|---|---|---|---|
| 1 | High | CLI's `--wait` flag enters polling-only mode but audit dispatch is **lazy** — `stream_handler.go:193::runLiveAudit` is the only thing that calls `streamSvc.StreamWithContext`, and it only fires when a client opens `/api/audits/<id>/stream`. Polling never opens that stream → audit sits in `pending` forever. | Smoke drops `--wait`, uses the CLI's default streaming path which triggers dispatch. | Backend should auto-dispatch on `POST /api/audits` (decouple dispatch from streaming) OR CLI's `--wait` mode should also open the stream in the background while polling. Recommended: backend fix — programmatic clients (CI/CD) shouldn't need SSE just to trigger an audit. |
| 2 | Medium | CLI prints `Audit started: <id>` with `id` truncated to 12 chars via `truncateID(a.ID, 12)`. Programmatic consumers can't use that ID — Postgres rejects it as not-a-UUID. | Smoke queries `/api/audits?limit=1` after the CLI returns to grab the full UUID. | CLI should print the full UUID at audit-start (or expose a `--quiet --print-id` flag for programmatic use). |
| 3 | Medium | `docker-compose.yml` was missing `VULTURE_API_KEYS_ENABLED`, `VULTURE_REQUIRE_LLM`, `VULTURE_USE_LLM`, `VULTURE_WEBHOOK_SECRET` in the backend env block. The Mode-B documented bootstrap procedure relies on these. | Fixed in this commit. | (Already fixed.) |
| 4 | Medium | `central_server_deployment.md` Step 8 documented `vulture login --register` then `vulture api-key create` — but the second command fails because new users default to `member` role and the API-key endpoint requires `admin`. The documented procedure was broken on a fresh stack. | Fixed in this commit (Phase 4). | (Already fixed.) |

## Detailed task list

### Phase 1 — `mode-b-smoke.sh`

- [ ] 1.1.t1 — Generate `.env` from a script-internal template (no real secrets)
- [ ] 1.1.t2 — `docker compose up -d --wait`
- [ ] 1.1.t3 — Backend `/health` poll (curl + retry)
- [ ] 1.1.t4 — Bootstrap admin: register → psql promote → login → mint API key
- [ ] 1.1.t5 — Build CLI binary on host: `cd cli && go build -o /tmp/vulture-cli .`
- [ ] 1.1.t6 — Run `vulture scan <fixture-path> --api-key vk_xxx --server http://localhost:28080 --type chaos --wait --timeout 300s`
- [ ] 1.1.t7 — Assert exit 0; verify audit completed via API
- [ ] 1.1.t8 — `docker compose down -v`
- [ ] 1.1.t9 — Run end-to-end on local machine, fix issues until green
- [ ] 1.1.t10 — Add `make mode-b-smoke` target

### Phase 2 — GHA workflow

- [ ] 2.1.t1 — `.github/workflows/mode-b-e2e.yml` with buildx cache, 25-min timeout
- [ ] 2.1.t2 — Push branch, observe first CI run; iterate on cold-start time
- [ ] 2.1.t3 — `continue-on-error: true` initially
- [ ] 2.1.t4 — Define stability window: ~10 consecutive green runs before promoting to required

### Phase 3 — Multi-agent matrix

- [ ] 3.1.t1 — Add second job `mode-b-e2e-multi` that runs scan with `--type chaos,owasp,cwe`
- [ ] 3.1.t2 — Catches agent-router or stream-aggregator bugs

### Phase 4 — Doc fix

- [ ] 4.1.t1 — Add the psql promote step to `central_server_deployment.md` Step 8 (between register and api-key create)
- [ ] 4.1.t2 — Mention the alternative `docker compose exec backend ./vulture admin promote ...` if/when that CLI command exists; for now psql is canonical

## Cross-cutting

- [ ] CC.1 — `scripts/mode-b-smoke.sh` works on Linux, macOS bash 3.2 (no bashisms past `set -euo pipefail` + `[[ ]]`)
- [ ] CC.2 — Script accepts `--keep` flag to skip teardown for debugging
- [ ] CC.3 — Workflow logs are dumpable via `docker compose logs` step on failure
- [ ] CC.4 — No real secrets committed; `.env` template lives in the script as a heredoc
- [ ] CC.5 — Job timeout ≤ 25 min (GHA free-tier sweet spot)

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-04-28 | Skills-only smoke (`VULTURE_USE_LLM=false`); LLM-path coverage stays in feature 0039. Avoids burning cloud tokens in CI and keeps run time low. | spec |
| 2026-04-28 | Bash + GHA YAML rather than a Go test runner. The script is runnable on a developer's laptop the same way it runs in CI — no mock layer between local and CI behavior. | spec |
| 2026-04-28 | Phase 1 v1.0 keeps the full 9-agent stack up rather than adding compose profiles to bring up only `chaos`. Adding profile groups is invasive (touches every compose service definition); accept the GHA resource headroom risk and revisit if OOMs happen. | spec |
| 2026-04-28 | Promote-to-admin step in `central_server_deployment.md` is a documentation sub-fix shipped as part of this feature's Phase 4. It's a real bug uncovered by the smoke test (the documented bootstrap procedure fails on a fresh stack). | spec |
| 2026-04-28 | `continue-on-error: true` on first ship; promote to required after ~10 consecutive green runs. Avoids holding the team hostage to flaky GHA runner conditions while we gather stability data. | spec |

## Out of scope (tracked separately)

- GitLab / Jenkins / Buildkite smoke parity. The CI workflow runs only on GHA.
- Performance regression assertions.
- B + C cross-mode interaction tests (writer + viewer simultaneous).
- Failure injection (kill an agent mid-audit).
- LLM-path smoke (feature 0039 owns it).
- A `vulture admin promote-first-user` CLI subcommand. The manual psql step is fine for the Ops-VM context.
