# 0031 Centralized Audit Server — Implementation Status

**Status: COMPLETE.** All 15 tasks implemented; backend unit + E2E test suites green (`go test ./...` and `go test -tags=e2e ./test/e2e/`).

| Task | Component | Status | Notes |
|------|-----------|--------|-------|
| 1  | APIKey model + migration 011 | **Done** | 3/3 model tests pass; migration added to both Postgres (`011_api_keys.sql`) and SQLite (`migrateAddColumns`) |
| 2  | APIKey repository | **Done** | 12/12 tests pass (6 sqlite + 6 mock); Postgres impl compiles, integration test stubbed |
| 3  | APIKey service | **Done** | 8/8 tests pass |
| 4  | APIKey CRUD handlers | **Done** | 10/10 tests pass; enforces `Role == "admin"` per endpoint (no RequireAdmin middleware exists) |
| 5  | Auth middleware API-key path | **Done** | 5/5 tests pass; `vk_` prefix is cheap discriminator; no fallthrough to JWT on failure |
| 6  | Webhook model + service + dispatch | **Done** | 8/8 webhook service tests pass; wired into `persistResults`; HMAC-SHA256; 3-retry backoff |
| 7  | Per-source git credentials | **Done** | 19/19 gitutil tests pass; supports token + ssh_key; scrubs credentials from error messages; never persisted |
| 8  | Per-run source directory isolation | **Done** | 3/3 tests pass; opt-in via `VULTURE_CLEANUP_RUN_DIRS=true` |
| 9  | Rate limit per API key | **Done** | `RateLimitByKey(apiKeyRPM, principalKeyFunc, ...)` wired at `server.go:265` on `/api/audits`; `VULTURE_APIKEY_RPM` env override (default 60) |
| 10 | CLI flags (--api-key, --wait, --output, --exit-on, --webhook, --ref, --git-credentials) | **Done** | Implemented in `cli/main.go::parseCIFlag` and consumed in `cmdScan`/`cmdProve`. `--wait` uses `pollUntilDone` and exits with `computeExitCode(audit, exit-on)` |
| 11 | CLI `api-key` subcommand | **Done** | `cli/apikey.go` — `create <name>`, `list`, `revoke <id>` |
| 12 | `.github/workflow-examples/vulture-audit.yml` | **Done** | GitHub Actions template |
| 13 | `docs/guides/ci_integration.md` | **Done** | GHA + GitLab + Jenkins examples |
| 14 | `docs/guides/central_server_deployment.md` | **Done** | VM + TLS + bootstrap admin + first API key |
| 14a | CLAUDE.md deployment matrix | **Done** | A/B/C/D modes documented |
| 15 | E2E test (simulated CI workflow) | **Done** | `backend/test/e2e/ci_workflow_test.go` — 3 tests: bootstrap+use+revoke API key happy path; APIKeysEnabled=false → 404 (dev-local backwards compat); unknown vk_ key → 401. Tests run with `LocalMode=false` to exercise the real auth path. |

## Backwards compat

- Dev-local mode (`docker compose up` with no env vars): **unchanged**. API-key routes are not registered when `VULTURE_API_KEYS_ENABLED` is unset; verified by `TestCIWorkflow_APIKeyRoutesGatedByEnvFlag`.
- Backend `go build ./...`: **clean** after all changes.
- Backend full test matrix (verified 2026-04-25 at HEAD `e7f2458`):
  - `go test ./...` — all green.
  - `go test -tags=e2e ./test/e2e/` — all green, including the 3 new CI-workflow E2E tests.
- Pre-existing failures called out in earlier status (auth role default, source ingest URL scheme, agent count) all resolve as of this commit.

## Summary of new test coverage added

| Package | New tests | Total pass |
|---------|-----------|------------|
| `model/` | 3 (APIKey) + source.GitCredentials.Mask tests | all pass |
| `repository/` | 12 (APIKey shared suite) | all pass |
| `service/` | 8 (APIKeyService) + 8 (webhook) + 3 (source paths) | all pass |
| `handler/` | 10 (APIKey handler) + 5 (AuthMiddleware apikey path) | all pass |
| `pkg/gitutil/` | 19 total after expansion (embed/scrub/ssh) | all pass |

## How to use what's built

### Bootstrapping an API key without the CLI subcommand

Until Task 11 ships, bootstrap via curl:

```bash
# 1. Log in as admin (get JWT)
TOKEN=$(curl -sX POST http://localhost:28080/api/auth/local-session | jq -r .token)

# 2. Enable API keys — edit .env:
echo "VULTURE_API_KEYS_ENABLED=true" >> .env
docker compose restart backend

# 3. Create a key
curl -sX POST http://localhost:28080/api/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-github-actions"}' | jq

# → returns {"id":"...","key":"vk_xxx...", ...}  (key shown once)

# 4. Use it from CI:
curl -sX POST http://localhost:28080/api/audits \
  -H "Authorization: Bearer vk_xxx..." \
  -H "Content-Type: application/json" \
  -d '{"source_id":"...","types":["cwe"],"webhook_url":"https://callback.example.com/hook"}'
```

### Submitting audits with webhook callback

Add `webhook_url` to the audit POST body. The server will POST the completion payload (with HMAC signature in `X-Vulture-Signature` header) to that URL with 3 retry attempts.

### Supplying git credentials per-source

Add `git_credentials` to the source POST body:

```json
{
  "type": "git",
  "url": "https://github.com/org/private-repo.git",
  "ref": "main",
  "git_credentials": {
    "type": "token",
    "value": "ghp_xxx..."
  }
}
```

Credentials are used for the clone and discarded — never persisted, never logged.
