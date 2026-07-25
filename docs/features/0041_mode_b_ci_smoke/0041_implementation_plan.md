# 0041 — Mode B + Mode D end-to-end CI smoke test

**Author**: tbd
**Status**: PLANNED
**Created**: 2026-04-28

## Problem

There is no CI signal that the Mode B + Mode D pair actually works end-to-end.

Audit pass on 2026-04-28 found:

- `.github/workflows/ci.yml` runs `go test ./...` without `-tags=e2e`, so all
  11 files in `backend/test/e2e/*.go` (including the 322-line
  `ci_workflow_test.go` that specifically tests the API-key + audit flow)
  never run in CI.
- Even if `-tags=e2e` were added, those tests use `httptest.Server` — they
  validate the API surface but don't exercise `docker compose up`,
  cross-container DNS, healthcheck ordering, env-var propagation, or volume
  mounts. The actual failures we hit on 2026-04-27 (entrypoint mount silently
  skipping migrations, FK type mismatch aborting init, broken venv, Go 1.22
  toolchain mismatch) were all container-layer issues that httptest cannot
  see.
- No CI job runs `docker compose up -d` against any branch. The closest is
  `ci.yml`'s `docker-build` job, which only does `docker compose build` — it
  verifies images compile but doesn't bring services up or issue a single
  HTTP request to a live stack.
- The `vulture scan` CLI binary (the Mode-D client) has zero coverage in
  CI. It exists, ships, and is documented in `docs/guides/ci_integration.md`,
  but nothing tests it against a real Mode-B server.

If a customer follows `docs/guides/central_server_deployment.md` step-by-step
on a fresh VM, our CI provides no signal that it'll succeed.

## Goals

1. **Catch container-wiring bugs at commit time.** A new GitHub Actions
   workflow brings up the full Mode-B stack via `docker compose up -d`,
   waits for backend health, bootstraps an admin + API key, runs
   `vulture scan` against the running stack, and asserts the audit
   completes.
2. **Mirror the documented operator procedure.** The smoke test follows the
   same steps an operator runs from `central_server_deployment.md` — if
   those steps are documented but broken, CI catches it.
3. **Reuse for local development.** The workflow's logic lives in a
   `scripts/mode-b-smoke.sh` script that's runnable on a developer's
   machine, not embedded YAML that only GitHub can run.
4. **Minimum cost.** Skills-only audit (no LLM key required); minimal source
   tarball (small file set); a single audit type to keep job time low.
5. **Doesn't replace the existing CI.** Runs as a separate workflow; failure
   here doesn't block PRs from merging *yet* (start as `continue-on-error`,
   promote to required after a stability window).

## Non-goals

- **Multi-mode stress testing.** Concurrent Mode-B writes + Mode-C reads,
  agent failure injection, etc., are out of scope. Single-stack happy path.
- **LLM provider testing.** The smoke runs with `VULTURE_USE_LLM=false`.
  LLM-path coverage stays in feature 0039's tests.
- **Cross-CI-system parity.** The workflow runs on GitHub Actions only.
  GitLab/Jenkins/Buildkite parity is documented in
  `docs/guides/ci_integration.md` but not exercised in this CI.
- **Performance regression detection.** The job has a generous timeout but
  doesn't measure startup latency or audit duration as an assertion.
- **Replacing the existing `migrations.yml` workflow** (feature 0040). That
  one tests the migration runner in isolation; this one tests the full
  stack. Both stay.

## Design

### File layout

```
.github/workflows/mode-b-e2e.yml             # NEW
scripts/mode-b-smoke.sh                      # NEW, runnable locally too
docs/features/0041_mode_b_ci_smoke/          # NEW
  0041_implementation_plan.md                # this file
  0041_implementation_status.md
  0041_rollback_plan.md
docs/guides/central_server_deployment.md     # updated (sub-fix: promote-to-admin step)
```

### `scripts/mode-b-smoke.sh`

The runnable test. Idempotent enough to re-run locally. Steps:

```
1. Generate .env from a fixed template (no secrets — test-only values):
     VULTURE_DB_PASSWORD=REDACTED-SMOKE-PW
     VULTURE_JWT_SECRET=ci-mode-b-jwt-secret
     VULTURE_API_KEYS_ENABLED=true
     VULTURE_LOCAL_MODE=false
     VULTURE_USE_LLM=false               # skills-only; no LLM keys needed
     VULTURE_DB_DSN=postgres://vulture:REDACTED-SMOKE-PW@postgres:25432/vulture?sslmode=disable
     # plus the agent URLs and ports the existing compose expects
2. docker compose up -d --wait
   (--wait blocks until all healthchecks pass; bounded by job timeout.)
3. Health check: curl http://localhost:28080/health → expect 200, status="healthy".
4. Bootstrap:
   a. POST /api/auth/register {admin@ci-test.local, REDACTED-SMOKE-PW, "Admin"}
   b. Promote that user to admin via psql:
        docker compose exec -T postgres psql -U vulture -d vulture \
          -c "UPDATE users SET role='admin' WHERE email='admin@ci-test.local'"
      (This is the documented manual step from
      central_server_deployment.md; the smoke test mirrors it exactly.)
   c. POST /api/auth/login → capture JWT.
   d. POST /api/api-keys with JWT → capture vk_xxx.
5. Build the CLI binary (it's already built in the docker-build job, but we
   need it on the runner host outside the container):
     cd cli && go build -o /tmp/vulture-cli .
6. Run a tiny scan against a fixture in the repo itself — e.g.
   `agents/shared/shared/llm/health.py` — small enough to finish quickly:
     /tmp/vulture-cli scan ./agents/shared/shared/llm/ \
       --api-key vk_xxx \
       --server http://localhost:28080 \
       --type chaos \
       --wait \
       --timeout 300s
7. Assert exit code 0 (or 1 if --exit-on hits — for the smoke test we
   don't pass --exit-on so the audit just completes).
8. Verify via API: GET /api/audits/<id> with the API key, assert
   status=completed.
9. docker compose down -v.
```

### `.github/workflows/mode-b-e2e.yml`

Thin wrapper around the bash script. Steps:

```yaml
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  workflow_dispatch:

jobs:
  mode-b-e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.24" }
      - uses: docker/setup-buildx-action@v3
      - name: Run Mode-B smoke
        run: bash scripts/mode-b-smoke.sh
      - name: Dump compose logs on failure
        if: failure()
        run: docker compose logs --tail=200
      - name: Tear down
        if: always()
        run: docker compose down -v --remove-orphans
```

### Resource constraints

A standard GHA runner: 7 GB RAM, 14 GB disk, 2 cores. Our compose stack:
- 1 Postgres (pgvector/pgvector:pg17) — ~250 MB
- 9 agent services (FastAPI + uvicorn + LiteLLM + Anthropic SDK) — ~150-300 MB each → ~2-3 GB total
- 1 backend (Go) — ~50 MB
- 1 frontend (Vite preview or built) — ~150 MB

Total ~3-4 GB with all 9 agents up. Tight but feasible.

**Resource fix v1.0**: bring up only the agents needed for the smoke
audit (`chaos` is enough — single audit type). The compose file already
has per-agent service definitions; profile groups would let us select.
If profiles are too invasive to add now, a leaner v1.0 brings up the
full stack and accepts the headroom risk.

**Image build cache**: Docker buildx with `cache-from`/`cache-to=type=gha`
keeps subsequent runs fast. Cold first run will take ~5 minutes; warm
runs ~1-2 minutes for the build phase.

### Test source for the audit

The simplest test-source is a directory inside the same repo, e.g. a
single file like `agents/shared/shared/llm/health.py`. The Mode-D CLI
supports `vulture scan <local-path>` (it tarballs and uploads). A
hand-picked file with known patterns (e.g., a deliberate `time.sleep(5)`
in a test helper) gives the chaos agent a finding to discover.

## Phases

### Phase 1 — `mode-b-smoke.sh` runnable locally

- [ ] 1.1.t1 — Write the script with the 9 steps above.
- [ ] 1.1.t2 — Run it locally against a fresh checkout; iterate until green.
- [ ] 1.1.t3 — Document local invocation in `scripts/README.md` (or as a
  Makefile target `make mode-b-smoke`).

### Phase 2 — GitHub Actions workflow

- [ ] 2.1.t1 — Write `.github/workflows/mode-b-e2e.yml`.
- [ ] 2.1.t2 — Push branch, observe first CI run.
- [ ] 2.1.t3 — Iterate on resource issues (profile groups if needed).
- [ ] 2.1.t4 — Run with `continue-on-error: true` for ~2 weeks of
  stability data before promoting to required.

### Phase 3 — Add `--type chaos` parity check

- [ ] 3.1.t1 — Once the chaos-only smoke is green, add a second job (or a
  matrix dimension) that runs a multi-agent audit (chaos + owasp + cwe).
  Catches agent-router bugs.

### Phase 4 — Sub-fix: promote-to-admin step in deployment guide

- [ ] 4.1.t1 — `docs/guides/central_server_deployment.md` Step 8 currently
  describes `vulture login --register` then `vulture api-key create`. The
  second step fails because newly-registered users are role=member, not
  admin. The smoke test reveals this mismatch. Fix by adding a step
  between them: `docker compose exec postgres psql ... UPDATE users SET
  role='admin' WHERE email=...`.
- [ ] 4.1.t2 — Open question: should we add `vulture admin promote-first-user`
  to the CLI? Skipped for now; manual step is fine for an Ops-VM context.

## Tests

The workflow IS the test. Asserts:

- `docker compose up -d --wait` exits 0 (all healthchecks pass).
- `curl http://localhost:28080/health` returns 200 + `"healthy"`.
- API-key bootstrap returns a `vk_xxx` token.
- `vulture scan` exits 0.
- `GET /api/audits/<id>` returns `status=completed`.

Failure of any step fails the job; logs are dumped via `docker compose
logs` for post-mortem.

## Risks

| Risk | Mitigation |
|---|---|
| GHA runner OOM with all 9 agents | Phase 1 v1.0 brings up minimal stack; full 9 agents wait for Phase 3 |
| Cold image-build time exceeds 25-minute timeout | Cache via buildx GHA cache; first warm run typically 1-2 min |
| Agent flakiness causes intermittent CI red | Start with `continue-on-error: true` to gather stability data |
| `vulture scan` against localhost CLI hits permission/networking edge case | Same mitigation as #3 — gather data before making it required |
| Skipping LLM means we're not testing the LLM path | By design; feature 0039 owns LLM-path coverage |
| CLI build needs Go 1.24 toolchain (we just shipped this fix) | Workflow uses `setup-go@v5` with `go-version: "1.24"`; consistent with existing CI |
| User email collision on rerun | Each run uses a fresh container + fresh DB volume; collisions not possible |

## Out-of-scope follow-ups

- GitLab CI / Jenkins / Buildkite parity smoke tests.
- Performance regression assertions (audit duration, startup latency).
- Cross-mode integration test (B + C running against same Postgres).
- Failure injection (kill an agent mid-audit, assert backend recovers).
- LLM-path smoke (covered by feature 0039 already, plus would require
  burning cloud LLM tokens in CI).
