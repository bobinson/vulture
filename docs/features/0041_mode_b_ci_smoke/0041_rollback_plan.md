# 0041 — Rollback Plan

This feature ships only test infrastructure (a CI workflow and a bash
script). It changes no application code paths. Rollback is correspondingly
trivial.

## Pre-flight

Note which phases are live in the deployment you're rolling back. The four
phases are:

1. `scripts/mode-b-smoke.sh`
2. `.github/workflows/mode-b-e2e.yml`
3. (v1.1) multi-agent matrix variant
4. `docs/guides/central_server_deployment.md` Step 8 promote-to-admin
   addition

## Rollback by phase (newest first)

### Phase 4 — Documentation sub-fix

- Revert the `central_server_deployment.md` change.
- Operators who started using the documented psql step will continue to
  succeed (it's a real, working step); reverting only removes it from
  the published procedure. They can re-derive it by reading the deployed
  schema.

### Phase 3 — Multi-agent matrix

- Delete the second job (or matrix dimension) from `mode-b-e2e.yml`.
- Phase 1 + 2 keep working independently.

### Phase 2 — GHA workflow

- Delete `.github/workflows/mode-b-e2e.yml`.
- The smoke script in `scripts/mode-b-smoke.sh` continues to work for
  local development and ad-hoc verification.

### Phase 1 — Local smoke script

- Delete `scripts/mode-b-smoke.sh`.
- Remove `make mode-b-smoke` target from `Makefile` (if added).

### Full rollback

```bash
git revert <0041 commits in reverse order>
```

No DB schema changes, no application binaries changed, no env-var
contracts altered. Pure additive.

## What this rollback does NOT do

- Doesn't touch any of the underlying application code (cli, backend,
  agents, frontend).
- Doesn't touch other CI workflows (`ci.yml`, `migrations.yml`).
- Doesn't change the canonical Mode-B deployment procedure beyond the
  one-line psql step in Phase 4.

## Smoke checks after rollback

```bash
# 1) Existing CI still runs
git push origin <branch>
# → ci.yml + migrations.yml jobs trigger as before; mode-b-e2e.yml gone

# 2) Local development workflows unaffected
./scripts/vulture.sh dev skills
# → still works

# 3) Customer-facing Mode-B deployment procedure
# Read docs/guides/central_server_deployment.md — should match what's
# expected by the docs/guides/ci_integration.md examples.
```

If any of these is broken, the rollback was incomplete or unrelated work
landed alongside it.

## Post-rollback gap

After this rollback, the original audit gap returns:

- No CI signal that `docker compose up -d` produces a working Mode-B
  stack on a fresh checkout.
- No CI signal that the documented bootstrap procedure works.
- No CI signal that `vulture scan --api-key X --server Y` succeeds against
  a real backend.

If you rolled back because the workflow was flaky, prefer fixing the
flake over rolling back — the gap costs more than the flake.
