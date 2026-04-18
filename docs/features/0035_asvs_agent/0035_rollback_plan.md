# 0035 — ASVS 5.0.0 Audit Agent: Rollback Plan

## Scope

This plan describes how to roll back the ASVS agent cleanly. The agent is **strictly additive**: no existing agent, backend, or frontend behavior changes as a result of this feature. Rollback is therefore a matter of removing files and reverting coordinated edits.

## Rollback triggers

Initiate rollback if any of:
- Production detection precision collapses (post-deploy false-positive rate > 20% on calibration corpus).
- Upstream ASVS 5.0.0 JSON is pulled or licensing changes (OWASP license change blocks redistribution).
- Backend registry fan-out causes timeouts on `/api/audits` for existing audits (performance regression).
- ASVS agent docker container consistently OOMs at import time with the 500 KB catalog (unexpected memory footprint).

## Rollback sequence — safe and reversible

1. **Disable agent discovery** (fastest mitigation, no code change):
   ```bash
   # In production .env or orchestration config:
   unset VULTURE_AGENT_ASVS_URL
   docker compose up -d backend
   ```
   The backend's agent discovery skips agents without a configured URL. ASVS audits become unavailable; all other agents unaffected.

2. **Stop the container**:
   ```bash
   docker compose stop agent-asvs
   docker compose rm -f agent-asvs
   ```

3. **Full git revert** (if decisions 1 and 2 prove insufficient):
   ```bash
   # Revert the 6 feature 0035 commits as a single range
   git revert --no-commit <first-0035-commit>..<last-0035-commit>
   git commit -m "revert: feature 0035 ASVS agent (rollback per rollback_plan.md)"
   ```
   Or, if merged as a PR:
   ```bash
   git revert -m 1 <merge-commit-hash>
   ```

4. **Verify rollback**:
   - `backend/pkg/agentregistry/registry.go` has no `asvs` entry.
   - `docker-compose.yml` has no `agent-asvs` service.
   - `agents/asvs/` directory is gone.
   - `GET /api/agents` returns only the original agent set.
   - All existing agent audits still succeed (full regression test suite).

## Data considerations

- **No schema changes** — the ASVS agent emits findings into the existing `findings` table with `category: "ASVS-V..."`. Existing records persist after rollback (no DB migration needed). They simply become orphan findings that no live agent claims.
- **Memory system** — `audit_memories` rows created by the ASVS agent have ASVS-prefixed categories. After rollback, these persist as read-only memory; semantic-search results may surface them (harmless). Optional cleanup:
  ```sql
  DELETE FROM audit_memories WHERE category LIKE 'ASVS-%';
  ```
  Only run this after confirming no downstream consumer depends on the data.
- **No migrations to revert** — this feature ships without SQL migrations.

## Vendored data

`agents/asvs/asvs_agent/data/asvs_source.json` is the upstream ASVS v5.0.0 JSON, redistributed under its original license (Creative Commons Attribution-ShareAlike 4.0 per the ASVS repository's LICENSE file). Rollback removes it from the repository; it remains available from https://github.com/OWASP/ASVS for future use.

## Partial rollback — per task

Each of the 6 tasks is independently revertible. Most common partial rollbacks:

| Revert | Effect |
|---|---|
| Task 6 only | Disables E2E test + verifier. Agent still runs. |
| Tasks 5-6 | Disables LLM catalog injection. Skill phase still runs. |
| Tasks 3-6 (keep 1-2) | Agent scaffolding remains but no skills registered — backend `/api/agents/asvs/info` returns an empty categories list. Useful for regression investigation without removing catalog data. |
| All (Tasks 1-6) | Full removal. |

## Verification after rollback

```bash
# Backend agent registry is back to pre-0035 state.
cd backend && go test ./pkg/agentregistry/...

# docker-compose up still boots all pre-0035 agents.
docker compose up -d
docker compose ps | grep -v asvs | grep -c "Up" # == N where N = pre-0035 agent count

# No ASVS references remain in the repo.
git grep -l "asvs\|ASVS" | grep -v "docs/features/0035" | wc -l
# Expected: 0
```

## Residual risk

None identified. The agent is isolated behind a discovery URL; absence of the URL disables the agent entirely without affecting other components.
