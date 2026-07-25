# 0026 Rollback Plan

## Risk: Medium

New database tables (pipelines, discover_results) and a new agent service. No changes to existing table schemas.

## Rollback Steps

1. `git revert <commit-hash>` to undo all changes
2. Drop new tables: `DROP TABLE IF EXISTS pipelines; DROP TABLE IF EXISTS discover_results;`
3. Remove `agent-discover` from docker-compose.yml
4. Rebuild backend: `cd backend && go build ./cmd/vulture/`
5. Rebuild CLI: `cd cli && go build .`
6. Restart services

## Backward Compatibility Notes

- Existing `POST /api/audits` endpoint: unchanged, backward compatible
- Existing `vulture scan` and `vulture prove` CLI commands: unchanged
- Prove agent: `config["site_map"]` field is optional; when absent, falls back to internal discovery (existing behavior)
- New `POST /api/pipelines` endpoint is additive — removing it does not affect existing audit functionality
- `agents/prove/prove_agent/discovery.py` shimmed to re-export from shared; rollback restores original implementation
- `AllAgents` registry entry for "discover" can be removed by reverting config.go change
- `ScanAgentTypes()` exclusion of "discover" reverts to only excluding "prove"
