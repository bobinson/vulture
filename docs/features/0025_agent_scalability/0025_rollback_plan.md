# 0025 Rollback Plan

## Risk: Low

All changes are backward compatible. No database migrations, no API contract changes.

## Rollback Steps

1. `git revert <commit-hash>` to undo all changes
2. Rebuild backend + CLI: `cd backend && go build ./cmd/vulture/`
3. Restart agents (no Python package changes needed)

## Backward Compatibility Notes

- SOC2: `config.get("clauses")` still works via fallback in agent.py
- SSDF: `config.get("practice_groups")` still works via fallback in agent.py
- `ALL_CLAUSES` and `ALL_PRACTICE_GROUPS` aliases preserved
- `CLAUSE_MAP` and `PRACTICE_GROUP_MAP` aliases preserved
- Frontend `AgentInfo.status` field is optional (`omitempty` in Go, `?` in TS)
- `use_llm` parameter defaults to `None` (falls back to env var)
