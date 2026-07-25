# 0015 - CWE 4.19.1 Full Coverage - Rollback Plan

## Rollback Steps

1. Remove 5 new skill files from `agents/cwe/cwe_agent/skills/`
2. Revert `skills/__init__.py` to remove 5 new imports and registrations
3. Revert `config.py` ALL_CATEGORIES to 10 entries
4. Revert `agent.py` INSTRUCTIONS string
5. Remove `agents/cwe/cwe_agent/catalog.py` and `data/` directory
6. Remove `scripts/extract_cwe_catalog.py`
7. Revert pattern additions in existing 10 skill files
8. Rollback DB migration 006 (DROP columns, DROP table)
9. Revert Go memory_repo.go MMR changes
10. Revert Python memory_client.py MMR changes

## Risk Assessment

- Low risk: All new skill categories are additive
- Existing 10 categories remain backward-compatible
- DB migration is additive (new columns, new table) — rollback is safe
