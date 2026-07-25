# 0018 — Full CWE v4.19.1 Rollback Plan

## Rollback Steps

1. **Remove catalog_detector skill**: Delete `agents/cwe/cwe_agent/skills/catalog_detector.py`
2. **Revert skills/__init__.py**: Remove `catalog_generic` from SKILL_MAP and SKILL_TOOLS
3. **Revert config.py**: Remove `catalog_generic` from ALL_CATEGORIES, revert description
4. **Revert agent.py**: Restore previous INSTRUCTIONS without self-learning protocol
5. **Revert catalog.py**: Remove new helper functions (get_static_detectable, build_catalog_context, etc.)
6. **Revert memory_client.py**: Remove _cosine_similarity, _similarity, _prove_confidence_boost, conditional LEARN lines
7. **Restore catalog data**: Revert `cwe_catalog.json` to previous version (523KB)
8. **Revert test_skills.py**: Change category count back to 15
9. **Remove new test files**: Delete test_catalog_detector.py, test_mmr_enhanced.py

## Risk Assessment

- **Low risk**: All changes are additive. Existing 15 skills are unchanged.
- **No schema changes**: No database migrations required.
- **No API changes**: Agent endpoints unchanged.
- **Backward compatible**: Frontend auto-discovers skills via /info endpoint.
