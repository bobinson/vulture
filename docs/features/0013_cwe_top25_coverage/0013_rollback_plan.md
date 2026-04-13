# 0013 - CWE Top 25 Full Coverage - Rollback Plan

## Rollback Strategy

All changes are additive - they add new check functions and wire existing patterns. No existing behavior was modified.

### To rollback:

1. Revert the 7 skill files to remove new `_check_*` functions and pattern definitions
2. Revert `_analyze_file` calls in each skill to remove new check function calls
3. Revert `agent.py` INSTRUCTIONS to original CWE list
4. Revert `config.py` description
5. Revert `SKILLS.md` to original documentation
6. Remove new tests from `test_cwe_audit.py` and `test_skills.py`

### Risk Assessment

- **Low risk**: All changes are additive; no existing patterns or logic were modified
- **No breaking changes**: The 79 original tests continue to pass unchanged
- **Backward compatible**: No API changes, no config schema changes
