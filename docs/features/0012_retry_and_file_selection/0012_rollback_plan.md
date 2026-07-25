# 0012 — Rollback Plan

## Risk Level: Low

Both features are purely additive with optional parameters. No database, API, or configuration changes.

## Rollback Steps

1. Revert the commit containing these changes
2. No database migration needed
3. No API changes to revert
4. No configuration changes needed

## Impact Assessment

- `retry_skill` is called via `pool.submit` — removing it reverts to direct `fn` calls
- `_build_source_context` `skill_findings` param defaults to `None` — removing it restores alphabetical ordering
- `is_entry_or_config` is only used by `_prioritize_files` — removing both is self-contained
- LLM jitter change (0.25→0.5) can be reverted independently
