# 0011 — Rollback Plan

## Rollback Steps

1. Revert `ProveResults.tsx` to original (no lineage, no copy, no description sections)
2. Revert `FindingsTable.tsx` to inline lineage state management
3. Remove `frontend/src/hooks/useLineage.ts`
4. Remove `proveResultToMarkdown` from `markdown.ts`
5. Remove new i18n keys from all 6 locale files
6. Revert `AuditResults.tsx` ProveResults invocation (remove auditId prop)

## Risk Assessment

- Low risk: All changes are frontend-only, no backend or database schema changes
- No data migration required
- Existing FindingsTable functionality preserved via hook extraction (same behavior)
