# 0011 — Enhanced Prove Results UI

## Overview

Enhance the ProveResults component with lineage integration, full finding descriptions, copy-as-issue functionality, and fix tracking.

## Changes

| File | Change |
|------|--------|
| `frontend/src/lib/markdown.ts` | Add `proveResultToMarkdown()` |
| `frontend/src/hooks/useLineage.ts` | New shared lineage hook (DRY extract) |
| `frontend/src/components/results/ProveResults.tsx` | Lineage, description, copy, fix tracking |
| `frontend/src/components/results/FindingsTable.tsx` | Refactor to use `useLineage` hook |
| `frontend/src/pages/AuditResults.tsx` | Pass `auditId` to ProveResults |
| `frontend/src/i18n/locales/*.json` | Add 4 new i18n keys |
| `frontend/e2e/prove-results.spec.ts` | E2E tests |

## Implementation Steps

1. Write E2E tests first
2. Add `proveResultToMarkdown()` to markdown.ts
3. Extract `useLineage` hook from FindingsTable
4. Add i18n keys to all 6 locales
5. Enhance ProveResults.tsx
6. Pass auditId in AuditResults.tsx
7. Refactor FindingsTable to use useLineage hook
8. Verify E2E tests pass
