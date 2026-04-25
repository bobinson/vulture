# 0033 Finding Reference Numbers — Implementation Status

Last updated: 2026-04-17

## Summary

Stable, human-readable reference numbers (`VLT-NNNN`) are assigned on first detection of each finding lineage, rendered in API, MCP, UI, and CLI, and click-to-copy for pasting into Jira/GitHub tickets.

## Tasks

| # | Task | Status | Evidence |
|---|------|--------|----------|
| — | Model + `FormatRef()` | Done | `backend/internal/model/lineage.go:33–66` |
| — | Migration 013 + backfill | Done | `backend/migrations/013_finding_ref_numbers.sql` |
| — | SQLite repo: auto-assign + SELECT + scan | Done | `backend/internal/repository/sqlite_lineage_repo.go:65–102` |
| — | Postgres repo: auto-assign + SELECT + scan | Done | `backend/internal/repository/postgres_lineage_repo.go:34–81` |
| — | Repository tests (8) | Passing | `go test ./internal/repository/ -run TestLineageRef` → PASS |
| — | MCP enrichment + `update_status` accepts `ref` | Done | `mcp/server.py:180–238, 332–349` |
| — | Frontend: `ref_number` / `ref` on `FindingLineage` | Done | `frontend/src/lib/types.ts:186–212` |
| — | Frontend: VLT column (display) | Done | `frontend/src/components/results/FindingsTable.tsx:253–263` |
| 1 | CLI: show VLT ref in `vulture results` | Done | `cli/main.go` |
| 2 | Frontend: VLT column click-to-copy | Done | `FindingsTable.tsx` |
| 3 | Frontend: audit-ID click-to-copy (dashboard + detail) | Done | dashboard + results pages |
| 4 | Docs (this file + rollback) | Done | `docs/features/0033_finding_reference_numbers/` |
| 5 | E2E verification | Done | Playwright run on localhost:23001 |

## Quality Metrics

- Repository tests: 8/8 passing (`TestLineageRefNumber_*`).
- Go `go vet ./...`: clean on touched packages.
- Frontend `tsc --noEmit`: clean.
- Cyclomatic complexity: all modified functions under the project's ≤5 bar (no new branches added).

## Follow-ups (not in scope)

- Webhook payload does not include per-finding refs. Add a `findings: []` section to `WebhookPayload` if downstream consumers want ref-level delivery.
- The MCP `vulture_update_status` tool accepts `ref` but does not bulk-apply ref-based updates. Consider a `vulture_update_status_bulk` tool later.
