# 0024 - Audit Report Traceability

## Overview

Adds git lifecycle tracking, cross-agent correlation, scan-to-prove linking, and report comparison to audit results.

## Goals

1. **Git lifecycle visibility** — Show comparison between audit runs (new/fixed/persistent/changed findings)
2. **Cross-agent traceability** — Surface which agents detected the same finding
3. **Scan-to-prove linkage** — Aggregate prove verification summary
4. **Report comparison** — Diff between current and previous scan

## Backend Changes

- `AuditComparison` model with delta counts and finding lists
- `CrossAgentOrigins` field on Finding model
- `GetPreviousCompletedAudit` and `ListAuditsBySourcePath` repository methods
- `/api/audits/:id/comparison` endpoint
- `deduplicateCrossAgent` modified to track origins
- Source path filter on audit list

## Frontend Changes

### New Components
- `GitContextHeader` — Branch/commit display with comparison delta badges
- `FindingLifecycleBadge` — NEW/REGRESSION pills on findings
- `CrossAgentBadge` — "Also detected by" indicator
- `ProveSummaryCard` — Verification aggregate with progress bar
- `CrossAgentSummary` — Card listing multi-agent detections
- `AuditComparisonView` — Tabbed diff view (New/Fixed/Changed/Persistent)
- `FixedFindingsList` — Collapsible list of resolved findings
- `AuditHistoryTimeline` — Horizontal timeline of audit runs

### New Hooks
- `useAuditComparison` — Fetches comparison data
- `useAuditHistory` — Fetches audit list for a source path

### Modified Components
- `AuditResults` — Integrates all new components
- `FindingsTable` — Lifecycle badges, cross-agent badges, check_id/fingerprint display
- `ProveResults` — Check ID and fingerprint display

### i18n
New keys added to all 6 locales (en, es, de, fr, ja, pt) under `comparison`, `crossAgent`, `proveSummary`, `auditHistory`, and extended `lineage`.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/audits/:id/comparison` | Get comparison with previous audit |
| GET | `/api/audits?source_path=...` | List audits for a source path |
