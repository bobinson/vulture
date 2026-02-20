# 009 Finding Lifecycle Traceability — Implementation Plan

## Overview

End-to-end finding traceability: discovery → status management → fix detection → timeline UI.

## Components

1. **Database**: New `finding_lineage` and `lineage_events` tables; git metadata on sources; fingerprints on findings
2. **Git Capture**: `gitutil.GetInfo()` captures branch, commit hash, remote URL during source ingestion
3. **Fingerprint**: SHA-256 of normalized title|filePath|category|agentType for cross-audit identity
4. **Lineage Repository**: CRUD for lineage records and events (Postgres + SQLite)
5. **Lineage Service**: Fix detection algorithm, status management, event logging
6. **API Endpoints**: REST CRUD for lineage, audit-scoped lineage, timeline events
7. **Frontend**: Status badges in FindingsTable, FindingTimeline component, git context display
8. **i18n**: Lineage keys in all 6 locales

## Fix Detection Algorithm

On audit completion:
1. Build set of current finding fingerprints
2. For each: upsert lineage (new → "detected" event; existing fixed → "regression")
3. For each open lineage NOT in current fingerprints → "fixed" event
4. Skip "accepted_risk" and "false_positive" statuses (user decisions preserved)

## API Surface

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/lineage` | List by source_path + status |
| GET | `/api/lineage/:id` | Get with events |
| PATCH | `/api/lineage/:id` | Update status, notes, ticket |
| GET | `/api/lineage/:id/timeline` | Events only |
| GET | `/api/audits/:id/lineage` | Lineage for audit |
