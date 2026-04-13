# 0016 - Prove Agent Lineage Traceability

## Problem

Prove verification results are stored with `finding_id` (audit-specific MD5 hash), while the lineage system uses `fingerprint` (stable SHA256 hash) to track findings across audits. There is no join between these two systems, making cross-audit verification tracking impossible.

## Solution

Add a `fingerprint` column to `prove_results` that links each verification result to the finding's stable fingerprint. This enables querying verification history across audits for any finding tracked by lineage.

## Changes

1. **Database Migration** - Add `fingerprint TEXT` column to `prove_results` with index
2. **Model** - Add `Fingerprint` field to `ProveResult` struct
3. **Stream Handler** - Build `findingID -> fingerprint` lookup map during event consumption, enrich prove results with fingerprints, backfill in persistResults
4. **Repository Layer** - Add fingerprint to all INSERT/SELECT queries, add `GetProveResultsByFingerprint` method
5. **Service Layer** - Add `GetResultsByFingerprint` method
6. **Handler + Route** - New `GET /api/prove-results?fingerprint=...` endpoint
7. **Frontend** - Add fingerprint to ProveResult type, API method, useLineage hook enhancement, verification history UI in ProveResults component
8. **i18n** - Add verification history keys to all 6 locales

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/prove-results?fingerprint=<fp>` | Cross-audit prove results by fingerprint |
