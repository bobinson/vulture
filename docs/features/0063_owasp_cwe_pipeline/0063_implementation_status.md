# 0063 OWASP-over-CWE Pipeline — Implementation Status

**Status:** IMPLEMENTED (2026-07-07) — all tasks landed; UI reload gaps closed; full platform suite green.
**Owner:** bobinson
**Plan:** `0063_implementation_plan.md`
**Rollback:** `0063_rollback_plan.md`

## Summary

Convert the OWASP agent from an independent regex scanner into a categorizer that
maps CWE-agent findings onto OWASP Top 10 categories (edition-versioned), and make
the CWE agent a prerequisite. Closes CWE detection gaps so every OWASP category in
both the 2021 and 2025 editions has at least one detectable CWE.

## Task checklist (revised after audit — single-stream design, no DB change)

| # | Task | Status | Verified by |
|---|------|--------|-------------|
| 1 | Edition mapping data files + registry (2021, 2025) | ☐ | JSON validation script |
| 2 | Mapping engine (CWE→category, edition loader) | ☐ | `test_owasp_mapping.py` |
| 3 | Coverage manifest builder (+ cwe_stage_status) | ☐ | `test_owasp_coverage_report.py` |
| 4 | Emitter: `result_event(extra=...)` | ☐ | `test_event_emitter_extra.py` |
| 5 | OWASP agent rewrite (scanner→mapper) | ☐ | `test_owasp_mapper.py` |
| 6 | OWASP no-detection guardrail + E2E (native transport) | ☐ | `test_no_detection.py`, `test_owasp_audit.py` |
| 7 | Registry: mark `owasp` Optional | ☐ | `registry_test.go` |
| 8 | Extract `agui.ParseDeltaFindings` (DRY) | ☐ | `finding_parse_test.go` |
| 9 | Backend: deferred OWASP phase + CWE-finding tap + prereq auto-inject | ☐ | `stream_service_owasp_test.go` |
| 10 | Measure 2025 coverage + CI floor test (derived, not hardcoded) | ☐ | `test_owasp_coverage_floor.py` |
| 11 | CWE agent: CWE-799 (A04), file-scoped | ☐ | `test_resource_rate_limit.py` |
| 12 | CWE agent: measured 2025 gaps (conditional on #10) | ☐ | `test_2025_gaps.py` |
| 13 | 0050-vs-editions reconciliation guard | ☐ | `test_0050_reconciliation.py` |
| 14 | Frontend + translator passthrough for coverage manifest | ☐ | `OwaspCoverage.test.tsx`, `translator_owasp_test.go` |
| 15 | Docs, /info, full-suite verification | ☐ | full test run |

## Key design change from the pre-audit draft

The first draft added `owasp`/`cwe` as new **pipeline stages** and new DB columns. Audit
finding #1 showed that path is secondary — the common flow fans scanners out concurrently
via `stream_service`, so OWASP would still race CWE and get no priors. The revised design:
mark `owasp` **Optional** (out of the concurrent scan set) and run it as a **deferred phase
in the same audit stream**, tapping CWE-category findings and passing them via the existing
`prior_findings` transport. **No pipeline stages, no DB schema change, no migration.**

## Baseline (pre-feature) facts captured during planning

- CWE agent currently emits **92 distinct CWE ids** (grep of `agents/cwe/cwe_agent/skills/*.py`).
- CWE-agent coverage of OWASP 2021 categories (mapped→detectable): A01 8/34, A02 6/29,
  A03 6/33, A04 4/40, A05 3/20, A06 2/3, A07 5/22, A08 3/10, A09 2/4, A10 1/1.
  Every 2021 category already has ≥1 detectable CWE; depth is the gap Tasks 6–7 raise.
- OWASP agent findings currently carry **no CWE id**; downstream mapping exists only in
  `backend/internal/cwe/` (feature 0050, single representative CWE per category).
- The `prior_findings` transport is already plumbed end to end
  (`stream_service.go` `priorByAgent` → `agent_proxy_service.go` `prior_findings`
  → `sse_app.py` `req.prior_findings` → agent `run_audit`).

## Open decisions / risks

- **Multi-category CWEs:** the engine emits one OWASP finding per matched category. 2021
  membership is near-disjoint; do NOT assume a specific overlap (the earlier CWE-611-in-A03
  claim was wrong — 611 is A05-only in 2021). Confirm the findings table shows both views
  acceptably during Task 14.
- **Both taxonomies in one audit:** OWASP findings now coexist with raw CWE findings under
  the same audit id (single-stream design). This is intentional (two views of one issue);
  the UI can filter by `owasp_category_id`. If double-counting in the score is undesirable,
  a follow-up can tag mapped findings as a separate rollup — out of scope here.
- **2025 CWE membership** must be fetched from official 2025 pages at build time (Task 1);
  only category names + likely-central CWEs are pre-filled in the plan.
- **2025 detection gaps** are unknown until Task 10 measures them; Tasks 11–12 are scoped to
  what that measurement flags (the agent already emits several 2025-relevant CWEs).
- **0050 reconciliation** (Task 13): the representative CWEs may be broad parents not present
  in the data-driven membership; resolve the assertion form during execution and record here.

## Verification log (2026-07-07)

- **2025 CWE lists**: fetched from the official owasp.org/Top10/2025/ category
  pages and embedded verbatim (counts match OWASP's published figures:
  A01=40, A02=16, A04=32, A09=5, A10=24).
- **shared** (`agents/shared`): 944 → 955 unit tests pass (added mapping,
  coverage, emitter-extra, 0050-reconciliation).
- **owasp** (`agents/owasp`): 20 tests pass (mapper, no-detection guardrail,
  E2E over native prior_findings). All 10 detection skills + 2 obsolete test
  files removed.
- **cwe** (`agents/cwe`): 601 unit tests pass (added CWE-799 file-scoped +
  coverage floor for both editions). VERIFIED_CWES.md regenerated (CWE-799 in
  DECLARED-ONLY; N=12 unchanged).
- **backend**: `go build ./...`, `go vet ./...` clean; every package green
  incl. new `stream_service_owasp_test.go`, `finding_parse_test.go`,
  `translator_owasp_test.go`, registry `TestOwasp_DeferredMapper`. CLI module
  green.
- **frontend**: `tsc --noEmit` clean; 345 vitest tests pass incl. new
  `OwaspCoverage.test.tsx`; 6 locales updated + valid JSON.

### Measured coverage (derived from CWE skills; every category ≥1 detectable)

| Category depth (found/mapped) | 2021 | 2025 |
|---|---|---|
| A01 | 8/34 | 10/40 |
| A02 | 6/29 | 3/16 |
| A03 | 6/33 | 1/6 |
| A04 | 5/40 | 6/32 |
| A05 | 3/20 | 6/37 |
| A06 | 2/3 | 4/39 |
| A07 | 5/22 | 5/36 |
| A08 | 3/10 | 4/14 |
| A09 | 2/4 | 2/5 |
| A10 | 1/1 | 8/24 |

No 2025 detector gaps were found (Task 12 was unnecessary — the floor passed
for 2025 with the existing skills plus CWE-799).

## UI reload/persistence gaps — closed (2026-07-07)

A post-implementation UI review found the coverage manifest was **live-stream-only**:
it showed while an audit ran but vanished on reload / when viewing a completed audit,
because (a) it was never persisted, (b) `replayCompletedAudit` synthesized snapshots
from findings+score only, and (c) the stream hook is disabled for terminal audits.
The component was also a bare `<table>` off the design system. Both closed:

- **Gap 1 — persistence (survives reload).**
  - `model.Audit.OwaspCoverage json.RawMessage` (opaque blob; edition data stays
    single-sourced in Python).
  - Captured from the OWASP result snapshot in `drainResult`
    (`extractOwaspCoverage`), threaded to `completeAuditWithError`.
  - Persisted: migration `023_audit_owasp_coverage.sql` (Postgres) + SQLite inline
    `ALTER`; read/write in both repos. Served via `GET /api/audits/:id`.
  - Re-emitted in `replayCompletedAudit` for the attach/replay path.
  - Frontend prefers the live manifest, falls back to `audit.owasp_coverage`
    (`AuditResults.tsx`: `coverage = owaspCoverage ?? audit?.owasp_coverage`).
  - Tests: `sqlite_owasp_coverage_test.go` (round-trip + absent), `stream_owasp_coverage_test.go` (extractor).
- **Gap 2 — design system + i18n.** `OwaspCoverage.tsx` rewritten to the `card`
  idiom (icon, `text-muted`/`success` palette, responsive grid) using
  `useTranslation`; two new keys added to all 6 locales. Test expanded to 5.

**R7 corrected:** previously only the live path was closed; the reload/replay path
is now persisted + re-emitted + REST-served, so the manifest is durable.

## Committed pipeline regression test (2026-07-07)

Added a cross-agent integration test so the OWASP agent is verified against real
code, not just hand-authored fixtures. Because the OWASP agent is a pure mapper
(never scans source), the faithful test runs the FULL pipeline:

- **Fixture** `agents/owasp/tests/fixtures/vulnerable_flask_app/app.py` — a
  deliberately-vulnerable Flask app (`# ruff: noqa`) with 6 planted CWEs across
  distinct classes (SQLi 89, cmd 78, weak-hash 328, secret 798, SSRF 918,
  deser 502). Lives under `fixtures/` (a scanner SKIP_DIR) so the repo's own
  audits never flag it.
  The fixture is engineered so its planted + incidental CWEs cover ALL TEN
  OWASP categories in BOTH editions (see per-category table below). A
  `requirements.txt` (`requests==2.31.0` known-vulnerable pin → CWE-937;
  `pyyaml` unpinned → CWE-1104) supplies the dependency/supply-chain signal.
- **Test** `agents/owasp/tests/e2e/test_owasp_over_cwe_integration.py` — copies
  the whole fixture dir into a clean `tmp_path` (the committed path under
  `tests/fixtures/` is skipped by the CWE scanner's SKIP_DIRS/`_TEST_DIRS`),
  runs the CWE `SKILL_MAP` to get REAL findings, feeds them to `run_audit`, and
  asserts the mapped OWASP categories == ALL TEN for BOTH editions (findings AND
  the `owasp_coverage` manifest), with `cwe_stage_status=completed`. Guarded
  with `pytest.importorskip("cwe_agent")` (skips in an isolated owasp-only
  install; runs in CI, which installs every agent and runs `pytest owasp/tests/`).
- **Full Top-10 coverage, verified end to end** (committed fixture, both editions):

  | Cat | 2021 found/mapped | 2025 found/mapped |
  |-----|------|------|
  | A01 | 3/34 | 4/40 | A02 | 1/29 | 1/16 | A03 | 3/33 | 1/6 | A04 | 2/40 | 1/32 | A05 | 1/20 | 3/37 |
  | A06 | 2/3 | 2/39 | A07 | 3/22 | 3/36 | A08 | 1/10 | 1/14 | A09 | 1/4 | 1/5 | A10 | 1/1 | 2/24 |

  Both editions: **10/10** categories covered.
- **Robustness**: a separate sanity assertion checks CWE detection produced the
  planted CWEs (distinguishes a detection regression from a mapping regression).
- **Adversarially verified**: breaking the mapper (`map_cwe → []`) empties the
  findings; dropping a single signal (e.g. the XXE CWE-611) makes the affected
  category vanish and the all-10 assertion FAIL — the test is not vacuously
  green. OWASP suite: 20 → 24 tests (CI-equivalent run green).

## Audit findings R1–R11 disposition

- R1 reconciliation path fixed (`parents[4]`), no silent skip. R2 bad-edition
  guarded (fallback + notice). R3 malformed-prior defaults. R4 cwe_stage_status
  derived positively (saw-result → completed; else failed/absent). R5 forwarding
  loop uses ctx.Done() select. R6 verified: `Optional` only removes from the
  default scan set (still launched/listed/URL-wired). R7 translator passthrough
  test added; live snapshot carries `owasp_coverage`. R8 non-issue
  (compute_score guards zero) — defensive `max(...,1)` used anyway. R9 floor test
  measures before prescribing. R10 detected set derived, not hardcoded; the
  no-detection guardrail asserts via imports. R11 importer sweep done (only tests
  referenced old skills). Plus R15 (file-scoped rate-limit), R17 (single assign),
  R18 (UI prereq note).
