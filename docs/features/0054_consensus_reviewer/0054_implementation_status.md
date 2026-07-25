# 0054 — Implementation status

**Last updated**: 2026-05-29
**State**: PLAN — LLD drafted; pre-review

## Checklist

- [x] LLD doc
- [ ] Cross-cutting review across 7 axes (correctness, security, reliability, maintenance, chaos, DRY, performance)
- [ ] Review findings incorporated (add changelog table when received)
- [ ] Phase 0 — Schema migrations (Postgres + SQLite)
- [ ] Phase 1 — Plugin contract v1.1 (coverage manifests + scan_completed event)
- [ ] Phase 2 — Canonical lineage (canonical_findings + canonical_lineages tables + backfill)
- [ ] Phase 3 — Consensus service (groupCrossAgent + competent silence + voter integration)
- [ ] Phase 4 — LLM-on-conflict reviewer agent (`agents/reviewer/`)
- [ ] Phase 5 — Trust ledger (rolling 90-day window + cron recompute)
- [ ] Phase 6 — Frontend (ConsensusBadge + canonical view + trust dashboard)
- [ ] Phase 7 — Compliance evidence endpoint
- [ ] Phase 8 — Feature flag + staging rollout

## Decisions log

| Date | Decision | Reason |
|---|---|---|
| 2026-05-29 | 5-line line-number bucket for canonical key | Absorbs off-by-N noise across detectors; small enough to avoid merging genuinely different vulns. Made tunable via `VULTURE_CANONICAL_LINE_BUCKET` |
| 2026-05-29 | Competent-silence weight caps at -0.30 (mirrors L3 +0.30 cap) | Symmetric; conservative; aligned with feature 0045 weight envelope |
| 2026-05-29 | Trust modifier never applied to plugin's primary finding weight, only to `cross_agent` + `competent_silence` participation | Avoids censorship-as-governance; emission stays the plugin's own decision |
| 2026-05-29 | Plugin contract v1.1 strictly additive; v1.0 plugins keep working | Mandatory for any contract bump; treated as advisory tier |
| 2026-05-29 | Reviewer LLM opt-in via `VULTURE_REVIEWER_LLM_ENABLED` (default off in v1) | Cost containment; staged rollout |
| 2026-05-29 | Reviewer model can be separate from main audit LLM | Lets ops use cheap-fast model for review without affecting scan quality |
| 2026-05-29 | Canonical lineage additive — per-agent lineage rows preserved | Migration safety; UI promotes canonical but old rows still queryable |

## Open questions

See "Open questions" section at the bottom of `0054_implementation_plan.md`. Resolve before kicking off Phase 0.

## Risks tracker

(See Risk register in plan. Update this table as risks are observed in implementation.)

| # | Risk | Status | Mitigation in place |
|---|---|---|---|
| 1 | Coverage manifests inaccurate | open | empirical validation; trust ledger flags drift |
| 2 | Correlated detectors over-counted | open | `provenance_class` field + dedup step |
| 3 | LLM cost runaway | open | per-audit token budget + opt-in flag |
| 4 | Voter weight calibration wrong | open | conservative caps; 30-day observation window |
| 5 | Migration FK type mismatch | open | covered by integration test contract |
| 6 | Trust ledger flip-flop on small samples | open | minimum-sample gate (≥30 findings); modifier formula uses agreement_rate - 0.5 |
| 7 | Plugin downgrade-as-censorship | mitigated | modifier never applied to primary emission weight |
| 8 | Reviewer LLM prompt injection via code | mitigated | strict-JSON parsing; system prompt warns; output schema-validated |
| 9 | Canonical key collision | open | 5-line bucket conservative; UI split path post-v1 |

## Notes

- Plan reviewed once internally; cross-cutting review pending (7-axis pass).
- Total budget estimate: 14–20 engineer-days for one engineer; parallelisable to ~10 days across two engineers (Phase 4 + Phase 6 split).
- Depends on no in-flight breaking changes to: plugin contract, voter signature, lineage schema. Confirm before Phase 0.
