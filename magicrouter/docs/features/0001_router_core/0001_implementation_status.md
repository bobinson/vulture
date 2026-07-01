# 0001 — magicrouter router core: implementation status

**Status**: DESIGN — research complete, plan written, no implementation code yet.
**Last updated**: 2026-07-02

## Done

- [x] Deep-research run on LLM routing/orchestration methodologies (2026-06-30, 107 agents,
      6 research angles, 24 sources fetched, 118 claims extracted, 25 adversarially verified).
      Report: `research/0001_research_report.md`; run log: `research/deep_research_run.json`;
      primary source extracts (RouteLLM, RouterBench, cascade routing, seed papers):
      `research/sources/`.
- [x] Standalone-library feasibility analysis ("decision, not execution" principle,
      library/vulture boundary, phased plan): `research/0001_design_feedback.md`.
- [x] Grounding pass over existing vulture code: `provider.py` (registry/cost/fallback data),
      `audit_runner.py` (budget, tiering 0057/0059), `cooldown.py`/health (0039),
      0049 stage-router naming distinction.
- [x] `magicrouter/` project created with `README.md` (design overview + decision model +
      contracts + interfaces), `CLAUDE.md`, and this feature-docs tree (vulture conventions).
- [x] Feature docs: implementation plan, this status doc, rollback plan.

## Next

- [ ] Confirm the two open questions in the plan (consumer languages; compliance-vs-cost
      priority ordering) — they reorder Phases 2/3 but do not block Phase 1.
- [ ] Phase 1: E2E tests for the decision contract, then contracts/registry/router skeleton;
      adapter-equivalence tests against vulture's `provider.py`.
- [ ] Phase 2: eligibility filter (policy predicates) + vulture wiring behind
      `VULTURE_ROUTER_ENABLED` (default off) — vulture side gets its own feature doc in
      vulture's `docs/features/` when it starts.
- [ ] Phase 3: difficulty-estimator prototype + Best-Single benchmark on the CWE corpus
      (hard investment gate for the optimizer half).

## Verification log

*(populated as phases land; each phase's gate result recorded here)*

| Date | Phase | Gate | Result |
|---|---|---|---|
| — | — | — | — |

## Known caveats carried from research

- ~15 report claims are 📄 *primary-source-but-unverified* (verification pass hit a session
  token limit mid-run); only 2 claims were genuinely refuted (marked ⚠️ in the report).
  Hardening the 📄 claims (esp. the "routers rarely beat Best-Single" bar, xRouter, MixLLM)
  by resuming the verification pass is optional follow-up work.
- The sovereignty/compliance evidence base is industry practice + blogs, not peer-reviewed
  literature — that thinness is precisely the opportunity, but treat the specific patterns
  (four-tier PII classification, pseudonymization middle path) as engineering guidance,
  not settled science.
