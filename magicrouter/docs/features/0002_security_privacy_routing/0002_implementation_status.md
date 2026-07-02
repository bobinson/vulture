# 0002 — security/privacy/injection routing: implementation status

**Status**: DESIGN — research complete, plan written, no implementation code yet.
**Last updated**: 2026-07-02
**Depends on**: 0001 (router core, also DESIGN).

## Done

- [x] Deep-research run on security/privacy/prompt-injection routing (2026-07-02, 109 agents,
      6 angles, 26 sources). Originally interrupted by a session token limit mid-verify, then
      **resumed and completed cleanly (109/109, 0 errors)**: the attacks-on-routers,
      injection-detector, and privacy-attack-surface clusters cleared **3-0**; **1 claim
      refuted** (PRISM DP-budget-inside-router, 1-2, both passes). Report:
      `research/0002_research_report.md`; per-claim verdicts: `research/verified_verdicts.json`;
      claims: `research/claims_by_source.json`; run log: `research/deep_research_run.json`.
- [x] Synthesis: extended decision model, new ModelCard/Request/Decision fields, and the
      detect/decide/enforce boundary table (the direct answer to "what fits a pure router vs
      the gateway").
- [x] Feature docs: implementation plan, this status doc, rollback plan.

## Key conclusions carried into the plan

- **Security must be explicit, not emergent** — a cost/quality-only router routes jailbreaks to
  the softest (cheapest) models (✅ 2504.07113).
- **The router is an attack surface** — denial-of-wallet via black-box adversarial suffixes
  (✅ R2A 2604.15022, ✅ confounder gadgets 2501.01818); perplexity filtering fails; static
  budget caps only throttle. Defenses that fit a pure router: cumulative-spend predicates,
  escalation rate-limits, suffix-resistant difficulty, escalation logging.
- **Injection detection cannot live in the router** — it needs 100M+ params or an LLM (✅ 3-0
  via 2501.15145 PromptShield + 2505.03574 PromptGuard-2) and is evadable/base-rate-fragile
  (📄 2606.22659). The router consumes a guard flag and carries independently-benchmarked
  robustness scores; it may run only cheap partial pattern predicates (unicode-smuggling),
  honestly labeled.
- **Privacy beyond static tiers** — entity-level (NER) sensitivity + execution-mode routing
  (cloud/split/local) is a *deterministic* decision (✅ PRISM gate); the DP/pseudonymization/MPC
  *mechanisms* are gateway work (⚠️ the "DP budget inside the router" claim was refuted 1-2).

## Next

- [ ] Resolve open questions (robustness-score source; hosted/sidecar form).
- [ ] Phase 1: extend contracts (backward-compatible defaults) with E2E tests.
- [ ] Phases 2–5 as gated in the plan; the safe-by-construction invariants are the contract.

## Verification log

| Date | Phase | Gate | Result |
|---|---|---|---|
| — | — | — | — |

## Known caveats carried from research

- The verification pass was **completed on resume** (109/109, 0 errors): 35 claims verified,
  most 3-0; only 1 refuted (PRISM DP-budget-inside-router, 1-2, both passes). Residual 📄 claims
  (JailbreakBench, MLCommons, CycloneDX, 2606.22659, 2510.01529, gateway docs) fell outside the
  top-ranked verifier budget or (2510.01529) were not re-fetched on resume — descriptive
  primary facts, low adversarial risk; a targeted third pass could harden them.
- Regulatory specifics (EU AI Act, GDPR articles) are the thinnest part of the corpus — the
  standards sources support auditability + posture scoring, not statute-level requirements.
  Docs must not overclaim there.
- Per-model robustness scores are not yet broadly available named (MLCommons v0.5 is anonymized/
  open-weight-only; v1.0 planned Q1 2026) — Phase 2's floor ships as mechanism, populated as
  benchmarks publish.
