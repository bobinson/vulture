# magicrouter — Policy-First LLM Routing Library

## Project Overview

magicrouter is a **standalone Python library** for LLM routing: given a routing request, a
pool of models, and a policy context, it returns a **routing decision** — which model should
handle the call, ordered fallbacks, and the auditable reasons. Selection is driven by token
cost but constrained by capability, data protection, and sovereignty:

```
maximize   E[quality(m, t)] − λ · cost(m, t)      # soft: cost-quality dial (RouteLLM α / xRouter λ)
subject to m ∈ Eligible(policy)                    # hard: sovereignty, residency, PII tier,
                                                   #       compliance, context fit, health
```

It lives inside the vulture repo (vulture is consumer #1) but is **standalone by
construction**: it must never import anything from vulture (`shared/`, `backend/`, …), and
all its data contracts are JSON-serializable so it can later become a separate package or a
polyglot HTTP sidecar without a rewrite.

## Core Principles (non-negotiable)

1. **Decision, not execution.** `router.route(request)` is pure — no I/O, no network, no
   credentials. The CALLER executes the chosen model (via LiteLLM, raw SDKs, anything) and
   walks `decision.fallbacks` on failure.
2. **Zero vulture imports.** Enforced mechanically by an import-isolation test in CI.
3. **Hard constraints before soft objectives.** Sovereignty/compliance/PII are eligibility
   predicates that filter the pool BEFORE any cost-quality optimization. A model in the
   wrong jurisdiction is disqualified no matter how cheap or capable.
4. **Deterministic policy classification.** Regex/domain rules, never an LLM — "sending data
   to an LLM to decide if it's too sensitive to send to an LLM is a circular problem."
5. **Auditability is a feature.** Every `RoutingDecision` carries `reasons`: which predicate
   excluded which model. This library serves compliance tooling.
6. **Prove it beats Best-Single.** Any optimizer change must be benchmarked against "always
   use the single best eligible model" on the cost-quality frontier. Most published routers
   fail this bar; don't ship complexity that doesn't earn its keep.

## Scope Locks (what magicrouter is NOT)

- **Not a gateway** — LiteLLM/OpenRouter do execution, failover, budgets, observability.
- **Not a coordinator** — Trinity/Conductor-style task decomposition and role assignment
  (arXiv 2512.04695, 2512.04388) belong in the harness above.
- **Not the smarts** — the `QualityEstimator` interface ships here; real estimators (e.g.
  vulture's pgvector-prior-findings difficulty signal) are consumer-supplied.

## Architecture

```
magicrouter/
  README.md                # design overview
  CLAUDE.md                # this file
  docs/features/           # feature docs (vulture conventions, see below)
  magicrouter/             # the package (planned; see 0001 plan)
    contracts.py           # RoutingRequest, PolicyContext, ModelCard, RoutingDecision
    registry.py            # ModelRegistry (static config default)
    policy.py              # PolicyFilter + built-in predicates
    estimator.py           # QualityEstimator interface + heuristic default
    cost.py                # CostModel (token estimate × per-1M pricing)
    health.py              # HealthSignal interface
    router.py              # route(): eligibility filter → optimizer → RoutingDecision
  tests/
    e2e/                   # business-logic tests (written FIRST)
    unit/
```

Pipeline: **Stage 1 eligibility filter** (deterministic predicates over
`(ModelCard, PolicyContext)`) → **Stage 2 cost-quality optimizer** (pluggable quality
estimate + α threshold → cheapest model clearing the bar; remaining eligible models ordered
into the fallback/escalation chain) → **RoutingDecision**. PII tiers: low/normal → full
pool; high → cloud with `pseudonymize=true` flag; critical → local-only or blocked.

## Research Context

The design is grounded in two deep-research runs, each persisted under its feature's
`research/` folder with the synthesized report, the raw claims, and the run log. Read the
reports first — they are confidence-marked (✅ verified 3-0 / 📄 primary-unverified / ⚠️ refuted).

### Feature 0001 — cost/capability/sovereignty (2026-06-30: 107 agents, 24 sources, 25 verified)

Under `docs/features/0001_router_core/research/`:

- **`0001_research_report.md`** — the synthesized, cited report (READ THIS FIRST). Covers:
  taxonomy (pre-generation routing vs. post-generation cascades; WHEN/WHAT/HOW framework),
  core techniques (RouteLLM α-threshold, cascade routing as constrained linear optimization,
  MixLLM contextual bandits, xRouter's `R = R_binary × (K − λC)` reward, FrugalGPT),
  benchmarks (RouterBench, LLMRouterBench, the Best-Single bar), sovereignty/PII-aware
  routing patterns, the two seed orchestration papers (TRINITY, Conductor), and the mapping
  onto vulture. Claims are confidence-marked (✅ verified / 📄 primary-unverified / ⚠️ refuted).
- **`0001_design_feedback.md`** — the standalone-library feasibility verdict: the
  decision-vs-execution principle, the library/vulture boundary table, language choice,
  in-repo-first strategy, honest risks, phased path.
- **`research/sources/`** — raw primary-source extracts (RouteLLM, RouterBench, cascade
  routing, seed papers). Reference material only; excluded from vulture self-audits via
  the repo `.vultureignore`.
- **`deep_research_run.json`** — the research run log (angles, verification votes, failures).

Key 0001 takeaways that bind design decisions:
- The **quality estimator is the make-or-break component** (cascade-routing finding) and is
  irreducibly domain-specific → interface here, smarts in consumers.
- **Sovereignty is the white space**: academic routers optimize cost-quality only; compliance
  lives in gateway practice, divorced from learned routing. Unifying them — with hard
  eligibility constraints, per-task capability profiles, and a domain difficulty estimator —
  is magicrouter's novel contribution.
- The **α threshold** (RouteLLM) is the operator's cost dial; expose it as a knob.

### Feature 0002 — security / privacy / prompt injection (2026-07-02: 109 agents, 26 sources, 25 verified)

Under `docs/features/0002_security_privacy_routing/research/` (`0002_research_report.md`,
`claims_by_source.json`, `deep_research_run.json`). Key takeaways that bind design decisions:
- **Security must be explicit, not emergent.** A cost/quality-only router routes jailbreak
  attempts to the *weakest* (cheapest, least-robust) models (✅ 2504.07113). Jailbreak/injection
  robustness become distinct numeric ModelCard attributes with a hard robustness-floor predicate.
- **The router is itself an attack surface** (denial-of-wallet): black-box adversarial suffixes
  force expensive-model escalation (✅ R2A 2604.15022, ✅ confounder gadgets 2501.01818).
  Perplexity filtering fails; budget caps only throttle. In-scope defenses are deterministic:
  per-tenant/session cumulative-spend predicates, escalation rate-limits, suffix-resistant
  difficulty, escalation logging in `reasons`.
- **Injection detection cannot live in the router** — it is a model-inference workload (100M+
  params or an LLM) and is evadable/base-rate-fragile (📄 2501.15145, 2606.22659, 2510.01529).
  The router *consumes* a guard flag and carries independently-benchmarked robustness scores
  (never vendor self-reports); it may run only cheap *partial* pattern predicates
  (unicode-smuggling), honestly labeled.
- **Privacy beyond static tiers**: entity-level (NER) sensitivity + execution-mode routing
  (cloud/split/local) is a deterministic decision (✅ PRISM); the DP/pseudonymization/MPC
  *mechanisms* are gateway work (⚠️ "DP budget inside the router" was refuted 1-2).
- **The organizing seam: detect / decide / enforce.** Guard = detect (gateway); magicrouter =
  decide (library); gateway = enforce (execute). This is the direct answer to "what belongs in a
  pure decision library vs the execution gateway" — see the boundary table in the 0002 report §7.

## Development Workflow (MANDATORY — inherited from vulture)

1. **Think** — understand the problem fully before writing any code.
2. **Plan** — design the approach, identify affected components, consider edge cases.
3. **Write E2E business logic tests FIRST** — expected behavior as E2E tests before any
   implementation code exists.
4. **Implement** — write the code to make the E2E tests pass.
5. **Verify** — run the full E2E suite; re-run after EVERY code change.

**CRITICAL INVARIANT: NEVER modify E2E business logic tests to make code pass.** Tests
define the business contract. If tests fail, fix the implementation.

## Planning and Documentation

Feature docs follow vulture's conventions exactly: each feature gets a folder
`docs/features/<4digits>_<feature_name>/` containing `<4digits>_implementation_plan.md`,
`<4digits>_implementation_status.md`, and `<4digits>_rollback_plan.md`. Numbering starts at
0001 (this project's own sequence, independent of vulture's). Current features:

| # | Feature | Status |
|---|---|---|
| 0001 | `0001_router_core` — contracts, eligibility filter, cost-quality optimizer | DESIGN |
| 0002 | `0002_security_privacy_routing` — security/privacy as first-class dimensions; injection & denial-of-wallet at the routing layer | DESIGN |

Vulture-side integration work (the `routing_adapter.py`, `VULTURE_ROUTER_*` env knobs,
`run_combined_audit()` wiring) is documented in **vulture's** `docs/features/` sequence,
not here.

## Coding Conventions

- Python 3.12+, type hints on all functions.
- No runtime dependencies beyond the standard library where practical; the library must stay
  import-light (it is a decision engine, not a client).
- Tests: `pytest`; E2E in `tests/e2e/`, unit in `tests/unit/`.
- `ruff` for linting, `radon` for complexity (target < 10, per vulture's quality rules).
- DRY; low cyclomatic complexity; all contracts JSON-serializable.
