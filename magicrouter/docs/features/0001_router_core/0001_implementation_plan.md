# 0001 — magicrouter router core: contracts, eligibility filter, cost-quality optimizer

**Author**: bobinson
**Status**: PLAN (design phase — research complete, awaiting scope confirmation)
**Created**: 2026-07-02
**Research basis**: `research/0001_research_report.md` (deep-research run, 107 agents,
24 sources, 25 adversarially-verified claims) + `research/0001_design_feedback.md`
(standalone-library feasibility verdict). Primary source extracts in `research/sources/`.
**Related vulture features**: 0039 (unified LLM health), 0049 (stage router — *agent*-level
routing, distinct layer), 0057/0059 (tiering / `llm_tier3`). The vulture-side integration
(adapter + env knobs) will get its own feature number in vulture's `docs/features/` when
implementation starts; this plan is the library side.

## Goal

Build **magicrouter**: a standalone Python library that, given a routing request, a pool of
models, and a policy context, returns a **routing decision** — which model to call, ordered
fallbacks, and the reasons. Constrained multi-objective selection:

```
maximize   E[quality(m, t)] − λ · cost(m, t)      # soft objective
subject to m ∈ Eligible(policy)                    # hard constraints: sovereignty, residency,
                                                   # PII tier, compliance, context fit, health
```

Vulture is consumer #1 (the agents' LLM phase routes through it); the library is
standalone-*ready* (zero vulture imports, JSON-serializable contracts) but not
standalone-*published* until a second consumer is real.

## Why

1. **Compliance is a correctness requirement for vulture.** We audit customer source code —
   sensitive IP, often residency-bound. "EU customer code never leaves EU-hosted models" or
   "air-gapped customer → local Ollama only" must be an enforced eligibility filter, not a
   convention. No existing tool unifies this with learned cost-quality routing (the research's
   central finding: academic routers ignore policy; policy gateways don't learn).
2. **Token cost.** The optimizer half picks the cheapest model clearing a quality bar
   (RouteLLM α-threshold pattern), with cascade escalation bounded by budget.
3. **The pieces already exist, scattered in vulture** — `provider.py` model
   resolution/context windows/costs/fallbacks, cooldown/health (0039), USD budget
   (`audit_runner.py`), tier heuristics (0057/0059). This is extraction + unification,
   not greenfield.

## Non-goals (scope locks)

- **No execution.** The router returns decisions; callers execute (via LiteLLM or anything
  else). No credentials, no retries, no provider quirks inside the library.
- **No gateway.** LiteLLM remains the enforcement/failover/observability plane.
- **No coordinator.** Trinity/Conductor-style task decomposition (seed papers arXiv
  2512.04695, 2512.04388) stays in the harness. Model selection only.
- **No learned estimator inside the library.** Ship the `QualityEstimator` interface +
  trivial heuristic defaults; vulture supplies its pgvector-derived estimator separately.
- **No PyPI publication in this feature.** In-repo (inside the vulture repo, top-level
  `magicrouter/`), import-isolated; extraction to its own repo is a later feature gated on
  a second consumer.

## Architecture

```
magicrouter/
  pyproject.toml            # own package; NO dependency on vulture code
  README.md                 # design overview (written)
  CLAUDE.md                 # project instructions + research context
  docs/features/            # feature docs, vulture conventions (this folder)
  magicrouter/
    __init__.py
    contracts.py            # RoutingRequest, PolicyContext, ModelCard, RoutingDecision
    registry.py             # ModelRegistry (static config default: dict / YAML / env)
    policy.py               # PolicyFilter + built-in predicates (PII tier, jurisdiction,
                            #   allowlist, min context window)
    estimator.py            # QualityEstimator interface + heuristic default
    cost.py                 # CostModel (token estimate × per-1M pricing)
    health.py               # HealthSignal interface (default: always available)
    router.py               # route(): eligibility filter → optimizer → RoutingDecision
  tests/
    e2e/                    # business-logic tests (written FIRST, per project rules)
    unit/
```

Vulture-side integration (separate, inside `agents/shared/`, own vulture feature doc):

```
agents/shared/shared/llm/routing_adapter.py
    # builds ModelCards from provider.py data + cooldown/health state
    # builds PolicyContext from source policy (env/config for v1)
    # supplies vulture's QualityEstimator (heuristic v1; pgvector-driven v2)
    # exposes route_model(source_policy, task_type, file_features) to audit_runner.py
```

### Decision pipeline

1. **Stage 1 — eligibility filter (hard).** Deterministic predicates over
   `(ModelCard, PolicyContext)`: data-classification tier (low/normal → full pool; high →
   cloud + `pseudonymize=true` flag on the decision; critical → local-only or blocked),
   hosting jurisdiction vs. residency requirement, provider allowlist, minimum context
   window, health/cooldown. Classification input is deterministic (regex/domain rules) —
   never an LLM.
2. **Stage 2 — cost-quality optimizer (soft).** Over the eligible pool: quality estimate per
   model (pluggable), α threshold converts the estimate into pick-cheapest-clearing-the-bar;
   remaining eligible models are ordered into the fallback/escalation chain (cheapest-first
   cascade below the bar boundary, strongest-first above it).
3. **Output — `RoutingDecision`** with `model_id`, `fallbacks`, `escalation`, `pseudonymize`,
   `eligible_pool`, and `reasons` (which predicate excluded which model — auditability is a
   product feature for a compliance tool).

All contracts JSON-serializable so a polyglot sidecar (HTTP service) is possible later
without a rewrite.

## Phases (each gated; E2E tests written first per project workflow)

### Phase 1 — Contracts + extraction (behavior-preserving)

- Write E2E tests defining the decision contract (given pool/policy/request → expected
  decision, including reasons).
- Implement `contracts.py`, `registry.py`, `cost.py`, `health.py`, `router.py` with a
  pass-through policy (everything eligible) and trivial estimator.
- Lift the *data* from vulture's `provider.py` (`MODEL_MAP` topology, `CONTEXT_WINDOWS` +
  family inference, `COST_PER_1M_TOKENS`, `FALLBACK_CHAINS`) into a vulture-side `ModelCard`
  set in `routing_adapter.py`. `provider.py` behavior unchanged; adapter proven equivalent by
  tests (same model chosen as `get_model_with_fallback` for every current configuration).
- **Gate**: full existing agent test suite green; adapter-equivalence E2E green.

### Phase 2 — Eligibility filter (the unconditional win)

- E2E tests: EU-residency source → non-EU cloud models excluded; `critical` classification →
  Ollama-only; allowlist enforcement; ctx-window exclusion; all with `reasons` populated.
- Implement `policy.py` predicates + `PolicyContext` plumbing.
- Vulture wiring: per-source policy (v1: env/config-level, e.g.
  `VULTURE_ROUTER_POLICY=eu_resident|local_only|open`; per-source DB field is a follow-up),
  routed through `route_model()` in the LLM phase of `run_combined_audit()`.
- New env knobs (all default-off, vulture mode-A behavior unchanged):
  `VULTURE_ROUTER_ENABLED=false`, `VULTURE_ROUTER_POLICY=open`,
  `VULTURE_ROUTER_ALPHA=` (cost-aggression dial, unset = balanced).
- **Gate**: policy E2E green; with router disabled, byte-identical behavior to today.

### Phase 3 — Quality estimator prototype + honest benchmark (investment gate)

- Vulture-side difficulty estimator v1: signals from prior findings (pgvector memory),
  skill-finding density, file size/tier — maps to P(cheap model suffices).
- **Benchmark against the Best-Single baseline** on a real audit corpus (reuse vulture's
  `agents/cwe/tests/corpus/`): router vs. always-cheap vs. always-expensive on the
  cost-quality frontier (findings recall vs. estimated USD).
- **Gate**: the router must beat or match Best-Single at lower cost. If it doesn't, STOP —
  keep the eligibility filter (Phase 2 stands on its own), park the optimizer, document the
  numbers in the status doc.

### Phase 4 — Standalone extraction (separate future feature)

- Only after: API stable against vulture + a second real consumer exists.
- Own repo, PyPI, optional HTTP sidecar for polyglot consumers, optional LiteLLM
  custom-routing-strategy adapter. Out of scope for 0001; recorded here so the boundary
  decisions above (no vulture imports, serializable contracts) are understood as load-bearing.

## Testing

- **E2E business-logic tests first** (`magicrouter/tests/e2e/`): decision contract, policy
  predicates, α-threshold behavior, fallback ordering, reasons audit trail.
- **Unit tests**: each predicate, cost math, registry parsing, estimator defaults.
- **Vulture integration E2E** (`agents/shared/tests/e2e/`): adapter equivalence (Phase 1),
  policy enforcement through `run_combined_audit()` (Phase 2), disabled-router no-op.
- **Import isolation check** in CI: `magicrouter` must not import `shared`/`backend`
  (a lint/test that fails on any vulture import).
- Python 3.12+, type hints on all functions, ruff + radon per project conventions.

## Risks (from the research — kept honest)

| Risk | Mitigation |
|---|---|
| Estimator is the critical lever and irreducibly domain-specific | Library ships interface only; expectations set: scaffolding + policy, not magic |
| Many published routers fail to beat Best-Single; vulture's skills-first cascade already banks the easy savings | Phase 3 benchmark is a hard gate; Phase 2 (policy) carries the feature even if Phase 3 fails |
| Library-with-one-consumer designs the wrong abstraction | In-repo first; extraction deferred until a second consumer is real |
| Scope creep toward "agent framework" | Non-goals section is the scope lock; coordinator layer explicitly out |
| Name collision with vulture 0049 "stage router" | Documented: 0049 routes agents/plugins (Go), magicrouter routes models (Python) |

## Open questions (carried from the research session — do not block Phases 1–2)

1. **Who are the "other tools"?** Python-only → library suffices; polyglot (Go/TS) → add the
   HTTP sidecar in Phase 4. Contracts are serializable either way.
2. **Primary driver — compliance or cost?** Current ordering assumes compliance-first
   (eligibility filter ships before the optimizer). Reverse Phases 2↔3 if cost is the
   burning driver.
