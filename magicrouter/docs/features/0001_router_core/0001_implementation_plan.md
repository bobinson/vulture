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
maximize   E[value(m, t)] − λ · cost(m, t)         # soft objective, over the eligible pool only
subject to m ∈ Eligible(policy, capability, t)      # hard constraints: sovereignty, residency, PII
                                                    # tier, compliance, context fit, health, AND
                                                    # capability-match to the task's requirements
```

Vulture is consumer #1 (the agents' LLM phase routes through it); the library is
standalone-*ready* (zero vulture imports, JSON-serializable contracts) but not
standalone-*published* until a second consumer is real.

### Capability match is a HARD constraint, not part of "value"

The single most important thing to get right about the objective: **capability is not a scalar
you trade off against cost — it is a multi-dimensional match between what the task *requires*
and what a model *can do*, and it is enforced as a hard eligibility filter (Stage 1), before any
value/cost optimization (Stage 2) runs.**

The motivating case (a generative example, but the structure is domain-general): choosing a
video model from a pool (Seedance 2.0/2.5, Veo, Kling, Wan, LTX, …). LTX is not "lower value per
dollar" than Seedance for a photoreal hero shot with an orbiting camera — it *categorically
cannot produce that output*. So it must be **disqualified in Stage 1** by the task's capability
requirement, exactly like a non-EU model is disqualified by residency. It never reaches the
value/cost comparison. Value only ranks models that are *all genuinely capable of the task*.

Concretely:

- **Requirements are a vector, matched by per-dimension dominance — never averaged.** A task
  carries a requirement vector, e.g. `{realism ≥ high, camera_motion ∈ {orbit, complex_dolly},
  duration ≥ 10s, res ≥ 1080p}`. A model is eligible only if its capability vector clears
  **every** required dimension. Cheapness/latency (dimensions a model scores well on) can **not**
  compensate for a missing capability — you cannot average `realism 0.5` against `cost 0.9` into
  "good enough." This is why capability match is vector dominance, not a single fitness scalar:
  a scalar lets cheapness paper over a categorical gap, which is the exact failure to avoid.
- **Two kinds of capability dimension:**
  - *Binary / hard* (supports 4K? lip-sync? max clip length ≥ N?) → pure eligibility predicate.
  - *Graded quality* (realism, motion fidelity) → a **floor** in Stage 1 (`realism ≥
    required_min`) **and** a soft term in Stage 2, with **diminishing returns** (surplus
    capability beyond the requirement adds little/no value).
- **The requirement gates BOTH directions.** For a throwaway animatic (`realism ≥ low`), LTX
  becomes eligible and Seedance 2.5 is *over-provisioned* — its extra realism adds ~no value for
  an animatic but costs more, so `value − λ·cost` correctly picks LTX. Under-capable models are
  removed by the floor; over-capable models lose on cost among the eligible. Value does real work
  only in the band where several models genuinely qualify. (Routing everything to the
  most-capable model regardless of need is the cost-waste / denial-of-wallet failure — see 0002.)
- **`value(m, t)` is fitness-for-purpose, conditional on capability** — it is *marginal* quality
  for *this* task (a better hero shot is worth more for a hero shot, not for an animatic), not a
  free-floating model-quality scalar. It is only ever evaluated over `Eligible`.

Where the capability numbers come from is the genuinely hard part, and it is **consumer-supplied
data on the ModelCard, never measured by the router** (same discipline as the security-posture
scores in 0002): independent benchmarks/arenas (most trustworthy), learned win-rate priors from
past outcomes (best signal for *subjective* quality; self-updates as the pool churns), or
provider-declared manifests (least trustworthy — treat like vendor self-reports). Turning a task
brief into a `requirements` vector is likewise the consumer's estimator (possibly an LLM parse),
caller-side; the router receives the requirement vector as a structured `RoutingRequest` input
and never interprets the brief itself.

When Stage 1 leaves several eligible models and quality is subjective / only knowable
post-generation (which of Seedance 2.0 vs 2.5 vs Veo is best *for this prompt*), the router does
not pretend to predict it: it emits the **ordered candidate set** (bounded into an N-way
bake-off by the budget gate), the caller generates on the top-k and has an evaluator/human pick
the winner, and that outcome feeds the win-rate prior. Pure decision in the router; generation +
judging in the caller. (This "post-generation quality" decision shape is the subject of the
feature-0003 research; the contract fields below are designed to carry it.)

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
    cost.py                 # CostModel.expected_usd() — normalizes ALL modalities to expected
                            #   USD for THIS request (token / per-image / per-second / per-asset /
                            #   gpu-second). See feature 0007 §1. cost_basis ∈ {metered_api,
                            #   self_hosted, gpu_second} (self-hosted ≠ free — 0007 §2)
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
   `(ModelCard, PolicyContext, RoutingRequest.requirements)`:
   - **capability match** — the request's `requirements` vector must be dominated by the
     ModelCard's `capabilities` vector on every required dimension (binary caps as predicates,
     graded caps as `capability ≥ required_min` floors); no averaging across dimensions;
   - data-classification tier (low/normal → full pool; high → cloud + `pseudonymize=true` flag;
     critical → local-only or blocked), hosting jurisdiction vs. residency, provider allowlist,
     minimum context window, health/cooldown.
   Classification input is deterministic (regex/domain rules) — never an LLM.
2. **Stage 2 — value/cost optimizer (soft), over the eligible pool only.** Value estimate per
   model (pluggable `QualityEstimator`; `value` is marginal fitness-for-*this*-task with
   diminishing returns on surplus capability), α threshold converts the estimate into
   pick-cheapest-clearing-the-bar; remaining eligible models are ordered into the
   fallback/escalation chain (cheapest-first cascade below the bar, strongest-first above it).
   When several models are eligible and quality is only knowable post-generation, the ordered
   set doubles as an **N-way bake-off candidate list**, bounded by the budget gate.
3. **Output — `RoutingDecision`** with `model_id`, `fallbacks`, `escalation`,
   `candidate_set` (for bake-off), `pseudonymize`, `eligible_pool`, and `reasons` (which
   predicate excluded which model — including *which capability dimension* disqualified a model;
   auditability is a product feature).

**Contract fields this requires** (added in Phase 1):
- `ModelCard.capabilities` — a map of `dimension → score/flag` (e.g. `{realism: 0.9,
  camera_motion: "advanced", max_duration_s: 20, supports_4k: true}`), consumer-supplied data
  (independent benchmark / learned win-rate prior / provider manifest — never measured by the
  router). Unknown/absent dimension handled conservatively (treated as failing a hard
  requirement — see the graceful-unknown rule for churning pools).
- `RoutingRequest.task_type` (opaque enum, e.g. `"text_to_video"`, `"prove_finding"`) and
  `RoutingRequest.requirements` — the per-dimension requirement vector for this task, produced
  by the consumer's estimator (possibly an LLM parse of a brief), consumed as structured input.
- Capability *scores* are per-`(task_type, model)` (a model strong at one task_type may be weak
  at another) — the profile is indexed by task_type, keeping the router domain-agnostic. The
  canonical cross-modality task-type taxonomy (LLM/image/video/3D) is defined in feature 0007 §3.
- Every ModelCard carries a universal **`latency`** field (soft term, or hard gate via an SLA
  requirement) and a **`cost_basis`** enum — not just LLM/token fields (feature 0007 §1–§2).
- **Fallback chains never cross `task_type`** (feature 0007 §4); cross-modality substitution is a
  caller-side pipeline redesign, never a router fallback.

All contracts JSON-serializable. **Polyglot is a hard requirement** (see feature 0005): the
contract is a public API from day one — strict serialization, semver, and a **payload-free
`RoutingRequest`** (derived signals only, never the raw prompt/source). The Python library here is
the *reference* runtime; the language-neutral contract + conformance suite + sidecar service +
native ports are designed in 0005 and follow the **prove → freeze → propagate** sequence (this
plan is the "prove" step).

## Phases (each gated; E2E tests written first per project workflow)

### Phase 1 — Contracts + extraction (behavior-preserving)

- Write E2E tests defining the decision contract (given pool/policy/request → expected
  decision, including reasons).
- Implement `contracts.py` (incl. `ModelCard.capabilities`, `RoutingRequest.task_type` +
  `requirements`, `RoutingDecision.candidate_set`), `registry.py`, `cost.py`, `health.py`,
  `router.py` with a pass-through policy (everything eligible) and trivial estimator. Capability
  fields are present but the filter is a no-op when `requirements` is empty (so behavior is
  unchanged for callers that don't set them — vulture's Phase-1 adapter equivalence holds).
- Lift the *data* from vulture's `provider.py` (`MODEL_MAP` topology, `CONTEXT_WINDOWS` +
  family inference, `COST_PER_1M_TOKENS`, `FALLBACK_CHAINS`) into a vulture-side `ModelCard`
  set in `routing_adapter.py`. `provider.py` behavior unchanged; adapter proven equivalent by
  tests (same model chosen as `get_model_with_fallback` for every current configuration).
- **Gate**: full existing agent test suite green; adapter-equivalence E2E green (empty
  `requirements` ⇒ capability filter inert ⇒ identical selection).

### Phase 2 — Eligibility filter, incl. capability match (the unconditional win)

- E2E tests: EU-residency source → non-EU cloud models excluded; `critical` classification →
  Ollama-only; allowlist enforcement; ctx-window exclusion; **capability match** — a request
  requiring a dimension a model lacks excludes that model (vector dominance, no averaging: a
  cheap model cannot survive a missing hard capability); over-provisioned model loses on cost
  among the eligible; unknown/absent capability dimension fails a hard requirement; all with
  `reasons` naming the disqualifying dimension.
- Implement `policy.py` predicates (incl. the capability-match predicate: vector dominance over
  `requirements`, binary caps as predicates + graded caps as floors) + `PolicyContext` plumbing.
  Graceful-unknown rule for churning pools: a model whose ModelCard lacks a required capability
  dimension is treated as failing that requirement (never silently eligible).
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

1. **Who are the "other tools"?** ~~Python-only vs polyglot~~ **RESOLVED (2026-07-03): polyglot is
   required** — magicrouter is a generic router for all platforms. The contract/conformance/sidecar/
   port work is feature 0005; this plan is the "prove" step (Python reference). Remaining sub-question
   there: *which* non-Python consumer/language comes first (likely Go, to match the vulture backend/CLI).
2. **Primary driver — compliance or cost?** Current ordering assumes compliance-first
   (eligibility filter ships before the optimizer). Reverse Phases 2↔3 if cost is the
   burning driver.
