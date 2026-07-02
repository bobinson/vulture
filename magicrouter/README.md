# magicrouter

**A standalone, policy-first LLM routing library.** Given a task, a pool of models, and a
policy context, magicrouter decides *which model should handle the call* — driven by token
cost, but constrained by capability, data protection, and sovereignty.

Born from vulture, designed to outgrow it. Full research corpus and design rationale:
`docs/features/0001_router_core/research/` (research report, design feedback, primary
source extracts). Project instructions: `CLAUDE.md`.

## The one principle

**magicrouter returns a *decision*; it never *executes* the call.**

```python
decision = router.route(request)           # pure, no I/O, no network
response = litellm.completion(             # the CALLER executes — LiteLLM, raw SDK, anything
    model=decision.model_id, ...)
# on failure → walk decision.fallbacks / decision.escalation
```

This split keeps the library side-effect-free, trivially unit-testable (no LLM mocking),
and execution-agnostic. The moment a router makes the call itself, it inherits credentials,
retries, provider quirks, and async models — and stops being reusable. (RouteLLM's OSS
"router-as-a-model" makes the opposite choice and pays for it in coupling.)

**Corollary: magicrouter must never import anything from vulture.** Enforced mechanically —
separate package, no path to `backend/` or `agents/` internals. If it can't import the
domain, it can't leak domain assumptions.

## Decision model

Routing is **constrained multi-objective selection**. For a task `t` with policy context `p`,
choose model `m`:

```
maximize   E[quality(m, t)]  −  λ · cost(m, t)     # soft: the cost-quality dial (RouteLLM α / xRouter λ)
subject to m ∈ Eligible(p)                          # hard: sovereignty, residency, PII-tier, compliance, ctx-fit
```

Implemented as a staged pipeline (the coordinator layer above and the execution layer below
are explicitly OUT of scope):

```
        (Stage 0 — coordinator / harness: task decomposition, role assignment — NOT magicrouter)
                                    │  one RoutingRequest per sub-task
                                    ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ Stage 1 — ELIGIBILITY FILTER (hard constraints)               │
        │ deterministic predicates over (data_classification,           │
        │ jurisdiction, compliance_regime, min_context_window,          │
        │ provider_allowlist, model_health) → eligible pool ⊆ M         │
        └──────────────────────────────┬───────────────────────────────┘
                                        ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ Stage 2 — COST-QUALITY OPTIMIZER (soft objective)             │
        │ pluggable QualityEstimator + α threshold → cheapest eligible  │
        │ model clearing the quality bar; orders cascade fallbacks      │
        └──────────────────────────────┬───────────────────────────────┘
                                        ▼
                            RoutingDecision (JSON-serializable)
        (execution + Stage-3 cascade escalation: the CALLER, e.g. via LiteLLM)
```

Two structural insights from the research corpus drive this shape:

1. **Sovereignty/compliance are HARD constraints (eligibility), not soft objectives.** A model
   in the wrong jurisdiction is disqualified no matter how cheap or capable. The academic
   routers (RouteLLM, MixLLM, xRouter, FrugalGPT) optimize cost-quality only; the compliance
   layer lives in industry gateway practice, divorced from learned routing. Unifying them is
   the white space magicrouter occupies.
2. **The quality estimator is the make-or-break component** (cascade-routing finding: estimator
   accuracy is "the critical factor" for whether routing helps at all). It is also irreducibly
   domain-specific — so magicrouter ships the *interface*, and consumers ship the smarts
   (vulture's: a difficulty signal derived from pgvector prior audit findings).

## Data contracts (all JSON-serializable — sidecar-ready)

| Type | Carries |
|---|---|
| `RoutingRequest` | task_type, size/feature hints, policy context, quality floor, cost dial (α/λ) |
| `PolicyContext` | data classification tier (public/normal/high/critical), jurisdiction, compliance regime, provider allowlist |
| `ModelCard` | model id, provider, hosting jurisdiction, context window, cost per 1M tokens (in/out), capability tags (structured_output, tool_calling, …), quality priors per task_type, health/cooldown state |
| `RoutingDecision` | chosen model_id, ordered fallbacks, escalation chain, eligible-pool snapshot, **reasons** (which predicates filtered what — auditability is a feature, this library serves compliance tools) |

Keeping every contract serializable means a future polyglot consumer (Go/TS) gets a tiny HTTP
sidecar speaking the same JSON — without a rewrite.

## Pluggable interfaces

| Interface | Contract | Default shipped |
|---|---|---|
| `ModelRegistry` | the model pool as `ModelCard`s | static config (dict/YAML/env) |
| `PolicyFilter` | `(ModelCard, PolicyContext) → eligible?` | PII-tier + jurisdiction + allowlist + ctx-fit predicates |
| `QualityEstimator` | `(RoutingRequest, ModelCard) → P(good enough)` | trivial heuristics (size/tier); real estimators are consumer-side |
| `CostModel` | `(RoutingRequest, ModelCard) → expected USD` | token-estimate × per-1M pricing |
| `HealthSignal` | `(model_id) → available?` | always-available; consumers plug cooldown/health state |

PII-tier semantics follow the four-tier pattern from the research: **low/normal → full pool;
high → cloud only with pseudonymization flag set on the decision; critical → local-only or
blocked.** Classification is deterministic (regex/domain rules) — never an LLM ("sending data
to an LLM to decide if it's too sensitive to send to an LLM is a circular problem").

## Security & privacy as first-class dimensions (feature 0002)

Cost and capability are not enough — **a cost/quality-only router is actively unsafe**: it
routes jailbreak attempts to the weakest, cheapest, least-robust models. So security and
privacy are hard dimensions layered onto the same decision model, and the router itself is
treated as an attack surface (denial-of-wallet). The organizing principle is a
**detect / decide / enforce** seam:

> **guard = detect** (gateway runs the guard model) → **magicrouter = decide** (library routes
> on the resulting flag) → **gateway = enforce** (execute / block / mask).

What this adds, all pure and deterministic:

- **Robustness as ModelCard attributes** — `jailbreak_robustness`, `injection_robustness`
  (distinct dimensions; sourced from *independent* low-FPR benchmarks like JailbreakBench /
  MLCommons, never vendor self-reports), plus `hosting_locality`, `split_inference_ok`,
  `certifications`, `provenance` (CycloneDX ML-BOM).
- **Safe-by-construction predicates** — a flagged-injection input can never be routed to a
  below-robustness-floor model; a `critical` privacy prompt can never be assigned a cloud-only
  model. These are invariants, not heuristics.
- **Anti-denial-of-wallet** — per-tenant/session cumulative-spend predicates, escalation
  rate-limits, and suffix-resistant difficulty estimation (adversarial suffixes that force
  expensive-model escalation cost ~$0.98 to train and beat perplexity filters — see 0002 report).
- **Privacy execution-mode routing** — `execution_mode ∈ {cloud, split, local}` and
  `require_pseudonymization` selected deterministically from an entity-level `privacy_tier`; the
  actual masking / DP / MPC mechanisms stay in the gateway.
- **Consumed guard signals** — an `injection_suspicion` flag from a caller-run guard model is a
  first-class `RoutingRequest` input. The router may additionally run only *cheap partial*
  pattern predicates (unicode-smuggling), honestly scoped as advisory, never as the detector.

Full evidence + the complete "what fits a pure router vs the execution gateway" boundary table:
`docs/features/0002_security_privacy_routing/`.

## What magicrouter is NOT

- **Not a gateway.** LiteLLM/OpenRouter already do execution, failover, budgets,
  observability. magicrouter is the decision layer that sits above.
- **Not a coordinator.** Trinity/Conductor-style task decomposition and role assignment
  (the two seed papers, arXiv 2512.04695 / 2512.04388) belong in the harness. Scope creep
  here turns the library into "an agent framework" and it never ships.
- **Not magic, despite the name.** The learned smarts (difficulty estimators, capability
  profiles) are consumer-supplied. The library is well-factored scaffolding + a policy engine.
- **Not a guardrail / injection detector.** Detection strong enough to gate on is a
  model-inference workload (100M+ params or an LLM) and is evadable — it lives in the
  caller/gateway. magicrouter *consumes* the guard's verdict as a flag; it never runs one.

## The honest bar

Across LLMRouterBench, **many learned/commercial routers fail to beat the trivial
"Best Single model" baseline.** Every magicrouter deployment must be benchmarked against
"always use your single best eligible model" on the cost-quality frontier. In vulture's case
the skills-first/LLM-second cascade already captures most easy cost savings — so the
cost-quality optimizer is the *speculative* half, gated on measured wins, while the
**eligibility/sovereignty filter is the part with unconditional standalone value** (for a
compliance-audit tool it's a correctness requirement, not an optimization).

## Relationship to vulture

magicrouter is extraction + unification of logic vulture already has, not greenfield:

| magicrouter concept | Extracted / adapted from |
|---|---|
| `ModelRegistry` + `ModelCard` | `agents/shared/shared/llm/provider.py` — `MODEL_MAP`, `CONTEXT_WINDOWS` (+ family inference), `COST_PER_1M_TOKENS`, `FALLBACK_CHAINS`, `supports_structured_output` |
| `HealthSignal` | `shared/llm/cooldown.py` + unified LLM health (feature 0039), CWE model-health gate |
| Cost cap inputs | `VULTURE_LLM_BUDGET_USD` enforcement in `audit_runner.py` |
| Cascade shape | skills-first → LLM-second pipeline (`run_combined_audit`) — a textbook FrugalGPT cascade |
| Crude difficulty router | entry-point tiering + `llm_tier3` (features 0057/0059) |

What stays in vulture: the pgvector-driven difficulty estimator, per-agent-type capability
profiles, source→policy mapping, `VULTURE_*` env knobs, and the wiring into `audit_runner.py`.

Naming note: vulture's feature 0049 "stage router" routes *audit agents/plugins* (Go backend,
which plugin handles which pipeline stage). magicrouter routes *models* (which LLM serves a
given call). Different layers; both can coexist.

## Status

Design phase. See `docs/features/0001_router_core/0001_implementation_plan.md` for the phased
plan (extract & define → eligibility filter → estimator prototype + benchmark gate →
standalone extraction) and `0001_implementation_status.md` for progress.
