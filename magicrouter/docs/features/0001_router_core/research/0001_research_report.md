---

# LLM Routing & Orchestration: Methodologies for a Capability/Cost/Sovereignty-Aware Router

**Research question:** how to build a router that selects the optimal LLM from a pool — driven by token cost, but constrained by capability, data protection, and sovereignty — inside an agentic harness.

### How to read this (confidence markers)

The deep-research run was interrupted by a token limit *during* the adversarial-verification phase, so the evidence comes at three confidence levels. I've marked every claim:

- ✅ **Verified** — survived 2–3 independent adversarial verifiers
- 📄 **Primary, unverified** — extracted verbatim from a primary source, but its verifiers errored out (NOT refuted — just unchecked)
- ⚠️ **Refuted / uncertain** — one claim was genuinely voted down
- 🔍 **My fetch** — I retrieved this directly this turn (the two seed papers + the sovereignty sources)

---

## 1. Bottom line

The field splits into two distinct problems, and **your question conflates them in a productive way**:

1. **Routing/cascading** (cost control): pick the cheapest model that's "good enough" per query. This is where RouteLLM, FrugalGPT, MixLLM, and cascade-routing live. Mature, benchmarked, directly about token cost.
2. **Orchestration/coordination** (capability): make *several* models collaborate to beat any single one. This is what **your two seed papers (Trinity + Conductor) actually are** — and notably, *neither addresses cost or sovereignty at all*.

Your "novel router" should sit at the **intersection**, structured as a **two-stage decision**:

```
        ┌─────────────────────────────────────────────────────────┐
        │ Stage 0 — HARNESS / COORDINATOR  (Trinity/Conductor)      │
        │ decompose task → assign roles → emit per-sub-task requests│
        └───────────────────────────┬─────────────────────────────┘
                                     ▼   one routing request per sub-task
        ┌─────────────────────────────────────────────────────────┐
        │ Stage 1 — ELIGIBILITY FILTER  (HARD constraints)          │
        │ sovereignty · residency · PII-tier · compliance · ctx-fit │
        │              → eligible model pool ⊆ M                     │
        └───────────────────────────┬─────────────────────────────┘
                                     ▼
        ┌─────────────────────────────────────────────────────────┐
        │ Stage 2 — COST-QUALITY OPTIMIZER  (SOFT objective)        │
        │ predictive win-prob + α threshold (RouteLLM/MixLLM)       │
        │   └─ optional cascade escalation gated by quality estimate│
        └─────────────────────────────────────────────────────────┘
              all enforced + observed through a gateway (LiteLLM)
```

**The single most important engineering lever**, per the cascade-routing paper: ✅ *the accuracy of your quality estimator* is "the critical factor for the success of model selection paradigms." Everything else is plumbing around that estimator.

---

## 2. Taxonomy — how the field categorizes routers

Two surveys give you the vocabulary (📄 both extracted but verification-interrupted):

**By *timing* of the decision** ([survey 2502.00409](https://arxiv.org/abs/2502.00409)):
- **Pre-generation / predictive** — estimate *before* generating whether a model will answer adequately, route once. (RouteLLM, MixLLM)
- **Post-generation / cascade** — generate with a cheap model, evaluate the output, *escalate* to a stronger model if it fails. (FrugalGPT)

**By *implementation method*** (same survey): **similarity-based** · **supervised** (performance profiles) · **reinforcement-learning** (routing as sequential decision) · **generative** (an LLM itself decides).

**A 3-dimensional framework** ([survey 2603.04445](https://arxiv.org/abs/2603.04445)) that's the cleanest mental model for *designing* one:
- **WHEN** — pre-generation, post-generation, or multi-stage
- **WHAT** — query features, model metadata, response-level signals, accumulated feedback
- **HOW** — heuristic, supervised classifier, bandit, or RL policy
- …layered over six paradigms: *difficulty-aware, preference-aligned, clustering-based, RL, uncertainty-based, cascading*. The survey notes production systems **combine routing and cascading** to optimize the cost/performance trade-off — which is exactly the hybrid I recommend in §8.

---

## 3. Core techniques

| Method | Type | How it decides | Cost / quality result | What to steal for your design |
|---|---|---|---|---|
| **RouteLLM** ✅ ([2406.18665](https://arxiv.org/abs/2406.18665), [OSS](https://github.com/lm-sys/routellm)) | Predictive, binary | Learned win-predictor `P(win_strong\|query)` + a **cost threshold α∈[0,1]** that converts probability → route to weak/strong | >2× cost cut at no quality loss; MT-Bench at 50%-strong-calls = **95% of GPT-4** (8.8 vs 9.3); up to **75%** cheaper than random | The **α threshold** is your cost-dial. Train a win-predictor; expose α as the knob ops turns. |
| **RouteLLM architectures** ✅ | — | similarity-weighted (Bradley-Terry), matrix factorization, BERT classifier, causal-LLM classifier | BERT/causal-LLM classifiers **underperform in low-data regimes** | Start with similarity/matrix-factorization unless you have a lot of labeled routing data. |
| **RouteLLM generalization** ✅ | — | Trained on Chatbot Arena prefs + GPT-4-judge augmentation | **Generalizes to new model pairs (Claude 3 Opus/Sonnet, Llama 3.1 70B/8B) with no retraining** | One router can survive an evolving model pool — critical for a long-lived system. |
| **Cascade routing** ✅ ([Dekoninck et al., ETH](https://files.sri.inf.ethz.ch/website/papers/dekoninck2024cascaderouting.pdf)) | Unified | Frames model selection as **linear optimization: maximize quality s.t. cost budget**; generalizes routing *and* cascading | Beats pure routing/cascading by **up to 8% (RouterBench), 14% (SWE-Bench)** | The theoretically-optimal target. Adopt its framing: it *is* a constrained optimization. |
| **Quality-estimator finding** ✅ | — | — | Estimator accuracy is "**the critical factor**" for whether routing/cascading helps at all | Invest your effort here, not in the routing policy. |
| **MixLLM** 📄 ([2502.18482](https://arxiv.org/abs/2502.18482)) | Predictive, multi-model | **Contextual bandit**; query tags → enhanced embeddings → lightweight per-LLM quality+cost predictors → meta-decision maker | **97.25% of GPT-4 quality at 24.18% of cost** under a latency constraint | Jointly optimizes **quality + cost + latency**; bandit handles online adaptation. The multi-objective shape you want. |
| **xRouter** 📄 ([2510.08439](https://arxiv.org/abs/2510.08439)) | RL, tool-calling | A router *agent* (fine-tuned Qwen2.5-7B) that answers directly **or** delegates via tool calls; reward `R = R_binary × (K − λC)` — success-gated, then cost-sensitive | ~**80–90% of GPT-5 accuracy at ~1/5 the cost** (GPQA); near-GPT-5 at ~1/8 cost (Olympiad) | The reward shape is the cleanest formalization of "correct first, then cheap." λ is your cost-aggression dial. |
| **FrugalGPT** 📄 (via [survey 2502.00409](https://arxiv.org/abs/2502.00409)) | Post-gen cascade | DistilBERT regressor infers answer-correctness probability → escalate or stop | Saves **59–98%** of inference cost at similar accuracy | The canonical cascade. Your "skills-first, LLM-second" pipeline is already a cascade in this spirit. |

**Mixture-of-Experts note:** MoE routing (gating networks inside a single model) is a *different* layer than model selection. It's relevant terminology but operates below the API boundary — not directly applicable to routing across a pool of separate LLM endpoints.

---

## 4. Benchmarks & the bar you must clear

- **RouterBench** ✅ ([Hu et al., 2403.12031](https://arxiv.org/abs/2403.12031)) — the standard router benchmark: **405k+ inference outcomes** across representative LLMs.
- **LLMRouterBench** 📄 ([2601.07206](https://arxiv.org/abs/2601.07206)) — larger unified framework: **400K+ instances, 21 datasets, 33 models**, two paradigms (performance-oriented vs performance-cost-tradeoff routing).
- **RouterEval** 📄 ([ResearchGate](https://www.researchgate.net/publication/397426224)) — a third benchmark, focused on "model-level scaling."

**The design bar that matters most** 📄: across LLMRouterBench, **many learned/commercial routers fail to beat the trivial "Best Single model" baseline** (always call the one best model). The best methods deliver only **up to ~4% accuracy gain** or **up to ~31.7% cost reduction while matching** Best Single. → *Any router you build must be benchmarked against "always use model X," and that's a surprisingly hard baseline to beat.* Don't ship routing complexity you can't prove earns its keep.

⚠️ **Uncertain:** a claim that RouterBench scores routers via an "AIQ (Average Inference Quality) = area under the convex hull of the cost-quality curve" metric was **refuted 0-2** by verifiers. RouterBench does evaluate on a cost-quality curve, but treat that specific metric name/definition as unconfirmed.

The unifying evaluation concept everyone agrees on: the **cost-quality Pareto frontier** — plot quality vs. $/token, and a good router pushes the frontier up-and-left.

---

## 5. Privacy, compliance & sovereignty-aware routing

This is the part your seed papers and the academic routers **don't** cover — it's industry-practice, and it's where your router would be genuinely differentiated. The key structural insight: **sovereignty/compliance are HARD constraints (eligibility), not soft objectives (optimization).** A model in the wrong jurisdiction is disqualified regardless of how cheap or capable it is.

**PII-aware routing** 🔍 ([dev.to](https://dev.to/micelclaw/pii-aware-routing-how-to-use-cloud-ai-and-keep-your-sensitive-data-local-1m40)) — a concrete, implementable pattern:
- **Four-tier sensitivity classification → routing target:** Low/Normal → best cloud model; **High → cloud *with pseudonymization*; Critical → local model only (Ollama) or blocked.**
- **Deterministic classification** (regex + domain defaults: emails="high", health="critical", SSN/IBAN/credit-card patterns), explicitly **no LLM in the loop** — *"sending data to an LLM to decide if the data is too sensitive to send to an LLM is a circular problem."*
- **Pseudonymization middle path:** replace identifiers with consistent SHA-256 tokens (`Ana García → Person_A3F2`); the cloud model still reasons over structure without seeing identity.

**LLM gateways as the control plane** 🔍 ([Masood](https://medium.com/@adnanmasood/llm-gateways-for-enterprise-risk-building-an-ai-control-plane-e7bed1fdcd9c)): a gateway is a *"policy-enforced reverse proxy"* between your app and providers, enforcing **data-residency, token budgets, multi-model routing/failover, semantic caching, and runtime prompt/output safety**. This is the enforcement layer where sovereignty rules actually bite.

**How to encode it:** turn each policy into a predicate over `(data_classification, jurisdiction, provider_attributes)` that filters the model pool *before* the cost-quality optimizer runs. E.g. `EU-resident source ⇒ {providers hosted in EU} ∪ {on-prem}`; `contains_PII ⇒ pseudonymize | local`; `air-gapped customer ⇒ local-only`.

---

## 6. Your two seed papers — orchestration, not routing 🔍

Both are from the same Sakana AI team, both ICLR 2026, and both are about **composing models for capability**, not selecting one for cost:

**TRINITY: An Evolved LLM Coordinator** ([2512.04695](https://arxiv.org/abs/2512.04695), [project page](https://sakana.ai/trinity/))
- A **lightweight coordinator** (~0.6B-param model + a ~10K-param decision head) that orchestrates *heterogeneous* LLMs by **dynamic role assignment** across reasoning turns — three roles: **Thinker, Worker, Verifier**.
- Trained with **separable CMA-ES** (an evolution strategy), not RL/imitation — chosen for tight parameter/compute budgets.
- Decisions use the coordinator's **hidden-state representations** to match sub-tasks to models. Motivation: weight-merging fails on mismatched architectures, and closed APIs block direct integration — so coordinate at the orchestration layer instead.
- **86.2% on LiveCodeBench**; strong OOD generalization. *Cost/privacy/sovereignty: not addressed.*

**Learning to Orchestrate Agents… with the Conductor** ([2512.04388](https://arxiv.org/abs/2512.04388))
- A **7B "Conductor" trained with RL** to discover coordination strategies: it **designs communication topologies** for agent-to-agent collaboration *and* **prompt-engineers** targeted instructions per worker.
- Trained with **randomized agent pools**, so it adapts to **arbitrary open/closed agents** — "meeting any user requirements." Supports **recursive topologies** (Conductor selects itself) → test-time scaling.
- SOTA on **LiveCodeBench and GPQA**, beating any individual worker. *Cost/privacy/sovereignty: not addressed.*

**What they contribute to your design:** they belong at **Stage 0** (the harness/coordinator) — the layer that *decomposes* a task and *assigns roles* before anything gets routed. Trinity's role-assignment-from-hidden-states and the Conductor's randomized-pool training (graceful handling of an arbitrary, changing model pool) are the orchestration primitives. But because **neither optimizes cost or enforces policy**, they are necessary-not-sufficient: you bolt a cost/sovereignty router (Stages 1–2) *underneath* a Trinity/Conductor-style coordinator. That marriage is the white space (§10).

---

## 7. Production tooling

- **LiteLLM** 📄 ([GitHub](https://github.com/BerriAI/litellm)) — the de-facto open gateway: unified OpenAI-compatible API across 100+ providers, with routing, fallbacks, budgets, and rate-limiting. **You already run this in Vulture** (`agents/shared/shared/llm/provider.py`) — it's your enforcement/observability plane, ready-made.
- **RouteLLM OSS** 📄 ([GitHub](https://github.com/lm-sys/routellm)) — drop-in router; serves a "router-as-model" that you call like any model and it dispatches strong/weak behind an α threshold.
- **OpenRouter** 📄 ([blog](https://openrouter.ai/blog/insights/llm-gateway/)) — hosted multi-provider gateway with its own routing/fallback.
- **Helicone** 📄 ([2025 gateway comparison](https://www.helicone.ai/blog/top-llm-gateways-comparison-2025)) — observability + gateway; good survey of the gateway landscape.

Practical stance: **don't build the gateway** (LiteLLM gives you enforcement, failover, budgets, residency hooks). **Do build the decision logic** (eligibility filter + quality estimator + α/λ policy) on top.

---

## 8. Synthesis — a design for your novel router

Formalize it as **constrained multi-objective selection**. For a sub-task `t` with policy context `p`, choose model `m`:

```
maximize   E[quality(m, t)]  −  λ · cost(m, t)            # soft: the cost-quality dial (RouteLLM α / xRouter λ)
subject to m ∈ Eligible(p)                               # hard: sovereignty, residency, PII-tier, compliance, context-fit
```

Implemented as the four layers from §1:

1. **Stage 0 — Coordinator (optional, for hard tasks).** Trinity/Conductor-style decomposition + role assignment. For most line-of-business tasks you skip this and route the whole task; reserve it for genuinely multi-step reasoning.
2. **Stage 1 — Eligibility filter (hard constraints).** Deterministic predicates over `(data_classification, jurisdiction, compliance_regime, min_context_window, provider_allowlist)` → eligible pool. *This is your novel, differentiating layer.* Borrow the PII tiering: Critical → local-only; High → pseudonymize-then-cloud; Normal → full pool.
3. **Stage 2 — Cost-quality optimizer (soft).** Over the eligible pool, a **predictive router**: a learned **quality/difficulty estimator** + the **α threshold** (RouteLLM) picks the cheapest model clearing the bar. A **contextual bandit** (MixLLM) is the upgrade path once you have online feedback, and it natively folds in latency.
4. **Stage 3 — Cascade escalation (post-gen).** If the chosen model's output fails a confidence check, escalate (FrugalGPT/cascade-routing). Bounded by a cost budget so escalation can't run away.

**Cross-cutting:** the **quality estimator is the make-or-break component** (✅ cascade-routing finding) — and you have a domain advantage for building it (§9). Wrap everything in **LiteLLM** for enforcement/failover/observability.

**Capability profiles:** because you orchestrate *specialized* agents, maintain a per-`(task_type, model)` competence map (a security/CWE task ≠ a doc-summarization task). The router conditions on task_type, not just generic difficulty — this is where general-purpose academic routers leave value on the table for a specialized harness.

**Validate against the bar (§4):** benchmark every version against "always use your single best eligible model." If it doesn't beat that on the cost-quality frontier, it's not earning its complexity.

---

## 9. Mapping to Vulture (where this becomes concrete)

Vulture is *already* most of this architecture — it just hasn't been named as a router:

| Router concept | Already in Vulture | Gap to close |
|---|---|---|
| Gateway / control plane | **LiteLLM** in `agents/shared/shared/llm/provider.py` | Add residency/provider-allowlist config to it |
| Cascade (cheap→expensive) | **Skills-first (deterministic, 100% coverage) → LLM-second on the context-fitting subset** — a textbook FrugalGPT cascade | Make the escalation decision *learned*, not just context-window-bounded |
| Difficulty-aware routing | **Entry-point tiering + `llm_tier3`** (features 0057/0059), `VULTURE_USE_LLM`, `VULTURE_CWE_DISABLE_LLM` | These are heuristic tiers → replace with a quality estimator |
| Quality estimator (the critical lever) | The "which files go to LLM / which tier" heuristic | **Train it.** You have the labels: the **memory system (pgvector prior findings)** is a ready-made difficulty signal — files with prior high-severity findings or low skill-confidence → escalate to a stronger tier. This is your domain advantage. |
| Eligibility filter (sovereignty) | — (the genuine new build) | **You audit customer source code** (SOC2/OWASP) — that's sensitive IP, often residency-bound. Classify each *source* (e.g., EU customer, air-gapped) → restrict the eligible model pool (EU-hosted, or on-prem Ollama only). Maps directly to PII-aware tiering: "Critical" customer code → local model only. |

**Concrete first step:** add a `route_model(source_policy, task_type, file_features)` function feeding `audit_runner.py`: (1) `source_policy` → eligible providers; (2) memory-derived difficulty score → cheapest eligible model clearing the confidence bar; (3) escalate to Tier-3 only when the estimator is unsure. Ship α (cost-aggression) as an env knob like the existing toggles.

---

## 10. What would make it genuinely "novel"

The academic routers optimize **cost-quality only**, single-query, on **general chat benchmarks**. Sovereignty/compliance live in **industry gateway practice**, divorced from the learned routers. The seed papers do **capability orchestration** with **no cost/policy awareness**. The unoccupied white space — and your contribution — is the **unification**:

> A router that treats **sovereignty/compliance/PII as first-class hard constraints** unified with a **learned cost-quality optimizer**, using **per-specialized-agent capability profiles** and a **domain-specific difficulty estimator (prior audit findings)**, sitting under a **Trinity/Conductor-style coordinator** — benchmarked honestly against the Best-Single baseline.

No single source in this corpus does all of that together.

---

## 11. Sources

**✅ Verified (primary):**
- RouteLLM — [arXiv 2406.18665](https://arxiv.org/abs/2406.18665) · [OSS](https://github.com/lm-sys/routellm)
- Cascade Routing (Dekoninck et al., ETH) — [PDF](https://files.sri.inf.ethz.ch/website/papers/dekoninck2024cascaderouting.pdf)
- RouterBench (Hu et al.) — [arXiv 2403.12031](https://arxiv.org/abs/2403.12031)

**🔍 Fetched this turn:**
- TRINITY — [arXiv 2512.04695](https://arxiv.org/abs/2512.04695) · [Sakana](https://sakana.ai/trinity/) | Conductor — [arXiv 2512.04388](https://arxiv.org/abs/2512.04388)
- PII-aware routing — [dev.to](https://dev.to/micelclaw/pii-aware-routing-how-to-use-cloud-ai-and-keep-your-sensitive-data-local-1m40) | LLM gateways as control plane — [Masood](https://medium.com/@adnanmasood/llm-gateways-for-enterprise-risk-building-an-ai-control-plane-e7bed1fdcd9c)

**📄 Primary, verification-interrupted:**
- LLMRouterBench — [arXiv 2601.07206](https://arxiv.org/abs/2601.07206) | xRouter — [arXiv 2510.08439](https://arxiv.org/abs/2510.08439) | MixLLM — [arXiv 2502.18482](https://arxiv.org/abs/2502.18482)
- Survey (pre/post-gen, 4 methods) — [arXiv 2502.00409](https://arxiv.org/abs/2502.00409) | Survey (WHEN/WHAT/HOW) — [arXiv 2603.04445](https://arxiv.org/abs/2603.04445)
- LiteLLM — [GitHub](https://github.com/BerriAI/litellm) | OpenRouter — [blog](https://openrouter.ai/blog/insights/llm-gateway/) | Helicone — [comparison](https://www.helicone.ai/blog/top-llm-gateways-comparison-2025) | RouterEval — [ResearchGate](https://www.researchgate.net/publication/397426224)

**Surfaced but not extracted** (fetched by the run, no claims recovered — leads for you to pull): arXiv [2512.00595](https://arxiv.org/abs/2512.00595), [2506.09033](https://arxiv.org/abs/2506.09033), [2511.22788](https://arxiv.org/abs/2511.22788), [EMNLP 2025 industry #28](https://aclanthology.org/2025.emnlp-industry.28/).

## 12. Caveats about this run (be honest with yourself here)

- The run **scoped 6 angles → 24 sources → 118 claims → verified 25** before the token limit hit. Of 17 "killed" claims, **only 2 were genuinely refuted** (the AIQ-metric one, 0-2; one taxonomy claim, 1-0). The other 15 were dropped purely because their verifiers errored — I've re-presented those as 📄 *unverified-but-from-primary-sources*, not as false.
- The **sovereignty/compliance dimension is the thinnest-evidenced** and leans on industry blogs + my own fetches rather than peer-reviewed work — because that's genuinely where the literature is thin, which is also why it's your opportunity.
- I did **not** re-run the failed adversarial verification (it would re-spawn ~45 agents). If you want the 📄 claims (especially the "fails to beat Best Single" bar, xRouter, MixLLM) hardened to ✅, I can resume just the verification + synthesis from the cached run.

---

**Where would you like to take this?** A few natural next steps:
1. **Harden the evidence** — resume the interrupted verify+synthesize pass so the 📄 claims get adversarially checked.
2. **Persist this** — save as `docs/features/0060_llm_router/0060_research.md` (matching your feature-doc convention) or render it as a shareable artifact.
3. **Design it for real** — turn §8–9 into an implementation plan for a Vulture router layer (eligibility filter + memory-driven difficulty estimator + α knob).

Say the word and I'll do any combination.