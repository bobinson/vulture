# Security-, Privacy-, and Injection-Aware LLM Routing

**Research question:** How can magicrouter go *beyond cost and capability* — making security and
privacy first-class routing dimensions — and can prompt injection be handled at the routing
layer, given magicrouter is a **pure, deterministic decision engine that makes no LLM calls**?

## How to read this (confidence markers)

The deep-research run (6 angles → 26 sources → 127 claims) was interrupted by a session token
limit *during* the adversarial-verification phase — the same failure mode as the feature-0001
run. Evidence therefore comes at graded confidence, and every claim below is marked:

- ✅ **Verified** — survived 3 independent adversarial verifiers, 3-0 (10 claims)
- ⚠️ **Refuted** — voted down (1 claim; noted where relevant)
- 📄 **Primary, unverified** — extracted verbatim from a primary/standards source, but its
  verifiers errored out on the token limit (NOT refuted — just unchecked). Recovered from the
  run journal. The bulk of the detail below.

Raw claims + quotes per source: `research/claims_by_source.json`. Run log:
`research/deep_research_run.json`.

---

## 1. Bottom line

Three findings reframe the whole design:

1. **A cost/quality-only router is not security-neutral — it is actively *unsafe*.** ✅ A
   preference-trained router "route[s] jailbreaking attempts to weaker [less safety-robust]
   models, thereby elevating safety risks" ([2504.07113](https://arxiv.org/abs/2504.07113)).
   Cheap models are typically the *least* jailbreak-resistant, so the cost optimizer
   systematically sends the most dangerous inputs to the softest targets. **Security cannot be
   emergent; it must be an explicit routing dimension** that overrides the cost objective.

2. **The router itself is an attack surface — a new one.** ✅ Cost-aware routing "introduces a
   new security concern that adversaries may manipulate the router to consistently select
   expensive high-capability models" — a **denial-of-wallet / cost-amplification** threat
   ([2604.15022](https://arxiv.org/abs/2604.15022)). This is demonstrated, cheap, and
   black-box: universal adversarial suffixes ([2501.01818](https://arxiv.org/abs/2501.01818),
   "confounder gadgets"; [2604.15022](https://arxiv.org/abs/2604.15022), "Route to Rome")
   force expensive-model escalation with no white-box access. And the routing *stage* is a new
   **privacy** leak point ([2604.15728](https://arxiv.org/html/2604.15728v1)): it sees every
   query and is often run by a third party.

3. **The purity boundary is real and the literature respects it.** Injection *detection* good
   enough to gate on is a **model-inference workload** (100M+ params, or an LLM), not a
   deterministic predicate ✅📄 — so runtime scanning must live in the caller/gateway.
   magicrouter's job is to **consume** guard signals as flags/scores and to enforce the
   *deterministic* parts: eligibility predicates over security/privacy posture, fail-open vs
   fail-closed policy, cost-amplification guards, and a handful of cheap pattern checks.

The clean articulation of the boundary, from the routing-attack paper, is **"LLM control
plane integrity"** 📄 ([2501.01818](https://arxiv.org/abs/2501.01818)): the router/gateway is a
control plane, and its robustness to adversarial input is a distinct, first-class safety
problem. magicrouter is that control plane's *decision* half.

---

## 2. Security-aware routing (the new hard/soft dimensions)

### 2a. Jailbreak/injection robustness is a per-model, benchmark-derived score → ModelCard attribute

The core enabler: **model safety posture is now measurable and standardized**, which is exactly
what a deterministic router needs (a number on a ModelCard, not a runtime judgment).

- 📄 **JailbreakBench** ([2404.01318](https://arxiv.org/pdf/2404.01318)) is a reproducible
  leaderboard scoring per-model jailbreak robustness (attack-success-rate per attack/defense).
  Robustness **varies enormously under identical attacks** — "Prompt with RS" hits 90% ASR on
  Llama-2 vs 78% on GPT-4; PAIR hits 0% on Llama-2 but 71% on GPT-3.5 — so a robustness-aware
  router "would make materially different model selections."
- 📄 **MLCommons v0.5 Jailbreak Benchmark**
  ([PDF](https://mlcommons.org/wp-content/uploads/2025/12/MLCommons-Security-Jailbreak-0.5.1.pdf))
  defines a quantitative **"Resilience Gap"** (baseline safe-rate − under-attack safe-rate) on
  five-tier grade bands — a machine-readable score suited to a ModelCard. Two design-binding
  caveats: (1) **safety alignment and jailbreak resistance are independent** — a router cannot
  infer injection robustness from a model's safety grade; they must be *separate* ModelCard
  dimensions. (2) v0.5 grades are **anonymized and open-weight-only**; named per-model
  production grades wait for v1.0 (planned Q1 2026). It also frames jailbreaking as "a
  user-provided special case of prompt injection" aligned to ISO/IEC 42001 release-gating —
  i.e. gate eligibility on certified posture, not runtime checks.
- 📄 The **DSC benchmark** ([2504.07113](https://arxiv.org/abs/2504.07113)) explicitly folds
  privacy + safety (incl. a jailbreaking query category) into *router* evaluation — a
  methodology for producing the per-model safety scores magicrouter would consume.

**Design consequence:** add `jailbreak_robustness` and `injection_robustness` as distinct
numeric ModelCard attributes. Source them from **independent benchmarks, never vendor
self-reports** (§4 shows why). A hard predicate ("high-risk input ⇒ eligible pool = models
with robustness ≥ X") plus a soft term (robustness as a tie-breaker in the optimizer).

### 2b. Provider security posture / model provenance → standards-backed ModelCard metadata

- 📄 **CycloneDX ML-BOM** ([cyclonedx.org](https://cyclonedx.org/capabilities/mlbom/), an OWASP
  project linked to ECMA-424) is a standardized, machine-readable representation of models,
  datasets, and configs — including **training-data/dataset provenance**. That means
  provenance, one of the proposed security dimensions, "already has a standards-backed
  machine-readable representation rather than needing an ad-hoc schema." Recording which
  ML-BOM-derived attributes drove each `RoutingDecision` aids the compliance/audit trail.
- Provider certifications (SOC2/ISO27001/GDPR/etc.) show up in practice as marketed gateway
  attributes (📄 Portkey claims SOC2/HIPAA/GDPR/CCPA) — cleanly modeled as deterministic
  boolean/enum ModelCard fields for an allowlist predicate.

### 2c. OWASP-style threat model for the router: Unbounded Consumption / Denial-of-Wallet

The relevant OWASP LLM Top-10 entry for a *router* is **Unbounded Consumption / Denial of
Wallet (DoW)** — a financially-motivated attack class specific to pay-per-use AI that "evade[s]
traditional availability-focused monitoring because no outage occurs" 📄
([layerxsecurity](https://layerxsecurity.com/generative-ai/denial-of-wallet-attacks/),
[a10networks](https://www.a10networks.com/glossary/llm-unbounded-consumption/),
[prompt.security](https://prompt.security/vulnerabilities/denial-of-wallet-service)). Why it
targets *this* library specifically:

- 📄 "Adversaries can craft resource-intensive queries that trigger the most computationally
  expensive operations… a cost-quality router whose alpha threshold escalates 'hard' queries to
  premium models can be adversarially steered toward expensive-model dispatch." The α-threshold
  *is* the exploit surface.
- 📄 Recursive prompting yields **exponential** token growth, so "per-request cost caps alone
  are insufficient; budget enforcement must track cumulative per-tenant/per-session spend" —
  supporting **privacy-budget-style accounting as a routing-decision input**.

**These translate directly into deterministic router logic** (see §5): per-tenant/session
cumulative-spend eligibility predicates, and a bias *against* unexplained escalation.

---

## 3. Attacks on the router itself (the sharpest new evidence)

This is the best-verified cluster and the most actionable, because the defenses are largely
deterministic and therefore *in-scope* for magicrouter.

- ✅ **Confounder gadgets** ([2501.01818](https://arxiv.org/abs/2501.01818)): query-independent
  token sequences that, appended to *any* query, force escalation to the expensive model.
  Works **white-box AND black-box** across multiple open-source and commercial routers 📄.
- ✅ **R2A / Route to Rome** ([2604.15022](https://arxiv.org/abs/2604.15022)): black-box
  adversarial-suffix optimization via a surrogate router. Raises escalation-success from 📄
  **0.26→0.78 (RouteLLM-Bert), →1.00 (RouterDC), 0.12→0.89 (OpenRouter)**; amplifies cost
  **~2.7–2.9× per M tokens**; the universal suffix costs **~$0.98** to train over 120 queries.
- 📄 **MCP metadata amplification** ([2601.10955v2](https://arxiv.org/html/2601.10955v2)):
  manipulating only *text-visible fields* of a tool server amplifies per-query cost **up to
  658×** while preserving task correctness (96.2% ASR) — so outcome-based monitoring can't see
  it.

**Two defense findings that shape the design:**

- ✅/📄 **Perplexity filtering does not work.** Gadgets/suffixes are crafted to stay within the
  benign perplexity distribution ([2501.01818](https://arxiv.org/abs/2501.01818)); against MCP
  amplification, perplexity filters and output/trajectory monitors flag it "<3% of the time"
  ([2601.10955v2](https://arxiv.org/html/2601.10955v2)). A naive perplexity predicate is a
  false comfort — **do not ship it as *the* defense.**
- 📄 Static budget caps **throttle but do not prevent** amplification — "routing-layer budget
  caps are a mitigation, not a defense" ([2601.10955v2](https://arxiv.org/html/2601.10955v2)).

**Design consequence (in-scope, deterministic):** treat *escalation itself as privileged*. The
router should (1) enforce per-tenant/session cumulative-spend ceilings as hard predicates;
(2) rate-limit or require stronger justification for expensive-model escalation; (3) log every
escalation with its reason (the `reasons` audit trail) so anomalous escalation is detectable
downstream; (4) support a "suffix-resistant" mode that ignores trailing/low-salience tokens in
the difficulty estimate. None of these need an LLM call.

---

## 4. Prompt injection at the routing layer — what's possible, what isn't

The question "can a router detect prompt injection before dispatch?" has a nuanced, well-
evidenced answer: **detection strong enough to gate on is a model-inference workload, so it
belongs in the caller/gateway; the router consumes its verdict as a flag.** But *some* cheap
deterministic checks are legitimately in-scope.

### What fits *inside* a pure deterministic router

- 📄 **Deterministic pattern checks** as used by production gateways: **Kong AI Prompt Guard**
  is pure PCRE regex allow/deny lists, and Kong recommends deny patterns for **hidden unicode
  (zero-width / bidirectional control chars)** used to smuggle instructions
  ([konghq](https://developer.konghq.com/plugins/ai-prompt-guard/)). "An injection heuristic
  that could equally be expressed as a pre-dispatch predicate in a pure decision library."
- 📄 The **heuristics + vector-similarity** layers of Rebuff (similarity against known injection
  patterns) are compatible with a pure router; only Rebuff's LLM-detector layer is not
  ([deepinspect](https://www.deepinspect.ai/blog/open-source-llm-guardrails)).

These reduce but do **not** eliminate risk — PromptGuard-2-86M *alone* cut AgentDojo ASR from
17.6%→7.5% (a 57% drop), while the full layered setup with an LLM auditor reached 1.75% 📄
([2505.03574](https://arxiv.org/pdf/2505.03574)). So deterministic checks are a cheap first
filter, honestly labeled as partial.

### Why real detection can't live in the router (must be a consumed flag)

- 📄 **It needs a model.** Strong low-FPR detection "required fine-tuned models of roughly
  100M+ parameters (best: 8B Llama-3.1, AUC 0.998, 94.8% TPR at 1% FPR)"
  ([2501.15145](https://arxiv.org/pdf/2501.15145)). PromptGuard-2 is 86M/22M mDeBERTa, ~19–92ms
  on an A100 📄 ([2505.03574](https://arxiv.org/pdf/2505.03574),
  [HF](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)) — cheap enough to run
  per-request, but still an inference step. Cloudflare's guardrail is Llama Guard 3 8B, **~500ms
  per request** 📄 ([cloudflare](https://developers.cloudflare.com/ai-gateway/features/guardrails/)).
- 📄 **The base-rate problem is brutal.** Benign traffic dwarfs injections, so detectors need
  extremely low FPR — and most fail there: at 0.1% FPR, PromptShield catches 65.3% but
  PromptGuard **9.4%**, InjecGuard 6.6%, ProtectAI **0%** ([2501.15145](https://arxiv.org/pdf/2501.15145)).
- 📄 **Vendor metrics lie for gating purposes.** PromptGuard scored 12.8% TPR@1%FPR OOD vs the
  71% Meta reported — so an `injection_robustness` ModelCard attribute "must come from
  independent low-FPR benchmarking, not vendor self-reports"
  ([2501.15145](https://arxiv.org/pdf/2501.15145)). And pooled calibration hides it: a detector
  at 0.06 pooled ECE was 0.91 on attacks alone ([2606.22659](https://arxiv.org/pdf/2606.22659)).
- 📄 **Detectors are evadable by paraphrase and blind to indirect injection.** All three tested
  detectors "confidently pass indirect behavior-hijack injections (encoding, cipher,
  reverse-text, emoji, translation overrides)" — the class most relevant to agentic/RAG traffic
  ([2606.22659](https://arxiv.org/pdf/2606.22659)); a black-box adversary rewriting injections
  as innocuous prose drives miss-rate ≈ 1.
- 📄 **The resource-asymmetry result** ([2510.01529](https://arxiv.org/pdf/2510.01529), USENIX
  Security 2026): guards run under stricter compute limits than the models they protect — "an
  inherent design flaw, not an implementation bug." "Controlled-release prompting" beat Gemini,
  DeepSeek, Grok, Mistral Le Chat at near-perfect rates in two turns; 14 open-weight guards
  couldn't reliably detect it without 3×–70× latency. Their conclusion: shift from pre-dispatch
  input detection toward **output prevention**.

**Net:** magicrouter must not pretend to *be* an injection detector. It should (a) offer the
cheap deterministic pattern predicates above (unicode-smuggling, known-pattern similarity),
honestly scoped as partial; (b) accept an **injection-suspicion flag/score from a caller-run
guard model** as a first-class `RoutingRequest` input and route on it (e.g. suspicious ⇒
restrict eligible pool to high-robustness models, or set a `block` decision); (c) carry
independently-benchmarked `injection_robustness` on ModelCards.

---

## 5. Privacy-preserving routing beyond static PII tiers

Feature 0001 already has static PII tiers. The new evidence pushes privacy from a static tier
to a **per-prompt, entity-level, sometimes-cryptographic** dimension — and, crucially, shows the
*decision* part is deterministic while the *mechanism* part is gateway work.

- ✅ **PRISM** ([2511.22788](https://arxiv.org/abs/2511.22788)) is the anchor: an edge-side gate
  routes each prompt to **direct cloud / sketch-based cloud-edge collaboration / fully local**
  based on assessed privacy risk — local-vs-cloud **split inference selected at the routing
  layer**. Its sensitivity assessment is **entity-level NER**, not static tiers (a binary
  indicator fires on any private linguistic cue). ✅ **The gate is deterministic** — "a linear
  classifier with softmax… top-1 selection, not an LLM call" — explicitly "compatible with a
  pure decision-engine boundary like magicrouter's." Cost is real and must be exposed: 📄
  1.54× latency, 2.32× energy, quality 6.88 vs 8.14 cloud-only.
  - ⚠️ **Refuted (1-2):** the specific claim that PRISM's *formal (ε₁+ε₂)-LDP privacy-budget
    mechanism* can be "operationalized inside a router's decision pipeline" was voted down. Take
    the split-mode *routing decision* as in-scope; treat the **DP-budget mechanism as
    gateway/execution work**, not router logic.
- 📄 **Split-N-Denoise** ([2310.09130](https://arxiv.org/pdf/2404.01318), ICML 2024): a concrete
  client-side split — token-embedding layer on the client, LDP noise before transmission,
  client-side denoise. So "supports client-side split inference with LDP" is a **real,
  implementable deployment mode** a router can model as an eligibility/PII-tier dimension, and
  privacy budgets are a "quantifiable, comparable axis" that could sit as a numeric ModelCard
  score. The mechanism lives in the caller; the router needs only a flag that it's available.
- ✅ **PPRoute** ([2604.15728](https://arxiv.org/html/2604.15728v1)) addresses the router-as-
  leak-point (§1): it runs the *routing model itself* under **2-party MPC** so the routing
  provider "cannot know the user query or the generated query embedding," at 📄 ~20× speedup
  over naive MPC with no routing-quality loss. Relevant to magicrouter's *hosted/sidecar* form
  (a third-party decision service), less so to the in-process library — but it names the threat:
  when routing is a separate service, the decision inputs themselves are sensitive.

**Design consequence:** model privacy as (a) a per-request `privacy_tier` that can be set by a
caller-run NER classifier (entity-level, beyond static rules); (b) execution-mode eligibility —
`local_only` / `split_inference_ok` / `cloud_ok` as deterministic predicates over ModelCards
tagged with hosting locality and split-inference support; (c) the actual pseudonymization / DP /
MPC mechanisms stay in the gateway (§6). GDPR/EU AI Act: the corpus supports **auditability** as
the concrete deliverable (ML-BOM provenance + `reasons` trail) — but note ⚠️ the ML-BOM source
does *not* itself name the EU AI Act, so don't overclaim regulatory specifics.

---

## 6. What production gateways do — and the boundary that falls out of it

Every production gateway implements security/privacy as **runtime hooks in the execution path**,
architecturally *separate* from routing. This is the strongest real-world confirmation of
magicrouter's purity boundary.

| Gateway | Security/privacy mechanism | Where it sits |
|---|---|---|
| **LiteLLM** 📄 | `async_pre_call_hook` (reject/modify input), `async_moderation_hook` (parallel w/ call), `post_call` (streaming = audit-only); Presidio **reversible pseudonymization** (`<CREDIT_CARD>` → restored on output), per-entity MASK/BLOCK, per-key (per-tenant) scoping | Execution hooks, lifecycle-configurable (`pre_call`/`during_call`/`post_call`) |
| **Kong AI Prompt Guard** 📄 | Deterministic PCRE allow/deny, unicode-smuggling denies, role/history-aware; **block-before-model** on match | Execution gateway (needs AI Proxy) |
| **Cloudflare AI Gateway** 📄 | Inline guard LLM (Llama Guard 3 8B, ~500ms); **fail-closed for block-mode, fail-open for flag-mode**; incompatible with streaming | Inline proxy |
| **Portkey** 📄 | 50+ declarative guardrail checks in/out, deny/suppress; PII redaction (enterprise); conditional routing + fallbacks; sub-ms for deterministic checks | Execution gateway |

Two patterns are worth lifting *into* the router because they are pure config:

1. 📄 **Per-category fail-open / fail-closed** (Cloudflare): "IS expressible as deterministic
   configuration in a routing/policy engine." When a guard signal is missing/unreachable, the
   *policy* for what to do is a magicrouter decision.
2. 📄 **Detection ≠ enforcement is architecturally separable** (Rebuff): "a detector emits a
   signal, and a separate component decides what to do with it." That separation *is*
   magicrouter's seam — **guard = detect (gateway); router = decide (library); gateway =
   enforce (execute).**

Everything else — running the guard model, masking PII, injecting DP noise, output filtering —
is stateful, per-request, model-invoking runtime work that must **not** be inside a pure
decision library.

---

## 7. Synthesis — the extended magicrouter decision model

Feature 0001 was `maximize E[quality] − λ·cost subject to m ∈ Eligible(policy)`. Security and
privacy extend **both** the hard constraint set and the ModelCard, and add a router-integrity
concern:

```
maximize   E[quality(m,t)] − λ·cost(m,t) + μ·robustness(m)      # soft: robustness as tie-breaker
subject to m ∈ Eligible(policy, security_posture, privacy_tier, injection_flag)   # HARD
           ∧ escalation(m,t) is budget-admissible for tenant/session               # anti-DoW
           ∧ ¬(input flagged critical-injection ∧ m below robustness floor)        # anti-jailbreak-routing
```

**New ModelCard attributes** (deterministic, benchmark/standard-sourced):
`jailbreak_robustness`, `injection_robustness` (independent low-FPR benchmarks, NOT vendor
self-reports), `hosting_locality` (`local`/`cloud`/region), `split_inference_ok`,
`certifications` (SOC2/ISO27001/…), `provenance` (ML-BOM ref).

**New `RoutingRequest` inputs** (produced by caller/gateway, consumed by router):
`injection_suspicion` flag/score (from a guard model), `privacy_tier` (from entity-level NER),
`tenant_id`/`session_id` + cumulative spend (for DoW predicates).

**New `RoutingDecision` outputs:** `block` (with reason), `require_pseudonymization`,
`execution_mode` (`cloud`/`split`/`local`), and per-category `fail_open`/`fail_closed`
directives — plus the existing `reasons` trail, now the compliance/audit artifact.

### The boundary table (the deliverable that answers the user's question)

| Concern | IN magicrouter (pure, deterministic) | IN caller/gateway (runtime, model-invoking) |
|---|---|---|
| Jailbreak/injection robustness | robustness **scores on ModelCards**; robustness-floor **eligibility predicate**; robustness tie-breaker | producing the scores (benchmark runs) |
| Prompt-injection detection | cheap **pattern predicates** (unicode-smuggling, known-pattern similarity); **consume** guard flag; route/block on it | **guard model** inference (PromptGuard/Llama Guard), output prevention |
| Denial-of-Wallet / cost-amp | per-tenant/session **cumulative-spend predicates**; escalation rate-limit; suffix-resistant difficulty; escalation logging | live anomaly detection, per-IP rate limiting, key hygiene |
| Privacy | `privacy_tier` + `execution_mode` eligibility; `require_pseudonymization` flag; hosting-locality predicate | NER classification, **PII masking/pseudonymization**, DP noise, MPC |
| Provider posture | certifications/provenance as **allowlist predicates** | attestation, cert verification |
| Fail-open/closed | **per-category policy config** | applying it when a guard is unreachable |

---

## 8. What would make magicrouter genuinely novel here

The feature-0001 white space was unifying cost-quality routing with sovereignty/PII policy. The
0002 evidence widens it: **no surveyed router or gateway unifies (a) security posture as a hard
eligibility dimension, (b) router-integrity defenses against denial-of-wallet, (c) entity-level
privacy execution-mode selection, and (d) a clean detect/decide/enforce seam — all as pure,
auditable, deterministic decisions.** The academic routers optimize cost-quality and are
*themselves attackable* ([2504.07113](https://arxiv.org/abs/2504.07113),
[2604.15022](https://arxiv.org/abs/2604.15022)); the gateways enforce security but don't *route*
on it. A router that is safe-by-construction (never sends a flagged input to a soft model, never
lets an adversary force escalation) and that treats every security/privacy input as a
deterministic flag it *consumes* rather than a model it *runs* — that's the contribution.

---

## 9. Sources

**✅ Verified (3-0):**
- Router routes jailbreaks to weak models; router backdoors — [2504.07113](https://arxiv.org/abs/2504.07113)
- Cost-routing = new attack surface; R2A black-box escalation — [2604.15022](https://arxiv.org/abs/2604.15022)
- Confounder-gadget router attack — [2501.01818](https://arxiv.org/abs/2501.01818)
- PRISM 3-way privacy routing; entity-level NER; deterministic gate — [2511.22788](https://arxiv.org/html/2511.22788v1)
- Routing stage as privacy leak point; PPRoute MPC routing — [2604.15728](https://arxiv.org/html/2604.15728v1)

**⚠️ Refuted (1-2):** PRISM formal DP-budget operationalizable *inside* the router — [2511.22788](https://arxiv.org/html/2511.22788v1) (take split-mode routing as in-scope, DP budget as gateway work)

**📄 Primary/standards, verification-interrupted:**
- Injection detector low-FPR failures, vendor-metric unreliability — [2501.15145](https://arxiv.org/pdf/2501.15145)
- Detector calibration/paraphrase-evasion, indirect-injection blind spot — [2606.22659](https://arxiv.org/pdf/2606.22659)
- Resource-asymmetry / controlled-release prompting (USENIX Sec 2026) — [2510.01529](https://arxiv.org/pdf/2510.01529)
- PromptGuard 2 (86M/22M mDeBERTa), LlamaFirewall layered pipeline — [2505.03574](https://arxiv.org/pdf/2505.03574) · [HF card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- MCP metadata cost-amplification (658×) — [2601.10955v2](https://arxiv.org/html/2601.10955v2)
- JailbreakBench per-model robustness — [2404.01318](https://arxiv.org/pdf/2404.01318)
- MLCommons v0.5 Jailbreak Benchmark / Resilience Gap — [MLCommons PDF](https://mlcommons.org/wp-content/uploads/2025/12/MLCommons-Security-Jailbreak-0.5.1.pdf)
- CycloneDX ML-BOM (provenance metadata) — [cyclonedx.org](https://cyclonedx.org/capabilities/mlbom/)
- Split-N-Denoise (client-side split + LDP) — [2310.09130](https://arxiv.org/abs/2310.09130)
- Denial-of-Wallet threat class — [prompt.security](https://prompt.security/vulnerabilities/denial-of-wallet-service) · [a10networks](https://www.a10networks.com/glossary/llm-unbounded-consumption/) · [layerxsecurity](https://layerxsecurity.com/generative-ai/denial-of-wallet-attacks/)
- Gateway guardrail implementations — [LiteLLM custom guardrail](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail) · [LiteLLM Presidio PII](https://docs.litellm.ai/docs/tutorials/presidio_pii_masking) · [Kong AI Prompt Guard](https://developer.konghq.com/plugins/ai-prompt-guard/) · [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/features/guardrails/) · [Portkey](https://github.com/portkey-ai/gateway) · [open-source guardrails survey](https://www.deepinspect.ai/blog/open-source-llm-guardrails)

## 10. Caveats about this run

- Stats: 6 angles → 26 sources → 127 claims; **25 reached verification, 10 confirmed 3-0, 1
  refuted**, the remainder interrupted by the session token limit mid-verify and recovered as
  📄 from the run journal (`research/deep_research_run.json`,
  `research/claims_by_source.json`). Treat 📄 as "from a primary/standards source but not
  independently cross-checked in this run."
- The injection-detection evidence is unusually *consistent* across independent primary sources
  (2501.15145, 2606.22659, 2510.01529 all converge on "detection is a model workload and is
  evadable"), so the boundary conclusion is robust even though those specific claims are 📄.
- Regulatory specifics (EU AI Act, GDPR articles) are the **thinnest** part of the corpus — the
  standards sources (ML-BOM, MLCommons, ISO/IEC 42001) support *auditability and posture
  scoring* but do not pin down statute-level requirements. Don't overclaim there.
