# 0002 — Security-, privacy-, and injection-aware routing dimensions

**Author**: bobinson
**Status**: PLAN (design phase — research complete)
**Created**: 2026-07-02
**Depends on**: 0001 (router core — contracts, eligibility filter, cost-quality optimizer)
**Research basis**: `research/0002_research_report.md` (deep-research run: 6 angles, 26 sources,
127 claims, 10 confirmed 3-0, 1 refuted, remainder recovered from journal as primary-unverified).
Raw claims: `research/claims_by_source.json`; run log: `research/deep_research_run.json`.

## Goal

Extend magicrouter beyond cost + capability so that **security and privacy are first-class
routing dimensions**, and prompt-injection risk is handled *at the routing layer to the extent a
pure decision engine can* — without ever making an LLM call inside the router.

The extended decision model (0001 → 0002):

```
maximize   E[quality(m,t)] − λ·cost(m,t) + μ·robustness(m)                        # soft
subject to m ∈ Eligible(policy, security_posture, privacy_tier, injection_flag)   # HARD
           ∧ escalation(m,t) is budget-admissible for tenant/session               # anti-denial-of-wallet
           ∧ ¬(input flagged critical-injection ∧ m below robustness floor)        # anti-jailbreak-routing
```

## Why (the three findings that force this)

1. **A cost/quality-only router is actively unsafe.** Preference-trained routers route jailbreak
   attempts to *weaker*, less-robust (cheaper) models (2504.07113, ✅). Security must be an
   explicit dimension that can override the cost objective, not an emergent property.
2. **The router is itself an attack surface.** Denial-of-wallet / cost-amplification: black-box
   adversarial suffixes force expensive-model escalation (R2A 2604.15022 ✅; confounder gadgets
   2501.01818 ✅; ~2.7–2.9× cost, ~$0.98 to train the attack). Perplexity filtering does **not**
   defend against it; static budget caps only throttle.
3. **The purity boundary is confirmed by the whole ecosystem.** Injection detection good enough
   to gate on is a model-inference workload (100M+ params or an LLM), and every production
   gateway runs it as an execution-path hook separate from routing. magicrouter *consumes* guard
   verdicts as flags; it does not run guards.

## Scope

### In scope (pure, deterministic, no LLM call)

1. **New ModelCard attributes** — `jailbreak_robustness`, `injection_robustness` (numeric,
   sourced from *independent* low-FPR benchmarks — never vendor self-reports),
   `hosting_locality`, `split_inference_ok`, `certifications`, `provenance` (ML-BOM ref).
2. **New hard eligibility predicates** —
   - robustness floor: input flagged critical-injection ⇒ eligible pool restricted to
     `injection_robustness ≥ threshold`;
   - privacy execution-mode: `privacy_tier` → `execution_mode ∈ {cloud, split, local}` filtered
     against ModelCard `hosting_locality` / `split_inference_ok`;
   - provider allowlist by `certifications` / `provenance`.
3. **Anti-denial-of-wallet predicates** — per-tenant/session cumulative-spend ceilings;
   escalation admissibility check; suffix-resistant difficulty estimate (ignore trailing/
   low-salience tokens); every escalation recorded in `reasons`.
4. **New `RoutingRequest` inputs** (produced by caller, consumed here) — `injection_suspicion`
   flag/score, `privacy_tier`, `tenant_id`/`session_id` + cumulative spend.
5. **New `RoutingDecision` outputs** — `block` (+reason), `require_pseudonymization`,
   `execution_mode`, per-category `fail_open`/`fail_closed` directives; extended `reasons` audit
   trail (the compliance artifact).
6. **Cheap deterministic input predicates** — unicode-smuggling detection (zero-width /
   bidirectional control chars, per Kong's pattern set) and known-pattern similarity, honestly
   documented as *partial* first-filter, NOT a substitute for a guard model.
7. **Per-category fail-open/fail-closed policy config** (the Cloudflare pattern, expressible as
   deterministic config).

### Out of scope (belongs in caller/gateway — documented, not built here)

- Running any guard model (PromptGuard/Llama Guard), perplexity scoring, output filtering.
- PII masking / reversible pseudonymization, differential-privacy noise, MPC-encrypted routing.
- NER classification that produces `privacy_tier` (the router consumes the resulting tier).
- Live per-IP rate limiting, credential/key hygiene, anomaly detection.

The **detect / decide / enforce seam** is the organizing principle: guard = detect (gateway);
magicrouter = decide (library); gateway = enforce (execute).

## Phases (E2E tests first, per project workflow)

### Phase 1 — ModelCard + RoutingRequest/Decision schema extension

- E2E tests pinning the extended contracts (new fields serialize; absent fields default to
  backward-compatible no-op so 0001 decisions are unchanged).
- Add the attributes/inputs/outputs above to `contracts.py`. No new predicate behavior yet.
- **Gate**: 0001 decision tests unchanged with new fields defaulted/absent.

### Phase 2 — Security eligibility predicates (robustness floor + posture allowlist)

- E2E tests: critical-injection input excludes below-floor models; certification allowlist
  excludes non-compliant providers; `reasons` names the excluding predicate.
- Implement predicates in `policy.py`; robustness scores loaded onto ModelCards (seed from
  JailbreakBench / MLCommons format; jailbreak-resistance and injection-robustness kept as
  *separate* dimensions per the research).
- **Gate**: a flagged-injection request can never be routed to a below-floor model (the
  safe-by-construction invariant).

### Phase 3 — Anti-denial-of-wallet predicates

- E2E tests: cumulative-spend ceiling blocks escalation; escalation rate-limit; suffix-resistant
  difficulty ignores an appended confounder gadget (regression test using a synthetic suffix);
  every escalation appears in `reasons`.
- Implement per-tenant/session spend accounting inputs + escalation-admissibility predicate.
- **Gate**: appending a known confounder-style suffix does not change the chosen model in
  suffix-resistant mode; over-budget escalation is refused.

### Phase 4 — Privacy execution-mode routing + fail-open/closed config

- E2E tests: `privacy_tier=critical` ⇒ `execution_mode=local`, cloud-only pool empty ⇒ `block`;
  `high` ⇒ `require_pseudonymization=true` + cloud allowed; per-category fail-closed on missing
  guard flag; `split_inference_ok` filtering.
- Implement `execution_mode` selection + `require_pseudonymization` + fail-open/closed policy.
- **Gate**: no `critical` prompt is ever assigned a cloud-only model; missing guard flag under a
  fail-closed category yields `block`.

### Phase 5 — Cheap deterministic injection predicates (partial, honest)

- E2E tests: unicode-smuggling patterns flagged; benign traffic not flagged (low-FPR intent);
  documentation asserts partial coverage.
- Implement pattern predicates; wire `injection_suspicion` flag consumption end-to-end.
- **Gate**: predicates raise the suspicion flag on the smuggling corpus without firing on a
  benign corpus; behavior is *advisory* (feeds Phase 2 floor), never sole enforcement.

## Vulture integration (separate vulture-side feature doc when built)

Vulture is consumer #1: source-classification → `privacy_tier` (customer-code residency /
air-gapped → `local`); vulture's own audit findings can seed model robustness expectations. All
behind the same default-off `VULTURE_ROUTER_ENABLED` flag; new sub-knobs (e.g.
`VULTURE_ROUTER_INJECTION_FLOOR`, `VULTURE_ROUTER_DOW_BUDGET`) default to permissive/off.

## Testing

- E2E business-logic tests first (`magicrouter/tests/e2e/`); the **safe-by-construction
  invariants** (no flagged input to a soft model; no over-budget escalation; no critical prompt
  to cloud) are the contract and must never be weakened to make code pass.
- Unit tests per predicate; import-isolation check still holds (no vulture imports; and no
  LLM-client imports inside the router — a lint asserting the purity boundary).
- Adversarial regression corpus: synthetic confounder suffixes + unicode-smuggling samples.

## Risks

| Risk | Mitigation |
|---|---|
| Robustness scores unavailable per-model (MLCommons v0.5 anonymized; v1.0 Q1 2026) | Ship the *attribute + predicate*; allow null → conservative default (treat unknown as below-floor for critical inputs); update scores as benchmarks publish |
| Deterministic injection predicates give false confidence | Documented as *partial*; the real signal is the caller's guard flag; predicates are advisory inputs to the floor, never sole enforcement |
| Suffix-resistance heuristic degrades legitimate routing | Gate behind a mode flag; regression-test both attack suppression and benign-quality preservation |
| Over-claiming regulatory compliance (EU AI Act/GDPR) | Corpus supports *auditability + posture scoring*, not statute specifics; docs claim only that, per report §5/§10 |
| Scope creep into running guards / masking PII | Out-of-scope table + purity lint; detect/decide/enforce seam is the scope lock |

## Open questions

1. Score source for robustness attributes at ship time — JailbreakBench vs MLCommons v1.0 (Q1
   2026) vs an internal harness; affects when Phase 2's floor is meaningfully populated.
2. Is the hosted/sidecar form (PPRoute-style third-party routing) in magicrouter's future? If so,
   the routing *inputs* become sensitive and MPC-routing is a real (gateway-side) concern; if
   library-only/in-process, it is not.
