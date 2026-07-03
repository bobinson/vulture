# 0001 — magicrouter router core: rollback plan

## Design principles that make rollback cheap

1. **Default-off integration.** All vulture wiring sits behind `VULTURE_ROUTER_ENABLED`
   (default `false`). With the flag off, `audit_runner.py` / `provider.py` behavior is
   byte-identical to pre-magicrouter — verified by an explicit E2E no-op test.
2. **The library is additive.** `magicrouter/` is a self-contained package with zero imports
   from vulture code, and vulture's only dependency on it is the single adapter module
   `agents/shared/shared/llm/routing_adapter.py`.
3. **Phase 1 is behavior-preserving by contract.** Vulture's `provider.py` public functions
   (`get_model`, `get_model_with_fallback`, `get_context_window`, `estimate_cost`, …) keep
   their signatures and semantics; the adapter is proven equivalent by tests before any
   caller switches.

## Rollback procedures

### Runtime rollback (no code change)

Set `VULTURE_ROUTER_ENABLED=false` (or simply unset it). All agents fall back to the
existing `provider.py` resolution path. This is the one-release safety valve, mirroring the
pattern of `VULTURE_CWE_DISABLE_DANGEROUS_FN` (vulture feature 0060).

### Phase 2/3 rollback (remove integration, keep library)

1. Delete `agents/shared/shared/llm/routing_adapter.py`.
2. Revert the `route_model()` call sites in `agents/shared/shared/audit_runner.py`
   (the LLM-phase model selection returns to `get_model_with_fallback()`).
3. Remove `VULTURE_ROUTER_*` entries from vulture's `.env.example` and `CLAUDE.md`.
4. Run: `cd agents/shared && python -m pytest tests/unit tests/e2e -q` — must be green.

### Full rollback (remove the project)

1. Steps above, plus `git rm -r magicrouter/` (excluding this docs tree if the history is
   worth keeping — see below).
2. Remove the magicrouter test job from `.github/workflows/ci.yml` (if added).
3. Keep the feature docs (including `research/`) — feature docs are historical record per
   project convention; mark the status doc `ROLLED BACK` with the reason and the benchmark
   numbers that motivated it.

## Rollback triggers

- Phase 1 adapter-equivalence tests cannot be made green without changing `provider.py`
  semantics → stop, revisit design (do not ship a behavior change disguised as a refactor).
- Phase 3 benchmark: router fails to beat/match the Best-Single baseline on the audit
  corpus → roll back the optimizer wiring only; the Phase 2 eligibility filter stands on
  its own merits (compliance correctness, not cost optimization).
- Any agent-service startup or audit-pipeline regression attributable to the adapter →
  `VULTURE_ROUTER_ENABLED=false` immediately, then diagnose offline.

## Data / schema impact

None. Feature 0001 touches no database tables, no migrations, no SSE event types. (A
per-source policy DB field is explicitly deferred to a follow-up feature; v1 policy is
env/config-only.)
