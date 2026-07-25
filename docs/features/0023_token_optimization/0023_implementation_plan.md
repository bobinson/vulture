# 0023 — Universal Token Optimization

## Overview

Implement 7 universal token optimization mechanisms across the shared agent infrastructure to reduce LLM API costs by 75-85%. All 7 agents (chaos, owasp, soc2, cwe, xss, ssdf, prove) benefit automatically since they all use `run_combined_audit()` from shared.

## Mechanisms

1. **Prompt Caching via LiteLLM** — Provider-specific caching hints (Anthropic `cache_control` header). 90% discount on cached input tokens.
2. **Accurate Token Counting (tiktoken)** — Replace `len(text)//4` heuristic with `tiktoken` for OpenAI-compatible models. 5-15% better context packing.
3. **Model-Adaptive Prior Context Limits** — `build_prior_context()` auto-scales `max_findings` based on model context window via `get_max_findings()`.
4. **Response Token Budget (max_tokens)** — Set `max_tokens` on `ModelSettings` to prevent unbounded output generation. Configurable via `VULTURE_LLM_MAX_OUTPUT_TOKENS`.
5. **Model Fallback with Cooldown** — `get_model_with_fallback()` checks `CooldownManager`, tries fallback chain on failure. Prevents wasting tokens on 3x retries against failing models.
6. **Source Context Deduplication** — `_build_source_context()` called once in `run_combined_audit()`, passed through to `_collect_llm_findings()` instead of being rebuilt.
7. **Token Usage Tracking & Cost Emission** — Extract actual `input_tokens`/`output_tokens` from LLM response. Emit `cost_usd` in `token_savings` events. `COST_PER_1M_TOKENS` dict for all known models.

## Files Modified

| File | Changes |
|------|---------|
| `agents/shared/pyproject.toml` | Add `tiktoken>=0.7.0` dependency |
| `agents/shared/shared/tools/memory_client.py` | tiktoken-backed `estimate_tokens()`/`safe_estimate_tokens()`, model-adaptive `build_prior_context()` default |
| `agents/shared/shared/llm/provider.py` | `get_model_settings()`, `get_model_with_fallback()`, `estimate_cost()`, `COST_PER_1M_TOKENS` |
| `agents/shared/shared/llm/__init__.py` | Export new functions |
| `agents/shared/shared/audit_runner.py` | `max_tokens`, `source_context` passthrough, token usage extraction, cost emission, fallback model |
| `agents/shared/shared/transport/event_emitter.py` | `cost_usd` field on `token_savings_event` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VULTURE_LLM_MAX_OUTPUT_TOKENS` | `16384` | Max output tokens for LLM response budget |
| `VULTURE_TOKEN_SAFETY_MARGIN` | `1.2` | Safety margin for heuristic token estimation (tiktoken uses 1.1x) |
