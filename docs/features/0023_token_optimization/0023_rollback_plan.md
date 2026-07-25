# 0023 — Token Optimization: Rollback Plan

## Risk Assessment: LOW

All changes are in the shared Python agent library. No database migrations. No API changes. No frontend changes.

## Rollback Steps

### Full Rollback

1. Revert all commits for this feature
2. Remove `tiktoken` from `agents/shared/pyproject.toml`
3. Rebuild agent Docker images: `docker compose build agent-chaos agent-owasp agent-soc2 agent-cwe`

### Partial Rollback (per mechanism)

| Mechanism | Rollback |
|-----------|----------|
| tiktoken | Remove `tiktoken` dep, revert `estimate_tokens()`/`safe_estimate_tokens()` to heuristic |
| Model-adaptive context | Change `max_findings=0` back to `max_findings=_MAX_CONTEXT_FINDINGS` in `build_prior_context()` |
| max_tokens | Remove `max_tokens` from `ModelSettings` in `_collect_llm_findings_async()` |
| Prompt caching | Remove `get_model_settings()` call, use `ModelSettings(temperature=0.1)` directly |
| Model fallback | Replace `get_model_with_fallback()` with `get_model()` in `_collect_llm_findings_async()` |
| Source context dedup | Remove `source_context` parameter passthrough (builds twice, no functional change) |
| Cost tracking | Remove `cost_usd` from `token_savings_event`, remove `estimate_cost()` calls |

## Fallback Behavior

- tiktoken gracefully degrades: if import fails, heuristic is used automatically
- Cooldown manager gracefully degrades: if all models in cooldown, primary is tried anyway
- Cost estimation returns 0.0 for unknown models (no error)
- All new fields (`cost_usd`, `actual_input_tokens`) are optional in SSE events
