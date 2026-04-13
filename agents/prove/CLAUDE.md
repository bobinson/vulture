# Prove Agent — Security Verification

Security-proving agent that verifies findings against live staging targets. Part of the Vulture compliance audit platform.

## Architecture

```
run_prove()
  Phase 1: Staging URL setup
  Phase 2: Call discover agent via HTTP SSE (discover_client.py)
           → receives SiteMap + learnings_context + findings
  Phase 3: Prove findings           # Security verification probes
```

Discovery (plugins, source analysis, Playwright, LLM endpoint suggestion) is owned by **discover_agent**. Prove calls discover via HTTP — zero Python import dependency.

## Key Modules

- `agent.py` — Pipeline orchestrator, `_BackgroundDiscovery` (HTTP call to discover), `_run_prove_pipeline()`
- `discover_client.py` — HTTP SSE client for discover agent (`call_discover()`)
- `runner.py` — Finding verification with timeout, phase management
- `api_prober.py` — HTTP probing engine for verification
- `llm_helper.py` — LLM-assisted proof generation
- `strategies/` — Verification strategies (OWASP, base, shared, rule_analyzer)
- `protocols/` — Multi-protocol support (detection, dispatcher, fallback, JSON-RPC, WS)
- `techniques.py` — Technique chains for finding categories
- `learning_store.py` — In-memory session learnings (dataclass definitions only, no persistence)
- `prove_learnings.py` — Slim session-only `ProveSessionLearnings` for verification tracking
- `discovery.py` — Backward-compatible shim (re-exports + `discover_incremental()`)
- `plugins/__init__.py` — Backward-compatible shim (re-exports shared discovery types)

## Discover Integration

Prove calls discover via `discover_client.call_discover()`:
- Sends POST to `VULTURE_DISCOVER_URL` (default `http://agent-discover:28008`)
- Streams SSE events: `discover_result` (SiteMap + learnings_context) and `finding` events
- Returns `(SiteMap | None, str, list[dict])` — site map, learnings context, findings

## Code Quality

- Cyclomatic complexity < 10 per function (use `radon cc -nc`)
- All tests: `python3 -m pytest tests/ -v`
- Zero dependency on `discover_agent` at Python import level
