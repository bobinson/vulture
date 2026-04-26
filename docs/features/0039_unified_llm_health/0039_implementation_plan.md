# 0039 — Unified LLM Health Probe + Degraded-Mode Signaling

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans`. Follow `CLAUDE.md §Development Workflow (MANDATORY)` — E2E tests written FIRST per phase. Each phase is independently mergeable; ship phases 1+2+3 as v1.0 (the canonical check + agent surface + backend aggregator) and 4+5+6 as v1.1 (launcher, per-audit, frontend). Phases 7+8 are hardening polish.

## Goal

Replace today's Ollama-only LLM preflight with a single, provider-agnostic health probe that:

1. **Covers every supported LLM backend uniformly**: OpenAI cloud, Anthropic cloud, Google Gemini cloud, Ollama, LM Studio, vLLM, LocalAI, generic OpenAI-compatible endpoints, and LiteLLM-aggregated providers.
2. **Confirms BOTH endpoint reachability AND model availability** — not just "endpoint up" but "the configured model is loaded/available to your account".
3. **Emits one canonical message format** consumed verbatim across the agent `/health` endpoint, the backend `/api/llm/health` aggregator, the bare-metal launcher banner, the per-audit-creation response, and the frontend degraded-mode banner. Same string, every surface.
4. **Marks audits with `degraded_reason`** when the LLM was unreachable so the UI surfaces a clear yellow warning instead of a successful-looking skills-only audit.
5. **Optionally refuses to start audits** when `VULTURE_REQUIRE_LLM=true` (for CI / production environments where skills-only output would be a regression).

The fix has minimal blast radius (one new Python module + one new backend endpoint + one new column + one frontend component) and zero impact on users who already have working LLM configs.

## Non-Goals

- Not refactoring `audit_runner.py`'s LLM phase logic. The existing in-flight error catch (lines 996-1000) stays.
- Not changing how agents call LLMs — `provider.py` is untouched.
- Not adding a "test this LLM key" interactive UI — the health probe runs automatically on each integration point.
- Not reaching into the `cooldown_manager` — health probe is a separate concern from per-call cooldown.
- Not adding model-quality probes (latency benchmarks, output validation). Health is reachability + model presence only.

## Background — what motivated this feature

Today's LLM preflight is **Ollama-only** (`backend/internal/localdev/launcher.go:142-160`). For LM Studio, vLLM, LocalAI, OpenAI cloud, Anthropic cloud, and Gemini cloud:

- No startup-time check
- No per-audit preflight
- Failures surface only as buried `text_message` SSE events from `audit_runner.py:996-1000`
- Audit completes "successfully" with skills-only findings; user has no UI signal that LLM phase was skipped

Empirical example from this session: user ran `./scripts/vulture.sh dev lmstudio` while LM Studio's local server wasn't running. Audit `fe2319d8…` completed in 1.2 seconds with 1258 findings (skills-only), no banner, no warning. The `LLM analysis failed (connection): Connection refused` text-message was emitted but invisible to anyone not tailing the SSE stream.

Per `CLAUDE.md §Code Quality Rules` ("100% test coverage"; "ISO 26262 safety"): silent functional degradation is a safety concern. A user expecting LLM analysis is getting skills-only without informed consent.

## Architecture — one canonical implementation, six call sites

```
                              ┌──────────────────────────────────┐
                              │  agents/shared/shared/llm/       │
                              │       health.py                  │
                              │   check_llm_health()             │  ← canonical implementation
                              │   LLMHealthStatus dataclass      │
                              │   .message() canonical string    │
                              └─────────────┬────────────────────┘
                                            │
        ┌───────────────────────┬───────────┼────────────┬──────────────┐
        │                       │           │            │              │
        ▼                       ▼           ▼            ▼              ▼
┌───────────────┐       ┌───────────────┐  ┌──────────────────┐  ┌────────────────┐
│ Agent         │       │ Backend       │  │ Bare-metal       │  │ Per-audit      │
│ /health       │       │ /api/llm/     │  │ launcher banner  │  │ preflight      │
│ endpoint      │       │ health        │  │ (Go calls one    │  │ (audit_handler │
│ (Python)      │       │ aggregator    │  │ agent's /health) │  │ .Create)       │
│               │       │ (5s LRU)      │  │                  │  │                │
└───────────────┘       └─────┬─────────┘  └──────────────────┘  └───────┬────────┘
                              │                                          │
                              ▼                                          ▼
                         ┌─────────────────────────────────────────────────┐
                         │  Frontend                                        │
                         │  - useLLMHealth() hook (polls /api/llm/health)   │
                         │  - LLMDegradedBanner (renders when audit's       │
                         │    degraded_reason field is set, OR pre-submit   │
                         │    when /api/llm/health says reachable=false)    │
                         └─────────────────────────────────────────────────┘

Database:
  audits.degraded_reason TEXT NOT NULL DEFAULT ''
  ← populated at audit-creation time by per-audit preflight
```

**Single source of truth**: every surface above derives its message from `LLMHealthStatus.message()` — produced once in Python, propagated as a string through agent SSE events, backend JSON responses, audit DB column, and frontend props. The user sees the same wording wherever they look.

## Provider/aggregator coverage matrix

| Provider | Probe | Auth | Detection rule | Model-loaded check |
|---|---|---|---|---|
| **OpenAI cloud** | `GET https://api.openai.com/v1/models` | `Authorization: Bearer $OPENAI_API_KEY` | `OPENAI_API_KEY` set, no `OPENAI_BASE_URL`, no Anthropic/Gemini-specific marker | model id appears in `data[].id` (filtered) |
| **Anthropic cloud** | `POST https://api.anthropic.com/v1/messages` (1-token probe — Anthropic has no GET /models) | `x-api-key: $ANTHROPIC_API_KEY` + `anthropic-version: 2023-06-01` | `ANTHROPIC_API_KEY` set OR `claude` in model name | 200 OK on minimal probe; 404 means model not available |
| **Google Gemini cloud** | `GET https://generativelanguage.googleapis.com/v1beta/models?key=$GEMINI_API_KEY` | query param | `GEMINI_API_KEY` set OR `gemini` in model name | model name appears in `models[].name` |
| **Ollama** (local) | `GET $OLLAMA_API_BASE/api/tags` (default `http://localhost:11434`) | none | model name in known Ollama list (`qwen3:*`, `llama3.2`, `mistral`) OR `OLLAMA_API_BASE` set OR `ollama` in model name | model name appears in `models[].name` |
| **LM Studio** | `GET $OPENAI_BASE_URL/models` | none (LM Studio doesn't require auth by default) | `OPENAI_BASE_URL` set, port 1234 (heuristic) | model id appears in `data[].id` |
| **vLLM** | `GET $OPENAI_BASE_URL/models` | optional bearer | `OPENAI_BASE_URL` set, port 8000 (heuristic) | model id appears in `data[].id` |
| **LocalAI** | `GET $OPENAI_BASE_URL/models` | optional bearer | `OPENAI_BASE_URL` set, port 8080 (heuristic) | model id appears in `data[].id` |
| **Generic OpenAI-compatible** | `GET $OPENAI_BASE_URL/models` | optional bearer | `OPENAI_BASE_URL` set, port not matching above | model id appears in `data[].id` |
| **LiteLLM aggregator** | falls through to underlying provider | depends | model name with `litellm/` prefix | provider-specific |
| **Disabled** | n/a | n/a | `VULTURE_USE_LLM != "true"` | n/a — returns `disabled` status |

Detection precedence (matches `provider.py`'s actual runtime logic so health probe answers what's *actually* reachable, not what's nominally configured):

```
1. VULTURE_USE_LLM != "true"        → "disabled"
2. OPENAI_BASE_URL set               → openai-compatible (LM Studio / vLLM / LocalAI / generic)
3. "claude" in model OR ANTHROPIC_API_KEY → "anthropic"
4. "gemini" in model OR GEMINI_API_KEY    → "gemini"
5. model in Ollama list OR OLLAMA_API_BASE OR "ollama" in model → "ollama"
6. OPENAI_API_KEY set                → "openai"
7. otherwise                         → "unknown"
```

This precedence intentionally mirrors `agents/shared/shared/llm/provider.py:25-50` so the health probe never disagrees with the actual call routing.

## Tech stack

- **httpx ≥ 0.27** — already a project dependency. All probes use `httpx.AsyncClient` with a 3s default timeout.
- **dataclasses** — stdlib. `LLMHealthStatus` is a frozen-ish dataclass.
- No new Python deps.
- Backend Go: stdlib `net/http` for the aggregator + `pgx` (already used) for the migration.
- No new infrastructure dependencies.

## Glossary

| Term | Meaning |
|---|---|
| **Reachable** | The LLM endpoint responded within timeout AND the configured model is loaded/available. |
| **Provider** | The vendor or aggregator class: openai, anthropic, gemini, ollama, lmstudio, vllm, localai, openai-compatible, litellm-aggregator, disabled, unknown. |
| **Endpoint** | The base URL probed (or `(default cloud)` for cloud providers without a custom URL). |
| **Degraded mode** | Audit ran but LLM phase was skipped because `reachable=false`. Findings come from skill-based pattern matching only. |
| **Canonical message** | The exact string produced by `LLMHealthStatus.message()`. Used verbatim by every surface. |
| **Strict mode** | When `VULTURE_REQUIRE_LLM=true`, the system refuses to start audits that would otherwise run in degraded mode. Default off. |

## Configuration surface

### Existing env vars (read by health probe — no changes)

```
VULTURE_USE_LLM        Default "false". "true" enables LLM phase.
VULTURE_LLM_MODEL      Model preference; resolves via provider.py:MODEL_MAP.
OPENAI_API_KEY         OpenAI cloud auth.
OPENAI_BASE_URL        Custom OpenAI-compatible endpoint (LM Studio, vLLM, LocalAI).
ANTHROPIC_API_KEY      Anthropic cloud auth.
GEMINI_API_KEY         Google Gemini auth.
OLLAMA_API_BASE        Ollama URL; default http://localhost:11434.
```

### New env vars

```
VULTURE_REQUIRE_LLM    Default "false". When "true", any audit that would run
                       degraded (LLM unreachable) is rejected at /api/audits POST
                       with HTTP 503 + canonical message. Used for CI / production.
VULTURE_LLM_HEALTH_TIMEOUT  Probe timeout in seconds. Default "3.0".
VULTURE_LLM_HEALTH_CACHE_TTL  Aggregator cache TTL in seconds. Default "5".
```

### config.ini precedence

```ini
[llm]
require    = false        # mirrors VULTURE_REQUIRE_LLM
timeout    = 3.0          # mirrors VULTURE_LLM_HEALTH_TIMEOUT
cache_ttl  = 5            # mirrors VULTURE_LLM_HEALTH_CACHE_TTL
```

CLI flag > env var > config.ini.

## Phase overview

| Phase | Scope | Effort | Independently shippable | v1.x |
|---|---|---|---|---|
| **1** | Canonical `shared/llm/health.py` + 6 provider probes + tests | ~1.5 days | yes | v1.0 |
| **2** | Wire into agent `/health` endpoint | ~0.5 day | yes | v1.0 |
| **3** | Backend `/api/llm/health` aggregator + LRU cache | ~0.5 day | yes | v1.0 |
| **4** | Bare-metal launcher: replace Ollama-only with generic check | ~0.5 day | yes | v1.1 |
| **5** | `audits.degraded_reason` column + per-audit preflight | ~0.5 day | yes | v1.1 |
| **6** | Frontend banner + `useLLMHealth` hook | ~0.5 day | yes | v1.1 |
| **7** | Per-provider test fixtures + 6×7 = ~42 unit tests | ~1 day | yes | v1.0 cut |
| **8** | `VULTURE_REQUIRE_LLM` strict mode + 503 rejection | ~0.5 day | yes | v1.2 |

**v1.0 cut-line**: Phases 1+2+3+7. Delivers the canonical probe and the surfaces that consume it server-side. Bare-metal launcher and frontend banner follow in v1.1. Total v1.0 effort: ~3.5 days.

**v1.1**: Phases 4+5+6. Brings the degraded-mode signal end-to-end into the user-facing UI.

**v1.2**: Phase 8. Strict-mode enforcement for environments where skills-only output is a regression (CI integration, regulated environments).

---

# Phase 1 — Canonical health probe (`agents/shared/shared/llm/health.py`)

**Goal**: One Python module with one public function (`check_llm_health()`) and one dataclass (`LLMHealthStatus`). Every other surface consumes this. Six provider-specific probes share one HTTP error-classification helper.

## 1.1 — `LLMHealthStatus` dataclass

```python
# agents/shared/shared/llm/health.py
"""Provider-agnostic LLM health probe.

Used uniformly by:
  - Agent /health endpoint
  - Backend /api/llm/health aggregator
  - Bare-metal launcher banner
  - Per-audit preflight
Producing one canonical message string consumed verbatim by every surface.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import asdict, dataclass, field
from typing import Any
import logging

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = float(os.environ.get("VULTURE_LLM_HEALTH_TIMEOUT", "3.0"))


@dataclass
class LLMHealthStatus:
    """Outcome of probing the configured LLM provider.

    Fields:
        provider:  Provider class. One of "openai" | "anthropic" | "gemini"
                   | "ollama" | "lmstudio" | "vllm" | "localai" |
                   "openai-compatible" | "litellm-aggregator" | "disabled" |
                   "unknown".
        endpoint:  Base URL probed, or "(default cloud)" for cloud without
                   custom URL.
        model:     Configured VULTURE_LLM_MODEL; "" if none.
        reachable: True iff endpoint responded within timeout AND model is
                   loaded/available.
        error:     One-line cause when reachable=False; "" otherwise.
        detail:    Provider-specific extras: model_count, available models
                   (capped to 10), version, latency_ms, etc.
    """
    provider: str
    endpoint: str
    model: str
    reachable: bool
    error: str
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        """Plain dict for JSON serialization on the agent /health endpoint."""
        return asdict(self)

    def message(self) -> str:
        """Canonical user-visible message. Used verbatim by every surface.

        Three shapes — invariant across providers:

          Reachable:
            LLM ready: {provider} ({model}) at {endpoint}

          Unreachable:
            LLM unavailable: {provider} ({model_or_no_model}) at {endpoint_or_default} — {error}. Audit will run skills-only.

          Disabled:
            LLM disabled (VULTURE_USE_LLM != true). Audit will run skills-only.
        """
        if self.provider == "disabled":
            return "LLM disabled (VULTURE_USE_LLM != true). Audit will run skills-only."
        if self.reachable:
            return f"LLM ready: {self.provider} ({self.model}) at {self.endpoint}"
        model = self.model if self.model else "no model"
        endpoint = self.endpoint if self.endpoint else "default"
        return (
            f"LLM unavailable: {self.provider} ({model}) at {endpoint} "
            f"— {self.error}. Audit will run skills-only."
        )
```

## 1.2 — Public entry point: `check_llm_health()`

```python
async def check_llm_health(timeout: float = DEFAULT_TIMEOUT) -> LLMHealthStatus:
    """Probe whichever provider VULTURE_USE_LLM/VULTURE_LLM_MODEL/* points at.

    Detection precedence MUST mirror provider.py routing logic so the health
    probe never disagrees with the actual call path:

      1. VULTURE_USE_LLM != "true"             → disabled
      2. OPENAI_BASE_URL set                   → openai-compatible (LM Studio etc.)
      3. "claude" in model OR ANTHROPIC_API_KEY → anthropic
      4. "gemini" in model OR GEMINI_API_KEY    → gemini
      5. ollama-list match OR OLLAMA_API_BASE OR "ollama" in model → ollama
      6. OPENAI_API_KEY set                     → openai
      7. otherwise                              → unknown
    """
    if os.environ.get("VULTURE_USE_LLM", "false").lower() != "true":
        return LLMHealthStatus(
            provider="disabled", endpoint="", model="", reachable=False,
            error="LLM disabled by config", detail={},
        )

    model = os.environ.get("VULTURE_LLM_MODEL", "")
    base_url = os.environ.get("OPENAI_BASE_URL", "")

    if base_url:
        return await _probe_openai_compatible(base_url, model, timeout)
    if "claude" in model.lower() or os.environ.get("ANTHROPIC_API_KEY"):
        return await _probe_anthropic(model, timeout)
    if "gemini" in model.lower() or os.environ.get("GEMINI_API_KEY"):
        return await _probe_gemini(model, timeout)
    if (
        model in _OLLAMA_NATIVE_MODELS
        or os.environ.get("OLLAMA_API_BASE")
        or "ollama" in model.lower()
    ):
        return await _probe_ollama(model, timeout)
    if os.environ.get("OPENAI_API_KEY"):
        return await _probe_openai(model, timeout)

    return LLMHealthStatus(
        provider="unknown", endpoint="", model=model, reachable=False,
        error="cannot infer provider from VULTURE_LLM_MODEL and env",
        detail={},
    )


_OLLAMA_NATIVE_MODELS: frozenset[str] = frozenset({
    "qwen3:1.7b", "qwen3:8b", "qwen3:14b",
    "llama3.2", "mistral",
})
```

## 1.3 — Per-provider probes

### 1.3.1 OpenAI-compatible (LM Studio / vLLM / LocalAI / generic)

```python
def _detect_compatible_flavour(base_url: str) -> str:
    """Heuristic provider name based on port. Falls back to 'openai-compatible'."""
    if ":1234" in base_url:
        return "lmstudio"
    if ":8000" in base_url:
        return "vllm"
    if ":8080" in base_url:
        return "localai"
    return "openai-compatible"


async def _probe_openai_compatible(
    base_url: str, model: str, timeout: float,
) -> LLMHealthStatus:
    flavour = _detect_compatible_flavour(base_url)
    bearer = os.environ.get("OPENAI_API_KEY")  # optional
    return await _probe_openai_models_endpoint(
        provider=flavour, base_url=base_url.rstrip("/"),
        model=model, timeout=timeout, bearer=bearer,
    )


async def _probe_openai(model: str, timeout: float) -> LLMHealthStatus:
    return await _probe_openai_models_endpoint(
        provider="openai", base_url="https://api.openai.com/v1",
        model=model, timeout=timeout,
        bearer=os.environ.get("OPENAI_API_KEY"),
    )


async def _probe_openai_models_endpoint(
    provider: str, base_url: str, model: str, timeout: float,
    bearer: str | None = None,
) -> LLMHealthStatus:
    """Shared GET /models probe for OpenAI cloud + all OpenAI-compatible servers."""
    url = f"{base_url}/models"
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as c:
            r = await c.get(url)
            return _interpret_models_response(provider, base_url, model, r)
    except httpx.ConnectError:
        return LLMHealthStatus(
            provider=provider, endpoint=base_url, model=model, reachable=False,
            error=f"connection refused at {base_url}", detail={},
        )
    except httpx.TimeoutException:
        return LLMHealthStatus(
            provider=provider, endpoint=base_url, model=model, reachable=False,
            error=f"timeout after {timeout}s", detail={},
        )
    except httpx.HTTPError as exc:
        return LLMHealthStatus(
            provider=provider, endpoint=base_url, model=model, reachable=False,
            error=f"{type(exc).__name__}: {exc}", detail={},
        )


def _interpret_models_response(
    provider: str, base_url: str, model: str, r: httpx.Response,
) -> LLMHealthStatus:
    if r.status_code == 401:
        return LLMHealthStatus(provider, base_url, model, False,
                               "auth: invalid or missing API key", {})
    if r.status_code == 403:
        return LLMHealthStatus(provider, base_url, model, False,
                               "auth: forbidden (key lacks permission)", {})
    if r.status_code == 429:
        return LLMHealthStatus(provider, base_url, model, False,
                               "rate limit / quota exceeded", {})
    if r.status_code >= 500:
        return LLMHealthStatus(provider, base_url, model, False,
                               f"upstream HTTP {r.status_code}", {})
    if r.status_code >= 400:
        return LLMHealthStatus(provider, base_url, model, False,
                               f"HTTP {r.status_code}", {})
    try:
        data = r.json().get("data", [])
    except ValueError:
        return LLMHealthStatus(provider, base_url, model, False,
                               "endpoint returned non-JSON", {})
    ids = [m.get("id", "") for m in data if isinstance(m, dict)]
    model_loaded = (not model) or any(model in mid for mid in ids if mid)
    return LLMHealthStatus(
        provider=provider, endpoint=base_url, model=model, reachable=model_loaded,
        error="" if model_loaded else (
            f"model {model!r} not loaded; available: {ids[:3]}"
        ),
        detail={"model_count": len(ids), "models": ids[:10]},
    )
```

### 1.3.2 Anthropic cloud

Anthropic does not expose `GET /v1/models`; the cheapest probe is a 1-token messages call.

```python
async def _probe_anthropic(model: str, timeout: float) -> LLMHealthStatus:
    endpoint = "api.anthropic.com"
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return LLMHealthStatus(
            "anthropic", endpoint, model, False,
            "ANTHROPIC_API_KEY not set", {},
        )
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model or "claude-3-5-haiku-20241022",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as c:
            r = await c.post("https://api.anthropic.com/v1/messages", json=body)
            if r.status_code == 401:
                return LLMHealthStatus("anthropic", endpoint, model, False,
                                       "auth: invalid x-api-key", {})
            if r.status_code == 403:
                return LLMHealthStatus("anthropic", endpoint, model, False,
                                       "auth: forbidden (key lacks permission)", {})
            if r.status_code == 404:
                return LLMHealthStatus("anthropic", endpoint, model, False,
                                       f"model {model!r} not available", {})
            if r.status_code == 429:
                return LLMHealthStatus("anthropic", endpoint, model, False,
                                       "rate limit / quota exceeded", {})
            if r.status_code >= 500:
                return LLMHealthStatus("anthropic", endpoint, model, False,
                                       f"upstream HTTP {r.status_code}", {})
            r.raise_for_status()
            return LLMHealthStatus("anthropic", endpoint, model, True, "", {})
    except httpx.ConnectError:
        return LLMHealthStatus("anthropic", endpoint, model, False,
                               "connection refused", {})
    except httpx.TimeoutException:
        return LLMHealthStatus("anthropic", endpoint, model, False,
                               f"timeout after {timeout}s", {})
    except httpx.HTTPError as exc:
        return LLMHealthStatus("anthropic", endpoint, model, False,
                               f"{type(exc).__name__}: {exc}", {})
```

### 1.3.3 Google Gemini cloud

```python
async def _probe_gemini(model: str, timeout: float) -> LLMHealthStatus:
    endpoint = "generativelanguage.googleapis.com"
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return LLMHealthStatus(
            "gemini", endpoint, model, False,
            "GEMINI_API_KEY not set", {},
        )
    url = f"https://{endpoint}/v1beta/models?key={key}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            if r.status_code in (401, 403):
                return LLMHealthStatus("gemini", endpoint, model, False,
                                       "auth: invalid GEMINI_API_KEY", {})
            if r.status_code == 429:
                return LLMHealthStatus("gemini", endpoint, model, False,
                                       "rate limit / quota exceeded", {})
            if r.status_code >= 500:
                return LLMHealthStatus("gemini", endpoint, model, False,
                                       f"upstream HTTP {r.status_code}", {})
            r.raise_for_status()
            try:
                names = [m.get("name", "") for m in r.json().get("models", [])]
            except ValueError:
                return LLMHealthStatus("gemini", endpoint, model, False,
                                       "endpoint returned non-JSON", {})
            ok = (not model) or any(model in n for n in names if n)
            return LLMHealthStatus(
                "gemini", endpoint, model, ok,
                "" if ok else f"model {model!r} not in account; first few: {names[:3]}",
                {"model_count": len(names), "models": [n.split("/")[-1] for n in names[:10]]},
            )
    except httpx.ConnectError:
        return LLMHealthStatus("gemini", endpoint, model, False,
                               "connection refused", {})
    except httpx.TimeoutException:
        return LLMHealthStatus("gemini", endpoint, model, False,
                               f"timeout after {timeout}s", {})
    except httpx.HTTPError as exc:
        return LLMHealthStatus("gemini", endpoint, model, False,
                               f"{type(exc).__name__}: {exc}", {})
```

### 1.3.4 Ollama (local)

```python
async def _probe_ollama(model: str, timeout: float) -> LLMHealthStatus:
    base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
    url = f"{base.rstrip('/')}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            if r.status_code >= 500:
                return LLMHealthStatus("ollama", base, model, False,
                                       f"upstream HTTP {r.status_code}", {})
            r.raise_for_status()
            try:
                tags = [m.get("name", "") for m in r.json().get("models", [])]
            except ValueError:
                return LLMHealthStatus("ollama", base, model, False,
                                       "ollama returned non-JSON", {})
            ok = (not model) or any(model in t for t in tags if t)
            return LLMHealthStatus(
                "ollama", base, model, ok,
                "" if ok else f"model {model!r} not pulled; pulled: {tags[:3]}",
                {"model_count": len(tags), "models": tags[:10]},
            )
    except httpx.ConnectError:
        return LLMHealthStatus("ollama", base, model, False,
                               f"ollama serve not running at {base}", {})
    except httpx.TimeoutException:
        return LLMHealthStatus("ollama", base, model, False,
                               f"timeout after {timeout}s", {})
    except httpx.HTTPError as exc:
        return LLMHealthStatus("ollama", base, model, False,
                               f"{type(exc).__name__}: {exc}", {})
```

## 1.4 — Tasks

- [ ] **1.1.t1** Create `agents/shared/shared/llm/health.py` with the `LLMHealthStatus` dataclass and `check_llm_health()` entry point.
- [ ] **1.2.t1** Implement detection precedence in `check_llm_health()` matching `provider.py` routing logic exactly.
- [ ] **1.3.t1** Implement `_probe_openai_compatible` + `_probe_openai` + `_probe_openai_models_endpoint` + `_interpret_models_response`.
- [ ] **1.3.t2** Implement `_probe_anthropic` (POST /v1/messages with 1-token probe).
- [ ] **1.3.t3** Implement `_probe_gemini` (GET /v1beta/models).
- [ ] **1.3.t4** Implement `_probe_ollama` (GET /api/tags).
- [ ] **1.4.t1** Smoke-test imports: `python3 -c "from shared.llm.health import check_llm_health, LLMHealthStatus; print('OK')"`.
- [ ] **1.4.t2** Manual smoke test against your live LM Studio: `python3 -c "import asyncio; from shared.llm.health import check_llm_health; r = asyncio.run(check_llm_health()); print(r.message())"`.

---

# Phase 2 — Agent `/health` endpoint integration

**Goal**: Each agent's existing `/health` endpoint includes an `llm` sub-object so backend can aggregate without per-agent custom logic.

## 2.1 — Modify `agents/shared/shared/transport/sse_app.py`

### Current code (line 49)

```python
@app.get("/health")
async def health():
    return {"ok": True}
```

### Replacement code

```python
from shared.llm.health import check_llm_health


@app.get("/health")
async def health():
    """Returns process liveness + LLM reachability sub-status.

    The 'llm' sub-object is the canonical LLMHealthStatus.as_dict(); the
    backend /api/llm/health aggregator reads it verbatim from any one agent.
    """
    llm = await check_llm_health(timeout=2.0)  # tighter timeout for /health responsiveness
    return {
        "ok": True,
        "agent": agent_name,    # already in scope
        "llm": llm.as_dict(),
        "llm_message": llm.message(),
    }
```

Note: the agent's existing process-liveness contract (returns 200 + `ok=true`) is preserved. The LLM probe runs in parallel with the response — if it times out, the agent still reports `ok=true` but `llm.reachable=false`.

## 2.2 — Tasks

- [ ] **2.1.t1** Update `sse_app.py:49` `/health` handler to include `llm` and `llm_message` fields.
- [ ] **2.1.t2** Verify all 8 agent containers' `/health` endpoints return the expanded shape: `for p in 28001 28002 28003 28004 28006 28007 28009 28010; do curl -s localhost:$p/health | jq; done`.
- [ ] **2.1.t3** Confirm latency: agent `/health` should respond within `2s + small constant`. Add a perf test if there's risk.

---

# Phase 3 — Backend `/api/llm/health` aggregator

**Goal**: Frontend has one endpoint to ask "is LLM reachable?". Backend caches the answer for 5s to avoid hammering during UI polling.

## 3.1 — New file `backend/internal/handler/llm_health_handler.go`

```go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulture/backend/internal/config"
)

// LLMHealthHandler aggregates one agent's /health.llm sub-object and serves
// it on /api/llm/health. The result is cached for VULTURE_LLM_HEALTH_CACHE_TTL
// seconds (default 5) to absorb UI polling load.
type LLMHealthHandler struct {
	cfg      config.Config
	mu       sync.Mutex
	cache    *llmHealthCacheEntry
	cacheTTL time.Duration
}

type llmHealthCacheEntry struct {
	value   llmHealthResponse
	cachedAt time.Time
}

type llmHealthResponse struct {
	Provider  string                 `json:"provider"`
	Endpoint  string                 `json:"endpoint"`
	Model     string                 `json:"model"`
	Reachable bool                   `json:"reachable"`
	Error     string                 `json:"error,omitempty"`
	Detail    map[string]interface{} `json:"detail,omitempty"`
	Message   string                 `json:"message"`
}

func NewLLMHealthHandler(cfg config.Config) *LLMHealthHandler {
	ttl := 5 * time.Second
	if v, _ := strconv.Atoi(envOr("VULTURE_LLM_HEALTH_CACHE_TTL", "5")); v > 0 {
		ttl = time.Duration(v) * time.Second
	}
	return &LLMHealthHandler{cfg: cfg, cacheTTL: ttl}
}

func (h *LLMHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp, err := h.get(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway,
			fmt.Sprintf("could not reach any agent: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *LLMHealthHandler) get(ctx context.Context) (llmHealthResponse, error) {
	h.mu.Lock()
	if h.cache != nil && time.Since(h.cache.cachedAt) < h.cacheTTL {
		v := h.cache.value
		h.mu.Unlock()
		return v, nil
	}
	h.mu.Unlock()

	v, err := h.fetchFromAnyAgent(ctx)
	if err != nil {
		return llmHealthResponse{}, err
	}

	h.mu.Lock()
	h.cache = &llmHealthCacheEntry{value: v, cachedAt: time.Now()}
	h.mu.Unlock()
	return v, nil
}

// fetchFromAnyAgent queries each registered agent's /health in turn and
// returns the first successful response's llm sub-object. All agents share
// the same env so the answer is identical; we just need one to be alive.
func (h *LLMHealthHandler) fetchFromAnyAgent(ctx context.Context) (llmHealthResponse, error) {
	client := http.Client{Timeout: 4 * time.Second}
	var lastErr error
	for _, ag := range h.cfg.Agents {
		req, err := http.NewRequestWithContext(ctx, "GET", ag.URL+"/health", nil)
		if err != nil { lastErr = err; continue }
		resp, err := client.Do(req)
		if err != nil { lastErr = err; continue }
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("agent %s returned HTTP %d", ag.Name, resp.StatusCode)
			continue
		}
		var body struct {
			LLM     llmHealthResponse `json:"llm"`
			Message string            `json:"llm_message"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			lastErr = err
			continue
		}
		body.LLM.Message = body.Message
		return body.LLM, nil
	}
	if lastErr == nil { lastErr = errors.New("no agents configured") }
	return llmHealthResponse{}, lastErr
}

func envOr(key, fallback string) string {
	v := strings.TrimSpace(getenvOr(key, fallback))
	if v == "" { return fallback }
	return v
}
```

## 3.2 — Wire into router

`backend/internal/server/server.go` register:

```go
mux.Handle("/api/llm/health", handler.NewLLMHealthHandler(cfg))
```

## 3.3 — Tasks

- [ ] **3.1.t1** Create `backend/internal/handler/llm_health_handler.go`.
- [ ] **3.1.t2** Add aggregator with 5s LRU cache.
- [ ] **3.1.t3** Wire into `server.go::registerRoutes`.
- [ ] **3.2.t1** End-to-end smoke test: `curl http://localhost:28080/api/llm/health | jq`. Expect a JSON body with `provider`, `model`, `reachable`, `message`.
- [ ] **3.2.t2** Cache test: hit endpoint 100 times in 2s; verify only one call made to underlying agent.

---

# Phase 4 — Bare-metal launcher integration

**Goal**: Replace the Ollama-only check with a generic call. Print the canonical message at startup.

## 4.1 — Modify `backend/internal/localdev/launcher.go`

The current Ollama preflight (lines 142-160) is replaced by a unified probe that delegates to the Python helper via one agent's `/health`. After agents are up, the launcher hits the first running agent's `/health` and prints the `llm_message`.

```go
// New helper in backend/internal/localdev/llm_check.go
func reportLLMHealthOrAbort(ctx context.Context, agentURL string) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(agentURL + "/health")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		var body struct {
			LLMMessage string `json:"llm_message"`
			LLM        struct {
				Reachable bool   `json:"reachable"`
				Provider  string `json:"provider"`
			} `json:"llm"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()

		// Print canonical message — same string user sees in UI banner.
		marker := "✓"
		if !body.LLM.Reachable && body.LLM.Provider != "disabled" {
			marker = "⚠"
		}
		fmt.Printf("  %s %s\n", marker, body.LLMMessage)

		// Strict mode: refuse to proceed if not reachable.
		if os.Getenv("VULTURE_REQUIRE_LLM") == "true" && !body.LLM.Reachable {
			log.Fatalf("VULTURE_REQUIRE_LLM=true and LLM unreachable; aborting startup")
		}
		return
	}
	log.Printf("  ⚠ could not query agent %s for LLM health; continuing", agentURL)
}
```

`launcher.go::startAll` calls `reportLLMHealthOrAbort` AFTER all agents have started successfully.

## 4.2 — Remove Ollama-only logic

The `OllamaIsRunning` / `OllamaHasModel` / `OllamaPullModel` helpers stay (they're still used to autopull models). But the **decision** about whether to set `VULTURE_USE_LLM=true` is no longer "Ollama-only specific":

```go
// New behavior:
//   1. If user has explicit VULTURE_USE_LLM=true and any provider env, trust them.
//   2. If OLLAMA available and no other provider, auto-pull and enable.
//   3. After agents start, the unified health probe reports actual state.
```

## 4.3 — Tasks

- [ ] **4.1.t1** Create `backend/internal/localdev/llm_check.go` with `reportLLMHealthOrAbort`.
- [ ] **4.1.t2** Modify `launcher.go::startAll` to call the new helper after agents are ready.
- [ ] **4.1.t3** Update the existing Ollama detection path so it still autopulls but doesn't unilaterally set `VULTURE_USE_LLM=true`.
- [ ] **4.2.t1** Manual test all six provider configs; confirm canonical message renders correctly:
  - LM Studio not running: `⚠ LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — connection refused at http://localhost:1234/v1. Audit will run skills-only.`
  - Ollama running with model: `✓ LLM ready: ollama (qwen3:1.7b) at http://localhost:11434`
  - OpenAI cloud OK: `✓ LLM ready: openai (gpt-4o) at https://api.openai.com/v1`
  - OpenAI cloud bad key: `⚠ LLM unavailable: openai (gpt-4o) at https://api.openai.com/v1 — auth: invalid or missing API key. Audit will run skills-only.`

---

# Phase 5 — Per-audit preflight + `degraded_reason` column

**Goal**: At audit creation, query LLM health. If degraded, persist `degraded_reason` on the audit record so UI shows the warning even after the audit completes.

## 5.1 — Migration `015_audit_degraded_reason.sql`

```sql
-- Postgres
ALTER TABLE audits ADD COLUMN IF NOT EXISTS degraded_reason TEXT NOT NULL DEFAULT '';

-- SQLite mirror in 015_audit_degraded_reason.sqlite.sql
ALTER TABLE audits ADD COLUMN degraded_reason TEXT NOT NULL DEFAULT '';
```

## 5.2 — Model + repository

`backend/internal/model/audit.go`:
```go
type Audit struct {
    // ... existing fields ...
    DegradedReason string `json:"degraded_reason,omitempty"`
}
```

Postgres + SQLite repos read/write the new column.

## 5.3 — `audit_handler.go::Create` preflight

```go
func (h *AuditHandler) Create(w http.ResponseWriter, r *http.Request) {
    // ... existing parsing ...

    // Preflight LLM health (uses cached aggregator response)
    health, err := h.llmHealthHandler.get(r.Context())
    var degraded string
    if err == nil && !health.Reachable && health.Provider != "disabled" {
        degraded = health.Message
        // Strict mode: refuse to start
        if os.Getenv("VULTURE_REQUIRE_LLM") == "true" {
            writeError(w, http.StatusServiceUnavailable, health.Message)
            return
        }
    }

    audit, err := h.svc.Create(req, degraded)
    // ... rest of handler ...
}
```

## 5.4 — Tasks

- [ ] **5.1.t1** Write `backend/migrations/015_audit_degraded_reason.sql` (Postgres).
- [ ] **5.1.t2** Write `backend/migrations/015_audit_degraded_reason.sqlite.sql`.
- [ ] **5.2.t1** Add `DegradedReason` to `model.Audit`.
- [ ] **5.2.t2** Update repos to read/write the column.
- [ ] **5.3.t1** Inject `LLMHealthHandler` into `AuditHandler` constructor.
- [ ] **5.3.t2** Implement preflight in `Create`.
- [ ] **5.3.t3** When `VULTURE_REQUIRE_LLM=true`, return 503 + canonical message body.
- [ ] **5.4.t1** End-to-end test: stop LM Studio, submit audit, verify response body has `degraded_reason` populated, audit DB row has the same string.

---

# Phase 6 — Frontend: degraded-mode banner + hook

**Goal**: User sees the canonical message in two places — the audit-creation page (proactive warning before submit) and the audit results page (when viewing degraded audits).

## 6.1 — `frontend/src/hooks/useLLMHealth.ts`

```typescript
import { useEffect, useState } from "react";

export interface LLMHealth {
  provider: string;
  endpoint: string;
  model: string;
  reachable: boolean;
  error?: string;
  message: string;
}

export function useLLMHealth(pollIntervalMs = 30000) {
  const [health, setHealth] = useState<LLMHealth | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    const fetchHealth = async () => {
      try {
        const r = await fetch("/api/llm/health");
        if (!r.ok) {
          if (!cancelled) setHealth(null);
          return;
        }
        const data = await r.json();
        if (!cancelled) setHealth(data);
      } catch {
        if (!cancelled) setHealth(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchHealth();
    const t = setInterval(fetchHealth, pollIntervalMs);
    return () => { cancelled = true; clearInterval(t); };
  }, [pollIntervalMs]);
  return { health, loading };
}
```

## 6.2 — `LLMDegradedBanner.tsx` component

```tsx
import { useLLMHealth } from "@/hooks/useLLMHealth";

interface Props {
  /** Pre-render message; set when an audit's degraded_reason field is non-empty. */
  preset?: string;
}

export function LLMDegradedBanner({ preset }: Props) {
  const { health } = useLLMHealth();
  const text = preset || (health && !health.reachable && health.provider !== "disabled" ? health.message : null);
  if (!text) return null;
  return (
    <div className="border border-yellow-300 bg-yellow-50 rounded p-3 text-sm">
      <strong className="text-yellow-900">Audit running in degraded mode.</strong>{" "}
      <span className="text-yellow-800">{text}</span>{" "}
      <a href="/settings/llm" className="underline text-yellow-900">
        Check LLM settings
      </a>
    </div>
  );
}
```

## 6.3 — Wire into pages

- `AuditNew.tsx` — render `<LLMDegradedBanner />` (no preset; uses live `useLLMHealth`)
- `AuditResults.tsx` — render `<LLMDegradedBanner preset={audit.degraded_reason} />` when `audit.degraded_reason` is set

## 6.4 — Tasks

- [ ] **6.1.t1** Create `frontend/src/hooks/useLLMHealth.ts`.
- [ ] **6.1.t2** Create `frontend/src/components/results/LLMDegradedBanner.tsx`.
- [ ] **6.2.t1** Add `degraded_reason?: string` to `Audit` type in `frontend/src/lib/types.ts`.
- [ ] **6.3.t1** Add `<LLMDegradedBanner />` to `AuditNew.tsx`.
- [ ] **6.3.t2** Add `<LLMDegradedBanner preset={audit.degraded_reason} />` to `AuditResults.tsx`.
- [ ] **6.4.t1** Playwright E2E: stop LM Studio, submit audit via UI, verify banner appears.
- [ ] **6.4.t2** Confirm `tsc --noEmit` clean.

---

# Phase 7 — Per-provider test fixtures

**Goal**: 6 providers × ~7 failure modes each = ~42 unit tests using `httpx.MockTransport`. Each test is deterministic, runs in <100ms, and confirms a specific message string.

## 7.1 — Test directory

`agents/shared/tests/unit/llm/test_health.py` — NEW file.

## 7.2 — Test pattern (one provider; pattern repeats for each)

```python
"""Unit tests for shared.llm.health.

Each provider has 7 test cases:
  1. Reachable + model loaded
  2. Endpoint reachable, model not loaded
  3. Connection refused
  4. Timeout
  5. Auth failure (401)
  6. Rate limit (429)
  7. Server error (500)

All tests use httpx.MockTransport — no network calls.
"""
import os
from unittest.mock import patch

import httpx
import pytest

from shared.llm.health import check_llm_health, LLMHealthStatus


@pytest.fixture(autouse=True)
def reset_env(monkeypatch):
    """Each test starts with a clean LLM-related env."""
    for k in [
        "VULTURE_USE_LLM", "VULTURE_LLM_MODEL", "OPENAI_BASE_URL",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
        "OLLAMA_API_BASE",
    ]:
        monkeypatch.delenv(k, raising=False)


# --- LM Studio (OpenAI-compatible, port 1234) ---

@pytest.mark.asyncio
async def test_lmstudio_reachable_model_loaded(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:8b")

    def handler(request):
        return httpx.Response(200, json={
            "data": [{"id": "qwen3:8b"}, {"id": "llama-3-3b"}]
        })

    with patch("httpx.AsyncClient.get", side_effect=handler):
        r = await check_llm_health(timeout=1.0)

    assert r.provider == "lmstudio"
    assert r.reachable is True
    assert r.message() == "LLM ready: lmstudio (qwen3:8b) at http://localhost:1234/v1"


@pytest.mark.asyncio
async def test_lmstudio_endpoint_up_model_not_loaded(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:8b")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "llama-3-3b"}]})

    with patch("httpx.AsyncClient.get", side_effect=handler):
        r = await check_llm_health(timeout=1.0)

    assert r.reachable is False
    assert "not loaded" in r.error
    assert r.message().startswith(
        "LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — model"
    )
    assert r.message().endswith(" Audit will run skills-only.")


@pytest.mark.asyncio
async def test_lmstudio_connection_refused(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:8b")

    def handler(request):
        raise httpx.ConnectError("Connection refused")

    with patch("httpx.AsyncClient.get", side_effect=handler):
        r = await check_llm_health(timeout=1.0)

    assert r.reachable is False
    assert r.message() == (
        "LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — "
        "connection refused at http://localhost:1234/v1. Audit will run skills-only."
    )


@pytest.mark.asyncio
async def test_lmstudio_timeout(monkeypatch):
    # ... TimeoutException raised ...

@pytest.mark.asyncio
async def test_lmstudio_auth_401(monkeypatch):
    # ... 401 returned (LM Studio rare but possible if user added auth) ...

@pytest.mark.asyncio
async def test_lmstudio_rate_limit_429(monkeypatch):
    # ... 429 returned ...

@pytest.mark.asyncio
async def test_lmstudio_server_500(monkeypatch):
    # ... 500 returned ...
```

Repeat the same 7-test pattern for: vLLM (port 8000), LocalAI (port 8080), generic OpenAI-compatible (port 9999), OpenAI cloud, Anthropic, Gemini, Ollama.

Plus tests for:
- `VULTURE_USE_LLM=false` → returns `provider="disabled"`
- `VULTURE_USE_LLM=true` but no provider env → returns `provider="unknown"`
- Detection precedence: when both `OPENAI_BASE_URL` and `ANTHROPIC_API_KEY` set, openai-compatible wins (matches `provider.py` routing)
- Message format invariance: each shape is asserted character-for-character

## 7.3 — Tasks

- [ ] **7.1.t1** Create `agents/shared/tests/unit/llm/__init__.py` and `agents/shared/tests/unit/llm/test_health.py`.
- [ ] **7.2.t1–t6** Implement 7-test corpus for each of: lmstudio, vllm, localai, openai, anthropic, gemini, ollama.
- [ ] **7.2.t7** Add detection-precedence tests (`VULTURE_USE_LLM=false`, no provider env, mixed-provider env).
- [ ] **7.2.t8** Add message-format invariance tests (assert exact strings for each shape).
- [ ] **7.3.t1** Run `python3 -m pytest agents/shared/tests/unit/llm/test_health.py -v`. **All ~50 tests must pass.**
- [ ] **7.3.t2** Coverage check: `pytest --cov=shared.llm.health` → 100% line coverage required (CLAUDE.md mandate).

---

# Phase 8 — `VULTURE_REQUIRE_LLM` strict mode

**Goal**: For environments where skills-only output is a regression (regulated audits, paid CI), refuse to start audits when LLM is unreachable.

## 8.1 — Implementation

Already wired into `audit_handler.go::Create` from Phase 5.3 — when `VULTURE_REQUIRE_LLM=true` and health is degraded, returns 503:

```go
{
  "error": "LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — connection refused at http://localhost:1234/v1. Audit will run skills-only.",
  "degraded_reason": "...",
  "code": "llm_required_but_unavailable"
}
```

CLI client `vulture scan` checks the response code and exits non-zero with the canonical message. CI integrations (GitHub Actions etc.) fail the workflow.

## 8.2 — Tasks

- [ ] **8.1.t1** Define error code constant in `backend/internal/handler/audit_handler.go` (`ErrLLMRequired`).
- [ ] **8.1.t2** CLI: handle 503 on audit submission, print canonical message, exit code 75 (EX_TEMPFAIL).
- [ ] **8.1.t3** Document in `docs/guides/ci_integration.md`.
- [ ] **8.2.t1** E2E test: with `VULTURE_REQUIRE_LLM=true` and LM Studio off, `vulture scan` exits non-zero with stderr containing the canonical message.

---

# Cross-cutting concerns

## CC.1 — TDD discipline

Every phase's tests are authored BEFORE the implementation per `CLAUDE.md`. Phase 7 is dedicated to the TDD red-baseline + post-fix verification:

1. Write tests in 7.2.t1-t8.
2. Tests fail because `check_llm_health` doesn't exist yet.
3. Implement Phase 1.
4. Tests pass.

## CC.2 — Performance

| Surface | Budget |
|---|---|
| `check_llm_health()` per call | < 3.5s p95 (3s timeout + small constant) |
| Agent `/health` response | < 2.5s p95 (2s probe timeout + 0.5s overhead) |
| Backend `/api/llm/health` | < 50 ms p95 (cached); < 4s on cache miss |
| Bare-metal launcher banner | < 15s before timing out and continuing |
| Per-audit preflight | < 50 ms p95 (cache hit; rare miss = full probe) |

Cache invalidation: TTL-only (no manual invalidation). 5s default keeps UI polling cheap; longer TTL would mask config changes.

## CC.3 — Security

- API keys NEVER appear in any logged or returned message. Probes that rely on bearer tokens send them in headers, never in URLs (Gemini uses query param — that's vendor-mandated; treat the GEMINI_API_KEY URL as sensitive in logs).
- Probe response bodies (model lists) are NOT cached in databases — only the digested status (provider, model, reachable, error, detail) is.
- The 1-token Anthropic probe MAY incur fractional cost ($~0.000001 per probe). Acceptable. Cache TTL keeps it bounded.
- `/api/llm/health` requires authentication in centralized server mode (per feature 0031 RLS / API-key middleware). Anonymous polling not allowed.

## CC.4 — Observability

Structured logs at three levels:

```
INFO  llm.health.probe provider=lmstudio endpoint=http://localhost:1234/v1 model=qwen3:8b reachable=true latency_ms=42
WARN  llm.health.probe provider=lmstudio endpoint=http://localhost:1234/v1 model=qwen3:8b reachable=false error="connection refused"
WARN  llm.health.required_but_unavailable audit_id=... message="..."
```

Prometheus metrics (deferred to a follow-up):
```
vulture_llm_health_probes_total{provider,reachable}
vulture_llm_health_probe_duration_seconds_bucket{provider}
```

## CC.5 — Backwards compatibility

- Existing audits without `degraded_reason` get the default `''` value via migration.
- API `/api/audits/{id}` response includes `degraded_reason` only when set (`omitempty`).
- Agent `/health` response gains the `llm` and `llm_message` keys but preserves `ok` — old health-check consumers (e.g. backend's `checkAgentHealth`) keep working.
- `VULTURE_REQUIRE_LLM` defaults to false; no behavior change for existing users.

## CC.6 — Rollback

See `0039_rollback_plan.md`. Per phase. Worst-case full rollback ~20 minutes. The `degraded_reason` column is the only schema change; harmless to leave in place if rolling back code.

## CC.7 — Documentation

- `docs/guides/llm_setup.md` — new doc explaining each provider's required env vars, what the canonical message means, and how to interpret `degraded_reason`.
- `docs/architecture/agent_protocol.md` — note the new `llm` sub-object in `/health`.
- `README.md` — one-line note about LM Studio / Ollama / cloud configuration.

---

# Open questions

1. **Should the launcher refuse to start when LLM unreachable AND `VULTURE_USE_LLM=true` AND `VULTURE_REQUIRE_LLM` unset?** Current proposal: warn + proceed (matches today's behavior; minimal regression risk). Alternative: warn + proceed but log loud. **Decision deferred to user.**

2. **Cache TTL default of 5s — too short or too long?** Frontend polls every 30s in the proposed `useLLMHealth` hook, so 5s cache means 1-of-6 polls hits the network. Probably right. **Open to override via env.**

3. **Anthropic 1-token probe cost.** Negligible per-probe but multiplied by audit volume could matter. Alternative: skip Anthropic probe entirely if `ANTHROPIC_API_KEY` looks valid (length check). **Recommend: keep the probe; cost is < $0.01 per million audits.**

4. **Multiple providers configured (env conflict).** Today's `provider.py` routes by precedence; this plan mirrors that exactly. If user wants different behavior they can use `VULTURE_LLM_MODEL` to disambiguate. **No new behavior; just transparent reporting.**

5. **Frontend banner UX.** The banner appears on AuditNew + AuditResults. Should it appear elsewhere (Dashboard, Settings)? **Deferred to v1.2 polish.**

---

## Summary

Feature 0039 closes the silent-LLM-unreachable gap with a single Python module (`shared/llm/health.py`) consumed verbatim by:

- Agent `/health` endpoint
- Backend `/api/llm/health` aggregator
- Bare-metal launcher banner
- Per-audit preflight
- Frontend banner (live + per-audit)

Provider/aggregator coverage: OpenAI cloud, Anthropic, Gemini, Ollama, LM Studio, vLLM, LocalAI, generic OpenAI-compatible. Detection precedence mirrors `provider.py` exactly so the probe answers what's actually called.

One canonical message format. Same string everywhere. ~5 days for one developer; v1.0 cut at Phase 1+2+3+7 (~3.5 days, ships the canonical probe + server-side surfaces). v1.1 adds launcher + per-audit + frontend. v1.2 adds strict mode.

Each phase independently mergeable, independently reversible.
