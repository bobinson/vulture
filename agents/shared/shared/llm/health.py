"""Provider-agnostic LLM health probe (feature 0039).

Used uniformly by:
  - Agent /health endpoint
  - Backend /api/llm/health aggregator
  - Bare-metal launcher banner
  - Per-audit preflight

Producing one canonical message string consumed verbatim by every surface.

Detection precedence MUST mirror provider.py routing logic so the health
probe never disagrees with the actual call routing path.

Public API:
    LLMHealthStatus       - dataclass with .as_dict() and .message()
    check_llm_health()    - async entry point; reads env, returns status
"""
from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = float(os.environ.get("VULTURE_LLM_HEALTH_TIMEOUT", "3.0"))

# Models recognised as Ollama-native (matches MODEL_MAP in provider.py).
_OLLAMA_NATIVE_MODELS: frozenset[str] = frozenset({
    "qwen3:1.7b", "qwen3:8b", "qwen3:14b",
    "llama3.2", "mistral",
})


@dataclass
class LLMHealthStatus:
    """Outcome of probing the configured LLM provider.

    Fields:
        provider:  One of "openai" | "anthropic" | "gemini" | "ollama" |
                   "lmstudio" | "vllm" | "localai" | "openai-compatible" |
                   "litellm-aggregator" | "disabled" | "unknown".
        endpoint:  Base URL probed, or "(default cloud)" for cloud without
                   custom URL.
        model:     Configured VULTURE_LLM_MODEL; "" if none.
        reachable: True iff endpoint responded within timeout AND model is
                   loaded/available.
        error:     One-line cause when reachable=False; "" otherwise.
        detail:    Provider-specific extras: model_count, available models
                   (capped to 10), version, etc.
    """
    provider: str
    endpoint: str
    model: str
    reachable: bool
    error: str
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        """Plain dict for JSON serialisation on the agent /health endpoint."""
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


async def check_llm_health(timeout: float = DEFAULT_TIMEOUT) -> LLMHealthStatus:
    """Probe whichever provider VULTURE_USE_LLM/VULTURE_LLM_MODEL/* points at.

    Detection precedence (mirrors provider.py routing exactly):
      1. VULTURE_USE_LLM != "true"             → disabled
      2. OPENAI_BASE_URL set                   → openai-compatible
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


# ---------------------------------------------------------------------------
# Per-provider probes
# ---------------------------------------------------------------------------


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
    bearer = os.environ.get("OPENAI_API_KEY")  # optional for local servers
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
    """Map an OpenAI-shape /models response to LLMHealthStatus."""
    status_to_error = {
        401: "auth: invalid or missing API key",
        403: "auth: forbidden (key lacks permission)",
        429: "rate limit / quota exceeded",
    }
    if r.status_code in status_to_error:
        return LLMHealthStatus(
            provider, base_url, model, False,
            status_to_error[r.status_code], {},
        )
    if r.status_code >= 500:
        return LLMHealthStatus(
            provider, base_url, model, False,
            f"upstream HTTP {r.status_code}", {},
        )
    if r.status_code >= 400:
        return LLMHealthStatus(
            provider, base_url, model, False,
            f"HTTP {r.status_code}", {},
        )
    try:
        data = r.json().get("data", [])
    except (ValueError, AttributeError):
        return LLMHealthStatus(
            provider, base_url, model, False,
            "endpoint returned non-JSON", {},
        )
    ids = [m.get("id", "") for m in data if isinstance(m, dict)]
    model_loaded = (not model) or any(model in mid for mid in ids if mid)
    return LLMHealthStatus(
        provider=provider, endpoint=base_url, model=model, reachable=model_loaded,
        error="" if model_loaded else (
            f"model {model!r} not loaded; available: {ids[:3]}"
        ),
        detail={"model_count": len(ids), "models": ids[:10]},
    )


async def _probe_anthropic(model: str, timeout: float) -> LLMHealthStatus:
    """Anthropic has no GET /models; the cheapest probe is a 1-token messages call."""
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
    status_to_error = {
        401: "auth: invalid x-api-key",
        403: "auth: forbidden (key lacks permission)",
        404: f"model {model!r} not available" if model else "model not found",
        429: "rate limit / quota exceeded",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as c:
            r = await c.post(
                "https://api.anthropic.com/v1/messages", json=body,
            )
            if r.status_code in status_to_error:
                return LLMHealthStatus(
                    "anthropic", endpoint, model, False,
                    status_to_error[r.status_code], {},
                )
            if r.status_code >= 500:
                return LLMHealthStatus(
                    "anthropic", endpoint, model, False,
                    f"upstream HTTP {r.status_code}", {},
                )
            if r.status_code >= 400:
                return LLMHealthStatus(
                    "anthropic", endpoint, model, False,
                    f"HTTP {r.status_code}", {},
                )
            return LLMHealthStatus("anthropic", endpoint, model, True, "", {})
    except httpx.ConnectError:
        return LLMHealthStatus(
            "anthropic", endpoint, model, False,
            "connection refused", {},
        )
    except httpx.TimeoutException:
        return LLMHealthStatus(
            "anthropic", endpoint, model, False,
            f"timeout after {timeout}s", {},
        )
    except httpx.HTTPError as exc:
        return LLMHealthStatus(
            "anthropic", endpoint, model, False,
            f"{type(exc).__name__}: {exc}", {},
        )


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
                return LLMHealthStatus(
                    "gemini", endpoint, model, False,
                    "auth: invalid GEMINI_API_KEY", {},
                )
            if r.status_code == 429:
                return LLMHealthStatus(
                    "gemini", endpoint, model, False,
                    "rate limit / quota exceeded", {},
                )
            if r.status_code >= 500:
                return LLMHealthStatus(
                    "gemini", endpoint, model, False,
                    f"upstream HTTP {r.status_code}", {},
                )
            if r.status_code >= 400:
                return LLMHealthStatus(
                    "gemini", endpoint, model, False,
                    f"HTTP {r.status_code}", {},
                )
            try:
                names = [m.get("name", "") for m in r.json().get("models", [])]
            except (ValueError, AttributeError):
                return LLMHealthStatus(
                    "gemini", endpoint, model, False,
                    "endpoint returned non-JSON", {},
                )
            ok = (not model) or any(model in n for n in names if n)
            return LLMHealthStatus(
                "gemini", endpoint, model, ok,
                "" if ok else (
                    f"model {model!r} not in account; first few: {names[:3]}"
                ),
                {
                    "model_count": len(names),
                    "models": [n.split("/")[-1] for n in names[:10] if n],
                },
            )
    except httpx.ConnectError:
        return LLMHealthStatus(
            "gemini", endpoint, model, False, "connection refused", {},
        )
    except httpx.TimeoutException:
        return LLMHealthStatus(
            "gemini", endpoint, model, False, f"timeout after {timeout}s", {},
        )
    except httpx.HTTPError as exc:
        return LLMHealthStatus(
            "gemini", endpoint, model, False, f"{type(exc).__name__}: {exc}", {},
        )


async def _probe_ollama(model: str, timeout: float) -> LLMHealthStatus:
    base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
    url = f"{base.rstrip('/')}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            if r.status_code >= 500:
                return LLMHealthStatus(
                    "ollama", base, model, False,
                    f"upstream HTTP {r.status_code}", {},
                )
            if r.status_code >= 400:
                return LLMHealthStatus(
                    "ollama", base, model, False,
                    f"HTTP {r.status_code}", {},
                )
            try:
                tags = [m.get("name", "") for m in r.json().get("models", [])]
            except (ValueError, AttributeError):
                return LLMHealthStatus(
                    "ollama", base, model, False,
                    "ollama returned non-JSON", {},
                )
            ok = (not model) or any(model in t for t in tags if t)
            return LLMHealthStatus(
                "ollama", base, model, ok,
                "" if ok else f"model {model!r} not pulled; pulled: {tags[:3]}",
                {"model_count": len(tags), "models": tags[:10]},
            )
    except httpx.ConnectError:
        return LLMHealthStatus(
            "ollama", base, model, False,
            f"ollama serve not running at {base}", {},
        )
    except httpx.TimeoutException:
        return LLMHealthStatus(
            "ollama", base, model, False,
            f"timeout after {timeout}s", {},
        )
    except httpx.HTTPError as exc:
        return LLMHealthStatus(
            "ollama", base, model, False,
            f"{type(exc).__name__}: {exc}", {},
        )
