"""LLM provider configuration via LiteLLM.

Supports cloud providers (OpenAI, Anthropic, Google), local Ollama models,
and OpenAI-compatible servers (LM Studio, vLLM, LocalAI, etc.).
For Ollama, install and run: ``ollama pull qwen3:1.7b && ollama serve``
"""

import logging
import os

logger = logging.getLogger(__name__)

MODEL_MAP: dict[str, str] = {
    # Cloud providers
    # NOTE: gpt-4o has no "litellm/" prefix, so the OpenAI Agents SDK calls
    # OpenAI directly (native Responses API). This means error formats differ
    # from LiteLLM-routed models, and loop guard hooks may not fire identically.
    # This is intentional: native SDK path provides better streaming and
    # structured output support for OpenAI models.
    "gpt-4o": "gpt-4o",
    # Update version date when new Claude releases are available
    "claude-sonnet": "litellm/anthropic/claude-sonnet-4-5-20250514",
    "gemini-pro": "litellm/gemini/gemini-1.5-pro",
    # Local Ollama models (zero cost, no API key needed)
    # Format: "litellm/ollama/X" — the "litellm/" prefix routes through the
    # Agents SDK's LiteLLM provider, which then handles "ollama/X" natively.
    "qwen3:1.7b": "litellm/ollama/qwen3:1.7b",
    "qwen3:8b": "litellm/ollama/qwen3:8b",
    "qwen3:14b": "litellm/ollama/qwen3:14b",
    "llama3.2": "litellm/ollama/llama3.2",
    "mistral": "litellm/ollama/mistral",
}

# When OPENAI_BASE_URL is set, the user is pointing at an OpenAI-compatible
# server (LM Studio, vLLM, LocalAI, etc.). These servers only support the
# Chat Completions API, but the Agents SDK uses the Responses API for models
# without a "litellm/" prefix. We detect this and route through LiteLLM's
# openai provider, which uses Chat Completions. We also propagate the base
# URL to OPENAI_API_BASE which LiteLLM reads.
_CUSTOM_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")
if _CUSTOM_BASE_URL:
    os.environ.setdefault("OPENAI_API_BASE", _CUSTOM_BASE_URL)

# Embedding model recommendations per LLM provider.
# Used by the frontend/docs to suggest compatible embedding models.
EMBEDDING_MODELS: dict[str, str] = {
    "gpt-4o": "text-embedding-3-small",           # 1536d, OpenAI API
    "claude-sonnet": "text-embedding-3-small",     # 1536d, OpenAI API
    "gemini-pro": "text-embedding-3-small",        # 1536d, OpenAI API
    "qwen3:1.7b": "nomic-embed-text",             # 768d, Ollama local
    "qwen3:8b": "nomic-embed-text",               # 768d, Ollama local
    "qwen3:14b": "nomic-embed-text",              # 768d, Ollama local
    "llama3.2": "nomic-embed-text",               # 768d, Ollama local
    "mistral": "nomic-embed-text",                # 768d, Ollama local
}

# Context window sizes per model (tokens).
CONTEXT_WINDOWS: dict[str, int] = {
    "gpt-4o": 128_000,
    "claude-sonnet": 200_000,
    "gemini-pro": 1_048_576,
    "qwen3:1.7b": 32_000,
    "qwen3:8b": 32_000,    # Ollama native default; override via VULTURE_LLM_CTX_SIZE if YaRN enabled
    "qwen3:14b": 32_000,   # Ollama native default; override via VULTURE_LLM_CTX_SIZE if YaRN enabled
    "llama3.2": 128_000,
    "mistral": 32_000,
}

# Model family patterns → context window size.  Used when the exact model name
# isn't in CONTEXT_WINDOWS (e.g. custom endpoint "qwen/qwen3.5-35b-a3b").
# Checked in order; first match wins.
_MODEL_FAMILY_CTX: list[tuple[str, int]] = [
    ("qwen3", 32_768),
    ("qwen2.5", 32_768),
    ("qwen", 32_768),
    ("llama-3", 128_000),
    ("llama3", 128_000),
    ("llama", 128_000),
    ("mistral", 32_000),
    ("mixtral", 32_000),
    ("gemma", 8_192),
    ("phi-3", 128_000),
    ("phi-4", 16_384),
    ("deepseek", 64_000),
    ("codestral", 32_000),
    ("command-r", 128_000),
    ("claude", 200_000),
    ("gpt-4", 128_000),
]

DEFAULT_MODEL = "gpt-4o"

# Fallback chains: if primary model fails, try these in order.
FALLBACK_CHAINS: dict[str, list[str]] = {
    "gpt-4o": ["claude-sonnet", "gemini-pro"],
    "claude-sonnet": ["gpt-4o", "gemini-pro"],
    "gemini-pro": ["gpt-4o", "claude-sonnet"],
    "qwen3:1.7b": ["qwen3:8b", "mistral"],
    "qwen3:8b": ["qwen3:14b", "qwen3:1.7b"],
    "qwen3:14b": ["qwen3:8b", "mistral"],
    "llama3.2": ["mistral", "qwen3:8b"],
    "mistral": ["llama3.2", "qwen3:8b"],
}


def get_model(preference: str | None = None) -> str:
    """Resolve the LLM model string for the OpenAI Agents SDK.

    Priority: preference arg > VULTURE_LLM_MODEL env > default.

    When OPENAI_BASE_URL is set (custom endpoint like LM Studio), models that
    aren't already prefixed are routed through ``litellm/openai/`` so the SDK
    uses Chat Completions instead of the Responses API.

    Args:
        preference: Optional model name or key from MODEL_MAP.

    Returns:
        Model string usable by the agents SDK.
    """
    key = preference or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    resolved = MODEL_MAP.get(key, key)
    # Route through LiteLLM for custom OpenAI-compatible endpoints.
    # OPENAI_BASE_URL means the user is pointing at an OpenAI-compatible
    # server (LM Studio, vLLM, etc.) — always use "openai/" provider
    # so litellm routes to the Chat Completions API at that base URL.
    if _CUSTOM_BASE_URL and not resolved.startswith("litellm/") and resolved != "gpt-4o":
        # If model already starts with "openai/", just add litellm prefix
        if resolved.startswith("openai/"):
            return f"litellm/{resolved}"
        # Otherwise, always wrap with openai/ — even if model has a /
        # (e.g. "qwen/qwen3-coder-next" → "litellm/openai/qwen/qwen3-coder-next")
        return f"litellm/openai/{resolved}"
    return resolved


def get_embedding_model(llm_model: str | None = None) -> str:
    """Get the recommended embedding model for the given LLM model.

    Args:
        llm_model: LLM model key. Defaults to VULTURE_LLM_MODEL env.

    Returns:
        Embedding model name (e.g., 'nomic-embed-text' or 'text-embedding-3-small').
    """
    key = llm_model or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    return EMBEDDING_MODELS.get(key, "text-embedding-3-small")


def get_max_findings(model: str | None = None) -> int:
    """Return the recommended max prior findings count for the given model.

    Scales based on context window: small models (<=32K) get 25,
    medium models (<=200K) get 50, large models (>200K) get 100.
    """
    ctx = get_context_window(model)
    if ctx <= 32_000:
        return 25
    if ctx < 200_000:
        return 50
    return 100


def _infer_family_ctx(model_lower: str) -> int | None:
    """Infer context window from model family name patterns."""
    for family, ctx in _MODEL_FAMILY_CTX:
        if family in model_lower:
            return ctx
    return None


def get_context_window(model: str | None = None) -> int:
    """Get context window size (in tokens) for the active model.

    Priority: VULTURE_LLM_CTX_SIZE env > CONTEXT_WINDOWS dict
              > model family inference > custom endpoint fallback.

    Args:
        model: Optional model key. Defaults to VULTURE_LLM_MODEL env.

    Returns:
        Context window size in tokens.
    """
    env_val = os.environ.get("VULTURE_LLM_CTX_SIZE", "")
    if env_val:
        try:
            return int(env_val)
        except ValueError:
            pass
    key = model or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    known = CONTEXT_WINDOWS.get(key)
    if known is not None:
        return known
    # Try model family pattern matching (e.g. "qwen/qwen3.5-35b" → qwen3 → 32K)
    family_ctx = _infer_family_ctx(key.lower())
    if family_ctx is not None:
        logger.info("inferred_ctx model=%s ctx=%d family_match", key, family_ctx)
        return family_ctx
    # Custom OpenAI-compatible endpoints: conservative fallback.
    if _CUSTOM_BASE_URL:
        logger.warning(
            "custom_endpoint_default_ctx model=%s ctx=8192 hint=set_VULTURE_LLM_CTX_SIZE", key,
        )
        return 8_192
    return 32_000


def get_fallback_models(model: str | None = None) -> list[str]:
    """Get the fallback chain for the given model.

    Returns a list of model keys to try (in order) if the primary fails.
    The primary model is NOT included in the returned list.

    Args:
        model: Model key. Defaults to VULTURE_LLM_MODEL env.

    Returns:
        List of fallback model keys, or empty list if no fallbacks defined.
    """
    key = model or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    return list(FALLBACK_CHAINS.get(key, []))


def is_ollama_model(model: str | None = None) -> bool:
    """Check if the resolved model uses Ollama (local)."""
    resolved = get_model(model)
    return "ollama/" in resolved


def uses_custom_endpoint() -> bool:
    """Check if a custom OpenAI-compatible endpoint is configured.

    Returns True when OPENAI_BASE_URL is set, indicating a non-standard
    backend (vLLM, LM Studio, LocalAI, etc.) that may not support
    structured output (response_format with JSON schema).
    """
    return bool(_CUSTOM_BASE_URL)


# Cost per 1M tokens: (input_cost_usd, output_cost_usd).
COST_PER_1M_TOKENS: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "claude-sonnet": (3.00, 15.00),
    "gemini-pro": (1.25, 5.00),
    "qwen3:1.7b": (0.0, 0.0),
    "qwen3:8b": (0.0, 0.0),
    "qwen3:14b": (0.0, 0.0),
    "llama3.2": (0.0, 0.0),
    "mistral": (0.0, 0.0),
}


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str | None = None,
) -> float:
    """Estimate cost in USD for a given token usage.

    Args:
        input_tokens: Number of input tokens consumed.
        output_tokens: Number of output tokens generated.
        model: Model key. Defaults to VULTURE_LLM_MODEL env.

    Returns:
        Estimated cost in USD. Returns 0.0 for unknown or local models.
    """
    key = model or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    costs = COST_PER_1M_TOKENS.get(key)
    if costs is None:
        return 0.0
    input_cost, output_cost = costs
    return (input_tokens * input_cost + output_tokens * output_cost) / 1_000_000


def get_model_settings(model: str | None = None) -> dict:
    """Return provider-specific model settings for prompt caching.

    OpenAI: Automatic prefix caching (>= 1024 tokens). No extra config needed.
    Anthropic: Requires ``anthropic-beta: prompt-caching-2024-07-31`` header.
        LiteLLM >= 1.50 auto-injects ``cache_control`` breakpoints on system
        messages when this header is present — no manual breakpoint placement
        needed.  The pyproject.toml already requires ``litellm>=1.50.0``.
    Google: Implicit caching on Gemini 2.5+.

    Returns:
        Dict of settings suitable for ``ModelSettings(**settings)``.
    """
    resolved = get_model(model)
    settings: dict = {"temperature": 0.1}
    if "anthropic" in resolved:
        settings["extra_headers"] = {"anthropic-beta": "prompt-caching-2024-07-31"}
    return settings


def resolve_model_for_litellm(preference: str | None = None) -> str:
    """Resolve model string for direct litellm.acompletion() calls.

    ``get_model()`` returns strings prefixed with ``litellm/`` for the
    OpenAI Agents SDK, but ``litellm.acompletion()`` doesn't understand
    that prefix.  This helper strips it so callers (e.g. the prove agent)
    that call litellm directly get a usable model string.

    Examples:
        "litellm/anthropic/claude-sonnet-4-5-20250514" → "anthropic/claude-sonnet-4-5-20250514"
        "litellm/ollama/qwen3:8b" → "ollama/qwen3:8b"
        "litellm/openai/my-model" → "openai/my-model"
        "gpt-4o" → "gpt-4o"  (no prefix, passed through)
    """
    resolved = get_model(preference)
    if resolved.startswith("litellm/"):
        return resolved[len("litellm/"):]
    return resolved


def resolve_model_for_litellm_with_fallback(preference: str | None = None) -> str:
    """Like ``resolve_model_for_litellm`` but respects cooldown/fallback.

    Uses ``get_model_with_fallback()`` to skip models in cooldown, then
    strips the ``litellm/`` prefix for direct litellm calls.
    """
    resolved = get_model_with_fallback(preference)
    if resolved.startswith("litellm/"):
        return resolved[len("litellm/"):]
    return resolved


def get_model_with_fallback(preference: str | None = None) -> str:
    """Get the best available model, skipping those in cooldown.

    Checks if the primary model is available (not in cooldown). If it is
    in cooldown, iterates through the fallback chain to find an alternative.
    Falls back to the primary model if all alternatives are also in cooldown.

    Args:
        preference: Optional model name or key.

    Returns:
        Resolved model string usable by the agents SDK.
    """
    from shared.llm.cooldown import cooldown_manager

    primary = preference or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    resolved = get_model(primary)
    if cooldown_manager.is_available(resolved):
        return resolved
    for fallback_key in get_fallback_models(primary):
        fallback_resolved = get_model(fallback_key)
        if cooldown_manager.is_available(fallback_resolved):
            logger.info(
                "model_fallback primary=%s fallback=%s", resolved, fallback_resolved,
            )
            return fallback_resolved
    return resolved  # all in cooldown, try primary anyway
