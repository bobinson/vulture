"""LLM provider configuration via LiteLLM.

Supports cloud providers (OpenAI, Anthropic, Google), local Ollama models,
and OpenAI-compatible servers (LM Studio, vLLM, LocalAI, etc.).
For Ollama, install and run: ``ollama pull qwen3:1.7b && ollama serve``
"""

import os

MODEL_MAP: dict[str, str] = {
    # Cloud providers
    "gpt-4o": "gpt-4o",
    "claude-sonnet": "litellm/anthropic/claude-sonnet-4-5-20250929",
    "gemini-pro": "litellm/gemini/gemini-pro",
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
    "gemini-pro": 1_000_000,
    "qwen3:1.7b": 32_000,
    "qwen3:8b": 128_000,
    "qwen3:14b": 128_000,
    "llama3.2": 128_000,
    "mistral": 32_000,
}

DEFAULT_MODEL = "gpt-4o"


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
    # Route through LiteLLM for custom OpenAI-compatible endpoints
    if _CUSTOM_BASE_URL and not resolved.startswith("litellm/") and resolved != "gpt-4o":
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
    key = model or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)
    # Resolve aliases: if key maps to a MODEL_MAP entry, use the key
    ctx = CONTEXT_WINDOWS.get(key, 128_000)
    if ctx <= 32_000:
        return 25
    if ctx <= 200_000:
        return 50
    return 100


def get_context_window(model: str | None = None) -> int:
    """Get context window size (in tokens) for the active model.

    Priority: VULTURE_LLM_CTX_SIZE env > CONTEXT_WINDOWS dict > 32K default.

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
    return CONTEXT_WINDOWS.get(key, 32_000)


def is_ollama_model(model: str | None = None) -> bool:
    """Check if the resolved model uses Ollama (local)."""
    resolved = get_model(model)
    return "ollama/" in resolved
