"""Tests for shared.llm.provider module."""


def test_get_model_default(monkeypatch):
    from shared.llm.provider import get_model
    monkeypatch.delenv("VULTURE_LLM_MODEL", raising=False)
    assert get_model() == "gpt-4o"


def test_get_model_cloud_providers():
    from shared.llm.provider import get_model
    assert get_model("gpt-4o") == "gpt-4o"
    assert get_model("claude-sonnet") == "litellm/anthropic/claude-sonnet-4-5-20250929"
    assert get_model("gemini-pro") == "litellm/gemini/gemini-pro"


def test_get_model_ollama_models():
    from shared.llm.provider import get_model
    assert get_model("qwen3:1.7b") == "litellm/ollama/qwen3:1.7b"
    assert get_model("qwen3:8b") == "litellm/ollama/qwen3:8b"
    assert get_model("qwen3:14b") == "litellm/ollama/qwen3:14b"
    assert get_model("llama3.2") == "litellm/ollama/llama3.2"
    assert get_model("mistral") == "litellm/ollama/mistral"


def test_get_model_passthrough():
    from shared.llm.provider import get_model
    # Unknown model strings pass through unchanged
    assert get_model("custom/my-model") == "custom/my-model"


def test_get_model_from_env(monkeypatch):
    from shared.llm.provider import get_model
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:1.7b")
    assert get_model() == "litellm/ollama/qwen3:1.7b"


def test_get_embedding_model_cloud():
    from shared.llm.provider import get_embedding_model
    assert get_embedding_model("gpt-4o") == "text-embedding-3-small"
    assert get_embedding_model("claude-sonnet") == "text-embedding-3-small"


def test_get_embedding_model_ollama():
    from shared.llm.provider import get_embedding_model
    assert get_embedding_model("qwen3:1.7b") == "nomic-embed-text"
    assert get_embedding_model("qwen3:8b") == "nomic-embed-text"
    assert get_embedding_model("llama3.2") == "nomic-embed-text"


def test_get_embedding_model_default():
    from shared.llm.provider import get_embedding_model
    assert get_embedding_model("unknown-model") == "text-embedding-3-small"


def test_is_ollama_model():
    from shared.llm.provider import is_ollama_model
    assert is_ollama_model("qwen3:1.7b") is True
    assert is_ollama_model("qwen3:8b") is True
    assert is_ollama_model("llama3.2") is True
    assert is_ollama_model("gpt-4o") is False
    assert is_ollama_model("claude-sonnet") is False
    assert is_ollama_model("gemini-pro") is False


def test_get_model_custom_base_url_prefixes_unknown(monkeypatch):
    """When OPENAI_BASE_URL is set, unknown models get litellm/openai/ prefix."""
    import shared.llm.provider as provider
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_model("glm-4-9b-0414-flash") == "litellm/openai/glm-4-9b-0414-flash"


def test_get_model_custom_base_url_skips_litellm_prefixed(monkeypatch):
    """Models already litellm/ prefixed are not double-prefixed."""
    import shared.llm.provider as provider
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_model("qwen3:1.7b") == "litellm/ollama/qwen3:1.7b"


def test_get_model_custom_base_url_skips_gpt4o(monkeypatch):
    """gpt-4o is excluded from prefixing (native OpenAI model)."""
    import shared.llm.provider as provider
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_model("gpt-4o") == "gpt-4o"


def test_get_model_no_custom_base_url_passes_through(monkeypatch):
    """Without OPENAI_BASE_URL, unknown models pass through unchanged."""
    import shared.llm.provider as provider
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    assert provider.get_model("glm-4-9b-0414-flash") == "glm-4-9b-0414-flash"


def test_get_context_window_from_env(monkeypatch):
    """VULTURE_LLM_CTX_SIZE env var overrides everything."""
    from shared.llm.provider import get_context_window
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "65536")
    assert get_context_window() == 65536


def test_get_context_window_from_dict(monkeypatch):
    """Known model key looks up CONTEXT_WINDOWS dict."""
    from shared.llm.provider import get_context_window
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    assert get_context_window("gpt-4o") == 128_000
    assert get_context_window("qwen3:1.7b") == 32_000
    assert get_context_window("gemini-pro") == 1_000_000


def test_get_context_window_default(monkeypatch):
    """Unknown model with no env var returns 32K default."""
    from shared.llm.provider import get_context_window
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.delenv("VULTURE_LLM_MODEL", raising=False)
    assert get_context_window("totally-unknown-model") == 32_000


def test_get_context_window_invalid_env(monkeypatch):
    """Invalid env var value falls through to dict/default."""
    from shared.llm.provider import get_context_window
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "not_a_number")
    # Falls through to dict lookup for gpt-4o
    assert get_context_window("gpt-4o") == 128_000


def test_get_context_window_env_overrides_known_model(monkeypatch):
    """Env var should override even for a known model."""
    from shared.llm.provider import get_context_window
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "8192")
    assert get_context_window("gpt-4o") == 8192
