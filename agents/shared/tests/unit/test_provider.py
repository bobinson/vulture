"""Tests for shared.llm.provider module."""


def test_get_model_default(monkeypatch):
    from shared.llm.provider import get_model
    monkeypatch.delenv("VULTURE_LLM_MODEL", raising=False)
    assert get_model() == "gpt-4o"


def test_get_model_cloud_providers():
    from shared.llm.provider import get_model
    assert get_model("gpt-4o") == "gpt-4o"
    assert get_model("claude-sonnet") == "litellm/anthropic/claude-sonnet-4-5-20250514"
    assert get_model("gemini-pro") == "litellm/gemini/gemini-1.5-pro"


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


def test_get_model_custom_base_url_provider_prefixed(monkeypatch):
    """Models with provider prefix (openai/X) get litellm/ not litellm/openai/."""
    import shared.llm.provider as provider
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_model("openai/gpt-oss-20b") == "litellm/openai/gpt-oss-20b"


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
    assert get_context_window("gemini-pro") == 1_048_576


def test_get_context_window_default(monkeypatch):
    """Unknown model with no env var returns 32K default."""
    from shared.llm.provider import get_context_window
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.delenv("VULTURE_LLM_MODEL", raising=False)
    import shared.llm.provider as provider
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    assert get_context_window("totally-unknown-model") == 32_000


def test_get_context_window_custom_endpoint_returns_8192(monkeypatch):
    """Custom endpoint (LM Studio, vLLM) falls back to 8192 for truly unknown models."""
    import shared.llm.provider as provider
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_context_window("unknown-local-model") == 8_192


def test_get_context_window_family_inference_qwen(monkeypatch):
    """Qwen model family inferred from model string on custom endpoint."""
    import shared.llm.provider as provider
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    # "qwen/qwen3.5-35b-a3b" contains "qwen3" → 32768
    assert provider.get_context_window("qwen/qwen3.5-35b-a3b") == 32_768


def test_get_context_window_family_inference_llama(monkeypatch):
    """Llama model family inferred from model string."""
    import shared.llm.provider as provider
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_context_window("meta-llama/llama-3.1-70b") == 128_000


def test_get_context_window_family_inference_deepseek(monkeypatch):
    """DeepSeek model family inferred from model string."""
    import shared.llm.provider as provider
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_context_window("deepseek/deepseek-r1-0528") == 64_000


def test_get_context_window_family_inference_no_custom_url(monkeypatch):
    """Family inference works even without OPENAI_BASE_URL."""
    import shared.llm.provider as provider
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    assert provider.get_context_window("qwen/qwen3.5-35b-a3b") == 32_768


def test_get_context_window_env_overrides_family(monkeypatch):
    """VULTURE_LLM_CTX_SIZE takes priority over family inference."""
    import shared.llm.provider as provider
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "65536")
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:1234/v1")
    assert provider.get_context_window("qwen/qwen3.5-35b-a3b") == 65_536


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


def test_get_fallback_models_known():
    """Known models have defined fallback chains."""
    from shared.llm.provider import get_fallback_models
    fallbacks = get_fallback_models("gpt-4o")
    assert isinstance(fallbacks, list)
    assert len(fallbacks) >= 1
    assert "gpt-4o" not in fallbacks  # primary not in fallback list


def test_get_fallback_models_unknown():
    """Unknown models return empty fallback list."""
    from shared.llm.provider import get_fallback_models
    assert get_fallback_models("totally-unknown") == []


def test_get_fallback_models_from_env(monkeypatch):
    """Uses VULTURE_LLM_MODEL env when no arg given."""
    from shared.llm.provider import get_fallback_models
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:1.7b")
    fallbacks = get_fallback_models()
    assert "qwen3:8b" in fallbacks


def test_fallback_chains_no_self_reference():
    """No model should appear in its own fallback chain."""
    from shared.llm.provider import FALLBACK_CHAINS
    for model, chain in FALLBACK_CHAINS.items():
        assert model not in chain, f"{model} references itself in fallback chain"


def test_fallback_chains_all_models_valid():
    """All models in fallback chains should be resolvable via MODEL_MAP."""
    from shared.llm.provider import FALLBACK_CHAINS, MODEL_MAP
    for model, chain in FALLBACK_CHAINS.items():
        assert model in MODEL_MAP, f"Primary {model} not in MODEL_MAP"
        for fallback in chain:
            assert fallback in MODEL_MAP, f"Fallback {fallback} not in MODEL_MAP"


# --- Tests for estimate_cost ---

class TestEstimateCost:
    def test_gpt4o_cost(self):
        from shared.llm.provider import estimate_cost
        # 1M input tokens at $2.50 + 1M output tokens at $10.00 = $12.50
        cost = estimate_cost(1_000_000, 1_000_000, model="gpt-4o")
        assert cost == 12.50

    def test_claude_cost(self):
        from shared.llm.provider import estimate_cost
        cost = estimate_cost(1_000_000, 0, model="claude-sonnet")
        assert cost == 3.00

    def test_local_model_zero_cost(self):
        from shared.llm.provider import estimate_cost
        cost = estimate_cost(100_000, 50_000, model="qwen3:1.7b")
        assert cost == 0.0

    def test_unknown_model_zero_cost(self):
        from shared.llm.provider import estimate_cost
        cost = estimate_cost(100_000, 50_000, model="totally-unknown")
        assert cost == 0.0

    def test_zero_tokens_zero_cost(self):
        from shared.llm.provider import estimate_cost
        assert estimate_cost(0, 0, model="gpt-4o") == 0.0

    def test_small_usage(self):
        from shared.llm.provider import estimate_cost
        # 1000 input tokens of gpt-4o: 1000 * 2.50 / 1M = 0.0025
        cost = estimate_cost(1000, 0, model="gpt-4o")
        assert abs(cost - 0.0025) < 0.0001

    def test_uses_env_default(self, monkeypatch):
        from shared.llm.provider import estimate_cost
        monkeypatch.setenv("VULTURE_LLM_MODEL", "gemini-pro")
        # gemini-pro: input $1.25, output $5.00
        cost = estimate_cost(1_000_000, 1_000_000)
        assert cost == 6.25


# --- Tests for get_model_settings ---

class TestGetModelSettings:
    def test_default_has_temperature(self):
        from shared.llm.provider import get_model_settings
        settings = get_model_settings("gpt-4o")
        assert settings["temperature"] == 0.1

    def test_anthropic_has_caching_header(self):
        from shared.llm.provider import get_model_settings
        settings = get_model_settings("claude-sonnet")
        assert "extra_headers" in settings
        assert "anthropic-beta" in settings["extra_headers"]
        assert "prompt-caching" in settings["extra_headers"]["anthropic-beta"]

    def test_openai_no_extra_headers(self):
        from shared.llm.provider import get_model_settings
        settings = get_model_settings("gpt-4o")
        assert "extra_headers" not in settings

    def test_gemini_no_extra_headers(self):
        from shared.llm.provider import get_model_settings
        settings = get_model_settings("gemini-pro")
        assert "extra_headers" not in settings

    def test_ollama_no_extra_headers(self):
        from shared.llm.provider import get_model_settings
        settings = get_model_settings("qwen3:1.7b")
        assert "extra_headers" not in settings


# --- Tests for get_model_with_fallback ---

class TestGetModelWithFallback:
    def test_returns_primary_when_available(self):
        from shared.llm.provider import get_model_with_fallback
        from shared.llm.cooldown import cooldown_manager
        cooldown_manager.reset()
        result = get_model_with_fallback("gpt-4o")
        assert result == "gpt-4o"

    def test_falls_back_when_primary_in_cooldown(self):
        from shared.llm.provider import get_model_with_fallback, get_model
        from shared.llm.cooldown import cooldown_manager
        cooldown_manager.reset()
        # Put primary in cooldown
        resolved_primary = get_model("gpt-4o")
        for _ in range(5):  # exceed failure threshold
            cooldown_manager.record_failure(resolved_primary)
        result = get_model_with_fallback("gpt-4o")
        # Should get a fallback (claude-sonnet or gemini-pro)
        assert result != resolved_primary
        cooldown_manager.reset()

    def test_returns_primary_when_all_in_cooldown(self):
        from shared.llm.provider import get_model_with_fallback, get_model, get_fallback_models
        from shared.llm.cooldown import cooldown_manager
        cooldown_manager.reset()
        # Put all models in cooldown
        primary = get_model("gpt-4o")
        for _ in range(5):
            cooldown_manager.record_failure(primary)
        for fb_key in get_fallback_models("gpt-4o"):
            fb_resolved = get_model(fb_key)
            for _ in range(5):
                cooldown_manager.record_failure(fb_resolved)
        result = get_model_with_fallback("gpt-4o")
        # Falls back to primary when all are in cooldown
        assert result == primary
        cooldown_manager.reset()

    def test_uses_env_default(self, monkeypatch):
        from shared.llm.provider import get_model_with_fallback
        from shared.llm.cooldown import cooldown_manager
        cooldown_manager.reset()
        monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:1.7b")
        result = get_model_with_fallback()
        assert result == "litellm/ollama/qwen3:1.7b"
        cooldown_manager.reset()


# --- Tests for COST_PER_1M_TOKENS ---

class TestCostDict:
    def test_all_known_models_have_costs(self):
        from shared.llm.provider import COST_PER_1M_TOKENS, MODEL_MAP
        for key in MODEL_MAP:
            assert key in COST_PER_1M_TOKENS, f"Model {key} missing from COST_PER_1M_TOKENS"

    def test_costs_are_non_negative(self):
        from shared.llm.provider import COST_PER_1M_TOKENS
        for model, (inp, out) in COST_PER_1M_TOKENS.items():
            assert inp >= 0.0, f"{model} has negative input cost"
            assert out >= 0.0, f"{model} has negative output cost"

    def test_local_models_are_free(self):
        from shared.llm.provider import COST_PER_1M_TOKENS
        local_models = ["qwen3:1.7b", "qwen3:8b", "qwen3:14b", "llama3.2", "mistral"]
        for model in local_models:
            inp, out = COST_PER_1M_TOKENS[model]
            assert inp == 0.0 and out == 0.0, f"Local model {model} should be free"
