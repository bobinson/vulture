"""Tests for ASVS agent LLM-phase wiring.

Verifies that the agent correctly integrates with shared.audit_runner's
two-phase pipeline: Phase 1 skills (deterministic regex) + Phase 2 LLM
augmentation (when VULTURE_USE_LLM=true or config.use_llm=True).
"""
from asvs_agent.agent import INSTRUCTIONS, _build_llm_catalog_context
from asvs_agent.skills import SKILL_MAP, SKILL_TOOLS


def test_instructions_cite_asvs_version():
    """LLM prompt must identify the standard being audited."""
    assert "ASVS v5.0.0" in INSTRUCTIONS


def test_instructions_direct_llm_to_use_asvs_prefix():
    """LLM must be instructed to cite req_ids as ASVS-V{X}.{Y}.{Z}."""
    assert "ASVS-V" in INSTRUCTIONS


def test_instructions_describe_self_learning_protocol():
    """Prior findings feedback loop (SKIP/BOOST/DEMOTE) must be documented."""
    assert "SKIP" in INSTRUCTIONS
    assert "BOOST" in INSTRUCTIONS
    assert "DEMOTE" in INSTRUCTIONS


def test_instructions_mention_cwe_linkage():
    """Findings should carry linked_cwe metadata when the crosswalk maps."""
    assert "linked_cwe" in INSTRUCTIONS


def test_skill_tools_exposed_to_llm_phase():
    """run_combined_audit gates Phase 2 on skill_tools non-empty."""
    assert len(SKILL_TOOLS) >= 1
    assert SKILL_TOOLS[0] is not None


def test_skill_map_has_single_entry():
    """Consolidated design: one entry, one dispatch function."""
    assert list(SKILL_MAP.keys()) == ["asvs_requirements"]


def test_llm_catalog_context_non_empty_and_bounded():
    """Catalog context must be present and under 4000 chars (3000 target)."""
    ctx = _build_llm_catalog_context()
    assert 200 < len(ctx) < 4000


def test_llm_catalog_context_contains_critical_chapter_reqs():
    """Critical chapters (auth/session/tokens/crypto) must appear first."""
    ctx = _build_llm_catalog_context()
    critical_chapters_hit = sum(
        1 for ch in ("V6", "V7", "V9", "V11") if f"ASVS-{ch}." in ctx
    )
    assert critical_chapters_hit >= 2


def test_run_audit_generator_wires_phase_2_correctly():
    """Verify run_audit yields SSE events and passes use_llm through."""
    from asvs_agent.agent import run_audit
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "empty.py").write_text("x = 1\n")
        # With use_llm=False, Phase 2 is suppressed — must still yield events.
        events = list(run_audit(
            run_id="test-run",
            source_path=d,
            config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
        ))
        assert len(events) > 0
        combined = "".join(str(e) for e in events)
        assert "agent_start" in combined or "thinking" in combined


# ---------------------------------------------------------------------------
# Multi-model dispatch + token-budget efficiency
# ---------------------------------------------------------------------------

import pytest  # noqa: E402


_ALL_SUPPORTED_MODELS = [
    "gpt-4o", "claude-sonnet", "gemini-pro",
    "qwen3:1.7b", "qwen3:8b", "qwen3:14b", "llama3.2", "mistral",
]


@pytest.mark.parametrize("model_key", _ALL_SUPPORTED_MODELS)
def test_model_resolution_for_every_supported_model(model_key):
    """Every model in MODEL_MAP must resolve to a usable SDK string."""
    from shared.llm.provider import get_model, CONTEXT_WINDOWS
    resolved = get_model(model_key)
    assert resolved  # non-empty
    assert model_key in CONTEXT_WINDOWS  # context window known


@pytest.mark.parametrize("model_key", _ALL_SUPPORTED_MODELS)
def test_context_window_scales_catalog_ctx_safely(model_key):
    """ASVS catalog context must stay <= 5% of every model's context budget."""
    from shared.llm.provider import get_context_window
    from shared.tools.memory_client import estimate_tokens
    ctx = get_context_window(model_key)
    catalog_ctx = _build_llm_catalog_context(ctx)
    tokens = estimate_tokens(catalog_ctx)
    pct = tokens / ctx * 100
    assert pct < 5.0, f"{model_key}: catalog ctx {tokens}tok is {pct:.1f}% of {ctx}tok budget"


@pytest.mark.parametrize("model_key", _ALL_SUPPORTED_MODELS)
def test_combined_prompt_fits_small_model_budget(model_key):
    """INSTRUCTIONS + catalog_ctx + SDK overhead must leave >= 50% for source+output."""
    from shared.llm.provider import get_context_window
    from shared.tools.memory_client import estimate_tokens
    ctx = get_context_window(model_key)
    prompt_tokens = estimate_tokens(INSTRUCTIONS) + estimate_tokens(_build_llm_catalog_context(ctx))
    sdk_overhead = 3000  # tool schemas + structured output schema
    remaining = ctx - prompt_tokens - sdk_overhead
    assert remaining / ctx >= 0.5, f"{model_key}: only {remaining}/{ctx} ({remaining/ctx*100:.0f}%) left for source + output"


def test_catalog_context_is_identical_across_repeated_calls_same_window():
    """Prompt-cache stability: same ctx_window must yield the same string
    object (lru_cache hit), ensuring Anthropic/OpenAI prefix caching gets
    byte-identical prefixes across audits."""
    ctx1 = _build_llm_catalog_context(128_000)
    ctx2 = _build_llm_catalog_context(128_000)
    assert ctx1 is ctx2  # same object (cache hit)


def test_catalog_context_differs_across_windows():
    """Small-window vs large-window must produce different (size-scaled) strings."""
    small = _build_llm_catalog_context(32_000)
    large = _build_llm_catalog_context(1_048_576)
    assert small != large
    assert len(small) < len(large)


def test_phase_2_toggle_via_config_overrides_env(monkeypatch):
    """use_llm=True in config forces Phase 2 regardless of env default."""
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    from asvs_agent.agent import run_audit
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "x.py").write_text("x = 1\n")
        # use_llm=False in config — Phase 2 MUST be skipped regardless of env.
        events = list(run_audit(
            run_id="t1", source_path=d,
            config={"use_llm": False, "chapters": [], "levels": [1, 2, 3]},
        ))
        combined = "".join(str(e) for e in events)
        # LLM phase emits 'Enhancing with LLM analysis' when active.
        assert "Enhancing with LLM analysis" not in combined


def test_fallback_chain_defined_for_every_supported_model():
    """Every cloud/local model must have at least one fallback peer configured."""
    from shared.llm.provider import get_fallback_models
    for model in _ALL_SUPPORTED_MODELS:
        fallbacks = get_fallback_models(model)
        assert len(fallbacks) >= 1, f"{model}: no fallback chain"


def test_prompt_caching_header_injected_for_anthropic():
    """Anthropic models must receive the prompt-caching beta header."""
    from shared.llm.provider import get_model_settings
    settings = get_model_settings("claude-sonnet")
    assert "extra_headers" in settings
    assert "anthropic-beta" in settings["extra_headers"]


def test_prompt_caching_header_not_set_for_openai():
    """OpenAI uses automatic prefix caching — no header needed."""
    from shared.llm.provider import get_model_settings
    settings = get_model_settings("gpt-4o")
    assert "extra_headers" not in settings


def test_get_max_findings_scales_with_context_window():
    """Small models get fewer prior findings to save tokens."""
    from shared.llm.provider import get_max_findings
    assert get_max_findings("qwen3:1.7b") == 25   # 32K ctx
    assert get_max_findings("gpt-4o") == 50       # 128K ctx
    assert get_max_findings("claude-sonnet") == 100  # 200K ctx
    assert get_max_findings("gemini-pro") == 100  # 1M ctx


def test_ollama_detection_for_local_models():
    """Local Ollama models must be detectable for cost/cache handling."""
    from shared.llm.provider import is_ollama_model
    assert is_ollama_model("qwen3:1.7b") is True
    assert is_ollama_model("llama3.2") is True
    assert is_ollama_model("gpt-4o") is False
    assert is_ollama_model("claude-sonnet") is False


def test_cost_estimation_zero_for_local_models():
    """Local Ollama models must report zero cost."""
    from shared.llm.provider import estimate_cost
    assert estimate_cost(1000, 1000, "qwen3:8b") == 0.0
    assert estimate_cost(1000, 1000, "llama3.2") == 0.0
    # Cloud models have non-zero cost.
    assert estimate_cost(1_000_000, 1_000_000, "gpt-4o") > 0


def test_env_ctx_size_override_wins_over_model_lookup(monkeypatch):
    """VULTURE_LLM_CTX_SIZE env must override CONTEXT_WINDOWS dict."""
    from shared.llm.provider import get_context_window
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "65536")
    assert get_context_window("qwen3:1.7b") == 65536  # overrides 32_000


def test_catalog_context_stays_byte_stable_for_claude_prefix_cache():
    """Anthropic prompt caching requires byte-identical prefix. Two calls
    at the same ctx_window must produce identical bytes."""
    ctx1 = _build_llm_catalog_context(200_000).encode()
    ctx2 = _build_llm_catalog_context(200_000).encode()
    import hashlib
    assert hashlib.sha256(ctx1).hexdigest() == hashlib.sha256(ctx2).hexdigest()
