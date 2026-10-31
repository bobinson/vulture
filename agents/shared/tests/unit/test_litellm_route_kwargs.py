"""`litellm_route_kwargs`: where a direct litellm call goes for this run.

The end-to-end contract (a real litellm call against a stub broker) lives in
agents/prove/tests/e2e/test_prove_llm_broker_route.py; these pin the branches.
"""

import pytest

from shared.llm.broker import broker_headers, set_broker_task_type, set_broker_token
from shared.llm.provider import bare_model_name, litellm_route_kwargs

BROKER_URL = "http://127.0.0.1:8090/v1"


@pytest.fixture
def broker_run(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", BROKER_URL)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gw.example/v1")  # must be ignored
    set_broker_token("run-tok")
    set_broker_task_type("prove")
    yield
    set_broker_token(None)
    set_broker_task_type(None)


@pytest.mark.parametrize("model", ["qwen3.8-flash", "openai/qwen3.8-flash", "litellm/openai/qwen3.8-flash"])
def test_broker_run_goes_to_the_broker_with_the_bare_model(broker_run, model):
    kwargs = litellm_route_kwargs(model)
    assert kwargs["model"] == "openai/qwen3.8-flash"
    assert kwargs["api_base"] == BROKER_URL
    assert kwargs["api_key"] == "run-tok"
    assert kwargs["extra_headers"] == {"X-Vulture-Task-Type": "prove"}


def test_broker_run_makes_one_http_attempt_per_call(broker_run):
    kwargs = litellm_route_kwargs("m")
    assert kwargs["max_retries"] == 0
    assert kwargs["num_retries"] == 0
    assert kwargs["timeout"] > 0


def test_broker_on_without_a_run_token_uses_the_env_path(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", BROKER_URL)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    set_broker_token(None)
    assert litellm_route_kwargs("gpt-4o") == {"model": "gpt-4o"}


def test_custom_endpoint_without_a_key_gets_a_placeholder(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert litellm_route_kwargs("openai/qwen") == {
        "model": "openai/qwen", "api_base": "http://localhost:1234/v1", "api_key": "not-needed",
    }


def test_custom_endpoint_with_a_key_leaves_it_to_litellm(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-local")
    assert litellm_route_kwargs("openai/qwen") == {"model": "openai/qwen", "api_base": "http://localhost:1234/v1"}


def test_no_task_type_sends_no_scope_header():
    set_broker_task_type(None)
    assert broker_headers() == {}


@pytest.mark.parametrize(
    ("raw", "bare"),
    [("litellm/anthropic/claude-x", "claude-x"), ("ollama/qwen3:8b", "qwen3:8b"), ("gpt-4o", "gpt-4o")],
)
def test_bare_model_name(raw, bare):
    assert bare_model_name(raw) == bare
