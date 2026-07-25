"""RED-phase contract tests for the feature 0064 LLM-broker agent client seam.

These tests define the behavior of ``shared.llm.broker`` (not yet implemented)
and the ``broker_token`` field on ``AuditRequest``. They MUST compile and FAIL
against the current tree (module absent) until the GREEN phase lands.

Contract under test (LLD §6, §17, §18, §20):

  * ``AuditRequest.broker_token`` is additive/optional, default ``None``.
  * ``broker_enabled()`` reads ``VULTURE_LLM_BROKER`` (on/true/1 enable it;
    off/unset disable it) — this is the dual-mode switch.
  * ``resolve_broker_config(token)`` returns a config with ``base_url`` =
    ``VULTURE_LLM_BROKER_URL`` and ``api_key`` = the run token *only* when the
    broker is enabled AND a URL is configured; otherwise ``None``.
  * ``apply_broker_client(token, *, client_factory, set_client)`` is the actual
    SDK seam. Dual-mode:
      - OFF  → does NOT touch the SDK client (set_client never called),
               returns ``None`` (today's behavior, unchanged).
      - ON   → builds a client with base_url→broker + api_key→broker_token and
               installs it via the injected ``set_client`` (the external
               boundary — SDK global mutation — is the ONLY thing mocked),
               returns the resolved config.
  * Security/edge cases: a missing URL while enabled is fail-safe (no repoint);
    a missing/None token while enabled is fail-safe (never install a keyless
    client); ``get_model()`` is untouched (the broker only repoints the client,
    it does not rewrite model selection).
"""

import pytest

# --------------------------------------------------------------------------
# AuditRequest.broker_token field
# --------------------------------------------------------------------------

def test_audit_request_broker_token_defaults_none():
    from shared.models.audit_request import AuditRequest
    req = AuditRequest(run_id="r1", source_path="/src")
    assert req.broker_token is None


def test_audit_request_broker_token_roundtrips():
    from shared.models.audit_request import AuditRequest
    req = AuditRequest(run_id="r1", source_path="/src", broker_token="jwt.abc.def")
    assert req.broker_token == "jwt.abc.def"
    # Optional + additive: serialization keeps it, existing fields unaffected.
    dumped = req.model_dump()
    assert dumped["broker_token"] == "jwt.abc.def"
    assert dumped["run_id"] == "r1"


# --------------------------------------------------------------------------
# broker_enabled() — the dual-mode switch (VULTURE_LLM_BROKER)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("on", True),
        ("ON", True),
        ("true", True),
        ("True", True),
        ("1", True),
        ("off", False),
        ("false", False),
        ("0", False),
        ("", False),
        (None, False),  # unset env => default off (Mode A zero-config)
    ],
)
def test_broker_enabled_env_matrix(monkeypatch, value, expected):
    from shared.llm.broker import broker_enabled
    if value is None:
        monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    else:
        monkeypatch.setenv("VULTURE_LLM_BROKER", value)
    assert broker_enabled() is expected


# --------------------------------------------------------------------------
# resolve_broker_config() — base_url + api_key derivation
# --------------------------------------------------------------------------

def test_resolve_config_disabled_returns_none(monkeypatch):
    from shared.llm.broker import resolve_broker_config
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    assert resolve_broker_config("tok") is None


def test_resolve_config_enabled_sets_base_url_and_token(monkeypatch):
    from shared.llm.broker import resolve_broker_config
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    cfg = resolve_broker_config("run-token-xyz")
    assert cfg is not None
    assert cfg.base_url == "http://broker:8080/internal/v1/llm"
    assert cfg.api_key == "run-token-xyz"


def test_resolve_config_enabled_but_no_url_is_none(monkeypatch):
    # Fail-safe: enabled with no URL must not silently pick a wrong target.
    from shared.llm.broker import resolve_broker_config
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.delenv("VULTURE_LLM_BROKER_URL", raising=False)
    assert resolve_broker_config("tok") is None


def test_resolve_config_enabled_but_no_token_is_none(monkeypatch):
    # Security: never derive a keyless broker config (would install a client
    # with no bearer token). Missing/None token => no repoint.
    from shared.llm.broker import resolve_broker_config
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    assert resolve_broker_config(None) is None
    assert resolve_broker_config("") is None


# --------------------------------------------------------------------------
# broker_model_provider() — the per-run SDK seam (dual-mode). The former
# global-mutation seam (apply_broker_client/set_default_openai_client) was
# removed: process-global state raced across concurrent audits. Full per-run
# coverage lives in test_broker_per_run_provider.py; the dual-mode/fail-safe
# contract stays pinned here.
# --------------------------------------------------------------------------

class _FakeClient:
    """Stand-in for openai.AsyncOpenAI capturing the config it was built with."""

    def __init__(self, *, base_url, api_key, **kwargs):
        self.base_url = base_url
        self.api_key = api_key
        self.kwargs = kwargs


def _build_provider_with_token(token):
    import contextvars

    from shared.llm import broker

    def _run():
        broker.set_broker_token(token)
        return broker.broker_model_provider(
            client_factory=lambda base_url, api_key: _FakeClient(base_url=base_url, api_key=api_key),
            provider_factory=lambda client: client,  # provider == client for assertions
        )

    return contextvars.copy_context().run(_run)


def test_provider_off_is_noop(monkeypatch):
    # OFF => today's behavior, unchanged: no provider, env-key path untouched.
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    assert _build_provider_with_token("tok") is None


def test_provider_on_carries_base_url_and_run_token(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    client = _build_provider_with_token("run-token-xyz")
    assert client is not None
    assert client.base_url == "http://broker:8080/internal/v1/llm"
    assert client.api_key == "run-token-xyz"


def test_provider_on_without_token_is_none(monkeypatch):
    # Security/edge: enabled but no run token => fail-safe, no keyless client.
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    assert _build_provider_with_token(None) is None


def test_provider_on_without_url_is_none(monkeypatch):
    # Fail-safe: enabled but no broker URL => no repoint.
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.delenv("VULTURE_LLM_BROKER_URL", raising=False)
    assert _build_provider_with_token("tok") is None


def test_provider_does_not_rewrite_model_selection(monkeypatch):
    # The broker seam ONLY carries the client; get_model() must be untouched.
    from shared.llm.provider import get_model
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker:8080/internal/v1/llm")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    before = get_model()
    _build_provider_with_token("tok")
    assert get_model() == before == "gpt-4o"


# --------------------------------------------------------------------------
# Ambient per-run token contextvar (transport → LLM phase seam, LLD §17/§20)
# --------------------------------------------------------------------------

def test_broker_token_contextvar_default_none():
    from shared.llm.broker import current_broker_token
    assert current_broker_token() is None


def test_broker_token_contextvar_isolated_per_context():
    # Bound value must be visible via a copied context (mirrors how the
    # transport binds it and the audit worker thread reads it) and must NOT
    # leak into the caller's context.
    import contextvars

    from shared.llm.broker import current_broker_token, set_broker_token

    seen = {}

    def _bind_and_read():
        set_broker_token("run-token-abc")
        seen["inner"] = current_broker_token()

    ctx = contextvars.copy_context()
    ctx.run(_bind_and_read)
    assert seen["inner"] == "run-token-abc"
    assert current_broker_token() is None  # no leak into caller context


# --------------------------------------------------------------------------
# The ambient-token → per-run-provider path (formerly apply_broker_from_
# context, removed with the global-mutation seam) is covered end-to-end in
# test_broker_per_run_provider.py.
# --------------------------------------------------------------------------
