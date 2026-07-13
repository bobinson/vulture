"""Feature 0064: LLM-broker agent client seam.

Dual-mode. When ``VULTURE_LLM_BROKER`` is off/unset (Mode A default), nothing
here touches the OpenAI-Agents-SDK model client — today's behavior is unchanged.
When on, the agent repoints its SDK model client at the internal LLM broker:
``base_url`` -> ``VULTURE_LLM_BROKER_URL`` and ``api_key`` -> the per-run
``broker_token`` from the AuditRequest.

Only the client is repointed; model selection (``provider.get_model``) is never
rewritten. The broker URL and token are secret-class: they are never logged.
"""

import contextvars
import os
from dataclasses import dataclass
from typing import Any, Callable

# Same truthiness contract as VULTURE_LLM_TIER3 (audit_runner) — keep in sync.
_TRUTHY = ("on", "true", "1", "yes")

# Ambient per-run broker token. Bound by the transport (sse_app) from
# ``AuditRequest.broker_token`` into the request contextvars context, exactly
# like the feature 0061 cancel token — the token is a cross-cutting per-run
# runtime concern, not threaded through every agent's ``run_audit`` signature.
# ``ContextVars`` are copied by ``contextvars.copy_context()`` so the value is
# visible in the audit worker thread that drives the LLM phase. Secret-class.
_current_broker_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "vulture_broker_token", default=None
)


def set_broker_token(token: str | None) -> contextvars.Token:
    """Bind *token* as the ambient per-run broker token; returns a reset handle."""
    return _current_broker_token.set(token)


def current_broker_token() -> str | None:
    """The ambient per-run broker token for the current context, or ``None``."""
    return _current_broker_token.get()


@dataclass(frozen=True)
class BrokerConfig:
    """Resolved broker repoint target. ``api_key`` is secret-class."""

    base_url: str
    api_key: str


def broker_enabled() -> bool:
    """Whether the LLM broker is on. Off/unset => Mode A default (disabled)."""
    return os.environ.get("VULTURE_LLM_BROKER", "").strip().lower() in _TRUTHY


def resolve_broker_config(token: str | None) -> BrokerConfig | None:
    """Derive the broker repoint config, or ``None`` when no repoint applies.

    Returns ``None`` (fail-safe, no repoint) when the broker is disabled, when
    no broker URL is configured, or when the run token is missing/empty (never
    install a keyless client).
    """
    if not broker_enabled():
        return None
    if not token:
        return None
    url = os.environ.get("VULTURE_LLM_BROKER_URL", "").strip()
    if not url:
        return None
    return BrokerConfig(base_url=url, api_key=token)


def broker_model_provider(
    *,
    client_factory: Callable[..., Any] | None = None,
    provider_factory: Callable[[Any], Any] | None = None,
) -> Any | None:
    """Build a PER-RUN SDK model provider routing this run through the broker.

    Returns an ``agents`` ModelProvider backed by an ``AsyncOpenAI`` client
    pointed at the broker with THIS run's ambient token (bound by the
    transport), for use as ``RunConfig(model_provider=...)``. Fail-safe:
    returns ``None`` when the broker is off, unconfigured, or the run has no
    token (Mode A behavior unchanged; env-key path untouched).

    This deliberately replaces the former ``set_default_openai_client``
    approach: that mutated PROCESS-GLOBAL SDK state, so with
    ``VULTURE_AUDIT_EXECUTOR_WORKERS > 1`` two concurrent audits raced the
    global and could bleed one run's broker token into another run's calls.
    A per-run provider carried on the run config shares nothing.

    ``client_factory(base_url=..., api_key=...)`` and ``provider_factory(client)``
    are injectable for tests; the defaults build the real SDK objects lazily
    (chat/completions mode — the broker implements /chat/completions, not the
    Responses API). Model selection (``provider.get_model``) is never rewritten.
    """
    cfg = resolve_broker_config(current_broker_token())
    if cfg is None:
        return None  # fail-safe: don't import the SDK when no repoint applies
    make_client = client_factory or _default_client_factory
    make_provider = provider_factory or _default_provider_factory
    return make_provider(make_client(base_url=cfg.base_url, api_key=cfg.api_key))


def _default_client_factory(*, base_url: str, api_key: str) -> Any:
    """Real SDK client (lazy import so this module needs no openai at import)."""
    from openai import AsyncOpenAI

    return AsyncOpenAI(base_url=base_url, api_key=api_key)


def _default_provider_factory(client: Any) -> Any:
    """Real SDK ModelProvider in chat/completions mode (the broker's surface)."""
    from agents.models.openai_provider import OpenAIProvider

    return OpenAIProvider(openai_client=client, use_responses=False)
