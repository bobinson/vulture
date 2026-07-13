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


# Ambient per-run task_type (§26 C1). The broker requires an X-Vulture-Task-Type
# header to scope-check a completion; it is a per-run constant, so the SDK client
# carries it via ``default_headers``. Bound by the transport alongside the token.
_current_broker_task_type: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "vulture_broker_task_type", default=None
)

# Per-run broker client handle, stored so the run can close it (§26 M7 — avoid
# leaking the AsyncOpenAI httpx pool/FDs in a long-lived agent process).
_current_broker_client: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "vulture_broker_client", default=None
)


def set_broker_task_type(task_type: str | None) -> contextvars.Token:
    """Bind *task_type* as the ambient per-run broker task type."""
    return _current_broker_task_type.set(task_type)


def current_broker_task_type() -> str | None:
    """The ambient per-run broker task type for the current context, or ``None``."""
    return _current_broker_task_type.get()


async def aclose_broker_client() -> None:
    """Close this run's broker client if one was built (§26 M7). Idempotent and
    safe for injected test clients that have no ``aclose``."""
    import inspect

    client = _current_broker_client.get()
    if client is None:
        return
    _current_broker_client.set(None)
    aclose = getattr(client, "aclose", None)
    if callable(aclose):
        result = aclose()
        if inspect.isawaitable(result):
            await result


@dataclass(frozen=True)
class BrokerConfig:
    """Resolved broker repoint target. ``api_key`` is secret-class."""

    base_url: str
    api_key: str


def broker_enabled() -> bool:
    """Whether the LLM broker is on. Off/unset => Mode A default (disabled)."""
    return os.environ.get("VULTURE_LLM_BROKER", "").strip().lower() in _TRUTHY


def current_llm_path() -> str:
    """Report how THIS run's LLM phase reaches a provider (§14 P0 rollout gate):
    ``broker`` when the run routes through the broker (enabled + a run token +
    a configured URL), else ``env`` (agent's own provider key). The caller emits
    ``skills`` when the LLM phase does not run at all."""
    return "broker" if resolve_broker_config(current_broker_token()) is not None else "env"


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
    client = make_client(base_url=cfg.base_url, api_key=cfg.api_key)
    _current_broker_client.set(client)  # remember it for aclose_broker_client (M7)
    return make_provider(client)


def _default_client_factory(*, base_url: str, api_key: str) -> Any:
    """Real SDK client (lazy import so this module needs no openai at import).

    Carries the per-run X-Vulture-Task-Type via default_headers (§26 C1) so the
    broker can scope-check every completion. request_id is NOT sent — it must be
    unique per call, which per-client default_headers cannot express, so the
    broker generates it server-side (§5).
    """
    from openai import AsyncOpenAI

    headers: dict[str, str] = {}
    task_type = current_broker_task_type()
    if task_type:
        headers["X-Vulture-Task-Type"] = task_type
    return AsyncOpenAI(base_url=base_url, api_key=api_key, default_headers=headers or None)


def _default_provider_factory(client: Any) -> Any:
    """Real SDK ModelProvider in chat/completions mode (the broker's surface)."""
    from agents.models.openai_provider import OpenAIProvider

    return OpenAIProvider(openai_client=client, use_responses=False)
