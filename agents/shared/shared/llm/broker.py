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


def apply_broker_client(
    token: str | None,
    *,
    client_factory: Callable[..., Any],
    set_client: Callable[[Any], None],
) -> BrokerConfig | None:
    """Repoint the SDK model client at the broker when enabled.

    Dual-mode:
      * OFF / fail-safe => returns ``None`` and never calls ``set_client``.
      * ON => builds a client via ``client_factory(base_url=..., api_key=...)``,
        installs it through ``set_client``, and returns the resolved config.

    ``client_factory`` and ``set_client`` are injected so the SDK-global
    mutation is the only external boundary. Model selection is untouched.
    """
    return _install_broker_client(
        resolve_broker_config(token), client_factory=client_factory, set_client=set_client,
    )


def _install_broker_client(
    cfg: BrokerConfig | None,
    *,
    client_factory: Callable[..., Any],
    set_client: Callable[[Any], None],
) -> BrokerConfig | None:
    """Install a broker client for an already-resolved *cfg* (or no-op on None).

    Split out so the context wrapper can resolve the config ONCE and pass it
    here, instead of re-resolving env inside ``apply_broker_client``.
    """
    if cfg is None:
        return None
    set_client(client_factory(base_url=cfg.base_url, api_key=cfg.api_key))
    return cfg


def apply_broker_from_context() -> BrokerConfig | None:
    """Repoint the live OpenAI-Agents-SDK client at the broker for this run.

    Convenience wrapper over :func:`apply_broker_client` that resolves the
    per-run token from the ambient context (bound by the transport) and wires
    the real SDK boundary: an ``openai.AsyncOpenAI`` client installed via
    ``agents.set_default_openai_client``. Fail-safe/dual-mode — returns
    ``None`` and touches nothing when the broker is off, unconfigured, or the
    run has no token (Mode A behavior unchanged). SDK/openai imports are lazy
    so this module stays importable without them.
    """
    cfg = resolve_broker_config(current_broker_token())
    if cfg is None:
        return None  # fail-safe: don't import the SDK when no repoint applies

    def _factory(*, base_url: str, api_key: str) -> Any:
        from openai import AsyncOpenAI

        return AsyncOpenAI(base_url=base_url, api_key=api_key)

    def _set_client(client: Any) -> None:
        from agents import set_default_openai_client

        # use_for_tracing=False: the broker token is a per-run credential, not
        # a tracing-export key; never repoint the tracing exporter at it.
        set_default_openai_client(client, use_for_tracing=False)

    return _install_broker_client(cfg, client_factory=_factory, set_client=_set_client)
