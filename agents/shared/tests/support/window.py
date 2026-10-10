"""Feature 0074 P1 — the broker window fixture shared by the unit file
(``test_0074_effective_window``) and the e2e file (``test_0074_window_source``).

A synthetic model id with no exact-table entry: it matches the ``qwen3``
family, so the agent's own resolution is a FAMILY GUESS of 32768 tokens. 32768
is the discriminating value: above the 32000 gateway ceiling, so a clamp would
move it to 32000 and flip ``source_fraction`` from 0.5 to 0.35.

Today's per-batch source budget, written out so expectations are hand-checkable:
    min(max(2000, int(window * fraction * 3)), VULTURE_MAX_SOURCE_CHARS)
    fraction = 0.35 if window <= 32000 else 0.5
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

MODEL = "qwen3-fixture-coder-32b"
FAMILY_WINDOW = 32_768
GATEWAY = "https://gateway.invalid/v1"
# The five values the broker may send as ``context_window_source``.
SOURCES = ("env", "probe", "table", "family", "default")
UNCLAMPED_32768_BUDGET = 49_152   # 32768 * 0.5  * 3
CLAMPED_32000_BUDGET = 33_600     # 32000 * 0.35 * 3


@contextmanager
def no_ambient_window(monkeypatch: Any) -> Iterator[None]:
    """MODEL selected and no injected window, before and after the body.

    Env and ``_CUSTOM_BASE_URL`` isolation is the suite conftest's; this adds
    only what the window tests need on top of it.
    """
    from shared.llm.broker import set_context_window

    monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)
    set_context_window(None)
    try:
        yield
    finally:
        set_context_window(None)


def set_gateway(monkeypatch: Any, url: str) -> None:
    """The import-time custom-endpoint copies, in both modules that hold one."""
    from shared import audit_runner
    from shared.llm import provider

    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", url)
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", url)


_MARKERS = {
    "endpoint_kind": lambda mp: mp.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible"),
    "base_url": lambda mp: set_gateway(mp, GATEWAY),
    "none": lambda mp: None,
}


def set_marker(monkeypatch: Any, marker: str) -> None:
    """Native broker wiring passes the endpoint-kind marker; a custom
    ``OPENAI_BASE_URL`` is the other; compose wiring passes neither."""
    _MARKERS[marker](monkeypatch)
