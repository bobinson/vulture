"""Feature 0074 P1 (agent side) — the broker window's SOURCE crosses the
``/run`` boundary and is published, while sizing stays exactly as it is today.

Business contract (plan §5.1 rev 3, owner decision O5):

* The backend injects ``context_window`` and, new in 0074,
  ``context_window_source`` (``env`` / ``probe`` / ``table`` / ``family`` /
  ``default``) at the top level of the ``/run`` body. The source tells a reader
  HOW the broker obtained the number; it never changes WHO decided it. The
  agent's own provenance label for an injected window stays ``broker``.
* Every run publishes the window it is using, once, in a log line
  ``llm_window resolved=.. effective=.. provenance=.. source=.. model=..`` and
  as an ``llm_window`` object on the ``agent_start`` (run_started) event, so the
  backend stream can show which source won (AC1, AC7).
* A broker-injected window is never clamped, whatever its source and whether
  or not the custom-endpoint marker is set (AC2b, AC3): the per-batch source
  budget equals the budget computed for the injected window.
* P1 never lowers the per-batch source budget for identical inputs (AC41), and
  a request that carries no ``context_window_source`` behaves exactly as today.
* Mode A (no injected window) is unaffected: a family guess behind a custom
  endpoint is clamped exactly as before 0074 (AC2).
* The agent never probes an endpoint itself (AC8).

These tests drive the real ASGI app with a real request body, because a field
pydantic does not declare is dropped at the door without a word (the 0091
lesson): only the HTTP seam shows whether the source can reach the runner.
Network-free: the LLM is the deterministic FakeLLMProvider, the L5 judge is
patched, and any socket connect attempted during a run is recorded.

All fixtures are synthetic.
"""

from __future__ import annotations

import json
import logging
import re
import socket
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from shared import audit_runner
from shared.llm import provider
from shared.llm.broker import set_context_window
from shared.transport.sse_app import create_sse_app
from tests._fake_llm import FakeLLMProvider, install_fake_runner, patch_l5_judge

# A synthetic model id. No exact-table entry; it matches the `qwen3` family, so
# the agent's own resolution is a FAMILY GUESS of 32768 tokens. 32768 is the
# discriminating value: above the 32000 gateway ceiling, so a clamp would move
# it to 32000 and flip `source_fraction` from 0.5 to 0.35.
MODEL = "qwen3-fixture-coder-32b"
FAMILY_WINDOW = 32_768

# Today's formula, written out so the expected budgets are hand-checkable:
#   min(max(2000, int(window * fraction * 3)), VULTURE_MAX_SOURCE_CHARS)
#   fraction = 0.35 if window <= 32000 else 0.5
UNCLAMPED_32768_BUDGET = 49_152   # 32768 * 0.5  * 3
CLAMPED_32000_BUDGET = 33_600     # 32000 * 0.35 * 3

# What a broker run with a Go family guess must publish (AC1 + AC7): the
# provenance says WHO decided (the broker), the source says HOW.
BROKER_FAMILY_FACTS = {
    "resolved": FAMILY_WINDOW, "effective": FAMILY_WINDOW,
    "provenance": "broker", "source": "family",
}

_DUMMY_TOOLS = ["__dummy_tool__"]
_LLM_WINDOW_RE = re.compile(
    r"llm_window resolved=(?P<resolved>\d+) effective=(?P<effective>\d+) "
    r"provenance=(?P<provenance>\S+) source=(?P<source>\S*) model=(?P<model>\S*)"
)


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> Any:
    """No operator override, no endpoint marker, no ambient window."""
    for name in (
        "VULTURE_LLM_CTX_SIZE", "VULTURE_LLM_ENDPOINT_KIND", "VULTURE_LLM_BROKER",
        "VULTURE_MAX_SOURCE_CHARS", "VULTURE_LLM_MAX_BODY_BYTES",
        "VULTURE_LLM_BUDGET_USD",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)
    # The 0079 reachability preflight is an existing, separate concern (a
    # liveness check, not a window probe); it is turned off so AC8 observes
    # only what 0074 could add.
    monkeypatch.setenv("VULTURE_LLM_PREFLIGHT", "off")
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    set_context_window(None)
    yield
    set_context_window(None)


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A small synthetic tree so the LLM phase has a batch to size."""
    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "def handler(request):\n"
        "    value = request.args.get('q')\n"
        "    return value\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture()
def budget_spy(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record every per-batch source budget the runner computes.

    A pass-through wrapper: it returns the real value, so it observes the
    budget without changing it.
    """
    seen: list[int] = []
    real = audit_runner._get_max_source_chars

    def _spy(model: str | None = None) -> int:
        value = real(model)
        seen.append(value)
        return value

    monkeypatch.setattr(audit_runner, "_get_max_source_chars", _spy)
    return seen


@pytest.fixture()
def llm_on(monkeypatch: pytest.MonkeyPatch) -> FakeLLMProvider:
    """The deterministic LLM tier: it finds nothing, offline."""
    fake = install_fake_runner(monkeypatch, FakeLLMProvider(scripted=[]))
    patch_l5_judge(monkeypatch)
    return fake


@pytest.fixture()
def connects(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Every outbound socket connect attempted during the run (AC8)."""
    attempts: list[Any] = []

    def _refuse(self: socket.socket, address: Any) -> None:
        attempts.append(address)
        raise ConnectionRefusedError(f"0074 e2e: no network ({address!r})")

    monkeypatch.setattr(socket.socket, "connect", _refuse)
    return attempts


def _noop_skill(_source_path: str) -> dict:
    return {"findings": []}


def _agent_app() -> Any:
    """The real SSE app over the real runner, LLM phase on."""

    def run_handler(run_id, source_path, config, prior_findings=None):
        yield from audit_runner.run_combined_audit(
            run_id=run_id,
            source_path=source_path,
            categories=["noop"],
            skill_map={"noop": _noop_skill},
            skill_tools=_DUMMY_TOOLS,
            instructions="audit",
            model=MODEL,
            use_llm=True,
        )

    return create_sse_app(
        agent_name="window",
        agent_info={
            "name": "Window Agent", "type": "window", "description": "0074 seam",
            "config_schema": {"type": "object", "properties": {}}, "skills": ["noop"],
        },
        run_handler=run_handler,
    )


def _field(chunk: str, prefix: str) -> str:
    """The value of the first ``prefix`` line in one SSE chunk ("" if none)."""
    return next((ln[len(prefix):].strip() for ln in chunk.split("\n") if ln.startswith(prefix)), "")


def _events(text: str) -> dict[str, dict]:
    """First payload of each SSE event name in the stream."""
    pairs = [(_field(c, "event:"), _field(c, "data:")) for c in text.split("\n\n")]
    # Reversed, so the FIRST occurrence of a name is the one kept.
    return {name: json.loads(data) for name, data in reversed(pairs) if data}


def _facts(window: Any) -> dict[str, Any]:
    """The four published facts, from a log-line match or the event object."""
    get = window.group if isinstance(window, re.Match) else window.get
    return {
        "resolved": _as_int(get("resolved")), "effective": _as_int(get("effective")),
        "provenance": get("provenance"), "source": get("source"),
    }


def _as_int(value: Any) -> Any:
    return int(value) if isinstance(value, str) and value.isdigit() else value


async def _post_run(tree: Path, **extra: Any) -> dict[str, dict]:
    body = {"run_id": "w-0074", "source_path": str(tree), "config": {}, **extra}
    async with AsyncClient(transport=ASGITransport(app=_agent_app()), base_url="http://a") as c:
        resp = await c.post("/run", json=body)
    assert resp.status_code == 200, resp.text
    events = _events(resp.text)
    assert "result" in events, f"run did not finish:\n{resp.text[:2000]}"
    return events


def _window_lines(caplog: pytest.LogCaptureFixture) -> list[re.Match]:
    return [m for r in caplog.records if (m := _LLM_WINDOW_RE.search(r.getMessage()))]


def _the_window_line(caplog: pytest.LogCaptureFixture) -> re.Match:
    lines = _window_lines(caplog)
    assert len(lines) == 1, (
        "AC7: every run logs exactly ONE `llm_window resolved=.. effective=.. "
        f"provenance=.. source=.. model=..` line; saw {len(lines)}"
    )
    return lines[0]


def _run_started_window(events: dict[str, dict]) -> dict:
    started = events.get("agent_start", {})
    window = started.get("llm_window")
    assert isinstance(window, dict), (
        "AC7: run_started (agent_start) must carry an `llm_window` object; "
        f"payload was {started!r}"
    )
    return window


def _clamp_logged(caplog: pytest.LogCaptureFixture) -> bool:
    return any("llm_body_window_clamped" in r.getMessage() for r in caplog.records)


def _without_source(facts: dict[str, Any]) -> dict[str, Any]:
    """Mode A's source is the agent's own; only the three sizing facts are pinned."""
    return {k: v for k, v in facts.items() if k != "source"}


def _set_marker(monkeypatch: pytest.MonkeyPatch, marker: str) -> None:
    """Native broker wiring passes the endpoint-kind marker; compose does not."""
    if marker == "endpoint_kind":
        monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
    elif marker == "base_url":
        monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "https://gateway.invalid/v1")
        monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "https://gateway.invalid/v1")


# --------------------------------------------------------------------------- #
# AC1 / AC7 — the broker's source is published, unchanged, once per run
# --------------------------------------------------------------------------- #


class TestBrokerSourceIsPublished:

    async def test_family_source_is_logged_once(
        self, tree, llm_on, budget_spy, caplog, monkeypatch,
    ) -> None:
        """AC1 + AC7: a Go family guess arrives labelled `family` in the log line.

        The provenance stays `broker` (who decided); the source says how.
        """
        _set_marker(monkeypatch, "endpoint_kind")
        with caplog.at_level(logging.INFO):
            await _post_run(tree, context_window=FAMILY_WINDOW, context_window_source="family")
        line = _the_window_line(caplog)
        assert (_facts(line), MODEL in line["model"]) == (BROKER_FAMILY_FACTS, True)

    async def test_run_started_carries_llm_window(
        self, tree, llm_on, budget_spy, monkeypatch,
    ) -> None:
        """AC1 + AC7: the same facts ride on run_started for the backend stream."""
        _set_marker(monkeypatch, "endpoint_kind")
        events = await _post_run(
            tree, context_window=FAMILY_WINDOW, context_window_source="family",
        )
        assert _facts(_run_started_window(events)) == BROKER_FAMILY_FACTS

    @pytest.mark.parametrize("source", ["env", "probe", "table", "family", "default"])
    async def test_every_source_value_is_passed_through_unchanged(
        self, source, tree, llm_on, budget_spy, monkeypatch,
    ) -> None:
        """AC1: each of the five broker sources reaches run_started verbatim."""
        events = await _post_run(
            tree, context_window=FAMILY_WINDOW, context_window_source=source,
        )
        assert _run_started_window(events).get("source") == source


# --------------------------------------------------------------------------- #
# AC2b / AC3 / AC41 — a broker window is never clamped; the budget never falls
# --------------------------------------------------------------------------- #


class TestBrokerWindowIsNeverClamped:

    @pytest.mark.parametrize("marker", ["endpoint_kind", "base_url", "none"])
    @pytest.mark.parametrize("source", ["family", "default", "env", "table", "probe"])
    async def test_budget_equals_the_injected_windows_budget(
        self, source, marker, tree, llm_on, budget_spy, caplog, monkeypatch,
    ) -> None:
        """AC2b + AC3 + AC41: native (marker) and compose (no marker) wiring alike.

        The per-batch source budget is the one computed for the injected
        window, not the 32000-token gateway ceiling, and the run states which
        source it came from.
        """
        _set_marker(monkeypatch, marker)
        with caplog.at_level(logging.INFO):
            events = await _post_run(
                tree, context_window=FAMILY_WINDOW, context_window_source=source,
            )
        assert (set(budget_spy), _clamp_logged(caplog)) == ({UNCLAMPED_32768_BUDGET}, False)
        assert _run_started_window(events).get("effective") == FAMILY_WINDOW


class TestAbsentSourceBehavesAsToday:

    async def test_no_source_same_budget_as_today(
        self, tree, llm_on, budget_spy, caplog, monkeypatch,
    ) -> None:
        """AC3 + AC41: an older backend sends no source; sizing is exactly today's."""
        _set_marker(monkeypatch, "endpoint_kind")
        with caplog.at_level(logging.INFO):
            events = await _post_run(tree, context_window=FAMILY_WINDOW)
        assert (set(budget_spy), _clamp_logged(caplog)) == ({UNCLAMPED_32768_BUDGET}, False)
        window = _run_started_window(events)
        # An absent source is published as absent (None), never invented.
        assert (window.get("provenance"), window.get("source")) == ("broker", None)

    async def test_large_broker_window_budget_not_lowered(
        self, tree, llm_on, budget_spy, monkeypatch,
    ) -> None:
        """AC41: 131072 from a family guess still yields today's 196,608 chars."""
        _set_marker(monkeypatch, "endpoint_kind")
        await _post_run(tree, context_window=131_072, context_window_source="family")
        assert set(budget_spy) == {196_608}


# --------------------------------------------------------------------------- #
# AC2 / AC7 — Mode A: the agent's own guess is clamped exactly as before
# --------------------------------------------------------------------------- #


class TestModeAUnchanged:

    async def test_family_guess_behind_gateway_is_clamped_and_published(
        self, tree, llm_on, budget_spy, caplog, monkeypatch,
    ) -> None:
        """AC2 + AC7: resolved 32768 (family), effective 32000, budget 33,600."""
        _set_marker(monkeypatch, "base_url")
        with caplog.at_level(logging.INFO):
            events = await _post_run(tree)
        assert set(budget_spy) == {CLAMPED_32000_BUDGET}
        expected = {"resolved": FAMILY_WINDOW, "effective": 32_000, "provenance": "family"}
        published = (_facts(_the_window_line(caplog)), _facts(_run_started_window(events)))
        assert tuple(map(_without_source, published)) == (expected, expected)


# --------------------------------------------------------------------------- #
# AC8 — no agent-side endpoint probe
# --------------------------------------------------------------------------- #


class TestNoAgentSideProbe:

    async def test_broker_run_opens_no_connection(
        self, tree, llm_on, budget_spy, connects, monkeypatch,
    ) -> None:
        """AC8 (regression pin): publishing the source never makes the agent
        reach for the gateway. The window is the broker's to measure."""
        _set_marker(monkeypatch, "endpoint_kind")
        await _post_run(tree, context_window=FAMILY_WINDOW, context_window_source="family")
        assert connects == []

    async def test_mode_a_gateway_run_opens_no_connection(
        self, tree, llm_on, budget_spy, connects, monkeypatch,
    ) -> None:
        """AC8 (regression pin): Mode A has no probe either (§5.1(h))."""
        _set_marker(monkeypatch, "base_url")
        await _post_run(tree)
        assert connects == []
