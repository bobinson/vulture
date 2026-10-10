"""0074 verification item 15: the generate tool loop gives its tool outputs the
byte budget the source gets (``VULTURE_LLM_MAX_BODY_BYTES``), so a request stays
within source + one budget, far below the broker's 1 MiB request cap.

The first request is capped where the source is assembled, but each tool turn
appends its output (a whole file read) and the conversation grew past the
broker's 1 MiB request cap: the broker answered 413 and the size retry halved
an innocent 5.7 KB source. A ``call_model_input_filter`` now bounds every call:
an oversized single output is cut where it stands, then the OLDEST outputs are
replaced in place by an elision marker (an item is never removed: that would
break call/output pairing), never the source turn or the instructions. The
filter is installed on every generate run, broker or not. Synthetic data.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from shared import audit_runner
from shared.llm import provider
from shared.llm.request_cap import bounded_model_input

_CAP = 131_072


def _data(*outputs: str, source: str = "S" * 40_000):
    from agents.run_config import CallModelData, ModelInputData

    items: list[dict] = [{"role": "user", "content": source}]
    for i, out in enumerate(outputs):
        items.append({"type": "function_call", "call_id": f"c{i}", "name": "read_file",
                      "arguments": json.dumps({"path": f"f{i}.py"})})
        items.append({"type": "function_call_output", "call_id": f"c{i}", "output": out})
    agent = SimpleNamespace(tools=[])
    return CallModelData(model_data=ModelInputData(input=items, instructions="audit it"),  # type: ignore[arg-type]
                         agent=agent, context=None)


def _tool_bytes(model_data) -> int:
    return sum(len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
               for item in model_data.input if item.get("type") == "function_call_output")


@pytest.fixture(autouse=True)
def _cap(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_MAX_BODY_BYTES", raising=False)


def test_growing_conversation_stays_under_the_cap() -> None:
    out = bounded_model_input(_data(*(c * 30_000 for c in "ABCDEF")))
    assert _tool_bytes(out) <= _CAP
    assert out.input[0]["content"] == "S" * 40_000, "the source turn is never touched"
    assert len(out.input) == 13, "items are replaced in place, never removed"
    outputs = [item["output"] for item in out.input if item.get("type") == "function_call_output"]
    assert "elided" in outputs[0] and outputs[-1] == "F" * 30_000, "the oldest goes first"


def test_one_oversized_output_is_cut_where_it_stands() -> None:
    out = bounded_model_input(_data("D" * 400_000))
    assert _tool_bytes(out) <= _CAP // 4
    newest = out.input[-1]["output"]
    assert newest.startswith("D" * 1000) and "narrower" in newest


def test_a_request_under_the_cap_is_unchanged() -> None:
    data = _data("small output")
    assert bounded_model_input(data) is data.model_data


def test_disabled_cap_is_a_no_op(monkeypatch) -> None:
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "0")
    data = _data("E" * 400_000)
    assert bounded_model_input(data) is data.model_data


class _Spy:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, agent, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(final_output="[]", context_wrapper=None, raw_responses=[])


def test_the_filter_is_installed_without_a_broker(monkeypatch, tmp_path) -> None:
    import agents

    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    spy = _Spy()
    monkeypatch.setattr(agents, "Runner", spy)
    asyncio.run(audit_runner._collect_llm_findings_async(
        run_id="v15", source_path=str(tmp_path), categories=["injection"], skill_tools=[],
        instructions="audit it", domain_label="categories"))
    assert spy.calls, "the model was called"
    run_config = spy.calls[0].get("run_config")
    assert run_config is not None and run_config.call_model_input_filter is bounded_model_input


def test_structured_outputs_are_counted_and_elided() -> None:
    """A tool returning content parts gives a list ``output``; it counts toward
    the budget and is elided in place like a string output."""
    from agents.run_config import CallModelData, ModelInputData

    parts = [{"type": "input_text", "text": "P" * 60_000}]
    items: list[dict] = [{"role": "user", "content": "S" * 1000}]
    for i in range(4):
        items.append({"type": "function_call", "call_id": f"c{i}", "name": "t", "arguments": "{}"})
        items.append({"type": "function_call_output", "call_id": f"c{i}", "output": parts})
    data = CallModelData(model_data=ModelInputData(input=items, instructions="x"),  # type: ignore[arg-type]
                         agent=SimpleNamespace(tools=[]), context=None)
    out = bounded_model_input(data)
    assert _tool_bytes(out) <= _CAP and len(out.input) == len(items)
    assert isinstance(out.input[2]["output"], str) and "elided" in out.input[2]["output"]
