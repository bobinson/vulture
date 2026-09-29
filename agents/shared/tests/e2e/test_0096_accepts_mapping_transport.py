"""E2E: the out-of-band ``accepts_mapping`` /run field (feature 0096 §2.1, H1).

The backend advertises the OWASP mapping capability as a TOP-LEVEL field of the
/run body, a sibling of ``run_id``/``config``/``prior_findings``, never inside
the user-controllable ``config`` (a pre-0096 backend forwards arbitrary user
config keys, so a capability read from config could be claimed by a user on a
backend that cannot honour it).

The transport contract pinned here:

- ``AuditRequest`` declares the field, default ``None`` (absent). It is
  declared untyped so the agent sees the value EXACTLY as sent — pydantic's
  lax int coercion would turn ``true``/``1.0``/``"1"`` into ``1`` and defeat
  the agent's strict-integer check.
- The transport passes it to a run handler as the ``accepts_mapping`` keyword
  ONLY when the handler declares that parameter; every other agent keeps its
  fixed four-argument call, whatever the body carries.
- An agent built on a model without the field ignores it (pydantic's default
  ``extra="ignore"``), so an older agent never 422s on the new key.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from shared.models.audit_request import AuditRequest
from shared.transport.event_emitter import AgUiEventEmitter
from shared.transport.sse_app import create_sse_app

_INFO = {"name": "t", "type": "t", "description": "t", "config_schema": {}, "skills": []}


def _seen_event(run_id: str, seen: dict) -> list[str]:
    emitter = AgUiEventEmitter(run_id)
    return [emitter.run_started(), emitter.text_message(json.dumps(seen)),
            emitter.run_finished()]


def _four_arg_handler(run_id, source_path, config, prior_findings=None):
    yield from _seen_event(run_id, {"config": config, "kwargs": None})


def _kw_handler(run_id, source_path, config, prior_findings=None, *, accepts_mapping=None):
    yield from _seen_event(run_id, {"config": config, "accepts_mapping": accepts_mapping,
                                    "type": type(accepts_mapping).__name__})


def _var_kw_handler(run_id, source_path, config, prior_findings=None, **kwargs):
    # A **kwargs handler did not declare the capability; it must not be told.
    yield from _seen_event(run_id, {"kwargs": sorted(kwargs)})


async def _post(handler, body: dict[str, Any]) -> tuple[int, dict]:
    app = create_sse_app(agent_name="t", agent_info=_INFO, run_handler=handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json={"run_id": "r", "source_path": "/x", **body})
    if resp.status_code != 200:
        return resp.status_code, {}
    for block in resp.text.split("\n\n"):
        if block.startswith("event: thinking"):
            return 200, json.loads(json.loads(block.split("data: ", 1)[1])["content"])
    raise AssertionError(f"no thinking event in {resp.text!r}")


def test_request_model_declares_the_field_absent_by_default():
    req = AuditRequest(run_id="r", source_path="/x")
    assert req.accepts_mapping is None


@pytest.mark.parametrize("value", [1, 0, 2, True, 1.0, "1", None, [1]])
def test_request_model_keeps_the_value_exactly_as_sent(value):
    req = AuditRequest.model_validate({"run_id": "r", "source_path": "/x",
                                       "accepts_mapping": value})
    assert req.accepts_mapping == value
    assert type(req.accepts_mapping) is type(value), "no lax coercion"


def test_a_model_without_the_field_ignores_it():
    """What an agent built before 0096 does with the new key: nothing."""

    class OldAuditRequest(BaseModel):
        run_id: str
        source_path: str
        config: dict = {}

    req = OldAuditRequest.model_validate({"run_id": "r", "source_path": "/x",
                                          "accepts_mapping": 1})
    assert not hasattr(req, "accepts_mapping")


@pytest.mark.anyio
async def test_declaring_handler_receives_the_top_level_value():
    status, seen = await _post(_kw_handler, {"config": {}, "accepts_mapping": 1})
    assert status == 200
    assert seen["accepts_mapping"] == 1 and seen["type"] == "int"


@pytest.mark.anyio
@pytest.mark.parametrize("value", [True, 1.0, "1"])
async def test_declaring_handler_receives_non_integers_uncoerced(value):
    status, seen = await _post(_kw_handler, {"config": {}, "accepts_mapping": value})
    assert status == 200, "a malformed capability must not reject the whole run"
    assert seen["accepts_mapping"] == value
    assert seen["type"] == type(value).__name__


@pytest.mark.anyio
async def test_declaring_handler_gets_none_when_absent():
    status, seen = await _post(_kw_handler, {"config": {"accepts_mapping": 1}})
    assert status == 200
    assert seen["accepts_mapping"] is None, "a config key is NOT the capability"
    assert seen["config"] == {"accepts_mapping": 1}


@pytest.mark.anyio
async def test_four_argument_handler_is_unaffected_by_the_field():
    status, seen = await _post(_four_arg_handler, {"config": {"a": 1}, "accepts_mapping": 1})
    assert status == 200
    assert seen["config"] == {"a": 1}


@pytest.mark.anyio
async def test_var_kwargs_handler_is_not_told():
    status, seen = await _post(_var_kw_handler, {"config": {}, "accepts_mapping": 1})
    assert status == 200
    assert seen["kwargs"] == []
