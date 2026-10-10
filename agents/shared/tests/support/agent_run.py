"""Feature 0074 — shared seams for driving the real audit runner.

* ``result_payload`` / ``result_findings`` / ``llm_rows`` read the ``result``
  event that ``run_combined_audit`` yields (the payload Go decodes as
  ``ScanResult``).
* ``agent_app`` / ``post_run`` are "the real SSE app over the real runner": a
  field pydantic does not declare is dropped at the door without a word, so
  only a real ``POST /run`` shows whether a request field reaches the runner.

Every helper is a straight line: no branch the tests would have to trust.
"""

from __future__ import annotations

import json
from typing import Any

# The LLM phase needs a non-empty tool list to build its agent; the fake
# runner never calls it.
DUMMY_TOOLS = ["__dummy_tool__"]


def _data(event: str) -> dict[str, Any]:
    line = next(ln for ln in event.split("\n") if ln.startswith("data:"))
    return json.loads(line[5:])


def result_payload(events: list[str]) -> dict[str, Any]:
    """The one ``result`` event's payload."""
    results = [e for e in events if e.startswith("event: result\n")]
    assert len(results) == 1, f"expected exactly one result event, got {len(results)}"
    return _data(results[0])


def result_findings(events: list[str]) -> list[dict[str, Any]]:
    """The findings the ``result`` snapshot carries."""
    return result_payload(events)["findings"]


def llm_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """The LLM-family rows of a result payload, by THE rule
    (``shared.provenance.is_llm_provenance``, pinned to Go's
    ``isLLMProvenance`` by ``llm_provenance_family_0074.json``)."""
    from shared.provenance import is_llm_provenance

    return [f for f in payload["findings"] if is_llm_provenance(f.get("provenance"))]


def noop_skill(_source_path: str) -> dict[str, Any]:
    """A real skill that finds nothing."""
    return {"findings": []}


def agent_app(**run_kwargs: Any) -> Any:
    """The real SSE app over the real runner, wired the way an agent wires it.

    ``run_kwargs`` go to ``run_combined_audit`` beside the request's own
    ``run_id`` / ``source_path`` and a single no-op skill.
    """
    from shared.audit_runner import run_combined_audit
    from shared.transport.sse_app import create_sse_app

    def run_handler(run_id, source_path, config, prior_findings=None):
        yield from run_combined_audit(
            run_id=run_id, source_path=source_path, categories=["noop"],
            skill_map={"noop": noop_skill}, **run_kwargs,
        )

    return create_sse_app(
        agent_name="seam",
        agent_info={
            "name": "Seam Agent", "type": "seam", "description": "0074 seam",
            "config_schema": {"type": "object", "properties": {}}, "skills": ["noop"],
        },
        run_handler=run_handler,
    )


async def post_run(app: Any, body: dict[str, Any]) -> str:
    """``POST /run`` to ``app`` and return the raw SSE text."""
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://a") as client:
        resp = await client.post("/run", json=body)
    assert resp.status_code == 200, resp.text
    return resp.text
