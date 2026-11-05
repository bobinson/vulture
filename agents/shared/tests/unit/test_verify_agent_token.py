"""Feature 0102: the in-tree agent's ``/run`` token check answers 403, never 500.

With ``VULTURE_AGENT_TOKEN`` set, a request without the matching
``X-Vulture-Agent-Token`` is refused with 403, whether the header is missing,
wrong or not ASCII. The comparison is constant-time over bytes; a plain
``hmac.compare_digest`` over ``str`` raises ``TypeError`` (so 500) for a
missing or non-ASCII header, which is what these cases pin.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from shared.transport import sse_app

TOKEN = "agent-run-token-0102"
TOKEN_REFUSED = {"detail": "invalid or missing agent token"}
RUN_BODY = {"run_id": "run-token-check", "source_path": "/src", "config": {}}


def _empty_run(run_id, source_path, config, prior_findings):
    yield 'event: agent_end\ndata: {"status": "completed"}\n\n'


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(sse_app, "_AGENT_TOKEN", TOKEN)
    app = sse_app.create_sse_app("token-check", {}, _empty_run)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="missing"),
        pytest.param({"X-Vulture-Agent-Token": "not-the-token"}, id="wrong"),
        pytest.param({"X-Vulture-Agent-Token": "tökén".encode()}, id="non-ascii"),
    ],
)
def test_run_refuses_a_bad_token_with_403(client, headers):
    resp = client.post("/run", json=RUN_BODY, headers=headers)
    assert resp.status_code == 403
    assert resp.json() == TOKEN_REFUSED


def test_run_accepts_the_right_token(client):
    resp = client.post("/run", json=RUN_BODY, headers={"X-Vulture-Agent-Token": TOKEN})
    assert resp.status_code == 200
    assert "agent_end" in resp.text
