"""Feature 0102: the plugin's Host rule is the backend's, vector for vector.

``docs/spec/plugin-v1/loopback_host_vectors.json`` is the one table of Host
values and their verdicts; the backend's Go rule is tested against the same
file, so the two implementations cannot drift apart.

The Host guard is an app-wide dependency, which only API routes run, so the app
serves no other kind of route (FastAPI's generated docs included). The run
token is compared with ``hmac.compare_digest`` over bytes; a plain ``!=`` would
give the same answers, so the comparison itself is recorded.
"""

import hmac
import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from src import wrapper

VECTORS = Path(__file__).resolve().parents[4] / "docs" / "spec" / "plugin-v1" / "loopback_host_vectors.json"
FRAMEWORK_DOC_PATHS = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")
FOREIGN_HOST = {"Host": "evil.example"}
TOKEN = "plugin-run-token"


def _disagreeing_hosts(vectors: list[dict]) -> list[str]:
    return [v["host"] for v in vectors if wrapper._is_loopback_host(v["host"]) != v["loopback"]]


def test_is_loopback_host_vectors():
    vectors = json.loads(VECTORS.read_text())["vectors"]
    assert vectors, "the vector fixture holds no vectors"
    wrong = _disagreeing_hosts(vectors)
    assert wrong == [], f"_is_loopback_host disagrees with the contract for {wrong}"


def test_every_route_runs_the_host_guard():
    unguarded = [route.path for route in wrapper.app.routes if not isinstance(route, APIRoute)]
    assert unguarded == [], f"routes outside the app-wide Host dependency: {unguarded}"


def test_framework_doc_paths_do_not_answer_a_foreign_host():
    # The client's requests arrive on 127.0.0.1, so the Host guard applies.
    client = TestClient(wrapper.app, base_url="http://127.0.0.1:28011")
    assert client.get("/health", headers=FOREIGN_HOST).status_code == 403, "the request must arrive on loopback"
    answers = {path: client.get(path, headers=FOREIGN_HOST).status_code for path in FRAMEWORK_DOC_PATHS}
    assert set(answers.values()) <= {403, 404}, answers


def test_run_token_is_compared_with_compare_digest_over_bytes(monkeypatch):
    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def recording(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(wrapper.hmac, "compare_digest", recording)
    monkeypatch.setenv(wrapper.AGENT_TOKEN_ENV, TOKEN)
    wrapper._verify_agent_token(TOKEN)
    with pytest.raises(HTTPException) as refused:
        wrapper._verify_agent_token("not-the-token")
    assert refused.value.status_code == 403
    assert calls == [(TOKEN.encode(), TOKEN.encode()), (b"not-the-token", TOKEN.encode())]
