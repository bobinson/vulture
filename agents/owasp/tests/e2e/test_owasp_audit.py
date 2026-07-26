"""E2E tests for the OWASP mapper agent (feature 0063).

The OWASP agent maps CWE findings onto OWASP Top 10 categories. The backend
delivers those CWE findings through the `prior_findings` payload field
(the deferred-phase transport); these tests exercise that exact path via the
real FastAPI /run SSE endpoint.
"""

import json

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def owasp_app():
    from owasp_agent.main import app

    return app


def _cwe_priors():
    return [
        {"category": "CWE-89", "title": "SQL injection", "severity": "critical",
         "file_path": "app.py", "line_start": 3, "line_end": 3,
         "description": "string interpolation in query", "check_id": "cwe.injection.sql"},
        {"category": "CWE-918", "title": "SSRF", "severity": "high",
         "file_path": "net.py", "line_start": 7, "line_end": 7,
         "description": "user-controlled url", "check_id": "cwe.injection.ssrf"},
    ]


class TestOwaspHealth:
    @pytest.mark.anyio
    async def test_health_returns_healthy(self, owasp_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=owasp_app), base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestOwaspInfo:
    @pytest.mark.anyio
    async def test_info_declares_mapper_and_prerequisite(self, owasp_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=owasp_app), base_url="http://test") as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["type"] == "owasp"
        assert body["skills"] == []  # no detection skills
        assert body["requires"] == ["cwe"]  # prerequisite advertised
        assert "config_schema" in body


class TestOwaspMapping:
    @pytest.mark.anyio
    async def test_run_maps_priors_and_emits_coverage(self, owasp_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=owasp_app), base_url="http://test") as client:
            resp = await client.post("/run", json={
                "run_id": "e2e-owasp-1", "source_path": "/tmp/x",
                "config": {"edition": "2021"}, "prior_findings": _cwe_priors(),
            })
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = resp.text
        assert "event: finding" in body and "event: result" in body and "event: agent_end" in body

        result_block = next(b for b in body.split("\n\n") if "event: result" in b)
        data = json.loads(result_block.split("data: ", 1)[1])
        assert len(data["owasp_coverage"]["categories"]) == 10
        assert data["owasp_coverage"]["cwe_stage_status"] == "completed"

    @pytest.mark.anyio
    async def test_run_without_prior_findings_still_completes(self, owasp_app) -> None:
        async with AsyncClient(transport=ASGITransport(app=owasp_app), base_url="http://test") as client:
            resp = await client.post("/run", json={
                "run_id": "e2e-owasp-2", "source_path": "/tmp/x",
                "config": {"edition": "2021"}, "prior_findings": [],
            })
        assert resp.status_code == 200
        assert "event: agent_end" in resp.text
        assert "CWE" in resp.text  # prerequisite notice surfaced
