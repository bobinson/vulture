"""E2E tests for the Chaos Engineering audit agent."""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def sample_source(tmp_path: Path) -> Path:
    """Create sample source code for chaos audit."""
    (tmp_path / "main.py").write_text(
        "import requests\n\n"
        "def call_service(url: str) -> str:\n"
        "    response = requests.get(url)\n"
        "    return response.text\n"
    )
    (tmp_path / "handler.go").write_text(
        'package main\n\nimport "net/http"\n\n'
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '    resp, err := http.Get("http://service:8080/api")\n'
        "    if err != nil {\n"
        '        http.Error(w, "error", 500)\n'
        "        return\n"
        "    }\n"
        "    defer resp.Body.Close()\n"
        "}\n"
    )
    return tmp_path


@pytest.fixture
def chaos_app():
    """Create the chaos agent FastAPI app."""
    from chaos_agent.main import app
    return app


class TestChaosHealth:
    """Tests for chaos agent health endpoint."""

    @pytest.mark.anyio
    async def test_health_returns_healthy(self, chaos_app) -> None:
        """GET /health returns healthy status."""
        async with AsyncClient(
            transport=ASGITransport(app=chaos_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["agent"] == "chaos_engineering"


class TestChaosInfo:
    """Tests for chaos agent info endpoint."""

    @pytest.mark.anyio
    async def test_info_returns_config_schema(self, chaos_app) -> None:
        """GET /info returns agent info with config_schema."""
        async with AsyncClient(
            transport=ASGITransport(app=chaos_app), base_url="http://test"
        ) as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Chaos Engineering Auditor"
        assert body["type"] == "chaos"
        assert "config_schema" in body
        schema = body["config_schema"]
        assert "properties" in schema
        assert "categories" in schema["properties"]
        assert "skills" in body
        assert len(body["skills"]) >= 5


class TestChaosRun:
    """Tests for chaos agent run endpoint."""

    @pytest.mark.anyio
    async def test_run_returns_sse_stream(
        self, chaos_app, sample_source: Path
    ) -> None:
        """POST /run returns SSE event stream with agent_start and agent_end."""
        async with AsyncClient(
            transport=ASGITransport(app=chaos_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-chaos-1",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body

    @pytest.mark.anyio
    async def test_run_emits_findings(
        self, chaos_app, sample_source: Path
    ) -> None:
        """POST /run emits finding events for detected issues."""
        async with AsyncClient(
            transport=ASGITransport(app=chaos_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-chaos-2",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        body = resp.text
        assert "event: finding" in body
        assert "event: result" in body

    @pytest.mark.anyio
    async def test_run_with_category_filter(
        self, chaos_app, sample_source: Path
    ) -> None:
        """POST /run respects category filter in config."""
        async with AsyncClient(
            transport=ASGITransport(app=chaos_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-chaos-3",
                    "source_path": str(sample_source),
                    "config": {"categories": ["retry"]},
                },
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body


class TestChaosSkills:
    """Tests for individual chaos engineering skills."""

    def test_check_retry_patterns(self, sample_source: Path) -> None:
        """check_retry_patterns finds missing retry logic."""
        from chaos_agent.skills.retry_analysis import check_retry_patterns
        result = check_retry_patterns(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_check_circuit_breaker(self, sample_source: Path) -> None:
        """check_circuit_breaker finds missing circuit breakers."""
        from chaos_agent.skills.circuit_breaker import check_circuit_breaker
        result = check_circuit_breaker(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_check_timeout_handling(self, sample_source: Path) -> None:
        """check_timeout_handling finds missing timeouts."""
        from chaos_agent.skills.timeout_analysis import check_timeout_handling
        result = check_timeout_handling(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_check_fallback_patterns(self, sample_source: Path) -> None:
        """check_fallback_patterns finds missing fallbacks."""
        from chaos_agent.skills.fallback_analysis import check_fallback_patterns
        result = check_fallback_patterns(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_assess_blast_radius(self, sample_source: Path) -> None:
        """assess_blast_radius assesses failure blast radius."""
        from chaos_agent.skills.blast_radius import assess_blast_radius
        result = assess_blast_radius(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)
