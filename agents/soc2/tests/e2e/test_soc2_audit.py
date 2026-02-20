"""E2E tests for the SOC2 audit agent."""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def sample_source(tmp_path: Path) -> Path:
    """Create sample source code for SOC2 audit."""
    (tmp_path / "app.py").write_text(
        "import logging\n\n"
        "logger = logging.getLogger(__name__)\n\n"
        "def process_data(data: dict) -> dict:\n"
        "    return data\n"
    )
    (tmp_path / "db.py").write_text(
        "import sqlite3\n\n"
        "def store_user(name: str, email: str) -> None:\n"
        '    conn = sqlite3.connect("app.db")\n'
        '    conn.execute("INSERT INTO users VALUES (?, ?)", (name, email))\n'
        "    conn.commit()\n"
    )
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/bash\n"
        "git pull origin main\n"
        "pip install -r requirements.txt\n"
        "python manage.py migrate\n"
        "systemctl restart app\n"
    )
    return tmp_path


@pytest.fixture
def soc2_app():
    """Create the SOC2 agent FastAPI app."""
    from soc2_agent.main import app
    return app


class TestSoc2Health:
    """Tests for SOC2 agent health endpoint."""

    @pytest.mark.anyio
    async def test_health_returns_healthy(self, soc2_app) -> None:
        """GET /health returns healthy status."""
        async with AsyncClient(
            transport=ASGITransport(app=soc2_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["agent"] == "soc2"


class TestSoc2Info:
    """Tests for SOC2 agent info endpoint."""

    @pytest.mark.anyio
    async def test_info_returns_config_schema(self, soc2_app) -> None:
        """GET /info returns agent info with clause config."""
        async with AsyncClient(
            transport=ASGITransport(app=soc2_app), base_url="http://test"
        ) as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "SOC2 Compliance Auditor"
        assert body["type"] == "soc2"
        assert "config_schema" in body
        schema = body["config_schema"]
        assert "properties" in schema
        assert "clauses" in schema["properties"]
        assert "skills" in body
        assert len(body["skills"]) >= 5


class TestSoc2Run:
    """Tests for SOC2 agent run endpoint."""

    @pytest.mark.anyio
    async def test_run_returns_sse_stream(self, soc2_app, sample_source: Path) -> None:
        """POST /run returns SSE event stream."""
        async with AsyncClient(
            transport=ASGITransport(app=soc2_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-soc2-1",
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
    async def test_run_emits_findings(self, soc2_app, sample_source: Path) -> None:
        """POST /run emits finding events for SOC2 issues."""
        async with AsyncClient(
            transport=ASGITransport(app=soc2_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-soc2-2",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        body = resp.text
        assert "event: result" in body

    @pytest.mark.anyio
    async def test_run_with_clause_filter(self, soc2_app, sample_source: Path) -> None:
        """POST /run respects clause filter in config."""
        async with AsyncClient(
            transport=ASGITransport(app=soc2_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-soc2-3",
                    "source_path": str(sample_source),
                    "config": {"clauses": ["CC6"]},
                },
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body


class TestSoc2Skills:
    """Tests for individual SOC2 skills."""

    def test_access_logging(self, sample_source: Path) -> None:
        """access_logging checks for audit logging."""
        from soc2_agent.skills.access_logging import check_access_logging
        result = check_access_logging(str(sample_source))
        assert "findings" in result

    def test_encryption_check(self, sample_source: Path) -> None:
        """encryption_check checks for encryption at rest/transit."""
        from soc2_agent.skills.encryption_check import check_encryption
        result = check_encryption(str(sample_source))
        assert "findings" in result

    def test_change_management(self, sample_source: Path) -> None:
        """change_management checks deployment practices."""
        from soc2_agent.skills.change_management import check_change_management
        result = check_change_management(str(sample_source))
        assert "findings" in result

    def test_monitoring_check(self, sample_source: Path) -> None:
        """monitoring_check checks for monitoring/alerting."""
        from soc2_agent.skills.monitoring_check import check_monitoring
        result = check_monitoring(str(sample_source))
        assert "findings" in result

    def test_data_retention(self, sample_source: Path) -> None:
        """data_retention checks for data lifecycle management."""
        from soc2_agent.skills.data_retention import check_data_retention
        result = check_data_retention(str(sample_source))
        assert "findings" in result


class TestSoc2Clauses:
    """Tests for SOC2 clause sub-agents."""

    def test_cc6_logical_access(self, sample_source: Path) -> None:
        """CC6 clause checks logical access controls."""
        from soc2_agent.clauses.cc6_logical_access import audit_cc6
        result = audit_cc6(str(sample_source))
        assert "findings" in result

    def test_cc7_system_operations(self, sample_source: Path) -> None:
        """CC7 clause checks system operations."""
        from soc2_agent.clauses.cc7_system_operations import audit_cc7
        result = audit_cc7(str(sample_source))
        assert "findings" in result

    def test_cc8_change_management(self, sample_source: Path) -> None:
        """CC8 clause checks change management."""
        from soc2_agent.clauses.cc8_change_management import audit_cc8
        result = audit_cc8(str(sample_source))
        assert "findings" in result
