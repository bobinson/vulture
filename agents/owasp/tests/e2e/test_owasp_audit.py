"""E2E tests for the OWASP audit agent."""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def sample_source(tmp_path: Path) -> Path:
    """Create sample source code with OWASP vulnerabilities."""
    (tmp_path / "app.py").write_text(
        "import sqlite3\n\n"
        "def get_user(user_id: str) -> dict:\n"
        '    conn = sqlite3.connect("app.db")\n'
        '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        "    return conn.execute(query).fetchone()\n\n"
        "def render_page(content: str) -> str:\n"
        '    return f"<html><body>{content}</body></html>"\n'
    )
    (tmp_path / "auth.py").write_text(
        "import hashlib\n\n"
        "def hash_password(password: str) -> str:\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n\n"
        "def check_admin(role: str) -> bool:\n"
        '    return role == "admin"\n'
    )
    (tmp_path / "config.py").write_text(
        "DEBUG = True\n"
        'SECRET_KEY = "hardcoded-secret-key-123"\n'
        'DATABASE_URL = "postgresql://user:pass@localhost/db"\n'
    )
    return tmp_path


@pytest.fixture
def owasp_app():
    """Create the OWASP agent FastAPI app."""
    from owasp_agent.main import app
    return app


class TestOwaspHealth:
    """Tests for OWASP agent health endpoint."""

    @pytest.mark.anyio
    async def test_health_returns_healthy(self, owasp_app) -> None:
        """GET /health returns healthy status."""
        async with AsyncClient(
            transport=ASGITransport(app=owasp_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["agent"] == "owasp"


class TestOwaspInfo:
    """Tests for OWASP agent info endpoint."""

    @pytest.mark.anyio
    async def test_info_returns_config_schema(self, owasp_app) -> None:
        """GET /info returns agent info with OWASP Top 10 config."""
        async with AsyncClient(
            transport=ASGITransport(app=owasp_app), base_url="http://test"
        ) as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "OWASP Security Auditor"
        assert body["type"] == "owasp"
        assert "config_schema" in body
        assert "skills" in body
        assert len(body["skills"]) >= 5


class TestOwaspRun:
    """Tests for OWASP agent run endpoint."""

    @pytest.mark.anyio
    async def test_run_returns_sse_stream(self, owasp_app, sample_source: Path) -> None:
        """POST /run returns SSE event stream."""
        async with AsyncClient(
            transport=ASGITransport(app=owasp_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-owasp-1",
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
    async def test_run_emits_findings(self, owasp_app, sample_source: Path) -> None:
        """POST /run emits finding events for OWASP issues."""
        async with AsyncClient(
            transport=ASGITransport(app=owasp_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-owasp-2",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        body = resp.text
        assert "event: finding" in body
        assert "event: result" in body

    @pytest.mark.anyio
    async def test_run_with_category_filter(self, owasp_app, sample_source: Path) -> None:
        """POST /run respects OWASP category filter."""
        async with AsyncClient(
            transport=ASGITransport(app=owasp_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-owasp-3",
                    "source_path": str(sample_source),
                    "config": {"categories": ["injection"]},
                },
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body


class TestOwaspSkills:
    """Tests for individual OWASP skills."""

    def test_injection_check(self, sample_source: Path) -> None:
        """injection_check finds SQL injection patterns."""
        from owasp_agent.skills.injection_check import check_injection
        result = check_injection(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_auth_check(self, sample_source: Path) -> None:
        """auth_check finds weak authentication patterns."""
        from owasp_agent.skills.auth_check import check_authentication
        result = check_authentication(str(sample_source))
        assert "findings" in result

    def test_crypto_check(self, sample_source: Path) -> None:
        """crypto_check finds weak cryptography."""
        from owasp_agent.skills.crypto_check import check_cryptography
        result = check_cryptography(str(sample_source))
        assert "findings" in result

    def test_access_control(self, sample_source: Path) -> None:
        """access_control finds access control issues."""
        from owasp_agent.skills.access_control import check_access_control
        result = check_access_control(str(sample_source))
        assert "findings" in result

    def test_security_misconfig(self, sample_source: Path) -> None:
        """security_misconfig finds misconfiguration issues."""
        from owasp_agent.skills.security_misconfig import check_security_misconfig
        result = check_security_misconfig(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_injection_check_no_false_positive_on_static_db_exec(self, tmp_path: Path) -> None:
        """injection_check must NOT flag db.exec('CREATE TABLE...') as command injection."""
        (tmp_path / "schema.py").write_text(
            "import sqlite3\n\n"
            "def init_db():\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    db = conn.cursor()\n"
            "    db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY)')\n"
        )
        from owasp_agent.skills.injection_check import check_injection
        result = check_injection(str(tmp_path))
        assert result["findings"] == []
