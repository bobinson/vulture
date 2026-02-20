"""E2E tests for the CWE audit agent."""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def sample_source(tmp_path: Path) -> Path:
    """Create sample source code with CWE vulnerabilities."""
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
        'PASSWORD = "admin123"\n'
    )
    (tmp_path / "config.py").write_text(
        "DEBUG = True\n"
        'SECRET_KEY = "hardcoded-secret-key-123"\n'
        'DATABASE_URL = "postgresql://user:pass@localhost/db"\n'
    )
    (tmp_path / "server.c").write_text(
        "#include <string.h>\n"
        "void copy_input(char *src) {\n"
        "    char buf[64];\n"
        "    strcpy(buf, src);\n"
        "}\n"
        "char *read_line() {\n"
        "    char buf[256];\n"
        "    return gets(buf);\n"
        "}\n"
    )
    (tmp_path / "handler.py").write_text(
        "import traceback\n\n"
        "def handle_request(req):\n"
        "    try:\n"
        "        process(req)\n"
        "    except:\n"
        "        traceback.print_exc()\n"
    )
    (tmp_path / "worker.py").write_text(
        "import os\n"
        "import threading\n\n"
        "counter = 0\n\n"
        "def increment():\n"
        "    global counter\n"
        "    counter += 1\n\n"
        "def check_file(path):\n"
        "    if os.path.exists(path):\n"
        "        f = open(path)\n"
        "        return f.read()\n"
    )
    (tmp_path / "views.py").write_text(
        "def get_user():\n"
        '    user = get_user(request.args["id"])\n'
        "    return user\n"
    )
    return tmp_path


@pytest.fixture
def clean_source(tmp_path: Path) -> Path:
    """Create clean source code with no CWE issues."""
    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "app.py").write_text(
        "import os\n\n"
        "def get_config():\n"
        '    return os.environ.get("SECRET_KEY")\n'
    )
    return clean_dir


@pytest.fixture
def cwe_app():
    """Create the CWE agent FastAPI app."""
    from cwe_agent.main import app
    return app


class TestCweHealth:
    """Tests for CWE agent health endpoint."""

    @pytest.mark.anyio
    async def test_health_returns_healthy(self, cwe_app) -> None:
        """GET /health returns healthy status."""
        async with AsyncClient(
            transport=ASGITransport(app=cwe_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["agent"] == "cwe"


class TestCweInfo:
    """Tests for CWE agent info endpoint."""

    @pytest.mark.anyio
    async def test_info_returns_config_schema(self, cwe_app) -> None:
        """GET /info returns agent info with CWE config."""
        async with AsyncClient(
            transport=ASGITransport(app=cwe_app), base_url="http://test"
        ) as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "CWE Weakness Auditor"
        assert body["type"] == "cwe"
        assert "config_schema" in body
        assert "skills" in body
        assert len(body["skills"]) >= 10


class TestCweRun:
    """Tests for CWE agent run endpoint."""

    @pytest.mark.anyio
    async def test_run_returns_sse_stream(self, cwe_app, sample_source: Path) -> None:
        """POST /run returns SSE event stream."""
        async with AsyncClient(
            transport=ASGITransport(app=cwe_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-cwe-1",
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
    async def test_run_emits_findings(self, cwe_app, sample_source: Path) -> None:
        """POST /run emits finding events for CWE issues."""
        async with AsyncClient(
            transport=ASGITransport(app=cwe_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-cwe-2",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        body = resp.text
        assert "event: finding" in body
        assert "event: result" in body

    @pytest.mark.anyio
    async def test_run_result_has_cwe_categories(self, cwe_app, sample_source: Path) -> None:
        """POST /run result findings have CWE-XXX category format."""
        async with AsyncClient(
            transport=ASGITransport(app=cwe_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-cwe-3",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        body = resp.text
        found_category = False
        for line in body.split("\n"):
            if not line.startswith("data:"):
                continue
            data = json.loads(line[5:])
            if "category" not in data:
                continue
            found_category = True
            assert data["category"].startswith("CWE-"), f"Category must be CWE-XXX, got {data['category']}"
        assert found_category, "No finding events with category field found"

    @pytest.mark.anyio
    async def test_run_with_category_filter(self, cwe_app, sample_source: Path) -> None:
        """POST /run respects CWE category filter."""
        async with AsyncClient(
            transport=ASGITransport(app=cwe_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-cwe-4",
                    "source_path": str(sample_source),
                    "config": {"categories": ["injection"]},
                },
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body


class TestCweSkills:
    """Tests for individual CWE skills."""

    def test_injection_check(self, sample_source: Path) -> None:
        """injection_check finds SQL injection patterns."""
        from cwe_agent.skills.injection_check import check_injection
        result = check_injection(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0
        assert any("CWE-89" in f["category"] for f in result["findings"])

    def test_buffer_check(self, sample_source: Path) -> None:
        """buffer_check finds buffer overflow patterns."""
        from cwe_agent.skills.buffer_check import check_buffer_handling
        result = check_buffer_handling(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0
        assert any("CWE-120" in f["category"] for f in result["findings"])

    def test_auth_check(self, sample_source: Path) -> None:
        """auth_check finds hardcoded credentials."""
        from cwe_agent.skills.auth_check import check_authentication
        result = check_authentication(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_crypto_check(self, sample_source: Path) -> None:
        """crypto_check finds weak cryptography."""
        from cwe_agent.skills.crypto_check import check_cryptography
        result = check_cryptography(str(sample_source))
        assert "findings" in result

    def test_input_validation_check(self, sample_source: Path) -> None:
        """input_validation_check finds path traversal and validation issues."""
        from cwe_agent.skills.input_validation_check import check_input_validation
        result = check_input_validation(str(sample_source))
        assert "findings" in result

    def test_resource_check(self, sample_source: Path) -> None:
        """resource_check finds resource management issues."""
        from cwe_agent.skills.resource_check import check_resource_management
        result = check_resource_management(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_info_exposure_check(self, sample_source: Path) -> None:
        """info_exposure_check finds information disclosure."""
        from cwe_agent.skills.info_exposure_check import check_information_exposure
        result = check_information_exposure(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_access_control_check(self, sample_source: Path) -> None:
        """access_control_check finds IDOR vulnerabilities."""
        from cwe_agent.skills.access_control_check import check_access_control
        result = check_access_control(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_error_handling_check(self, sample_source: Path) -> None:
        """error_handling_check finds swallowed exceptions."""
        from cwe_agent.skills.error_handling_check import check_error_handling
        result = check_error_handling(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_concurrency_check(self, sample_source: Path) -> None:
        """concurrency_check finds race conditions."""
        from cwe_agent.skills.concurrency_check import check_concurrency
        result = check_concurrency(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0


class TestCweCleanCode:
    """Tests for clean code producing no findings."""

    def test_no_findings_for_clean_code(self, clean_source: Path) -> None:
        """Clean code produces no findings."""
        from cwe_agent.skills import SKILL_MAP
        total_findings = 0
        for skill_fn in SKILL_MAP.values():
            result = skill_fn(str(clean_source))
            total_findings += len(result["findings"])
        assert total_findings == 0
