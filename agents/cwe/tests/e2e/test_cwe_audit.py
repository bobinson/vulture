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
    # CWE-918: SSRF
    (tmp_path / "ssrf_handler.py").write_text(
        "import requests\n\n"
        "def fetch_url(url):\n"
        "    return requests.get(user_input)\n"
    )
    # CWE-352: CSRF + CWE-502: Deserialization
    (tmp_path / "csrf_app.py").write_text(
        "import pickle\n\n"
        '@app.route("/update", methods=["POST"])\n'
        "def update():\n"
        "    return process()\n"
    )
    (tmp_path / "deserialize.py").write_text(
        "import pickle\n\n"
        "def load_data(data):\n"
        "    return pickle.loads(data)\n"
    )
    # CWE-416: Use after free + CWE-190: Integer overflow
    (tmp_path / "vuln.c").write_text(
        "#include <stdlib.h>\n"
        "void use_freed(char *ptr) {\n"
        "    free(ptr);\n"
        "    ptr->field = 1;\n"
        "}\n"
        "void compute() {\n"
        "    int result = a * b;\n"
        "}\n"
    )
    # CWE-476: NULL pointer deref (Go method call without nil check)
    (tmp_path / "null_deref.go").write_text(
        "package main\n\n"
        "func process() {\n"
        "    val := obj.GetItem()\n"
        "    val.Use()\n"
        "}\n"
    )
    # CWE-770: Unbounded alloc
    (tmp_path / "alloc.go").write_text(
        "package main\n\n"
        "func collect() {\n"
        "    items := make([]string, 0)\n"
        "}\n"
    )
    # CWE-200: Sensitive response
    (tmp_path / "api_response.py").write_text(
        "def error_handler(err):\n"
        '    return Response(str(internal_path))\n'
    )
    # CWE-754: I/O without error check
    (tmp_path / "io_nocheck.py").write_text(
        "def read_data():\n"
        "    data = open('file.txt').read()\n"
        "    return data\n"
    )
    # CWE-833: Deadlock
    (tmp_path / "deadlock.py").write_text(
        "import threading\n\n"
        "lock_a = threading.Lock()\n"
        "lock_b = threading.Lock()\n\n"
        "def transfer():\n"
        "    lock_a.acquire()\n"
        "    lock_b.acquire()\n"
    )
    # CWE-601: Open redirect
    (tmp_path / "redirect_handler.py").write_text(
        "def handle_login(request):\n"
        "    next_url = request.args['next']\n"
        "    return redirect(request.args['url'])\n"
    )
    # CWE-1004: Cookie without HttpOnly
    (tmp_path / "cookie_handler.py").write_text(
        "def set_session(response):\n"
        "    response.set_cookie('session_id', token)\n"
    )
    # CWE-1188: Insecure default config
    (tmp_path / "prod_config.py").write_text(
        "CORS_ALLOW_ALL = True\n"
        "VERIFY_SSL = False\n"
    )
    # CWE-732: Overly permissive permissions
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/bash\n"
        "chmod 777 /var/data\n"
    )
    # CWE-1104: Unpinned dependencies
    (tmp_path / "requirements.txt").write_text(
        "flask\n"
        "requests>=2.0\n"
        "django==4.2.1\n"
    )
    # CWE-829: Untrusted source
    (tmp_path / "install.sh").write_text(
        "#!/bin/bash\n"
        "curl http://example.com/setup.sh | bash\n"
    )
    # CWE-134: Format string
    (tmp_path / "format_vuln.c").write_text(
        "#include <stdio.h>\n"
        "void log_input(char *argv[]) {\n"
        "    printf(argv[1]);\n"
        "}\n"
    )
    # CWE-1321: Prototype pollution
    (tmp_path / "merge_handler.js").write_text(
        "function handleUpdate(req) {\n"
        "    Object.assign({}, req.body);\n"
        "}\n"
    )
    # CWE-401: Memory leak
    (tmp_path / "leak.c").write_text(
        "#include <stdlib.h>\n"
        "void process() {\n"
        "    char *buf = malloc(1024);\n"
        "    return;\n"
        "}\n"
    )
    # CWE-415: Double free
    (tmp_path / "double_free.c").write_text(
        "#include <stdlib.h>\n"
        "void cleanup(char *ptr) {\n"
        "    free(ptr);\n"
        "    ptr = NULL;\n"
        "    free(ptr);\n"
        "}\n"
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
        assert len(body["skills"]) >= 15


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

    def test_injection_detects_ssrf(self, sample_source: Path) -> None:
        """injection_check finds SSRF patterns (CWE-918)."""
        from cwe_agent.skills.injection_check import check_injection
        result = check_injection(str(sample_source))
        assert any(f["category"] == "CWE-918" for f in result["findings"])

    def test_buffer_detects_use_after_free(self, sample_source: Path) -> None:
        """buffer_check finds use-after-free patterns (CWE-416)."""
        from cwe_agent.skills.buffer_check import check_buffer_handling
        result = check_buffer_handling(str(sample_source))
        assert any(f["category"] == "CWE-416" for f in result["findings"])

    def test_buffer_detects_integer_overflow(self, sample_source: Path) -> None:
        """buffer_check finds integer overflow patterns (CWE-190)."""
        from cwe_agent.skills.buffer_check import check_buffer_handling
        result = check_buffer_handling(str(sample_source))
        assert any(f["category"] == "CWE-190" for f in result["findings"])

    def test_input_validation_detects_csrf(self, sample_source: Path) -> None:
        """input_validation_check finds CSRF patterns (CWE-352)."""
        from cwe_agent.skills.input_validation_check import check_input_validation
        result = check_input_validation(str(sample_source))
        assert any(f["category"] == "CWE-352" for f in result["findings"])

    def test_input_validation_detects_deserialization(self, sample_source: Path) -> None:
        """input_validation_check finds deserialization patterns (CWE-502)."""
        from cwe_agent.skills.input_validation_check import check_input_validation
        result = check_input_validation(str(sample_source))
        assert any(f["category"] == "CWE-502" for f in result["findings"])

    def test_resource_detects_null_deref(self, sample_source: Path) -> None:
        """resource_check finds NULL pointer dereference (CWE-476)."""
        from cwe_agent.skills.resource_check import check_resource_management
        result = check_resource_management(str(sample_source))
        assert any(f["category"] == "CWE-476" for f in result["findings"])

    def test_resource_detects_unbounded_alloc(self, sample_source: Path) -> None:
        """resource_check finds unbounded allocation (CWE-770)."""
        from cwe_agent.skills.resource_check import check_resource_management
        result = check_resource_management(str(sample_source))
        assert any(f["category"] == "CWE-770" for f in result["findings"])

    def test_info_exposure_detects_sensitive_response(self, sample_source: Path) -> None:
        """info_exposure_check finds sensitive info in responses (CWE-200)."""
        from cwe_agent.skills.info_exposure_check import check_information_exposure
        result = check_information_exposure(str(sample_source))
        assert any(f["category"] == "CWE-200" for f in result["findings"])

    def test_error_handling_detects_unchecked_io(self, sample_source: Path) -> None:
        """error_handling_check finds unchecked I/O (CWE-754)."""
        from cwe_agent.skills.error_handling_check import check_error_handling
        result = check_error_handling(str(sample_source))
        assert any(f["category"] == "CWE-754" for f in result["findings"])

    def test_concurrency_detects_deadlock(self, sample_source: Path) -> None:
        """concurrency_check finds deadlock patterns (CWE-833)."""
        from cwe_agent.skills.concurrency_check import check_concurrency
        result = check_concurrency(str(sample_source))
        assert any(f["category"] == "CWE-833" for f in result["findings"])

    def test_web_security_check(self, sample_source: Path) -> None:
        """web_security_check finds open redirect and cookie issues."""
        from cwe_agent.skills.web_security_check import check_web_security
        result = check_web_security(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_web_security_detects_open_redirect(self, sample_source: Path) -> None:
        """web_security_check finds open redirect (CWE-601)."""
        from cwe_agent.skills.web_security_check import check_web_security
        result = check_web_security(str(sample_source))
        assert any(f["category"] == "CWE-601" for f in result["findings"])

    def test_configuration_check(self, sample_source: Path) -> None:
        """configuration_check finds insecure defaults and permissions."""
        from cwe_agent.skills.configuration_check import check_configuration
        result = check_configuration(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_configuration_detects_insecure_default(self, sample_source: Path) -> None:
        """configuration_check finds insecure defaults (CWE-1188)."""
        from cwe_agent.skills.configuration_check import check_configuration
        result = check_configuration(str(sample_source))
        assert any(f["category"] == "CWE-1188" for f in result["findings"])

    def test_dependency_check(self, sample_source: Path) -> None:
        """dependency_check finds unpinned deps and untrusted sources."""
        from cwe_agent.skills.dependency_check import check_dependency_security
        result = check_dependency_security(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_dependency_detects_unpinned(self, sample_source: Path) -> None:
        """dependency_check finds unpinned dependencies (CWE-1104)."""
        from cwe_agent.skills.dependency_check import check_dependency_security
        result = check_dependency_security(str(sample_source))
        assert any(f["category"] == "CWE-1104" for f in result["findings"])

    def test_dependency_detects_untrusted_source(self, sample_source: Path) -> None:
        """dependency_check finds pipe-to-shell install (CWE-829)."""
        from cwe_agent.skills.dependency_check import check_dependency_security
        result = check_dependency_security(str(sample_source))
        assert any(f["category"] == "CWE-829" for f in result["findings"])

    def test_data_handling_check(self, sample_source: Path) -> None:
        """data_handling_check finds format string and prototype pollution."""
        from cwe_agent.skills.data_handling_check import check_data_handling
        result = check_data_handling(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_data_handling_detects_format_string(self, sample_source: Path) -> None:
        """data_handling_check finds format string vulnerability (CWE-134)."""
        from cwe_agent.skills.data_handling_check import check_data_handling
        result = check_data_handling(str(sample_source))
        assert any(f["category"] == "CWE-134" for f in result["findings"])

    def test_data_handling_detects_prototype_pollution(self, sample_source: Path) -> None:
        """data_handling_check finds prototype pollution (CWE-1321)."""
        from cwe_agent.skills.data_handling_check import check_data_handling
        result = check_data_handling(str(sample_source))
        assert any(f["category"] == "CWE-1321" for f in result["findings"])

    def test_memory_safety_check(self, sample_source: Path) -> None:
        """memory_safety_check finds memory lifecycle issues."""
        from cwe_agent.skills.memory_safety_check import check_memory_safety
        result = check_memory_safety(str(sample_source))
        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_memory_safety_detects_leak(self, sample_source: Path) -> None:
        """memory_safety_check finds memory leak (CWE-401)."""
        from cwe_agent.skills.memory_safety_check import check_memory_safety
        result = check_memory_safety(str(sample_source))
        assert any(f["category"] == "CWE-401" for f in result["findings"])

    def test_findings_have_catalog_metadata(self, sample_source: Path) -> None:
        """Findings from new skills include catalog enrichment metadata."""
        from cwe_agent.skills.web_security_check import check_web_security
        result = check_web_security(str(sample_source))
        enriched = [f for f in result["findings"] if f.get("cwe_name")]
        assert len(enriched) > 0, "Expected at least one finding with cwe_name from catalog"


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
