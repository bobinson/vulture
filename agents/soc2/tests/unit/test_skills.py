"""Unit tests for SOC2 agent skills."""

import pytest

from soc2_agent.skills.access_logging import (
    check_access_logging,
    AUTH_ACTION_PATTERNS,
    LOGGING_PATTERNS,
)
from soc2_agent.config import ALL_CLAUSES, AGENT_INFO, CONFIG_SCHEMA


class TestLoggingPatterns:
    """Tests for logging pattern detection."""

    def test_detects_python_logging(self):
        assert any(p.search("logging.info('User logged in')") for p in LOGGING_PATTERNS)

    def test_detects_logger_instance(self):
        assert any(p.search("logger.error('Auth failed')") for p in LOGGING_PATTERNS)

    def test_detects_go_log(self):
        assert any(p.search('log.Info("Operation complete")') for p in LOGGING_PATTERNS)

    def test_detects_console_log(self):
        assert any(p.search("console.log('Request received')") for p in LOGGING_PATTERNS)

    def test_detects_audit_log(self):
        assert any(p.search("audit_log.write(event)") for p in LOGGING_PATTERNS)


class TestAuthActionPatterns:
    """Tests for authentication action detection."""

    def test_detects_login_function(self):
        assert any(p.search("def login(request):") for p in AUTH_ACTION_PATTERNS)

    def test_detects_logout_function(self):
        assert any(p.search("def logout(request):") for p in AUTH_ACTION_PATTERNS)

    def test_detects_create_function(self):
        assert any(p.search("def create_user(data):") for p in AUTH_ACTION_PATTERNS)

    def test_detects_delete_function(self):
        assert any(p.search("def delete_record(id):") for p in AUTH_ACTION_PATTERNS)

    def test_detects_go_auth(self):
        assert any(p.search("func HandleLogin(w http.ResponseWriter)") for p in AUTH_ACTION_PATTERNS)


class TestCheckAccessLogging:
    """Tests for access logging skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_no_findings_for_empty_dir(self, source_dir):
        result = check_access_logging(str(source_dir))
        assert result == {"findings": []}

    def test_no_findings_when_logging_present(self, source_dir):
        code = """import logging
logger = logging.getLogger(__name__)

def login(request):
    logger.info("User login attempt")
    return True
"""
        (source_dir / "auth.py").write_text(code)
        result = check_access_logging(str(source_dir))
        assert result["findings"] == []

    def test_finding_when_auth_without_logging(self, source_dir):
        code = """def login(request):
    if check_password(request.password):
        return create_session(request.user)
    return None
"""
        (source_dir / "auth.py").write_text(code)
        result = check_access_logging(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "high"
        assert "logging" in result["findings"][0]["title"].lower()

    def test_skips_test_files(self, source_dir):
        code = """def login(request):
    return True
"""
        (source_dir / "test_auth.py").write_text(code)
        result = check_access_logging(str(source_dir))
        assert result["findings"] == []

    def test_finding_for_crud_without_logging(self, source_dir):
        code = """def create_user(data):
    db.insert(data)
    return data

def delete_record(id):
    db.delete(id)
"""
        (source_dir / "handlers.py").write_text(code)
        result = check_access_logging(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "CC6" in result["findings"][0]["category"]


class TestSOC2Config:
    """Tests for SOC2 agent configuration."""

    def test_all_clauses(self):
        assert "CC6" in ALL_CLAUSES
        assert "CC7" in ALL_CLAUSES
        assert "CC8" in ALL_CLAUSES

    def test_agent_type_is_soc2(self):
        assert AGENT_INFO["type"] == "soc2"

    def test_config_schema_has_clauses(self):
        assert "clauses" in CONFIG_SCHEMA["properties"]
        items = CONFIG_SCHEMA["properties"]["clauses"]["items"]
        assert "CC6" in items["enum"]
        assert "CC7" in items["enum"]
        assert "CC8" in items["enum"]
