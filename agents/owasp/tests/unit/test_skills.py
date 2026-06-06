"""Unit tests for OWASP agent skills."""

import pytest

from owasp_agent.skills.injection_check import (
    check_injection,
    SQL_INJECTION_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
)
from owasp_agent.skills.security_misconfig import (
    check_security_misconfig,
    DEBUG_PATTERNS,
    EXPOSED_PATTERNS,
    CORS_PATTERNS,
    COMBINED_DEBUG_RE,
    COMBINED_CORS_RE,
    COMBINED_EXPOSED_RE,
)
from owasp_agent.skills.auth_check import (
    check_authentication,
)
from owasp_agent.skills.crypto_check import (
    check_cryptography,
)
from owasp_agent.skills.access_control import (
    check_access_control,
)
from owasp_agent.config import ALL_CATEGORIES, AGENT_INFO, CONFIG_SCHEMA


class TestSQLInjectionPatterns:
    """Tests for SQL injection regex detection."""

    def test_detects_f_string_select(self):
        line = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_detects_query_string_concat(self):
        line = 'query = "SELECT * FROM users WHERE id = " + user_id'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_detects_sprintf_select(self):
        line = 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", uid)'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_no_false_positive_on_parameterized(self):
        line = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
        assert not any(p.search(line) for p in SQL_INJECTION_PATTERNS)


class TestCommandInjectionPatterns:
    """Tests for command injection regex detection."""

    def test_detects_os_system(self):
        assert any(p.search("os.system(cmd)") for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_subprocess_shell_true(self):
        line = "subprocess.call(cmd, shell=True)"
        assert any(p.search(line) for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_eval(self):
        assert any(p.search("eval(user_input)") for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_os_popen(self):
        assert any(p.search("os.popen(cmd)") for p in COMMAND_INJECTION_PATTERNS)

    def test_no_false_positive_on_method_exec(self):
        line = "db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY)')"
        assert not any(p.search(line) for p in COMMAND_INJECTION_PATTERNS)

    def test_no_false_positive_on_regex_exec(self):
        line = "const m = pattern.exec(input)"
        assert not any(p.search(line) for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_bare_exec_with_variable(self):
        assert any(p.search("exec(user_input)") for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_bare_eval_with_variable(self):
        assert any(p.search("eval(data)") for p in COMMAND_INJECTION_PATTERNS)


class TestCheckInjection:
    """Tests for the injection check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_no_findings_for_clean_code(self, source_dir):
        code = """def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
"""
        (source_dir / "db.py").write_text(code)
        result = check_injection(str(source_dir))
        assert result["findings"] == []

    def test_detects_sql_injection(self, source_dir):
        code = '''def get_user(uid):
    query = f"SELECT * FROM users WHERE id = {uid}"
    cursor.execute(query)
'''
        (source_dir / "db.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "critical"
        assert "injection" in result["findings"][0]["category"].lower()

    def test_detects_command_injection(self, source_dir):
        code = """import os
def run_cmd(user_input):
    os.system(user_input)
"""
        (source_dir / "cmd.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "command injection" in result["findings"][0]["title"].lower()

    def test_test_files_get_medium_severity(self, source_dir):
        code = '''def test_query():
    query = f"SELECT * FROM users WHERE id = {1}"
'''
        (source_dir / "test_db.py").write_text(code)
        result = check_injection(str(source_dir))
        for f in result["findings"]:
            assert f["severity"] == "medium"

    def test_no_finding_for_db_exec_static(self, source_dir):
        code = "db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY)');\n"
        (source_dir / "schema.py").write_text(code)
        result = check_injection(str(source_dir))
        assert result["findings"] == []

    def test_no_finding_for_commented_exec(self, source_dir):
        code = "# exec(user_input)\n"
        (source_dir / "old.py").write_text(code)
        result = check_injection(str(source_dir))
        assert result["findings"] == []

    def test_no_finding_for_static_exec_string(self, source_dir):
        code = """exec("print('hello')")\n"""
        (source_dir / "run.py").write_text(code)
        result = check_injection(str(source_dir))
        assert result["findings"] == []

    def test_finding_for_bare_exec_variable(self, source_dir):
        code = "exec(user_input)\n"
        (source_dir / "danger.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "critical"


class TestSecurityMisconfig:
    """Tests for security misconfiguration detection."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_debug_mode(self, source_dir):
        (source_dir / "settings.py").write_text("DEBUG = True\n")
        result = check_security_misconfig(str(source_dir))
        assert len(result["findings"]) >= 1
        assert "debug" in result["findings"][0]["title"].lower()

    def test_detects_exposed_secret_key(self, source_dir):
        code = """SECRET_KEY = 'my-super-secret-key-123'\n"""
        (source_dir / "config.py").write_text(code)
        result = check_security_misconfig(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "high"

    def test_no_findings_for_clean_config(self, source_dir):
        code = """import os
SECRET_KEY = os.environ.get("SECRET_KEY")
DEBUG = False
"""
        (source_dir / "config.py").write_text(code)
        result = check_security_misconfig(str(source_dir))
        assert result["findings"] == []

    def test_skips_test_files(self, source_dir):
        code = """DEBUG = True\nSECRET_KEY = 'test-key'\n"""
        (source_dir / "test_settings.py").write_text(code)
        result = check_security_misconfig(str(source_dir))
        assert result["findings"] == []


class TestOWASPConfig:
    """Tests for OWASP agent configuration."""

    def test_all_categories(self):
        assert "injection" in ALL_CATEGORIES
        assert "auth_failure" in ALL_CATEGORIES
        assert "crypto_failure" in ALL_CATEGORIES
        assert "access_control" in ALL_CATEGORIES
        assert "security_misconfig" in ALL_CATEGORIES

    def test_agent_type_is_owasp(self):
        assert AGENT_INFO["type"] == "owasp"

    def test_config_schema_has_categories(self):
        assert "categories" in CONFIG_SCHEMA["properties"]


class TestInjectionUntested:
    """Tests for SQL injection patterns not covered by existing tests."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_single_quote_f_string(self, source_dir):
        """Single-quote f-string SQL injection."""
        code = "def get(uid):\n    q = f'SELECT * FROM users WHERE id={uid}'\n"
        (source_dir / "app.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "critical"
        assert result["findings"][0]["category"] == "A03-injection"

    def test_detects_format_call(self, source_dir):
        """str.format() SQL injection."""
        code = 'def get(uid):\n    q = "SELECT * FROM users WHERE id={}".format(uid)\n'
        (source_dir / "app.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["title"] == "Potential SQL injection"

    def test_detects_percent_execute(self, source_dir):
        """Percent-format in execute() call."""
        code = 'def get(uid):\n    cursor.execute("SELECT * FROM users WHERE id=%s" % uid)\n'
        (source_dir / "app.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "A03-injection"


class TestAuthUntested:
    """Tests for authentication patterns not covered by existing tests."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_sha1_hashing(self, source_dir):
        """SHA1 is a weak hashing algorithm."""
        code = "import hashlib\ndef hash_pw(password):\n    return hashlib.sha1(password.encode())\n"
        (source_dir / "auth.py").write_text(code)
        result = check_authentication(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "high"
        assert result["findings"][0]["category"] == "A07-auth-failure"

    def test_detects_password_comparison(self, source_dir):
        """Direct password comparison is insecure."""
        code = 'def login(password):\n    if password == "admin123":\n        return True\n'
        (source_dir / "auth.py").write_text(code)
        result = check_authentication(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["title"] == "Weak authentication mechanism"

    def test_detects_hardcoded_password(self, source_dir):
        """Hardcoded password variable."""
        code = 'hardcoded_password = "secret123"\n'
        (source_dir / "config.py").write_text(code)
        result = check_authentication(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "A07-auth-failure"

    def test_detects_default_password(self, source_dir):
        """Default password constant."""
        code = 'DEFAULT_PASSWORD = "changeme"\n'
        (source_dir / "config.py").write_text(code)
        result = check_authentication(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "high"


class TestAuthMissingAuth:
    """Tests for missing authentication on routes (dead code contract)."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_post_route_without_auth(self, source_dir):
        """POST route without auth decorator should be flagged."""
        code = '''from flask import Flask
app = Flask(__name__)

@app.route("/api/users", methods=["POST"])
def create_user():
    return "created"
'''
        (source_dir / "routes.py").write_text(code)
        result = check_authentication(str(source_dir))
        findings_missing_auth = [
            f for f in result["findings"]
            if "missing authentication" in f["title"].lower()
        ]
        assert len(findings_missing_auth) >= 1
        assert findings_missing_auth[0]["severity"] == "high"

    def test_no_finding_when_auth_decorator_present(self, source_dir):
        """Route with auth decorator should not be flagged for missing auth."""
        code = '''from flask import Flask
from auth import login_required
app = Flask(__name__)

@app.route("/api/users", methods=["POST"])
@login_required
def create_user():
    return "created"
'''
        (source_dir / "routes.py").write_text(code)
        result = check_authentication(str(source_dir))
        findings_missing_auth = [
            f for f in result["findings"]
            if "missing authentication" in f["title"].lower()
        ]
        assert len(findings_missing_auth) == 0


class TestCryptoUntested:
    """Tests for cryptographic patterns not covered by existing tests."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_des(self, source_dir):
        """DES is a weak cipher."""
        code = "from Crypto.Cipher import DES\ncipher = DES.new(key)\n"
        (source_dir / "crypto.py").write_text(code)
        result = check_cryptography(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["title"] == "Weak cryptographic algorithm"
        assert result["findings"][0]["category"] == "A02-crypto-failure"

    def test_detects_rc4(self, source_dir):
        """RC4 cipher detected."""
        code = "cipher = RC4.new(key)\n"
        (source_dir / "crypto.py").write_text(code)
        result = check_cryptography(str(source_dir))
        weak_findings = [f for f in result["findings"] if f["title"] == "Weak cryptographic algorithm"]
        assert len(weak_findings) >= 1

    def test_detects_ecb_mode(self, source_dir):
        """ECB mode is insecure."""
        code = "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\n"
        (source_dir / "crypto.py").write_text(code)
        result = check_cryptography(str(source_dir))
        weak_findings = [f for f in result["findings"] if f["title"] == "Weak cryptographic algorithm"]
        assert len(weak_findings) >= 1
        assert weak_findings[0]["severity"] == "high"

    def test_detects_weak_random(self, source_dir):
        """random() is not cryptographically secure."""
        code = "import random\ntoken = random()\n"
        (source_dir / "tokens.py").write_text(code)
        result = check_cryptography(str(source_dir))
        weak_findings = [f for f in result["findings"] if f["title"] == "Weak cryptographic algorithm"]
        assert len(weak_findings) >= 1

    def test_detects_math_random(self, source_dir):
        """Math.random() is not cryptographically secure."""
        code = "var token = Math.random()\n"
        (source_dir / "tokens.js").write_text(code)
        result = check_cryptography(str(source_dir))
        weak_findings = [f for f in result["findings"] if f["title"] == "Weak cryptographic algorithm"]
        assert len(weak_findings) >= 1

    def test_detects_secret_key(self, source_dir):
        """Hardcoded secret key detected."""
        code = 'secret_key = "my-super-secret-key-12345"\n'
        (source_dir / "config.py").write_text(code)
        result = check_cryptography(str(source_dir))
        secret_findings = [f for f in result["findings"] if f["title"] == "Hardcoded secret detected"]
        assert len(secret_findings) >= 1
        assert secret_findings[0]["severity"] == "critical"

    def test_detects_api_key(self, source_dir):
        """Hardcoded API key detected."""
        code = 'api_key = "sk-1234567890abcdef"\n'
        (source_dir / "config.py").write_text(code)
        result = check_cryptography(str(source_dir))
        secret_findings = [f for f in result["findings"] if f["title"] == "Hardcoded secret detected"]
        assert len(secret_findings) >= 1
        assert secret_findings[0]["category"] == "A02-crypto-failure"

    def test_detects_token(self, source_dir):
        """Hardcoded token detected."""
        code = 'token = "eyJhbGciOiJIUzI1NiJ9.payload"\n'
        (source_dir / "config.py").write_text(code)
        result = check_cryptography(str(source_dir))
        secret_findings = [f for f in result["findings"] if f["title"] == "Hardcoded secret detected"]
        assert len(secret_findings) >= 1
        assert secret_findings[0]["recommendation"] == "Use environment variables or a secrets manager"


class TestSecurityMisconfigUntested:
    """Tests for security misconfiguration patterns not covered by existing tests."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_yaml_debug(self, source_dir):
        """YAML debug: true detected."""
        code = "server:\n  debug: true\n  port: 8080\n"
        (source_dir / "config.yaml").write_text(code)
        result = check_security_misconfig(str(source_dir))
        debug_findings = [f for f in result["findings"] if "debug" in f["title"].lower()]
        assert len(debug_findings) >= 1
        assert debug_findings[0]["severity"] == "medium"

    def test_detects_node_env_development(self, source_dir):
        """NODE_ENV=development detected."""
        code = "NODE_ENV=development\nPORT=3000\n"
        (source_dir / "config.sh").write_text(code)
        result = check_security_misconfig(str(source_dir))
        debug_findings = [f for f in result["findings"] if "debug" in f["title"].lower()]
        assert len(debug_findings) >= 1
        assert debug_findings[0]["category"] == "A05-security-misconfig"

    def test_detects_database_url_with_creds(self, source_dir):
        """DATABASE_URL with embedded credentials detected."""
        code = 'DATABASE_URL = "postgres://user:pass@localhost/db"\n'
        (source_dir / "config.py").write_text(code)
        result = check_security_misconfig(str(source_dir))
        exposed_findings = [f for f in result["findings"] if "exposed" in f["title"].lower() or "config" in f["title"].lower()]
        assert len(exposed_findings) >= 1
        assert exposed_findings[0]["severity"] == "high"

    def test_detects_cors_wildcard(self, source_dir):
        """CORS allow_origins wildcard detected (dead code contract)."""
        code = 'from fastapi.middleware.cors import CORSMiddleware\nallow_origins = ["*"]\n'
        (source_dir / "main.py").write_text(code)
        result = check_security_misconfig(str(source_dir))
        # CORS patterns are defined but not wired into _analyze_file yet.
        # This test defines the contract for when they are wired.
        cors_findings = [
            f for f in result["findings"]
            if "cors" in f.get("title", "").lower() or "cors" in f.get("description", "").lower()
        ]
        assert len(cors_findings) >= 1

    def test_detects_cors_header(self, source_dir):
        """Access-Control-Allow-Origin wildcard detected."""
        code = 'response.headers["Access-Control-Allow-Origin"] = "*"\n'
        (source_dir / "middleware.py").write_text(code)
        result = check_security_misconfig(str(source_dir))
        # This also relies on CORS patterns being wired.
        cors_findings = [
            f for f in result["findings"]
            if "cors" in f.get("title", "").lower() or "cors" in f.get("description", "").lower()
        ]
        assert len(cors_findings) >= 1


class TestAccessControlUntested:
    """Tests for access control patterns not covered by existing tests."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_request_args_id(self, source_dir):
        """Direct use of request.args["id"] is an IDOR risk."""
        code = 'def get_user():\n    user = get_user(request.args["id"])\n    return user\n'
        (source_dir / "views.py").write_text(code)
        result = check_access_control(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["title"] == "Potential IDOR vulnerability"
        assert result["findings"][0]["category"] == "A01-access-control"

    def test_detects_request_form_user_id(self, source_dir):
        """Direct use of request.form["user_id"] is an IDOR risk."""
        code = 'def update():\n    user_id = request.form["user_id"]\n    update_user(user_id)\n'
        (source_dir / "views.py").write_text(code)
        result = check_access_control(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["title"] == "Potential IDOR vulnerability"

    def test_detects_go_url_query(self, source_dir):
        """Go URL query parameter used directly."""
        code = 'func handler(w http.ResponseWriter, r *http.Request) {\n    id := r.URL.Query().Get("user_id")\n}\n'
        (source_dir / "handler.go").write_text(code)
        result = check_access_control(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "A01-access-control"

    def test_severity_high_without_auth(self, source_dir):
        """IDOR without any auth patterns should be high severity."""
        code = 'def get_profile():\n    user = get_user(request.args["id"])\n    return user\n'
        (source_dir / "views.py").write_text(code)
        result = check_access_control(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "high"

    def test_severity_medium_with_auth(self, source_dir):
        """IDOR with auth patterns present should be medium severity."""
        code = '''@requires_permission("read")
def get_profile():
    user = get_user(request.args["id"])
    return user
'''
        (source_dir / "views.py").write_text(code)
        result = check_access_control(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "medium"

    def test_skips_test_files(self, source_dir):
        """Test files with IDOR patterns should not produce findings."""
        code = 'def test_get_user():\n    user = get_user(request.args["id"])\n    assert user is not None\n'
        (source_dir / "test_views.py").write_text(code)
        result = check_access_control(str(source_dir))
        assert result["findings"] == []


class TestCombinedRegexPatterns:
    """Tests that combined regex patterns match the same inputs as individual patterns."""

    def test_combined_debug_matches_debug_true(self):
        """COMBINED_DEBUG_RE matches DEBUG = True."""
        assert COMBINED_DEBUG_RE.search("DEBUG = True")

    def test_combined_debug_matches_yaml_debug(self):
        """COMBINED_DEBUG_RE matches YAML debug: true."""
        assert COMBINED_DEBUG_RE.search("debug: true")

    def test_combined_debug_matches_node_env(self):
        """COMBINED_DEBUG_RE matches NODE_ENV=development."""
        assert COMBINED_DEBUG_RE.search("NODE_ENV=development")

    def test_combined_debug_no_false_positive(self):
        """COMBINED_DEBUG_RE does not match clean config."""
        assert not COMBINED_DEBUG_RE.search("DEBUG = False")
        assert not COMBINED_DEBUG_RE.search("NODE_ENV=production")

    def test_combined_cors_matches_wildcard_origin(self):
        """COMBINED_CORS_RE matches allow_origins = ['*']."""
        assert COMBINED_CORS_RE.search('allow_origins = ["*"]')

    def test_combined_cors_matches_header_wildcard(self):
        """COMBINED_CORS_RE matches Access-Control-Allow-Origin *."""
        assert COMBINED_CORS_RE.search("Access-Control-Allow-Origin: *")

    def test_combined_cors_matches_cors_call(self):
        """COMBINED_CORS_RE matches cors(origin=*)."""
        assert COMBINED_CORS_RE.search("cors(origin='*')")

    def test_combined_cors_no_false_positive(self):
        """COMBINED_CORS_RE does not match restrictive CORS."""
        assert not COMBINED_CORS_RE.search('allow_origins = ["https://example.com"]')

    def test_combined_exposed_matches_db_url(self):
        """COMBINED_EXPOSED_RE matches DATABASE_URL with creds."""
        assert COMBINED_EXPOSED_RE.search('DATABASE_URL = "postgres://user:pass@localhost/db"')

    def test_combined_exposed_matches_secret_key(self):
        """COMBINED_EXPOSED_RE matches SECRET_KEY = 'value'."""
        assert COMBINED_EXPOSED_RE.search("SECRET_KEY = 'my-secret'")

    def test_combined_exposed_no_false_positive(self):
        """COMBINED_EXPOSED_RE does not match env var reference."""
        assert not COMBINED_EXPOSED_RE.search("SECRET_KEY = os.environ.get('KEY')")

    def test_combined_regexes_equivalent_to_originals(self):
        """Combined patterns match the same inputs as iterating individual patterns."""
        debug_lines = [
            "DEBUG = True",
            "debug : true",
            "NODE_ENV = 'development'",
            "DEBUG = False",
            "regular code",
        ]
        for line in debug_lines:
            individual = any(p.search(line) for p in DEBUG_PATTERNS)
            combined = bool(COMBINED_DEBUG_RE.search(line))
            assert individual == combined, f"Mismatch on debug line: {line!r}"

        cors_lines = [
            'allow_origins = ["*"]',
            "Access-Control-Allow-Origin: *",
            "cors(origin='*')",
            'allow_origins = ["https://safe.com"]',
        ]
        for line in cors_lines:
            individual = any(p.search(line) for p in CORS_PATTERNS)
            combined = bool(COMBINED_CORS_RE.search(line))
            assert individual == combined, f"Mismatch on cors line: {line!r}"

        exposed_lines = [
            'DATABASE_URL = "postgres://user:pass@localhost/db"',
            "SECRET_KEY = 'my-secret'",
            "SECRET_KEY = os.environ.get('KEY')",
        ]
        for line in exposed_lines:
            individual = any(p.search(line) for p in EXPOSED_PATTERNS)
            combined = bool(COMBINED_EXPOSED_RE.search(line))
            assert individual == combined, f"Mismatch on exposed line: {line!r}"
