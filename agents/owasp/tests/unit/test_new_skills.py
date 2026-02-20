"""Unit tests for new OWASP skills (A04, A06, A08, A09, A10)."""

import pytest

from owasp_agent.skills.insecure_design import check_insecure_design
from owasp_agent.skills.vulnerable_components import check_vulnerable_components
from owasp_agent.skills.data_integrity import check_data_integrity
from owasp_agent.skills.logging_check import check_logging
from owasp_agent.skills.ssrf_check import check_ssrf


class TestInsecureDesign:
    """Tests for A04 insecure design detection (auth without rate limiting)."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_auth_endpoint_without_rate_limit(self, source_dir):
        code = """from flask import request

def login(request):
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    return jsonify(user)
"""
        (source_dir / "app.py").write_text(code)
        result = check_insecure_design(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "medium"
        assert finding["category"] == "A04-insecure-design"

    def test_no_finding_when_rate_limited(self, source_dir):
        code = """from flask import request

def login(request):
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    return jsonify(user)
"""
        (source_dir / "app.py").write_text(code)
        middleware_code = """from functools import wraps

@rate_limit
def apply_rate_limiting(f):
    pass
"""
        (source_dir / "middleware.py").write_text(middleware_code)
        result = check_insecure_design(str(source_dir))
        assert result["findings"] == []

    def test_no_finding_for_non_auth_endpoint(self, source_dir):
        code = """def get_users():
    return User.query.all()
"""
        (source_dir / "app.py").write_text(code)
        result = check_insecure_design(str(source_dir))
        assert result["findings"] == []

    def test_skips_test_files(self, source_dir):
        code = """def login(request):
    username = request.form['username']
    return authenticate(username)
"""
        (source_dir / "test_auth.py").write_text(code)
        result = check_insecure_design(str(source_dir))
        assert result["findings"] == []


class TestVulnerableComponents:
    """Tests for A06 vulnerable components detection."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_vulnerable_pyyaml(self, source_dir):
        (source_dir / "requirements.txt").write_text("pyyaml==5.3\n")
        result = check_vulnerable_components(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "high"
        assert finding["category"] == "A06-vulnerable-components"

    def test_safe_version_no_finding(self, source_dir):
        (source_dir / "requirements.txt").write_text("pyyaml==6.0.1\n")
        result = check_vulnerable_components(str(source_dir))
        assert result["findings"] == []

    def test_detects_vulnerable_npm(self, source_dir):
        pkg = '{"dependencies":{"lodash":"4.17.20"}}'
        (source_dir / "package.json").write_text(pkg)
        result = check_vulnerable_components(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_deps_no_finding(self, source_dir):
        result = check_vulnerable_components(str(source_dir))
        assert result["findings"] == []


class TestDataIntegrity:
    """Tests for A08 data integrity / unsafe deserialization detection."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_pickle_loads(self, source_dir):
        code = """import pickle
data = pickle.loads(user_input)
"""
        (source_dir / "handler.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "critical"
        assert finding["category"] == "A08-data-integrity"

    def test_detects_pickle_load(self, source_dir):
        code = """import pickle
obj = pickle.load(open("data.pkl", "rb"))
"""
        (source_dir / "loader.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_detects_unsafe_yaml_load(self, source_dir):
        code = """import yaml
config = yaml.load(data)
"""
        (source_dir / "config.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_finding_yaml_safe_load(self, source_dir):
        code = """import yaml
config = yaml.safe_load(data)
"""
        (source_dir / "config.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert result["findings"] == []

    def test_no_finding_yaml_load_with_safe_loader(self, source_dir):
        code = """import yaml
from yaml import SafeLoader
config = yaml.load(data, Loader=SafeLoader)
"""
        (source_dir / "config.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert result["findings"] == []

    def test_detects_marshal_loads(self, source_dir):
        code = """import marshal
obj = marshal.loads(data)
"""
        (source_dir / "codec.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_skips_comments(self, source_dir):
        code = """# pickle.loads(data)
"""
        (source_dir / "old.py").write_text(code)
        result = check_data_integrity(str(source_dir))
        assert result["findings"] == []


class TestLoggingCheck:
    """Tests for A09 logging failure / sensitive data in logs detection."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_password_in_log(self, source_dir):
        code = """import logging
logger = logging.getLogger(__name__)
logger.info(f"User login: password={password}")
"""
        (source_dir / "auth.py").write_text(code)
        result = check_logging(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "high"
        assert finding["category"] == "A09-logging-failure"

    def test_detects_secret_in_print(self, source_dir):
        code = """print(f"Secret: {secret}")
"""
        (source_dir / "debug.py").write_text(code)
        result = check_logging(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_detects_token_in_log(self, source_dir):
        code = """import logging
log = logging.getLogger()
log.debug(f"Token: {token}")
"""
        (source_dir / "middleware.py").write_text(code)
        result = check_logging(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_finding_generic_log(self, source_dir):
        code = """import logging
logger = logging.getLogger(__name__)
logger.info("User logged in successfully")
"""
        (source_dir / "auth.py").write_text(code)
        result = check_logging(str(source_dir))
        assert result["findings"] == []

    def test_no_finding_password_prompt(self, source_dir):
        code = """print("Enter your password:")
"""
        (source_dir / "cli.py").write_text(code)
        result = check_logging(str(source_dir))
        assert result["findings"] == []

    def test_skips_comments(self, source_dir):
        code = """# logger.info(f"password={pwd}")
"""
        (source_dir / "old.py").write_text(code)
        result = check_logging(str(source_dir))
        assert result["findings"] == []


class TestSsrfCheck:
    """Tests for A10 SSRF detection (HTTP requests with variable URLs)."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_requests_get_variable(self, source_dir):
        code = """import requests
resp = requests.get(url)
"""
        (source_dir / "client.py").write_text(code)
        result = check_ssrf(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "high"
        assert finding["category"] == "A10-ssrf"

    def test_detects_requests_post_variable(self, source_dir):
        code = """import requests
resp = requests.post(user_url, data=payload)
"""
        (source_dir / "api.py").write_text(code)
        result = check_ssrf(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_finding_literal_url(self, source_dir):
        code = """import requests
resp = requests.get("https://api.example.com/data")
"""
        (source_dir / "client.py").write_text(code)
        result = check_ssrf(str(source_dir))
        assert result["findings"] == []

    def test_detects_urllib_variable(self, source_dir):
        code = """import urllib.request
resp = urllib.request.urlopen(target_url)
"""
        (source_dir / "fetcher.py").write_text(code)
        result = check_ssrf(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_detects_go_http_get(self, source_dir):
        code = """package main
resp, err := http.Get(targetURL)
"""
        (source_dir / "client.go").write_text(code)
        result = check_ssrf(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_detects_httpx_get(self, source_dir):
        code = """import httpx
resp = httpx.get(url)
"""
        (source_dir / "async_client.py").write_text(code)
        result = check_ssrf(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_skips_test_files(self, source_dir):
        code = """import requests
resp = requests.get(url)
"""
        (source_dir / "test_api.py").write_text(code)
        result = check_ssrf(str(source_dir))
        for finding in result["findings"]:
            assert finding["severity"] == "medium"

    def test_skips_comments(self, source_dir):
        code = """# requests.get(url)
"""
        (source_dir / "old.py").write_text(code)
        result = check_ssrf(str(source_dir))
        assert result["findings"] == []
