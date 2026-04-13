"""Unit tests for CWE agent skills."""

import pytest

from cwe_agent.skills.injection_check import (
    check_injection,
    SQL_INJECTION_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    XSS_PATTERNS,
    CODE_INJECTION_PATTERNS,
    SSRF_PATTERNS,
)
from cwe_agent.skills.buffer_check import (
    check_buffer_handling,
    UNBOUNDED_COPY_PATTERNS,
    OOB_WRITE_PATTERNS,
    USE_AFTER_FREE_PATTERNS,
    INTEGER_OVERFLOW_PATTERNS,
)
from cwe_agent.skills.auth_check import (
    check_authentication,
    HARDCODED_CRED_PATTERNS,
    WEAK_AUTH_PATTERNS,
)
from cwe_agent.skills.crypto_check import (
    check_cryptography,
    BROKEN_CRYPTO_PATTERNS,
    WEAK_RANDOM_PATTERNS,
    HARDCODED_KEY_PATTERNS,
)
from cwe_agent.skills.input_validation_check import (
    check_input_validation,
    PATH_TRAVERSAL_PATTERNS,
    XXE_PATTERNS,
    CSRF_PATTERNS,
    DESERIALIZATION_PATTERNS,
)
from cwe_agent.skills.resource_check import (
    check_resource_management,
    RESOURCE_OPEN_PATTERNS,
    NULL_DEREF_PATTERNS,
    UNBOUNDED_ALLOC_PATTERNS,
)
from cwe_agent.skills.info_exposure_check import (
    check_information_exposure,
    ERROR_DISCLOSURE_PATTERNS,
    LOG_SENSITIVE_PATTERNS,
    SENSITIVE_RESPONSE_PATTERNS,
)
from cwe_agent.skills.access_control_check import (
    check_access_control,
    IDOR_PATTERNS,
)
from cwe_agent.skills.error_handling_check import (
    check_error_handling,
    BARE_EXCEPT_PATTERNS,
    EMPTY_CATCH_PATTERNS,
    IO_WITHOUT_CHECK,
)
from cwe_agent.skills.concurrency_check import (
    check_concurrency,
    TOCTOU_CHECK_PATTERNS,
    TOCTOU_USE_PATTERNS,
    LOCK_ACQUIRE,
)
from cwe_agent.config import ALL_CATEGORIES, AGENT_INFO, CONFIG_SCHEMA


# === Injection Patterns ===

class TestSQLInjectionPatterns:
    """Tests for SQL injection regex detection."""

    def test_detects_f_string_select(self):
        line = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_detects_format_call(self):
        line = 'query = "SELECT * FROM users WHERE id={}".format(uid)'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_detects_sprintf(self):
        line = 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", uid)'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_no_false_positive_parameterized(self):
        line = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
        assert not any(p.search(line) for p in SQL_INJECTION_PATTERNS)


class TestCommandInjectionPatterns:
    """Tests for command injection regex detection."""

    def test_detects_os_system(self):
        assert any(p.search("os.system(cmd)") for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_subprocess_shell(self):
        line = "subprocess.call(cmd, shell=True)"
        assert any(p.search(line) for p in COMMAND_INJECTION_PATTERNS)

    def test_detects_os_popen(self):
        assert any(p.search("os.popen(cmd)") for p in COMMAND_INJECTION_PATTERNS)


class TestXSSPatterns:
    """Tests for XSS regex detection."""

    def test_detects_innerhtml(self):
        line = 'element.innerHTML = userInput'
        assert any(p.search(line) for p in XSS_PATTERNS)

    def test_detects_document_write(self):
        line = 'document.write(data)'
        assert any(p.search(line) for p in XSS_PATTERNS)


class TestCheckInjection:
    """Tests for the injection check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_returns_dict_with_findings(self, source_dir):
        result = check_injection(str(source_dir))
        assert isinstance(result, dict)
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_detects_sql_injection(self, source_dir):
        code = 'def get(uid):\n    q = f"SELECT * FROM users WHERE id = {uid}"\n'
        (source_dir / "db.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-89"
        assert result["findings"][0]["severity"] == "critical"

    def test_detects_command_injection(self, source_dir):
        code = "import os\ndef run(cmd):\n    os.system(cmd)\n"
        (source_dir / "cmd.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-78"

    def test_test_files_get_reduced_severity(self, source_dir):
        code = 'def test_q():\n    q = f"SELECT * FROM users WHERE id = {1}"\n'
        (source_dir / "test_db.py").write_text(code)
        result = check_injection(str(source_dir))
        for f in result["findings"]:
            assert f["severity"] in ("medium", "low")

    def test_no_finding_for_commented_code(self, source_dir):
        code = "# os.system(cmd)\n"
        (source_dir / "old.py").write_text(code)
        result = check_injection(str(source_dir))
        assert result["findings"] == []

    def test_no_findings_clean_code(self, source_dir):
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))\n'
        (source_dir / "db.py").write_text(code)
        result = check_injection(str(source_dir))
        assert result["findings"] == []


# === Buffer Handling Patterns ===

class TestBufferPatterns:
    """Tests for buffer overflow regex detection."""

    def test_detects_strcpy(self):
        assert any(p.search("strcpy(buf, src);") for p in UNBOUNDED_COPY_PATTERNS)

    def test_detects_gets(self):
        assert any(p.search("gets(buffer);") for p in UNBOUNDED_COPY_PATTERNS)

    def test_detects_sprintf(self):
        assert any(p.search('sprintf(buf, "%s", src);') for p in UNBOUNDED_COPY_PATTERNS)

    def test_no_false_positive_strncpy(self):
        assert not any(p.search("strncpy(buf, src, sizeof(buf));") for p in UNBOUNDED_COPY_PATTERNS)


class TestCheckBufferHandling:
    """Tests for the buffer handling check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_strcpy(self, source_dir):
        code = "void f(char *src) {\n    char buf[64];\n    strcpy(buf, src);\n}\n"
        (source_dir / "buf.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-120"

    def test_detects_gets(self, source_dir):
        code = "char *read() {\n    char buf[256];\n    return gets(buf);\n}\n"
        (source_dir / "input.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_findings_safe_code(self, source_dir):
        code = "void f(char *src) {\n    char buf[64];\n    strncpy(buf, src, sizeof(buf));\n}\n"
        (source_dir / "safe.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        assert result["findings"] == []

    def test_ignores_python_files(self, source_dir):
        code = "data = 'strcpy'\n"
        (source_dir / "safe.py").write_text(code)
        result = check_buffer_handling(str(source_dir))
        assert result["findings"] == []


# === Authentication Patterns ===

class TestAuthPatterns:
    """Tests for authentication regex detection."""

    def test_detects_hardcoded_password(self):
        line = 'PASSWORD = "secret123"'
        assert any(p.search(line) for p in HARDCODED_CRED_PATTERNS)

    def test_detects_md5_hashing(self):
        line = "hashlib.md5(password.encode())"
        assert any(p.search(line) for p in WEAK_AUTH_PATTERNS)


class TestCheckAuthentication:
    """Tests for the authentication check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_hardcoded_password(self, source_dir):
        code = 'PASSWORD = "admin123"\n'
        (source_dir / "config.py").write_text(code)
        result = check_authentication(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-798"

    def test_detects_weak_hash(self, source_dir):
        code = "import hashlib\ndef h(password):\n    return hashlib.md5(password.encode())\n"
        (source_dir / "auth.py").write_text(code)
        result = check_authentication(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-287"

    def test_no_finding_for_env_var(self, source_dir):
        code = 'import os\nPASSWORD = os.environ.get("PASSWORD")\n'
        (source_dir / "config.py").write_text(code)
        result = check_authentication(str(source_dir))
        cred_findings = [f for f in result["findings"] if f["category"] == "CWE-798"]
        assert len(cred_findings) == 0


# === Cryptography Patterns ===

class TestCryptoPatterns:
    """Tests for cryptographic weakness detection."""

    def test_detects_des(self):
        line = "from Crypto.Cipher import DES"
        assert any(p.search(line) for p in BROKEN_CRYPTO_PATTERNS)

    def test_detects_math_random(self):
        line = "var token = Math.random()"
        assert any(p.search(line) for p in WEAK_RANDOM_PATTERNS)

    def test_detects_hardcoded_key(self):
        line = 'secret_key = "my-super-secret-key-12345"'
        assert any(p.search(line) for p in HARDCODED_KEY_PATTERNS)


class TestCheckCryptography:
    """Tests for the cryptography check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_des_cipher(self, source_dir):
        code = "from Crypto.Cipher import DES\ncipher = DES.new(key)\n"
        (source_dir / "crypto.py").write_text(code)
        result = check_cryptography(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-327"

    def test_detects_weak_random(self, source_dir):
        code = "import random\ntoken = random.random()\n"
        (source_dir / "tokens.py").write_text(code)
        result = check_cryptography(str(source_dir))
        random_findings = [f for f in result["findings"] if f["category"] == "CWE-330"]
        assert len(random_findings) >= 1

    def test_detects_hardcoded_secret_key(self, source_dir):
        code = 'secret_key = "my-super-secret-key-12345"\n'
        (source_dir / "config.py").write_text(code)
        result = check_cryptography(str(source_dir))
        assert len(result["findings"]) >= 1


# === Input Validation Patterns ===

class TestInputValidationPatterns:
    """Tests for input validation regex detection."""

    def test_detects_path_traversal(self):
        line = 'path = os.path.join(base_dir, user_input)'
        assert any(p.search(line) for p in PATH_TRAVERSAL_PATTERNS)

    def test_detects_xxe(self):
        line = "tree = etree.parse(xml_file)"
        assert any(p.search(line) for p in XXE_PATTERNS)


class TestCheckInputValidation:
    """Tests for the input validation check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_path_traversal(self, source_dir):
        code = 'import os\ndef serve(name):\n    path = os.path.join("/uploads", name)\n    return open(path).read()\n'
        (source_dir / "views.py").write_text(code)
        result = check_input_validation(str(source_dir))
        assert len(result["findings"]) >= 1

    def test_no_findings_for_clean_code(self, source_dir):
        code = "import os\nx = os.environ.get('FOO')\n"
        (source_dir / "app.py").write_text(code)
        result = check_input_validation(str(source_dir))
        assert result["findings"] == []


# === Resource Management Patterns ===

class TestResourcePatterns:
    """Tests for resource management regex detection."""

    def test_detects_open_without_close(self):
        line = "f = open('data.txt')"
        assert any(p.search(line) for p in RESOURCE_OPEN_PATTERNS)


class TestCheckResourceManagement:
    """Tests for the resource management check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_resource_leak(self, source_dir):
        code = "def read():\n    f = open('data.txt')\n    data = f.read()\n    return data\n"
        (source_dir / "io.py").write_text(code)
        result = check_resource_management(str(source_dir))
        assert len(result["findings"]) >= 1
        assert any(f["category"] == "CWE-404" for f in result["findings"])

    def test_no_finding_for_with_statement(self, source_dir):
        code = "def read():\n    with open('data.txt') as f:\n        return f.read()\n"
        (source_dir / "io.py").write_text(code)
        result = check_resource_management(str(source_dir))
        leak_findings = [f for f in result["findings"] if f["category"] == "CWE-404"]
        assert len(leak_findings) == 0


# === Information Exposure Patterns ===

class TestInfoExposurePatterns:
    """Tests for information exposure regex detection."""

    def test_detects_traceback(self):
        line = "traceback.print_exc()"
        assert any(p.search(line) for p in ERROR_DISCLOSURE_PATTERNS)

    def test_detects_log_password(self):
        line = 'logging.info(f"password={password}")'
        assert any(p.search(line) for p in LOG_SENSITIVE_PATTERNS)


class TestCheckInformationExposure:
    """Tests for the information exposure check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_error_disclosure(self, source_dir):
        code = "import traceback\ndef h(r):\n    try:\n        f()\n    except:\n        traceback.print_exc()\n"
        (source_dir / "handler.py").write_text(code)
        result = check_information_exposure(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-209"


# === Access Control Patterns ===

class TestAccessControlPatterns:
    """Tests for access control regex detection."""

    def test_detects_request_args_id(self):
        line = 'user = get_user(request.args["id"])'
        assert any(p.search(line) for p in IDOR_PATTERNS)


class TestCheckAccessControl:
    """Tests for the access control check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_idor(self, source_dir):
        code = 'def get():\n    user = get_user(request.args["id"])\n    return user\n'
        (source_dir / "views.py").write_text(code)
        result = check_access_control(str(source_dir))
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["category"] == "CWE-639"

    def test_reduces_severity_for_test_files(self, source_dir):
        code = 'def test_get():\n    user = get_user(request.args["id"])\n'
        (source_dir / "test_views.py").write_text(code)
        result = check_access_control(str(source_dir))
        for f in result["findings"]:
            assert f["severity"] in ("low", "medium", "info")


# === Error Handling Patterns ===

class TestErrorHandlingPatterns:
    """Tests for error handling regex detection."""

    def test_detects_bare_except(self):
        line = "except:"
        assert any(p.search(line) for p in BARE_EXCEPT_PATTERNS)

    def test_detects_empty_catch(self):
        line = "} catch (Exception e) {}"
        assert any(p.search(line) for p in EMPTY_CATCH_PATTERNS)


class TestCheckErrorHandling:
    """Tests for the error handling check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_bare_except(self, source_dir):
        code = "def f():\n    try:\n        do()\n    except:\n        pass\n"
        (source_dir / "util.py").write_text(code)
        result = check_error_handling(str(source_dir))
        assert len(result["findings"]) >= 1
        assert any(f["category"] == "CWE-755" for f in result["findings"])

    def test_no_finding_for_specific_except(self, source_dir):
        code = "def f():\n    try:\n        do()\n    except ValueError as e:\n        log(e)\n"
        (source_dir / "util.py").write_text(code)
        result = check_error_handling(str(source_dir))
        bare_findings = [f for f in result["findings"] if f["category"] == "CWE-755"]
        assert len(bare_findings) == 0


# === Concurrency Patterns ===

class TestConcurrencyPatterns:
    """Tests for concurrency regex detection."""

    def test_detects_toctou_check(self):
        line = "if os.path.exists(path):"
        assert any(p.search(line) for p in TOCTOU_CHECK_PATTERNS)


class TestCheckConcurrency:
    """Tests for the concurrency check skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_toctou(self, source_dir):
        code = "import os\ndef check(path):\n    if os.path.exists(path):\n        f = open(path)\n        return f.read()\n"
        (source_dir / "worker.py").write_text(code)
        result = check_concurrency(str(source_dir))
        toctou = [f for f in result["findings"] if f["category"] == "CWE-367"]
        assert len(toctou) >= 1


# === SSRF Patterns (CWE-918) ===

class TestSSRFPatterns:
    """Tests for SSRF regex detection."""

    def test_detects_requests_get_user_input(self):
        line = "resp = requests.get(user_input)"
        assert any(p.search(line) for p in SSRF_PATTERNS)

    def test_detects_urllib_user_input(self):
        line = "urllib.request.urlopen(user_input)"
        assert any(p.search(line) for p in SSRF_PATTERNS)

    def test_no_false_positive_static_url(self):
        line = 'requests.get("https://api.example.com/data")'
        assert not any(p.search(line) for p in SSRF_PATTERNS)


class TestCheckSSRF:
    """Tests for the SSRF check in injection skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_ssrf(self, source_dir):
        code = "import requests\ndef fetch(url):\n    return requests.get(user_input)\n"
        (source_dir / "api.py").write_text(code)
        result = check_injection(str(source_dir))
        ssrf = [f for f in result["findings"] if f["category"] == "CWE-918"]
        assert len(ssrf) >= 1

    def test_no_finding_with_allowlist(self, source_dir):
        code = "import requests\ndef fetch(url):\n    validate_url(url)\n    allowed_hosts = ['api.example.com']\n    return requests.get(user_input)\n"
        (source_dir / "api.py").write_text(code)
        result = check_injection(str(source_dir))
        ssrf = [f for f in result["findings"] if f["category"] == "CWE-918"]
        assert len(ssrf) == 0


# === Use After Free Patterns (CWE-416) ===

class TestUseAfterFreePatterns:
    """Tests for use-after-free regex detection."""

    def test_detects_free_call(self):
        line = "    free(ptr);"
        assert any(p.search(line) for p in USE_AFTER_FREE_PATTERNS)

    def test_no_false_positive_no_free(self):
        line = "    ptr->field = 1;"
        assert not any(p.search(line) for p in USE_AFTER_FREE_PATTERNS)


class TestCheckUseAfterFree:
    """Tests for the use-after-free check in buffer skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_use_after_free(self, source_dir):
        code = "void f(char *ptr) {\n    free(ptr);\n    ptr->field = 1;\n}\n"
        (source_dir / "uaf.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        uaf = [f for f in result["findings"] if f["category"] == "CWE-416"]
        assert len(uaf) >= 1

    def test_no_finding_when_nulled(self, source_dir):
        code = "void f(char *ptr) {\n    free(ptr);\n    ptr = NULL;\n}\n"
        (source_dir / "safe.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        uaf = [f for f in result["findings"] if f["category"] == "CWE-416"]
        assert len(uaf) == 0


# === Integer Overflow Patterns (CWE-190) ===

class TestIntegerOverflowPatterns:
    """Tests for integer overflow regex detection."""

    def test_detects_int_arithmetic(self):
        line = "    int result = a * b;"
        assert any(p.search(line) for p in INTEGER_OVERFLOW_PATTERNS)

    def test_detects_malloc_multiply(self):
        line = "    malloc(count * size)"
        assert any(p.search(line) for p in INTEGER_OVERFLOW_PATTERNS)


class TestCheckIntegerOverflow:
    """Tests for the integer overflow check in buffer skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_overflow(self, source_dir):
        code = "void f() {\n    int result = a * b;\n}\n"
        (source_dir / "math.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        overflow = [f for f in result["findings"] if f["category"] == "CWE-190"]
        assert len(overflow) >= 1

    def test_no_finding_with_check(self, source_dir):
        code = "void f() {\n    if (a > INT_MAX / b) return;\n    int result = a * b;\n}\n"
        (source_dir / "safe.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        overflow = [f for f in result["findings"] if f["category"] == "CWE-190"]
        assert len(overflow) == 0


# === CSRF Patterns (CWE-352) ===

class TestCSRFPatterns:
    """Tests for CSRF regex detection."""

    def test_detects_flask_post_route(self):
        line = '@app.route("/update", methods=["POST"])'
        assert any(p.search(line) for p in CSRF_PATTERNS)

    def test_detects_express_post(self):
        line = 'router.post("/api/update", handler)'
        assert any(p.search(line) for p in CSRF_PATTERNS)

    def test_no_false_positive_get(self):
        line = '@app.route("/read", methods=["GET"])'
        assert not any(p.search(line) for p in CSRF_PATTERNS)


class TestCheckCSRF:
    """Tests for the CSRF check in input validation skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_csrf(self, source_dir):
        code = '@app.route("/update", methods=["POST"])\ndef update():\n    return process()\n'
        (source_dir / "app.py").write_text(code)
        result = check_input_validation(str(source_dir))
        csrf = [f for f in result["findings"] if f["category"] == "CWE-352"]
        assert len(csrf) >= 1

    def test_no_finding_with_csrf_token(self, source_dir):
        code = 'csrf = CSRFProtect(app)\n@app.route("/update", methods=["POST"])\ndef update():\n    return process()\n'
        (source_dir / "app.py").write_text(code)
        result = check_input_validation(str(source_dir))
        csrf = [f for f in result["findings"] if f["category"] == "CWE-352"]
        assert len(csrf) == 0


# === Deserialization Patterns (CWE-502) ===

class TestDeserializationPatterns:
    """Tests for deserialization regex detection."""

    def test_detects_pickle_loads(self):
        line = "data = pickle.loads(user_data)"
        assert any(p.search(line) for p in DESERIALIZATION_PATTERNS)

    def test_detects_yaml_load(self):
        line = "config = yaml.load(data)"
        assert any(p.search(line) for p in DESERIALIZATION_PATTERNS)

    def test_no_false_positive_safe_load(self):
        line = "config = yaml.safe_load(data)"
        assert not any(p.search(line) for p in DESERIALIZATION_PATTERNS)


class TestCheckDeserialization:
    """Tests for the deserialization check in input validation skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_pickle(self, source_dir):
        code = "import pickle\ndef load(data):\n    return pickle.loads(data)\n"
        (source_dir / "loader.py").write_text(code)
        result = check_input_validation(str(source_dir))
        deser = [f for f in result["findings"] if f["category"] == "CWE-502"]
        assert len(deser) >= 1

    def test_no_finding_safe_loader(self, source_dir):
        code = "import yaml\ndef load(data):\n    return yaml.safe_load(data)\n"
        (source_dir / "loader.py").write_text(code)
        result = check_input_validation(str(source_dir))
        deser = [f for f in result["findings"] if f["category"] == "CWE-502"]
        assert len(deser) == 0


# === NULL Pointer Dereference (CWE-476) ===

class TestNullDerefPatterns:
    """Tests for NULL pointer dereference regex detection."""

    def test_detects_go_method_call(self):
        line = "    val := obj.GetItem()"
        assert NULL_DEREF_PATTERNS[0].search(line)


class TestCheckNullDeref:
    """Tests for the null deref check in resource skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_null_deref(self, source_dir):
        code = "package main\n\nfunc process() {\n    val := obj.GetItem()\n    val.Use()\n}\n"
        (source_dir / "ptr.go").write_text(code)
        result = check_resource_management(str(source_dir))
        null_deref = [f for f in result["findings"] if f["category"] == "CWE-476"]
        assert len(null_deref) >= 1

    def test_no_finding_with_nil_check(self, source_dir):
        code = "package main\n\nfunc process() {\n    val := obj.GetItem()\n    if val != nil {\n        val.Use()\n    }\n}\n"
        (source_dir / "safe.go").write_text(code)
        result = check_resource_management(str(source_dir))
        null_deref = [f for f in result["findings"] if f["category"] == "CWE-476"]
        assert len(null_deref) == 0


# === Unbounded Allocation (CWE-770) ===

class TestUnboundedAllocPatterns:
    """Tests for unbounded allocation regex detection."""

    def test_detects_unbounded_go_slice(self):
        line = "    items := make([]string, 0)"
        assert any(p.search(line) for p in UNBOUNDED_ALLOC_PATTERNS)


class TestCheckUnboundedAlloc:
    """Tests for the unbounded alloc check in resource skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_unbounded_alloc(self, source_dir):
        code = "package main\n\nfunc collect() {\n    items := make([]string, 0)\n}\n"
        (source_dir / "alloc.go").write_text(code)
        result = check_resource_management(str(source_dir))
        alloc = [f for f in result["findings"] if f["category"] == "CWE-770"]
        assert len(alloc) >= 1

    def test_no_finding_with_capacity(self, source_dir):
        code = "package main\n\nfunc collect() {\n    max_size := 100\n    items := make([]string, 0)\n}\n"
        (source_dir / "safe.go").write_text(code)
        result = check_resource_management(str(source_dir))
        alloc = [f for f in result["findings"] if f["category"] == "CWE-770"]
        assert len(alloc) == 0


# === Sensitive Response (CWE-200) ===

class TestSensitiveResponsePatterns:
    """Tests for sensitive response regex detection."""

    def test_detects_internal_path_in_response(self):
        line = 'return Response(str(internal_path))'
        assert any(p.search(line) for p in SENSITIVE_RESPONSE_PATTERNS)


class TestCheckSensitiveResponse:
    """Tests for the sensitive response check in info exposure skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_sensitive_response(self, source_dir):
        code = "def error_handler(err):\n    return Response(str(internal_path))\n"
        (source_dir / "api.py").write_text(code)
        result = check_information_exposure(str(source_dir))
        sens = [f for f in result["findings"] if f["category"] == "CWE-200"]
        assert len(sens) >= 1


# === I/O Without Error Check (CWE-754) ===

class TestIOWithoutCheckPatterns:
    """Tests for I/O without error check regex detection."""

    def test_detects_open_without_check(self):
        line = "    data = open('file.txt')"
        assert any(p.search(line) for p in IO_WITHOUT_CHECK)


class TestCheckIOWithoutCheck:
    """Tests for the I/O without check in error handling skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_unchecked_io(self, source_dir):
        code = "def read_data():\n    data = open('file.txt').read()\n    return data\n"
        (source_dir / "io.py").write_text(code)
        result = check_error_handling(str(source_dir))
        io_findings = [f for f in result["findings"] if f["category"] == "CWE-754"]
        assert len(io_findings) >= 1

    def test_no_finding_with_try(self, source_dir):
        code = "def read_data():\n    try:\n        data = open('file.txt').read()\n    except IOError:\n        pass\n"
        (source_dir / "io.py").write_text(code)
        result = check_error_handling(str(source_dir))
        io_findings = [f for f in result["findings"] if f["category"] == "CWE-754"]
        assert len(io_findings) == 0


# === Deadlock (CWE-833) ===

class TestDeadlockPatterns:
    """Tests for deadlock regex detection."""

    def test_detects_lock_acquire(self):
        line = "    lock_a.acquire()"
        assert any(p.search(line) for p in LOCK_ACQUIRE)


class TestCheckDeadlock:
    """Tests for the deadlock check in concurrency skill."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_detects_nested_locks(self, source_dir):
        code = "import threading\nlock_a = threading.Lock()\nlock_b = threading.Lock()\ndef transfer():\n    lock_a.acquire()\n    lock_b.acquire()\n"
        (source_dir / "worker.py").write_text(code)
        result = check_concurrency(str(source_dir))
        deadlock = [f for f in result["findings"] if f["category"] == "CWE-833"]
        assert len(deadlock) >= 1


# === Configuration Tests ===

class TestCWEConfig:
    """Tests for CWE agent configuration."""

    def test_all_categories_complete(self):
        assert len(ALL_CATEGORIES) == 16
        assert "injection" in ALL_CATEGORIES
        assert "buffer_handling" in ALL_CATEGORIES
        assert "authentication" in ALL_CATEGORIES
        assert "cryptography" in ALL_CATEGORIES
        assert "input_validation" in ALL_CATEGORIES
        assert "resource_management" in ALL_CATEGORIES
        assert "information_exposure" in ALL_CATEGORIES
        assert "access_control" in ALL_CATEGORIES
        assert "error_handling" in ALL_CATEGORIES
        assert "concurrency" in ALL_CATEGORIES
        assert "web_security" in ALL_CATEGORIES
        assert "configuration" in ALL_CATEGORIES
        assert "dependency_security" in ALL_CATEGORIES
        assert "data_handling" in ALL_CATEGORIES
        assert "memory_safety" in ALL_CATEGORIES
        assert "catalog_generic" in ALL_CATEGORIES

    def test_agent_type_is_cwe(self):
        assert AGENT_INFO["type"] == "cwe"

    def test_agent_name(self):
        assert AGENT_INFO["name"] == "CWE Weakness Auditor"

    def test_config_schema_has_categories(self):
        assert "categories" in CONFIG_SCHEMA["properties"]

    def test_config_schema_enum_matches_categories(self):
        schema_enum = CONFIG_SCHEMA["properties"]["categories"]["items"]["enum"]
        assert schema_enum == ALL_CATEGORIES

    def test_skills_list_has_ten_entries(self):
        assert len(AGENT_INFO["skills"]) >= 10


# === Finding Format Tests ===

class TestFindingFormat:
    """Tests verifying finding dict structure."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        return tmp_path

    def test_finding_has_required_fields(self, source_dir):
        code = 'def get(uid):\n    q = f"SELECT * FROM users WHERE id = {uid}"\n'
        (source_dir / "db.py").write_text(code)
        result = check_injection(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        required = {"severity", "category", "title", "description", "file_path", "line_start", "line_end", "recommendation"}
        assert required.issubset(finding.keys()), f"Missing fields: {required - finding.keys()}"

    def test_category_format_is_cwe(self, source_dir):
        code = 'PASSWORD = "admin"\n'
        (source_dir / "config.py").write_text(code)
        result = check_authentication(str(source_dir))
        for f in result["findings"]:
            assert f["category"].startswith("CWE-"), f"Expected CWE-XXX, got {f['category']}"

    def test_severity_is_valid(self, source_dir):
        code = "void f() { char buf[10]; strcpy(buf, input); }\n"
        (source_dir / "buf.c").write_text(code)
        result = check_buffer_handling(str(source_dir))
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for f in result["findings"]:
            assert f["severity"] in valid_severities
