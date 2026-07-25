"""Regression tests for the 38-finding CWE-agent audit (2026-05-06).

One test per material correctness or false-positive fix. Each test
codifies the contract the audit established so future edits can't
silently regress."""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.memory_safety_check import _analyze_file as memory_analyze
from cwe_agent.skills.concurrency_check import _analyze_file as concurrency_analyze
from cwe_agent.skills.crypto_check import _check_hardcoded_key
from cwe_agent.skills.buffer_check import OOB_READ_PATTERNS, SAFE_SIZEOF_CHECK
from cwe_agent.skills.injection_check import SQL_INJECTION_PATTERNS
from cwe_agent.skills.input_validation_check import (
    NO_VALIDATION_PATTERNS, CSRF_PATTERNS, SAFE_XXE_PATTERNS,
)
from cwe_agent.skills.access_control_check import IDOR_PATTERNS
from cwe_agent.skills.dangerous_function_check import _C_STRING
from cwe_agent.skills.error_handling_check import BARE_EXCEPT_PATTERNS
from cwe_agent.skills.weak_entropy_check import _WEAK_RNG
from cwe_agent.skills.path_equivalence_check import _VARIANTS
from cwe_agent.skills.divide_by_zero_check import _strip_strings_and_comments
from cwe_agent.skills.plaintext_transmission_check import (
    check_plaintext_transmission,
)
from cwe_agent.skills.dependency_check import _spec_matches, _check_cve_match
from cwe_agent.skills.secret_scan.crypto_wallets import find_mnemonics
from cwe_agent.skills.secret_scan.cloud_providers import CLOUD_PATTERNS
from cwe_agent.skills.secret_scan.entropy import _is_high_entropy_secret
from cwe_agent.skills.secret_scan import pem_blocks


# ---------------------------------------------------------------------------
# Batch 1: critical correctness
# ---------------------------------------------------------------------------

class TestPerVariableLeakTracking:
    """#1 — `_check_memory_leak` no longer skips the whole file when ANY
    free() exists. A different free()d pointer doesn't release THIS
    allocation."""

    def test_unrelated_free_does_not_suppress_leak(self, tmp_path: Path) -> None:
        # Two distinct allocations; only `b` is freed. `a` should still
        # be flagged as leaking.
        src = tmp_path / "leak.c"
        src.write_text(
            "int main() {\n"
            "    char *a = malloc(64);\n"
            "    char *b = malloc(64);\n"
            "    free(b);\n"
            "    return 0;\n"
            "}\n"
        )
        findings: list[dict] = []
        memory_analyze(src, findings)
        leaks = [f for f in findings if "memory_leak" in f.get("check_id", "")]
        assert len(leaks) >= 1, f"expected leak finding for 'a', got {findings}"

    def test_freed_var_is_suppressed(self, tmp_path: Path) -> None:
        # When the bound variable IS freed, no leak finding for that
        # alloc — the per-variable tracking honors the matching free.
        src = tmp_path / "ok.c"
        src.write_text(
            "int main() {\n"
            "    char *p = malloc(64);\n"
            "    free(p);\n"
            "    return 0;\n"
            "}\n"
        )
        findings: list[dict] = []
        memory_analyze(src, findings)
        leaks = [f for f in findings if "memory_leak" in f.get("check_id", "")]
        assert len(leaks) == 0, f"freed variable should not flag, got {leaks}"


class TestPerSpawnLockTracking:
    """#2 — `_check_thread_no_sync` requires a lock-acquire shape near
    the spawn site, not just any "Lock" mention in the file."""

    def test_unrelated_lock_mention_does_not_suppress_finding(self, tmp_path: Path) -> None:
        # A function-name `lock_state` and an unrelated comment shouldn't
        # cancel the unsynchronised goroutine spawn far away.
        src = tmp_path / "race.go"
        body = (
            "package main\n"
            "import \"fmt\"\n"
            "// uses Lock terminology but no real sync primitive\n"
            "var lock_state = false\n"
            "\n"
        )
        # 50 lines of padding to push the spawn beyond the lock-mention scope
        body += "func helper() {}\n" * 50
        body += (
            "func race() {\n"
            "    go func() { fmt.Println(\"unsync\") }()\n"
            "}\n"
        )
        src.write_text(body)
        findings: list[dict] = []
        concurrency_analyze(src, findings)
        no_sync = [f for f in findings if "no_sync" in f.get("check_id", "")]
        assert len(no_sync) >= 1

    def test_nearby_real_lock_suppresses(self, tmp_path: Path) -> None:
        src = tmp_path / "ok.go"
        src.write_text(
            "package main\n"
            "import \"sync\"\n"
            "var mu sync.Mutex\n"
            "func ok() {\n"
            "    mu.Lock()\n"
            "    go func() { mu.Unlock() }()\n"
            "}\n"
        )
        findings: list[dict] = []
        concurrency_analyze(src, findings)
        no_sync = [f for f in findings if "no_sync" in f.get("check_id", "")]
        assert no_sync == []


class TestHardcodedKeyCWE321:
    """#3 — hardcoded crypto key category is CWE-321, not CWE-327."""

    def test_emits_cwe_321(self) -> None:
        findings: list[dict] = []
        _check_hardcoded_key(
            Path("/x.py"),
            'aes_key = "0123456789abcdef0123456789abcdef"',
            1, ("aes_key = \"0123456789abcdef0123456789abcdef\"",), findings,
        )
        assert len(findings) == 1
        assert findings[0]["category"] == "CWE-321"


class TestOOBReadNarrow:
    """#4 — OOB_READ no longer matches every `arr[i]`."""

    def test_no_match_on_plain_indexing(self) -> None:
        plain = "for (int i = 0; i < n; i++) { sum += arr[i]; }"
        for pattern in OOB_READ_PATTERNS:
            assert pattern.search(plain) is None, f"FP on plain: {pattern.pattern}"

    def test_match_on_tainted_input(self) -> None:
        tainted = "char c = buf[atoi(argv[1])];"
        assert any(p.search(tainted) for p in OOB_READ_PATTERNS)

    def test_match_on_compound_arithmetic(self) -> None:
        line = "int v = arr[i + offset];"
        assert any(p.search(line) for p in OOB_READ_PATTERNS)


# ---------------------------------------------------------------------------
# Batch 2: false-positive reduction
# ---------------------------------------------------------------------------

class TestSizeofCheckTight:
    """#9 — SAFE_SIZEOF_CHECK now requires sizeof as a memcpy arg."""

    def test_unrelated_sizeof_no_longer_suppresses(self) -> None:
        # `sizeof` mentioned in unrelated context shouldn't suppress.
        line = "memcpy(dst, src, n);   // sizeof(other_buf) is unrelated"
        assert SAFE_SIZEOF_CHECK.search(line) is None

    def test_real_sizeof_arg_still_suppresses(self) -> None:
        line = "memcpy(dst, src, sizeof(dst))"
        assert SAFE_SIZEOF_CHECK.search(line) is not None


class TestBIP39NeedsContext:
    """#22 — BIP-39 requires content cue OR wallet-shaped path."""

    SAMPLE = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    def test_prose_without_context_no_match(self) -> None:
        # No path, no context cue → no finding.
        out = find_mnemonics(self.SAMPLE)
        assert out == []

    def test_path_hint_triggers(self) -> None:
        out = find_mnemonics(self.SAMPLE, Path("src/wallet.py"))
        assert out  # at least one finding

    def test_content_cue_triggers(self) -> None:
        # Embedded `mnemonic =` keyword counts as context.
        text = f"mnemonic = {self.SAMPLE}"
        out = find_mnemonics(text)
        assert out


class TestEntropyHashesFiltered:
    """#34 — entropy detector skips SHA-* hashes and UUIDs."""

    def test_sha256_is_not_secret(self) -> None:
        sha = "a" * 64  # 64 hex chars
        assert _is_high_entropy_secret(sha) is False
        # Realistic hash with mixed hex
        h = "a3f2b9c8e0d4516789abcdef0123456789abcdef0123456789abcdef01234567"
        assert _is_high_entropy_secret(h) is False

    def test_uuid_is_not_secret(self) -> None:
        u = "550e8400-e29b-41d4-a716-446655440000"
        assert _is_high_entropy_secret(u) is False

    def test_random_token_still_secret(self) -> None:
        # Mixed-case alnum + symbols, exceeds threshold
        token = "k7Mq8rXp4Lz9YbAa3DcEhFgIjN5oP6QrSt8UvWxYz0123_abc"
        assert _is_high_entropy_secret(token) is True


class TestOpenAIKeyTight:
    """#23 — OpenAI sk- pattern is bounded to actual key shapes."""

    def test_sk_proj_long_matches(self) -> None:
        key = "sk-proj-" + "A" * 100
        pat = next(p.regex for p in CLOUD_PATTERNS if p.rule_id == "openai_api_key")
        assert pat.search(key) is not None

    def test_short_sk_does_not_match(self) -> None:
        # Generic 30-char `sk-` token (e.g. Stripe test) shouldn't match.
        key = "sk-test_abcdef0123456789abcdef0123"
        pat = next(p.regex for p in CLOUD_PATTERNS if p.rule_id == "openai_api_key")
        assert pat.search(key) is None


class TestPEMSafeContext:
    """#36 — PEM detector skips obvious documentation placeholders."""

    def test_placeholder_body_suppressed(self) -> None:
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "REDACTED\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        out = pem_blocks.find_pem_blocks(Path("README.md"), block)
        assert out == []

    def test_real_block_still_detected(self) -> None:
        # Sustained body with no placeholder marker — the existing tests
        # cover the positive path; we just sanity-check here.
        body = "\n".join("A" * 64 for _ in range(4))
        block = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
        out = pem_blocks.find_pem_blocks(Path("src/key.pem"), block)
        assert len(out) == 1


class TestDivideByZeroComments:
    """#12 — divide-by-zero ignores `/` inside strings and comments."""

    def test_url_in_string_stripped(self) -> None:
        line = 'url = "http://example.com/path/x" ; // comment with /y'
        cleaned = _strip_strings_and_comments(line)
        # All `/` inside strings/comments should be replaced by spaces.
        assert "//" not in cleaned
        assert "://" not in cleaned


# ---------------------------------------------------------------------------
# Batch 3: coverage gaps in existing skills
# ---------------------------------------------------------------------------

class TestSQLPercentFormatting:
    """#5 — SQL injection pattern matches `%` formatting."""

    def test_percent_format_matched(self) -> None:
        line = 'cur.execute("SELECT * FROM u WHERE id = %s" % user_input)'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_concat_still_matched(self) -> None:
        line = 'query = "SELECT * FROM u WHERE name = " + name'
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)


class TestInputAccessVariants:
    """#16 — non-bracket request access shapes are matched."""

    def test_dot_access(self) -> None:
        assert any(p.search("v = request.args.user_id") for p in NO_VALIDATION_PATTERNS)

    def test_get_method(self) -> None:
        assert any(p.search('v = request.GET.get("uid")') for p in NO_VALIDATION_PATTERNS)

    def test_request_json(self) -> None:
        assert any(p.search("body = request.json") for p in NO_VALIDATION_PATTERNS)


class TestCSRFFetch:
    """#17 — CSRF detector matches modern fetch / axios / xhr."""

    def test_fetch_post(self) -> None:
        line = 'fetch("/api/x", { method: "POST", body: data })'
        assert any(p.search(line) for p in CSRF_PATTERNS)

    def test_axios_put(self) -> None:
        line = 'axios.put("/api/x", payload)'
        assert any(p.search(line) for p in CSRF_PATTERNS)


class TestIDORDjango:
    """#18 — IDOR detector matches Django request.GET/POST."""

    def test_django_get(self) -> None:
        assert any(p.search('uid = request.GET["user_id"]') for p in IDOR_PATTERNS)

    def test_django_get_method(self) -> None:
        assert any(p.search('uid = request.GET.get("user_id")') for p in IDOR_PATTERNS)


class TestDangerousLibcAdded:
    """#19 — strdup, vsprintf, tmpnam etc. now flagged."""

    @pytest.mark.parametrize("fn", [
        "strdup", "strndup", "vsprintf", "tmpnam", "tempnam", "alloca", "getwd",
    ])
    def test_unsafe_libc(self, fn: str) -> None:
        line = f"char *p = {fn}(arg);"
        assert _C_STRING.search(line) is not None, fn


class TestBaseExceptionFlagged:
    """#20 — BaseException / catch(Throwable) are now flagged."""

    def test_base_exception(self) -> None:
        line = "        except BaseException:"
        assert any(p.search(line) for p in BARE_EXCEPT_PATTERNS)

    def test_throwable(self) -> None:
        line = "        catch (Throwable t)"
        assert any(p.search(line) for p in BARE_EXCEPT_PATTERNS)


class TestTimeAsSeed:
    """#35 — time-based RNG seeds detected."""

    @pytest.mark.parametrize("line", [
        "srand(time(NULL));",
        "Random r = new Random(System.currentTimeMillis());",
        "random.seed(time.time())",
        "mt_srand(time(NULL));",
    ])
    def test_seed_pattern(self, line: str) -> None:
        assert _WEAK_RNG.search(line) is not None


class TestSemanticXXE:
    """#30 — XXE safe-pattern requires real disabling, not just keyword
    presence in a comment."""

    def test_real_disable(self) -> None:
        line = 'parser = XMLParser(resolve_entities=False)'
        assert SAFE_XXE_PATTERNS.search(line) is not None

    def test_comment_keyword_no_match(self) -> None:
        line = '# safe: defusedxml mention but no real disabling'
        assert SAFE_XXE_PATTERNS.search(line) is None

    def test_defusedxml_import_matches(self) -> None:
        line = 'from defusedxml.ElementTree import parse'
        assert SAFE_XXE_PATTERNS.search(line) is not None


# ---------------------------------------------------------------------------
# Batch 4: new CWE-class detection
# ---------------------------------------------------------------------------

class TestPlaintextTransmission:
    """#6 — CWE-319 detector emits findings."""

    def test_userinfo_credentials(self, tmp_path: Path) -> None:
        src = tmp_path / "main.py"
        src.write_text('URL = "http://admin:hunter2@db.example.com:5432/data"\n')
        out = check_plaintext_transmission(str(tmp_path))
        ids = [f["check_id"] for f in out["findings"]]
        assert any("plaintext_http_credentials" in i for i in ids)

    def test_disabled_verify(self, tmp_path: Path) -> None:
        src = tmp_path / "main.py"
        src.write_text('r = requests.get("https://api.example.com", verify=False)\n')
        out = check_plaintext_transmission(str(tmp_path))
        ids = [f["check_id"] for f in out["findings"]]
        assert any("disabled_tls_verification" in i for i in ids)

    def test_loopback_suppressed(self, tmp_path: Path) -> None:
        src = tmp_path / "main.py"
        src.write_text('REDIS_URL = "redis://127.0.0.1:6379/0"\n')
        out = check_plaintext_transmission(str(tmp_path))
        # No finding for loopback
        ids = [f["check_id"] for f in out["findings"]]
        assert not any("plaintext_scheme_url" in i for i in ids)


class TestKnownVulnDB:
    """#7 — dependency_check has a working CVE catalog."""

    def test_spec_matches_lt(self) -> None:
        assert _spec_matches("2.31.0", "<2.32.0") is True
        assert _spec_matches("2.32.0", "<2.32.0") is False

    def test_spec_matches_compatible(self) -> None:
        assert _spec_matches("1.4.5", "~=1.4") is True
        assert _spec_matches("2.0.0", "~=1.4") is False

    def test_real_cve_matches(self) -> None:
        # PyYAML <5.4 has CVE-2020-14343
        matches = _check_cve_match("3.13", "pypi", "pyyaml")
        assert matches, "PyYAML 3.13 should match the bundled CVE entry"
        assert any("CVE-2020-14343" in m["cve"] for m in matches)


class TestPathTraversalEncoded:
    """#8 — encoded path-traversal variants detected."""

    @pytest.mark.parametrize("payload", [
        "..%2f", "..%2F", "..%252f", "%2e%2e/", "%2e%2e%2f",
        "..%c0%af", "..%00", "..\\",
    ])
    def test_encoded_variant(self, payload: str) -> None:
        # _VARIANTS is (cwe_id, regex, label, severity)
        assert any(pat.search(payload) for _, pat, _, _ in _VARIANTS), payload


# ---------------------------------------------------------------------------
# Batch 5: misc
# ---------------------------------------------------------------------------

class TestDangerousFnSeverityTuning:
    """#33 — feature 0060: exec/os.system severity tuning moved to the injection
    skill together with ownership of command/code execution. dangerous_function
    now carries per-sink severity for memory-unsafe *library* functions:
    gets() has no safe bound (CWE-242, critical); the bounded-alternative
    string-handling family is CWE-676 high."""

    def test_gets_is_critical_242(self, tmp_path) -> None:
        from cwe_agent.skills.dangerous_function_check import check_dangerous_function
        (tmp_path / "v.c").write_text("void f(char *b){ gets(b); }\n")
        f = check_dangerous_function(str(tmp_path))["findings"][0]
        assert (f["category"], f["severity"]) == ("CWE-242", "critical")

    def test_strcpy_is_high_676(self, tmp_path) -> None:
        from cwe_agent.skills.dangerous_function_check import check_dangerous_function
        (tmp_path / "v.c").write_text(
            "void f(char *b, const char *s){ strcpy(b, s); }\n"
        )
        f = check_dangerous_function(str(tmp_path))["findings"][0]
        assert (f["category"], f["severity"]) == ("CWE-676", "high")
