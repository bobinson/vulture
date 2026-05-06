"""Tests for `$VAR` reference suppression in credential detectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills._var_reference import (
    is_variable_reference,
    line_value_is_variable_ref,
)
from cwe_agent.skills.auth_check import _check_hardcoded_creds
from cwe_agent.skills.info_exposure_check import _check_cleartext_storage
from cwe_agent.skills.crypto_check import _check_hardcoded_key


# ---------------------------------------------------------------------------
# Pure regex tests
# ---------------------------------------------------------------------------

class TestIsVariableReference:
    @pytest.mark.parametrize("v", [
        "$VAR",
        "${VAR}",
        "${VAR:-default}",
        "%(SECRET)s",
        "{{ apiKey }}",
        "{{ .Values.apiKey }}",
        "<%= API_KEY %>",
        "$$ESCAPED",
    ])
    def test_variable_shapes_match(self, v: str) -> None:
        assert is_variable_reference(v), f"should match: {v!r}"

    @pytest.mark.parametrize("v", [
        "actually-a-real-secret-string",
        "sk_live_abcdef12345",
        "Bearer abc123",
        "",
        "$",        # bare dollar sign isn't a var reference
    ])
    def test_literal_secrets_dont_match(self, v: str) -> None:
        assert not is_variable_reference(v), f"should NOT match: {v!r}"


class TestLineValueIsVariableRef:
    @pytest.mark.parametrize("line", [
        'STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"',
        '--build-arg CONGRESS_API_KEY="$CONGRESS_API_KEY"',
        'PGPASSWORD="${POSTGRES_PASSWORD}"',
        "api_key: '${SECRET}'",
        "token: $TOKEN",
        'password = "$DB_PASSWORD"',
        "api_key: '%(SECRET_KEY)s'",
        "value: {{ .Values.apiKey }}",
    ])
    def test_var_ref_on_rhs_suppresses(self, line: str) -> None:
        assert line_value_is_variable_ref(line), f"should suppress: {line!r}"

    @pytest.mark.parametrize("line", [
        'password = "hunter2"',
        'api_key = "sk_live_realkey1234567890abcdef"',
        'TOKEN: "ghp_realtoken123"',
        # No assignment at all
        'just some prose mentioning password',
    ])
    def test_literal_secret_does_not_suppress(self, line: str) -> None:
        assert not line_value_is_variable_ref(line), f"should NOT suppress: {line!r}"


# ---------------------------------------------------------------------------
# End-to-end tests: detector functions actually skip $VAR lines
# ---------------------------------------------------------------------------

class TestAuthCheckSuppresses:
    def test_dollar_var_line_no_finding(self) -> None:
        line = '--build-arg STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"'
        findings: list[dict] = []
        _check_hardcoded_creds(
            Path("/x/.ci/jobs/k8s.yml"),
            line, 162, (line,), line, findings, {},
        )
        assert findings == [], "auth_check should not flag $VAR refs"

    def test_literal_secret_still_flagged(self) -> None:
        line = 'api_key = "sk_live_realsecret1234567890abcdef"'
        findings: list[dict] = []
        _check_hardcoded_creds(
            Path("/x/auth.py"),
            line, 5, (line,), line, findings, {},
        )
        assert len(findings) == 1
        assert findings[0]["category"] == "CWE-798"


class TestInfoExposureSuppresses:
    def test_pgpassword_var_no_finding(self) -> None:
        line = 'docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" toto-db'
        findings: list[dict] = []
        _check_cleartext_storage(
            Path("/x/.ci/deploy.yml"),
            line, 222, (line,), line, findings, {},
        )
        assert findings == [], "cleartext-storage should not flag $VAR pass-through"


class TestCryptoCheckSuppresses:
    def test_var_ref_in_aes_key(self) -> None:
        line = 'aes_key = "${AES_KEY}"'
        findings: list[dict] = []
        _check_hardcoded_key(
            Path("/x/crypto.py"),
            line, 1, (line,), findings,
        )
        assert findings == [], "crypto_check should not flag ${VAR} indirection"

    def test_literal_aes_key_still_flagged(self) -> None:
        line = 'aes_key = "0123456789abcdef0123456789abcdef"'
        findings: list[dict] = []
        _check_hardcoded_key(
            Path("/x/crypto.py"),
            line, 1, (line,), findings,
        )
        assert len(findings) == 1
        assert findings[0]["category"] == "CWE-321"
