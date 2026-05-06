"""Dedicated skill for CWE-319 (cleartext transmission of sensitive
information).

Flags three high-confidence shapes:

  1. HTTP URLs that include credentials in the userinfo part:
        http://user:pass@host/...
  2. Configuration / connection strings using plaintext schemes for
     services that have a TLS variant available:
        amqp://, ftp://, ldap://, mongodb://, mysql://, postgres://,
        redis://, smtp://, telnet://
     The skill flags these only when the URL appears in code (string
     literal or assignment) — not in plaintext docs/comments.
  3. Insecure transport-layer disabling at the API call site:
        verify=False on requests.* / httpx.*
        rejectUnauthorized: false on Node.js HTTPS / TLS calls
        InsecureSkipVerify: true on Go tls.Config

Suppress when the file path / surrounding context indicates test
fixtures, local-loopback addresses (127.0.0.1, localhost), or
documentation comments.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding


# ---------------------------------------------------------------------------
# Pattern set
# ---------------------------------------------------------------------------

# 1. HTTP URL with credentials in userinfo (RFC 3986 userinfo ABNF).
_HTTP_USERINFO = re.compile(
    r"\bhttp://[A-Za-z0-9._~%!$&'()*+,;=-]+:[A-Za-z0-9._~%!$&'()*+,;=-]+@",
    re.IGNORECASE,
)

# 2. Plaintext connection-string schemes whose TLS variant is widely
# available. The trailing `://` makes this insensitive to mentions of
# "redis" or "mysql" alone in prose. We REQUIRE that the URL appear in
# a string-literal-shaped context to keep scope tight; the line check
# catches lines that have a quoted URL.
_PLAINTEXT_SCHEME = re.compile(
    r"\b(amqp|ftp|ldap|mongodb|mysql|postgres(?:ql)?|redis|smtp|telnet|http)"
    r"://"
    r"(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|host\.docker\.internal)\b)"
    r"[A-Za-z0-9._~%-]+",
    re.IGNORECASE,
)

# 3. Disabled TLS / certificate verification.
_INSECURE_TRANSPORT = re.compile(
    r"\bverify\s*=\s*False\b"
    r"|\brejectUnauthorized\s*:\s*false\b"
    r"|\bInsecureSkipVerify\s*:\s*true\b"
    r"|\bSSL_VERIFY_NONE\b"
    r"|\bcurl(?:opt)?[_-]?ssl[_-]?verifypeer\s*[,=]\s*0\b"
)

# Suppression: lines that explicitly target loopback or are clearly
# part of test fixtures / examples.
_LOOPBACK_HINT = re.compile(
    r"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|host\.docker\.internal)\b",
    re.IGNORECASE,
)
_DOC_HINT = re.compile(r"^\s*(?:#|//|/\*|\*)")  # comment-only lines


# Languages where we run this skill. CWE-319 applies to any
# transport-aware code, but limiting to source-code extensions avoids
# scanning JSON/YAML config (which often legitimately stores plaintext
# scheme URLs that operators rotate via env-var substitution). For
# config files, a separate skill (config-secrets) covers the keying
# concern.
_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".go", ".java", ".rb", ".rs", ".php", ".cs",
    ".kt", ".scala", ".swift", ".cpp", ".cc", ".c", ".m",
})


def _classify(line: str) -> tuple[str, str, str] | None:
    """Return (rule_id, severity, title) for a CWE-319 match or None.

    Order matters: the userinfo URL is the most damaging shape (creds
    on the wire), so it ranks above plaintext-scheme alone.
    """
    if _HTTP_USERINFO.search(line):
        return ("plaintext_http_credentials", "critical",
                "Credentials in plaintext HTTP URL")
    if _INSECURE_TRANSPORT.search(line):
        return ("disabled_tls_verification", "high",
                "Disabled TLS / certificate verification")
    if _LOOPBACK_HINT.search(line):
        # Loopback addresses on plaintext schemes are usually intended
        # (dev / containerised dependencies). Don't flag.
        return None
    if _PLAINTEXT_SCHEME.search(line):
        return ("plaintext_scheme_url", "medium",
                "Plaintext connection string for a TLS-capable service")
    return None


def _build_finding(
    rule_id: str,
    severity: str,
    title: str,
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "severity": severity,
        "check_id": f"cwe.plaintext_transmission.{rule_id}",
        "category": "CWE-319",
        "title": title,
        "description": (
            f"Line {lineno} carries sensitive data over a non-encrypted "
            "transport (CWE-319). Eavesdroppers on any intermediate "
            "network hop can read the payload and any embedded "
            "credentials."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Use the TLS variant of the protocol (https://, amqps://, "
            "ftps://, ldaps://, mongodb+srv://, mysql with require_ssl, "
            "postgresql with sslmode=require, rediss://, smtps://, ssh:// "
            "instead of telnet://). Re-enable certificate verification."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, "319")


def _scan_line(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a single line for CWE-319 patterns."""
    if _DOC_HINT.match(line):
        return
    if COMMENT_INDICATORS.match(line):
        return
    classified = _classify(line)
    if classified is None:
        return
    rule_id, severity, title = classified
    findings.append(_build_finding(rule_id, severity, title, file_path, lineno, lines))


def _should_scan(file_path: Path) -> bool:
    if file_path.suffix.lower() not in _LANG_EXTENSIONS:
        return False
    if is_generated_file(file_path):
        return False
    if is_test_file(file_path):
        return False
    return True


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_line(line, lineno, path_str, lines, findings)


def check_plaintext_transmission(source_path: str) -> dict[str, Any]:
    """Scan source files for cleartext transmission of sensitive data
    (CWE-319)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_plaintext_transmission_tool = function_tool(check_plaintext_transmission)
