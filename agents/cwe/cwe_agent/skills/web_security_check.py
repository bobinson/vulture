"""Web security vulnerability detection skill."""

import re
from dataclasses import dataclass
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.header_taint import header_taint_pattern
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-601: URL Redirection to Untrusted Site (Open Redirect)
OPEN_REDIRECT_PATTERNS = [
    re.compile(r"redirect\s*\(\s*(?:request|req)\.(?:args|params|query|GET)", re.IGNORECASE),
    re.compile(r"(?:res|response)\.redirect\s*\(\s*(?:req|request)\.", re.IGNORECASE),
    re.compile(r"http\.Redirect\([^,]+,\s*[^,]+,\s*r\.", re.IGNORECASE),
    # Anchored at both ends. Unanchored, this matched
    # `const hasProfileLocation = Boolean(userAddressData)` -- "Location"
    # inside the identifier, "user" inside the value. Shared with the xss
    # agent, which carried a byte-identical copy of the same defect.
    header_taint_pattern("Location"),
    re.compile(r"(?:redirect_to|return_to|next|url)\s*=\s*(?:request|req|params)", re.IGNORECASE),
]

SAFE_REDIRECT_PATTERNS = re.compile(
    r"(?:url_has_allowed_host|is_safe_url|validate_redirect|"
    r"allowed_hosts|whitelist|ALLOWED_REDIRECT|urlparse|"
    r"startswith\s*\(\s*['\"/])",
    re.IGNORECASE,
)

# CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
# Detection relies on matching cookie-setting calls and then checking context
# for HttpOnly via SAFE_COOKIE_PATTERNS (avoids broken negative lookaheads).
COOKIE_NO_HTTPONLY_PATTERNS = [
    re.compile(r"Set-Cookie:", re.IGNORECASE),
    re.compile(r"\.set_cookie\s*\(", re.IGNORECASE),
    re.compile(r"http\.SetCookie\s*\("),
    re.compile(r"(?:res|response)\.cookie\s*\(", re.IGNORECASE),
]

SAFE_COOKIE_PATTERNS = re.compile(
    r"(?:HttpOnly|httponly|http_only|httpOnly\s*[:=]\s*[Tt]rue)",
    re.IGNORECASE,
)

# CWE-384: Session Fixation
SESSION_FIXATION_PATTERNS = [
    re.compile(r"session\[.*\]\s*=.*(?:request|req|params|input)", re.IGNORECASE),
    re.compile(r"session\.(?:set|put|setAttribute)\s*\(.*(?:request|req|user)", re.IGNORECASE),
]

SAFE_SESSION_PATTERNS = re.compile(
    r"(?:regenerate|rotate|new_session|invalidate|session\.clear|flush)",
    re.IGNORECASE,
)

# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure'
COOKIE_NO_SECURE_PATTERNS = [
    re.compile(r"\.set_cookie\s*\("),
    re.compile(r"http\.SetCookie\s*\("),
    re.compile(r"(?:res|response)\.cookie\s*\("),
    re.compile(r"Set-Cookie:"),
]

SAFE_SAMESITE_PATTERNS = re.compile(
    # CWE-1275 is NOT an "attribute absent" check like its siblings: SameSite=None
    # is present AND vulnerable. Only strict/lax are safe, so presence alone must
    # never suppress. A predicate copied from CWE-1004/614 passes on the worst case.
    r"same[_-]?site\s*[:=]\s*['\"]?(?:strict|lax)\b",
    re.IGNORECASE,
)

SAFE_SECURE_PATTERNS = re.compile(
    r"(?:secure\s*[:=]\s*[Tt]rue|[;,]\s*[Ss]ecure\b|__Secure-|__Host-)",
    re.IGNORECASE,
)

@dataclass(frozen=True)
class CookieAttributeSpec:
    """One missing-cookie-attribute check, as data.

    CWE-1004 and CWE-614 were near-identical functions differing only in these
    fields; a third hand-written copy for CWE-1275 would have made the
    duplication threefold. ``adaptive_window`` is per-spec deliberately: CWE-1004
    needs the call-block window, and pinning CWE-614 to the fixed ±3 window keeps
    its behaviour byte-identical through this refactor.

    ``fields`` holds the static finding body and MUST spell its category as a
    literal ``"category": "CWE-N"``. The coverage attestation
    (``report_coverage._CATEGORY_LITERAL_RE``) discovers emitted CWEs by scanning
    skill source for exactly that form, so an f-string here would silently drop
    the CWE from ``VERIFIED_CWES.md`` while detection kept working — a coverage
    under-claim, which is the one direction that document exists to prevent.
    """

    fields: dict
    triggers: tuple[re.Pattern, ...]
    safe: re.Pattern
    adaptive_window: bool

    @property
    def cwe(self) -> str:
        """Bare id for ``enrich_finding``, derived so it cannot drift."""
        return self.fields["category"].removeprefix("CWE-")


COOKIE_ATTRIBUTE_SPECS: tuple[CookieAttributeSpec, ...] = (
    CookieAttributeSpec(
        fields={
            "category": "CWE-1004",
            "check_id": "cwe.web_security.cookie_no_httponly",
            "title": "Cookie without HttpOnly flag",
            "description": "Cookie set without HttpOnly protection at line {line}",
            "recommendation": "Set HttpOnly flag on cookies to prevent XSS cookie theft",
        },
        triggers=tuple(COOKIE_NO_HTTPONLY_PATTERNS),
        safe=SAFE_COOKIE_PATTERNS,
        adaptive_window=True,
    ),
    CookieAttributeSpec(
        fields={
            "category": "CWE-614",
            "check_id": "cwe.web_security.cookie_no_secure",
            "title": "Cookie without Secure flag",
            "description": "Cookie set without Secure flag at line {line}",
            "recommendation": "Set Secure flag on cookies to prevent transmission over HTTP",
        },
        triggers=tuple(COOKIE_NO_SECURE_PATTERNS),
        safe=SAFE_SECURE_PATTERNS,
        adaptive_window=False,
    ),
    CookieAttributeSpec(
        fields={
            "category": "CWE-1275",
            "check_id": "cwe.web_security.cookie_improper_samesite",
            "title": "Sensitive cookie with improper SameSite attribute",
            "description": (
                "Cookie set without SameSite=Strict/Lax at line {line}; it is sent "
                "on cross-site requests, enabling CSRF-style forced actions"
            ),
            "recommendation": (
                "Set SameSite=Strict (or Lax) on session cookies. SameSite=None is "
                "only safe when the cross-site use is deliberate and Secure is set"
            ),
        },
        triggers=tuple(COOKIE_NO_HTTPONLY_PATTERNS),
        safe=SAFE_SAMESITE_PATTERNS,
        adaptive_window=True,
    ),
)


# CWE-113: HTTP Response Splitting (CRLF Injection)
CRLF_PATTERNS = [
    re.compile(r"(?:header|Header)\s*\(.*(?:request|req|params|input|user)", re.IGNORECASE),
    re.compile(r"(?:add_header|set_header|setHeader|w\.Header\(\)\.Set)\s*\(.*(?:request|req|params|input)", re.IGNORECASE),
    re.compile(r"(?:response|res)\.headers?\[.*\]\s*=.*(?:request|req|params)", re.IGNORECASE),
]

SAFE_CRLF_PATTERNS = re.compile(
    r"(?:strip|replace|sanitize|escape|encode|\\r|\\n|CRLF)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")


def check_web_security(source_path: str) -> dict:
    """Check for web security vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of web security issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if _skip_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _skip_file(path: Path) -> bool:
    """Generated, test, prose and tabular files are not code under review."""
    if is_generated_file(path) or is_test_file(path):
        return True
    return _is_prose_or_tabular(path)


def _is_prose_or_tabular(path: Path) -> bool:
    """Skip documentation and tabular data (P7).

    ``default_extensions()`` reaches ``.md/.rst/.adoc/.txt/.csv/.tsv``, and
    ``COMMENT_INDICATORS`` does not match markdown body text — so a fenced
    Electron-security snippet in a README, or a cookie tutorial, reads as
    executable source. Every pattern in this module is a code idiom, so a
    mention in prose is never an instance of it.
    """
    return is_prose_file(path) or path.suffix.lower() in _TABULAR_SUFFIXES


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for web security patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    active = _active_lines(lines)
    _scan_lines(file_path, lines, active, findings)
    # File-scoped rules run AFTER the per-line pass: CWE-539 keys off whether
    # CWE-1004/614/1275 already claimed the line (P5 row stacking).
    for rule in _FILE_RULES:
        rule(file_path, lines, active, findings)


def _active_lines(lines: list[str]) -> list[tuple[int, str]]:
    """1-indexed (line_num, line) pairs that survive the module's guards."""
    return [
        (n, line) for n, line in enumerate(lines, start=1) if not _is_guarded(line)
    ]


def _is_guarded(line: str) -> bool:
    """Comment, import, or another scanner's own pattern definition."""
    if COMMENT_INDICATORS.match(line) or IMPORT_LINE.match(line):
        return True
    return bool(SCANNER_DEF_LINE.search(line))


def _scan_lines(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """Per-line checks (CWE-601 / 384 / 113 / 1004 / 614 / 1275)."""
    for line_num, line in active:
        _check_open_redirect(file_path, line, line_num, lines, findings)
        _check_session_fixation(file_path, line, line_num, lines, findings)
        _check_crlf_injection(file_path, line, line_num, lines, findings)
        for spec in COOKIE_ATTRIBUTE_SPECS:
            _check_cookie_attribute(spec, file_path, line, line_num, lines, findings)


def _check_open_redirect(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-601 open redirect."""
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_REDIRECT_PATTERNS.search(context):
        return
    for pattern in OPEN_REDIRECT_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.web_security.open_redirect",
                "category": "CWE-601",
                "title": "Open redirect vulnerability",
                "description": f"User-controlled redirect target at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate redirect URLs against an allowlist of trusted hosts",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "601"))
            return


def _cookie_context(line: str, lines: list[str], line_num: int, adaptive: bool) -> str:
    """Window the cookie call for attribute lookup.

    ``adaptive`` extends forward through the closing paren (12-line cap) when the
    line opens a multi-line call. A fixed ±3 window missed `httponly=True` on a
    6th line and produced false positives, which is why CWE-1004 needs this;
    CWE-614 keeps the fixed window so P6 changes none of its behaviour.
    """
    if adaptive and _has_unmatched_open_paren(line):
        end = _find_call_close(lines, line_num - 1, max_lines=12)
        return "\n".join(lines[max(0, line_num - 1):end])
    return "\n".join(lines[max(0, line_num - 3):min(len(lines), line_num + 3)])


def _check_cookie_attribute(
    spec: "CookieAttributeSpec", file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Report ``spec``'s CWE when a cookie call lacks a safe attribute value.

    One routine for CWE-1004 / CWE-614 / CWE-1275. The three differed only in
    their trigger list, safe-pattern and copy, so they are data (see
    ``COOKIE_ATTRIBUTE_SPECS``) rather than three near-identical functions.
    """
    if not any(p.search(line) for p in spec.triggers):
        return
    if spec.safe.search(_cookie_context(line, lines, line_num, spec.adaptive_window)):
        return
    finding = {
        **spec.fields,
        "severity": "medium",
        "description": spec.fields["description"].format(line=line_num),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "code_snippet": extract_snippet(lines, line_num),
    }
    findings.append(enrich_finding(finding, spec.cwe))


def _has_unmatched_open_paren(line: str) -> bool:
    """True when the line has more `(` than `)` — a multi-line call start."""
    return line.count("(") > line.count(")")


def _find_call_close(lines: list[str], start_idx: int, max_lines: int = 12) -> int:
    """Return the (exclusive) line index where parens balance.

    Used to extend a multi-line call's context window through its full
    argument list. Caps at ``max_lines`` so a forgotten `)` can't make
    the whole file the "context".
    """
    return _find_block_close(lines, start_idx, "(", ")", max_lines)


def _find_block_close(
    lines: list[str], start_idx: int, opener: str, closer: str, max_lines: int,
) -> int:
    """Return the (exclusive) line index where ``opener``/``closer`` balance.

    One walker for both delimiter families: parens for a multi-line call
    (CWE-1004's cookie context) and braces for a handler body (CWE-940). Caps at
    ``max_lines`` so an unbalanced file can't make the whole file the "context".
    """
    depth = 0
    end = min(start_idx + max_lines, len(lines))
    for i in range(start_idx, end):
        depth += lines[i].count(opener) - lines[i].count(closer)
        if depth <= 0 and i > start_idx:
            return i + 1
    return end


def _check_session_fixation(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-384 session fixation."""
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SESSION_PATTERNS.search(context):
        return
    for pattern in SESSION_FIXATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.web_security.session_fixation",
                "category": "CWE-384",
                "title": "Potential session fixation",
                "description": f"Session populated from user input without regeneration at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Regenerate session ID after authentication or privilege change",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "384"))
            return


def _check_crlf_injection(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-113 HTTP response splitting."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_CRLF_PATTERNS.search(context):
        return
    for pattern in CRLF_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.web_security.crlf_injection",
                "category": "CWE-113",
                "title": "HTTP response splitting (CRLF injection)",
                "description": f"User input in HTTP header at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Strip CR/LF characters from user input before placing in headers",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "113"))
            return


# ══════════════════════════════════════════════════════════════════════════
# Feature 0070 P7 — web-security group.
#
# Eight file-scoped rules. They live behind ``_FILE_RULES`` (one uniform
# signature) rather than inside the per-line loop because several of them are
# capped at one row per file, and CWE-539 must observe what CWE-1004/614/1275
# already claimed — skill findings are NOT deduplicated against each other
# (P5), so a child specialisation has to suppress its parent itself.
#
# Every ``_FIELDS`` dict spells its category as a LITERAL ``"category":
# "CWE-N"``: ``report_coverage._CATEGORY_LITERAL_RE`` discovers emitted CWEs by
# scanning skill source for exactly that form, so an f-string would keep
# detection working while the attestation denied the CWE existed.
# ══════════════════════════════════════════════════════════════════════════

# Tabular data joins prose in the file-level skip: `.csv`/`.tsv` are in
# WHITELIST_EXTENSIONS and carry no code.
_TABULAR_SUFFIXES = frozenset({".csv", ".tsv"})

# Bundled/minified single-line chunks defeat every line-scoped predicate and
# report every hit at the same line. Cap borrowed from signatures/detector.py.
_MAX_LINE_LEN = 600


def _capped(line: str) -> str:
    """`line`, or "" when it is bundle-shaped (over the 600-char cap)."""
    return "" if len(line) > _MAX_LINE_LEN else line


def _emit(
    findings: list[dict], fields: dict, file_path: Path, line_num: int,
    lines: list[str], severity: str,
) -> None:
    """Append one finding built from a literal-category ``fields`` table."""
    finding = {
        **fields,
        "severity": severity,
        "description": fields["description"].format(line=line_num),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "code_snippet": extract_snippet(lines, line_num),
    }
    findings.append(enrich_finding(finding, fields["category"].removeprefix("CWE-")))


# ── CWE-749: Exposed Dangerous Method or Function ──────────────────────────
# A JavaScript bridge (Android WebView) or an Electron renderer with node /
# remote access enabled hands host-privileged methods to web content.
#
# `@JavascriptInterface` is deliberately NOT an anchor. Since API 17 the
# annotation is the HARDENING mechanism (before it, every public method of a
# bound object was callable from the page), so treating its presence as the
# weakness reports bridge classes that are never bound and reads as penalising
# the safer form. It may corroborate, never trigger.
# A method receiver (`webView.addJavascriptInterface(`) is the ONLY real form,
# so the lookbehind must exclude word characters but NOT the dot.
_WEBVIEW_BRIDGE = re.compile(r"(?<![\w$])addJavascriptInterface\s*\(")
_ELECTRON_UNSAFE_HIGH = re.compile(
    r"\bnodeIntegration(?:InWorker|InSubFrames)?\s*:\s*true"
    r"|\bcontextIsolation\s*:\s*false"
    r"|\benableRemoteModule\s*:\s*true"
    r"|\bwebSecurity\s*:\s*false"
    r"|\ballowRunningInsecureContent\s*:\s*true"
)
_ELECTRON_UNSAFE_MED = re.compile(r"\bsandbox\s*:\s*false")
_WEBVIEW_SUFFIXES = frozenset({".java", ".kt"})
_ELECTRON_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_DOC_PATH_SEGMENT = re.compile(
    r"(?:^|/)(?:docs?|examples?|samples?|demo)(?:/|$)", re.IGNORECASE
)

_EXPOSED_METHOD_FIELDS = {
    "category": "CWE-749",
    "check_id": "cwe.web_security.exposed_dangerous_method",
    "title": "Dangerous host method exposed to web content",
    "description": (
        "Web content is granted host-privileged access at line {line} "
        "(JavaScript bridge, or renderer with node/remote access enabled)"
    ),
    "recommendation": (
        "Drop the bridge, or keep contextIsolation enabled and expose a "
        "minimal, explicitly enumerated API through a preload script"
    ),
}


def _check_exposed_dangerous_method(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """CWE-749 — one row per file (a bridge is a per-file property)."""
    if _DOC_PATH_SEGMENT.search(file_path.as_posix()):
        return
    hit = _first_spec_match(active, _bridge_specs(file_path))
    if hit is None:
        return
    _emit(findings, _EXPOSED_METHOD_FIELDS, file_path, hit[0], lines, hit[1])


def _bridge_specs(file_path: Path) -> tuple[tuple[re.Pattern, str], ...]:
    """Per-language anchors. An arm only runs on a dialect that has it."""
    suffix = file_path.suffix.lower()
    if suffix in _WEBVIEW_SUFFIXES:
        return ((_WEBVIEW_BRIDGE, "high"),)
    if suffix in _ELECTRON_SUFFIXES:
        return ((_ELECTRON_UNSAFE_HIGH, "high"), (_ELECTRON_UNSAFE_MED, "medium"))
    return ()


def _first_spec_match(
    active: list[tuple[int, str]], specs: tuple[tuple[re.Pattern, str], ...],
) -> tuple[int, str] | None:
    """First (line, severity) hit, severity-major so `high` cannot be masked."""
    for pattern, severity in specs:
        for line_num, line in active:
            if pattern.search(_capped(line)):
                return line_num, severity
    return None


# CWE-1022 (window.open / target=_blank without noopener) is DELIBERATELY
# ABSENT. It was implemented, measured, and reverted: all 5 rows on a real
# tree were false (same-origin `window.open` of a generated document,
# anchors to fixed trusted hosts), and modern browsers imply noopener for
# `target=_blank`. Do not re-propose; see TestWindowOpenerStaysKilled.


# ── Cookie name analysis, shared by CWE-315 and CWE-539 ────────────────────
# The subject is the cookie NAME argument, not the line: a sensitive token
# anywhere on a cookie-setting line says nothing about what the cookie holds.
_COOKIE_NAME_SINKS = (
    re.compile(r"(?:res|resp|response|reply)\s*\.\s*cookie\s*\(\s*['\"]([\w.\-]+)['\"]"),
    re.compile(r"\.set_cookie\s*\(\s*['\"]([\w.\-]+)['\"]"),
    re.compile(r"\bsetcookie\s*\(\s*['\"]([\w.\-]+)['\"]", re.IGNORECASE),
    re.compile(r"\bcookies\s*\.\s*set\s*\(\s*['\"]([\w.\-]+)['\"]", re.IGNORECASE),
    re.compile(r"\bnew\s+Cookie\s*\(\s*['\"]([\w.\-]+)['\"]"),
    re.compile(r"Set-Cookie:\s*([\w.\-]+)\s*=", re.IGNORECASE),
)

# Single tokens plus adjacent-token JOINS, so `credit_card` / `privateKey`
# match while `card` or `key` alone never do.
_SENSITIVE_NAME_TOKENS = frozenset({
    "password", "passwd", "pwd", "passphrase", "secret", "ssn", "cvv", "cvc",
    "iban", "creditcard", "cardnumber", "privatekey", "securityanswer",
    "securitycode", "apikey",
})
# CWE-539 is about persistence, so session/auth material joins the set: a
# long-lived "remember me" credential is exactly the weakness.
_PERSISTENT_SENSITIVE_TOKENS = _SENSITIVE_NAME_TOKENS | frozenset({
    "session", "sessionid", "sid", "token", "jwt", "auth", "authtoken",
    "remembertoken", "remember", "refresh", "refreshtoken", "accesstoken",
})

# Password-WORKFLOW names store no password. Measured: `password_changed_at`
# and `x-pwd-reset` both satisfy a bare delimiter-bounded token test, and
# workflow cookies vastly outnumber genuine cleartext-password cookies.
_COOKIE_NAME_MODIFIER = re.compile(
    r"reset|chang(?:e|ed|ing)|expir(?:e|ed|y)|updat(?:e|ed)|policy|step|stage"
    r"|prompt|attempt|last|hint|requir(?:e|ed)|strength|length|min|max|count"
    r"|flag|shown|visible|verified|confirm(?:ed)?|at$|ts$",
    re.IGNORECASE,
)
_COOKIE_NAME_SAFE = re.compile(r"csrf|xsrf|(?:^|[_\-.])(?:hash|hashed|digest|id)$", re.IGNORECASE)
_COOKIE_VALUE_PROTECTED = re.compile(
    r"encrypt|cipher|\bAES\b|seal|bcrypt|argon2|scrypt|pbkdf2"
    r"|clearCookie|deleteCookie|removeCookie|unset",
    re.IGNORECASE,
)

_CLEARTEXT_COOKIE_FIELDS = {
    "category": "CWE-315",
    "check_id": "cwe.web_security.cleartext_cookie_payload",
    "title": "Sensitive information stored in a cookie in cleartext",
    "description": (
        "The cookie set at line {line} is named for a secret, so its CONTENTS "
        "(not a missing attribute) travel to the client unprotected"
    ),
    "recommendation": (
        "Keep the secret server-side and store an opaque session reference in "
        "the cookie; never place a password, PAN or key in cookie state"
    ),
}


def _cookie_name(line: str) -> str | None:
    """The cookie name argument of a cookie-setting call, if any."""
    for pattern in _COOKIE_NAME_SINKS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def _name_tokens(name: str) -> list[str]:
    """Delimiter- and camelCase-split lowercase tokens of a cookie name."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def _has_sensitive_token(tokens: list[str], token_set: frozenset[str]) -> bool:
    """Token equality (never substring) plus adjacent-token joins."""
    words = set(tokens) | {a + b for a, b in zip(tokens, tokens[1:])}
    return not words.isdisjoint(token_set)


def _check_cleartext_cookie(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """CWE-315 — cleartext sensitive information in a cookie's payload."""
    for line_num, line in active:
        name = _cookie_name(line)
        if name is None or not _is_cleartext_sensitive(name, line):
            continue
        _emit(findings, _CLEARTEXT_COOKIE_FIELDS, file_path, line_num, lines, "medium")


def _is_cleartext_sensitive(name: str, line: str) -> bool:
    """Sensitive name, minus the workflow/hashed/encrypted carve-outs."""
    if _COOKIE_VALUE_PROTECTED.search(line) or _COOKIE_NAME_SAFE.search(name):
        return False
    if _COOKIE_NAME_MODIFIER.search(name):
        return False
    return _has_sensitive_token(_name_tokens(name), _SENSITIVE_NAME_TOKENS)


# ── CWE-539: persistent cookie containing sensitive information ────────────
# The discriminator is lifetime MAGNITUDE, not the presence of a lifetime. A
# bounded `maxAge` on a session cookie is the RECOMMENDED shape; flagging it
# would report the advice as the defect.
_MAXAGE_NUM = re.compile(r"(max[_-]?age)\s*[:=]\s*(\d+)", re.IGNORECASE)
_LONG_EXPIRY = re.compile(
    r"Max-Age=\d{7,}"
    r"|Date\.now\(\)\s*\+\s*\d{10,}"
    r"|timedelta\(\s*days\s*=\s*(?:[3-9]\d|\d{3,})"
    r"|AddDate\(\s*[1-9]",
    re.IGNORECASE,
)
_THIRTY_DAYS_SEC = 2_592_000
_THIRTY_DAYS_MS = 2_592_000_000
_PERSISTENT_NAME_EXCLUDE = re.compile(
    r"csrf|xsrf|consent|locale|lang|theme|cart|prefs"
    r"|(?:^|[_\-.])(?:hash|hashed|digest)$",
    re.IGNORECASE,
)
_COOKIE_ATTR_CHECK_IDS = frozenset(
    spec.fields["check_id"] for spec in COOKIE_ATTRIBUTE_SPECS
)

_PERSISTENT_COOKIE_FIELDS = {
    "category": "CWE-539",
    "check_id": "cwe.web_security.persistent_sensitive_cookie",
    "title": "Sensitive cookie persisted for a long lifetime",
    "description": (
        "The credential-bearing cookie at line {line} is persisted well beyond "
        "a session (30+ days), so it survives on disk for reuse or theft"
    ),
    "recommendation": (
        "Keep credential cookies session-scoped, or issue a rotating, "
        "revocable remember-me token instead of a long-lived credential"
    ),
}


def _check_persistent_cookie(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """CWE-539 — one row per file, and never stacked on its own siblings.

    A line that already produced CWE-1004/614/1275 is skipped: skill findings
    are not cross-deduplicated, so without this one `res.cookie(...)` call
    yields four rows.
    """
    claimed = _lines_claimed_by_cookie_attributes(file_path, findings)
    for line_num, line in active:
        if line_num in claimed:
            continue
        if not _is_persistent_sensitive_cookie(line, line_num, lines):
            continue
        _emit(findings, _PERSISTENT_COOKIE_FIELDS, file_path, line_num, lines, "low")
        return


def _lines_claimed_by_cookie_attributes(
    file_path: Path, findings: list[dict],
) -> set[int]:
    """Lines on which CWE-1004/614/1275 already reported this file."""
    path = str(file_path)
    return {
        f["line_start"] for f in findings
        if f["file_path"] == path and f["check_id"] in _COOKIE_ATTR_CHECK_IDS
    }


def _is_persistent_sensitive_cookie(
    line: str, line_num: int, lines: list[str],
) -> bool:
    """Sensitive cookie name AND a lifetime past the 30-day threshold."""
    name = _cookie_name(line)
    if name is None or _PERSISTENT_NAME_EXCLUDE.search(name):
        return False
    if not _has_sensitive_token(_name_tokens(name), _PERSISTENT_SENSITIVE_TOKENS):
        return False
    return _is_long_lifetime(_cookie_context(line, lines, line_num, True))


def _is_long_lifetime(text: str) -> bool:
    """True when a persistence attribute exceeds ~30 days."""
    if _LONG_EXPIRY.search(text):
        return True
    return any(
        _exceeds_lifetime(m.group(1), m.group(2))
        for m in _MAXAGE_NUM.finditer(text)
    )


def _exceeds_lifetime(key: str, digits: str) -> bool:
    """Seconds vs milliseconds, disambiguated by the attribute SPELLING.

    Digit count cannot do it: `maxAge: 3600000` is a one-hour JS lifetime (the
    recommended shape) and would clear a seconds threshold. The delimiter is
    the reliable signal — `max_age` / `Max-Age` are the seconds dialects
    (Python/Go/PHP/Set-Cookie), camelCase `maxAge` is JS milliseconds.
    """
    value = int(digits)
    if "_" in key or "-" in key:
        return value >= _THIRTY_DAYS_SEC
    return value >= _THIRTY_DAYS_MS


# ── CWE-940: unverified source of a communication channel ──────────────────
# A `window`-scoped `message` receiver with an inline handler that never looks
# at the origin. Plugin/webview envelopes are excluded: a Figma plugin iframe,
# a VS Code webview, an Office add-in and an extension page all receive at
# origin `null` BY DESIGN, so there is no origin to verify and the envelope
# field IS the platform contract. That shape was the only surviving
# window-scoped listener in the review corpus — 0 TP / 1 FP without it.
_WINDOW_MESSAGE_LISTENER = re.compile(
    r"\bwindow\s*\.\s*addEventListener\s*\(\s*['\"]message['\"]\s*,\s*"
    r"(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)"
    r"|\bwindow\s*\.\s*onmessage\s*=\s*"
    r"(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)"
)
_ORIGIN_CHECK = re.compile(
    r"\.origin\b|event\.source|\bsource\s*===|allowed_?origins|trusted_?origins",
    re.IGNORECASE,
)
_MESSAGE_ENVELOPE = re.compile(
    r"pluginMessage|acquireVsCodeApi|vscode\.postMessage|webkit\.messageHandlers"
    r"|chrome\.runtime|browser\.runtime|Office\.(?:context|onReady)"
    r"|figma\.(?:ui|showUI)|require\(['\"]ws['\"]\)|from\s+['\"]ws['\"]"
    r"|child_process"
)

_MESSAGE_ORIGIN_FIELDS = {
    "category": "CWE-940",
    "check_id": "cwe.web_security.unverified_message_origin",
    "title": "postMessage handler does not verify the sender",
    "description": (
        "The window `message` handler at line {line} never checks "
        "`event.origin` or `event.source`, so any frame can drive it"
    ),
    "recommendation": (
        "Compare event.origin against an explicit allowlist (and event.source "
        "against the expected frame) before acting on the payload"
    ),
}


def _check_message_origin(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """CWE-940 — one row per file."""
    if _MESSAGE_ENVELOPE.search("\n".join(lines)):
        return
    line_num = _first_unverified_listener(lines, active)
    if line_num is not None:
        _emit(findings, _MESSAGE_ORIGIN_FIELDS, file_path, line_num, lines, "medium")


def _first_unverified_listener(
    lines: list[str], active: list[tuple[int, str]],
) -> int | None:
    """First inline window `message` handler whose body ignores the origin."""
    for line_num, line in active:
        if not _WINDOW_MESSAGE_LISTENER.search(_capped(line)):
            continue
        if not _ORIGIN_CHECK.search(_handler_body(lines, line_num)):
            return line_num
    return None


def _handler_body(lines: list[str], line_num: int, max_lines: int = 40) -> str:
    """Brace-balanced handler body starting at ``line_num`` (capped)."""
    line = lines[line_num - 1]
    if line.count("{") <= line.count("}"):
        return line
    end = _find_block_close(lines, line_num - 1, "{", "}", max_lines)
    return "\n".join(lines[line_num - 1:end])


# ── CWE-784 / CWE-565: reliance on an untrusted cookie ─────────────────────
# One weakness split by the CWE hierarchy: 784 is literally "…in a Security
# Decision", i.e. the branch-anchored variant of 565. Splitting the READ side
# by that distinction makes the pair disjoint by construction — no cross-file
# bookkeeping, and nothing stacks on cookie-WRITE lines (which already carry
# CWE-1004 + 614 + 1275).
#
# SERVER-SIDE accessors only. `Cookies.get` (js-cookie) and hand-rolled
# `document.cookie` helpers are browser reads: an SPA choosing which nav items
# to render is not making a server-side authorization decision, and its honest
# label (CWE-602) is out of scope here.
_SERVER_COOKIE_ACCESSOR = (
    r"req(?:uest)?\.cookies|request\.COOKIES|\$_COOKIE|ctx\.cookies\.get"
    r"|cookies\(\)\.get|r\.Cookie|c\.Cookie|Request\.Cookies|cookies(?=\[\s*:)"
)
_PRIV_NAME = (
    r"is_?admin|isadmin|admin|roles?|is_?auth\w*|authenticated|logged_?in"
    r"|loggedin|user_?id|userid|uid|account_?id|priv\w*|access_?level"
    r"|is_?verified|superuser|impersonat\w*"
)
_HIGH_PRIV_NAME = re.compile(
    r"^(?:is_?admin|isadmin|admin|superuser|roles?|access_?level|priv\w*)$",
    re.IGNORECASE,
)


def _cookie_read_re(accessor: str) -> re.Pattern:
    """Compile `<accessor><connector><privileged name>`.

    The connector admits an intervening `.get(` because `req.cookies.get('role')`
    / `request.COOKIES.get('role')` is the dominant Express/Django form — a
    connector of only `[`, `(` or `.` silently misses it.
    """
    return re.compile(
        rf"(?<![\w$])(?:{accessor})"
        rf"\s*(?:\[\s*:?\s*|\(\s*|\.\s*(?:get\s*\(\s*)?)"
        rf"['\"]?(?P<name>{_PRIV_NAME})\b",
        re.IGNORECASE,
    )


_COOKIE_READ = _cookie_read_re(_SERVER_COOKIE_ACCESSOR)
# `getCookie(` is admissible only where the file proves it is server-side.
_COOKIE_READ_WITH_HELPER = _cookie_read_re(_SERVER_COOKIE_ACCESSOR + r"|getCookie")
_SERVER_FRAMEWORK_MARKER = re.compile(
    r"\bexpress\b|\bfastify\b|\bkoa\b|next/headers|HttpServletRequest"
    r"|http\.HandlerFunc",
    re.IGNORECASE,
)

# Branch keywords only. `?`, `&&`, `||` are NOT decision predicates: they fire
# on JSX render guards and display-default ternaries, which have nothing to do
# with authorization.
_BRANCH_KEYWORD = re.compile(
    r"(?:^|[^\w.$])(?:if|elif|else\s+if|while|unless|switch|assert|require)\b\s*\(?",
    re.IGNORECASE,
)
_COMPARISON_AFTER = re.compile(
    r"^['\"]?\s*\]?\s*\)?\s*(?:===?|!==?|<>|=~|\.equals\(|\.includes\(|\.startsWith\()"
)
_ASSIGNMENT = re.compile(r"(?<![=!<>+\-*/%&|^:])=(?!=)")
_ARG_POSITION = re.compile(r"[\w.$\]]\s*\([^()]*$")
_COOKIE_READ_LINE_SAFE = re.compile(
    r"(?<![\w.$])Cookies\.get|document\.cookie|(?<![\w.$])useCookies|\$cookies\b"
    r"|signedCookies|cookies\.signed|get_signed_cookie|SecureCookie"
    r"|expect\(|\bassert\w*\s*[(:]|should\.",
    re.IGNORECASE,
)
_BENIGN_COOKIE_NAME = re.compile(
    r"^(?:csrf|xsrf|token|jwt|session|sid|jsessionid|next|redirect|locale|lang"
    r"|theme|consent)$",
    re.IGNORECASE,
)
_COOKIE_VERIFIER = re.compile(
    r"jwt\.verify|jwtVerify|verify_signature|hmac|compare_digest|itsdangerous"
    r"|URLSafeTimedSerializer|Signer\(|verifySignature",
    re.IGNORECASE,
)

_COOKIE_DECISION_FIELDS = {
    "category": "CWE-784",
    "check_id": "cwe.web_security.cookie_security_decision",
    "title": "Security decision made on an unverified cookie value",
    "description": (
        "Line {line} branches on a client-controlled cookie value; the cookie "
        "is attacker-editable, so the check can be flipped at will"
    ),
    "recommendation": (
        "Derive privilege from server-side session state, or use a signed / "
        "encrypted cookie and verify the signature before reading it"
    ),
}
_COOKIE_RELIANCE_FIELDS = {
    "category": "CWE-565",
    "check_id": "cwe.web_security.cookie_reliance",
    "title": "Reliance on an unverified cookie value",
    "description": (
        "Line {line} propagates a privileged, client-controlled cookie value "
        "into application state without verifying it"
    ),
    "recommendation": (
        "Treat cookie values as untrusted input: resolve privileges from "
        "server-side session state or verify a signed cookie first"
    ),
}


def _check_cookie_reliance(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """CWE-784 / CWE-565 — one row per (file, cookie name), 784 winning."""
    reader = _cookie_reader_for(lines)
    seen: set[tuple[str, str]] = set()
    for line_num, line in active:
        hit = _cookie_reliance_hit(reader, _capped(line), line_num, lines)
        if hit is None:
            continue
        key = (hit[0]["category"], hit[1].lower())
        if key in seen:
            continue
        seen.add(key)
        _emit(findings, hit[0], file_path, line_num, lines, hit[2])


def _cookie_reader_for(lines: list[str]) -> re.Pattern:
    """Widen to `getCookie(` only in a file that proves it is server-side."""
    if _SERVER_FRAMEWORK_MARKER.search("\n".join(lines[:400])):
        return _COOKIE_READ_WITH_HELPER
    return _COOKIE_READ


def _cookie_reliance_hit(
    reader: re.Pattern, line: str, line_num: int, lines: list[str],
) -> tuple[dict, str, str] | None:
    """(fields, cookie name, severity) for the winning shape, or None."""
    match = reader.search(line)
    if match is None or _cookie_read_is_safe(match, line, line_num, lines):
        return None
    return _first_reliance_shape(match, line)


def _cookie_read_is_safe(
    match: re.Match, line: str, line_num: int, lines: list[str],
) -> bool:
    """Browser accessor, signed cookie, assertion, benign name, or verifier."""
    if _COOKIE_READ_LINE_SAFE.search(line):
        return True
    if _BENIGN_COOKIE_NAME.match(match.group("name")):
        return True
    window = "\n".join(lines[max(0, line_num - 3):line_num + 2])
    return bool(_COOKIE_VERIFIER.search(window))


def _first_reliance_shape(match: re.Match, line: str) -> tuple[dict, str, str] | None:
    """First matching shape in precedence order (784 before 565)."""
    for fields, test in _RELIANCE_SHAPES:
        if test(match, line):
            name = match.group("name")
            return fields, name, _reliance_severity(fields, name)
    return None


def _reliance_severity(fields: dict, name: str) -> str:
    """Admin-shaped privilege names are high; everything else medium."""
    if fields is not _COOKIE_DECISION_FIELDS:
        return "medium"
    return "high" if _HIGH_PRIV_NAME.match(name) else "medium"


def _is_security_decision(match: re.Match, line: str) -> bool:
    """Branch-anchored or comparison-anchored read (CWE-784)."""
    if _BRANCH_KEYWORD.search(line[:match.start()]):
        return True
    return bool(_COMPARISON_AFTER.match(line[match.end():]))


def _is_bound_or_passed(match: re.Match, line: str) -> bool:
    """Read bound to a name or passed as an argument (CWE-565)."""
    prefix = line[:match.start()]
    if _ASSIGNMENT.search(prefix):
        return True
    return bool(_ARG_POSITION.search(prefix))


# Ordered: CWE-784 takes precedence, which is what enforces `784 XOR 565` on a
# line — the pair is disjoint by construction, with no cross-pass bookkeeping.
_RELIANCE_SHAPES = (
    (_COOKIE_DECISION_FIELDS, _is_security_decision),
    (_COOKIE_RELIANCE_FIELDS, _is_bound_or_passed),
)


# ── CWE-644: HTTP headers reflected into a scripting syntax ────────────────
# The source MUST be receiver-anchored: `response.getHeader(` is not
# attacker-controlled, and a bare `.getHeader(` cannot tell the two apart —
# the same defect class as a bare `.exec(` or `http.Get`. Bare `print` is
# Python's CONSOLE sink (that instance is CWE-117), so `echo`/`print` are
# admitted for PHP dialects only.
_HEADER_SOURCES = re.compile(
    r"(?:request|req|httpRequest|httpServletRequest)\s*\.\s*getHeader\s*\("
    r"|req(?:uest)?\s*\.\s*headers?\s*(?:\[|\.)"
    r"|\$_SERVER\s*\[\s*['\"]HTTP_"
    r"|request\.META\s*\[\s*['\"]HTTP_"
    r"|r\.Header\.Get\s*\(",
    re.IGNORECASE,
)
_HEADER_SINK_SRC = (
    r"res(?:ponse)?\s*\.\s*(?:send|write|end)\s*\("
    r"|fmt\.Fprintf\s*\(\s*w\b"
    r"|(?:Http|Json)Response\s*\("
    r"|\.getWriter\(\)\s*\.\s*(?:print|write)"
)
_HEADER_SINKS = re.compile(_HEADER_SINK_SRC, re.IGNORECASE)
_HEADER_SINKS_PHP = re.compile(
    _HEADER_SINK_SRC + r"|\b(?:echo|print)\b", re.IGNORECASE
)
_PHP_SUFFIXES = frozenset({".php", ".phtml"})
_HEADER_NEUTRALIZED = re.compile(
    r"htmlspecialchars|escapeHtml|escape\(|encodeURIComponent|sanitiz|encodeHTML"
    r"|Encode\.forHtml|JSON\.stringify|json\.dumps|allowlist|whitelist",
    re.IGNORECASE,
)

_HEADER_SCRIPTING_FIELDS = {
    "category": "CWE-644",
    "check_id": "cwe.web_security.header_scripting_syntax",
    "title": "Request header reflected into a response without neutralization",
    "description": (
        "Line {line} writes an attacker-controlled request header straight "
        "into the response body, where it is interpreted as markup/script"
    ),
    "recommendation": (
        "Encode header values for the output context (HTML/JS) before echoing "
        "them, or restrict the value to a validated allowlist"
    ),
}


def _check_header_scripting(
    file_path: Path, lines: list[str], active: list[tuple[int, str]],
    findings: list[dict],
) -> None:
    """CWE-644 — request header reflected into a response sink."""
    sink = _header_sink_for(file_path)
    for line_num, line in active:
        if not _is_header_reflected(_capped(line), sink):
            continue
        _emit(findings, _HEADER_SCRIPTING_FIELDS, file_path, line_num, lines, "medium")


def _header_sink_for(file_path: Path) -> re.Pattern:
    """`echo`/`print` are output sinks in PHP dialects only."""
    if file_path.suffix.lower() in _PHP_SUFFIXES:
        return _HEADER_SINKS_PHP
    return _HEADER_SINKS


def _is_header_reflected(line: str, sink: re.Pattern) -> bool:
    """Header source AND response sink on one line, not neutralized."""
    if _HEADER_NEUTRALIZED.search(line):
        return False
    return bool(_HEADER_SOURCES.search(line) and sink.search(line))


# File-scoped rules, in emission order. CWE-539 runs last: it reads what the
# cookie-attribute checks already claimed.
_FILE_RULES = (
    _check_exposed_dangerous_method,
    _check_cleartext_cookie,
    _check_message_origin,
    _check_cookie_reliance,
    _check_header_scripting,
    _check_persistent_cookie,
)


check_web_security_tool = function_tool(check_web_security)
