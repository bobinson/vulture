"""Consolidated ASVS 5.0.0 requirements skill.

Single entry point for all 17 chapters. Dispatches per-line via a
registry of per-requirement ``(regex, severity, safe_context, lang_gate)``
tuples. Requirements without a dedicated entry fall through to a
keyword-index fallback pass derived from the catalog.

Why a single skill rather than 17? One scan of the source tree (not 17),
one per-line loop, one dispatch layer. Avoids the N x file-I/O multiplier
that concurrent skills incur in Vulture's ThreadPoolExecutor model.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from asvs_agent.catalog import (
    enrich_finding,
    is_applicable_at_level,
    load_catalog,
)

# Reuse hand-crafted CWE regex constants so overlap ASVS reqs don't
# duplicate patterns. The ASVS registry references these compiled patterns
# directly — no re-compilation.
from cwe_agent.skills.auth_check import HARDCODED_CRED_PATTERNS
from cwe_agent.skills.crypto_check import (
    BROKEN_CRYPTO_PATTERNS,
    WEAK_RANDOM_PATTERNS,
)
from cwe_agent.skills.configuration_check import DEBUG_PROD_PATTERNS
from cwe_agent.skills.input_validation_check import PATH_TRAVERSAL_PATTERNS
from cwe_agent.skills.web_security_check import (
    COOKIE_NO_HTTPONLY_PATTERNS,
    COOKIE_NO_SECURE_PATTERNS,
    SAFE_COOKIE_PATTERNS,
    SAFE_SECURE_PATTERNS,
    SESSION_FIXATION_PATTERNS,
)

# Type alias for a per-requirement check specification.
CheckSpec = tuple[
    re.Pattern[str],
    str,
    re.Pattern[str] | None,
    frozenset[str] | None,
]

# Keep in sync with catalog-extractor generic-token list.
_GENERIC_TOKENS = frozenset({
    "the", "and", "for", "that", "this", "with", "from", "all",
    "must", "shall", "verify", "check", "ensure", "application",
    "system", "user", "users", "data", "value", "input", "output",
    "request", "response", "function", "method", "name", "file",
    "path", "type", "code", "object", "return", "result",
})

# Language-extension gate sets.
_WEB_EXTS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm",
    ".java", ".go", ".rb", ".php", ".cs",
})
_CRYPTO_EXTS = frozenset({
    ".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".cs", ".rb",
})
_CODE_EXTS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
    ".php", ".cs", ".c", ".cpp", ".rs",
})
_CONFIG_EXTS = frozenset({
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".json", ".sh", ".bash",
})
_PY_EXTS = frozenset({".py"})

# ---------------------------------------------------------------------------
# Dedicated regex for reqs where no CWE pattern exists or the CWE pattern is
# too broad. Each is compiled once at module import (performance: no per-call
# re.compile).
# ---------------------------------------------------------------------------

# V3.3.1 — Cookie missing Secure attribute (reused)
# V3.3.4 — Cookie HttpOnly flag (reused)
# V3.3.2 — Cookie SameSite missing (custom)
_COOKIE_NO_SAMESITE = re.compile(
    r"(?:\.set_cookie\s*\(|Set-Cookie:|response\.cookie\s*\(|http\.SetCookie\s*\()",
    re.IGNORECASE,
)
# SameSite=None is SAFE only when Secure is also set (RFC 6265bis); we
# conservatively treat only Strict/Lax as unconditionally safe here.
# SameSite=None without Secure is a real bug and must not be suppressed.
_SAFE_SAMESITE = re.compile(
    r"SameSite\s*[:=]\s*['\"]?(?:Strict|Lax)['\"]?",
    re.IGNORECASE,
)

# V3.4.2 — CORS wildcard Access-Control-Allow-Origin
_CORS_WILDCARD = re.compile(
    r"(?:Access-Control-Allow-Origin['\"]?\s*[:,=]\s*['\"]?\*|"
    r"allow_origins\s*=\s*\[\s*['\"]\*['\"]|"
    r"AllowedOrigins\s*:\s*\[\s*['\"]\*['\"])",
    re.IGNORECASE,
)
_SAFE_CORS = re.compile(r"(?:trusted_origins|allowlist|whitelist)", re.IGNORECASE)

# V3.4.4 — X-Content-Type-Options missing (flag any Content-Type header that
# sets a non-nosniff value). Simple check: absence pattern.
_MIME_SNIFF = re.compile(
    r"X-Content-Type-Options['\"]?\s*[:,=]\s*['\"]?(?!nosniff)",
    re.IGNORECASE,
)

# V3.5.6 — JSONP endpoint (callback param)
_JSONP = re.compile(
    r"(?:callback\s*=\s*(?:request|req|params|query)|\bjsonp\s*\()",
    re.IGNORECASE,
)

# V3.5.3 — GET used for sensitive state-changing ops (delete/update over GET)
_GET_STATE_CHANGING = re.compile(
    r"@app\.(?:get|route)\s*\([^)]*['\"]/[^'\"]*/(?:delete|remove|update|reset|logout)['\"]",
    re.IGNORECASE,
)

# V5.1.2 — file extension validation (allow all / no check)
_UNRESTRICTED_UPLOAD_EXT = re.compile(
    r"(?:allowed_extensions\s*=\s*\[\s*\]|accept\s*=\s*['\"]\*|ALLOWED_EXTENSIONS\s*=\s*None)",
    re.IGNORECASE,
)

# V6.2.1 — minimum password length < 8
_MIN_PASSWORD_SHORT = re.compile(
    r"(?:password|passwd)[\w_]*\s*(?:min_?length|min_?len)\s*[:=]\s*[1-7]\b",
    re.IGNORECASE,
)

# V9.1.1 — unsigned JWT decode
_JWT_NO_VERIFY = re.compile(
    r"(?:jwt|JWT|jose)\.(?:decode|verify)\s*\([^)]*verify\s*=\s*False",
    re.IGNORECASE,
)
_JWT_NO_VERIFY2 = re.compile(
    r"jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature\s*:\s*False",
    re.IGNORECASE,
)

# V9.1.2 — jwt alg:none / HS256 with weak key
_JWT_ALG_NONE = re.compile(
    r"(?:alg['\"]?\s*[:,=]\s*['\"]none['\"]|algorithm['\"]?\s*[:,=]\s*['\"]none['\"])",
    re.IGNORECASE,
)

# V9.2.1 — JWT exp claim unchecked (jwt decoded but no exp verify)
_JWT_NO_EXP = re.compile(
    r"jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_exp\s*:\s*False",
    re.IGNORECASE,
)

# V11.3.1 — ECB mode / weak padding already in BROKEN_CRYPTO_PATTERNS,
# but add explicit padding check.
_WEAK_PADDING = re.compile(
    r"(?:PKCS#?1_?v1_?5|RSA/ECB/PKCS1Padding|PKCS1\.5)",
    re.IGNORECASE,
)

# V11.3.4 — reused IV/nonce (hardcoded)
_HARDCODED_IV = re.compile(
    r"(?:\biv\b|\bnonce\b)\s*[:=]\s*b?[\"\'][\\x0-9A-Fa-f]{8,}[\"\']",
    re.IGNORECASE,
)

# V11.4.1 — SHA1/MD5 general use (beyond password hashing).
_WEAK_HASH_GENERAL = re.compile(
    r"(?:hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]|"
    r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"])",
    re.IGNORECASE,
)

# V11.4.2 — password hashing with weak KDF (plain hashing not bcrypt/argon2)
_WEAK_PW_HASH = re.compile(
    r"(?:hashlib\.(?:md5|sha1|sha256)\s*\(\s*(?:password|passwd)|"
    r"DigestUtils\.(?:md5|sha1|sha256)\(\s*(?:password|passwd))",
    re.IGNORECASE,
)
_SAFE_PW_HASH = re.compile(
    r"(?:bcrypt|argon2|scrypt|pbkdf2)",
    re.IGNORECASE,
)

# V11.5.1 — non-cryptographic RNG for security tokens (reused)

# V12.1.1 / V12.1.2 — Legacy TLS versions
_WEAK_TLS = re.compile(
    r"(?:SSLv2|SSLv3|TLSv1(?:\.0|\.1)?|PROTOCOL_SSLv|PROTOCOL_TLSv1_0|PROTOCOL_TLSv1_1|"
    r"MinVersion\s*:\s*tls\.VersionTLS1[01])",
    re.IGNORECASE,
)

# V12.2.1 — cleartext HTTP endpoint for sensitive use
_CLEARTEXT_HTTP = re.compile(
    r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com)",
)
_SAFE_HTTP = re.compile(
    r"(?:localhost|127\.0\.0\.1|docs|schema|xmlns|example|test|mock)",
    re.IGNORECASE,
)

# V12.3.2 — TLS certificate verification disabled
_INSECURE_TLS_VERIFY = re.compile(
    r"(?:verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|"
    r"CERT_NONE|rejectUnauthorized\s*:\s*false|ssl_verify\s*=\s*False|"
    r"SSL_VERIFYPEER[^\n]*(?:False|0)|check_hostname\s*=\s*False)",
    re.IGNORECASE,
)
_SAFE_TLS_VERIFY = re.compile(
    r"(?:test|mock|dev(?:elopment)?|fixture|sample)",
    re.IGNORECASE,
)

# V13.4.1 — .git / source-control metadata exposed in deployment
_SCM_METADATA_EXPOSED = re.compile(
    r"(?:COPY\s+\.git|ADD\s+\.git|location\s+~\s+\.git)",
    re.IGNORECASE,
)

# V13.4.2 — debug enabled in production already in DEBUG_PROD_PATTERNS.

# V13.4.6 — version disclosure
_VERSION_DISCLOSURE = re.compile(
    r"(?:Server:\s*[A-Za-z]+/|X-Powered-By:\s|X-AspNet-Version:)",
)

# V14.2.1 — sensitive data in URL/query string
_SENSITIVE_IN_URL = re.compile(
    r"['\"]\?(?:token|api_key|password|session_id|jwt)=",
    re.IGNORECASE,
)

# V14.2.5 — cache-control / private data cached
_MISSING_CACHE_CONTROL = re.compile(
    r"Cache-Control\s*:\s*public",
    re.IGNORECASE,
)

# V16.1.1 — logger doesn't log auth events / log generic issues -> covered by fallback

# V16.2.2 — logging sensitive data (reused via LOG_SENSITIVE_PATTERNS)

# V16.3.1 — auth events not logged (negative check — omitted)

# V16.3.2 — bare except / hide errors
_BARE_EXCEPT = re.compile(r"^\s*except\s*:\s*(?:#|$)")

# V16.3.4 — stack trace exposed in response
_STACK_TRACE_IN_RESPONSE = re.compile(
    r"(?:return|response|Response|json|render)\s*\([^)]*(?:traceback|stack_trace|stacktrace|printStackTrace)",
    re.IGNORECASE,
)

# V1.2.x — SQL/OS command injection (V1.2.3)
_SQL_INJECTION_CONCAT = re.compile(
    r"(?:execute|exec)\s*\(\s*[\"'].*(?:\%s|\+\s*\w+|\$\{|format\s*\()",
    re.IGNORECASE,
)
_SAFE_SQLI = re.compile(
    r"(?:parameterized|prepare|placeholder|\?|%s\s*,\s*\()",
    re.IGNORECASE,
)

_OS_CMD_INJECTION = re.compile(
    r"(?:os\.system|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True|"
    r"Runtime\.getRuntime\(\)\.exec|exec\s*\()",
    re.IGNORECASE,
)

# V4.1.1 — content-type / charset mismatch
_CONTENT_TYPE_NO_CHARSET = re.compile(
    r"Content-Type\s*:\s*(?:text|application)/[a-z-]+(?!.*charset)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Per-requirement registry. Key = ASVS Shortcode.
# Value = (compiled_regex, severity, safe_context_regex_or_None, lang_gate_or_None)
# ---------------------------------------------------------------------------

# Combine CWE-agent multi-pattern lists into single alternation-regex objects
# (compiled once at module load) for speed.
_SUPPORTED_UNION_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL


def _union(patterns: list[re.Pattern[str]]) -> re.Pattern[str]:
    """Combine many compiled patterns into a single one by alternation.

    Preserves IGNORECASE / MULTILINE / DOTALL flags from any sub-pattern.
    Asserts no unsupported flags are silently dropped so future CWE
    pattern changes fail loudly rather than change match semantics.
    """
    flags = 0
    unsupported: set[int] = set()
    for p in patterns:
        meaningful = p.flags & ~re.UNICODE
        flags |= meaningful & _SUPPORTED_UNION_FLAGS
        if meaningful & ~_SUPPORTED_UNION_FLAGS:
            unsupported.add(meaningful & ~_SUPPORTED_UNION_FLAGS)
    assert not unsupported, f"_union: cannot preserve flags {unsupported}"
    joined = "|".join(f"(?:{p.pattern})" for p in patterns)
    return re.compile(joined, flags)


_HARDCODED_CRED_UNION = _union(HARDCODED_CRED_PATTERNS)
_BROKEN_CRYPTO_UNION = _union(BROKEN_CRYPTO_PATTERNS)
_WEAK_RANDOM_UNION = _union(WEAK_RANDOM_PATTERNS)
_COOKIE_NO_HTTPONLY_UNION = _union(COOKIE_NO_HTTPONLY_PATTERNS)
_COOKIE_NO_SECURE_UNION = _union(COOKIE_NO_SECURE_PATTERNS)
_SESSION_FIXATION_UNION = _union(SESSION_FIXATION_PATTERNS)
_DEBUG_PROD_UNION = _union(DEBUG_PROD_PATTERNS)
_PATH_TRAVERSAL_UNION = _union(PATH_TRAVERSAL_PATTERNS)


_CHECKS: dict[str, CheckSpec] = {
    # -------------------- V1 Encoding & Sanitization --------------------
    "V1.2.3": (_SQL_INJECTION_CONCAT, "critical", _SAFE_SQLI, _CODE_EXTS),
    "V1.2.5": (_OS_CMD_INJECTION, "critical", None, _CODE_EXTS),

    # -------------------- V2 Validation ---------------------------------
    # V2.2.1 input validation removed — regex matched any request
    # accessor (too broad). The LLM phase is a better fit: input
    # validation is context-sensitive and needs data-flow tracing.

    # -------------------- V3 Web Frontend Security -----------------------
    # V3.3.1 cookies missing Secure flag.
    "V3.3.1": (
        _COOKIE_NO_SECURE_UNION,
        "high",
        SAFE_SECURE_PATTERNS,
        _WEB_EXTS,
    ),
    # V3.3.2 SameSite missing.
    "V3.3.2": (_COOKIE_NO_SAMESITE, "medium", _SAFE_SAMESITE, _WEB_EXTS),
    # V3.3.4 cookies missing HttpOnly.
    "V3.3.4": (
        _COOKIE_NO_HTTPONLY_UNION,
        "high",
        SAFE_COOKIE_PATTERNS,
        _WEB_EXTS,
    ),
    # V3.4.2 CORS wildcard origin.
    "V3.4.2": (_CORS_WILDCARD, "high", _SAFE_CORS, _CONFIG_EXTS),
    # V3.4.4 X-Content-Type-Options non-nosniff.
    "V3.4.4": (_MIME_SNIFF, "medium", None, _WEB_EXTS),
    # V3.5.3 state-changing GET handler.
    "V3.5.3": (_GET_STATE_CHANGING, "medium", None, _PY_EXTS),
    # V3.5.6 JSONP enabled.
    "V3.5.6": (_JSONP, "high", None, _WEB_EXTS),

    # -------------------- V4 API & Web Service --------------------------
    "V4.1.1": (
        _CONTENT_TYPE_NO_CHARSET,
        "medium",
        None,
        _CODE_EXTS,
    ),

    # -------------------- V5 File Handling ------------------------------
    # V5.1.1 path traversal — upload paths that include user-controlled
    # segments. Matches the "restrict access to uploaded files" pattern
    # better than V5.3.1 which is about post-upload execution behavior.
    "V5.1.1": (_PATH_TRAVERSAL_UNION, "high", None, _CODE_EXTS),
    # V5.1.2 "filenames from user input must be sanitized or rejected"
    # — unrestricted upload extension pattern matches this.
    "V5.1.2": (_UNRESTRICTED_UPLOAD_EXT, "high", None, _CODE_EXTS),
    # Note: V5.2.5 (symlink-in-archive), V5.2.6 (pixel-flood), V5.3.1
    # (post-upload execution), V5.3.3 (zip-slip) removed in correctness
    # hardening — no SAST regex cleanly matches these semantics.
    # Keyword fallback may surface related findings.

    # -------------------- V6 Authentication -----------------------------
    # V6.2.1 password min length < 8.
    "V6.2.1": (_MIN_PASSWORD_SHORT, "medium", None, _CODE_EXTS),
    # V6.2.2 hardcoded credentials (password change / reuse).
    # V13.3.1: use a secrets management solution (hardcoded secrets
    # violate this — no bare credentials committed to source).
    "V13.3.1": (_HARDCODED_CRED_UNION, "critical", None, _CODE_EXTS),
    # V6.2.5 password composition limits (limit to digits/letters only).
    "V6.2.5": (
        re.compile(r"password.*(?:match|pattern|regex).*\[0-9a-zA-Z\]", re.IGNORECASE),
        "medium",
        None,
        _CODE_EXTS,
    ),

    # -------------------- V7 Session Management -------------------------
    # V7.1.1 session fixation (session IDs populated from user input).
    # Previously mapped to V7.2.2 which is about static API secrets.
    "V7.1.1": (_SESSION_FIXATION_UNION, "high", None, _CODE_EXTS),
    # Note: V7.2.1/V7.2.2 previously had regexes that matched the wrong
    # concerns (client-side storage / session-from-request). Removed in
    # correctness hardening. Keyword fallback covers token-handling reqs.

    # -------------------- V8 Authorization ------------------------------
    # Note: V8.2.1 (function-level access) and V8.3.1 (trusted service
    # layer) are largely runtime/behavioral concerns — no reliable SAST
    # regex fits these without high false-positive rates. Removed in
    # correctness hardening.

    # -------------------- V9 Tokens -------------------------------------
    "V9.1.1": (_JWT_NO_VERIFY, "critical", None, _CODE_EXTS),
    "V9.1.2": (_JWT_ALG_NONE, "critical", None, _CODE_EXTS),
    "V9.2.1": (_JWT_NO_EXP, "high", None, _CODE_EXTS),
    "V9.2.2": (_JWT_NO_VERIFY2, "critical", None, _CODE_EXTS),

    # -------------------- V11 Cryptography ------------------------------
    # V11.3.2: only approved ciphers and modes (AES-GCM etc.) — broken
    # ciphers like DES/RC4 violate this approved-algorithms requirement.
    "V11.3.2": (_BROKEN_CRYPTO_UNION, "critical", None, _CRYPTO_EXTS),
    "V11.3.1": (_WEAK_PADDING, "critical", None, _CRYPTO_EXTS),
    "V11.3.4": (_HARDCODED_IV, "high", None, _CRYPTO_EXTS),
    "V11.4.1": (_WEAK_HASH_GENERAL, "medium", None, _CRYPTO_EXTS),
    "V11.4.2": (_WEAK_PW_HASH, "high", _SAFE_PW_HASH, _CRYPTO_EXTS),
    "V11.5.1": (_WEAK_RANDOM_UNION, "high", None, _CRYPTO_EXTS),
    # V13.3.1 hardcoded-keys check also applies here as "static secrets
    # for cryptographic operations" — already covered via V13.3.1 entry.
    # Previously mapped as V11.6.1 which is about approved algorithms
    # for key gen, not hardcoded key values. Removed.

    # -------------------- V12 TLS Configuration -------------------------
    "V12.1.1": (_WEAK_TLS, "high", None, _CONFIG_EXTS),
    "V12.1.2": (_WEAK_TLS, "high", None, _CONFIG_EXTS),
    "V12.2.1": (_CLEARTEXT_HTTP, "high", _SAFE_HTTP, _CODE_EXTS),
    "V12.3.1": (_INSECURE_TLS_VERIFY, "high", _SAFE_TLS_VERIFY, _CODE_EXTS),
    "V12.3.2": (_INSECURE_TLS_VERIFY, "high", _SAFE_TLS_VERIFY, _CODE_EXTS),

    # -------------------- V13 Configuration -----------------------------
    # Note: V13.2.1/V13.2.2 (backend-to-backend comms) removed — their
    # regex was duplicating V13.3.1 hardcoded-creds detection, causing
    # noisy triple findings per hit. V13.3.1 is the authoritative home.
    # V13.3.1 registration is earlier in the dict (ensuring the single
    # critical-severity mapping wins).
    "V13.4.1": (_SCM_METADATA_EXPOSED, "high", None, _CONFIG_EXTS),
    "V13.4.2": (_DEBUG_PROD_UNION, "high", None, _CONFIG_EXTS),
    "V13.4.6": (_VERSION_DISCLOSURE, "low", None, _CONFIG_EXTS),

    # -------------------- V14 Data Logging & Privacy --------------------
    "V14.2.1": (_SENSITIVE_IN_URL, "medium", None, _CODE_EXTS),
    "V14.2.5": (_MISSING_CACHE_CONTROL, "low", None, _CODE_EXTS),

    # -------------------- V15 Secure Coding & Architecture --------------
    # Pipe-to-shell install is a supply-chain risk; no exact 5.0.0 req
    # maps cleanly. Removed V15.3.1/V15.3.2 mislabels in hardening pass.

    # -------------------- V16 Logging, Errors & Auditing ----------------
    # V14.2.1: sensitive data must not be exposed — includes logs with
    # passwords/tokens/secrets. Relocated from V16.2.1/V16.2.2 which are
    # about log-metadata completeness and timestamp sync (neither of
    # which match the LOG_SENSITIVE regex semantics).
    # (V14.2.1 is already registered earlier with _SENSITIVE_IN_URL;
    #  adding _LOG_SENSITIVE_UNION here would double-register — use the
    #  keyword fallback for LOG_SENSITIVE detection instead.)
    "V16.3.4": (_STACK_TRACE_IN_RESPONSE, "high", None, _CODE_EXTS),
    # V16.5.3: fail gracefully when exceptions occur — bare except
    # blocks swallow errors which prevents graceful failure.
    # Previously mapped to V16.3.2 (failed authorization logging).
    "V16.5.3": (_BARE_EXCEPT, "medium", None, _PY_EXTS),

    # -------------------- V17 WebRTC & Misc -----------------------------
    # Note: V17.2.2 previously had a CORS wildcard regex duplicating
    # V3.4.2. Removed — V17 reqs are WebRTC-specific (DTLS, SRTP, ICE)
    # and require protocol-aware detection out of SAST scope.

    # -------------------- V10 Authorization -----------------------------
    # V10.1.1 — origin validation (CWE-346)
    "V10.1.1": (
        re.compile(r"(?:Origin|Referer)\s*[:=]\s*['\"]?\*['\"]?", re.IGNORECASE),
        "medium",
        None,
        _CONFIG_EXTS,
    ),
    # V10.2.1 — decision without authn
    "V10.2.1": (
        re.compile(
            r"(?:auth(?:entication)?_(?:skip|bypass|off)|authenticate\s*=\s*False|"
            r"skip_auth|anon(?:ymous)?_allowed)",
            re.IGNORECASE,
        ),
        "high",
        None,
        _CODE_EXTS,
    ),
    # V10.3.1 — open redirect (CWE-601)
    "V10.3.1": (
        re.compile(
            r"(?:redirect|Location)\s*\(\s*(?:request|req|params|query|input|user_input)",
            re.IGNORECASE,
        ),
        "high",
        re.compile(r"(?:allowlist|whitelist|is_safe_url|url_has_allowed_host)", re.IGNORECASE),
        _CODE_EXTS,
    ),

    # -------------------- Additional V3 entries -------------------------
    # V3.2.2 — dangerous innerHTML-style sink (CWE-1021 UI redress / XSS)
    "V3.2.2": (
        re.compile(
            r"(?:innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|"
            r"v-html\s*=|\$\.html\()",
        ),
        "high",
        re.compile(r"(?:sanitize|DOMPurify|escape|textContent)", re.IGNORECASE),
        _WEB_EXTS,
    ),

    # -------------------- Additional V6 entries -------------------------
    # V6.3.2 — weak account recovery question/answer
    "V6.3.2": (
        re.compile(
            r"(?:security_question|secret_question|answer_hash|account_recovery)",
            re.IGNORECASE,
        ),
        "medium",
        re.compile(r"(?:MFA|2FA|totp|OTP|magic[_-]?link)", re.IGNORECASE),
        _CODE_EXTS,
    ),

    # -------------------- Additional V11 entry --------------------------
    # V11.6.2 — unsafe key exchange (static DH groups)
    "V11.6.2": (
        re.compile(r"(?:DH_GENERATE_KEY|RSA_generate_key\s*\([^)]*,\s*[0-9]{3}\b)"),
        "medium",
        None,
        _CRYPTO_EXTS,
    ),

    # -------------------- Additional V13 entries ------------------------
    # V13.4.3 — directory listing enabled
    "V13.4.3": (
        re.compile(
            r"(?:autoindex\s+on|DirectoryIndex\s+disabled|Options\s+\+?Indexes|"
            r"options\s*=\s*\{\s*['\"]directory_listing['\"]\s*:\s*True)",
            re.IGNORECASE,
        ),
        "medium",
        None,
        _CONFIG_EXTS,
    ),

    # -------------------- Additional V16 entries ------------------------
    # V16.4.2 — logs not immutable / logs in writable location
    "V16.4.2": (
        re.compile(r"os\.chmod\s*\([^)]*(?:log|audit)[^)]*(?:0o?)?666"),
        "medium",
        None,
        _PY_EXTS,
    ),

    # -------------------- Additional V1 entry ---------------------------
    # V1.2.6 — LDAP injection
    "V1.2.6": (
        re.compile(r"(?:ldap(?:3)?|LDAPConnection|DirContext)[^()]*\.search\s*\([^)]*\+"),
        "high",
        None,
        _CODE_EXTS,
    ),
}


# ---------------------------------------------------------------------------
# Keyword-fallback index for static reqs NOT in _CHECKS.
# ---------------------------------------------------------------------------

_LINE_KEYWORD_RE = re.compile(r"[a-zA-Z_]\w{2,}")


def _should_index_fallback(req_id: str, entry: dict[str, Any]) -> bool:
    """Return True if this catalog entry qualifies for fallback indexing."""
    if entry.get("detectability") != "static":
        return False
    if req_id in _CHECKS:
        return False
    specific = frozenset(entry.get("keywords", [])) - _GENERIC_TOKENS
    return len(specific) >= 3


@lru_cache(maxsize=1)
def _keyword_fallback_index() -> dict[str, list[dict[str, Any]]]:
    """Build keyword -> list of ASVS req-entries for fallback matching.

    Only reqs with ``detectability == "static"`` AND not already in
    ``_CHECKS`` are indexed. Each entry is augmented with a pre-computed
    ``_specific_kw`` frozenset (keywords minus generic tokens) for fast
    dispatch inside the per-line loop.
    """
    idx: dict[str, list[dict[str, Any]]] = {}
    for req_id, entry in load_catalog().items():
        if not _should_index_fallback(req_id, entry):
            continue
        enriched = dict(entry)
        enriched["_specific_kw"] = frozenset(entry["keywords"]) - _GENERIC_TOKENS
        for kw in entry["keywords"]:
            idx.setdefault(kw.lower(), []).append(enriched)
    return idx


def _extract_line_keywords(line: str) -> set[str]:
    """Extract lowercase keywords (len >= 3) from a source line."""
    return {w.lower() for w in _LINE_KEYWORD_RE.findall(line)}


def _is_in_active_config(
    req: dict[str, Any],
    cfg_chapters: set[str],
    target_level: int,
) -> bool:
    """Return True if ``req`` passes the configured chapter+level filters."""
    if cfg_chapters and req.get("chapter_id") not in cfg_chapters:
        return False
    return is_applicable_at_level(req, target_level)


def _active_registry(
    catalog: dict[str, Any],
    cfg_chapters: set[str],
    target_level: int,
) -> list[tuple[str, "CheckSpec"]]:
    """Pre-filter ``_CHECKS`` to entries whose req passes the active config.

    Hoisted out of the per-line hot path: called once per audit, reducing
    per-line dispatch cost from O(|_CHECKS|) to O(|active|) + cutting
    300K max() / dict.get() calls on medium codebases.
    """
    if not cfg_chapters and target_level >= 3:
        return list(_CHECKS.items())
    return [
        (rid, spec) for rid, spec in _CHECKS.items()
        if (req := catalog.get(rid)) is None
        or _is_in_active_config(req, cfg_chapters, target_level)
    ]


def _build_finding(
    req_id: str,
    severity: str,
    path_str: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a finding dict and enrich with ASVS catalog metadata."""
    finding: dict[str, Any] = {
        "severity": severity,
        "check_id": f"asvs.{req_id.lower()}",
        "category": f"ASVS-{req_id}",
        "title": f"ASVS {req_id} violation",
        "description": "",
        "file_path": path_str,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": "",
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, req_id)


def _registry_entry_matches(
    spec: CheckSpec,
    line: str,
    ext: str,
) -> bool:
    """Single-entry gate: lang-gate + primary regex + safe-context regex."""
    pat, _, safe, lang_gate = spec
    if lang_gate is not None and ext not in lang_gate:
        return False
    if not pat.search(line):
        return False
    return safe is None or not safe.search(line)


def _scan_line_registry(
    line: str,
    lineno: int,
    path_str: str,
    lines: tuple[str, ...],
    ext: str,
    active: list[tuple[str, "CheckSpec"]],
    findings: list[dict[str, Any]],
) -> None:
    """Apply every active registry entry whose lang-gate matches this file ext."""
    for req_id, spec in active:
        if not _registry_entry_matches(spec, line, ext):
            continue
        findings.append(_build_finding(req_id, spec[1], path_str, lineno, lines))


def _score_req_for_line(
    req: dict[str, Any],
    line_keywords: set[str],
) -> float:
    """Return keyword-overlap ratio for a single fallback req, or 0.0."""
    specific = req.get("_specific_kw", frozenset())
    matched = line_keywords & specific
    if len(matched) < 3:
        return 0.0
    ratio = len(matched) / max(1, len(specific))
    return ratio if ratio >= 0.4 else 0.0


def _rank_fallback_candidates(
    line_keywords: set[str],
    idx: dict[str, list[dict[str, Any]]],
    cfg_chapters: set[str],
    target_level: int,
) -> dict[str, float]:
    """Score fallback-index candidates for a single line of source."""
    scores: dict[str, float] = {}
    for kw in line_keywords:
        for req in idx.get(kw, []):
            ratio = _score_req_for_line(req, line_keywords)
            if ratio == 0.0:
                continue
            if not _is_in_active_config(req, cfg_chapters, target_level):
                continue
            rid = req["req_id"]
            scores[rid] = max(scores.get(rid, 0.0), ratio)
    return scores


def _scan_line_keyword_fallback(
    line: str,
    lineno: int,
    path_str: str,
    lines: tuple[str, ...],
    cfg_chapters: set[str],
    target_level: int,
    findings: list[dict[str, Any]],
    seen_per_file: set[str],
) -> None:
    """Keyword-fallback dispatch for static reqs not in ``_CHECKS``.

    Each req fires at most once per file to avoid noise.
    """
    idx = _keyword_fallback_index()
    if not idx:
        return
    line_keywords = _extract_line_keywords(line) - _GENERIC_TOKENS
    if len(line_keywords) < 3:
        return
    for req_id in _rank_fallback_candidates(line_keywords, idx, cfg_chapters, target_level):
        if req_id in seen_per_file:
            continue
        seen_per_file.add(req_id)
        findings.append(_build_finding(req_id, "medium", path_str, lineno, lines))


def _line_is_scannable(line: str) -> bool:
    """Return False for comments and scanner-definition lines."""
    if COMMENT_INDICATORS.match(line):
        return False
    return not SCANNER_DEF_LINE.search(line)


def _scan_lines(
    lines: tuple[str, ...],
    path_str: str,
    ext: str,
    active: list[tuple[str, "CheckSpec"]],
    cfg_chapters: set[str],
    target_level: int,
    findings: list[dict[str, Any]],
) -> None:
    """Inner per-line dispatch loop (registry + keyword fallback)."""
    seen_fallback: set[str] = set()
    for lineno, line in enumerate(lines, start=1):
        if not _line_is_scannable(line):
            continue
        _scan_line_registry(
            line, lineno, path_str, lines, ext, active, findings,
        )
        _scan_line_keyword_fallback(
            line, lineno, path_str, lines,
            cfg_chapters, target_level, findings, seen_fallback,
        )


def _scan_file(
    file_path: Path,
    active: list[tuple[str, "CheckSpec"]],
    cfg_chapters: set[str],
    target_level: int,
    findings: list[dict[str, Any]],
) -> None:
    """Scan one file line-by-line with both registry and fallback dispatch."""
    if is_generated_file(file_path) or is_test_file(file_path):
        return
    lines = read_file_lines(file_path)
    if not lines:
        return
    _scan_lines(
        lines, str(file_path), file_path.suffix.lower(),
        active, cfg_chapters, target_level, findings,
    )


def _resolve_config(config: dict | None) -> tuple[set[str], set[int]]:
    """Normalize config dict into (chapters_set, levels_set)."""
    cfg = config or {}
    chapters = set(cfg.get("chapters") or [])
    levels_raw = cfg.get("levels") or [1, 2, 3]
    levels = {int(v) for v in levels_raw}
    return chapters, levels


def check_asvs_requirements(
    source_path: str,
    config: dict | None = None,
) -> dict[str, Any]:
    """Consolidated ASVS audit dispatch over all 17 chapters.

    Args:
        source_path: Root directory to audit.
        config: Optional dict with keys ``chapters`` (list[str]) and
                ``levels`` (list[int]) to filter which requirements
                participate in the scan.

    Returns:
        ``{"findings": [...]}`` with enriched ASVS findings.
    """
    cfg_chapters, cfg_levels = _resolve_config(config)
    target_level = max(cfg_levels) if cfg_levels else 3
    catalog = load_catalog()
    active = _active_registry(catalog, cfg_chapters, target_level)
    findings: list[dict[str, Any]] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, active, cfg_chapters, target_level, findings)
    return {"findings": findings}


def _tool_entry(source_path: str) -> dict[str, Any]:
    """Thin agent-tool wrapper around :func:`check_asvs_requirements`.

    Accepts only ``source_path`` (str) so the OpenAI Agents SDK strict
    JSON-schema validator can derive a clean, parameterless tool schema.
    Config filtering is handled by the Python-level caller via
    ``check_asvs_requirements``.
    """
    return check_asvs_requirements(source_path)


check_asvs_requirements_tool = function_tool(_tool_entry)
