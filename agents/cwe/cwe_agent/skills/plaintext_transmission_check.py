"""Transport-security skill: cleartext transmission and certificate-validation
defects.

Feature 0070 P7 (§1.3) turned this module from a single-CWE detector into an
ordered, table-driven family. Each rule is one row of ``_SPECS``; the FIRST
spec that matches a line wins, which is what keeps the one-row-per-line
invariant (skill findings are not deduplicated against each other, so a child
specialisation must actively suppress its parent rather than stack on it).

Emitted ids, most specific first:

  CWE-523  Credentials on the wire — ``http://user:pass@host``, an
           ``Authorization: Basic`` header on an ``http://`` line, an
           ``http:// + credential + request-idiom`` conjunction within ±3
           lines, and (template files only) a ``<form action="http://">`` in a
           page that also has a password field.
  CWE-347  A JWT/JOSE token decoded with signature verification off. Retained
           deliberately: the CWE-295 arm below requires a TLS-client token, so
           without this arm ``jwt.decode(..., verify=False)`` would go from two
           rows to none.
  CWE-297  Hostname verification disabled (host mismatch accepted).
  CWE-299  Revocation checking disabled.
  CWE-298  Expiry checking disabled.
  CWE-296  Chain of trust not followed — an EMPTY ``checkServerTrusted``, null
           or empty trust anchors, ``X509_V_FLAG_PARTIAL_CHAIN``.
  CWE-295  Certificate validation disabled WHOLESALE — ``verify=False`` (with a
           TLS client on the line), ``rejectUnauthorized=false``,
           ``InsecureSkipVerify: true``, ``verify_mode = …CERT_NONE`` /
           ``…VERIFY_NONE``, ``_create_unverified_context``, a ``=> true``
           validation callback, any ``set_verify(…, …VERIFY_NONE)`` in the
           OpenSSL family and ``CURLOPT_SSL_VERIFYPEER, 0``.

           These arms are one weakness in eight dialects, so they must share
           ONE id. Splitting the C/.NET/Python spellings onto CWE-296 would
           file the same defect under two ids by language and inflate 296.
           The ``VERIFY_NONE`` token therefore lives here and ONLY here — it
           is receiver-anchored on a ``set_verify`` call (``SSL_CTX_set_verify``,
           ``SSL_set_verify``, pyOpenSSL ``ctx.set_verify``) rather than
           matched bare, because a bare token also appears in mode tables and
           constant enumerations.
  CWE-319  Everything else that puts a TLS-capable protocol on a plaintext
           scheme (``amqp://``, ``ftp://``, ``redis://``, plain ``http://`` …).

Two suppressions are load-bearing rather than cosmetic:

* **Certificate pinning.** Disabling CA validation *in order to* pin a
  fingerprint is the documented substitute for chain validation, not a
  weakness. Every certificate rule skips a site whose ±6-line window (or an
  enclosing ``@SuppressLint`` / ``nosec`` marker) names a fingerprint, thumb
  print, SPKI hash or TOFU flow.
* **Non-endpoint URLs.** ``xmlns``, ``w3.org``, ``apache.org/licenses``,
  ``spdx.org`` … are identifiers, not endpoints. The veto is module-wide
  because the shipped plaintext-scheme rule already fired on them.

Deliberately NOT built (each would be dead code or a false positive here):
``--ssl-no-revoke`` / ``-Dcom.sun.net.ssl.checkRevocation=false`` (shell,
gradle and Dockerfile lines, which this skill does not scan), the Go
``CurrentTime: time.Time{}`` arm (the zero value means "use now" — the secure
default), ``X509VerificationFlags.AllFlags`` (not expiry-specific), and
``CURLOPT_SSL_VERIFYHOST, 1`` (since libcurl 7.28.1 the value 1 means full
verification).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    effective_suffix,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# ---------------------------------------------------------------------------
# Extension scopes (per RULE, never module-wide — widening the module set
# exposes every existing pattern to a new file population)
# ---------------------------------------------------------------------------

# Source dialects. CWE-319 applies to any transport-aware code, but limiting to
# source extensions avoids scanning JSON/YAML config, which legitimately stores
# plaintext-scheme URLs that operators rotate via env-var substitution.
_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".go", ".java", ".rb", ".rs", ".php", ".cs",
    ".kt", ".scala", ".swift", ".cpp", ".cc", ".c", ".m",
})

# JVM / .NET / C dialects — the only places the named PKIX and OpenSSL
# constants can appear. Scoping them keeps the constant arms off six languages
# where they can only be a mention.
_PKIX_EXTENSIONS: frozenset[str] = frozenset({
    ".java", ".kt", ".scala", ".cs", ".c", ".cc", ".cpp", ".m",
})

# Server-rendered templates — reached ONLY by the CWE-523 form rule.
_TEMPLATE_EXTENSIONS: frozenset[str] = frozenset({
    ".html", ".htm", ".hbs", ".handlebars", ".ejs", ".pug", ".jade",
    ".mustache", ".twig", ".liquid", ".njk", ".vue", ".svelte", ".astro",
})

# ---------------------------------------------------------------------------
# Shared vetoes / guards
# ---------------------------------------------------------------------------

_LOOPBACK_HINT = re.compile(
    r"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|host\.docker\.internal)\b",
    re.IGNORECASE,
)

# URLs that identify a schema, licence or spec rather than an endpoint. These
# are never dereferenced at runtime, so they carry nothing over the wire.
_NON_ENDPOINT_URL = re.compile(
    r"xmlns|schemaLocation|namespace\s*=|w3\.org|apache\.org/licenses"
    r"|spdx\.org|purl\.org|schema\.org|xmlsoap\.org|docbook\.org"
    r"|json-schema\.org|maven\.apache\.org|springframework\.org/schema"
    r"|xml\.org|iana\.org|ietf\.org|example\.(?:com|org|net)/(?:ns|schema)",
    re.IGNORECASE,
)

# Certificate pinning / TOFU: the documented substitute for CA validation.
_PINNING_HINT = re.compile(
    r"fingerprint|thumbprint|pin(?:ned|ning)\b|pinner|publicKeyHash"
    r"|certificateHash|expectedCert|sha256Hex|\bTOFU\b|\bSPKI\b",
    re.IGNORECASE,
)
_AUDITED_MARKER = re.compile(
    r"@SuppressLint\s*\(|#\s*nosec|//\s*nosec|/\*\s*nosec|lgtm\s*\[",
    re.IGNORECASE,
)
_PINNING_RADIUS = 6

# Long-term / archival signature validation legitimately validates a
# certificate as of a timestamp instead of now.
_ARCHIVAL_HINT = re.compile(
    r"archiv|timestamp|counter.?sign|\bTSA\b|long.?term|historical|as.?of",
    re.IGNORECASE,
)

# A flag constant being DEFINED or enumerated is not a flag being used.
_ENUM_DEF = re.compile(r"\benum\b|\[Flags\]|^\s*#\s*define\b|\bconst\s+int\b")

_DOC_HINT = re.compile(r"^\s*(?:#|//|/\*|\*)")

# Hard cap on the length of a line this skill will examine — a longer line is a
# bundle/minified artefact, never hand-written transport code.
_MAX_LINE_CHARS = 600

# ---------------------------------------------------------------------------
# CWE-523 — credentials on the wire
# ---------------------------------------------------------------------------

# RFC 3986 userinfo ABNF.
_HTTP_USERINFO = re.compile(
    r"\bhttp://[A-Za-z0-9._~%!$&'()*+,;=-]+:[A-Za-z0-9._~%!$&'()*+,;=-]+@",
    re.IGNORECASE,
)
_BASIC_AUTH = re.compile(
    r"Authorization[\"']?\s*[:=]\s*[\"']?\s*Basic\b", re.IGNORECASE
)
_HTTP_URL = re.compile(r"\bhttp://[A-Za-z0-9._~%-]+", re.IGNORECASE)
_CREDENTIAL_TOKEN = re.compile(
    r"\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credential"
    r"|client_secret|access_key|private_key|authorization)\b",
    re.IGNORECASE,
)
_REQUEST_IDIOM = re.compile(
    r"\brequests\s*\.\s*(?:get|post|put|patch|delete|request)\b"
    r"|\bhttpx\s*\.|\bfetch\s*\(|\baxios\s*\.|\burlopen\s*\("
    r"|\bhttp\s*\.\s*(?:Get|Post|NewRequest|Do)\b|\bHttpClient\b"
    r"|\bRestTemplate\b|\bokhttp\b|\bcurl_exec\s*\(|\bWebClient\b"
    r"|\bnew\s+Request\s*\(|\bsession\s*\.\s*(?:get|post|put|delete)\b",
    re.IGNORECASE,
)
_CREDENTIAL_RADIUS = 3
_FORM_ACTION_HTTP = re.compile(
    r"<form[^>]+action\s*=\s*[\"']http://", re.IGNORECASE
)
_PASSWORD_FIELD = re.compile(r"type\s*=\s*[\"']password", re.IGNORECASE)

# ---------------------------------------------------------------------------
# CWE-347 — signature verification disabled on a token
# ---------------------------------------------------------------------------

_JWT_VERIFY_OFF = re.compile(
    r"\b(?:jwt|jws|jose)\b[^\n]*\bdecode\b[^\n]*\bverify\s*=\s*False\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CWE-297 — hostname verification disabled
# ---------------------------------------------------------------------------

_HOSTNAME_CHECK_OFF = re.compile(
    r"\bcheck_hostname\s*=\s*False\b"
    r"|\b(?:NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER"
    r"|AllowAllHostnameVerifier)\b"
    r"|\bsetHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true\s*\)"
    r"|\bHostnameVerifier\s*\{[^}]*->\s*true\s*\}"
    r"|\bcheckServerIdentity\s*[:=]\s*(?:\([^)]*\)\s*=>|function\s*\([^)]*\))"
    r"\s*\{\s*\}"
    r"|\bCURLOPT_SSL_VERIFYHOST\s*[,=]\s*0\b"
)
_HOSTNAME_CHECK_ON = re.compile(r"\bcheck_hostname\s*=\s*True\b")

# ---------------------------------------------------------------------------
# CWE-299 — revocation checking disabled
# ---------------------------------------------------------------------------

_REVOCATION_OFF = re.compile(
    r"\bsetRevocationEnabled\s*\(\s*false\s*\)"
    r"|\bX509RevocationMode\s*\.\s*NoCheck\b"
    r"|\bCheckCertificateRevocationList\s*=\s*false\b"
    r"|(?:clear_flags|&\s*~|&=\s*~)[^;\n]*\bX509_V_FLAG_CRL_CHECK\b"
)

# ---------------------------------------------------------------------------
# CWE-298 — expiry checking disabled
# ---------------------------------------------------------------------------

_EXPIRY_CHECK_OFF = re.compile(
    r"\bX509_V_FLAG_NO_CHECK_TIME\b"
    r"|\bX509VerificationFlags\s*\.\s*Ignore(?:NotTimeValid|CtlNotTimeValid)\b"
    r"|\bIgnoreCertificateExpiration\s*=\s*true\b"
    r"|\bcatch\s*\(\s*CertificateExpiredException[^)]*\)\s*\{\s*\}"
)

# ---------------------------------------------------------------------------
# CWE-296 — chain of trust not followed
# ---------------------------------------------------------------------------

# Anchor on the SERVER-side method only: an empty `checkClientTrusted` is the
# ordinary case for a client that presents no certificate.
_SERVER_TRUST_ANCHOR = re.compile(r"\bcheckServerTrusted\s*\(")
_EMPTY_TRUST_BODY = re.compile(
    r"\bcheckServerTrusted\s*\([^)]*\)\s*(?::\s*[\w<>\[\], ]+)?"
    r"(?:throws\s+[\w., ]+)?\s*\{\s*(?://[^\n]*\s*|/\*.*?\*/\s*)*\}"
)
_TRUST_BODY_RADIUS = 4
_NO_TRUST_ANCHORS = re.compile(
    r"\bgetAcceptedIssuers\s*\([^)]*\)\s*\{[^}]*return\s+"
    r"(?:null|new\s+X509Certificate\s*\[\s*0\s*\]"
    r"|new\s+X509Certificate\s*\[\s*\]\s*\{\s*\})"
    r"|\bgetAcceptedIssuers\s*\([^)]*\)\s*:[^=\n]*=\s*"
    r"(?:emptyArray|arrayOf)\s*\(\s*\)"
    r"|\bX509_V_FLAG_PARTIAL_CHAIN\b"
)

# ---------------------------------------------------------------------------
# CWE-295 — certificate validation disabled wholesale
# ---------------------------------------------------------------------------

# `verify=False` alone is a kwarg name shared with form/schema validators, so
# the arm requires a TLS client on the same line.
_VERIFY_FALSE = re.compile(r"\bverify\s*=\s*False\b")
_TLS_CLIENT_TOKEN = re.compile(
    r"\brequests\s*\.|\bhttpx\s*\.|\baiohttp\b|\burllib3\b|\bpycurl\b"
    r"|\bSession\s*\(|\bsession\s*\.|\bssl\s*\.|\bSSLContext\b"
    r"|\bhttp\.client\b|\bhttps?://|\bws{1,2}://|\bclient\s*\.",
    re.IGNORECASE,
)
_VERIFICATION_OFF = re.compile(
    r"\brejectUnauthorized\s*[:=]\s*false\b"
    r"|\bInsecureSkipVerify\s*:\s*true\b"
    r"|\bverify_mode\s*=\s*(?:[\w:.]*[.:])?(?:CERT_NONE|VERIFY_NONE)\b"
    r"|\b_create_unverified_context\s*\("
    r"|\b(?:Server|Remote)CertificateValidationCallback\s*\+?=\s*"
    r"(?:\([^)]*\)\s*=>\s*true\b|delegate)"
    r"|\b(?:SSL_(?:CTX_)?)?set_verify\s*\([^;)\n]{0,80}?"
    r"\b(?:SSL[._])?VERIFY_NONE\b"
    r"|\bcurl(?:opt)?[_-]?ssl[_-]?verifypeer\s*[,=]\s*0\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CWE-319 — plaintext scheme for a TLS-capable service
# ---------------------------------------------------------------------------

_PLAINTEXT_SCHEME = re.compile(
    r"\b(amqp|ftp|ldap|mongodb|mysql|postgres(?:ql)?|redis|smtp|telnet|http)"
    r"://"
    r"(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|host\.docker\.internal)\b)"
    r"[A-Za-z0-9._~%-]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Ctx:
    """Per-file scan context."""

    path: str
    lines: tuple[str, ...]
    suffix: str
    text: str


@dataclass(frozen=True)
class _Spec:
    """One detection rule.

    ``guards`` names entries of ``_GUARDS``; any guard that fires suppresses
    the row. ``require`` / ``require_file`` / ``require_window`` are additional
    conjuncts — a rule only fires when all of them hold.
    """

    rule_id: str
    category: str
    severity: str
    title: str
    detail: str
    fix: str
    pattern: re.Pattern[str]
    extensions: frozenset[str] = _LANG_EXTENSIONS
    guards: tuple[str, ...] = ()
    require: re.Pattern[str] | None = None
    forbid: re.Pattern[str] | None = None
    require_file: re.Pattern[str] | None = None
    require_window: re.Pattern[str] | None = None
    window_radius: int = 0
    proximity: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    proximity_radius: int = 0


_CERT_GUARDS = ("scanner_def", "pinning")

# ORDER IS THE DEDUPLICATION MECHANISM: the first spec that matches a line is
# the only row that line produces (§6 P5 — skill findings are not
# cross-deduplicated, so a specialisation must displace its parent).
_SPECS: tuple[_Spec, ...] = (
    _Spec(
        rule_id="plaintext_http_credentials",
        category="CWE-523",
        severity="critical",
        title="Credentials in plaintext HTTP URL",
        detail=(
            "the URL embeds credentials in its userinfo component and is "
            "fetched over plain HTTP, so the credentials themselves travel in "
            "cleartext"
        ),
        fix=(
            "Move to https:// and pass the credentials in an Authorization "
            "header sourced from a secret store, never in the URL."
        ),
        pattern=_HTTP_USERINFO,
        guards=("scanner_def", "non_endpoint"),
    ),
    _Spec(
        rule_id="basic_auth_over_http",
        category="CWE-523",
        severity="high",
        title="HTTP Basic credentials sent over plain HTTP",
        detail=(
            "an Authorization: Basic header carries base64-encoded (not "
            "encrypted) credentials, and this request target is http://"
        ),
        fix=(
            "Send Basic credentials only over https://. Base64 is an encoding, "
            "not protection."
        ),
        pattern=_BASIC_AUTH,
        require=_HTTP_URL,
        guards=("scanner_def", "non_endpoint", "loopback"),
    ),
    _Spec(
        rule_id="credentials_over_http_request",
        category="CWE-523",
        severity="high",
        title="Credentials submitted to a plain-HTTP endpoint",
        detail=(
            "a plain-HTTP endpoint, a credential-shaped value and an outbound "
            "request idiom occur together, so the credential is transmitted "
            "without transport encryption"
        ),
        fix=(
            "Use https:// for any request whose payload or headers carry "
            "credentials, and reject plaintext endpoints in configuration."
        ),
        pattern=_HTTP_URL,
        guards=("scanner_def", "non_endpoint", "loopback"),
        proximity=(_CREDENTIAL_TOKEN, _REQUEST_IDIOM),
        proximity_radius=_CREDENTIAL_RADIUS,
    ),
    _Spec(
        rule_id="credential_form_over_http",
        category="CWE-523",
        severity="high",
        title="Login form posts to a plain-HTTP action",
        detail=(
            "the form action uses http:// and the page collects a password, so "
            "the submitted credentials cross the network in cleartext"
        ),
        fix="Point the form action at https:// (and serve the page over TLS).",
        pattern=_FORM_ACTION_HTTP,
        extensions=_TEMPLATE_EXTENSIONS,
        require_file=_PASSWORD_FIELD,
        guards=("non_endpoint", "loopback"),
    ),
    _Spec(
        rule_id="token_signature_verification_disabled",
        category="CWE-347",
        severity="critical",
        title="Token decoded without signature verification",
        detail=(
            "the token is decoded with verification switched off, so any "
            "attacker-supplied claims are accepted as authentic"
        ),
        fix=(
            "Verify the signature with the expected key and an explicit "
            "algorithm allowlist; never decode with verify=False."
        ),
        pattern=_JWT_VERIFY_OFF,
        guards=("scanner_def",),
    ),
    _Spec(
        rule_id="hostname_verification_disabled",
        category="CWE-297",
        severity="high",
        title="Certificate hostname verification disabled",
        detail=(
            "the peer certificate is accepted without checking that it was "
            "issued for the host being contacted, so any valid certificate "
            "from any host satisfies the check"
        ),
        fix=(
            "Leave hostname verification enabled (check_hostname=True, the "
            "default HostnameVerifier, CURLOPT_SSL_VERIFYHOST=2)."
        ),
        pattern=_HOSTNAME_CHECK_OFF,
        forbid=_HOSTNAME_CHECK_ON,
        guards=_CERT_GUARDS,
    ),
    _Spec(
        rule_id="certificate_revocation_unchecked",
        category="CWE-299",
        severity="medium",
        title="Certificate revocation checking disabled",
        detail=(
            "revocation status is not consulted, so a certificate revoked "
            "after a key compromise is still accepted"
        ),
        fix=(
            "Enable revocation checking (setRevocationEnabled(true), "
            "X509RevocationMode.Online, X509_V_FLAG_CRL_CHECK) with a "
            "documented soft-fail policy."
        ),
        pattern=_REVOCATION_OFF,
        extensions=_PKIX_EXTENSIONS,
        guards=_CERT_GUARDS,
    ),
    _Spec(
        rule_id="certificate_expiry_unchecked",
        category="CWE-298",
        severity="medium",
        title="Certificate expiration checking disabled",
        detail=(
            "validity dates are ignored, so an expired certificate — including "
            "one whose key has since been retired — is accepted"
        ),
        fix=(
            "Do not clear the time check; if a historical validation is really "
            "required, validate as of a trusted timestamp instead."
        ),
        pattern=_EXPIRY_CHECK_OFF,
        extensions=_PKIX_EXTENSIONS,
        guards=(*_CERT_GUARDS, "archival", "enum_def"),
    ),
    _Spec(
        rule_id="empty_trust_manager",
        category="CWE-296",
        severity="high",
        title="Trust manager accepts any server certificate chain",
        detail=(
            "checkServerTrusted has an empty body, so no chain of trust is "
            "followed and any certificate — including a self-signed one from "
            "an interceptor — is accepted"
        ),
        fix=(
            "Delegate to the platform trust manager, or build a validator over "
            "an explicit trust anchor set."
        ),
        pattern=_SERVER_TRUST_ANCHOR,
        extensions=_PKIX_EXTENSIONS,
        require_window=_EMPTY_TRUST_BODY,
        window_radius=_TRUST_BODY_RADIUS,
        guards=_CERT_GUARDS,
    ),
    _Spec(
        rule_id="missing_trust_anchors",
        category="CWE-296",
        severity="high",
        title="No trust anchors for certificate chain validation",
        detail=(
            "the accepted-issuer set is null or empty, or a partial chain is "
            "accepted, so the certificate chain is never followed to a trusted "
            "root"
        ),
        fix=(
            "Return the platform's accepted issuers and require a complete "
            "chain to a trusted root."
        ),
        pattern=_NO_TRUST_ANCHORS,
        extensions=_PKIX_EXTENSIONS,
        guards=_CERT_GUARDS,
    ),
    _Spec(
        rule_id="disabled_tls_verification",
        category="CWE-295",
        severity="high",
        title="Disabled TLS / certificate verification",
        detail=(
            "the TLS client is told to skip certificate validation, so an "
            "active network attacker can present any certificate and read or "
            "modify the traffic"
        ),
        fix=(
            "Keep certificate verification on and trust a specific CA bundle "
            "for internal endpoints instead of disabling the check."
        ),
        pattern=_VERIFY_FALSE,
        require=_TLS_CLIENT_TOKEN,
        guards=_CERT_GUARDS,
    ),
    _Spec(
        rule_id="certificate_validation_disabled",
        category="CWE-295",
        severity="high",
        title="Certificate validation disabled",
        detail=(
            "certificate validation is switched off wholesale for this "
            "connection, so any presented certificate is accepted"
        ),
        fix=(
            "Restore certificate validation; pin or trust a specific CA for "
            "self-signed internal endpoints."
        ),
        pattern=_VERIFICATION_OFF,
        guards=_CERT_GUARDS,
    ),
    _Spec(
        rule_id="plaintext_scheme_url",
        category="CWE-319",
        severity="medium",
        title="Plaintext connection string for a TLS-capable service",
        detail=(
            "the connection uses a non-encrypted scheme even though the "
            "protocol has a TLS variant, so eavesdroppers on any intermediate "
            "hop can read the payload"
        ),
        fix=(
            "Use the TLS variant of the protocol (https://, amqps://, ftps://, "
            "ldaps://, mongodb+srv://, mysql with require_ssl, postgresql with "
            "sslmode=require, rediss://, smtps://, ssh:// instead of telnet://)."
        ),
        pattern=_PLAINTEXT_SCHEME,
        guards=("scanner_def", "non_endpoint", "loopback"),
    ),
)


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

def _window(ctx: _Ctx, lineno: int, radius: int) -> str:
    """Joined text of the ±``radius`` lines around ``lineno`` (1-based)."""
    start = max(0, lineno - 1 - radius)
    return "\n".join(ctx.lines[start:lineno + radius])


def _forward_window(ctx: _Ctx, lineno: int, radius: int) -> str:
    """Joined text of ``lineno`` and the ``radius`` lines that follow it."""
    return " ".join(ctx.lines[lineno - 1:lineno + radius])


def _guard_scanner_def(ctx: _Ctx, line: str, lineno: int) -> bool:
    return SCANNER_DEF_LINE.search(line) is not None


def _guard_non_endpoint(ctx: _Ctx, line: str, lineno: int) -> bool:
    return _NON_ENDPOINT_URL.search(line) is not None


def _guard_loopback(ctx: _Ctx, line: str, lineno: int) -> bool:
    return _LOOPBACK_HINT.search(line) is not None


def _guard_pinning(ctx: _Ctx, line: str, lineno: int) -> bool:
    win = _window(ctx, lineno, _PINNING_RADIUS)
    return _PINNING_HINT.search(win) is not None or _AUDITED_MARKER.search(win) is not None


def _guard_archival(ctx: _Ctx, line: str, lineno: int) -> bool:
    return _ARCHIVAL_HINT.search(_window(ctx, lineno, _PINNING_RADIUS)) is not None


def _guard_enum_def(ctx: _Ctx, line: str, lineno: int) -> bool:
    return _ENUM_DEF.search(line) is not None


_GUARDS = {
    "scanner_def": _guard_scanner_def,
    "non_endpoint": _guard_non_endpoint,
    "loopback": _guard_loopback,
    "pinning": _guard_pinning,
    "archival": _guard_archival,
    "enum_def": _guard_enum_def,
}


def _suppressed(ctx: _Ctx, spec: _Spec, line: str, lineno: int) -> bool:
    return any(_GUARDS[name](ctx, line, lineno) for name in spec.guards)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _present(pattern: re.Pattern[str] | None, text: str) -> bool:
    """True when an OPTIONAL required pattern is absent-or-satisfied."""
    return pattern is None or pattern.search(text) is not None


def _absent(pattern: re.Pattern[str] | None, text: str) -> bool:
    """True when an OPTIONAL forbidden pattern is absent-or-unset."""
    return pattern is None or pattern.search(text) is None


def _line_conjuncts_ok(ctx: _Ctx, spec: _Spec, line: str) -> bool:
    return (
        _present(spec.require, line)
        and _absent(spec.forbid, line)
        and _present(spec.require_file, ctx.text)
    )


def _proximity_ok(ctx: _Ctx, spec: _Spec, lineno: int) -> bool:
    """Every proximity conjunct must appear in the ±radius window."""
    if not spec.proximity:
        return True
    win = _window(ctx, lineno, spec.proximity_radius)
    return all(p.search(win) is not None for p in spec.proximity)


def _window_conjuncts_ok(ctx: _Ctx, spec: _Spec, lineno: int) -> bool:
    if spec.require_window is not None:
        win = _forward_window(ctx, lineno, spec.window_radius)
        return _present(spec.require_window, win) and _proximity_ok(ctx, spec, lineno)
    return _proximity_ok(ctx, spec, lineno)


def _spec_hits(ctx: _Ctx, spec: _Spec, line: str, lineno: int) -> bool:
    if ctx.suffix not in spec.extensions:
        return False
    if spec.pattern.search(line) is None:
        return False
    if not _line_conjuncts_ok(ctx, spec, line):
        return False
    return _window_conjuncts_ok(ctx, spec, lineno)


def _classify(ctx: _Ctx, line: str, lineno: int) -> _Spec | None:
    """First matching spec wins — that is the one-row-per-line invariant."""
    for spec in _SPECS:
        if not _spec_hits(ctx, spec, line, lineno):
            continue
        if _suppressed(ctx, spec, line, lineno):
            return None
        return spec
    return None


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

def _build_finding(spec: _Spec, ctx: _Ctx, lineno: int) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "severity": spec.severity,
        "check_id": f"cwe.plaintext_transmission.{spec.rule_id}",
        "category": spec.category,
        "title": spec.title,
        "description": (
            f"Line {lineno}: {spec.detail} ({spec.category})."
        ),
        "file_path": ctx.path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": spec.fix,
        "code_snippet": extract_snippet(ctx.lines, lineno),
    }
    return enrich_finding(finding, spec.category.removeprefix("CWE-"))


def _skip_line(line: str) -> bool:
    """Lines that can only produce noise.

    The length cap is the bundle defence (§6 P8): ``_MINIFIED_RE`` matches on
    FILENAME only, so webpack/Next chunk files under a non-canonical build
    directory are scanned in full. Measured: one 127KB single-line chunk
    produced the only CWE-523 row on the baseline, and it was false. The cap
    reuses the 600-char bound already used by ``signatures/detector.py``; no
    hand-written source line carries a transport defect past it.
    """
    if len(line) > _MAX_LINE_CHARS:
        return True
    return _DOC_HINT.match(line) is not None or COMMENT_INDICATORS.match(line) is not None


def _scan_line(ctx: _Ctx, line: str, lineno: int, findings: list[dict]) -> None:
    if _skip_line(line):
        return
    spec = _classify(ctx, line, lineno)
    if spec is None:
        return
    findings.append(_build_finding(spec, ctx, lineno))


# ---------------------------------------------------------------------------
# File walk
# ---------------------------------------------------------------------------

_ALL_EXTENSIONS: frozenset[str] = frozenset().union(
    *(spec.extensions for spec in _SPECS)
)


def _should_scan(file_path: Path) -> bool:
    if effective_suffix(file_path.name) not in _ALL_EXTENSIONS:
        return False
    if is_prose_file(file_path) or is_generated_file(file_path):
        return False
    return not is_test_file(file_path)


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    ctx = _Ctx(
        path=str(file_path),
        lines=lines,
        suffix=effective_suffix(file_path.name),
        text="\n".join(lines),
    )
    for lineno, line in enumerate(lines, 1):
        _scan_line(ctx, line, lineno, findings)


def check_plaintext_transmission(source_path: str) -> dict[str, Any]:
    """Scan source files for cleartext transmission (CWE-319/523) and
    certificate-validation defects (CWE-295/296/297/298/299, CWE-347)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_plaintext_transmission_tool = function_tool(check_plaintext_transmission)
