"""CWE authentication vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet
from shared.tools.suppression import AUTH_CHECK_SUPPRESSIONS, should_suppress

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._var_reference import line_value_is_variable_ref

# CWE-798: Hardcoded credentials.
#
# Length floor raised to 8 chars for password/api_key/etc. — the prior
# 3-char minimum trapped fixture-style assignments like
#   password = "abc"
#   pwd = "test"
# producing constant noise in non-test files that happen to define
# example credentials. 8 chars matches conventional hardcoded-secret
# heuristics (most real keys/tokens far exceed 8). Trade-off: a real
# 6-char admin password slips through; the SAFE_CRED_PATTERNS line-
# context filter and downstream LLM phase pick those up.
HARDCODED_CRED_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{12,}["\']', re.IGNORECASE),
    re.compile(r'(?:secret_key|secret)\s*=\s*["\'][^"\']{12,}["\']', re.IGNORECASE),
    re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{12,}["\']', re.IGNORECASE),
    re.compile(r'(?:AWS_SECRET|PRIVATE_KEY)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
]

SAFE_CRED_PATTERNS = re.compile(
    r'(?:os\.(?:environ|getenv)|process\.env|Config\.|config\[|'
    r'placeholder|example|changeme|xxx|test|dummy|fake|mock|<|TODO|FIXME)',
    re.IGNORECASE,
)

# CWE-287: Improper authentication (weak hashing for passwords)
WEAK_AUTH_PATTERNS = [
    re.compile(r'(?:md5|MD5)\s*\([^)]*(?:password|passwd|pwd)', re.IGNORECASE),
    re.compile(r'(?:sha1|SHA1)\s*\([^)]*(?:password|passwd|pwd)', re.IGNORECASE),
    re.compile(r'hashlib\.(?:md5|sha1)\([^)]*(?:password|passwd)', re.IGNORECASE),
    re.compile(r'(?:password|passwd)\s*==\s*(?:request|req|params|input|body)', re.IGNORECASE),
    re.compile(r'(?:request|req|params|input|body)\S*\s*==\s*\S*(?:password|passwd)', re.IGNORECASE),
]

# CWE-306: Missing authentication on critical function
UNPROTECTED_ROUTE_PATTERNS = [
    re.compile(r'@app\.(?:route|post|put|delete|patch)\s*\([^)]*\)\s*$'),
    re.compile(r'router\.(?:post|put|delete|patch)\s*\([^)]*,\s*(?:async\s+)?(?:function|\(|handler)'),
    re.compile(r'\.(?:Post|Put|Delete|Patch)\s*\([^)]*,\s*\w+Handler'),
]

SAFE_AUTH_DECORATORS = re.compile(
    r'(?:@login_required|@auth|@require_auth|@authenticated|'
    r'@permission|@protect|middleware\.|auth_required|isAuthenticated|'
    r'@jwt_required|@token_required)',
    re.IGNORECASE,
)

# CWE-521: Weak password requirements.
#
# Common idioms covered:
#   1. min_length = 5      / minLength: 5      / 'min_length': 5
#   2. len(password) >= 6  / len(password) < 8 (the inverted operator is the
#                                              most common Python form)
#   3. password.length < 8 / passwordControl ... minLength(5)
#   4. Django MinLengthValidator(4) / MinimumLengthValidator(min_length=5)
#
# PRECISION: every one of these used to fire without any password context, and
# the generic `\.length\s*>\s*[1-9]` arm turned every array-size comparison in
# the tree into a "weak password requirement" — in one sweep 15 of 18 rows were
# `solves.length > 1`, `match.length >= 1`, `result.data.length > 1` and
# friends. `password.*min.*[1-7]` was just as loose: it matched
# `waitForInputToHaveValue('#password', 'admin1')` because "ad-MIN-1" contains
# "min" followed by a digit.
#
# So each rule now declares how it earns its password context:
#   "self"   — the pattern names a password itself, nothing more needed
#   "line"   — a password token must appear on the SAME line
#   "window" — a password token may appear within a few lines (config blocks
#              name the field on the enclosing key)
_PASSWORD_TOKEN = re.compile(
    r"(?:pass[_-]?(?:word|wd|phrase)|passwd|pwd)", re.IGNORECASE,
)
_PASSWORD_CONTEXT_LINES = 3

WEAK_PASSWORD_RULES: list[tuple[re.Pattern, str]] = [  # type: ignore[type-arg]
    (re.compile(r'min.?(?:length|len)["\']?\s*(?:=|:)\s*[1-7]\b', re.IGNORECASE), "window"),
    (re.compile(r'len\(\s*(?:password|passwd|pwd)\s*\)\s*(?:>=?|<)\s*[1-7]\b', re.IGNORECASE), "self"),
    (re.compile(r'(?:password|passwd|pwd)\w*\.length\s*(?:>=?|<)\s*[1-7]\b', re.IGNORECASE), "self"),
    (re.compile(r'\.length\s*(?:>=?|<)\s*[1-7]\b'), "line"),
    # `passwordControl ... Validators.minLength(5)`. `\bmin` refuses to see a
    # minimum inside "admin1"; the bound must follow the min* token closely.
    (re.compile(
        r'(?:password|passwd|pwd)\w*.*\bmin(?:imum)?\w*\W{0,3}[1-7]\b', re.IGNORECASE,
    ), "self"),
    (re.compile(r'Min(?:imum)?LengthValidator\s*\(\s*(?:min_length\s*=\s*)?[1-7]\b'), "window"),
]

# Back-compat export: the raw pattern list without the context tags.
WEAK_PASSWORD_PATTERNS = [pattern for pattern, _ in WEAK_PASSWORD_RULES]

SAFE_PASSWORD_VALIDATION = re.compile(
    r'(?:bcrypt|argon2|scrypt|pbkdf2|zxcvbn|password.?strength)',
    re.IGNORECASE,
)

# CWE-916 / CWE-759: password hash with insufficient computational effort, and
# no salt.
#
# An app that stores md5 password hashes (a `security.hash(req.body.password)`
# helper over `createHash('md5')`) produced only CWE-328
# "weak hash algorithm for integrity" at MEDIUM — which describes a checksum,
# not a password store. The discriminator is the VALUE being digested: a bare
# one-shot digest of a password is CWE-916 regardless of which digest it is,
# and one with no salt in sight is also CWE-759.
#
# Scope is deliberately the STORAGE site (`password = hash(...)`,
# `setDataValue('password', hash(...))`) and not comparison sites
# (`user.password !== hash(pw)`), which restate the same design flaw at every
# call site; and it is capped at one row per file per CWE.
_PASSWORD_VALUE = r"(?:password|passwd|pwd|passphrase|security.?answer)"

DIGEST_ON_PASSWORD = re.compile(
    rf"\b(?:\w+\.)?(?:hash|md5|sha1|sha_?1|digest|createHash|createHmac)\s*\("
    rf"[^)]*{_PASSWORD_VALUE}",
    re.IGNORECASE,
)
# `password = <digest>` / `password: <digest>` / `'password', <digest>`.
# `=(?!=)` keeps `password === hash(pw)` and `password !== hash(pw)` out.
PASSWORD_FIELD_WRITE = re.compile(
    rf"{_PASSWORD_VALUE}[\"']?\s*(?:=(?!=)|:|,)", re.IGNORECASE,
)
KDF_TOKENS = re.compile(
    r"(?:bcrypt|argon2|scrypt|pbkdf2|\bkdf\b|sodium|passlib|Rfc2898|"
    r"password_hash|generate_password_hash)",
    re.IGNORECASE,
)
SALT_TOKEN = re.compile(r"\bsalt\b", re.IGNORECASE)

# CWE-620 / CWE-640: password-change and password-recovery flows.
PASSWORD_UPDATE = re.compile(
    r"(?:update|set|save|create)\w*\s*\(\s*\{?\s*[\"']?password[\"']?\s*[,:]"
    r"|(?<![\w.])password\s*[:=](?!=)\s*(?:new|req|body|query|params|input)",
    re.IGNORECASE,
)
PASSWORD_CHANGE_INTENT = re.compile(
    r"(?:new.?password|change.?password|update.?password|password.?change)", re.IGNORECASE,
)
PASSWORD_RECOVERY_INTENT = re.compile(
    r"(?:security.?answer|security.?question|forgot.?password|reset.?password|"
    r"password.?recovery|account.?recovery)",
    re.IGNORECASE,
)
CURRENT_PASSWORD = re.compile(r"(?:current|old|existing).?password", re.IGNORECASE)
# `if (currentPassword && hash(currentPassword) !== stored)` — the verification
# only runs when the client bothered to send the value, so omitting it skips it.
OPTIONAL_CURRENT_PASSWORD = re.compile(
    r"if\s*\(?\s*!?\s*(?:current|old|existing).?password\s*(?:&&|\?|and\b)", re.IGNORECASE,
)
SECURITY_ANSWER_GATE = re.compile(r"(?:security.?answer|security.?question)", re.IGNORECASE)
SECURITY_ANSWER_COMPARE = re.compile(r"answer\s*(?:===|==|!==|!=)|(?:===|==)\s*[\w.]*answer", re.IGNORECASE)
# A second recovery factor that makes the flow more than a guessable question.
RECOVERY_SECOND_FACTOR = re.compile(
    r"(?:reset.?token|verification.?code|one.?time|\botp\b|magic.?link|"
    r"expiresAt|expires_at|token.?expiry|sendMail|sendEmail)",
    re.IGNORECASE,
)

# CWE-287 / CWE-347: JWT verification with the public key and no algorithm
# allowlist — `expressJwt({ secret: publicKey })` and
# `jws.verify(token, publicKey)`.
# With no `algorithms` allowlist an attacker re-signs the token with HS256
# using the *public* key as the HMAC secret and is authenticated.
JWT_VERIFY_CALL = re.compile(
    r"\b(?:expressJwt|jwtVerify)\s*\(|\b(?:jwt|jws|jsonwebtoken)\.verify\b", re.IGNORECASE,
)
JWT_PUBLIC_KEY = re.compile(r"\bpublic[_-]?key\b|\bpubKey\b", re.IGNORECASE)
JWT_ALGORITHMS = re.compile(r"algorithms\s*[:=]", re.IGNORECASE)
# The key must be an identifier (a variable holding a key), not an expression
# like `'' + Math.random()`: only a real verification key can be confused.
JWT_KEY_IDENTIFIER = re.compile(r"(?:secret|key)\s*:\s*[A-Za-z_$]|,\s*[A-Za-z_$][\w.$]*\s*[,)]")
_JWT_CALL_LINES = 3

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

# Two-tier context: hardcoded creds are critical only with auth/connection context
_CREDENTIAL_CONTEXT = [re.compile(r"(connect|login|auth|session|database)", re.IGNORECASE)]


def _should_skip(file_path: Path) -> bool:
    """True for files that carry no auth behaviour at all.

    Prose is deliberately *not* an arm here. This skill owns one
    exposed-value detector (CWE-798), and a credential pasted into a README
    is leaked whether or not anything executes. Prose is instead narrowed
    per-detector in :func:`_analyze_file`, which keeps CWE-798 running and
    drops only the pattern-shaped checks.
    """
    return is_generated_file(file_path) or is_test_file(file_path)


def check_authentication(source_path: str) -> dict:
    """Check for CWE authentication vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of authentication vulnerabilities.
    """
    findings: list[dict] = []
    suppression_counts: dict[int, int] = {}

    for file_path in scan_code_files(source_path):
        if _should_skip(file_path):
            continue
        _analyze_file(file_path, findings, suppression_counts)

    return {"findings": findings}


def _is_non_code_line(line: str) -> bool:
    """True for comment / import / scanner-definition lines."""
    return bool(
        COMMENT_INDICATORS.match(line) or IMPORT_LINE.match(line) or SCANNER_DEF_LINE.search(line)
    )


def _check_code_shapes(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], emitted: set[str],
) -> None:
    """Pattern-shaped auth detectors — an instance only, never a mention.

    These are the checks suppressed in prose: a document quoting
    ``algorithms: ['none']`` in order to forbid it verifies no token.
    """
    _check_weak_auth(file_path, line, line_num, lines, findings)
    _check_missing_auth(file_path, line, line_num, lines, findings)
    _check_weak_password(file_path, line, line_num, lines, findings)
    _check_password_hash(file_path, line, line_num, lines, content, findings, emitted)
    _check_jwt_verification(file_path, line, line_num, lines, findings, emitted)


def _scan_lines(
    file_path: Path, lines: list[str], content: str,
    findings: list[dict], suppression_counts: dict[int, int], prose: bool,
) -> None:
    """Run the per-line detectors, keeping only CWE-798 when the file is prose."""
    emitted: set[str] = set()
    for line_num, line in enumerate(lines, start=1):
        if _is_non_code_line(line):
            continue
        _check_hardcoded_creds(file_path, line, line_num, lines, content, findings, suppression_counts)
        if prose:
            continue
        _check_code_shapes(file_path, line, line_num, lines, content, findings, emitted)


def _analyze_file(file_path: Path, findings: list[dict], suppression_counts: dict[int, int]) -> None:
    """Analyze a file for authentication patterns.

    In prose only the exposed-value detector (CWE-798) runs; every
    pattern-shaped check is dropped, because markdown body text carries no
    comment marker for ``COMMENT_INDICATORS`` and so a quoted anti-pattern
    reads as executable source.
    """
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    prose = is_prose_file(file_path)
    if not prose:
        _check_password_change(file_path, lines, content, findings)
        _check_password_recovery(file_path, lines, content, findings)
    _scan_lines(file_path, lines, content, findings, suppression_counts, prose)


def _check_hardcoded_creds(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for CWE-798 hardcoded credentials.

    Suppresses lines whose RHS is a variable reference (`$VAR`,
    `${VAR}`, `{{ var }}`, `%(VAR)s`, etc.) — those are env / template
    indirections, not literal secrets. CI YAML files in particular are
    full of these false positives.
    """
    if SAFE_CRED_PATTERNS.search(line):
        return
    if line_value_is_variable_ref(line):
        return
    for pattern in HARDCODED_CRED_PATTERNS:
        if pattern.search(line):
            # Two-tier: demote to medium if file lacks auth/connection context
            severity = "critical"
            if not check_context(content, _CREDENTIAL_CONTEXT):
                severity = "medium"
            finding = {
                "severity": severity,
                "check_id": "cwe.auth.hardcoded_cred",
                "category": "CWE-798",
                "title": "Hardcoded credentials detected",
                "description": f"Possible hardcoded secret at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables or a secrets manager",
                "verification_hints": ["Check if credential is used in production config", "Verify no env var override"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            if should_suppress(finding["title"], file_path, line, AUTH_CHECK_SUPPRESSIONS, suppression_counts):
                return
            findings.append(enrich_finding(finding, "798"))
            return


def _check_weak_auth(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-287 improper authentication."""
    for pattern in WEAK_AUTH_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.auth.weak_mechanism",
                "category": "CWE-287",
                "title": "Weak authentication mechanism",
                "description": f"Weak hash or direct password comparison at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use bcrypt, argon2, or scrypt for password hashing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "287"))
            return


def _check_missing_auth(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-306 missing authentication on critical functions."""
    for pattern in UNPROTECTED_ROUTE_PATTERNS:
        if not pattern.search(line):
            continue
        # Look at preceding 3 lines for auth decorators/middleware
        context_start = max(0, line_num - 4)
        preceding = "\n".join(lines[context_start:line_num - 1])
        if SAFE_AUTH_DECORATORS.search(preceding):
            return
        finding = {
            "severity": "high",
            "check_id": "cwe.auth.missing_auth",
            "category": "CWE-306",
            "title": "Missing authentication on endpoint",
            "description": f"Route handler without auth check at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add authentication middleware or decorator to protect endpoint",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "306"))
        return


def _has_password_context(line: str, lines: list[str], line_num: int, mode: str) -> bool:
    """Whether a weak-bound match on this line is about a password."""
    if mode == "self":
        return True
    if _PASSWORD_TOKEN.search(line):
        return True
    if mode != "window":
        return False
    start = max(0, line_num - 1 - _PASSWORD_CONTEXT_LINES)
    end = min(len(lines), line_num + _PASSWORD_CONTEXT_LINES)
    return bool(_PASSWORD_TOKEN.search("\n".join(lines[start:end])))


def _check_weak_password(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-521 weak password requirements."""
    if SAFE_PASSWORD_VALIDATION.search(line):
        return
    for pattern, mode in WEAK_PASSWORD_RULES:
        if pattern.search(line):
            if not _has_password_context(line, lines, line_num, mode):
                continue
            finding = {
                "severity": "medium",
                "check_id": "cwe.auth.weak_password",
                "category": "CWE-521",
                "title": "Weak password requirements",
                "description": f"Insufficient password validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Enforce minimum 8 characters with complexity requirements",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "521"))
            return


def _emit(
    file_path: Path, lines: list[str], line_num: int, findings: list[dict],
    *, category: str, check_id: str, severity: str, title: str,
    description: str, recommendation: str, **extra: object,
) -> None:
    """Append one enriched finding (shared by the 0070 detectors).

    ``category`` is the FULL literal (``"CWE-620"``), not the bare id. The
    coverage attestation discovers emitted CWEs by scanning this source for a
    literal ``CWE-N`` at an emit site, so passing the bare id made every CWE
    emitted through here invisible to the report while detection worked fine —
    an under-claim, which is the one direction the attestation must never take.
    """
    cwe = category.removeprefix("CWE-")
    finding: dict = {
        "severity": severity,
        "check_id": check_id,
        "category": category,
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": recommendation,
    }
    finding.update(extra)
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, cwe))


def _first_match_line(lines: list[str], pattern: re.Pattern) -> int | None:  # type: ignore[type-arg]
    """1-based line number of the first non-comment line matching `pattern`."""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if pattern.search(line):
            return line_num
    return None


def _check_password_hash(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], emitted: set[str],
) -> None:
    """Check for CWE-916 / CWE-759 password hashing without a KDF or salt.

    Line patterns are tested BEFORE the whole-file KDF lookup: a per-line
    `content` scan is O(lines x file size) and made a full-tree sweep
    pathologically slow.
    """
    if not (DIGEST_ON_PASSWORD.search(line) and PASSWORD_FIELD_WRITE.search(line)):
        return
    if KDF_TOKENS.search(content):
        return
    if "916" not in emitted:
        emitted.add("916")
        _emit(
            file_path, lines, line_num, findings,
            category="CWE-916", check_id="cwe.auth.password_hash_effort", severity="critical",
            title="Password stored with insufficient hashing effort",
            description=(
                f"Password value hashed with a bare one-shot digest at line {line_num}; "
                "a single digest round is brute-forceable at billions of guesses per second"
            ),
            recommendation="Store passwords with bcrypt, argon2id, scrypt, or PBKDF2 at a tuned work factor",
            verification_hints=["Confirm the hashing helper is a plain digest, not a KDF wrapper"],
            requires_context=True,
        )
    if "759" in emitted or SALT_TOKEN.search(content):
        return
    emitted.add("759")
    _emit(
        file_path, lines, line_num, findings,
        category="CWE-759", check_id="cwe.auth.password_hash_no_salt", severity="high",
        title="Password hash computed without a salt",
        description=(
            f"Password digest at line {line_num} uses no salt, so identical passwords "
            "produce identical hashes and precomputed rainbow tables apply"
        ),
        recommendation="Use a KDF that generates a per-password random salt (bcrypt/argon2id) and store it with the hash",
        verification_hints=["Check whether a salt is added by the hashing helper"],
        requires_context=True,
    )


def _check_password_change(
    file_path: Path, lines: list[str], content: str, findings: list[dict],
) -> None:
    """Check for CWE-620 unverified password change.

    File-level: a password-change flow that updates the stored password without
    a mandatory current-password check. Recovery flows are excluded — they
    legitimately have no current password and are covered by CWE-640.
    """
    if PASSWORD_RECOVERY_INTENT.search(content):
        return
    if not (PASSWORD_CHANGE_INTENT.search(content) and PASSWORD_UPDATE.search(content)):
        return
    anchor = _first_match_line(lines, OPTIONAL_CURRENT_PASSWORD)
    detail = "the current-password check only runs when the client supplies the value"
    if anchor is None:
        if CURRENT_PASSWORD.search(content):
            return  # a mandatory current-password check exists
        anchor = _first_match_line(lines, PASSWORD_UPDATE)
        detail = "no current-password verification precedes the password update"
    if anchor is None:
        return
    _emit(
        file_path, lines, anchor, findings,
        category="CWE-620", check_id="cwe.auth.unverified_password_change", severity="high",
        title="Unverified password change",
        description=f"Password change at line {anchor}: {detail}",
        recommendation="Require and verify the current password (or a freshly re-authenticated session) before changing it",
        verification_hints=["Confirm no upstream middleware enforces re-authentication"],
        requires_context=True,
    )


def _check_password_recovery(
    file_path: Path, lines: list[str], content: str, findings: list[dict],
) -> None:
    """Check for CWE-640 weak password recovery mechanism.

    A reset flow whose only gate is a security answer: the answer is
    low-entropy, guessable, often public, and never expires.
    """
    if not PASSWORD_UPDATE.search(content):
        return
    if not (SECURITY_ANSWER_GATE.search(content) and SECURITY_ANSWER_COMPARE.search(content)):
        return
    if RECOVERY_SECOND_FACTOR.search(content):
        return
    anchor = _first_match_line(lines, SECURITY_ANSWER_COMPARE) or _first_match_line(lines, PASSWORD_UPDATE)
    if anchor is None:
        return
    _emit(
        file_path, lines, anchor, findings,
        category="CWE-640", check_id="cwe.auth.weak_password_recovery", severity="high",
        title="Weak password recovery mechanism",
        description=(
            f"Password reset at line {anchor} is gated only on a security answer, "
            "with no emailed reset token, expiry, or second factor"
        ),
        recommendation="Reset passwords via a single-use, short-lived token sent to a verified channel",
        verification_hints=["Check for rate limiting and token issuance elsewhere in the flow"],
        requires_context=True,
    )


def _check_jwt_verification(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], emitted: set[str],
) -> None:
    """Check for CWE-287 / CWE-347 JWT algorithm confusion.

    Capped at one row per file per CWE: the flaw is per-configuration, not per
    call site.
    """
    if not JWT_VERIFY_CALL.search(line):
        return
    window = "\n".join(lines[line_num - 1:line_num - 1 + _JWT_CALL_LINES])
    if JWT_ALGORITHMS.search(window):
        return
    if "jwt287" not in emitted and JWT_PUBLIC_KEY.search(line):
        emitted.add("jwt287")
        _emit(
            file_path, lines, line_num, findings,
            category="CWE-287", check_id="cwe.auth.jwt_public_key_verify", severity="critical",
            title="JWT verified with a public key and no algorithm allowlist",
            description=(
                f"Token verification at line {line_num} passes a public key as the "
                "verification secret with no algorithm restriction; a token re-signed "
                "with HS256 using that public key as the HMAC secret will validate"
            ),
            recommendation="Pin the expected asymmetric algorithm (algorithms: ['RS256']) so a symmetric token is rejected",
        )
    if "jwt347" in emitted or not JWT_KEY_IDENTIFIER.search(line):
        return
    emitted.add("jwt347")
    _emit(
        file_path, lines, line_num, findings,
        category="CWE-347", check_id="cwe.auth.jwt_no_algorithm_allowlist", severity="high",
        title="JWT signature verified without an algorithm allowlist",
        description=(
            f"Verification call at line {line_num} declares no `algorithms` allowlist, "
            "so the token's own `alg` header selects the verification algorithm"
        ),
        recommendation="Always pass an explicit algorithms allowlist to the JWT verifier",
    )


check_authentication_tool = function_tool(check_authentication)
