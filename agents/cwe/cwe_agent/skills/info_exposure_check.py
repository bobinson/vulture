"""Information exposure vulnerability detection skill."""

import re
from functools import lru_cache
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    effective_name,
    is_backup_name,
    is_generated_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_all_files,
    scan_backup_files,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet
from shared.tools.suppression import INFO_EXPOSURE_SUPPRESSIONS, should_suppress

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._var_reference import line_value_is_variable_ref

# CWE-209: Error message information disclosure
#
# The first five patterns are Python/Java/Go. That left Node entirely uncovered,
# so a TypeScript target which mounts `errorhandler()` — a package whose whole
# purpose is to return the stack trace and surrounding source to the client —
# reported nothing. The Node additions follow.
ERROR_DISCLOSURE_PATTERNS = [
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"\.printStackTrace\s*\("),  # Java
    re.compile(r"debug\.PrintStack\s*\("),  # Go
    re.compile(r"return\s+.*(?:traceback|stacktrace|stack_trace)", re.IGNORECASE),
    # Node/Express: an error VALUE echoed into the response body.
    #
    # Two exclusions carry the precision. The character class stops at a quote,
    # so `res.send('failed')` cannot match. The `(?!\s*:)` lookahead rejects the
    # token when it is an object KEY — `res.json({ error: 'Try again' })` names
    # a field "error" and returns a literal, which is the correct behaviour.
    # `res.json({ error: err.message })` still matches, on the value.
    re.compile(
        r"\.(?:send|json|end|write)\s*\(\s*[^'\"`)]*"
        r"\b((?:err|error|ex|exception)\w*)\b(?!\s*:)",
        re.IGNORECASE,
    ),
    # A `.stack` property reaching the response, in any wrapping:
    #   res.status(500).json({ stack: err.stack })
    re.compile(r"\.(?:send|json|end|write)\s*\([^)]*\.stack\b"),
]

# Middleware that returns diagnostic detail to the client by design. Reporting
# the mount site is the point: the leak is the mount, not a line inside the
# package.
LEAKY_ERROR_MIDDLEWARE = re.compile(
    r"\buse\s*\(\s*(?:\w+\.)?(?:errorhandler|errorHandler|expressErrorHandler)\s*\(",
)

# Gating the above on the environment is its documented safe usage, so a guard
# anywhere near the mount suppresses the finding.
_ENV_GUARD = re.compile(
    r"(?:NODE_ENV|app\.get\(\s*['\"]env['\"]\s*\)|process\.env\.\w*ENV\w*)"
    r"|\b(?:isDev|isDevelopment|__DEV__|devMode)\b",
    re.IGNORECASE,
)

# Server-side logging of an error is CWE-532's concern, not disclosure. Without
# this, `logger.error(err.stack)` would match the `.stack` pattern above.
_LOG_SINK = re.compile(
    r"\b(?:console|logger|log|winston|pino|bunyan)\s*\.\s*\w+\s*\(|"
    r"\b(?:log|logger)\s*\(",
    re.IGNORECASE,
)

# CWE-532: Information through log files.
#
# Two independent sources of noise had to go.
#
# 1. The call shape. `(?:log(?:ger)?|print|fmt\.Print)\w*\(` treated any method
#    whose name merely CONTAINS "log" as a log sink, so `oauthLogin(...)`,
#    `this.userService.login({ ... password ... })` and `await login(app, {
#    email, password })` all reported a logged credential. Fixed the same way
#    CWE-754 was: a negative lookbehind so the verb cannot start mid-identifier
#    (`oauthLogin` -> the `Log` is preceded by a word char), plus the verb
#    anchored to the START of the method name so `login` is no longer a prefix
#    match for `log`. A dotted receiver is still allowed, because
#    `this.logger.info(...)` and `self.log.debug(...)` are genuine sinks.
#
# 2. The message text. A log line whose LITERAL merely mentions a credential
#    ("ORG_ADMIN_TOKEN secret not configured", "BEE tokens extracted
#    successfully", "Role from token could not be accessed.") discloses nothing.
#    `_strip_literals` removes literal text before matching — see the note there
#    on why it must run before EVERY pattern in this list, and why interpolated
#    expressions are kept so `logger.warn(`token: ${authToken}`)` still reports.
_LOG_RECEIVER = r"(?:console|logger|log|logging|winston|pino|bunyan|klog|slog)"
_LOG_VERB = (
    r"(?:log|debug|info|warn|warning|error|fatal|trace|verbose|silly"
    r"|print|println|printf|write)"
)
# Go's `fmt` is NOT interchangeable with a logger: `fmt.Errorf("...: %w", token.
# ErrRevoked)` builds an error value and `fmt.Sprintf` builds a string — neither
# writes anywhere. Only the Print family is a sink, so `fmt` gets its own verbs.
_PRINT_CALL = r"fmt\s*\.\s*F?Print(?:f|ln)?"
# Bare function call: log(), logger(), logError(), log_info(), print(), printf().
# `login(` cannot match: after `log` the optional verb group cannot consume "in",
# so the required "(" lands on "i" and the match fails.
_LOG_BARE = rf"log(?:ger)?(?:[_.]?{_LOG_VERB})?|print(?:ln|f)?"
_LOG_CALL = (
    rf"(?<![\w$])(?:{_LOG_RECEIVER}\s*\.\s*{_LOG_VERB}\w*|{_PRINT_CALL}|{_LOG_BARE})\s*\("
)

# "token" is the most overloaded word in the keyword set: an LLM/tokenizer token
# count is not a credential. `logger.info("prompt_truncated original=%d ...",
# estimated_tokens, target_tokens, removed_count)` matched purely on the
# substring "token" inside a counter name. These spans are blanked before
# matching; a bare `token` / `access_token` / `authToken` is untouched.
_TOKEN_COUNT_NOISE = re.compile(
    r"\b(?:max|min|num|n|total|estimated|target|prompt|completion|input|output"
    r"|remaining|used|budget|context|ctx|chunk|avg|sum)[_.]?tokens?\b"
    r"|\btokens?[_.]?(?:count|used|budget|limit|estimates?|estimated|remaining"
    r"|usage|savings|saved|per[_.]?sec(?:ond)?|window|size|len(?:gth)?)\b"
    r"|\btoken(?:ize[rd]?|ization|izing)\b"
    # A path/handle NAMING a token store is not the token itself:
    # `fmt.Printf("Token saved to ~/%s/%s", configDir, tokenFile)`.
    r"|\btokens?[_.]?(?:file|filename|path|dir|store|cache)\b",
    re.IGNORECASE,
)

LOG_SENSITIVE_PATTERNS = [
    re.compile(_LOG_CALL + r".*(?:password|passwd|secret|token|api_key|apikey)", re.IGNORECASE),
    re.compile(r"(?<![\w$])logging\.(?:debug|info|warning|error)\(.*(?:password|secret|token|api_key)", re.IGNORECASE),
    re.compile(r"(?<![\w$])console\.log\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
    re.compile(r"(?<![\w$])log\.(?:Info|Debug|Warn|Error)\w*\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
]

# String literals, per language dialect. Used to drop literal MESSAGE text
# before the CWE-532 patterns run.
_STRING_LITERAL = re.compile(
    r"`(?:\\.|[^`\\])*`"                 # JS/TS template literal
    r"|'''(?:\\.|[^\\])*?'''"           # Python triple-quoted
    r'|"""(?:\\.|[^\\])*?"""'
    r"|'(?:\\.|[^'\\\n])*'"
    r'|"(?:\\.|[^"\\\n])*"'
)

# Interpolated expressions inside a literal: `${expr}` (JS) and `{expr}` (Python
# f-string / str.format). These are VALUES, not message text, so they survive the
# strip — `logging.info(f"password={password}")` must still report.
_INTERPOLATION = re.compile(r"\$\{([^{}]+)\}|\{([^{}]+)\}")


def _strip_literals(line: str) -> str:
    """Remove literal message text, keeping interpolated expressions.

    Applied before EVERY entry of LOG_SENSITIVE_PATTERNS, not just the first:
    pattern 3 (``console\\.log\\(.*(?:password|secret|token|apiKey)``) re-fires
    independently on a literal-only message, so narrowing the call shape alone
    left most of the noise in place.
    """
    def _repl(match: re.Match[str]) -> str:
        body = match.group(0).strip("`'\"")
        kept = " ".join(g for m in _INTERPOLATION.finditer(body) for g in m.groups() if g)
        return f'""{" " + kept if kept else ""}'

    return _TOKEN_COUNT_NOISE.sub("count", _STRING_LITERAL.sub(_repl, line))

# CWE-200: Exposure of sensitive info
SENSITIVE_RESPONSE_PATTERNS = [
    re.compile(r"(?:json|JSON)\w*\(.*(?:internal_path|db_host|database_url|dsn)", re.IGNORECASE),
    re.compile(r"(?:Response|response|w\.Write)\(.*(?:stack|internal|debug_info)", re.IGNORECASE),
]

# CWE-312: Cleartext storage of sensitive info
CLEARTEXT_STORAGE_PATTERNS = [
    re.compile(r"(?:password|secret|token|api_key)\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE),
    re.compile(r"(?:set|put|store|save)\w*\(.*(?:password|secret|token).*,\s*[\"']", re.IGNORECASE),
]
# Exclude safe patterns: hashing, env vars, config constants
SAFE_STORAGE = re.compile(
    r"\b(?:hash|bcrypt|encrypt|sha256|os\.(?:environ|getenv)|ENV\[|config\.|PLACEHOLDER|example|changeme|xxx)\b",
    re.IGNORECASE,
)

# CWE-497: Exposure of sensitive system information to an unauthorized control
# sphere. The instance this was written for serialises the WHOLE application
# config into an HTTP response:
#
#   const safeConfig = structuredClone(config.util.toObject(config))
#   res.json({ config: safeConfig })
#
# The dump and the send are on DIFFERENT lines, which is the normal shape, so a
# single-line regex finds nothing. The rule therefore matches a response sink
# and then resolves the identifiers it sends against nearby assignments.
_RESPONSE_SINK = re.compile(
    r"\b(?:res|resp|response|reply|w)\s*\.\s*(?:json|send|write|end)\s*\("
    r"|\bjsonify\s*\("
    r"|\bJsonResponse\s*\("
    r"|\bHttpResponse\s*\(",
    re.IGNORECASE,
)

# Expressions that materialise an ENTIRE configuration/environment object. Each
# alternative is anchored so a single lookup — `config.get('x')`,
# `process.env.NODE_ENV`, `os.environ["K"]` — does not match: reading one value
# is not a system-information dump.
_CONFIG_DUMP = re.compile(
    r"\bconfig\.util\.toObject\s*\("
    r"|\bJSON\.stringify\s*\(\s*(?:config|settings|appConfig|process\.env)\b"
    r"|\bprocess\.env\s*(?![\w.\[])"
    r"|\bdict\s*\(\s*os\.environ\s*\)"
    r"|\bos\.environ\s*(?![\w.\[(])"
    r"|\bapp\.config\s*(?![\w.\[])"
    r"|\bsettings\.__dict__\b"
    r"|\bnconf\.get\s*\(\s*\)"
    r"|\bviper\.AllSettings\s*\("
)

_ASSIGNMENT_RADIUS = 25
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
_NOT_A_VALUE = frozenset({
    "res", "resp", "response", "reply", "json", "send", "write", "end",
    "status", "jsonify", "return", "const", "let", "var", "await", "new",
    "this", "self", "type", "true", "false", "null", "undefined", "None",
})

# CWE-598: Use of GET request method with sensitive query strings. A credential
# in a query string is written to proxy logs, browser history, the Referer
# header and server access logs regardless of TLS.
_SENSITIVE_QUERY_PARAM = re.compile(
    r"[?&](?:access[_-]?token|id[_-]?token|auth[_-]?token|refresh[_-]?token"
    r"|api[_-]?key|apikey|client[_-]?secret|password|passwd|pwd|secret"
    r"|session[_-]?id|sessionid|jwt|bearer|token)\s*=",
    re.IGNORECASE,
)
# The parameter must belong to a URL, not to a `--password=` CLI flag or a
# `.env`-style line that happens to sit after an ampersand.
_URLISH = re.compile(r"https?://|[\"'`]/|\.get\s*\(|\.post\s*\(|fetch\s*\(|url|uri|endpoint|href", re.IGNORECASE)
# Non-HTTP URI schemes whose query string is not a request at all. The
# `otpauth://totp/...?secret=...` provisioning URI is the standard, unavoidable
# way to hand a TOTP seed to an authenticator app — reporting it would be
# unactionable, and CWE-598 is specifically about the GET request method.
_NON_HTTP_SCHEME = re.compile(r"\b(?:otpauth|mailto|data|magnet|tel|sms|geo|intent):", re.IGNORECASE)

IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")
STRING_ONLY = re.compile(r"^\s*[\"']")

# Two-tier context: cleartext storage is only high with database/persist context
_STORAGE_CONTEXT = [re.compile(r"(database|persist|store|save|write|insert|sqlite|postgres|mysql|redis)", re.IGNORECASE)]


def check_information_exposure(source_path: str) -> dict:
    """Check for information exposure vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of information exposure issues.
    """
    findings: list[dict] = []
    suppression_counts: dict[int, int] = {}

    # A shadow copy is a finding in its own right, whatever its contents
    # (feature 0068). Walked separately from the code scan: running this
    # inside the scan_code_files loop meant a backup was only reported if it
    # was also *parseable*. Marker stripping makes a shadow copy inherit its
    # target's exclusions, so `package-lock.json.bak` (effective name in
    # SKIP_FILES) and `notes.md.bak` (non-code extension) were silently exempt —
    # i.e. the most common backup shapes were the ones never reported.
    for backup_path in scan_backup_files(source_path):
        _check_backup_exposure(backup_path, source_path, findings)

    # CWE-219: sensitive NON-backup files under a served root. Walked separately
    # for the same reason as backups — a .kdbx/.key is never in the extension
    # allowlist, so the scan_code_files loop below can never see it, yet it leaks
    # verbatim if it sits in a mounted directory.
    _check_served_sensitive_files(source_path, findings)

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings, suppression_counts)

    return {"findings": findings}


# Directories typically reachable by an unauthenticated client. A shadow copy
# here is materially worse than one buried in src/.
_SERVED_DIRS = frozenset({
    "ftp", "public", "static", "www", "wwwroot", "htdocs", "dist", "build",
    "assets", "uploads", "files", "download", "downloads", "web",
})

# Mount declarations. Reachability is DECLARED in the source, so deriving it beats
# guessing by directory name. A fixed name list cuts both ways: it misses any
# served directory whose name nobody thought to enumerate (`encryptionkeys`,
# `attachments`, `exports`), and it mis-fires on a directory merely *named*
# `assets` that is never mounted.
_MOUNT_PATTERNS = (
    re.compile(r"express\.static\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"serveIndex\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"app\.use\(\s*['\"][^'\"]*['\"]\s*,\s*serveStatic\(\s*['\"]([^'\"]+)['\"]"),
)

# Extensions whose exposure is a finding regardless of whether we can parse them.
# Deliberately narrow: `.md`/`.txt`/`.json` are excluded because a served root
# full of documentation is normal and would drown the signal.
#
# `.asc` and `.gpg` were in this set and were REMOVED after measurement. ASCII-
# armored PGP files under a served root are usually *detached signatures* or
# public keys — CSAF/OpenVEX advisory feeds publish them at well-known paths by
# design — so the extension carries no exposure signal and the rule fired about
# as often on published artefacts as on real secrets. Private key material is
# already covered by `.key`/`.pem`/`.p12`/`.pfx`/`.ppk`.
_SENSITIVE_SERVED_SUFFIXES = frozenset({
    ".kdbx", ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".ppk",
    ".sql", ".env", ".pyc", ".ovpn", ".dump", ".sqlite", ".db",
})


def _declared_mounts(content: str) -> set[str]:
    """Mount targets declared in one file, normalised to lowercase paths."""
    return {
        match.group(1).strip("/").lower()
        for pattern in _MOUNT_PATTERNS
        for match in pattern.finditer(content)
    }


@lru_cache(maxsize=8)
def served_roots(source_path: str) -> frozenset[str]:
    """Directories reachable by an unauthenticated client.

    Code-declared mounts UNION the ``_SERVED_DIRS`` fallback names. Single source
    of truth, consumed by both CWE-552 (backup exposure) and CWE-219 — so
    resolving a mount from source improves the pre-existing detector too.

    Cached per source path, and ``read_file_safe`` is itself cached, so the mount
    sweep costs at most one pass over files the main scan reads anyway.
    """
    roots = set(_SERVED_DIRS)
    for file_path in scan_code_files(source_path):
        roots |= _declared_mounts(read_file_safe(file_path) or "")
    return frozenset(roots)


def _relative_to_root(file_path: Path, source_path: str) -> Path:
    """``file_path`` relative to the scan root, or unchanged if outside it."""
    try:
        return file_path.relative_to(source_path)
    except ValueError:
        return file_path


def _relative_parts(file_path: Path, source_path: str) -> list[str]:
    """Lowercased directory components of ``file_path`` relative to the root."""
    return [p.lower() for p in _relative_to_root(file_path, source_path).parts[:-1]]


def _is_served(parts: list[str], roots: frozenset[str]) -> bool:
    """True when any ancestor directory is a served root.

    Checks bare names and multi-segment mount paths (``frontend/dist/frontend``).
    Both are set lookups, so the test is O(depth) with constant-time membership.
    """
    if any(p in roots for p in parts):
        return True
    return any("/".join(parts[: i + 1]) in roots for i in range(len(parts)))


def _is_served_sensitive(file_path: Path, source_path: str, roots: frozenset[str]) -> bool:
    """CWE-219's predicate. Backups are excluded: CWE-552 already owns them."""
    if is_backup_name(file_path.name):
        return False
    if file_path.suffix.lower() not in _SENSITIVE_SERVED_SUFFIXES:
        return False
    return _is_served(_relative_parts(file_path, source_path), roots)


def _check_served_sensitive_files(source_path: str, findings: list[dict]) -> None:
    """CWE-219: a sensitive file stored under a web-reachable directory."""
    roots = served_roots(source_path)
    for file_path in scan_all_files(source_path):
        if not _is_served_sensitive(file_path, source_path, roots):
            continue
        rel = file_path.relative_to(source_path)
        findings.append(enrich_finding({
            "severity": "high",
            "check_id": "cwe.info_exposure.served_sensitive_file",
            "category": "CWE-219",
            "title": f"Sensitive file '{file_path.name}' under a web-served directory",
            "description": (
                f"'{rel}' has a sensitive extension and sits under a directory that "
                "is served to unauthenticated clients, so its bytes are retrievable "
                "over HTTP regardless of application-level authorization."
            ),
            "file_path": str(file_path),
            "line_start": 1,
            "line_end": 1,
            "recommendation": (
                "Move the file outside the served tree, or restrict the mount. Rotate "
                "any credential or key it contains — assume it has been fetched."
            ),
            "code_snippet": "",
        }, "219"))


def _check_backup_exposure(file_path: Path, source_path: str, findings: list[dict]) -> None:
    """Report a backup/shadow copy of source or config as an exposure.

    Precise weakness is CWE-530 (Exposure of Backup File), which the OWASP 2025
    edition does not map; we therefore categorise as the mapped parent CWE-552
    (Files or Directories Accessible to External Parties -> A01) and name
    CWE-530 in the text rather than inventing a mapping.
    """
    if not is_backup_name(file_path.name):
        return
    shadowed = effective_name(file_path.name)
    rel = _relative_to_root(file_path, source_path)
    # Shared resolver: a mount declared in code counts even when its directory
    # name is absent from _SERVED_DIRS, which previously scored such a backup
    # `medium` despite being fully reachable.
    served = _is_served(_relative_parts(file_path, source_path), served_roots(source_path))

    finding = {
        "severity": "high" if served else "medium",
        "check_id": "cwe.info_exposure.backup_file",
        "category": "CWE-552",
        "title": f"Exposed backup file '{file_path.name}' (CWE-530)",
        "description": (
            f"'{rel}' is a backup/shadow copy of '{shadowed}'. Backup files "
            "commonly retain credentials, dependency pins and logic that were "
            "deliberately removed from the live file, and are served verbatim "
            "if they sit inside the deployed tree (CWE-530)."
            + (" It is located under a publicly-served directory." if served else "")
        ),
        "file_path": str(file_path),
        "line_start": 1,
        "line_end": 1,
        "recommendation": (
            "Delete the backup from the repository/deploy artefact and keep "
            "history in version control; block backup extensions at the web server."
        ),
    }
    findings.append(enrich_finding(finding, "552"))


def _analyze_file(file_path: Path, findings: list[dict], suppression_counts: dict[int, int]) -> None:
    """Analyze a file for information exposure issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_error_disclosure(file_path, line, line_num, lines, findings)
        _check_log_sensitive(file_path, line, line_num, lines, findings, suppression_counts)
        _check_cleartext_storage(file_path, line, line_num, lines, content, findings, suppression_counts)
        _check_sensitive_response(file_path, line, line_num, lines, findings)
        _check_config_exposure(file_path, line, line_num, lines, findings)
        _check_token_in_query(file_path, line, line_num, lines, findings)


def _check_error_disclosure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for error message information disclosure (CWE-209)."""
    # Diagnostic middleware: the mount site IS the vulnerability, so it is
    # checked separately from the "error value in a response" patterns.
    if LEAKY_ERROR_MIDDLEWARE.search(line):
        if _has_env_guard(lines, line_num):
            return
        _add_disclosure(
            file_path, line_num, lines, findings,
            title="Diagnostic error middleware returns stack traces to clients",
            description=(
                f"Error-handling middleware mounted at line {line_num} without an "
                "environment guard. Packages of this kind return the stack trace and "
                "surrounding source of any unhandled error in the HTTP response, "
                "disclosing file paths, dependency versions and internal logic to "
                "unauthenticated callers."
            ),
            recommendation=(
                "Mount diagnostic error middleware only for development (guard on "
                "NODE_ENV / app.get('env')), and register a production handler that "
                "returns a generic message while logging detail server-side."
            ),
        )
        return

    # Server-side logging of an error is CWE-532's concern; without this a
    # `logger.error(err.stack)` line would match the `.stack` pattern.
    if _LOG_SINK.search(line):
        return

    for pattern in ERROR_DISCLOSURE_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        # An error-SHAPED name is not an error. `const errMsg = { err: 'not
        # supported' }` returned to the client discloses nothing, so when the
        # match is a bare identifier, check what it was assigned nearby.
        if m.groups() and m.group(1) and _holds_literal(lines, line_num, m.group(1)):
            return
        _add_disclosure(
            file_path, line_num, lines, findings,
            title="Error message information disclosure",
            description=f"Stack trace or error details exposed at line {line_num}",
            recommendation="Return generic error messages; log detailed errors server-side only",
        )
        return


def _holds_literal(lines: list[str], line_num: int, ident: str, radius: int = 6) -> bool:
    """True when ``ident`` is assigned a literal within ``radius`` lines above.

    Conservative on purpose: only a right-hand side that STARTS with a quote or
    an object brace counts, and an object brace only when it contains no
    identifier-valued field. Anything derived from a caught error
    (``e.message``, ``getErrorMessage(err)``) therefore still reports.
    """
    pat = re.compile(
        rf"(?:const|let|var)?\s*\b{re.escape(ident)}\b\s*=\s*(['\"`{{].*)$"
    )
    start = max(0, line_num - 1 - radius)
    for ln in lines[start:line_num - 1]:
        m = pat.search(ln)
        if not m:
            continue
        rhs = m.group(1).strip()
        if rhs[0] in "'\"`":
            return True
        # Object literal: every value must itself be a literal.
        if rhs.startswith("{"):
            values = re.findall(r":\s*([^,}]+)", rhs)
            if values and all(v.strip()[:1] in "'\"`" or v.strip().isdigit()
                              for v in values):
                return True
    return False


def _add_disclosure(
    file_path: Path, line_num: int, lines: list[str], findings: list[dict],
    title: str, description: str, recommendation: str,
) -> None:
    """Append a CWE-209 finding."""
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.error_disclosure",
        "category": "CWE-209",
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": recommendation,
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "209"))


def _has_env_guard(lines: list[str], line_num: int, radius: int = 8) -> bool:
    """True when an environment check sits within `radius` lines of the mount.

    Deliberately generous: gating diagnostic middleware on the environment is
    its documented safe usage, and a false negative there costs far less than
    telling every Express project its dev-only error handler is a vulnerability.
    """
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return any(_ENV_GUARD.search(ln) for ln in lines[start:end])


def _check_log_sensitive(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for sensitive data in log output (CWE-532)."""
    probe = _strip_literals(line)
    for pattern in LOG_SENSITIVE_PATTERNS:
        if not pattern.search(probe):
            continue
        finding = {
            "severity": "critical",
            "check_id": "cwe.info_exposure.log_sensitive",
            "category": "CWE-532",
            "title": "Sensitive data written to log",
            "description": f"Potential password/token/secret logged at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Never log sensitive data; use redaction or masked output",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        if should_suppress(finding["title"], file_path, line, INFO_EXPOSURE_SUPPRESSIONS, suppression_counts):
            return
        findings.append(enrich_finding(finding, "532"))
        return


def _check_cleartext_storage(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for cleartext storage of sensitive info (CWE-312).

    Suppress lines whose RHS is a variable reference — `password=$X`,
    `--build-arg STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"` etc. are env
    indirections that the static analysis can't see resolve to a
    literal.
    """
    if SAFE_STORAGE.search(line):
        return
    if line_value_is_variable_ref(line):
        return
    for pattern in CLEARTEXT_STORAGE_PATTERNS:
        if not pattern.search(line):
            continue
        # Two-tier: demote to medium if file lacks database/persist context
        severity = "critical"
        if not check_context(content, _STORAGE_CONTEXT):
            severity = "medium"
        finding = {
            "severity": severity,
            "check_id": "cwe.info_exposure.cleartext_storage",
            "category": "CWE-312",
            "title": "Cleartext storage of sensitive information",
            "description": f"Sensitive value stored in cleartext at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use environment variables, vaults, or encryption for sensitive data",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        if should_suppress(finding["title"], file_path, line, INFO_EXPOSURE_SUPPRESSIONS, suppression_counts):
            return
        findings.append(enrich_finding(finding, "312"))
        return


def _check_sensitive_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for sensitive information in responses (CWE-200)."""
    for pattern in SENSITIVE_RESPONSE_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.info_exposure.sensitive_response",
            "category": "CWE-200",
            "title": "Sensitive information exposure in response",
            "description": f"Internal details exposed in response at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Do not expose internal paths, database details, or debug info in responses",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "200"))
        return


def _dump_source(lines: list[str], line_num: int, line: str) -> str | None:
    """Return the expression that dumps a whole config into ``line``, if any.

    Same-line first (`res.json(process.env)`), then the identifiers the sink
    sends, resolved against assignments above. Only an assignment whose
    right-hand side is itself a whole-config dump counts, which is what keeps
    `res.json({ version: config.get('app.version') })` quiet.
    """
    if _CONFIG_DUMP.search(line):
        return line.strip()
    args = line[line.find("(", _RESPONSE_SINK.search(line).start()) :]
    names = {n for n in _IDENTIFIER.findall(args) if n not in _NOT_A_VALUE}
    if not names:
        return None
    start = max(0, line_num - 1 - _ASSIGNMENT_RADIUS)
    for prior in lines[start : line_num - 1]:
        if "=" not in prior or not _CONFIG_DUMP.search(prior):
            continue
        target = prior.split("=", 1)[0]
        if any(re.search(rf"\b{re.escape(n)}\b", target) for n in names):
            return prior.strip()
    return None


def _check_config_exposure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for a whole application config/environment in a response (CWE-497)."""
    if not _RESPONSE_SINK.search(line):
        return
    dump = _dump_source(lines, line_num, line)
    if dump is None:
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.config_exposure",
        "category": "CWE-497",
        "title": "Application configuration exposed in HTTP response",
        "description": (
            f"The response built at line {line_num} carries a whole-configuration "
            f"or whole-environment object (`{dump[:160]}`). Serialising the full "
            "config exposes internal hostnames, feature flags, file paths, "
            "third-party endpoints and any credential that lives in the same "
            "object to every caller of the endpoint."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Return an explicit allow-list of the settings the client actually "
            "needs instead of the whole config object, and keep secrets in a "
            "separate namespace that is never serialised."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "497"))


def _check_token_in_query(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for a credential carried in a URL query string (CWE-598)."""
    match = _SENSITIVE_QUERY_PARAM.search(line)
    if match is None:
        return
    if not _URLISH.search(line):
        return
    if _NON_HTTP_SCHEME.search(line):
        return
    param = match.group(0).strip("?&=")
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.token_in_query_string",
        "category": "CWE-598",
        "title": f"Credential '{param}' passed in a URL query string",
        "description": (
            f"Line {line_num} builds a URL that carries '{param}' as a query "
            "parameter. Query strings are recorded in browser history, proxy and "
            "web-server access logs, and are forwarded in the Referer header of "
            "any subsequent request, so the value leaks even over TLS."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Send credentials in a request header (Authorization) or a POST body "
            "instead of the query string, and rotate any token that has already "
            "been transmitted this way."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "598"))


check_information_exposure_tool = function_tool(check_information_exposure)
