"""Configuration and deployment security detection skill."""

import re
from collections.abc import Iterator
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    effective_suffix,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-1188: Insecure Default Initialization of Resource
INSECURE_DEFAULT_PATTERNS = [
    re.compile(r'(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|"true")', re.IGNORECASE),
    re.compile(r'(?:CORS_ALLOW_ALL|allow_all_origins|AllowAllOrigins)\s*[:=]\s*(?:True|true|1)', re.IGNORECASE),
    re.compile(r'(?:verify|ssl_verify|VERIFY_SSL)\s*[:=]\s*(?:False|false|0)', re.IGNORECASE),
    re.compile(r'(?:secure|SECURE)\s*[:=]\s*(?:False|false|0)', re.IGNORECASE),
    re.compile(r'(?:ALLOWED_HOSTS|allowedHosts)\s*[:=]\s*\[\s*["\']?\*["\']?\s*\]', re.IGNORECASE),
]

SAFE_DEFAULT_PATTERNS = re.compile(
    r"(?:test|spec|_test\.|\.test\.|development|dev\.config|example|sample|template)",
    re.IGNORECASE,
)

# Per-pattern Weakness CWE IDs (CWE-16 is a Category/Obsolete, not a Weakness).
#
# Each row carries a LITERAL ``"category": "CWE-N"``. The coverage extractor
# (`tests/corpus/report_coverage.py`) reads source text, not runtime values, so
# the previous `f"CWE-{cwe_id}"` construction made this whole table invisible to
# the attestation — 295/319/942/1275/1336 were emitted and counted unreachable.
MISCONFIGURATION_PATTERNS: list[tuple[re.Pattern[str], dict]] = [
    (re.compile(r"(?:bind|listen|host)\s*[:=]\s*['\"]0\.0\.0\.0['\"]"),
     {"category": "CWE-668", "title": "Service bound to all interfaces"}),
    # CWE-757 (algorithm downgrade), not CWE-326 (inadequate strength): the
    # weakness is negotiating a superseded protocol version, not a short key.
    # `(?![.\d])` rejects `TLSv1.2`; the trailing `\b` rejects the hardened
    # `PROTOCOL_TLSv1_2` constant (`1` -> `_` is not a word boundary).
    (re.compile(r'(?:TLS|tls|ssl).*(?:min|minimum).*(?:1\.0|SSLv|TLSv1(?![.\d])\b)', re.IGNORECASE),
     {"category": "CWE-757", "title": "Weak TLS/SSL protocol version negotiated"}),
    (re.compile(r'InsecureSkipVerify\s*:\s*true', re.IGNORECASE),
     {"category": "CWE-295", "title": "Certificate verification disabled"}),
    (re.compile(r'(?:HSTS|Strict-Transport-Security).*max-age\s*[:=]\s*(?:[0-9]{1,4})\b'),
     {"category": "CWE-319", "title": "Weak HSTS max-age value"}),
    # Permissive CORS — Access-Control-Allow-Origin: * in any
    # config-shape line is rarely intentional in production.
    (re.compile(r'(?:Access-Control-Allow-Origin|cors\.allow_origin\w*)\s*[:=]\s*["\']?\*', re.IGNORECASE),
     {"category": "CWE-942", "title": "Permissive CORS Access-Control-Allow-Origin: *"}),
    # Cookie SameSite=None without Secure — cross-site cookie send
    # over http.
    (re.compile(r'SameSite\s*[:=]\s*["\']?None["\']?(?![^,;\n}]*Secure)', re.IGNORECASE),
     {"category": "CWE-1275", "title": "Cookie SameSite=None without Secure attribute"}),
    # Content-Security-Policy with `unsafe-inline` or `unsafe-eval`.
    (re.compile(r'Content-Security-Policy[^"\']*["\'][^"\']*(?:unsafe-inline|unsafe-eval)', re.IGNORECASE),
     {"category": "CWE-1336", "title": "CSP includes 'unsafe-inline' / 'unsafe-eval'"}),
]

# CWE-1021: Improper Restriction of Rendered UI Layers or Frames.
#
# Positive-only: every arm names a switch that REMOVES framing protection.
# `X-Frame-Options: ALLOWALL` moved here out of MISCONFIGURATION_PATTERNS —
# skill findings are not deduplicated against each other, so leaving it in both
# places would report one weakness twice.
#
# The CSP arm is anchored `frame-ancestors\s+\*\s*(?:;|quote|$)` on purpose:
# `frame-ancestors *.partner.example.com` is a wildcard-SUBDOMAIN allowlist,
# i.e. a restriction, and calling it "framing unrestricted" is a false claim.
FRAME_PROTECTION_OFF_PATTERNS = [
    re.compile(r"frameguard\s*:\s*false", re.IGNORECASE),
    re.compile(r"xFrameOptions\s*:\s*false", re.IGNORECASE),
    re.compile(r"\.\s*frameOptions\s*\(\s*\)\s*\.\s*disable\s*\(", re.IGNORECASE),
    re.compile(r"frameOptions\s*\([^)]*(?:disable|FrameOptionsConfig::disable)", re.IGNORECASE),
    re.compile(r"@xframe_options_exempt\b"),
    re.compile(r"X[-_]FRAME[-_]OPTIONS\s*(?:[:=]\s*)?['\"]?ALLOWALL", re.IGNORECASE),
    re.compile(r"frame-ancestors\s+\*\s*(?:;|['\"]|$)", re.IGNORECASE),
]

# `ALLOW-FROM` names a specific origin and is merely unsupported by modern
# browsers: "no protection for old browsers" is a weaker claim than "framing by
# anyone", so it gets its own low-severity row.
FRAME_ALLOW_FROM_PATTERNS = [
    re.compile(r"X[-_]FRAME[-_]OPTIONS\s*(?:[:=]\s*)?['\"]?ALLOW-FROM\b", re.IGNORECASE),
]

# A report-only policy enforces nothing, so it cannot remove protection.
_CSP_REPORT_ONLY = re.compile(r"Content-Security-Policy-Report-Only", re.IGNORECASE)

# ALLOW-FROM is redundant (not a weakness) when a CSP already restricts
# framing; the `ALLOWALL` arm also keeps a single 1021 row per file.
_FRAME_ALLOW_FROM_VETO = re.compile(r"frame-ancestors|ALLOWALL", re.IGNORECASE)

# CWE-444: Inconsistent Interpretation of HTTP Requests (request smuggling).
#
# `insecureHTTPParser` is itself the enabling condition — it tells Node to
# accept the malformed framing a front-end proxy interprets differently. Only
# the switch is detected: hand-set Transfer-Encoding + Content-Length is the
# smuggling PROBE (or an HTTP proxy implementation), not the weakness.
INSECURE_HTTP_PARSER_PATTERNS = [
    re.compile(r"insecureHTTPParser\s*:\s*(?:true|1)\b"),
    re.compile(r"--insecure-http-parser\b"),
]

# CWE-426: Untrusted Search Path.
#
# Only sudoers directives that carry a loader variable across the privilege
# boundary. The `sudo -E` / `su -p` shapes are deliberately absent: measured
# 4/4 false (install docs), and a developer typing `sudo -E` inherits an
# environment they already own — no privilege boundary is crossed.
# The line must BEGIN with `Defaults`, so hardening code that merely names
# `env_keep` while scrubbing it cannot match.
SUDOERS_SEARCH_PATH_PATTERNS = [
    re.compile(
        r"^\s*Defaults\b[^\n]*\benv_keep\b[^\n]*"
        r"\b(?:PATH|LD_[A-Z_]+|DYLD_[A-Z_]+|PYTHONPATH|PERL5LIB|RUBYLIB"
        r"|NODE_PATH|CLASSPATH|GEM_PATH)\b"
    ),
    re.compile(r"^\s*Defaults\b[^\n]*!\s*env_reset\b"),
]

_SECURE_PATH = re.compile(r"secure_path\s*=")

# CWE-489: Active Debug Code. Statement-anchored breakpoint forms only — a
# lint entry naming `debugger` or a `debug: true` config value is a different
# weakness (CWE-1188/CWE-1295, already emitted above) and must not match here.
BREAKPOINT_PATTERNS = [
    re.compile(r"^\s*debugger\s*;?\s*$"),
    re.compile(r"^\s*(?:import\s+p(?:u)?db\s*;\s*)?p(?:u)?db\.set_trace\s*\(\s*\)"),
    re.compile(r"^\s*breakpoint\s*\(\s*\)\s*;?\s*$"),
    re.compile(r"^\s*binding\.(?:pry|irb)\b"),
    re.compile(r"^\s*byebug\s*;?\s*$"),
    re.compile(r"^\s*(?:System\.Diagnostics\.)?Debugger\.(?:Launch|Break)\s*\(\s*\)"),
    re.compile(r"^\s*xdebug_break\s*\(\s*\)"),
    re.compile(r"^\s*runtime\.Breakpoint\s*\(\s*\)"),
]

_NET_DEBUGGER = re.compile(r"Debugger\.(?:Launch|Break)")
_IF_DEBUG_REGION = re.compile(r"^\s*#\s*if\s+(?:DEBUG\b|!\s*RELEASE\b)")
_ENDIF_REGION = re.compile(r"^\s*#\s*endif\b")
_ENV_GATED = re.compile(
    r"\bif\b[^\n]*(?:os\.getenv\s*\(|process\.env\b|ENV\[|getenv\s*\()"
)
_DEBUG_REGION_LOOKBACK = 10

# CWE-732: Incorrect Permission Assignment for Critical Resource.
#
# This list names ONE resource whose permission is wrong. The default-permission
# list below (CWE-276) is deliberately disjoint from it: the two are tried in
# order and at most one row is emitted per line, so a permission line can never
# carry both. `umask` moved to that list — a creation mask is not a permission
# on any particular resource, it is the default every later resource inherits.
PERMISSION_PATTERNS = [
    re.compile(r"chmod\s+(?:666|667|776|777)\b"),
    re.compile(r"os\.chmod\([^)]*0o?(?:666|667|776|777)"),
    re.compile(r'(?:mode|perm)\s*[:=]\s*0o?(?:666|667|776|777)'),
    re.compile(r"os\.MkdirAll\([^)]*0o?777\)"),
]

# An octal mode whose final digit grants write to `other`. The lookbehind and
# the trailing `\b` keep it from matching a slice of a longer number: `2775`
# (setgid, group-writable) must not read as `277`.
_WORLD_WRITABLE_MODE = r"(?<![0-7])0?o?[0-7]{2}[2367]\b"

# CWE-276: Incorrect Default Permissions.
#
# The weakness is the DEFAULT that everything created or installed by the recipe
# inherits, not one named resource:
#   * a cleared creation mask — every file the process later writes is
#     world-writable, whatever mode the calling code asks for;
#   * a recursive install-time grant over a whole tree;
#   * a build-time `--chmod=` copy, which stamps the mode onto every copied
#     file;
#   * a mount-wide `defaultMode`, which is the projection default for every key
#     in the mounted secret/config volume.
# `umask 077`, `chmod -R 755`, `--chmod=644` and `defaultMode: 0400` are the
# correct forms of each and stay silent.
DEFAULT_PERMISSION_PATTERNS = [
    re.compile(r"\bumask\s*\(\s*0(?:o?0*)\s*\)"),
    re.compile(r"\bumask\s+0{1,4}(?![0-7])"),
    # systemd. Reached through the `.conf` walk (a drop-in override), which is
    # the form that ships inside a repository; a packaged `.service` unit is
    # outside every skill's extension set.
    re.compile(r"^\s*UMask\s*=\s*0{3,4}\s*$"),
    re.compile(
        r"\bchmod\s+(?:-[A-Za-z]*R[A-Za-z]*|--recursive)\s+"
        r"(?:" + _WORLD_WRITABLE_MODE + r"|(?:a|o|go|ugo)\+w\b|a=rwx\b)"
    ),
    re.compile(r"--chmod=" + _WORLD_WRITABLE_MODE),
    re.compile(r"\bdefaultMode\s*:\s*['\"]?" + _WORLD_WRITABLE_MODE),
]

SAFE_PERMISSION_PATTERNS = re.compile(
    r"(?:temp|tmp|cache|test|spec|example)",
    re.IGNORECASE,
)

# CWE-15: External Control of System or Configuration Setting.
#
# BOTH halves must be on the line: a process-wide setting being WRITTEN, and a
# request-derived value (or a request-derived KEY) as what it is written from.
# The sink on its own is ordinary configuration code — `process.env.PORT = 3000`
# and `System.setProperty("user.timezone", "UTC")` are how applications are
# configured — so the source token is what makes it a weakness. Reading a
# setting through a request-supplied key is not control and is not matched:
# the assignment `=` is required, and `==` is excluded.
_REQUEST_SOURCE = (
    r"(?:req(?:uest)?\s*\.\s*(?:query|body|params?|headers?|args|form|json|"
    r"values|cookies|GET|POST|getParameter|getHeader|get_json|form_data)"
    r"|\$_(?:GET|POST|REQUEST|COOKIE)\b)"
)

_SETTING_SINK = r"(?:process\s*\.\s*env|os\s*\.\s*environ|(?<![\w.])ENV)"

EXTERNAL_SETTING_PATTERNS = [
    # Value comes from the request: process.env.X = req.query.v
    re.compile(
        _SETTING_SINK + r"\s*(?:\[[^\]]*\]|\.\w+)\s*=(?!=)[^=]*" + _REQUEST_SOURCE
    ),
    # Key comes from the request: process.env[req.body.name] = "on"
    re.compile(
        _SETTING_SINK + r"\s*\[[^\]]*" + _REQUEST_SOURCE + r"[^\]]*\]\s*=(?!=)"
    ),
    # Call-shaped setting writers (JVM system property, PHP ini/env).
    re.compile(
        r"(?:System\.setProperty|putenv|apache_setenv|ini_set)\s*\("
        r"[^)]*" + _REQUEST_SOURCE
    ),
]

# CWE-668: Exposure of Resource to Wrong Sphere
EXPOSURE_PATTERNS = [
    re.compile(r"(?:EXPOSE|expose)\s+(?:22|3306|5432|6379|27017)\b"),
    re.compile(r'(?:bind|host).*["\']0\.0\.0\.0["\'].*(?:3306|5432|6379|27017|9200)', re.IGNORECASE),
    re.compile(r"(?:public|PUBLIC)\s*[:=]\s*(?:True|true|1)", re.IGNORECASE),
]

# CWE-1295: Debug Features Enabled in Production
DEBUG_PROD_PATTERNS = [
    re.compile(r"(?:app|server|flask)\.(?:run|debug)\s*\([^)]*debug\s*=\s*True", re.IGNORECASE),
    re.compile(r"(?:DEBUG|debug)\s*=\s*(?:True|true|1)\s*#?\s*(?!.*(?:test|dev|local))", re.IGNORECASE),
    re.compile(r'(?:devtools|debugger|profiler)\s*[:=]\s*(?:True|true|enabled)', re.IGNORECASE),
    re.compile(r"(?:stacktrace|stack_trace|verbose_errors)\s*[:=]\s*(?:True|true|1)", re.IGNORECASE),
]

SAFE_DEBUG_PATTERNS = re.compile(
    r"(?:test|spec|development|dev\.|local|__name__.*__main__|if.*DEBUG)",
    re.IGNORECASE,
)

# CWE-942: Permissive Cross-domain Policy with Untrusted Domains.
#
# The header form (`Access-Control-Allow-Origin: *`) is already covered
# per-line by MISCONFIGURATION_PATTERNS above. What that misses is the
# *middleware* form, which is how a real Express app opens itself up:
# `cors()` with no options reflects any Origin — the "allow everything so the
# CORS problems go away" shortcut. Also caught: an explicit `origin: true` / `origin: '*'`
# in the options object, and the two-argument setHeader form that the
# `[:=]`-shaped header pattern cannot see.
#
# Reported ONCE PER FILE: `app.options('*', cors())` immediately followed
# by `app.use(cors())` is one misconfiguration, not two.
PERMISSIVE_CORS_PATTERNS = [
    re.compile(r"(?<![\w.])cors\s*\(\s*\)"),
    re.compile(r"(?<![\w.])cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['\"]\*['\"])", re.IGNORECASE),
    re.compile(
        r"(?:setHeader|addHeader|append|header|set)\s*\(\s*"
        r"['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]",
        re.IGNORECASE,
    ),
]

# CWE-348: Use of Less Trusted Source.
#
# Unconditional `trust proxy` makes X-Forwarded-For client-controlled, so
# every downstream consumer of req.ip — rate limiters, login throttles,
# audit logs, IP allowlists — can be spoofed by any client
# (`app.set('trust proxy', true)`). A bounded hop count (`trust proxy: 1`) is
# the recommended config and is NOT flagged.
TRUST_PROXY_PATTERNS = [
    re.compile(r"\.\s*enable\s*\(\s*['\"]trust[ _-]?proxy['\"]\s*\)", re.IGNORECASE),
    re.compile(
        r"\.\s*set\s*\(\s*['\"]trust[ _-]?proxy['\"]\s*,\s*(?:true|['\"]\*['\"])",
        re.IGNORECASE,
    ),
    re.compile(r"trust[_-]proxy\s*[:=]\s*(?:true|['\"]\*['\"])", re.IGNORECASE),
]

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

# Two-tier context: debug mode is only high with production/deploy context
_DEBUG_CONTEXT = [re.compile(r"(production|deploy|release|staging|prod|gunicorn|uwsgi)", re.IGNORECASE)]

# Configuration files to scan
CONFIG_EXTENSIONS = frozenset({
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".json",
})

# Dialects walked ONLY for the breakpoint check (CWE-489). Deliberately a
# separate walk instead of widening CONFIG_EXTENSIONS: widening exposes all 25
# existing patterns to a new file population (measured: +1 row, itself an FP),
# whereas this pass runs one statement-anchored predicate. `.tsx`/`.jsx` matter
# most — a React component is the likeliest home of a forgotten `debugger;`.
DEBUG_CODE_EXTENSIONS = frozenset({".tsx", ".jsx", ".mjs", ".cjs", ".php", ".cs"})

# XML/config dialects walked ONLY for the four XML checks below (CWE-5, CWE-11,
# CWE-756, CWE-926). Same reasoning: adding `.xml` to CONFIG_EXTENSIONS would
# expose every existing pattern to every POM/Spring/Ant/strings file in every
# Java repo — an unmeasured blast radius for zero measured gain.
XML_EXTENSIONS = frozenset({".xml", ".config", ".csproj"})

# Shell dialects walked ONLY for the default-permission check (CWE-276). An
# install/provision script is where a recursive world-writable grant and a
# cleared creation mask actually live, and neither has a `.py`/`.yml` home. Same
# containment reasoning as the two walks above: one predicate list, not all 25.
INSTALL_SCRIPT_EXTENSIONS = frozenset({".sh", ".bash", ".zsh"})

# Real sudoers files carry no extension. `sudoers.d` members have arbitrary
# basenames and remain out of reach (they would need a shared scanner change).
_CONFIG_EXTRA_FILENAMES = frozenset({"sudoers"})
_NO_EXTRA_FILENAMES: frozenset[str] = frozenset()


def check_configuration(source_path: str) -> dict:
    """Check for configuration and deployment security issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of configuration vulnerabilities.
    """
    findings: list[dict] = []
    for extensions, extras, analyze in _WALKS:
        _walk(source_path, extensions, extras, analyze, findings)
    return {"findings": findings}


def _walk(source_path: str, extensions: frozenset[str], extras: frozenset[str],
          analyze, findings: list[dict]) -> None:
    """Run one analysis pass over the files matching ``extensions``."""
    for file_path in scan_code_files(
        source_path, extensions=extensions, extra_filenames=extras,
    ):
        if _skip_file(file_path):
            continue
        analyze(file_path, findings)


def _skip_file(file_path: Path) -> bool:
    """True for files whose content is not this project's executable config."""
    return (
        is_generated_file(file_path)
        or is_test_file(file_path)
        or is_prose_file(file_path)
    )


def _wrong_walk(file_path: Path, extensions: frozenset[str]) -> bool:
    """True when a canonical extensionless file (Dockerfile, .npmrc) was folded
    into a specialised walk by ``WELL_KNOWN_FILENAMES``.

    Those files belong to the main pass; re-analysing them in a specialised pass
    would report the same line twice (skill findings are not deduplicated
    against each other).
    """
    return effective_suffix(file_path.name) not in extensions


def _iter_code_lines(lines: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    """Yield (1-based line number, text) for lines that are not comments."""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        yield line_num, line


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for configuration security issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    for line_num, line in _iter_code_lines(lines):
        # Before the import guard: `import pdb; pdb.set_trace()` is an import
        # line AND a live breakpoint.
        _check_active_debug_code(file_path, line, line_num, lines, findings)
        _check_config_line(file_path, line, line_num, lines, content, findings)
    _check_cors_and_trust_proxy(file_path, lines, findings)
    _check_file_level(file_path, lines, content, findings)


def _check_config_line(
    file_path: Path, line: str, line_num: int, lines: tuple[str, ...],
    content: str, findings: list[dict],
) -> None:
    """Run every per-line configuration check on one candidate line."""
    if _skip_line(line, None):
        return
    _check_insecure_defaults(file_path, line, line_num, lines, findings)
    _check_misconfiguration(file_path, line, line_num, lines, findings)
    _check_permissions(file_path, line, line_num, lines, findings)
    _check_exposure(file_path, line, line_num, lines, findings)
    _check_debug_prod(file_path, line, line_num, lines, content, findings)
    _check_external_control(file_path, line, line_num, lines, findings)


def _specialised_lines(
    file_path: Path, extensions: frozenset[str],
) -> tuple[str, ...] | None:
    """The file's lines, or None when it does not belong to this walk."""
    if _wrong_walk(file_path, extensions):
        return None
    return read_file_lines(file_path)


def _analyze_dialects(file_path: Path, findings: list[dict]) -> None:
    """Breakpoint + external-control pass over dialects outside ``CONFIG_EXTENSIONS``.

    `.php` is why the external-control check runs here: `ini_set`/`putenv` have
    no other home. The JS dialects carry the `process.env` arms.
    """
    lines = _specialised_lines(file_path, DEBUG_CODE_EXTENSIONS)
    if lines is None:
        return
    for line_num, line in _iter_code_lines(lines):
        # Before the skip guard, as in the main pass: an import line can carry
        # a live breakpoint.
        _check_active_debug_code(file_path, line, line_num, lines, findings)
        if not _skip_line(line, None):
            _check_external_control(file_path, line, line_num, lines, findings)


def _analyze_install_script(file_path: Path, findings: list[dict]) -> None:
    """Default-permission-only pass over shell install scripts."""
    lines = _specialised_lines(file_path, INSTALL_SCRIPT_EXTENSIONS)
    if lines is None:
        return
    for line_num, line in _iter_code_lines(lines):
        if not _skip_line(line, None):
            _check_default_permissions(file_path, line, line_num, lines, findings)


def _skip_line(line: str, line_veto: re.Pattern[str] | None) -> bool:
    """True when a line is an import, a scanner pattern table, or vetoed."""
    if IMPORT_LINE.match(line) or SCANNER_DEF_LINE.search(line):
        return True
    return line_veto is not None and bool(line_veto.search(line))


def _line_matches(line: str, patterns: list[re.Pattern[str]]) -> bool:
    """True when any pattern matches the line."""
    return any(pattern.search(line) for pattern in patterns)


def _matching_lines(
    lines: tuple[str, ...], patterns: list[re.Pattern[str]],
    line_veto: re.Pattern[str] | None = None,
) -> list[int]:
    """Return 1-based line numbers where any pattern matches real code."""
    hits: list[int] = []
    for line_num, line in _iter_code_lines(lines):
        if _skip_line(line, line_veto):
            continue
        if _line_matches(line, patterns):
            hits.append(line_num)
    return hits


def _check_cors_and_trust_proxy(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Check for CWE-942 permissive CORS and CWE-348 unconditional proxy trust.

    File-level, not line-level: a file that opens CORS twice in adjacent
    lines has one misconfiguration.
    """
    cors_hits = _matching_lines(lines, PERMISSIVE_CORS_PATTERNS)
    if cors_hits:
        findings.append(_cors_finding(file_path, lines, cors_hits))
    proxy_hits = _matching_lines(lines, TRUST_PROXY_PATTERNS)
    if proxy_hits:
        findings.append(_trust_proxy_finding(file_path, lines, proxy_hits))


def _cors_finding(file_path: Path, lines: list[str], hits: list[int]) -> dict:
    """Build the CWE-942 permissive-CORS finding for a file."""
    finding = {
        "severity": "high",
        "check_id": "cwe.configuration.permissive_cors",
        "category": "CWE-942",
        "title": "CORS enabled with no origin restriction",
        "description": (
            f"Cross-origin access is granted to any origin at "
            f"line(s) {', '.join(str(n) for n in hits)}; combined with "
            f"credentialed requests this lets any site read authenticated "
            f"responses on behalf of a logged-in user"
        ),
        "file_path": str(file_path),
        "line_start": hits[0],
        "line_end": hits[-1],
        "recommendation": (
            "Pass an explicit origin allowlist to the CORS middleware and never "
            "reflect an arbitrary Origin alongside credentials"
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, hits[0])
    return enrich_finding(finding, "942")


def _trust_proxy_finding(file_path: Path, lines: list[str], hits: list[int]) -> dict:
    """Build the CWE-348 unconditional-trust-proxy finding for a file."""
    finding = {
        "severity": "medium",
        "check_id": "cwe.configuration.trust_proxy",
        "category": "CWE-348",
        "title": "Proxy headers trusted unconditionally",
        "description": (
            f"`trust proxy` is enabled without bounding the hop count at "
            f"line(s) {', '.join(str(n) for n in hits)}, so a client can set "
            f"X-Forwarded-For and control req.ip — spoofing rate limits, login "
            f"throttles, IP allowlists and audit logs. Note CWE-348 has no "
            f"OWASP Top 10 2025 category, so it is reported on its own"
        ),
        "file_path": str(file_path),
        "line_start": hits[0],
        "line_end": hits[-1],
        "recommendation": (
            "Trust a bounded number of hops (e.g. app.set('trust proxy', 1)) or "
            "name the proxy addresses explicitly"
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, hits[0])
    return enrich_finding(finding, "348")


def _check_insecure_defaults(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-1188 insecure default initialization."""
    if SAFE_DEFAULT_PATTERNS.search(file_path.name):
        return
    for pattern in INSECURE_DEFAULT_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.configuration.insecure_default",
                "category": "CWE-1188",
                "title": "Insecure default configuration",
                "description": f"Insecure default value at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use secure defaults: disable debug, restrict CORS, enable SSL verification",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1188"))
            return


def _check_misconfiguration(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for configuration issues mapped to specific Weakness CWE IDs."""
    for pattern, spec in MISCONFIGURATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.configuration.misconfiguration",
                "category": spec["category"],
                "title": spec["title"],
                "description": f"Potentially insecure configuration at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Bind to localhost, enforce TLS 1.2+, enable certificate verification",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, _cwe_id(spec)))
            return


def _cwe_id(spec: dict) -> str:
    """Numeric id from a spec's literal ``"category": "CWE-N"`` value."""
    return spec["category"].removeprefix("CWE-")


_DEFAULT_PERMISSION_FINDING = {
    "severity": "high",
    "check_id": "cwe.configuration.default_permissions",
    "category": "CWE-276",
    "title": "World-modifiable default permissions",
    "description": (
        "The default permission applied to everything this recipe creates or "
        "installs grants write access to every local account, so any user on "
        "the host can replace application files or read the data they hold"
    ),
    "recommendation": (
        "Keep a restrictive creation mask (umask 027 or 077) and grant the "
        "narrowest recursive mode the runtime user needs (0755 directories, "
        "0644 files, 0400 for mounted secrets)"
    ),
}

_CRITICAL_PERMISSION_FINDING = {
    "severity": "high",
    "check_id": "cwe.configuration.overly_permissive",
    "category": "CWE-732",
    "title": "Overly permissive file permissions",
    "description": "World-writable or overly permissive permissions",
    "recommendation": "Use restrictive permissions (0644 for files, 0755 for directories)",
}

# Ordered most-specific-first. One line yields at most ONE permission row: the
# default-permission idioms and the single-resource idioms are disjoint, and the
# early return keeps them that way even if a future arm blurs the boundary.
DEFAULT_PERMISSION_CHECKS: list[tuple[list[re.Pattern[str]], dict]] = [
    (DEFAULT_PERMISSION_PATTERNS, _DEFAULT_PERMISSION_FINDING),
]

PERMISSION_CHECKS: list[tuple[list[re.Pattern[str]], dict]] = [
    *DEFAULT_PERMISSION_CHECKS,
    (PERMISSION_PATTERNS, _CRITICAL_PERMISSION_FINDING),
]


def _emit_permission_row(
    file_path: Path, line: str, line_num: int, lines: list[str],
    checks: list[tuple[list[re.Pattern[str]], dict]], findings: list[dict],
) -> None:
    """Emit the first matching permission row for a line, or none."""
    if SAFE_PERMISSION_PATTERNS.search(file_path.name):
        return
    for patterns, base in checks:
        if _line_matches(line, patterns):
            findings.append(_line_finding(file_path, lines, line_num, base))
            return


def _check_permissions(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-276 default permissions and CWE-732 permission assignment."""
    _emit_permission_row(
        file_path, line, line_num, lines, PERMISSION_CHECKS, findings,
    )


def _check_default_permissions(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-276 only.

    The shell walk stops here on purpose. `chmod 777 <one path>` in a script is
    already reported by the access-control skill (CWE-269), and skill findings
    are not deduplicated against each other — running the CWE-732 arm over the
    same population would put two rows on that one line.
    """
    _emit_permission_row(
        file_path, line, line_num, lines, DEFAULT_PERMISSION_CHECKS, findings,
    )


_EXTERNAL_SETTING_FINDING = {
    "severity": "high",
    "check_id": "cwe.configuration.external_control_setting",
    "category": "CWE-15",
    "title": "System setting written from request data",
    "description": (
        "A process-wide setting (environment variable, JVM system property or "
        "PHP ini entry) is written from request-controlled data, so a caller "
        "chooses configuration that the whole process — including other "
        "requests — then runs under"
    ),
    "recommendation": (
        "Never write request data into process settings. Map the input to a "
        "fixed allowlist of permitted values and keep it in request scope"
    ),
}


def _check_external_control(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-15 external control of a system/configuration setting."""
    if _line_matches(line, EXTERNAL_SETTING_PATTERNS):
        findings.append(
            _line_finding(file_path, lines, line_num, _EXTERNAL_SETTING_FINDING)
        )


def _check_exposure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-668 resource exposure to wrong sphere."""
    for pattern in EXPOSURE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.configuration.resource_exposure",
                "category": "CWE-668",
                "title": "Resource exposed to wrong sphere",
                "description": f"Internal service port or resource publicly exposed at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Bind internal services to localhost; use network policies to restrict access",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "668"))
            return


def _check_debug_prod(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict],
) -> None:
    """Check for CWE-1295 debug features in production."""
    if SAFE_DEBUG_PATTERNS.search(file_path.name):
        return
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_DEBUG_PATTERNS.search(context):
        return
    for pattern in DEBUG_PROD_PATTERNS:
        if pattern.search(line):
            # Two-tier: demote to medium if file lacks production/deploy context
            severity = "high"
            if not check_context(content, _DEBUG_CONTEXT):
                severity = "medium"
            finding = {
                "severity": severity,
                "check_id": "cwe.configuration.debug_enabled",
                "category": "CWE-1295",
                "title": "Debug features enabled in production",
                "description": f"Debug mode or verbose errors enabled at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Disable debug mode and verbose error output in production deployments",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1295"))
            return


# ── file-level checks (one row per file) ──────────────────────────────────
#
# Each spec is `patterns` + optional `line_veto` (a line that matches it can
# never be a hit) + optional `file_veto` (any occurrence anywhere in the file
# suppresses the whole rule) + the finding template, whose `category` is a
# LITERAL so the coverage extractor can see it.
FILE_LEVEL_CHECKS: list[dict] = [
    {
        "patterns": FRAME_PROTECTION_OFF_PATTERNS,
        "line_veto": _CSP_REPORT_ONLY,
        "file_veto": None,
        "finding": {
            "severity": "medium",
            "check_id": "cwe.configuration.frame_protection",
            "category": "CWE-1021",
            "title": "Framing protection disabled",
            "description": "Frame/clickjacking protection is switched off",
            "recommendation": (
                "Keep X-Frame-Options DENY/SAMEORIGIN (or helmet's frameguard) "
                "and name the permitted embedders in a CSP frame-ancestors "
                "directive instead of allowing any origin"
            ),
        },
    },
    {
        "patterns": FRAME_ALLOW_FROM_PATTERNS,
        "line_veto": None,
        "file_veto": _FRAME_ALLOW_FROM_VETO,
        "finding": {
            "severity": "low",
            "check_id": "cwe.configuration.frame_allow_from",
            "category": "CWE-1021",
            "title": "X-Frame-Options ALLOW-FROM is not honoured",
            "description": (
                "X-Frame-Options ALLOW-FROM is unsupported by every modern "
                "browser, so the intended single-origin restriction is not "
                "enforced"
            ),
            "recommendation": (
                "Replace ALLOW-FROM with a Content-Security-Policy "
                "frame-ancestors directive naming the same origin"
            ),
        },
    },
    {
        "patterns": INSECURE_HTTP_PARSER_PATTERNS,
        "line_veto": None,
        "file_veto": None,
        "finding": {
            "severity": "high",
            "check_id": "cwe.configuration.insecure_http_parser",
            "category": "CWE-444",
            "title": "Lenient HTTP parser enabled",
            "description": (
                "The HTTP parser is told to accept malformed request framing, "
                "which is the enabling condition for request smuggling when a "
                "front-end proxy interprets that framing differently"
            ),
            "recommendation": (
                "Remove insecureHTTPParser / --insecure-http-parser and fix the "
                "upstream client that emits non-conforming requests"
            ),
        },
    },
    {
        "patterns": SUDOERS_SEARCH_PATH_PATTERNS,
        "line_veto": None,
        "file_veto": _SECURE_PATH,
        "finding": {
            "severity": "medium",
            "check_id": "cwe.configuration.untrusted_search_path",
            "category": "CWE-426",
            "title": "Loader search path preserved across privilege boundary",
            "description": (
                "A sudoers directive carries a loader variable (PATH/LD_*/"
                "PYTHONPATH/CLASSPATH) into the privileged environment, so an "
                "unprivileged caller chooses which library the privileged "
                "process loads"
            ),
            "recommendation": (
                "Keep env_reset enabled, drop loader variables from env_keep, "
                "and set an explicit secure_path"
            ),
        },
    },
]


def _check_file_level(
    file_path: Path, lines: tuple[str, ...], content: str, findings: list[dict],
) -> None:
    """Run every file-level (one-row-per-file) check."""
    for spec in FILE_LEVEL_CHECKS:
        _apply_file_level(file_path, lines, content, spec, findings)


def _apply_file_level(
    file_path: Path, lines: tuple[str, ...], content: str, spec: dict,
    findings: list[dict],
) -> None:
    """Emit at most one finding for ``spec`` over the whole file."""
    veto = spec["file_veto"]
    if veto is not None and veto.search(content):
        return
    hits = _matching_lines(lines, spec["patterns"], spec["line_veto"])
    if hits:
        findings.append(_file_level_finding(file_path, lines, hits, spec["finding"]))


def _file_level_finding(
    file_path: Path, lines: tuple[str, ...], hits: list[int], base: dict,
) -> dict:
    """Build one finding from a file-level spec template."""
    finding = dict(base)
    finding["description"] = (
        f"{base['description']} at line(s) "
        f"{', '.join(str(n) for n in hits)}"
    )
    finding["file_path"] = str(file_path)
    finding["line_start"] = hits[0]
    finding["line_end"] = hits[-1]
    finding["code_snippet"] = extract_snippet(lines, hits[0])
    return enrich_finding(finding, _cwe_id(base))


# ── CWE-489: active debug code ────────────────────────────────────────────


def _check_active_debug_code(
    file_path: Path, line: str, line_num: int, lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Check for a live breakpoint statement left in shipped code."""
    if not _line_matches(line, BREAKPOINT_PATTERNS):
        return
    if _debug_gate_present(lines, line_num, line):
        return
    finding = {
        "severity": "medium",
        "check_id": "cwe.configuration.active_debug_code",
        "category": "CWE-489",
        "title": "Active debug code (breakpoint statement)",
        "description": (
            f"A breakpoint statement at line {line_num} halts execution or "
            f"attaches a debugger in whatever environment the code runs in"
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Remove the breakpoint statement; gate deliberate debugger "
            "attachment behind an environment flag or a compile-time region"
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "489"))


def _debug_gate_present(lines: tuple[str, ...], line_num: int, line: str) -> bool:
    """True when the breakpoint is env-gated or compiled out of Release."""
    if _ENV_GATED.search(_previous_code_line(lines, line_num)):
        return True
    return bool(_NET_DEBUGGER.search(line)) and _in_debug_region(lines, line_num)


def _previous_code_line(lines: tuple[str, ...], line_num: int) -> str:
    """The nearest preceding non-blank line ('' when there is none)."""
    for idx in range(line_num - 2, -1, -1):
        if lines[idx].strip():
            return lines[idx]
    return ""


def _in_debug_region(lines: tuple[str, ...], line_num: int) -> bool:
    """True when the line sits inside an open ``#if DEBUG`` region."""
    floor = max(0, line_num - 1 - _DEBUG_REGION_LOOKBACK)
    for idx in range(line_num - 2, floor - 1, -1):
        if _ENDIF_REGION.match(lines[idx]):
            return False
        if _IF_DEBUG_REGION.match(lines[idx]):
            return True
    return False


# ── XML / .config dialects ────────────────────────────────────────────────

_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_XDT_TRANSFORM = re.compile(r"xdt:(?:Transform|Locator)", re.IGNORECASE)
_SYSTEM_WEB = re.compile(r"<system\.web\b", re.IGNORECASE)

# CWE-756 (missing custom error page) and CWE-11 (ASP.NET debug binary).
# The CWE-11 gate is `<system.web`, NOT `<configuration` — the latter is also
# the root element of nuget.config and packages.config.
XML_TOKEN_CHECKS: list[dict] = [
    {
        "patterns": [
            re.compile(r"<\s*customErrors\b[^>]*\bmode\s*=\s*[\"']Off[\"']", re.IGNORECASE),
            re.compile(r"<\s*httpErrors\b[^>]*\berrorMode\s*=\s*[\"']Detailed[\"']", re.IGNORECASE),
        ],
        "gate": None,
        "finding": {
            "severity": "medium",
            "check_id": "cwe.configuration.missing_custom_error_page",
            "category": "CWE-756",
            "title": "Custom error page disabled",
            "description": (
                "Error handling falls through to the framework's own detailed "
                "error page, which discloses stack traces, physical paths and "
                "framework versions to remote callers"
            ),
            "recommendation": (
                "Set customErrors mode=\"RemoteOnly\" (or \"On\") with a "
                "defaultRedirect, and httpErrors errorMode=\"Custom\""
            ),
        },
    },
    {
        "patterns": [
            re.compile(r"<compilation\b[^>]*\bdebug\s*=\s*[\"']true[\"']", re.IGNORECASE),
        ],
        "gate": _SYSTEM_WEB,
        "finding": {
            "severity": "medium",
            "check_id": "cwe.configuration.aspnet_debug_binary",
            "category": "CWE-11",
            "title": "ASP.NET compiled with debug enabled",
            "description": (
                "The application is compiled as a debug binary: timeouts are "
                "disabled, output is unoptimised and error pages carry source "
                "and path detail"
            ),
            "recommendation": (
                "Set debug=\"false\" for deployed configurations and keep the "
                "debug switch to local build transforms only"
            ),
        },
    },
]

# The SDK-style signal is optimisation being OFF or DEBUG being defined in a
# Release build. `<DebugType>portable</DebugType>` is the Release DEFAULT and
# emitting a portable PDB is recommended practice — it is never a finding.
_RELEASE_PROPERTY_GROUP = re.compile(
    r"<PropertyGroup\b[^>]*Condition\s*=\s*\"[^\"]*Release[^\"]*\"[^>]*>"
    r".*?</PropertyGroup\s*>",
    re.IGNORECASE | re.DOTALL,
)
_OPTIMIZE_OFF = re.compile(r"<Optimize>\s*false\s*</Optimize>", re.IGNORECASE)
_DEFINE_DEBUG = re.compile(r"<DefineConstants>[^<]*\bDEBUG\b", re.IGNORECASE)

_SDK_DEBUG_FINDING = {
    "severity": "medium",
    "check_id": "cwe.configuration.aspnet_debug_binary",
    "category": "CWE-11",
    "title": "Release build produces a debug binary",
    "description": (
        "The Release configuration disables optimisation or defines DEBUG, so "
        "the shipped assembly is a debug build"
    ),
    "recommendation": (
        "Remove <Optimize>false</Optimize> and the DEBUG constant from Release "
        "property groups; a portable PDB alone is fine"
    ),
}

# CWE-5: J2EE data transmission without encryption.
_WEB_APP = re.compile(r"<web-app\b", re.IGNORECASE)
_SECURITY_CONSTRAINT = re.compile(
    r"<security-constraint\b.*?</security-constraint\s*>", re.IGNORECASE | re.DOTALL,
)
_TRANSPORT_GUARANTEE = re.compile(
    r"<transport-guarantee>\s*(?:CONFIDENTIAL|INTEGRAL)\s*</transport-guarantee>",
    re.IGNORECASE,
)
# A role-less or self-closing <auth-constraint> is the standard deny-all idiom
# (e.g. for /WEB-INF/*): no credential ever crosses that wire, so a transport
# guarantee is meaningless there and flagging it is pure noise.
_ROLE_PROTECTED = re.compile(
    r"<auth-constraint\b(?![^>]*/>).*?<role-name>\s*\S", re.IGNORECASE | re.DOTALL,
)
_URL_PATTERN = re.compile(r"<url-pattern>\s*([^<]*?)\s*</url-pattern>", re.IGNORECASE)

_J2EE_FINDING = {
    "severity": "low",
    "check_id": "cwe.configuration.j2ee_cleartext_transport",
    "category": "CWE-5",
    "title": "Role-protected resource with no transport guarantee",
    "description": (
        "A security-constraint authenticates a named role but names no "
        "transport guarantee, so the container will serve it over cleartext "
        "HTTP and the credentials and session cookie travel in the clear"
    ),
    "recommendation": (
        "Add <user-data-constraint><transport-guarantee>CONFIDENTIAL"
        "</transport-guarantee></user-data-constraint>, or record that TLS "
        "terminates upstream and the connector is not reachable in cleartext"
    ),
}

# CWE-926: improper export of Android application components.
_ANDROID_MANIFEST = re.compile(r"<manifest\b", re.IGNORECASE)
_ANDROID_NS = re.compile(
    r"xmlns:android\s*=\s*[\"']http://schemas\.android\.com/apk/res/android[\"']",
)
_ANDROID_ELEMENT = re.compile(
    r"<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(/?)>",
    re.DOTALL,
)
_ANDROID_EXPORTED = re.compile(r"android:exported\s*=\s*[\"']true[\"']", re.IGNORECASE)
_ANDROID_PERMISSION = re.compile(
    r"android:(?:permission|readPermission|writePermission)\s*=", re.IGNORECASE,
)
_ANDROID_GRANT_URI = re.compile(
    r"android:grantUriPermissions\s*=\s*[\"']true[\"']", re.IGNORECASE,
)
_ANDROID_NAME = re.compile(r"android:name\s*=\s*[\"']([^\"']+)[\"']")
_TOOLS_NODE_REMOVE = re.compile(r"tools:node\s*=\s*[\"']remove", re.IGNORECASE)
# MAIN or LAUNCHER — OR, never AND: a formatting variant or a truncated body
# must never be able to turn the app entry point into a finding. The remaining
# actions are framework contracts that REQUIRE the component to be exported.
_ANDROID_CONTRACT_ACTION = re.compile(
    r"android\.intent\.category\.LAUNCHER"
    r"|android\.intent\.action\.MAIN"
    r"|android\.intent\.action\.BOOT_COMPLETED"
    r"|android\.accessibilityservice\.AccessibilityService"
    r"|android\.service\.quicksettings\.TileService"
    r"|android\.content\.SyncAdapter"
    r"|android\.view\.InputMethod"
    r"|android\.appwidget\.action\.APPWIDGET_UPDATE"
    r"|android\.app\.action\.DEVICE_ADMIN_ENABLED"
    r"|android\.service\.notification\.NotificationListenerService"
    r"|android\.service\.autofill\.AutofillService"
)


def _analyze_xml(file_path: Path, findings: list[dict]) -> None:
    """Run the XML-dialect checks over one file."""
    if _wrong_walk(file_path, XML_EXTENSIONS):
        return
    raw = read_file_safe(file_path)
    if not raw:
        return
    # Blank comment spans BEFORE matching: COMMENT_INDICATORS only sees a
    # comment that opens a line, so a commented-out descriptor would otherwise
    # match verbatim. Blanking (rather than deleting) preserves line numbers.
    content = _blank_xml_comments(raw)
    lines = raw.splitlines()
    for check in _XML_CHECKS:
        check(file_path, content, lines, findings)


def _blank_xml_comments(raw: str) -> str:
    """Replace every ``<!-- ... -->`` span with spaces, keeping line breaks."""
    return _XML_COMMENT.sub(
        lambda m: re.sub(r"[^\n]", " ", m.group(0)), raw,
    )


def _line_of(content: str, index: int) -> int:
    """1-based line number of ``index`` within ``content``."""
    return content.count("\n", 0, index) + 1


def _line_text(content: str, index: int) -> str:
    """The full text of the line containing ``index``."""
    start = content.rfind("\n", 0, index) + 1
    end = content.find("\n", index)
    return content[start:] if end == -1 else content[start:end]


def _line_finding(
    file_path: Path, lines: list[str], line_num: int, base: dict,
) -> dict:
    """Build one finding anchored at a single line from a template."""
    finding = dict(base)
    finding["file_path"] = str(file_path)
    finding["line_start"] = line_num
    finding["line_end"] = line_num
    finding["code_snippet"] = extract_snippet(lines, line_num)
    return enrich_finding(finding, _cwe_id(base))


def _check_xml_tokens(
    file_path: Path, content: str, lines: list[str], findings: list[dict],
) -> None:
    """Run every content-token XML check (CWE-756, CWE-11 primary)."""
    for spec in XML_TOKEN_CHECKS:
        _apply_xml_token_spec(file_path, content, lines, spec, findings)


def _apply_xml_token_spec(
    file_path: Path, content: str, lines: list[str], spec: dict,
    findings: list[dict],
) -> None:
    """Emit one finding per matching line for a token spec."""
    gate = spec["gate"]
    if gate is not None and not gate.search(content):
        return
    for line_num in _xml_token_hits(content, spec["patterns"]):
        findings.append(_line_finding(file_path, lines, line_num, spec["finding"]))


def _xml_token_hits(content: str, patterns: list[re.Pattern[str]]) -> list[int]:
    """Line numbers matching any pattern, excluding build-transform lines."""
    hits: set[int] = set()
    for pattern in patterns:
        for match in pattern.finditer(content):
            if _XDT_TRANSFORM.search(_line_text(content, match.start())):
                continue
            hits.add(_line_of(content, match.start()))
    return sorted(hits)


def _check_sdk_release_debug(
    file_path: Path, content: str, lines: list[str], findings: list[dict],
) -> None:
    """Check a Release PropertyGroup for a debug build (CWE-11 secondary)."""
    for match in _RELEASE_PROPERTY_GROUP.finditer(content):
        block = match.group(0)
        if not (_OPTIMIZE_OFF.search(block) or _DEFINE_DEBUG.search(block)):
            continue
        findings.append(_line_finding(
            file_path, lines, _line_of(content, match.start()), _SDK_DEBUG_FINDING,
        ))


def _check_j2ee_transport(
    file_path: Path, content: str, lines: list[str], findings: list[dict],
) -> None:
    """Check web.xml security constraints for a missing transport guarantee."""
    if not _WEB_APP.search(content):
        return
    seen: set[str] = set()
    for match in _SECURITY_CONSTRAINT.finditer(content):
        _emit_j2ee_constraint(file_path, content, lines, match, seen, findings)


def _emit_j2ee_constraint(
    file_path: Path, content: str, lines: list[str], match: re.Match[str],
    seen: set[str], findings: list[dict],
) -> None:
    """Emit one CWE-5 finding for a security-constraint block, deduped by URL."""
    block = match.group(0)
    if not _j2ee_needs_transport(block):
        return
    key = _first_url_pattern(block) or str(match.start())
    if key in seen:
        return
    seen.add(key)
    finding = dict(_J2EE_FINDING)
    finding["description"] = f"{_J2EE_FINDING['description']} (URL pattern {key})"
    findings.append(_line_finding(
        file_path, lines, _line_of(content, match.start()), finding,
    ))


def _j2ee_needs_transport(block: str) -> bool:
    """True when a constraint protects a named role but names no guarantee."""
    if _TRANSPORT_GUARANTEE.search(block):
        return False
    return bool(_ROLE_PROTECTED.search(block))


def _first_url_pattern(block: str) -> str:
    """The block's first ``<url-pattern>`` text ('' when absent)."""
    found = _URL_PATTERN.search(block)
    return found.group(1) if found else ""


def _check_android_exports(
    file_path: Path, content: str, lines: list[str], findings: list[dict],
) -> None:
    """Check an Android manifest for components exported without permission."""
    if not (_ANDROID_MANIFEST.search(content) and _ANDROID_NS.search(content)):
        return
    seen: set[str] = set()
    for match in _ANDROID_ELEMENT.finditer(content):
        _emit_android_element(file_path, content, lines, match, seen, findings)


def _android_body(content: str, match: re.Match[str]) -> str:
    """The element's body text.

    Two-phase on purpose: a non-greedy ``(?:/>|</name>)`` alternation terminates
    at the first self-closing CHILD, which puts a launcher activity's LAUNCHER
    category OUTSIDE the block and reports the app entry point (measured 100%
    false on a real manifest).
    """
    if match.group(3) == "/":
        return ""
    close = content.find(f"</{match.group(1)}>", match.end())
    return content[match.end(): close if close != -1 else len(content)]


def _android_is_unprotected_export(content: str, match: re.Match[str]) -> bool:
    """True when the element is exported with no permission and no contract."""
    attrs = match.group(2)
    if not _ANDROID_EXPORTED.search(attrs):
        return False
    if _ANDROID_PERMISSION.search(attrs) or _TOOLS_NODE_REMOVE.search(attrs):
        return False
    return not _ANDROID_CONTRACT_ACTION.search(_android_body(content, match))


def _android_component_name(match: re.Match[str]) -> str:
    """The element's ``android:name`` value, or its tag name as a fallback."""
    found = _ANDROID_NAME.search(match.group(2))
    return found.group(1) if found else match.group(1)


def _emit_android_element(
    file_path: Path, content: str, lines: list[str], match: re.Match[str],
    seen: set[str], findings: list[dict],
) -> None:
    """Emit at most one CWE-926 finding per component name."""
    if not _android_is_unprotected_export(content, match):
        return
    name = _android_component_name(match)
    if name in seen:
        return
    seen.add(name)
    findings.append(_line_finding(
        file_path, lines, _line_of(content, match.start()),
        _android_finding_template(match, name),
    ))


def _android_finding_template(match: re.Match[str], name: str) -> dict:
    """Finding template for one exported Android component."""
    grants_uris = (
        match.group(1) == "provider"
        and bool(_ANDROID_GRANT_URI.search(match.group(2)))
    )
    return {
        "severity": "high" if grants_uris else "medium",
        "check_id": "cwe.configuration.android_component_export",
        "category": "CWE-926",
        "title": "Android component exported without permission",
        "description": (
            f"<{match.group(1)}> {name} is android:exported=\"true\" with no "
            f"android:permission, so any installed app can invoke it"
        ),
        "recommendation": (
            "Set android:exported=\"false\" unless another app must reach the "
            "component; otherwise guard it with a signature-level "
            "android:permission"
        ),
    }


_XML_CHECKS = (
    _check_xml_tokens,
    _check_sdk_release_debug,
    _check_j2ee_transport,
    _check_android_exports,
)

# (extensions, extra basenames, analysis pass). Defined after the passes so the
# table holds the functions themselves rather than a name lookup.
_WALKS = (
    (CONFIG_EXTENSIONS, _CONFIG_EXTRA_FILENAMES, _analyze_file),
    (DEBUG_CODE_EXTENSIONS, _NO_EXTRA_FILENAMES, _analyze_dialects),
    (XML_EXTENSIONS, _NO_EXTRA_FILENAMES, _analyze_xml),
    (INSTALL_SCRIPT_EXTENSIONS, _NO_EXTRA_FILENAMES, _analyze_install_script),
)

check_configuration_tool = function_tool(check_configuration)
