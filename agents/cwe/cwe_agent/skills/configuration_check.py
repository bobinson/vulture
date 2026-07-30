"""Configuration and deployment security detection skill."""

import re
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
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

# Per-pattern Weakness CWE IDs (CWE-16 is a Category/Obsolete, not a Weakness)
MISCONFIGURATION_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(?:bind|listen|host)\s*[:=]\s*['\"]0\.0\.0\.0['\"]"),
     "668", "Service bound to all interfaces"),
    (re.compile(r'(?:TLS|tls|ssl).*(?:min|minimum).*(?:1\.0|SSLv|TLSv1[^.])', re.IGNORECASE),
     "326", "Weak TLS/SSL protocol version"),
    (re.compile(r'InsecureSkipVerify\s*:\s*true', re.IGNORECASE),
     "295", "Certificate verification disabled"),
    (re.compile(r'(?:HSTS|Strict-Transport-Security).*max-age\s*[:=]\s*(?:[0-9]{1,4})\b'),
     "319", "Weak HSTS max-age value"),
    # Permissive CORS — Access-Control-Allow-Origin: * in any
    # config-shape line is rarely intentional in production.
    (re.compile(r'(?:Access-Control-Allow-Origin|cors\.allow_origin\w*)\s*[:=]\s*["\']?\*', re.IGNORECASE),
     "942", "Permissive CORS Access-Control-Allow-Origin: *"),
    # Cookie SameSite=None without Secure — cross-site cookie send
    # over http.
    (re.compile(r'SameSite\s*[:=]\s*["\']?None["\']?(?![^,;\n}]*Secure)', re.IGNORECASE),
     "1275", "Cookie SameSite=None without Secure attribute"),
    # X-Frame-Options absent — heuristic via DENY/SAMEORIGIN being
    # explicitly removed.
    (re.compile(r'X-Frame-Options\s*[:=]\s*["\']?ALLOWALL', re.IGNORECASE),
     "1021", "X-Frame-Options ALLOWALL (clickjacking)"),
    # Content-Security-Policy with `unsafe-inline` or `unsafe-eval`.
    (re.compile(r'Content-Security-Policy[^"\']*["\'][^"\']*(?:unsafe-inline|unsafe-eval)', re.IGNORECASE),
     "1336", "CSP includes 'unsafe-inline' / 'unsafe-eval'"),
]

# CWE-732: Incorrect Permission Assignment for Critical Resource
PERMISSION_PATTERNS = [
    re.compile(r"chmod\s+(?:666|667|776|777)\b"),
    re.compile(r"os\.chmod\([^)]*0o?(?:666|667|776|777)"),
    re.compile(r"umask\s*\(\s*0\s*\)"),
    re.compile(r'(?:mode|perm)\s*[:=]\s*0o?(?:666|667|776|777)'),
    re.compile(r"os\.MkdirAll\([^)]*0o?777\)"),
]

SAFE_PERMISSION_PATTERNS = re.compile(
    r"(?:temp|tmp|cache|test|spec|example)",
    re.IGNORECASE,
)

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
# `cors()` with no options reflects any Origin and is juice-shop's
# server.ts:182-183 ("Bludgeon solution for possible CORS problems: Allow
# everything!"). Also caught: an explicit `origin: true` / `origin: '*'`
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
# (juice-shop server.ts:342). A bounded hop count (`trust proxy: 1`) is
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


def check_configuration(source_path: str) -> dict:
    """Check for configuration and deployment security issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of configuration vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=CONFIG_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for configuration security issues."""
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
        _check_insecure_defaults(file_path, line, line_num, lines, findings)
        _check_misconfiguration(file_path, line, line_num, lines, findings)
        _check_permissions(file_path, line, line_num, lines, findings)
        _check_exposure(file_path, line, line_num, lines, findings)
        _check_debug_prod(file_path, line, line_num, lines, content, findings)
    _check_cors_and_trust_proxy(file_path, lines, findings)


def _matching_lines(lines: list[str], patterns: list[re.Pattern[str]]) -> list[int]:
    """Return 1-based line numbers where any pattern matches real code."""
    hits: list[int] = []
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line) or IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        if any(pattern.search(line) for pattern in patterns):
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
    for pattern, cwe_id, title in MISCONFIGURATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.configuration.misconfiguration",
                "category": f"CWE-{cwe_id}",
                "title": title,
                "description": f"Potentially insecure configuration at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Bind to localhost, enforce TLS 1.2+, enable certificate verification",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, cwe_id))
            return


def _check_permissions(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-732 incorrect permission assignment."""
    if SAFE_PERMISSION_PATTERNS.search(file_path.name):
        return
    for pattern in PERMISSION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.configuration.overly_permissive",
                "category": "CWE-732",
                "title": "Overly permissive file permissions",
                "description": f"World-writable or overly permissive permissions at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use restrictive permissions (0644 for files, 0755 for directories)",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "732"))
            return


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


check_configuration_tool = function_tool(check_configuration)
