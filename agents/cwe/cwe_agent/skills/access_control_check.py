"""Access control vulnerability detection skill."""

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

# CWE-862: Missing authorization
ROUTE_PATTERNS = [
    re.compile(r"@app\.(?:route|get|post|put|delete|patch)\s*\("),  # Flask/FastAPI
    re.compile(r"router\.(?:GET|POST|PUT|DELETE|Handle)\w*\s*\("),  # Go
    re.compile(r"@(?:Get|Post|Put|Delete|Patch)Mapping\s*\("),  # Java Spring
    re.compile(r"app\.(?:get|post|put|delete|patch)\s*\("),  # Express.js
]
AUTHZ_PRESENT = re.compile(
    r"\b(?:requires_auth|login_required|@authenticate|@authorize|"
    r"RequireAuth|authMiddleware|IsAuthenticated|jwt_required|"
    r"@permission_required|protect|guard|@UseGuards)\b",
    re.IGNORECASE,
)

# Receiver-aware authz middleware. A very common Express idiom hangs the guards
# off a helper object, e.g.:
# security.isAuthorized(), security.denyAll(), security.isAccounting(),
# security.isDeluxe(). None of those are in AUTHZ_PRESENT, which is why the
# old whole-file boolean condemned all 109 route lines of server.ts at once.
#
# Match on the RECEIVER *and* anchor the verb to the START of the method name
# (same shape as the CWE-754 fix in error_handling_check.py) so request
# decorators keep reading as decorators: `security.appendUserId()` authorises
# nothing ("append" is not a verb here), nor does
# `security.updateAuthenticatedUsers()`.
_AUTHZ_RECEIVER = (
    r"(?:security|securityHandler|authz|auth|acl|rbac|policy|guard|guards|"
    r"perm|perms|permission|permissions)"
)
_AUTHZ_VERB = (
    r"(?:is|are|has|can|must|may|only|require|requires|required|ensure|assert|"
    r"check|verify|validate|deny|forbid|reject|allow|permit|restrict|protect|"
    r"authorize|authorise|authenticate)"
)

# The guard is just as real when the receiver hangs off an object:
# `this.security.isAuthorized()`, `self.authz.require_role('admin')`. Allow a
# short, explicit owner prefix rather than any dotted path, so the lookbehind
# still rejects a receiver that is merely the TAIL of another identifier
# (`dataSecurity.isEmpty()` must not exonerate a route).
_AUTHZ_OWNER = r"(?:this|self|req|ctx|svc|services|deps)\s*\.\s*"
AUTHZ_MIDDLEWARE = re.compile(
    rf"(?<![\w.])(?:{_AUTHZ_OWNER})?{_AUTHZ_RECEIVER}"
    rf"\s*\.\s*{_AUTHZ_VERB}[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)

# Express-style mount that confers authz on everything under a prefix:
#   app.use('/api/BasketItems', security.isAuthorized())
MOUNT_CALL = re.compile(
    r"(?<![\w.])(?:app|router|server|api)\s*\.\s*use\s*\(\s*"
    r"(\[[^\]]*\]|['\"][^'\"]+['\"])\s*,"
)
_QUOTED = re.compile(r"['\"]([^'\"]+)['\"]")

# First quoted argument of a route registration = the route path.
ROUTE_PATH_ARG = re.compile(r"\(\s*\[?\s*['\"]([^'\"]*)['\"]")

_DECORATOR_LINE = re.compile(r"^\s*@")

# A file with this many unprotected routes gets ONE rollup finding instead of
# one row per route: a single route-registration file would otherwise dominate the
# whole report with identically-titled rows.
_ROLLUP_MIN_ROUTES = 3
_ROLLUP_PATH_LIST_MAX = 80

# CWE-863: Incorrect authorization via string comparison.
# Longest-first alternation — `admin` before `administrator` would match the
# prefix and then fail the closing quote.
_PRIV_ROLE = (
    r"(?:administrator|superadmin|superuser|sysadmin|admin|root|owner|moderator)"
)
_ROLE_ATTR = r"(?:role|roles|user_role|userRole|userRoles)"
ROLE_STRING_CMP = [
    # Python / generic bare identifier: role == 'admin', role === 'admin'
    re.compile(
        rf'(?:role|user_role|userRole)\s*(?:===|!==|==|!=)\s*["\']{_PRIV_ROLE}["\']'
    ),
    re.compile(
        rf'["\']{_PRIV_ROLE}["\']\s*(?:===|!==|==|!=)\s*(?:role|user_role|userRole)\b'
    ),
    # JS/TS attribute compare: user.role === 'admin', req.user.role != "root"
    re.compile(rf'\.\s*{_ROLE_ATTR}\s*(?:===|!==|==|!=)\s*["\']{_PRIV_ROLE}["\']'),
    re.compile(
        rf'["\']{_PRIV_ROLE}["\']\s*(?:===|!==|==|!=)\s*[\w.]*\.\s*{_ROLE_ATTR}\b'
    ),
    # JS/TS membership test: role.includes('admin'), roles.indexOf('admin')
    re.compile(
        rf'\b{_ROLE_ATTR}\s*\.\s*(?:includes|indexOf|contains|has)\s*\(\s*'
        rf'["\']{_PRIV_ROLE}["\']'
    ),
]

# CWE-639: Authorization Bypass Through User-Controlled Key (IDOR).
#
# Cover Django/DRF (request.GET / request.POST), Flask
# (request.args / request.form), generic params, Go (URL.Query().Get),
# Express/Node (req.params), and method-call form (.get("id")). The
# previous pattern set missed Django entirely.
IDOR_PATTERNS = [
    # Bracket access via well-known web-framework attrs
    re.compile(r'request\.(?:args|params|query|GET|POST)\[?["\'](?:\w*id)["\']', re.IGNORECASE),
    re.compile(r'request\.form\[?["\'](?:\w*id)["\']', re.IGNORECASE),
    # Express/Node
    re.compile(r'req\.(?:params|query|body)\.\w*id\b', re.IGNORECASE),
    re.compile(r'req\.(?:params|query|body)\[\s*["\']\w*id["\']', re.IGNORECASE),
    # .get() method form (Django + Flask alike)
    re.compile(
        r'request\.(?:GET|POST|args|form|query|params)\.get\(\s*["\']\w*id["\']',
        re.IGNORECASE,
    ),
    # Go net/http URL query
    re.compile(r'r\.URL\.Query\(\)\.Get\(\s*"[a-z_]*id"'),
    # Generic params
    re.compile(r'params\[[\'"]\w*id[\'"]\]'),
]
OWNERSHIP_CHECK = re.compile(
    r"\b(?:check_owner|verify_owner|is_owner|belongs_to|owned_by|current_user\.id)\b",
    re.IGNORECASE,
)

# CWE-269: Improper privilege management
PRIVILEGE_PATTERNS = [
    re.compile(r"chmod\s+777\b"),
    re.compile(r"os\.chmod\([^)]*0o?777"),
    re.compile(r'(?:run|exec).*(?:--privileged|as\s+root|USER\s+root)', re.IGNORECASE),
    re.compile(r"setuid\s*\(\s*0\s*\)"),
]

IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")

# Two-tier context: missing auth is only high with route/handler context
_ROUTE_CONTEXT = [re.compile(r"(route|handler|endpoint|controller|app\.|router\.|api)", re.IGNORECASE)]


def check_access_control(source_path: str) -> dict:
    """Check for access control vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of access control issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for access control issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""

    has_ownership = OWNERSHIP_CHECK.search(content) is not None
    mounts = _authz_mount_prefixes(lines)
    unprotected: list[tuple[int, str | None]] = []
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        if _is_unprotected_route(lines, line, line_num, mounts):
            unprotected.append((line_num, _route_path(line)))
        _check_role_string_cmp(file_path, line, line_num, lines, findings)
        _check_idor(file_path, line, line_num, has_ownership, lines, findings)
        _check_privilege(file_path, line, line_num, lines, findings)
    _emit_missing_authz(file_path, lines, content, unprotected, findings)


# --- CWE-862 helpers -------------------------------------------------------


def _statement_text(lines: list[str], idx: int, max_lines: int = 12) -> str:
    """Text of the logical statement starting at 0-based ``idx``.

    Follows parenthesis balance so a route registration spread over several
    lines is judged as one unit — and, critically, so a route does NOT get
    exonerated by its *neighbour's* authz middleware.
    """
    depth = 0
    parts: list[str] = []
    for i in range(idx, min(len(lines), idx + max_lines)):
        parts.append(lines[i])
        depth += lines[i].count("(") - lines[i].count(")")
        if depth <= 0:
            break
    return "\n".join(parts)


def _decorator_block_text(lines: list[str], idx: int) -> str:
    """Text of a decorator-style route: the contiguous decorator run around
    ``idx`` plus the signature and first few body lines (Flask/Spring put the
    authz on an adjacent decorator, not on the route line)."""
    start = idx
    while start > 0 and _DECORATOR_LINE.match(lines[start - 1]):
        start -= 1
    end = idx
    n = len(lines)
    while end + 1 < n and _DECORATOR_LINE.match(lines[end + 1]):
        end += 1
    # Signature + a little body, but never spill into the next route's
    # decorator stack.
    body = 0
    while end + 1 < n and body < 4 and not _DECORATOR_LINE.match(lines[end + 1]):
        end += 1
        body += 1
    return "\n".join(lines[start:end + 1])


def _route_scope_text(lines: list[str], line: str, line_num: int) -> str:
    """The text in which THIS route's own authz may legitimately appear."""
    idx = line_num - 1
    if _DECORATOR_LINE.match(line):
        return _decorator_block_text(lines, idx)
    return _statement_text(lines, idx)


def _has_authz(text: str) -> bool:
    return (
        AUTHZ_PRESENT.search(text) is not None
        or AUTHZ_MIDDLEWARE.search(text) is not None
    )


def _authz_mount_prefixes(lines: list[str]) -> list[str]:
    """Path prefixes mounted with authz middleware, e.g.
    ``app.use('/api/BasketItems', security.isAuthorized())``."""
    prefixes: list[str] = []
    for idx, line in enumerate(lines):
        if COMMENT_INDICATORS.match(line):
            continue
        match = MOUNT_CALL.search(line)
        if not match:
            continue
        if not _has_authz(_statement_text(lines, idx)):
            continue
        prefixes.extend(p for p in _QUOTED.findall(match.group(1)) if p.startswith("/"))
    return prefixes


def _path_segments(path: str) -> list[str]:
    return [s for s in path.split("?")[0].split("/") if s]


def _mount_covers(route_path: str, mount_path: str) -> bool:
    """True when an Express mount at ``mount_path`` runs for ``route_path``.

    Segment-aware on purpose: ``app.use('/api/Feedbacks/:id', ...)`` does NOT
    run for ``POST /api/Feedbacks``, so a naive string prefix would exonerate a
    genuinely unprotected route.
    """
    mount = _path_segments(mount_path)
    route = _path_segments(route_path)
    if len(mount) > len(route):
        return False
    for want, got in zip(mount, route):
        if want == got or want in ("*", "") or got == "*":
            continue
        if want.startswith(":") or got.startswith(":"):
            continue
        return False
    return True


def _route_path(line: str) -> str | None:
    """The quoted path of a route registration, if it carries one."""
    match = ROUTE_PATH_ARG.search(line)
    if not match:
        return None
    path = match.group(1)
    return path if path.startswith("/") else None


def _is_unprotected_route(
    lines: list[str], line: str, line_num: int, mounts: list[str],
) -> bool:
    """Per-ROUTE authorization decision (was a per-FILE boolean before 0070)."""
    if not any(pattern.search(line) for pattern in ROUTE_PATTERNS):
        return False
    if _has_authz(_route_scope_text(lines, line, line_num)):
        return False
    path = _route_path(line)
    return not (path and any(_mount_covers(path, mount) for mount in mounts))


def _missing_authz_finding(
    file_path: Path, lines: list[str], severity: str,
    line_start: int, line_end: int, title: str, description: str,
) -> dict:
    finding = {
        "severity": severity,
        "check_id": "cwe.access_control.missing_authz",
        "category": "CWE-862",
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_start,
        "line_end": line_end,
        "recommendation": "Add authentication/authorization middleware or decorators",
    }
    finding["code_snippet"] = extract_snippet(lines, line_start)
    return enrich_finding(finding, "862")


def _rollup_description(unprotected: list[tuple[int, str | None]]) -> str:
    """Name the unprotected routes: distinct paths where available."""
    paths: list[str] = []
    for _line_num, path in unprotected:
        if path and path not in paths:
            paths.append(path)
    if not paths:
        lines_txt = ", ".join(str(n) for n, _ in unprotected[:_ROLLUP_PATH_LIST_MAX])
        return (
            f"{len(unprotected)} route registrations in this file have no "
            f"visible authorization check. Lines: {lines_txt}"
        )
    shown = paths[:_ROLLUP_PATH_LIST_MAX]
    listed = ", ".join(shown)
    if len(paths) > len(shown):
        listed += f", (+{len(paths) - len(shown)} more)"
    return (
        f"{len(unprotected)} route registrations in this file have no visible "
        f"authorization check ({len(paths)} distinct paths). "
        f"Unprotected paths: {listed}"
    )


def _emit_missing_authz(
    file_path: Path,
    lines: list[str],
    content: str,
    unprotected: list[tuple[int, str | None]],
    findings: list[dict],
) -> None:
    """Emit CWE-862 rows: one per route, or one rollup for a route table."""
    if not unprotected:
        return
    # Two-tier: demote to medium if file lacks route/handler context
    severity = "high" if check_context(content, _ROUTE_CONTEXT) else "medium"
    if len(unprotected) < _ROLLUP_MIN_ROUTES:
        for line_num, path in unprotected:
            where = f"Endpoint {path} (line {line_num})" if path else f"Endpoint at line {line_num}"
            findings.append(_missing_authz_finding(
                file_path, lines, severity, line_num, line_num,
                "Route handler without authorization",
                f"{where} has no visible auth check",
            ))
        return
    finding = _missing_authz_finding(
        file_path, lines, severity,
        unprotected[0][0], unprotected[-1][0],
        "Route handlers without authorization",
        _rollup_description(unprotected),
    )
    finding["is_rollup"] = True
    finding["instance_count"] = len(unprotected)
    findings.append(finding)


def _check_role_string_cmp(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for incorrect authorization via string comparison (CWE-863)."""
    for pattern in ROLE_STRING_CMP:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.access_control.role_string_cmp",
            "category": "CWE-863",
            "title": "Role check via string comparison",
            "description": f"Direct string comparison for role at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use a role-based access control (RBAC) system instead of string checks",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "863"))
        return


def _check_idor(
    file_path: Path,
    line: str,
    line_num: int,
    has_ownership: bool,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for IDOR vulnerabilities (CWE-639)."""
    if has_ownership:
        return
    for pattern in IDOR_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.access_control.idor",
            "category": "CWE-639",
            "title": "Potential IDOR vulnerability",
            "description": f"User-supplied ID used without ownership check at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Verify resource ownership before granting access",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "639"))
        return


def _check_privilege(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for improper privilege management (CWE-269)."""
    for pattern in PRIVILEGE_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "critical",
            "check_id": "cwe.access_control.improper_privilege",
            "category": "CWE-269",
            "title": "Improper privilege management",
            "description": f"Excessive permissions or privilege escalation at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Apply least privilege principle; avoid running as root or using 777 permissions",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "269"))
        return


check_access_control_tool = function_tool(check_access_control)
