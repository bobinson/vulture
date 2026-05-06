"""Dependency and supply chain security detection skill.

Covers CWE-1104 (unmaintained / unpinned), CWE-829 (untrusted source),
CWE-494 (download without integrity check), CWE-506 (suspicious
embedded code), and CWE-937 (using known-vulnerable component) — the
last via an embedded JSON catalog of well-known CVEs.

Operators can override the bundled catalog by setting
``VULTURE_DEPENDENCY_DB`` to a JSON file matching the same shape
(``data/known_vulnerable_versions.json``).
"""

import json
import os
import re
from functools import lru_cache
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
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding


# ---------------------------------------------------------------------------
# CWE-937: Known-Vulnerable Component
# ---------------------------------------------------------------------------

_KNOWN_VULN_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "known_vulnerable_versions.json"


@lru_cache(maxsize=1)
def _load_known_vulnerable_db() -> dict:
    """Load the known-vulnerable-versions catalog.

    Tries ``VULTURE_DEPENDENCY_DB`` first (operator override), then the
    bundled JSON. Missing / unreadable file → empty dict (skill runs in
    degraded mode without crashing).
    """
    override = os.environ.get("VULTURE_DEPENDENCY_DB")
    candidates = [Path(override)] if override else []
    candidates.append(_KNOWN_VULN_DEFAULT_PATH)
    for path in candidates:
        try:
            if path.is_file():
                with path.open() as f:
                    return json.load(f)
        except (OSError, ValueError):
            continue
    return {}


# Spec → comparator. `version_spec` strings come from the JSON catalog
# and use a small grammar we evaluate ourselves so we don't pull in
# packaging.
_OP_RE = re.compile(r"^(<=|>=|==|!=|<|>|~=)\s*(.+)$")


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted-numeric version into a comparable tuple.

    Non-numeric components fall back to 0 — sufficient for the simple
    CVE-bound matching this skill performs (we never compare against
    pre-release tags, just bounded ranges).
    """
    parts: list[int] = []
    for chunk in re.split(r"[.+\-]", v):
        m = re.match(r"(\d+)", chunk)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts)


def _spec_matches(installed: str, spec: str) -> bool:
    """Return True when ``installed`` satisfies a single spec like
    ``<2.27.0``. Comma-separated specs are AND-joined by the caller."""
    m = _OP_RE.match(spec.strip())
    if not m:
        return False
    op, ver = m.groups()
    a = _parse_version(installed)
    b = _parse_version(ver)
    if op == "==": return a == b
    if op == "!=": return a != b
    if op == "<":  return a < b
    if op == "<=": return a <= b
    if op == ">":  return a > b
    if op == ">=": return a >= b
    if op == "~=":
        # Python compatible release: ~=1.4 means >=1.4,<2.0
        prefix = b[:-1]
        next_major = b[:-1] + (b[-1] + 1,) if b else b
        return a >= b and a < next_major
    return False


def _check_cve_match(installed: str, ecosystem: str, package: str) -> list[dict]:
    """Return the list of catalog entries whose version_spec matches."""
    db = _load_known_vulnerable_db()
    pkgs = (db.get(ecosystem) or {}).get(package, [])
    matched = []
    for entry in pkgs:
        spec = entry.get("version_spec", "")
        # Comma-separated AND of specs
        all_match = True
        for piece in spec.split(","):
            piece = piece.strip()
            if piece and not _spec_matches(installed, piece):
                all_match = False
                break
        if all_match and spec:
            matched.append(entry)
    return matched

# CWE-1104: Use of Unmaintained Third Party Components
DEPENDENCY_FILE_NAMES = frozenset({
    "requirements.txt", "Pipfile", "pyproject.toml",
    "package.json", "package-lock.json",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
})

# Patterns suggesting pinned vs unpinned dependencies
UNPINNED_PYTHON = re.compile(r"^[a-zA-Z][\w.-]*\s*$")  # No version constraint
UNPINNED_PYTHON_LOOSE = re.compile(r"^[a-zA-Z][\w.-]*\s*>=")  # Only lower bound
PINNED_VERSION = re.compile(r"==|~=|===|\block\b")

# CWE-829: Inclusion of Functionality from Untrusted Control Sphere
UNTRUSTED_SOURCE_PATTERNS = [
    re.compile(r'<script\s+src\s*=\s*["\']http:', re.IGNORECASE),
    re.compile(r'(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|python)', re.IGNORECASE),
    re.compile(r'pip\s+install\s+--index-url\s+http:', re.IGNORECASE),
    re.compile(r'go\s+get\s+.*(?:github\.com|gitlab\.com).*@latest'),
    re.compile(r'npm\s+install\s+.*(?:github:|git\+http:)', re.IGNORECASE),
]

SAFE_SCRIPT_PATTERNS = re.compile(
    r"(?:integrity\s*=|crossorigin|nonce=|SRI|subresource)",
    re.IGNORECASE,
)

# CWE-494: Download of Code Without Integrity Check
DOWNLOAD_NO_VERIFY_PATTERNS = [
    re.compile(r'(?:curl|wget)\s+.*(?:-o|-O|>)\s+\S+', re.IGNORECASE),
    re.compile(r'urllib\.request\.urlretrieve\s*\('),
    re.compile(r'requests\.get\([^)]*\)\.content'),
    re.compile(r'http\.Get\([^)]*\)'),
]

SAFE_INTEGRITY_PATTERNS = re.compile(
    r"(?:sha256|sha512|checksum|verify|gpg|signature|digest|hash)",
    re.IGNORECASE,
)

# CWE-506: Embedded Malicious Code (suspicious patterns)
SUSPICIOUS_CODE_PATTERNS = [
    re.compile(r'base64\.(?:b64decode|decodebytes)\s*\([^)]*\)\s*.*(?:exec|eval|compile)', re.IGNORECASE),
    re.compile(r"__import__\s*\(\s*['\"](?:os|subprocess|socket|http)['\"]"),
    re.compile(r'exec\s*\(\s*(?:base64|codecs|zlib)\.\w+\s*\('),
    re.compile(r"(?:socket|http\.client).*connect.*(?:exec|system|popen)", re.IGNORECASE),
]

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

ALL_EXTENSIONS = frozenset({
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".sh", ".bash",
    ".html", ".htm", ".yml", ".yaml", ".toml",
    ".txt", ".json", ".xml", ".gradle", ".lock",
})


def check_dependency_security(source_path: str) -> dict:
    """Check for dependency and supply chain security issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of dependency security issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=ALL_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        if file_path.name in DEPENDENCY_FILE_NAMES:
            _analyze_dependency_file(file_path, findings)
        else:
            _analyze_code_file(file_path, findings)

    return {"findings": findings}


def _analyze_dependency_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze dependency manifest files for CWE-1104 (unpinned) and
    CWE-937 (known-vulnerable component)."""
    content = read_file_safe(file_path)
    if content is None:
        return

    if file_path.name == "requirements.txt":
        _analyze_requirements_txt(file_path, content, findings)
    elif file_path.name in ("package.json", "package-lock.json"):
        _analyze_npm_manifest(file_path, content, findings)


# Requirement spec for `pkg==1.2.3` / `pkg>=1.2`. Captures (name, version).
_PIP_SPEC = re.compile(r"^([A-Za-z][\w.\-]*)\s*(?:==|~=|===)\s*([0-9][\w.\-]*)")


def _analyze_requirements_txt(file_path: Path, content: str, findings: list[dict]) -> None:
    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        if UNPINNED_PYTHON.match(stripped) or UNPINNED_PYTHON_LOOSE.match(stripped):
            finding = {
                "severity": "medium",
                "check_id": "cwe.dependency.unpinned_version",
                "category": "CWE-1104",
                "title": "Unpinned dependency version",
                "description": f"Dependency '{stripped.split()[0]}' lacks pinned version at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Pin dependencies to specific versions (use == or ~=)",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1104"))
            continue
        # CWE-937: pinned version → check the known-vuln catalog.
        m = _PIP_SPEC.match(stripped)
        if m:
            _emit_cve_findings(file_path, lines, line_num, m.group(1).lower(), m.group(2),
                               ecosystem="pypi", findings=findings)


def _analyze_npm_manifest(file_path: Path, content: str, findings: list[dict]) -> None:
    """Best-effort parse of package*.json to extract pinned versions.

    Uses a JSON parser; bails out gracefully on unparseable input.
    Looks at top-level ``dependencies`` and ``devDependencies``. For
    package-lock.json, walks the ``packages`` map.
    """
    try:
        data = json.loads(content)
    except (ValueError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    lines = content.splitlines()
    pairs: list[tuple[str, str]] = []
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                if isinstance(name, str) and isinstance(ver, str):
                    pairs.append((name.lower(), _strip_npm_range(ver)))
    pkgs_map = data.get("packages")
    if isinstance(pkgs_map, dict):
        for path, info in pkgs_map.items():
            if not (isinstance(info, dict) and isinstance(path, str)):
                continue
            ver = info.get("version")
            if not isinstance(ver, str):
                continue
            # path is "node_modules/<pkg>" — strip the prefix
            name = path.rsplit("node_modules/", 1)[-1].lower()
            if name:
                pairs.append((name, ver))
    for name, ver in pairs:
        if not ver:
            continue
        _emit_cve_findings(file_path, lines, 1, name, ver, ecosystem="npm", findings=findings)


def _strip_npm_range(spec: str) -> str:
    """Best-effort: drop `^`, `~`, `>=`, `<` etc. from an npm spec.

    Accuracy isn't critical — we use the resulting version as the
    LOWER bound for CVE matching. Catalog spec matching is conservative
    (false negatives over false positives) so a stripped `^1.2.3` →
    `1.2.3` is fine.
    """
    spec = spec.strip()
    m = re.search(r"\d[\w.\-]*", spec)
    return m.group(0) if m else ""


def _emit_cve_findings(
    file_path: Path,
    lines: list[str],
    line_num: int,
    package: str,
    version: str,
    ecosystem: str,
    findings: list[dict],
) -> None:
    matches = _check_cve_match(version, ecosystem, package)
    for entry in matches:
        cve = entry.get("cve", "UNKNOWN")
        severity = entry.get("severity", "medium")
        summary = entry.get("summary", "Known-vulnerable version")
        fixed_in = entry.get("fixed_in", "")
        finding = {
            "severity": severity,
            "check_id": f"cwe.dependency.known_vulnerable.{cve}",
            "category": "CWE-937",
            "title": f"Known-vulnerable dependency: {package} {version} ({cve})",
            "description": (
                f"{ecosystem.upper()} package {package!r} version {version} matches "
                f"a known CVE: {cve}. {summary}."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                f"Upgrade {package} to {fixed_in} or later. Refer to {cve} "
                "advisory for full impact and remediation guidance."
            ),
        }
        if lines:
            finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "937"))


def _analyze_code_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze code files for dependency-related vulnerabilities."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_untrusted_source(file_path, line, line_num, lines, findings)
        _check_download_no_verify(file_path, line, line_num, lines, findings)
        _check_suspicious_code(file_path, line, line_num, lines, findings)


def _check_untrusted_source(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-829 inclusion from untrusted control sphere."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SCRIPT_PATTERNS.search(context):
        return
    for pattern in UNTRUSTED_SOURCE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.dependency.untrusted_source",
                "category": "CWE-829",
                "title": "Code from untrusted source",
                "description": f"Code loaded or executed from untrusted source at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use HTTPS, verify integrity (SRI/checksums), pin to specific versions",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "829"))
            return


def _check_download_no_verify(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-494 download without integrity check."""
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 4)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_INTEGRITY_PATTERNS.search(context):
        return
    for pattern in DOWNLOAD_NO_VERIFY_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.dependency.download_no_verify",
                "category": "CWE-494",
                "title": "Download without integrity verification",
                "description": f"Code/file downloaded without checksum verification at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Verify checksums or signatures of downloaded files before use",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "494"))
            return


def _check_suspicious_code(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-506 embedded malicious code patterns."""
    for pattern in SUSPICIOUS_CODE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.dependency.suspicious_code",
                "category": "CWE-506",
                "title": "Suspicious code pattern (potential malicious code)",
                "description": f"Obfuscated or suspicious execution pattern at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Review this code carefully; decoded-then-executed patterns are a malware indicator",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "506"))
            return


check_dependency_security_tool = function_tool(check_dependency_security)
