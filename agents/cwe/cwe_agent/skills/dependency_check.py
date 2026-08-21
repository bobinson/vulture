"""Dependency and supply chain security detection skill.

Covers CWE-1104 (unmaintained / unpinned), CWE-829 (untrusted source),
CWE-494 (download without integrity check), CWE-506 (suspicious
embedded code), and CWE-1395 (dependency on a vulnerable third-party
component) — the last via an embedded JSON catalog of well-known CVEs.

Two precision decisions (feature 0070):

* The known-vulnerable finding is reported as **CWE-1395**, not CWE-937.
  CWE-937 is a CWE *Category*, not a Weakness: the CWE catalog cannot
  enrich it and the OWASP 2025 edition maps it to nothing, so the single
  highest-value supply-chain signal here never reached A03. CWE-1395
  ("Dependency on Vulnerable Third-Party Component") is the Weakness for
  exactly this observation and is in A03's 2025 mapped set. Trade-off:
  the OWASP **2021** edition maps 937 (A06) but not 1395, so under 2021
  these findings now reach A06 only through CWE-1104's rollup.
* CWE-1104 is emitted once **per manifest**, not once per floating spec.
  One row per caret/tilde dependency carries a single bit of information
  repeated N times (244 rows in one measured sweep, 70 of them cross-manifest
  duplicates); the rollup keeps the count and the package list.

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
    MAX_MANIFEST_SIZE,
    SCANNER_DEF_LINE,
    effective_name,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# ---------------------------------------------------------------------------
# CWE-1395: Dependency on Vulnerable Third-Party Component
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
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    if op == "~=":
        # Python compatible release: ~=1.4 means >=1.4,<2.0
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

# ---------------------------------------------------------------------------
# CWE-830: Inclusion of Web Functionality from an Untrusted Source
# ---------------------------------------------------------------------------
# Child specialisation of the CWE-829 pattern above, which owns the plaintext
# `<script src="http:` population only. 830 takes the https / scheme-relative
# population: the transport is fine, the *provenance* is not, because whatever
# the third-party origin serves executes with this page's privileges.
#
# Two measured decisions are load-bearing.
#
# * `rel="stylesheet"` / `rel="preload"` are NOT arms. They produced 28 of 29
#   measured hits, all webfont stylesheets, and such a stylesheet cannot carry
#   SRI at all (the served bytes vary by User-Agent, so a pinned hash breaks the
#   page). An unfixable row is a false one. `rel="modulepreload"` IS an arm — it
#   preloads JavaScript, for which SRI is both defined and expected.
# * A bare `.src =` is not an anchor. `<img>`/`<video>`/`poster` assignments have
#   no integrity mechanism and are not this weakness, so the DOM arm requires a
#   script/iframe element creation in the same ±3-line window.
#
# The host must be a literal: a templated host (`//{{ cdn }}/…`) is resolved by
# a deploy-time value this file does not control. A templated PATH under a
# literal host still reports — that is a real remote include.
_REMOTE_HOST = (
    r"""(?:https:)?//(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\{\{|\$\{|<%)[^"'>]+"""
)

_SRI_ATTR = re.compile(r"""integrity\s*=\s*["']sha(?:256|384|512)-""", re.IGNORECASE)

# Loaders whose vendor documents SRI as unsupported and/or rotates the artefact
# behind a stable URL. A pinned hash breaks these by design, so a row is
# unactionable. Generic vendor idiom — no repository is referenced.
_SRI_UNSUPPORTED_HOST = re.compile(
    r"(?:fonts\.googleapis\.com|fonts\.gstatic\.com|www\.googletagmanager\.com|"
    r"www\.google-analytics\.com|js\.stripe\.com|checkout\.stripe\.com|"
    r"www\.google\.com/recaptcha|www\.gstatic\.com/recaptcha|"
    r"connect\.facebook\.net|challenges\.cloudflare\.com|"
    r"maps\.googleapis\.com|apis\.google\.com)",
    re.IGNORECASE,
)

# Arm A — a whole <script> tag, closing on this line. Requiring the `>` is what
# keeps a wrapped tag (whose integrity attribute sits on a later line) from
# being reported: the safe form simply does not match.
_SCRIPT_TAG_REMOTE = re.compile(
    rf"""<script\b[^>]*?\bsrc\s*=\s*(["']){_REMOTE_HOST}\1[^>]*?>""",
    re.IGNORECASE,
)
_MODULEPRELOAD_REMOTE = re.compile(
    r"""<link\b(?=[^>]*\brel\s*=\s*["']?modulepreload\b)"""
    rf"""[^>]*?\bhref\s*=\s*(["']){_REMOTE_HOST}\1[^>]*?>""",
    re.IGNORECASE,
)
# Arm B — runtime module / worker load, plus the STATIC remote ESM import. The
# static form is evaluated before the module's IMPORT_LINE filter (see
# `_scan_code_line`); after it, the shape can never fire.
_REMOTE_MODULE_LOAD = re.compile(
    rf"""\b(?:importScripts|import)\s*\(\s*(["']){_REMOTE_HOST}\1"""
    rf"""|^\s*import\b[^;\n]*\bfrom\s+(["']){_REMOTE_HOST}\2"""
)
# Arm C — DOM injection: the assignment plus a script/iframe creation nearby.
_DOM_REMOTE_SRC = re.compile(rf"""\.src\s*=\s*(["']){_REMOTE_HOST}\1""")
_DOM_ELEMENT_CREATE = re.compile(
    r"""createElement\s*\(\s*["'](?:script|iframe)["']""", re.IGNORECASE
)

# (check_id, title, phrase, pattern, required ±3-line context or None)
_WEB_INCLUDE_ARMS: tuple[tuple[str, str, str, re.Pattern, re.Pattern | None], ...] = (
    (
        "cwe.dependency.script_no_integrity",
        "Remote script loaded without subresource integrity",
        "script tag",
        _SCRIPT_TAG_REMOTE,
        None,
    ),
    (
        "cwe.dependency.modulepreload_no_integrity",
        "Remote module preloaded without subresource integrity",
        "modulepreload link",
        _MODULEPRELOAD_REMOTE,
        None,
    ),
    (
        "cwe.dependency.remote_module_load",
        "Remote module loaded at runtime without integrity verification",
        "runtime module or worker load",
        _REMOTE_MODULE_LOAD,
        None,
    ),
    (
        "cwe.dependency.injected_remote_element",
        "Remote script or frame injected into the DOM at runtime",
        "dynamically injected element",
        _DOM_REMOTE_SRC,
        _DOM_ELEMENT_CREATE,
    ),
)

# `_MINIFIED_RE` in the scanner matches by FILENAME, so a bundler chunk under an
# arbitrary name is scanned in full — and a bundle is exactly where a remote
# include is neither authored nor fixable here. Longest-line heuristic instead.
_BUNDLE_LINE_CHARS = 2000

# ---------------------------------------------------------------------------
# CWE-427: Uncontrolled Search Path Element
# ---------------------------------------------------------------------------
# All arms are `low`: the realistic instance is a relative element in a dev or
# CI script, which resolves against the invoking working directory. That is a
# search-path weakness, not a demonstrated code-execution path, and the wording
# must not claim otherwise.
_LOADER_VAR = (
    r"(?:PATH|LD_LIBRARY_PATH|LD_PRELOAD|DYLD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES"
    r"|PYTHONPATH|CLASSPATH|NODE_PATH|PERL5LIB|RUBYLIB|GEM_PATH)"
)

# An element that resolves against the caller's working directory (or a
# world-writable temp dir). `(["'])(?:…)?\1` makes the empty-string element
# `""` — the classic implicit-cwd form — explicit rather than incidental.
_CWD_ELEMENT = (
    r"""(?:(["'])(?:\.{1,2}|/tmp[^"']*|/var/tmp[^"']*)?\1|os\.getcwd\(\)|os\.curdir)"""
)

# Arm (a). The dominant real idiom derives the element from the module's own
# location (`Path(__file__).parent`), which this predicate cannot match: only a
# literal `.`/`..`/`""`, a temp dir, or an explicit cwd call qualifies.
_PY_SEARCH_PATH = re.compile(
    r"\bsys\.path(?:\.(?:insert|append)\s*\(\s*(?:0\s*,\s*)?"
    r"|\[\s*0\s*:\s*0\s*\]\s*=\s*\[\s*)" + _CWD_ELEMENT
)

# Arms (b)/(c). The `(?<![:?+])` lookbehind on the `=` is mandatory: Makefile
# and GNUmakefile reach this skill through WELL_KNOWN_FILENAMES, and
# `PYTHONPATH := $(ROOT)` / `PATH ?= x` / `CLASSPATH += y` put a `:`, `?` or `+`
# immediately left of the `=`. Reading that `:` as a leading empty path element
# is a guaranteed false positive on every Makefile that sets a loader variable.
_ENV_ASSIGN = r"\b" + _LOADER_VAR + r"\s*(?<![:?+])=\s*"
_ENV_CWD_ELEMENT = re.compile(
    _ENV_ASSIGN
    + r"""["']?(?:[^"'\n]*:)?(?:\.{1,2}|\$PWD|`pwd`|/tmp|/var/tmp)(?::|["']?(?:\s|$))"""
)
_ENV_EMPTY_ELEMENT = re.compile(
    _ENV_ASSIGN
    + r"""["']?(?::(?![=/])|[^"'\n]*::|[^"'\n]*:["']?\s*(?:#|$))"""
)

# Arm (d). An explicit flag or API call is required. A bare
# `java.library.path=.` substring match reads documentation as a finding, and
# the property VALUE must actually start with a relative or empty element —
# `"/opt/lib"` is absolute and must not match.
_JVM_SEARCH_PATH = re.compile(
    r"""System\.setProperty\(\s*(["'])java\.(?:library|class)\.path\1\s*,\s*"""
    r"""(["'])(?:[.:][^"']*)?\2"""
    r"""|(?:^|\s)-Djava\.(?:library|class)\.path=(?:\.|:)"""
)
_PY_ENV_SEARCH_PATH = re.compile(
    r"""os\.environ\[\s*(["'])""" + _LOADER_VAR + r"""\1\s*\]\s*=\s*"""
    r"""[^\n]*(?:os\.getcwd\(\)|(["'])\.\2)"""
)

# Arm (e). The YAML mapping form, which the `VAR=` shape cannot express — a CI
# `env:` block writes `PYTHONPATH: .`. Declared because it is implemented.
_YAML_SEARCH_PATH = re.compile(
    r"^\s*" + _LOADER_VAR + r"""\s*:\s*["']?(?:\.{1,2}|/tmp|/var/tmp)(?::|["']?\s*$)"""
)

# (check_id, title, phrase, pattern)
_SEARCH_PATH_ARMS: tuple[tuple[str, str, str, re.Pattern], ...] = (
    (
        "cwe.dependency.search_path_module",
        "Module search path includes the working directory",
        "module search path (sys.path)",
        _PY_SEARCH_PATH,
    ),
    (
        "cwe.dependency.search_path_loader_var",
        "Loader search path includes a relative or temporary element",
        "loader environment variable",
        _ENV_CWD_ELEMENT,
    ),
    (
        "cwe.dependency.search_path_empty_element",
        "Loader search path contains an empty element",
        "loader environment variable",
        _ENV_EMPTY_ELEMENT,
    ),
    (
        "cwe.dependency.search_path_jvm",
        "JVM library/class search path includes a relative element",
        "JVM search-path property",
        _JVM_SEARCH_PATH,
    ),
    (
        "cwe.dependency.search_path_env_write",
        "Loader search path is rewritten to include the working directory",
        "loader environment variable",
        _PY_ENV_SEARCH_PATH,
    ),
    (
        "cwe.dependency.search_path_yaml",
        "Loader search path includes a relative or temporary element",
        "loader variable in a configuration mapping",
        _YAML_SEARCH_PATH,
    ),
)


def check_dependency_security(source_path: str) -> dict:
    """Check for dependency and supply chain security issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of dependency security issues.
    """
    findings: list[dict] = []

    # Manifests are dispatched FIRST and are exempt from the generated/test
    # filters (feature 0068). `is_generated_file()` classifies package.json as
    # generated, which previously killed the npm branch for every JS/TS repo
    # before it ran. Manifests are also requested as `extra_filenames` so
    # SKIP_FILES (which hard-skips lock files) cannot veto them. Backup copies
    # resolve through `effective_name`, so `ftp/package.json.bak` is audited as
    # the manifest it is.
    for file_path in scan_code_files(
        source_path, extensions=ALL_EXTENSIONS,
        extra_filenames=frozenset(DEPENDENCY_FILE_NAMES),
    ):
        if effective_name(file_path.name) in DEPENDENCY_FILE_NAMES:
            _analyze_dependency_file(file_path, findings)
            continue
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_code_file(file_path, findings)

    return {"findings": findings}


def _analyze_dependency_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze dependency manifest files for CWE-1104 (unpinned, rolled up
    per manifest) and CWE-1395 (known-vulnerable component)."""
    # Manifests are read under the larger MAX_MANIFEST_SIZE ceiling: a lock
    # file's size tracks its dependency count, so the general source-file cap
    # dropped exactly the manifests with the most to report.
    content = read_file_safe(file_path, max_size=MAX_MANIFEST_SIZE)
    if content is None:
        return

    # Resolve backup/shadow copies to the manifest they shadow so
    # `package.json.bak` takes the npm path (feature 0068).
    name = effective_name(file_path.name)
    if name == "requirements.txt":
        _analyze_requirements_txt(file_path, content, findings)
    elif name in ("package.json", "package-lock.json"):
        _analyze_npm_manifest(file_path, content, findings)


# Requirement spec for `pkg==1.2.3` / `pkg>=1.2`. Captures (name, version).
_PIP_SPEC = re.compile(r"^([A-Za-z][\w.\-]*)\s*(?:==|~=|===)\s*([0-9][\w.\-]*)")
# Split a requirements line into (name, remainder) for rollup display.
_PIP_NAME = re.compile(r"^([A-Za-z][\w.\-]*)\s*(.*)$")

# How many packages the rollup description spells out WITH their version spec.
# Beyond this the tail is still listed, but by bare name only: a root
# package.json can declare 113 floating specs, and "name (^1.2.3)" x113 would
# dominate the finding. No package name is dropped — the rollup must not lose
# what the 244 individual rows carried.
_ROLLUP_SPEC_LIMIT = 25


def _emit_unpinned_rollup(
    file_path: Path,
    lines: list[str],
    unpinned: list[tuple[str, str, int]],
    findings: list[dict],
) -> None:
    """Emit ONE CWE-1104 finding covering every floating spec in a manifest.

    ``unpinned`` holds ``(package, raw_spec, line)`` triples in declaration
    order. One row per dependency repeats a single bit of information N times
    (244 rows over three manifests in one sweep), so the rollup replaces them —
    but it must not lose information, hence ``instance_count`` plus a spelled-out
    package list in the description.

    The title deliberately omits the count. The backend fingerprints a finding
    on (title, file_path, category), so a count in the title would make every
    dependency bump present as a brand-new finding instead of the same one.
    """
    if not unpinned:
        return
    count = len(unpinned)
    head, tail = unpinned[:_ROLLUP_SPEC_LIMIT], unpinned[_ROLLUP_SPEC_LIMIT:]
    listed = ", ".join(f"{name} ({spec or '*'})" for name, spec, _ in head)
    if tail:
        listed += (
            f", and {len(tail)} more: "
            + ", ".join(name for name, _, _ in tail)
        )
    line_start = min(u[2] for u in unpinned)
    finding = {
        "severity": "low",
        "check_id": "cwe.dependency.unpinned_version",
        "category": "CWE-1104",
        "title": f"Unpinned dependency versions in {file_path.name}",
        "description": (
            f"{count} dependencies in {file_path.name} are declared as floating "
            "ranges rather than exact versions. The installed version can change "
            "with no change to the manifest, so a component may silently become "
            f"outdated, unmaintained, or vulnerable. Unpinned ({count}): {listed}."
        ),
        "file_path": str(file_path),
        "line_start": line_start,
        "line_end": max(u[2] for u in unpinned),
        "instance_count": count,
        "recommendation": (
            "Pin exact versions and commit a lockfile so installs are "
            "reproducible and auditable."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_start)
    findings.append(enrich_finding(finding, "1104"))


def _analyze_requirements_txt(file_path: Path, content: str, findings: list[dict]) -> None:
    lines = content.splitlines()
    unpinned: list[tuple[str, str, int]] = []
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        if UNPINNED_PYTHON.match(stripped) or UNPINNED_PYTHON_LOOSE.match(stripped):
            m_name = _PIP_NAME.match(stripped)
            name = m_name.group(1) if m_name else stripped.split()[0]
            spec = m_name.group(2).strip() if m_name else ""
            unpinned.append((name, spec, line_num))
            continue
        # CWE-1395: pinned version → check the known-vuln catalog.
        m = _PIP_SPEC.match(stripped)
        if m:
            _emit_cve_findings(file_path, lines, line_num, m.group(1).lower(), m.group(2),
                               ecosystem="pypi", findings=findings)
    _emit_unpinned_rollup(file_path, lines, unpinned, findings)


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
    unpinned: list[tuple[str, str, int]] = []
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                if isinstance(name, str) and isinstance(ver, str):
                    # Inspect the RAW spec before _strip_npm_range() destroys the
                    # range operator — that operator is the whole signal (0068).
                    _check_npm_spec_pinning(file_path, lines, name, ver, findings, unpinned)
                    pairs.append((name.lower(), _strip_npm_range(ver)))
    # One CWE-1104 row per manifest, not per floating spec (feature 0070).
    _emit_unpinned_rollup(file_path, lines, unpinned, findings)
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


# Specs that resolve to whatever the registry serves at install time.
_UNPINNED_PREFIXES = ("^", "~", ">", "<", "=>", "=<")
_UNPINNED_EXACT = frozenset({"", "*", "x", "X", "latest", "next", "*.*.*"})
# Specs that bypass the registry entirely — provenance is not verifiable.
_UNTRUSTED_SPEC = re.compile(r"^(?:git(?:\+\w+)?:|https?:|file:|link:|github:|[\w.-]+/[\w.-]+#)", re.IGNORECASE)


def _npm_spec_line(lines: list[str], name: str) -> int:
    """1-based line of `"<name>":` in the manifest, else 1."""
    needle = f'"{name}"'
    for i, line in enumerate(lines, start=1):
        if needle in line:
            return i
    return 1


def _check_npm_spec_pinning(
    file_path: Path, lines: list[str], name: str, spec: str, findings: list[dict],
    unpinned: list[tuple[str, str, int]],
) -> None:
    """Classify one npm spec that is not pinned to an exact version.

    Covers the two A03-mapped CWEs a static check can justify:
      * CWE-1357 — spec bypasses the registry (git/url/file), so the delivered
        artefact is not verifiable (Reliance on Insufficiently Trustworthy
        Component). Emitted per dependency: each such spec is a distinct,
        individually actionable supply-chain decision.
      * CWE-1104 — floating range, so the resolved version drifts and may
        become unmaintained/vulnerable without a manifest change. NOT emitted
        here; appended to ``unpinned`` for the caller's per-manifest rollup,
        because a caret range is a manifest-wide policy problem, not N
        independent ones.
    """
    raw = spec.strip()
    line = _npm_spec_line(lines, name)

    if _UNTRUSTED_SPEC.match(raw):
        finding = {
            "severity": "medium",
            "check_id": "cwe.dependency.untrusted_spec",
            "category": "CWE-1357",
            "title": f"Dependency '{name}' installed from an unverifiable source",
            "description": (
                f"Dependency '{name}' is declared as '{raw}', which bypasses the "
                "package registry (git/URL/file spec). The delivered code is not "
                "integrity-checked or version-locked, so its provenance cannot be "
                f"verified. Declared at line {line}."
            ),
            "file_path": str(file_path),
            "line_start": line,
            "line_end": line,
            "recommendation": (
                "Publish the dependency to a registry and pin an exact version, or "
                "vendor it with a recorded integrity hash."
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line)
        findings.append(enrich_finding(finding, "1357"))
        return

    if raw in _UNPINNED_EXACT or raw.startswith(_UNPINNED_PREFIXES):
        unpinned.append((name, raw, line))


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
            # CWE-1395, not CWE-937: 937 is a Category (unenrichable, unmapped
            # by OWASP 2025); 1395 is the Weakness and is in A03's 2025 set.
            "category": "CWE-1395",
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
        findings.append(enrich_finding(finding, "1395"))


def _analyze_code_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze code files for dependency-related vulnerabilities."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    # Gates for the two rules added in feature 0070 P7, computed once per file:
    #   * prose — `.txt` is in ALL_EXTENSIONS and `is_prose_file()` classifies it
    #     as documentation. A loader-path assignment quoted in an install guide
    #     is a mention, not an instance, and COMMENT_INDICATORS cannot tell:
    #     prose body text carries no comment marker.
    #   * bundled — the scanner's minified check is filename-only, so a bundler
    #     chunk under an arbitrary name is scanned in full.
    prose = is_prose_file(file_path)
    scan_web = not prose and not _looks_bundled(lines)
    for line_num, line in enumerate(lines, start=1):
        _scan_code_line(file_path, line, line_num, lines, (prose, scan_web), findings)


def _looks_bundled(lines: tuple[str, ...] | list[str]) -> bool:
    """True when the file looks like a minified/bundled artefact by CONTENT."""
    return any(len(line) > _BUNDLE_LINE_CHARS for line in lines)


def _skip_code_line(line: str) -> bool:
    """Comment lines and this agent's own pattern tables are never instances."""
    return bool(COMMENT_INDICATORS.match(line) or SCANNER_DEF_LINE.search(line))


def _scan_code_line(
    file_path: Path, line: str, line_num: int, lines: list[str],
    gates: tuple[bool, bool], findings: list[dict],
) -> None:
    """Run every per-line rule over one source line."""
    if _skip_code_line(line):
        return
    # CWE-830 / CWE-427 run BEFORE the IMPORT_LINE filter: a static remote ESM
    # import IS an import line, so a rule evaluated after the filter can never
    # fire. A CWE-830 hit also CLAIMS the line, so the CWE-829 parent cannot
    # stack a second row on it (skill findings are not cross-deduplicated).
    if _check_p7_web_and_path(file_path, line, line_num, lines, gates, findings):
        return
    if IMPORT_LINE.match(line):
        return
    _check_untrusted_source(file_path, line, line_num, lines, findings)
    _check_download_no_verify(file_path, line, line_num, lines, findings)
    _check_suspicious_code(file_path, line, line_num, lines, findings)


def _check_p7_web_and_path(
    file_path: Path, line: str, line_num: int, lines: list[str],
    gates: tuple[bool, bool], findings: list[dict],
) -> bool:
    """CWE-830 + CWE-427. Returns True when the line is claimed by CWE-830."""
    prose, scan_web = gates
    if prose:
        return False
    if scan_web and _check_web_include(file_path, line, line_num, lines, findings):
        return True
    _check_search_path(file_path, line, line_num, lines, findings)
    return False


def _sri_not_applicable(text: str) -> bool:
    """True when the matched tag already pins an integrity hash, or the vendor
    documents SRI as unsupported for that endpoint (a pinned hash would break
    the page, so the row could never be actioned)."""
    return bool(_SRI_ATTR.search(text) or _SRI_UNSUPPORTED_HOST.search(text))


def _has_nearby(pattern: re.Pattern | None, line_num: int, lines: list[str]) -> bool:
    """True when ``pattern`` occurs within ±3 lines of ``line_num``. A ``None``
    pattern means the arm has no context requirement."""
    if pattern is None:
        return True
    window = "\n".join(lines[max(0, line_num - 4):line_num + 3])
    return bool(pattern.search(window))


def _web_include_match(
    arm: tuple[str, str, str, re.Pattern, re.Pattern | None],
    line: str, line_num: int, lines: list[str],
) -> str | None:
    """Matched text for one CWE-830 arm, or None."""
    match = arm[3].search(line)
    if match is None or _sri_not_applicable(match.group(0)):
        return None
    if not _has_nearby(arm[4], line_num, lines):
        return None
    return match.group(0)


def _check_web_include(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> bool:
    """Check for CWE-830 inclusion of web functionality from an untrusted
    source. Returns True when a row was emitted for this line."""
    for arm in _WEB_INCLUDE_ARMS:
        if _web_include_match(arm, line, line_num, lines) is None:
            continue
        finding = {
            "severity": "medium",
            "check_id": arm[0],
            "category": "CWE-830",
            "title": arm[1],
            "description": (
                f"A {arm[2]} at line {line_num} pulls code from a third-party "
                "origin with no subresource-integrity hash, so whatever that "
                "origin serves — after a CDN, DNS or vendor-account compromise — "
                "runs with this page's full privileges and no tamper detection."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Pin the artefact with integrity=\"sha384-…\" plus crossorigin, "
                "or self-host it and load it same-origin."
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "830"))
        return True
    return False


def _check_search_path(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-427 uncontrolled search path element."""
    for check_id, title, phrase, pattern in _SEARCH_PATH_ARMS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "low",
            "check_id": check_id,
            "category": "CWE-427",
            "title": title,
            "description": (
                f"The {phrase} at line {line_num} contains an element that "
                "resolves relative to the invoking working directory (or to a "
                "world-writable temporary directory), so which module, library "
                "or executable is loaded depends on where the process happens "
                "to be started rather than on this configuration."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Use an absolute path, or one derived from the installed "
                "artefact's own location, and drop empty/relative elements."
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "427"))
        return


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
