"""Catalog-driven generic CWE detection engine.

Uses enriched CWE v4.19.1 catalog metadata to detect weaknesses beyond
the hand-crafted regex patterns in individual skill modules. The engine:

1. Loads all CWEs marked as static-analysis detectable
2. Builds keyword-to-CWE index for fast file-level matching
3. For matched CWEs, applies catalog-derived pattern heuristics
4. Context-aware exclusions reduce false positives
5. Produces enriched findings with catalog confidence scores

This gives broad coverage of 400+ additional CWEs that the 15 hand-crafted
skills don't explicitly cover. Findings from this engine carry a
``catalog_confidence`` field reflecting detection reliability.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,

    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import (
    enrich_finding,
    get_static_detectable,
    load_catalog,
)

# CWE IDs already covered by dedicated skill modules — skip to avoid
# dupes. Includes direct skill CWEs AND their child/variant CWEs to
# prevent near-duplicate findings (e.g. CWE-22 covers CWE-23..40 path
# traversal).
#
# These are split into two layers:
#   _BASE_DEDICATED_CWES : the explicit, hand-curated list. Edit this
#                          when adding a new skill that owns a CWE
#                          family.
#   _DEDICATED_SKILL_CWES: the runtime-merged superset that ALSO pulls
#                          CWE IDs from `category: "CWE-N"` strings in
#                          every registered skill detector — so adding
#                          a skill whose check_id mentions a new CWE
#                          automatically suppresses the catalog
#                          detector from re-emitting it.
_BASE_DEDICATED_CWES = frozenset({
    # --- Direct dedicated skill CWEs ---
    "16", "20", "22", "78", "79", "89", "94", "113", "120", "125", "134",
    "190", "200", "209", "252", "269", "287", "295", "306", "312", "319",
    "321",  # added in batch 1 — hardcoded crypto key (was wrongly 327)
    "326", "327", "328", "330", "352", "362", "367", "384", "390", "400",
    "401", "404", "415", "416", "434", "457", "467", "476", "494", "502",
    "506", "521", "532", "562", "601", "611", "614", "639", "662", "668",
    "681", "704", "732", "754", "755", "770", "787", "798", "824", "829",
    "833", "838", "862", "863", "918", "937", "942", "1004", "1021",
    "1104", "1188", "1275", "1295", "1321", "1336",
    # --- Task 4 narrow skills: divide/dangerous/logging/exception/entropy ---
    "242", "248", "331", "332", "338", "369", "676", "778",
    # --- Path traversal family (children of CWE-22) ---
    "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33",
    "34", "35", "36", "37", "38", "39", "40",
    # --- XSS variants (children of CWE-79) ---
    "80", "81", "82", "83", "84", "85", "86", "87",
    # --- Info exposure variants (children of CWE-200) ---
    "201", "203", "204", "205", "206", "207", "208", "210", "211",
    "497", "535", "536", "537", "538",
    # --- Cleartext storage variants (children of CWE-312) ---
    "313", "314", "315", "316", "317", "318", "526",
    # --- Path equivalence family (children of CWE-41) ---
    "42", "43", "46", "48", "49", "50", "51", "52", "54", "55", "56", "57",
    "158", "159",
})


def _discovered_cwes_from_skills() -> frozenset[str]:
    """Scan registered skill modules for CWE IDs they mention in
    ``category`` literals. This catches new skills that ship a
    `category: "CWE-N"` without having to remember to update
    _BASE_DEDICATED_CWES.

    Best-effort: parses string-literal occurrences via a regex against
    each skill module's source. Failures (file unreadable, import
    error) fall back silently to _BASE_DEDICATED_CWES alone.
    """
    cwe_re = re.compile(r'"CWE-(\d+)"|\'CWE-(\d+)\'')
    found: set[str] = set()
    skills_dir = Path(__file__).parent
    try:
        for py in skills_dir.rglob("*_check.py"):
            try:
                txt = py.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in cwe_re.finditer(txt):
                found.add(m.group(1) or m.group(2))
    except OSError:
        return frozenset()
    return frozenset(found)


_DEDICATED_SKILL_CWES = _BASE_DEDICATED_CWES | _discovered_cwes_from_skills()

# Data/config file extensions that should not be analyzed for CWE patterns.
# These files contain structured data, not executable source code.
_DATA_EXTENSIONS = frozenset({".json", ".xml", ".yaml", ".yml", ".toml"})

# Common comment/import/scanner exclusion patterns
_COMMENT = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
_IMPORT = re.compile(r"^\s*(?:from|import|require|use|#\s*include)\s")

# Pre-compiled regex for keyword extraction (Issue #6: avoid per-call recompilation)
_LINE_KEYWORD_RE = re.compile(r"[a-zA-Z_]\w{2,}")

from shared.tools.file_scanner import SCANNER_DEF_LINE as _SCANNER_DEF  # DRY

# Generic programming tokens that match nearly every source line and cause
# false positives when used as CWE keyword matches.
_GENERIC_TOKENS = frozenset({
    "error", "errors", "message", "value", "return", "function",
    "string", "type", "object", "data", "use", "used", "get",
    "set", "check", "access", "information", "through", "code",
    "the", "and", "for", "with", "from", "that", "this",
    "input", "output", "result", "name", "file", "path",
    "method", "request", "response", "status", "control",
    "exception", "handling", "read", "write", "list",
})

# Max files a single CWE can be reported across before being capped.
_MAX_FILES_PER_CWE = 8

# Language extension mapping for catalog language filtering
_LANG_EXTENSIONS: dict[str, frozenset[str]] = {
    "C": frozenset({".c", ".h"}),
    "C++": frozenset({".cpp", ".cc", ".cxx", ".hpp", ".h"}),
    "Java": frozenset({".java"}),
    "Python": frozenset({".py"}),
    "JavaScript": frozenset({".js", ".jsx", ".mjs"}),
    "TypeScript": frozenset({".ts", ".tsx"}),
    "Go": frozenset({".go"}),
    "PHP": frozenset({".php"}),
    "Ruby": frozenset({".rb"}),
    "Rust": frozenset({".rs"}),
    "C#": frozenset({".cs"}),
    "Perl": frozenset({".pl", ".pm"}),
    "Shell": frozenset({".sh", ".bash"}),
    "SQL": frozenset({".sql"}),
}

# Severity mapping from catalog consequences
_IMPACT_SEVERITY: dict[str, str] = {
    "Execute Unauthorized Code or Commands": "critical",
    "Gain Privileges or Assume Identity": "critical",
    "Bypass Protection Mechanism": "high",
    "Read Application Data": "high",
    "Modify Application Data": "high",
    "Read Memory": "high",
    "Modify Memory": "high",
    "DoS: Crash, Exit, or Restart": "high",
    "DoS: Resource Consumption (CPU)": "medium",
    "DoS: Resource Consumption (Memory)": "medium",
    "DoS: Resource Consumption (Other)": "medium",
    "Read Files or Directories": "high",
    "Modify Files or Directories": "high",
    "Hide Activities": "medium",
    "Reduce Performance": "low",
    "Quality Degradation": "low",
    "Varies by Context": "medium",
    "Other": "medium",
    "Unexpected State": "medium",
    "Alter Execution Logic": "high",
}


@lru_cache(maxsize=1)
def _build_keyword_index() -> dict[str, list[dict[str, Any]]]:
    """Build keyword → CWE entries index for fast lookup. Thread-safe singleton."""
    index: dict[str, list[dict[str, Any]]] = {}
    for entry in get_static_detectable(min_score=0.2):
        if entry["id"] in _DEDICATED_SKILL_CWES:
            continue
        entry["_specific_kw"] = frozenset(entry.get("keywords", [])) - _GENERIC_TOKENS
        for kw in entry.get("keywords", []):
            index.setdefault(kw, []).append(entry)
    return index


def _severity_from_consequences(consequences: list[dict]) -> str:
    """Derive severity from CWE catalog consequences."""
    best = "medium"
    for c in consequences:
        impact = c.get("impact", "")
        sev = _IMPACT_SEVERITY.get(impact, "medium")
        if sev == "critical":
            return "critical"
        if sev == "high":
            best = "high"
    return best


def _file_matches_languages(file_ext: str, cwe_languages: list[str]) -> bool:
    """Check if file extension matches CWE's applicable languages."""
    if not cwe_languages:
        return True  # Language-agnostic
    for lang in cwe_languages:
        exts = _LANG_EXTENSIONS.get(lang, frozenset())
        if file_ext in exts:
            return True
    return False


def _extract_line_keywords(line: str) -> set[str]:
    """Extract lowercase keywords from a code line, excluding generic tokens."""
    return {w.lower() for w in _LINE_KEYWORD_RE.findall(line)} - _GENERIC_TOKENS


def _keyword_match_score(line_keywords: set[str], specific_kw: frozenset[str]) -> float:
    """Score how well a line's keywords match a CWE's pre-computed specific keywords.

    Requires at least 3 non-generic keyword matches AND 40% overlap ratio
    to reduce false positives from coincidental token overlap.
    """
    if not specific_kw or not line_keywords:
        return 0.0
    matched = line_keywords & specific_kw
    if len(matched) < 3:
        return 0.0
    ratio = len(matched) / len(specific_kw)
    if ratio < 0.4:
        return 0.0
    return min(1.0, ratio)


# Keywords that indicate safe/mitigated patterns
_SAFE_CONTEXT = re.compile(
    r"(?:sanitize|validate|escape|encode|whitelist|allowlist|parameterize|"
    r"prepared|binding|safeguard|mitigat|protect|secure|verify|check|"
    r"assert|ensure|guard|filter|clean|purif)",
    re.IGNORECASE,
)


def check_catalog_generic(source_path: str) -> dict:
    """Scan source code using catalog-driven keyword matching.

    Uses the CWE v4.19.1 enriched catalog to detect weaknesses beyond
    the hand-crafted regex patterns. Matches are scored by keyword overlap
    and catalog confidence, filtered by language applicability.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of catalog-detected vulnerabilities.
    """
    findings: list[dict] = []
    kw_index = _build_keyword_index()
    if not kw_index:
        return {"findings": findings}

    seen_per_file: dict[str, set[str]] = {}
    cwe_file_counts: dict[str, int] = {}

    catalog = load_catalog()

    for file_path in scan_code_files(source_path):
        if file_path.suffix.lower() in _DATA_EXTENSIONS:
            continue
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, kw_index, findings, seen_per_file, cwe_file_counts, catalog)

    return {"findings": findings}


def _is_class_or_pillar(parent: dict[str, Any] | None) -> bool:
    """True if parent entry has Class or Pillar abstraction."""
    return bool(parent) and parent.get("abstraction") in ("Class", "Pillar")


def _collect_parent_child_hits(
    file_key: str,
    seen_per_file: dict[str, set[str]],
    catalog: dict[str, Any],
) -> dict[str, set[str]]:
    """For each Class/Pillar parent, collect which children are seen in this file."""
    child_hits: dict[str, set[str]] = {}
    for child_cwe in seen_per_file.get(file_key, set()):
        for r in catalog.get(child_cwe, {}).get("related_weaknesses", []):
            if r.get("nature") != "ChildOf":
                continue
            parent_id = r.get("cwe_id", "")
            if not _is_class_or_pillar(catalog.get(parent_id)):
                continue
            child_hits.setdefault(parent_id, set()).add(child_cwe)
    return child_hits


def _build_rollup_finding(
    file_path: Path,
    parent_id: str,
    parent: dict[str, Any],
    hits: set[str],
) -> dict[str, Any]:
    """Build a single rollup finding dict for a Class/Pillar parent."""
    sorted_hits = sorted(hits)
    return {
        "severity": _severity_from_consequences(parent.get("consequences", [])),
        "check_id": f"cwe.catalog.cwe_{parent_id}.rollup",
        "category": f"CWE-{parent_id}",
        "title": parent.get("name", f"CWE-{parent_id}"),
        "description": (
            f"Multiple children of CWE-{parent_id} matched in this file: "
            f"{', '.join('CWE-' + c for c in sorted_hits)}"
        ),
        "file_path": str(file_path),
        "line_start": 1,
        "line_end": 1,
        "recommendation": parent.get(
            "mitigation",
            "Review the code for the class-level weakness pattern.",
        ),
        "rollup_children": sorted_hits,
    }


def _emit_parent_rollups(
    file_path: Path,
    file_key: str,
    seen_per_file: dict[str, set[str]],
    cwe_file_counts: dict[str, int],
    findings: list[dict],
    catalog: dict[str, Any],
) -> None:
    """Emit Class/Pillar rollup findings for files where >=2 distinct
    children of the same parent matched. Respects _MAX_FILES_PER_CWE."""
    child_hits = _collect_parent_child_hits(file_key, seen_per_file, catalog)
    for parent_id, hits in child_hits.items():
        if len(hits) < 2:
            continue
        if parent_id in seen_per_file[file_key]:
            continue
        if cwe_file_counts.get(parent_id, 0) >= _MAX_FILES_PER_CWE:
            continue
        parent = catalog[parent_id]
        finding = _build_rollup_finding(file_path, parent_id, parent, hits)
        findings.append(enrich_finding(finding, parent_id))
        seen_per_file[file_key].add(parent_id)
        cwe_file_counts[parent_id] = cwe_file_counts.get(parent_id, 0) + 1


def _analyze_file(
    file_path: Path,
    kw_index: dict[str, list[dict[str, Any]]],
    findings: list[dict],
    seen_per_file: dict[str, set[str]],
    cwe_file_counts: dict[str, int],
    catalog: dict[str, Any] | None = None,
) -> None:
    """Analyze a file using catalog keyword matching."""
    lines = read_file_lines(file_path)
    if lines is None:
        return

    file_ext = file_path.suffix.lower()
    file_key = str(file_path)

    if file_key not in seen_per_file:
        seen_per_file[file_key] = set()
    for line_num, line in enumerate(lines, start=1):
        if _COMMENT.match(line):
            continue
        if _IMPORT.match(line):
            continue
        if _SCANNER_DEF.search(line):
            continue

        line_keywords = _extract_line_keywords(line)
        if not line_keywords:
            continue

        ctx_start = max(0, line_num - 4)
        ctx_end = min(len(lines), line_num + 3)
        context = "\n".join(lines[ctx_start:ctx_end])
        has_safe_context = _SAFE_CONTEXT.search(context) is not None

        candidate_cwes: dict[str, float] = {}
        for kw in line_keywords:
            if kw not in kw_index:
                continue
            for entry in kw_index[kw]:
                cwe_id = entry["id"]
                if cwe_id in seen_per_file[file_key]:
                    continue
                if cwe_file_counts.get(cwe_id, 0) >= _MAX_FILES_PER_CWE:
                    continue
                if not _file_matches_languages(file_ext, entry.get("languages", [])):
                    continue
                score = _keyword_match_score(line_keywords, entry.get("_specific_kw", frozenset()))
                if score > candidate_cwes.get(cwe_id, 0):
                    candidate_cwes[cwe_id] = score

        for cwe_id, score in sorted(candidate_cwes.items(), key=lambda x: -x[1]):
            if score < 0.6:
                continue
            if has_safe_context and score < 0.8:
                continue

            entry = (catalog or load_catalog()).get(cwe_id)
            if not entry:
                continue

            abstraction = entry.get("abstraction", "")
            if abstraction in ("Pillar", "Class"):
                continue

            seen_per_file[file_key].add(cwe_id)
            cwe_file_counts[cwe_id] = cwe_file_counts.get(cwe_id, 0) + 1
            severity = _severity_from_consequences(entry.get("consequences", []))
            catalog_conf = entry.get("static_detectability", 0.5)
            effective_conf = round(catalog_conf * score, 2)

            finding = {
                "severity": severity,
                "check_id": f"cwe.catalog.cwe_{cwe_id}",
                "category": f"CWE-{cwe_id}",
                "title": entry.get("name", f"CWE-{cwe_id}"),
                "description": (
                    f"Potential {entry.get('name', 'weakness')} detected via "
                    f"catalog keyword matching at line {line_num} "
                    f"(confidence: {effective_conf:.0%})"
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": entry.get("mitigation", "Review this code for the identified weakness pattern."),
                "catalog_confidence": effective_conf,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, cwe_id))
            if len(seen_per_file[file_key]) >= 15:
                break

    _emit_parent_rollups(
        file_path, file_key, seen_per_file, cwe_file_counts,
        findings, catalog or load_catalog(),
    )


check_catalog_generic_tool = function_tool(check_catalog_generic)
