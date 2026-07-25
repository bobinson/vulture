"""L1 context heuristics — path classifier, suppression markers,
surrounding-line sanitizer scan.

Pure function. Reads ±20 lines around each finding via the existing
`read_file_lines` helper, with a process-local LRU cache for the
duration of one validate() call (the helper is hopefully already
cached; this layer doesn't trust that and re-caches defensively).
"""

from __future__ import annotations

import functools
import re
from typing import Any

from .types import ValidationCheck

__all__ = ["run_l1"]


# ─── Path classification (demote test/vendor, promote production) ──

_DEMOTING_PATH_RE = re.compile(
    r"(?:^|/)(?:"
    # Standard test / fixture conventions
    r"tests?|test_data|testdata|fixtures?|examples?|samples?|demos?|"
    r"specs?|__tests__|spec|e2e|integration_tests?|unit_tests?|"
    # Dependencies / vendored
    r"vendor|third_party|node_modules|\.venv|venv|__pycache__|stubs|"
    r"\.gradle|build|target|out|dist|coverage|htmlcov|\.pytest_cache|"
    # Documentation / data
    r"docs?|examples|tutorials?|sample[_-]?code|cookbook|"
    # Generated / cached data (specific to this codebase)
    r"data|cache|\.cache|generated|"
    # Verification target (deliberately vulnerable code)
    r"simulated[_-]target|verification/simulated"
    r")(?:/|$)"
    # Also match specific filename suffixes
    r"|(?:_test|_spec|\.test|\.spec|_mock|\.mock)\.(?:py|go|ts|tsx|js)$"
    # Catalog / pure-data JSON
    r"|(?:cwe_catalog|asvs_catalog|requirements\.txt|requirements-frozen\.txt|"
    r"package(?:-lock)?\.json|go\.sum|Cargo\.lock)$"
    # Vendored upstream data
    r"|(?:^|/)docs/features/[0-9]"
    # Catalog data subdirs
    r"|(?:^|/)agents/[^/]+/[^/]+/data/"
    # Skill source code — files that DESCRIBE detection patterns rather
    # than contain vulnerable code. Self-scan 2026-05-26 showed these
    # are the largest FP source (60% of findings). The files literally
    # contain regex strings that match their own patterns.
    r"|(?:^|/)agents/[^/]+/[^/]+/skills/"
    # Tool helpers under agents/shared/shared/tools — same story:
    # obfuscation.py describes obfuscation patterns; _var_reference.py
    # documents $VAR indirection as a safe pattern; etc.
    r"|(?:^|/)agents/shared/shared/tools/"
    # The validate package itself — it scans for sanitiser keywords
    # in source code, so its own code naturally contains those keywords.
    r"|(?:^|/)agents/shared/shared/validate/",
    re.IGNORECASE,
)
_PROMOTING_PATH_RE = re.compile(
    r"(?:^|/)(?:"
    r"main\.(?:py|go|ts|tsx)|"
    r"app\.(?:py|go|ts)|"
    r"server\.(?:py|go|ts)|"
    r"cmd/|prod|production|"
    # Production handler / service / repository paths
    r"backend/internal/(?:handler|server|service|repository)/|"
    # Backend command line
    r"backend/cmd/|"
    # Frontend public pages
    r"frontend/src/pages/"
    r")(?:/|$)",
    re.IGNORECASE,
)


# ─── Suppression markers (operator override; authoritative per V7) ──

_SUPPRESSION_RE = re.compile(
    r"#\s*(?:nosec|noqa(?::\s*[A-Z][A-Z0-9_]+)?)\b"
    r"|//\s*(?:nolint|noqa)\b"
    r"|gosec\s*:\s*ignore\b"
    r"|eslint-disable(?:-next-line)?\b"
)


# ─── Sanitizer regex per CWE category (M1 spec) ───
# Seeded from known patterns in the existing skill detectors. Extending
# this map is a one-line diff per category. v1 ships with the highest-
# volume CWE categories.

SANITIZER_MAP: dict[str, list[re.Pattern[str]]] = {
    "CWE-89": [
        re.compile(r"\bparameterize\b|\bprepared\b|\bsanitize_sql\b|\bescape_sql\b", re.I),
        re.compile(r"\.bind_param\(|\.execute\([^,]*,\s*\("),
    ],
    "CWE-79": [
        re.compile(r"\b(?:escape|escapeHtml|sanitizeHtml|DOMPurify|html\.escape)\b", re.I),
    ],
    "CWE-78": [
        re.compile(r"\bshlex\.quote\(|\bshell_escape\("),
        re.compile(r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*False", re.I),
    ],
    "CWE-22": [
        re.compile(r"\b(?:os\.path\.realpath|os\.path\.abspath|"
                   r"secure_filename|sanitize_path|validate_path)\b", re.I),
    ],
    "CWE-94": [
        re.compile(r"\b(?:ast\.literal_eval|sandbox|whitelist|allowlist)\b", re.I),
    ],
    "CWE-918": [
        re.compile(r"\b(?:validate_url|allowed_hosts|url_whitelist|"
                   r"is_private_address|ipaddress\.ip_address)\b", re.I),
    ],
    # Resource limits (CWE-770)
    "CWE-770": [
        re.compile(r"\b(?:max_size|max_length|maxlength|max_count|"
                   r"limit|timeout|deadline|max_workers|maxlen|capacity|"
                   r"max_concurrent|throttle|rate_limit|semaphore|"
                   r"bounded_|context\.WithTimeout|asyncio\.wait_for)\b", re.I),
        re.compile(r"\.MaxBytesReader\(|\.MaxRequestBodySize\b"),
    ],
    # Exceptional condition handling (CWE-755)
    "CWE-755": [
        re.compile(r"\b(?:except\s+\w+(?:Error|Exception)\b|"
                   r"errors\.(?:Is|As)\(|"
                   r"if\s+err\s*!=\s*nil)", re.I),
        # Specific named exception (vs bare except:)
        re.compile(r"except\s+[A-Z]\w+(?:Error|Exception)\s*(?:as\s+\w+)?\s*:"),
    ],
    # Insufficient logging (CWE-778)
    "CWE-778": [
        re.compile(r"\b(?:logger|logging|log)\.(?:error|exception|warn|"
                   r"warning|critical|fatal|info)\s*\(", re.I),
        re.compile(r"\bzap\.|\bzerolog\.|\.WithError\("),
        # Go-side
        re.compile(r"\blog\.(?:Printf|Println|Print|Errorf)\s*\("),
    ],
    # Null-pointer / dereference (CWE-476)
    "CWE-476": [
        re.compile(r"\bif\s+\w+\s+is\s+(?:not\s+)?None\b", re.I),
        re.compile(r"\bif\s+\w+\s*!=\s*nil\b"),
        re.compile(r"\.get\([^,)]+,\s*\w+\)"),     # dict.get(k, default)
        re.compile(r"\b(?:Optional|None|nullable|optional)\b"),
    ],
    # Information exposure through logs (CWE-532)
    "CWE-532": [
        re.compile(r"\b(?:redact|mask|sanitize|scrub|filter_sensitive|"
                   r"remove_pii|strip_secrets)\b", re.I),
    ],
    # Improper exception handling (CWE-248) and CWE-754
    "CWE-754": [
        re.compile(r"\bif\s+err\s*!=\s*nil\b|\bexcept\s+\w+"),
    ],
    "CWE-248": [
        re.compile(r"\btry\s*:[^\n]*\n[^\n]*\bexcept\s+\w+(?:Error|Exception)\b",
                   re.MULTILINE),
    ],
    # Insecure randomness (CWE-330)
    "CWE-330": [
        re.compile(r"\b(?:secrets|os\.urandom|crypto/rand|rand\.Reader)\b"),
        re.compile(r"\b(?:secrets\.token_(?:hex|urlsafe|bytes)|"
                   r"secrets\.choice)\b"),
    ],
    # Improper input validation (CWE-20)
    "CWE-20": [
        re.compile(r"\b(?:validate|is_valid|is_safe|sanitize|"
                   r"pydantic|marshmallow|cerberus|jsonschema)\b", re.I),
    ],
    # File upload (CWE-434)
    "CWE-434": [
        re.compile(r"\b(?:allowed_extensions|file_type|mimetype|content_type|"
                   r"max_size|validate_file)\b", re.I),
    ],
    # Authentication (CWE-287, CWE-306)
    "CWE-287": [
        re.compile(r"\b(?:authenticate|authorize|require_auth|@login_required|"
                   r"@require_permission|Bearer\s+|JWT)\b", re.I),
    ],
    "CWE-306": [
        re.compile(r"\b(?:authenticate|require_auth|@login_required|"
                   r"require_authentication)\b", re.I),
    ],
}


def _path_check(file_path: str) -> ValidationCheck:
    """Path classifier — neutral / demote / promote based on the path."""
    if not file_path:
        return ValidationCheck(
            id="path", result="neutral", weight=0.0,
            reason="file_path is empty (dependency-policy finding)",
        )
    if _DEMOTING_PATH_RE.search(file_path):
        return ValidationCheck(
            id="path", result="demoted", weight=-0.20,
            reason="path matches test/vendor/docs/examples",
            extras={"file_path": file_path},
        )
    if _PROMOTING_PATH_RE.search(file_path):
        return ValidationCheck(
            id="path", result="promoted", weight=0.10,
            reason="path matches production entry point",
            extras={"file_path": file_path},
        )
    return ValidationCheck(
        id="path", result="neutral", weight=0.0,
        reason="path uncategorised",
    )


@functools.lru_cache(maxsize=256)
def _read_lines_cached(file_path: str) -> tuple[str, ...]:
    """Module-level cache to avoid re-reading the same file for
    multiple findings. Use `clear_l1_cache()` between validate calls.
    """
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            return tuple(f.read().splitlines())
    except (OSError, PermissionError):
        return ()


def clear_l1_cache() -> None:
    _read_lines_cached.cache_clear()


def _suppression_check(file_path: str, line_start: int) -> ValidationCheck | None:
    """Scan the window [line_start - 2, line_start] for a suppression
    directive. Returns an authoritative-demoting check if found,
    otherwise None.
    """
    if not file_path or line_start <= 0:
        return None
    lines = _read_lines_cached(file_path)
    if not lines:
        return None
    start = max(0, line_start - 3)   # -3 because line numbers are 1-indexed
    end = min(len(lines), line_start)
    for i in range(start, end):
        m = _SUPPRESSION_RE.search(lines[i])
        if m:
            return ValidationCheck(
                id="suppression", result="demoted", weight=-0.40,
                reason=f"suppression marker on line {i + 1}: {m.group(0).strip()}",
                extras={"marker_line": i + 1, "marker_text": m.group(0).strip()},
            )
    return None


def _sanitizer_check(
    file_path: str, line_start: int, category: str,
) -> ValidationCheck:
    """Scan the window [line_start - 20, line_start] for a sanitizer
    pattern matching the finding's CWE category. Returns a promoting
    check if found, otherwise a neutral check.
    """
    if not file_path or line_start <= 0:
        return ValidationCheck(id="sanitizer", result="skipped", weight=0.0,
                               reason="no line context")
    patterns = SANITIZER_MAP.get(category, [])
    if not patterns:
        return ValidationCheck(id="sanitizer", result="no_map", weight=0.0,
                               reason=f"no sanitizer map for {category}")
    lines = _read_lines_cached(file_path)
    if not lines:
        return ValidationCheck(id="sanitizer", result="no_file", weight=0.0,
                               reason="could not read file")
    start = max(0, line_start - 21)
    end = min(len(lines), line_start)
    for i in range(start, end):
        for pat in patterns:
            if pat.search(lines[i]):
                return ValidationCheck(
                    id="sanitizer", result="promoted", weight=0.15,
                    reason=f"sanitizer matched on line {i + 1}",
                    extras={"sanitizer_at": i + 1, "category": category},
                )
    return ValidationCheck(id="sanitizer", result="absent", weight=0.0,
                           reason="no sanitizer in surrounding lines")


def run_l1(findings: list[dict[str, Any]]) -> list[list[ValidationCheck]]:
    """Run L1 against every finding; return per-finding check lists.

    Layer-isolated (RC3): one finding raising does NOT prevent others.
    """
    results: list[list[ValidationCheck]] = []
    for f in findings:
        try:
            file_path = f.get("file_path", "") or ""
            line_start = int(f.get("line_start") or 0)
            category = f.get("category", "") or ""

            checks: list[ValidationCheck] = []
            checks.append(_path_check(file_path))

            sup = _suppression_check(file_path, line_start)
            if sup is not None:
                checks.append(sup)

            checks.append(_sanitizer_check(file_path, line_start, category))

            results.append(checks)
        except Exception as exc:    # RC3 layer isolation
            results.append([ValidationCheck(
                id="path", result="error", weight=0.0,
                reason=f"L1 error: {type(exc).__name__}: {str(exc)[:100]}",
            )])
    return results
