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

from shared.anchor import anchor_weight
from shared.env import env_truthy

from .refutation import REFUTATION_MAP, Scope, obligation_check, route_model_for
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
        re.compile(r"\bparameterize\b|\bprepared\b|\bsanitize_sql\b|\bescape_sql\b", re.IGNORECASE),
        re.compile(r"\.bind_param\(|\.execute\([^,]*,\s*\("),
    ],
    "CWE-79": [
        re.compile(r"\b(?:escape|escapeHtml|sanitizeHtml|DOMPurify|html\.escape)\b", re.IGNORECASE),
    ],
    "CWE-78": [
        re.compile(r"\bshlex\.quote\(|\bshell_escape\("),
        re.compile(r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*False", re.IGNORECASE),
    ],
    "CWE-22": [
        re.compile(r"\b(?:os\.path\.realpath|os\.path\.abspath|"
                   r"secure_filename|sanitize_path|validate_path)\b", re.IGNORECASE),
    ],
    "CWE-94": [
        re.compile(r"\b(?:ast\.literal_eval|sandbox|whitelist|allowlist)\b", re.IGNORECASE),
    ],
    "CWE-918": [
        re.compile(r"\b(?:validate_url|allowed_hosts|url_whitelist|"
                   r"is_private_address|ipaddress\.ip_address)\b", re.IGNORECASE),
    ],
    # Resource limits (CWE-770)
    "CWE-770": [
        re.compile(r"\b(?:max_size|max_length|maxlength|max_count|"
                   r"limit|timeout|deadline|max_workers|maxlen|capacity|"
                   r"max_concurrent|throttle|rate_limit|semaphore|"
                   r"bounded_|context\.WithTimeout|asyncio\.wait_for)\b", re.IGNORECASE),
        re.compile(r"\.MaxBytesReader\(|\.MaxRequestBodySize\b"),
    ],
    # Exceptional condition handling (CWE-755)
    "CWE-755": [
        re.compile(r"\b(?:except\s+\w+(?:Error|Exception)\b|"
                   r"errors\.(?:Is|As)\(|"
                   r"if\s+err\s*!=\s*nil)", re.IGNORECASE),
        # Specific named exception (vs bare except:)
        re.compile(r"except\s+[A-Z]\w+(?:Error|Exception)\s*(?:as\s+\w+)?\s*:"),
    ],
    # Insufficient logging (CWE-778)
    "CWE-778": [
        re.compile(r"\b(?:logger|logging|log)\.(?:error|exception|warn|"
                   r"warning|critical|fatal|info)\s*\(", re.IGNORECASE),
        re.compile(r"\bzap\.|\bzerolog\.|\.WithError\("),
        # Go-side
        re.compile(r"\blog\.(?:Printf|Println|Print|Errorf)\s*\("),
    ],
    # Null-pointer / dereference (CWE-476)
    "CWE-476": [
        re.compile(r"\bif\s+\w+\s+is\s+(?:not\s+)?None\b", re.IGNORECASE),
        re.compile(r"\bif\s+\w+\s*!=\s*nil\b"),
        re.compile(r"\.get\([^,)]+,\s*\w+\)"),     # dict.get(k, default)
        re.compile(r"\b(?:Optional|None|nullable|optional)\b"),
    ],
    # Information exposure through logs (CWE-532)
    "CWE-532": [
        re.compile(r"\b(?:redact|mask|sanitize|scrub|filter_sensitive|"
                   r"remove_pii|strip_secrets)\b", re.IGNORECASE),
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
                   r"pydantic|marshmallow|cerberus|jsonschema)\b", re.IGNORECASE),
    ],
    # File upload (CWE-434)
    "CWE-434": [
        re.compile(r"\b(?:allowed_extensions|file_type|mimetype|content_type|"
                   r"max_size|validate_file)\b", re.IGNORECASE),
    ],
    # Authentication (CWE-287, CWE-306)
    "CWE-287": [
        re.compile(r"\b(?:authenticate|authorize|require_auth|@login_required|"
                   r"@require_permission|Bearer\s+|JWT)\b", re.IGNORECASE),
    ],
    "CWE-306": [
        re.compile(r"\b(?:authenticate|require_auth|@login_required|"
                   r"require_authentication)\b", re.IGNORECASE),
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
    _scan_for_sanitizer.cache_clear()


# ── T2.6: textual matching must not fire on comments or string literals ──
# A word-level regex like \bsanitize\b matching a comment ("TODO: sanitize
# this") or a log string would discharge an obligation nothing satisfied.
# Strings are blanked FIRST (so a '#' or '//' inside a string cannot truncate
# the code part), then line comments and inline block comments are dropped.
# Best-effort and line-based by design: multi-line strings/docstrings are not
# tracked; the failure mode is a missed strip (extra discharge), never a
# dropped finding — discharge only supports, it cannot refute (§5.1).
# Single-sourced in shared.tools.line_context so detectors and the validate
# layer cannot drift apart. NOTE the bias differs by layer: here a missed strip
# means an extra discharge (safe); in a detector it would mean a dropped
# finding, which is why that module forbids using it as a hard skip.
from shared.tools.line_context import strip_strings_and_comments


def _strip_comments_and_strings(line: str) -> str:
    return strip_strings_and_comments(line)


@functools.lru_cache(maxsize=4096)
def _scan_for_sanitizer(
    file_path: str, category: str, start: int, end: int,
) -> int:
    """First sanitizer-pattern hit in lines [start, end) (0-based bounds),
    after comment/string stripping. Returns the 1-based line, or 0.

    Memoised on (file, class, extent) — T2.4: the extent MUST be in the key,
    or one function's answer would be served for a different function under a
    sub-file scope. For FILE scope the extent is stable, so the cache
    collapses to one entry per (file, class) where it matters most. Cleared
    per validate() call via clear_l1_cache.
    """
    patterns = SANITIZER_MAP.get(category, [])
    lines = _read_lines_cached(file_path)
    for i in range(max(0, start), min(end, len(lines))):
        stripped = _strip_comments_and_strings(lines[i])
        if not stripped:
            continue
        for pat in patterns:
            if pat.search(stripped):
                return i + 1
    return 0


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


# ─── Feature 0076: the evidence-quote anchor status ─────────────────
# The LLM phase stamps the verifier's outcome onto the finding as PRIVATE,
# underscore-prefixed fields and strips them before egress. `run_l1` is their
# last consumer: the check it emits here is the status's ONLY persisted route
# (§5.4(4)), because `_apply_validation_to_finding` (validate/__init__.py:194)
# overwrites `finding["validation"]` wholesale, so a check pre-stamped during
# the LLM phase would be destroyed before the voter ever saw it (C2/AC16).
#
# The WEIGHT is not decided here. `shared.anchor.anchor_weight` is the one
# authority for it and reads `VULTURE_LLM_QUOTE_DEMOTE_ABSENT` at CALL time:
# every status is 0.0 except `absent`, and `absent` only while that switch is
# on. Re-deriving the table here would be the non-DRY alternative, and gating
# only the AUTHORITATIVE_CHECKS membership while leaving −1.0 applied is the
# exact silent downgrade AC34 forbids.
_ANCHOR_ID = "anchor"

# (private stamp, extras key). Numeric provenance only — the status itself is
# the check's `result`, like every other L1 check's outcome label.
_ANCHOR_PROVENANCE: tuple[tuple[str, str], ...] = (
    ("_claimed_line", "claimed_line"),
    ("_anchor_delta", "delta"),
    ("_anchor_candidates", "candidates"),
    ("_anchor_other_path", "other_path"),
    ("_anchor_quote_chars", "quote_chars"),
    ("_anchor_quote_tokens", "quote_tokens"),
)

_KEEP_TEXT = "VULTURE_LLM_QUOTE_KEEP_TEXT"


def _kept_quote(finding: dict[str, Any]) -> str:
    """The redacted quote to retain, or "" — the default retains nothing.

    `VULTURE_LLM_QUOTE_KEEP_TEXT=true` buys offline debugging, never a secret
    channel: what is retained is `_redact_snippet(quote)`, the same primitive
    `code_snippet` already goes through. Imported lazily because `audit_runner`
    imports this package.
    """
    quote = str(finding.get("evidence_quote") or "")
    if not quote or not env_truthy(_KEEP_TEXT):
        return ""
    from shared.audit_runner import _redact_snippet

    return _redact_snippet(quote)


def _anchor_extras(finding: dict[str, Any]) -> dict[str, Any]:
    """The verifier's numeric provenance, plus a redacted quote under KEEP_TEXT."""
    extras: dict[str, Any] = {
        name: finding[stamp]
        for stamp, name in _ANCHOR_PROVENANCE
        if finding.get(stamp) is not None
    }
    kept = _kept_quote(finding)
    if kept:
        extras["quote_redacted"] = kept
    return extras


def _anchor_reason(finding: dict[str, Any], status: str) -> str:
    """The verifier's own reason, not just a restatement of the status.

    `anchor.py` distinguishes outcomes the status alone cannot: a truncated
    quote that still matched exactly is `oversize` with reason `truncated:exact`,
    and one that matched nowhere is `unquoted` with `oversize_truncated`. Building
    the reason as f"evidence quote: {status}" discarded that, so the oversize
    bucket stayed undecomposable in the persisted blob even after the verifier
    learned to decompose it.
    """
    detail = str(finding.get("_anchor_reason") or "")
    return f"evidence quote: {status}" + (f" ({detail})" if detail else "")


def _anchor_check(finding: dict[str, Any]) -> ValidationCheck | None:
    """The `anchor` check for a finding the verifier stamped, else None.

    A finding with no `_anchor_status` (every skill finding, and every LLM
    finding when `VULTURE_LLM_QUOTE_VERIFY=off`) carries no anchor check at
    all — an absent check and a zero-weight one must stay distinguishable.
    """
    status = str(finding.get("_anchor_status") or "")
    if not status:
        return None

    return ValidationCheck(
        id=_ANCHOR_ID, result=status, weight=anchor_weight(status),
        reason=_anchor_reason(finding, status),
        extras=_anchor_extras(finding),
    )


def _sanitizer_search_extent(
    file_path: str, line_start: int, category: str,
) -> tuple[int, int, str]:
    """(start, end, scope_searched) for the sanitizer scan — 0-based bounds.

    T2.4: a class whose declared refutation scope is FILE **and reviewed**
    is searched across the whole file, forward as well as backward. Every
    other class keeps the legacy 20-line backward window — behaviour-
    preserving until each migrated entry is reviewed (T2.1a). The window
    actually used is recorded as `scope_searched` so the obligation's
    `scope_actual` extras (and T7.4's divergence alert) reflect the truth.
    """
    lines = _read_lines_cached(file_path)
    ref = REFUTATION_MAP.get(category)
    if ref is not None and ref.scope is Scope.FILE and ref.scope_reviewed:
        return 0, len(lines), "file"
    return max(0, line_start - 21), min(len(lines), line_start), "window20_backward"


def _sanitizer_check(
    file_path: str, line_start: int, category: str,
) -> ValidationCheck:
    """Scan the class's search extent for a sanitizer pattern matching the
    finding's CWE category (comment- and string-stripped — T2.6/AC17).
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
    start, end, scope_searched = _sanitizer_search_extent(
        file_path, line_start, category)
    hit = _scan_for_sanitizer(file_path, category, start, end)
    if hit:
        # Feature 0072 P0: a mitigation match must NEVER promote.
        #
        # SANITIZER_MAP holds patterns for SAFE practice (parameterize,
        # prepared, bind_param, DOMPurify, shlex.quote), so a match is
        # evidence that the weakness is mitigated. Returning +0.15 here
        # meant a parameterised query near a CWE-89 sink RAISED the
        # SQL-injection finding's confidence — the sign was backwards.
        #
        # The weight is now neutral and `result` no longer claims a
        # direction. The state stays distinguishable from "absent"
        # because the obligation model needs to tell "searched, found a
        # mitigation" apart from "searched, found nothing".
        return ValidationCheck(
            id="sanitizer", result="matched", weight=0.0,
            reason=f"mitigation pattern matched on line {hit}",
            extras={"sanitizer_at": hit, "category": category,
                    "scope_searched": scope_searched},
        )
    return ValidationCheck(id="sanitizer", result="absent", weight=0.0,
                           reason="no sanitizer in surrounding lines",
                           extras={"scope_searched": scope_searched})


def _scope_available(category: str, source_root: str = "") -> bool:
    """Whether the resolver for this class's declared scope can decide HERE.

    WIRING scope is available only when a route model actually resolved routes
    for this tree. A model that found none means the stack is one no resolver
    understands, which must report unavailable rather than "searched and clean":
    a non-degradable class then stays `unknown` instead of discharging at a
    narrower scope — precisely how an earlier design re-opened the very
    false-positive class this feature exists to close.
    """
    ref = REFUTATION_MAP.get(category)
    if ref is None or ref.scope is not Scope.WIRING:
        return True
    model = route_model_for(source_root)
    return model is not None and bool(model.routes())


def _obligation_for(
    f: dict[str, Any], san: ValidationCheck, category: str,
    file_path: str, line_start: int, source_root: str,
) -> ValidationCheck:
    """Feature 0072: derive the obligation from the search that just ran.

    `no_map` / `no_file` / `skipped` mean the mitigation was never searched
    for, which must be distinguishable from "searched and found nothing" — in
    an additive vote both are weight 0.0.

    A WIRING-scoped class is resolved against the route model when a source
    root is known; where no model resolves, its scope reports unavailable and
    the non-degradable classes stay `unknown` rather than discharging at a
    narrower scope.
    """
    return obligation_check(
        category, san.result,
        scope_available=_scope_available(category, source_root),
        file_path=file_path,
        line_start=line_start,
        source_root=source_root or None,
        check_id=f.get("check_id") or "",
        scope_searched=(san.extras or {}).get("scope_searched", ""),
    )


def _optional_checks(
    f: dict[str, Any], file_path: str, line_start: int,
) -> list[ValidationCheck]:
    """The checks that may not apply at all — a suppression marker, and feature
    0076's `anchor`.

    Absent rather than neutral: a check that is MISSING and a check that weighs
    0.0 are different facts, and only the second one says "we looked".
    """
    found = (_suppression_check(file_path, line_start), _anchor_check(f))
    return [c for c in found if c is not None]


def _finding_checks(
    f: dict[str, Any], source_root: str,
) -> list[ValidationCheck]:
    """Every L1 check for ONE finding, in blob order."""
    file_path = f.get("file_path", "") or ""
    line_start = int(f.get("line_start") or 0)
    category = f.get("category", "") or ""
    san = _sanitizer_check(file_path, line_start, category)
    return [
        _path_check(file_path),
        *_optional_checks(f, file_path, line_start),
        san,
        _obligation_for(f, san, category, file_path, line_start, source_root),
    ]


def _l1_error_checks(
    f: dict[str, Any], exc: BaseException,
) -> list[ValidationCheck]:
    """RC3: a crashed layer must not read as "checked and clean" — emit a
    blocking obligation alongside the error so the batch cannot be confirmed
    on the strength of a layer that never ran.
    """
    return [
        ValidationCheck(
            id="path", result="error", weight=0.0,
            reason=f"L1 error: {type(exc).__name__}: {str(exc)[:100]}",
        ),
        obligation_check(f.get("category", "") or "", None),
    ]


def run_l1(
    findings: list[dict[str, Any]], source_root: str = "",
) -> list[list[ValidationCheck]]:
    """Run L1 against every finding; return per-finding check lists.

    `source_root` enables WIRING-scope refutation: without it an authorization
    obligation can only ever be `unknown`, because the middleware chain that
    would refute it lives outside any window this layer can see.

    Layer-isolated (RC3): one finding raising does NOT prevent others.
    """
    results: list[list[ValidationCheck]] = []
    for f in findings:
        try:
            results.append(_finding_checks(f, source_root))
        except Exception as exc:    # RC3 layer isolation
            results.append(_l1_error_checks(f, exc))
    return results
