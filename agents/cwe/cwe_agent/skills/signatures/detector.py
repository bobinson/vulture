"""P4b — the generic 3-step signature matcher.

One matcher drives every signature (R10): the executor is generic, the
signatures are data. Per candidate line:

  1. **sink gates the line** — the sink regex must match, else skip.
  2. **require_source** — if the signature requires a tainted source, a
     ``source`` match must appear within ``±window`` lines, else skip.
  3. **sanitizer suppresses** — if a ``sanitizer`` match appears within
     ``±window`` lines, the candidate is suppressed.

Signatures are indexed by file extension once (module-level), so a per-file
call only walks the signatures that apply to that extension — keeping the
matcher's cyclomatic complexity low and avoiding a full-registry scan per line.

ReDoS-safety: every line is length-capped to ``_MAX_LINE_CHARS`` before any
regex touches it, on top of the bounded quantifiers the signatures already use.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from shared.tools.snippet import extract_snippet

from cwe_agent.skills.signatures.registry import SIGNATURES
from cwe_agent.skills.signatures.schema import CweSignature

# Catalog language name → file extensions (kept in sync with catalog_detector
# _LANG_EXTENSIONS; duplicated minimally here to avoid a circular import).
_LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "C": (".c", ".h"),
    "C++": (".cpp", ".cc", ".cxx", ".hpp", ".h"),
    "Java": (".java",),
    "Python": (".py",),
    "JavaScript": (".js", ".jsx", ".mjs"),
    "TypeScript": (".ts", ".tsx"),
    "Go": (".go",),
    "PHP": (".php",),
    "Ruby": (".rb",),
    "Rust": (".rs",),
    "C#": (".cs",),
    "Perl": (".pl", ".pm"),
    "Shell": (".sh", ".bash"),
    "SQL": (".sql",),
}

# Hard cap on the number of characters a single line contributes to a regex
# match — defends against pathological long lines (ReDoS / memory).
_MAX_LINE_CHARS = 600


def _build_ext_index() -> dict[str, tuple[CweSignature, ...]]:
    """Index every signature by the file extensions of its languages, once."""
    index: dict[str, list[CweSignature]] = {}
    for sig in SIGNATURES:
        for lang in sig.languages:
            for ext in _LANG_EXTENSIONS.get(lang, ()):  # unknown langs → no ext
                index.setdefault(ext, []).append(sig)
    return {ext: tuple(sigs) for ext, sigs in index.items()}


_SIGS_BY_EXT: dict[str, tuple[CweSignature, ...]] = _build_ext_index()


def _window_text(lines: Sequence[str], idx: int, window: int) -> str:
    """Return the ``±window``-line block around 0-based ``idx`` as one string,
    each line length-capped (ReDoS-safe)."""
    lo = max(0, idx - window)
    hi = min(len(lines), idx + window + 1)
    return "\n".join(line[:_MAX_LINE_CHARS] for line in lines[lo:hi])


def _signature_fires(
    sig: CweSignature, line: str, lines: Sequence[str], idx: int,
) -> bool:
    """Apply the 3-step gate for one signature at 0-based line ``idx``."""
    if not sig.sink.search(line):
        return False
    if sig.require_source or sig.sanitizer is not None:
        window = _window_text(lines, idx, sig.window)
        if sig.require_source and (
            sig.source is None or not sig.source.search(window)
        ):
            return False
        if sig.sanitizer is not None and sig.sanitizer.search(window):
            return False
    return True


def _make_finding(sig: CweSignature, lines: Sequence[str], line_num: int) -> dict:
    """Build a finding dict for a fired signature. Reuses the shared snippet
    helper; emits check_id=sig_id, category=CWE-N, signature_status=status."""
    return {
        "severity": sig.severity,
        "check_id": sig.sig_id,
        "category": f"CWE-{sig.cwe_id}",
        "title": sig.title,
        "description": (
            f"{sig.title} (deterministic signature {sig.sig_id}, "
            f"line {line_num})"
        ),
        "line_start": line_num,
        "line_end": line_num,
        "confidence": sig.confidence,
        "signature_status": sig.status,
        "code_snippet": extract_snippet(lines, line_num),
    }


def match_signatures(lines: Sequence[str], file_ext: str) -> list[dict]:
    """Run every signature applicable to ``file_ext`` over ``lines``.

    Args:
        lines: Source file split into lines (0-indexed sequence).
        file_ext: Lower-case file extension including the dot (e.g. ``".py"``).

    Returns:
        A list of finding dicts (``check_id`` = sig_id, ``category`` = CWE-N).
        At most one finding per signature per file (first hit wins) — the
        catalog rollup / dedup machinery owns cross-detector aggregation.
    """
    sigs = _SIGS_BY_EXT.get(file_ext.lower())
    if not sigs:
        return []
    findings: list[dict] = []
    fired: set[str] = set()
    for idx, raw in enumerate(lines):
        line = raw[:_MAX_LINE_CHARS]
        for sig in sigs:
            if sig.sig_id in fired:
                continue
            if _signature_fires(sig, line, lines, idx):
                findings.append(_make_finding(sig, lines, idx + 1))
                fired.add(sig.sig_id)
    return findings
