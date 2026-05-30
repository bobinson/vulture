"""Translate Semgrep JSON findings into Vulture's Finding shape.

Also exposes ``normalise_source_path`` (TM4/BLOCKER #9 path-traversal
+ argv-injection guard). The wrapper imports both from here.
"""

from __future__ import annotations

import os
import re
from typing import Any

# Real Semgrep JSON emits "cwe": ["CWE-89: Improper Neutralization..."]
# A list of human-readable strings with the CWE-NNN prefix; strip to
# the canonical form via this regex. (BLOCKER #5.)
_CWE_RE = re.compile(r"^(CWE-\d{1,5})\b")

# MINOR #14: ERROR → high (not critical) so L2 rollup groups Semgrep
# findings with in-tree high-severity findings on the same (category,
# file_path).
_SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
}


def extract_cwe(rule: dict) -> str | None:
    """Return canonical CWE-NNN string from a Semgrep finding, or None
    if no parseable CWE in ``rule.extra.metadata.cwe``.

    Handles both list-of-strings and scalar-string forms. Anything that
    doesn't begin with ``CWE-<digits>`` is treated as missing.
    """
    extra = rule.get("extra") if isinstance(rule, dict) else None
    if not isinstance(extra, dict):
        return None
    metadata = extra.get("metadata")
    if not isinstance(metadata, dict):
        return None
    cwes: Any = metadata.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    if not isinstance(cwes, list):
        return None
    for entry in cwes:
        if not isinstance(entry, str):
            continue
        m = _CWE_RE.match(entry.strip())
        if m:
            return m.group(1)
    return None


def map_severity(s: str | None) -> str:
    """Map Semgrep severity (ERROR/WARNING/INFO) to Vulture severity.

    Anything unrecognised — including ``None`` and the empty string —
    falls back to ``info``.
    """
    if not isinstance(s, str):
        return "info"
    return _SEMGREP_SEVERITY_MAP.get(s, "info")


def _translate_one(r: dict, agent_type: str) -> dict:
    """Translate one Semgrep result into a Vulture Finding dict."""
    extra = r.get("extra", {}) or {}
    message = extra.get("message", "") or ""
    first_line = message.split("\n", 1)[0]
    cwe = extract_cwe(r)
    check_id = r.get("check_id", "")
    path = r.get("path", "")
    line_start = (r.get("start") or {}).get("line")
    # Compose id from (check_id, path, line) so multiple instances of
    # the same rule at different locations don't collide under the
    # persistence layer's ON CONFLICT DO NOTHING.
    return {
        "id": f"{check_id}:{path}:{line_start}",
        "agent_type": agent_type,
        "title": first_line[:200],
        "description": message,
        "severity": map_severity(extra.get("severity", "INFO")),
        # Prefer canonical CWE for category; fall back to check_id so
        # the 0050 prefix/rule maps can resolve downstream.
        "category": cwe or check_id,
        "check_id": check_id,
        "file_path": r.get("path", ""),
        "line_start": (r.get("start") or {}).get("line"),
        "line_end": (r.get("end") or {}).get("line"),
        "code_snippet": extra.get("lines", ""),
    }


def translate_findings(semgrep_json: dict, agent_type: str) -> list[dict]:
    """Translate a full Semgrep JSON document into a list of Findings."""
    results = (semgrep_json or {}).get("results", []) or []
    return [_translate_one(r, agent_type) for r in results]


def normalise_source_path(raw: Any, root: str) -> str | None:
    """Validate + canonicalise an audit source_path.

    Returns the resolved absolute path on success, or ``None`` if the
    input fails any of the safety checks:

    * not a non-empty string;
    * starts with ``-`` (would be parsed as a Semgrep flag — TM4);
    * contains a literal ``..`` component (defence-in-depth);
    * resolves (via ``os.path.realpath``, following symlinks) to a
      target outside ``root``.

    The prefix check requires either exact equality with ``root`` or a
    trailing OS separator, so a sibling like ``/audit-inputs-evil`` is
    rejected against root ``/audit-inputs``.
    """
    if not isinstance(raw, str) or not raw:
        return None
    if raw.startswith("-"):
        return None
    if ".." in raw.split(os.sep):
        return None
    resolved = os.path.realpath(raw)
    real_root = os.path.realpath(root)
    if resolved != real_root and not resolved.startswith(real_root + os.sep):
        return None
    return resolved
