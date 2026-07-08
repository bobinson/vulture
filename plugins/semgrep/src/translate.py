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


def _to_repo_relative(path: Any, root: str) -> str:
    """C1 (0058 audit): strip the scan-root prefix so Semgrep's paths match the
    in-tree skills' repo-relative paths (``audit_runner`` emits
    ``relative_to(source_path)``). Without this, a skill's ``app/views.py`` and
    Semgrep's ``/audit-inputs/app/views.py`` never collide in the cross-agent
    dedup key → guaranteed double-reporting. Idempotent for already-relative
    paths, so it is correct whether Semgrep returns absolute or relative."""
    if not isinstance(path, str) or not path:
        return ""
    if root:
        r = root.rstrip(os.sep)
        if path == r:
            return ""
        if path.startswith(r + os.sep):
            return path[len(r) + 1:]
    return path


def _translate_one(r: dict, agent_type: str, root: str = "") -> dict:
    """Translate one Semgrep result into a Vulture Finding dict."""
    extra = r.get("extra", {}) or {}
    message = extra.get("message", "") or ""
    first_line = message.split("\n", 1)[0]
    cwe = extract_cwe(r)
    check_id = r.get("check_id", "")
    path = _to_repo_relative(r.get("path", ""), root)
    line_start = (r.get("start") or {}).get("line")
    # C4 (0058 audit): Semgrep documents severity under extra.severity; fall
    # back to a top-level `severity` defensively so a schema shift can't
    # silently downgrade every finding to info.
    severity = extra.get("severity")
    if severity is None:
        severity = r.get("severity")
    # Compose id from (check_id, path, line) so multiple instances of
    # the same rule at different locations don't collide under the
    # persistence layer's ON CONFLICT DO NOTHING.
    return {
        "id": f"{check_id}:{path}:{line_start}",
        "agent_type": agent_type,
        "title": first_line[:200],
        "description": message,
        "severity": map_severity(severity),
        # Prefer canonical CWE for category; fall back to check_id so
        # the 0050 prefix/rule maps can resolve downstream.
        "category": cwe or check_id,
        # R4 (0058): every finding is CWE-attributed from the rule's own
        # extra.metadata.cwe; unmapped rules are tagged CWE-unknown and
        # NEVER dropped. (The check_id fallback belongs to `category`
        # only — `cwe` is always canonical-or-unknown.)
        "cwe": cwe or "CWE-unknown",
        "check_id": check_id,
        # R6 (0058): tag origin so the orchestrator/UI can distinguish Semgrep
        # findings and (future R7) gate/attribute them separately. These are
        # NOT corpus-gated — provenance makes that explicit downstream.
        "provenance": "semgrep",
        "file_path": path,
        "line_start": line_start,
        "line_end": (r.get("end") or {}).get("line"),
        "code_snippet": extra.get("lines", ""),
    }


def translate_findings(semgrep_json: dict, agent_type: str, root: str = "") -> list[dict]:
    """Translate a full Semgrep JSON document into a list of Findings.

    ``root`` is the scan target (source_path); Semgrep paths are made relative
    to it so they match the in-tree agents' repo-relative paths (C1)."""
    results = (semgrep_json or {}).get("results", []) or []
    return [_translate_one(r, agent_type, root) for r in results]


# P2g (0058): composite scam-risk score. Individually each vendored Solidity
# rule below is a review-level signal; when several co-occur in ONE contract
# the shape is a scam (rug pull / honeypot / wallet drainer). Semgrep cannot
# reason across findings, so we correlate here in a plugin post-process. The
# generic vulns (tx.origin, delegatecall) are deliberately excluded — they are
# bugs, not owner-omnipotence/drainer markers.
SCAM_MARKER_RULE_IDS = frozenset({
    "vulture-solidity-honeypot-transfer-gate",
    "vulture-solidity-uncapped-fee-setter",
    "vulture-solidity-owner-direct-balance-write",
    "vulture-solidity-unprotected-initializer",
    "vulture-solidity-unprotected-selfdestruct",
    "vulture-solidity-arbitrary-from-transferfrom",
    "vulture-solidity-arbitrary-from-nft-transfer",
    "vulture-solidity-set-approval-for-all-untrusted",
})

# Minimum distinct markers in one file before the composite fires.
SCAM_SCORE_MIN_MARKERS = 3


def _bare_rule_id(check_id: Any) -> str:
    """Semgrep namespaces --config-dir rules as `rules.vulture.solidity.<id>`;
    the stable identity is the last dotted segment."""
    return (check_id or "").split(".")[-1] if isinstance(check_id, str) else ""


def _composite_scam_finding(file_path: str, markers: set, agent_type: str, line: Any) -> dict:
    short = sorted(m.replace("vulture-solidity-", "") for m in markers)
    return {
        "id": f"vulture-solidity-composite-scam-risk:{file_path}",
        "agent_type": agent_type,
        "title": (
            f"Composite scam risk: {len(short)} owner-omnipotence / drainer "
            "markers in one contract"
        ),
        "description": (
            "Multiple independent malicious-contract indicators co-occur in this "
            "file (" + ", ".join(short) + "). Individually each is a review "
            "signal; together they strongly indicate a scam contract — rug pull, "
            "honeypot, or wallet drainer. Review ownership powers, fee bounds, "
            "and transfer gating before interacting with or approving it."
        ),
        "severity": "high",
        "category": "CWE-284",
        "cwe": "CWE-284",
        "check_id": "vulture-solidity-composite-scam-risk",
        "provenance": "semgrep",
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": "",
    }


def _accumulate_marker(markers_by_file: dict, line_by_file: dict, f: dict) -> None:
    """Fold one finding into the per-file marker set + earliest-line maps."""
    rid = _bare_rule_id(f.get("check_id"))
    if rid not in SCAM_MARKER_RULE_IDS:
        return
    fp = f.get("file_path") or ""
    markers_by_file.setdefault(fp, set()).add(rid)
    line = f.get("line_start")
    if isinstance(line, int):
        cur = line_by_file.get(fp)
        line_by_file[fp] = line if cur is None else min(cur, line)


def summarize_scam_risk(findings: list[dict], agent_type: str = "semgrep") -> list[dict]:
    """Return synthetic composite findings for files where >= SCAM_SCORE_MIN_MARKERS
    DISTINCT scam markers co-occur. Empty when no file crosses the threshold."""
    markers_by_file: dict[str, set] = {}
    line_by_file: dict[str, Any] = {}
    for f in findings:
        _accumulate_marker(markers_by_file, line_by_file, f)
    return [
        _composite_scam_finding(fp, markers_by_file[fp], agent_type, line_by_file.get(fp))
        for fp in sorted(markers_by_file)
        if len(markers_by_file[fp]) >= SCAM_SCORE_MIN_MARKERS
    ]


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
