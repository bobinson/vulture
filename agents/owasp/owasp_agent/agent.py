"""OWASP Top 10 agent: maps CWE findings onto OWASP categories.

This agent performs NO detection. The CWE agent detects weaknesses and tags
each finding with ``category: "CWE-NNN"``; this agent consumes those findings
(via the standard ``prior_findings`` transport), maps each CWE to its OWASP
Top 10 category for the selected edition, re-labels it, and emits a
per-category coverage manifest.

Invariants (feature 0063):
- Never scans source; never imports detection skills.
- Never fails: a bad edition, missing/malformed priors, or an absent/failed
  CWE stage all resolve to a clear notice + a full (possibly zero) manifest
  and ``agent_end status=completed``.
- Code snippets are never echoed (they can contain secrets); only file+line
  location and metadata are carried onto OWASP findings.
"""

from collections.abc import Generator
from typing import Any

from shared.audit_runner import compute_score
from shared.owasp.coverage import STATUS_ABSENT, STATUS_COMPLETED, build_manifest
from shared.owasp.mapping import Edition, UnknownEditionError, load_edition, parse_cwe_id
from shared.transport.event_emitter import AgUiEventEmitter
from shared.env import env_flag
from shared.tools.window import WINDOW_INHERITED, record_window_reason

_PREREQ_NOTICE = (
    "OWASP agent requires the CWE agent to run first. No CWE findings were "
    "provided, so nothing can be categorized — reporting zero coverage. "
    "Enable the CWE agent (it is added automatically when OWASP is selected)."
)

# Fields carried from a CWE finding onto an OWASP finding. `code_snippet` is
# deliberately EXCLUDED — snippets can contain secrets and must not be
# re-emitted here (feature 0063 security constraint). That exclusion is
# UNCHANGED by 0078.
#
# 0078 track D adds the EVIDENCE fields. Before this, every OWASP row reached
# the DB with no provenance, no validation status and no confidence, however
# well-evidenced the CWE finding it was derived from — 217 of 217 rows on the
# reference target, and the entire remaining empty-provenance population
# fleet-wide once track C had fixed the rest.
#
# Provenance is INHERITED, not replaced with an `owasp_categorized` tag: the
# useful question about an OWASP row is whether the underlying detection was
# deterministic or a model's guess. Inventing a sixth vocabulary value in the
# feature whose thesis is closed declared vocabularies would contradict itself.
#
# The `validation` blob is carried even though its check labels name the CWE
# category, because the alternative is worse than staleness: the backend
# SYNTHESISES a blob when it finds none and then re-votes it, so an absent blob
# is persisted as a FABRICATED confidence rather than as "unvalidated".
_CARRY = (
    "file_path", "line_start", "line_end", "recommendation",
    "provenance", "validation_status", "validation_confidence", "validation",
)

# Keys inside a carried `validation` blob that may hold source text. The 0063
# constraint is about snippets, and a validation extra is another way for one to
# travel; scrubbed defensively so widening _CARRY cannot re-open that door.
_SNIPPET_BEARING = ("quote_text", "code_snippet", "snippet", "evidence_quote")

# The window check id, dropped on carry — see _scrub_validation.
_WINDOW_CHECK_ID = "window"


def _scrub_validation(blob: Any) -> Any:
    """Drop snippet-bearing extras, and the twin's window reason, from a
    carried validation blob.

    The window check is dropped because the WINDOW is the one thing this carry
    deliberately does not bring: 0063 forbids the snippet, so a CWE twin's
    `window: present` would assert evidence that is not on this row — and
    because `record_window_reason` lets the first reason win, it would also
    suppress the truthful `inherited` stamp applied in `_relabel`. Measured
    before this drop: 339 of 340 persisted OWASP rows had an empty snippet and
    claimed `present`.
    """
    if not isinstance(blob, dict):
        return blob
    checks = blob.get("checks")
    if not isinstance(checks, list):
        return blob
    cleaned = []
    for check in checks:
        if isinstance(check, dict) and check.get("id") == _WINDOW_CHECK_ID:
            continue
        if isinstance(check, dict) and isinstance(check.get("extras"), dict):
            check = {**check, "extras": {
                k: v for k, v in check["extras"].items()
                if k not in _SNIPPET_BEARING
            }}
        cleaned.append(check)
    return {**blob, "checks": cleaned}


def _manifest_summary(m: dict) -> str:
    lines = [f"OWASP Top 10:{m['edition']} coverage (CWE stage: {m['cwe_stage_status']}):"]
    for c in m["categories"]:
        lines.append(
            f"  {c['id']} {c['name']}: {c['found_count']}/{c['mapped_count']} "
            f"mapped CWEs found ({c['status']})"
        )
    return "\n".join(lines)


def _window_parity_enabled() -> bool:
    """``VULTURE_FINDING_WINDOW_PARITY`` — default TRUE, read at call time."""
    return env_flag("VULTURE_FINDING_WINDOW_PARITY", True)


def _relabel(finding: dict, cat, cwe_id: int, run_id: str, idx: int) -> dict:
    """Build an OWASP-labeled finding from a CWE finding + its category.

    Required emitter fields (severity, description) are defaulted so a
    malformed prior can never raise (feature 0063 reliability constraint).
    """
    out: dict[str, Any] = {k: finding[k] for k in _CARRY if k in finding}
    if "validation" in out:
        out["validation"] = _scrub_validation(out["validation"])
    out["id"] = f"{run_id}-owasp-{idx}"
    out["severity"] = finding.get("severity") or "medium"
    out["description"] = finding.get("description") or ""
    out["category"] = cat.slug
    out["owasp_category_id"] = cat.id
    out["owasp_category_name"] = cat.name
    out["mapped_from"] = f"CWE-{cwe_id}"
    out["check_id"] = f"owasp.{cat.id}.cwe-{cwe_id}"
    out["references"] = list(dict.fromkeys([*finding.get("references", []), cat.source_url]))
    title = finding.get("title") or f"CWE-{cwe_id}"
    out["title"] = title if title.startswith(f"[{cat.id}]") else f"[{cat.id}] {title}"
    # Feature 0082 C10: this agent never reads source (see the module docstring)
    # and 0063 forbids carrying the CWE row's snippet, so an OWASP row has no
    # code window BY DESIGN. Record that, so an empty window here is
    # distinguishable from a failed read. `inherited` is the honest label even
    # for the 71 of 342 rows that sit at a rollup parent's line — what happened
    # is that the window was not carried, not that a parent stood in for members.
    if _window_parity_enabled() and not out.get("code_snippet"):
        record_window_reason(out, WINDOW_INHERITED)
    return out


def _resolve_edition(config: dict) -> tuple[Edition, list[str]]:
    """Load the requested edition, falling back to default on a bad id.

    Returns (edition, notices) — notices are emitted by the caller. Never
    raises (feature 0063 reliability constraint).
    """
    requested = config.get("edition")
    try:
        return load_edition(requested), []
    except UnknownEditionError:
        fallback = load_edition()
        return fallback, [
            f"Unknown OWASP edition {requested!r}; falling back to "
            f"{fallback.edition_id}."
        ]


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the OWASP categorization and yield SSE events."""
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    config = config or {}
    edition, notices = _resolve_edition(config)
    for n in notices:
        yield emitter.text_message(n)

    selected = set(config.get("categories") or [])
    priors = prior_findings or []
    cwe_status = config.get("cwe_stage_status") or (
        STATUS_ABSENT if not priors else STATUS_COMPLETED
    )

    yield emitter.text_message(
        f"Categorizing {len(priors)} CWE finding(s) against OWASP Top 10:{edition.edition_id}."
    )
    if not priors:
        yield emitter.text_message(_PREREQ_NOTICE)

    detected: set[int] = set()
    emitted: list[dict] = []
    idx = 0
    for f in priors:
        if not isinstance(f, dict):
            continue
        cwe_id = parse_cwe_id(str(f.get("category", "")))
        if cwe_id is None:
            continue
        detected.add(cwe_id)
        for cat in edition.map_cwe(cwe_id):
            if selected and cat.id not in selected:
                continue
            relabeled = _relabel(f, cat, cwe_id, run_id, idx)
            idx += 1
            emitted.append(relabeled)
            yield emitter.finding_event(**relabeled)

    manifest = build_manifest(edition, detected, cwe_stage_status=cwe_status).to_dict()
    yield emitter.text_message(_manifest_summary(manifest))

    files = {f.get("file_path", "") for f in priors if isinstance(f, dict)}
    yield emitter.progress_event(len(files), len(files), len(emitted))

    found = sum(1 for c in manifest["categories"] if c["found_count"] > 0)
    summary = (
        f"Mapped {len(emitted)} finding(s) into {found}/10 OWASP Top 10:"
        f"{edition.edition_id} categories."
    )
    # Reuse the shared scoring convention so the UI treats this agent's score
    # like every other agent's. compute_score guards empty/zero internally.
    score = compute_score(emitted, max(len(priors), len(emitted), 1))
    yield emitter.result_event(
        findings=emitted, summary=summary, score=score,
        extra={"owasp_coverage": manifest},
    )
    yield emitter.run_finished(status="completed")
