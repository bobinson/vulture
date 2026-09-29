"""OWASP Top 10 agent: maps CWE findings onto OWASP categories.

This agent performs NO detection. The CWE agent detects weaknesses and tags
each finding with ``category: "CWE-NNN"``; this agent consumes those findings
(via the standard ``prior_findings`` transport), maps each CWE to its OWASP
Top 10 category for the selected edition, re-labels it, and emits a
per-category coverage manifest.

Two answers, chosen per request by negotiation (feature 0096):

- MAPPING (the backend's out-of-band ``accepts_mapping`` is the integer 1):
  the result carries the
  edition's full CWE->category table as a ``mapping`` object and NO findings.
  The backend labels its final, deduplicated CWE-categorised findings with it,
  so a weakness is persisted, counted and triaged once.
- LEGACY (anything else): one OWASP copy row per mapped CWE finding, exactly as
  feature 0063 shipped it. A backend that predates 0096 never sends the key,
  and would read a zero-finding OWASP result as "every OWASP issue was fixed",
  so this answer stays until the release after 0096.

The capability arrives as the TOP-LEVEL ``accepts_mapping`` field of the /run
body, which the transport passes to ``run_audit`` as the ``accepts_mapping``
keyword. ``config["accepts_mapping"]`` is ignored: a pre-0096 backend forwards
arbitrary user config keys to agents, so a capability read from config could
be claimed by a user on a backend that would then close OWASP lineage (H1).

Invariants (feature 0063):
- Never scans source; never imports detection skills.
- Never fails: a bad edition, missing/malformed priors, or an absent/failed
  CWE stage all resolve to a clear notice + a full (possibly zero) manifest
  and ``agent_end status=completed``.
- Code snippets are never echoed (they can contain secrets); only file+line
  location and metadata are carried onto OWASP findings.
"""

import json
from collections.abc import Generator, Iterator
from typing import Any

from shared.audit_runner import compute_score
from shared.env import env_flag
from shared.owasp.coverage import STATUS_ABSENT, STATUS_COMPLETED, build_manifest
from shared.owasp.mapping import Edition, UnknownEditionError, load_edition, parse_cwe_id
from shared.tools.window import WINDOW_INHERITED, record_window_reason
from shared.transport.event_emitter import AgUiEventEmitter

_PREREQ_NOTICE = (
    "OWASP agent requires the CWE agent to run first. No CWE findings were "
    "provided, so nothing can be categorized — reporting zero coverage. "
    "Enable the CWE agent (it is added automatically when OWASP is selected)."
)

# The mapping-result version this agent speaks (feature 0096). The backend
# advertises the version it can consume as the top-level /run field
# `accepts_mapping` (never a config key); any other value,
# absence included, gets the legacy answer, so version skew in either direction
# degrades to copy rows and never to a zero-finding result an older backend
# would close lineage on.
MAPPING_VERSION = 1

# The fields that identify one prior finding for the mapping-mode score: a
# prior repeated verbatim counts once, distinct sites each count.
_PRIOR_IDENTITY = (
    "category", "check_id", "file_path", "line_start", "line_end", "title", "severity",
)

# The `selected` of a filter that selects NOTHING. `[]` means "all", so a
# filter left with no usable id needs an id of its own: this one has the
# category-id shape the backend requires and belongs to no edition.
_SELECT_NONE = "A00"

# --- legacy answer (feature 0063) ------------------------------------------
# _CARRY, _SNIPPET_BEARING, _scrub_validation, the window stamp in _relabel and
# the `owasp.{cat}.cwe-{N}` check id exist only for the legacy answer and are
# deleted with it.

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
    out["severity"] = _prior_severity(finding)
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


def _prior_severity(finding: dict) -> str:
    """A prior's severity, ``medium`` when it is missing, empty or not a string.

    Both answers apply this default, so a malformed severity never raises and
    scores the same whichever answer was negotiated (feature 0063 reliability
    constraint).
    """
    severity = finding.get("severity")
    return severity if isinstance(severity, str) and severity else "medium"


# How much of an unknown edition value a notice echoes. The value is arbitrary
# audit input, so it is truncated and repr-quoted: it can neither flood the
# stream nor inject a line.
_ECHO_MAX = 32


def _bounded_repr(value: Any) -> str:
    """``repr`` of *value*, at most ``_ECHO_MAX`` characters of it echoed."""
    if isinstance(value, str):
        return repr(value[:_ECHO_MAX]) + ("..." if len(value) > _ECHO_MAX else "")
    if value is None or isinstance(value, (bool, int, float)):
        text = repr(value)
        return text[:_ECHO_MAX] + ("..." if len(text) > _ECHO_MAX else "")
    return f"<{type(value).__name__}>"


def _resolve_edition(config: dict) -> tuple[Edition, list[str]]:
    """Load the requested edition, falling back to default on a bad id.

    Returns (edition, notices) — notices are emitted by the caller. Never
    raises (feature 0063 reliability constraint).
    """
    requested = config.get("edition")
    try:
        # An edition id is a string; a list or object (unhashable) would raise
        # TypeError inside the registry lookup, so it is unknown by definition.
        if isinstance(requested, (list, dict)):
            raise UnknownEditionError(f"edition of type {type(requested).__name__}")
        return load_edition(requested), []
    except UnknownEditionError:
        fallback = load_edition()
        return fallback, [
            f"Unknown OWASP edition {_bounded_repr(requested)}; falling back to "
            f"{fallback.edition_id}."
        ]


def _speaks_mapping(accepts_mapping: Any) -> bool:
    """Whether the backend asked for the mapping answer.

    *accepts_mapping* is the out-of-band top-level /run field, NEVER
    ``config["accepts_mapping"]`` (H1). Only the integer version this agent
    speaks qualifies. ``True == 1`` and ``1.0 == 1`` in Python, so a boolean
    and a float are refused by the exact type check: the capability is a
    version number, and anything else is "not asked".
    """
    return type(accepts_mapping) is int and accepts_mapping == MAPPING_VERSION


def _cwe_priors(priors: list) -> Iterator[tuple[dict, int]]:
    """Yield ``(finding, cwe_id)`` for every prior that is a CWE finding.

    Malformed entries (non-dicts, non-CWE categories) are skipped, never
    raised on (feature 0063 reliability constraint).
    """
    for f in priors:
        if not isinstance(f, dict):
            continue
        cwe_id = parse_cwe_id(str(f.get("category", "")))
        if cwe_id is not None:
            yield f, cwe_id


def _selected_categories(edition: Edition, cwe_id: int, selected: set[str]) -> list:
    """The edition's categories for ``cwe_id``, narrowed to ``selected`` (empty = all)."""
    return [c for c in edition.map_cwe(cwe_id) if not selected or c.id in selected]


def _cwe_stage_status(config: dict, priors: list) -> str:
    """The backend's CWE-stage provenance, else inferred from the priors."""
    return config.get("cwe_stage_status") or (STATUS_ABSENT if not priors else STATUS_COMPLETED)


def _found_categories(manifest: dict) -> int:
    """Legacy summary count: found in ANY category, whatever was selected.

    Kept only because the legacy answer is pinned byte for byte (0063 golden);
    the mapping answer uses :func:`_category_tally`.
    """
    return sum(1 for c in manifest["categories"] if c["found_count"] > 0)


def _category_tally(manifest: dict, selected: list[str]) -> tuple[int, int]:
    """``(found, total)`` over the audit's category universe (mapping answer).

    The universe is the selected categories of the edition, or every category
    of the edition when nothing is selected (``[]``); a filter that selects
    nothing (``[_SELECT_NONE]``) has an empty universe. ``found`` counts the
    categories of that universe with at least one found CWE.
    """
    universe = [c for c in manifest["categories"] if not selected or c["id"] in selected]
    return sum(1 for c in universe if c["found_count"] > 0), len(universe)


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
    *,
    accepts_mapping: Any = None,
) -> Generator[str, None, None]:
    """Execute the OWASP categorization and yield SSE events.

    *accepts_mapping* is the backend's out-of-band capability (the top-level
    /run field, passed by the transport); ``None`` means absent. Any
    ``accepts_mapping`` key inside *config* is ignored.
    """
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    config = config or {}
    edition, notices = _resolve_edition(config)
    for n in notices:
        yield emitter.text_message(n)

    priors = prior_findings or []
    cwe_status = _cwe_stage_status(config, priors)

    yield emitter.text_message(
        f"Categorizing {len(priors)} CWE finding(s) against OWASP Top 10:{edition.edition_id}."
    )
    if not priors:
        yield emitter.text_message(_PREREQ_NOTICE)

    if _speaks_mapping(accepts_mapping):
        yield from _mapping_answer(emitter, edition, config, priors, cwe_status)
    else:
        selected = set(config.get("categories") or [])
        yield from _legacy_answer(emitter, run_id, edition, selected, priors, cwe_status)
    yield emitter.run_finished(status="completed")


def _legacy_answer(
    emitter: AgUiEventEmitter,
    run_id: str,
    edition: Edition,
    selected: set[str],
    priors: list,
    cwe_status: str,
) -> Iterator[str]:
    """Feature 0063: one OWASP copy row per (CWE finding, selected category)."""
    detected: set[int] = set()
    emitted: list[dict] = []
    for f, cwe_id in _cwe_priors(priors):
        detected.add(cwe_id)
        for cat in _selected_categories(edition, cwe_id, selected):
            relabeled = _relabel(f, cat, cwe_id, run_id, len(emitted))
            emitted.append(relabeled)
            yield emitter.finding_event(**relabeled)

    manifest = build_manifest(edition, detected, cwe_stage_status=cwe_status).to_dict()
    yield emitter.text_message(_manifest_summary(manifest))

    files = {f.get("file_path", "") for f in priors if isinstance(f, dict)}
    yield emitter.progress_event(len(files), len(files), len(emitted))

    summary = (
        f"Mapped {len(emitted)} finding(s) into {_found_categories(manifest)}/10 OWASP Top 10:"
        f"{edition.edition_id} categories."
    )
    # Reuse the shared scoring convention so the UI treats this agent's score
    # like every other agent's. compute_score guards empty/zero internally.
    score = compute_score(emitted, max(len(priors), len(emitted), 1))
    yield emitter.result_event(
        findings=emitted, summary=summary, score=score,
        extra={"owasp_coverage": manifest},
    )


# --- mapping answer (feature 0096) -----------------------------------------


def _edition_table(edition: Edition) -> dict[str, list[dict[str, str]]]:
    """The edition's FULL CWE->categories table, keyed ``"CWE-<n>"``.

    Every CWE the edition maps, whatever the audit selected: the backend keeps
    lineage labels per edition across category subsets. Entries carry only
    ``id`` and ``name`` and follow the edition's category order; keys are in
    numeric order so the payload is stable run to run.
    """
    table: dict[int, list[dict[str, str]]] = {}
    for cat in edition.categories:
        for cwe in cat.cwes:
            table.setdefault(cwe, []).append({"id": cat.id, "name": cat.name})
    return {f"CWE-{cwe}": table[cwe] for cwe in sorted(table)}


def _effective_selected(edition: Edition, categories: Any) -> tuple[list[str], int]:
    """The audit's ``categories`` filter as the backend will apply it.

    Returns ``(selected, dropped)``. ``selected`` holds the edition's own
    category ids, in the order given, each once; ``[]`` (no filter) means all.
    The backend rejects a whole mapping over one bad ``selected`` entry, so
    anything else — another agent's vocabulary, a non-string, an id this
    edition lacks, a filter that is not a list — is dropped and counted. A
    filter left with no usable id selects nothing (``[_SELECT_NONE]``), as the
    legacy answer's does, never all.
    """
    if not categories:
        return [], 0
    # A filter that is not a list ("A07", 7, {...}) counts as one unusable entry.
    entries = categories if isinstance(categories, list) else [None]
    kept = _edition_ids_in(edition, entries)
    return list(dict.fromkeys(kept)) or [_SELECT_NONE], len(entries) - len(kept)


def _edition_ids_in(edition: Edition, entries: list) -> list[str]:
    """The entries that are one of the edition's category ids, as given."""
    ids = {c.id for c in edition.categories}
    return [e for e in entries if isinstance(e, str) and e in ids]


def _selected_label(selected: list[str]) -> str:
    if not selected:
        return "all"
    return "none" if selected == [_SELECT_NONE] else ",".join(selected)


def _dropped_notice(edition: Edition, dropped: int) -> str:
    """Counts the dropped filter entries without echoing them: they are
    arbitrary audit input, of any length."""
    entries = "entry" if dropped == 1 else "entries"
    return (
        f"Ignored {dropped} categories filter {entries}: not an OWASP Top 10:"
        f"{edition.edition_id} category id."
    )


def _mapping_object(edition: Edition, selected: list[str]) -> dict:
    """The ``mapping`` member of a mapping-mode result (mapping v1).

    ``selected`` is the effective category filter (``[]`` = all). Only
    edition knowledge travels here — no prior finding's text (0096 I6).
    """
    return {
        "version": MAPPING_VERSION,
        "framework": "owasp",
        "edition": edition.edition_id,
        "selected": selected,
        "table": _edition_table(edition),
    }


def _prior_key(f: dict) -> str:
    return json.dumps([f.get(k) for k in _PRIOR_IDENTITY], default=str)


def _scored_priors(priors: list, edition: Edition, selected: set[str]) -> list[dict]:
    """The DISTINCT priors that map to at least one selected category.

    One entry per prior however many categories it maps to; a prior repeated
    verbatim counts once. Pre-dedup by necessity: the agent never sees the
    backend's final finding set. Each carries the severity the legacy answer
    would give it, so the score is the same whichever answer was negotiated.
    """
    seen: set[str] = set()
    out: list[dict] = []
    for f, cwe_id in _cwe_priors(priors):
        key = _prior_key(f)
        if key in seen or not _selected_categories(edition, cwe_id, selected):
            continue
        seen.add(key)
        out.append({**f, "severity": _prior_severity(f)})
    return out


def _mapping_answer(
    emitter: AgUiEventEmitter,
    edition: Edition,
    config: dict,
    priors: list,
    cwe_status: str,
) -> Iterator[str]:
    """Feature 0096: the edition's table, the coverage manifest, no findings."""
    selected, dropped = _effective_selected(edition, config.get("categories"))
    if dropped:
        yield emitter.text_message(_dropped_notice(edition, dropped))
    mapping = _mapping_object(edition, selected)
    yield emitter.text_message(
        f"Mapping v{MAPPING_VERSION}: returning the OWASP Top 10:{edition.edition_id} "
        f"table ({len(mapping['table'])} CWEs, selected={_selected_label(selected)}); "
        "the CWE findings are labelled with it, and no OWASP finding rows are emitted."
    )

    detected = {cwe_id for _, cwe_id in _cwe_priors(priors)}
    manifest = build_manifest(edition, detected, cwe_stage_status=cwe_status).to_dict()
    yield emitter.text_message(_manifest_summary(manifest))

    files = {f.get("file_path", "") for f in priors if isinstance(f, dict)}
    yield emitter.progress_event(len(files), len(files), 0)

    scored = _scored_priors(priors, edition, set(selected))
    found, total = _category_tally(manifest, selected)
    summary = (
        f"Mapped {len(scored)} finding(s) into {found}/{total} OWASP Top 10:"
        f"{edition.edition_id} categories."
    )
    score = compute_score(scored, max(len(priors), 1))
    yield emitter.result_event(
        findings=[], summary=summary, score=score,
        extra={"owasp_coverage": manifest, "mapping": mapping},
    )
