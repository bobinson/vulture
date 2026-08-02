"""Line-stack collapse for skill findings.

Skill findings are never deduplicated against each other: every skill runs
independently over the whole tree, so one source construct can produce
several rows anchored to the *same* ``(file_path, line_start)``. Some of
those rows are genuinely different problems with different remediations
(three separately-missing cookie attributes, say) and must all survive.
Others are the same problem stated at two levels of abstraction, where one
CWE is a generalisation of the other — reporting both adds no remediation
value and inflates the count.

This module collapses only the second kind, and only on evidence read from
the CWE catalog rather than a hand-maintained id list:

    For rows sharing (file_path, line_start), drop row A when A's category is
    a **transitive ancestor** of some other category B present on that line,
    following ``related_weaknesses`` edges whose nature is ``ChildOf``.

Consequences of that rule, all of them deliberate:

* **Siblings never collapse.** Two categories that merely share a parent are
  not in an ancestor relation, so both survive. Dropping one would discard a
  distinct remediation — that is a rollup/presentation concern, not dedup.
* Only the general row is dropped; the specific descendant is the one an
  engineer can act on.
* Severity is preserved: a survivor is raised to the maximum severity of the
  ancestors that collapsed into it, so a high-severity generalisation is
  never silently downgraded by a medium-severity specialisation.
* The outcome is order-independent (the line's *set* of categories decides,
  not list position), emission order of the survivors is unchanged, and a
  line can never lose its last categorised row.

The catalog is optional. When it cannot be located the hierarchy is empty,
every group is left untouched, and the collapse degrades to a no-op — an
agent shipping without the catalog data still audits, it just does not
collapse.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections import OrderedDict
from collections.abc import Callable, Iterable
from functools import lru_cache
from operator import itemgetter
from pathlib import Path
from typing import Any

__all__ = [
    "CATALOG_PATH_ENV",
    "collapse_line_stacks",
    "cwe_ancestors",
    "max_severity",
]

logger = logging.getLogger(__name__)

# Env override for the catalog location; useful for tests and for agents that
# vendor the data somewhere other than the conventional package layout.
CATALOG_PATH_ENV = "VULTURE_CWE_CATALOG_PATH"

_CHILD_OF = "ChildOf"
_CATALOG_GLOBS = ("*/data/cwe_catalog.json", "*/*/data/cwe_catalog.json")
_CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)

# Same ranking the rollup layer uses; kept local so this module carries no
# dependency on the validate package.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def max_severity(sevs: Iterable[str]) -> str:
    """Highest severity label in ``sevs`` (unknown labels rank lowest)."""
    return max(sevs, key=lambda s: _SEVERITY_RANK.get((s or "").lower(), 0))


# --------------------------------------------------------------------------
# Catalog -> ChildOf hierarchy
# --------------------------------------------------------------------------


def _search_roots() -> list[Path]:
    """Directories to look for a packaged catalog under.

    First the tree that holds the sibling agent packages (source checkout
    layout: ``shared/shared/tools/<this file>`` -> the agents directory),
    then the import path, which is where an installed agent's data file
    lives. Both are searched with a glob, so nothing here is tied to which
    agent happens to ship the catalog.
    """
    return [Path(__file__).resolve().parents[3], *(Path(p) for p in sys.path if p)]


def _first_match(root: Path) -> Path | None:
    """First catalog file found directly beneath ``root``."""
    for pattern in _CATALOG_GLOBS:
        hit = next(iter(sorted(root.glob(pattern))), None)
        if hit is not None:
            return hit
    return None


def _discover_catalog() -> Path | None:
    for root in _search_roots():
        hit = _first_match(root) if root.is_dir() else None
        if hit is not None:
            return hit
    return None


def _catalog_path() -> Path | None:
    """Locate the CWE catalog JSON, or None when it is not installed."""
    override = os.environ.get(CATALOG_PATH_ENV, "").strip()
    if not override:
        return _discover_catalog()
    path = Path(override)
    return path if path.is_file() else None


def _load_catalog() -> dict[str, Any]:
    """Parse the catalog JSON; {} when absent or unreadable (degraded mode)."""
    path = _catalog_path()
    if path is None:
        logger.info("finding_collapse: no CWE catalog found; collapse disabled")
        return {}
    try:
        with path.open() as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("finding_collapse: catalog unreadable at %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _is_child_edge(edge: dict, cid: str) -> bool:
    """True when ``edge`` names a usable ``ChildOf`` parent other than ``cid``."""
    pid = str(edge.get("cwe_id", "")).strip()
    return edge.get("nature") == _CHILD_OF and pid not in ("", cid)


def _parent_ids(entry: dict, cid: str) -> set[str]:
    """One-hop ``ChildOf`` parent ids declared by a catalog entry."""
    edges = entry.get("related_weaknesses") or []
    return {str(e.get("cwe_id", "")).strip() for e in edges if _is_child_edge(e, cid)}


def _direct_parents() -> dict[str, frozenset[str]]:
    """Numeric CWE id -> ids named by its one-hop ``ChildOf`` edges."""
    parents: dict[str, frozenset[str]] = {}
    for cid, entry in _load_catalog().items():
        pids = _parent_ids(entry, str(cid)) if isinstance(entry, dict) else set()
        if pids:
            parents[str(cid)] = frozenset(pids)
    return parents


@lru_cache(maxsize=1)
def _hierarchy() -> dict[str, frozenset[str]]:
    """Numeric CWE id -> all transitive ``ChildOf`` ancestors.

    Walked iteratively with a visited set, so a malformed catalog containing
    a relationship cycle terminates instead of recursing forever.
    """
    parents = _direct_parents()
    closure: dict[str, frozenset[str]] = {}
    for cid, direct in parents.items():
        seen: set[str] = set()
        stack = list(direct)
        while stack:
            pid = stack.pop()
            if pid not in seen:
                seen.add(pid)
                stack.extend(parents.get(pid, ()))
        closure[cid] = frozenset(seen)
    return closure


def cwe_ancestors(cwe_id: str) -> frozenset[str]:
    """Transitive ``ChildOf`` ancestors of a numeric CWE id string."""
    return _hierarchy().get(cwe_id, frozenset())


def _cwe_id(finding: dict) -> str | None:
    """Numeric id from a ``CWE-N`` category, or None for anything else."""
    match = _CWE_RE.match(str(finding.get("category", "")).strip())
    return match.group(1) if match else None


# --------------------------------------------------------------------------
# Collapse
# --------------------------------------------------------------------------

_Pair = tuple[int, dict]
_Ancestors = Callable[[str], frozenset[str]]


def _generalises_any(cid: str, ids: set[str], ancestors: _Ancestors) -> bool:
    """True when ``cid`` is a transitive ancestor of another id in ``ids``."""
    return any(cid in ancestors(other) for other in ids if other != cid)


def _redundant_ids(ids: set[str], ancestors: _Ancestors) -> set[str]:
    """Ids in ``ids`` that generalise another id in the same set."""
    return {cid for cid in ids if _generalises_any(cid, ids, ancestors)}


def _group_ids(pairs: list[_Pair]) -> set[str]:
    """Distinct numeric CWE ids present in a line stack."""
    ids: set[str] = set()
    for _idx, row in pairs:
        cid = _cwe_id(row)
        if cid:
            ids.add(cid)
    return ids


def _split(pairs: list[_Pair], redundant: set[str]) -> tuple[list[_Pair], list[_Pair]]:
    """Partition a line stack into (survivors, rows to collapse away)."""
    kept: list[_Pair] = []
    dropped: list[_Pair] = []
    for idx, row in pairs:
        bucket = dropped if _cwe_id(row) in redundant else kept
        bucket.append((idx, row))
    return kept, dropped


def _absorbed_severities(
    row: dict, dropped: list[_Pair], ancestors: _Ancestors
) -> list[str]:
    """Severities of the collapsed rows that generalise ``row``."""
    anc = ancestors(_cwe_id(row) or "")
    return [d.get("severity", "") for _idx, d in dropped if _cwe_id(d) in anc]


def _promote(
    kept: list[_Pair], dropped: list[_Pair], ancestors: _Ancestors
) -> list[_Pair]:
    """Copy survivors, raising each to the severity of what collapsed into it."""
    out: list[_Pair] = []
    for idx, row in kept:
        absorbed = _absorbed_severities(row, dropped, ancestors)
        if absorbed:
            row = dict(row)
            row["severity"] = max_severity([row.get("severity", "")] + absorbed)
        out.append((idx, row))
    return out


def _collapse_group(pairs: list[_Pair], ancestors: _Ancestors) -> list[_Pair]:
    """Collapse one ``(file_path, line_start)`` stack of ``(index, finding)``."""
    ids = _group_ids(pairs)
    redundant = _redundant_ids(ids, ancestors)
    # ``redundant == ids`` can only arise from a catalog cycle; refusing it
    # guarantees a line never loses its last categorised row.
    if not redundant or redundant == ids:
        return pairs
    kept, dropped = _split(pairs, redundant)
    return _promote(kept, dropped, ancestors)


def _group_key(finding: dict) -> tuple[str, int] | None:
    """Grouping key, or None for a finding that cannot be line-anchored."""
    path = finding.get("file_path")
    line = finding.get("line_start")
    if not path or not isinstance(line, int):
        return None
    return (str(path), line)


def _grouped(findings: list[dict]) -> "OrderedDict[Any, list[_Pair]]":
    """Bucket findings by line anchor, remembering their emission index."""
    groups: OrderedDict[Any, list[_Pair]] = OrderedDict()
    for idx, finding in enumerate(findings):
        groups.setdefault(_group_key(finding), []).append((idx, finding))
    return groups


def collapse_line_stacks(
    findings: list[dict],
    ancestors: _Ancestors = cwe_ancestors,
) -> tuple[list[dict], int]:
    """Drop generalisation rows that share a line with their specialisation.

    Args:
        findings: Skill findings, in emission order.
        ancestors: Resolver from a numeric CWE id to its transitive
            ancestors. Injectable so callers (and tests) can supply their own
            hierarchy instead of the packaged catalog.

    Returns:
        ``(kept, collapsed_count)``. Survivor order matches the input, and
        ``collapsed_count`` is the number of rows removed — report it so the
        collapse is never silent.
    """
    survivors: list[_Pair] = []
    for key, pairs in _grouped(findings).items():
        if key is None or len(pairs) < 2:
            survivors += pairs
        else:
            survivors += _collapse_group(pairs, ancestors)
    # Restore emission order: grouping is an implementation detail and must
    # not reshuffle findings the caller already streamed.
    survivors.sort(key=itemgetter(0))
    return list(map(itemgetter(1), survivors)), len(findings) - len(survivors)
