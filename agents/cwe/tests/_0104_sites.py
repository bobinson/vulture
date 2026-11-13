"""Feature 0104 -- the E2E site tree as the 0104 tests read it. Not a test module.

``fixtures/0104_hint_tier`` holds one subdirectory per workstream (``WORKSTREAMS``) plus
``regress/`` (``SUBDIRS`` is both); every site is a 0101 marker (``tests/e2e/_0101_markers.py``)
that names its check id, and ``CATEGORY`` is the row category of each check id a 0104 site may
name (``CHECK`` the other way round). A marker line may add ``NAME=value`` attributes after the
check id (``HINT=param_hint``, ``SHOWS=request``); ``attrs`` reads them for a site, paired with
the site by the 0101 parser itself. ``scan`` runs the two AST skills on each subdirectory of a
neutral copy, on its own.

WS-A2's subdirectory ``a2/`` (``A2``) is the exception: A2 groups rows where the agent
finalizes them, not in a skill, so its sites (``A2_SITES``, kept out of ``SITES``) assert on
``finalized``'s rows, and ``scan`` runs the CWE-23 skill on it too, whose row at a member's line
refuses a group (R1, R2). Its AST ``finding`` markers name ``SINKS=`` (``A2_SINKED``,
``sinks_of``); a group row lists them as ``validation.flow.sinks`` (``row_sinks``).
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills.path_equivalence_check import check_path_equivalence
from tests import _ast_v1
from tests._ast_heads import relative
from tests.e2e._0101_markers import _MARKER, Site, neutral_copy, parse_markers, parse_tree

FIXTURES = Path(__file__).resolve().parent / "e2e" / "fixtures" / "0104_hint_tier"
WORKSTREAMS = ("a1", "c", "d", "h")
SUBDIRS = (*WORKSTREAMS, "regress")
A2 = "a2"
CATEGORY = {
    "cwe.input_validation.path_traversal": "CWE-22",
    "cwe.input_validation.external_path_control": "CWE-73",
    "cwe.input_validation.absolute_path_traversal": "CWE-36",
    "cwe.injection.command": "CWE-78",
    "cwe.injection.ssrf": "CWE-918",
    "cwe.path_eq.cwe_23": "CWE-23",
}
CHECK = {category: check_id for check_id, category in CATEGORY.items()}
Rows = dict[str, list[dict[str, Any]]]
_ATTR = re.compile(r"\b([A-Z]+)=(\w+)")


def sub_of(site: Site) -> str:
    """The subdirectory (workstream) a site belongs to."""
    return site.rel.split("/", 1)[0]


_TREE: list[Site] = parse_tree(FIXTURES)
SITES: list[Site] = [s for s in _TREE if sub_of(s) != A2]
A2_SITES: list[Site] = [s for s in _TREE if sub_of(s) == A2]


def site_key(site: Site) -> str:
    """``<path under the tree>:<line>:<category>`` of a site, as ``rel_key`` names a row."""
    return f"{site.rel}:{site.line}:{CATEGORY.get(site.check or '', site.check)}"


def category_of(site: Site) -> str:
    """The row category of the check id the site names."""
    return CATEGORY[site.check or ""]


def rel_key(row: dict[str, Any], root: Path) -> str:
    """``<path under root>:<line>:<category>`` of a row."""
    return f"{relative(root, row['file_path'])}:{int(row.get('line_start') or 0)}:{row['category']}"


@cache
def _file_attrs(rel: str) -> dict[Site, dict[str, str]]:
    """Each site of one fixture file -> the attributes its marker line names. The 0101 parser
    yields one site per marker line, in line order, so the two lists pair up."""
    lines = (FIXTURES / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    marked = [line[found.end():] for line in lines if (found := _MARKER.search(line))]
    sites = parse_markers(FIXTURES / rel, FIXTURES)
    return {site: dict(_ATTR.findall(tail)) for site, tail in zip(sites, marked, strict=True)}


def attrs(site: Site) -> dict[str, str]:
    """The ``NAME=value`` attributes of the marker asserting on ``site``."""
    return _file_attrs(site.rel)[site]


A2_SINKED: list[Site] = [s for s in A2_SITES if "SINKS" in attrs(s)]


def sinks_of(site: Site) -> list[int] | None:
    """The sink lines an ``a2/`` marker's ``SINKS=`` names (``_``-joined), None for ``none``."""
    named = attrs(site)["SINKS"]
    return None if named == "none" else [int(line) for line in named.split("_")]


def row_sinks(row: dict[str, Any]) -> list[int] | None:
    """A2: the member lines a group row lists (``validation.flow.sinks``), else None."""
    return (row["validation"].get("flow") or {}).get("sinks")


def scan(root: Path, subs: tuple[str, ...] = SUBDIRS) -> Rows:
    """Each of ``subs`` under the neutral copy ``root``, scanned on its own: its rows."""
    return {sub: _rows(root / sub, sub) for sub in subs}


def _rows(path: Path, sub: str) -> list[dict[str, Any]]:
    """The two AST skills' rows on ``path``; on ``a2/``, the CWE-23 skill's too."""
    rows = _ast_v1.migrated_rows(path)
    return [*rows, *check_path_equivalence(str(path))["findings"]] if sub == A2 else rows


def finalized(
    factory: pytest.TempPathFactory, subs: tuple[str, ...]
) -> tuple[Path, list[dict[str, Any]]]:
    """A neutral copy of the tree and the rows ``finalize_skill_findings`` makes of each of
    ``subs``' (what a full audit does to skill rows with the LLM off), under the documented
    defaults and a private, empty L5 cache (the stage stores evidence quotes there)."""
    from shared import audit_runner, quote_store
    from shared.testing.isolation import isolate

    root = neutral_copy(FIXTURES, factory.mktemp("final0104"))
    with pytest.MonkeyPatch.context() as patch:
        isolate(patch, factory.mktemp("final0104_home"))
        # ``isolate`` opens a new cache, but leaves the quote table marked as made in the last.
        patch.setattr(quote_store, "_table_ready", False)
        rows = scan(root, subs)
        return root, [row for sub in subs for row in audit_runner.finalize_skill_findings(
            rows[sub], str(root / sub), "run-0104")]
