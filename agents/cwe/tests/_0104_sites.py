"""Feature 0104 -- the E2E site tree as the 0104 tests read it. Not a test module.

``fixtures/0104_hint_tier`` holds one subdirectory per workstream (``WORKSTREAMS``) plus
``regress/`` (``SUBDIRS`` is both); every site is a 0101 marker (``tests/e2e/_0101_markers.py``)
that names its check id, and ``CATEGORY`` is the row category of each check id a 0104 site may
name (``CHECK`` the other way round). A marker line may add ``NAME=value`` attributes after the
check id (``HINT=param_hint``, ``SHOWS=request``); ``attrs`` reads them for a site, paired with
the site by the 0101 parser itself. ``scan`` runs the two AST skills on each subdirectory of a
neutral copy, on its own.
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Any

from tests import _ast_v1
from tests._ast_heads import relative
from tests.e2e._0101_markers import _MARKER, Site, parse_markers, parse_tree

FIXTURES = Path(__file__).resolve().parent / "e2e" / "fixtures" / "0104_hint_tier"
WORKSTREAMS = ("a1", "c", "d", "h")
SUBDIRS = (*WORKSTREAMS, "regress")
SITES: list[Site] = parse_tree(FIXTURES)
CATEGORY = {
    "cwe.input_validation.path_traversal": "CWE-22",
    "cwe.input_validation.external_path_control": "CWE-73",
    "cwe.input_validation.absolute_path_traversal": "CWE-36",
    "cwe.injection.command": "CWE-78",
    "cwe.injection.ssrf": "CWE-918",
}
CHECK = {category: check_id for check_id, category in CATEGORY.items()}
Rows = dict[str, list[dict[str, Any]]]
_ATTR = re.compile(r"\b([A-Z]+)=(\w+)")


def sub_of(site: Site) -> str:
    """The subdirectory (workstream) a site belongs to."""
    return site.rel.split("/", 1)[0]


def site_key(site: Site) -> str:
    """``<path under the tree>:<line>:<category>`` of a site, as ``rel_key`` names a row."""
    return f"{site.rel}:{site.line}:{CATEGORY.get(site.check or '', site.check)}"


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


def scan(root: Path, subs: tuple[str, ...] = SUBDIRS) -> Rows:
    """Each of ``subs`` under the neutral copy ``root``, scanned on its own: its rows."""
    return {sub: _ast_v1.migrated_rows(root / sub) for sub in subs}
