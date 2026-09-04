"""A widened shared extension allowlist must not reduce endpoint discovery.

`scan_code_files` truncates at `_MAX_SCAN_FILES` in WALK ORDER, not by
usefulness, and this analyzer inherits its extension set from the shared
`CODE_EXTENSIONS`. When feature 0087 added C++ header spellings to that
constant for a CWE-778 arm, a tree with 600 `include/*.hpp` files consumed the
whole 500-file budget before the walk reached `src/`, and route discovery went
from 31/31 to 10/31 — silently, because this agent emits no partial-coverage
notice.

This test fails if a future widening reintroduces that coupling.
"""

from __future__ import annotations

from pathlib import Path

import discover_agent.source_analyzer as sa


def _routes(result) -> int:
    routes = getattr(result, "routes", None)
    if routes is None and isinstance(result, dict):
        routes = result.get("routes")
    return len(routes or [])


def test_headers_do_not_crowd_out_route_bearing_source(tmp_path: Path) -> None:
    include = tmp_path / "include"
    include.mkdir()
    # More header files than the whole scan budget, and `include` sorts before
    # `src`, which is what makes this a total loss rather than a partial one.
    for i in range(sa._MAX_SCAN_FILES + 100):
        (include / f"h{i:04d}.hpp").write_text("#pragma once\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/api/users", methods=["GET"])\n'
        "def u():\n    return ''\n"
        '@app.route("/api/admin/delete", methods=["POST"])\n'
        "def d():\n    return ''\n"
    )

    result = sa.analyze_source(str(tmp_path))
    assert _routes(result) == 2, (
        f"expected both routes, found {_routes(result)}; a non-API extension is "
        f"consuming the {sa._MAX_SCAN_FILES}-file budget ahead of real source"
    )


def test_non_api_extensions_are_excluded_from_the_scan_set() -> None:
    """Pin the exclusion itself, so the mechanism is visible, not incidental."""
    assert sa._NON_API_EXTENSIONS, "the exclusion set is empty; the guard is off"
    overlap = sa._NON_API_EXTENSIONS & sa._SOURCE_EXTENSIONS
    assert not overlap, f"declared non-API but still scanned: {sorted(overlap)}"
    # A header cannot declare a route; if one of these ever legitimately can,
    # this assertion is the place to argue it.
    for ext in (".h", ".hpp", ".hh", ".hxx"):
        assert ext not in sa._SOURCE_EXTENSIONS, f"{ext} is back in the scan set"
