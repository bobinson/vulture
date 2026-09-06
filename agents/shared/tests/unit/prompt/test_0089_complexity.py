"""The cross-phase complexity Definition of Done, as a gate. Feature 0089.

The plan states it for the whole feature: *"`make complexity` shows no new
outlier under `shared/prompt/`; every renderer rule and lint check is one
function <= 5."* Until now that was prose. Prose does not fail a build, and the
two functions this file was written to catch — `render` at 15 and
`parse_fragment` at 13 — were written by the same work that stated the rule.

Why a test and not the Makefile. `make complexity` runs `radon cc . -a -nc`,
and `-nc` is *minimum rank C*, i.e. **11 and above**. A function at 6, 7 or 8 is
rank B and prints nothing, so the Makefile can be green while five functions sit
over the stated bar — which is exactly the state this file found. CI is looser
still (`|| true`). The bar the plan names is 5, so the gate that enforces it has
to count, not grep a rank.

The threshold is deliberately not configurable and there is no allow list. An
extraction that lowers a count is always available and always cheap here: every
function under `shared/prompt/` is pure, and the 120 goldens plus the parity
suites pin the bytes, so the refactor that satisfies this gate is verifiable in
a way most refactors are not. If a future function genuinely cannot be split,
the honest move is to change this line in review, not to annotate around it.
"""

from __future__ import annotations

import importlib
import pathlib

from radon.complexity import cc_visit

import shared.prompt

# The plan's number. Not an env var, not a fixture parameter (rule: 0089 adds no
# flags), and not "whatever the tree happens to be at" — a ratchet initialised
# from the current worst case would have accepted 15.
MAX_COMPLEXITY = 5

_PKG = pathlib.Path(shared.prompt.__file__).parent


def _blocks() -> list[tuple[int, str, str, int]]:
    """(complexity, relative path, block name, line) for every block in the package.

    Walks the installed package directory rather than a path relative to this
    test file, so it keeps measuring the code that actually gets imported.
    """
    out: list[tuple[int, str, str, int]] = []
    for path in sorted(_PKG.rglob("*.py")):
        for block in cc_visit(path.read_text(encoding="utf-8")):
            rel = path.relative_to(_PKG.parent.parent).as_posix()
            out.append((block.complexity, rel, block.name, block.lineno))
    return out


def test_package_is_not_empty() -> None:
    """Guard the gate itself: a walk that finds nothing would pass vacuously."""
    blocks = _blocks()
    assert len(blocks) > 100, f"expected the whole prompt package, measured {len(blocks)}"
    assert any(name == "render" for _, _, name, _ in blocks)
    assert any(name == "parse_fragment" for _, _, name, _ in blocks)


def test_no_function_under_prompt_exceeds_five_paths() -> None:
    """Every block under `shared/prompt/` is one function of <= 5 paths."""
    over = sorted((b for b in _blocks() if b[0] > MAX_COMPLEXITY), reverse=True)
    assert not over, "cyclomatic complexity over %d:\n%s" % (
        MAX_COMPLEXITY,
        "\n".join(f"  {c:3d}  {p}:{line}  {name}" for c, p, name, line in over),
    )


def test_render_is_a_pipeline() -> None:
    """`render` composes the rules; it does not contain them.

    Named separately from the sweep above because it is the specific shape the
    plan asks for ("a short pipeline that composes them"), and because a sweep
    failure lists six names while this one says which of them is the point.
    """
    # `shared.prompt.render` the ATTRIBUTE is the function — the package's
    # `__init__` re-exports it over the submodule of the same name — so the
    # module has to be fetched by path, not by attribute access.
    render_mod = importlib.import_module("shared.prompt.render")

    by_name = {name: c for c, p, name, _ in _blocks() if p.endswith("prompt/render.py")}
    assert by_name["render"] <= MAX_COMPLEXITY, by_name
    assert callable(render_mod.render)
    # The rules `render` composes are still separately addressable. If a future
    # edit re-inlines them, `render`'s own count goes back up and the assertion
    # above fires — this one says which shape the count is defending.
    for rule in ("_adapt", "_rule_system_role", "_rule_mirror",
                 "_rule_language", "_rule_json_contract"):
        assert by_name[rule] <= MAX_COMPLEXITY, (rule, by_name)
