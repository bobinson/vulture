"""Feature 0104 WS-C (LLD §4.3, HT-12): the existence-probe rule's use check costs O(1)
amortised per node, never functions x uses.

Review finding #3. ``_Entries.uses_resolved(fn)`` (``Params.hinted_itself``, asked once per
hint-only BASE probe flow) reads every same-file use of ``fn``'s name and walks each one up its
ancestors (``_only_resolved`` -> ``_accounted`` -> ``_listing``), afresh for every function. M
CommonJS listings ``exports.f = f;`` before N declarations ``function f(filePath) { return
fs.existsSync(filePath); }`` make each of the N probe flows walk the M listings again: N x M
steps, so a crafted file of that shape times the AST worker out.

The cost is counted, never timed (a loaded host flakes a wall clock), and at the contract: a
``sys.setprofile`` hook (``_0104._profiled``) profiles the whole ``analysis()`` of a fresh
model, what the worker runs, so a fix that moves or renames ``hinted_itself`` hides nothing. It
counts the ``FileModel.parent`` frames (the ancestor walk), the frames of
``shared/ast/_params.py`` code (the use check, wherever that module runs it) and every Python
frame entered or C function called (all the interpreted work). The crafted file is analysed
once at each of two sizes, the second twice the first in both M and N; linear work at most
doubles (ratio <= ``LINEAR``), quadratic work quadruples. RED on HEAD: the three ratios are
about 3.8, 3.8 and 3.6.

Pinned, so the fix cannot move a decision: the probe still declines ``probe:param_hint`` for a
bare hinted function whose name is used only by its listing and a direct call; a reference use
still keeps the report; and the crafted shape itself decides as on HEAD (one listed ``f``
declines; two declarations of ``f`` each block the other, so both report).
"""

from __future__ import annotations

import functools
from operator import attrgetter

import pytest

from shared.ast import FileModel, _params
from tests.unit.ast._0104 import LINEAR, PROBE, _growth, _profiled, _Work, cases
from tests.unit.ast._analysis import REPORT, Spec, judge, model_of, subject, verdicts_at

pytestmark = pytest.mark.usefixtures("real_pool")

SINK = "fs.existsSync"
# The smaller size of the crafted file (M listings = N functions = size); ``_growth`` doubles it.
SMALL = 50
_PARENT = FileModel.parent.__code__
_PARAMS = _params.__file__

_HEAD = 'const fs = require("fs");\n\n'
_LISTING = "exports.f = f;\n"
_PROBE_FN = "function f(filePath) {\n  return fs.existsSync(filePath);\n}\n"


def _crafted(size: int) -> str:
    """The review's file: ``size`` listings ``exports.f = f;``, then ``size`` hinted probe
    functions all named ``f``."""
    return _HEAD + _LISTING * size + _PROBE_FN * size


def _parents(work: _Work) -> int:
    """``FileModel.parent`` frames: the ancestor walk."""
    return work.frames[_PARENT]


def _use_checks(work: _Work) -> int:
    """Frames of ``shared/ast/_params.py`` code: the use check, however that module spells it."""
    return sum(n for code, n in work.frames.items() if code.co_filename == _PARAMS)


@functools.cache
def _measured(size: int) -> _Work:
    """The work of the whole ``analysis()`` of a fresh model of ``_crafted(size)``, once per
    size; the use check's module must have run in it."""
    work = _profiled(model_of(_crafted(size), "js").analysis)
    assert _use_checks(work), "the analysis never ran shared/ast/_params.py"
    return work


def test_ancestor_walk_is_linear_in_the_file() -> None:
    """The ancestor walk ``_listing`` / ``_accounted`` take is O(1) amortised per use: twice
    the listings and functions, at most about twice the ``FileModel.parent`` calls."""
    growth = _growth(_measured, _parents, SMALL)
    assert growth <= LINEAR, f"parent calls grew x{growth:.2f} when the file doubled"


def test_use_check_work_is_linear_in_the_file() -> None:
    """However the walk is spelled: twice the file, at most about twice the frames of
    ``_params`` code, so no function re-reads every use of its name."""
    growth = _growth(_measured, _use_checks, SMALL)
    assert growth <= LINEAR, f"use-check work grew x{growth:.2f} when the file doubled"


def test_file_analysis_is_linear_in_the_file() -> None:
    """The worker's whole ``analysis()`` of the crafted file: twice the file, at most about
    twice the work, wherever the use check runs."""
    growth = _growth(_measured, attrgetter("steps"), SMALL)
    assert growth <= LINEAR, f"analysis work grew x{growth:.2f} when the file doubled"


# ── the decisions the fix keeps ──

_LISTED_AND_CALLED: Spec = ("js", """
    const fs = require("fs");

    function present(filePath) {
      return fs.existsSync(filePath);
    }

    function presentDefault() {
      return present("defaults.json");
    }

    exports.present = present;
    exports.presentDefault = presentDefault;
""")
_REFERENCED: Spec = ("js", """
    const fs = require("fs");

    function present(filePath) {
      return fs.existsSync(filePath);
    }

    const checks = [present];

    exports.present = present;
    exports.checks = checks;
""")

DECIDED: list[tuple[str, Spec, str]] = [
    ("a listing and a direct call", _LISTED_AND_CALLED, PROBE),
    ("a reference use", _REFERENCED, REPORT),
]


@pytest.mark.parametrize(("spec", "verdict"), cases(DECIDED))
def test_use_check_decides_as_before(spec: Spec, verdict: str) -> None:
    assert verdicts_at(subject(spec), "path", SINK) == verdict


CRAFTED: list[tuple[str, int, str]] = [
    ("one listed f", 1, PROBE),
    ("two declarations of f", 2, REPORT),
]


@pytest.mark.parametrize(("size", "verdict"), cases(CRAFTED))
def test_crafted_shape_decides_as_before(size: int, verdict: str) -> None:
    """Every probe flow of the crafted file at ``size`` gets ``verdict`` (``require``'s
    constant-only flow decides ``none`` and is left out)."""
    verdicts = judge(model_of(_crafted(size), "js"), "path").verdicts
    assert [found for _, found in verdicts if found != "none"] == [verdict] * size
