"""Feature 0104: coverage pins of WS-C (LLD §4.3, A54) and WS-D rev 4 (LLD §4.4, D-P (1)) code
paths no other unit test reaches. Each pins the behaviour as built; none was RED.

WS-C, ``_params._Entries._listing``'s EXPORT branch. A54 (b): a probe declines only when every
same-file use of the function's name is its declaration, an export listing or a resolved call.
``test_0104_precision_probes`` reaches the CommonJS ASSIGN arm (``module.exports = { f }``,
``exports.f = function``); an ES export listing, ``export { f }`` or ``export { f as g }``, ships
its ``f`` as a NAME directly under the EXPORT node, so the walk up from that use ends at the
EXPORT and the use is accounted. The bare probe of the entry's hinted parameter then declines
``probe:param_hint`` in both spellings (the alias ``g`` is another name, no use of ``f``), and
the same file with one reference use of ``f`` beside the listing (``const checks = [f]``)
reports: the listing, not an empty use check, is what declines.

WS-C, ``Params._bare_slot``'s rest and defaulted shapes. A54 (c): the parameter's slot (its
PARAM) must start at its name. A rest parameter's PARAM starts at ``...``, before the name, so
``...filePath`` is no bare slot: the flow keeps ``bare_path_arg`` False and reports, as the
destructured shape does (framework entries deliver request data so). A defaulted parameter's
PARAM starts at its name (``filePath = "/srv"``), so it is a bare slot: the default is a
constant, which ``hint_only`` never reads (externals only), and WS-B (default values) was
dropped (D-N (2)), so the probe declines ``probe:param_hint`` as the plain parameter's does.

WS-D rev 4, ``Calls.binds_name``'s memo. The bound names are read once per file, on the first
ask: two digest-keyed calls in one file get the same answer, and the file's analysis work grows
linearly in the number of such calls (counted by ``_0104._profiled``; a walk of the file per
call grows it about 3x when the calls double).
"""

from __future__ import annotations

from functools import partial
from operator import attrgetter

import pytest

from shared.ast import FileModel
from shared.ast._origins import Engine
from tests.unit.ast._0104 import LINEAR, PROBE, _growth, _profiled, _Work, cases
from tests.unit.ast._analysis import (
    REPORT,
    Spec,
    call_at,
    flows_at_call,
    judge,
    program,
    subject,
    verdicts_at,
)

pytestmark = pytest.mark.usefixtures("real_pool")

EXISTS = "fs.existsSync"

# ── WS-C: an ES export listing accounts for the function's name (A54 (b)) ──

_LISTED: tuple[str, str] = ("js", """
    const fs = require("node:fs");

    function present(filePath) {
      return fs.existsSync(filePath);
    }

    export { present };
""")
_LISTED_AS: tuple[str, str] = ("ts", """
    import fs from "node:fs";

    function present(filePath: string): boolean {
      return fs.existsSync(filePath);
    }

    export { present as presentFile };
""")
LISTINGS: list[tuple[str, tuple[str, str]]] = [
    ("export { f }", _LISTED),
    ("export { f as g }", _LISTED_AS),
]


def _engine(spec: Spec) -> tuple[FileModel, Engine]:
    """``spec``'s shared model and a fresh origin engine over it (the flow pass's own scope
    table, ``Calls`` and ``Params``)."""
    model = subject(spec)
    return model, Engine(model)


def _referenced(spec: tuple[str, str]) -> Spec:
    """``spec`` plus one reference use of ``present`` (an array element), listed apart."""
    lang, source = spec
    return lang, f"{source}\n    const checks = [present];\n    export {{ checks }};\n"


@pytest.mark.parametrize("spec", cases(LISTINGS))
def test_an_export_listing_use_ends_at_the_export(spec: tuple[str, str]) -> None:
    """The listing's use of ``present`` is accounted, so the probe declines; a reference use
    beside it is not, so the same probe reports."""
    verdicts = [verdicts_at(subject(s), "path", EXISTS) for s in (spec, _referenced(spec))]
    assert verdicts == [PROBE, REPORT]


@pytest.mark.parametrize("spec", cases(LISTINGS))
def test_an_export_listed_bare_probe_declines(spec: Spec) -> None:
    assert verdicts_at(subject(spec), "path", EXISTS) == PROBE


# ── WS-C: a rest parameter is no bare slot; a defaulted one is (A54 (c)) ──

_REST: Spec = ("js", """
    const fs = require("node:fs");

    export function present(...filePath) {
      return fs.existsSync(filePath);
    }
""")
_DEFAULTED: Spec = ("js", """
    const fs = require("node:fs");

    export function present(filePath = "/srv") {
      return fs.existsSync(filePath);
    }
""")
# id, spec, ``_bare_slot`` of the probe argument's Def, the verdict at the probe.
SLOTS: list[tuple[str, Spec, bool, str]] = [
    ("rest ...filePath: reported", _REST, False, REPORT),
    ("defaulted filePath = '/srv': declined", _DEFAULTED, True, PROBE),
]


@pytest.mark.parametrize(("spec", "bare", "verdict"), cases(SLOTS))
def test_a_hinted_slot_shape_decides_the_probe(spec: Spec, bare: bool, verdict: str) -> None:
    model, engine = _engine(spec)
    (flow,) = flows_at_call(model, "path", EXISTS)
    slots = [engine.params._bare_slot(d) for d in engine.scope.resolve(flow.arg)]
    assert (slots, flow.bare_path_arg) == ([bare], bare)
    assert verdicts_at(model, "path", EXISTS) == verdict


# ── WS-D rev 4: the file's bound names are read once (``Calls.binds_name``) ──

_OWN_HASH = """
    import os

    from flask import request

    ROOT = "/srv/shelf"
    hash = os.path.join
"""
_IMPORTED_HASH = """
    import os

    from flask import request
    from shelf_naming import hash

    ROOT = "/srv/shelf"
"""
# One handler of a file: ``{n}`` numbers it, ``{sink}`` is its ``open`` argument.
_HANDLER = """

    def shelf_{n}():
        with open({sink}) as fh:
            return fh.read()
"""
# id, the file's head, each handler's ``open`` argument (``{n}`` keys its request value),
# whether each ``open`` sink reports (the file's own ``hash`` is no digest).
DIGESTS: list[tuple[str, str, str, bool]] = [
    ("the file binds hash: both report", _OWN_HASH, 'hash(ROOT, request.args["k{n}"])', True),
    ("an imported hash: both digest", _IMPORTED_HASH,
     'os.path.join(ROOT, hash(request.args["k{n}"]))', False),
]
# The handlers of the smaller file the work is counted on; ``_growth`` doubles them.
HANDLERS = 100


def _handlers(head: str, sink: str, count: int) -> FileModel:
    """A fresh model (its analysis built by the caller, never shared) of ``head`` and
    ``count`` handlers."""
    body = "".join(_HANDLER.format(n=n, sink=sink.format(n=n)) for n in range(count))
    return program.__wrapped__("py", head + body)


def _sink_reports(head: str, sink: str) -> list[bool]:
    """Whether ``decide`` reports the ``open`` sink of each of two handlers, in document
    order."""
    model = _handlers(head, sink, 2)
    reported = judge(model, "path").reported
    return [model.line(call_at(model, "open", nth=n)) in reported for n in range(2)]


def _analysis_work(head: str, sink: str, count: int) -> _Work:
    return _profiled(_handlers(head, sink, count).analysis)


@pytest.mark.parametrize(("head", "sink", "reports"), cases(DIGESTS))
def test_bound_names_are_read_once_per_file(head: str, sink: str, reports: bool) -> None:
    """Both ``hash(...)`` calls get the same answer (both sinks decide alike), and the bound
    names are read once per file, not once per call: twice the handlers, at most about twice
    the analysis work."""
    assert _sink_reports(head, sink) == [reports, reports]
    growth = _growth(partial(_analysis_work, head, sink), attrgetter("steps"), HANDLERS)
    assert growth <= LINEAR, f"analysis work grew x{growth:.2f} when the handlers doubled"
