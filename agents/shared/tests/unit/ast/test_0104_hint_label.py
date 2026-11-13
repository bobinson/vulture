"""Feature 0104 WS-A1 (LLD §4.1, HT-7, HT-9; A48): a hint-only row says so, nothing moves.

Rule. A reported row whose flow is hint-only -- it holds an external origin, and every external
origin it holds is R-T's parameter-name hint (``external(param_hint)``, with or without a
``via``) -- carries ``validation.flow.heuristic = "param_hint"`` (``_records.PARAM_HINT_ROLE``;
``flow.hint_only(origins)`` is the one predicate). A D25 row keeps ``command_param``: its flow
has no external origin, so the two tokens never meet. A row with the hint and any other
external origin (request, ``any`` ...) carries no key, and so does a row on whose sink line a
non-hint flow reports: ``consume._by_line`` prefers that flow, but only among flows whose sink
is on that same line (A48, the skeptic's R1) -- a nested sink on a later line of a multi-line
call keeps its own flow and its own row. No verdict and no row moves (HT-8).

RED until A1 lands: the ``param_hint`` rows, ``hint_only``, ``PARAM_HINT_ROLE`` and the rows
that must show the request flow sharing their sink line. Green today, and kept: every row's
existence, the D25 token, the no-key rows, and each sink line mapped to its own flow.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.unit.ast._0104 import HINT, ROOT, cases, flow_blob, layer_name, required, spans_of
from tests.unit.ast._analysis import (
    Spec,
    constant,
    external,
    finding_of,
    flow_with,
    roles_mod,
    stub_rule,
    unknown,
)

pytestmark = pytest.mark.usefixtures("real_pool")

_HINT_PATH: Spec = ("ts", """
    import fs from "node:fs";

    export function loadNote(filePath: string): Buffer {
      return fs.readFileSync(filePath);
    }
""")
_HINT_COMMAND: Spec = ("py", """
    import os


    def run_tool(file_path):
        os.system("wc " + file_path)
""")
_HINT_AND_REQUEST: Spec = ("js", """
    const fs = require("fs");

    function loadNote(filePath, req) {
      return fs.readFileSync(filePath + req.query.ext);
    }

    module.exports = { loadNote };
""")
_TWO_ARGS: Spec = ("ts", """
    import fs from "node:fs";

    export function shelve(destPath: string, req: any): void {
      fs.copyFileSync(req.query.src, destPath);
    }
""")
_NESTED: Spec = ("ts", """
    import fs from "node:fs";

    export function reflect(sourcePath: string, filePath: string, req: any): void {
      fs.appendFileSync(req.query.dest, fs.readFileSync(filePath));
    }
""")
_SHARED_HELPER: Spec = ("js", """
    const fs = require("fs");
    const app = require("express")();

    function fetchText(p) {
      return fs.readFileSync(p, "utf8");
    }

    app.get("/doc", (req, res) => res.send(fetchText(req.query.name)));

    function peek(fileName) {
      return fetchText(fileName);
    }

    module.exports = { peek };
""")
_COMMAND_PARAM: Spec = ("py", """
    import os


    def run_command(cmd):
        os.system(cmd)
""")
_REQUEST_ONLY: Spec = ("js", """
    const fs = require("fs");

    function handler(req, res) {
      res.send(fs.readFileSync(req.query.f));
    }
""")
_MULTILINE_TS: Spec = ("ts", """
    import fs from "node:fs";

    export function reflect(filePath: string, req: any): void {
      fs.appendFileSync(
        req.query.dest,
        fs.readFileSync(filePath)
      );
    }
""")
_MULTILINE_PY: Spec = ("py", """
    import shutil

    from flask import request


    def twin(file_path):
        shutil.copyfile(
            request.args["src"],
            open(file_path).read(),
        )
""")
# 17 distinct sanitiser compositions of one hinted parameter: past MAX_ORIGINS the origins
# collapse to ``external(any)`` (the overflow), which is no hint-only flow.
_TERMS = (
    "filePath", "basename(filePath)", "allow(filePath)", "validate(filePath)",
    "shellEscape(filePath)", "privateOnly(filePath)", "allow(basename(filePath))",
    "validate(basename(filePath))", "shellEscape(basename(filePath))",
    "privateOnly(basename(filePath))", "validate(allow(filePath))",
    "shellEscape(allow(filePath))", "privateOnly(allow(filePath))",
    "shellEscape(validate(filePath))", "privateOnly(validate(filePath))",
    "privateOnly(shellEscape(filePath))", "validate(allow(basename(filePath)))",
)
_ANY: Spec = ("ts", 'import fs from "node:fs";\n\nexport function gather(filePath) {\n'
              f"  return fs.readFileSync({' + '.join(_TERMS)});\n}}\n")

# (case, program, family, sink line, the row's ``heuristic``: a token, or None for no key)
LABELS: list[tuple[str, Spec, str, int, str | None]] = [
    ("path hint-only", _HINT_PATH, "path", 4, HINT),
    ("command hint-only", _HINT_COMMAND, "command", 5, HINT),
    ("multi-line, the nested hint-only sink", _MULTILINE_TS, "path", 6, HINT),
    ("python multi-line, the nested hint-only sink", _MULTILINE_PY, "path", 9, HINT),
    ("hint + request in one flow", _HINT_AND_REQUEST, "path", 4, None),
    ("two arguments, a request flow and a hint flow", _TWO_ARGS, "path", 4, None),
    ("nested sinks on one line", _NESTED, "path", 4, None),
    ("a helper a request and a hinted caller share", _SHARED_HELPER, "path", 5, None),
    ("multi-line, the outer request sink", _MULTILINE_TS, "path", 4, None),
    ("D25 unknown(param) at a shell sink", _COMMAND_PARAM, "command", 5, "command_param"),
    ("external(any), the overflow collapse", _ANY, "path", 4, None),
    ("request only", _REQUEST_ONLY, "path", 4, None),
]


@pytest.mark.parametrize(("spec", "family", "line", "token"), cases(LABELS))
def test_row_heuristic(spec: Spec, family: str, line: int, token: str | None) -> None:
    assert flow_blob(spec, family, line).get("heuristic") == token


# (case, program, sink line): a request flow reports at the row's sink line, so the row shows it
SHOWN: list[tuple[str, Spec, int]] = [
    ("two arguments", _TWO_ARGS, 4),
    ("nested sinks on one line", _NESTED, 4),
    ("a helper a request and a hinted caller share", _SHARED_HELPER, 5),
    ("multi-line, the outer sink", _MULTILINE_TS, 4),
    ("python multi-line, the outer sink", _MULTILINE_PY, 7),
]


@pytest.mark.parametrize(("spec", "line"), cases(SHOWN))
def test_row_shows_the_request_flow_of_its_sink_line(spec: Spec, line: int) -> None:
    assert "external:request" in flow_blob(spec, "path", line)["origins"]


@pytest.mark.parametrize("spec", [_MULTILINE_TS, _MULTILINE_PY], ids=["ts", "py"])
def test_tie_break_never_crosses_sink_lines(spec: Spec) -> None:
    """A48: each reported sink line maps to a flow that sinks there, so each keeps its row."""
    spans = spans_of(spec, "path")
    sink_lines = {flow.sink_line for flow in spans.values()}
    assert len(sink_lines) == 2, sink_lines
    assert all(spans[line].sink_line == line for line in sink_lines)


def test_label_is_read_from_the_flow_alone() -> None:
    """A model-free flow of only the hint becomes a labelled row (no wire change: origins)."""
    row = finding_of(flow_with("path", external(HINT)), stub_rule("path"), ROOT / "f", ["x"])
    assert row["validation"]["flow"].get("heuristic") == HINT


# ── hint_only (HT-7) ──

HINT_ONLY: list[tuple[str, Any, bool]] = [
    ("empty", (), False),
    ("the hint", (external(HINT),), True),
    ("the hint with a via", (external(HINT, "numeric"),), True),
    ("the hint and an unknown", (external(HINT), unknown("unresolved")), True),
    ("the hint and a constant", (external(HINT), constant()), True),
    ("hint + request", (external(HINT), external("request")), False),
    ("hint + any", (external(HINT), external("any")), False),
    ("request", (external("request"),), False),
    ("unknown only", (unknown("param"),), False),
]


@pytest.mark.parametrize(("origins", "want"), cases(HINT_ONLY))
def test_hint_only(origins: Any, want: bool) -> None:
    assert required("flow", "hint_only")(frozenset(origins)) is want


def test_param_hint_role_is_the_one_spelling() -> None:
    role = layer_name("_records", "PARAM_HINT_ROLE")
    families = roles_mod().SOURCE_ROLES_BY_FAMILY
    held = [role in roles for roles in (families["path"], families["command"], families["request"])]
    assert (role, role in layer_name("_records", "EXTERNAL_ROLES"), held) == (
        HINT, True, [True, True, False])
