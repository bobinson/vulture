"""Feature 0102, A47 (LLD §3 D22, D23; §8.4 R-T; §8.5; §8.8 (h), (i); §9.1): stage D round 2.

Measured on real public code after stage C, the AST tier's CWE-22/78 rows still held four
false-positive shapes. A47 (with the user's decision D-K) narrows each by a concept or
structural rule — CWE rules are framework-agnostic, so no helper, package, library or
framework name is ever an entry:

D23-d  R-T's ``PARAM_HINTS`` parameter (``filename``, ``file_path`` ...) is
       ``external(param_hint)`` only when its scope is an ENTRY function of the file: in
       JavaScript/TypeScript an EXPORTED function (an ``export`` statement holding a top-level
       function, a name an ``export`` lists, a CommonJS ``exports.x`` / ``module.exports[.x]``
       value — a function, a class's methods, a name's bound function or class, one level
       into an object); in every language a PUBLIC top-level named function (a method of a
       top-level class too) that no same-file call site resolves to — public is Python's no
       leading ``_``, Go's upper-case initial, any name elsewhere. No server-context
       condition. Elsewhere the parameter is ``unknown(param)`` (R-B's receiver for an
       iteration callback);
D22-c  ``external(argv)`` comes only from C4 (C and C++ ``main``'s argv parameter). Every
       other argv source the flow pass reads — a ``CONDITIONAL_SOURCE_ROOTS`` chain
       (``process.argv``, ``sys.argv``, ``Deno.args``, ``Bun.argv``), a chain root or bare name
       whose words hold ``argv``, an imported symbol ``argv`` (R-H) — is ``unknown(argv)``;
       ``argv`` joins ``_records.UNKNOWN_REASONS`` (D3') and stays in ``EXTERNAL_ROLES``. Such a
       flow is unknown-only (D9) unless D25 names it: the command hook reads ``unknown(argv)``
       as it reads ``unknown(param)`` (a shell-interpreting sink, a built argument, a builtin's
       program), its row names ``command_param``, and ``param_bound`` keeps its meaning
       (``unknown(param)`` only);
(h)    an early exit dominates the rest of its function: §8.5 clause (a)'s window is read in
       ``block_of(sink)`` and in every BLOCK enclosing it up to the body of the FUNCTION
       holding it (the MODULE when none), nearest block first, ``GUARD_WINDOW`` IF / TRY
       siblings per block; the walk is cut at the function boundary (R-O joins every Def of a
       closure read), and A44 (1) (d) (i)'s check statements share it (A47 (6)(g)). Guard
       roles and A29's order do not
       change. A47 corrects class 8's diagnosis: ``guard_roles`` already unions every
       disjunct's roles, so the cause was the window, not a De Morgan reading of ``||``;
(i)    a generic verb is a path sink only with file-system evidence: a ``path`` key that,
       after (e)'s sync-twin reading, is in ``GENERIC_PATH_VERBS`` needs a
       ``FILE_SYSTEM_WORDS`` word in the callee chain (W3), the receiver chain or the WHOLE
       module path of the import binding of the bare callee or the receiver chain's base, or
       is a bare call to a name no Def binds (a language global). A profile builtin decides
       first (W5): Go's predeclared ``append`` / ``copy`` share C's empty-family entry, now
       ``profiles.NO_FAMILY`` (R5). Every other path key needs none. The module reader is the
       one A44 (1) (c)'s process evidence reads. Known gap (SKILLS.md): a real file API whose
       receiver and import carry no file-system word (an image object's ``open``, an
       archive's ``write``) is no longer a path sink.

Each case is a synthetic program (identifiers renamed) or an ``ast_v1`` row — one A47
allocates for the shape (``cwe_22_71`` to ``cwe_22_80``, ``cwe_22_go_4`` and ``cwe_78_26``,
with their clean twins), or an existing row whose recall a rule keeps (the pins ``cwe_22_37``
and ``cwe_78_14``, the C4 rows, the positives whose key is a generic verb); the held-out token
rule, cwe ``test_0102_held_out.py``, reads those rows. All are read through ``_analysis`` (real
worker models, the analysis built in the test process).
``judge`` and A44's readers decide under the stub rule — no ``server_ctx`` gate and no D25
hook — except D22-c's command cases, which decide under D25's hook, the rule cwe ships for
``command``.

RED until A47 lands: the negative tables of D23-d, D22-c, (h) and (i), and what A47 newly
reads or adds (argv under D25, an enclosing block's exits, whole module paths, the vocabulary
and tables). The positive tables pass today, pinning the recall each narrowing must keep.
"""

from __future__ import annotations

import dataclasses
import importlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from shared.ast.limits import GUARD_WINDOW
from shared.ast.profile import PROFILES
from tests.unit.ast._analysis import (
    ALLOWLIST,
    HOST_ALLOW,
    NO_GUARD,
    PATH_CONTAIN,
    READ,
    REPORT,
    SINK,
    SINK_P,
    VALIDATE,
    Spec,
    consume_mod,
    decided,
    external,
    externals,
    finding_of,
    flow_mod,
    flow_with,
    flows_at_call,
    guard_roles_of,
    guard_verdict,
    if_test,
    js_handler,
    model_of,
    newline_row,
    numbered,
    program,
    roles_mod,
    stub_rule,
    subject,
    unknown,
)
from tests.unit.ast._prefetch import answer_mod

# test 21's forgery and its D3' reader; D25's command rule and its verdict names; the
# same-block window's rows, its IF filler and the guard records; A44's readers of "origins
# at a sink", "reported" and "no sink", shared by every precision module, and its sync rows;
# the role reader's IF, per language code
from tests.unit.ast.test_0102_answer_wire import _by_validator, _origin, _Rich
from tests.unit.ast.test_0102_command_param import CMD_PATH, NONE, TOKEN, UNKNOWN_ONLY, _rule
from tests.unit.ast.test_0102_guards import _IF_FILLER, _WINDOW, _guard_records
from tests.unit.ast.test_0102_precision_a44 import (
    _INSIDE,
    _SYNC_SINKS,
    _no_sink,
    _origins_at,
    _reported,
)
from tests.unit.ast.test_0102_roles import _GUARD

if TYPE_CHECKING:
    from shared.ast.flow import Origin

pytestmark = pytest.mark.usefixtures("real_pool")

# A case is (``Spec``, the sink CALL's head as ``call_head`` reads it, ...).


def _unknown_at(
    spec: Spec, family: str, head: str, reason: str
) -> tuple[frozenset[Origin], bool]:
    """The external origins at the ``family`` sink ``head`` and whether ``unknown(reason)`` is
    among its origins: ``(frozenset(), True)`` where a narrowing leaves the value unknown."""
    origins = _origins_at(spec, family, head)
    return externals(origins), unknown(reason) in origins


# ══ D23-d: the parameter hint of an ENTRY function ════════════════════════════

HINT = "param_hint"

# ── the hint kept: an entry function's parameter ──

_EXPORT_DEFAULT = """
    export default function (fileName) {
      fs.readFile(fileName, () => {});
    }
"""
_EXPORT_CONST_ARROW = """
    import fs from "node:fs";

    export const readEntry = (fileName: string): Buffer => fs.readFileSync(fileName);

    readEntry("defaults.json");
"""
_EXPORT_LIST = """
    function readEntry(fileName) {
      fs.readFile(fileName, () => {});
    }

    readEntry("defaults.json");
    export { readEntry };
"""
# A top-level function whose hinted parameter reaches the sink, with no export and no call.
_JS_READ_ENTRY = """
    const fs = require("fs");

    function readEntry(fileName) {
      fs.readFile(fileName, () => {});
    }
"""


def _read_entry_then(*lines: str) -> str:
    """``_JS_READ_ENTRY``, then a blank line and ``lines``, one per line."""
    return _JS_READ_ENTRY + "\n" + "".join(f"    {line}\n" for line in lines)


# ``readEntry`` called in its own file: only an export reading of the line after it can keep
# the hint
_CALLED = 'readEntry("defaults.json");'
_MODULE_EXPORTS_OBJECT = _read_entry_then(_CALLED, "module.exports = { readEntry };")
_EXPORTS_MEMBER = """
    const fs = require("fs");

    exports.readEntry = function (fileName) {
      fs.readFile(fileName, () => {});
    };
"""
_MODULE_EXPORTS_MEMBER = _EXPORTS_MEMBER.replace("exports.", "module.exports.")
_MODULE_EXPORTS_CLASS = """
    const fs = require("fs");

    const EntryStore = class {
      read(fileName) {
        fs.readFile(fileName, () => {});
      }

      readDefaults() {
        this.read("defaults.json");
      }
    };

    module.exports = EntryStore;
"""
# a class DECLARATION creates no scope Def: the export reads the file's top-level class of the name
_CLASS_DECLARATION = _MODULE_EXPORTS_CLASS.replace(
    "const EntryStore = class {", "class EntryStore {"
).replace("    };\n\n    module.exports", "    }\n\n    module.exports")
_CLASS_DECLARATION_LISTED = _CLASS_DECLARATION.replace(
    "module.exports = EntryStore;", "export { EntryStore };"
)
_EXPORT_CLASS = """
    import fs from "node:fs";

    export class EntryStore {
      read(fileName: string): Buffer {
        return fs.readFileSync(fileName);
      }

      readDefaults(): Buffer {
        return this.read("defaults.json");
      }
    }
"""
# A47 (6)(b): a Def that binds no function or class does not hide the declared class
_CLASS_REASSIGNED = _CLASS_DECLARATION.replace(
    "    module.exports", "    EntryStore = register(EntryStore);\n    module.exports"
)
# A47 (6)(c): a wrapped callback is the exported value's function, reached through the wrapper
_WRAPPED_EXPORT = """
    import fs from "node:fs";

    export const readEntry = withCache((fileName: string): Buffer => fs.readFileSync(fileName));
"""
# A47 (6)(e): an out-of-line method is named by its declarator's last identifier
_CPP_OUT_OF_LINE = """
    #include <cstdio>

    FILE *Store::readEntry(const char *fileName) {
        return fopen(fileName, "r");
    }
"""
_PY_TOP_LEVEL_METHOD = """
    class EntryStore:
        def read(self, file_path):
            return open(file_path).read()
"""
_GO_UPPER = """
    package store

    import "os"

    func ReadEntry(fileName string) ([]byte, error) {
    	return os.ReadFile(fileName)
    }
"""
# case -> (subject, the sink CALL's head)
_KEPT: dict[str, tuple[Spec, str]] = {
    # an export statement holding a function its own file also calls
    "export_function_called_in_file": ("cwe_22_78", "fs.readFileSync"),
    "export_default_anonymous": (("js", _EXPORT_DEFAULT), "fs.readFile"),
    "export_const_arrow": (("ts", _EXPORT_CONST_ARROW), "fs.readFileSync"),
    "export_list": (("js", _EXPORT_LIST), "fs.readFile"),
    "module_exports_object_member": (("js", _MODULE_EXPORTS_OBJECT), "fs.readFile"),
    "exports_member": (("js", _EXPORTS_MEMBER), "fs.readFile"),
    "module_exports_member": (("js", _MODULE_EXPORTS_MEMBER), "fs.readFile"),
    # a CommonJS or default export of a NAME bound to the function
    "module_exports_name": (("js", _read_entry_then(_CALLED, "module.exports = readEntry;")),
                            "fs.readFile"),
    "exports_member_name": (("js", _read_entry_then(_CALLED, "exports.readEntry = readEntry;")),
                            "fs.readFile"),
    "export_default_name": (("js", _read_entry_then(_CALLED, "export default readEntry;")),
                            "fs.readFile"),
    # a name bound to a class expression: its methods, though `this.read(...)` calls one
    "module_exports_class_name": (("js", _MODULE_EXPORTS_CLASS), "fs.readFile"),
    # a name bound to a class declaration (A47 (5)(a))
    "module_exports_class_declaration": (("js", _CLASS_DECLARATION), "fs.readFile"),
    "export_list_class_declaration": (("js", _CLASS_DECLARATION_LISTED), "fs.readFile"),
    # ... in TypeScript too, whose grammar names a class by a type name (A47 (6)(a))
    "ts_module_exports_class_declaration": (("ts", _CLASS_DECLARATION), "fs.readFile"),
    "ts_export_list_class_declaration": (("ts", _CLASS_DECLARATION_LISTED), "fs.readFile"),
    "reassigned_class_declaration": (("js", _CLASS_REASSIGNED), "fs.readFile"),
    # a subscript link names a CommonJS export as a member does (A47 (6)(d))
    "exports_subscript_name": (
        ("js", _read_entry_then(_CALLED, 'exports["readEntry"] = readEntry;')), "fs.readFile"
    ),
    "wrapped_export_const": (("ts", _WRAPPED_EXPORT), "fs.readFileSync"),
    "export_class_method": (("ts", _EXPORT_CLASS), "fs.readFileSync"),
    # public top-level and called nowhere in the file (any name is public outside Python and Go)
    "js_uncalled_unexported": ("cwe_22_37", "fs.readFile"),
    "js_underscore_uncalled": (("js", _JS_READ_ENTRY.replace("readEntry", "_readEntry")),
                               "fs.readFile"),
    # a reference is no call site (`Calls.local`): the function stays uncalled
    "referenced_not_called": (("js", _read_entry_then("queuedNames.forEach(readEntry);")),
                              "fs.readFile"),
    "python_public_uncalled": ("cwe_22_79", "open"),
    "python_method_of_a_top_level_class": (("py", _PY_TOP_LEVEL_METHOD), "open"),
    "go_upper_case_uncalled": (("go", _GO_UPPER), "os.ReadFile"),
    "cpp_out_of_line_method": (("cpp", _CPP_OUT_OF_LINE), "fopen"),
}

# ── the hint gone: a parameter no outside caller reaches ──

_JS_CALLED = _read_entry_then("readEntry(queuedName);")
_JS_NESTED = """
    import fs from "node:fs";

    export function makeReader() {
      function readEntry(fileName) {
        return fs.readFileSync(fileName);
      }
      return readEntry;
    }
"""
_PY_PRIVATE = """
    def _load(file_path):
        return open(file_path).read()
"""
_PY_NESTED_CLASS = """
    def make_store():
        class EntryStore:
            def read(self, file_path):
                return open(file_path).read()

        return EntryStore
"""
_GO_LOWER = _GO_UPPER.replace("ReadEntry", "readEntry")
# Go has no export reading: an upper-case function its own file calls is no entry
_GO_CALLED = _GO_UPPER + """
    func Boot() {
    	ReadEntry(queued)
    }
"""
# case -> (subject, sink head, the unknown reason the parameter is read as)
_GONE: dict[str, tuple[Spec, str, str]] = {
    "js_helper_called_in_file": (("js", _JS_CALLED), "fs.readFile", "param"),
    # R-B: the element takes its receiver's origins, a list no Def binds
    "callback_over_an_unresolved_list": ("cwe_22_78_clean", "fs.readFileSync", "unresolved"),
    "js_function_nested_in_an_export": (("js", _JS_NESTED), "fs.readFileSync", "param"),
    # an export reads one level into an object, no deeper
    "object_two_levels_deep": (
        ("js", _read_entry_then(_CALLED, "module.exports = { io: { readEntry } };")),
        "fs.readFile", "param",
    ),
    "python_private": (("py", _PY_PRIVATE), "open", "param"),
    "python_public_called_in_file": ("cwe_22_79_clean", "open", "param"),
    # public is the METHOD's own name, not its class's
    "python_private_method_of_a_top_level_class": (
        ("py", _PY_TOP_LEVEL_METHOD.replace("def read", "def _read")), "open", "param",
    ),
    "python_method_of_a_nested_class": (("py", _PY_NESTED_CLASS), "open", "param"),
    "go_lower_case": (("go", _GO_LOWER), "os.ReadFile", "param"),
    "go_upper_case_called_in_file": (("go", _GO_CALLED), "os.ReadFile", "param"),
}


def _hint_reports(spec: Spec, head: str = "fs.readFile") -> tuple[bool, bool]:
    """Whether the path sink ``head``'s origins hold the hint, and whether it reports."""
    return external(HINT) in _origins_at(spec, "path", head), _reported(spec, "path", head)


@pytest.mark.parametrize("case", list(_KEPT))
def test_an_entry_functions_hinted_parameter_keeps_the_hint(case: str) -> None:
    """Kept: the parameter of an exported or public uncalled top-level function is
    ``external(param_hint)``, and ``decide`` reports the path sink it reaches."""
    spec, head = _KEPT[case]
    assert _hint_reports(spec, head) == (True, True)


@pytest.mark.parametrize("case", list(_GONE))
def test_a_non_entry_functions_hinted_parameter_loses_the_hint(case: str) -> None:
    """Gone: the parameter's origins hold no external at all — ``unknown(param)``, or R-B's
    receiver for an iteration callback — so ``decide`` reports nothing."""
    spec, head, reason = _GONE[case]
    assert _unknown_at(spec, "path", head, reason) == (frozenset(), True)
    assert not _reported(spec, "path", head), f"{head} is still reported"


# ── no server-context condition, either way ──

# The cwe tier's server-context test reads these two lines (a server framework's import and
# its app): each shape below is judged without them and with them prepended.
_PRELUDES: dict[str, str] = {
    "no_server": "",
    "server": """
    const express = require("express");
    const app = express();
""",
}
_CALLBACK_IN_AN_EXPORT = """
    const fs = require("fs");

    function readQueued() {
      queuedNames.forEach((fileName) => fs.readFile(fileName, () => {}));
    }

    module.exports = { readQueued };
"""
# case -> (a JS program without the prelude, whether the hint is kept)
_SERVER_INDEPENDENT: dict[str, tuple[str, bool]] = {
    "exported_helper": (_MODULE_EXPORTS_OBJECT, True),
    "callback_inside_an_exported_function": (_CALLBACK_IN_AN_EXPORT, False),
}


@pytest.mark.parametrize("case", list(_SERVER_INDEPENDENT))
def test_the_hint_does_not_depend_on_server_context(case: str) -> None:
    """The entry reading alone decides: an exported helper keeps the hint in a file with no
    server framework, and a callback inside an exported function loses it in a server-shaped
    file — each the same with and without the server prelude."""
    source, kept = _SERVER_INDEPENDENT[case]
    seen = {name: _hint_reports(("js", prelude + source)) for name, prelude in _PRELUDES.items()}
    assert seen == dict.fromkeys(_PRELUDES, (kept, kept))


# ══ D22-c: argv is external only from C4 ══════════════════════════════════════

ARGV = "argv"
# What ``_decision`` reads off one flow: (verdict, the heuristic its row names, tallied
# ``unknown_only_sinks``).
type Decision = tuple[str, str | None, int]
BY_D25: Decision = (REPORT, TOKEN, 0)
UNKNOWN_ONLY_NONE: Decision = (NONE, None, 1)  # D9: tallied, not reported
ON_ITS_EXTERNAL: Decision = (REPORT, None, 0)


def _decision(flow: Any) -> Decision:
    """``decide`` on ``flow`` under its family's hook (cwe's command rule carries D25's, no
    other rule one): the verdict, the heuristic the row names (``named_heuristic``, the one
    question ``decide`` and the row share) and the tally."""
    rule = _rule() if flow.family == "command" else stub_rule(flow.family)
    verdict, ctx = decided(flow, flow.family, heuristic=rule.heuristic)
    return verdict, flow_mod().named_heuristic(flow, rule), ctx.tallies[UNKNOWN_ONLY]


def _decisions(spec: Spec, family: str, head: str) -> list[Decision]:
    """``_decision`` of each ``family`` flow on the line of the sink CALL ``head`` that holds an
    origin (a constant argument's flow decides ``none`` untallied, W15 (c))."""
    flows = flows_at_call(subject(spec), family, head)
    return [_decision(flow) for flow in flows if flow.origins]


def _unknown_only(spec: Spec, family: str, head: str) -> None:
    """Assert the ``family`` sink ``head`` holds ``unknown(argv)`` and no external origin, and
    ``decide`` tallies it unknown-only and reports nothing (D9)."""
    assert _unknown_at(spec, family, head, ARGV) == (frozenset(), True)
    assert _decisions(spec, family, head) == [UNKNOWN_ONLY_NONE]


# ── every argv source but C4 is unknown(argv) ──

# C4 is ``main``'s argv parameter, not the language's: the same parameter of another function.
_C_RUN = """
    #include <stdio.h>

    int run(int argc, char **argv) {
        return remove(argv[1]);
    }
"""
_CPP_RUN = _C_RUN.replace("stdio.h", "filesystem").replace("remove", "std::filesystem::remove")
# One case per argv source the flow pass mints (``_origins._source_roles`` on a bare name, a
# chain root or an imported symbol; ``_conditional_source`` on a root and its next segment),
# each read at a path sink: (subject, the sink CALL's head).
_NON_C4_READS: dict[str, tuple[Spec, str]] = {
    "process_argv_root": ("cwe_22_80_clean", "fs.readFileSync"),
    "deno_args_root": (("ts", 'import * as fs from "fs";\n\nfs.readFileSync(Deno.args[0]);\n'),
                       "fs.readFileSync"),
    "bun_argv_root": (("js", "fs.readFileSync(Bun.argv[2]);\n"), "fs.readFileSync"),
    "imported_module_segment": (("py", "import sys\n\nopen(sys.argv[1])\n"), "open"),
    "imported_symbol": (("py", "from sys import argv\n\nopen(argv[1])\n"), "open"),
    "unbound_name": (("php", "<?php\nreadfile($argv[1]);\n"), "readfile"),
    # a parameter named argv outside C main: its own unknown(param) stays beside it
    "parameter_root": (("py", "def main(argv):\n    open(argv[1])\n"), "open"),
    "c_function_other_than_main": (("c", _C_RUN), "remove"),
    "cpp_function_other_than_main": (("cpp", _CPP_RUN), "std::filesystem::remove"),
}


@pytest.mark.parametrize("case", list(_NON_C4_READS))
def test_an_argv_read_outside_c_main_is_unknown_argv(case: str) -> None:
    """Negative: the sink stays a sink, its argument holds ``unknown(argv)`` and no external
    origin, so ``decide`` tallies it unknown-only and reports nothing (the path rule has no
    D25 hook)."""
    spec, head = _NON_C4_READS[case]
    _unknown_only(spec, "path", head)


# C4: ``main``'s argv parameter at a path and a command sink, in C and C++ (the ast_v1 rows).
_C4_ROWS: dict[str, tuple[str, str, str]] = {
    "c_path": ("cwe_22_c_1", "path", "fopen"),
    "c_command_after_a_flag": ("cwe_78_c_1", "command", "execlp"),
    "cpp_path": ("cwe_22_cpp_2", "path", "std::filesystem::remove"),
    "cpp_command": ("cwe_78_cpp_1", "command", "std::system"),
}


@pytest.mark.parametrize("case", list(_C4_ROWS))
def test_c_main_argv_stays_external(case: str) -> None:
    """Positive: C4 keeps ``external(argv)``, so ``decide`` reports on that origin and the row
    names no heuristic (an ``unknown(argv)`` beside it, from the root word, moves nothing)."""
    stem, family, head = _C4_ROWS[case]
    assert external(ARGV) in _origins_at(stem, family, head)
    assert _decisions(stem, family, head) == [ON_ITS_EXTERNAL]


# ── the D3' vocabulary ──


def test_argv_is_an_unknown_reason_and_still_an_external_role() -> None:
    """``argv`` joins ``UNKNOWN_REASONS`` (every non-C4 argv origin) and stays in
    ``EXTERNAL_ROLES`` (C4)."""
    from shared.ast._records import EXTERNAL_ROLES, UNKNOWN_REASONS

    assert (ARGV in UNKNOWN_REASONS, ARGV in EXTERNAL_ROLES) == (True, True)


_CLI_JS = 'const fs = require("fs");\n\nfs.readFileSync(process.argv[2]);\n'


def _cli_answer() -> _Rich:
    """A command-line program's answer as a worker builds it (``answer.encode``, the code its
    answer branch runs), with the bytes its request ships: test 21's ``_Rich``."""
    model = model_of(_CLI_JS, "js")
    return _Rich(Path("cli.js"), _CLI_JS.encode("utf-8"), answer_mod().encode(model))


def test_d3_admits_an_answer_carrying_unknown_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D3': the answer's first path flow with origins carries ``unknown(argv)`` first; the
    answer is admitted, and the same answer with that reason swapped for an unlisted one
    (test 21's ``origin role`` forgery) is still ``bad_model``."""
    rich = _cli_answer()
    assert _origin(rich.doc) == ["unknown", ARGV, []]
    forgeries = (None, "origin role")
    verdicts = [_by_validator(rich, forgery, tmp_path, monkeypatch) for forgery in forgeries]
    assert verdicts == ["admitted", "bad_model"]


# ── D25 reads unknown(argv) as it reads unknown(param) ──

_SHELL_KWARG = "import subprocess\nimport sys\n\nsubprocess.call(sys.argv[1], shell=True)\n"
_BUILTIN_PROGRAM = (
    "use std::env;\nuse std::process::Command;\n\nfn main() {\n"
    "    let argv: Vec<String> = env::args().collect();\n"
    "    Command::new(&argv[1]).spawn().unwrap();\n}\n"
)
# (subject, the sink's head, its (shell_sink, built_arg, builtin_program))
_AT_A_COMMAND: dict[str, tuple[Spec, str, tuple[bool, bool, bool]]] = {
    "shell_interpreting_sink": (("py", _SHELL_KWARG), "subprocess.call", (True, False, False)),
    "built_template": ("cwe_78_14", "cp.exec", (False, True, False)),
    "shelled_and_built_one_hop": ("cwe_78_26", "os.system", (True, True, False)),
    "builtin_program": (("rs", _BUILTIN_PROGRAM), "Command::new", (False, False, True)),
}


@pytest.mark.parametrize("case", list(_AT_A_COMMAND))
def test_d25_reports_an_argv_flow_where_it_reports_a_parameter(case: str) -> None:
    """Positive: an ``unknown(argv)`` flow with no external origin, at a sink that shells the
    argument, of a built argument or of a builtin's whole command, reports through D25: the
    row names ``command_param`` and its origins ``unknown:argv``."""
    spec, head, facts = _AT_A_COMMAND[case]
    model = subject(spec)
    (flow,) = flows_at_call(model, "command", head)
    record = finding_of(flow, _rule(), CMD_PATH, model.nl_lines)["validation"]["flow"]
    assert ((flow.shell_sink, flow.built_arg, flow.builtin_program), externals(flow.origins)) == (
        facts, frozenset(),
    )
    assert (_decision(flow), "unknown:argv" in record["origins"]) == (BY_D25, True)
    assert record["heuristic"] == TOKEN


_BUILT_PATH = 'import sys\n\nopen("/srv/reports/" + sys.argv[1])\n'
_ELSEWHERE: dict[str, tuple[Spec, str, str]] = {
    # the clean twin of cwe_78_26: the same value as a non-shell argument list
    "non_shell_list_argument": ("cwe_78_26_clean", "command", "subprocess.run"),
    # built, but D25 is the command rule's only
    "built_path_argument": (("py", _BUILT_PATH), "path", "open"),
}


@pytest.mark.parametrize("case", list(_ELSEWHERE))
def test_d25_leaves_an_argv_flow_unreported_elsewhere(case: str) -> None:
    """Negative: at a command sink that neither shells nor builds it, and at a path sink, the
    ``unknown(argv)`` flow is unknown-only: tallied, not reported."""
    _unknown_only(*_ELSEWHERE[case])


_BOTH_HALVES = """
    import os
    import sys


    def ping(host):
        os.system("ping -c 1 " + host + " " + sys.argv[1])


    ping("localhost")
"""


def test_a_bound_parameter_is_superseded_and_its_callers_argv_flow_reports() -> None:
    """A47 read literally: ``param_bound`` keeps its meaning, so the base flow holding
    ``unknown(param)`` and ``unknown(argv)``, whose parameter the same-file caller binds, is
    superseded (tallied, not reported); the caller's context holds ``unknown(argv)`` and no
    ``unknown(param)``, is never ``param_bound``, and reports through D25. The sink reports
    once, through its argv half."""
    flows = flows_at_call(subject(("py", _BOTH_HALVES)), "command", "os.system")
    param, argv = unknown("param"), unknown(ARGV)
    found = sorted(
        (param in f.origins, argv in f.origins, f.param_bound, *_decision(f)) for f in flows
    )
    assert found == [(False, True, False, *BY_D25), (True, True, True, *UNKNOWN_ONLY_NONE)]


# (the unknown reasons a flow holds, shell_sink, param_bound) -> what the command hook answers
_HOOK_READS: dict[str, tuple[tuple[str, ...], bool, bool, str | None]] = {
    "argv_shelled": ((ARGV,), True, False, TOKEN),
    "argv_neither_shelled_nor_built": ((ARGV,), False, False, None),
    "param_shelled": (("param",), True, False, TOKEN),
    "param_and_argv_bound": (("param", ARGV), True, True, None),
    "param_and_argv_unbound": (("param", ARGV), True, False, TOKEN),
    "another_reason": (("unresolved",), True, False, None),
}


@pytest.mark.parametrize("case", list(_HOOK_READS))
def test_the_command_hook_reads_argv_as_it_reads_param(case: str) -> None:
    """``consume.command_param``: ``(unknown(param) or unknown(argv))`` held at a sink that
    shells, builds or is the builtin's program, and not ``param_bound`` — which supersedes a
    flow holding both exactly as one holding ``unknown(param)`` alone."""
    reasons, shell, bound, token = _HOOK_READS[case]
    flow = flow_with("command", *map(unknown, reasons))
    hooked = dataclasses.replace(flow, shell_sink=shell, param_bound=bound)
    assert consume_mod().command_param(hooked) == token


# ══ (h): an early exit dominates the rest of its function ═════════════════════

# ``guard_verdict`` reads ``NO_GUARD`` for "no guard found" and ``REPORT`` for "guards that
# cover nothing" (A29 (2): an exit with no covering role is still a guard, and decide reports).
_CONTAIN_EXIT = "if (!p.startsWith(ROOT)) return;"  # a path_contain exit on p
_ALLOW_EXIT = "if (!ALLOWED.includes(p)) return;"  # an {allowlist, path_contain} exit on p
_TRUTHY_EXIT = "if (!p) return;"  # an exit on p with no covering role


def _nested(statement: str) -> tuple[str, str, str]:
    """``statement`` one block below the statements before it."""
    return "if (a) {", statement, "}"


_SINK_IN_IF = _nested(SINK_P)


def _guard_lines(spec: Spec, head: str) -> list[int]:
    """The lines of the guards ``guards_for`` found for the path sink ``head``, in its order."""
    model = subject(spec)
    return [model.line(node) for node, _ in _guard_records(flows_at_call(model, "path", head))]


def _lines_of(spec: Spec, *needles: str) -> list[int]:
    """The line each of ``needles`` first starts on in the text ``spec``'s model parsed."""
    text = "\n".join(subject(spec).nl_lines)
    return [newline_row(text, needle) for needle in needles]


# ── an exit one or more blocks up guards the nested sink ──

# A Python view whose request value a containment exit guards; each tail below holds the sink.
_PY_VIEW = """
    def view(request):
        name = request.args["f"]
        if not name.startswith(ROOT):
            return None
"""
_PY_WITH = _PY_VIEW + """\
        with lock:
            return open(name)
"""
# R-R one block up: a try whose body tests containment and whose except exits
_PY_TRY_CONTAIN = """
    def view(request):
        full = (ROOT / request.args["f"]).resolve()
        try:
            full.relative_to(ROOT)
        except ValueError:
            return None
        if full.suffix:
            return open(full)
"""
# no FUNCTION holds the sink: the walk reaches the MODULE
_PY_SCRIPT = """
    import sys

    name = sys.stdin.readline()
    if not name.startswith(ROOT):
        sys.exit(1)
    if name.endswith(".csv"):
        open(name)
"""
_JS_LOOP = js_handler(
    "for (const k of KEYS) {", "const p = req.query[k];", "if (!ALLOWED.includes(p)) { continue; }",
    *_SINK_IN_IF, "}",
)
_TRY_BODY = js_handler(READ, _CONTAIN_EXIT, "try {", SINK_P, "} catch (e) {", "log(e);", "}")
_TWO_BLOCKS_UP = js_handler(READ, _CONTAIN_EXIT, "if (b) {", *_SINK_IN_IF, "}")
_ALTERNATIVE = js_handler(READ, _CONTAIN_EXIT, "if (a) {", "log(a);", "} else {", SINK_P, "}")
# case -> (subject, sink head, the verdict)
_NESTED_SINKS: dict[str, tuple[Spec, str, str]] = {
    "disjunction_one_block_up": ("cwe_22_71_clean", "fs.readFile", PATH_CONTAIN),
    "loop_continue_one_block_up": ("cwe_22_72_clean", "open", PATH_CONTAIN),
    "try_body": (_TRY_BODY, SINK, PATH_CONTAIN),
    "js_loop_continue": (_JS_LOOP, SINK, ALLOWLIST),
    "two_blocks_up": (_TWO_BLOCKS_UP, SINK, PATH_CONTAIN),
    "alternative_branch": (_ALTERNATIVE, SINK, PATH_CONTAIN),
    "python_with_body": (("py", _PY_WITH), "open", PATH_CONTAIN),
    "script_module": (("py", _PY_SCRIPT), "open", PATH_CONTAIN),
    "rr_try_contain_one_block_up": (("py", _PY_TRY_CONTAIN), "open", PATH_CONTAIN),
}


@pytest.mark.parametrize("case", list(_NESTED_SINKS))
def test_an_early_exit_in_an_enclosing_block_guards_a_nested_sink(case: str) -> None:
    """(h) negative: a covering exit in an enclosing block of the same function (or module),
    an IF by clause (a) or a TRY by R-R, declines the nested sink with its role."""
    spec, head, verdict = _NESTED_SINKS[case]
    assert guard_verdict(subject(spec), "path", head) == verdict


# ``guards_for`` is family-agnostic, so the window widens for every family:
# case -> (subject, family, sink head, the covering role's decline label)
_EVERY_FAMILY: dict[str, tuple[Spec, str, str, str]] = {
    "request": (
        js_handler("const u = req.query.u;", "if (!isAllowedHost(u)) return;",
                   *_nested("fetch(u);")),
        "request", "fetch", HOST_ALLOW,
    ),
    "command": (
        js_handler("const c = req.query.c;", "if (!/^[a-z]+$/.test(c)) return;",
                   *_nested("cp.exec(c);")),
        "command", "cp.exec", VALIDATE,
    ),
}


@pytest.mark.parametrize("case", list(_EVERY_FAMILY))
def test_an_enclosing_exit_guards_every_family(case: str) -> None:
    """(h) negative: a covering exit one block up declines a request and a command sink as it
    declines a path sink."""
    spec, family, head, verdict = _EVERY_FAMILY[case]
    assert guard_verdict(subject(spec), family, head) == verdict


# The guards found, each by its statement's text: the IF ancestor (clause (b), no role) where
# there is one, then the exit.
_ROLELESS_EXITS: dict[str, tuple[Spec, str, tuple[str, ...]]] = {
    "extension_deny_list": (
        "cwe_22_71", "fs.readFile",
        ("if (notePath.endsWith('.md'))", "if (notePath.endsWith('.bak')"),
    ),
    "temporary_skip_in_a_loop": (
        "cwe_22_72", "open", ('if ledger_path.endswith(".csv")', 'if ledger_path.endswith(".tmp")'),
    ),
    "truthiness": (js_handler(READ, _TRUTHY_EXIT, *_SINK_IN_IF), SINK, (_TRUTHY_EXIT,)),
}


@pytest.mark.parametrize("case", list(_ROLELESS_EXITS))
def test_an_enclosing_exit_without_a_covering_role_still_reports(case: str) -> None:
    """(h) positive, A29 (2): the enclosing exit meets the value and exits, so it is a guard,
    and with no covering role ``decide`` still reports the sink."""
    spec, head, guards = _ROLELESS_EXITS[case]
    assert (guard_verdict(subject(spec), "path", head), _guard_lines(spec, head)) == (
        REPORT, _lines_of(spec, *guards),
    )


# ── an exit that does not dominate the value at the sink ──

_NOT_DOMINATING: dict[str, Spec] = {
    "exit_on_another_value": js_handler(
        READ, "const q = req.query.g;", "if (!q.startsWith(ROOT)) return;", *_SINK_IN_IF,
    ),
    "exit_after_the_statement": js_handler(READ, *_SINK_IN_IF, _CONTAIN_EXIT),
    "value_reassigned_in_between": js_handler(
        "let p = req.query.f;", _CONTAIN_EXIT, "p = req.query.g;", *_SINK_IN_IF,
    ),
    "exit_in_a_sibling_block": js_handler(
        READ, "if (a) {", _CONTAIN_EXIT, "}", "if (b) {", SINK_P, "}",
    ),
    "exit_in_the_other_branch": js_handler(
        READ, "if (a) {", _CONTAIN_EXIT, "} else {", SINK_P, "}",
    ),
    # the covering role alone is no guard: clause (a) needs a CONSEQ that exits
    "covering_test_without_an_exit": js_handler(
        READ, "if (!p.startsWith(ROOT)) { log(p); }", *_SINK_IN_IF,
    ),
}


@pytest.mark.parametrize("case", list(_NOT_DOMINATING))
def test_an_exit_on_another_value_or_after_the_sink_guards_nothing(case: str) -> None:
    """(h) positive: only an exit (a CONSEQ that exits) before the sink's ancestor statement in
    an enclosing block, on the Def that reaches the sink, is a candidate; none of these is a
    guard."""
    assert guard_verdict(subject(_NOT_DOMINATING[case]), "path", SINK) == NO_GUARD


# ── the walk stops at the function boundary ──

_PY_NESTED_DEF = _PY_VIEW + """\

        def inner():
            return open(name)

        return inner()
"""
_PY_LAMBDA = _PY_VIEW + """\
        return run_later(lambda: open(name))
"""


def _in_callback(guard: str) -> Spec:
    """``guard``, then the sink in a block-bodied callback."""
    return js_handler(READ, guard, "items.forEach((x) => {", SINK_P, "});")


def _in_closure(guard: str) -> Spec:
    """``guard``, then the sink in a closure, then p reassigned (R-O: the closure read joins
    both Defs of p, the one ``guard`` tests among them)."""
    return js_handler(
        "let p = req.query.f;", guard, "setTimeout(() => {", SINK_P, "}, 10);", "p = req.query.g;"
    )


def _in_arrow(guard: str) -> Spec:
    """``guard``, then the sink in an expression-bodied arrow: no BLOCK of its own, so
    block_of(sink) is the enclosing function's body, as today."""
    return js_handler(READ, guard, "items.forEach(() => fs.readFileSync(p));")


_NESTED_FUNCTION = js_handler(READ, _CONTAIN_EXIT, "function inner() {", SINK_P, "}", "inner();")
# A47 (6)(g): a check statement (A44 (1) (d) (i)) stops at the same boundary as an exit
_CHECK = f'{_INSIDE}(p, "/srv");'
_BOUNDARY: dict[str, tuple[Spec, str, str]] = {
    "block_bodied_callback": (_in_callback(_CONTAIN_EXIT), SINK, NO_GUARD),
    "closure_read_reassigned_after": (_in_closure(_CONTAIN_EXIT), SINK, NO_GUARD),
    "nested_function_declaration": (_NESTED_FUNCTION, SINK, NO_GUARD),
    "python_nested_def": (("py", _PY_NESTED_DEF), "open", NO_GUARD),
    "expression_bodied_arrow": (_in_arrow(_CONTAIN_EXIT), SINK, PATH_CONTAIN),
    "python_lambda": (("py", _PY_LAMBDA), "open", PATH_CONTAIN),
    "check_before_a_block_bodied_callback": (_in_callback(_CHECK), SINK, NO_GUARD),
    "check_before_a_closure_read_reassigned_after": (_in_closure(_CHECK), SINK, NO_GUARD),
    "check_before_an_expression_bodied_arrow": (_in_arrow(_CHECK), SINK, PATH_CONTAIN),
}


@pytest.mark.parametrize("case", list(_BOUNDARY))
def test_the_enclosing_window_stops_at_the_function_boundary(case: str) -> None:
    """(h) positive: an exit - or a check statement, A47 (6)(g) - before a nested function's
    statement does not guard a sink in its body; a sink with no block of its own is read where
    it is today."""
    spec, head, verdict = _BOUNDARY[case]
    assert guard_verdict(subject(spec), "path", head) == verdict


# ── roles: a combined TEST is read whole (L4), not as a De Morgan reading ──

# (language code, one part, the other part, the template that combines the two)
_COMBINED_TESTS: dict[str, tuple[str, str, str, str]] = {
    "containment_first": ("js", "!p.startsWith(ROOT)", "p.endsWith('.swp')", "{} || {}"),
    "containment_second": ("js", "p.endsWith('.bak')", "!p.startsWith(ROOT)", "{} || {}"),
    "two_roles": ("js", "!ALLOWED.includes(p)", "!p.startsWith(ROOT)", "{} || {}"),
    "conjunction": ("js", "!p.startsWith(ROOT)", "p.length > 64", "{} && {}"),
    "parenthesised": ("js", "!p.startsWith(ROOT)", "p.endsWith('.swp')", "({}) || ({})"),
    "python_or": ("py", "not name.startswith(ROOT)", 'name.endswith(".tmp")', "{} or {}"),
    "negated_conjunction": ("py", "name.startswith(ROOT)", 'name.endswith(".csv")',
                            "not ({} and {})"),
}


def _test_roles(lang: str, *tests: str) -> list[frozenset[str]]:
    """The guard roles of each of ``tests`` as an IF's TEST, in one ``lang`` program."""
    model = program(lang, "".join(_GUARD[lang].format(test) for test in tests))
    return [guard_roles_of(model, if_test(model, nth=i)) for i in range(len(tests))]


@pytest.mark.parametrize("case", list(_COMBINED_TESTS))
def test_a_disjunction_exit_reads_every_disjuncts_roles(case: str) -> None:
    """As built (A47's correction of the class-8 diagnosis): a combined TEST's roles are the
    union of its parts' roles, whatever the operator, order, parentheses or negation."""
    lang, *parts, template = _COMBINED_TESTS[case]
    left, right, combined = _test_roles(lang, *parts, template.format(*parts))
    assert combined == left | right
    assert "path_contain" in combined


# ── A29's order across blocks ──

_VALID_IF = "if (isValid(p)) {"  # an IF ancestor (clause (b))
_ORDERED = js_handler(
    READ,
    _CONTAIN_EXIT,  # a window exit in the handler's body
    "if (a) {",
    _ALLOW_EXIT,  # a window exit in if (a)'s block
    _CHECK,
    _VALID_IF,
    _TRUTHY_EXIT,  # a window exit in block_of(sink)
    SINK_P,
    "}",
    "}",
)
# The nearest covering exit labels the decline: if (a)'s allowlist, not the body's containment.
_NEAREST_COVERS = js_handler(
    READ, _CONTAIN_EXIT, "if (a) {", _ALLOW_EXIT, "if (b) {", _TRUTHY_EXIT, SINK_P, "}", "}",
)


def test_enclosing_guards_follow_block_order() -> None:
    """A29: ancestors, then each window block nearest first, then the check statements; the
    label is the first covering guard's."""
    order = (_VALID_IF, _TRUTHY_EXIT, _ALLOW_EXIT, _CONTAIN_EXIT, _CHECK)
    assert _guard_lines(_ORDERED, SINK) == _lines_of(_ORDERED, *order)
    assert guard_verdict(subject(_NEAREST_COVERS), "path", SINK) == ALLOWLIST


# ── §8.7: GUARD_WINDOW candidates per block ──

# (filler, how many before the sink's statement in the handler's body, how many before the
# sink in its own block, verdict): each same-block window row (``_WINDOW``) one block up, then
# a full window in the sink's own block
_CAPPED = [
    pytest.param(filler, outer, 0, verdict, id=str(row.id).replace("guard-", "exit-"))
    for row in _WINDOW
    for filler, outer, verdict in [row.values]
] + [pytest.param(_IF_FILLER, 0, GUARD_WINDOW, ALLOWLIST, id="a-full-inner-window-is-its-own")]


@pytest.mark.parametrize(("filler", "outer", "inner", "verdict"), _CAPPED)
def test_the_enclosing_window_is_capped_per_block(
    filler: str, outer: int, inner: int, verdict: str
) -> None:
    """(h), §8.7: each block reads its own ``GUARD_WINDOW`` nearest IF / TRY siblings."""
    before, within = numbered(filler, outer), numbered(filler, inner)
    spec = js_handler(READ, _ALLOW_EXIT, before, "if (a) {", within, SINK_P, "}")
    assert guard_verdict(subject(spec), "path", SINK) == verdict


# ══ (i): a generic verb is a path sink only with file-system evidence ═════════


def _js_at(*statements: str) -> tuple[Spec, str]:
    """A JS handler of ``READ`` then ``statements``, and its sink: the last statement's head."""
    return js_handler(READ, *statements), statements[-1].partition("(")[0]


# ── no file-system evidence: no path sink ──

_YAML_LOAD = """
    import yaml


    def view(request):
        return yaml.load(request.args["doc"])
"""
# a generic verb no Go shadow names, on a receiver with no file-system word
_GO_STORE_OPEN = """
    package app

    import "net/http"

    func view(w http.ResponseWriter, r *http.Request) {
        store.Open(r.URL.Query().Get("f"))
    }
"""
# a Def binds the callee (a parameter, a value): it is no language global
_PARAM_CALLEE = """
    function handler(req, res, load) {
      load(req.query.f);
    }
"""


def _py_restore(imports: str, call: str) -> tuple[Spec, str]:
    """A Python view after ``imports`` that passes a request value to ``call``, and its head:
    each name of a multi-module import reads the module its own SOURCE names (A47 (6)(f))."""
    body = f'{imports}\n\n\ndef restore(request):\n    {call}(request.args["src"], "/srv/out")\n'
    return ("py", body), call


# case -> (subject, sink head)
_NO_EVIDENCE: dict[str, tuple[Spec, str]] = {
    "in_app_required_module": ("cwe_22_73_clean", "archive.remove"),
    "in_app_aliased_import": ("cwe_22_74_clean", "duplicate"),
    "storage_object": ("cwe_22_75_clean", "draftStorage.save"),
    "buffer": ("cwe_22_76_clean", "given.copy"),
    "in_app_named_import": ("cwe_22_77_clean", "truncate"),
    "go_predeclared_append": ("cwe_22_go_4_clean", "append"),
    "go_predeclared_copy": ("cwe_22_go_4_clean", "copy"),
    "go_generic_verb_on_a_store": (("go", _GO_STORE_OPEN), "store.Open"),
    # W5 reads a shadow's single key for any receiver, as C's read / write (A47 (5)(b)):
    # the builtin decides before the receiver's file-system word
    "go_shadow_on_a_qualified_call": (
        ("go", _GO_STORE_OPEN.replace("store.Open(", "files.Copy(")), "files.Copy"
    ),
    "tab_list": _js_at("tabs.remove(p);"),
    "class_list": _js_at("el.classList.remove(p);"),
    "form_data": _js_at("form.append(p, req.body.value);"),
    "document_parser": (("py", _YAML_LOAD), "yaml.load"),
    "parameter_callee": (("js", _PARAM_CALLEE), "load"),
    "alias_after_a_file_system_module": _py_restore("import os, store as sh", "sh.remove"),
    "name_after_a_file_system_module": _py_restore("import shutil, store", "store.remove"),
}

# ── file-system evidence: the path sink stays ──

_FS_PROMISES_DEFAULT = """
    import fsp from "node:fs/promises";

    export async function handler(req, res) {
      await fsp.open(req.query.f);
    }
"""
_FS_PROMISES_NAMED = """
    import { open as openEntry } from "node:fs/promises";

    export async function handler(req, res) {
      await openEntry(req.query.f);
    }
"""
_SHUTIL_ALIAS = """
    import shutil as sh


    def restore(request):
        sh.copy(request.args["src"], "/srv/restore")
"""
_JAVA_FILES_COPY = """
    class RestoreController {
        @PostMapping("/restore")
        void restore(@RequestParam String name) throws Exception {
            Files.copy(UPLOADS.resolve(name), TARGET);
        }
    }
"""
_PHP_RENAME = """
    <?php
    $from = $_GET['from'];
    rename($from, '/srv/archive/old.txt');
"""
_C_REMOVE = _C_RUN.replace("int run", "int main")  # C4's argv at a C language global
_WITH_EVIDENCE: dict[str, tuple[Spec, str]] = {
    "file_system_required_module": ("cwe_22_73", "archive.remove"),
    "file_system_aliased_import": ("cwe_22_74", "duplicate"),
    "fs_receiver_sync_twin": _SYNC_SINKS["rename_row"],
    "qualified_callee": ("cwe_22_cpp_2", "std::filesystem::remove"),
    "go_os_receiver": ("cwe_22_go_2", "os.Open"),
    "python_global": ("cwe_22_14", "open"),
    "fs_promises_default_import": (("js", _FS_PROMISES_DEFAULT), "fsp.open"),
    "fs_promises_named_import": (("js", _FS_PROMISES_NAMED), "openEntry"),
    "module_alias": (("py", _SHUTIL_ALIAS), "sh.copy"),
    # a WORD of a glued identifier (``roles.words``), not the whole segment
    "compound_receiver_word": _js_at("uploadDir.remove(p);"),
    "member_chain_word": _js_at("this.fileStore.save(p);"),
    "java_files_receiver": (("java", _JAVA_FILES_COPY), "Files.copy"),
    "php_global": (("php", _PHP_RENAME), "rename"),
    "c_global": (("c", _C_REMOVE), "remove"),
    "file_system_alias_second": _py_restore("import store as sh, shutil as su", "su.copy"),
    "dotted_alias_second": _py_restore("import json, os.path as osp", "osp.exists"),
}


@pytest.mark.parametrize("case", list(_NO_EVIDENCE))
def test_a_generic_path_verb_without_file_system_evidence_is_no_path_sink(case: str) -> None:
    """Negative: a generic verb on a receiver, an import or a bound name with no file-system
    word, and Go's predeclared slice builtins, are no path sink - no ``path`` candidate."""
    spec, head = _NO_EVIDENCE[case]
    assert _no_sink(spec, "path", head), f"{head} is still a path sink"


@pytest.mark.parametrize("case", list(_WITH_EVIDENCE))
def test_a_generic_path_verb_with_file_system_evidence_stays_a_path_sink(case: str) -> None:
    """Positive: a file-system word in the callee chain, the receiver chain or the whole
    module path of the binding, or a language global, keeps the sink: it reports a request
    value."""
    spec, head = _WITH_EVIDENCE[case]
    assert _reported(spec, "path", head), f"{head} is no longer reported"


# ── a profile builtin decides first (W5, R5) ──

# (profile, key): a language global that only shadows a path sink word - Go's predeclared
# slice builtins (A47) and C's fd / buffer calls (P4; C++ inherits them) - one shared entry.
_SHADOWS = (("go", "append"), ("go", "copy"), ("c", "read"), ("c", "write"), ("cpp", "read"))


def test_go_predeclared_append_and_copy_shadow_the_sink_words() -> None:
    """R5's mechanism: each shadow is a builtin of its profile with the EMPTY family set, the
    ONE ``profiles.NO_FAMILY`` entry (C's moved there, shared), so neither a sink word nor the
    language-global evidence makes it a path sink."""
    no_family = getattr(importlib.import_module("shared.ast.profiles"), "NO_FAMILY", None)
    assert no_family is not None and not no_family.families, "profiles exports no empty NO_FAMILY"
    assert [
        f"{lang}:{key}" for lang, key in _SHADOWS
        if PROFILES[lang].builtin_sinks.get(key) is not no_family
    ] == []


# ── every other path key needs no evidence ──

_RMTREE = """
    def purge(request):
        cleanup.rmtree(request.args["dir"])
"""
_FILE_SPECIFIC: dict[str, tuple[Spec, str]] = {
    "send_file": _js_at("res.sendFile(p);"),
    "download": _js_at("res.download(p);"),
    "read_file": _js_at("store.readFile(p, () => {});"),
    "unlink": _js_at("vault.unlink(p, () => {});"),
    "read_stream": _js_at("archive.createReadStream(p);"),
    "extract_all": _js_at("bundle.extractAll(p);"),
    "rmtree": (("py", _RMTREE), "cleanup.rmtree"),
}


@pytest.mark.parametrize("case", list(_FILE_SPECIFIC))
def test_a_file_specific_path_key_needs_no_evidence(case: str) -> None:
    """Positive: a path key outside ``GENERIC_PATH_VERBS`` names a file operation by itself,
    so it reports with no file-system word anywhere."""
    spec, head = _FILE_SPECIFIC[case]
    assert _reported(spec, "path", head), f"{head} is no longer reported"


# ── (e)'s sync twin reads as its stem ──

_FS_EXTRA = 'const fse = require("fs-extra");'
# ((the handler, the sink's head), whether it is a path sink)
_SYNC_TWINS: dict[str, tuple[tuple[Spec, str], bool]] = {
    "remove_no_evidence": (_js_at("drafts.removeSync(p);"), False),
    "exists_no_evidence": (_js_at("cache.existsSync(p);"), False),
    "copy_no_evidence": (_js_at('snapshot.copySync(p, "/srv/out");'), False),
    "remove_fs_receiver": (_js_at("fs.removeSync(p);"), True),
    "copy_required_module": (_js_at(_FS_EXTRA, 'fse.copySync(p, "/srv/out");'), True),
}


@pytest.mark.parametrize("case", list(_SYNC_TWINS))
def test_a_sync_twin_is_read_as_its_stem_by_the_generic_test(case: str) -> None:
    """``<stem>Sync`` is a generic verb when its stem is: it needs the same evidence. RED for
    the three ``*_no_evidence`` cases; the two with evidence pin (e)'s recall."""
    (spec, head), sink = _SYNC_TWINS[case]
    found = not _no_sink(spec, "path", head)
    assert found is sink, f"{head}: a path sink is {found}, A47 says {sink}"


# ── the one import reader reads the whole module path ──

_JS_PROCESS_SEGMENT = """
    import { runCommandForJob } from "../process/jobs.js";

    export async function handler(req, res) {
      await runCommandForJob(req.query.cmd);
    }
"""
_PY_PROCESS_MODULE = """
    from tools.process import run_command_logged


    def rebuild(request):
        run_command_logged(request.args["target"])
"""
# A47 (6)(h): (c) reads the import of the receiver chain's root, as (i) does
_JS_PROCESS_ALIAS = """
    const cp = require("child_process");

    export function handler(req, res) {
      cp.execFile(req.query.tool);
    }
"""
_TS_PROCESS_NAMESPACE = """
    import * as cp from "node:child_process";

    export function handler(req, res) {
      cp.execFileSync(req.body.tool);
    }
"""
_JS_NO_PROCESS = _JS_PROCESS_SEGMENT.replace("../process/jobs.js", "../tasks/queue.js")
# `filepath` carries no file-system word; the module path's first segment does
_GO_FILEPATH = """
    package app

    import (
        "net/http"
        "path/filepath"
    )

    func listTree(w http.ResponseWriter, r *http.Request) {
        filepath.Walk(r.URL.Query().Get("dir"), visit)
    }
"""
# (subject, family, head) -> whether it reports: (c)'s process evidence and (i)'s file-system
# evidence read the one reader (``node:fs/promises`` is in _WITH_EVIDENCE)
_WHOLE_PATH: dict[str, tuple[Spec, str, str, bool]] = {
    "js_inner_segment": (("js", _JS_PROCESS_SEGMENT), "command", "runCommandForJob", True),
    "python_dotted_module": (("py", _PY_PROCESS_MODULE), "command", "run_command_logged", True),
    "no_process_segment": (("js", _JS_NO_PROCESS), "command", "runCommandForJob", False),
    "go_inner_segment": (("go", _GO_FILEPATH), "path", "filepath.Walk", True),
    "js_aliased_process_module": (("js", _JS_PROCESS_ALIAS), "command", "cp.execFile", True),
    "ts_process_namespace": (("ts", _TS_PROCESS_NAMESPACE), "command", "cp.execFileSync", True),
}


@pytest.mark.parametrize("case", list(_WHOLE_PATH))
def test_an_import_names_its_whole_module_path(case: str) -> None:
    """``Calls._import_words`` reads an import's WHOLE module path - every segment of a JS or
    Go path, a Python dotted module - for (c)'s process evidence and (i)'s file-system evidence
    alike, each from the bare callee's import or the receiver chain root's (A47 (6)(h)). RED
    for the command cases that report; the path case and the module with no process concept
    pin what the reading keeps and bounds."""
    spec, family, head, reported = _WHOLE_PATH[case]
    found = _reported(spec, family, head)
    assert found is reported, f"{head}: a reported {family} sink is {found}, A47 says {reported}"


# ── the two tables (§9.1: concept words, defined once and exported by roles) ──

_GENERIC_PATH_VERBS = frozenset({
    "open", "read", "write", "append", "remove", "rename", "copy", "move", "truncate", "exists",
    "access", "watch", "walk", "stream", "save", "load", "extract",
})
_FILE_SYSTEM_WORDS = frozenset({
    "fs", "file", "files", "path", "paths", "dir", "dirs", "directory", "folder", "filesystem",
    "os", "shutil",
})
# What a non-file receiver's words carry (a storage service, a DOM root, a cache, a buffer):
# never evidence, so no such word is a file-system word.
_NOT_FILE_SYSTEM = frozenset({"root", "roots", "storage", "store", "cache", "buffer", "stream"})


def _a47_table(name: str) -> frozenset[str]:
    """An A47 table as ``roles`` exports it (A27 (5)), whichever of its modules defines it; a
    missing table fails here as an assertion."""
    roles = roles_mod()
    table = getattr(roles, name, None)
    assert table is not None and name in roles.__all__, f"{name} is not exported by roles"
    return frozenset(table)


def test_generic_path_verbs_are_path_sink_keys() -> None:
    """A47's verb table, exactly, and a subset of the path sink keys: the rule narrows a sink
    and never adds one."""
    verbs = _a47_table("GENERIC_PATH_VERBS")
    assert verbs == _GENERIC_PATH_VERBS
    assert verbs - roles_mod().SINK_WORDS["path"] == frozenset()


def test_file_system_words_name_no_store_or_root() -> None:
    """A47's evidence words, exactly: a storage, root, cache or buffer concept and every
    data-store word stay out, so a storage object's ``save`` or a DOM root's
    ``classList.remove`` is no file API."""
    found = _a47_table("FILE_SYSTEM_WORDS")
    assert found == _FILE_SYSTEM_WORDS
    assert found & (_NOT_FILE_SYSTEM | roles_mod().DATA_STORE_WORDS) == frozenset()
