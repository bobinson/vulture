"""Feature 0102 (A43 (1), (2); LLD §8.5, §9.3; D9, D10, D25): the AST tier's counterparts of
the pre-0102 unit tests that pin REGEX-tier behaviour on inputs the AST tier now owns.

WHY THIS EXISTS
---------------
Nine pre-0102 tests of ``check_injection`` pin what the regex bodies do on a file the AST tier
now parses. They now run on the regex fallback path through the ``regex_tier`` fixture
(``tests/unit/conftest.py``), inputs and assertions unchanged, because the regex bodies still
own every file the AST tier does not parse (D10). This module scans the SAME inputs as the
skill ships and pins what the AST tier does on the parsed file, and why — each a reading of the
LLD as amended: D9 (a constant-only sink is nothing; an UNKNOWN-only one is tallied, not
reported, unless D25 names it), the scope of §8.5's server-context gate, a whole-file flow
rather than a 25-line window, and structural guards rather than context words.

    re-pointed test                                                   counterpart here
    test_injection_command_langs::test_java_runtime_exec_flagged_cwe78  bare parameter, tallied
    test_injection_command_langs::test_php_passthru_flagged_cwe78       bare parameter, tallied
    test_injection_command_langs::test_php_proc_open_flagged_cwe78      bare parameter, tallied
    test_injection_command_langs::test_php_shell_exec_static_arg_...    constant argument
    test_injection_command_langs::test_java_runtime_exec_static_arg_... constant argument
    test_0070_p7_injection::TestArgumentInjection::
        test_processbuilder_stays_cwe78_only                            an argv element
    test_0070_injection::TestSsrfOneHopTaint::
        test_req_body_assigned_identifier_reaches_fetch                 map read in server code
        test_taint_does_not_reach_beyond_window                         whole-file flow
    test_skills::TestCheckSSRF::test_no_finding_with_allowlist          context words

A43 (1), D25's builtin half: a bare parameter that is the WHOLE command of a command builtin of
the profile's own table — Java ``new ProcessBuilder(cmd)``, Rust ``Command::new(cmd)``, C
``posix_spawn`` — reports (``Flow.builtin_program``), so
``test_java_processbuilder_flagged_cwe78`` passes as it stands. A receiver-less call of a
``COMMAND_STRONG`` key (PHP ``passthru($cmd)``) does not: no table lists it, and measured as a
condition it raised the held-out command FP from 4/9 to 5/9 and added three clean real-code
rows, so A43 (1) leaves it out.

Every input is the re-pointed test's own literal: imported where its module names it
(``JAVA_PROCESSBUILDER``, ``PROFILE_IMAGE_UPLOAD``), else copied verbatim.
"""

from __future__ import annotations

import contextvars
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from cwe_agent.skills.dangerous_function_check import check_dangerous_function
from cwe_agent.skills.injection_check import check_injection
from shared.ast import context
from shared.ast.cache import owns
from tests import _ast_heads, _ast_v1
from tests.unit.skills.test_0070_injection import PROFILE_IMAGE_UPLOAD
from tests.unit.skills.test_0070_p7_injection import JAVA_PROCESSBUILDER

COMMAND, SSRF = "CWE-78", "CWE-918"
PARAM, REQUEST = "unknown:param", "external:request"
TOKEN = "command_param"  # D25's ``validation.flow.heuristic``

# ── the inputs, verbatim ─────────────────────────────────────────────────────
# test_injection_command_langs: a bare parameter at a command sink D25 does not name.
RUNTIME_EXEC_PARAM = (
    "V.java",
    "public class V {\n"
    "    public void run(String cmd) throws Exception {\n"
    "        Runtime.getRuntime().exec(cmd);\n"
    "    }\n"
    "}\n",
)
PASSTHRU_PARAM = ("v.php", "<?php\nfunction run($cmd) { passthru($cmd); }\n")
PROC_OPEN_PARAM = ("v.php", "<?php\nfunction run($cmd) { proc_open($cmd, [], $p); }\n")
# test_injection_command_langs: a constant argument (audit #2).
SHELL_EXEC_STATIC = ("v.php", '<?php\nfunction run() { return shell_exec("ls -la"); }\n')
RUNTIME_EXEC_STATIC = (
    "V.java",
    "public class V {\n"
    '    void run() throws Exception { Runtime.getRuntime().exec("ls -la"); }\n'
    "}\n",
)
STATIC, STATIC_IDS = (SHELL_EXEC_STATIC, RUNTIME_EXEC_STATIC), ("shell_exec", "runtime_exec")
# test_injection_command_langs::test_java_processbuilder_flagged_cwe78 (passes by A43 (1)).
PROCESSBUILDER_PARAM = (
    "V.java",
    "public class V {\n"
    "    public void run(String cmd) throws Exception {\n"
    "        new ProcessBuilder(cmd).start();\n"
    "    }\n"
    "}\n",
)
PROCESSBUILDER_ARGV = ("R.java", JAVA_PROCESSBUILDER)
IMAGE_URL_UPLOAD = ("imageUrlUpload.ts", PROFILE_IMAGE_UPLOAD)
# test_0070_injection::test_taint_does_not_reach_beyond_window.
_FAR = ["import express from 'express'", "const url = req.query.u"]
_FAR += ["  // filler"] * 25
_FAR += ["await fetch(url)"]
BEYOND_WINDOW = ("far.ts", "\n".join(_FAR) + "\n")
# test_skills::TestCheckSSRF::test_no_finding_with_allowlist.
ALLOWLIST_WORDS = (
    "api.py",
    "import requests\ndef fetch(url):\n    validate_url(url)\n"
    "    allowed_hosts = ['api.example.com']\n    return requests.get(user_input)\n",
)

# ── the contrasts (not from a re-pointed test) ───────────────────────────────
RUNTIME_EXEC_REQUEST = (
    "V.java",
    "public class V {\n"
    "    void run(HttpServletRequest request) throws Exception {\n"
    '        Runtime.getRuntime().exec(request.getParameter("c"));\n'
    "    }\n"
    "}\n",
)
PASSTHRU_REQUEST = ("v.php", "<?php\nfunction run() { passthru($_GET['c']); }\n")
PROC_OPEN_REQUEST = ("v.php", "<?php\nfunction run() { proc_open($_GET['c'], [], $p); }\n")
# A host check on the sink's own argument: a guard by structure (membership + a host word).
HOST_GUARD = (
    "api.py",
    "import requests\nfrom flask import request\ndef fetch():\n"
    "    user_input = request.args['u']\n    if user_input not in allowed_hosts:\n"
    "        return None\n    return requests.get(user_input)\n",
)
# The other two tables A43 (1) reads: a Rust builtin pair key and a C builtin (program = arg 1).
COMMAND_NEW_PARAM = (
    "m.rs",
    "use std::process::Command;\n\n"
    "fn run(cmd: &str) {\n    Command::new(cmd).spawn().unwrap();\n}\n",
)
POSIX_SPAWN_PARAM = (
    "s.c",
    "#include <spawn.h>\nextern char **environ;\n"
    "void run(const char *path, char *const argv[]) {\n    pid_t pid;\n"
    "    posix_spawn(&pid, path, NULL, NULL, argv, environ);\n}\n",
)
# A parameter later in the argv of a builtin is not its whole command.
PROCESSBUILDER_ARG = (
    "V.java",
    "public class V {\n"
    "    public void run(String dir) throws Exception {\n"
    '        new ProcessBuilder("ls", dir).start();\n'
    "    }\n"
    "}\n",
)
# D25 (c): a same-file caller binds the parameter, and its constant context decides.
PROCESSBUILDER_BOUND = (
    "V.java",
    "public class V {\n"
    "    void run(String cmd) throws Exception {\n"
    "        new ProcessBuilder(cmd).start();\n"
    "    }\n"
    "    void main() throws Exception {\n"
    '        run("ls");\n'
    "    }\n"
    "}\n",
)


class Audit(NamedTuple):
    """One ``check_injection`` run over one staged file, in an audit of its own (D20)."""

    rows: list[dict[str, Any]]
    unknown_only: int  # ``ast_coverage.tallies.unknown_only_sinks``
    declines: list[str]  # the audit's ``ast_decline`` lines (§10.3)
    # ``(sink line, shell_sink, built_arg, builtin_program, param_bound)`` of each command flow
    facts: list[tuple[int, bool, bool, bool, bool]]


def _stage(tmp_path: Path, spec: tuple[str, str]) -> Path:
    """``spec`` (``(name, source)``) written alone under ``tmp_path``."""
    name, source = spec
    path = tmp_path / name
    path.write_text(source)
    return path


def _audit(tmp_path: Path, spec: tuple[str, str]) -> Audit:
    """``spec`` staged alone and scanned as the skill ships, in a copied context as the runner
    submits a skill (plan 3.4): ``_ast_heads``' one audit, read here before it is left."""
    return contextvars.copy_context().run(_audited, tmp_path, _stage(tmp_path, spec))


def _audited(root: Path, path: Path) -> Audit:
    scan = _ast_heads._audited(check_injection, root)
    tallies = context.current().coverage.snapshot(root)["tallies"]
    return Audit(scan.rows, tallies["unknown_only_sinks"], scan.declines, _facts(path))


def _facts(path: Path) -> list[tuple[int, bool, bool, bool, bool]]:
    """D25's per-flow facts of every command candidate of the file's model (a cache hit)."""
    model = owns(path)
    flows = model.analysis().candidates("command") if model is not None else ()
    return [
        (f.sink_line, f.shell_sink, f.built_arg, f.builtin_program, f.param_bound) for f in flows
    ]


def _rows(audit: Audit, category: str) -> list[tuple[int, str | None, list[str], str | None]]:
    """``(line, engine, origins, heuristic)`` of each ``category`` row, the engine as
    ``_ast_v1.engine_of`` names it (D13)."""
    return [_shape(r) for r in audit.rows if r["category"] == category]


def _shape(row: dict[str, Any]) -> tuple[int, str | None, list[str], str | None]:
    flow = row.get("validation", {}).get("flow", {})
    return row["line_start"], _ast_v1.engine_of(row), flow.get("origins", []), flow.get("heuristic")


# ── a bare parameter at a command sink D25 does not name ─────────────────────


@pytest.mark.parametrize(
    "spec",
    [RUNTIME_EXEC_PARAM, PASSTHRU_PARAM, PROC_OPEN_PARAM],
    ids=["runtime_exec", "passthru", "proc_open"],
)
def test_a_bare_parameter_outside_d25_is_tallied_not_reported(
    tmp_path: Path, spec: tuple[str, str]
) -> None:
    """``Runtime.getRuntime().exec(cmd)``, ``passthru($cmd)``, ``proc_open($cmd, …)`` with
    ``cmd`` a parameter no caller in the file binds: the flow's origins are UNKNOWN-only
    (``unknown(param)``), so D9 tallies it. D25 does not name it: the sink shells nothing by
    the existing tables, the argument is not built, and the key is no command builtin of the
    profile's table (Java's lists ``processbuilder`` only, PHP's none; A43 (1) adds no
    entry). The regex tier flagged the call by its name (the re-pointed tests)."""
    audit = _audit(tmp_path, spec)
    assert _rows(audit, COMMAND) == []
    assert audit.unknown_only == 1
    assert [fact[1:] for fact in audit.facts] == [(False, False, False, False)]


@pytest.mark.parametrize(
    ("spec", "line"),
    [(RUNTIME_EXEC_REQUEST, 3), (PASSTHRU_REQUEST, 2), (PROC_OPEN_REQUEST, 2)],
    ids=["runtime_exec", "passthru", "proc_open"],
)
def test_the_same_sink_reports_a_request_value(
    tmp_path: Path, spec: tuple[str, str], line: int
) -> None:
    """The contrast: the call IS a command sink; only the origin decides. A request value
    reaching it reports as data flow, with no heuristic."""
    assert _rows(_audit(tmp_path, spec), COMMAND) == [(line, "ast", [REQUEST], None)]


# ── a constant argument ─────────────────────────────────────────────────────


@pytest.mark.parametrize("spec", STATIC, ids=STATIC_IDS)
def test_a_constant_argument_is_nothing(tmp_path: Path, spec: tuple[str, str]) -> None:
    """``shell_exec("ls -la")``, ``Runtime.getRuntime().exec("ls -la")``: a literal carries no
    origin, so the sink argument is no candidate (D9: constant-only is nothing — not even a
    tally). The regex tier flagged any such call (audit #2)."""
    audit = _audit(tmp_path, spec)
    assert (_rows(audit, COMMAND), audit.unknown_only) == ([], 0)


@pytest.mark.parametrize("spec", STATIC, ids=STATIC_IDS)
def test_dangerous_function_does_not_report_a_constant_command(
    tmp_path: Path, spec: tuple[str, str]
) -> None:
    """Verified for A43 (2): CWE-676's ``dangerous_function`` does NOT report the presence of
    an execution sink — feature 0060 ceded ``Runtime.exec``, ``shell_exec`` and the rest to the
    injection skill — so with the AST tier's nothing above, a constant-argument command on a
    parsed file has neither a CWE-78 nor a CWE-676 row (SKILLS.md known gaps). The regex
    fallback still flags it on a file that does not parse."""
    _stage(tmp_path, spec)
    assert check_dangerous_function(str(tmp_path))["findings"] == []


# ── an argv element after a literal program ──────────────────────────────────


def test_a_request_value_in_a_later_argv_element_is_no_command(tmp_path: Path) -> None:
    """``new ProcessBuilder("tar", "-C" + request.getParameter("d"))``: the program position
    holds the literal ``"tar"``, and a later argv element reaches the command row only after a
    shell interpreter plus flag (L3, R-M), so the request value is an argument (CWE-88's shape),
    not a command; CWE-88's own specialisation leaves ``new ProcessBuilder(`` lines to CWE-78.
    So nothing is reported on the line (SKILLS.md known gaps); the regex tier gave CWE-78."""
    audit = _audit(tmp_path, PROCESSBUILDER_ARGV)
    assert [r["category"] for r in audit.rows if r["line_start"] == 4] == []
    assert audit.unknown_only == 0


# ── SSRF: the server-context gate's scope, a whole-file flow ─────────────────


def test_a_map_read_in_server_code_is_a_request_sink(tmp_path: Path) -> None:
    """``security.authenticatedUsers.get(req.cookies.token)`` (line 7) beside the real
    ``fetch(url)`` (line 10, through ``const url = req.body.imageUrl``): the glued key ``get``
    is a request sink, and §8.5's server-context gate holds it back only in a file that is not
    server code; this file imports ``express``, so a map read keyed by a request value reports
    as SSRF — an FP direction recorded in SKILLS.md. The regex tier's one-hop rule saw only
    line 10."""
    assert _rows(_audit(tmp_path, IMAGE_URL_UPLOAD), SSRF) == [
        (7, "ast", [REQUEST], None),
        (10, "ast", [REQUEST], None),
    ]


def test_a_flow_is_followed_through_the_whole_file(tmp_path: Path) -> None:
    """``const url = req.query.u`` 26 lines above ``fetch(url)``: the flow is the file's, not a
    25-line window around the sink, so the row reports at the sink line (28)."""
    assert _rows(_audit(tmp_path, BEYOND_WINDOW), SSRF) == [(28, "ast", [REQUEST], None)]


# ── SSRF: context words are not guards ──────────────────────────────────────


def test_context_words_are_not_a_guard(tmp_path: Path) -> None:
    """``validate_url(url)`` checks ``url``, not the sink's argument ``user_input``, and
    ``allowed_hosts = [...]`` is an assignment, not a test of it: neither is a guard of the
    flow (a guard is an ``if``/``try`` over the argument, L4), so the row reports with no
    guard. The regex tier suppressed it on the words alone."""
    audit = _audit(tmp_path, ALLOWLIST_WORDS)
    assert _rows(audit, SSRF) == [(5, "ast", [REQUEST], None)]
    assert audit.declines == []


def test_a_host_check_on_the_argument_declines_it(tmp_path: Path) -> None:
    """The contrast: a membership test of the argument against a host list (``host_allow``,
    L12) guards it, and the flow is declined and recorded, not reported."""
    audit = _audit(tmp_path, HOST_GUARD)
    assert _rows(audit, SSRF) == []
    assert [line.split(" rule=")[1].split()[0] for line in audit.declines] == ["guarded:host_allow"]


# ── A43 (1): D25's builtin half ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("spec", "line"),
    [(PROCESSBUILDER_PARAM, 3), (COMMAND_NEW_PARAM, 4), (POSIX_SPAWN_PARAM, 5)],
    ids=["java_processbuilder", "rust_command_new", "c_posix_spawn"],
)
def test_a_parameter_that_is_a_builtins_whole_command_reports(
    tmp_path: Path, spec: tuple[str, str], line: int
) -> None:
    """The parameter is the program position of a command builtin of the profile's own table
    (§6.3: Java ``processbuilder``, the Rust pair ``Command::new``, C ``posix_spawn`` at
    argument 1): D25 names it (``builtin_program``), and the row says so."""
    audit = _audit(tmp_path, spec)
    assert _rows(audit, COMMAND) == [(line, "ast", [PARAM], TOKEN)]
    assert audit.facts == [(line, False, False, True, False)]


def test_a_later_argv_element_of_a_builtin_is_not_its_whole_command(tmp_path: Path) -> None:
    """``new ProcessBuilder("ls", dir)``: the program is a literal, so the one candidate is
    constant-only (nothing), and ``dir`` reaches no command argument (no interpreter + flag)."""
    audit = _audit(tmp_path, PROCESSBUILDER_ARG)
    assert (_rows(audit, COMMAND), audit.unknown_only) == ([], 0)


def test_a_same_file_caller_still_supersedes_the_builtin_half(tmp_path: Path) -> None:
    """D25 (c) holds for the builtin half: ``run("ls")`` binds ``cmd`` in the file, so the
    parameter flow is superseded and the caller's constant context decides — nothing."""
    audit = _audit(tmp_path, PROCESSBUILDER_BOUND)
    assert _rows(audit, COMMAND) == []
    assert sorted(fact[4] for fact in audit.facts) == [False, True]
