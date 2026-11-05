"""The construct-precision rules cost O(1) per line (CWE-269/89/94/312).

Each rule entry point cuts its line at ``MAX_SCAN_CHARS`` before any regex
runs, so its cost is linear up to the cap and flat past it. Measured in a child
process with the 0101 lexical harness (round-robin min-of-N sweeps): a doubling
ratio < 2.6 up to the cap, <= 0.5 ms/KB at it, and a 512 KB line costing about
what a line at the cap costs.

The subjects are the reviewers' hostile shapes: repeated quotes and escapes,
unclosed `${` / `f"{`, `"select "` runs ahead of `.format(`, `styled(` runs
for the display-consumer veto, flag-free `run` runs, setter calls without a
quote. The CWE-94 view is built once per subject outside the timing, as a file
builds it once: what is timed is the per-line check.

Every subject is one the rule DECIDES not to report. An emitted row also gets
its snippet from the shared ``extract_snippet``, whose cost follows the line's
length whatever rule emits it; that is output, outside the per-line decision
this file measures.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.unit import test_0101_lexical_redos as lexgate
from tests.unit.test_0087_redos import INPUT_BYTES, PROC_TIMEOUT_SEC

AGENT_ROOT = Path(__file__).resolve().parents[2]


def _repeat(unit: str) -> Callable[[int], str]:
    return lambda n: (unit * (n // len(unit) + 1))[:n]


def _code_check(language: str) -> Callable[[str], object]:
    """CWE-94's per-line decision, with the subject's view built on first sight."""
    from cwe_agent.skills import injection_check as ic
    from shared.tools.code_view import CodeView

    views: dict[str, CodeView] = {}
    path = Path("/x/app")

    def call(subject: str) -> object:
        view = views.get(subject)
        if view is None:
            view = views[subject] = CodeView((subject,), language)
            view.line(1)
        return ic._check_code_injection(path, subject, 1, (subject,), [], view)

    return call


def _go_sql_check() -> Callable[[str], object]:
    """``_check_sql`` on a Go line, so the constant-Sprintf test runs too."""
    from cwe_agent.skills import injection_check as ic
    from shared.tools.code_view import CodeView

    views: dict[str, CodeView] = {}

    def call(subject: str) -> object:
        lines = ("func f() {", subject, "}")
        view = views.get(subject)
        if view is None:
            view = views[subject] = CodeView(lines, "go")
            view.line(1)
        return ic._check_sql(Path("/x/repo.go"), subject, 2, lines, [], view)

    return call


def _go_function_check() -> Callable[[str], object]:
    """``_check_sql`` on a constant Go ``Sprintf`` whose function holds 20 copies of
    the subject: the provenance walk reads each of them."""
    from cwe_agent.skills import injection_check as ic
    from shared.tools.code_view import CodeView

    views: dict[str, CodeView] = {}
    head = ("func f(db DB) {", '\tx := "a"', '\tq := fmt.Sprintf("SELECT %s FROM t", x)', "\tdb.Query(q)")

    def call(subject: str) -> object:
        view = views.get(subject)
        if view is None:
            view = views[subject] = CodeView((*head, *[subject] * 20, "}"), "go")
            view.line(1)
        return ic._check_sql(Path("/x/repo.go"), head[2], 3, view._lines, [], view)

    return call


def _helper_cases() -> dict[str, tuple[Callable[[str], object], Callable[[int], str]]]:
    from cwe_agent.skills import access_control_check as ac
    from cwe_agent.skills import info_exposure_check as ie
    from cwe_agent.skills import injection_check as ic

    def sql(subject: str) -> object:
        return ic._check_sql(Path("/x/q.py"), subject, 1, (subject,), [], None)

    def privilege(subject: str) -> object:
        return ac._check_privilege(Path("/x/run.sh"), subject, 1, [subject], [])

    def storage(subject: str) -> object:
        return ie._check_cleartext_storage(Path("/x/s.py"), subject, 1, [subject], subject, [], {})

    return {
        "sql_select_runs_before_format": (sql, _repeat('"select x" .format( ')),
        "sql_fstring_verbs": (sql, _repeat('f"SELECT {x} ')),
        "sql_percent_verbs": (sql, _repeat("\"select '%s' % ")),
        "sql_escapes": (sql, _repeat('"\\')),
        "sql_fstring_unclosed_verbs": (sql, lambda n: 'f"' + _repeat("SELECT ")(n)),
        "sql_percent_unclosed_verbs": (sql, lambda n: '"' + _repeat("select ")(n)),
        "sql_select_without_from": (sql, lambda n: 'f"{x}' + _repeat(" SELECT")(n)),
        "sql_format_receiver_chain": (sql, lambda n: '"select " ' + _repeat("(x).f().format( ")(n)),
        "sql_styled_consumer": (sql, lambda n: 'f"SELECT {x}" ' + _repeat("styled(")(n)),
        "sql_go_sprintf_args": (_go_sql_check(), lambda n: 'q := fmt.Sprintf("UPDATE t SET %s", ' + _repeat("a, ")(n)),
        "sql_go_hostile_function": (_go_function_check(), lambda n: "\t_ = " + _repeat("x+")(n)),
        "code_strings_python": (_code_check("python"), _repeat('"eval(" ')),
        "code_template_text_js": (_code_check("javascript"), _repeat("`eval(x)` ")),
        "code_unclosed_fields_python": (_code_check("python"), _repeat('f"{x(')),
        "privilege_verbs_without_flag": (privilege, _repeat("run -- ")),
        "privilege_flags_without_verb": (privilege, _repeat("--privileged ")),
        "storage_setters_without_quote": (storage, _repeat("set(password ")),
        "storage_placeholder_values": (storage, _repeat('password = "**" ')),
    }


HELPER_NAMES: tuple[str, ...] = tuple(sorted(_helper_cases()))


def _child(name: str, out_path: str) -> int:
    call, build = _helper_cases()[name]
    subjects = {f"n={n}": build(n) for n in lexgate.DOUBLING_SIZES}
    subjects["past_cap"] = build(INPUT_BYTES)
    with open(out_path, "w", encoding="utf-8") as handle:
        emit = lexgate._emit_to(handle)
        emit({"status": "start", "input": "sweep"})
        for key, ms in lexgate._time_sweep(call, subjects).items():
            emit({"status": "ok", "input": key, "ms": ms})
    return 0


def _run(name: str) -> dict[str, float | None]:
    fd, out = tempfile.mkstemp(prefix=f"construct_linear_{name}_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run([sys.executable, "-m", "tests.unit.test_construct_rule_linear", "--child", name, out],
                           cwd=AGENT_ROOT, capture_output=True, text=True,
                           timeout=PROC_TIMEOUT_SEC * 2, check=False)
        except subprocess.TimeoutExpired:
            pass
        results: dict[str, float | None] = {}
        with open(out, encoding="utf-8") as handle:
            for raw in filter(None, map(str.strip, handle)):
                lexgate._fold(results, json.loads(raw))
    finally:
        os.unlink(out)
    assert results, f"linearity child for {name!r} produced no records"
    return results


@pytest.mark.parametrize("helper", HELPER_NAMES)
def test_rule_is_linear_to_the_cap_and_bounded_past_it(helper: str) -> None:
    problems = lexgate._helper_verdict(helper, _run(helper))
    assert not problems, "\n".join(problems)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest")
