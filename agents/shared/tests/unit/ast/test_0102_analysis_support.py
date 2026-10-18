"""Feature 0102 Phase 2: the shared harness ``_analysis.py``, on what exists today.

Every Phase-2 RED module locates its nodes, builds its models and reads its fixtures through
``_analysis``. A broken locator would fail all of them for the wrong reason, so the helpers
that need no Phase-2 module are pinned here, against the real worker pool: a model per v1
language code, the ``ast_v1`` fixtures by stem, the locators, the ``decide`` doubles, the
pool spy and the program and JSON helpers. Nothing here imports a Phase-2 module, so this
module is green before Phase 2 and stays green through it.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from shared.ast import FileModel
from shared.ast.kinds import Kind
from shared.ast.pool import get_pool
from shared.ast.profile import profile_for
from tests.unit.ast import _support
from tests.unit.ast._analysis import (
    FAMILIES,
    LANG_SUFFIX,
    LANGS,
    Judgement,
    RecordingContext,
    StubRule,
    call_at,
    call_head,
    dumped,
    fixture_model,
    fixture_path,
    fixture_text,
    if_test,
    language_of,
    model_of,
    nested,
    newline_row,
    node_at,
    nodes_of,
    numbered,
    program,
    source_of,
    spy_pool,
    stub_guard,
    stub_rule,
    subject,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# One program per language code: an IF whose TEST is the call ``ok(p)``, guarding one sink
# call, and that sink's head as ``call_at`` takes it (Java's receiver ships under OBJECT,
# yet its head is still ``Files.readString``).
_PROGRAMS: dict[str, tuple[str, str]] = {
    "js": ("if (ok(p)) {\n  fs.readFile(p);\n}\n", "fs.readFile"),
    "ts": ("if (ok(p)) {\n  fs.readFile(p);\n}\n", "fs.readFile"),
    "py": ("if ok(p):\n    open(p)\n", "open"),
    "go": ("package main\n\nfunc f(p string) {\n\tif ok(p) {\n\t\tos.Open(p)\n\t}\n}\n", "os.Open"),
    "java": (
        "class A {\n  void f(String p) {\n    if (ok(p)) {\n      Files.readString(p);\n    }\n  }\n}\n",
        "Files.readString",
    ),
    "rs": ("fn f(p: &str) {\n    if ok(p) {\n        fs::read_to_string(p);\n    }\n}\n", "fs::read_to_string"),
    "php": ("<?php\nif (ok($p)) {\n    file_get_contents($p);\n}\n", "file_get_contents"),
    "c": ('void f(char *p) {\n    if (ok(p)) {\n        fopen(p, "r");\n    }\n}\n', "fopen"),
    "cpp": ('void f(char *p) {\n    if (ok(p)) {\n        fopen(p, "r");\n    }\n}\n', "fopen"),
}

# Three fixtures by stem, three suffixes: a JS positive, a Go positive (O1), a Python one.
_FIXTURES = ("cwe_22_1", "cwe_22_go_3", "cwe_78_18")


# ── models by language code ──────────────────────────────────────────────────


def test_langs_are_the_nine_v1_profiles() -> None:
    assert LANGS == ("js", "ts", "py", "go", "java", "rs", "php", "c", "cpp")
    assert tuple(_PROGRAMS) == LANGS
    assert sorted(map(language_of, LANGS)) == sorted(_support.LANGUAGES)


def _assert_clean(m: FileModel) -> None:
    """``m`` was parsed without an ERROR node."""
    assert m.error_nodes == 0


@pytest.mark.parametrize("lang", LANGS)
def test_model_of_parses_each_language(lang: str) -> None:
    source, _ = _PROGRAMS[lang]

    m = model_of(source, lang)

    assert isinstance(m, FileModel)
    assert m.language == language_of(lang) == profile_for(f"x{LANG_SUFFIX[lang]}").language
    _assert_clean(m)
    assert "\n".join(m.nl_lines) == source, "the model is built from the source verbatim"


def _assert_found_again(m: FileModel, call: int, source: str, head: str) -> None:
    """``call`` reads back as ``head``, and ``call_at`` finds it again by its line in
    ``source``."""
    assert call_head(m, call) == head
    assert call_at(m, head, line=newline_row(source, head)) == call


@pytest.mark.parametrize("lang", LANGS)
def test_call_at_finds_the_sink_by_its_head(lang: str) -> None:
    source, head = _PROGRAMS[lang]
    m = program(lang, source)

    call = call_at(m, head)

    assert m.kind(call) is Kind.CALL
    assert m.line(call) == newline_row(source, head)
    _assert_found_again(m, call, source, head)


@pytest.mark.parametrize("lang", LANGS)
def test_if_test_is_the_guard_condition(lang: str) -> None:
    m = program(lang, _PROGRAMS[lang][0])

    test = if_test(m)

    assert source_of(m, test) == ("ok($p)" if lang == "php" else "ok(p)")
    assert m.kind(test) is Kind.CALL


def test_a_missing_call_names_the_calls_the_model_holds() -> None:
    m = program("js", _PROGRAMS["js"][0])

    with pytest.raises(AssertionError, match=r"fs\.readFile"):
        call_at(m, "fs.writeFile")
    with pytest.raises(AssertionError, match=r"#1"):
        call_at(m, "fs.readFile", nth=1)


def test_source_of_slices_bytes_after_multibyte_text() -> None:
    # A two-byte, a three-byte and a D21 separator before the sink: spans are byte offsets
    # into the UTF-8 encoding, and lines are counted by "\n" only.
    source = 'const s = "é€ ";\nfs.readFile(p);\n'
    m = model_of(source, "js")

    call = call_at(m, "fs.readFile", line=2)

    assert source_of(m, call) == "fs.readFile(p)"


def _assert_dedented(m: FileModel) -> None:
    """``m`` is ``a(p);`` then ``b(p);``, the common indent and the leading newline dropped:
    line 1 is the first line written."""
    assert "\n".join(m.nl_lines) == "a(p);\nb(p);\n"
    assert m.line(call_at(m, "b")) == 2


def test_program_is_dedented_and_shared() -> None:
    """``program`` drops the common indent and a leading newline (line 1 is the first line
    written) and builds each program once; ``model_of`` parses afresh, verbatim."""
    indented = "\n    a(p);\n    b(p);\n"

    m = program("js", indented)

    _assert_dedented(m)
    assert program("js", indented) is m
    assert model_of("a(p);\n", "js") is not model_of("a(p);\n", "js")


def test_subject_reads_a_fixture_stem_or_an_inline_program() -> None:
    inline = ("py", "open(p)\n")

    assert subject("cwe_22_1") is fixture_model("cwe_22_1")
    assert subject(inline) is program(*inline)


def test_nodes_of_filters_by_text_and_line() -> None:
    m = model_of("a(p);\nb(p, q);\n", "js")

    assert [m.line(i) for i in nodes_of(m, Kind.NAME, text="p")] == [1, 2]
    assert m.line(node_at(m, Kind.NAME, text="p", line=2)) == 2
    assert nodes_of(m, Kind.NAME, line=2) == [node_at(m, Kind.NAME, text=t, line=2) for t in "bpq"]


# ── ast_v1 fixtures by stem ──────────────────────────────────────────────────


@pytest.mark.parametrize("stem", _FIXTURES)
def test_fixture_path_resolves_the_suffix(stem: str) -> None:
    path = fixture_path(stem)

    assert path.parent == _support.AST_V1
    assert path.stem == stem
    assert fixture_path(path.name) == path


@pytest.mark.parametrize("stem", _FIXTURES)
def test_fixture_text_is_the_file(stem: str) -> None:
    assert fixture_text(stem) == fixture_path(stem).read_text(encoding="utf-8")


@pytest.mark.parametrize("stem", _FIXTURES)
def test_fixture_model_is_the_shared_model_of_the_fixture(stem: str) -> None:
    path = fixture_path(stem)

    m = fixture_model(stem)

    assert m is fixture_model(path.name) is _support.fixture_model(path.name)[0]
    assert m.language == profile_for(path).language
    _assert_clean(m)
    assert "\n".join(m.nl_lines) == fixture_text(stem)


def test_an_unknown_fixture_is_a_key_error() -> None:
    with pytest.raises(KeyError):
        fixture_path("cwe_22_0")


def test_a_fixture_without_a_profile_still_reads() -> None:
    assert profile_for(fixture_path("cwe_22_18")) is None
    assert fixture_text("cwe_22_18")


# ── doubles, spy and plain helpers ───────────────────────────────────────────


def test_stub_rule_has_the_family_rule_fields() -> None:
    assert [f.name for f in dataclasses.fields(StubRule)] == [
        "family", "check_id", "category", "title", "severity", "recommendation", "cwe_id",
        "gate",
    ]
    assert [(r.family, r.category, r.cwe_id, r.gate) for r in map(stub_rule, FAMILIES)] == [
        ("path", "CWE-22", "22", None),
        ("request", "CWE-918", "918", None),
        ("command", "CWE-78", "78", None),
    ]


def test_recording_context_keeps_calls_in_order() -> None:
    """A30 (1): ``decline(path, flow, rule, label)``, the file first, as ``decide`` calls it."""
    ctx = RecordingContext()
    first, second = Path("src/a.js"), Path("src/b.js")

    ctx.tally("unknown_only_sinks")
    ctx.decline(first, "flow", "rule", "guarded:validate")
    ctx.tally("unknown_only_sinks")
    ctx.decline(second, "flow", "rule", "sanitized:path_normalize")

    assert ctx.tallies == {"unknown_only_sinks": 2}
    assert ctx.labels == ["guarded:validate", "sanitized:path_normalize"]
    assert [(d.path, d.flow, d.rule) for d in ctx.declines] == [
        (first, "flow", "rule"), (second, "flow", "rule"),
    ]


def test_judgement_reports_the_report_lines() -> None:
    j = Judgement(((3, "report"), (5, "decline"), (9, "report"), (12, "none")), (), {})

    assert j.reported == (3, 9)


def test_spy_pool_counts_requests_and_can_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = spy_pool(monkeypatch)
    assert isinstance(model_of("f(a);\n", "js"), FileModel)
    spy.answer = "too_deep"

    assert get_pool().parse("python", b"f(a)\n") == "too_deep"
    assert spy.languages() == ["javascript", "python"]


def test_program_helpers_are_literal() -> None:
    assert numbered("if (c{i}) { return; }\n", 2) == "if (c0) { return; }\nif (c1) { return; }\n"
    assert numbered("x", 0) == ""
    assert nested("if (c) {\n", "}\n", 2, "f(p);\n") == "if (c) {\nif (c) {\nf(p);\n}\n}\n"


def test_dumped_is_order_independent() -> None:
    assert dumped(stub_guard("validate", "allowlist")) == '{"roles": ["allowlist", "validate"]}'
    assert dumped(stub_guard("allowlist", "validate")) == dumped(stub_guard("validate", "allowlist"))
    assert dumped({"b": frozenset({2, 1}), "a": None}) == '{"a": null, "b": [1, 2]}'
