r"""Feature 0102, plan task 1.4: egress, the span/window half (LLD §4, §6.2, §11 T5/T14, D21).

Every span is a byte offset into ONE buffer: the parent's decoded text
(``read_file_safe``, ``errors="replace"``) encoded once as UTF-8 — never the raw file
bytes (LLD §4, T5). A node's line is newline-only: tree-sitter counts ``\n`` while
``str.splitlines`` also splits on ``\r``, ``\x0b``, ``\x0c``, ``\x1c``-``\x1e``,
``\x85``, U+2028 and U+2029, and an AST row takes its window from ``text.split("\n")``
(D21, T14). So for every node of every model:

* its span lies in the buffer, on character boundaries, and ``size`` is the buffer's
  length;
* its line is one plus the ``\n`` count before its start;
* its window line (``nl_lines[line - 1]``) holds the first line of its span at the same
  byte column;
* a NAME's text is byte-exactly its span (no normalisation, no desync), PHP's ``$``
  sigil the one difference (LLD §6.3).

Hostile inputs: invalid UTF-8 (each replaced by U+FFFD, which re-encodes LONGER than the
raw bytes, so a raw-byte slice misses the sink), a BOM, bidi controls, astral and
zero-width characters, a NUL, every non-``\n`` separator of D21 inside a literal, CRLF
and CR-only line endings — and a parse-error file. Files are written as bytes and read
back through ``read_file_safe``, so the real decode is the one under test. That decode
is ``Path.read_text``, which translates ``\r\n`` and a lone ``\r`` to ``\n`` (universal
newlines), so a ``\r`` reaches the model as ``\n``. An expected line is therefore read
from the parent's text, never from the raw bytes, and the D21 separators that reach
the model are the seven others.

The finding half — M1/M4 placeholders in hops, declines and ``validation.flow`` (task
2.6) and ``test_control_chars_in_path`` (task 2.4) — follows the span half, below. Its four
``validation.flow`` cases read ``shared.ast.consume`` (``flow_to_finding``) and are Phase 3's
(plan 3.1, A30 (4)): they stay RED through the Phase-2 exit.

RED until ``shared.ast`` exists (``ModuleNotFoundError`` at collection).
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from shared.ast import FileModel, owns
from shared.ast._validate import IDENTIFIER, admissible
from shared.ast.kinds import Kind
from tests.unit.ast._analysis import (
    LANG_SUFFIX,
    call_line,
    consume_mod,
    coverage_snapshot,
    decided,
    dumped,
    flow_at_call,
    fresh_context,
    in_audit,
    judge,
    model_of,
    newline_row,
    safe_path,
    stub_rule,
    unprintable,
)
from tests.unit.ast._audit import decline_record, rendered
from tests.unit.ast._support import (
    STRUCTURE_FIXTURES,
    failing,
    fixture_model,
    model_of_path,
    only_call,
    write,
)

pytestmark = pytest.mark.usefixtures("real_pool")

_SINK = {".js": "fs.readFile(p)", ".py": "open(p)"}
_JS = b"fs.readFile(p);\n"
_PY = b"open(p)\n"
# D21: every character str.splitlines() breaks a line on, besides "\n" \u2014 less "\r",
# which read_file_safe's universal-newline decode turns into "\n" before any model.
_SEPARATORS = "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"


def _span_bytes(m: FileModel, i: int, enc: bytes) -> bytes:
    sb, eb = m.span(i)
    return enc[sb:eb]


def _span_head(m: FileModel, i: int, enc: bytes) -> bytes:
    r"""The first ``\n`` line of node ``i``'s span."""
    return _span_bytes(m, i, enc).split(b"\n", 1)[0]


def _window(m: FileModel, i: int) -> bytes:
    r"""What ``i``'s window line holds from ``i``'s byte column, as far as its line runs.

    The window line is ``nl_lines[line(i) - 1]``; its offset in the buffer is the encoded
    length of the lines before it, each with its ``\n``.
    """
    line = m.line(i)
    start = len("\n".join(m.nl_lines[: line - 1]).encode("utf-8")) + (line > 1)
    return m.nl_lines[line - 1].encode("utf-8")[m.span(i)[0] - start:]


def _window_misses_span(m: FileModel, i: int, enc: bytes) -> bool:
    return not _window(m, i).startswith(_span_head(m, i, enc))


def _off_buffer(m: FileModel, i: int, enc: bytes) -> bool:
    sb, eb = m.span(i)
    return not 0 <= sb <= eb <= len(enc)


def _splits_a_character(m: FileModel, i: int, enc: bytes) -> bool:
    try:
        _span_bytes(m, i, enc).decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _line_not_newline_counted(m: FileModel, i: int, enc: bytes) -> bool:
    return m.line(i) != enc[: m.span(i)[0]].count(b"\n") + 1


def _name_text_is_not_its_span(m: FileModel, i: int, enc: bytes) -> bool:
    """A NAME's text is its span byte for byte; the one allowed difference is PHP's
    variable sigil (LLD §6.3: ``variable_name`` ships its text without the ``$``)."""
    text = m.ident(i)
    return text is not None and _span_bytes(m, i, enc) not in _spellings(text)


def _spellings(text: str) -> tuple[bytes, bytes]:
    raw = text.encode("utf-8")
    return raw, b"$" + raw


def _disagreements(m: FileModel, text: str) -> dict[str, object]:
    """Every span/line/window invariant over every node; see the module docstring."""
    enc = text.encode("utf-8")
    nodes = range(m.node_count)
    return {
        "size is the buffer length": m.size == len(enc),
        "nl_lines is text.split": list(m.nl_lines) == text.split("\n"),
        "span off the buffer": failing(nodes, lambda i: _off_buffer(m, i, enc)),
        "span splits a character": failing(nodes, lambda i: _splits_a_character(m, i, enc)),
        "line not newline-counted": failing(nodes, lambda i: _line_not_newline_counted(m, i, enc)),
        "window misses the span": failing(nodes, lambda i: _window_misses_span(m, i, enc)),
        "NAME text is not its span": failing(
            m.nodes(Kind.NAME), lambda i: _name_text_is_not_its_span(m, i, enc)),
    }


_AGREE = {
    "size is the buffer length": True, "nl_lines is text.split": True,
    "span off the buffer": [], "span splits a character": [], "line not newline-counted": [],
    "window misses the span": [], "NAME text is not its span": [],
}


# ── the plan's test ────────────────────────────────────────────────────────────


def test_invalid_utf8_window_matches_span(tmp_path: Path) -> None:
    r"""``b"\xff"`` in a literal before the sink: the parent's text holds U+FFFD (three
    bytes), so the sink's span slices ``fs.readFile(p)`` out of ``text.encode()`` — and
    the same offsets into the raw file bytes would not."""
    raw = b'const s = "\xff";\n' + _JS
    m, text = model_of_path(write(tmp_path / "bad.js", raw))
    sink = only_call(m)
    sb, eb = m.span(sink)
    observed = {
        "span": text.encode("utf-8")[sb:eb].decode("utf-8"),
        "raw bytes at the span": raw[sb:eb] == b"fs.readFile(p)",
        "line": m.line(sink),
    }
    assert observed == {"span": "fs.readFile(p)", "raw bytes at the span": False, "line": 2}


# ── one hostile prefix at a time ───────────────────────────────────────────────

_HOSTILE = [
    pytest.param("a.js", b'const s = "\xc3";\n' + _JS, id="invalid-truncated"),
    pytest.param("a.js", b'const s = "\xc0\xaf";\n' + _JS, id="invalid-overlong"),
    pytest.param("a.js", b'const s = "\xed\xa0\x80";\n' + _JS, id="invalid-surrogate"),
    pytest.param("a.js", b'const s = "\xf4\x90\x80\x80";\n' + _JS, id="invalid-beyond-unicode"),
    pytest.param("a.py", b's = "\xff"\n' + _PY, id="invalid-python"),
    pytest.param("a.js", "\ufeffconst s = 'a';\n".encode() + _JS, id="bom"),
    pytest.param("a.py", "\ufeffs = 'a'\n".encode() + _PY, id="bom-python"),
    pytest.param("a.js", 'const s = "\u202e\u2066x\u2069";\n'.encode() + _JS, id="bidi-literal"),
    pytest.param("a.js", "/* \u202e } \u2066 */\n".encode() + _JS, id="bidi-comment"),
    pytest.param("a.js", 'const s = "\U0001f600";\n'.encode() + _JS, id="astral"),
    pytest.param("a.js", 'const s = "a\u200bb";\n'.encode() + _JS, id="zero-width"),
    pytest.param("a.js", b'const s = "a\x00b";\n' + _JS, id="nul"),
    pytest.param("a.js", b'const s = "a";\r\nfs.readFile(p);\r\n', id="crlf"),
    pytest.param("a.js", b'const s = "a";\rfs.readFile(p);\r', id="cr-only"),
]


@pytest.mark.parametrize(("name", "data"), _HOSTILE)
def test_sink_span_and_window_survive_hostile_text(tmp_path: Path, name: str, data: bytes) -> None:
    m, text = model_of_path(write(tmp_path / name, data))
    sink = only_call(m)
    enc = text.encode("utf-8")
    sink_text = _SINK[Path(name).suffix]
    observed = {
        "span": _span_bytes(m, sink, enc).decode("utf-8"),
        "line": m.line(sink),
        "window": _window(m, sink)[: len(_span_head(m, sink, enc))].decode("utf-8"),
    }
    assert observed == {"span": sink_text, "line": newline_row(text, sink_text), "window": sink_text}


def _splitlines_row(text: str, needle: str) -> int:
    """The 1-based ``str.splitlines`` row holding ``needle`` (the numbering D21 rejects)."""
    return next(row for row, part in enumerate(text.splitlines(), 1) if needle in part)


_SEPARATOR_FILES = {
    "a.js": ("const s = `a{}b`;\n", _JS),   # a template literal admits every separator raw
    "a.py": ('s = "a{}b"\n', _PY),
}


@pytest.mark.parametrize("separator", _SEPARATORS, ids=lambda c: f"U+{ord(c):04X}")
@pytest.mark.parametrize("name", sorted(_SEPARATOR_FILES))
def test_a_separator_in_a_literal_moves_no_line(tmp_path: Path, name: str, separator: str) -> None:
    """D21: the sink is on line 2 by ``\\n`` and its window holds it; ``splitlines``
    would put it on line 3, which is the desync this numbering exists to prevent."""
    prefix, sink_line = _SEPARATOR_FILES[name]
    m, text = model_of_path(write(tmp_path / name, prefix.format(separator).encode() + sink_line))
    sink = only_call(m)
    sink_text = _SINK[Path(name).suffix]
    observed = {
        "line": m.line(sink),
        "window": m.nl_lines[m.line(sink) - 1],
        "splitlines row": _splitlines_row(text, sink_text),
    }
    assert observed == {"line": 2, "window": sink_line.decode().rstrip("\n"), "splitlines row": 3}


# ── every node ─────────────────────────────────────────────────────────────────

_COMBINED = (
    "\ufeff// \u202e } \u2066 bidi in a comment \u2069\n".encode()
    + b'const a = "\xff\xc0\xaf\x00";\n'
    + "const b = `\u2028\u2029\x0b\x0c\x1c\x1d\x1e\x85\r\U0001f600\u200b`;\r\n".encode()
    + b"function handler(req) {\n"
    + b"  const p = req.query.f;\n"
    + b"  fs.readFile(\n    p,\n    () => {});\n"
    + b"}\n"
)


def test_every_node_agrees_on_a_hostile_file(tmp_path: Path) -> None:
    """Every hazard above in one file, and its one CALL on its ``\\n`` row."""
    m, text = model_of_path(write(tmp_path / "hostile.js", _COMBINED))
    observed = (_disagreements(m, text), [m.line(c) for c in m.calls()])
    assert observed == (_AGREE, [newline_row(text, "fs.readFile(")])


@pytest.mark.parametrize("name", STRUCTURE_FIXTURES)
def test_every_node_agrees_on_the_corpus(name: str) -> None:
    """One fixture per v1 profile, a parse-error file, a multi-line call, U+2028."""
    m, text = fixture_model(name)
    assert _disagreements(m, text) == _AGREE


def test_u2028_fixture_numbers_its_sink_by_newlines_only() -> None:
    """``cwe_22_20.js``: two raw U+2028 inside a string on line 3; the sink is on line 5
    by ``\\n`` and on line 7 by ``splitlines`` — the model's line and window are the
    ``\\n`` ones (D21)."""
    m, text = fixture_model("cwe_22_20.js")
    sink = only_call(m)
    observed = {
        "line": m.line(sink),
        "window": m.nl_lines[m.line(sink) - 1].strip(),
        "splitlines row": _splitlines_row(text, "fs.readFile("),
    }
    assert observed == {"line": 5, "window": "fs.readFile(p, () => {});", "splitlines row": 7}


def test_a_multiline_call_is_windowed_at_its_first_line() -> None:
    """``cwe_22_16.js``: a four-line ``fs.readFile(`` call; its line is the first, its
    span ends on the fourth, and its window starts with the call's first line."""
    m, text = fixture_model("cwe_22_16.js")
    enc = text.encode("utf-8")
    (call,) = [c for c in m.calls() if m.chain_words(m.callee(c)) == ("fs", "readfile")]
    observed = {
        "first line": m.line(call),
        "last line": enc[: m.span(call)[1]].count(b"\n") + 1,
        "window": _window(m, call).decode("utf-8"),
    }
    assert observed == {"first line": 3, "last line": 6, "window": "fs.readFile("}


# ── attacker-named files: one renderer for every emitted path (task 2.4, §10.3, T15) ──

# A directory and a file an attacker names: an OSC title sequence, a colour escape, a bell
# and a newline that would forge a second ``thinking`` line.
_CRAFTED = ("dir\x1b]0;owned\x07", "evil\x1b[31mred\x07bell\nline.js")
_CONTROL = "\x1b\x07\n"
# A parse error: ``owns`` declines the file as ``parse_error`` and coverage lists it.
_BROKEN_JS = "fs.readFile(\n"


def _safe_path_shown(root: Path, path: Path) -> list[str]:
    return [safe_path(root, path)]


def _decline_shown(root: Path, path: Path) -> list[str]:
    """One decline of the crafted file (``_audit.decline_record``), rendered by the audit's
    ledger (``_audit.rendered``; §10.3: ``file=<safe_path>``)."""
    record = decline_record(path, line=1, origins=())
    ledger = fresh_context(root).ledger
    ledger.add(record)
    return rendered(ledger, root)


def _listed_after_fallback(root: Path, path: Path) -> list[str]:
    assert owns(path) is None, "the crafted file must fall back (parse_error)"
    return list(coverage_snapshot(root)["files"]["fallback_paths"])


def _fallback_shown(root: Path, path: Path) -> list[str]:
    """``files.fallback_paths``, the human-facing list (§10.2), after the crafted file fell
    back in one audit. ``fallback_keys`` is lossless by design (D24) and is not shown."""
    return in_audit(root, _listed_after_fallback, root, path)


_PATH_SURFACES: dict[str, Callable[[Path, Path], list[str]]] = {
    "safe_path": _safe_path_shown,
    "decline render": _decline_shown,
    "fallback_paths": _fallback_shown,
}


def _characters(shown: Sequence[str], bad: Callable[[str], bool]) -> list[str]:
    """The distinct characters of ``shown`` for which ``bad`` holds."""
    return sorted({c for line in shown for c in line if bad(c)})


@pytest.mark.parametrize("surface", _PATH_SURFACES)
def test_control_chars_in_path(tmp_path: Path, surface: str) -> None:
    """T15: a file named with ``\\x1b``, ``\\x07`` and ``\\n`` reaches ``safe_path``, a
    rendered decline and the coverage display only as printable ASCII, root-relative, with
    its visible name kept (§10.3: printable ASCII only, others ``?``)."""
    root = tmp_path / "repo"
    path = write(root.joinpath(*_CRAFTED), _BROKEN_JS)
    shown = _PATH_SURFACES[surface](root, path)
    observed = {
        "name shown": any("line.js" in line for line in shown),
        "control characters": _characters(shown, _CONTROL.__contains__),
        "outside printable ASCII": sorted(set(unprintable("".join(shown)))),
        "absolute": any(str(root) in line for line in shown),
    }
    assert observed == {
        "name shown": True,
        "control characters": [],
        "outside printable ASCII": [],
        "absolute": False,
    }


# ── the finding half: M1/M4 text leaves only as a placeholder (2.6, invariant 4) ──

# Two credential-shaped literals the worker ADMITS (§6.2): an identifier-shaped M1 subscript
# key and an M4 command flag (at most 17 characters by the flag shape), both on one taint
# flow into a shell behind an interpreter and ``-c`` (R-M).
_KEY_CREDENTIAL = "AKIAIDENTIFIERSHAPED"
_FLAG_CREDENTIAL = "-AKIAFLAGSHAPED1"
# A leak, case-folded: ``glue``/``words`` lower-case an identifier, so a value may leave as
# ``akiaidentifiershaped`` as well as verbatim.
_LEAK_MARKS = ("akiaidentifiershaped", "akiaflagshaped1")


class _CredentialFlow(NamedTuple):
    template: str  # the program; {key}, {flag} and the {guard} slot before the sink
    guard: str  # a covering guard (allowlist): the flow declines
    sink: str  # the sink's call head


_CREDENTIAL_FLOWS = {
    "js": _CredentialFlow(
        "function handler(req, res) {{\n"
        "  const config = req.body;\n"
        '  const cmd = config["{key}"];\n'
        '{guard}  spawn("sh", ["{flag}", "-c", cmd]);\n'
        "}}\n",
        "  if (!ALLOWED.includes(cmd)) return;\n",
        "spawn",
    ),
    "py": _CredentialFlow(
        "def handler(request):\n"
        "    config = request.form\n"
        '    cmd = config["{key}"]\n'
        '{guard}    subprocess.run(["sh", "{flag}", "-c", cmd])\n',
        "    if cmd not in ALLOWED:\n        return\n",
        "subprocess.run",
    ),
}
_CREDENTIAL_LANGS = sorted(_CREDENTIAL_FLOWS)


@functools.cache
def _credential_model(lang: str, guarded: bool) -> FileModel:
    case = _CREDENTIAL_FLOWS[lang]
    guard = case.guard if guarded else ""
    source = case.template.format(key=_KEY_CREDENTIAL, flag=_FLAG_CREDENTIAL, guard=guard)
    return model_of(source, lang)


def _sink_line(lang: str, guarded: bool) -> int:
    return call_line(_credential_model(lang, guarded), _CREDENTIAL_FLOWS[lang].sink)


def _credential_flow(lang: str, guarded: bool) -> Any:
    """The ``command`` candidate at the credential program's sink."""
    return flow_at_call(_credential_model(lang, guarded), "command", _CREDENTIAL_FLOWS[lang].sink)


def _hop_name(hop: Any) -> str:
    """§8.6, A28 (4): a hop is the NamedTuple ``Hop(line, kind, name)``; its ``name``."""
    return hop.name


def _validation_flow(lang: str, root: Path) -> dict[str, Any]:
    """``validation.flow`` (§10.1) of the finding the reported flow becomes (plan 3.1)."""
    finding = consume_mod().flow_to_finding(
        _credential_flow(lang, False),
        stub_rule("command"),
        file_path=root / f"handler{LANG_SUFFIX[lang]}",
        nl_lines=_credential_model(lang, False).nl_lines,
    )
    return finding["validation"]["flow"]


def _flow_emitted(lang: str, _root: Path) -> list[str]:
    return [dumped(_credential_flow(lang, False))]


def _hops_emitted(lang: str, _root: Path) -> list[str]:
    return [_hop_name(hop) for hop in _credential_flow(lang, False).hops]


def _decline_emitted(lang: str, root: Path) -> list[str]:
    """The guarded twin, decided against a real ``AuditContext`` on the consumer's file
    (A30 (1): ``decide`` takes the ``path`` it hands to ``ctx.decline``), then its ledger
    rendered."""
    ctx = fresh_context(root)
    path = root / f"handler{LANG_SUFFIX[lang]}"
    outcome, _ = decided(_credential_flow(lang, True), "command", ctx, path=path)
    assert outcome == "decline"
    return rendered(ctx.ledger, root)


def _validation_emitted(lang: str, root: Path) -> list[str]:
    return [dumped(_validation_flow(lang, root))]


_EMITTED: dict[str, Callable[[str, Path], list[str]]] = {
    "flow": _flow_emitted,
    "hop names": _hops_emitted,
    "decline": _decline_emitted,
    "validation.flow": _validation_emitted,
}


def _leaks(emitted: Sequence[str]) -> list[str]:
    """The credential marks any emitted text carries, case-folded."""
    return sorted({mark for text in emitted for mark in _LEAK_MARKS if mark in text.lower()})


@pytest.mark.parametrize("lang", _CREDENTIAL_LANGS)
def test_credentials_cross_the_worker_boundary(lang: str) -> None:
    """The premise of the placeholder tests: both values ARE in the model (§6.2 admits the
    M1 key and the M4 flag as LITERAL text), so only emission keeps them out (invariant 4)."""
    model = _credential_model(lang, False)
    credentials = {_KEY_CREDENTIAL, _FLAG_CREDENTIAL}
    texts = {model.ident(i) for i in model.nodes(Kind.LITERAL)}
    assert sorted(texts & credentials) == sorted(credentials)


@pytest.mark.parametrize("lang", _CREDENTIAL_LANGS)
def test_credential_programs_report_and_decline(lang: str) -> None:
    """The flows the egress tests read are real: the plain program reports at its sink, the
    guarded twin declines there."""
    observed = {guarded: set(judge(_credential_model(lang, guarded), "command").outcomes)
                for guarded in (False, True)}
    assert observed == {
        False: {(_sink_line(lang, False), "report")},
        True: {(_sink_line(lang, True), "decline")},
    }


@pytest.mark.parametrize("surface", _EMITTED)
@pytest.mark.parametrize("lang", _CREDENTIAL_LANGS)
def test_credential_literals_leave_only_as_placeholders(
    tmp_path: Path, lang: str, surface: str
) -> None:
    """Invariant 4, T11: neither credential appears — verbatim or case-folded — in
    ``json.dumps`` of the Flow, its hop names, the rendered decline or ``validation.flow``;
    M1/M4 text is emitted only as ``<index>``/``<flag>``."""
    emitted = _EMITTED[surface](lang, tmp_path)
    assert {"emitted": bool(emitted), "leaks": _leaks(emitted)} == {"emitted": True, "leaks": []}


# A30 (2): the placeholders a hop-name segment may be (M1 subscript key, M4 flag), and how many
# ``.``-joined segments a hop name has at most.
_HOP_PLACEHOLDERS = frozenset({"<index>", "<flag>"})
_HOP_SEGMENTS = 3


def _is_hop_segment(segment: str) -> bool:
    """One segment of a hop name: a placeholder, or ONE D16 identifier (no ``.`` of its own)."""
    return segment in _HOP_PLACEHOLDERS or ("." not in segment and admissible(IDENTIFIER, segment))


def _is_d16(name: str) -> bool:
    """A30 (2): a hop name is ``<expr>``, or up to three ``.``-joined segments, each a D16
    identifier or a placeholder ``<index>`` / ``<flag>``."""
    segments = name.split(".")
    return name == "<expr>" or (len(segments) <= _HOP_SEGMENTS and all(map(_is_hop_segment, segments)))


def _validation_hop_names(lang: str, root: Path) -> list[str]:
    """The hop names of ``validation.flow`` (§10.1: ``{"line", "kind", "name"}``)."""
    return [hop["name"] for hop in _validation_flow(lang, root)["hops"]]


_HOP_NAMES: dict[str, Callable[[str, Path], list[str]]] = {
    "flow": _hops_emitted,
    "validation.flow": _validation_hop_names,
}


@pytest.mark.parametrize("source", _HOP_NAMES)
@pytest.mark.parametrize("lang", _CREDENTIAL_LANGS)
def test_hop_names_match_d16(tmp_path: Path, lang: str, source: str) -> None:
    """D16, A30 (2): every hop name of the credential flow, in the Flow and in
    ``validation.flow``, is up to three ``.``-joined segments, each a D16 identifier or a
    placeholder (``<index>``, ``<flag>``), or else ``<expr>``."""
    names = _HOP_NAMES[source](lang, tmp_path)
    assert {"hops": bool(names), "off the pattern": [n for n in names if not _is_d16(n)]} == {
        "hops": True, "off the pattern": [],
    }
