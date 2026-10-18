"""Feature 0102, plan task 1.4: the file model's query surface, read through a REAL worker.

``FileModel`` is the parent-side view of one worker document: columnar, immutable,
shared across audits, and every per-node question the scope and flow passes ask of
it is an O(1) index lookup (LLD §5, §6.2, §8.7). Each model here is built by the
``get_model`` pipeline of plan task 1.5 minus its cache: ``read_file_safe`` (the one
``errors="replace"`` decode), one UTF-8 encode, ``WorkerPool.parse`` in a spawned
worker, ``validate_model`` at the boundary, ``FileModel.from_doc``. A test passes only
when the profile tables, the worker, the validator and the model agree; no document
is written by hand.

What is pinned, and where it comes from:

* the plan's task 1.4 list on ``cwe_22_1.js`` (two CALLs, the glued callee chain
  ``("fs", "readfile")``, arg 0 the NAME ``p``, ``function_of`` the handler, line 2),
  ``kwargs`` mapping ``shell`` to a LITERAL ``true`` (``cwe_78_18.py``) and a string
  literal carrying no value;
* LLD §5's methods: ``nodes``/``kind``/``parent``/``field``/``children`` agree as one
  CSR index, ``callee``/``args``/``kwargs``, ``function_of``/``block_of`` are the
  nearest FUNCTION and the nearest BLOCK or MODULE (W2), the kind shortcuts,
  ``chain_words`` memoised;
* walk corrections: W1 (``expression_statement`` transparent; ``args`` are positional,
  KWARGs excluded; a multi-child argument keeps one position), W3 (compound names are
  chains), W7 (a bare PARAM carries its text), and the OTHER declaration keyword;
* the ``lit`` record (LLD §6.2, R3, W15 b, D16): only booleans and numbers of at most
  20 characters keep a value; every null spelling is kind ``null``; a string's length
  is its content's;
* ``owns_lang`` (plan task 1.4): the profile table by extension, decided WITHOUT a parse.

Caps (D18: each is exercised at cap and at cap + 1, and cap + 1 tallies; LLD §8.7):
``MAX_ARGS`` (a call exposes its first 16 positional arguments, positions kept),
``MAX_CHAIN`` (a chain lists at most 8 consecutive segments, in source order) and
``MAX_WORDS`` (an identifier of more than 16 words). A cap's tally is a fact about the
FILE, so it is read from the immutable, cross-audit model as ``FileModel.tallies``: the
per-file counts an audit's ``ast_coverage.tallies`` aggregates, as ``unmapped`` feeds
``unmapped_kinds`` (LLD §10.2). The ``AuditContext`` does not exist until task 2.4, and
task 2.4 replaces only the pool's and the cache's stubs. Every cap test compares a
file with its twin one step below, so no tally key is named, and a tally counts
constructs, never queries.

``MAX_WORDS`` never shortens a ``chain_words`` entry: L1 (a §3 decision) keys a callee
by ``glue`` of its WHOLE last identifier. The cap bounds the word probes the role
lexicons make on an identifier (LLD §8.5: at most MAX_WORDS + 1), and the model tallies
the identifiers it caps.

Fixtures come from the cwe ``ast_v1`` corpus, by path and read-only. The pipeline and the
fixture loader live in ``_support.py``, shared with ``test_0102_egress.py`` (the span/window
half); the module's one W = 1 pool is ``conftest.py``'s ``real_pool``.

RED until ``shared.ast`` exists (``ModuleNotFoundError`` at collection).
"""

from __future__ import annotations

import string
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

from shared.ast import FileModel, owns_lang
from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_ARGS, MAX_CHAIN, MAX_WORDS
from shared.ast.model import Literal_
from shared.ast.pool import WorkerPool
from shared.ast.profile import PROFILES
from shared.language import _LANGUAGE_BY_EXT, detect_language
from tests.unit.ast._support import (
    STRUCTURE_FIXTURES,
    failing,
    fixture_model,
    only_call,
    parse_model,
)

pytestmark = pytest.mark.usefixtures("real_pool")

_END = {"javascript": ";\n", "typescript": ";\n", "python": "\n"}
_READ = {"javascript": "readFile", "python": "read_file"}       # both glue to "readfile"
_DECLARE = {"javascript": "const v = {};\n", "python": "v = {}\n"}
_FUNCTION = frozenset({Kind.FUNCTION})
_BLOCK_OR_MODULE = frozenset({Kind.BLOCK, Kind.MODULE})


def _nearest_ancestor(m: FileModel, i: int, kinds: frozenset[Kind]) -> int | None:
    """``i``'s nearest strict ancestor whose kind is in ``kinds``, by parent links."""
    p = m.parent(i)
    while p != -1 and m.kind(p) not in kinds:
        p = m.parent(p)
    return None if p == -1 else p


# ── cwe_22_1.js: the plan's task 1.4 list ──────────────────────────────────────
# line 2: function handler(req) { const p = req.query.f; fs.readFile(p); }
# line 3: app.use("/doc", handler);


def _call_on_line(m: FileModel, line: int) -> int:
    (call,) = [c for c in m.calls() if m.line(c) == line]
    return call


def _sink_and_use() -> tuple[FileModel, int, int]:
    m, _ = fixture_model("cwe_22_1.js")
    return m, _call_on_line(m, 2), _call_on_line(m, 3)


def test_cwe_22_1_has_two_calls() -> None:
    m, _ = fixture_model("cwe_22_1.js")
    observed = (list(m.calls()), sorted(m.line(c) for c in m.calls()))
    assert observed == (list(m.nodes(Kind.CALL)), [2, 3])


def test_callee_chain_is_glued_segments() -> None:
    """L1 (a): each segment glued, lowercased with ``_``/``$`` removed; memoised (§5)."""
    m, sink, use = _sink_and_use()
    callee = m.callee(sink)
    observed = {
        "callee is the CALLEE child": [callee] == list(m.children(sink, Field.CALLEE)),
        "sink": m.chain_words(callee),
        "use": m.chain_words(m.callee(use)),
        "memoised": m.chain_words(callee) is m.chain_words(callee),
    }
    assert observed == {
        "callee is the CALLEE child": True, "sink": ("fs", "readfile"),
        "use": ("app", "use"), "memoised": True,
    }


def test_sink_argument_zero_is_the_name_p() -> None:
    """The ARGS container's positional child, shipped with Field NONE (W1)."""
    m, sink, _ = _sink_and_use()
    (arg,) = m.args(sink)
    (container,) = m.children(sink, Field.ARGS)
    observed = (m.kind(arg), m.ident(arg), m.field(arg), m.kind(container), m.parent(arg))
    assert observed == (Kind.NAME, "p", Field.NONE, Kind.ARGS, container)


def test_function_of_the_sink_is_the_handler() -> None:
    m, sink, use = _sink_and_use()
    handler = m.function_of(sink)
    observed = {
        "kind": m.kind(handler),
        "functions": list(m.functions()),
        "name": [m.ident(n) for n in m.children(handler, Field.NAME)],
        "the top-level call is outside it": m.function_of(use) != handler,
    }
    assert observed == {
        "kind": Kind.FUNCTION, "functions": [handler], "name": ["handler"],
        "the top-level call is outside it": True,
    }


def test_sink_line_is_two() -> None:
    m, sink, use = _sink_and_use()
    assert (m.line(sink), m.line(use)) == (2, 3)


def test_block_of_is_the_nearest_block_or_the_module() -> None:
    """W1: ``expression_statement`` is transparent, so a statement CALL is a direct child
    of its BLOCK; W2: script-level code belongs to the MODULE, the root at index 0."""
    m, sink, use = _sink_and_use()
    (body,) = m.children(m.function_of(sink), Field.BODY)
    observed = {
        "root": (m.kind(0), m.parent(0)),
        "sink": (m.kind(body), m.block_of(sink), m.parent(sink)),
        "top-level call": (m.block_of(use), m.parent(use)),
    }
    assert observed == {
        "root": (Kind.MODULE, -1), "sink": (Kind.BLOCK, body, body), "top-level call": (0, 0),
    }


def test_parameter_and_declaration_keyword_text() -> None:
    """W7: a bare-identifier PARAM carries its own text, under the ARGS container that
    ``formal_parameters`` ships as; W1: a JS declaration is OTHER carrying its keyword."""
    m, sink, _ = _sink_and_use()
    (params,) = m.children(m.function_of(sink), Field.PARAMS)
    observed = {
        "container": m.kind(params),
        "params": [(m.kind(p), m.ident(p)) for p in m.children(params)],
        "keywords": [m.ident(o) for o in m.nodes(Kind.OTHER)],
    }
    assert observed == {"container": Kind.ARGS, "params": [(Kind.PARAM, "req")], "keywords": ["const"]}


def test_string_literal_has_no_value() -> None:
    """D16: a string's value never leaves the worker; its content length does (R3)."""
    m, _, use = _sink_and_use()
    record = m.literal(m.args(use)[0])                 # "/doc"
    assert (isinstance(record, Literal_), record.value, record.length) == (True, None, 4)


def test_python_kwargs_map_shell_to_literal_true() -> None:
    """``shell=True`` is a KWARG, never an argument (W1); a boolean is the one literal
    class that keeps a value, written lowercased (W15 b)."""
    m, _ = fixture_model("cwe_78_18.py")
    call = only_call(m)
    kwargs = m.kwargs(call)
    observed = {
        "chain": m.chain_words(m.callee(call)),
        "names": set(kwargs),
        "shell": (m.kind(kwargs["shell"]), m.literal(kwargs["shell"]).value),
        "positional": [m.kind(a) for a in m.args(call)],
    }
    assert observed == {
        "chain": ("subprocess", "checkoutput"), "names": {"shell"},
        "shell": (Kind.LITERAL, "true"), "positional": [Kind.BINOP],
    }


# ── the lit record (LLD §6.2, R3, W15 b, D16) ──────────────────────────────────

_LITERALS = [
    ("javascript", "null", {"kind": "null", "value": None}),
    ("javascript", "undefined", {"kind": "null", "value": None}),
    ("python", "None", {"kind": "null", "value": None}),
    ("javascript", '""', {"length": 0, "value": None}),
    ("javascript", '"abc"', {"length": 3, "value": None}),
    ("javascript", '"AKIAIDENTIFIERSHAPED"', {"value": None}),
    ("python", "'s3cr3t/+value=='", {"value": None}),
    ("javascript", "false", {"value": "false"}),
    ("python", "True", {"value": "true"}),
    ("javascript", "1_000", {"value": "1_000"}),
    ("javascript", "12345678901234567890", {"value": "12345678901234567890"}),
    ("javascript", "123456789012345678901", {"value": None}),
    ("javascript", "0x1F", {"value": None}),
    ("javascript", "1e5", {"value": None}),
]


def _idents(m: FileModel) -> set[str | None]:
    return {m.ident(i) for i in range(m.node_count)}


@pytest.mark.parametrize(
    ("language", "source", "expected"), _LITERALS,
    ids=[f"{language}:{source}" for language, source, _ in _LITERALS],
)
def test_literal_record(language: str, source: str, expected: Mapping[str, object]) -> None:
    """Only a boolean or a number of at most 20 characters keeps a value; every null
    spelling is kind ``null``; a string's length counts its content; and no literal's
    spelling reaches ``ident`` outside the M1/M4 positions."""
    m = parse_model(_DECLARE[language].format(source), language)
    (lit,) = m.nodes(Kind.LITERAL)
    record = m.literal(lit)
    observed = {name: getattr(record, name) for name in expected}
    leaked = source.strip("'\"") in _idents(m)
    assert (isinstance(record, Literal_), observed, leaked) == (True, expected, False)


# ── owns_lang: the profile table, without a parse ──────────────────────────────


def _refuse_parse(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("owns_lang decides by extension; it never parses")


def _ownership_mismatches(root: Path) -> list[str]:
    """Extensions whose ``owns_lang`` answer is not "its language has a v1 profile"."""
    return [ext for ext in _LANGUAGE_BY_EXT
            if owns_lang(root / f"a{ext}") != (detect_language(f"a{ext}") in PROFILES)]


def test_owns_lang_is_the_profile_table_without_a_parse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Every extension ``shared.language`` knows: owned iff its language has a v1
    profile, for a path that does not exist, with every parse refused (O1: Ruby is the
    unsupported language, Go a v1 one)."""
    monkeypatch.setattr(WorkerPool, "parse", _refuse_parse)
    named = [owns_lang(p) for p in ("x/a.go", "x/a.rb", "x/a.TSX", "x/Dockerfile")]
    observed = (_ownership_mismatches(tmp_path / "missing"), named)
    assert observed == ([], [True, False, True, False])


# ── one CSR index (LLD §5, §6.2) ───────────────────────────────────────────────


def _nodes_of_kind(m: FileModel, kind: Kind) -> list[int]:
    return [i for i in range(m.node_count) if m.kind(i) is kind]


def _kind_index_mismatches(m: FileModel) -> list[Kind]:
    return [k for k in Kind if list(m.nodes(k)) != _nodes_of_kind(m, k)]


def _unlinked(m: FileModel, i: int) -> bool:
    p = m.parent(i)
    return not (0 <= p < i and i in m.children(p))


def _field_slices_disagree(m: FileModel, i: int) -> bool:
    kids = list(m.children(i))
    return any(list(m.children(i, f)) != [c for c in kids if m.field(c) is f] for f in Field)


@pytest.mark.parametrize("name", STRUCTURE_FIXTURES)
def test_indexes_agree_with_the_parent_links(name: str) -> None:
    """The per-kind index is a partition in document order; every child slice — whole,
    and per Field — agrees with ``parent`` and ``field``; the root is the MODULE."""
    m, _ = fixture_model(name)
    nodes = range(m.node_count)
    observed = {
        "kind index": _kind_index_mismatches(m),
        "parent links": failing(nodes[1:], lambda i: _unlinked(m, i)),
        "field slices": failing(nodes, lambda i: _field_slices_disagree(m, i)),
        "root": (m.kind(0), m.parent(0)),
    }
    assert observed == {"kind index": [], "parent links": [], "field slices": [],
                        "root": (Kind.MODULE, -1)}


def _outside_parent(m: FileModel, i: int) -> bool:
    (sb, eb), (pb, pe) = m.span(i), m.span(m.parent(i))
    return not pb <= sb <= eb <= pe


# C++ is left out: a C3/R-X stack-constructor CALL is synthesised around a declarator
# while its callee is the declaration's type, so its span is not specified (LLD §6.3).
@pytest.mark.parametrize("name", [n for n in STRUCTURE_FIXTURES if not n.endswith(".cpp")])
def test_a_child_span_lies_within_its_parent_span(name: str) -> None:
    m, _ = fixture_model(name)
    assert failing(range(1, m.node_count), lambda i: _outside_parent(m, i)) == []


def _not_nearest(m: FileModel, call: int) -> bool:
    function = _nearest_ancestor(m, call, _FUNCTION)
    wrong_function = function is not None and m.function_of(call) != function
    return wrong_function or m.block_of(call) != _nearest_ancestor(m, call, _BLOCK_OR_MODULE)


@pytest.mark.parametrize("name", STRUCTURE_FIXTURES)
def test_function_of_and_block_of_are_the_nearest_ancestors(name: str) -> None:
    """For every CALL: ``function_of`` is its nearest FUNCTION, ``block_of`` its nearest
    BLOCK or MODULE (W2) — the precomputed arrays agree with the parent links."""
    m, _ = fixture_model(name)
    assert failing(m.calls(), lambda c: _not_nearest(m, c)) == []


_NESTED_JS = (
    "function outer(req) {\n"
    "  const inner = () => { fs.readFile(req.query.f); };\n"
    "  return inner;\n"
    "}\n"
)


def test_function_of_a_call_in_a_nested_function_is_the_inner_one() -> None:
    m = parse_model(_NESTED_JS, "javascript")
    sink = only_call(m)
    functions = list(m.functions())
    (body,) = m.children(functions[1], Field.BODY)
    observed = (len(functions), m.function_of(sink), m.block_of(sink))
    assert observed == (2, functions[1], body)


# ── the kind shortcuts (LLD §5) ────────────────────────────────────────────────

_SHORTCUTS = {"functions": Kind.FUNCTION, "calls": Kind.CALL, "catches": Kind.CATCH, "loops": Kind.LOOP}
_CONTROL_JS = (
    "function h(xs) {\n"
    "  for (const x of xs) {\n"
    "    try { f(x); } catch (e) { g(e); }\n"
    "  }\n"
    "  while (xs.length) { xs.pop(); }\n"
    "}\n"
)


def _shortcut_answers(m: FileModel) -> dict[str, list[int]]:
    return {name: list(getattr(m, name)()) for name in _SHORTCUTS}


def _kind_answers(m: FileModel) -> dict[str, list[int]]:
    return {name: list(m.nodes(kind)) for name, kind in _SHORTCUTS.items()}


def test_kind_shortcuts_are_the_kind_index() -> None:
    m = parse_model(_CONTROL_JS, "javascript")
    observed = _shortcut_answers(m)
    sizes = {name: len(nodes) for name, nodes in observed.items()}
    assert (observed, sizes) == (
        _kind_answers(m), {"functions": 1, "calls": 3, "catches": 1, "loops": 2},
    )


# ── chain_words across profiles (L1, W3, §8.2 M1) ──────────────────────────────

_CHAINS = [
    ("javascript", "$http.get_url(u);\n", ("http", "geturl")),            # L1: `$`, `_` removed
    ("javascript", 'event["body"].x(p);\n', ("event", "body", "x")),       # §8.2: an M1 key joins
    ("typescript", "fs.readFile(p);\n", ("fs", "readfile")),
    ("python", "os.path.join(a, b)\n", ("os", "path", "join")),
    ("go", "package main\n\nfunc h(p string) { os.ReadFile(p) }\n", ("os", "readfile")),
    ("rust", "fn h(p: &str) { fs::read_to_string(p); }\n", ("fs", "readtostring")),        # W3
    ("cpp", "void h(const char *p) { std::filesystem::remove(p); }\n",
     ("std", "filesystem", "remove")),                                                    # W3
    ("c", "void h(const char *p) { system(p); }\n", ("system",)),
]


@pytest.mark.parametrize(("language", "source", "chain"), _CHAINS,
                         ids=[f"{language}:{chain[-1]}" for language, _, chain in _CHAINS])
def test_chain_words_lists_glued_segments_in_source_order(
    language: str, source: str, chain: tuple[str, ...],
) -> None:
    """A MEMBER chain, an M1 subscript key and a compound name (W3: a text-less MEMBER)
    all list their segments in source order; the last is the callee's key (L1 (a))."""
    m = parse_model(source, language)
    assert m.chain_words(m.callee(only_call(m))) == chain


# ── argument positions (W1) ────────────────────────────────────────────────────

_POSITIONS = [
    ("javascript", "f((a, b), c);\n"),
    ("go", "package main\n\nfunc h() { f(b[1:n], c) }\n"),
    ("rust", "fn h() { f(0..n, c); }\n"),
]


@pytest.mark.parametrize(("language", "source"), _POSITIONS, ids=[p[0] for p in _POSITIONS])
def test_a_multi_child_argument_keeps_one_position(language: str, source: str) -> None:
    """W1: an unlisted node in an argument position that would re-parent more than one
    shipped child ships as one text-less BINOP, so ``c`` stays argument 1."""
    m = parse_model(source, language)
    observed = [(m.kind(a), m.ident(a)) for a in m.args(only_call(m))]
    assert observed == [(Kind.BINOP, None), (Kind.NAME, "c")]


# ── caps: MAX_ARGS, MAX_CHAIN, MAX_WORDS (D18, LLD §8.7) ───────────────────────


def _call_with_args(language: str, count: int) -> str:
    return f"f({', '.join(f'a{i}' for i in range(count))}){_END[language]}"


def _chain_call(language: str, segments: int) -> str:
    receivers = ".".join(f"s{i}" for i in range(segments - 1))
    return f"{receivers}.{_READ[language]}(p){_END[language]}"


def _worded_call(language: str, words: int) -> str:
    return f"fs.{'_'.join(string.ascii_lowercase[:words])}(p){_END[language]}"


def _glued_chain(segments: int) -> tuple[str, ...]:
    return (*(f"s{i}" for i in range(segments - 1)), "readfile")


def _models(source: Callable[[str, int], str], language: str,
            sizes: Sequence[int]) -> dict[int, FileModel]:
    return {n: parse_model(source(language, n), language) for n in sizes}


def _arg_idents(m: FileModel) -> list[str | None]:
    return [m.ident(a) for a in m.args(only_call(m))]


def _callee_chain(m: FileModel) -> tuple[str, ...]:
    return m.chain_words(m.callee(only_call(m)))


def _extra_tallies(over: FileModel, under: FileModel) -> int:
    """How many more cap events ``over`` tallied than its twin ``under``."""
    return sum((Counter(over.tallies) - Counter(under.tallies)).values())


def _tallied_steps(models: Mapping[int, FileModel], cap: int) -> tuple[int, bool]:
    """(extra tallies at the cap over cap - 1, whether cap + 1 tallied over the cap)."""
    return (_extra_tallies(models[cap], models[cap - 1]),
            _extra_tallies(models[cap + 1], models[cap]) >= 1)


@pytest.mark.parametrize("language", ["javascript", "python"])
def test_max_args_keeps_the_first_positions_and_tallies(language: str) -> None:
    """Extra arguments are ignored and tallied; the kept ones are positions
    ``0 .. MAX_ARGS - 1``, unshifted (a sink's ``path_args`` index them, L9)."""
    models = _models(_call_with_args, language, (MAX_ARGS - 1, MAX_ARGS, MAX_ARGS + 1, 4 * MAX_ARGS))
    first = [f"a{i}" for i in range(MAX_ARGS)]
    observed = {
        "kept": [_arg_idents(models[n]) for n in (MAX_ARGS, MAX_ARGS + 1, 4 * MAX_ARGS)],
        "tallied (cap, cap + 1)": _tallied_steps(models, MAX_ARGS),
    }
    assert observed == {"kept": [first] * 3, "tallied (cap, cap + 1)": (0, True)}


@pytest.mark.parametrize("language", ["javascript", "python"])
def test_max_chain_keeps_consecutive_segments_and_tallies(language: str) -> None:
    """A chain longer than MAX_CHAIN lists MAX_CHAIN consecutive segments in source
    order (which end survives is not specified: its first or its last) and tallies."""
    models = _models(_chain_call, language, (MAX_CHAIN - 1, MAX_CHAIN, MAX_CHAIN + 1, 4 * MAX_CHAIN))
    chains = {n: _callee_chain(m) for n, m in models.items()}
    full = _glued_chain(MAX_CHAIN + 1)
    observed = {
        "at cap": chains[MAX_CHAIN],
        "cap + 1 is a window": chains[MAX_CHAIN + 1] in (full[:MAX_CHAIN], full[-MAX_CHAIN:]),
        "length far over": len(chains[4 * MAX_CHAIN]),
        "tallied (cap, cap + 1)": _tallied_steps(models, MAX_CHAIN),
    }
    assert observed == {
        "at cap": _glued_chain(MAX_CHAIN), "cap + 1 is a window": True,
        "length far over": MAX_CHAIN, "tallied (cap, cap + 1)": (0, True),
    }, chains


@pytest.mark.parametrize("language", ["javascript", "python"])
def test_max_words_tallies_and_never_shortens_the_glued_key(language: str) -> None:
    """An identifier of MAX_WORDS + 1 single-letter words (``a_b_..._q``) is tallied;
    its glued key stays whole (L1: ``glue`` of the whole last identifier)."""
    models = _models(_worded_call, language, (MAX_WORDS - 1, MAX_WORDS, MAX_WORDS + 1))
    observed = {
        "keys": [_callee_chain(models[n]) for n in (MAX_WORDS, MAX_WORDS + 1)],
        "tallied (cap, cap + 1)": _tallied_steps(models, MAX_WORDS),
    }
    letters = string.ascii_lowercase
    assert observed == {
        "keys": [("fs", letters[:MAX_WORDS]), ("fs", letters[: MAX_WORDS + 1])],
        "tallied (cap, cap + 1)": (0, True),
    }


def _query_every_call(m: FileModel) -> list[tuple[tuple[int, ...], tuple[str, ...]]]:
    return [(tuple(m.args(c)), m.chain_words(m.callee(c))) for c in m.calls()]


def test_cap_tallies_count_constructs_not_queries() -> None:
    """One file holding one construct over each cap: the first round of queries may
    tally, a repeat — every rule of every audit sharing the model asks again — never
    does, and the answers do not change. ``tallies`` is a mapping of counts."""
    source = "".join(f("javascript", cap + 1) for f, cap in (
        (_call_with_args, MAX_ARGS), (_chain_call, MAX_CHAIN), (_worded_call, MAX_WORDS)))
    m = parse_model(source, "javascript")
    first = _query_every_call(m)
    tallies = dict(m.tallies)
    repeated = [_query_every_call(m) for _ in range(2)]
    assert (repeated, dict(m.tallies), sum(tallies.values()) >= 3) == ([first] * 2, tallies, True)


# ── nl_lines (D21) ─────────────────────────────────────────────────────────────


def test_nl_lines_reads_as_the_newline_only_split() -> None:
    """D21: ``nl_lines`` answers as ``text.split("\\n")`` does — by index, from the end, in
    slices, iterated — splitting on ``\\n`` only (a CR and a U+2028 stay inside their line),
    and refuses an index past either end as a list does."""
    text = "a = 1\r\nb = ' '\n\nlast = 2"
    m = parse_model(text, "python")
    lines = text.split("\n")
    observed = (len(m.nl_lines), m.nl_lines[1], m.nl_lines[-1], m.nl_lines[1:3], list(m.nl_lines))
    assert observed == (len(lines), lines[1], lines[-1], lines[1:3], lines)
    for past in (len(lines), -len(lines) - 1):
        with pytest.raises(IndexError):
            m.nl_lines[past]
