"""Feature 0102, plan task 2.5: property tests over generated programs (LLD §13.1).

A hypothesis generator writes small JavaScript and Python programs from the role lexicons of
§9.1 (``shared.ast.roles``, imported when a test first draws, never at collection) and from
literal and structure fragments: assignments, calls, members, subscripts, ``if``/``else``,
functions, and, in a TAINTED program only, ``try``/``catch``, a route handler and the source
words. Six properties hold on every program:

* the pool never raises: ``WorkerPool.parse`` answers a document or a fallback reason (§4);
* every worker document validates (``validate_reply``) and builds a ``FileModel``, or the
  answer is a fallback reason (D3, §6.2);
* no candidate sink has an ``external`` origin unless the text holds a source-role token —
  a token whose words or glued key are in a lexicon that can ORIGINATE an external origin
  (§8.2, §8.4: the source words and roots, the parameter hints, annotation, route,
  registration, callback-payload and accessor words, the request sinks whose result is
  ``external(network)`` (R-I), ``catch``/``except`` (a CATCH parameter is ``external(error)``)
  and the profiles' builtin sources). An UNTAINTED program draws no such token, so the
  property bites on about half of the examples, and the test checks the generator kept it so;
* the branch join (§7.2) is commutative: ``if t: A else: B`` and ``if t: B else: A`` give
  every later sink the same origins;
* the branch join is idempotent: ``if t: A else: A`` gives every later sink the origins
  straight-line ``A`` gives it;
* two runs are equal: the same text parsed twice gives the same skeleton and the same
  candidates of every family (D14).

Every property runs ``max_examples=200`` with ``deadline=None``, ``derandomize=True`` and
no example database, so CI draws the same programs every run. The module's examples share
ONE W = 1 pool (``real_pool``), so a run costs a few parses per example, never a spawn.

RED until plan tasks 2.1-2.3: the generator reads ``shared.ast.roles`` (task 2.2,
``ModuleNotFoundError``), the analysis is ``shared.ast.flow`` (task 2.3) and the join is the
scope pass (task 2.1).
"""

from __future__ import annotations

import functools
import keyword
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from itertools import chain, product
from types import ModuleType
from typing import Any, NamedTuple, get_args

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from shared.ast import FileModel
from shared.ast._validate import validate_reply
from shared.ast.pool import FallbackReason, ParseResult, get_pool
from shared.ast.profile import LanguageProfile
from tests.unit.ast._analysis import (
    FAMILIES,
    candidates_of,
    entries_of,
    externals,
    model_of,
    profile_of,
    roles_mod,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# One settings object for every property: bounded, deterministic, no example database.
_PROPERTY = settings(
    max_examples=200,
    deadline=None,
    derandomize=True,
    database=None,
    print_blob=False,
    suppress_health_check=(HealthCheck.too_slow, HealthCheck.data_too_large),
)

_LANGUAGES = ("js", "py")
# Structure: the variables a program reads and writes, and its literals (no lexicon word).
_VARS = ("v0", "v1", "v2", "v3")
_LITERALS = ('"a"', '"x/y"', '""', "7", "0")
# Literal fragments placed before or after a program: hostile to a parser, inert to the
# source oracle (no fragment holds a lexicon word).
_NOISE = ("", "\ufeff", "\u2028", "\x00", "{", ")", "]", '"unclosed', "/* note", "x" * 70,
          "\U0001f600", "\t")

# ── the vocabulary, read from the role lexicons (§9.1) ───────────────────────

# Every lexicon a word of which can ORIGINATE an external origin (§8.2 NAME/PARAM/MEMBER/
# SUBSCRIPT rows, SOURCE_CALL_KEYS, R-A, R-C, R-D, R-E, R-T, R-U, R-V's terminal on a carrier).
# Their words are read by ``_analysis.entries``, the reading the roles module pins: a table's
# words, never the role or family names it is keyed by.
_MARK_LEXICONS = (
    "SOURCE_WORDS", "CONDITIONAL_SOURCE_ROOTS", "SOURCE_CALL_KEYS", "PARAM_HINTS",
    "PARAM_ANNOTATION_WORDS", "TYPE_ANNOTATION_WORDS", "ROUTE_WORDS",
    "HANDLER_REGISTRATION_WORDS", "CALLBACK_PAYLOAD_WORDS", "ACCESSOR_WORDS",
    "ACCESSOR_RECEIVER_WORDS", "REQUEST_TERMINAL_WORDS", "REQUEST_CARRIER_WORDS",
)
# A CATCH parameter is external(error) (§8.2 PARAM row): its keyword is a source token.
_HANDLER_KEYWORDS = frozenset({"catch", "except"})
# The lexicons an untainted program draws its callees, properties and parameters from, less
# every source mark: sinks, sanitisers, guards, exits.
_NEUTRAL_LEXICONS = (
    "COMMAND_STRONG", "COMMAND_WEAK", "SANITIZER_WORDS", "SANITIZER_KEYS", "GUARD_WORDS",
    "MEMBERSHIP_KEYS", "EXIT_WORDS",
)
_NAME = re.compile(r"[a-z][a-z0-9]{1,31}")
# A word a JavaScript or Python program cannot use as a plain name.
_RESERVED = frozenset(keyword.kwlist) | frozenset(keyword.softkwlist) | frozenset({
    "arguments", "async", "await", "break", "case", "catch", "class", "const", "continue",
    "debugger", "default", "delete", "do", "else", "enum", "eval", "export", "extends", "false",
    "finally", "for", "function", "if", "implements", "import", "in", "instanceof", "interface",
    "let", "new", "null", "package", "private", "protected", "public", "return", "static",
    "super", "switch", "this", "throw", "true", "try", "typeof", "undefined", "var", "void",
    "while", "with", "yield",
})
# A token of the text, as the source oracle reads it (string and comment contents included).
_TOKEN = re.compile(r"[A-Za-z_$][\w$]*")


class _Vocabulary(NamedTuple):
    sources: tuple[str, ...]  # SOURCE_WORDS entries
    chains: tuple[tuple[str, str], ...]  # CONDITIONAL_SOURCE_ROOTS (root, member) pairs
    neutral: tuple[str, ...]  # lexicon words outside `marks`
    sinks: tuple[str, ...]  # path / request sink words and the strong command keys
    marks: frozenset[str]  # every word that can originate an external origin
    glue: Callable[[str], str]
    words: Callable[[str], tuple[str, ...]]


def _flat(value: Any) -> frozenset[str]:
    """Every string of a value of any §9.1 shape that is no named table: a word, a set, a set
    of sets, a mapping (its keys and its values)."""
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Mapping):
        return _flat(list(value)) | _flat(list(value.values()))
    return frozenset().union(*map(_flat, value))


def _is_name(word: str) -> bool:
    return _NAME.fullmatch(word) is not None and word not in _RESERVED


def _usable(words: frozenset[str]) -> tuple[str, ...]:
    """The words a program can spell as plain names, sorted (a deterministic draw order)."""
    return tuple(sorted(filter(_is_name, words)))


def _request_builtins(profile: LanguageProfile) -> frozenset[str]:
    """The profile's builtin request sinks: a call result is ``external(network)`` (R-I)."""
    sinks = profile.builtin_sinks
    return frozenset(key for key, sink in sinks.items() if "request" in sink.families)


def _marks(roles: ModuleType) -> frozenset[str]:
    """The source-role vocabulary: the entries of ``_MARK_LEXICONS``, the request sinks (R-I),
    the CATCH keywords and each generated language's builtin sources and request builtins."""
    profiles = [profile_of(lang) for lang in _LANGUAGES]
    return frozenset(entries_of(_MARK_LEXICONS)) | _flat([
        roles.SINK_WORDS["request"],
        _HANDLER_KEYWORDS,
        *(frozenset(p.builtin_sources) | _request_builtins(p) for p in profiles),
    ])


def _chains(roles: ModuleType) -> tuple[tuple[str, str], ...]:
    """Every ``(root, member)`` of ``CONDITIONAL_SOURCE_ROOTS`` a program can spell."""
    roots = roles.CONDITIONAL_SOURCE_ROOTS
    pairs = chain.from_iterable(product((root,), members) for root, members in roots.items())
    return tuple(sorted(pair for pair in pairs if all(map(_is_name, pair))))


@functools.cache
def _vocabulary() -> _Vocabulary:
    """The generator's words, read once from ``shared.ast.roles`` (plan task 2.2)."""
    roles = roles_mod()
    marks = _marks(roles)
    neutral = _flat([
        *(getattr(roles, name) for name in _NEUTRAL_LEXICONS), roles.SINK_WORDS["path"],
    ])
    sinks = _flat([roles.SINK_WORDS["path"], roles.SINK_WORDS["request"], roles.COMMAND_STRONG])
    return _Vocabulary(
        sources=_usable(_flat(roles.SOURCE_WORDS.values())),
        chains=_chains(roles),
        neutral=_usable(neutral - marks),
        sinks=_usable(sinks),
        marks=marks,
        glue=roles.glue,
        words=roles.words,
    )


# ── the source oracle ────────────────────────────────────────────────────────


def _marked(token: str, voc: _Vocabulary) -> bool:
    """A source-role token: its glued key or one of its words is a source mark."""
    return voc.glue(token) in voc.marks or not voc.marks.isdisjoint(voc.words(token))


def _source_tokens(text: str, voc: _Vocabulary) -> list[str]:
    return sorted({token for token in _TOKEN.findall(text) if _marked(token, voc)})


def _external_sinks(model: FileModel) -> list[tuple[str, int]]:
    """``(family, sink line)`` of every candidate with an ``external`` origin."""
    return [(family, flow.sink_line) for family in FAMILIES
            for flow in candidates_of(model, family) if externals(flow.origins)]


# ── programs: statements and their rendering ─────────────────────────────────


class _Stmt(NamedTuple):
    kind: str  # stmt | decl | return | if | def | try | route
    head: str = ""  # the statement, the declared name, the test, or the signature
    body: tuple[_Stmt, ...] = ()
    alt: tuple[_Stmt, ...] = ()


_RETURN = _Stmt("return")
_PAD = {"js": "  ", "py": "    "}
_SYNTAX: dict[str, dict[str, str]] = {
    "js": {
        "stmt": "{};", "decl": "let {} = 0;", "return": "return;", "if": "if ({}) {{",
        "else": "}} else {{", "def": "function {} {{", "try": "try {{", "catch": "}} catch (e) {{",
        "route": 'app.get("/x", function ({}) {{',
    },
    "py": {
        "stmt": "{}", "decl": "{} = 0", "return": "return", "if": "if {}:", "else": "else:",
        "def": "def {}:", "try": "try:", "catch": "except Exception as e:",
        "route": '@app.route("/x")\ndef view({}):',
    },
}
_CLOSE: dict[str, dict[str, str]] = {
    "js": {"if": "}", "def": "}", "try": "}", "route": "});"},
    "py": {},
}
# A block's head lines, in order; each takes the children the matching member holds. Every
# other kind is one line.
_OPENERS = {"if": ("if", "else"), "def": ("def",), "try": ("try", "catch"), "route": ("route",)}


def _segments(stmt: _Stmt) -> list[tuple[str, tuple[_Stmt, ...]]]:
    return [(key, kids) for key, kids in zip(_OPENERS[stmt.kind], (stmt.body, stmt.alt)) if kids]


def _line(stmt: _Stmt, lang: str, depth: int) -> list[str]:
    return [_PAD[lang] * depth + _SYNTAX[lang][stmt.kind].format(stmt.head)]


def _block(stmt: _Stmt, lang: str, depth: int) -> list[str]:
    pad, syntax = _PAD[lang] * depth, _SYNTAX[lang]
    lines = [
        line
        for key, kids in _segments(stmt)
        for line in (pad + syntax[key].format(stmt.head), *_render(kids, lang, depth + 1))
    ]
    closer = _CLOSE[lang].get(stmt.kind)
    return [*lines, pad + closer] if closer else lines


def _rendered(stmt: _Stmt, lang: str, depth: int) -> list[str]:
    """One statement's lines: a block (an ``_OPENERS`` kind) or one line."""
    return (_block if stmt.kind in _OPENERS else _line)(stmt, lang, depth)


def _render(stmts: Sequence[_Stmt], lang: str, depth: int) -> list[str]:
    """``stmts`` as ``lang`` source lines at nesting ``depth``."""
    return [line for stmt in stmts for line in _rendered(stmt, lang, depth)]


def _text(stmts: Sequence[_Stmt], lang: str) -> str:
    return "\n".join(_render(stmts, lang, 0)) + "\n"


# ── strategies ───────────────────────────────────────────────────────────────

type _Strategy[T] = st.SearchStrategy[T]
type _Block = _Strategy[tuple[_Stmt, ...]]


def _shaped(template: str, *parts: _Strategy[str]) -> _Strategy[str]:
    """``template`` filled with one draw of each part."""
    return st.tuples(*parts).map(lambda drawn: template.format(*drawn))


def _sources(voc: _Vocabulary) -> _Strategy[str]:
    """A source read: a source word, a conditional root's member, or its M1 subscript."""
    chain = st.sampled_from(voc.chains)
    return st.one_of(
        st.sampled_from(voc.sources),
        chain.map(lambda pair: "{}.{}".format(*pair)),
        chain.map(lambda pair: '{}["{}"]'.format(*pair)),
    )


def _names(voc: _Vocabulary, tainted: bool) -> tuple[str, ...]:
    """Callees, properties and parameters: neutral words, plus the source words when tainted."""
    return voc.neutral + voc.sources if tainted else voc.neutral


def _leaves(voc: _Vocabulary, tainted: bool) -> _Strategy[str]:
    plain = st.sampled_from((*_VARS, *_LITERALS, *voc.neutral))
    return st.one_of(plain, _sources(voc)) if tainted else plain


def _compound(names: _Strategy[str], inner: _Strategy[str]) -> _Strategy[str]:
    return st.one_of(
        _shaped("{}({})", names, inner),
        _shaped("{}({}, {})", names, inner, inner),
        _shaped("({}).{}", inner, names),
        _shaped("({})[{}]", inner, inner),
        _shaped("{} + {}", inner, inner),
    )


def _expressions(voc: _Vocabulary, tainted: bool) -> _Strategy[str]:
    names = st.sampled_from(_names(voc, tainted))
    return st.recursive(_leaves(voc, tainted), functools.partial(_compound, names), max_leaves=5)


def _assignments(exprs: _Strategy[str]) -> _Strategy[_Stmt]:
    return _shaped("{} = {}", st.sampled_from(_VARS), exprs).map(functools.partial(_Stmt, "stmt"))


def _parameters(voc: _Vocabulary, tainted: bool) -> _Strategy[str]:
    names = st.sampled_from((*_VARS, *_names(voc, tainted)))
    return st.lists(names, max_size=3, unique=True).map(", ".join)


def _signatures(voc: _Vocabulary, tainted: bool) -> _Strategy[str]:
    return _shaped("{}({})", st.sampled_from(voc.neutral), _parameters(voc, tainted))


def _ifs(exprs: _Strategy[str], inner: _Block) -> _Strategy[_Stmt]:
    return st.builds(_Stmt, st.just("if"), exprs, inner, st.one_of(st.just(()), inner))


def _defs(signatures: _Strategy[str], inner: _Block) -> _Strategy[_Stmt]:
    return st.builds(_Stmt, st.just("def"), signatures, inner)


def _tries(inner: _Block) -> _Strategy[_Stmt]:
    return st.builds(_Stmt, st.just("try"), st.just(""), inner, inner)


type _Blocks = tuple[Callable[[_Block], _Strategy[_Stmt]], ...]


def _nested(simple: _Strategy[_Stmt], blocks: _Blocks, inner: _Block) -> _Block:
    statement = st.one_of(simple, *(block(inner) for block in blocks))
    return st.lists(statement, min_size=1, max_size=4).map(tuple)


def _statements(voc: _Vocabulary, tainted: bool) -> _Block:
    """A statement list: assignments, expression statements and returns, nested in ``if``/
    ``else`` and functions (and ``try``/``catch`` when tainted)."""
    exprs = _expressions(voc, tainted)
    statement = exprs.map(functools.partial(_Stmt, "stmt"))
    # A return is one draw in five: enough for exits, too few to crowd out the flows.
    simple = st.one_of(*(_assignments(exprs), statement) * 2, st.just(_RETURN))
    blocks: _Blocks = (
        functools.partial(_ifs, exprs),
        functools.partial(_defs, _signatures(voc, tainted)),
        *((_tries,) if tainted else ()),
    )
    base = st.lists(simple, min_size=1, max_size=3).map(tuple)
    return st.recursive(base, functools.partial(_nested, simple, blocks), max_leaves=6)


def _one(kind: str, head: str, body: tuple[_Stmt, ...]) -> tuple[_Stmt, ...]:
    return (_Stmt(kind, head, body),)


@functools.cache
def _wrapped(voc: _Vocabulary, tainted: bool) -> _Block:
    """A program's top level: the statements bare, in a function, or (tainted) in a route."""
    body = _statements(voc, tainted)
    function = st.builds(_one, st.just("def"), _signatures(voc, tainted), body)
    route = st.builds(_one, st.just("route"), _parameters(voc, True), body)
    return st.one_of(body, function, route) if tainted else st.one_of(body, function)


class _Program(NamedTuple):
    lang: str
    text: str
    tainted: bool  # False: the generator drew no source-role token


@st.composite
def _program(draw: st.DrawFn, voc: _Vocabulary) -> _Program:
    lang, tainted = draw(st.sampled_from(_LANGUAGES)), draw(st.booleans())
    body = _text(draw(_wrapped(voc, tainted)), lang)
    noise = draw(st.one_of(st.just(""), st.sampled_from(_NOISE)))  # about half are clean
    at_end = draw(st.booleans())
    return _Program(lang, body + noise if at_end else noise + body, tainted)


@functools.cache
def _programs(voc: _Vocabulary) -> _Strategy[_Program]:
    return _program(voc)


# ── the join cases (§7.2) ────────────────────────────────────────────────────


class _JoinCase(NamedTuple):
    lang: str
    test: str  # the IF's test: a variable
    a: tuple[_Stmt, ...]  # assignments only, so no sink sits in a branch
    b: tuple[_Stmt, ...]
    sinks: tuple[_Stmt, ...]  # sink calls after the IF, reading the variables


@functools.cache
def _join_cases(voc: _Vocabulary) -> _Strategy[_JoinCase]:
    branch = st.lists(_assignments(_expressions(voc, True)), min_size=1, max_size=4).map(tuple)
    sink = _shaped("{}({})", st.sampled_from(voc.sinks), st.sampled_from(_VARS))
    sinks = st.lists(sink.map(functools.partial(_Stmt, "stmt")), min_size=1, max_size=3).map(tuple)
    langs, tests = st.sampled_from(_LANGUAGES), st.sampled_from(_VARS)
    return st.builds(_JoinCase, langs, tests, branch, branch, sinks)


# Every variable is declared first, so a branch's assignment writes the outer binding.
_DECLARATIONS = tuple(_Stmt("decl", var) for var in _VARS)


def _branch(
    case: _JoinCase, conseq: tuple[_Stmt, ...], alt: tuple[_Stmt, ...]
) -> tuple[_Stmt, ...]:
    return (_Stmt("if", case.test, conseq, alt),)


def _sink_origins(
    case: _JoinCase, middle: Sequence[_Stmt]
) -> Counter[tuple[str, frozenset[Any]]]:
    """The origins every candidate after ``middle`` carries, as a multiset of
    ``(family, origins)``: line-free, so two variants of ``middle`` compare."""
    head = _render((*_DECLARATIONS, *middle), case.lang, 0)
    after = len(head) + 1
    model = model_of("\n".join((*head, *_render(case.sinks, case.lang, 0))) + "\n", case.lang)
    return Counter((family, flow.origins) for family in FAMILIES
                   for flow in candidates_of(model, family) if flow.sink_line >= after)


# ── one program, parsed ──────────────────────────────────────────────────────

_FALLBACKS = frozenset(get_args(FallbackReason))


def _answer(program: _Program) -> tuple[LanguageProfile, bytes, ParseResult]:
    """The pool's answer for ``program`` (an exception here fails the test that asked)."""
    profile, data = profile_of(program.lang), program.text.encode("utf-8")
    return profile, data, get_pool().parse(profile.language, data)


def _admitted(program: _Program) -> str:
    """``document`` when the answer validates against its request and builds a model; the
    fallback reason otherwise (a ``ModelError`` fails the property)."""
    profile, data, answer = _answer(program)
    if not isinstance(answer, dict):
        return answer
    FileModel.from_doc(validate_reply(answer, profile, profile.grammar_attr, data), program.text)
    return "document"


def _skeleton(model: FileModel) -> list[tuple[Any, ...]]:
    return [
        (model.kind(i), model.parent(i), model.field(i), model.span(i), model.line(i),
         model.ident(i), model.literal(i))
        for i in range(model.node_count)
    ]


def _run(program: _Program) -> tuple[list[tuple[Any, ...]], dict[str, tuple[Any, ...]]]:
    """One run: a fresh parse, its skeleton and the candidates of every family (``Flow`` is
    a frozen dataclass, so two runs compare by value, origin sets order-free)."""
    model = model_of(program.text, program.lang)
    return _skeleton(model), {family: tuple(candidates_of(model, family)) for family in FAMILIES}


# ── the generator's premise ──────────────────────────────────────────────────


def test_the_generator_vocabulary_is_not_vacuous() -> None:
    """The untainted draw reaches path and command sinks with no source mark among its
    words, and the tainted draw has sources and conditional roots to read."""
    voc, roles = _vocabulary(), roles_mod()
    path_sinks, command_keys = _flat(roles.SINK_WORDS["path"]), _flat(roles.COMMAND_STRONG)
    observed = {
        "source words": bool(voc.sources),
        "conditional roots": bool(voc.chains),
        "path sinks among the neutral words": not path_sinks.isdisjoint(voc.neutral),
        "command keys among the neutral words": not command_keys.isdisjoint(voc.neutral),
        "neutral words that carry a source mark": [w for w in voc.neutral if _marked(w, voc)],
    }
    assert observed == {
        "source words": True,
        "conditional roots": True,
        "path sinks among the neutral words": True,
        "command keys among the neutral words": True,
        "neutral words that carry a source mark": [],
    }


_PLANTED = (_Stmt("stmt", "v0 = req.query.f"), _Stmt("stmt", "readfile(v0)"))
_PLANTED_CLEAN = (_Stmt("stmt", 'v0 = "a"'), _Stmt("stmt", "readfile(v0)"))


@pytest.mark.parametrize("lang", _LANGUAGES)
def test_the_oracle_and_the_analysis_agree_on_a_planted_pair(lang: str) -> None:
    """The property's two sides on a fixed pair: ``req.query.f`` into the path sink
    ``readfile`` is a source token AND an external origin; a literal is neither."""
    voc = _vocabulary()
    texts = {"tainted": _text(_PLANTED, lang), "clean": _text(_PLANTED_CLEAN, lang)}
    observed = {
        name: (bool(_source_tokens(text, voc)), _external_sinks(model_of(text, lang)))
        for name, text in texts.items()
    }
    assert observed == {"tainted": (True, [("path", 2)]), "clean": (False, [])}


# ── the properties ───────────────────────────────────────────────────────────


@_PROPERTY
@given(data=st.data())
def test_the_pool_never_raises(data: st.DataObject) -> None:
    """``parse`` answers a document or a fallback reason, never an exception (§4)."""
    _, _, answer = _answer(data.draw(_programs(_vocabulary())))
    assert isinstance(answer, dict) or answer in _FALLBACKS, answer


@_PROPERTY
@given(data=st.data())
def test_every_worker_document_validates_or_falls_back(data: st.DataObject) -> None:
    """A document is admitted by ``validate_reply`` and builds a model; anything else is a
    named fallback reason (D3, §6.2)."""
    assert _admitted(data.draw(_programs(_vocabulary()))) in _FALLBACKS | {"document"}


@_PROPERTY
@given(data=st.data())
def test_no_external_origin_at_a_sink_without_a_source_token(data: st.DataObject) -> None:
    """No candidate of any family carries ``external`` unless the text holds a source-role
    token; an untainted program holds none (the generator's own check)."""
    voc = _vocabulary()
    program = data.draw(_programs(voc))
    tokens = _source_tokens(program.text, voc)
    unmarked = [] if tokens else _external_sinks(model_of(program.text, program.lang))
    observed = {
        "source tokens in an untainted program": [] if program.tainted else tokens,
        "external sinks with no source token": unmarked,
    }
    assert observed == {
        "source tokens in an untainted program": [],
        "external sinks with no source token": [],
    }


@_PROPERTY
@given(data=st.data())
def test_join_is_commutative(data: st.DataObject) -> None:
    """``join(Δa, Δb) == join(Δb, Δa)`` (§7.2): swapping the branches moves no origin."""
    case = data.draw(_join_cases(_vocabulary()))
    swapped = _sink_origins(case, _branch(case, case.b, case.a))
    assert _sink_origins(case, _branch(case, case.a, case.b)) == swapped


@_PROPERTY
@given(data=st.data())
def test_join_is_idempotent(data: st.DataObject) -> None:
    """``join(Δa, Δa) == Δa`` (§7.2): the same branch twice is that branch run once."""
    case = data.draw(_join_cases(_vocabulary()))
    assert _sink_origins(case, _branch(case, case.a, case.a)) == _sink_origins(case, case.a)


@_PROPERTY
@given(data=st.data())
def test_two_runs_are_equal(data: st.DataObject) -> None:
    """The same text parsed twice: the same skeleton and the same candidates (D14)."""
    program = data.draw(_programs(_vocabulary()))
    assert _run(program) == _run(program)
