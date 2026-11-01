"""Feature 0102 plan task 2.2: the role lexicons, the two identifier normalisers and the role
predicates (LLD §8.3, §8.5, §9.1; L1, L2, L5, L12, P1-P3, R1-R4, R6, R9, W4, W9, W15 d, A10,
and the lead's rulings A21 and A27).

Three kinds of lexicon, never mixed (§9.1, L1 as restated by P1):

* (a) SINK-SIDE callee lexicons are stored GLUED and matched by the callee's glued key;
* (b) GUARD and SANITISER role lexicons are WORD lexicons of generic concept words, never a
  helper name; the short ambiguous words reach a role only as an EXACT glued callee key or
  inside a composition (R4: ``shell_quote``; L12: ``host_allow``);
* (c) WORD SETS (sources, carriers, receivers) are matched on ``roles.words``.

The tables are read from ``shared.ast.roles`` by their §9.1 names — every one defined there,
once, with ``COVERED_BY`` and ``COVERING_GUARDS`` (A27 (5)); the predicates take the model first
(A21) and are spelled once, in ``_analysis`` (``sanitizer_roles_of``, ``guard_roles_of``,
``host_allow_of``), over models built by a real worker. ``model_needed`` is the public
prefilter of §5 / §9.2, exported by ``shared.ast`` from its home ``roles`` (A27 (4)).

RED until ``shared.ast.roles`` exists: every test fails on its ``ModuleNotFoundError`` (the
``model_needed`` cases on the ``AttributeError`` of ``shared.ast.model_needed``). The
``*_on_fixtures`` and ``*_at_the_sink`` tests read flows, so they stay RED until
``shared.ast.flow`` (plan 2.3).
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from itertools import chain
from types import MappingProxyType, ModuleType
from typing import Any, NamedTuple

import pytest

from shared.ast import FileModel, _validate
from shared.ast.profile import PROFILES
from tests.unit.ast._analysis import (
    FAMILIES,
    call_at,
    candidates_of,
    entries,
    entries_of,
    fixture_model,
    flow_mod,
    guard_roles_of,
    host_allow_of,
    if_test,
    inner,
    judge,
    model_of,
    roles_mod,
    sanitizer_roles_of,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# ── the §9.1 tables, by kind ─────────────────────────────────────────────────

# Mode (a): the sink-side callee lexicons, stored glued (L1 (a)); A27 (6) names the §8.2 R-J
# merge keys MERGE_WORDS; A47 (2) (i)'s GENERIC_PATH_VERBS are path sink keys.
SINK_SIDE_TABLES = (
    "SINK_WORDS", "COMMAND_STRONG", "COMMAND_WEAK", "REQUEST_TERMINAL_WORDS",
    "COMMAND_BUILDER_WORDS", "OUTPUT_PARAM_WORDS", "EXIT_WORDS", "REQUEST_SINK_NO_POSITIONAL",
    "ACCESSOR_WORDS", "HANDLER_REGISTRATION_WORDS", "ITERATION_WORDS", "MERGE_WORDS",
    "GENERIC_PATH_VERBS",
)
# Mode (b): the guard and sanitiser WORD lexicons and the composition word sets (P1, R4, L12).
ROLE_WORD_TABLES = (
    "SANITIZER_WORDS", "GUARD_WORDS", "ALLOWLIST_WORDS", "VALIDATE_WORDS", "QUOTE_WORDS",
    "SHELL_CONTEXT_WORDS", "HOST_WORDS", "TRUST_WORDS", "ADDRESS_CLASS_WORDS",
)
# R4: the EXACT glued callee-key lexicons (language builtin spellings and single words).
EXACT_KEY_TABLES = ("MEMBERSHIP_KEYS", "EQUALITY_KEYS", "SANITIZER_KEYS", "GUARD_KEYS")
# Mode (c): the word sets, matched on ``roles.words`` (W4 adds TYPE_ANNOTATION_WORDS, A47 (2)
# (i) FILE_SYSTEM_WORDS).
WORD_SET_TABLES = (
    "SOURCE_WORDS", "CONDITIONAL_SOURCE_ROOTS", "PARAM_HINTS", "PARAM_ANNOTATION_WORDS",
    "TYPE_ANNOTATION_WORDS", "ROUTE_WORDS", "CALLBACK_PAYLOAD_WORDS", "RESPONSE_WORDS",
    "ACCESSOR_RECEIVER_WORDS", "REQUEST_CARRIER_WORDS", "COMMAND_CARRIER_WORDS",
    "COMMAND_RECEIVER_WORDS", "FILE_SYSTEM_WORDS",
)
# Derived once (W9 (a), §9.1) and the demotion record the lift test reads.
DERIVED_TABLES = ("SOURCE_CALL_KEYS", "SINK_SIDE_KEYS", "WORD_ROLES", "KEY_ROLES", "DEMOTED_WORDS")
# M4 literal values, compared lowercased: exempt from the entry shape (§9.1).
LITERAL_TABLES = ("FLAG_LITERALS", "SHELL_INTERPRETERS")
# Every table whose entries are words or glued keys: all but the M4 literal sets and the M2
# operator tables GUARD_OPERATORS / EQUALITY_OPERATORS.
WORD_TABLES = (
    *SINK_SIDE_TABLES, *ROLE_WORD_TABLES, *EXACT_KEY_TABLES, *WORD_SET_TABLES, *DERIVED_TABLES,
)
# §9.1: the shape of every such entry. A table's entries are read by ``_analysis.entries``
# (one reading of each table's shape, shared with the property module's source oracle).
ENTRY = re.compile(r"[a-z0-9]{2,32}")
# A27 (1): the ONE documented exception to the entry shape - ``w``, Go's conventional
# ``http.ResponseWriter`` parameter, kept in RESPONSE_WORDS.
ENTRY_EXCEPTIONS: Mapping[str, frozenset[str]] = MappingProxyType({"RESPONSE_WORDS": frozenset({"w"})})


def violations(items: Iterable[str], holds: Callable[[str], object]) -> list[str]:
    """The items for which ``holds`` is falsy, sorted: empty while a table rule is kept."""
    return sorted(item for item in items if not holds(item))


def tables_holding(word: str) -> list[str]:
    """The word tables of which ``word`` is an entry, in ``WORD_TABLES`` order."""
    return [name for name in WORD_TABLES if word in entries(name)]


# Every profile's builtin sinks (W5: glued single or pair keys), read from the profiles.
BUILTINS = tuple((key, sink) for p in PROFILES.values() for key, sink in p.builtin_sinks.items())
ALL_BUILTIN_KEYS = frozenset(key for key, _ in BUILTINS)


def builtin_keys(family: str) -> set[str]:
    """The builtin keys whose family set holds ``family`` (an EMPTY set is no sink, P4/R5)."""
    return {key for key, sink in BUILTINS if family in sink.families}


def model_needed(text: str, family: str) -> bool:
    """``shared.ast.model_needed`` (§5, §9.2): the public prefilter."""
    return bool(importlib.import_module("shared.ast").model_needed(text, family))


# ── role reads over real models ──────────────────────────────────────────────

# An IF whose TEST is the code under test, and a call statement, per language code.
_GUARD = MappingProxyType({
    "js": "if ({}) {{}}\n",
    "py": "if {}:\n    pass\n",
    "go": "package p\n\nfunc f() {{\n\tif {} {{\n\t}}\n}}\n",
    "java": "class A {{\n  void f() {{\n    if ({}) {{}}\n  }}\n}}\n",
    "php": "<?php\nif ({}) {{}}\n",
})
_STATEMENT = MappingProxyType({
    "js": "{};\n",
    "py": "{}\n",
    "go": "package p\n\nfunc f() {{\n\t{}\n}}\n",
    "java": "class A {{\n  void f() {{\n    {};\n  }}\n}}\n",
    "php": "<?php\n{};\n",
})


def guard_test(lang: str, test: str) -> tuple[FileModel, int]:
    """The model of ``if (test)`` in ``lang`` and its IF's TEST (what guard roles read)."""
    model = model_of(_GUARD[lang].format(test), lang)
    return model, if_test(model)


def call_node(lang: str, call: str) -> tuple[FileModel, int]:
    """The model of the statement ``call`` in ``lang`` and that CALL, by its head."""
    model = model_of(_STATEMENT[lang].format(call), lang)
    return model, call_at(model, call[: call.index("(")])


# kind -> (where the node comes from, what is read off it)
_ROLE_READS = MappingProxyType({
    "sanitizer": (call_node, sanitizer_roles_of),
    "guard": (guard_test, guard_roles_of),
})
_SHAPES = MappingProxyType({"test": guard_test, "call": call_node})


def roles_at(kind: str, lang: str, code: str) -> frozenset[str]:
    """``sanitizer_roles`` of the CALL ``code``, or ``guard_roles`` of ``if (code)``."""
    locate, read = _ROLE_READS[kind]
    return frozenset(read(*locate(lang, code)))


# ── entries and the two normalisers (§9.1, L1) ───────────────────────────────


@pytest.mark.parametrize("name", WORD_TABLES)
def test_every_entry_is_one_lowercase_word(name: str) -> None:
    """§9.1: every entry matches ``^[a-z0-9]{2,32}$`` (the M4 literal sets and the M2
    operator tables excepted, and A27 (1)'s one named exception) and is its own ``words()``,
    so a word-set lookup and a glued-key lookup are each one O(1) probe."""
    words = roles_mod().words
    found = entries(name)
    excepted = ENTRY_EXCEPTIONS.get(name, frozenset())
    assert found, f"{name} is empty"
    assert violations(found - excepted, ENTRY.fullmatch) == []
    assert violations(found, lambda entry: words(entry) == (entry,)) == []


def test_response_words_keep_w_as_the_one_exception_to_the_entry_shape() -> None:
    """A27 (1): ``w`` (Go's ``http.ResponseWriter``) stays in ``RESPONSE_WORDS``, and it is the
    only entry of any word table off the ``^[a-z0-9]{2,32}$`` shape."""
    off_shape = sorted(
        (name, entry) for name in WORD_TABLES for entry in violations(entries(name), ENTRY.fullmatch)
    )
    assert off_shape == [("RESPONSE_WORDS", "w")]


@pytest.mark.parametrize(
    ("ident", "expected"),
    [
        ("oauth2Token", ("oauth2", "token")),
        ("loadX509Cert", ("load", "x509", "cert")),
        ("HTTP2Server", ("http2", "server")),
        ("check_output", ("check", "output")),
        ("isTrustedHost", ("is", "trusted", "host")),
        ("secure_filename", ("secure", "filename")),
        ("$request", ("request",)),
    ],
)
def test_words_identities(ident: str, expected: tuple[str, ...]) -> None:
    """``roles.words`` is 0101's identifier splitter: digits stay with the letters before
    them (``oauth2Token`` -> ``oauth2``, ``token``); ``_`` and ``$`` split."""
    assert roles_mod().words(ident) == expected


def test_conditional_source_roots_are_no_flat_source_words() -> None:
    """W9 (b): a conditional root (``process``, ``event``, ``os`` ...) is a source only with
    its member word, so no root is also an entry of a flat ``SOURCE_WORDS`` set."""
    roles = roles_mod()
    assert sorted(set(roles.CONDITIONAL_SOURCE_ROOTS) & inner(roles.SOURCE_WORDS)) == []


@pytest.mark.parametrize(
    ("root", "member", "role"),
    [
        ("process", "env", "env"),
        ("process", "argv", "argv"),
        ("sys", "argv", "argv"),
        ("os", "environ", "env"),
        ("event", "body", "request"),
    ],
)
def test_conditional_source_roots_name_the_role(root: str, member: str, role: str) -> None:
    """W9 (b): ``CONDITIONAL_SOURCE_ROOTS`` is ``{root: {member word: role}}``; the member
    names the role (``process.env`` -> ``env``)."""
    assert roles_mod().CONDITIONAL_SOURCE_ROOTS[root][member] == role


def test_source_call_keys_are_reading_functions() -> None:
    """W9 (a): a CALL is a lexicon source by its glued key against ``SOURCE_CALL_KEYS`` -
    reading functions of the stdin/network/env sets, with that set's role. A request word
    names an object, never a reading function; ``socket`` is a request sink key."""
    roles = roles_mod()
    keys = roles.SOURCE_CALL_KEYS
    sinks = inner(roles.SINK_WORDS) | set(roles.COMMAND_STRONG) | set(roles.COMMAND_WEAK)
    facts = {
        "roles of input, getenv, recv": tuple(map(keys.get, ("input", "getenv", "recv"))),
        "request words keyed": sorted({"request", "socket"} & set(keys)),
        "roles outside stdin/network/env": sorted(set(keys.values()) - {"stdin", "network", "env"}),
        "keys outside their role's set": violations(keys, lambda k: k in roles.SOURCE_WORDS[keys[k]]),
        "sink keys": sorted(set(keys) & sinks),
    }
    assert facts == {
        "roles of input, getenv, recv": ("stdin", "env", "network"),
        "request words keyed": [],
        "roles outside stdin/network/env": [],
        "keys outside their role's set": [],
        "sink keys": [],
    }


def _sink_keys(roles: Any) -> set[str]:
    """A27 (2) ``SINK_KEYS``: the keys that make a CALL a sink."""
    sinks = inner(roles.SINK_WORDS) | set(roles.COMMAND_STRONG) | set(roles.COMMAND_WEAK)
    return sinks | ALL_BUILTIN_KEYS


def _reading_words(roles: Any) -> Iterator[tuple[str, str]]:
    """(word, role) for each stdin, network and env source word, in that role order."""
    return ((key, role) for role in ("stdin", "network", "env") for key in roles.SOURCE_WORDS[role])


def _reading_keys(roles: Any, sink_keys: set[str]) -> dict[str, str]:
    """A27 (2): the stdin, network and env source words, less ``sink_keys``, each keyed to its
    role (in that order, as §9.1's comprehension reads them)."""
    return {key: role for key, role in _reading_words(roles) if key not in sink_keys}


def test_source_call_keys_are_the_reading_words_minus_the_sink_keys() -> None:
    """A27 (2): ``SOURCE_CALL_KEYS = (SOURCE_WORDS stdin | network | env) - SINK_KEYS``, keyed
    to their role, where ``SINK_KEYS`` are the keys that make a CALL a sink - every
    ``SINK_WORDS`` set, ``COMMAND_STRONG``, ``COMMAND_WEAK`` and every profile's builtin sink
    keys - NOT every sink-side structural lexicon: ``input`` is an ``ACCESSOR_WORDS`` key
    (sink-side) and still reads ``stdin``."""
    roles = roles_mod()
    assert dict(roles.SOURCE_CALL_KEYS) == _reading_keys(roles, _sink_keys(roles))
    assert ("input" in roles.SINK_SIDE_KEYS, roles.SOURCE_CALL_KEYS["input"]) == (True, "stdin")


def test_type_annotation_words_exclude_value_types() -> None:
    """W4: ``TYPE_ANNOTATION_WORDS = PARAM_ANNOTATION_WORDS - {path, file, files, ip}``: those
    four name value types (``&Path``, ``*os.File``, ``net.IP``), never a request carrier."""
    roles = roles_mod()
    value_types = {"path", "file", "files", "ip"}
    assert value_types <= roles.PARAM_ANNOTATION_WORDS
    assert set(roles.TYPE_ANNOTATION_WORDS) == set(roles.PARAM_ANNOTATION_WORDS) - value_types


def test_demoted_words_carry_their_reason() -> None:
    """§9.1: a demoted word is recorded with its reason, and only so is it accepted by the
    lift test; ``user``, ``args`` and ``env`` are demoted."""
    demoted = roles_mod().DEMOTED_WORDS
    assert {"user", "args", "env"} <= set(demoted)
    assert violations(demoted, lambda word: isinstance(demoted[word], str)) == []
    assert violations(demoted, demoted.get) == []


# A27 (3): the regex-vocabulary tokens no lexicon holds. Each is demoted with a one-line reason
# (a library or module name - CWE rules are framework-agnostic; a builder or syntax token; a
# regex-alternation fragment whose glued callee is already a key; a config constant; a
# normalisation without containment, which proves nothing; not one of the three families).
DEMOTED_REGEX_TOKENS = (
    "ioutil", "httpx", "requests", "urllib", "Runtime", "Paths", "AllBytes", "Create", "String",
    "True", "bin", "new", "join", "BASE_DIR", "ROOT_DIR", "__dir__", "normpath", "eval",
)


@pytest.mark.parametrize("token", DEMOTED_REGEX_TOKENS)
def test_demoted_regex_tokens_enter_no_role_lexicon(token: str) -> None:
    """A27 (3): each token is accounted for by ``DEMOTED_WORDS`` (its glued form or one of its
    words, with a non-empty reason), and none enters a role lexicon: its glued form is no
    entry of a guard, sanitiser, composition or exact-key lexicon, and none of its words an
    entry of a role word lexicon."""
    roles = roles_mod()
    key, words = roles.glue(token), roles.words(token)
    reasons = [roles.DEMOTED_WORDS.get(part) for part in (key, *words)]
    role_words = entries_of(ROLE_WORD_TABLES)
    observed = {
        "demoted with a reason": any(reasons),
        "glued form in a role lexicon": key in role_words | entries_of(EXACT_KEY_TABLES),
        "words in a role word lexicon": sorted(role_words.intersection(words)),
    }
    assert observed == {
        "demoted with a reason": True,
        "glued form in a role lexicon": False,
        "words in a role word lexicon": [],
    }


# ── the regex vocabulary is lifted (§9.1) ────────────────────────────────────

# The cwe regex constants whose vocabulary the lexicons lift, and the skill module of each.
REGEX_TABLES = MappingProxyType({
    "PATH_TRAVERSAL_PATTERNS": "input_validation_check",
    "SAFE_PATH_PATTERNS": "input_validation_check",
    "_SSRF_TAINT": "injection_check",
    "_SSRF_SERVER_ONLY_PATTERNS": "injection_check",
    "COMMAND_INJECTION_PATTERNS": "injection_check",
    "SAFE_STATIC_CALL": "injection_check",
})
# §9.1: the lift test's stop-list.
LIFT_STOP_LIST = frozenset({"re", "sub", "exp", "com", "www", "sync"})
# A regex escape (``\b``, ``\s``, ``\.``) is syntax, never part of a token.
_ESCAPE = re.compile(r"\\.")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _regex_texts(value: Any) -> list[str]:
    """The pattern text of a regex constant: a string, a compiled pattern, or a list of them."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, re.Pattern):
        return [value.pattern]
    return [pattern.pattern for pattern in value]


def regex_tokens(name: str) -> set[str]:
    """The identifier tokens of the cwe regex constant ``name`` with at least three letters
    once glued (``fs``, ``os``, ``r`` drop out), escapes removed first."""
    module = importlib.import_module(f"cwe_agent.skills.{REGEX_TABLES[name]}")
    glue = roles_mod().glue
    texts = _regex_texts(getattr(module, name))
    tokens = chain.from_iterable(_IDENT.findall(_ESCAPE.sub(" ", text)) for text in texts)
    return {token for token in tokens if len(glue(token)) >= 3}


class Vocabulary(NamedTuple):
    """The lexicons a regex token is compared with, by match mode (§9.1)."""

    # The glued form ALONE: mode (a)'s sink-side callee keys (``checkoutput``), R4's exact
    # keys (``escapeshellarg``) and the lift test's stop-list.
    keys: frozenset[str]
    # A word or the glued form: modes (b) and (c), and the M4 literal values
    # (``secure_filename`` -> ``secure``, ``allowed_paths`` -> ``allowed``).
    words: frozenset[str]
    demoted: Mapping[str, str]  # word -> reason: a demoted word counts only with its reason


def vocabulary() -> Vocabulary:
    """The lexicons of ``shared.ast.roles``, by match mode."""
    roles = roles_mod()
    return Vocabulary(
        frozenset(roles.SINK_SIDE_KEYS) | entries_of(EXACT_KEY_TABLES) | LIFT_STOP_LIST,
        frozenset(entries_of((*ROLE_WORD_TABLES, *WORD_SET_TABLES, *LITERAL_TABLES))),
        roles.DEMOTED_WORDS,
    )


def lifted(text: str, vocab: Vocabulary) -> bool:
    """True when some lexicon, the demotion record or the stop-list accounts for ``text``."""
    roles = roles_mod()
    key = roles.glue(text)
    parts = {key, *roles.words(text)}
    return (
        key in vocab.keys
        or not vocab.words.isdisjoint(parts)
        or any(map(vocab.demoted.get, parts))
    )


@pytest.mark.parametrize("name", tuple(REGEX_TABLES))
def test_regex_vocabulary_lifted(name: str) -> None:
    """§9.1: every identifier token of the regex tier's pattern tables is in a lexicon, in
    ``DEMOTED_WORDS`` with its reason, or in the stop-list - compared by its glued form with
    the sink-side callee lexicons, by its words or glued form with the role and word-set
    lexicons, and by its glued form alone with the R4 exact-key lexicons. The AST tier can
    then miss no vocabulary the regex tier fires on."""
    vocab = vocabulary()
    tokens = regex_tokens(name)
    assert tokens, f"{name} yields no token"
    assert violations(tokens, lambda token: lifted(token, vocab)) == [], (
        f"{name}: tokens in no lexicon, not demoted with a reason and not stop-listed"
    )


# ── the prefilter (§5, §9.1 note 2, W15 d) ───────────────────────────────────


@pytest.mark.parametrize(
    ("text", "family", "expected"),
    [
        ("x = 1", "path", False),
        ("fs.readFile(p)", "path", True),
        # W15 d: a Java File constructor is reached through the profile's builtin key.
        ("class A { long f() { return new File(d, n).length(); } }", "path", True),
        # §9.1: the R-L term is the two characters $` on the raw text, never a bare $.
        ("const s=`${x}`;", "command", False),
        ("$scope.foo=1", "command", False),
        ("$`rm -rf ${d}`", "command", True),
    ],
)
def test_model_needed(text: str, family: str, expected: bool) -> None:
    """``model_needed(text, family)`` is False only when no sink of the family can exist."""
    assert model_needed(text, family) is expected


def test_model_needed_is_exported_from_its_home_in_roles() -> None:
    """A27 (4): ``model_needed`` is defined in ``shared.ast.roles`` (beside ``PREFILTER``) and
    ``shared.ast`` exports that same function."""
    package = importlib.import_module("shared.ast")
    assert package.model_needed is roles_mod().model_needed


def test_prefilter_is_one_pattern_per_family() -> None:
    """§9.1: ``PREFILTER[family]`` is ONE compiled alternation per family (``len == 3``),
    living in ``roles`` (A27 (4))."""
    prefilter = roles_mod().PREFILTER
    assert len(prefilter) == 3
    assert set(prefilter) == set(FAMILIES)
    assert all(isinstance(pattern, re.Pattern) for pattern in prefilter.values())


def family_keys(family: str) -> set[str]:
    """The glued keys whose presence must make ``family``'s parse happen (W15 d): its sink
    words, every profile's builtin keys of the family (a pair key holds its qualifier), and
    for ``request`` the terminal words, for ``command`` the strong prefixes and weak keys."""
    roles = roles_mod()
    extra = {
        "request": set(roles.REQUEST_TERMINAL_WORDS),
        "command": set(roles.COMMAND_STRONG) | set(roles.COMMAND_WEAK),
    }
    return set(roles.SINK_WORDS.get(family, ())) | builtin_keys(family) | extra.get(family, set())


@pytest.mark.parametrize("family", FAMILIES)
def test_prefilter_holds_every_sink_key(family: str) -> None:
    """W15 d: a substring test over the glued view that may over-include a parse but never
    skips one - every key of the family is found by its family's pattern."""
    pattern = roles_mod().PREFILTER[family]
    keys = family_keys(family)
    assert keys
    assert violations(keys, pattern.search) == []


# ── L1 (a): sink-side callee keys are glued ──────────────────────────────────


# L1 (a): identifier -> its glued key (lowercased, `_` and `$` removed).
GLUED = MappingProxyType({
    "check_output": "checkoutput",
    "startsWith": "startswith",
    "create_subprocess_shell": "createsubprocessshell",
    "$http_Get": "httpget",
})


def test_glued_callee_key() -> None:
    """L1 (a): one normaliser ``roles.glue`` (lowercased, ``_`` and ``$`` removed); every
    sink-side callee entry - sink, command strong/weak, builder/terminal, output-parameter,
    exit, accessor, registration, iteration, R-J merge and every profile builtin key - is in
    ``SINK_SIDE_KEYS`` and equals its own glue; ``checkOutput`` reaches ``COMMAND_STRONG``
    through ``checkoutput``, never through the words ``check``/``output``."""
    roles = roles_mod()
    strong = set(roles.COMMAND_STRONG)
    assert {ident: roles.glue(ident) for ident in GLUED} == GLUED
    facts = {
        "glue(checkOutput) in COMMAND_STRONG": roles.glue("checkOutput") in strong,
        "a word of checkOutput in COMMAND_STRONG": bool(set(roles.words("checkOutput")) & strong),
        "model_needed(check_output, command)": model_needed("subprocess.check_output(x)", "command"),
    }
    assert facts == {
        "glue(checkOutput) in COMMAND_STRONG": True,
        "a word of checkOutput in COMMAND_STRONG": False,
        "model_needed(check_output, command)": True,
    }


def test_glued_callee_key_every_sink_side_entry() -> None:
    """L1 (a): ``SINK_SIDE_KEYS`` holds every mode-(a) table (``MERGE_WORDS``, the R-J merge
    keys, among them, A27 (6)) and every profile builtin key, each stored glued (its own
    ``glue``)."""
    roles = roles_mod()
    sink_side = set(roles.SINK_SIDE_KEYS)
    assert violations(sink_side, lambda key: roles.glue(key) == key) == []
    missing = {name: sorted(entries(name) - sink_side) for name in SINK_SIDE_TABLES}
    missing["builtin keys"] = sorted(ALL_BUILTIN_KEYS - sink_side)
    assert missing == dict.fromkeys(missing, [])


def test_sink_words_rev9_additions_and_no_replace() -> None:
    """§9.1 ``REV9_GLUED_ADDITIONS`` merged (``fs::read_to_string``, ``fs::remove_file``) and
    R9: a string ``replace`` is no file operation, so it is no path sink word."""
    path = roles_mod().SINK_WORDS["path"]
    assert {"readtostring", "removefile"} <= set(path)
    assert "replace" not in path


# ── L1 (b), P1: guard and sanitiser lexicons hold concept words only ─────────

# (i) the retired helper keys: none is an entry of a role lexicon.
RETIRED_HELPER_KEYS = frozenset({
    "istrustedhost", "isprivateaddress", "hostisallowed", "gethost", "ssrfguard", "allowedhost",
    "safeurl", "safename", "securefilename", "sanitizefilename", "issafeurl", "ssrffilter",
    "urlhasallowedhostandscheme", "shlex", "shellwords", "isprivate", "isloopback", "isinternal",
})
RETIRED_KEY_TABLES = (
    "SANITIZER_WORDS", "SANITIZER_KEYS", "GUARD_WORDS", "GUARD_KEYS", "HOST_WORDS", "TRUST_WORDS",
    "ADDRESS_CLASS_WORDS",
)
# (ii) the closed, all-lowercase language builtin spellings a word lexicon may hold (§6.3)...
WORD_BUILTIN_SPELLINGS = frozenset({
    "startswith", "strpos", "indexof", "realpath", "abspath", "commonpath", "commonprefix",
    "inarray", "isalnum", "isalpha", "isdigit", "isinstance", "fullmatch",
})
# ... and the glued builtin spellings an R4 exact-key lexicon may hold beside single words.
KEY_BUILTIN_SPELLINGS = frozenset({
    "haskey", "hasownproperty", "containskey", "inarray", "equalsignorecase", "escapeshellarg",
    "escapeshellcmd", "parseint", "parsefloat", "atoi", "atol", "strtol", "toint", "tonumber",
    "isdigit", "isnumeric", "isdecimal",
})
CONCEPT_KEY_TABLES = ("MEMBERSHIP_KEYS", "EQUALITY_KEYS", "SANITIZER_KEYS")
# (iii) A47 (2) (i)'s concept tables: no entry glues two of their own entries or of the role
# lexicons (``filepath`` would: ``file`` + ``path``).
A47_CONCEPT_TABLES = ("GENERIC_PATH_VERBS", "FILE_SYSTEM_WORDS")


def _is_compound(entry: str, vocab: set[str]) -> bool:
    """``entry`` is two entries of ``vocab`` glued together (``trusted`` + ``host``)."""
    return any(entry[:i] in vocab and entry[i:] in vocab for i in range(2, len(entry) - 1))


def compounds(
    names: Iterable[str], allowed: frozenset[str], own: tuple[str, ...] = ()
) -> list[str]:
    """The entries of ``names``, builtin spellings ``allowed`` aside, that concatenate two
    entries of the role and exact-key lexicons (and of the ``own`` tables): a helper name, not
    a concept word."""
    vocab = entries_of((*ROLE_WORD_TABLES, *EXACT_KEY_TABLES, *own))
    return sorted(e for e in entries_of(names) - allowed if _is_compound(e, vocab))


def test_role_words_generic_no_helper_names() -> None:
    """L1 (b), P1, R4: (i) no retired helper key is an entry of a role lexicon, and ``shlex``
    is admitted ONLY as a ``SHELL_CONTEXT_WORDS`` context word; (ii) every role-lexicon entry
    is one concept word or a listed builtin spelling, and the R4 exact-key sets hold single
    words and listed builtin spellings - no other entry concatenates two entries; (iii) nor
    does an entry of A47 (2) (i)'s two concept tables, whose own entries count too."""
    facts = {
        "retired keys": {name: sorted(entries(name) & RETIRED_HELPER_KEYS) for name in RETIRED_KEY_TABLES},
        "tables holding shlex": tables_holding("shlex"),
        "compound role words": compounds(ROLE_WORD_TABLES, WORD_BUILTIN_SPELLINGS),
        "compound exact keys": compounds(CONCEPT_KEY_TABLES, KEY_BUILTIN_SPELLINGS),
        "compound A47 words": compounds(A47_CONCEPT_TABLES, frozenset(), A47_CONCEPT_TABLES),
    }
    assert facts == {
        "retired keys": dict.fromkeys(RETIRED_KEY_TABLES, []),
        "tables holding shlex": ["SHELL_CONTEXT_WORDS"],
        "compound role words": [],
        "compound exact keys": [],
        "compound A47 words": [],
    }


def _inverted(table: Mapping[str, Iterable[str]]) -> dict[str, frozenset[str]]:
    """``invert`` of §9.1: member -> the frozenset of the roles whose set holds it."""
    index: dict[str, set[str]] = {}
    for role, members in table.items():
        for member in members:
            index.setdefault(member, set()).add(role)
    return {member: frozenset(found) for member, found in index.items()}


@pytest.mark.parametrize(
    ("index", "kind", "source"),
    [
        ("WORD_ROLES", "sanitizer", "SANITIZER_WORDS"),
        ("WORD_ROLES", "guard", "GUARD_WORDS"),
        ("KEY_ROLES", "sanitizer", "SANITIZER_KEYS"),
        ("KEY_ROLES", "guard", "GUARD_KEYS"),
    ],
)
def test_role_words_generic_no_helper_names_inverted_index(
    index: str, kind: str, source: str
) -> None:
    """(iv): the inverted index ``WORD_ROLES`` answers each word, and ``KEY_ROLES`` each glued
    callee key, with ONE dict probe: derived once as ``invert`` of its lexicon."""
    roles = roles_mod()
    table = getattr(roles, index)
    assert set(table) == {"sanitizer", "guard"}
    assert isinstance(table[kind], Mapping)
    assert dict(table[kind]) == _inverted(getattr(roles, source))


@pytest.mark.parametrize(
    ("kind", "lang", "code", "role"),
    [
        ("sanitizer", "py", "secure_filename(x)", "path_normalize"),
        ("sanitizer", "js", "sanitizeFilename(x)", "path_normalize"),
        ("sanitizer", "py", "shlex.quote(x)", "shell_quote"),
        ("sanitizer", "js", "shellEscape(x)", "shell_quote"),
        ("sanitizer", "js", "parseInt(x)", "numeric"),
        ("guard", "py", "p.is_relative_to(root)", "path_contain"),
        ("guard", "js", "isValidPath(p)", "validate"),
    ],
)
def test_role_words_generic_no_helper_names_by_call(
    kind: str, lang: str, code: str, role: str
) -> None:
    """(iii): a helper reaches its role through its words (``secure``, ``sanitize``,
    ``relative``, ``valid``), the R4 ``shell_quote`` composition, or a builtin's exact key
    (``parseint``) - never through an entry of its own."""
    assert role in roles_at(kind, lang, code)


@pytest.mark.parametrize(
    "helper",
    ["secure_filename", "sanitizeFilename", "shellEscape", "is_relative_to", "isValidPath"],
)
def test_role_words_generic_no_helper_names_has_no_entry(helper: str) -> None:
    """(iii): the helpers above have no entry of their own: their glued key answers no
    ``WORD_ROLES`` or ``KEY_ROLES`` probe."""
    roles = roles_mod()
    key = roles.glue(helper)
    indexes = (*roles.WORD_ROLES.values(), *roles.KEY_ROLES.values())
    assert [index[key] for index in indexes if key in index] == []


# ── L12, P2, R1-R3, R6: host_allow is composed ───────────────────────────────


@pytest.mark.parametrize(
    ("shape", "lang", "code", "expected"),
    [
        # (a) a membership or equality role AND a host word
        ("test", "js", "ALLOWED.includes(new URL(u).hostname)", True),
        ("test", "py", "urlparse(u).hostname not in ALLOWED", True),
        ("test", "java", "TRUSTED_HOSTS.contains(URI.create(u).getHost())", True),
        ("test", "php", 'parse_url($u, PHP_URL_HOST) !== "x"', True),
        ("test", "php", "in_array(parse_url($u, PHP_URL_HOST), HOSTS)", True),
        ("test", "js", "!ALLOWED_HOSTS.includes(target)", True),  # R2: the plural `hosts`
        ("test", "java", '!host.equals("x")', True),  # R3: EQUALITY_KEYS
        ("test", "java", "host.equalsIgnoreCase(h)", True),
        # (b) one identifier with a trust word AND a host word
        ("test", "js", "isTrustedHost(u)", True),
        ("test", "py", "host_is_allowed(u)", True),
        ("test", "py", "url_has_allowed_host_and_scheme(u)", True),
        ("call", "js", "allowedHost(x)", True),  # the sanitiser call
        # (c) one identifier with an address-class word (R1: `reserved`, `ssrf` kept)
        ("test", "py", "is_private_address(u)", True),
        ("test", "py", "ip.is_private", True),
        ("test", "js", "addr.isLoopback", True),
        ("test", "py", "ip.is_reserved", True),
        ("test", "js", "ssrfGuard(u)", True),
        # bare truthiness on a host
        ("test", "js", "host", False),
        ("test", "js", "!new URL(u).hostname", False),
        ("test", "py", "not urlparse(u).netloc", False),
        # R3: presence comparisons
        ("test", "js", "u.hostname == null", False),
        ("test", "js", 'host === ""', False),
        ("test", "py", "host != None", False),
        ("test", "java", "host.equals(null)", False),
        # no host word
        ("test", "js", "isURL(u)", False),
        ("test", "py", "is_url(u)", False),
        ("test", "py", "is_safe_url(u)", False),  # R6: a known gap
        # no address-class word (R6: known gaps)
        ("test", "py", "is_link_local(ip)", False),
        ("test", "java", "addr.isSiteLocalAddress()", False),
        # no membership, trust or address word; R4: `has` is no word
        ("test", "js", "getHost(u)", False),
        ("test", "js", "hasHost(u)", False),
        # membership with no host word (`allowed` is a trust word, but of a NAME)
        ("test", "js", "ALLOWED.includes(name)", False),
        # a sink call
        ("call", "js", "fetch(host)", False),
    ],
)
def test_host_allow_composition(shape: str, lang: str, code: str, expected: bool) -> None:
    """L12: ``roles.host_allow`` holds iff (a) a membership/equality role meets a host word,
    (b) one callee or member identifier carries a trust word and a host word, or (c) one
    carries an address-class word; never for a bare truthiness test or a presence check."""
    assert host_allow_of(*_SHAPES[shape](lang, code)) is expected


def test_host_allow_sanitiser_call_is_a_sanitiser_role() -> None:
    """§8.5 sanitiser roles (4): ``host_allow`` joins ``sanitizer_roles`` of a CALL for which
    ``roles.host_allow`` holds (``allowedHost(x)``: trust + host word in one identifier)."""
    assert "host_allow" in roles_at("sanitizer", "js", "allowedHost(x)")


# ── L5, P3: a URL parse covers nothing ───────────────────────────────────────


def test_url_parse_covers_nothing() -> None:
    """L5, P3: there is no ``url_parse`` role - in neither coverage table (§8.3) nor a role
    lexicon - and no ``URL_PARSE_CALLEES``."""
    roles = roles_mod()
    for name in ("COVERED_BY", "COVERING_GUARDS", "SANITIZER_WORDS", "GUARD_WORDS"):
        table = getattr(roles, name)
        assert "url_parse" not in set(table) | inner(table), name
    assert not hasattr(roles, "URL_PARSE_CALLEES")


@pytest.mark.parametrize(
    ("lang", "code"),
    [
        ("js", "new URL(u)"),
        ("java", "URI.create(u)"),
        ("py", "urlparse(u)"),
        ("go", "url.Parse(u)"),
        ("php", "parse_url($u)"),
    ],
)
def test_url_parse_covers_nothing_by_call(lang: str, code: str) -> None:
    """L5: a URL parse neither sanitises nor guards: its sanitiser roles and the guard roles
    of a test made of it are empty."""
    assert roles_at("sanitizer", lang, code) == frozenset()
    assert roles_at("guard", lang, code) == frozenset()


@pytest.mark.parametrize(
    ("stem", "line"),
    [("cwe_918_java_1", 7), ("cwe_918_16", 5), ("cwe_918_17", 9)],
)
def test_url_parse_covers_nothing_on_fixtures(stem: str, line: int) -> None:
    """L5: ``new URL(t).openConnection()`` reports and records no ``sanitized:url_parse``;
    an ``isURL`` / ``is_url`` format check guards nothing, so the request sink reports."""
    verdict = judge(fixture_model(stem), "request")
    assert line in verdict.reported
    assert [label for label in verdict.declines if "url_parse" in label] == []


# ── L2: exact beats prefix ───────────────────────────────────────────────────

# R-N's strong keys: a COMMAND_STRONG prefix, and no exact weak or non-command entry.
STRONG_KEYS = ("execsync", "execa", "checkoutput", "createsubprocessshell")
# The non-command sink-side callee lexicons (§9.1 mode (a) minus the command ones).
NON_COMMAND_TABLES = tuple(t for t in SINK_SIDE_TABLES if not t.startswith("COMMAND_"))


def exact_non_strong_keys() -> set[str]:
    """``COMMAND_WEAK`` and every non-command callee entry: the keys a strong prefix never
    promotes (L2)."""
    builtins = ALL_BUILTIN_KEYS - builtin_keys("command")
    non_command = entries_of(NON_COMMAND_TABLES) | builtins
    return set(roles_mod().COMMAND_WEAK) | non_command


def strong_prefixed(key: str) -> bool:
    """``key`` starts with a ``COMMAND_STRONG`` entry (R-N's prefix match)."""
    return key.startswith(tuple(roles_mod().COMMAND_STRONG))


def test_exact_weak_beats_strong_prefix() -> None:
    """L2: ``execute`` is an exact ``COMMAND_WEAK`` key although ``exec`` is a strong prefix;
    ``execsync``, ``execa``, ``checkoutput`` and ``createsubprocessshell`` carry a strong
    prefix and are no exact weak or non-command entry, so R-N may promote them."""
    exact = exact_non_strong_keys()
    verdicts = {key: (strong_prefixed(key), key in exact) for key in (*STRONG_KEYS, "execute")}
    # (a COMMAND_STRONG prefix, an exact weak or non-command entry)
    assert verdicts == {**dict.fromkeys(STRONG_KEYS, (True, False)), "execute": (True, True)}
    assert "execute" in roles_mod().COMMAND_WEAK


# A handler whose first parameter is a request (R-C), the call under test on line 2.
_HANDLER = MappingProxyType({
    "js": "function h(req, res) {{\n  {};\n}}\n",
    "py": "def h(request):\n    {}\n",
})


def command_sink_lines(lang: str, call: str) -> list[int]:
    """The sink lines of the ``command`` candidates of a handler making ``call``."""
    model = model_of(_HANDLER[lang].format(call), lang)
    return [flow.sink_line for flow in candidates_of(model, "command")]


@pytest.mark.parametrize(
    ("lang", "call"),
    [
        ("js", "execSync(req.query.c)"),
        ("js", "execa(req.query.c)"),
        ("py", 'subprocess.check_output(request.args["c"])'),
        ("py", 'asyncio.create_subprocess_shell(request.args["c"])'),
    ],
)
def test_exact_weak_beats_strong_prefix_at_the_sink(lang: str, call: str) -> None:
    """R-N: a strong-prefixed glued key is a command sink with no strengthener."""
    assert 2 in command_sink_lines(lang, call)


def test_exact_weak_beats_strong_prefix_never_promotes_an_exact_key() -> None:
    """L2: no strong-prefixed key that is an exact weak or non-command callee entry is
    promoted - ``db.execute(req.query.c)`` (no strengthener) is no command sink."""
    demoted = sorted(filter(strong_prefixed, exact_non_strong_keys()))
    assert "execute" in demoted
    sunk = violations(demoted, lambda key: 2 not in command_sink_lines("js", f"db.{key}(req.query.c)"))
    assert sunk == []


# ── R4: the short ambiguous words are exact keys or compositions only ───────

SHORT_WORDS = frozenset({"has", "base", "escape", "quote", "number", "int"})
# (KEY_ROLES kind, exact glued callee key) -> the role its ONE probe answers (R4).
KEY_PROBES: Mapping[tuple[str, str], str] = MappingProxyType({
    ("sanitizer", "base"): "path_normalize",
    ("sanitizer", "escapeshellarg"): "shell_quote",
    **{("sanitizer", key): "numeric" for key in ("int", "number", "parseint", "atoi", "isdigit")},
    **{("guard", key): "allowlist" for key in ("has", "hasownproperty", "containskey", "includes")},
})


def key_roles(kind: str, key: str) -> frozenset[str]:
    """One ``KEY_ROLES`` probe: the roles of the exact glued callee ``key`` (none: empty)."""
    return frozenset(roles_mod().KEY_ROLES[kind].get(key, ()))


def test_short_words_exact_key_only() -> None:
    """R4: ``has``, ``base``, ``escape``, ``quote``, ``number`` and ``int`` are entries of no
    WORD set; each role is then the word-index probes plus ONE ``KEY_ROLES`` probe of the
    exact glued callee key."""
    word_sets = ("SANITIZER_WORDS", "GUARD_WORDS", "WORD_ROLES")
    in_words = {name: sorted(entries(name) & SHORT_WORDS) for name in word_sets}
    probes = {probe: role in key_roles(*probe) for probe, role in KEY_PROBES.items()}
    assert (in_words, probes) == (dict.fromkeys(word_sets, []), dict.fromkeys(KEY_PROBES, True))


@pytest.mark.parametrize(
    ("kind", "lang", "code", "role", "present"),
    [
        # membership by exact key
        ("guard", "js", "set.has(x)", "allowlist", True),
        ("guard", "js", "obj.hasOwnProperty(k)", "allowlist", True),
        ("guard", "java", "map.containsKey(k)", "allowlist", True),
        ("guard", "js", "ALLOWED.includes(x)", "allowlist", True),
        # `base`: the exact key, not the word
        ("sanitizer", "go", "filepath.Base(p)", "path_normalize", True),
        ("sanitizer", "go", "path.Base(p)", "path_normalize", True),
        # `escape` / `quote`: an exact builtin key, or with a shell context word
        ("sanitizer", "php", "escapeshellarg($x)", "shell_quote", True),
        ("sanitizer", "py", "shlex.quote(x)", "shell_quote", True),
        ("sanitizer", "py", "shell_escape(x)", "shell_quote", True),
        ("sanitizer", "js", "shellEscape([x])", "shell_quote", True),
        ("sanitizer", "js", "escapeHtml(x)", "shell_quote", False),
        ("sanitizer", "py", "urllib.parse.quote(x)", "shell_quote", False),
        ("sanitizer", "py", "quote(x)", "shell_quote", False),
        # `number` / `int`: exact keys only
        ("sanitizer", "js", "Number(x)", "numeric", True),
        ("sanitizer", "py", "int(x)", "numeric", True),
        ("sanitizer", "js", "parseInt(x)", "numeric", True),
        ("sanitizer", "java", "Integer.parseInt(x)", "numeric", True),
        ("sanitizer", "go", "strconv.Atoi(x)", "numeric", True),
        ("sanitizer", "py", "s.isdigit()", "numeric", True),
        ("sanitizer", "js", "formatPhoneNumber(x)", "numeric", False),
    ],
)
def test_short_words_exact_key_only_by_call(
    kind: str, lang: str, code: str, role: str, present: bool
) -> None:
    """R4: a short word reaches its role only as the exact glued callee key or inside the
    ``shell_quote`` composition."""
    assert (role in roles_at(kind, lang, code)) is present


@pytest.mark.parametrize(
    ("kind", "lang", "code", "expected"),
    [
        ("guard", "go", "strings.HasPrefix(p, root)", frozenset({"path_contain"})),
        ("guard", "js", "hasHost(u)", frozenset()),
        ("sanitizer", "js", "basePath(p)", frozenset()),
    ],
)
def test_short_words_exact_key_only_role_sets(
    kind: str, lang: str, code: str, expected: frozenset[str]
) -> None:
    """R4: Go ``strings.HasPrefix`` is ``{path_contain}`` only (by the word ``prefix``; ``has``
    is no word, so no membership and no ``command`` cover); ``hasHost`` and ``basePath`` have
    no role at all."""
    assert roles_at(kind, lang, code) == expected


# ── the tables the rulings fix (§8.3, §9.1; R1-R4, M2) ───────────────────────

_ALLOWLIST_AND_CONTAIN = frozenset({"allowlist", "path_contain"})
_MEMBERSHIP = frozenset({"has", "haskey", "hasownproperty", "contains", "includes", "inarray", "containskey"})
RULED_TABLES: Mapping[str, Any] = MappingProxyType({
    # A27 (6): §8.2's R-J merge keys, named MERGE_WORDS; §8.5's no-positional request keys.
    "MERGE_WORDS": frozenset({"assign", "merge", "extend", "defaults", "deepmerge"}),
    "REQUEST_SINK_NO_POSITIONAL": frozenset({
        "send", "ws", "websocket", "socket", "channel", "stream", "execute", "perform",
    }),
    "HOST_WORDS": frozenset({
        "host", "hosts", "hostname", "hostnames", "domain", "domains", "origin", "origins",
        "netloc", "authority",
    }),
    "TRUST_WORDS": frozenset({"trusted", "allowed", "allow", "permitted", "safe"}),
    "ADDRESS_CLASS_WORDS": frozenset({"private", "loopback", "internal", "reserved", "ssrf"}),
    "EQUALITY_OPERATORS": frozenset({"==", "===", "!=", "!=="}),
    "EQUALITY_KEYS": frozenset({"equals", "equalsignorecase"}),
    "MEMBERSHIP_KEYS": _MEMBERSHIP,
    "QUOTE_WORDS": frozenset({"escape", "quote"}),
    "SHELL_CONTEXT_WORDS": frozenset({"shell", "shlex", "cmd", "command", "arg", "args", "argv"}),
    "SANITIZER_KEYS": {
        "path_normalize": frozenset({"base"}),
        "shell_quote": frozenset({"escapeshellarg", "escapeshellcmd"}),
        "numeric": frozenset({
            "int", "float", "number", "parseint", "parsefloat", "atoi", "atol", "strtol", "toint",
            "tonumber", "integer", "isdigit", "isnumeric", "isdecimal",
        }),
    },
    "GUARD_KEYS": {"allowlist": _MEMBERSHIP},
    "GUARD_OPERATORS": {
        "in": _ALLOWLIST_AND_CONTAIN,
        "not in": _ALLOWLIST_AND_CONTAIN,
        "typeof": frozenset({"validate"}),
        "instanceof": frozenset({"validate"}),
    },
    "COVERED_BY": {
        "path": frozenset({"path_normalize", "numeric"}),
        "request": frozenset({"host_allow", "numeric"}),
        "command": frozenset({"shell_quote", "allowlist", "numeric"}),
    },
    "COVERING_GUARDS": {
        "path": frozenset({"path_contain", "allowlist", "validate"}),
        "request": frozenset({"host_allow"}),
        "command": frozenset({"allowlist", "validate", "shell_quote"}),
    },
})


def _plain(table: Any) -> Any:
    """A set as a frozenset; a table of sets as a dict of frozensets."""
    if isinstance(table, Mapping):
        return {key: frozenset(value) for key, value in table.items()}
    return frozenset(table)


@pytest.mark.parametrize("name", tuple(RULED_TABLES))
def test_ruled_tables_are_exact(name: str) -> None:
    """The tables a ruling fixes, exactly as §9.1 and §8.3 give them: R2's plural host words,
    R1's address classes, R3's equality, R4's exact keys and compositions, the M2 operator
    roles and the two coverage tables."""
    assert _plain(getattr(roles_mod(), name)) == RULED_TABLES[name]


def test_tables_are_defined_once_in_roles() -> None:
    """A27 (5): every §9.1 table, ``COVERED_BY`` and ``COVERING_GUARDS`` is defined ONCE, in
    ``shared.ast.roles``; ``flow`` imports them, so any table ``flow`` also names is the
    very object ``roles`` holds."""
    roles, flow = roles_mod(), flow_mod()
    assert {"COVERED_BY", "COVERING_GUARDS"} <= set(vars(roles))
    assert _redefined(flow, roles) == []


def _redefined(module: ModuleType, home: ModuleType) -> list[str]:
    """The UPPER_CASE names ``module`` binds to an object other than ``home``'s of that name."""
    named = sorted(set(vars(module)) & set(vars(home)))
    return [name for name in named if name.isupper() and vars(module)[name] is not vars(home)[name]]


def test_operator_tables_are_wire_tokens() -> None:
    """M2: the operator tables are keyed by tokens the wire carries (``OPERATOR_TOKENS``)."""
    roles = roles_mod()
    assert set(roles.GUARD_OPERATORS) <= _validate.OPERATOR_TOKENS
    assert set(roles.EQUALITY_OPERATORS) <= _validate.OPERATOR_TOKENS


# ── A10: one home each ───────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["glue", "words"])
def test_normalisers_are_defined_once_in_roles_words(name: str) -> None:
    """A10: ``glue``/``words`` are defined once, in ``shared/ast/roles/_words.py``; ``roles``
    re-exports them and ``model`` imports them from there."""
    home = importlib.import_module("shared.ast.roles._words")
    model = importlib.import_module("shared.ast.model")
    normaliser = getattr(home, name)
    assert normaliser.__module__ == "shared.ast.roles._words"
    assert getattr(roles_mod(), name) is normaliser
    assert getattr(model, name) is normaliser


@pytest.mark.parametrize(
    "name", ["SHELL_INTERPRETERS", "OPERATOR_TOKENS", "IDENTIFIER", "DECLARATION_KEYWORDS"]
)
def test_roles_reexports_the_wire_vocabulary(name: str) -> None:
    """A10: the wire vocabulary lives in ``_validate``; ``roles`` re-exports the same object
    rather than redefining it (the D16 identifier pattern is ``_validate.IDENTIFIER``)."""
    assert getattr(roles_mod(), name) is getattr(_validate, name)
