"""Feature 0101 (LLD 4.6, RM-01) -- held-out fixtures must stay held out.

A held-out fixture scores a rule on idioms its lexicons were never tuned on. The
moment one of its API tokens is added to a lexicon, the score stops measuring
generalisation and starts measuring memorisation, and nothing else would notice.
Each held-out file declares the tokens its sites depend on
(``HELD-OUT-TOKENS: a, b``); this test fails if any declared token appears
literally -- as a whole token, case-insensitively -- in any 0101 lexicon:
every module-level string of ``_lexical`` and the three rule modules, found by
introspection: ``re.Pattern`` sources, plain ``str`` values (per-name pattern
templates), and the strings inside a ``frozenset``, ``set``, ``tuple`` or
``list`` (nested too) and the keys and values of a ``dict``. A module-level
``*_PREFIXES`` tuple is matched by PREFIX, as the rules read it: a declared token
that starts with one of its entries is a leak too.

It skips, with the reason, until the held-out fixtures exist (they are written
after the Phase 2 lexicon freeze, by an author who does not edit the rules).
"""
from __future__ import annotations

import importlib
import importlib.util
import itertools
import re
from pathlib import Path

import pytest

from tests.e2e._0101_markers import held_out_tokens

LEXICON_MODULES = (
    "cwe_agent.skills._lexical",
    "cwe_agent.skills.insufficient_logging_check",
    "cwe_agent.skills.resource_check",
    "cwe_agent.skills.info_exposure_check",
)
HELD_OUT_DIR = Path(__file__).resolve().parents[1] / "e2e" / "fixtures" / "0101_heldout"


_SEQUENCES = (frozenset, set, tuple, list)
_MAX_NESTING = 4


def _members(value: object) -> list[object]:
    """The direct members of a container (a dict gives its keys and its values)."""
    if isinstance(value, dict):
        return [*value.keys(), *value.values()]
    return list(value) if isinstance(value, _SEQUENCES) else []


def _own_text(value: object) -> str | None:
    """A string's text, or a pattern's source; None for anything else."""
    if isinstance(value, re.Pattern):
        return value.pattern
    return value if isinstance(value, str) else None


def strings_in(value: object, depth: int = 0) -> list[str]:
    """Every string a module-level value holds: itself, a pattern's source, or a
    container's members, nested up to _MAX_NESTING levels."""
    text = _own_text(value)
    if text is not None:
        return [text]
    if depth >= _MAX_NESTING:
        return []
    return list(itertools.chain.from_iterable(strings_in(m, depth + 1) for m in _members(value)))


_PRISTINE: dict[str, dict[str, object]] = {}


def _pristine(module_name: str) -> dict[str, object]:
    """The module's namespace as importing it leaves it, from a private fresh copy.

    The imported module's own namespace also holds RUNTIME state, per-file caches
    whose dicts and tuples carry the text of whatever was scanned last (in a full
    suite run, the held-out fixtures themselves). Only the import-time values are
    lexicons."""
    if module_name not in _PRISTINE:
        spec = importlib.util.find_spec(module_name)
        fresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh)
        _PRISTINE[module_name] = dict(vars(fresh))
    return _PRISTINE[module_name]


def _module_values(module_name: str) -> dict[str, object]:
    """Module-level names, without the dunders (`__doc__`, `__file__`)."""
    return {k: v for k, v in _pristine(module_name).items() if not k.startswith("__")}


# A finding title or message (`A `Result` discarded with `.ok()` ...`) is prose
# shown to a reader, never matched against code: three or more words separated by
# plain spaces. No lexicon entry or pattern source is written that way.
_PROSE = re.compile(r"(?:[A-Za-z`'.]{1,40} +){3}")


def _is_lexicon_text(text: str) -> bool:
    return _PROSE.search(text) is None


def _lexicon_texts(module_name: str) -> list[str]:
    texts = itertools.chain.from_iterable(map(strings_in, _module_values(module_name).values()))
    return list(filter(_is_lexicon_text, texts))


def lexicon_sources() -> dict[str, list[str]]:
    """Per module: every string any module-level value holds."""
    return {name: _lexicon_texts(name) for name in LEXICON_MODULES}


def _prefix_entries(module_name: str) -> list[str]:
    prefixed = (v for k, v in _module_values(module_name).items() if k.endswith("_PREFIXES"))
    return list(itertools.chain.from_iterable(map(strings_in, prefixed)))


def prefix_lexicons() -> dict[str, list[str]]:
    """Per module: the entries of its ``*_PREFIXES`` tuples, which the rules match by prefix."""
    return {name: _prefix_entries(name) for name in LEXICON_MODULES}


# A regex escape glues its letter to the token after it (`\\brunCatching`), so
# escapes are blanked before the whole-token test.
_REGEX_ESCAPE = re.compile(r"\\[A-Za-z]")


def token_hits(token: str, sources: dict[str, list[str]]) -> list[str]:
    """Modules whose lexicon contains ``token`` as a whole token (case-insensitive)."""
    rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])", re.IGNORECASE)
    return [mod for mod, texts in sources.items() if any(rx.search(_REGEX_ESCAPE.sub(" ", t)) for t in texts)]


def prefix_hits(token: str, prefixes: dict[str, list[str]]) -> list[str]:
    """Modules with a ``*_PREFIXES`` entry that ``token`` starts with (case-insensitive)."""
    low = token.lower()
    return [mod for mod, entries in prefixes.items() if _starts_with_any(low, entries)]


def _starts_with_any(low: str, entries: list[str]) -> bool:
    return any(low.startswith(e.lower()) for e in filter(None, entries))


def held_out_files() -> list[Path]:
    if not HELD_OUT_DIR.is_dir():
        return []
    return sorted(p for p in HELD_OUT_DIR.rglob("*") if p.is_file())


def test_lexicon_introspection_is_not_vacuous() -> None:
    sources = lexicon_sources()
    empty = [mod for mod, texts in sources.items() if not texts]
    assert not empty, f"no pattern or frozenset found by introspection in {empty}"


@pytest.mark.parametrize(
    ("token", "source", "hit"),
    [
        ("recv", r"\b(?:recv|read)\(", True),
        ("RECV", r"\b(?:recv|read)\(", True),
        ("rec", r"\b(?:recv|read)\(", False),
        ("consumer", "consume", False),
        ("consume", "consume", True),
        # A token right after a regex escape is still a whole token.
        ("runCatching", r"\brunCatching\s*\{", True),
        ("bsend", r"\bsend\(", False),
    ],
)
def test_token_matching_is_whole_token(token: str, source: str, hit: bool) -> None:
    assert token_hits(token, {"m": [source]}) == (["m"] if hit else [])


def _declared_pairs(files: list[Path]) -> list[tuple[str, str]]:
    return [(p.relative_to(HELD_OUT_DIR).as_posix(), t) for p in files for t in held_out_tokens(p)]


def _token_leaks(token: str, sources: dict[str, list[str]], prefixes: dict[str, list[str]]) -> list[str]:
    return sorted(set(token_hits(token, sources)) | set(prefix_hits(token, prefixes)))


def _leaks(files: list[Path], sources: dict[str, list[str]],
           prefixes: dict[str, list[str]]) -> dict[tuple[str, str], list[str]]:
    """``(file, token) -> modules`` for every declared token found in a lexicon."""
    found = {pair: _token_leaks(pair[1], sources, prefixes) for pair in _declared_pairs(files)}
    return {pair: hits for pair, hits in found.items() if hits}


def _undeclared(files: list[Path]) -> list[str]:
    return [p.relative_to(HELD_OUT_DIR).as_posix() for p in files if not held_out_tokens(p)]


def test_held_out_tokens_absent_from_every_lexicon() -> None:
    files = held_out_files()
    if not files:
        pytest.skip(f"no held-out fixtures yet under {HELD_OUT_DIR} (written after the lexicon freeze)")
    undeclared = _undeclared(files)
    assert not undeclared, f"held-out files without a HELD-OUT-TOKENS declaration: {undeclared}"
    leaks = _leaks(files, lexicon_sources(), prefix_lexicons())
    assert not leaks, f"held-out tokens found in a lexicon (the held-out score is void): {leaks}"


# Non-vacuity of the container walk: each container kind a lexicon can be held in
# yields its strings, so a token hidden in one of them is seen.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("NAME\\s{0,8}\\+=", ["NAME\\s{0,8}\\+="]),          # a per-name template held as str
        (re.compile(r"\brecv\("), [r"\brecv\("]),
        (frozenset({"take"}), ["take"]),
        ({"take"}, ["take"]),
        (("max", "limit"), ["max", "limit"]),
        (["drain"], ["drain"]),
        ({".ex": "elixir"}, [".ex", "elixir"]),               # dict keys AND values
        ((("timing", "safe"),), ["timing", "safe"]),          # a tuple of word pairs
        (({"k": ("deep",)},), ["k", "deep"]),
        (42, []),
    ],
)
def test_every_container_kind_yields_its_strings(value: object, expected: list[str]) -> None:
    assert sorted(strings_in(value)) == sorted(expected)


def test_container_walk_reaches_tuple_and_dict_lexicons_of_the_rules() -> None:
    sources = lexicon_sources()
    for module, sample in (("cwe_agent.skills.resource_check", "watermark"),
                           ("cwe_agent.skills.insufficient_logging_check", "kerberos")):
        assert module in token_hits(sample, sources), f"{sample} not seen in {module}"


@pytest.mark.parametrize(("token", "hit"), [("maxRows", True), ("MaxRows", True), ("rowmax", False)])
def test_prefix_lexicon_matches_by_prefix(token: str, hit: bool) -> None:
    assert prefix_hits(token, {"m": ["max"]}) == (["m"] if hit else [])


def test_rules_expose_prefix_lexicons() -> None:
    prefixes = prefix_lexicons()
    assert prefixes["cwe_agent.skills.resource_check"], "no *_PREFIXES tuple found in the CWE-770 rule"


@pytest.mark.parametrize(("text", "lexicon"), [
    ("A `Result` discarded with `.ok()` in statement position", False),
    ("Sensitive data written to log", False),
    ("max", True),
    (r"\bResult\s{0,4}<", True),
    (" ? ", True),
])
def test_prose_titles_are_not_lexicons(text: str, lexicon: bool) -> None:
    assert _is_lexicon_text(text) is lexicon


def test_runtime_cache_contents_are_not_lexicons() -> None:
    """A rule's per-file cache filled by a scan must not read as a lexicon."""
    from cwe_agent.skills import insufficient_logging_check as m

    probe = "zqxheldoutprobezq"
    m._TRY_CACHE[("probe", 0)] = ((f"  {probe}(x)",), -1)
    try:
        assert not token_hits(probe, lexicon_sources())
    finally:
        m._TRY_CACHE.pop(("probe", 0), None)
