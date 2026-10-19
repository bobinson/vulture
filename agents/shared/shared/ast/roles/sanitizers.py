"""The sanitiser role lexicons, the coverage table of sanitiser roles, the two inverted indexes
and ``sanitizer_roles`` (feature 0102, LLD §8.2, §8.3, §8.5, §9.1; L1 (b), L12, P1, R4, R-Q,
A21, A27, A28).

Mode (b) of §9.1, like the guard lexicons: a callee's last identifier reaches sanitiser role r
when any of its ``words`` - or its glued key - is in r's WORD set (``secure_filename`` ->
``secure`` -> ``path_normalize``), and r of ``SANITIZER_KEYS`` when its glued key is an EXACT
key (R4: ``filepath.Base`` -> ``base``, ``parseInt`` -> ``parseint``). ``shell_quote`` is also
COMPOSED (R4) and ``host_allow`` composed (L12), never one word. A role the §8.2 sanitiser row
adds to ``via`` covers a family per ``COVERED_BY`` (§8.3).
"""

from __future__ import annotations

from collections.abc import Mapping
from itertools import chain
from types import MappingProxyType
from typing import TYPE_CHECKING

from shared.ast._nodes import union
from shared.ast.roles._words import glue, hits, invert, words
from shared.ast.roles.guards import (
    ALLOWLIST_WORDS,
    GUARD_INDEX,
    NO_ROLES,
    VALIDATE_WORDS,
    RoleIndex,
    SymbolOf,
    call_host_allow,
    callee_text,
    chain_names,
    held,
)

if TYPE_CHECKING:
    from shared.ast.model import FileModel

__all__ = [
    "CONTAINED_WORDS",
    "COVERED_BY",
    "FILE_NAME_WORDS",
    "KEY_ROLES",
    "PATH_RESULT_WORDS",
    "PLACE_WORDS",
    "QUOTE_WORDS",
    "SANITIZER_INDEX",
    "SANITIZER_KEYS",
    "SANITIZER_WORDS",
    "SHELL_CONTEXT_WORDS",
    "WORD_ROLES",
    "sanitizer_roles",
]

# ── the sanitiser lexicons (§9.1 mode (b); R4) ───────────────────────────────

SANITIZER_WORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    # normalize/abspath/realpath/clean/encode are NOT sanitisers (B7);
    # secure_filename -> secure, sanitizeFilename -> sanitize
    "path_normalize": frozenset({"basename", "secure", "sanitize", "sanitise", "slug", "slugify"}),
    "allowlist": ALLOWLIST_WORDS | {"choices"},
    "validate": VALIDATE_WORDS,  # recorded in `via`; covers no family (§8.3)
})  # no shell_quote / numeric WORDS (R4); no host_allow key (composed, guards.host_allow)
# R4: EXACT glued callee keys (language builtins).
SANITIZER_KEYS: Mapping[str, frozenset[str]] = MappingProxyType({
    # Go filepath.Base / path.Base; basePath(x) is not (basename: a word above)
    "path_normalize": frozenset({"base"}),
    # PHP builtins; every other shell_quote is COMPOSED (below)
    "shell_quote": frozenset({"escapeshellarg", "escapeshellcmd"}),
    # R-Q: Number(x), parseInt, strconv.Atoi; formatPhoneNumber is not
    "numeric": frozenset({
        "int", "float", "number", "parseint", "parsefloat", "atoi", "atol", "strtol", "toint",
        "tonumber", "integer", "isdigit", "isnumeric", "isdecimal",
    }),
})
# shell_quote is COMPOSED (R4): a QUOTE_WORDS word in the callee's last identifier AND a
# SHELL_CONTEXT_WORDS word in the callee or its receiver chain. shlex.quote, shell_escape,
# shellEscape: yes; escapeHtml, urllib.parse.quote, a bare quote(x): no. `shlex` is the Python
# standard library's shell-lexing module (a language builtin spelling, the §6.3 allowance),
# admitted ONLY here, as a context word - never as a role word.
QUOTE_WORDS = frozenset({"escape", "quote"})
SHELL_CONTEXT_WORDS = frozenset({"shell", "shlex", "cmd", "command", "arg", "args", "argv"})
# R-S (W12): a MEMBER read or a method CALL whose last identifier's words hold one of
# FILE_NAME_WORDS (`.name`, `.stem`, `file_name()`, `getFileName()`), on the result of a CALL
# whose chain words hold one of PATH_RESULT_WORDS, adds `path_normalize` to `via`.
FILE_NAME_WORDS = frozenset({"name", "stem"})
PATH_RESULT_WORDS = frozenset({"path"})
# A44 (1) (d) (ii): a CALL returning a containment-checked path is a `path_normalize` sanitiser
# by COMPOSITION - a CONTAINED_WORDS word AND a PLACE_WORDS word in its callee's last identifier
# (`resolveWithinRoot`, `resolveSafeInstallDir`), never one word alone (`safe_name`,
# `rootPath`).
CONTAINED_WORDS = frozenset({"within", "inside", "safe", "sandbox"})
PLACE_WORDS = frozenset({"path", "dir", "root"})

# ── coverage (§8.3; defined here, once, A27 (5)) ─────────────────────────────

# The sanitiser roles in `via` that cover each family: covered(o, family) iff o is external and
# o.via meets COVERED_BY[family]. `numeric` is listed for every family (R-Q), although the
# numeric row of §8.2 already makes the value constant (A28). Nothing covers a request by parsing
# it: there is no `url_parse` role (L5, P3).
COVERED_BY: Mapping[str, frozenset[str]] = MappingProxyType({
    "path": frozenset({"path_normalize", "numeric"}),
    "request": frozenset({"host_allow", "numeric"}),
    "command": frozenset({"shell_quote", "allowlist", "numeric"}),
})

# ── the inverted indexes (§9.1; derived once) ────────────────────────────────

SANITIZER_INDEX = RoleIndex(invert(SANITIZER_WORDS), invert(SANITIZER_KEYS))
# word -> frozenset(roles): a role test is <= MAX_WORDS dict probes + one for the glued key.
WORD_ROLES: Mapping[str, Mapping[str, frozenset[str]]] = MappingProxyType({
    "sanitizer": SANITIZER_INDEX.words,
    "guard": GUARD_INDEX.words,
})
# R4: EXACT glued CALL callee key -> frozenset(roles): one probe, exact membership only.
KEY_ROLES: Mapping[str, Mapping[str, frozenset[str]]] = MappingProxyType({
    "sanitizer": SANITIZER_INDEX.keys,
    "guard": GUARD_INDEX.keys,
})


def _shell_quote(model: FileModel, call: int, ident: str) -> bool:
    """R4's composition: a quote word in the callee's last identifier AND a shell context word
    in it or in its receiver chain (at most ``MAX_CHAIN`` x ``MAX_WORDS`` probes)."""
    if QUOTE_WORDS.isdisjoint(words(ident)):
        return False
    return hits(chain((ident,), chain_names(model, call)), SHELL_CONTEXT_WORDS)


def _contained(ident: str) -> bool:
    """A44 (1) (d) (ii): a containment word AND a place word in one identifier."""
    found = words(ident)
    return not CONTAINED_WORDS.isdisjoint(found) and not PLACE_WORDS.isdisjoint(found)


def sanitizer_roles(model: FileModel, call: int, *, symbol_of: SymbolOf = None) -> frozenset[str]:
    """The sanitiser roles of a CALL whose callee is no local FUNCTION (§8.5, A21): (1) the
    ``SANITIZER_WORDS`` roles its callee's last identifier reaches by a word or its glued key,
    (2) the ``SANITIZER_KEYS`` roles of its EXACT glued key, (3) ``shell_quote`` by composition,
    (4) ``host_allow`` when ``host_allow(model, call)`` holds and (5) ``path_normalize`` for a
    containment-checked path (A44 (1) (d) (ii)). Empty for a URL parse (L5).
    The callee identifier is resolved and glued once, for every test."""
    ident = callee_text(model, call, symbol_of)
    key = glue(ident)
    composed = held((
        ("shell_quote", _shell_quote(model, call, ident)),
        ("host_allow", call_host_allow(model, call, ident, key)),
        ("path_normalize", _contained(ident)),
    ))
    return union((SANITIZER_INDEX.of_glued(ident, key), composed), NO_ROLES)
