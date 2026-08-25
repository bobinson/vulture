"""ASVS delegates its pattern union to the shared leaf module.

Three separate contracts, because they can break independently:

1. DELEGATION — `asvs_requirements_check._union` IS
   `shared.tools.pattern_union.union_patterns`. Kept as a module-level name
   because the existing suite (`test_fp_union_flags_and_placeholders.py`)
   imports `_union` directly, and that suite is the business contract for the
   flag-widening fix.

2. BYTE-IDENTICAL OUTPUT for non-empty input. The shared version must produce
   the same pattern STRING as the per-member-scoped-flags algorithm the ASVS
   module shipped, for all eight real CWE pattern lists — so the extraction
   cannot change what any ASVS requirement detects. Checked against an
   independent re-implementation of that algorithm below, not against the
   shared function's own output.

3. CALLERS USE `search()` TRUTHINESS ONLY. Unioning RENUMBERS capture groups
   (member 2's group 1 becomes group N), so any caller reading `.group(n)` on
   a unioned pattern would read the WRONG group. This is verified structurally
   over the whole skill module's AST, so a future caller that starts reading
   groups fails here rather than silently mis-reporting.
"""
from __future__ import annotations

import ast
import importlib
import pathlib
import re

import pytest
from asvs_agent.skills import asvs_requirements_check as mod
from asvs_agent.skills._cwe_patterns import (
    BROKEN_CRYPTO_PATTERNS,
    COOKIE_NO_HTTPONLY_PATTERNS,
    COOKIE_NO_SECURE_PATTERNS,
    DEBUG_PROD_PATTERNS,
    HARDCODED_CRED_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    SESSION_FIXATION_PATTERNS,
    WEAK_RANDOM_PATTERNS,
)
from shared.tools.pattern_union import union_patterns

_REAL_LISTS = {
    "HARDCODED_CRED": HARDCODED_CRED_PATTERNS,
    "BROKEN_CRYPTO": BROKEN_CRYPTO_PATTERNS,
    "WEAK_RANDOM": WEAK_RANDOM_PATTERNS,
    "COOKIE_NO_HTTPONLY": COOKIE_NO_HTTPONLY_PATTERNS,
    "COOKIE_NO_SECURE": COOKIE_NO_SECURE_PATTERNS,
    "SESSION_FIXATION": SESSION_FIXATION_PATTERNS,
    "DEBUG_PROD": DEBUG_PROD_PATTERNS,
    "PATH_TRAVERSAL": PATH_TRAVERSAL_PATTERNS,
}

_SKILL_SRC = pathlib.Path(mod.__file__)


def _reference_union_pattern(patterns) -> str:
    """The ASVS-local algorithm, re-implemented independently.

    Per-member SCOPED inline flags — deliberately NOT calling the shared
    helper, so this is a real parity check rather than a tautology.
    """
    parts = []
    for p in patterns:
        meaningful = p.flags & ~re.UNICODE
        local = ""
        if meaningful & re.IGNORECASE:
            local += "i"
        if meaningful & re.MULTILINE:
            local += "m"
        if meaningful & re.DOTALL:
            local += "s"
        parts.append(f"(?{local}:{p.pattern})" if local else f"(?:{p.pattern})")
    return "|".join(parts)


class TestDelegation:
    def test_union_is_the_shared_function(self):
        assert mod._union is union_patterns

    def test_shared_module_is_a_leaf_import(self):
        # A LEAF: no import back into shared.* or asvs_*, so any pattern-based
        # skill in any agent can use it without risking an import cycle.
        module = importlib.import_module(union_patterns.__module__)
        tree = ast.parse(pathlib.Path(module.__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not [m for m in imported if m.startswith(("shared.", "asvs_"))], imported


class TestByteIdenticalForNonEmptyInput:
    @pytest.mark.parametrize("name", sorted(_REAL_LISTS))
    def test_real_list_pattern_string_is_unchanged(self, name):
        members = _REAL_LISTS[name]
        assert members, f"{name} is empty — parity check would be vacuous"
        assert union_patterns(members).pattern == _reference_union_pattern(members)

    @pytest.mark.parametrize("name", sorted(_REAL_LISTS))
    def test_real_list_flags_are_unchanged(self, name):
        # No flags on the COMBINED object: every flag is scoped per member.
        combined = union_patterns(_REAL_LISTS[name])
        assert combined.flags & ~re.UNICODE == 0

    def test_registry_unions_are_the_shared_output(self):
        pairs = [
            (mod._HARDCODED_CRED_UNION, HARDCODED_CRED_PATTERNS),
            (mod._BROKEN_CRYPTO_UNION, BROKEN_CRYPTO_PATTERNS),
            (mod._WEAK_RANDOM_UNION, WEAK_RANDOM_PATTERNS),
            (mod._COOKIE_NO_HTTPONLY_UNION, COOKIE_NO_HTTPONLY_PATTERNS),
            (mod._COOKIE_NO_SECURE_UNION, COOKIE_NO_SECURE_PATTERNS),
            (mod._SESSION_FIXATION_UNION, SESSION_FIXATION_PATTERNS),
            (mod._DEBUG_PROD_UNION, DEBUG_PROD_PATTERNS),
            (mod._PATH_TRAVERSAL_UNION, PATH_TRAVERSAL_PATTERNS),
        ]
        for built, members in pairs:
            assert built.pattern == _reference_union_pattern(members)


class TestNoRegistryPatternIsEmpty:
    """An empty registry pattern would now never match instead of flooding."""

    def test_every_check_pattern_is_non_degenerate(self):
        for req, spec in mod._CHECKS.items():
            pat = spec[0]
            assert pat.pattern != "", f"{req} has an everything-matching pattern"


class TestCallersUseSearchTruthinessOnly:
    """Group RENUMBERING is only harmless because nothing reads group N."""

    def test_no_match_group_accessor_anywhere_in_the_skill(self):
        tree = ast.parse(_SKILL_SRC.read_text())
        accessors = {"group", "groups", "groupdict", "lastindex", "lastgroup"}
        offenders = [
            (n.lineno, n.attr)
            for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr in accessors
        ]
        assert offenders == [], (
            "unioning renumbers capture groups; reading .group(n) on a union "
            f"reads the wrong group: {offenders}"
        )

    def test_registry_gate_returns_a_bool_not_a_match(self):
        spec = mod._CHECKS["V13.3.1"]
        out = mod._registry_entry_matches(
            spec, 'const token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";', ".ts"
        )
        assert out is True or out is False
