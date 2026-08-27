"""AC15.1 — AST SHAPE guard against the flag-widening regex combinator (0078 F1).

WHAT IS BEING GUARDED
---------------------
The `_union` defect, in the form it actually shipped::

    flags = 0
    for p in patterns:
        flags |= p.flags & _SUPPORTED_UNION_FLAGS
    return re.compile("|".join(_wrap(p) for p in patterns), flags)

`|=` ORs every member's flags onto the COMBINED pattern, so one
``re.IGNORECASE`` member silently re-flags all of its case-SENSITIVE siblings.
Measured consequence: case-sensitive ``ECB\\b`` became case-insensitive and
matched plain ``ecb`` in ordinary identifiers (ECB is also the European Central
Bank in any FX or ledger codebase). Nothing raises; detection quality just
degrades.

WHY A SHAPE TEST AND NOT A GREP
-------------------------------
A name-based grep for ``_union`` / ``flags`` answers "is that one function still
wrong", not "has the shape come back somewhere else under another name". This
guard is keyed on the SHAPE only:

    a local that is aug-assigned with ``|=`` inside a function, and then handed
    to ``re.compile`` as its flags argument

so it fires regardless of what the variable, the function or the module is
called.

NON-VACUITY
-----------
A guard that passes because it can see nothing is indistinguishable from a
guard that works. Two committed tests exist to make the difference visible:

* `TestNonVacuity` feeds the pre-fix body AS A SOURCE STRING and asserts it is
  flagged — with no real file touched.
* `TestRealTreeIsClean` asserts a FLOOR on the number of files walked, so a
  walk that silently enumerates nothing fails instead of passing.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

# agents/shared/tests/unit/this_file.py -> agents/
AGENTS_ROOT = Path(__file__).resolve().parents[3]

#: Vendored / generated / fixture trees. Their contents are not ours to fix,
#: and a corpus fixture may contain the broken shape ON PURPOSE.
SKIP_PARTS = frozenset(
    {
        ".venv",
        "venv",
        "site-packages",
        "node_modules",
        "__pycache__",
        ".git",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "build",
        "dist",
        ".eggs",
        "corpus",
        "fixtures",
    }
)

#: Modules whose ``.compile(pattern, flags)`` takes regex flags positionally.
REGEX_MODULES = frozenset({"re", "regex"})

#: Enumerating fewer than this many files means the walk broke, not that the
#: tree got smaller. Measured at 554 files when this guard was written.
MIN_FILES_WALKED = 300

FIX_HINT = (
    "Fix: build the combined pattern with "
    "shared.tools.pattern_union.union_patterns(), which scopes each member's "
    "flags in its own inline '(?i:...)' group, instead of merging member flags "
    "into one flags argument with '|='."
)


@dataclass(frozen=True)
class Violation:
    """One flag-widening site, described so an operator can act on it."""

    path: str
    line: int
    function: str
    variable: str

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line}: function {self.function!r} ORs flags into "
            f"local {self.variable!r} with '|=' and then passes {self.variable!r} "
            "as the flags argument to re.compile. That WIDENS flags: every "
            "member's flags land on the combined pattern, so one IGNORECASE "
            "member re-flags its case-SENSITIVE siblings. " + FIX_HINT
        )


def _is_bitor_aug_assign(node: ast.AST) -> bool:
    """True for ``name |= ...`` (a bare local target, not a subscript/attr)."""
    return (
        isinstance(node, ast.AugAssign)
        and isinstance(node.op, ast.BitOr)
        and isinstance(node.target, ast.Name)
    )


def _bitor_aug_targets(func: ast.AST) -> set[str]:
    """Locals that are aug-assigned with ``|=`` anywhere inside `func`."""
    return {
        node.target.id for node in ast.walk(func) if _is_bitor_aug_assign(node)
    }


def _is_regex_compile(call: ast.Call) -> bool:
    """True for ``re.compile(...)`` / ``regex.compile(...)``."""
    func = call.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "compile"
        and isinstance(func.value, ast.Name)
        and func.value.id in REGEX_MODULES
    )


def _positional_flags_name(call: ast.Call) -> str | None:
    """Name passed as the SECOND positional argument, if it is a bare name."""
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Name):
        return call.args[1].id
    return None


def _keyword_flags_name(call: ast.Call) -> str | None:
    """Name passed as ``flags=`` — the same defect, spelled differently."""
    for keyword in call.keywords:
        if keyword.arg == "flags" and isinstance(keyword.value, ast.Name):
            return keyword.value.id
    return None


def _flags_argument_name(call: ast.Call) -> str | None:
    """Name handed to `re.compile` as its flags argument, if any."""
    return _positional_flags_name(call) or _keyword_flags_name(call)


def _widened_flag_name(node: ast.AST, widened: set[str]) -> str | None:
    """The widened local this node passes to `re.compile`, if it is one."""
    if not isinstance(node, ast.Call) or not _is_regex_compile(node):
        return None
    variable = _flags_argument_name(node)
    return variable if variable in widened else None


def _function_violations(func: ast.AST, name: str, path: str) -> list[Violation]:
    """Every widened-flags `re.compile` call inside one function."""
    widened = _bitor_aug_targets(func)
    if not widened:
        return []
    return [
        Violation(path, node.lineno, name, variable)
        for node in ast.walk(func)
        if (variable := _widened_flag_name(node, widened))
    ]


def violations_in_source(source: str, path: str = "<string>") -> list[Violation]:
    """Flag-widening sites in one module's source text."""
    tree = ast.parse(source)
    hits: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            hits.extend(_function_violations(node, node.name, path))
    return hits


def python_files(root: Path) -> list[Path]:
    """Every non-vendored ``*.py`` under `root`, sorted for stable output."""
    return sorted(
        path
        for path in root.rglob("*.py")
        if not (SKIP_PARTS & set(path.relative_to(root).parts))
    )


def walk_violations(root: Path) -> tuple[list[Violation], int]:
    """(violations, files_walked) for a whole tree."""
    hits: list[Violation] = []
    files = python_files(root)
    for path in files:
        rel = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            hits.extend(violations_in_source(source, rel))
        except SyntaxError:
            continue
    return hits, len(files)


# The pre-fix `_union` body, verbatim in shape, as a STRING. No repository file
# is mutated to prove this guard can fail.
PRE_FIX_UNION = '''
import re

_SUPPORTED_UNION_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL


def _union(patterns):
    """Combine patterns, preserving each one's flags."""
    flags = 0
    for p in patterns:
        flags |= p.flags & _SUPPORTED_UNION_FLAGS
    return re.compile("|".join(f"(?:{p.pattern})" for p in patterns), flags)
'''

# Same shape, nothing named `_union`, `flags` or `pattern`: the objection a
# name-based grep cannot answer.
PRE_FIX_UNION_RENAMED = '''
import re


def combine_detectors(members):
    accumulated = 0
    for member in members:
        accumulated |= member.flags
    return re.compile("|".join(m.pattern for m in members), flags=accumulated)
'''


class TestNonVacuity:
    """The guard must be SHOWN failing on the defect it exists to catch."""

    def test_flags_the_prefix_union_shape(self):
        hits = violations_in_source(PRE_FIX_UNION, "synthetic_union.py")
        assert len(hits) == 1, f"expected the pre-fix shape to be flagged, got {hits}"
        assert hits[0].function == "_union"
        assert hits[0].variable == "flags"

    def test_failure_message_names_the_fix(self):
        message = str(violations_in_source(PRE_FIX_UNION, "synthetic_union.py")[0])
        assert "union_patterns" in message
        assert "'|='" in message
        assert "synthetic_union.py" in message

    def test_flags_the_shape_under_different_names(self):
        hits = violations_in_source(PRE_FIX_UNION_RENAMED, "renamed.py")
        assert [h.function for h in hits] == ["combine_detectors"]
        assert hits[0].variable == "accumulated"

    def test_tree_walk_itself_flags_an_injected_copy(self, tmp_path):
        """Prove the FILE-WALKING path can fail, not only the string parser."""
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "combinator.py").write_text(PRE_FIX_UNION)
        hits, walked = walk_violations(tmp_path)
        assert walked == 1
        assert len(hits) == 1
        assert hits[0].path.endswith("combinator.py")

    def test_tree_walk_skips_vendored_trees(self, tmp_path):
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "vendored.py").write_text(PRE_FIX_UNION)
        (tmp_path / "clean.py").write_text("import re\nA = re.compile('a')\n")
        hits, walked = walk_violations(tmp_path)
        assert walked == 1, "vendored tree must not be walked"
        assert hits == []


class TestGuardDiscriminates:
    """Shapes that are NOT the defect must not be flagged."""

    def test_bitor_aug_assign_without_recompile_is_clean(self):
        source = "def f(cs):\n    seen = set()\n    for c in cs:\n        seen |= c\n    return seen\n"
        assert violations_in_source(source) == []

    def test_recompile_with_literal_flags_is_clean(self):
        source = (
            "import re\n"
            "def f(ps):\n"
            "    seen = 0\n"
            "    for p in ps:\n"
            "        seen |= p.flags\n"
            "    return re.compile('a', re.IGNORECASE)\n"
        )
        assert violations_in_source(source) == []

    def test_flags_parameter_that_is_never_widened_is_clean(self):
        source = "import re\ndef f(pattern, flags):\n    return re.compile(pattern, flags)\n"
        assert violations_in_source(source) == []

    def test_scoped_inline_flag_union_is_clean(self):
        """The shipped fix's shape: no flags argument at all."""
        source = (
            "import re\n"
            "def union(ps):\n"
            "    return re.compile('|'.join(f'(?i:{p.pattern})' for p in ps))\n"
        )
        assert violations_in_source(source) == []


class TestRealTreeIsClean:
    """AC15.1's second half: the shipped tree carries none of the shape."""

    def test_no_flag_widening_under_agents(self):
        hits, walked = walk_violations(AGENTS_ROOT)
        assert walked >= MIN_FILES_WALKED, (
            f"only {walked} python files walked under {AGENTS_ROOT} (floor "
            f"{MIN_FILES_WALKED}) — the guard is not seeing the tree, so a "
            "clean result would be meaningless. Check SKIP_PARTS and "
            "AGENTS_ROOT in this file."
        )
        assert not hits, "flag-widening regex combinator(s):\n" + "\n".join(
            str(h) for h in hits
        )

    def test_files_walked_is_reported(self, capsys):
        """Print the walk size so a shrinking walk is visible in -s output."""
        _, walked = walk_violations(AGENTS_ROOT)
        print(f"0078-F1: walked {walked} python files under {AGENTS_ROOT}")
        assert "0078-F1: walked" in capsys.readouterr().out
