#!/usr/bin/env python3
"""Report, per agent, the declared vs. actually-emitted `category` vocabulary.

Feature 0078 (AC15.2). The per-agent vocabulary table was written into a plan
document, and a table in a document is a claim frozen at the moment somebody
read the tree. This script recomputes the same table from the tree, so it is
reproducible on a clean checkout and cannot quietly go stale.

Four columns, and the first three are three DIFFERENT things -- conflating them
is the defect 0078 exists to answer:

  selector vocabulary   `ALL_CATEGORIES` (or `CATEGORY_IDS`) in the agent's
                        config.py. This is what a CALLER switches on in
                        config_schema; it says nothing about findings. Four of
                        six audited agents proved the two are unrelated.
  finding vocabulary    the `category_enum=` argument the agent passes to
                        `run_combined_audit`, i.e. the set findings are really
                        reduced to at the emission choke point. Only an agent
                        that passes it has DECLARED a finding vocabulary.
  emitted literals      the distinct string values of dict entries keyed
                        "category" under the agent's skills/ directory.
  dynamic sites         the `category` assignments whose value is NOT a string
                        constant in a dict display, so the literal column
                        cannot report them: `f"ASVS-{req_id}"`, a ternary,
                        `spec['category']`, `cat.slug`, or a
                        `out["category"] = x` subscript assignment. Each site
                        is COUNTED, and narrowed to a shape where that is
                        statically possible (an f-string's literal prefix
                        becomes `ASVS-*`; a ternary of literals becomes its
                        operands; anything else is `*`).

The emitted column is extracted by AST, never by a regex over source: a regex
matches the identical text inside a COMMENT or a DOCSTRING, and several skills
document the `"category": "CWE-N"` convention in prose. The first conformance
guard used a regex and flagged documentation as emission.

The dynamic-sites column exists because `(none)` for an agent that provably
emits a category is a FALSE CLAIM OF ABSENCE -- the same claim `declared_selector`
already refuses to make for a computed selector vocabulary. Two of ten agents
(asvs, owasp) build every category dynamically, so without it the report showed
the fleet's canonical declared-vs-emitted mismatch as clean, and a new agent
emitting `f"GDPR-{art}"` could pass every check by being invisible to all of
them.

`emitted_by_skills` is scoped to exactly `<agent>/skills/**/*.py`, which is the
scope `agents/shared/tests/unit/test_0078_finding_category_conformance.py`
checks -- that guard is the single source of truth for this view and
`test_0078_f2_vocab_reporter.py` asserts the two agree agent for agent. That is
exactly why the dynamic sites are SEPARATE fields (`emitted_shapes`,
`dynamic_sites`) rather than a widened `emitted_by_skills`: folding them in
would break that agreement invariant for a reason that has nothing to do with
either extractor. `test_0078_f2_dynamic_category_sites.py` pins both halves.
Literals found in the agent's other modules are reported separately, as
advisory context, under `emitted_outside_skills`.

Standard library only, no agent imports: it must run on a checkout with nothing
installed.

Usage:
    python scripts/report_category_vocabulary.py                 # table
    python scripts/report_category_vocabulary.py --json          # machine view
    python scripts/report_category_vocabulary.py --root DIR      # other tree
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parents[1] / "agents"

# Checked in order; the first module-level string list found wins. Two names
# because owasp declares its selector vocabulary as CATEGORY_IDS.
SELECTOR_NAMES = ("ALL_CATEGORIES", "CATEGORY_IDS")


# --------------------------------------------------------------------------
# AST primitives
# --------------------------------------------------------------------------

def _parse(path: pathlib.Path) -> ast.Module | None:
    """Parse a module, or None if it is absent or unparseable."""
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None


def _str_const(node: ast.expr | None) -> str | None:
    """The value of a string constant, else None."""
    if not isinstance(node, ast.Constant):
        return None
    return node.value if isinstance(node.value, str) else None


def _is_category_key(node: ast.expr | None) -> bool:
    """True for the literal key "category" (None is a ** expansion, not a key)."""
    return _str_const(node) == "category"


def _dict_category_nodes(node: ast.Dict) -> list[ast.expr]:
    """Every value expression in `node` keyed by the literal "category"."""
    return [v for k, v in zip(node.keys, node.values) if _is_category_key(k)]


def _dict_category_values(node: ast.Dict) -> set[str]:
    resolved = (_str_const(v) for v in _dict_category_nodes(node))
    return {text for text in resolved if text is not None}


def _walk(tree: ast.Module | None):
    return ast.walk(tree) if tree is not None else ()


def _tree_category_literals(tree: ast.Module | None) -> set[str]:
    out: set[str] = set()
    for node in _walk(tree):
        if isinstance(node, ast.Dict):
            out |= _dict_category_values(node)
    return out


# --------------------------------------------------------------------------
# dynamic sites: `category` assignments the literal view cannot report
# --------------------------------------------------------------------------

# Marker for a value that cannot be narrowed at all (`cat.slug`, `category`).
# Chosen so a shape can never be mistaken for an emitted literal, and so the
# tests can assert no shape leaked into `emitted_by_skills`.
_OPAQUE_SHAPE = "*"


def _joinedstr_shape(node: ast.expr) -> set[str] | None:
    """`f"ASVS-{req_id}"` -> {"ASVS-*"}; an f-string's prefix is static."""
    if not isinstance(node, ast.JoinedStr) or not node.values:
        return None
    prefix = _str_const(node.values[0])
    return {f"{prefix}{_OPAQUE_SHAPE}"} if prefix else None


def _ifexp_shape(node: ast.expr) -> set[str] | None:
    """`"CWE-798" if private else "CWE-200"` -> both operands, each resolved."""
    if not isinstance(node, ast.IfExp):
        return None
    return _dynamic_shapes(node.body) | _dynamic_shapes(node.orelse)


_SHAPE_RESOLVERS = (_joinedstr_shape, _ifexp_shape)


def _dynamic_shapes(node: ast.expr) -> set[str]:
    """Best-effort narrowing of one `category` value expression."""
    literal = _str_const(node)
    if literal is not None:
        return {literal}
    for resolve in _SHAPE_RESOLVERS:
        found = resolve(node)
        if found:
            return found
    return {_OPAQUE_SHAPE}


def _is_category_subscript(node: ast.expr) -> bool:
    """True for the assignment TARGET `x["category"]`."""
    return isinstance(node, ast.Subscript) and _is_category_key(node.slice)


def _dict_sites(node: ast.AST) -> list[ast.expr]:
    return _dict_category_nodes(node) if isinstance(node, ast.Dict) else []


def _assign_sites(node: ast.AST) -> list[ast.expr]:
    """`out["category"] = expr` -- an Assign, invisible to an ast.Dict walk."""
    if not isinstance(node, ast.Assign):
        return []
    if not any(_is_category_subscript(t) for t in node.targets):
        return []
    return [node.value]


def _hidden_sites(tree: ast.Module | None) -> list[ast.expr]:
    """Category value expressions the LITERAL view cannot report.

    That view is exactly "a string constant sitting in a dict display", so a
    site is hidden when it is anything else -- including a subscript assignment
    whose value IS a constant, because `_tree_category_literals` walks only
    `ast.Dict` and never sees it.
    """
    hidden: list[ast.expr] = []
    for node in _walk(tree):
        hidden += [v for v in _dict_sites(node) if _str_const(v) is None]
        hidden += _assign_sites(node)
    return hidden


def _tree_category_shapes(tree: ast.Module | None) -> tuple[set[str], int]:
    hidden = _hidden_sites(tree)
    shapes: set[str] = set()
    for node in hidden:
        shapes |= _dynamic_shapes(node)
    return shapes, len(hidden)


def category_shapes(source: str) -> tuple[set[str], int]:
    """Shapes and site count for the `category` sites hidden from the literal
    view, via AST -- so an f-string in a comment or docstring counts as
    nothing."""
    return _tree_category_shapes(ast.parse(source))


def category_literals(source: str) -> set[str]:
    """Literal `category` values in dict displays in `source`, via AST.

    Mirrors `_category_literals` in the conformance guard; a test pins the two
    to the same answer on the real tree.
    """
    return _tree_category_literals(ast.parse(source))


def _name_of(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _assign_parts(stmt: ast.stmt) -> tuple[str | None, ast.expr | None]:
    """Name and value of a single-target module-level assignment."""
    if isinstance(stmt, ast.AnnAssign):
        return _name_of(stmt.target), stmt.value
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        return _name_of(stmt.targets[0]), stmt.value
    return None, None


def _string_list(node: ast.expr | None) -> list[str] | None:
    """The elements of a list/tuple/set display of string constants."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for element in node.elts:
        value = _str_const(element)
        if value is None:
            return None
        values.append(value)
    return values


def _module_assignments(tree: ast.Module | None) -> dict[str, ast.expr]:
    out: dict[str, ast.expr] = {}
    for stmt in tree.body if tree is not None else []:
        name, value = _assign_parts(stmt)
        if name is not None and value is not None:
            out[name] = value
    return out


def _string_lists(symbols: dict[str, ast.expr]) -> dict[str, list[str]]:
    resolved = ((name, _string_list(expr)) for name, expr in symbols.items())
    return {name: values for name, values in resolved if values is not None}


# --------------------------------------------------------------------------
# the three columns
# --------------------------------------------------------------------------

def declared_selector(symbols: dict[str, ast.expr]) -> dict:
    """The selector column.

    `selector_vocabulary` is None when the declaration is COMPUTED rather than
    a literal display (owasp: `[f"A{n:02d}" for n in range(1, 11)]`). That is
    still a declaration, so the name and the expression are reported -- calling
    it "not declared" would be the same false claim this report exists to stop.
    """
    for name in SELECTOR_NAMES:
        if name in symbols:
            return {
                "selector_name": name,
                "selector_expr": ast.unparse(symbols[name]),
                "selector_vocabulary": _string_list(symbols[name]),
            }
    return {"selector_name": None, "selector_expr": None, "selector_vocabulary": None}


def _kwarg(node: ast.expr, name: str) -> ast.expr | None:
    if not isinstance(node, ast.Call):
        return None
    matches = [kw.value for kw in node.keywords if kw.arg == name]
    return matches[0] if matches else None


def _category_enum_expr(tree: ast.Module | None) -> ast.expr | None:
    """The `category_enum=` keyword argument, wherever it is passed."""
    for node in _walk(tree):
        found = _kwarg(node, "category_enum")
        if found is not None:
            return found
    return None


def _sorted_or_none(values: list[str] | None) -> list[str] | None:
    return sorted(set(values)) if values else None


def _resolve_values(
    expr: ast.expr, lists: dict[str, list[str]]
) -> list[str] | None:
    """Best-effort static value of a vocabulary expression."""
    direct = _string_list(expr)
    if direct is not None:
        return _sorted_or_none(direct)
    if isinstance(expr, ast.Name):
        return _sorted_or_none(lists.get(expr.id))
    if isinstance(expr, ast.Call) and expr.args:
        return _resolve_values(expr.args[0], lists)  # frozenset(X), set(X), ...
    return None


def declared_finding_vocabulary(
    agent_dir: pathlib.Path, lists: dict[str, list[str]]
) -> dict:
    """What the agent binds as `category_enum` at the emission choke point."""
    expr = _category_enum_expr(_parse(agent_dir / "agent.py"))
    if expr is None:
        return {"declared": False, "expr": None, "values": None}
    return {
        "declared": True,
        "expr": ast.unparse(expr),
        "values": _resolve_values(expr, lists),
    }


def emitted_categories(paths: list[pathlib.Path]) -> set[str]:
    out: set[str] = set()
    for path in paths:
        tree = _parse(path)
        if tree is not None:
            out |= _tree_category_literals(tree)
    return out


def emitted_shapes(paths: list[pathlib.Path]) -> tuple[set[str], int]:
    """Shapes and total site count over `paths`, for the hidden sites."""
    shapes: set[str] = set()
    total = 0
    for path in paths:
        found, count = _tree_category_shapes(_parse(path))
        shapes |= found
        total += count
    return shapes, total


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def discover_agents(root: pathlib.Path) -> list[pathlib.Path]:
    """Same glob as the conformance guard, so neither can see more agents."""
    return sorted(p for p in root.glob("*/[a-z]*_agent") if p.is_dir())


def _split_modules(
    agent_dir: pathlib.Path,
) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    skills_dir = agent_dir / "skills"
    inside, outside = [], []
    for path in sorted(agent_dir.rglob("*.py")):
        bucket = inside if skills_dir in path.parents else outside
        bucket.append(path)
    return inside, outside


def _emitted_columns(
    paths: list[pathlib.Path], literal_key: str, shapes_key: str, count_key: str
) -> dict:
    """The literal view and the dynamic view of one file scope.

    `emitted_by_skills` is the view the conformance guard is compared against,
    so it stays exactly the literal set; the dynamic sites are additive fields.
    """
    shapes, dynamic = emitted_shapes(paths)
    return {
        literal_key: sorted(emitted_categories(paths)),
        shapes_key: sorted(shapes),
        count_key: dynamic,
    }


def agent_report(agent_dir: pathlib.Path) -> dict:
    symbols = _module_assignments(_parse(agent_dir / "config.py"))
    inside, outside = _split_modules(agent_dir)
    return {
        "agent": f"{agent_dir.parent.name}/{agent_dir.name}",
        **declared_selector(symbols),
        "finding_vocabulary": declared_finding_vocabulary(
            agent_dir, _string_lists(symbols)
        ),
        "has_skills_dir": (agent_dir / "skills").is_dir(),
        **_emitted_columns(
            inside, "emitted_by_skills", "emitted_shapes", "dynamic_sites"
        ),
        **_emitted_columns(
            outside,
            "emitted_outside_skills",
            "emitted_shapes_outside_skills",
            "dynamic_sites_outside_skills",
        ),
    }


def build_report(root: pathlib.Path) -> dict:
    return {
        "root": str(root),
        "agents": [agent_report(p) for p in discover_agents(root)],
    }


def _fmt(values: list[str] | None, absent: str) -> str:
    return ", ".join(values) if values else absent


def _emitted_cell(literals: list[str], shapes: list[str], dynamic: int) -> str:
    """The emitted column. `(none)` ONLY when there is no site at all.

    An agent that builds every category as `f"ASVS-{req_id}"` has no literals
    and is not silent; printing `(none)` for it is a false claim of absence,
    which is the one thing this report exists to stop.
    """
    if not literals and not dynamic:
        return "(none)"
    head = _fmt(literals, "(no literals)")
    if not dynamic:
        return head
    plural = "" if dynamic == 1 else "s"
    return (
        f"{head}  [+{dynamic} dynamic site{plural}: "
        f"{_fmt(shapes, _OPAQUE_SHAPE)}]"
    )


def _render_agent(row: dict) -> list[str]:
    finding = row["finding_vocabulary"]
    declared = (
        f"{_fmt(finding['values'], '(unresolved statically)')}  "
        f"[category_enum={finding['expr']}]"
        if finding["declared"]
        else "(not declared -- findings are not reduced to any set)"
    )
    skills_note = "" if row["has_skills_dir"] else "  (no skills/ directory)"
    selector = _fmt(
        row["selector_vocabulary"],
        f"(computed: {row['selector_expr']})" if row["selector_name"] else "(none)",
    )
    return [
        row["agent"],
        f"  selector vocabulary  ({row['selector_name'] or 'not declared'}): "
        f"{selector}",
        f"  finding vocabulary   : {declared}",
        f"  emitted by skills    : "
        f"{_emitted_cell(row['emitted_by_skills'], row['emitted_shapes'], row['dynamic_sites'])}"
        f"{skills_note}",
        f"  emitted elsewhere    : "
        f"{_emitted_cell(row['emitted_outside_skills'], row['emitted_shapes_outside_skills'], row['dynamic_sites_outside_skills'])}",
        "",
    ]


def render(report: dict) -> str:
    lines = [
        f"category vocabulary report for {report['root']}",
        "selector vocabulary = config.py declaration a caller switches on;",
        "finding vocabulary  = category_enum bound at the emission choke point;",
        "emitted by skills   = AST-extracted \"category\" dict values under skills/;",
        "[+N dynamic sites]  = \"category\" assignments whose value is not a literal,",
        "                      narrowed to a shape where possible (ASVS-*), else *.",
        "",
    ]
    for row in report["agents"]:
        lines += _render_agent(row)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=DEFAULT_ROOT,
        help="agents/ directory to scan (default: this repo's)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        print(f"no such directory: {args.root}", file=sys.stderr)
        return 2
    report = build_report(args.root)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
