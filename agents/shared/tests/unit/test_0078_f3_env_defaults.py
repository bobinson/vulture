"""Feature 0078 Track F, guard **F3** (AC15.3) — a documented default must equal
the code default.

`env.example` is the only place most operators ever read the shipped defaults
from. It once documented ``VULTURE_LLM_MAX_BODY_BYTES=400000`` against a code
default of ``131072`` — and 400000 is a *different* setting's default
(``VULTURE_MAX_SOURCE_CHARS``) measured in CHARACTERS rather than bytes, and is
*above* the ~192KB body that produced the gateway 413 the control exists to
prevent. Uncommenting the documented line therefore disabled the protection it
appeared to configure. Nothing failed, because nothing checked.

This guard reads every default `env.example` STATES and compares it to what the
code actually falls back to.

What counts as a stated default (§15.4):

* a commented assignment at the left margin — ``# VAR=value`` (at most one space
  after the ``#``), and
* prose in that variable's own comment block — ``(default N)`` / ``Default N``.

What deliberately does not:

* the **KNOWN-GOOD PROFILES** block. Its values are *recommended overrides*, not
  default restatements — `PROFILE B` legitimately sets
  ``VULTURE_LLM_MAX_BODY_BYTES=400000`` for a local model with no gateway in
  front. Excluded **by structure**: every assignment in that block is indented
  under the ``#``. The exclusion is checked, not assumed
  (`test_profile_exclusion_is_structural_and_non_empty`).
* uncommented lines. Those are the values that become the operator's `.env`
  (ports, DB name, secrets); they are configuration, not a claim about a
  fallback.

Code defaults are resolved from the code, three ways, never transcribed:

1. ``_python_static_defaults()`` — AST scan of ``agents/**/*.py`` for the reader
   idioms (``_safe_int_env`` / ``_int_env`` / ``env_flag`` / ``env_truthy`` /
   ``os.getenv`` / ``os.environ.get``), resolving a named constant such as
   ``_DEFAULT_MAX_BODY_BYTES = 131072`` to its literal.
2. ``_explicit_resolvers()`` — for readers the scan cannot see through (an
   f-string var name, or a default that lives past an ``if env.isdigit()``).
   Each one CALLS the shipping reader with the environment cleared, so it
   reports the real fallback rather than a copy of it.
3. ``_go_defaults()`` — for the Go-side switches, the literal in the enclosing
   function of the ``os.Getenv`` call.

A stated default that none of the three can resolve is a FAILURE, not a skip
(`test_unresolvable_variable_fails_loudly`); the only way out is an
`ALLOWLIST` entry, which puts the exemption on the record.
"""

from __future__ import annotations

import ast
import itertools
import os
import pathlib
import re
import shutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import pytest

# ── repository layout ────────────────────────────────────────────────────────

REPO = pathlib.Path(__file__).resolve().parents[4]
ENV_EXAMPLE = REPO / "env.example"
AGENTS_DIR = REPO / "agents"
BACKEND_DIR = REPO / "backend"

# A parser that matches nothing passes forever. These floors are asserted.
MIN_STATED_DEFAULTS = 30
MIN_RESOLVED_DEFAULTS = 25
MIN_PROSE_DEFAULTS = 4
MIN_PROFILE_EXCLUSIONS = 8


# ── env.example parsing ──────────────────────────────────────────────────────

# An assignment LINE is "#", padding, VAR=<one token>, and then either nothing
# or a trailing "# ..." comment (PROFILE lines annotate their values that way).
# The trailing-comment requirement is what separates an assignment from a
# sentence that merely quotes one: "# VULTURE_LLM_FEED_PROSE=false: a credential
# in a README ..." is prose about the switch, not a statement of its default.
_ASSIGNMENT_LINE_RE = re.compile(
    r"^#(?P<pad>[ \t]*)(?P<var>[A-Z][A-Z0-9_]*)=(?P<val>\S*)(?:\s+#.*)?$"
)
# A stated default sits at the left margin: at most one space after the "#".
# Anything indented further is inside a PROFILE block (a recommended override).
_LEFT_MARGIN_PAD = frozenset({"", " "})
_PROSE_RES = (
    re.compile(r"\(default\s+(?P<v>[0-9][0-9_.]*|true|false)\b"),
    re.compile(r"\b[Dd]efaults?\s+(?P<v>[0-9][0-9_.]*|true|false)\b"),
)
_PROFILE_BANNER = "KNOWN-GOOD PROFILES"
_SECTION_BANNER_RE = re.compile(r"^# (-{3}|={3})")


@dataclass(frozen=True)
class Stated:
    """One default `env.example` states, and where it says it."""

    var: str
    value: str
    line: int
    kind: str  # "assignment" | "prose"

    def where(self) -> str:
        return f"env.example:{self.line} ({self.kind})"


def _prose_defaults(comment_block: Iterable[str]) -> list[str]:
    out: list[str] = []
    for line in comment_block:
        for pattern in _PROSE_RES:
            out += [m.group("v") for m in pattern.finditer(line)]
    return out


def parse_stated_defaults(text: str) -> list[Stated]:
    """Every default the file STATES, in file order.

    Only ``VULTURE_*`` is in scope (AC15.3); provider keys such as
    ``OPENAI_BASE_URL`` are examples, not Vulture defaults.
    """
    stated: list[Stated] = []
    block: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        match = _ASSIGNMENT_LINE_RE.match(line)
        if match and match.group("pad") in _LEFT_MARGIN_PAD:
            stated += _from_declaration(match, lineno, block)
            block = []
            continue
        if line.lstrip().startswith("#"):
            block.append(line)
        else:
            block = []  # a blank or uncommented line ends the comment block
    return stated


def _from_declaration(match: re.Match, lineno: int, block: list[str]) -> list[Stated]:
    var, value = match.group("var"), match.group("val").strip()
    if not var.startswith("VULTURE_"):
        return []
    out: list[Stated] = []
    if value:  # "# VAR=" states no value, so there is nothing to check
        out.append(Stated(var, value, lineno, "assignment"))
    out += [Stated(var, v, lineno, "prose") for v in dict.fromkeys(_prose_defaults(block))]
    return out


def _continues_profile_block(line: str) -> bool:
    """The block runs to the first non-comment line or the next section banner."""
    return line.startswith("#") and not _SECTION_BANNER_RE.match(line)


def profile_region(text: str) -> range:
    """Line range of the KNOWN-GOOD PROFILES block (1-indexed, end-exclusive)."""
    lines = text.splitlines()
    start = next((n for n, line in enumerate(lines, 1) if _PROFILE_BANNER in line), 0)
    if not start:
        return range(0, 0)
    body = itertools.takewhile(_continues_profile_block, lines[start:])
    return range(start, start + 1 + sum(1 for _ in body))


def excluded_commented_assignments(text: str) -> list[tuple[int, str, str]]:
    """Indented commented assignments — the ones the left-margin rule skipped."""
    out = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        match = _ASSIGNMENT_LINE_RE.match(raw.rstrip())
        if match and match.group("pad") not in _LEFT_MARGIN_PAD:
            out.append((lineno, match.group("var"), match.group("val")))
    return out


# ── code-default resolution: (1) Python AST scan ─────────────────────────────

_BARE_READERS = frozenset({"_safe_int_env", "_int_env", "env_flag", "env_truthy", "getenv"})
_UNRESOLVED = object()
# ``os.getenv(VAR, "")`` is an "env absent" sentinel, not a documented default:
# the real fallback is further down the function. Such a candidate is dropped so
# the variable falls through to an explicit resolver rather than comparing a
# stated "300000" against "".
_SENTINEL_DEFAULTS = ("",)


def _is_env_reader(func: ast.AST) -> str | None:
    """Reader name if this call reads the process environment, else None."""
    if isinstance(func, ast.Name):
        return func.id if func.id in _BARE_READERS else None
    if isinstance(func, ast.Attribute):
        return "getenv" if _is_environ_attribute(func) else None
    return None


def _is_environ_attribute(func: ast.Attribute) -> bool:
    """``os.getenv(...)`` or ``os.environ.get(...)``, and nothing else.

    Matching a bare ``.get`` would pull in every dictionary lookup whose key
    happens to start with ``VULTURE_``.
    """
    if func.attr == "getenv":
        return _is_name(func.value, "os")
    return func.attr == "get" and _is_os_environ(func.value)


def _is_name(node: ast.AST, ident: str) -> bool:
    return isinstance(node, ast.Name) and node.id == ident


def _is_os_environ(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "environ" and _is_name(node.value, "os")


def _literal(node: ast.AST, consts: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id]
    return _UNRESOLVED


def _constant_assignment(node: ast.AST) -> tuple[str, Any] | None:
    """``NAME = <literal>`` at module level, e.g. ``_DEFAULT_MAX_BODY_BYTES = 131072``."""
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    target = node.targets[0]
    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
        return target.id, node.value.value
    return None


def _module_constants(tree: ast.Module) -> dict[str, Any]:
    pairs = (_constant_assignment(node) for node in tree.body)
    return dict(p for p in pairs if p is not None)


def _reader_default(call: ast.Call, reader: str, consts: dict[str, Any]) -> Any:
    # env_truthy has no default parameter: absent means False, by construction.
    if reader == "env_truthy":
        return False
    if len(call.args) < 2:
        return _UNRESOLVED
    return _literal(call.args[1], consts)


def _vulture_var_name(call: ast.Call, consts: dict[str, Any]) -> str | None:
    """The ``VULTURE_*`` name this call reads, if it is a literal one."""
    var = _literal(call.args[0], consts) if call.args else None
    return var if isinstance(var, str) and var.startswith("VULTURE_") else None


def _usable_default(call: ast.Call, reader: str, consts: dict[str, Any]) -> Any:
    """The call's default, or ``_UNRESOLVED`` when it cannot stand in for one."""
    default = _reader_default(call, reader, consts)
    return _UNRESOLVED if default in _SENTINEL_DEFAULTS else default


def _call_env_default(call: ast.Call, consts: dict[str, Any]) -> tuple[str, Any] | None:
    """(var, code default) if this call is a ``VULTURE_*`` read with a default."""
    reader = _is_env_reader(call.func)
    var = _vulture_var_name(call, consts) if reader else None
    if var is None:
        return None
    default = _usable_default(call, reader, consts)
    return None if default is _UNRESOLVED else (var, default)


def _module_env_defaults(path: pathlib.Path) -> list[tuple[str, Any, str]]:
    """(var, default, site) for every resolvable env read in one module."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):  # pragma: no cover - fixture files
        return []
    consts = _module_constants(tree)
    out = []
    for node in ast.walk(tree):
        pair = _call_env_default(node, consts) if isinstance(node, ast.Call) else None
        if pair is not None:
            out.append((pair[0], pair[1], f"{path.relative_to(REPO)}:{node.lineno}"))
    return out


def _is_production_module(path: pathlib.Path) -> bool:
    return "tests" not in path.parts and not path.name.startswith("test_")


def _freeze_sites(
    found: dict[str, dict[Any, list[str]]],
) -> dict[str, dict[Any, tuple[str, ...]]]:
    return {var: {d: tuple(s) for d, s in by_value.items()} for var, by_value in found.items()}


@lru_cache(maxsize=1)
def _python_static_defaults() -> dict[str, dict[Any, tuple[str, ...]]]:
    """var -> {default_value: (site, ...)} from the agent tree's reader calls."""
    found: dict[str, dict[Any, list[str]]] = {}
    modules = (p for p in sorted(AGENTS_DIR.rglob("*.py")) if _is_production_module(p))
    for path in modules:
        for var, default, site in _module_env_defaults(path):
            found.setdefault(var, {}).setdefault(default, []).append(site)
    return _freeze_sites(found)


# ── code-default resolution: (2) explicit resolvers that call the reader ─────


class _ClearedVultureEnv:
    """Run a reader with every ``VULTURE_*`` removed, i.e. on pure defaults."""

    def __enter__(self) -> None:
        self._saved = {k: v for k, v in os.environ.items() if k.startswith("VULTURE_")}
        for key in self._saved:
            del os.environ[key]

    def __exit__(self, *exc: object) -> None:
        os.environ.update(self._saved)


Resolver = tuple[Callable[[], Any], str]


def _quote_knob_resolvers() -> dict[str, Resolver]:
    """The eight ``VULTURE_LLM_QUOTE_<NAME>`` numeric knobs.

    ``anchor._knob`` builds its variable name with an f-string, so no static
    scan can see it. Enumerated from ``anchor._KNOB_DEFAULTS`` so a ninth knob
    travels here without an edit, and resolved by CALLING ``_knob``.
    """
    from shared import anchor

    return {
        f"VULTURE_LLM_QUOTE_{name}": (
            (lambda n=name: anchor._knob(n)),
            f"agents/shared/shared/anchor.py _knob({name!r}) [called]",
        )
        for name in anchor._KNOB_DEFAULTS
    }


def _judge_resolvers() -> dict[str, Resolver]:
    """L5 judge knobs: env > ValidateConfig > module constant.

    The env read is ``os.getenv(VAR, "")`` and the fallback is past an
    ``isdigit()`` branch, so these are resolved by calling the resolver with a
    default-constructed config. The two timeouts are stated in MILLISECONDS and
    resolved in SECONDS — the conversion is written here rather than assumed,
    because a unit mix-up is the exact defect this guard exists for.
    """
    from shared.validate import llm_judge
    from shared.validate.types import ValidateConfig

    def cfg() -> ValidateConfig:
        return ValidateConfig()

    judge = "agents/shared/shared/validate/llm_judge.py"
    return {
        "VULTURE_VALIDATE_LLM_TOP_N": (
            lambda: llm_judge._resolve_top_n(cfg()),
            f"{judge} _resolve_top_n(ValidateConfig()) [called]",
        ),
        "VULTURE_VALIDATE_LLM_BATCH_SIZE": (
            lambda: llm_judge._resolve_batch_size(cfg()),
            f"{judge} _resolve_batch_size(ValidateConfig()) [called]",
        ),
        "VULTURE_VALIDATE_LLM_MAX_CONCURRENCY": (
            lambda: llm_judge._resolve_concurrency(cfg()),
            f"{judge} _resolve_concurrency(ValidateConfig()) [called]",
        ),
        "VULTURE_VALIDATE_LLM_TIMEOUT_MS": (
            lambda: llm_judge._resolve_total_timeout(cfg()) * 1000,
            f"{judge} _resolve_total_timeout(ValidateConfig()) x 1000 [seconds -> ms]",
        ),
        "VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS": (
            lambda: llm_judge._resolve_per_batch_timeout(cfg()) * 1000,
            f"{judge} _resolve_per_batch_timeout(ValidateConfig()) x 1000 [seconds -> ms]",
        ),
    }


@lru_cache(maxsize=1)
def _explicit_resolvers() -> dict[str, Resolver]:
    from shared import audit_runner
    from shared.tools import file_scanner

    resolvers: dict[str, Resolver] = {
        # Read as os.environ.get(VAR, "") + membership test: the "" is a
        # sentinel, so the real default is the reader's return on an empty env.
        "VULTURE_LLM_TIER3": (
            audit_runner._llm_tier3_enabled,
            "agents/shared/shared/audit_runner.py _llm_tier3_enabled() [called]",
        ),
        "VULTURE_LLM_FEED_PROSE": (
            file_scanner._llm_feed_prose,
            "agents/shared/shared/tools/file_scanner.py _llm_feed_prose() [called]",
        ),
        # Mode string, resolved by calling the reader on an empty env.
        "VULTURE_LLM_PREFLIGHT": (
            audit_runner._preflight_mode,
            "agents/shared/shared/audit_runner.py _preflight_mode() [called]",
        ),
    }
    resolvers.update(_quote_knob_resolvers())
    resolvers.update(_judge_resolvers())
    return resolvers


# ── code-default resolution: (3) the Go backend ──────────────────────────────

_GO_LITERAL_RE = re.compile(
    r"\breturn\s+(?P<ret>true|false|-?\d+)\b|\b[A-Z]\w*:\s+(?P<field>true|false|-?\d+),"
)


def _go_function_body(lines: list[str], hit: int) -> tuple[str, int]:
    start = next((j for j in range(hit, -1, -1) if lines[j].startswith("func ")), 0)
    end = next((j for j in range(start + 1, len(lines)) if lines[j] == "}"), len(lines))
    return "\n".join(lines[start:end]), start + 1


def _go_file_defaults(path: pathlib.Path, var: str) -> list[tuple[str, str]]:
    """(literal, site) for every literal in a func of ``path`` that reads ``var``."""
    lines = path.read_text(encoding="utf-8").splitlines()
    needle = f'os.Getenv("{var}")'
    out = []
    for idx, line in enumerate(lines):
        if needle not in line:
            continue
        body, func_line = _go_function_body(lines, idx)
        site = f"{path.relative_to(REPO)}:{func_line}"
        out += [(m.group("ret") or m.group("field"), site) for m in _GO_LITERAL_RE.finditer(body)]
    return out


@lru_cache(maxsize=None)
def _go_defaults(var: str) -> dict[str, tuple[str, ...]]:
    """{literal: (site, ...)} for literals in the func that reads ``var``."""
    found: dict[str, list[str]] = {}
    for path in sorted(BACKEND_DIR.rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        for literal, site in _go_file_defaults(path, var):
            found.setdefault(literal, []).append(site)
    return {k: tuple(v) for k, v in found.items()}


# ── comparison ───────────────────────────────────────────────────────────────

_TRUTHY = frozenset({"true", "1", "yes", "on"})
_FALSEY = frozenset({"false", "0", "no", "off", ""})


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).replace("_", ""))
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUTHY:
        return True
    if text in _FALSEY:
        return False
    return None


def values_agree(stated: str, code: Any) -> bool:
    """Does the documented token mean the same thing as the code's fallback?"""
    stated_bool = _as_bool(stated)
    if stated_bool is not None and _as_number(stated) is None:
        return _as_bool(code) is stated_bool
    stated_num, code_num = _as_number(stated), _as_number(code)
    if stated_num is not None and code_num is not None:
        return stated_num == code_num
    return stated.strip() == str(code).strip()


# ── exemptions, each one on the record ───────────────────────────────────────

ALLOWLIST: dict[str, str] = {
    "VULTURE_FINDING_IDENTITY": (
        "Go-side STRING mode switch (handler.findingIdentityMode, "
        "off|observe|enforce). Same limitation as VULTURE_FINDING_PATH_CANON "
        "below: _go_defaults resolves bool and int literals only. The default "
        "is pinned by TestFingerprintV2DefaultsToOff in "
        "backend/internal/handler/fingerprint_v2_test.go, which asserts the off "
        "default and the full parse table. Delete this entry if that Go test "
        "goes away."
    ),
    "VULTURE_FINDING_PATH_CANON": (
        "Go-side STRING mode switch (handler.pathCanonMode, off|observe|enforce). "
        "_go_defaults resolves bool and int literals only, so a string-valued "
        "switch resolves to nothing here. Widening _GO_LITERAL_RE to strings was "
        "tried and reverted: several string literals per function make "
        "_sole_candidate ambiguous and it broke eight tests in this file. The "
        "default is pinned instead by TestPathCanonDefaultsToOff in "
        "backend/internal/handler/path_canon_test.go, which asserts both the "
        "off default and the full parse table. Delete this entry if that Go "
        "test goes away."
    ),
    "VULTURE_LLM_CTX_SIZE": (
        "Example override, not a default restatement. There is no numeric code "
        "fallback for this var: llm/provider.py reads os.environ.get(name, '') and, "
        "when unset, falls through to the model table / 32K guess; the broker's "
        "ContextWindow() 0 is 'broker disabled', not a window. 262144 is shown "
        "because that is what a 256K local model needs behind a custom base URL."
    ),
    "VULTURE_SOURCE_DIR": (
        "docker-compose interpolation default (${VULTURE_SOURCE_DIR:-./}); it is "
        "read by compose, not by any Python or Go fallback, so there is no code "
        "default to agree with."
    ),
}


# ── the checker ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Violation:
    stated: Stated
    message: str


@dataclass(frozen=True)
class Report:
    violations: tuple[Violation, ...]
    stated: tuple[Stated, ...]
    resolved: tuple[str, ...]

    def summary(self) -> str:
        return "\n".join(f"  - {v.message}" for v in self.violations)


def _sole_candidate(var: str, found: dict[Any, tuple[str, ...]], kind: str) -> tuple[Any, str] | None:
    """The one code default, or a loud failure when the code has several."""
    if not found:
        return None
    if len(found) > 1:
        sites = "; ".join(f"{value!r} at {where[0]}" for value, where in found.items())
        raise AssertionError(
            f"{var}: {kind} disagree about the code default ({sites}). FIX: make them "
            f"share one default, or add {var} to _explicit_resolvers() in "
            f"{pathlib.Path(__file__).name} naming the authoritative reader."
        )
    (value, where), = found.items()
    return value, where[0]


def _resolve_called(var: str) -> tuple[Any, str] | None:
    """Ask the shipping reader itself, on a cleared environment."""
    resolvers = _explicit_resolvers()
    if var not in resolvers:
        return None
    reader, label = resolvers[var]
    with _ClearedVultureEnv():
        return reader(), label


def _resolve(var: str) -> tuple[Any, str] | None:
    """(code default, where it comes from), or None if the code has none."""
    return (
        _resolve_called(var)
        or _sole_candidate(var, _python_static_defaults().get(var, {}), "python readers")
        or _sole_candidate(var, _go_defaults(var), "go literals")
    )


def check(text: str, allowlist: Iterable[str] = tuple(ALLOWLIST)) -> Report:
    """Compare every stated default in ``text`` with the code's own fallback."""
    violations: list[Violation] = []
    resolved: list[str] = []
    exempt = frozenset(allowlist)
    for stated in parse_stated_defaults(text):
        if stated.var in exempt:
            continue
        found = _resolve(stated.var)
        if found is None:
            violations.append(Violation(stated, _unresolved_message(stated)))
            continue
        code, source = found
        resolved.append(stated.var)
        if not values_agree(stated.value, code):
            violations.append(Violation(stated, _mismatch_message(stated, code, source)))
    return Report(tuple(violations), tuple(parse_stated_defaults(text)), tuple(resolved))


def _mismatch_message(stated: Stated, code: Any, source: str) -> str:
    return (
        f"{stated.where()} documents {stated.var}={stated.value} but the code falls "
        f"back to {code!r} ({source}). FIX: change env.example to {code!r}, or change "
        f"the code default if the documented value is the intended one. Do not leave "
        f"them different — env.example is where operators read the default from."
    )


def _unresolved_message(stated: Stated) -> str:
    return (
        f"{stated.where()} states a default for {stated.var} but no code default "
        f"could be resolved. FIX: if a reader exists, add it to _explicit_resolvers() in "
        f"{pathlib.Path(__file__).name} so the value is checked against the code; if "
        f"the value is an example or a recommended override rather than a default, "
        f"add {stated.var} to that file's ALLOWLIST with the reason."
    )


# ── the guard ────────────────────────────────────────────────────────────────


def test_documented_defaults_equal_code_defaults() -> None:
    """AC15.3 — every default env.example states equals the code's fallback."""
    report = check(ENV_EXAMPLE.read_text(encoding="utf-8"))
    assert not report.violations, (
        "env.example disagrees with the code about "
        f"{len(report.violations)} default(s):\n{report.summary()}"
    )


# ── non-vacuity: the parser must actually see the file ───────────────────────


def _assert_floor(actual: int, floor: int, what: str, fix: str) -> None:
    assert actual >= floor, (
        f"only {actual} {what} (expected >= {floor}), so this guard is close to "
        f"vacuous. FIX: {fix}"
    )


def test_parser_examined_a_plausible_number_of_keys() -> None:
    """A parser that matches nothing would pass the guard above forever."""
    report = check(ENV_EXAMPLE.read_text(encoding="utf-8"))
    kinds = [s.kind for s in report.stated]
    _assert_floor(
        kinds.count("assignment"), MIN_STATED_DEFAULTS,
        "commented '# VAR=value' defaults parsed out of env.example",
        f"_ASSIGNMENT_LINE_RE in {pathlib.Path(__file__).name} has stopped matching "
        "the file's format.",
    )
    _assert_floor(
        kinds.count("prose"), MIN_PROSE_DEFAULTS,
        "'(default N)' prose defaults parsed",
        "_PROSE_RES no longer matches how env.example phrases defaults.",
    )
    _assert_floor(
        len(set(report.resolved)), MIN_RESOLVED_DEFAULTS,
        "variables compared against a resolved code default",
        "resolution is silently returning None; check _python_static_defaults, "
        "_explicit_resolvers and _go_defaults.",
    )


def test_resolution_reaches_all_three_mechanisms() -> None:
    """Static scan, called reader, and Go extraction must each resolve something.

    If one mechanism silently stops resolving, the variables it covered would
    become 'unresolved' — which fails loudly — but a future allowlist entry
    could paper over that. Pin one representative of each here.
    """
    static, _ = _resolve("VULTURE_LLM_MAX_BODY_BYTES")
    called, _ = _resolve("VULTURE_LLM_QUOTE_MIN_CHARS")
    go, _ = _resolve("VULTURE_DEDUP_PREFER_DETERMINISTIC")
    assert static == 131072, f"static AST scan resolved {static!r}, expected 131072"
    assert called == 24, f"anchor._knob('MIN_CHARS') resolved {called!r}, expected 24"
    assert _as_bool(go) is True, f"Go extraction resolved {go!r}, expected true"


def test_millisecond_defaults_are_compared_in_milliseconds() -> None:
    """The L5 timeouts are stated in ms and resolved in seconds.

    A wrong conversion here would make the guard compare 300000 against 300.0
    and fail on a correct file — or, with the factor on the wrong side, pass on
    a broken one. Pin the unit.
    """
    total, _ = _resolve("VULTURE_VALIDATE_LLM_TIMEOUT_MS")
    per_batch, _ = _resolve("VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS")
    assert total == 300000, total
    assert per_batch == 30000, per_batch


def test_profile_exclusion_is_structural_and_non_empty() -> None:
    """PROFILE overrides are excluded BY INDENTATION, and there really are some.

    The historical trap is the point: PROFILE B recommends
    ``VULTURE_LLM_MAX_BODY_BYTES=400000`` — legitimate for a local model with no
    gateway — while the code default is 131072. If that line were read as a
    default restatement the guard would fail on a correct file, so the exclusion
    must exist; if the exclusion were instead "match nothing", the guard would be
    vacuous. Both directions are pinned here.
    """
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    excluded = excluded_commented_assignments(text)
    assert profile_region(text), "the KNOWN-GOOD PROFILES banner is gone from env.example"
    _assert_floor(
        len(excluded), MIN_PROFILE_EXCLUSIONS,
        "indented commented assignments were excluded from the check",
        "the PROFILE block's formatting changed, so the structural exclusion no "
        "longer describes it.",
    )
    _assert_exclusions_sit_inside_a_profile(excluded, profile_region(text))
    _assert_profile_override_is_excluded(excluded)


def _assert_exclusions_sit_inside_a_profile(
    excluded: list[tuple[int, str, str]], region: range
) -> None:
    outside = [(line, var) for line, var, _ in excluded if line not in region]
    assert not outside, (
        f"commented assignments excluded from the check but sitting OUTSIDE the "
        f"KNOWN-GOOD PROFILES block: {outside}. FIX: un-indent them so they are "
        "checked as defaults, or move them into a PROFILE block."
    )


def _assert_profile_override_is_excluded(excluded: list[tuple[int, str, str]]) -> None:
    overrides = [val for _, var, val in excluded if var == "VULTURE_LLM_MAX_BODY_BYTES"]
    assert overrides == ["400000"], (
        "PROFILE B's VULTURE_LLM_MAX_BODY_BYTES=400000 override is no longer being "
        f"excluded by indentation (found: {overrides}); the guard would now fail on a "
        "correct file."
    )


# ── non-vacuity: injected mismatches, on a tmp copy only ─────────────────────


@pytest.fixture()
def env_copy(tmp_path: pathlib.Path) -> pathlib.Path:
    """A writable copy of env.example. The real file is never mutated."""
    dest = tmp_path / "env.example"
    shutil.copyfile(ENV_EXAMPLE, dest)
    return dest


def _inject(path: pathlib.Path, old: str, new: str) -> str:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"fixture drift: {old!r} is no longer in env.example"
    patched = text.replace(old, new, 1)
    path.write_text(patched, encoding="utf-8")
    return patched


def _violation_for(report: Report, var: str) -> Violation:
    hits = [v for v in report.violations if v.stated.var == var]
    assert hits, f"no violation reported for {var}; report={report.summary() or '(clean)'}"
    return hits[0]


def test_injected_numeric_mismatch_is_caught(env_copy: pathlib.Path) -> None:
    """The historical defect, reproduced: the byte cap documented as 400000.

    400000 is VULTURE_MAX_SOURCE_CHARS's default, in CHARACTERS. This is the
    exact edit that shipped once and was found by reading.
    """
    patched = _inject(
        env_copy,
        "# VULTURE_LLM_MAX_BODY_BYTES=131072",
        "# VULTURE_LLM_MAX_BODY_BYTES=400000",
    )
    violation = _violation_for(check(patched), "VULTURE_LLM_MAX_BODY_BYTES")
    assert "400000" in violation.message and "131072" in violation.message
    assert "FIX:" in violation.message
    assert ENV_EXAMPLE.read_text(encoding="utf-8") != patched, "the real file must be untouched"


def test_injected_prose_mismatch_is_caught(env_copy: pathlib.Path) -> None:
    """A '(default N)' sentence is checked too, not just the commented line."""
    patched = _inject(env_copy, "(default 32000)", "(default 99999)")
    violation = _violation_for(check(patched), "VULTURE_LLM_GATEWAY_GUESS_CTX")
    assert violation.stated.kind == "prose", violation.message
    assert "99999" in violation.message and "32000" in violation.message


def test_injected_boolean_flip_is_caught(env_copy: pathlib.Path) -> None:
    """A rollback switch documented with its default inverted."""
    patched = _inject(env_copy, "# VULTURE_LLM_JSON_SCAN=true", "# VULTURE_LLM_JSON_SCAN=false")
    violation = _violation_for(check(patched), "VULTURE_LLM_JSON_SCAN")
    assert "False" in violation.message or "false" in violation.message


def test_injected_go_side_mismatch_is_caught(env_copy: pathlib.Path) -> None:
    """The Go-side switches are checked against the Go source, not skipped."""
    patched = _inject(
        env_copy,
        "# VULTURE_DEDUP_PREFER_DETERMINISTIC=true",
        "# VULTURE_DEDUP_PREFER_DETERMINISTIC=false",
    )
    violation = _violation_for(check(patched), "VULTURE_DEDUP_PREFER_DETERMINISTIC")
    assert "stream_handler.go" in violation.message, violation.message


def test_injected_unit_confusion_is_caught(env_copy: pathlib.Path) -> None:
    """A ms knob documented with its second-valued constant (300 for 300000)."""
    patched = _inject(
        env_copy,
        "# VULTURE_VALIDATE_LLM_TIMEOUT_MS=300000",
        "# VULTURE_VALIDATE_LLM_TIMEOUT_MS=300",
    )
    violation = _violation_for(check(patched), "VULTURE_VALIDATE_LLM_TIMEOUT_MS")
    assert "300000" in violation.message


def test_profile_indentation_decides_and_nothing_else() -> None:
    """Same variable, same wrong value: indented is exempt, left-margin is not."""
    exempt = (
        "# ─── KNOWN-GOOD PROFILES ───\n"
        "# PROFILE B — local model\n"
        "#     VULTURE_LLM_MAX_BODY_BYTES=400000\n"
    )
    stated = "# VULTURE_LLM_MAX_BODY_BYTES=400000\n"
    assert not check(exempt).violations, "an indented PROFILE override must be exempt"
    assert _violation_for(check(stated), "VULTURE_LLM_MAX_BODY_BYTES")


def test_unresolvable_variable_fails_loudly() -> None:
    """A stated default with no code default must FAIL, never be skipped.

    This is what stops the guard from decaying: a knob added to env.example but
    never read by any code, or read through an idiom the resolver cannot see,
    has to be noticed rather than quietly ignored.
    """
    report = check("# A knob nobody reads\n# VULTURE_F3_PHANTOM_KNOB=7\n")
    violation = _violation_for(report, "VULTURE_F3_PHANTOM_KNOB")
    assert "no code default could be resolved" in violation.message
    assert "ALLOWLIST" in violation.message and "_explicit_resolvers()" in violation.message


def test_empty_valued_and_uncommented_lines_state_no_default() -> None:
    """'# VAR=' states no value; an uncommented line is config, not a claim."""
    stated = parse_stated_defaults(
        "# VULTURE_F3_NOTHING_STATED=\nVULTURE_F3_PLAIN_CONFIG=28080\n"
    )
    assert [s.var for s in stated] == [], stated


# ── the allowlist must stay honest ───────────────────────────────────────────


def test_allowlist_entries_are_live_and_load_bearing() -> None:
    """Every exemption must be used, reasoned, and actually needed.

    "Load-bearing" is the part that keeps the allowlist from becoming a dumping
    ground: with the entry removed, the checker must report that variable. An
    exemption that changes nothing is dead weight and gets deleted.
    """
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    stated_vars = {s.var for s in parse_stated_defaults(text)}
    for var, reason in ALLOWLIST.items():
        _assert_exemption_is_honest(var, reason, text, stated_vars)


def _assert_exemption_is_honest(var: str, reason: str, text: str, stated: set[str]) -> None:
    here = pathlib.Path(__file__).name
    assert var in stated, (
        f"{var} is allowlisted but env.example no longer states a default for it. "
        f"FIX: delete the ALLOWLIST entry in {here}."
    )
    assert len(reason) > 40, f"{var}'s allowlist reason is too thin to audit: {reason!r}"
    without = check(text, allowlist=set(ALLOWLIST) - {var})
    assert any(v.stated.var == var for v in without.violations), (
        f"{var} is allowlisted but the checker would not flag it anyway. FIX: delete "
        f"the ALLOWLIST entry in {here} — the documented value now agrees with a "
        "resolvable code default."
    )
