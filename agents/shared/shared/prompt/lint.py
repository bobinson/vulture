"""promptlint — twelve checks over a rendered prompt. Feature 0089 §5 Layer A.

Every check is decidable without calling a model. The check number IS the test
name: check_01_orphan_field -> test_lint_01_orphan_field. A thirteenth check is
a thirteenth function, never a branch inside an existing one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .fragment import CONFLICTING, Role, Stance
from .registry import get


@dataclass(frozen=True)
class LintFinding:
    check: str
    fragment: str
    message: str


def _frags(spec):
    return [get(i) for i in tuple(spec.fragments) + tuple(spec.user_fragments)]


def check_01_orphan_field(spec, rp) -> list[LintFinding]:
    """A fragment may not instruct the model to emit a field no schema has."""
    known = set(spec.schema_fields)
    return [LintFinding("orphan_field", f.id, f"declares {name!r}, not in schema")
            for f in _frags(spec) for name in f.declares_fields if name not in known]


def check_02_duplicate_contract(spec, rp) -> list[LintFinding]:
    """At most one fragment per render may declare the field list."""
    declaring = [f for f in _frags(spec) if f.declares_fields]
    if len(declaring) <= 1:
        return []
    return [LintFinding("duplicate_contract", f.id,
                        f"{len(declaring)} fragments declare a field list")
            for f in declaring]


def check_03_stance_conflict(spec, rp) -> list[LintFinding]:
    """No two fragments in one render may hold opposing stances."""
    present = {s: f.id for f in _frags(spec) for s in f.stance}
    out = []
    for pair in CONFLICTING:
        a, b = tuple(pair)
        if a in present and b in present:
            out.append(LintFinding("stance_conflict", f"{present[a]}+{present[b]}",
                                   f"{a.value} conflicts with {b.value}"))
    return out


def check_04_vocab_closure(spec, rp) -> list[LintFinding]:
    """A field with a vocabulary needs exactly one binding fragment."""
    bound = [f for f in _frags(spec) if f.binds_vocabulary]
    fields = {k for f in bound for k, _ in f.binds_vocabulary}
    return [LintFinding("vocab_closure", "-", f"{k!r} has no binding fragment")
            for k, _ in spec.vocabulary if k not in fields]


def check_05_slot_marking(spec, rp) -> list[LintFinding]:
    """Untrusted bytes require the marker fragment in the same render."""
    if not spec.slots:
        return []
    marks = any(Stance.MARKS_UNTRUSTED in f.stance for f in _frags(spec))
    if marks:
        return []
    return [LintFinding("slot_marking", spec.id,
                        f"{len(spec.slots)} slot(s) with no MARKS_UNTRUSTED fragment")]


def check_06_marker_forgery(spec, rp) -> list[LintFinding]:
    """Slot content may not carry its own closing marker."""
    return [LintFinding("marker_forgery", spec.id, f"{s.kind} slot contains its closer")
            for s in spec.slots if f"{s.kind}:" in s.content and ">>>" in s.content]


def check_07_dangling_reference(spec, rp) -> list[LintFinding]:
    """Every `references` entry must resolve to something in THIS render."""
    have = set(spec.variables) | {s.kind.lower() for s in spec.slots}
    return [LintFinding("dangling_reference", f.id, f"references {r!r}, absent here")
            for f in _frags(spec) for r in f.references if r not in have]


def check_08_exemplar_validity(spec, rp) -> list[LintFinding]:
    """Every embedded JSON example must parse."""
    out = []
    for f in _frags(spec):
        for block in re.findall(r"\{[^{}]*\}", f.text):
            try:
                json.loads(block)
            except ValueError:
                if '"' in block:
                    out.append(LintFinding("exemplar_validity", f.id,
                                           f"unparseable example: {block[:48]}"))
    return out


_PLACEHOLDERS = ("/real-path", "payload if POST", "your-", "TODO", "...")


def check_09_placeholder_echo(spec, rp) -> list[LintFinding]:
    """Exemplar values must not teach a literal the executor would send."""
    return [LintFinding("placeholder_echo", f.id, f"exemplar contains {p!r}")
            for f in _frags(spec) for p in _PLACEHOLDERS if p in f.text]


def check_10_budget(spec, rp) -> list[LintFinding]:
    """Prompt + tools must leave room to answer at this context window."""
    if rp.output_budget_hint >= 512:
        return []
    return [LintFinding("budget", spec.id,
                        f"only {rp.output_budget_hint} output tokens left")]


def check_11_tool_announcement(spec, rp) -> list[LintFinding]:
    """Tools attached ⇒ a fragment that positively permits using them."""
    if not spec.tools:
        return []
    if any(Stance.PERMITS_TOOL_USE in f.stance for f in _frags(spec)):
        return []
    return [LintFinding("tool_announcement", spec.id,
                        f"{len(spec.tools)} tools attached, no PERMITS_TOOL_USE fragment")]


def check_12_language_pin(spec, rp) -> list[LintFinding]:
    """Free-text output that egresses needs the language bound once."""
    if not spec.schema_fields:
        return []
    free_text = {"reasoning", "description", "title", "recommendation", "evidence"}
    if not (free_text & set(spec.schema_fields)):
        return []
    if any(Stance.BINDS_LANGUAGE in f.stance for f in _frags(spec)):
        return []
    return [LintFinding("language_pin", spec.id, "free-text fields, no BINDS_LANGUAGE")]


CHECKS = (
    check_01_orphan_field, check_02_duplicate_contract, check_03_stance_conflict,
    check_04_vocab_closure, check_05_slot_marking, check_06_marker_forgery,
    check_07_dangling_reference, check_08_exemplar_validity,
    check_09_placeholder_echo, check_10_budget, check_11_tool_announcement,
    check_12_language_pin,
)


def lint(spec, rp) -> list[LintFinding]:
    return [f for check in CHECKS for f in check(spec, rp)]
