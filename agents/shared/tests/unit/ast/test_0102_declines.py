"""Feature 0102, plan task 2.4 (LLD D9, D14, D16, §8.7, §10.3; §11 T6, T15): the bounded
decline ledger and ``safe_path``.

``decide`` (§8.5) is the only suppression the AST tier has, and every decline it makes is
recorded on the audit (D9). An adversarial repository can make thousands of them (T6), so
the ledger keeps at most ``MAX_SUPPRESSIONS_PER_RULE`` per rule in a bounded heap and names
the rules it capped. Pinned here:

* **The cap (plan 2.4).** Sixty declines of one rule render fifty: the lexicographically
  smallest, whatever order they arrived in (D14), and ``capped_rules == [rule]``. Each rule
  is capped on its own; ``by_rule`` counts every decline added, kept or not.
* **The rendered line (§10.3).** ``ast_decline family=<f> file=<safe_path> line=<n>
  rule=<label> origins=<origins>``, one per kept record, in sorted order (D14).
* **``safe_path(root, path)`` (§10.3, T15, A30 (5))** is root-relative, printable ASCII only
  (others ``?``), the FIRST ``limits.MAX_RENDERED_PATH`` (200) characters of a longer path, and
  is the renderer ``render`` uses for every path, so a terminal control character in a file
  name never reaches the ``thinking`` stream.

The shapes the lead ruled (A30 (1), A31 (1)): ``DeclineRecord(family, file, line, rule,
origins)``, ``origins`` a sorted tuple of rendered origins (``external:request``), its file the
consumer's (``_audit.decline_record``); ``DeclineLedger()`` takes no argument; ``render(root)``
takes the audit root, as ``coverage.snapshot(root)`` does, and returns the sorted lines
(``_audit.rendered``, the one spelling); ``by_rule`` counts every ``add`` (60 for 60) per
decline label; ``capped_rules`` is a sorted list. ``by_rule`` and ``capped_rules`` are read
whether they are methods or properties (the plan lists them beside the methods ``add`` and
``render``).

The ``test_control_chars_in_path`` egress test of plan 2.4 lives in ``test_0102_egress.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.ast import limits
from shared.ast.limits import MAX_SUPPRESSIONS_PER_RULE
from tests.unit.ast._analysis import declines_mod, safe_path, unprintable
from tests.unit.ast._audit import (
    GUARDED,
    OVER,
    REQUEST_ORIGINS,
    SANITIZED,
    decline_line,
    decline_record,
    ledger_view,
    names,
    records,
    shuffled,
)

# A rule that stays under its cap.
_UNDER = 7
# Characters a terminal acts on: an ANSI colour sequence, newline, carriage return, bell,
# a bidi override and the one-byte C1 control sequence introducer.
_HOSTILE_NAMES = ("a\x1b[31mb.js", "a\nb.js", "a\rb.js", "a\x07b.js", "a‮b.js", "a\x9bb.js")


# ── the ledger ───────────────────────────────────────────────────────────────


def test_an_empty_ledger_renders_nothing(tmp_path: Path) -> None:
    assert ledger_view(tmp_path, []) == ([], {}, [])


def test_a_decline_record_is_its_five_ruled_fields_in_order(tmp_path: Path) -> None:
    """A30 (1): ``DeclineRecord(family, file, line, rule, origins)``, positionally as by name."""
    file = tmp_path / "src" / "a.js"
    record = declines_mod().DeclineRecord("path", file, 3, SANITIZED, REQUEST_ORIGINS)

    assert record == decline_record(file)
    assert (record.family, record.file, record.line, record.rule, record.origins) == (
        "path", file, 3, SANITIZED, REQUEST_ORIGINS,
    )


def test_a_decline_renders_as_one_ast_decline_line(tmp_path: Path) -> None:
    """§10.3, verbatim: the line a ``thinking`` event carries for one decline."""
    record = decline_record(tmp_path / "src" / "a.js", line=12)

    rendered, _, _ = ledger_view(tmp_path, [record])

    assert rendered == [
        "ast_decline family=path file=src/a.js line=12 rule=sanitized:path_normalize"
        " origins=external:request"
    ]


def test_a_rule_past_its_cap_renders_its_smallest_declines(tmp_path: Path) -> None:
    """Plan 2.4: sixty declines of one rule, shuffled -> the fifty lexicographically smallest
    are rendered, in order, and the rule is named as capped."""
    files = names(OVER)

    rendered, by_rule, capped = ledger_view(tmp_path, shuffled(records(tmp_path, files), seed=102))

    expected = [decline_line(name) for name in files[:MAX_SUPPRESSIONS_PER_RULE]]
    assert (rendered, capped) == (expected, [SANITIZED])


def test_by_rule_counts_every_decline_kept_or_not(tmp_path: Path) -> None:
    _, by_rule, _ = ledger_view(tmp_path, records(tmp_path, names(OVER)))

    assert by_rule == {SANITIZED: OVER}


def test_each_rule_is_capped_on_its_own(tmp_path: Path) -> None:
    """A rule under its cap keeps every decline and is not named, beside a capped one."""
    over, under = names(OVER), names(_UNDER)
    added = records(tmp_path, over) + records(tmp_path, under, rule=GUARDED)

    observed = ledger_view(tmp_path, added)

    kept = [decline_line(n) for n in over[:MAX_SUPPRESSIONS_PER_RULE]] + [
        decline_line(n, GUARDED) for n in under
    ]
    assert observed == (sorted(kept), {SANITIZED: OVER, GUARDED: _UNDER}, [SANITIZED])


def test_capped_rules_is_a_sorted_list(tmp_path: Path) -> None:
    """A31 (1): two rules past their caps, added in reverse label order, are named in a list
    sorted by label."""
    added = records(tmp_path, names(OVER, "s")) + records(tmp_path, names(OVER, "g"), rule=GUARDED)

    _, by_rule, capped = ledger_view(tmp_path, added)

    assert (by_rule, capped) == ({SANITIZED: OVER, GUARDED: OVER}, sorted([SANITIZED, GUARDED]))


def test_the_ledger_does_not_depend_on_insertion_order(tmp_path: Path) -> None:
    """D14: concurrent skill threads add in any order; what the ledger reports is the same."""
    added = records(tmp_path, names(OVER)) + records(tmp_path, names(_UNDER), rule=GUARDED)
    orders = [added, added[::-1], shuffled(added, seed=1), shuffled(added, seed=2)]

    views = [ledger_view(tmp_path, order) for order in orders]

    assert all(view == views[0] for view in views), views


# ── safe_path, the one renderer of a path (§10.3) ────────────────────────────


def test_safe_path_is_root_relative(tmp_path: Path) -> None:
    assert safe_path(tmp_path, tmp_path / "src" / "a.js") == "src/a.js"


@pytest.mark.parametrize("name", _HOSTILE_NAMES, ids=ascii)
def test_safe_path_emits_printable_ascii_only(tmp_path: Path, name: str) -> None:
    """T15: no escape sequence, newline, bell or bidi control survives; the printable parts
    of the name around it do."""
    shown = safe_path(tmp_path, tmp_path / "src" / name)

    assert (shown.startswith("src/a"), shown.endswith("b.js"), unprintable(shown)) == (
        True, True, ""
    ), ascii(shown)


def test_safe_path_shows_a_non_ascii_character_as_a_question_mark(tmp_path: Path) -> None:
    """§10.3: printable ASCII only, "others ``?``"."""
    assert safe_path(tmp_path, tmp_path / "naïve.js") == "na?ve.js"


def test_safe_path_keeps_200_characters_and_cuts_a_longer_path(tmp_path: Path) -> None:
    """A30 (5): a ``MAX_RENDERED_PATH``-character (200) path is shown whole; a longer one is cut
    to its FIRST ``MAX_RENDERED_PATH`` characters (the root-relative prefix is kept)."""
    cap = limits.MAX_RENDERED_PATH
    at_cap = "d/" * ((cap - 4) // 2) + "a.js"
    longer = [at_cap[:-4] + "ab.js", "d/" * (cap - 50) + "a.js"]
    assert (cap, len(at_cap)) == (200, cap)

    shown = safe_path(tmp_path, tmp_path / at_cap)
    cut = [safe_path(tmp_path, tmp_path / rel) for rel in longer]

    assert (shown, cut) == (at_cap, [rel[:cap] for rel in longer])


def test_render_shows_every_path_through_safe_path(tmp_path: Path) -> None:
    """Plan 2.4: a decline in a file whose name carries a bell character is rendered with
    ``safe_path``'s spelling of that file, and the bell is gone."""
    file = tmp_path / "src" / "a\x07b.js"

    rendered, _, _ = ledger_view(tmp_path, [decline_record(file)])

    shown = decline_line(safe_path(tmp_path, file))
    assert (rendered, "\x07" in "".join(rendered)) == ([shown], False)
