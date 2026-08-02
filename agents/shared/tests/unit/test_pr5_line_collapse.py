"""PR5: ancestor/descendant collapse of skill findings sharing a source line.

The business contract these tests pin down:

* Two rows on the same line collapse ONLY when one CWE is a transitive
  ``ChildOf`` ancestor of the other, and it is the ancestor that goes.
* Siblings (distinct weaknesses under a shared parent) NEVER collapse — they
  carry different remediations.
* Severity is carried onto the survivor; nothing is quietly downgraded.
* The result is order-independent, preserves emission order, and never
  empties a line.
* The hierarchy is read from the shipped CWE catalog, not hardcoded here.

Fixtures are synthetic finding dicts; the hierarchy used by the unit-level
tests is injected so they do not depend on catalog contents, and a separate
group of tests asserts the real catalog is wired up.
"""

import pytest

from shared.audit_runner import _collapse_skill_findings
from shared.tools.finding_collapse import (
    collapse_line_stacks,
    cwe_ancestors,
    max_severity,
)

# --- synthetic hierarchy ---------------------------------------------------
# GEN -> MID -> SPEC is a chain; SIB shares MID's parent but is not on the
# chain. Numeric ids are invented so nothing here depends on real CWE data.
GEN, MID, SPEC, SIB = "9000", "9001", "9002", "9003"
_FAKE_ANCESTORS = {
    MID: frozenset({GEN}),
    SPEC: frozenset({MID, GEN}),
    SIB: frozenset({GEN}),
}


def fake_ancestors(cwe_id):
    return _FAKE_ANCESTORS.get(cwe_id, frozenset())


def row(cwe, line=10, severity="medium", path="app/handler.py", **extra):
    finding = {
        "category": f"CWE-{cwe}" if cwe else "",
        "file_path": path,
        "line_start": line,
        "severity": severity,
        "title": f"finding {cwe}@{line}",
    }
    finding.update(extra)
    return finding


def cats(findings):
    return [f["category"] for f in findings]


# --- core rule -------------------------------------------------------------


def test_ancestor_on_same_line_is_dropped_and_descendant_survives():
    kept, collapsed = collapse_line_stacks(
        [row(GEN), row(SPEC)], ancestors=fake_ancestors
    )
    assert collapsed == 1
    assert cats(kept) == [f"CWE-{SPEC}"]


def test_transitive_ancestor_two_hops_away_is_dropped():
    kept, collapsed = collapse_line_stacks(
        [row(GEN), row(MID), row(SPEC)], ancestors=fake_ancestors
    )
    assert collapsed == 2
    assert cats(kept) == [f"CWE-{SPEC}"]


def test_siblings_never_collapse():
    """Different weaknesses under a shared parent keep their own rows."""
    stack = [row(SPEC), row(SIB)]
    kept, collapsed = collapse_line_stacks(stack, ancestors=fake_ancestors)
    assert collapsed == 0
    assert cats(kept) == [f"CWE-{SPEC}", f"CWE-{SIB}"]


def test_sibling_survives_while_shared_ancestor_collapses():
    kept, collapsed = collapse_line_stacks(
        [row(GEN), row(SPEC), row(SIB)], ancestors=fake_ancestors
    )
    assert collapsed == 1
    assert cats(kept) == [f"CWE-{SPEC}", f"CWE-{SIB}"]


def test_different_lines_do_not_interact():
    kept, collapsed = collapse_line_stacks(
        [row(GEN, line=10), row(SPEC, line=11)], ancestors=fake_ancestors
    )
    assert collapsed == 0
    assert len(kept) == 2


def test_different_files_on_the_same_line_number_do_not_interact():
    kept, collapsed = collapse_line_stacks(
        [row(GEN, path="a.py"), row(SPEC, path="b.py")], ancestors=fake_ancestors
    )
    assert collapsed == 0
    assert len(kept) == 2


# --- order independence & ordering ----------------------------------------


@pytest.mark.parametrize(
    "order",
    [
        [GEN, MID, SPEC],
        [SPEC, MID, GEN],
        [MID, SPEC, GEN],
        [SPEC, GEN, MID],
    ],
)
def test_collapse_is_order_independent(order):
    kept, collapsed = collapse_line_stacks(
        [row(c) for c in order], ancestors=fake_ancestors
    )
    assert (cats(kept), collapsed) == ([f"CWE-{SPEC}"], 2)


def test_emission_order_of_survivors_is_preserved():
    stack = [
        row(SIB, line=1),
        row(GEN, line=2),
        row(SPEC, line=2),
        row(SPEC, line=3),
    ]
    kept, collapsed = collapse_line_stacks(stack, ancestors=fake_ancestors)
    assert collapsed == 1
    assert [(f["category"], f["line_start"]) for f in kept] == [
        (f"CWE-{SIB}", 1),
        (f"CWE-{SPEC}", 2),
        (f"CWE-{SPEC}", 3),
    ]


# --- severity preservation -------------------------------------------------


def test_survivor_inherits_max_severity_of_collapsed_ancestors():
    kept, _ = collapse_line_stacks(
        [row(GEN, severity="critical"), row(SPEC, severity="low")],
        ancestors=fake_ancestors,
    )
    assert kept[0]["severity"] == "critical"


def test_survivor_keeps_its_own_higher_severity():
    kept, _ = collapse_line_stacks(
        [row(GEN, severity="low"), row(SPEC, severity="high")],
        ancestors=fake_ancestors,
    )
    assert kept[0]["severity"] == "high"


def test_sibling_severity_is_not_inflated_by_an_unrelated_collapse():
    """Only rows the ancestor actually generalises may absorb its severity."""
    kept, _ = collapse_line_stacks(
        [
            row(MID, severity="critical"),
            row(SPEC, severity="low"),
            row(SIB, severity="info"),
        ],
        ancestors=fake_ancestors,
    )
    by_cat = {f["category"]: f["severity"] for f in kept}
    assert by_cat == {f"CWE-{SPEC}": "critical", f"CWE-{SIB}": "info"}


def test_input_findings_are_not_mutated():
    original = row(SPEC, severity="low")
    collapse_line_stacks(
        [row(GEN, severity="critical"), original], ancestors=fake_ancestors
    )
    assert original["severity"] == "low"


def test_max_severity_ranks_unknown_labels_lowest():
    assert max_severity(["low", "bogus", "medium"]) == "medium"
    assert max_severity(["bogus", ""]) in ("bogus", "")


# --- robustness ------------------------------------------------------------


def test_no_row_survives_alone_removal_under_a_relationship_cycle():
    """A cyclic hierarchy must not empty a line."""
    cyclic = {"1": frozenset({"2"}), "2": frozenset({"1"})}
    kept, collapsed = collapse_line_stacks(
        [row("1"), row("2")], ancestors=lambda c: cyclic.get(c, frozenset())
    )
    assert collapsed == 0
    assert len(kept) == 2


def test_findings_without_a_line_anchor_pass_through():
    stack = [
        {"category": f"CWE-{GEN}", "file_path": "a.py", "severity": "high"},
        {"category": f"CWE-{SPEC}", "file_path": "a.py", "severity": "low"},
    ]
    kept, collapsed = collapse_line_stacks(stack, ancestors=fake_ancestors)
    assert collapsed == 0
    assert len(kept) == 2


def test_non_cwe_categories_are_never_dropped():
    stack = [row(GEN), row(SPEC), {**row(None), "category": "policy.custom"}]
    kept, collapsed = collapse_line_stacks(stack, ancestors=fake_ancestors)
    assert collapsed == 1
    assert "policy.custom" in cats(kept)


def test_empty_input():
    assert collapse_line_stacks([], ancestors=fake_ancestors) == ([], 0)


def test_single_finding_is_untouched():
    stack = [row(GEN)]
    kept, collapsed = collapse_line_stacks(stack, ancestors=fake_ancestors)
    assert collapsed == 0
    assert kept[0] is stack[0]


# --- real catalog wiring ---------------------------------------------------


def test_catalog_hierarchy_is_loaded_and_transitive():
    """The shipped catalog must yield a non-trivial ChildOf closure."""
    populated = [c for c in ("252", "759", "321") if cwe_ancestors(c)]
    assert populated, "catalog ChildOf hierarchy is empty"
    # Ancestors of an ancestor are ancestors (transitive closure, not one hop).
    for cid in populated:
        for parent in cwe_ancestors(cid):
            assert cwe_ancestors(parent) <= cwe_ancestors(cid)


def test_unknown_cwe_id_has_no_ancestors():
    assert cwe_ancestors("999999") == frozenset()
    assert cwe_ancestors("") == frozenset()


def test_default_resolver_leaves_a_real_sibling_stack_intact():
    """Three separate missing-cookie-attribute rows must all survive."""
    stack = [row("1004"), row("614"), row("1275")]
    kept, collapsed = collapse_line_stacks(stack)
    assert collapsed == 0
    assert len(kept) == 3


# --- audit_runner integration ---------------------------------------------


def test_runner_helper_collapses_and_reports_count():
    stack = [row("754", severity="high"), row("252", severity="medium")]
    kept, collapsed = _collapse_skill_findings(stack, run_id="t")
    assert (collapsed, cats(kept)) == (1, ["CWE-252"])
    assert kept[0]["severity"] == "high"


def test_runner_helper_is_disabled_by_env(monkeypatch):
    monkeypatch.setenv("VULTURE_DISABLE_LINE_COLLAPSE", "true")
    stack = [row("754"), row("252")]
    kept, collapsed = _collapse_skill_findings(stack, run_id="t")
    assert (collapsed, len(kept)) == (0, 2)


def test_runner_helper_degrades_on_malformed_findings():
    """A broken row must not cost the run its findings."""
    kept, collapsed = _collapse_skill_findings(["not-a-dict"], run_id="t")
    assert (collapsed, kept) == (0, ["not-a-dict"])
