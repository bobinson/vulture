"""A rollup parent's verdict must be derived from its members, not invented.

The parent is synthesised in L2, after L1, and appended to the result only
after ``validate()`` has returned (``audit_runner``:
``all_findings + v_result.rollups``), so it never reaches the voter. L5 skips
it explicitly. The consequence, measured on one 336-finding run: 83 rows
(24.7%) carried ``suspicious`` at exactly 0.40 — a literal from
``rollup.py``, not a judgement — and ``_rollup_status_for`` returned the
string ``"suspicious"`` for every category and every instance count, its own
docstring conceding that inheriting max-of-members was "handled by the
caller" when no caller did it.

Two things follow from an un-voted parent, both pinned below:

* ``likely_fp`` is unreachable for it. ``_classify`` needs
  ``confidence < 0.30 AND demoting_count >= 2``; a parent's checks are all
  weight 0.0, so ``demoting_count`` is 0 and confidence is pinned at 0.40.
* A parent whose members were every one of them dismissed still reads
  ``suspicious``, and a parent hiding a confirmed bug reads no worse than
  one hiding three dismissals.

The members ARE fully voted (L1 + L2 + L5), so the information exists by the
time ``_emit_summary`` runs. The parent inherits from its highest-confidence
member: a group is worth reviewing at the strength of its worst instance.
"""

from __future__ import annotations

from shared.validate.rollup import derive_parent_verdicts, run_l2


def _member(mid: str, line: int) -> dict:
    return {
        "id": mid,
        "category": "CWE-89",
        "title": "SQL injection via string interpolation",
        "description": f"SQL query built with string formatting at line {line}",
        "recommendation": "Use parameterized queries.",
        "file_path": "/x/seed.ts",
        "line_start": line,
        "line_end": line,
        "severity": "critical",
    }


def _voted(mid: str, line: int, status: str, confidence: float) -> dict:
    f = _member(mid, line)
    f["validation_status"] = status
    f["validation_confidence"] = confidence
    return f


def _parent_for(members: list[dict]) -> dict:
    _checks, parents = run_l2(members, audit_id="a1")
    assert parents, "two members sharing category+title+file must produce a parent"
    return parents[0]


class TestParentInheritsItsMembersVerdict:
    def test_confirmed_member_lifts_the_parent(self):
        """A group containing a real bug must not read as merely suspicious."""
        members = [
            _voted("m1", 10, "high_confidence", 0.99),
            _voted("m2", 20, "suspicious", 0.50),
        ]
        parent = _parent_for(members)
        derive_parent_verdicts(members, [parent])

        assert parent["validation"]["confidence"] == 0.99
        assert parent["validation"]["status"] == "high_confidence"

    def test_wholly_dismissed_group_reaches_likely_fp(self):
        """The label that was structurally unreachable for a parent."""
        members = [
            _voted("m1", 10, "likely_fp", 0.10),
            _voted("m2", 20, "likely_fp", 0.05),
        ]
        parent = _parent_for(members)
        derive_parent_verdicts(members, [parent])

        assert parent["validation"]["status"] == "likely_fp"
        assert parent["validation"]["confidence"] == 0.10

    def test_the_verdict_is_no_longer_a_constant(self):
        """Two groups with different evidence must not get the same number."""
        weak = [_voted("a1", 1, "likely_fp", 0.10), _voted("a2", 2, "likely_fp", 0.10)]
        strong = [_voted("b1", 1, "high_confidence", 0.99),
                  _voted("b2", 2, "high_confidence", 0.99)]
        pw, ps = _parent_for(weak), _parent_for(strong)
        derive_parent_verdicts(weak, [pw])
        derive_parent_verdicts(strong, [ps])

        assert pw["validation"]["confidence"] != ps["validation"]["confidence"], (
            "a parent's confidence must track its members, not a literal"
        )

    def test_derivation_is_recorded_as_a_stated_fact(self):
        """Why the parent holds this verdict must be readable in the blob."""
        members = [
            _voted("m1", 10, "high_confidence", 0.99),
            _voted("m2", 20, "suspicious", 0.50),
        ]
        parent = _parent_for(members)
        derive_parent_verdicts(members, [parent])

        checks = parent["validation"]["checks"]
        derived = [c for c in checks if c.get("id") == "rollup"]
        assert derived, "the parent must carry a rollup check explaining its verdict"
        assert derived[0]["result"] == "derived"
        assert derived[0]["weight"] == 0.0, "bookkeeping, never evidence"
        assert derived[0]["extras"]["inherited_from"] == "m1"
        assert derived[0]["extras"]["members_voted"] == 2

    def test_validated_at_is_stamped_once_the_verdict_is_real(self):
        members = [_voted("m1", 10, "suspicious", 0.50),
                   _voted("m2", 20, "suspicious", 0.50)]
        parent = _parent_for(members)
        assert parent["validation"]["validated_at"] == "", "unvoted before derivation"
        derive_parent_verdicts(members, [parent])
        assert parent["validation"]["validated_at"], "a derived verdict has a time"


class TestParentWithNothingToInheritFrom:
    def test_unresolvable_members_keep_the_placeholder_and_say_so(self):
        """V6 demote-never-drop: an orphan parent must not silently read 0.99."""
        members = [_voted("m1", 10, "high_confidence", 0.99),
                   _voted("m2", 20, "high_confidence", 0.99)]
        parent = _parent_for(members)
        derive_parent_verdicts([], [parent])       # members not in the result

        assert parent["validation"]["confidence"] == 0.40
        assert parent["validation"]["status"] == "suspicious"
        orphan = [c for c in parent["validation"]["checks"]
                  if c.get("id") == "rollup" and c.get("result") == "orphan"]
        assert orphan, "an un-derivable parent must record WHY it kept the placeholder"

    def test_members_lacking_a_vote_are_not_counted_as_zero(self):
        """An unvoted member must not drag the parent down to 0.0."""
        members = [_member("m1", 10), _voted("m2", 20, "high_confidence", 0.99)]
        parent = _parent_for(members)
        derive_parent_verdicts(members, [parent])

        assert parent["validation"]["confidence"] == 0.99
        assert parent["validation"]["status"] == "high_confidence"
