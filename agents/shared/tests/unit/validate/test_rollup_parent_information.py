"""L2 rollup parents must summarise their members, not paraphrase them away.

The rollup groups by ``(category, normalized_title, file_path)`` — deliberately
not by line — so every member shares a title by construction. What members do
NOT share is their line and whatever detail their description carries beyond
the common title.

The parent previously discarded all of it, emitting a fixed
``"N instances rolled up; see member findings for individual line locations."``
and taking ``recommendation`` from ``members[0]`` arbitrarily. Two consequences,
both pinned below:

* The line numbers were withheld from the one row a reader is most likely to
  look at, replaced by a pointer telling them to go find the members.
* When one member carries richer remediation than its siblings — which is
  exactly what happens after an ancestor collapse folds a specialised
  detector's text into a survivor — a positional pick can silently choose the
  poorer one.
"""

from __future__ import annotations

from shared.validate.rollup import run_l2


def _member(line: int, *, rec: str = "Generic advice.", desc: str = "") -> dict:
    return {
        "id": f"m{line}",
        "category": "CWE-321",
        "title": "Hardcoded cryptographic key",
        "description": desc or f"Cryptographic key embedded in source code at line {line}",
        "recommendation": rec,
        "file_path": "/x/keys.ts",
        "line_start": line,
        "line_end": line,
        "severity": "critical",
    }


def _parent(findings: list[dict]) -> dict:
    _checks, parents = run_l2(findings, audit_id="a1")
    assert parents, "two members sharing category+title+file must produce a parent"
    return parents[0]


class TestRollupParentCarriesMemberDetail:
    def test_parent_names_the_member_lines(self):
        """The count alone sends the reader elsewhere for the one fact they need."""
        parent = _parent([_member(21), _member(42)])
        assert "21" in parent["description"] and "42" in parent["description"], (
            f"parent must name its member lines, got: {parent['description']!r}"
        )

    def test_parent_still_states_the_instance_count(self):
        parent = _parent([_member(21), _member(42)])
        assert "2" in parent["description"]
        assert parent["instance_count"] == 2

    def test_parent_takes_the_most_specific_recommendation(self):
        """A positional pick loses a member enriched by an ancestor collapse."""
        rich = (
            "Remove the key from source and rotate it immediately; treat any "
            "key already committed to a remote as compromised."
        )
        parent = _parent([_member(21, rec="Generic advice."), _member(42, rec=rich)])
        assert parent["recommendation"] == rich, (
            "the parent must not discard the richer remediation just because it "
            "belongs to a later member"
        )

    def test_absorbed_notes_from_members_survive_on_the_parent(self):
        """Text folded in by the line-stack collapse must reach the parent."""
        note = "Also reported as CWE-798: Hardcoded private key (RSA PRIVATE KEY)"
        parent = _parent([
            _member(21, desc=f"Cryptographic key embedded at line 21 {note}"),
            _member(42),
        ])
        assert "RSA PRIVATE KEY" in parent["description"], (
            "a member's absorbed identification is the most specific thing the "
            "group knows; the parent must not paraphrase it away"
        )

    def test_line_span_is_unchanged(self):
        parent = _parent([_member(21), _member(42)])
        assert (parent["line_start"], parent["line_end"]) == (21, 42)

    def test_many_members_do_not_produce_an_unbounded_description(self):
        """A 300-instance dependency rollup must stay readable."""
        parent = _parent([_member(n) for n in range(1, 301)])
        assert len(parent["description"]) < 400, (
            f"description grew to {len(parent['description'])} chars"
        )
        assert parent["instance_count"] == 300
