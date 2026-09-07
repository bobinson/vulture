"""Feature 0089 Phase 0.c — the VALIDATE tier's abstention stances, in full.

Phase 0.c's one rule with judgement in it: *declare what the text says*. The
plan is explicit about why (`0089_implementation_plan.md` §0.c): "A fragment
that says *'it is the answer'* gets `BLESSES_ABSTENTION`, not `_AFTER_LOOKING`.
The linter's job in 0.e is to show those declarations conflicting; soften them
and it proves nothing."

The motivating defect is not one clause, it is several. The library says so in
two places, from two directions:

* `fragment.py` — "the judge holding tools while **four clauses** told it that
  not looking was a valid answer".
* `judge_tools.tool_discipline_prompt` — the previous text "told the model, in
  **five places across two prompts**, that not looking was a valid terminal
  answer".

Those two counts reconcile exactly: four clauses in `validate_judge.txt`
(`validate/closure` carries two of them, `validate/evidence_citation` and
`validate/output_contract` one each) plus the fifth in the tool prompt, which
is the second prompt. So three system fragments of the judge prompt bless
abstention, and a transcription that declares the stance on only one of them
under-reports the defect it exists to surface: the 0.e report then names one
clause, and a reader who fixes that clause leaves three in place.

`validate/calibration` is deliberately NOT in the set. "0.50: genuinely
impossible to tell from the snippet" defines what a probability band *means*;
it does not tell the model what to DO when it cannot see enough. The stance
enum is about the latter — every member is a directive about the answer, not
about the scale. Declaring it here would be over-declaration, which fails the
same rule from the other side.
"""

from __future__ import annotations

import pytest

from shared.prompt import Mode, lint, profile_for, render
from shared.prompt.fragment import Stance
from shared.prompt.manifests.validate_judge import VALIDATE_JUDGE
from shared.prompt.registry import get

# The four clauses, as the byte-exact text that carries each one. A clause is
# listed by the words that do the blessing, so the assertion fails if a future
# re-sync removes the words but leaves the stance behind.
ABSTENTION_CLAUSES: tuple[tuple[str, str], ...] = (
    ("validate/closure", "prefer false when unsure"),
    ("validate/closure", "is not a failure"),
    ("validate/evidence_citation", "not a confident verdict"),
    ("validate/output_contract", "set exploitable=0.5"),
)

# The fragments those four clauses live in — no more, no fewer.
ABSTENTION_SITES = frozenset({
    "validate/closure",
    "validate/evidence_citation",
    "validate/output_contract",
})

TOOL_SITE = "validate/tool_discipline"


def _profile():
    return profile_for("gpt-4o")


# The phrases 4.1 added to qualify an abstention clause. A fragment whose text
# contains one of these must declare the SOFT stance; one without must declare
# the hard stance. Deriving the expectation from the text is what makes this
# guard survive 4.1 landing (or being reverted) without going stale — and it
# still catches softening, because softening the declaration without changing
# the text now fails.
# Every phrase that turns an abstention clause into "look first, then abstain".
# 4.1 added the first two (Closure); 4.1b added the rest, after promptlint
# showed the judge prompt had THREE abstention sites and 4.1 had qualified only
# one — which is the concrete explanation for 4.1 measuring zero tool calls.
QUALIFIERS = (
    "not yet the answer",
    "Look first",
    "READ THE FILE and look for it",
    "spend a tool call on it",
)


def _expected_stance(text: str) -> Stance:
    if any(q in text for q in QUALIFIERS):
        return Stance.BLESSES_ABSTENTION_AFTER_LOOKING
    return Stance.BLESSES_ABSTENTION


def _declared_sites() -> frozenset[str]:
    return frozenset(fid for fid in VALIDATE_JUDGE.fragments
                     if {Stance.BLESSES_ABSTENTION,
                         Stance.BLESSES_ABSTENTION_AFTER_LOOKING}
                     & set(get(fid).stance))


def _conflicts() -> list:
    rp = render(VALIDATE_JUDGE, _profile(), mode=Mode.TRANSCRIBE)
    return [f for f in lint(VALIDATE_JUDGE, rp) if f.check == "stance_conflict"]


def _pairs_with_tools(findings) -> frozenset[str]:
    """Fragment ids reported as conflicting with the tool-permitting fragment.

    The two halves of a `CONFLICTING` pair are unpacked from a frozenset, so
    which side of the `+` each lands on is not stable across runs. The set of
    OTHER ids is, and that is what this reads.
    """
    return frozenset(part
                     for f in findings if TOOL_SITE in f.fragment
                     for part in f.fragment.split("+") if part != TOOL_SITE)


@pytest.mark.parametrize(("fid", "clause"), ABSTENTION_CLAUSES)
def test_each_abstention_clause_is_present_and_declared(fid: str, clause: str):
    """Each clause is really in the text, and its fragment declares the stance."""
    frag = get(fid)
    assert clause in frag.text, f"{fid}: clause absent from transcribed text"
    want = _expected_stance(frag.text)
    assert want in frag.stance, (
        f"{fid} says {clause!r} so it must declare {want.value}, "
        f"not {[s.value for s in frag.stance]}")


def test_abstention_is_declared_at_every_site_and_no_others():
    """Neither softened nor inflated: the declared set is exactly the sites."""
    assert _declared_sites() == ABSTENTION_SITES


def test_soft_stance_only_where_the_text_qualifies():
    """A fragment may claim the soft stance ONLY if its text earns it.

    This is the anti-softening guard, and it now runs in both directions: a
    fragment declaring _AFTER_LOOKING whose text still says "it is the answer"
    fails, and so does a qualified fragment still declaring the hard stance.
    Item 4.1 qualified `validate/closure`, so that one legitimately holds the
    soft stance today — asserting otherwise would be pinning a stale
    transcription, which is what this file previously did.
    """
    for fid in ABSTENTION_SITES:
        frag = get(fid)
        want = _expected_stance(frag.text)
        assert want in frag.stance, f"{fid}: text wants {want.value}"
        wrong = ({Stance.BLESSES_ABSTENTION,
                  Stance.BLESSES_ABSTENTION_AFTER_LOOKING} - {want})
        assert not (wrong & set(frag.stance)), (
            f"{fid} declares {wrong} but its text says otherwise")


def test_stance_conflict_names_every_unqualified_abstention_site():
    """The 0.e report must name every site that still conflicts — no more.

    Sites whose text 4.1 qualified drop out, and that is correct: the live
    prompt no longer holds the contradiction there. The check itself stays
    pinned by test_lint_catches_the_pre_41_stance_conflict in
    test_0089_manifest_validate.py, against a fixture.
    """
    still_hard = frozenset(
        fid for fid in ABSTENTION_SITES
        if _expected_stance(get(fid).text) is Stance.BLESSES_ABSTENTION)
    assert _pairs_with_tools(_conflicts()) == still_hard


def test_tool_site_still_permits_tool_use():
    """The other half of the conflict — asserted so the test above cannot pass
    by the tool fragment losing its stance."""
    assert Stance.PERMITS_TOOL_USE in get(TOOL_SITE).stance
    assert VALIDATE_JUDGE.tools


def test_no_fragment_declares_a_stance_twice():
    """A stance list is a SET of positions, and a repeat is always an artifact.

    It has no meaning the single entry lacks, `check_03` already dedups by
    fragment id so it changes no lint row, and that is exactly why it can sit
    in a declaration unnoticed. It shows up when two edits add the same
    position to one fragment — the merge keeps both.
    """
    dupes = {fid: [s.value for s in get(fid).stance]
             for fid in VALIDATE_JUDGE.fragments + VALIDATE_JUDGE.user_fragments
             if len(set(get(fid).stance)) != len(get(fid).stance)}
    assert dupes == {}, f"repeated stance entries: {dupes}"
