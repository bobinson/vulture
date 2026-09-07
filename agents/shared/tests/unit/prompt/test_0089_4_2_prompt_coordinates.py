"""Feature 0089 item 4.2 — one coordinate space in the judge PROMPT.

The audit's blocker (LLD §9.5, first row): ``evidence_line`` was asked for in
two coordinate spaces in the same request. ``validate_judge.txt:46-48`` said
*"the ONE line number (from the numbered snippet)"* and ``judge_tools.py``'s
tool contract said *"evidence_line in the file you read it from"*. One field,
two meanings, and one consumer (``_citation_class``) that assumes a single one.
promptlint saw the symptom from the declarations alone —
``check_07_dangling_reference`` on ``validate/evidence_citation``, whose
``references: [numbered_snippet]`` resolved to nothing in the render, because
the snippet coordinate space existed only in that sentence.

WHAT THIS FILE PINS, and why each assertion cannot be made anywhere else:

* the space is stated ONCE and is the FILE's own numbering, in both the system
  prompt and the tool contract — a text assertion, because two fragments
  agreeing is not something a declaration can express;
* ``evidence_file`` exists in the schema, is declared by exactly one fragment,
  and is named by the contract the model is shown;
* the dangling reference is GONE rather than annotated — the allow entry it
  had is retired, which is what item 4.2 is expected to pay for;
* the retained originals (``prompts/validate_judge.txt``,
  ``_TOOL_DISCIPLINE_TEMPLATE``) moved WITH the fragments. They are the
  transcription's oracle and production reads neither; the assembly suite
  compares the live turns against them, so a fragment edited without them
  would leave that oracle asserting a prompt nobody is sent.

Offline: file reads and string comparison only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import shared.validate as _validate_pkg
from shared.prompt import Mode, lint, profile_for, render
from shared.prompt.manifests.validate_judge import (
    VALIDATE_JUDGE,
    VALIDATE_JUDGE_PLAIN,
)
from shared.prompt.registry import get
from shared.prompt.schema import VERDICT_SCHEMA
from shared.validate.judge_tools import tool_discipline_prompt

_PROMPTS = Path(_validate_pkg.__file__).parent / "prompts"
SYSTEM_SRC = (_PROMPTS / "validate_judge.txt").read_text(encoding="utf-8")

SPECS = (VALIDATE_JUDGE, VALIDATE_JUDGE_PLAIN)


def _rendered(spec) -> str:
    return render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE).instructions


# ── one coordinate space ──────────────────────────────────────────────────

@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_the_snippet_coordinate_space_is_gone(spec):
    """BEFORE 4.2 the citation section read "(from the numbered snippet)".

    That phrase is the second space. It is not enough that the tool contract
    stopped contradicting it; the phrase itself has to go, because a snippet is
    not a coordinate system the model can be held to.
    """
    text = _rendered(spec)
    assert "numbered snippet" not in text
    assert "from the numbered snippet" not in text


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_the_one_space_is_stated_and_it_is_the_file(spec):
    text = _rendered(spec)
    assert "evidence_line" in text
    lowered = text.lower()
    assert "file" in lowered
    # The two presentations the model actually sees, named so the number it is
    # shown and the number it reports are the same number.
    assert "L<n>: " in text
    assert "<n>: " in text


def test_the_tool_contract_no_longer_redefines_the_line():
    """BEFORE 4.2: "(evidence_line in the file you read it from)".

    That parenthetical is the tool-side redefinition. The file now travels in
    `evidence_file`, so the tool contract may name the file — it may not
    re-scope the line.
    """
    contract = get("validate/tool_discipline").text
    assert "evidence_line in the file you read it from" not in contract
    assert "evidence_file" in contract
    # ...and the live template it transcribes moved with it.
    assert "evidence_line in the file you read it from" not in tool_discipline_prompt(1)
    assert "evidence_file" in tool_discipline_prompt(1)


# ── evidence_file is a real field, declared once ──────────────────────────

def test_evidence_file_is_in_the_verdict_schema_next_to_the_line():
    names = tuple(f.name for f in VERDICT_SCHEMA.fields)
    assert "evidence_file" in names
    assert names.index("evidence_file") == names.index("evidence_line") + 1
    field = next(f for f in VERDICT_SCHEMA.fields if f.name == "evidence_file")
    assert field.required is False


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_the_spec_carries_the_schema_and_one_fragment_declares_it(spec):
    assert spec.schema_fields == tuple(f.name for f in VERDICT_SCHEMA.fields)
    declaring = [get(f) for f in spec.fragments if get(f).declares_fields]
    assert [f.id for f in declaring] == ["validate/output_contract"]
    assert set(declaring[0].declares_fields) == set(spec.schema_fields)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_the_model_is_shown_the_field_it_is_asked_for(spec):
    """A schema field no prompt mentions is a field no model will emit."""
    assert "evidence_file" in _rendered(spec)


# ── the linter finding this item was raised against ───────────────────────

@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_the_dangling_reference_is_gone_not_annotated(spec):
    """`check_07` fired on `validate/evidence_citation`; 4.2 retires it."""
    rp = render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    dangling = [f for f in lint(spec, rp) if f.check == "dangling_reference"]
    assert dangling == [], dangling
    assert get("validate/evidence_citation").references == ()
    allows = [(a.check, a.fragment) for a in spec.allow]
    assert ("dangling_reference", "validate/evidence_citation") not in allows


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_no_new_lint_finding_was_created_by_the_rewrite(spec):
    """The rewrite may retire a violation; it may not trade one for another.

    LITERAL SHORTENED BY ITEM 4.3, in the direction this test permits. It read

        assert checks == ["exemplar_validity", "language_pin", "placeholder_echo"]

    and `placeholder_echo` is gone because 4.3 retired the fragment that raised
    it: `validate/untrusted_warning` documented the marker pairs as
    `<<<CODE ... CODE>>>`, and `_PLACEHOLDERS` carries a bare `...`. The
    replacement, `core/untrusted`, writes the same markers as
    `<<<CHANNEL:TOKEN`. The remaining two are unchanged, so 4.3 traded nothing
    — which is the property this test exists to hold, and it holds in the
    direction the docstring above already allows.

    SHORTENED AGAIN BY ITEM 4.8, in the same direction. It read

        assert checks == ["exemplar_validity", "language_pin"]

    and `language_pin` is gone because that item added `core/language`, the
    library's first `BINDS_LANGUAGE` fragment, which is what `check_12` looks
    for. One finding is left on this spec and it belongs to the verdict
    exemplar's angle-bracket type placeholders, which no item has claimed.
    """
    rp = render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    checks = sorted({f.check for f in lint(spec, rp)})
    assert checks == ["exemplar_validity"]


# ── the version moved with the bytes ──────────────────────────────────────

@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.id)
def test_the_manifest_version_was_bumped(spec):
    assert spec.version >= 2, (
        "item 4.2 changes three validate fragments; the manifest version is "
        "how a cached render and a stale golden are told apart"
    )


# ── the retained originals moved with the fragments ───────────────────────

def test_the_retained_prompt_file_states_the_same_one_space():
    """`prompts/validate_judge.txt` is the assembly suite's only non-library
    byte source. Left behind, it would assert the pre-4.2 prompt forever."""
    assert "numbered snippet" not in SYSTEM_SRC
    assert "evidence_file" in SYSTEM_SRC


@pytest.mark.parametrize("fid", ["validate/evidence_citation",
                                 "validate/output_contract"])
def test_the_rewritten_fragments_are_still_byte_exact_in_the_retained_file(fid):
    assert get(fid).text in SYSTEM_SRC, (
        f"{fid} and prompts/validate_judge.txt disagree; the transcription "
        "oracle must be edited in the same commit as the fragment"
    )


# ── the substitution rule the fragments must not trip ─────────────────────

@pytest.mark.parametrize("fid", ["validate/evidence_citation",
                                 "validate/output_contract",
                                 "validate/tool_discipline"])
def test_no_doubled_braces_reached_the_rewritten_fragments(fid):
    """`render._fill` is one-pass `{name}` substitution, not `str.format`.

    A `{{` written out of `.format` habit ships TWO literal braces to the
    model. Fourteen fragments carried that defect before it was found; a
    rewrite is exactly when it comes back.
    """
    text = get(fid).text
    assert "{{" not in text and "}}" not in text
