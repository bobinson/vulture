"""Item 4.8 — `core/language`, admitted by profile (LLD rule 9).

THE DEFECT. `promptlint`'s `check_12_language_pin` fired on eighteen specs —
the largest annotated block in the Phase 3 backlog — for one reason: no
fragment in the library carried `BINDS_LANGUAGE` at all, so every free-text
field in every tier egressed to the database and the UI with no bound output
language. The LLD names the failure it protects against (§ "language drift"):
*"GLM / Kimi / Seed may answer in Chinese under pressure"*, and the fix it
prescribes is *"one explicit output-language clause, once, in a fragment every
prompt includes"*.

THE RULE ALREADY EXISTED. `render._rule_language` has dropped
`BINDS_LANGUAGE` fragments for a profile whose `output_language_pin` is unset
since Phase 0, and until this item it could never fire, because no fragment on
disk declared that stance. This item is the fragment plus its admission at
every call site; the renderer is not touched.

WHAT IS ASSERTED HERE, AND WHY EACH ASSERTION EXISTS

  A  The fragment exists, declares `BINDS_LANGUAGE`, and says the two things
     the clause has to say. The second — that a quotation is copied, never
     translated — is not decoration: feature 0076 verifies `evidence_quote` by
     searching for it in the cited file, so a model that helpfully translated
     the line it quoted would turn every quote into `absent`. A language pin
     with no quotation exception would have made the anchor verifier worse.

  B  Admission is by PROFILE, not by tier or by call site. Rendered ADAPT, the
     clause is present for exactly the four families whose profile pins the
     output language and absent for the other six — asserted over every
     manifest × every family, so a spec that forgot to list it and a family
     that should not receive it fail differently.

  C  The TRANSCRIBE renders carry it unconditionally, and that is recorded
     rather than hidden. TRANSCRIBE applies no rule by construction, so the one
     call site still in that mode (the L5 judge — item 4.1 owns its flip) now
     sends the clause to every model. That is a real behaviour change beyond
     rule 9's scope; `_VERDICT_SCHEMA_VERSION` moves with it because every
     cached verdict was produced under the prompt without it.

  D  Production, not just the manifests. Four of the six call sites build their
     spec at call time (`generate.live_spec`, `domain_instructions`,
     `render_prove_prompt`, and the judge's `replace(...)`), so "the manifest
     lists it" is not the same claim as "the model is shown it". Each site is
     driven here.

  E  The eighteen exemptions are GONE, not silenced: no `language_pin` entry
     survives in any manifest's `allow`, and the sweep reports no such finding
     for any spec on any family.
"""

from __future__ import annotations

import dataclasses

import pytest

from shared.prompt import Mode, profile_for, render
from shared.prompt.fragment import Role, Stance
from shared.prompt.lint import family_models, gate, lint, sweep
from shared.prompt.manifests import MANIFESTS
from shared.prompt.profile import MODEL_PROFILES
from shared.prompt.registry import FRAGMENTS, get

PIN = "core/language"

# The families whose profile pins the output language. A literal, because the
# claim under test is that these four and no others receive the clause; reading
# it off `MODEL_PROFILES` would make every assertion below a tautology.
PINNED_FAMILIES = frozenset({"qwen", "glm", "kimi", "seed"})

# Every spec whose render must carry the clause: every manifest except two,
# named. Deliberately the COMPLEMENT of a named pair rather than a list of the
# 24, and never `[s for s in MANIFESTS if PIN in s.fragments]` — the latter
# would assert only that the tree equals itself, while this makes a NEW
# manifest a pinned spec by default and fails until it either lists the clause
# or is exempted here on purpose.
#
# `prove_retry_1` / `prove_retry_2` are the two exemptions. They have no system
# turn at all (`fragments=()`) — each is a user-turn suffix concatenated onto a
# prompt whose system turn is `prove_system`, which does carry the clause. A
# second copy in the suffix would state it twice per retry.
EXPECTED_PINNED_SPECS = frozenset(set(MANIFESTS) - {"prove_retry_1", "prove_retry_2"})


def _body(rp) -> str:
    return rp.instructions + "\n" + rp.user


def _pin_text() -> str:
    """The clause as the registry holds it — never a copy written here."""
    return get(PIN).text.strip("\n")


def _adapt(spec, family: str):
    return render(spec, profile_for(family_models()[family]), mode=Mode.ADAPT)


# ── A: the fragment itself ────────────────────────────────────────────────

def test_the_pin_fragment_exists_and_binds_language():
    """Rule 9's subject. Without the stance the rule cannot see it."""
    assert PIN in FRAGMENTS, sorted(FRAGMENTS)
    frag = get(PIN)
    assert Stance.BINDS_LANGUAGE in frag.stance, frag.stance
    assert frag.role in (Role.SYSTEM, Role.SYSTEM_USER_MIRROR), frag.role
    assert frag.text.strip(), "the clause is empty"


def test_the_pin_is_the_only_fragment_that_binds_language():
    """One clause, once (LLD §"language drift").

    Two binding fragments in one render would state the output language twice
    and `check_12` would be satisfied by either, so the second could drift
    unnoticed.
    """
    binders = sorted(fid for fid, f in FRAGMENTS.items()
                     if Stance.BINDS_LANGUAGE in f.stance)
    assert binders == [PIN], binders


def test_the_clause_states_the_language_and_exempts_quotations():
    """Both halves, because the second is what keeps 0076's verifier working.

    `evidence_quote` is checked by searching the cited file for the quoted
    bytes. A pin that told the model to write everything in English without
    exempting quoted source would instruct it to translate its own evidence,
    and every translated quote would verify as `absent`.
    """
    text = _pin_text().lower()
    assert "english" in text
    assert "quot" in text, "no quotation exception in the clause"
    assert "translat" in text, "the exception does not say quotes are not translated"


def test_the_clause_declares_no_field_and_no_vocabulary():
    """It constrains HOW fields are written, never WHICH fields exist.

    A `declares_fields` here would make it a second author of every tier's
    output contract (`check_02_duplicate_contract`), which is the duplication
    the library exists to remove.
    """
    frag = get(PIN)
    assert frag.declares_fields == ()
    assert frag.binds_vocabulary == ()
    assert frag.references == ()


# ── B: admitted by profile, over every manifest × every family ───────────

@pytest.mark.parametrize("family", sorted(MODEL_PROFILES))
def test_the_pinned_families_are_exactly_the_four(family: str):
    """The profile table is the rule's only input; pin what it says today."""
    pinned = profile_for(family_models()[family]).output_language_pin
    assert pinned is (family in PINNED_FAMILIES), (
        f"{family}: output_language_pin={pinned}, expected "
        f"{family in PINNED_FAMILIES}"
    )


@pytest.mark.parametrize("spec_id", sorted(EXPECTED_PINNED_SPECS))
def test_every_free_text_spec_lists_the_pin(spec_id: str):
    """The admission is a call-site declaration, one id per line (0089 §3.3)."""
    spec = MANIFESTS[spec_id]
    assert PIN in spec.fragments, spec.fragments


def test_the_two_retry_suffixes_do_not_list_it():
    """The complement, so "every spec" cannot be satisfied by listing it twice.

    A retry suffix is appended to a prompt whose system turn already carries
    the clause.
    """
    for spec_id in sorted(set(MANIFESTS) - EXPECTED_PINNED_SPECS):
        spec = MANIFESTS[spec_id]
        assert PIN not in spec.fragments + spec.user_fragments, spec_id


@pytest.mark.parametrize("family", sorted(MODEL_PROFILES))
def test_adapt_admits_the_clause_for_exactly_the_pinning_families(family: str):
    """Rule 9, measured on the rendered BYTES of every manifest.

    Not on `rp.fragments`, which reports the spec's list and is unmoved by any
    ADAPT rule — a test reading that field would pass for all ten families with
    the rule deleted.
    """
    clause = _pin_text()
    expected = family in PINNED_FAMILIES
    wrong = [sid for sid in sorted(EXPECTED_PINNED_SPECS)
             if (clause in _body(_adapt(MANIFESTS[sid], family))) is not expected]
    assert wrong == [], (
        f"{family}: clause {'missing from' if expected else 'present in'} "
        f"{len(wrong)} render(s): {wrong[:5]}"
    )


def test_the_rule_is_what_removes_it_and_not_the_fragment_list():
    """Red team: with the stance stripped, an unpinned family keeps the clause.

    The one mutation that tells "rule 9 fires" apart from "the fragment happens
    not to be listed". Done on a scratch registry entry and a scratch spec, so
    the tree is not touched.
    """
    from shared.prompt import registry

    frag = get(PIN)
    stanceless = dataclasses.replace(frag, id="rt/language_no_stance", stance=())
    registry.FRAGMENTS[stanceless.id] = stanceless
    try:
        spec = MANIFESTS["validate_judge"]
        mutated = dataclasses.replace(
            spec,
            fragments=tuple(stanceless.id if f == PIN else f
                            for f in spec.fragments),
            allow=(),
        )
        for family in ("openai", "gemma", "generic"):
            profile = profile_for(family_models()[family])
            shipped = _body(render(spec, profile, mode=Mode.ADAPT))
            without = _body(render(mutated, profile, mode=Mode.ADAPT))
            assert _pin_text() not in shipped, family
            assert _pin_text() in without, (
                f"{family}: the clause is gone even without BINDS_LANGUAGE, so "
                "rule 9 is not what removed it"
            )
    finally:
        registry.FRAGMENTS.pop(stanceless.id, None)


# ── C: the TRANSCRIBE consequence, recorded rather than hidden ───────────

@pytest.mark.parametrize("spec_id", sorted(EXPECTED_PINNED_SPECS))
def test_transcribe_carries_the_clause_for_every_model(spec_id: str):
    """TRANSCRIBE applies no rule, so a site in that mode ships it to everyone.

    True of exactly one production site when this item landed — the L5 judge —
    and asserted rather than left implicit, because it is the reason
    `_VERDICT_SCHEMA_VERSION` moved here. Item 4.1 has since flipped that site
    to ADAPT, so no production site renders TRANSCRIBE any more and the clause
    reaches only the four pinning families
    (`test_the_judge_system_prompt_carries_the_clause_only_where_it_is_asked_for`
    below is that statement). This assertion is now about the RENDERER alone,
    which is what it always compared; keeping it is what makes 4.1's narrowing
    a measurable delta rather than an unrecorded one.
    """
    rp = render(MANIFESTS[spec_id], profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    assert _pin_text() in _body(rp)


def test_the_cached_verdict_schema_version_moved_with_the_judge_prompt():
    """A verdict cached under the pre-4.8 judge prompt must not be served."""
    import re

    from shared.validate import l5_cache

    version = l5_cache._VERDICT_SCHEMA_VERSION
    match = re.match(r"v(\d+)-", version)
    assert match, f"unreadable cache schema version {version!r}"
    assert int(match.group(1)) >= 8, (
        f"still {version}: the judge's system turn changed (TRANSCRIBE admits "
        "the clause for every model), so the verdict cache key must move with "
        "it or a verdict reached under the older prompt is served for 30 days"
    )


# ── D: production, not just the manifests ────────────────────────────────

@pytest.mark.parametrize("family", sorted(MODEL_PROFILES))
def test_the_judge_system_prompt_carries_the_clause_only_where_it_is_asked_for(
    family: str,
):
    """`llm_judge`, both paths: tool-equipped and the plain degrade.

    BEFORE ITEM 4.1 this took no argument and asserted the clause was present
    unconditionally, which was the correct statement for a TRANSCRIBE site:
    that mode runs no rule, so the judge sent it to all ten families. 4.1
    flipped the site to ADAPT and rule 9 now confines it to the four whose
    profile pins the output language — the narrowing this item's own manifest
    note predicted would happen "by itself, with no edit here". So the
    assertion gains the axis it was missing rather than being dropped: present
    for a pinning family, ABSENT for the other six, and the expected side is
    the profile, never a list of family names.
    """
    from shared.validate.llm_judge import (
        _judge_system_prompt,
        _judge_system_prompt_plain,
    )

    model = family_models()[family]
    pins = profile_for(model).output_language_pin
    clause = _pin_text()
    assert (clause in _judge_system_prompt(1, model)) is pins, family
    assert (clause in _judge_system_prompt_plain(model)) is pins, family


@pytest.mark.parametrize("source", ("inline", "system", "none"))
def test_the_generate_live_spec_lists_the_pin_on_every_branch(source: str):
    """`live_spec` is production; the seven committed specs are its oracle."""
    from shared.prompt.manifests.generate import live_spec

    for flags in range(16):
        spec = live_spec(
            source=source, vocabulary=bool(flags & 1), fenced=bool(flags & 2),
            quote=bool(flags & 4), prior=bool(flags & 8),
        )
        assert PIN in spec.fragments, (source, flags, spec.fragments)


def test_a_pinning_profile_reaches_the_generate_system_turn():
    """The tier's live assembly, rendered for a family that pins."""
    from shared.prompt.manifests.generate import live_spec

    spec = live_spec(source="inline", vocabulary=True, fenced=True,
                     quote=True, prior=False)
    profile = profile_for(family_models()["glm"])
    assert _pin_text() in render(spec, profile, mode=Mode.ADAPT).instructions


def test_the_prove_system_turn_carries_it_for_a_pinning_profile():
    """PROVE renders its system turn from `PROVE_SYSTEM` once, at import."""
    from shared.prompt.manifests.prove_system import PROVE_SYSTEM

    profile = profile_for(family_models()["kimi"])
    assert _pin_text() in render(PROVE_SYSTEM, profile, mode=Mode.ADAPT).instructions


def test_the_discover_turn_carries_it_for_a_pinning_profile():
    from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST

    profile = profile_for(family_models()["seed"])
    rp = render(DISCOVER_SUGGEST, profile, mode=Mode.ADAPT)
    assert _pin_text() in _body(rp)


# ── E: the exemptions are retired, not silenced ──────────────────────────

def test_no_manifest_still_annotates_language_pin():
    """The eighteen `allow` entries are gone from the tree."""
    survivors = [(sid, a.fragment) for sid, spec in sorted(MANIFESTS.items())
                 for a in getattr(spec, "allow", ()) if a.check == "language_pin"]
    assert survivors == [], survivors


def test_the_check_reports_nothing_on_any_spec_or_family():
    """The finding itself is gone — the allow list is not what is hiding it."""
    offenders = [(sid, fam) for sid, spec in sorted(MANIFESTS.items())
                 for fam in sorted(MODEL_PROFILES)
                 for f in lint(spec, _adapt(spec, fam))
                 if f.check == "language_pin"]
    assert offenders == [], offenders


def test_the_sweep_gained_no_new_finding_from_the_clause():
    """Admitting a fragment must not trade one backlog entry for another."""
    rows = [(r.spec, r.family, f.check, f.fragment)
            for r in sweep()
            for f in tuple(r.report.findings) + tuple(r.report.errors)]
    assert rows == [], rows


@pytest.mark.parametrize("spec_id", sorted(EXPECTED_PINNED_SPECS))
def test_the_gate_is_clean_for_the_pinning_family_too(spec_id: str):
    """The sweep covers every family, but this names the ones the rule moves."""
    spec = MANIFESTS[spec_id]
    for family in sorted(PINNED_FAMILIES):
        report = gate(spec, _adapt(spec, family))
        assert report.ok, (spec_id, family, report.findings, report.errors)
