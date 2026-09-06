"""`test_version_bump_on_change` — a fragment cannot change without a bump.

Feature 0089, plan test inventory ("fingerprint change ⇒ manifest version
change"), and the Phase 4 red team: *"revert the fragment but not the version —
`test_version_bump_on_change` must fail."*

WHAT THIS DEFENDS. Phases 0-3 proved every fragment byte-equal to the live
builder it transcribes, and those parity tests are the reason a fragment edit
fails today. Phase 4 spends them: an item that deliberately rewords
`validate/closure` retires or rewrites that fragment's parity assertion, and
from then on the fragment has no oracle at all. Measured, before this file
existed:

* editing `validate/calibration` failed 9 tests — all of them "these bytes are
  not the transcription", none of them "bump the version";
* editing `generate/tools_only` failed **nothing**: 0 in `tests/unit/prompt`
  (364 tests) and 0 in the whole shared unit suite (2708 passed, 3 skipped)
  with a production prompt fragment silently altered. It is reachable — it is
  the empty-source branch of `live_spec` and the GENERATE tier's only sentence
  that permits tool use — but it is in no manifest, so no golden and no parity
  test renders it.

So this file is both the version gate and the only byte pin the seven
manifest-less fragments have.

WHAT IS PINNED, AND WHY IT IS TWO HASHES. `Fragment.fingerprint` covers the
fragment's TEXT. It does not cover the front matter, and `role:`, `seam:` and
`keep_trailing:` all move rendered bytes — `seam` decides whether the join
before a fragment is one newline or two, and Phase 4.7 changes `role:` on
several fragments to enable `SYSTEM+USER_MIRROR`. A text-only pin would sleep
through all of it, so each row carries a second digest over the declarations.
The two are separate so the failure says which half moved.

HOW TO SATISFY IT WHEN THE CHANGE IS INTENDED. Three edits in the one commit:
the fragment, the owning manifest's `version=`, and the row here (the failure
message prints the row to paste). Updating the row WITHOUT bumping the version
would go green — a pin can only compare against its own last review — which is
why the row is a hand-written literal in a test rather than a captured golden:
it is meant to be read in the diff, next to the version it certifies.
"""

from __future__ import annotations

import hashlib

import pytest

from shared.prompt import registry
from shared.prompt.manifests import MANIFESTS
from shared.prompt.manifests.generate import live_spec

# ── the pin ───────────────────────────────────────────────────────────────
#
# fragment id: (text fingerprint, declaration digest)
#
# Captured at the end of Phase 3 (tree 5f0beb4), when every fragment was still
# a byte-exact transcription of the live builder. A row moves only in the
# commit that moves the fragment.

PINNED: dict[str, tuple[str, str]] = {
    # Item 4.8 created this one. It is the library's ONLY `BINDS_LANGUAGE`
    # fragment, which is why `check_12_language_pin` could fire on eighteen
    # specs before it and on none after: the check asks whether the render
    # contains that stance, and until this file existed the answer was no
    # everywhere. Listed by 24 of the 26 manifests, so a change to it costs 24
    # version bumps — the price of stating the clause once instead of per tier.
    "core/language": ("eb802943ff62d396", "f1de918b5f4ff181"),
    # Item 4.3 created this one and RETIRED `validate/untrusted_warning`, whose
    # row is gone from this table for that reason: the two are one policy, and
    # keeping both would be the duplication the library exists to remove. The
    # declaration digest is unchanged from the fragment it replaces (same role,
    # same single MARKS_UNTRUSTED stance) — only the text moved, which is what
    # the two-hash split is for.
    #
    # Item 4.7 moved the DECLARATION half only: `role: SYSTEM` ->
    # `SYSTEM+USER_MIRROR`. The text hash is byte-identical, which is the
    # clearest case this table's two-hash split was written for — the whole
    # of the marker rule now also renders at the front of the user turn of
    # nine specs, and not one character of it changed.
    "core/untrusted": ("dba3022798c871b5", "9b541eb8b3fbc499"),
    # Phase 4.6 split the DISCOVER turn and rewrote both halves; both rows and
    # `VERSIONS["discover_suggest"]` moved in that one change.
    "discover/suggest": ("7de13ff0699ee316", "140c6ff2c24d1578"),
    "discover/system": ("c39041e4cd3ae5ae", "16ad218fc6c1695a"),
    "domains/asvs": ("43ddac3b0b5f6006", "1403cec6b1224115"),
    "domains/chaos": ("f83422f26557dfde", "61bfec93581a2123"),
    "domains/cwe": ("a89b463ab7377b30", "3008549c80c572ab"),
    "domains/do178c": ("0d50a3fdead2ab59", "61bfec93581a2123"),
    "domains/soc2": ("6615334023dd605b", "61bfec93581a2123"),
    "domains/ssdf": ("a4d31d7cd1144e36", "61bfec93581a2123"),
    "domains/xss": ("9b569e69cc7d4a03", "d9c08aae58571860"),
    # Item 4.4 owns the six GENERATE rows that follow, and its `VERSIONS`
    # entries move with them. Four fragments are NEW — the tier had no
    # presentation contract, no evidence discipline, no sentence permitting the
    # three tools it always attaches, and no statement of `severity`'s closed
    # set — and two moved:
    #
    # * `generate/json_fenced` — BOTH hashes. Its text stopped enumerating the
    #   eight field names (leaving `generate/field_contract` the only author of
    #   the list) and lost the `...` that `check_09` reported; its declaration
    #   digest moved because `declares_fields` is now empty.
    # * `generate/quote_obligation` — the DECLARATION half only, and the text
    #   hash is deliberately unchanged: the sentence is byte-identical and only
    #   its `role:` moved, SYSTEM+USER_MIRROR -> USER. That is exactly the split
    #   this table's two hashes exist for. The role IS the item: the sentence
    #   used to be emitted twice per call, and only on the unstructured branch,
    #   so a structured-output model saw it once and an LM Studio / Gemini model
    #   twice.
    "generate/evidence_discipline": ("6ee032e5f85be6c9", "61bfec93581a2123"),
    "generate/field_contract": ("059537642da43c36", "e8bab3adf1c7a537"),
    # Item 4.7: DECLARATION half only, `role` -> SYSTEM+USER_MIRROR. Text
    # unchanged from 4.4.
    "generate/json_fenced": ("c24148e3bc93857f", "19c46c70eae622be"),
    "generate/prior_context": ("b9dd40c2d32be481", "04b9f55d3aca2b60"),
    "generate/quote_obligation": ("a6e36c535b6c1b1d", "58d9da2e3a21b037"),
    "generate/source_in_system": ("5247706b8f4591a0", "d9c08aae58571860"),
    "generate/source_in_system_ref": ("c490d9853ee60056", "140c6ff2c24d1578"),
    "generate/source_inline": ("5247706b8f4591a0", "04b9f55d3aca2b60"),
    "generate/source_presentation": ("2f67a4432e26b967", "61bfec93581a2123"),
    "generate/task": ("174a948ef0cbb8db", "140c6ff2c24d1578"),
    "generate/tool_trigger": ("be3354ec3690cee7", "4ce8710c96bcc6f9"),
    "generate/tools_only": ("2238ecda15965bf2", "1525327738b3f0dd"),
    "generate/vocab_category": ("4dfddcb6838fdba8", "61bfec93581a2123"),
    # The one row whose declaration digest carries a `binds_vocabulary`. Until
    # item 4.4, `parse_fragment` set that field to `()` unconditionally and
    # never read the key, so no fragment on disk could close a
    # `check_04_vocab_closure` gap; this row is the first one that does, and its
    # digest is what would move if the bound set drifted from
    # `audit_runner._SEVERITY_WEIGHTS`.
    "generate/vocab_severity": ("ccbcace1b162b6d9", "0307f17d6cc65eef"),
    "prove/analyze": ("e2594e6aaa2280a3", "734d44ed556c570f"),
    "prove/analyze_http": ("83a35a835d9695bc", "734d44ed556c570f"),
    "prove/analyze_jsonrpc": ("68899e08346ed62b", "734d44ed556c570f"),
    "prove/analyze_ws": ("0735ee5108bf343f", "734d44ed556c570f"),
    "prove/plan": ("50dc865449b2f432", "9bb9d4086fcbc881"),
    "prove/plan_chaos": ("48b5873e167439df", "9bb9d4086fcbc881"),
    "prove/plan_cwe": ("f29553a71ce04baf", "6326663742175727"),
    "prove/plan_owasp": ("32c1fb6a74845141", "9bb9d4086fcbc881"),
    "prove/plan_soc2": ("b4608a2343b5078c", "9bb9d4086fcbc881"),
    "prove/plan_ssdf": ("a9b16237684cb63a", "9bb9d4086fcbc881"),
    "prove/reflect": ("da6cade4908b8f01", "2ae5feb493e1a965"),
    "prove/reflect_chaos": ("5aebd089578f2601", "2ae5feb493e1a965"),
    "prove/reflect_cwe": ("df60fdf064b66ad2", "2ae5feb493e1a965"),
    "prove/reflect_owasp": ("4082fbcd2592e1ac", "2ae5feb493e1a965"),
    "prove/reflect_soc2": ("a5f05e80e329a7b2", "2ae5feb493e1a965"),
    "prove/reflect_ssdf": ("9e3ee0f410e91f78", "2ae5feb493e1a965"),
    "prove/retry_guidance_1": ("51aad6ba742f972e", "3ca0b17fb39a0cf6"),
    "prove/retry_guidance_2": ("87139f0e41ec8071", "3ca0b17fb39a0cf6"),
    "prove/system": ("a2303c99fa112c56", "02d18fd9e91a78c4"),
    "validate/calibration": ("21c605fde941c79b", "61bfec93581a2123"),
    "validate/closure": ("197d6c869aa35005", "95329efab1b7d51e"),
    # Item 4.2 rewrote the citation section to ONE coordinate space and gave
    # the contract `evidence_file`; `validate/tool_discipline` lost its
    # competing definition of `evidence_line`. All three rows and both
    # `VERSIONS["validate_judge*"]` moved in that one change.
    "validate/evidence_citation": ("b2cce6e3e5de1f47", "95329efab1b7d51e"),
    "validate/language_idioms": ("a423459da75a6545", "61bfec93581a2123"),
    # Item 4.7: DECLARATION half only, `role` -> SYSTEM+USER_MIRROR. It was
    # declared and not shipped while the judge site rendered TRANSCRIBE; item
    # 4.1 flipped that site, so the declaration is live and the row is
    # unchanged — the fragment's BYTES never moved for either item.
    "validate/output_contract": ("6ea2375bc8a8d847", "8340330e6aea1336"),
    "validate/role": ("b8a29ed6369f5fcf", "61bfec93581a2123"),
    "validate/tool_discipline": ("24d419e2becd3dfc", "1d2c380fddeaeb91"),
    # Item 4.7: DECLARATION half only, `keep_trailing: true`. Not a mirrored
    # fragment — the one the mirror lands ON. `verbatim` preserved this
    # template's terminator only while it was the SOLE user fragment, and a
    # mirrored fragment ahead of it routes the turn through `_seam_join` —
    # which item 4.1's flip is what actually makes happen on the wire. Its
    # bytes did not move for either item, so the row does not either.
    "validate/user_template": ("7bb6281141d60dcf", "8d8d98f8b5676001"),
}

# manifest spec id: the `version=` its PromptSpec carries.
VERSIONS: dict[str, int] = {
    "discover_suggest": 3,        # item 4.8 (4.6 took it to 2)
    "generate/asvs": 5,           # item 4.8 (4.7 took it to 4)
    "generate/chaos": 5,          # item 4.8 (4.7 took it to 4)
    "generate/cwe": 5,            # item 4.8 (4.7 took it to 4)
    "generate/do178c": 5,         # item 4.8 (4.7 took it to 4)
    "generate/soc2": 5,           # item 4.8 (4.7 took it to 4)
    "generate/ssdf": 5,           # item 4.8 (4.7 took it to 4)
    "generate/xss": 5,            # item 4.8 (4.7 took it to 4)
    "prove_analyze_http": 3,      # item 4.8 (4.5 took it to 2)
    "prove_analyze_jsonrpc": 3,   # item 4.8
    "prove_analyze_ws": 3,        # item 4.8
    "prove_plan_chaos": 3,        # item 4.8
    "prove_plan_cwe": 3,          # item 4.8
    "prove_plan_owasp": 3,        # item 4.8
    "prove_plan_soc2": 3,         # item 4.8
    "prove_plan_ssdf": 3,         # item 4.8
    "prove_reflect_chaos": 3,     # item 4.8
    "prove_reflect_cwe": 3,       # item 4.8
    "prove_reflect_owasp": 3,     # item 4.8
    "prove_reflect_soc2": 3,      # item 4.8
    "prove_reflect_ssdf": 3,      # item 4.8
    # The only two specs item 4.8 did not touch: a retry suffix has no system
    # turn (`fragments=()`), and the turn it is appended to already carries the
    # clause via `prove_system`.
    "prove_retry_1": 1,
    "prove_retry_2": 1,
    "prove_system": 3,              # item 4.8 (4.5 took it to 2)
    # Item 4.1, the mode flip: the only bump in this table that no fragment
    # row below accounts for. `version` tracks the prompt a manifest SENDS, and
    # what moved is `llm_judge._judge_prompt`'s `mode=` constant — three rules
    # switching on at once (mirror, language pin, no-system-role fold). The
    # fragment pins are therefore unchanged for this item, which is exactly the
    # combination `unbumped()` cannot flag, so it is spelled out here instead.
    "validate_judge": 6,            # item 4.1 (4.8 took it to 5)
    "validate_judge_plain": 6,      # item 4.1
}

# ── who owns a fragment that no manifest lists ────────────────────────────
#
# `MANIFESTS` collects module-level `PromptSpec` literals, and two production
# specs are built per call instead: `generate.live_spec()` (five booleans, so no
# single render to commit) and the collapsed prove template spec inside
# `prove_agent.llm_helper.render_prove_prompt`. Their branch-only fragments
# therefore appear in no manifest and have no `version` of their own to bump.
#
# The owning versions are declared here rather than invented: each entry names
# the manifest specs that ARE the committed transcription of the same call
# site, which is the same set that already has to bump when a shared fragment
# of that tier changes. `generate/task` is listed by all seven GENERATE specs,
# so a change to it costs seven bumps today; `generate/tools_only` is the same
# tier's alternative user-turn tail, so it costs the same seven. Nothing here
# is heavier than the equivalent change to a fragment one line away from it.

_GENERATE = tuple(sorted(s for s in VERSIONS if s.startswith("generate/")))
_PROVE_PLAN = tuple(sorted(s for s in VERSIONS if s.startswith("prove_plan_")))
_PROVE_REFLECT = tuple(sorted(s for s in VERSIONS if s.startswith("prove_reflect_")))
_PROVE_ANALYZE = tuple(sorted(s for s in VERSIONS if s.startswith("prove_analyze_")))

DYNAMIC_OWNERS: dict[str, tuple[tuple[str, ...], str]] = {
    "generate/prior_context": (
        _GENERATE, "live_spec(prior=True): the memory-context block of the "
                   "same user turn the seven GENERATE specs transcribe"),
    "generate/source_in_system": (
        _GENERATE, "live_spec(source='system'): the anthropic prompt-caching "
                   "branch, source body in the system turn"),
    "generate/source_in_system_ref": (
        _GENERATE, "live_spec(source='system'): the user-turn pointer that "
                   "replaces the body on that branch"),
    "generate/tools_only": (
        _GENERATE, "live_spec(source='none'): the empty-source branch, and the "
                   "tier's only sentence that permits tool use"),
    "prove/plan": (
        _PROVE_PLAN, "the collapsed template the five prove_plan_* specs "
                     "transcribe per strategy (Phase 2.6)"),
    "prove/reflect": (
        _PROVE_REFLECT, "the collapsed template of the five prove_reflect_* "
                        "specs (Phase 2.6)"),
    "prove/analyze": (
        _PROVE_ANALYZE, "the collapsed template of the three prove_analyze_* "
                        "specs, one per protocol (Phase 2.6)"),
}


# ── live values ───────────────────────────────────────────────────────────

def _declaration_digest(frag) -> str:
    """A digest over everything in the front matter that can move bytes.

    Ordered and explicit rather than `repr(dataclasses.astuple(...))`: a field
    added to `Fragment` must be considered here on purpose, and
    `test_the_declaration_digest_covers_every_declared_field` fails until it is.
    """
    parts = (
        frag.role.value,
        "|".join(s.value for s in frag.stance),
        "|".join(frag.declares_fields),
        # Empty for every fragment but one. `parse_fragment` set this to `()`
        # unconditionally until feature 0089 item 4.4 taught it the
        # `field=[a, b]` front-matter shape; `generate/vocab_severity` is the
        # first fragment to bind a vocabulary, and this line is why its digest
        # differs from every other plain SYSTEM fragment's.
        ";".join(f"{k}={','.join(v)}" for k, v in frag.binds_vocabulary),
        "|".join(frag.references),
        "|".join(frag.exemplars),
        frag.version,
        str(frag.verbatim),
        frag.seam,
        str(frag.keep_trailing),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def live_rows() -> dict[str, tuple[str, str]]:
    return {fid: (f.fingerprint, _declaration_digest(f))
            for fid, f in registry.FRAGMENTS.items()}


def live_versions() -> dict[str, int]:
    return {sid: spec.version for sid, spec in MANIFESTS.items()}


def owners_of(fragment_id: str) -> tuple[str, ...]:
    """The manifest specs whose `version` must move when this fragment does."""
    listed = tuple(sorted(
        sid for sid, spec in MANIFESTS.items()
        if fragment_id in tuple(spec.fragments) + tuple(spec.user_fragments)
    ))
    return listed or DYNAMIC_OWNERS.get(fragment_id, ((), ""))[0]


# ── the rule, as a pure function so it can be red-teamed directly ─────────

def unbumped(
    pinned: dict[str, tuple[str, str]],
    live: dict[str, tuple[str, str]],
    pinned_versions: dict[str, int],
    versions: dict[str, int],
    owners,
) -> list[str]:
    """One message per fragment that moved while an owning version did not."""
    out: list[str] = []
    for fid in sorted(set(pinned) & set(live)):
        if pinned[fid] == live[fid]:
            continue
        moved = "text" if pinned[fid][0] != live[fid][0] else "declarations"
        stale = [o for o in owners(fid)
                 if versions.get(o) == pinned_versions.get(o)]
        if stale:
            out.append(
                f"{fid}: {moved} changed ({pinned[fid]} -> {live[fid]}) but "
                + ", ".join(f"{o} is still version {versions.get(o)}"
                            for o in stale)
                + f". Bump it (to {max(versions.get(o, 0) for o in stale) + 1}), "
                f're-capture that spec\'s golden, and pin the new row: '
                f'"{fid}": {live[fid]!r},'
            )
    return out


# ── the gate ──────────────────────────────────────────────────────────────

def test_version_bump_on_change():
    """A fragment's bytes may not move unless an owning manifest version does."""
    stale = unbumped(PINNED, live_rows(), VERSIONS, live_versions(), owners_of)
    assert stale == [], (
        f"{len(stale)} fragment(s) changed without a manifest version "
        "bump:\n" + "\n".join(stale)
    )


def test_the_pin_is_current():
    """...and once bumped, the row here is re-pinned, or the next change is free.

    Separate from the gate above so the two failures read differently: that one
    means "you forgot the bump", this one means "you bumped, now record what
    you bumped it for". A pin left behind after a legitimate change silently
    admits the NEXT change to the same fragment.
    """
    live = live_rows()
    drifted = {fid: (PINNED[fid], live[fid])
               for fid in sorted(set(PINNED) & set(live)) if PINNED[fid] != live[fid]}
    assert drifted == {}, (
        "re-pin these rows in PINNED (fragment: (pinned, live)):\n"
        + "\n".join(f'    "{fid}": {new!r},   # was {old!r}'
                    for fid, (old, new) in drifted.items())
    )
    assert live_versions() == VERSIONS, (
        "a manifest version moved; update VERSIONS in this file so the pin "
        "keeps certifying a known state: "
        f"{ {k: v for k, v in live_versions().items() if VERSIONS.get(k) != v} }"
    )


# ── the pin cannot quietly stop covering things ───────────────────────────

def test_the_pin_covers_every_fragment_and_every_manifest():
    """A new fragment or manifest is a deliberate addition here, not a silence."""
    assert set(PINNED) == set(registry.FRAGMENTS), (
        f"unpinned fragment(s): {sorted(set(registry.FRAGMENTS) - set(PINNED))}; "
        f"pinned but gone: {sorted(set(PINNED) - set(registry.FRAGMENTS))}"
    )
    assert set(VERSIONS) == set(MANIFESTS), (
        f"unpinned manifest(s): {sorted(set(MANIFESTS) - set(VERSIONS))}; "
        f"pinned but gone: {sorted(set(VERSIONS) - set(MANIFESTS))}"
    )


def test_every_fragment_has_at_least_one_owning_version():
    """A fragment nobody owns is a fragment nobody has to bump for."""
    orphans = [fid for fid in sorted(registry.FRAGMENTS) if not owners_of(fid)]
    assert orphans == [], (
        f"{orphans}: listed by no manifest and named in no DYNAMIC_OWNERS entry, "
        "so this file would let them change for free"
    )


def test_dynamic_owner_entries_are_neither_stale_nor_invented():
    """The `allow_stale` lesson from the Phase 3 gate, applied to this table."""
    listed_anywhere = {f for spec in MANIFESTS.values()
                       for f in tuple(spec.fragments) + tuple(spec.user_fragments)}
    for fid, (specs, why) in sorted(DYNAMIC_OWNERS.items()):
        assert fid in registry.FRAGMENTS, f"{fid}: no such fragment"
        assert fid not in listed_anywhere, (
            f"{fid} IS listed by a manifest now — the manifest is authoritative "
            "and this entry has rotted into a second, unread answer"
        )
        assert specs, f"{fid}: empty owner list"
        assert why.strip(), f"{fid}: no reason"
        assert set(specs) <= set(MANIFESTS), f"{fid}: unknown spec(s) {specs}"


def test_the_declaration_digest_covers_every_declared_field():
    """A new `Fragment` field must be added to the digest, or it moves bytes free.

    `text` is covered by `fingerprint` and `id` names the row, so those two are
    the only exemptions.
    """
    from dataclasses import fields

    covered = {"role", "stance", "declares_fields", "binds_vocabulary",
               "references", "exemplars", "version", "verbatim", "seam",
               "keep_trailing"}
    declared = {f.name for f in fields(registry.Fragment)} - {"id", "text"}
    assert declared == covered, (
        f"Fragment gained/lost a declaration: {declared ^ covered}. Add it to "
        "_declaration_digest and re-pin, or this file stops seeing it."
    )


def test_dynamic_fragments_really_are_rendered_by_production():
    """The seven manifest-less rows must be reachable, or they are dead pins.

    Drives the real builder over its whole branch space rather than asserting
    against a list: `live_spec` is production, and if a branch stops emitting a
    fragment this fails instead of the pin quietly guarding nothing.
    """
    reached: set[str] = set()
    for source in ("inline", "system", "none"):
        for flags in range(16):
            spec = live_spec(
                source=source,
                vocabulary=bool(flags & 1), fenced=bool(flags & 2),
                quote=bool(flags & 4), prior=bool(flags & 8),
            )
            reached |= set(spec.fragments) | set(spec.user_fragments)
    generate_dynamic = {f for f in DYNAMIC_OWNERS if f.startswith("generate/")}
    assert generate_dynamic <= reached, generate_dynamic - reached


@pytest.mark.parametrize("fid", sorted(f for f in DYNAMIC_OWNERS
                                       if f.startswith("prove/")))
def test_collapsed_prove_templates_are_named_by_production_code(fid):
    """The prove side of the same question: the id is a literal in the runtime.

    `render_prove_prompt(user_fragment=...)` takes the id as an argument, so the
    only place the binding exists is the caller — `strategies/*.py` and the two
    protocol executors. A text scan is the honest check; importing them proves
    nothing about which id they pass.
    """
    from pathlib import Path

    here = Path(__file__).resolve()
    root = next((p for p in here.parents
                 if (p / "agents").is_dir() and (p / "backend").is_dir()), None)
    assert root is not None, f"no vulture checkout above {here}"
    prove = root / "agents" / "prove" / "prove_agent"
    assert prove.is_dir(), prove
    hits = [p.name for p in prove.rglob("*.py")
            if f'"{fid}"' in p.read_text(encoding="utf-8")]
    assert hits, f"{fid} is named by no prove runtime module"


# ── red team: the rule itself must bite ───────────────────────────────────

_PINNED_FIXTURE = {"f/a": ("aaaa", "1111"), "f/b": ("bbbb", "2222")}
_VERSIONS_FIXTURE = {"spec/x": 1, "spec/y": 1}


def _owners_fixture(fid: str) -> tuple[str, ...]:
    return ("spec/x", "spec/y") if fid == "f/a" else ("spec/y",)


def test_an_edited_fragment_without_a_bump_is_reported():
    live = {"f/a": ("EDITED", "1111"), "f/b": ("bbbb", "2222")}
    out = unbumped(_PINNED_FIXTURE, live, _VERSIONS_FIXTURE,
                   dict(_VERSIONS_FIXTURE), _owners_fixture)
    assert len(out) == 1 and out[0].startswith("f/a: text changed")
    assert "spec/x is still version 1" in out[0]
    assert "spec/y is still version 1" in out[0]
    assert '"f/a": (\'EDITED\', \'1111\'),' in out[0], out[0]


def test_a_declaration_only_edit_is_reported_and_named_as_such():
    """`seam:` or `role:` moves rendered bytes without touching the text."""
    live = {"f/a": ("aaaa", "CHANGED"), "f/b": ("bbbb", "2222")}
    out = unbumped(_PINNED_FIXTURE, live, _VERSIONS_FIXTURE,
                   dict(_VERSIONS_FIXTURE), _owners_fixture)
    assert len(out) == 1 and out[0].startswith("f/a: declarations changed")


def test_an_edit_with_the_bump_is_accepted():
    live = {"f/a": ("EDITED", "1111"), "f/b": ("bbbb", "2222")}
    bumped = {"spec/x": 2, "spec/y": 2}
    assert unbumped(_PINNED_FIXTURE, live, _VERSIONS_FIXTURE, bumped,
                    _owners_fixture) == []


def test_a_partial_bump_still_fails_and_names_only_the_laggard():
    """Every owning spec bumps: a shared fragment changed the prompt of each."""
    live = {"f/a": ("EDITED", "1111"), "f/b": ("bbbb", "2222")}
    half = {"spec/x": 2, "spec/y": 1}
    out = unbumped(_PINNED_FIXTURE, live, _VERSIONS_FIXTURE, half, _owners_fixture)
    assert len(out) == 1
    assert "spec/y is still version 1" in out[0]
    assert "spec/x" not in out[0]


def test_reverting_a_fragment_without_reverting_the_version_fails():
    """The plan's own Phase 4 red team, in the direction it names.

    "revert the fragment but not the version" — the text goes back, the version
    stays where the item left it, and the pin no longer describes the tree. It
    must fail, because a pin that only noticed changes in one direction would
    make a revert the cheapest way to ship an unreviewed prompt.
    """
    pinned_after_item = {"f/a": ("VERSION_2_TEXT", "1111")}
    reverted = {"f/a": ("aaaa", "1111")}
    versions = {"spec/x": 2, "spec/y": 2}
    out = unbumped(pinned_after_item, reverted, versions, versions, _owners_fixture)
    assert len(out) == 1 and "f/a: text changed" in out[0]
