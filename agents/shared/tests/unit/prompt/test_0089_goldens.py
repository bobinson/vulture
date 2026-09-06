"""Feature 0089 — the golden byte gate over EVERY manifest.

One test for all of them. A per-manifest test would let a set be added with no
golden and still be green; iterating `MANIFESTS` means a manifest that ships
without a committed golden fails here, naming the command that writes one.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

from shared.prompt import Mode, profile_for, render
from shared.prompt.manifests import MANIFESTS
from shared.prompt.profile import MODEL_PROFILES
from shared.prompt.spec import PromptSpec

_MANIFEST_ROOT = (
    Path(__file__).resolve().parents[3] / "shared" / "prompt" / "manifests"
)


def _load_capture():
    """Load the sibling capture script by path.

    `tests/unit/prompt/` is not a package, so a relative import would not
    resolve; loading by path also guarantees the test and the writer share one
    formatter — two copies of the layout would drift and the golden would then
    be testing the test.
    """
    path = Path(__file__).with_name("capture_goldens.py")
    spec = importlib.util.spec_from_file_location("_capture_goldens", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_capture = _load_capture()


@pytest.mark.parametrize("manifest_id", sorted(MANIFESTS))
def test_golden_bytes_default_profile(manifest_id):
    """Re-render and compare bytes against the committed golden."""
    spec = MANIFESTS[manifest_id]
    path = _capture.golden_path(manifest_id)
    assert path.exists(), (
        f"no golden for manifest {manifest_id!r} at {path}; write it with:\n"
        f"    {_capture.CAPTURE_CMD}"
    )
    rp = render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    assert _capture.golden_text(spec, rp) == path.read_text(encoding="utf-8"), (
        f"{manifest_id} no longer renders to its golden; if the change is "
        f"intended, re-run:\n    {_capture.CAPTURE_CMD}"
    )


@pytest.mark.parametrize(
    ("manifest_id", "family"),
    [(mid, fam) for mid, fam in _capture.captures() if fam != "default"],
    ids=lambda v: v,
)
def test_golden_bytes_adapt_profile(manifest_id, family):
    """The same gate over the ADAPT captures item 4.7 added.

    Separate from the TRANSCRIBE test rather than folded into it, because the
    two answer different questions and a merged failure would not say which.
    `.default` asks "does the transcription still hold" — the Phase 0-3 claim.
    `.<family>` asks "do the RULES still emit this" — the Phase 4 claim, and
    the only one that can see a `role:`, `seam:` or `keep_trailing:` change,
    since TRANSCRIBE reads no front matter at all.

    The rendering is done here rather than by calling `_capture.capture_one`,
    which WRITES: a checker that could rewrite the file it compares against
    would pass unconditionally. Only `golden_text` and `golden_path` are
    shared, and those are the two pieces that must not drift.
    """
    spec, rp = _capture._render_for(manifest_id, family)
    path = _capture.golden_path(manifest_id, family)
    assert path.exists(), (
        f"no {family} golden for manifest {manifest_id!r} at {path}; write it "
        f"with:\n    {_capture.CAPTURE_CMD}"
    )
    assert _capture.golden_text(spec, rp) == path.read_text(encoding="utf-8"), (
        f"{manifest_id} no longer renders to its {family} golden; if the "
        f"change is intended, re-run:\n    {_capture.CAPTURE_CMD}"
    )


def test_every_manifest_has_a_golden_for_every_captured_profile():
    """The gate cannot quietly stop covering a manifest or a profile.

    `captures()` is the writer's own list, so this is the assertion that the
    writer and the committed tree agree — a profile added to `ADAPT_PROFILES`
    with no capture run, or a golden file left behind by a deleted manifest,
    fails here rather than at review time.
    """
    expected = {_capture.golden_path(mid, fam) for mid, fam in _capture.captures()}
    on_disk = set(_capture.GOLDEN_DIR.rglob("*.txt"))
    assert on_disk == expected, (
        f"uncommitted golden(s): {sorted(str(p) for p in expected - on_disk)}; "
        f"orphaned file(s): {sorted(str(p) for p in on_disk - expected)}"
    )
    # Item 4.8 gave `AXIS_MANIFEST` a golden per FAMILY rather than per captured
    # class, so the count is no longer one number times another. Recomputed from
    # the two independent sources (the manifest set and the two profile lists)
    # rather than from `captures()` itself, which would make it a tautology.
    extra = set(_capture.axis_profiles()) - set(_capture.ADAPT_PROFILES)
    assert len(expected) == (
        len(MANIFESTS) * (1 + len(_capture.ADAPT_PROFILES)) + len(extra)
    )


def test_golden_validate_judge_all_profiles():
    """The axis-covering manifest, captured for EVERY family (plan §inventory).

    `ADAPT_PROFILES` commits one golden per equivalence CLASS, which is what
    makes 26 manifests affordable — and it is also what that set cannot see: a
    family inside a class has no bytes of its own, so changing `kimi`'s
    capabilities to match nothing would fail
    `test_every_family_matches_a_captured_profiles_golden` with a message about
    an unmatched family and no committed bytes to diff against. This gate gives
    the one spec that exercises all four axes — system role, tools, JSON mode,
    language pin — a file per family, so such a change is a diff.

    Named by the plan's test inventory, which asks for "8 profile goldens for
    the axis-covering manifest". Eight was the family count when the plan was
    written; `MODEL_PROFILES` carries ten now, and the derived set is what
    keeps "all profiles" true as that number moves — a literal 8 would have
    stopped covering `o-series` and `generic` the day they were added.
    """
    mid = _capture.AXIS_MANIFEST
    assert mid in MANIFESTS, mid
    families = _capture.axis_profiles()
    assert set(families) == set(MODEL_PROFILES), (
        "the axis capture no longer covers every family: "
        f"{sorted(set(MODEL_PROFILES) ^ set(families))}"
    )
    missing, drifted = [], []
    for family in families:
        spec, rp = _capture._render_for(mid, family)
        path = _capture.golden_path(mid, family)
        if not path.exists():
            missing.append(family)
        elif _capture.golden_text(spec, rp) != path.read_text(encoding="utf-8"):
            drifted.append(family)
    assert (missing, drifted) == ([], []), (
        f"{mid}: no golden for {missing}; no longer renders to its golden for "
        f"{drifted}. If the change is intended, re-run:\n"
        f"    {_capture.CAPTURE_CMD}"
    )
    # ...and the set is not vacuous, nor is it four copies of one file: the
    # language pin splits it, so at least two distinct renders must be present.
    bodies = {_capture.golden_path(mid, f).read_text(encoding="utf-8")
              for f in families}
    assert len(families) >= 8, families
    assert len(bodies) >= 2, "every family renders the same bytes here"


def test_every_family_matches_a_captured_profiles_golden():
    """No family's ADAPT render may go unpinned.

    `ADAPT_PROFILES` is five families standing in for ten (four until item 4.8
    split the language-pinning families off `generic`), and the claim that
    makes that legitimate is that the other five render IDENTICALLY to one of
    the five. That is a measurement, so it is measured here rather than
    asserted in a comment: every family is rendered over every manifest and
    must reproduce some captured profile's golden text exactly.

    This is what fails when a capability is added to `MODEL_PROFILES`, when an
    existing family's capabilities change, or when a new rule (4.8's language
    pin) splits a class — none of which any per-file golden comparison can see,
    because a family with no golden simply is not compared.

    Item 4.8 is the worked example: it split `qwen`, `glm`, `kimi` and `seed`
    off the `generic` class, and this test is what failed until one of them was
    added to `ADAPT_PROFILES`.
    """
    covered = {}
    for family in _capture.ADAPT_PROFILES:
        profile = profile_for(_capture.family_models()[family])
        covered[family] = tuple(
            _capture.golden_text(MANIFESTS[m],
                                 render(MANIFESTS[m], profile, mode=Mode.ADAPT))
            for m in sorted(MANIFESTS))
    orphans = {}
    for family, model in sorted(_capture.family_models().items()):
        profile = profile_for(model)
        rendered = tuple(
            _capture.golden_text(MANIFESTS[m],
                                 render(MANIFESTS[m], profile, mode=Mode.ADAPT))
            for m in sorted(MANIFESTS))
        match = [f for f, texts in covered.items() if texts == rendered]
        if not match:
            orphans[family] = model
    assert orphans == {}, (
        f"{sorted(orphans)} render unlike every captured profile "
        f"{list(_capture.ADAPT_PROFILES)}. Add one of them to ADAPT_PROFILES "
        f"and re-run:\n    {_capture.CAPTURE_CMD}"
    )
    # ...and the five are not five copies of one another: a set that collapsed
    # would satisfy the loop above while pinning a fifth of what it claims.
    assert len({texts for texts in covered.values()}) == len(covered)


def test_the_adapt_captures_can_actually_see_a_role_change():
    """Red team on the new dimension: does it distinguish a mirror or not?

    A golden set that could not tell a mirrored fragment from an unmirrored one
    would be 104 files of ceremony. Rather than mutate the tree, this renders
    one manifest twice — once as shipped, once with the same fragment demoted
    to `role: SYSTEM` in a scratch registry entry — and requires the two golden
    BODIES to differ on the discriminating family and to MATCH on gemma, which
    is the asymmetry the docstring in `capture_goldens` claims.
    """
    import dataclasses

    from shared.prompt import registry
    from shared.prompt.fragment import Role

    mirrored = registry.get("core/untrusted")
    assert mirrored.role is Role.SYSTEM_USER_MIRROR, "fixture assumption"
    demoted = dataclasses.replace(mirrored, id="rt/demoted", role=Role.SYSTEM)
    registry.FRAGMENTS[demoted.id] = demoted
    try:
        shipped = MANIFESTS["generate/cwe"]
        without = dataclasses.replace(
            shipped,
            fragments=tuple(demoted.id if f == mirrored.id else f
                            for f in shipped.fragments),
        )
        for family, must_differ in (("generic", True), ("gemma", False)):
            model = _capture.family_models()[family]
            profile = profile_for(model)
            a = _capture.golden_text(
                shipped, render(shipped, profile, mode=Mode.ADAPT))
            b = _capture.golden_text(
                without, render(without, profile, mode=Mode.ADAPT))
            assert (a != b) is must_differ, (
                f"{family}: demoting the mirror "
                f"{'changed nothing' if must_differ else 'changed the golden'}"
            )
    finally:
        registry.FRAGMENTS.pop(demoted.id, None)


def _manifest_modules() -> list[Path]:
    """Every manifest module on disk, found recursively.

    Recursive on purpose: `MANIFESTS` is built with `pkgutil.iter_modules`,
    which is NOT, so a manifest added inside a subpackage
    (`manifests/generate/cwe.py`) would be absent from the registry, absent
    from the golden gate, and absent from the lint sweep while its own test
    stayed green. That is the exact hole the registry docstring says it
    closes, so it is asserted here rather than assumed.
    """
    return [p for p in sorted(_MANIFEST_ROOT.rglob("*.py")) if p.name != "__init__.py"]


def _dotted(path: Path) -> str:
    rel = path.relative_to(_MANIFEST_ROOT).with_suffix("")
    return "shared.prompt.manifests." + ".".join(rel.parts)


def _module_specs(path: Path) -> list[PromptSpec] | str:
    """This module's module-level specs, or why they could not be collected."""
    try:
        mod = importlib.import_module(_dotted(path))
    except ImportError as exc:                       # e.g. subpackage with no __init__
        return f"not importable ({exc})"
    specs = [v for v in vars(mod).values() if isinstance(v, PromptSpec)]
    return specs or "defines no module-level PromptSpec"


def _unreachable(path: Path) -> list[str]:
    """Spec ids this module defines that `MANIFESTS` does not resolve to it."""
    specs = _module_specs(path)
    if isinstance(specs, str):
        return [f"{path.name}: {specs}"]
    return [f"{path.name}: {s.id!r}" for s in specs if MANIFESTS.get(s.id) is not s]


def test_every_manifest_module_reaches_the_registry():
    """No module under `manifests/` may define specs the registry cannot see.

    Imports each module and compares by IDENTITY, not by id string, so a
    module whose spec is shadowed by a same-id spec from another module fails
    here too — that is the duplicate `_claim` is meant to make fatal.
    """
    missing = [m for path in _manifest_modules() for m in _unreachable(path)]
    assert not missing, (
        "manifest module(s) not reachable via shared.prompt.manifests.MANIFESTS: "
        f"{missing}"
    )
