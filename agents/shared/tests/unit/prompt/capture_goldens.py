"""Write the committed golden render of every manifest. Feature 0089.

A SCRIPT, not a test: pytest must not collect it (no `test_` name, no
module-level work), because writing the file it is asked to compare against
would make the golden gate unfalsifiable. `test_0089_goldens.py` imports
`golden_text` from here so the writer and the checker share one formatter.

Run from `agents/shared`:

    python tests/unit/prompt/capture_goldens.py

Output is byte-deterministic across runs and across machines: neither mode
emits a nonce here (no manifest has slots), nothing in the layout carries a
timestamp or a hostname, and the four captured sections are the profile-
independent ones — the environment can move `output_budget_hint`, which is
deliberately not in the file.

TWO KINDS OF GOLDEN, added by item 4.7.

`<id>.default.txt` is the TRANSCRIBE render on `gpt-4o` and is what Phases 0-3
proved byte-equal to the live builders. It cannot see a `role:` change at all:
TRANSCRIBE places a fragment by which TUPLE the manifest lists it in and never
reads its front matter, so item 4.7 flipped three fragments to
`SYSTEM+USER_MIRROR` and moved zero bytes in all 26 of these files. A golden
that cannot fail for the change being made is not evidence about it.

`<id>.<family>.txt` is the ADAPT render, one per family in `ADAPT_PROFILES`
(plus, for one manifest, one per family outright — see the axis note below),
and is where the rules are visible.

WHY FIVE FAMILIES AND NOT TEN. The ten capability families collapse to exactly
five distinct ADAPT renders over the whole manifest set — four until item 4.8
split the language-pinning families off `generic` — measured, not
assumed, and `test_every_family_matches_a_captured_profiles_golden` re-measures
it on every run, so a family whose render stops matching its class fails
instead of going unpinned:

* `openai`   — with `o-series`. `Structured.NATIVE`: rules 4+5 drop the prose
               JSON contract, and they run BEFORE the mirror, so
               `generate/json_fenced` appears in neither turn here. This is the
               only class where that ordering is observable.
* `claude`   — `Structured.EMULATED_TOOL`, `json_mode_with_tools=False`.
* `generic`  — with `gemini`: two families, one render. System role plus
               `Structured.NONE`, which makes it the DISCRIMINATING profile for
               item 4.7 — a mirrored fragment appears in BOTH turns here and an
               unmirrored one in exactly one, so the two cases are
               distinguishable in the file.
* `glm`      — with `qwen`, `kimi`, `seed`: the four families whose profile
               pins the output language. ITEM 4.8 SPLIT THEM OFF `generic`,
               which is what that item's arrival looks like in this file: they
               were six families and one render before it and are two classes
               now, differing by exactly `core/language`. The four are
               identical to each other — the capabilities they differ in
               (`reasoning_leak`, `reasoning_overhead_tokens`) reach only
               `output_budget_hint`, which is deliberately not captured — so
               one of them stands for all four here, and
               `test_every_family_matches_a_captured_profiles_golden` is what
               re-measures that on every run.
* `gemma`    — no system role, and the profile the plan's 4.7 measurement
               names. It is the one that CANNOT discriminate the mirror: rule 1
               folds the entire system turn into the user turn for this family,
               so the mirrored text is in gemma's user turn with or without the
               mirror, and all 26 of these files are byte-identical across item
               4.7. Captured anyway, because "nothing is lost when there is no
               system turn" is the other half of the claim and needs committed
               bytes of its own.

THE AXIS-COVERING MANIFEST. `validate_judge` is captured for EVERY family, not
just for the five above, and it is the only manifest that is. The LLD asks for
exactly that (§5 Layer B: *"the one manifest that exercises every axis (system
role, tools, JSON mode, language pin), across all profiles in ADAPT mode.
Portability rules are proven here once; every other manifest inherits them
through the same renderer"*) and it is the only spec in the library that
exercises all four axes at once — a system turn, attached tools, a JSON
contract, and free-text output that the language pin binds.

The five extra files that buys are the ones no equivalence class would commit:
`o-series`, `gemini`, `qwen`, `kimi` and `seed` each render like one of the
five captured classes today, so a capability change to any ONE of them is
invisible in a class representative's golden and visible here. Item 4.8's own
golden column names three of them (`validate_judge.<glm,kimi,seed>`), which is
this set.
"""

from __future__ import annotations

from pathlib import Path

from shared.prompt import Mode, profile_for, render
from shared.prompt.lint import family_models
from shared.prompt.manifests import MANIFESTS

GOLDEN_DIR = Path(__file__).resolve().parents[3] / "shared" / "prompt" / "goldens"
GOLDEN_PROFILE = "gpt-4o"
CAPTURE_CMD = "cd agents/shared && python tests/unit/prompt/capture_goldens.py"

# One family per distinct ADAPT render (see the docstring). Resolved to a model
# string through `lint.family_models()` — the linter's own inversion of
# `_FAMILY_PATTERNS` — so these goldens and the lint sweep can never disagree
# about which model represents a family.
ADAPT_PROFILES: tuple[str, ...] = ("openai", "claude", "generic", "gemma",
                                   "glm")

# The one manifest captured for every capability family (see the docstring).
# A single id rather than a list: the claim is that ONE spec exercises every
# axis, and a second entry would be a second answer to which spec that is.
AXIS_MANIFEST = "validate_judge"


def axis_profiles() -> tuple[str, ...]:
    """Every family, for `AXIS_MANIFEST`. Read from the profile table.

    Derived, never listed: a family added to `MODEL_PROFILES` must gain a
    golden here on the next capture, and `test_golden_validate_judge_all_
    profiles` fails until it does. A hand-written list would simply stop
    covering the new family, silently — the same failure mode `family_models()`
    exists to avoid one layer down.
    """
    from shared.prompt.profile import MODEL_PROFILES

    return tuple(sorted(MODEL_PROFILES))


def profiles_for(manifest_id: str) -> tuple[str, ...]:
    """The ADAPT families one manifest is captured for."""
    if manifest_id == AXIS_MANIFEST:
        return axis_profiles()
    return ADAPT_PROFILES


_NONE = "(none)"


def golden_text(spec, rp) -> str:
    """The golden file body for one rendered manifest.

    Sections are fixed and always all four present, so a prompt that loses its
    system turn shows up as an empty section rather than as a missing one.
    """
    tools = ", ".join(spec.tools) or _NONE
    rf = repr(rp.response_format) if rp.response_format is not None else _NONE
    return "\n".join((
        "=== SYSTEM ===", rp.instructions,
        "=== USER ===", rp.user,
        "=== TOOLS ===", tools,
        "=== RESPONSE_FORMAT ===", rf,
    )) + "\n"


def golden_path(manifest_id: str, family: str = "default") -> Path:
    """Where one manifest's golden lives, per capture.

    A manifest id may contain `/` (`generate/cwe`), so this is a nested path,
    not a flat filename — and the checker calls the same function, so the two
    cannot disagree about where to look. `family` is `"default"` for the
    TRANSCRIBE capture and a `MODEL_PROFILES` key for an ADAPT one; both go
    through this one function so a new dimension cannot be half-wired.
    """
    return GOLDEN_DIR / f"{manifest_id}.{family}.txt"


def _render_for(manifest_id: str, family: str):
    """The (spec, rendered) pair one golden file records.

    The mode is decided by the family, not passed in: `"default"` IS the
    TRANSCRIBE capture and every named family IS an ADAPT one, so there is no
    combination in which a file's name and its contents can disagree about
    which mode produced it.
    """
    spec = MANIFESTS[manifest_id]
    if family == "default":
        return spec, render(spec, profile_for(GOLDEN_PROFILE), mode=Mode.TRANSCRIBE)
    model = family_models()[family]
    return spec, render(spec, profile_for(model), mode=Mode.ADAPT)


def capture_one(manifest_id: str, family: str = "default") -> Path:
    spec, rp = _render_for(manifest_id, family)
    path = golden_path(manifest_id, family)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(golden_text(spec, rp), encoding="utf-8")
    return path


def captures() -> list[tuple[str, str]]:
    """Every (manifest, family) pair with a committed golden, in file order."""
    return [(mid, fam) for mid in sorted(MANIFESTS)
            for fam in ("default", *profiles_for(mid))]


def main() -> int:
    for manifest_id, family in captures():
        print(f"wrote {capture_one(manifest_id, family)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
