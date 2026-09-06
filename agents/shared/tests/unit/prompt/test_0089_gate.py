"""The Phase 3 CI gate over promptlint. Feature 0089 §5.

Phase 3 adds no check and fixes no prompt. It turns the twelve existing checks
into a gate: every violation the library trips today is annotated on its own
manifest with an owner and the item that owns the fix, and anything NOT
annotated fails the build.

The tests here defend the two ways a gate like this stops working:

* it stops covering — a new spec, a new family, or a fragment that declares a
  field no schema has, and nothing fails;
* it stops meaning anything — the allow list grows quietly, or an entry rots
  into an assertion about a defect that was fixed years ago.

`lint()` itself is deliberately untouched and still returns EVERY finding.
Phase 1's manifest tests assert that specific checks fire on specific specs, so
a `lint()` that filtered its own output by the allow list would silence the
audit record this phase exists to gate. The partitioning lives in `gate()`.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest

from shared.prompt import LintAllow, PromptSpec, gate, lint, profile_for
from shared.prompt.lint import family_models, sweep
from shared.prompt.manifests import MANIFESTS
from shared.prompt.profile import MODEL_PROFILES
from shared.prompt.render import Mode, render

# ── the committed backlog ─────────────────────────────────────────────────
#
# The number of annotations in the tree at the end of Phase 3. It is a
# CEILING, not a target: Phase 4 drives it to zero, and nothing may raise it
# without the raise being a visible, reviewed edit to this line.
#
# 71 -> 69: Phase 4.6 replaced the DISCOVER exemplar with valid JSON, which
# retired BOTH of `discover_suggest`'s text findings at once — `exemplar_validity`
# and `placeholder_echo`, which `check_09` raised on the same bare `...`. The
# manifest recorded them as needing "different repairs (valid JSON vs. no
# echoable placeholder)"; one repair satisfied both, because the ellipsis WAS
# the invalid token.
#
# 69 -> 63: Item 4.5 retired six more — the five `placeholder_echo` exemptions
# on `prove/plan_*` (the exemplar no longer teaches `/real-path` or `payload
# if POST`) and cwe's one `orphan_field` (the plan schema now carries
# `filename`).
#
# 63 -> 61: Item 4.2 retired the `dangling_reference` exemption on
# `validate/evidence_citation`, which `_judge_allow` hands to BOTH judge specs
# — hence two entries for one repair. The fragment declared
# `references: [numbered_snippet]` against a render that supplies no such
# variable and no such slot, because the "numbered snippet" coordinate space
# existed in that one sentence and nowhere else. 4.2 states one space (the
# file's own numbering), so the reference has nothing left to dangle from.
#
# 61 -> 59: item 4.3 retired the `placeholder_echo` exemption on
# `validate/untrusted_warning` — again two entries for one repair, because
# `_judge_allow` gives it to both judge specs. The exemption was not addressed;
# the FRAGMENT was retired. Its `...` came from documenting the marker pairs as
# `<<<CODE ... CODE>>>`, i.e. from eliding the content between them, and
# `core/untrusted` documents the same markers as `<<<CHANNEL:TOKEN` — naming
# the part that matters instead of eliding the part that does not, so there is
# no ellipsis left to annotate.
#
# Note what 4.3 did NOT add. It put `check_05_slot_marking` and
# `check_06_marker_forgery` into force on real manifests for the first time —
# both were structurally silent while no spec declared an untrusted channel —
# and neither needed an entry, which is that item's stated measurement.
#
# 59 -> 26: item 4.4, the largest single retirement in Phase 4. All 33 were
# GENERATE entries, and each went because the prompt change its reason named
# actually landed — 7 specs x 4 tier-wide entries plus 5 specs x 1:
#
#   tool_announcement    x7  `generate/tool_trigger` is on every branch, so the
#                            three file tools attached to every call are
#                            permitted by a sentence the model is shown. It
#                            states the two budgets `shared.llm.loop_detector`
#                            actually kills at, read from that module.
#   vocab_closure        x7  `generate/vocab_severity` binds `severity`'s closed
#                            set. That needed `parse_fragment` to start reading
#                            a `binds_vocabulary:` key at all — it hardcoded
#                            `()`, so no fragment on disk could close one.
#   duplicate_contract   x7  on `generate/json_fenced`: it states the wire shape
#                            and no longer enumerates the eight field names.
#   placeholder_echo     x7  on the same fragment: the `...` it reported was
#                            fence-syntax illustration in the sentence that was
#                            rewritten.
#   duplicate_contract   x5  on `generate/field_contract`, for the five agents
#                            whose `domains/` fragment ships no field list. cwe
#                            and asvs keep theirs: that half is the agent
#                            identity's "## Reporting Format" block, pinned
#                            byte-for-byte against the constant those agents'
#                            own unit tests assert on.
#
# 26 -> 8: item 4.8, and the last block that spanned every tier. All 18 were
# `language_pin`, one per spec with a free-text schema field — 1 discover, 7
# generate, 3 prove_analyze, 5 prove_plan, 2 validate — and one fragment
# retired all of them: `core/language` is the library's first and only
# `BINDS_LANGUAGE` fragment, which is the stance `check_12` looks for. Before
# it, the check could not have passed anywhere; the annotation was recording
# the absence of a fragment rather than a per-tier defect, which is why one
# addition closed 18 entries.
#
# What remains is 8, and none of it is tier-wide: the two `domains/` fragments
# of cwe and asvs ship their own "## Reporting Format" field list (5 entries
# across `duplicate_contract` / `orphan_field` / `placeholder_echo`) and the
# judge's verdict exemplar uses angle-bracket type placeholders instead of
# parseable JSON (2 entries, one per judge spec). Both belong to text this
# feature does not own.
COMMITTED_ALLOW_ENTRIES = 8

# A reason has to name the item that owns the fix. Both forms are accepted
# because the backlog spans phases of this feature and one item (`linked_cwe`)
# lands in Phase 2.5, before Phase 4 starts.
_OWNS_A_FIX = re.compile(r"\b(?:Phase \d+(?:\.\d+)?|feature \d{4})\b")


def _allows():
    """(spec_id, allow) for every annotation in the tree."""
    return [(sid, a) for sid, spec in sorted(MANIFESTS.items())
            for a in getattr(spec, "allow", ())]


def _render(spec):
    return render(spec, profile_for("gpt-4o"), mode=Mode.ADAPT)


# ── the gate is closed ────────────────────────────────────────────────────

def test_the_sweep_is_clean_on_every_spec_and_family():
    """The gate's whole contract: nothing unannotated, no stale annotation.

    This is what CI runs. It sweeps ADAPT renders of every manifest against
    every capability family, so a spec added without annotations — or an
    annotation left behind by a fix — fails here rather than at review time.
    """
    offenders = [(r.spec, r.family, f.check, f.fragment, f.message)
                 for r in sweep()
                 for f in tuple(r.report.findings) + tuple(r.report.errors)]
    assert offenders == [], (
        f"{len(offenders)} unannotated violation(s)/allow-list error(s); "
        f"annotate them on the spec's manifest or fix them:\n"
        + "\n".join(map(str, offenders))
    )


def test_the_sweep_covers_every_spec_and_every_family():
    """A gate that silently stopped rendering something would also be clean."""
    rows = sweep()
    assert {r.spec for r in rows} == set(MANIFESTS)
    assert {r.family for r in rows} == set(MODEL_PROFILES)
    assert len(rows) == len(MANIFESTS) * len(MODEL_PROFILES)


def test_every_family_resolves_through_profile_for():
    """`family_models` must yield a real profile of the family it claims.

    `MODEL_PROFILES` values carry capabilities only — no `family`, no
    `ctx_window` — so a model string is the only honest way in, and a needle
    that stopped matching would silently downgrade that family to `generic`.
    """
    for family, model in family_models().items():
        assert profile_for(model).family == family, (family, model)


# ── the allow list means something ────────────────────────────────────────

def test_allow_list_is_bounded():
    """The backlog may shrink freely; growing it takes an edit to this file.

    Without a pinned ceiling the cheapest way past a red build is one more
    allow entry, and the gate degrades into a list of checks somebody turned
    off — one annotation at a time, each individually defensible.
    """
    n = len(_allows())
    assert n <= COMMITTED_ALLOW_ENTRIES, (
        f"the allow list grew to {n} (committed: {COMMITTED_ALLOW_ENTRIES}). "
        "Fix the violation, or raise COMMITTED_ALLOW_ENTRIES deliberately."
    )
    assert n == COMMITTED_ALLOW_ENTRIES, (
        f"the allow list shrank to {n} — Phase 4 progress. Lower "
        f"COMMITTED_ALLOW_ENTRIES to {n} so the ceiling keeps ratcheting down."
    )


def test_every_allow_entry_is_owned_and_names_the_item_that_owns_the_fix():
    """An unowned or unexplained exemption is indistinguishable from a mute."""
    for spec_id, a in _allows():
        where = f"{spec_id} :: {a.check}+{a.fragment}"
        assert a.owner.strip(), f"{where}: no owner"
        assert a.reason.strip(), f"{where}: no reason"
        assert _OWNS_A_FIX.search(a.reason), (
            f"{where}: reason names no Phase item or feature number: {a.reason!r}"
        )


def test_no_two_allow_entries_on_one_spec_share_a_key():
    """A duplicate key hides a second, unreviewed reason behind the first."""
    for spec_id, spec in sorted(MANIFESTS.items()):
        keys = [(a.check, a.fragment) for a in getattr(spec, "allow", ())]
        assert len(keys) == len(set(keys)), f"{spec_id}: duplicate keys in allow"


# ── red team: the gate must bite ──────────────────────────────────────────

_SPEC = PromptSpec(id="rt", tier="test", fragments=("domains/asvs",),
                   schema_fields=("severity",))


def test_a_fragment_declaring_a_field_in_no_schema_fails_the_gate():
    """The plan's first red-team probe: an unfielded instruction must fail."""
    report = gate(_SPEC, _render(_SPEC))
    orphans = [f for f in report.findings if f.check == "orphan_field"]
    assert orphans, f"orphan_field must reach the gate unannotated: {report}"
    assert not report.ok


def test_the_same_violation_annotated_passes_the_gate():
    """...and the annotation is what makes it pass — nothing else changed."""
    allowed = [LintAllow("orphan_field", "domains/asvs",
                         reason="Phase 4.4 — red-team fixture", owner="tester")]
    spec = PromptSpec(id="rt", tier="test", fragments=("domains/asvs",),
                      schema_fields=("severity",), allow=tuple(allowed))
    report = gate(spec, _render(spec))
    assert [f.check for f in report.findings if f.check == "orphan_field"] == []
    assert any(f.check == "orphan_field" for f in report.allowed)


@pytest.mark.parametrize("missing", ["owner", "reason"])
def test_an_allow_missing_owner_or_reason_fails_the_gate(missing):
    """The plan's second red-team probe.

    Two things must be true, not one: the incomplete entry is reported, AND it
    does not grant the exemption. An entry that silenced the check while
    reporting itself would still hide the finding from anyone who read only the
    violations section.
    """
    kw = {"owner": "tester", "reason": "Phase 4.4 — red-team fixture"}
    kw[missing] = ""
    spec = PromptSpec(id="rt", tier="test", fragments=("domains/asvs",),
                      schema_fields=("severity",),
                      allow=(LintAllow("orphan_field", "domains/asvs", **kw),))
    report = gate(spec, _render(spec))
    assert [f.message for f in report.errors] == [f"allow entry has no {missing}"]
    assert any(f.check == "orphan_field" for f in report.findings), (
        "an incomplete entry must not grant the exemption it failed to earn"
    )
    assert not report.ok


def test_a_stale_allow_entry_fails_the_gate():
    """An allow matching nothing must fail rather than rot.

    This is the failure mode that makes a gate lie: the backlog item is fixed,
    the check stops firing, the annotation stays, and the next real occurrence
    of that check on that fragment is admitted in silence.
    """
    spec = PromptSpec(
        id="rt", tier="test", fragments=("domains/asvs",),
        schema_fields=("severity",),
        allow=(LintAllow("orphan_field", "domains/asvs",
                         reason="Phase 4.4 — real", owner="tester"),
               LintAllow("stance_conflict", "domains/asvs",
                         reason="Phase 4.4 — fixed long ago", owner="tester")),
    )
    report = gate(spec, _render(spec))
    assert [(f.check, f.fragment) for f in report.errors] == [
        ("allow_stale", "stance_conflict+domains/asvs")]
    assert not report.ok


def test_lint_still_returns_every_finding_for_phase_1_callers():
    """`lint()` must not filter: Phase 1 asserts these very findings fire.

    The set was `{orphan_field, duplicate_contract, language_pin}` until item
    4.8, which retired `language_pin` on this spec along with seventeen others
    — the check no longer fires here, so requiring it would be requiring a
    defect to still exist. The two that remain are enough for what this test
    asserts, which is that `lint()` reports what `gate()` then annotates away:
    the gate is clean below and the raw check output is not.
    """
    spec = MANIFESTS["generate/asvs"]
    rp = _render(spec)
    assert gate(spec, rp).findings == ()          # gate is clean
    checks = {f.check for f in lint(spec, rp)}    # lint is not
    assert {"orphan_field", "duplicate_contract"} <= checks
    assert "language_pin" not in checks, (
        "item 4.8 retired this finding; `lint()` reporting it again means "
        "`core/language` left this render"
    )


# ── the CLI ───────────────────────────────────────────────────────────────

def _cli(*args):
    return subprocess.run([sys.executable, "-m", "shared.prompt.lint", *args],
                          capture_output=True, text=True, check=False)


def test_cli_exits_zero_on_the_current_tree():
    """The CI gate itself. Non-zero here is a red build."""
    done = _cli()
    assert done.returncode == 0, done.stdout + done.stderr
    assert "PASS" in done.stdout


def test_cli_json_mode_is_parseable_and_reports_the_backlog():
    """`--json` must keep stdout clean — runpy's warning goes to stderr."""
    done = _cli("--json")
    assert done.returncode == 0, done.stdout + done.stderr
    payload = json.loads(done.stdout)
    assert payload["ok"] is True
    assert payload["findings"] == [] and payload["errors"] == []
    assert payload["specs"] == len(MANIFESTS)
    assert payload["families"] == len(MODEL_PROFILES)
    assert payload["allow_entries"] == COMMITTED_ALLOW_ENTRIES
