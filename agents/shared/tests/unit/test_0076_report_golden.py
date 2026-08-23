"""0076 T5.2 / T5.3 / AC25 — the anchor-verifier golden and its staleness gate.

WHY A GOLDEN AT ALL. `shared/anchor.py` decides, offline, whether a model's claim can
be located in the file it accuses. That decision is the whole business contract of
feature 0076, and it is the kind of contract that rots silently: a knob default moves,
a normalisation step changes, and the verifier keeps returning *a* status for every
claim while returning a *different* one than the fixtures were authored to produce.
Unit assertions catch the case they name; a committed, regenerated table catches the
case nobody thought to name, because every row of it has to still be true.

WHAT AC25 PINS, and what this module therefore asserts:

  * three exit codes — current -> 0, stale -> 1, missing -> 1
  * ``--check`` is **provably read-only**: the golden's bytes AND its ``st_mtime_ns``
    are identical after a check run, and a check against a missing golden does not
    create one. "It only reads" is an easy thing to believe and an easy thing to
    break (the obvious `--check` implementation that "helpfully" writes on drift
    turns a CI gate into a rubber stamp), so it is measured, not asserted in prose.
  * the ``--write`` -> ``--check`` round-trip closes: what the writer produced is
    exactly what the checker accepts, and a second write is byte-identical to the
    first (idempotence — a non-idempotent writer makes every PR diff noise).

WHAT THE PLAN IS EXPLICIT ABOUT, and what the derivation tests below exist for: every
count in the rendered table is **derived from the input**, never hand-typed. So the
tests never compare the header against a literal they also had to maintain — they
compare it against ``len(load_manifest(...))`` for several different manifests. A
report that hard-coded its N would pass on one fragment and fail on the next.

T5.3, the fragment layout, mirrors ``agents/cwe/tests/corpus/manifest.d/``: production
fragments are globbed; a fragment whose basename starts with ``_`` is excluded from
that glob and loadable only by explicit name, so the unit-test slice can never leak
into the committed attestation's N.

Tier V throughout (plan section 5.8): hand-authored claims plus the on-disk fixture
tree under ``tests/fixtures/anchor/``. No model, no network, no writes to the scanned
tree — the last of which is asserted here rather than assumed.
"""

from __future__ import annotations

import importlib.util
import os
import socket
from pathlib import Path

import pytest

# tests/unit/test_0076_report_golden.py -> agents/shared/
_SHARED_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _SHARED_ROOT / "tools" / "report_anchor_status.py"

# The banner literal, written out here rather than imported from the module under
# test: a generated file that stops declaring itself generated is exactly the drift
# this pin exists to catch, and importing the constant would make the test agree with
# any value the module happens to hold.
BANNER = "<!-- GENERATED FILE — do NOT edit by hand"


def _load_tool():
    """Import ``tools/report_anchor_status.py`` by path.

    It is a repo-local script, not a member of the installed ``shared`` package (the
    wheel ships ``packages = ["shared"]`` only), so there is no import name for it.
    Loading by path keeps it that way instead of inventing a package to hold one file.
    """
    spec = importlib.util.spec_from_file_location("report_anchor_status", _TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def tool():
    return _load_tool()


@pytest.fixture
def sandboxed(tool, tmp_path, monkeypatch):
    """The tool with its golden redirected into ``tmp_path``.

    Every exit-code test needs a golden it may freely create, corrupt and delete; the
    committed one must survive the suite untouched. ``GOLDEN_PATH`` is read at call
    time for exactly this reason.
    """
    monkeypatch.setattr(tool, "GOLDEN_PATH", tmp_path / "ANCHOR_STATUS.md")
    return tool


def _fingerprint(path: Path) -> tuple[bytes, int]:
    """(bytes, mtime_ns) — the two things a write cannot leave unchanged."""
    stat = path.stat()
    return path.read_bytes(), stat.st_mtime_ns


def _tree_fingerprint(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


# ══ T5.3 — manifest as fragments, with `_`-prefixed exclusion ═════════════════

def test_underscore_prefixed_fragments_are_excluded_from_the_default_glob(tool):
    """The unit-test slice must never enter the committed attestation's N.

    Mirrors ``corpus_runner.load_manifest``: production fragments are globbed, and a
    leading underscore is the opt-out. Without the exclusion, adding a test fixture
    silently changes a published count — the CWE corpus learned this the expensive way
    and the plan says to copy the answer, not the mistake.
    """
    default_ids = {e["id"] for e in tool.load_manifest()}
    golden_ids = {e["id"] for e in tool.load_manifest(["_golden"])}

    assert golden_ids, "the _golden fragment must exist and carry claims"
    assert not (default_ids & golden_ids), (
        "an `_`-prefixed fragment leaked into the default glob: "
        f"{sorted(default_ids & golden_ids)}"
    )


def test_an_excluded_fragment_is_still_loadable_by_explicit_name(tool):
    """Exclusion is about the *default* glob, not about reachability."""
    explicit = tool.load_manifest(["_golden"])

    assert len(explicit) >= 2, "the golden slice needs at least two claims to be useful"
    assert all("id" in e and "expect" in e for e in explicit)


def test_every_manifest_entry_declares_an_expectation_in_the_status_vocabulary(tool):
    """A claim whose `expect` is outside the nine statuses can never agree with an
    observation, so it would sit in the table as a permanent, meaningless failure."""
    from shared.anchor import STATUSES

    unknown = {
        e["id"]: e["expect"]
        for e in tool.load_manifest()
        if e["expect"] not in STATUSES
    }
    assert not unknown, f"manifest expectations outside the nine statuses: {unknown}"


# ══ the table itself ══════════════════════════════════════════════════════════

def test_the_manifest_exercises_every_one_of_the_nine_statuses(tool):
    """AC12's coverage claim, restated as a property of the committed manifest.

    The golden is only an attestation if it attests to the whole vocabulary; a table
    that silently stopped producing `found_elsewhere` would still render, still pass a
    staleness check, and still be regenerated on every commit.
    """
    from shared.anchor import STATUSES

    observed = {row["observed"] for row in tool.build_rows()}

    assert observed == set(STATUSES), (
        f"statuses never produced by the manifest: {sorted(set(STATUSES) - observed)}"
    )


def test_every_observed_status_agrees_with_the_manifest_expectation(tool):
    """The substance of the attestation: the verifier does what the fixtures say.

    This is the assertion the committed table makes durable. It is stated here too so
    a disagreement fails as a named test rather than only as a diff.
    """
    disagreements = {
        row["id"]: (row["expect"], row["observed"], row["reason"])
        for row in tool.build_rows()
        if not row["agrees"]
    }
    assert not disagreements, f"verifier outcome drifted from the manifest: {disagreements}"


def test_the_report_carries_the_generated_file_banner(tool):
    markdown = tool.build_markdown()

    assert BANNER in markdown, "a generated file must say so, in the file"
    assert "--write" in markdown, "the banner must name the regeneration command"


# ══ counts are DERIVED, never hand-typed ══════════════════════════════════════

@pytest.mark.parametrize("fragments", [None, ["_golden"]])
def test_the_headline_count_is_derived_from_the_manifest(tool, fragments):
    """N must track the input for *every* input.

    Compared against ``len(load_manifest(...))`` rather than a literal, and over two
    manifests of different size: a hard-coded N passes the first case and fails the
    second, which is precisely the failure a single-case test cannot see.
    """
    expected = len(tool.load_manifest(fragments))
    markdown = tool.build_markdown(fragments)

    assert f"**N = {expected} claims**" in markdown
    assert expected == len(tool.build_rows(fragments))


def test_the_histogram_counts_sum_to_the_claim_total(tool):
    """A per-status breakdown that does not add up to N is not a breakdown of N."""
    rows = tool.build_rows()
    histogram = tool.build_histogram(rows)

    assert sum(h["claims"] for h in histogram) == len(rows)
    assert {h["status"] for h in histogram} == set(__import__(
        "shared.anchor", fromlist=["STATUSES"]).STATUSES), (
        "the histogram must list all nine statuses, including the unexercised ones"
    )


def test_no_status_carries_a_positive_weight_in_the_table(tool):
    """AC27, as a property of the published table rather than only of the code.

    The report prints the weight both at the default posture and with
    ``VULTURE_LLM_QUOTE_DEMOTE_ABSENT`` armed, because a reader's first question about
    an attestation of a *verifier* is what it can do to a finding. The answer must
    stay "nothing, except demote `absent` when explicitly armed".
    """
    histogram = {h["status"]: h for h in tool.build_histogram(tool.build_rows())}

    assert all(h["weight"] == 0.0 for h in histogram.values()), (
        "no status may carry a non-zero weight at the default posture"
    )
    armed = {s: h["weight_armed"] for s, h in histogram.items() if h["weight_armed"] != 0.0}
    assert armed == {"absent": -1.0}, f"only `absent` may arm, and only negatively: {armed}"


# ══ AC25 — the three exit codes ═══════════════════════════════════════════════

def test_check_exits_zero_when_the_golden_is_current(sandboxed):
    assert sandboxed.main(["--write"]) == 0
    assert sandboxed.main(["--check"]) == 0


def test_check_exits_one_when_the_golden_is_stale(sandboxed):
    assert sandboxed.main(["--write"]) == 0
    sandboxed.GOLDEN_PATH.write_text(
        sandboxed.GOLDEN_PATH.read_text(encoding="utf-8") + "\n| drift | drift |\n",
        encoding="utf-8",
    )

    assert sandboxed.main(["--check"]) == 1


def test_check_exits_one_when_the_golden_is_missing(sandboxed):
    assert not sandboxed.GOLDEN_PATH.exists()

    assert sandboxed.main(["--check"]) == 1
    assert not sandboxed.GOLDEN_PATH.exists(), (
        "a missing-golden check must report, not repair — a gate that writes is not a gate"
    )


# ══ AC25 — `--check` is provably read-only ════════════════════════════════════

def test_check_leaves_the_golden_byte_identical_and_untouched(sandboxed):
    """Bytes AND mtime. Bytes alone would pass a rewrite of identical content, which
    is still a write: it dirties a working tree and defeats a mtime-based build."""
    assert sandboxed.main(["--write"]) == 0
    before = _fingerprint(sandboxed.GOLDEN_PATH)

    assert sandboxed.main(["--check"]) == 0

    assert _fingerprint(sandboxed.GOLDEN_PATH) == before


def test_check_leaves_a_stale_golden_stale(sandboxed):
    """The nonzero path is the one most likely to "helpfully" self-heal."""
    assert sandboxed.main(["--write"]) == 0
    sandboxed.GOLDEN_PATH.write_text("stale\n", encoding="utf-8")
    before = _fingerprint(sandboxed.GOLDEN_PATH)

    assert sandboxed.main(["--check"]) == 1

    assert _fingerprint(sandboxed.GOLDEN_PATH) == before


def test_neither_mode_writes_to_the_fixture_tree(sandboxed):
    """Plan T0.6, extended to the reporter: a probe never writes to what it reads."""
    fixtures = Path(sandboxed.FIXTURES_DIR)
    before = _tree_fingerprint(fixtures)

    assert sandboxed.main(["--write"]) == 0
    assert sandboxed.main(["--check"]) == 0

    assert _tree_fingerprint(fixtures) == before


def test_building_the_report_opens_no_socket(tool, monkeypatch):
    """The verifier is offline by construction; the reporter must not smuggle a call in."""
    def _refuse(*_args, **_kwargs):
        raise AssertionError("the report opened a socket")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)

    assert tool.build_markdown()


# ══ AC25 — the write -> check round-trip ══════════════════════════════════════

def test_write_then_check_round_trips(sandboxed):
    """What the writer emits is exactly what the checker accepts."""
    assert sandboxed.main(["--write"]) == 0
    written = sandboxed.GOLDEN_PATH.read_text(encoding="utf-8")

    assert sandboxed.main(["--check"]) == 0
    assert written == sandboxed.build_markdown()


def test_writing_twice_is_byte_identical(sandboxed):
    """Idempotence. A writer that varies (a timestamp, a set iteration order) turns
    every regeneration into a diff and trains reviewers to ignore the gate."""
    assert sandboxed.main(["--write"]) == 0
    first = sandboxed.GOLDEN_PATH.read_bytes()

    assert sandboxed.main(["--write"]) == 0

    assert sandboxed.GOLDEN_PATH.read_bytes() == first


def test_the_report_is_independent_of_ambient_quote_knobs(tool, monkeypatch):
    """The golden attests the DEFAULT posture, so a developer's shell must not change it.

    Every ``VULTURE_LLM_QUOTE_*`` knob is read at call time (D14) — which is right for
    the verifier and fatal for a committed golden unless the reporter pins them. Two
    knobs are set here to values that would demonstrably move rows (``MAX_LINES=1``
    re-labels the oversize claim; ``MIN_CHARS=500`` would push every quote under the
    floor).
    """
    baseline = tool.build_markdown()
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "1")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MIN_CHARS", "500")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", "true")

    assert tool.build_markdown() == baseline


def test_the_reporter_restores_the_environment_it_pinned(tool, monkeypatch):
    """Pinning is a loan, not a confiscation: the audit process shares this env."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "7")
    tool.build_markdown()

    assert os.environ["VULTURE_LLM_QUOTE_MAX_LINES"] == "7"


# ══ the committed golden ══════════════════════════════════════════════════════

def test_the_committed_golden_is_current(tool):
    """The CI staleness gate, as a test — so `pytest tests/unit/` alone catches drift.

    Failure message names the exact regeneration command, because a stale golden is
    fixed by running one thing and the reviewer should not have to find it.
    """
    assert tool.main(["--check"]) == 0, (
        "the committed anchor golden is stale or missing; regenerate with\n"
        "  agents/.venv/bin/python agents/shared/tools/report_anchor_status.py --write"
    )


def test_the_committed_golden_declares_itself_generated(tool):
    assert BANNER in Path(tool.GOLDEN_PATH).read_text(encoding="utf-8")
