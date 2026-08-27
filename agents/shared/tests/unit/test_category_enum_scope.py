"""Scope of the declared category vocabulary: both tiers, and one audit at a time.

Two defects are pinned here.

1. **Tier coverage.** ``_conform_category`` was reached only from the two LLM
   parse branches, so the SKILL tier egressed its categories raw. The
   measurement that motivated the feature found 30 out-of-vocabulary rows, and
   *nine* of them — every skill row in the run — came from the skill tier. A
   fix that only covers the LLM path leaves that third of the violations in
   place.

2. **Cross-audit isolation.** The active vocabulary lived in a module-level
   global assigned by ``run_combined_audit``. ``transport/sse_app.py`` drives up
   to ``VULTURE_AUDIT_EXECUTOR_WORKERS`` (default 8) audit generators
   concurrently in one interpreter, each inside its own copied
   ``contextvars.Context``, so two audits declaring different enums overwrote
   each other's vocabulary — one agent reducing its categories against
   another's, decided by nothing but which generator started second.

The concurrency test mirrors ``_cancellable_stream``: one thread and one copied
Context per audit, with a barrier that holds both audits open until each has
declared its own vocabulary.

A third class pins the reduction's BLAST RADIUS rather than a defect.
``catalog_rollup`` groups on ``category``, and conformance mutates the finding
dicts in place before the validate stage sees them, so folding two
sub-categories into one declared value adds a rollup parent that did not exist
before. That is a change in what the ``result`` snapshot contains, not a
relabel, and it is pinned in both directions: the fold must happen when two rows
reduce to the same declared value, and must NOT happen when they do not.
"""

import contextvars
import json
import threading

import pytest

from shared.audit_runner import current_category_enum, run_combined_audit
from shared.validate.rollup import rollup_id

SSDF_ENUM = frozenset({"PO", "PS", "PW", "RV"})

# A second, DISJOINT vocabulary whose members are letters-only, because
# `normalize_to_enum` reduces to the leading *alphabetic* token: a declared name
# carrying a digit (SOC2's `CC6`) can never be the result of a reduction, so it
# would make this test measure that limitation instead of isolation. Each row
# below conforms under its own enum and is left ALONE under the other one, which
# is what makes a leaked vocabulary visible rather than merely different.
CHAOS_ENUM = frozenset({"RETRY", "TIMEOUT", "FALLBACK"})


@pytest.fixture(autouse=True)
def _skills_only(monkeypatch):
    """Skill tier only: no LLM phase, no validate stage, no line collapse.

    Each is an independent consumer of ``category``; switching them off keeps
    these tests measuring the conformance choke point rather than theirs.
    """
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "true")
    monkeypatch.setenv("VULTURE_DISABLE_LINE_COLLAPSE", "true")


def _finding(category: str, title: str) -> dict:
    return {
        "severity": "medium",
        "category": category,
        "title": title,
        "description": "d",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "recommendation": "r",
    }


def _skill(findings: list[dict], gate=None):
    """A skill function returning fixed rows, optionally waiting on *gate*."""

    def run(source_path: str) -> dict:
        if gate is not None:
            gate()
        return {"findings": [dict(f) for f in findings]}

    return run


def _event_data(events: list[str], name: str) -> list[dict]:
    out = []
    for ev in events:
        if not ev.startswith(f"event: {name}\n"):
            continue
        line = next(ln for ln in ev.split("\n") if ln.startswith("data:"))
        out.append(json.loads(line[5:]))
    return out


def _result_categories(events: list[str]) -> list[str]:
    results = _event_data(events, "result")
    assert len(results) == 1, "expected exactly one result event"
    return [f["category"] for f in results[0]["findings"]]


def _stream_categories(events: list[str]) -> list[str]:
    return [f["category"] for f in _event_data(events, "finding")]


class TestSkillTierConformance:
    """The skill tier must reach the same conformance choke point as the LLM tier."""

    def test_skill_finding_is_reduced_to_the_declared_enum(self, tmp_path):
        events = list(run_combined_audit(
            run_id="cat-skill-1",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("PW-3.3", "Unpinned dependency")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        ))
        assert _result_categories(events) == ["PW"]

    def test_skill_finding_keeps_the_specific_practice_reference(self, tmp_path):
        events = list(run_combined_audit(
            run_id="cat-skill-2",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("PW-3.3", "Unpinned dependency")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        ))
        findings = _event_data(events, "result")[0]["findings"]
        assert findings[0]["practice"] == "PW-3.3"

    def test_live_finding_event_agrees_with_the_result_snapshot(self, tmp_path):
        """A per-finding SSE event is emitted before the result; both must conform.

        Otherwise one finding has two different categories depending on whether
        you watched the stream or replayed the run.
        """
        events = list(run_combined_audit(
            run_id="cat-skill-3",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("PW-3.3", "Unpinned dependency")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        ))
        assert _stream_categories(events) == ["PW"]
        assert _stream_categories(events) == _result_categories(events)

    def test_unrecognised_category_is_left_alone(self, tmp_path):
        """The rule is narrow: reduce to a declared leading token, never guess."""
        events = list(run_combined_audit(
            run_id="cat-skill-4",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("XX-9", "Unknown group")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        ))
        assert _result_categories(events) == ["XX-9"]

    def test_no_declared_enum_leaves_skill_categories_untouched(self, tmp_path):
        """Agents that never opt in must be byte-identical to before."""
        events = list(run_combined_audit(
            run_id="cat-skill-5",
            source_path=str(tmp_path),
            categories=["cwe"],
            skill_map={"cwe": _skill([_finding("CWE-798", "Hardcoded secret")])},
            use_llm=False,
        ))
        assert _result_categories(events) == ["CWE-798"]


class TestVocabularyIsolation:
    """Concurrent audits must not see each other's declared vocabulary."""

    def test_two_concurrent_audits_keep_their_own_vocabularies(self, tmp_path):
        # The barrier holds both skill functions until BOTH audits have declared
        # their vocabulary — the exact interleaving eight executor workers make
        # routine, and the one a module-level global cannot survive.
        barrier = threading.Barrier(2, timeout=30)
        got: dict[str, list[str]] = {}
        errors: list[BaseException] = []

        def drive(name: str, enum: frozenset[str], row: dict) -> None:
            def go() -> None:
                events = list(run_combined_audit(
                    run_id=f"cat-iso-{name}",
                    source_path=str(tmp_path),
                    categories=[name],
                    skill_map={name: _skill([row], gate=barrier.wait)},
                    use_llm=False,
                    category_enum=enum,
                ))
                got[name] = _result_categories(events)

            try:
                # One copied Context per audit, as _cancellable_stream does.
                contextvars.copy_context().run(go)
            except BaseException as exc:  # surfaced to the test body below
                errors.append(exc)
                barrier.abort()

        threads = [
            threading.Thread(
                target=drive, args=("ssdf", SSDF_ENUM, _finding("PW-3.3", "A")),
            ),
            threading.Thread(
                target=drive, args=("chaos", CHAOS_ENUM, _finding("TIMEOUT_absent", "B")),
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            assert not t.is_alive(), "audit thread did not finish"

        assert not errors, f"audit raised: {errors!r}"
        assert got["ssdf"] == ["PW"], "SSDF run conformed against another audit's enum"
        assert got["chaos"] == ["TIMEOUT"], (
            "chaos run conformed against another audit's enum"
        )

    def test_vocabulary_is_reset_when_the_audit_completes(self, tmp_path):
        assert current_category_enum() is None
        list(run_combined_audit(
            run_id="cat-reset-1",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("PW-3.3", "A")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        ))
        assert current_category_enum() is None

    def test_abandoned_audit_does_not_leak_its_vocabulary(self, tmp_path):
        """A client disconnect closes the generator mid-run (feature 0061).

        The reset must ride a ``finally``, not the normal exit path, or the
        abandoned run's vocabulary outlives it on that thread.
        """
        gen = run_combined_audit(
            run_id="cat-reset-2",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("PW-3.3", "A")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        )
        next(gen)                       # vocabulary is now declared
        assert current_category_enum() == SSDF_ENUM
        gen.close()                     # consumer gone
        assert current_category_enum() is None

    def test_nested_audit_restores_the_outer_vocabulary(self, tmp_path):
        """Reset restores the PREVIOUS value, it does not blanket-clear."""
        outer = run_combined_audit(
            run_id="cat-nest-outer",
            source_path=str(tmp_path),
            categories=["pw"],
            skill_map={"pw": _skill([_finding("PW-3.3", "A")])},
            use_llm=False,
            category_enum=SSDF_ENUM,
        )
        next(outer)
        list(run_combined_audit(
            run_id="cat-nest-inner",
            source_path=str(tmp_path),
            categories=["timeout"],
            skill_map={"timeout": _skill([_finding("TIMEOUT_absent", "B")])},
            use_llm=False,
            category_enum=CHAOS_ENUM,
        ))
        assert current_category_enum() == SSDF_ENUM
        outer.close()
        assert current_category_enum() is None


def _result_findings(events: list[str]) -> list[dict]:
    results = _event_data(events, "result")
    assert len(results) == 1, "expected exactly one result event"
    return results[0]["findings"]


def _rollup_parents(events: list[str]) -> list[dict]:
    return [f for f in _result_findings(events) if f.get("is_rollup")]


def _rollup_row(category: str, line: int, title: str) -> dict:
    """A ``_finding`` pinned to *line* — rollup members differ only by line."""
    row = _finding(category, title)
    row["line_start"] = line
    row["line_end"] = line
    return row


def _run_validated(
    tmp_path, run_id: str, rows: list[dict], enum: frozenset[str] | None,
) -> list[str]:
    """One skills-only audit with the validate stage ON, so L2 rollup runs.

    ``category_enum`` is omitted entirely when *enum* is None rather than passed
    as None, so the control arm exercises the same call shape a non-opted-in
    agent uses.
    """
    kwargs: dict = dict(
        run_id=run_id,
        source_path=str(tmp_path),
        categories=["cc6"],
        skill_map={"cc6": _skill(rows)},
        use_llm=False,
    )
    if enum is not None:
        kwargs["category_enum"] = enum
    return list(run_combined_audit(**kwargs))


class TestRollupParentCountUnderConformance:
    """``catalog_rollup`` groups on the CONFORMED category, so the parent count
    is part of this feature's blast radius — pin it.

    ``_group_findings`` (``validate/rollup.py``) keys on
    ``(category, normalised title, file_path)``. Conformance runs at
    ``_finalize_finding_inplace`` and mutates the finding dicts IN PLACE, and
    the same list object is what reaches the validate stage — so two rows that
    occupied different groups before the reduction occupy ONE group after it.
    That is a change in what the ``result`` snapshot contains, not a relabel.

    Reachability is structural rather than contrived: soc2's dispatch map is
    clause-keyed, so selecting the single clause ``CC6`` runs three leaf skills
    (access_logging, data_retention, encryption) whose categories all reduce to
    ``CC6``. Chaos reaches it a second way — it DECLARES ``blast_radius`` while
    a tier emits ``blast-radius``, a separator-only difference.

    Both arms of each test run the real pipeline. The control arm is what makes
    these pins discriminating instead of tautological: with no declared
    vocabulary the same rows produce no parent at all.
    """

    ROWS = [
        _rollup_row("CC6-encryption", 1, "Unencrypted field at rest"),
        _rollup_row("CC6-data-retention", 9, "Unencrypted field at rest"),
    ]

    def test_no_declared_vocabulary_produces_no_rollup_parent(
        self, tmp_path, monkeypatch,
    ):
        """Control arm: unreduced categories put the two rows in two groups."""
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        events = _run_validated(tmp_path, "cat-rollup-none", self.ROWS, None)
        findings = _result_findings(events)
        assert [f["category"] for f in findings] == [
            "CC6-encryption", "CC6-data-retention",
        ]
        assert _rollup_parents(events) == []

    def test_folded_subcategories_produce_exactly_one_rollup_parent(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        events = _run_validated(
            tmp_path, "cat-rollup-fold", self.ROWS, frozenset({"CC6", "CC7", "CC8"}),
        )
        parents = _rollup_parents(events)
        assert len(parents) == 1, f"expected one rollup parent, got {parents}"
        assert parents[0]["category"] == "CC6"
        assert parents[0]["instance_count"] == 2
        assert parents[0]["provenance"] == "catalog_rollup"

    def test_the_parent_is_ADDED_and_no_member_is_lost(
        self, tmp_path, monkeypatch,
    ):
        """V6 — demote, never drop. The fold must not delete a finding.

        Member ids hash ``audit_id:title:file_path:index``, none of which
        conformance touches, so the SAME run_id yields the same member ids in
        both arms. Anything else would mean the fold re-identified rows that a
        prior audit had already triaged.
        """
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        control = _run_validated(tmp_path, "cat-rollup-same", self.ROWS, None)
        folded = _run_validated(
            tmp_path, "cat-rollup-same", self.ROWS, frozenset({"CC6", "CC7", "CC8"}),
        )

        control_ids = [f["id"] for f in _result_findings(control)]
        members = [f for f in _result_findings(folded) if not f.get("is_rollup")]
        assert [f["id"] for f in members] == control_ids
        assert len(_result_findings(folded)) == len(control_ids) + 1

    def test_each_member_keeps_the_specific_subcategory_it_reported(
        self, tmp_path, monkeypatch,
    ):
        """The group id is shared; the specific clause reference is not lost."""
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        events = _run_validated(
            tmp_path, "cat-rollup-detail", self.ROWS,
            frozenset({"CC6", "CC7", "CC8"}),
        )
        members = [f for f in _result_findings(events) if not f.get("is_rollup")]
        assert [m["practice"] for m in members] == [
            "CC6-encryption", "CC6-data-retention",
        ]
        assert {m["category"] for m in members} == {"CC6"}

    def test_the_parent_id_is_keyed_on_the_conformed_category(
        self, tmp_path, monkeypatch,
    ):
        """``rollup_id`` hashes the category, so the fold decides the parent id.

        Pinned because it is the one identifier this feature creates: a later
        change that grouped on the retained pre-conformance value instead would
        key the parent differently even where the parent count agreed.
        """
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        events = _run_validated(
            tmp_path, "cat-rollup-id", self.ROWS, frozenset({"CC6", "CC7", "CC8"}),
        )
        expected = rollup_id(
            "cat-rollup-id", "CC6", "Unencrypted field at rest", "app.py",
        )
        assert _rollup_parents(events)[0]["id"] == expected

    def test_separator_only_variants_fold_into_one_parent(
        self, tmp_path, monkeypatch,
    ):
        """Chaos declares ``blast_radius``; a tier emits ``blast-radius``."""
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        rows = [
            _rollup_row("blast-radius", 1, "Unbounded fan-out"),
            _rollup_row("blast_radius", 9, "Unbounded fan-out"),
        ]
        chaos = frozenset(
            {"retry", "circuit_breaker", "timeout", "fallback", "blast_radius"},
        )
        assert _rollup_parents(
            _run_validated(tmp_path, "cat-rollup-sep-none", rows, None),
        ) == []
        parents = _rollup_parents(
            _run_validated(tmp_path, "cat-rollup-sep", rows, chaos),
        )
        assert len(parents) == 1, f"expected one rollup parent, got {parents}"
        assert parents[0]["category"] == "blast_radius"
        assert parents[0]["instance_count"] == 2

    def test_rows_reducing_to_DIFFERENT_declared_values_stay_ungrouped(
        self, tmp_path, monkeypatch,
    ):
        """The fold must not over-group: only a shared reduction may collapse.

        Without this the class would pass just as well against a normaliser that
        collapsed every category to one value.
        """
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        rows = [
            _rollup_row("CC6-encryption", 1, "Unencrypted field at rest"),
            _rollup_row("CC7-monitoring", 9, "Unencrypted field at rest"),
        ]
        events = _run_validated(
            tmp_path, "cat-rollup-split", rows, frozenset({"CC6", "CC7", "CC8"}),
        )
        findings = _result_findings(events)
        assert [f["category"] for f in findings] == ["CC6", "CC7"]
        assert _rollup_parents(events) == []

    def test_an_unrecognised_category_does_not_join_a_declared_group(
        self, tmp_path, monkeypatch,
    ):
        """A value with nothing declared to reduce to is left ALONE, so it
        cannot be swept into a rollup it does not belong to."""
        monkeypatch.delenv("VULTURE_DISABLE_VALIDATE", raising=False)
        rows = [
            _rollup_row("CC6-encryption", 1, "Unencrypted field at rest"),
            _rollup_row("Availability", 9, "Unencrypted field at rest"),
        ]
        events = _run_validated(
            tmp_path, "cat-rollup-unknown", rows, frozenset({"CC6", "CC7", "CC8"}),
        )
        assert [f["category"] for f in _result_findings(events)] == [
            "CC6", "Availability",
        ]
        assert _rollup_parents(events) == []
