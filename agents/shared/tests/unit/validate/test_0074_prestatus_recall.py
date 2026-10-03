"""Feature 0074 P7 — ``prestatus_recall`` (AC23, AC24, AC25).

``surviving_recall`` only ever sees rows that were EMITTED and carry a
validation status (``evaluate_rules``). A labelled-real row lost before status
assignment — an eligibility drop, a dedup collapse, an L4 removal — shrinks its
denominator, so the metric reads the loss as an improvement. ``prestatus_recall``
measures against the labelled CORPUS instead: every labelled-real site, whether
or not anything was emitted for it.

Contract exercised here (``calibration.prestatus_recall(corpus, emitted)``):

* ``corpus`` is the labelled site list in the same ``(finding, is_real)`` shape
  ``evaluate_rules`` takes; ``emitted`` is the list of findings that came out,
  each carrying ``validation_status``.
* A corpus site is matched by its site — ``file_path``, ``line_start`` and the
  rule (``check_id``) — never by status or by object identity.
* A labelled-real site counts as recalled only when an emitted finding matches it
  and that finding was not dismissed (``likely_fp``).
* No labelled-real site in the corpus -> ``None`` (as ``surviving_recall``).

AC25: every fixture here is synthetic and self-contained — neutral ``d<i>/f<i>``
paths, no external tree, no model, no network.
"""

from __future__ import annotations

import copy

import pytest

from shared.validate.calibration import evaluate_rules

_RULE = "cwe.synthetic.sink"


def _site(index: int) -> dict:
    """One synthetic labelled site, neutral path, single rule."""
    return {
        "file_path": f"d0/f{index}.py",
        "line_start": 10 + index,
        "check_id": _RULE,
        "cwe": "CWE-89",
    }


def _corpus() -> list[tuple[dict, bool]]:
    """Four labelled-real sites (0-3) and two labelled false positives (4-5)."""
    return [(_site(i), i < 4) for i in range(6)]


def _emit(corpus, status_of=None, drop=()) -> list[dict]:
    """Emitted findings: a copy of every corpus site not in ``drop``, with a status."""
    status_of = status_of or {}
    out = []
    for index, (site, _real) in enumerate(corpus):
        if index in drop:
            continue
        row = copy.deepcopy(site)
        row["validation_status"] = status_of.get(index, "suspicious")
        out.append(row)
    return out


def prestatus_recall(corpus, emitted) -> float | None:
    """Resolve the symbol under test per call, so each AC fails on its own
    (a missing symbol is reported per test, not as one collection error)."""
    from shared.validate import calibration

    return calibration.prestatus_recall(corpus, emitted)


def _surviving(corpus, emitted) -> float | None:
    """``surviving_recall`` as calibration computes it today: emitted rows only."""
    labels = {(s["file_path"], s["line_start"]): real for s, real in corpus}
    pairs = [(f, labels[(f["file_path"], f["line_start"])]) for f in emitted]
    return evaluate_rules(pairs)[_RULE].surviving_recall


def test_full_emission_is_full_prestatus_recall():
    """AC23 baseline: every labelled-real site emitted and kept -> 1.0."""
    corpus = _corpus()
    assert prestatus_recall(corpus, _emit(corpus)) == pytest.approx(1.0)


def test_drop_before_status_lowers_prestatus_recall():
    """AC23: a labelled-real row dropped BEFORE status assignment lowers it."""
    corpus = _corpus()
    baseline = prestatus_recall(corpus, _emit(corpus))
    dropped = prestatus_recall(corpus, _emit(corpus, drop={1}))
    assert dropped == pytest.approx(3 / 4)
    assert dropped < baseline


@pytest.mark.parametrize(
    "status_of",
    [
        pytest.param({}, id="nothing-dismissed-surviving-stays-1.0"),
        pytest.param({1: "likely_fp"}, id="dropped-row-would-have-been-dismissed"),
    ],
)
def test_drop_before_status_is_invisible_to_surviving_recall(status_of):
    """AC24: the same drop leaves ``surviving_recall`` unchanged or higher,
    while ``prestatus_recall`` falls.

    This asserts the blindness rather than assuming it — the reason
    ``surviving_recall`` must never be cited as a guard for pre-status drops.
    Row 1 is the dropped labelled-real row in both cases; in the second the
    voter would have dismissed it had it survived to status assignment, so
    dropping it early RAISES ``surviving_recall``.
    """
    corpus = _corpus()
    kept = _emit(corpus, status_of=status_of)
    dropped = _emit(corpus, status_of=status_of, drop={1})
    assert _surviving(corpus, dropped) >= _surviving(corpus, kept)
    assert prestatus_recall(corpus, dropped) < prestatus_recall(corpus, kept)


def test_dismissal_after_status_is_visible_to_both():
    """Plan §8 negative fixture: the same row dismissed AFTER status -> both fall."""
    corpus = _corpus()
    kept = _emit(corpus)
    dismissed = _emit(corpus, status_of={1: "likely_fp"})
    assert prestatus_recall(corpus, dismissed) < prestatus_recall(corpus, kept)
    assert _surviving(corpus, dismissed) < _surviving(corpus, kept)


def test_dropping_a_labelled_false_positive_does_not_move_it():
    """Only labelled-real sites are in the denominator (AC23 corollary)."""
    corpus = _corpus()
    assert prestatus_recall(corpus, _emit(corpus, drop={4, 5})) == pytest.approx(1.0)


def test_match_is_by_site_not_by_object_or_status():
    """A re-serialised copy at a different site does not recall a dropped site."""
    corpus = _corpus()
    emitted = _emit(corpus, drop={2})
    stray = copy.deepcopy(corpus[2][0])
    stray["line_start"] += 500
    stray["validation_status"] = "high_confidence"
    assert prestatus_recall(corpus, emitted + [stray]) == pytest.approx(3 / 4)


def test_duplicate_emission_never_exceeds_one():
    """Two emitted rows at one site recall it once: the figure is bounded by 1.0."""
    corpus = _corpus()
    emitted = _emit(corpus)
    assert prestatus_recall(corpus, emitted + copy.deepcopy(emitted)) == pytest.approx(1.0)


def test_no_labelled_real_site_is_none():
    """No labelled-real site -> None, the same convention as ``surviving_recall``."""
    corpus = [(_site(i), False) for i in range(3)]
    assert prestatus_recall(corpus, _emit(corpus)) is None
