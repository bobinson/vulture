"""Guard: a mapped CWE must never silently stop being reachable.

The hazard this exists for is a **relabel**, not a deletion. A rule keeps
firing on exactly the same code, but its emitted ``category`` is re-tagged from
one CWE to another. Nothing crashes, no detector is lost, the finding count
does not move — yet one OWASP category quietly loses a reachable id while
another gains one. Net zero in the headline number, invisible in review.

Two independent assertions, because they fail for different reasons:

1. **Per-id** (:func:`test_committed_mapped_ids_are_still_reachable`) — every
   OWASP-2025-mapped CWE recorded in the committed attestation must still be
   reachable today. This is the precise one: it names the id and the categories
   that would lose it. Its baseline is the committed attestation, which is
   REGENERATED, so on its own it can be "fixed" by regenerating rather than by
   fixing the relabel — hence (2).

2. **Per-category floor** (:func:`test_per_category_reach_never_regresses`) —
   a monotone table of counts that lives in this file and can only be changed
   by editing it. Regenerating the attestation does not move it. This is the
   assertion a silent relabel cannot outrun: the losing category's count drops
   even though the gaining category's rises.

Both sets are DERIVED — the attestation's own extraction for what is reachable,
``shared.owasp.mapping.load_edition("2025")`` for what is mapped. No list of
CWE-ids is hardcoded anywhere in this file: such a list would need editing on
every additive change and would itself become the thing that rots. The only
committed baseline here is a table of COUNTS, and it is compared with ``>=`` so
new detectors never fail it.

Measured on a scratch copy of the tree: re-tagging one rule's emitted CWE to a
different id, updating that rule's own unit tests to match, and regenerating
the attestation left the ENTIRE rest of the suite green (1501 passed, same one
pre-existing failure as before the change) while one OWASP category silently
lost a reachable id and another gained one. The floor assertion below was the
only thing that failed, naming both the dropped id and the losing category.

Fast by construction: the attestation extraction reads skill sources and the
small labeled corpus fixtures — 1.7s for the whole module, and the derivation
is computed once and cached. No large tree is scanned.
"""

import functools
import re
import subprocess
import sys
from pathlib import Path

import pytest
from shared.owasp.mapping import load_edition

_CORPUS = Path(__file__).resolve().parents[2] / "corpus"
if str(_CORPUS) not in sys.path:
    sys.path.insert(0, str(_CORPUS))

import report_coverage as rc  # noqa: E402

EDITION_ID = "2025"

# The committed per-OWASP-category reach of the deterministic union. This is
# the guard's baseline and the ONLY hand-maintained number here.
#
# Monotone: compared with ``>=``, so adding detectors never fails it. Raise an
# entry when a category gains reachable ids. LOWERING an entry is the explicit,
# reviewable act of accepting that the agent can no longer reach a weakness it
# used to reach — never do it to make a red suite green.
CATEGORY_REACH_FLOOR = {
    "A01": 26,
    "A02": 12,
    "A03": 3,
    "A04": 22,
    "A05": 17,
    "A06": 16,
    "A07": 12,
    "A08": 11,
    "A09": 3,
    "A10": 17,
}

# Distinct mapped CWE-ids reachable overall (a CWE may sit in more than one
# category, so this is NOT the sum of the table above). Same monotone contract.
TOTAL_REACH_FLOOR = 139

_FIX = (
    "If the loss is INTENTIONAL, say so explicitly and update this guard's "
    "baseline in the SAME commit (lower the entry in CATEGORY_REACH_FLOOR / "
    "TOTAL_REACH_FLOOR and regenerate the committed attestation). If it is "
    "not intentional, restore the emitted `category` literal — a rule that was "
    "re-tagged to a different CWE still fires, so nothing else will tell you."
)


@functools.lru_cache(maxsize=1)
def reachable_cwe_ids() -> frozenset[int]:
    """Deterministically reachable CWE-ids, via the attestation's extraction.

    The union of the attestation's deterministic buckets: corpus-VERIFIED,
    DETECTED-below-gate and DECLARED-ONLY. Using the attestation's own
    derivation (rather than a second, subtly different regex) is what keeps
    this guard and the committed document talking about the same set.
    """
    buckets = rc.build_buckets()
    ids = (
        buckets["verified"]
        + buckets["detected_below_gate"]
        + buckets["declared_only"]
    )
    return frozenset(int(i) for i in ids)


@functools.lru_cache(maxsize=1)
def mapped_cwe_ids() -> frozenset[int]:
    """Every CWE-id mapped by the OWASP edition under guard."""
    universe: set[int] = set()
    for category in load_edition(EDITION_ID).categories:
        universe |= set(category.cwes)
    return frozenset(universe)


def parse_attestation_ids(text: str) -> frozenset[int]:
    """CWE-ids claimed by an attestation document.

    Parsed from the two shapes the attestation renders — one-per-row table
    entries and comma-joined id lists — so incidental mentions in prose are
    never picked up as a claim.
    """
    rows = re.findall(r"^\| CWE-(\d+) \|", text, re.MULTILINE)
    lists = re.findall(r"^CWE-\d+(?:, CWE-\d+)*[ \t]*$", text, re.MULTILINE)
    return frozenset(
        int(m) for m in rows + re.findall(r"CWE-(\d+)", " ".join(lists))
    )


@functools.lru_cache(maxsize=1)
def committed_cwe_ids() -> frozenset[int]:
    """CWE-ids recorded in the attestation as it stands in the working tree."""
    return parse_attestation_ids(rc.GOLDEN_PATH.read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=1)
def last_committed_cwe_ids() -> frozenset[int]:
    """CWE-ids recorded in the attestation at the last commit.

    Diagnostic only, and best effort: empty when git is unavailable or the file
    is untracked. Regenerating the attestation in the working tree cannot move
    this set, which is what lets the floor failure below still name the id that
    was dropped even when the document was regenerated alongside the change.
    """
    try:
        done = subprocess.run(
            ["git", "-C", str(rc.GOLDEN_PATH.parent), "show",
             f"HEAD:./{rc.GOLDEN_PATH.name}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env dependent
        return frozenset()
    return parse_attestation_ids(done.stdout) if done.returncode == 0 else frozenset()


def dropped_id_suspects(categories: set) -> str:
    """Ids previously claimed for ``categories`` that are no longer reachable."""
    known = committed_cwe_ids() | last_committed_cwe_ids()
    gone = sorted((known & mapped_cwe_ids()) - reachable_cwe_ids())
    named = [
        f"CWE-{cwe} (was in {', '.join(categories_of(cwe))})"
        for cwe in gone
        if set(categories_of(cwe)) & categories
    ]
    return "; ".join(named) if named else "(no previously-claimed id identified)"


def categories_of(cwe_id: int) -> list[str]:
    """Ids of the OWASP categories that map ``cwe_id`` (may be more than one)."""
    return [c.id for c in load_edition(EDITION_ID).map_cwe(cwe_id)]


def lost_mapped_ids(baseline: frozenset[int], reachable: frozenset[int]) -> dict:
    """Mapped ids present in ``baseline`` but no longer in ``reachable``."""
    return {
        cwe: categories_of(cwe)
        for cwe in sorted((baseline & mapped_cwe_ids()) - reachable)
    }


def category_shortfalls(reachable: frozenset[int]) -> dict:
    """Categories whose reach fell below the committed floor: id -> (now, floor)."""
    out = {}
    for category in load_edition(EDITION_ID).categories:
        floor = CATEGORY_REACH_FLOOR.get(category.id)
        now = len(set(category.cwes) & reachable)
        if floor is not None and now < floor:
            out[category.id] = (now, floor)
    return out


# ---------------------------------------------------------------------------
# derivation sanity — a guard that derives its own inputs can pass vacuously
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["mapped_cwe_ids", "reachable_cwe_ids", "committed_cwe_ids"],
)
def test_derivations_are_not_vacuous(name):
    """If a derivation silently returns nothing, every assertion below passes
    for the wrong reason. Fail loudly here instead."""
    derived = globals()[name]()
    assert len(derived) > 100, f"{name}() returned {len(derived)} ids — derivation broken"


def test_floor_table_covers_the_edition():
    assert CATEGORY_REACH_FLOOR.keys() == {
        c.id for c in load_edition(EDITION_ID).categories
    }, "the floor table must cover exactly the edition's categories"


# ---------------------------------------------------------------------------
# 1. per-id — names the id and the category that would lose it
# ---------------------------------------------------------------------------


def test_committed_mapped_ids_are_still_reachable():
    lost = lost_mapped_ids(committed_cwe_ids(), reachable_cwe_ids())
    detail = "; ".join(
        f"CWE-{cwe} (mapped in {', '.join(cats) or 'no category'})"
        for cwe, cats in lost.items()
    )
    assert not lost, (
        f"{len(lost)} OWASP-{EDITION_ID}-mapped CWE-id(s) recorded in the "
        f"committed attestation are no longer reachable: {detail}. Each listed "
        f"category loses that id from its reachable set. {_FIX}"
    )


# ---------------------------------------------------------------------------
# 2. per-category floor — survives a regenerated attestation
# ---------------------------------------------------------------------------


def test_per_category_reach_never_regresses():
    shortfalls = category_shortfalls(reachable_cwe_ids())
    detail = "; ".join(
        f"{cat}: {now} reachable, floor {floor}"
        for cat, (now, floor) in sorted(shortfalls.items())
    )
    suspects = dropped_id_suspects(set(shortfalls)) if shortfalls else ""
    assert not shortfalls, (
        f"OWASP {EDITION_ID} per-category reach REGRESSED: {detail}. Dropped: "
        f"{suspects}. A rule stopped emitting a CWE mapped in that category — "
        f"most often because its emitted `category` literal was re-tagged to a "
        f"different CWE, which keeps the finding count flat and hides the "
        f"loss. {_FIX}"
    )


def test_total_mapped_reach_never_regresses():
    now = len(reachable_cwe_ids() & mapped_cwe_ids())
    assert now >= TOTAL_REACH_FLOOR, (
        f"distinct OWASP-{EDITION_ID}-mapped CWE-ids reachable dropped to "
        f"{now}, below the committed floor of {TOTAL_REACH_FLOOR}. {_FIX}"
    )


# ---------------------------------------------------------------------------
# 3. the guard must actually fire — a passing guard proves nothing on its own
# ---------------------------------------------------------------------------


@pytest.fixture
def relabelled():
    """Simulate a relabel: one mapped, reachable id stops being emitted.

    The victim is picked from the live data (never hardcoded), so this stays
    meaningful as the reachable set changes.
    """
    reachable = reachable_cwe_ids()
    victim = min(reachable & mapped_cwe_ids())
    return victim, frozenset(reachable - {victim})


def test_per_id_check_catches_a_relabel(relabelled):
    victim, after = relabelled
    lost = lost_mapped_ids(committed_cwe_ids(), after)
    assert victim in lost, "the per-id check must catch a dropped mapped id"
    assert lost[victim] == categories_of(victim), (
        "the failure must name the categories that lose the id"
    )


def test_attestation_parsing_ignores_prose(relabelled):
    """Only rendered claims count — a CWE mentioned in a sentence is not one."""
    victim, _ = relabelled
    doc = f"CWE-{victim} is discussed here but never claimed.\n"
    assert not parse_attestation_ids(doc)
    assert parse_attestation_ids(f"| CWE-{victim} | VERIFIED | 3 |") == {victim}
    assert parse_attestation_ids(f"CWE-{victim}, CWE-{victim + 1}") == {
        victim, victim + 1
    }


def test_failure_names_the_dropped_id(monkeypatch, relabelled):
    """The floor failure must say WHICH id went missing, not just how many."""
    victim, after = relabelled
    monkeypatch.setitem(globals(), "reachable_cwe_ids", lambda: after)
    suspects = dropped_id_suspects(set(categories_of(victim)))
    assert f"CWE-{victim}" in suspects, suspects


def test_per_category_check_catches_a_relabel(relabelled):
    victim, after = relabelled
    shortfalls = category_shortfalls(after)
    assert set(shortfalls) & set(categories_of(victim)), (
        "the floor must drop for every category mapping the dropped id, even "
        "when another category gains an id at the same time"
    )
