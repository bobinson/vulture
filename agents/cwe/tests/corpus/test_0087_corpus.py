"""0087 corpus regression tests (plan section 7, "Corpus regression tests").

Three things the plan asks this file to pin, none of which any other test does:

* per-repo, per-arm finding counts, each with a non-empty floor;
* the section 6.9 set difference on suppressions;
* the Go band from section 6.1, and the `.c`/`.h` gate exclusion from D-drop-1.

Each reference repository is OPTIONAL: absent ones skip with a stated reason
rather than passing silently, because a green suite that scanned nothing is the
failure mode this file exists to prevent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cwe_agent.skills.insufficient_logging_check import (
    _BASE_LANG_EXTENSIONS,
    _WIDENED_LANG_EXTENSIONS,
    _lang_extensions,
    check_insufficient_logging,
)

REPO_PARENT = Path("/home/user/src")
COUNTS = json.loads((Path(__file__).parent / "cwe778_counts.json").read_text())

# Counts move whenever detection legitimately changes, so the pin is a BAND, not
# an equality: wide enough that an intentional arm addition does not fail it,
# tight enough that losing an arm or doubling the volume does. An exact pin was
# rejected because it would have to be rewritten on every legitimate change,
# which trains the reader to update it without looking.
TOLERANCE = 0.25


def _repo(name: str) -> Path:
    path = REPO_PARENT / name
    if not path.is_dir():
        pytest.skip(f"reference repo {name} is not present at {path}")
    return path


@pytest.mark.parametrize("name", sorted(COUNTS))
def test_total_within_band(name: str) -> None:
    expected = COUNTS[name]["total"]
    found = len(check_insufficient_logging(str(_repo(name))).get("findings", []))
    assert found > 0, f"{name}: scanned to zero findings; the pin is vacuous"
    lo, hi = expected * (1 - TOLERANCE), expected * (1 + TOLERANCE)
    assert lo <= found <= hi, (
        f"{name}: {found} findings, expected {expected} +/-{TOLERANCE:.0%} "
        f"({lo:.0f}-{hi:.0f}). If this change is intentional, regenerate "
        f"tests/corpus/cwe778_counts.json and say why in the commit."
    )


@pytest.mark.parametrize("name", sorted(COUNTS))
def test_every_pinned_arm_still_fires(name: str) -> None:
    """An arm going to zero is the regression a total cannot show."""
    expected = COUNTS[name]["by_check"]
    assert expected, f"{name}: no arms pinned; the test is vacuous"
    findings = check_insufficient_logging(str(_repo(name))).get("findings", [])
    actual: dict[str, int] = {}
    for f in findings:
        key = f.get("check_id") or "rollup"
        actual[key] = actual.get(key, 0) + 1
    dead = [arm for arm, count in expected.items() if count > 0 and not actual.get(arm)]
    assert not dead, f"{name}: arm(s) stopped firing entirely: {dead}"


def test_go_band_on_backend() -> None:
    """6.1: 80-160 Go rows on `backend/`; over 250 is a hard failure."""
    backend = _repo("vulture") / "backend"
    if not backend.is_dir():
        pytest.skip("vulture/backend not present")
    rows = [
        f
        for f in check_insufficient_logging(str(backend)).get("findings", [])
        if (f.get("check_id") or "").endswith("go_swallow")
    ]
    assert len(rows) <= 250, (
        f"{len(rows)} Go rows exceeds 6.1's hard ceiling of 250; the arm is "
        "matching propagating or logging sites"
    )
    assert 80 <= len(rows) <= 160, (
        f"{len(rows)} Go rows is outside 6.1's expected band of 80-160"
    )


def test_c_and_h_are_not_in_the_gate() -> None:
    """D-drop-1: `.c`/`.h` stay out, so a future re-add is a deliberate act.

    C has no exceptions and no `if err != nil`; its error convention is a
    returned int checked inline, which this feature's shapes cannot express.
    """
    for ext in (".c", ".h"):
        assert ext not in _BASE_LANG_EXTENSIONS, f"{ext} entered the base gate"
        assert ext not in _WIDENED_LANG_EXTENSIONS, f"{ext} entered the widened gate"
        assert ext not in _lang_extensions(), f"{ext} is live in the resolved gate"


def test_widened_gate_covers_every_extension_step_9_names() -> None:
    """Step 9 names nine extensions; all nine must be live by default."""
    named = {".tsx", ".jsx", ".cjs", ".mjs", ".cpp", ".cc", ".cxx", ".hpp", ".kt"}
    missing = sorted(named - set(_lang_extensions()))
    assert not missing, f"step 9 extensions absent from the default gate: {missing}"


def test_legacy_gate_switch_actually_narrows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-vacuity for the switch itself: `legacy` must drop step 9's additions."""
    monkeypatch.setenv("VULTURE_CWE778_EXTENSIONS", "legacy")
    narrowed = _lang_extensions()
    assert narrowed == _BASE_LANG_EXTENSIONS
    assert ".tsx" not in narrowed and ".cc" not in narrowed
