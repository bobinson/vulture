"""Feature 0074 review item 17 — a numeric ``VULTURE_LLM_QUOTE_*`` knob that is
not a finite, non-negative number falls back to its default. Zero stays a
deliberate setting (``MAX_DELTA=0``: record, never move; pinned by 0076).

Before the fix ``nan``, ``inf`` and ``1e400`` turned every anchor into
``unreadable/verifier_error`` and ``MAX_DELTA=-5`` silently disabled movement;
0074 made ``enforce`` the default, so one bad knob reached every run.

All fixtures are synthetic.
"""

from __future__ import annotations

import pytest

from shared import anchor

_KNOBS = sorted(anchor._KNOB_DEFAULTS)
_BAD = ["nan", "NaN", "inf", "-inf", "1e400", "-1e400", "-5", "-0.5", "abc", ""]


@pytest.mark.parametrize("raw", _BAD)
@pytest.mark.parametrize("name", _KNOBS)
def test_bad_knob_takes_its_default(name, raw, monkeypatch) -> None:
    monkeypatch.setenv(f"VULTURE_LLM_QUOTE_{name}", raw)
    assert anchor._knob(name) == anchor._KNOB_DEFAULTS[name]


@pytest.mark.parametrize(("raw", "value"), [(" 7 ", 7.0), ("0", 0.0), ("0.25", 0.25)])
@pytest.mark.parametrize("name", _KNOBS)
def test_good_knob_is_honoured(name, raw, value, monkeypatch) -> None:
    monkeypatch.setenv(f"VULTURE_LLM_QUOTE_{name}", raw)
    assert anchor._knob(name) == value


@pytest.mark.parametrize("raw", ["nan", "inf", "1e400"])
def test_bad_knob_does_not_break_verification(raw, monkeypatch, tmp_path) -> None:
    """The reproduced case: a verbatim quote still verifies ``exact``."""
    for name in ("MAX_DELTA", "MIN_CHARS", "MAX_LINES"):
        monkeypatch.setenv(f"VULTURE_LLM_QUOTE_{name}", raw)
    path = tmp_path / "m.py"
    path.write_text("a = 1\nresult_value = eval(request.form['expression'])\nb = 2\n")
    finding = {"line_start": 2, "line_end": 2,
               "evidence_quote": "result_value = eval(request.form['expression'])"}
    assert anchor.verify_anchor(finding, path, mode="enforce").status == "exact"
