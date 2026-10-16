"""shared.testing.timing: a budget is never stricter than its reference figure."""

from __future__ import annotations

from shared.testing import timing


def test_speed_factor_never_tightens_a_budget() -> None:
    assert timing.speed_factor() >= 1.0
    assert timing.budget(0.5) >= 0.5 * timing.MARGIN


def test_budget_scales_with_how_slow_the_machine_is(monkeypatch) -> None:
    monkeypatch.setattr(timing, "reference_ms", lambda rounds=5: timing.REFERENCE_MS * 3)
    timing.speed_factor.cache_clear()
    try:
        assert timing.speed_factor() == 3.0
        assert timing.budget(0.5) == 0.5 * timing.MARGIN * 3
    finally:
        timing.speed_factor.cache_clear()


def test_a_faster_machine_is_held_to_the_reference_figure(monkeypatch) -> None:
    monkeypatch.setattr(timing, "reference_ms", lambda rounds=5: timing.REFERENCE_MS / 4)
    timing.speed_factor.cache_clear()
    try:
        assert timing.budget(0.5) == 0.5 * timing.MARGIN
    finally:
        timing.speed_factor.cache_clear()
