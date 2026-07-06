"""Regression guard (0058 review, HIGH): a nonzero Semgrep exit must yield
an ERROR result, never a silent clean 0-findings scan.

This is the exact bug class behind the --project-root incident — semgrep
exited nonzero, the plugin (correctly) returned an error, but such an error
must remain distinguishable from a genuine clean scan. Pin _classify_exit's
contract so a future regression that swallows the failure is caught.
"""

from types import SimpleNamespace

from src.wrapper import _classify_exit


def _proc(rc: int, stderr: str = ""):
    return SimpleNamespace(returncode=rc, stderr=stderr, stdout="")


def test_clean_exit_is_not_an_error():
    assert _classify_exit(_proc(0)) is None
    assert _classify_exit(_proc(1)) is None  # 1 = findings present


def test_nonzero_exit_yields_error_payload_not_silent_zero():
    payload = _classify_exit(_proc(2, stderr="No such option: --project-root"))
    assert payload is not None, "a nonzero exit must produce an error result, not None"
    assert "error" in payload and payload["error"], "error payload must carry a non-empty message"
    assert "--project-root" in payload["error"]


def test_auth_required_exit_is_flagged():
    payload = _classify_exit(_proc(7))
    assert payload is not None and "error" in payload
