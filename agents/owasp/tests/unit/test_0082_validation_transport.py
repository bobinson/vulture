"""Feature 0082 C4 — the validation blob now crosses the wire.

Before 0082 `model.PriorFinding` had no `validation` field, so the OWASP
agent's `_CARRY` entry for it was dead over the transport: the backend found
no blob, SYNTHESISED one, and re-voted from a 0.5 base — turning an inherited
`likely_fp`/0.05 into `high_confidence`/0.90.

C4 adds the field. That makes `_scrub_validation` a security control rather
than a defensive nicety: it is now the only thing standing between a
snippet-bearing validation extra and an OWASP row, and the 0063 constraint
("snippets can contain secrets") depends on it holding.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from owasp_agent.agent import _SNIPPET_BEARING, _scrub_validation


def _blob_with_every_snippet_key():
    return {
        "status": "likely_fp",
        "confidence": 0.05,
        "checks": [
            {
                "name": "anchor",
                "weight": -1.0,
                "extras": {
                    "quote_text": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
                    "code_snippet": "const key = 'AKIAIOSFODNN7EXAMPLE'",
                    "snippet": "password = 'hunter2'",
                    "evidence_quote": "token: ghp_deadbeefcafe",
                    "status": "exact",
                },
            }
        ],
    }


def test_non_vacuity_fixture_carries_every_snippet_bearing_key():
    """Guard: if the fixture stopped carrying these, the test below would
    pass over an empty set and prove nothing."""
    extras = _blob_with_every_snippet_key()["checks"][0]["extras"]
    for key in _SNIPPET_BEARING:
        assert key in extras, f"fixture must exercise {key}"


def test_scrub_removes_every_snippet_bearing_key():
    cleaned = _scrub_validation(_blob_with_every_snippet_key())
    extras = cleaned["checks"][0]["extras"]
    for key in _SNIPPET_BEARING:
        assert key not in extras, f"{key} survived the scrub — 0063 constraint broken"


def test_scrub_preserves_the_verdict_it_exists_to_transport():
    """The scrub must not cost the thing C4 added the field for."""
    cleaned = _scrub_validation(_blob_with_every_snippet_key())
    assert cleaned["status"] == "likely_fp"
    assert cleaned["confidence"] == 0.05
    assert cleaned["checks"][0]["name"] == "anchor"
    assert cleaned["checks"][0]["weight"] == -1.0
    # Non-snippet extras are evidence about the verdict, not source text.
    assert cleaned["checks"][0]["extras"]["status"] == "exact"


def test_scrub_is_total_over_malformed_blobs():
    for bad in (None, "not a dict", 42, {}, {"checks": "not a list"}):
        _scrub_validation(bad)  # must not raise


def test_carried_blob_must_not_import_the_twins_window_reason():
    """Feature 0082 — the CWE twin's `window` check must NOT survive the carry.

    A CWE row that HAS a code window carries `window: present` in its blob. The
    OWASP row inherits the blob but NOT the window (0063 forbids the snippet),
    so an inherited `present` asserts evidence that is not there — and because
    `record_window_reason` lets the first reason win, it also suppresses the
    truthful `inherited` stamp.

    Measured live before the fix: with snapshot consumption enabled, 339
    of 340 persisted OWASP rows had an empty code_snippet and claimed `present`.
    """
    from owasp_agent.agent import _relabel

    class _Cat:
        id, slug, name, source_url = "A03", "A03:2021-Injection", "Injection", "https://x"

    twin = {
        "title": "SQLi", "severity": "high", "file_path": "a.ts", "line_start": 10,
        "code_snippet": "10: db.query(raw)",
        "validation": {"status": "suspicious", "confidence": 0.4, "checks": [
            {"id": "obligation", "result": "discharged", "weight": 0.1},
            {"id": "window", "result": "present", "weight": 0.0},
        ]},
    }
    # NON-VACUITY: the twin must really carry a `present` window check.
    assert any(c["id"] == "window" and c["result"] == "present"
               for c in twin["validation"]["checks"])

    out = _relabel(twin, _Cat(), 89, "run-1", 0)

    assert not out.get("code_snippet"), "0063: the snippet must not be carried"
    win = [c for c in out["validation"]["checks"] if c.get("id") == "window"]
    assert len(win) == 1, f"expected exactly one window check, got {win}"
    assert win[0]["result"] == "inherited", (
        f"OWASP row claims {win[0]['result']!r} while carrying no window"
    )
    # The rest of the twin's verdict must survive — that is the whole point.
    assert out["validation"]["status"] == "suspicious"
    assert any(c["id"] == "obligation" for c in out["validation"]["checks"])
