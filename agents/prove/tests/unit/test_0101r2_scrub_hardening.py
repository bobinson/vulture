"""Feature 0101 (review round 2): unit contract for the scrub hardening.

- Timeout evidence is scrubbed BEFORE it is cut, and the cut never splits a
  placeholder.
- One emitter per run carries every finding's markers (cross-finding
  learnings reach every plan prompt), and per-finding wrapping is then a
  no-op instead of a rebuild.
- The cost of a scrub does not grow with the number of findings in the run.
- Evasions the first round let through: reflowed whitespace inside a quoted
  code line, a URL-encoded path, a Windows path, and another file under the
  scan root.
- A failure raised through a task group keeps its category.

Fixtures are synthetic.
"""

import time

from prove_agent.evidence_scrub import (
    CODE_PLACEHOLDER,
    FILE_PLACEHOLDER,
    ROOT_PLACEHOLDER,
    clip,
    scrubbing,
    scrubbing_all,
)
from prove_agent.public_error import describe_failure
from prove_agent.runner import _synthesize_timeout_evidence
from prove_agent.strategies.base import AttemptRecord
from shared.transport.event_emitter import AgUiEventEmitter

ROOT = "/srv/fake-repo"
LINE = 'raise LedgerError(f"settle failed for {account.iban}")'
FINDING = {
    "id": "f-1", "file_path": "src/billing/ledger.py",
    "code_snippet": f"41: def settle(account):\n42:     {LINE}\n",
}
OTHER = {
    "id": "f-2", "file_path": "src/payments/alpha_gateway.go",
    "code_snippet": '10: token := os.Getenv("PAYMENT_GATEWAY_SECRET")\n',
}


def _em(*findings):
    return scrubbing_all(AgUiEventEmitter("r"), list(findings), source_root=ROOT)


def _attempt(evidence: str) -> AttemptRecord:
    return AttemptRecord(
        iteration=1, method="GET", url_path="/api/orders", status_code=200,
        response_snippet="", response_headers={}, evidence=evidence,
        conclusive=False, reproduced=False, plan_description="",
        failure_reason=None, protocol="http",
    )


class TestTimeoutEvidence:
    def test_path_across_the_cut_is_replaced_whole(self):
        em = _em(FINDING)
        ev = _synthesize_timeout_evidence(
            "t", 120, [_attempt("z" * 190 + " see src/billing/ledger.py")], scrub=em.scrub,
        )
        assert "src/b" not in ev and "ledger" not in ev
        assert FILE_PLACEHOLDER in ev

    def test_default_is_unchanged_text(self):
        ev = _synthesize_timeout_evidence("t", 120, [_attempt("plain")])
        assert "Evidence: plain" in ev

    def test_clip_never_splits_a_placeholder(self):
        text = "a" * 8 + FILE_PLACEHOLDER + " tail"
        assert clip(text, 12) == "a" * 8 + FILE_PLACEHOLDER
        assert clip("abcdef", 3) == "abc"
        assert clip(FILE_PLACEHOLDER + "xyz", 20) == FILE_PLACEHOLDER + "xyz"


class TestRunWideMarkers:
    def test_every_findings_markers_in_one_emitter(self):
        em = _em(FINDING, OTHER)
        out = em.scrub("B quotes src/payments/alpha_gateway.go and "
                       'token := os.Getenv("PAYMENT_GATEWAY_SECRET")')
        assert "alpha_gateway" not in out and "PAYMENT_GATEWAY_SECRET" not in out
        assert FILE_PLACEHOLDER in out and CODE_PLACEHOLDER in out

    def test_per_finding_wrap_is_a_noop_when_covered(self):
        em = _em(FINDING, OTHER)
        assert scrubbing(em, OTHER) is em

    def test_per_finding_wrap_still_adds_unknown_markers(self):
        em = _em(FINDING)
        per = scrubbing(em, OTHER)
        assert per is not em
        assert "alpha_gateway" not in per.scrub("see src/payments/alpha_gateway.go")

    def test_cost_does_not_grow_with_findings(self):
        """1000 findings (6000+ markers). Measured before the token index:
        5.2 ms per 5 KB event in marker checks alone, and 0.16 s to build each
        per-finding emitter. Bound is loose (CI noise); the indexed form
        measures ~0.3 ms for the marker pass."""
        findings = [
            {"file_path": f"src/mod{i}/sub{i % 7}/file_{i}.py",
             "code_snippet": f"{i}: value_{i} = compute_thing(arg_{i}, other)\n"}
            for i in range(1000)
        ]
        em = _em(*findings)
        text = ("probe /api/orders returned 200 with body ok and header x-y. " * 90)[:5000]
        start = time.perf_counter()
        for _ in range(20):
            em.scrub(text)
        assert (time.perf_counter() - start) / 20 < 0.004
        start = time.perf_counter()
        for f in findings[:50]:
            assert scrubbing(em, f) is em
        assert time.perf_counter() - start < 0.05


class TestEvasions:
    def test_reflowed_whitespace_in_a_code_line(self):
        out = _em(FINDING).scrub('it runs raise  LedgerError( f"settle failed for {account.iban}" )')
        assert "LedgerError" not in out and CODE_PLACEHOLDER in out

    def test_url_encoded_path(self):
        out = _em(FINDING).scrub("GET /download?f=src%2Fbilling%2Fledger.py and %2Fopt%2Fsrc%2Fbilling%2Fledger.py")
        assert "billing" not in out and "ledger" not in out

    def test_url_encoding_of_target_content_is_left_alone(self):
        out = _em(FINDING).scrub("payload q=%27%20OR%201%3D1 reflected")
        assert out == "payload q=%27%20OR%201%3D1 reflected"

    def test_windows_path(self):
        out = _em(FINDING).scrub(r"open C:\work\repo\src\billing\ledger.py failed")
        assert out == f"open {FILE_PLACEHOLDER} failed"

    def test_other_file_under_the_root(self):
        out = _em(FINDING).scrub(f"also read {ROOT}/src/other.py:12 then stopped")
        assert out == f"also read {ROOT_PLACEHOLDER} then stopped"

    def test_target_route_named_like_a_directory_is_kept(self):
        out = _em(FINDING).scrub("GET /api/billing/invoices -> 200")
        assert out == "GET /api/billing/invoices -> 200"


class TestExceptionGroup:
    def test_member_category_is_found(self):
        exc = ExceptionGroup("tasks failed", [ConnectionRefusedError("10.0.3.7:9944")])
        assert describe_failure(exc) == "connection refused (ExceptionGroup)"

    def test_nested_group_in_a_cause_chain(self):
        inner = BaseExceptionGroup("g", [ExceptionGroup("h", [TimeoutError("x")])])
        outer = RuntimeError("wrapper")
        outer.__cause__ = inner
        assert describe_failure(outer) == "timed out (RuntimeError)"

    def test_wide_group_is_bounded(self):
        exc = ExceptionGroup("many", [ValueError(str(i)) for i in range(500)])
        assert describe_failure(exc) == "internal error (ExceptionGroup)"
