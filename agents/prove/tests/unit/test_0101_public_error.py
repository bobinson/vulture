"""Feature 0101: unit contract of the prove agent's public failure text and
repository scrub.

Proof evidence is persisted and shown to whoever reads the audit, so it may
say WHAT kind of failure happened and never the failure's own text (a
resolver error names an internal host; an exception raised while handling a
finding can name a source path). The full text goes to the server log only.
"""

import logging
import socket
import ssl

import httpx
import pytest
from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

from prove_agent.evidence_scrub import (
    CODE_PLACEHOLDER,
    FILE_PLACEHOLDER,
    ScrubbingEmitter,
    repo_markers,
    scrubbing,
)
from prove_agent.public_error import describe_failure, failure_category, log_failure
from shared.testing.timing import budget
from shared.transport.event_emitter import AgUiEventEmitter

MSG = (
    "open /srv/fake-repo/src/billing/ledger.py failed; "
    "token=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234 via db.corp.internal:5432"
)
LEAKS = ("/srv/fake-repo", "ledger.py", "ghp_FAKE", "db.corp.internal")


def _chained(outer: BaseException, inner: BaseException) -> BaseException:
    try:
        try:
            raise inner
        except BaseException as cause:
            raise outer from cause
    except BaseException as wrapped:
        return wrapped


def _invalid_status(code: int) -> InvalidStatus:
    return InvalidStatus(Response(code, "Forbidden", Headers(), b""))


class TestFailureCategory:
    @pytest.mark.parametrize(("exc", "label"), [
        (socket.gaierror(MSG), "name resolution failed"),
        (ssl.SSLError(MSG), "TLS handshake failed"),
        (ConnectionRefusedError(MSG), "connection refused"),
        (TimeoutError(MSG), "timed out"),
        (httpx.ReadTimeout(MSG), "timed out"),
        (_invalid_status(403), "handshake rejected"),
        (httpx.RemoteProtocolError(MSG), "protocol error"),
        (OSError(MSG), "connection failed"),
        (RuntimeError(MSG), "internal error"),
        (ValueError(MSG), "internal error"),
    ])
    def test_category_by_type(self, exc, label):
        assert failure_category(exc) == label

    def test_cause_outranks_wrapper(self):
        # httpx reports a DNS failure as ConnectError whose cause is gaierror.
        exc = _chained(httpx.ConnectError(MSG), socket.gaierror(MSG))
        assert failure_category(exc) == "name resolution failed"

    def test_context_is_followed_too(self):
        try:
            try:
                raise ConnectionRefusedError(MSG)
            except ConnectionRefusedError:
                raise RuntimeError(MSG)
        except RuntimeError as exc:
            assert failure_category(exc) == "connection refused"

    def test_cause_cycle_terminates(self):
        a, b = RuntimeError("a"), RuntimeError("b")
        a.__cause__, b.__cause__ = b, a
        assert failure_category(a) == "internal error"


class TestDescribeFailure:
    def test_class_and_category_never_message(self):
        text = describe_failure(_chained(httpx.ConnectError(MSG), ConnectionRefusedError(MSG)))
        assert text == "connection refused (ConnectError)"

    def test_status_code_only_as_integer(self):
        assert describe_failure(_invalid_status(403)) == (
            "handshake rejected (InvalidStatus, HTTP 403)"
        )

    def test_non_integer_status_ignored(self):
        exc = RuntimeError(MSG)
        exc.response = type("R", (), {"status_code": MSG})()  # type: ignore[attr-defined]
        assert describe_failure(exc) == "internal error (RuntimeError)"

    def test_never_raises(self):
        class Hostile(Exception):
            def __str__(self) -> str:
                raise RuntimeError("boom")

            @property
            def response(self):
                raise RuntimeError("boom")

        assert describe_failure(Hostile()) == "internal error (Hostile)"

    @pytest.mark.parametrize("exc", [
        socket.gaierror(MSG), OSError(MSG), RuntimeError(MSG), ssl.SSLError(MSG),
    ])
    def test_no_leak(self, exc):
        text = describe_failure(exc)
        assert not [leak for leak in LEAKS if leak in text]

    def test_full_detail_goes_to_the_log(self, caplog):
        log = logging.getLogger("prove-0101-test")
        with caplog.at_level(logging.INFO, logger="prove-0101-test"):
            log_failure(log, "ws_probe", OSError(MSG))
        logged = caplog.text
        assert "ws_probe" in logged and "/srv/fake-repo" in logged
        assert "ghp_FAKE" not in logged  # the log copy is still secret-redacted


FINDING = {
    "id": "f-1",
    "title": "Error detail exposure",
    "file_path": "src/billing/ledger.py",
    "code_snippet": (
        "41: def settle(account):\n"
        '42:     raise LedgerError(f"settle failed for {account.iban}")\n'
        "43:     }\n"
        "44:     x = 1\n"
    ),
}
SNIPPET_LINE = 'raise LedgerError(f"settle failed for {account.iban}")'


class TestRepoMarkers:
    def test_path_forms_longest_first(self):
        found = [m for m, _ in repo_markers(FINDING, "/srv/fake-repo")]
        assert found.index("/srv/fake-repo/src/billing/ledger.py") < found.index("ledger.py")
        assert {"src/billing/ledger.py", "billing/ledger.py", "/srv/fake-repo"} <= set(found)

    def test_excerpt_floors(self):
        found = [m for m, _ in repo_markers(FINDING)]
        assert SNIPPET_LINE in found
        # `}` and `x = 1` carry no signal and would match everywhere.
        assert "}" not in found and "x = 1" not in found
        assert "def settle(account):" not in found  # 20 chars: under the floor

    def test_basename_needs_an_extension(self):
        found = [m for m, _ in repo_markers({"file_path": "deploy/Makefile"})]
        assert "Makefile" not in found and "deploy/Makefile" in found

    def test_single_component_root_is_not_a_marker(self):
        assert repo_markers({}, "/srv") == ()


class TestScrubbingEmitter:
    def _data(self, event: str) -> str:
        return event.split("data: ", 1)[1]

    def test_text_fields_scrubbed_identity_fields_kept(self):
        em = scrubbing(AgUiEventEmitter("r"), FINDING, source_root="/srv/fake-repo")
        event = em.proof_result_event(
            "src/billing/ledger.py", "inconclusive",
            f"saw {SNIPPET_LINE} in /srv/fake-repo/src/billing/ledger.py "
            "with ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234",
            1, staging_url="https://staging.example/ledger.py",
        )
        data = self._data(event)
        assert '"finding_id": "src/billing/ledger.py"' in data
        assert '"staging_url": "https://staging.example/ledger.py"' in data
        evidence = data.split('"evidence": ', 1)[1].split('", "iterations_used"')[0]
        assert not [leak for leak in LEAKS if leak in evidence]
        assert FILE_PLACEHOLDER in evidence and CODE_PLACEHOLDER in evidence

    def test_word_boundary(self):
        em = scrubbing(AgUiEventEmitter("r"), {"file_path": "a.py"})
        assert "data.py" in em.text_message("loaded data.py")

    def test_nesting_merges_markers(self):
        run = scrubbing(AgUiEventEmitter("r"), source_root="/srv/fake-repo")
        per = scrubbing(run, FINDING)
        assert isinstance(per, ScrubbingEmitter)
        text = per.text_message("root /srv/fake-repo/x and ledger.py")
        assert not [leak for leak in LEAKS if leak in text]

    def test_review_concerns_scrubbed(self):
        em = scrubbing(AgUiEventEmitter("r"), FINDING)
        event = em.proof_review_event("f-1", True, ["edits ledger.py"], 1)
        assert "ledger.py" not in event and FILE_PLACEHOLDER in event

    def test_unknown_directory_prefix_absorbed(self):
        # The model wrote a root the agent never saw in front of the path.
        em = scrubbing(AgUiEventEmitter("r"), FINDING)
        text = em.text_message("read /opt/build/src/billing/ledger.py then GET /api/orders")
        assert "/opt/build" not in text and "/api/orders" in text

    def test_slash_heavy_text_stays_linear(self):
        import time

        em = scrubbing(AgUiEventEmitter("r"), FINDING, source_root="/srv/fake-repo")
        hostile = "/" + "/".join("seg" for _ in range(4000)) + "/ledger.py"
        started = time.perf_counter()
        em.scrub(hostile)
        assert time.perf_counter() - started < budget(0.5)
