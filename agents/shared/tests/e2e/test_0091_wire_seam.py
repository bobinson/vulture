"""Feature 0091 §6.1 — the agent side of the seam, end to end over HTTP.

TWO THINGS ARE TESTED HERE, AND NEITHER WAS COVERED BEFORE.

1. THE TRANSPORT SEAM. ``test_0091_lineage_checks.py`` calls
   ``run_combined_audit(lineage_checks_requested=...)`` directly, which proves
   the verifier works but says nothing about whether the payload can REACH it.
   It could not: the backend puts ``lineage_checks_requested`` at the top level
   of the ``/run`` body (§6.1), ``AuditRequest`` did not declare the field, and
   pydantic drops an undeclared key without a word. The backend asked, ten
   agents never heard the question, and the backend then read every unanswered
   row as ``unconfirmable`` — on every scan, with both ends of the wire looking
   correct in isolation. The tests below drive the real ASGI app with a real
   request body, which is the only place that gap is visible.

2. THE CROSS-LANGUAGE FIELD NAMES. Every 0091 key is optional on both sides
   (``omitempty`` in Go, ``.get()`` here), so a rename does not error anywhere
   — it reads as "absent", and absent is a legal, quiet, wrong answer. One
   shared fixture is therefore asserted against by BOTH languages:

       agents/shared/tests/contract/0091_lineage_wire.json
       backend/internal/agui/wire_contract_0091_test.go   (the Go half)

   Editing the fixture to make this file pass moves the failure into the Go
   suite, which is exactly what a contract should do.

Network-free: no LLM is involved. The evidence pass reads the stored quote and
the file cache the skill phase already warmed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from shared import quote_store
from shared.audit_runner import LINEAGE_REQUEST_SCHEMA, RESULT_SCHEMA
from shared.lineage_checks import _OUTCOME_BY_ANCHOR_STATUS, quote_hash, verify_lineage_checks
from shared.models.audit_request import AuditRequest
from shared.transport.sse_app import create_sse_app

# --------------------------------------------------------------------------- #
# The shared contract
# --------------------------------------------------------------------------- #

# Four parents up from tests/e2e/<file>: e2e -> tests -> shared -> agents.
_CONTRACT = (
    Path(__file__).resolve().parents[2] / "tests" / "contract" / "0091_lineage_wire.json"
)


def _contract() -> dict[str, Any]:
    """The shared wire contract. A hard failure when missing, never a skip.

    A pin that quietly stops running is worse than no pin: the report still
    says green while the two languages drift.
    """
    assert _CONTRACT.is_file(), (
        f"shared 0091 wire contract not found at {_CONTRACT}. It is read by "
        "this file and by backend/internal/agui/wire_contract_0091_test.go; "
        "if it moved, update both."
    )
    return json.loads(_CONTRACT.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Fixture tree — one row, present in the file, so the answer is `confirmed`
# --------------------------------------------------------------------------- #

QUOTE = (
    'token = request.headers.get("X-Api-Token")\n'
    'if token == "s3cr3t-static-token-value":'
)

LINEAGE_ID = "seam-row-1"
FINGERPRINT_V2 = "fp2-seam-row-1"


@pytest.fixture()
def seam_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A scannable tree, the remembered quote, and the row that cites it."""
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "cache" / "l5_cache.db"))
    quote_store.reset_for_tests()

    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    preamble = ['"""Fixture module."""', "", "", "def handle(request):"]
    body = preamble + ["    " + ln for ln in QUOTE.splitlines()] + [
        "        pass", "    return None", "",
    ]
    (root / "src" / "app.py").write_text("\n".join(body), encoding="utf-8")
    start = len(preamble) + 1

    quote_store.store(FINGERPRINT_V2, QUOTE)

    row = {
        "lineage_id": LINEAGE_ID,
        "fingerprint_v2": FINGERPRINT_V2,
        "rel_path": "src/app.py",
        "line_start": start,
        "line_end": start + 1,
        "quote_hash": quote_hash(QUOTE),
        "status": "open",
        "file_hash": "sha256:" + "1" * 64,
    }
    yield {"root": root, "row": row}
    quote_store.reset_for_tests()


def _noop_skill(_source_path: str) -> dict:
    """A real skill that finds nothing — the shape of the incident scan."""
    return {"findings": []}


def _agent_app():
    """The real SSE app over the real runner, wired the way an agent wires it."""
    from shared.audit_runner import run_combined_audit

    def run_handler(run_id, source_path, config, prior_findings=None):
        yield from run_combined_audit(
            run_id=run_id,
            source_path=source_path,
            categories=["noop"],
            skill_map={"noop": _noop_skill},
        )

    return create_sse_app(
        agent_name="seam",
        agent_info={
            "name": "Seam Agent", "type": "seam", "description": "wire seam",
            "config_schema": {"type": "object", "properties": {}}, "skills": ["noop"],
        },
        run_handler=run_handler,
    )


async def _post_run(body: dict[str, Any], app: Any = None) -> dict[str, Any]:
    """POST /run and return the parsed `result` event payload."""
    app = app or _agent_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://a") as client:
        resp = await client.post("/run", json=body)
        assert resp.status_code == 200, resp.text
        text = resp.text
    for chunk in text.split("\n\n"):
        if "event: result" in chunk:
            data = next(ln for ln in chunk.split("\n") if ln.startswith("data:"))
            return json.loads(data[5:])
    raise AssertionError(f"no result event in SSE stream:\n{text[:2000]}")


# --------------------------------------------------------------------------- #
# 1. The transport seam
# --------------------------------------------------------------------------- #


class TestRequestReachesTheRunner:
    """The backend's question has to survive the HTTP boundary."""

    def test_audit_request_declares_the_key(self) -> None:
        """`AuditRequest` must RETAIN `lineage_checks_requested`.

        This is the whole defect in one assertion. Pydantic ignores an
        undeclared key silently, so without the field the payload is dropped at
        the door — and nothing downstream can tell "the backend asked nothing"
        from "the backend asked and I threw it away".
        """
        contract = _contract()
        req = AuditRequest(
            run_id="r1",
            source_path="/tmp/x",
            lineage_checks_requested=contract["request"],
        )
        assert req.lineage_checks_requested == contract["request"]

    def test_audit_request_defaults_to_no_question(self) -> None:
        """Absent is None, not `{}` — an ordinary scan asks nothing."""
        assert AuditRequest(run_id="r1", source_path="/tmp/x").lineage_checks_requested is None

    @pytest.mark.anyio
    async def test_posted_request_is_answered_on_the_result_event(
        self, seam_tree: dict[str, Any]
    ) -> None:
        """The full seam: POST the key, get `lineage_checks` back.

        Nothing here passes `lineage_checks_requested` to `run_combined_audit`
        — the run handler has the ordinary four-argument shape every agent
        uses, exactly so that this test fails if the value only arrives when an
        agent is rewritten to forward it by hand.
        """
        result = await _post_run({
            "run_id": "seam-1",
            "source_path": str(seam_tree["root"]),
            "config": {},
            "lineage_checks_requested": {
                "schema": LINEAGE_REQUEST_SCHEMA, "rows": [seam_tree["row"]],
            },
        })

        assert result["result_schema"] == RESULT_SCHEMA
        checks = result["lineage_checks"]
        assert len(checks) == 1, (
            "the posted lineage row was not answered; the request never reached "
            f"run_combined_audit. result keys: {sorted(result)}"
        )
        assert checks[0]["lineage_id"] == LINEAGE_ID
        assert checks[0]["outcome"] == "confirmed", (
            "the quote is in the file byte for byte, so the only correct answer "
            f"is `confirmed`; got {checks[0]}"
        )

    @pytest.mark.anyio
    async def test_the_question_does_not_leak_into_the_next_run(
        self, seam_tree: dict[str, Any]
    ) -> None:
        """A question asked of one run must not be answered by the next.

        Both requests go to the SAME long-lived app, which is how an agent
        actually runs: one process, many audits. An ambient value bound outside
        the per-request context copy would survive into request two and make
        one scan's evidence decide another scan's rows — a cross-audit data
        error, and a silent one, since the stale answer is well-formed.

        Also pins that `result_schema` stays unconditional: the backend reads
        its absence as "old agent" and then closes nothing in the LLM tier
        (S26), so an agent that emitted it only when asked would disable the
        feature for every ordinary scan.
        """
        app = _agent_app()

        asked = await _post_run({
            "run_id": "seam-2a",
            "source_path": str(seam_tree["root"]),
            "config": {},
            "lineage_checks_requested": {"schema": 1, "rows": [seam_tree["row"]]},
        }, app)
        assert len(asked["lineage_checks"]) == 1, "setup: the first run must be answered"

        silent = await _post_run({
            "run_id": "seam-2b", "source_path": str(seam_tree["root"]), "config": {},
        }, app)

        assert silent["result_schema"] == RESULT_SCHEMA
        assert silent["lineage_checks"] == [], (
            "the previous run's question was answered again on a run that asked "
            f"nothing: {silent['lineage_checks']}"
        )
        assert isinstance(silent["pruned_dirs"], list)


# --------------------------------------------------------------------------- #
# 2. The cross-language field names
# --------------------------------------------------------------------------- #


class TestSharedWireContract:
    """Every key and every outcome string, against the file Go also reads."""

    def test_schema_numbers_agree(self) -> None:
        """The two version numbers are the handshake; they cannot drift."""
        contract = _contract()
        assert contract["result"]["result_schema"] == RESULT_SCHEMA
        assert contract["request"]["schema"] == LINEAGE_REQUEST_SCHEMA

    def test_result_check_row_keys_are_exactly_what_the_agent_emits(
        self, seam_tree: dict[str, Any]
    ) -> None:
        """`verify_lineage_checks` emits the contract's key set, exactly.

        Not a subset: a key Go reads and Python stopped sending is the silent
        half of this failure mode, and a key Python sends that Go never reads
        is the other.
        """
        contract = _contract()
        want = set(contract["result"]["lineage_checks"][0])

        produced = verify_lineage_checks([seam_tree["row"]], seam_tree["root"])
        assert len(produced) == 1
        assert set(produced[0]) == want, (
            f"agent emits {sorted(produced[0])}, contract declares {sorted(want)}"
        )

    @pytest.mark.anyio
    async def test_result_event_carries_every_contract_key(
        self, seam_tree: dict[str, Any]
    ) -> None:
        """The three result-event keys the Go parser reads are all present."""
        contract = _contract()
        result = await _post_run({
            "run_id": "seam-3",
            "source_path": str(seam_tree["root"]),
            "config": {},
            "lineage_checks_requested": {"schema": 1, "rows": [seam_tree["row"]]},
        })
        for key in ("result_schema", "pruned_dirs", "lineage_checks"):
            assert key in result, f"result event is missing {key!r}"
            assert key in contract["result"], f"contract is missing {key!r}"

    def test_request_row_keys_are_all_consumed(self, seam_tree: dict[str, Any]) -> None:
        """The contract's own request row must verify, unmodified.

        Feeding Go's exact serialised row through the reader is what proves the
        agent reads the names Go writes — `rel_path` above all, since a row
        whose path does not resolve answers `unconfirmable` rather than
        erroring, and that answer is indistinguishable from a real one.
        """
        contract = _contract()
        row = dict(contract["request"]["rows"][0])
        # Re-point the contract's illustrative row at the real fixture file and
        # the real remembered quote; every OTHER key stays as Go wrote it.
        row["rel_path"] = seam_tree["row"]["rel_path"]
        row["line_start"] = seam_tree["row"]["line_start"]
        row["line_end"] = seam_tree["row"]["line_end"]
        row["fingerprint_v2"] = FINGERPRINT_V2
        row["quote_hash"] = quote_hash(QUOTE)

        out = verify_lineage_checks([row], seam_tree["root"])
        assert out[0]["outcome"] == "confirmed", (
            "a row serialised by the Go request struct did not verify; a key "
            f"name disagrees. got {out[0]}"
        )
        assert out[0]["lineage_id"] == row["lineage_id"]

    def test_outcome_vocabulary_is_exactly_the_contract(self) -> None:
        """The five outcome STRINGS.

        Compared with `==` on the Go side, whose default branch is
        `unconfirmable`. A one-character disagreement therefore does not error:
        it routes `confirmed` into the default and marks a live, still-present
        finding `unconfirmed` forever.
        """
        contract = _contract()
        # `unconfirmable` never comes from an anchor status — it is the ladder's
        # answer for every fact about the CHECKER — so it is added here.
        emitted = set(_OUTCOME_BY_ANCHOR_STATUS.values()) | {"unconfirmable"}
        assert emitted == set(contract["outcomes"]), (
            f"agent can emit {sorted(emitted)}, contract declares "
            f"{sorted(contract['outcomes'])}"
        )

    def test_only_gone_closes_a_finding(self) -> None:
        """`gone` is the sole closing outcome, and it maps from `absent` alone.

        The design principle in one assertion: an outcome may close a row only
        when it is a fact about the CODE. If any other anchor status ever maps
        to the closing outcome, a checker that could not look would close a
        live finding.
        """
        contract = _contract()
        closing = contract["closing_outcome"]
        assert closing == "gone"
        mapped_to_closing = {
            status for status, outcome in _OUTCOME_BY_ANCHOR_STATUS.items()
            if outcome == closing
        }
        assert mapped_to_closing == {"absent"}, (
            f"anchor statuses mapping to {closing!r}: {sorted(mapped_to_closing)} — "
            "only a verified absence from a file that was actually read may close"
        )
