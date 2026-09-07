"""Feature 0089 prerequisites — two ways the LLM tier loses a whole batch in
silence, both in ``shared.audit_runner``.

P4 — ``_normalize_finding`` passes ``raw.get("severity", "info")`` straight to
``normalize_severity``, which does ``raw.lower()``. A model emitting
``"severity": null`` (or a number) therefore raises ``AttributeError`` from
inside the parse, the exception escapes to the batch-level ``except Exception``
in ``_collect_llm_findings_async``, and EVERY finding in that batch is thrown
away and recorded as an LLM failure. One malformed field of one row costs the
batch. The numeric fields are already coerced (``_coerce_line``, B2) under the
rule "junk costs the FIELD, never the FINDING"; the string fields were not.

P5 — ``_parse_llm_findings`` returned a plain list, so "the model answered and
nothing parsed" and "the model found nothing" were the same value. In the batch
sweep ``error`` is set only by an exception, so a contract failure RESET the
consecutive-failure counter: a model that can never be parsed produced a clean,
green, zero-finding run and walked every batch to do it.
"""

import asyncio

import pytest

from shared import audit_runner
from shared.llm import provider

# ─────────────────────────────────────────────────────────────────────────────
# P4 — a malformed severity costs the field, not the batch
# ─────────────────────────────────────────────────────────────────────────────

_BATCH = (
    '[{"severity": "high", "title": "first", "file_path": "a.py"},'
    ' {"severity": %s, "title": "middle", "file_path": "b.py"},'
    ' {"severity": "low", "title": "last", "file_path": "c.py"}]'
)


@pytest.mark.parametrize("bad_severity", ["null", "123"])
def test_prereq_null_severity_survives(bad_severity):
    """Three rows in, three rows out — the bad one downgraded to ``info``.

    The parse must not raise: raising is what loses the two INNOCENT rows either
    side of the malformed one.
    """
    rows = audit_runner._parse_llm_findings(_BATCH % bad_severity)

    assert len(rows) == 3, (
        f"a malformed severity must cost the FIELD, not the batch; got {rows!r}"
    )
    assert [r["title"] for r in rows] == ["first", "middle", "last"]
    assert rows[1]["severity"] == "info", (
        f"the unusable severity must fall back to info; got {rows[1]['severity']!r}"
    )
    assert [r["severity"] for r in (rows[0], rows[2])] == ["high", "low"], (
        "the well-formed neighbours must be untouched"
    )


def test_prereq_null_severity_survives_for_the_other_string_fields():
    """``category``/``title``/``description`` reach the same ``.lower()``-shaped
    consumers and the dedup key; a non-string there must not cost the row."""
    rows = audit_runner._parse_llm_findings(
        '[{"severity": "high", "category": null, "title": null,'
        ' "description": 7, "file_path": "a.py"}]'
    )

    assert len(rows) == 1, f"the row must survive its junk fields; got {rows!r}"
    assert rows[0]["category"] == "unknown"
    assert rows[0]["title"] == "Untitled finding"
    assert rows[0]["description"] == "7"
    assert all(
        isinstance(rows[0][field], str)
        for field in ("severity", "category", "title", "description")
    ), "every text field must leave the parser as a str"


# ─────────────────────────────────────────────────────────────────────────────
# P5 — an unparseable response is a failure, not "no findings"
# ─────────────────────────────────────────────────────────────────────────────


class _FakeResult:
    """Minimal stand-in for an Agents SDK RunResult (same shape as 0070 P5's)."""

    def __init__(self, payload: str) -> None:
        self.final_output = payload
        self.raw_responses = []


class _ScriptedRunner:
    """Returns the SAME payload on every ``Runner.run`` and counts the calls."""

    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls: list[dict] = []

    async def run(self, agent, **kwargs):
        self.calls.append(kwargs)
        return _FakeResult(self.payload)


def _sweep(monkeypatch, tmp_path, payload: str, prefix: str):
    """Drive the real batch loop against a model that always answers *payload*."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    monkeypatch.setenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", "3")
    # Many small batches, and no 0059 tier filter, so there is a sweep to abort.
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "300")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")
    for i in range(20):
        (tmp_path / f"{prefix}{i}.py").write_text(f"# file {i}\n" + ("z = 3\n" * 30))

    runner = _ScriptedRunner(payload)
    import agents

    monkeypatch.setattr(agents, "Runner", runner)
    result = asyncio.run(
        audit_runner._collect_llm_findings_batched_async(
            f"0089-{prefix}", str(tmp_path), ["injection"], [], "inst", "categories",
        )
    )
    return runner, result


def test_prereq_unparsed_counts_as_failure(monkeypatch, tmp_path, caplog):
    """A model whose answer never parses must trip the consecutive-failure abort.

    Today it cannot: no exception is raised, so ``error`` stays ``None``, the
    counter is RESET by each unparseable batch and the sweep walks all 20
    batches to produce zero findings and report success.
    """
    with caplog.at_level("WARNING"):
        runner, (findings, error, _in, _out, notice) = _sweep(
            monkeypatch, tmp_path, "I found no issues in the codebase.", "u",
        )

    assert findings == []
    assert error, "a permanently unparseable model must not report success"
    assert len(runner.calls) <= 4, (
        f"the sweep must abort at the 3rd unparseable batch; it made "
        f"{len(runner.calls)} calls, i.e. it kept walking batches"
    )
    assert any(
        "llm_consecutive_failure_abort" in r.getMessage() for r in caplog.records
    ), "the abort must be logged so a truncated sweep is never silent"
    assert notice and "consecutive" in notice


def test_prereq_empty_arrays_are_not_failures(monkeypatch, tmp_path, caplog):
    """The other half of the contract: a well-formed empty array is an ANSWER.

    Without this the fix would be indistinguishable from "abort whenever a batch
    yields nothing", which would end every clean sweep after three quiet files.
    """
    with caplog.at_level("WARNING"):
        runner, (findings, error, _in, _out, notice) = _sweep(
            monkeypatch, tmp_path, "```json\n[]\n```", "e",
        )

    assert findings == []
    assert error is None, f"a parsed empty array is not a failure; got {error!r}"
    assert len(runner.calls) > 6, (
        "premise: the sweep must be long enough that an abort would be visible; "
        f"got {len(runner.calls)} batches"
    )
    assert not any(
        "llm_consecutive_failure_abort" in r.getMessage() for r in caplog.records
    )


def test_prereq_parse_outcome_reports_whether_anything_parsed():
    """The distinction the batch loop needs, at its source — and the list
    behaviour every existing caller of ``_parse_llm_findings`` relies on."""
    empty_answer = audit_runner._parse_llm_findings("```json\n[]\n```")
    unparseable = audit_runner._parse_llm_findings("I found no issues.")

    assert empty_answer.parsed is True
    assert empty_answer.rows == []
    assert unparseable.parsed is False
    # A response with no text at all is the model saying nothing, not a
    # contract breach: there is no payload to have failed to parse.
    assert audit_runner._parse_llm_findings("").parsed is True
    # Backward compatibility: the outcome is still usable as the row list.
    assert unparseable == [] and len(unparseable) == 0 and list(unparseable) == []


# ─────────────────────────────────────────────────────────────────────────────
# RED — P5 regressions found by attacking the P5 implementation
# ─────────────────────────────────────────────────────────────────────────────


class _SequenceRunner:
    """Answers a scripted payload per call, then repeats the last one."""

    def __init__(self, payloads: list[str]) -> None:
        self.payloads = payloads
        self.calls: list[dict] = []

    async def run(self, agent, **kwargs):
        payload = self.payloads[min(len(self.calls), len(self.payloads) - 1)]
        self.calls.append(kwargs)
        return _FakeResult(payload)


def _sweep_with(monkeypatch, tmp_path, runner, prefix: str):
    """``_sweep``'s environment, but driven by a caller-supplied runner."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    monkeypatch.setenv("VULTURE_LLM_MAX_CONSECUTIVE_FAILURES", "3")
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "300")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")
    for i in range(20):
        (tmp_path / f"{prefix}{i}.py").write_text(f"# file {i}\n" + ("z = 3\n" * 30))

    import agents

    monkeypatch.setattr(agents, "Runner", runner)
    return asyncio.run(
        audit_runner._collect_llm_findings_batched_async(
            f"0089-{prefix}", str(tmp_path), ["injection"], [], "inst", "categories",
        )
    )


@pytest.mark.parametrize(
    "payload",
    ["[]", "[ ]", "[\n]", "```\n[]\n```"],
    ids=["bare", "spaced", "newline", "unlabelled-fence"],
)
def test_prereq_bare_empty_array_is_an_answer_not_a_failure(payload):
    """An UNFENCED ``[]`` is the compliant "nothing found", not a contract miss.

    ``_score_array`` returns ``None`` for a zero-hit array so a prose decoy
    cannot shadow a real payload — and ``[]`` has no hits, so the compliant
    empty answer reached ``_extract_finding_rows`` as "no strategy matched".
    Only the ```` ```json ```` fence was covered. A model that answers a clean
    batch with a bare ``[]`` therefore booked an LLM FAILURE per batch, and
    three clean batches in a row aborted the whole sweep.
    """
    outcome = audit_runner._parse_llm_findings(payload)

    assert outcome.rows == []
    assert outcome.parsed is True, (
        f"{payload!r} is a well-formed empty findings array; calling it "
        "unparseable turns a clean sweep into an aborted one"
    )


def test_prereq_bare_empty_array_does_not_abort_the_sweep(monkeypatch, tmp_path, caplog):
    """The same defect at the level where it costs coverage: the batch loop."""
    runner = _SequenceRunner(["[]"])
    with caplog.at_level("WARNING"):
        findings, error, _in, _out, notice = _sweep_with(monkeypatch, tmp_path, runner, "b")

    assert findings == []
    assert error is None, f"a bare empty array is an answer, not a failure; got {error!r}"
    assert len(runner.calls) > 6, (
        f"the sweep must walk every batch; it stopped after {len(runner.calls)}"
    )
    assert not any(
        "llm_consecutive_failure_abort" in r.getMessage() for r in caplog.records
    )
    assert notice is None or "consecutive" not in notice


def test_prereq_a_parsed_batch_resets_the_unparsed_counter(monkeypatch, tmp_path, caplog):
    """The counter is CONSECUTIVE for the unparsed path too.

    Two unparseable batches, then one that parses, then three more unparseable:
    the abort must land on the SIXTH call, not the third. Without a reset the
    sweep would stop at call 3 and lose seventeen batches of coverage to two
    unlucky responses.
    """
    runner = _SequenceRunner([
        "I found no issues.",
        "Still nothing to report.",
        '```json\n[{"severity":"high","title":"real","file_path":"b2.py"}]\n```',
        "Nothing here either.",
        "Nor here.",
        "Nor here.",
    ])
    with caplog.at_level("WARNING"):
        findings, _error, _in, _out, notice = _sweep_with(monkeypatch, tmp_path, runner, "r")

    assert len(runner.calls) == 6, (
        "the parsed batch at call 3 must reset the counter, so the abort lands "
        f"on call 6; it landed on call {len(runner.calls)}"
    )
    assert any(
        "llm_consecutive_failure_abort" in r.getMessage() for r in caplog.records
    ), "three CONSECUTIVE unparsed batches must still abort"
    assert notice and "consecutive" in notice
    assert [f["title"] for f in findings] == ["real"], (
        "the one batch that parsed must keep its finding through the abort"
    )


@pytest.mark.parametrize(
    "payload",
    ['{"findings": []}', '```json\n{"findings": []}\n```'],
    ids=["bare", "fenced"],
)
def test_prereq_an_empty_wrapped_array_is_an_answer_not_a_failure(payload):
    """The same defect in its second shape, proven by ASYMMETRY.

    ``{"findings": [<rows>]}`` parses today — ``_scan_json_arrays`` reaches the
    inner array. The identical wrapper with ZERO rows does not, because a
    zero-hit array scores ``None``. So a model that always wraps works on every
    dirty batch and is booked an LLM failure on every clean one; three clean
    batches then abort the sweep. Whatever the wrapper, an empty findings array
    is an answer.
    """
    assert audit_runner._parse_llm_findings(
        '{"findings": [{"severity":"high","title":"x","file_path":"a.py"}]}'
    ).parsed is True, "premise: the wrapper parses when it carries rows"

    outcome = audit_runner._parse_llm_findings(payload)
    assert outcome.rows == []
    assert outcome.parsed is True, f"{payload!r} is an empty findings array"


def test_prereq_a_json_response_with_no_findings_array_is_still_unparsed():
    """The bound on the last-resort strategy: it must not admit any old JSON.

    Without this the fix degrades into "well-formed JSON is always an answer",
    and the contract-failure signal P5 exists for disappears.
    """
    for payload in ('{"status": "ok"}', '"a string"', "null", "42",
                    'I found no issues.', 'const rows = [{"id":1}]'):
        assert audit_runner._parse_llm_findings(payload).parsed is False, (
            f"{payload!r} carries no findings array and must stay unparsed"
        )
