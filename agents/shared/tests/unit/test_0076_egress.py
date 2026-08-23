"""0076 §5.4(2) — the egress hole: a model-copied quote must never leave the agent.

`evidence_quote` is the field 0076 asks the model to fill with **source text copied
verbatim** out of the file it is accusing. On a credential finding — CWE-798, the
single most common secret-bearing class in this tree — that text *is* the secret.
Nothing downstream knows this: `_redact_finding_inplace` (`audit_runner.py:1874`)
only ever looks at `code_snippet`, and `AgUiEventEmitter.finding_event`
(`transport/event_emitter.py:45-61`) forwards every `**extra` key **verbatim** into
the SSE payload. A new key on a finding dict is therefore, by default, a new
public egress channel — to the live stream, to the persisted row, and into the L5
judge's input.

WHAT THIS FILE EXISTS TO PREVENT, AND IT IS NOT HYPOTHETICAL. An earlier revision of
the design called the strip from **inside the verifier**. The verifier is gated on
`VULTURE_LLM_QUOTE_VERIFY`, so at `VULTURE_LLM_QUOTE_VERIFY=off` — the documented
rollback position — the verifier never ran, nothing stripped the field, and the
quote flowed straight to SSE, to the DB and into the L5 prompt. **The rollback path
walked through the hole**: an operator disabling the feature after an incident would
have ENABLED the leak. Every test below that drives the pipeline at
`VULTURE_LLM_QUOTE_VERIFY=off` fails against that design, and that is the whole
point of the twelve-way cross product (AC29, T1.9). The fix is one unconditional
pass, `_strip_private_fields`, at the parse choke point (`:2602`) — **upstream of
every mode check**, so no switch position can widen egress.

The seven `_anchor_*` fields ride along for a second, quieter reason (AC11). Were
they plain public fields they would reach the live SSE stream and then be dropped at
the Go unmarshal boundary (`model.Finding` is a fixed struct), so the same finding
would differ between the live stream and its 0071 replay. Private-and-stripped keeps
those two byte-identical; the authoritative copy travels in the `anchor` check's
`extras` inside the already-persisted `validation` blob (§5.4(4)).

Two tests here are REGRESSION LOCKS, not RED guards, and are labelled as such: the
emitter's verbatim `**extra` forwarding (it is the mechanism that makes the strip
load-bearing, and it passes today) and the public-field survival check. The rest are
RED until `_strip_private_fields` exists.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from shared import audit_runner
from shared.llm import provider
from shared.transport.event_emitter import AgUiEventEmitter

# A credential that a model would copy into `evidence_quote` verbatim. No quote
# characters and no backslashes, so a substring search over JSON-escaped output is
# exact rather than approximate.
_SECRET = "sk-live-DEADBEEF-9c1f2a"
_QUOTE = f'api_key = "{_SECRET}"'
_SOURCE = f"import os\n{_QUOTE}\nprint(api_key)\n"

# The seven verifier outputs of §5.4(2). Named here so the roster test and the SSE
# test cannot drift apart.
_ANCHOR_FIELDS = (
    "_anchor_status",
    # 10th: the verifier's own reason ("truncated:exact" vs "oversize_truncated").
    # Added when the persisted `anchor` check was found to be rebuilding its reason
    # from the status alone, which collapsed a truncated-but-located quote and a
    # truncated-and-lost one into the same undecomposable bucket.
    "_anchor_reason",
    "_claimed_line",
    "_anchor_delta",
    "_anchor_candidates",
    "_anchor_other_path",
    "_anchor_quote_chars",
    "_anchor_quote_tokens",
)

# The full switch cross product of AC29: 3 x 2 x 2 = twelve.
_CROSS_PRODUCT = [
    (verify, required, keep_text)
    for verify in ("off", "observe", "enforce")
    for required in ("true", "false")
    for keep_text in ("true", "false")
]
_CROSS_IDS = [f"verify={v}-required={r}-keep_text={k}" for v, r, k in _CROSS_PRODUCT]


# ---------------------------------------------------------------------------
# harness — no network, no model, no sleeps
# ---------------------------------------------------------------------------


class _FakeResult:
    """Minimal stand-in for an Agents SDK RunResult."""

    def __init__(self, payload: str) -> None:
        self.final_output = payload
        self.raw_responses = []


class _SpyRunner:
    """Returns a canned model payload; records every Runner.run call."""

    def __init__(self, payload: str = "", behaviour: Any = None) -> None:
        self._payload = payload
        self._behaviour = behaviour
        self.calls: list[dict] = []

    async def run(self, agent, **kwargs):
        self.calls.append(kwargs)
        if self._behaviour is not None:
            return await self._behaviour(len(self.calls), kwargs)
        return _FakeResult(self._payload)


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """Deterministic model resolution; nothing reaches a network."""
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(audit_runner, "_CUSTOM_BASE_URL", "")
    from shared.llm.broker import set_context_window

    set_context_window(None)
    yield
    set_context_window(None)


def _tree(tmp_path: Path) -> Path:
    """The one fixture tree every pipeline test uses: a real file whose line 2 is
    byte-identical to `_QUOTE`, so the verifier resolves it as `exact` and no test
    accidentally measures a matching failure instead of an egress failure."""
    src = tmp_path / "svc.py"
    src.write_text(_SOURCE)
    return src


def _model_payload(quote: str = _QUOTE) -> str:
    """One CWE-798 finding, quoted, carrying a model-authored `check_id` (which P1
    demotes to the private `_model_check_id`)."""
    body = json.dumps([{
        "title": "Hardcoded credential",
        "severity": "high",
        "category": "CWE-798",
        "description": "The API key is committed in source.",
        "file_path": "svc.py",
        "line_start": 2,
        "line_end": 2,
        "recommendation": "Move it to the environment.",
        "evidence_quote": quote,
        "check_id": "MODEL-MADE-UP-ID",
    }])
    return f"```json\n{body}\n```"


def _install_strip_spy(monkeypatch) -> list[dict]:
    """Wrap the real `_strip_private_fields` so a test can see what it was handed
    BEFORE it ran. This is the non-vacuity guard: absence at egress proves nothing
    unless something was there to remove."""
    real = audit_runner._strip_private_fields
    seen: list[dict] = []

    # The roster parameter exists because the two kinds of private field have
    # DIFFERENT LIFETIMES (corrected after the first implementation shipped the
    # feature inert): `evidence_quote`/`_model_check_id` must die at the parse
    # choke point, while the `_anchor_*` stamps must survive until `run_l1` --
    # their documented last consumer -- or no `anchor` check is ever produced and
    # the entire downstream (the voter seat, the Go parity fixtures, the survivor
    # merge) is unreachable. The spy forwards whatever roster the caller passed;
    # every ASSERTION in this file is unchanged.
    def _spy(finding: dict, *args, **kwargs) -> None:
        seen.append(dict(finding))
        real(finding, *args, **kwargs)

    monkeypatch.setattr(audit_runner, "_strip_private_fields", _spy)
    return seen


def _drive(monkeypatch, tmp_path: Path, runner: _SpyRunner, **kwargs):
    """Run `_collect_llm_findings_async` once, synchronously. This is the choke
    point (`:2602`) in its real calling context — both parse branches, the strip and
    the size-retry re-entry all live inside it."""
    import agents

    monkeypatch.setattr(agents, "Runner", runner)
    call: dict[str, Any] = dict(
        run_id="egress",
        source_path=str(tmp_path),
        categories=["CWE-798"],
        skill_tools=[],
        instructions="audit it",
        domain_label="categories",
    )
    call.update(kwargs)
    return asyncio.run(audit_runner._collect_llm_findings_async(**call))


def _sse_payload(finding: dict) -> dict:
    """The exact bytes the live stream carries for this finding: `:1875` does
    `emitter.finding_event(**finding)` and `**extra` is forwarded verbatim."""
    raw = AgUiEventEmitter("egress").finding_event(**finding)
    return json.loads(raw.split("data: ", 1)[1])


def _assert_quote_never_egresses(finding: dict, where: str) -> None:
    """The AC29 property, asserted on one finding across all three egress surfaces:
    the SSE payload, the persisted dict, and the dict handed to L5 (L5 receives the
    finding itself, so its serialisation is the L5 input)."""
    blob = json.dumps(finding, default=str)
    sse = _sse_payload(finding)
    sse_blob = json.dumps(sse, default=str)
    for key in ("evidence_quote", "_model_check_id"):
        assert key not in finding, f"{key} survived into the persisted finding at {where}"
        assert key not in sse, f"{key} reached the SSE payload at {where}"
    assert _SECRET not in blob, (
        f"the model-copied credential reached the persisted finding / L5 input at {where}"
    )
    assert _SECRET not in sse_blob, f"the model-copied credential reached SSE at {where}"


# ---------------------------------------------------------------------------
# the roster and the primitive
# ---------------------------------------------------------------------------


def test_private_field_roster_is_the_documented_nine():
    """`_PRIVATE_FIELDS` is the contract: one list, deleted by one pass. Adding a
    private field without adding it here is how the next leak happens.

    The count is asserted as "no duplicates" rather than a literal, so the roster
    can grow deliberately (it did: `_anchor_reason`) while the completeness check
    -- every name this module knows about must be in the roster -- still binds."""
    from shared.audit_runner import _PRIVATE_FIELDS

    expected = {"evidence_quote", "_model_check_id", *_ANCHOR_FIELDS}
    assert set(_PRIVATE_FIELDS) == expected, (
        "the private roster must be exactly the fields of §5.4(2); "
        f"missing={expected - set(_PRIVATE_FIELDS)} "
        f"unexpected={set(_PRIVATE_FIELDS) - expected}"
    )
    assert len(_PRIVATE_FIELDS) == len(set(_PRIVATE_FIELDS)), "no duplicates in the roster"


def test_strip_removes_every_private_field_and_leaves_the_finding_intact():
    """The primitive, in isolation: it deletes all nine, mutates in place, returns
    None, is idempotent, and touches nothing else.

    The last clause is the recall half. A strip that took `line_start` or
    `description` with it would turn a leak fix into a data-loss bug, and every
    other test in this file asserts ABSENCE, so none of them would notice.
    """
    from shared.audit_runner import _PRIVATE_FIELDS, _strip_private_fields

    public = {
        "title": "Hardcoded credential",
        "severity": "high",
        "category": "CWE-798",
        "description": "d",
        "file_path": "svc.py",
        "line_start": 2,
        "line_end": 2,
        "recommendation": "r",
    }
    finding = dict(public)
    finding.update({name: "x" for name in _PRIVATE_FIELDS})

    assert _strip_private_fields(finding) is None, "the strip mutates in place"
    for name in _PRIVATE_FIELDS:
        assert name not in finding, f"{name} survived the strip"
    assert finding == public, "the strip must not disturb any public field"

    _strip_private_fields(finding)  # idempotent: a second pass is a no-op
    assert finding == public


# ---------------------------------------------------------------------------
# why the strip is load-bearing: the emitter forwards anything
# ---------------------------------------------------------------------------


def test_finding_event_forwards_unknown_keys_verbatim():
    """REGRESSION LOCK — passes today, and it is the mechanism the rest of this file
    guards against. `finding_event(**extra)` (`event_emitter.py:45-61`) copies every
    unrecognised key straight into the SSE data blob. There is no allowlist, no
    schema and no redaction between a finding dict and the live stream, so a private
    field is only private because something deleted it first."""
    payload = _sse_payload({
        "severity": "high", "category": "CWE-798", "title": "t",
        "description": "d", "evidence_quote": _QUOTE, "_anchor_status": "exact",
    })
    assert payload["evidence_quote"] == _QUOTE, (
        "if this ever stops holding, the emitter grew a filter and the docstrings "
        "in this file need rewriting — but do NOT rely on it as the leak defence"
    )
    assert payload["_anchor_status"] == "exact"


def test_anchor_private_fields_never_reach_the_sse_payload():
    """AC11: none of the seven verifier outputs may reach the live stream.

    Not a secrecy concern — a correctness one. The Go side unmarshals into a fixed
    `model.Finding`, so a plain `anchor_*` field would be visible live and absent
    from the 0071 replay of the same run: one finding, two different contents,
    depending on when you looked. The authoritative copy travels in the `anchor`
    check's `extras` inside the persisted `validation` blob instead.
    """
    from shared.audit_runner import _strip_private_fields

    finding = {
        "severity": "high", "category": "CWE-798", "title": "t",
        "description": "d", "file_path": "svc.py", "line_start": 2,
        "line_end": 2, "recommendation": "r",
        "evidence_quote": _QUOTE,
        "_model_check_id": "MODEL-MADE-UP-ID",
    }
    finding.update({name: "stamped" for name in _ANCHOR_FIELDS})

    _strip_private_fields(finding)
    payload = _sse_payload(finding)

    for name in _ANCHOR_FIELDS:
        assert name not in payload, f"{name} reached the SSE payload"
    leaked = [k for k in payload if k.startswith("_")]
    assert leaked == [], f"no underscore-prefixed key may egress; leaked {leaked}"
    # REGRESSION LOCK half: live and replay stay byte-identical only if the PUBLIC
    # fields are all still there.
    assert payload["line_start"] == 2 and payload["title"] == "t"


# ---------------------------------------------------------------------------
# AC29 — the twelve-way cross product
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("verify", "required", "keep_text"), _CROSS_PRODUCT, ids=_CROSS_IDS)
def test_evidence_quote_never_egresses_at_any_switch_setting(
    monkeypatch, tmp_path, verify, required, keep_text,
):
    """AC29 / T1.9 — twelve combinations, one property: the quote and the model's
    `check_id` are gone from every egress surface in ALL of them.

    `VULTURE_LLM_QUOTE_VERIFY=off` is the row that matters. Under the withdrawn
    design (strip called from inside the verifier) those four rows leak: the
    verifier does not run, nothing deletes `evidence_quote`, and a live credential
    reaches SSE, the DB row and the L5 prompt. This test fails against that design
    by construction, which is why the strip is unconditional and sits upstream of
    every mode check.

    The spy makes the assertion non-vacuous: it records what the strip was HANDED,
    so "the key is absent" cannot be satisfied by a parser that quietly dropped the
    field before the choke point ever saw it.
    """
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", verify)
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", required)
    monkeypatch.setenv("VULTURE_LLM_QUOTE_KEEP_TEXT", keep_text)
    _tree(tmp_path)
    seen = _install_strip_spy(monkeypatch)

    findings, error, _in, _out = _drive(
        monkeypatch, tmp_path, _SpyRunner(_model_payload()),
    )

    assert error is None, f"the drive itself must succeed: {error}"
    assert len(findings) == 1, (
        "the model's finding must survive the strip — 0076 deletes fields, never rows"
    )
    assert len(seen) >= 1, (
        "the strip did not run at all in this configuration; it is unconditional"
    )
    _assert_quote_never_egresses(findings[0], f"verify={verify} keep_text={keep_text}")


def test_the_strip_runs_with_the_verifier_disabled_entirely(monkeypatch, tmp_path):
    """§5.4(2) — the strip is UPSTREAM of every mode check.

    The sharpest form of the AC29 row above: at `VULTURE_LLM_QUOTE_VERIFY=off` the
    finding that reaches the strip still carries the model's quote (so the parser
    preserved it, per §5.1's `_FINDING_KEYS`), and the finding that leaves the choke
    point does not. The deletion is therefore attributable to the strip and to
    nothing else — which is exactly the claim the rollback path depends on.
    """
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "off")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", "true")
    _tree(tmp_path)
    seen = _install_strip_spy(monkeypatch)

    findings, error, _in, _out = _drive(
        monkeypatch, tmp_path, _SpyRunner(_model_payload()),
    )

    assert error is None, f"the drive itself must succeed: {error}"
    assert len(seen) == 1, "the strip runs once per parsed finding, verifier or not"
    assert seen[0].get("evidence_quote") == _QUOTE, (
        "with the verifier off the quote must still REACH the strip — otherwise this "
        "test proves nothing about the strip and the VERIFY=off hole is untested"
    )
    _assert_quote_never_egresses(findings[0], "verify=off")


def test_the_size_retry_re_entry_is_also_stripped(monkeypatch, tmp_path):
    """D1: the choke point is re-entered by the halved-body retry (`:2628-2634`).

    A 413 halves the source and calls `_collect_llm_findings_async` again. That
    second call parses a second model response — a response nothing else in the run
    has seen. If the strip lived anywhere that the re-entry bypasses, the retried
    batch would be the one that leaks, and it would leak only under gateway
    pressure: the least reproducible condition there is.
    """
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    _tree(tmp_path)
    seen = _install_strip_spy(monkeypatch)

    async def _behaviour(attempt: int, _kwargs: dict):
        if attempt == 1:
            raise RuntimeError("Error code: 413 - request_too_large")
        return _FakeResult(_model_payload())

    runner = _SpyRunner(behaviour=_behaviour)
    source_context = "\n\n".join(f"--- f{i}.py ---\n{'x' * 400}" for i in range(8))
    findings, error, _in, _out = _drive(
        monkeypatch, tmp_path, runner, source_context=source_context,
    )

    assert error is None, f"the halved retry should have succeeded: {error}"
    assert len(runner.calls) == 2, "premise: exactly one size retry actually happened"
    assert len(findings) == 1 and len(seen) == 1
    _assert_quote_never_egresses(findings[0], "size-retry re-entry")


# ---------------------------------------------------------------------------
# KEEP_TEXT — a redacted copy, or no copy; never the raw quote
# ---------------------------------------------------------------------------


def _anchor_extras(finding: dict, source_root: Path) -> dict:
    """The `anchor` check `run_l1` emits for this finding (§5.4(3)-(4)): the single
    committed egress route for anything the verifier learned."""
    from shared.validate.context_heuristics import run_l1

    (checks,) = run_l1([finding], source_root=str(source_root))
    for check in checks:
        if check.id == "anchor":
            return dict(check.extras or {})
    raise AssertionError(
        "run_l1 emitted no `anchor` check for a finding carrying _anchor_status; "
        "the status has no other persisted egress route (§5.4(4))"
    )


def _quoted_finding(src: Path) -> dict:
    """A finding in the state `run_l1` sees it: verifier outputs stamped, quote not
    yet stripped (§5.4(2) — `run_l1` is the last consumer before the strip)."""
    return {
        "title": "Hardcoded credential", "severity": "high", "category": "CWE-798",
        "description": "d", "file_path": str(src), "line_start": 2, "line_end": 2,
        "recommendation": "r", "evidence_quote": _QUOTE, "_anchor_status": "exact",
        "_claimed_line": 2, "_anchor_delta": 0,
    }


def test_keep_text_false_retains_no_copy_of_the_quote(monkeypatch, tmp_path):
    """Default (`VULTURE_LLM_QUOTE_KEEP_TEXT=false`): the quote is not retained at
    all — not raw, not redacted. The status is what the validation blob is for; the
    text was never the payload."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_KEEP_TEXT", "false")
    src = _tree(tmp_path)

    extras = _anchor_extras(_quoted_finding(src), tmp_path)
    blob = json.dumps(extras, default=str)

    assert _SECRET not in blob, "the raw credential reached the persisted validation blob"
    assert "REDACTED" not in blob, (
        "nothing is retained by default — a redacted copy is opt-in via KEEP_TEXT"
    )


def test_keep_text_true_retains_only_a_redacted_copy(monkeypatch, tmp_path):
    """`VULTURE_LLM_QUOTE_KEEP_TEXT=true` buys offline debugging, NOT a secret
    channel. What lands in the `anchor` check's extras is `_redact_snippet(quote)` —
    the same primitive `code_snippet` already goes through (`:1406`) — so the shape
    of the line survives for triage and the value does not.

    Note the polarity: this is the ONLY switch in the feature that puts any part of
    the quote on a persisted path, and even it may not put the credential there.
    """
    from shared.audit_runner import _redact_snippet

    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_KEEP_TEXT", "true")
    src = _tree(tmp_path)

    extras = _anchor_extras(_quoted_finding(src), tmp_path)
    redacted = _redact_snippet(_QUOTE)

    assert _SECRET not in redacted, "premise: the redaction primitive masks this value"
    assert _SECRET not in json.dumps(extras, default=str), (
        "KEEP_TEXT=true must retain a REDACTED copy — the raw quote is a credential"
    )
    values = [v for v in extras.values() if isinstance(v, str)]
    assert redacted in values, (
        "KEEP_TEXT=true must retain the redacted quote in the anchor check's extras; "
        f"got {values}"
    )
