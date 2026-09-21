"""Feature 0093 — the LLM transport must be bounded, diagnosable and safe to persist.

Three defects, each proven against the live code before this file was written:

W1  The generate path's HTTP client sets no socket timeout. The broker client
    inherits the openai SDK default (read=600) and the LiteLLM path inherits
    litellm's request_timeout=6000, so the documented
    VULTURE_LLM_CALL_TIMEOUT_SEC never reaches the socket at all.

W2  `retry_llm_call` logs `str(exc)[:200]`. For APIConnectionError that string
    is the constant "Connection error." and the __cause__ naming the real
    httpx fault is discarded — 23 such lines in one measured run, carrying no
    diagnostic content. And the text it renders reaches four persisted sinks
    (log, SSE thinking, audits.degraded_reason, and lineage_events.notes once
    per skipped row), with no sanitising whatsoever.

W2b A second rendering defect in the same function: `_BROKER_PERMANENT_RE`
    expects `"x_retriable": false`, but the SDK renders the envelope with
    Python repr quoting — `'x_retriable': False`. The broker's authoritative
    non-retriable signal therefore never matches, and permanent failures are
    retried three times.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

# ── W1: the socket honours the documented budget ────────────────────────────


def _timeout_for(call_timeout: str | None):
    from shared.llm import broker

    env = {} if call_timeout is None else {"VULTURE_LLM_CALL_TIMEOUT_SEC": call_timeout}
    with mock.patch.dict(os.environ, env, clear=False):
        if call_timeout is None:
            os.environ.pop("VULTURE_LLM_CALL_TIMEOUT_SEC", None)
        return broker._client_timeout()


def test_socket_read_tracks_the_documented_call_timeout() -> None:
    assert _timeout_for("900").read == 900.0, (
        "VULTURE_LLM_CALL_TIMEOUT_SEC is documented as the per-call bound; if it "
        "does not reach the socket the operator's setting is decorative"
    )


def test_socket_read_falls_back_to_the_DERIVED_default() -> None:
    """Not the literal 120. An absent or unparseable value falls back to the
    same derived budget the batch uses, because a socket that cuts at 120s
    inside a 439s batch would truncate every long answer — the defect this
    feature exists to remove, reintroduced one layer down."""
    from shared.llm.env import resolve_call_timeout

    for bad in (None, "0", "-5", "notanumber", ""):
        got = _timeout_for(bad).read
        assert got == float(resolve_call_timeout()), f"{bad!r} gave {got}"
        assert got >= 120.0, "never below the historical default"


def test_connect_write_and_pool_do_not_scale_with_the_call_budget() -> None:
    """Only `read` is a generation-length question.

    Scaling `pool` with the call budget turns a pool-exhaustion bug into a
    45-minute silent hang at call=2700; scaling `write` gives 2730s to send a
    body that VULTURE_LLM_MAX_BODY_BYTES caps at 128KB.
    """
    small, large = _timeout_for("120"), _timeout_for("2700")
    assert small.connect == large.connect
    assert small.write == large.write
    assert small.pool == large.pool
    assert small.connect > 5.0, "the SDK's 5s connect is tight under load"


def test_the_socket_sits_inside_the_batch_budget_not_outside() -> None:
    """THE correction that adversarial review forced.

    The first cut set the socket to `call + 30` so it would "outlive the
    broker's deadline". But audit_runner wraps the whole BATCH in
    `asyncio.wait_for(..., timeout=call)` using the same variable, so a
    `call + 30` socket can never fire at any value — it was unreachable by
    construction. The socket bounds ONE HTTP call and must nest inside.
    """
    call = 600
    batch_budget = float(call)  # what audit_runner's wait_for uses
    assert _timeout_for(str(call)).read <= batch_budget, (
        "a socket above the batch budget is dead code: wait_for always wins"
    )


def test_the_litellm_path_carries_a_timeout_too() -> None:
    """The broker ships OFF (docker-compose: VULTURE_LLM_BROKER=off), so the
    path most deployments actually run is LiteLLM — which set no timeout at
    all and inherited litellm's request_timeout=6000."""
    from shared.llm.provider import litellm_retry_extra_args

    with mock.patch.dict(os.environ, {"VULTURE_LLM_CALL_TIMEOUT_SEC": "300"}):
        args = litellm_retry_extra_args("litellm/gemini/gemini-2.5-pro")
    assert args.get("timeout") == 300.0, f"no per-call timeout on the shipped path: {args}"
    assert args.get("max_retries") == 0, "the retry pin must survive"


# ── W2: the failure names its cause ─────────────────────────────────────────


class _FakeConnErr(Exception):
    """openai's APIConnectionError shape: a constant message, real fault on __cause__."""

    def __init__(self) -> None:
        super().__init__("Connection error.")


def _conn_error_with_cause(cause: BaseException) -> Exception:
    try:
        raise cause
    except BaseException as inner:
        try:
            raise _FakeConnErr() from inner
        except _FakeConnErr as outer:
            return outer


def test_the_cause_chain_is_rendered() -> None:
    from shared.llm.errors import exception_detail

    exc = _conn_error_with_cause(
        RuntimeError("server disconnected without sending a response")
    )
    detail = exception_detail(exc)
    assert "Connection error." in detail
    assert "server disconnected" in detail, (
        f"the cause is the only part that says WHAT failed: {detail!r}"
    )
    assert "RuntimeError" in detail


def test_a_bare_exception_still_renders() -> None:
    from shared.llm.errors import exception_detail

    assert "boom" in exception_detail(ValueError("boom"))


def test_the_rendering_is_bounded() -> None:
    from shared.llm.errors import exception_detail

    exc = _conn_error_with_cause(RuntimeError("A" * 5000))
    assert len(exception_detail(exc, max_len=200)) <= 220


def test_a_deep_cause_chain_does_not_run_away() -> None:
    from shared.llm.errors import exception_detail

    exc: BaseException = ValueError("root")
    for i in range(10):
        exc = _conn_error_with_cause(exc) if i == 0 else _wrap(exc, f"layer{i}")
    assert len(exception_detail(exc)) <= 220


def _wrap(inner: BaseException, msg: str) -> Exception:
    try:
        raise inner
    except BaseException as e:
        try:
            raise RuntimeError(msg) from e
        except RuntimeError as outer:
            return outer


# ── W2: and it must be safe to persist ──────────────────────────────────────
#
# The rendered text reaches audits.degraded_reason in both dialects, the SSE
# thinking stream, the React UI, and lineage_events.notes ONCE PER SKIPPED ROW.
# The Go side already sanitises provider text for exactly these reasons
# (broker/provider/upstream_detail.go); Python had no equivalent.


def test_credential_shapes_are_redacted_from_the_cause() -> None:
    from shared.llm.errors import exception_detail

    for name, secret in {
        "url userinfo": "http://admin:hunter2handshake@llm.internal:8080/v1",
        "google key": "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
        "openai key": "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
        "bearer": "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghij.klmnop",
        "aws key id": "AKIAIOSFODNN7EXAMPLE",
    }.items():
        detail = exception_detail(_conn_error_with_cause(RuntimeError(f"failed {secret} x")))
        assert secret not in detail, f"{name} survived into a persisted field: {detail!r}"


def test_control_characters_and_bidi_are_stripped() -> None:
    from shared.llm.errors import exception_detail

    raw = "boom \x1b[31mRED\x07 ‮reversed​ zero\nforged: line"
    detail = exception_detail(_conn_error_with_cause(RuntimeError(raw)))
    for bad in ("\x1b", "\x07", "‮", "​", "\n"):
        assert bad not in detail, f"{bad!r} reached a persisted, UI-rendered field: {detail!r}"
    assert "boom" in detail, "sanitising must not destroy the diagnosis"


def test_redaction_runs_before_truncation() -> None:
    """A secret cut in half is still a secret — the Go side documents this
    ordering as load-bearing (upstream_detail.go)."""
    from shared.llm.errors import exception_detail

    secret = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
    exc = _conn_error_with_cause(RuntimeError("x" * 150 + " " + secret))
    detail = exception_detail(exc, max_len=180)
    assert secret[:20] not in detail, f"a half-secret survived truncation: {detail!r}"


def test_an_ordinary_diagnosis_is_not_over_redacted() -> None:
    from shared.llm.errors import exception_detail

    for ordinary in (
        "All connection attempts failed",
        "peer closed connection without sending complete message body",
        "models/gemini-2.5-pro is not found for API version v1beta",
        "qwen/qwen3.8-27b",
    ):
        detail = exception_detail(_conn_error_with_cause(RuntimeError(ordinary)))
        assert ordinary.split()[0] in detail, f"over-redacted: {ordinary!r} -> {detail!r}"


def test_the_persisted_failure_message_uses_the_cause() -> None:
    from shared.llm.errors import LLMErrorKind, llm_failure_message

    exc = _conn_error_with_cause(RuntimeError("all connection attempts failed"))
    msg = llm_failure_message(LLMErrorKind.CONNECTION_ERROR, exc)
    assert "connection attempts failed" in msg, (
        f"audits.degraded_reason must carry the cause, not just 'Connection error.': {msg!r}"
    )


def test_the_persisted_failure_message_is_sanitised() -> None:
    from shared.llm.errors import LLMErrorKind, llm_failure_message

    exc = _conn_error_with_cause(
        RuntimeError("fail http://u:sup3rsecret@host/v1 \x1b[31m ‮")
    )
    msg = llm_failure_message(LLMErrorKind.CONNECTION_ERROR, exc)
    for bad in ("sup3rsecret", "\x1b", "‮"):
        assert bad not in msg, f"{bad!r} reached audits.degraded_reason: {msg!r}"


# ── W2b: the broker's non-retriable signal must actually match ──────────────


@pytest.mark.parametrize(
    "wire",
    [
        # What the openai SDK actually produces: Python repr, single quotes,
        # capital-F False. The regex expected JSON double quotes and lowercase.
        "Error code: 400 - {'error': {'code': 'invalid_request', 'x_retriable': False}}",
        # A raw httpx/requests caller still sees real JSON.
        'Error code: 400 - {"error": {"code": "invalid_request", "x_retriable": false}}',
    ],
)
def test_a_non_retriable_broker_error_is_classified_permanent(wire: str) -> None:
    from shared.llm.errors import RETRYABLE_KINDS, classify_llm_error

    kind = classify_llm_error(RuntimeError(wire))
    assert kind not in RETRYABLE_KINDS, (
        f"x_retriable:false means retrying cannot help, yet {kind} is retryable. "
        f"Rendering: {wire[:60]}"
    )


# ── W3': the loop-guard branch that has never executed ──────────────────────
#
# `audit_runner` has `except LoopDetectedError` whose comment says a loop is an
# agent reasoning failure, not a model failure, so it must NOT record a model
# cooldown. That branch is dead code: the Agents SDK wraps any non-AgentsException
# raised from a tool hook —
#     raise UserError(f"Error running tool {name}: {e}") from e
# (agents/run_internal/tool_execution.py) — so what propagates is a UserError
# with LoopDetectedError on __cause__. Measured across every agent log: 33
# `ping_pong_detected` events, ZERO `loop_detected run_id` lines, and the
# observed degraded reason is the GENERIC handler's "LLM analysis failed
# (unknown): Error running tool list_files_confined: Tool loop detected…".
#
# So every loop trip has been recording the model cooldown the comment forbids.


def test_a_loop_error_is_recognised_through_the_sdk_wrapper() -> None:
    from shared.audit_runner import _loop_error_from
    from shared.llm.loop_guard import LoopDetectedError

    inner = LoopDetectedError("Tool loop detected: list_files_confined", total_calls=4)
    try:
        raise inner
    except LoopDetectedError as e:
        try:
            # exactly what the SDK does
            raise RuntimeError(f"Error running tool list_files_confined: {e}") from e
        except RuntimeError as wrapped:
            found = _loop_error_from(wrapped)

    assert found is inner, (
        "the loop error must be recognised through the SDK's UserError wrapper, "
        "or the loop branch stays dead and every trip records a spurious cooldown"
    )


def test_a_direct_loop_error_is_still_recognised() -> None:
    from shared.audit_runner import _loop_error_from
    from shared.llm.loop_guard import LoopDetectedError

    exc = LoopDetectedError("direct", total_calls=1)
    assert _loop_error_from(exc) is exc


def test_an_ordinary_failure_is_not_mistaken_for_a_loop() -> None:
    from shared.audit_runner import _loop_error_from

    assert _loop_error_from(RuntimeError("Connection error.")) is None
    assert _loop_error_from(ValueError("Max turns (12) exceeded")) is None


def test_the_walk_is_bounded_and_survives_a_cycle() -> None:
    """Never raise inside a failure handler, even on a self-referential chain."""
    from shared.audit_runner import _loop_error_from

    a = RuntimeError("a")
    b = RuntimeError("b")
    a.__cause__ = b
    b.__cause__ = a
    assert _loop_error_from(a) is None


# ── the call-timeout default must fit the output-token default ──────────────
#
# THE INCONSISTENCY: VULTURE_LLM_MAX_OUTPUT_TOKENS defaults to 16384 and
# VULTURE_LLM_CALL_TIMEOUT_SEC to 120. No provider generates 16384 tokens in
# 120 seconds — a fast cloud model at ~100 tok/s needs 164s, and the local
# model measured for 0093 runs at ~50 tok/s and needs ~327s. So the shipped
# pair guaranteed that a model producing a full-length answer was cut off,
# on EVERY provider, and the only escape was for each operator to discover
# the interaction and hand-tune it. That is what forced the tuning that then
# destroyed the LLM tier.
#
# The fix derives the default from the budget it has to accommodate, so the
# two defaults cannot drift apart again. No new flag: both variables already
# exist, and an explicit operator value still wins.


def _call_timeout(env: dict[str, str]) -> int:
    from shared import audit_runner

    with mock.patch.dict(os.environ, env, clear=False):
        for k in ("VULTURE_LLM_CALL_TIMEOUT_SEC", "VULTURE_LLM_MAX_OUTPUT_TOKENS"):
            if k not in env:
                os.environ.pop(k, None)
        return audit_runner._resolve_call_timeout()


def test_the_default_can_actually_generate_the_default_output_budget() -> None:
    """The floor: 16384 tokens at a conservative local rate, not 120 seconds."""
    got = _call_timeout({})
    assert got >= 16384 / 100, f"{got}s cannot produce 16384 tokens at even 100 tok/s"
    assert got >= 300, (
        f"{got}s is below the ~327s a 50 tok/s local model needs for a full answer; "
        "the default would truncate every long answer and look like a quiet model"
    )


def test_an_explicit_operator_value_still_wins() -> None:
    assert _call_timeout({"VULTURE_LLM_CALL_TIMEOUT_SEC": "90"}) == 90
    assert _call_timeout({"VULTURE_LLM_CALL_TIMEOUT_SEC": "3600"}) == 3600


def test_the_default_tracks_the_output_budget() -> None:
    """Lower the output budget and the derived timeout follows it down, so the
    pair stays consistent however the operator sizes it."""
    small = _call_timeout({"VULTURE_LLM_MAX_OUTPUT_TOKENS": "2048"})
    large = _call_timeout({"VULTURE_LLM_MAX_OUTPUT_TOKENS": "32768"})
    assert small < large
    assert small >= 120, "never below the historical default — that would be a regression"


def test_a_nonsense_output_budget_does_not_produce_a_nonsense_timeout() -> None:
    for bad in ("0", "-1", "notanumber", ""):
        got = _call_timeout({"VULTURE_LLM_MAX_OUTPUT_TOKENS": bad})
        assert 120 <= got <= 3600, f"{bad!r} produced {got}s"


def test_the_go_margin_check_mirrors_the_same_default() -> None:
    """agent_proxy_service.go hardcodes the agent-side default to decide whether
    the shipped timeout margin is safe. If the two drift, the backend declares
    a configuration safe that is not — which is the exact failure its own
    comment documents (audit 3c168626, four agents truncated)."""
    import re
    from pathlib import Path

    go = (
        Path(__file__).resolve().parents[4]
        / "backend" / "internal" / "config" / "config.go"
    ).read_text(encoding="utf-8")
    m = re.search(r"DefaultLLMCallTimeoutSec\s*=\s*(\d+)", go)
    assert m, "the Go mirror constant is gone; the margin check cannot be right"
    assert int(m.group(1)) == _call_timeout({}), (
        f"Go mirrors {m.group(1)}s but the agent now defaults to {_call_timeout({})}s"
    )


def test_no_go_site_keeps_its_own_call_timeout_literal() -> None:
    """The mirror above pinned ONE Go constant while a SECOND, unpinned literal
    sat in config.go defaulting the broker to 120.

    That one mattered more: the Go broker sits between the agent and the
    provider, so its shorter deadline fired first and came back as
    `502 provider_unavailable` — a provider fault, not a timeout — and the
    agent's correct 439s budget never got the chance to apply. Measured live
    (audit cde171bd): broker egress deadline at exactly T+120s, LLM tier
    contributing 0 of 34 findings.

    One constant, referenced everywhere. A bare numeric fallback on
    VULTURE_LLM_CALL_TIMEOUT_SEC anywhere in the Go tree is the regression.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[4] / "backend"
    offenders = []
    for go_file in root.rglob("*.go"):
        if go_file.name.endswith("_test.go"):
            continue
        for line in go_file.read_text(encoding="utf-8").splitlines():
            if "VULTURE_LLM_CALL_TIMEOUT_SEC" not in line:
                continue
            # A numeric fallback argument, e.g. `..., 120)`. The canonical
            # spelling passes the named constant instead.
            if re.search(r',\s*\d+\s*\)', line):
                offenders.append(f"{go_file.relative_to(root)}: {line.strip()}")
    assert not offenders, (
        "Go sites defaulting VULTURE_LLM_CALL_TIMEOUT_SEC to a literal instead "
        "of config.DefaultLLMCallTimeoutSec:\n  " + "\n  ".join(offenders)
    )


# ── the LiteLLM path's per-call budget ──────────────────────────────────────
#
# Three places carry a per-call budget: the batch bound (audit_runner), the
# socket read (llm.broker) and the kwarg the SDK splats into litellm
# (provider.litellm_retry_extra_args). env.resolve_call_timeout exists so all
# three are ONE number — its own docstring says "Two numbers that must agree
# are one function" — but it named only two readers, and provider was the one
# left out, still hardcoding the historical 120.
#
# The provider path is not a corner: `litellm_retry_extra_args` returns {} when
# the broker is on, so this budget governs exactly the configuration
# docker-compose ships (`VULTURE_LLM_BROKER=off`) — most deployments. A 120s cut
# inside a 439s batch truncates every long answer, which is the defect 0093 was
# written to remove.


def _provider_call_timeout(raw: str | None) -> float:
    from shared.llm import provider

    prior = os.environ.get("VULTURE_LLM_CALL_TIMEOUT_SEC")
    try:
        if raw is None:
            os.environ.pop("VULTURE_LLM_CALL_TIMEOUT_SEC", None)
        else:
            os.environ["VULTURE_LLM_CALL_TIMEOUT_SEC"] = raw
        return provider._call_timeout_s()
    finally:
        if prior is not None:
            os.environ["VULTURE_LLM_CALL_TIMEOUT_SEC"] = prior
        else:
            os.environ.pop("VULTURE_LLM_CALL_TIMEOUT_SEC", None)


def test_provider_call_budget_uses_the_shared_resolver() -> None:
    from shared.llm.env import resolve_call_timeout

    for bad in (None, "0", "-5", "notanumber", ""):
        got = _provider_call_timeout(bad)
        assert got == float(resolve_call_timeout()), (
            f"{bad!r} gave {got}: the LiteLLM path must derive its budget from "
            f"the same resolver as the batch and the socket"
        )


def test_provider_call_budget_honours_an_explicit_setting() -> None:
    assert _provider_call_timeout("900") == 900.0


def test_all_three_call_budgets_are_the_same_number() -> None:
    """The regression that motivated this: on shipped defaults the provider
    path cut at 120s while the batch allowed 439s, so the tightest of the three
    bound — silently, and below the budget the other two had agreed on."""
    from shared.llm import broker, provider
    from shared.llm.env import resolve_call_timeout

    prior = os.environ.get("VULTURE_LLM_CALL_TIMEOUT_SEC")
    try:
        os.environ.pop("VULTURE_LLM_CALL_TIMEOUT_SEC", None)
        expected = float(resolve_call_timeout())
        assert expected > 120.0, (
            "non-vacuity: on defaults the derived budget must exceed the "
            "historical 120, or this test cannot detect the hardcode"
        )
        assert provider._call_timeout_s() == expected
        assert broker._client_timeout().read == expected
    finally:
        if prior is not None:
            os.environ["VULTURE_LLM_CALL_TIMEOUT_SEC"] = prior
