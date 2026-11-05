"""Feature 0074 — ``llm_sweep body_truncations`` counts every body actually cut.

Observed live: the broker answered 413 ``request_too_large``, the generate
path's size retry halved the request (``llm_body_truncated label=size_retry
... files_dropped=19``), and the run's single ``llm_sweep`` line still said
``body_truncations=0``. The count was a PREDICTION — "would this batch exceed
the byte cap?" — made before sending, so the cut that a provider size rejection
forces was invisible to it.

The contract: ``body_truncations`` is the number of request bodies the sweep
actually cut, whether to the encoded-byte cap before sending or by halving
after a provider size rejection. Every such cut is announced by exactly one
``llm_body_truncated`` warning, so the two must agree. Driven through
``run_combined_audit`` with the network-free fake runner.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from shared.audit_runner import run_combined_audit
from tests._fake_llm import FakeLLMProvider, install_fake_runner

_SWEEP = re.compile(r"^llm_sweep run_id=(?P<run>\S+) .*\bbody_truncations=(?P<trunc>\d+)\b")
_CUT = re.compile(r"^llm_body_truncated label=(?P<label>\S+) ")
# The broker's rendering of an upstream 413 (classified CONTEXT_OVERFLOW).
_REJECTION = "Error code: 413 - {'error': {'code': 'request_too_large', 'x_retriable': False}}"


class _RejectFirstCall(FakeLLMProvider):
    """The provider refuses the first request as too large, then answers."""

    def __init__(self) -> None:
        super().__init__(scripted_per_call=[[] for _ in range(20)])
        self.rejected: list[str] = []

    async def run(self, agent: Any, *, input: str = "", **kwargs: Any) -> Any:
        if not self.rejected:
            self.rejected.append(input)
            raise RuntimeError(_REJECTION)
        return await super().run(agent, input=input, **kwargs)


def _skill(_source_path: str) -> dict:
    return {"findings": []}


def _audit(monkeypatch, tmp_path, caplog, run_id: str) -> tuple[_RejectFirstCall, list[dict], list[str]]:
    fake = install_fake_runner(monkeypatch, _RejectFirstCall())
    with caplog.at_level(logging.INFO, logger="shared.audit_runner"):
        list(run_combined_audit(
            run_id=run_id, source_path=str(tmp_path), categories=["x"],
            skill_map={"x": _skill}, skill_tools=["__dummy_tool__"],
            instructions="audit", model="gpt-4o", use_llm=True,
        ))
    messages = [r.getMessage() for r in caplog.records]
    sweeps = [m.groupdict() for m in map(_SWEEP.match, messages) if m]
    cuts = [m["label"] for m in map(_CUT.match, messages) if m]
    return fake, sweeps, cuts


def _one_batch(monkeypatch) -> None:
    """Room for every file in ONE batch, so the first call carries them all."""
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "20000")
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "64000")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")


def _files(tmp_path, count: int, lines: int = 30) -> None:
    for i in range(count):
        (tmp_path / f"mod{i}.py").write_text(
            f"# module {i}\n" + "\n".join(f"value_{i}_{j} = {j}" for j in range(lines)))


def test_size_rejection_halving_is_a_body_truncation(monkeypatch, tmp_path, caplog) -> None:
    """No batch exceeds the byte cap, so nothing is cut before sending; the 413
    forces the one cut, and the sweep line must count it."""
    _one_batch(monkeypatch)
    _files(tmp_path, 6)
    fake, sweeps, cuts = _audit(monkeypatch, tmp_path, caplog, "sweep-413")

    assert fake.rejected, "the first request must have reached the provider and been refused"
    assert fake.calls == 1, "the halved request is retried exactly once and succeeds"
    assert cuts == ["size_retry"], f"the size retry is the only cut, got {cuts!r}"
    assert len(sweeps) == 1 and sweeps[0]["run"] == "sweep-413", sweeps
    assert int(sweeps[0]["trunc"]) == 1, (
        f"the size retry cut the request body, so body_truncations must be 1, "
        f"got {sweeps[0]['trunc']}")


def test_pre_send_cap_and_size_retry_are_both_counted(monkeypatch, tmp_path, caplog) -> None:
    """A multibyte batch over the byte cap is cut before sending AND the
    provider still refuses it: two real cuts, two counted."""
    _one_batch(monkeypatch)
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "3000")
    _files(tmp_path, 4, lines=20)
    (tmp_path / "wide.py").write_text("s = '" + "é" * 900 + "'\n", encoding="utf-8")
    fake, sweeps, cuts = _audit(monkeypatch, tmp_path, caplog, "sweep-both")

    assert fake.rejected and fake.calls >= 1
    assert "batch" in cuts and "size_retry" in cuts, f"both cut paths must fire, got {cuts!r}"
    assert len(sweeps) == 1, sweeps
    assert int(sweeps[0]["trunc"]) == len(cuts), (
        f"one body_truncation per llm_body_truncated warning: cuts={cuts!r} "
        f"line={sweeps[0]!r}")


def test_no_cut_counts_nothing(monkeypatch, tmp_path, caplog) -> None:
    """A run whose bodies are never cut reports zero, even with a rejection
    that left nothing to halve (the caller degrades instead of retrying)."""
    _one_batch(monkeypatch)
    (tmp_path / "tiny.py").write_text("x = 1\n")
    fake, sweeps, cuts = _audit(monkeypatch, tmp_path, caplog, "sweep-none")

    assert fake.rejected
    assert cuts == []
    assert len(sweeps) == 1 and int(sweeps[0]["trunc"]) == 0, sweeps
