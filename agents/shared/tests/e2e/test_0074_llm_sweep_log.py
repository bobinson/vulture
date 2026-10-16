"""Feature 0074 T1.9 — one ``llm_sweep`` INFO line per run, through the real sweep.

The LLM sweep's sizing decisions (the per-batch source budget, the largest
batch actually sent, how many batches the encoded-body cap had to truncate,
the effective context window) were invisible after the fact: a run that sent
one oversized batch and a run that sent forty small ones logged the same. The
line is emitted once, when the sweep finishes, and is driven here through
``run_combined_audit`` with the network-free fake runner.
"""

from __future__ import annotations

import logging
import re

from shared.audit_runner import _get_max_source_chars, run_combined_audit
from shared.llm.provider import effective_context_window
from tests._fake_llm import FakeLLMProvider, install_fake_runner

_LINE = re.compile(
    r"^llm_sweep run_id=(?P<run>\S+) batches=(?P<batches>\d+) "
    r"files_sent=(?P<files>\d+) source_budget_chars=(?P<budget>\d+) "
    r"max_batch_chars=(?P<max_batch>\d+) body_truncations=(?P<trunc>\d+) "
    r"effective_window=(?P<window>\d+)$"
)


def _skill(_source_path: str) -> dict:
    return {"findings": []}


def _spy_batches(monkeypatch) -> list[str]:
    """Record the batch text of every per-batch call the sweep makes."""
    from shared import audit_runner

    sent: list[str] = []
    real = audit_runner._collect_llm_findings_async

    async def spy(*args, **kwargs):
        sent.append(kwargs.get("source_context", ""))
        return await real(*args, **kwargs)

    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", spy)
    return sent


def _sweep(monkeypatch, tmp_path, caplog, run_id: str) -> tuple[FakeLLMProvider, list[dict]]:
    fake = FakeLLMProvider(scripted_per_call=[[] for _ in range(20)])
    install_fake_runner(monkeypatch, fake)
    fake.sent = _spy_batches(monkeypatch)
    with caplog.at_level(logging.INFO, logger="shared.audit_runner"):
        list(run_combined_audit(
            run_id=run_id, source_path=str(tmp_path), categories=["x"],
            skill_map={"x": _skill}, skill_tools=["__dummy_tool__"],
            instructions="audit", model="gpt-4o", use_llm=True,
        ))
    lines = [_LINE.match(r.getMessage()) for r in caplog.records
             if r.getMessage().startswith("llm_sweep ")]
    return fake, [m.groupdict() if m else {} for m in lines]


def _small_budget(monkeypatch) -> None:
    monkeypatch.setenv("VULTURE_MAX_SOURCE_CHARS", "400")
    monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "2000")
    monkeypatch.setenv("VULTURE_LLM_TIER3", "on")


def test_one_sweep_line_with_the_sizing_facts(monkeypatch, tmp_path, caplog) -> None:
    _small_budget(monkeypatch)
    for i in range(4):
        (tmp_path / f"file{i}.py").write_text(
            f"# file {i}\n" + "\n".join(f"x{i}_{j} = {j}" for j in range(30)))
    fake, lines = _sweep(monkeypatch, tmp_path, caplog, "sweep-a")

    assert len(lines) == 1, f"exactly one llm_sweep line per run, got {lines!r}"
    line = lines[0]
    budget = _get_max_source_chars("gpt-4o")
    assert line["run"] == "sweep-a"
    assert int(line["batches"]) == fake.calls == 4
    assert int(line["files"]) == 4
    assert int(line["budget"]) == budget == 400
    # The largest batch actually SENT — which may exceed the budget: a single
    # file bigger than the budget still goes out as its own batch.
    assert int(line["max_batch"]) == max(len(t) for t in fake.sent) > 0
    assert int(line["trunc"]) == 0
    assert int(line["window"]) == effective_context_window("gpt-4o").effective == 2000


def test_body_truncations_count_batches_over_the_byte_cap(monkeypatch, tmp_path, caplog) -> None:
    """A multibyte batch packed under the CHAR budget can still exceed the
    encoded-byte ceiling; each such batch is one body truncation."""
    _small_budget(monkeypatch)
    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "300")
    (tmp_path / "wide.py").write_text("s = '" + "é" * 200 + "'\n", encoding="utf-8")
    (tmp_path / "ascii.py").write_text("x = 1\n", encoding="utf-8")
    _fake, lines = _sweep(monkeypatch, tmp_path, caplog, "sweep-b")

    assert len(lines) == 1 and lines[0], f"one parseable line, got {lines!r}"
    assert int(lines[0]["trunc"]) == 1
    assert int(lines[0]["budget"]) == 400  # the budget, before the byte clamp
