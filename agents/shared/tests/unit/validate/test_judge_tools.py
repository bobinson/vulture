"""Feature 0072 P3b — the tool-equipped judge (T3.7–T3.9a, AC30, AC31).

The judge gains read-only tools; the tests pin the three properties that
make that safe:
  * confinement — model-controlled paths can never leave the source root;
  * AC31 — exhausting the tool budget yields "could not decide"
    (exploitable 0.5, no closure), never a verdict built on the partial
    view;
  * AC30 — a tool-run DEMOTION that cites no found construct loses its
    closure assertion: a fruitless search may not refute.
"""

from __future__ import annotations

import json

from shared.validate.judge_tools import (
    DEFAULT_MAX_TOOL_CALLS,
    JUDGE_TOOL_SPECS,
    JudgeToolExecutor,
)
from shared.validate.llm_judge import run_l5
from shared.validate.types import ValidateConfig
from shared.validate.voter import JUDGE_UNDECIDED

# ── executor confinement and bounds ────────────────────────────────────────


def test_read_file_outside_root_is_refused(tmp_path):
    (tmp_path / "inside.txt").write_text("secret-inside")
    ex = JudgeToolExecutor(str(tmp_path))
    out = ex.execute("read_file", json.dumps({"path": "/etc/passwd"}))
    assert out.startswith("Error:")
    out2 = ex.execute("read_file", json.dumps({"path": "../../../etc/passwd"}))
    assert out2.startswith("Error:")


def test_read_file_returns_numbered_lines(tmp_path):
    (tmp_path / "a.py").write_text("one\ntwo\nthree\n")
    ex = JudgeToolExecutor(str(tmp_path))
    out = ex.execute("read_file", json.dumps({"path": "a.py"}))
    assert "1: one" in out and "3: three" in out


def test_read_file_caps_the_span(tmp_path):
    (tmp_path / "big.py").write_text("\n".join(f"l{i}" for i in range(1, 1000)))
    ex = JudgeToolExecutor(str(tmp_path))
    out = ex.execute("read_file", json.dumps(
        {"path": "big.py", "start_line": 1, "end_line": 999}))
    assert len(out.splitlines()) <= 120


def test_read_file_rejects_oversize_file(tmp_path):
    """A model-chosen huge file must not be slurped whole into memory — the
    read honours the pipeline's size cap (read_file_lines returns None past
    MAX_FILE_SIZE) and returns an error instead of allocating it."""
    from shared.tools.file_scanner import MAX_FILE_SIZE
    (tmp_path / "huge.py").write_text("x = 1\n" * (MAX_FILE_SIZE // 3))  # > cap
    ex = JudgeToolExecutor(str(tmp_path))
    out = ex.execute("read_file", json.dumps({"path": "huge.py"}))
    assert out.startswith("Error:"), (
        "an over-cap file must be refused, not read whole into memory"
    )


def test_search_pattern_is_bounded_and_confined(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text("needle = 1\n" * 30)
    ex = JudgeToolExecutor(str(tmp_path))
    out = ex.execute("search_pattern", json.dumps({"pattern": "needle"}))
    assert len(json.loads(out)) <= 25
    bad = ex.execute("search_pattern", json.dumps(
        {"pattern": "root", "subdir": "/"}))
    assert bad.startswith("Error:")


def test_executor_never_raises_on_garbage():
    ex = JudgeToolExecutor("")
    assert ex.execute("read_file", "{not json").startswith("Error:")
    ex2 = JudgeToolExecutor("/nonexistent-root-xyz")
    assert isinstance(ex2.execute("unknown_tool", "{}"), str)


def test_the_tool_budget_is_a_fixed_value():
    """Was VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS. 4 is enough to read a span
    and search twice, which is the whole intended shape of the loop."""
    assert DEFAULT_MAX_TOOL_CALLS == 4


def test_the_env_gate_is_gone():
    """VULTURE_VALIDATE_LLM_TOOLS and VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS.

    The gate guarded a provider-compatibility failure the code already
    recovers from (`test_provider_rejecting_tools_falls_back_to_plain_judging`),
    and its cost was that the judge could not open a file on any run — the
    capability inversion this feature exists to repair. What replaces it is
    the fallback, not another switch, so the module must expose no gate at
    all: a re-introduced one would silently blind the judge again.
    """
    import shared.validate.judge_tools as jt

    assert not hasattr(jt, "tools_enabled")
    assert not hasattr(jt, "max_tool_calls")


# ── fake OpenAI client for the loop ────────────────────────────────────────


class _FakeFunction:
    def __init__(self, name, arguments):
        self.name, self.arguments = name, arguments


class _FakeToolCall:
    def __init__(self, tc_id, name, arguments):
        self.id = tc_id
        self.type = "function"
        self.function = _FakeFunction(name, arguments)


class _FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class _FakeChoice:
    def __init__(self, message):
        self.message = message
        self.finish_reason = "stop"


class _FakeResp:
    def __init__(self, message):
        self.choices = [_FakeChoice(message)]


class _FakeCompletions:
    def __init__(self, script, calls_log):
        self._script = script          # list of _FakeMessage to return in order
        self.calls = calls_log         # records each create() kwargs

    def create(self, **kw):
        self.calls.append(kw)
        if not self._script:
            return _FakeResp(_FakeMessage(content='{"verdicts":[]}'))
        return _FakeResp(self._script.pop(0))


class _FakeClient:
    def __init__(self, script, calls_log):
        self.chat = type("chat", (), {})()
        self.chat.completions = _FakeCompletions(script, calls_log)


def _wire_fake_client(monkeypatch, script, calls_log):
    monkeypatch.setattr(
        "shared.validate.llm_judge._get_client",
        lambda: _FakeClient(script, calls_log),
    )


def _finding(tmp_path):
    src = tmp_path / "handler.js"
    src.write_text("\n".join([
        "function update(req, res) {",
        "  db.update({ where: { id: req.params.id } })",   # line 2
        "}",
        "function guard(req) { return req.auth.ok }",       # line 4
    ]))
    return {
        "id": "f0", "severity": "high", "title": "IDOR",
        "file_path": "handler.js", "line_start": 2, "line_end": 2,
        "description": "d", "code_snippet": "2: db.update(...)",
        "check_id": "chk", "category": "CWE-639",
    }


def _cfg():
    return ValidateConfig(enable_l5=True, l5_model_override="test-model")


def _l5_check(finding):
    return next(c for c in finding["validation"]["checks"]
                if c["id"] == "llm_judge")


# ── the loop (through run_l5, tools enabled) ───────────────────────────────


def test_tool_call_then_verdict(monkeypatch, tmp_path):
    f = _finding(tmp_path)
    calls = []
    script = [
        _FakeMessage(tool_calls=[_FakeToolCall(
            "t1", "read_file",
            json.dumps({"path": "handler.js", "start_line": 1, "end_line": 4}))]),
        _FakeMessage(content=json.dumps({"verdicts": [{
            "id": "f0", "exploitable": 0.9, "window_sufficient": True,
            "evidence_line": 2, "reasoning": "raw params.id reaches the query",
        }]})),
    ]
    _wire_fake_client(monkeypatch, script, calls)
    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
    check = _l5_check(f)
    assert check["weight"] > 0
    assert check["extras"]["evidence_line"] == 2
    # The first request carried the tool schemas; the tool result reached
    # the second request as a tool-role message.
    assert calls[0].get("tools") == JUDGE_TOOL_SPECS
    roles = [m["role"] for m in calls[1]["messages"]]
    assert "tool" in roles


def test_ac31_budget_exhaustion_yields_undecided(monkeypatch, tmp_path):
    """A model that keeps asking for tools past the budget gets no verdict —
    every finding in the batch lands at 'could not decide', never at the
    claim the model would have made from its partial view."""
    f = _finding(tmp_path)
    calls = []
    def ask(i):
        return _FakeMessage(tool_calls=[_FakeToolCall(
            f"t{i}", "read_file", json.dumps({"path": "handler.js"}))])
    # Anchored to the constant, not a magic 10: the loop runs
    # range(DEFAULT_MAX_TOOL_CALLS + 2) turns and trips exhaustion once
    # calls_used reaches the budget, so DEFAULT_MAX_TOOL_CALLS + 1 asks is the
    # minimum that reaches it. Scripting from the constant keeps this test
    # honest if the budget ever changes -- a fixed 10 would silently stop
    # exercising exhaustion the moment the budget passed 9.
    script = [ask(i) for i in range(DEFAULT_MAX_TOOL_CALLS + 2)]
    _wire_fake_client(monkeypatch, script, calls)
    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
    # THE discriminator. Every assertion below is also satisfied when the
    # script merely runs out (the stub then returns an empty verdict list, the
    # finding gets no verdict, and it lands undecided for an unrelated reason),
    # so without this the test passed even with the budget raised to 100 —
    # where exhaustion is unreachable. Pinning the call count to the budget is
    # what ties the observed outcome to the mechanism the test names.
    assert len(calls) == DEFAULT_MAX_TOOL_CALLS + 1, (
        f"the loop must stop AT the budget: {len(calls)} calls for a budget of "
        f"{DEFAULT_MAX_TOOL_CALLS}"
    )
    check = _l5_check(f)
    assert check["result"] == JUDGE_UNDECIDED
    assert check["weight"] == 0.0
    assert "budget" in check["reason"].lower()
    assert check["extras"]["window_sufficient"] is None, (
        "exhaustion is a genuine could-not-decide; it must not assert closure"
    )


def test_ac30_uncited_tool_demotion_loses_closure(monkeypatch, tmp_path):
    """'I searched and found nothing' is an absence claim over a bounded
    search. A tool-run demotion citing no found construct must not carry the
    closure assertion that would let it override the deterministic tier."""
    f = _finding(tmp_path)
    calls = []
    script = [
        _FakeMessage(tool_calls=[_FakeToolCall(
            "t1", "search_pattern", json.dumps({"pattern": "sanitize"}))]),
        _FakeMessage(content=json.dumps({"verdicts": [{
            "id": "f0", "exploitable": 0.1, "window_sufficient": True,
            "evidence_line": None,
            "reasoning": "searched, found no use of the field anywhere",
        }]})),
    ]
    _wire_fake_client(monkeypatch, script, calls)
    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
    check = _l5_check(f)
    assert check["extras"]["window_sufficient"] is None


def test_ac30_cited_tool_demotion_keeps_closure(monkeypatch, tmp_path):
    f = _finding(tmp_path)
    # A deterministic finding would have the demotion suppressed anyway;
    # use a non-deterministic one so the honoured demotion is visible.
    f["provenance"] = "llm"
    f.pop("check_id")
    calls = []
    script = [
        _FakeMessage(tool_calls=[_FakeToolCall(
            "t1", "read_file", json.dumps({"path": "handler.js"}))]),
        _FakeMessage(content=json.dumps({"verdicts": [{
            "id": "f0", "exploitable": 0.1, "window_sufficient": True,
            "evidence_line": 4,
            "reasoning": "guard() pins the subject before the query",
        }]})),
    ]
    _wire_fake_client(monkeypatch, script, calls)
    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
    check = _l5_check(f)
    assert check["extras"]["window_sufficient"] is True
    assert check["extras"]["citation_class"] == "other_line"


def test_provider_rejecting_tools_falls_back_to_plain_judging(monkeypatch, tmp_path):
    """Enabling the flag against a provider that 400s on `tools=` must not
    kill L5 — the batch falls back to the tool-less call path."""
    f = _finding(tmp_path)

    class _RejectingCompletions:
        def __init__(self):
            self.calls = []

        def create(self, **kw):
            self.calls.append(kw)
            if "tools" in kw:
                raise RuntimeError("400: unknown parameter: tools")
            return _FakeResp(_FakeMessage(content=json.dumps({"verdicts": [{
                "id": "f0", "exploitable": 0.9, "reasoning": "x",
            }]})))

    comp = _RejectingCompletions()
    client = type("C", (), {})()
    client.chat = type("chat", (), {})()
    client.chat.completions = comp
    monkeypatch.setattr("shared.validate.llm_judge._get_client", lambda: client)

    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
    check = _l5_check(f)
    assert check["weight"] > 0, "fallback path must still produce the verdict"


def test_tools_are_offered_whenever_reads_can_be_confined(monkeypatch, tmp_path):
    """The inverse of the old default.

    This previously asserted the toolless call shape with the flag off, which
    was every run. The judge now gets its tools whenever there is a root to
    confine reads to, and the toolless shape survives for the case where
    there is none — a provider that rejects `tools=` is handled by the
    fallback instead (see
    `test_provider_rejecting_tools_falls_back_to_plain_judging`).
    """
    script = [_FakeMessage(content=json.dumps({"verdicts": [{
        "id": "f0", "exploitable": 0.9, "reasoning": "x"}]}))]

    with_root = []
    _wire_fake_client(monkeypatch, list(script), with_root)
    run_l5([_finding(tmp_path)], [[]], _cfg(), source_path=str(tmp_path))
    assert any("tools" in kw for kw in with_root), (
        "a confinable root is the only precondition for offering tools"
    )

    # A DIFFERENT finding: both halves judging the same one let the L5 verdict
    # cache short-circuit the second run_l5, so `no_root` stayed empty and the
    # assertion below passed vacuously over an empty list.
    other = _finding(tmp_path)
    other["id"] = "f1"
    other["line_start"] = (other.get("line_start") or 1) + 1
    no_root = []
    _wire_fake_client(monkeypatch, list(script), no_root)
    run_l5([other], [[]], _cfg(), source_path="")
    assert no_root, "the judge must actually have been called for this to mean anything"
    assert all("tools" not in kw for kw in no_root), (
        "with no root, reads cannot be confined, so no tools are offered"
    )
