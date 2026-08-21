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
    max_tool_calls,
    tools_enabled,
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


def test_budget_env_parsing(monkeypatch):
    monkeypatch.delenv("VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS", raising=False)
    assert max_tool_calls() == DEFAULT_MAX_TOOL_CALLS
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS", "7")
    assert max_tool_calls() == 7
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS", "0")
    assert max_tool_calls() == DEFAULT_MAX_TOOL_CALLS
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS", "banana")
    assert max_tool_calls() == DEFAULT_MAX_TOOL_CALLS


def test_tools_are_off_by_default(monkeypatch):
    monkeypatch.delenv("VULTURE_VALIDATE_LLM_TOOLS", raising=False)
    assert tools_enabled() is False


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
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TOOLS", "true")
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
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TOOLS", "true")
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_MAX_TOOL_CALLS", "2")
    f = _finding(tmp_path)
    calls = []
    ask = lambda i: _FakeMessage(tool_calls=[_FakeToolCall(
        f"t{i}", "read_file", json.dumps({"path": "handler.js"}))])
    # Asks for tools forever; after the budget the loop must stop on its own.
    script = [ask(i) for i in range(10)]
    _wire_fake_client(monkeypatch, script, calls)
    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
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
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TOOLS", "true")
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
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TOOLS", "true")
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
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TOOLS", "true")
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


def test_tools_disabled_keeps_the_legacy_call_shape(monkeypatch, tmp_path):
    monkeypatch.delenv("VULTURE_VALIDATE_LLM_TOOLS", raising=False)
    f = _finding(tmp_path)
    calls = []
    script = [_FakeMessage(content=json.dumps({"verdicts": [{
        "id": "f0", "exploitable": 0.9, "reasoning": "x"}]}))]
    _wire_fake_client(monkeypatch, script, calls)
    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))
    assert all("tools" not in kw for kw in calls), (
        "with the flag off, the call shape must be byte-identical to pre-P3b"
    )
