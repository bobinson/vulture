"""0074 P5 / T5.3 / AC19, AGENT HALF: flipping the re-anchor actuator loses no
LLM row at the agent-side collapse site.

Scope, stated plainly: the agent-side key (`_dedup_key`,
`(check_id or normalised title, path)`) carries NO line, so a re-anchor cannot
change what collapses here. The flip-invariance asserted below holds by
construction at this site. It is kept as an end-to-end sanity check that the
real parse choke point (`_verify_and_strip`) runs before the counted dedup, and
that the counters stay exact while lines move. The hazard the flip actually
creates, a re-anchored row landing on a skill row's line, lives at Go's
LINE-KEYED cross-agent key. That half is pinned in
backend/internal/handler/reanchor_flip_0074_test.go.

The counters (`llm_emitted`, `llm_collapsed_agent` on the `result` event, which
Go decodes as `ScanResult`) are P4's; their own unit tests and the result-parse
helpers live in tests/support/agent_run.py and are reused here.

Invariant, with REANCHOR off and then on:

    llm_emitted == (LLM rows in the result) + llm_collapsed_agent

Fixture: five synthetic LLM rows over one synthetic file:

  A  duplicate of a skill row (same check_id), cited on the wrong line
  B  unique, cited on the wrong line (its quote sits 15 lines lower)
  C  same title and file as B, different claimed line -> collides with B
  D  unique, cited on the right line
  E  unique, quoting text that is not in the file (`absent`)

so `llm_emitted == 5`, `llm_collapsed_agent == 2` and three LLM rows reach the
result, under both settings. Driven through `run_combined_audit` with the
network-free FakeLLMProvider.
"""

from __future__ import annotations

from typing import Any

import pytest

from shared.audit_runner import run_combined_audit
from tests._fake_llm import FakeLLMProvider, fake_finding, install_fake_runner
from tests.support.agent_run import DUMMY_TOOLS, llm_rows, result_payload

_HASH_LINE = 5
_EXEC_LINE = 27
_EVAL_LINE = 33
_LINES = {
    _HASH_LINE: "password_hash = hashlib.md5(raw_password).hexdigest()",
    _EXEC_LINE: "os.system('convert ' + request.args['file_name'])",
    _EVAL_LINE: "result_value = eval(request.form['expression_text'])",
}
_EXEC_TITLE = "Command injection via os.system"
_EXEC_CLAIM = 12  # row B's claimed line; its quote sits on _EXEC_LINE
_EMITTED = 5
_COLLAPSED_AGENT = 2


def _write_source(tmp_path) -> str:
    body = [f"filler_value_{i} = {i}" for i in range(1, 41)]
    for line, text in _LINES.items():
        body[line - 1] = text
    (tmp_path / "app.py").write_text("\n".join(body) + "\n")
    return str(tmp_path)


def _skill_rows(src: str):
    row = {"severity": "medium", "category": "CWE-328",
           "title": "Weak hash", "description": "md5 on a password",
           "file_path": f"{src}/app.py", "line_start": _HASH_LINE,
           "line_end": _HASH_LINE, "recommendation": "use a KDF",
           "check_id": "cwe.crypto.weak_hash"}

    def _skill(_source_path: str) -> dict:
        return {"findings": [dict(row)]}
    return _skill


def _llm_batch() -> list[dict[str, Any]]:
    """The five synthetic LLM rows (A-E in the module docstring)."""
    return [
        fake_finding(title="Weak hash", category="CWE-328", line_start=9,
                     line_end=9, check_id="cwe.crypto.weak_hash",
                     evidence_quote=_LINES[_HASH_LINE]),
        fake_finding(title=_EXEC_TITLE, category="CWE-78", line_start=_EXEC_CLAIM,
                     line_end=_EXEC_CLAIM, evidence_quote=_LINES[_EXEC_LINE]),
        fake_finding(title=_EXEC_TITLE, category="CWE-78", line_start=30,
                     line_end=30, evidence_quote=_LINES[_EXEC_LINE]),
        fake_finding(title="Eval of form input", category="CWE-95",
                     line_start=_EVAL_LINE, line_end=_EVAL_LINE,
                     evidence_quote=_LINES[_EVAL_LINE]),
        fake_finding(title="Hardcoded API token", category="CWE-798",
                     line_start=2, line_end=2,
                     evidence_quote="API_TOKEN = 'synthetic-not-in-file'"),
    ]


def _audit(tmp_path, monkeypatch, reanchor: str) -> dict[str, Any]:
    # The L5 judge builds its own OpenAI client (not Runner.run); keep it off
    # so no request can leave the process. T5.3 measures the GENERATE tier.
    monkeypatch.setenv("VULTURE_USE_VALIDATE_LLM", "false")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "enforce")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", reanchor)
    install_fake_runner(monkeypatch, FakeLLMProvider(scripted_per_call=[_llm_batch()]))
    src = _write_source(tmp_path)
    return result_payload(list(run_combined_audit(
        run_id=f"t53-{reanchor}", source_path=src, categories=["x"],
        skill_map={"x": _skill_rows(src)}, skill_tools=DUMMY_TOOLS,
        instructions="audit", model="gpt-4o", use_llm=True,
    )))


def _counter(result: dict[str, Any], name: str) -> int:
    assert name in result, (
        f"AC19: the agent must publish `{name}` on its result event "
        "(ScanResult) so Go can bucket the LLM tier"
    )
    return int(result[name])


def _buckets(result: dict[str, Any]) -> tuple[int, int, int]:
    return (_counter(result, "llm_emitted"),
            _counter(result, "llm_collapsed_agent"),
            len(llm_rows(result)))


@pytest.mark.parametrize(("reanchor", "exec_line"), [
    ("false", _EXEC_CLAIM),   # off: row B keeps its claim
    ("true", _EXEC_LINE),     # on: row B is moved onto its quote
])
def test_every_emitted_llm_row_is_kept_or_bucketed(tmp_path, monkeypatch, reanchor, exec_line):
    """AC19 / T5.3: count in == count out + collapsed, at the agent site, with
    the actuator off and on. A non-zero gap would be a silent loss.

    Both settings must land on the SAME bucket counts, so the flip moves no
    row between buckets — and the flip really did take effect (row B's line),
    so that equality is not vacuous."""
    result = _audit(tmp_path, monkeypatch, reanchor)
    emitted, collapsed, kept = _buckets(result)

    assert emitted == kept + collapsed, (
        f"REANCHOR={reanchor}: {emitted} emitted != {kept} kept + "
        f"{collapsed} collapsed_agent — an LLM row went missing"
    )
    assert (emitted, collapsed, kept) == (_EMITTED, _COLLAPSED_AGENT,
                                          _EMITTED - _COLLAPSED_AGENT)
    assert _exec_line(result) == exec_line, f"REANCHOR={reanchor} moved row B wrongly"


def _exec_line(result: dict[str, Any]) -> int:
    """Row B's final line."""
    (row,) = [f for f in llm_rows(result) if f["title"] == _EXEC_TITLE]
    return int(row["line_start"])
