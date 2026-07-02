"""Feature 0057 Phase 2 (P2a) — code_snippet redaction for secret-bearing CWEs.

TDD: these tests are the CONTRACT. They are written BEFORE the implementation
and MUST currently FAIL (RED) for the right reason — snippet redaction is not
yet built — never error out for unrelated import/setup reasons.

Business contract (plan §6, P2a / R7):

    For SECRET-BEARING findings (CWE-798 hardcoded creds, CWE-319 cleartext
    transmission, and the related cleartext-storage / plaintext-password CWEs),
    the secret VALUE in the finding's code_snippet is MASKED with a placeholder
    BEFORE it reaches the SSE `result` event and the DB `code_snippet` column.

    Redaction must:
      * remove the literal secret value from the snippet,
      * insert a recognisable placeholder (e.g. ``***REDACTED***``),
      * PRESERVE structure — keys / variable names, line numbers, line shape —
        so the finding stays useful for triage,
      * NOT touch non-secret findings (e.g. CWE-770, CWE-89) — their snippet
        survives verbatim.

The choke point is the snippet-finalisation step in run_combined_audit
(``_attach_code_snippet`` on ``all_findings``, audit_runner.py:1016), which runs
once on the merged skill+LLM finding list just before the validate stage and
before ``result_event`` — so BOTH the SSE result and the persisted DB row carry
the redacted form. Redaction must apply even when a skill already populated the
snippet itself (auth_check sets ``code_snippet`` directly), so it cannot be
gated behind the "missing snippet" back-fill branch.

All behaviour is exercised deterministically (no model / no network): the
secret-bearing finding is produced by a fake skill, LLM off. R9: the CI gate
never calls a live model.
"""

from __future__ import annotations

import json

from shared.audit_runner import run_combined_audit


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _parse_event(events: list[str], event_name: str) -> dict:
    for event in events:
        if f"event: {event_name}" in event:
            data_line = [ln for ln in event.split("\n") if ln.startswith("data:")][0]
            return json.loads(data_line[5:])
    raise AssertionError(f"no '{event_name}' event found in SSE output")


def _result_findings(events: list[str]) -> list[dict]:
    return _parse_event(events, "result")["findings"]


def _make_source(tmp_path, name: str, body: str) -> str:
    f = tmp_path / name
    f.write_text(body)
    return str(tmp_path)


def _skill_returning(findings: list[dict]):
    def _skill(_source_path: str) -> dict:
        return {"findings": [dict(f) for f in findings]}
    return _skill


# A placeholder substring the redactor must insert. We assert on the marker
# token rather than the exact wrapper so the implementation can pick the exact
# spelling (``***REDACTED***`` is the plan's example).
_REDACTION_MARKER = "REDACTED"

# The literal secret value that must NOT survive into the produced snippet.
_SECRET = "S3cr3t-Pa55w0rd!"


# --------------------------------------------------------------------------- #
# T (P2a) — secret value masked for secret-bearing CWEs
# --------------------------------------------------------------------------- #


class TestSecretBearingSnippetRedacted:
    """A CWE-798 / CWE-319 finding has its secret VALUE masked in code_snippet,
    while structure (keys, variable names, line numbers) is preserved."""

    def test_cwe798_hardcoded_secret_value_masked_when_snippet_backfilled(
        self, tmp_path, monkeypatch
    ):
        """The skill emits NO snippet; the central populator back-fills it from
        source — and the back-filled window for a CWE-798 finding is redacted."""
        body = (
            "import os\n"
            "def connect():\n"
            f'    password = "{_SECRET}"\n'   # line 3 — the offending secret
            "    return password\n"
        )
        src = _make_source(tmp_path, "config.py", body)

        skill = _skill_returning([{
            "severity": "critical",
            "category": "CWE-798",
            "check_id": "cwe.auth.hardcoded_cred",
            "title": "Hardcoded credentials detected",
            "description": "Possible hardcoded secret at line 3",
            "file_path": f"{src}/config.py",
            "line_start": 3,
            "line_end": 3,
            "recommendation": "Use a secrets manager",
            # deliberately NO code_snippet — back-filled by the populator
        }])

        events = list(run_combined_audit(
            run_id="redact-798-backfill",
            source_path=src,
            categories=["x"],
            skill_map={"x": skill},
            use_llm=False,
        ))

        f = next(
            f for f in _result_findings(events)
            if f["title"] == "Hardcoded credentials detected"
        )
        snippet = f.get("code_snippet", "")
        assert snippet, "secret-bearing finding must still carry a (redacted) snippet"

        # The secret value must be gone, replaced by a placeholder.
        assert _SECRET not in snippet, (
            f"secret value {_SECRET!r} must be masked in the snippet, got:\n{snippet}"
        )
        assert _REDACTION_MARKER in snippet, (
            f"a redaction placeholder must replace the secret, got:\n{snippet}"
        )
        # Structure preserved: the variable name / key and the line number stay.
        assert "password" in snippet, "variable/key name must be preserved"
        assert "3:" in snippet, "line numbers must be preserved in the snippet"

    def test_cwe798_secret_value_masked_when_skill_preset_snippet(
        self, tmp_path, monkeypatch
    ):
        """auth_check sets code_snippet itself (audit_runner choke point cannot
        rely on the missing-snippet back-fill branch). A CWE-798 finding that
        ARRIVES with a snippet already containing the secret must STILL be
        redacted at the finalisation choke point."""
        body = (
            "def login():\n"
            f'    api_key = "{_SECRET}"\n'   # line 2
            "    return api_key\n"
        )
        src = _make_source(tmp_path, "auth.py", body)

        preset_snippet = (
            "1: def login():\n"
            f'2:     api_key = "{_SECRET}"\n'
            "3:     return api_key"
        )
        skill = _skill_returning([{
            "severity": "critical",
            "category": "CWE-798",
            "check_id": "cwe.auth.hardcoded_cred",
            "title": "Hardcoded credentials detected",
            "description": "Possible hardcoded secret at line 2",
            "file_path": f"{src}/auth.py",
            "line_start": 2,
            "line_end": 2,
            "recommendation": "Use a secrets manager",
            "code_snippet": preset_snippet,   # skill already set the window
        }])

        events = list(run_combined_audit(
            run_id="redact-798-preset",
            source_path=src,
            categories=["x"],
            skill_map={"x": skill},
            use_llm=False,
        ))

        f = next(
            f for f in _result_findings(events)
            if f["title"] == "Hardcoded credentials detected"
        )
        snippet = f.get("code_snippet", "")
        assert _SECRET not in snippet, (
            "a pre-set snippet carrying the secret must also be redacted at the "
            f"finalisation choke point, got:\n{snippet}"
        )
        assert _REDACTION_MARKER in snippet, (
            f"a redaction placeholder must replace the secret, got:\n{snippet}"
        )
        assert "api_key" in snippet, "variable/key name must be preserved"

    def test_cwe319_cleartext_transmission_value_masked(self, tmp_path, monkeypatch):
        """CWE-319 (cleartext transmission) is also secret-bearing — the
        embedded credential / URL value is masked."""
        body = (
            "def send():\n"
            f'    url = "http://user:{_SECRET}@host/api"\n'   # line 2
            "    requests.get(url)\n"
        )
        src = _make_source(tmp_path, "net.py", body)

        skill = _skill_returning([{
            "severity": "high",
            "category": "CWE-319",
            "check_id": "cwe.cleartext.transmission",
            "title": "Cleartext transmission of sensitive data",
            "description": "Credentials sent over http at line 2",
            "file_path": f"{src}/net.py",
            "line_start": 2,
            "line_end": 2,
            "recommendation": "Use TLS",
        }])

        events = list(run_combined_audit(
            run_id="redact-319",
            source_path=src,
            categories=["x"],
            skill_map={"x": skill},
            use_llm=False,
        ))

        f = next(
            f for f in _result_findings(events)
            if f["title"] == "Cleartext transmission of sensitive data"
        )
        snippet = f.get("code_snippet", "")
        assert _SECRET not in snippet, (
            f"CWE-319 secret value must be masked, got:\n{snippet}"
        )
        assert _REDACTION_MARKER in snippet, (
            f"a redaction placeholder must replace the secret, got:\n{snippet}"
        )
        assert "2:" in snippet, "line numbers must be preserved"


# --------------------------------------------------------------------------- #
# Non-secret findings must be left intact (no over-redaction)
# --------------------------------------------------------------------------- #


class TestNonSecretSnippetUntouched:
    """A non-secret-bearing finding (CWE-770 resource exhaustion) keeps its
    snippet verbatim — string literals and assignment values are NOT masked."""

    def test_cwe770_snippet_not_redacted(self, tmp_path, monkeypatch):
        body = (
            "def handler(req):\n"
            '    label = "unbounded-loop"\n'    # line 2 — an ordinary literal
            "    while True:\n"                  # line 3 — the offending line
            "        process(req)\n"
        )
        src = _make_source(tmp_path, "svc.py", body)

        skill = _skill_returning([{
            "severity": "medium",
            "category": "CWE-770",
            "check_id": "cwe.resource.unbounded",
            "title": "Allocation without limits",
            "description": "Unbounded loop at line 3",
            "file_path": f"{src}/svc.py",
            "line_start": 3,
            "line_end": 3,
            "recommendation": "Bound the loop",
        }])

        events = list(run_combined_audit(
            run_id="nonsecret-770",
            source_path=src,
            categories=["x"],
            skill_map={"x": skill},
            use_llm=False,
        ))

        f = next(
            f for f in _result_findings(events)
            if f["title"] == "Allocation without limits"
        )
        snippet = f.get("code_snippet", "")
        assert snippet, "non-secret finding must carry its snippet"
        # The ordinary string literal in the window must survive verbatim —
        # redaction must NOT mask non-secret code.
        assert "unbounded-loop" in snippet, (
            f"non-secret literal must NOT be redacted, got:\n{snippet}"
        )
        assert _REDACTION_MARKER not in snippet, (
            f"non-secret findings must not have a redaction placeholder, got:\n{snippet}"
        )
        assert "while True" in snippet, "the offending code line must be present"
