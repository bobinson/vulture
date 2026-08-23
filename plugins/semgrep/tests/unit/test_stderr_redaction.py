"""Semgrep stderr must not carry host detail into the SSE `result` event.

CodeQL py/stack-trace-exposure flagged `_classify_exit` returning 2KB of raw
Semgrep stderr, which reaches the user-facing audit stream through the `result`
event. Semgrep's stderr can carry absolute host paths, site-packages layout and
(if the operator mis-set it on the command line) token material.

The fix is REDACTION, not suppression. Two existing tests pin the opposing
requirement — a Semgrep failure must stay distinguishable from a clean scan
(test_exit_error_not_silent.py, test_wrapper.py::test_run_exit_code_2_includes_stderr)
— and that requirement is real: a bad `--project-root` flag once made every scan
fail. So the CLI diagnostic survives; the host detail around it does not, and the
untouched original still goes to the server log.
"""

import logging

from src.wrapper import _classify_exit, _parse_semgrep_stdout, _redact_stderr


def _proc(rc: int, stderr: str = "", stdout: str = ""):
    from types import SimpleNamespace

    return SimpleNamespace(returncode=rc, stderr=stderr, stdout=stdout)


class TestRedaction:
    def test_absolute_paths_reduced_to_basename(self):
        out = _redact_stderr("File /usr/local/lib/python3.12/site-packages/semgrep/core_runner.py line 8")
        assert "/usr/local/lib" not in out and "site-packages" not in out
        assert "core_runner.py" in out, "basename kept so the message stays diagnosable"

    def test_scanned_source_path_not_leaked(self):
        out = _redact_stderr("cannot read /home/alice/clients/acme-secret-project/src/app.ts")
        assert "alice" not in out and "acme-secret-project" not in out
        assert "app.ts" in out

    def test_token_material_removed(self):
        for s in ("SEMGREP_APP_TOKEN=abcdef1234567890abcdef", "api_key: sk-0123456789abcdefghij"):
            out = _redact_stderr(s)
            assert "abcdef1234567890abcdef" not in out and "sk-0123456789abcdefghij" not in out

    def test_cli_diagnostic_survives(self):
        out = _redact_stderr("No such option: --project-root")
        assert "--project-root" in out

    def test_url_not_mangled_into_a_path(self):
        out = _redact_stderr("see https://semgrep.dev/docs/cli-reference")
        assert "semgrep.dev" in out

    def test_empty_and_none_safe(self):
        assert _redact_stderr("") == ""
        assert _redact_stderr(None) == ""


class TestClassifyExit:
    def test_clean_exits_still_none(self):
        assert _classify_exit(_proc(0)) is None
        assert _classify_exit(_proc(1)) is None

    def test_failure_still_reports_and_is_redacted(self):
        payload = _classify_exit(_proc(2, stderr="No such option: --project-root (/home/bob/x.py)"))
        assert payload is not None and payload["error"]
        assert "--project-root" in payload["error"], "must stay distinguishable from a clean scan"
        assert "/home/bob" not in payload["error"]

    def test_full_stderr_goes_to_the_server_log(self, caplog):
        raw = "Traceback: /home/bob/secret/path/thing.py boom"
        with caplog.at_level(logging.ERROR):
            _classify_exit(_proc(2, stderr=raw))
        assert raw in caplog.text, "operator keeps the untouched detail server-side"

    def test_output_capped(self):
        payload = _classify_exit(_proc(2, stderr="A" * 9000))
        assert len(payload["error"]) <= 2000

    def test_auth_message_unchanged(self):
        payload = _classify_exit(_proc(7))
        assert "SEMGREP_APP_TOKEN" in payload["error"]


class TestParseError:
    def test_json_error_is_redacted_too(self):
        _, err = _parse_semgrep_stdout("{not json /home/bob/x.py")
        assert err and "/home/bob" not in err


class TestRedactorDoesNotOverreach:
    """The blob backstop must not eat ordinary code identifiers: an unreadable
    message would defeat the diagnosability this design exists to preserve."""

    def test_snake_case_identifiers_survive(self):
        out = _redact_stderr("in test_run_exit_code_2_includes_stderr at frame 3")
        assert "test_run_exit_code_2_includes_stderr" in out

    def test_dotted_rule_ids_survive(self):
        rule = "python.lang.security.audit.dangerous-subprocess-use-audit"
        assert rule in _redact_stderr(f"rule {rule} matched")

    def test_bare_secret_blob_still_caught(self):
        assert "A1b2C3d4E5f6G7h8I9j0" not in _redact_stderr("leaked A1b2C3d4E5f6G7h8I9j0 here")
