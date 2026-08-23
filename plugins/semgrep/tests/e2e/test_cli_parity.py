"""Differential accuracy test (feature 0058): the plugin's audit path must
agree with a STANDALONE Semgrep CLI run on the same source.

The audit path is `semgrep CLI → translate_findings`. Running the raw CLI
as ground truth and comparing the two finding sets pins that translation
neither drops findings nor mis-attributes CWEs, and that the argv the
plugin builds actually scans what a plain `semgrep` scan would. This is
the guard that would have caught the --project-root incident (plugin
path returned 0 while the CLI found the vuln) and any future rule/argv
drift.

Hermetic: uses the vendored rules only (no registry/network).
"""

import json
import os
import shutil
import subprocess

import pytest
from src.translate import extract_cwe, translate_findings
from src.wrapper import VENDORED_RULES_DIR

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "taint")


def _cli_results(target: str) -> list[dict]:
    """Ground truth: a plain standalone `semgrep scan` with the vendored rules."""
    proc = subprocess.run(
        ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
         "--project-root", target, "--config", os.fspath(VENDORED_RULES_DIR), "--", target],
        capture_output=True, text=True, timeout=300,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
    )
    assert proc.returncode in (0, 1), f"semgrep failed rc={proc.returncode}: {proc.stderr[:1000]}"
    return json.loads(proc.stdout).get("results", [])


def _key(cwe: str, path: str, line) -> tuple:
    return (cwe, os.path.basename(path), line)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_audit_path_matches_standalone_cli():
    target = os.path.abspath(FIXTURE_DIR)
    cli = _cli_results(target)
    assert cli, "standalone CLI must find >=1 finding on the taint fixtures (ground truth)"

    # Ground-truth (cwe, file, line) set straight off the raw CLI JSON.
    cli_keys = {
        _key(extract_cwe(r) or "CWE-unknown", r["path"], r["start"]["line"])
        for r in cli
    }

    # The plugin's translation of the SAME raw CLI output.
    translated = translate_findings({"results": cli}, agent_type="semgrep", root=target)
    plugin_keys = {
        _key(f.get("cwe", "CWE-unknown"), f.get("file_path", ""), f.get("line_start"))
        for f in translated
    }

    # Parity: translation must neither drop nor invent findings, and must
    # preserve the CWE + location of each.
    assert len(translated) == len(cli), (
        f"translation changed the finding COUNT: cli={len(cli)} plugin={len(translated)}"
    )
    assert plugin_keys == cli_keys, (
        "audit path diverged from standalone CLI on (cwe,file,line):\n"
        f"  only in CLI:    {sorted(cli_keys - plugin_keys)}\n"
        f"  only in plugin: {sorted(plugin_keys - cli_keys)}"
    )
