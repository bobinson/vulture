"""Workspace / editor autorun detection — CWE-506 and CWE-829 (feature 0091 D2).

WHAT THIS EXISTS FOR. A repository can carry configuration that EXECUTES the
moment somebody opens the folder, before they run anything and before any code
review of the thing that ran. A VS Code task with ``"runOn": "folderOpen"`` is
the canonical instance; an IDEA shell run configuration, a devcontainer
lifecycle command and a Claude Code hook are the same shape. All of them live
inside directories the walker used to prune outright (``.vscode``, ``.idea``,
``.claude`` are in ``SKIP_DIRS``), so a scan of a project root reported nothing
about the single most dangerous thing the project could contain.

WHY IT IS DETERMINISTIC. The one time the reference incident WAS reported, it
came from the LLM tier — and an LLM-tier finding goes into the next scan's
prior-findings block, which tells the model to skip known issues. The model
complied, the finding vanished, its absence was read as repair and the lineage
row closed while the offending line sat in the file byte for byte. A skill's
finding is reproducible on every scan, never enters that suppression block, and
closes only when the pattern actually leaves the file.

ONE LIST, NEVER TWO. The file allowlist is :data:`WELL_KNOWN_AUTORUN_FILES` in
the walker. This module IMPORTS it and each rule declares which of its entries
it owns; ``test_every_autorun_file_has_a_rule`` pins that the rules' claims and
the walker's list are the same set, so un-pruning a new path cannot silently
land with no rule to read it.

CATEGORY SPLIT. The four rules whose trigger is "this executes because the
project was opened" emit **CWE-506** (embedded malicious code). The devcontainer
rules emit **CWE-829** (inclusion of functionality from an untrusted control
sphere): a lifecycle command provisions the workspace from an image, a registry
or a fetched install script that the developer does not control.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from shared.tools.file_scanner import (
    WELL_KNOWN_AUTORUN_FILES,
    autorun_rel_path,
    match_rel_pattern,
    read_file_lines,
    scan_autorun_files,
)

# The command text carried as `code_snippet`. Same per-line cap the snippet
# extractor and the L5 judge use, so a minified one-liner cannot blow a prompt.
_MAX_COMMAND_CHARS = 400

# --------------------------------------------------------------------------- #
# Shared detectors
# --------------------------------------------------------------------------- #

# Command substitution inside a value that the editor injects into every
# terminal it opens: `$(...)` or a backtick pair. A literal value is inert; a
# substituted one runs.
_COMMAND_SUBSTITUTION = re.compile(r"\$\(|`")

# Remote content fetched and piped straight into an interpreter. This is the
# CWE-829 shape proper: functionality arriving from outside the repository and
# being executed unreviewed.
_REMOTE_EXEC = re.compile(
    r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^|\n]*\|\s*"
    r"(?:sudo\s+)?(?:(?:ba|z|k|da)?sh|python\d?|node|perl|ruby)\b",
    re.IGNORECASE,
)

# An explicit shell-out from a hook script: an interpreter invoked with `-c`,
# or content evaluated at runtime.
_SHELL_OUT = re.compile(
    r"\b(?:ba|z|k|da)?sh\s+(?:-[A-Za-z]+\s+)*-c\b"
    r"|\b(?:pwsh|powershell|cmd(?:\.exe)?)\s+(?:-\w+\s+)*(?:-c|/c)\b"
    r"|\beval\b",
    re.IGNORECASE,
)

# The devcontainer lifecycle keys. Every one of them runs without a human
# asking for it; `initializeCommand` runs on the HOST, not in the container.
_DEVCONTAINER_HOOKS = (
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)

_TERMINAL_ENV_PREFIX = "terminal.integrated.env."

# `<command>` is an IDEA shell run configuration's command line; the two option
# names are how the same thing is spelled in a saved workspace.
_IDEA_AUTORUN = re.compile(
    r"<command[\s>]|name=\"(?:SCRIPT_TEXT|INTERPRETER_PATH)\"", re.IGNORECASE
)

# JSONC: VS Code, devcontainer and Claude settings files all legally carry `//`
# and `/* */` comments and trailing commas, and `json.loads` rejects all three.
_JSONC_NOISE = re.compile(
    r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.DOTALL,
)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    """Blank out `//` and `/* */` comments, leaving string literals intact."""
    return _JSONC_NOISE.sub(lambda m: m.group(0) if m.group(0)[0] == '"' else " ", text)


def _load_jsonc(lines: tuple[str, ...]) -> Any:
    """Parse a JSON-with-comments document, or ``None`` when it will not parse.

    A malformed workspace file is not a finding — it is a file this skill has
    nothing to say about — so every parse failure is silent.
    """
    try:
        return json.loads(_TRAILING_COMMA.sub(r"\1", _strip_jsonc("\n".join(lines))))
    except (ValueError, RecursionError):
        return None


def _line_of_key(lines: tuple[str, ...], key: str, used: set[int]) -> int:
    """1-based line of the next unclaimed occurrence of ``"key"``.

    Line numbers are recovered from the raw text rather than from the parsed
    document because a finding must cite the line that EXECUTES — the reference
    incident is `.vscode/tasks.json:7`, the `"command"` line — and JSON parsing
    discards positions. ``used`` makes a second task with a `"command"` land on
    its own line instead of re-citing the first.
    """
    needle = f'"{key}"'
    for index, line in enumerate(lines, start=1):
        if needle in line and index not in used:
            used.add(index)
            return index
    return 1


def _command_text(value: Any) -> str:
    """Flatten a command value — string, argv list, or named-command map."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return " ".join(_command_text(v) for v in value).strip()
    return _named_commands_text(value)


def _named_commands_text(value: Any) -> str:
    """A devcontainer named-command map runs its entries in PARALLEL, so `;`
    keeps them readable as separate commands rather than one long line."""
    if not isinstance(value, dict):
        return ""
    return " ; ".join(_command_text(v) for v in value.values()).strip()


def _finding(
    *,
    rule: str,
    category: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    file_path: Path,
    line: int,
    command: str,
) -> dict[str, Any]:
    """One autorun finding. ``code_snippet`` is the COMMAND, not a window: the
    thing a reviewer has to judge is the text that will run.

    ``category`` arrives as a LITERAL ``"CWE-N"`` from each rule rather than
    being composed here. The coverage extractor
    (`tests/corpus/report_coverage.py`) reads source text, not runtime values,
    so an f-string would make this whole skill invisible to the attestation —
    the exact defect called out in `configuration_check.py`.
    """
    return enrich_finding(
        {
            "severity": severity,
            "check_id": f"cwe.workspace_autorun.{rule}",
            "category": category,
            "title": title,
            "description": description,
            "file_path": str(file_path),
            "line_start": line,
            "line_end": line,
            "recommendation": recommendation,
            "code_snippet": command[:_MAX_COMMAND_CHARS],
        },
        category.removeprefix("CWE-"),
    )


# --------------------------------------------------------------------------- #
# Rule 1 — VS Code task that runs on folder open
# --------------------------------------------------------------------------- #


def _runs_on_folder_open(task: dict[str, Any]) -> bool:
    """`"runOn": "folderOpen"`, at the task or inside its ``runOptions``."""
    if str(task.get("runOn", "")).strip() == "folderOpen":
        return True
    options = task.get("runOptions")
    if not isinstance(options, dict):
        return False
    return "folderOpen" in {str(v).strip() for v in options.values()}


def _folder_open_tasks(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Every task in the document that VS Code starts by itself."""
    for task in data.get("tasks") or []:
        if isinstance(task, dict) and _runs_on_folder_open(task):
            yield task


def _scan_vscode_tasks(path: Path, lines: tuple[str, ...]) -> Iterator[dict[str, Any]]:
    """`.vscode/tasks.json` / `.vscode/launch.json`: a task VS Code executes by
    itself the moment the folder is opened."""
    data = _load_jsonc(lines)
    if not isinstance(data, dict):
        return
    used: set[int] = set()
    for task in _folder_open_tasks(data):
        command = _command_text(task.get("command")) or _command_text(task.get("args"))
        if not command:
            continue
        yield _finding(
            rule="vscode_task",
            category="CWE-506",
            severity="critical",
            title="VS Code task runs a command on folder open",
            description=(
                "This task declares `runOn: folderOpen`, so VS Code executes it "
                "automatically when the workspace is opened — before the command "
                f"has been read or approved by whoever opened it: {command!r}."
            ),
            recommendation=(
                "Remove `runOn: folderOpen` so the task only runs when a human "
                "starts it, or delete the task. Never let a repository decide "
                "what runs on a reviewer's machine."
            ),
            file_path=path,
            line=_line_of_key(lines, "command", used),
            command=command,
        )


# --------------------------------------------------------------------------- #
# Rule 2 — terminal environment carrying command substitution
# --------------------------------------------------------------------------- #


def _env_blocks(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key, value in data.items():
        if key.startswith(_TERMINAL_ENV_PREFIX) and isinstance(value, dict):
            yield value


def _substituted_env_values(data: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(name, value) for every terminal env entry that is evaluated, not literal."""
    for block in _env_blocks(data):
        for name, value in block.items():
            if isinstance(value, str) and _COMMAND_SUBSTITUTION.search(value):
                yield name, value


def _scan_vscode_env(path: Path, lines: tuple[str, ...]) -> Iterator[dict[str, Any]]:
    """`.vscode/settings.json`: `terminal.integrated.env.*` whose VALUE is
    substituted rather than literal, so it executes on every terminal open."""
    data = _load_jsonc(lines)
    if not isinstance(data, dict):
        return
    used: set[int] = set()
    for name, value in _substituted_env_values(data):
        yield _finding(
            rule="vscode_env",
            category="CWE-506",
            severity="high",
            title="Terminal environment variable executes a command",
            description=(
                f"`terminal.integrated.env` sets {name} to a value containing "
                f"command substitution ({value!r}). The shell evaluates it every "
                "time an integrated terminal is opened in this workspace."
            ),
            recommendation=(
                "Set the variable to a literal value, or drop it. A workspace "
                "setting must not be able to run code in the developer's shell."
            ),
            file_path=path,
            line=_line_of_key(lines, name, used),
            command=value,
        )


# --------------------------------------------------------------------------- #
# Rule 3 — IntelliJ / IDEA run configuration
# --------------------------------------------------------------------------- #


def _scan_idea_run_config(path: Path, lines: tuple[str, ...]) -> Iterator[dict[str, Any]]:
    """`.idea/runConfigurations/*.xml`, `.idea/workspace.xml`: a stored run
    configuration whose body is a shell command line."""
    for index, line in enumerate(lines, start=1):
        if not _IDEA_AUTORUN.search(line):
            continue
        command = line.strip()
        yield _finding(
            rule="idea_run_config",
            category="CWE-506",
            severity="high",
            title="IDE run configuration carries a shell command",
            description=(
                "A run configuration checked into the repository defines a shell "
                f"command line: {command!r}. It is offered — and with a saved "
                "'run on open' or startup task, executed — by the IDE of anyone "
                "who opens the project."
            ),
            recommendation=(
                "Do not commit run configurations that shell out. Move the step "
                "into a reviewed build script the developer invokes explicitly."
            ),
            file_path=path,
            line=index,
            command=command,
        )


# --------------------------------------------------------------------------- #
# Rule 4 — devcontainer lifecycle hooks
# --------------------------------------------------------------------------- #


def _scan_devcontainer(path: Path, lines: tuple[str, ...]) -> Iterator[dict[str, Any]]:
    """`.devcontainer/devcontainer.json`: a lifecycle command the container
    runtime executes without anyone asking."""
    data = _load_jsonc(lines)
    if not isinstance(data, dict):
        return
    used: set[int] = set()
    for hook in _DEVCONTAINER_HOOKS:
        command = _command_text(data.get(hook))
        if not command:
            continue
        yield _finding(
            rule="devcontainer_hook",
            category="CWE-829",
            severity="high",
            title=f"Devcontainer {hook} runs a command automatically",
            description=(
                f"`{hook}` executes {command!r} when the devcontainer is built, "
                "started or attached to. Nothing prompts the developer, and the "
                "command commonly provisions the workspace from outside the "
                "repository."
            ),
            recommendation=(
                "Pin what the hook installs to a reviewed, version-locked source, "
                "or remove the hook and document the setup step instead."
            ),
            file_path=path,
            line=_line_of_key(lines, hook, used),
            command=command,
        )


def _scan_devcontainer_script(
    path: Path, lines: tuple[str, ...]
) -> Iterator[dict[str, Any]]:
    """`.devcontainer/*.sh`: the script a lifecycle hook points at, fetching and
    executing remote content."""
    for index, line in enumerate(lines, start=1):
        if not _REMOTE_EXEC.search(line):
            continue
        yield _finding(
            rule="devcontainer_hook",
            category="CWE-829",
            severity="high",
            title="Devcontainer setup script executes remote content",
            description=(
                "This devcontainer script downloads content and pipes it into an "
                f"interpreter: {line.strip()!r}. Whatever the remote host serves "
                "at build time runs unreviewed."
            ),
            recommendation=(
                "Download to a file, verify a pinned checksum or signature, and "
                "only then execute it."
            ),
            file_path=path,
            line=index,
            command=line.strip(),
        )


# --------------------------------------------------------------------------- #
# Rule 5 — Claude Code hooks
# --------------------------------------------------------------------------- #


def _hook_commands(node: Any) -> Iterator[str]:
    """Every ``command`` string anywhere beneath a settings ``hooks`` block.

    The block's shape is nested and has changed across releases, so the walk is
    structural rather than keyed on a fixed path: a hook that runs is a hook
    that runs, whatever level it was written at.
    """
    if isinstance(node, list):
        for item in node:
            yield from _hook_commands(item)
    elif isinstance(node, dict):
        yield from _dict_hook_commands(node)


def _dict_hook_commands(node: dict[str, Any]) -> Iterator[str]:
    command = _command_text(node.get("command"))
    if command:
        yield command
    for key, value in node.items():
        if key != "command":
            yield from _hook_commands(value)


def _scan_claude_settings(path: Path, lines: tuple[str, ...]) -> Iterator[dict[str, Any]]:
    """`.claude/settings.json` / `settings.local.json`: a hook that shells out.

    A hook fires on the agent's own lifecycle events, so it runs without the
    developer starting anything — the same trigger class as `folderOpen`.
    """
    data = _load_jsonc(lines)
    if not isinstance(data, dict):
        return
    used: set[int] = set()
    for command in _hook_commands(data.get("hooks")):
        yield _finding(
            rule="claude_hook",
            category="CWE-506",
            severity="critical",
            title="Agent hook runs a shell command automatically",
            description=(
                f"A hook in this settings file executes {command!r} on an agent "
                "lifecycle event. Opening the project is enough to arm it."
            ),
            recommendation=(
                "Remove the hook, or restrict it to a reviewed script committed "
                "in the repository and audited like any other executable."
            ),
            file_path=path,
            line=_line_of_key(lines, "command", used),
            command=command,
        )


def _scan_claude_hook_script(
    path: Path, lines: tuple[str, ...]
) -> Iterator[dict[str, Any]]:
    """`.claude/hooks/*`: a hook script that shells out or fetches and runs
    remote content. A hook that only inspects its input is not a finding."""
    for index, line in enumerate(lines, start=1):
        if not (_REMOTE_EXEC.search(line) or _SHELL_OUT.search(line)):
            continue
        yield _finding(
            rule="claude_hook",
            category="CWE-506",
            severity="critical",
            title="Agent hook script shells out",
            description=(
                "This hook script runs automatically on an agent lifecycle event "
                f"and shells out: {line.strip()!r}."
            ),
            recommendation=(
                "Remove the hook or replace the shell-out with an inert check. "
                "Anything a hook runs, it runs unprompted."
            ),
            file_path=path,
            line=index,
            command=line.strip(),
        )


# --------------------------------------------------------------------------- #
# Rule table
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Rule:
    """One detector plus the WELL_KNOWN_AUTORUN_FILES entries it reads."""

    patterns: tuple[str, ...]
    scan: Callable[[Path, tuple[str, ...]], Iterator[dict[str, Any]]]


RULES: tuple[_Rule, ...] = (
    _Rule((".vscode/tasks.json", ".vscode/launch.json"), _scan_vscode_tasks),
    _Rule((".vscode/settings.json",), _scan_vscode_env),
    _Rule((".idea/runConfigurations/*.xml", ".idea/workspace.xml"), _scan_idea_run_config),
    _Rule((".devcontainer/devcontainer.json",), _scan_devcontainer),
    _Rule((".devcontainer/*.sh",), _scan_devcontainer_script),
    _Rule((".claude/settings.json", ".claude/settings.local.json"), _scan_claude_settings),
    _Rule((".claude/hooks/*",), _scan_claude_hook_script),
)

# Every pattern any rule claims. Pinned equal to the walker's allowlist by
# `test_every_autorun_file_has_a_rule`: un-pruning a path with no rule to read
# it would put the file in the scan set and still report nothing.
RULE_PATTERNS: frozenset[str] = frozenset(
    pattern for rule in RULES for pattern in rule.patterns
)


def _rules_for(rel_path: str) -> Iterator[_Rule]:
    for rule in RULES:
        if any(match_rel_pattern(rel_path, pat) for pat in rule.patterns):
            yield rule


def _scan_file(source_path: Path, path: Path) -> Iterator[dict[str, Any]]:
    # The rule is chosen from the SAME re-anchored path the walker used to
    # yield the file. Taking the plain root-relative path instead loses the
    # segment that names the rule whenever the scan stands inside the editor
    # directory (`.vscode/tasks.json` becomes `tasks.json`), and the file is
    # then read and owned by no rule — reported clean while the payload is
    # on disk.
    rel = autorun_rel_path(source_path, path)
    if not rel:
        return
    rules = list(_rules_for(rel))
    if not rules:
        return
    lines = read_file_lines(path)
    if not lines:
        return
    for rule in rules:
        yield from rule.scan(path, lines)


def check_workspace_autorun(source_path: str) -> dict[str, Any]:
    """Scan editor / IDE / devcontainer configuration for autorun commands."""
    root = Path(source_path)
    findings = [
        finding
        for path in scan_autorun_files(source_path)
        for finding in _scan_file(root, path)
    ]
    return {"findings": findings}


check_workspace_autorun_tool = function_tool(check_workspace_autorun)


__all__ = [
    "RULES",
    "RULE_PATTERNS",
    "WELL_KNOWN_AUTORUN_FILES",
    "check_workspace_autorun",
    "check_workspace_autorun_tool",
]
