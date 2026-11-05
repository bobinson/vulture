"""Change management audit skill for SOC2."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    SAFE_IMPORT_LINE,
    is_generated_file,
    is_non_code_line,
    is_prose_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.line_context import is_diagnostic_line
from shared.tools.snippet import extract_snippet

UNSAFE_DEPLOY_PATTERNS = [
    re.compile(r"git pull.*main|git pull.*master"),
    re.compile(r"ftp.*upload", re.IGNORECASE),
    re.compile(r"ssh.*deploy|manual.?deploy", re.IGNORECASE),
]

# rsync and scp as whole COMMANDS -- not the letters inside `readdirSync` or
# `mkdirSync` -- and case-sensitive, as the commands are. Whether one deploys is
# decided by its operands (below), not by the command name.
_COPY_COMMAND = re.compile(r"\b(?:rsync|scp)\b")

# An operand starts after whitespace, or a comma or bracket of a call/list form
# (`["rsync", "-a", src, f"{host}:/srv"]`), behind an optional quote and string
# prefix. Never after `=`: `--chown=www:www` is an option value, not a host.
_OPERAND_START = r"(?:^|(?<=[\s,(\[]))[fFrRbB]{0,2}[\"'`]?"
# A name filled in at run time: a shell or make variable (`$VAR`, `${VAR}`,
# `$(VAR)`, make's escaped `$$VAR`), a template or CI expression (`{{ host }}`,
# `${{ secrets.HOST }}`), or a format slot (`{name}`, `{}`, `%s`, `%(host)s`,
# Go's `%v`).
_PLACEHOLDER = (
    r"\${1,2}\{?\w{1,64}\}?"
    r"|\$\(\w{1,64}\)"
    r"|\$?\{\{[^{}\n]{1,128}\}\}"
    r"|\{\w{0,64}\}"
    r"|%(?:\(\w{1,64}\))?[sv]"
)
_QUOTE = r"[\"'`]?"
# A literal host, or a placeholder whose quote may close before the `:` or `@`
# (`"$USER"@"$HOST":/srv`). A literal is never quoted apart from its colon, so a
# JSON `"key":"value"` is no host.
_HOST = rf"(?:[\w.-]{{1,253}}|\[[0-9A-Fa-f:.]{{2,45}}\]|(?:{_PLACEHOLDER}){_QUOTE})"
_USER_AT = rf"(?:[\w.+-]{{1,64}}|(?:{_PLACEHOLDER}){_QUOTE})@{_QUOTE}"
# After a bare `host:` comes the path at once (`host:/srv`, `host::module`;
# `scheme://` is a URL), or nothing: the remote home directory, as `prod:` ending
# the command or followed only by options. A `key: value` pair, or an options
# object's `{ cwd: root }`, has a value after the space, so it is no host.
_AFTER_HOST = r":(?:(?!//)\S|(?=[ \t]*(?:$|-[-A-Za-z])))"
# A copy to ANOTHER HOST: `user@host:[path]`; `host:path`, `host::module` or
# `host:`; `rsync://`; a remote shell option (`-e ssh`, `-avze ssh`, `--rsh=`);
# or a value concatenated with a string that opens with the colon
# (`host + ":" + dest`, `host+":/srv"`). ReDoS: every run is bounded and the
# host arms are anchored to an operand start, so each start costs a bounded
# number of steps.
_REMOTE_TARGET = re.compile(
    rf"{_OPERAND_START}(?:{_USER_AT}{_HOST}:|{_HOST}{_AFTER_HOST})"
    r"|\brsync://"
    r"|(?:^|(?<=\s))(?:-[A-Za-z]{0,16}e|--rsh)(?=[\s=])"
    r"|[+.][ \t]{0,4}[\"'`]:(?!\s)",
)
# An operand that is ONE placeholder and nothing else (`"$TARGET"`, `"$DEST/"`,
# `${DEST}`, `$(DEST)`, or a bare name in a call/list form): it may hold a whole
# `user@host:path`, so the copy may be remote, but nothing says it is. A
# variable followed by more path (`"$STAGE/runtime/"`) names a directory.
_OPAQUE_OPERAND = re.compile(
    rf"(?:^|(?<=\s))([\"']?)(?:{_PLACEHOLDER})/?\1(?=[\s`]|$)"
    r"|(?<=[,(\[])[ \t]{0,8}[A-Za-z_]\w{0,64}[ \t]{0,8}(?=[,)\]])",
)
# A command ends at a shell control operator; `2>&1` cuts after the operands.
_CONTROL_OPERATOR = re.compile(r"[;&|]")
# The shell's display builtins: `echo "scp a.sh phone:~/"` prints an instruction
# for a person and runs nothing. (Print and log calls: `is_diagnostic_line`.)
_SHELL_DISPLAY = re.compile(r"\b(?:echo|printf)\b")
# Bounds on reading one command: its continuation lines, and its length.
_MAX_CONTINUATION_LINES = 32
_MAX_COMMAND_CHARS = 4096

# Quoted text, or a comment starting a word: `#` (shell, Python, YAML) or `//`
# (C family). Quoted text is matched first and KEPT -- a command's operands are
# usually quoted, and a `#` inside them is no comment -- and the word start
# keeps the `//` of `rsync://host/module` and shell's `$#`. ReDoS: each arm
# runs possessively to the end of the line at most, so a match is one pass.
_QUOTED_OR_COMMENT = re.compile(
    r"\"(?:[^\"\\\n]|\\.)*+\"?"
    r"|'[^'\n]*+'?"
    r"|(?:^|(?<=\s))(?:#|//)[^\n]*",
)


def check_change_management(source_path: str) -> dict:
    """Check for proper change management and deployment practices.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of change management issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        # Prose DESCRIBES a control; it is not an instance of one (F6).
        if is_prose_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for change management issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for idx in range(len(lines)):
        severity = _line_severity(lines, idx)
        if severity:
            findings.append(_finding(file_path, lines, idx + 1, severity))


def _line_severity(lines: list[str], idx: int) -> str | None:
    """Severity of the unsafe deployment practice on ``lines[idx]``, if any."""
    line = lines[idx]
    if is_non_code_line(line, SAFE_IMPORT_LINE):
        return None
    if any(p.search(line) for p in UNSAFE_DEPLOY_PATTERNS):
        return "medium"
    return _remote_copy_severity(lines, idx)


def _remote_copy_severity(lines: list[str], idx: int) -> str | None:
    """``medium`` for an rsync/scp to another host, ``low`` for one whose
    destination is a single variable, None for a local copy or no command.

    Read with comments removed (a comment is not a command) and with the
    command's backslash-continuation lines, where its operands often are.
    """
    rest = _executed_copy_rest(lines[idx])
    if rest is None:
        return None
    command = _command_text(rest, lines[idx + 1:idx + 1 + _MAX_CONTINUATION_LINES])
    if _REMOTE_TARGET.search(command):
        return "medium"
    return "low" if _OPAQUE_OPERAND.search(command) else None


def _executed_copy_rest(line: str) -> str | None:
    """The text after the rsync/scp command on ``line``, comment removed; None
    when there is no such command, or its statement only displays it."""
    # Most lines name neither command: strip comments only from those that do.
    code = _strip_comment(line) if _COPY_COMMAND.search(line) else ""
    match = _COPY_COMMAND.search(code)
    if match is None or _is_display(code[:match.start()]):
        return None
    return code[match.end():]


def _is_display(before: str) -> bool:
    """Whether the statement holding a command, read up to it, prints rather than runs it."""
    statement = _CONTROL_OPERATOR.split(before)[-1]
    return bool(_SHELL_DISPLAY.search(statement)) or is_diagnostic_line(statement)


def _command_text(rest: str, following: list[str]) -> str:
    """``rest`` of a command line, joined with its continuation lines, up to the
    first control operator."""
    parts = [rest]
    for line in following:
        if not parts[-1].rstrip().endswith("\\"):
            break
        parts.append(_strip_comment(line))
    joined = " ".join(p.rstrip().removesuffix("\\") for p in parts)
    return _CONTROL_OPERATOR.split(joined[:_MAX_COMMAND_CHARS], maxsplit=1)[0]


def _strip_comment(line: str) -> str:
    """``line`` without its comment; quoted text is kept."""
    return _QUOTED_OR_COMMENT.sub(_keep_quoted, line)


def _keep_quoted(match: re.Match[str]) -> str:
    text = match.group(0)
    return text if text[0] in "\"'" else ""


def _finding(file_path: Path, lines: list[str], line_num: int, severity: str) -> dict:
    description = (
        f"Manual/unsafe deployment at line {line_num}"
        if severity == "medium"
        else f"Copy at line {line_num} to a destination held in a variable, "
        "which may name a remote host"
    )
    return {
        "severity": severity,
        "check_id": "soc2.change_mgmt.unsafe_deploy",
        "category": "CC8-change-management",
        "title": "Unsafe deployment practice detected",
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use CI/CD pipelines with approval gates",
        "code_snippet": extract_snippet(lines, line_num),
    }


check_change_management_tool = function_tool(check_change_management)
