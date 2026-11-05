"""Access logging audit skill for SOC2."""

import re
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path
from typing import NamedTuple

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.line_context import mask_multiline, strip_strings_and_comments

LOGGING_PATTERNS = [
    re.compile(r"logging\.(info|warning|error|debug)\("),
    re.compile(r"logger\.(info|warning|error|debug)\("),
    re.compile(r"log\.(Info|Warn|Error|Debug|Printf)\("),
    re.compile(r"console\.(log|warn|error)\("),
    re.compile(r"audit.?log|AuditLog|audit_trail", re.IGNORECASE),
]

# Acting on an identity: always worth an audit record, wherever it happens.
_IDENTITY_ACTION_PATTERNS = [
    re.compile(r"def\s+(login|logout|authenticate|authorize)", re.IGNORECASE),
    re.compile(r"func\s+\w*(Login|Logout|Auth)\w*\("),
]
# Changing data: worth an audit record when it is done FOR someone, so a
# definition counts only with an actor in scope: a parameter naming one, or a
# body using one. Group 1 is the function's name; the parameter list, if any,
# opens right after it.
_DATA_ACTION_DEF = re.compile(r"\bdef\s+((?:create|update|delete)_\w*)[ \t]*")

# Every action shape the skill recognises.
AUTH_ACTION_PATTERNS = [*_IDENTITY_ACTION_PATTERNS, _DATA_ACTION_DEF]

# Parameter-name words that denote a principal, or the request/session that
# carries one. Concepts, not any framework's names; matched as whole words of a
# snake_case or camelCase name (`current_user`, `httpRequest`, `req`), also with
# a glued id/name suffix or plural (`username`, `userid`, `accounts`).
_ACTOR_WORDS = frozenset({
    "user", "principal", "actor", "session", "request", "req",
    "account", "identity", "ctx", "context", "caller",
})
# In a BODY, only the words naming a principal or the request that carries one
# (`self.request.user`, `current_user`, `g.user`): there `session`, `ctx` and
# `context` name a database or HTTP-client session and a TLS or library context
# as often as a caller's, and `account`/`identity` the record being changed or
# a matrix. Exact words, so a plural (`requests`, `users`) names a module or a
# table, not the caller.
_BODY_ACTOR_WORDS = frozenset({"user", "principal", "actor", "request", "req", "caller"})
# An identifier USED as a value: `request.user` and `self.request` name the
# caller, while a called `self._request(...)` or `client.request(...)` is a
# function that SENDS a request. Possessive, so no prefix of a called name
# matches in its place.
_USED_IDENTIFIER = re.compile(r"(?<!\w)[A-Za-z_]\w*+(?![ \t]{0,16}\()")
_NAME_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_GLUED_SUFFIX = re.compile(r"(?:name|ids?|s)$")
# `name`, `*args`, `**kwargs`; a bare `*` or `/` separator has no name.
_PARAM_NAME = re.compile(r"\s*(?:\*{1,2}\s*)?([A-Za-z_]\w*)")
_OPENERS, _CLOSERS = "([{", ")]}"
# A signature longer than this is read up to here; parameters come first.
_MAX_SIGNATURE_CHARS = 2000
# A parameter list never holds another definition, so reading stops at the next
# one: the windows of consecutive definitions then never overlap, and a file of
# unclosed `def create_x(` costs time linear in its size.
_NEXT_DEF = re.compile(r"\bdef\b")
# A one-line body (`def f(x): return x`) ends with its line, or the same way.
_END_OF_LINE_BODY = re.compile(r"\n|\bdef\b")


def check_access_logging(source_path: str) -> dict:
    """Check for proper access and audit logging.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of logging issues.
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
    """Analyze a file for access logging."""
    content = read_file_safe(file_path)
    site = _unlogged_action(content) if content else None
    if site:
        findings.append(_finding(file_path, *site))


def _unlogged_action(content: str) -> tuple[int, str] | None:
    """(line, what) of an action needing an audit record the file never writes.

    An identity action is file-level (line 1), as it always was; a data change
    is reported at its own definition.
    """
    if _matches_any(LOGGING_PATTERNS, content):
        return None
    if _matches_any(_IDENTITY_ACTION_PATTERNS, content):
        return 1, "auth actions"
    return _data_action_for_actor(content)


def _matches_any(patterns: list[re.Pattern[str]], content: str) -> bool:
    return any(p.search(content) for p in patterns)


def _line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


class _Layout(NamedTuple):
    """A file's code (strings and comments blanked) and its line structure,
    computed once so each definition is judged in near-constant time."""

    code: str
    starts: list[int]       # offset of each line's first character
    block_ends: list[int]   # per line: the line its indented block ends before
    actor_lines: list[int]  # prefix count: lines[:i] that use an actor word


def _data_action_for_actor(content: str) -> tuple[int, str] | None:
    """(line, what) of the first create/update/delete definition acting for an actor.

    A developer tool's ``update_snapshot(rules_dir, name, entry)`` acts for no
    one; ``delete_user(request, user_id)`` acts for whoever sent ``request``, and
    ``delete_item(self, item_id)`` for the ``self.request.user`` its body reads.
    Read with strings and comments blanked: a ``")"`` default does not close the
    parameter list, and a docstring that mentions a user is no actor.
    """
    if not _DATA_ACTION_DEF.search(content):
        return None
    layout = _layout(content)
    for match in _DATA_ACTION_DEF.finditer(layout.code):
        if _acts_for_actor(layout, match):
            return _line_of(layout.code, match.start()), f"a data change ({match.group(1)}) for a caller"
    return None


def _layout(content: str) -> _Layout:
    lines = list(map(strip_strings_and_comments, mask_multiline(content.split("\n"))))
    indents = [_indent(line) if line.strip() else None for line in lines]
    return _Layout(
        code="\n".join(lines),
        starts=list(accumulate((len(line) + 1 for line in lines[:-1]), initial=0)),
        block_ends=_block_ends(indents),
        actor_lines=list(accumulate(map(_body_names_actor, lines), initial=0)),
    )


def _block_ends(indents: list[int | None]) -> list[int]:
    """Per line, the next non-blank line indented no deeper (``len`` for none):
    where the block a line opens ends. One pass with a stack."""
    ends = [len(indents)] * len(indents)
    stack: list[int] = []
    for j in _non_blank(indents):
        while stack and indents[stack[-1]] >= indents[j]:
            ends[stack.pop()] = j
        stack.append(j)
    return ends


def _non_blank(indents: list[int | None]) -> list[int]:
    return [j for j, indent in enumerate(indents) if indent is not None]


def _acts_for_actor(layout: _Layout, match: re.Match[str]) -> bool:
    params, signature_end = _signature(layout.code, match.end())
    if any(map(_denotes_actor, _parameter_names(params))):
        return True
    return _body_uses_actor(layout, match.start(), signature_end)


def _signature(code: str, start: int) -> tuple[str, int]:
    """The parameter list opening at ``code[start]`` and the offset just past it;
    ``("", start)`` when no list opens there."""
    if code[start:start + 1] != "(":
        return "", start
    params = _bracketed(_signature_window(code, start))
    return params, start + len(params) + 2


def _parameter_names(params: str) -> list[str]:
    """Names of the parameters in ``params``, a parameter list's inside."""
    return [m.group(1) for m in map(_PARAM_NAME.match, _top_level_split(params)) if m]


def _signature_window(content: str, start: int) -> str:
    limit = start + _MAX_SIGNATURE_CHARS
    next_def = _NEXT_DEF.search(content, start, limit)
    return content[start:next_def.start() if next_def else limit]


def _body_uses_actor(layout: _Layout, def_start: int, signature_end: int) -> bool:
    """Whether the body uses an actor: the rest of the signature's line, then the
    lines indented deeper than the ``def`` (``self.request.user``, ``current_user``)."""
    def_line = bisect_right(layout.starts, def_start) - 1
    signature_line = bisect_right(layout.starts, signature_end) - 1
    end = _body_end(layout.block_ends, def_line, signature_line)
    in_body = layout.actor_lines[end] - layout.actor_lines[signature_line + 1]
    return in_body > 0 or _body_names_actor(_rest_of_line(layout.code, signature_end))


def _body_end(block_ends: list[int], def_line: int, signature_line: int) -> int:
    """The line the definition's body ends before. A signature closed on a line
    as shallow as the ``def`` (``) -> None:``) ends the ``def``'s own block
    there, so the body is the block that closing line opens."""
    end = block_ends[def_line]
    while end <= signature_line:
        end = block_ends[end]
    return end


def _rest_of_line(code: str, offset: int) -> str:
    limit = offset + _MAX_SIGNATURE_CHARS
    end = _END_OF_LINE_BODY.search(code, offset, limit)
    return code[offset:end.start() if end else limit]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _body_names_actor(text: str) -> bool:
    words = _NAME_WORDS.findall(" ".join(_USED_IDENTIFIER.findall(text)))
    return any(word.lower() in _BODY_ACTOR_WORDS for word in words)


def _bracketed(text: str) -> str:
    """The inside of the bracket group ``text`` opens with (all of it if unclosed)."""
    depth = 0
    for i, ch in enumerate(text):
        depth += (ch in _OPENERS) - (ch in _CLOSERS)
        if depth == 0:
            return text[1:i]
    return text[1:]


def _top_level_split(params: str) -> list[str]:
    """``params`` split at its top-level commas, so ``dict[str, Any]`` stays whole."""
    parts, depth, begin = [], 0, 0
    for i, ch in enumerate(params):
        depth += (ch in _OPENERS) - (ch in _CLOSERS)
        if ch == "," and depth == 0:
            parts.append(params[begin:i])
            begin = i + 1
    return [*parts, params[begin:]]


def _denotes_actor(name: str) -> bool:
    words = (_GLUED_SUFFIX.sub("", word.lower()) for word in _NAME_WORDS.findall(name))
    return any(word in _ACTOR_WORDS for word in words)


def _finding(file_path: Path, line_num: int, what: str) -> dict:
    return {
        "severity": "high",
        "check_id": "soc2.access_logging.missing_audit_log",
        "category": "CC6-access-logging",
        "title": "Missing audit logging for sensitive operations",
        "description": f"File {file_path.name} has {what} without audit logging",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Add structured audit logging for all auth and data operations",
    }


check_access_logging_tool = function_tool(check_access_logging)
