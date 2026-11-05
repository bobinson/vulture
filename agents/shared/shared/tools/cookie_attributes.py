"""Cookie attributes: what counts as set, and the text a cookie call is judged on.

The CWE agent (CWE-1004 / 614 / 1275) and the ASVS agent (V3.3.4 / 3.3.1 /
3.3.2) ask the same three questions of the same calls, and each kept its own
copy of the answers. ASVS judged the call LINE alone, so a multi-line
``res.cookie(name, value, {httpOnly: true, ...})`` was reported whatever its
options said; both judged ``http.SetCookie(w, sessionCookie(r, token))`` on the
call alone, although ``sessionCookie``, defined in the same file, sets every
attribute. One module now holds the predicates and the context:

``cookie_context``
    The call's window -- two lines before it through the closing paren of a
    multi-line call, or the line and three lines after -- plus the definition
    of each routine of the same file that BUILDS the cookie: one called inside
    the call's own arguments (``sessionCookie(r, token)``), or one whose result
    a variable passed there was assigned just above (``c := strictCookie(t)``).
    The routine the call sits in, its neighbours and other calls nearby add
    nothing. A name with no definition in the file, or with more than one,
    adds nothing, so its call is judged on the window alone.

``SAFE_HTTPONLY`` / ``SAFE_SECURE`` / ``SAFE_SAMESITE``
    An attribute assigned a value other than a false literal (``Secure: https``,
    ``secure: req.secure``, ``setHttpOnly(true)``) is set; ``HttpOnly: false``
    is not. A cookie marked Secure only over HTTPS is the correct form. A
    SameSite enum member naming Strict or Lax (``http.SameSiteStrictMode``,
    ``SameSiteMode.Lax``) is Strict or Lax; None and Default stay unsafe.
"""
from __future__ import annotations

import re
import threading
from collections.abc import Sequence

from shared.tools.snippet import collect_scoped_body, find_block_close

# A value that switches the attribute OFF; anything else assigned sets it.
_NOT_FALSE = r"(?!(?:false|0|nil|none|null|undefined)\b)[\w.!(]"
# The attribute named as a key, a field or a setter: `Secure:`, `secure=`,
# `'secure' =>`, `cookie["secure"] =`, `c.Secure =`, `setSecure(`, `.secure(`,
# `SESSION_COOKIE_SECURE =`. A header string's `; Secure` flag stands alone.
_NAMED = r"(?:\b|(?<=_)|(?<=set)){name}"
_ASSIGNED = r"['\"]?\]?\s*(?:=>|[:=])\s*" + _NOT_FALSE
_CALLED_WITH = r"\s*\(\s*" + _NOT_FALSE


def _attribute(name: str) -> re.Pattern[str]:
    named = _NAMED.format(name=name)
    return re.compile(
        rf"{named}(?:{_ASSIGNED}|{_CALLED_WITH})|[;,]\s*{name}\b(?!['\"]?\s*[:=])",
        re.IGNORECASE,
    )


SAFE_HTTPONLY = _attribute("http_?only")

SAFE_SECURE = re.compile(rf"{_attribute('secure').pattern}|__Secure-|__Host-", re.IGNORECASE)

SAFE_SAMESITE = re.compile(
    # SameSite=None is present AND vulnerable, so presence alone never counts:
    # only a Strict or Lax value does, spelled or as an enum member.
    r"same[_-]?site['\"]?\s*[:=]\s*['\"]?(?:\w+\.){0,3}(?:same[_-]?site)?(?:strict|lax)(?:mode)?\b",
    re.IGNORECASE,
)

# A multi-line call is followed to its closing paren, at most this many lines.
_CALL_LINES = 12
# The call's arguments are read up to this many characters.
_ARGS_CHARS = 2000
# How far above the call a variable it passes is looked for, assigned from a routine.
_ASSIGN_LOOKBACK = 3
# Routines resolved per call, and lines read from each definition.
_MAX_ROUTINES = 4
_BODY_LINES = 40

_CALLED = re.compile(r"(?<![\w.$])([A-Za-z_$][\w$]{0,63})\s*\(")
_PASSED = re.compile(r"(?<![\w.$])([A-Za-z_$][\w$]{0,63})(?![\w$]|\s*[(.:])")
_DEFINITION = re.compile(
    r"^\s*(?:(?:export|default|async|static|public|private|protected|pub)\s+)*"
    r"(?:(?P<kw>func|def|function|fun|fn)\s*\*?\s*(?:\([^)]*\)\s*)?(?P<fn>[A-Za-z_$][\w$]*)\s*[(<]"
    r"|(?:const|let|var|val)\s+(?P<var>[A-Za-z_$][\w$]*)\s*(?::[^=]{0,80})?="
    r"\s*(?:async\s+)?(?:function\b|\(|[\w$]+\s*=>))"
)

# One file at a time per thread: its definition index, and the context of each
# cookie call already judged (the CWE agent asks three questions of one call).
# Keyed by the identity of the file's line sequence, which the slot holds, so a
# different file can never be answered from it.
_SLOT = threading.local()
_Index = dict[str, list[tuple[int, str]]]


def call_open(trigger: re.Match[str] | None) -> int | None:
    """The column just past a matched cookie call's opening paren; None when the
    trigger is no call (a `Set-Cookie:` header string)."""
    return trigger.end() if trigger and trigger.group().endswith("(") else None


def cookie_context(lines: Sequence[str], line_num: int, call_open: int | None = None) -> str:
    """The text a cookie call on ``line_num`` (1-based) is judged on.

    ``call_open`` is the column just past the call's opening paren; without it
    the call's arguments are unknown and only the window is read.
    """
    index, contexts = _file_state(lines)
    key = (line_num, call_open)
    if key not in contexts:
        contexts[key] = _context(lines, index, line_num, call_open)
    return contexts[key]


def _file_state(lines: Sequence[str]) -> tuple[_Index, dict[tuple[int, int | None], str]]:
    slot = getattr(_SLOT, "file", None)
    if slot is None or slot[0] is not lines:
        slot = (lines, _definitions(lines), {})
        _SLOT.file = slot
    return slot[1], slot[2]


def _definitions(lines: Sequence[str]) -> _Index:
    """name -> [(0-based header line, keyword)] for every routine defined in the file."""
    index: _Index = {}
    for i, line in enumerate(lines):
        m = _DEFINITION.match(line)
        if m:
            index.setdefault(m.group("fn") or m.group("var"), []).append((i, m.group("kw") or ""))
    return index


def _context(lines: Sequence[str], index: _Index, line_num: int, call_open: int | None) -> str:
    window = _call_window(lines, line_num)
    names = _builder_names(lines, line_num, call_open) if call_open is not None else []
    bodies = [body for body in (_definition_text(lines, index, n) for n in names) if body]
    return "\n".join([window, *bodies[:_MAX_ROUTINES]])


def _call_window(lines: Sequence[str], line_num: int) -> str:
    idx = line_num - 1
    end = min(len(lines), idx + 4)
    if lines[idx].count("(") > lines[idx].count(")"):
        end = max(end, find_block_close(lines, idx, "(", ")", _CALL_LINES))
    return "\n".join(lines[max(0, idx - 2):end])


def _builder_names(lines: Sequence[str], line_num: int, call_open: int) -> list[str]:
    """Routines that build the cookie: called in the arguments, or assigned to a
    variable the arguments pass, on the few lines above the call."""
    args = _arguments(lines, line_num, call_open)
    called = [m.group(1) for m in _CALLED.finditer(args)]
    above = lines[max(0, line_num - 1 - _ASSIGN_LOOKBACK):line_num - 1]
    assigned = [name for v in _PASSED.findall(args) if (name := _assigned_from(above, v))]
    return list(dict.fromkeys(called + assigned))


def _arguments(lines: Sequence[str], line_num: int, call_open: int) -> str:
    """The call's argument text, from ``call_open`` to its closing paren."""
    text = "\n".join(lines[line_num - 1:line_num - 1 + _CALL_LINES])[call_open:call_open + _ARGS_CHARS]
    depth = 1
    for i, ch in enumerate(text):
        depth += (ch == "(") - (ch == ")")
        if depth == 0:
            return text[:i]
    return text


def _assigned_from(above: Sequence[str], variable: str) -> str | None:
    """The routine whose result ``variable`` was last assigned in ``above``."""
    assignment = re.compile(rf"\b{re.escape(variable)}\s*:?=\s*([A-Za-z_$][\w$]{{0,63}})\s*\(")
    found = [m.group(1) for line in above if (m := assignment.search(line))]
    return found[-1] if found else None


def _definition_text(lines: Sequence[str], index: _Index, name: str) -> str:
    """The header and body of ``name``'s only definition in the file, else ""."""
    found = index.get(name, [])
    if len(found) != 1:
        return ""
    idx, keyword = found[0]
    body = collect_scoped_body(
        lines, idx + 1, brace_family=keyword != "def",
        max_body_lines=_BODY_LINES, search_window=2 * _BODY_LINES,
    )
    return "\n".join([lines[idx], *body])
