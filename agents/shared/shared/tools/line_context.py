"""Line-shape predicates shared by pattern-based skills.

Every detector that needed to ask "is this line a log statement / a type
declaration?" answered it locally or not at all, so the same defect was
rediscovered independently:

  * CWE-89 reported ``console.log(`Failed to insert ... ${x}`)`` as SQL injection
  * CWE-94 reported ``eval(script: string, ...)`` inside a TypeScript
    ``interface`` — a declaration, where nothing executes
  * ASVS V5.1.1 reported ``import x from '../a'`` as path traversal

`injection_check` already carried a one-off `_CMD_DEF_BEFORE` for the Ruby/PHP
``def system`` case. This module is that idea generalised, so the next detector
inherits it instead of rediscovering it.

SAFETY BIAS — read before using any of this as a skip.
`strip_strings_and_comments` comes from `validate.context_heuristics`, where the
documented bias is "a missed strip means an extra discharge, never a dropped
finding": in the validate layer a discharge only *supports* a finding, so
failing open is safe. Inside a DETECTOR that bias INVERTS — a missed strip
becomes a dropped finding. The implementation is line-based and does not track
multi-line strings or docstrings, so a template literal spanning lines is only
partially blanked.

Therefore: use these to compute EVIDENCE (veto, demote, corroborate), never as a
hard skip that can silently remove a finding.
"""
from __future__ import annotations

import functools
import re
from pathlib import Path

# Single-sourced with validate.context_heuristics, which imports them from here.
_STRING_LITERAL_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`[^`]*`")
_COMMENT_RE = re.compile(r"#.*$|//.*$|/\*.*?\*/")


def strip_strings_and_comments(line: str) -> str:
    """Blank string literals and strip comments, leaving code structure.

    Catches TRAILING comments, which ``COMMENT_INDICATORS`` structurally cannot
    (it is anchored at line start). Strings are blanked BEFORE comments are
    stripped, so the ``//`` inside a URL literal is not mistaken for a comment.

    Limitation, deliberate and tested: a literal opened on one line and closed on
    another is not tracked, so the opening line keeps its contents. See the
    module docstring — never use this as a hard skip.
    """
    line = _STRING_LITERAL_RE.sub('""', line)
    return _COMMENT_RE.sub("", line)


# A line whose purpose is to DISPLAY a value rather than execute it.
#
# The riskiest predicate here: log-injection detectors (CWE-117) exist precisely
# to examine log calls, so applying this in one of those would blind it. It is
# for detectors whose sink is something else (SQL, shell, filesystem).
#
# `logger`/`log` require a method call after the dot, so a mere definition
# (`const logger = makeLogger()`) is not diagnostic.
_DIAGNOSTIC_LINE = re.compile(
    r"console\s*\.\s*\w+\s*\("
    r"|\b(?:logger|log|winston|pino|logrus)\s*\.\s*"
    r"(?:trace|debug|info|warn|warning|error|fatal|log|print)\s*\("
    r"|\bSystem\s*\.\s*(?:out|err)\s*\.\s*print\w*\s*\("
    r"|\bthrow\s+new\s+\w*Error\s*\("
    r"|\braise\s+\w+\s*\("
    r"|(?<![\w.])print\s*\(|\bprintln!\s*\("
    r"|(?<![\w.])(?:i18n\s*\.\s*)?t\s*\(\s*[`'\"]"
    r"|(?<![\w.])(?:describe|it|expect)\s*\(",
    re.IGNORECASE,
)


def is_diagnostic_line(line: str) -> bool:
    """Whether the line consumes a value for display/diagnostics, not execution."""
    return bool(_DIAGNOSTIC_LINE.search(line))


# Text immediately preceding a match that means "this names a thing" rather than
# "this calls a thing". Generalises injection_check's `_CMD_DEF_BEFORE`.
_DECLARATION_BEFORE = re.compile(
    r"(?:\b(?:def|function|fn|func|sub)\s+$)"                 # def system( / function system(
    r"|(?:\b(?:declare|abstract|readonly|static|public|private|protected)\s+$)"
    r"|(?:^\s*$)"                                             # bare member line: `  eval(`
    r"|(?:[;{]\s*$)"                                          # after a member terminator
)

# A TS/Java-style typed signature: `name(arg: T, ...): Ret` — the parameter list
# carries type annotations and the call site would not.
_TYPED_SIGNATURE = re.compile(r"\w+\s*\([^)]*\w+\s*:\s*\w[\w<>\[\]|. ]*[,)]")


def is_declaration_context(line: str, match_start: int) -> bool:
    """Whether the match at ``match_start`` is a DECLARATION, not a call.

    Covers the shape that made CWE-94 fire on a Redis client interface::

        export interface AiRateLimitClient {
          eval(script: string, options: { keys: string[] }): Promise<unknown>;
        }

    ``eval`` there is a method being TYPED. Nothing executes.
    """
    before = line[:match_start]
    if _DECLARATION_BEFORE.search(before):
        # A bare/indented member line only counts as a declaration when the
        # signature is typed; otherwise `  eval("x")` at the start of a line
        # would be misread as a member.
        if _DECLARATION_BEFORE.search(before) and before.strip() in ("", "{", "}"):
            return bool(_TYPED_SIGNATURE.search(line)) or line.rstrip().endswith(";")
        return True
    return bool(_TYPED_SIGNATURE.search(line)) and line.rstrip().endswith(";")


@functools.lru_cache(maxsize=1024)
def _file_text(file_path: str) -> str:
    try:
        return Path(file_path).read_text(errors="ignore")
    except OSError:
        return ""


def file_has_sink(file_path: str | Path, sink_pattern: re.Pattern[str]) -> bool:
    """Whether ``sink_pattern`` appears anywhere in the file.

    Whole-file evidence for detectors whose sink may sit far from the match.
    Cached because a per-line caller would otherwise re-read the file once per
    line.
    """
    return bool(sink_pattern.search(_file_text(str(file_path))))
