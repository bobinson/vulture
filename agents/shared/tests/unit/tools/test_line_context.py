"""Shared line-context predicates (F5).

Every skill that needed to ask "is this line a log statement / a type
declaration / prose?" answered it locally or not at all, so the same defect
appeared independently in several detectors:

  * CWE-89 fired on ``console.log(`Failed to insert ... ${x}`)``
  * CWE-94 fired on ``eval(script: string, ...)`` inside a TypeScript
    ``interface`` — a declaration, nothing executes
  * ASVS V5.1.1 fired on ``import x from '../a'``

`injection_check` already carried a one-off `_CMD_DEF_BEFORE` for the Ruby/PHP
`def system` case; this module is that idea generalised so the next detector
does not have to rediscover it.

SAFETY BIAS — the reason these are helpers and not hard skips.
`strip_strings_and_comments` is moved verbatim from `validate/context_heuristics`,
where its documented bias is "a missed strip means an extra discharge, never a
dropped finding". In the validate layer a discharge only *supports* a finding.
Inside a DETECTOR that bias INVERTS: a missed strip becomes a dropped finding.
It is line-based and does not track multi-line strings, so callers must use it
to compute EVIDENCE (veto / demote), never as a hard skip. The multi-line case
is pinned below so the limitation is visible rather than folklore.
"""

from pathlib import Path

from shared.tools.file_scanner import (
    is_prose_file,
    is_story_file,
    is_type_declaration_file,
)
from shared.tools.line_context import (
    is_declaration_context,
    is_diagnostic_line,
    strip_strings_and_comments,
)

# ── strip_strings_and_comments ────────────────────────────────────────────


def test_blanks_string_literals_but_keeps_code():
    out = strip_strings_and_comments('db.query("SELECT * FROM t")')
    assert "SELECT" not in out, "string contents must be blanked"
    assert "db.query(" in out, "the call itself must survive"


def test_blanks_template_literals():
    out = strip_strings_and_comments("const q = `DROP TABLE x`;")
    assert "DROP" not in out


def test_strips_trailing_line_comment():
    """COMMENT_INDICATORS is anchored at line start, so it structurally cannot
    see a TRAILING comment. This is the gap that helper leaves."""
    out = strip_strings_and_comments("doWork();  // TODO: DELETE FROM users")
    assert "DELETE" not in out
    assert "doWork()" in out


def test_url_inside_a_string_does_not_eat_the_line():
    """The `//` of a URL lives inside a string literal, which is blanked first,
    so the comment rule never sees it."""
    out = strip_strings_and_comments('fetch("https://example.com/a") ; call()')
    assert "call()" in out


def test_multiline_literal_is_a_documented_limitation():
    """A template literal opened on one line and closed on a later one cannot be
    handled line-by-line: the opening line keeps an UNBALANCED backtick and its
    contents are NOT blanked. Pinned so callers never mistake this for a hard
    skip they can rely on."""
    opening = "const q = `SELECT * FROM users"
    out = strip_strings_and_comments(opening)
    assert "SELECT" in out, (
        "an unterminated literal is NOT stripped — this is the documented "
        "failure mode, and why this helper may only produce evidence"
    )


# ── is_diagnostic_line ────────────────────────────────────────────────────


def test_diagnostic_lines_detected():
    for line in [
        'console.error("boom", e)',
        "console.log(`x ${y}`)",
        "logger.warn('careful')",
        "log.debug('x')",
        'System.out.println("x")',
        "throw new Error(`bad ${x}`)",
        "raise ValueError('bad')",
        "print('hello')",
    ]:
        assert is_diagnostic_line(line), line


def test_real_sinks_are_not_diagnostic():
    """The single riskiest helper: if this over-matches, log-injection
    detectors (CWE-117), which need log lines, go blind."""
    for line in [
        "db.query(`SELECT * FROM t WHERE id = ${id}`)",
        "res.send(payload)",
        "fs.readFile(p, cb)",
        "await hasuraRunSql(sql)",
        "const logger = makeLogger()",   # a definition, not a call
        "loggerFactory(config)",         # not logger.*
    ]:
        assert not is_diagnostic_line(line), line


# ── is_declaration_context ────────────────────────────────────────────────


def test_type_and_interface_members_are_declarations():
    for line, needle in [
        ("  eval(script: string, options: { keys: string[] }): Promise<unknown>;", "eval("),
        ("  abstract exec(cmd: string): void;", "exec("),
        ("  declare function evalX(s: string): void;", "evalX("),
        ("  readonly open(path: string): FileHandle;", "open("),
    ]:
        idx = line.index(needle)
        assert is_declaration_context(line, idx), line


def test_real_calls_are_not_declarations():
    for line, needle in [
        ('  eval("dangerous")', "eval("),
        ("  const r = eval(x)", "eval("),
        ("  if (cond) eval(y)", "eval("),
        ("  return exec(cmd)", "exec("),
    ]:
        idx = line.index(needle)
        assert not is_declaration_context(line, idx), line


def test_function_definition_still_recognised():
    """Generalises injection_check's one-off `_CMD_DEF_BEFORE` (Ruby `def
    system`, PHP `function system`)."""
    for line, needle in [("def system(cmd)", "system("), ("function system($c)", "system(")]:
        idx = line.index(needle)
        assert is_declaration_context(line, idx), line


# ── file_scanner predicates ───────────────────────────────────────────────


def test_type_declaration_file_by_name_not_suffix():
    """Path.suffix of `api.d.ts` is only `.ts`, so the check must look at the
    NAME."""
    assert is_type_declaration_file(Path("api.d.ts"))
    assert is_type_declaration_file(Path("x/y/global.d.mts"))
    assert not is_type_declaration_file(Path("api.ts"))
    assert not is_type_declaration_file(Path("d.ts"))


def test_story_file_detection():
    assert is_story_file(Path("Button.stories.tsx"))
    assert is_story_file(Path("Card.story.jsx"))
    assert is_story_file(Path("src/stories/Thing.tsx"))
    assert not is_story_file(Path("Button.tsx"))


def test_prose_file_unchanged():
    """Guard the pre-existing predicate the new ones sit beside."""
    assert is_prose_file(Path("README.md"))
    assert not is_prose_file(Path("main.py"))
