"""The masked code view: what it blanks, what it keeps, and what it costs.

A rule that reads this view instead of the raw line cannot report a call named
in a comment, a docstring or a message string. The other half of the contract
matters more: inside a detector an over-blanked call is a DROPPED finding, so
every lexeme a naive lexer misreads (a regex literal holding a quote, a JSX
apostrophe, nested template literals, a URL in an unlexed language) is pinned
here as staying visible.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

from shared.language import _LANGUAGE_BY_BASENAME, _LANGUAGE_BY_EXT
from shared.tools import code_view
from shared.tools.code_view import CodeView, mask_non_code, masks


def _lines(text: str, language: str) -> list[str]:
    out = mask_non_code(text, language)
    assert len(out) == len(text), "the view must keep every column"
    assert out.count("\n") == text.count("\n"), "the view must keep every line"
    return out.split("\n")


def test_every_detected_language_has_an_explicit_row() -> None:
    names = {*_LANGUAGE_BY_EXT.values(), *_LANGUAGE_BY_BASENAME.values(), "unknown"}
    assert names == set(code_view._SYNTAX), "a language without a row would be masked by accident or not at all"


@pytest.mark.parametrize("language", ["java", "shell", "html", "unknown", "markdown"])
def test_a_language_without_a_lexer_is_not_masked(language: str) -> None:
    text = 'a = "eval(x)" // eval(y) # eval(z) `eval(w)`'
    assert not masks(language)
    assert mask_non_code(text, language) == text


# ── what is blanked ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("language", "text", "expected"),
    [
        ("python", 'x = 1  # eval(x)', 'x = 1           '),
        ("python", 'y = "eval(a)"; eval(b)', 'y = "       "; eval(b)'),
        ("python", "r'\\d+eval(' + s", "r'        ' + s"),
        ("javascript", 'f(x); // eval(x)', 'f(x);           '),
        ("javascript", 'const y = x; /* eval(x) */ return y;', 'const y = x;               return y;'),
        ("javascript", 'const help = `call eval(x)`;', 'const help = `            `;'),
        ("go", 'x := `C:\\`; y := "eval"', 'x := `   `; y := "    "'),
        ("go", "r := '\"'; s := \"a\"", "r := ' '; s := \" \""),
        ("ruby", "'eval(x)' # eval(y)", "'       '          "),
        ("php", '<?php $a = "eval(b)"; // eval(d)', '<?php $a = "       ";           '),
        ("php", "<?php # eval(c)", "<?php          "),
        ("php", "<?php // eval(c) ?> <p>x</p>", "<?php            ?> <p>x</p>"),  # `?>` ends the comment
    ],
)
def test_comments_and_literal_text_are_blanked(language: str, text: str, expected: str) -> None:
    assert _lines(text, language) == [expected]


def test_php_heredoc_and_multiline_strings_are_blanked() -> None:
    text = "<?php\n$h = <<<'TXT'\neval(a)\nTXT;\n$s = \"x\neval(b)\";\neval(c);"
    out = "\n".join(_lines(text, "php"))
    assert "eval(a)" not in out and "eval(b)" not in out and "eval(c)" in out


def test_a_docstring_spanning_lines_is_blanked() -> None:
    text = '"""Helpers.\n\nexec(compile(...)) invocations.\n"""\nexec(code)'
    assert _lines(text, "python") == ['"""        ', "", " " * 31, '"""', "exec(code)"]


def test_a_template_literal_spanning_lines_is_blanked() -> None:
    text = "const s = `\neval(x)\n`;\neval(y);"
    assert _lines(text, "javascript") == ["const s = `", "       ", "`;", "eval(y);"]


# ── what stays code ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("language", "text", "kept"),
    [
        ("python", 'f"result: {eval(expr)}"', "eval(expr)"),
        ("python", "f'{d[\"k\"]} {eval(e)}'", "eval(e)"),           # 3.12 nested same quotes
        ("python", 'f"""\n{eval(e)}\n"""', "eval(e)"),
        ("python", 'f"{x:>{eval(w)}}"', "eval(w)"),                  # a field in a format spec
        ("python", 't"{eval(e)}"', "eval(e)"),                       # 3.14 template string
        ("javascript", "res.send(`result: ${eval(req.query.x)}`);", "eval(req.query.x)"),
        ("javascript", "return `${a ? `x` : eval(y)}`;", "eval(y)"),  # nested template
        ("javascript", "`${ {a: 1}[eval(k)] }`", "eval(k)"),          # braces inside a field
        ("ruby", '"result: #{eval(params[:x])}"', "eval(params[:x])"),
        ("python", "a // 2 if eval(y) else 0", "eval(y)"),           # `//` is no Python comment
        ("python", "label = \"it's\"; eval(code)", "eval(code)"),
    ],
)
def test_interpolated_and_plain_code_stays(language: str, text: str, kept: str) -> None:
    assert kept in "\n".join(_lines(text, language))


@pytest.mark.parametrize(
    ("language", "text", "blanked"),
    [
        ("python", '"${eval(y)}"', "eval"),        # no f prefix: not a field
        ("python", 'f"{{eval(y)}}"', "eval"),      # `{{` is a literal brace
        ("ruby", "'#{eval(y)}'", "eval"),          # single quotes do not interpolate
        ("javascript", '"${eval(y)}"', "eval"),    # only templates interpolate
    ],
)
def test_text_that_only_looks_interpolated_is_blanked(language: str, text: str, blanked: str) -> None:
    assert blanked not in "\n".join(_lines(text, language))


# ── mis-read lexemes stay visible (the safety bias) ──────────────────────────


@pytest.mark.parametrize(
    ("language", "text", "kept"),
    [
        # a quote inside a regex literal opens no string
        ("javascript", 's = s.replace(/"/g, "&quot;"); eval(code);', "eval(code)"),
        # `\/*` inside a regex literal opens no block comment
        ("javascript", 'p = p.replace(/^\\/*/, "");\neval(x);', "eval(x)"),
        ("javascript", "s.split(/\\/\\//); eval(x)", "eval(x)"),
        ("javascript", "s.split(/`/); eval(x)", "eval(x)"),
        # a JSX apostrophe never closes on its line, so it hides nothing
        ("javascript", "return <p>Don't {eval(code)}</p>;", "eval(code)"),
        # a JSX closing tag is no regex literal
        ("javascript", '<a href="/x">{t}</a> <b>{eval(z)}</b>', "eval(z)"),
        # a PHP 8 attribute is no comment
        ("php", '<?php #[Route("/x")] function f($x) { eval($x); }', "eval($x)"),
        # markup outside `<?php ... ?>` is never lexed, a heredoc ends at its terminator,
        # and a PHP string may span lines
        ("php", "<p>Upload to /uploads/*</p>\n<?php eval($x); ?>\n<?php /** x */ ?>", "eval($x)"),
        ("php", "<?php\n$h = <<<TXT\nclean /tmp/cache/*\nTXT;\neval($x);\n/** d */", "eval($x)"),
        ("php", "<?php\n$m = 'Hello\nworld'; eval($x); $y = 'z';", "eval($x)"),
        # `/*` after a word character is text (a path, a glob), not a comment
        ("javascript", "const A = () => <p>Routes under /admin/* need auth</p>;\nconst run = (s) => eval(s);\n/** d */", "eval(s)"),
        # an apostrophe after a letter is no string opener
        ("javascript", '<label>Can\'t</label><input onChange={e => eval(e.target.value)} placeholder="it\'s" />',
         "eval(e.target.value)"),
        # a backtick after a markup `>` is text
        ("javascript", "<p>Press <kbd>`</kbd> key</p>;\nfunction run(s) { return eval(s); }\nconst m = `done`;", "eval(s)"),
        # `i++ / 2` divides
        ("javascript", "var r = i++ / 2; eval(s); var q = n / 3;", "eval(s)"),
        # a Ruby `#` inside a regex is no comment
        ("ruby", "x if line =~ /#/ && eval(params[:c])", "eval(params[:c])"),
        # a backslash does not escape a brace in a Python f-string
        ("python", 'f"\\{eval(code)}"', "eval(code)"),
        ("python", 'rf"^\\{eval(code)}"', "eval(code)"),
        # an unclosed block comment or template blanks nothing after it
        ("javascript", "/* never closed\neval(x)", "eval(x)"),
        ("javascript", "const t = `never closed\neval(x)", "eval(x)"),
        # a field that never closes keeps its line
        ("python", 'f"{eval(x)"', "eval(x)"),
    ],
)
def test_misread_lexemes_hide_no_code(language: str, text: str, kept: str) -> None:
    assert kept in "\n".join(_lines(text, language))


def test_division_is_not_a_regex_literal() -> None:
    text = 'x = (a) / 2; s = "eval(y)"; eval(z)'
    assert _lines(text, "javascript") == ['x = (a) / 2; s = "       "; eval(z)']


# ── CodeView ────────────────────────────────────────────────────────────────


def test_view_is_built_on_first_use_and_matches_the_file() -> None:
    lines = ("def f(x):", '    """eval(x) docs"""', "    return eval(x)  # eval")
    view = CodeView(lines, "python")
    assert view._view is None, "a file nobody asks about must cost nothing"
    assert view.line(3) == "    return eval(x)        "
    assert view.line(2) == '    """            """'
    assert [len(view.line(n)) for n in (1, 2, 3)] == [len(x) for x in lines]


def test_view_of_an_unlexed_language_is_the_file_itself() -> None:
    lines = ("eval(x) // c",)
    view = CodeView(lines, "java")
    assert view.line(1) is lines[0]


# ── cost ────────────────────────────────────────────────────────────────────

# Each input repeats a lexeme that makes a naive lexer rescan: unclosed openers,
# fields that never close, escapes, regex classes, one 512 KB line.
_ADVERSARIAL = {
    "dq_escape": ("javascript", '"\\'),
    "block_open": ("javascript", "/* "),
    "template_field_open": ("javascript", "`${"),
    "backticks": ("javascript", "`"),
    "regex_class_open": ("javascript", "(/["),
    "apostrophes": ("javascript", "'"),
    "fstring_field_open": ("python", 'f"{'),
    "fstring_nested": ("python", 'f"{f"{'),
    "ftriple_field_open": ("python", 'f"""{'),
    "triple": ("python", '"""'),
    "ruby_field_open": ("ruby", '"#{'),
    "go_raw": ("go", "`"),
    "php_attribute": ("php", "<?php #["),
    "php_heredoc_open": ("php", "<?php <<<A\n"),
    "php_regions": ("php", "<?php ?>"),
    "php_comment_leave": ("php", "<?php // ?>"),
    "jsx_text": ("javascript", "<p>a/* it's</p> "),
}
_SIZES = (65536, 131072, 262144, 524288)
_MAX_DOUBLING_RATIO = 2.6
# Below this a doubling ratio is timer noise, not growth: a linear lexer spends
# a few milliseconds on most of these inputs.
_NOISE_FLOOR_SEC = 0.02
# 512 KB of the worst input, measured at about 0.4 s: the ceiling is a cliff
# detector, not a benchmark.
_CEILING_SEC = 3.0
_CHILD_TIMEOUT_SEC = 120

_CHILD = textwrap.dedent(
    """
    import json, sys, time
    from shared.tools.code_view import mask_non_code
    language, unit = sys.argv[1], sys.argv[2]
    out = []
    for n in json.loads(sys.argv[3]):
        text = (unit * (n // len(unit) + 1))[:n]
        best = min(
            (time.perf_counter(), mask_non_code(text, language), time.perf_counter())
            for _ in range(3)
        )
        out.append(best[2] - best[0])
    print(json.dumps(out))
    """
)


@pytest.mark.parametrize("case", sorted(_ADVERSARIAL))
def test_lexing_is_linear_on_hostile_input(case: str) -> None:
    language, unit = _ADVERSARIAL[case]
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, language, unit, json.dumps(_SIZES)],
        capture_output=True, text=True, timeout=_CHILD_TIMEOUT_SEC, check=True,
    )
    times = json.loads(proc.stdout)
    grown = [(a, b) for a, b in zip(times, times[1:]) if b >= _NOISE_FLOOR_SEC]
    assert all(b < _MAX_DOUBLING_RATIO * a for a, b in grown), f"{case}: {times} s per size {_SIZES}"
    assert times[-1] < _CEILING_SEC, f"{case}: {times[-1]:.2f} s for {_SIZES[-1]} bytes"
