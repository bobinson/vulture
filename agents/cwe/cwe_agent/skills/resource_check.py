"""Resource management vulnerability detection skill."""

import re
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable
from functools import lru_cache
from itertools import accumulate, islice
from pathlib import Path
from typing import NamedTuple, TypeVar

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._guard_application import CLIENT_IP_HEADER
from cwe_agent.skills._lexical import (
    MAX_SCAN_CHARS,
    call_argument_text,
    identifier_words,
    indent_width,
    opening_bracket,
    stripped_code,
)
from cwe_agent.skills._message_send import check_message_sends
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import collect_scoped_body, extract_snippet

# CWE-476: NULL pointer dereference.
#
# The Go pattern previously used `\(.*\)\s*$` which produces ReDoS
# backtracking on long assignment lines with many parens. Tighten to
# `[^()]*` inside the call so quantifier expansion is bounded.
NULL_DEREF_PATTERNS = [
    re.compile(r"(\w+)\s*:=\s*\w+\.\w+\([^()]*\)\s*$"),  # Go: no nil check after call
    re.compile(r"\*(\w+)\s*(?:=|\.)"),  # Pointer dereference
]
GO_NIL_CHECK = re.compile(r"if\s+\w+\s*[!=]=\s*nil")

# Feature 0085. A Go `:=` assignment is not a nil dereference on its own — it is
# just a variable binding, and most bind a value type that can never be nil
# (`os.Getenv` returns string, `DetectMode()` returns a named scalar). Measured
# on the Vulture tree: 345 of 345 CWE-476 rows were exactly that, all at HIGH.
#
# What makes it a candidate is that the bound name is later USED AS A POINTER:
# `v.Field`, `*v`, or `v[...]`. That is the shape the protected E2E fixture
# encodes (`val := obj.GetItem()` / `val.Use()`), and it is the shape of the real
# bug (error discarded, value dereferenced anyway).
GO_DEREF_OF = "(?:\\*{v}\\b|\\b{v}\\.\\w|\\b{v}\\[)"

# The FIRST bound name, which is the value; the second is conventionally the
# error. NULL_DEREF_PATTERNS[0]'s own capture group takes the LAST `\w+` before
# `:=`, so on `req, _ := http.NewRequest(...)` it captured `_` — harmless while
# nothing read the group, wrong the moment the deref check does.
GO_ASSIGN_FIRST = re.compile(
    r"^\s*(?P<first>[A-Za-z_]\w*)\s*(?:,\s*(?P<second>[A-Za-z_]\w*)\s*)?:="
)

# `x := pkg.NewThing(...)` — the Go constructor convention (single value only).
GO_NEW_CTOR = re.compile(r":=\s*[\w.]*\bNew[A-Z]\w*\s*\(")

# Go stdlib constructors documented to ALWAYS return a usable non-nil value.
# Dereferencing one is correct Go, not a defect. Purely suppressive: this list
# can only remove findings, never add them, so a wrong entry costs recall on one
# call shape rather than manufacturing noise. Drawn from the residual measured
# on the Vulture tree after the dereference gate (bufio.NewScanner, hmac.New,
# flag.NewFlagSet and similar accounted for most of the remaining 100).
GO_NEVER_NIL_CALL = re.compile(
    r"""(?:^|[^\w.])(?:
          bufio\.New\w+ | bytes\.New\w+ | strings\.New\w+ | errors\.New
        | hmac\.New | sha1\.New | sha256\.New | sha512\.New | md5\.New | fnv\.New\w+
        | flag\.NewFlagSet | log\.New | tabwriter\.NewWriter
        | json\.NewEncoder | json\.NewDecoder | csv\.NewReader | csv\.NewWriter
        | time\.\w+ | strconv\.\w+ | filepath\.\w+ | fmt\.\w+
        | strings\.\w+ | exec\.\w+ | context\.\w+ | sort\.\w+ | utf8\.\w+
        | make | new | len | cap | append
      )\s*\(""",
    re.VERBOSE,
)

# A nil guard need not be spelled `if x != nil`. Go writes it in `return`
# expressions, `&&` chains, assignments and switch cases just as often.
# GO_NIL_CHECK's literal `if` missed all of those; measured, two of four sampled
# survivors on the Vulture tree were guarded this way. Variable-specific, unlike
# GO_NIL_CHECK, so an unrelated `err != nil` no longer clears a real finding.
GO_VAR_NIL_GUARD = re.compile(r"\b{v}\s*[!=]=\s*nil|\bnil\s*[!=]=\s*{v}\b")

# A nil slice/map has len 0, so a length guard is a real nil guard.
GO_LEN_GUARD = re.compile(r"\blen\(\s*{v}\s*\)")
_DEREF_SCAN_LINES = 12


def _go_var_is_dereferenced(var: str, lines: list[str], line_num: int) -> bool:
    """True when ``var`` is later used in a position that would fault if nil."""
    import re as _re
    pat = _re.compile(GO_DEREF_OF.format(v=_re.escape(var)))
    end = min(line_num + _DEREF_SCAN_LINES, len(lines))
    return any(pat.search(ln) for ln in lines[line_num:end])

# CWE-400: Uncontrolled resource consumption
RESOURCE_CONSUMPTION_PATTERNS = [
    re.compile(r"for\s*\{", re.IGNORECASE),  # Go: infinite loop
    re.compile(r"while\s*(?:True|1)\s*:"),  # Python: infinite loop
    re.compile(r"while\s*\(\s*(?:true|1)\s*\)"),  # C/Java: infinite loop
]
# An exit path OR a yield to the scheduler. `await` and `yield` belong here:
# an awaiting loop is a standard polling/consumer pattern, not a spin — it
# releases the event loop on every iteration. Measured on juice-shop, every one
# of the 17 CWE-400 rows was a bounded loop of this shape, reported at HIGH.
BREAK_OR_RETURN = re.compile(
    r"\b(?:break|return|sys\.exit|os\.Exit|await|yield)\b"
)

# How far to read for an exit path. A loop whose exit is more than this many
# lines away is not "visible" in the sense the finding claims.
_LOOP_BODY_SCAN_LINES = 40

# Extensions the infinite-loop patterns must NOT run against. These regexes are
# language-specific — `for\s*\{` is Go, `while True:` is Python — and markup is
# neither. Measured on juice-shop: after the exit-path guard removed 16 bounded
# loops, the ONE remaining CWE-400 was the Go pattern matching English prose,
# "Our Privacy Policy for {{applicationName}} is", in an Angular template.
_LOOP_PATTERN_SKIP_SUFFIXES = frozenset({
    ".html", ".htm", ".xhtml", ".vue", ".svelte",
    ".md", ".markdown", ".rst", ".txt", ".adoc",
})


def _loop_has_visible_exit(lines: list[str], line_num: int) -> bool:
    """True when the loop opened at ``line_num`` shows an exit path or a
    scheduler yield within the next few lines.

    The finding's own description says "Unbounded loop without visible exit",
    and BREAK_OR_RETURN has existed since the rule was written — but nothing
    ever called it, so every infinite-loop KEYWORD was reported regardless of
    its body. This makes the code match the sentence.
    """
    start = line_num  # 1-indexed line_num -> the line AFTER the loop header
    for probe in lines[start:start + _LOOP_BODY_SCAN_LINES]:
        if BREAK_OR_RETURN.search(probe):
            return True
    return False

# CWE-404: Improper resource shutdown
#
# The verb alone is not enough — this is the same defect the CWE-754 fix in
# error_handling_check.py cured. A bare `(?:open|fopen)\s*\(` matched every
# method whose name merely *ends* with "open": in one sweep 82 of 84 rows
# were `snackBarHelperService.open(...)`, `dialog.open(...)`,
# `window.open(...)` and friends — UI calls, not resources.
#
# Three parts are needed together:
#   1. a receiver guard on the builtin form, so only a *bare* open/fopen
#      call (no `foo.` / `$foo` prefix) qualifies;
#   2. a real-resource-namespace branch, because the bare form alone loses
#      the `fs.createWriteStream` / `fs.createReadStream` stream family
#      (5 genuine sites in the same sweep) — dropping those would be an
#      over-correction, not a narrowing;
#   3. a declaration skip, because `open (` at the START of a line is a
#      method DECLARATION, not a call that leaks a handle.
_RES_NS = r"(?:fs|fsPromises|net|os|io|ioutil|sql|pgx|mongo|gorm)"

RESOURCE_OPEN_PATTERNS = [
    # Bare builtin open()/fopen() — no receiver before it.
    re.compile(r"(?<![\w.$])(?:open|fopen)\s*\("),
    # Real resource namespaces: fs.createWriteStream, os.Open, os.Create,
    # fs.createReadStream, sql.Open, mongo.Connect...
    re.compile(rf"\b{_RES_NS}\.(?:[Oo]pen|[Cc]reate)\w*\s*\("),
    re.compile(r"\b(?:sql\.Open|pgx\.Connect|mongo\.Connect)\s*\("),
    re.compile(r"\bnet\.(?:Dial|Listen)\s*\("),
]

# `open (...)` / `public open (): void {` at line start is a declaration.
RESOURCE_OPEN_DECL = re.compile(
    r"^\s*(?:(?:public|private|protected|static|async|export|function|def)\s+)*"
    r"open\s*\("
)

# Markup is never a resource-shutdown site: `(click)="open()"` is a template
# binding to a component method.
_MARKUP_SUFFIXES = frozenset({".html", ".htm"})
RESOURCE_CLOSE_SAFE = re.compile(
    r"\b(?:defer\s|\.close\(\)|\.Close\(\)|with\s+open|context\s*manager)\b",
    re.IGNORECASE,
)

# CWE-770: Allocation without limits.
# The Go `make([]T, 0)` arm is PROTECTED and unchanged (feature 0085: the
# protected E2E fixture and TestCheckUnboundedAlloc depend on it, and it was not
# part of the measured false-positive mass). Accumulation is decided by the
# feature 0101 predicates below, not by a pattern in this list.
_GO_MAKE = re.compile(r"make\(\[\]\w+,\s*0\)")  # Go: unbounded slice
UNBOUNDED_ALLOC_PATTERNS = [_GO_MAKE]
# Applies to the Go arm ONLY, over STRIPPED context: a comment saying "no limit
# here yet" no longer silences a finding.
SIZE_LIMIT = re.compile(r"\b(?:max_size|maxlen|capacity|limit|MAX_)\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# CWE-770, feature 0101: input-driven, uncapped ACCUMULATION.
#
# The weakness is a collection or buffer that GROWS inside repetition the
# process does not control, with nothing bounding that growth. Before 0101 the
# rule reported a Python `.append` with any `for`/`while` above it. Measured on
# one real tree: 343 rows, 0 genuine; 233 of 270 were appends inside
# `for x in <finite in-memory collection>`, which cannot outgrow the collection.
# The loop was found, but nobody asked what DROVE it.
#
# A finding now needs all four:
#   sink      a receiver that grows (a growth verb, or a self-growth operator);
#   lifetime  the receiver outlives one iteration;
#   driver    an enclosing loop fed by input (a pull from a stream, socket,
#             queue, request or child process), or an input-event callback;
#   no cap    nothing in the loop bounds that receiver's size.
# Every decision reads language-neutral ROLES (a pull, a peer, a limit name, a
# size accessor) from identifier words; there is no framework or API table.
# The one name-only decision -- an UNBOUND iteration source such as a routine
# parameter named `client_sock` -- is a heuristic and SKILLS.md says so.
#
# Bounds: every looked-at line is capped at MAX_SCAN_CHARS
# before any pattern runs, and every `_ACC_*` pattern reads ONE capped line (or
# a bounded slice of one); only the per-identifier `*_TEMPLATE` patterns read
# joined routine text, and they are literal-led. The look-back is 120 lines, a
# body 80, at most 4 enclosing loops; per-file facts, loop bodies, routine text
# and cap verdicts are memoised, so sites that share a loop share its analysis.
# ---------------------------------------------------------------------------
_ACC_LOOKBACK = 120
_ACC_BODY_LINES = 80
_ACC_MAX_LOOPS = 4
_ACC_CALLBACK_LOOKBACK = 12
_ACC_CAP_BLOCK_LINES = 40
_ACC_MEMO_MAX = 4096
_ACC_ROUTINE_MEMO_MAX = 256

# Per-identifier patterns are built from these templates (NAME is replaced by
# the escaped identifier) through one lru_cached builder, never per call. Each
# starts with the LITERAL name and asserts the boundary after it
# (`NAME(?<![\w$.]NAME)`, the same spans as a leading lookbehind), so the regex
# engine's literal-prefix scan applies to routine text of up to 120 lines.
_ACC_VALUE_ADD_TEMPLATE = r"NAME(?<![\w$.]NAME)\s{0,4}=\s{0,4}$"
# A tuple target (`chunks, total = [], 0`) binds by POSITION, which is not read:
# `total` there is 0, not `[]` (measured: the shipped-shape `total += len(c)`
# size counter was reported as a growing collection).
_ACC_SCALAR_BIND_TEMPLATE = (
    r"NAME(?<![\w$.,]NAME)(?<!,\sNAME)\s{0,4}(?::[^=]{0,60})?=(?![=>])\s{0,4}([^\n]{0,60})"
)
_ACC_NUMERIC_INIT_TEMPLATE = (
    r"NAME(?<![\w$.,]NAME)(?<!,\sNAME)\s{0,4}(?::[^=]{0,60})?=(?![=>])\s{0,4}"
    r"(?:-?\d|0x|new\s{1,4}AtomicLong|atomic)"
)
# `var wg sync.WaitGroup` (one space after `var`, as formatters write it).
_ACC_VAR_TYPE_TEMPLATE = r"NAME(?<=\bvar\sNAME)\s{1,4}\*?([\w.]{1,80})"
_ACC_TYPE_HEAD = re.compile(r"\s{0,4}&?[\w.]{0,80}")
_ACC_PLUS_EQ_TEMPLATE = r"NAME\s{0,8}\+="
_ACC_RESET_TEMPLATE = (
    r"^\s{0,80}(?:(?:const|let|var|val)\s{1,4})?NAME\s{0,4}(?::[^=]{0,60})?"
    r"(?::=|=(?![=>]))(.{0,300})"
)
_ACC_SELF_REF_TEMPLATE = r"NAME(?<![\w$]NAME)(?![\w$])"
# `recent = recent[1:]`, `window = window[-1024:]`, `buf = buf[:0]`: a slice of
# itself is a trim, not growth.
_ACC_SELF_SLICE_TEMPLATE = r"^\s{0,4}NAME\s{0,4}\[[^\[\]\n]{0,80}:[^\[\]\n]{0,80}\]\s{0,4};?\s{0,4}$"
_ACC_RESET_HEAD = re.compile(
    r"^\s{0,80}(?:(?:const|let|var|val)\s{1,4})?([A-Za-z_$@][\w$]{0,63})\s{0,4}(?::[^=]{0,60})?(?::=|=(?![=>]))"
)


@lru_cache(maxsize=4096)
def _named(template: str, name: str) -> re.Pattern[str]:
    """Test oracle: the composed per-identifier pattern of ``template``.

    The reference meaning of a template, and what the ReDoS gate measures on
    joined text. The analysis never compiles it: see ``_form_finditer``, whose
    parity with this pattern ``test_0101_cwe770_review_r2.py`` pins.
    """
    return re.compile(template.replace("NAME", re.escape(name)))


# --- per-identifier forms -------------------------------------------
# Compiling a template per accumulator name cost ~8 compiles per DISTINCT name
# (measured: 15 of 18 s in `re.compile` on a script of ~15k distinct sites, and
# a 4096-entry cache thrashing above ~500 names). A template is instead split at
# NAME, once, into a LEFT context and a SUFFIX: the look-behinds written after
# the name (`NAME(?<![\w$.]NAME)`, there so the composed pattern is literal-led)
# move to the left as plain look-behinds. Each occurrence of the name, found by
# `str.find`, is accepted when the left context ends at it and the suffix
# matches after it; both are compiled once for all names. Occurrences examined
# per lookup are capped, so a name repeated throughout its window costs a bound.
_ACC_NAME_LOOKBEHIND = re.compile(r"\(\?<([!=])([^()]{0,40}?)NAME\)")
_ACC_LEFT_SPAN = 100
_ACC_MAX_OCCURRENCES = 64


class _Form(NamedTuple):
    left: re.Pattern[str] | None
    span: int
    suffix: re.Pattern[str]


class _FormMatch:
    """The parts of a composed-template match the analysis reads."""

    __slots__ = ("_text", "_start", "_suffix")

    def __init__(self, text: str, start: int, suffix: re.Match[str]) -> None:
        self._text, self._start, self._suffix = text, start, suffix

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._suffix.end()

    def group(self, index: int = 0) -> str:
        return self._text[self._start:self._suffix.end()] if index == 0 else self._suffix.group(index)


def _compile_left(left: str) -> re.Pattern[str] | None:
    return re.compile(f"(?:{left})\\Z") if left else None


def _split_form(template: str) -> _Form:
    left, suffix = template.split("NAME", 1)
    moved = "".join(f"(?<{m.group(1)}{m.group(2)})" for m in _ACC_NAME_LOOKBEHIND.finditer(suffix))
    suffix = _ACC_NAME_LOOKBEHIND.sub("", suffix)
    if "NAME" in suffix:
        raise ValueError(f"template names NAME twice: {template}")
    return _Form(_compile_left(left + moved), _ACC_LEFT_SPAN if left else 0, re.compile(suffix))


_ACC_FORMS: dict[str, _Form] = {}


def _form(template: str) -> _Form:
    found = _ACC_FORMS.get(template)
    if found is None:
        found = _ACC_FORMS[template] = _split_form(template)
    return found


def _left_start(form: _Form, text: str, pos: int) -> int:
    if form.left is None:
        return pos
    m = form.left.search(text, max(0, pos - form.span), pos)
    return -1 if m is None else m.start()


def _form_at(form: _Form, name: str, text: str, pos: int) -> _FormMatch | None:
    # The suffix first: it is one anchored match that usually fails at its first
    # character, while the left context is a search across up to 100 characters.
    # The two read disjoint text, so the order does not change the result.
    suffix = form.suffix.match(text, pos + len(name))
    if not suffix:
        return None
    start = _left_start(form, text, pos)
    return _FormMatch(text, start, suffix) if start >= 0 else None


def _occurrences(name: str, text: str) -> Iterable[int]:
    pos = text.find(name)
    for _ in range(_ACC_MAX_OCCURRENCES):
        if pos < 0:
            return
        yield pos
        pos = text.find(name, pos + 1)


def _occurrences_back(name: str, text: str) -> Iterable[int]:
    pos = text.rfind(name)
    for _ in range(_ACC_MAX_OCCURRENCES):
        if pos < 0:
            return
        yield pos
        pos = text.rfind(name, 0, pos + len(name) - 1) if pos else -1


def _form_finditer(template: str, name: str, text: str) -> Iterable[_FormMatch]:
    """Non-overlapping matches of ``template`` for ``name``, as ``finditer`` of the composed pattern."""
    form, end = _form(template), 0
    for pos in _occurrences(name, text):
        m = _form_at(form, name, text, pos)
        if m is not None and m.start() >= end:
            end = m.end()
            yield m


def _form_search(template: str, name: str, text: str) -> _FormMatch | None:
    if name not in text:
        return None
    return next(iter(_form_finditer(template, name, text)), None)


def _form_rsearch(template: str, name: str, text: str) -> Iterable[_FormMatch]:
    """Matches of ``template`` for ``name`` from the END of ``text`` backwards."""
    form = _form(template)
    return filter(None, (_form_at(form, name, text, pos) for pos in _occurrences_back(name, text)))


_T = TypeVar("_T")


def _identity_memo(memo: dict, anchor: object, key: object, build: Callable[..., _T], *args: object) -> _T:
    """Memoise ``build(*args)`` under ``key``, valid only while ``anchor`` is the same object.

    Typed by ``build``'s result, and called with its arguments rather than a
    closure: a hit then allocates nothing (a lambda per lookup was a per-site cost).
    """
    hit = memo.get(key)
    if hit is not None and hit[0] is anchor:
        return hit[1]
    if len(memo) > _ACC_MEMO_MAX:
        memo.clear()
    value = build(*args)
    memo[key] = (anchor, value)
    return value


def _words_of(text: str) -> set[str]:
    return {w for ident in _ACC_IDENT.findall(text) for w in identifier_words(ident)}


# --- per-file line facts ----------------------------------------------------
# One capped copy per file, shared by every loop (revision 1 rebuilt it per loop
# header: O(file) per loop), and each line's indent computed once (the upward
# walks otherwise re-measured near-cap lines per site: the `nested.py` density probe).
# Lines INSIDE a multi-line string literal are blanked: a column-0
# `"""` body inside a loop otherwise reads as code at indent 0 and ends the walk.
_ACC_TRIPLE_QUOTE = re.compile(r"\"\"\"|'''")


class _LineFacts(NamedTuple):
    capped: list[str]
    indents: list[int]
    fidx: list                   # [None | _FileIndex]: the one-pass per-file index (see _file_index)
    braces: list                 # line -> its raw text holds `{` (a necessary condition for brace mode)
    codes: list                  # line -> its stripped code, filled on first read (None until then)
    bound: list                  # [None | frozenset]: suffixes of every run a binding could name (_may_bind)
    callbacks: list              # [None | bool]: some line may hold an input-event callback opener


_ACC_BODY_MEMO: dict = {}
_ACC_ROUTINE_MEMO: dict = {}
_ACC_DECL_MEMO: dict = {}
_ACC_CAP_MEMO: dict = {}
_ACC_TOTALS_MEMO: dict = {}
_ACC_CAP_ROWS_MEMO: dict = {}
_ACC_BODY_INDEX_MEMO: dict = {}
_ACC_BODY_TEXT_MEMO: dict = {}
_ACC_DRIVEN_MEMO: dict = {}
_ACC_CB_MEMO: dict = {}
_ACC_CHAIN_MEMO: dict = {}
_ACC_ACTIVE_MEMO: dict = {}
# Every analysis below is per file; dropping them when a new file starts bounds
# what the memos retain to one file's loops.
_ACC_PER_FILE_MEMOS = (
    _ACC_BODY_MEMO, _ACC_ROUTINE_MEMO, _ACC_DECL_MEMO, _ACC_CAP_MEMO, _ACC_TOTALS_MEMO, _ACC_CAP_ROWS_MEMO,
    _ACC_BODY_INDEX_MEMO, _ACC_BODY_TEXT_MEMO, _ACC_DRIVEN_MEMO, _ACC_CB_MEMO,
    _ACC_CHAIN_MEMO, _ACC_ACTIVE_MEMO,
)


def _has_triple_quote(line: str) -> bool:
    return '"""' in line or "'''" in line


def _quote_state(line: str, open_quote: str | None) -> str | None:
    for m in _ACC_TRIPLE_QUOTE.finditer(line):
        if open_quote is None:
            open_quote = m.group()
        elif m.group() == open_quote:
            open_quote = None
    return open_quote


def _string_interior(capped: list[str]) -> list[int]:
    """Indexes of lines that START inside a triple-quoted string literal."""
    out, open_quote = [], None
    for i, line in enumerate(capped):
        if open_quote:
            out.append(i)
        if _has_triple_quote(line):
            open_quote = _quote_state(line, open_quote)
    return out


def _clear_file_memos() -> None:
    for memo in _ACC_PER_FILE_MEMOS:
        memo.clear()


def _blank_interiors(capped: list[str]) -> list[str]:
    for i in _string_interior(capped):
        capped[i] = ""
    return capped


def _build_facts(lines: list[str]) -> _LineFacts:
    _clear_file_memos()   # a new file: drop the previous file's analyses
    capped = _blank_interiors([line[:MAX_SCAN_CHARS] for line in lines])
    return _LineFacts(capped, list(map(indent_width, capped)), [None],
                      ["{" in line for line in capped], [None] * len(capped), [None], [None])


_ACC_LAST_FACTS: list = [None, None]   # [lines object, its facts]: one file at a time


def _facts(lines: list[str]) -> _LineFacts:
    if _ACC_LAST_FACTS[0] is not lines:
        _ACC_LAST_FACTS[:] = [lines, _build_facts(lines)]
    return _ACC_LAST_FACTS[1]


def _line_code(facts: _LineFacts, i: int) -> str:
    code = facts.codes[i]
    if code is None:
        code = facts.codes[i] = stripped_code(facts.capped[i])
    return code


# --- sink: a receiver that grows --------------------------------------------
# A growth verb, matched by PREFIX so `push_back`, `extend_from_slice`,
# `AddRange` and `append(contentsOf:)` need no entries. JS `concat` is not one:
# it returns a new array.
_ACC_GROW_VERB = re.compile(
    r"\.\s{0,8}((?:append|push|add|extend|insert|put|enqueue|emplace|unshift)\w{0,12})\s{0,8}\(",
    re.IGNORECASE,
)
_ACC_RECEIVER_TAIL = re.compile(r"([A-Za-z_$@][\w$]{0,63})\s{0,8}$")
# Self-growth operators: `x = append(x, ...)` / `realloc(x, ...)`, `x = x + ...`,
# `x[] =` / `x[#x+1] =`, `array_push(x, ...)`, `x << v`, `x += v`, `x .= v`.
# The OPERATOR is found first and the receiver read BACKWARDS from it:
# reading the receiver forwards retried a 128-char class at every identifier
# boundary, and in a chain of 1-character segments (`a.a.a.`) every other
# character is one (measured 3.7 ms/KB). Now each operator costs one bounded
# backward read, and at most _ACC_OPS_PER_LINE operators are read per line.
_ACC_GROW_OP = re.compile(
    r"=\s{0,8}(?:append|realloc)\s{0,8}\(\s{0,8}(?P<a>[A-Za-z_$@][\w$.]{0,127}+)\s{0,8},"
    r"|=\s{0,8}(?P<b>[A-Za-z_$@][\w$.]{0,127}+)\s{1,8}\+\s"
    r"|\[\s{0,4}(?:#\s{0,4}(?P<c>[A-Za-z_$@][\w$.]{0,127}+)\s{0,4}\+\s{0,4}1\s{0,4})?\]\s{0,4}=(?!=)"
    r"|array_push\s{0,4}\(\s{0,4}(?P<d>\$?[\w$]{1,64})"
    r"|<<\s{0,8}(?![\d<])"
    r"|(?<!\.)\.=|\+="
)
# The receiver chain ending just before an operator, read on the REVERSED text.
_ACC_REV_CHAIN = re.compile(r"\s{0,8}([\w$.@]{1,128})")
_ACC_CHAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.@")
_ACC_CHAIN_FIRST = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$@")
_ACC_OPS_PER_LINE = 8
_ACC_REV_WINDOW = 140
_ACC_IDENT = re.compile(r"[A-Za-z_$][\w$]{0,63}")
_ACC_EMPTY_INIT = (
    r"=\s{0,4}(?:\[\s{0,2}\]|\{\s{0,2}\}|''|\"\"|b''|b\"\"|bytearray\(\)"
    r"|new\s{1,4}\w{0,40}(?:Builder|List|Buffer)\w{0,10}\(|String::new\(\)|Vec::new\(\)"
    r"|\w{0,20}(?:list|bytearray|StringIO)\(\))"
)
_ACC_EMPTY_INIT_RE = re.compile(_ACC_EMPTY_INIT)
_ACC_EMPTY_BIND_TEMPLATE = r"NAME(?<![\w$.]NAME)\s{0,4}(?::[^=]{0,60})?" + _ACC_EMPTY_INIT
# A receiver with one of these NAMES is a counter unless it is initialised to an
# empty collection (`x = x.add(...)`, BigDecimal and atomics are arithmetic).
_ACC_SCALAR_NAMES = frozenset({
    "count", "total", "n", "num", "size", "len", "length", "sum", "bytes", "stats", "counter",
    "i", "j", "idx", "index", "offset", "pos",
})
_ACC_COUNTER_WORDS = frozenset({"count", "total", "sum", "counter", "stats", "bytes", "read"})
_ACC_COUNTER_HINT = re.compile("|".join(sorted(_ACC_COUNTER_WORDS)))
_ACC_COLLECTION_WORDS = frozenset({"buf", "buffer", "data", "chunks", "parts", "lines", "items", "list"})


def _verb_receiver(code: str, at: int) -> str | None:
    tail = _ACC_RECEIVER_TAIL.search(code[max(0, at - 72):at])
    if not tail:
        return None
    name = tail.group(1)
    before = code[:max(0, at - len(name))].rstrip()[-80:] + " "
    return None if _form_search(_ACC_VALUE_ADD_TEMPLATE, name, before) else name


# Growth verbs that are not growth: an `add` whose
# arguments are only numeric is arithmetic on a counter, an atomic or a wait
# group (`wg.Add(1)`, `n.Add(int64(v))`, `Interlocked.Add(ref total, n)`,
# `metrics.add(value.length)`); a `put`/`insert` keyed by a literal overwrites
# one entry (`map.put("last", line)`). A bare `n` is NOT numeric evidence:
# `nums.add(n)` may collect parsed input.
_ACC_VERBS_PER_LINE = 8
_ACC_NUMERIC_ARGS = re.compile(
    r"\s{0,8}(?P<ref>ref\s{1,4}[\w$.]{1,64}\s{0,4},\s{0,4})?"
    r"(?:-?\d[\w.]{0,30}"
    r"|(?:u?int\d{0,3}|long|float\d{0,2}|double|usize|isize|[iu]\d{1,3}|size_t)\s{0,4}"
    r"\((?:[^()]{0,200}|[^()]{0,200}\([^()]{0,200}\)[^()]{0,200})\)"
    r"|len\s{0,2}\([^()]{0,200}\)"
    r"|(?P<chain>[A-Za-z_$][\w$.]{0,120}))\s{0,8}"
)
_ACC_LITERAL_KEY = re.compile(r"\s{0,8}(?:\"\"|''|-?\d[\w.]{0,30})\s{0,8}")
_ACC_STRING_KEY = re.compile(r"\s{0,8}(?:\"\"|'')\s{0,8}")


def _chain_is_size(chain: str) -> bool:
    return _last_word_is_size(chain.rsplit(".", 1)[-1])


def _numeric_args(args: str) -> bool:
    m = _ACC_NUMERIC_ARGS.fullmatch(args)
    if not m:
        return False
    chain = m.group("chain")
    return chain is None or bool(m.group("ref")) or _chain_is_size(chain)


def _literal_keyed(verb: str, args: str) -> bool:
    if "," not in args or not verb.startswith(("put", "insert")):
        return False
    key = _ACC_LITERAL_KEY if verb.startswith("put") else _ACC_STRING_KEY
    return bool(key.fullmatch(args.split(",", 1)[0]))


def _verb_is_growth(code: str, verb: re.Match[str]) -> bool:
    name = verb.group(1).lower()
    if name == "add":
        return not _numeric_args(call_argument_text(code, verb.end() - 1))
    if not name.startswith(("put", "insert")):
        return True
    return not _literal_keyed(name, call_argument_text(code, verb.end() - 1))


# The numeric-`add` exemption yields to the receiver's binding. An
# `add` of a number into a receiver bound in the routine to a collection
# (`seen = set()`, `mutableListOf<Int>()`, `NewSet()`, `[]`) grows it. The words
# of the constructor are read, never a type table.
_ACC_COLLECTION_WORDS_CTOR = frozenset({
    "set", "list", "map", "dict", "vec", "array", "deque", "queue", "bag", "collection", "slice",
})
_ACC_CTOR_HEAD = re.compile(r"\s{0,4}(?:new\s{1,4})?&?[\w.]{1,80}")


def _numeric_add_receiver(code: str) -> str | None:
    """The receiver of the first `add` whose arguments are only numeric, or None."""
    for verb in islice(_ACC_GROW_VERB.finditer(code), _ACC_VERBS_PER_LINE):
        if verb.group(1).lower() == "add" and _numeric_args(call_argument_text(code, verb.end() - 1)):
            return _verb_receiver(code, verb.start())
    return None


def _collection_ctor(rhs: str) -> bool:
    head = _ACC_CTOR_HEAD.match(rhs)
    words = identifier_words(head.group().replace(".", "_")) if head else ()
    return bool(set(words) & _ACC_COLLECTION_WORDS_CTOR)


def _bound_to_collection(acc: str, routine_text: str) -> bool:
    """``acc`` is first bound in the routine to an empty literal or a collection constructor."""
    m = _first_binding(_ACC_SCALAR_BIND_TEMPLATE, acc, routine_text)
    return bool(m) and (bool(_ACC_EMPTY_INIT_RE.search("=" + m.group(1))) or _collection_ctor(m.group(1)))


def _verb_accumulator(code: str, verbs: list[re.Match[str]]) -> str | None:
    growing = next((v for v in verbs if _verb_is_growth(code, v)), None)
    return _verb_receiver(code, growing.start()) if growing else None


# The commonest sink, `   name.append(x)`: the line opens with the receiver and
# its first `.` starts a growth verb. That first match is the one `_accumulator`
# reads, the receiver tail is the whole name (at most 64 characters, preceded
# only by indentation) and nothing before it can make it a value add, so for a
# verb that is growth whatever its arguments the receiver is the name itself.
# Case is folded in the verb only: folded, `[A-Za-z]` would also admit `ſ` and `K`.
# Indentation is bounded (as everywhere here) so a search stays linear; a line
# indented deeper simply takes the general path, which gives the same answer.
_ACC_LEAD_SINK = re.compile(r"\s{0,80}([A-Za-z_$@][\w$]{0,63})(?i:" + _ACC_GROW_VERB.pattern + ")")


def _lead_receiver(code: str) -> str | None:
    m = _ACC_LEAD_SINK.match(code)
    return m.group(1) if m and _verb_grows(m.group(2)) else None


def _verb_grows(verb: str) -> bool:
    """A growth verb that grows whatever its arguments: not `add`, `put*` or `insert*`."""
    low = verb.lower()
    return low != "add" and not low.startswith(("put", "insert"))


@lru_cache(maxsize=4096)
def _accumulator(code: str) -> str | None:
    """The receiver ``code`` grows, or None (a pure function of the stripped line)."""
    lead = _lead_receiver(code)
    if lead is not None:
        return lead
    verbs = list(islice(_ACC_GROW_VERB.finditer(code), _ACC_VERBS_PER_LINE))
    if verbs:
        return _verb_accumulator(code, verbs)
    name = _self_grown(code)
    return name.rsplit(".", 1)[-1].lstrip("@$") if name else None


def _self_grown(code: str) -> str | None:
    """The receiver chain of the first self-growth operator on ``code`` that has one."""
    ops = islice(_ACC_GROW_OP.finditer(code), _ACC_OPS_PER_LINE)
    return next(filter(None, (_op_receiver(code, op) for op in ops)), None)


def _op_receiver(code: str, op: re.Match[str]) -> str | None:
    if op.group("d"):
        return op.group("d")
    chain = _chain_before(code, op.start())
    return chain if _operand_agrees(chain, _op_operand(op)) else None


def _op_operand(op: re.Match[str]) -> str | None:
    return op.group("a") or op.group("b") or op.group("c")


def _operand_agrees(chain: str | None, operand: str | None) -> bool:
    """`x = append(x, …)`, `x = x + …`, `t[#t + 1]`: the operand names the receiver (or a tail of it)."""
    if chain is None or operand is None:
        return True
    return chain == operand or chain.endswith("." + operand)


def _chain_before(code: str, at: int) -> str | None:
    """The dotted receiver chain that ends just before ``at`` (whitespace allowed), or None."""
    window = code[max(0, at - _ACC_REV_WINDOW):at]
    m = _ACC_REV_CHAIN.match(window[::-1])
    if not m:
        return None
    run = m.group(1)[::-1]
    before = len(window) - m.end() - 1
    return _chain_from_run(run, before >= 0 and window[before] in _ACC_CHAIN_CHARS)


def _chain_from_run(run: str, cut: bool) -> str | None:
    """A run cut by the read limit starts after its first dot; a chain starts with a letter."""
    if cut:
        run = run.partition(".")[2]
    run = run.lstrip(".")
    return run if run and run[0] in _ACC_CHAIN_FIRST else None


@lru_cache(maxsize=4096)
def _counter_named(acc: str) -> bool:
    low = acc.lower()
    if low in _ACC_SCALAR_NAMES:
        return True
    # No counter word inside the name: skip the word split.
    return bool(_ACC_COUNTER_HINT.search(low)) and _counter_words(acc)


def _counter_words(acc: str) -> bool:
    words = set(identifier_words(acc))
    return bool(words & _ACC_COUNTER_WORDS) and not words & _ACC_COLLECTION_WORDS


def _bound_to_empty(acc: str, routine_text: str) -> bool:
    m = _first_binding(_ACC_SCALAR_BIND_TEMPLATE, acc, routine_text)
    return bool(m and _ACC_EMPTY_INIT_RE.search("=" + m.group(1)))


def _scalar_type_words(text: str) -> bool:
    """A type or constructor whose words name an atomic or a wait group."""
    words = identifier_words(text.replace(".", "_"))
    return "atomic" in words or ("wait", "group") in zip(words, words[1:])


def _type_head(rhs: str) -> str:
    head = _ACC_TYPE_HEAD.match(rhs)   # matches at every position (all of it is optional)
    return head.group() if head else ""


def _typed_scalar(acc: str, routine_text: str) -> bool:
    """`var wg sync.WaitGroup`, `var n atomic.Int64`, `wg := sync.WaitGroup{}`."""
    for template in (_ACC_VAR_TYPE_TEMPLATE, _ACC_SCALAR_BIND_TEMPLATE):
        m = _first_binding(template, acc, routine_text)
        if m and _scalar_type_words(_type_head(m.group(1))):
            return True
    return False


def _is_scalar(acc: str, routine_text: str) -> bool:
    """A counter, a number or an atomic: growth there is arithmetic, not allocation."""
    if acc not in routine_text:
        return _counter_named(acc)   # no binding to read: one substring search, not four
    return (_counter_scalar(acc, routine_text) or bool(_first_binding(_ACC_NUMERIC_INIT_TEMPLATE, acc, routine_text))
            or _typed_scalar(acc, routine_text))


def _counter_scalar(acc: str, routine_text: str) -> bool:
    return _counter_named(acc) and not _bound_to_empty(acc, routine_text)


def _plus_eq_is_arithmetic(acc: str, code: str, routine_text: str) -> bool:
    """`x += v` grows a collection only when x starts empty here or v is itself a pull."""
    if "+=" not in code or not _form_search(_ACC_PLUS_EQ_TEMPLATE, acc, code):
        return False
    return not (_pulls(code) or _form_search(_ACC_EMPTY_BIND_TEMPLATE, acc, routine_text))


# --- lifetime -----------------------------------------------------
# A receiver declared inside the loop body, or reassigned there to something that
# does not contain itself (`batch = []` after a flush), lives one iteration.
_ACC_DECL = re.compile(
    r"(?:const|let|var|val|:=)\s{0,4}([A-Za-z_$][\w$]{0,63})\b|^\s{0,80}([A-Za-z_$][\w$]{0,63})\s{0,4}:="
)


# A statically typed local (`List<String> parts = ...`, `std::vector<char> f = ...`,
# `char *buf = ...`, `final a.b.T x = ...`) declares its name exactly as `var` does:
# a row that STARTS with a type (a word, optionally qualified, with generic
# arguments and array brackets) followed by a name and `=`. A control word is not
# a type (`else buf = ...`, `return x = ...`), so the row must not start with one.
_ACC_DECL_NOT_TYPE = (
    "if|else|elif|elsif|return|yield|await|throw|raise|case|new|delete|print|echo|puts|while|for"
    "|foreach|do|not|and|or|in|is|goto|defer|go|unless|until|when|then|typeof|sizeof|assert|lambda"
    "|with|import|from|export|using|package|del|pass|break|continue|default|static_assert"
)
_ACC_TYPED_DECL = re.compile(
    r"^\s{0,80}(?:(?:final|readonly|static|const|auto|mut|volatile|register|unsigned|signed)\s{1,8}){0,3}"
    r"(?!(?:" + _ACC_DECL_NOT_TYPE + r")\b)"
    r"[A-Za-z_][\w.]{0,80}(?:::[\w.]{1,40}){0,4}"
    r"(?:<(?:[^<>=;\n]|<(?:[^<>=;\n]|<[^<>=;\n]{0,60}>){0,80}>){0,120}>)?"
    r"(?:\s{0,4}\[\s{0,4}\])*[\s*&]{1,8}([A-Za-z_$][\w$]{0,63})\s{0,4}=(?![=>])"
)


def _keyword_declared(code: str) -> set[str]:
    return {g for m in _ACC_DECL.finditer(code) for g in m.groups() if g}


def _declared_in_line(code: str) -> set[str]:
    names = _keyword_declared(code)
    typed = _ACC_TYPED_DECL.match(code)
    return names | {typed.group(1)} if typed else names


# Every declaration form holds one of these: a row without one declares nothing.
_ACC_DECL_HINT = re.compile(r"const|let|var|val|=")


def _collect_declared(body: list[str]) -> frozenset[str]:
    names: set[str] = set()
    for code in _declaring_rows(body):
        names |= _declared_in_line(code)
    return frozenset(names)


def _declaring_rows(body: list[str]) -> list[str]:
    """Rows after the header that hold a declaration word (one search per active row)."""
    return [body[i] for i in _active_rows(body) if i and _ACC_DECL_HINT.search(body[i])]


def _declared_names(body: list[str]) -> frozenset[str]:
    """Names declared in a loop body (memoised per body object)."""
    return _identity_memo(_ACC_DECL_MEMO, body, (id(body),), _collect_declared, body)


def _declared_inside(acc: str, body: list[str]) -> bool:
    """Test oracle: the analysis reads ``_Loop.declared``; unit tests ask by body."""
    return acc in _declared_names(body)


def _resets(acc: str, code: str) -> bool:
    """``code`` rebinds ``acc`` to a value without itself, or to a slice of itself."""
    m = _form_search(_ACC_RESET_TEMPLATE, acc, code)
    if not m:
        return False
    rhs = m.group(1)
    return not _form_search(_ACC_SELF_REF_TEMPLATE, acc, rhs) or bool(_form_search(_ACC_SELF_SLICE_TEMPLATE, acc, rhs))


def _reset_in_loop(acc: str, body: list[str]) -> bool:
    """Test oracle: the analysis reads ``_CapProfile.trims``; unit tests ask by body."""
    return acc in _body_index(body).reset


# --- loop discovery ---------------------------------------------------------
# The sink's own line first (`while (...) acc.add(x);`), then upward by strictly
# decreasing indent, skipping comment-only and string-interior lines; an Allman
# `{` hands over to the previous code line; a body that is NOT indented is found
# by brace depth. Revision 0's walker (feature 0085) accepted a sibling loop.
# `foreach` and an `await` prefix open loops too (C#, PHP).
_ACC_LOOP_WORDS = "for|foreach|while|until|loop|do|repeat"
_ACC_SCOPE_WORDS = "def|func|fn|fun|function|class|sub|proc|impl|interface|struct"
_ACC_LOOP_HEADER = re.compile(
    r"^\s{0,80}(?:\}\s{0,8})?(?:(?:async|await)\s{1,8})?(?:" + _ACC_LOOP_WORDS + r")\b"
)
_ACC_SCOPE_HEADER = re.compile(
    r"^\s{0,80}(?:export\s{1,8})?(?:pub(?:\(\w{1,20}\))?\s{1,8})?(?:async\s{1,8})?"
    r"(?:" + _ACC_SCOPE_WORDS + r")\b"
)
# A line either header matches holds one of their words, as a whole word after
# a non-word character or the line start: every such line holds a match of this
# literal-led pattern, so it finds them all (and some lines that are not headers).
_ACC_HEADER_WORD = re.compile(f"(?:{_ACC_SCOPE_WORDS}|{_ACC_LOOP_WORDS})\\b")


def _prev_code_line(facts: _LineFacts, k: int, stop: int) -> int | None:
    while k > stop and not _line_code(facts, k).strip():
        k -= 1
    return k if k > stop else None


def _allman_header(facts: _LineFacts, j: int, stop: int) -> int:
    """A lone `{` line opens the block of the code line above it."""
    if _line_code(facts, j).strip() != "{":
        return j
    k = _prev_code_line(facts, j - 1, stop)
    return k if k is not None and facts.indents[k] <= facts.indents[j] else j


def _next_opener(facts: _LineFacts, i: int, stop: int) -> int | None:
    """The block opener of line index ``i`` (Allman `{` handed to its header line)."""
    index = _file_index(facts)
    j = index.parent[i]
    if j <= stop:
        return None
    return _allman_header(facts, j, stop) if index.lone[j] else j


def _opener_ends_walk(facts: _LineFacts, hdr: int, out: list[int]) -> bool:
    index = _file_index(facts)
    if hdr in index.head_set:
        return True
    if hdr in index.loops:
        out.append(hdr + 1)
    return False


def _chain_from(facts: _LineFacts, hdr: int) -> tuple[int, ...]:
    """1-based loop headers on the block-opener chain from ``hdr`` up to the routine (at most 4)."""
    out: list[int] = []
    stop = max(-1, hdr - _ACC_LOOKBACK)
    at: int | None = hdr
    while at is not None and len(out) < _ACC_MAX_LOOPS and not _opener_ends_walk(facts, at, out):
        at = _next_opener(facts, at, stop)
    return tuple(out)


def _chain_above(facts: _LineFacts, i: int, stop: int) -> list[int]:
    """Loop headers on the opener chain of line index ``i``, those within the look-back (above ``stop``)."""
    hdr = _next_opener(facts, i, stop)
    if hdr is None:
        return []
    return [h for h in _identity_memo(_ACC_CHAIN_MEMO, facts, hdr, _chain_from, facts, hdr) if h - 1 > stop]


def _brace_opener_ends_walk(code: str, j: int, out: list[int]) -> bool:
    if _ACC_LOOP_HEADER.match(code):
        out.append(j + 1)
        return len(out) >= _ACC_MAX_LOOPS
    return bool(_ACC_SCOPE_HEADER.match(code))


def _brace_loop_openers(lines: list[str], n: int) -> list[int]:
    """Enclosing loop openers by brace depth: a line that drives the depth below zero."""
    facts = _facts(lines)
    out, depth = [], 0
    for j in range(n - 2, max(-1, n - 1 - _ACC_LOOKBACK), -1):
        code = _line_code(facts, j)
        depth += code.count("}") - code.count("{")
        if depth < 0 and _brace_opener_ends_walk(code, j, out):
            break
        depth = max(depth, 0)
    return out


def _brace_near(lines: list[str], n: int) -> bool:
    facts = _facts(lines)
    near = range(max(0, n - 4), n)
    if True not in facts.braces[near.start:n]:
        return False   # no brace in the raw lines: none survives stripping either
    return "{" in "".join(_line_code(facts, i) for i in near)


def _merge_loops(found: list[int], braced: list[int]) -> list[int]:
    extra = set(braced) - set(found)
    return sorted(set(found) | extra, reverse=True)[:_ACC_MAX_LOOPS] if extra else found


def _enclosing_loops(lines: list[str], n: int) -> list[int]:
    """1-based loop header lines enclosing line ``n``, nearest first (at most 4)."""
    return _loops_in(_facts(lines), lines, n)


def _loops_in(facts: _LineFacts, lines: list[str], n: int) -> list[int]:
    """``_enclosing_loops`` on the file's facts.

    By indentation: the line's own loop, then the opener chain above it (shared
    per opener); by brace depth as well when a brace is near.
    """
    chain = _chain_above(facts, n - 1, max(-1, n - 1 - _ACC_LOOKBACK))
    found = [n, *chain][:_ACC_MAX_LOOPS] if n - 1 in _file_index(facts).loops else chain
    if True not in facts.braces[max(0, n - 4):n] or not _brace_near(lines, n):
        return found   # (the first test is _brace_near's own first test, without the call)
    return _merge_loops(found, _brace_loop_openers(lines, n))


# --- routine text -----------------------------------------------------------
# One pass per file, on the first routine query: every line's stripped code
# joined into ONE text with line offsets, and for each line the nearest routine
# header at or above it. A site's routine start is then an array read and its
# routine text one slice (revision 2 extended a joined chunk per site, copying
# the chunk on every append, and rescanned for headers per query).
class _FileIndex(NamedTuple):
    text: str              # stripped code of every line, each followed by "\n"
    offsets: list[int]     # line index -> offset of its first character; [len] = len(text)
    heads: list[int]       # ascending indexes of routine-header lines (`_ACC_SCOPE_HEADER`)
    head_set: frozenset[int]
    parent: list[int]      # line index -> nearest code line above it with a smaller indent, -1 for none
    loops: frozenset[int]  # indexes of lines whose code opens a loop (`_ACC_LOOP_HEADER`)
    lone: list[bool]       # line index -> its code is a lone `{` (an Allman block opener)


def _header_lines(codes: list[str], text: str, offsets: list[int]) -> tuple[list[int], list[int]]:
    """(routine-header lines, loop-header lines), ascending: each pattern tried only on a line with a header word."""
    hits = _lines_with(_ACC_HEADER_WORD, text, offsets)
    return _lines_matching(_ACC_SCOPE_HEADER, codes, hits), _lines_matching(_ACC_LOOP_HEADER, codes, hits)


def _lines_with(pattern: re.Pattern[str], text: str, offsets: list[int]) -> list[int]:
    """Ascending indexes of the lines of ``text`` holding a match of ``pattern`` (which never spans lines).

    After a hit the search resumes at the next line, so a line dense with
    matches costs one search, not one per match.
    """
    out: list[int] = []
    m = pattern.search(text)
    while m:
        out.append(bisect_right(offsets, m.start()) - 1)
        m = pattern.search(text, offsets[out[-1] + 1])
    return out


def _lines_matching(pattern: re.Pattern[str], codes: list[str], lines: list[int]) -> list[int]:
    return [i for i in lines if pattern.match(codes[i])]


def _build_index(facts: _LineFacts) -> _FileIndex:
    codes = list(map(stripped_code, facts.capped))
    facts.codes[:] = codes
    text = "\n".join(codes) + "\n"
    offsets = list(accumulate(map((1).__add__, map(len, codes)), initial=0))
    heads, loops = _header_lines(codes, text, offsets)
    return _FileIndex(text, offsets, heads, frozenset(heads), _parents(codes, facts.indents), frozenset(loops),
                      ["{" in code and code.strip() == "{" for code in codes])


def _parents(codes: list[str], indents: list[int]) -> list[int]:
    """Per line, the nearest CODE line above it with a smaller indent, in one pass.

    The open code lines form a stack of strictly increasing indents: a code line
    closes every open line at or past its own indent, so the answer for any line
    is the last open line indented less than it (one bisection). Blank,
    comment-only and string-interior lines are answered but never opened.
    """
    out, lines_open, cols = [], [], []
    for i, code in enumerate(codes):
        k = bisect_left(cols, indents[i])
        out.append(lines_open[k - 1] if k else -1)
        if code.strip():
            del lines_open[k:], cols[k:]
            lines_open.append(i)
            cols.append(indents[i])
    return out


def _file_index(facts: _LineFacts) -> _FileIndex:
    index = facts.fidx[0]
    if index is None:
        index = facts.fidx[0] = _build_index(facts)
    return index


def _routine_start(facts: _LineFacts, n: int) -> int:
    """Index of the nearest routine header in lines ``lo..n-2`` (``lo`` 120 lines up), else ``lo``."""
    lo = max(0, n - 1 - _ACC_LOOKBACK)
    heads = _file_index(facts).heads
    k = bisect_right(heads, n - 2)
    return heads[k - 1] if k and heads[k - 1] >= lo else lo


def _joined_span(facts: _LineFacts, lo: int, n: int) -> tuple[str, int, int, int]:
    """(joined text, offset of line ``lo``, offset of line ``n-1``, offset of line ``n``)."""
    index = _file_index(facts)
    offsets = index.offsets
    return index.text, offsets[lo], offsets[max(lo, n - 1)], offsets[n]


def _joined_slice(facts: _LineFacts, lo: int, n: int) -> str:
    """Lines ``lo..n-1`` of stripped code, one slice of the file's joined text."""
    text, start, _, end = _joined_span(facts, lo, n)
    return text[start:max(start, end - 1)]


def _routine_text(lines: list[str], n: int) -> str:
    """Stripped code from the enclosing routine's header (<= 120 lines up) to line n-1."""
    facts = _facts(lines)
    if len(_ACC_ROUTINE_MEMO) > _ACC_ROUTINE_MEMO_MAX:
        _ACC_ROUTINE_MEMO.clear()   # bounds retained text: a site needs only recent headers
    return _identity_memo(_ACC_ROUTINE_MEMO, lines, (n,), _routine_slice, facts, n)


def _routine_slice(facts: _LineFacts, n: int) -> str:
    return _joined_slice(facts, _routine_start(facts, n), n)


# --- loop body --------------------------------------------------------------
# Brace mode only when the header (or, Allman, the next line) holds `{`; else
# indentation, which stops at Ruby/Lua `end` (round 0 read past `end` into the
# next method). A one-line loop's own tail is its body; `do`/`repeat` join the
# trailing `} while (...)` line, which carries the condition.
_ACC_DO_REPEAT = re.compile(r"^\s{0,80}(?:do|repeat)\b")
_ACC_DO_TRAILER = re.compile(r"\}\s{0,8}while\b")


def _allman_next(facts: _LineFacts, h: int) -> bool:
    return h < len(facts.capped) and _line_code(facts, h).strip() == "{"


def _body_opener(facts: _LineFacts, h: int, header: str) -> tuple[int, bool]:
    """(the line the body hangs from, brace mode) for ``collect_scoped_body``."""
    if "{" in header or header.endswith((":", "do")):
        return h, "{" in header
    return (h + 1, True) if _allman_next(facts, h) else (h, False)


def _loop_trailer(facts: _LineFacts, h: int, header: str, size: int) -> list[str]:
    if not _ACC_DO_REPEAT.match(header):
        return []
    end = h + size - 1
    for k in range(end, min(len(facts.capped), end + 3)):
        code = _line_code(facts, k)
        if _ACC_DO_TRAILER.search(code):
            return [code]
    return []


def _build_loop_body(lines: list[str], h: int) -> list[str]:
    facts = _facts(lines)
    header = _line_code(facts, h - 1).rstrip()
    start, brace = _body_opener(facts, h, header)
    scoped = collect_scoped_body(facts.capped, start, brace, _ACC_BODY_LINES, _ACC_BODY_LINES + 40)
    body = [header, *(stripped_code(b) for b in scoped)]
    return body + _loop_trailer(facts, h, header, len(body))


def _loop_body(lines: list[str], h: int) -> list[str]:
    """Stripped code of the loop at header line ``h``, the header first (memoised)."""
    _facts(lines)   # resets the per-file memos when ``lines`` is a new file
    return _identity_memo(_ACC_BODY_MEMO, lines, ("loop", h), _build_loop_body, lines, h)


# --- pull roles ---------------------------------------------------------------
# A pull from something the process does not control. Suffixes are an explicit
# camel/snake set and case-sensitive, so `readdirSync(` is not a pull and a pull
# verb inside a longer name (`resolveListenHosts(`) never matches. `read` and
# `accept` count only with an empty, numeric, slice, `&mut` or buffer/size
# argument, or when the result is compared with end of stream (`!= -1`, `> 0`):
# `ConfigParser.read(paths)` and `visitor.accept(v)` are not pulls, and
# `read_text`/`read_bytes`/`readAll` stay materialisers (measured: widening `read`
# brought back a row through `json.loads(path.read_text())`).
_ACC_CAMEL_SUFFIX = "Line|Lines|Bytes|Async|String|Message|JSON|Exact|Until|Into|Chunk|From|All"
_ACC_SNAKE_RECV = r"_(?:line|lines|bytes|async|string|message|json|text|exact|until|into|some|chunk|from|all)"
_ACC_SNAKE_READ = r"_(?:line|lines|exact|until|into|some|chunk|from)"
_ACC_PULL = re.compile(
    r"(?:\.|\b)(?:recv|receive|fgets|fread|getline|readpartial|poll|consume|dequeue|listen|subscribe)"
    r"(?:" + _ACC_CAMEL_SUFFIX + "|" + _ACC_SNAKE_RECV + r"){0,2}\s{0,8}\("
    r"|(?:\.|\b)(?:read|accept)"
    r"(?:" + _ACC_CAMEL_SUFFIX.replace("|All", "").replace("Bytes|", "") + "|" + _ACC_SNAKE_READ
    + r"){0,2}\s{0,8}\(\s{0,4}"
    r"(?:\)|\d|[^()]{0,80}?\b(?:buf|buffer|size|chunk|len|length|count|bytes|n)\b|\w{0,30}\[|&\s{0,2}mut\b"
    r"|[^()]{0,80}?,\s{0,4}\d"   # a numeric size argument: `os.read(fd, 4096)`
    r"|(?:[^()]|\([^()]{0,40}\)){1,80}\)\s{0,4}\)?\s{0,4}(?:!==?|>=?|==|<=?)\s{0,4}(?:-\s{0,2}1|0|EOF)\b)"
    r"|(?:\.|\b)(?:nextLine|hasNextLine|hasNext|nextBytes)\s{0,8}\("
    # A read/receive routine named with a word prefix (`socket_read($s, 2048)`,
    # `stream_socket_recvfrom($s, 1500)`) when a later argument is a numeric size;
    # a bare `_read()` helper or an unsized `file_read(path)` is not a pull.
    r"|(?<=[A-Za-z0-9])_(?:read|recv(?:from)?|receive)\s{0,8}\([^()]{0,80}?,\s{0,4}\d"
    r"|\.\s{0,4}a?iter_\w{1,12}\s{0,4}\("
    r"|\.\s{0,4}(?:gets|readline|readpartial|each_line)\b|(?<![\w.])gets\b"
    r"|\.\s{0,4}get(?:_nowait)?\s{0,4}\(\s{0,4}(?:\)|timeout|block)"
    r"|(?:[=(,]|\bcase|\breturn)\s{0,8}<-\s{0,8}\w|(?<![\w.])input\s{0,8}\("
    r"|\.\s{0,4}input\s{0,4}\(\s{0,4}\)"
    r"|\.\s{0,4}take\s{0,4}\(\s{0,4}\)"   # a blocking pull from a queue
)
_ACC_PULL_CS = re.compile(
    r"(?:\.|\b)(?:Read|Receive|Accept|Recv)(?:" + _ACC_CAMEL_SUFFIX + r"|Async){0,2}\s{0,8}\("
)


@lru_cache(maxsize=2048)
def _pulls(text: str) -> bool:
    """True when ``text`` pulls from a peer, stream, queue or child process."""
    return bool(_ACC_PULL.search(text) or _ACC_PULL_CS.search(text))


# --- driver: what feeds the loop ----------------------------------------------
_ACC_INFINITE = re.compile(
    r"^\s{0,80}(?:\}\s{0,4})?(?:for\s{0,4}\{|for\s{0,4}\(\s{0,4};\s{0,4};\s{0,4}\)|loop\b|do\b"
    r"|repeat\b|(?:while|until)\s{0,4}\(?\s{0,4}(?:true|True|TRUE|1|false|False)\s{0,4}\)?"
    r"\s{0,4}(?:[:{]|do\b)?\s{0,4}$)"
)
_ACC_RANGE_CALL = re.compile(r"\brange\s{0,4}\(")
_ACC_RANGE_BOUND = re.compile(r"\brange\s{0,4}\((.{0,200})")
_ACC_COUNTED = re.compile(
    r"^\s{0,80}for\s{0,4}\([^;()]{0,120};[^;]{0,120};|\brange\s{0,4}\(|\.\.=?\s{0,4}\w|\.times\b"
)
_ACC_ITER_SPLIT = re.compile(r"\s(?:in|of)\s|\s:\s|\s<-\s|:=\s{0,4}range\s|\brange\s")
_ACC_FOR_HEADER = re.compile(r"^\s{0,80}(?:(?:async|await)\s{1,8})?for(?:each)?\b")
_ACC_HEADER_ADVANCE = re.compile(r"\.\s{0,8}Scan\s{0,8}\(")
_ACC_HEADER_BOUND = re.compile(r"(?:<=?|>=?)\s{0,4}(?:[2-9]|\d{2,20})\b")
_ACC_SOURCE_DELIM = re.compile(r"[(){]")
_ACC_PAREN_DELTA = {"(": 1, ")": -1, "{": 0}
_ACC_PARENS = re.compile(r"[()]")
# A materialiser in the iteration source means the data is already in memory.
_ACC_MATERIALISE = re.compile(
    r"\.\s{0,4}(?:split\w{0,8}|keys|items|values|entries|json|text|readlines|read_text|readAll\w{0,8}"
    r"|toList|collect)\s{0,4}\(\s{0,4}[^()]{0,40}\)\s{0,4}[\])}:]{0,3}\s{0,4}$"
    r"|\b(?:readdir\w{0,8}|listdir|glob|rglob|iterdir|walk|sorted|list|enumerate|zip)\s{0,4}\("
)
_ACC_INMEMORY = re.compile(
    r"(?:StringIO|BytesIO|StringReader|strings\s{0,2}\.\s{0,2}NewReader|bytes\s{0,2}\.\s{0,2}NewReader"
    r"|ByteArrayInputStream|Cursor::new)\s{0,4}\("
)
_ACC_RECV_BEFORE_PULL = re.compile(
    r"(?<![\w$])([A-Za-z_$][\w$]{0,63})\s{0,2}\.\s{0,2}"
    r"(?:read\w{0,12}|Read\w{0,12}|Scan|recv\w{0,12}|next\w{0,8}|hasNext\w{0,8}|gets)\s{0,2}[\(\b]?"
)
_ACC_BIND_TEMPLATE = r"NAME(?<![\w$.]NAME)\s{0,4}(?::[^=\n]{0,60})?(?::=|=(?![=>]))([^\n]{0,300})"
_ACC_AS_TEMPLATE = r"\bas\s{1,4}NAME\b"
_ACC_CHAN_TEMPLATE = (
    r"NAME(?<![\w$.]NAME)"
    r"(?:\s{0,4}(?::=|=)\s{0,4}make\s{0,4}\(\s{0,4}chan\b|\s{1,4}(?:<-\s{0,2})?chan\b)"
)
# A bound range is driven only when its bound reaches peer data.
_ACC_PEER_ARG_WORDS = frozenset({"req", "request", "args", "headers", "header", "params", "query", "form", "body"})
_ACC_HEADER_LIMIT_PREFIXES = ("max", "limit", "cap", "budget", "quota", "ceil", "hwm", "watermark")
# The role-name fallback for an UNBOUND source (a parameter or attribute): its
# LAST word is a source or peer role. A heuristic, named as one in SKILLS.md:
# `client_sock`, `upstreamConn`, `self.rfile` match; `ws_urls`, `req.Messages`
# do not; a parameter named `ws` that is really a worksheet still reports.
_ACC_ROLE_SOURCE_WORDS = frozenset({
    "stdin", "stdout", "stderr", "sock", "socket", "conn", "connection", "ws", "websocket", "stream",
    "reader", "subscription", "consumer", "rfile", "pipe", "fd", "rl", "inbox", "pubsub", "channel",
    "req", "request", "res", "resp", "response", "body", "urlopen", "upload", "payload",
})
# A BOUND source is a stream when the HEAD NOUN of its value (the last word of the
# last identifier segment) is a producer. Revision 1 tested every word of the
# value; measured on one tree, `resolveListenHosts(...)` (word `listen`) and
# `step.stdoutTail` (word `stdout`) made in-memory loops driven.
_ACC_STREAM_PRODUCER_WORDS = frozenset({
    "connect", "connection", "accept", "socket", "sock", "urlopen", "popen", "makefile", "listen",
    "subscribe", "stdin", "stdout", "stream", "request", "conn", "consumer", "pipe",
})


# A keyword argument (`Popen(cmd, stdout=PIPE)`, `get(url, stream=True)`) is not a
# binding of its name: revision 1 read `stdout=subprocess.PIPE` as
# the value of `stdout`, so the child-process loop after it was missed. A `name=`
# is a keyword argument when it follows `(` or `,` inside a CALL that is still
# open on its line; `while ((line = r.readLine()) ...)` and `if (x = next())`
# open their paren after a control word or another paren, so they stay bindings.
_ACC_KWARG_LOOKBACK = 300
_ACC_CONTROL_WORDS = frozenset({
    "if", "elif", "while", "for", "foreach", "until", "unless", "switch", "return", "when", "match",
    "catch", "with", "and", "or", "not", "in",
})


def _unclosed_paren(prefix: str) -> int:
    depth = 0
    for m in reversed(list(_ACC_PARENS.finditer(prefix))):
        depth += 1 if m.group() == ")" else -1
        if depth < 0:
            return m.start()
    return -1


def _opens_a_call(before: str) -> bool:
    tail = _ACC_RECEIVER_TAIL.search(before[-72:])
    return bool(tail) and tail.group(1) not in _ACC_CONTROL_WORDS


def _keyword_argument(text: str, m: _FormMatch) -> bool:
    whole = m.group(0)
    if whole[:whole.find("=") + 1].endswith(":="):   # a walrus or Go `:=` is always a binding
        return False
    at = m.start()
    prefix = text[max(text.rfind("\n", 0, at) + 1, at - _ACC_KWARG_LOOKBACK):at]
    if not prefix.rstrip().endswith(("(", ",")):
        return False
    open_at = _unclosed_paren(prefix)
    return open_at >= 0 and _opens_a_call(prefix[:open_at])


def _bindings(template: str, name: str, text: str) -> Iterable[_FormMatch]:
    """Matches of a binding ``template`` for ``name`` that are not keyword arguments."""
    return (m for m in _form_finditer(template, name, text) if not _keyword_argument(text, m))


def _first_binding(template: str, name: str, text: str) -> _FormMatch | None:
    if name not in text:
        return None
    return next(iter(_bindings(template, name, text)), None)


def _last_binding(template: str, name: str, text: str) -> _FormMatch | None:
    """The binding nearest the END of ``text`` (read backwards, so a long window stays bounded)."""
    if name not in text:
        return None
    return next((m for m in _form_rsearch(template, name, text) if not _keyword_argument(text, m)), None)


def _binding_rhs(name: str, routine_text: str) -> str | None:
    """The value of the LAST assignment of ``name`` in the routine, or its `as` line."""
    last = _last_binding(_ACC_BIND_TEMPLATE, name, routine_text)
    if last:
        return last.group(1)
    alias = _form_search(_ACC_AS_TEMPLATE, name, routine_text)
    return routine_text[:alias.start()].rsplit("\n", 1)[-1] if alias else None


def _source_end(src: str) -> int:
    """Where the iteration source ends: the header's closing `)` or its `{`."""
    depth = 0
    for m in _ACC_SOURCE_DELIM.finditer(src):
        if depth == 0 and m.group() != "(":
            return m.start()
        depth += _ACC_PAREN_DELTA[m.group()]
    return len(src)


def _iter_source(header: str) -> str:
    parts = _ACC_ITER_SPLIT.split(header, maxsplit=1)
    src = parts[1] if len(parts) == 2 else ""
    return src[:_source_end(src)].strip().rstrip(":").strip()


def _last_two(segs: list[str]) -> tuple[str | None, str | None]:
    return (segs[-1] if segs else None), (segs[-2] if len(segs) > 1 else None)


def _last_callee_and_receiver(src: str) -> tuple[str | None, str | None]:
    """The last identifier of ``src`` (the callee of its last call) and the one before it."""
    src = src.strip()
    if not src.endswith(")"):
        segs = _ACC_IDENT.findall(src[-200:])
        return (segs[-1] if segs else None), None
    at = opening_bracket(src, parens_only=True)
    return _last_two(_ACC_IDENT.findall(src[:at].rstrip()[-200:])) if at >= 0 else (None, None)


def _head_noun(rhs: str) -> str | None:
    last, _ = _last_callee_and_receiver(rhs.strip().rstrip(";"))
    words = identifier_words(last) if last else ()
    return words[-1] if words else None


def _is_chan(name: str, routine_text: str) -> bool:
    return bool(_form_search(_ACC_CHAN_TEMPLATE, name, routine_text))


def _role_named_source(name: str) -> bool:
    words = identifier_words(name)
    return bool(words) and words[-1] in _ACC_ROLE_SOURCE_WORDS


def _bound_source_verdict(rhs: str) -> bool | None:
    """False: an in-memory wrapper; True: a pull or a producer; None: undecided."""
    if _ACC_INMEMORY.search(rhs):
        return False
    return _streams(rhs) or None


def _streams(rhs: str) -> bool:
    return _pulls(rhs) or _produces(rhs)


# A reader constructed over a source is that source: the head noun
# of `BufReader::new(stream)` is `new`, so revision 1 left it undecided. The
# constructed TYPE must be a wrapper role (reader, scanner, stream, decoder) and
# its first argument a source role or a pull; `BufReader::new(text.as_bytes())`
# wraps memory and stays undecided.
_ACC_WRAPPER_TYPE_WORDS = frozenset({"reader", "scanner", "stream", "decoder"})


def _constructed_type(rhs: str) -> str | None:
    callee, receiver = _last_callee_and_receiver(rhs)
    return receiver if callee == "new" else callee


def _first_argument(rhs: str) -> str:
    at = opening_bracket(rhs, parens_only=True)
    return rhs[at + 1:-1].split(",", 1)[0].strip() if at >= 0 else ""


def _argument_is_source(arg: str) -> bool:
    last, _ = _last_callee_and_receiver(arg) if arg else (None, None)
    return _pulls(arg) or bool(last and _role_named_source(last))


def _wrapper_type(rhs: str) -> bool:
    kind = _constructed_type(rhs) if rhs.endswith(")") else None
    words = identifier_words(kind) if kind else ()
    return bool(words) and words[-1] in _ACC_WRAPPER_TYPE_WORDS


def _wraps_a_source(rhs: str) -> bool:
    rhs = rhs.strip().rstrip(";").rstrip("?").strip()
    return _wrapper_type(rhs) and _argument_is_source(_first_argument(rhs))


def _name_source_verdict(name: str, routine_text: str) -> bool | None:
    rhs = _binding_rhs(name, routine_text)
    if rhs is None:
        return _role_named_source(name) or None
    return _bound_source_verdict(rhs)


def _first_verdict(verdicts: Iterable[bool | None]) -> bool:
    return next((v for v in verdicts if v is not None), False)


def _named_source_is_input(src: str, routine_text: str) -> bool:
    last, receiver = _last_callee_and_receiver(src)
    if not last:
        return False
    if _is_chan(last, routine_text):
        return True   # Go `range ch` over a channel made or typed in the routine
    return _names_verdict((last, receiver), routine_text) or _receiver_chain_is_stream(src, routine_text)


# The receiver CHAIN of a source: `sys.stdin.buffer`, `stdin.lock().lines()`
# and `proc.stdout` iterate a stream reached through an attribute or a call on a
# stream. Only STREAM roles count on the chain: `req.Messages` and `body.items`
# are fields of a request already decoded into memory.
_ACC_STREAM_ROLE_WORDS = frozenset({
    "stdin", "stdout", "stderr", "sock", "socket", "stream", "pipe", "rfile", "reader", "fd",
})


def _chain_receivers(src: str) -> list[str]:
    head = src[:opening_bracket(src, parens_only=True)] if src.endswith(")") else src
    return _ACC_IDENT.findall(head[-200:])[:-1]


def _receiver_is_stream(name: str, routine_text: str) -> bool:
    """An unbound stream role, or a receiver bound to a PRODUCER (`proc = Popen(...)`).

    A receiver bound to a PULL is data already read: `registry = await params.read()`
    then `registry.entries` iterates memory (measured: one row on one tree).
    """
    rhs = _binding_rhs(name, routine_text)
    if rhs is None:
        words = identifier_words(name)
        return bool(words) and words[-1] in _ACC_STREAM_ROLE_WORDS
    return not _ACC_INMEMORY.search(rhs) and _produces(rhs)


def _produces(rhs: str) -> bool:
    return _head_noun(rhs) in _ACC_STREAM_PRODUCER_WORDS or _wraps_a_source(rhs)


def _receiver_chain_is_stream(src: str, routine_text: str) -> bool:
    return any(_receiver_is_stream(n, routine_text) for n in _chain_receivers(src.strip()))


def _names_verdict(names: tuple[str | None, ...], routine_text: str) -> bool:
    return _first_verdict(_name_source_verdict(n, routine_text) for n in names if n)


def _source_is_input(src: str, routine_text: str) -> bool:
    """An iteration source fed by input: decided by binding first, by role name last."""
    if _ACC_MATERIALISE.search(src):
        return False
    if _pulls(src):
        return True
    return _named_source_is_input(src, routine_text)


def _binding_hops(arg: str, routine_text: str) -> list[str]:
    """The bound value of each identifier in ``arg``: one assignment hop back."""
    if not routine_text:
        return []
    return list(filter(None, (_binding_rhs(i, routine_text) for i in _ACC_IDENT.findall(arg))))


def _range_bound_text(header: str, routine_text: str) -> str | None:
    m = _ACC_RANGE_BOUND.search(header)
    return " ".join([m.group(1), *_binding_hops(m.group(1), routine_text)]) if m else None


def _counted_driven(header: str, routine_text: str) -> bool:
    """`range(n)` is driven when n, one assignment hop back, carries peer data or a pull."""
    arg = _range_bound_text(header, routine_text)
    if arg is None:
        return False
    return bool(_words_of(arg) & _ACC_PEER_ARG_WORDS) or _pulls(arg)


def _in_memory_binding(name: str, routine_text: str) -> bool:
    rhs = _binding_rhs(name, routine_text)
    return bool(rhs and _ACC_INMEMORY.search(rhs))


def _header_pull_in_memory(text: str, routine_text: str) -> bool:
    """The pulled receiver is bound to an in-memory wrapper (`BufferedReader(new StringReader(s))`)."""
    return any(_in_memory_binding(m.group(1), routine_text) for m in _ACC_RECV_BEFORE_PULL.finditer(text))


def _bound_operand_caps(header: str) -> bool:
    if any(w.startswith(_ACC_HEADER_LIMIT_PREFIXES) for w in _words_of(header)):
        return True
    return bool(_ACC_HEADER_BOUND.search(header))


def _is_infinite(header: str) -> bool:
    return bool(_ACC_INFINITE.match(header))


def _is_range(header: str) -> bool:
    return bool(_ACC_RANGE_CALL.search(header))


def _is_iteration(header: str) -> bool:
    return bool(_ACC_FOR_HEADER.match(header) and _ACC_ITER_SPLIT.search(header))


def _is_counted(header: str) -> bool:
    return bool(_ACC_COUNTED.search(header))


def _header_pulls(header: str) -> bool:
    return _pulls(header) or bool(_ACC_HEADER_ADVANCE.search(header))


def _body_pulls(body_text: str) -> bool:
    """A pull on any body line; per line, so every pattern reads a capped line."""
    return any(_pulls(line) for line in body_text.split("\n"))


def _body_pull_in_memory(body_text: str, routine_text: str) -> bool:
    return any(_header_pull_in_memory(line, routine_text) for line in body_text.split("\n"))


def _infinite_driven(header: str, body_text: str, routine_text: str) -> bool:
    return _body_pulls(body_text)


def _range_driven(header: str, body_text: str, routine_text: str) -> bool:
    return _counted_driven(header, routine_text)


def _iteration_driven(header: str, body_text: str, routine_text: str) -> bool:
    return _source_is_input(_iter_source(header), routine_text)


def _header_pull_driven(header: str, body_text: str, routine_text: str) -> bool:
    return not _header_pull_in_memory(header, routine_text)


def _body_pull_driven(header: str, body_text: str, routine_text: str) -> bool:
    """Any other `while`: the body pulls and the header is not bounded by a limit."""
    return (_body_pulls(body_text) and not _bound_operand_caps(header)
            and not _body_pull_in_memory(body_text, routine_text))


# Loop kinds, tried in order; the first whose header test holds decides.
_ACC_DRIVERS: tuple[tuple[Callable[[str], bool], Callable[[str, str, str], bool]], ...] = (
    (_is_infinite, _infinite_driven),          # `while True` / `for {}` / `loop`: the body pulls
    (_is_range, _range_driven),                # `range(...)`: the bound reaches peer data
    (_is_iteration, _iteration_driven),        # `for x in/of/: src`
    (_is_counted, _range_driven),              # C-style `for (a; b; c)`
    (_header_pulls, _header_pull_driven),      # `while ((line = r.readLine()) != null)`
)


def _loop_driven(header: str, body_text: str, routine_text: str) -> bool:
    """True when the loop's repetition is fed by input the process does not control."""
    for applies, driven in _ACC_DRIVERS:
        if applies(header):
            return driven(header, body_text, routine_text)
    return _body_pull_driven(header, body_text, routine_text)


# --- cap ------------------------------------------------------------------------
# A line caps growth only when it compares the accumulator's SIZE (or a running
# total grown from sizes) with a LIMIT (a limit-role name or a literal >= 2) and
# either is the loop header or EXITS or TRIMS anywhere in the block it opens.
# A retry counter, `len(lines) > 0` and an unrelated collection's size are not
# caps. Revision 1 looked only at the next line, so the canonical capped read
# loop `if (total > maxBytes) { try { await r.cancel() } catch {} throw ... }`
# was reported (measured on one tree).
_ACC_GENERIC = re.compile(r"(?<=[\w$])<[\w$\s,.\[\]?:&*']{0,80}>")
_ACC_REL = re.compile(r"(?<![<>=\-!])(?:<=?|>=?|==)(?![<>=\-])")
_ACC_UPPER = re.compile(r"(?<![<>=\-!])<=?(?![<>=\-])|(?<![<>=\-!])>=?(?![<>=\-])")
_ACC_EXIT = re.compile(
    r"\b(?:break|return|raise|throw|panic|exit|abort)\b|\.\s{0,2}(?i:pop\w{0,12}|shift|clear|truncate"
    r"|remove\w{0,12}|dequeue\w{0,12}|reset|setlength|drain)\s{0,2}\(|\bdel\s"
)
_ACC_NUMERIC_BOUND = re.compile(
    r"(?:<=?|>=?|==)\s{0,4}(?:[2-9]|\d{2,20})\b|\b(?:[2-9]|\d{2,20})\s{0,4}(?:<=?|>=?|==)"
)
_ACC_NUMERIC_LITERAL = re.compile(r"\b(?:[2-9]|\d{2,20})\b")
_ACC_GUARD_IF = re.compile(r"^\s{0,80}(?:\}\s{0,4}else\s{1,4})?(?:if|elif|unless)\b")
_ACC_SIZE_CALL = re.compile(r"\blen\s{0,2}\(|\bn\b")
_ACC_RUNNING_TOTAL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]{0,63})\s{0,4}\+=\s{0,4}(.{0,120})")
_ACC_CAPACITY = re.compile(
    r"\b(?:maxlen|maxsize|capacity|bounded|max_size)\b|ArrayBlockingQueue"
    r"|LinkedBlockingQueue\s{0,2}\(\s{0,2}\d|LRU|lru"
)
_ACC_WRAPPER_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$.]{0,80})\s{0,4}\(")
_ACC_CHAIN = re.compile(r"[A-Za-z_$][\w$]{0,63}(?:\.[A-Za-z_$][\w$]{0,63}){0,3}")
_ACC_LIMIT_PREFIXES = (
    "max", "limit", "cap", "budget", "quota", "ceil", "hwm", "watermark", "maximum", "bound",
)
_ACC_SIZE_LAST_WORDS = frozenset({"len", "length", "size", "count", "bytes", "nbytes"})
_ACC_TAKE_WORDS = frozenset({"take", "islice", "head"})
_ACC_LIMIT_PAIRS = frozenset({("high", "water"), ("water", "mark")})
_ACC_FIRST_BIND_TEMPLATE = r"NAME(?<![\w$.]NAME)\s{0,4}(?::[^=]{0,60})?=(?![=>])([^\n]{0,300})"
_ACC_CHAIN_BIND_TEMPLATE = r"NAME(?<![\w$]NAME)\s{0,4}(?::=|=(?![=>]))([^\n]{0,300})"
# `len(X)` and `X.<member>` over a space-free row; the look-ahead lets every
# segment of `a.b.length` be a candidate, as the per-name template did.
_ACC_LEN_OF = re.compile(r"len\(([^()\s]{1,128})\)")
_ACC_MEMBER_OF = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]{0,127})(?=\.([A-Za-z_]\w{0,30}))")
_ACC_TOTAL_TEMPLATE = r"NAME(?<![\w$.]NAME)(?![\w$])"
_ACC_GROWS_TEMPLATE = r"NAME(?<![\w$.]NAME)\s{0,4}(?:\.|\+=|<<|\[)"
# Trim and reset verbs, without case and by prefix: C#
# `Clear()`/`RemoveAt(0)`/`Dequeue()`, Java `removeFirst()`/`setLength(0)`, Rust
# `pop_front()`/`drain(..)`, Go `Reset()`. A removal of any kind counts: the
# rule asks whether growth is bounded, and a loop that also removes is not the
# monotone accumulation CWE-770 names.
_ACC_TRIM_VERBS = (
    r"(?i:pop\w{0,12}|shift|clear|truncate|splice|remove\w{0,12}|dequeue\w{0,12}|reset|setlength"
    r"|drain|poll\w{0,12}|discard|delete)"
)
_ACC_TRIM_TEMPLATE = r"NAME(?<![\w$.]NAME)\s{0,2}\.\s{0,2}" + _ACC_TRIM_VERBS + r"\s{0,2}\("
_ACC_DEL_TEMPLATE = r"del(?<![\w]del)\s{1,4}NAME\b"
_ACC_TRIM_CALL = re.compile(r"\.\s{0,2}" + _ACC_TRIM_VERBS + r"\s{0,2}\(")
# `del` asserts its boundary AFTER the literal (`(?<!\w)del` spans the same
# matches): a pattern that starts with a literal lets the scan skip to it.
_ACC_DEL_CALL = re.compile(r"del(?<!\wdel)\s{1,4}([A-Za-z_$][\w$]{0,63})")
# Either of the two above, in one search: a body row with neither yields no trim candidate.
_ACC_TRIM_ANY = re.compile(f"{_ACC_TRIM_CALL.pattern}|{_ACC_DEL_CALL.pattern}")


def _last_word_is_size(ident: str) -> bool:
    words = identifier_words(ident)
    return bool(words) and words[-1] in _ACC_SIZE_LAST_WORDS


def _sizes(acc: str, code: str) -> bool:
    """``code`` reads the accumulator's size: `len(acc)` or a size-role member of it."""
    return acc in _sized_names(code)


@lru_cache(maxsize=4096)
def _sized_names(code: str) -> frozenset[str]:
    """Every name whose size ``code`` reads, computed once per row for all accumulators.

    Revision 1 asked per (accumulator, row): 77 receivers under one body made
    5,929 pattern builds and searches per loop (the `cmp` density probe).
    """
    s = _squeezed(code)
    members = (m.group(1) for m in _ACC_MEMBER_OF.finditer(s) if _last_word_is_size(m.group(2)))
    return frozenset((*_ACC_LEN_OF.findall(s), *members))


def _word_names_limit(words: tuple[str, ...]) -> bool:
    if any(w.startswith(_ACC_LIMIT_PREFIXES) for w in words):
        return True
    return any(pair in _ACC_LIMIT_PAIRS for pair in zip(words, words[1:]))


@lru_cache(maxsize=4096)
def _squeezed(code: str) -> str:
    """``code`` without spaces; cached because every accumulator of a loop asks about the same rows."""
    return code.replace(" ", "")


@lru_cache(maxsize=4096)
def _names_limit(code: str) -> bool:
    return any(_word_names_limit(identifier_words(i)) for i in _ACC_IDENT.findall(code))


def _mentions_size(text: str) -> bool:
    if _ACC_SIZE_CALL.search(text):
        return True
    return any(_last_word_is_size(i) for i in _ACC_IDENT.findall(text))


def _running_totals(acc: str, body: list[str]) -> set[str]:
    """Totals grown FROM SIZES (`t += len(c)`, `.byteLength`); a `+= 1` retry counter is not one.

    The body is scanned ONCE (memoised per body object) and ``acc`` excluded
    afterwards: per accumulator, 77 distinct receivers under one near-cap body
    re-ran the scan 77 times (41 ms/KB measured).
    """
    return {name for name in _body_size_totals(body) if name != acc}


def _body_size_totals(body: list[str]) -> tuple[str, ...]:
    return _identity_memo(_ACC_TOTALS_MEMO, body, (id(body),), _collect_size_totals, body)


def _collect_size_totals(body: list[str]) -> tuple[str, ...]:
    return tuple(filter(None, map(_total_from_size, body)))


def _total_from_size(code: str) -> str | None:
    """The receiver of the first `name += <size>` on ``code``; rows without `+=` are skipped first."""
    m = _ACC_RUNNING_TOTAL.search(code) if "+=" in code else None
    return m.group(1) if m and _mentions_size(m.group(2)) else None


def _brace_block(rows: list[str], i: int) -> list[str]:
    out, depth = [rows[i]], rows[i].count("{") - rows[i].count("}")
    for row in rows[i + 1:i + 1 + _ACC_CAP_BLOCK_LINES]:
        if depth <= 0:
            break
        out.append(row)
        depth += row.count("{") - row.count("}")
    return out


def _indent_block(rows: list[str], i: int) -> list[str]:
    out, col = [rows[i]], indent_width(rows[i])
    for row in rows[i + 1:i + 1 + _ACC_CAP_BLOCK_LINES]:
        if row.strip() and indent_width(row) <= col:
            break
        out.append(row)
    return out


def _block_after(rows: list[str], i: int) -> list[str]:
    """The block ``rows[i]`` opens (itself included): brace depth, indentation, or one line."""
    if "{" in rows[i]:
        return _brace_block(rows, i)
    if rows[i].rstrip().endswith((":", "then", "do")):
        return _indent_block(rows, i)
    return rows[i:i + 2]


def _size_subject(acc: str, code: str, totals: set[str]) -> bool:
    return _sizes(acc, code) or any(_form_search(_ACC_TOTAL_TEMPLATE, t, code) for t in totals)


def _bounds_size(acc: str, code: str, totals: set[str]) -> bool:
    if not _size_subject(acc, code, totals):
        return False
    return _names_limit(code) or bool(_ACC_NUMERIC_BOUND.search(code))


def _block_exits(rows: list[str], i: int) -> bool:
    return any(_ACC_EXIT.search(row) for row in _block_after(rows, i))


def _cap_line_at(acc: str, rows: list[str], i: int, code: str, totals: set[str]) -> bool:
    if not _bounds_size(acc, code, totals):
        return False
    return bool(_ACC_LOOP_HEADER.match(code)) or _block_exits(rows, i)


def _guard_condition(code: str) -> bool:
    """An `if`/`elif`/`unless` with an upper-bound comparison."""
    return bool(_ACC_GUARD_IF.match(code) and _ACC_UPPER.search(code))


def _guard_limit(code: str) -> bool:
    return _names_limit(code) or bool(_ACC_NUMERIC_LITERAL.search(code))


def _guards_size(acc: str, code: str, totals: set[str]) -> bool:
    if not _guard_condition(code):
        return False
    return _size_subject(acc, code, totals) and _guard_limit(code)


def _guard_line_at(acc: str, rows: list[str], i: int, code: str, totals: set[str]) -> bool:
    """The growth sits inside an `if` that bounds the size from above (`if (n < 16384) { b.push(c) }`)."""
    if not _guards_size(acc, code, totals):
        return False
    return any(_form_search(_ACC_GROWS_TEMPLATE, acc, row) for row in _block_after(rows, i)[1:])


def _is_cap_wrapper(callee: str) -> bool:
    words = identifier_words(callee)
    if any(w.startswith(_ACC_LIMIT_PREFIXES) for w in words):
        return True
    return bool(words) and words[-1] in _ACC_TAKE_WORDS


def _has_cap_wrapper(text: str) -> bool:
    """A call whose words name a limit, or take/islice/head (`io.LimitReader`, `.take(n)`)."""
    return any(_is_cap_wrapper(m.group(1)) for m in _ACC_WRAPPER_CALL.finditer(text))


def _iter_tail(header: str) -> str:
    parts = _ACC_ITER_SPLIT.split(header, maxsplit=1)
    return parts[1] if len(parts) == 2 else header


def _bound_with_capacity(acc: str, routine_text: str) -> bool:
    if not routine_text:
        return False   # nothing above the site can bind it (see _feeds)
    m = _first_binding(_ACC_FIRST_BIND_TEMPLATE, acc, routine_text)
    return bool(m and _ACC_CAPACITY.search(m.group(1)))


def _rhs_of_chain(chain: str, routine_text: str) -> str | None:
    last = _last_binding(_ACC_CHAIN_BIND_TEMPLATE, chain, routine_text)
    return last.group(1) if last else None


def _hop_capped(chain: str, routine_text: str) -> bool:
    hop = _rhs_of_chain(chain, routine_text)
    return bool(hop) and _has_cap_wrapper(hop)


def _receiver_capped(name: str, routine_text: str) -> bool:
    rhs = _binding_rhs(name, routine_text)
    if not rhs:
        return False
    args = _ACC_CHAIN.findall(rhs.split("(", 1)[-1])
    return _has_cap_wrapper(rhs) or any(_hop_capped(a, routine_text) for a in args)


def _pull_receiver_capped(header: str, routine_text: str) -> bool:
    """A cap wrapper on the binding of a header-pull receiver, one hop: `bufio.NewScanner(io.LimitReader(c, N))`."""
    return any(_receiver_capped(m.group(1), routine_text)
               for m in _ACC_RECV_BEFORE_PULL.finditer(header))


def _source_capped(header: str, routine_text: str) -> bool:
    """The loop's source is capped by a wrapper: the same for every accumulator of the loop."""
    return _has_cap_wrapper(_iter_tail(header)) or _pull_receiver_capped(header, routine_text)




class _BodyIndex(NamedTuple):
    trimmed: frozenset[str]   # names a body row trims (a trim verb or `del`)
    reset: frozenset[str]     # names a body row (header excluded) resets or re-slices


def _trim_candidates(row: str) -> set[str]:
    names: set[str] = set()
    for m in islice(_ACC_TRIM_CALL.finditer(row), _ACC_VERBS_PER_LINE):
        tail = _ACC_RECEIVER_TAIL.search(row[max(0, m.start() - 72):m.start()])
        names |= {tail.group(1), tail.group(1).lstrip("@")} if tail else set()
    return names | {m.group(1) for m in islice(_ACC_DEL_CALL.finditer(row), _ACC_VERBS_PER_LINE)}


def _trims(name: str, row: str) -> bool:
    return bool(_form_search(_ACC_TRIM_TEMPLATE, name, row) or _form_search(_ACC_DEL_TEMPLATE, name, row))


def _may_trim(row: str) -> bool:
    return "(" in row or "del" in row


def _trim_names(row: str) -> set[str]:
    if not _may_trim(row):
        return set()   # neither a trim call nor `del`: skip both patterns
    return {n for n in _trim_candidates(row) if _trims(n, row)}


def _reset_name(row: str) -> str | None:
    m = _ACC_RESET_HEAD.match(row) if "=" in row else None
    return m.group(1) if m and _resets(m.group(1), row) else None


def _build_body_index(body: list[str]) -> _BodyIndex:
    return _BodyIndex(_trimmed_names([body[i] for i in _active_rows(body)]), _reset_names(body))


def _trimmed_names(rows: list[str]) -> frozenset[str]:
    """Names trimmed by ``rows``; a row with neither a trim call nor `del` is skipped by one search."""
    return frozenset(n for row in rows if _ACC_TRIM_ANY.search(row) for n in _trim_names(row))


def _reset_names(body: list[str]) -> frozenset[str]:
    rows = [body[i] for i in _active_rows(body) if i and "=" in body[i]]   # the header never resets
    return frozenset(filter(None, map(_reset_name, rows)))


# One search per body row for what every per-row analysis of a loop body needs
# (a declaration word, a trim call or `del`, an `=`, a comparison): most rows of
# a body hold none of them, and each analysis then reads only the rows that do.
_ACC_ROW_HINT = re.compile(f"{_ACC_DECL_HINT.pattern}|{_ACC_TRIM_ANY.pattern}|[=<>]")
# The same, for one search of the JOINED body: its whitespace may not cross a
# row break, so every match lies in one row and a row matches exactly when
# `_ACC_ROW_HINT.search(row)` would.
_ACC_ROW_HINT_ROWS = re.compile(_ACC_ROW_HINT.pattern.replace(r"\s", r"[^\S\n]"))


def _active_rows(body: list[str]) -> tuple[int, ...]:
    """Indexes of the rows of ``body`` that any per-row analysis can use (memoised per body)."""
    return _identity_memo(_ACC_ACTIVE_MEMO, body, (id(body),), _find_active_rows, body)


def _find_active_rows(body: list[str]) -> tuple[int, ...]:
    starts = list(accumulate(map((1).__add__, map(len, body)), initial=0))
    return tuple(_lines_with(_ACC_ROW_HINT_ROWS, _body_text(body), starts))


def _body_index(body: list[str]) -> _BodyIndex:
    """Trims and resets of a loop body, found ONCE per body for every accumulator."""
    return _identity_memo(_ACC_BODY_INDEX_MEMO, body, (id(body),), _build_body_index, body)


def _trimmed(acc: str, body: list[str]) -> bool:
    """Test oracle: the analysis reads ``_CapProfile.trims``; unit tests ask by body."""
    return acc in _body_index(body).trimmed


def _has_relation(row: str) -> bool:
    return "<" in row or ">" in row or "==" in row


def _comparison_rows(rows: list[str], candidates: list[int]) -> tuple[tuple[int, str], ...]:
    """(index, generic-stripped code) of every row with a comparison: the only rows that can cap.

    Only the ``candidates`` rows can hold one (every other row lacks `<`, `>` and `=`).
    """
    out = []
    for i in candidates:
        code = _relation_code(rows[i])
        if code:
            out.append((i, code))
    return tuple(out)


def _relation_code(row: str) -> str | None:
    if not _has_relation(row):
        return None   # no `<`, `>` or `==`: skip the generic strip and the pattern
    code = _ACC_GENERIC.sub(" ", row)   # `Vec<u8>` is not one
    return code if _ACC_REL.search(code) else None


def _cap_rows(header: str, body: list[str]) -> tuple[list[str], tuple[tuple[int, str], ...]]:
    """The loop's rows and its comparison rows, built once per body (not per accumulator)."""
    return _identity_memo(_ACC_CAP_ROWS_MEMO, body, (id(body), header), _build_cap_rows, header, body)


def _build_cap_rows(header: str, body: list[str]) -> tuple[list[str], tuple[tuple[int, str], ...]]:
    rows = [header, *body]
    return rows, _comparison_rows(rows, [0, *(i + 1 for i in _active_rows(body))])


def _caps_at(acc: str, rows: list[str], i: int, code: str, totals: set[str]) -> bool:
    return _cap_line_at(acc, rows, i, code, totals) or _guard_line_at(acc, rows, i, code, totals)


def _any_cap_row(acc: str, header: str, body: list[str]) -> bool:
    rows, compared = _cap_rows(header, body)
    if not compared:
        return False   # no comparison row: nothing can cap, and the totals need not be read
    totals = _running_totals(acc, body)
    return any(_caps_at(acc, rows, i, code, totals) for i, code in compared if _size_subject(acc, code, totals))


class _CapProfile(NamedTuple):
    trims: frozenset[str]   # names trimmed, reset or re-sliced in the body
    compared: bool          # the loop has a comparison row (the only rows that can cap)
    source_capped: bool     # the loop's source is wrapped in a cap


def _build_cap_profile(header: str, body: list[str], routine_text: str) -> _CapProfile:
    index = _body_index(body)
    return _CapProfile(index.trimmed | index.reset, bool(_cap_rows(header, body)[1]),
                       _source_capped(header, routine_text))


def _cap_profile(header: str, body: list[str], routine_text: str) -> _CapProfile:
    return _identity_memo(_ACC_CAP_MEMO, body, (id(body), header), _build_cap_profile, header, body, routine_text)


def _profile_caps(acc: str, profile: _CapProfile) -> bool:
    return acc in profile.trims or profile.source_capped


def _capped_by(acc: str, profile: _CapProfile, header: str, body: list[str], routine_text: str) -> bool:
    if _profile_caps(acc, profile) or _bound_with_capacity(acc, routine_text):
        return True
    return profile.compared and _any_cap_row(acc, header, body)


def _capped(acc: str, header: str, body: list[str], routine_text: str) -> bool:
    """Something in the loop bounds ``acc``'s growth.

    Everything that does not depend on ``acc`` is found once per loop body
    (`_cap_profile`); per accumulator only set lookups, one binding read and,
    when the body has a comparison row, the cap-row test remain.
    """
    return _capped_by(acc, _cap_profile(header, body, routine_text), header, body, routine_text)


# --- input-event callback --------------------------------------
# `req.on('data', c => chunks.push(c))` repeats once per chunk the peer sends.
# The callback body is judged like a loop body: its caps, guards and trims count
# (revision 1 reported every callback sink; measured on one tree, two capped
# `'data'` handlers were reported).
# Also the assigned form, `ws.onmessage = (ev) => ...`.
_ACC_CALLBACK = re.compile(
    r"\.\s{0,4}(?:on|once|addListener|addEventListener|subscribe)\s{0,4}\(\s{0,4}['\"]"
    r"(?:data|message|chunk|line|readable|text|frame)['\"]"
    r"|\.\s{0,4}on(?:data|message|chunk|line|readable|text|frame)\s{0,4}=(?![=>])"
)
_ACC_KEEP_WALKING = -1   # never a verdict: a found opener is a 1-based line


def _callback_verdict(facts: _LineFacts, j: int) -> int | None:
    if _ACC_CALLBACK.search(facts.capped[j]):
        return j + 1
    return None if _ACC_SCOPE_HEADER.match(_line_code(facts, j)) else _ACC_KEEP_WALKING


def _walk_callback(facts: _LineFacts, j: int) -> tuple[int | None, int]:
    """(verdict, line index that decided it) walking block openers up from ``j``."""
    stop = max(-1, j - _ACC_LOOKBACK)
    at: int | None = j
    while at is not None:
        found = _callback_verdict(facts, at)
        if found != _ACC_KEEP_WALKING:
            return found, at
        at = _next_opener(facts, at, stop)
    return None, -1


def _enclosing_callback(facts: _LineFacts, n: int) -> int | None:
    """The callback opener above line ``n`` within the look-back, walking the block-opener chain.

    The walk from an opener is the same for every line under it, so it is
    memoised per opener and only checked against this site's look-back.
    """
    stop = max(-1, n - _ACC_CALLBACK_LOOKBACK)
    j = _next_opener(facts, n - 1, stop)
    if j is None:
        return None
    found, at = _identity_memo(_ACC_CB_MEMO, facts, (j,), _walk_callback, facts, j)
    return found if at > stop else None


def _file_may_have_callback(facts: _LineFacts) -> bool:
    """One search of the whole file: with no callback opener anywhere, no site sits in one.

    A match spanning a line break only keeps the per-site test on; a match
    within one line is always a match of the joined text, so None is exact.
    """
    found = facts.callbacks[0]
    if found is None:
        text = "\n".join(facts.capped)
        found = facts.callbacks[0] = _names_a_callback(text) and bool(_ACC_CALLBACK.search(text))
    return found


def _names_a_callback(text: str) -> bool:
    """Every `_ACC_CALLBACK` form holds `on`, `Listener` or `subscribe`: three substring scans first."""
    return "on" in text or "Listener" in text or "subscribe" in text


def _input_callback_opener(lines: list[str], n: int) -> int | None:
    """The line of the input-event callback the sink at ``n`` sits in (own line first), or None."""
    return _callback_opener_in(_facts(lines), n)


def _callback_opener_in(facts: _LineFacts, n: int) -> int | None:
    if not _file_may_have_callback(facts):
        return None
    if _ACC_CALLBACK.search(facts.capped[n - 1]):
        return n
    return _enclosing_callback(facts, n)


def _build_callback_body(lines: list[str], j: int) -> list[str]:
    facts = _facts(lines)
    rows = [_line_code(facts, i) for i in range(j - 1, min(len(lines), j - 1 + _ACC_BODY_LINES))]
    return _block_after(rows, 0)[1:] if rows else []


def _callback_body(lines: list[str], j: int) -> list[str]:
    _facts(lines)
    return _identity_memo(_ACC_BODY_MEMO, lines, ("callback", j), _build_callback_body, lines, j)


IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")

# CWE-379: creation of a temporary file/directory at a PREDICTABLE path inside
# a shared, world-writable temp directory.
#
# The weakness is not "a temp file exists" — it is that the path is guessable
# AND its parent is writable by every local account, so another user can
# pre-create, symlink or read the entry before the owner touches it. Two
# idioms express exactly that, and both are content-keyed:
#
#   arm 1  a FIXED name joined onto the platform temp-dir accessor
#          (`filepath.Join(os.TempDir(), "app-ssh")`)
#   arm 2  a hardcoded `/tmp`-family literal handed to a create/write sink
#          (`open('/tmp/app-export.csv', 'w')`)
#
# Both arms are cleared by any secure-temp API, because those generate an
# unpredictable name inside a 0700 directory, and by any randomiser in the
# name — an unguessable entry in a shared directory is a different (and much
# weaker) exposure than a fixed one.
_TEMP_ROOT = re.compile(
    r"\bos\.TempDir\s*\(\s*\)|"                             # Go
    r"\bos\.tmpdir\s*\(\s*\)|"                              # Node
    r"\btempfile\.gettempdir\s*\(\s*\)|"                    # Python
    r"\bPath\.GetTempPath\s*\(\s*\)|"                       # C#
    r"getProperty\s*\(\s*['\"]java\.io\.tmpdir['\"]\s*\)"   # Java
)

# The root has to be COMBINED with a name for a path to be built from it; a
# bare read of the temp directory (`fs.readdirSync(os.tmpdir(), 'utf8')`) is
# not a creation site, and without this arm that line's `'utf8'` argument
# would read as the fixed name.
_JOIN_OR_CONCAT = re.compile(
    r"\.[Jj]oin\s*\(|"      # filepath.Join / path.join / os.path.join
    r"\bPaths\.get\s*\(|"   # Java NIO
    r"\.resolve\s*\(|"      # Java Path.resolve
    r"\bnew\s+File\s*\(|"   # Java legacy
    r"\+\s*['\"`]"          # string concatenation
)

# A FIXED path component: name characters only. A format placeholder (`%d`),
# a brace template (`{}` / `${...}`) or an interpolation therefore never reads
# as fixed, which is the point — those names are not guessable.
_FIXED_SEGMENT = re.compile(r"['\"`](/?[A-Za-z0-9][\w.\-]*(?:/[\w.\-]+)*)['\"`]")

# Arm 2 anchor. The literal must BE the path (it starts at the quote) and must
# carry a child component, so `'/tmp'` alone — the directory itself — and a
# log message that merely mentions a path both stay clear.
_TEMP_PATH_LITERAL = re.compile(
    r"['\"`](/(?:tmp|var/tmp|usr/tmp|dev/shm)/[\w.\-][^'\"`]*)['\"`]"
)

_TEMP_FILE_SINK = re.compile(
    r"(?<![\w.$])(?:open|fopen|creat|mkdir|makedirs|touch)\s*\(|"
    r"\b(?:os|fs|fsPromises|ioutil|shutil)\."
    r"(?:[Oo]pen\w*|[Cc]reate\w*|[Ww]rite\w*|[Mm]kdir\w*|makedirs|append\w*|copy\w*)\s*\(|"
    r"\bcreateWriteStream\s*\(|"
    r"\bnew\s+File(?:Writer|OutputStream)\s*\(|"
    r"\bFiles\.(?:write|newOutputStream|createFile|createDirector\w+)\s*\(|"
    r"\.write_(?:text|bytes)\s*\("
)

# Secure-temp APIs: every one of these mints an unpredictable name (and, on
# POSIX, an owner-only directory), which is the recommended fix — so their
# presence on the line is the clean twin of both arms.
_SECURE_TEMP_API = re.compile(
    r"\b(?:MkdirTemp|CreateTemp|TempFile|mkdtemp\w*|mkstemp\w*|"
    r"NamedTemporaryFile|SpooledTemporaryFile|TemporaryFile|TemporaryDirectory|"
    r"createTempFile|createTempDirectory|GetTempFileName|tmpfile)\s*\("
)

_UNPREDICTABLE_NAME = re.compile(
    r"uuid|nanoid|Math\.random|randomUUID|random_|randomBytes|"
    r"\brand\b|\brandom\b|secrets\.|token_hex|"
    r"[Gg]etpid|process\.pid|Date\.now|time\.Now",
    re.IGNORECASE,
)

# CWE-799: Improper control of interaction frequency (missing rate limiting).
# Auth-related endpoints without any rate limiter in the SAME file. This is
# the OWASP A04/A06 rate-limiting contributor (feature 0063). Suppression is
# file-scoped — a limiter reference anywhere in the file clears the file —
# which is narrower and less false-positive-prone than a project-wide check.
AUTH_ENDPOINT_DEF = re.compile(
    r"^\s*(?:async\s+)?(?:def|func)\s+"
    r"(?:login|signin|sign_in|signup|sign_up|register|authenticate|"
    r"reset_password|forgot_password|change_password)\b",
    re.IGNORECASE,
)
RATE_LIMIT_HINT = re.compile(
    r"rate[_-]?limit|throttl|ratelimiter|slowapi|\bLimiter\s*\(|"
    r"flask[_-]limiter|express[_-]rate",
    re.IGNORECASE,
)

# AUTH_ENDPOINT_DEF above is anchored to `def` / `func`, so no Express route
# can ever match it — Broken Anti Automation was a structurally blind
# category on Node codebases. This is the route-REGISTRATION form.
EXPRESS_AUTH_ROUTE = re.compile(
    r"\b(?:app|router|server)\s*\.\s*(?:post|put|patch|get)\s*\(\s*['\"`]"
    # The auth keyword must be a delimited path segment, not any substring:
    # `/rest/saveLoginIp` is not a credential endpoint even though "Login"
    # occurs inside it.
    r"(?P<path>[^'\"`]*(?<![A-Za-z0-9])"
    r"(?:login|register|reset-?password|forgot-?password|"
    r"change-?password|signin|sign-?in|signup|sign-?up)"
    r"(?![A-Za-z0-9])[^'\"`]*)['\"`]",
    re.IGNORECASE,
)
# Broader than RATE_LIMIT_HINT: Express limiters are usually named middleware
# (`loginLimiter`), which carries no "rate" token.
LIMITER_TOKEN = re.compile(
    r"limiter|rate[_-]?limit|throttl|slow[_-]?down|brute[_-]?force",
    re.IGNORECASE,
)
QUOTED_ROUTE_PATH = re.compile(r"['\"`](/[^'\"`]*)['\"`]")

# CWE-807: reliance on an untrusted input for a security decision — a rate
# limiter keyed on a client-controlled header can be bypassed by spoofing it.
KEY_GENERATOR = re.compile(r"\bkeyGenerator\b")
# The header vocabulary is single-sourced with access_control's CWE-290 rule.
SPOOFABLE_CLIENT_HEADER = re.compile(
    r"headers\s*(?:\[\s*['\"`]\s*|\.\s*get\s*\(\s*['\"`]\s*|\.\s*)" + CLIENT_IP_HEADER,
    re.IGNORECASE,
)


def _should_skip(file_path: Path) -> bool:
    """True for files whose resource patterns cannot be real leaks.

    ``is_prose_file`` is the third arm: nothing in a document is ever opened,
    so nothing in it can leak. Measured on a prose file that merely quotes an
    unclosed ``open()`` as the thing not to do: 2 false CWE-404 rows.
    """
    return is_generated_file(file_path) or is_test_file(file_path) or is_prose_file(file_path)


def check_resource_management(source_path: str) -> dict:
    """Check for resource management vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of resource management issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if _should_skip(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for resource management issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _analyze_line(file_path, line, line_num, lines, findings)
    # File-scoped: rate limiting is a whole-file property, checked once.
    _check_rate_limiting(file_path, lines, findings)


def _analyze_line(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Run every per-line resource check against one already-filtered line."""
    _check_resource_consumption(file_path, line, line_num, lines, findings)
    # Rule 6 (no row stacking): CWE-379 keys on the same `open(` /
    # `fs.create*` verbs as CWE-404, and CWE-379 is not a catalog descendant
    # of CWE-404, so the two would be a duplicate row rather than a
    # collapsible ancestor pair. The temp-directory row is the more specific
    # defect, so it claims the line and CWE-404 stands down.
    if not _check_insecure_temp_dir(file_path, line, line_num, lines, findings):
        _check_improper_shutdown(file_path, line, line_num, lines, findings)
    _check_null_deref(file_path, line, line_num, lines, findings)
    _check_unbounded_alloc(file_path, line, line_num, lines, findings)


def _check_rate_limiting(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """File-scoped rate-limiting checks (CWE-799 / CWE-807)."""
    _check_def_rate_limiting(file_path, lines, findings)
    _check_express_rate_limiting(file_path, lines, findings)
    _check_spoofable_limiter_key(file_path, lines, findings)
    check_message_sends(file_path, lines, findings)


def _limiter_protected_paths(lines: list[str]) -> set[str]:
    """Route paths that a limiter registration in this file mentions.

    `app.use('/rest/user/reset-password', rateLimit({...}))` protects that
    path (and everything under it), but says nothing about `/rest/user/login`
    — so suppression for the Express form is PATH-scoped, not file-scoped.
    """
    protected: set[str] = set()
    for line in lines:
        if COMMENT_INDICATORS.match(line):
            continue
        if not LIMITER_TOKEN.search(line):
            continue
        protected.update(QUOTED_ROUTE_PATH.findall(line))
    return protected


def _is_path_protected(route_path: str, protected: set[str]) -> bool:
    """True when a limiter covers this route path (exact or prefix mount)."""
    normalized = route_path.rstrip("/") or "/"
    for mount in protected:
        base = mount.rstrip("/") or "/"
        if normalized == base or normalized.startswith(base + "/"):
            return True
    return False


def _check_express_rate_limiting(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Auth route registered on an Express app with no limiter (CWE-799)."""
    protected = _limiter_protected_paths(lines)
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        match = EXPRESS_AUTH_ROUTE.search(line)
        if match is None:
            continue
        if LIMITER_TOKEN.search(line):
            continue
        route_path = match.group("path")
        if _is_path_protected(route_path, protected):
            continue
        finding = {
            "severity": "medium",
            "check_id": "cwe.resource.express_rate_limit",
            "category": "CWE-799",
            "title": "Authentication route registered without rate limiting",
            "description": (
                f"Express route '{route_path}' at line {line_num} is an "
                "authentication endpoint with no rate limiter applied to it"
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Mount a rate limiter (e.g. express-rate-limit) on this route "
                "to resist credential stuffing and brute-force automation"
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "799"))


def _check_spoofable_limiter_key(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Rate-limit identity derived from a client-controlled header (CWE-807)."""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if not KEY_GENERATOR.search(line):
            continue
        window_end = min(line_num + 4, len(lines))
        window = "\n".join(lines[line_num - 1 : window_end])
        if not SPOOFABLE_CLIENT_HEADER.search(window):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.spoofable_rate_limit_key",
            "category": "CWE-807",
            "title": "Rate limiter keyed on a client-controlled header",
            "description": (
                f"keyGenerator at line {line_num} derives the rate-limit "
                "identity from a request header the client can set, so the "
                "limit is trivially bypassed by varying that header"
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Key the limiter on the trusted peer address (req.ip with a "
                "correctly configured trust-proxy hop count) or an "
                "authenticated identity, never on a raw client header"
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "807"))


def _check_def_rate_limiting(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Check for missing rate limiting on auth endpoints (CWE-799).

    File-scoped: if any line in this file references a rate limiter, the
    whole file is considered protected and no finding is raised.
    """
    if any(RATE_LIMIT_HINT.search(line) for line in lines):
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if not AUTH_ENDPOINT_DEF.match(line):
            continue
        finding = {
            "severity": "medium",
            "check_id": "cwe.resource.rate_limit",
            "category": "CWE-799",
            "title": "Improper control of interaction frequency (missing rate limiting)",
            "description": (
                f"Authentication-related endpoint at line {line_num} with no "
                "rate limiting in this file"
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Apply rate limiting/throttling to authentication endpoints to "
                "resist brute-force and abuse"
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "799"))


def _joined_temp_path(line: str) -> str | None:
    """Arm 1 — a fixed name combined with the platform temp-dir accessor."""
    root = _TEMP_ROOT.search(line)
    if root is None or not _JOIN_OR_CONCAT.search(line):
        return None
    segment = _FIXED_SEGMENT.search(line, root.end())
    return segment.group(1) if segment else None


def _predictable_temp_path(line: str) -> str | None:
    """The predictable shared-temp path this line builds, if any (CWE-379)."""
    if _SECURE_TEMP_API.search(line) or _UNPREDICTABLE_NAME.search(line):
        return None
    literal = _TEMP_PATH_LITERAL.search(line)
    if literal is not None and _TEMP_FILE_SINK.search(line):
        return literal.group(1)
    return _joined_temp_path(line)


def _check_insecure_temp_dir(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> bool:
    """Temp file/dir at a predictable path in a shared directory (CWE-379).

    Returns True when the line was claimed, so the caller can keep the
    one-row-per-line invariant against the CWE-404 arm.
    """
    target = _predictable_temp_path(line)
    if target is None:
        return False
    finding = {
        "severity": "medium",
        "check_id": "cwe.resource.insecure_temp_dir",
        "category": "CWE-379",
        "title": "Temporary file created at a predictable path in a shared directory",
        "description": (
            f"Line {line_num} builds '{target}' inside a world-writable "
            "temp directory using a fixed name, so any local account can "
            "pre-create, symlink or read that entry"
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Create temporary files through the platform's secure API "
            "(os.MkdirTemp/os.CreateTemp, tempfile.mkstemp/mkdtemp, "
            "fs.mkdtemp, Files.createTempFile), which mints an unpredictable "
            "name in an owner-only directory"
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "379"))
    return True


def _check_resource_consumption(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for uncontrolled resource consumption (CWE-400)."""
    if file_path.suffix.lower() in _LOOP_PATTERN_SKIP_SUFFIXES:
        return
    for pattern in RESOURCE_CONSUMPTION_PATTERNS:
        if not pattern.search(line):
            continue
        if _loop_has_visible_exit(lines, line_num):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.uncontrolled_consumption",
            "category": "CWE-400",
            "title": "Potential uncontrolled resource consumption",
            "description": f"Unbounded loop without visible exit at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add explicit bounds, timeouts, or break conditions to loops",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "400"))
        return


def _check_improper_shutdown(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for improper resource shutdown (CWE-404)."""
    if file_path.suffix.lower() in _MARKUP_SUFFIXES:
        return
    if RESOURCE_OPEN_DECL.match(line):
        return
    for pattern in RESOURCE_OPEN_PATTERNS:
        if not pattern.search(line):
            continue
        # Look for close/defer in surrounding context (next 5 lines)
        context_end = min(line_num + 5, len(lines))
        context = "\n".join(lines[line_num - 1 : context_end])
        if RESOURCE_CLOSE_SAFE.search(context):
            return
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.improper_shutdown",
            "category": "CWE-404",
            "title": "Resource opened without proper cleanup",
            "description": f"Resource opened at line {line_num} without close/defer/with",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use defer (Go), with statement (Python), or try-finally to ensure cleanup",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "404"))
        return


def _check_null_deref(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for NULL pointer dereference (CWE-476)."""
    # Feature 0085 gate 1 — LANGUAGE. Every construct below is Go-specific, and
    # Python's walrus operator is also `:=`, so without this the Go rule fires
    # on Python.
    if file_path.suffix.lower() != ".go":
        return
    # Focus on Go pattern: assignment from method call without nil check
    if not NULL_DEREF_PATTERNS[0].search(line):
        return
    bound = GO_ASSIGN_FIRST.search(line)
    if not bound:
        return
    # Feature 0085 gate 3 — NIL-ABILITY. If the right-hand side is a constructor
    # that cannot return nil, there is nothing to dereference unsafely.
    if GO_NEVER_NIL_CALL.search(line):
        return
    # Gate 3b — Go's `New*` constructor convention. A SINGLE-value assignment
    # from a `New…` function returns a ready-to-use value; a constructor that
    # can fail returns (T, error), which is a two-value assignment and is NOT
    # suppressed here. This is an assumption, stated plainly: a `New…` that
    # returns a bare nil on bad input is now missed. Recall knowingly traded
    # against 56 measured false positives at HIGH severity, all of this shape.
    if bound.group("second") is None and GO_NEW_CTOR.search(line):
        return
    # Feature 0085 gate 2 — the bound name must actually be DEREFERENCED later.
    # Binding a value and passing it along cannot fault.
    if not _go_var_is_dereferenced(bound.group("first"), lines, line_num):
        return
    # Check following lines for nil check before use
    window_end = min(line_num + 5, len(lines))
    window = "\n".join(lines[line_num:window_end])
    if GO_NIL_CHECK.search(window):
        return
    # Feature 0085 gate 4 — a `len(v)` test is a nil guard for slices and maps,
    # and a guard on THIS variable counts wherever it is written.
    _v = re.escape(bound.group("first"))
    if re.search(GO_LEN_GUARD.pattern.format(v=_v), window):
        return
    if re.search(GO_VAR_NIL_GUARD.pattern.format(v=_v), window):
        return
    # Gate 4b — a check on the assignment's OWN second result guards the first.
    # `u, err := url.Parse(x)` followed by `err == nil && u.Host != ""` is
    # correct Go: the error is what tells you the value is usable. Only a NAMED
    # second result counts — `_` is precisely the discarded-error bug this rule
    # must keep reporting.
    _second = bound.group("second")
    if _second and _second != "_" and re.search(
        GO_VAR_NIL_GUARD.pattern.format(v=re.escape(_second)), window
    ):
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.resource.null_deref",
        "category": "CWE-476",
        "title": "Potential NULL pointer dereference",
        "description": f"Return value used without nil check at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Check for nil/null before dereferencing pointers",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "476"))


# --- CWE-770 site decision ----------------------------------------------------
# A cheap literal-led necessary condition on the RAW line runs before any strip
# (measured: the whole rule became faster than the pre-0101 one on two trees).
_ACC_RAW_PREFILTER = re.compile(
    r"\.\s{0,8}(?i:append|push|add|extend|insert|put|enqueue|emplace|unshift|write)"
    r"|<<|\+=|\.=|\]\s{0,4}="
    # `\b(?:realloc|array_push|append)\s{0,4}\(`, each boundary asserted after its
    # literal so every branch starts with one (the scan then skips between them).
    r"|realloc(?<!\wrealloc)\s{0,4}\(|array_push(?<!\warray_push)\s{0,4}\(|append(?<!\wappend)\s{0,4}\("
)
# `.write*(` grows only a receiver BOUND in the routine to an in-memory buffer,
# read from the constructor's words: buffer|builder, or bytes/byte/string/memory/
# array together with io|stream (`io.BytesIO()`, `StringIO`, `ByteArrayOutputStream`,
# `MemoryStream`). Revision 1 compared against the fused token "bytesio", which
# the word splitter never produces, so `buf = io.BytesIO(); buf.write(b)` in a
# recv loop was missed.
_ACC_WRITE_VERB = re.compile(r"\.\s{0,8}(?:write\w{0,12}|Write\w{0,12})\s{0,8}\(")
_ACC_BUFFER_WORDS = frozenset({"buffer", "builder"})
_ACC_BUFFER_KIND_WORDS = frozenset({"bytes", "byte", "string", "memory", "array"})
_ACC_BUFFER_STREAM_WORDS = frozenset({"io", "stream"})


@lru_cache(maxsize=4096)
def _skip_suffix(path: str) -> bool:
    return Path(path).suffix.lower() in _LOOP_PATTERN_SKIP_SUFFIXES


def _growth_receiver(line: str, n: int, lines: list[str]) -> tuple[str, str] | None:
    """(accumulator, routine text) when ``line`` grows a receiver that is not a scalar."""
    code = stripped_code(line)
    acc = _accumulator(code)
    numeric = acc is None
    acc = acc or _numeric_add_receiver(code)
    if not acc:
        return None
    routine_text = _binding_scope(acc, lines, n, code)
    return None if _not_growth(acc, code, routine_text, numeric) else (acc, routine_text)


_ACC_LAST_ABOVE: list = [None, 0, "", False]   # [lines, n, acc, verdict]: the site being decided

# What the routine text adds over the site line is the BINDINGS above it, and
# every template read from that text binds by an `=` after the name
# (`NAME\s{0,4}(?::[^=]{0,60})?=`, with any tail) or follows `var `. Such a name
# ends a run of identifier characters that is followed, after at most four
# spaces, by `:` or `=`, or that follows `var` and a space: a SUPERSET of the
# runs that can bind, found in the JOINED text (a binding split over lines too).
# The first form is searched in the REVERSED text, where it starts with `:` or
# `=`, so the scan skips to those characters instead of trying every position.
_ACC_BOUND_REV = re.compile(r"[=:]\s{0,4}([\w$@]+)")
_ACC_VAR_RUN = re.compile(r"var\s([\w$@]+)")
_ACC_SUFFIX_KEY = 24   # suffixes kept per run: a longer name is looked up by its last 24 characters


def _bound_runs(text: str) -> set[str]:
    return {run[::-1] for run in set(_ACC_BOUND_REV.findall(text[::-1]))} | set(_ACC_VAR_RUN.findall(text))


def _run_suffixes(runs: set[str]) -> frozenset[str]:
    return frozenset(run[-k:] for run in runs for k in range(1, min(len(run), _ACC_SUFFIX_KEY) + 1))


def _may_bind(facts: _LineFacts, acc: str) -> bool:
    """False when no run in the file that a binding could name ends with ``acc``: then nothing binds it."""
    found = facts.bound[0]
    if found is None:
        found = facts.bound[0] = _run_suffixes(_bound_runs(_file_index(facts).text))
    return acc[-_ACC_SUFFIX_KEY:] in found


def _occurs_above(acc: str, lines: list[str], n: int) -> bool:
    """``acc`` may be bound in the routine above line ``n``: it occurs there and a binding could name it.

    When nothing in the file can bind ``acc`` the routine text and the site line
    give every reader the same answer (no template matches either), so the
    routine is not searched (a script of distinct names searched 120 lines per site).
    """
    last = _ACC_LAST_ABOVE
    if last[0] is not lines or last[1] != n or last[2] != acc:
        last[:] = [lines, n, acc, _bound_above(acc, _facts(lines), n)]
    return last[3]


def _bound_above(acc: str, facts: _LineFacts, n: int) -> bool:
    return _may_bind(facts, acc) and _found_above(acc, facts, n)


def _found_above(acc: str, facts: _LineFacts, n: int) -> bool:
    """``acc`` occurs in the routine above line ``n`` (one search of the joined text, no slice)."""
    index = _file_index(facts)
    return index.text.find(acc, index.offsets[_routine_start(facts, n)], index.offsets[n - 1]) >= 0


def _binding_scope(acc: str, lines: list[str], n: int, code: str) -> str:
    """The routine text, or only the site line when ``acc`` occurs nowhere above it.

    Every binding form matches within one line, so with no earlier occurrence
    only the site line can bind: a few searches of a short line instead of the
    routine, and no routine text is cut (a script of distinct names
    otherwise searched 120 lines four times per site). ``code`` is the site
    line's stripped code; the routine text holds it as "" inside a string literal.
    """
    if _occurs_above(acc, lines, n):
        return _routine_text(lines, n)
    return _site_scope(code if _facts(lines).capped[n - 1] else "")


def _site_scope(site: str) -> str:
    return site if "=" in site or "var" in site else ""   # every binding form needs one of the two


def _not_growth(acc: str, code: str, routine_text: str, numeric: bool) -> bool:
    """A numeric `add` on anything but a collection bound here, a scalar, or arithmetic `+=`."""
    if numeric and not _bound_to_collection(acc, routine_text):
        return True
    return _is_scalar(acc, routine_text) or _plus_eq_is_arithmetic(acc, code, routine_text)


def _body_text(body: list[str]) -> str:
    return _identity_memo(_ACC_BODY_TEXT_MEMO, body, (id(body),), "\n".join, body)


class _Loop(NamedTuple):
    header: str
    body: list[str]
    routine_text: str     # the routine text ABOVE the header
    driven: bool
    declared: frozenset[str]
    profile: _CapProfile


def _build_loop(lines: list[str], h: int) -> _Loop:
    header, body, routine_text = _line_code(_facts(lines), h - 1), _loop_body(lines, h), _routine_text(lines, h)
    driven = _loop_driven(header, _body_text(body), routine_text)
    return _Loop(header, body, routine_text, driven, _declared_names(body),
                 _cap_profile(header, body, routine_text))


def _loop_at(lines: list[str], h: int) -> _Loop:
    """The loop at header line ``h``, its driver decided ONCE per loop.

    What drives a loop and what caps its source are read at its header, so the
    routine text is the text above the header and every site of the loop
    shares it.
    """
    return _identity_memo(_ACC_DRIVEN_MEMO, lines, h, _build_loop, lines, h)


def _feeds(acc: str, loop: _Loop, fresh: bool, above: bool) -> bool:
    """``loop`` is driven by input and does not cap ``acc``.

    ``fresh``: a receiver declared in the body lives one iteration (a fresh
    collection each time round). ``above``: ``acc`` may be bound above the site,
    so the text above the header is read; otherwise nothing there binds it.
    """
    if not loop.driven or (fresh and acc in loop.declared):
        return False
    return not _capped_by(acc, loop.profile, loop.header, loop.body, ("", loop.routine_text)[above])


def _driven_uncapped(acc: str, n: int, lines: list[str], loops: list[int], lifetime: bool) -> bool:
    above = _occurs_above(acc, lines, n)
    for h in loops:
        if _feeds(acc, _loop_at(lines, h), lifetime and h != n, above):
            return True
    return False


def _loop_site(line: str, n: int, lines: list[str], loops: list[int]) -> bool:
    grown = _growth_receiver(line, n, lines)
    return grown is not None and _driven_uncapped(grown[0], n, lines, loops, lifetime=True)


def _is_buffer_ctor(rhs: str) -> bool:
    words = _words_of(rhs)
    if words & _ACC_BUFFER_WORDS:
        return True
    return bool(words & _ACC_BUFFER_KIND_WORDS and words & _ACC_BUFFER_STREAM_WORDS)


def _declared_type(acc: str, routine_text: str) -> str:
    """The type of a `var buf bytes.Buffer` declaration (a zero value has no `=`), else ""."""
    m = _first_binding(_ACC_VAR_TYPE_TEMPLATE, acc, routine_text)
    return m.group(1) if m else ""


def _write_receiver(code: str) -> str | None:
    verb = _ACC_WRITE_VERB.search(code)
    if not verb:
        return None
    tail = _ACC_RECEIVER_TAIL.search(code[max(0, verb.start() - 72):verb.start()])
    return tail.group(1) if tail else None


def _write_site(line: str, n: int, lines: list[str], loops: list[int]) -> bool:
    acc = _write_receiver(stripped_code(line))
    if not acc:
        return False
    routine_text = _routine_text(lines, n)
    if not _is_buffer_ctor(_binding_rhs(acc, routine_text) or _declared_type(acc, routine_text)):
        return False
    return _driven_uncapped(acc, n, lines, loops, lifetime=False)


def _callback_site(line: str, n: int, lines: list[str], opener: int) -> bool:
    grown = _growth_receiver(line, n, lines)
    if grown is None:
        return False
    header = _line_code(_facts(lines), opener - 1)
    return not _capped(grown[0], header, _callback_body(lines, opener), _routine_text(lines, opener))


def _accumulation_site(line: str, n: int, lines: list[str]) -> bool:
    """Input-driven, uncapped accumulation at line ``n``."""
    facts = _facts(lines)
    opener = _callback_opener_in(facts, n)
    if opener is not None:
        return _callback_site(line, n, lines, opener)
    # Loop discovery reads per-file facts only; the sink and scalar tests read the
    # routine text, so a site with no enclosing loop stops here.
    loops = _loops_in(facts, lines, n)
    if not loops:
        return False
    return _loop_site(line, n, lines, loops) or _write_site(line, n, lines, loops)


def _report_unbounded_alloc(file_path: Path, n: int, lines: list[str], findings: list[dict]) -> None:
    finding = {
        "severity": "medium",
        "check_id": "cwe.resource.unbounded_alloc",
        "category": "CWE-770",
        "title": "Allocation without resource limits",
        "description": f"Unbounded allocation at line {n}",
        "file_path": str(file_path),
        "line_start": n,
        "line_end": n,
        "recommendation": "Add size limits, max capacity, or bounded data structures",
    }
    finding["code_snippet"] = extract_snippet(lines, n)
    findings.append(enrich_finding(finding, "770"))


def _go_make_capped(n: int, lines: list[str]) -> bool:
    facts = _facts(lines)
    context = "\n".join(_line_code(facts, i) for i in range(max(0, n - 4), min(len(lines), n + 3)))
    return bool(SIZE_LIMIT.search(context))


_ACC_LAST_PATH: list = [None, False]   # [path object, skipped]: the file being scanned


def _path_skipped(file_path: Path) -> bool:
    if _ACC_LAST_PATH[0] is not file_path:
        _ACC_LAST_PATH[:] = [file_path, _skip_suffix(str(file_path))]
    return _ACC_LAST_PATH[1]


def _accumulation_candidate(file_path: Path, line: str) -> bool:
    return bool(_ACC_RAW_PREFILTER.search(line[:MAX_SCAN_CHARS])) and not _path_skipped(file_path)


def _check_go_make(file_path: Path, n: int, lines: list[str], findings: list[dict]) -> None:
    if not _go_make_capped(n, lines):
        _report_unbounded_alloc(file_path, n, lines, findings)


def _check_unbounded_alloc(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for allocation without limits (CWE-770)."""
    if _GO_MAKE.search(line):
        _check_go_make(file_path, line_num, lines, findings)
    elif _accumulation_candidate(file_path, line) and _accumulation_site(line, line_num, lines):
        _report_unbounded_alloc(file_path, line_num, lines, findings)

check_resource_management_tool = function_tool(check_resource_management)
