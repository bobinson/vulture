"""The cwe side of the AST tier's consumer head (feature 0102, LLD §9.2, §9.3; D10, D19, D21,
A41 (5)).

WHY THIS EXISTS
---------------
Every check the cwe agent moves to the AST tier — CWE-22 in ``input_validation_check``,
CWE-918, CWE-78 and CWE-89's AST rows (feature 0105) in ``injection_check`` — asks the tier
about a file the same way: the D10 ownership decision (the prefilter, then ``owns``), the
spans of the check's family, and the lines its rows are numbered from. One copy here, so no
two heads can decide ownership differently (``test_0102_owner_disjoint``).

CONTRACT
--------
``ast_walk(files, skip, rules)`` is a skill's file loop under parse prefetch (LLD §4.1 item 6):
the files its ``skip`` predicate keeps, in order, as ``shared.ast.prefetch.walk`` over the
families of its ``rules``. ``ast_answers(file_path, text, rules, server_ctx)`` is the tier's
answer for one file and each rule (``AstAnswer``), asked once per file; ``ast_spans`` is its
one-rule form. The real head asks ``prefetch.advance``, then ``owns_answer`` (§4.1: the file's
worker-built answer, a ticket issued ahead collected in place of a request), then
``prefetch.refill`` (the collected ticket's slot freed), with ``profile.owns_family`` the one
ownership predicate of the head and the prefetch. ``emit_at`` is
``shared.ast.consume.emit_for_line`` over an answer at the model's line, with the catalog's
``enrich_finding``, which ``shared.ast`` cannot import (A41 (5)); ``claim`` is ``emit_at`` asked
by a skill's line loop. ``ast_owns`` is the head of a check the tier owns line by line (LLD
§9.3: CWE-918, CWE-78): the row of a reported sink at its line, and whether the regex body may
run at all. CWE-89's AST rows are emitted after the line loop instead
(``injection_check._statement_rows``), where no regex row covers their flow. CWE-22's head
reads the same answer (``input_validation_check._ast_claims``), its claim chain around it.

The two numberings (feature 0105, LLD §4.6): a skill's line loop numbers its lines
by ``str.splitlines()`` (``read_file_lines``), which also breaks at ``\\f``, ``\\v``,
``\\x1c``-``\\x1e``, ``\\x85``, U+2028 and U+2029; the model by ``"\\n"`` alone (D21), and every
AST row keeps the model's numbering. Where they differ, ``ast_answers`` gives each answer that
reports a span the loop's numbering (``LoopLines``, built once per file), and the head reads
every loop line as the model's line it lies on (``model_line``; ``loop_lines`` the other way):
``claim`` owns a model line the loop splits on each of its loop lines and appends its row
once; ``unread_sinks`` reads a sink line when the loop reads any of its loop lines. A file
whose numberings agree has no ``LoopLines``: nothing is built, and its rows are unchanged.
``regex_row`` is a regex body's row: the rule's identity row (``consume.rule_row``, D19),
enriched as the AST row is. Feature 0104 A2: ``hint_groups`` is a file's group of hint-only
rows of one rule, asked once per (file, rule) where each head builds its file context
(CWE-89's: after its line loop); ``claim`` stamps each member's row with it
(``consume.stamp_member``), and the agent folds the rows into one once every row it emits is
known (``consume.fold_hint_groups``).
The model, the cache and the lexicons are imported where ``ast_answers`` first needs them, as
``consume`` imports its own: importing a skill loads no worker pool, profile or model (D1).
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence, Set
from functools import cache, partial
from itertools import filterfalse
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol

from cwe_agent.catalog import enrich_finding
from shared.ast import consume, prefetch
from shared.ast.consume import (
    RuleIdentity,
    emit_for_line,
    family_flows,
    rule_row,
    sink_lines,
    stamp_member,
)
from shared.ast.context import current

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from shared.ast.answer import FileFacts
    from shared.ast.consume import Enrich, FamilyRule, Finding
    from shared.ast.flow import Flow

__all__ = [
    "FALLBACK",
    "AstAnswer",
    "CatalogRule",
    "LoopLines",
    "ast_answers",
    "ast_owns",
    "ast_spans",
    "ast_walk",
    "claim",
    "emit_at",
    "hint_groups",
    "loop_lines",
    "model_line",
    "regex_row",
    "unread_sinks",
]


class LoopLines:
    """The line loop's numbering of a file whose model numbers its lines otherwise (feature
    0105, LLD §4.6): ``model`` holds each loop line's model line, loop line ``k`` at
    ``model[k - 1]`` (non-decreasing; one model line may hold several loop lines), shared by
    the file's answers; ``again`` records, per answer, the model lines the loop asked about."""

    __slots__ = ("_asked", "model")

    def __init__(self, model: Sequence[int]) -> None:
        self.model = model
        self._asked: set[int] = set()

    def again(self, line: int) -> bool:
        """True when the loop asked about the model line ``line`` before, on another of its
        loop lines; the ask is recorded."""
        asked = line in self._asked
        self._asked.add(line)
        return asked


class AstAnswer(NamedTuple):
    """The AST tier's answer for one file and one rule (``ast_answers``)."""

    # Each line of every reported sink span -> its flow; None when the regex body owns the file.
    spans: Mapping[int, Flow] | None
    # The model's ``text.split("\n")`` (D21), the lines a row is numbered and quoted from.
    nl_lines: Sequence[str]
    # The line loop's numbering where it differs from the model's (feature 0105, LLD §4.6);
    # None where the two agree (``ast_answers``, ``_numbered``).
    loop: LoopLines | None = None
    # Every flow the tier reports for the rule, hint-only ones included: the list ``spans`` is
    # built from (``consume.family_flows``), where a sink with several sink arguments has a flow
    # per argument and ``spans`` keeps one. The CWE-89 cover test reads a sink over every flow
    # at it (``consume.sink_flows``; feature 0105, LLD §4.6). ``()``, none recorded (an answer
    # built without them): each sink line reads its own flow alone.
    reported: Sequence[Flow] = ()


# The answer for a file the AST tier falls back on: the regex body owns it (D10).
FALLBACK = AstAnswer(None, ())


def hint_groups(
    answer: AstAnswer, rule: FamilyRule, file_path: Path, excluded: Set[int] = frozenset()
) -> tuple[int, ...]:
    """0104 A2 (S1, S3, S4): the file's group of hint-only rows of one rule — every member's
    sink line, sorted, the anchor's first: the stamp ``emit_at`` puts on each member's row; ``()``
    when the file has none. ``consume.hint_groups``' candidate for ``answer`` (``excluded`` the
    sink lines that are no row: those a child replaces and those the head never reads,
    ``unread_sinks``). Asked once per (file, rule), ``file_path`` and ``rule``: where the head
    builds its file context, or for CWE-89 after its line loop (feature 0105)."""
    return consume.hint_groups(answer.spans, excluded)


def unread_sinks(
    answer: AstAnswer, lines: Sequence[str], scanned: Callable[[str], bool]
) -> frozenset[int]:
    """0104 A2: the sink lines of ``answer`` (``consume.sink_lines``) the head's line loop over
    ``lines`` never reads: none of the sink line's loop lines (``loop_lines``, feature 0105,
    LLD §4.6) is one it reads (``scanned`` false, or past their end). ``claim`` is never asked
    about such a line, so no row stands at it and it is never an anchor or a member
    (``consume.hint_groups``)."""
    return frozenset(n for n in sink_lines(answer.spans) if not _read(answer, lines, n, scanned))


def _read(
    answer: AstAnswer, lines: Sequence[str], line: int, scanned: Callable[[str], bool]
) -> bool:
    """The line loop reads one of the model line ``line``'s loop lines (``loop_lines``)."""
    return any(_reads(lines, k, scanned) for k in loop_lines(answer, line))


def _reads(lines: Sequence[str], line_num: int, scanned: Callable[[str], bool]) -> bool:
    """The line loop reaches ``line_num`` and its ``scanned`` predicate keeps the line."""
    return 0 < line_num <= len(lines) and scanned(lines[line_num - 1])


def model_line(answer: AstAnswer, line_num: int) -> int:
    """The model's line (``"\\n"``, D21) the line loop's line ``line_num`` lies on (feature
    0105, LLD §4.6): ``line_num`` itself when the two numberings agree (no ``answer.loop``),
    else ``LoopLines.model``'s; 0, no line, past the loop's lines."""
    loop = answer.loop
    if loop is None:
        return line_num
    return loop.model[line_num - 1] if 0 < line_num <= len(loop.model) else 0


def loop_lines(answer: AstAnswer, line: int) -> range:
    """The line loop's lines of the model's line ``line`` (``model_line`` the other way):
    ``line`` alone when the two numberings agree, else those ``LoopLines.model`` maps to it
    (none past the loop's lines)."""
    loop = answer.loop
    if loop is None:
        return range(line, line + 1)
    return range(bisect_left(loop.model, line) + 1, bisect_right(loop.model, line) + 1)


class CatalogRule(RuleIdentity, Protocol):
    """A rule a regex body's row is built for (``regex_row``): its identity strings (D19) and
    the catalog id the row is enriched by — a ``FamilyRule``, or a skill's own rule entry."""

    @property
    def cwe_id(self) -> str: ...


def ast_walk(
    files: Iterable[Path], skip: Callable[[Path], bool], rules: Sequence[FamilyRule]
) -> AbstractContextManager[list[Path]]:
    """A skill's file loop: ``files`` less those ``skip`` drops, in order — the files its loop
    analyses — walked by ``prefetch.walk`` over the families ``rules`` ask about, so the head's
    ``advance`` sends the next ones ahead (LLD §4.1 item 6). A skipped file is never sent."""
    return prefetch.walk(filterfalse(skip, files), {rule.family for rule in rules})


def ast_answers(
    file_path: Path, text: str, rules: Sequence[FamilyRule], server_ctx: bool = True
) -> tuple[AstAnswer, ...]:
    """The AST tier's answer for each of ``rules`` on ``file_path``, in order (LLD §9.2): the
    prefilter reads the text once for every rule's family (``needed_families``: one glued
    view), BEFORE any parse — a file with no sink key of a family is never shipped to a worker
    for it, so it skips the parse, not just the flow pass. Each family's model is read once,
    by the first rule that asks for it (``_answer``, through ``model_of``), however many rules
    name the family (feature 0105, LLD §4.6: CWE-78 and CWE-89 both read the command family);
    each rule then reads its own spans of it. An answer that reports a span carries the line
    loop's numbering where it differs from the model's (``_numbered``; feature 0105, LLD
    §4.6)."""
    from shared.ast.roles import needed_families

    needed = needed_families(text, {rule.family for rule in rules})
    model_of = cache(partial(_family_model, file_path))
    answers = tuple(_answer(file_path, rule, needed, model_of, server_ctx) for rule in rules)
    return _numbered(answers)


def ast_spans(
    file_path: Path, text: str, rule: FamilyRule, server_ctx: bool = True
) -> AstAnswer:
    """``ast_answers`` for the one ``rule``."""
    return ast_answers(file_path, text, (rule,), server_ctx)[0]


def _answer(
    file_path: Path, rule: FamilyRule, needed: Set[str],
    model_of: Callable[[str], FileFacts | None], server_ctx: bool,
) -> AstAnswer:
    """The AST tier's answer for ``rule`` on ``file_path``, ``needed`` the families the
    prefilter found a sink key of, ``model_of`` the file's model of a family
    (``_family_model``, asked once per family and ``ast_answers`` call, a None included).

    The spans: each line of every ``rule.family`` sink span the tier reports -> its flow,
    declines recorded on the current audit against this file; ``{}`` for an owned file that
    cannot hold such a sink; None when the regex body owns the file (no profile, a profile
    that owns no ``rule.family`` — C and C++ own no ``request``, so CWE-918 stays regex-owned
    there (LLD §6.3) — no model, an ERROR node, the breaker open — D10). The lines: the
    model's ``nl_lines``, the ``text.split("\\n")`` (D21) of the very text the spans index;
    ``()`` with no model. The reported flows: every flow the spans are built from, from the
    same ``decide`` pass (``consume.family_flows``; feature 0105, LLD §4.6)."""
    if rule.family not in needed:
        return AstAnswer({} if _owned(file_path, rule.family) else None, ())
    model = model_of(rule.family)
    if model is None:
        return FALLBACK
    spans, reported = family_flows(model, rule, current(), file_path, server_ctx=server_ctx)
    return AstAnswer(spans, model.nl_lines, reported=reported)


# The line breaks ``str.splitlines`` takes beside ``"\n"``: the line loop breaks at each, the
# model at none (D21). A model text holding none of them is numbered alike by both.
_LOOP_BREAKS = "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"


def _numbered(answers: tuple[AstAnswer, ...]) -> tuple[AstAnswer, ...]:
    """``answers``, each that reports a span carrying a ``LoopLines`` of its own over one
    per-file map (``_loop_model``, from the first such answer's lines, the model's); ``answers``
    unchanged when none reports a span or the two numberings agree (feature 0105, LLD §4.6).
    All of a file's answers hold the one model's lines."""
    model = _loop_model(_spanned_lines(answers))
    if model is None:
        return answers
    return tuple(_with_loop(answer, model) for answer in answers)


def _spanned_lines(answers: Iterable[AstAnswer]) -> Sequence[str]:
    """The model's lines of the first of ``answers`` that reports a span; none when none does."""
    return next((answer.nl_lines for answer in answers if answer.spans), ())


def _with_loop(answer: AstAnswer, model: Sequence[int]) -> AstAnswer:
    """``answer`` with a ``LoopLines`` over ``model`` when it reports a span."""
    return answer._replace(loop=LoopLines(model)) if answer.spans else answer


def _loop_model(nl_lines: Sequence[str]) -> tuple[int, ...] | None:
    """Each line loop's line's model line, read off the model's text (``_model_text``): the
    pieces of ``str.splitlines(keepends=True)`` are the loop's lines, and a model line ends with
    each piece ending in ``"\\n"``. None when the text holds none of ``_LOOP_BREAKS``: the
    two numberings agree, and nothing is built."""
    text = _model_text(nl_lines)
    if not any(brk in text for brk in _LOOP_BREAKS):
        return None
    return tuple(_model_lines(text.splitlines(keepends=True)))


def _model_lines(pieces: Iterable[str]) -> Iterator[int]:
    """The model line of each loop line ``pieces`` holds, in order, from 1."""
    line = 1
    for piece in pieces:
        yield line
        line += piece.endswith("\n")


def _model_text(nl_lines: Sequence[str]) -> str:
    """The model's text whole: a ``Lines``' own (``shared.ast.model.Lines.text``), else
    ``nl_lines`` joined by ``"\\n"``."""
    from shared.ast.model import Lines

    return nl_lines.text if isinstance(nl_lines, Lines) else "\n".join(nl_lines)


def _owned(file_path: Path, family: str) -> bool | None:
    """D10 by extension alone, never a parse: whether the file's profile owns ``family``
    (``profile.owns_family``, §6.3 ``owned_families``); None when its language has no
    profile."""
    from shared.ast.profile import owns_family

    return owns_family(file_path, family)


def _family_model(file_path: Path, family: str) -> FileFacts | None:
    """``owns_answer`` (D10: the file's worker-built answer, no ERROR node, the breaker
    closed), unless the file's profile owns no ``family`` — then None, and no parse. First
    ``prefetch.advance``, so the walk sends its next files ahead (LLD §4.1 item 6); after it
    ``prefetch.refill``, so the slot the file's collected ticket freed is used at once. A file
    with no profile still asks, and is tallied ``unsupported`` (§10.2)."""
    from shared.ast.cache import owns_answer

    if _owned(file_path, family) is False:
        return None
    prefetch.advance(file_path)
    answer = owns_answer(file_path)
    prefetch.refill()
    return answer


def claim(
    answer: AstAnswer, rule: FamilyRule, file_path: Path, line_num: int, findings: list[Any],
    *, groups: tuple[int, ...] = (),
) -> bool:
    """True when the line loop's line ``line_num`` lies in a sink span ``answer`` reports — the
    AST owns the line — and then, on a sink line, the row ``emit_at`` appends there. The loop's
    line is read as the model's (``model_line``, feature 0105, LLD §4.6): a model line the loop
    splits is owned on each of its loop lines, and its row is appended once, the first time the
    loop asks (``LoopLines.again``). A line outside every span is answered without building the
    call (most lines of an owned file)."""
    spans = answer.spans
    if not spans:
        return False
    line = model_line(answer, line_num)
    if line not in spans:
        return False
    if _again(answer, line):
        return True
    return emit_at(answer, rule, file_path, line, findings, groups=groups)


def _again(answer: AstAnswer, line: int) -> bool:
    """The loop asked about the model line ``line`` before, on another of its loop lines
    (``LoopLines.again``); never where the two numberings agree."""
    return answer.loop is not None and answer.loop.again(line)


def emit_at(
    answer: AstAnswer, rule: FamilyRule, file_path: Path, line: int, findings: list[Any],
    *, groups: tuple[int, ...] = (),
) -> bool:
    """True when the model's line ``line`` lies in a sink span ``answer`` reports, and then, on
    a sink line (``consume.sink_lines``), the row ``emit_for_line`` appends there, built
    through ``_enrich``: enriched as the regex body's rows are, and stamped when it is a member
    of the file's ``groups`` (0104 A2). What ``claim`` appends, and what
    ``injection_check._statement_rows`` appends at each CWE-89 sink line it keeps (feature
    0105, LLD §4.6)."""
    return emit_for_line(
        answer.spans or {}, line, rule, file_path=file_path, nl_lines=answer.nl_lines,
        findings=findings, enrich=_enrich(groups),
    )


def _enrich(groups: tuple[int, ...]) -> Enrich:
    """``emit_for_line``'s ``enrich`` for the head (D-S (1)): the catalog's ``enrich_finding``
    (A41 (5)), then the group's stamp (``consume.stamp_member``, 0104 A2) when the row's own
    line is one of the file's ``groups``."""

    def enrich(row: Finding, cwe_id: str) -> Finding:
        row = enrich_finding(row, cwe_id)
        if row["line_start"] in groups:
            stamp_member(row, groups)
        return row

    return enrich


def ast_owns(
    answer: AstAnswer, rule: FamilyRule, file_path: Path, line_num: int, findings: list[Any],
    *, groups: tuple[int, ...] = (),
) -> bool:
    """The head of a check the AST tier owns line by line (LLD §9.3): True when the tier owns
    ``rule``'s check on the file — ``answer`` holds its spans — and then ``claim``'s row at
    ``line_num``, if any (stamped with the file's 0104 A2 ``groups``); False when the regex
    body owns the file and runs on the line."""
    if answer.spans is None:
        return False
    claim(answer, rule, file_path, line_num, findings, groups=groups)
    return True


def regex_row(
    rule: CatalogRule, description: str, file_path: Path, line_num: int, lines: Sequence[str],
    **extra: Any,
) -> dict[str, Any]:
    """A regex body's row at ``line_num``: ``rule``'s identity row (``consume.rule_row``, D19)
    with the body's own ``description`` and ``extra`` keys, numbered from ``lines``,
    enriched."""
    row = rule_row(rule, description, file_path=file_path, line=line_num, lines=lines, **extra)
    return enrich_finding(row, rule.cwe_id)
