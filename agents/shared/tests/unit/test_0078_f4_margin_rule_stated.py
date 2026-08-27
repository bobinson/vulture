"""Feature 0078, Track F guard F4 (AC15.4) — superseded phrasing must not survive.

THE INVARIANT THIS PINS
-----------------------
The backend's per-agent cutoff must clear the agent's own whole-audit ceiling by
a WHOLE llm call:

    VULTURE_AGENT_PROXY_TIMEOUT_SEC >= VULTURE_AGENT_MAX_AUDIT_SECONDS
                                     + VULTURE_LLM_CALL_TIMEOUT_SEC

The rule that used to be documented — ``PROXY >= MAX_AUDIT``, with no margin
term — LOOKS sufficient and is not: an agent checks its own deadline only
BETWEEN llm calls, so after the deadline passes it can still be inside one call
for a full VULTURE_LLM_CALL_TIMEOUT_SEC before it looks again. Measured,
7500/7200/600 satisfies the old rule and still truncated four agents at exactly
2h5m; when the backend closes first the agent never sends its result snapshot
and its findings are rescued from the delta path WITHOUT provenance, validation,
snippets or score.

The margin term was reported as documented, and three restatements of the old
rule survived that report — one of them INVERTED — plus one in
``docker-compose.yml``. That is why this is a test and not a re-read: wherever a
file states the ordering between those two knobs, the margin term must be stated
with it.

Deliberately narrow (plan §15.5): it pins ONE mechanically decidable fact whose
misstatement has already cost a truncated run. Extend it by adding a path to
``TARGET_FILES`` when another invariant earns the same treatment; a general
"docs must be consistent" checker is not buildable.
"""

from __future__ import annotations

import pathlib
import re

import pytest

# test file: agents/shared/tests/unit/ -> repo root is parents[4].
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]

# AC15.4 names exactly these three files.
# Widened after the first version of this guard shipped: an adversarial review
# found TWO live restatements of the superseded rule OUTSIDE the three files the
# AC named, and one of them was actively harmful --
# docs/guides/native_installation.md recommended PROXY=7500 alongside
# MAX_AUDIT=7200 and LLM_CALL=600, i.e. the exact configuration that truncated
# four agents at 2h5m. A reader following that guide reproduced the bug.
#
# The lesson is the guard's own: a checker scoped to the files someone remembered
# is not a guard, it is a spot check. Anything that STATES the invariant answers
# to it, including source comments.
TARGET_FILES = (
    "env.example",
    "CLAUDE.md",
    "docker-compose.yml",
    "docs/guides/native_installation.md",
    "backend/internal/service/agent_proxy_service.go",
)

# How many lines either side of a detected ordering statement may carry the
# margin term. A wrapped comment splits the rule across lines, so the term does
# not have to sit on the same line -- only next to it.
MARGIN_WINDOW = 3

# The backend cutoff, spelled in full or by the shorthand the docs already use
# ("PROXY >= MAX_AUDIT + LLM_CALL_TIMEOUT"). Shorthand is matched case
# sensitively so ordinary prose about a reverse "proxy" cannot trip it.
_PROXY = re.compile(r"VULTURE_AGENT_PROXY_TIMEOUT_SEC|(?<![A-Za-z_])PROXY(?![A-Za-z_])")
# The agent's own whole-audit ceiling.
_CEILING = re.compile(
    r"VULTURE_AGENT_MAX_AUDIT_SECONDS|(?<![A-Za-z_])MAX_AUDIT(?![A-Za-z_])"
)
# The margin term -- the whole point of the rule. Merely NAMING it is not
# evidence that the rule states it: `VULTURE_LLM_CALL_TIMEOUT_SEC=120` on the
# next line is a knob definition, not a margin. The term counts only in an
# ADDITIVE position (`+ LLM_CALL`, `PROXY - LLM_CALL`, "plus one whole call"),
# because that `+` is exactly what the superseded rule was missing.
_MARGIN_TOKEN = r"VULTURE_LLM_CALL_TIMEOUT_SEC|LLM_CALL(?:_TIMEOUT)?(?![A-Za-z_])"
_MARGIN = re.compile(
    r"(?:[+-]|(?i:\bplus\b|\bminus\b))"
    r"\s*(?i:one\s+)?(?i:(?:whole|full|entire)\s+)*"
    rf"(?:{_MARGIN_TOKEN})"
    rf"|(?:{_MARGIN_TOKEN})\s*[+-]"
)
# An arithmetic margin spelled in numbers rather than knob names -- e.g.
# "900 > 600 - 120". Accepted only inside the statement itself, never merely
# nearby, because stray numbers are common and a margin is not.
_NUMERIC_MARGIN = re.compile(r"\d+\s*[+-]\s*\d+")
# An ordering claim. Bare < / > only when whitespace-delimited, so arrows
# (`->`, `=>`) and YAML/markdown punctuation are not comparators.
_ORDERING = re.compile(
    r">=|<=|\s>\s|\s<\s"
    r"|at or below|at or above|no more than|no less than"
    r"|not exceed|at most|at least",
    re.IGNORECASE,
)

_FIX = (
    "state the MARGIN RULE in full: VULTURE_AGENT_PROXY_TIMEOUT_SEC >= "
    "VULTURE_AGENT_MAX_AUDIT_SECONDS + VULTURE_LLM_CALL_TIMEOUT_SEC (NOT merely "
    ">= VULTURE_AGENT_MAX_AUDIT_SECONDS). VULTURE_LLM_CALL_TIMEOUT_SEC must appear "
    f"within {MARGIN_WINDOW} lines of the ordering AND in an additive position "
    "(`+ VULTURE_LLM_CALL_TIMEOUT_SEC`, or `PROXY - VULTURE_LLM_CALL_TIMEOUT_SEC` "
    "when writing the rule from the agent side) -- naming the knob without the "
    "`+`/`-` is the superseded rule with a decoration. Or delete the ordering claim."
)


# A wrapped comment continues with its own marker, and leaving it in place breaks
# every adjacency check across the wrap. Measured: the correctly-stated rule
#     // MARGIN RULE: must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS +
#     // VULTURE_LLM_CALL_TIMEOUT_SEC, NOT merely >= MAX_AUDIT.
# joined to "... SECONDS + // VULTURE_LLM_CALL_TIMEOUT_SEC", so the additive
# position test could not see the `+` beside the term and the guard flagged a
# CORRECT statement. The docstring already claimed wrapped statements were seen
# whole; this makes that true.
_CONTINUATION = re.compile(r"^\s*(?://+|#+)\s?")


def _unit(lines: list[str], index: int) -> str:
    """One line joined with the next, so a wrapped statement is seen whole."""
    tail = lines[index + 1] if index + 1 < len(lines) else ""
    return f"{lines[index]} {_CONTINUATION.sub('', tail)}"


def _is_ordering_statement(unit: str) -> bool:
    """True when `unit` orders one of the two timeout knobs against something."""
    if not _ORDERING.search(unit):
        return False
    return bool(_PROXY.search(unit) or _CEILING.search(unit))


# Text that QUOTES the superseded rule in order to reject it is not a statement
# of the rule. Without this the guard flags its own explanation --
# "The documented invariant used to be PROXY >= AGENT_MAX, and it is not enough"
# is the clearest possible statement that the old rule is wrong, and reporting it
# as a violation is the false positive that gets a guard deleted by the next
# person to read it.
#
# Mechanically decidable: a rejection marker in the same window.
_REJECTION = re.compile(
    # Deliberately EXCLUDES "not merely": that phrase belongs to the CORRECT
    # rule ("must be >= A + B, NOT merely >= A"), so treating it as a rejection
    # marker excused a statement that had lost its margin term -- caught by this
    # guard's own non-vacuity test on CLAUDE.md.
    r"\b(?:used to be|previously|superseded|no longer|not enough|insufficient"
    r"|is wrong|was wrong|old (?:rule|invariant)|pre-fix|before this)\b",
    re.IGNORECASE,
)


def _rejects_the_old_rule(lines: list[str], index: int) -> bool:
    """True when THIS statement marks the old rule as superseded.

    Scoped to the statement unit, not a window. A window-wide exemption is too
    generous: a file that rejects the old rule in one paragraph and then
    misstates it in another would be excused entirely -- and it also defeated
    this guard's own non-vacuity tests, which strip the margin term from a real
    file and require the flag to appear.
    """
    return bool(_REJECTION.search(_unit(lines, index)))


def _margin_stated(lines: list[str], index: int) -> bool:
    """True when a margin term qualifies the statement at `index`."""
    low = max(0, index - MARGIN_WINDOW)
    high = min(len(lines), index + 2 + MARGIN_WINDOW)
    # Search JOINED units, not raw lines: the additive position can straddle a
    # comment wrap, with the `+` ending one line and the term starting the next.
    # Searching raw lines could never see that, which is why a correctly-stated
    # rule was reported as a violation.
    if any(_MARGIN.search(_unit(lines, i)) for i in range(low, high)):
        return True
    return bool(_NUMERIC_MARGIN.search(_unit(lines, index)))


def _anchor(lines: list[str], index: int) -> int:
    """The line of the statement that carries the comparison (0-based)."""
    if _ORDERING.search(lines[index]):
        return index
    return index + 1


def ordering_statements(text: str) -> list[tuple[int, str]]:
    """Every (1-based lineno, line) that states a timeout ordering.

    A statement is read as one line joined with the next, so a rule wrapped
    across two comment lines is still seen whole; the reported line is the one
    carrying the comparison, and duplicate anchors collapse.
    """
    lines = text.splitlines()
    hits: dict[int, int] = {}
    for i, _ in enumerate(lines):
        if not _is_ordering_statement(_unit(lines, i)):
            continue
        hits.setdefault(_anchor(lines, i), i)
    return [(a + 1, lines[a].strip()) for a in sorted(hits)]


def margin_rule_violations(text: str) -> list[tuple[int, str]]:
    """Ordering statements that never state the margin term."""
    lines = text.splitlines()
    return [
        (lineno, line)
        for lineno, line in ordering_statements(text)
        if not _margin_stated(lines, lineno - 1)
        and not _rejects_the_old_rule(lines, lineno - 1)
    ]


# ---------------------------------------------------------------------------
# NON-VACUITY. A guard that passes because it finds nothing is indistinguishable
# from a guard that cannot see, so the checker is first shown to FLAG the old
# phrasing -- in every shape it has actually appeared in -- on synthetic source.
# No repository file is mutated by any test here.
# ---------------------------------------------------------------------------

_OLD_RULE_SHAPES = {
    "forward, full names": (
        "# VULTURE_AGENT_PROXY_TIMEOUT_SEC must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS\n"
    ),
    "INVERTED, full names": (
        "# VULTURE_AGENT_MAX_AUDIT_SECONDS should be <= the backend per-agent\n"
        "# timeout VULTURE_AGENT_PROXY_TIMEOUT_SEC so the backend does not cut in\n"
    ),
    "shorthand": "#     PROXY >= MAX_AUDIT\n",
    "prose, no comparator glyph": (
        "# Keep VULTURE_AGENT_MAX_AUDIT_SECONDS at or below the backend cutoff.\n"
    ),
    "wrapped across two lines": (
        "# The backend's per-agent cutoff. Must be >=\n"
        "#     VULTURE_AGENT_MAX_AUDIT_SECONDS (900 below), or the backend severs\n"
    ),
    "yaml comment above the knob": (
        "      # Must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS (900 below).\n"
        "      - VULTURE_AGENT_PROXY_TIMEOUT_SEC=${VULTURE_AGENT_PROXY_TIMEOUT_SEC:-1200}\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(_OLD_RULE_SHAPES))
def test_synthetic_old_rule_is_flagged(shape: str) -> None:
    """The guard fires on the superseded phrasing (non-vacuity proof)."""
    violations = margin_rule_violations(_OLD_RULE_SHAPES[shape])
    assert violations, (
        f"F4 guard is BLIND: the {shape!r} form of the superseded rule "
        f"{_OLD_RULE_SHAPES[shape]!r} was not flagged. The guard cannot protect "
        "the margin rule until this synthetic case fails detection-free. Widen "
        "_ORDERING / _PROXY / _CEILING in this file."
    )


_CORRECTED_SHAPES = {
    "forward, full names": (
        "# VULTURE_AGENT_PROXY_TIMEOUT_SEC must stay >= VULTURE_AGENT_MAX_AUDIT_SECONDS\n"
        "#     + VULTURE_LLM_CALL_TIMEOUT_SEC (the MARGIN RULE).\n"
    ),
    "shorthand": (
        "#     PROXY >= MAX_AUDIT + LLM_CALL_TIMEOUT      (7800 >= 7200 + 600)\n"
        "#   NOT merely PROXY >= MAX_AUDIT. An agent checks its deadline only\n"
        "#   BETWEEN llm calls.\n"
    ),
    "agent side, subtractive": (
        "# Keep this value at or below\n"
        "#     VULTURE_AGENT_PROXY_TIMEOUT_SEC - VULTURE_LLM_CALL_TIMEOUT_SEC\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(_CORRECTED_SHAPES))
def test_synthetic_corrected_rule_is_clean(shape: str) -> None:
    """The corrected phrasing must NOT be flagged, or the guard is unusable."""
    assert margin_rule_violations(_CORRECTED_SHAPES[shape]) == [], (
        f"F4 guard is OVER-EAGER: the {shape!r} form already states the margin "
        "term and was flagged anyway. Fix the detector in this file, not the docs."
    )


def test_margin_term_must_be_nearby_not_merely_somewhere() -> None:
    """A margin term far from the statement does not corroborate it.

    Proximity is the whole mechanism: a file that names
    VULTURE_LLM_CALL_TIMEOUT_SEC once, hundreds of lines from a restatement of
    the old rule, still misleads the operator reading that restatement.
    """
    far = (
        "# VULTURE_AGENT_PROXY_TIMEOUT_SEC must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS\n"
        + "# filler\n" * (MARGIN_WINDOW + 2)
        + "# VULTURE_LLM_CALL_TIMEOUT_SEC=120\n"
    )
    assert margin_rule_violations(far), (
        "F4 guard accepted a margin term more than "
        f"{MARGIN_WINDOW} lines from the ordering it is supposed to qualify."
    )

    near = (
        "# VULTURE_AGENT_PROXY_TIMEOUT_SEC must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS\n"
        "# plus one whole VULTURE_LLM_CALL_TIMEOUT_SEC.\n"
    )
    assert margin_rule_violations(near) == [], (
        "F4 guard rejected a margin term on the adjacent line; MARGIN_WINDOW "
        "must admit a wrapped statement."
    )


# ---------------------------------------------------------------------------
# The guard must be looking at real content. Without this, a bad path or an
# empty read would make AC15.4 pass by seeing nothing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relpath", TARGET_FILES)
def test_guard_actually_reads_the_target_file(relpath: str) -> None:
    path = _REPO_ROOT / relpath
    assert path.is_file(), (
        f"F4 guard cannot see {relpath}: {path} does not exist. Fix TARGET_FILES "
        "or _REPO_ROOT in this test -- do not delete the assertion."
    )
    text = path.read_text(encoding="utf-8")
    statements = ordering_statements(text)
    assert statements, (
        f"F4 guard found NO timeout-ordering statement in {relpath}. Either the "
        "margin rule was dropped from that file (restate it) or the detector no "
        "longer matches how it is written -- a guard that sees nothing proves "
        "nothing."
    )


@pytest.mark.parametrize("relpath", TARGET_FILES)
def test_guard_would_flag_the_real_file_with_the_margin_removed(relpath: str) -> None:
    """Non-vacuity against the REAL content, not just synthetic strings.

    Every margin term is stripped from an in-memory copy of the shipped file
    (the file on disk is never touched). What remains is precisely the
    superseded phrasing, so the guard must flag it -- otherwise AC15.4 passes on
    this file for reasons unrelated to what it says.
    """
    text = (_REPO_ROOT / relpath).read_text(encoding="utf-8")
    stripped = re.sub(_MARGIN_TOKEN, "MARGIN_TERM_REMOVED", text)
    stripped = _NUMERIC_MARGIN.sub("N", stripped)
    assert margin_rule_violations(stripped), (
        f"F4 guard is VACUOUS for {relpath}: with every margin term removed it "
        "still reports the file clean. Its ordering statements are not being "
        "checked -- fix the detector in this test file."
    )


# ---------------------------------------------------------------------------
# AC15.4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relpath", TARGET_FILES)
def test_no_superseded_margin_rule_phrasing(relpath: str) -> None:
    """AC15.4 — no file states the margin rule without its margin term."""
    path = _REPO_ROOT / relpath
    violations = margin_rule_violations(path.read_text(encoding="utf-8"))
    report = "\n".join(f"  {relpath}:{n}: {line[:160]}" for n, line in violations)
    assert not violations, (
        f"{relpath} states the VULTURE_AGENT_PROXY_TIMEOUT_SEC / "
        "VULTURE_AGENT_MAX_AUDIT_SECONDS ordering without the margin term "
        f"VULTURE_LLM_CALL_TIMEOUT_SEC:\n{report}\n\nTo fix: at each line above, "
        f"{_FIX}"
    )
