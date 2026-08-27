"""Combine many compiled regexes into one, without changing what any of them means.

Pattern-based skills keep their detectors as LISTS of small compiled regexes —
one per shape, each with its own flags — and then want a single object to run
per line, because N `search()` calls per line times every line of every file is
the hot loop. This module is that join, and it is a LEAF: it imports only
`re`, so any skill in any agent can use it.

WHY IT IS NOT ``"|".join(p.pattern for p in patterns)``
--------------------------------------------------------
Four ways the obvious version is wrong, all of them silent:

* FLAGS WIDEN. Doing ``flags |= p.flags`` ORs every member's flags onto the
  combined object, so ONE ``re.IGNORECASE`` member re-flags all its
  case-SENSITIVE siblings. Measured in `BROKEN_CRYPTO_PATTERNS`, which mixes
  both kinds: case-sensitive ``ECB\\b`` became case-insensitive and matched
  plain ``ecb`` in ordinary identifiers — and ECB is the European Central Bank
  in any FX or ledger codebase. Fixed here with per-member SCOPED inline
  groups: ``(?i:...)`` applies to that member and nothing else.

* AN EMPTY LIST MATCHES EVERYTHING. ``"|".join([])`` is ``""`` and
  ``re.compile("")`` matches at every position of every subject, so a detector
  whose list came out empty (a config gate, a filtered edition, a data load
  that returned nothing) fires on every line of every file. That is the
  failure mode that floods rather than errors, so it gets an explicit
  never-matching pattern instead — see `NEVER_MATCHES`.

* A TOP-LEVEL ``|`` INSIDE A MEMBER ESCAPES ITS ALTERNATIVE. ``a|b`` joined
  raw with ``cd`` yields ``a|b|cd`` — accidentally fine, but ``a|b`` joined
  with a member that must be anchored is not. Every member is therefore
  wrapped, always, even when it needs no flags.

* DUPLICATE NAMED GROUPS raise `re.error` from inside `re.compile`, i.e. from
  the one module-load line that names NEITHER colliding member. Detected up
  front here and reported with the group name and both patterns.

CAPTURE GROUPS ARE RENUMBERED — READ THIS BEFORE USING A UNION
---------------------------------------------------------------
Wrapping members and concatenating them shifts every group number: a member's
own group 1 becomes group N of the union, where N depends on how many groups
the members BEFORE it declare. So:

    >>> import re
    >>> second = re.compile(r"bbb(\\d+)")
    >>> second.search("bbb42").group(1)
    '42'
    >>> union_patterns([re.compile(r"aaa(\\d+)"), second]).search("bbb42").group(1) is None
    True

Anything that reads ``.group(n)``, ``.groups()`` or ``.lastindex`` on a union
reads the WRONG group, silently. A union is safe for `search()`/`match()`
TRUTHINESS and for `.span()`; it is NOT safe for positional group reads. If a
call site needs a group, keep that pattern OUT of the union and run it alone.
Named groups survive by name (they are checked for collisions above), so
``.group("name")`` is safe if every member's names are distinct.

The union adds no quantifier and no nesting: it is an alternation of the
members as written, so it cannot introduce catastrophic backtracking that the
members did not already have. It also never adds a flag — in particular never
IGNORECASE, which would be wrong for language-capitalised identifiers.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

# Flags that a scoped inline group can carry per member. Anything else cannot
# be expressed per-member here, so it is refused rather than dropped: a
# silently dropped flag changes what the detector matches.
SUPPORTED_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

_FLAG_LETTERS: tuple[tuple[int, str], ...] = (
    (re.IGNORECASE, "i"),
    (re.MULTILINE, "m"),
    (re.DOTALL, "s"),
)

#: The union of NO patterns. ``(?!)`` is a negative lookahead on the empty
#: string: it fails at every position, including in the empty subject. This is
#: the deliberate opposite of ``re.compile("")``, which succeeds everywhere.
NEVER_MATCHES: re.Pattern[str] = re.compile(r"(?!)")


def _member_flag_letters(pattern: re.Pattern[str]) -> str:
    """Inline-flag letters for one member, or '' when it needs none."""
    meaningful = pattern.flags & ~re.UNICODE
    unsupported = meaningful & ~SUPPORTED_FLAGS
    if unsupported:
        raise ValueError(
            "union_patterns: cannot scope flag(s) "
            f"{re.RegexFlag(unsupported)!r} per member, and dropping them "
            f"would change what {pattern.pattern!r} matches. Keep this "
            "pattern out of the union and run it alone."
        )
    return "".join(letter for flag, letter in _FLAG_LETTERS if meaningful & flag)


def _require_compiled(members: list[object]) -> None:
    """Reject raw strings up front, before anything reads pattern attributes."""
    for member in members:
        if not isinstance(member, re.Pattern):
            raise TypeError(
                "union_patterns: expected compiled re.Pattern objects, got "
                f"{type(member).__name__}. Compile the member first so its "
                "flags are explicit."
            )


def _wrap(pattern: re.Pattern[str]) -> str:
    """One member as a self-contained group carrying only its OWN flags."""
    letters = _member_flag_letters(pattern)
    return f"(?{letters}:{pattern.pattern})" if letters else f"(?:{pattern.pattern})"


def _reject_duplicate_group_names(members: list[re.Pattern[str]]) -> None:
    """Fail with the group name and both patterns, not a distant `re.error`."""
    owner: dict[str, str] = {}
    for pattern in members:
        for name in pattern.groupindex:
            previous = owner.get(name)
            if previous is not None:
                raise ValueError(
                    f"union_patterns: duplicate named group {name!r} in two "
                    f"members — {previous!r} and {pattern.pattern!r}. Rename "
                    "one, or keep it out of the union."
                )
            owner[name] = pattern.pattern


# Constructs whose meaning depends on GROUP NUMBER. Alternating N patterns
# renumbers every capture group, so a member carrying one of these refers to a
# different group inside the union than it did alone -- and stops matching, with
# no exception raised. That is a silent loss of detection, so it is refused at
# construction, which is the only point where anyone can see it.
#
# Matched against the pattern SOURCE. `(?<!\\)` skips an escaped backslash, so
# a literal `\\1` in the source is not mistaken for a backreference. A
# backreference inside a character class is not a backreference, but flagging it
# is harmless -- the caller just uses `any()` instead.
_GROUP_DEPENDENT = re.compile(
    r"(?<!\\)\\[1-9]"          # \1 .. \9
    r"|\(\?P=[^)]+\)"          # (?P=name)
    r"|\(\?\([^)]+\)"          # (?(1)yes|no) conditional
)


def _reject_group_dependent(patterns: list[re.Pattern[str]]) -> None:
    """Raise if any member's meaning depends on its group NUMBER."""
    for member in patterns:
        hit = _GROUP_DEPENDENT.search(member.pattern)
        if hit is None:
            continue
        raise ValueError(
            "union_patterns: refusing to union a pattern whose meaning depends "
            f"on a group number ({hit.group(0)!r} in {member.pattern!r}). "
            "Alternation renumbers capture groups, so this member would stop "
            "matching inside the union WITHOUT raising -- a silent loss of "
            "detection. Keep the list and use any(p.search(s) for p in ps) "
            "instead, which preserves each member's meaning by construction."
        )


def union_patterns(patterns: Iterable[re.Pattern[str]]) -> re.Pattern[str]:
    """Alternate many compiled patterns into one, preserving each one's meaning.

    Each member keeps its OWN ``re.IGNORECASE`` / ``re.MULTILINE`` /
    ``re.DOTALL`` via a scoped inline group, so a flag on one member never
    leaks onto another. The returned object carries no flags of its own.

    Args:
        patterns: Compiled patterns. May be any iterable, including empty.

    Returns:
        A compiled pattern matching exactly the subjects that at least one
        member matches. For EMPTY input, `NEVER_MATCHES` — never
        ``re.compile("")``, which would match every position of every
        subject.

    Raises:
        TypeError: A member is not a compiled `re.Pattern`.
        ValueError: A member carries a flag that cannot be scoped per member;
            two members declare the same named group; or a member uses a
            global inline flag (``(?i)`` rather than ``(?i:...)``), which is
            only legal at the start of a whole expression and so cannot be
            nested.

    Warning:
        Unioning RENUMBERS positional capture groups — a member's group 1
        becomes group N of the union. Use the result for `search()`
        truthiness (or `.span()`), never for ``.group(n)`` /``.groups()``.
        Named groups are safe by name; the collision check above is what makes
        that true.
    """
    members = list(patterns)
    if not members:
        return NEVER_MATCHES
    _require_compiled(members)
    _reject_group_dependent(members)
    _reject_duplicate_group_names(members)
    joined = "|".join(_wrap(p) for p in members)
    try:
        return re.compile(joined)
    except re.error as exc:
        raise ValueError(
            f"union_patterns: members do not compose into one pattern ({exc}). "
            "A member using a GLOBAL inline flag such as '(?i)foo' cannot be "
            "nested — pass re.IGNORECASE to re.compile instead, or use the "
            "scoped form '(?i:foo)'."
        ) from exc
