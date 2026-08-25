"""Shared `union_patterns` — the four edge cases the ASVS-local `_union` missed.

The local helper (asvs_agent/skills/asvs_requirements_check.py) already fixed
the flag-widening defect: each member keeps its OWN i/m/s via a SCOPED inline
group so one `re.IGNORECASE` sibling cannot re-flag a case-sensitive one. This
suite locks that fix in the shared leaf module and adds the cases the local
version does not handle:

1. EMPTY input. `"|".join([])` is `""`, and `re.compile("")` matches
   EVERY position of EVERY subject. A skill whose pattern list happened to be
   empty (a config gate, a filtered edition, a data-file load that returned
   nothing) would therefore fire on every line of every file — a silent flood,
   not an error. The shared version must return a NEVER-matching pattern.

2. DUPLICATE NAMED GROUPS across members. `(?P<x>..)|(?P<x>..)` is an
   `re.error` raised from inside `re.compile`, i.e. from a module-load line
   that names neither colliding member. Must raise a clear error naming the
   group and both patterns.

3. Scoped `(?i:...)` must be SEMANTICALLY IDENTICAL to compiling that member
   alone — including `\\b` sitting at a member boundary (where the alternation
   `|` and the group wrapper are inserted) and lookarounds (which must still
   see the subject outside the group, not just inside it). Verified against
   the standalone compile, not assumed.

4. Unioning RENUMBERS capture groups: member 2's group 1 becomes group N.
   Anything reading `.group(n)` on a union reads the WRONG group. Callers must
   use `search()` truthiness only; the asvs-side suite proves its callers do.
"""
from __future__ import annotations

import re

import pytest

from shared.tools.pattern_union import union_patterns


class TestEmptyInputNeverMatches:
    """(1) The silent-flood case: `re.compile("")` matches everything."""

    def test_empty_list_does_not_match_ordinary_text(self):
        assert union_patterns([]).search("const rate = ecb.rates[key];") is None

    def test_empty_list_does_not_match_the_empty_string(self):
        assert union_patterns([]).search("") is None

    def test_empty_list_does_not_match_at_any_position(self):
        pat = union_patterns([])
        assert pat.match("anything") is None
        assert pat.fullmatch("") is None
        assert list(pat.finditer("a\nb\nc")) == []

    def test_empty_list_is_not_the_empty_pattern(self):
        # The whole point: "" would match. Guard the construction, not just
        # one probe subject.
        assert union_patterns([]).pattern != ""

    def test_empty_tuple_and_generator_also_never_match(self):
        assert union_patterns(()).search("x") is None
        assert union_patterns(p for p in []).search("x") is None


class TestDuplicateNamedGroups:
    """(2) A clear error naming the collision, not a distant `re.error`."""

    def test_collision_raises_valueerror_naming_the_group(self):
        members = [
            re.compile(r"key\s*=\s*(?P<val>\w+)"),
            re.compile(r"token\s*=\s*(?P<val>\w+)"),
        ]
        with pytest.raises(ValueError) as exc:
            union_patterns(members)
        assert "val" in str(exc.value)

    def test_collision_error_names_both_colliding_patterns(self):
        members = [
            re.compile(r"key\s*=\s*(?P<val>\w+)"),
            re.compile(r"token\s*=\s*(?P<val>\w+)"),
        ]
        with pytest.raises(ValueError) as exc:
            union_patterns(members)
        msg = str(exc.value)
        assert "key" in msg and "token" in msg

    def test_collision_is_not_a_bare_re_error(self):
        members = [re.compile(r"(?P<a>x)"), re.compile(r"(?P<a>y)")]
        with pytest.raises(ValueError) as exc:
            union_patterns(members)
        assert not isinstance(exc.value, re.error)

    def test_distinct_named_groups_are_allowed_and_usable(self):
        u = union_patterns(
            [re.compile(r"key=(?P<k>\w+)"), re.compile(r"tok=(?P<t>\w+)")]
        )
        assert u.search("tok=abc").group("t") == "abc"

    def test_error_message_says_it_is_a_union_collision(self):
        members = [re.compile(r"(?P<dup>x)"), re.compile(r"(?P<dup>y)")]
        with pytest.raises(ValueError, match="union_patterns"):
            union_patterns(members)


def _parity_corpus() -> list[tuple[re.Pattern[str], list[str]]]:
    """(member, subjects) pairs whose standalone behaviour must survive union.

    Deliberately includes the shapes where a naive `"|".join` breaks:
    `\\b` at a member boundary, a lookBEHIND at the very start of a member
    (must see text BEFORE the group), a negative lookAHEAD spanning the rest
    of the line, and mixed per-member case sensitivity.
    """
    return [
        # \b at both member boundaries, case-SENSITIVE.
        (re.compile(r"\bECB\b"), ["mode = ECB", "ecb.rates", "XECBX", " ECB "]),
        # \b with per-member IGNORECASE.
        (
            re.compile(r"\bBlowfish\b", re.IGNORECASE),
            ["cipher = blowfish.new(k)", "BLOWFISH", "myBlowfishThing"],
        ),
        # Lookbehind at the START of the member.
        (
            re.compile(r"(?<![.\w])exec\s*\("),
            ["exec(cmd)", "db.exec(q)", "safe_exec(q)", "  exec (x)"],
        ),
        # Negative lookahead reaching to end of line.
        (
            re.compile(r"Content-Type\s*:\s*text/html(?!.*charset)", re.IGNORECASE),
            [
                "Content-Type: text/html",
                "content-type: text/html; charset=utf-8",
                "Content-Type: text/html; boundary=x",
            ],
        ),
        # MULTILINE anchor.
        (re.compile(r"^secret", re.MULTILINE), ["a\nsecret=1", "xsecret=1"]),
        # DOTALL.
        (re.compile(r"BEGIN.*END", re.DOTALL), ["BEGIN\nmid\nEND", "BEGIN\nmid"]),
        # No flags, plain literal with a capture group (renumbering bait).
        (re.compile(r"md5\((\w+)\)"), ["md5(x)", "MD5(x)"]),
    ]


class TestScopedFlagsAreSemanticallyIdentical:
    """(3) Verified against the standalone compile — not assumed."""

    @pytest.mark.parametrize(
        ("member", "subjects"),
        _parity_corpus(),
        ids=lambda v: None,
    )
    def test_single_member_union_matches_standalone(self, member, subjects):
        u = union_patterns([member])
        for s in subjects:
            assert bool(u.search(s)) == bool(member.search(s)), (member.pattern, s)

    def test_single_member_union_span_matches_standalone(self):
        for member, subjects in _parity_corpus():
            u = union_patterns([member])
            for s in subjects:
                mine, theirs = u.search(s), member.search(s)
                if theirs is None:
                    assert mine is None
                else:
                    assert mine is not None and mine.span() == theirs.span()

    def test_full_union_is_the_or_of_every_member(self):
        corpus = _parity_corpus()
        members = [m for m, _ in corpus]
        subjects = [s for _, subs in corpus for s in subs]
        u = union_patterns(members)
        for s in subjects:
            expected = any(m.search(s) for m in members)
            assert bool(u.search(s)) is expected, s

    def test_case_sensitive_member_is_not_widened_by_ignorecase_sibling(self):
        u = union_patterns(
            [re.compile(r"ECB\b"), re.compile(r"\bBlowfish\b", re.IGNORECASE)]
        )
        assert u.search("mode = ECB")
        assert u.search("cipher = blowfish.new(key)")
        assert not u.search("const rate = ecb.rates[key];")
        assert not u.search('rows = ecb.fetch(currency, mode="daily")')

    def test_multiline_member_does_not_leak_onto_siblings(self):
        u = union_patterns([re.compile(r"^aaa", re.MULTILINE), re.compile(r"^bbb")])
        assert u.search("x\naaa")
        assert not u.search("x\nbbb")

    def test_dotall_member_does_not_leak_onto_siblings(self):
        u = union_patterns([re.compile(r"A.B", re.DOTALL), re.compile(r"C.D")])
        assert u.search("A\nB")
        assert not u.search("C\nD")

    def test_word_boundary_at_member_boundary_survives_alternation(self):
        # `\b` is the shape most at risk from the inserted group + `|`.
        members = [re.compile(r"\bfoo\b"), re.compile(r"\bbar\b")]
        u = union_patterns(members)
        assert u.search("a foo b")
        assert not u.search("xfoox")
        assert not u.search("xbarx")

    def test_lookbehind_sees_text_outside_the_group(self):
        member = re.compile(r"(?<![.\w])exec\s*\(")
        u = union_patterns([member, re.compile(r"\bnever_here\b")])
        assert u.search("exec(x)")
        assert not u.search("db.exec(x)")
        assert not u.search("do_exec(x)")


class TestUnsupportedFlagsFailLoudly:
    """A flag that cannot be scoped must not be silently dropped."""

    def test_verbose_member_is_rejected(self):
        with pytest.raises(ValueError) as exc:
            union_patterns([re.compile(r"a b", re.VERBOSE)])
        assert "flag" in str(exc.value).lower()

    def test_ascii_member_is_rejected(self):
        with pytest.raises(ValueError):
            union_patterns([re.compile(r"\w+", re.ASCII)])

    def test_supported_flag_trio_is_accepted(self):
        u = union_patterns(
            [re.compile(r"a.b", re.IGNORECASE | re.MULTILINE | re.DOTALL)]
        )
        assert u.search("A\nB")


class TestGroupRenumberingIsDocumented:
    """(4) The renumbering is real; the docstring must warn about it."""

    def test_group_numbers_shift_under_union(self):
        first = re.compile(r"aaa(\d+)")
        second = re.compile(r"bbb(\d+)")
        u = union_patterns([first, second])
        m = u.search("bbb42")
        # Standalone, the digits are group 1. In the union they are group 2.
        assert second.search("bbb42").group(1) == "42"
        assert m.group(1) is None
        assert m.group(2) == "42"

    def test_docstring_warns_about_renumbering(self):
        assert "renumber" in union_patterns.__doc__.lower()


class TestInputRobustness:
    def test_raw_strings_are_rejected_not_silently_treated_as_patterns(self):
        with pytest.raises(TypeError):
            union_patterns(["ECB"])

    def test_global_inline_flag_member_raises_a_clear_error(self):
        # `(?i)foo` is only legal at the START of a whole expression; inside a
        # group Python raises `global flags not at the start of the
        # expression`. Surface that as a named ValueError, not a bare re.error
        # from a module-load line.
        with pytest.raises(ValueError) as exc:
            union_patterns([re.compile(r"(?i)foo"), re.compile(r"bar")])
        assert "inline" in str(exc.value).lower() or "flag" in str(exc.value).lower()

    def test_single_member_no_flags_is_wrapped_not_bare(self):
        # A bare join would let a top-level `|` inside a member escape its
        # alternative.
        u = union_patterns([re.compile(r"a|b"), re.compile(r"cd")])
        assert bool(u.search("b")) and bool(u.search("cd"))
