"""A member with a backreference must be REFUSED, not silently broken.

Plan §11.3. Scoped inline flags fix flags; they do nothing about group
NUMBERING. Alternating N patterns renumbers every capture group, so a member
containing `\\1` (or `(?P=name)`, or a conditional `(?(1)...)`) refers to a
DIFFERENT group inside the union than it did alone — and simply stops matching.
No exception is raised, so the failure is a silent loss of detection: a
violation of the union's contract in the direction of FEWER matches.

Refusing at construction turns a silent detection loss into a loud error at
import time, which is the only point where it can be seen.
"""

import re

import pytest

from shared.tools.pattern_union import union_patterns


class TestBackreferenceRefused:
    def test_numeric_backreference(self):
        doubled = re.compile(r"(\w+)\s+\1")
        with pytest.raises(ValueError, match="backreference|group"):
            union_patterns([re.compile(r"plain"), doubled])

    def test_named_backreference(self):
        named = re.compile(r"(?P<w>\w+)\s+(?P=w)")
        with pytest.raises(ValueError, match="backreference|group"):
            union_patterns([re.compile(r"plain"), named])

    def test_conditional_group(self):
        cond = re.compile(r"(a)?(?(1)b|c)")
        with pytest.raises(ValueError, match="backreference|group|conditional"):
            union_patterns([re.compile(r"plain"), cond])


class TestTheFailureItPrevents:
    def test_backreference_would_have_broken_silently(self):
        """Proves the refusal is not theoretical."""
        doubled = re.compile(r"(\w+)\s+\1")
        assert doubled.search("hello hello")
        # Hand-built union with a preceding capture group: \1 now points at the
        # WRONG group and the member stops matching, with no error raised.
        naive = re.compile(r"(?:(x)(y))|(?:(\w+)\s+\1)")
        assert not naive.search("hello hello")


class TestNonCapturingMembersStillWork:
    def test_plain_members_union(self):
        u = union_patterns([re.compile(r"alpha"), re.compile(r"BETA", re.IGNORECASE)])
        assert u.search("alpha") and u.search("beta") and not u.search("gamma")

    def test_capturing_group_without_backref_is_allowed(self):
        u = union_patterns([re.compile(r"(alpha)"), re.compile(r"(beta)")])
        assert u.search("beta")
