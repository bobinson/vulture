"""Feature 0105 (LLD §4.1): pins for classifier branches no ``test_0105_command_classes`` row
reaches on its own.

Each row is a program, the glued key of the one CALL it is about, and that call's class, as
``test_0105_command_classes`` spells a row (the same ``_assert_class``). The first five
classes are the measured prototype's with every piece on; the other ten are the built
classifier's, each also measured with its clause removed (the class named "else" below).
Removing the branch a row names makes that row fail (but ``ce_shell_true_text``'s, below):

* WS-C, the glued clause of ``_regex_named``: ``RegExp`` glues to ``regexp`` while its head word
  is ``exp``, so only the glued reading takes the receiver as a regex (None);
* WS-C, ``_head_word`` past ``MAX_WORDS`` (E5): a receiver of ``MAX_WORDS + 1`` words ending in
  ``Regex`` has no head word, so it stays a process; its ``MAX_WORDS``-th word is ``Regex`` too,
  so a head word read off the capped words would wrongly make it a regex. At ``MAX_WORDS`` words
  the head word is read (None);
* WS-A on every path (E3): a receiver bound to a data store on one path and to another call on
  the other is no data store (a process);
* WS-A over mixed reaching Defs: a typed ``*sql.DB`` parameter reassigned from ``sql.Open`` on
  one path is a data store on both, the type words of the one and the chain words of the other
  (``store``);
* D-7 (feature 0105, LLD §3.2 E2, §3.4 N4): E2 outranks the regex exit, so a receiver bound to
  a regex literal or construction on every path but named with a process word (``PROCESS_RE``,
  ``childRe``, ``shellRe``) is a process, a CWE-78 sink where the base was silent: the named
  cost of D-7, pinned as built (``process``; else None);
* E2's binding clause (``_bound_meets`` over ``PROCESS_WORDS``) alone keeps a call a process
  against a later rule: the type words of a reaching parameter (``p *ProcDB``, else a data
  store) and the chain words of a reaching call (``re = m.childProcess()``, else a regex by its
  name); E2's literal ``shell=True`` alone keeps ``db.run(cmd, shell=True)`` a process (else a
  data store);
* command evidence's binding half (``_bound_meets`` over the command-evidence words) alone keeps
  a call a process against WS-S and WS-D: the chain words of a reaching call
  (``h = m.sshConnect()``, else ``text``; ``r = m.command_runner()``, else ``unproven``) and the
  type words of a reaching parameter (``s *SshSession``, else ``text``). Its ``shell=True`` half
  is pinned by ``ce_shell_true_text`` as built; E2 tests the same literal two rules earlier, so
  that row stays a process with the half removed (feature 0105, LLD §5.6).
"""

from __future__ import annotations

from string import ascii_lowercase

import pytest

from shared.ast.limits import MAX_WORDS
from shared.ast.roles import REGEX_WORDS
from shared.ast.roles._words import word_count, words
from tests.unit.ast.test_0105_command_classes import (
    GO_HTTP,
    PROCESS,
    STORE,
    Row,
    _assert_class,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# ``MAX_WORDS - 1`` words in no lexicon (``Qax``, ``Qbx``, ...), so only the last words decide.
FILLER = "".join(f"Q{letter}x" for letter in ascii_lowercase[: MAX_WORDS - 1])
AT_CAP = FILLER + "Regex"  # MAX_WORDS words, the last ``regex``
PAST_CAP = FILLER + "RegexRegex"  # MAX_WORDS + 1 words, the last two ``regex``


def _named_receiver(name: str, cls: str | None) -> Row:
    """A JavaScript ``exec`` call on a parameter receiver named ``name``, of class ``cls``."""
    return (("js", f"function f({name}, c) {{ {name}.exec(c); }}\n"), "exec", cls)


BRANCH_PINS: dict[str, Row] = {
    # WS-C: _regex_named's glued clause
    "c_glued_only_regexp": _named_receiver("RegExp", None),
    # WS-C: _head_word past MAX_WORDS (E5), and at it
    "c_head_word_past_cap": _named_receiver(PAST_CAP, PROCESS),
    "c_head_word_at_cap": _named_receiver(AT_CAP, None),
    # WS-A: a data store on every path (E3), and over mixed reaching Defs
    "a_store_on_one_path_only": (
        ("go", GO_HTTP + 'func f(o X, q string, c bool) { h, _ := sql.Open("x", "y"); '
                         'if c { h = o.Make() }; h.Exec(q) }\n'),
        "exec", PROCESS),
    "a_store_mixed_reach": (
        ("go", GO_HTTP + 'func f(h *sql.DB, q string, c bool) { '
                         'if c { h, _ = sql.Open("x", "y") }; h.Exec(q) }\n'),
        "exec", STORE),
    # D-7: E2 (a process word in the receiver's own name) outranks a regex binding
    "d7_process_named_regex_literal": (
        ("js", 'const PROCESS_RE = /^(\\w+)\\s+(\\d+)/;\n'
               'function f(req, res) { res.json(PROCESS_RE.exec(req.query.line)); }\n'),
        "exec", PROCESS),
    "d7_child_named_regex_literal": (
        ("js", 'const childRe = /^child:(.*)$/;\n'
               'function parse(x) { return childRe.exec("child:" + x); }\n'),
        "exec", PROCESS),
    "d7_shell_named_regex_construction": (
        ("js", 'const shellRe = new RegExp("^x");\n'
               'function f(req) { return shellRe.exec(req.body.out); }\n'),
        "exec", PROCESS),
    # E2: the binding clause alone (a data store, a regex by name, without it)
    "e2_bound_param_type": (
        ("go", GO_HTTP + 'type ProcDB struct{}\nfunc f(p *ProcDB, cmd string) { p.Exec(cmd) }\n'),
        "exec", PROCESS),
    "e2_bound_call_chain": (
        ("js", 'function f(m, c) { const re = m.childProcess(); re.exec(c); }\n'),
        "exec", PROCESS),
    # E2: the literal shell=True alone (a data store without it)
    "e2_shell_true_store": (
        ("py", 'def f(db, cmd):\n    db.run(cmd, shell=True)\n'), "run", PROCESS),
    # command evidence: the binding half alone (statement text or WS-D without it)
    "ce_bound_call_text": (
        ("js", 'function f(m, x) { const h = m.sshConnect(); '
               'h.exec("DELETE FROM t WHERE id = " + x); }\n'),
        "exec", PROCESS),
    "ce_bound_param_type_text": (
        ("go", GO_HTTP + 'type SshSession struct{}\nfunc f(s *SshSession, x string) { '
                         's.Exec("DELETE FROM t WHERE id = " + x) }\n'),
        "exec", PROCESS),
    "ce_bound_call_system": (
        ("py", 'def f(m, cmd):\n    r = m.command_runner()\n    r.system(cmd)\n'),
        "system", PROCESS),
    # command evidence: the shell=True half, as built (E2 holds the same literal first)
    "ce_shell_true_text": (
        ("py", 'def f(h, x):\n    h.run("DELETE FROM t WHERE id = " + x, shell=True)\n'),
        "run", PROCESS),
}


@pytest.mark.parametrize("name", list(BRANCH_PINS))
def test_branch_pin_class(name: str) -> None:
    _assert_class(BRANCH_PINS[name])


def test_head_word_names_sit_at_and_past_the_cap() -> None:
    """The two head-word rows test the cap: ``AT_CAP`` has ``MAX_WORDS`` words and ``PAST_CAP``
    one more, whose capped words end in a regex word, so only the cap branch keeps it a process."""
    assert (word_count(AT_CAP), word_count(PAST_CAP)) == (MAX_WORDS, MAX_WORDS + 1)
    assert words(AT_CAP)[-1] == words(PAST_CAP)[-1] == "regex"
    assert "regex" in REGEX_WORDS
