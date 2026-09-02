"""0087 acceptance criteria (plan section 6), asserted mechanically.

These are the falsifiable gates the plan states, not restatements of the
implementation. Two of them caught real regressions during development and are
the reason this file exists rather than a manual check:

* 6.9 caught `_PROPAGATES_STMT` being given a `\\s{0,8}` indent bound during the
  ReDoS work, which silently stopped excusing every `throw` nested more than
  eight columns deep - 62 distinct lines across the three reference repos.
* The scope-leak guard caught `collect_scoped_body` walking past a handler that
  closed its own braces and excusing it with the NEXT handler's log call.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
from shared.tools.snippet import collect_scoped_body

from cwe_agent.skills.insufficient_logging_check import (
    _body_delegates,
    _body_has_logging,
    _body_propagates,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
SKILL_REL = "agents/cwe/cwe_agent/skills/insufficient_logging_check.py"

D3_PREDICATES = (
    ("has_logging", "_body_has_logging", _body_has_logging),
    ("propagates", "_body_propagates", _body_propagates),
    ("delegates", "_body_delegates", _body_delegates),
)


def _pre_0087_skill():
    """Load the committed (pre-0087) skill so D3 can be diffed against it.

    Returns None when 0087 is already committed and HEAD no longer holds a
    pre-0087 copy, in which case the criterion is no longer decidable this way
    and the test skips with that reason rather than passing silently.
    """
    try:
        src = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"HEAD:{SKILL_REL}"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout
    except Exception:
        return None
    if "_GO_SITE" in src:  # HEAD already contains 0087
        return None
    tmp = Path(__file__).parent / "_pre0087_skill.py"
    tmp.write_text(src)
    try:
        spec = importlib.util.spec_from_file_location("_pre0087_skill", tmp)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_pre0087_skill"] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        tmp.unlink(missing_ok=True)


# A compact corpus of body lines that the OLD predicates excused. Checked in
# rather than harvested from the reference repos at test time, so the gate runs
# in CI where those repos are absent. Every entry was produced by the harvest.
D3_EXCUSED_CORPUS = {
    "has_logging": [
        "        logger.error('boom', e)",
        "            console.error(err)",
        "    log.Printf(\"x: %v\", err)",
        "                self.logger.warning(exc)",
    ],
    "propagates": [
        "throw new Error('No such item found!')",
        "        throw new Error('url returned a non-OK status code')",
        # The indent-depth case. Nine or more columns is what the regex bound
        # silently excluded; a handler nested three levels deep is ordinary.
        "         throw new Error('Username is null')",
        "                    throw new Error('deeply nested')",
        "                        raise",
        "    return err",
        "  next(err)",
        "        reject(e)",
        "    callback(err)",
    ],
    "delegates": [
        "        handleError(e)",
        "    self.report_error(&e)",
        "  reportError($e)",
    ],
}


@pytest.mark.parametrize(("label", "_name", "pred"), D3_PREDICATES)
def test_6_9_d3_only_widens_excusals(label, _name, pred) -> None:
    """6.9: no currently-suppressed handler becomes a finding via the D3 rewrite.

    D3 unions new logger/propagate/delegate spellings onto the existing sets, so
    it can only ever ADD excusals. Any line the old predicate excused that the
    new one does not is a lost suppression, i.e. a new false positive.
    """
    corpus = D3_EXCUSED_CORPUS[label]
    assert len(corpus) >= 3, f"{label} corpus has {len(corpus)} lines; gate is vacuous"
    lost = [line for line in corpus if not pred([line])]
    assert not lost, (
        f"{label}: {len(lost)} previously-excused line(s) are now reported, so a "
        f"handler that was correctly suppressed becomes a false positive:\n  "
        + "\n  ".join(repr(x) for x in lost)
    )


@pytest.mark.parametrize(("label", "name", "pred"), D3_PREDICATES)
def test_6_9_against_the_committed_skill(label, name, pred) -> None:
    """The same criterion, diffed against the real pre-0087 implementation."""
    old = _pre_0087_skill()
    if old is None:
        pytest.skip("HEAD holds no pre-0087 skill; 6.9 is pinned by the corpus test")
    old_pred = getattr(old, name)
    corpus = [
        line
        for lines in D3_EXCUSED_CORPUS.values()
        for line in lines
    ]
    considered = [line for line in corpus if old_pred([line])]
    assert considered, f"{label}: old predicate excused none of the corpus; vacuous"
    lost = [line for line in considered if not pred([line])]
    assert not lost, f"{label}: lost suppressions vs the committed skill: {lost}"


def test_indent_depth_does_not_change_propagation() -> None:
    """A `throw` is propagation at ANY indent.

    Pinned separately because the failure mode is a silent bound in a regex, and
    a test that only checks column 0 and column 4 passes straight through it.
    """
    for indent in (0, 4, 8, 9, 12, 24, 40, 79):
        line = " " * indent + "throw new Error('x')"
        assert _body_propagates([line]), f"not propagation at indent {indent}"


def test_non_statement_throw_is_not_propagation() -> None:
    """`obj.throw()` is a generator method, not a rethrow."""
    assert not _body_propagates(["    gen.throw(exc)"])
    assert not _body_propagates(["    obj.raise(x)"])


def test_mixed_line_still_finds_the_real_propagation() -> None:
    """A non-statement `throw` must not mask a genuine `next(err)`.

    The leftmost-match version of this pattern consulted only the first hit, so
    a line carrying both scored as not propagating.
    """
    assert _body_propagates(["  // see: obj.throw and next(err) forms", "  next(err)"])
    assert _body_propagates(["Propagation (raise, throw e, next(err), reject(...))"])


def test_handler_closing_its_own_braces_has_no_body() -> None:
    """A handler that opens and closes on its header line has an EMPTY body.

    Walking past the closing brace collects the following handler's lines, which
    excuses an empty handler with its neighbour's log call.
    """
    lines = (
        "function a() {",
        "  do { f() } catch { }",
        "  do { f() } catch { console.error(e) }",
        "}",
    )
    assert collect_scoped_body(lines, 2, brace_family=True) == [], (
        "the empty handler on line 2 borrowed line 3's body"
    )


def test_close_of_previous_block_is_not_the_handler_brace() -> None:
    """`} catch (e) {` opens a multi-line body; its braces net to zero.

    Counting braces across the whole header line conflates the `}` that closes
    the preceding `try` with the handler's own `{`, which makes the single most
    common form in every brace language look inline-closed.
    """
    lines = (
        "function p(x) {",
        "  try {",
        "    resolve(x());",
        "  } catch (e) {",
        "    reject(e);",
        "  }",
        "}",
    )
    body = [b.strip() for b in collect_scoped_body(lines, 4, brace_family=True)]
    assert "reject(e);" in body, f"body of `}} catch (e) {{` not collected: {body}"
