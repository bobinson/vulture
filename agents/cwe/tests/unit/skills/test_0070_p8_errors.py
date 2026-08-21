"""Feature 0070 P8 — error-handling detection backlog (group `errors`).

One rule lands here.

  CWE-460  improper cleanup on thrown exception

           A handle is CREATED inside a ``try`` body and released later in
           that same body, but the handler clauses (``except`` / ``else`` /
           ``finally``) never release it. The success path cleans up; the
           failure path leaks. That is CWE-460's definition verbatim — "does
           not clean up its state ... when an exception is thrown".

           The predicate is purely structural: it carries no allowlist of
           acquire APIs and no allowlist of resource names. Whatever the
           object is, the code itself declares the cleanup obligation by
           closing it on the happy path; the finding is the *absence* of that
           same call on the exceptional path. A vocabulary-based rule
           ("flag ``open()`` without ``with``") would fire on every correct
           short-lived handle in the tree; this one cannot, because a file
           that never closes the handle at all states no obligation to leak.

           Clean twins therefore differ by exactly one property: the release
           moved into ``finally``, duplicated into the handler, or made
           unnecessary by a context manager.

           CWE-460 REPLACES any per-line row on the acquire line (see
           ``_analyze_lines``): CWE-754 otherwise claims ``f = open(p)`` when
           the handler sits more than three lines below, which would stack two
           rows on one line for one defect.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.error_handling_check import check_error_handling


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_error_handling(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f["category"] == f"CWE-{cwe}"]


# ------------------------------------------------------------------ CWE-460


def test_handle_closed_only_on_success_path_is_flagged() -> None:
    code = """\
def probe(target):
    try:
        channel = connect(target)
        reply = channel.check()
        channel.close()
        return reply
    except OSError as exc:
        report(exc)
        return None
"""
    rows = _of(_run({"mod.py": code}), "460")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 3


def test_release_in_finally_is_clean() -> None:
    code = """\
def probe(target):
    try:
        channel = connect(target)
        reply = channel.check()
        return reply
    except OSError as exc:
        report(exc)
        return None
    finally:
        channel.close()
"""
    assert _of(_run({"mod.py": code}), "460") == []


def test_release_repeated_in_handler_is_clean() -> None:
    code = """\
def probe(target):
    try:
        channel = connect(target)
        reply = channel.check()
        channel.close()
        return reply
    except OSError as exc:
        channel.close()
        report(exc)
        return None
"""
    assert _of(_run({"mod.py": code}), "460") == []


def test_context_manager_is_clean() -> None:
    code = """\
def probe(target):
    try:
        with connect(target) as channel:
            return channel.check()
    except OSError as exc:
        report(exc)
        return None
"""
    assert _of(_run({"mod.py": code}), "460") == []


def test_handle_never_released_states_no_obligation() -> None:
    """No cleanup call anywhere means no declared obligation to leak."""
    code = """\
def probe(target):
    try:
        channel = connect(target)
        return channel.check()
    except OSError as exc:
        report(exc)
        return None
"""
    assert _of(_run({"mod.py": code}), "460") == []


def test_acquire_outside_any_try_is_clean() -> None:
    code = """\
def probe(target):
    channel = connect(target)
    reply = channel.check()
    channel.close()
    return reply
"""
    assert _of(_run({"mod.py": code}), "460") == []


def test_arm_is_python_only() -> None:
    """The brace dialects are NOT covered: the shape measured zero rows in
    JS/TS/Java/C# on both measurement trees, so no arm ships for them."""
    code = """\
function probe(target) {
  try {
    const channel = connect(target)
    const reply = channel.check()
    channel.close()
    return reply
  } catch (err) {
    report(err)
    return null
  }
}
"""
    assert _of(_run({"mod.js": code}), "460") == []


def test_one_row_per_leaked_handle() -> None:
    """CWE-460 replaces the CWE-754 row on the acquire line.

    ``f = open(path)`` sits four lines above the handler, so CWE-754's
    +/-3-line context window sees no try/except and would otherwise claim the
    same line for the same defect.
    """
    code = """\
def load(path):
    try:
        f = open(path)
        first = f.readline()
        second = f.readline()
        third = f.readline()
        f.close()
        return first, second, third
    except OSError as exc:
        report(exc)
        return None
"""
    rows = [f for f in _run({"mod.py": code}) if f["line_start"] == 3]
    assert len(rows) == 1
    assert rows[0]["category"] == "CWE-460"


def test_one_row_per_try_block_when_two_handles_leak() -> None:
    code = """\
def probe(target):
    try:
        channel = connect(target)
        stream = channel.open_stream()
        stream.close()
        channel.close()
        return True
    except OSError:
        report(target)
        return False
"""
    assert len(_of(_run({"mod.py": code}), "460")) == 1


def test_nested_try_reports_the_handle_once() -> None:
    code = """\
def probe(target):
    try:
        setup(target)
        try:
            channel = connect(target)
            reply = channel.check()
            channel.close()
            return reply
        except TimeoutError:
            return None
    except OSError:
        return None
"""
    assert len(_of(_run({"mod.py": code}), "460")) == 1


def test_try_without_any_handler_clause_is_ignored() -> None:
    """A ``try`` with no except/else/finally cannot be parsed as a handler."""
    code = """\
def probe(target):
    channel = connect(target)
    channel.close()
    return True
"""
    assert _of(_run({"mod.py": code}), "460") == []
