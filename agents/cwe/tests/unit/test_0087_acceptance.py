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
    # Walk the file's history for the newest revision that does NOT contain
    # 0087. Pinning this to HEAD was wrong: once 0087 is committed HEAD holds
    # the post-fix skill, the comparison becomes trivial, and the test skips --
    # which turns a gate that caught a real 62-line regression into a no-op
    # exactly when it starts mattering most.
    try:
        revs = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "log", "--format=%H", "-n", "40",
             "--", SKILL_REL],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.split()
    except Exception:
        return None
    src = None
    for rev in revs:
        try:
            candidate = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "show", f"{rev}:{SKILL_REL}"],
                capture_output=True, text=True, timeout=30, check=True,
            ).stdout
        except Exception:
            continue
        if "_GO_SITE" not in candidate:
            src = candidate
            break
    if src is None:
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


# ---------------------------------------------------------------------------
# Per-fix pins.
#
# A completeness audit found that ~30 of this feature's behaviour fixes were
# real but unpinned: the suite asserted aggregates (a recall floor of 0.55, a
# +/-25% count band) that individual reverts slid under. That is not a
# theoretical worry -- it happened. A perf change made the raw line's pattern
# match the precondition for stripping, which silently killed the C# `when`
# filter and no-binding Allman shapes at their own ground-truth fixture sites,
# and every gate stayed green because 37/39 clears a 0.55 floor.
#
# Each test below therefore pins ONE behaviour at the smallest input that
# distinguishes fixed from broken.
# ---------------------------------------------------------------------------

from cwe_agent.skills.insufficient_logging_check import (  # noqa: E402
    _CATCH_LINE,
    _ERROR_DELEGATE,
    _KT_RUN_CATCHING,
    _LOG_CALL,
    _PHP_SET_HANDLER,
    _PY_EXCEPT_INLINE,
    _PY_SUPPRESS,
    _RUBY_MODIFIER,
    _SWIFT_CATCH,
    _SWIFT_TRY_OPT,
    _lang_extensions,
    _max_line_chars,
    check_insufficient_logging,
)


def _scan(tmp_path, name: str, text: str) -> set[int]:
    """Scan one file from a path the skill will actually look at."""
    root = tmp_path / "app"
    root.mkdir(exist_ok=True)
    (root / name).write_text(text)
    return {
        f["line_start"]
        for f in check_insufficient_logging(str(root)).get("findings", [])
    }


def test_pin_trailing_comment_does_not_hide_a_handler(tmp_path) -> None:
    """The regression that motivated this whole block.

    A comment after an Allman/`when` header must not make the site invisible.
    """
    hits = _scan(
        tmp_path,
        "A.cs",
        "class A {\n"
        "  long F() {\n"
        "    try { return 1; }\n"
        "    catch (SqlException ex) when (ex.Number == 1205) // deadlock victim\n"
        "    {\n"
        "      return 0L;\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert 4 in hits, (
        "a `when`-filter header carrying a trailing comment was not reported; "
        "the site match must retry on stripped code"
    )


def test_pin_allman_header_with_comment(tmp_path) -> None:
    hits = _scan(
        tmp_path,
        "B.cs",
        "class B {\n"
        "  long G() {\n"
        "    try { return 1; }\n"
        "    catch (IOException) // no binding, brace below\n"
        "    {\n"
        "      return 0L;\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert 4 in hits, "no-binding Allman header with a trailing comment missed"


def test_pin_comment_mentioning_a_handler_is_not_a_finding(tmp_path) -> None:
    """The opposite direction: prose must not become a finding."""
    hits = _scan(
        tmp_path,
        "C.java",
        "class C {\n"
        "  // Opened AND closed on the header line: `catch { }`, or a one-liner.\n"
        "  int h() { return 1; }\n"
        "}\n",
    )
    assert 2 not in hits, "a comment describing `catch { }` was reported as one"


def test_pin_char_guard_skips_counts_and_notes(tmp_path) -> None:
    """Step 1's per-line guard: skip, count, and surface -- all three."""
    root = tmp_path / "app"
    root.mkdir()
    (root / "D.java").write_text(
        "class D {\n"
        "  void f() { try { g(); } catch (Exception e) { } }\n"
        "  // " + "x" * 3000 + "\n"
        "}\n"
    )
    res = check_insufficient_logging(str(root))
    assert res.get("skipped_long_lines") == 1, (
        f"expected 1 skipped long line, got {res.get('skipped_long_lines')!r}"
    )
    assert res.get("notes"), "the skipped-line count was not surfaced as a note"
    assert "partial" in res["notes"][0].lower(), (
        "the note must say coverage of those lines is partial"
    )
    assert any(f["line_start"] == 2 for f in res["findings"]), (
        "the guard suppressed an ordinary line in the same file"
    )


def test_pin_char_guard_is_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _max_line_chars() == 2000
    monkeypatch.setenv("VULTURE_CWE778_MAX_LINE_CHARS", "500")
    assert _max_line_chars() == 500
    monkeypatch.setenv("VULTURE_CWE778_MAX_LINE_CHARS", "0")
    assert _max_line_chars() == 0, "0 must disable the guard"
    monkeypatch.setenv("VULTURE_CWE778_MAX_LINE_CHARS", "not-a-number")
    assert _max_line_chars() == 2000, "an unparseable value must fall back, not zero"


def test_pin_scala_arm_requires_a_catch(tmp_path) -> None:
    """A `case` arm outside a catch is ordinary pattern matching, not a handler."""
    hits = _scan(
        tmp_path,
        "E.scala",
        "object E {\n"
        "  def f(s: State): State = s match {\n"
        "    case Scan() => ScanRunning()\n"
        "    case Prove() => ProveRunning()\n"
        "  }\n"
        "}\n",
    )
    assert not ({3, 4} & hits), (
        f"ordinary `match` arms reported as swallowed handlers: {sorted(hits)}"
    )


def test_pin_scala_arm_inside_catch_is_reported(tmp_path) -> None:
    hits = _scan(
        tmp_path,
        "F.scala",
        "object F {\n"
        "  def f(): Unit = {\n"
        "    try { w() } catch {\n"
        "      case NonFatal(e) =>\n"
        "        ()\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert 4 in hits, "a silent `case NonFatal(e)` arm of a catch must be reported"


@pytest.mark.parametrize(
    ("ext", "present"),
    [(".cc", True), (".cxx", True), (".hpp", True), (".kts", True),
     (".c", False), (".h", False)],
)
def test_pin_scanner_and_gate_agree_on_extensions(ext: str, present: bool) -> None:
    """A gate that admits an extension the SCANNER withholds is inert.

    That asymmetry was the original step-9 defect: three of the nine extensions
    step 9 names passed the skill gate and were never handed to it.
    """
    from shared.tools.file_scanner import CODE_EXTENSIONS, WHITELIST_EXTENSIONS

    scannable = set(CODE_EXTENSIONS) | set(WHITELIST_EXTENSIONS)
    assert (ext in _lang_extensions()) is present, f"{ext} gate membership"
    if present:
        assert ext in scannable, (
            f"{ext} is in the CWE-778 gate but the scanner never yields such "
            f"files, so the gate entry is inert"
        )


@pytest.mark.parametrize(
    ("pattern", "text", "expected", "why"),
    [
        (_PY_SUPPRESS, "with contextlib.suppress(OSError):", True, "qualified"),
        (_PY_SUPPRESS, "with suppress(OSError):", True, "from-import"),
        (_PY_EXCEPT_INLINE, "except X: return None", True, "same-line return"),
        (_PY_EXCEPT_INLINE, "except X: continue", True, "same-line continue"),
        (_PY_EXCEPT_INLINE, "except X: pass  # deliberate", True, "trailing comment"),
        (_SWIFT_CATCH, "do { try f() } catch let e as E {", True, "swift bound"),
        (_SWIFT_TRY_OPT, "let v = try? f()", True, "try? discards"),
        (_SWIFT_TRY_OPT, "let v = try! f()", False, "try! aborts loudly"),
        (_KT_RUN_CATCHING, "runCatching { f() }.getOrNull()", True, "kotlin discard"),
        (_KT_RUN_CATCHING, "runCatching { f() }.getOrThrow()", False, "propagates"),
        (_RUBY_MODIFIER, "x = risky rescue nil", True, "ruby modifier"),
        (_PHP_SET_HANDLER, "set_error_handler(function () { });", True, "empty handler"),
        (_CATCH_LINE, "promise.catch(handler)", False, "JS method call, not a header"),
        (_LOG_CALL, 'LOG.warn("x", e)', True, "java constant logger"),
        (_LOG_CALL, "_logger.LogError(ex)", True, "MS.Extensions.Logging"),
        (_LOG_CALL, 'log::error!("x")', True, "rust path separator"),
        (_LOG_CALL, "System.err.println(e)", True, "jvm stderr is the report"),
        (_LOG_CALL, "e.printStackTrace()", True, "java canonical"),
        (_LOG_CALL, "NSLog(\"%@\", e)", True, "objc"),
        (_ERROR_DELEGATE, "self.report_error(&e)", True, "snake_case + borrow"),
        (_ERROR_DELEGATE, "report($e)", True, "laravel helper"),
        (_ERROR_DELEGATE, "doWork(e)", False, "not a delegate"),
    ],
)
def test_pin_individual_shape(pattern, text: str, expected: bool, why: str) -> None:
    """One assertion per shape, so a revert fails HERE and not on an aggregate."""
    assert bool(pattern.search(text)) is expected, f"{why}: {text!r}"


def test_pin_brace_in_string_does_not_truncate_the_body(tmp_path) -> None:
    """A `}` inside a string literal must not close the handler scope.

    Mutation-proved unpinned before this test existed: reverting the strip in
    `collect_scoped_body` left 1971 CWE + 2185 shared tests green, produced
    byte-identical findings on the whole fixture corpus, and changed nothing on
    six real trees -- while creating false positives on the shape below. The
    corpus could not see it because no fixture contained an UNBALANCED brace
    inside a string or comment; 0.27% of real brace-bearing source lines do.
    """
    fixture = (
        Path(__file__).parent.parent / "fixtures" / "cwe778" / "langs" / "braces.ts"
    )
    root = tmp_path / "app"
    root.mkdir()
    (root / "braces.ts").write_text(fixture.read_text())
    hits = {
        f["line_start"]
        for f in check_insufficient_logging(str(root)).get("findings", [])
    }
    assert 4 not in hits, (
        "the handler on line 4 logs on line 6, but a `}` inside the string on "
        "line 5 truncated the collected body before the log call was seen"
    )
    assert 13 not in hits, (
        "the handler on line 13 logs on line 14, but a `}` inside the trailing "
        "comment on line 13 truncated the scope"
    )
