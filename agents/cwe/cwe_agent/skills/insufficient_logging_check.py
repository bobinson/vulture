"""Dedicated skill for CWE-778 (insufficient logging).

Flags two patterns:

  1. Exception handlers (``catch`` / ``except`` blocks) whose body does
     not emit a logging call. Swallowed exceptions hide evidence
     needed for incident response.
  2. Authentication/authorization decision points (login_failed,
     access_denied, permission denied, token invalid, MFA failure)
     that don't log the event. CWE-778 specifically calls out auth
     decisions as critical events that must be logged for forensics
     and intrusion detection.
"""
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from agents import function_tool
from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.line_context import strip_strings_and_comments
from shared.tools.snippet import (
    collect_handler_body,
    collect_scoped_body,
    extract_snippet,
)

from cwe_agent.catalog import enrich_finding

# Language gate — logging conventions differ and the regex targets these.
# 0087 B7/step 9. Six of the languages the LLD called "structurally blind" were
# excluded HERE, before any pattern ran — .cpp and .kt already match the existing
# catch shape, so widening this frozenset adds them with no new patterns. The
# .tsx/.jsx/.cjs/.mjs omission mattered most: 212 catch sites in togetherapp were
# never scanned, and togetherapp is the repo every ground-truth true positive came
# from, so the TP search space itself was incomplete.
#
# `.c`/`.h` are deliberately ABSENT: the errno arm was dropped as non-viable
# line-locally (plan D-drop-1) — `if (rc < 0)` is indistinguishable from ordinary
# control flow without type information.
_BASE_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".java", ".js", ".ts", ".go", ".cs", ".rb", ".php",
})
_WIDENED_LANG_EXTENSIONS: frozenset[str] = _BASE_LANG_EXTENSIONS | frozenset({
    ".tsx", ".jsx", ".cjs", ".mjs",           # JS/TS families never gated in
    ".cpp", ".cc", ".cxx", ".hpp",            # already match _CATCH_LINE
    ".kt", ".kts", ".swift", ".scala", ".rs",  # own shapes / brace family
    # `.rake` is Ruby; `.hh`/`.hxx` are C++ headers. Both were added to the
    # SCANNER by this feature, so they must have a consuming arm here too --
    # an extension the scanner yields and no arm accepts is the same inert
    # asymmetry step 9 existed to remove, only mirrored.
    ".rake", ".hh", ".hxx",
})


def _lang_extensions() -> frozenset[str]:
    """``VULTURE_CWE778_EXTENSIONS`` — default widened (0087 step 9).

    ``legacy`` restores the pre-0087 eight-extension gate.
    """
    if os.environ.get("VULTURE_CWE778_EXTENSIONS", "").strip().lower() == "legacy":
        return _BASE_LANG_EXTENSIONS
    return _WIDENED_LANG_EXTENSIONS

# Python except header (we need next lines of body).
# 0087 B4: the old `\s*$` anchor rejected any except header carrying a trailing
# comment — 18 of vulture's 316, and systematically the interesting ones, since
# a comment on an `except` line is usually the author justifying the swallow.
_PY_EXCEPT = re.compile(r"^\s*except\b[^:]{0,200}:\s{0,8}(?:#.*)?$")

# Same-line Python except with a trivial body (pass / None / etc.).
# 0087 step 6. Three Python shapes the shipped detector could not see:
#
#  1. Same-line body beyond the three trivial literals. `except X: return None`
#     and `except X: continue` are swallows exactly as much as `except X: pass`,
#     and the shipped alternation admitted only pass/None/... .
#  2. Trailing comment on the header (`except ValueError:  # nope`), handled by
#     stripping the site line before matching.
#  3. `with contextlib.suppress(...)`, which is a handler with no body at all --
#     the statement IS the suppression.
#
# `except ImportError:` guarding an optional dependency is deliberately NOT a
# finding: an absent optional import is a supported configuration, not a failure
# that wants recording.
_PY_EXCEPT_INLINE = re.compile(
    r"^\s{0,80}except\b[^:]{0,200}:\s{0,8}"
    r"(?:pass|None|\.\.\.|return(?:\s{1,4}(?:None|False|True|\[\]|\{\}|\(\)|0|\"\"|''))?"
    r"|continue|break)\s{0,8}(?:\#.{0,200})?$"
)
# An optional-dependency guard. Excused before the inline shape is consulted.
_PY_OPTIONAL_IMPORT = re.compile(r"^\s{0,80}except\b[^:]{0,120}\bImportError\b")
_PY_SUPPRESS = re.compile(
    r"\bwith\s{1,4}(?:contextlib\s*\.\s*)?suppress\s*\(([^)]{0,200})\)\s*:"
)

# Java/JS/C#/Go/PHP catch clause — may be single-line or open a block.
# 0087 B5: the ES2019 optional-binding form `} catch {` was unmatchable —
# 56 such sites in togetherapp .ts/.tsx alone. Quantifiers bounded per B2.
# 0087 step 7. Three forms the single `catch ... {` pattern could not express:
#
#   catch (X ex) when (ex.Number == 1205)   C# exception filter
#   catch (IOException e)                   Allman: the `{` is on the NEXT line
#   catch (IOException)                     C#/PHP 8 no-binding form
#
# The Allman alternative requires the line to END after the clause, and forbids a
# preceding `.`, so `promise.catch(handler)` -- which also has `catch (...)` and
# no brace -- cannot match it.
_CATCH_LINE = re.compile(
    r"\bcatch\s{0,8}(?:\([^)]{0,200}\)\s{0,8})?(?:when\s{0,4}\([^)]{0,200}\)\s{0,8})?\{"
    # Anchored at BOTH ends. The Allman form always occupies its own line, and
    # `$` without a start anchor makes the engine retry at every position of the
    # line -- which is what put this pattern over the adversarial-input budget.
    r"|^\s{0,80}catch\s{0,8}\([^)]{0,200}\)"
    r"(?:\s{0,8}when\s{0,4}\([^)]{0,200}\))?\s{0,8}$"
)

# Single-line catch with empty/near-empty body: `catch (...) {}` or `catch (...) { ; }`.
# 0087 B2: every quantifier bounded. The prior `\s*[;]?\s*` is quadratic —
# measured 12.98 ms on one line with 4000 trailing spaces, and Vulture scans
# arbitrary git URLs with a 512 KB per-file cap, so this is remote
# content-driven cost.
# 0087 B2: every quantifier bounded. The shipped `\s*`/`[^)]*` form is quadratic
# in the trailing-space count -- `catch(e){` followed by 512 KB of spaces did not
# finish inside the adversarial-input gate's 12 s ceiling. Bounding changes no
# match: no real handler has more than 8 spaces between these tokens, nor a
# 200-character exception clause.
_CATCH_EMPTY = re.compile(r"\bcatch\s{0,8}\([^)]{0,200}\)\s{0,8}\{\s{0,8};?\s{0,8}\}")

# Logging-call regex — anchors the handler-body test.
# 0087 B6/D3: built by UNION with the shipped alternation, never replacement —
# the LLD's per-language sets omitted `logger.`/`log.`, which would have turned
# correct suppressions into false positives across the two largest populations.
_LOG_CALL = re.compile(
    r"\bslog\."          # Go structured logging
    r"|\bspdlog\b|\bglog\b|\bos_log\b|\bsyslog\b|\bNSLog\s*\("  # C++/ObjC/POSIX
    # JVM: stderr IS the report in a catch block, exactly as it is for a Go CLI.
    r"|\bSystem\s*\.\s*(?:err|out)\s*\.\s*print(?:ln|f)?\s*\("
    r"|\bprintStackTrace\s*\("
    r"|\b(?:tracing|log|slog)::"   # Rust: PATH separator, not a dot
    r"|\berror_log\s*\(|\bLog::"                      # PHP / Laravel
    r"|\bzap\.|\blogrus\.|\bzerolog\."               # Go libs
    # A logger held in a CONSTANT or a private field. `LOG.warn(..)` and
    # `_logger.Error(..)` are the conventional Java and C# spellings, and their
    # absence was reported as three separate false positives on the fixtures.
    # The optional `Log` prefix is Microsoft.Extensions.Logging's spelling
    # (`_logger.LogError`, `_logger.LogWarning`), which is how virtually all
    # modern C# logs and which the bare level names do not match.
    r"|\b(?:LOG|LOGGER|_?[Ll]og(?:ger)?)\s*\.\s*(?:Log)?"
    r"(?:warn(?:ing)?|error|info(?:rmation)?|debug|trace|fatal|critical"
    r"|Warn(?:ing)?|Error|Info(?:rmation)?|Debug|Trace|Fatal|Critical)\b"
    r"|\blog\."
    r"|\blogger\."
    r"|\blogging\."
    r"|\bslf4j\b"
    r"|\bconsole\.(?:error|warn|info|log)\s*\("
    r"|\bsyslog\b"
    r"|\bLOG_[A-Z]"
    r"|\bfmt\.Fprintf\s*\(\s*os\.Stderr"
    r"|\bzap\.\w+\s*\("
    r"|\bzerolog\.\w+\s*\("
    r"|\baudit_log\b"
    r"|\bsecurity_log\b"
)


# Authentication/authorization decision points that should be audit-
# logged. Lines matching these are scanned for nearby logging calls;
# absence emits a CWE-778 finding.
_AUTH_DECISION = re.compile(
    r"(?:"
    r"\b(?:login|authentication|auth)[_\-]?(?:failed|fail|denied|invalid|reject)\b"
    r"|\b(?:permission|access)[_\-]?denied\b"
    r"|\bmfa[_\-]?(?:failed|fail|invalid)\b"
    r"|\btoken[_\-]?(?:invalid|expired|reject)\b"
    r"|\bunauthorized\b"
    r"|\bforbidden\b"
    r"|\binvalid[_\-]?credentials\b"
    r")",
    re.IGNORECASE,
)


def _has_log_within(lines: tuple[str, ...], lineno: int, radius: int = 4) -> bool:
    """True when a log call appears within ``radius`` lines of ``lineno``."""
    start = max(0, lineno - radius - 1)
    end = min(len(lines), lineno + radius)
    for i in range(start, end):
        if _LOG_CALL.search(lines[i]):
            return True
    return False


def _body_has_logging(body_lines: list[str]) -> bool:
    """Return True if any line in the handler body invokes a logging call."""
    for line in body_lines:
        if _LOG_CALL.search(line):
            return True
    return False


# An error identifier a propagation call would be handed. Anchored with
# ``\b`` at both ends so ``entry`` / ``errCount`` are not error names.
# Case-sensitive by design (see the ``Exception``/``Error`` spellings
# listed explicitly rather than using re.IGNORECASE).
# `&`/`*`/`$` prefixes admit Rust's borrow (`&e`), C/C++'s dereference and PHP's
# sigil. Without them a delegate call written the way the language requires
# looked like a call with no error argument at all.
_ERR_ARG = (
    r"[&*$]{0,2}"
    r"(?:e|ex|exc|err|error|exception|reason"
    r"|E|Ex|Exc|Err|Error|Exception|Reason)\b"
)

# Handler bodies that FORWARD the error instead of swallowing it. Not a
# logging defect: the caller still receives the evidence, so CWE-778
# does not apply. ``raise``/``throw`` are anchored to a statement start
# (line start, ``{``, ``;`` or ``:``). That anchor alone is NOT enough --
# ``:`` matches inside prose like "note: throw is avoided here" -- so
# _body_propagates strips comments and strings before matching.
# All quantifiers bounded; no nested repetition (ReDoS-safe).
# The handler hands the error to a dedicated error-handling routine, and that
# routine is where the logging lives. Measured on one real target: 95 of 168
# CWE-778 rows were `catch (error) { handleApiError(error, res); }`, and
# handleApiError logs `console.log("AppError", payload)` ONE HOP away. Matching
# only DIRECT log calls let a single hop of indirection defeat the whole rule.
#
# BOTH halves are required -- an error-handling NAME SHAPE and an error-shaped
# ARGUMENT -- so `cleanup(e)` and `swallow(e)` are still reported. Accepted
# limit: a routine NAMED like a handler that discards the error is excused
# here; resolving that needs cross-file analysis, and the defect would belong
# to that routine rather than to its caller.
_ERROR_DELEGATE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]{0,40}\.)?"
    r"(?:"
    # `_?` and the `_(?:error|err|...)` branch admit snake_case: Rust, Ruby, Python
    # and Go all spell this `report_error(&e)`, which the CamelCase-only form missed.
    r"(?:handle|report|capture|record|notify|forward|log|trace|emit)"
    r"(?:[A-Za-z0-9_]{0,32}(?:Error|Err|Exception|Failure)"
    r"|[a-z0-9_]{0,32}_(?:error|err|exception|failure)s?)"
    r"|[A-Za-z0-9_]{0,32}(?:Error|Exception)Handler"
    r"|onError"
    # Framework helpers that take the exception and are THE reporting path:
    # Laravel's global `report($e)`, Sentry/Bugsnag/Airbrake capture entrypoints.
    r"|report|notify|capture"
    # Substrate/ink! runtime event emission is that environment's reporting path.
    r"|deposit_event|emit[A-Za-z_]{0,20}"
    r")"
    r"\s*\(\s*" + _ERR_ARG
)


def _body_delegates(body_lines: list[str]) -> bool:
    """True if the body hands the error to a named error-handling routine."""
    return any(
        _ERROR_DELEGATE.search(strip_strings_and_comments(line))
        for line in body_lines
    )


# Quantifiers are held to the {0,8} convention used elsewhere in this module:
# the `\s{0,80}` this replaced cost 40 ms on a 512 KB single-line input, four
# times the budget the adversarial-input gate allows. `next` and `callback`
# share one branch rather than two, for the same reason.
# Every branch begins with a LITERAL so the engine can build a first-character
# set and skip non-matching positions. The previous form led with `(?:^|[{};:])`
# — an assertion, which defeats that optimisation and cost 23 ms on a 512 KB
# single-line input against a 10 ms budget. The statement-start requirement for
# `raise`/`throw` moves to a second pattern, evaluated only when the fast one
# already matched, so the expensive check runs on a handful of lines rather than
# at every position of every line.
# Split in two, because they are decided differently: `raise`/`throw` additionally
# require statement position, the rest do not. Keeping them in one alternation
# meant only the LEFTMOST match was consulted, so a line carrying a non-statement
# `throw` ahead of a genuine `next(err)` was scored as not propagating -- the
# forms are independent and must each get their own chance to match.
_PROPAGATES = re.compile(
    r"\b(?:next|callback)\s{0,4}\(\s{0,4}(?:new\s{1,4}[A-Za-z_][A-Za-z0-9_.]{0,63}|"
    + _ERR_ARG + r")"
    r"|\breject\s{0,4}\("
    # Rust, unioned in rather than given its own pattern (D3: per-language sets
    # are built by UNION with the shipped alternations). `return Err(..)` is the
    # propagating form; the panic family aborts loudly, which is CWE-248 not 778;
    # `bail!`/`ensure!`/`anyhow!` all expand to an early Err return. Bare
    # `Err(..)` is deliberately absent -- it is the SITE token of two of the
    # three Rust shapes, and admitting it would excuse every site by its own
    # header, the self-excusal `_GO_CAPTURED` already hit once.
    r"|\breturn\s{1,4}Err\b"
    r"|\b(?:panic|unreachable|todo|unimplemented|bail|ensure|anyhow|eyre)\s{0,4}!"
    r"|\breturn\s{1,4}(?:[A-Za-z_][A-Za-z0-9_.]{0,40}\s{0,4},\s{0,4})?" + _ERR_ARG
)
_RAISE_THROW = re.compile(r"\b(?:raise|throw)\b")


def _opens_statement(text: str, at: int) -> bool:
    r"""True if only whitespace, or a statement terminator, precedes ``at``.

    `raise`/`throw` must OPEN a statement: `obj.throw()` is a generator method,
    not propagation. This is deliberately not a regex. The regex form
    `(?:^|[{};:])\s{0,N}(?:raise|throw)\b` has to pick an N, and N is the
    maximum indent it can see: at N=8 every `throw` nested three levels deep
    stopped counting as propagation and became a false positive, which is a
    regression against every previously-excused handler in the corpus (62
    distinct lines across the three reference repos). Raising N instead
    reintroduces the per-position cost that the adversarial-input gate rejects.
    A prefix test has neither problem -- it is exact at any indent, runs once per
    candidate line rather than at every position, and keeps one more pattern off
    the ReDoS surface entirely.
    """
    prefix = text[:at].rstrip()
    return not prefix or prefix[-1] in "{};:"


def _body_propagates(body_lines: list[str]) -> bool:
    """Return True if the handler body re-raises or forwards the error.

    Propagation (``raise``, ``throw e``, ``next(err)``, ``reject(...)``,
    ``return err``, ``callback(err)``) preserves the error for the
    caller, so the handler is not "insufficient logging". An EMPTY body
    propagates nothing and is deliberately not covered here — empty
    handlers are reported by their own early-return paths.
    """
    for line in body_lines:
        # Strip comments and string literals FIRST. The statement-start anchor
        # below includes ``:``, so prose such as ``// note: throw is avoided
        # here`` would otherwise match and SUPPRESS a real finding. Stripping
        # fails safe in this direction: if it misses a comment the finding is
        # still reported, never silently dropped (see line_context's docstring
        # on not using it as a hard skip -- suppression here is the only use
        # that could lose a row, and a missed strip cannot cause that).
        cleaned = strip_strings_and_comments(line)
        if _PROPAGATES.search(cleaned):
            return True
        if any(
            _opens_statement(cleaned, m.start())
            for m in _RAISE_THROW.finditer(cleaned)
        ):
            return True
    return False


def _scoped_body_enabled() -> bool:
    """``VULTURE_CWE778_SCOPED_BODY`` — default TRUE, read at call time (0087 step 4).

    ``false`` restores ``collect_handler_body``, whose fixed 5-line/10-line window
    ignores scope and lets a log call in the next function excuse this handler.
    """
    return os.environ.get("VULTURE_CWE778_SCOPED_BODY", "true").strip().lower() != "false"


def _body_for(lines, lineno: int, brace_family: bool) -> list[str]:
    """Collect a handler body, scope-aware when 0087 step 4 is enabled."""
    if _scoped_body_enabled():
        return collect_scoped_body(lines, lineno, brace_family)
    return collect_handler_body(lines, lineno)


def _handler_is_excused(body: list[str], inline: str = "") -> bool:
    """True when a NON-EMPTY handler body neither swallows nor hides the
    error: it logs it, or it forwards it to the caller.

    Args:
        body: Body lines collected after the handler header.
        inline: Text following the opening brace on the header line
            itself (single-line ``catch (err) { next(err) }``), which
            ``collect_handler_body`` never returns.
    """
    lines = [inline, *body]
    return (
        # 0087 B1: `lines`, not `body`. Every sibling test below already gets the
        # header-line remainder; this one did not, so a one-line handler whose log
        # call sits on the header (`} catch (e) { console.error(e); }`) was invisible
        # and reported as a swallow. One-line handlers are the norm in C++, Kotlin,
        # Swift and Scala, so this becomes the dominant false positive the moment the
        # extension gate widens.
        _body_has_logging(lines)
        or _body_propagates(lines)
        or _body_delegates(lines)
    )


def _build_finding(
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single CWE-778 finding dict."""
    finding = {
        "severity": "medium",
        "check_id": "cwe.insufficient_logging.cwe_778",
        "category": "CWE-778",
        "title": "Insufficient Logging",
        "description": (
            f"Exception handler at line {lineno} does not log the error. "
            f"Swallowed exceptions break incident-response workflows."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Emit a logging call (e.g., ``logger.error(e)`` / ``logging.exception``) "
            "within the handler body so diagnostic evidence is preserved."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, "778")


# A comment opener in any of the languages this skill scans. Used to decide
# whether a line that failed the raw site match is worth stripping and retrying.
_COMMENT_TOKEN = re.compile(r"//|/\*|#|--")


def _scan_py_except(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a Python ``except`` header for an unlogged handler body."""
    # Both patterns below require the literal keyword, so this substring test is
    # a strict necessary condition and cannot change what is reported. It keeps
    # two regex searches off every line of every non-Python file in the tree.
    if "except" not in line and "suppress" not in line:
        return
    if not (
        _PY_EXCEPT_INLINE.search(line)
        or _PY_EXCEPT.search(line)
        or _PY_SUPPRESS.search(line)
    ) and not _COMMENT_TOKEN.search(line):
        return
    code = strip_strings_and_comments(line)
    if "suppress" in code and _PY_SUPPRESS.search(code):
        # `with suppress(X):` -- the statement itself discards the exception,
        # so there is no body to inspect and nothing can excuse it.
        findings.append(_build_finding(file_path, lineno, lines))
        return
    line = code
    if "except" not in line:
        return
    if _PY_OPTIONAL_IMPORT.search(line):
        return
    if _PY_EXCEPT_INLINE.search(line):
        findings.append(_build_finding(file_path, lineno, lines))
        return
    if not _PY_EXCEPT.search(line):
        return
    body = _body_for(lines, lineno, brace_family=False)  # lineno is 1-based → start at index lineno
    if _handler_is_excused(body):
        return
    findings.append(_build_finding(file_path, lineno, lines))


def _scan_catch(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a Java/JS-style ``catch`` clause for an unlogged handler body."""
    # Same necessary-condition gate as _scan_py_except: every pattern this
    # function consults requires the literal `catch`.
    if "catch" not in line:
        return
    # Match the CODE, not a comment or a string: a line of PROSE that mentions
    # `catch { }` -- including this module's own comments -- was a finding.
    # The RAW line is pattern-matched first and stripping happens only if that
    # matched, so the strip cost is paid by actual candidate sites rather than
    # by every line containing the word `catch`. On the TS-heavy reference repo
    # stripping unconditionally cost 3% of the warm budget, because `.catch(`
    # appears on thousands of lines that are not handler headers.
    # Try the RAW line first, then -- only if that failed and the line actually
    # carries a comment token -- strip and retry. Using the raw match alone as
    # the precondition for stripping was a real defect: `_CATCH_LINE`'s Allman
    # alternative is anchored `^...$`, so a trailing comment defeats it, the
    # strip never ran, and the C# `when`-filter and no-binding-Allman shapes
    # reported ZERO rows -- including at the fixture sites written to demonstrate
    # them. Gating the strip on a comment token keeps the cost off the thousands
    # of `.catch(` lines that have no comment, which is what the optimisation was
    # for, without making a comment hide the site.
    if not (_CATCH_EMPTY.search(line) or _CATCH_LINE.search(line)):
        if not _COMMENT_TOKEN.search(line):
            return
        line = strip_strings_and_comments(line)
        if "catch" not in line or not (
            _CATCH_EMPTY.search(line) or _CATCH_LINE.search(line)
        ):
            return
    else:
        line = strip_strings_and_comments(line)
        if "catch" not in line:
            return
    if _CATCH_EMPTY.search(line):
        findings.append(_build_finding(file_path, lineno, lines))
        return
    match = _CATCH_LINE.search(line)
    if not match:
        return
    body = _body_for(lines, lineno, brace_family=True)
    # A single-line `catch (err) { next(err) }` keeps its whole body on
    # the header line, which collect_handler_body never returns — so the
    # text after the opening brace is part of the body for propagation.
    if _handler_is_excused(body, inline=line[match.end():]):
        return
    findings.append(_build_finding(file_path, lineno, lines))


def _should_scan(file_path: Path) -> bool:
    """Return True if file passes language-gate and non-generated/test filters."""
    if file_path.suffix.lower() not in _lang_extensions():
        return False
    return not (is_generated_file(file_path) or is_test_file(file_path))


# 0087 step 1 — per-line character guard, the second half of the step.
#
# Defence in depth for section 5: the adversarial-input gate keeps each pattern
# fast, but that is per-pattern discipline and the margin is thin (the worst
# pattern measures ~5.8 ms against a 10 ms budget). This guard means a single
# crafted line cannot cost pattern-count x per-pattern time regardless of how
# the patterns later change. It matters because Vulture scans arbitrary git
# URLs, so line content is remote input.
#
# It is NOT `is_minified_content`: that one is whole-file, only applies to
# JS/TS/CSS suffixes, requires long lines to be >= 50% of the file, and is
# controlled by VULTURE_SCAN_MINIFIED. Measured on eight 512 KB single-line
# files, it dropped only the `.ts` one -- `.java .cs .go .php .py .rb .rs` all
# reached the line loop unguarded.
#
# Skipped lines are COUNTED and surfaced, never silently dropped: a scan that
# quietly ignored part of a file would report partial coverage as complete.
_MAX_LINE_CHARS_DEFAULT = 2000


def _max_line_chars() -> int:
    """``VULTURE_CWE778_MAX_LINE_CHARS`` — 0 disables the guard (0087 step 1)."""
    raw = os.environ.get("VULTURE_CWE778_MAX_LINE_CHARS", "").strip()
    if not raw:
        return _MAX_LINE_CHARS_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return _MAX_LINE_CHARS_DEFAULT
    return value if value >= 0 else _MAX_LINE_CHARS_DEFAULT


def _scan_file(
    file_path: Path,
    findings: list[dict],
    stats: dict[str, dict[str, int]] | None = None,
    skipped: dict[str, int] | None = None,
) -> None:
    """Read file lines and scan each one for un-logged exception handlers
    or un-logged auth decisions."""
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    suffix = file_path.suffix.lower()
    scoped = _security_scope_enabled()
    # Resolved ONCE per file, not once per line. Reading os.environ and building
    # a Path inside the line loop cost 2-7x the section 5 budget on the reference
    # repos: those are per-line costs paid on every line of every file, including
    # the overwhelming majority whose language the arm cannot match.
    auth_strip = _auth_strip_enabled()
    do_go = suffix == ".go" and _go_arm_enabled()
    do_js = suffix in _JS_EXTENSIONS and _js_arm_enabled()
    do_extra = (
        _extra_langs_enabled()
        and any(suffix in exts for exts, *_ in _EXTRA_SHAPES)
    )
    seen_lines: set[int] = set()
    max_chars = _max_line_chars()
    for lineno, line in enumerate(lines, 1):
        if max_chars and len(line) > max_chars:
            if skipped is not None:
                skipped["lines"] = skipped.get("lines", 0) + 1
            continue
        before = len(findings)
        _scan_py_except(line, lineno, path_str, lines, findings)
        _scan_catch(line, lineno, path_str, lines, findings)
        _scan_auth_decision(
            line, lineno, path_str, lines, findings, seen_lines, auth_strip
        )
        if do_go:
            _scan_go_error_check(line, lineno, path_str, lines, findings)
        if do_js:
            _scan_promise_rejection(line, lineno, path_str, lines, findings, seen_lines)
        if do_extra:
            _scan_extra_language_shapes(
                line, lineno, path_str, lines, findings, seen_lines, suffix
            )
        if scoped and len(findings) > before and not _in_security_scope(lines, lineno):
            del findings[before:]
        if stats is not None:
            _record_site(stats, line, suffix, lines, lineno, len(findings) > before)


def _auth_strip_enabled() -> bool:
    """``VULTURE_CWE778_AUTH_STRIP`` — default TRUE, read at call time (0087 step 2).

    ``false`` restores the pre-0087 behaviour of matching auth keywords against the
    raw line, comments and string literals included.
    """
    return os.environ.get("VULTURE_CWE778_AUTH_STRIP", "true").strip().lower() != "false"


# ---------------------------------------------------------------------------
# 0087 step 11 — the Go (value-error) arm.
#
# Go has no exceptions. The LLD treated all 1,118 `if err != nil` sites as places
# that must log; the census in plan §1 shows why that would have been a disaster:
# of 788 non-test sites in vulture/backend, 554 PROPAGATE (`return err`,
# `fmt.Errorf(..%w..)`) and 72 log. Propagating is the language's correct idiom —
# the caller logs. Only three body classes are defects, ~102 sites total:
#
#   1. `return` with no error value   (the error is dropped on the floor)
#   2. `continue` / `break`           (swallowed inside a loop)
#   3. non-terminating body           (execution falls through as if nothing failed)
#
# `panic`/`os.Exit` are NOT reported here — that is CWE-248.
_GO_SITE = re.compile(
    r"^\s{0,80}if\s{1,4}(?:[\w,\s]{0,60}:?=\s{0,4}[^;]{0,200};\s{0,4})?"
    r"\w{0,40}err\w{0,20}\s{0,4}!=\s{0,4}nil\b[^\n]{0,120}\{"
)
# A logger-shaped RECEIVER is required. A bare `\.Error\(` collides with
# `fmt.Errorf(` and with `err.Error()`, which is a formatter, not a log call.
# `[^\n]{0,80}?` allows the builder hop that logrus and zerolog both use:
# `logrus.WithError(err).Warn(..)`, `zerolog.Ctx(ctx).Error().Err(err).Msg(..)`.
# Both are canonical for their library and were being reported as swallows.
_GO_LOG = re.compile(
    r"\b(?:log|slog|logger|zap|logrus|zerolog|klog|glog)\s*\.[^\n]{0,80}?\b"
    r"(?:Print|Printf|Println|Error|Errorf|Warn|Warnf|Warning|Info|Infof|Debug|Debugf|Fatal|Fatalf|Panic|Msg|Msgf)\b"
)
# Propagation, including the wrap form `_PROPAGATES` misses (plan B6): without
# this, 554 correctly-written sites score as swallows.
_GO_PROPAGATES = re.compile(
    r"\breturn\b[^\n]{0,200}\b(?:err\b|fmt\.Errorf|errors\.(?:New|Wrap|Wrapf|Join))"
    r"|\bpanic\s*\(|\bos\.Exit\s*\(|\bt\.(?:Fatal|Fatalf|Error|Errorf)\b"
)
# Four excusals found by adjudicating a 30-row sample (0087 step 11). Each was a
# real reporting mechanism the first cut could not see; together they were 9 of
# the 30 rows, i.e. the entire gap between 70% and the shipped precision.
#
# 1. stderr IS the logger for a CLI. `fmt.Fprintf(os.Stderr, "...: %v", err)` is
#    how every Go command-line tool reports; requiring `log.` there would demand
#    that CLIs log to a file nobody reads.
# 2. A fatal helper (`fatalf`, `die`, `log.Fatal`) prints and exits.
# 3. A SENTINEL error return propagates. `\berr\b` cannot see `errInvalidRequest`
#    or `ErrNotFound`, which is Go's naming convention for exactly this.
# 4. An error captured into a variable (`lastErr = err.Error()`) is retained for
#    a later report — the retry loop that does this reports after the last attempt.
_GO_STDERR = re.compile(
    r"\bfmt\.(?:Fprint|Fprintf|Fprintln)\s*\(\s*(?:os\.)?(?:Stderr|stderr|Stdout|stdout|w?[eE]rr[Ww]riter)\b"
)
_GO_FATAL = re.compile(r"\b(?:[Ff]atal\w*|die|Die|[Ee]xitf?)\s*\(")
_GO_SENTINEL_RETURN = re.compile(r"\breturn\b[^\n]{0,200}\b(?:err|Err)[A-Z_]\w{0,60}")
# Both sides must be loose. `lastErr = derr` names the source `derr`, and
# `failed = append(failed, err.Error())` names the destination `failed` — the
# first cut demanded the literal token `err` at both ends and matched neither.
# The destination must look like an ERROR ACCUMULATOR, not merely any field that
# happens to be assigned an error. `s.lastFailure = fmt.Errorf(..).Error()` and
# `h.status.Detail = err.Error()` are stored state, not a deferred report, and
# excusing them hid real swallows.
_GO_CAPTURED = re.compile(
    r"\b(?:last|first|final|saved|stored|pending|collected|all|agg\w{0,8})?"
    r"(?:err|Err)\w{0,12}\s{0,4}(?::?=)\s{0,4}[^\n]{0,120}\b\w{0,20}(?:err|Err)\w{0,20}\b"
    r"|\bappend\s*\([^\n]{0,120}\b\w{0,20}(?:err|Err)\w{0,20}\b"
)
_GO_EXCUSED = re.compile(
    "|".join(x.pattern for x in (_GO_STDERR, _GO_FATAL, _GO_SENTINEL_RETURN, _GO_CAPTURED))
)
# Surfacing the error to an HTTP client is NOT an excusal — the operator still has
# no record, which is the canonical A09 / CWE-778 case — but it changes what the
# finding should SAY, so the reviewer is not told "no trace" about a 500 they can see.
_GO_CLIENT_RESPONSE = re.compile(
    r"\b(?:writeError|writeJSONError|http\.Error|respondError|c\.(?:JSON|AbortWith\w*)|w\.WriteHeader)\s*\("
)
_GO_SWALLOW_RETURN = re.compile(r"^\s{0,80}return\s{0,4}$|^\s{0,80}return\s+nil\s{0,4}$")
_GO_SWALLOW_LOOP = re.compile(r"^\s{0,80}(?:continue|break)\b")


def _go_arm_enabled() -> bool:
    """``VULTURE_CWE778_GO`` — default TRUE (0087 step 11)."""
    return os.environ.get("VULTURE_CWE778_GO", "true").strip().lower() != "false"


def _scan_go_error_check(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Report a Go `if err != nil` block that neither logs nor propagates."""
    if "err" not in line or "nil" not in line:
        return
    if not _GO_SITE.search(line):
        return
    if not _go_arm_enabled() or not file_path.endswith(".go"):
        return
    body = collect_scoped_body(lines, lineno, brace_family=True)
    # No early return on an empty body. `collect_scoped_body` returns nothing
    # for a block that opens AND closes on the header line, so returning here
    # dropped every single-line form -- `if err != nil { }`, `{}` and
    # `{ count++ }` alike -- before the "is empty" classification below could
    # see them. It also made the `header_tail` comment two blocks down
    # unreachable: that exists so a one-line `if err != nil { log.Print(err) }`
    # is not lost, and this return fired first for exactly those lines.
    # Rare in gofmt'd Go, which splits the brace onto its own line, but the
    # shape the empty-body fix claims to cover.
    # Only the part of the header AFTER `{` may count as handling. The init
    # clause of `if err := run(); err != nil {` is the SITE, not a response to
    # it — and it reads as an assignment whose right-hand side mentions `err`,
    # so leaving it in made _GO_CAPTURED excuse every block written that way.
    # Dropping the whole header instead would lose the one-line form
    # `if err != nil { log.Print(err) }`, which is why the tail is kept.
    header_tail = line.split("{", 1)[1] if "{" in line else ""
    text = "\n".join([header_tail, *body])
    if _GO_LOG.search(text) or _GO_PROPAGATES.search(text) or _GO_EXCUSED.search(text):
        return
    stripped = [b.strip() for b in body if b.strip() not in ("}", "};", "")]
    if not stripped:
        # `if err != nil { }` — the one shape with nothing at all in it. The
        # first cut returned here, making the clearest swallow unreportable.
        why = "is empty"
    elif _GO_CLIENT_RESPONSE.search(text):
        why = "answers the client but writes no server-side log"
    elif any(_GO_SWALLOW_RETURN.search(b) for b in stripped):
        why = "returns without the error"
    elif any(_GO_SWALLOW_LOOP.search(b) for b in stripped):
        why = "continues or breaks the loop"
    else:
        why = "falls through without terminating"
    finding = {
        "severity": "medium",
        "check_id": "cwe.insufficient_logging.go_swallow",
        "category": "CWE-778",
        "title": "Go error checked but neither logged nor propagated",
        "description": (
            f"The `if err != nil` block at line {lineno} {why}, and no logging "
            "call records it. In Go, returning or wrapping the error is the "
            "correct alternative to logging — this block does neither, so the "
            "failure leaves no trace."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Either log the error with the package logger, or return it to a "
            "caller that does (`return fmt.Errorf(\"context: %w\", err)`)."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, lineno)
    findings.append(enrich_finding(finding, "778"))


# ---------------------------------------------------------------------------
# 0087 step 8 — JS/TS promise rejection handlers.
#
# `try/catch` is only half of JavaScript's error surface; the other half is the
# promise chain, which the catch-block scanner cannot see at all. Three shapes:
#
#   .catch(e => { })            rejection swallowed
#   .then(ok, e => { })         the two-arg form, same thing
#   process.on('unhandledRejection', ...)   the last-resort handler
#
# `.catch(next)` / `.catch(reject)` / `.catch(done)` DELEGATE — the callee is
# responsible — and are excused, as is any handler that rethrows.
_JS_EXTENSIONS = frozenset({".js", ".jsx", ".ts", ".tsx", ".cjs", ".mjs"})
_JS_CATCH = re.compile(r"\.catch\s{0,4}\(")
_JS_THEN2 = re.compile(r"\.then\s{0,4}\([^,()]{0,80},\s{0,4}(?:\(|function|\w{1,40}\s{0,4}=>)")
_JS_PROC_ON = re.compile(
    r"\bprocess\s*\.\s*on\s*\(\s*[\"\']" 
    r"(?:uncaughtException|unhandledRejection)[\"\']"
)
# A bare identifier argument is a delegation, not a swallow: `.catch(next)`.
_JS_DELEGATE_ARG = re.compile(r"\.catch\s{0,4}\(\s{0,4}[\w.$]{1,60}\s{0,4}\)")
# An empty handler body, in the three ways JS spells a callback. Two variants,
# because they need different treatment: a handler that opens AND closes on the
# header line (`.catch(() => {})`) has no further body to read, while one that
# opens at end-of-line does. Running the body collector on the first kind walks
# straight past the closing brace into unrelated code — the scope leak step 4
# fixed for handlers whose body is genuinely below the header.
# The whole callback head must be ONE group: without the outer (?:...) the
# top-level `|` splits the ENTIRE pattern it is interpolated into, so the first
# branch ends at `=>` and the `{}` that follows is never required.
_JS_CB = r"(?:(?:\([^)]{0,80}\)|\w{1,40})\s{0,4}=>|function\s{0,4}\([^)]{0,80}\))"
_JS_EMPTY_INLINE = re.compile(r"\.(?:catch|then)\s{0,4}\([^\n]{0,120}?" + _JS_CB + r"\s{0,4}\{\s{0,4}\}")
# A handler that RETURNS a null-ish value erases the failure: the caller cannot
# tell a rejection from a legitimate absent value. This is narrower than "any
# value fallback" on purpose. Measured on real code, treating every fallback as
# a swallow gave 4/14 precision, because `.catch(() => setSubmittable(false))`
# surfaces the failure through the UI and `.catch(() => "")` / `.catch(() => [])`
# return a TYPED empty default that the caller can act on. `null`/`undefined`
# do neither.
_JS_NULLISH = r"(?:null|undefined|void\s{0,4}0)"
_JS_NULLISH_INLINE = re.compile(
    r"\.(?:catch|then)\s{0,4}\([^\n]{0,120}?" + _JS_CB + r"\s{0,4}" + _JS_NULLISH + r"\s{0,4}[,)]"
)
# The two-argument `.then(onOk, onRejected)` form, whose rejection arm commonly
# sits on its own line several lines below the `.then(`.
_JS_NULLISH_ARM = re.compile(
    r"^\s{0,80}(?:\([^)]{0,80}\)|\w{1,40})\s{0,4}=>\s{0,4}" + _JS_NULLISH + r"\s{0,4},?\s{0,4}$"
)
_JS_CHAIN_OPEN = re.compile(r"\.(?:then|catch)\s{0,4}\(")
_JS_OPEN_HANDLER = re.compile(r"\.(?:catch|then)\s{0,4}\([^\n]{0,120}?" + _JS_CB + r"\s{0,4}\{\s{0,4}$")


def _js_arm_enabled() -> bool:
    """``VULTURE_CWE778_JS_PROMISE`` — default TRUE (0087 step 8)."""
    return os.environ.get("VULTURE_CWE778_JS_PROMISE", "true").strip().lower() != "false"


def _scan_promise_rejection(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
    seen_lines: set[int],
) -> None:
    """Report a promise rejection handler that records nothing."""
    if lineno in seen_lines:
        return
    # Match the CODE. The other three arms strip; this one was left on raw
    # text, and its site token is literally `.catch(` -- so a comment or doc
    # string quoting a promise chain became a finding.
    if _COMMENT_TOKEN.search(line):
        line = strip_strings_and_comments(line)
    has_catch = ".catch" in line
    has_then = ".then" in line
    # `"=>" in line` alone admits most lines of a modern TS file and cost 3% of
    # the warm budget on the TS-heavy reference repo. A bare nullish arm must
    # also carry one of the nullish tokens, which is far more selective and is
    # still a strict necessary condition of _JS_NULLISH_ARM.
    maybe_arm = "=>" in line and (
        "null" in line or "undefined" in line or "void" in line
    )
    if not (has_catch or has_then or maybe_arm or "process" in line):
        return
    is_proc = "process" in line and bool(_JS_PROC_ON.search(line))
    # A bare rejection arm (`() => undefined,` on its own line, the two-argument
    # `.then(onOk, onRejected)` form) carries neither `.catch` nor `.then`, so it
    # has to be admitted here or the nullish-arm rule below is unreachable.
    bare_arm = bool(_JS_NULLISH_ARM.match(line))
    if not (
        is_proc
        or bare_arm
        or (has_catch and _JS_CATCH.search(line))
        or (has_then and _JS_THEN2.search(line))
    ):
        return
    if not _js_arm_enabled() or not file_path.lower().endswith(tuple(_JS_EXTENSIONS)):
        return
    # Adjudicating 14 rows from the first cut gave 4/14. Two idioms dominated the
    # losses and BOTH genuinely handle the rejection:
    #   .catch(() => '')            a value fallback — Promise.catch used as orElse
    #   .catch(() => setSubmittable(false))   the failure IS surfaced, via the UI
    # Neither is a swallow, and in a frontend the second is how errors are meant to
    # reach a user. So the arm requires an EMPTY body: `.catch(() => {})`. That is
    # the one shape with no defensible reading — nothing is recorded, nothing is
    # shown, and the promise settles as success. Low recall by construction; the
    # alternative measured 29% precision, which is worse than not shipping the arm.
    inline_empty = bool(_JS_EMPTY_INLINE.search(line)) or bool(
        _JS_NULLISH_INLINE.search(line)
    )
    anchor = lineno
    if not inline_empty and _JS_NULLISH_ARM.match(line):
        # A bare nullish arm; only a rejection handler if a chain opened above
        # it. The finding is anchored on the line that OPENED the chain, not on
        # the arm: the `.then(` call is the site a reader needs to look at, and
        # it is what the fixture marker contract points to.
        lo = max(0, lineno - 5)
        for back in range(lineno - 2, lo - 1, -1):
            if _JS_CHAIN_OPEN.search(lines[back]):
                inline_empty = True
                anchor = back + 1
                break
        if anchor in seen_lines:
            return
    if not (is_proc or inline_empty or _JS_OPEN_HANDLER.search(line)):
        return
    if inline_empty:
        # Body is empty and closed on this line: nothing further to read.
        if _body_has_logging([line]) or _body_delegates([line]):
            return
    else:
        body = collect_scoped_body(lines, lineno, brace_family=True)
        scope = [line, *body]
        if _body_has_logging(scope) or _body_propagates(scope) or _body_delegates(scope):
            return
        if not is_proc and [b.strip() for b in body if b.strip() not in ("", "}", "});", ")", "},")]:
            return
    seen_lines.add(anchor)
    what = (
        "The last-resort handler"
        if is_proc
        else "The promise rejection handler"
    )
    finding = {
        "severity": "high" if is_proc else "medium",
        "check_id": "cwe.insufficient_logging.promise_swallow",
        "category": "CWE-778",
        "title": "Promise rejection handled without logging",
        "description": (
            f"{what} at line {anchor} neither logs the rejection nor rethrows it. "
            "The promise settles as though it succeeded and the failure leaves no "
            "record, so the condition is invisible to both callers and operators."
        ),
        "file_path": file_path,
        "line_start": anchor,
        "line_end": anchor,
        "recommendation": (
            "Log the rejection reason in the handler, rethrow it, or forward it to "
            "an error middleware (`.catch(next)`)."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, anchor)
    findings.append(enrich_finding(finding, "778"))


# ---------------------------------------------------------------------------
# 0087 steps 10 & 12 — languages whose handler shape `catch (...) {` cannot see.
#
# Step 10 (Ruby, Swift, Scala, PHP) carries NO switch, per the work order; only
# the Rust arm of step 12 is switched, as `VULTURE_CWE778_RUST`.
#
# Ruby   `rescue => e`          no braces, no parenthesised type
# Ruby   `x = f rescue nil`     the MODIFIER form; the body is the text after it
# Swift  `catch let e as X {`   pattern-bound catch, and bare `catch {`
# Swift  `try?`                 converts a throw to nil and discards the error
# Scala  `case NonFatal(e) =>`  ONE SITE PER ARM, not one per `catch`
# Scala  `Try(..).toOption`     discards the Failure
# PHP    `@func()`              the error-suppression operator: a swallow by design
# Rust   `if let Err(e) = ..`   no exceptions at all; Result is a value
# Rust   `Err(e) => { }`        the match arm
# Rust   `expr.ok();`           statement-position discard of a Result
#
# Rust's `?`, `.unwrap()` and `.expect()` are deliberately NOT reported: `?`
# propagates, and the other two abort loudly with a message and a backtrace.
# A panic is CWE-248, not a silent failure. Swift's `try!` is the same class and
# is likewise excluded; `try?` IS reported, because it discards silently.
_RUBY_RESCUE = re.compile(r"^\s{0,80}rescue\b[^\n]{0,120}$")
# The modifier form. `rescue_from` and `ensure` must not match, hence the
# explicit boundary and the requirement of an assignment ahead of it.
_RUBY_MODIFIER = re.compile(r"=\s{0,4}[^\n]{1,120}?\brescue\s+(?!_)[^\n]{1,80}$")
# NOT anchored to line start: Swift's canonical form is `do { try f() } catch {`,
# so the catch is mid-line. The pattern-bound variant `catch let e as X {` is the
# reason a Swift arm is needed at all -- the generic `_CATCH_LINE` expects either
# parentheses or `{` immediately after `catch`, and this form has neither.
# Requires the `let` binding. A bare `} catch {` is already matched by
# `_CATCH_LINE` and reported as `cwe_778`, so accepting it here emitted a SECOND
# row on the same line. The pattern-bound form is the only shape the generic
# brace pattern cannot express, and therefore the only reason this arm exists.
_SWIFT_CATCH = re.compile(r"\bcatch\s{1,4}let\b[^\n{]{0,120}\{")
# `try? await ...` is excluded: awaiting under structured concurrency throws
# CancellationError on cancellation, and discarding it is the documented idiom
# (`try? await Task.sleep(...)` is the canonical cancellable sleep). Measured on
# a real Swift tree, 33% of this arm's 322 rows were exactly that call.
_SWIFT_TRY_OPT = re.compile(r"(?<![\w!?])try\?\s(?!\s{0,4}await\b)")
_SCALA_CASE_ARM = re.compile(
    r"^\s{0,80}case\s{1,4}(?:NonFatal\s{0,4}\(|_\s{0,4}:|[A-Za-z_]\w{0,60}\s{0,4}:|[A-Z]\w{0,60})"
    r"[^\n]{0,120}=>"
)
_SCALA_TRY_TOOPTION = re.compile(
    r"\bTry\s{0,4}\([^\n]{0,160}\)\s{0,4}\.\s{0,4}toOption\b"
)
_RUST_IF_LET_ERR = re.compile(r"^\s{0,80}if\s+let\s+(?:Some\s*\(\s*)?Err\s*\(")
_RUST_MATCH_ERR = re.compile(r"^\s{0,80}Err\s*\((?:_|\w{1,40})?\)?\s{0,4}=>")
# Statement position only. `[^;=\n]` rather than an explicit character class:
# the receiver is an arbitrary expression and may contain quotes, generics or
# operators (`fs::remove_dir_all(root.join("scratch")).ok();` was missed by a
# class that omitted `"`). Excluding `=` is what keeps `let v = x.ok();` out --
# that ASSIGNS the Option, which is a legitimate conversion, not a discard.
# Anchored at both ends so the scan cost is one attempt per line.
_RUST_OK_DISCARD = re.compile(
    r"^\s{0,80}[^;=\n]{1,160}\.ok\s{0,4}\(\s{0,4}\)\s{0,4};\s{0,8}(?://.{0,200})?$"
)
# `@` suppression. A docblock `@param` is not a call, so the trailing `(` is
# required; the lookbehind keeps `"@foo("` inside a string from matching.
_PHP_SUPPRESS = re.compile(r"(?<![\w\"'])@(?:[a-zA-Z_]\w{2,60})\s*\(")
# `set_error_handler(function () { })` installs a handler that discards every
# diagnostic in the process -- broader than a single `@`, and named by step 10.
_PHP_SET_HANDLER = re.compile(
    r"\bset_(?:error|exception)_handler\s*\(\s*"
    r"(?:function\s*\([^)]{0,80}\)\s*\{\s{0,8}\}|fn\s*\([^)]{0,80}\)\s{0,4}=>\s{0,4}(?:null|\{\s{0,8}\}))"
)
# Kotlin's Result wrapper. `.getOrNull()` / `.getOrDefault()` / `.getOrElse {}`
# throw the Throwable away; `.getOrThrow()` propagates it and is excluded.
_KT_RUN_CATCHING = re.compile(
    r"\brunCatching\s*\{[^\n]{0,200}\}\s*\.\s*(?:getOrNull|getOrDefault|getOrElse)\b"
)
_KT_EXT = frozenset({".kt", ".kts"})
_RUBY_EXT = frozenset({".rb", ".rake"})
_SWIFT_EXT = frozenset({".swift"})
_SCALA_EXT = frozenset({".scala", ".sc"})
_RUST_EXT = frozenset({".rs"})
_PHP_EXT = frozenset({".php"})


_SCALA_CATCH_OPEN = re.compile(r"\bcatch\s{0,4}\{")
_SCALA_MATCH_OPEN = re.compile(r"\bmatch\s{0,4}\{")


def _scala_arm_in_catch(lines: tuple[str, ...], lineno: int) -> bool:
    """True only when this `case` arm belongs to a `catch`, not a `match`.

    `case X => Y` is Scala's universal pattern-match syntax; the overwhelming
    majority of arms are ordinary matches. Without this precondition the arm
    shape reported 38 rows on this repo's Isabelle-exported Scala, every one of
    them an ordinary state transition (`case Scan() => ScanRunning()`), and the
    work order asks specifically for one site per arm OF A CATCH.
    """
    arm_indent = len(lines[lineno - 1]) - len(lines[lineno - 1].lstrip())
    for i in range(lineno - 2, max(-1, lineno - 42), -1):
        src = lines[i]
        stripped = src.strip()
        if not stripped:
            continue
        if _SCALA_CATCH_OPEN.search(src):
            return (len(src) - len(src.lstrip())) < arm_indent
        if _SCALA_MATCH_OPEN.search(src):
            return False
        # A closing brace at or left of the arm's column ends the enclosing
        # block, so anything above it cannot be this arm's `catch`.
        if stripped.startswith("}") and (len(src) - len(src.lstrip())) <= arm_indent:
            return False
    return False


# Extra preconditions that cannot be expressed as a line pattern.
_SHAPE_GUARDS: dict[str, Any] = {"scala_case_arm": _scala_arm_in_catch}


def _extra_langs_enabled() -> bool:
    """``VULTURE_CWE778_EXTRA_LANGS`` — master hatch for the step-10/12 shapes.

    The work order gives step 10 no switch and step 12 the switch
    ``VULTURE_CWE778_RUST``; this one is retained only as a single kill switch
    for the whole group, defaulting on, and is not the per-arm control.
    """
    return os.environ.get("VULTURE_CWE778_EXTRA_LANGS", "true").strip().lower() != "false"


# Rust-specific excusals. The shared predicates were written for
# exception languages: they do not know that returning `Err(..)`, invoking a
# `panic!`-family macro, emitting a runtime event, or calling a snake_case
# error handler all REPORT the failure. Measured on a real Rust tree, 23 of 33
# rust_* rows had one of these in the body.
def _rust_arm_enabled() -> bool:
    """``VULTURE_CWE778_RUST`` — default TRUE (0087 step 12)."""
    return os.environ.get("VULTURE_CWE778_RUST", "true").strip().lower() != "false"


# (extensions, pattern, brace_family, check_id suffix, description, switch)
# `switch` is None for the step-10 languages, which the work order gives no
# switch, and `_rust_arm_enabled` for the step-12 Rust arm.
_EXTRA_SHAPES: tuple[tuple[frozenset[str], Any, bool, str, str, Any], ...] = (
    (_RUBY_EXT, _RUBY_RESCUE, False, "rescue_swallow",
     "A `rescue` clause that neither logs the exception nor re-raises it", None),
    (_RUBY_EXT, _RUBY_MODIFIER, False, "rescue_modifier",
     "A `rescue` modifier that substitutes a value and discards the exception", None),
    (_SWIFT_EXT, _SWIFT_CATCH, True, "swift_catch",
     "A `catch` block that neither logs the error nor rethrows it", None),
    (_SWIFT_EXT, _SWIFT_TRY_OPT, False, "swift_try_optional",
     "`try?`, which converts a thrown error to nil and discards it", None),
    # brace_family=False: a `case` arm is delimited by INDENT and by the next
    # `case`, not by braces. With brace matching the arm's body ran on to the
    # following arm and was excused by ITS logging call, which is precisely the
    # "one site per case arm" requirement failing.
    (_SCALA_EXT, _SCALA_CASE_ARM, False, "scala_case_arm",
     "A `case` arm of a `catch` that neither logs the exception nor rethrows it", None),
    (_SCALA_EXT, _SCALA_TRY_TOOPTION, False, "scala_try_tooption",
     "`Try(..).toOption`, which discards the Failure and its exception", None),
    (_KT_EXT, _KT_RUN_CATCHING, False, "kt_run_catching",
     "`runCatching { .. }.getOrNull()`, which discards the Throwable", None),
    (_PHP_EXT, _PHP_SUPPRESS, True, "php_suppress",
     "The `@` error-suppression operator, which discards the diagnostic entirely", None),
    (_PHP_EXT, _PHP_SET_HANDLER, True, "php_empty_error_handler",
     "An error/exception handler registered with an empty body, which discards "
     "every diagnostic in the process", None),
    (_RUST_EXT, _RUST_IF_LET_ERR, True, "rust_if_let_err",
     "An `if let Err(..)` arm that neither logs the error nor returns it",
     _rust_arm_enabled),
    (_RUST_EXT, _RUST_MATCH_ERR, True, "rust_match_err",
     "A `match` error arm that neither logs the error nor returns it",
     _rust_arm_enabled),
    (_RUST_EXT, _RUST_OK_DISCARD, True, "rust_ok_discard",
     "A `Result` discarded with `.ok()` in statement position", _rust_arm_enabled),
)

# Shapes that are a single expression: there is no block below them to inspect.
_EXPRESSION_SHAPES = frozenset({
    "rust_ok_discard", "php_suppress", "php_empty_error_handler", "rescue_modifier",
    "kt_run_catching",
    "swift_try_optional", "scala_try_tooption",
})


@lru_cache(maxsize=64)
def _shapes_for(suffix: str) -> tuple:
    """The extra-language shapes that can apply to this extension."""
    return tuple(sh for sh in _EXTRA_SHAPES if suffix in sh[0])


def _scan_extra_language_shapes(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
    seen_lines: set[int],
    suffix: str | None = None,
) -> None:
    """Report handler shapes that the brace/except scanners cannot express."""
    if lineno in seen_lines:
        return
    if suffix is None:
        suffix = Path(file_path).suffix.lower()
    if not _extra_langs_enabled():
        return
    # Match the CODE, not a comment or a string literal: the plan's Ruby fixture
    # requires the word `rescue` inside a comment not to fire.
    code = strip_strings_and_comments(line)
    for exts, pattern, brace_family, check, what, switch in _shapes_for(suffix):
        if switch is not None and not switch():
            continue
        if not pattern.search(code):
            continue
        guard = _SHAPE_GUARDS.get(check)
        if guard is not None and not guard(lines, lineno):
            continue
        # A one-expression discard has no body to inspect; the others do.
        if check in _EXPRESSION_SHAPES:
            scope = [line]
        else:
            # An EMPTY body is not a reason to skip -- it is the clearest
            # possible swallow. collect_scoped_body returns nothing in exactly
            # two situations, and both mean the handler is empty: the block
            # opened and closed on the header line, or nothing is indented
            # deeper than the header. Skipping here made `catch let e as X { }`
            # unreportable, the same way the Go arm's `if not stripped: return`
            # made `if err != nil { }` unreportable.
            scope = [line, *_body_for(lines, lineno, brace_family)]
        if _body_has_logging(scope) or _body_propagates(scope) or _body_delegates(scope):
            continue
        seen_lines.add(lineno)
        finding = {
            "severity": "medium",
            "check_id": f"cwe.insufficient_logging.{check}",
            "category": "CWE-778",
            "title": "Error handled without logging",
            "description": (
                f"{what}, at line {lineno}. The failure leaves no record, so it "
                "cannot be detected or investigated after the fact."
            ),
            "file_path": file_path,
            "line_start": lineno,
            "line_end": lineno,
            "recommendation": (
                "Log the error with the language's logger, or propagate it to a "
                "caller that does."
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, lineno)
        findings.append(enrich_finding(finding, "778"))
        return


def _scan_auth_decision(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
    seen_lines: set[int],
    strip: bool | None = None,
) -> None:
    """Flag auth-decision points that aren't audit-logged in the
    surrounding window. The same line is only reported once even if it
    matches multiple auth keywords."""
    if lineno in seen_lines:
        return
    # Cheap necessary condition first. Stripping only ever REMOVES text, so a raw
    # line that does not match cannot match once stripped — testing the raw line
    # first is therefore sound, and it keeps strip_strings_and_comments off the
    # ~99% of lines that were never candidates. Measured: this scanner was half
    # the skill's total runtime, with 184k strip calls and 184k os.environ reads
    # for 62 findings.
    if not _AUTH_DECISION.search(line):
        return
    if strip is None:
        strip = _auth_strip_enabled()
    # 0087 B3: match the CODE, not the comments and string literals. Measured on
    # the shipped detector: 58 of 62 auth_decision findings lose their keyword
    # under strip_strings_and_comments — 15 are pure comment lines (`// … treated
    # as forbidden (403)`), several are enum entries (`"UNAUTHORIZED",`). The
    # module already imports the stripper; this path simply never used it.
    if strip:
        code = strip_strings_and_comments(line)
        if not code.strip() or not _AUTH_DECISION.search(code):
            return
    if _has_log_within(lines, lineno, radius=4):
        return
    # 0087 B3: an auth decision that propagates or delegates the error is no more
    # a logging defect than a handler that does. The excusals the handler path has
    # always applied were never applied here.
    if strip:
        # Include the site line itself. Starting at `lineno` skips it, so
        # `if (!authorized) throw new ForbiddenError()` -- propagation written on
        # the decision line -- was never excused.
        window = list(lines[lineno - 1 : min(lineno + 4, len(lines))])
        if _body_propagates(window) or _body_delegates(window):
            return
    seen_lines.add(lineno)
    finding = {
        "severity": "medium",
        "check_id": "cwe.insufficient_logging.auth_decision",
        "category": "CWE-778",
        "title": "Authentication/authorization decision not logged",
        "description": (
            f"Auth decision at line {lineno} (e.g. login failure, access "
            "denied, invalid credentials) doesn't emit a logging call "
            "within 4 lines. Auth events must be audit-logged."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Log the decision and identifying context (subject, "
            "resource, reason) via your audit-log facility so security "
            "monitoring and forensics can reconstruct the event."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    findings.append(enrich_finding(finding, "778"))


# ---------------------------------------------------------------------------
# 0087 step 14 (D1b) — security scoping.
#
# Sink-FIRST: what matters is what the guarded operation DID, not what the
# handler says. A swallowed `json.Unmarshal` of a config file and a swallowed
# signature check are the same shape and very different findings. When this is
# on, only handlers guarding a security-relevant operation are reported.
#
# Word-anchored and pinned in one module-level constant so the vocabulary is
# reviewable in a single place: substring matching turned `auth` into a match
# on `uniqueAuthorIds`, which is how a flagship true positive was contaminated
# during the method comparison that preceded this feature.
_SECURITY_TERMS: tuple[str, ...] = (
    "auth", "authn", "authz", "login", "logout", "signin", "signup",
    "password", "passwd", "credential", "secret", "token", "apikey",
    "session", "cookie", "jwt", "oauth", "saml", "sso",
    "permission", "privilege", "role", "acl", "grant", "revoke",
    "crypt", "encrypt", "decrypt", "cipher", "hash", "hmac", "signature",
    "sign", "verify", "validate", "sanitize", "escape",
    "admin", "root", "sudo", "chmod", "chown", "umask",
    "cert", "tls", "ssl", "x509", "keystore", "truststore",
    "csrf", "xsrf", "cors", "origin", "referer",
    "audit", "firewall", "allowlist", "denylist", "blocklist",
)
# Tokenise-then-test rather than a 59-way alternation with two lookarounds
# evaluated at every position: same identifier-boundary semantics, linear cost.
# Splitting on non-alphanumerics is what makes `auth_token` match both `auth`
# and `token`, which a plain `\b` alternation would not do (`_` is a word char).
_SECURITY_SET = frozenset(_SECURITY_TERMS)
_WORD_RE = re.compile(r"[A-Za-z]{2,}")
# Section 3.2 rule 1 also counts a rejection RESPONSE as security-relevant, and
# that is not a word: `[A-Za-z]{2,}` cannot see `401`. Status codes and explicit
# deny/reject returns are matched separately, or the whole first bullet of the
# scoping rule is undetectable.
_SECURITY_SIGNAL_RE = re.compile(
    r"\b(?:401|403|407|419|423|451)\b"
    r"|\bStatus(?:Code)?\s*[.=:(]\s*(?:401|403|407)"
    r"|\bhttp\.Status(?:Unauthorized|Forbidden|ProxyAuthRequired)\b"
    r"|\bHTTP_(?:UNAUTHORIZED|FORBIDDEN|PROXY_AUTHENTICATION_REQUIRED)\b"
    # No trailing \b: the canonical spelling is a CLASS name, and `\b` after
    # `Unauthorized` cannot match before the `E` of `UnauthorizedError`.
    r"|\b(?:Unauthorized|Forbidden|AccessDenied|PermissionDenied|NotPermitted)\w{0,24}"
    r"|\breturn\s{1,4}(?:False|false|nil|None)\s{0,4}(?:;|$)"
    r"|\b(?:deny|denied|reject|rejected|forbid|forbidden|unauthorised|unauthorized)\b",
    re.IGNORECASE,
)


def _security_scope_enabled() -> bool:
    """``VULTURE_CWE778_SECURITY_SCOPE`` — default FALSE (0087 step 14).

    Off by default because it is a RECALL cut, not a precision fix: a swallowed
    error is a defect whether or not the operation was security-relevant. It
    exists for the operator who wants CWE-778 restricted to the security surface.
    """
    return os.environ.get("VULTURE_CWE778_SECURITY_SCOPE", "").strip().lower() == "true"


def _in_security_scope(lines: tuple[str, ...], lineno: int) -> bool:
    """True when the operation the handler guards looks security-relevant."""
    lo = max(0, lineno - 1 - _SECURITY_LOOKBACK)
    for src in lines[lo:lineno]:
        for word in _WORD_RE.findall(src):
            if word.lower() in _SECURITY_SET:
                return True
        if _SECURITY_SIGNAL_RE.search(src):
            return True
    return False


_SECURITY_LOOKBACK = 6


# ---------------------------------------------------------------------------
# 0087 step 13 (D1a) — the aggregate hygiene row.
#
# One row per language plus an overall row, reporting how many handler sites
# record nothing. The denominator EXCLUDES propagating sites: in Go, and in any
# language with a `throw`/`raise`/`?`, handing the error upward is correct and
# counting those as "should have logged" makes the ratio meaningless — the Go
# census behind this feature had 554 of 788 sites propagating.
#
# The row text carries no cross-repo baseline. A number from another codebase
# is not a target for this one, and stating it invites the reader to treat it
# as a threshold it was never measured to be.
_METRIC_VERSION = "0087.1"


def _aggregate_enabled() -> bool:
    """``VULTURE_CWE778_AGGREGATE`` — default FALSE (0087 step 13)."""
    return os.environ.get("VULTURE_CWE778_AGGREGATE", "").strip().lower() == "true"


def _build_aggregate_rows(stats: dict[str, dict[str, int]]) -> list[dict]:
    """Summarise handler hygiene per language, propagating sites excluded."""
    rows: list[dict] = []
    total_d = total_r = 0
    for lang in sorted(stats):
        st = stats[lang]
        denom = st["sites"] - st["propagating"]
        if denom <= 0:
            continue
        total_d += denom
        total_r += st["reported"]
        rows.append(_aggregate_row(lang, st["reported"], denom))
    if total_d > 0 and len(rows) > 1:
        rows.append(_aggregate_row("all languages", total_r, total_d))
    return rows


def _aggregate_row(lang: str, reported: int, denom: int) -> dict:
    pct = round(100.0 * reported / denom, 1)
    return enrich_finding(
        {
            "severity": "info",
            "check_id": f"cwe.insufficient_logging.aggregate.{lang.replace(' ', '_')}",
            "category": "CWE-778",
            "title": f"Error-handling hygiene summary ({lang})",
            "description": (
                f"{reported} of {denom} non-propagating error handlers in {lang} "
                f"record nothing ({pct}%). Handlers that propagate the error to a "
                "caller are excluded from the denominator, because propagating is "
                "a correct alternative to logging. This row is a summary of the "
                "individual findings, not an additional defect. "
                f"metric_version={_METRIC_VERSION}"
            ),
            "file_path": "",
            "line_start": 0,
            "line_end": 0,
            "recommendation": (
                "Use this ratio to track handler hygiene between scans of this "
                "same codebase."
            ),
        },
        "778",
    )


# The denominator must be drawn from the SAME population the scanners consider,
# or the ratio is meaningless. Leaving the promise and Rust/PHP shapes out gave
# typescript 17/17 = 100%: `try/catch` sites counted, `.catch(...)` sites did
# not, so every promise finding landed in a numerator with no denominator.
_SITE_PATTERNS: tuple[tuple[str, Any], ...] = (
    ("python", _PY_EXCEPT),
    ("go", _GO_SITE),
    ("ruby", _RUBY_RESCUE),
    ("rust", _RUST_IF_LET_ERR),
    ("rust", _RUST_MATCH_ERR),
    ("rust", _RUST_OK_DISCARD),
    ("php", _PHP_SUPPRESS),
    ("javascript", _JS_CATCH),
    ("javascript", _JS_THEN2),
    ("brace", _CATCH_LINE),
)


def _site_language(line: str, suffix: str) -> str | None:
    """Name the language whose handler shape this line opens, if any."""
    for lang, pattern in _SITE_PATTERNS:
        if pattern.search(line):
            return _SUFFIX_LANG.get(suffix, lang)
    return None


_SUFFIX_LANG: dict[str, str] = {
    ".py": "python", ".go": "go", ".rb": "ruby", ".rs": "rust", ".php": "php",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
    ".scala": "scala", ".cs": "c#", ".cpp": "c++", ".cc": "c++", ".cxx": "c++",
    ".hpp": "c++", ".js": "javascript", ".cjs": "javascript", ".mjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
}


def _record_site(
    stats: dict[str, dict[str, int]],
    line: str,
    suffix: str,
    lines: tuple[str, ...],
    lineno: int,
    reported: bool,
) -> None:
    """Count one handler site for the aggregate row (0087 step 13)."""
    lang = _site_language(line, suffix)
    if lang is None:
        return
    st = stats.setdefault(lang, {"sites": 0, "reported": 0, "propagating": 0})
    st["sites"] += 1
    if reported:
        st["reported"] += 1
        return
    # Only unreported sites need the propagation test: a reported one by
    # definition did not propagate, so re-deriving it there would be wasted work
    # on the hot path.
    body = _body_for(lines, lineno, suffix != ".py")
    if _body_propagates([line, *body]) or _GO_PROPAGATES.search("\n".join(body)):
        st["propagating"] += 1


def check_insufficient_logging(source_path: str) -> dict[str, Any]:
    """Scan source files for silent exception handlers (CWE-778)."""
    findings: list[dict] = []
    stats: dict[str, dict[str, int]] | None = {} if _aggregate_enabled() else None
    skipped: dict[str, int] = {}
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings, stats, skipped)
    if stats:
        findings.extend(_build_aggregate_rows(stats))
    result: dict[str, Any] = {"findings": findings}
    if skipped.get("lines"):
        # Surfaced, not silent: coverage of these lines is PARTIAL.
        result["notes"] = [
            f"{skipped['lines']} line(s) exceeded the "
            f"{_max_line_chars()}-character per-line guard and were not scanned; "
            "coverage of those lines is partial "
            "(raise VULTURE_CWE778_MAX_LINE_CHARS, or 0 to disable)"
        ]
        result["skipped_long_lines"] = skipped["lines"]
    return result


check_insufficient_logging_tool = function_tool(check_insufficient_logging)
