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

Feature 0101 narrows both to what CWE-778 means -- a SECURITY-RELEVANT event that
is not recorded: a handler that hands its failure on is excused outside the
security surface (Concept A), a keyword that names an outcome is not a decision
(Concept B), and a best-effort promise swallow is excused when its chain head is
not a security operation (Concept C). Each fails toward the pre-0101 verdict.
"""
import os
import re
from functools import cached_property, lru_cache
from itertools import islice
from pathlib import Path
from typing import Any

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._lexical import (
    MAX_SCAN_CHARS,
    call_argument_text,
    catch_binding,
    identifier_words,
    indent_width,
    opening_bracket,
    param_name,
    paren_lists,
    routine_header,
    stripped_code,
)
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

# Language gate — logging conventions differ and the regex targets these.
# 0087 B7/step 9. Six of the languages the LLD called "structurally blind" were
# excluded HERE, before any pattern ran — .cpp and .kt already match the existing
# catch shape, so widening this frozenset adds them with no new patterns. The
# .tsx/.jsx/.cjs/.mjs omission mattered most: 212 catch sites in reference-app were
# never scanned, and reference-app is the repo every ground-truth true positive came
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
# 56 such sites in reference-app .ts/.tsx alone. Quantifiers bounded per B2.
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


# A strict necessary condition of `_AUTH_DECISION`, tested on the lower-cased line:
# every alternative contains one of these roots. The case-insensitive alternation
# was a third of the skill's cold time on a 120k-line tree (93 ms) because it runs
# on every line; the hint plus `lower()` costs about a third of that and the full
# pattern then runs on ~2% of lines. It cannot change what is reported: a non-ASCII
# line (where IGNORECASE folds characters `lower()` does not, such as `ſ`) skips
# the hint and goes straight to the full pattern.
_AUTH_HINT = re.compile(r"auth|login|denied|mfa|token|forbidden|credential")


def _auth_candidate(line: str) -> bool:
    hinted = not line.isascii() or _AUTH_HINT.search(line.lower()) is not None
    return hinted and _AUTH_DECISION.search(line) is not None


def _has_log_within(lines: tuple[str, ...], lineno: int, radius: int = 4) -> bool:
    """True when a log call appears within ``radius`` lines of ``lineno``."""
    start = max(0, lineno - radius - 1)
    end = min(len(lines), lineno + radius)
    return any(map(_line_logs, lines[start:end]))


# Per-line verdicts of the window predicates, cached by line text: an auth line's
# 9-line log window and 5-line propagation window overlap its neighbours', so an
# auth-dense file re-read every line up to 14 times. The answer is a
# pure function of the line, so caching cannot change what is reported.
_LINE_MEMO = 2048


@lru_cache(maxsize=_LINE_MEMO)
def _line_logs(line: str) -> bool:
    return _LOG_CALL.search(line) is not None


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
    return any(map(_line_delegates, body_lines))


@lru_cache(maxsize=_LINE_MEMO)
def _line_delegates(line: str) -> bool:
    return _ERROR_DELEGATE.search(strip_strings_and_comments(line)) is not None


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
    return any(map(_line_propagates, body_lines))


@lru_cache(maxsize=_LINE_MEMO)
def _line_propagates(line: str) -> bool:
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
    return any(_opens_statement(cleaned, m.start()) for m in _RAISE_THROW.finditer(cleaned))


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


# ---------------------------------------------------------------------------
# 0101 Concept A -- a handler that HANDS THE FAILURE ON, outside the security surface.
#
# CWE-778 is "a security-relevant event is not recorded"; the rule implemented "any
# handler that does not log". Measured on one real target: 250 matched false
# positives, and every handler SHAPE that had them also had true positives (an empty
# catch, a conversion to a value, answering the client, forwarding the error --
# `return toOpaqueFault(err)` was real in two byte-identical handlers and false in
# three). The separating signal is where the failure GOES together with WHAT was
# guarded. So a non-empty handler that neither logs nor propagates is excused only
# when (1) its try opener resolves, (2) it hands the failure on, with the error
# itself as evidence, and (3) the guarded operation is not security-relevant. Fails
# toward the pre-0101 verdict: an unresolved try is reported.
#
# Every looked-at line, joined statement and argument span is capped at
# `MAX_SCAN_CHARS` before a predicate runs, independent of the site-line guard,
# and the per-routine analysis is memoised per file: handlers that
# share a routine share its opener chain, prior names and security verdict.
# ---------------------------------------------------------------------------
_FAILURE_WORDS = frozenset({
    "err", "error", "errors", "errored", "fail", "failed", "failure", "failures",
    "exception", "exc", "fault",
})
# A handler that hands the error to one of these verbs keeps it: collected for a
# batch report, or sent to a reporting sink. `set` is deliberately absent: it made
# `res.set('X-Error', ...)` and `setTimeout(...)` excuse handlers.
_COLLECT_VERBS = frozenset({"push", "append", "add", "insert", "put", "unshift", "enqueue", "extend", "store"})
_REPORT_VERBS = frozenset({"report", "capture", "notify", "record", "track"})
_HANDOFF_VERBS = _COLLECT_VERBS | _REPORT_VERBS
# A routine whose name asks a question, or NEGATES the failure, never hands it on:
# `isError(e)`, `swallowError(e)`, `ignoreFailures()`, `clearFailures()`,
# `resetErrorState()`.
_NOT_A_SINK_FIRST_WORDS = frozenset({
    "is", "has", "can", "should", "was",
    "swallow", "ignore", "suppress", "clear", "reset", "silence", "mute", "discard", "cleanup", "drop",
})
_STMT_END_TOKENS = ("{", "}", ";", ")", "=>")
_STMT_END_WORDS = frozenset({"await", "void", "else", "then", "do"})
_LOOK_BEHIND = 64            # characters `_statement_position` reads
_TYPE_LOOK_BEHIND = 16       # characters the type-introspection test reads
_ARG_SPAN = 400              # characters of a call's argument text
_TRY_LOOKBACK = 80           # lines to the try opener before the handler is unresolved
_ROUTINE_LOOKBACK = 300      # lines to the routine declaration
_MEMO_MAX = 4096

_WORD_ONLY = re.compile(r"[A-Z]?[a-z]{1,64}|[A-Z]{1,64}(?![a-z])")
_TYPE_INTROSPECTION_BEFORE = re.compile(r"(?:\btype\s{0,2}\(|\btypeof\s{1,4})$")
_TYPE_INTROSPECTION_AFTER = re.compile(
    r"\s{0,2}(?:\.\s{0,2}(?:__class__|constructor|GetType|getClass|javaClass|__name__)\b|::\s{0,2}class\b)"
)
# The left-hand side also admits a `->` member chain: PHP `$this->x = $e` is a
# field store. An element write through it
# (`$this->errors[] = $e`) is not admitted: it is a pinned residual (`residual/residual.php`).
_ASSIGN = re.compile(
    r"^\s{0,80}(?P<decl>(?:const|let|var|val|my|local|final|auto)\s{1,4})?"
    r"(?P<lhs>[@\w$][\w$.@]{0,120}(?:\[[^\]=]{0,60}\])?|[@\w$][\w$.@]{0,60}(?:->[\w$]{1,60}){1,6})"
    r"\s{0,4}(?:\+|-|\|\||\?\?)?=(?![=>])\s{0,4}"
    r"(?P<rhs>.{0,2000})$"
)
_CALLEE = re.compile(
    r"(?<![\w$.])(new\s{1,4})?([A-Za-z_$][\w$]{0,60}(?:\s{0,2}\.\s{0,2}[A-Za-z_$][\w$]{0,60}){0,6})\s{0,4}\("
)
_DOT_SPLIT = re.compile(r"\s{0,2}\.\s{0,2}")
_APPEND_OP = re.compile(r"[\w$\])]\s{0,4}<<\s{0,4}")
_RETURN_KW = re.compile(r"(?:^|[\s{;:])return\b")
_OBJECT_KEY = re.compile(r"(?<![\w$])[\w$]{1,60}\s{0,4}:(?!:)")
_SEVERITY_ARG = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]{0,60}\s{0,2}\.\s{0,2}([A-Za-z_]{1,30})(?![\w$(.])")
_BRACKET = re.compile(r"[()\[\]{}]")
_BRACKET_DELTA = {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}
_NEXT_NONSPACE = re.compile(r"\S")
# A field target, an element write, or a member write: the value outlives the handler.
_FIELD_LHS = re.compile(r"[.@]|->|\[")
# `try`/`begin`/`do` followed by a block, a colon or the end of the line; or a
# try-with-resources header `try (Reader r = open(id)) {` (one level of nested
# parentheses; each repetition takes one character or one group, so no
# backtracking ambiguity), with its `{` on the line or the next.
_TRY_OPEN = re.compile(
    r"(?:^|[\s};])(?:(?:try|begin|do)\b\s{0,4}(?:\{|:|$)"
    r"|try\s{0,4}\((?:[^()]|\([^()]{0,200}\)){0,300}\)\s{0,4}(?:\{|$))"
)
_RUBY_DEF = re.compile(r"^\s{0,80}def\b")
_PRIOR_ASSIGN = re.compile(
    r"(?:^|[\s,(;])(?:(?:const|let|var|val|my|local|final|auto)\s{1,4})?([A-Za-z_$@][\w$]{0,60})"
    r"\s{0,4}(?::[^=]{0,80})?=(?![=>])"
)
_IDENT_ANY = re.compile(r"[A-Za-z_$][\w$]{0,60}")
_SIGNATURE_CONTINUATION = (")", "})")


@lru_cache(maxsize=4096)
def _verb_words(ident: str) -> tuple[str, ...]:
    """Letter-only words of a callee name, for the verb and failure lexicons."""
    return tuple(w.lower() for w in _WORD_ONLY.findall(ident[:MAX_SCAN_CHARS]))


def _tail_verb_words(dotted: str) -> tuple[str, ...]:
    """Letter-only words of the LAST segment of a (possibly dotted) callee name."""
    return _verb_words(_DOT_SPLIT.split(dotted)[-1])


def _evidence_names(binding: frozenset[str]) -> frozenset[str]:
    """The binding plus its `$` spelling: PHP writes the bound `e` as `$e`."""
    return binding | frozenset("$" + n for n in binding)


@lru_cache(maxsize=256)
def _name_re(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])")


@lru_cache(maxsize=256)
def _interp_re(name: str) -> re.Pattern[str]:
    return re.compile(r"\{\s{0,2}" + re.escape(name) + r"(?![\w$])")


def _type_only(text: str, m: re.Match[str]) -> bool:
    """`type(e)`, `typeof e`, `e.constructor`: only the error's TYPE escapes."""
    before = text[max(0, m.start() - _TYPE_LOOK_BEHIND):m.start()]
    return bool(_TYPE_INTROSPECTION_BEFORE.search(before) or _TYPE_INTROSPECTION_AFTER.match(text, m.end()))


def _mentions_evidence(text: str, names: frozenset[str] | set[str]) -> bool:
    """True when ``text`` carries the error itself, not merely its type."""
    text = text[:MAX_SCAN_CHARS]
    return any(not _type_only(text, m) for name in names for m in _name_re(name).finditer(text))


def _interpolates(raw: str, names: frozenset[str] | set[str]) -> bool:
    """`f"...{exc}"` / `${err}`: the error sits in a template hole the stripper blanked."""
    return any(_interp_re(n).search(raw) for n in names)


def _statement_position(code: str, at: int) -> bool:
    """The call's value is not consumed by an enclosing expression."""
    prefix = code[max(0, at - _LOOK_BEHIND):at].rstrip()
    if not prefix or prefix.endswith(_STMT_END_TOKENS):
        return True
    return prefix.rsplit(None, 1)[-1] in _STMT_END_WORDS


def _depth_delta(code: str) -> int:
    return sum(_BRACKET_DELTA[b] for b in _BRACKET.findall(code))


def _join_statements(lines: list[str]) -> list[tuple[str, str]]:
    """Physical lines joined into (code, raw) statements by bracket depth: O(body)."""
    out: list[tuple[str, str]] = []
    code_acc, raw_acc, depth = "", "", 0
    for raw in lines:
        code = stripped_code(raw)  # lines arrive capped
        code_acc, raw_acc = f"{code_acc} {code.strip()}", f"{raw_acc} {raw.strip()}"
        depth += _depth_delta(code)
        if depth <= 0:
            out.append((code_acc.strip(), raw_acc))
            code_acc, raw_acc, depth = "", "", 0
    if code_acc.strip():
        out.append((code_acc.strip(), raw_acc))
    return out


def _is_braced_block(code: str) -> bool:
    return code.startswith("{") and ";" in code


def _split_braced(code: str, raw: str) -> list[tuple[str, str]]:
    """Allman: a joined statement that STARTS with `{` holds several statements."""
    if not _is_braced_block(code):
        return [(code, raw)]
    return [(part, raw) for part in filter(None, (p.strip(" {}") for p in code.split(";")))]


def _statements(header_tail: str, body: list[str]) -> list[tuple[str, str]]:
    """The handler's statements, each body line and each statement capped first.

    A lone `{` line (Allman) opens nothing to join, so it is dropped before joining
    (the Allman and K&R twins of one handler must agree).
    """
    lines = [header_tail[:MAX_SCAN_CHARS], *_body_lines(body)]
    return [_capped(pair) for code, raw in _join_statements(lines) for pair in _split_braced(code, raw)]


def _body_lines(body: list[str]) -> list[str]:
    return [b[:MAX_SCAN_CHARS] for b in body if stripped_code(b).strip() != "{"]


def _capped(pair: tuple[str, str]) -> tuple[str, str]:
    return pair[0][:MAX_SCAN_CHARS], pair[1][:MAX_SCAN_CHARS]


def _chain_follows(expr: str, m: re.Match[str]) -> bool:
    if m.group(0) != ")":
        return False
    nxt = _NEXT_NONSPACE.search(expr, m.end())
    return nxt is not None and nxt.group(0) == "."


def _is_call_chain(expr: str) -> bool:
    """`a.b(..).c(..)`: a call's RESULT is itself called, at bracket depth 0."""
    expr, depth = expr[:MAX_SCAN_CHARS], 0
    for m in _BRACKET.finditer(expr):
        depth += _BRACKET_DELTA[m.group(0)]
        if depth == 0 and _chain_follows(expr, m):
            return True
    return False


def _args_flag_failure(args: str) -> bool:
    """An argument is a failure SEVERITY constant: `Kind.ERROR`, `Status.FAILED`.

    Only the constant's own (final) name counts. `Catalog.BAD_REQUEST` names a
    catalog that merely contains errors, and passing it is how a response is
    written, which is not a hand-off.
    """
    return any(
        _FAILURE_WORDS.intersection(_verb_words(m.group(1)))
        for m in _SEVERITY_ARG.finditer(_OBJECT_KEY.sub(" ", args))
    )


def _names_failure(words: tuple[str, ...], args: str) -> bool:
    """A failure-named routine (`onReloadFailure`), or a failure severity argument."""
    return bool(_FAILURE_WORDS.intersection(words)) or _args_flag_failure(args)


def _callee_excluded(words: tuple[str, ...]) -> bool:
    return not words or words[0] in _NOT_A_SINK_FIRST_WORDS


def _callee_is_sink(words: tuple[str, ...], args: str, names: frozenset[str]) -> bool:
    """The callee keeps the failure: failure-named, or a collect/report verb given the error."""
    if _callee_excluded(words):
        return False
    if _names_failure(words, args):
        return True
    return words[0] in _HANDOFF_VERBS and _mentions_evidence(args, names)


def _is_statement_call(code: str, m: re.Match[str]) -> bool:
    return not m.group(1) and _statement_position(code, m.start())


def _callee_hands_on(code: str, m: re.Match[str], names: frozenset[str], ctx: "_HandlerContext") -> bool:
    """One statement-position call keeps the failure.

    Callback forwarding is decided by DATA FLOW: the error passed to a call whose
    callee is a PARAMETER of the enclosing routine (`cb(err)`, `done(err)`,
    `reject(e)`), never by a list of callback names.
    """
    args = call_argument_text(code, m.end() - 1, _ARG_SPAN)
    if _mentions_evidence(args, names) and m.group(2).lstrip("$") in ctx.params:
        return True
    return _callee_is_sink(_tail_verb_words(m.group(2)), args, names)


def _call_hands_on(code: str, names: frozenset[str], ctx: "_HandlerContext") -> bool:
    """``ctx.params`` is read only when the error reaches a call's arguments (lazy)."""
    return any(
        _callee_hands_on(code, m, names, ctx)
        for m in _CALLEE.finditer(code) if _is_statement_call(code, m)
    )


def _return_rhs(code: str) -> str | None:
    """The text after the FIRST `return`, by search plus slice."""
    m = _RETURN_KW.search(code[:MAX_SCAN_CHARS])
    return None if m is None else code[m.end():MAX_SCAN_CHARS]


class _HandlerContext:
    """The handler's window. Each part is computed on first use: most handlers hand
    nothing on and never need the prior names or parameters (cold-start cost).

    ``openers``: enclosing opener lines, innermost first, capped. ``prior``: names
    assigned (or parameters) before the try. ``params``: parameters of the routine.
    Tests may pass any part ready-made.
    """

    def __init__(self, lines: tuple[str, ...] = (), start: int = 0, *, openers=None, prior=None, params=None):
        self._lines, self.start = lines, start
        self._given = {"openers": openers, "prior": prior, "params": params}

    def _part(self, name: str, compute):
        given = self._given[name]
        return given if given is not None else compute()

    @cached_property
    def _indices(self) -> tuple[int, ...]:
        return _opener_indices(self._lines, self.start)

    @cached_property
    def _routine(self) -> int:
        return _routine_line(self._lines, self._indices)

    @cached_property
    def openers(self) -> tuple[str, ...]:
        return self._part("openers", lambda: tuple(self._lines[i][:MAX_SCAN_CHARS] for i in self._indices))

    @cached_property
    def prior(self) -> frozenset[str]:
        return self._part("prior", lambda: _names_before_try(self._lines, self._routine, self.start))

    @cached_property
    def params(self) -> frozenset[str]:
        return self._part("params", lambda: _routine_params(self._lines, self._routine))


def _return_hands_on(rhs: str, raw: str, names: frozenset[str], ctx: _HandlerContext) -> bool:
    rhs = rhs.strip()
    if _is_call_chain(rhs):
        # `return res.status(500).json(err)`: a fluent write whose value is returned
        # only to end the routine. Judged as the call it is.
        return _call_hands_on(rhs, names, ctx)
    return _mentions_evidence(rhs, names) or _interpolates(raw, names)


def _plain_assignment(code: str) -> re.Match[str] | None:
    asg = _ASSIGN.match(code)
    return asg if asg and not asg.group("decl") else None


def _assign_hands_on(asg: re.Match[str], raw: str, names: frozenset[str], prior: frozenset[str]) -> bool:
    """Store by data flow: a field target, or a name that existed before the try.

    A fresh local that nothing reads is not a hand-off, in any language, so the
    Python `detail = str(exc)` and the TS `const detail = String(exc)` twins agree.
    """
    lhs = asg.group("lhs")
    if not (_FIELD_LHS.search(lhs) or lhs in prior):
        return False
    return _mentions_evidence(asg.group("rhs"), names) or _interpolates(raw, names)


def _append_hands_on(code: str, names: frozenset[str]) -> bool:
    """`errors << e`: appended to a collection."""
    app = _APPEND_OP.search(code)
    return app is not None and _mentions_evidence(code[app.end():], names)


def _line_hands_on(code: str, raw: str, names: frozenset[str], ctx: _HandlerContext) -> bool:
    """One statement hands the failure on: returned, stored, appended, or sent to a sink."""
    rhs = _return_rhs(code)
    if rhs is not None:
        return _return_hands_on(rhs, raw, names, ctx)
    asg = _plain_assignment(code)
    if asg is not None:
        return _assign_hands_on(asg, raw, names, ctx.prior)
    return _append_hands_on(code, names) or _call_hands_on(code, names, ctx)


def _alias(code: str, names: frozenset[str]) -> str | None:
    """`const msg = err.message`: a declared local that now carries the error."""
    asg = _ASSIGN.match(code)
    if asg and asg.group("decl") and _mentions_evidence(asg.group("rhs"), names):
        return asg.group("lhs")
    return None


def _handler_hands_on(header_tail: str, body: list[str], names: frozenset[str], ctx: _HandlerContext) -> bool:
    for code, raw in _statements(header_tail, body):
        alias = _alias(code, names)
        if alias is not None:
            names = names | {alias}
        elif _line_hands_on(code, raw, names, ctx):
            return True
    return False


# ---- the window: try opener, enclosing openers, prior names, parameters ----
_TRY_CACHE: dict = {}
_CONTEXT_CACHE: dict = {}


def _memo(cache: dict, lines: tuple[str, ...], key: int, compute):
    """Per-file memo keyed by (id(lines), key), with an identity check on ``lines``."""
    hit = cache.get((id(lines), key))
    if hit is None or hit[0] is not lines:
        if len(cache) > _MEMO_MAX:
            cache.clear()
        hit = (lines, compute())
        cache[(id(lines), key)] = hit
    return hit[1]


def _opens_try(s: str, rescue: bool) -> bool:
    code = stripped_code(s)
    return bool(_TRY_OPEN.search(code)) or (rescue and bool(_RUBY_DEF.match(code)))


def _try_step(s: str, base: int, rescue: bool) -> bool | None:
    """None: this line opens the try. True: keep walking. False: the walk left the block."""
    ind = indent_width(s) if s.strip() else base + 1
    if ind != base:
        return ind > base
    return None if _opens_try(s, rescue) else True


def _scan_try_start(lines: tuple[str, ...], i0: int) -> int:
    base, rescue = indent_width(lines[i0]), lines[i0].lstrip().startswith("rescue")
    for i in range(i0 - 1, max(-1, i0 - _TRY_LOOKBACK), -1):
        step = _try_step(lines[i], base, rescue)
        if step is None:
            return i
        if not step:
            return -1
    return -1


def _try_start(lines: tuple[str, ...], i0: int) -> int:
    """Index of the handler's try opener, or -1 when unresolved within 80 lines.

    `try`/`begin`/`do` at the handler's indent; for a Ruby method-level `rescue`,
    the `def` at its indent. Unresolved is reported, never excused (a
    security call 86 lines above its catch was once read as non-security).
    """
    return _memo(_TRY_CACHE, lines, i0, lambda: _scan_try_start(lines, i0))


# A call statement whose arguments open an anonymous callback
# (`await withLock(id, async () => {`, `queue.run(function () {`, Java
# `submit(() -> {`) has the shape of a member signature but declares nothing
# (declaration syntax only). It is an enclosing opener, and the walk
# continues to the routine above. The arrow must END the line (a block or
# an expression body follows): an arrow inside a parameter TYPE,
# `render(onDone: (r: Row) => void) {`, is followed by more of the signature, so
# that method stays a declaration. The callee may be a PHP member or
# static chain (`$this->db->transaction(function () {`, `Db::transaction(`).
_CALLBACK_CALL = re.compile(
    r"^\s{0,80}(?:await\s{1,4}|return\s{1,4})?(?:[\w$.]|->|::){1,120}\s{0,4}\([^\n]{0,300}?"
    r"(?:(?:=>|->)\s{0,4}[{(]?\s{0,4}$|\bfunction\b[^(]{0,60}\()"
)
# `name(...) {` with nothing before the name -- no routine keyword, modifier or
# return type -- is either a block statement inside a routine (`synchronized (lock) {`,
# `lock (_sync)`, `using (...)`, `withContext(...) {`, Ruby `with_lock(id) {`) or a
# method of a class or object literal whose language writes none (`repaint(cb) {`).
# The walk keeps going: a keyword, modifier or typed declaration above it is the
# routine; a type or object-literal opener above it makes it the routine.
_BARE_CALL_OPENER = re.compile(r"^\s{0,80}[A-Za-z_$][\w$]{0,60}\s{0,4}\(")
_TYPE_CONTAINER = re.compile(
    r"\b(?:class|struct|object|interface|trait|impl|enum|record|module|namespace|extension"
    r"|protocol|actor)\b|[=:(,]\s{0,4}\{?\s{0,4}$|^\s{0,80}(?:export\s{1,4})?default\s{0,4}\{"
)


@lru_cache(maxsize=16384)
def _is_decl_line(line: str) -> bool:
    """A routine declaration line, never a call that takes a callback."""
    return routine_header(line) and not _CALLBACK_CALL.match(stripped_code(line))


def _is_opener(s: str, floor: int, in_sig: bool) -> bool:
    ind = indent_width(s)
    return bool(s.strip()) and (ind < floor or (in_sig and ind <= floor))


def _opener_and_header(lines: tuple[str, ...], i: int) -> tuple[int, ...]:
    """An Allman `{` alone on its line (a comment may follow) was opened by the code
    line above it, which may sit at the same indent: both are openers."""
    if stripped_code(lines[i]).strip() != "{":
        return (i,)
    above = _prev_code_index(lines, i + 1)
    return (i,) if above < 0 else (i, above)


def _opener_steps(lines: tuple[str, ...], start: int):
    """Enclosing opener lines, nearest first: strictly decreasing indent, following
    a multi-line `})` signature and an Allman brace's header, within 300 lines."""
    floor, in_sig, below = indent_width(lines[start]), False, start
    for i in range(start - 1, max(-1, start - _ROUTINE_LOOKBACK), -1):
        if i >= below or not _is_opener(lines[i], floor, in_sig):
            continue
        found = _opener_and_header(lines, i)
        yield from found
        below = found[-1]
        floor, in_sig = indent_width(lines[below]), lines[below].lstrip().startswith(_SIGNATURE_CONTINUATION)


def _opener_kind(line: str, bare_pending: bool) -> str:
    if _is_decl_line(line):
        return "bare" if _BARE_CALL_OPENER.match(stripped_code(line)) else "decl"
    return "container" if _ends_bare_walk(line, bare_pending) else "other"


def _ends_bare_walk(line: str, bare_pending: bool) -> bool:
    return bare_pending and _TYPE_CONTAINER.search(stripped_code(line)) is not None


class _RoutineWalk:
    """Collects openers up to the routine. A keyword, modifier or typed declaration
    ends the walk. A bare `name(...) {` is remembered; if a type or object-literal
    opener, or the bound, comes before any such declaration, the walk ends at the
    first bare opener, which is the reading the shipped walk always gave it."""

    def __init__(self):
        self.out: list[int] = []
        self.bare, self.decl = -1, False

    def stops_at(self, i: int, line: str) -> bool:
        kind = _opener_kind(line, self.bare >= 0)
        if kind == "container":
            return True
        self.out.append(i)
        if kind == "bare" and self.bare < 0:
            self.bare = len(self.out) - 1
        self.decl = kind == "decl"
        return self.decl

    def result(self) -> tuple[int, ...]:
        if self.decl or self.bare < 0:
            return tuple(self.out)
        return tuple(self.out[:self.bare + 1])


def _opener_indices(lines: tuple[str, ...], start: int) -> tuple[int, ...]:
    """Enclosing opener lines, up to and including the routine declaration or 300 lines."""
    walk = _RoutineWalk()
    any(walk.stops_at(i, lines[i]) for i in _opener_steps(lines, start))
    return walk.result()


def _enclosing_openers(lines: tuple[str, ...], start: int) -> tuple[str, ...]:
    """Test oracle: the opener lines ``_opener_indices`` finds, as text."""
    return tuple(lines[i][:MAX_SCAN_CHARS] for i in _opener_indices(lines, start))


def _routine_line(lines: tuple[str, ...], openers: tuple[int, ...]) -> int:
    """Index of the routine declaration among the openers, or -1."""
    return openers[-1] if openers and _is_decl_line(lines[openers[-1]]) else -1


def _names_before_try(lines: tuple[str, ...], routine: int, start: int) -> frozenset[str]:
    """Names assigned from the routine start to the try, plus every identifier of
    the declaration line (its parameters)."""
    if routine < 0:
        return frozenset()
    out = set(_IDENT_ANY.findall(stripped_code(lines[routine])))
    out.update(*map(_assigned_names, lines[routine:start + 1]))
    return frozenset(out)


@lru_cache(maxsize=16384)
def _assigned_names(line: str) -> frozenset[str]:
    return frozenset(m.group(1) for m in _PRIOR_ASSIGN.finditer(stripped_code(line)))


def _routine_params(lines: tuple[str, ...], routine: int) -> frozenset[str]:
    if routine < 0:
        return frozenset()
    parts = (p for group in paren_lists(stripped_code(lines[routine])) for p in group.split(","))
    return frozenset(filter(None, map(param_name, parts)))


class _LazyContext:
    """Resolves the try opener only when a strategy first reads the window: most
    handlers hand nothing on, so they never pay for the walk (cold-start cost).
    An unresolved window reads as no prior names and no parameters, and the
    handler is reported regardless."""

    def __init__(self, lines: tuple[str, ...], lineno: int):
        self._lines, self._lineno = lines, lineno

    @cached_property
    def window(self) -> "_HandlerContext | None":
        return _handler_context(self._lines, self._lineno)

    @property
    def prior(self) -> frozenset[str]:
        return self.window.prior if self.window is not None else frozenset()

    @property
    def params(self) -> frozenset[str]:
        return self.window.params if self.window is not None else frozenset()


def _handler_context(lines: tuple[str, ...], lineno: int) -> _HandlerContext | None:
    """The memoised window of the handler at 1-based ``lineno``; None when unresolved."""
    start = _try_start(lines, lineno - 1)
    if start < 0:
        return None
    return _memo(_CONTEXT_CACHE, lines, start, lambda: _HandlerContext(lines, start))


# ---- the security gate: concept roots over identifier words ----
# Prefix roots (a word STARTING with one), the infix `crypt` (bcrypt, decrypt,
# crypto), exact words, and key compounds (`findByApiKey` -> api+key). Measured:
# `hash` as a prefix matched content hashes (`blobHash`, `recordHash`), so it is
# exact-only; `publicKey` is not a key compound. Over-matching is a precision cost,
# never a recall loss (`tokenizer` matches by design).
_SECURITY_PREFIXES = (
    "auth", "login", "logout", "signin", "signup", "passw", "credential", "secret", "token",
    "apikey", "session", "cookie", "jwt", "jws", "jwk", "jwe", "oauth", "oidc", "saml",
    "permission", "privilege", "role", "grant", "revok", "cipher", "decipher", "hmac",
    "signature", "sign", "verif", "validat", "sanitiz", "escape", "admin", "sudo", "chmod",
    "chown", "umask", "cert", "x509", "keystore", "truststore", "trust", "csrf", "xsrf",
    "audit", "firewall", "allowlist", "denylist", "blocklist", "polic", "enforc", "entitl",
    "access", "allow", "totp", "nonce", "digest", "protect", "pbkdf", "scrypt", "argon",
    "impersonat", "consent", "captcha", "hashpass", "passwordhash",
    # Credential and directory/keystore roots: a PIN check, an LDAP bind,
    # a keychain read, a biometric unlock, a Kerberos ticket, a bearer header.
    "passphrase", "ldap", "bearer", "keychain", "biometric", "kerberos",
    # Privilege change, credential stores, remote login, secret release,
    # sandboxing, device attestation, lockout and rate limiting.
    # Measured one root at a time: zero row change on the reference trees.
    "setuid", "setgid", "seteuid", "setegid", "setresuid", "setresgid", "setreuid", "setregid",
    "setgroups", "initgroups", "keyring", "userauth", "unseal", "seccomp", "sandbox",
    "webauthn", "fido", "pkcs", "lockout", "ratelimit",
)
_SECURITY_EXACT = frozenset({
    "acl", "sso", "otp", "mfa", "2fa", "kms", "mac", "tls", "ssl", "root", "cors", "origin",
    "referer", "scope", "scopes", "seal", "authn", "authz", "hash", "hashed", "hashing", "rehash",
    # Symmetric cipher primitives (`AES.GCM.open(box, using: key)` names no other root).
    # Measured: zero row change on the reference trees.
    "aes", "gcm", "chacha20",
    # Credential abbreviations, exact words only: `pin` as a prefix would match
    # `pinned`/`pinch`, `sig` would match `sigma`.
    "pin", "pw", "pwd", "sig",
    # Exact only: `ssh` as a prefix would match `sshare`, `unlock` would match
    # `unlocked` counters; `pinning` (certificate pinning) is not `pinned`.
    "ssh", "unlock", "pinning", "limiter",
})
# Adjacent identifier-word pairs naming a constant-time comparison, a primitive
# that exists only to compare secrets (`timingSafeEqual`, `constantTimeCompare`).
_SECURITY_PAIRS = frozenset({
    ("timing", "safe"), ("constant", "time"),
    # The keychain primitive (`SecItemCopyMatching`), a secure credential store, a rate limit.
    ("sec", "item"), ("secure", "store"), ("rate", "limit"),
})
_SECURITY_INFIXES = ("crypt",)
_KEY_QUALIFIERS = frozenset({
    "api", "signing", "private", "secret", "master", "encryption", "sign", "access", "session",
    "hmac", "jwt",
})
# An ARGUMENT or receiver counts only through the narrower credential roots: a
# `user` or `doc` argument says nothing about the operation.
_CREDENTIAL_PREFIXES = (
    "token", "passw", "credential", "secret", "signature", "jwt", "jws", "otp", "totp", "mfa",
    "cert", "apikey", "session", "nonce", "csrf", "cookie",
)
_CREDENTIAL_EXACT = frozenset({"otp", "mfa", "2fa", "pin", "pw", "pwd", "passphrase", "bearer"})
_OBJECT_KEY_ANY = re.compile(r"(?<![\w$])[\w$]{1,60}\s{0,4}\??:(?!:)")
_CALLEE_PATH = re.compile(
    r"(?<![\w$])((?:[A-Za-z_$][\w$]{0,60}\s{0,2}(?:\?\.|\.|::|->)\s{0,2}){0,8}[A-Za-z_$][\w$]{0,60})"
    r"\s{0,4}(?:<[^<>()]{0,80}>)?\s{0,2}\("
)


def _word_is_security(w: str) -> bool:
    return w in _SECURITY_EXACT or w.startswith(_SECURITY_PREFIXES) or any(x in w for x in _SECURITY_INFIXES)


def _has_key_compound(words: tuple[str, ...]) -> bool:
    return any(a in _KEY_QUALIFIERS and b in ("key", "keys") for a, b in zip(words, words[1:]))


def _has_security_pair(words: tuple[str, ...]) -> bool:
    return any(pair in _SECURITY_PAIRS for pair in zip(words, words[1:]))


def guards_security_operation(words: tuple[str, ...]) -> bool:
    """True when identifier ``words`` name a security operation (one vocabulary,
    shared by the hand-off gate, the promise gate and the SECURITY_SCOPE arm)."""
    return any(map(_word_is_security, words)) or _has_key_compound(words) or _has_security_pair(words)


def _word_is_credential(w: str) -> bool:
    return w.startswith(_CREDENTIAL_PREFIXES) or w in _CREDENTIAL_EXACT


def _names_credential(ident: str) -> bool:
    words = identifier_words(ident)
    return any(map(_word_is_credential, words)) or _has_key_compound(words)


def _callee_is_security(m: re.Match[str]) -> bool:
    return any(guards_security_operation(identifier_words(i)) for i in _IDENT_ANY.findall(m.group(1)))


@lru_cache(maxsize=16384)
def _text_is_security(code: str) -> bool:
    """Every segment of every callee path, plus non-key argument/receiver identifiers
    through the credential roots (object keys excluded: `{ addressVerified: true }`)."""
    code = code[:MAX_SCAN_CHARS]
    if any(map(_callee_is_security, _CALLEE_PATH.finditer(code))):
        return True
    return any(map(_names_credential, _IDENT_ANY.findall(_OBJECT_KEY_ANY.sub(" ", code))))


@lru_cache(maxsize=16384)
def _line_is_security(line: str) -> bool:
    code = stripped_code(line)
    return _text_is_security(code) or bool(_SECURITY_SIGNAL_RE.search(code))


def _window_is_security(lines: tuple[str, ...], lineno: int, header: str,
                        ctx: _HandlerContext | None) -> bool:
    """The guarded text -- try body, every enclosing opener, and the handler header
    (its exception TYPE: `BadSignature`, `JWT::DecodeError`) -- names a security
    operation. True when the window is unresolved (report)."""
    if ctx is None or _text_is_security(stripped_code(header)):
        return True
    guarded = (*lines[ctx.start:lineno], *ctx.openers)
    return any(_line_is_security(s[:MAX_SCAN_CHARS]) for s in guarded)


def _handler_excused(header: str, header_tail: str, body: list[str],
                     lines: tuple[str, ...], lineno: int, suffix: str) -> bool:
    """The shipped excusals (log, propagate, delegate), then 0101 Concept A."""
    return _handler_is_excused(body, inline=header_tail) or _excused_as_handed_on(
        header, header_tail, body, lines, lineno, suffix)


def _excused_as_handed_on(header: str, header_tail: str, body: list[str],
                          lines: tuple[str, ...], lineno: int, suffix: str = "") -> bool:
    """0101 Concept A: the handler hands its failure on, outside the security surface."""
    lazy = _LazyContext(lines, lineno)
    if not _handler_hands_on(header_tail, body, _evidence_names(catch_binding(header, suffix)), lazy):
        return False
    ctx = lazy.window
    return ctx is not None and not _window_is_security(lines, lineno, header, ctx)


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
    if _handler_excused(line, "", body, lines, lineno, ".py"):
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
    if _handler_excused(line, line[match.end():], body, lines, lineno, Path(file_path).suffix.lower()):
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
        if _body_has_logging([line]) or _delegates_or_best_effort([line], line, lines, lineno, is_proc):
            return
    else:
        body = collect_scoped_body(lines, lineno, brace_family=True)
        scope = [line, *body]
        if _body_has_logging(scope) or _body_propagates(scope) or _delegates_or_best_effort(
            scope, line, lines, lineno, is_proc
        ):
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
# 0101 Concept C -- a promise swallow that is best effort by design.
#
# `.catch(() => <nothing>)` after a TEARDOWN call (`stale.disconnect()`), or whose
# fallback the code null-checks (`const p = await r.json().catch(() => null)` then
# `p?.code`), records nothing because nothing needs recording. Excused only when
# the chain head is not a security operation: `verifyJwt(t).catch(() => null)`
# followed by a 401, and `session.destroy().catch(() => {})` on logout, stay
# reported. The teardown must be the LAST call before `.catch`:
# `revokeToken(t).then(() => session.destroy()).catch(...)` and
# `....finally(() => db.close()).catch(...)` stay reported.
# ---------------------------------------------------------------------------
_TEARDOWN_VERBS = frozenset({
    "close", "disconnect", "destroy", "dispose", "cleanup", "release", "unsubscribe",
    "abort", "cancel", "stop", "terminate", "shutdown", "quit", "unref", "detach",
})
_ASSIGNED_CATCH = re.compile(r"(?:^|[^=!<>])=\s{0,4}(?:await\s{1,4})?[^=;]{0,200}\.catch\s{0,4}\(")
_ASSIGNED_NAME = re.compile(
    r"^\s{0,80}(?:(?:const|let|var|val)\s{1,4})?([A-Za-z_$][\w$]{0,60})\s{0,4}(?::[^=]{0,120})?=(?![=>])"
)
# `(await x.catch(() => null)) ?? DEFAULTS`: the fallback is replaced on the same line.
_SAME_LINE_FALLBACK = re.compile(r"\)\s{0,4}(?:\)\s{0,4})?(?:\?\?|\|\|)")
_NULL_GUARD_LINES = 3
_CHAIN_LOOKBACK = 6


def _chain_head(code: str) -> str:
    return code[:MAX_SCAN_CHARS].split(".catch", 1)[0]


def _last_callee_words(head: str) -> tuple[str, ...]:
    last = None
    for last in _CALLEE.finditer(head):
        pass
    return _tail_verb_words(last.group(2)) if last else ()


def _chain_prefix(lines: tuple[str, ...], lineno: int) -> list[str]:
    """The earlier lines of a chain the site line continues, at most 6: a `.then(...)`
    on its own line, and the lines of a call whose arguments break over
    lines, `revokeAllTokens(` / `userId,` / `).catch(...)`. The walk
    goes back while the text read so far closes more brackets than it opens, or
    starts with `.`."""
    out, cur = [], stripped_code(lines[lineno - 1]).lstrip()
    depth = _depth_delta(_chain_head(cur))
    for i in range(lineno - 2, max(-1, lineno - 2 - _CHAIN_LOOKBACK), -1):
        if depth >= 0 and not cur.startswith("."):
            break
        cur = stripped_code(lines[i]).lstrip()
        depth += _depth_delta(cur)
        out.append(cur)
    return out[::-1]


def _chain_head_text(code: str, lines: tuple[str, ...], lineno: int) -> str:
    """The text before `.catch`, read across `.`-continuation line breaks."""
    return " ".join((*_chain_prefix(lines, lineno), _chain_head(code)))


def _chain_is_security(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    return _text_is_security(_chain_head_text(code, lines, lineno)[-MAX_SCAN_CHARS:])


# Read on the REVERSED text before a `(`, so the match is anchored at its start:
# a `...$`-anchored search would retry 61 characters at every position. `\A`
# keeps an unanchored search (the 0087 ReDoS gate) from trying the leading
# whitespace run at every position of a 512 KB line.
_REVERSED_NAME = re.compile(r"\A\s{0,4}([\w$]{1,61})")


def _last_call(head: str) -> tuple[str, str] | None:
    """(callee name, argument text) of the call that ENDS the chain head: the last
    depth-0 segment, `.then(() => db.close())` in `load().then(() => db.close())`."""
    head = head.rstrip()
    open_at = opening_bracket(head) if head.endswith(")") else -1
    name = _name_before(head, open_at) if open_at > 0 else ""
    if not name:
        return None
    return name, call_argument_text(head, open_at, _ARG_SPAN)


def _name_before(text: str, at: int) -> str:
    """The identifier that ends just before ``text[at]`` (spaces allowed), or ""."""
    m = _REVERSED_NAME.match(text[max(0, at - 80):at][::-1])
    name = m.group(1)[::-1] if m else ""
    return "" if name[:1].isdigit() else name


def _ends_in_teardown(head: str) -> bool:
    """The last call is a teardown verb, or a `.then(...)` whose callback's last call
    is one (`x.then(l => l.close())`). `.finally(() => db.close())`, or a teardown
    followed by `.then(render)`, does not count."""
    call = _last_call(head)
    if call is None:
        return False
    words = _last_callee_words(call[1]) if call[0] == "then" else _verb_words(call[0])
    return bool(words) and words[0] in _TEARDOWN_VERBS


def _chain_tears_down(code: str) -> bool:
    """The LAST call before `.catch` is a teardown verb, on a non-security chain."""
    head = _chain_head(code)
    return not _text_is_security(head) and _ends_in_teardown(head)


@lru_cache(maxsize=256)
def _null_guard_re(name: str) -> re.Pattern[str]:
    name = re.escape(name)
    return re.compile(
        r"(?<![\w$])" + name + r"\s{0,2}(?:\?\.|\?\?|[!=]==?\s{0,2}(?:null|undefined))"
        r"|(?:\bif\s{0,4}\(\s{0,4}!?\s{0,2}|\btypeof\s{1,4})" + name + r"(?![\w$])"
    )


def _assigned_and_guarded(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    """The `.catch` result is assigned and null-guarded within the next 3 lines."""
    m = _ASSIGNED_NAME.search(code) if _ASSIGNED_CATCH.search(code) else None
    if m is None:
        return False
    guard = _null_guard_re(m.group(1))
    return any(guard.search(stripped_code(s)) for s in lines[lineno:lineno + _NULL_GUARD_LINES])


def _fallback_is_null_checked(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    """The swallowed rejection's fallback value is checked, on this line or the next 3."""
    head = _chain_head(code)
    if _text_is_security(head):
        return False
    if _SAME_LINE_FALLBACK.search(code[:MAX_SCAN_CHARS], len(head)):
        return True
    return _assigned_and_guarded(code[:MAX_SCAN_CHARS], lines, lineno)


def _delegates_or_best_effort(scope: list[str], line: str, lines: tuple[str, ...], lineno: int,
                              is_proc: bool) -> bool:
    """The shipped delegation excusal, then 0101 Concept C."""
    return _body_delegates(scope) or _promise_swallow_excused(line, lines, lineno, is_proc)


def _promise_swallow_excused(line: str, lines: tuple[str, ...], lineno: int, is_proc: bool) -> bool:
    """0101 Concept C, never on a security chain. The last-resort `process.on(...)`
    handler is never excused."""
    if is_proc or _chain_is_security(line, lines, lineno):
        return False
    return _chain_tears_down(line) or _fallback_is_null_checked(line, lines, lineno)


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


def _logs_or_forwards(scope: list[str]) -> bool:
    return _body_has_logging(scope) or _body_propagates(scope) or _body_delegates(scope)


def _shape_excused(check: str, line: str, scope: list[str], lines: tuple[str, ...], lineno: int,
                   suffix: str) -> bool:
    """The shipped excusals, then 0101 Concept A for shapes that have a block body."""
    if _logs_or_forwards(scope):
        return True
    return check not in _EXPRESSION_SHAPES and _excused_as_handed_on(line, "", scope[1:], lines, lineno, suffix)


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
        if _shape_excused(check, line, scope, lines, lineno, suffix):
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
    if not _auth_candidate(line):
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
    if _auth_line_excused(line, lines, lineno):
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
# 0101 Concept B -- a keyword that NAMES an outcome is not an authorization decision.
#
# Measured on one real target: 45 auth_decision rows were error-code enums, i18n
# key maps, error catalogs and regexes classifying failure reasons -- lines where
# "unauthorized"/"forbidden" is the name being DEFINED. A matched line is skipped
# only when its keyword is that name (a declaration's left-hand side, an enum
# member, a `when` mapping, a pattern branch, a type query, a declaration's
# parameter, a bare case label, an element of an open list); a value being decided
# or answered is still reported. Runs OUTSIDE the AUTH_STRIP branch, so
# `VULTURE_CWE778_AUTH_STRIP=false` keeps its 0087 meaning exactly.
# ---------------------------------------------------------------------------
_DECL_PREFIX = re.compile(
    r"^\s{0,80}(?:(?:export|const|val|var|let|static|readonly|final|public|private|protected"
    r"|internal|declare|def|lazy|override)\s{1,4}){1,5}$"
)
_CASE_ARM = re.compile(r"^\s{0,80}case\b[^:=]{0,200}?(?::(?!:)|=>)(?P<rest>.{0,2000})$")
_BOOLISH = re.compile(r"[!<>]|&&|\|\||===?|!==?")
_BOOL_VALUE = re.compile(
    r"^\s{0,8}(?:!(?!=)|not\b)|&&|\|\||[=!]==?|[<>]=|\s[<>]\s|\b(?:and|or|not|instanceof|is)\b"
)
# A `when` mapping has a LITERAL left-hand side (a number or a string literal,
# optionally a comma list): `401 -> Reason.UNAUTHORIZED`. `user.banned ->`,
# `Role.GUEST ->`, `else ->` and `default ->` decide the outcome.
# Literals arrive blanked by the stripper (`"denied"` reads as `""`).
_WHEN_LITERAL = r"(?:-?\d[\w.]{0,20}|\"\"|'')"
_WHEN_BRANCH = re.compile(r"^\s{0,80}" + _WHEN_LITERAL + r"(?:\s{0,4},\s{0,4}" + _WHEN_LITERAL + r"){0,10}\s{0,4}->")
_COLLECTION_ELEMENT = re.compile(
    r"^\s{0,80}(?:\.\.\.)?[A-Za-z_$][\w$]{0,60}(?:\.[A-Za-z_$][\w$]{0,60}){0,6}\s{0,4},?\s{0,4}$"
)
_KEY_VALUE = re.compile(r"\s{0,4}\??:(?!:)(?P<v>.{0,2000})")
_CONST_ASSIGN = re.compile(r"\s{0,4}=(?![=>])")
_ENUM_ARGS = re.compile(r"\s{0,4}\([^()]{0,120}\)\s{0,4},?\s{0,4}$")
_INLINE_ENUM = re.compile(r"\benum\b[^{]{0,120}\{")
_ENUM_WORD = re.compile(r"\benum\b")
_TYPE_QUERY = re.compile(r"\btypeof\s{1,4}[\w.]{0,120}$")
_CONTROL_IN_OPENER = re.compile(r"\b(?:if|while|return|throw)\b")
_BRANCH_ENDS = ("else", "=>", "=", "->", "?", ":")
_BRACKET_SCAN_LINES = 40
_BRACKET_SCAN_RAW = 4 * _BRACKET_SCAN_LINES
# A whole-line comment: `//`, `#` (not a `#[` attribute), `/*`, `*/`, or a
# block-comment body line (`* text`, `*` alone). `*p = 0;` is code and is not matched.
_COMMENT_ONLY = re.compile(r"^\s{0,80}(?://|#(?!\[)|/\*|\*/|\*(?:\s|$))")


def _is_alternation_branch(before: str, after: str) -> bool:
    """`|unauthorized|` in a pattern; `||` is an OPERATOR (`expired||forbidden` decides)."""
    return (before.endswith("|") and not before.endswith("||")) or (
        after.startswith("|") and not after.startswith("||"))


def _typed_non_decision(after: str) -> bool:
    """`forbidden?: boolean` / `UNAUTHORIZED: { code: 401 }`: a key whose value decides nothing."""
    km = _KEY_VALUE.match(after)
    return km is not None and not _BOOLISH.search(km.group("v").split("//")[0])


def _boolean_value(value: str) -> bool:
    """The assigned value decides something: `!x`, `not x`, `&&`, `||`, `and`, `or`,
    or a comparison. A generic `<T>` and an arrow `=>` are not comparisons."""
    return bool(_BOOL_VALUE.search(value.split("//")[0]))


def _assigned_constant(after: str, keyword: str, before: str) -> bool:
    """`FORBIDDEN = 403` / `const unauthorized = ERRORS.x`: a name bound to a value that
    is not a boolean expression (`const forbidden = !user.isAdmin`
    is the decision itself)."""
    m = _CONST_ASSIGN.match(after)
    if m is None or _boolean_value(after[m.end():]):
        return False
    return keyword.isupper() or bool(_DECL_PREFIX.match(before))


def _declares(after: str, keyword: str, before: str) -> bool:
    return _typed_non_decision(after) or _assigned_constant(after, keyword, before) or bool(_ENUM_ARGS.match(after))


def _is_declaration_lhs(before: str, after: str, keyword: str) -> bool:
    """The keyword follows only declaration prefixes and is the name being defined."""
    at_lhs = before.strip() == "" or bool(_DECL_PREFIX.match(before))
    return at_lhs and _declares(after, keyword, before)


@lru_cache(maxsize=_LINE_MEMO)
def _auth_matches(code: str) -> tuple[tuple[int, int, str], ...]:
    """(start, end, keyword) of every auth keyword on a stripped line, computed once:
    Concept B reads them three times per candidate line."""
    return tuple((m.start(), m.end(), m.group(0)) for m in _AUTH_DECISION.finditer(code))


def _auth_match_is_declaration(code: str, match: tuple[int, int, str]) -> bool:
    start, end, keyword = match
    before, after = code[:start], code[end:]
    return (_is_alternation_branch(before, after) or _is_declaration_lhs(before, after, keyword)
            or (bool(_WHEN_BRANCH.match(code)) and "->" in before))


# Runs of one bracket character; kinds match independently. The group that
# matched names the run: (kind, opens).
_BRACKET_RUN = re.compile(r"(\(+)|(\)+)|(\[+)|(\]+)|(\{+)|(\}+)")
_RUN_KIND = (None, ("(", True), ("(", False), ("[", True), ("[", False), ("{", True), ("{", False))


class _BracketTrack:
    """Forward bracket stacks, one per opener kind, over a run of lines of one file.

    The innermost bracket still open above a line is the most recent unmatched
    opener: per kind, brackets match the same way read forwards (a stack) as read
    backwards (a carried depth), so the top of each stack is what the backward
    walk would stop at. The run advances with the scan, so each line is read once
    per file instead of once per auth-candidate line below it (a file
    of auth-candidate lines re-read 40 lines of up to 2000 characters each).
    Stack entries are runs ``[line, first column, count]``, so a line of 2000
    identical brackets costs one entry, not 2000."""

    def __init__(self, lines: tuple[str, ...], start: int):
        self.lines, self.start, self.next = lines, start, start
        self.stacks: dict[str, list[list[int]]] = {"(": [], "[": [], "{": []}
        self.rank = [0]   # rank[k]: code lines in lines[start:start + k]

    def advance(self, upto: int) -> None:
        for i in range(self.next, upto):
            self._feed(i)
        self.next = max(self.next, upto)

    def _feed(self, i: int) -> None:
        is_code = _is_code_line(self.lines[i])
        self.rank.append(self.rank[-1] + is_code)
        if is_code and _may_leave_open(stripped_code(self.lines[i])):
            self._match(i, stripped_code(self.lines[i]))

    def _match(self, i: int, code: str) -> None:
        for m in _BRACKET_RUN.finditer(code):
            kind, opens = _RUN_KIND[m.lastindex]
            start, end = m.span()
            if opens:
                self.stacks[kind].append([i, start, end - start])
            else:
                _pop_runs(self.stacks[kind], end - start)

    def innermost(self, i: int) -> tuple[int, int, str] | None:
        """The unmatched opener nearest line ``i`` (state after ``lines[:i]``) as
        (line, column, bracket), within the window the backward walk reads."""
        top = max(self._tops(), default=None)
        return top if top is not None and self._in_window(top[0], i) else None

    def _tops(self):
        """(line, column, bracket) of each kind's innermost unmatched opener."""
        return ((s[-1][0], s[-1][1] + s[-1][2] - 1, kind) for kind, s in self.stacks.items() if s)

    def _in_window(self, at: int, i: int) -> bool:
        """At most 40 code lines above ``i``, within 160 raw lines."""
        code_lines = self.rank[i - self.start] - self.rank[at - self.start]
        return at >= i - _BRACKET_SCAN_RAW and code_lines <= _BRACKET_SCAN_LINES


_NOT_BRACKET = re.compile(r"[^()\[\]{}]+")
_NEST_PASSES = 4


def _may_leave_open(code: str) -> bool:
    """False when the line's brackets nest completely, so it leaves every stack as
    it found it: adjacent pairs are removed (C string operations, at most four
    passes) until nothing is left. A properly nested word is balanced per kind.
    Anything else, or deeper nesting, is read bracket by bracket."""
    rest = _NOT_BRACKET.sub("", code)
    for _ in range(_NEST_PASSES):
        if not rest:
            return False
        rest = rest.replace("()", "").replace("[]", "").replace("{}", "")
    return bool(rest)


def _pop_runs(stack: list[list[int]], n: int) -> None:
    """Close ``n`` openers, innermost first; closers beyond the stack match nothing."""
    while n and stack:
        take = min(n, stack[-1][2])
        stack[-1][2] -= take
        n -= take
        if not stack[-1][2]:
            stack.pop()


_TRACKS: dict = {}


def _bracket_track(lines: tuple[str, ...], i: int) -> _BracketTrack:
    """The file's track advanced to line ``i``. A query behind the run, or past a
    gap wider than the window, starts a new run at the window start, so a file
    with few candidates never pays for the lines between them."""
    lo = max(0, i - _BRACKET_SCAN_RAW)
    track = _TRACKS.get(id(lines))
    if not _track_reaches(track, lines, lo, i):
        if len(_TRACKS) > 64:
            _TRACKS.clear()
        track = _TRACKS[id(lines)] = _BracketTrack(lines, lo)
    track.advance(i)
    return track


def _track_reaches(track: _BracketTrack | None, lines: tuple[str, ...], lo: int, i: int) -> bool:
    """The run is this file's and can be advanced to ``i`` without a window-wide gap."""
    return track is not None and track.lines is lines and lo <= track.next <= i


def _code_lines_above(lines: tuple[str, ...], lineno: int):
    """Test oracle for ``_BracketTrack``: (index, code) of the non-blank,
    non-comment lines above 1-based ``lineno``, nearest first: at most 40 of them, within 160 raw lines. This is the window
    ``_BracketTrack._in_window`` answers for; a documented enum spends three
    comment lines per member, so comments must not spend the budget."""
    raw = range(lineno - 2, max(-1, lineno - 2 - _BRACKET_SCAN_RAW), -1)
    return islice(((i, stripped_code(lines[i])) for i in raw if _is_code_line(lines[i])), _BRACKET_SCAN_LINES)


def _is_code_line(line: str) -> bool:
    return not _COMMENT_ONLY.match(line) and bool(stripped_code(line).strip())


def _open_bracket_above(lines: tuple[str, ...], lineno: int) -> tuple[str | None, int, str]:
    """Innermost bracket still open just above 1-based ``lineno``, read within 40
    code lines (comment-only and blank lines skipped, 160 raw lines at most): the
    bracket, the index of its line, that line's code. A documented enum spends
    three comment lines per member, so comments do not spend the budget."""
    top = _bracket_track(lines, lineno - 1).innermost(lineno - 1)
    if top is None:
        return None, -1, ""
    return top[2], top[0], stripped_code(lines[top[0]])


def _prev_code_index(lines: tuple[str, ...], lineno: int) -> int:
    """Index of the nearest non-blank code line above 1-based ``lineno`` (bounded), or -1."""
    for i in range(lineno - 2, max(-1, lineno - 12), -1):
        if stripped_code(lines[i]).strip():
            return i
    return -1


def _prev_code(lines: tuple[str, ...], lineno: int) -> str:
    """The nearest non-blank code line above 1-based ``lineno`` (bounded)."""
    i = _prev_code_index(lines, lineno)
    return stripped_code(lines[i]).strip() if i >= 0 else ""


def _bracket_context(lines: tuple[str, ...], lineno: int) -> tuple[str | None, str]:
    """The open bracket above and the line that opened it. An Allman `{` alone on its
    line was opened by the line above it (`public enum Reason` / `{`)."""
    ch, at, opener = _open_bracket_above(lines, lineno)
    if ch == "{" and opener.strip() == "{":
        opener = _prev_code(lines, at + 1)
    return ch, opener


def _bracket_names_declaration(ch: str | None, opener: str) -> bool:
    """Inside an enum body, or inside the parameter list of a declaration."""
    if ch == "{":
        return bool(_ENUM_WORD.search(opener))
    return ch == "(" and _is_decl_line(opener) and not _CONTROL_IN_OPENER.search(opener)


def _auth_line_by_bracket(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    ch, opener = _bracket_context(lines, lineno)
    if _COLLECTION_ELEMENT.match(code):
        return ch in ("[", "{")       # a lone `a.b,` is an element of an open list, not a call argument
    if _bracket_names_declaration(ch, opener):
        return True
    return all(_auth_match_is_declaration(code, m) for m in _auth_matches(code))


def _auth_line_by_structure(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    if not code.strip() or not _auth_matches(code):
        return False
    arm = _CASE_ARM.match(code)
    if arm:
        return not arm.group("rest").strip()      # a bare label; an arm with a body is judged
    return _auth_line_by_bracket(code, lines, lineno)


def _is_branch_value(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    """Scala's lone `Forbidden` returned from an `else`: a value a branch decides."""
    return bool(_COLLECTION_ELEMENT.match(code)) and _prev_code(lines, lineno).endswith(_BRANCH_ENDS)


def _is_inline_enum_or_type_query(code: str) -> bool:
    # Each pattern starts with a literal word: a substring test first keeps the
    # regex off the lines that cannot match (case-sensitive, like the patterns).
    return ("enum" in code and _INLINE_ENUM.search(code) is not None) or _is_type_query(code)


def _is_type_query(code: str) -> bool:
    found = _auth_matches(code) if "typeof" in code else ()
    return bool(found) and _TYPE_QUERY.search(code[:found[0][0]]) is not None


def _auth_line_excused(line: str, lines: tuple[str, ...], lineno: int) -> bool:
    """0101 Concept B, then the shipped log-within-4-lines excusal."""
    return _auth_line_is_declaration(stripped_code(line), lines, lineno) or _has_log_within(lines, lineno, radius=4)


def _auth_line_is_declaration(code: str, lines: tuple[str, ...], lineno: int) -> bool:
    """True when every auth keyword on the (stripped) line NAMES an outcome."""
    code = code[:MAX_SCAN_CHARS]
    if _is_branch_value(code, lines, lineno):
        return False
    if _is_inline_enum_or_type_query(code):
        return True
    return _auth_line_by_structure(code, lines, lineno)


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
#
# 0101: the vocabulary is the hand-off gate's (`guards_security_operation`, roots
# over identifier words), so the two security tests cannot drift. Splitting on
# identifier words is what makes `auth_token` match both `auth` and `token`, and
# `uniqueAuthorIds` still splits to (unique, author, ids): `author` matches the
# `auth` root, an over-match that costs precision, never recall.
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
    return any(_scope_line_is_security(src[:MAX_SCAN_CHARS]) for src in lines[lo:lineno])


@lru_cache(maxsize=16384)
def _scope_line_is_security(src: str) -> bool:
    words = (identifier_words(ident) for ident in _IDENT_ANY.findall(src))
    return any(map(guards_security_operation, words)) or bool(_SECURITY_SIGNAL_RE.search(src))


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
# 0101: Concept A/B/C remove rows from the numerator, so the ratio is not
# comparable with an 0087.1 row of the same codebase.
_METRIC_VERSION = "0101.1"


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
