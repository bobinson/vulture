"""Error handling vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet
from shared.validate.language import detect_language

from cwe_agent.catalog import enrich_finding

# CWE-252: Unchecked return value
UNCHECKED_RETURN_GO = [
    re.compile(r"^\s*_\s*,\s*_\s*=\s*\w+"),  # Go: _, _ = func()
    re.compile(r"^\s*_\s*=\s*\w+\.\w+\("),  # Go: _ = obj.Method()
]
GO_ERR_ASSIGN = re.compile(r",\s*err\s*:?=\s*\w+")
GO_ERR_CHECK = re.compile(r"if\s+err\s*!=\s*nil")

# Broad exception handlers. Every shape here is a defect; the CWE id depends on
# whether the handler NAMES a generic type:
#
#   CWE-396 (Declaration of Catch for Generic Exception) — a generic type IS
#           named (`except Exception`, `catch (Throwable t)`).
#   CWE-755 — no type is declared at all (`except:`, `catch(...)`, `catch {`).
#             The two language-specific spellings live in gated arms below
#             (`_UNTYPED_CATCH_ARMS`); this list holds the ungated ones.
#
# That is the distinction in 396's own definition, and it leaves both ids with
# a shape of their own: a relabel that moved every declaration form onto 396
# would leave 755 with no reachable form, trading one id for another and
# detecting nothing new. `_broad_catch_spec` resolves ONE spec per line
# (396 XOR 755) — skill findings are not deduplicated against each other, so a
# line matching both sets would otherwise be reported twice.
BARE_EXCEPT_PATTERNS = [
    re.compile(r"^\s*except\s*:"),  # Python: bare except
    re.compile(r"^\s*except\s+Exception\s*(?:as\s+\w+\s*)?:"),  # Python: catch-all
    re.compile(r"^\s*except\s+BaseException\s*(?:as\s+\w+\s*)?:"),  # SystemExit etc.
    # Tuple form: except (Exception,) / except (X, BaseException, ...)
    re.compile(r"^\s*except\s+\([^)]*\b(?:Exception|BaseException)\b[^)]*\)\s*(?:as\s+\w+\s*)?:"),
    re.compile(r"catch\s*\(\s*Exception\s+\w+\s*\)"),  # Java: catch(Exception e)
    re.compile(r"catch\s*\(\s*Throwable\s+\w+\s*\)"),  # Java: catch(Throwable t)
]

# The subset of the above that declares a generic exception TYPE → CWE-396.
GENERIC_TYPED_CATCH_PATTERNS = [
    re.compile(r"^\s*except\s+(?:Exception|BaseException)\s*(?:as\s+\w+\s*)?:"),
    re.compile(
        r"^\s*except\s+\([^)]*\b(?:Exception|BaseException)\b[^)]*\)"
        r"\s*(?:as\s+\w+\s*)?:"
    ),
    # Java/C#: catch (Exception e) / catch (Throwable t) / catch (SystemException).
    # The trailing `\b` on the type name is what rejects
    # `catch (ExceptionInInitializerError e)`, which a `\w*` tail absorbs.
    re.compile(
        r"catch\s*\(\s*(?:System\.)?"
        r"(?:Exception|Throwable|RuntimeException|SystemException)\b\s*\w*\s*\)"
    ),
]

# Optional catch binding (`} catch {`), C# only.
#
# It is also valid JS/TS (ES2019+), and the review licensed the JS/TS half on a
# measurement of ONE such line. That measurement does not hold: `} catch {` is
# the idiomatic TypeScript spelling for "I do not need the error object" —
# measured 986 occurrences in a single TS codebase, and 1,390 rows across five
# repositories. At that volume the row is a style census, not a weakness
# report, so the JS/TS half is DROPPED and only C# (where the form is rare and
# usually a genuine swallow) is kept.
OPTIONAL_BINDING_CATCH = re.compile(r"(?:^|\})\s*catch\s*\{")
_OPTIONAL_BINDING_EXTENSIONS = frozenset({".cs"})

# `catch (...)` is C++ syntax and nothing else. Ungated, it matched the prose
# ``catch(...)`` inside a Python docstring — a measured false row. Language
# gates for the other BARE_EXCEPT_PATTERNS members are unnecessary: `except:`
# is Python-only and `catch (Exception e)` needs a Java/C#-shaped declaration.
_CXX_CATCH_ALL = re.compile(r"catch\s*\(\s*\.\.\.\s*\)")
_CXX_EXTENSIONS = frozenset({".c", ".h", ".cpp"})

# Untyped-handler arms: (patterns, extensions the arm is valid in — None = any).
_UNTYPED_CATCH_ARMS = (
    (tuple(BARE_EXCEPT_PATTERNS), None),
    ((_CXX_CATCH_ALL,), _CXX_EXTENSIONS),
    ((OPTIONAL_BINDING_CATCH,), _OPTIONAL_BINDING_EXTENSIONS),
)

# CWE-754: Improper check for unusual conditions (I/O without error check)
#
# The verb alone is not enough. A bare `(?:open|read|write|connect|send|recv)\(`
# matched any method with a similar name, and on a front-end codebase almost
# every hit was a false positive: `snackBarHelperService.open()`,
# `dialog.open()`, `res.send()`, and `socket.disconnect()` (which merely *ends*
# with "connect()"). In one sweep that was 81 identical-titled rows, and they
# were the only support for OWASP A10 — a category propped up entirely by noise.
#
# So match on the RECEIVER as well, and anchor the verb to the start of the
# method name so `disconnect` no longer reads as `connect`.
_IO_NAMESPACES = r"(?:os|fs|fsPromises|net|socket|sock|io|ioutil|shutil|subprocess)"

IO_WITHOUT_CHECK = [
    # Python builtin open(), optionally chained: open(p) / open(p).read()
    re.compile(r"(?<![\w.])open\s*\([^)]*\)\s*(?:\.\w+\(\s*\))?\s*$"),
    # Namespaced I/O in Python/JS: os.write(...), fs.writeFileSync(...),
    # sock.send(...). The verb must begin the method name.
    re.compile(
        rf"\b{_IO_NAMESPACES}\.(?:open|read|write|connect|send|recv)\w*\s*\([^)]*\)\s*$"
    ),
    # Go file/conn handles: f.Write(...), file.Read(...), conn.Write(...)
    re.compile(r"\b(?:f|fh|fp|file|conn)\.(?:Open|Read|Write|Close)\w*\s*\([^)]*\)\s*$"),
]

# CWE-390: Error detection without action
EMPTY_CATCH_PATTERNS = [
    re.compile(r"except\s+\w+.*:\s*$"),  # Python: except SomeError: (check next line)
    re.compile(r"catch\s*\([^)]+\)\s*\{\s*\}"),  # Java/JS: catch(e) {}
]
PASS_OR_EMPTY = re.compile(r"^\s*(?:pass|\.\.\.)\s*$")

# CWE-280: an empty handler whose declared type is a PERMISSION failure. This
# is a strict child of the CWE-390 empty-handler predicate above: swallowing an
# authorization error silently continues on a path the caller believes is
# permitted. The 280 row REPLACES the 390 row on those lines (see
# `_EMPTY_HANDLER_SPECS` ordering) — it never adds a second one.
_PERMISSION_TYPES = (
    r"(?:PermissionError|PermissionDenied\w*|AccessDenied\w*|AccessControlException"
    r"|UnauthorizedAccess\w*|UnauthorizedError|ForbiddenError|SecurityException"
    r"|NotPermittedError|OperationNotPermitted\w*|AuthorizationException|EACCES|EPERM)"
)
# The Python arm deliberately accepts the tuple form as well:
# `except (OSError, PermissionError):` cannot match the parent's `except\s+\w+`
# (the `\w+` fails on the open paren). The widening is scoped to this branch so
# the CWE-390 row set is unchanged.
_PERMISSION_HANDLER_PATTERNS = [
    re.compile(rf"^\s*except\s+\(?[^:]*\b{_PERMISSION_TYPES}\b[^:]*:\s*$"),
    re.compile(rf"catch\s*\([^)]*\b{_PERMISSION_TYPES}\b[^)]*\)\s*\{{\s*\}}"),
]

# CWE-484: a switch case that neither terminates nor is marked as an
# intentional fallthrough. Go and Rust are absent on purpose — neither language
# has implicit fallthrough, so a rule that fired there would be false by
# construction. Only extensions the scanner actually yields are listed.
_SWITCH_EXTENSIONS = frozenset({
    ".c", ".h", ".cpp", ".java", ".cs",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".phtml",
})
_SWITCH_HEAD = re.compile(r"\bswitch\s*\(")
# Scope-aware label: `(?:[^:]|::)*` lets a C++ scoped enumerator
# (`case Color::Red:`) be crossed, so the label is not truncated at `Color:`
# — which would leave `:Red:` as segment body and read as a fallthrough.
_CASE_LABEL = re.compile(r"^\s*(?:case\b(?:[^:]|::)*|default)\s*:(?!:)")
_CASE_TERMINATOR = re.compile(
    r"\b(?:break|return|continue|goto|throw|exit|die|raise|panic)\b"
)
# Explicit-fallthrough markers, searched over the RAW segment (the blanked copy
# has its comments removed). The block-comment spelling `/* fallthrough */` is
# one of the forms GCC's -Wimplicit-fallthrough accepts, so a line-comment-only
# marker list reports deliberate fallthrough as a defect.
_FALLTHROUGH_MARKER = re.compile(
    r"(?://|/\*|#)\s*(?:falls?[ _\-]?thr(?:u|ough)|fallthru|no\s+break"
    r"|deliberate\s+fall)"
    r"|\[\[fallthrough\]\]"
    r"|__attribute__\s*\(\s*\(\s*fallthrough",
    re.IGNORECASE,
)
# String literals and comments, blanked before any brace/label walk so that
# `return "switch (x) { case 1: }"` cannot be parsed as control flow. `#` is
# NOT included: blanking a JS `#privateField` line to end-of-line would delete
# real braces and corrupt the walk.
_NONCODE_SPAN = re.compile(
    r"\"(?:\\.|[^\"\\\n])*\""
    r"|'(?:\\.|[^'\\\n])*'"
    r"|`(?:\\.|[^`\\])*`"
    r"|/\*.*?\*/"
    r"|//[^\n]*",
    re.DOTALL,
)

# CWE-382: System.exit() inside a container-managed component kills the whole
# shared container, not just the request. The context set is restricted to
# genuine container-managed components: `@RestController`/`@Controller` are NOT
# included, because in a Spring Boot service the JVM *is* the application and
# shutting it down is a legitimate lifecycle call.
_JVM_EXIT = re.compile(
    r"(?<![\w.])System\.exit\s*\("
    r"|Runtime\.getRuntime\s*\(\s*\)\s*\.\s*(?:exit|halt)\s*\("
)
_CONTAINER_CONTEXT = re.compile(
    r"javax\.servlet|jakarta\.servlet|HttpServlet"
    r"|@WebServlet|@WebFilter|@WebListener|ServletContextListener"
    r"|javax\.ejb|jakarta\.ejb|@Stateless|@Stateful|@MessageDriven"
)
_CONTAINER_EXEMPT = re.compile(
    r"\bpublic\s+static\s+void\s+main\s*\("
    r"|@SpringBootApplication"
    r"|implements\s+[\w,\s]*(?:CommandLineRunner|ApplicationRunner)"
)

# CWE-394: a response body consumed without ever inspecting the status.
#
# The primitive set holds ONLY clients that do not raise on a non-2xx reply.
# `urllib.request.urlopen` raises HTTPError through the default
# HTTPErrorProcessor, exactly like axios/got/ky — it is excluded BY NAME below
# so it cannot be re-added: it accounted for 11 of 13 measured rows, all false.
_RAISING_CLIENTS = re.compile(
    r"\baxios\b|\bgot\s*\(|\bky\.|superagent|httpx|HttpClient"
    r"|urlopen|urllib|raise_for_status|raiseForStatus"
)
_STATUS_TOKEN = re.compile(r"\.ok\b|status(?:_code|Code)?\b|raise_for_status")
_BODY_CONSUMED = re.compile(
    r"\.(?:json|text|blob|arrayBuffer|formData)\s*\(|\.(?:content|text)\b"
)
_JS_STATUS_EXTENSIONS = frozenset({
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
})
_STATUS_ARMS = (
    {
        "extensions": _JS_STATUS_EXTENSIONS,
        "call": re.compile(r"\b(?:await\s+)?fetch\s*\("),
        "file_gate": None,
        # Conservative: a `.catch(`/`try {` around a fetch usually means the
        # author is handling failure somewhere, so do not claim otherwise.
        "suppress": re.compile(r"\.catch\s*\(|\btry\s*\{"),
    },
    {
        "extensions": frozenset({".py"}),
        "call": re.compile(
            r"\brequests\.(?:get|post|put|patch|delete|head)\s*\("
        ),
        "file_gate": None,
        "suppress": None,
    },
    {
        # A bare `session.get(...)` is a dict read on a web session far more
        # often than an HTTP call, so this arm requires the file to actually
        # build a requests.Session.
        "extensions": frozenset({".py"}),
        "call": re.compile(
            r"\b\w*[Ss]ession\.(?:get|post|put|patch|delete|head)\s*\("
        ),
        "file_gate": re.compile(r"requests\.Session\s*\("),
        "suppress": None,
    },
)

# CWE-460: a handle created inside a `try` body and released later in THAT
# body, while the handler clauses (`except`/`else`/`finally`) never release it.
# The success path cleans up; the exceptional path leaks.
#
# The predicate is structural and carries NO vocabulary: no allowlist of
# acquire APIs, no allowlist of resource names. The code itself declares the
# cleanup obligation by closing the handle on the happy path, and the finding
# is the absence of that same call on the failure path. That is what keeps the
# row count honest — a vocabulary rule ("`open()` without `with`") fires on
# every correct short-lived handle in a tree, whereas a file that never closes
# the handle at all declares no obligation and is not reported here.
#
# Python only. The same shape in the brace dialects (`try {` + `catch`) was
# measured across the JS/TS/Java/C# sources of two real trees and matched
# nothing, so no arm ships for them: an unmeasured arm is unverified noise.
_PY_TRY_HEADER = re.compile(r"^\s*try\s*:\s*$")
_PY_HANDLER_HEADER = re.compile(r"^\s*(?:except\b|finally\s*:|else\s*:)")
_PY_ASSIGN_CALL = re.compile(r"^\s*(\w+)\s*=\s*(?:await\s+)?[\w.]*\w\s*\(")
_CLEANUP_CALL = r"(?:close|release|disconnect|shutdown|dispose|terminate|cleanup)"

IMPORT_LINE = re.compile(r"^\s*(?:import|from|package)\s+")

# ── finding specs ─────────────────────────────────────────────────────
# One table, one emitter (DRY). Every `category` is a LITERAL: the coverage
# extractor reads `"category": "CWE-N"` out of this source, so an f-string
# would detect the weakness while the attestation denied it.
_UNCHECKED_RETURN_SPEC = {
    "severity": "high",
    "check_id": "cwe.error_handling.unchecked_return",
    "category": "CWE-252",
    "title": "Unchecked return value",
    "detail": "Return value discarded",
    "recommendation": "Check all return values, especially errors",
}
_GENERIC_TYPE_CATCH_SPEC = {
    "severity": "high",
    "check_id": "cwe.error_handling.generic_catch_type",
    "category": "CWE-396",
    "title": "Catch declared for a generic exception type",
    "detail": "Handler catches Exception/Throwable rather than a specific type",
    "recommendation": (
        "Declare the specific exception types this handler can recover from; "
        "let the rest propagate."
    ),
}
_UNTYPED_CATCH_SPEC = {
    "severity": "high",
    "check_id": "cwe.error_handling.bare_except",
    "category": "CWE-755",
    "title": "Overly broad exception handler",
    "detail": "Handler declares no exception type at all",
    "recommendation": "Catch specific exception types and handle each appropriately",
}
_PERMISSION_HANDLER_SPEC = {
    "severity": "high",
    "check_id": "cwe.error_handling.permission_swallowed",
    "category": "CWE-280",
    "title": "Permission failure caught but not handled",
    "detail": "Insufficient-permission error swallowed by an empty handler",
    "recommendation": (
        "Handle the permission failure explicitly: surface it to the caller, "
        "fall back to a lower-privilege path, or fail closed."
    ),
}
_EMPTY_CATCH_SPEC = {
    "severity": "high",
    "check_id": "cwe.error_handling.empty_catch",
    "category": "CWE-390",
    "title": "Error caught but not handled",
    "detail": "Empty exception handler",
    "recommendation": "Log the error or take corrective action in catch/except blocks",
}
_IO_NO_CHECK_SPEC = {
    "severity": "medium",
    "check_id": "cwe.error_handling.io_no_check",
    "category": "CWE-754",
    "title": "I/O operation without error check",
    "detail": "I/O call without error handling",
    "recommendation": "Wrap I/O operations in try/except or check return values",
}
_OMITTED_BREAK_SPEC = {
    "severity": "medium",
    "check_id": "cwe.error_handling.omitted_break",
    "category": "CWE-484",
    "title": "Omitted break statement in switch",
    "detail": "Switch case falls through with no break, return or fallthrough marker",
    "recommendation": (
        "Terminate the case with break/return, or mark the fallthrough "
        "explicitly (`/* fallthrough */`, `[[fallthrough]]`)."
    ),
}
_J2EE_EXIT_SPEC = {
    "severity": "medium",
    "check_id": "cwe.error_handling.j2ee_system_exit",
    "category": "CWE-382",
    "title": "System.exit() in a container-managed component",
    "detail": "JVM shutdown requested from a servlet/EJB component",
    "recommendation": (
        "Throw an application exception and let the container decide; a "
        "component must never terminate the shared JVM."
    ),
}
_EXC_CLEANUP_SPEC = {
    "severity": "medium",
    "check_id": "cwe.error_handling.exception_cleanup",
    "category": "CWE-460",
    "title": "Handle released on the success path only",
    "detail": (
        "Handle created and released inside the try body, but no handler "
        "clause releases it when the block throws"
    ),
    "recommendation": (
        "Release the handle in a `finally:` clause, or acquire it with a "
        "context manager, so an exception cannot skip the cleanup."
    ),
}
_UNEXPECTED_STATUS_SPEC = {
    "severity": "low",
    "check_id": "cwe.error_handling.unexpected_status",
    "category": "CWE-394",
    "title": "HTTP response body used without checking the status",
    "detail": "Response body consumed with no status/ok check",
    "recommendation": (
        "Check the response status (`res.ok`, `status_code`, "
        "`raise_for_status()`) before using the body."
    ),
}

# Empty-handler specs, most specific FIRST. CWE-280 is a child of CWE-390 and
# REPLACES it on the lines it claims — skill findings are not deduplicated
# against each other, so falling through would stack two rows on one handler.
_EMPTY_HANDLER_SPECS = (
    (_PERMISSION_HANDLER_SPEC, tuple(_PERMISSION_HANDLER_PATTERNS)),
    (_EMPTY_CATCH_SPEC, tuple(EMPTY_CATCH_PATTERNS)),
)


def check_error_handling(source_path: str) -> dict:
    """Check for error handling vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of error handling issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if _skip_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _skip_file(file_path: Path) -> bool:
    """Return True for files whose contents are not executable source.

    ``is_prose_file`` matters here: documentation extensions are in the scan
    set and ``COMMENT_INDICATORS`` does not match markdown body text, so a
    policy document that *condemns* ``except Exception: pass`` otherwise reads
    as an instance of it.
    """
    if is_generated_file(file_path) or is_test_file(file_path):
        return True
    return is_prose_file(file_path)


def _matches_any(patterns, line: str) -> bool:
    """True when any pattern in ``patterns`` matches ``line``."""
    return any(pattern.search(line) for pattern in patterns)


def _finding_from_spec(
    file_path: Path, line_num: int, lines: list[str], spec: dict,
) -> dict:
    """Build + enrich one finding from a spec table entry."""
    finding = {
        "severity": spec["severity"],
        "check_id": spec["check_id"],
        "category": spec["category"],
        "title": spec["title"],
        "description": f"{spec['detail']} at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": spec["recommendation"],
        "code_snippet": extract_snippet(lines, line_num),
    }
    return enrich_finding(finding, spec["category"].removeprefix("CWE-"))


def _skip_line(line: str) -> bool:
    """Return True for comment, import and detector-definition lines."""
    if COMMENT_INDICATORS.match(line) or IMPORT_LINE.match(line):
        return True
    return bool(SCANNER_DEF_LINE.search(line))


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for error handling issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    _check_omitted_break(file_path, lines, findings)
    _check_j2ee_exit(file_path, lines, findings)
    claimed = _check_exception_cleanup(file_path, lines, findings)
    _analyze_lines(file_path, lines, findings, claimed)


def _analyze_lines(
    file_path: Path,
    lines: list[str],
    findings: list[dict],
    claimed: set[int],
) -> None:
    """Run every per-line check over each non-skipped, unclaimed line.

    ``claimed`` holds the lines CWE-460 already reported. Those lines are
    skipped outright: CWE-754 claims ``f = open(p)`` whenever the handler sits
    outside its +/-3-line context window, which would stack a second row on
    one line for one defect.
    """
    for line_num, line in enumerate(lines, start=1):
        if _line_skipped(line_num, line, claimed):
            continue
        for check in _LINE_CHECKS:
            check(file_path, line, line_num, lines, findings)


def _line_skipped(line_num: int, line: str, claimed: set[int]) -> bool:
    """True when a line is already claimed, or is not scannable at all."""
    return line_num in claimed or _skip_line(line)


def _check_unchecked_return(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for unchecked return values (CWE-252)."""
    if _matches_any(UNCHECKED_RETURN_GO, line):
        findings.append(
            _finding_from_spec(file_path, line_num, lines, _UNCHECKED_RETURN_SPEC)
        )


def _arm_applies(extensions, suffix: str) -> bool:
    """True when an arm is unrestricted or valid for this file's extension."""
    return extensions is None or suffix in extensions


def _untyped_catch(file_path: Path, line: str) -> bool:
    """Return True for a handler that declares NO exception type."""
    suffix = file_path.suffix.lower()
    return any(
        _arm_applies(extensions, suffix) and _matches_any(patterns, line)
        for patterns, extensions in _UNTYPED_CATCH_ARMS
    )


def _broad_catch_spec(file_path: Path, line: str) -> dict | None:
    """Resolve the ONE broad-handler spec for this line (396 XOR 755)."""
    if _matches_any(GENERIC_TYPED_CATCH_PATTERNS, line):
        return _GENERIC_TYPE_CATCH_SPEC
    return _UNTYPED_CATCH_SPEC if _untyped_catch(file_path, line) else None


def _check_bare_except(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for overly broad exception handlers (CWE-396 XOR CWE-755)."""
    spec = _broad_catch_spec(file_path, line)
    if spec is not None:
        findings.append(_finding_from_spec(file_path, line_num, lines, spec))


def _handler_body_is_empty(line: str, line_num: int, lines: list[str]) -> bool:
    """For a Python handler header, require the next line to be pass/`...`."""
    if "except" not in line or line_num >= len(lines):
        return True
    return bool(PASS_OR_EMPTY.match(lines[line_num]))


def _empty_handler_spec(
    line: str, line_num: int, lines: list[str],
) -> dict | None:
    """Resolve the ONE empty-handler spec for this line (280 replaces 390)."""
    for spec, patterns in _EMPTY_HANDLER_SPECS:
        if not _matches_any(patterns, line):
            continue
        if _handler_body_is_empty(line, line_num, lines):
            return spec
        return None
    return None


def _check_empty_catch(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for empty handlers (CWE-390, or CWE-280 when permission-typed)."""
    spec = _empty_handler_spec(line, line_num, lines)
    if spec is not None:
        findings.append(_finding_from_spec(file_path, line_num, lines, spec))


def _check_io_without_check(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for I/O operations without error checking (CWE-754)."""
    if not _matches_any(IO_WITHOUT_CHECK, line):
        return
    # Check surrounding context for error handling
    context_start = max(0, line_num - 2)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if re.search(r"\b(?:try|if\s+err|except|catch|\.catch)\b", context):
        return
    findings.append(_finding_from_spec(file_path, line_num, lines, _IO_NO_CHECK_SPEC))


# ── CWE-484 ───────────────────────────────────────────────────────────
def _blank_noncode(text: str) -> str:
    """Replace string-literal and comment spans with spaces, preserving both
    line structure and offsets so a brace walk stays byte-aligned."""
    return _NONCODE_SPAN.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _match_delim(text: str, start: int, opener: str, closer: str) -> int | None:
    """Offset of the delimiter closing the one at ``start`` (which must be an
    ``opener``), or None when unbalanced."""
    depth = 0
    for index in range(start, len(text)):
        depth += (text[index] == opener) - (text[index] == closer)
        if depth == 0:
            return index
    return None


def _switch_body_bounds(blanked: str, head_end: int) -> tuple[int, int] | None:
    """Offsets of the `{` and `}` bracketing a switch body."""
    open_paren = blanked.find("(", head_end - 1)
    close_paren = _match_delim(blanked, open_paren, "(", ")")
    if close_paren is None:
        return None
    open_brace = blanked.find("{", close_paren)
    if open_brace < 0:
        return None
    close_brace = _match_delim(blanked, open_brace, "{", "}")
    return None if close_brace is None else (open_brace, close_brace)


def _label_lines(blanked_lines: list[str], first: int, last: int) -> list[int]:
    """0-based indices of the TOP-LEVEL case/default labels in a switch body.

    Brace depth is tracked so labels of a nested switch (depth > 0) are not
    read as segments of the outer one.
    """
    found: list[int] = []
    depth = 0
    for index in range(first, last):
        if depth == 0 and _CASE_LABEL.match(blanked_lines[index]):
            found.append(index)
        depth += blanked_lines[index].count("{") - blanked_lines[index].count("}")
    return found


def _segment_text(lines: list[str], start: int, end: int) -> str:
    """Text of one case segment: the label line minus its label, plus the
    lines up to the next label."""
    head = _CASE_LABEL.sub("", lines[start], count=1)
    return "\n".join([head, *lines[start + 1:end]])


def _falls_through(
    blanked_lines: list[str], raw_lines: list[str], start: int, end: int,
) -> bool:
    """True when the segment has a body, no terminator, and no marker."""
    segment = _segment_text(blanked_lines, start, end)
    if not segment.strip():
        return False  # stacked label — shares the next case's body
    if _CASE_TERMINATOR.search(segment):
        return False
    return not _FALLTHROUGH_MARKER.search(_segment_text(raw_lines, start, end))


def _report_fallthrough(
    file_path: Path,
    lines: list[str],
    blanked_lines: list[str],
    span: tuple[int, int],
    findings: list[dict],
) -> None:
    """Emit at most one CWE-484 row per switch body. The LAST segment is never
    a candidate — falling out of the final case is how a switch ends."""
    labels = _label_lines(blanked_lines, span[0] + 1, span[1])
    for position, start in enumerate(labels[:-1]):
        if not _falls_through(blanked_lines, lines, start, labels[position + 1]):
            continue
        findings.append(
            _finding_from_spec(file_path, start + 1, lines, _OMITTED_BREAK_SPEC)
        )
        return


def _check_omitted_break(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Check for switch cases that fall through silently (CWE-484)."""
    if file_path.suffix.lower() not in _SWITCH_EXTENSIONS:
        return
    blanked = _blank_noncode("\n".join(lines))
    blanked_lines = blanked.split("\n")
    for match in _SWITCH_HEAD.finditer(blanked):
        bounds = _switch_body_bounds(blanked, match.end())
        if bounds is None:
            continue
        span = (
            blanked.count("\n", 0, bounds[0]),
            blanked.count("\n", 0, bounds[1]),
        )
        _report_fallthrough(file_path, lines, blanked_lines, span, findings)


# ── CWE-382 ───────────────────────────────────────────────────────────
def _container_managed(text: str) -> bool:
    """True when the file declares a container-managed component and is not
    itself a JVM entrypoint."""
    if _CONTAINER_EXEMPT.search(text):
        return False
    return bool(_CONTAINER_CONTEXT.search(text))


def _first_exit_line(lines: list[str]) -> int | None:
    """1-based line number of the first JVM-shutdown call, if any."""
    for line_num, line in enumerate(lines, start=1):
        if _JVM_EXIT.search(line) and not COMMENT_INDICATORS.match(line):
            return line_num
    return None


def _check_j2ee_exit(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Check for System.exit() in a container-managed component (CWE-382)."""
    if detect_language(str(file_path)) != "java":
        return
    if not _container_managed("\n".join(lines)):
        return
    line_num = _first_exit_line(lines)
    if line_num is not None:
        findings.append(
            _finding_from_spec(file_path, line_num, lines, _J2EE_EXIT_SPEC)
        )


# ── CWE-460 ───────────────────────────────────────────────────────────
def _indent_of(line: str) -> int:
    """Column of the first non-space character (blank lines report 0)."""
    return len(line) - len(line.lstrip())


def _body_continues(line: str, base: int) -> bool:
    """True while a line still belongs to a suite opened at ``base``."""
    return not line.strip() or _indent_of(line) > base


def _clause_continues(line: str, base: int) -> bool:
    """True while a line still belongs to the handler clauses of a try.

    A dedented ``except``/``else``/``finally`` at exactly ``base`` opens the
    next clause of the SAME statement; one at a shallower indent belongs to an
    enclosing try and ends the walk.
    """
    if _body_continues(line, base):
        return True
    return _indent_of(line) == base and bool(_PY_HANDLER_HEADER.match(line))


def _suite_end(lines: list[str], start: int, base: int, predicate) -> int:
    """Index one past the last line ``predicate`` accepts."""
    index = start
    while index < len(lines) and predicate(lines[index], base):
        index += 1
    return index


def _leaks_handle(line: str, body: str, handler: str) -> bool:
    """True when this assignment's handle is released in ``body`` only."""
    match = _PY_ASSIGN_CALL.match(line)
    if match is None:
        return False
    closer = re.compile(rf"\b{re.escape(match.group(1))}\.{_CLEANUP_CALL}\s*\(")
    return bool(closer.search(body)) and not closer.search(handler)


def _first_leak_line(
    lines: list[str], span: tuple[int, int], texts: tuple[str, str],
    claimed: set[int],
) -> int | None:
    """1-based line of the first unclaimed leaking assignment in the body."""
    for index in range(span[0], span[1]):
        if index + 1 not in claimed and _leaks_handle(lines[index], *texts):
            return index + 1
    return None


def _scan_try_block(
    file_path: Path, lines: list[str], start: int,
    findings: list[dict], claimed: set[int],
) -> None:
    """Emit at most one CWE-460 row for the try statement opened at ``start``."""
    base = _indent_of(lines[start])
    body_end = _suite_end(lines, start + 1, base, _body_continues)
    clause_end = _suite_end(lines, body_end, base, _clause_continues)
    if clause_end == body_end:
        return  # a bare `try:` with no handler clause is not a handler
    texts = ("\n".join(lines[start + 1:body_end]), "\n".join(lines[body_end:clause_end]))
    line_num = _first_leak_line(lines, (start + 1, body_end), texts, claimed)
    if line_num is not None:
        claimed.add(line_num)
        findings.append(
            _finding_from_spec(file_path, line_num, lines, _EXC_CLEANUP_SPEC)
        )


def _check_exception_cleanup(
    file_path: Path, lines: list[str], findings: list[dict],
) -> set[int]:
    """Check for handles released on the success path only (CWE-460).

    Returns the line numbers claimed, so the per-line checks can skip them.
    """
    claimed: set[int] = set()
    if file_path.suffix.lower() != ".py":
        return claimed
    for index, line in enumerate(lines):
        if _PY_TRY_HEADER.match(line):
            _scan_try_block(file_path, lines, index, findings, claimed)
    return claimed


# ── CWE-394 ───────────────────────────────────────────────────────────
def _matching_status_arm(suffix: str, line: str) -> dict | None:
    """Resolve the HTTP-client arm this line belongs to, if any."""
    for arm in _STATUS_ARMS:
        if suffix in arm["extensions"] and arm["call"].search(line):
            return arm
    return None


def _pattern_hits(pattern: "re.Pattern | None", text: str) -> bool:
    """True when an optional pattern is present and matches."""
    return pattern is not None and bool(pattern.search(text))


def _gate_open(pattern: "re.Pattern | None", text: str) -> bool:
    """True when an optional gate pattern is absent, or present and matching."""
    return pattern is None or bool(pattern.search(text))


def _status_unchecked(arm: dict, line_num: int, lines: list[str]) -> bool:
    """True when the body is consumed and no status check sits in the window."""
    if not _gate_open(arm["file_gate"], "\n".join(lines)):
        return False
    window = "\n".join(lines[max(0, line_num - 4):line_num + 8])
    if _STATUS_TOKEN.search(window) or _pattern_hits(arm["suppress"], window):
        return False
    return bool(_BODY_CONSUMED.search(window))


def _check_unexpected_status(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for a response body used without a status check (CWE-394)."""
    arm = _matching_status_arm(file_path.suffix.lower(), line)
    if arm is None or _RAISING_CLIENTS.search(line):
        return
    if _status_unchecked(arm, line_num, lines):
        findings.append(
            _finding_from_spec(file_path, line_num, lines, _UNEXPECTED_STATUS_SPEC)
        )


# Per-line checks, run in order for every non-skipped line.
_LINE_CHECKS = (
    _check_unchecked_return,
    _check_bare_except,
    _check_empty_catch,
    _check_io_without_check,
)

check_error_handling_tool = function_tool(check_error_handling)
