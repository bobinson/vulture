"""CWE injection vulnerability detection skill."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.obfuscation import check_obfuscation
from shared.tools.snippet import extract_snippet
from shared.validate.language import detect_language

from cwe_agent.catalog import enrich_finding

# CWE-89: SQL Injection.
#
# All four common Python string-construction antipatterns are now
# matched, plus Go's Sprintf / direct concat:
#   - f-string with placeholder            f"SELECT ... {var}"
#   - .format(...)                          "SELECT ...".format(x)
#   - %-formatting                          "SELECT ... %s" % var       (NEW)
#   - + concatenation                       query = "SELECT " + var
#   - Sprintf                               fmt.Sprintf("SELECT %s", x)
SQL_INJECTION_PATTERNS = [
    # f-strings
    re.compile(r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*\{'),
    re.compile(r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^']*\{"),
    # .format(...)
    re.compile(r"\.format\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
    re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\s.*\.format\(", re.IGNORECASE),
    # %-formatting against a SQL string. Two complementary shapes
    # because the SQL keyword can be in either operand of `%`.
    re.compile(
        r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"\']*["\']\s*%\s*[\w(]',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:query|sql|stmt)\s*=\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*%',
        re.IGNORECASE,
    ),
    # Sprintf (Go)
    re.compile(r'Sprintf\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
    # Concatenation
    re.compile(r'(?:query|sql|stmt)\s*=\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+',
               re.IGNORECASE),
    re.compile(r'(?:query|sql)\s*=\s*[f"\'"].*\+'),
    # JS/TS template literal with an interpolated value inside a DML
    # statement:  db.query(`SELECT ... WHERE id = ${req.params.id}`)
    #
    # Every pattern above is Python- or Go-shaped, so Node was entirely
    # uncovered: Node login and search routes that build SQL by template-literal
    # interpolation — textbook injection — produced zero CWE-89 findings.
    # Requiring BOTH a DML keyword and a `${` keeps static template
    # literals and parameterised calls (which use quotes, not backticks)
    # out of the results.
    re.compile(r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`]*\$\{", re.IGNORECASE),
    # Feature 0070: the previous clause-only branch was
    #   `[^`]*\$\{[^`]*\b(?:FROM|WHERE|VALUES|SET)\b[^`]*`
    # under re.IGNORECASE. English prose is full of those words, so it fired
    # on "instructions on how to *set* up and configure the Alchemy API" and
    # "the bonus points *from* this order will be added" — 3 CRITICAL false
    # positives in one sweep and zero true positives (both genuine SQLi
    # sites come from the verb branch above).
    #
    # A single clause keyword is not evidence of SQL. A *bigram* — verb plus
    # its mandatory clause, adjacent — is. Every quantifier below is bounded
    # so the alternation stays ReDoS-safe on adversarial input.
    re.compile(
        r"`[^`]{0,400}?"
        r"(?:SELECT\s+[\w*.,\s()]{1,120}?\s+FROM\s"
        r"|INSERT\s+INTO\s"
        r"|UPDATE\s+[\w.\"'\[\]]{1,60}\s+SET\s"
        r"|DELETE\s+FROM\s"
        r"|DROP\s+(?:TABLE|DATABASE)\s)"
        r"[^`]{0,400}\$\{",
        re.IGNORECASE,
    ),
]

# CWE-78: OS Command Injection
#
# Real CWE-78 = passing user input to a shell. In Python that means the
# patterns below — os.system / os.popen / subprocess.* with shell=True.
# In Go, `exec.Command(name, arg, ...)` does NOT invoke a shell; argv
# concatenation there is a different vulnerability class (CWE-88 argument
# injection or CWE-94 code injection if the binary is an interpreter).
# We retain a narrow Go pattern that flags ONLY shell-binary invocations
# explicitly: exec.Command("sh"/"bash"/"/bin/sh"/etc., "-c", ...).
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"os\.system\("),
    re.compile(r"os\.popen\("),
    re.compile(r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True"),
    re.compile(r'exec\.Command\(\s*"(?:sh|bash|zsh|/bin/(?:sh|bash|zsh))"\s*,'),
    # Feature 0060: cross-language OS-command sinks moved here from the
    # dangerous_function skill (were mis-attributed as CWE-676). Each is an
    # unambiguous shell/command-execution API — receiver-anchored so benign
    # same-named method calls (e.g. Statement.exec()) are not matched.
    re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),          # Java
    re.compile(r"\bnew\s+ProcessBuilder\s*\("),                 # Java
    re.compile(r"(?<![\w.>])(?:shell_exec|passthru|proc_open)\s*\("),  # PHP
]

# Validation-guard patterns. If any of these match within the radius of
# an injection-pattern hit, the detector treats the call as guarded and
# does NOT emit a finding. Mirrors the `_has_safe_context` approach used
# by the XSS skill.
SAFE_VALIDATION_PATTERNS = re.compile(
    r"(?:"
    r"regexp\.MustCompile|"               # Go: precompiled regex
    r"\bre\.compile\s*\(|"                # Python: precompiled regex
    r"\.MatchString\s*\(|"                # Go: regexp.MatchString
    r"\.match\s*\(|"                      # Python: pattern.match()
    r"\bIsValid\w*|"                      # Go: IsValidX, IsValidPython, ...
    r"\bis_valid\w*|"                     # Python snake_case: is_valid_*
    r"\b[Vv]alidate\w+|"                  # validate_x / ValidateX
    r"\b[Ss]anitize\w+|"                  # sanitize_x / SanitizeX
    r"\bshlex\.(?:quote|split)\s*\(|"     # Python: command-escaping helpers
    r"\bshell_quote\s*\(|"                # custom shell-quote helpers
    r"\.isidentifier\s*\(|"               # Python: name.isidentifier()
    r"allowlist|allow_list|whitelist"     # allowlist-style guards
    r")",
)

# CWE-79: Cross-site Scripting (XSS)
#
# Feature 0070: the list knew React (`dangerouslySetInnerHTML`), Vue
# (`v-html`), jQuery and raw DOM — but no Angular idiom at all, so an
# Angular codebase was effectively unscanned for XSS. Two sinks added:
#
#   * `bypassSecurityTrust*` — the explicit "turn Angular's sanitizer off"
#     escape hatch. Every call is a deliberate trust decision worth a row.
#   * `[innerHTML]="expr"` template binding — Angular sanitizes HTML bindings,
#     but the binding is still the sink an attacker aims at and is routinely
#     paired with a `bypassSecurityTrustHtml` value, which is the common real
#     pairing. The negative lookahead drops pure-i18n bindings whose expression
#     is a `| translate` pipe over a literal message key: those render
#     developer-authored catalogue text, not request data.
_XSS_BYPASS_SANITIZER = re.compile(
    r"\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\("
)
_XSS_ANGULAR_BINDING = re.compile(
    r"\[innerHTML\]\s*=\s*([\"'])(?![^\"']*\|\s*translate)[^\"']*\1"
)

XSS_PATTERNS = [
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"document\.write\("),
    re.compile(r"dangerouslySetInnerHTML"),
    re.compile(r"\$\(\s*['\"]#?\w+['\"]\s*\)\.html\("),
    re.compile(r"v-html\s*="),
    _XSS_BYPASS_SANITIZER,
    _XSS_ANGULAR_BINDING,
]

# Request-controlled sources reachable from an Angular component body. When the
# value handed to `bypassSecurityTrust*` traces to one of these, the sanitizer
# is being switched off on data the attacker supplies — a confirmed reflected
# XSS rather than a trust decision over server-owned markup — so the row is
# escalated to critical.
#
# Proximity alone is not enough. In one sweep a bare +/-15-line window
# escalated 3 of the 9 calls: `route.snapshot.queryParams` happens to sit
# within 15 lines of two bypasses whose arguments are unrelated
# (`tableData[i].description`, `results.data[0].orderId`). So the tainted
# *identifier* must actually appear in the call's argument, and appear
# unqualified — `results.data[0].orderId` is a property of a server response,
# not the local `orderId` that came off the query string.
_XSS_ROUTE_TAINT = re.compile(
    r"route\.snapshot\.(?:queryParams|params)|ActivatedRoute"
    r"|location\.search|window\.name"
)
_XSS_TAINT_ASSIGN = re.compile(
    r"(?:^|[\s;{(])(?:const\s+|let\s+|var\s+|this\.)?([A-Za-z_$][\w$]*)"
    r"(?:\s*:\s*[\w<>\[\]|, ]+)?\s*=\s*[^=][^\n]*?(?:"
    r"route\.snapshot\.(?:queryParams|params)|ActivatedRoute"
    r"|location\.search|window\.name)"
)
_LINE_COMMENT = re.compile(r"//.*$")
_XSS_TAINT_RADIUS = 15

# The `[innerHTML]=` half of the Angular coverage lives in `.html` templates,
# and `.html` only reaches this skill through the scanner's extension
# whitelist. Surfaced in the finding text so a triager who sees the count drop
# knows which knob did it.
_XSS_WHITELIST_NOTE = (
    "Angular template sinks are only visible while the scanner extension "
    "whitelist is enabled; VULTURE_DISABLE_EXTENSION_WHITELIST=true removes "
    ".html from the scan set and blinds this check to template bindings."
)

# CWE-94: Code Injection.
#
# The previous `(?<!\w)exec\s*\(` pattern matched `.exec(` because the
# `.` between a method receiver and the method name is NOT a word
# character. That trapped JavaScript regex calls like
# `myRegex.exec(input)` (which is regex MATCHING, not code execution).
# Tighten to `(?<![\w.\]\)])` so any method-call shape — `.exec(`,
# `].exec(`, `).exec(` — is excluded.
#
# True positives still match: bare `eval(` / `exec(` at statement start,
# after assignment, after semicolons, after `if`, etc.
#
# Qualified eval/Function on global objects (`globalThis.eval`,
# `window.eval`, ...) are real code-exec calls but match the
# generic method-call shape the lookbehind excludes. Listed
# explicitly so they aren't silenced.
CODE_INJECTION_PATTERNS = [
    re.compile(r"(?<![\w.\]\)])eval\s*\("),
    re.compile(r"(?<![\w.\]\)])exec\s*\("),
    re.compile(r"\b(?:globalThis|window|self|global)\.eval\s*\("),
    re.compile(r"\b(?:globalThis|window|self|global)\.Function\s*\("),
    re.compile(r"new\s+Function\s*\("),
    re.compile(r"setTimeout\s*\(\s*['\"`]"),
    re.compile(r"setInterval\s*\(\s*['\"`]"),
]

# CWE-918: Server-Side Request Forgery (SSRF)
#
# Feature 0070. The old single list produced 29 rows in one sweep, all 29
# false, from one pattern:
#
#   re.compile(r"http\.Get\([^)]*(?:...|\+)", re.IGNORECASE)
#
# Two compounding defects. (a) `http.Get` is Go's stdlib client and is
# case-significant, but IGNORECASE made it match Angular's
# `return this.http.get(this.host + '/', { params })` — every service method
# in the frontend. (b) the bare `\+` alternative treated *any* string
# concatenation as taint, so even a fully static URL built from a version
# constant scored.
#
# Fixes: the namespace is now case-exact AND receiver-anchored (a negative
# lookbehind, the same shape that fixed CWE-754 in error_handling_check), and
# the `\+` alternative is gone — concatenation is a construction technique,
# not a source.
_SSRF_TAINT = r"(?:request|req|params|input|user|body|query)"

# Server-side-only client libraries. `requests`, `urllib` and `httpx` cannot
# run in a browser, so the file is server code by construction and no
# framework marker is required.
_SSRF_SERVER_ONLY_PATTERNS = [
    re.compile(rf"requests\.(?:get|post|put|delete|head|patch)\([^)]*{_SSRF_TAINT}", re.IGNORECASE),
    re.compile(rf"urllib\.request\.urlopen\([^)]*{_SSRF_TAINT}", re.IGNORECASE),
    re.compile(rf"httpx\.(?:get|post)\([^)]*{_SSRF_TAINT}", re.IGNORECASE),
]

# Sinks that exist in the browser too (`fetch`, and `http.get` which is both
# Go's `http.Get` and Node's `http.get`). A hit here is only SSRF if the file
# is server code, so these are gated on _SERVER_CONTEXT.
_SSRF_CLIENT_CAPABLE_PATTERNS = [
    # Case-exact on the namespace and receiver-anchored: `http.Get(` (Go) and
    # `http.get(` (Node) match; `this.http.get(` / `svc.http.get(` do not.
    re.compile(rf"(?<![\w.$])http\.(?:Get|get)\([^)]*{_SSRF_TAINT}"),
    re.compile(rf"(?<![\w.$])fetch\([^)]*{_SSRF_TAINT}", re.IGNORECASE),
]

SSRF_PATTERNS = _SSRF_SERVER_ONLY_PATTERNS + _SSRF_CLIENT_CAPABLE_PATTERNS

# Evidence that a file is server-side request-handling code: a server
# framework import, or a handler signature that takes a request object.
_SERVER_CONTEXT = re.compile(
    r"""(?:
        (?:from|require\s*\(\s*)\s*['"](?:express|koa|fastify|@nestjs/[\w-]+|next/server|hapi|@hapi/hapi|http|node:http|https|node:https)['"]
      | \bimport\s+(?:express|koa|fastify|Fastify)\b
      | \bexpress\s*\(\s*\)
      | \bfrom\s+(?:flask|django[\w.]*|fastapi|aiohttp|starlette|bottle|tornado[\w.]*)\s+import\b
      | \bimport\s+(?:flask|django|fastapi|aiohttp|tornado|bottle|webapp2)\b
      | \bnet/http\b
      | \bhttp\.(?:ResponseWriter|HandlerFunc|Handle(?:Func)?\s*\()
      | \(\s*(?:req|request)\s*(?::\s*\w|,|\))
      | \b(?:app|router|server)\.(?:get|post|put|patch|delete|use|all)\s*\(
    )""",
    re.VERBOSE,
)

# Feature 0070, item 3: one-hop taint. The shape that matters is
#   const url = req.body.imageUrl
#   const response = await fetch(url)      // a few lines later
# The sink argument is a bare identifier, so no pattern that inspects only the
# sink line can ever see the taint. Resolve exactly one assignment hop back.
_SSRF_BARE_ARG_SINK = re.compile(
    r"(?<![\w.$])(?:fetch|request)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]"
    r"|(?<![\w.$])(?:axios|http)\.(?:get|Get)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]"
)
_SSRF_REQ_SOURCE = r"req(?:uest)?\.(?:body|query|params)\b"
_SSRF_TAINT_LOOKBACK = 15

SAFE_SSRF_PATTERNS = re.compile(
    r"(?:allowlist|whitelist|allowed_hosts|allowed_urls|validate_url|urlparse|ALLOWED_DOMAINS)",
    re.IGNORECASE,
)

# Audit #2: anchor to BARE exec/eval (code-injection, CWE-94) so it does not
# substring-match the command sinks `shell_exec("x")` / `Runtime….exec("x")` and
# silently suppress a real static-string shell invocation.
SAFE_STATIC_CALL = re.compile(r"""(?<![\w.>])(?:exec|eval)\(\s*(?:'[^']*'|"[^"]*")\s*[,)]""")
SHELL_FUNC_DEF = re.compile(r"^\s*\w+\s*\(\s*\)\s*\{")

# Feature 0060: bare `system(` is a shell sink in PHP/Ruby (Kernel#system /
# PHP system()) but a benign local call elsewhere (e.g. a Python def system()).
# Applied ONLY to PHP/Ruby files (receiver-anchored) to avoid cross-language FPs.
_BARE_SYSTEM = re.compile(r"(?<![\w.>])system\s*\(")
_PHP_RUBY_COMMAND_PATTERNS = COMMAND_INJECTION_PATTERNS + [_BARE_SYSTEM]

# Audit #1: a same-named function DEFINITION (Ruby `def system`, PHP
# `function system`) is a declaration, not a call — skip when a def keyword
# immediately precedes the matched command sink.
_CMD_DEF_BEFORE = re.compile(r"\b(?:def|function)\s+$")


def check_injection(source_path: str) -> dict:
    """Check for CWE injection vulnerabilities (SQL, command, XSS, code).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of injection vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if _is_excluded_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _is_excluded_file(file_path: Path) -> bool:
    """Files this skill must not read.

    Feature 0070 P7 adds ``is_prose_file``: documentation is where sinks get
    *named*, not used. ``.md/.rst/.txt/.adoc`` reach this skill through the
    scanner's extension whitelist and ``COMMENT_INDICATORS`` cannot help
    (markdown body text carries no comment marker). Measured on a real tree: 5
    rows, all SKILLS.md / INSTRUCTIONS.md prose describing ``innerHTML =`` and
    ``eval(`` — every one false.
    """
    return (
        is_generated_file(file_path)
        or is_test_file(file_path)
        or is_prose_file(file_path)
    )


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for injection patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    lang = detect_language(str(file_path))
    ext = file_path.suffix.lower()
    # Resolved once per file: whether this is server-side request-handling code.
    # Gates the browser-capable SSRF sinks (feature 0070).
    server_ctx = bool(_SERVER_CONTEXT.search("\n".join(lines)))
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SAFE_IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_sql(file_path, line, line_num, lines, findings)
        _check_command(file_path, line, line_num, lines, findings, lang)
        _check_xss(file_path, line, line_num, lines, findings)
        _check_code_injection(file_path, line, line_num, lines, findings)
        _check_ssrf(file_path, line, line_num, lines, findings, server_ctx)
        _check_a05_specialisations(
            _LineCtx(file_path, ext, line, line_num, lines), findings
        )

    # Obfuscation detection across all lines
    content = read_file_safe(file_path) or ""
    obfuscation_findings = check_obfuscation(file_path, lines, content)
    findings.extend(obfuscation_findings)


def _check_sql(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-89 SQL injection."""
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.injection.sql",
                "category": "CWE-89",
                "title": "SQL injection via string interpolation",
                "description": f"SQL query built with string formatting at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use parameterized queries or prepared statements",
                "verification_hints": ["Test with payload: ' OR 1=1--", "Check if input is reflected in SQL error"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "89"))
            return


def _has_validation_context(lines: list[str], line_num: int, radius: int = 10) -> bool:
    """Check if a validation/sanitization guard appears within `radius`
    lines of `line_num`. The window covers the function body that contains
    the suspicious call — guards like `if !isValidX(arg) { return }` or
    `if not validate_module(name): return False` immediately preceding the
    call mitigate the injection risk and should suppress the finding.
    """
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return bool(SAFE_VALIDATION_PATTERNS.search("\n".join(lines[start:end])))


def _check_command(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], lang: str,
) -> None:
    """Check for CWE-78 OS command injection. ``lang`` is the file's language
    (resolved once per file by the caller) — used to language-scope the bare
    PHP/Ruby ``system(`` sink."""
    if SHELL_FUNC_DEF.match(line):
        return
    patterns = (
        _PHP_RUBY_COMMAND_PATTERNS
        if lang in ("php", "ruby")
        else COMMAND_INJECTION_PATTERNS
    )
    for pattern in patterns:
        m = pattern.search(line)
        if m is not None:
            # Skip a same-named function DEFINITION (audit #1).
            if _CMD_DEF_BEFORE.search(line[:m.start()]):
                continue
            if SAFE_STATIC_CALL.search(line):
                return
            if _has_validation_context(lines, line_num):
                return
            finding = {
                "severity": "critical",
                "check_id": "cwe.injection.command",
                "category": "CWE-78",
                "title": "OS command injection",
                "description": f"Unsafe command execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use subprocess with shell=False and list arguments",
                "verification_hints": ["Test with payload: ; id", "Check if command output is reflected"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "78"))
            return


def _check_xss(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-79 cross-site scripting."""
    for pattern in XSS_PATTERNS:
        if not pattern.search(line):
            continue
        severity, title, description, recommendation = _xss_shape(
            pattern, line_num, lines
        )
        finding = {
            "severity": severity,
            "check_id": "cwe.injection.xss",
            "category": "CWE-79",
            "title": title,
            "description": description,
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": recommendation,
            "verification_hints": ["Check if input is reflected unescaped", "Test with payload: <script>alert(1)</script>"],
            "requires_context": True,
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "79"))
        return


def _xss_shape(
    pattern: re.Pattern, line_num: int, lines: list[str],
) -> tuple[str, str, str, str]:
    """Return (severity, title, description, recommendation) for an XSS hit.

    Angular's two sinks get their own wording, and `bypassSecurityTrust*` is
    escalated to critical when a request-controlled source is visible in the
    same function body — at that point the sanitizer is being disabled on
    attacker input rather than on server-owned markup.
    """
    if pattern is _XSS_BYPASS_SANITIZER:
        tainted = _bypass_arg_is_route_tainted(lines[line_num - 1], lines, line_num)
        return (
            "critical" if tainted else "high",
            "Angular sanitizer bypassed on request-controlled value"
            if tainted
            else "Angular sanitizer explicitly bypassed",
            (
                f"bypassSecurityTrust* at line {line_num} disables Angular's "
                "output sanitizer on a value that a request-controlled source "
                f"(route params / location.search / window.name) reaches within "
                f"{_XSS_TAINT_RADIUS} lines."
                if tainted
                else f"bypassSecurityTrust* at line {line_num} disables Angular's "
                "output sanitizer for this value; anything attacker-influenced "
                "that reaches it is rendered verbatim."
            ),
            "Remove the bypass and let Angular sanitize, or sanitize the value "
            "with DomPurify before marking it trusted",
        )
    if pattern is _XSS_ANGULAR_BINDING:
        return (
            "high",
            "Angular [innerHTML] binding renders dynamic markup",
            f"[innerHTML] binding at line {line_num} renders an expression as "
            f"HTML. {_XSS_WHITELIST_NOTE}",
            "Bind with interpolation ({{ value }}) instead, or sanitize the "
            "expression before binding it to [innerHTML]",
        )
    return (
        "high",
        "Potential cross-site scripting (XSS)",
        f"Unescaped HTML output at line {line_num}",
        "Sanitize user input before rendering as HTML",
    )


def _bypass_arg_is_route_tainted(
    line: str, lines: list[str], line_num: int,
) -> bool:
    """True when the value passed to ``bypassSecurityTrust*`` traces to a
    request-controlled Angular source.

    Either the argument names the source directly, or it names a local that was
    assigned from one within ``_XSS_TAINT_RADIUS`` lines. The local must appear
    unqualified in the argument, so a same-named property of a server response
    (``results.data[0].orderId``) does not count as the query-string ``orderId``.
    """
    m = _XSS_BYPASS_SANITIZER.search(line)
    if m is None:
        return False
    arg = _LINE_COMMENT.sub("", line[m.end():])
    if _XSS_ROUTE_TAINT.search(arg):
        return True
    start = max(0, line_num - 1 - _XSS_TAINT_RADIUS)
    end = min(len(lines), line_num + _XSS_TAINT_RADIUS)
    for near in lines[start:end]:
        for ident in _XSS_TAINT_ASSIGN.findall(_LINE_COMMENT.sub("", near)):
            if re.search(rf"(?<![\w.$]){re.escape(ident)}\b", arg):
                return True
    return False


def _check_code_injection(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-94 code injection."""
    for pattern in CODE_INJECTION_PATTERNS:
        if pattern.search(line):
            if SAFE_STATIC_CALL.search(line):
                return
            finding = {
                "severity": "critical",
                "check_id": "cwe.injection.code",
                "category": "CWE-94",
                "title": "Code injection via dynamic execution",
                "description": f"Dynamic code execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Avoid eval/exec; use safe alternatives or whitelisted operations",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "94"))
            return


def _ssrf_taint_hop(line: str, line_num: int, lines: list[str]) -> str | None:
    """One-hop taint resolution for a sink whose argument is a bare identifier.

    Returns the identifier when it was assigned from ``req.body`` /
    ``req.query`` / ``req.params`` within the preceding
    ``_SSRF_TAINT_LOOKBACK`` lines of the same file, else ``None``.

    This is what recovers the common real SSRF shape: the request value is
    parked in a local (`const url = req.body.imageUrl`) five lines above
    `await fetch(url)`, so nothing that inspects the sink line alone can see it.
    """
    m = _SSRF_BARE_ARG_SINK.search(line)
    if m is None:
        return None
    ident = m.group(1) or m.group(2)
    if not ident:
        return None
    assign = re.compile(
        rf"(?<![\w.$]){re.escape(ident)}\s*=\s*[^=][^\n]{{0,120}}?{_SSRF_REQ_SOURCE}"
    )
    start = max(0, line_num - 1 - _SSRF_TAINT_LOOKBACK)
    for prev in lines[start:line_num - 1]:
        if assign.search(prev):
            return ident
    return None


def _check_ssrf(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], server_ctx: bool = True,
) -> None:
    """Check for CWE-918 server-side request forgery.

    ``server_ctx`` says whether the file looks like server-side
    request-handling code (resolved once per file by the caller). Sinks that
    also exist in the browser — ``fetch``, ``http.get`` — only count as SSRF
    inside server code; without that gate every Angular service method scored.
    """
    # Check surrounding context for URL validation
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SSRF_PATTERNS.search(context):
        return

    reason = _ssrf_reason(line, line_num, lines, server_ctx)
    if reason is None:
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.injection.ssrf",
        "category": "CWE-918",
        "title": "Server-side request forgery (SSRF)",
        "description": f"{reason} at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Validate URLs against an allowlist of permitted hosts/schemes",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "918"))


def _ssrf_reason(
    line: str, line_num: int, lines: list[str], server_ctx: bool,
) -> str | None:
    """Return a description fragment when the line is an SSRF sink, else None."""
    for pattern in _SSRF_SERVER_ONLY_PATTERNS:
        if pattern.search(line):
            return "User-controlled URL in server request"
    if not server_ctx:
        return None
    for pattern in _SSRF_CLIENT_CAPABLE_PATTERNS:
        if pattern.search(line):
            return "User-controlled URL in server request"
    ident = _ssrf_taint_hop(line, line_num, lines)
    if ident is not None:
        return (
            f"Request-controlled value `{ident}` (assigned from req.body/query/"
            f"params above) is fetched as a URL"
        )
    return None


# ---------------------------------------------------------------------------
# Feature 0070 P7 — A05 injection specialisations
#
# Six reviewed detectors that share one dispatch: a per-extension arm table
# plus a predicate, emitted through a single spec-driven routine (no six
# near-identical `_check_*` functions).
#
# Two rules govern all of them:
#
#  * **Qualified taint only.** A bare word `request` inside a +/-4-line window
#    means "the word request is nearby"; measured across four codebases it
#    contributed ZERO recall at 69 argv-spawn sites while carrying the whole
#    FP surface. Every taint test below names the accessor.
#  * **No row stacking.** Skill findings are not cross-deduplicated
#    (`_deduplicate_findings` is LLM-vs-skill only), so a child specialisation
#    must yield to the sibling that already owns the line: CWE-564 stands down
#    when a CWE-89 pattern matches, CWE-88 when the line is the CWE-78
#    `new ProcessBuilder(` / shell-argv[0] shape, CWE-470 when
#    `obfuscation.computed_import` already reports the `__import__(var)` form.
# ---------------------------------------------------------------------------

_JS_EXTENSIONS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts",
})
_JVM_EXTENSIONS = frozenset({".java", ".kt", ".kts"})
_PHP_EXTENSIONS = frozenset({".php", ".phtml"})
_MARKUP_EXTENSIONS = frozenset({
    ".html", ".htm", ".hbs", ".handlebars", ".ejs", ".mustache", ".twig",
    ".liquid", ".njk", ".vue", ".svelte", ".astro", ".pug", ".jade",
})

# Extension-keyed arms: (extensions, pattern). A rule is only allowed to look
# at a line whose language can express it — per-rule scoping, never a
# module-wide extension widening.
_ExtArms = tuple[tuple[frozenset[str], re.Pattern], ...]


@dataclass(frozen=True)
class _LineCtx:
    """One line of one file, with the file context a predicate may consult."""

    path: Path
    ext: str
    line: str
    line_num: int
    lines: list[str]


def _window_text(lines: list[str], line_num: int, radius: int) -> str:
    """Text of the +/-``radius`` line window centred on ``line_num``."""
    start = max(0, line_num - 1 - radius)
    return "\n".join(lines[start:min(len(lines), line_num + radius)])


def _matches_arm(ctx: _LineCtx, arms: _ExtArms) -> bool:
    """True when an arm whose extension set contains this file's extension
    matches the line."""
    for extensions, pattern in arms:
        if ctx.ext in extensions and pattern.search(ctx.line):
            return True
    return False


# Request-controlled accessors, named rather than guessed.
_QUALIFIED_TAINT = re.compile(
    r"req(?:uest)?\.(?:body|query|params|args|form|files|GET|POST)"
    r"|getParameter\s*\("
    r"|\$_(?:GET|POST|REQUEST)\b"
    r"|\br\.(?:URL|FormValue|PostFormValue)\b"
    r"|\bc\.(?:Query|Param|PostForm)\s*\("
)
_TAINT_RADIUS = 4


def _has_request_taint(ctx: _LineCtx) -> bool:
    """True when a qualified request accessor is visible on the line or within
    ``_TAINT_RADIUS`` lines of it."""
    return bool(
        _QUALIFIED_TAINT.search(
            _window_text(ctx.lines, ctx.line_num, _TAINT_RADIUS)
        )
    )


# ── CWE-564: SQL injection through Hibernate / JPA query construction ──
#
# `createQuery` / `createNativeQuery` / `createSQLQuery` / Spring Data `@Query`
# with a concatenated operand. None of the CWE-89 patterns above match these
# shapes (they key on a `query|sql|stmt =` assignment, `.format(`, `Sprintf` or
# a backtick literal), so this is new detection rather than a relabel.
_HQL_SINK = re.compile(
    r"\b(?:createQuery|createNativeQuery|createSQLQuery)\s*\(|@Query\s*\("
)
# The generic-DAO idiom: the concatenated operand is derived from the entity
# TYPE, not from a request. `createQuery("from " + entityClass.getSimpleName())`
# is a standard Hibernate base class and is not injectable.
_HQL_TYPE_DERIVED = re.compile(
    r"\.getSimpleName\s*\(|\.getName\s*\(|\.class\b"
    r"|\bentityName\b|\bpersistentClass\b|\bentityClass\b"
)
_HQL_OPERAND = re.compile(r"\+\s*([A-Za-z_$][\w$.]*)")
_HQL_CONSTANT_OPERAND = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _cwe89_owns_line(line: str) -> bool:
    """True when an existing CWE-89 pattern already matches — that row is
    emitted by ``_check_sql``, so the 564 specialisation must not stack on it."""
    return any(pattern.search(line) for pattern in SQL_INJECTION_PATTERNS)


def _hql_has_dynamic_operand(line: str) -> bool:
    """True when the query text is extended by an interpolation or by a
    concatenated operand that is not an UPPER_CASE constant."""
    if "${" in line:
        return True
    return any(
        not _HQL_CONSTANT_OPERAND.match(operand.split(".")[0])
        for operand in _HQL_OPERAND.findall(line)
    )


def _is_hql_injection(ctx: _LineCtx) -> bool:
    """CWE-564: a Hibernate/JPA query sink with a non-constant, non-type-derived
    concatenated operand (or a `${}` template interpolation)."""
    if not _HQL_SINK.search(ctx.line) or _cwe89_owns_line(ctx.line):
        return False
    if _HQL_TYPE_DERIVED.search(ctx.line):
        return False
    return _hql_has_dynamic_operand(ctx.line)


# ── CWE-80: template escape hatches ──
#
# Every "non-literal argument" lookahead excludes `)` as well as whitespace and
# quotes. Without it `mark_safe()` / `template.HTML()` match, which turns a
# remediation string ("Remove |safe filter or mark_safe() call") into a
# finding — measured, in a sibling skill's own source.
#
# `.jinja` / `.j2` are in neither CODE_EXTENSIONS nor WHITELIST_EXTENSIONS, so
# Jinja files only reach this rule via VULTURE_EXTRA_EXTENSIONS.
_TPL_SAFE_FILTER = re.compile(r"\{\{\s*[^}\n]{0,200}\|\s*(?:safe|raw)\b")
_TPL_MARK_SAFE = re.compile(r"\bmark_safe\s*\(\s*(?![\s'\")])[A-Za-z_$]")
_TPL_GO_HTML = re.compile(
    r"\btemplate\.(?:HTML|JS|CSS|URL|HTMLAttr)\s*\(\s*(?![\s\"`)])[A-Za-z_$]"
)
_TPL_RUBY_RAW = re.compile(r"<%=\s*raw\s+[A-Za-z_@$]|\.html_safe\b")
_TPL_HANDLEBARS_RAW = re.compile(r"\{\{\{\s*[A-Za-z_$]")
_TPL_BLADE_RAW = re.compile(r"\{!!\s*\S")

_TPL_ARMS: _ExtArms = (
    (frozenset({".html", ".htm", ".twig", ".njk", ".liquid", ".jinja", ".j2"}),
     _TPL_SAFE_FILTER),
    (frozenset({".py"}), _TPL_MARK_SAFE),
    (frozenset({".go"}), _TPL_GO_HTML),
    (frozenset({".erb", ".rb"}), _TPL_RUBY_RAW),
    (frozenset({".hbs", ".handlebars", ".mustache"}), _TPL_HANDLEBARS_RAW),
)

# i18n carve-out. The pipe form covers Jinja/Twig; the call form covers the
# actual measured FP shape, Rails `t('welcome.body').html_safe`, which has no
# pipe at all — a catalogue message is developer-authored, not request data.
_TPL_I18N = re.compile(
    r"\|\s*(?:translate|trans|t)\b"
    r"|(?:\bI18n\.t|\bt|\btranslate)\s*\(\s*['\"][^'\"]{1,80}['\"]"
    r"[^)]{0,80}\)\s*\.html_safe"
)


def _is_template_escape_hatch(ctx: _LineCtx) -> bool:
    """CWE-80: output rendered through a template auto-escaping escape hatch."""
    if _TPL_I18N.search(ctx.line):
        return False
    # Blade is gated on the FULL filename: `Path('x.blade.php').suffix` is
    # `.php`, so an extension gate would apply Blade syntax to every PHP file.
    if ctx.path.name.endswith(".blade.php"):
        return bool(_TPL_BLADE_RAW.search(ctx.line))
    return _matches_arm(ctx, _TPL_ARMS)


# ── CWE-88: argument injection ──
#
# argv-LIST sinks only: a shell string is CWE-78 and already emitted. The Java
# `new ProcessBuilder(` sink is deliberately absent — it is character-for-
# character an existing COMMAND_INJECTION_PATTERNS entry.
_ARGV_SINK_ARMS: _ExtArms = (
    (frozenset({".py"}), re.compile(
        r"\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(\s*\["
    )),
    (_JS_EXTENSIONS, re.compile(
        r"\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*[^,\n]{1,60},\s*\["
    )),
    (frozenset({".go"}), re.compile(r"\bexec\.Command(?:Context)?\s*\(")),
    (_JVM_EXTENSIONS, re.compile(r"\.command\s*\(")),
)

# argv[0] naming a shell, or an explicit shell flag, means the weakness is
# CWE-78 command injection and this rule must stand down.
_ARGV_SHELL_ARGV0 = re.compile(
    r"""["'](?:sh|bash|zsh|/bin/(?:sh|bash|zsh)|cmd(?:\.exe)?|powershell)["']"""
)
_ARGV_SHELL_FLAG = re.compile(r"shell\s*=\s*True|shell\s*:\s*true")
# `--` terminates option parsing, so a built element after it cannot be read as
# a flag by the callee.
_ARGV_SEPARATOR = re.compile(r"""["']--["']""")
_ARGV_NUMERIC_CAST = re.compile(
    r"\bint\s*\(|\bparseInt\s*\(|\bNumber\s*\(|strconv\.Atoi|Integer\.parseInt"
)
# The process's own argv is not request data.
_ARGV_SELF_ARGS = re.compile(r"sys\.argv|process\.argv|os\.Args")
_ARGV_VETOES = (
    _ARGV_SHELL_ARGV0, _ARGV_SHELL_FLAG, _ARGV_SEPARATOR,
    _ARGV_NUMERIC_CAST, _ARGV_SELF_ARGS,
)

# An argv element that is BUILT. The option-flag shape is the injectable one
# (`"--output=" + name` lets an attacker rewrite the flag); the generic shape is
# the fallback. Applied to the argument TEXT, so it is defined for variadic Go
# and Java calls that have no bracketed list.
_ARGV_OPTION_BUILT = re.compile(
    r"""["'`]-{1,2}[A-Za-z][\w.-]{0,30}=?["'`]?\s*(?:\+|\$\{)"""
)
_ARGV_GENERIC_BUILT = re.compile(
    r"\+\s*[A-Za-z_$]|\$\{|\.format\s*\(|Sprintf\s*\("
)


def _argv_sink_text(ctx: _LineCtx) -> str | None:
    """Argument text of an argv-list spawn on this line, else None."""
    for extensions, pattern in _ARGV_SINK_ARMS:
        if ctx.ext not in extensions:
            continue
        match = pattern.search(ctx.line)
        if match is not None:
            return ctx.line[match.start():]
    return None


def _argv_vetoed(ctx: _LineCtx, text: str) -> bool:
    """True when the line belongs to CWE-78, is validated, or is not attacker
    reachable."""
    if "new ProcessBuilder" in ctx.line:
        return True
    if _has_validation_context(ctx.lines, ctx.line_num):
        return True
    return any(pattern.search(text) for pattern in _ARGV_VETOES)


def _argv_is_built(text: str) -> bool:
    """True when some argv element is assembled rather than literal."""
    return bool(
        _ARGV_OPTION_BUILT.search(text) or _ARGV_GENERIC_BUILT.search(text)
    )


def _is_argument_injection(ctx: _LineCtx) -> bool:
    """CWE-88: a request value is concatenated into an argv element."""
    text = _argv_sink_text(ctx)
    if text is None or _argv_vetoed(ctx, text):
        return False
    if not _argv_is_built(text):
        return False
    return _has_request_taint(ctx)


# ── CWE-470: unsafe reflection ──
#
# Anchored on class/module SELECTORS only. `.newInstance()` / `.getMethod()` are
# the invocation, not the selection: they take no arguments in the canonical
# `Class.forName(x).newInstance()` pair, so anchoring on them both fires on
# every no-arg reflective instantiation and double-reports the pair.
_REFLECT_ARMS: _ExtArms = (
    (_JVM_EXTENSIONS, re.compile(
        r"\b(?:Class\.forName|ClassLoader\s*\.\s*loadClass|\.loadClass)"
        r"\s*\(\s*(?![\s\"])[A-Za-z_$]"
    )),
    (frozenset({".py"}), re.compile(
        r"\b(?:importlib\.import_module|__import__)\s*\(\s*(?![\s'\")])[A-Za-z_$]"
        r"|\bgetattr\s*\(\s*\w+\s*,\s*(?![\s'\")])[A-Za-z_$]"
    )),
    (_PHP_EXTENSIONS, re.compile(
        r"\bnew\s+\$\w+\b|\bcall_user_func(?:_array)?\s*\(\s*\$"
    )),
    (_JS_EXTENSIONS, re.compile(r"\brequire\s*\(\s*(?![\s'\")])[A-Za-z_$]")),
)
# `shared.tools.obfuscation` already emits `obfuscation.computed_import` for
# exactly this shape, and `check_obfuscation` runs on every file here.
_REFLECT_OBFUSCATION_OWNED = re.compile(r"__import__\s*\(\s*[a-zA-Z_]\w*\s*\)")
# Registry / allowlist / enum lookup and configuration reads: the selector is
# constrained to a known set, so the reflective call is not attacker-directed.
_REFLECT_SAFE = re.compile(
    r"allow(?:ed|list|_list)|whitelist|registry|\bvalueOf\s*\("
    r"|getProperty\s*\(|os\.environ|process\.env|\bsettings\.",
    re.IGNORECASE,
)


def _is_unsafe_reflection(ctx: _LineCtx) -> bool:
    """CWE-470: a class/module selector driven by a request value."""
    if _REFLECT_OBFUSCATION_OWNED.search(ctx.line):
        return False
    if not _matches_arm(ctx, _REFLECT_ARMS):
        return False
    if _REFLECT_SAFE.search(_window_text(ctx.lines, ctx.line_num, _TAINT_RADIUS)):
        return False
    return _has_request_taint(ctx)


# ── CWE-98: PHP file inclusion ──
_PHP_INCLUDE = re.compile(r"\b(?:include|include_once|require|require_once)\b")
_PHP_SUPERGLOBAL = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[")
# A superglobal used only as a map KEY selects from a fixed table — the path
# itself is constant. Generalised: any `$map[$_GET[...]]`, not one hardcoded
# variable name.
_PHP_MAP_KEY = re.compile(r"\$\w+\s*\[\s*\$_(?:GET|POST|REQUEST|COOKIE)")
_PHP_INCLUDE_SAFE = re.compile(
    r"\bbasename\s*\(|\bin_array\s*\(|\brealpath\s*\(|\bswitch\s*\("
    r"|allow(?:ed|list|_list)|whitelist",
    re.IGNORECASE,
)
_PHP_HOP_ASSIGN = re.compile(
    r"\$(\w+)\s*=\s*[^;\n]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)\s*\["
)
_PHP_HOP_LOOKBACK = 10


def _php_include_vetoed(line: str) -> bool:
    """True for the declared-safe shapes: basename/in_array/realpath/switch
    guards, or a superglobal used only as a map key."""
    return bool(_PHP_INCLUDE_SAFE.search(line) or _PHP_MAP_KEY.search(line))


def _php_var_is_path(expr: str, var: str) -> bool:
    """True when ``$var`` appears in the include expression somewhere other than
    as an array subscript. `include $map[$tpl];` uses the tainted value as a
    KEY, which is safe; `include $tpl;` uses it as the path."""
    for match in re.finditer(rf"\${re.escape(var)}\b", expr):
        if not expr[:match.start()].rstrip().endswith("["):
            return True
    return False


def _php_hop_vars(line: str) -> list[str]:
    """Locals assigned from a superglobal on this line.

    Empty when the value is sanitised AT the assignment — `$t =
    basename($_GET['t']);` two lines above `include "tpl/" . $t;` is the
    canonical safe form, and a veto that only inspects the include line cannot
    see it (measured: 1 of 3 clean twins flagged).
    """
    if _PHP_INCLUDE_SAFE.search(line):
        return []
    return _PHP_HOP_ASSIGN.findall(line)


def _php_one_hop_taint(ctx: _LineCtx, expr: str) -> bool:
    """True when the include path names a local assigned from a superglobal
    within the preceding ``_PHP_HOP_LOOKBACK`` lines."""
    start = max(0, ctx.line_num - 1 - _PHP_HOP_LOOKBACK)
    for previous in ctx.lines[start:ctx.line_num - 1]:
        for var in _php_hop_vars(previous):
            if _php_var_is_path(expr, var):
                return True
    return False


def _is_php_file_inclusion(ctx: _LineCtx) -> bool:
    """CWE-98: an include/require whose path is request-controlled, directly or
    through one assignment hop."""
    match = _PHP_INCLUDE.search(ctx.line)
    if match is None or _php_include_vetoed(ctx.line):
        return False
    expr = ctx.line[match.end():]
    if _PHP_SUPERGLOBAL.search(expr):
        return True
    return _php_one_hop_taint(ctx, expr)


# ── CWE-83: script in an attribute ──
#
# The quote class is BACKREFERENCE-relative so nested quotes are crossable:
# `onclick="doThing('${userName}')"` is the commonest real spelling, and a
# `[^"']` class can never reach the interpolation inside it.
_ATTR_EVENTS = (
    r"click|dblclick|change|input|submit|load|error|focus|blur|mouseover"
    r"|mouseout|mouseenter|mouseleave|keyup|keydown|keypress|drop|paste|toggle"
)
_ATTR_INLINE_HANDLER = re.compile(
    rf"\bon(?:{_ATTR_EVENTS})\s*=\s*([\"'])(?:(?!\1)[^\n]){{0,200}}?"
    r"(?:\$\{|\{\{|<%=|<%-|#\{|\{%)"
)
# The interpolated expression must name a plausibly external value...
_ATTR_EXTERNAL_VALUE = re.compile(
    r"param|query|search|user|name|email|title|comment|message|body|input"
    r"|req|request|\.get\(",
    re.IGNORECASE,
)
# ...and must not be a render counter. A loop index passed to an inline handler
# is a per-row idiom in every server-rendered template and is structurally
# identical to a true positive, so it is suppressed by name.
_ATTR_COUNTER = re.compile(r"loop\.|forloop\.|\bindex\b|\bidx\b|\bi\b|\bcounter\b")
_ATTR_EXPR_END = re.compile(r"\}\}|%>|\}|\)")
_ATTR_LOOKAHEAD = 80
# A literal second argument is not a weakness: `setAttribute('onclick',
# 'toggle()')` is static markup.
_ATTR_SET_ATTRIBUTE = re.compile(
    # The lookahead must reject whitespace as well as a quote: with a bare
    # `(?!["'])` the preceding `\s*` simply matches zero characters and the
    # lookahead passes on the space, so `setAttribute('onclick', 'toggle()')`
    # — a literal handler, not a weakness — matched.
    r"\.setAttribute\s*\(\s*[\"']on[a-z]{3,15}[\"']\s*,\s*(?![\s\"'])"
)
_ATTR_JS_SCHEME = re.compile(
    r"""["'`]\s*javascript:[^\n]{0,80}?(?:\$\{|\{\{|<%=|#\{|["'`]\s*\+\s*[A-Za-z_$])"""
)
_ATTR_EXTENSIONS = _JS_EXTENSIONS | _MARKUP_EXTENSIONS | _PHP_EXTENSIONS | frozenset(
    {".erb", ".jinja", ".j2"}
)


def _attr_interpolation_is_external(line: str, match: re.Match) -> bool:
    """True when the interpolation names an external value and is not a render
    counter."""
    tail = line[match.end():match.end() + _ATTR_LOOKAHEAD]
    end = _ATTR_EXPR_END.search(tail)
    expression = tail[: end.start()] if end else tail
    if _ATTR_COUNTER.search(expression):
        return False
    return bool(_ATTR_EXTERNAL_VALUE.search(tail))


def _is_script_in_attribute(ctx: _LineCtx) -> bool:
    """CWE-83: a script-bearing attribute (or `javascript:` URL) assembled from
    a dynamic value."""
    if _ATTR_SET_ATTRIBUTE.search(ctx.line) or _ATTR_JS_SCHEME.search(ctx.line):
        return True
    match = _ATTR_INLINE_HANDLER.search(ctx.line)
    return match is not None and _attr_interpolation_is_external(ctx.line, match)


# ── spec table + single emitter ──


@dataclass(frozen=True)
class _A05Spec:
    """One A05 specialisation: where it may look, what proves it, what it says.

    ``category`` is a LITERAL `CWE-N` string. Building it with an f-string would
    detect correctly and still be reported unreachable — the coverage extractor
    only sees literals.
    """

    category: str
    check_id: str
    severity: str
    title: str
    description: str
    recommendation: str
    extensions: frozenset[str]
    predicate: Callable[[_LineCtx], bool]


_A05_SPECS: tuple[_A05Spec, ...] = (
    _A05Spec(
        category="CWE-564",
        check_id="cwe.injection.hql",
        severity="high",
        title="SQL injection via Hibernate/JPA query concatenation",
        description="HQL/JPQL query assembled by string concatenation",
        recommendation=(
            "Use a named or positional parameter (setParameter) instead of "
            "concatenating the value into the query text"
        ),
        extensions=_JVM_EXTENSIONS,
        predicate=_is_hql_injection,
    ),
    _A05Spec(
        category="CWE-80",
        check_id="cwe.injection.template_escape",
        severity="medium",
        title="Template auto-escaping bypassed for rendered output",
        description="Output marked safe / rendered raw, bypassing HTML escaping",
        recommendation=(
            "Render the value through the template's default escaping, or "
            "sanitize the HTML before marking it safe"
        ),
        extensions=frozenset({".py", ".go", ".erb", ".rb", ".hbs", ".handlebars",
                              ".mustache", ".html", ".htm", ".twig", ".njk",
                              ".liquid", ".jinja", ".j2", ".php", ".phtml"}),
        predicate=_is_template_escape_hatch,
    ),
    _A05Spec(
        category="CWE-88",
        check_id="cwe.injection.argument",
        severity="high",
        title="Argument injection into a spawned process",
        description="Request value concatenated into an argv element",
        recommendation=(
            "Pass the value as its own argv element, place it after a `--` "
            "option terminator, and validate it against an allowlist"
        ),
        extensions=frozenset({".py", ".go"}) | _JS_EXTENSIONS | _JVM_EXTENSIONS,
        predicate=_is_argument_injection,
    ),
    _A05Spec(
        category="CWE-470",
        check_id="cwe.injection.reflection",
        severity="high",
        title="Unsafe reflection: class/module selected from request data",
        description="Reflective class or module selector driven by request data",
        recommendation=(
            "Map the request value to a class through an explicit allowlist "
            "instead of resolving it reflectively"
        ),
        extensions=frozenset({".py"}) | _JS_EXTENSIONS | _JVM_EXTENSIONS
        | _PHP_EXTENSIONS,
        predicate=_is_unsafe_reflection,
    ),
    _A05Spec(
        category="CWE-98",
        check_id="cwe.injection.php_include",
        severity="critical",
        title="PHP file inclusion with a request-controlled path",
        description="include/require path derived from a superglobal",
        recommendation=(
            "Resolve the value through a fixed map of allowed templates; never "
            "pass request data to include/require"
        ),
        extensions=_PHP_EXTENSIONS,
        predicate=_is_php_file_inclusion,
    ),
    _A05Spec(
        category="CWE-83",
        check_id="cwe.injection.attr_script",
        severity="medium",
        title="Script-bearing attribute built from a dynamic value",
        description=(
            "Event-handler attribute or javascript: URL assembled from an "
            "interpolated value"
        ),
        recommendation=(
            "Bind the handler in script (addEventListener) and pass the value "
            "as data, JavaScript-escaping it if it must be inlined"
        ),
        extensions=_ATTR_EXTENSIONS,
        predicate=_is_script_in_attribute,
    ),
)


def _a05_finding(spec: _A05Spec, ctx: _LineCtx) -> dict:
    """Build the finding dict for a matched spec."""
    return {
        "severity": spec.severity,
        "check_id": spec.check_id,
        "category": spec.category,
        "title": spec.title,
        "description": f"{spec.description} at line {ctx.line_num}",
        "file_path": str(ctx.path),
        "line_start": ctx.line_num,
        "line_end": ctx.line_num,
        "recommendation": spec.recommendation,
        "requires_context": True,
        "code_snippet": extract_snippet(ctx.lines, ctx.line_num),
    }


def _check_a05_specialisations(ctx: _LineCtx, findings: list[dict]) -> None:
    """Emit at most ONE A05 specialisation row for this line (P5: skill
    findings are not deduplicated against each other, so the specs are ordered
    and the first match wins)."""
    for spec in _A05_SPECS:
        if ctx.ext not in spec.extensions or not spec.predicate(ctx):
            continue
        findings.append(
            enrich_finding(_a05_finding(spec, ctx), spec.category.split("-")[1])
        )
        return


check_injection_tool = function_tool(check_injection)
