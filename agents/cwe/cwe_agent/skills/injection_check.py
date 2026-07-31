"""CWE injection vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
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
    # uncovered: juice-shop's login and search routes — textbook
    # template-literal SQL injection — produced zero CWE-89 findings.
    # Requiring BOTH a DML keyword and a `${` keeps static template
    # literals and parameterised calls (which use quotes, not backticks)
    # out of the results.
    re.compile(r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`]*\$\{", re.IGNORECASE),
    # Feature 0070: the previous clause-only branch was
    #   `[^`]*\$\{[^`]*\b(?:FROM|WHERE|VALUES|SET)\b[^`]*`
    # under re.IGNORECASE. English prose is full of those words, so it fired
    # on "instructions on how to *set* up and configure the Alchemy API" and
    # "the bonus points *from* this order will be added" — 3 CRITICAL false
    # positives on juice-shop and zero true positives (both genuine SQLi
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
#     paired with a `bypassSecurityTrustHtml` value (juice-shop does exactly
#     that). The negative lookahead drops pure-i18n bindings whose expression
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
# Proximity alone is not enough. On juice-shop a bare +/-15-line window
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
# Feature 0070. The old single list produced 29 rows on juice-shop, all 29
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

# Feature 0070, item 3: one-hop taint. juice-shop's single real SSRF is
#   routes/profileImageUrlUpload.ts:19  const url = req.body.imageUrl
#   routes/profileImageUrlUpload.ts:24  const response = await fetch(url)
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
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for injection patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    lang = detect_language(str(file_path))
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

    This is what recovers juice-shop's only genuine SSRF: the request value is
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


check_injection_tool = function_tool(check_injection)
