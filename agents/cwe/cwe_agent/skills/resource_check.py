"""Resource management vulnerability detection skill."""

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

from cwe_agent.catalog import enrich_finding

# CWE-476: NULL pointer dereference.
#
# The Go pattern previously used `\(.*\)\s*$` which produces ReDoS
# backtracking on long assignment lines with many parens. Tighten to
# `[^()]*` inside the call so quantifier expansion is bounded.
NULL_DEREF_PATTERNS = [
    re.compile(r"(\w+)\s*:=\s*\w+\.\w+\([^()]*\)\s*$"),  # Go: no nil check after call
    re.compile(r"\*(\w+)\s*(?:=|\.)"),  # Pointer dereference
]
GO_NIL_CHECK = re.compile(r"if\s+\w+\s*[!=]=\s*nil")

# Feature 0085. A Go `:=` assignment is not a nil dereference on its own — it is
# just a variable binding, and most bind a value type that can never be nil
# (`os.Getenv` returns string, `DetectMode()` returns a named scalar). Measured
# on the Vulture tree: 345 of 345 CWE-476 rows were exactly that, all at HIGH.
#
# What makes it a candidate is that the bound name is later USED AS A POINTER:
# `v.Field`, `*v`, or `v[...]`. That is the shape the protected E2E fixture
# encodes (`val := obj.GetItem()` / `val.Use()`), and it is the shape of the real
# bug (error discarded, value dereferenced anyway).
GO_DEREF_OF = "(?:\\*{v}\\b|\\b{v}\\.\\w|\\b{v}\\[)"

# The FIRST bound name, which is the value; the second is conventionally the
# error. NULL_DEREF_PATTERNS[0]'s own capture group takes the LAST `\w+` before
# `:=`, so on `req, _ := http.NewRequest(...)` it captured `_` — harmless while
# nothing read the group, wrong the moment the deref check does.
GO_ASSIGN_FIRST = re.compile(
    r"^\s*(?P<first>[A-Za-z_]\w*)\s*(?:,\s*(?P<second>[A-Za-z_]\w*)\s*)?:="
)

# `x := pkg.NewThing(...)` — the Go constructor convention (single value only).
GO_NEW_CTOR = re.compile(r":=\s*[\w.]*\bNew[A-Z]\w*\s*\(")

# Go stdlib constructors documented to ALWAYS return a usable non-nil value.
# Dereferencing one is correct Go, not a defect. Purely suppressive: this list
# can only remove findings, never add them, so a wrong entry costs recall on one
# call shape rather than manufacturing noise. Drawn from the residual measured
# on the Vulture tree after the dereference gate (bufio.NewScanner, hmac.New,
# flag.NewFlagSet and similar accounted for most of the remaining 100).
GO_NEVER_NIL_CALL = re.compile(
    r"""(?:^|[^\w.])(?:
          bufio\.New\w+ | bytes\.New\w+ | strings\.New\w+ | errors\.New
        | hmac\.New | sha1\.New | sha256\.New | sha512\.New | md5\.New | fnv\.New\w+
        | flag\.NewFlagSet | log\.New | tabwriter\.NewWriter
        | json\.NewEncoder | json\.NewDecoder | csv\.NewReader | csv\.NewWriter
        | time\.\w+ | strconv\.\w+ | filepath\.\w+ | fmt\.\w+
        | strings\.\w+ | exec\.\w+ | context\.\w+ | sort\.\w+ | utf8\.\w+
        | make | new | len | cap | append
      )\s*\(""",
    re.VERBOSE,
)

# A nil guard need not be spelled `if x != nil`. Go writes it in `return`
# expressions, `&&` chains, assignments and switch cases just as often.
# GO_NIL_CHECK's literal `if` missed all of those; measured, two of four sampled
# survivors on the Vulture tree were guarded this way. Variable-specific, unlike
# GO_NIL_CHECK, so an unrelated `err != nil` no longer clears a real finding.
GO_VAR_NIL_GUARD = re.compile(r"\b{v}\s*[!=]=\s*nil|\bnil\s*[!=]=\s*{v}\b")

# A nil slice/map has len 0, so a length guard is a real nil guard.
GO_LEN_GUARD = re.compile(r"\blen\(\s*{v}\s*\)")
_DEREF_SCAN_LINES = 12


def _go_var_is_dereferenced(var: str, lines: list[str], line_num: int) -> bool:
    """True when ``var`` is later used in a position that would fault if nil."""
    import re as _re
    pat = _re.compile(GO_DEREF_OF.format(v=_re.escape(var)))
    end = min(line_num + _DEREF_SCAN_LINES, len(lines))
    return any(pat.search(l) for l in lines[line_num:end])

# CWE-400: Uncontrolled resource consumption
RESOURCE_CONSUMPTION_PATTERNS = [
    re.compile(r"for\s*\{", re.IGNORECASE),  # Go: infinite loop
    re.compile(r"while\s*(?:True|1)\s*:"),  # Python: infinite loop
    re.compile(r"while\s*\(\s*(?:true|1)\s*\)"),  # C/Java: infinite loop
]
# An exit path OR a yield to the scheduler. `await` and `yield` belong here:
# an awaiting loop is a standard polling/consumer pattern, not a spin — it
# releases the event loop on every iteration. Measured on juice-shop, every one
# of the 17 CWE-400 rows was a bounded loop of this shape, reported at HIGH.
BREAK_OR_RETURN = re.compile(
    r"\b(?:break|return|sys\.exit|os\.Exit|await|yield)\b"
)

# How far to read for an exit path. A loop whose exit is more than this many
# lines away is not "visible" in the sense the finding claims.
_LOOP_BODY_SCAN_LINES = 40

# Extensions the infinite-loop patterns must NOT run against. These regexes are
# language-specific — `for\s*\{` is Go, `while True:` is Python — and markup is
# neither. Measured on juice-shop: after the exit-path guard removed 16 bounded
# loops, the ONE remaining CWE-400 was the Go pattern matching English prose,
# "Our Privacy Policy for {{applicationName}} is", in an Angular template.
_LOOP_PATTERN_SKIP_SUFFIXES = frozenset({
    ".html", ".htm", ".xhtml", ".vue", ".svelte",
    ".md", ".markdown", ".rst", ".txt", ".adoc",
})


def _loop_has_visible_exit(lines: list[str], line_num: int) -> bool:
    """True when the loop opened at ``line_num`` shows an exit path or a
    scheduler yield within the next few lines.

    The finding's own description says "Unbounded loop without visible exit",
    and BREAK_OR_RETURN has existed since the rule was written — but nothing
    ever called it, so every infinite-loop KEYWORD was reported regardless of
    its body. This makes the code match the sentence.
    """
    start = line_num  # 1-indexed line_num -> the line AFTER the loop header
    for probe in lines[start:start + _LOOP_BODY_SCAN_LINES]:
        if BREAK_OR_RETURN.search(probe):
            return True
    return False

# CWE-404: Improper resource shutdown
#
# The verb alone is not enough — this is the same defect the CWE-754 fix in
# error_handling_check.py cured. A bare `(?:open|fopen)\s*\(` matched every
# method whose name merely *ends* with "open": in one sweep 82 of 84 rows
# were `snackBarHelperService.open(...)`, `dialog.open(...)`,
# `window.open(...)` and friends — UI calls, not resources.
#
# Three parts are needed together:
#   1. a receiver guard on the builtin form, so only a *bare* open/fopen
#      call (no `foo.` / `$foo` prefix) qualifies;
#   2. a real-resource-namespace branch, because the bare form alone loses
#      the `fs.createWriteStream` / `fs.createReadStream` stream family
#      (5 genuine sites in the same sweep) — dropping those would be an
#      over-correction, not a narrowing;
#   3. a declaration skip, because `open (` at the START of a line is a
#      method DECLARATION, not a call that leaks a handle.
_RES_NS = r"(?:fs|fsPromises|net|os|io|ioutil|sql|pgx|mongo|gorm)"

RESOURCE_OPEN_PATTERNS = [
    # Bare builtin open()/fopen() — no receiver before it.
    re.compile(r"(?<![\w.$])(?:open|fopen)\s*\("),
    # Real resource namespaces: fs.createWriteStream, os.Open, os.Create,
    # fs.createReadStream, sql.Open, mongo.Connect...
    re.compile(rf"\b{_RES_NS}\.(?:[Oo]pen|[Cc]reate)\w*\s*\("),
    re.compile(r"\b(?:sql\.Open|pgx\.Connect|mongo\.Connect)\s*\("),
    re.compile(r"\bnet\.(?:Dial|Listen)\s*\("),
]

# `open (...)` / `public open (): void {` at line start is a declaration.
RESOURCE_OPEN_DECL = re.compile(
    r"^\s*(?:(?:public|private|protected|static|async|export|function|def)\s+)*"
    r"open\s*\("
)

# Markup is never a resource-shutdown site: `(click)="open()"` is a template
# binding to a component method.
_MARKUP_SUFFIXES = frozenset({".html", ".htm"})
RESOURCE_CLOSE_SAFE = re.compile(
    r"\b(?:defer\s|\.close\(\)|\.Close\(\)|with\s+open|context\s*manager)\b",
    re.IGNORECASE,
)

# CWE-770: Allocation without limits
UNBOUNDED_ALLOC_PATTERNS = [
    re.compile(r"\.append\(.*\)\s*$"),  # Python list append in loop
    re.compile(r"make\(\[\]\w+,\s*0\)"),  # Go: unbounded slice
]
SIZE_LIMIT = re.compile(r"\b(?:max_size|maxlen|capacity|limit|MAX_)\b", re.IGNORECASE)

# Feature 0085. `.append(` alone is not allocation without limits — it is the
# ordinary way to build any list. The pattern's own comment has always said
# "Python list append in loop", but the loop was never checked. Measured on the
# Vulture tree: 466 of 469 CWE-770 rows were bare appends, 114 of them appending
# a string LITERAL outside any loop.
#
# The weakness needs repetition, so the append must sit inside a loop. Scoped to
# Python because the indentation walk below is only sound where indentation IS
# the block syntax — and in JS/TS `.append()` is a DOM/FormData call that
# allocates nothing.
_PY_SUFFIXES = frozenset({".py", ".pyi"})
_PY_LOOP_HEADER = re.compile(r"^\s*(?:for\b|while\b)")
_PY_SCOPE_HEADER = re.compile(r"^\s*(?:def\b|class\b|async\s+def\b)")
_LOOP_LOOKBACK_LINES = 30


def _py_append_is_in_a_loop(lines: list[str], line_num: int) -> bool:
    """True when the statement at ``line_num`` is inside a for/while block.

    Walks back for a header at a STRICTLY smaller indent, stopping at the
    enclosing def/class — a loop in a different function is not this
    statement's loop.
    """
    idx = line_num - 1
    if idx < 0 or idx >= len(lines):
        return False
    indent = len(lines[idx]) - len(lines[idx].lstrip())
    for j in range(idx - 1, max(-1, idx - _LOOP_LOOKBACK_LINES), -1):
        cur = lines[j]
        if not cur.strip():
            continue
        cur_indent = len(cur) - len(cur.lstrip())
        if cur_indent >= indent:
            continue
        if _PY_LOOP_HEADER.search(cur):
            return True
        if _PY_SCOPE_HEADER.search(cur):
            return False
    return False

IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")

# CWE-379: creation of a temporary file/directory at a PREDICTABLE path inside
# a shared, world-writable temp directory.
#
# The weakness is not "a temp file exists" — it is that the path is guessable
# AND its parent is writable by every local account, so another user can
# pre-create, symlink or read the entry before the owner touches it. Two
# idioms express exactly that, and both are content-keyed:
#
#   arm 1  a FIXED name joined onto the platform temp-dir accessor
#          (`filepath.Join(os.TempDir(), "app-ssh")`)
#   arm 2  a hardcoded `/tmp`-family literal handed to a create/write sink
#          (`open('/tmp/app-export.csv', 'w')`)
#
# Both arms are cleared by any secure-temp API, because those generate an
# unpredictable name inside a 0700 directory, and by any randomiser in the
# name — an unguessable entry in a shared directory is a different (and much
# weaker) exposure than a fixed one.
_TEMP_ROOT = re.compile(
    r"\bos\.TempDir\s*\(\s*\)|"                             # Go
    r"\bos\.tmpdir\s*\(\s*\)|"                              # Node
    r"\btempfile\.gettempdir\s*\(\s*\)|"                    # Python
    r"\bPath\.GetTempPath\s*\(\s*\)|"                       # C#
    r"getProperty\s*\(\s*['\"]java\.io\.tmpdir['\"]\s*\)"   # Java
)

# The root has to be COMBINED with a name for a path to be built from it; a
# bare read of the temp directory (`fs.readdirSync(os.tmpdir(), 'utf8')`) is
# not a creation site, and without this arm that line's `'utf8'` argument
# would read as the fixed name.
_JOIN_OR_CONCAT = re.compile(
    r"\.[Jj]oin\s*\(|"      # filepath.Join / path.join / os.path.join
    r"\bPaths\.get\s*\(|"   # Java NIO
    r"\.resolve\s*\(|"      # Java Path.resolve
    r"\bnew\s+File\s*\(|"   # Java legacy
    r"\+\s*['\"`]"          # string concatenation
)

# A FIXED path component: name characters only. A format placeholder (`%d`),
# a brace template (`{}` / `${...}`) or an interpolation therefore never reads
# as fixed, which is the point — those names are not guessable.
_FIXED_SEGMENT = re.compile(r"['\"`](/?[A-Za-z0-9][\w.\-]*(?:/[\w.\-]+)*)['\"`]")

# Arm 2 anchor. The literal must BE the path (it starts at the quote) and must
# carry a child component, so `'/tmp'` alone — the directory itself — and a
# log message that merely mentions a path both stay clear.
_TEMP_PATH_LITERAL = re.compile(
    r"['\"`](/(?:tmp|var/tmp|usr/tmp|dev/shm)/[\w.\-][^'\"`]*)['\"`]"
)

_TEMP_FILE_SINK = re.compile(
    r"(?<![\w.$])(?:open|fopen|creat|mkdir|makedirs|touch)\s*\(|"
    r"\b(?:os|fs|fsPromises|ioutil|shutil)\."
    r"(?:[Oo]pen\w*|[Cc]reate\w*|[Ww]rite\w*|[Mm]kdir\w*|makedirs|append\w*|copy\w*)\s*\(|"
    r"\bcreateWriteStream\s*\(|"
    r"\bnew\s+File(?:Writer|OutputStream)\s*\(|"
    r"\bFiles\.(?:write|newOutputStream|createFile|createDirector\w+)\s*\(|"
    r"\.write_(?:text|bytes)\s*\("
)

# Secure-temp APIs: every one of these mints an unpredictable name (and, on
# POSIX, an owner-only directory), which is the recommended fix — so their
# presence on the line is the clean twin of both arms.
_SECURE_TEMP_API = re.compile(
    r"\b(?:MkdirTemp|CreateTemp|TempFile|mkdtemp\w*|mkstemp\w*|"
    r"NamedTemporaryFile|SpooledTemporaryFile|TemporaryFile|TemporaryDirectory|"
    r"createTempFile|createTempDirectory|GetTempFileName|tmpfile)\s*\("
)

_UNPREDICTABLE_NAME = re.compile(
    r"uuid|nanoid|Math\.random|randomUUID|random_|randomBytes|"
    r"\brand\b|\brandom\b|secrets\.|token_hex|"
    r"[Gg]etpid|process\.pid|Date\.now|time\.Now",
    re.IGNORECASE,
)

# CWE-799: Improper control of interaction frequency (missing rate limiting).
# Auth-related endpoints without any rate limiter in the SAME file. This is
# the OWASP A04/A06 rate-limiting contributor (feature 0063). Suppression is
# file-scoped — a limiter reference anywhere in the file clears the file —
# which is narrower and less false-positive-prone than a project-wide check.
AUTH_ENDPOINT_DEF = re.compile(
    r"^\s*(?:async\s+)?(?:def|func)\s+"
    r"(?:login|signin|sign_in|signup|sign_up|register|authenticate|"
    r"reset_password|forgot_password|change_password)\b",
    re.IGNORECASE,
)
RATE_LIMIT_HINT = re.compile(
    r"rate[_-]?limit|throttl|ratelimiter|slowapi|\bLimiter\s*\(|"
    r"flask[_-]limiter|express[_-]rate",
    re.IGNORECASE,
)

# AUTH_ENDPOINT_DEF above is anchored to `def` / `func`, so no Express route
# can ever match it — Broken Anti Automation was a structurally blind
# category on Node codebases. This is the route-REGISTRATION form.
EXPRESS_AUTH_ROUTE = re.compile(
    r"\b(?:app|router|server)\s*\.\s*(?:post|put|patch|get)\s*\(\s*['\"`]"
    # The auth keyword must be a delimited path segment, not any substring:
    # `/rest/saveLoginIp` is not a credential endpoint even though "Login"
    # occurs inside it.
    r"(?P<path>[^'\"`]*(?<![A-Za-z0-9])"
    r"(?:login|register|reset-?password|forgot-?password|"
    r"change-?password|signin|sign-?in|signup|sign-?up)"
    r"(?![A-Za-z0-9])[^'\"`]*)['\"`]",
    re.IGNORECASE,
)
# Broader than RATE_LIMIT_HINT: Express limiters are usually named middleware
# (`loginLimiter`), which carries no "rate" token.
LIMITER_TOKEN = re.compile(
    r"limiter|rate[_-]?limit|throttl|slow[_-]?down|brute[_-]?force",
    re.IGNORECASE,
)
QUOTED_ROUTE_PATH = re.compile(r"['\"`](/[^'\"`]*)['\"`]")

# CWE-807: reliance on an untrusted input for a security decision — a rate
# limiter keyed on a client-controlled header can be bypassed by spoofing it.
KEY_GENERATOR = re.compile(r"\bkeyGenerator\b")
SPOOFABLE_CLIENT_HEADER = re.compile(
    r"headers\s*(?:\[\s*['\"`]\s*|\.\s*get\s*\(\s*['\"`]\s*|\.\s*)"
    r"(?:x-)?(?:forwarded-for|forwarded|real-ip|client-ip|true-client-ip|"
    r"cf-connecting-ip)",
    re.IGNORECASE,
)


def _should_skip(file_path: Path) -> bool:
    """True for files whose resource patterns cannot be real leaks.

    ``is_prose_file`` is the third arm: nothing in a document is ever opened,
    so nothing in it can leak. Measured on a prose file that merely quotes an
    unclosed ``open()`` as the thing not to do: 2 false CWE-404 rows.
    """
    return is_generated_file(file_path) or is_test_file(file_path) or is_prose_file(file_path)


def check_resource_management(source_path: str) -> dict:
    """Check for resource management vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of resource management issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if _should_skip(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for resource management issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _analyze_line(file_path, line, line_num, lines, findings)
    # File-scoped: rate limiting is a whole-file property, checked once.
    _check_rate_limiting(file_path, lines, findings)


def _analyze_line(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Run every per-line resource check against one already-filtered line."""
    _check_resource_consumption(file_path, line, line_num, lines, findings)
    # Rule 6 (no row stacking): CWE-379 keys on the same `open(` /
    # `fs.create*` verbs as CWE-404, and CWE-379 is not a catalog descendant
    # of CWE-404, so the two would be a duplicate row rather than a
    # collapsible ancestor pair. The temp-directory row is the more specific
    # defect, so it claims the line and CWE-404 stands down.
    if not _check_insecure_temp_dir(file_path, line, line_num, lines, findings):
        _check_improper_shutdown(file_path, line, line_num, lines, findings)
    _check_null_deref(file_path, line, line_num, lines, findings)
    _check_unbounded_alloc(file_path, line, line_num, lines, findings)


def _check_rate_limiting(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """File-scoped rate-limiting checks (CWE-799 / CWE-807)."""
    _check_def_rate_limiting(file_path, lines, findings)
    _check_express_rate_limiting(file_path, lines, findings)
    _check_spoofable_limiter_key(file_path, lines, findings)


def _limiter_protected_paths(lines: list[str]) -> set[str]:
    """Route paths that a limiter registration in this file mentions.

    `app.use('/rest/user/reset-password', rateLimit({...}))` protects that
    path (and everything under it), but says nothing about `/rest/user/login`
    — so suppression for the Express form is PATH-scoped, not file-scoped.
    """
    protected: set[str] = set()
    for line in lines:
        if COMMENT_INDICATORS.match(line):
            continue
        if not LIMITER_TOKEN.search(line):
            continue
        protected.update(QUOTED_ROUTE_PATH.findall(line))
    return protected


def _is_path_protected(route_path: str, protected: set[str]) -> bool:
    """True when a limiter covers this route path (exact or prefix mount)."""
    normalized = route_path.rstrip("/") or "/"
    for mount in protected:
        base = mount.rstrip("/") or "/"
        if normalized == base or normalized.startswith(base + "/"):
            return True
    return False


def _check_express_rate_limiting(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Auth route registered on an Express app with no limiter (CWE-799)."""
    protected = _limiter_protected_paths(lines)
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        match = EXPRESS_AUTH_ROUTE.search(line)
        if match is None:
            continue
        if LIMITER_TOKEN.search(line):
            continue
        route_path = match.group("path")
        if _is_path_protected(route_path, protected):
            continue
        finding = {
            "severity": "medium",
            "check_id": "cwe.resource.express_rate_limit",
            "category": "CWE-799",
            "title": "Authentication route registered without rate limiting",
            "description": (
                f"Express route '{route_path}' at line {line_num} is an "
                "authentication endpoint with no rate limiter applied to it"
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Mount a rate limiter (e.g. express-rate-limit) on this route "
                "to resist credential stuffing and brute-force automation"
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "799"))


def _check_spoofable_limiter_key(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Rate-limit identity derived from a client-controlled header (CWE-807)."""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if not KEY_GENERATOR.search(line):
            continue
        window_end = min(line_num + 4, len(lines))
        window = "\n".join(lines[line_num - 1 : window_end])
        if not SPOOFABLE_CLIENT_HEADER.search(window):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.spoofable_rate_limit_key",
            "category": "CWE-807",
            "title": "Rate limiter keyed on a client-controlled header",
            "description": (
                f"keyGenerator at line {line_num} derives the rate-limit "
                "identity from a request header the client can set, so the "
                "limit is trivially bypassed by varying that header"
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Key the limiter on the trusted peer address (req.ip with a "
                "correctly configured trust-proxy hop count) or an "
                "authenticated identity, never on a raw client header"
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "807"))


def _check_def_rate_limiting(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Check for missing rate limiting on auth endpoints (CWE-799).

    File-scoped: if any line in this file references a rate limiter, the
    whole file is considered protected and no finding is raised.
    """
    if any(RATE_LIMIT_HINT.search(line) for line in lines):
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if not AUTH_ENDPOINT_DEF.match(line):
            continue
        finding = {
            "severity": "medium",
            "check_id": "cwe.resource.rate_limit",
            "category": "CWE-799",
            "title": "Improper control of interaction frequency (missing rate limiting)",
            "description": (
                f"Authentication-related endpoint at line {line_num} with no "
                "rate limiting in this file"
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Apply rate limiting/throttling to authentication endpoints to "
                "resist brute-force and abuse"
            ),
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "799"))


def _joined_temp_path(line: str) -> str | None:
    """Arm 1 — a fixed name combined with the platform temp-dir accessor."""
    root = _TEMP_ROOT.search(line)
    if root is None or not _JOIN_OR_CONCAT.search(line):
        return None
    segment = _FIXED_SEGMENT.search(line, root.end())
    return segment.group(1) if segment else None


def _predictable_temp_path(line: str) -> str | None:
    """The predictable shared-temp path this line builds, if any (CWE-379)."""
    if _SECURE_TEMP_API.search(line) or _UNPREDICTABLE_NAME.search(line):
        return None
    literal = _TEMP_PATH_LITERAL.search(line)
    if literal is not None and _TEMP_FILE_SINK.search(line):
        return literal.group(1)
    return _joined_temp_path(line)


def _check_insecure_temp_dir(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> bool:
    """Temp file/dir at a predictable path in a shared directory (CWE-379).

    Returns True when the line was claimed, so the caller can keep the
    one-row-per-line invariant against the CWE-404 arm.
    """
    target = _predictable_temp_path(line)
    if target is None:
        return False
    finding = {
        "severity": "medium",
        "check_id": "cwe.resource.insecure_temp_dir",
        "category": "CWE-379",
        "title": "Temporary file created at a predictable path in a shared directory",
        "description": (
            f"Line {line_num} builds '{target}' inside a world-writable "
            "temp directory using a fixed name, so any local account can "
            "pre-create, symlink or read that entry"
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Create temporary files through the platform's secure API "
            "(os.MkdirTemp/os.CreateTemp, tempfile.mkstemp/mkdtemp, "
            "fs.mkdtemp, Files.createTempFile), which mints an unpredictable "
            "name in an owner-only directory"
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "379"))
    return True


def _check_resource_consumption(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for uncontrolled resource consumption (CWE-400)."""
    if file_path.suffix.lower() in _LOOP_PATTERN_SKIP_SUFFIXES:
        return
    for pattern in RESOURCE_CONSUMPTION_PATTERNS:
        if not pattern.search(line):
            continue
        if _loop_has_visible_exit(lines, line_num):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.uncontrolled_consumption",
            "category": "CWE-400",
            "title": "Potential uncontrolled resource consumption",
            "description": f"Unbounded loop without visible exit at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add explicit bounds, timeouts, or break conditions to loops",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "400"))
        return


def _check_improper_shutdown(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for improper resource shutdown (CWE-404)."""
    if file_path.suffix.lower() in _MARKUP_SUFFIXES:
        return
    if RESOURCE_OPEN_DECL.match(line):
        return
    for pattern in RESOURCE_OPEN_PATTERNS:
        if not pattern.search(line):
            continue
        # Look for close/defer in surrounding context (next 5 lines)
        context_end = min(line_num + 5, len(lines))
        context = "\n".join(lines[line_num - 1 : context_end])
        if RESOURCE_CLOSE_SAFE.search(context):
            return
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.improper_shutdown",
            "category": "CWE-404",
            "title": "Resource opened without proper cleanup",
            "description": f"Resource opened at line {line_num} without close/defer/with",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use defer (Go), with statement (Python), or try-finally to ensure cleanup",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "404"))
        return


def _check_null_deref(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for NULL pointer dereference (CWE-476)."""
    # Feature 0085 gate 1 — LANGUAGE. Every construct below is Go-specific, and
    # Python's walrus operator is also `:=`, so without this the Go rule fires
    # on Python.
    if file_path.suffix.lower() != ".go":
        return
    # Focus on Go pattern: assignment from method call without nil check
    if not NULL_DEREF_PATTERNS[0].search(line):
        return
    bound = GO_ASSIGN_FIRST.search(line)
    if not bound:
        return
    # Feature 0085 gate 3 — NIL-ABILITY. If the right-hand side is a constructor
    # that cannot return nil, there is nothing to dereference unsafely.
    if GO_NEVER_NIL_CALL.search(line):
        return
    # Gate 3b — Go's `New*` constructor convention. A SINGLE-value assignment
    # from a `New…` function returns a ready-to-use value; a constructor that
    # can fail returns (T, error), which is a two-value assignment and is NOT
    # suppressed here. This is an assumption, stated plainly: a `New…` that
    # returns a bare nil on bad input is now missed. Recall knowingly traded
    # against 56 measured false positives at HIGH severity, all of this shape.
    if bound.group("second") is None and GO_NEW_CTOR.search(line):
        return
    # Feature 0085 gate 2 — the bound name must actually be DEREFERENCED later.
    # Binding a value and passing it along cannot fault.
    if not _go_var_is_dereferenced(bound.group("first"), lines, line_num):
        return
    # Check following lines for nil check before use
    window_end = min(line_num + 5, len(lines))
    window = "\n".join(lines[line_num:window_end])
    if GO_NIL_CHECK.search(window):
        return
    # Feature 0085 gate 4 — a `len(v)` test is a nil guard for slices and maps,
    # and a guard on THIS variable counts wherever it is written.
    _v = re.escape(bound.group("first"))
    if re.search(GO_LEN_GUARD.pattern.format(v=_v), window):
        return
    if re.search(GO_VAR_NIL_GUARD.pattern.format(v=_v), window):
        return
    # Gate 4b — a check on the assignment's OWN second result guards the first.
    # `u, err := url.Parse(x)` followed by `err == nil && u.Host != ""` is
    # correct Go: the error is what tells you the value is usable. Only a NAMED
    # second result counts — `_` is precisely the discarded-error bug this rule
    # must keep reporting.
    _second = bound.group("second")
    if _second and _second != "_":
        if re.search(GO_VAR_NIL_GUARD.pattern.format(v=re.escape(_second)), window):
            return
    finding = {
        "severity": "high",
        "check_id": "cwe.resource.null_deref",
        "category": "CWE-476",
        "title": "Potential NULL pointer dereference",
        "description": f"Return value used without nil check at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Check for nil/null before dereferencing pointers",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "476"))


def _check_unbounded_alloc(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for allocation without limits (CWE-770)."""
    # Check surrounding context for size limits
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SIZE_LIMIT.search(context):
        return
    for idx, pattern in enumerate(UNBOUNDED_ALLOC_PATTERNS):
        if not pattern.search(line):
            continue
        # Feature 0085: the `.append` arm (index 0) requires Python AND a loop.
        # The Go `make([]T, 0)` arm (index 1) is deliberately UNCHANGED — the
        # protected E2E fixture depends on it, and it was not part of the
        # measured false-positive mass.
        if idx == 0:
            if file_path.suffix.lower() not in _PY_SUFFIXES:
                continue
            if not _py_append_is_in_a_loop(lines, line_num):
                continue
        finding = {
            "severity": "medium",
            "check_id": "cwe.resource.unbounded_alloc",
            "category": "CWE-770",
            "title": "Allocation without resource limits",
            "description": f"Unbounded allocation at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add size limits, max capacity, or bounded data structures",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "770"))
        return


check_resource_management_tool = function_tool(check_resource_management)
