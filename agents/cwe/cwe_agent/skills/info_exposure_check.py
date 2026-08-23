"""Information exposure vulnerability detection skill."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    effective_name,
    is_backup_name,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_all_files,
    scan_backup_files,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet
from shared.tools.suppression import INFO_EXPOSURE_SUPPRESSIONS, should_suppress

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._var_reference import line_value_is_variable_ref

# CWE-209: Error message information disclosure
#
# The first five patterns are Python/Java/Go. That left Node entirely uncovered,
# so a TypeScript target which mounts `errorhandler()` — a package whose whole
# purpose is to return the stack trace and surrounding source to the client —
# reported nothing. The Node additions follow.
ERROR_DISCLOSURE_PATTERNS = [
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"\.printStackTrace\s*\("),  # Java
    re.compile(r"debug\.PrintStack\s*\("),  # Go
    re.compile(r"return\s+.*(?:traceback|stacktrace|stack_trace)", re.IGNORECASE),
    # Node/Express: an error VALUE echoed into the response body.
    #
    # Two exclusions carry the precision. The character class stops at a quote,
    # so `res.send('failed')` cannot match. The `(?!\s*:)` lookahead rejects the
    # token when it is an object KEY — `res.json({ error: 'Try again' })` names
    # a field "error" and returns a literal, which is the correct behaviour.
    # `res.json({ error: err.message })` still matches, on the value.
    re.compile(
        r"\.(?:send|json|end|write)\s*\(\s*[^'\"`)]*"
        r"\b((?:err|error|ex|exception)\w*)\b(?!\s*:)",
        re.IGNORECASE,
    ),
    # A `.stack` property reaching the response, in any wrapping:
    #   res.status(500).json({ stack: err.stack })
    re.compile(r"\.(?:send|json|end|write)\s*\([^)]*\.stack\b"),
]

# Middleware that returns diagnostic detail to the client by design. Reporting
# the mount site is the point: the leak is the mount, not a line inside the
# package.
LEAKY_ERROR_MIDDLEWARE = re.compile(
    r"\buse\s*\(\s*(?:\w+\.)?(?:errorhandler|errorHandler|expressErrorHandler)\s*\(",
)

# Gating the above on the environment is its documented safe usage, so a guard
# anywhere near the mount suppresses the finding.
_ENV_GUARD = re.compile(
    r"(?:NODE_ENV|app\.get\(\s*['\"]env['\"]\s*\)|process\.env\.\w*ENV\w*)"
    r"|\b(?:isDev|isDevelopment|__DEV__|devMode)\b",
    re.IGNORECASE,
)

# Server-side logging of an error is CWE-532's concern, not disclosure. Without
# this, `logger.error(err.stack)` would match the `.stack` pattern above.
_LOG_SINK = re.compile(
    r"\b(?:console|logger|log|winston|pino|bunyan)\s*\.\s*\w+\s*\(|"
    r"\b(?:log|logger)\s*\(",
    re.IGNORECASE,
)

# CWE-532: Information through log files.
#
# Two independent sources of noise had to go.
#
# 1. The call shape. `(?:log(?:ger)?|print|fmt\.Print)\w*\(` treated any method
#    whose name merely CONTAINS "log" as a log sink, so `oauthLogin(...)`,
#    `this.userService.login({ ... password ... })` and `await login(app, {
#    email, password })` all reported a logged credential. Fixed the same way
#    CWE-754 was: a negative lookbehind so the verb cannot start mid-identifier
#    (`oauthLogin` -> the `Log` is preceded by a word char), plus the verb
#    anchored to the START of the method name so `login` is no longer a prefix
#    match for `log`. A dotted receiver is still allowed, because
#    `this.logger.info(...)` and `self.log.debug(...)` are genuine sinks.
#
# 2. The message text. A log line whose LITERAL merely mentions a credential
#    ("ORG_ADMIN_TOKEN secret not configured", "BEE tokens extracted
#    successfully", "Role from token could not be accessed.") discloses nothing.
#    `_strip_literals` removes literal text before matching — see the note there
#    on why it must run before EVERY pattern in this list, and why interpolated
#    expressions are kept so `logger.warn(`token: ${authToken}`)` still reports.
_LOG_RECEIVER = r"(?:console|logger|log|logging|winston|pino|bunyan|klog|slog)"
_LOG_VERB = (
    r"(?:log|debug|info|warn|warning|error|fatal|trace|verbose|silly"
    r"|print|println|printf|write)"
)
# Go's `fmt` is NOT interchangeable with a logger: `fmt.Errorf("...: %w", token.
# ErrRevoked)` builds an error value and `fmt.Sprintf` builds a string — neither
# writes anywhere. Only the Print family is a sink, so `fmt` gets its own verbs.
_PRINT_CALL = r"fmt\s*\.\s*F?Print(?:f|ln)?"
# Bare function call: log(), logger(), logError(), log_info(), print(), printf().
# `login(` cannot match: after `log` the optional verb group cannot consume "in",
# so the required "(" lands on "i" and the match fails.
_LOG_BARE = rf"log(?:ger)?(?:[_.]?{_LOG_VERB})?|print(?:ln|f)?"
_LOG_CALL = (
    rf"(?<![\w$])(?:{_LOG_RECEIVER}\s*\.\s*{_LOG_VERB}\w*|{_PRINT_CALL}|{_LOG_BARE})\s*\("
)

# "token" is the most overloaded word in the keyword set: an LLM/tokenizer token
# count is not a credential. `logger.info("prompt_truncated original=%d ...",
# estimated_tokens, target_tokens, removed_count)` matched purely on the
# substring "token" inside a counter name. These spans are blanked before
# matching; a bare `token` / `access_token` / `authToken` is untouched.
_TOKEN_COUNT_NOISE = re.compile(
    r"\b(?:max|min|num|n|total|estimated|target|prompt|completion|input|output"
    r"|remaining|used|budget|context|ctx|chunk|avg|sum)[_.]?tokens?\b"
    r"|\btokens?[_.]?(?:count|used|budget|limit|estimates?|estimated|remaining"
    r"|usage|savings|saved|per[_.]?sec(?:ond)?|window|size|len(?:gth)?)\b"
    r"|\btoken(?:ize[rd]?|ization|izing)\b"
    # A path/handle NAMING a token store is not the token itself:
    # `fmt.Printf("Token saved to ~/%s/%s", configDir, tokenFile)`.
    r"|\btokens?[_.]?(?:file|filename|path|dir|store|cache)\b",
    re.IGNORECASE,
)

LOG_SENSITIVE_PATTERNS = [
    re.compile(_LOG_CALL + r".*(?:password|passwd|secret|token|api_key|apikey)", re.IGNORECASE),
    re.compile(r"(?<![\w$])logging\.(?:debug|info|warning|error)\(.*(?:password|secret|token|api_key)", re.IGNORECASE),
    re.compile(r"(?<![\w$])console\.log\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
    re.compile(r"(?<![\w$])log\.(?:Info|Debug|Warn|Error)\w*\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
]

# String literals, per language dialect. Used to drop literal MESSAGE text
# before the CWE-532 patterns run.
_STRING_LITERAL = re.compile(
    r"`(?:\\.|[^`\\])*`"                 # JS/TS template literal
    r"|'''(?:\\.|[^\\])*?'''"           # Python triple-quoted
    r'|"""(?:\\.|[^\\])*?"""'
    r"|'(?:\\.|[^'\\\n])*'"
    r'|"(?:\\.|[^"\\\n])*"'
)

# Interpolated expressions inside a literal: `${expr}` (JS) and `{expr}` (Python
# f-string / str.format). These are VALUES, not message text, so they survive the
# strip — `logging.info(f"password={password}")` must still report.
_INTERPOLATION = re.compile(r"\$\{([^{}]+)\}|\{([^{}]+)\}")


def _strip_literals(line: str) -> str:
    """Remove literal message text, keeping interpolated expressions.

    Applied before EVERY entry of LOG_SENSITIVE_PATTERNS, not just the first:
    pattern 3 (``console\\.log\\(.*(?:password|secret|token|apiKey)``) re-fires
    independently on a literal-only message, so narrowing the call shape alone
    left most of the noise in place.
    """
    def _repl(match: re.Match[str]) -> str:
        body = match.group(0).strip("`'\"")
        kept = " ".join(g for m in _INTERPOLATION.finditer(body) for g in m.groups() if g)
        return f'""{" " + kept if kept else ""}'

    return _TOKEN_COUNT_NOISE.sub("count", _STRING_LITERAL.sub(_repl, line))

# CWE-200: Exposure of sensitive info
SENSITIVE_RESPONSE_PATTERNS = [
    re.compile(r"(?:json|JSON)\w*\(.*(?:internal_path|db_host|database_url|dsn)", re.IGNORECASE),
    re.compile(r"(?:Response|response|w\.Write)\(.*(?:stack|internal|debug_info)", re.IGNORECASE),
]

# CWE-312: Cleartext storage of sensitive info
CLEARTEXT_STORAGE_PATTERNS = [
    re.compile(r"(?:password|secret|token|api_key)\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE),
    re.compile(r"(?:set|put|store|save)\w*\(.*(?:password|secret|token).*,\s*[\"']", re.IGNORECASE),
]
# Exclude safe patterns: hashing, env vars, config constants
SAFE_STORAGE = re.compile(
    r"\b(?:hash|bcrypt|encrypt|sha256|os\.(?:environ|getenv)|ENV\[|config\.|PLACEHOLDER|example|changeme|xxx)\b",
    re.IGNORECASE,
)

# CWE-497: Exposure of sensitive system information to an unauthorized control
# sphere. The instance this was written for serialises the WHOLE application
# config into an HTTP response:
#
#   const safeConfig = structuredClone(config.util.toObject(config))
#   res.json({ config: safeConfig })
#
# The dump and the send are on DIFFERENT lines, which is the normal shape, so a
# single-line regex finds nothing. The rule therefore matches a response sink
# and then resolves the identifiers it sends against nearby assignments.
_RESPONSE_SINK = re.compile(
    r"\b(?:res|resp|response|reply|w)\s*\.\s*(?:json|send|write|end)\s*\("
    r"|\bjsonify\s*\("
    r"|\bJsonResponse\s*\("
    r"|\bHttpResponse\s*\(",
    re.IGNORECASE,
)

# Expressions that materialise an ENTIRE configuration/environment object. Each
# alternative is anchored so a single lookup — `config.get('x')`,
# `process.env.NODE_ENV`, `os.environ["K"]` — does not match: reading one value
# is not a system-information dump.
_CONFIG_DUMP = re.compile(
    r"\bconfig\.util\.toObject\s*\("
    r"|\bJSON\.stringify\s*\(\s*(?:config|settings|appConfig|process\.env)\b"
    r"|\bprocess\.env\s*(?![\w.\[])"
    r"|\bdict\s*\(\s*os\.environ\s*\)"
    r"|\bos\.environ\s*(?![\w.\[(])"
    r"|\bapp\.config\s*(?![\w.\[])"
    r"|\bsettings\.__dict__\b"
    r"|\bnconf\.get\s*\(\s*\)"
    r"|\bviper\.AllSettings\s*\("
)

_ASSIGNMENT_RADIUS = 25
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
_NOT_A_VALUE = frozenset({
    "res", "resp", "response", "reply", "json", "send", "write", "end",
    "status", "jsonify", "return", "const", "let", "var", "await", "new",
    "this", "self", "type", "true", "false", "null", "undefined", "None",
})

# CWE-598: Use of GET request method with sensitive query strings. A credential
# in a query string is written to proxy logs, browser history, the Referer
# header and server access logs regardless of TLS.
_SENSITIVE_QUERY_PARAM = re.compile(
    r"[?&](?:access[_-]?token|id[_-]?token|auth[_-]?token|refresh[_-]?token"
    r"|api[_-]?key|apikey|client[_-]?secret|password|passwd|pwd|secret"
    r"|session[_-]?id|sessionid|jwt|bearer|token)\s*=",
    re.IGNORECASE,
)
# The parameter must belong to a URL, not to a `--password=` CLI flag or a
# `.env`-style line that happens to sit after an ampersand.
_URLISH = re.compile(r"https?://|[\"'`]/|\.get\s*\(|\.post\s*\(|fetch\s*\(|url|uri|endpoint|href", re.IGNORECASE)
# Non-HTTP URI schemes whose query string is not a request at all. The
# `otpauth://totp/...?secret=...` provisioning URI is the standard, unavoidable
# way to hand a TOTP seed to an authenticator app — reporting it would be
# unactionable, and CWE-598 is specifically about the GET request method.
_NON_HTTP_SCHEME = re.compile(r"\b(?:otpauth|mailto|data|magnet|tel|sms|geo|intent):", re.IGNORECASE)

# CWE-359: Private personal information in a URL query string. Same weakness
# mechanics as CWE-598 (proxy logs, browser history, Referer) over a DISJOINT
# keyword set — 598 owns credentials, 359 owns personal data — so a parameter
# can never produce both rows.
#
# The `[?&] … =` anchor is mandatory, and it is what makes the rule cheap:
# `new URLSearchParams(u).get('dob')` contains no `?dob=` substring, so the
# whole URL-parsing population is excluded by construction rather than by a
# suppression. Relaxing `dob`/`cvc`/`mrn`/`iban` to bare word matches would be
# a different, far noisier rule.
#
# The trailing `(?:[_-][a-z0-9]{1,12})?` is delimiter-separated on purpose:
# it buys `?medical_record_id=` and `?patient_id_hash=` without turning `dob`
# into a prefix match for `?dobro=`.
_PII_QUERY_PARAM = re.compile(
    r"[?&](?:"
    r"dob|date[_-]?of[_-]?birth|birth[_-]?date|birthdate"
    r"|ssn|social[_-]?security(?:[_-]?number)?"
    r"|cvc|cvv|card[_-]?number|cardnumber|credit[_-]?card|creditcard"
    r"|iban|bank[_-]?account|routing[_-]?number"
    r"|mrn|medical[_-]?record|health[_-]?record|patient[_-]?id|diagnosis"
    r"|passport(?:[_-]?(?:no|number))?"
    r"|driver[_-]?licen[cs]e|drivers[_-]?licen[cs]e|national[_-]?id|tax[_-]?id"
    r")(?:[_-][a-z0-9]{1,12})?\s*=",
    re.IGNORECASE,
)

# CWE-550: a SERVER-GENERATED error value handed to an HTTP response.
#
# Deliberately narrow. The loose JS shapes — a bare error-shaped identifier and
# `.stack` reaching `res.send/json/end/write` — stay on CWE-209, where their
# measured noise is already priced in and pinned by contract tests. What lands
# here are the sinks where the response and the server-generated value are both
# unambiguous. Each carries a receiver-anchored, WHOLE-TOKEN error identifier:
# `\b(?:err|error|ex)\w*` was the defect that let `extensionConnected` match.
_SERVER_ERROR_PATTERNS = [
    # Go: `http.Error(w, err.Error(), 500)` — the error is argument two.
    re.compile(r"\bhttp\.Error\s*\(\s*\w+\s*,\s*err\b(?:\.Error\s*\(\s*\))?"),
    re.compile(
        r"\b(?:w|rw|writer)\s*\.\s*Write\s*\((?:\s*\[\]byte\s*\()?[^)]*"
        r"\berr\.Error\s*\(\s*\)"
    ),
    # Java servlet. `sendError` cannot match CWE-209's `\.send\s*\(` shape, so
    # this is new detection rather than a re-tag.
    re.compile(
        r"\bsendError\s*\([^)]*(?<![.\w])(?:e|ex|err|error|exception|t|throwable)"
        r"\s*\.\s*(?:getMessage|getLocalizedMessage|toString)\s*\(",
        re.IGNORECASE,
    ),
    # ASP.NET
    re.compile(
        r"\bResponse\.Write\s*\([^)]*(?<![.\w])(?:ex|exception|err)\s*\.\s*"
        r"(?:Message|StackTrace|ToString)\b"
    ),
    # Python, EXPLICIT response sink only. A bare `return str(e)` in a helper
    # is not an HTTP response, and `return str(` at large is 4/4 false
    # (`str(uuid.uuid4())`, `str(fpath)`).
    re.compile(
        r"\b(?:jsonify|make_response|HttpResponse|JsonResponse|Response)\s*\("
        r"[^)]*\bstr\s*\(\s*e\w*\s*\)"
    ),
]

# CWE-313: Cleartext storage in a file. Filesystem sinks only — the shell
# `echo … >` arm measured 9 false of 10 (stderr diagnostics, `NOPASSWD` as a
# `passwd` substring, a Vault policy glob) and is deliberately absent.
#
# Every entry either ends at the call's `(` (so the PATH argument can be
# dropped) or consumes a complete `open(…, 'w')` call (so the content is what
# follows). See `_content_arguments`.
_FILE_WRITE_SINK = re.compile(
    r"\bfs(?:\.promises)?\s*\.\s*(?:write|append)File(?:Sync)?\s*\("
    r"|\bos\.WriteFile\s*\("
    r"|\bFiles\.write(?:String)?\s*\("
    r"|\bFile\.(?:WriteAll(?:Text|Lines|Bytes)|AppendAllText)\s*\("
    r"|\bnew\s+(?:PrintWriter|FileWriter)\s*\("
    r"|\bopen\s*\([^)]*,\s*[\"'][wa]b?\+?[\"']\s*\)"
)
# The first argument of a call, allowing one level of nesting and quoted spans,
# up to the top-level comma. A `[^,]+` stand-in is a proven defect class: it
# slides onto a literal inside the first argument.
_FIRST_ARGUMENT = re.compile(
    r"^\s*(?:'[^']*'|\"[^\"]*\"|`[^`]*`|\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\}"
    r"|[^,()\[\]{}'\"`])*,"
)
# Bare `token` is excluded: a token COUNT is not a credential, and the specific
# forms below carry the evidence without it.
_STORED_CREDENTIAL = re.compile(
    r"\b(?:password|passwd|pwd|secret\w*|api[_-]?key|apikey"
    r"|access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token"
    r"|private[_-]?key|client[_-]?secret|credentials?)\b",
    re.IGNORECASE,
)
# Content that is demonstrably not cleartext.
_PROTECTED_CONTENT = re.compile(
    r"\b(?:encrypt\w*|hash\w*|bcrypt|scrypt|argon2|pbkdf2|redact\w*|mask\w*"
    r"|sanitiz\w*|seal\w*|cipher\w*)\b|\*{3,}",
    re.IGNORECASE,
)

# CWE-215: sensitive information in debugging code.
#
# Shape (a): a dump primitive whose argument is EVIDENTIALLY sensitive. The
# `[Cc]onfig` alternative is dropped — an object named `config` carries no
# sensitivity evidence, and `console.dir(config)` / `print_r($config)` is a
# routine dev idiom. `process.env` / `os.environ` / `$_SESSION` are enumerated
# explicitly instead.
_DEBUG_DUMP_SINK = re.compile(
    r"(?<![\w$>])(?:var_dump|print_r|var_export)\s*\("
    r"|\bconsole\s*\.\s*(?:dir|table)\s*\("
    r"|\bpprint\s*\("
    r"|\bSystem\.out\.print(?:ln)?\s*\("
)
# Laravel/Symfony helpers are ordinary words in every other language, so they
# are PHP-gated and require a `$`-sigil argument.
_PHP_DUMP_SINK = re.compile(r"(?<![\w$>])(?:dd|dump)\s*\(\s*\$")
_PHP_SUFFIXES = frozenset({".php", ".phtml"})
_SENSITIVE_DUMP_ARG = re.compile(
    r"\$_(?:SESSION|POST|GET|REQUEST|ENV|SERVER|COOKIE)\b"
    r"|\bos\.environ\s*(?![\w.\[(])"
    r"|\bprocess\.env\s*(?![\w.\[])"
    r"|\brequest\.(?:headers|cookies|session|form|body)\b"
    r"|\bgetSession\s*\(\s*\)"
    r"|\bvars\s*\("
    r"|\blocals\s*\("
    r"|\w*[Cc]redentials?\b"
)

# Shape (b): a debug gate whose body writes a secret to a NON-LOG sink. The
# log sinks are excluded because CWE-532 already reports that exact line —
# without this the gate would restate 532 one line earlier.
_DEBUG_GATE = re.compile(
    r"(?:^|[};]|\belse\s+)\s*if\s*[\(:]?\s*!?\s*\$?(?:[\w.]+\.)?"
    r"(?:is_?debug\w*|debug(?:_?(?:mode|enabled|on))?|DEBUG)\b",
    re.IGNORECASE,
)
_DEBUG_BODY_RADIUS = 5
_NON_LOG_OUTPUT_SINK = re.compile(
    r"(?<![\w$])echo\b"
    r"|\bgetWriter\s*\(\s*\)\s*\.\s*print(?:ln)?\s*\("
    r"|\b(?:res|resp|response)\s*\.\s*(?:send|write|json)\s*\("
    r"|\bdocument\.write\s*\("
)
_DEBUG_BODY_KEYWORD = re.compile(
    r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|session[_-]?id"
    r"|access[_-]?token|auth[_-]?token|credentials?)\b",
    re.IGNORECASE,
)

# CWE-201: inbound request headers forwarded verbatim to an outbound client, so
# the caller's Authorization/Cookie reaches a third party.
#
# Every anchor carries an EXPLICIT request receiver. A bare `c` receiver (Hono
# / Koa) was dropped: a one-character name is a chart config, a column, a
# component, a context or a client, and its FP surface is unquantifiable.
_HEADER_FORWARD_PATTERNS = [
    re.compile(r"headers\s*[:=]\s*(?:req|request|ctx)\s*\.\s*(?:headers|Header)\b"),
    re.compile(r"headers\s*[:=]\s*\{\s*\.\.\.\s*(?:req|request)\.headers\s*\}"),
    re.compile(r"headers\s*=\s*(?:\*\*\s*)?request\.headers\b"),
    re.compile(r"\.Header\s*=\s*(?:r|req)\.Header\b"),
]
_OUTBOUND_RADIUS = 2
_STRIP_RADIUS = 6
_OUTBOUND_CLIENT = re.compile(
    r"\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bsuperagent\b|\bky\s*\("
    r"|\bhttp\.(?:Get|Post|Head|Do|NewRequest)\b|\bclient\s*\.\s*[Dd]o\s*\("
    r"|\brequests\.(?:get|post|put|patch|delete|request)\s*\("
    r"|\bhttpx\.(?:get|post|put|patch|delete|request|Client)\b"
    r"|\burllib\.request\.|\bsession\.(?:get|post|request)\s*\("
    r"|\bHttpClient\b|\bWebClient\b|\brestTemplate\b"
)
# Inbound parsers CONSUME headers rather than send them — and
# `busboy({ headers: req.headers })` is a designated CWE-434 must-fire line in
# this agent's own no-blunders test, so without this the same line would carry
# two rows, one of them wrong.
_INBOUND_PARSER = re.compile(
    r"\b(?:busboy|Busboy|multer|formidable|IncomingForm|parseMultipart"
    r"|content-type|contentType)\b"
)
# A declared reverse proxy / BFF forwards headers by design; that architecture
# is the dominant real-world instance of this shape.
_PROXY_MACHINERY = re.compile(
    r"createProxyMiddleware|http-proxy|httpProxy|fastify-reply-from"
    r"|node-http-proxy|\bproxyReq\b|\breverseProxy\b|X-Forwarded-For",
    re.IGNORECASE,
)
# An inbound request is a handler PARAMETER, never a local. MEASURED: without
# these two conditions the Python arm produced 18 rows on one real tree and all
# 18 were an SDK handing its OWN prepared request's headers to its own session
# (`request = self._prepare_request()` … `session.get(url,
# headers=request.headers)`) — an outbound-to-outbound copy that forwards
# nothing. The receiver name alone carries no evidence of direction, which is
# the same defect that disqualified a bare `c` receiver.
_INBOUND_HANDLER = re.compile(
    r"\bdef\s+\w+\s*\(\s*(?:self\s*,\s*)?request\b"
    r"|\b(?:async\s+)?function\s+\w*\s*\(\s*(?:req|request)\b"
    r"|[(,]\s*(?:req|request)\s*,\s*(?:res|reply|response)\b"
    r"|\bfunc\s+\w*\s*\([^)]*\*http\.Request"
    r"|\b(?:HttpServletRequest|HttpRequest)\b"
    r"|@(?:app|router|bp|blueprint|api_view|route)\b"
    r"|\brequest\.META\b"
)
_LOCAL_REQUEST_BUILD = re.compile(
    r"^\s*(?:const|let|var)?\s*(?:req|request)\s*(?::=|=)(?!=)"
)
_LOCAL_BUILD_RADIUS = 10
_HEADER_STRIPPED = re.compile(
    r"\bdelete\s+[\w.\[\]'\"]*(?:authorization|cookie)"
    r"|\b(?:omit|pick)\s*\("
    r"|allowed_?headers|filter_?headers|sanitiz\w*_?headers|header_?allow(?:list|ed)"
    r"|\bpop\s*\(\s*['\"](?:authorization|cookie)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")
STRING_ONLY = re.compile(r"^\s*[\"']")

# Two-tier context: cleartext storage is only high with database/persist context
_STORAGE_CONTEXT = [re.compile(r"(database|persist|store|save|write|insert|sqlite|postgres|mysql|redis)", re.IGNORECASE)]


def check_information_exposure(source_path: str) -> dict:
    """Check for information exposure vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of information exposure issues.
    """
    findings: list[dict] = []
    suppression_counts: dict[int, int] = {}

    # A shadow copy is a finding in its own right, whatever its contents
    # (feature 0068). Walked separately from the code scan: running this
    # inside the scan_code_files loop meant a backup was only reported if it
    # was also *parseable*. Marker stripping makes a shadow copy inherit its
    # target's exclusions, so `package-lock.json.bak` (effective name in
    # SKIP_FILES) and `notes.md.bak` (non-code extension) were silently exempt —
    # i.e. the most common backup shapes were the ones never reported.
    for backup_path in scan_backup_files(source_path):
        _check_backup_exposure(backup_path, source_path, findings)

    # CWE-219: sensitive NON-backup files under a served root. Walked separately
    # for the same reason as backups — a .kdbx/.key is never in the extension
    # allowlist, so the scan_code_files loop below can never see it, yet it leaks
    # verbatim if it sits in a mounted directory.
    _check_served_sensitive_files(source_path, findings)

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings, suppression_counts, served_roots(source_path))

    return {"findings": findings}


# Directories typically reachable by an unauthenticated client. A shadow copy
# here is materially worse than one buried in src/.
_SERVED_DIRS = frozenset({
    "ftp", "public", "static", "www", "wwwroot", "htdocs", "dist", "build",
    "assets", "uploads", "files", "download", "downloads", "web",
})

# Mount declarations. Reachability is DECLARED in the source, so deriving it beats
# guessing by directory name. A fixed name list cuts both ways: it misses any
# served directory whose name nobody thought to enumerate (`encryptionkeys`,
# `attachments`, `exports`), and it mis-fires on a directory merely *named*
# `assets` that is never mounted.
#
# Node was the only dialect covered, which made every rule built on the resolver
# Node-only. The Python and Go idioms below declare exactly the same thing, and
# the `join()` arm covers the spelling most projects actually use
# (`express.static(path.join(__dirname, 'logs'))`) — a quoted-literal-only
# pattern silently misses it.
_MOUNT_PATTERNS = (
    re.compile(r"express\.static\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"serveIndex\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"serveStatic\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"StaticFiles\s*\(\s*directory\s*=\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"send_from_directory\s*\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"static_folder\s*=\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"http\.Dir\s*\(\s*[\"`]([^\"`]+)[\"`]"),
    re.compile(
        r"(?:express\.static|serveIndex|serveStatic|http\.Dir)\s*\(\s*"
        r"(?:path\.)?(?:join|resolve)\s*\([^)]*?['\"]([^'\"]+)['\"]\s*\)"
    ),
)

# CWE-538: a runtime artefact whose DESTINATION is a directory the web server
# publishes. An access log, an audit trail, a database dump or a scheduled
# export accumulates credentials, session identifiers, internal hostnames and
# stack traces; writing one under a served root makes all of that retrievable
# by anyone who can guess the path.
#
# Anchoring on the destination is also what keeps the row disjoint. The obvious
# alternative — reporting the MOUNT that publishes a sensitive-looking directory
# — was built first and dropped: the deterministic signature tier already claims
# `serveIndex(` / `autoIndex: true` lines for CWE-548, so on the only shape that
# measured any real instances the mount rule was a second row for one weakness.
# The `express.static('logs')` remainder measured zero on both trees.
#
# Three independent facts are required, because each alone is ordinary code:
#   1. the line CONFIGURES a log/audit destination;
#   2. the literal path's directory resolves to a served root, either a mount
#      DECLARED in the source or a conventional public name;
#   3. the basename names a GENERATED artefact.
#
# Fact 3 is what keeps user content out, and it is not optional: measured
# without it, a stream writing an uploaded attachment into `uploads/` and one
# writing a profile image into the built frontend's asset directory were 2 of 4
# rows. Both are the design of the feature, and neither basename carries an
# artefact word.
#
# Fact 1 is deliberately a DESTINATION declaration and not the generic
# file-write sink table this module already owns for CWE-313. The generic verbs
# (`createWriteStream`, `fs.writeFile*`, `os.WriteFile`, `open(…, 'w')`) are the
# same ones the resource skill keys on for CWE-404/CWE-379, so a rule built on
# them lands a second row on lines that are already claimed — verified on a
# fixture where `fs.createWriteStream('public/access.log')` drew both CWE-404
# and this row. Dropping the arm cost nothing measurable: every real instance on
# the measurement trees is a configured destination, and a destination KEY
# (`filename:` / `fileName=` / `audit_file:`) is what carries the rule across
# Node, Python, Go and the JVM logging config dialects alike.
#
# Logback's `<file>logs/app.log</file>` is NOT covered, and adding the element
# would be dishonest without also teaching `_PATH_LITERAL` about element text —
# the path there is unquoted. Log4j2's `fileName="…"` attribute is quoted and is
# already reached by the key arm.
_ARTEFACT_DESTINATION = re.compile(
    r"\b(?:file_?name|log_?file|audit_?file|output_?file|log_?path)\s*[:=]"
    r"|\btransports\s*\.\s*(?:File|DailyRotateFile)\s*\("
    r"|\b(?:Rotating|TimedRotating|Watched|Concurrent)?FileHandler\s*\("
    r"|\blogging\.basicConfig\s*\(",
    re.IGNORECASE,
)
_GENERATED_ARTEFACT = re.compile(
    r"(?:^|[._-])(?:logs?|access|audit|error|debug|trace|backups?|bak|dumps?"
    r"|exports?|reports?)(?:[._-]|$)"
    r"|\.log(?:\.|$)"
    r"|\.(?:bak|dump|sql|sqlite|db|csv)(?:\.|$)",
    re.IGNORECASE,
)
# A quoted path candidate. Bounded on purpose (ReDoS-safe) and deliberately
# blind to interpolation: `logs/${name}.log` still resolves its directory.
_PATH_LITERAL = re.compile(r"['\"`]([^'\"`\n]{3,200})['\"`]")

# Extensions whose exposure is a finding regardless of whether we can parse them.
# Deliberately narrow: `.md`/`.txt`/`.json` are excluded because a served root
# full of documentation is normal and would drown the signal.
#
# `.asc` and `.gpg` were in this set and were REMOVED after measurement. ASCII-
# armored PGP files under a served root are usually *detached signatures* or
# public keys — CSAF/OpenVEX advisory feeds publish them at well-known paths by
# design — so the extension carries no exposure signal and the rule fired about
# as often on published artefacts as on real secrets. Private key material is
# already covered by `.key`/`.pem`/`.p12`/`.pfx`/`.ppk`.
_SENSITIVE_SERVED_SUFFIXES = frozenset({
    ".kdbx", ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".ppk",
    ".sql", ".env", ".pyc", ".ovpn", ".dump", ".sqlite", ".db",
})


def _normalise_mount(target: str) -> str:
    """A mount target reduced to a root-relative, lowercase, slash path.

    ``./`` prefixes are stripped iteratively rather than with ``lstrip('./')``:
    that would eat the leading dot of ``.git`` / ``.env`` / ``.ssh``, which are
    exactly the directory names whose exposure matters most.
    """
    cleaned = target.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.strip("/").lower()


def _declared_mounts(content: str) -> set[str]:
    """Mount targets declared in one file, normalised to lowercase paths."""
    return {
        _normalise_mount(match.group(1))
        for pattern in _MOUNT_PATTERNS
        for match in pattern.finditer(content)
    }


def _is_served_artefact(path: str, roots: frozenset[str]) -> bool:
    """True when ``path`` names a generated artefact inside a served root."""
    head, _, base = path.rpartition("/")
    if not head or not _GENERATED_ARTEFACT.search(base):
        return False
    return _is_served(head.split("/"), roots)


def _served_artefact_path(line: str, roots: frozenset[str]) -> str | None:
    """The literal path on ``line`` that lands an artefact in a served root."""
    paths = (_normalise_mount(lit) for lit in _PATH_LITERAL.findall(line))
    return next((p for p in paths if _is_served_artefact(p, roots)), None)


@lru_cache(maxsize=8)
def served_roots(source_path: str) -> frozenset[str]:
    """Directories reachable by an unauthenticated client.

    Code-declared mounts UNION the ``_SERVED_DIRS`` fallback names. Single source
    of truth, consumed by both CWE-552 (backup exposure) and CWE-219 — so
    resolving a mount from source improves the pre-existing detector too.

    Cached per source path, and ``read_file_safe`` is itself cached, so the mount
    sweep costs at most one pass over files the main scan reads anyway.
    """
    roots = set(_SERVED_DIRS)
    for file_path in scan_code_files(source_path):
        roots |= _declared_mounts(read_file_safe(file_path) or "")
    return frozenset(roots)


def _relative_to_root(file_path: Path, source_path: str) -> Path:
    """``file_path`` relative to the scan root, or unchanged if outside it."""
    try:
        return file_path.relative_to(source_path)
    except ValueError:
        return file_path


def _relative_parts(file_path: Path, source_path: str) -> list[str]:
    """Lowercased directory components of ``file_path`` relative to the root."""
    return [p.lower() for p in _relative_to_root(file_path, source_path).parts[:-1]]


def _is_served(parts: list[str], roots: frozenset[str]) -> bool:
    """True when any ancestor directory is a served root.

    Checks bare names and multi-segment mount paths (``frontend/dist/frontend``).
    Both are set lookups, so the test is O(depth) with constant-time membership.
    """
    if any(p in roots for p in parts):
        return True
    return any("/".join(parts[: i + 1]) in roots for i in range(len(parts)))


def _is_served_sensitive(file_path: Path, source_path: str, roots: frozenset[str]) -> bool:
    """CWE-219's predicate. Backups are excluded: CWE-552 already owns them."""
    if is_backup_name(file_path.name):
        return False
    if file_path.suffix.lower() not in _SENSITIVE_SERVED_SUFFIXES:
        return False
    return _is_served(_relative_parts(file_path, source_path), roots)


def _check_served_sensitive_files(source_path: str, findings: list[dict]) -> None:
    """CWE-219: a sensitive file stored under a web-reachable directory."""
    roots = served_roots(source_path)
    for file_path in scan_all_files(source_path):
        if not _is_served_sensitive(file_path, source_path, roots):
            continue
        rel = file_path.relative_to(source_path)
        findings.append(enrich_finding({
            "severity": "high",
            "check_id": "cwe.info_exposure.served_sensitive_file",
            "category": "CWE-219",
            "title": f"Sensitive file '{file_path.name}' under a web-served directory",
            "description": (
                f"'{rel}' has a sensitive extension and sits under a directory that "
                "is served to unauthenticated clients, so its bytes are retrievable "
                "over HTTP regardless of application-level authorization."
            ),
            "file_path": str(file_path),
            "line_start": 1,
            "line_end": 1,
            "recommendation": (
                "Move the file outside the served tree, or restrict the mount. Rotate "
                "any credential or key it contains — assume it has been fetched."
            ),
            "code_snippet": "",
        }, "219"))


def _check_backup_exposure(file_path: Path, source_path: str, findings: list[dict]) -> None:
    """Report a backup/shadow copy of source or config as an exposure.

    Precise weakness is CWE-530 (Exposure of Backup File), which the OWASP 2025
    edition does not map; we therefore categorise as the mapped parent CWE-552
    (Files or Directories Accessible to External Parties -> A01) and name
    CWE-530 in the text rather than inventing a mapping.
    """
    if not is_backup_name(file_path.name):
        return
    shadowed = effective_name(file_path.name)
    rel = _relative_to_root(file_path, source_path)
    # Shared resolver: a mount declared in code counts even when its directory
    # name is absent from _SERVED_DIRS, which previously scored such a backup
    # `medium` despite being fully reachable.
    served = _is_served(_relative_parts(file_path, source_path), served_roots(source_path))

    finding = {
        "severity": "high" if served else "medium",
        "check_id": "cwe.info_exposure.backup_file",
        "category": "CWE-552",
        "title": f"Exposed backup file '{file_path.name}' (CWE-530)",
        "description": (
            f"'{rel}' is a backup/shadow copy of '{shadowed}'. Backup files "
            "commonly retain credentials, dependency pins and logic that were "
            "deliberately removed from the live file, and are served verbatim "
            "if they sit inside the deployed tree (CWE-530)."
            + (" It is located under a publicly-served directory." if served else "")
        ),
        "file_path": str(file_path),
        "line_start": 1,
        "line_end": 1,
        "recommendation": (
            "Delete the backup from the repository/deploy artefact and keep "
            "history in version control; block backup extensions at the web server."
        ),
    }
    findings.append(enrich_finding(finding, "552"))


@dataclass(frozen=True)
class _FileCtx:
    """Per-file state shared by the rules added in feature 0070 P7.

    ``prose`` carries the documentation guard: `.md/.rst/.txt` are in the scan
    set and ``COMMENT_INDICATORS`` does not match markdown body text, so a
    hardening guide that only *condemns* an insecure call reads as executable
    source. Pattern-shaped rules must skip prose; the credential-VALUE rules
    (CWE-312/532) deliberately do not — a secret pasted into a README is a real
    leak whether or not anything executes.
    """

    path: Path
    lines: Sequence[str]
    content: str
    findings: list[dict]
    prose: bool
    php: bool
    roots: frozenset[str]


def _analyze_file(
    file_path: Path, findings: list[dict], suppression_counts: dict[int, int],
    roots: frozenset[str] = frozenset(),
) -> None:
    """Analyze a file for information exposure issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    ctx = _FileCtx(
        path=file_path,
        lines=lines,
        content=content,
        findings=findings,
        prose=is_prose_file(file_path),
        php=file_path.suffix.lower() in _PHP_SUFFIXES,
        roots=roots,
    )
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_error_disclosure(file_path, line, line_num, lines, findings)
        _check_log_sensitive(file_path, line, line_num, lines, findings, suppression_counts)
        _check_storage(ctx, line, line_num, suppression_counts)
        _check_sensitive_response(file_path, line, line_num, lines, findings)
        _check_config_exposure(file_path, line, line_num, lines, findings)
        _check_token_in_query(file_path, line, line_num, lines, findings)
        _check_pii_in_query(ctx, line, line_num)
        _check_debug_exposure(ctx, line, line_num)
        _check_header_forward(ctx, line, line_num)
        _check_artefact_under_served_root(ctx, line, line_num)


def _emit(ctx: _FileCtx, spec: dict, cwe: str, line_num: int) -> None:
    """Append one finding built from a literal ``spec``.

    ``spec`` must carry its ``"category": "CWE-N"`` as a literal — the coverage
    extractor only sees literals, so an f-string category would detect while
    the attestation denied it.
    """
    finding = dict(spec)
    finding["file_path"] = str(ctx.path)
    finding["line_start"] = line_num
    finding["line_end"] = line_num
    finding["code_snippet"] = extract_snippet(ctx.lines, line_num)
    ctx.findings.append(enrich_finding(finding, cwe))


def _window_matches(
    lines: Sequence[str], line_num: int, radius: int, pattern: re.Pattern[str]
) -> bool:
    """True when ``pattern`` matches any line within ``radius`` of ``line_num``."""
    start = max(0, line_num - 1 - radius)
    return any(pattern.search(ln) for ln in lines[start : line_num + radius])


def _check_error_disclosure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for error detail reaching a client (CWE-209, CWE-550)."""
    # Diagnostic middleware: the mount site IS the vulnerability, so it is
    # checked separately from the "error value in a response" patterns.
    if LEAKY_ERROR_MIDDLEWARE.search(line):
        _report_leaky_middleware(file_path, line_num, lines, findings)
        return

    # Server-side logging of an error is CWE-532's concern; without this a
    # `logger.error(err.stack)` line would match the `.stack` pattern.
    if _LOG_SINK.search(line):
        return

    # CWE-550 is the precise id where the sink is unambiguously an HTTP
    # response and the value unambiguously server-generated. It REPLACES the
    # 209 row on that line — skill findings are not deduplicated against each
    # other, so a child that does not suppress its parent ships two rows.
    if _check_server_error_response(file_path, line, line_num, lines, findings):
        return

    _check_error_value_in_response(file_path, line, line_num, lines, findings)


def _report_leaky_middleware(
    file_path: Path, line_num: int, lines: list[str], findings: list[dict],
) -> None:
    """Report an unguarded diagnostic error-handler mount (CWE-209)."""
    if _has_env_guard(lines, line_num):
        return
    _add_disclosure(
        file_path, line_num, lines, findings,
        title="Diagnostic error middleware returns stack traces to clients",
        description=(
            f"Error-handling middleware mounted at line {line_num} without an "
            "environment guard. Packages of this kind return the stack trace and "
            "surrounding source of any unhandled error in the HTTP response, "
            "disclosing file paths, dependency versions and internal logic to "
            "unauthenticated callers."
        ),
        recommendation=(
            "Mount diagnostic error middleware only for development (guard on "
            "NODE_ENV / app.get('env')), and register a production handler that "
            "returns a generic message while logging detail server-side."
        ),
    )


def _matched_a_literal_identifier(
    match: re.Match[str], lines: list[str], line_num: int,
) -> bool:
    """True when the matched identifier holds a literal, so nothing leaks.

    An error-SHAPED name is not an error: `const errMsg = { err: 'not
    supported' }` returned to the client discloses nothing.
    """
    return bool(
        match.groups()
        and match.group(1)
        and _holds_literal(lines, line_num, match.group(1))
    )


def _check_error_value_in_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check the loose error-value shapes, which stay on CWE-209."""
    for pattern in ERROR_DISCLOSURE_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        if _matched_a_literal_identifier(m, lines, line_num):
            return
        _add_disclosure(
            file_path, line_num, lines, findings,
            title="Error message information disclosure",
            description=f"Stack trace or error details exposed at line {line_num}",
            recommendation="Return generic error messages; log detailed errors server-side only",
        )
        return


def _check_server_error_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> bool:
    """CWE-550: a server-generated error value written to an HTTP response.

    Returns True when a row was emitted, which suppresses the CWE-209 row for
    the same line (P5 — skill findings do not cross-deduplicate).
    """
    if is_prose_file(file_path):
        return False
    if not any(p.search(line) for p in _SERVER_ERROR_PATTERNS):
        return False
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.server_error_message",
        "category": "CWE-550",
        "title": "Server-generated error message returned to the client",
        "description": (
            f"Line {line_num} writes a server-generated error value (message, "
            "stack trace or exception text) into the HTTP response. That text "
            "names internal file paths, framework and driver versions, SQL "
            "fragments and hostnames, which is reconnaissance an unauthenticated "
            "caller should never receive."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Return a generic message plus a correlation id, and log the error "
            "detail server-side only."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "550"))
    return True


def _holds_literal(lines: list[str], line_num: int, ident: str, radius: int = 6) -> bool:
    """True when ``ident`` is assigned a literal within ``radius`` lines above.

    Conservative on purpose: only a right-hand side that STARTS with a quote or
    an object brace counts, and an object brace only when it contains no
    identifier-valued field. Anything derived from a caught error
    (``e.message``, ``getErrorMessage(err)``) therefore still reports.
    """
    pat = re.compile(
        rf"(?:const|let|var)?\s*\b{re.escape(ident)}\b\s*=\s*(['\"`{{].*)$"
    )
    start = max(0, line_num - 1 - radius)
    for ln in lines[start:line_num - 1]:
        m = pat.search(ln)
        if not m:
            continue
        rhs = m.group(1).strip()
        if rhs[0] in "'\"`":
            return True
        # Object literal: every value must itself be a literal.
        if rhs.startswith("{"):
            values = re.findall(r":\s*([^,}]+)", rhs)
            if values and all(v.strip()[:1] in "'\"`" or v.strip().isdigit()
                              for v in values):
                return True
    return False


def _add_disclosure(
    file_path: Path, line_num: int, lines: list[str], findings: list[dict],
    title: str, description: str, recommendation: str,
) -> None:
    """Append a CWE-209 finding."""
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.error_disclosure",
        "category": "CWE-209",
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": recommendation,
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "209"))


def _has_env_guard(lines: list[str], line_num: int, radius: int = 8) -> bool:
    """True when an environment check sits within `radius` lines of the mount.

    Deliberately generous: gating diagnostic middleware on the environment is
    its documented safe usage, and a false negative there costs far less than
    telling every Express project its dev-only error handler is a vulnerability.
    """
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return any(_ENV_GUARD.search(ln) for ln in lines[start:end])


def _check_log_sensitive(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for sensitive data in log output (CWE-532)."""
    probe = _strip_literals(line)
    for pattern in LOG_SENSITIVE_PATTERNS:
        if not pattern.search(probe):
            continue
        finding = {
            "severity": "critical",
            "check_id": "cwe.info_exposure.log_sensitive",
            "category": "CWE-532",
            "title": "Sensitive data written to log",
            "description": f"Potential password/token/secret logged at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Never log sensitive data; use redaction or masked output",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        if should_suppress(finding["title"], file_path, line, INFO_EXPOSURE_SUPPRESSIONS, suppression_counts):
            return
        findings.append(enrich_finding(finding, "532"))
        return


def _check_storage(
    ctx: _FileCtx, line: str, line_num: int, suppression_counts: dict[int, int],
) -> None:
    """Route a line to CWE-313 (file sink) or CWE-312, never both.

    CWE-313 is the child specialisation: a credential written INTO a file.
    ``fs.writeFileSync(p, `password="${pw}"`)`` matches CWE-312's quoted-value
    pattern as well, so without this precedence the line ships two rows.
    """
    if _check_cleartext_file_write(ctx, line, line_num):
        return
    _check_cleartext_storage(
        ctx.path, line, line_num, ctx.lines, ctx.content, ctx.findings, suppression_counts,
    )


def _content_arguments(line: str, sink: re.Match[str]) -> str:
    """The sink's arguments AFTER the path argument.

    The path is the file's NAME, not its contents, so
    ``fs.writeFileSync('secrets/password.txt', rendered)`` must not report. A
    depth-aware first-argument match is what makes that distinction; a `[^,]+`
    stand-in slides onto literals nested inside the path expression.
    """
    tail = line[sink.end():]
    if not sink.group(0).endswith("("):
        return tail
    first = _FIRST_ARGUMENT.match(tail)
    return tail[first.end():] if first else ""


def _stored_credential(line: str) -> str | None:
    """The credential token in a file-write sink's CONTENT position, if any."""
    sink = _FILE_WRITE_SINK.search(line)
    if sink is None:
        return None
    content = _content_arguments(line, sink)
    if _PROTECTED_CONTENT.search(content):
        return None
    match = _STORED_CREDENTIAL.search(content)
    return match.group(0) if match else None


def _check_cleartext_file_write(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """CWE-313: a credential written to a file in cleartext.

    Returns True when a row was emitted, so CWE-312 stays out of that line.
    """
    token = None if ctx.prose else _stored_credential(line)
    if token is None:
        return False
    _emit(ctx, {
        "severity": "high",
        "check_id": "cwe.info_exposure.cleartext_file_storage",
        "category": "CWE-313",
        "title": f"Credential '{token}' written to a file in cleartext",
        "description": (
            f"Line {line_num} writes '{token}' into a file with no encryption. "
            "Anything that can read the path — another process, a backup, a "
            "container image layer, a mounted volume or a log-shipping agent — "
            "recovers the credential verbatim."
        ),
        "recommendation": (
            "Keep the secret in a secrets manager or the process environment and "
            "read it at use time; if it must be persisted, encrypt it with a key "
            "held elsewhere and restrict the file mode."
        ),
    }, "313", line_num)
    return True


def _pii_query_param(line: str) -> str | None:
    """The PII query parameter carried by ``line``, when it is a real URL."""
    match = _PII_QUERY_PARAM.search(line)
    if match is None:
        return None
    if not _URLISH.search(line) or _NON_HTTP_SCHEME.search(line):
        return None
    return match.group(0).strip("?&= ")


def _check_pii_in_query(ctx: _FileCtx, line: str, line_num: int) -> None:
    """CWE-359: private personal information in a URL query string."""
    param = None if ctx.prose else _pii_query_param(line)
    if param is None:
        return
    _emit(ctx, {
        "severity": "high",
        "check_id": "cwe.info_exposure.pii_in_query_string",
        "category": "CWE-359",
        "title": f"Personal information '{param}' passed in a URL query string",
        "description": (
            f"Line {line_num} builds a URL that carries '{param}' — a direct "
            "personal identifier — as a query parameter. Query strings are "
            "recorded in browser history, proxy and web-server access logs, and "
            "are forwarded in the Referer header of any subsequent request, so "
            "the value is retained by systems outside the application's control "
            "even over TLS."
        ),
        "recommendation": (
            "Move personal identifiers into a POST body or a request header, and "
            "purge the access logs that already contain them."
        ),
    }, "359", line_num)


def _sensitive_dump(ctx: _FileCtx, line: str) -> bool:
    """Shape (a): a dump primitive whose argument is evidentially sensitive."""
    if not _SENSITIVE_DUMP_ARG.search(line):
        return False
    if _DEBUG_DUMP_SINK.search(line):
        return True
    return bool(ctx.php and _PHP_DUMP_SINK.search(line))


def _leaks_secret_to_output(body_line: str) -> bool:
    """True when a debug-gate body line writes a secret to a NON-log sink.

    The log case is excluded because CWE-532 already reports that exact line;
    the receiver suppression governs the gate line, not the body line, so the
    test has to be made here or CWE-215 restates 532 one line earlier.
    """
    if not (_NON_LOG_OUTPUT_SINK.search(body_line) and _DEBUG_BODY_KEYWORD.search(body_line)):
        return False
    probe = _strip_literals(body_line)
    return not any(p.search(probe) for p in LOG_SENSITIVE_PATTERNS)


def _debug_gate_leak(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """Shape (b): a debug gate whose body writes a secret to a client."""
    if not _DEBUG_GATE.search(line):
        return False
    body = ctx.lines[line_num : line_num + _DEBUG_BODY_RADIUS]
    return any(_leaks_secret_to_output(b) for b in body)


def _check_debug_exposure(ctx: _FileCtx, line: str, line_num: int) -> None:
    """CWE-215: sensitive information exposed by debugging code."""
    if ctx.prose:
        return
    if _sensitive_dump(ctx, line):
        _emit(ctx, {
            "severity": "medium",
            "check_id": "cwe.info_exposure.debug_dump",
            "category": "CWE-215",
            "title": "Debug dump of a sensitive aggregate object",
            "description": (
                f"Line {line_num} passes a session, environment or credential "
                "aggregate to a debugging dump primitive. Dump output is written "
                "to the page, the response stream or the console, so on a server "
                "that is even briefly left in debug mode the whole object — "
                "session identifiers, environment secrets, request headers — is "
                "disclosed to whoever triggered the request."
            ),
            "recommendation": (
                "Remove the dump, or replace it with an explicit allow-list of "
                "non-sensitive fields written to a server-side log."
            ),
        }, "215", line_num)
        return
    if _debug_gate_leak(ctx, line, line_num):
        _emit(ctx, {
            "severity": "medium",
            "check_id": "cwe.info_exposure.debug_branch_output",
            "category": "CWE-215",
            "title": "Debug branch writes a credential to client-visible output",
            "description": (
                f"The debug branch opened at line {line_num} writes a "
                "credential-bearing value to a client-visible sink rather than a "
                "server-side log. The branch survives into production whenever "
                "the debug flag is enabled to diagnose an incident, which is "
                "exactly when it is reachable by real users."
            ),
            "recommendation": (
                "Never emit credentials from a debug branch; log a redacted form "
                "server-side and remove the client-visible output."
            ),
        }, "215", line_num)


def _receiver_is_inbound(ctx: _FileCtx, line_num: int) -> bool:
    """True when the header collection plausibly belongs to an INBOUND request.

    Requires a request-shaped handler parameter in the file and no local
    construction of the receiver nearby — the two conditions that separate a
    forwarded caller header from an SDK copying its own prepared headers.
    """
    if not _INBOUND_HANDLER.search(ctx.content):
        return False
    return not _window_matches(
        ctx.lines, line_num, _LOCAL_BUILD_RADIUS, _LOCAL_REQUEST_BUILD
    )


def _forward_is_suppressed(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """Deliberate, non-forwarding or non-inbound uses of a header collection."""
    return bool(
        not _receiver_is_inbound(ctx, line_num)
        or _INBOUND_PARSER.search(line)
        or _PROXY_MACHINERY.search(ctx.content)
        or _window_matches(ctx.lines, line_num, _STRIP_RADIUS, _HEADER_STRIPPED)
    )


def _forwards_request_headers(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """True when inbound headers reach an outbound client unmodified."""
    if not any(p.search(line) for p in _HEADER_FORWARD_PATTERNS):
        return False
    if _forward_is_suppressed(ctx, line, line_num):
        return False
    return _window_matches(ctx.lines, line_num, _OUTBOUND_RADIUS, _OUTBOUND_CLIENT)


def _check_header_forward(ctx: _FileCtx, line: str, line_num: int) -> None:
    """CWE-201: inbound request headers inserted into outbound data."""
    if ctx.prose or not _forwards_request_headers(ctx, line, line_num):
        return
    _emit(ctx, {
        # Medium, not high: the rule proves forwarding, not that the recipient
        # is a third party.
        "severity": "medium",
        "check_id": "cwe.info_exposure.header_forwarding",
        "category": "CWE-201",
        "title": "Inbound request headers forwarded to an outbound request",
        "description": (
            f"Line {line_num} copies the incoming request's header collection "
            "onto an outbound call. The collection carries the caller's "
            "Authorization, Cookie and Proxy-Authorization values, so the "
            "upstream service receives credentials that were issued for this "
            "application and can replay them."
        ),
        "recommendation": (
            "Forward an explicit allow-list of headers (content negotiation, "
            "trace ids) and strip Authorization / Cookie before the outbound "
            "call; mint a separate token for the upstream service."
        ),
    }, "201", line_num)


def _check_artefact_under_served_root(ctx: _FileCtx, line: str, line_num: int) -> None:
    """CWE-538: a generated artefact configured to land in a served directory.

    Disjoint from every neighbouring rule by construction. CWE-219 keys on a
    sensitive EXTENSION of a file already on disk (`.log` is not one of them)
    and CWE-552 on a backup copy's name — both anchor on the data file, not on
    the declaration. CWE-548's directory-listing signature anchors on the mount.
    CWE-313/CWE-312 need a credential in the line, which a destination
    declaration does not carry.
    """
    if ctx.prose:
        return
    if not _ARTEFACT_DESTINATION.search(line):
        return
    path = _served_artefact_path(line, ctx.roots)
    if path is None:
        return
    _emit(ctx, {
        "severity": "high",
        "check_id": "cwe.info_exposure.artefact_under_served_root",
        "category": "CWE-538",
        "title": f"Generated artefact written to the web-served path '{path}'",
        "description": (
            f"Line {line_num} writes a log, audit trail, dump or export to "
            f"'{path}', whose directory is served to HTTP clients — either by a "
            "static mount declared in this codebase or by a conventional public "
            "name. Artefacts of this kind accumulate session identifiers, "
            "authorization headers, internal hostnames, query fragments and "
            "stack traces, so publishing the directory hands all of it to any "
            "unauthenticated caller who guesses the filename."
        ),
        "recommendation": (
            "Write the artefact outside the served tree (or to a log shipper) "
            "and remove the mount that publishes the directory. Treat anything "
            "already written there as disclosed and rotate the credentials and "
            "sessions it recorded."
        ),
    }, "538", line_num)


def _check_cleartext_storage(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict], suppression_counts: dict[int, int],
) -> None:
    """Check for cleartext storage of sensitive info (CWE-312).

    Suppress lines whose RHS is a variable reference — `password=$X`,
    `--build-arg STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"` etc. are env
    indirections that the static analysis can't see resolve to a
    literal.
    """
    if SAFE_STORAGE.search(line):
        return
    if line_value_is_variable_ref(line):
        return
    for pattern in CLEARTEXT_STORAGE_PATTERNS:
        if not pattern.search(line):
            continue
        # Two-tier: demote to medium if file lacks database/persist context
        severity = "critical"
        if not check_context(content, _STORAGE_CONTEXT):
            severity = "medium"
        finding = {
            "severity": severity,
            "check_id": "cwe.info_exposure.cleartext_storage",
            "category": "CWE-312",
            "title": "Cleartext storage of sensitive information",
            "description": f"Sensitive value stored in cleartext at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use environment variables, vaults, or encryption for sensitive data",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        if should_suppress(finding["title"], file_path, line, INFO_EXPOSURE_SUPPRESSIONS, suppression_counts):
            return
        findings.append(enrich_finding(finding, "312"))
        return


def _check_sensitive_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for sensitive information in responses (CWE-200)."""
    for pattern in SENSITIVE_RESPONSE_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.info_exposure.sensitive_response",
            "category": "CWE-200",
            "title": "Sensitive information exposure in response",
            "description": f"Internal details exposed in response at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Do not expose internal paths, database details, or debug info in responses",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "200"))
        return


def _dump_source(lines: list[str], line_num: int, line: str) -> str | None:
    """Return the expression that dumps a whole config into ``line``, if any.

    Same-line first (`res.json(process.env)`), then the identifiers the sink
    sends, resolved against assignments above. Only an assignment whose
    right-hand side is itself a whole-config dump counts, which is what keeps
    `res.json({ version: config.get('app.version') })` quiet.
    """
    if _CONFIG_DUMP.search(line):
        return line.strip()
    args = line[line.find("(", _RESPONSE_SINK.search(line).start()) :]
    names = {n for n in _IDENTIFIER.findall(args) if n not in _NOT_A_VALUE}
    if not names:
        return None
    start = max(0, line_num - 1 - _ASSIGNMENT_RADIUS)
    for prior in lines[start : line_num - 1]:
        if "=" not in prior or not _CONFIG_DUMP.search(prior):
            continue
        target = prior.split("=", 1)[0]
        if any(re.search(rf"\b{re.escape(n)}\b", target) for n in names):
            return prior.strip()
    return None


def _check_config_exposure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for a whole application config/environment in a response (CWE-497)."""
    if not _RESPONSE_SINK.search(line):
        return
    dump = _dump_source(lines, line_num, line)
    if dump is None:
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.config_exposure",
        "category": "CWE-497",
        "title": "Application configuration exposed in HTTP response",
        "description": (
            f"The response built at line {line_num} carries a whole-configuration "
            f"or whole-environment object (`{dump[:160]}`). Serialising the full "
            "config exposes internal hostnames, feature flags, file paths, "
            "third-party endpoints and any credential that lives in the same "
            "object to every caller of the endpoint."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Return an explicit allow-list of the settings the client actually "
            "needs instead of the whole config object, and keep secrets in a "
            "separate namespace that is never serialised."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "497"))


def _check_token_in_query(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for a credential carried in a URL query string (CWE-598)."""
    match = _SENSITIVE_QUERY_PARAM.search(line)
    if match is None:
        return
    if not _URLISH.search(line):
        return
    if _NON_HTTP_SCHEME.search(line):
        return
    param = match.group(0).strip("?&=")
    finding = {
        "severity": "high",
        "check_id": "cwe.info_exposure.token_in_query_string",
        "category": "CWE-598",
        "title": f"Credential '{param}' passed in a URL query string",
        "description": (
            f"Line {line_num} builds a URL that carries '{param}' as a query "
            "parameter. Query strings are recorded in browser history, proxy and "
            "web-server access logs, and are forwarded in the Referer header of "
            "any subsequent request, so the value leaks even over TLS."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Send credentials in a request header (Authorization) or a POST body "
            "instead of the query string, and rotate any token that has already "
            "been transmitted this way."
        ),
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "598"))


check_information_exposure_tool = function_tool(check_information_exposure)
