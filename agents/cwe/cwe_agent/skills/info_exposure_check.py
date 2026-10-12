"""Information exposure vulnerability detection skill."""

import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterator, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from itertools import accumulate
from pathlib import Path
from threading import Lock, get_ident, local
from typing import NamedTuple

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._args import mask_literals
from cwe_agent.skills._lexical import (
    MAX_SCAN_CHARS,
    call_argument_text,
    catch_binding,
    identifier_words,
    indent_width,
    param_name,
    paren_lists,
    routine_header,
    stripped_code,
)
from cwe_agent.skills._var_reference import line_value_is_variable_ref
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

# CWE-209: Error message information disclosure
#
# The first five patterns are Python/Java/Go stack shapes. Node is covered by the
# `.stack` arm below and, since feature 0101, by the value resolver at the end of
# the CWE-209 section (`_response_discloses_error`): the Node bare-NAME regex that
# stood here matched any identifier starting err/error/ex/exception inside a
# response write, whatever it held (measured on one real target: 7 true of 84).
_FIXED_STACK_SHAPES = [
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"\.printStackTrace\s*\("),  # Java
    re.compile(r"debug\.PrintStack\s*\("),  # Go
    re.compile(r"return\s+.*(?:traceback|stacktrace|stack_trace)", re.IGNORECASE),
]
# A `.stack` property reaching the response, in any wrapping:
#   res.status(500).json({ stack: err.stack })
# Judged only when the write goes to the PEER (`_sink_is_peer`): measured on a
# review probe, `process.stderr.write(err.stack)` was reported through this arm alone.
_STACK_IN_WRITE = re.compile(r"\.(?:send|json|end|write)\s*\([^)]*\.stack\b")
ERROR_DISCLOSURE_PATTERNS = [*_FIXED_STACK_SHAPES, _STACK_IN_WRITE]


def _any_of(patterns: list[re.Pattern[str]]) -> re.Pattern[str]:
    """One alternation matching wherever any of ``patterns`` matches (flags kept per arm)."""
    return re.compile("|".join(f"(?{'i' if p.flags & re.IGNORECASE else ''}:{p.pattern})" for p in patterns))


# Per-line prefilters: one C search instead of a Python loop of five or six.
_FIXED_STACK_ANY = _any_of(_FIXED_STACK_SHAPES)
_DISCLOSURE_ANY = _any_of(ERROR_DISCLOSURE_PATTERNS)

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

    text = _STRING_LITERAL.sub(_repl, line)
    # Every alternative of the noise pattern spells "token" (case-insensitively):
    # without it the pattern cannot match, and its scan is most of this function's cost.
    return _TOKEN_COUNT_NOISE.sub("count", text) if "token" in text.lower() else text

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
    # One CWE-209 scan context per call (feature 0101 rev3): the arms' per-scan
    # state and the tree's declaration index never cross into another scan.
    token = _SCAN.set(_ScanCtx(complete=False))
    try:
        _scan_source(source_path, findings, suppression_counts)
        _judge_deferred(findings)
    finally:
        _SCAN.reset(token)
    return {"findings": findings}


def _scan_source(source_path: str, findings: list[dict], suppression_counts: dict[int, int]) -> None:
    """Backups, sensitive files under a served root, then every code file."""
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
    _walk_code_files(source_path, findings, suppression_counts)


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
    if "use" in line and LEAKY_ERROR_MIDDLEWARE.search(line):   # the pattern spells `use`
        _report_leaky_middleware(file_path, line_num, lines, findings)
        return

    # Server-side logging of an error is CWE-532's concern, so the error inside a
    # log call never counts -- but only the log call's own SPAN is blanked, not
    # the line: `console.error(err); res.json({ error: err.message })` still
    # writes the error to the peer.
    code = _mask_log_calls(line)

    # CWE-550 is the precise id where the sink is unambiguously an HTTP
    # response and the value unambiguously server-generated. It REPLACES the
    # 209 row on that line — skill findings are not deduplicated against each
    # other, so a child that does not suppress its parent ships two rows.
    if _check_server_error_response(file_path, code, line_num, lines, findings):
        return

    _check_error_value_in_response(file_path, code, line_num, lines, findings)


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


def _check_error_value_in_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Report error detail reaching the peer (CWE-209): the value rule, then the additive
    revision-3 arms (W, C1/C2/H, S) on a line it leaves clean. One row per line, once."""
    ctx = _active_scan()
    _begin_line(ctx, file_path, lines, findings)
    try:
        if _discloses_error(file_path, line, line_num, lines) or _arm_reports(ctx, line, line_num):
            _emit_209(line_num)
    finally:
        ctx.active, ctx.findings = False, None


# Every _SERVER_ERROR_PATTERNS entry spells one of these words (the `sendError`
# one case-insensitively), so a line with none of them skips all five scans.
_SERVER_ERROR_WORDS = ("error", "write", "response", "jsonify")


_SERVER_ERROR_WORD = re.compile("|".join(_SERVER_ERROR_WORDS))   # one C scan, not four


def _may_be_server_error(line: str) -> bool:
    if not _SERVER_ERROR_WORD.search(line.lower()):
        return False
    return any(p.search(line) for p in _SERVER_ERROR_PATTERNS)


def _check_server_error_response(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> bool:
    """CWE-550: a server-generated error value written to an HTTP response.

    Returns True when a row was emitted, which suppresses the CWE-209 row for
    the same line (P5 — skill findings do not cross-deduplicate).
    """
    # The pattern test first and the path parse memoised: it runs on every line, and
    # the per-line parse was 15% of a dense file's time.
    if not _may_be_server_error(line) or _is_prose(file_path):
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


# ---------------------------------------------------------------------------
# CWE-209 VALUE SECTION (feature 0101): WHAT VALUE reaches a peer write.
#
# The replaced shape matched any identifier whose NAME began err/error/ex/
# exception inside a `.send/.json/.end/.write(` call. Measured on one real
# target: 8.3% precision (7 true of 84 adjudicated). About 60 false rows were a
# catalogue helper whose own name starts with "error" returning a fixed entry,
# and about 8 were a code or enum FIELD (`{ error: err.code }`). The name of
# what is written says nothing; what is written does. Disclosure is the error's
# MESSAGE, STACK, string form or raw object reaching the PEER, so the rule
# resolves the value: within the sink call's arguments first, then back to its
# binding in the routine (a catch binding, an error parameter, a local assigned
# from either). A raw error flows through any call unless that call projects or
# sanitises it, so `Object.assign({}, err)` and `serializeFault(err)` still
# report while `catalogEnvelope(FaultCatalog.X)` carries no error at all.
#
# Every role is a word lexicon over identifier words, never a library table, so
# a new language whose idioms map onto the roles needs no change here. Every
# line a helper reads is capped at MAX_SCAN_CHARS and every quantifier is
# bounded (gated by tests/unit/test_0101_cwe209_redos.py); per-line binding
# facts, per-row binding verdicts and per-sink resolutions are memoised, so a
# file's cost is linear in its size (tests/unit/test_0101_cwe209_density.py:
# 25.8 s -> ~0.03 s on a review's worst file of 40 near-cap sinks). A sink that no
# error marker can reach is not analysed at all (`_MARKER`, `_may_feed`), and
# everything cached per file lives in that file's `_FileState`, of which at
# most _STATE_FILES are kept (tests/unit/test_0101_cwe209_sinks_per_line.py,
# test_0101_cwe209_memo_bounded.py).
# ---------------------------------------------------------------------------

# The sink: a member write or send to the peer, operator neutral (`.` or `->`).
# A verb suffix is accepted only when it is RESPONSE-shaped (camel or snake, up
# to three words: `writeHead`, `sendStatus`, `WriteAsJsonAsync`, `write_all`,
# `send_error`). Measured on one multi-language target, accepting any short
# suffix made an enum case constructor (`Fault.writeFailed(...)` x4) and an
# outbound `session.sendMessage(...)` x2 into sinks.
_SINK_SUFFIX = r"(?:_?(?i:as|async|json|text|html|status|head|header|headers|body|all|error|string|bytes))"
_RESPONSE_WRITE = re.compile(
    r"(?:\.|->)\s{0,4}(?:(?i:json|end)|(?i:send|write|respond|reply)" + _SINK_SUFFIX + r"{0,3})\s{0,4}\("
)
_ID = r"\$?[A-Za-z_][\w$]{0,63}"
_ACC = r"\s{0,2}(?:\?\.|\.|->)\s{0,2}"
# A member chain ending in a detail accessor; removed before bare tokens are read,
# so `err` in `err.message` is not ALSO judged as a raw value.
_DETAIL_ACCESSOR = (
    r"(?:message|Message|msg|getMessage|getLocalizedMessage|toString|ToString|Error|what"
    r"|details?|full_message|stack|StackTrace|stackTrace|stack_trace|backtrace|getStackTrace)\b"
)
_DETAIL_CHAIN = re.compile(rf"(?<![\w$])({_ID}(?:{_ACC}{_ID}){{0,4}}?){_ACC}{_DETAIL_ACCESSOR}")
# The access operator plus the accessor: implied by every match of the chain
# pattern, and accessor-led, so a text with none skips the chain-led scan
# (measured ~12x cheaper on a 2000-character argument text).
_ACCESS_OP = r"(?:\?\.|\.|->)\s{0,2}"
_DETAIL_TAIL = re.compile(_ACCESS_OP + _DETAIL_ACCESSOR)
# Possessive identifiers (`{0,63}+`): every identifier here is followed by an
# access operator or ends the match, and neither can start inside one, so
# backtracking into it never matches. Same matches, ~2.5x faster on a sink's arguments.
_ID_POSSESSIVE = r"\$?[A-Za-z_][\w$]{0,63}+"
_MEMBER_CHAIN = re.compile(rf"(?<![\w$.])({_ID_POSSESSIVE})((?:{_ACC}{_ID_POSSESSIVE}){{1,5}})")
_SEGMENT_SPLIT = re.compile(r"\?\.|\.|->")
# An identifier that names an error: the conventional bindings, an err/error/
# exception prefix followed by a further word, or an *Error / *Exception suffix.
_ERROR_NAME = re.compile(   # fullmatch only; `^` keeps a stray search linear
    r"^\$?(?:e|ex|exc|err|error|exception|throwable|cause"
    r"|(?:err|error|exception)[A-Z_0-9][\w$]{0,60}"
    r"|[\w$]{0,60}(?:Error|Exception|Err|Exc))"
)
# A necessary condition for a MEMBER segment matching `_ERROR_NAME`: one of these
# words in the lower-cased text, or a bare `e`/`ex` token (literal-led, so the
# search skips ahead; ~50x cheaper than a case-insensitive alternation).
_ERROR_WORDS = ("err", "exc", "throwable", "cause")
_BARE_E = re.compile(r"ex?(?![\w$])(?<![\w$]e)(?<![\w$]ex)")
# The unresolved fallback. Bare `e` and `ex` are not in it: they reported
# WebSocket relays (`(e) => client.send(e)`) and row streams.
_EXACT_ERROR_NAME = re.compile(r"\$?(?:exc|err|error|exception)")
# Innermost call, bounded so a long line cannot drive backtracking.
_INNER_CALL = re.compile(r"(?<![\w$])([$A-Za-z_][\w$.]{0,80})\s{0,2}\(([^()]{0,400})\)")
# Every `_INNER_CALL` match ends in an innermost group and starts at most
# _CALLEE_REACH characters before it (an 81-character callee and 2 spaces), so
# the callee-led search starts there, not at every identifier of the text.
_INNER_GROUP = re.compile(r"\([^()]{0,400}\)")
_CALLEE_REACH = 83
_STRINGIFIER = re.compile(
    r"(?i)(?:str|string|repr|inspect|stringify|dumps?|to_?json|to_?string|serialize|sprint\w{0,3}|format)"
)
# A value token: not a member, not a callee, not an object key (`key:` but not
# `::`), not itself followed by an access.
_VALUE_TOKEN = re.compile(rf"(?<![\w$.>])({_ID})(?![\w$])(?!\s{{0,2}}(?:\(|\??:(?!:)|\?\.|\.|->))")
_PREDICATE_METHODS = (
    r"\.\s{0,2}(?:includes|startsWith|endsWith|match|matches|test|indexOf|contains|startswith"
    r"|endswith|search)\s{0,2}\("
)
_PREDICATE_CALL = re.compile(_PREDICATE_METHODS)   # trigger for `_PM_PRED`, which ends in one
# Methods that keep a string a string: `String(err).slice(0, 500)` still carries the error.
_STRING_TRANSFORM = re.compile(
    r"\.\s{0,2}(?:slice|substring|substr|encode|trim\w{0,6}|as_bytes|replace\w{0,4}|to\w{0,8}Case|strip"
    r"|rstrip|lstrip|padEnd|padStart|getBytes)\s{0,2}\([^()]{0,80}\)"
)
# A zero-argument method that renders its receiver: replaced by the receiver.
_RENDER_METHOD = (
    r"(?:toJSON|to_json|to_string|toString|ToString|to_s|inspect"
    r"|__str__|__repr__|getMessage|getLocalizedMessage|localizedMessage|stackTraceToString"
    r"|getTraceAsString|getStackTrace|Error)\s{0,2}\(\s{0,2}\)"
)
_METHOD_STRINGIFIER = re.compile(rf"(?<![\w$])({_ID}(?:{_ACC}{_ID}){{0,4}}){_ACC}{_RENDER_METHOD}")
_RENDER_TAIL = re.compile(_ACCESS_OP + _RENDER_METHOD)   # as _DETAIL_TAIL
# Members of a CAUGHT error that project it to a safe value. Any other member is
# detail (`err.response.data`, `err.sqlMessage`, `e.args`, `e.localizedMessage`),
# so no per-language accessor list is needed.
_SAFE_MEMBERS = frozenset({
    "code", "status", "statuscode", "status_code", "name", "type", "kind", "errno", "getcode",
    "getstatuscode", "expose", "gettype", "getclass", "javaclass", "constructor", "__class__",
    "__name__", "id", "httpstatus", "statustext", "payload", "publicmessage", "public_message",
})
# Detail roles of the LAST member of an error-NAMED chain whose root is unresolved.
_DETAIL_WORDS = frozenset({
    "message", "msg", "stack", "trace", "traceback", "backtrace", "description", "inspect", "cause",
    "inner", "original", "args", "details", "detail", "what", "s", "str", "repr", "json", "string",
    "localized",
})
_DETAIL_MEMBERS = frozenset({"Error", "getMessage", "getLocalizedMessage"})
# A callee whose words carry one of these PROJECTS or sanitises what it is given.
_PROJECTION_WORDS = frozenset({
    "code", "codes", "status", "catalog", "catalogue", "public", "safe", "sanitize", "sanitise",
    "redact", "mask", "map", "mapper", "translate", "i18n", "t", "id", "count", "length", "len",
    "size", "bool", "boolean", "number", "int", "is", "has", "can", "should", "kind", "type", "name",
    "hash", "classify", "category", "user", "friendly", "generic", "body", "payload", "build",
    "envelope", "problem", "format", "dto", "view",
})
# Extractor by words, with explicit precedence: a stack verb + stack noun pair
# (`format_exception`, `print_exc`, `dumpStack`), else a detail word whose callee
# does not END in a projection word (`getErrorMessage` yes, `getTraceId` no).
_DETAIL_CALL_WORDS = frozenset({
    "message", "msg", "messages", "stack", "trace", "traceback", "backtrace", "stacktrace",
})
# A callee with one of these words VALIDATES the peer's input; its result's error
# names the refused field (fixtures f10 / rp14).
_VALIDATION_WORDS = frozenset({"validate", "validation", "validator", "schema"})
_STACK_VERBS = frozenset({"format", "print", "dump"})
_STACK_NOUNS = frozenset({"exception", "exc", "tb", "traceback", "stack", "trace"})
_BASE_ERROR_TYPES = frozenset({
    "error", "exception", "throwable", "unknown", "any", "object", "standarderror", "baseexception",
})
_SCALAR_TYPES = frozenset({
    "string", "str", "number", "int", "integer", "bool", "boolean", "float", "double", "long",
})
# A write is a PEER write unless its receiver chain carries a local role.
_NONPEER_WORDS = frozenset({
    "stderr", "stdout", "console", "fs", "file", "files", "log", "logger", "logs", "mail", "mailer",
    "smtp", "builder", "sb", "buf", "buffer", "queue", "producer", "beacon", "navigator", "ipc",
    "process", "sys", "os", "crash", "disk", "cache", "metrics", "telemetry", "debug", "trace",
})
_STDIO_WORDS = frozenset({"stderr", "stdout", "os"})
# A PascalCase chain ROOT names a type, enum or static, not a peer, unless its
# own words carry a peer role (`Response.Write(` in classic server pages).
_PEER_ROOT_WORDS = frozenset({
    "response", "request", "http", "context", "client", "socket", "writer", "output", "reply", "res",
    "resp", "conn", "connection", "stream", "channel",
})
# A type ROOT may also be the handler's results factory (`Results.Json(...)`, `TypedResults.Problem(...)`):
# what it builds is the response. Only a chain root: a variable named `results` is no peer.
_PEER_TYPE_ROOT_WORDS = _PEER_ROOT_WORDS | frozenset({"results"})
_RECEIVER_IDS = re.compile(r"[A-Za-z_$][\w$]{0,60}")
_RECEIVER_ROOT = re.compile(
    r"(?<![\w$])([A-Za-z_$][\w$]{0,60})((?:\s{0,2}(?:\?\.|\.|->)\s{0,2}[A-Za-z_$][\w$]{0,60}){0,5})\s{0,2}$"
)
_FIRST_ARGUMENT_CHAIN = re.compile(r"^\s{0,4}([\w$.]{1,60})")
_TYPED_PARAM = re.compile(   # match only
    r"^(?:(\$?[A-Za-z_][\w$]{0,60})\s{0,2}\??:\s{0,2}([\w$.:&*<>\[\]|]{1,60})"
    r"|([\w$.<>\[\]]{1,60})\s{1,4}\$?([A-Za-z_][\w$]{0,60})\s{0,2}$)"
)
# A callback literal declares parameters without being a NAMED declaration,
# which is all `_lexical.routine_header` accepts (by design).
_ARROW = re.compile(r"=>")
# `clean` only for a literal, a constant / catalogue member, or a constructor
# with literal arguments; anything else is `unknown`, never assumed safe.
_LITERALISH = re.compile(
    r"^\s{0,4}(?:[\"'`]|-?\d|true\b|false\b|null\b|None\b|nil\b|undefined\b|\{\s{0,2}\}|\[\s{0,2}\]"
    r"|[A-Z][\w$]{0,60}(?:\.[A-Z_][\w$]{0,60}){1,3}\s{0,4}[;,)]?\s{0,4}$|new\s{1,4}\w{1,60}\(\s{0,4}[\"'`])"
)
_CAST = re.compile(r"\(\s{0,2}([\w$.]{1,80})\s{1,4}as\s{1,4}[\w$.<>]{1,60}\s{0,2}\)")
_NON_NULL = re.compile(r"(?<![\w$])([\w$]{1,60})!(?=[.\s;,)])")
_LEAD_KEYWORD = re.compile(r"^(?:await|yield|try)\s{1,4}")
_SINGLE_CALL = re.compile(r"^([$A-Za-z_][\w$.]{0,80})\s{0,2}\((.{0,400})\)")
_ASSIGN_TARGET = re.compile(
    r"(?<![\w$.])(\$?[A-Za-z_][\w$]{0,60})\s{0,4}(?::\s{0,4}[\w$.<>\[\]|]{1,60}\s{0,2})?(?::=|=(?![=>]))"
)
# `{a, b} = [await|yield|try] source[(`: the lead keyword is never the source (a
# review measured `await` captured as one), and a trailing `(` marks a call result.
_DESTRUCTURE = re.compile(
    r"\{([^{}]{0,200})\}\s{0,4}=(?![=>])\s{0,4}(?:(?:await|yield|try)\s{1,4})?([\w$.]{1,80})(\s{0,2}\()?"
)
_NAMES = re.compile(r"[\w$]{1,64}")
# 209-local literal strip (the shared `_strip_literals` serves CWE-532): a
# `{...}` hole survives only when it is an identifier or member chain, so JSON
# text inside a raw string (`{"error":"disabled"}`) is not read as a value.
_INTERPOLATION_209 = re.compile(r"\$\{([^{}]{1,200})\}|\{([A-Za-z_$][\w$.\[\]()]{0,80})\}")
# `_premask`: tokens that are READ, not WRITTEN -- index keys (`x[...]`, not an
# array literal), negations, comparison and `instanceof` / `&&` left operands,
# predicate-method chains, ternary conditions (`x ?`, but not Kotlin's elvis
# default `x ?: y`, which writes `x`) and `key =` initialisers.
_PM_INDEX = re.compile(r"(?<=[\w$\])])\s{0,2}\[[^\[\]]{0,120}\]")
_PM_NEG = re.compile(rf"!\s{{0,2}}{_ID}(?:{_ACC}{_ID}){{0,4}}")
_PM_CMP = re.compile(rf"(?<![\w$]){_ID}(?:{_ACC}{_ID}){{0,4}}\s{{0,2}}(?:===?|!==?|<=?|>=?|instanceof\b|&&)")
_PM_PRED = re.compile(rf"(?<![\w$]){_ID}(?:{_ACC}{_ID}){{0,4}}(?:{_PREDICATE_METHODS}[^()]{{0,80}}\))")
_PM_TERN = re.compile(rf"(?<![\w$]){_ID}(?:{_ACC}{_ID}){{0,4}}\s{{0,2}}\?(?![.?:])")
_PM_INIT = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]{0,60}\s{0,2}=(?![=>])")
# What `_PM_CMP` can end in; a bare assignment `=` is not one of them.
_COMPARISON_MARKS = ("==", "!=", "<", ">", "&&", "instanceof")

# A comment start on the literal-masked line: a block opener anywhere, a line
# comment (`//`, `#`) at the line start or after whitespace, so `this.#field`,
# `t[#t+1]` and `$#list` are code. Before this, `res.send('ok'); // never
# res.send(err.message)` reported, because sinks were found on a copy with only
# the literals masked (predicates read the comment-stripped line).
_COMMENT_START = re.compile(r"/\*|(?<![^\s])(?://|#)")
# An error-VARIANT pattern binds its payload, as a catch clause does: `Err(problem)
# =>`, `if let Err(problem) =`, `Error(reason) ->`. Only the
# bare variant words of _EXACT_ERROR_NAME: a domain variant's field
# (`QuotaError(limit) =>`) is clean, as a domain-typed parameter is.
_VARIANT_BINDING = re.compile(
    r"(?<![\w$.])([A-Z][a-z]{0,8})\s{0,2}\(\s{0,2}(?:(?:let|ref|mut)\s{1,4})?([a-z_][\w$]{0,60})\s{0,2}\)"
    r"\s{0,2}(?:=>|->|=(?![=>]))"
)
# Python `with ... as fh`, Go `var b T`: declarations that bind a receiver
# without `=`; indexed so the receiver's declaration is found.
_DECLARES = re.compile(r"(?<![\w$.])(?:as|var)\s{1,4}([A-Za-z_][\w$]{0,60})")
# A receiver whose declaration in the routine carries one of these words (and no
# peer word) is local: an opened file, a buffer, a builder
# (`with open(...) as fh: fh.write(str(e))`, `var b bytes.Buffer; b.WriteString(...)`).
_LOCAL_DECL_WORDS = frozenset({"open", "bytes", "tempfile", "tmp", "temp"})

_HANDLER_WORDS = ("catch", "except", "rescue", "case", "pcall")
_BINDING_RADIUS = 30
_MAX_CALL_PASSES = 8
_CONTINUATION_LINES = 12
_MAX_DEPTH = 2
_MAX_TOKENS = 32
_REACH = (_MAX_DEPTH + 1) * _BINDING_RADIUS   # every window walked at depth 0..2
# Sinks judged one by one per line. Measured over four multi-language trees:
# 7,469 lines hold one response write, 35 hold two, one minified line holds four.
_MAX_SINKS_PER_LINE = 4
_CHAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.?->")
_PREFIX_CHARS = 400
# Placeholder for an opaque call's result: NOT an identifier, so it can never
# resolve to a binding. Measured on one multi-language target, the previous `_`
# resolved through a Kotlin `catch (_: Throwable)` 25 lines up.
_OPAQUE = " 0 "
# `field`: a name destructured from a source that is not an error and not known
# clean (a call result, a member, an unresolved name). Its bare value is a result
# FIELD, clean as fixture n04 pins; a detail chain on it is judged by name,
# exactly as the member form `accountRes.error.message` is.
_UNTAINTED = ("clean", "unknown", "field")
_BY_NAME = ("unknown", "field")
# Per-file resolver state (binding index, marker counts, resolution memo) for at
# most _STATE_FILES files, oldest dropped first. Before this, a module-global
# memo capped by ENTRY count kept a reference to every file's lines, so 1500
# scanned files of ~200 KB grew RSS by 394 MB and stayed held across audits.
_STATE_FILES = 8
_MEMO_LIMIT = 4096
# Keyed per thread as well as per line list: the scanner caches a file's line
# tuple, so two concurrent scans of one file hold the SAME list, and a state
# (its memo, its incremental index) must never be shared between them. Every
# get / evict / insert happens under _STATES_LOCK (feature 0101 rev3: 9 of 160
# concurrent thread-runs raised `KeyError` at the unlocked eviction).
_FILE_STATES: dict[tuple, "_FileState"] = {}
_STATES_LOCK = Lock()
_LOCAL = local()     # per thread: the last state and arm file asked for (no lock on the hot path)
# A line can only feed an error into a sink when it holds one of these (lower-
# cased): an error word, a handler keyword, or a bare `e` / `ex` / `$e`. Every
# caught or tainted verdict and every by-name judgement starts from such a line
# (catch bindings are only read on handler-keyword lines, error-named
# parameters and the exact-name fallback spell an error word, by-name chains
# need an error-named segment), and resolution reaches at most _REACH lines
# above the sink. So a sink with no marker from _REACH lines above it to the
# end of its continuation cannot disclose, and is not analysed. Without the gate
# the per-sink resolver cost 1.1-2.2 ms/KB on short closed sink lines (HEAD
# 0.12-0.24), against the 0.5 ms/KB density budget.
_MARKER = re.compile(r"err|exc|throwable|cause|catch|rescue|case|pcall|ex?(?![\w$])(?<![\w]e)(?<![\w]ex)")


class _Scope(NamedTuple):
    """Where a value is read: the file's lines, the line, the text before the sink.

    A NamedTuple, not a frozen dataclass: one is built per sink and per binding
    row, and the frozen dataclass's ``__init__`` was ~2% of a dense file's time."""

    lines: Sequence[str]
    line_num: int
    prefix: str
    depth: int = 0
    suffix: str = ""

    def at(self, line_num: int, depth: int) -> "_Scope":
        return _Scope(self.lines, line_num, "", depth, self.suffix)


class _LineCtx(NamedTuple):
    """The line a sink sits on, and where it sits."""

    lines: Sequence[str]
    line_num: int
    line: str
    suffix: str
    masked: str        # the capped line with literal bodies masked, offsets unchanged


class _Facts(NamedTuple):
    """What one raw line binds: computed once per distinct line text."""

    code: str
    caught: frozenset[str]
    assigns: dict[str, str]
    params: tuple[str, ...]
    destructure: tuple[frozenset[str], str] | None
    names: frozenset[str]


def _discloses_error(file_path: Path, line: str, line_num: int, lines: Sequence[str]) -> bool:
    """Executable code whose line matches a fixed shape or writes error detail to a peer.

    The prose test is a path parse; it runs only on the ~1% of lines that hold a
    stack shape or a response write (measured: per-line, it was the single
    largest cost the port added on one real tree).
    """
    if not _may_disclose(line) or _is_prose(file_path):
        return False
    if _fixed_shape_discloses(line):
        return True
    return _response_discloses_error(lines, line_num, line, _suffix(file_path))


@lru_cache(maxsize=256)
def _suffix(file_path: Path) -> str:
    """The lower-cased suffix once per path, not once per sink line."""
    return file_path.suffix.lower()


@lru_cache(maxsize=256)
def _is_prose(file_path: Path) -> bool:
    """`is_prose_file` once per path, not once per sink line (a path parse)."""
    return is_prose_file(file_path)


def _may_disclose(line: str) -> bool:
    if _RESPONSE_WRITE.search(line[:MAX_SCAN_CHARS]):
        return True
    return _DISCLOSURE_ANY.search(line) is not None


def _fixed_shape_discloses(line: str) -> bool:
    """The five shipped stack shapes, and `.stack` reaching a PEER write."""
    if _FIXED_STACK_ANY.search(line):
        return True
    m = _STACK_IN_WRITE.search(line) if ".stack" in line else None   # the pattern spells it
    return bool(m) and _sink_is_peer(line, m.start(), line.index("(", m.start()) + 1)


# Every _LOG_SINK alternative spells one of these (case-insensitively; `logger`
# contains `log`), so a line with none of them is not searched.
_LOG_SINK_WORDS = ("log", "console", "winston", "pino", "bunyan")


_LOG_SINK_WORD = re.compile("|".join(_LOG_SINK_WORDS))   # one C scan, not five


def _may_log(text: str) -> bool:
    return _LOG_SINK_WORD.search(text.lower()) is not None


def _mask_log_calls(line: str) -> str:
    """Blank the span of every log call: the error inside it is CWE-532's concern.

    Only the call's own span, not the line: `console.error(err); res.json({ error:
    err.message })` still writes the error to the peer after the log call.
    """
    capped = line[:MAX_SCAN_CHARS]
    if not _may_log(capped) or not _LOG_SINK.search(capped):
        return line
    masked = line
    for m in _LOG_SINK.finditer(line[:MAX_SCAN_CHARS]):
        end = m.end() + len(call_argument_text(line, m.end() - 1, MAX_SCAN_CHARS)) + 1
        masked = masked[: m.start()] + " " * (end - m.start()) + masked[end:]
    return masked[: len(line)]


def _response_discloses_error(
    lines: Sequence[str], line_num: int, line: str, suffix: str = "",
) -> bool:
    """True when a peer write on ``line`` carries an error's detail.

    Bounded per line: each sink reads only its OWN span, up to the
    next sink, and past _MAX_SINKS_PER_LINE the remaining sinks are judged once,
    together. Sinks are found on the literal-masked line, so text inside a string
    that merely spells a sink is neither judged nor a cut point.
    """
    state = _file_state(lines, suffix)
    if not state.marked(line_num - 1 - _REACH, line_num + _CONTINUATION_LINES):
        return False
    code, masked = _uncomment(line)
    spans = _sink_spans(masked)
    if not spans or not _may_feed(state, line_num, code, spans):
        return False
    return _spans_disclose(_LineCtx(lines, line_num, code, suffix, masked), spans)


def _spans_disclose(ctx: "_LineCtx", spans: list[tuple[re.Match[str], int | None]]) -> bool:
    if len(spans) == 1:
        return _sink_discloses(ctx, spans)   # the usual line: one write
    return _several_spans_disclose(ctx, spans)


def _several_spans_disclose(ctx: "_LineCtx", spans: list[tuple[re.Match[str], int | None]]) -> bool:
    if any(_sink_discloses(ctx, [span]) for span in spans[:_MAX_SINKS_PER_LINE]):
        return True
    return len(spans) > _MAX_SINKS_PER_LINE and _sink_discloses(ctx, spans[_MAX_SINKS_PER_LINE:])


def _read_rows(code: str, last: re.Match[str]) -> int:
    """How many lines the sinks read: the line's last call continues onto the next
    lines exactly when `_sink_tail` finds it open (its first `_read_enough`)."""
    return 1 + (0 if _read_enough(_strip_literals_209(code[last.end():][:MAX_SCAN_CHARS])) else _CONTINUATION_LINES)


def _may_feed(state: "_FileState", line_num: int, code: str, spans: list) -> bool:
    """A marker can reach the sink: on the lines it reads, or through a name it can
    resolve that some window row mentions with a marker within the two deeper
    windows (see _MARKER). A row that binds a name mentions it, so mentions are
    a superset of bindings, and need no binding facts."""
    rows = _read_rows(code, spans[-1][0])
    if state.marked(line_num - 1, line_num - 1 + rows):
        return True
    names = _resolvable_names(state, line_num, code, spans[0][0], rows)
    return _marker_above_mentions(state, line_num, names) or _mentioned_near_marker(state, line_num, names)


def _marker_above_mentions(state: "_FileState", line_num: int, names: set[str]) -> bool:
    """`_mentioned_near_marker` for the row just above alone, read without the
    file's mention index: the nearest row is the usual binding (`catch (e) {` or
    `const r = await load()` over the write), and when it qualifies the index is
    never built (it was ~8% of a dense file's time)."""
    above = line_num - 2
    if above < 0 or not state.marked(above - 2 * _BINDING_RADIUS, above + 1):
        return False
    return not names.isdisjoint(_NAMES.findall(state.lines[above][:MAX_SCAN_CHARS]))


def _mentioned_near_marker(state: "_FileState", line_num: int, names: set[str]) -> bool:
    """Some window row mentioning a name has a marker within 2 * _BINDING_RADIUS above it.

    A name's window rows all lie in the _BINDING_RADIUS-row window, so their spans
    [r - 2R, r] overlap into ONE span from its first row's start to its last row:
    one marker lookup per name, not one per row."""
    end = line_num - 1
    words, start = state.mentions(end), max(0, end - _BINDING_RADIUS)
    return any(_marked_span(state, rows, start, end) for rows in filter(None, map(words.get, names)))


def _marked_span(state: "_FileState", rows: list[int], start: int, end: int) -> bool:
    i, j = bisect_left(rows, start), bisect_left(rows, end)
    return i < j and state.marked(rows[i] - 2 * _BINDING_RADIUS, rows[j - 1] + 1)


def _resolvable_names(state: "_FileState", line_num: int, code: str, first: re.Match[str], rows: int) -> set[str]:
    """What the sinks can resolve: the text from the first sink's `(` on, its
    continuation, and the prefix only when the prefix binds a name. The receiver
    and the verb are never resolved (`r.send(q)`: only `q`)."""
    text = _resolvable_text(state, line_num, code, first, rows)
    words = set(_NAMES.findall(text))
    return words.union([w.lstrip("$") for w in words]) if "$" in text else words


def _resolvable_text(state: "_FileState", line_num: int, code: str, first: re.Match[str], rows: int) -> str:
    prefix = code[: first.start()][-_PREFIX_CHARS:]
    binds = bool(_line_names(prefix, state.suffix))
    if rows == 1 and not binds:
        return code[first.end():]   # the usual write: no join to build
    tail = state.lines[line_num: line_num - 1 + rows]
    return " ".join([prefix if binds else "", code[first.end():], *tail])


def _uncomment(line: str) -> tuple[str, str]:
    """(code, masked): the line with every comment blanked, and that line with its
    literal bodies masked too; offsets unchanged. Text past the cap is kept only
    when no comment runs to the cap (the shipped read of a long last argument)."""
    capped = line[:MAX_SCAN_CHARS]
    masked = mask_literals(capped)
    spans = _comment_spans(masked)
    if not spans:
        return line, masked
    tail = "" if spans[-1][1] >= len(capped) else line[MAX_SCAN_CHARS:]
    return _blank(capped, spans) + tail, _blank(masked, spans)


def _comment_spans(masked: str) -> list[tuple[int, int]]:
    if "/" not in masked and "#" not in masked:
        return []   # every comment start spells one of them
    spans: list[tuple[int, int]] = []
    m = _COMMENT_START.search(masked)
    while m:
        spans.append((m.start(), _comment_end(masked, m)))
        m = _COMMENT_START.search(masked, spans[-1][1])
    return spans


def _comment_end(masked: str, start: re.Match[str]) -> int:
    if start.group() != "/*":
        return len(masked)
    close = masked.find("*/", start.end())
    return len(masked) if close < 0 else close + 2


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    parts, prev = [], 0
    for a, b in spans:
        parts += [text[prev:a], " " * (b - a)]
        prev = b
    return "".join(parts) + text[prev:]


@lru_cache(maxsize=4096)
def _uncommented(line: str) -> str:
    """A continuation line with its comments blanked (it is capped already)."""
    return _uncomment(line)[0]


def _sink_spans(masked: str) -> list[tuple[re.Match[str], int | None]]:
    """Every sink outside a literal, with where its span ends (None: the line's end)."""
    sinks = list(_RESPONSE_WRITE.finditer(masked))
    if len(sinks) < 2:
        return [(s, None) for s in sinks]
    ends: list[int | None] = [_receiver_start(masked, s.start()) for s in sinks[1:]]
    return list(zip(sinks, [*ends, None]))


def _receiver_start(masked: str, pos: int) -> int:
    """Where the receiver chain ending at ``pos`` begins: the next write's receiver
    is not an argument of the call before it (at most 160 characters back)."""
    i, floor = pos, max(0, pos - 160)
    while i > floor and masked[i - 1] in _CHAIN_CHARS:
        i -= 1
    return i


def _sink_discloses(ctx: "_LineCtx", spans: list[tuple[re.Match[str], int | None]]) -> bool:
    """The value rule, then arm Y (a detail-role key over an error field beside a code)."""
    return _value_sink_discloses(ctx, spans) or _key_role_reports(ctx, spans)


def _value_sink_discloses(ctx: "_LineCtx", spans: list[tuple[re.Match[str], int | None]]) -> bool:
    """The first sink's receiver and prefix stand for every span judged with it."""
    first = spans[0][0]
    if not _sink_is_peer(ctx.line, first.start(), first.end()):
        return False
    scope = _Scope(ctx.lines, ctx.line_num, ctx.line[: first.start()], suffix=ctx.suffix)
    args = _joined_arguments(ctx, spans)
    return _args_disclose(_strip_literals_209(args[:MAX_SCAN_CHARS]), scope) and not _declared_local(scope)


def _joined_arguments(ctx: "_LineCtx", spans: list[tuple[re.Match[str], int | None]]) -> str:
    if len(spans) == 1:
        return _span_arguments(ctx, spans[0][0].end(), spans[0][1])
    return " , ".join(_span_arguments(ctx, sink.end(), end) for sink, end in spans)


def _declared_local(scope: _Scope) -> bool:
    """The receiver's nearest declaration in the window names a local role and no
    peer role. Read only for a sink that would report, so it costs nothing elsewhere."""
    root = _chain_root(stripped_code(scope.prefix)[-160:])
    if not root:
        return False
    rows = _candidate_rows(_file_state(scope.lines, scope.suffix).index(scope.line_num - 1), root,
                           scope.line_num - 1)
    return bool(rows) and _local_role(_declaration(scope.lines[rows[0]], root, scope.suffix))


def _declaration(raw: str, root: str, suffix: str) -> str:
    """The text declaring ``root``: on a routine header only its own parameter, so
    another parameter's type (`raw: string`) cannot lend it a role."""
    facts = _line_facts(raw[:MAX_SCAN_CHARS], suffix)
    if root not in facts.params:
        return facts.code
    return next((p for p in _param_list(facts.code) if param_name(p) == root), "")


def _local_role(text: str) -> bool:
    words = {w for r in _RECEIVER_IDS.findall(text) for w in identifier_words(r)}
    return bool(words & (_LOCAL_DECL_WORDS | _NONPEER_WORDS)) and not words & _PEER_ROOT_WORDS


def _span_arguments(ctx: "_LineCtx", start: int, end: int | None) -> str:
    """The call's raw arguments within its span; only the line's last sink
    continues onto the following lines while its call stays open."""
    if end is None:
        return call_argument_text("(" + _sink_tail(ctx.lines, ctx.line_num, ctx.line[start:]), 0, MAX_SCAN_CHARS)
    seg = ctx.masked[start:end]
    if "(" in seg:
        return call_argument_text("(" + ctx.line[start:end], 0, MAX_SCAN_CHARS)
    close = seg.find(")")
    return ctx.line[start:end] if close < 0 else ctx.line[start:start + close]


def _sink_is_peer(line: str, start: int, end: int) -> bool:
    """A write whose receiver (or first argument) is in a local role is not to the peer."""
    before = stripped_code(line[:start])[-160:]
    return not (_receiver_is_local(before) or _first_argument_is_stdio(line[end:]))


@lru_cache(maxsize=1024)
def _receiver_is_local(before: str) -> bool:
    """The receiver chain ending ``before`` is a type or names a local role. Cached:
    a file writes through a handful of receivers (`res`, `w`, `ctx`) on every sink."""
    return _type_root(before) or bool(_receiver_words(before) & _NONPEER_WORDS)


def _receiver_words(before: str) -> set[str]:
    """Words of the last four identifiers of the receiver chain."""
    if before.count("(") > before.count(")"):
        before = before.split("(")[-1]
    return {w for r in _RECEIVER_IDS.findall(before)[-4:] for w in identifier_words(r)}


def _type_root(before: str) -> bool:
    """`Fault.writeFailed(` / `Pipeline.send(`: a PascalCase root with no peer role."""
    root = _chain_root(before)
    return bool(root) and _names_a_type(root) and not set(identifier_words(root)) & _PEER_TYPE_ROOT_WORDS


@lru_cache(maxsize=1024)
def _chain_root(before: str) -> str | None:
    """The root of the receiver chain, or None when the chain is longer than we read."""
    m = _RECEIVER_ROOT.search(before)
    if not m or before[: m.start()].rstrip().endswith((".", "->", "?")):
        return None
    return m.group(1)


def _names_a_type(root: str) -> bool:
    return root[:1].isupper() and not root.isupper()


def _first_argument_is_stdio(after: str) -> bool:
    """`io.WriteString(os.Stderr, ...)`: the target is the first argument."""
    m = _FIRST_ARGUMENT_CHAIN.match(after)
    return bool(m) and "." in m.group(1) and bool(set(identifier_words(m.group(1))) & _STDIO_WORDS)


def _sink_tail(lines: Sequence[str], line_num: int, tail: str) -> str:
    """The text after the sink's `(`, continued while the call stays open.

    `res.status(s).json({` with the leaking key many lines down is the same
    disclosure; bounded so an unbalanced call costs at most _CONTINUATION_LINES
    more (capped) lines, never the rest of the file. A following line's own sink
    ends the read there: that line judges what it writes, and reading on made a
    short open line carry ~MAX_SCAN_CHARS of analysis.
    """
    joined = _strip_literals_209(tail[:MAX_SCAN_CHARS])
    for nxt in lines[line_num: line_num + _CONTINUATION_LINES]:
        if _read_enough(joined):
            break
        head, sink = _before_sink(_uncommented(nxt[:MAX_SCAN_CHARS]))
        joined = f"{joined} {_strip_literals_209(head)}"
        if sink:
            break
    return joined[:MAX_SCAN_CHARS]


def _read_enough(joined: str) -> bool:
    """The call closed, or the cap is reached (nothing past it is read, so nothing is stripped)."""
    return len(joined) >= MAX_SCAN_CHARS or joined.count("(") < joined.count(")")


def _before_sink(line: str) -> tuple[str, bool]:
    """``line`` up to its first sink outside a literal, and whether it has one."""
    sink = _RESPONSE_WRITE.search(mask_literals(line)) if _RESPONSE_WRITE.search(line) else None
    return (line[: sink.start()], True) if sink else (line, False)


@lru_cache(maxsize=4096)
def _strip_literals_209(line: str) -> str:
    """Literal text out, interpolated identifiers kept."""
    return _STRING_LITERAL.sub(_literal_holes, line)


def _literal_holes(match: re.Match[str]) -> str:
    kept = " ".join(_holes(match.group(0).strip("`'\"")))
    return f'"" {kept}' if kept else '""'


def _holes(body: str) -> list[str]:
    return [g for m in _INTERPOLATION_209.finditer(body) for g in m.groups() if g]


def _args_disclose(args: str, scope: _Scope) -> bool:
    """Detail on an error chain, or an error value surviving every call around it."""
    if not args.strip():
        return False
    if _detail_reaches(args, scope):
        return True
    text = _neutralise_calls(args, scope)
    return text is None or _bare_error_reaches(text, scope)


def _detail_reaches(text: str, scope: _Scope) -> bool:
    return _member_chain_discloses(_premask(text), scope)


def _carries_error(text: str, scope: _Scope) -> bool:
    return _detail_reaches(text, scope) or _bare_error_reaches(text, scope)


def _has_access(text: str) -> bool:
    """Every chain pattern needs an access operator; most argument texts have none."""
    return "." in text or "->" in text


def _member_chain_discloses(text: str, scope: _Scope) -> bool:
    """Chains grouped by root, so each root is resolved once."""
    by_root = _chains_by_root(text) if _has_access(text) else {}
    if not by_root:
        return False
    may_bind = _binder(scope)   # one window read for every root
    return any(_root_discloses(root, chains, scope, text, may_bind) for root, chains in by_root.items())


def _chains_by_root(text: str) -> dict[str, list[str]]:
    by_root: dict[str, list[str]] = defaultdict(list)
    for root, chain in _MEMBER_CHAIN.findall(text):
        by_root[root].append(chain)
    return by_root


def _root_discloses(root: str, chains: list[str], scope: _Scope, text: str, may_bind: Callable[[str], bool]) -> bool:
    """The value rule's verdict, then arm F (a result field filled from an error)."""
    return _root_discloses_by_name(root, chains, scope, text, may_bind) or _field_arm(root, chains, scope, may_bind)


def _root_discloses_by_name(root: str, chains: list[str], scope: _Scope, text: str,
                            may_bind: Callable[[str], bool]) -> bool:
    """Caught-root inversion first; else an error-NAMED chain ending in detail.
    ``may_bind`` is `_binder(scope)`: `_resolve`, with the window read once per text."""
    verdict = _resolve_with(root, scope, may_bind)
    if verdict not in _UNTAINTED:
        return _any_unsafe_member(chains)
    return _judged_by_name(verdict, root, text) and any(_named_chain_discloses(root, _members(c)) for c in chains)


def _any_unsafe_member(chains: list[str]) -> bool:
    """A caught or tainted root: any first member but a safe projection is detail.

    A chain's first member is its first identifier run: `_members(c)[0]` without
    building the whole member list."""
    return any(_IDENT_RUN.search(c).group().lower() not in _SAFE_MEMBERS for c in chains)


_IDENT_RUN = re.compile(r"[\w$]+")


def _judged_by_name(verdict: str, root: str, text: str) -> bool:
    """A by-name verdict on an error-named root, or in a ``text`` holding some
    error-named segment at all (read only here: a caught root never needs it)."""
    return verdict in _BY_NAME and (_ERROR_NAME.fullmatch(root) is not None or _names_some_error(text))


_ERROR_WORD = re.compile("|".join(_ERROR_WORDS))   # one C scan, not four


@lru_cache(maxsize=1024)
def _names_some_error(text: str) -> bool:
    return _ERROR_WORD.search(text.lower()) is not None or _BARE_E.search(text) is not None


def _members(chain: str) -> list[str]:
    return [s for s in _SEGMENT_SPLIT.split("".join(chain.split())) if s]


def _named_chain_discloses(root: str, members: list[str]) -> bool:
    """`uploadError.message`; never `Type.CONST.message` (a constant)."""
    if not _chain_names_error(root, members) or _is_type_constant(root, members):
        return False
    return _is_detail_member(members[-1])


def _chain_names_error(root: str, members: list[str]) -> bool:
    return any(_ERROR_NAME.fullmatch(s) for s in (root, *members[:-1]))


def _is_type_constant(root: str, members: list[str]) -> bool:
    return root[:1].isupper() and members[0].isupper()


def _is_detail_member(member: str) -> bool:
    return bool(set(identifier_words(member)) & _DETAIL_WORDS) or member in _DETAIL_MEMBERS


def _neutralise_calls(text: str, scope: _Scope) -> str | None:
    """Collapse calls innermost first; None as soon as one yields error detail."""
    text = _render_receivers(text)
    for _ in range(_MAX_CALL_PASSES):
        text = _drop_transforms(text)
        m = _innermost_call(text)
        if not m:
            return text
        replacement = _call_replacement(m.group(1), m.group(2), scope)
        if replacement is None:
            return None
        text = text[: m.start()] + replacement + text[m.end():]
    return text


def _drop_transforms(text: str) -> str:
    return _STRING_TRANSFORM.sub(" ", text) if "(" in text and "." in text else text   # both in every match


def _innermost_call(text: str) -> re.Match[str] | None:
    """`_INNER_CALL.search(text)`, started where its leftmost match can first begin:
    at most _CALLEE_REACH before the first innermost group, and never before the
    paren preceding that group -- a callee and its spacing hold no paren, and every
    match's group starts at or after the first one. On nested calls the reach alone
    re-tried every enclosing callee, ~2 us per pass."""
    group = _INNER_GROUP.search(text)
    if not group:
        return None
    start = group.start()
    floor = max(text.rfind("(", 0, start), text.rfind(")", 0, start)) + 1
    return _INNER_CALL.search(text, max(floor, start - _CALLEE_REACH))


def _render_receivers(text: str) -> str:
    """`err.toJSON()` -> ` err `: a zero-argument renderer is its receiver."""
    return _METHOD_STRINGIFIER.sub(_receiver_of, text) if _RENDER_TAIL.search(text) else text


def _receiver_of(match: re.Match[str]) -> str:
    return f" {match.group(1)} "


def _call_replacement(callee: str, inner: str, scope: _Scope) -> str | None:
    """A stringifier or extractor of an error discloses; a projection is opaque;
    any other call passes its arguments through (containers, encoders, wrappers)."""
    last = _last_segment(callee)
    if _renders_detail(last):
        return None if _carries_error(inner, scope) else _OPAQUE
    if not _is_opaque_call(callee, last, inner):
        return f" {inner} "
    return _opaque_or_rendered(callee, inner, scope)


def _opaque_or_rendered(callee: str, inner: str, scope: _Scope) -> str | None:
    """Arm X: an opaque projection call discloses when its definition renders its parameter."""
    return None if _renders_through_definition(callee, inner, scope) else _OPAQUE


@lru_cache(maxsize=4096)
def _renders_detail(name: str) -> bool:
    """A stringifier (`String`, `str`, `toJson`) or a detail extractor."""
    return bool(_STRINGIFIER.fullmatch(name)) or _is_extractor(name)


def _is_opaque_call(callee: str, last: str, inner: str) -> bool:
    """A projection-role callee, or a PascalCase constructor with no arguments."""
    if not _PROJECTION_WORDS.isdisjoint(_callee_words(callee)):
        return True
    return last[:1].isupper() and not inner.strip()


def _last_segment(callee: str) -> str:
    return _SEGMENT_SPLIT.split(callee)[-1]


@lru_cache(maxsize=4096)
def _callee_words(callee: str) -> tuple[str, ...]:
    """`identifier_words` of a callee: each collapse pass reads them twice (as the
    last segment and as the callee), and an undotted callee is both."""
    return identifier_words(callee)


def _is_extractor(name: str) -> bool:
    words = _callee_words(name)
    return _is_stack_pair(words) or _is_detail_getter(words)


def _is_stack_pair(words: tuple[str, ...]) -> bool:
    """`format_exception`, `print_exc`, `dumpStack`: a stack verb then a stack noun."""
    return len(words) == 2 and words[0] in _STACK_VERBS and words[1] in _STACK_NOUNS


def _is_detail_getter(words: tuple[str, ...]) -> bool:
    """A detail word, and the callee does not END in a projection word (`getTraceId`)."""
    return bool(set(words) & _DETAIL_CALL_WORDS) and words[-1] not in _PROJECTION_WORDS


def _bare_error_reaches(text: str, scope: _Scope) -> bool:
    """A value token resolving to an error. Past _MAX_TOKENS distinct tokens only
    the conventional names count, so one sink cannot cost more than 32 resolutions.

    A token nothing in reach binds resolves `unknown`, which counts exactly when it
    is a conventional error name; that is decided here with one membership test,
    so only a token some window row (or the prefix) binds pays for resolution."""
    tokens = _distinct_tokens(_premask(_without_detail_chains(text)))
    if not tokens:
        return False
    may_bind = _binder(scope)
    return any(_token_counts(ident, k, scope) if may_bind(ident) else _is_conventional_error(ident)
               for k, ident in enumerate(tokens))


def _is_conventional_error(ident: str) -> bool:
    """An exact error name -- unless it is a parameter of the routine a fill is judged in (rule P)."""
    return not _strict_param(ident) and _EXACT_ERROR_NAME.fullmatch(ident) is not None


def _binder(scope: _Scope) -> Callable[[str], bool]:
    """``may_bind(ident)`` for one scope: the window index and the prefix's names are
    read once, then each token is a few membership tests (see `_may_bind`)."""
    if scope.depth > _MAX_DEPTH:
        return _binds_nothing
    state = _file_state(scope.lines, scope.suffix)
    end = scope.line_num - 1
    rows, start = state.index(end), max(0, end - _BINDING_RADIUS)
    names = _line_names(scope.prefix[-_PREFIX_CHARS:], scope.suffix) if scope.prefix else frozenset()

    def may_bind(ident: str) -> bool:
        bare = ident.lstrip("$")
        return _named_in(names, ident, bare) or _row_in(rows, ident, start, end) or (
            bare != ident and _row_in(rows, bare, start, end))
    return may_bind


def _binds_nothing(ident: str) -> bool:
    return False


def _named_in(names: frozenset[str], ident: str, bare: str) -> bool:
    return ident in names or bare in names


def _row_in(rows: dict[str, list[int]], name: str, start: int, end: int) -> bool:
    """Some row in [start, end) binds ``name``: one bisect, then the row it lands on."""
    found = rows.get(name)
    if not found:
        return False
    i = bisect_left(found, start)
    return i < len(found) and found[i] < end


def _without_detail_chains(text: str) -> str:
    return _DETAIL_CHAIN.sub(" ", text) if _DETAIL_TAIL.search(text) else text


def _distinct_tokens(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in _VALUE_TOKEN.finditer(text)))


def _token_counts(ident: str, index: int, scope: _Scope) -> bool:
    if index >= _MAX_TOKENS:
        return bool(_EXACT_ERROR_NAME.fullmatch(ident))
    return _token_is_error(ident, scope)


def _token_is_error(ident: str, scope: _Scope) -> bool:
    """A tainted or caught binding; a bare result field only with arm F's evidence."""
    verdict = _resolve_bound(ident, scope)   # only reached once `may_bind(ident)` held
    if verdict == "unknown":
        return bool(_EXACT_ERROR_NAME.fullmatch(ident))
    return verdict not in _UNTAINTED or (verdict == "field" and _field_token(ident, scope))


def _resolve(ident: str, scope: _Scope) -> str:
    """Where ``ident`` came from, nearest first: caught / tainted / clean / unknown.

    Memoised per (sink line, prefix, identifier, depth) in the file's own state,
    so the sinks of one routine share their window and the memo goes with the file.
    """
    return _resolve_with(ident, scope, _binder(scope))


def _resolve_with(ident: str, scope: _Scope, may_bind: Callable[[str], bool]) -> str:
    """`_resolve`, given ``may_bind = _binder(scope)`` already built for the text."""
    if _strict_param(ident):
        return "clean"   # rule P: a parameter of the routine a fill is judged in
    if not may_bind(ident):
        return "unknown"   # nothing in reach binds it: no walk, no memo entry
    return _resolve_bound(ident, scope)


def _resolve_bound(ident: str, scope: _Scope) -> str:
    """`_resolve` for a name some row in reach (or the prefix) binds."""
    if _strict_param(ident):
        return "clean"   # rule P
    memo = _frame_memos(_file_state(scope.lines, scope.suffix))[0]
    key = (scope.line_num, scope.prefix, ident, scope.depth)
    verdict = memo.get(key)
    if verdict is None:
        if len(memo) >= _MEMO_LIMIT:
            memo.clear()
        verdict = memo[key] = _walk_window(ident, scope)
    return verdict


def _walk_window(ident: str, scope: _Scope) -> str:
    """The nearest binding of ``ident`` within _BINDING_RADIUS lines above the sink.

    Only the window lines that bind the name are visited (`_file_index`), so a
    resolution costs a few lookups, not a 30-line scan per identifier.
    """
    if scope.depth > _MAX_DEPTH:
        return "unknown"
    return _prefix_binding(ident, scope) or _rows_binding(ident, scope) or "unknown"


def _prefix_binding(ident: str, scope: _Scope) -> str | None:
    """The sink line's own text before the sink, read back _PREFIX_CHARS at most:
    a same-line binding is statement-scale, and an uncapped prefix cost a parse of
    the whole line per sink."""
    if not scope.prefix:
        return None   # an empty prefix binds nothing
    prefix = scope.prefix[-_PREFIX_CHARS:]
    names = _line_names(prefix, scope.suffix)
    if ident not in names and ident.lstrip("$") not in names:
        return None
    return _line_binding(prefix, ident, scope, scope.line_num)


def _rows_binding(ident: str, scope: _Scope) -> str | None:
    """The window lines above the sink that bind ``ident``, nearest first."""
    state = _file_state(scope.lines, scope.suffix)
    for i in _candidate_rows(state.index(scope.line_num - 1), ident, scope.line_num - 1):
        verdict = _row_binding(state, i, ident, scope)
        if verdict:
            return verdict
    return None


def _row_binding(state: "_FileState", row: int, ident: str, scope: _Scope) -> str | None:
    """What row ``row`` binds ``ident`` to, seen from depth ``scope.depth``: it depends
    on nothing else, so the sinks below the row share it."""
    rows = _frame_memos(state)[1]
    key = (row, ident, scope.depth)
    if key not in rows:
        rows[key] = _line_binding(state.lines[row], ident, scope, row + 1)
    return rows[key]


class _FileState:
    """What the resolver keeps for one file; dropped with the file.

    ``names``: bound name -> ascending 0-based indices of the lines binding it,
    extended as resolution reaches further down, so every line is indexed once
    per file (the per-sink-line window map it replaced re-read 30 rows for every
    sink line). ``marks``: running count of marker lines,
    so "any marker in rows [a, b)" is two lookups. ``memo``: per-sink resolutions.
    """

    __slots__ = ("lines", "suffix", "names", "upto", "marks", "memo", "rows", "words", "words_upto", "row_names")

    def __init__(self, lines: Sequence[str], suffix: str) -> None:
        self.lines, self.suffix, self.names, self.upto = lines, suffix, defaultdict(list), 0
        self.marks: list[int] = [0]
        self.memo: dict[tuple, str] = {}
        self.rows: dict[tuple, str | None] = {}
        self.words: dict[str, list[int]] = defaultdict(list)
        self.words_upto = 0
        self.row_names: list[frozenset[str]] = []

    def index(self, upto: int) -> dict[str, list[int]]:
        if upto > self.upto:   # most calls ask for rows already indexed
            self._index_to(upto)
        return self.names

    def _index_to(self, upto: int) -> None:
        names, row_names, suffix = self.names, self.row_names, self.suffix
        for i in range(self.upto, upto):
            row_names.append(_line_names(self.lines[i], suffix))
            for name in row_names[i]:
                names[name].append(i)
        self.upto = upto

    def mentions(self, upto: int) -> dict[str, list[int]]:
        """Every name -> ascending rows that spell it (bare and `$` forms as written)."""
        words, lines = self.words, self.lines
        for i in range(self.words_upto, upto):
            for w in set(_NAMES.findall(lines[i][:MAX_SCAN_CHARS])):
                words[w].append(i)
        self.words_upto = max(self.words_upto, upto)
        return self.words

    def marked(self, start: int, end: int) -> bool:
        """Any marker line in rows [start, end)."""
        marks, size = self.marks, len(self.lines)
        if end > size:
            end = size
        if end >= len(marks):
            self._mark_to(end)
        return marks[end] > marks[start if start > 0 else 0]

    def _mark_to(self, end: int) -> None:
        marks, lines = self.marks, self.lines
        for i in range(len(marks) - 1, end):
            marks.append(marks[-1] + (_MARKER.search(lines[i].lower()) is not None))


def _file_state(lines: Sequence[str], suffix: str) -> _FileState:
    """The thread's state for ``lines``: the last one asked for, else from the shared cache."""
    state = getattr(_LOCAL, "state", None)
    if state is None or state.lines is not lines or state.suffix != suffix:
        state = _LOCAL.state = _cached_state(lines, suffix)
    return state


def _cached_state(lines: Sequence[str], suffix: str) -> _FileState:
    key = (get_ident(), id(lines), suffix)
    with _STATES_LOCK:
        state = _FILE_STATES.get(key)
        if state is None or state.lines is not lines:
            state = _new_state(key, lines, suffix)
    return state


def _new_state(key: tuple, lines: Sequence[str], suffix: str) -> _FileState:
    """Under _STATES_LOCK. Oldest file out first: a long scan never keeps an early file alive."""
    _FILE_STATES.pop(key, None)
    while len(_FILE_STATES) >= _STATE_FILES:
        _FILE_STATES.pop(next(iter(_FILE_STATES)))
    state = _FILE_STATES[key] = _FileState(lines, suffix)
    return state


def _line_names(raw: str, suffix: str) -> frozenset[str]:
    """Every name a window line binds; an over-long line binds none (never read)."""
    return frozenset() if len(raw) > MAX_SCAN_CHARS else _line_facts(raw, suffix).names


def _candidate_rows(names: dict[str, list[int]], ident: str, end: int) -> list[int]:
    """Indices in [end - _BINDING_RADIUS, end) binding ``ident`` or its bare form, nearest first."""
    start = max(0, end - _BINDING_RADIUS)
    rows = _within(names.get(ident, ()), start, end)
    bare = ident.lstrip("$")
    if bare != ident:
        rows = sorted({*rows, *_within(names.get(bare, ()), start, end)})
    return rows[::-1]


def _within(rows: Sequence[int], start: int, end: int) -> Sequence[int]:
    return rows[bisect_left(rows, start): bisect_left(rows, end)]


def _line_binding(raw: str, ident: str, scope: _Scope, line_no: int) -> str | None:
    """The binding one window line gives ``ident``, or None when it gives none."""
    facts = _line_facts(raw, scope.suffix)
    rhs = facts.assigns.get(ident)
    if not _binds_here(facts, ident, rhs):
        return None
    if ident.lstrip("$") in facts.caught:
        return "caught"   # needs no deeper scope
    deeper = scope.at(line_no, scope.depth + 1)   # destructuring too, so _REACH bounds every chain
    return _binding_from_facts(facts, ident, rhs, deeper) or _destructured(facts, ident, deeper)


def _binds_here(facts: _Facts, ident: str, rhs: str | None) -> bool:
    """The line binds ``ident``, and not as `err = coerceFault(err)` (there the older binding wins)."""
    return _mentions_binding(facts, ident, rhs) and not _self_wrap(ident, rhs)


def _mentions_binding(facts: _Facts, ident: str, rhs: str | None) -> bool:
    """Cheap pre-check (dict and set lookups) before any scope is built."""
    bare = ident.lstrip("$")
    if rhs is not None or bare in facts.caught or bare in facts.params:
        return True
    return _destructures(facts, ident)


def _destructures(facts: _Facts, ident: str) -> bool:
    return facts.destructure is not None and ident in facts.destructure[0]


def _self_wrap(ident: str, rhs: str | None) -> bool:
    """`err = coerceFault(err)`. The substring test first: compiling a name pattern
    for every bound name cost a fifth of a dense file's time."""
    return rhs is not None and ident in rhs and bool(_name_pattern(ident).search(_rhs_text(rhs)))


@lru_cache(maxsize=1024)
def _rhs_text(rhs: str) -> str:
    """`_strip_literals(rhs)`, once per right-hand side: four readers of one binding row use it."""
    return _strip_literals(rhs)


@lru_cache(maxsize=4096)
def _name_pattern(ident: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w$.]){re.escape(ident)}(?![\w$])")


def _binding_from_facts(facts: _Facts, ident: str, rhs: str | None, scope: _Scope) -> str | None:
    """A name `_line_binding` found bound here but not caught: assigned or a parameter."""
    if rhs is not None:
        return _rhs_verdict(rhs, scope)
    if ident.lstrip("$") in facts.params:
        return _param_binding(facts.code, ident)
    return None


def _destructured(facts: _Facts, ident: str, scope: _Scope) -> str | None:
    """`const { message, stack } = e`: the source's verdict."""
    if not _destructures(facts, ident):
        return None
    return _destructure_verdict(facts.destructure[1], ident, scope)


def _destructure_verdict(source: str, ident: str, scope: _Scope) -> str:
    """tainted from an error, clean from a clean name or a validation result; any
    other source -- a call result, a member, ``ident`` itself, an unresolved
    name -- is a `field`. A call source is recorded as `callee(`."""
    if source.endswith("("):
        return _call_result_verdict(source[:-1])
    if "." in source or source == ident:
        return "field"
    return _source_verdict(_resolve(source, scope))


def _call_result_verdict(callee: str) -> str:
    return "clean" if _is_validation_callee(callee) else "field"


def _source_verdict(verdict: str) -> str:
    """A bare source's own verdict, as seen through destructuring."""
    if verdict not in _UNTAINTED:
        return "tainted"
    return "clean" if verdict == "clean" else "field"


@lru_cache(maxsize=8192)
def _line_facts(raw: str, suffix: str = "") -> _Facts:
    """Every binding one raw line makes, read once per distinct line text."""
    code = stripped_code(raw)
    assigns: dict[str, str] = {}
    for m in _ASSIGN_TARGET.finditer(raw) if "=" in raw else ():   # every target form spells `=`
        assigns.setdefault(m.group(1), raw[m.end(): m.end() + 400].lstrip())
    caught, params = _caught_names(raw, suffix), tuple(_header_params(code))
    destructure = _destructure_of(code)
    names = caught.union(assigns, params, _declared(code), destructure[0] if destructure else ())
    return _Facts(code, caught, assigns, params, destructure, names)


_HANDLER_WORD = re.compile("|".join(_HANDLER_WORDS))   # literal alternation: one C scan, not five


def _declared(code: str) -> list[str]:
    return _DECLARES.findall(code) if "as" in code or "var" in code else []


def _caught_names(raw: str, suffix: str) -> frozenset[str]:
    """`_lexical.catch_binding`, skipped on a line without any handler keyword.

    Every binding form it knows spells one of _HANDLER_WORDS, so a line with none
    binds nothing; the substring test costs ~1% of the form search, which was a
    third of a review's worst-file time (pinned by a unit test over every form).
    """
    handler = catch_binding(raw, suffix) if _HANDLER_WORD.search(raw) else frozenset()
    return handler | _variant_names(raw)


def _variant_names(raw: str) -> frozenset[str]:
    """`Err(problem) =>` binds ``problem``; every bare error variant spells Err or Exc."""
    if "Err" not in raw and "Exc" not in raw:
        return frozenset()
    return frozenset(filter(None, map(_bare_variant_payload, _VARIANT_BINDING.finditer(raw))))


def _bare_variant_payload(match: re.Match[str]) -> str:
    return match.group(2) if _EXACT_ERROR_NAME.fullmatch(match.group(1).lower()) else ""


def _destructure_of(code: str) -> tuple[frozenset[str], str] | None:
    if "=" not in code:
        return None   # every destructuring spells `=`
    m = _DESTRUCTURE.search(code)
    if not m:
        return None
    names = frozenset(_NAMES.findall(m.group(1).split(":")[0])) | _alias_names(code)
    return names, m.group(2) + ("(" if m.group(3) else "")


def _alias_names(code: str) -> frozenset[str]:
    """Rule R: the aliases of `{ F: alias }` are bound by the destructuring too."""
    return frozenset(alias for alias, _ in _destructure_aliases(code))


def _rhs_verdict(rhs: str, scope: _Scope) -> str:
    """tainted when the right-hand side discloses at depth <= 2; clean for a
    literal, a constant, or a projection OF an error; otherwise unknown."""
    if _rhs_discloses(_uncast(_rhs_text(rhs)), scope):
        return "tainted"
    if _is_literalish(rhs) or _is_projection_of_error(rhs, scope):
        return "clean"
    return "unknown"


def _rhs_discloses(text: str, scope: _Scope) -> bool:
    """`_args_disclose`, skipped when it cannot hold (see `_may_carry_error`)."""
    return _may_carry_error(text, scope) and _args_disclose(text, scope)


def _may_carry_error(text: str, scope: _Scope) -> bool:
    """False only when `_args_disclose(text, scope)` is False for certain.

    Every token, root and segment it judges is a substring of ``text`` (each
    rewrite blanks a span or keeps a substring between spaces). A token resolves
    past `unknown` only when ``may_bind`` holds, i.e. a name bound in reach -- by
    the prefix or a window row -- is that token or its bare form, so that name is
    a substring of ``text``. With every token `unknown`, only an error-NAMED
    segment or a conventional error name counts, and each of those spells a
    _MARKER word. So: no marker and no bound name inside ``text`` -> no disclosure.
    Most binding rows are service calls with neither; the walk cost ~11 us each.
    """
    return _MARKER.search(text.lower()) is not None or _bound_name_in(text, scope)


def _bound_name_in(text: str, scope: _Scope) -> bool:
    """Some name `_binder(scope)` would accept occurs in ``text``."""
    if scope.depth > _MAX_DEPTH:
        return False
    return any(name in text for names in filter(None, _names_in_reach(scope)) for name in names)


def _names_in_reach(scope: _Scope) -> list[frozenset[str]]:
    """What each window row binds, and the prefix: the names `_binder(scope)` accepts."""
    state = _file_state(scope.lines, scope.suffix)
    end = scope.line_num - 1
    state.index(end)
    rows = state.row_names[max(0, end - _BINDING_RADIUS): end]
    if scope.prefix:
        rows.append(_line_names(scope.prefix[-_PREFIX_CHARS:], scope.suffix))
    return rows


def _single_call(rhs: str) -> re.Match[str] | None:
    """The right-hand side as ONE call, after a lead await/yield/try."""
    return _SINGLE_CALL.fullmatch(_LEAD_KEYWORD.sub("", _rhs_text(rhs).strip().rstrip(";")))


def _is_validation_callee(callee: str) -> bool:
    """`schema.validate(body)`: its error describes the PEER'S OWN input (a field
    and why it was refused), which is the answer to give, not internal detail."""
    return bool(set(identifier_words(callee)) & _VALIDATION_WORDS)


def _is_literalish(rhs: str) -> bool:
    return bool(_LITERALISH.match(_rhs_text(rhs)) or _LITERALISH.match(rhs))


def _uncast(text: str) -> str:
    """`(err as Error)` -> `err`, `err!` -> `err`."""
    return _NON_NULL.sub(r"\1", _CAST.sub(r" \1 ", text))


def _is_projection_of_error(rhs: str, scope: _Scope) -> bool:
    """`quotaFault = formatQuotaError(err)`: one projection-named call given the error.

    A projection-named call WITHOUT an error argument stays unknown: measured on
    one real target, treating any opaque call result as clean dropped five cited
    leak lines (`accountRes = await loadAccountById(uid)` -> `accountRes.error.message`).
    """
    m = _single_call(rhs)
    if not m or _renders_detail(_last_segment(m.group(1))):
        return False
    return bool(set(identifier_words(m.group(1))) & _PROJECTION_WORDS) and _carries_error(m.group(2), scope)


def _header_params(code: str) -> list[str]:
    if not _declares_parameters(code):
        return []
    return [name for name in map(param_name, _param_list(code)) if name]


def _declares_parameters(code: str) -> bool:
    """No `(`, no parameter list for `_param_list` to read, so no header parse."""
    return "(" in code and (routine_header(code) or bool(_ARROW.search(code)))


def _param_list(code: str) -> list[str]:
    """The first parenthesised list of ``code``, split on commas."""
    lists = paren_lists(code, limit=1)
    return lists[0].split(",") if lists else []


def _param_binding(code: str, ident: str) -> str | None:
    """Error-first -> caught; an error-named parameter, untyped or base-error-typed
    -> caught; scalar- or domain-typed, or not error-named -> clean."""
    names = _header_params(code)
    if ident.lstrip("$") not in names:
        return None
    if not _is_error_named(ident):
        return "clean"
    if names[0] == ident.lstrip("$"):
        return "caught"
    return _typed_param_verdict(_param_type(code, ident))


def _is_error_named(ident: str) -> bool:
    return len(ident.lstrip("$")) > 2 and bool(_ERROR_NAME.fullmatch(ident))


def _typed_param_verdict(typ: str | None) -> str:
    if typ is None:
        return "caught"
    if set(identifier_words(typ)) & _SCALAR_TYPES:
        return "clean"
    return "caught" if _type_name(typ).lower() in _BASE_ERROR_TYPES else "clean"


def _type_name(typ: str) -> str:
    """The last path segment: `std::io::Error` and `java.lang.Exception` name the base
    type (the Rust form was measured read as the domain type `std`)."""
    return _SEGMENT_SPLIT.split(typ.replace("::", "."))[-1].strip("[]<>&*")


def _param_type(code: str, ident: str) -> str | None:
    for param in _param_list(code):
        name, typ = _typed_param(param.strip().split("=")[0].strip())
        if name and name.lstrip("$") == ident.lstrip("$"):
            return typ
    return None


def _typed_param(param: str) -> tuple[str | None, str | None]:
    m = _TYPED_PARAM.match(param)
    if not m:
        return None, None
    return (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))


# (trigger, pattern, replacement), in order; a pattern runs only when its trigger
# is found. Each trigger is one C search: the substring tests they replace ran as
# five Python predicates per text, one a six-way generator.
_PREMASK_STEPS = (
    (re.compile("!"), _PM_NEG, " "),
    (re.compile("|".join(map(re.escape, _COMPARISON_MARKS))), _PM_CMP, " "),
    (_PREDICATE_CALL, _PM_PRED, " "),
    (re.compile(r"\?"), _PM_TERN, " ? "),
    (re.compile("="), _PM_INIT, " "),
)


@lru_cache(maxsize=4096)
def _premask(text: str) -> str:
    """Remove tokens that are READ, not WRITTEN; a spread becomes the bare value."""
    t = text.replace("...", " ").replace("**", " ")
    t = _PM_INDEX.sub(" ", t) if "[" in t else t
    for trigger, pattern, replacement in _PREMASK_STEPS:
        if trigger.search(t):
            t = pattern.sub(replacement, t)
    return t


# END OF THE CWE-209 VALUE SECTION
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CWE-209 REVISION 3 SECTION (feature 0101): provenance and sink arms.
#
# Every arm below is ADDITIVE: it can only turn a site the rule above leaves
# clean into a reported one. The check_id, category, severity and message are
# the base rule's.
#
#   F  a result FIELD read (`x.error`, `{ error } = ...`) is error text only with
#      evidence: the routine the root is bound from fills the field from an
#      error in the value it RETURNS (keyed fill, same-file positional
#      construction, a same-file factory or helper hop <= 2), or the file fills
#      `.F = <error>` (not for detail-word fields). A fill whose value is an
#      error only through a parameter of its named routine counts only when a
#      same-file caller passes an error there (P). `{ F: alias }` reads F (R).
#   Y  a detail-role key over a singular error field, beside a literal or
#      constant under a code-role key, when the root is not validation-bound.
#   W  an object or collection filled from an error, then sent whole.
#   C1 a bare response helper whose first argument has a peer role; C2 a
#      `respond`/`reply` responder handed to the routine; H a same-file helper
#      that writes its parameter whole to a peer. V and T excuse C/H.
#   S  an error event of an asynchronously iterated stream, discriminated by an
#      enclosing branch.
#   X  a projection-named helper whose only definition renders its parameter.
#   X2 a field's producer found as the only definition in the scanned tree.
#
# State: per-file indexes and memos live in `_R3File` (keyed per thread and per
# line list, identity-checked, at most _STATE_FILES files); every per-scan
# structure (emitted rows, the line being judged, the parameter frames of rule P,
# the tree's declaration index and the deferred files) lives in `_ScanCtx`, one
# per call of `check_information_exposure`, reached through a ContextVar. X and
# X2 queries that need the tree index are answered after the walk: the index is
# built from the lines the walk already holds, and a file that asked such a
# question is judged again once the index is complete (the arms are additive,
# so deferral is exact).
# ---------------------------------------------------------------------------

_FIELD_ERROR_WORDS = frozenset({"error", "errors", "err", "errs", "failure", "failures"})
_FIELD_NOT_TEXT = _PROJECTION_WORDS | frozenset({
    "code", "codes", "type", "kind", "name", "id", "status", "count", "key", "class", "level", "flag",
    "at", "time",
})
_FIELD_DETAIL_WORDS = frozenset({"message", "msg", "detail", "details", "reason", "description"})
_TRAILING_TRANSFORMS = frozenset({
    "encode", "decode", "as_bytes", "getBytes", "trim", "strip", "to_string", "toString", "ToString", "slice",
    "substring", "toUpperCase", "toLowerCase", "to_s", "into", "clone", "as_str", "to_owned", "unwrap_or_default",
})
_QUOTED_KEY = re.compile(r"[\"'`]([A-Za-z_$][\w$]{0,63})[\"'`](?=\s{0,2}(?::|=>|\]))")
_LOG_OPEN = re.compile(_LOG_SINK.pattern + r"$", re.IGNORECASE)
_BRACKET = re.compile(r"[()\[\]{}]")
_CUT_CHARS = re.compile(r"[()\[\]{},;]")
_SPLIT_CHARS = re.compile(r"[()\[\]{},]")
_DEPTH_DELTA = {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}
_CALL_HEAD = re.compile(r"^([$A-Za-z_][\w$.]{0,80})\s{0,2}\(")
_NAME_RE = re.compile(r"[A-Za-z_$][\w$]{0,63}")
_CTOR_NAMES = frozenset({"constructor", "__init__", "init", "initialize"})
_CLASS_DECL = re.compile(r"(?<![\w$])(?:class|struct|record|object)\s{1,4}([A-Za-z_$][\w$]{0,63})")
_SKIP_NAMES = frozenset({
    "if", "for", "while", "switch", "catch", "with", "elif", "else", "until", "unless", "foreach", "return",
    "match", "when", "do", "try", "function", "async", "await", "new", "typeof", "super", "print", "assert",
    "yield", "throw", "raise", "not", "and", "or", "in", "is", "lambda", "fn", "func", "fun", "def",
})
_NAMED_DECL = (
    r"(?:\b(?:function\*?|def|func|fn|fun|sub)\s{{1,4}}(?:\([^)]{{0,80}}\)\s{{0,4}})?{n}\s{{0,4}}[(<]"
    r"|\b(?:const|let|var|val)\s{{1,4}}{n}\s{{0,2}}(?::[^=]{{0,80}})?=\s{{0,2}}(?:async\s{{1,4}})?"
    r"(?:function\b|\(|[\w$]{{1,40}}\s{{0,2}}=>)"
    r"|^\s{{0,80}}(?:(?:public|private|protected|internal|static|async|override|final|export|default|suspend|open"
    r"|abstract|virtual)\s{{1,4}}){{0,5}}"
    r"(?:[\w$<>\[\],.?]{{1,80}}\s{{1,4}})?{n}\s{{0,2}}\()"
)
_DEF_KEYWORD = re.compile(r"(?:^|[\s(])(?:function\*?|def|func|fn|fun|sub)\s")
_NAME_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]{0,63})\s{0,2}(?:<[^<>()]{0,80}>)?\s{0,2}[({]")
_DECL_NAME = re.compile(
    r"(?:(?<![\w$.])(?:function\*?|def|func|fn|fun|sub)\s{1,4}(?:\([^)]{0,80}\)\s{0,4})?([A-Za-z_$][\w$]{0,63})"
    r"\s{0,4}[(<]"
    r"|(?<![\w$.])([A-Za-z_$][\w$]{0,63})\s{0,2}[:=]\s{0,2}(?:async\s{1,4})?(?:function\b|\([^)]{0,200}\)\s{0,4}"
    r"(?::[^=]{0,120})?=>|[\w$]{1,40}\s{0,2}=>)"
    r"|^\s{0,40}(?:(?:public|private|protected|static|async|override|internal|final|suspend|export|default)"
    r"\s{1,4}){0,4}"
    r"(?:[\w$<>\[\],.?]{1,60}\s{1,4})?([A-Za-z_$][\w$]{0,63})\s{0,2}\()")
# The three alternatives of _DECL_NAME, each alone: a line none can match is skipped
# before the (slower) combined search, which then decides exactly as before.
_LEADING_DECL = re.compile(
    r"\s{0,40}(?:(?:public|private|protected|static|async|override|internal|final|suspend|export|default)"
    r"\s{1,4}){0,4}(?:[\w$<>\[\],.?]{1,60}\s{1,4})?[A-Za-z_$][\w$]{0,63}\s{0,2}\(")
_ROUTINE_KEYWORD = re.compile(r"(?<![\w$.])(?:function|def|func|fn|fun|sub)\s")
# The rows `_could_declare` can accept, found by passes over the joined text (a superset):
# the line-start form, then one literal-led pass per keyword (each a fast literal search).
_LEADING_DECL_ROWS = re.compile(_LEADING_DECL.pattern.replace("\\s{0,40}", "^\\s{0,40}", 1), re.MULTILINE)
_ARROW_ROWS = re.compile(r"=>")
_FUNCTION_ROWS = re.compile(r"function")
_DEF_ROWS = re.compile(r"def\s")
_FUNC_ROWS = re.compile(r"func?\s")
_FN_ROWS = re.compile(r"fn\s")
_SUB_ROWS = re.compile(r"sub\s")
_DECL_ROW_HINTS = (_LEADING_DECL_ROWS, _ARROW_ROWS, _FUNCTION_ROWS, _DEF_ROWS, _FUNC_ROWS, _FN_ROWS, _SUB_ROWS)
_INLINE_HEADER = re.compile(
    r"([A-Za-z_$][\w$]{0,63})\s{0,2}\(([^()]{0,300})\)\s{0,4}(?:(?::|->)[^{=]{0,80})?\{"
    r"|([A-Za-z_$][\w$]{0,63})\s{0,2}[:=]\s{0,2}(?:async\s{1,4})?(?:function\s{0,4})?\(([^()]{0,300})\)\s{0,4}"
    r"(?::[^=]{0,80})?=>")
_NAMED_DECL_ANY = re.compile(_NAMED_DECL.format(n=r"([A-Za-z_$][\w$]{0,63})"))
_ASSIGNED_ROUTINE_ANY = re.compile(   # match only: \A keeps a stray search anchored
    r"\A\s{0,40}([A-Za-z_$][\w$]{0,63})\s{0,2}(?::[^=]{0,80})?[:=]\s{0,2}(?:async\s{1,4})?(?:function\b|\()")
_CALL_TAIL = re.compile(r"(?:\s{0,2}\.\s{0,2}new)?\s{0,2}([({])")
_CALL_LEAD = re.compile(r"(?<![\w$])(?:new\s{1,4})?(?:[\w$]{1,60}\s{0,2}(?:\.|::)\s{0,2})?$")
_PARAM_LIST_NAME = re.compile(r"([A-Za-z_$][\w$]{0,63})\s{0,2}(?:<[^<>]{0,80}>)?$")
_PARAM_LIST_ASSIGNED = re.compile(
    r"([A-Za-z_$][\w$]{0,63})\s{0,2}(?::[^=]{0,80})?=\s{0,2}(?:async\s{1,4})?(?:function\s{0,4})?$")
_KEYWORD_ARG = re.compile(r"\A\s{0,4}([A-Za-z_$][\w$]{0,63})\s{0,2}(?:=(?!=)|:(?!:))")   # match only
_INDENT_CONTINUES = re.compile(r"^\s*(?:rescue|ensure|else|elsif|elif|except|finally|catch|end)\b")
_PY_DEF = re.compile(r"(?:^|\s)def\s")
_ROUTINE_SPAN = 200
_CONSTRUCT = re.compile(
    r"(?<![\w$])(new\s{1,4})?((?:[A-Za-z_$][\w$]{0,63}\s{0,2}(?:\.|::)\s{0,2}){0,3}[A-Za-z_$][\w$]{0,63})"
    r"(\s{0,2}\.\s{0,2}new)?\s{0,2}([({])")
_PATH_SEGMENT = re.compile(r"\s*(?:\.|::)\s*")
_MEMBER_PREFIX = re.compile(r"^\s*(?:val|var|public|private|readonly|let)\s+")
_STRUCT_MEMBER = re.compile(r"(?:pub\s+)?([A-Za-z_][\w]{0,63})\s*(?::|\s)")
_DATACLASS_MEMBER = re.compile(r"\s*([A-Za-z_]\w{0,63})\s*:")
# F2 yields to a literal producer: a literal-only value is, past its string literals, keys,
# code constants (`Codes.X`) and type-construction heads, only these words and punctuation
_LITERAL_NOISE = re.compile(
    r"(?=[\w$])(?:(?<![\w$])[fFrRbBuU]{1,2}(?=[\"'`])"
    r"|(?<![\w$.])(?:[A-Za-z_$][\w$]{0,40}+\s{0,2}(?:\.|::)\s{0,2}[A-Z][A-Z0-9_]{0,63}+(?![\w$(])"
    r"|\$?[A-Za-z_][\w$]{0,63}+\s{0,2}(?=:(?!:)|=>|=(?![=>]))"
    r"|[A-Z][\w$]{0,63}+(?:\s{0,2}\.\s{0,2}new)?\s{0,2}(?=[({])))")
_LITERAL_WORD = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]{0,63}")
_LITERAL_WORDS = frozenset({"true", "false", "True", "False", "null", "nil", "None", "undefined", "new", "return",
                            "yield", "await"})
# K: a constructor whose parameters declare members (TS parameter properties, PHP promotion)
_CTOR_PARAMS = re.compile(r"(?<![\w$])(?:constructor|__construct)\s{0,2}\(")
# an out-of-file factory whose name is ONLY an error role builds the failure value of a result
# (`fail`, `failure`, `Err`); a name that also says what is done to the error (`sanitizeError`,
# `toPublicError`) transforms it and is not one
_ERROR_FACTORY_WORDS = frozenset({"fail", "failure", "failed", "error", "err", "reject", "rejected"})
_PROPERTY_MODIFIER = re.compile(r"\A\s{0,4}(?:public|private|protected|readonly|internal)\s")   # match only
_RETURN_WORD = re.compile(r"(?<![\w$.])(?:return|yield)\b")
_ARM_ARROW = re.compile(r"=>|\s->\s")
_EXPR_BODY = re.compile(r"\)\s{0,4}(?::\s{0,4}[\w$<>?,\[\]. ]{1,80})?\s{0,4}=(?![=>])")
_CTOR_HEAD = re.compile(
    r"(?:new\s{1,4})?[A-Z][\w$]{0,63}(?:\s{0,2}\.\s{0,2}new|\s{0,2}::\s{0,2}[a-z_][\w$]{0,63})?\s{0,2}[({]")
_GROUP_OR_CTOR = re.compile(
    r"\s{0,8}(?:&|\*)?(?:(?:new\s{1,4})?[A-Z][\w$]{0,63}(?:\s{0,2}\.\s{0,2}new|\s{0,2}::\s{0,2}[a-z_][\w$]{0,63})?"
    r"\s{0,2})?\(")
_BARE_VARIABLE = re.compile(
    r"\s{0,8}[&*]?(\$?[A-Za-z_][\w$]{0,63})\s{0,2}(?:,\s{0,2}[\w$.]{1,40}\s{0,2}){0,3}[;!]?\s{0,4}$")
_STATEMENT_STARTS = re.compile(r"[;{]\s*")
_LEAD_CLOSE = re.compile(r"\s*(?:\}\s*)?")
_CONTINUES_AT_END = tuple("([{,+?:=&|.")
_CONTINUES_AT_START = (".", "?", ":", ")", "]", "}")
_NOT_A_VARIABLE = frozenset({"nil", "null", "None", "true", "false", "undefined", "this", "self"})
_FILL_RECEIVER = re.compile(r"(\$?[A-Za-z_][\w$]{0,63})\s{0,2}(?:\?\.|\.|->)?\s{0,2}$")
_OPEN_SUBSCRIPT = re.compile(r"\[\s{0,2}$")
_ATTRIBUTE_LINE = re.compile(r"\s*(?:\[[^\]]{1,200}\]|@[\w.]{1,80}(?:\([^)]{0,200}\))?)\s*$")
_BODY_OPENERS = ("{", "where", "throws", ":", "=>")
_HEADER_FOLLOWERS = ("{", ":", "->", "=>", "throws", "where")
_DETAIL_KEYS = r"(?:message|msg|detail|details|description|reason|stack)"
_KEYED_FIELD = re.compile(
    rf"(?<![\w$])[\"'`]?{_DETAIL_KEYS}[\"'`]?\s{{0,2}}(?::(?!:)|=>|=(?![=>]))\s{{0,2}}"
    rf"({_ID}(?:{_ACC}{_ID}){{1,4}})")
_CODE_KEY = re.compile(
    r"(?<![\w$])[\"'`]?(?:error|err|code|errorCode|error_code|errCode|status|kind|type)[\"'`]?\s{0,2}"
    r"(?::(?!:)|=>|=(?![=>]))\s{0,2}"
    r"(?:[\"'`]|[A-Z][A-Z0-9_]{2,63}\b|[A-Za-z_$][\w$]{0,40}\s{0,2}\.\s{0,2}[A-Z][A-Z0-9_]{2,63}\b)")
# File-level hints for Y, literal-led supersets of _KEYED_FIELD and _CODE_KEY (the per-sink
# test is exact; a file with neither key form skips Y entirely).
_DETAIL_KEY_HINT = re.compile(r"(?:message|msg|detail|description|reason|stack)[\"'`]?\s{0,2}(?::|=>|=)")
_CODE_KEY_HINT = re.compile(r"(?:error|err|code|errorCode|error_code|errCode|status|kind|type)[\"'`]?\s{0,2}(?::|=>|=)")
_KEY_SPLIT = re.compile(r"(?::(?!:)|=>|=)")
_ROOT_SPLIT = re.compile(r"[.?\[]")
_PEER_ARGS = frozenset({"res", "resp", "response", "reply", "w", "rw", "writer", "ctx", "conn", "handler", "call",
                        "exchange"})
_RESPONSE_VERBS = frozenset({"write", "send", "respond", "reply", "json"})
_RESPONSE_SHAPES = frozenset({"as", "async", "json", "text", "html", "status", "head", "header", "headers", "body",
                              "all", "error", "err", "string", "bytes", "response", "problem"})
_BARE_CALL = re.compile(r"(?<![\w$.>:])([A-Za-z_$][\w$]{1,63})\s{0,2}\(")
_PEER_FIRST_ARG = re.compile(r"(?:this\.|self\.|&|\*)?([A-Za-z_$][\w$]{0,20})\s{0,2}[,)]")
_RECEIVER_PREFIX = re.compile(r"^(?:this|self)\s{0,2}\.\s{0,2}")
_RESPONDERS = frozenset({"respond", "reply"})
# H: a write that takes the peer WRITER as its first argument (`Fprint(w, v)`, `Error(w, v, 500)`,
# `WriteString(w, v)`) or an encoder built over it (`NewEncoder(w).Encode(v)`). Writer-role names
# only: `ctx` / `call` / `handler` are peers that are never written through as an argument.
_WRITER_ARGS = ("w", "rw", "writer", "res", "resp", "response", "conn", "reply")
_WRITER_ARG_CALL = re.compile(
    r"(?<![\w$])([A-Za-z_$][\w$]{0,40})\s{0,2}\(\s{0,2}[&*]?(?:" + "|".join(_WRITER_ARGS) + r")\s{0,2}([,)])")
_CHAINED_CALL = re.compile(r"\s{0,2}\.\s{0,2}([A-Za-z_$][\w$]{0,40})\s{0,2}\(")   # .match(text, pos) only
_WRITER_VERBS = frozenset({"write", "print", "fprint", "fprintf", "fprintln", "error", "send", "encode", "reply",
                           "respond"})
# H: a parameter converted on its way out is written whole (`msg.encode()`, `msg.getBytes()`)
_CONVERSIONS = "|".join(map(re.escape, sorted(_TRAILING_TRANSFORMS)))
# H: a Go parameter entry, name before type (`msg string`, `w http.ResponseWriter`); match only
_NAME_BEFORE_TYPE = re.compile(r"\A\s{0,4}([A-Za-z_]\w{0,63})\s{1,4}[\[\]*.\w]")
_ENTRY_NAME_TAIL = re.compile(r"\s{0,2}(?::(?!:)|=(?![=>]))")   # match only: after a key / keyword name
_FUNC_WORD = re.compile(r"(?<![\w$.])func\s")
_CONTENT_TEST = re.compile(
    r"(?:\.|\b)(?:includes|startsWith|endsWith|match|test|contains|Contains|HasPrefix|HasSuffix|"
    r"indexOf|search|startswith|endswith)\s{0,2}\(")
_ERROR_CONSTRUCTOR = re.compile(
    r"(?:\bErrorf|\berrors\.New|\bnew\s{1,4}[A-Z]\w{0,40}(?:Error|Exception)|\b[A-Z]\w{0,40}(?:Error|Exception))"
    r"\s{0,2}\(")
_EXIT_WORD = re.compile(r"\breturn\b|\bthrow\b|\braise\b")
_FORWARDED = re.compile(r"\s*(?:return|throw|raise)\s{1,4}([A-Za-z_$][\w$]{0,63})\s{0,2};?\s*$")
_RAW_ERROR_READ = re.compile(r"%w|\berr\b(?!\s{0,2}(?:!=|==))|\berror\b(?!\s{0,2}[:(])|\bcause\b")
_WRAPPED_CAUSE = re.compile(r",\s{0,2}(?:err|error|e|ex|exc|cause)\s{0,2}\)")
_NOT_A_VALUE_NAME = frozenset({"nil", "null", "None", "true", "false", "undefined"})
_EXCUSE_SKIP = frozenset({"http", "String", "str", "fmt"})
_MEMBER_CHAIN_TEXT = re.compile(r"[A-Za-z_$][\w$]{0,63}(?:\.[A-Za-z_$][\w$]{0,63})+")
_QUOTE = re.compile(r"[\"'`]")
_BRANCH_HEADS = ("if", "} else if", "else if", "elif")
_MEMBER_WRITE = re.compile(
    r"(?<![\w$.])(\$?[A-Za-z_][\w$]{0,63})(?:\s{0,2}(?:\.|->)\s{0,2}([A-Za-z_$][\w$]{0,63})|\s{0,2}\[[^\[\]=]{1,80}\])"
    r"\s{0,2}=(?![=>])")
_SETTER_WRITE = re.compile(r"(?<![\w$.])(\$?[A-Za-z_][\w$]{0,63})\s{0,2}\.\s{0,2}set[A-Z][\w$]{0,63}\s{0,2}\(")
_INSERT_WRITE = re.compile(
    r"(?<![\w$.])(\$?[A-Za-z_][\w$]{0,63})\s{0,2}(?:\.|->)\s{0,2}"
    r"(?:push|append|add|unshift|insert|extend|put|Add|Append|Push)\s{0,2}\(")
_INSERT_HINT = re.compile(r"(?:\.|->)\s{0,2}(?:push|append|add|unshift|insert|extend|put|Add|Append|Push)\s{0,2}\(")
_ASYNC_ITERATION = re.compile(
    r"(?:\bfor\s{1,4}await\s{0,4}\(\s{0,4}(?:const|let|var)?\s{0,4}([A-Za-z_$][\w$]{0,63})\s{1,4}of\b"
    r"|\basync\s{1,4}for\s{1,4}([A-Za-z_]\w{0,63})\s{1,4}in\b"
    r"|\bawait\s{1,4}foreach\s{0,4}\(\s{0,4}(?:var|[\w<>]{1,40})\s{1,4}([A-Za-z_]\w{0,63})\s{1,4}in\b)")
_QUOTED_WORD = re.compile(r"[\"'`]([A-Za-z_.:-]{0,40})[\"'`]")
_CASE_LABEL = re.compile(r"\s*(?:case\b|default\b|[\"'`][^\"'`]{0,40}[\"'`]\s*(?:->|=>))")
_OWN_CASE_LABEL = re.compile(r"\s*(?:case\b|[\"'`][^\"'`]{0,40}[\"'`]\s*(?:->|=>))")
_MEMBER_NAME = re.compile(r"(?:\?\.|\.)\s{0,2}([A-Za-z_$][\w$]{0,63})")
_ERROR_EVENT_WORDS = frozenset({"error", "failure", "failed", "exception", "err"})
_PEER_FIRST_TEXT = (r"\(\s{0,2}(?:this\.|self\.|&|\*)?(?:res|resp|response|reply|w|rw|writer|ctx|conn|handler|call"
                    r"|exchange)\s{0,2}[,)]")
_PEER_FIRST_CALL = re.compile(_PEER_FIRST_TEXT)
_RESPONDER_CALL_TEXT = r"(?<![\w$.])(?:respond|reply)\s{0,2}\("
_RESPONDER_CALL = re.compile(_RESPONDER_CALL_TEXT)
_PEER_OR_RESPONDER = re.compile(_PEER_FIRST_TEXT + "|" + _RESPONDER_CALL_TEXT)
_PEER_OR_RESPONDER_HINT = re.compile(_PEER_FIRST_TEXT + r"|(?:respond|reply)\s{0,2}\(")   # no lookbehind: a fast superset
_CALLED_NAME = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s{0,2}\(")
_LITERAL_RETURN = re.compile(
    r"^\s*(?:return|yield)\s{0,4}(?:[\"'`][^\"'`]{0,200}[\"'`]|null|nil|None|undefined|true|false|-?\d+"
    r"|[A-Za-z_$][\w$]{0,40}\s{0,2}(?:\.|::)\s{0,2}[A-Z][A-Z0-9_]{1,63})?\s{0,2};?\s*$")
_PAREN = re.compile(r"\(")
_NOT_PARAMS = frozenset({"self", "cls", "this", ""})
_OWNER_REACH = 200            # the longest `name<...>` / `name: T = async function` a list owner spans
_PROVENANCE_DEPTH = 2         # nested provenance evaluations (a fill judged inside a fill)
_HOPS = 2                     # caller / factory / helper hops (rule P, W-helper, V)
_TEMPLATE_LIMIT = 4096        # templated per-name patterns kept per scan
_R3_MEMO_LIMIT = 20000        # entries per per-file memo before it is cleared
_OTHER_FILES = 32             # files read for X / X2 definitions, kept per scan
_INDEX_NAMES = 400            # same-file routine names folded into the bare-call prefilter
_HEADER_SPAN = 60
_CLASS_SPAN = 400
_CALLBACK_SPAN = 800
_ENCLOSING_SPAN = 400
_EXCUSE_SPAN = 60
_JOIN_ROWS = 8
_TYPE_ROWS = 30
_MEMBER_ROWS = 40
_BRACE_SPAN = 1200
_SPAN_ROWS = 40


class _Frame(NamedTuple):
    """Rule P: the named routine holding a fill, while the fill's value is judged."""

    params: frozenset[str]
    header: str
    memos: dict


class _ScanCtx:
    """Everything one scan of the CWE-209 arms keeps; never shared between scans."""

    __slots__ = ("emitted", "path", "file_path", "lines", "findings", "owner", "active", "prose", "suffix",
                 "frames", "seen_params", "in_prov", "x2_off", "x_guard", "defs", "indexed", "deferred",
                 "complete", "other", "templates", "detached")

    def __init__(self, complete: bool, detached: bool = False) -> None:
        self.emitted: set[tuple[str, int]] = set()
        self.path, self.file_path, self.lines, self.findings, self.owner = "", None, None, None, None
        self.active, self.prose, self.suffix = False, False, ""
        self.detached = detached
        self.frames: list[_Frame] = []
        self.seen_params: list[tuple[str, str]] = []
        self.in_prov = 0
        self.x2_off = False
        self.x_guard = 0
        self.defs: dict[str, list[str]] = defaultdict(list)
        self.indexed: set[str] = set()
        self.deferred: dict[str, tuple[Path, Sequence[str]]] = {}
        self.complete = complete
        self.other: dict[str, tuple[str, ...]] = {}
        self.templates: dict[tuple, re.Pattern[str]] = {}


_SCAN: ContextVar[_ScanCtx | None] = ContextVar("_cwe209_scan", default=None)


def _active_scan() -> _ScanCtx:
    """The running scan, or this thread's detached context for a caller that judges lines
    directly (no tree index, no emitted set: its stacks are balanced by every user)."""
    return _SCAN.get() or getattr(_LOCAL, "detached", None) or _new_detached()


def _new_detached() -> _ScanCtx:
    ctx = _LOCAL.detached = _ScanCtx(complete=True, detached=True)
    return ctx


class _R3File:
    """Per-file indexes and memos of the arms: built once per file, dropped with it."""

    __slots__ = ("lines", "calls", "decls", "decl_rows", "memo", "masked", "ends", "facts", "arm_rows", "joined",
                 "balance")

    def __init__(self, lines: Sequence[str]) -> None:
        self.lines = lines
        self.calls: dict[str, list[int]] | None = None
        self.decls: dict[str, list[int]] | None = None
        self.decl_rows: dict[int, bool] = {}
        self.memo: dict[tuple, object] = {}
        self.masked: dict[int, str] = {}
        self.ends: dict[int, int] = {}
        self.facts: _ArmFacts | None = None
        self.arm_rows: frozenset[int] | None = None
        self.joined: tuple[str, list[int]] | None = None
        self.balance: dict[int, int] = {}


class _ArmFacts(NamedTuple):
    """Which arms can fire in a file at all (one joined-text pass)."""

    w: bool
    bare: re.Pattern[str] | None
    async_iter: bool
    keyed: bool          # Y can fire: some detail key over a member chain, and some code key
    names: frozenset[str]   # the same-file routine names a bare call may reach (an H candidate)


_R3_FILES: dict[tuple, _R3File] = {}


def _r3_file(lines: Sequence[str]) -> _R3File:
    """The thread's arm file for ``lines``: the last one asked for, else from the shared cache."""
    rf = getattr(_LOCAL, "rf", None)
    if rf is None or rf.lines is not lines:
        rf = _LOCAL.rf = _cached_r3_file(lines)
    return rf


def _cached_r3_file(lines: Sequence[str]) -> _R3File:
    key = (get_ident(), id(lines))
    with _STATES_LOCK:
        rf = _R3_FILES.get(key)
        if rf is None or rf.lines is not lines:
            rf = _new_r3_file(key, lines)
    return rf


def _new_r3_file(key: tuple, lines: Sequence[str]) -> _R3File:
    """Under _STATES_LOCK. Oldest file out first, as `_new_state`."""
    _R3_FILES.pop(key, None)
    while len(_R3_FILES) >= _STATE_FILES:
        _R3_FILES.pop(next(iter(_R3_FILES)))
    rf = _R3_FILES[key] = _R3File(lines)
    return rf


def _drop_file(lines: Sequence[str]) -> None:
    """Forget every per-file state of ``lines`` in this thread (judged again from scratch)."""
    me, ident = get_ident(), id(lines)
    with _STATES_LOCK:
        for cache in (_FILE_STATES, _R3_FILES):
            _drop_keys(cache, me, ident)
    _LOCAL.state = _LOCAL.rf = None


def _drop_keys(cache: dict, me: int, ident: int) -> None:
    for key in [k for k in cache if k[:2] == (me, ident)]:
        del cache[key]


def _memo(rf: _R3File, key: tuple, compute: Callable[[], object]) -> object:
    """``rf.memo[key]``, computed once; False while it is being computed (cycles end there)."""
    if key in rf.memo:
        return rf.memo[key]
    if len(rf.memo) >= _R3_MEMO_LIMIT:
        rf.memo.clear()
    rf.memo[key] = False
    value = rf.memo[key] = compute()
    return value


def _templated(builder: Callable[[str], str], name: str) -> re.Pattern[str]:
    """A per-name pattern, compiled once per scan (bounded, cleared with the scan)."""
    cache = _active_scan().templates
    key = (builder, name)
    pattern = cache.get(key)
    if pattern is None:
        if len(cache) >= _TEMPLATE_LIMIT:
            cache.clear()
        pattern = cache[key] = re.compile(builder(name))
    return pattern


# ---- small text helpers ----

def _depth_cut(depth: int, ch: str) -> bool:
    return depth < 0 or (depth == 0 and ch in ",;")


def _top_level_cut(text: str) -> str:
    """``text`` up to its first top-level `,` / `;`, or the bracket that closes outside it."""
    depth = 0
    for m in _CUT_CHARS.finditer(text):
        depth += _DEPTH_DELTA.get(m.group(), 0)
        if _depth_cut(depth, m.group()):
            return text[: m.start()]
    return text


def _split_top(text: str) -> list[str]:
    """``text`` split on its top-level commas (literal bodies masked for the split)."""
    out, start = [], 0
    for at in _top_commas(mask_literals(text)):
        out.append(text[start:at])
        start = at + 1
    tail = text[start:]
    return [*out, tail] if tail.strip() else out


def _top_commas(masked: str):
    depth = 0
    for m in _SPLIT_CHARS.finditer(masked):
        depth += _DEPTH_DELTA.get(m.group(), 0)
        if depth == 0 and m.group() == ",":
            yield m.start()


def _brace_args(text: str, open_at: int) -> str:
    """The text between the `(`/`{` at ``open_at`` and its partner (literal-masked match)."""
    masked = mask_literals(text)
    depth = 0
    for m in _BRACKET.finditer(masked, open_at, min(len(text), open_at + _BRACE_SPAN)):
        depth += _DEPTH_DELTA[m.group()]
        if depth == 0:
            return text[open_at + 1: m.start()]
    return text[open_at + 1: open_at + _BRACE_SPAN]


def _row_brace_args(lines: Sequence[str], row: int, open_at: int) -> str:
    """`_brace_args` of the bracket at ``open_at`` of row ``row``, read on into the next rows
    only when it does not close on its own row (a closed bracket, with no open quote that a
    later row could close, cannot be changed by what follows)."""
    first = lines[row][:MAX_SCAN_CHARS]
    args = _brace_args(first, open_at)
    if len(args) < min(len(first), open_at + _BRACE_SPAN) - open_at - 1 and not _open_quote(first):
        return args
    return _brace_args(_joined(lines, row), open_at)


def _joined(lines: Sequence[str], row: int, n: int = _JOIN_ROWS) -> str:
    return " ".join(x[:MAX_SCAN_CHARS] for x in lines[row: row + n])


def _masked_row(rf: _R3File, row: int) -> str:
    """Row ``row`` with comments blanked and literal bodies masked (memoised per file)."""
    text = rf.masked.get(row)
    if text is None:
        text = rf.masked[row] = _uncomment(rf.lines[row][:MAX_SCAN_CHARS])[1]
    return text


def _pick_argument(args: str, idx: int, pname: str) -> str | None:
    """The argument for parameter ``pname`` (keyword first), else the ``idx``-th positional one."""
    parts = _split_top(args)
    keyed = _keyword_argument(parts, pname.lower())
    return keyed if keyed is not None else _positional_argument(parts, idx)


def _keyword_argument(parts: list[str], low: str) -> str | None:
    for p in parts:
        m = _KEYWORD_ARG.match(p)
        if m and m.group(1).lower() == low:
            return p[m.end():]
    return None


def _positional_argument(parts: list[str], idx: int) -> str | None:
    positional = [p for p in parts if not _KEYWORD_ARG.match(p)]
    return positional[idx] if idx < len(positional) else None


def _error_field(member: str, detail_ok: bool = True) -> bool:
    """F's field: an error word and no projection word (`error`, `lastFailure`); with
    ``detail_ok``, a field of detail words only (M: `message`, `reason`) too."""
    words = set(identifier_words(member))
    if words & _FIELD_NOT_TEXT:
        return False
    return bool(words & _FIELD_ERROR_WORDS) or (detail_ok and bool(words & _FIELD_DETAIL_WORDS))


def _detail_only(member: str) -> bool:
    return _error_field(member) and not _error_field(member, detail_ok=False)


def _field_name(member: str) -> str:
    """`getError` (a getter) names the field `error`."""
    return member[3].lower() + member[4:] if member.startswith("get") and member[3:4].isupper() else member


def _chain_fields(chain: str) -> list[str]:
    """A chain's members, trailing string transforms dropped and a getter read as its field."""
    members = _members(chain)
    while len(members) > 1 and members[-1] in _TRAILING_TRANSFORMS:
        members = members[:-1]
    return [*members[:-1], _field_name(members[-1])] if members else []


def _constant_read(root: str, members: list[str]) -> bool:
    """`Type.CONST`, an all-caps member, or a member of a type: a constant, not a stored failure."""
    return members[-1].isupper() or _is_type_constant(root, members) or (root[:1].isupper() and not root.isupper())


def _chain_error_fields(chains: list[str], root: str = ""):
    for chain in chains:
        field = _error_chain_field(chain, root)
        if field:
            yield field


def _error_chain_field(chain: str, root: str) -> str | None:
    members = _chain_fields(chain)
    if members and _error_field(members[-1]) and not _constant_read(root, members):
        return members[-1]
    return None


# ---- routines: declarations, extents, headers, call sites ----

def _call_index(rf: _R3File) -> dict[str, list[int]]:
    """Per file: name -> rows where `name(` / `name{` occurs (call sites and declaration candidates)."""
    if rf.calls is None:
        calls: dict[str, list[int]] = defaultdict(list)
        for i, raw in enumerate(rf.lines):
            for name in _called_names(raw):
                calls[name].append(i)
        rf.calls = calls
    return rf.calls


def _called_names(raw: str):
    return set(_NAME_CALL.findall(raw)) if len(raw) <= MAX_SCAN_CHARS else ()


def _decl_index(rf: _R3File) -> dict[str, list[int]]:
    """Per file: routine name -> rows declaring it. A row is a declaration by look-ahead to
    its body opener, so a Go/Python/Kotlin call statement ending in `)` is not one."""
    if rf.decls is None:
        decls: dict[str, list[int]] = defaultdict(list)
        for i in _declaration_candidates(rf):
            for name in _declared_names(rf, i, rf.lines[i]):
                decls[name].append(i)
        rf.decls = decls
    return rf.decls


def _declaration_candidates(rf: _R3File) -> list[int]:
    """The rows the declaration hints touch, ascending (a superset of the declaring rows)."""
    text, ends = _file_text(rf)
    return sorted(set().union(*(_touched_rows(h, text, ends) for h in _DECL_ROW_HINTS)))


def _file_text(rf: _R3File) -> tuple[str, list[int]]:
    """The file's capped lines joined by newlines, and the end offset of each row (memoised)."""
    if rf.joined is None:
        rf.joined = ("\n".join(x[:MAX_SCAN_CHARS] for x in rf.lines),
                     list(accumulate(len(x[:MAX_SCAN_CHARS]) + 1 for x in rf.lines)))
    return rf.joined


def _declared_names(rf: _R3File, row: int, raw: str) -> list[str]:
    names = _plain_decl_names(raw) if _may_declare_row(raw) else []
    return names if names and _is_declaration_row(rf, row) else []


def _may_declare_row(raw: str) -> bool:
    return len(raw) <= MAX_SCAN_CHARS and ("(" in raw or "=>" in raw) and _could_declare(raw)


def _plain_decl_names(raw: str) -> list[str]:
    return [n for n in map(_decl_match_name, _DECL_NAME.finditer(raw)) if _plain_name(n)]


def _decl_match_name(m: re.Match[str]) -> str | None:
    return m.group(1) or m.group(2) or m.group(3)


def _plain_name(name: str | None) -> bool:
    return bool(name) and name not in _SKIP_NAMES


def _could_declare(raw: str) -> bool:
    """Exactly when `_DECL_NAME` can match: its line-start form, an arrow or `function`
    (the assigned form), or a routine keyword (the keyword form)."""
    return _LEADING_DECL.match(raw) is not None or "=>" in raw or "function" in raw or \
        _ROUTINE_KEYWORD.search(raw) is not None


def _is_declaration_row(rf: _R3File, row: int) -> bool:
    found = rf.decl_rows.get(row)
    if found is None:
        found = rf.decl_rows[row] = _is_declaration(rf.lines[row], rf.lines, row)
    return found


def _def_rows(lines: Sequence[str], name: str) -> list[int]:
    return _decl_index(_r3_file(lines)).get(name, [])


def _is_declaration(raw: str, lines: Sequence[str] | None = None, row: int | None = None) -> bool:
    """A declaration header, not a call statement: a routine keyword, an arrow, or the
    parameter list (read ahead up to 8 lines) followed by a body opener on its own line
    (`{`, `:`, `->`, `=>`, `throws`, `where`) or, Allman style, on the next code line."""
    code = stripped_code(raw[:MAX_SCAN_CHARS]).rstrip()
    if _DEF_KEYWORD.search(code) or "=>" in code:
        return True
    return _declared_by_body(code, lines, row)


def _declared_by_body(code: str, lines: Sequence[str] | None, row: int | None) -> bool:
    text, last = _header_join(code, lines, row)
    return _opens_body(text) or (lines is not None and last is not None and _allman_body(text, lines, last))


def _header_join(code: str, lines: Sequence[str] | None, row: int | None) -> tuple[str, int | None]:
    """The header from ``row`` joined until its parentheses balance (at most 8 lines)."""
    if lines is None or row is None:
        return code, row
    return _join_until_balanced(code, lines, row)


def _join_until_balanced(code: str, lines: Sequence[str], row: int) -> tuple[str, int]:
    text, last, end = code, row, min(len(lines), row + 8)
    while text.count("(") > text.count(")") and last + 1 < end:
        last += 1
        text += " " + stripped_code(lines[last][:MAX_SCAN_CHARS]).strip()
    return text, last


def _opens_body(text: str) -> bool:
    close = mask_literals(text).rfind(")")
    if close < 0:
        return text.endswith(("{", ":"))
    after = text[close + 1:].strip()
    return after.startswith(_HEADER_FOLLOWERS) or (after.startswith("=") and not after.startswith("=="))


def _allman_body(text: str, lines: Sequence[str], last: int) -> bool:
    """The parameter list closes the line and the next code line (after attribute
    lines) opens the body."""
    if "(" not in text or not text.rstrip().endswith(")"):
        return False
    nxt = _next_code_line(lines, last)
    return nxt is not None and nxt.startswith(_BODY_OPENERS)


def _next_code_line(lines: Sequence[str], last: int) -> str | None:
    """The first of the next 3 rows that holds code and is not an attribute line."""
    for r in range(last + 1, min(len(lines), last + 4)):
        nxt = stripped_code(lines[r][:MAX_SCAN_CHARS]).strip()
        if nxt and not _ATTRIBUTE_LINE.match(nxt):
            return nxt
    return None


def _routine_end(lines: Sequence[str], start: int) -> int:
    """One past the routine starting at ``start``: brace depth, else indentation (memoised)."""
    rf = _r3_file(lines)
    end = rf.ends.get(start)
    if end is None:
        end = rf.ends[start] = _routine_end_uncached(lines, start)
    return end


def _routine_end_uncached(lines: Sequence[str], start: int) -> int:
    code = stripped_code(lines[start][:MAX_SCAN_CHARS]).rstrip()
    if code.endswith(":") or _python_def_without_brace(code):
        return _indent_end(lines, start)
    return _brace_end(lines, start)


def _python_def_without_brace(code: str) -> bool:
    return not code.endswith(("{", "(", ",")) and "{" not in code and _PY_DEF.search(code) is not None


def _brace_end(lines: Sequence[str], start: int) -> int:
    """Brace depth from the header; a header that never opens a brace ends by indentation."""
    end, opened = _brace_close(lines, start)
    if end is not None:
        return end
    return min(len(lines), start + _ROUTINE_SPAN) if opened else _plain_indent_end(lines, start)


def _brace_close(lines: Sequence[str], start: int) -> tuple[int | None, bool]:
    """(one past the row closing the first brace, True), else (None, whether a brace opened)."""
    depth, opened = 0, False
    for i in range(start, min(len(lines), start + _ROUTINE_SPAN)):
        code = mask_literals(lines[i][:MAX_SCAN_CHARS])
        depth += code.count("{") - code.count("}")
        opened |= "{" in code
        if opened and depth <= 0:
            return i + 1, True
    return None, opened


def _plain_indent_end(lines: Sequence[str], start: int) -> int:
    ind = len(lines[start]) - len(lines[start].lstrip())
    for i in range(start + 1, min(len(lines), start + _ROUTINE_SPAN)):
        s = lines[i]
        if s.strip() and len(s) - len(s.lstrip()) <= ind:
            return i
    return min(len(lines), start + _ROUTINE_SPAN)


def _indent_end(lines: Sequence[str], start: int) -> int:
    """Indentation extent: continuation keywords at the header's indent stay inside (Ruby
    `rescue`, Python `except`), and a Ruby `end` at that indent closes it."""
    ind = indent_width(lines[start])
    for i in range(start + 1, min(len(lines), start + _ROUTINE_SPAN)):
        end = _indent_row_end(lines[i], i, ind)
        if end is not None:
            return end
    return min(len(lines), start + _ROUTINE_SPAN)


def _indent_row_end(t: str, i: int, ind: int) -> int | None:
    if not t.strip() or indent_width(t) > ind:
        return None
    return _dedent_end(t, i)


def _dedent_end(t: str, i: int) -> int | None:
    if not _INDENT_CONTINUES.match(t):
        return i
    return i + 1 if t.strip() == "end" else None


def _is_header_line(raw: str) -> bool:
    return bool(routine_header(raw)) or _ARROW.search(stripped_code(raw)) is not None


def _header_row(lines: Sequence[str], row: int, span: int = _HEADER_SPAN) -> int | None:
    """Nearest routine header at or above ``row`` (bounded)."""
    for r in range(row, max(-1, row - span), -1):
        if _is_header_line(lines[r][:MAX_SCAN_CHARS]):
            return r
    return None


def _header_text(lines: Sequence[str], row: int) -> str:
    """The header from ``row`` up to the line closing its parameter list (<= 8 lines)."""
    text = ""
    for r in range(row, min(len(lines), row + 8)):
        text += " " + stripped_code(lines[r][:MAX_SCAN_CHARS])
        if text.count("(") and text.count("(") <= text.count(")"):
            break
    return text


def _list_owner(before: str) -> str:
    """The routine name in front of a parameter list (`name(`, `name = function(`, `name: (`)."""
    tail = before[-_OWNER_REACH:]      # both forms end the text and span fewer characters
    name = _group_or_empty(_PARAM_LIST_NAME.search(tail))
    if name in ("function", "async", "") or name in _SKIP_NAMES:
        name = _group_or_empty(_PARAM_LIST_ASSIGNED.search(tail))
    return name


def _group_or_empty(m: re.Match[str] | None) -> str:
    return m.group(1) if m else ""


def _is_named_routine(header: str, name: str) -> bool:
    if not name or name in _SKIP_NAMES:
        return False
    return _declares_name(header, name) or _assigned_name(header) == name


def _assigned_name(header: str) -> str | None:
    m = _ASSIGNED_ROUTINE_ANY.match(header)
    return m.group(1) if m else None


def _declares_name(text: str, name: str) -> bool:
    """``text`` declares a routine named ``name`` (any declaration form of _NAMED_DECL): one
    generic pattern, the name compared, instead of a pattern compiled per name."""
    return any(name in m.groups() for m in _NAMED_DECL_ANY.finditer(text))


def _param_list_of(header: str, param: str) -> tuple[str, list[str], bool]:
    """(routine name, params, is_named) of the paren list of ``header`` declaring ``param``."""
    for m in _PAREN.finditer(header):
        params = _list_params(header, m.start())
        if param in params:
            return _routine_signature(header, m.start(), params)
    return "", [], False


def _list_params(header: str, at: int) -> list[str]:
    return [param_name(p) for p in _split_top(call_argument_text(header, at, MAX_SCAN_CHARS))]


def _routine_signature(header: str, at: int, params: list[str]) -> tuple[str, list[str], bool]:
    name = _list_owner(header[:at].rstrip())
    return name, [p for p in params if p not in _NOT_PARAMS], _is_named_routine(header, name)


def _class_of(lines: Sequence[str], row: int) -> str | None:
    for r in range(row, max(-1, row - _CLASS_SPAN), -1):
        m = _CLASS_DECL.search(stripped_code(lines[r][:MAX_SCAN_CHARS]))
        if m and indent_width(lines[r]) <= indent_width(lines[row]):
            return m.group(1)
    return None


def _is_declaring_row(code: str, name: str) -> bool:
    return _declares_name(code, name) and (
        bool(routine_header(code)) or code.lstrip().startswith(("class", "data", "record", "struct", "type")))


def _call_sites(lines: Sequence[str], name: str):
    """(row, prefix, args) for each same-file call or construction of ``name`` (not its declaration)."""
    for row in _call_index(_r3_file(lines)).get(name, ()):
        code = lines[row][:MAX_SCAN_CHARS]
        if not _is_declaring_row(code, name):
            for start, bracket in _call_matches(mask_literals(code), name):
                yield row, code[:start], _row_brace_args(lines, row, bracket)


def _call_matches(masked: str, name: str) -> list[tuple[int, int]]:
    """(start, bracket) of each `[new ][recv.|recv::]name[.new](` / `{` in ``masked``, as a
    per-name pattern's finditer finds them (the leftmost start, matches not overlapping)."""
    out: list[tuple[int, int]] = []
    floor, i = 0, masked.find(name)
    while i >= 0:
        tail = _CALL_TAIL.match(masked, i + len(name)) if _starts_name(masked, i) else None
        if tail is None:
            i = masked.find(name, i + 1)
            continue
        out.append((_call_start(masked, floor, i), tail.start(1)))
        floor = tail.end()
        i = masked.find(name, floor)
    return out


def _starts_name(text: str, i: int) -> bool:
    return i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$")


def _call_start(masked: str, floor: int, i: int) -> int:
    """Where the call naming the identifier at ``i`` starts: its `new ` and receiver included."""
    lead = _CALL_LEAD.search(masked, floor, i)
    return lead.start() if lead else i


# ---- rule P: a parameter-sourced fill needs a same-file caller passing an error ----

def _enclosing_header(lines: Sequence[str], row: int, prefix: str) -> str | None:
    """Header text of the routine enclosing a fill: the fill line's own prefix first
    (`constructor(a, b) { this.b = b }`), else the nearest header above whose extent holds it."""
    inline = _inline_header(stripped_code(prefix))
    return inline if inline is not None else _header_holding(lines, row)


def _inline_header(code: str) -> str | None:
    hits = [m for m in _INLINE_HEADER.finditer(code) if _inline_name(m) not in _SKIP_NAMES]
    return code[hits[-1].start():] if hits else None


def _inline_name(m: re.Match[str]) -> str:
    return m.group(1) or m.group(3)


def _header_holding(lines: Sequence[str], row: int) -> str | None:
    for r in range(row - 1, max(-1, row - _ROUTINE_SPAN), -1):
        if _is_header_line(lines[r][:MAX_SCAN_CHARS]) and _routine_end(lines, r) > row:
            return _header_text(lines, r)
    return None


def _fill_routine_params(header: str) -> tuple[str, list[str], bool]:
    m = _PAREN.search(header)
    if not m:
        return "", [], False
    first = _first_param(call_argument_text(header, m.start(), MAX_SCAN_CHARS))
    return _param_list_of(header, first) if first else ("", [], False)


def _first_param(inner: str) -> str:
    return next((param_name(p) for p in _split_top(inner) if param_name(p)), "")


_FRAMES_OPEN = [0]       # rule-P frames open in ALL threads: a hint, so a resolution with none open
_FRAMES_LOCK = Lock()    # skips the context lookup; a thread always counts its own frames first


def _count_frames(delta: int) -> None:
    with _FRAMES_LOCK:
        _FRAMES_OPEN[0] += delta


def _strict_param(ident: str) -> bool:
    """Inside a fill of a NAMED routine, its own parameters are not errors by name or by
    binding: they are whatever the routine's same-file callers pass (rule P)."""
    if not _FRAMES_OPEN[0]:
        return False          # no rule-P frame open in any thread (the usual case)
    ctx = _active_scan()
    if not ctx.frames:
        return False
    frame = ctx.frames[-1]
    bare = ident.lstrip("$")
    if bare not in frame.params:
        return False
    ctx.seen_params.append((frame.header, bare))
    return True


def _frame_memos(state: "_FileState") -> tuple[dict, dict]:
    """The resolution memos to use for ``state``: inside a rule-P frame, the frame's own
    (a parameter there resolves differently), else the file's."""
    frames = _active_scan().frames if _FRAMES_OPEN[0] else None
    if not frames:
        return state.memo, state.rows
    memos = frames[-1].memos
    if state not in memos:
        memos[state] = ({}, {})
    return memos[state]


def _fill_is_error(lines: Sequence[str], row: int, prefix: str, rhs: str, hop: int = 0) -> bool:
    """`_args_disclose` on a fill's value; a parameter of the NAMED routine holding the fill
    counts only through a same-file caller passing an error at its position (<= 2 hops)."""
    rf = _r3_file(lines)
    key = ("fill", row, prefix[-80:], rhs[:200], hop)
    return _memo(rf, key, lambda: _fill_uncached(lines, row, prefix, rhs, hop))


def _fill_uncached(lines: Sequence[str], row: int, prefix: str, rhs: str, hop: int) -> bool:
    hit, seen = _judge_fill(lines, row, prefix, rhs)
    return hit or (hop < _HOPS and _a_seen_caller_passes(lines, row, seen, hop + 1))


def _a_seen_caller_passes(lines: Sequence[str], row: int, seen: list[tuple[str, str]], hop: int) -> bool:
    return any(_callers_pass_error(lines, row, header, param, hop) for header, param in seen)


def _judge_fill(lines: Sequence[str], row: int, prefix: str, rhs: str) -> tuple[bool, list[tuple[str, str]]]:
    """The fill's value judged inside its routine's rule-P frame, and the parameters it read."""
    ctx = _active_scan()
    ctx.frames.append(_fill_frame(lines, row, prefix))
    _count_frames(1)
    mark = len(ctx.seen_params)
    try:
        hit = _args_disclose(_strip_literals_209(rhs), _Scope(lines, row + 1, prefix, 0, ""))
    finally:
        ctx.frames.pop()
        _count_frames(-1)
    seen = list(dict.fromkeys(ctx.seen_params[mark:]))
    del ctx.seen_params[mark:]
    return hit, seen


def _fill_frame(lines: Sequence[str], row: int, prefix: str) -> _Frame:
    header = _enclosing_header(lines, row, prefix)
    _, params, named = _fill_routine_params(header) if header else ("", [], False)
    return _Frame(frozenset(params) if named else frozenset(), header or "", {})


def _callers_pass_error(lines: Sequence[str], fill_row: int, header: str, param: str, hop: int) -> bool:
    """A same-file call of the routine declaring ``param`` passes an error at its position
    (a constructor's calls are those of its class); memoised per (header, param, hop)."""
    key = ("callers", header, param, hop)
    return _memo(_r3_file(lines), key, lambda: _callers_uncached(lines, fill_row, header, param, hop))


def _callers_uncached(lines: Sequence[str], fill_row: int, header: str, param: str, hop: int) -> bool:
    name, params, named = _param_list_of(header, param)
    if not named or param not in params:
        return False
    return _a_target_passes(lines, fill_row, name, (params.index(param), param, hop))


def _a_target_passes(lines: Sequence[str], fill_row: int, name: str, at: tuple[int, str, int]) -> bool:
    """A constructor's calls are those of its class."""
    target = _class_of(lines, fill_row) if name in _CTOR_NAMES else name
    return bool(target) and _a_caller_passes(lines, target, *at)


def _a_caller_passes(lines: Sequence[str], target: str, idx: int, param: str, hop: int) -> bool:
    return any(_caller_arg_is_error(lines, site, idx, param, hop) for site in _call_sites(lines, target))


def _caller_arg_is_error(lines: Sequence[str], site: tuple, idx: int, param: str, hop: int) -> bool:
    row, prefix, args = site
    arg = _pick_argument(args, idx, param)
    return bool(arg) and bool(arg.strip()) and _fill_is_error(lines, row, prefix, arg, hop)


# ---- arm F: where a field is filled ----

def _population_pattern(field: str) -> str:
    alt = {field, field[:1].upper() + field[1:], field[:1].lower() + field[1:]}
    names = "|".join(map(re.escape, sorted(alt)))
    cap = field[:1].upper() + field[1:]
    return (rf"(?<![\w$.])(?:{names})\s{{0,2}}(?::(?!:)|=>)"
            rf"|(?:\.|->)\s{{0,2}}(?:{names})\s{{0,2}}=(?![=>])"
            rf"|\[\s{{0,2}}(?:{names})\s{{0,2}}\]\s{{0,2}}=(?![=>])"
            rf"|(?<![\w$.])(?:{names})\s{{0,2}}=(?![=>])"
            rf"|(?<![\w$])set{re.escape(cap)}\s{{0,2}}\(")


def _member_assign_pattern(field: str) -> str:
    alt = {field, field[:1].upper() + field[1:], field[:1].lower() + field[1:]}
    names = "|".join(map(re.escape, sorted(alt)))
    cap = field[:1].upper() + field[1:]
    # a merge into an existing object (`assign(v, { F: ... })`) fills F as `v.F = ...` does
    return (rf"(?:(?:\.|->)\s{{0,2}}(?:{names})\s{{0,2}}=(?![=>])|(?<![\w$])set{re.escape(cap)}\s{{0,2}}\("
            rf"|(?<![\w$])(?:assign|merge|extend)\s{{0,2}}\(\s{{0,2}}[\w$.]{{1,63}}\s{{0,2}},\s{{0,2}}\{{[^{{}}]{{0,200}}?"
            rf"(?<![\w$.])(?:{names})\s{{0,2}}:(?!:))")


def _closes_outward(depth: int, ch: str) -> tuple[int, bool]:
    """Reading backwards: a closer goes one level in; an opener at level 0 encloses."""
    if ch in ")]}":
        return depth + 1, False
    return (0, True) if depth == 0 else (depth - 1, False)


def _in_log_call(lines: Sequence[str], row: int, col: int) -> bool:
    """The position sits inside a still-open log call that began up to 12 lines above."""
    if not _log_word_near(lines, row):
        return False          # every log-call form spells a log word (see _LOG_SINK_WORDS)
    return _open_log_call(mask_literals("\n".join([*lines[max(0, row - 12): row], lines[row][:col]])))


def _open_log_call(masked: str) -> bool:
    depth = 0
    for m in reversed(list(_BRACKET.finditer(masked))):
        depth, encloses = _closes_outward(depth, m.group())
        if encloses and _opens_log_at(masked, m):
            return True
    return False


def _opens_log_at(masked: str, m: re.Match[str]) -> bool:
    return m.group() == "(" and _LOG_OPEN.search(masked[max(0, m.start() - 80): m.start() + 1]) is not None


def _log_word_near(lines: Sequence[str], row: int) -> bool:
    """Some row in [row - 12, row] spells a log word (per-file running count, memoised)."""
    rf = _r3_file(lines)
    counts = rf.memo.get(("logwords",))
    if counts is None:
        counts = rf.memo[("logwords",)] = [0, *accumulate(_may_log(x) for x in lines)]
    return counts[row + 1] > counts[max(0, row - 12)]


def _population_rows(lines: Sequence[str], field: str, lo: int, hi: int):
    """(row, prefix, value, line) for each fill of ``field`` in rows [lo, hi), log calls excluded."""
    pattern = _templated(_population_pattern, field)
    low = field.lower()
    for row in range(lo, hi):
        raw = lines[row][:MAX_SCAN_CHARS]
        if low in raw.lower() and stripped_code(raw).strip():
            yield from _row_fills(lines, row, raw, pattern)


def _row_fills(lines: Sequence[str], row: int, raw: str, pattern: re.Pattern[str]):
    norm = _QUOTED_KEY.sub(lambda m: " " + m.group(1) + " ", raw)
    masked = _mask_log_calls(mask_literals(norm))
    for m in pattern.finditer(masked):
        if not _in_log_call(lines, row, m.start()):
            cut = len(_top_level_cut(masked[m.end():]))
            yield row, norm[: m.start()], norm[m.end(): m.end() + cut], norm


def _producer_callee(root: str, scope: _Scope) -> str | None:
    """`root = [await] f(...)` or `{.., root, ..} = [await] f(...)`, nearest above the sink
    (the sink's own line included, _BINDING_RADIUS + 1 rows): `f`. Only rows that bind
    ``root`` are read (the file's binding index), plus any over-long row in reach."""
    site = _producer_site(root, scope)
    return None if site is None else site[1]


def _producer_site(root: str, scope: _Scope) -> tuple[int, str | None] | None:
    """(row, callee) of the binding `_producer_callee` reads, or None."""
    end = scope.line_num - 1
    for row in _binding_rows(scope, root, max(0, end - _BINDING_RADIUS - 1), end + 1):
        found, callee = _row_producer(_line_facts(scope.lines[row], scope.suffix), root)
        if found:
            return row, callee
    return None


def _binding_rows(scope: _Scope, name: str, start: int, end: int) -> list[int]:
    """Rows in [start, end) that may bind ``name``, nearest first: those the index lists, and
    the rows too long for the index (it skips them; `_line_facts` reads them whole)."""
    state = _file_state(scope.lines, scope.suffix)
    rows = set(_within(state.index(end).get(name, ()), start, end))
    rows.update(_within(_long_rows(scope.lines), start, end))
    return sorted(rows, reverse=True)


def _long_rows(lines: Sequence[str]) -> list[int]:
    rf = _r3_file(lines)
    long_rows = rf.memo.get(("long",))
    if long_rows is None:
        long_rows = rf.memo[("long",)] = [i for i, x in enumerate(lines) if len(x) > MAX_SCAN_CHARS]
    return long_rows


def _row_producer(facts: _Facts, root: str) -> tuple[bool, str | None]:
    rhs = facts.assigns.get(root)
    if rhs is not None:
        return True, _assigned_callee(rhs)
    if facts.destructure and root in facts.destructure[0]:
        return True, _source_callee(facts.destructure[1])
    return False, None


def _assigned_callee(rhs: str) -> str | None:
    m = _CALL_HEAD.match(_LEAD_KEYWORD.sub("", _rhs_text(rhs).strip()))
    return _last_segment(m.group(1)) if m else None


def _source_callee(src: str) -> str | None:
    return _last_segment(src[:-1]) if src.endswith("(") else None


def _member_fills(lines: Sequence[str], field: str) -> bool:
    """F2: the file holds `.F = <error>` or `setF(<error>)` (memoised per file and field)."""
    return _memo(_r3_file(lines), ("member", field), lambda: _member_fills_uncached(lines, field))


def _member_fills_uncached(lines: Sequence[str], field: str) -> bool:
    pattern = _templated(_member_assign_pattern, field)
    low = field.lower()
    return any(_member_fill_row(lines, row, low, pattern) for row in range(len(lines)))


def _member_fill_row(lines: Sequence[str], row: int, low: str, pattern: re.Pattern[str]) -> bool:
    raw = lines[row][:MAX_SCAN_CHARS]
    return low in raw.lower() and bool(stripped_code(raw).strip()) and _row_member_fill(lines, row, raw, pattern)


def _row_member_fill(lines: Sequence[str], row: int, raw: str, pattern: re.Pattern[str]) -> bool:
    masked = _mask_log_calls(mask_literals(raw))
    for m in pattern.finditer(masked):
        rhs = raw[m.end(): m.end() + len(_top_level_cut(masked[m.end():]))]
        if rhs.strip() and _provenance_fill(lines, row, raw[: m.start()], rhs):
            return True
    return False


def _provenance_fill(lines: Sequence[str], row: int, prefix: str, rhs: str) -> bool:
    """`_fill_is_error`, one provenance level deeper (F stops at _PROVENANCE_DEPTH)."""
    ctx = _active_scan()
    ctx.in_prov += 1
    try:
        return _fill_is_error(lines, row, prefix, rhs)
    finally:
        ctx.in_prov -= 1


# ---- return binding: producer evidence counts only inside the value a routine returns ----

def _expression_end(rf: _R3File, row: int, col: int, hi: int) -> tuple[int, int]:
    """(row, col) where the expression starting at (row, col) ends: bracket depth, `;` or a
    line end at depth 0 that does not continue onto the next line."""
    depth, last = 0, min(hi, row + _SPAN_ROWS)
    for r in range(row, last):
        depth, stop = _expression_row(rf, r, col if r == row else None, depth)
        if stop is not None:
            return r, stop
    return last - 1, 10 ** 6


def _expression_row(rf: _R3File, r: int, col: int | None, depth: int) -> tuple[int, int | None]:
    """(depth, the column the expression stops at or None) after row ``r``; ``col`` is the
    start column on the expression's first row, None on the rows after it."""
    text = _masked_row(rf, r)
    depth, stop = _scan_expression(text, col or 0, depth)
    return depth, stop if stop is not None else _line_stop(rf, r, text, col, depth)


def _line_stop(rf: _R3File, r: int, text: str, col: int | None, depth: int) -> int | None:
    return len(text) if depth == 0 and _ends_statement(rf, r, text, col) else None


def _scan_expression(text: str, start: int, depth: int) -> tuple[int, int | None]:
    for m in _CUT_CHARS.finditer(text, start):
        depth, stopped = _expression_step(m.group(), depth)
        if stopped:
            return depth, m.start()
    return depth, None


def _expression_step(ch: str, depth: int) -> tuple[int, bool]:
    """A top-level `;` ends the expression; so does a bracket closing outside it."""
    if ch == ";" and depth == 0:
        return depth, True
    depth += _DEPTH_DELTA.get(ch, 0)
    return depth, depth < 0


def _ends_statement(rf: _R3File, r: int, text: str, col: int | None) -> bool:
    """The line ends the expression: no trailing continuation, no leading one on the next
    line, and (on the first line) something after the start."""
    tail = text.rstrip()
    if _continues(rf, r, tail):
        return False
    return col is None or bool(tail[col:].strip())


def _continues(rf: _R3File, r: int, tail: str) -> bool:
    nxt = _masked_row(rf, r + 1).lstrip() if r + 1 < len(rf.lines) else ""
    return tail.endswith(_CONTINUES_AT_END) or nxt.startswith(_CONTINUES_AT_START)


def _value_spans(rf: _R3File, start: int, end: int) -> tuple[list, frozenset[str]]:
    """The spans of the values the routine at ``start`` returns, and the variables it
    returns whole (memoised per routine)."""
    return _memo(rf, ("vspans", start, end), lambda: _value_spans_uncached(rf, start, end))


def _value_spans_uncached(rf: _R3File, start: int, end: int) -> tuple[list, frozenset[str]]:
    spans: list = []
    returned: set[str] = set()
    for r in range(start, end):
        text = _masked_row(rf, r)
        _return_spans(rf, r, text, end, spans, returned)
        _arrow_spans(rf, r, text, end, spans)
        _construction_statement_spans(rf, r, text, end, spans)
        if r == start:
            _expression_body_span(rf, r, text, end, spans)
    for name in returned:
        _binding_spans(rf, name, start, end, spans)
    return spans, frozenset(returned)


def _return_spans(rf: _R3File, r: int, text: str, end: int, spans: list, returned: set[str]) -> None:
    """After `return` / `yield`; a bare returned variable is remembered."""
    for m in _RETURN_WORD.finditer(text):
        stop = _expression_end(rf, r, m.end(), end)
        spans.append((r, m.end(), stop))
        returned.update(_returned_variable(text, r, m.end(), stop))


def _returned_variable(text: str, r: int, at: int, stop: tuple[int, int]) -> tuple[str, ...]:
    v = _BARE_VARIABLE.match(text[at: stop[1]]) if stop[0] == r else None
    return (v.group(1),) if v and v.group(1) not in _NOT_A_VARIABLE else ()


def _arrow_spans(rf: _R3File, r: int, text: str, end: int, spans: list) -> None:
    """An arrow or match-arm expression that is not a block (a construction block counts)."""
    for m in _ARM_ARROW.finditer(text):
        after = text[m.end():].lstrip()
        if not after.startswith("{") or _CTOR_HEAD.match(after):
            spans.append((r, m.end(), _expression_end(rf, r, m.end(), end)))


def _expression_body_span(rf: _R3File, r: int, text: str, end: int, spans: list) -> None:
    """`) [: T] = expr`: an expression body on the header line."""
    m = _EXPR_BODY.search(text)
    if m:
        spans.append((r, m.end(), _expression_end(rf, r, m.end(), end)))


def _construction_statement_spans(rf: _R3File, r: int, text: str, end: int, spans: list) -> None:
    """A statement that is a bare construction: the block value of Ruby, Kotlin, Rust and Scala."""
    starts = [_LEAD_CLOSE.match(text).end(), *(m.end() for m in _STATEMENT_STARTS.finditer(text))]
    for pos in starts:
        if _CTOR_HEAD.match(text, pos):
            spans.append((r, pos, _expression_end(rf, r, pos, end)))


def _variable_binding_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}\s{{0,2}}(?::\s{{0,2}}[\w$<>?\[\]. ]{{1,60}})?(?::=|=(?![=>]))"


def _binding_spans(rf: _R3File, name: str, start: int, end: int, spans: list) -> None:
    """The binding statements of a variable the routine returns whole."""
    pattern = _templated(_variable_binding_pattern, name)
    for r in range(start, end):
        text = _masked_row(rf, r)
        if name in text:
            spans.extend((r, m.end(), _expression_end(rf, r, m.end(), end)) for m in pattern.finditer(text))


def _call_depth(rf: _R3File, r0: int, c0: int, r: int, c: int) -> tuple[int, bool]:
    """Unclosed `(` between (r0, c0) and (r, c), and whether the outermost one is a grouping
    paren or a construction head at the span start."""
    depth, first = 0, None
    for row in range(r0, r + 1):
        text = _masked_row(rf, row)
        span = (c0 if row == r0 else 0, c if row == r else len(text))
        depth, first = _row_parens(text, span, depth, first, row == r0)
    return depth, bool(first)


def _row_parens(text: str, span: tuple[int, int], depth: int, first: bool | None,
                on_start_row: bool) -> tuple[int, bool | None]:
    lo, hi = span
    for m in _PARENS.finditer(text, lo, min(hi, len(text))):
        depth, first = _paren_step(text, (lo, m), depth, first, on_start_row)
    return depth, first


def _paren_step(text: str, at: tuple[int, re.Match[str]], depth: int, first: bool | None,
                on_start_row: bool) -> tuple[int, bool | None]:
    """One paren; the first `(` opened at depth 0 is judged once (None until then)."""
    lo, m = at
    if m.group() == ")":
        return depth - 1, first
    if depth == 0 and first is None:
        first = _first_paren_ok(text, lo, m.start(), on_start_row)
    return depth + 1, first


def _first_paren_ok(text: str, lo: int, at: int, on_start_row: bool) -> bool:
    return on_start_row and bool(_GROUP_OR_CTOR.fullmatch(text[lo: at + 1]))


_PARENS = re.compile(r"[()]")


def _in_value(rf: _R3File, start: int, end: int, at: tuple[int, int], receiver: str = "") -> bool:
    """(row, col) is part of what the routine returns: on a returned variable, or inside a
    value span at call depth 0 (1 when the outer paren groups or constructs the value)."""
    spans, returned = _value_spans(rf, start, end)
    return (bool(receiver) and receiver in returned) or _in_a_span(rf, spans, at)


def _in_a_span(rf: _R3File, spans: list, at: tuple[int, int]) -> bool:
    return any(_depth_in_value(rf, r0, c0, at) for r0, c0, stop in spans if (r0, c0) <= at <= stop)


def _depth_in_value(rf: _R3File, r0: int, c0: int, at: tuple[int, int]) -> bool:
    depth, first_ok = _call_depth(rf, r0, c0, at[0], at[1])
    return depth <= 0 or (depth == 1 and first_ok)


def _fill_receiver(prefix: str, line: str) -> str:
    """The object a keyed fill writes into: `X.F =`, `X->F =`, `X.setF(` or `X[...] =`."""
    m = _FILL_RECEIVER.search(prefix)
    return m.group(1) if m and _writes_into(prefix, line[len(prefix):].lstrip()) else ""


def _writes_into(prefix: str, rest: str) -> bool:
    """The fill is a member or subscript write (the match starts at the `.`, `->` or `[`)."""
    if prefix.rstrip().endswith((".", "->", "?.")) or rest.startswith((".", "->")):
        return True
    return _OPEN_SUBSCRIPT.search(prefix) is None and rest.startswith("[")


def _returned_fill(lines: Sequence[str], field: str, start: int, end: int) -> bool:
    """F1: a keyed fill of ``field`` from an error, inside the returned value."""
    rf = _r3_file(lines)
    return any(_returned_fill_row(lines, rf, (start, end), fill)
               for fill in _population_rows(lines, field, start, end))


def _returned_fill_row(lines: Sequence[str], rf: _R3File, extent: tuple[int, int], fill: tuple) -> bool:
    row, prefix, rhs, norm = fill
    start, end = extent
    return bool(rhs.strip()) and _in_value(rf, start, end, (row, len(prefix)), _fill_receiver(prefix, norm)) \
        and _provenance_fill(lines, row, prefix, rhs)


def _construction_callee(m: re.Match[str]) -> str:
    segs = list(filter(None, _PATH_SEGMENT.split(m.group(2))))
    return segs[-2] if len(segs) > 1 and segs[-1] == "new" else segs[-1]


def _construction_fills(lines: Sequence[str], field: str, start: int, end: int, hop: int, own: str) -> bool:
    """F3/F4: a construction or same-file hop in the returned value fills ``field`` from an error."""
    rf = _r3_file(lines)
    for row in range(start, end):
        raw = lines[row][:MAX_SCAN_CHARS]
        for m in _CONSTRUCT.finditer(mask_literals(raw)):
            if _construction_hit(lines, rf, field, (start, end, row, hop, own), raw, m):
                return True
    return False


def _construction_hit(lines, rf, field, where, raw, m) -> bool:
    start, end, row, hop, own = where
    callee = _construction_callee(m)
    if not _candidate_callee(callee, own) or not _in_value(rf, start, end, (row, m.start())):
        return False
    args = _row_brace_args(lines, row, m.end(4) - 1)
    return bool(args.strip()) and _constructed_from_error(lines, field, (row, hop, callee), raw[: m.start()], args)


def _candidate_callee(callee: str, own: str) -> bool:
    return callee not in _SKIP_NAMES and callee[:1].isalpha() and callee != own


def _constructed_from_error(lines, field, at, prefix, args) -> bool:
    """K: a same-file type's member order names ``field``; else P: a same-file routine hop."""
    row, hop, callee = at
    members = _type_members(lines, callee)
    if members:
        return _positional_fill(lines, field, members, (row, hop), prefix, args)
    return _hop_fills(lines, field, callee, hop) or _error_factory_fill(lines, at, prefix, args)


def _error_factory_fill(lines: Sequence[str], at: tuple, prefix: str, args: str) -> bool:
    """An error-role factory defined outside the file (`Result.fail(e.message)`, `Outcome.failure(...)`)
    whose ONLY argument is error text: that text is the failure the result carries."""
    row, hop, callee = at
    if not _ERROR_FACTORY_WORDS.issuperset(_lower_words(callee)) or _def_rows(lines, callee):
        return False
    parts = _split_top(args)
    return len(parts) == 1 and _fill_is_error(lines, row, prefix, parts[0], hop)


def _hop_fills(lines: Sequence[str], field: str, callee: str, hop: int) -> bool:
    return hop < _HOPS and callee != field and bool(_def_rows(lines, callee)) and \
        _producer_fills(lines, field, callee, hop + 1)


def _positional_fill(lines, field, members, at, prefix, args) -> bool:
    low = [x.lower() for x in members]
    if field.lower() not in low:
        return False
    row, hop = at
    arg = _pick_argument(args, low.index(field.lower()), field)
    return bool(arg) and _fill_is_error(lines, row, prefix, arg, hop)


def _producer_fills(lines: Sequence[str], field: str, callee: str, hop: int = 0) -> bool:
    """F1/F3/F4: a same-file routine ``callee`` fills ``field`` from an error in what it returns."""
    key = ("producer", field, callee, hop)
    return _memo(_r3_file(lines), key, lambda: _producer_fills_uncached(lines, field, callee, hop))


def _producer_fills_uncached(lines: Sequence[str], field: str, callee: str, hop: int) -> bool:
    for start in _def_rows(lines, callee):
        end = _routine_end(lines, start)
        if _returned_fill(lines, field, start, end) or _construction_fills(lines, field, start, end, hop, callee):
            return True
    return False


# ---- K: ordered members of a same-file type ----

def _record_head(name: str) -> str:
    n = re.escape(name)
    return (rf"(?:\brecord|\bdata\s{{1,4}}class|\bcase\s{{1,4}}class|\bclass)\s{{1,4}}{n}\s{{0,2}}"
            rf"(?:<[^<>]{{0,80}}>)?\s{{0,2}}\(")


def _struct_new_head(name: str) -> str:
    return rf"(?<![\w$]){re.escape(name)}\s{{0,2}}=\s{{0,2}}Struct\.new\s{{0,2}}\("


def _struct_block_head(name: str) -> str:
    n = re.escape(name)
    return rf"(?:\btype\s{{1,4}}{n}\s{{1,4}}struct|\bstruct\s{{1,4}}{n})\s{{0,4}}\{{"


def _dataclass_head(name: str) -> str:
    return rf"\s*class\s+{re.escape(name)}\s*[:(]"


_TYPE_HEADS = (_record_head, _struct_new_head, _struct_block_head)


def _type_members(lines: Sequence[str], name: str) -> list[str] | None:
    """Ordered members of a same-file type declaration of ``name``, or None (memoised per file)."""
    rf = _r3_file(lines)
    key = ("type", name)
    if key not in rf.memo:
        rf.memo[key] = _type_members_uncached(lines, name)
    return rf.memo[key]


def _type_members_uncached(lines: Sequence[str], name: str) -> list[str] | None:
    heads = _type_heads(name)
    for row, raw in enumerate(lines):
        found = _head_members(lines, row, raw, heads) if name in raw else None
        if found is not None:
            return found
    return _first_known((_dataclass_members, _ctor_property_members), lines, name)


def _first_known(readers: tuple, lines: Sequence[str], name: str) -> list[str] | None:
    return next((found for found in (read(lines, name) for read in readers) if found is not None), None)


def _type_heads(name: str) -> list[re.Pattern[str]]:
    return [_templated(head, name) for head in _TYPE_HEADS]


def _head_members(lines: Sequence[str], row: int, raw: str, heads: list) -> list[str] | None:
    code = raw[:MAX_SCAN_CHARS]
    for k, head in enumerate(heads):
        m = head.search(code)
        if m:
            return _MEMBER_READERS[k](lines, row, code, m)
    return None


def _record_members(lines: Sequence[str], row: int, code: str, m: re.Match[str]) -> list[str]:
    joined = _joined(lines, row, _TYPE_ROWS)
    body = _brace_args(joined, joined.index(code) + m.end() - 1)
    return [param_name(_MEMBER_PREFIX.sub("", p)) for p in _split_top(body)]


def _struct_new_members(lines: Sequence[str], row: int, code: str, m: re.Match[str]) -> list[str]:
    joined = _joined(lines, row, _TYPE_ROWS)
    body = _brace_args(joined, joined.index(code) + m.end() - 1)
    return [s.strip().lstrip(":").strip("'\" ") for s in _split_top(body)]


def _struct_block_members(lines: Sequence[str], row: int, code: str, m: re.Match[str]) -> list[str]:
    out: list[str] = []
    for r in range(row + 1, min(len(lines), row + _MEMBER_ROWS)):
        s = stripped_code(lines[r]).strip()
        if s.startswith("}"):
            return out
        out.extend(_struct_row_members(s))
    return out


def _struct_row_members(s: str) -> list[str]:
    return [mm.group(1) for mm in map(_struct_member, s.split(",")) if mm]


def _struct_member(part: str) -> re.Match[str] | None:
    part = part.strip()
    return _STRUCT_MEMBER.match(part + " ") if part else None


_MEMBER_READERS = (_record_members, _struct_new_members, _struct_block_members)


def _class_head(name: str) -> str:
    return rf"(?<![\w$])class\s{{1,4}}{re.escape(name)}(?![\w$])"


def _ctor_property_members(lines: Sequence[str], name: str) -> list[str] | None:
    """A class whose constructor declares members in its parameter list (`constructor(public
    ok: boolean, public error?: string)`, `__construct(public bool $ok, ...)`): those, in order;
    a parameter with no modifier is not a member and keeps its position as ""."""
    head = _templated(_class_head, name)
    row = next((r for r, raw in enumerate(lines) if _declares_class(raw, name, head)), None)
    return None if row is None else _ctor_members_below(lines, row)


def _declares_class(raw: str, name: str, head: re.Pattern[str]) -> bool:
    return name in raw and head.search(raw[:MAX_SCAN_CHARS]) is not None


def _ctor_members_below(lines: Sequence[str], row: int) -> list[str] | None:
    """The first constructor in the class body (before another class starts)."""
    for r in range(row, min(len(lines), row + _MEMBER_ROWS)):
        raw = lines[r][:MAX_SCAN_CHARS]
        m = _CTOR_PARAMS.search(raw)
        if m or _another_class(raw, r > row):
            return _property_list(lines, r, raw, m)
    return None


def _another_class(raw: str, below: bool) -> bool:
    return below and _CLASS_DECL.search(stripped_code(raw)) is not None


def _property_list(lines: Sequence[str], r: int, raw: str, m: re.Match[str] | None) -> list[str] | None:
    if m is None:
        return None
    joined = _joined(lines, r, _TYPE_ROWS)
    return _declared_members(_split_top(_brace_args(joined, joined.index(raw) + m.end() - 1)))


def _declared_members(entries: list[str]) -> list[str] | None:
    """Entries come from rows joined as one text, so a wrapped list (one parameter per line,
    as formatters write it) carries the row's indentation: it is stripped before the match."""
    names = [param_name(e.strip()) if _PROPERTY_MODIFIER.match(e.strip()) else "" for e in entries]
    return names if any(names) else None


def _dataclass_members(lines: Sequence[str], name: str) -> list[str] | None:
    """A Python `@dataclass` class body, in declaration order."""
    head = _templated(_dataclass_head, name)
    row = next((r for r, raw in enumerate(lines) if _dataclass_header(lines, r, raw, head)), None)
    return None if row is None else _indented_members(lines, row, indent_width(lines[row]))


def _dataclass_header(lines: Sequence[str], r: int, raw: str, head: re.Pattern[str]) -> bool:
    return head.match(raw) is not None and r > 0 and "dataclass" in lines[r - 1]


def _indented_members(lines: Sequence[str], row: int, ind: int) -> list[str]:
    out: list[str] = []
    for r in range(row + 1, min(len(lines), row + _MEMBER_ROWS)):
        s = lines[r]
        if s.strip() and indent_width(s) <= ind:
            break
        out.extend(_dataclass_member(s))
    return out


def _dataclass_member(s: str) -> tuple[str, ...]:
    mm = _DATACLASS_MEMBER.match(s)
    return (mm.group(1),) if mm else ()


# ---- arm F entry points ----

def _populated_in_producer(lines: Sequence[str], field: str, callee: str) -> bool:
    """The producer ``callee`` fills ``field`` from an error: same file, else (X2, an error-named
    field only, never inside a C1 helper's arguments) its only definition in the tree."""
    return _producer_fills(lines, field, callee, 0) or _tree_producer_fills(lines, field, callee)


def _tree_producer_fills(lines: Sequence[str], field: str, callee: str) -> bool:
    if not _x2_applies(lines, field, callee):
        return False
    other = _only_definition_file(callee)
    return other is not None and _sole_producer_fills(other, field, callee)


def _x2_applies(lines: Sequence[str], field: str, callee: str) -> bool:
    return not (_active_scan().x2_off or not _error_field(field, detail_ok=False) or _def_rows(lines, callee))


def _sole_producer_fills(other: Sequence[str], field: str, callee: str) -> bool:
    return len(_def_rows(other, callee)) == 1 and _producer_fills(other, field, callee, 0)


def _field_discloses(field: str, scope: _Scope, root: str | None = None) -> bool:
    """Arm F: the field read is error text only with evidence of where it was filled."""
    if _active_scan().in_prov >= _PROVENANCE_DEPTH or not _error_field(field):
        return False
    return _field_has_evidence(field, scope, root)


def _field_has_evidence(field: str, scope: _Scope, root: str | None) -> bool:
    callee = _read_producer(field, scope, root)
    return _producer_evidence(field, scope, callee) or _member_evidence_stands(field, scope, callee, root or field)


def _read_producer(field: str, scope: _Scope, root: str | None) -> str | None:
    return _producer_callee(root or field, scope)


def _member_evidence_stands(field: str, scope: _Scope, callee: str | None, root: str) -> bool:
    """F2, unless the read's own same-file producer decides the field (all literal) and nothing
    refills the field on the read's root between that binding and the read."""
    return _member_evidence(field, scope) and not (
        _producer_decides(scope.lines, field, callee) and not _refilled_since_binding(root, field, scope))


def _producer_evidence(field: str, scope: _Scope, callee: str | None) -> bool:
    return bool(callee) and _populated_in_producer(scope.lines, field, callee)


def _member_evidence(field: str, scope: _Scope) -> bool:
    """F2: a file-wide `.F = <error>` (not for a detail-word field: M needs a producer)."""
    return not _detail_only(field) and _member_fills(scope.lines, field)


# ---- F2 yields to a visible producer whose every value is literal ----

def _refilled_since_binding(root: str, field: str, scope: _Scope) -> bool:
    """A non-literal fill of ``field`` on ``root`` itself (`v.F = ...`, `v["F"] = ...`,
    `assign(v, ...)` / `v.update(...)`) between the producer's binding and the read: the
    producer no longer says what the field holds."""
    site = _producer_site(root, scope)
    lo = site[0] + 1 if site else 0
    pattern = _templated(_refill_pattern, f"{root.lstrip('$')}.{field}")
    return any(_row_refills(scope.lines[r], pattern) for r in range(lo, scope.line_num))


def _refill_pattern(key: str) -> str:
    root, field = key.split(".")
    names = "|".join(map(re.escape, sorted({field, field[:1].upper() + field[1:], field[:1].lower() + field[1:]})))
    r = rf"\$?{re.escape(root)}"
    return (rf"(?<![\w$.]){r}\s{{0,2}}(?:(?:\?\.|\.|->)\s{{0,2}}(?:{names})|\[\s{{0,2}}(?:{names})"
            rf"\s{{0,2}}\])\s{{0,2}}=(?![=>])"
            rf"|(?<![\w$])(?:assign|merge|extend)\s{{0,2}}\(\s{{0,2}}{r}\s{{0,2}},"
            rf"|(?<![\w$.]){r}\s{{0,2}}(?:\.|->)\s{{0,2}}update\s{{0,2}}\(")


def _row_refills(raw: str, pattern: re.Pattern[str]) -> bool:
    """A quoted key (`v["F"] =`) is read as the bare key, as `_row_fills` reads it."""
    code = _QUOTED_KEY.sub(lambda k: " " + k.group(1) + " ", _uncomment(raw[:MAX_SCAN_CHARS])[0])
    masked = mask_literals(code)
    m = pattern.search(masked)
    return m is not None and not _literal_text(code[m.end(): m.end() + len(_top_level_cut(masked[m.end():]))])


def _producer_decides(lines: Sequence[str], field: str, callee: str | None) -> bool:
    """The read's root is bound from a same-file routine whose every fill of ``field`` and
    every value it returns is literal or a code constant: that routine, not an unrelated
    `.F = <error>` elsewhere in the file, says what the field holds (memoised per file)."""
    if not callee:
        return False
    key = ("decides", field, callee)
    return bool(_memo(_r3_file(lines), key, lambda: _producer_decides_uncached(lines, field, callee)))


def _producer_decides_uncached(lines: Sequence[str], field: str, callee: str) -> bool:
    starts = _def_rows(lines, callee)
    return bool(starts) and all(_routine_decides(lines, field, start) for start in starts)


def _routine_decides(lines: Sequence[str], field: str, start: int) -> bool:
    end = _routine_end(lines, start)
    rf = _r3_file(lines)
    spans, _ = _value_spans(rf, start, end)
    return bool(spans) and all(_literal_text(_span_code(rf, span)) for span in spans) and \
        _fills_literal(lines, field, start, end)


def _fills_literal(lines: Sequence[str], field: str, start: int, end: int) -> bool:
    return all(_literal_text(rhs) for _, _, rhs, _ in _population_rows(lines, field, start, end))


def _span_code(rf: _R3File, span: tuple) -> str:
    """The code of a value span (comments blanked, literals kept for `_strip_literals_209`)."""
    r0, c0, (r1, c1) = span
    rows = [_uncomment(rf.lines[r][:MAX_SCAN_CHARS])[0] for r in range(r0, min(r1, len(rf.lines) - 1) + 1)]
    if len(rows) == 1:
        return rows[0][c0:c1]
    return " ".join([rows[0][c0:], *rows[1:-1], rows[-1][:c1]])


def _literal_text(text: str) -> bool:
    """Only literals, code constants (`Codes.X`), keys and type constructions: no name that
    could carry text from elsewhere (a conditional, a lowercase call or a variable is not)."""
    stripped = _strip_literals_209(text)
    if "?" in stripped:
        return False
    return _LITERAL_WORDS.issuperset(_LITERAL_WORD.findall(_LITERAL_NOISE.sub(" ", stripped)))


def _field_arm(root: str, chains: list[str], scope: _Scope, may_bind: Callable[[str], bool]) -> bool:
    """`x.error` with ``x`` resolving by name (unknown / a result field): F decides."""
    if _resolve_with(root, scope, may_bind) not in _BY_NAME:
        return False
    return any(_field_discloses(f, scope, root) for f in _chain_error_fields(chains, root))


def _field_token(ident: str, scope: _Scope) -> bool:
    """A bare value bound from a result field (`{ error } = load()`, `{ error: why } = ...`)."""
    if _resolve_bound(ident, scope) != "field":
        return False
    if _field_discloses(ident, scope, None):
        return True
    field = _alias_field(ident, scope)
    return field is not None and _field_discloses(field, scope, ident)


# ---- rule R: a renamed destructure `{ F: alias }` reads F ----

@lru_cache(maxsize=1024)
def _destructure_aliases(code: str) -> tuple[tuple[str, str], ...]:
    """(alias, field) for each `F: alias` of the line's destructuring pattern; a conventional
    error name as the alias keeps the exact-name rule (`{ error: err }`)."""
    m = _DESTRUCTURE.search(code) if "=" in code else None
    return _renamed_pairs(m.group(1)) if m else ()


def _renamed_pairs(pattern: str) -> tuple[tuple[str, str], ...]:
    return tuple(pair for part in _split_top(pattern) if (pair := _renamed(part)))


def _renamed(part: str) -> tuple[str, str] | None:
    if ":" not in part:
        return None
    key, alias = (x.strip() for x in part.split(":", 1))
    alias = alias.split("=")[0].strip()
    return (alias, key) if _renameable(key, alias) else None


def _renameable(key: str, alias: str) -> bool:
    return bool(_NAME_RE.fullmatch(key) and _NAME_RE.fullmatch(alias)) and not _EXACT_ERROR_NAME.fullmatch(alias)


def _alias_field(ident: str, scope: _Scope) -> str | None:
    """The field ``ident`` renames, read from its nearest destructuring binding above the sink."""
    state = _file_state(scope.lines, scope.suffix)
    end = scope.line_num - 1
    for row in _candidate_rows(state.index(end), ident, end):
        pairs = dict(_destructure_aliases(_line_facts(scope.lines[row], scope.suffix).code))
        if ident in pairs:
            return pairs[ident]
    return None


# ---- arm Y: a detail-role key over a singular error field, beside a code ----

def _keyed_chain(chain: str) -> tuple[str, list[str]]:
    root = _SEGMENT_SPLIT.split(chain)[0].strip()
    members = _members(chain[len(root):])
    while len(members) > 1 and members[-1] in _TRAILING_TRANSFORMS:
        members = members[:-1]
    return root, members


def _keyed_error_field(root: str, members: list[str]) -> bool:
    """A singular error-named field (a plural `errors` is a list of issues: validation)."""
    if not members:
        return False
    field = _field_name(members[-1])
    return _error_field(field, detail_ok=False) and not _is_type_constant(root, members) \
        and not field.lower().endswith("s")


def _key_role_field(ctx: "_LineCtx", spans: list) -> tuple[int, str] | None:
    """Arm Y: (row, key text) of a detail-role key whose value is an error field of a root
    that is not clean, in an object that also carries a literal code; V excuses it."""
    args = _joined_arguments(ctx, spans)[:MAX_SCAN_CHARS]
    m = _first_keyed(ctx, spans, args) if _CODE_KEY.search(args) else None
    return None if m is None else _unexcused_key(ctx, m)


def _first_keyed(ctx: "_LineCtx", spans: list, args: str) -> re.Match[str] | None:
    scope = _Scope(ctx.lines, ctx.line_num, ctx.line[: spans[0][0].start()], suffix=ctx.suffix)
    return next((m for m in _KEYED_FIELD.finditer(args) if _keyed_qualifies(scope, m)), None)


def _unexcused_key(ctx: "_LineCtx", m: re.Match[str]) -> tuple[int, str] | None:
    chain_root = _ROOT_SPLIT.split(_KEY_SPLIT.split(m.group(0), maxsplit=1)[-1].strip())[0]
    return None if _excused(ctx.lines, ctx.line_num, chain_root) else (_key_row(ctx, m) + 1, m.group(0))


def _keyed_qualifies(scope: _Scope, m: re.Match[str]) -> bool:
    """The keyed value is a singular error field of a root that does not resolve clean."""
    root, members = _keyed_chain(m.group(1))
    return _keyed_error_field(root, members) and root not in ("this", "self") and _resolve(root, scope) != "clean"


def _key_row(ctx: "_LineCtx", m: re.Match[str]) -> int:
    """The line of the sink's call that holds the key (the finding's anchor)."""
    head = m.group(1).split(".")[0]
    key = m.group(0).split(":")[0].strip("\"'` ")
    rows = range(ctx.line_num - 1, min(len(ctx.lines), ctx.line_num + _CONTINUATION_LINES))
    return next((r for r in rows if head in ctx.lines[r] and key in ctx.lines[r]), ctx.line_num - 1)


def _key_role_reports(ctx: "_LineCtx", spans: list) -> bool:
    """Y on a peer sink: True when the key sits on the sink's line; a key on a continuation
    line is reported on its own line."""
    hit = _key_role_hit(ctx, spans)
    if hit is None or hit[0] == ctx.line_num:
        return hit is not None
    _emit_209(hit[0])
    return False


def _key_role_hit(ctx: "_LineCtx", spans: list) -> tuple[int, str] | None:
    first = spans[0][0]
    if not _file_facts(ctx.lines).keyed or not _sink_is_peer(ctx.line, first.start(), first.end()):
        return None
    return _key_role_field(ctx, spans)


# ---- arms C1 / C2 / H: bare-call response sinks, with the excuses V and T ----

def _is_response_helper(name: str) -> bool:
    """C1 by name: a response verb and a DIFFERENT response-shaped word (`writeError`, `sendJson`)."""
    words = _lower_words(name)
    verb = _first_verb(words)
    return len(words) > 1 and verb is not None and _has_shape_besides(words, verb)


def _lower_words(name: str) -> list[str]:
    return [w.lower() for w in identifier_words(name)]


def _first_verb(words: list[str]) -> str | None:
    return next((w for w in words if w in _RESPONSE_VERBS), None)


def _has_shape_besides(words: list[str], verb: str) -> bool:
    return any(w in _RESPONSE_SHAPES and w != verb for w in words)


def _helper_signature_pattern(name: str) -> str:
    return (rf"{re.escape(name)}\s{{0,2}}(?:<[^<>]{{0,80}}>)?\s{{0,2}}"
            rf"(?:=\s{{0,2}}(?:async\s{{1,4}})?(?:function\s{{0,4}})?)?\(")


def _whole_token_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}(?![\w$])(?!\s{{0,2}}(?:\.|\?\.|->|\[))"


def _helper_writes(lines: Sequence[str], name: str) -> set[int] | None:
    """H: indices of the parameters a same-file routine ``name`` writes WHOLE to a peer sink;
    None when no same-file routine has that name (memoised per file)."""
    rf = _r3_file(lines)
    key = ("helper", name)
    if key not in rf.memo:
        rf.memo[key] = None          # a recursive ask meanwhile reads "no same-file routine"
        rf.memo[key] = _helper_writes_uncached(lines, name)
    return rf.memo[key]


def _helper_writes_uncached(lines: Sequence[str], name: str) -> set[int] | None:
    out: set[int] | None = None
    for start in _def_rows(lines, name):
        params = _helper_params(_header_text(lines, start), name)
        if params is not None:
            out = (out or set()) | _params_written(lines, start, params)
    return out


def _helper_params(header: str, name: str) -> list[str] | None:
    m = _templated(_helper_signature_pattern, name).search(header)
    return None if m is None else _helper_param_names(header, m)


def _helper_param_names(header: str, m: re.Match[str]) -> list[str]:
    name_first = _FUNC_WORD.search(header[: m.start() + 1]) is not None
    entries = _split_top(call_argument_text(header, m.end() - 1, MAX_SCAN_CHARS))
    return [p for p in (_entry_name(e, name_first) for e in entries) if p not in ("self", "cls", "this")]


def _entry_name(entry: str, name_first: bool) -> str:
    """A parameter entry's name; under `func` an entry with no `:` is Go's `name Type` (Swift
    entries always carry `:`)."""
    m = _NAME_BEFORE_TYPE.match(entry) if name_first and ":" not in entry else None
    return m.group(1) if m else param_name(entry)


def _params_written(lines: Sequence[str], start: int, params: list[str]) -> set[int]:
    written: set[int] = set()
    for r in range(start, _routine_end(lines, start)):
        written.update(_written_indices(lines, r, params))
    return written


def _written_indices(lines: Sequence[str], r: int, params: list[str]) -> set[int]:
    """The parameters row ``r`` writes to a peer; none when the base rule already reports
    the row itself (that row is the report, the call is not reported a second time)."""
    out = _row_written(lines, r, params)
    return out if out and not _row_reported(lines, r) else set()


def _row_written(lines: Sequence[str], r: int, params: list[str]) -> set[int]:
    return {i for args in _peer_write_arguments(lines, r, lines[r]) for i in _params_in(args, params)}


def _params_in(args: str, params: list[str]) -> list[int]:
    return [i for i, p in enumerate(params) if _written_whole(p, args)]


def _row_reported(lines: Sequence[str], r: int) -> bool:
    """The base rule reports row ``r`` on its own: the CWE-550 shape, or the value rule."""
    raw = lines[r]
    path = _active_scan().file_path or Path("site")
    return _may_be_server_error(raw) or _discloses_error(path, raw, r + 1, lines)


def _peer_write_arguments(lines: Sequence[str], r: int, raw: str) -> Iterator[str]:
    """The arguments of every peer sink on row ``r`` (``raw``: the row as read), continued
    while the call is open; then those of the writes that take the peer writer as an argument."""
    code, masked = _uncomment(raw)
    for s in _RESPONSE_WRITE.finditer(masked):
        if _sink_is_peer(code, s.start(), s.end()):
            yield call_argument_text("(" + _sink_tail(lines, r + 1, code[s.end():]), 0, MAX_SCAN_CHARS)
    yield from _writer_writes(lines, r, code, masked)


def _writer_writes(lines: Sequence[str], r: int, code: str, masked: str) -> Iterator[str]:
    calls = list(_WRITER_ARG_CALL.finditer(masked))
    if calls and not _declares_routine(code, lines, r):
        yield from filter(None, (_writer_write(code, masked, m) for m in calls))


def _declares_routine(code: str, lines: Sequence[str], r: int) -> bool:
    """A routine's own header (`function sendJson(res, status, body) {`) writes nothing."""
    return routine_header(code) and _is_declaration(code, lines, r)


def _writer_write(code: str, masked: str, m: re.Match[str]) -> str | None:
    """`verb(w, args...)`: the arguments after the writer; `f(w).verb(args)`: the chained call's."""
    if m.group(2) == ",":
        return _after_writer(code, masked.index("(", m.end(1))) if _is_writer_verb(m.group(1)) else None
    return _chained_write(code, _CHAINED_CALL.match(masked, m.end()))


def _chained_write(code: str, chained: re.Match[str] | None) -> str | None:
    if chained is None or not _is_writer_verb(chained.group(1)):
        return None
    return call_argument_text(code, chained.end() - 1, MAX_SCAN_CHARS)


def _after_writer(code: str, open_at: int) -> str:
    return " , ".join(_split_top(call_argument_text(code, open_at, MAX_SCAN_CHARS))[1:])


def _is_writer_verb(name: str) -> bool:
    return not _WRITER_VERBS.isdisjoint(_lower_words(name))


def _converted_token_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}\s{{0,2}}\.\s{{0,2}}(?:{_CONVERSIONS})\s{{0,2}}\("


def _member_read_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}\s{{0,2}}{_ACCESS_OP}{_DETAIL_ACCESSOR}"


def _written_whole(param: str, args: str) -> bool:
    """The parameter itself, converted on its way out (`msg.encode()`), or read through its
    error-text member (`e.Error()`, `e.message`), whatever it is named: whether the base
    rule already reports the helper's own row is decided per row (`_row_reported`)."""
    if not param:
        return False
    masked = mask_literals(args)
    return _token_written(_templated(_whole_token_pattern, param), masked) or any(
        _templated(b, param).search(masked) for b in (_converted_token_pattern, _member_read_pattern))


def _token_written(token: re.Pattern[str], masked: str) -> bool:
    """A whole occurrence that is a value, not an entry's name (`{ name: ...`, `(name=...`)."""
    return any(not _names_an_entry(masked, m) for m in token.finditer(masked))


def _names_an_entry(masked: str, m: re.Match[str]) -> bool:
    return _ENTRY_NAME_TAIL.match(masked, m.end()) is not None and masked[: m.start()].rstrip()[-1:] in ("{", ",", "(")


def _assigned_call_pattern(name: str) -> str:
    return (rf"(?<![\w$.]){re.escape(name)}\s{{0,2}}(?::=|=(?![=>]))\s{{0,2}}(?:await\s{{1,4}})?"
            rf"([\w$.]{{1,80}})\s{{0,2}}\(")


def _nearest_assignment_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}\s{{0,2}}(?::=|=(?![=>]))\s{{0,2}}(?:await\s{{1,4}})?([\w$.]{{0,80}})"


def _word_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}\b"


def _validated_binding(lines: Sequence[str], lo: int, row: int, name: str, hop: int) -> bool:
    """``name`` is bound in rows [lo, row) from a validation-named or literal-errors-only callee."""
    pattern = _templated(_assigned_call_pattern, name)
    m = next(filter(None, (pattern.search(lines[r][:MAX_SCAN_CHARS]) for r in range(row - 1, lo - 1, -1))), None)
    return m is not None and _validating_callee(lines, m.group(1), hop)


def _validating_callee(lines: Sequence[str], callee: str, hop: int) -> bool:
    return _is_validation_callee(callee) or (
        hop < _HOPS and _literal_errors_only(lines, _last_segment(callee), hop + 1))


def _literal_errors_only(lines: Sequence[str], name: str, hop: int = 0) -> bool:
    """V: every error a same-file routine returns or throws is CONSTRUCTED from a literal
    message, or forwarded from a validation-named / literal-only callee: its text is the
    routine's own, client-facing wording."""
    seen = False
    for start in _def_rows(lines, name):
        verdict = _routine_errors_literal(lines, start, hop)
        if verdict is False:
            return False
        seen |= verdict is True
    return seen


def _routine_errors_literal(lines: Sequence[str], start: int, hop: int) -> bool | None:
    """False at the first raw, wrapped or forwarded error; else True once a literal-built or
    validated error was seen, None when the routine has none."""
    seen = None
    for r in range(start + 1, _routine_end(lines, start)):
        verdict = _exit_verdict(lines, start, r, hop)
        if verdict is False:
            return False
        seen = seen or verdict
    return seen


def _exit_verdict(lines: Sequence[str], start: int, r: int, hop: int) -> bool | None:
    """One row of `_literal_errors_only`: None (not an exit), True (a literal-built or
    validated error), False (a raw, wrapped or forwarded error)."""
    raw = lines[r][:MAX_SCAN_CHARS]
    code = stripped_code(raw)
    if not _EXIT_WORD.search(code):
        return None
    fwd = _FORWARDED.match(code)
    if fwd and fwd.group(1) not in _NOT_A_VALUE_NAME:
        return _validated_binding(lines, start, r, fwd.group(1), hop)
    return _built_verdict(raw, code)


def _built_verdict(raw: str, code: str) -> bool | None:
    if _RAW_ERROR_READ.search(code) and not _ERROR_CONSTRUCTOR.search(code):
        return False
    return _constructed_verdict(raw)


def _constructed_verdict(raw: str) -> bool | None:
    if not _ERROR_CONSTRUCTOR.search(raw):
        return None
    return not ("%w" in raw or _WRAPPED_CAUSE.search(raw))


def _excused(lines: Sequence[str], line_num: int, value: str) -> bool:
    """V: the value's error is bound from a VALIDATION-named callee (its text describes the
    peer's own input) or a literal-errors-only routine; T: the sink sits in a branch whose
    condition tests that value's CONTENT against a literal (an anticipated message)."""
    names = _excuse_names(value)
    return _validation_bound(lines, line_num, names) or _content_tested(lines, line_num, names)


def _excuse_names(value: str) -> set[str]:
    return {n for n in _value_tokens(value) | _chain_roots(value) if _excusable_name(n)}


def _value_tokens(value: str) -> set[str]:
    return {m.group(1) for m in _VALUE_TOKEN.finditer(_strip_literals_209(value))}


def _chain_roots(value: str) -> set[str]:
    return {c.split(".")[0] for c in _MEMBER_CHAIN_TEXT.findall(value)}


def _excusable_name(name: str) -> bool:
    return bool(name) and name not in _EXCUSE_SKIP


def _validation_bound(lines: Sequence[str], line_num: int, names: set[str]) -> bool:
    """The NEAREST binding of some name is a validation-named or literal-errors-only call."""
    pending = set(names)
    for r in range(line_num - 1, max(-1, line_num - 1 - _BINDING_RADIUS), -1):
        if _row_validates(lines, lines[r][:MAX_SCAN_CHARS], pending):
            return True
    return False


def _row_validates(lines: Sequence[str], raw: str, pending: set[str]) -> bool:
    """The row's bindings of the names still pending; a name's nearest binding decides it."""
    for n in _present(pending, raw):
        if _first_binding_validates(lines, raw, n, pending):
            return True
    return False


def _present(names: set[str], raw: str) -> list[str]:
    return [n for n in names if n in raw]


def _first_binding_validates(lines: Sequence[str], raw: str, n: str, pending: set[str]) -> bool:
    m = _templated(_nearest_assignment_pattern, n).search(raw)
    if m is None:
        return False
    pending.discard(n)
    return _validating_call(lines, raw, m)


def _validating_call(lines: Sequence[str], raw: str, m: re.Match[str]) -> bool:
    callee = m.group(1)
    if not callee or "(" not in raw[m.end(): m.end() + 3]:
        return False
    return _is_validation_callee(callee) or _literal_errors_only(lines, _last_segment(callee))


def _content_tested(lines: Sequence[str], line_num: int, names: set[str]) -> bool:
    innermost = next(_enclosing_blocks(lines, line_num - 1, _EXCUSE_SPAN), None)
    return innermost is not None and _tests_content(innermost[1], names)


def _tests_content(header: str, names: set[str]) -> bool:
    if not _is_content_branch(header):
        return False
    return any(_templated(_word_pattern, n).search(header) for n in names)


def _is_content_branch(header: str) -> bool:
    return header.lstrip().startswith(_BRANCH_HEADS) and _CONTENT_TEST.search(header) is not None \
        and _QUOTE.search(header) is not None


def _responder_param_pattern(name: str) -> str:
    return rf"[({{,]\s{{0,4}}{name}\s{{0,2}}[,:)}}]"


def _is_param_callback(lines: Sequence[str], line_num: int, name: str) -> bool:
    """``name`` is a parameter (or a destructured parameter) of an enclosing routine: the
    responder a framework hands the handler, not a same-file routine."""
    pattern = _templated(_responder_param_pattern, name)
    rows = range(line_num - 1, max(-1, line_num - 1 - _CALLBACK_SPAN), -1)
    return any(_declares_responder(lines[r][:MAX_SCAN_CHARS], name, pattern) for r in rows)


def _declares_responder(raw: str, name: str, pattern: re.Pattern[str]) -> bool:
    return name in raw and _is_header_line(raw) and pattern.search(stripped_code(raw)) is not None


class _BareCall(NamedTuple):
    name: str
    parts: list[str]
    first: str
    args: str
    scope: _Scope


def _bare_sink(lines: Sequence[str], line_num: int, line: str, suffix: str) -> str | None:
    """C1, C2 and H on one line: the arm that reports, or None. A same-file definition decides
    first (a sanitising helper is not a sink)."""
    code, masked = _uncomment(line)
    if routine_header(code) and _is_declaration(code, lines, line_num - 1):
        return None
    arms = (_bare_match_arm(lines, line_num, (code, masked), m, suffix)
            for m in _BARE_CALL.finditer(masked[:MAX_SCAN_CHARS]))
    return next(filter(None, arms), None)


def _bare_match_arm(lines: Sequence[str], line_num: int, texts: tuple[str, str], m: re.Match[str],
                    suffix: str) -> str | None:
    call = _bare_call(lines, line_num, texts, m, suffix)
    return _bare_call_reports(lines, line_num, call) if call else None


def _bare_call(lines: Sequence[str], line_num: int, texts: tuple[str, str], m: re.Match[str],
               suffix: str) -> _BareCall | None:
    code, masked = texts
    name = m.group(1)
    if not _judgeable_call(lines, name, masked[m.end(): m.end() + 24].lstrip()):
        return None
    args = _call_with_continuation(code[m.end() - 1:], lines, line_num, _uncommented_continuation)
    parts = _split_top(args)
    scope = _Scope(lines, line_num, code[: m.start()], suffix=suffix)
    return _bare_call_of(name, parts, args, scope) if len(parts) > 1 or name in _RESPONDERS else None


def _judgeable_call(lines: Sequence[str], name: str, head: str) -> bool:
    return name not in _SKIP_NAMES and _may_be_bare_sink(lines, name, head)


def _bare_call_of(name: str, parts: list[str], args: str, scope: _Scope) -> _BareCall:
    first = _RECEIVER_PREFIX.sub("", parts[0].strip() if parts else "").lstrip("&*")
    return _BareCall(name, parts, first, args, scope)


def _may_be_bare_sink(lines: Sequence[str], name: str, head: str) -> bool:
    """A responder, a call whose first argument has a peer role, or a same-file routine."""
    peer_first = _PEER_FIRST_ARG.match(head)
    return name in _RESPONDERS or bool(peer_first and peer_first.group(1) in _PEER_ARGS) or \
        name in _decl_index(_r3_file(lines))


def _bare_call_reports(lines: Sequence[str], line_num: int, call: _BareCall) -> str | None:
    written = _helper_writes(lines, call.name)
    if written is not None:
        return "H" if _helper_call_discloses(lines, line_num, call, written) else None
    return _responder_arm(lines, line_num, call)


def _responder_arm(lines: Sequence[str], line_num: int, call: _BareCall) -> str | None:
    if call.name in _RESPONDERS and _is_param_callback(lines, line_num, call.name):
        return "C2" if _responder_discloses(lines, line_num, call) else None
    return _response_helper_arm(lines, line_num, call)


def _response_helper_arm(lines: Sequence[str], line_num: int, call: _BareCall) -> str | None:
    if call.first in _PEER_ARGS and _is_response_helper(call.name):
        return "C1" if _response_helper_discloses(lines, line_num, call) else None
    return None


def _helper_call_discloses(lines: Sequence[str], line_num: int, call: _BareCall, written: set[int]) -> bool:
    return any(i < len(call.parts) and _value_discloses(call.parts[i], call.scope)
               and not _excused(lines, line_num, call.parts[i]) for i in sorted(written))


def _responder_discloses(lines: Sequence[str], line_num: int, call: _BareCall) -> bool:
    return any(_value_discloses(x, call.scope) for x in call.parts) and not _excused(lines, line_num, call.args)


def _response_helper_discloses(lines: Sequence[str], line_num: int, call: _BareCall) -> bool:
    """C1 is judged by its name, so X2 (a cross-file producer) never feeds it."""
    rest = " , ".join(call.parts[1:])
    ctx = _active_scan()
    ctx.x2_off = True
    try:
        hit = _value_discloses(rest, call.scope)
    finally:
        ctx.x2_off = False
    return hit and not _excused(lines, line_num, rest)


def _value_discloses(value: str, scope: _Scope) -> bool:
    return _args_disclose(_strip_literals_209(value), scope)


# ---- arm W: an object or collection filled from an error, then sent whole ----

def _routine_extent(lines: Sequence[str], row: int) -> tuple[int, int, int | None]:
    header = _header_row(lines, row, _ROUTINE_SPAN)
    if header is None:
        return max(0, row - _ROUTINE_SPAN), min(len(lines), row + _ROUTINE_SPAN), None
    return header, _routine_end(lines, header), header


def _reaches_peer_whole(lines: Sequence[str], name: str, row: int, hops: int = 0) -> bool:
    """``name`` is written WHOLE to a peer later in its routine (a member-call sink, or a C1/H
    bare call), or through a same-file caller that passes the object (W-helper, <= 2 hops)."""
    key = ("reach", name, row, hops)
    return _memo(_r3_file(lines), key, lambda: _reaches_uncached(lines, name, row, hops))


def _reaches_uncached(lines: Sequence[str], name: str, row: int, hops: int) -> bool:
    _, hi, header = _routine_extent(lines, row)
    if _sends_whole_below(lines, name, row, hi):
        return True
    return header is not None and hops < _HOPS and _caller_sends_whole(lines, name, header, hops)


def _sends_whole_below(lines: Sequence[str], name: str, row: int, hi: int) -> bool:
    token = _templated(_whole_token_pattern, name)
    return any(_row_sends_whole(lines, r, name, token) for r in range(row + 1, hi))


def _row_sends_whole(lines: Sequence[str], r: int, name: str, token: re.Pattern[str]) -> bool:
    raw = lines[r][:MAX_SCAN_CHARS]
    if name not in raw and not _RESPONSE_WRITE.search(raw):
        return False
    return _sink_sends(lines, r, raw, token) or _bare_sends(lines, raw, token)


def _sink_sends(lines: Sequence[str], r: int, raw: str, token: re.Pattern[str]) -> bool:
    return any(token.search(a) for a in _peer_write_arguments(lines, r, raw))


def _bare_sends(lines: Sequence[str], raw: str, token: re.Pattern[str]) -> bool:
    code, masked = _uncomment(raw)
    return any(_bare_call_sends(lines, code, m, token) for m in _BARE_CALL.finditer(masked))


def _bare_call_sends(lines: Sequence[str], code: str, m: re.Match[str], token: re.Pattern[str]) -> bool:
    parts = _split_top(call_argument_text(code, m.end() - 1, MAX_SCAN_CHARS))
    return _passes_token(parts, token) and (
        _is_response_helper(m.group(1)) or bool(_helper_writes(lines, m.group(1))))


def _passes_token(parts: list[str], token: re.Pattern[str]) -> bool:
    """A peer first argument, and the object as a later argument."""
    return len(parts) > 1 and parts[0].strip() in _PEER_ARGS and any(token.search(p) for p in parts[1:])


def _caller_sends_whole(lines: Sequence[str], name: str, header: int, hops: int) -> bool:
    bare = name.lstrip("$")
    routine, params, named = _param_list_of(_header_text(lines, header), bare)
    if not named or bare not in params:
        return False
    at = (params.index(bare), name)
    return any(_passed_object_sends(lines, site, at, hops) for site in _call_sites(lines, routine))


def _passed_object_sends(lines: Sequence[str], site: tuple, at: tuple[int, str], hops: int) -> bool:
    """A caller passes a plain name at the object's position, and that object reaches a peer."""
    crow, _, args = site
    idx, name = at
    arg = (_pick_argument(args, idx, name) or "").strip().lstrip("&*")
    return _NAME_RE.fullmatch(arg) is not None and _reaches_peer_whole(lines, arg, crow, hops + 1)


def _member_write(lines: Sequence[str], line_num: int, line: str, suffix: str) -> str | None:
    """W: the object written from an error on this line (`X.F = v`, `X[k] = v`, `X.setF(v)`,
    `X.push(v)`) when it then reaches a peer whole; None otherwise."""
    code = _mask_log_calls(line)
    return _reaching_write(lines, line_num, code, suffix) if _write_spelled(lines, line_num, code) else None


def _write_spelled(lines: Sequence[str], line_num: int, code: str) -> bool:
    """A write form is spelled in the code and an error marker is within reach. The raw tests
    come first: each is a superset of its stripped form."""
    if not _INSERT_WRITE.search(code) and not _assignment_marked(code):
        return False
    stripped = stripped_code(code)
    insert = _INSERT_WRITE.search(stripped) is not None
    return _spells_write(stripped, insert) and _write_marked(lines, line_num, code, insert)


def _assignment_marked(code: str) -> bool:
    return ("=" in code or "set" in code) and _MARKER.search(code.lower()) is not None


def _spells_write(stripped: str, insert: bool) -> bool:
    return insert or "=" in stripped or "set" in stripped


def _write_marked(lines: Sequence[str], line_num: int, code: str, insert: bool) -> bool:
    """An error marker on the line, or (an insert, whose value may continue) on what follows."""
    reach = code + " " + _continuation(lines, line_num) if insert else code
    return _MARKER.search(reach.lower()) is not None


def _reaching_write(lines: Sequence[str], line_num: int, code: str, suffix: str) -> str | None:
    for m in _write_matches(mask_literals(code[:MAX_SCAN_CHARS])):
        if _write_reaches(lines, line_num, (code, suffix), m):
            return m.group(1)
    return None


def _write_matches(masked: str):
    for pattern in (_MEMBER_WRITE, _SETTER_WRITE, _INSERT_WRITE):
        yield from pattern.finditer(masked)


def _continuation(lines: Sequence[str], line_num: int) -> str:
    return " ".join(x[:MAX_SCAN_CHARS] for x in lines[line_num: line_num + _CONTINUATION_LINES])


def _write_reaches(lines: Sequence[str], line_num: int, texts: tuple[str, str], m: re.Match[str]) -> bool:
    target = m.group(1)
    if not _write_target(target) or _in_log_call(lines, line_num - 1, m.start()):
        return False
    return _written_from_error(lines, line_num, texts, m) and _reaches_peer_whole(lines, target, line_num - 1)


def _written_from_error(lines: Sequence[str], line_num: int, texts: tuple[str, str], m: re.Match[str]) -> bool:
    code, suffix = texts
    value = _written_value(code, lines, line_num, m)
    return bool(value.strip()) and _value_discloses(value, _Scope(lines, line_num, code[: m.start()], suffix=suffix))


def _write_target(name: str) -> bool:
    """Not instance state (`this`, `self`) and not an object in a non-peer role (metrics, logs)."""
    return name not in ("this", "self", "$this") and not set(identifier_words(name.lstrip("$"))) & _NONPEER_WORDS


def _written_value(code: str, lines: Sequence[str], line_num: int, m: re.Match[str]) -> str:
    if m.re is _MEMBER_WRITE:
        rest = code[m.end():]
        return rest[: len(_top_level_cut(mask_literals(rest)))]
    return _call_with_continuation(code[m.end() - 1:], lines, line_num, _continuation)


def _call_with_continuation(tail: str, lines: Sequence[str], line_num: int,
                            continuation: Callable[[Sequence[str], int], str]) -> str:
    """`call_argument_text` of the call opening at ``tail[0]``, read on into the following
    lines only when it does not close on its own line: a call that closes (with no open
    quote that a later line could close) cannot be changed by what follows."""
    args = call_argument_text(tail, 0, MAX_SCAN_CHARS)
    if len(args) < min(len(tail), MAX_SCAN_CHARS + 1) - 1 and not _open_quote(tail):
        return args
    return call_argument_text(tail + " " + continuation(lines, line_num), 0, MAX_SCAN_CHARS)


def _open_quote(text: str) -> bool:
    return any(text.count(q) % 2 for q in "\"'`")


def _uncommented_continuation(lines: Sequence[str], line_num: int) -> str:
    return " ".join(_uncommented(x[:MAX_SCAN_CHARS]) for x in lines[line_num: line_num + _CONTINUATION_LINES])


# ---- arm S: the error event of an asynchronously iterated stream ----

def _enclosing_blocks(lines: Sequence[str], row: int, limit: int = _ENCLOSING_SPAN):
    """(row, text, case labels met at that level) of each block header enclosing ``row``,
    innermost first, produced lazily (a caller stops at the header it needs): bracket depth
    in a brace language, indentation otherwise."""
    rf = _r3_file(lines)
    rows = range(row - 1, max(-1, row - limit), -1)
    return _brace_blocks(rf, rows) if _braces_near(rf, row) else _indent_blocks(lines, row, rows)


def _braces_near(rf: _R3File, row: int) -> bool:
    """A `{` outside literals within the 40 rows above ``row`` (and on it): a brace language."""
    counts = _r3_brace_counts(rf)
    return counts[row + 1] > counts[max(0, row - 40)]


def _r3_brace_counts(rf: _R3File) -> list[int]:
    """Running count of rows whose literal-masked text holds a `{` (memoised per file)."""
    counts = rf.memo.get(("braces",))
    if counts is None:
        counts = rf.memo[("braces",)] = [0, *accumulate("{" in mask_literals(x[:MAX_SCAN_CHARS]) for x in rf.lines)]
    return counts


def _brace_blocks(rf: _R3File, rows: range):
    depth, labels = 0, []
    for r in rows:
        raw = rf.lines[r][:MAX_SCAN_CHARS]
        depth += _row_balance(rf, r)
        if depth < 0:
            yield r, raw, tuple(labels)
            labels, depth = [], 0
        else:
            labels.extend(_label_at_level(raw, depth))


def _label_at_level(raw: str, depth: int) -> tuple[str, ...]:
    """A case label met at the block's own level (depth 0)."""
    return (raw,) if depth == 0 and _CASE_LABEL.match(raw) else ()


def _row_balance(rf: _R3File, r: int) -> int:
    """Closers minus openers on row ``r`` (reading upwards, an unclosed opener makes the depth
    negative), memoised per row."""
    balance = rf.balance.get(r)
    if balance is None:
        code = mask_literals(stripped_code(rf.lines[r][:MAX_SCAN_CHARS]))
        balance = rf.balance[r] = sum(-_DEPTH_DELTA[m.group()] for m in _BRACKET.finditer(code))
    return balance


def _indent_blocks(lines: Sequence[str], row: int, rows: range):
    ind = indent_width(lines[row])
    for r in rows:
        raw = lines[r][:MAX_SCAN_CHARS]
        if raw.strip() and indent_width(raw) < ind:
            yield r, raw, ()
            ind = indent_width(raw)


def _error_literal(text: str) -> bool:
    return any(w.lower() in _ERROR_EVENT_WORDS for lit in _QUOTED_WORD.findall(text) for w in identifier_words(lit))


def _member_of_pattern(x: str) -> str:
    return rf"(?<![\w$.]){x}\s{{0,2}}(?:\?\.|\.)\s{{0,2}}([A-Za-z_$][\w$]{{0,63}})"


def _compared_member_pattern(x: str) -> str:
    return rf"(?<![\w$.]){x}\s{{0,2}}(?:\?\.|\.)\s{{0,2}}\w+\s{{0,2}}(?:===?|==|\bis\b)"


def _switch_on_pattern(x: str) -> str:
    return rf"\b(?:switch|when|match)\s{{0,2}}\(?\s{{0,2}}{x}\s{{0,2}}(?:\?\.|\.)"


def _stream_event(lines: Sequence[str], line_num: int, line: str, suffix: str) -> bool:
    """S: the sink writes X.F (F error-named), X is bound by an asynchronous iteration header
    enclosing the sink, and an enclosing branch discriminates X as an error event."""
    args = _peer_sink_args(lines, line_num, _uncomment(line), suffix)
    if args is None or not _writes_error_member(args):
        return False          # no error-named member is written: nothing for S to decide
    return _iterated_error_event(lines, line_num, args)


def _peer_sink_args(lines: Sequence[str], line_num: int, texts: tuple[str, str], suffix: str) -> str | None:
    code, masked = texts
    spans = _sink_spans(masked)
    if not spans or not _sink_is_peer(code, spans[0][0].start(), spans[0][0].end()):
        return None
    return _span_arguments(_LineCtx(lines, line_num, code, suffix, masked), spans[0][0].end(), spans[0][1])


def _writes_error_member(args: str) -> bool:
    return any(_error_field(f, detail_ok=False) for f in _MEMBER_NAME.findall(args))


def _iterated_error_event(lines: Sequence[str], line_num: int, args: str) -> bool:
    """The innermost enclosing asynchronous iteration, discriminated by the blocks inside it."""
    inner: list = []
    for block in _enclosing_blocks(lines, line_num - 1):
        m = _ASYNC_ITERATION.search(block[1])
        if m:
            return _discriminated(lines, line_num, inner, m, args)
        inner.append(block)
    return False


def _discriminated(lines: Sequence[str], line_num: int, inner: list, m: re.Match[str], args: str) -> bool:
    """The blocks inside the iteration (``inner``, innermost first) discriminate its variable."""
    x = re.escape(_iteration_variable(m))
    if not _writes_member_of(x, args):
        return False
    return any(_branch_is_error_event(lines, line_num, inner, j, x) for j in range(len(inner)))


def _iteration_variable(m: re.Match[str]) -> str:
    return m.group(1) or m.group(2) or m.group(3)


def _writes_member_of(x: str, args: str) -> bool:
    return any(_error_field(f, detail_ok=False) for f in _templated(_member_of_pattern, x).findall(args))


def _branch_is_error_event(lines: Sequence[str], line_num: int, inner: list, j: int, x: str) -> bool:
    """`X.type === 'error'`, or a `switch (X.type)` whose label above the sink is an error literal."""
    raw2 = inner[j][1]
    return _compares_to_error(x, raw2) or _switch_label_is_error(lines, line_num, inner, j, x)


def _compares_to_error(x: str, raw2: str) -> bool:
    return _templated(_compared_member_pattern, x).search(raw2) is not None and _error_literal(raw2)


def _switch_label_is_error(lines: Sequence[str], line_num: int, inner: list, j: int, x: str) -> bool:
    r2, raw2, _ = inner[j]
    if not _templated(_switch_on_pattern, x).search(raw2):
        return False
    labels = _labels_below(lines, line_num, inner, j, r2)
    return bool(labels) and _error_literal(labels[0])


def _labels_below(lines: Sequence[str], line_num: int, inner: list, j: int, header_row: int) -> tuple:
    """The case label governing the sink: on its own line, else the nearest at the switch body's level."""
    own = lines[line_num - 1][:MAX_SCAN_CHARS]
    if _OWN_CASE_LABEL.match(own):
        return (own,)
    return inner[j - 1][2] if j else _labels_between(lines, line_num - 1, header_row)


def _labels_between(lines: Sequence[str], row: int, header_row: int) -> tuple:
    for r in range(row - 1, header_row, -1):
        raw = lines[r][:MAX_SCAN_CHARS]
        if _CASE_LABEL.match(raw):
            return (raw,)
    return ()


# ---- which arms can fire in a file ----

def _file_facts(lines: Sequence[str]) -> _ArmFacts:
    """Per-file prefilters, built once from the joined text: which arms can fire at all."""
    rf = _r3_file(lines)
    if rf.facts is None:
        rf.facts = _file_facts_uncached(rf)
    return rf.facts


def _file_facts_uncached(rf: _R3File) -> _ArmFacts:
    text = _file_text(rf)[0]
    has_sink = _RESPONSE_WRITE.search(text) is not None
    peer_first = _PEER_FIRST_CALL.search(text) is not None
    return _ArmFacts(has_sink or peer_first, _bare_pattern(text, has_sink, peer_first), _streams(text, has_sink),
                     _keyed(text), _bare_names(rf) if has_sink else frozenset())


def _bare_pattern(text: str, has_sink: bool, peer_first: bool) -> re.Pattern[str] | None:
    return _PEER_OR_RESPONDER if has_sink or peer_first or _calls_responder(text) else None


def _calls_responder(text: str) -> bool:
    return ("respond" in text or "reply" in text) and _RESPONDER_CALL.search(text) is not None


def _streams(text: str, has_sink: bool) -> bool:
    return has_sink and ("for await" in text or "async for" in text or "await foreach" in text)


def _keyed(text: str) -> bool:
    return _DETAIL_KEY_HINT.search(text) is not None and _CODE_KEY_HINT.search(text) is not None


def _arm_rows(lines: Sequence[str], suffix: str) -> frozenset[int]:
    """Rows where W, C1/C2/H or S can fire (a superset; each arm still decides on its line):
    W within reach of an error marker, a bare-call prefilter match, a sink in a streaming file."""
    rf = _r3_file(lines)
    if rf.arm_rows is None:
        rf.arm_rows = frozenset(_arm_row_set(rf, _file_facts(lines), suffix))
    return rf.arm_rows


def _arm_row_set(rf: _R3File, facts: _ArmFacts, suffix: str) -> set[int]:
    text, ends = _file_text(rf)
    rows = _write_rows(rf.lines, suffix, text, ends) if facts.w else set()
    rows |= _bare_rows(rf, facts, text, ends) if facts.bare is not None else set()
    return rows | (_touched_rows(_RESPONSE_WRITE, text, ends) if facts.async_iter else set())


def _write_rows(lines: Sequence[str], suffix: str, text: str, ends: list[int]) -> set[int]:
    """Rows `_member_write` can act on (a write form is spelled: `=`, `set`, an insert) that
    have an error marker within reach."""
    spelled = _spelled_rows(lines) | _touched_rows(_INSERT_HINT, text, ends)
    return _marked_window_rows(lines, suffix, spelled) if spelled else set()


def _spelled_rows(lines: Sequence[str]) -> set[int]:
    return {i for i, x in enumerate(lines) if "=" in x or "set" in x}


def _marked_window_rows(lines: Sequence[str], suffix: str, rows: set[int]) -> set[int]:
    """Those of ``rows`` with an error marker in [r, r + 13): the reach `_write_arm` asks of `marked`."""
    state = _file_state(lines, suffix)
    size = len(lines)
    state.marked(0, size)
    marks, reach = state.marks, _CONTINUATION_LINES + 1
    return {r for r in rows if marks[min(r + reach, size)] > marks[r]}


def _touched_rows(pattern: re.Pattern[str], text: str, ends: list[int]) -> set[int]:
    """Every row a match of ``pattern`` in the joined text touches."""
    return {r for m in pattern.finditer(text)
            for r in range(bisect_right(ends, m.start()), bisect_right(ends, max(m.start(), m.end() - 1)) + 1)}


def _bare_names(rf: _R3File) -> frozenset[str]:
    """Where the file writes to a peer: its own routines' names (the first _INDEX_NAMES, sorted)."""
    return frozenset(sorted(n for n in _decl_index(rf) if len(n) > 1)[:_INDEX_NAMES])


def _bare_rows(rf: _R3File, facts: _ArmFacts, text: str, ends: list[int]) -> set[int]:
    """Rows a peer-first or responder call touches, and rows calling one of ``facts.names``."""
    calls = _call_index(rf) if facts.names else {}
    named = {r for n in facts.names for r in calls.get(n, ())}
    return named | _touched_rows(_PEER_OR_RESPONDER_HINT, text, ends)


def _bare_line(facts: _ArmFacts, line: str) -> bool:
    """The line holds a peer-first call, a responder call, or a call of one of the file's
    own routines (each a bare call `_bare_sink` can judge)."""
    text = line[:MAX_SCAN_CHARS]
    if facts.bare.search(text):
        return True
    return bool(facts.names) and any(m.group(1) in facts.names for m in _CALLED_NAME.finditer(text))


# ---- arms X / X2: a name followed to its only definition in the scanned tree ----

def _index_declarations(ctx: _ScanCtx, path: str, lines: Sequence[str]) -> None:
    """Add the routine names ``lines`` declares to the scan's tree index (from the lines the
    walk already holds: never a second disk walk)."""
    ctx.indexed.add(path)
    for name in _tree_names(lines):
        ctx.defs[name].append(path)


def _tree_names(lines: Sequence[str]) -> set[str]:
    names: set = set()
    for raw in lines:
        names.update(_tree_row_names(raw))
    return names - _SKIP_NAMES - {None}


def _tree_row_names(raw: str):
    if "(" not in raw or len(raw) > MAX_SCAN_CHARS or not _could_declare(raw):
        return ()
    return map(_decl_match_name, _DECL_NAME.finditer(raw))


def _defer_current(ctx: _ScanCtx) -> None:
    """A tree-index question while the index is incomplete: judge this file again after the walk."""
    if ctx.file_path is not None:
        ctx.deferred.setdefault(ctx.path, (ctx.file_path, ctx.lines))


def _only_definition_file(name: str) -> Sequence[str] | None:
    """The lines of the only scanned file declaring ``name``; None when there are none or
    several, or (deferred) while the walk is still building the index."""
    ctx = _active_scan()
    paths = ctx.defs.get(name, ())
    if len(paths) > 1:
        return None
    if not ctx.complete:
        _defer_current(ctx)
        return None
    return _other_lines(ctx, paths[0]) if paths else None


def _other_lines(ctx: _ScanCtx, path: str) -> tuple[str, ...]:
    """Another file's lines, read once per scan (at most _OTHER_FILES kept)."""
    lines = ctx.other.get(path)
    if lines is None:
        while len(ctx.other) >= _OTHER_FILES:
            ctx.other.pop(next(iter(ctx.other)))
        lines = ctx.other[path] = _read_other(path)
    return lines


def _read_other(path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(path).read_text(errors="replace").splitlines())
    except OSError:
        return ()


def _definition_of(lines: Sequence[str], name: str) -> tuple[Sequence[str] | None, list[int]]:
    """``name``'s definition: in the same file first, else its only definition in the tree."""
    rows = _def_rows(lines, name)
    if rows:
        return lines, rows
    other = _only_definition_file(name)
    rows = _def_rows(other, name) if other is not None else []
    return (other, rows) if len(rows) == 1 else (None, [])


def _renders_through_definition(callee: str, inner: str, scope: _Scope) -> bool:
    """X: an opaque projection-named call whose arguments carry an error discloses when the
    callee's definition renders its parameter's detail."""
    if _active_scan().x_guard or _PROJECTION_WORDS.isdisjoint(_callee_words(callee)):
        return False
    return _carries_error(inner, scope) and _renders_param(scope.lines, _last_segment(callee))


def _renders_param(lines: Sequence[str], name: str) -> bool:
    return bool(_memo(_r3_file(lines), ("render", name), lambda: _renders_param_uncached(lines, name)))


def _renders_param_uncached(lines: Sequence[str], name: str) -> bool:
    src, rows = _definition_of(lines, name)
    if src is None:
        return False
    ctx = _active_scan()
    ctx.x_guard += 1
    try:
        return any(_definition_renders(src, s, _routine_end(src, s)) for s in rows)
    finally:
        ctx.x_guard -= 1


def _definition_renders(lines: Sequence[str], start: int, end: int) -> bool:
    """The routine reads a parameter's detail (a detail member or a stringifier of it, outside
    a log call) and returns something other than literals or `Type.CONST`."""
    params = _routine_params(_header_text(lines, start))
    if not params:
        return False
    codes = _routine_codes(lines, start, end)
    return any(map(_returns_non_literal, codes)) and _reads_any_detail(lines, start, codes, params)


def _routine_codes(lines: Sequence[str], start: int, end: int) -> list[str]:
    return [_mask_log_calls(_uncomment(lines[r][:MAX_SCAN_CHARS])[0]) for r in range(start, end)]


def _reads_any_detail(lines: Sequence[str], start: int, codes: list[str], params: list[str]) -> bool:
    return any(_reads_detail(lines, start + i, code, params) for i, code in enumerate(codes))


def _routine_params(header: str) -> list[str]:
    m = _PAREN.search(header)
    if not m:
        return []
    return [p for p in _list_params(header, m.start()) if _real_param(p)]


def _real_param(name: str) -> bool:
    return bool(name) and name not in ("self", "cls", "this")


def _returns_non_literal(code: str) -> bool:
    return _RETURN_WORD.search(mask_literals(code)) is not None and not _LITERAL_RETURN.match(stripped_code(code))


def _param_as_error_pattern(name: str) -> str:
    return rf"(?<![\w$.]){re.escape(name)}(?![\w$])"


def _reads_detail(lines: Sequence[str], r: int, code: str, params: list[str]) -> bool:
    return any(_param_detail_read(lines, r, code, p) for p in params if p in code)


def _param_detail_read(lines: Sequence[str], r: int, code: str, param: str) -> bool:
    """The row read with ``param`` as an error discloses (a detail member, or a stringifier)."""
    text = _templated(_param_as_error_pattern, param).sub("err", _strip_literals_209(code))
    scope = _Scope(lines, r + 1, "", 0, "")
    return _detail_reaches(text, scope) or _neutralise_calls(text, scope) is None


# ---- the line check, the emitted set and the deferred files ----

def _begin_line(ctx: _ScanCtx, file_path: Path, lines: Sequence[str], findings: list[dict]) -> None:
    if _file_changed(ctx, file_path, lines):
        _begin_file(ctx, file_path, lines)
    if ctx.owner is not findings:     # a detached caller's next run: its rows start afresh
        ctx.emitted, ctx.owner = set(), findings
    ctx.findings = findings
    ctx.active = True


def _file_changed(ctx: _ScanCtx, file_path: Path, lines: Sequence[str]) -> bool:
    return ctx.lines is not lines or (ctx.file_path is not file_path and ctx.file_path != file_path)


def _begin_file(ctx: _ScanCtx, file_path: Path, lines: Sequence[str]) -> None:
    ctx.path, ctx.file_path, ctx.lines = str(file_path), file_path, lines
    ctx.prose, ctx.suffix = _is_prose(file_path), _suffix(file_path)
    if not ctx.complete and ctx.path not in ctx.indexed:
        _index_declarations(ctx, ctx.path, lines)


def _emit_209(line_num: int) -> None:
    """One CWE-209 row for ``line_num`` of the file being judged, once."""
    ctx = _active_scan()
    key = (ctx.path, line_num)
    if not ctx.active or key in ctx.emitted:
        return
    ctx.emitted.add(key)
    _add_disclosure(
        ctx.file_path, line_num, ctx.lines, ctx.findings,
        title="Error message information disclosure",
        description=f"Stack trace or error details exposed at line {line_num}",
        recommendation="Return generic error messages; log detailed errors server-side only",
    )


def _arm_reports(ctx: _ScanCtx, line: str, line_num: int) -> bool:
    """W, then C1/C2/H, then S, on a line the base rule leaves clean."""
    if ctx.prose or line_num - 1 not in _arm_rows(ctx.lines, ctx.suffix):
        return False
    return _arms_report(_file_facts(ctx.lines), ctx.lines, line_num, line, ctx.suffix)


def _arms_report(facts: _ArmFacts, lines: Sequence[str], line_num: int, line: str, suffix: str) -> bool:
    return _write_arm(facts, lines, line_num, line, suffix) or _bare_arm(facts, lines, line_num, line, suffix) \
        or (facts.async_iter and _stream_event(lines, line_num, line, suffix))


def _write_arm(facts: _ArmFacts, lines: Sequence[str], line_num: int, line: str, suffix: str) -> bool:
    if not facts.w or not _file_state(lines, suffix).marked(line_num - 1, line_num + _CONTINUATION_LINES):
        return False
    return _member_write(lines, line_num, line, suffix) is not None


def _bare_arm(facts: _ArmFacts, lines: Sequence[str], line_num: int, line: str, suffix: str) -> bool:
    if facts.bare is None or "(" not in line or not _bare_line(facts, line):
        return False
    return _bare_sink(lines, line_num, line, suffix) is not None


def _judge_deferred(findings: list[dict]) -> None:
    """After the walk: the index is complete, so each file that asked it a question is
    judged again from scratch (only rows not already emitted are added)."""
    ctx = _active_scan()
    ctx.complete = True
    for file_path, lines in list(ctx.deferred.values()):
        _drop_file(lines)
        for line_num, code in _value_lines(file_path, lines):
            _check_error_value_in_response(file_path, code, line_num, lines, findings)


def _value_lines(file_path: Path, lines: Sequence[str]):
    """(line_num, code) of each line `_check_error_disclosure` hands to the value check."""
    for line_num, line in enumerate(lines, start=1):
        code = _value_line(file_path, line)
        if code is not None:
            yield line_num, code


def _value_line(file_path: Path, line: str) -> str | None:
    if _skipped_line(line):
        return None
    code = _mask_log_calls(line)
    return None if _may_be_server_error(code) and not _is_prose(file_path) else code


def _skipped_line(line: str) -> bool:
    """A line `_analyze_file` skips, or one the middleware check answers instead."""
    return _not_code_line(line) or ("use" in line and LEAKY_ERROR_MIDDLEWARE.search(line) is not None)


def _not_code_line(line: str) -> bool:
    return bool(COMMENT_INDICATORS.match(line) or IMPORT_LINE.match(line) or SCANNER_DEF_LINE.search(line))


def _walk_code_files(source_path: str, findings: list[dict], suppression_counts: dict[int, int]) -> None:
    roots = served_roots(source_path)
    for file_path in scan_code_files(source_path):
        if not (is_generated_file(file_path) or is_test_file(file_path)):
            _analyze_file(file_path, findings, suppression_counts, roots)


# END OF THE CWE-209 REVISION 3 SECTION
# ---------------------------------------------------------------------------


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
