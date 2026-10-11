"""Information exposure vulnerability detection skill."""

import re
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._args import mask_literals
from cwe_agent.skills._lexical import (
    MAX_SCAN_CHARS,
    call_argument_text,
    catch_binding,
    identifier_words,
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
    """Report error detail reaching the peer (CWE-209)."""
    if not _discloses_error(file_path, line, line_num, lines):
        return
    _add_disclosure(
        file_path, line_num, lines, findings,
        title="Error message information disclosure",
        description=f"Stack trace or error details exposed at line {line_num}",
        recommendation="Return generic error messages; log detailed errors server-side only",
    )


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
_FILE_STATES: dict[tuple, "_FileState"] = {}
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
    return bool(root) and _names_a_type(root) and not set(identifier_words(root)) & _PEER_ROOT_WORDS


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
    return _OPAQUE if _is_opaque_call(callee, last, inner) else f" {inner} "


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
    return _EXACT_ERROR_NAME.fullmatch(ident) is not None


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
    verdict = _resolve_bound(ident, scope)   # only reached once `may_bind(ident)` held
    if verdict == "unknown":
        return bool(_EXACT_ERROR_NAME.fullmatch(ident))
    return verdict not in _UNTAINTED


def _resolve(ident: str, scope: _Scope) -> str:
    """Where ``ident`` came from, nearest first: caught / tainted / clean / unknown.

    Memoised per (sink line, prefix, identifier, depth) in the file's own state,
    so the sinks of one routine share their window and the memo goes with the file.
    """
    return _resolve_with(ident, scope, _binder(scope))


def _resolve_with(ident: str, scope: _Scope, may_bind: Callable[[str], bool]) -> str:
    """`_resolve`, given ``may_bind = _binder(scope)`` already built for the text."""
    if not may_bind(ident):
        return "unknown"   # nothing in reach binds it: no walk, no memo entry
    return _resolve_bound(ident, scope)


def _resolve_bound(ident: str, scope: _Scope) -> str:
    """`_resolve` for a name some row in reach (or the prefix) binds."""
    state = _file_state(scope.lines, scope.suffix)
    key = (scope.line_num, scope.prefix, ident, scope.depth)
    verdict = state.memo.get(key)
    if verdict is None:
        if len(state.memo) >= _MEMO_LIMIT:
            state.memo.clear()
        verdict = state.memo[key] = _walk_window(ident, scope)
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
    key = (row, ident, scope.depth)
    if key not in state.rows:
        state.rows[key] = _line_binding(state.lines[row], ident, scope, row + 1)
    return state.rows[key]


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
    key = (id(lines), suffix)
    state = _FILE_STATES.get(key)
    if state is None or state.lines is not lines:
        state = _new_state(key, lines, suffix)
    return state


def _new_state(key: tuple, lines: Sequence[str], suffix: str) -> _FileState:
    """Oldest file out first: a long scan never keeps an early file alive."""
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
    names = m.group(1).split(":")[0]
    return frozenset(_NAMES.findall(names)), m.group(2) + ("(" if m.group(3) else "")


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
