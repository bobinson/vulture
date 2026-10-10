"""LLM error classification and retry logic.

Based on production experience with error classification patterns. Categorizes LLM failures
into actionable types so callers can decide whether to retry, fall back, or abort.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import random
import re
import time
import unicodedata
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

from shared.llm.jsonscan import first_json_object

logger = logging.getLogger(__name__)


class LLMErrorKind(Enum):
    """Categorized LLM failure reasons."""
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    CONTEXT_OVERFLOW = "context_overflow"
    TIMEOUT = "timeout"
    SERVER_ERROR = "server_error"
    INVALID_RESPONSE = "invalid_response"
    CONNECTION_ERROR = "connection_error"
    # §32.1 #6: a PERMANENT provider/config fault surfaced by the broker
    # (provider_bad_request / provider_auth_error / model_not_found, or an
    # explicit x_retriable:false). Never retried — a retry fails identically.
    PROVIDER_BAD_REQUEST = "provider_bad_request"
    UNKNOWN = "unknown"


# Errors worth retrying (transient failures).
RETRYABLE_KINDS = frozenset({
    LLMErrorKind.RATE_LIMITED,
    LLMErrorKind.TIMEOUT,
    LLMErrorKind.SERVER_ERROR,
    LLMErrorKind.CONNECTION_ERROR,
})

_RATE_LIMIT_RE = re.compile(
    r"(rate.?limit|429|too many requests|quota|resource.exhausted|throttl)",
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"(401|403|unauthorized|forbidden|invalid.?api.?key|invalid.?token|"
    r"authentication.failed|access.denied|no.credentials)",
    re.IGNORECASE,
)
# Size/overflow PHRASING only (feature 0074 re-audit R6), the broker's
# contextOverflowBody (backend/internal/broker/provider/upstream_detail.go)
# restated; both are pinned by ONE message fixture,
# backend/internal/broker/provider/testdata/ctx_overflow_messages_0074.json, so
# a raw provider error and a broker-mediated one classify alike. A message that
# merely names a size-related parameter (`max_tokens`, `context_size`, a
# field's maximum length) is a different fault: calling it an overflow cost a
# pointless halve-and-retry. `request_too_large` is the provider's error CODE;
# LiteLLM surfaces the human MESSAGE instead — "OpenAIException - request body
# too large" — so both forms are listed (`.` spans the separator).
# Two phrasings beyond the broker's, both still size/overflow wording, pinned
# by the pre-existing classifier tests: "maximum context window is N" and
# "max tokens / maximum length exceeded".
_CTX_OVERFLOW_RE = re.compile(
    r"(context.length.exceeded|maximum.context.(?:length|window)|"
    r"max(?:imum)?.(?:tokens|length).exceeded|"
    r"context.(?:window|limit|size|length).(?:exceeded|overflow)|"
    r"exceeds?.(?:the.)?(?:available.|maximum.)?(?:context|token).(?:length|window|size|limit)|"
    r"(?:greater|longer|larger).than.the.(?:maximum.)?context.(?:length|window|size)|"
    r"token.limit.(?:exceeded|reached)|n_keep.*n_ctx|prompt.{0,10}too.long|too.large.for.model|"
    r"input.token.count.*exceeds|exceeds.the.maximum.number.of.tokens|"
    r"request.payload.size.exceeds|payload.too.large|"
    r"request_too_large|request.body.too.large|provider_context_overflow)",
    re.IGNORECASE,
)
_TIMEOUT_RE = re.compile(
    r"(timeout|timed.out|deadline.exceeded|ETIMEDOUT|ECONNRESET)",
    re.IGNORECASE,
)
_SERVER_RE = re.compile(r"(500|502|503|504|529|internal.server.error|bad.gateway|overloaded)", re.IGNORECASE)
_CONN_RE = re.compile(r"(connect|dns|resolve|refused|unreachable|ECONNREFUSED)", re.IGNORECASE)
# §32.1 #6: the broker's AUTHORITATIVE permanent-fault signal — a permanent
# error code or an explicit x_retriable:false. Checked BEFORE the status-code
# regexes because the broker returns these as HTTP 502, which _SERVER_RE would
# otherwise (wrongly) classify as a retryable server error.
# QUOTING IS LOAD-BEARING HERE, and it was wrong. The broker writes JSON
# (`"x_retriable": false`), but the openai SDK does not hand us the JSON — it
# renders the decoded body with Python's repr, so the text this regex actually
# sees is `'x_retriable': False`: single quotes and a capital F. `"?` matches a
# double quote or nothing, never an apostrophe, and `false` is case-sensitive
# without a flag. So the broker's AUTHORITATIVE non-retriable signal never
# matched, and every permanent failure was retried three times before being
# reported. Measured: `Error code: 400 - {'error': {... 'x_retriable': False}}`
# classified `unknown`. Accept both renderings, and both cases.
# Feature 0074 review item 5: the size/overflow CODES, checked before the
# broker-permanent pattern. The broker marks an upstream context overflow or
# 413 `x_retriable: false` (an identical retry fails identically) and answers
# it as `provider_context_overflow` (HTTP 413, static secret-free message).
# That is exactly the class whose SMALLER retry is a different request, so the
# permanent signal must not hide it from the generate path's halve-and-retry.
# Codes only: free-text overflow phrasing stays below the auth/rate-limit
# checks, where it always was.
_OVERFLOW_CODE_RE = re.compile(
    r"(provider_context_overflow|request_too_large|context_length_exceeded|"
    r"payload_too_large|string_above_max_length)",
    re.IGNORECASE,
)
_BROKER_PERMANENT_RE = re.compile(
    r'(["\']?x_retriable["\']?\s*:\s*false|'
    r'provider_bad_request|provider_auth_error|model_not_found)',
    re.IGNORECASE,
)


def classify_llm_error(exc: Exception) -> LLMErrorKind:
    """Classify an LLM exception into an actionable error kind.

    Args:
        exc: The exception raised by the LLM call.

    Returns:
        Categorized error kind for retry/fallback decisions.
    """
    msg = str(exc)
    for pattern, kind in _CLASSIFIERS:
        if pattern.search(msg):
            return kind
    return LLMErrorKind.UNKNOWN


# First match wins. The size/overflow codes come first (0074 review item 5),
# then the broker's authoritative retryability BEFORE any status-string
# heuristic — a permanent 502 must not be retried (§32.1 #6).
_CLASSIFIERS: tuple[tuple[re.Pattern[str], LLMErrorKind], ...] = (
    (_OVERFLOW_CODE_RE, LLMErrorKind.CONTEXT_OVERFLOW),
    (_BROKER_PERMANENT_RE, LLMErrorKind.PROVIDER_BAD_REQUEST),
    (_RATE_LIMIT_RE, LLMErrorKind.RATE_LIMITED),
    (_AUTH_RE, LLMErrorKind.AUTH_ERROR),
    (_CTX_OVERFLOW_RE, LLMErrorKind.CONTEXT_OVERFLOW),
    (_TIMEOUT_RE, LLMErrorKind.TIMEOUT),
    (_SERVER_RE, LLMErrorKind.SERVER_ERROR),
    (_CONN_RE, LLMErrorKind.CONNECTION_ERROR),
)


async def retry_llm_call(
    coro_factory: Callable[[], Awaitable[Any]],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.5,
) -> Any:
    """Retry an async LLM call with exponential backoff on transient errors.

    Args:
        coro_factory: Zero-arg callable returning an awaitable.
        max_attempts: Maximum retry attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay cap.
        jitter: Random jitter factor (±jitter * delay).

    Returns:
        The result of the first successful call.

    Raises:
        The last exception if all attempts fail or error is non-retryable.
    """
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            kind = classify_llm_error(exc)
            logger.warning(
                "llm_call_failed attempt=%d/%d kind=%s error=%s",
                attempt + 1, max_attempts, kind.value, exception_detail(exc),
            )
            if kind not in RETRYABLE_KINDS or attempt >= max_attempts - 1:
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            offset = (random.random() * 2 - 1) * jitter
            delay = max(0.1, delay * (1 + offset))
            logger.info("llm_retry delay=%.1fs attempt=%d/%d", delay, attempt + 1, max_attempts)
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Skill-level retry (synchronous, for ThreadPoolExecutor)
# ---------------------------------------------------------------------------


# ── rendering an exception for a PERSISTED, operator-facing field ───────────
#
# What this text reaches, all four of them:
#   1. the operator log line (retry_llm_call, below),
#   2. the SSE `thinking` stream,
#   3. `audits.degraded_reason`, persisted by BOTH dialects,
#   4. `lineage_events.notes` — ONE ROW PER SKIPPED LINEAGE ROW, permanent
#      history that outlives the audit row (service/lineage_scan_pass.go).
#
# And what an httpx/openai exception chain can CONTAIN, measured against the
# installed SDK: `RemoteProtocolError` embeds a verbatim fragment of the
# upstream response buffer — which on this path is model output derived from
# the scanned source tree; `HTTPStatusError` interpolates the full request URL
# including any `user:password@` userinfo; `SSLCertVerificationError`
# discloses hostnames and certificate subjects.
#
# The Go side already solved exactly this for provider text
# (backend/internal/broker/provider/upstream_detail.go). This is that
# discipline ported, and the ORDER is the same correctness property it is
# there: sanitise, then redact, then truncate. Redacting after truncation
# would leave half a secret, and half a secret is still a secret.

# Bidi overrides and zero-width characters are not control characters, so a
# C0/C1 filter misses them — yet a right-to-left override renders a model id
# reversed and a zero-width space makes an identifier compare unequal while
# looking identical. Dropped outright rather than mapped to a space: they
# carry no separator meaning, and substituting one would split an identifier.
_BIDI_AND_ZERO_WIDTH = frozenset(
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
    + list(range(0x200B, 0x2010)) + [0xFEFF]
)

# Secret SHAPES. One source of truth, compiled twice:
#
# * ``_SECRET_SHAPE_RE`` masks FINDING text (code windows and descriptions of
#   every agent's findings). It must be precise: prose after "Bearer"/"Basic",
#   commit SHAs, image digests, hashes, UUIDs and CSS class names are evidence,
#   not secrets. Case-sensitive unless a shape opts in with ``(?i:...)``, and no
#   shape crosses a newline (``[ \t]``, never ``\s``), so a window keeps its rows.
# * ``_SECRETISH`` masks one sanitised LOG line, where over-masking costs
#   nothing: every finding shape, case-insensitive, plus the broad legacy shapes
#   (bare 32+ hex, loose ``sk-`` / Bearer / Basic). A strict superset of the log
#   pattern this set replaced.
#
# A ``keep_*`` group is context that stays readable (the key name before a
# value); a ``*_letters`` group is a letters-only value that is left alone when
# it reads as CamelCase words (``HTTPAuthenticationScheme``), not a token.
#
# Every shape is linear: a run is possessive, bounded, or starts only where its
# lookbehind allows, so a 100k-character minified line cannot stall a finding's
# post-processing.
_SECRET_SHAPES: tuple[str, ...] = (
    # URL userinfo, any scheme case, the user possibly empty (redis://:pw@);
    # the host is not a secret. Starts only at the first character of a scheme
    # run, so a long run is scanned once.
    r"(?<![A-Za-z0-9+.\-])[A-Za-z0-9+.\-]++://[^\s/@:]*+:[^\s/@]++@",
    r"\bAIza[0-9A-Za-z_\-]{10,}",                              # Google API key
    # OpenAI / Anthropic style: optional short segments (proj-, ant-api03-),
    # then either a hyphen-free 16+ run holding a digit or a capital, or a 40+
    # body over the key alphabet holding BOTH (a random body puts a hyphen
    # anywhere, also inside its first 16 characters). Not a CSS class or a
    # lowercase hyphenated name. The lookaheads are bounded: linear.
    r"\bsk-(?:[a-z0-9]{1,16}+-){0,3}+(?:(?=[a-z_]*+[0-9A-Z])[0-9A-Za-z_]{16,}+[0-9A-Za-z_\-]*+"
    r"|(?=[a-z0-9_\-]{0,200}+[A-Z])(?=[A-Za-z_\-]{0,200}+[0-9])[0-9A-Za-z_\-]{40,}+)",
    r"\beyJ[0-9A-Za-z._\-]{16,}",                              # JWT
    r"\bgh[pousr]_[0-9A-Za-z]{16,}",                           # GitHub
    r"\bgithub_pat_[0-9A-Za-z_]{40,}",                         # GitHub fine-grained
    r"\bxox[baprse]-[0-9A-Za-z\-]{10,}",                       # Slack
    r"(?<=hooks\.slack\.com/services/)[A-Za-z0-9/]{20,}+",     # Slack webhook path
    r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AIPA)[0-9A-Z]{12,}",       # AWS key id
    r"(?P<keep_aws>(?i:aws_?secret_?access_?key)[\"']?[ \t]*[:=][ \t]*[\"']?)"
    r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])",                     # AWS secret key
    r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}",                 # Stripe
    r"\bnpm_[0-9A-Za-z]{36}\b",                                # npm
    r"\bglpat-[0-9A-Za-z_\-]{20,}",                            # GitLab
    r"\bSG\.[\w\-]{16,}+\.[\w\-]{16,}+",                       # SendGrid
    r"\bhf_[A-Za-z]{30,}",                                     # Hugging Face
    # A connection-string secret (ADO.NET, Azure storage), not a keyword argument.
    r"(?P<keep_conn>[;\"'](?i:AccountKey|SharedAccessKey|Password|Pwd)=)[^;\s\"']++",
    # Bearer <token> as a header value (after Authorization, or quoted): a 12+
    # run with a digit, or 16+ mixed-case letters. In that position even a
    # word-like run is the credential, so it is not judged as words.
    r"(?P<keep_auth>(?i:authorization)[\"']?[ \t]*[:=,][ \t]*[\"']?|[\"'])(?i:bearer)[ \t]+"
    r"(?:(?=[A-Za-z._~+/\-]*+\d)[0-9A-Za-z._~+/\-]{12,}"
    r"|(?=[a-z]*+[A-Z])(?=[A-Z]*+[a-z])[A-Za-z]{16,})=*",
    # Bearer <token> anywhere else, not "<Word>/..." prose: a run with a digit
    # (16+), or a 24+ letter run with 5+ capitals.
    r"\b(?i:bearer)[ \t]+(?![A-Za-z][a-z]{3,}/)"
    r"(?:(?=[A-Za-z._~+/\-]*\d)[0-9A-Za-z._~+/\-]{16,}"
    r"|(?=(?:[a-z]*[A-Z]){5})(?P<bearer_letters>[A-Za-z]{24,}))=*",
    # Basic <base64> on the same line, not "<Word>/..." prose: base64 with a
    # digit, + or /; a padded letters-only value; or 16+ letters with 5+ capitals.
    r"\b(?i:basic)[ \t]+(?![A-Za-z][a-z]{3,}/)"
    r"(?:(?=[A-Za-z]*[0-9+/])[0-9A-Za-z+/]{12,}={0,2}|[A-Za-z]{11,}={1,2}"
    r"|(?=(?:[a-z]*[A-Z]){5})(?P<basic_letters>[A-Za-z]{16,}))",
    r"-----BEGIN[ A-Z]{0,40}PRIVATE KEY(?: BLOCK)?-----",
)
_LOG_ONLY_SHAPES: tuple[str, ...] = (
    r"\bsk-[0-9A-Za-z_\-]{12,}",
    r"\bBearer\s+[0-9A-Za-z._\-]{12,}",
    r"\bBasic\s+[0-9A-Za-z+/=]{16,}",
    r"\b[0-9a-f]{32,}+\b",                                     # Azure 32-hex / sha-shaped
)
_SECRET_SHAPE_RE = re.compile("|".join(_SECRET_SHAPES))
_SECRETISH = re.compile("(?i)" + "|".join((*_SECRET_SHAPES, *_LOG_ONLY_SHAPES)))
_KEEP_GROUPS = ("keep_aws", "keep_conn", "keep_auth")
_LETTER_GROUPS = ("bearer_letters", "basic_letters")
# CamelCase / acronym words of a letters-only run: HTTP|Authentication|Scheme
_CAMEL_PART = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")


def _reads_as_words(run: str) -> bool:
    """A letters-only run made of word-length CamelCase parts (an identifier
    such as ``AuthenticationSchemeHandlerForAPIs``), where a random token's
    case changes leave parts of one or two letters."""
    parts = _CAMEL_PART.findall(run)
    return bool(parts) and max(map(len, parts)) <= 16 and len(run) >= 4 * len(parts)


def _first_group(m: re.Match[str], names: tuple[str, ...]) -> str:
    return next((m.group(g) for g in names if m.group(g)), "")


def _shape_replacement(m: re.Match[str], placeholder: str, judge_words: bool) -> str:
    """``placeholder`` for the value, keeping its context; an identifier made of
    words is left alone when ``judge_words`` (finding text, not logs)."""
    if judge_words and _reads_as_words(_first_group(m, _LETTER_GROUPS)):
        return m.group(0)
    return _first_group(m, _KEEP_GROUPS) + placeholder


# A bare hex value is a secret only on a line that NAMES a credential: an
# identifier to its left on the same line (``SECRET_KEY_BASE=``,
# ``headers["X-Api-Key"] = ``, ``define("SECRET_KEY", ``, ``ENV API_KEY``)
# with a credential word among its parts and no part naming a non-secret key
# (``cache_key``, ``commit``, ``password_hash``). Judged in Python over a
# bounded left reach, which is linear and readable where a lookbehind
# alternation is neither.
_HEX_RUN = re.compile(r"\b[0-9A-Fa-f]{32,}+\b")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]{0,63}+")
_LEFT_REACH = 160
# snake, kebab and camelCase parts of a name
_NAME_PART = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_CRED_WORDS = frozenset({
    "key", "secret", "token", "password", "passwd", "pwd", "credential", "credentials",
    "auth", "apikey", "apitoken", "secretkey", "privatekey", "accesskey", "accesstoken",
    "authtoken", "clientsecret", "appsecret", "appkey", "passphrase", "signingkey",
    "masterkey", "encryptionkey", "sessionkey",
})
_NOT_CRED = frozenset({
    "cache", "primary", "foreign", "idempotency", "sort", "partition", "checksum",
    "hash", "commit", "etag", "digest", "integrity", "public", "lookup", "dedup",
    "sha", "sha1", "sha256", "sha512", "md5", "fingerprint", "uuid", "guid",
})


def _credential_name(name: str) -> bool:
    """A part of the name is a credential word, and no part names a non-secret key."""
    parts = {p.lower() for p in _NAME_PART.findall(name)}
    return not parts.isdisjoint(_CRED_WORDS) and parts.isdisjoint(_NOT_CRED)


def _credential_line(text: str, start: int) -> bool:
    """An identifier on ``text``'s line, left of ``start``, names a credential."""
    lo = max(text.rfind("\n", max(0, start - _LEFT_REACH), start) + 1, start - _LEFT_REACH)
    return any(map(_credential_name, _IDENT.findall(text, lo, start)))


def _keyed_hex(m: re.Match[str], placeholder: str) -> str:
    return placeholder if _credential_line(m.string, m.start()) else m.group(0)


# A private-key region: BEGIN..END (or the end of the text), or the start of
# the text..END (a window that begins below the BEGIN row).
_PEM_REGION = re.compile(
    r"-----BEGIN[ A-Z]{0,40}PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END[ A-Z]{0,40}PRIVATE KEY(?: BLOCK)?-----|\Z)"
    r"|\A(?:(?!-----BEGIN).)*?-----END[ A-Z]{0,40}PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)
# Inside a region, mask only what IS key material, never part of a code row: a
# whole base64 row (optionally numbered, quoted, "\n"-escaped, concatenated,
# CRLF-terminated), or a run right after the header or a "\n" escape (a
# one-line JSON key).
_KEY_BODY_ROW = re.compile(
    r"(?m)^(?P<pre>(?:\d+: )?[ \t]*[\"']?)[A-Za-z0-9+/]{16,}={0,2}"
    r"(?P<post>(?:\\n)?[\"']?[ \t]*[+,]?[ \t]*\r?)$"
)
_ESCAPED_KEY_RUN = re.compile(r"(?:(?<=-----)|(?<=\\n))[A-Za-z0-9+/]{16,}={0,2}")


def _mask_key_region(region: str, placeholder: str) -> str:
    region = _KEY_BODY_ROW.sub(lambda m: m.group("pre") + placeholder + m.group("post"), region)
    return _ESCAPED_KEY_RUN.sub(placeholder, region)


def _mask_shapes(
    text: str, placeholder: str, shapes: re.Pattern[str], judge_words: bool,
) -> str:
    """Private-key bodies, then credential-named hex, then the token shapes."""
    text = _PEM_REGION.sub(lambda m: _mask_key_region(m.group(0), placeholder), text)
    text = _HEX_RUN.sub(lambda m: _keyed_hex(m, placeholder), text)
    return shapes.sub(lambda m: _shape_replacement(m, placeholder, judge_words), text)


def _sanitise(text: str) -> str:
    """Drop anything that can steer a terminal, forge a log line, or misrender
    an identifier, and collapse the result to one line."""
    cleaned = []
    for ch in text:
        o = ord(ch)
        if o < 0x20 or 0x7F <= o <= 0x9F:
            cleaned.append(" ")
        elif o in _BIDI_AND_ZERO_WIDTH:
            continue
        else:
            cleaned.append(ch)
    return " ".join("".join(cleaned).split())


def mask_secret_values(text: str, placeholder: str = "[redacted]") -> str:
    """Replace every secret-SHAPED value in ``text`` with ``placeholder``.

    Keys on the value's shape (a provider token, URL userinfo, a private-key
    header), not on what the surrounding text is about, so it masks a token
    wherever it sits: a code window around an unrelated finding, or a
    dependency spec quoted in a description. Line structure is preserved; use
    :func:`redact_for_log` for text that must also be collapsed to one line.
    """
    return _mask_shapes(text, placeholder, _SECRET_SHAPE_RE, judge_words=True)


def redact_for_log(text: str) -> str:
    """Sanitise then redact, in that order. One function because the order is a
    correctness property and callers kept getting it wrong."""
    return _mask_shapes(_sanitise(text), "[redacted]", _SECRETISH, judge_words=False)


def _escaped(ch: str) -> str:
    return ch.encode("unicode_escape", "backslashreplace").decode("ascii")


# Controls (C0, DEL, C1), format characters (every Bidi_Control character,
# zero-width and joiner marks, the soft hyphen), lone surrogates, and the line
# and paragraph separators: none prints as itself, and each can rewrite or hide
# what a terminal shows.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _unprintable(ch: str) -> bool:
    return unicodedata.category(ch) in _INVISIBLE_CATEGORIES


def escape_unprintable(text: str) -> str:
    """``text`` with every control, format (bidi, zero-width), line-separator
    and lone-surrogate character written as its Python escape, so it cannot
    steer a terminal or fail to encode."""
    return "".join(_escaped(c) if _unprintable(c) else c for c in text)


_MAX_CAUSE_LINKS = 3


def exception_detail(exc: BaseException, *, max_len: int = 200) -> str:
    """``Type: message``, plus the ``__cause__`` chain that names the real fault.

    ``APIConnectionError.__str__()`` is the constant string "Connection error."
    The SDK raises it via ``raise APIConnectionError(...) from err``, so the
    httpx exception that says WHAT failed — ConnectError, ReadError,
    RemoteProtocolError — sits on ``__cause__`` and was never read. A diagnosis
    that omits it is not a shorter diagnosis, it is an absent one: one measured
    run produced 23 failure lines whose entire content was "Connection error."

    Never raises: this runs inside failure handlers, where an exception would
    replace a logged problem with an unlogged one.
    """
    try:
        parts: list[str] = []
        seen: set[str] = set()
        cur: BaseException | None = exc
        for _ in range(_MAX_CAUSE_LINKS + 1):
            if cur is None:
                break
            rendered = f"{type(cur).__name__}: {cur}".strip()
            if rendered not in seen:
                seen.add(rendered)
                parts.append(rendered)
            cur = cur.__cause__
        joined = redact_for_log(" <- ".join(parts))
        if len(joined) > max_len:
            joined = joined[: max(0, max_len - 1)] + "\u2026"
        return joined
    except Exception:  # pragma: no cover - never fail inside a failure handler
        try:
            return type(exc).__name__
        except Exception:
            return "unrenderable error"


# ── the broker's own diagnosis ──────────────────────────────────────────────
#
# Lives here rather than beside its first caller (validate/llm_judge) because
# it has two, and they write to surfaces of very different durability: the L5
# judge puts it in a log line, while the generate path puts it in `llm_error`,
# which is emitted on the SSE `thinking` stream, carried in the `result`
# snapshot and PERSISTED as audits.degraded_reason. Two copies of "what did the
# broker actually say" is how the durable one ends up the worse one.

def broker_detail(exc: Exception) -> str:
    """The broker's own diagnosis, or "" when the failure is not one of ours.

    The broker answers with a typed envelope (`broker/server/dto.go::writeErr`)
    whose `code` already separates the causes an operator would act on
    differently — `model_not_found`, `token_revoked`, `token_expired`,
    `provider_auth_error`, `budget_exceeded`. Several are served with 5xx
    because the broker IS a gateway reporting an upstream fault, so the SDK
    raises `InternalServerError` and the class name alone says nothing.

    Measured: 33 upstream 404s for the retired model id `gemini-pro` reached
    the operator as "could not reach the LLM endpoint ... check the resolved
    base URL". The broker had already written `model not found: upstream
    status 404`; only the boundary lost it.

    Defensive by construction: any shape that is not the envelope yields "",
    and nothing here may raise — this runs inside failure handlers, where an
    exception would replace a logged problem with an unlogged one.
    """
    try:
        for raw in _envelope_candidates(exc):
            err = _unwrap_envelope(raw)
            if err is None or not _is_broker_envelope(err):
                continue
            detail = _render_envelope(err)
            if detail:
                return detail
        return ""
    except Exception:  # pragma: no cover - never fail inside a failure handler
        return ""


def _envelope_candidates(exc: Exception) -> list[object]:
    """Every place a client library might have left the broker's JSON body.

    THREE CLIENTS, THREE PLACES. The openai SDK parses the body onto `.body`;
    litellm re-raises its own exception type carrying the httpx response on
    `.response`; and several wrappers keep no structured body at all and only
    interpolate the response text into the message. Reading only the first was
    why the pass-through worked for the client it was written against and
    silently produced nothing for the LiteLLM-routed traffic that is most of
    the agent's calls.
    """
    out: list[object] = [getattr(exc, "body", None)]
    resp = getattr(exc, "response", None)
    if resp is not None:
        reader = getattr(resp, "json", None)
        if callable(reader):
            try:
                out.append(reader())
            except Exception:
                pass
        out.append(first_json_object(str(getattr(resp, "text", "") or "")))
    out.append(first_json_object(str(exc)))
    return [c for c in out if c is not None]


def _unwrap_envelope(raw: object) -> dict | None:
    """TWO SHAPES, because two producers.

    The broker writes `{"error": {...}}` (broker/server/dto.go::writeErr), but
    the openai SDK UNWRAPS that before building the exception —
    ``data = body.get("error", body) if is_mapping(body) else body`` — and
    hands over the inner object. Reading only the wrapped shape made this
    function dead code on the production path: it returned "" for every real
    broker error while the unit tests passed against a hand-built wrapper the
    SDK never produces. A raw httpx/requests caller still sees the wrapper.
    """
    if not isinstance(raw, dict):
        return None
    inner = raw.get("error")
    err = inner if isinstance(inner, dict) else raw
    return err if isinstance(err, dict) else None


def _is_broker_envelope(err: dict) -> bool:
    """Proof the BROKER is speaking, not the provider directly.

    A direct provider error has the same unwrapped shape, and saying "broker
    says" about it is confidently wrong — it would also re-admit provider text
    on a path the broker deliberately gates to a single status. `x_retriable`
    is written on EVERY broker error by writeErr and appears nowhere in the
    OpenAI wire format; `upstream` is ours alone. Either one proves it.
    """
    return isinstance(err.get("x_retriable"), bool) or isinstance(err.get("upstream"), dict)


def _render_envelope(err: dict) -> str:
    code = str(err.get("code") or err.get("type") or "").strip()
    if not code:
        return ""
    detail = f"broker says {code}"
    message = str(err.get("message") or "").strip()
    if message:
        detail += f": {message}"
    detail += _upstream_clause(err.get("upstream"))
    if err.get("x_retriable") is False:
        detail += " (not retriable — retrying cannot help)"
    return detail


def _upstream_clause(up: object) -> str:
    """The PROVIDER's own words, when the broker judged them safe to forward.

    It does so only for the status whose body cannot echo the request — see
    backend/internal/broker/provider/upstream_detail.go. This is the half that
    names WHICH model was rejected; the broker's static message never could.
    """
    if not isinstance(up, dict):
        return ""
    upmsg = str(up.get("message") or "").strip()
    if not upmsg:
        return ""
    provider = str(up.get("provider") or "provider").strip()
    status = up.get("status")
    where = f"{provider} {status}" if status else provider
    return f" | {where} said: {upmsg}"


# Bound on the WHOLE rendering, not on the borrowed half. It is the whole
# string that is written to a column and drawn in a UI line, and a cap on one
# component leaves the total free to grow every time a component is added.
_FAILURE_MESSAGE_MAX = 320


def llm_failure_message(kind: "LLMErrorKind", exc: Exception) -> str:
    """Render an LLM-phase failure for a USER-FACING, PERSISTED field.

    Not a log line. This string is emitted on the SSE `thinking` stream, kept
    in the `result` snapshot, and written to audits.degraded_reason in both
    dialects, where it is the operator's whole account of why a scan came back
    with skill findings only.

    The previous rendering was `str(exc)[:200]`. For a broker error the openai
    SDK builds that string as `Error code: 404 - {whole body dict}`, so the
    field received a Python repr of the envelope, cut mid-dict — and the key
    naming the rejected model is the last one in it, so the truncation removed
    exactly the part worth keeping. When the broker is the thing that answered,
    prefer its curated diagnosis; otherwise the rendering is unchanged.
    """
    prefix = f"LLM analysis failed ({kind.value}): "
    # broker_detail keeps priority: when the broker spoke, its typed envelope
    # is the better answer and already carries the provider's own words. The
    # cause chain is the fallback for when nothing answered at all — and it is
    # redacted, because unlike the broker's text it is server-controlled.
    detail = broker_detail(exc) or exception_detail(exc, max_len=_FAILURE_MESSAGE_MAX)
    budget = max(0, _FAILURE_MESSAGE_MAX - len(prefix))
    if len(detail) > budget:
        detail = detail[: max(0, budget - 1)] + "\u2026"
    return prefix + detail


_TRANSIENT_SKILL_ERRORS = (PermissionError, TimeoutError)

_TRANSIENT_ERRNOS = frozenset({
    errno.EAGAIN,
    errno.EBUSY,
    errno.ENOLCK,
})


def _is_transient_skill_error(exc: Exception) -> bool:
    """Return True if *exc* is a transient OS/filesystem error worth retrying.

    Matches PermissionError, TimeoutError, and OSError with EAGAIN/EBUSY/ENOLCK.
    """
    if isinstance(exc, _TRANSIENT_SKILL_ERRORS):
        return True
    return bool(isinstance(exc, OSError) and getattr(exc, "errno", None) in _TRANSIENT_ERRNOS)


def retry_skill(
    fn: Callable[..., Any],
    *args: Any,
    max_attempts: int = 2,
    base_delay: float = 0.5,
    jitter: float = 0.5,
) -> Any:
    """Retry a synchronous skill function on transient OS errors.

    Args:
        fn: The skill callable to execute.
        *args: Positional arguments forwarded to *fn*.
        max_attempts: Maximum number of attempts (default 2 = 1 retry).
        base_delay: Base delay in seconds between retries.
        jitter: Random jitter factor (±jitter * delay).

    Returns:
        The result of the first successful *fn* call.

    Raises:
        The last exception if all attempts fail or error is non-transient.
    """
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return fn(*args)
        except Exception as exc:
            last_exc = exc
            if not _is_transient_skill_error(exc) or attempt >= max_attempts - 1:
                raise
            delay = base_delay * (2 ** attempt)
            offset = (random.random() * 2 - 1) * jitter
            delay = max(0.05, delay * (1 + offset))
            logger.info(
                "skill_retry fn=%s delay=%.2fs attempt=%d/%d error=%s",
                getattr(fn, "__name__", fn), delay, attempt + 1, max_attempts,
                str(exc)[:200],
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]
