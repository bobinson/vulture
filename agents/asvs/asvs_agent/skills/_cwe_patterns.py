"""Inlined copy of CWE-agent regex constants used by the ASVS skill.

Why a local copy (not an import from cwe_agent):
  1. Docker build isolation — agent-asvs's Dockerfile only pip-installs
     the ASVS package; adding vulture-cwe-agent to pyproject would
     require bundling CWE source into every ASVS image, or publishing
     CWE to a registry.
  2. Supply-chain decoupling — the earlier code review flagged ASVS's
     cross-agent import of CWE as a hidden dependency. If CWE changes
     pattern shape (list -> single Pattern, flag differences), ASVS
     silently breaks. A local copy makes the invariant explicit.
  3. Independent evolution — ASVS can diverge patterns as needed (we
     already tightened several to reduce FPs during the self-scan).

Sync protocol: when CWE agent patterns change, review whether ASVS
needs the update. Deliberate out-of-sync is acceptable.
"""
import os
import re

HARDCODED_CRED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
    re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
    re.compile(r'(?:secret_key|secret)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:AWS_SECRET|PRIVATE_KEY)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
]

BROKEN_CRYPTO_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\bDES\b(?!C)'),
    re.compile(r'\bRC4\b'),
    re.compile(r'\bBlowfish\b', re.IGNORECASE),
    re.compile(r'\b3DES\b'),
    re.compile(r'\bTripleDES\b', re.IGNORECASE),
    re.compile(r'ECB\b'),
    re.compile(r'DES\.new\('),
    re.compile(r'ARC4\.new\('),
    re.compile(r'Blowfish\.new\('),
    re.compile(r'mode\s*=\s*["\']?ECB'),
    re.compile(r'MODE_ECB'),
]

WEAK_RANDOM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\brandom\.random\s*\('),
    re.compile(r'\brandom\.randint\s*\('),
    re.compile(r'\brandom\.choice\s*\('),
    re.compile(r'\bMath\.random\s*\('),
    re.compile(r'\brand\(\s*\)'),
    re.compile(r'\bsrand\s*\('),
    re.compile(r'java\.util\.Random\b'),
]

DEBUG_PROD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(?:app|server|flask)\.(?:run|debug)\s*\([^)]*debug\s*=\s*True', re.IGNORECASE),
    re.compile(r'(?:DEBUG|debug)\s*=\s*(?:True|true|1)\s*#?\s*(?!.*(?:test|dev|local))', re.IGNORECASE),
    re.compile(r'(?:devtools|debugger|profiler)\s*[:=]\s*(?:True|true|enabled)', re.IGNORECASE),
    re.compile(r'(?:stacktrace|stack_trace|verbose_errors)\s*[:=]\s*(?:True|true|1)', re.IGNORECASE),
]

# A filesystem accessor — the sink that makes a `../` dangerous rather than
# merely relative. Kept generous: a missing accessor here costs a true positive.
# Each alternative carries its OWN call syntax, so neither arm below appends a
# paren. An earlier draft appended `\s*\(` to the whole alternation, which turned
# the entries that already ended in `(` or `.` into unsatisfiable `Path((`,
# `stat((`, `shutil.(` — silently killing the Python file-API branch of the
# sink-AFTER direction that the comment promised to cover.
#
# The `(?<![A-Za-z0-9_])` lookbehind plus the required call paren is what keeps
# a bare `open` from matching inside an identifier: `openDialog('../a.png')` is
# not a filesystem read, and under IGNORECASE the unanchored form re-admitted
# exactly the false-positive class this change exists to remove.
_FS_SINK = (
    r"(?<![A-Za-z0-9_])(?:open|readFile|readFileSync|writeFile|writeFileSync"
    r"|createReadStream|createWriteStream|sendFile|download|copyfile|copyFile"
    r"|unlink|rmdir|readdir|stat|lstat|rename|remove|send_file|FileResponse"
    r"|Path)\s*\("
    r"|(?:os\.path\.join|path\.join|shutil\.\w+|fs\.promises\.\w+|fsp\.\w+"
    r"|io\.open|codecs\.open|tar\.extract)\s*\("
    # `require('path').join(...)` spells the accessor indirectly, so the literal
    # `path.join` never appears. Matched explicitly rather than by a bare
    # `\.join\s*\(`, which would hit every Array.prototype.join in the tree.
    r"|require\s*\(\s*['\"](?:node:)?path['\"]\s*\)\s*\.\s*join\s*\("
)

# `../` co-occurring with a filesystem accessor ON THE SAME LINE, in either
# order. This replaces a BARE `\.\./` literal that required nothing at all.
#
# Measured: that bare literal produced 504 of 517 ASVS findings (97.5%, all
# HIGH) on one real target, and every sample was an ordinary relative import —
# `import { loadEnv } from '../env';`. In JS/TS `../` is simply how a relative
# module path is spelled, so on its own it is not evidence of traversal. The
# five sibling patterns in this list all already required an accessor; this one
# was the outlier.
#
# KNOWN LIMITATION, deliberate: a genuine traversal whose `../` is assembled on
# a different line from its sink is now missed (`const p = '../' + req.query.f;`
# on one line, `fs.readFile(p)` nine lines later). That is a real false negative
# traded for a 504:0 precision problem. If measurement later shows misses, widen
# to a statement window rather than restoring the bare literal.
_TRAVERSAL_WITH_SINK = [
    # accessor then traversal:  fs.readFileSync('../uploads/' + f)
    re.compile(r"(?:" + _FS_SINK + r")[^\n]{0,160}\.\.[/\\]", re.IGNORECASE),
    # traversal then accessor:  p = '../' + name; Path(p).read_text()
    re.compile(r"\.\.[/\\][^\n]{0,160}(?:" + _FS_SINK + r")", re.IGNORECASE),
]

# Rollback: restore the pre-fix bare literals for one release.
_BARE_TRAVERSAL = [re.compile(r'\.\./'), re.compile(r'\.\.\\\\')]


def _traversal_gate_disabled() -> bool:
    return os.getenv(
        "VULTURE_ASVS_DISABLE_TRAVERSAL_SINK_GATE", "false"
    ).strip().lower() in ("1", "true", "yes", "on")


PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'os\.path\.join\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    *(_BARE_TRAVERSAL if _traversal_gate_disabled() else _TRAVERSAL_WITH_SINK),
    re.compile(r'open\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    # Left boundary required, same defect as DROP-inside-backdrop: without it
    # `Path\(` matches the TAIL of any identifier ending in Path, so
    # `resolveCompletionPath(user, url)` was reported as path traversal.
    # pathlib's `Path(` and `pathlib.Path(` still match ('.' is outside the class).
    re.compile(r'(?<![A-Za-z0-9_])Path\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    re.compile(r'(?:readFile|readFileSync)\([^)]*(?:req|params|query)', re.IGNORECASE),
]

COOKIE_NO_HTTPONLY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'Set-Cookie:', re.IGNORECASE),
    re.compile(r'\.set_cookie\s*\(', re.IGNORECASE),
    re.compile(r'http\.SetCookie\s*\('),
    re.compile(r'(?:res|response)\.cookie\s*\(', re.IGNORECASE),
]

COOKIE_NO_SECURE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\.set_cookie\s*\('),
    re.compile(r'http\.SetCookie\s*\('),
    re.compile(r'(?:res|response)\.cookie\s*\('),
    re.compile(r'Set-Cookie:'),
]

SAFE_COOKIE_PATTERNS: re.Pattern[str] = re.compile(
    r'(?:HttpOnly|httponly|http_only|httpOnly\s*[:=]\s*[Tt]rue)', re.IGNORECASE,
)

SAFE_SECURE_PATTERNS: re.Pattern[str] = re.compile(
    r'(?:secure\s*[:=]\s*[Tt]rue|[;,]\s*[Ss]ecure\b|__Secure-|__Host-)', re.IGNORECASE,
)

SESSION_FIXATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'session\[.*\]\s*=.*(?:request|req|params|input)', re.IGNORECASE),
    re.compile(r'session\.(?:set|put|setAttribute)\s*\(.*(?:request|req|user)', re.IGNORECASE),
]
