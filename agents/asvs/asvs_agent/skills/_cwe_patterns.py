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

PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'os\.path\.join\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    re.compile(r'\.\./'),
    re.compile(r'\.\.\\\\'),
    re.compile(r'open\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
    re.compile(r'Path\([^)]*(?:request|req|params|input|user|body|query)', re.IGNORECASE),
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
