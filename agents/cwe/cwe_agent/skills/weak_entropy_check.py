"""Weak / insufficient entropy: CWE-331, CWE-332, CWE-336, CWE-337.

Two independent rules.

**Flow rule (CWE-331 + CWE-332).** Calls to non-cryptographic RNG APIs
(``random.random``, ``Math.random``, ``rand()``, ``new Random()``) whose result
flows into a variable whose name signals a security-sensitive use (``token``,
``key``, ``nonce``, ``secret``, ``session``, ``password``, ``iv``, ``salt``).

Suppressed when:
* A cryptographic RNG (``secrets.token_*``, ``os.urandom``,
  ``SecureRandom``, ``crypto.randomBytes``) also appears in the same
  function scope, signaling the weak RNG is used for non-crypto purposes.
* The variable name itself signals test / mock / fake usage.

**Seed rule (CWE-336 / CWE-337).** A PRNG explicitly seeded from a value an
attacker can reproduce: a constant literal (CWE-336, "same seed") or a
clock/pid read (CWE-337, "predictable seed"). The two classifications are
mutually exclusive — a seed slot is one, the other, or neither.

The seed rule is gated on a security-value token appearing in the surrounding
window. That gate is what makes it usable rather than noisy: a fixed seed is
*pervasive and correct* in real code (reproducible samplers, fixture
generators, simulations), so a bare "fixed seed" predicate reports correct code.
Measured over real trees, every non-test fixed-seed candidate found was a
reproducibility seed and every one is rejected here.
"""
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple

from agents import function_tool
from shared.tools.file_scanner import (
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._args import arg_slot, split_call_args

# Assignment anchor that binds a weak-RNG call to a target identifier.
_ASSIGN = re.compile(
    r"^\s*(?:const\s+|let\s+|var\s+|final\s+|public\s+|private\s+|static\s+)*"
    r"(?:[A-Za-z_][\w<>\[\]]*\s+)?"
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$"
)

# Weak (non-cryptographic) RNG call signatures, plus time-as-seed
# patterns (CWE-338 — predictable PRNG when time is the only entropy).
_WEAK_RNG = re.compile(
    r"\brandom\.random\s*\("
    r"|\bMath\.random\s*\("
    r"|\brand\s*\(\s*\)"
    r"|\bnew\s+Random\s*\("
    # time-as-seed shapes: srand(time(...)), Random(currentTimeMillis),
    # mt_srand(time(...)), random.seed(time.time()), Math.random()
    # nominally is platform-seeded but explicit Random(Date.now()) is
    # a code smell.
    r"|\bsrand\s*\(\s*time\s*\("
    r"|\bnew\s+Random\s*\(\s*(?:System\.currentTimeMillis|Date\.now|System\.nanoTime)\s*\("
    r"|\brandom\.seed\s*\(\s*time\.time\s*\("
    r"|\bmt_srand\s*\(\s*time\s*\("
    r"|\bMath\.random\s*\([^)]*Date\.now"
)

# Security-sensitive target-name tokens.
_SENSITIVE_NAME = re.compile(
    r"token|key|nonce|secret|session|password|iv|salt",
    re.IGNORECASE,
)

# Non-production signal in variable name → suppress.
_NONPROD_NAME = re.compile(
    r"test|mock|fake|example|cache|demo",
    re.IGNORECASE,
)

# Cryptographic RNG co-occurrence in same function scope → suppress.
_SAFE_COOCCUR = re.compile(
    r"\bsecrets\.(?:token|choice|randbelow)"
    r"|\bSecureRandom\b"
    r"|\bcrypto\.randomBytes\b"
    r"|\bos\.urandom\b"
)

# ---------------------------------------------------------------------------
# Shared security-value vocabulary. Lives here because ``crypto_check`` already
# imports this module (the reverse would be a cycle) and both skills need the
# SAME answer to "does this text name a credential?" — two drifting copies of
# that judgement is how one rule ends up flagging what the other exempts.
#
# `auth\w*` (matches `authors`), `uuid`, `guid`, `iv`, `nonce` and `salt` are
# deliberately absent: the first three are display/correlation values and the
# last three are claimed by the CWE-323/329/760 rules.
#
# `(?![a-z])` is applied case-SENSITIVELY (scoped inline flag) so `csrfValue`
# and `OTP_CODE` match while `tokenizer` does not.
# ---------------------------------------------------------------------------
SECURITY_VALUE_TOKEN = re.compile(
    r"(?i:\b(?:tokens?|secrets?|passwords?|passwd|api_?key|secret_?key"
    r"|private_?key|session_?id|sessionid|otp|one_?time|csrf|xsrf"
    r"|reset_?token|verification_?code|signatures?|credentials?))(?![a-z])",
)

# ---------------------------------------------------------------------------
# CWE-336 / CWE-337: an explicitly seeded PRNG.
#
# One spec table (constructor anchor + seed slot) and one slot test. The slot
# is read with the depth-aware argument tokeniser rather than a `[^,)]+`
# stand-in, so a literal nested inside an EARLIER argument can never be read as
# the seed.
# ---------------------------------------------------------------------------


class _SeedSpec(NamedTuple):
    """One seeding shape: where the seed argument sits."""

    anchor: re.Pattern[str]
    seed: int


_SEED_SPECS = (
    _SeedSpec(re.compile(r"\b(?:np|numpy)?\.?random\.seed\s*\("), 0),
    _SeedSpec(re.compile(r"\brandom\.Random\s*\("), 0),
    _SeedSpec(re.compile(r"\b(?:mt_)?srand\s*\("), 0),
    _SeedSpec(re.compile(r"\brand\.(?:Seed|NewSource)\s*\("), 0),
    _SeedSpec(re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\("), 0),
    _SeedSpec(re.compile(r"\bseedrandom\s*\("), 0),
    _SeedSpec(re.compile(r"\bsetSeed\s*\("), 0),
)

# A constant written into the seed slot: an integer (any base, with a C/Java
# width suffix) or a string literal. `-` is allowed so `srand(-1)` is caught.
_FIXED_SEED = re.compile(
    r"^(?:-\s*)?(?:0[xXbBoO][0-9a-fA-F_]+|[0-9][0-9_]*[lLuUfF]*)$"
    r"|^(?:b|u|r)?(?:\"[^\"]*\"|'[^']*'|`[^`]*`)$"
)
# A clock or process-id read. Every arm is a CALL or a well-known constant
# attribute — a bare identifier named `time` is not evidence of anything.
_PREDICTABLE_SEED = re.compile(
    r"\btime\s*\(\s*(?:NULL|nullptr|0|\)\s*)"
    r"|\btime\.time\s*\(|\btime\.Now\s*\(|\bDate\.now\s*\("
    r"|\bnew\s+Date\s*\(\s*\)|currentTimeMillis\s*\(|nanoTime\s*\("
    r"|\bgetTime\s*\(\s*\)|\bgetpid\s*\(|\bgetPid\s*\(|\bos\.getpid\s*\("
    r"|\bprocess\.pid\b|\bProcess\.pid\b|\bmicrotime\s*\(",
)

_SEED_ROWS = {
    "336": {
        "severity": "high",
        "check_id": "cwe.weak_entropy.same_seed",
        "category": "CWE-336",
        "title": "PRNG seeded with a fixed constant",
        "detail": "a hardcoded constant",
        "recommendation": (
            "Leave a security-relevant PRNG unseeded and use a CSPRNG "
            "(``secrets``, ``os.urandom``, ``SecureRandom``, ``crypto/rand``); "
            "a constant seed replays the identical value stream on every run"
        ),
    },
    "337": {
        "severity": "high",
        "check_id": "cwe.weak_entropy.predictable_seed",
        "category": "CWE-337",
        "title": "PRNG seeded from the clock or process id",
        "detail": "a clock or process-id read",
        "recommendation": (
            "Seed from a CSPRNG, or use one directly: the wall clock and the "
            "pid are both low-entropy values an attacker can narrow to a "
            "handful of candidates"
        ),
    },
}

# How far a security-value token may sit from the seeding call. The seeded
# draw is what makes the seed a weakness, and it is written next to the seed.
_SEED_WINDOW = 8

# Cheap pre-filter so the spec table is only walked for lines that could seed.
# Case-folded ALTERNATION is the expensive shape here (measured ~3x the cost of
# spelling the two casings out), and this runs on every line of every file.
_SEED_HINT = re.compile(r"[sS]eed|SEED|srand|Random\s*\(|NewSource\s*\(")

# ``SECURITY_VALUE_TOKEN`` anchors each name at a word boundary, which is right
# for the line-local consumption test it was measured for but leaves an
# identifier's INNER words unreadable: `sessionToken` and `make_session_id`
# carry no boundary before `token` / `id`. Splitting an identifier into its
# words gives the window a second, equivalent view of the same line — the raw
# text still matches the underscore-joined compounds (`api_key`) that a split
# would break apart, so both are searched.
_WORD_SPLIT = re.compile(r"_|(?<=[a-z0-9])(?=[A-Z])")


def _looks_like_flow(line: str) -> str | None:
    """Return the assigned var name if line assigns a weak-RNG call to it."""
    m = _ASSIGN.match(line)
    if not m:
        return None
    if not _WEAK_RNG.search(m.group("rhs")):
        return None
    return m.group("name")


def _is_sensitive(var_name: str) -> bool:
    """Return True if variable name signals security-sensitive usage."""
    if _NONPROD_NAME.search(var_name):
        return False
    return _SENSITIVE_NAME.search(var_name) is not None


def _has_safe_cooccurrence(lines: tuple[str, ...]) -> bool:
    """Return True if a cryptographic RNG appears anywhere in the file."""
    for line in lines:
        if _SAFE_COOCCUR.search(line):
            return True
    return False


# The flow rule's two rows. The ``category`` values are LITERALS: built with an
# f-string they never appeared in source, so the reachability attestation —
# which scans skill sources for `"category": "CWE-N"` — could not see two ids
# this skill has always emitted.
_FLOW_ROWS = {
    "331": {
        "check_id": "cwe.weak_entropy.cwe_331",
        "category": "CWE-331",
    },
    "332": {
        "check_id": "cwe.weak_entropy.cwe_332",
        "category": "CWE-332",
    },
}


def _build_finding(
    cwe_id: str,
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single CWE-331/332 finding dict."""
    finding = {
        "severity": "high",
        **_FLOW_ROWS[cwe_id],
        "title": "Weak / Insufficient Entropy for Security-Sensitive Value",
        "description": (
            f"Non-cryptographic RNG result assigned to a security-sensitive "
            f"variable at line {lineno}. Predictable values enable session "
            f"hijacking, token guessing, and cryptographic attacks."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Use a cryptographic RNG: ``secrets.token_hex()``, "
            "``os.urandom``, ``SecureRandom``, or ``crypto.randomBytes``."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, cwe_id)


def _scan_line(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
    safe_cooccur: bool,
) -> bool:
    """Scan a single line for weak-entropy flows into sensitive identifiers.

    Returns True when the line was claimed, so the seed rule stands down:
    CWE-331/332 and CWE-336/337 are SIBLINGS under CWE-330, not ancestor and
    descendant, so both on one line would be a duplicate row (P5).
    """
    var_name = _looks_like_flow(line)
    if var_name is None or not _is_sensitive(var_name) or safe_cooccur:
        return False
    findings.append(_build_finding("331", file_path, lineno, lines))
    findings.append(_build_finding("332", file_path, lineno, lines))
    return True


@lru_cache(maxsize=256)
def _classify_seed(slot: str) -> str | None:
    """``336`` for a constant seed, ``337`` for a clock/pid seed, else None."""
    if _FIXED_SEED.match(slot):
        return "336"
    return "337" if _PREDICTABLE_SEED.search(slot) else None


def _spec_seed(spec: _SeedSpec, line: str) -> str | None:
    """Apply one seeding spec to ``line`` and classify its seed slot."""
    match = spec.anchor.search(line)
    if match is None:
        return None
    args = split_call_args(line, match.end() - 1)
    slot = arg_slot(args, spec.seed) if args else None
    return _classify_seed(slot) if slot else None


def _seed_cwe(line: str) -> str | None:
    """The seed classification for the first seeding call on ``line``."""
    if not _SEED_HINT.search(line):
        return None
    for spec in _SEED_SPECS:
        cwe = _spec_seed(spec, line)
        if cwe is not None:
            return cwe
    return None


def _security_window(lines: tuple[str, ...], lineno: int) -> bool:
    """True when a security-value token sits within the seed window.

    The seeded DRAW is what turns a fixed seed into a weakness, and it is
    written next to the seed — a reproducibility seed has no such neighbour.
    """
    low = max(0, lineno - 1 - _SEED_WINDOW)
    high = min(len(lines), lineno + _SEED_WINDOW)
    return any(_names_a_security_value(lines[i]) for i in range(low, high))


@lru_cache(maxsize=2048)
def _names_a_security_value(text: str) -> bool:
    """True when ``text`` names a credential, reading identifier inner words."""
    return any(
        SECURITY_VALUE_TOKEN.search(view)
        for view in (text, _WORD_SPLIT.sub(" ", text))
    )


def _scan_seed(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a single line for a PRNG seeded from a reproducible value."""
    cwe = _seed_cwe(line)
    if cwe is None or not _security_window(lines, lineno):
        return
    row = dict(_SEED_ROWS[cwe])
    detail = row.pop("detail")
    finding = {
        **row,
        "description": (
            f"The PRNG seed at line {lineno} is {detail}, so the value stream "
            f"drawn from it is reproducible by anyone who can guess it"
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "code_snippet": extract_snippet(lines, lineno),
        "verification_hints": ["Confirm the seeded stream feeds a security value"],
    }
    findings.append(enrich_finding(finding, cwe))


def _should_skip(file_path: Path) -> bool:
    """True for files whose weak-RNG assignments cannot be real flows.

    ``is_prose_file`` is the third arm: a document listing
    ``token = Math.random()`` under "never write this" seeds nothing.
    Measured on such a file: 8 false CWE-331/CWE-332 rows.
    """
    return is_generated_file(file_path) or is_test_file(file_path) or is_prose_file(file_path)


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan for weak-entropy flows."""
    if _should_skip(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    safe_cooccur = _has_safe_cooccurrence(lines)
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        claimed = _scan_line(line, lineno, path_str, lines, findings, safe_cooccur)
        if not claimed:
            _scan_seed(line, lineno, path_str, lines, findings)


def check_weak_entropy(source_path: str) -> dict[str, Any]:
    """Scan source files for weak-entropy flows (CWE-331 / CWE-332)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_weak_entropy_tool = function_tool(check_weak_entropy)
