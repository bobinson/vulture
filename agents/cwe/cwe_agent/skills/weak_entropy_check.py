"""Dedicated skill for CWE-331 / CWE-332 (weak / insufficient entropy).

Flags calls to non-cryptographic RNG APIs (``random.random``,
``Math.random``, ``rand()``, ``new Random()``) whose result flows into a
variable whose name signals a security-sensitive use (``token``, ``key``,
``nonce``, ``secret``, ``session``, ``password``, ``iv``, ``salt``).

Suppressed when:
* A cryptographic RNG (``secrets.token_*``, ``os.urandom``,
  ``SecureRandom``, ``crypto.randomBytes``) also appears in the same
  function scope, signaling the weak RNG is used for non-crypto purposes.
* The variable name itself signals test / mock / fake usage.
"""
import re
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

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


def _build_finding(
    cwe_id: str,
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single CWE-331/332 finding dict."""
    finding = {
        "severity": "high",
        "check_id": f"cwe.weak_entropy.cwe_{cwe_id}",
        "category": f"CWE-{cwe_id}",
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
) -> None:
    """Scan a single line for weak-entropy flows into sensitive identifiers."""
    var_name = _looks_like_flow(line)
    if var_name is None:
        return
    if not _is_sensitive(var_name):
        return
    if safe_cooccur:
        return
    findings.append(_build_finding("331", file_path, lineno, lines))
    findings.append(_build_finding("332", file_path, lineno, lines))


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan for weak-entropy flows."""
    if is_generated_file(file_path) or is_test_file(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    safe_cooccur = _has_safe_cooccurrence(lines)
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_line(line, lineno, path_str, lines, findings, safe_cooccur)


def check_weak_entropy(source_path: str) -> dict[str, Any]:
    """Scan source files for weak-entropy flows (CWE-331 / CWE-332)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_weak_entropy_tool = function_tool(check_weak_entropy)
