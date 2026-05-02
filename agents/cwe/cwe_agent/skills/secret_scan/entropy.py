"""High-entropy generic-secret fallback.

Last-resort detector for high-entropy strings that don't match any
named pattern. Off by default (``VULTURE_SECRET_SCAN_ENTROPY=true`` to
enable) because the false-positive rate is intrinsically higher than
named-pattern detection — long random-looking strings can be hashes,
UUIDs, keys, IDs, base64-encoded data, or actual secrets.

When enabled, all findings ship with ``severity=low`` so operators can
filter them via the audit UI without losing high-confidence detections.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from cwe_agent.skills.secret_scan import context as ctx


# Minimum string length to consider. Below this, even maximum entropy
# isn't strong evidence (3-char strings are commonly random IDs).
MIN_LENGTH = 32

# Minimum Shannon entropy. 4.5 bits/char rules out most natural text
# (English ~3.5-4.0 bits/char) and most short identifiers; admits
# base64/hex/random tokens.
MIN_ENTROPY = 4.5

# Minimum fraction of characters that look like base64/hex alphabet.
# Rules out text with high entropy from punctuation/whitespace mix.
MIN_SAFE_CHAR_FRACTION = 0.95

# Token-extractor: long alphanumeric runs (with limited punctuation).
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_high_entropy_secret(s: str) -> bool:
    if len(s) < MIN_LENGTH:
        return False
    if shannon_entropy(s) < MIN_ENTROPY:
        return False
    safe_chars = sum(1 for c in s if c.isalnum() or c in "+/=_-")
    if safe_chars / len(s) < MIN_SAFE_CHAR_FRACTION:
        return False
    return True


def find_high_entropy(file_path: Path, content: str) -> list[dict]:
    """Scan ``content`` for high-entropy tokens that may be secrets.

    Per-line scanning with placeholder/test-context filters applied.
    """
    findings: list[dict] = []
    seen: set[tuple[int, str]] = set()

    for line_num, line in enumerate(content.splitlines(), start=1):
        if ctx.is_safe_context_line(line):
            continue
        # Skip comment-only lines.
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "/*", "*", ";", "--")):
            continue
        for match in _TOKEN_RE.finditer(line):
            token = match.group(0)
            if not _is_high_entropy_secret(token):
                continue
            key = (line_num, token[:16])  # dedupe on prefix
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": "low",
                "check_id": "cwe.secret_scan.entropy_generic",
                "category": "CWE-798",
                "title": "High-entropy string (potential secret)",
                "description": (
                    f"Line {line_num} contains a {len(token)}-char "
                    "high-entropy string. The entropy detector cannot "
                    "confirm this is a real secret — only that the "
                    "shape is consistent with one. Review manually."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "If the string is a real secret, move it to a "
                    "secrets manager. If it's not (e.g. it's a hash, "
                    "JWT public payload, or test fixture), suppress "
                    "this finding via the operator UI or by adding a "
                    "`# noqa: vulture-secret` comment."
                ),
                "code_snippet": f"{token[:6]}…[REDACTED]",
            })

    return findings
