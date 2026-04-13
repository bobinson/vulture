"""Obfuscation detection helpers for scan skills.

Detects common obfuscation patterns: base64-encoded payloads, hex escape
sequences, String.fromCharCode chains, eval+concat, computed imports, and
exec(compile(...)) invocations.
"""

import re
from pathlib import Path

from shared.tools.snippet import extract_snippet

# Skip lines that appear in test/example contexts
SAFE_OBFUSCATION_CONTEXT = re.compile(
    r"(?:test_|_test\.py|example|fixture|mock|README|\.md|CHANGELOG)",
    re.IGNORECASE,
)

# Pattern 1: b64decode/atob/Buffer.from with long base64 string nearby
_BASE64_CALL = re.compile(
    r"(?:b64decode|base64\.b64decode|atob|Buffer\.from)\s*\([^)]*[A-Za-z0-9+/=]{100,}",
)

# Pattern 2: Hex escape sequences (6+ consecutive \x## pairs)
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")

# Pattern 3: String.fromCharCode with 20+ characters of arguments
_FROM_CHAR_CODE = re.compile(r"String\.fromCharCode\s*\([^)]{20,}\)")

# Pattern 4: chr() concatenation chains (3+ chr() calls joined by +)
_CHR_CONCAT = re.compile(
    r"chr\s*\([^)]+\)\s*\+\s*chr\s*\([^)]+\)\s*\+\s*chr\s*\([^)]+\)",
)

# Pattern 5: exec(compile(...))
_EXEC_COMPILE = re.compile(r"exec\s*\(\s*compile\s*\(")

# Pattern 6: Computed import: __import__(variable) (not string literal)
_COMPUTED_IMPORT = re.compile(r"__import__\s*\(\s*[a-zA-Z_]\w*\s*\)")

# Pattern 7: eval with string concatenation: eval(str + str)
_EVAL_CONCAT = re.compile(r"eval\s*\([^)]*\+[^)]*\)")

_ALL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (_BASE64_CALL, "Base64-encoded payload in runtime decode call", "base64_decode"),
    (_HEX_ESCAPES, "Hex-escaped byte sequence (possible shellcode/payload)", "hex_escape"),
    (_FROM_CHAR_CODE, "String.fromCharCode obfuscation chain", "fromcharcode"),
    (_CHR_CONCAT, "chr() concatenation chain (obfuscated string)", "chr_concat"),
    (_EXEC_COMPILE, "exec(compile(...)) dynamic code execution", "exec_compile"),
    (_COMPUTED_IMPORT, "Computed __import__ (dynamic module loading)", "computed_import"),
    (_EVAL_CONCAT, "eval() with string concatenation", "eval_concat"),
]

COMMENT_LINE = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")


def check_obfuscation(file_path: Path, lines: list[str], content: str) -> list[dict]:
    """Scan file lines for obfuscation patterns.

    Args:
        file_path: Path to the source file.
        lines: Source file split into lines.
        content: Full file content (for context checks).

    Returns:
        List of finding dicts for detected obfuscation.
    """
    # Skip test/example files entirely
    if SAFE_OBFUSCATION_CONTEXT.search(str(file_path)):
        return []

    findings: list[dict] = []
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_LINE.match(line):
            continue
        for pattern, description, tag in _ALL_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "severity": "high",
                    "category": "obfuscation",
                    "title": description,
                    "description": f"Obfuscated code detected at line {line_num} ({tag})",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Review obfuscated code for malicious intent; replace with readable equivalents",
                    "code_snippet": extract_snippet(lines, line_num),
                    "check_id": f"obfuscation.{tag}",
                })
                break  # one finding per line
    return findings
