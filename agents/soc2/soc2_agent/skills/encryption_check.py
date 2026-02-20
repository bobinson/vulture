"""Encryption audit skill for SOC2."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

ENCRYPTION_PATTERNS = [
    re.compile(r"AES|aes|encrypt|decrypt|Cipher", re.IGNORECASE),
    re.compile(r"TLS|SSL|https|HTTPS"),
    re.compile(r"cryptography|crypto\.subtle|bcrypt|argon2"),
]

# More targeted data storage patterns - focus on actual persistence
DATA_STORAGE_PATTERNS = [
    re.compile(r"INSERT INTO|UPDATE\s+\w+\s+SET"),
    re.compile(r"\.save\(|\.put\(|\.create\("),
    re.compile(r"sqlite3|psycopg|mysql|pymongo|sql\.Open"),
]


def check_encryption(source_path: str) -> dict:
    """Check for encryption at rest and in transit.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of encryption issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for encryption issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_data_storage = any(p.search(content) for p in DATA_STORAGE_PATTERNS)
    has_encryption = any(p.search(content) for p in ENCRYPTION_PATTERNS)

    if has_data_storage and not has_encryption:
        findings.append({
            "severity": "high",
            "category": "CC6-encryption",
            "title": "Data storage without encryption",
            "description": f"File {file_path.name} stores data without encryption",
            "file_path": str(file_path),
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Encrypt data at rest using AES-256 and use TLS for transit",
        })


check_encryption_tool = function_tool(check_encryption)
