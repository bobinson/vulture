"""Circuit breaker analysis skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

CIRCUIT_BREAKER_PATTERNS = [
    re.compile(r"circuit.?breaker|CircuitBreaker|circuit_breaker", re.IGNORECASE),
    re.compile(r"pybreaker|circuitbreaker|gobreaker|resilience4j"),
    re.compile(r"half.?open|open.?state|closed.?state", re.IGNORECASE),
]

SERVICE_CALL_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete)\("),
    re.compile(r"http\.(Get|Post|Do)\("),
    re.compile(r"grpc\.|\.Dial\(|\.NewClient\("),
]


def check_circuit_breaker(source_path: str) -> dict:
    """Analyze source code for circuit breaker patterns.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of circuit breaker issues.
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
    """Check a file for missing circuit breaker patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_service_calls = any(p.search(content) for p in SERVICE_CALL_PATTERNS)
    has_breaker = any(p.search(content) for p in CIRCUIT_BREAKER_PATTERNS)

    if has_service_calls and not has_breaker:
        findings.append({
            "severity": "medium",
            "check_id": "chaos.circuit_breaker.missing",
            "category": "circuit-breaker",
            "title": "Missing circuit breaker for external service calls",
            "description": f"File {file_path.name} makes external calls without circuit breaker",
            "file_path": str(file_path),
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Wrap external calls with a circuit breaker pattern",
        })


check_circuit_breaker_tool = function_tool(check_circuit_breaker)
