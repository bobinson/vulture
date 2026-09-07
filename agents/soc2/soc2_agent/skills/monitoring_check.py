"""Monitoring and alerting audit skill for SOC2."""

import re

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

MONITORING_PATTERNS = [
    re.compile(r"prometheus|grafana|datadog|newrelic|sentry", re.IGNORECASE),
    re.compile(r"metrics\.|counter\.|gauge\.|histogram\.", re.IGNORECASE),
    re.compile(r"health.?check|readiness|liveness", re.IGNORECASE),
    re.compile(r"alert|notification|pagerduty|opsgenie", re.IGNORECASE),
]

SERVICE_PATTERNS = [
    re.compile(r"@app\.route|func\s+\w+Handler|app\.listen"),
    re.compile(r"FastAPI|Flask|gin\.Default|Express"),
]


def check_monitoring(source_path: str) -> dict:
    """Check for monitoring, alerting, and observability.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of monitoring issues.
    """
    findings: list[dict] = []

    all_files = scan_code_files(source_path)

    has_monitoring = False
    has_service = False

    for file_path in all_files:
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        content = read_file_safe(file_path)
        if content is None:
            continue
        if any(p.search(content) for p in MONITORING_PATTERNS):
            has_monitoring = True
        if any(p.search(content) for p in SERVICE_PATTERNS):
            has_service = True

    if has_service and not has_monitoring:
        finding = {
            "severity": "medium",
            "check_id": "soc2.monitoring.absent",
            "category": "CC7-monitoring",
            "title": "No monitoring or alerting detected",
            "description": "Service code found but no monitoring/alerting instrumentation",
            "file_path": source_path,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Add metrics, health checks, and alerting integration",
        }
        finding["code_snippet"] = extract_snippet([], 0)
        findings.append(finding)

    return {"findings": findings}


check_monitoring_tool = function_tool(check_monitoring)
