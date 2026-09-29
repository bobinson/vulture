"""Regenerate ``owasp_0096_mapping_stream.json`` from the real OWASP agent.

Feature 0096. The fixture is the OWASP agent's exact SSE output for one
mapping-mode request, together with the inputs that produced it:

- ``cwe_findings`` — the result a mock CWE agent returns in the backend flow
  test (``backend/test/e2e/owasp_mapping_flow_test.go``);
- ``priors`` — those findings as the backend forwards them to the OWASP agent
  (the ``findingsToPriors`` projection);
- ``config`` / ``run_id`` / ``accepts_mapping`` — the OWASP request as the
  backend sends it. ``accepts_mapping`` is the TOP-LEVEL /run capability field
  (feature 0096 §2.1, H1), never a ``config`` key;
- ``stream`` — what ``run_audit`` yielded, byte for byte.

The backend test replays ``stream`` from a mock OWASP agent, so the backend is
exercised against the payload the real agent emits rather than a hand-written
approximation of it. ``tests/e2e/test_0096_mapping.py`` re-runs the agent on
the same inputs and fails when the two drift; re-run this script (from
``agents/owasp``) to refresh the fixture after an intended change:

    PYTHONPATH=.:../shared ../.venv/bin/python tests/fixtures/regen_owasp_0096_mapping_stream.py
"""

from __future__ import annotations

import json
import pathlib

from owasp_agent.agent import run_audit

FIXTURE = pathlib.Path(__file__).with_name("owasp_0096_mapping_stream.json")

RUN_ID = "owasp-0096-flow"

# One row per file so cross-agent dedup cannot fold two of them together, and
# a spread that exercises every labelling branch: two CWEs in the selected
# categories, two mapped CWEs outside them, and one CWE no edition maps.
CWE_FINDINGS = [
    {"severity": "high", "category": "CWE-798", "title": "Hardcoded credential",
     "description": "secret assigned in source", "file_path": "config/secrets.py",
     "line_start": 3, "line_end": 3, "recommendation": "load from a vault",
     "provenance": "skill", "check_id": "cwe.secret.generic"},
    {"severity": "critical", "category": "CWE-89", "title": "SQL injection",
     "description": "string interpolation in query", "file_path": "app/db.py",
     "line_start": 12, "line_end": 12, "recommendation": "use parameters",
     "provenance": "skill", "check_id": "cwe.injection.sql"},
    {"severity": "high", "category": "CWE-918", "title": "Server-side request forgery",
     "description": "user-controlled url", "file_path": "app/net.py",
     "line_start": 7, "line_end": 7, "recommendation": "allowlist hosts",
     "provenance": "skill", "check_id": "cwe.injection.ssrf"},
    {"severity": "medium", "category": "CWE-532", "title": "Sensitive data in log",
     "description": "token written to a log", "file_path": "app/log.py",
     "line_start": 40, "line_end": 40, "recommendation": "redact",
     "provenance": "skill", "check_id": "cwe.logging.sensitive"},
    {"severity": "low", "category": "CWE-1234", "title": "Weakness no edition maps",
     "description": "unmapped", "file_path": "native/x.c",
     "line_start": 2, "line_end": 2, "recommendation": "review",
     "provenance": "skill", "check_id": "cwe.misc.unmapped"},
]

# The fields findingsToPriors carries (backend/internal/service/stream_service.go).
_PRIOR_FIELDS = ("title", "severity", "category", "description", "file_path",
                 "line_start", "line_end", "check_id", "provenance")

CONFIG = {
    "edition": "2025",
    "categories": ["A05", "A07"],
    "cwe_stage_status": "completed",
}

# The out-of-band capability the backend's agent proxy writes beside `config`.
ACCEPTS_MAPPING = 1


def priors() -> list[dict]:
    return [{k: f[k] for k in _PRIOR_FIELDS} for f in CWE_FINDINGS]


def build() -> dict:
    stream = "".join(run_audit(RUN_ID, "/unused", dict(CONFIG), prior_findings=priors(),
                               accepts_mapping=ACCEPTS_MAPPING))
    return {
        "run_id": RUN_ID,
        "config": CONFIG,
        "accepts_mapping": ACCEPTS_MAPPING,
        "cwe_findings": CWE_FINDINGS,
        "priors": priors(),
        "stream": stream,
    }


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(build(), indent=1) + "\n")
    print(f"wrote {FIXTURE}")
