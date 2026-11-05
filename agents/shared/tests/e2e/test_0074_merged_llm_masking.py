"""Feature 0074 verification item 1, end to end on the agent side.

An LLM row the agent collapses onto a skill row keeps its description in the
survivor's ``merged_llm``. That text rides the ``result`` snapshot to live SSE
clients and is persisted by Go as ``validation.merged_descriptions``, so it must
get the SAME secret-shape masking every finding's own description gets (0098):
a JWT, URL userinfo, a private-key body and a provider key must not survive
anywhere in the emitted payload. The payload also declares that its
``merged_llm`` descriptions are masked, so the backend can tell a masking agent
from an older one.

The model is never called; the real batch loop, final dedup and validate stage
run. Every value below is synthetic.
"""

from __future__ import annotations

import json

from tests.unit.test_0074_agent_dedup_counters import SKILL_CHECK_ID, _llm_env, _run

_JWT = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ0ZXN0LXVzZXIifQ." + "c2lnbmF0dXJlLXRlc3Qtb25seQ"
_URL_PASSWORD = "S3cr3tPassw0rdX9"
_URL = f"postgres://admin:{_URL_PASSWORD}@db.internal:5432/app"
_GOOGLE_KEY = "AIza" + "SyD-synthetic0000000000000000000000"
_PEM_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
_PEM = f"-----BEGIN RSA PRIVATE KEY-----\n{_PEM_BODY}\n-----END RSA PRIVATE KEY-----"
_RAW = (_JWT, _URL_PASSWORD, _GOOGLE_KEY, _PEM_BODY)

_DESCRIPTION = (
    f"The handler logs the token {_JWT}, connects with {_URL}, "
    f"embeds {_GOOGLE_KEY} and the key\n{_PEM}"
)


def _secret_rows(_batch: int) -> list[dict]:
    """The model echoes the skill row's check_id in its file, so the agent
    collapses this row onto the skill row; its description holds the secrets."""
    return [{
        "severity": "high", "category": "injection", "title": "Query built by concatenation",
        "description": _DESCRIPTION, "file_path": "a0.py", "line_start": 9, "line_end": 9,
        "recommendation": "fix", "check_id": SKILL_CHECK_ID,
    }]


def test_collapsed_llm_description_is_masked_in_the_result(monkeypatch, tmp_path) -> None:
    _llm_env(monkeypatch, tmp_path, _secret_rows)
    payload = json.loads(json.dumps(_run(tmp_path, "0074-v1-mask", use_llm=True)))
    survivors = [f for f in payload["findings"]
                 if f.get("check_id") == SKILL_CHECK_ID and f.get("provenance") == "skill"]
    assert len(survivors) == 1 and survivors[0].get("merged_llm"), "the pair collapsed in the agent"
    merged = survivors[0]["merged_llm"][0]["description"]
    assert "***REDACTED***" in merged and "db.internal:5432/app" in merged, merged
    wire = json.dumps(payload)
    leaked = [value for value in _RAW if value in wire]
    assert not leaked, f"raw secret values reached the result payload: {leaked}"
    assert payload.get("merged_llm_masked") is True
