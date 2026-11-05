"""Feature 0102: the in-tree agent compares its ``/run`` token in constant time.

A plain ``!=`` gives the same 403 and 200 answers, so only the comparison
itself can show which one runs: every check goes through
``hmac.compare_digest``, over bytes.
"""

from __future__ import annotations

import hmac

import pytest
from fastapi import HTTPException

from shared.transport import sse_app

TOKEN = "agent-run-token-0102"


@pytest.fixture
def compared(monkeypatch):
    """Record every ``hmac.compare_digest`` call, still answering as the real one."""
    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def recording(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(sse_app.hmac, "compare_digest", recording)
    monkeypatch.setattr(sse_app, "_AGENT_TOKEN", TOKEN)
    return calls


def test_token_check_uses_compare_digest_over_bytes(compared):
    sse_app._verify_agent_token(TOKEN)
    with pytest.raises(HTTPException) as refused:
        sse_app._verify_agent_token("not-the-token")
    assert refused.value.status_code == 403
    assert compared == [(TOKEN.encode(), TOKEN.encode()), (b"not-the-token", TOKEN.encode())]
