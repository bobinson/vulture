"""RED team: MCP tool tests. Must FAIL until server.py implements the tools."""
import asyncio
import contextlib
import json
import pathlib
from time import monotonic

import httpx
import pytest
import respx

LINEAGE_RESPONSE = [
    {"id": "lin-1", "fingerprint": "fp1", "current_status": "open", "ref_number": 1, "ref": "VLT-0001"},
    {"id": "lin-2", "fingerprint": "fp2", "current_status": "false_positive", "ref_number": 2, "ref": "VLT-0002"},
    {"id": "lin-3", "fingerprint": "fp3", "current_status": "open", "ref_number": 3, "ref": "VLT-0003"},
]

AUDIT_RESPONSE = {
    "id": "a1",
    "source_path": "/src/project",
    "types": ["owasp", "cwe"],
    "status": "completed",
    "findings_count": 3,
    "scores": {"owasp": 72, "cwe": 85},
    "webhook_url": "https://internal.corp/hook",
    "findings": [
        {
            "fingerprint": "fp1", "severity": "critical", "category": "injection",
            "agent_type": "owasp", "title": "SQL injection",
            "description": 'Query uses password="secret123"',
            "file_path": "/app/db.py", "line_start": 10, "line_end": 10,
            "recommendation": "Use parameterized queries", "check_id": "owasp.injection.sql",
        },
        {
            "fingerprint": "fp2", "severity": "medium", "category": "crypto",
            "agent_type": "cwe", "title": "Weak hash",
            "description": "MD5 used for passwords",
            "file_path": "/app/auth.py", "line_start": 25, "line_end": 25,
            "recommendation": "Use bcrypt", "check_id": "cwe.crypto.weak_hash",
        },
        {
            "fingerprint": "fp3", "severity": "critical", "category": "injection",
            "agent_type": "cwe", "title": "Command injection",
            "description": "os.system call",
            "file_path": "/app/utils.py", "line_start": 5, "line_end": 5,
            "recommendation": "Use subprocess with shell=False", "check_id": "cwe.injection.cmd",
        },
    ],
    "created_at": "2026-01-01T00:00:00Z",
    "completed_at": "2026-01-01T00:01:00Z",
}


@respx.mock
@pytest.mark.asyncio
async def test_list_audits_strips_internals():
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[AUDIT_RESPONSE])
    )
    from server import vulture_list_audits
    result = await vulture_list_audits(limit=10)
    assert len(result) == 1
    assert "findings" not in result[0]
    assert "prove_results" not in result[0]
    assert "webhook_url" not in result[0]


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_returns_paginated():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=[])
    )
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="a1", limit=2, offset=0)
    assert "findings" in result
    assert len(result["findings"]) == 2
    assert result["total"] == 3
    assert result["has_more"] is True
    assert result["next_offset"] == 2


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_filters_by_severity():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=[])
    )
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="a1", severity="critical")
    assert all(f["severity"] == "critical" for f in result["findings"])
    assert result["total"] == 2


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_redacts_secrets():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=[])
    )
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="a1")
    descs = [f["description"] for f in result["findings"]]
    for desc in descs:
        assert "secret123" not in desc


@respx.mock
@pytest.mark.asyncio
async def test_get_finding_detail_includes_lineage():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=[
            {"fingerprint": "fp1", "current_status": "open", "first_found_at": "2026-01-01"}
        ])
    )
    from server import vulture_get_finding_detail
    result = await vulture_get_finding_detail(audit_id="a1", fingerprint="fp1")
    assert result["fingerprint"] == "fp1"
    assert "lineage" in result
    assert result["lineage"]["current_status"] == "open"


@respx.mock
@pytest.mark.asyncio
async def test_get_finding_detail_missing_fingerprint():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    from server import vulture_get_finding_detail
    with pytest.raises(ValueError, match="not found"):
        await vulture_get_finding_detail(audit_id="a1", fingerprint="nonexistent")


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_redacts_content():
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=[
            {"title": "Secret leak", "content": 'password="hunter2"', "severity": "high"}
        ])
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="password")
    assert "hunter2" not in result[0].get("content", "")


@pytest.mark.asyncio
async def test_update_status_blocked_by_default(monkeypatch):
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "false")
    from server import vulture_update_status
    with pytest.raises(PermissionError, match="write access disabled"):
        await vulture_update_status(lineage_id="l1", status="false_positive")


@pytest.mark.asyncio
async def test_update_status_rejects_invalid_status(monkeypatch):
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "true")
    from server import vulture_update_status
    with pytest.raises(ValueError, match="Invalid status"):
        await vulture_update_status(lineage_id="l1", status="regression")


@respx.mock
@pytest.mark.asyncio
async def test_update_status_works_when_enabled(monkeypatch):
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "true")
    respx.patch("http://localhost:28080/api/lineage/l1").mock(
        return_value=httpx.Response(200, json={"id": "l1", "current_status": "false_positive"})
    )
    from server import vulture_update_status
    result = await vulture_update_status(lineage_id="l1", status="false_positive", notes="not a real issue")
    assert result["current_status"] == "false_positive"


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_includes_ref_and_lineage_status():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json=AUDIT_RESPONSE)
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=LINEAGE_RESPONSE)
    )
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="a1")
    f1 = result["findings"][0]
    assert f1["ref"] == "VLT-0001"
    assert f1["lineage_id"] == "lin-1"
    assert f1["lineage_status"] == "open"


@respx.mock
@pytest.mark.asyncio
async def test_update_status_by_ref(monkeypatch):
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "true")
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[{"id": "a1"}])
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=LINEAGE_RESPONSE)
    )
    respx.patch("http://localhost:28080/api/lineage/lin-1").mock(
        return_value=httpx.Response(200, json={"id": "lin-1", "current_status": "false_positive"})
    )
    from server import vulture_update_status
    result = await vulture_update_status(ref="VLT-0001", status="false_positive", notes="not a real issue")
    assert result["current_status"] == "false_positive"


@respx.mock
@pytest.mark.asyncio
async def test_update_status_by_fingerprint(monkeypatch):
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "true")
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[{"id": "a1"}])
    )
    respx.get("http://localhost:28080/api/audits/a1/lineage").mock(
        return_value=httpx.Response(200, json=LINEAGE_RESPONSE)
    )
    respx.patch("http://localhost:28080/api/lineage/lin-2").mock(
        return_value=httpx.Response(200, json={"id": "lin-2", "current_status": "fixed"})
    )
    from server import vulture_update_status
    result = await vulture_update_status(fingerprint="fp2", status="fixed")
    assert result["current_status"] == "fixed"


# ---------------------------------------------------------------------------
# Feature 0096: OWASP is a label on CWE-categorised findings, not an agent's rows
# ---------------------------------------------------------------------------

def _owasp_label(cat_id: str, name: str, cwe: str, edition: str = "2025") -> dict:
    return {"framework": "owasp", "edition": edition, "category_id": cat_id,
            "category_name": name, "cwe": cwe}


# A mapping-mode audit: the OWASP agent ran, persisted no rows of its own, and
# the backend labelled the CWE-categorised findings of the scan agents.
MAPPED_AUDIT_RESPONSE = {
    "id": "m1",
    "source_path": "/src/project",
    "types": ["owasp", "cwe", "xss"],
    "status": "completed",
    "findings_count": 4,
    "findings": [
        {
            "fingerprint": "mf1", "severity": "critical", "category": "CWE-798",
            "agent_type": "cwe", "title": "Hard-coded credential",
            "description": "literal key", "file_path": "/app/cfg.py", "line_start": 3,
            "compliance_labels": [_owasp_label("A07", "Authentication Failures", "CWE-798")],
        },
        {
            "fingerprint": "mf2", "severity": "high", "category": "CWE-89",
            "agent_type": "cwe", "title": "SQL injection",
            "description": "string concat", "file_path": "/app/db.py", "line_start": 10,
            "compliance_labels": [_owasp_label("A05", "Injection", "CWE-89")],
        },
        {
            "fingerprint": "mf3", "severity": "medium", "category": "CWE-79",
            "agent_type": "xss", "title": "Reflected XSS",
            "description": "unescaped echo", "file_path": "/app/view.js", "line_start": 7,
            "compliance_labels": [_owasp_label("A05", "Injection", "CWE-79")],
        },
        {
            "fingerprint": "mf4", "severity": "low", "category": "retry",
            "agent_type": "chaos", "title": "No retry", "description": "bare call",
            "file_path": "/app/net.py", "line_start": 1,
        },
    ],
}


def _mock_mapped_audit():
    respx.get("http://localhost:28080/api/audits/m1").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    respx.get("http://localhost:28080/api/audits/m1/lineage").mock(
        return_value=httpx.Response(200, json=[])
    )


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_filters_by_framework_category_over_labels():
    _mock_mapped_audit()
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="m1", framework="owasp", category="A07")
    assert result["total"] == 1
    assert [f["fingerprint"] for f in result["findings"]] == ["mf1"]
    assert result["findings"][0]["compliance_labels"][0]["category_id"] == "A07"


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_framework_category_spans_agents():
    _mock_mapped_audit()
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="m1", framework="owasp", category="A05")
    assert sorted(f["fingerprint"] for f in result["findings"]) == ["mf2", "mf3"]
    assert {f["agent_type"] for f in result["findings"]} == {"cwe", "xss"}


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_framework_alone_returns_every_labelled_finding():
    _mock_mapped_audit()
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="m1", framework="owasp")
    assert result["total"] == 3
    assert "mf4" not in {f["fingerprint"] for f in result["findings"]}


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_framework_composes_with_agent_type_and_severity():
    _mock_mapped_audit()
    from server import vulture_get_findings
    result = await vulture_get_findings(
        audit_id="m1", framework="owasp", category="A05", agent_type="xss", severity="medium",
    )
    assert [f["fingerprint"] for f in result["findings"]] == ["mf3"]


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_framework_input_is_case_insensitive():
    _mock_mapped_audit()
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="m1", framework="OWASP", category="a07")
    assert [f["fingerprint"] for f in result["findings"]] == ["mf1"]


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_agent_type_owasp_stays_literal_on_mapping_audit():
    _mock_mapped_audit()
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="m1", agent_type="owasp")
    assert result["total"] == 0
    assert result["findings"] == []


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_category_without_framework_stays_literal():
    _mock_mapped_audit()
    from server import vulture_get_findings
    literal = await vulture_get_findings(audit_id="m1", category="CWE-89")
    assert [f["fingerprint"] for f in literal["findings"]] == ["mf2"]
    # "A07" is not any finding's own category, so a literal filter finds nothing.
    assert (await vulture_get_findings(audit_id="m1", category="A07"))["total"] == 0


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_framework_matches_pre_0096_owasp_rows():
    # The shape GET /api/audits/{id} really returns for a pre-0096 OWASP copy
    # row: the category id lives only in check_id and the category slug.
    legacy = {
        "id": "l1", "status": "completed",
        "findings": [
            {"fingerprint": "lf1", "severity": "high", "category": "A07-authentication-failures",
             "check_id": "owasp.A07.cwe-798", "agent_type": "owasp",
             "title": "[A07] Hard-coded credential"},
            {"fingerprint": "lf2", "severity": "high", "category": "CWE-798",
             "check_id": "cwe.CWE-798.hardcoded", "agent_type": "cwe",
             "title": "Hard-coded credential"},
            {"fingerprint": "lf3", "severity": "high", "category": "A01-broken-access-control",
             "check_id": "owasp.A01.cwe-862", "agent_type": "owasp",
             "title": "[A01] Route handler without authorization"},
        ],
    }
    respx.get("http://localhost:28080/api/audits/l1").mock(return_value=httpx.Response(200, json=legacy))
    respx.get("http://localhost:28080/api/audits/l1/lineage").mock(return_value=httpx.Response(200, json=[]))
    from server import vulture_get_findings
    result = await vulture_get_findings(audit_id="l1", framework="owasp", category="A07")
    assert [f["fingerprint"] for f in result["findings"]] == ["lf1"]
    every = await vulture_get_findings(audit_id="l1", framework="owasp")
    assert sorted(f["fingerprint"] for f in every["findings"]) == ["lf1", "lf3"]


@pytest.mark.parametrize("row, want", [
    # check_id alone, and the category slug alone, each carry the id.
    ({"agent_type": "owasp", "category": "", "check_id": "owasp.A07.cwe-798"}, ["A07"]),
    ({"agent_type": "owasp", "category": "A07-authentication-failures"}, ["A07"]),
    # Only an OWASP agent row is read this way; another agent's look-alike is not.
    ({"agent_type": "cwe", "category": "A07-authentication-failures",
      "check_id": "owasp.A07.cwe-798"}, []),
    ({"agent_type": "owasp", "category": "CWE-798", "check_id": "owasp.x"}, []),
])
def test_pre_0096_owasp_row_label_comes_from_persisted_fields(row, want):
    from server import _framework_labels
    assert [lb["category_id"] for lb in _framework_labels(row)] == want


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs, match", [
    ({"framework": "pci"}, "framework"),
    ({"framework": ""}, "framework"),
    ({"framework": "owasp", "category": "A7"}, "category"),
    ({"framework": "owasp", "category": "injection"}, "category"),
    ({"framework": "owasp", "category": "A07:2025"}, "category"),
    ({"framework": "owasp", "category": "CWE-89"}, "category"),
])
async def test_get_findings_rejects_invalid_framework_filters_before_any_request(kwargs, match):
    # respx.mock with no routes: any HTTP call would fail with a respx error, so
    # a ValueError proves validation ran before the backend was contacted.
    from server import vulture_get_findings
    with pytest.raises(ValueError, match=match):
        await vulture_get_findings(audit_id="m1", **kwargs)


# The shape GET /api/memories/search really returns: no fingerprint, no labels.
MEMORY_RESULTS = [
    {"id": "mem-1", "audit_id": "m1", "agent_type": "cwe", "category": "CWE-798",
     "title": "Hard-coded credential", "content": 'token="abcdefgh"', "severity": "critical",
     "finding_type": "hardcoded-credential", "file_paths": ["/app/cfg.py"], "similarity": 0.9},
    {"id": "mem-2", "audit_id": "m1", "agent_type": "cwe", "category": "CWE-89",
     "title": "SQL injection", "content": "concat", "severity": "high",
     "finding_type": "sql-injection", "file_paths": ["/app/db.py"], "similarity": 0.8},
    {"id": "mem-3", "audit_id": "m1", "agent_type": "chaos", "category": "retry",
     "title": "No retry", "content": "bare call", "severity": "low",
     "finding_type": "retry", "file_paths": ["/app/net.py"], "similarity": 0.7},
]


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_filters_by_framework_category_over_labels():
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=MEMORY_RESULTS)
    )
    _mock_mapped_audit()
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", framework="owasp", category="A07")
    assert [r["id"] for r in result] == ["mem-1"]
    assert result[0]["compliance_labels"][0]["category_id"] == "A07"
    assert "abcdefgh" not in result[0]["content"]


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_framework_alone_keeps_labelled_only():
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=MEMORY_RESULTS)
    )
    audit_route = respx.get("http://localhost:28080/api/audits/m1").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="anything", framework="owasp")
    assert [r["id"] for r in result] == ["mem-1", "mem-2"]
    # One lookup per distinct audit, not one per memory.
    assert audit_route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_uses_labels_carried_on_the_record():
    carried = [dict(MEMORY_RESULTS[0], compliance_labels=[_owasp_label("A07", "Auth", "CWE-798")])]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=carried)
    )
    audit_route = respx.get("http://localhost:28080/api/audits/m1").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", framework="owasp", category="A07")
    assert [r["id"] for r in result] == ["mem-1"]
    assert audit_route.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_without_framework_makes_no_audit_lookup():
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=MEMORY_RESULTS)
    )
    audit_route = respx.get("http://localhost:28080/api/audits/m1").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="anything")
    assert len(result) == 3
    literal = await vulture_search_findings(query="anything", category="CWE-89")
    assert [r["id"] for r in literal] == ["mem-2"]
    assert audit_route.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_many_audits_do_not_trip_the_rate_limit(monkeypatch):
    # Memories of one finding recur across many audits of the same codebase; a
    # framework filter must still answer rather than fail on the client's own
    # request pacing.
    monkeypatch.setenv("VULTURE_MCP_RATE_LIMIT", "3")
    many = [dict(MEMORY_RESULTS[0], id=f"mem-{i}", audit_id=f"a{i}") for i in range(5)]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=many)
    )
    respx.get(url__regex=r"http://localhost:28080/api/audits/a\d$").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", framework="owasp", category="A07")
    assert len(result) == 5


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_matches_pre_0096_owasp_memories_without_a_lookup():
    legacy = [{"id": "mem-l", "audit_id": "l1", "agent_type": "owasp",
               "category": "A07-authentication-failures", "title": "[A07] Hard-coded credential",
               "content": "x", "severity": "high"}]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=legacy)
    )
    audit_route = respx.get("http://localhost:28080/api/audits/l1").mock(
        return_value=httpx.Response(200, json={"id": "l1", "findings": []})
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", framework="owasp", category="A07")
    assert [r["id"] for r in result] == ["mem-l"]
    assert audit_route.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_bounds_the_audit_lookups_to_the_most_relevant():
    # Records arrive most-similar first, each from its own audit. The label
    # lookup is bounded, so it resolves the leading audits and no more. The
    # audit ids sort in the REVERSE of relevance order, so a selection by id
    # instead of by relevance resolves the wrong audits.
    from server import _LABEL_LOOKUP_MAX_AUDITS as cap
    many = [dict(MEMORY_RESULTS[0], id=f"mem-{i:02d}", audit_id=f"b{(cap + 4 - i):02d}")
            for i in range(cap + 5)]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=many)
    )
    audit_route = respx.get(url__regex=r"http://localhost:28080/api/audits/b\d\d$").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", limit=100, framework="owasp")
    fetched = [call.request.url.path.rsplit("/", 1)[-1] for call in audit_route.calls]
    assert fetched == [r["audit_id"] for r in many[:cap]]
    assert [r["id"] for r in result] == [r["id"] for r in many[:cap]]


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 500])
async def test_search_findings_skips_an_audit_whose_lookup_fails(status):
    # One unreadable audit (deleted, or the server erring) must not fail the
    # whole search: its records stay unlabelled, the other audits still match.
    records = [dict(MEMORY_RESULTS[0], id="mem-gone", audit_id="gone"), MEMORY_RESULTS[0]]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=records)
    )
    gone_route = respx.get("http://localhost:28080/api/audits/gone").mock(
        return_value=httpx.Response(status, json={"error": "not found"})
    )
    ok_route = respx.get("http://localhost:28080/api/audits/m1").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", framework="owasp", category="A07")
    assert [r["id"] for r in result] == ["mem-1"]
    assert gone_route.call_count == 1 and ok_route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_answers_promptly_while_other_sessions_keep_the_client_busy():
    # Every MCP session shares one client. Another session holding half the
    # rate window or more (while staying under the limit) must not hang a
    # framework-filtered search: once a label lookup cannot get a slot within
    # the client's wait bound the search answers with what it resolved, and
    # it does not spend that bound again on every remaining audit.
    import server
    from server import _LABEL_LOOKUP_MAX_AUDITS as cap
    many = [dict(MEMORY_RESULTS[0], id=f"mem-{i}", audit_id=f"c{i}") for i in range(cap)]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=many)
    )
    audit_route = respx.get(url__regex=r"http://localhost:28080/api/audits/c\d$").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    client = await server._get_client()
    rejected = 0

    async def other_session():
        nonlocal rejected
        while True:
            try:
                await client._enforce_rate_limit()
            except Exception:
                rejected += 1
            await asyncio.sleep(0.15)  # ~6.7 req/s: under 10, over half

    busy = asyncio.create_task(other_session())
    try:
        await asyncio.sleep(1.2)
        started = monotonic()
        result = await asyncio.wait_for(
            server.vulture_search_findings(query="credential", framework="owasp"), timeout=10)
        elapsed = monotonic() - started
    finally:
        busy.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await busy
    assert elapsed < 5, elapsed
    assert result == [] and audit_route.call_count == 0
    assert rejected == 0


def test_search_findings_description_states_the_lookup_bound():
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    assert str(server._LABEL_LOOKUP_MAX_AUDITS) in tools["vulture_search_findings"].description


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs, match", [
    ({"framework": "soc2"}, "framework"),
    ({"framework": "owasp", "category": "A1"}, "category"),
])
async def test_search_findings_rejects_invalid_framework_filters_before_any_request(kwargs, match):
    from server import vulture_search_findings
    with pytest.raises(ValueError, match=match):
        await vulture_search_findings(query="x", **kwargs)


@pytest.mark.parametrize("tool_name", ["vulture_get_findings", "vulture_search_findings"])
def test_finding_tool_descriptions_point_callers_at_framework_owasp(tool_name):
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    desc = tools[tool_name].description
    assert 'framework="owasp"' in desc
    params = tools[tool_name].parameters["properties"]
    assert "framework" in params and "category" in params


def test_get_findings_description_says_agent_type_owasp_is_literal():
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    desc = tools["vulture_get_findings"].description
    assert "agent_type" in desc and "literal" in desc


# ---------------------------------------------------------------------------
# A category id is edition-specific: A03 is Injection in OWASP 2021 and
# Software Supply Chain Failures in 2025. `edition` tells them apart.
# ---------------------------------------------------------------------------

EDITION_AUDITS = {
    "e21": {"id": "e21", "findings": [
        {"fingerprint": "x21", "category": "CWE-89", "agent_type": "cwe", "severity": "high",
         "compliance_labels": [_owasp_label("A03", "Injection", "CWE-89", edition="2021")]},
    ]},
    "e25": {"id": "e25", "findings": [
        {"fingerprint": "x25", "category": "CWE-1104", "agent_type": "cwe", "severity": "high",
         "compliance_labels": [_owasp_label("A03", "Software Supply Chain Failures", "CWE-1104")]},
    ]},
}

EDITION_MEMORIES = [
    {"id": "m21", "audit_id": "e21", "agent_type": "cwe", "category": "CWE-89",
     "title": "SQL injection", "content": "concat", "severity": "high"},
    {"id": "m25", "audit_id": "e25", "agent_type": "cwe", "category": "CWE-1104",
     "title": "Unmaintained dependency", "content": "old lib", "severity": "high"},
]


def _mock_edition_audits():
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=EDITION_MEMORIES)
    )
    for aid, body in EDITION_AUDITS.items():
        respx.get(f"http://localhost:28080/api/audits/{aid}").mock(
            return_value=httpx.Response(200, json=body)
        )
        respx.get(f"http://localhost:28080/api/audits/{aid}/lineage").mock(
            return_value=httpx.Response(200, json=[])
        )


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_edition_separates_a_category_id_across_editions():
    _mock_edition_audits()
    from server import vulture_search_findings
    q = {"query": "x", "framework": "owasp", "category": "A03"}
    assert [r["id"] for r in await vulture_search_findings(**q, edition="2021")] == ["m21"]
    assert [r["id"] for r in await vulture_search_findings(**q, edition="2025")] == ["m25"]
    # Without an edition the id matches in every edition, and each record's
    # labels say which one it was.
    mixed = await vulture_search_findings(**q)
    assert {r["id"]: r["compliance_labels"][0]["edition"] for r in mixed} == {"m21": "2021", "m25": "2025"}


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_edition_alone_keeps_that_editions_labels():
    _mock_edition_audits()
    from server import vulture_search_findings
    result = await vulture_search_findings(query="x", framework="owasp", edition="2021")
    assert [r["id"] for r in result] == ["m21"]


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_filters_by_edition():
    _mock_mapped_audit()  # a 2025-labelled audit
    from server import vulture_get_findings
    hit = await vulture_get_findings(audit_id="m1", framework="owasp", category="A07", edition="2025")
    assert [f["fingerprint"] for f in hit["findings"]] == ["mf1"]
    miss = await vulture_get_findings(audit_id="m1", framework="owasp", category="A07", edition="2021")
    assert miss["total"] == 0
    assert (await vulture_get_findings(audit_id="m1", framework="owasp", edition=" 2021 "))["total"] == 0


LEGACY_EDITION_AUDIT = {
    "id": "l2", "findings": [
        # The category slug names its edition: "A03-injection" exists only in 2021.
        {"fingerprint": "s21", "category": "A03-injection", "check_id": "owasp.A03.cwe-89",
         "agent_type": "owasp", "severity": "high"},
        {"fingerprint": "s25", "category": "A03-software-supply-chain-failures",
         "check_id": "owasp.A03.cwe-1104", "agent_type": "owasp", "severity": "high"},
        # Same slug in both editions, and a row with a check_id only: no edition.
        {"fingerprint": "sA1", "category": "A01-broken-access-control",
         "check_id": "owasp.A01.cwe-862", "agent_type": "owasp", "severity": "high"},
        {"fingerprint": "sNo", "category": "", "check_id": "owasp.A03.cwe-89",
         "agent_type": "owasp", "severity": "high"},
    ],
}


@respx.mock
@pytest.mark.asyncio
async def test_pre_0096_owasp_rows_match_an_edition_only_when_their_slug_names_it():
    respx.get("http://localhost:28080/api/audits/l2").mock(
        return_value=httpx.Response(200, json=LEGACY_EDITION_AUDIT))
    respx.get("http://localhost:28080/api/audits/l2/lineage").mock(
        return_value=httpx.Response(200, json=[]))
    from server import vulture_get_findings

    async def fps(**kw):
        res = await vulture_get_findings(audit_id="l2", framework="owasp", **kw)
        return sorted(f["fingerprint"] for f in res["findings"])

    assert await fps(category="A03", edition="2021") == ["s21"]
    assert await fps(category="A03", edition="2025") == ["s25"]
    assert await fps(category="A01", edition="2025") == []
    assert await fps(category="A03") == ["s21", "s25", "sNo"]
    assert await fps(category="A01") == ["sA1"]


@pytest.mark.parametrize("row, edition", [
    ({"agent_type": "owasp", "category": "A10-ssrf"}, "2021"),
    ({"agent_type": "owasp", "category": "A07-authentication-failures"}, "2025"),
    ({"agent_type": "owasp", "category": "A01-broken-access-control"}, ""),
    ({"agent_type": "owasp", "category": "", "check_id": "owasp.A07.cwe-798"}, ""),
])
def test_pre_0096_owasp_row_label_carries_the_edition_its_slug_names(row, edition):
    from server import _framework_labels
    assert [lb["edition"] for lb in _framework_labels(row)] == [edition]


def test_legacy_slug_editions_match_the_edition_tables():
    # Pre-0096 rows were written with the 2021 and 2025 tables' slugs; a slug
    # names an edition exactly when only one of those tables has it.
    from server import _LEGACY_OWASP_SLUG_EDITIONS
    root = pathlib.Path(__file__).resolve().parents[2] / "agents/shared/shared/owasp/editions"
    seen: dict[str, set[str]] = {}
    for edition in ("2021", "2025"):
        table = json.loads((root / f"owasp_{edition}.json").read_text())
        for cat in table["categories"]:
            seen.setdefault(cat["slug"], set()).add(edition)
    want = {slug: eds.pop() for slug, eds in seen.items() if len(eds) == 1}
    assert _LEGACY_OWASP_SLUG_EDITIONS == want


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("tool, kwargs, match", [
    ("vulture_get_findings", {"framework": "owasp", "edition": "25"}, "edition"),
    ("vulture_get_findings", {"framework": "owasp", "edition": "2025a"}, "edition"),
    ("vulture_get_findings", {"edition": "2025"}, "framework"),
    ("vulture_search_findings", {"framework": "owasp", "edition": "OWASP-2025"}, "edition"),
    ("vulture_search_findings", {"edition": "2021", "category": "A03"}, "framework"),
])
async def test_edition_filter_is_validated_before_any_request(tool, kwargs, match):
    import server
    base = {"audit_id": "m1"} if tool == "vulture_get_findings" else {"query": "x"}
    with pytest.raises(ValueError, match=match):
        await getattr(server, tool)(**base, **kwargs)


@pytest.mark.parametrize("tool_name", ["vulture_get_findings", "vulture_search_findings"])
def test_finding_tool_descriptions_say_a_category_id_is_edition_specific(tool_name):
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    assert "edition" in tools[tool_name].parameters["properties"]
    desc = tools[tool_name].description
    assert 'edition="2025"' in desc and "edition-specific" in desc


# ---------------------------------------------------------------------------
# The label lookup is spent only on records that can carry a label, and a
# match it leaves out is reported rather than dropped in silence.
# ---------------------------------------------------------------------------

@respx.mock
@pytest.mark.asyncio
async def test_search_findings_spends_label_lookups_only_on_records_that_can_carry_labels():
    # Only a CWE-categorised record of a scan agent can carry an OWASP label.
    # Records that never can (a chaos pattern category, an OWASP agent row whose
    # fields name no category id) lead the relevance order from more distinct
    # audits than the lookup bound; the one real match comes last and must
    # still be resolved.
    from server import _LABEL_LOOKUP_MAX_AUDITS as cap
    never = [{"id": f"n-{i:02d}", "audit_id": f"n{i:02d}", "agent_type": "chaos",
              "category": "retry", "title": "No retry", "content": "x", "severity": "low"}
             for i in range(cap)]
    never.append({"id": "o-1", "audit_id": "o1", "agent_type": "owasp", "category": "injection",
                  "title": "Injection", "content": "x", "severity": "high"})
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=never + [MEMORY_RESULTS[0]])
    )
    wasted = respx.get(url__regex=r"http://localhost:28080/api/audits/(n\d\d|o1)$").mock(
        return_value=httpx.Response(200, json={"id": "n", "findings": []})
    )
    real = respx.get("http://localhost:28080/api/audits/m1").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="credential", limit=100, framework="owasp")
    assert [r["id"] for r in result] == ["mem-1"]
    assert wasted.call_count == 0 and real.call_count == 1


class _Warnings:
    """A stand-in MCP context that records the warnings a tool sends."""

    def __init__(self):
        self.messages: list[str] = []

    async def warning(self, message: str, **_):
        self.messages.append(message)


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_reports_matches_the_lookup_bound_left_out():
    from server import _LABEL_LOOKUP_MAX_AUDITS as cap
    many = [dict(MEMORY_RESULTS[0], id=f"mem-{i:02d}", audit_id=f"t{i:02d}") for i in range(cap + 2)]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=many)
    )
    respx.get(url__regex=r"http://localhost:28080/api/audits/t\d\d$").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    from server import vulture_search_findings
    ctx = _Warnings()
    result = await vulture_search_findings(query="credential", limit=100, framework="owasp", ctx=ctx)
    assert len(result) == cap
    assert len(ctx.messages) == 1
    msg = ctx.messages[0]
    assert "2 match" in msg and "2 audit" in msg and str(cap) in msg


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_reports_matches_left_out_while_the_client_is_busy(monkeypatch):
    import server
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=EDITION_MEMORIES)
    )

    async def busy(self, audit_id, wait=False):
        raise server.RateLimitExceeded("busy")

    monkeypatch.setattr(server.VultureClient, "get_audit", busy)
    ctx = _Warnings()
    result = await server.vulture_search_findings(query="x", framework="owasp", ctx=ctx)
    assert result == []
    assert len(ctx.messages) == 1 and "2 match" in ctx.messages[0] and "busy" in ctx.messages[0]


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_sends_no_warning_when_every_label_was_resolved():
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=MEMORY_RESULTS)
    )
    _mock_mapped_audit()
    from server import vulture_search_findings
    ctx = _Warnings()
    assert [r["id"] for r in await vulture_search_findings(query="x", framework="owasp", ctx=ctx)] \
        == ["mem-1", "mem-2"]
    assert ctx.messages == []


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_left_out_warning_reaches_a_connected_mcp_client():
    # Over the real protocol: the tool call answers, and the client receives
    # the report as a warning log message for that call.
    import server
    from mcp.shared.memory import create_connected_server_and_client_session
    from server import _LABEL_LOOKUP_MAX_AUDITS as cap
    many = [dict(MEMORY_RESULTS[0], id=f"mem-{i:02d}", audit_id=f"u{i:02d}") for i in range(cap + 1)]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=many)
    )
    respx.get(url__regex=r"http://localhost:28080/api/audits/u\d\d$").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    received = []

    async def on_log(params):
        received.append(params)

    async with create_connected_server_and_client_session(server.mcp, logging_callback=on_log) as session:
        out = await session.call_tool("vulture_search_findings",
                                      {"query": "credential", "limit": 100, "framework": "owasp"})
    assert not out.isError
    assert [p.level for p in received] == ["warning"]
    assert "1 match" in str(received[0].data)


@respx.mock
@pytest.mark.asyncio
async def test_search_findings_called_outside_a_request_still_answers():
    # FastMCP hands a tool a request-less context when it is called directly
    # (mcp.call_tool); a report that cannot be sent must not fail the search.
    import server
    from server import _LABEL_LOOKUP_MAX_AUDITS as cap
    many = [dict(MEMORY_RESULTS[0], id=f"mem-{i:02d}", audit_id=f"v{i:02d}") for i in range(cap + 1)]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=many)
    )
    respx.get(url__regex=r"http://localhost:28080/api/audits/v\d\d$").mock(
        return_value=httpx.Response(200, json=MAPPED_AUDIT_RESPONSE)
    )
    out = await server.mcp.call_tool("vulture_search_findings",
                                     {"query": "credential", "limit": 100, "framework": "owasp"})
    assert out  # answered with the resolved matches


def test_search_findings_context_is_not_a_tool_parameter():
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    assert "ctx" not in tools["vulture_search_findings"].parameters["properties"]


# ---------------------------------------------------------------------------
# A pre-0096 OWASP row that matches a framework filter carries the label it
# matched on, marked legacy, so every matched record has `compliance_labels`.
# ---------------------------------------------------------------------------

@respx.mock
@pytest.mark.asyncio
async def test_search_findings_pre_0096_owasp_match_carries_its_legacy_label():
    legacy = [
        {"id": "mem-l", "audit_id": "l1", "agent_type": "owasp",
         "category": "A07-authentication-failures", "title": "[A07] Hard-coded credential",
         "content": "x", "severity": "high"},
        {"id": "mem-u", "audit_id": "l1", "agent_type": "owasp",
         "category": "A01-broken-access-control", "title": "[A01] No authz",
         "content": "x", "severity": "high"},
    ]
    respx.get("http://localhost:28080/api/memories/search").mock(
        return_value=httpx.Response(200, json=legacy)
    )
    from server import vulture_search_findings
    result = await vulture_search_findings(query="x", framework="owasp")
    labels = {r["id"]: r["compliance_labels"] for r in result}
    assert labels == {
        "mem-l": [{"framework": "owasp", "edition": "2025", "category_id": "A07",
                   "category_name": "", "legacy": True}],
        "mem-u": [{"framework": "owasp", "edition": "", "category_id": "A01",
                   "category_name": "", "legacy": True}],
    }


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_pre_0096_owasp_match_carries_its_legacy_label():
    respx.get("http://localhost:28080/api/audits/l2").mock(
        return_value=httpx.Response(200, json=LEGACY_EDITION_AUDIT))
    respx.get("http://localhost:28080/api/audits/l2/lineage").mock(
        return_value=httpx.Response(200, json=[]))
    from server import vulture_get_findings
    res = await vulture_get_findings(audit_id="l2", framework="owasp", category="A03")
    got = {f["fingerprint"]: (f["compliance_labels"][0]["edition"], f["compliance_labels"][0]["legacy"])
           for f in res["findings"]}
    assert got == {"s21": ("2021", True), "s25": ("2025", True), "sNo": ("", True)}


@respx.mock
@pytest.mark.asyncio
async def test_current_labels_are_not_marked_legacy():
    _mock_mapped_audit()
    from server import vulture_get_findings
    res = await vulture_get_findings(audit_id="m1", framework="owasp", category="A07")
    assert "legacy" not in res["findings"][0]["compliance_labels"][0]


@pytest.mark.parametrize("tool_name", ["vulture_get_findings", "vulture_search_findings"])
def test_finding_tool_descriptions_state_the_legacy_label_contract(tool_name):
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    desc = tools[tool_name].description
    assert "`compliance_labels`" in desc and "`legacy`" in desc and 'edition ""' in desc


def test_search_findings_description_says_left_out_matches_are_reported():
    import server
    tools = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    desc = tools["vulture_search_findings"].description
    assert "warning" in desc and "CWE" in desc


# ---------------------------------------------------------------------------
# Feature 0096 (M10): a finding resolves to its lineage row the way the backend
# writer and the UI findings table resolve it — agent-scoped, fingerprint_v2
# first, then v1; v1 alone only when the caller knows no agent.
# ---------------------------------------------------------------------------

def _lineage_row(lid: str, fp: str, fp2: str, agent: str, status: str, ref_number: int) -> dict:
    return {"id": lid, "fingerprint": fp, "fingerprint_v2": fp2, "agent_type": agent,
            "current_status": status, "ref_number": ref_number, "ref": f"VLT-{ref_number:04d}"}


def _finding(fp: str, fp2: str, agent: str, title: str) -> dict:
    return {"fingerprint": fp, "fingerprint_v2": fp2, "agent_type": agent, "severity": "high",
            "category": "CWE-89", "title": title, "description": "d", "file_path": "/app/x.py",
            "line_start": 1, "line_end": 1, "check_id": "cwe.sql"}


def _mock_lineage_audit(findings: list, rows: list):
    respx.get("http://localhost:28080/api/audits/v2a").mock(
        return_value=httpx.Response(200, json={"id": "v2a", "findings": findings}))
    respx.get("http://localhost:28080/api/audits/v2a/lineage").mock(
        return_value=httpx.Response(200, json=rows))


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_resolves_lineage_by_v2_when_v1_differs():
    # The writer recognised the finding through v2 and kept the row's ORIGINAL v1.
    _mock_lineage_audit([_finding("new-v1", "v2-x", "cwe", "SQLi")],
                        [_lineage_row("lin-x", "old-v1", "v2-x", "cwe", "in_progress", 42)])
    from server import vulture_get_findings
    f = (await vulture_get_findings(audit_id="v2a"))["findings"][0]
    assert (f["lineage_id"], f["lineage_status"], f["ref"]) == ("lin-x", "in_progress", "VLT-0042")


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_findings_sharing_v1_resolve_to_their_own_rows_via_v2():
    _mock_lineage_audit(
        [_finding("shared", "v2-a", "cwe", "A"), _finding("shared", "v2-b", "cwe", "B")],
        [_lineage_row("lin-a", "shared", "v2-a", "cwe", "open", 1),
         _lineage_row("lin-b", "shared", "v2-b", "cwe", "false_positive", 2)])
    from server import vulture_get_findings
    got = {f["title"]: (f["lineage_id"], f["lineage_status"], f["ref"])
           for f in (await vulture_get_findings(audit_id="v2a"))["findings"]}
    assert got == {"A": ("lin-a", "open", "VLT-0001"), "B": ("lin-b", "false_positive", "VLT-0002")}


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_does_not_attach_another_agents_lineage_row():
    _mock_lineage_audit([_finding("fp", "v2", "cwe", "SQLi")],
                        [_lineage_row("lin-o", "fp", "v2", "owasp", "false_positive", 7)])
    from server import vulture_get_findings
    f = (await vulture_get_findings(audit_id="v2a"))["findings"][0]
    assert "lineage_id" not in f and "ref" not in f and "lineage_status" not in f


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_lineage_agent_is_compared_case_insensitively_and_first_row_wins():
    _mock_lineage_audit([_finding("fp", "", "CWE", "SQLi")],
                        [_lineage_row("lin-new", "fp", "", "cwe", "open", 9),
                         _lineage_row("lin-old", "fp", "", "cwe", "fixed", 3)])
    from server import vulture_get_findings
    f = (await vulture_get_findings(audit_id="v2a"))["findings"][0]
    assert f["lineage_id"] == "lin-new"


@respx.mock
@pytest.mark.asyncio
async def test_get_finding_detail_resolves_lineage_agent_scoped_v2_first():
    _mock_lineage_audit([_finding("new-v1", "v2-x", "cwe", "SQLi")],
                        [_lineage_row("lin-o", "new-v1", "", "owasp", "false_positive", 5),
                         _lineage_row("lin-x", "old-v1", "v2-x", "cwe", "in_progress", 42)])
    from server import vulture_get_finding_detail
    res = await vulture_get_finding_detail(audit_id="v2a", fingerprint="new-v1")
    assert res["lineage"]["id"] == "lin-x"


@respx.mock
@pytest.mark.asyncio
async def test_get_findings_framework_filter_still_attaches_v2_resolved_lineage():
    f = _finding("new-v1", "v2-x", "cwe", "SQLi")
    f["compliance_labels"] = [_owasp_label("A05", "Injection", "CWE-89")]
    _mock_lineage_audit([f], [_lineage_row("lin-x", "old-v1", "v2-x", "cwe", "open", 42)])
    from server import vulture_get_findings
    res = await vulture_get_findings(audit_id="v2a", framework="owasp", category="A05")
    assert [(r["ref"], r["compliance_labels"][0]["category_id"]) for r in res["findings"]] == [("VLT-0042", "A05")]
