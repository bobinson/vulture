"""RED team: MCP tool tests. Must FAIL until server.py implements the tools."""
import pytest
import httpx
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
