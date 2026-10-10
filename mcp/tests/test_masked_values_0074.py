"""0074 verification item 1b: an MCP client verifies a masked value without
ever receiving it. ``vulture_verify_masked_values`` returns where each masked
value sits (file, line, column, kind, length of a fixed-format token), whether
the scanned file still reproduces the masked rows, and a UI link to the finding,
where a human can switch the value on. A ``value`` the server might send is
dropped here as well: MCP output lands in the calling model's context.
Synthetic values."""

import httpx
import pytest
import respx

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
AUDIT = {"id": "a1", "status": "completed", "findings": [
    {"id": "f1", "fingerprint": "fp1", "file_path": "src/config.ts", "line_start": 2,
     "code_snippet": '2: const token = "***REDACTED***";'},
]}
MASKED = {
    "source_available": True, "matches_scan": True, "values_included": True, "file": "src/config.ts",
    "rows_checked": 1, "ui_path": "/audit/a1?finding=f1",
    "spans": [{"line": 2, "ordinal": 0, "column": 16, "kind": "jwt", "length": len(JWT), "value": JWT}],
}


def _mock(masked=MASKED):
    respx.get("http://localhost:28080/api/audits/a1").mock(return_value=httpx.Response(200, json=AUDIT))
    return respx.get("http://localhost:28080/api/audits/a1/findings/f1/masked").mock(
        return_value=httpx.Response(200, json=masked))


@respx.mock
@pytest.mark.asyncio
async def test_locates_masked_values_without_returning_them():
    route = _mock()
    from server import vulture_verify_masked_values
    result = await vulture_verify_masked_values(audit_id="a1", fingerprint="fp1")
    assert route.called
    assert JWT not in repr(result)
    assert result["matches_scan"] is True and result["file"] == "src/config.ts"
    assert result["spans"] == [{"line": 2, "ordinal": 0, "column": 16, "kind": "jwt", "length": len(JWT)}]
    assert "values_included" not in result


@respx.mock
@pytest.mark.asyncio
async def test_ui_url_prefers_the_frontend_url(monkeypatch):
    _mock()
    monkeypatch.setenv("VULTURE_FRONTEND_URL", "https://ui.example.test/")
    from server import vulture_verify_masked_values
    result = await vulture_verify_masked_values(audit_id="a1", fingerprint="fp1")
    assert result["ui_url"] == "https://ui.example.test/audit/a1?finding=f1"


@respx.mock
@pytest.mark.asyncio
async def test_ui_url_falls_back_to_the_server(monkeypatch):
    _mock()
    monkeypatch.delenv("VULTURE_FRONTEND_URL", raising=False)
    from server import vulture_verify_masked_values
    result = await vulture_verify_masked_values(audit_id="a1", fingerprint="fp1")
    assert result["ui_url"] == "http://localhost:28080/audit/a1?finding=f1"


@respx.mock
@pytest.mark.asyncio
async def test_unknown_fingerprint_raises():
    _mock()
    from server import vulture_verify_masked_values
    with pytest.raises(ValueError):
        await vulture_verify_masked_values(audit_id="a1", fingerprint="nope")
