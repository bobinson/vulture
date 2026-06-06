"""RED team: VultureClient tests. Must FAIL until server.py implements VultureClient."""
import pytest
import httpx
import respx


@respx.mock
@pytest.mark.asyncio
async def test_client_sends_auth_header():
    route = respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[])
    )
    from server import VultureClient
    client = VultureClient("http://localhost:28080", "vk_test123")
    await client.list_audits()
    assert route.calls[0].request.headers["authorization"] == "Bearer vk_test123"
    await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_client_works_without_api_key():
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(200, json=[])
    )
    from server import VultureClient
    client = VultureClient("http://localhost:28080", None)
    result = await client.list_audits()
    assert result == []
    await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_client_raises_on_401():
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    from server import VultureClient
    client = VultureClient("http://localhost:28080", "vk_bad")
    with pytest.raises(Exception, match="401"):
        await client.list_audits()
    await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_client_redacts_error_response():
    """Error responses might echo auth headers — they must be redacted."""
    respx.get("http://localhost:28080/api/audits").mock(
        return_value=httpx.Response(502, text='Authorization: Bearer vk_leaked_secret_key')
    )
    from server import VultureClient
    client = VultureClient("http://localhost:28080", "vk_test")
    with pytest.raises(Exception) as exc_info:
        await client.list_audits()
    assert "vk_leaked_secret_key" not in str(exc_info.value)
    await client.close()


@pytest.mark.asyncio
async def test_client_rate_limit_blocks():
    from server import VultureClient
    client = VultureClient("http://localhost:28080", None, rate_limit=2)
    # Exhaust rate limit without making real requests
    # We need to mock actual requests for rate limit to trigger
    # Just test the rate limit mechanism directly
    from collections import deque
    from time import monotonic
    client._timestamps = deque([monotonic(), monotonic()])  # pretend 2 recent calls
    with pytest.raises(Exception, match="Rate limit"):
        await client._enforce_rate_limit()
    await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_client_get_audit():
    respx.get("http://localhost:28080/api/audits/a1").mock(
        return_value=httpx.Response(200, json={"id": "a1", "findings": []})
    )
    from server import VultureClient
    client = VultureClient("http://localhost:28080", None)
    result = await client.get_audit("a1")
    assert result["id"] == "a1"
    await client.close()
