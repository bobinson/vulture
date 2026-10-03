"""RED team: VultureClient tests. Must FAIL until server.py implements VultureClient."""
import asyncio
import contextlib
from time import monotonic

import httpx
import pytest
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


@pytest.mark.asyncio
async def test_waiting_fan_out_leaves_a_slot_for_other_tool_calls():
    # A tool's own paced fan-out (wait=True) must not take every slot, or a
    # concurrent tool call on the same client fails with "Rate limit exceeded".
    from server import VultureClient
    client = VultureClient("http://localhost:28080", None, rate_limit=10)
    taken = 0

    async def fan_out():
        nonlocal taken
        for _ in range(40):
            await client._enforce_rate_limit(wait=True)
            taken += 1

    task = asyncio.create_task(fan_out())
    try:
        await asyncio.sleep(0.2)
        for _ in range(5):
            await asyncio.sleep(0.3)
            await client._enforce_rate_limit()  # must not raise
        # The fan-out really ran alongside: it did not crash, and it kept
        # taking slots past its first window rather than stalling.
        assert not task.done() or task.exception() is None
        assert taken > client._rate_limit // 2
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await client.close()


@pytest.mark.asyncio
async def test_waiting_fan_out_is_paced_to_half_the_rate_limit():
    # wait=True sleeps for a slot rather than skipping the limiter, and fills
    # exactly half the slots of any one-second window: no more (other tool
    # calls keep the rest) and no less (the fan-out is not needlessly slow).
    from server import VultureClient
    client = VultureClient("http://localhost:28080", None, rate_limit=4)
    share = client._rate_limit // 2
    stamps = []
    for _ in range(5):
        await client._enforce_rate_limit(wait=True)
        stamps.append(monotonic())
    await client.close()
    assert stamps[share - 1] - stamps[0] < 0.5  # the whole share at once
    assert stamps[-1] - stamps[0] >= 1.9  # 5 calls at 2 per window span > 2 windows
    for i, t in enumerate(stamps):
        in_window = [u for u in stamps[i:] if u - t < 0.9]
        assert len(in_window) <= share, stamps


@pytest.mark.asyncio
async def test_waiting_fan_out_still_progresses_at_rate_limit_one():
    from server import VultureClient
    client = VultureClient("http://localhost:28080", None, rate_limit=1)
    await asyncio.wait_for(client._enforce_rate_limit(wait=True), timeout=0.5)
    await client.close()


@pytest.mark.asyncio
async def test_waiting_call_gives_up_when_other_callers_keep_half_the_slots():
    # A concurrent caller staying UNDER the limit can still hold half the
    # window or more indefinitely. A waiting call must then give up within a
    # bound rather than hang: the client is shared by every MCP session.
    from server import RateLimitExceeded, VultureClient
    client = VultureClient("http://localhost:28080", None, rate_limit=10)
    rejected = 0

    async def steady():
        nonlocal rejected
        while True:
            try:
                await client._enforce_rate_limit()
            except Exception:
                rejected += 1
            await asyncio.sleep(0.15)  # ~6.7 req/s: under 10, over half

    busy = asyncio.create_task(steady())
    try:
        await asyncio.sleep(1.2)
        started = monotonic()
        with pytest.raises(RateLimitExceeded, match="Rate limit"):
            await asyncio.wait_for(client._enforce_rate_limit(wait=True), timeout=6)
        assert monotonic() - started < 4
        assert rejected == 0  # the busy caller really stayed under the limit
    finally:
        busy.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await busy
        await client.close()


@pytest.mark.asyncio
async def test_non_waiting_rate_limit_raises_the_named_error():
    from server import RateLimitExceeded, VultureClient
    client = VultureClient("http://localhost:28080", None, rate_limit=1)
    await client._enforce_rate_limit()
    with pytest.raises(RateLimitExceeded, match=r"Rate limit exceeded \(1 req/s\)"):
        await client._enforce_rate_limit()
    await client.close()
