class BackendClient:
    def __init__(self, transport):
        self._transport = transport

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        return await self._transport.send(method, path, **kwargs)

    async def update_lineage(self, lineage_id: str, status: str, notes: str = "") -> dict:
        return await self._request("PATCH", f"/api/lineage/{lineage_id}", json={"status": status})
