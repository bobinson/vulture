async def probe(client, base, ep, make):
    resp = await client.delete(f"{base}{ep}")
    if resp.status_code == 200:
        return make(
            f"Unprotected DELETE method on {ep}",  # EXPECT: clean
            "HIGH",
            f"DELETE {ep} returned 200 OK, destructive method unprotected",  # EXPECT: clean
        )
    return None
