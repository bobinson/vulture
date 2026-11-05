# ruff: noqa
async def price_view(request):
    try:
        await price(request)
    except Exception as e:
        # EXPECT-NEXT: clean  known-gap a response built by a free function, not a member write
        return json_response({"error": str(e)})
