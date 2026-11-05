# ruff: noqa
async def chat(request, response):
    async for ev in agent.stream(request):
        if ev.kind == "error":
            await response.write(ev.error)  # EXPECT: finding tp-S-py
        else:
            await response.write(ev.text)
