# ruff: noqa
async def run(emitter, source):
    try:
        info = await analyze(source)
    except Exception as exc:
        yield emitter.text_message(f"Source analysis failed: {exc}")  # EXPECT: clean gap-K16-outbound-event-stream
        return
    yield emitter.result(info)
