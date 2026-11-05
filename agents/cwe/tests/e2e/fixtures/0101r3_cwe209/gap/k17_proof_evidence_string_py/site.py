# ruff: noqa
async def probe(target):
    try:
        reply = await connect(target)
    except Exception as exc:
        return Outcome(success=False, evidence=f"connection failed: {exc}")  # EXPECT: clean gap-K17-evidence-string
    return Outcome(success=True, evidence=reply.text)
