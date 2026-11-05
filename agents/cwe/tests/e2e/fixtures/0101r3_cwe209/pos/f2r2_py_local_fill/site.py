# ruff: noqa
def validate(body):
    if not body.get("email"):
        return Result(ok=False, error="email is required")
    return Result(ok=True, error=None)


def signup(handler, body):
    v = validate(body)
    try:
        persist(body)
    except Exception as e:
        v.ok = False
        v.error = str(e)
    if not v.ok:
        handler.wfile.write(v.error.encode())  # EXPECT: finding tp-local-fill-py
