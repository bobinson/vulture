# ruff: noqa
def do_get(handler):
    out = {"ok": True}
    try:
        store.read()
    except Exception as exc:
        out["error"] = str(exc)  # EXPECT: finding tp-W-local-subscript
    handler.wfile.write(json.dumps(out).encode())
