# ruff: noqa
def fail(handler, msg):
    LOG.warning("request failed: %s", msg)
    handler.send_response(500)
    handler.wfile.write("internal error".encode())


def do_GET(handler):
    try:
        store.read()
    except Exception as exc:
        fail(handler, str(exc))  # EXPECT: clean helper-writes-literal
