# ruff: noqa
def fail(handler, msg):
    handler.send_response(500)
    handler.wfile.write(msg.encode())


def do_GET(handler):
    try:
        store.read()
    except Exception as exc:
        fail(handler, str(exc))  # EXPECT: finding tp-H-py-encode
