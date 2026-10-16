# ruff: noqa
def emit(handler, msg):
    handler.send_response(500)
    handler.wfile.write(msg.encode("utf-8"))


def do_GET(handler):
    try:
        store.read()
    except Exception as exc:
        emit(handler, str(exc))  # EXPECT: finding tp-H-py-encode-arg
