# ruff: noqa
def respond_json(handler, status, payload):
    handler.send_response(status)
    handler.wfile.write(json.dumps(payload).encode())


def do_get(handler):
    try:
        store.read()
    except Exception as exc:
        write_error(handler, 500, str(exc))  # probe tp-C-py-handler-not-peer-word
        respond_json(handler, 500, {"error": str(exc)})  # EXPECT: finding tp-H-py
