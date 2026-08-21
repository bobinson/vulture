"""Banner grab over a raw stream."""


def grab(host, port):
    try:
        stream = open_stream(host, port)
        banner = stream.recv(64)
        stream.release()
        return banner
    except TimeoutError as exc:
        log(exc)
        return b""
