"""Banner grab that releases the stream on both paths."""


def grab(host, port):
    try:
        stream = open_stream(host, port)
        banner = stream.recv(64)
        stream.release()
        return banner
    except TimeoutError as exc:
        stream.release()
        log(exc)
        return b""
