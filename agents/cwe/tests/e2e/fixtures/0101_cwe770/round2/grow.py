import io


def via_buffer(sock):
    buf = io.BytesIO()
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: finding BytesIO write in a recv loop
        buf.write(b)
    return buf.getvalue()


def keyed(sock):
    seen = {}
    while True:
        k = sock.recv(64)
        if not k:
            break
        # EXPECT-NEXT: clean known-gap: keyed map insertion is not a sink (LLD 5.2.6)
        seen[k] = True
    return seen
