MAX_RETRIES = 5


def slurp(conn):
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        # EXPECT-NEXT: finding unbounded concat growth from a socket
        data += chunk
    return data


def slurp_list(conn):
    frames = []
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        # EXPECT-NEXT: finding tuned shape
        frames.append(chunk)
    return frames


def retry_capped(conn):
    frames = []
    retries = 0
    while True:
        chunk = conn.recv(4096)
        if retries > MAX_RETRIES:
            break
        # EXPECT-NEXT: finding the cap bounds retries, not growth
        frames.append(chunk)
    return frames
