def slurp(conn):
    frames = []
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        # TODO: there is no limit here yet
        # EXPECT-NEXT: finding comment mentions "limit"
        frames.append(chunk)
    return frames
