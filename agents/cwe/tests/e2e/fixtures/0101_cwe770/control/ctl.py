def c2(consumer):
    out = []
    for msg in consumer:
        # EXPECT-NEXT: finding C2 control for E2 (bare name)
        out.append(msg.value)
    return out


def c6(jobs):
    backlog = []
    while True:
        job = jobs.get_nowait()
        if job is None:
            break
        # EXPECT-NEXT: finding C6 control for E6 (get_nowait)
        backlog.append(job)
    return backlog


def c7(sock, headers):
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            break
        # EXPECT-NEXT: finding C7 control for E7 (no relational header)
        chunks.append(data)
    return chunks


def c8(sock):
    attempts = 0
    msgs = []
    while True:
        try:
            m = sock.recv(1024)
        except TimeoutError:
            attempts += 1
            if attempts > 5:
                raise
            continue
        if not m:
            break
        # EXPECT-NEXT: finding C8 control for E8 (literal 5, no cap word)
        msgs.append(m)
    return msgs


def c9(sock):
    frames = []
    while True:
        f = sock.recv(4096)
        if not f:
            break
        if frames and frames[-1] == f:
            continue
        # EXPECT-NEXT: finding C9 control for E9 (truthiness instead of len > 0)
        frames.append(f)
    return frames


def c10(sock):
    out = []
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # TODO: unbounded
        # EXPECT-NEXT: finding C10 control for E10
        out.append(b)
    return out
