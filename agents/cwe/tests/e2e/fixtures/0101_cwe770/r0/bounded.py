MAX_FRAMES = 64


def copy(items):
    out = []
    for x in items:
        # EXPECT-NEXT: clean N1
        out.append(x)
    return out


def counted(n):
    out = []
    for i in range(n):
        # EXPECT-NEXT: clean N2
        out.append(i)
    return out


def index_walk(s):
    out = []
    i = 0
    while i < len(s):
        # EXPECT-NEXT: clean N3
        out.append(s[i])
        i += 1
    return out


def split_commas(s):
    parts, i = [], 0
    while True:
        j = s.find(",", i)
        if j < 0:
            break
        # EXPECT-NEXT: clean N4
        parts.append(s[i:j])
        i = j + 1
    return parts


def capped_frames(sock):
    buf = []
    while True:
        c = sock.recv(4096)
        if not c or len(buf) >= MAX_FRAMES:
            break
        # EXPECT-NEXT: clean N5
        buf.append(c)
    return buf


def capped_bytes(sock, limit_bytes):
    chunks, total = [], 0
    while True:
        c = sock.recv(4096)
        if not c:
            break
        # EXPECT-NEXT: clean a size counter assigned by tuple unpacking is not a collection
        total += len(c)
        if total > limit_bytes:
            raise ValueError("too large")
        # EXPECT-NEXT: clean N6
        chunks.append(c)
    return chunks


def sibling_loop(xs, cond):
    out = []
    for x in xs:
        pass
    if cond:
        # EXPECT-NEXT: clean N7
        out.append(1)
    return out


async def collect(gen):
    evts = []
    async for e in gen():
        # EXPECT-NEXT: clean N14
        evts.append(e)
    return evts


def probe(ws, MAX_MESSAGES=5):
    messages = []
    for _ in range(MAX_MESSAGES):
        # EXPECT-NEXT: clean N15
        messages.append(ws.recv())
    return messages
