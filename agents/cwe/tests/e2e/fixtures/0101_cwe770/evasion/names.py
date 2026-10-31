import queue


def drain_client(client_sock):
    frames = []
    for chunk in iter(lambda: client_sock.recv(4096), b""):
        # EXPECT-NEXT: finding E1 iter(callable, sentinel) over a socket
        frames.append(chunk)
    return frames


def from_kafka(kafka_consumer):
    out = []
    for msg in kafka_consumer:
        # EXPECT-NEXT: finding E2 compound source name defeats \b lexicon
        out.append(msg.value)
    return out


def from_peer(upstreamConn):
    lines = []
    for line in upstreamConn.makefile("r"):
        # EXPECT-NEXT: finding E3 camelCase source name
        lines.append(line)
    return lines


def from_child(proc):
    rows = []
    for line in proc.stdout:
        # EXPECT-NEXT: finding E4 stdout of a child process (lexicon has only stdin)
        rows.append(line)
    return rows


class Handler:
    def do_POST(self):
        parts = []
        for line in self.rfile:
            # EXPECT-NEXT: finding E5 rfile (request body file) not in lexicon
            parts.append(line)
        return parts


def worker(jobs: queue.Queue):
    backlog = []
    while True:
        job = jobs.get()
        if job is None:
            break
        # EXPECT-NEXT: finding E6 blocking queue .get() not a pull verb
        backlog.append(job)
    return backlog


def body_by_header(sock, headers):
    length = int(headers["Content-Length"])
    received = 0
    chunks = []
    while received < length:
        data = sock.recv(65536)
        received += len(data)
        # EXPECT-NEXT: finding E7 attacker-chosen length in the relational header
        chunks.append(data)
    return b"".join(chunks)


def with_retries(sock):
    attempts = 0
    MAX_RETRIES = 5
    msgs = []
    while True:
        try:
            m = sock.recv(1024)
        except TimeoutError:
            attempts += 1
            if attempts > MAX_RETRIES:
                raise
            continue
        if not m:
            break
        # EXPECT-NEXT: finding E8 cap-vocabulary word on an UNRELATED retry counter excuses the loop
        msgs.append(m)
    return msgs


def with_emptiness_check(sock):
    frames = []
    while True:
        f = sock.recv(4096)
        if not f:
            break
        if len(frames) > 0 and frames[-1] == f:
            continue
        # EXPECT-NEXT: finding E9 any relational on len(acc) counts as a cap
        frames.append(f)
    return frames


def noisy_comment(sock):
    out = []
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # TODO: there is no limit on this buffer yet
        # EXPECT-NEXT: finding E10 the cap word in a TODO comment within +-3 lines
        out.append(b)
    return out


def via_bytesio(sock):
    import io
    buf = io.BytesIO()
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: finding E11 .write() growth sink not an accumulate verb
        buf.write(b)
    return buf.getvalue()


def via_plus_equals(sock):
    data = b""
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: finding E12 += concatenation sink
        data += b
    return data


def via_dict(sock):
    sessions = {}
    while True:
        line = sock.recv(256)
        if not line:
            break
        # EXPECT-NEXT: clean known-gap: keyed map insertion is not a sink (LLD 5.2.6, E13) (probe:E13 subscript-assign growth of a map)
        sessions[line] = object()
    return sessions


_SEEN_REQUESTS = []


def handle_request(request):
    # EXPECT-NEXT: clean known-gap: module-global growth once per request, no loop (NG7) (probe:E14 module-global grows once per request, no loop)
    _SEEN_REQUESTS.append(request.body)
    return "ok"


class Recorder:
    def __init__(self):
        self.messages = []

    def on_message(self, msg):
        # EXPECT-NEXT: clean known-gap: instance state grown by a callback (NG7) (probe:E15 callback-driven growth in long-lived state)
        self.messages.append(msg)


def recurse(sock, acc):
    b = sock.recv(4096)
    if not b:
        return acc
    # EXPECT-NEXT: clean known-gap: recursion over input (NG7) (probe:E16 recursion over input (LLD names it, design omits it))
    acc.append(b)
    return recurse(sock, acc)


async def aio_body(incoming):
    parts = []
    async for chunk in incoming.content.iter_chunked(1024):
        # EXPECT-NEXT: finding E17 iter_chunked + non-lexicon peer name
        parts.append(chunk)
    return parts


def slurp_body(request):
    # EXPECT-NEXT: clean known-gap: a single unbounded read, no accumulation (NG7) (probe:E18 single unbounded read, no loop at all)
    return request.stream.read()
