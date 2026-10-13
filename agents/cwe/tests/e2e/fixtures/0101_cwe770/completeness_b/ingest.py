def drain(q):
    items = []
    while True:
        item = q.get()
        if item is None:
            break
        # EXPECT-NEXT: finding blocking queue get
        items.append(item)
    return items


def read_declared(sock, headers):
    content_length = int(headers["Content-Length"])
    chunks = []
    total = 0
    while total < content_length:
        chunk = sock.recv(4096)
        total += len(chunk)
        # EXPECT-NEXT: finding peer-declared length, no cap
        chunks.append(chunk)
    return chunks


def build(request):
    count = int(request.args["count"])
    out = []
    for _ in range(count):
        # EXPECT-NEXT: finding attacker-sized range
        out.append(bytearray(1024))
    return out


class Handler:
    def do_POST(self):
        rows = []
        for line in self.rfile:
            # EXPECT-NEXT: finding http request body file
            rows.append(line)
        return rows


def walk(node, acc):
    # EXPECT-NEXT: clean known-gap: recursion over an input tree (NG7) (probe:recursion over input tree)
    acc.append(node.value)
    for child in node.children:
        walk(child, acc)


def listen(pubsub):
    events = []
    for event in pubsub.listen():
        # EXPECT-NEXT: finding pubsub listen
        events.append(event)
    return events


async def ws_loop(websocket):
    msgs = []
    while True:
        m = await websocket.receive_text()
        # EXPECT-NEXT: finding ws receive
        msgs.append(m)


def upload(request):
    parts = []
    for chunk in request.stream:
        # EXPECT-NEXT: finding request stream
        parts.append(chunk)
    return parts


def paged(client):
    out = []
    token = None
    while True:
        page = client.fetch(token)
        # EXPECT-NEXT: clean remote pagination (debatable)
        out.extend(page.items)
        token = page.next
        if not token:
            break
    return out
