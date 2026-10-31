import sys


def drain_socket(sock):
    frames = []
    while True:
        frame = sock.recv(4096)
        if not frame:
            break
        # EXPECT-NEXT: finding P1
        frames.append(frame)
    return frames


def slurp(stream):
    parts = []
    while chunk := stream.read(65536):
        # EXPECT-NEXT: finding P2
        parts.append(chunk)
    return b"".join(parts)


def read_stdin():
    rows = []
    for line in sys.stdin:
        # EXPECT-NEXT: finding P3
        rows.append(line)
    return rows


def pull_events(resp):
    events = []
    for line in resp.iter_lines():
        # EXPECT-NEXT: finding P4
        events.append(line)
    return events


async def inbox_of(websocket):
    inbox = []
    async for msg in websocket:
        # EXPECT-NEXT: finding P5
        inbox.append(msg)
    return inbox


def decode_all(sock, decode):
    acc = []
    while True:
        data = sock.recv(1024)
        if not data:
            break
        for item in decode(data):
            # EXPECT-NEXT: finding P11 (outer loop drives)
            acc.append(item)
    return acc
