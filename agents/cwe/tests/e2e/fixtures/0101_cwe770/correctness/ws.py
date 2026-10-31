import socket
import urllib.request

RETRY_CEILING = 5

MAX_FRAME = 65536


def collect(sock):
    frames = []
    while True:
        frame = sock.recv(4096)
        if not frame:
            break
        if len(frame) > MAX_FRAME:
            raise ValueError("frame too large")
        # EXPECT-NEXT: finding per-item cap does not bound count
        frames.append(frame)
    return frames


def collect_retry(sock):
    chunks = []
    attempts = 0
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            attempts += 1
            if attempts > RETRY_CEILING:
                break
            continue
        if not data:
            break
        # EXPECT-NEXT: finding retry cap is not a growth cap
        chunks.append(data)
    return chunks


def dedupe(conn):
    lines = []
    while True:
        line = conn.readline()
        if not line:
            break
        if len(lines) > 0 and line == lines[-1]:
            continue
        # EXPECT-NEXT: finding len(lines) > 0 is not a cap
        lines.append(line)
    return lines


def paginate(session, url):
    items = []
    while url:
        r = session.get(url)
        # EXPECT-NEXT: clean known-gap: peer-driven pagination (LLD 5.2.6) (probe:peer-driven pagination)
        items.extend(r.json()["items"])
        url = r.json().get("next")
    return items


def proc_lines(proc):
    out = []
    for line in proc.stdout:
        # EXPECT-NEXT: finding subprocess output
        out.append(line)
    return out


async def drain(queue):
    got = []
    while True:
        item = await queue.get()
        # EXPECT-NEXT: finding asyncio queue
        got.append(item)
    return got


def http_lines(url):
    rows = []
    for line in urllib.request.urlopen(url):
        # EXPECT-NEXT: finding sync response stream
        rows.append(line)
    return rows


def with_query(cur, sock):
    rows = []
    while True:
        q = """
SELECT 1
"""
        cur.execute(q)
        # EXPECT-NEXT: finding a column-0 string inside the loop no longer hides it (R-C15); the loop pulls from sock
        rows.append(cur.fetchone())
        data = sock.recv(10)
        if not data:
            break
    return rows
