import io
import itertools
from collections import deque

CONFIG = "settings.ini"


def read_config():
    entries = []
    with open(CONFIG) as stream:
        for line in stream:
            # EXPECT-NEXT: clean F1 local config file named 'stream'
            entries.append(line.strip())
    return entries


def split_text(text):
    reader = io.StringIO(text)
    lines = []
    for line in reader:
        # EXPECT-NEXT: clean F2 in-memory StringIO named 'reader'
        lines.append(line)
    return lines


def tail(sock):
    recent = deque(maxlen=500)

    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: clean F3 deque bounded at construction, >3 lines away
        recent.append(b)
    return list(recent)


def batched(sock, flush):
    batch = []
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: clean F4 batch-and-flush resets the collection
        batch.append(b)
        if len(batch) == 64:
            flush(batch)
            batch = []
    flush(batch)


def per_message(sock, handle):
    while True:
        msg = sock.recv(4096)
        if not msg:
            break
        parts = []
        # EXPECT-NEXT: clean F5 collection recreated every iteration
        parts.append(msg)
        handle(parts)


def first_n(sock_file, MAX_LINES):
    out = []
    for line in itertools.islice(sock_file, MAX_LINES):
        # EXPECT-NEXT: clean F6 cap expressed by islice, no relational
        out.append(line)
    return out


def trimmed(sock):
    window = []
    while True:
        b = sock.recv(512)
        if not b:
            break
        # EXPECT-NEXT: clean F7 trimmed by slice, no relational test
        window.append(b)
        del window[:-100]
    return window


def capped_by_maximum(sock, MAXIMUM_FRAMES):
    frames = []
    while True:
        f = sock.recv(4096)
        if not f:
            break
        if len(frames) == MAXIMUM_FRAMES:
            break
        # EXPECT-NEXT: clean F8 cap with == and a 'maximum' name
        frames.append(f)
    return frames


def counted(sock, stats):
    total = 0
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: clean F9 .add on a running counter, not a collection
        stats.add(len(b))
    return total


def kinds(sock):
    seen = set()
    while True:
        b = sock.recv(1)
        if not b:
            break
        # EXPECT-NEXT: finding known-gap: set over a small key domain (LLD 5.2.6) (probe:F10 set over a 16-value domain)
        seen.add(b[0] & 0x0F)
    return seen


def hand_off(sock, q):
    # q = queue.Queue(maxsize=100) at the call site: put() blocks when full
    while True:
        b = sock.recv(4096)
        if not b:
            break
        # EXPECT-NEXT: finding known-gap: bounded queue declared at the call site, outside the routine (LLD 5.2.6) (probe:F11 bounded queue put (back-pressure))
        q.put(b)


def drain_local(q):
    items = []
    while True:
        try:
            # EXPECT-NEXT: finding known-gap: in-process queue drained with get_nowait reads as a pull (LLD 5.2.6, declared-outside class) (probe:F12 draining an in-process queue snapshot)
            items.append(q.get_nowait())
        except Exception:
            break
    return items
