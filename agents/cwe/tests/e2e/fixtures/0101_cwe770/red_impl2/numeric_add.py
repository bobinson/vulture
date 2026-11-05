import sys


def ids():
    seen = set()
    for line in sys.stdin:
        # EXPECT-NEXT: finding a set of peer-supplied numbers grows per line
        seen.add(int(line))
    return seen


def tally(sock, metrics):
    while True:
        d = sock.recv(64)
        if not d:
            return
        # EXPECT-NEXT: clean a metric object incremented by a size is arithmetic
        metrics.add(len(d))
