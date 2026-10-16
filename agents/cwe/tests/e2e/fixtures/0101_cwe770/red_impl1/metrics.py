def counters(sock, metrics):
    while True:
        d = sock.recv(10)
        if not d:
            return
        # EXPECT-NEXT: clean a metric incremented by a literal
        metrics.add(1)


def remember(sock, seen):
    while True:
        d = sock.recv(64)
        if not d:
            return
        # EXPECT-NEXT: finding peer data added to a set
        seen.add(d)
