def tail(sock):
    window = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        # EXPECT-NEXT: clean the buffer is re-sliced to a fixed tail every iteration
        window += data
        window = window[-1024:]
    return window
