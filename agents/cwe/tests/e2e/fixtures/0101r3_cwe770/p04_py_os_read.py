import os


def drain(fd):
    chunks = []
    while True:
        data = os.read(fd, 4096)
        if not data:
            break
        # EXPECT-NEXT: finding read with a numeric size argument is a pull
        chunks.append(data)
    return b"".join(chunks)
