def read_config(path):
    # EXPECT-NEXT: finding
    handle = open(path, encoding="utf-8")
    return handle.read().splitlines()


def close_quietly(stream):
    stream.close()
