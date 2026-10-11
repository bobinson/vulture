def parse(blob):
    out = []
    for name in blob.split(","):
        # EXPECT-NEXT: clean in-memory
        out.append(name)
    return out


def cfgread(cp, paths):
    vals = []
    while True:
        ok = cp.read(paths)
        # EXPECT-NEXT: clean ConfigParser.read
        vals.append(ok)
        break
    return vals
