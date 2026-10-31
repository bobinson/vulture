class Loader:
    def load(self):
        out = []
        while True:
            item = self._read()
            if item is None:
                break
            # EXPECT-NEXT: clean a private helper named _read is not a pull from a peer
            out.append(item)
        return out
