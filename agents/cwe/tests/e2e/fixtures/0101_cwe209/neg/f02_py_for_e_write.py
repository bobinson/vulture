# ruff: noqa
def dump(self, entries):
    for e in entries:
        # EXPECT-NEXT: clean  py for e write
        self.write(e)
