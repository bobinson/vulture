# ruff: noqa
class LedgerHandler:
    def do_GET(self):
        # EXPECT-NEXT: clean  a sink spelled in a trailing hash comment is not a sink
        self.wfile.write(b"ok")  # never self.wfile.write(err.message)
