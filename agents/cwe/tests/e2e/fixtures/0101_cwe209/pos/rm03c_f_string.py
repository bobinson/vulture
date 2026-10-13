# ruff: noqa
class H(BaseHTTPRequestHandler):
    def do_PUT(self):
        try:
            run()
        except Exception as exception:
            # EXPECT-NEXT: finding  f-string
            self.wfile.write(f"failed: {exception}".encode())
