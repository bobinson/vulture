# ruff: noqa
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            run()
        except Exception as exc:
            # EXPECT-NEXT: finding  http server wfile str exc encode
            self.wfile.write(str(exc).encode())
