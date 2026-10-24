# ruff: noqa
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            run()
        except Exception as exc:
            # EXPECT-NEXT: finding  py wfile encode
            self.wfile.write(str(exc).encode('utf-8'))
