# ruff: noqa
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            run()
        except Exception as exc:
            # EXPECT-NEXT: finding  snake suffix send error
            self.send_error(500, str(exc))
