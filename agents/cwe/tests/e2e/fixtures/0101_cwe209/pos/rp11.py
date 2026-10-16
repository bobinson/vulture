# ruff: noqa
class H(RequestHandler):
    def get(self):
        try:
            run()
        except Exception as e:
            # EXPECT-NEXT: finding
            self.write({"error": e.args})
