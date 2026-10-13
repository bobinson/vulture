# ruff: noqa
class H(RequestHandler):
    def get(self):
        try:
            run()
        except Exception as exc:
            # EXPECT-NEXT: finding  py dict ctor
            self.write(dict(error=str(exc)))
