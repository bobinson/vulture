# ruff: noqa
class H(RequestHandler):
    def get(self):
        try:
            run()
        except Exception as exc:
            # EXPECT-NEXT: finding  py format exception
            self.write(''.join(traceback.format_exception(exc)))
