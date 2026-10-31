# ruff: noqa
class Handler:
    def post(self):
        try:
            run(self.request)
        except Exception as exc:
            if isinstance(exc, ValidationError):
                self.write(repr(exc.__context__))  # EXPECT: finding tp-py-isinstance-context
