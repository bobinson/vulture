# ruff: noqa
class Handler:
    def post(self):
        try:
            run(self.request)
        except ValidationError as exc:
            self.write(str(exc.__cause__))  # EXPECT: finding tp-py-typed-dunder-cause
