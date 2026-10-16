# ruff: noqa
class ValidationError(Exception):
    pass


class Handler:
    def post(self):
        try:
            run(self.request)
        except ValidationError as exc:
            self.write(str(exc))  # EXPECT: clean tg-py-typed-except
