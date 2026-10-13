# ruff: noqa
class Handler:
    def put(self):
        try:
            run(self.request)
        except Exception as exc:
            if isinstance(exc, ValidationError):
                self.write(str(exc))  # EXPECT: clean tg-py-isinstance
                return
            self.write("failed")
