# ruff: noqa
def safe_error_message(exc):
    return str(exc)


class Handler:
    def get(self):
        try:
            run()
        except Exception as exc:
            self.write(safe_error_message(exc))  # EXPECT: finding tp-py-sanitiser-name-renders
