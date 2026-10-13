# ruff: noqa
class Handler:
    def get(self):
        try:
            run()
        except Exception as exc:
            self.write(get_redacted_message(exc))  # EXPECT: clean sq-py-redacted-qualifier
