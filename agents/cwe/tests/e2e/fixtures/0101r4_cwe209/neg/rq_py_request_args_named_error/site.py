# ruff: noqa
class Callback:
    def get(self):
        error = self.request.args.get("error")
        if error:
            self.write(f"Authentication failed: {error}")  # EXPECT: clean rq-py-request-args
