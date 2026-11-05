# ruff: noqa
def status_for(exc):
    if not isinstance(exc, (ValidationError, AuthorizationError)):
        return None
    return 403 if isinstance(exc, AuthorizationError) else 400


class Handler:
    def post(self):
        try:
            run(self.request)
        except Exception as exc:
            status = status_for(exc)
            if status is not None:
                self.write(str(exc))  # EXPECT: clean tg-py-classifier-screen
                return
            self.write("failed")
