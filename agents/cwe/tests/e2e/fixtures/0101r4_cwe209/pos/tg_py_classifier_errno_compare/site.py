# ruff: noqa
def status_for(exc):
    if isinstance(exc, ValidationError):
        return 400
    if exc.errno == 2:
        return 404
    return None


class Handler:
    def post(self):
        try:
            run(self.request)
        except Exception as exc:
            status = status_for(exc)
            if status is not None:
                self.write(str(exc))  # EXPECT: finding tp-py-classifier-admits-an-errno
