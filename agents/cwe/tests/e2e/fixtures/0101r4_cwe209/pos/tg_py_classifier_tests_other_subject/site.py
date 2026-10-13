# ruff: noqa
def status_for(exc, previous=None):
    if not isinstance(previous, (ValidationError, AuthorizationError)):
        return None
    return 400


class Handler:
    def post(self):
        try:
            run(self.request)
        except Exception as exc:
            status = status_for(exc)
            if status is not None:
                self.write(str(exc))  # EXPECT: finding tp-py-classifier-other-subject
                return
            self.write("failed")
