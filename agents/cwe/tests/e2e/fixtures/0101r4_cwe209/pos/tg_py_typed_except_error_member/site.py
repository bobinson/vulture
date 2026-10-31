# ruff: noqa
class Handler:
    def post(self):
        try:
            repo.save(self.request)
        except ValidationError as exc:
            self.write(str(exc.error))  # EXPECT: finding tp-py-own-member-error
