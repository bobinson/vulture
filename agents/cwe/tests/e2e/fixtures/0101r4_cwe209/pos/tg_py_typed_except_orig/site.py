# ruff: noqa
class Handler:
    def post(self):
        try:
            repo.save(self.request)
        except InputValidationError as exc:
            self.write(str(exc.orig))  # EXPECT: finding tp-py-own-member-orig
