# ruff: noqa
class Handler:
    def post(self):
        try:
            run(self.request)
        except ValidationError as exc:
            self.write("invalid request")
        except DatabaseError as exc:
            self.write(str(exc))  # EXPECT: finding tp-py-typed-database-error
