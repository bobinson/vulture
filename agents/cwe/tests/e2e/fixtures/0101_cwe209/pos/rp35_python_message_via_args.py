# ruff: noqa
class H:
    def get(self):
        try:
            svc.load()
        except Exception as exc:
            # EXPECT-NEXT: finding  Python message via args
            self.write(exc.args[0])
