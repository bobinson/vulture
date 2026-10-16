# ruff: noqa
def get(self):
    try:
        run()
    except ValueError as exc:
        # EXPECT-NEXT: finding  python tornado write str e
        self.write(str(exc))
