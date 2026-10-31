# ruff: noqa
def get(self):
    # EXPECT-NEXT: clean  py kwarg literal error
    self.write(json_encode(error="Not found"))
