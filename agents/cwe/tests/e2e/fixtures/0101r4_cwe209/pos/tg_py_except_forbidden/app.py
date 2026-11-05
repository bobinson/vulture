# ruff: noqa
class DocHandler:
    def get(self, name):
        try:
            data = bucket.blob(name).download_as_bytes()
        except Forbidden as exc:
            self.write(str(exc))  # EXPECT: finding tp-py-outbound-forbidden
            return
        self.write(data)
