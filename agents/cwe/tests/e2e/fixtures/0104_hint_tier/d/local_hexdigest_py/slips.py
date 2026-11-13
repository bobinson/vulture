import os

from flask import Flask, request

app = Flask(__name__)
SPOOL = "/srv/spool"


class Slip:
    def __init__(self, raw):
        self.raw = raw

    def hexdigest(self):
        return self.raw.strip().lower()


@app.route("/slip")
def slip():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(os.path.join(SPOOL, Slip(request.args["t"]).hexdigest())) as fh:
        return fh.read()
