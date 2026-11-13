import os

from flask import Flask, request

app = Flask(__name__)
ROOT = "/srv/shelf"
hash = os.path.join


@app.route("/shelf")
def shelf():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(hash(ROOT, request.args["name"])) as fh:
        return fh.read()
