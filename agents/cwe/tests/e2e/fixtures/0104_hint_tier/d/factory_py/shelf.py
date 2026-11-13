import os

from flask import Flask, request

app = Flask(__name__)


def make_layout(root):
    return lambda name: os.path.join(root, name)


hash = make_layout("/srv/shelf")


@app.route("/shelf")
def shelf():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(hash(request.args["name"])) as fh:
        return fh.read()
