import functools
import os

from flask import Flask, request

app = Flask(__name__)
hash = functools.partial(os.path.join, "/srv/shelf")


@app.route("/shelf")
def shelf():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(hash(request.args["name"])) as fh:
        return fh.read()
