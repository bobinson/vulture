import os

from flask import Flask, request

app = Flask(__name__)
ROOT = "/srv/shards"


class Layout:
    hash = staticmethod(lambda name: name[:2] + "/" + name)


@app.route("/shard")
def shard():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(os.path.join(ROOT, Layout.hash(request.args["name"]))) as fh:
        return fh.read()
