import os

from flask import Flask, request

app = Flask(__name__)


class Shelf:
    def __init__(self, root):
        self.hash = lambda name: os.path.join(root, name)


shelf = Shelf("/srv/shards")


@app.route("/shard")
def shard():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(shelf.hash(request.args["name"])) as fh:
        return fh.read()
