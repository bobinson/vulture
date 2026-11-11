import hashlib
import os

from flask import Flask, request, send_file

app = Flask(__name__)
ROOT = "/srv/shards"


class ShardIndex:
    def hash(self, name):
        shard = hashlib.sha1(name.encode()).hexdigest()[:2]
        return os.path.join(shard, name)


index = ShardIndex()


@app.route("/shard")
def shard():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return send_file(os.path.join(ROOT, index.hash(request.args["name"])))
