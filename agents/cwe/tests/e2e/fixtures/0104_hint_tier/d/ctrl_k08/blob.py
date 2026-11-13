from flask import Flask, request

from .cas import blob_path_for_id

app = Flask(__name__)


@app.route("/blob")
def blob():
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    with open(blob_path_for_id(request.args["d"]), "rb") as fh:
        return fh.read()
