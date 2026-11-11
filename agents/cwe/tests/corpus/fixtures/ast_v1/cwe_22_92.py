# pins: 0104 WS-D - blob_path_for_digest is a word, not the exact key (positive)
from flask import Flask, request

from .cas import blob_path_for_digest

app = Flask(__name__)


@app.route("/blob")
def blob():
    with open(blob_path_for_digest(request.args["d"]), "rb") as fh:
        return fh.read()
