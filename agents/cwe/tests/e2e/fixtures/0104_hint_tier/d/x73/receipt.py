import hashlib
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/receipt", methods=["POST"])
def receipt():
    # EXPECT-NEXT: clean check=cwe.input_validation.path_traversal
    with open(
        # EXPECT-NEXT: finding check=cwe.input_validation.external_path_control
        os.path.join("/srv/receipts", hashlib.sha1(request.form["email"].encode()).hexdigest()),
        "w",
    ) as fh:
        fh.write("ok")
    return "ok"
