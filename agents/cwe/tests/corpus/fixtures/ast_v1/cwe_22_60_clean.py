# pins: a statement-level validation call in an enclosing block guards the path role - ensure_within_directory(BASE, target) dominates the open(target) nested under with (negative)
import os

from flask import Flask, request

from .guards import ensure_within_directory

app = Flask(__name__)
BASE = "/srv/exports"


@app.route("/export")
def export():
    target = os.path.join(BASE, request.args["name"])
    ensure_within_directory(BASE, target)
    with open(target, "rb") as handle:
        return handle.read()
