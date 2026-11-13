# pins: 0104 WS-C - an augmented assignment composes the probed path (positive)
import os

from flask import Flask, jsonify

app = Flask(__name__)
ATLAS_ROOT = "/srv/atlas"


def atlas_exists(file_name):
    full = ATLAS_ROOT + "/"
    full += file_name
    return jsonify(found=os.path.exists(full))


app.add_url_rule("/atlas/<path:file_name>/exists", view_func=atlas_exists)
