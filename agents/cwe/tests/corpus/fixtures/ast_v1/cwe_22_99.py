# pins: 0104 WS-C - a view registered by reference probes a joined path (positive)
import os

from flask import Flask, jsonify

app = Flask(__name__)
ATLAS_ROOT = "/srv/atlas"


def atlas_exists(file_name):
    full = os.path.join(ATLAS_ROOT, file_name)
    return jsonify(exists=os.path.exists(full))


app.add_url_rule("/atlas/<path:file_name>/exists", view_func=atlas_exists)
