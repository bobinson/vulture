import os

from flask import Flask, jsonify

app = Flask(__name__)
ATLAS_ROOT = "/srv/atlas"


def _present(p):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return os.path.exists(p)


def atlas_exists(file_name):
    return jsonify(found=_present(os.path.join(ATLAS_ROOT, file_name)))


app.add_url_rule("/atlas/<path:file_name>/exists", view_func=atlas_exists)
