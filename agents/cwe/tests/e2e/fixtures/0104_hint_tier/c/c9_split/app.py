import os

from flask import Flask, jsonify

app = Flask(__name__)
ATLAS_ROOT = "/srv/atlas"


def atlas_exists(file_name):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return jsonify(found=os.path.exists(os.path.join(ATLAS_ROOT, file_name)))


def atlas_isfile(file_name):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return jsonify(found=os.path.isfile(os.path.join(ATLAS_ROOT, file_name)))


app.add_url_rule("/a/<path:file_name>", view_func=atlas_exists)
app.add_url_rule("/b/<path:file_name>", view_func=atlas_isfile)
