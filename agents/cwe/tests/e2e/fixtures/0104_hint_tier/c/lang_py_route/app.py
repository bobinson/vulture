import os

from flask import Flask, jsonify

app = Flask(__name__)


def sheet_exists(file_path):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return jsonify(present=os.path.exists(file_path))


app.add_url_rule("/sheets/exists/<path:file_path>", view_func=sheet_exists)
