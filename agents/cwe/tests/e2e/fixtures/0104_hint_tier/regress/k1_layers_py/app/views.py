from flask import Flask, g, request

from .service import fetch_bundle

app = Flask(__name__)


@app.route("/bundles")
def get_bundle():
    return fetch_bundle(g.user, request.args.get("name", ""))
