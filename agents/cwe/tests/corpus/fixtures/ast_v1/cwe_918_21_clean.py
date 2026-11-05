# pins: a dict literal is no HTTP client - PREVIEWS is bound to {}, so PREVIEWS.get(url) is a dictionary lookup even though its key is URL-shaped (negative)
from flask import Flask, request

app = Flask(__name__)
PREVIEWS = {}


@app.route("/preview")
def preview():
    url = request.args["u"]
    return PREVIEWS.get(url, "")
