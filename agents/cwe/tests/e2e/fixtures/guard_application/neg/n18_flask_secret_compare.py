import hmac

from flask import Flask, abort, current_app, request, session

app = Flask(__name__)


@app.before_request
def gate():
    if hmac.compare_digest(request.headers.get("X-Service-Token", ""), current_app.config["SVC_TOKEN"]):
        return
    if "uid" not in session:
        abort(401)
