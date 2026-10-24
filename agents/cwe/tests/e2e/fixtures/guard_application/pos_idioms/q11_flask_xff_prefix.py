from flask import Flask, abort, request, session

app = Flask(__name__)


@app.before_request
def ip_gate():
    if request.headers.get("X-Forwarded-For", "").startswith("10."):
        return
    if "user_id" not in session:
        abort(401)
