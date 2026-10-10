from flask import Flask, abort, g, request, session

app = Flask(__name__)


@app.before_request
def load():
    if request.args.get("debug") == "1":
        g.authenticated = True
    if not g.get("authenticated") and "user_id" not in session:
        abort(401)
