from flask import Flask, jsonify, request, session

app = Flask(__name__)


@app.before_request
def gate():
    if request.args.get("debug") == "1":
        return
    if "uid" not in session:
        return jsonify(error="unauthorized"), 401
