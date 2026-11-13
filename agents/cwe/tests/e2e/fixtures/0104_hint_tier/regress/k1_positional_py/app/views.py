from flask import Flask, request

from app.sheets import save_sheet

app = Flask(__name__)


@app.route("/sheets", methods=["POST"])
def create_sheet():
    save_sheet(request.form["body"], request.form["name"])
    return "ok"
