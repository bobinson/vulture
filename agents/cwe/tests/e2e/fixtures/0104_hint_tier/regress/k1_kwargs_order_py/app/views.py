from flask import Flask, request

from app.sheets import save_sheet

app = Flask(__name__)


@app.route("/sheets", methods=["POST"])
def create_sheet():
    save_sheet(file_name=request.form["name"], content=request.form["body"])
    return "ok"
