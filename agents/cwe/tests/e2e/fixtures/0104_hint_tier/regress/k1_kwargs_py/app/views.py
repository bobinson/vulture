from flask import Flask, request

from app.sheets import save_sheet

app = Flask(__name__)


@app.route("/sheets", methods=["POST"])
def create_sheet():
    save_sheet(content=request.form["body"], file_name=request.form["name"])
    return "ok"
