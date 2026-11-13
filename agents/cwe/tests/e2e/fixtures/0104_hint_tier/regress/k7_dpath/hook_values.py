import subprocess

import dpath.util
from flask import Flask, request

app = Flask(__name__)


@app.route("/hook", methods=["POST"])
def hook():
    cmd = dpath.util.values(request.get_json(), "build/command")
    # EXPECT-NEXT: finding check=cwe.injection.command
    subprocess.run(cmd, shell=True)
