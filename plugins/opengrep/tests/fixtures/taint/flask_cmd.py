"""Taint E2E fixture (feature 0058 T2): a Flask request parameter flows
into ``os.system`` across multiple lines/variables — a source->sink
dataflow a single-line regex skill structurally cannot catch.

Deliberately vulnerable. Never import or run this module.
"""

import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping() -> str:
    # SOURCE: attacker-controlled HTTP query parameter.
    target = request.args.get("host", "127.0.0.1")
    # Taint propagates through an intermediate variable on another line.
    command = "ping -c 1 " + target
    # SINK: tainted value reaches the shell (CWE-78 command injection).
    os.system(command)
    return "pong"
