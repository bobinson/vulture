from flask import request


def purge(sh):
    sh.run("DELETE FROM t WHERE id = " + request.args["id"])  # EXPECT: finding
