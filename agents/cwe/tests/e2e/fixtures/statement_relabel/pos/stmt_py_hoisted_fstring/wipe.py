from flask import request


def wipe(store):
    q = f"DELETE FROM t WHERE id = {request.args['id']}"  # EXPECT: finding
    store.exec(q)
