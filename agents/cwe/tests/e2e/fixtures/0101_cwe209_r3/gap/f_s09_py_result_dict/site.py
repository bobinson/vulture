# ruff: noqa
def load_ledger(ident):
    try:
        return {"ok": True, "rows": store.read(ident)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def show_ledger(request):
    outcome = load_ledger(request.args["id"])
    if not outcome["ok"]:
        return jsonify({"error": outcome["error"]})  # EXPECT: clean tp-subscript
    return jsonify(outcome["rows"])
