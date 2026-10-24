# ruff: noqa
@app.route("/x")
def show(ident):
    try:
        x()
    except Exception as exc:
        msg = str(exc)
        return jsonify(error=msg), 500  # EXPECT: clean ctl-flask-kw
    try:
        x()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500  # probe ctl-flask-dict
    try:
        x()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))  # probe ctl-fastapi
