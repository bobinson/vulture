# ruff: noqa
def load(ident):
    try:
        return {"ok": True}
    except Exception as exc:
        return Outcome(False, error=str(exc))


@app.route("/x")
def show(ident):
    outcome = load(ident)
    return jsonify(error=outcome.error), 500  # probe tp-flask-kw


@app.route("/y")
def show2(ident):
    outcome = load(ident)
    return jsonify({"error": outcome.error}), 500  # EXPECT: clean tp-flask-dict


@router.get("/z")
async def show3(ident):
    outcome = load(ident)
    raise HTTPException(status_code=500, detail=outcome.error)  # probe tp-fastapi-raise
