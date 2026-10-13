# ruff: noqa
@app.route("/x")
def x():
    try:
        do()
    except Exception as e:
        # EXPECT-NEXT: clean  known-gap flask jsonify str e
        return jsonify({"error": str(e)}), 500
