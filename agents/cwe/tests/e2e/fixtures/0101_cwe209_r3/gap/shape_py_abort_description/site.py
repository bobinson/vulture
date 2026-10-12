# ruff: noqa
def show(ident):
    try:
        store.read(ident)
    except Exception as exc:
        abort(500, description=str(exc))  # EXPECT: clean gap-abort-description
