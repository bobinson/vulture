# ruff: noqa
def _note(ident):
    try:
        ping(ident)
    except Exception as exc:
        LAST.append(Note(str(exc)))


def load(ident):
    _note(ident)
    return remote_lookup(ident)


def show(handler, ident):
    outcome = load(ident)
    handler.wfile.write(outcome.error.encode())  # EXPECT: clean clean-hop-py
