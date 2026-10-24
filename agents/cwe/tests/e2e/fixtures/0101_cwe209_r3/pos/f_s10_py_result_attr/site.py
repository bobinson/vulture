# ruff: noqa
class Outcome:
    def __init__(self, error=None):
        self.error = error


def load_ledger(ident):
    try:
        store.read(ident)
        return Outcome()
    except Exception as exc:
        return Outcome(error=str(exc))


def show_ledger(handler, ident):
    outcome = load_ledger(ident)
    handler.wfile.write(outcome.error.encode())  # EXPECT: finding tp
