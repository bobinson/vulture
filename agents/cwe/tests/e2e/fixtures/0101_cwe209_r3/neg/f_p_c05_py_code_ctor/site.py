# ruff: noqa
class Outcome:
    def __init__(self, ok, error=None):
        self.ok = ok
        self.error = error


def load_ledger(ident):
    if not store.exists(ident):
        return Outcome(False, error="E_NOT_FOUND")
    return Outcome(True)


def show_ledger(handler, ident):
    outcome = load_ledger(ident)
    handler.wfile.write(outcome.error.encode())  # EXPECT: clean clean-code
