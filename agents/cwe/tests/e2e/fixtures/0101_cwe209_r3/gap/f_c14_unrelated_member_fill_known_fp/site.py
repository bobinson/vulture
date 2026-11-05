# ruff: noqa
from dataclasses import dataclass


@dataclass
class Outcome:
    ok: bool
    error: str | None = None


def audit(handler, exc_holder):
    try:
        exc_holder.run()
    except Exception as exc:
        exc_holder.last.error = str(exc)
        LOG.warning("run failed")


def load_ledger(ident):
    return Outcome(False, error="E_NOT_FOUND") if not store.exists(ident) else Outcome(True)


def show_ledger(handler, ident):
    outcome = load_ledger(ident)
    handler.wfile.write(outcome.error.encode())  # EXPECT: finding clean-code-unrelated-member
