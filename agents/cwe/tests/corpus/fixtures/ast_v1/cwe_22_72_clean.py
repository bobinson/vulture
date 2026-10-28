# pins: an early exit dominates the rest of its loop body - the loop skips every canonical path outside the root (not ledger_path.startswith(LEDGER_ROOT) -> continue) before open(ledger_path) nested in a later IF, so the open declines guarded:path_contain (negative)
import os

from flask import request

LEDGER_ROOT = "/srv/ledgers/"


def export_ledgers():
    pages = []
    for ledger_name in request.args.getlist("ledger"):
        ledger_path = os.path.realpath(os.path.join(LEDGER_ROOT, ledger_name))
        if not ledger_path.startswith(LEDGER_ROOT):
            continue
        if ledger_path.endswith(".csv"):
            with open(ledger_path) as handle:
                pages.append(handle.read())
    return "".join(pages)
