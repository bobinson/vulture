# pins: an early exit one block above a nested open guards it only with a covering role - the loop skips temporaries (ledger_path.endswith(".tmp") -> continue) before open(ledger_path) nested in a later IF, so the open still reports (positive)
import os

from flask import request

LEDGER_ROOT = "/srv/ledgers/"


def export_ledgers():
    pages = []
    for ledger_name in request.args.getlist("ledger"):
        ledger_path = os.path.realpath(os.path.join(LEDGER_ROOT, ledger_name))
        if ledger_path.endswith(".tmp"):
            continue
        if ledger_path.endswith(".csv"):
            with open(ledger_path) as handle:
                pages.append(handle.read())
    return "".join(pages)
