"""Export the account ledger for the nightly reconciliation job."""

import os
import tempfile


def export_ledger(rows: str) -> str:
    destination = os.path.join(tempfile.mkdtemp(), "ledger-export.csv")
    with open(destination, "w", encoding="utf-8") as handle:
        handle.write(rows)
    return destination
