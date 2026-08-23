"""Export the account ledger for the nightly reconciliation job."""


def export_ledger(rows: str) -> str:
    with open("/tmp/ledger-export.csv", "w", encoding="utf-8") as handle:
        handle.write(rows)
    return "/tmp/ledger-export.csv"
