import os

LEDGER_DIR = "/var/app/ledgers"


def resolve_ledger(ledger_file_name):
    candidate = os.path.join(LEDGER_DIR, ledger_file_name)
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    if not os.path.exists(candidate):
        raise FileNotFoundError(ledger_file_name)
    return candidate
