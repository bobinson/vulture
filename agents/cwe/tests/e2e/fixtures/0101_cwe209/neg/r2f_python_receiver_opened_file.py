# ruff: noqa
def export_ledger(rows):
    try:
        build_ledger(rows)
    except Exception as e:
        with open("ledger-failures.txt", "a") as fh:
            # EXPECT-NEXT: clean  a receiver bound in the routine to an opened file is a local write
            fh.write(str(e))
