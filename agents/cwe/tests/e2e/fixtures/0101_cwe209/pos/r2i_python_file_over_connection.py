# ruff: noqa
def answer_peer(conn, rows):
    try:
        build_ledger(rows)
    except Exception as e:
        with conn.makefile("wb") as fh:
            # EXPECT-NEXT: finding
            fh.write(str(e).encode())
