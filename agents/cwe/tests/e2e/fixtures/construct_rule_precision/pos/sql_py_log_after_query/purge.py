def purge(cur, x, log):
    q = f"DELETE FROM t WHERE id = {x}"; log.info(q)  # noqa: E702 -- read as text. EXPECT: finding
    a = 1
    b = 2
    c = 3
    cur.execute(q)
    return a + b + c
