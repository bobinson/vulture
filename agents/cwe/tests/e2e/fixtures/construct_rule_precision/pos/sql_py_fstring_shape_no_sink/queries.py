def build(i):
    query = f"DELETE FROM t WHERE id = {i}"  # EXPECT: finding
    return query
