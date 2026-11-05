def report(cursor, cols, table):
    query = (
        f"SELECT {cols} "  # EXPECT: finding
        f"FROM {table}"
    )
    cursor.execute(query)
