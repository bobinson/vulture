def find(cursor, x):
    text = ("SELECT * FROM t " "WHERE id = {}").format(x)  # EXPECT: finding
    return cursor.execute(text)
