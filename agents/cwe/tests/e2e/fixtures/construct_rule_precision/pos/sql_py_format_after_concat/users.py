def find(cursor, t, x):
    q = "SELECT * FROM " + t + " WHERE id = {}".format(x)  # EXPECT: finding
    return cursor.execute(q)
