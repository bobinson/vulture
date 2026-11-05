def find(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = '{}'".format(uid))  # EXPECT: finding
