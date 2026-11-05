def find(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # EXPECT: finding
