def get_user(cur, name):
    # Safe: bound parameter, no concatenation.
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
