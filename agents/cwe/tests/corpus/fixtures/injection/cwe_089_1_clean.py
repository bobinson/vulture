def get_user(cur, uid):
    # Safe: parameterized query, value bound separately.
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
