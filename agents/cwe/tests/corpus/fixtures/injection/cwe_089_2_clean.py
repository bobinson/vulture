def get_user(cur, uid):
    # Safe: parameterized query with named placeholder.
    cur.execute("SELECT * FROM users WHERE id = %(uid)s", {"uid": uid})
