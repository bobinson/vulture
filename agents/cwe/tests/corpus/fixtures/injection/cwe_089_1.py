def get_user(cur, uid):
    # CWE-89: f-string interpolates untrusted id into SQL.
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
