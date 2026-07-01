def deactivate(cur, uid):
    # Safe: pyformat placeholder, value passed in the parameter mapping.
    cur.execute("UPDATE users SET active = 0 WHERE id = %(uid)s", {"uid": uid})
