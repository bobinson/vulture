def deactivate(cur, uid):
    # CWE-89: .format() interpolates untrusted id into an UPDATE.
    cur.execute("UPDATE users SET active = 0 WHERE id = {}".format(uid))
