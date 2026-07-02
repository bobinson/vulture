def get_user(cur, uid):
    # CWE-89: .format() builds SQL from untrusted id.
    cur.execute("SELECT * FROM users WHERE id = {}".format(uid))
