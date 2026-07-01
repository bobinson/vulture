def get_user(cur, name):
    # CWE-89: string concatenation builds SQL from untrusted name.
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
