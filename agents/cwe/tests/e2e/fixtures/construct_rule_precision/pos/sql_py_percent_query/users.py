def find(cur, email):
    cur.execute("SELECT id FROM accounts WHERE email = '%s'" % email)  # EXPECT: finding
