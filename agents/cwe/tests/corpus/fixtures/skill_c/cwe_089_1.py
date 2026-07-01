def find_by_email(cur, email):
    # CWE-89: %-formatting splices untrusted email into a SELECT.
    cur.execute("SELECT id FROM accounts WHERE email = '%s'" % email)
