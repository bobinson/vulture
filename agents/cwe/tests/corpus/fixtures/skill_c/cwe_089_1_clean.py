def find_by_email(cur, email):
    # Safe: parameterized query, email bound as a parameter.
    cur.execute("SELECT id FROM accounts WHERE email = ?", (email,))
