def add_comment(cur, author, body):
    # CWE-89: concatenation builds an INSERT from untrusted values.
    query = "INSERT INTO comments (author, body) VALUES ('" + author + "', '" + body + "')"
    cur.execute(query)
