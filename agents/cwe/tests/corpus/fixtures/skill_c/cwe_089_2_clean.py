def add_comment(cur, author, body):
    # Safe: placeholders bind both values; no string building.
    cur.execute(
        "INSERT INTO comments (author, body) VALUES (?, ?)",
        (author, body),
    )
