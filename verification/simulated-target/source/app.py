# Sample code with planted vulnerabilities for scan agent verification.
# Each vulnerability is documented with its expected detection ID.

import sqlite3


def get_user(user_id):
    """SRC_001: SQL injection — string formatting in query."""
    conn = sqlite3.connect("app.db")
    cursor = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def render_page(user_input):
    """SRC_002: XSS — unescaped user input in HTML."""
    return f"<html><body>Hello {user_input}</body></html>"


# SRC_003: Hardcoded credentials
DB_PASSWORD = "admin123"
API_SECRET = "changeme_not_rotated"
