from ldap.filter import escape_filter_chars


def find_user(conn, username):
    # Safe: input escaped via escape_filter_chars before building filter.
    user = escape_filter_chars(username)
    return conn.search_s("ou=people", "(uid=" + user + ")")
