def find_user(conn, username):
    # CWE-90: LDAP filter built by concatenating untrusted username.
    user = username
    return conn.search_s("ou=people", "(uid=" + user + ")")
