from ldap.filter import escape_filter_chars


def find_user(conn, request):
    # Safe: request value escaped before use.
    name = escape_filter_chars(request.args.get("name"))
    return conn.search_ext_s("dc=example", "(cn=" + name + ")")
