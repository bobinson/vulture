from ldap.filter import escape_filter_chars


def find_by_mail(conn, request):
    # Safe: input escaped with escape_filter_chars before building the filter.
    mail = escape_filter_chars(request.args.get("mail"))
    flt = "(mail=" + mail + ")"
    return conn.search_ext_s("dc=example,dc=com", 2, flt)
