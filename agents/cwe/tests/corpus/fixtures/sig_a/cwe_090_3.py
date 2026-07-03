def find_by_mail(conn, request):
    # CWE-90: LDAP mail filter interpolated from untrusted request input.
    mail = request.args.get("mail")
    flt = "(mail=" + mail + ")"
    return conn.search_ext_s("dc=example,dc=com", 2, flt)
