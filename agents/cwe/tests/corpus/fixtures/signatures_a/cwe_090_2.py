def find_user(conn, request):
    # CWE-90: filter interpolates a request parameter.
    name = request.args.get("name")
    return conn.search_ext_s("dc=example", "(cn=" + name + ")")
