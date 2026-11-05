# CWE-918 keyword host: request.args["host"] is passed as the host= keyword of a connect() call (the reported half of C11).
def view(request):
    db_host = request.args["host"]
    conn = driver.connect(host=db_host, port=5432)
    return conn
