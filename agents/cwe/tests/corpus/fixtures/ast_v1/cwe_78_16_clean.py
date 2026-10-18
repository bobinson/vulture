# pins: db.execute(sql) where sql = "select " + request.args["q"] - execute is itself a weak command word, so an exec prefix does not promote it and with no strengthener it is no command sink (negative)
def handler(request):
    sql = "select " + request.args["q"]
    return db.execute(sql)
