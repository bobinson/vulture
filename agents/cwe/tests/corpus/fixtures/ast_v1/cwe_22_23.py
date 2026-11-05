# pins: a function whose decorator carries a route word gets request-sourced parameters (R-C); name reaches open()
@app.route("/doc/<name>")
def show(name):
    return open("/srv/docs/" + name)
