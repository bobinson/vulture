import logging


def configure(app):
    handler = logging.FileHandler("static/audit.log")
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
