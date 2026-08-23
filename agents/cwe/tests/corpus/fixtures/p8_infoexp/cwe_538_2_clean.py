import logging


def configure(app):
    handler = logging.FileHandler("/var/log/app/audit.log")
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
