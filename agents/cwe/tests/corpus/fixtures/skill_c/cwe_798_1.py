# CWE-798: hardcoded Flask secret_key literal in source.
secret_key = "f3a9c1b7e5d28406aa91bc73de45f012"


def configure(app):
    app.config["SECRET_KEY"] = secret_key
