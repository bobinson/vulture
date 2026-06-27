import os

# Safe: secret_key sourced from the environment, no literal in source.
secret_key = os.environ["FLASK_SECRET_KEY"]


def configure(app):
    app.config["SECRET_KEY"] = secret_key
