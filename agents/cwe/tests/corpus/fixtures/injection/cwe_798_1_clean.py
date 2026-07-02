import os

# Safe: secret read from environment, no literal in source.
DB_PASSWORD = os.environ["DB_PASSWORD"]


def connect():
    return f"postgres://admin:{DB_PASSWORD}@db/app"
