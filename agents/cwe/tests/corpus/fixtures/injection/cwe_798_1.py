# CWE-798: hardcoded database password literal.
DB_PASSWORD = "s3cr3tProductionDbP4ssw0rd!"


def connect():
    return f"postgres://admin:{DB_PASSWORD}@db/app"
