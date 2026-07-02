# CWE-798: hardcoded secret token literal.
AUTH_TOKEN = "ghp_aB12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr"


def headers():
    return {"X-Token": AUTH_TOKEN}
