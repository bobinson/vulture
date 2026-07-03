def login(config):
    # Safe: password pulled from runtime config, never a source literal.
    passwd = config["admin_password"]
    return {"user": "root", "password": passwd}
