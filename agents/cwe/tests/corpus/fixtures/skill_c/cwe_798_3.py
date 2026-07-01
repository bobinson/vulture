# CWE-798: hardcoded admin password literal.
passwd = "Adm1n!ProdCluster2024"


def login():
    return {"user": "root", "password": passwd}
