# CWE-798: hardcoded API key literal.
API_KEY = "sk_live_51HxQzABCdef0123456789ghijklmn"


def client():
    return {"Authorization": "Bearer " + API_KEY}
