"""Token refresher with a catch-all handler."""


def refresh(client):
    try:
        return client.renew()
    except Exception as exc:
        report(exc)
        return None
