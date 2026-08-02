"""Token refresher that names the failures it recovers from."""


def refresh(client):
    try:
        return client.renew()
    except (TimeoutError, ConnectionResetError) as exc:
        report(exc)
        return None
