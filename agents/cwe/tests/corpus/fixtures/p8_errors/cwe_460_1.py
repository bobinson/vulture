"""Health probe over a long-lived channel."""


def probe(target):
    try:
        channel = connect(target)
        reply = channel.check(timeout=5.0)
        channel.close()
        return reply
    except OSError as exc:
        report(exc)
        return None
