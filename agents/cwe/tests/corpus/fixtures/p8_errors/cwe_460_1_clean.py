"""Health probe that releases the channel in a finally clause."""


def probe(target):
    try:
        channel = connect(target)
        reply = channel.check(timeout=5.0)
        return reply
    except OSError as exc:
        report(exc)
        return None
    finally:
        channel.close()
