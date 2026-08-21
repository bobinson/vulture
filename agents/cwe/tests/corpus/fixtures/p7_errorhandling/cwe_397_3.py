"""Rate limiter that raises a generic exception."""


def admit(bucket, limit):
    if len(bucket) >= limit:
        raise Exception(f"rate limit exceeded ({limit}/s)")
    return True
