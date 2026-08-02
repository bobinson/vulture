"""Rate limiter that raises a specific exception."""


class RateLimitExceeded(RuntimeError):
    pass


def admit(bucket, limit):
    if len(bucket) >= limit:
        raise RateLimitExceeded(f"rate limit exceeded ({limit}/s)")
    return True
