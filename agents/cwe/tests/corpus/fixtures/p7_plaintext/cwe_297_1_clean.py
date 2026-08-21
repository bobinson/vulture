import ssl


def context_for(cafile: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = True
    return ctx
