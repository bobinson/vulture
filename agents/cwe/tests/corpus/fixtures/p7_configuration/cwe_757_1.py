import ssl


def make_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_minimum_version = 'TLSv1'
    context.minimum_version = ssl_minimum_version
    return context
