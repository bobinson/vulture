def handle(logger, request):
    # CWE-117: untrusted input interpolated into log line.
    user = request.args.get("user")
    logger.info("login attempt by " + user)
