def handle(logger, request):
    # Safe: newlines stripped (sanitize) before logging.
    user = request.args.get("user").replace("\r", "_").replace("\n", "_")
    logger.info("login attempt by " + user)
