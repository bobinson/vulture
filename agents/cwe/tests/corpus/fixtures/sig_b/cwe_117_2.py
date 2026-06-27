def record_upload(logger, request):
    # CWE-117: untrusted filename interpolated into an f-string log message.
    filename = request.args.get("filename")
    logger.error(f"upload rejected for file {filename}")
