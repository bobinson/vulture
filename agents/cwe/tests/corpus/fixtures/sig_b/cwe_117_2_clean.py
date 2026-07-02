def record_upload(logger, request):
    # Safe: newlines stripped from the untrusted filename before logging.
    filename = request.args.get("filename")
    safe_name = filename.replace("\r", "").replace("\n", "")
    logger.error(f"upload rejected for file {safe_name}")
