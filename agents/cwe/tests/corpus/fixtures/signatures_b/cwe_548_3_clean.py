def make_handler():
    # Safe: directory listing disabled.
    return StaticHandler(directoryListing=False, root="/srv/public")
