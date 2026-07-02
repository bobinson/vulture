def make_handler():
    # CWE-548: directory listing enabled in static handler config.
    return StaticHandler(directoryListing=True, root="/srv/public")
