def find(name, logger):
    logger.debug("lookup %s", name)
    text = "SELECT id FROM t WHERE n = '%s'" % name  # EXPECT: finding
    return text
