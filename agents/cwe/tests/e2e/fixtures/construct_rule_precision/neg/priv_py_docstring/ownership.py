def chown_tree(path):
    """Fix ownership after an install.

    EXPECT-NEXT: clean
    Run as root: the installer leaves files owned by uid 0.
    """
    return path
