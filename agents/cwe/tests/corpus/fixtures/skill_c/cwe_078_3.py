import os


def disk_usage(path):
    # CWE-78: os.popen reads output of a shell command built by concatenation.
    return os.popen("du -sh " + path).read()
