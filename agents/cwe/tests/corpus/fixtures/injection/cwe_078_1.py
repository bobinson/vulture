import os


def run_ping(host):
    # CWE-78: untrusted host concatenated into shell command string.
    os.system("ping -c 1 " + host)
