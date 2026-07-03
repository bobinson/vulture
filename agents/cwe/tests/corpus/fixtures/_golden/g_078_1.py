import os


def run_ping(host):
    # Untrusted host concatenated into a shell command.
    os.system("ping -c 1 " + host)
