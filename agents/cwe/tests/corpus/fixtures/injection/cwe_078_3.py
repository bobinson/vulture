import os


def lookup(domain):
    # CWE-78: f-string builds a shell command from user input.
    os.popen(f"whois {domain}").read()
