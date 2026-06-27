import subprocess


def lookup(domain):
    # Safe: pass argument as a list element, no shell.
    return subprocess.run(["whois", domain], capture_output=True, check=True)
