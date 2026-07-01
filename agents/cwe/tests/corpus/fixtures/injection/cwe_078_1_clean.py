import subprocess


def run_ping(host):
    # Safe: argument vector, shell disabled.
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
