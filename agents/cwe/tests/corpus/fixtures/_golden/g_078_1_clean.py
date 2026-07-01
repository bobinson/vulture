import subprocess


def run_ping(host):
    # Safe: argument vector, no shell interpolation.
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
