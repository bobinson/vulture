import subprocess


def show_log(service):
    # Safe: argument vector, shell disabled — no shell metacharacter parsing.
    return subprocess.run(
        ["journalctl", "-u", service, "--no-pager"],
        capture_output=True,
        check=True,
    )
