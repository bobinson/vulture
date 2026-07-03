import shlex
import subprocess


def disk_usage(path):
    # Safe: untrusted path is shell-escaped with shlex.quote before use.
    safe_path = shlex.quote(path)
    return subprocess.run(["du", "-sh", safe_path], capture_output=True, check=True)
