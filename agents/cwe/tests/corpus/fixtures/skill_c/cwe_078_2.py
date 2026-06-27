import subprocess


def kill_proc(pid):
    # CWE-78: Popen with shell=True and an interpolated untrusted pid.
    subprocess.Popen(f"kill -9 {pid}", shell=True)
