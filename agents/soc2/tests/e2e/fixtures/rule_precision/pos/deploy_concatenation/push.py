import subprocess


def push(host: str, dest: str) -> None:
    subprocess.run(["rsync", "-az", "dist/", host + ":" + dest], check=True)
