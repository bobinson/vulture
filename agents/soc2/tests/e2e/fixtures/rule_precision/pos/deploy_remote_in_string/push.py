import subprocess


def push(host: str) -> None:
    subprocess.run(["rsync", "-az", "dist/", f"{host}:/srv/app"], check=True)
