import subprocess


def push(user: str, host: str) -> None:
    subprocess.run(["rsync", "-az", "dist/", "%s@%s:/srv" % (user, host)], check=True)
