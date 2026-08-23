import subprocess


def fetch(req):
    target = req.query["host"]
    subprocess.run(["curl", "--url", target], check=False)
