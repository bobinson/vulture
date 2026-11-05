import subprocess


def launch(image):
    return subprocess.run(["docker", "run", "--privileged", image])  # EXPECT: finding
