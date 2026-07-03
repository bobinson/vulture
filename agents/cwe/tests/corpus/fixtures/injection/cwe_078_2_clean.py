import subprocess


def archive(name):
    # Safe: argument list, no shell, no string interpolation.
    subprocess.run(["tar", "czf", "/tmp/out.tgz", "."], shell=False, check=True)
