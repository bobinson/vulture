import subprocess


def archive(name):
    # CWE-78: shell=True with interpolated untrusted name.
    subprocess.call("tar czf /tmp/%s.tgz ." % name, shell=True)
