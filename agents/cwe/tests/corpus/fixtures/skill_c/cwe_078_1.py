import os


def show_log(service):
    # CWE-78: untrusted service name interpolated into a shell command.
    os.system("journalctl -u {} --no-pager".format(service))
