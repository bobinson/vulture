import os


def prepare_data_dir(base):
    os.umask(0)
    os.makedirs(base, exist_ok=True)
    return base
