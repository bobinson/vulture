import os


def apply_settings(settings):
    os.environ['UPLOAD_DIR'] = settings.upload_dir
    return 'applied'
