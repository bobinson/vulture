import os


def apply_settings(request):
    os.environ['UPLOAD_DIR'] = request.args.get('dir')
    return 'applied'
