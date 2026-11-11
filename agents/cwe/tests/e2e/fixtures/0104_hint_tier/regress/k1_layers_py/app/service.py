from .storage import read_bundle


def fetch_bundle(user, bundle_name):
    if not user.can_fetch:
        raise PermissionError(bundle_name)
    return read_bundle(bundle_name)
