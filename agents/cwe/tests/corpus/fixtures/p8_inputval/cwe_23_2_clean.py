import os
import tarfile


def unpack_archive(archive, dest):
    tar = tarfile.open(archive)
    for member in tar.getmembers():
        target = os.path.join(dest, os.path.basename(member.name))
        _store(target, tar.extractfile(member).read())
