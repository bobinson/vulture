# pins: the same aliased generic verb imported from an in-app module is no path sink - from .journal import copy as duplicate, no file-system word in the module path (negative)
from .journal import copy as duplicate

from flask import request

BACKUP_DIR = "/srv/backups"


def snapshot():
    duplicate(request.args["source"], BACKUP_DIR)
    return "ok"
