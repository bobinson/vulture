# pins: a generic verb imported from a file-system module stays a path sink - from shutil import copy as duplicate, then duplicate(request value, BACKUP_DIR) (positive)
from shutil import copy as duplicate

from flask import request

BACKUP_DIR = "/srv/backups"


def snapshot():
    duplicate(request.args["source"], BACKUP_DIR)
    return "ok"
