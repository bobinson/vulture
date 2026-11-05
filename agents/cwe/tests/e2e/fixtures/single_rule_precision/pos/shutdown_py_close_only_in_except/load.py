import json
import logging


def load(path):
    # EXPECT-NEXT: finding
    handle = open(path, encoding="utf-8")
    try:
        return json.load(handle)
    except ValueError:
        handle.close()
        logging.info("remember to call handle.close()")
        raise
