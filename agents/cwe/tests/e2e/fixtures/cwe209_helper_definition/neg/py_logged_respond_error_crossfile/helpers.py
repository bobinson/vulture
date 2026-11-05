import json
import logging

log = logging.getLogger(__name__)


def write_json(resp, status, body):
    resp.status = status
    resp.write(json.dumps(body))


def respond_error(resp, exc):
    log.error("request failed: %s", exc)
    write_json(resp, 500, {"error": "internal"})
