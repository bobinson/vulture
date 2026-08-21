"""Fetch the plan record and use the body regardless of the reply."""

import requests


def load_plan(base):
    reply = requests.get(f"{base}/plan", timeout=5)
    return reply.json()["plan"]
